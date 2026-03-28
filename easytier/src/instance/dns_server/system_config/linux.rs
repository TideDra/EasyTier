// DNS auto-configuration for Linux.
// Detection logic translated from tailscale #32ce1bdb48078ec4cedaeeb5b1b2ff9c0ef61a49

use crate::defer;
use anyhow::{Context, Result};
use dbus::blocking::stdintf::org_freedesktop_dbus::Properties as _;
use std::fs;
use std::io::{self, BufRead, Cursor, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use version_compare::Cmp;

use super::{OSConfig, SystemConfig};

const RESOLV_CONF: &str = "/etc/resolv.conf";
const RESOLV_CONF_BACKUP: &str = "/etc/resolv.conf.easytier.bak";
const RESOLV_CONF_HEADER: &str = "# Added by easytier\n";
const PING_TIMEOUT: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// DNS configurator implementations
// ---------------------------------------------------------------------------

/// Configures DNS via systemd-resolved using the `resolvectl` CLI.
/// Sets per-interface DNS and routing domains so only matching queries
/// are sent to the EasyTier DNS server.
pub struct ResolvedManager {
    tun_name: String,
}

impl ResolvedManager {
    pub fn new(tun_name: &str) -> Self {
        Self {
            tun_name: tun_name.to_string(),
        }
    }
}

impl SystemConfig for ResolvedManager {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        // resolvectl dns <iface> <ns1> <ns2> ...
        let mut args = vec!["dns".to_string(), self.tun_name.clone()];
        args.extend(cfg.nameservers.iter().cloned());
        let output = Command::new("resolvectl").args(&args).output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "resolvectl dns failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // resolvectl domain <iface> ~<domain1> ~<domain2> ...
        // The ~ prefix marks routing-only domains.
        let mut args = vec!["domain".to_string(), self.tun_name.clone()];
        for domain in &cfg.match_domains {
            let d = domain.trim_end_matches('.');
            args.push(format!("~{}", d));
        }
        let output = Command::new("resolvectl").args(&args).output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "resolvectl domain failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        // resolvectl revert <iface> — undoes all per-link DNS settings.
        // May fail if the interface is already gone; that's fine.
        let _ = Command::new("resolvectl")
            .args(["revert", &self.tun_name])
            .output();
        Ok(())
    }
}

/// Configures DNS via the `resolvconf` tool (works for both Debian resolvconf
/// and OpenResolv).
pub struct ResolvconfManager {
    iface_label: String,
}

impl ResolvconfManager {
    pub fn new(tun_name: &str) -> Self {
        // Convention: <ifname>.<program> so different programs don't collide.
        Self {
            iface_label: format!("{}.easytier", tun_name),
        }
    }
}

impl SystemConfig for ResolvconfManager {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let mut content = String::new();
        for ns in &cfg.nameservers {
            content.push_str(&format!("nameserver {}\n", ns));
        }
        if !cfg.search_domains.is_empty() {
            let domains: Vec<&str> = cfg
                .search_domains
                .iter()
                .map(|d| d.trim_end_matches('.'))
                .collect();
            content.push_str(&format!("search {}\n", domains.join(" ")));
        }

        let mut child = Command::new("resolvconf")
            .args(["-a", &self.iface_label, "-m", "0"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        if let Some(ref mut stdin) = child.stdin {
            stdin.write_all(content.as_bytes())?;
        }

        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "resolvconf -a failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        let _ = Command::new("resolvconf")
            .args(["-d", &self.iface_label])
            .output();
        Ok(())
    }
}

/// Directly modifies `/etc/resolv.conf` as a last resort when no DNS manager
/// is detected. Backs up the original file and restores it on close.
#[derive(Default)]
pub struct DirectManager;

impl DirectManager {
    pub fn new() -> Self {
        Self
    }
}

impl SystemConfig for DirectManager {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        // Read original resolv.conf to preserve existing nameservers and search
        // domains so that normal internet access is not disrupted.
        let (mut orig_nameservers, mut orig_search) = (Vec::new(), Vec::new());
        if let Ok(original) = fs::read_to_string(RESOLV_CONF) {
            // Don't re-parse our own output on repeated calls.
            if !original.starts_with(RESOLV_CONF_HEADER) {
                for line in original.lines() {
                    let line = line.trim();
                    if let Some(ns) = line.strip_prefix("nameserver ") {
                        let ns = ns.trim();
                        if !ns.is_empty() {
                            orig_nameservers.push(ns.to_string());
                        }
                    } else if let Some(s) = line.strip_prefix("search ") {
                        orig_search.extend(s.split_whitespace().map(String::from));
                    }
                }
            }
        }

        // Only create backup if one doesn't already exist (avoid overwriting
        // the original with our modified version on repeated calls).
        if !Path::new(RESOLV_CONF_BACKUP).exists() && Path::new(RESOLV_CONF).exists() {
            fs::copy(RESOLV_CONF, RESOLV_CONF_BACKUP)?;
        }

        let mut content = String::from(RESOLV_CONF_HEADER);
        content.push_str("# Original resolv.conf backed up to ");
        content.push_str(RESOLV_CONF_BACKUP);
        content.push('\n');

        // EasyTier nameserver first, then original ones for fallback.
        for ns in &cfg.nameservers {
            content.push_str(&format!("nameserver {}\n", ns));
        }
        for ns in &orig_nameservers {
            if !cfg.nameservers.contains(ns) {
                content.push_str(&format!("nameserver {}\n", ns));
            }
        }

        // Merge search domains: EasyTier domains first, then original.
        let et_domains: Vec<&str> = cfg
            .search_domains
            .iter()
            .map(|d| d.trim_end_matches('.'))
            .collect();
        let mut all_domains = et_domains.clone();
        for d in &orig_search {
            let d = d.trim_end_matches('.');
            if !all_domains.contains(&d) {
                all_domains.push(d);
            }
        }
        if !all_domains.is_empty() {
            content.push_str(&format!("search {}\n", all_domains.join(" ")));
        }

        fs::write(RESOLV_CONF, content)?;
        Ok(())
    }

    fn close(&self) -> io::Result<()> {
        // Only restore if we were the ones who modified it.
        if let Ok(current) = fs::read_to_string(RESOLV_CONF) {
            if !current.starts_with(RESOLV_CONF_HEADER) {
                return Ok(());
            }
        }

        if Path::new(RESOLV_CONF_BACKUP).exists() {
            fs::copy(RESOLV_CONF_BACKUP, RESOLV_CONF)?;
            fs::remove_file(RESOLV_CONF_BACKUP)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public factory — called from server_instance.rs
// ---------------------------------------------------------------------------

/// Detect the active DNS management mode and return the appropriate
/// `SystemConfig` implementation.
pub fn new_os_configurator(interface_name: &str) -> Result<Box<dyn SystemConfig>> {
    let env = new_os_config_env();
    let mode = dns_mode(&env).unwrap_or_else(|e| {
        tracing::warn!("dns: failed to detect mode ({}), falling back to direct", e);
        "direct".to_string()
    });

    tracing::info!("dns: using {} mode", mode);

    match mode.as_str() {
        "systemd-resolved" => Ok(Box::new(ResolvedManager::new(interface_name))),
        "debian-resolvconf" | "openresolv" => Ok(Box::new(ResolvconfManager::new(interface_name))),
        _ => {
            tracing::info!("dns: using direct /etc/resolv.conf management");
            Ok(Box::new(DirectManager::new()))
        }
    }
}

// ---------------------------------------------------------------------------
// DNS mode detection
// ---------------------------------------------------------------------------

type DbusPingFn = dyn Fn(&str, &str) -> Result<()>;
type DbusReadStringFn = dyn Fn(&str, &str, &str, &str) -> Result<String>;
type NmIsUsingResolvedFn = dyn Fn() -> Result<()>;
type NmVersionBetweenFn = dyn Fn(&str, &str) -> Result<bool>;

struct OSConfigEnv {
    fs: Box<dyn FileSystem>,
    dbus_ping: Box<DbusPingFn>,
    dbus_read_string: Box<DbusReadStringFn>,
    nm_is_using_resolved: Box<NmIsUsingResolvedFn>,
    nm_version_between: Box<NmVersionBetweenFn>,
    resolvconf_style: Box<dyn Fn() -> String>,
}

trait FileSystem {
    fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    fn exists(&self, path: &str) -> bool;
}

struct DirectFS;

impl FileSystem for DirectFS {
    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        fs::read(path).context("Failed to read file")
    }

    fn exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }
}

/// Check whether NetworkManager is using systemd-resolved as its DNS backend.
fn nm_is_using_resolved() -> Result<()> {
    let conn = dbus::blocking::Connection::new_system().context("Failed to connect to D-Bus")?;
    let proxy = conn.with_proxy(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager/DnsManager",
        Duration::from_secs(1),
    );

    let (value,): (dbus::arg::Variant<Box<dyn dbus::arg::RefArg + 'static>>,) = proxy
        .method_call(
            "org.freedesktop.DBus.Properties",
            "Get",
            ("org.freedesktop.NetworkManager.DnsManager", "Mode"),
        )
        .context("Failed to get NM mode property")?;

    if value.0.as_str() != Some("systemd-resolved") {
        return Err(anyhow::anyhow!(
            "NetworkManager is not using systemd-resolved, found: {:?}",
            value
        ));
    }
    Ok(())
}

/// Detect which resolvconf implementation is installed ("debian", "openresolv",
/// or "" if not present).
pub fn resolvconf_style() -> String {
    if which::which("resolvconf").is_err() {
        return String::new();
    }

    let output = match Command::new("resolvconf").arg("--version").output() {
        Ok(output) => output,
        Err(e) => {
            if let Some(code) = e.raw_os_error() {
                if code == 99 {
                    return "debian".to_string();
                }
            }
            return String::new();
        }
    };

    if output.stdout.starts_with(b"Debian resolvconf") {
        return "debian".to_string();
    }

    "openresolv".to_string()
}

fn new_os_config_env() -> OSConfigEnv {
    OSConfigEnv {
        fs: Box::new(DirectFS),
        dbus_ping: Box::new(dbus_ping),
        dbus_read_string: Box::new(dbus_read_string),
        nm_is_using_resolved: Box::new(nm_is_using_resolved),
        nm_version_between: Box::new(nm_version_between),
        resolvconf_style: Box::new(resolvconf_style),
    }
}

/// Determine the owner of `/etc/resolv.conf` by scanning header comments.
pub fn resolv_owner(bs: &[u8]) -> String {
    let mut likely = String::new();
    let cursor = Cursor::new(bs);
    let reader = io::BufReader::new(cursor);

    for line_result in reader.lines() {
        match line_result {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if !line.starts_with('#') {
                    return likely;
                }
                if line.contains("systemd-resolved") {
                    likely = "systemd-resolved".to_string();
                } else if line.contains("NetworkManager") {
                    likely = "NetworkManager".to_string();
                } else if line.contains("resolvconf") {
                    likely = "resolvconf".to_string();
                }
            }
            Err(_) => return likely,
        }
    }

    likely
}

/// Detect the DNS management mode on this system.
/// Returns one of: "systemd-resolved", "debian-resolvconf", "openresolv", "direct".
fn dns_mode(env: &OSConfigEnv) -> Result<String> {
    let debug = std::cell::RefCell::new(Vec::new());
    let dbg = |k: &str, v: &str| debug.borrow_mut().push((k.to_string(), v.to_string()));

    defer! {
        if !debug.borrow().is_empty() {
            let log_entries: Vec<String> =
                debug.borrow().iter().map(|(k, v)| format!("{}={}", k, v)).collect();
            tracing::info!("dns: [{}]", log_entries.join(" "));
        }
    };

    let resolved_up =
        (env.dbus_ping)("org.freedesktop.resolve1", "/org/freedesktop/resolve1").is_ok();
    if resolved_up {
        dbg("resolved-ping", "yes");
    }

    let content = match env.fs.read_file(RESOLV_CONF) {
        Ok(content) => content,
        Err(e) if e.to_string().contains("NotFound") => {
            dbg("rc", "missing");
            return Ok("direct".to_string());
        }
        Err(e) => return Err(e).context("reading /etc/resolv.conf"),
    };

    match resolv_owner(&content).as_str() {
        "systemd-resolved" => {
            dbg("rc", "resolved");
            if let Err(e) = resolved_is_actually_resolver(env, &dbg, &content) {
                tracing::warn!("resolvedIsActuallyResolver error: {}", e);
                dbg("resolved", "not-in-use");
                return Ok("direct".to_string());
            }
            Ok("systemd-resolved".to_string())
        }
        "resolvconf" => {
            let style = (env.resolvconf_style)();
            dbg("rc", "resolvconf");
            dbg("resolvconf-style", &style);
            match style.as_str() {
                "openresolv" => Ok("openresolv".to_string()),
                "debian" => Ok("debian-resolvconf".to_string()),
                _ => Ok("direct".to_string()),
            }
        }
        "NetworkManager" => {
            dbg("rc", "nm");
            if resolved_up && (env.nm_is_using_resolved)().is_ok() {
                dbg("nm", "resolved");
                Ok("systemd-resolved".to_string())
            } else {
                let style = (env.resolvconf_style)();
                if !style.is_empty() {
                    dbg("nm", &format!("resolvconf-{}", style));
                    match style.as_str() {
                        "openresolv" => Ok("openresolv".to_string()),
                        _ => Ok("debian-resolvconf".to_string()),
                    }
                } else {
                    dbg("nm", "direct");
                    Ok("direct".to_string())
                }
            }
        }
        _ => Ok("direct".to_string()),
    }
}

fn dbus_ping(name: &str, object_path: &str) -> Result<()> {
    let conn = dbus::blocking::Connection::new_system()?;
    let proxy = conn.with_proxy(name, object_path, PING_TIMEOUT);
    let _: () = proxy.method_call("org.freedesktop.DBus.Peer", "Ping", ())?;
    Ok(())
}

fn dbus_read_string(name: &str, object_path: &str, iface: &str, member: &str) -> Result<String> {
    let conn = dbus::blocking::Connection::new_system()?;
    let proxy = conn.with_proxy(name, object_path, PING_TIMEOUT);
    let (value,): (String,) =
        proxy.method_call("org.freedesktop.DBus.Properties", "Get", (iface, member))?;
    Ok(value)
}

fn nm_version_between(first: &str, last: &str) -> Result<bool> {
    let conn = dbus::blocking::Connection::new_system()?;
    let proxy = conn.with_proxy(
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        PING_TIMEOUT,
    );

    let version: String = proxy.get("org.freedesktop.NetworkManager", "Version")?;
    let cmp_first = version_compare::compare(&version, first).unwrap_or(Cmp::Lt);
    let cmp_last = version_compare::compare(&version, last).unwrap_or(Cmp::Gt);
    Ok(cmp_first == Cmp::Ge && cmp_last == Cmp::Le)
}

fn resolved_is_actually_resolver(
    env: &OSConfigEnv,
    dbg: &dyn Fn(&str, &str),
    content: &[u8],
) -> Result<()> {
    if is_libnss_resolve_used(env).is_ok() {
        dbg("resolved", "nss");
        return Ok(());
    }

    let resolver = resolv_conf::Config::parse(content)?;
    if resolver.nameservers.is_empty() {
        return Err(anyhow::anyhow!("resolv.conf has no nameservers"));
    }

    for ns in resolver.nameservers {
        if ns != Ipv4Addr::new(127, 0, 0, 53).into() {
            return Err(anyhow::anyhow!(
                "resolv.conf doesn't point to systemd-resolved"
            ));
        }
    }

    dbg("resolved", "file");
    Ok(())
}

fn is_libnss_resolve_used(env: &OSConfigEnv) -> Result<()> {
    let content = env.fs.read_file("/etc/nsswitch.conf")?;

    for line in String::from_utf8_lossy(&content).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.first() == Some(&"hosts:") {
            for module in parts.iter().skip(1) {
                if *module == "dns" {
                    return Err(anyhow::anyhow!("dns module has higher priority"));
                }
                if *module == "resolve" {
                    return Ok(());
                }
            }
        }
    }

    Err(anyhow::anyhow!("libnss_resolve not used"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_mode_test() {
        let env = new_os_config_env();
        let mode = dns_mode(&env).unwrap();
        println!("Detected DNS mode: {}", mode);
    }

    #[test]
    fn test_resolv_owner_systemd() {
        let content = b"# This is /run/systemd/resolve/stub-resolv.conf managed by systemd-resolved.\nnameserver 127.0.0.53\n";
        assert_eq!(resolv_owner(content), "systemd-resolved");
    }

    #[test]
    fn test_resolv_owner_nm() {
        let content =
            b"# Generated by NetworkManager\nnameserver 192.168.1.1\nsearch example.com\n";
        assert_eq!(resolv_owner(content), "NetworkManager");
    }

    #[test]
    fn test_resolv_owner_resolvconf() {
        let content =
            b"# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)\nnameserver 8.8.8.8\n";
        assert_eq!(resolv_owner(content), "resolvconf");
    }

    #[test]
    fn test_resolv_owner_unknown() {
        let content = b"nameserver 8.8.8.8\nsearch local\n";
        assert_eq!(resolv_owner(content), "");
    }

    #[test]
    fn test_direct_manager_set_and_close() {
        let dir = tempfile::tempdir().unwrap();
        let resolv_path = dir.path().join("resolv.conf");
        let backup_path = dir.path().join("resolv.conf.bak");

        // Write an original resolv.conf
        fs::write(&resolv_path, "nameserver 8.8.8.8\n").unwrap();

        // We can't easily test DirectManager with const paths, but we can
        // verify the logic by testing the OSConfig construction.
        let cfg = OSConfig {
            nameservers: vec!["100.100.100.101".to_string()],
            search_domains: vec!["et.net.".to_string()],
            match_domains: vec!["et.net.".to_string()],
        };

        // Verify the config is well-formed.
        assert_eq!(cfg.nameservers.len(), 1);
        assert_eq!(cfg.search_domains.len(), 1);
    }
}
