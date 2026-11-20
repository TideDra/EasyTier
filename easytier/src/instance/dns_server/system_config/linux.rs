#[cfg(test)]
mod resolved_fixture;

use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use serde::Serialize;
use zbus::{
    blocking::{Connection, Proxy, connection::Builder, proxy::Builder as ProxyBuilder},
    names::OwnedUniqueName,
    proxy::{CacheProperties, MethodFlags},
    zvariant::{DynamicType, OwnedObjectPath},
};

use super::{OSConfig, SystemConfig};

const RESOLVED_SERVICE: &str = "org.freedesktop.resolve1";
const RESOLVED_MANAGER_PATH: &str = "/org/freedesktop/resolve1";
const RESOLVED_MANAGER_INTERFACE: &str = "org.freedesktop.resolve1.Manager";
const RESOLVED_LINK_INTERFACE: &str = "org.freedesktop.resolve1.Link";
const NETWORKD_SERVICE: &str = "org.freedesktop.network1";
const NETWORKD_MANAGER_PATH: &str = "/org/freedesktop/network1";
const NETWORKD_MANAGER_INTERFACE: &str = "org.freedesktop.network1.Manager";
const LINK_BUSY_ERROR: &str = "org.freedesktop.resolve1.LinkBusy";
const DBUS_METHOD_TIMEOUT: Duration = Duration::from_secs(30);
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const RESOLV_CONF_BACKUP_PATH: &str = "/etc/resolv.conf.easytier.bak";
const RESOLV_CONF_HEADER: &str = "# Added by easytier\n";

pub fn new_configurator(interface: &str) -> io::Result<Box<dyn SystemConfig>> {
    Ok(Box::new(LinuxConfigurator::new(interface)))
}

enum LinuxBackend {
    Resolved(ResolvedConfigurator),
    Direct(DirectConfigurator),
}

/// Uses native `systemd-resolved` per-link split DNS when resolved is in the
/// system query path and reachable over D-Bus; otherwise falls back to direct
/// `/etc/resolv.conf` backup/restore (e.g. inside containers without D-Bus).
pub struct LinuxConfigurator {
    interface: String,
    backend: Mutex<Option<LinuxBackend>>,
}

impl LinuxConfigurator {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            backend: Mutex::new(None),
        }
    }

    fn backend(&self) -> io::Result<MutexGuard<'_, Option<LinuxBackend>>> {
        let mut guard = self.backend.lock().unwrap();
        if guard.is_none() {
            let resolv_conf = match fs::read_to_string(RESOLV_CONF_PATH) {
                Ok(content) => content,
                Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
                Err(error) => return Err(error),
            };
            let nsswitch = fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
            let selected = if ResolvedConfigurator::uses_resolved(&resolv_conf, &nsswitch) {
                let resolved = ResolvedConfigurator::new(&self.interface);
                match resolved.probe_dbus() {
                    Ok(()) => LinuxBackend::Resolved(resolved),
                    Err(error) => {
                        tracing::info!(
                            %error,
                            "systemd-resolved D-Bus is unavailable; falling back to direct /etc/resolv.conf management"
                        );
                        LinuxBackend::Direct(DirectConfigurator::new())
                    }
                }
            } else {
                tracing::info!(
                    "systemd-resolved is not in the system query path; using direct /etc/resolv.conf management"
                );
                LinuxBackend::Direct(DirectConfigurator::new())
            };
            *guard = Some(selected);
        }
        Ok(guard)
    }
}

impl SystemConfig for LinuxConfigurator {
    fn prepare(&self) -> io::Result<()> {
        match self.backend()?.as_ref().unwrap() {
            LinuxBackend::Resolved(configurator) => configurator.prepare(),
            LinuxBackend::Direct(configurator) => configurator.prepare(),
        }
    }

    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        match self.backend()?.as_ref().unwrap() {
            LinuxBackend::Resolved(configurator) => configurator.set_dns(cfg),
            LinuxBackend::Direct(configurator) => configurator.set_dns(cfg),
        }
    }

    fn refresh(&self) -> io::Result<()> {
        let guard = self.backend.lock().unwrap();
        let Some(backend) = guard.as_ref() else {
            return Ok(());
        };
        match backend {
            LinuxBackend::Resolved(configurator) => configurator.refresh(),
            LinuxBackend::Direct(configurator) => configurator.refresh(),
        }
    }

    fn close(&self) -> io::Result<()> {
        let guard = self.backend.lock().unwrap();
        let Some(backend) = guard.as_ref() else {
            return Ok(());
        };
        match backend {
            LinuxBackend::Resolved(configurator) => configurator.close(),
            LinuxBackend::Direct(configurator) => configurator.close(),
        }
    }
}

/// Directly manages `/etc/resolv.conf` with backup/restore when no D-Bus
/// `systemd-resolved` integration is available (such as inside containers).
pub struct DirectConfigurator {
    resolv_conf: PathBuf,
    backup_path: PathBuf,
    desired: Mutex<Option<OSConfig>>,
}

impl Default for DirectConfigurator {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectConfigurator {
    pub fn new() -> Self {
        Self::with_paths(RESOLV_CONF_PATH, RESOLV_CONF_BACKUP_PATH)
    }

    fn with_paths(resolv_conf: impl Into<PathBuf>, backup_path: impl Into<PathBuf>) -> Self {
        Self {
            resolv_conf: resolv_conf.into(),
            backup_path: backup_path.into(),
            desired: Mutex::new(None),
        }
    }

    fn is_managed_content(content: &str) -> bool {
        content.starts_with(RESOLV_CONF_HEADER)
    }

    fn apply_file(&self, cfg: &OSConfig) -> io::Result<()> {
        let mut orig_nameservers = Vec::new();
        let mut orig_search = Vec::new();
        let mut orig_other = Vec::new();

        let current_content = match fs::read_to_string(&self.resolv_conf) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(io::Error::other(format!(
                    "Cannot read {} for Magic DNS: {error}",
                    self.resolv_conf.display()
                )));
            }
        };

        let source = if current_content
            .as_deref()
            .is_some_and(Self::is_managed_content)
        {
            fs::read_to_string(&self.backup_path).ok()
        } else {
            current_content.clone()
        };

        if let Some(original) = source {
            for line in original.lines() {
                let trimmed = line.trim();
                if let Some(ns) = trimmed
                    .strip_prefix("nameserver")
                    .and_then(|rest| rest.strip_prefix(|ch: char| ch.is_whitespace()))
                {
                    let ns = ns.split('#').next().unwrap_or_default().trim();
                    if !ns.is_empty() {
                        orig_nameservers.push(ns.to_owned());
                    }
                } else if let Some(search) = trimmed
                    .strip_prefix("search")
                    .and_then(|rest| rest.strip_prefix(|ch: char| ch.is_whitespace()))
                {
                    let search = search.split('#').next().unwrap_or_default();
                    orig_search.extend(search.split_whitespace().map(str::to_owned));
                } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    orig_other.push(line.to_owned());
                }
            }
        }

        if !Path::new(&self.backup_path).exists()
            && let Some(current) = &current_content
            && !Self::is_managed_content(current)
        {
            fs::copy(&self.resolv_conf, &self.backup_path)?;
        }

        let mut content = String::from(RESOLV_CONF_HEADER);
        content.push_str("# Original resolv.conf backed up to ");
        content.push_str(&self.backup_path.to_string_lossy());
        content.push('\n');

        for ns in &cfg.nameservers {
            content.push_str("nameserver ");
            content.push_str(ns);
            content.push('\n');
        }
        for ns in &orig_nameservers {
            if !cfg.nameservers.contains(ns) {
                content.push_str("nameserver ");
                content.push_str(ns);
                content.push('\n');
            }
        }

        let mut all_domains: Vec<&str> = Vec::new();
        for domain in cfg.search_domains.iter().chain(cfg.match_domains.iter()) {
            let domain = domain.trim_end_matches('.');
            if !domain.is_empty() && !all_domains.contains(&domain) {
                all_domains.push(domain);
            }
        }
        for domain in &orig_search {
            let domain = domain.trim_end_matches('.');
            if !domain.is_empty() && !all_domains.contains(&domain) {
                all_domains.push(domain);
            }
        }
        if !all_domains.is_empty() {
            content.push_str("search ");
            content.push_str(&all_domains.join(" "));
            content.push('\n');
        }

        let have_search = !all_domains.is_empty();
        for line in &orig_other {
            if have_search {
                let trimmed = line.trim_start();
                if trimmed.starts_with("domain ") || trimmed.starts_with("domain\t") {
                    continue;
                }
            }
            content.push_str(line);
            content.push('\n');
        }

        fs::write(&self.resolv_conf, content)?;
        Ok(())
    }

    fn restore_file(&self) -> io::Result<()> {
        if let Ok(current) = fs::read_to_string(&self.resolv_conf)
            && !Self::is_managed_content(&current)
        {
            return Ok(());
        }

        if self.backup_path.exists() {
            fs::copy(&self.backup_path, &self.resolv_conf)?;
            fs::remove_file(&self.backup_path)?;
        } else {
            let _ = fs::remove_file(&self.resolv_conf);
        }
        Ok(())
    }
}

impl SystemConfig for DirectConfigurator {
    fn prepare(&self) -> io::Result<()> {
        self.restore_file()
    }

    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let mut desired = self.desired.lock().unwrap();
        self.apply_file(cfg)?;
        *desired = Some(cfg.clone());
        Ok(())
    }

    fn refresh(&self) -> io::Result<()> {
        let desired = self.desired.lock().unwrap();
        let Some(cfg) = desired.as_ref() else {
            return Ok(());
        };
        let still_managed = fs::read_to_string(&self.resolv_conf)
            .map(|content| Self::is_managed_content(&content))
            .unwrap_or(false);
        if still_managed {
            return Ok(());
        }
        self.apply_file(cfg)
    }

    fn close(&self) -> io::Result<()> {
        let mut desired = self.desired.lock().unwrap();
        *desired = None;
        self.restore_file()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinkConfig {
    nameservers: Vec<IpAddr>,
    domains: Vec<String>,
    default_route: bool,
    dns_over_tls: String,
    dnssec: String,
}

struct LinkState {
    config: LinkConfig,
    owner: OwnedUniqueName,
}

struct AppliedConfig {
    original: LinkConfig,
    current: LinkConfig,
    desired: LinkConfig,
    owner: OwnedUniqueName,
}

/// Only configures the EasyTier link. Other links retain their DNS settings.
pub struct ResolvedConfigurator {
    interface: String,
    connection: Mutex<Option<Connection>>,
    check_query_path: fn() -> io::Result<()>,
    applied: Mutex<Option<AppliedConfig>>,
}

impl ResolvedConfigurator {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_owned(),
            connection: Mutex::new(None),
            check_query_path: Self::ensure_resolved_in_query_path,
            applied: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn with_connection(
        interface: &str,
        connection: Connection,
        check_query_path: fn() -> io::Result<()>,
    ) -> Self {
        Self {
            interface: interface.to_owned(),
            connection: Mutex::new(Some(connection)),
            check_query_path,
            applied: Mutex::new(None),
        }
    }

    fn connection(&self) -> zbus::Result<Connection> {
        let mut connection = self.connection.lock().unwrap();
        if let Some(connection) = connection.as_ref() {
            return Ok(connection.clone());
        }
        let new = Builder::system()
            .and_then(|builder| builder.method_timeout(DBUS_METHOD_TIMEOUT).build())?;
        *connection = Some(new.clone());
        Ok(new)
    }

    fn probe_dbus(&self) -> zbus::Result<()> {
        let connection = self.connection()?;
        let bus = Proxy::new(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )?;
        let _: OwnedUniqueName = bus.call("GetNameOwner", &(RESOLVED_SERVICE,))?;
        Ok(())
    }

    fn dbus_error(context: &str, error: zbus::Error) -> io::Error {
        let kind = match &error {
            zbus::Error::InputOutput(error) | zbus::Error::Connection(error, _) => error.kind(),
            zbus::Error::FDO(error)
                if matches!(
                    error.as_ref(),
                    zbus::fdo::Error::AccessDenied(_)
                        | zbus::fdo::Error::InteractiveAuthorizationRequired(_)
                ) =>
            {
                io::ErrorKind::PermissionDenied
            }
            zbus::Error::MethodError(name, _, _)
                if matches!(
                    name.as_str(),
                    "org.freedesktop.DBus.Error.AccessDenied"
                        | "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"
                ) =>
            {
                io::ErrorKind::PermissionDenied
            }
            _ => io::ErrorKind::Other,
        };
        io::Error::new(
            kind,
            format!("Magic DNS D-Bus call failed while {context}: {error}"),
        )
    }

    fn ifindex(&self) -> io::Result<i32> {
        let ifindex = nix::net::if_::if_nametoindex(self.interface.as_str()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Cannot find Magic DNS interface {}: {error}",
                    self.interface
                ),
            )
        })?;
        i32::try_from(ifindex).map_err(|_| {
            io::Error::other(format!(
                "Magic DNS interface index {ifindex} exceeds the resolved API range"
            ))
        })
    }

    pub(super) fn uses_resolved(resolv_conf: &str, nsswitch: &str) -> bool {
        resolv_conf.lines().any(|line| {
            let mut words = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace();
            words.next() == Some("nameserver")
                && matches!(words.next(), Some("127.0.0.53" | "127.0.0.54"))
        }) || nsswitch.lines().any(|line| {
            let mut words = line
                .split('#')
                .next()
                .unwrap_or_default()
                .split_whitespace();
            words.next() == Some("hosts:") && words.any(|word| word == "resolve")
        })
    }

    fn decode_nameservers(addresses: Vec<(i32, Vec<u8>)>) -> io::Result<Vec<IpAddr>> {
        addresses
            .into_iter()
            .map(|(family, address)| match (family, address.len()) {
                (nix::libc::AF_INET, 4) => {
                    let mut bytes = [0; 4];
                    bytes.copy_from_slice(&address);
                    Ok(IpAddr::V4(Ipv4Addr::from(bytes)))
                }
                (nix::libc::AF_INET6, 16) => {
                    let mut bytes = [0; 16];
                    bytes.copy_from_slice(&address);
                    Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "resolved returned a DNS address with family {family} and {} bytes",
                        address.len()
                    ),
                )),
            })
            .collect()
    }

    fn read_state(&self) -> io::Result<LinkState> {
        let connection = self
            .connection()
            .map_err(|error| Self::dbus_error("connecting to the system bus", error))?;
        let bus = Proxy::new(
            &connection,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(|error| Self::dbus_error("creating the D-Bus proxy", error))?;
        let owner: OwnedUniqueName = bus
            .call("GetNameOwner", &(RESOLVED_SERVICE,))
            .map_err(|error| Self::dbus_error("getting the resolved service owner", error))?;
        let manager = Proxy::new_owned(
            connection.clone(),
            owner.as_str().to_owned(),
            RESOLVED_MANAGER_PATH,
            RESOLVED_MANAGER_INTERFACE,
        )
        .map_err(|error| Self::dbus_error("creating the resolved manager proxy", error))?;
        let link_path: OwnedObjectPath = manager
            .call("GetLink", &(self.ifindex()?,))
            .map_err(|error| Self::dbus_error("getting the resolved link", error))?;
        let link: Proxy<'_> = ProxyBuilder::new(&connection)
            .destination(owner.as_str().to_owned())
            .map_err(|error| Self::dbus_error("creating the resolved link proxy", error))?
            .path(link_path)
            .map_err(|error| Self::dbus_error("creating the resolved link proxy", error))?
            .interface(RESOLVED_LINK_INTERFACE)
            .map_err(|error| Self::dbus_error("creating the resolved link proxy", error))?
            .cache_properties(CacheProperties::No)
            .build()
            .map_err(|error| Self::dbus_error("creating the resolved link proxy", error))?;
        let nameservers = Self::decode_nameservers(
            link.get_property("DNS")
                .map_err(|error| Self::dbus_error("reading resolved DNS servers", error))?,
        )?;
        let domains = link
            .get_property::<Vec<(String, bool)>>("Domains")
            .map_err(|error| Self::dbus_error("reading resolved domains", error))?
            .into_iter()
            .map(|(domain, route_only)| {
                if route_only {
                    format!("~{domain}")
                } else {
                    domain
                }
            })
            .collect();
        let default_route = link
            .get_property("DefaultRoute")
            .map_err(|error| Self::dbus_error("reading resolved DefaultRoute", error))?;
        let dns_over_tls = link
            .get_property("DNSOverTLS")
            .map_err(|error| Self::dbus_error("reading resolved DNSOverTLS", error))?;
        // Like DNSOverTLS, DNSSEC exposes the effective mode, not whether it
        // was inherited. Cleanup restores this sampled value.
        let dnssec = link
            .get_property("DNSSEC")
            .map_err(|error| Self::dbus_error("reading resolved DNSSEC", error))?;
        let current_owner: OwnedUniqueName = bus
            .call("GetNameOwner", &(RESOLVED_SERVICE,))
            .map_err(|error| Self::dbus_error("checking the resolved service owner", error))?;
        if current_owner != owner {
            return Err(io::Error::other(
                "systemd-resolved restarted while Magic DNS was reading link state",
            ));
        }
        Ok(LinkState {
            config: LinkConfig {
                nameservers,
                domains,
                default_route,
                dns_over_tls,
                dnssec,
            },
            owner,
        })
    }

    fn desired_config(cfg: &OSConfig) -> io::Result<LinkConfig> {
        let mut domains = Vec::new();
        for domain in &cfg.search_domains {
            let domain = domain.trim_end_matches('.');
            if domain.is_empty() || domain.starts_with('~') {
                return Err(io::Error::other("Magic DNS requires non-root domains"));
            }
            if !domains.contains(&domain.to_owned()) {
                domains.push(domain.to_owned());
            }
        }
        for domain in &cfg.match_domains {
            let domain = domain.trim_end_matches('.');
            if domain.is_empty() || domain.starts_with('~') {
                return Err(io::Error::other("Magic DNS requires non-root domains"));
            }
            if !domains.iter().any(|search| search == domain) {
                domains.push(format!("~{domain}"));
            }
        }
        if cfg.nameservers.is_empty() || domains.is_empty() {
            return Err(io::Error::other(
                "Magic DNS requires nameservers and domains",
            ));
        }
        let nameservers = cfg
            .nameservers
            .iter()
            .map(|server| {
                server.parse().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Invalid Magic DNS nameserver {server}: {error}"),
                    )
                })
            })
            .collect::<io::Result<Vec<IpAddr>>>()?;
        Ok(LinkConfig {
            nameservers,
            domains,
            default_route: false,
            dns_over_tls: "no".to_owned(),
            dnssec: "no".to_owned(),
        })
    }

    fn call_manager_on<B>(
        &self,
        service: &str,
        path: &str,
        interface: &str,
        method: &str,
        body: &B,
    ) -> zbus::Result<()>
    where
        B: Serialize + DynamicType,
    {
        let connection = self.connection()?;
        let proxy = Proxy::new(&connection, service, path, interface)?;
        // zbus's blocking call_with_flags bypasses the connection method timeout.
        // A timeout only stops waiting; the peer may still apply the call later.
        let _: Option<()> = zbus::block_on(async {
            tokio::time::timeout(
                connection.method_timeout().unwrap_or(DBUS_METHOD_TIMEOUT),
                proxy.inner().call_with_flags(
                    method,
                    MethodFlags::AllowInteractiveAuth.into(),
                    body,
                ),
            )
            .await
        })
        .map_err(|_| {
            zbus::Error::InputOutput(std::sync::Arc::new(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{service}.{method} did not reply in time"),
            )))
        })??;
        Ok(())
    }

    fn call_manager<B>(&self, resolved_owner: &str, method: &str, body: &B) -> io::Result<()>
    where
        B: Serialize + DynamicType,
    {
        match self.call_manager_on(
            resolved_owner,
            RESOLVED_MANAGER_PATH,
            RESOLVED_MANAGER_INTERFACE,
            method,
            body,
        ) {
            Err(zbus::Error::MethodError(name, _, _)) if name.as_str() == LINK_BUSY_ERROR => self
                .call_manager_on(
                    NETWORKD_SERVICE,
                    NETWORKD_MANAGER_PATH,
                    NETWORKD_MANAGER_INTERFACE,
                    method,
                    body,
                )
                .map_err(|error| Self::dbus_error(method, error)),
            result => result.map_err(|error| Self::dbus_error(method, error)),
        }
    }

    fn write_dnssec(
        &self,
        applied: &mut AppliedConfig,
        ifindex: i32,
        mode: &str,
    ) -> io::Result<()> {
        self.call_manager(applied.owner.as_str(), "SetLinkDNSSEC", &(ifindex, mode))?;
        applied.current.dnssec = mode.to_owned();
        Ok(())
    }

    // Record each successful write so normal cleanup also handles partial setup.
    fn write_config(
        &self,
        applied: &mut AppliedConfig,
        cfg: &LinkConfig,
        restoring: bool,
    ) -> io::Result<()> {
        let ifindex = self.ifindex()?;
        let owner = applied.owner.clone();
        // Disable validation before publishing private DNS. Restore the sampled
        // mode only after withdrawing our DNS servers and domains.
        if !restoring {
            self.write_dnssec(applied, ifindex, &cfg.dnssec)?;
        }
        self.call_manager(
            owner.as_str(),
            "SetLinkDefaultRoute",
            &(ifindex, cfg.default_route),
        )?;
        applied.current.default_route = cfg.default_route;
        let domains: Vec<(String, bool)> = cfg
            .domains
            .iter()
            .map(|domain| {
                if let Some(domain) = domain.strip_prefix('~') {
                    (domain.to_owned(), true)
                } else {
                    (domain.clone(), false)
                }
            })
            .collect();
        self.call_manager(owner.as_str(), "SetLinkDomains", &(ifindex, domains))?;
        applied.current.domains.clone_from(&cfg.domains);
        let nameservers: Vec<(i32, Vec<u8>)> = cfg
            .nameservers
            .iter()
            .map(|server| match server {
                IpAddr::V4(address) => (nix::libc::AF_INET, address.octets().to_vec()),
                IpAddr::V6(address) => (nix::libc::AF_INET6, address.octets().to_vec()),
            })
            .collect();
        self.call_manager(owner.as_str(), "SetLinkDNS", &(ifindex, nameservers))?;
        applied.current.nameservers.clone_from(&cfg.nameservers);
        self.call_manager(
            owner.as_str(),
            "SetLinkDNSOverTLS",
            &(ifindex, cfg.dns_over_tls.as_str()),
        )?;
        applied.current.dns_over_tls.clone_from(&cfg.dns_over_tls);
        if restoring {
            self.write_dnssec(applied, ifindex, &cfg.dnssec)?;
        }
        Ok(())
    }

    fn ensure_resolved_in_query_path() -> io::Result<()> {
        if !Self::uses_resolved(
            &fs::read_to_string("/etc/resolv.conf")?,
            &fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default(),
        ) {
            return Err(io::Error::other(
                "Magic DNS requires system DNS to use the systemd-resolved stub or nss-resolve",
            ));
        }
        Ok(())
    }

    fn apply_config_locked(
        &self,
        state: &mut Option<AppliedConfig>,
        desired: LinkConfig,
    ) -> io::Result<()> {
        if let Some(applied) = state.as_mut() {
            applied.desired = desired.clone();
        }
        let LinkState {
            config: current,
            owner,
        } = self.read_state()?;
        if let Some(applied) = state.as_mut() {
            if owner != applied.owner {
                if current != applied.current {
                    // A nonempty value may contain our own completed but
                    // unacknowledged writes, so only adopt an empty baseline.
                    if current.nameservers.is_empty() && current.domains.is_empty() {
                        applied.original = current.clone();
                    }
                    applied.current.clone_from(&current);
                }
                applied.owner = owner;
            }
        } else {
            if !current.nameservers.is_empty() || !current.domains.is_empty() {
                return Err(io::Error::other(format!(
                    "{} already has DNS settings; refusing to take ownership",
                    self.interface,
                )));
            }
            *state = Some(AppliedConfig {
                original: current.clone(),
                current: current.clone(),
                desired: desired.clone(),
                owner,
            });
        }
        let applied = state.as_mut().unwrap();
        if current == desired {
            applied.current = current;
            return Ok(());
        }
        // Once owned, maintain the latest desired state instead of treating a
        // late reply or external write as a permanent snapshot conflict.
        self.write_config(applied, &desired, false)
    }
}

impl SystemConfig for ResolvedConfigurator {
    fn set_dns(&self, cfg: &OSConfig) -> io::Result<()> {
        let desired = Self::desired_config(cfg)?;
        (self.check_query_path)()?;
        let mut state = self.applied.lock().unwrap();
        self.apply_config_locked(&mut state, desired)
    }

    fn refresh(&self) -> io::Result<()> {
        let mut state = self.applied.lock().unwrap();
        let Some(desired) = state.as_ref().map(|applied| applied.desired.clone()) else {
            return Ok(());
        };
        (self.check_query_path)()?;
        self.apply_config_locked(&mut state, desired)
    }

    fn close(&self) -> io::Result<()> {
        let mut state = self.applied.lock().unwrap();
        let Some(applied) = state.as_mut() else {
            return Ok(());
        };
        if applied.desired == applied.original && applied.current == applied.original {
            *state = None;
            return Ok(());
        }
        let observed = self.read_state()?;
        if observed.owner != applied.owner {
            if observed.config != applied.current {
                *state = None;
                return Ok(());
            }
            applied.owner = observed.owner;
        }
        let original = applied.original.clone();
        self.write_config(applied, &original, true)?;
        *state = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use resolved_fixture::{AF_INET, FixtureConfig, FixtureFailure, ResolvedFixture};
    use zbus::blocking::connection::Builder;

    fn config() -> OSConfig {
        OSConfig {
            nameservers: vec!["100.100.100.101".to_owned()],
            search_domains: vec!["et.test.".to_owned()],
            match_domains: vec!["et.test.".to_owned(), "internal.test.".to_owned()],
        }
    }

    fn original_config() -> FixtureConfig {
        FixtureConfig {
            default_route: true,
            dns_over_tls: "yes".to_owned(),
            dnssec: "yes".to_owned(),
            ..Default::default()
        }
    }

    fn desired_config() -> FixtureConfig {
        FixtureConfig {
            nameservers: vec![(AF_INET, vec![100, 100, 100, 101])],
            domains: vec![
                ("et.test".to_owned(), false),
                ("internal.test".to_owned(), true),
            ],
            default_route: false,
            dns_over_tls: "no".to_owned(),
            dnssec: "no".to_owned(),
        }
    }

    fn updated_config() -> OSConfig {
        OSConfig {
            nameservers: vec!["100.100.100.102".to_owned()],
            search_domains: vec!["new.test.".to_owned()],
            match_domains: vec!["new.test.".to_owned()],
        }
    }

    fn updated_fixture_config() -> FixtureConfig {
        FixtureConfig {
            nameservers: vec![(AF_INET, vec![100, 100, 100, 102])],
            domains: vec![("new.test".to_owned(), false)],
            default_route: false,
            dns_over_tls: "no".to_owned(),
            dnssec: "no".to_owned(),
        }
    }

    fn setup() -> (ResolvedFixture, ResolvedConfigurator) {
        setup_with_timeout(Duration::from_secs(2))
    }

    fn setup_with_timeout(timeout: Duration) -> (ResolvedFixture, ResolvedConfigurator) {
        let fixture = ResolvedFixture::start();
        fixture.set_config(original_config());
        let connection = Builder::address(fixture.address.as_str())
            .unwrap()
            .method_timeout(timeout)
            .build()
            .unwrap();
        let configurator = ResolvedConfigurator::with_connection("lo", connection, || Ok(()));
        (fixture, configurator)
    }

    #[test]
    fn search_domains_and_route_only_domains_are_distinct() {
        let cfg = ResolvedConfigurator::desired_config(&OSConfig {
            nameservers: vec!["100.100.100.101".to_owned()],
            search_domains: vec!["et.net.".to_owned()],
            match_domains: vec!["et.net.".to_owned(), "internal.test.".to_owned()],
        })
        .unwrap();
        assert_eq!(cfg.domains, ["et.net", "~internal.test"]);
        assert!(!cfg.default_route);
        assert_eq!(cfg.dns_over_tls, "no");
        assert_eq!(cfg.dnssec, "no");
    }

    #[test]
    fn refuses_root_domain_routing() {
        assert!(
            ResolvedConfigurator::desired_config(&OSConfig {
                nameservers: vec!["100.100.100.101".to_owned()],
                match_domains: vec![".".to_owned()],
                ..Default::default()
            })
            .is_err()
        );
    }

    #[test]
    fn requires_resolved_in_the_system_query_path() {
        assert!(ResolvedConfigurator::uses_resolved(
            "nameserver 127.0.0.53\n",
            ""
        ));
        assert!(ResolvedConfigurator::uses_resolved(
            "nameserver 192.0.2.53\n",
            "hosts: files resolve [!UNAVAIL=return] dns"
        ));
        assert!(!ResolvedConfigurator::uses_resolved(
            "nameserver 192.0.2.53 # 127.0.0.53\n",
            "hosts: files dns # resolve"
        ));
    }

    #[test]
    fn applies_and_restores_link_config_over_dbus() {
        let (fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        assert_eq!(fixture.config(), desired_config());
        assert!(fixture.interactive());
        assert_eq!(
            fixture.calls(),
            [
                "resolved.SetLinkDNSSEC",
                "resolved.SetLinkDefaultRoute",
                "resolved.SetLinkDomains",
                "resolved.SetLinkDNS",
                "resolved.SetLinkDNSOverTLS",
            ]
        );

        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
        assert_eq!(
            &fixture.calls()[5..],
            [
                "resolved.SetLinkDefaultRoute",
                "resolved.SetLinkDomains",
                "resolved.SetLinkDNS",
                "resolved.SetLinkDNSOverTLS",
                "resolved.SetLinkDNSSEC",
            ]
        );
        configurator.close().unwrap();
    }

    #[test]
    fn refuses_existing_link_dns_before_changing_dnssec() {
        for existing in [
            FixtureConfig {
                nameservers: vec![(AF_INET, vec![192, 0, 2, 53])],
                ..original_config()
            },
            FixtureConfig {
                domains: vec![("external.test".to_owned(), true)],
                ..original_config()
            },
        ] {
            let (fixture, configurator) = setup();
            fixture.set_config(existing.clone());
            assert!(configurator.set_dns(&config()).is_err());
            assert_eq!(fixture.config(), existing);
            assert!(fixture.calls().is_empty());
        }
    }

    #[test]
    fn cleans_up_partial_dbus_writes() {
        let (fixture, configurator) = setup();
        fixture.fail("resolved.SetLinkDomains", FixtureFailure::AccessDenied);
        assert!(configurator.set_dns(&config()).is_err());
        assert!(!fixture.config().default_route);
        assert_eq!(fixture.config().dnssec, "no");

        fixture.clear_failures();
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn cleans_up_after_dns_over_tls_write_fails() {
        let (fixture, configurator) = setup();
        fixture.fail("resolved.SetLinkDNSOverTLS", FixtureFailure::AccessDenied);
        assert!(configurator.set_dns(&config()).is_err());
        let mut partial = desired_config();
        partial.dns_over_tls = "yes".to_owned();
        assert_eq!(fixture.config(), partial);

        fixture.clear_failures();
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn maintains_and_closes_over_external_dbus_changes() {
        let (fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        let mut changed = fixture.config();
        changed.nameservers = vec![(AF_INET, vec![192, 0, 2, 53])];
        changed.dns_over_tls = "yes".to_owned();
        changed.dnssec = "yes".to_owned();
        fixture.set_config(changed);

        configurator.set_dns(&config()).unwrap();
        assert_eq!(fixture.config(), desired_config());
        let mut changed = fixture.config();
        changed.dnssec = "yes".to_owned();
        fixture.set_config(changed);
        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn close_retries_after_dnssec_restore_fails() {
        let (fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.fail("resolved.SetLinkDNSSEC", FixtureFailure::AccessDenied);

        let error = configurator.close().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let mut partial = original_config();
        partial.dnssec = "no".to_owned();
        assert_eq!(fixture.config(), partial);
        assert!(configurator.applied.lock().unwrap().is_some());

        fixture.clear_failures();
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
        assert!(configurator.applied.lock().unwrap().is_none());
    }

    #[test]
    fn refresh_maintains_the_latest_config_after_a_late_write() {
        let (fixture, configurator) = setup_with_timeout(Duration::from_millis(50));
        configurator.set_dns(&config()).unwrap();
        fixture.fail(
            "resolved.SetLinkDNS",
            FixtureFailure::Delay(Duration::from_millis(300)),
        );

        let error = configurator.set_dns(&updated_config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        std::thread::sleep(Duration::from_millis(350));
        assert_eq!(fixture.config(), updated_fixture_config());

        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), updated_fixture_config());
        configurator.set_dns(&config()).unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn a_late_write_can_still_arrive_after_close() {
        let (fixture, configurator) = setup_with_timeout(Duration::from_millis(50));
        configurator.set_dns(&config()).unwrap();
        fixture.fail("resolved.SetLinkDNS", FixtureFailure::Wait);

        let error = configurator.set_dns(&updated_config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let (close_tx, close_rx) = std::sync::mpsc::channel();
        let closer = std::thread::spawn(move || {
            close_tx.send(configurator.close()).unwrap();
        });
        let closed = close_rx.recv_timeout(Duration::from_secs(2));
        if matches!(&closed, Ok(Ok(()))) {
            assert_eq!(fixture.config(), original_config());
        }
        fixture.release_wait();
        closer.join().unwrap();
        closed.unwrap().unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while fixture.config().nameservers != updated_fixture_config().nameservers {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut late = original_config();
        late.nameservers = updated_fixture_config().nameservers;
        assert_eq!(fixture.config(), late);
    }

    #[test]
    fn retained_owner_after_late_write_keeps_original_baseline() {
        let (mut fixture, configurator) = setup_with_timeout(Duration::from_millis(50));
        configurator.set_dns(&config()).unwrap();
        let mut changed = config();
        changed.search_domains = vec!["new.test.".to_owned()];
        changed.match_domains = vec!["new.test.".to_owned()];
        fixture.fail(
            "resolved.SetLinkDomains",
            FixtureFailure::Delay(Duration::from_millis(300)),
        );

        let error = configurator.set_dns(&changed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        std::thread::sleep(Duration::from_millis(350));
        assert_eq!(fixture.config().domains, [("new.test".to_owned(), false)]);
        fixture.restart_resolved_preserving_config();

        configurator.refresh().unwrap();
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn refresh_accepts_changes_from_a_new_resolved_owner() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.restart_resolved();
        let external = FixtureConfig {
            nameservers: vec![(AF_INET, vec![192, 0, 2, 53])],
            domains: vec![("external.test".to_owned(), true)],
            default_route: true,
            dns_over_tls: "yes".to_owned(),
            dnssec: "yes".to_owned(),
        };
        fixture.set_config(external);

        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn link_busy_falls_back_to_networkd() {
        let (fixture, configurator) = setup();
        for method in [
            "resolved.SetLinkDNSSEC",
            "resolved.SetLinkDefaultRoute",
            "resolved.SetLinkDomains",
            "resolved.SetLinkDNS",
            "resolved.SetLinkDNSOverTLS",
        ] {
            fixture.fail(method, FixtureFailure::LinkBusy);
        }

        configurator.set_dns(&config()).unwrap();
        assert_eq!(fixture.config(), desired_config());
        let calls = fixture.calls();
        for method in [
            "networkd.SetLinkDNSSEC",
            "networkd.SetLinkDefaultRoute",
            "networkd.SetLinkDomains",
            "networkd.SetLinkDNS",
            "networkd.SetLinkDNSOverTLS",
        ] {
            assert!(calls.contains(&method.to_owned()));
        }
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn permission_errors_do_not_fall_back_to_networkd() {
        let (fixture, configurator) = setup();
        fixture.fail("resolved.SetLinkDNSSEC", FixtureFailure::AccessDenied);

        let error = configurator.set_dns(&config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fixture.config(), original_config());
        assert_eq!(fixture.calls(), ["resolved.SetLinkDNSSEC"]);
    }

    #[test]
    fn networkd_dnssec_permission_failure_does_not_publish_dns() {
        let (fixture, configurator) = setup();
        fixture.fail("resolved.SetLinkDNSSEC", FixtureFailure::LinkBusy);
        fixture.fail("networkd.SetLinkDNSSEC", FixtureFailure::AccessDenied);

        let error = configurator.set_dns(&config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fixture.config(), original_config());
        assert_eq!(
            fixture.calls(),
            ["resolved.SetLinkDNSSEC", "networkd.SetLinkDNSSEC"]
        );
    }

    #[test]
    fn missing_default_route_method_preserves_partial_setup_for_cleanup() {
        let (fixture, configurator) = setup();
        fixture.fail(
            "resolved.SetLinkDefaultRoute",
            FixtureFailure::UnknownMethod,
        );

        assert!(configurator.set_dns(&config()).is_err());
        let mut partial = original_config();
        partial.dnssec = "no".to_owned();
        assert_eq!(fixture.config(), partial);
        fixture.clear_failures();
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn dbus_calls_honor_the_connection_timeout() {
        let (fixture, configurator) = setup_with_timeout(Duration::from_millis(250));
        fixture.fail(
            "resolved.SetLinkDefaultRoute",
            FixtureFailure::Delay(Duration::from_millis(300)),
        );

        let error = configurator.set_dns(&config()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn refresh_reapplies_config_after_resolved_restarts() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.restart_resolved();
        assert_eq!(fixture.config(), original_config());
        let mut original = original_config();
        original.dnssec = "allow-downgrade".to_owned();
        fixture.set_config(original.clone());

        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original);
    }

    #[test]
    fn persisted_config_remains_owned_after_resolved_restarts() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.restart_resolved_preserving_config();

        configurator.refresh().unwrap();
        assert_eq!(fixture.config(), desired_config());
        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
    }

    #[test]
    fn close_does_not_write_to_a_new_resolved_owner() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        fixture.restart_resolved();
        let calls = fixture.calls();

        configurator.close().unwrap();
        assert_eq!(fixture.config(), original_config());
        assert_eq!(fixture.calls(), calls);
    }

    #[test]
    fn writes_fail_when_the_validated_owner_disappears() {
        let (mut fixture, configurator) = setup();
        configurator.set_dns(&config()).unwrap();
        let desired = configurator
            .applied
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .current
            .clone();
        fixture.restart_resolved();

        let mut state = configurator.applied.lock().unwrap();
        configurator
            .write_config(state.as_mut().unwrap(), &desired, false)
            .unwrap_err();
        assert_eq!(fixture.config(), original_config());
    }

    #[tokio::test]
    async fn constructor_is_safe_in_a_tokio_context() {
        let _configurator = ResolvedConfigurator::new("lo");
        let _linux = new_configurator("lo").unwrap();
    }

    #[test]
    fn direct_configurator_backs_up_merges_refreshes_and_restores_resolv_conf() {
        let temp = tempfile::tempdir().unwrap();
        let resolv = temp.path().join("resolv.conf");
        let backup = temp.path().join("resolv.conf.easytier.bak");
        let initial = "\
# Generated by Docker Engine.
nameserver 127.0.0.53
search host.internal
domain legacy.internal
options edns0 trust-ad
";
        fs::write(&resolv, initial).unwrap();

        let configurator = DirectConfigurator::with_paths(&resolv, &backup);
        configurator.set_dns(&config()).unwrap();
        assert_eq!(fs::read_to_string(&backup).unwrap(), initial);
        let written = fs::read_to_string(&resolv).unwrap();
        assert!(written.starts_with(RESOLV_CONF_HEADER));
        assert!(written.contains("nameserver 100.100.100.101\nnameserver 127.0.0.53\n"));
        assert!(written.contains("search et.test internal.test host.internal\n"));
        assert!(!written.contains("domain legacy.internal"));
        assert!(written.contains("options edns0 trust-ad\n"));

        // Repeated updates must read from the original backup rather than overwriting it.
        configurator.set_dns(&updated_config()).unwrap();
        assert_eq!(fs::read_to_string(&backup).unwrap(), initial);

        // External overwrite is repaired by refresh().
        fs::write(&resolv, "nameserver 8.8.8.8\n").unwrap();
        configurator.refresh().unwrap();
        assert!(
            fs::read_to_string(&resolv)
                .unwrap()
                .starts_with(RESOLV_CONF_HEADER)
        );

        // Crash recovery via prepare() restores the original file cleanly.
        let restarted = DirectConfigurator::with_paths(&resolv, &backup);
        restarted.prepare().unwrap();
        assert_eq!(fs::read_to_string(&resolv).unwrap(), initial);
        assert!(!backup.exists());

        // Normal lifecycle close() also restores the original file cleanly.
        restarted.set_dns(&config()).unwrap();
        restarted.close().unwrap();
        assert_eq!(fs::read_to_string(&resolv).unwrap(), initial);
        assert!(!backup.exists());
    }
}
