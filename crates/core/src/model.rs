use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One server ("tunnel"). The connection itself is stored as a ready
/// sing-box outbound (or endpoint for WireGuard) without its `tag`, so every
/// option sing-box knows can be kept and edited as JSON.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub outbound: Value,
    /// Subscription this server came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<String>,
    /// Original share link, if imported from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default)]
    pub created_at: i64,
    /// Manual VLESS transport choice. Older profiles omitted the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xray: Option<bool>,
    /// WireGuard through WireSock VPN Client (Windows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wiresock: Option<WireSock>,
    /// The adapter of Cisco Secure Client, which ReTunl logs in and out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cisco: Option<Cisco>,
}

/// A server that is Cisco Secure Client (AnyConnect) on Windows. ReTunl logs
/// in through its command line (vpncli) and sends the traffic of its rules
/// into Cisco's network adapter: the `outbound` is `direct` bound to it. The
/// password is asked at each login and never kept.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct Cisco {
    /// The VPN server: an address or a name from Cisco's own list.
    pub host: String,
    /// The group (connection profile) the server asks for; empty: it asks none.
    pub group: String,
    pub username: String,
    /// Log out of Cisco when ReTunl disconnects.
    pub disconnect: bool,
}

/// How a WireGuard server goes through WireSock VPN Client: WireSock masks
/// the handshake (fake QUIC/DNS packets, junk packets) where plain WireGuard
/// is blocked. The masking is sent by the client only, so any WireGuard server
/// takes it. Junk packets (Jc, Jmin, Jmax) stay in the server's own fields.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct WireSock {
    pub enabled: bool,
    /// `Id`: a popular site the traffic pretends to go to.
    pub domain: String,
    /// `Ip`: `quic`, `dns`, `sip` or `stun`; empty: no masking.
    pub protocol: String,
    /// `Ib`: `chrome`, `firefox` or `curl` (QUIC only).
    pub browser: String,
    /// `Jd`: pause between junk packets, milliseconds.
    pub junk_delay: u32,
}

/// sing-box types that live in `endpoints`, not `outbounds`.
pub const ENDPOINT_TYPES: &[&str] = &["wireguard", "tailscale"];

/// sing-box outbound types we accept as servers.
pub const PROXY_TYPES: &[&str] = &[
    "vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "wireguard",
    "socks", "http", "anytls", "shadowtls", "ssh", "naive", "tailscale", "direct",
];

impl Profile {
    /// A server with only its connection: no subscription, link or extras.
    pub fn new(id: impl Into<String>, name: impl Into<String>, outbound: Value) -> Profile {
        Profile { id: id.into(), name: name.into(), outbound, subscription: None, link: None, created_at: 0, xray: None, wiresock: None, cisco: None }
    }

    pub fn protocol(&self) -> &str {
        self.outbound.get("type").and_then(Value::as_str).unwrap_or("?")
    }

    pub fn uses_xray(&self) -> bool {
        self.uses_xray_on(crate::util::Os::CURRENT)
    }

    pub(crate) fn uses_xray_on(&self, os: crate::util::Os) -> bool {
        os == crate::util::Os::Windows && self.protocol() == "vless"
            && self.xray.unwrap_or_else(|| crate::xray::vless(&self.outbound).is_ok())
    }

    pub fn is_endpoint(&self) -> bool {
        ENDPOINT_TYPES.contains(&self.protocol())
    }

    /// `direct` bound to another adapter (AmneziaVPN, Tailscale, OpenVPN...).
    pub fn is_interface(&self) -> bool {
        self.protocol() == "direct"
    }

    /// Human label of the protocol.
    pub fn protocol_label(&self) -> String {
        let t = self.protocol();
        let base = match t {
            "vless" => "VLESS",
            "vmess" => "VMess",
            "trojan" => "Trojan",
            "shadowsocks" => "Shadowsocks",
            "hysteria" => "Hysteria",
            "hysteria2" => "Hysteria2",
            "tuic" => "TUIC",
            "wireguard" if crate::awg::is_amnezia(&self.outbound) => "AmneziaWG",
            "wireguard" => "WireGuard",
            "socks" => "SOCKS",
            "http" => "HTTP",
            "anytls" => "AnyTLS",
            "direct" => "Интерфейс",
            other => other,
        };
        let reality = self
            .outbound
            .pointer("/tls/reality/enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let transport = self.outbound.pointer("/transport/type").and_then(Value::as_str);
        match (reality, transport) {
            (true, Some(tr)) => format!("{base} · Reality · {tr}"),
            (true, None) => format!("{base} · Reality"),
            (false, Some(tr)) => format!("{base} · {tr}"),
            (false, None) => base.to_string(),
        }
    }

    /// Server address and port for display and TCP ping.
    pub fn address(&self) -> Option<(String, u16)> {
        let ob = &self.outbound;
        if self.is_endpoint() {
            let peer = ob.pointer("/peers/0")?;
            let host = peer.get("address")?.as_str()?.to_string();
            let port = peer.get("port")?.as_u64()? as u16;
            return Some((host, port));
        }
        let host = ob.get("server")?.as_str()?.to_string();
        let port = ob
            .get("server_port")
            .and_then(Value::as_u64)
            .map(|p| p as u16)
            .or_else(|| {
                // hysteria2 port hopping: first port of the first range
                ob.pointer("/server_ports/0")
                    .and_then(Value::as_str)
                    .and_then(|r| r.split(':').next())
                    .and_then(|p| p.parse().ok())
            })?;
        Some((host, port))
    }

    /// Cisco Secure Client's adapter.
    pub fn is_cisco(&self) -> bool {
        self.cisco.is_some() && self.is_interface()
    }

    /// A WireGuard server switched to WireSock.
    pub fn uses_wiresock(&self) -> bool {
        self.protocol() == "wireguard" && self.wiresock.as_ref().is_some_and(|w| w.enabled)
    }

    /// Whether this server needs the sing-box-lx core.
    pub fn core_need(&self) -> crate::awg::CoreNeed {
        crate::awg::core_need(&self.outbound)
    }

    /// True if the protocol runs over UDP only (TCP ping is meaningless).
    pub fn is_udp_only(&self) -> bool {
        matches!(self.protocol(), "hysteria" | "hysteria2" | "tuic" | "wireguard")
            || self.outbound.pointer("/transport/type").and_then(Value::as_str) == Some("quic")
    }
}

/// Where a rule (or all unmatched traffic) goes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Route {
    /// The currently selected server.
    #[default]
    Proxy,
    /// A specific server, regardless of the selected one.
    Profile { id: String },
    /// Bypass the tunnel.
    Direct,
    /// Drop the connection.
    Block,
}

/// A split-tunnel rule.
///
/// Conditions come in two groups: *who* (apps) and *where* (domains, IPs and
/// rule sets together). By default a connection matches if either group
/// matches ("Discord app **or** Discord sites"); with `match_all` both must
/// ("Chrome **and** only YouTube"). Ports and network always narrow the rule.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub match_all: bool,
    /// `chrome.exe`, `C:\Path\app.exe`, or a folder `C:\Games\` (ends with `\`).
    #[serde(default)]
    pub apps: Vec<String>,
    /// `example.com` (with subdomains), `full:a.example.com`, `keyword:goog`, `regex:...`.
    #[serde(default)]
    pub domains: Vec<String>,
    /// `1.2.3.4`, `10.0.0.0/8`, `2001:db8::/32`.
    #[serde(default)]
    pub ips: Vec<String>,
    /// `443`, `27000-27100`.
    #[serde(default)]
    pub ports: Vec<String>,
    /// Rule-set tags like `geosite-youtube`, `geoip-ru` or an `https://….srs` URL.
    #[serde(default)]
    pub rule_sets: Vec<String>,
    /// `tcp` or `udp`; empty = both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub route: Route,
    /// Preset id this rule was created from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
}

fn yes() -> bool {
    true
}

/// The user's own preset: a rule template kept in the gallery next to the
/// built-in ones. Applying it adds a rule with the same conditions.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct CustomPreset {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub match_all: bool,
    #[serde(default)]
    pub apps: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub rule_sets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default)]
    pub route: Route,
    #[serde(default)]
    pub created_at: i64,
}

impl CustomPreset {
    /// A new rule made from this preset.
    pub fn to_rule(&self, id: String) -> Rule {
        Rule {
            id,
            name: self.title.clone(),
            enabled: true,
            match_all: self.match_all,
            apps: self.apps.clone(),
            domains: self.domains.clone(),
            ips: self.ips.clone(),
            ports: self.ports.clone(),
            rule_sets: self.rule_sets.clone(),
            network: self.network.clone(),
            route: self.route.clone(),
            preset: Some(self.id.clone()),
        }
    }

    /// The conditions of a rule as a preset.
    pub fn from_rule(rule: &Rule, id: String, title: String, description: String, created_at: i64) -> CustomPreset {
        CustomPreset {
            id,
            title,
            description,
            match_all: rule.match_all,
            apps: rule.apps.clone(),
            domains: rule.domains.clone(),
            ips: rule.ips.clone(),
            ports: rule.ports.clone(),
            rule_sets: rule.rule_sets.clone(),
            network: rule.network.clone(),
            route: rule.route.clone(),
            created_at,
        }
    }
}

impl Rule {
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
            && self.domains.is_empty()
            && self.ips.is_empty()
            && self.ports.is_empty()
            && self.rule_sets.is_empty()
            && self.network.is_none()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InboundMode {
    /// Virtual adapter: all programs, needs administrator rights.
    #[default]
    Tun,
    /// Windows system proxy: only programs that honour it, no admin rights.
    SystemProxy,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsPolicy {
    /// Follow the default route: through the tunnel if unmatched traffic goes there.
    #[default]
    Auto,
    Remote,
    Direct,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DnsSettings {
    /// Resolver for direct traffic and for server addresses.
    pub direct: String,
    /// Resolver used through the tunnel.
    pub remote: String,
    pub policy: DnsPolicy,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            direct: "77.88.8.8".into(),
            remote: "https://1.1.1.1/dns-query".into(),
            policy: DnsPolicy::Auto,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TunSettings {
    pub interface_name: String,
    /// `mixed`, `system` or `gvisor`.
    pub stack: String,
    pub mtu: u32,
    /// Block traffic that tries to go around the adapter (DNS leaks etc.).
    pub strict_route: bool,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            interface_name: "ReTunl".into(),
            stack: "mixed".into(),
            mtu: 9000,
            strict_route: false,
        }
    }
}

/// What the speed test downloads and through which server.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct SpeedPrefs {
    /// Ids of the test servers to choose from, built-in or the user's own.
    /// Empty: ReTunl picks among its usual ones.
    pub targets: Vec<String>,
    /// The user's own test servers.
    pub custom: Vec<SpeedCustom>,
    /// Server the VPN part goes through; `None`: the selected one.
    pub profile: Option<String>,
}

/// A test server the user added: any large file over HTTP(S).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct SpeedCustom {
    pub id: String,
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub mode: InboundMode,
    /// Traffic that no rule matched.
    pub final_route: Route,
    pub active_profile: Option<String>,
    /// Keep LAN, loopback and other private ranges off the tunnel.
    pub bypass_lan: bool,
    pub ipv6: bool,
    pub sniff: bool,
    pub dns: DnsSettings,
    pub tun: TunSettings,
    /// Local proxy port in system-proxy mode.
    pub mixed_port: u16,
    /// sing-box control API port (127.0.0.1 only).
    pub controller_port: u16,
    /// Physical adapter for direct traffic; empty = detect automatically.
    pub direct_interface: Option<String>,
    pub log_level: String,
    pub test_url: String,
    /// Official sing-box or sing-box-lx (AmneziaWG, XHTTP).
    pub core: crate::awg::CorePref,
    pub connect_on_launch: bool,
    pub close_to_tray: bool,
    pub start_minimized: bool,
    /// Windows: every start is elevated. A start by hand asks UAC; autostart goes
    /// through Task Scheduler and does not.
    pub run_as_admin: bool,
    pub speed: SpeedPrefs,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: InboundMode::Tun,
            final_route: Route::Proxy,
            active_profile: None,
            bypass_lan: true,
            ipv6: false,
            sniff: true,
            dns: DnsSettings::default(),
            tun: TunSettings::default(),
            mixed_port: 2080,
            controller_port: 19190,
            direct_interface: None,
            log_level: "info".into(),
            test_url: "https://www.gstatic.com/generate_204".into(),
            core: crate::awg::CorePref::Auto,
            connect_on_launch: false,
            close_to_tray: true,
            // only applies when started by autostart
            start_minimized: true,
            // «Все программы», the default mode, needs admin rights on Windows anyway
            run_as_admin: true,
            speed: SpeedPrefs::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct SubscriptionInfo {
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub updated_at: Option<i64>,
    #[serde(default)]
    pub info: Option<SubscriptionInfo>,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// Everything the app saves to disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppData {
    pub version: u32,
    pub profiles: Vec<Profile>,
    pub subscriptions: Vec<Subscription>,
    pub rules: Vec<Rule>,
    /// The user's own presets for the rule gallery.
    pub presets: Vec<CustomPreset>,
    pub settings: Settings,
}

impl Default for AppData {
    fn default() -> Self {
        Self {
            version: 1,
            profiles: Vec::new(),
            subscriptions: Vec::new(),
            rules: Vec::new(),
            presets: Vec::new(),
            settings: Settings::default(),
        }
    }
}

impl AppData {
    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn profile_mut(&mut self, id: &str) -> Option<&mut Profile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }

    pub fn active_profile(&self) -> Option<&Profile> {
        self.settings.active_profile.as_deref().and_then(|id| self.profile(id))
    }
}
