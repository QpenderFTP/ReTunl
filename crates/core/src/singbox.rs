//! Turning profiles, rules and settings into a sing-box 1.14 config.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;

use serde_json::{json, Map, Value};

use crate::awg::{self, CoreKind, CoreNeed, CorePref};
use crate::dns;
use crate::model::*;
use crate::rulesets::{self, RuleSetKind, RuleSetSource};
use crate::util::{is_ip, re_escape, strip_suffix_ci, Os};

pub const TAG_DIRECT: &str = "direct";
pub const DNS_DIRECT: &str = "dns-direct";
pub const DNS_REMOTE: &str = "dns-remote";
pub const DNS_BOOTSTRAP: &str = "dns-bootstrap";
const BOOTSTRAP_SERVER: &str = "77.88.8.8";
const RESERVED_TAGS: &[&str] = &[TAG_DIRECT, "tun-in", "mixed-in", "block", "dns"];

#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// Folder with downloaded `.srs` files.
    pub ruleset_dir: PathBuf,
    pub controller_secret: String,
    pub cache_file: Option<PathBuf>,
    /// sing-box-lx is installed (AmneziaWG, XHTTP).
    pub extended_available: bool,
    /// TUN with strict route: send direct DNS to a known public resolver over
    /// TLS (port 853). Strict route on Windows blocks DNS port 53 outside the
    /// tunnel, and on some PCs that catches sing-box's own queries too. The
    /// engine sets it after checking that the resolver answers on 853.
    pub direct_dns_tls: bool,
}

#[derive(Debug, Clone)]
pub struct Built {
    pub config: Value,
    /// Core this config is written for.
    pub core: CoreKind,
    /// Outbound tag → profile id.
    pub tags: HashMap<String, String>,
    /// Rule sets that must exist in `ruleset_dir` before starting.
    pub rule_sets: Vec<RuleSetSource>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
#[error("{0}")]
pub struct BuildError(pub String);

type Res<T> = Result<T, BuildError>;

fn err<T>(msg: impl Into<String>) -> Res<T> {
    Err(BuildError(msg.into()))
}

#[derive(Debug, Clone, PartialEq)]
enum Target {
    Outbound(String),
    Reject,
}

struct Ctx<'a> {
    data: &'a AppData,
    /// profile id → tag
    tag_of: HashMap<String, String>,
    used_tags: HashSet<String>,
    rule_sets: BTreeMap<String, RuleSetSource>,
    warnings: Vec<String>,
}

impl<'a> Ctx<'a> {
    fn tag_for(&mut self, profile: &Profile) -> String {
        if let Some(t) = self.tag_of.get(&profile.id) {
            return t.clone();
        }
        let base = profile.name.trim();
        let base = if base.is_empty() { profile.protocol().to_string() } else { base.to_string() };
        let mut tag = base.clone();
        let mut n = 2;
        while self.used_tags.contains(&tag) || RESERVED_TAGS.contains(&tag.as_str()) || tag.starts_with("dns-") {
            tag = format!("{base} #{n}");
            n += 1;
        }
        self.used_tags.insert(tag.clone());
        self.tag_of.insert(profile.id.clone(), tag.clone());
        tag
    }

    fn target(&mut self, route: &Route, what: &str) -> Res<Target> {
        match route {
            Route::Direct => Ok(Target::Outbound(TAG_DIRECT.into())),
            Route::Block => Ok(Target::Reject),
            Route::Proxy => match self.data.active_profile() {
                Some(p) => Ok(Target::Outbound(self.tag_for(p))),
                None => err(format!("{what} идёт «через VPN», но сервер не выбран. Выберите сервер на вкладке «Серверы».")),
            },
            Route::Profile { id } => match self.data.profile(id) {
                Some(p) => Ok(Target::Outbound(self.tag_for(p))),
                None => err(format!("{what} ссылается на удалённый сервер. Выберите другой сервер в правиле.")),
            },
        }
    }

    fn rule_set_tag(&mut self, entry: &str, rule_name: &str) -> Res<(String, RuleSetKind)> {
        let src = rulesets::resolve(entry).map_err(|e| BuildError(format!("Правило «{rule_name}»: {e}")))?;
        let out = (src.tag.clone(), src.kind);
        self.rule_sets.entry(src.tag.clone()).or_insert(src);
        Ok(out)
    }
}

/// Matcher fields of one user rule, split the way sing-box combines them.
#[derive(Default)]
struct Parts {
    /// process_path_regex
    apps: Vec<String>,
    /// field → values (domain, domain_suffix, domain_keyword, domain_regex, ip_cidr, rule_set)
    dest: BTreeMap<&'static str, Vec<String>>,
    /// Domain-type rule sets (usable in DNS rules).
    domain_sets: Vec<String>,
    ports: Vec<u16>,
    port_ranges: Vec<String>,
    network: Option<String>,
}

impl Parts {
    fn has_dest(&self) -> bool {
        self.dest.values().any(|v| !v.is_empty())
    }
    fn has_filters(&self) -> bool {
        !self.ports.is_empty() || !self.port_ranges.is_empty() || self.network.is_some()
    }
    fn push(&mut self, field: &'static str, v: String) {
        let list = self.dest.entry(field).or_default();
        if !list.contains(&v) {
            list.push(v);
        }
    }
    fn write_filters(&self, m: &mut Map<String, Value>) {
        if !self.ports.is_empty() {
            m.insert("port".into(), json!(self.ports));
        }
        if !self.port_ranges.is_empty() {
            m.insert("port_range".into(), json!(self.port_ranges));
        }
        if let Some(n) = &self.network {
            m.insert("network".into(), json!([n]));
        }
    }
    fn write_apps(&self, m: &mut Map<String, Value>) {
        if !self.apps.is_empty() {
            m.insert("process_path_regex".into(), json!(self.apps));
        }
    }
    fn write_dest(&self, m: &mut Map<String, Value>) {
        for (k, v) in &self.dest {
            if !v.is_empty() {
                m.insert((*k).into(), json!(v));
            }
        }
    }
}

/// How an app entry matches the program's full path.
enum AppMatch {
    /// a program name (escaped), merged with others into one expression
    Name(String),
    /// a whole regex: an exact path or a folder
    Regex(String),
}

fn has_app_suffix(s: &str) -> bool {
    strip_suffix_ci(s, ".app").len() < s.len()
}

fn app_match(entry: &str, os: Os) -> Result<AppMatch, String> {
    let raw = entry.trim().trim_matches('"');
    if raw.is_empty() {
        return Err("пустое имя программы".into());
    }
    let not_app = || format!("«{entry}» — не похоже на программу");
    match os {
        Os::Windows => {
            // a macOS path or bundle from a rule made on a Mac: keep the program name
            let unix = raw.trim_end_matches('/');
            if (raw.starts_with('/') && !raw.starts_with("//")) || has_app_suffix(unix) {
                let base = strip_suffix_ci(unix.rsplit('/').next().unwrap_or(""), ".app");
                if base.is_empty() {
                    return Err(not_app());
                }
                return Ok(AppMatch::Name(re_escape(&format!("{base}.exe"))));
            }
            let e = raw.replace('/', "\\");
            if e.ends_with('\\') {
                // a folder and everything inside it
                return Ok(AppMatch::Regex(format!("(?i)^{}", re_escape(&e))));
            }
            if e.contains('\\') {
                return Ok(AppMatch::Regex(format!("(?i)^{}$", re_escape(&e))));
            }
            let name = if e.contains('.') { e } else { format!("{e}.exe") };
            Ok(AppMatch::Name(re_escape(&name)))
        }
        Os::MacOs => {
            // a Windows path or .exe from a rule made on Windows: keep the program name
            if raw.contains('\\') {
                let base = strip_suffix_ci(raw.trim_end_matches('\\').rsplit('\\').next().unwrap_or(""), ".exe");
                if base.is_empty() {
                    return Err(not_app());
                }
                return Ok(AppMatch::Name(re_escape(base)));
            }
            let path = match raw.strip_prefix("~/") {
                Some(rest) => std::env::var("HOME")
                    .map(|h| format!("{}/{rest}", h.trim_end_matches('/')))
                    .unwrap_or_else(|_| raw.to_string()),
                None => raw.to_string(),
            };
            if path.starts_with('/') {
                let dir = path.trim_end_matches('/');
                // a folder or an .app bundle: everything inside, helpers included
                if path.ends_with('/') || has_app_suffix(dir) {
                    return Ok(AppMatch::Regex(format!("(?i)^{}/", re_escape(dir))));
                }
                return Ok(AppMatch::Regex(format!("(?i)^{}$", re_escape(&path))));
            }
            let name = strip_suffix_ci(strip_suffix_ci(raw.trim_end_matches('/'), ".exe"), ".app");
            if name.is_empty() {
                return Err(not_app());
            }
            Ok(AppMatch::Name(re_escape(name)))
        }
    }
}

/// Program names → one regex: the executable itself, and on macOS also
/// anything inside `<name>.app` (Chromium-based apps talk from helper processes).
fn names_regex(names: &[String], os: Os) -> String {
    let joined = if names.len() == 1 { names[0].clone() } else { format!("(?:{})", names.join("|")) };
    match os {
        Os::Windows => format!("(?i)\\\\{joined}$"),
        Os::MacOs => format!("(?i)/{joined}(?:\\.app/|$)"),
    }
}

/// One app entry → RE2 regex on the full program path, case-insensitive.
pub fn app_regex(entry: &str) -> Result<String, String> {
    app_regex_for(entry, Os::CURRENT)
}

pub fn app_regex_for(entry: &str, os: Os) -> Result<String, String> {
    Ok(match app_match(entry, os)? {
        AppMatch::Name(n) => names_regex(&[n], os),
        AppMatch::Regex(r) => r,
    })
}

/// `example.com`, `*.example.com`, `full:a.b`, `keyword:x`, `regex:…`, URLs → (field, value).
pub fn domain_matcher(entry: &str) -> Result<(&'static str, String), String> {
    let e = entry.trim();
    if e.is_empty() {
        return Err("пустой домен".into());
    }
    if let Some(r) = e.strip_prefix("regex:") {
        return Ok(("domain_regex", r.trim().to_string()));
    }
    // an IP or a subnet typed into the domain list
    if let Ok(c) = cidr(e) {
        return Ok(("ip_cidr", c));
    }
    let lower = e.to_ascii_lowercase();
    let (field, rest) = if let Some(r) = lower.strip_prefix("full:").or_else(|| lower.strip_prefix('=')) {
        ("domain", r.to_string())
    } else if let Some(r) = lower.strip_prefix("keyword:") {
        ("domain_keyword", r.to_string())
    } else if let Some(r) = lower.strip_prefix("domain:").or_else(|| lower.strip_prefix("suffix:")) {
        ("domain_suffix", r.to_string())
    } else {
        ("domain_suffix", lower.clone())
    };
    // tolerate pasted URLs: https://www.example.com/path → www.example.com
    let mut host = rest.trim().to_string();
    if let Some((_, after)) = host.split_once("://") {
        host = after.to_string();
    }
    let host = host.split(['/', '?', '#']).next().unwrap_or("").to_string();
    let host = match host.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => h.to_string(),
        _ => host,
    };
    let host = host.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.').to_string();
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err(format!("«{entry}» не похоже на домен"));
    }
    if field == "domain_keyword" {
        return Ok((field, host));
    }
    if is_ip(&host) || host.contains('/') && host.split('/').next().is_some_and(is_ip) {
        return Ok(("ip_cidr", cidr(&host)?));
    }
    // сайт.рф travels as punycode (xn--80aswg.xn--p1ai): sing-box compares that form
    let host = if host.is_ascii() {
        host
    } else {
        idna::domain_to_ascii(&host).map_err(|_| format!("«{entry}» не похоже на домен"))?
    };
    if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
        return Err(format!("«{entry}» не похоже на домен"));
    }
    Ok((field, host))
}

/// `1.2.3.4` → `1.2.3.4/32`; validates `10.0.0.0/8`, `2001:db8::/32`.
pub fn cidr(entry: &str) -> Result<String, String> {
    let e = entry.trim();
    let (ip, prefix) = match e.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (e, None),
    };
    let addr: IpAddr = ip.parse().map_err(|_| format!("«{entry}» — не IP-адрес"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => {
            let n: u8 = p.parse().map_err(|_| format!("неверная маска в «{entry}»"))?;
            if n > max {
                return Err(format!("неверная маска в «{entry}»"));
            }
            n
        }
        None => max,
    };
    Ok(format!("{addr}/{prefix}"))
}

enum PortSpec {
    One(u16),
    Range(String),
}

fn port(entry: &str) -> Result<PortSpec, String> {
    let e = entry.trim();
    if let Some((a, b)) = e.split_once(['-', ':']) {
        let a: u16 = a.trim().parse().map_err(|_| format!("«{entry}» — неверный диапазон портов"))?;
        let b: u16 = b.trim().parse().map_err(|_| format!("«{entry}» — неверный диапазон портов"))?;
        if a > b {
            return Err(format!("«{entry}» — неверный диапазон портов"));
        }
        return Ok(PortSpec::Range(format!("{a}:{b}")));
    }
    e.parse::<u16>().map(PortSpec::One).map_err(|_| format!("«{entry}» — неверный порт"))
}

fn rule_parts(ctx: &mut Ctx, rule: &Rule) -> Res<Parts> {
    let name = if rule.name.trim().is_empty() { "без названия" } else { rule.name.trim() };
    let bad = |e: String| BuildError(format!("Правило «{name}»: {e}"));
    let mut parts = Parts::default();

    let mut names = Vec::new();
    for app in &rule.apps {
        // plain program names are merged into one expression
        match app_match(app, Os::CURRENT).map_err(bad)? {
            AppMatch::Name(n) => names.push(n),
            AppMatch::Regex(r) => parts.apps.push(r),
        }
    }
    if !names.is_empty() {
        parts.apps.insert(0, names_regex(&names, Os::CURRENT));
    }
    for d in &rule.domains {
        let (field, v) = domain_matcher(d).map_err(bad)?;
        parts.push(field, v);
    }
    for ip in &rule.ips {
        let v = cidr(ip).map_err(bad)?;
        parts.push("ip_cidr", v);
    }
    for rs in &rule.rule_sets {
        let (tag, kind) = ctx.rule_set_tag(rs, name)?;
        if kind == RuleSetKind::Domain && !parts.domain_sets.contains(&tag) {
            parts.domain_sets.push(tag.clone());
        }
        parts.push("rule_set", tag);
    }
    for p in &rule.ports {
        match port(p).map_err(bad)? {
            PortSpec::One(n) => parts.ports.push(n),
            PortSpec::Range(r) => parts.port_ranges.push(r),
        }
    }
    if let Some(n) = rule.network.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        match n.to_ascii_lowercase().as_str() {
            "tcp" | "udp" => parts.network = Some(n.to_ascii_lowercase()),
            _ => return Err(bad(format!("сеть «{n}» — допустимо tcp или udp"))),
        }
    }
    Ok(parts)
}

/// Check the conditions of a rule without building a whole config
/// (used by the rule editor before saving).
pub fn validate_rule(rule: &Rule) -> Result<(), String> {
    if rule.name.trim().is_empty() {
        return Err("Дайте правилу название".into());
    }
    if rule.is_empty() {
        return Err("Добавьте хотя бы одно условие: программу, сайт, IP-адрес, порт или список".into());
    }
    for a in &rule.apps {
        app_regex(a)?;
    }
    for d in &rule.domains {
        domain_matcher(d)?;
    }
    for ip in &rule.ips {
        cidr(ip)?;
    }
    for p in &rule.ports {
        port(p)?;
    }
    for rs in &rule.rule_sets {
        rulesets::resolve(rs)?;
    }
    if let Some(n) = rule.network.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        if !matches!(n.to_ascii_lowercase().as_str(), "tcp" | "udp") {
            return Err(format!("сеть «{n}» — допустимо tcp или udp"));
        }
    }
    Ok(())
}

/// Text fragments that identify a user rule inside the rule descriptions
/// sing-box reports for each connection (`process_path_regex=… => route(x)`).
pub fn rule_signatures(rule: &Rule) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(a) = rule.apps.first() {
        // the escaped name or path appears inside the merged regex too
        match app_match(a, Os::CURRENT) {
            Ok(AppMatch::Name(n)) => out.push(n),
            Ok(AppMatch::Regex(r)) => {
                let body = r.trim_start_matches("(?i)^");
                out.push(body.strip_suffix('$').unwrap_or(body).to_string());
            }
            Err(_) => {}
        }
    }
    if let Some((_, v)) = rule.domains.first().and_then(|d| domain_matcher(d).ok()) {
        out.push(v);
    }
    if let Some(ip) = rule.ips.first().and_then(|i| cidr(i).ok()) {
        out.push(ip);
    }
    if let Some(rs) = rule.rule_sets.first().and_then(|r| rulesets::resolve(r).ok()) {
        out.push(rs.tag);
    }
    out
}

fn with_action(mut m: Map<String, Value>, target: &Target) -> Value {
    match target {
        Target::Outbound(tag) => {
            m.insert("action".into(), json!("route"));
            m.insert("outbound".into(), json!(tag));
        }
        Target::Reject => {
            m.insert("action".into(), json!("reject"));
        }
    }
    Value::Object(m)
}

fn route_rule(parts: &Parts, match_all: bool, target: &Target) -> Value {
    let both = !parts.apps.is_empty() && parts.has_dest();
    if both && !match_all {
        let mut a = Map::new();
        parts.write_apps(&mut a);
        parts.write_filters(&mut a);
        let mut d = Map::new();
        parts.write_dest(&mut d);
        parts.write_filters(&mut d);
        let mut m = Map::new();
        m.insert("type".into(), json!("logical"));
        m.insert("mode".into(), json!("or"));
        m.insert("rules".into(), json!([Value::Object(a), Value::Object(d)]));
        return with_action(m, target);
    }
    let mut m = Map::new();
    parts.write_apps(&mut m);
    parts.write_dest(&mut m);
    parts.write_filters(&mut m);
    with_action(m, target)
}

/// DNS rule for the domain part of a user rule, if it makes sense: DNS
/// queries come from the Windows DNS service, so app conditions can't apply.
fn dns_rule(parts: &Parts, match_all: bool, target: &Target, remote: Option<&str>) -> Option<Value> {
    if match_all && !parts.apps.is_empty() {
        return None;
    }
    // a port-limited block must not kill name resolution for every port
    if *target == Target::Reject && parts.has_filters() {
        return None;
    }
    let mut m = Map::new();
    for field in ["domain", "domain_suffix", "domain_keyword", "domain_regex"] {
        if let Some(v) = parts.dest.get(field).filter(|v| !v.is_empty()) {
            m.insert(field.into(), json!(v));
        }
    }
    if !parts.domain_sets.is_empty() {
        m.insert("rule_set".into(), json!(parts.domain_sets));
    }
    if m.is_empty() {
        return None;
    }
    match target {
        Target::Reject => {
            m.insert("action".into(), json!("reject"));
        }
        Target::Outbound(tag) if tag == TAG_DIRECT => {
            m.insert("action".into(), json!("route"));
            m.insert("server".into(), json!(DNS_DIRECT));
        }
        Target::Outbound(_) => {
            m.insert("action".into(), json!("route"));
            m.insert("server".into(), json!(remote.unwrap_or(DNS_DIRECT)));
        }
    }
    Some(Value::Object(m))
}

/// Full config for the main connection.
pub fn build(data: &AppData, opts: &BuildOptions) -> Res<Built> {
    let s = &data.settings;
    let mut ctx = Ctx {
        data,
        tag_of: HashMap::new(),
        used_tags: HashSet::new(),
        rule_sets: BTreeMap::new(),
        warnings: Vec::new(),
    };

    // 1. user rules → route rules (also decides which servers are needed)
    let final_target = ctx.target(&s.final_route, "Весь остальной трафик")?;
    let mut user_rules: Vec<(Parts, bool, Target)> = Vec::new();
    for rule in data.rules.iter().filter(|r| r.enabled) {
        let label = format!("Правило «{}»", rule.name.trim());
        if rule.is_empty() {
            ctx.warnings.push(format!("{label} пустое и пропущено."));
            continue;
        }
        let target = ctx.target(&rule.route, &label)?;
        let parts = rule_parts(&mut ctx, rule)?;
        user_rules.push((parts, rule.match_all, target));
    }

    // Through which server the remote DNS goes
    let remote_detour: Option<String> = match &final_target {
        Target::Outbound(t) if t != TAG_DIRECT => Some(t.clone()),
        _ => data
            .active_profile()
            .filter(|_| user_rules.iter().any(|(_, _, t)| matches!(t, Target::Outbound(x) if x != TAG_DIRECT)))
            .map(|p| ctx.tag_for(p))
            .or_else(|| {
                user_rules.iter().find_map(|(_, _, t)| match t {
                    Target::Outbound(x) if x != TAG_DIRECT => Some(x.clone()),
                    _ => None,
                })
            }),
    };

    // 2. route
    let mut rules: Vec<Value> = Vec::new();
    if s.sniff {
        rules.push(json!({"action": "sniff"}));
    }
    if s.mode == InboundMode::Tun {
        rules.push(json!({"protocol": "dns", "action": "hijack-dns"}));
    }
    if s.bypass_lan {
        rules.push(json!({"ip_is_private": true, "action": "route", "outbound": TAG_DIRECT}));
    }
    for (parts, match_all, target) in &user_rules {
        rules.push(route_rule(parts, *match_all, target));
    }
    let final_tag = match &final_target {
        Target::Outbound(t) => t.clone(),
        Target::Reject => {
            rules.push(json!({"network": ["tcp", "udp"], "action": "reject"}));
            TAG_DIRECT.to_string()
        }
    };

    // 3. DNS
    let mut dns_servers: Vec<Value> = Vec::new();
    let mut need_bootstrap = false;
    let dot = opts.direct_dns_tls && s.mode == InboundMode::Tun && s.tun.strict_route;
    let direct_spec = match dns::dot_ip(&s.dns.direct) {
        Some(ip) if dot => format!("tls://{ip}"),
        _ => s.dns.direct.clone(),
    };
    let direct = dns::server(&direct_spec, DNS_DIRECT, None, DNS_BOOTSTRAP)
        .map_err(|e| BuildError(format!("DNS для прямого трафика: {e}")))?;
    need_bootstrap |= direct.get("domain_resolver").is_some();
    dns_servers.push(direct);
    let remote_tag = match &remote_detour {
        Some(detour) => {
            let remote = dns::server(&s.dns.remote, DNS_REMOTE, Some(detour), DNS_BOOTSTRAP)
                .map_err(|e| BuildError(format!("DNS через VPN: {e}")))?;
            need_bootstrap |= remote.get("domain_resolver").is_some();
            dns_servers.push(remote);
            Some(DNS_REMOTE)
        }
        None => None,
    };
    if need_bootstrap {
        dns_servers.push(json!({"type": if dot { "tls" } else { "udp" }, "tag": DNS_BOOTSTRAP, "server": BOOTSTRAP_SERVER}));
    }
    let mut dns_rules: Vec<Value> = Vec::new();
    for (parts, match_all, target) in &user_rules {
        if let Some(r) = dns_rule(parts, *match_all, target, remote_tag) {
            dns_rules.push(r);
        }
    }
    let dns_final = match (s.dns.policy, remote_tag) {
        (DnsPolicy::Direct, _) | (_, None) => DNS_DIRECT,
        (DnsPolicy::Remote, Some(r)) => r,
        (DnsPolicy::Auto, Some(r)) => {
            if matches!(&final_target, Target::Outbound(t) if t != TAG_DIRECT) {
                r
            } else {
                DNS_DIRECT
            }
        }
    };
    let mut dns_obj = Map::new();
    dns_obj.insert("servers".into(), Value::Array(dns_servers));
    if !dns_rules.is_empty() {
        dns_obj.insert("rules".into(), Value::Array(dns_rules));
    }
    dns_obj.insert("final".into(), json!(dns_final));
    dns_obj.insert("strategy".into(), json!(if s.ipv6 { "prefer_ipv4" } else { "ipv4_only" }));

    // 4. outbounds and endpoints (only servers that are actually used)
    let mut direct_ob = Map::new();
    direct_ob.insert("type".into(), json!("direct"));
    direct_ob.insert("tag".into(), json!(TAG_DIRECT));
    if let Some(iface) = s.direct_interface.as_deref().filter(|i| !i.trim().is_empty()) {
        direct_ob.insert("bind_interface".into(), json!(iface.trim()));
    }
    let mut outbounds = vec![Value::Object(direct_ob)];
    let mut endpoints = Vec::new();
    let mut tags = HashMap::new();
    let mut used: Vec<(&Profile, String)> = data
        .profiles
        .iter()
        .filter_map(|p| ctx.tag_of.get(&p.id).map(|t| (p, t.clone())))
        .collect();
    used.sort_by(|a, b| a.1.cmp(&b.1));
    let core = choose_core(s.core, used.iter().map(|(p, _)| *p), opts.extended_available)?;
    for (p, tag) in used {
        let mut ob = p
            .outbound
            .as_object()
            .cloned()
            .ok_or_else(|| BuildError(format!("Сервер «{}» повреждён: настройки не являются JSON-объектом", p.name)))?;
        if !ob.contains_key("type") {
            return err(format!("У сервера «{}» не указан тип протокола", p.name));
        }
        if core == CoreKind::Official && awg::strip_for_official(&mut ob) {
            ctx.warnings.push(format!(
                "У сервера «{}» не отправляются мусорные пакеты AmneziaWG (Jc/Jmin/Jmax): официальное ядро их не умеет. \
                 Скачайте ядро sing-box-lx в настройках, чтобы маскировка работала полностью.",
                p.name
            ));
        }
        ob.insert("tag".into(), json!(tag));
        tags.insert(tag.clone(), p.id.clone());
        if p.is_endpoint() {
            endpoints.push(Value::Object(ob));
        } else {
            outbounds.push(Value::Object(ob));
        }
    }

    // 5. inbounds
    let inbound = match s.mode {
        InboundMode::Tun => {
            let mut address = vec![json!("172.19.0.1/30")];
            if s.ipv6 {
                address.push(json!("fdfe:dcba:9876::1/126"));
            }
            let stack = match s.tun.stack.as_str() {
                "system" | "gvisor" | "mixed" => s.tun.stack.clone(),
                _ => "mixed".into(),
            };
            let mut tun = json!({
                "type": "tun",
                "tag": "tun-in",
                "address": address,
                "mtu": s.tun.mtu.clamp(1280, 65535),
                "auto_route": true,
                "strict_route": s.tun.strict_route,
                "stack": stack,
            });
            // macOS names tunnels itself (utunN)
            if Os::CURRENT == Os::Windows {
                let name = if s.tun.interface_name.trim().is_empty() { "ReTunl" } else { s.tun.interface_name.trim() };
                tun["interface_name"] = json!(name);
            }
            tun
        }
        InboundMode::SystemProxy => json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": s.mixed_port,
            "set_system_proxy": true,
        }),
    };

    // 6. rule sets
    let rule_sets: Vec<RuleSetSource> = ctx.rule_sets.values().cloned().collect();
    let rule_set_json: Vec<Value> = rule_sets
        .iter()
        .map(|r| {
            json!({
                "type": "local",
                "tag": r.tag,
                "format": "binary",
                "path": opts.ruleset_dir.join(&r.file_name).to_string_lossy(),
            })
        })
        .collect();

    let mut route = Map::new();
    route.insert("rules".into(), Value::Array(rules));
    if !rule_set_json.is_empty() {
        route.insert("rule_set".into(), Value::Array(rule_set_json));
    }
    route.insert("final".into(), json!(final_tag));
    route.insert("auto_detect_interface".into(), json!(true));
    route.insert("find_process".into(), json!(true));
    route.insert("default_domain_resolver".into(), json!(DNS_DIRECT));

    let mut experimental = Map::new();
    experimental.insert(
        "clash_api".into(),
        json!({"external_controller": format!("127.0.0.1:{}", s.controller_port), "secret": opts.controller_secret}),
    );
    if let Some(cache) = &opts.cache_file {
        experimental.insert("cache_file".into(), json!({"enabled": true, "path": cache.to_string_lossy()}));
    }

    let mut config = Map::new();
    config.insert("log".into(), json!({"level": log_level(&s.log_level), "timestamp": true}));
    config.insert("dns".into(), Value::Object(dns_obj));
    config.insert("inbounds".into(), json!([inbound]));
    config.insert("outbounds".into(), Value::Array(outbounds));
    if !endpoints.is_empty() {
        config.insert("endpoints".into(), Value::Array(endpoints));
    }
    config.insert("route".into(), Value::Object(route));
    config.insert("experimental".into(), Value::Object(experimental));

    Ok(Built { config: Value::Object(config), core, tags, rule_sets, warnings: ctx.warnings })
}

/// Text of the error when a server needs sing-box-lx; the UI looks for the
/// [`NEED_EXTENDED`] marker to offer the download.
pub const NEED_EXTENDED: &str = "ядро sing-box-lx";

/// Core for a set of servers, with a clear error when sing-box-lx is needed.
pub fn choose_core<'a>(
    pref: CorePref,
    profiles: impl Iterator<Item = &'a Profile>,
    extended_available: bool,
) -> Res<CoreKind> {
    let mut need = CoreNeed::Any;
    let mut strict: Vec<&Profile> = Vec::new();
    for p in profiles {
        let n = p.core_need();
        if n == CoreNeed::Extended {
            strict.push(p);
        }
        need = need.max(n);
    }
    awg::pick_core(pref, need, extended_available).map_err(|_| {
        let names: Vec<String> = strict
            .iter()
            .take(3)
            .map(|p| format!("«{}» ({})", p.name, awg::need_reason(&p.outbound)))
            .collect();
        let who = match names.len() {
            0 => "В настройках выбрано".to_string(),
            1 => format!("Сервер {} работает только через", names[0]),
            _ => format!("Серверы {} работают только через", names.join(", ")),
        };
        BuildError(match (pref, extended_available) {
            (CorePref::Official, _) => format!(
                "{who} {NEED_EXTENDED}, а в настройках выбрано официальное ядро. Переключите ядро в «Настройки» → «Ядро и списки»."
            ),
            _ => format!("{who} {NEED_EXTENDED}. Скачайте его в «Настройки» → «Ядро и списки»."),
        })
    })
}

fn log_level(l: &str) -> &'static str {
    match l {
        "trace" => "trace",
        "debug" => "debug",
        "warn" => "warn",
        "error" => "error",
        _ => "info",
    }
}

/// Probe config: every given server as an outbound tagged with its id, no
/// inbounds, control API on `port`. Used for real latency tests via
/// `GET /proxies/{id}/delay` without touching system networking.
pub fn build_probe(profiles: &[&Profile], settings: &Settings, port: u16, secret: &str, core: CoreKind) -> Res<Value> {
    let direct = dns::server(&settings.dns.direct, DNS_DIRECT, None, DNS_BOOTSTRAP)
        .map_err(|e| BuildError(format!("DNS: {e}")))?;
    let mut servers = vec![direct.clone()];
    if direct.get("domain_resolver").is_some() {
        servers.push(json!({"type": "udp", "tag": DNS_BOOTSTRAP, "server": BOOTSTRAP_SERVER}));
    }
    let mut outbounds = vec![json!({"type": "direct", "tag": TAG_DIRECT})];
    let mut endpoints = Vec::new();
    for p in profiles {
        let Some(mut ob) = p.outbound.as_object().cloned() else { continue };
        if core == CoreKind::Official {
            awg::strip_for_official(&mut ob);
        }
        ob.insert("tag".into(), json!(p.id));
        if p.is_endpoint() {
            endpoints.push(Value::Object(ob));
        } else {
            outbounds.push(Value::Object(ob));
        }
    }
    let mut config = json!({
        "log": {"level": "warn", "timestamp": true},
        "dns": {"servers": servers, "final": DNS_DIRECT, "strategy": if settings.ipv6 { "prefer_ipv4" } else { "ipv4_only" }},
        "outbounds": outbounds,
        "route": {"final": TAG_DIRECT, "auto_detect_interface": true, "default_domain_resolver": DNS_DIRECT},
        "experimental": {"clash_api": {"external_controller": format!("127.0.0.1:{port}"), "secret": secret}},
    });
    if !endpoints.is_empty() {
        config["endpoints"] = Value::Array(endpoints);
    }
    Ok(config)
}

#[cfg(test)]
mod tests;
