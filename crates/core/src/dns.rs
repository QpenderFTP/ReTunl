//! Friendly DNS strings (`77.88.8.8`, `https://1.1.1.1/dns-query`, `tls://dns.google`,
//! `local`) → sing-box 1.14 DNS server objects.

use serde_json::{json, Map, Value};

use crate::util::{is_ip, split_host_port};

/// Ready choices for the settings screen: (value, label).
pub const PRESETS: &[(&str, &str)] = &[
    ("77.88.8.8", "Яндекс DNS"),
    ("1.1.1.1", "Cloudflare"),
    ("8.8.8.8", "Google"),
    ("94.140.14.14", "AdGuard (без рекламы)"),
    ("https://1.1.1.1/dns-query", "Cloudflare DoH"),
    ("https://8.8.8.8/dns-query", "Google DoH"),
    ("https://dns.adguard-dns.com/dns-query", "AdGuard DoH"),
    ("tls://1.1.1.1", "Cloudflare DoT"),
    ("local", "Системный DNS Windows"),
];

/// Build a DNS server. `bootstrap` is the tag used to resolve a resolver
/// given by name (e.g. `dns.google`).
pub fn server(spec: &str, tag: &str, detour: Option<&str>, bootstrap: &str) -> Result<Value, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("пустой адрес DNS".into());
    }
    let mut m = Map::new();
    let lower = spec.to_ascii_lowercase();
    if lower == "local" || lower == "system" {
        m.insert("type".into(), json!("local"));
        m.insert("tag".into(), json!(tag));
        return Ok(Value::Object(m));
    }
    if lower == "dhcp" {
        m.insert("type".into(), json!("dhcp"));
        m.insert("tag".into(), json!(tag));
        return Ok(Value::Object(m));
    }
    let (kind, rest) = match spec.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("udp".to_string(), spec),
    };
    let kind = match kind.as_str() {
        "udp" | "tcp" | "tls" | "https" | "quic" | "h3" => kind,
        "dot" => "tls".into(),
        "doh" => "https".into(),
        other => return Err(format!("неизвестный тип DNS «{other}»")),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    let (host, port) = split_host_port(authority);
    if host.is_empty() {
        return Err(format!("в «{spec}» нет адреса сервера"));
    }
    m.insert("type".into(), json!(kind));
    m.insert("tag".into(), json!(tag));
    m.insert("server".into(), json!(host));
    if let Some(port) = port {
        let port: u16 = port.parse().map_err(|_| format!("неверный порт в «{spec}»"))?;
        m.insert("server_port".into(), json!(port));
    }
    if matches!(kind.as_str(), "https" | "h3") {
        if let Some(path) = path.filter(|p| *p != "/" && *p != "/dns-query") {
            m.insert("path".into(), json!(path));
        }
    }
    if !is_ip(&host) {
        m.insert("domain_resolver".into(), json!(bootstrap));
    }
    if let Some(d) = detour {
        m.insert("detour".into(), json!(d));
    }
    Ok(Value::Object(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes() {
        assert_eq!(server("77.88.8.8", "d", None, "b").unwrap(), json!({"type": "udp", "tag": "d", "server": "77.88.8.8"}));
        assert_eq!(
            server("https://1.1.1.1/dns-query", "r", Some("proxy"), "b").unwrap(),
            json!({"type": "https", "tag": "r", "server": "1.1.1.1", "detour": "proxy"})
        );
        assert_eq!(
            server("tls://dns.google:853", "t", None, "boot").unwrap(),
            json!({"type": "tls", "tag": "t", "server": "dns.google", "server_port": 853, "domain_resolver": "boot"})
        );
        assert_eq!(
            server("https://dns.example.com/custom", "x", None, "b").unwrap()["path"],
            "/custom"
        );
        assert_eq!(server("local", "l", None, "b").unwrap(), json!({"type": "local", "tag": "l"}));
        assert!(server("ftp://x", "x", None, "b").is_err());
        assert_eq!(server("[2606:4700::1111]:53", "v6", None, "b").unwrap()["server"], "2606:4700::1111");
    }
}
