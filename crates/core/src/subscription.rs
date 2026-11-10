//! Text with links, base64 subscriptions, sing-box JSON and WireGuard files.

use serde_json::Value;

use crate::links::{parse_link, ParsedLink};
use crate::model::{SubscriptionInfo, ENDPOINT_TYPES, PROXY_TYPES};
use crate::util::b64_decode_str;
use crate::wgconf;

#[derive(Debug, Default, Clone)]
pub struct ImportResult {
    pub profiles: Vec<ParsedLink>,
    /// Original share link of each profile (same order), when there was one.
    pub links: Vec<Option<String>>,
    /// (short form of the line, error text)
    pub errors: Vec<(String, String)>,
    pub warnings: Vec<String>,
    /// http(s) lines — most likely subscription addresses.
    pub urls: Vec<String>,
    /// WireSock settings of a WireGuard file (`Id`, `Ip`, `Jd`…).
    pub wiresock: Option<crate::model::WireSock>,
}

/// Parse anything a user may paste or a subscription may return.
pub fn parse_text(text: &str) -> ImportResult {
    parse_inner(text, 0)
}

fn parse_inner(text: &str, depth: u8) -> ImportResult {
    let text = text.trim().trim_start_matches('\u{feff}');
    let mut out = ImportResult::default();
    if text.is_empty() {
        return out;
    }
    if wgconf::looks_like_wg_conf(text) {
        match wgconf::parse(text, "WireGuard") {
            Ok(r) => {
                out.profiles.push(r.profile);
                out.warnings.extend(r.warnings);
                out.wiresock = r.wiresock;
            }
            Err(e) => out.errors.push(("WireGuard-конфиг".into(), e.to_string())),
        }
        return out;
    }
    if text.starts_with('{') || text.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(text) {
            out.profiles = from_singbox_json(&v);
            if out.profiles.is_empty() {
                out.errors.push(("JSON".into(), "в JSON нет серверов (outbounds/endpoints)".into()));
            }
            return out;
        }
    }
    if !text.contains("://") && depth == 0 {
        if let Some(decoded) = b64_decode_str(text) {
            return parse_inner(&decoded, depth + 1);
        }
    }
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("http://") || lower.starts_with("https://") {
            out.urls.push(line.to_string());
            continue;
        }
        match parse_link(line) {
            Ok(p) => {
                out.profiles.push(p);
                out.links.push(Some(line.to_string()));
            }
            Err(e) => out.errors.push((shorten(line), e.to_string())),
        }
    }
    out
}

fn shorten(line: &str) -> String {
    let scheme_end = line.find("://").map(|i| i + 3).unwrap_or(0);
    let name = line.rsplit_once('#').map(|(_, n)| crate::util::pct_decode(n));
    match name {
        Some(n) if !n.trim().is_empty() => format!("{}… {}", &line[..scheme_end], n.trim()),
        _ => line.chars().take(48).collect::<String>() + if line.chars().count() > 48 { "…" } else { "" },
    }
}

/// Servers from a sing-box config (or a bare outbound / list of outbounds).
pub fn from_singbox_json(v: &Value) -> Vec<ParsedLink> {
    let mut items: Vec<&Value> = Vec::new();
    match v {
        Value::Array(list) => items.extend(list.iter()),
        Value::Object(o) => {
            if o.contains_key("outbounds") || o.contains_key("endpoints") {
                for key in ["outbounds", "endpoints"] {
                    if let Some(Value::Array(list)) = o.get(key) {
                        items.extend(list.iter());
                    }
                }
            } else {
                items.push(v);
            }
        }
        _ => {}
    }
    let mut out = Vec::new();
    for item in items {
        let Some(t) = item.get("type").and_then(Value::as_str) else { continue };
        // "direct" is only a server when bound to an adapter
        let is_server = PROXY_TYPES.contains(&t) && (t != "direct" || item.get("bind_interface").is_some());
        if !is_server && !ENDPOINT_TYPES.contains(&t) {
            continue;
        }
        let mut ob = item.clone();
        let name = ob
            .as_object_mut()
            .and_then(|o| o.remove("tag"))
            .and_then(|t| t.as_str().map(str::to_string))
            .unwrap_or_else(|| t.to_string());
        out.push(ParsedLink { name, outbound: ob });
    }
    out
}

/// `subscription-userinfo: upload=1; download=2; total=3; expire=4`
pub fn parse_userinfo(header: &str) -> SubscriptionInfo {
    let mut info = SubscriptionInfo::default();
    for part in header.split(';') {
        let Some((k, v)) = part.split_once('=') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "upload" => info.upload = v.parse().ok(),
            "download" => info.download = v.parse().ok(),
            "total" => info.total = v.parse().ok(),
            "expire" => info.expire = v.parse().ok().filter(|e: &i64| *e > 0),
            _ => {}
        }
    }
    info
}

/// `profile-title: base64:0J/RgNC40LLQtdGC` or plain text.
pub fn decode_title(header: &str) -> Option<String> {
    let h = header.trim();
    let title = match h.strip_prefix("base64:") {
        Some(b) => b64_decode_str(b)?,
        None => h.to_string(),
    };
    Some(title.trim().to_string()).filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::json;

    use super::*;

    const LINKS: &str = "vless://id@a.example.com:443?security=tls#A
# comment
trojan://pw@b.example.com:443#B
vless://id@c.example.com:443?type=kcp&security=tls#C-bad
https://sub.example.com/abc
";

    #[test]
    fn plain_list() {
        let r = parse_text(LINKS);
        assert_eq!(r.profiles.len(), 2);
        assert_eq!(r.errors.len(), 1);
        assert!(r.errors[0].0.contains("C-bad"));
        assert_eq!(r.urls, vec!["https://sub.example.com/abc"]);
    }

    #[test]
    fn base64_list() {
        let r = parse_text(&STANDARD.encode(LINKS));
        assert_eq!(r.profiles.len(), 2);
        assert_eq!(r.profiles[1].name, "B");
    }

    #[test]
    fn singbox_json_config() {
        let cfg = json!({
            "outbounds": [
                {"type": "selector", "tag": "proxy", "outbounds": ["a"]},
                {"type": "vless", "tag": "a", "server": "x", "server_port": 1, "uuid": "u"},
                {"type": "direct", "tag": "direct"},
                {"type": "direct", "tag": "awg", "bind_interface": "AmneziaVPN"}
            ],
            "endpoints": [{"type": "wireguard", "tag": "wg", "address": ["10.0.0.2/32"], "private_key": "k", "peers": []}]
        });
        let r = parse_text(&cfg.to_string());
        let names: Vec<_> = r.profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["a", "awg", "wg"]);
        assert!(r.profiles[0].outbound.get("tag").is_none());
    }

    #[test]
    fn userinfo_and_title() {
        let i = parse_userinfo("upload=455727941; download=6174315083; total=1073741824000; expire=1767225600");
        assert_eq!(i.download, Some(6174315083));
        assert_eq!(i.expire, Some(1767225600));
        assert_eq!(decode_title("base64:0JzQvtC5IFZQTg==").as_deref(), Some("Мой VPN"));
        assert_eq!(decode_title("Plain").as_deref(), Some("Plain"));
    }
}
