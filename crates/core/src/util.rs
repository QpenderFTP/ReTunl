use std::collections::HashMap;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;

/// The system the app runs on: program paths and some defaults differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Windows,
    MacOs,
}

impl Os {
    pub const CURRENT: Os = if cfg!(target_os = "macos") { Os::MacOs } else { Os::Windows };
}

/// `s` without `suffix`, ignoring ASCII case.
pub fn strip_suffix_ci<'a>(s: &'a str, suffix: &str) -> &'a str {
    let cut = s.len().wrapping_sub(suffix.len());
    if s.len() >= suffix.len() && s.is_char_boundary(cut) && s[cut..].eq_ignore_ascii_case(suffix) {
        &s[..cut]
    } else {
        s
    }
}

/// New random id for profiles, rules and subscriptions.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// Lenient base64: standard or URL-safe alphabet, with or without padding,
/// whitespace and line breaks ignored.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    let unpadded = cleaned.trim_end_matches('=');
    for engine in [&STANDARD, &URL_SAFE] {
        if let Ok(v) = engine.decode(&cleaned) {
            return Some(v);
        }
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(v) = engine.decode(unpadded) {
            return Some(v);
        }
    }
    None
}

pub fn b64_decode_str(s: &str) -> Option<String> {
    String::from_utf8(b64_decode(s)?).ok()
}

pub fn pct_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Query string to a map with lower-case keys. Unlike form decoding, `+` stays `+`
/// (passwords and keys in share links often contain it).
pub fn query_map(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(pct_decode(k).to_ascii_lowercase(), pct_decode(v));
    }
    map
}

/// The pieces of a share link like `scheme://user@host:port/path?query#name`.
/// Hand-written instead of a URL parser because share links break URL rules:
/// port ranges (`host:20000-30000`), raw base64 in the user part, etc.
#[derive(Debug, Clone, Default)]
pub struct LinkParts {
    pub scheme: String,
    /// Raw (still percent-encoded) user info.
    pub userinfo: Option<String>,
    pub host: String,
    /// Raw port text: `443`, `443,20000-30000`, ...
    pub port: Option<String>,
    pub path: String,
    pub query: HashMap<String, String>,
    /// Decoded fragment (usually the server name).
    pub fragment: String,
}

impl LinkParts {
    pub fn parse(link: &str) -> Result<LinkParts, String> {
        let link = link.trim();
        let (scheme, rest) = link
            .split_once("://")
            .ok_or_else(|| "нет схемы вида xxx://".to_string())?;
        let (rest, fragment) = match rest.split_once('#') {
            Some((r, f)) => (r, pct_decode(f)),
            None => (rest, String::new()),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((r, q)) => (r, query_map(q)),
            None => (rest, HashMap::new()),
        };
        let (userinfo, after) = match rest.rfind('@') {
            Some(at) => (Some(rest[..at].to_string()), &rest[at + 1..]),
            None => (None, rest),
        };
        let (hostport, path) = match after.find('/') {
            Some(i) => (&after[..i], after[i..].to_string()),
            None => (after, String::new()),
        };
        let (host, port) = split_host_port(hostport);
        if host.is_empty() {
            return Err("нет адреса сервера".into());
        }
        Ok(LinkParts {
            scheme: scheme.to_ascii_lowercase(),
            userinfo,
            host,
            port,
            path,
            query,
            fragment: fragment.trim().to_string(),
        })
    }

    pub fn user(&self) -> Option<String> {
        self.userinfo.as_deref().map(pct_decode).filter(|s| !s.is_empty())
    }

    pub fn port_u16(&self) -> Result<u16, String> {
        let p = self.port.as_deref().ok_or("не указан порт")?;
        p.parse::<u16>().map_err(|_| format!("неверный порт «{p}»"))
    }

    pub fn q(&self, keys: &[&str]) -> Option<String> {
        for k in keys {
            if let Some(v) = self.query.get(*k) {
                if !v.is_empty() {
                    return Some(v.clone());
                }
            }
        }
        None
    }

    pub fn q_bool(&self, keys: &[&str]) -> bool {
        matches!(self.q(keys).as_deref(), Some("1" | "true" | "yes"))
    }

    /// Fragment or `host:port` when the link has no name.
    pub fn name(&self) -> String {
        if !self.fragment.is_empty() {
            return self.fragment.clone();
        }
        match &self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        }
    }
}

/// `host:port`, `[v6]:port`, `host` → (host without brackets, raw port).
pub fn split_host_port(s: &str) -> (String, Option<String>) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..].strip_prefix(':').map(|p| p.to_string());
            return (host, port.filter(|p| !p.is_empty()));
        }
    }
    // A bare IPv6 address has several colons and no port.
    if s.matches(':').count() > 1 {
        return (s.to_string(), None);
    }
    match s.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), Some(p.to_string()).filter(|p| !p.is_empty())),
        None => (s.to_string(), None),
    }
}

pub fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// Escape for Go RE2 regular expressions used in sing-box rules.
pub fn re_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if r"\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

pub fn split_list(s: &str) -> Vec<String> {
    s.split([',', ';', '\n'])
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_parts_basic() {
        let p = LinkParts::parse("vless://id@example.com:443?type=ws&path=%2Fws#My%20server").unwrap();
        assert_eq!(p.scheme, "vless");
        assert_eq!(p.user().unwrap(), "id");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port_u16().unwrap(), 443);
        assert_eq!(p.query["path"], "/ws");
        assert_eq!(p.name(), "My server");
    }

    #[test]
    fn link_parts_ipv6_and_ranges() {
        let p = LinkParts::parse("hy2://pa+ss@[2001:db8::1]:20000-30000/?obfs=salamander").unwrap();
        assert_eq!(p.host, "2001:db8::1");
        assert_eq!(p.port.as_deref(), Some("20000-30000"));
        assert_eq!(p.user().unwrap(), "pa+ss");
        assert_eq!(p.path, "/");
    }

    #[test]
    fn base64_variants() {
        assert_eq!(b64_decode_str("aGVsbG8gd29ybGQ=").unwrap(), "hello world");
        assert_eq!(b64_decode_str("aGVsbG8gd29ybGQ").unwrap(), "hello world");
        assert_eq!(b64_decode_str("aGVsbG8g\nd29ybGQ=").unwrap(), "hello world");
        // URL-safe alphabet: "-_8" is bytes fb ff
        assert_eq!(b64_decode("-_8").unwrap(), vec![0xfb, 0xff]);
    }

    #[test]
    fn regex_escape() {
        assert_eq!(re_escape(r"C:\Games\a.exe"), r"C:\\Games\\a\.exe");
    }
}
