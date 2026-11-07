//! Share links (`vless://`, `hy2://`, `ss://` ...) → sing-box outbounds.

mod amnezia;
mod other;
mod quic;
mod ss;
mod v2ray;

use serde_json::{json, Map, Value};

use crate::util::{is_ip, split_list, LinkParts};

pub use amnezia::{admin_access, AdminAccess};
pub(crate) use other::with_prefix;

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedLink {
    pub name: String,
    /// sing-box outbound / endpoint without `tag`.
    pub outbound: Value,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum LinkError {
    #[error("неизвестный тип ссылки «{0}»")]
    UnknownScheme(String),
    #[error("ошибка в ссылке: {0}")]
    Invalid(String),
    #[error("не поддерживается: {0}")]
    Unsupported(String),
}

impl From<String> for LinkError {
    fn from(s: String) -> Self {
        LinkError::Invalid(s)
    }
}

impl From<&str> for LinkError {
    fn from(s: &str) -> Self {
        LinkError::Invalid(s.to_string())
    }
}

pub type LinkResult = Result<ParsedLink, LinkError>;

/// Schemes [`parse_link`] understands.
pub const SCHEMES: &[&str] = &[
    "vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "hysteria", "tuic", "wireguard", "wg",
    "socks", "socks5", "anytls", "vpn",
];

pub fn parse_link(link: &str) -> LinkResult {
    let link = link.trim();
    let scheme = link
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or_else(|| LinkError::Invalid("это не ссылка вида протокол://…".into()))?;
    match scheme.as_str() {
        "vless" => v2ray::vless(link),
        "vmess" => v2ray::vmess(link),
        "trojan" => v2ray::trojan(link),
        "ss" => ss::parse(link),
        "hysteria2" | "hy2" => quic::hysteria2(link),
        "hysteria" => quic::hysteria(link),
        "tuic" => quic::tuic(link),
        "wireguard" | "wg" => other::wireguard(link),
        "socks" | "socks5" | "socks5h" => other::socks(link),
        "anytls" => other::anytls(link),
        "vpn" => amnezia::parse(link),
        "ssr" => Err(LinkError::Unsupported("ShadowsocksR устарел и не поддерживается sing-box".into())),
        other => Err(LinkError::UnknownScheme(other.to_string())),
    }
}

/// TLS block from the usual share-link parameters
/// (`security`, `sni`, `alpn`, `fp`, `pbk`, `sid`, `allowInsecure`).
pub(crate) fn tls_from(p: &LinkParts, security: &str) -> Result<Option<Value>, LinkError> {
    match security {
        "" | "none" => return Ok(None),
        "tls" | "xtls" | "reality" => {}
        other => return Err(LinkError::Unsupported(format!("шифрование security={other}"))),
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    let sni = p.q(&["sni", "peer", "servername"]).or_else(|| {
        // Without SNI sing-box sends the server address, which is what we want
        // for a domain; for an IP address a `host` parameter is the better guess.
        if is_ip(&p.host) {
            p.q(&["host"]).map(|h| h.split(',').next().unwrap_or("").trim().to_string())
        } else {
            None
        }
    });
    if let Some(sni) = sni.filter(|s| !s.is_empty()) {
        tls.insert("server_name".into(), json!(sni));
    }
    if p.q_bool(&["allowinsecure", "insecure", "allow_insecure", "skip-cert-verify"]) {
        tls.insert("insecure".into(), json!(true));
    }
    if let Some(alpn) = p.q(&["alpn"]) {
        let list = split_list(&alpn);
        if !list.is_empty() {
            tls.insert("alpn".into(), json!(list));
        }
    }
    let fp = p.q(&["fp", "fingerprint"]).map(|f| normalize_fingerprint(&f));
    let reality = security == "reality";
    match (fp, reality) {
        (Some(fp), _) => {
            tls.insert("utls".into(), json!({"enabled": true, "fingerprint": fp}));
        }
        // sing-box: "uTLS is required by reality client"
        (None, true) => {
            tls.insert("utls".into(), json!({"enabled": true, "fingerprint": "chrome"}));
        }
        (None, false) => {}
    }
    if reality {
        let pbk = p
            .q(&["pbk", "publickey", "public_key"])
            .ok_or_else(|| LinkError::Invalid("для Reality нужен публичный ключ (pbk)".into()))?;
        let mut r = Map::new();
        r.insert("enabled".into(), json!(true));
        r.insert("public_key".into(), json!(pbk));
        if let Some(sid) = p.q(&["sid", "shortid", "short_id"]) {
            r.insert("short_id".into(), json!(sid));
        }
        tls.insert("reality".into(), Value::Object(r));
    }
    Ok(Some(Value::Object(tls)))
}

fn normalize_fingerprint(fp: &str) -> String {
    let fp = fp.trim().to_ascii_lowercase();
    match fp.as_str() {
        "chrome" | "firefox" | "edge" | "safari" | "360" | "qq" | "ios" | "android" | "random"
        | "randomized" => fp,
        _ => "chrome".into(),
    }
}

/// Transport block from `type`/`net`, `path`, `host`, `serviceName`, `headerType`.
pub(crate) fn transport_from(p: &LinkParts) -> Result<Option<Value>, LinkError> {
    let ty = p.q(&["type", "net", "network"]).unwrap_or_else(|| "tcp".into()).to_ascii_lowercase();
    let path = p.q(&["path"]);
    let host = p.q(&["host"]);
    let first_host = host
        .as_deref()
        .map(|h| h.split(',').next().unwrap_or("").trim().to_string())
        .filter(|h| !h.is_empty());
    match ty.as_str() {
        "tcp" | "raw" => match p.q(&["headertype"]).as_deref() {
            None | Some("none") => Ok(None),
            Some(other) => Err(LinkError::Unsupported(format!(
                "TCP с маскировкой заголовков ({other}) есть только в Xray"
            ))),
        },
        "ws" | "websocket" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("ws"));
            let mut path = path.unwrap_or_else(|| "/".into());
            let mut early = p.q(&["ed"]).and_then(|e| e.parse::<u32>().ok());
            // Xray style early data: /path?ed=2048
            if let Some((base, q)) = path.clone().split_once('?') {
                let params = crate::util::query_map(q);
                if let Some(ed) = params.get("ed").and_then(|e| e.parse::<u32>().ok()) {
                    early = Some(ed);
                    path = base.to_string();
                }
            }
            t.insert("path".into(), json!(path));
            if let Some(h) = first_host {
                t.insert("headers".into(), json!({ "Host": h }));
            }
            if let Some(ed) = early {
                t.insert("max_early_data".into(), json!(ed));
                t.insert("early_data_header_name".into(), json!("Sec-WebSocket-Protocol"));
            }
            Ok(Some(Value::Object(t)))
        }
        "grpc" | "gun" => {
            let service = p.q(&["servicename", "service_name"]).or(path).unwrap_or_default();
            Ok(Some(json!({"type": "grpc", "service_name": service})))
        }
        "http" | "h2" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("http"));
            if let Some(h) = host {
                let hosts = split_list(&h);
                if !hosts.is_empty() {
                    t.insert("host".into(), json!(hosts));
                }
            }
            if let Some(path) = path {
                t.insert("path".into(), json!(path));
            }
            Ok(Some(Value::Object(t)))
        }
        "httpupgrade" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("httpupgrade"));
            if let Some(h) = first_host {
                t.insert("host".into(), json!(h));
            }
            t.insert("path".into(), json!(path.unwrap_or_else(|| "/".into())));
            Ok(Some(Value::Object(t)))
        }
        "quic" => Ok(Some(json!({"type": "quic"}))),
        // Only the sing-box-lx core has XHTTP; the app picks it for such servers.
        "xhttp" | "splithttp" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("xhttp"));
            t.insert("path".into(), json!(path.unwrap_or_else(|| "/".into())));
            if let Some(h) = first_host {
                t.insert("host".into(), json!(h));
            }
            if let Some(mode) = p.q(&["mode"]).filter(|m| !m.is_empty()) {
                match mode.as_str() {
                    "auto" | "packet-up" | "stream-up" | "stream-one" => {
                        t.insert("mode".into(), json!(mode));
                    }
                    other => return Err(LinkError::Unsupported(format!("режим XHTTP «{other}»"))),
                }
            }
            if let Some(extra) = p.q(&["extra"]).filter(|e| !e.trim().is_empty()) {
                xhttp_extra(&extra, &mut t)?;
            }
            Ok(Some(Value::Object(t)))
        }
        "kcp" | "mkcp" => Err(LinkError::Unsupported("транспорт mKCP".into())),
        other => Err(LinkError::Unsupported(format!("транспорт {other}"))),
    }
}

/// Xray `extra` JSON of an XHTTP link → sing-box-lx transport fields.
fn xhttp_extra(extra: &str, t: &mut Map<String, Value>) -> Result<(), LinkError> {
    let v: Value = serde_json::from_str(extra).map_err(|_| LinkError::Invalid("параметр extra не является JSON".into()))?;
    let Some(obj) = v.as_object() else { return Ok(()) };
    // Xray writes ranges as "100-1000", 500 or {"from": 100, "to": 1000}
    let range = |v: &Value| -> Option<String> {
        match v {
            Value::String(s) if !s.trim().is_empty() => Some(s.replace(' ', "")),
            Value::Number(n) => Some(n.to_string()),
            Value::Object(o) => {
                let (a, b) = (o.get("from")?.as_u64()?, o.get("to")?.as_u64()?);
                Some(format!("{a}-{b}"))
            }
            _ => None,
        }
    };
    for (xray, ours) in [
        ("xPaddingBytes", "x_padding_bytes"),
        ("scMaxEachPostBytes", "sc_max_each_post_bytes"),
        ("scMinPostsIntervalMs", "sc_min_posts_interval_ms"),
    ] {
        if let Some(r) = obj.get(xray).and_then(range) {
            t.insert(ours.into(), json!(r));
        }
    }
    if let Some(n) = obj.get("scMaxBufferedPosts").and_then(Value::as_u64) {
        t.insert("sc_max_buffered_posts".into(), json!(n));
    }
    if obj.get("noGRPCHeader").and_then(Value::as_bool) == Some(true) {
        t.insert("no_grpc_header".into(), json!(true));
    }
    if let Some(mux) = obj.get("xmux").and_then(Value::as_object) {
        let mut m = Map::new();
        for (xray, ours) in [
            ("maxConcurrency", "max_concurrency"),
            ("maxConnections", "max_connections"),
            ("cMaxReuseTimes", "c_max_reuse_times"),
            ("hMaxRequestTimes", "h_max_request_times"),
            ("hMaxReusableSecs", "h_max_reusable_secs"),
            ("hKeepAlivePeriod", "h_keep_alive_period"),
        ] {
            match mux.get(xray) {
                Some(Value::Number(n)) => {
                    m.insert(ours.into(), json!(n));
                }
                Some(other) => {
                    if let Some(r) = range(other) {
                        m.insert(ours.into(), json!(r));
                    }
                }
                None => {}
            }
        }
        if !m.is_empty() {
            t.insert("xmux".into(), Value::Object(m));
        }
    }
    if obj.get("downloadSettings").is_some_and(|d| !d.is_null()) {
        return Err(LinkError::Unsupported("XHTTP с отдельным сервером для загрузки (downloadSettings)".into()));
    }
    Ok(())
}

/// Insert `key` only if the value is a non-empty string.
pub(crate) fn put_str(m: &mut Map<String, Value>, key: &str, v: Option<String>) {
    if let Some(v) = v.filter(|v| !v.is_empty()) {
        m.insert(key.into(), json!(v));
    }
}

#[cfg(test)]
mod tests;
