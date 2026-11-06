use serde_json::{json, Map, Value};

use super::{LinkError, LinkResult, ParsedLink};
use crate::util::{b64_decode_str, pct_decode, query_map, split_host_port};

const METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// SIP002 `ss://base64(method:pass)@host:port?plugin=…#name`,
/// plain `ss://method:pass@host:port`, and legacy `ss://base64(method:pass@host:port)#name`.
pub fn parse(link: &str) -> LinkResult {
    let body = link.trim().splitn(2, "://").nth(1).unwrap_or("");
    let (body, name) = match body.split_once('#') {
        Some((b, f)) => (b, pct_decode(f).trim().to_string()),
        None => (body, String::new()),
    };
    let (body, query) = match body.split_once('?') {
        Some((b, q)) => (b, query_map(q)),
        None => (body, Default::default()),
    };
    let body = body.trim_end_matches('/');

    let (userinfo, hostport) = match body.rfind('@') {
        Some(at) => (decode_userinfo(&body[..at])?, body[at + 1..].to_string()),
        None => {
            let decoded = b64_decode_str(body).ok_or("не удалось раскодировать ss-ссылку")?;
            let at = decoded.rfind('@').ok_or("в ss-ссылке нет адреса")?;
            (decoded[..at].to_string(), decoded[at + 1..].to_string())
        }
    };
    let (method, password) = userinfo.split_once(':').ok_or("в ss-ссылке нет метода и пароля")?;
    let method = method.trim().to_ascii_lowercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(LinkError::Unsupported(format!("метод шифрования {method}")));
    }
    let (host, port) = split_host_port(hostport.trim_end_matches('/'));
    let port: u16 = port.ok_or("не указан порт")?.parse().map_err(|_| "неверный порт")?;

    let mut ob = Map::new();
    ob.insert("type".into(), json!("shadowsocks"));
    ob.insert("server".into(), json!(host));
    ob.insert("server_port".into(), json!(port));
    ob.insert("method".into(), json!(method));
    ob.insert("password".into(), json!(password));
    if let Some(plugin) = query.get("plugin").filter(|p| !p.is_empty()) {
        let (name, opts) = match plugin.split_once(';') {
            Some((n, o)) => (n, o),
            None => (plugin.as_str(), ""),
        };
        let name = match name {
            "obfs-local" | "simple-obfs" | "obfs" => "obfs-local",
            "v2ray-plugin" => "v2ray-plugin",
            other => return Err(LinkError::Unsupported(format!("плагин {other}"))),
        };
        ob.insert("plugin".into(), json!(name));
        if !opts.is_empty() {
            ob.insert("plugin_opts".into(), json!(opts));
        }
    }
    let name = if name.is_empty() { format!("{host}:{port}") } else { name };
    Ok(ParsedLink { name, outbound: Value::Object(ob) })
}

fn decode_userinfo(raw: &str) -> Result<String, LinkError> {
    let decoded = pct_decode(raw);
    // "method:password" in clear text (allowed for 2022 ciphers)
    if let Some((m, _)) = decoded.split_once(':') {
        if METHODS.contains(&m.to_ascii_lowercase().as_str()) {
            return Ok(decoded);
        }
    }
    if let Some(s) = b64_decode_str(&decoded) {
        if s.contains(':') {
            return Ok(s);
        }
    }
    if decoded.contains(':') {
        return Ok(decoded);
    }
    Err(LinkError::Invalid("не удалось прочитать метод и пароль".into()))
}
