//! `vpn://` keys exported by AmneziaVPN: base64url of a Qt `qCompress`ed JSON
//! (4-byte big-endian length + zlib). For AmneziaWG and WireGuard containers
//! the JSON carries the ready client `.conf` in `last_config`.

use std::io::Read;

use serde_json::Value;

use super::{LinkError, LinkResult, ParsedLink};
use crate::util::b64_decode;

pub fn parse(link: &str) -> LinkResult {
    let body = link.trim();
    let body = body.get(6..).unwrap_or("").trim(); // after "vpn://"
    let raw = b64_decode(body).ok_or("ключ vpn:// повреждён: это не base64")?;
    let json = decode_payload(&raw).ok_or("ключ vpn:// повреждён: не удалось распаковать")?;
    let v: Value = serde_json::from_slice(&json).map_err(|_| LinkError::Invalid("ключ vpn:// повреждён: внутри не JSON".into()))?;
    from_json(&v)
}

/// SSH access to a server, from an AmneziaVPN full-access key
/// («Поделиться → Полный доступ»): the server's login and its protocols.
#[derive(Debug, Clone, PartialEq)]
pub struct AdminAccess {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// A password, or a private key when it starts with `-----BEGIN`.
    pub secret: String,
}

/// The access a `vpn://` key gives, if it is a full-access key.
pub fn admin_access(link: &str) -> Option<AdminAccess> {
    let body = link.trim().strip_prefix("vpn://")?.trim();
    let json = decode_payload(&b64_decode(body)?)?;
    let v: Value = serde_json::from_slice(&json).ok()?;
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let host = text("hostName")?;
    let user = text("userName")?;
    let secret = v.get("password").and_then(Value::as_str).filter(|s| !s.is_empty())?.to_string();
    let port = v.get("port").and_then(Value::as_u64).filter(|p| (1..=65535).contains(p)).unwrap_or(22) as u16;
    let name = text("description").unwrap_or_else(|| host.clone());
    Some(AdminAccess { name, host, port, user, secret })
}

fn decode_payload(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.first() == Some(&b'{') {
        return Some(raw.to_vec());
    }
    // qCompress: 4 bytes of uncompressed length, then a zlib stream
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(raw.get(4..)?).read_to_end(&mut out).ok()?;
    Some(out)
}

fn from_json(v: &Value) -> LinkResult {
    let name = v
        .get("description")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .or_else(|| v.get("hostName").and_then(Value::as_str))
        .unwrap_or("")
        .trim()
        .to_string();
    let containers = v.get("containers").and_then(Value::as_array).cloned().unwrap_or_default();
    if containers.is_empty() {
        return Err(LinkError::Unsupported(
            "в ключе Amnezia нет настроек сервера (так выглядят ключи Amnezia Premium и Free: их сервер выдаёт \
             настройки только приложению AmneziaVPN). Для своего сервера поделитесь подключением в AmneziaVPN \
             или сохраните файл .conf"
                .into(),
        ));
    }
    let default = v.get("defaultContainer").and_then(Value::as_str).unwrap_or("");
    let mut ordered: Vec<&Value> = containers.iter().filter(|c| c["container"] == default).collect();
    ordered.extend(containers.iter().filter(|c| c["container"] != default));
    let mut kinds = Vec::new();
    for c in ordered {
        let kind = c.get("container").and_then(Value::as_str).unwrap_or("");
        kinds.push(kind.to_string());
        // amnezia-awg, amnezia-awg2, amnezia-wireguard: the section is named after the protocol
        let section = ["awg", "wireguard"].iter().find_map(|k| c.get(*k));
        let Some(section) = section else { continue };
        let Some(last) = section.get("last_config").and_then(Value::as_str) else { continue };
        let last: Value = serde_json::from_str(last).unwrap_or(Value::Null);
        let Some(conf) = last.get("config").and_then(Value::as_str) else { continue };
        let display = if name.is_empty() { String::new() } else { name.clone() };
        let r = crate::wgconf::parse(conf, &display)?;
        return Ok(ParsedLink { name: r.profile.name, outbound: r.profile.outbound });
    }
    Err(LinkError::Unsupported(format!(
        "в ключе Amnezia нет AmneziaWG или WireGuard (есть: {}). Такие подключения пока не поддерживаются",
        if kinds.is_empty() { "ничего".to_string() } else { kinds.join(", ") }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::json;
    use std::io::Write;

    fn key(v: &Value) -> String {
        let json = serde_json::to_vec(v).unwrap();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&json).unwrap();
        let mut raw = (json.len() as u32).to_be_bytes().to_vec();
        raw.extend(z.finish().unwrap());
        format!("vpn://{}", URL_SAFE_NO_PAD.encode(raw))
    }

    const CONF: &str = "[Interface]\nAddress = 10.8.1.2/32\nDNS = $PRIMARY_DNS\nPrivateKey = OOrcz46udUCWEuue7YueYT6OGhchZ91v0NqtRu+W2FI=\nJc = 3\nJmin = 10\nJmax = 40\nS1 = 20\nS2 = 30\nS3 = 16\nS4 = 12\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nHeaderProtectionKey = KIKOZNzj+d+G5Gw84nfLm49oM/f+xMoThA4AEOqyZkc=\n\n[Peer]\nPublicKey = xqz8eGLSa0P5JHkSTGnKoczKZjmonaUDbbx8bUqRjWw=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.7:39000\nPersistentKeepalive = 25\n";

    #[test]
    fn awg_key() {
        let last = json!({"config": CONF, "hostName": "203.0.113.7", "port": 39000}).to_string();
        let v = json!({
            "containers": [
                {"container": "amnezia-xray", "xray": {"last_config": "{}"}},
                {"container": "amnezia-awg2", "awg": {"last_config": last, "port": "39000"}},
            ],
            "defaultContainer": "amnezia-awg2",
            "description": "Мой сервер",
            "hostName": "203.0.113.7",
        });
        let p = super::super::parse_link(&key(&v)).unwrap();
        assert_eq!(p.name, "Мой сервер");
        assert_eq!(p.outbound["type"], "wireguard");
        assert_eq!(p.outbound["header_protection_key"], "KIKOZNzj+d+G5Gw84nfLm49oM/f+xMoThA4AEOqyZkc=");
        assert_eq!(p.outbound["peers"][0]["port"], 39000);
    }

    #[test]
    fn full_access_key() {
        let v = json!({
            "containers": [{"container": "amnezia-awg2", "awg": {"port": "39000"}}],
            "defaultContainer": "amnezia-awg2",
            "description": "VPS",
            "hostName": "203.0.113.7",
            "userName": "root",
            "password": "s3cret",
            "port": 2222,
        });
        let a = admin_access(&key(&v)).unwrap();
        assert_eq!(a, AdminAccess { name: "VPS".into(), host: "203.0.113.7".into(), port: 2222, user: "root".into(), secret: "s3cret".into() });
        // a connection key has no login
        let mut plain = v.clone();
        plain["userName"] = json!("");
        plain["password"] = json!("");
        assert!(admin_access(&key(&plain)).is_none());
        assert!(admin_access("vless://x").is_none());
    }

    #[test]
    fn premium_key_explains() {
        let v = json!({"api_config": {"service_type": "amnezia-premium"}, "auth_data": {"api_key": "x"}});
        let e = super::super::parse_link(&key(&v)).unwrap_err();
        assert!(matches!(e, LinkError::Unsupported(ref m) if m.contains("Premium")));
        assert!(super::super::parse_link("vpn://###").is_err());
    }
}
