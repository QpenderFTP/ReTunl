use std::collections::HashMap;

use serde_json::{json, Map, Value};

use super::{put_str, tls_from, transport_from, LinkError, LinkResult, ParsedLink};
use crate::util::{b64_decode_str, LinkParts};

pub fn vless(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    let uuid = p.user().ok_or("нет UUID пользователя")?;
    let port = p.port_u16()?;
    let mut ob = Map::new();
    ob.insert("type".into(), json!("vless"));
    ob.insert("server".into(), json!(p.host));
    ob.insert("server_port".into(), json!(port));
    ob.insert("uuid".into(), json!(uuid));
    if let Some(flow) = p.q(&["flow"]) {
        // Xray's "xtls-rprx-vision-udp443" is vision plus UDP/443, same on the wire
        let flow = if flow.starts_with("xtls-rprx-vision") { "xtls-rprx-vision".to_string() } else { flow };
        ob.insert("flow".into(), json!(flow));
    }
    if let Some(enc) = p.q(&["encryption"]) {
        if enc != "none" {
            return Err(LinkError::Unsupported(format!("VLESS encryption={enc}")));
        }
    }
    ob.insert("packet_encoding".into(), json!(p.q(&["packetencoding"]).unwrap_or_else(|| "xudp".into())));
    let security = p.q(&["security"]).unwrap_or_default().to_ascii_lowercase();
    if let Some(tls) = tls_from(&p, &security)? {
        ob.insert("tls".into(), tls);
    }
    if let Some(tr) = transport_from(&p)? {
        ob.insert("transport".into(), tr);
    }
    Ok(ParsedLink { name: p.name(), outbound: Value::Object(ob) })
}

pub fn trojan(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    let password = p.user().ok_or("нет пароля")?;
    let port = p.port_u16()?;
    let mut ob = Map::new();
    ob.insert("type".into(), json!("trojan"));
    ob.insert("server".into(), json!(p.host));
    ob.insert("server_port".into(), json!(port));
    ob.insert("password".into(), json!(password));
    // Trojan is TLS unless the link says otherwise.
    let security = p.q(&["security"]).unwrap_or_else(|| "tls".into()).to_ascii_lowercase();
    if let Some(tls) = tls_from(&p, &security)? {
        ob.insert("tls".into(), tls);
    }
    if let Some(tr) = transport_from(&p)? {
        ob.insert("transport".into(), tr);
    }
    Ok(ParsedLink { name: p.name(), outbound: Value::Object(ob) })
}

/// `vmess://base64(json)` in the v2rayN format; falls back to the URL form.
pub fn vmess(link: &str) -> LinkResult {
    let body = link.trim().split_once("://").map_or("", |(_, rest)| rest);
    let (body, fragment) = match body.split_once('#') {
        Some((b, f)) => (b, Some(crate::util::pct_decode(f))),
        None => (body, None),
    };
    let Some(text) = b64_decode_str(body) else {
        return vmess_url(link);
    };
    let v: Value = match serde_json::from_str(text.trim()) {
        Ok(v) => v,
        Err(_) => return vmess_url(link),
    };
    let s = |k: &str| -> Option<String> {
        match v.get(k)? {
            Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    };
    let host = s("add").ok_or("нет адреса сервера (add)")?;
    let port: u16 = s("port").ok_or("нет порта")?.parse().map_err(|_| "неверный порт")?;
    let uuid = s("id").ok_or("нет UUID (id)")?;

    // Re-use the share-link helpers by building the equivalent query.
    let mut q: HashMap<String, String> = HashMap::new();
    let mut set = |k: &str, val: Option<String>| {
        if let Some(val) = val {
            q.insert(k.to_string(), val);
        }
    };
    set("type", s("net"));
    set("headertype", s("type"));
    set("host", s("host"));
    set("path", s("path"));
    if s("net").as_deref() == Some("grpc") {
        set("servicename", s("path"));
    }
    set("sni", s("sni"));
    set("alpn", s("alpn"));
    set("fp", s("fp"));
    set("allowinsecure", s("allowInsecure").or(s("skip-cert-verify")));
    let parts = LinkParts {
        scheme: "vmess".into(),
        host: host.clone(),
        port: Some(port.to_string()),
        query: q,
        ..Default::default()
    };
    let mut ob = Map::new();
    ob.insert("type".into(), json!("vmess"));
    ob.insert("server".into(), json!(host));
    ob.insert("server_port".into(), json!(port));
    ob.insert("uuid".into(), json!(uuid));
    let security = s("scy").unwrap_or_else(|| "auto".into());
    ob.insert("security".into(), json!(security));
    let alter_id: u32 = s("aid").and_then(|a| a.parse().ok()).unwrap_or(0);
    ob.insert("alter_id".into(), json!(alter_id));
    ob.insert("packet_encoding".into(), json!("xudp"));
    let tls_mode = s("tls").unwrap_or_default().to_ascii_lowercase();
    if let Some(tls) = tls_from(&parts, &tls_mode)? {
        ob.insert("tls".into(), tls);
    }
    if let Some(tr) = transport_from(&parts)? {
        ob.insert("transport".into(), tr);
    }
    let name = fragment.filter(|f| !f.is_empty()).or(s("ps")).unwrap_or_else(|| format!("{host}:{port}"));
    Ok(ParsedLink { name, outbound: Value::Object(ob) })
}

/// `vmess://uuid@host:port?...` (less common URL form).
fn vmess_url(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    let uuid = p.user().ok_or("не удалось разобрать vmess-ссылку")?;
    let port = p.port_u16()?;
    let mut ob = Map::new();
    ob.insert("type".into(), json!("vmess"));
    ob.insert("server".into(), json!(p.host));
    ob.insert("server_port".into(), json!(port));
    ob.insert("uuid".into(), json!(uuid));
    put_str(&mut ob, "security", p.q(&["encryption", "scy"]).or(Some("auto".into())));
    ob.insert("alter_id".into(), json!(0));
    let security = p.q(&["security"]).unwrap_or_default().to_ascii_lowercase();
    if let Some(tls) = tls_from(&p, &security)? {
        ob.insert("tls".into(), tls);
    }
    if let Some(tr) = transport_from(&p)? {
        ob.insert("transport".into(), tr);
    }
    Ok(ParsedLink { name: p.name(), outbound: Value::Object(ob) })
}
