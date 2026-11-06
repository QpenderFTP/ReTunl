use serde_json::{json, Map, Value};

use super::{LinkError, LinkResult, ParsedLink};
use crate::util::{is_ip, split_list, LinkParts};

fn quic_tls(p: &LinkParts, default_alpn: Option<&str>) -> Value {
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    let sni = p.q(&["sni", "peer", "servername"]).or_else(|| (!is_ip(&p.host)).then(|| p.host.clone()));
    if let Some(sni) = sni {
        tls.insert("server_name".into(), json!(sni));
    }
    if p.q_bool(&["insecure", "allowinsecure", "allow_insecure", "skip-cert-verify"]) {
        tls.insert("insecure".into(), json!(true));
    }
    let alpn = p.q(&["alpn"]).map(|a| split_list(&a)).filter(|a| !a.is_empty());
    match (alpn, default_alpn) {
        (Some(a), _) => {
            tls.insert("alpn".into(), json!(a));
        }
        (None, Some(d)) => {
            tls.insert("alpn".into(), json!([d]));
        }
        _ => {}
    }
    Value::Object(tls)
}

/// `443`, `443,20000-30000`, `20000-30000` → (single port, hop ranges).
fn port_spec(spec: &str) -> Result<(Option<u16>, Vec<String>), LinkError> {
    let mut single = None;
    let mut ranges = Vec::new();
    let parts: Vec<&str> = spec.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    for part in &parts {
        if let Some((a, b)) = part.split_once(['-', ':']) {
            let a: u16 = a.trim().parse().map_err(|_| format!("неверный диапазон портов «{part}»"))?;
            let b: u16 = b.trim().parse().map_err(|_| format!("неверный диапазон портов «{part}»"))?;
            if a > b {
                return Err(format!("неверный диапазон портов «{part}»").into());
            }
            ranges.push(format!("{a}:{b}"));
        } else {
            let port: u16 = part.parse().map_err(|_| format!("неверный порт «{part}»"))?;
            if parts.len() == 1 {
                single = Some(port);
            } else {
                ranges.push(format!("{port}:{port}"));
            }
        }
    }
    if single.is_none() && ranges.is_empty() {
        return Err("не указан порт".into());
    }
    Ok((single, ranges))
}

pub fn hysteria2(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    let password = p.user().or_else(|| p.q(&["auth", "password"])).ok_or("нет пароля")?;
    let mut ob = Map::new();
    ob.insert("type".into(), json!("hysteria2"));
    ob.insert("server".into(), json!(p.host));
    let spec = p.q(&["mport", "ports"]).or_else(|| p.port.clone()).unwrap_or_else(|| "443".into());
    let (single, ranges) = port_spec(&spec)?;
    if ranges.is_empty() {
        ob.insert("server_port".into(), json!(single.unwrap_or(443)));
    } else {
        ob.insert("server_ports".into(), json!(ranges));
    }
    ob.insert("password".into(), json!(password));
    match p.q(&["obfs"]).as_deref() {
        None | Some("none") => {}
        Some("salamander") => {
            let pass = p.q(&["obfs-password", "obfs_password", "obfspassword"]).ok_or("нет пароля obfs")?;
            ob.insert("obfs".into(), json!({"type": "salamander", "password": pass}));
        }
        Some(other) => return Err(LinkError::Unsupported(format!("обфускация {other}"))),
    }
    for (key, names) in [("up_mbps", ["upmbps", "up"]), ("down_mbps", ["downmbps", "down"])] {
        if let Some(v) = p.q(&names).and_then(|v| v.trim_end_matches(" mbps").parse::<u32>().ok()) {
            ob.insert(key.into(), json!(v));
        }
    }
    ob.insert("tls".into(), quic_tls(&p, Some("h3")));
    Ok(ParsedLink { name: p.name(), outbound: Value::Object(ob) })
}

/// Hysteria v1: `hysteria://host:port?auth=…&peer=…&upmbps=…&downmbps=…&obfsParam=…`.
pub fn hysteria(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    match p.q(&["protocol"]).as_deref() {
        None | Some("udp") => {}
        Some(other) => return Err(LinkError::Unsupported(format!("Hysteria protocol={other}"))),
    }
    let port = p.port_u16()?;
    let mut ob = Map::new();
    ob.insert("type".into(), json!("hysteria"));
    ob.insert("server".into(), json!(p.host));
    ob.insert("server_port".into(), json!(port));
    let up: u32 = p.q(&["upmbps", "up"]).and_then(|v| v.parse().ok()).unwrap_or(20);
    let down: u32 = p.q(&["downmbps", "down"]).and_then(|v| v.parse().ok()).unwrap_or(100);
    ob.insert("up_mbps".into(), json!(up));
    ob.insert("down_mbps".into(), json!(down));
    if let Some(auth) = p.q(&["auth", "auth_str"]).or_else(|| p.user()) {
        ob.insert("auth_str".into(), json!(auth));
    }
    if let Some(obfs) = p.q(&["obfsparam", "obfs-password"]) {
        ob.insert("obfs".into(), json!(obfs));
    }
    ob.insert("tls".into(), quic_tls(&p, Some("hysteria")));
    Ok(ParsedLink { name: p.name(), outbound: Value::Object(ob) })
}

/// TUIC v5: `tuic://uuid:password@host:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3`.
pub fn tuic(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    let user = p.user().ok_or("нет UUID и пароля")?;
    let (uuid, password) = match user.split_once(':') {
        Some((u, pw)) => (u.to_string(), pw.to_string()),
        None => (user.clone(), p.q(&["password"]).unwrap_or_default()),
    };
    let port = p.port_u16()?;
    let mut ob = Map::new();
    ob.insert("type".into(), json!("tuic"));
    ob.insert("server".into(), json!(p.host));
    ob.insert("server_port".into(), json!(port));
    ob.insert("uuid".into(), json!(uuid));
    if !password.is_empty() {
        ob.insert("password".into(), json!(password));
    }
    if let Some(cc) = p.q(&["congestion_control", "congestion-control", "cc"]) {
        ob.insert("congestion_control".into(), json!(cc));
    }
    if let Some(mode) = p.q(&["udp_relay_mode", "udp-relay-mode"]) {
        ob.insert("udp_relay_mode".into(), json!(mode));
    }
    let mut tls = quic_tls(&p, Some("h3"));
    if p.q_bool(&["disable_sni", "disable-sni"]) {
        tls["disable_sni"] = json!(true);
    }
    ob.insert("tls".into(), tls);
    Ok(ParsedLink { name: p.name(), outbound: Value::Object(ob) })
}
