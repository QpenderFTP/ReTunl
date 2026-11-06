use serde_json::{json, Map, Value};

use super::{LinkResult, ParsedLink};
use crate::util::{is_ip, split_list, LinkParts};

/// `wireguard://PRIVATE_KEY@host:port?publickey=…&address=…&reserved=1,2,3&mtu=…#name`
/// (v2rayN / Hiddify style; several parameter spellings accepted).
pub fn wireguard(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    let private_key = p
        .user()
        .or_else(|| p.q(&["privatekey", "private_key", "secretkey", "pk"]))
        .ok_or("нет приватного ключа")?;
    let public_key = p
        .q(&["publickey", "public_key", "peer_public_key", "peerpublickey", "pbk"])
        .ok_or("нет публичного ключа сервера (publickey)")?;
    let port = p.port_u16()?;
    let address = p
        .q(&["address", "ip", "local_address", "localaddress"])
        .map(|a| split_list(&a))
        .unwrap_or_default();
    if address.is_empty() {
        return Err("нет адреса интерфейса (address)".into());
    }
    let address: Vec<String> = address.into_iter().map(with_prefix).collect();
    let mut peer = Map::new();
    peer.insert("address".into(), json!(p.host));
    peer.insert("port".into(), json!(port));
    peer.insert("public_key".into(), json!(public_key));
    if let Some(psk) = p.q(&["presharedkey", "pre_shared_key", "psk", "preshared_key"]) {
        peer.insert("pre_shared_key".into(), json!(psk));
    }
    let allowed = p
        .q(&["allowedips", "allowed_ips"])
        .map(|a| split_list(&a))
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| vec!["0.0.0.0/0".into(), "::/0".into()]);
    peer.insert("allowed_ips".into(), json!(allowed));
    if let Some(ka) = p.q(&["keepalive", "persistentkeepalive"]).and_then(|k| k.parse::<u32>().ok()) {
        peer.insert("persistent_keepalive_interval".into(), json!(ka));
    }
    if let Some(reserved) = p.q(&["reserved"]) {
        let bytes: Vec<u8> = split_list(&reserved).iter().filter_map(|b| b.parse().ok()).collect();
        if bytes.len() == 3 {
            peer.insert("reserved".into(), json!(bytes));
        }
    }
    let mut ob = Map::new();
    ob.insert("type".into(), json!("wireguard"));
    ob.insert("address".into(), json!(address));
    ob.insert("private_key".into(), json!(private_key));
    if let Some(mtu) = p.q(&["mtu"]).and_then(|m| m.parse::<u32>().ok()) {
        ob.insert("mtu".into(), json!(mtu));
    }
    ob.insert("peers".into(), json!([Value::Object(peer)]));
    Ok(ParsedLink { name: p.name(), outbound: Value::Object(ob) })
}

/// `10.0.0.2` → `10.0.0.2/32`, `fd00::2` → `fd00::2/128`.
pub(crate) fn with_prefix(a: String) -> String {
    if a.contains('/') {
        return a;
    }
    match a.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => format!("{a}/32"),
        Ok(std::net::IpAddr::V6(_)) => format!("{a}/128"),
        Err(_) => a,
    }
}

pub fn socks(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    let port = p.port_u16()?;
    let mut ob = Map::new();
    ob.insert("type".into(), json!("socks"));
    ob.insert("server".into(), json!(p.host));
    ob.insert("server_port".into(), json!(port));
    ob.insert("version".into(), json!("5"));
    if let Some(user) = p.user() {
        // socks://base64(user:pass)@host:port is also seen in the wild
        let user = match crate::util::b64_decode_str(&user) {
            Some(d) if d.contains(':') && !user.contains(':') => d,
            _ => user,
        };
        match user.split_once(':') {
            Some((u, pw)) => {
                ob.insert("username".into(), json!(u));
                ob.insert("password".into(), json!(pw));
            }
            None => {
                ob.insert("username".into(), json!(user));
            }
        }
    }
    Ok(ParsedLink { name: p.name(), outbound: Value::Object(ob) })
}

pub fn anytls(link: &str) -> LinkResult {
    let p = LinkParts::parse(link)?;
    let password = p.user().ok_or("нет пароля")?;
    let port = p.port_u16()?;
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    if let Some(sni) = p.q(&["sni", "peer"]).or_else(|| (!is_ip(&p.host)).then(|| p.host.clone())) {
        tls.insert("server_name".into(), json!(sni));
    }
    if p.q_bool(&["insecure", "allowinsecure"]) {
        tls.insert("insecure".into(), json!(true));
    }
    let ob = json!({
        "type": "anytls",
        "server": p.host,
        "server_port": port,
        "password": password,
        "tls": Value::Object(tls),
    });
    Ok(ParsedLink { name: p.name(), outbound: ob })
}
