//! Xray VLESS servers as AmneziaVPN keeps them: one inbound in `server.json`,
//! its clients are VLESS ids; with Reality the public key is derived from
//! the private one in the same file.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};

pub const FLOW: &str = "xtls-rprx-vision";
pub const DEFAULT_SITE: &str = "www.googletagmanager.com";

#[derive(Debug, Clone, PartialEq)]
pub struct Inbound {
    pub port: u16,
    pub network: String,
    pub security: String,
    pub sni: Option<String>,
    pub short_id: Option<String>,
    /// Reality public key, derived from the server's private key.
    pub public_key: Option<String>,
    pub flow: Option<String>,
    pub clients: Vec<String>,
}

fn first_inbound(v: &Value) -> Result<&Value, String> {
    v.get("inbounds")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().find(|i| i["protocol"] == "vless"))
        .ok_or_else(|| "в server.json нет входа VLESS".to_string())
}

pub fn parse_server(text: &str) -> Result<Inbound, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("server.json повреждён: {e}"))?;
    let ib = first_inbound(&v)?;
    let ss = &ib["streamSettings"];
    let rs = &ss["realitySettings"];
    let clients = ib["settings"]["clients"].as_array().cloned().unwrap_or_default();
    let s = |v: &Value| v.as_str().map(str::to_string).filter(|s| !s.is_empty());
    Ok(Inbound {
        port: ib["port"].as_u64().or_else(|| ib["port"].as_str().and_then(|p| p.parse().ok())).unwrap_or(443) as u16,
        network: s(&ss["network"]).unwrap_or_else(|| "raw".into()),
        security: s(&ss["security"]).unwrap_or_else(|| "none".into()),
        sni: s(&rs["serverNames"][0]).or_else(|| s(&rs["serverName"])),
        short_id: rs["shortIds"].as_array().and_then(|a| a.iter().find_map(s)),
        public_key: rs["privateKey"].as_str().and_then(public_from_private),
        flow: clients.first().and_then(|c| s(&c["flow"])),
        clients: clients.iter().filter_map(|c| s(&c["id"])).collect(),
    })
}

fn edit_clients(text: &str, f: impl FnOnce(&mut Vec<Value>) -> Result<(), String>) -> Result<String, String> {
    let mut v: Value = serde_json::from_str(text).map_err(|e| format!("server.json повреждён: {e}"))?;
    let ib = v
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .and_then(|a| a.iter_mut().find(|i| i["protocol"] == "vless"))
        .ok_or("в server.json нет входа VLESS")?;
    let settings = ib.as_object_mut().ok_or("server.json повреждён")?.entry("settings").or_insert_with(|| json!({}));
    let list = settings.as_object_mut().ok_or("server.json повреждён")?.entry("clients").or_insert_with(|| json!([]));
    let arr = list.as_array_mut().ok_or("server.json повреждён")?;
    f(arr)?;
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

pub fn add_client(text: &str, id: &str, flow: Option<&str>) -> Result<String, String> {
    edit_clients(text, |arr| {
        let mut c = json!({ "id": id });
        if let Some(f) = flow.filter(|f| !f.is_empty()) {
            c["flow"] = json!(f);
        }
        arr.push(c);
        Ok(())
    })
}

pub fn remove_client(text: &str, id: &str) -> Result<String, String> {
    edit_clients(text, |arr| {
        let before = arr.len();
        arr.retain(|c| c["id"] != id);
        if arr.len() == before {
            return Err("такого клиента на сервере уже нет".into());
        }
        Ok(())
    })
}

/// A `vless://` link for one client, or why there can't be one.
pub fn link(ib: &Inbound, host: &str, id: &str, name: &str) -> Result<String, String> {
    if !matches!(ib.network.as_str(), "raw" | "tcp") {
        return Err(format!("ссылку для транспорта «{}» ReTunl пока не собирает", ib.network));
    }
    let host = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.to_string() };
    let enc = |s: &str| utf8_percent_encode(s, NON_ALPHANUMERIC).to_string();
    let mut q = vec![("type", "tcp".to_string()), ("encryption", "none".to_string())];
    if let Some(f) = &ib.flow {
        q.push(("flow", f.clone()));
    }
    match ib.security.as_str() {
        "reality" => {
            let pbk = ib.public_key.clone().ok_or("в server.json нет ключа Reality")?;
            q.push(("security", "reality".into()));
            q.push(("pbk", pbk));
            q.push(("fp", "chrome".into()));
            if let Some(sni) = &ib.sni {
                q.push(("sni", sni.clone()));
            }
            if let Some(sid) = &ib.short_id {
                q.push(("sid", sid.clone()));
            }
        }
        "none" => {}
        other => return Err(format!("ссылку для защиты «{other}» ReTunl пока не собирает")),
    }
    let query: Vec<String> = q.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect();
    Ok(format!("vless://{id}@{host}:{}?{}#{}", ib.port, query.join("&"), enc(name)))
}

/// A Reality key pair (private, public), base64url like `xray x25519` prints.
pub fn reality_keypair() -> (String, String) {
    let (p, q) = super::wg::raw_keypair();
    (B64URL.encode(p), B64URL.encode(q))
}

fn public_from_private(private: &str) -> Option<String> {
    let raw: [u8; 32] = B64URL.decode(private.trim().trim_end_matches('=')).ok()?.try_into().ok()?;
    Some(B64URL.encode(super::wg::public_of(&raw)))
}

pub fn short_id() -> String {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `server.json` for a fresh VLESS Reality server.
pub fn server_json(port: u16, first_client: &str, private_key: &str, short_id: &str, site: &str) -> String {
    let v = json!({
        "log": { "loglevel": "error" },
        "inbounds": [{
            "port": port,
            "protocol": "vless",
            "settings": { "clients": [{ "id": first_client, "flow": FLOW }], "decryption": "none" },
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "dest": format!("{site}:443"),
                    "privateKey": private_key,
                    "serverNames": [site],
                    "shortIds": [short_id],
                },
            },
        }],
        "outbounds": [{ "protocol": "freedom" }],
    });
    serde_json::to_string_pretty(&v).expect("plain JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_server_round_trip() {
        let (private, public) = reality_keypair();
        let text = server_json(8443, "11111111-1111-4111-8111-111111111111", &private, "0123456789abcdef", "www.example.com");
        let ib = parse_server(&text).unwrap();
        assert_eq!(ib.port, 8443);
        assert_eq!(ib.security, "reality");
        assert_eq!(ib.public_key.as_deref(), Some(public.as_str()));
        assert_eq!(ib.sni.as_deref(), Some("www.example.com"));
        assert_eq!(ib.flow.as_deref(), Some(FLOW));

        let text = add_client(&text, "22222222-2222-4222-8222-222222222222", ib.flow.as_deref()).unwrap();
        let ib = parse_server(&text).unwrap();
        assert_eq!(ib.clients.len(), 2);
        let link = link(&ib, "203.0.113.7", &ib.clients[1], "Мой телефон").unwrap();
        assert!(link.starts_with("vless://22222222-2222-4222-8222-222222222222@203.0.113.7:8443?type=tcp&encryption=none&flow=xtls%2Drprx%2Dvision&security=reality&pbk="));
        assert!(link.contains("&sid=0123456789abcdef"));
        let parsed = retunl_core::links::parse_link(&link).unwrap();
        assert_eq!(parsed.name, "Мой телефон");
        assert_eq!(parsed.outbound["tls"]["reality"]["public_key"], public);

        let text = remove_client(&text, "11111111-1111-4111-8111-111111111111").unwrap();
        assert_eq!(parse_server(&text).unwrap().clients, ["22222222-2222-4222-8222-222222222222"]);
        assert!(remove_client(&text, "nope").is_err());
    }

    #[test]
    fn other_transports_have_no_link() {
        let ib = Inbound {
            port: 443,
            network: "xhttp".into(),
            security: "reality".into(),
            sni: None,
            short_id: None,
            public_key: Some("k".into()),
            flow: None,
            clients: vec![],
        };
        assert!(link(&ib, "h", "id", "n").is_err());
    }
}
