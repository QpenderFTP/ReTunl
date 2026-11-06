//! WireGuard `.conf` files (also AmneziaWG files when they are compatible).

use serde_json::{json, Map, Value};

use crate::links::{LinkError, ParsedLink};
use crate::util::{split_host_port, split_list};

#[derive(Debug, Clone, PartialEq)]
pub struct WgImport {
    pub profile: ParsedLink,
    pub warnings: Vec<String>,
}

pub fn looks_like_wg_conf(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("[interface]") && t.contains("[peer]")
}

pub fn parse(text: &str, name: &str) -> Result<WgImport, LinkError> {
    let mut section = String::new();
    let mut iface: Vec<(String, String)> = Vec::new();
    let mut peers: Vec<Vec<(String, String)>> = Vec::new();
    for raw in text.lines() {
        let line = raw.split(['#', ';']).next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            if section == "peer" {
                peers.push(Vec::new());
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let kv = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match section.as_str() {
            "interface" => iface.push(kv),
            "peer" => peers.last_mut().expect("peer section").push(kv),
            _ => {}
        }
    }
    let get = |list: &[(String, String)], key: &str| -> Option<String> {
        list.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).filter(|v| !v.is_empty())
    };
    let get_all = |list: &[(String, String)], key: &str| -> Vec<String> {
        list.iter().filter(|(k, _)| k == key).flat_map(|(_, v)| split_list(v)).collect()
    };

    let mut warnings = Vec::new();
    let awg = amnezia_fields(&iface, &mut warnings)?;

    let private_key = get(&iface, "privatekey").ok_or("в [Interface] нет PrivateKey")?;
    let address: Vec<String> = get_all(&iface, "address").into_iter().map(crate::links::with_prefix).collect();
    if address.is_empty() {
        return Err("в [Interface] нет Address".into());
    }
    if peers.is_empty() {
        return Err("нет секции [Peer]".into());
    }
    let mut out_peers = Vec::new();
    for peer in &peers {
        let public_key = get(peer, "publickey").ok_or("в [Peer] нет PublicKey")?;
        let endpoint = get(peer, "endpoint").ok_or("в [Peer] нет Endpoint")?;
        let (host, port) = split_host_port(&endpoint);
        let port: u16 = port.ok_or("в Endpoint нет порта")?.parse().map_err(|_| "неверный порт в Endpoint")?;
        let mut p = Map::new();
        p.insert("address".into(), json!(host));
        p.insert("port".into(), json!(port));
        p.insert("public_key".into(), json!(public_key));
        if let Some(psk) = get(peer, "presharedkey") {
            p.insert("pre_shared_key".into(), json!(psk));
        }
        let mut allowed = get_all(peer, "allowedips");
        if allowed.is_empty() {
            allowed = vec!["0.0.0.0/0".into(), "::/0".into()];
        }
        p.insert("allowed_ips".into(), json!(allowed));
        if let Some(ka) = get(peer, "persistentkeepalive") {
            // AmneziaWG 3.x allows a range ("22-30"); only sing-box-lx takes it.
            match parse_range(&ka) {
                Some(Range::One(0)) | None => {}
                Some(Range::One(n)) => {
                    p.insert("persistent_keepalive_interval".into(), json!(n));
                }
                Some(Range::Span(..)) => {
                    p.insert("persistent_keepalive_interval".into(), json!(ka.replace(' ', "")));
                }
            }
        }
        out_peers.push(Value::Object(p));
    }
    let mut ob = Map::new();
    ob.insert("type".into(), json!("wireguard"));
    ob.insert("address".into(), json!(address));
    ob.insert("private_key".into(), json!(private_key));
    if let Some(mtu) = get(&iface, "mtu").and_then(|m| m.parse::<u32>().ok()) {
        ob.insert("mtu".into(), json!(mtu));
    }
    ob.insert("peers".into(), Value::Array(out_peers));
    ob.extend(awg);
    if get(&iface, "dns").is_some() {
        warnings.push("DNS из файла не используется: ReTunl настраивает DNS сам.".into());
    }
    let default_name = if crate::awg::is_amnezia(&Value::Object(ob.clone())) { "AmneziaWG" } else { "WireGuard" };
    let name = if name.trim().is_empty() { default_name.to_string() } else { name.trim().to_string() };
    Ok(WgImport { profile: ParsedLink { name, outbound: Value::Object(ob) }, warnings })
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Range {
    One(u64),
    Span(u64, u64),
}

/// `25` or `22-30`.
fn parse_range(v: &str) -> Option<Range> {
    let v = v.trim();
    match v.split_once('-') {
        Some((a, b)) => {
            let (a, b) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
            (a <= b).then_some(Range::Span(a, b))
        }
        None => v.parse().ok().map(Range::One),
    }
}

/// Keys of plain WireGuard (and wg-quick) that need no translation here.
const PLAIN_KEYS: &[&str] = &[
    "privatekey", "address", "dns", "mtu", "listenport", "table", "fwmark", "saveconfig", "preup",
    "postup", "predown", "postdown",
];

/// AmneziaWG 1.x–3.1 fields of `[Interface]` as sing-box-lx endpoint fields.
/// Values left at their "off" setting are dropped, so a file without
/// obfuscation stays a plain WireGuard server.
fn amnezia_fields(iface: &[(String, String)], warnings: &mut Vec<String>) -> Result<Map<String, Value>, LinkError> {
    let mut out = Map::new();
    let mut unknown = Vec::new();
    for (key, raw) in iface {
        let v = raw.trim();
        let bad = |what: &str| LinkError::Invalid(format!("параметр AmneziaWG {key} = {v}: {what}"));
        let (name, value): (&str, Value) = match key.as_str() {
            // plain numbers
            "jc" | "jmin" | "jmax" | "s1" | "s2" | "s3" | "s4" => {
                let n: u64 = v.parse().map_err(|_| bad("нужно целое число"))?;
                (static_key(key), json!(n))
            }
            // a number or a range "a-b"
            "h1" | "h2" | "h3" | "h4" | "contentpaddingaddition" | "rekeyaftertime" | "rekeytimeout"
            | "rejectaftertime" | "keepalivetimeout" | "maxhandshakeattempts" => {
                let value = match parse_range(v).ok_or_else(|| bad("нужно число или диапазон вида 10-20"))? {
                    Range::One(n) => json!(n),
                    Range::Span(..) => json!(v.replace(' ', "")),
                };
                (static_key(key), value)
            }
            // decoy packets: "<b 0x…><r 16>…"
            "i1" | "i2" | "i3" | "i4" | "i5" => (static_key(key), json!(v)),
            "headerprotectionkey" => ("header_protection_key", json!(v)),
            "randomtrailers" | "disablecookies" => {
                let on = match v.to_ascii_lowercase().as_str() {
                    "on" | "true" | "yes" | "1" => true,
                    "off" | "false" | "no" | "0" | "" => false,
                    _ => return Err(bad("нужно on или off")),
                };
                (static_key(key), json!(on))
            }
            k if PLAIN_KEYS.contains(&k) => continue,
            _ => {
                unknown.push(key.clone());
                continue;
            }
        };
        out.insert(name.to_string(), value);
    }
    // drop values that mean "off" (S1 = 0, H1 = 1, RandomTrailers = off …)
    let probe = Value::Object({
        let mut m = out.clone();
        m.insert("type".into(), json!("wireguard"));
        m
    });
    let active = crate::awg::awg_fields(&probe);
    out.retain(|k, _| active.contains(&k.as_str()));
    if !unknown.is_empty() {
        warnings.push(format!("Неизвестные параметры пропущены: {}.", unknown.join(", ")));
    }
    Ok(out)
}

fn static_key(conf_key: &str) -> &'static str {
    match conf_key {
        "jc" => "jc",
        "jmin" => "jmin",
        "jmax" => "jmax",
        "s1" => "s1",
        "s2" => "s2",
        "s3" => "s3",
        "s4" => "s4",
        "h1" => "h1",
        "h2" => "h2",
        "h3" => "h3",
        "h4" => "h4",
        "i1" => "i1",
        "i2" => "i2",
        "i3" => "i3",
        "i4" => "i4",
        "i5" => "i5",
        "contentpaddingaddition" => "content_padding_addition",
        "rekeyaftertime" => "rekey_after_time",
        "rekeytimeout" => "rekey_timeout",
        "rejectaftertime" => "reject_after_time",
        "keepalivetimeout" => "keepalive_timeout",
        "maxhandshakeattempts" => "max_handshake_attempts",
        "randomtrailers" => "random_trailers",
        "disablecookies" => "disable_cookies",
        _ => unreachable!("unknown AmneziaWG key {conf_key}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32, fd42:42:42::2/128
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = 9kbV2lBtv6GQw9tDYtjxf1Xh7xOzs0n1Ha7I1xvLK3E=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
";

    #[test]
    fn plain_wireguard() {
        let r = parse(CONF, "home").unwrap();
        let o = &r.profile.outbound;
        assert_eq!(r.profile.name, "home");
        assert_eq!(o["address"], json!(["10.8.0.2/32", "fd42:42:42::2/128"]));
        assert_eq!(o["mtu"], 1420);
        assert_eq!(o["peers"][0]["address"], "vpn.example.com");
        assert_eq!(o["peers"][0]["port"], 51820);
        assert_eq!(o["peers"][0]["persistent_keepalive_interval"], 25);
        assert_eq!(o["peers"][0]["pre_shared_key"], "9kbV2lBtv6GQw9tDYtjxf1Xh7xOzs0n1Ha7I1xvLK3E=");
        assert_eq!(r.warnings.len(), 1); // DNS ignored
    }

    #[test]
    fn amnezia_junk_only() {
        let conf = CONF.replace("MTU = 1420", "MTU = 1420\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4");
        let o = parse(&conf, "awg").unwrap().profile.outbound;
        assert_eq!((o["jc"].clone(), o["jmin"].clone(), o["jmax"].clone()), (json!(4), json!(40), json!(70)));
        // "off" values are not carried over
        assert!(o.get("s1").is_none() && o.get("h1").is_none());
        assert_eq!(crate::awg::core_need(&o), crate::awg::CoreNeed::PreferExtended);
    }

    #[test]
    fn amnezia_2_0() {
        let conf = CONF.replace(
            "MTU = 1420",
            "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 86\nS2 = 12\nS3 = 20\nS4 = 9\nH1 = 1234567-1240000\nH2 = 22\nH3 = 3\nH4 = 4\nI1 = <b 0xc700000001><r 16>",
        );
        let o = parse(&conf, "").unwrap().profile;
        assert_eq!(o.name, "AmneziaWG");
        let o = o.outbound;
        assert_eq!(o["s1"], 86);
        assert_eq!(o["h1"], "1234567-1240000");
        assert_eq!(o["h2"], 22);
        assert!(o.get("h3").is_none());
        assert_eq!(o["i1"], "<b 0xc700000001><r 16>");
        assert_eq!(crate::awg::core_need(&o), crate::awg::CoreNeed::Extended);
    }

    #[test]
    fn amnezia_3_1() {
        let conf = CONF
            .replace(
                "MTU = 1420",
                "Jc = 3\nJmin = 10\nJmax = 40\nS1 = 20\nS2 = 30\nS3 = 16\nS4 = 12\n\
                 HeaderProtectionKey = KIKOZNzj+d+G5Gw84nfLm49oM/f+xMoThA4AEOqyZkc=\n\
                 ContentPaddingAddition = 0-32\nRekeyAfterTime = 100-120\nMaxHandshakeAttempts = 18\n\
                 RandomTrailers = on\nDisableCookies = off\nFooBar = 1",
            )
            .replace("PersistentKeepalive = 25", "PersistentKeepalive = 22-30");
        let r = parse(&conf, "awg3").unwrap();
        let o = &r.profile.outbound;
        assert_eq!(o["header_protection_key"], "KIKOZNzj+d+G5Gw84nfLm49oM/f+xMoThA4AEOqyZkc=");
        assert_eq!(o["content_padding_addition"], "0-32");
        assert_eq!(o["rekey_after_time"], "100-120");
        assert_eq!(o["max_handshake_attempts"], 18);
        assert_eq!(o["random_trailers"], true);
        assert!(o.get("disable_cookies").is_none());
        assert_eq!(o["peers"][0]["persistent_keepalive_interval"], "22-30");
        assert!(r.warnings.iter().any(|w| w.contains("foobar")));
    }

    #[test]
    fn amnezia_bad_values() {
        assert!(parse(&CONF.replace("MTU = 1420", "Jc = many"), "x").is_err());
        assert!(parse(&CONF.replace("MTU = 1420", "H1 = 30-10"), "x").is_err());
        assert!(parse(&CONF.replace("MTU = 1420", "RandomTrailers = maybe"), "x").is_err());
    }

    #[test]
    fn missing_parts() {
        assert!(parse("[Interface]\nPrivateKey = x\n", "x").is_err());
        assert!(looks_like_wg_conf(CONF));
        assert!(!looks_like_wg_conf("vless://x"));
    }
}
