//! AmneziaWG and other options only the sing-box-lx core understands, and the
//! choice between the official core and sing-box-lx.
//!
//! AmneziaWG fields sit at the root of a sing-box `wireguard` endpoint
//! (`jc`, `s1`, `h1`, `i1`, `header_protection_key`, …). Junk packets
//! (`jc/jmin/jmax`) are sent by the client only, so a server works without
//! them; everything else changes the packets and must match the server.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Client-side junk packets: safe to drop when only the official core is available.
pub const JUNK_KEYS: &[&str] = &["jc", "jmin", "jmax"];

/// Fields that change the wire format (AWG 1.x–3.1); they must reach the core.
pub const STRICT_KEYS: &[&str] = &[
    "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
    "header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout",
    "reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers",
    "disable_cookies",
];

/// Which sing-box build runs the connection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CoreKind {
    /// sing-box from SagerNet.
    #[default]
    Official,
    /// sing-box-lx: AmneziaWG 2.0–3.1, XHTTP.
    Extended,
}

/// User preference for the core.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CorePref {
    /// Official core, sing-box-lx only when a server needs it.
    #[default]
    Auto,
    Official,
    Extended,
}

/// What a server asks of the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoreNeed {
    Any,
    /// Works on the official core, but loses AmneziaWG junk packets there.
    PreferExtended,
    Extended,
}

fn is_default(key: &str, v: &Value) -> bool {
    let header = match key {
        "h1" => Some(1),
        "h2" => Some(2),
        "h3" => Some(3),
        "h4" => Some(4),
        _ => None,
    };
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_u64() == Some(0) || (header.is_some() && n.as_u64() == header),
        Value::String(s) => {
            let s = s.trim();
            s.is_empty() || s == "0" || s == "0-0" || header.is_some_and(|h| s == h.to_string())
        }
        _ => false,
    }
}

/// AmneziaWG fields that are actually set (not left at their "off" value).
pub fn awg_fields(outbound: &Value) -> Vec<&'static str> {
    if outbound.get("type").and_then(Value::as_str) != Some("wireguard") {
        return Vec::new();
    }
    JUNK_KEYS
        .iter()
        .chain(STRICT_KEYS)
        .copied()
        .filter(|k| outbound.get(*k).is_some_and(|v| !is_default(k, v)))
        .collect()
}

pub fn is_amnezia(outbound: &Value) -> bool {
    !awg_fields(outbound).is_empty()
}

pub fn core_need(outbound: &Value) -> CoreNeed {
    if outbound.pointer("/transport/type").and_then(Value::as_str) == Some("xhttp") {
        return CoreNeed::Extended;
    }
    let fields = awg_fields(outbound);
    let ranged_keepalive = outbound
        .get("peers")
        .and_then(Value::as_array)
        .is_some_and(|ps| ps.iter().any(|p| p.get("persistent_keepalive_interval").is_some_and(Value::is_string)));
    if ranged_keepalive || fields.iter().any(|f| STRICT_KEYS.contains(f)) {
        CoreNeed::Extended
    } else if !fields.is_empty() {
        CoreNeed::PreferExtended
    } else {
        CoreNeed::Any
    }
}

/// Short reason for the user: what makes this server need sing-box-lx.
pub fn need_reason(outbound: &Value) -> &'static str {
    if outbound.pointer("/transport/type").and_then(Value::as_str) == Some("xhttp") {
        "XHTTP"
    } else {
        "AmneziaWG"
    }
}

/// Pick the core for a set of servers. `Err` means sing-box-lx is required
/// but not available (or switched off in settings).
pub fn pick_core(pref: CorePref, need: CoreNeed, extended_available: bool) -> Result<CoreKind, ()> {
    match pref {
        CorePref::Official if need == CoreNeed::Extended => Err(()),
        CorePref::Official => Ok(CoreKind::Official),
        CorePref::Extended if extended_available => Ok(CoreKind::Extended),
        CorePref::Extended => Err(()),
        CorePref::Auto => match need {
            CoreNeed::Any => Ok(CoreKind::Official),
            _ if extended_available => Ok(CoreKind::Extended),
            CoreNeed::PreferExtended => Ok(CoreKind::Official),
            CoreNeed::Extended => Err(()),
        },
    }
}

/// Make an endpoint acceptable to the official core: drop AmneziaWG fields
/// left at their "off" value and the junk-packet settings. Returns true if
/// junk packets were dropped.
pub fn strip_for_official(ob: &mut Map<String, Value>) -> bool {
    if ob.get("type").and_then(Value::as_str) != Some("wireguard") {
        return false;
    }
    let mut dropped_junk = false;
    for k in JUNK_KEYS {
        if let Some(v) = ob.remove(*k) {
            dropped_junk |= !is_default(k, &v);
        }
    }
    for k in STRICT_KEYS {
        if ob.get(*k).is_some_and(|v| is_default(k, v)) {
            ob.remove(*k);
        }
    }
    dropped_junk
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn needs() {
        assert_eq!(core_need(&json!({"type": "wireguard", "private_key": "x"})), CoreNeed::Any);
        assert_eq!(core_need(&json!({"type": "wireguard", "jc": 4, "s1": 0, "h1": 1})), CoreNeed::PreferExtended);
        assert_eq!(core_need(&json!({"type": "wireguard", "jc": 4, "h1": "100-200"})), CoreNeed::Extended);
        assert_eq!(core_need(&json!({"type": "wireguard", "random_trailers": true})), CoreNeed::Extended);
        assert_eq!(core_need(&json!({"type": "wireguard", "random_trailers": false, "h3": 3})), CoreNeed::Any);
        assert_eq!(
            core_need(&json!({"type": "wireguard", "peers": [{"persistent_keepalive_interval": "20-30"}]})),
            CoreNeed::Extended
        );
        assert_eq!(core_need(&json!({"type": "vless", "transport": {"type": "xhttp"}})), CoreNeed::Extended);
        assert_eq!(core_need(&json!({"type": "vless", "jc": 4})), CoreNeed::Any);
    }

    #[test]
    fn picking() {
        use CoreNeed::*;
        assert_eq!(pick_core(CorePref::Auto, Any, true), Ok(CoreKind::Official));
        assert_eq!(pick_core(CorePref::Auto, PreferExtended, true), Ok(CoreKind::Extended));
        assert_eq!(pick_core(CorePref::Auto, PreferExtended, false), Ok(CoreKind::Official));
        assert_eq!(pick_core(CorePref::Auto, Extended, false), Err(()));
        assert_eq!(pick_core(CorePref::Official, PreferExtended, true), Ok(CoreKind::Official));
        assert_eq!(pick_core(CorePref::Official, Extended, true), Err(()));
        assert_eq!(pick_core(CorePref::Extended, Any, true), Ok(CoreKind::Extended));
        assert_eq!(pick_core(CorePref::Extended, Any, false), Err(()));
    }

    #[test]
    fn stripping() {
        let mut ob = json!({"type": "wireguard", "jc": 4, "jmin": 10, "jmax": 50, "s1": 0, "h1": 1, "mtu": 1280})
            .as_object()
            .cloned()
            .unwrap();
        assert!(strip_for_official(&mut ob));
        assert_eq!(Value::Object(ob), json!({"type": "wireguard", "mtu": 1280}));
    }
}
