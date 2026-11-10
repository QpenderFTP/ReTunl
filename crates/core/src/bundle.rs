//! Encrypted export of servers, subscriptions, rules and presets — to move
//! them to another computer.
//!
//! Text form: `retunl-bundle:1:` + base64url of
//! `version(1) | m_cost KiB (u32 LE) | t_cost (u8) | lanes (u8) | salt (16) | nonce (24) | ciphertext`.
//! The key comes from the password with Argon2id; the payload (deflated JSON)
//! is sealed with XChaCha20-Poly1305, the header is authenticated too.

use std::collections::HashMap;
use std::io::{Read, Write};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::model::{AppData, CustomPreset, Profile, Route, Rule, Subscription};
use crate::util::{new_id, now_unix};

pub const PREFIX: &str = "retunl-bundle:1:";
/// File extension for saved bundles.
pub const EXTENSION: &str = "retunl";

const VERSION: u8 = 1;
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u8 = 3;
const LANES: u8 = 1;
const HEADER: usize = 1 + 4 + 1 + 1 + 16 + 24;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct BundleSubscription {
    pub subscription: Subscription,
    /// Servers as they were on export (usable even if the address is unreachable).
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct Bundle {
    #[serde(default)]
    pub app: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub subscriptions: Vec<BundleSubscription>,
    /// Servers added by hand.
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub presets: Vec<CustomPreset>,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum BundleError {
    #[error("это не файл экспорта ReTunl")]
    NotBundle,
    #[error("файл экспорта сделан более новой версией ReTunl")]
    TooNew,
    #[error("неверный пароль или файл повреждён")]
    WrongPassword,
    #[error("файл экспорта повреждён")]
    Corrupt,
    #[error("пароль не может быть пустым")]
    EmptyPassword,
    #[error("{0}")]
    Other(String),
}

pub fn looks_like(text: &str) -> bool {
    text.trim_start().trim_start_matches('\u{feff}').starts_with(PREFIX)
}

fn derive(password: &str, salt: &[u8], m: u32, t: u8, p: u8) -> Result<[u8; 32], BundleError> {
    let params = Params::new(m, t as u32, p as u32, Some(32)).map_err(|_| BundleError::Corrupt)?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| BundleError::Other(e.to_string()))?;
    Ok(key)
}

pub fn seal(bundle: &Bundle, password: &str) -> Result<String, BundleError> {
    if password.is_empty() {
        return Err(BundleError::EmptyPassword);
    }
    let json = serde_json::to_vec(bundle).map_err(|e| BundleError::Other(e.to_string()))?;
    let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    z.write_all(&json).map_err(|e| BundleError::Other(e.to_string()))?;
    let plain = z.finish().map_err(|e| BundleError::Other(e.to_string()))?;

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let mut header = Vec::with_capacity(HEADER);
    header.push(VERSION);
    header.extend(M_COST_KIB.to_le_bytes());
    header.push(T_COST);
    header.push(LANES);
    header.extend(salt);
    header.extend(nonce);

    let key = derive(password, &salt, M_COST_KIB, T_COST, LANES)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let sealed = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &header })
        .map_err(|_| BundleError::Other("не удалось зашифровать".into()))?;
    let mut raw = header;
    raw.extend(sealed);
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)))
}

pub fn open(text: &str, password: &str) -> Result<Bundle, BundleError> {
    let text = text.trim().trim_start_matches('\u{feff}');
    let body = text.strip_prefix(PREFIX).ok_or(BundleError::NotBundle)?;
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = URL_SAFE_NO_PAD.decode(body.trim_end_matches('=')).map_err(|_| BundleError::Corrupt)?;
    if raw.len() < HEADER + 16 {
        return Err(BundleError::Corrupt);
    }
    if raw[0] != VERSION {
        return Err(BundleError::TooNew);
    }
    let m = u32::from_le_bytes(raw[1..5].try_into().expect("4 bytes"));
    let (t, p) = (raw[5], raw[6]);
    // refuse absurd parameters instead of allocating gigabytes
    if !(8..=1024 * 1024).contains(&m) || t == 0 || t > 16 || p == 0 || p > 16 {
        return Err(BundleError::Corrupt);
    }
    let salt = &raw[7..23];
    let nonce = &raw[23..HEADER];
    let key = derive(password, salt, m, t, p)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: &raw[HEADER..], aad: &raw[..HEADER] })
        .map_err(|_| BundleError::WrongPassword)?;
    let mut json = Vec::new();
    flate2::read::DeflateDecoder::new(&plain[..])
        .take(64 * 1024 * 1024)
        .read_to_end(&mut json)
        .map_err(|_| BundleError::Corrupt)?;
    serde_json::from_slice(&json).map_err(|_| BundleError::Corrupt)
}

/// What to put into an export. Ids are local ones.
pub fn collect(data: &AppData, subscription_ids: &[String], profile_ids: &[String], rules: bool, presets: bool) -> Bundle {
    Bundle {
        app: "ReTunl".into(),
        created_at: now_unix(),
        subscriptions: data
            .subscriptions
            .iter()
            .filter(|s| subscription_ids.contains(&s.id))
            .map(|s| BundleSubscription {
                subscription: s.clone(),
                profiles: data.profiles.iter().filter(|p| p.subscription.as_deref() == Some(s.id.as_str())).cloned().collect(),
            })
            .collect(),
        profiles: data
            .profiles
            .iter()
            .filter(|p| p.subscription.is_none() && profile_ids.contains(&p.id))
            .cloned()
            .collect(),
        rules: if rules { data.rules.clone() } else { Vec::new() },
        presets: if presets { data.presets.clone() } else { Vec::new() },
    }
}

/// What an import changed.
#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Merged {
    pub subscriptions: usize,
    /// Already here (same address) — kept as they are.
    pub subscriptions_existing: usize,
    pub profiles: usize,
    pub profiles_existing: usize,
    pub rules: usize,
    pub rules_existing: usize,
    pub presets: usize,
    /// Rules and templates whose server did not come along: now "through VPN".
    pub routes_reset: usize,
}

/// Bundle parts that are already on this computer, by bundle ids.
#[derive(Debug, Default, Serialize, PartialEq)]
pub struct Overlap {
    pub subscriptions: Vec<String>,
    pub profiles: Vec<String>,
}

pub fn overlap(data: &AppData, b: &Bundle) -> Overlap {
    Overlap {
        subscriptions: b
            .subscriptions
            .iter()
            .filter(|bs| data.subscriptions.iter().any(|s| s.url.trim() == bs.subscription.url.trim()))
            .map(|bs| bs.subscription.id.clone())
            .collect(),
        profiles: b
            .profiles
            .iter()
            .filter(|p| data.profiles.iter().any(|x| x.outbound == p.outbound))
            .map(|p| p.id.clone())
            .collect(),
    }
}

/// Conditions of a rule, without its identity — to spot the same rule twice.
fn rule_key(r: &Rule) -> Rule {
    Rule { id: String::new(), enabled: true, preset: None, ..r.clone() }
}

/// Add everything from a bundle that is not here yet. Servers and
/// subscriptions get new ids; rules and templates follow them.
pub fn merge(data: &mut AppData, b: Bundle) -> Merged {
    let mut m = Merged::default();
    // bundle profile id -> local id
    let mut ids: HashMap<String, String> = HashMap::new();

    for bs in b.subscriptions {
        let url = bs.subscription.url.trim().to_string();
        if let Some(local) = data.subscriptions.iter().find(|s| s.url.trim() == url) {
            m.subscriptions_existing += 1;
            let local_id = local.id.clone();
            for p in &bs.profiles {
                let same = data.profiles.iter().find(|x| x.subscription.as_deref() == Some(local_id.as_str()) && x.name == p.name).or_else(|| {
                    data.profiles.iter().find(|x| x.subscription.as_deref() == Some(local_id.as_str()) && x.outbound == p.outbound)
                });
                if let Some(x) = same {
                    ids.insert(p.id.clone(), x.id.clone());
                }
            }
            continue;
        }
        let sid = new_id();
        let mut sub = bs.subscription;
        sub.id = sid.clone();
        sub.last_error = None;
        data.subscriptions.push(sub);
        m.subscriptions += 1;
        for mut p in bs.profiles {
            let pid = new_id();
            ids.insert(std::mem::replace(&mut p.id, pid), p.id.clone());
            p.subscription = Some(sid.clone());
            data.profiles.push(p);
            m.profiles += 1;
        }
    }

    for mut p in b.profiles {
        if let Some(x) = data.profiles.iter().find(|x| x.outbound == p.outbound) {
            ids.insert(p.id, x.id.clone());
            m.profiles_existing += 1;
            continue;
        }
        let pid = new_id();
        ids.insert(std::mem::replace(&mut p.id, pid), p.id.clone());
        p.subscription = None;
        p.created_at = now_unix();
        data.profiles.push(p);
        m.profiles += 1;
    }

    let local: std::collections::HashSet<String> = data.profiles.iter().map(|p| p.id.clone()).collect();
    let remap = |route: &mut Route, m: &mut Merged| {
        if let Route::Profile { id } = route {
            match ids.get(id.as_str()) {
                Some(n) => *id = n.clone(),
                // exported and imported on the same computer
                None if local.contains(id.as_str()) => {}
                None => {
                    *route = Route::Proxy;
                    m.routes_reset += 1;
                }
            }
        }
    };

    for mut r in b.rules {
        remap(&mut r.route, &mut m);
        if data.rules.iter().any(|x| rule_key(x) == rule_key(&r)) {
            m.rules_existing += 1;
            continue;
        }
        r.id = new_id();
        data.rules.push(r);
        m.rules += 1;
    }

    for mut p in b.presets {
        remap(&mut p.route, &mut m);
        let same_as = |x: &CustomPreset| CustomPreset { id: String::new(), created_at: 0, ..x.clone() };
        if let Some(x) = data.presets.iter_mut().find(|x| x.id == p.id) {
            if same_as(&*x) != same_as(&p) {
                *x = p;
                m.presets += 1;
            }
            continue;
        }
        if data.presets.iter().any(|x| same_as(x) == same_as(&p)) {
            continue;
        }
        if p.id.is_empty() {
            p.id = format!("my-{}", new_id());
        }
        data.presets.push(p);
        m.presets += 1;
    }

    if data.settings.active_profile.as_ref().and_then(|id| data.profile(id)).is_none() {
        data.settings.active_profile = data.profiles.first().map(|p| p.id.clone());
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collect_and_merge() {
        let mut src = AppData::default();
        let b = sample();
        merge(&mut src, b.clone());
        let manual = Profile {
            id: "m1".into(),
            name: "Дом".into(),
            outbound: json!({"type": "socks", "server": "10.0.0.1", "server_port": 1080}),
            subscription: None,
            link: None,
            created_at: 0,
            wiresock: None,
        };
        src.profiles.push(manual);
        let nl = src.profiles[0].id.clone();
        src.rules.push(Rule { id: "r1".into(), name: "Telegram".into(), apps: vec!["Telegram.exe".into()], route: Route::Profile { id: nl.clone() }, ..Default::default() });
        src.rules.push(Rule { id: "r2".into(), name: "Дом".into(), ips: vec!["10.0.0.0/8".into()], route: Route::Profile { id: "m1".into() }, ..Default::default() });
        src.presets.push(CustomPreset { id: "my-1".into(), title: "Игры".into(), apps: vec!["C:\\Games\\".into()], route: Route::Direct, ..Default::default() });

        // only the subscription: the rule to the manual server falls back to the VPN
        let sid = src.subscriptions[0].id.clone();
        let out = collect(&src, &[sid], &[], true, true);
        assert_eq!(out.subscriptions.len(), 1);
        assert_eq!(out.subscriptions[0].profiles.len(), 1);
        assert!(out.profiles.is_empty());
        let text = seal(&out, "pw").unwrap();

        let mut dst = AppData::default();
        let m = merge(&mut dst, open(&text, "pw").unwrap());
        assert_eq!((m.subscriptions, m.profiles, m.rules, m.presets, m.routes_reset), (1, 1, 2, 1, 1));
        let new_nl = dst.profiles[0].id.clone();
        assert_ne!(new_nl, nl);
        assert_eq!(dst.rules[0].route, Route::Profile { id: new_nl.clone() });
        assert_eq!(dst.rules[1].route, Route::Proxy);
        assert_eq!(dst.settings.active_profile.as_deref(), Some(new_nl.as_str()));
        assert_eq!(dst.profiles[0].subscription.as_deref(), Some(dst.subscriptions[0].id.as_str()));

        // the same again: nothing new, rules point at the same server
        let ov = overlap(&dst, &out);
        assert_eq!(ov.subscriptions.len(), 1);
        let m = merge(&mut dst, out.clone());
        assert_eq!((m.subscriptions, m.subscriptions_existing, m.rules, m.rules_existing, m.presets), (0, 1, 0, 2, 0));
        assert_eq!(dst.rules.len(), 2);
        assert_eq!(dst.profiles.len(), 1);
    }

    #[test]
    fn same_computer_keeps_routes() {
        let mut d = AppData::default();
        merge(&mut d, sample());
        let id = d.profiles[0].id.clone();
        d.rules.push(Rule { id: "r".into(), name: "x".into(), domains: vec!["a.com".into()], route: Route::Profile { id: id.clone() }, ..Default::default() });
        let mut b = collect(&d, &[], &[], true, false);
        b.rules[0].name = "y".into();
        let m = merge(&mut d, b);
        assert_eq!((m.rules, m.routes_reset), (1, 0));
        assert_eq!(d.rules[1].route, Route::Profile { id });
    }

    fn sample() -> Bundle {
        Bundle {
            app: "ReTunl".into(),
            created_at: 1,
            subscriptions: vec![BundleSubscription {
                subscription: Subscription {
                    id: "s1".into(),
                    name: "Моя подписка".into(),
                    url: "https://sub.example.com/x".into(),
                    updated_at: None,
                    info: None,
                    last_error: None,
                },
                profiles: vec![Profile {
                    id: "p1".into(),
                    name: "NL".into(),
                    outbound: json!({"type": "vless", "server": "nl.example.com", "server_port": 443}),
                    subscription: Some("s1".into()),
                    link: None,
                    created_at: 0,
                    wiresock: None,
                }],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn round_trip() {
        let text = seal(&sample(), "пароль 123").unwrap();
        assert!(looks_like(&text));
        assert!(!text.contains("example.com"));
        assert_eq!(open(&text, "пароль 123").unwrap(), sample());
    }

    #[test]
    fn wrong_password_and_tampering() {
        let text = seal(&sample(), "secret").unwrap();
        assert_eq!(open(&text, "Secret"), Err(BundleError::WrongPassword));
        // flip one byte of the header (memory cost) — authenticated, must fail
        let mut raw = URL_SAFE_NO_PAD.decode(&text[PREFIX.len()..]).unwrap();
        raw[1] ^= 1;
        let bad = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&raw));
        assert!(matches!(open(&bad, "secret"), Err(BundleError::WrongPassword)));
        assert_eq!(open("vless://x", "secret"), Err(BundleError::NotBundle));
        assert_eq!(seal(&sample(), ""), Err(BundleError::EmptyPassword));
    }
}
