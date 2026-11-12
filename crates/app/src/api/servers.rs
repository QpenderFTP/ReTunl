//! The list of servers: selecting, renaming, editing, WireSock, tests.

use std::collections::HashMap;

use retunl_core::links::ParsedLink;
use retunl_core::{wgconf, Profile, WireSock};
use serde::Deserialize;
use serde_json::Value;
use tauri::{AppHandle, Emitter};

use super::{St, R};
use crate::probe::{self, Latency};
use crate::speed::{self, SpeedResult};
use crate::state::{add_profiles, forget_profiles};
use crate::sys::{self, Adapter};
use crate::util::{blocking, locked};
use crate::wiresock;

#[tauri::command]
pub fn set_active(st: St<'_>, id: String) -> R<()> {
    st.mutate(|d| {
        if d.profile(&id).is_none() {
            return Err("Сервер не найден".into());
        }
        d.settings.active_profile = Some(id.clone());
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

#[tauri::command]
pub fn rename_profile(st: St<'_>, id: String, name: String) -> R<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Название не может быть пустым".into());
    }
    st.mutate(|d| {
        let p = d.profile_mut(&id).ok_or("Сервер не найден")?;
        p.name = name;
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

/// Replace a server's sing-box settings with edited JSON.
#[tauri::command]
pub fn set_profile_json(st: St<'_>, id: String, json: String) -> R<()> {
    let mut v: Value = serde_json::from_str(&json).map_err(|e| format!("Ошибка в JSON: {e}"))?;
    let obj = v.as_object_mut().ok_or("Нужен JSON-объект { … }")?;
    obj.remove("tag");
    let ty = obj.get("type").and_then(Value::as_str).ok_or("Не указан \"type\" (протокол)")?;
    if !retunl_core::PROXY_TYPES.contains(&ty) {
        return Err(format!("Неизвестный протокол «{ty}»"));
    }
    st.mutate(|d| {
        let p = d.profile_mut(&id).ok_or("Сервер не найден")?;
        p.outbound = v;
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

/// Junk packets of a WireGuard server (AmneziaWG `Jc`, `Jmin`, `Jmax`): sent
/// by the client only, so any server takes them.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Junk {
    jc: u64,
    jmin: u64,
    jmax: u64,
}

/// Switch a WireGuard server to WireSock or back, with its masking and junk packets.
#[tauri::command]
pub fn set_wiresock(st: St<'_>, id: String, wiresock: WireSock, junk: Junk) -> R<()> {
    let mut ws = wiresock;
    ws.domain = ws.domain.trim().to_ascii_lowercase();
    ws.protocol = ws.protocol.trim().to_ascii_lowercase();
    ws.browser = ws.browser.trim().to_ascii_lowercase();
    if !ws.protocol.is_empty() && !wgconf::WS_PROTOCOLS.contains(&ws.protocol.as_str()) {
        return Err(format!("Неизвестный протокол маскировки «{}»", ws.protocol));
    }
    if !ws.protocol.is_empty() && ws.domain.is_empty() {
        return Err("Укажите домен для маскировки: популярный в вашей стране сайт, например ozon.ru".into());
    }
    if ws.domain.contains(['/', ' ', ':']) {
        return Err("Домен для маскировки пишется без http:// и пути, например ozon.ru".into());
    }
    if ws.protocol != "quic" || !wgconf::WS_BROWSERS.contains(&ws.browser.as_str()) {
        ws.browser = String::new();
    }
    if ws.protocol.is_empty() {
        ws.domain = String::new();
    }
    if junk.jc > 128 {
        return Err("Мусорных пакетов может быть не больше 128".into());
    }
    if junk.jc > 0 && (junk.jmin > junk.jmax || junk.jmax > 1280) {
        return Err("Размер мусорных пакетов: минимум не больше максимума, максимум до 1280 байт".into());
    }
    if ws.junk_delay > 1000 {
        return Err("Пауза между мусорными пакетами — не больше 1000 мс".into());
    }
    st.mutate(|d| {
        let p = d.profile_mut(&id).ok_or("Сервер не найден")?;
        if p.protocol() != "wireguard" {
            return Err("Через WireSock подключаются только серверы WireGuard и AmneziaWG".into());
        }
        let mut ob = p.outbound.clone();
        let o = ob.as_object_mut().ok_or("Сервер повреждён")?;
        if junk.jc > 0 {
            o.insert("jc".into(), junk.jc.into());
            o.insert("jmin".into(), junk.jmin.into());
            o.insert("jmax".into(), junk.jmax.into());
        } else {
            for k in retunl_core::awg::JUNK_KEYS {
                o.remove(*k);
            }
        }
        if ws.enabled {
            if let Some(why) = wgconf::wiresock_unsupported(&ob) {
                return Err(why);
            }
        }
        p.outbound = ob;
        p.wiresock = (ws != WireSock::default()).then_some(ws);
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

#[tauri::command]
pub fn delete_profiles(st: St<'_>, ids: Vec<String>) -> R<usize> {
    let fixed = st.mutate(|d| {
        d.profiles.retain(|p| !ids.contains(&p.id));
        Ok(forget_profiles(d, &ids, None))
    })?;
    st.request_reload();
    Ok(fixed)
}

#[tauri::command]
pub fn add_interface(st: St<'_>, name: String) -> R<String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Выберите адаптер".into());
    }
    let item = ParsedLink { name: name.clone(), outbound: serde_json::json!({"type": "direct", "bind_interface": name}) };
    let (added, _) = st.mutate(|d| Ok(add_profiles(d, vec![item], None, &[None])))?;
    added.first().cloned().ok_or_else(|| "Такой адаптер уже добавлен".into())
}

#[tauri::command]
pub async fn list_adapters() -> R<Vec<Adapter>> {
    blocking(sys::adapters).await
}

#[tauri::command]
pub async fn test_latency(st: St<'_>, ids: Option<Vec<String>>) -> R<HashMap<String, Latency>> {
    let data = st.snapshot();
    // a server WireSock runs right now is measured through WireSock
    let link = st.engine.wiresock_link();
    let profiles: Vec<Profile> = data
        .profiles
        .iter()
        .filter(|p| ids.as_ref().is_none_or(|ids| ids.contains(&p.id)))
        .cloned()
        .map(|p| wiresock::through_tunnel(p, link.as_ref()))
        .collect();
    if profiles.is_empty() {
        return Ok(HashMap::new());
    }
    let results = probe::measure(&st.paths, &data.settings, profiles, st.engine.job()).await?;
    locked(&st.latency).extend(results.clone());
    Ok(results)
}

/// Download speed and ping without the VPN and through a server: `profile`
/// for this run only, else the one from the speed settings, else the selected
/// one. Progress comes as `speed-progress` events.
#[tauri::command]
pub async fn speed_test(app: AppHandle, st: St<'_>, profile: Option<String>) -> R<SpeedResult> {
    let Ok(_running) = st.speed_lock.try_lock() else {
        return Err("Проверка скорости уже идёт.".into());
    };
    let data = st.snapshot();
    let profile = profile
        .as_deref()
        .or(data.settings.speed.profile.as_deref())
        .and_then(|id| data.profile(id))
        .or_else(|| data.active_profile())
        .cloned()
        .map(|p| wiresock::through_tunnel(p, st.engine.wiresock_link().as_ref()));
    let h = app.clone();
    let r = speed::run(&st.paths, &data.settings, profile, st.engine.job(), move |p| {
        let _ = h.emit("speed-progress", &p);
    })
    .await?;
    *locked(&st.speed) = Some(r.clone());
    Ok(r)
}
