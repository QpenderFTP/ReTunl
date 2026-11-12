//! Settings, and the config they lead to.

use retunl_core::singbox::{self, BuildOptions};
use retunl_core::{dns, Settings};
use serde_json::Value;

use super::{St, R};
use crate::{speed, sys};

fn config_part(s: &Settings) -> Settings {
    let mut c = s.clone();
    c.connect_on_launch = false;
    c.close_to_tray = false;
    c.start_minimized = false;
    c.run_as_admin = false;
    c.test_url = String::new();
    c.speed = Default::default();
    c
}

/// Merge a partial settings object (`{"mode": "tun"}`) into the current ones.
#[tauri::command]
pub fn update_settings(st: St<'_>, patch: Value) -> R<Settings> {
    let (before, after) = st.mutate(|d| {
        let before = d.settings.clone();
        let mut current = serde_json::to_value(&d.settings).map_err(|e| e.to_string())?;
        merge_json(&mut current, patch);
        let next: Settings = serde_json::from_value(current).map_err(|e| format!("Неверные настройки: {e}"))?;
        dns::server(&next.dns.direct, "x", None, "y").map_err(|e| format!("DNS для прямого трафика: {e}"))?;
        dns::server(&next.dns.remote, "x", None, "y").map_err(|e| format!("DNS через VPN: {e}"))?;
        if next.mixed_port < 1024 || next.controller_port < 1024 {
            return Err("Порты должны быть от 1024 до 65535".into());
        }
        let mut next = next;
        for own in &mut next.speed.custom {
            own.url = own.url.trim().to_string();
            speed::check_custom_url(&own.url)?;
            own.name = own.name.trim().to_string();
            if own.name.is_empty() {
                // the host says where the file is
                own.name = reqwest::Url::parse(&own.url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
            }
            if own.id.trim().is_empty() {
                return Err("У своего тестового сервера нет идентификатора".into());
            }
        }
        d.settings = next.clone();
        Ok((before, next))
    })?;
    if config_part(&before) != config_part(&after) {
        st.request_reload();
    }
    // autostart follows: elevated through Task Scheduler or plain through the Run key
    if cfg!(windows) && before.run_as_admin != after.run_as_admin && sys::autostart_status().enabled {
        if let Err(e) = sys::set_autostart(true, after.run_as_admin) {
            st.engine.log_app("WARN", &format!("Автозапуск не перенастроен: {e}"));
        }
    }
    Ok(after)
}

fn merge_json(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(t), Value::Object(p)) => {
            for (k, v) in p {
                match t.get_mut(&k) {
                    // tagged values like a Route are replaced whole, not merged
                    Some(slot) if slot.is_object() && v.is_object() && v.get("kind").is_none() => merge_json(slot, v),
                    _ => {
                        t.insert(k, v);
                    }
                }
            }
        }
        (t, p) => *t = p,
    }
}

/// The config that would be used right now (for the "show config" button).
#[tauri::command]
pub fn preview_config(st: St<'_>) -> R<String> {
    let built = singbox::build(
        &st.snapshot(),
        &BuildOptions {
            ruleset_dir: st.paths.ruleset_dir(),
            controller_secret: "••••".into(),
            cache_file: None,
            extended_available: st.paths.find_lx_core().is_some(),
            // the preview shows the settings as chosen; the TLS switch happens on connect
            direct_dns_tls: false,
            wiresock: None,
        },
    )
    .map_err(|e| e.0)?;
    serde_json::to_string_pretty(&built.config).map_err(|e| e.to_string())
}
