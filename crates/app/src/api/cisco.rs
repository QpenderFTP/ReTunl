//! Cisco Secure Client as a server: its settings, logging in and out.

use retunl_core::util::{new_id, now_unix};
use retunl_core::{Cisco, Profile};

use super::{St, R};
use crate::cisco;
use crate::util::blocking;

/// Add a Cisco Secure Client server, or change one (`id`). Gives its id.
#[tauri::command]
pub async fn save_cisco(st: St<'_>, id: Option<String>, name: String, cisco: Cisco) -> R<String> {
    let c = Cisco {
        host: cisco.host.trim().to_string(),
        group: cisco.group.trim().to_string(),
        username: cisco.username.trim().to_string(),
        disconnect: cisco.disconnect,
    };
    if c.host.is_empty() {
        return Err("Укажите сервер Cisco: адрес или имя из списка в окне Cisco".into());
    }
    if [&c.host, &c.group, &c.username].iter().any(|f| f.contains(['\r', '\n'])) {
        return Err("Сервер, группа и логин пишутся в одну строку".into());
    }
    let name = match name.trim() {
        "" => "Cisco".to_string(),
        n => n.to_string(),
    };
    // the adapter is looked up again at each connection
    let adapter = blocking(cisco::adapter).await?;
    let id = st.mutate(|d| match id {
        Some(id) => {
            let p = d.profile_mut(&id).ok_or("Сервер не найден")?;
            if !p.is_cisco() {
                return Err("Это не сервер Cisco Secure Client".into());
            }
            p.name = name;
            p.cisco = Some(c);
            Ok(id)
        }
        None => {
            let id = new_id();
            let adapter = adapter.unwrap_or_else(|| "Cisco Secure Client".into());
            let outbound = serde_json::json!({"type": "direct", "bind_interface": adapter});
            d.profiles.push(Profile { created_at: now_unix(), cisco: Some(c), ..Profile::new(id.clone(), name, outbound) });
            if d.settings.active_profile.as_ref().and_then(|a| d.profile(a)).is_none() {
                d.settings.active_profile = Some(id.clone());
            }
            Ok(id)
        }
    })?;
    st.request_reload();
    Ok(id)
}

#[tauri::command]
pub async fn cisco_status() -> R<cisco::Status> {
    blocking(cisco::status).await?
}

/// Log in to Cisco Secure Client for server `id`. The password only passes through.
#[tauri::command]
pub async fn cisco_login(st: St<'_>, id: String, password: String, second: Option<String>) -> R<()> {
    let c = st.snapshot().profile(&id).and_then(|p| p.cisco.clone()).ok_or("Сервер Cisco не найден")?;
    let engine = st.engine.clone();
    blocking(move || {
        cisco::login(&c, &password, second.as_deref().unwrap_or_default(), &|level, text| engine.log_app(level, text))
    })
    .await?
}

#[tauri::command]
pub async fn cisco_logout(st: St<'_>) -> R<()> {
    st.engine.log_app("INFO", "Выхожу из Cisco Secure Client");
    blocking(cisco::logout).await?
}

/// Cisco's own window: logins with a browser (SAML) or a certificate check.
#[tauri::command]
pub fn cisco_open() -> R<()> {
    cisco::open_ui()
}
