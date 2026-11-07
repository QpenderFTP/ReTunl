//! The «Мои серверы» commands the UI calls.

use std::sync::Arc;

use retunl_core::links::{parse_link, ParsedLink};
use retunl_core::wgconf;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::DialogExt;

use super::{install, AddForm, ClientKey, Kind, Plan, ServerView};
use crate::state::{add_profiles, AppState};

type St<'a> = State<'a, Arc<AppState>>;
type R<T> = Result<T, String>;

#[derive(Serialize)]
pub struct WithKey {
    server: ServerView,
    key: Option<ClientKey>,
}

#[tauri::command]
pub fn admin_servers(st: St<'_>) -> Vec<ServerView> {
    st.admin.list()
}

#[tauri::command]
pub async fn admin_add(st: St<'_>, form: AddForm) -> R<ServerView> {
    st.admin.add(form).await
}

#[tauri::command]
pub async fn admin_scan(st: St<'_>, id: String) -> R<ServerView> {
    st.admin.scan(&id).await
}

#[tauri::command]
pub async fn admin_client_add(st: St<'_>, id: String, container: String, name: String) -> R<WithKey> {
    let (server, key) = st.admin.client_add(&id, &container, &name).await?;
    Ok(WithKey { server, key: Some(key) })
}

#[tauri::command]
pub async fn admin_client_remove(st: St<'_>, id: String, container: String, client: String) -> R<ServerView> {
    st.admin.client_remove(&id, &container, &client).await
}

#[tauri::command]
pub async fn admin_client_rename(st: St<'_>, id: String, container: String, client: String, name: String) -> R<ServerView> {
    st.admin.client_rename(&id, &container, &client, &name).await
}

#[tauri::command]
pub async fn admin_client_key(st: St<'_>, id: String, container: String, client: String) -> R<ClientKey> {
    st.admin.client_key(&id, &container, &client).await
}

#[tauri::command]
pub async fn admin_install(app: AppHandle, st: St<'_>, id: String, kind: Kind, port: u16, site: Option<String>, client: Option<String>) -> R<WithKey> {
    if port == 0 {
        return Err("Укажите порт".into());
    }
    install::container_of(kind)?;
    let plan = Plan { kind, port, site: site.unwrap_or_default() };
    let progress = move |p: super::Progress| {
        let _ = app.emit("admin-progress", &p);
    };
    let (server, key) = st.admin.install(&id, plan, client.filter(|c| !c.trim().is_empty()), &progress).await?;
    Ok(WithKey { server, key })
}

#[tauri::command]
pub async fn admin_remove_protocol(st: St<'_>, id: String, container: String) -> R<ServerView> {
    st.admin.remove_protocol(&id, &container).await
}

#[tauri::command]
pub async fn admin_start_protocol(st: St<'_>, id: String, container: String) -> R<ServerView> {
    st.admin.start_protocol(&id, &container).await
}

#[tauri::command]
pub fn admin_rename(st: St<'_>, id: String, name: String) -> R<()> {
    st.admin.rename(&id, &name)
}

#[tauri::command]
pub fn admin_forget(st: St<'_>, id: String) -> R<()> {
    st.admin.forget(&id)
}

#[tauri::command]
pub fn admin_trust_key(st: St<'_>, id: String) -> R<()> {
    st.admin.trust_new_key(&id)
}

#[tauri::command]
pub async fn admin_pick_key(app: AppHandle) -> R<Option<String>> {
    let picked = tokio::task::spawn_blocking(move || {
        let mut d = app.dialog().file().set_title("SSH-ключ");
        if let Some(home) = dirs::home_dir() {
            d = d.set_directory(home.join(".ssh"));
        }
        d.blocking_pick_file()
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(picked.and_then(|p| p.into_path().ok()).map(|p| p.to_string_lossy().into_owned()))
}

/// Add a client made on the server to this computer's servers.
#[tauri::command]
pub fn admin_use_client(st: St<'_>, text: String, name: String) -> R<String> {
    let item = if wgconf::looks_like_wg_conf(&text) {
        let p = wgconf::parse(&text, &name).map_err(|e| e.to_string())?.profile;
        ParsedLink { name: p.name, outbound: p.outbound }
    } else {
        let mut l = parse_link(text.trim()).map_err(|e| e.to_string())?;
        l.name = name.clone();
        l
    };
    let link = (!wgconf::looks_like_wg_conf(&text)).then(|| text.trim().to_string());
    let (added, _) = st.mutate(|d| Ok(add_profiles(d, vec![item.clone()], None, &[link])))?;
    let id = match added.first() {
        Some(id) => id.clone(),
        None => st.snapshot().profiles.iter().find(|p| p.outbound == item.outbound).map(|p| p.id.clone()).ok_or("Сервер не добавился")?,
    };
    st.request_reload();
    Ok(id)
}

#[tauri::command]
pub async fn admin_save_conf(app: AppHandle, name: String, text: String) -> R<Option<String>> {
    let picked = tokio::task::spawn_blocking(move || {
        app.dialog().file().set_title("Сохранить настройки клиента").set_file_name(&name).add_filter("WireGuard", &["conf"]).blocking_save_file()
    })
    .await
    .map_err(|e| e.to_string())?;
    let Some(path) = picked.and_then(|p| p.into_path().ok()) else { return Ok(None) };
    std::fs::write(&path, text).map_err(|e| format!("Не удалось сохранить файл: {e}"))?;
    Ok(Some(path.to_string_lossy().into_owned()))
}
