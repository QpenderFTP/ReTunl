//! The «Мои серверы» commands the UI calls.

use std::sync::Arc;

use retunl_core::links::{parse_link, ParsedLink};
use retunl_core::wgconf;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::DialogExt;

use super::{install, AddForm, ClientKey, Kind, Plan, ServerView};
use crate::state::{add_profiles, AppState};
use crate::util::blocking;

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
    let copy = form.key_path.clone().filter(|p| is_key_copy(&st, p));
    let r = st.admin.add(form).await;
    // the key is stored sealed now: the plain copy from the picker goes
    if let Some(p) = copy {
        let _ = std::fs::remove_file(p);
    }
    r
}

/// Android hands picked files out as links: [`admin_pick_key`] copies the key here.
fn key_copy(st: &AppState) -> std::path::PathBuf {
    st.paths.run_dir().join("picked-ssh-key")
}

fn is_key_copy(st: &AppState, path: &str) -> bool {
    std::path::Path::new(path) == key_copy(st)
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
pub async fn admin_pick_key(app: AppHandle, st: St<'_>) -> R<Option<String>> {
    let a = app.clone();
    let picked = blocking(move || {
        let mut d = a.dialog().file().set_title("SSH-ключ");
        if let Some(home) = dirs::home_dir() {
            d = d.set_directory(home.join(".ssh"));
        }
        d.blocking_pick_file()
    })
    .await?;
    let Some(picked) = picked else { return Ok(None) };
    if let Ok(p) = picked.clone().into_path() {
        return Ok(Some(p.to_string_lossy().into_owned()));
    }
    // a content:// link: keep a private copy until the server is added
    let bytes = crate::files::read(&app, &picked)?;
    let copy = key_copy(&st);
    std::fs::write(&copy, bytes).map_err(|e| format!("Не удалось сохранить ключ: {e}"))?;
    Ok(Some(copy.to_string_lossy().into_owned()))
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
    let a = app.clone();
    let picked = blocking(move || {
        a.dialog().file().set_title("Сохранить настройки клиента").set_file_name(&name).add_filter("WireGuard", &["conf"]).blocking_save_file()
    })
    .await?;
    let Some(picked) = picked else { return Ok(None) };
    crate::files::write(&app, &picked, text.as_bytes())?;
    Ok(Some(crate::files::shown(&picked)))
}
