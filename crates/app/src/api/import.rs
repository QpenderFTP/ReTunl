//! Adding servers from a link, the clipboard or a file.

use std::sync::Arc;

use retunl_core::subscription::{self, ImportResult};
use retunl_core::{bundle, wgconf};
use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

use super::{subscriptions, St, R};
use crate::files;
use crate::state::{add_profiles, AppState};
use crate::util::blocking;

#[derive(Serialize, Default)]
pub struct ImportErr {
    pub(super) what: String,
    pub(super) error: String,
}

#[derive(Serialize, Default)]
pub struct ImportSummary {
    pub(super) added: Vec<String>,
    pub(super) names: Vec<String>,
    pub(super) duplicates: usize,
    pub(super) errors: Vec<ImportErr>,
    pub(super) warnings: Vec<String>,
    pub(super) subscriptions: Vec<String>,
    /// The text is an encrypted ReTunl export: the UI asks for its password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) bundle: Option<String>,
    /// AmneziaVPN full-access keys: these servers went to «Мои серверы».
    pub(super) admin: Vec<crate::admin::ServerView>,
}

fn apply_import(st: &Arc<AppState>, res: ImportResult) -> R<ImportSummary> {
    let mut sum = ImportSummary {
        errors: res.errors.into_iter().map(|(what, error)| ImportErr { what, error }).collect(),
        warnings: res.warnings,
        ..Default::default()
    };
    let names: Vec<String> = res.profiles.iter().map(|p| p.name.clone()).collect();
    let links = res.links;
    let profiles = res.profiles;
    let ws = res.wiresock;
    let (added, dups) = st.mutate(|d| {
        let (added, dups) = add_profiles(d, profiles, None, &links);
        // a WireSock file: its server goes through WireSock
        if let (Some(ws), [id]) = (ws, added.as_slice()) {
            if let Some(p) = d.profile_mut(id) {
                p.wiresock = Some(ws);
            }
        }
        Ok((added, dups))
    })?;
    sum.names = names;
    sum.added = added;
    sum.duplicates = dups;
    Ok(sum)
}

async fn import_any(st: &Arc<AppState>, text: &str) -> R<ImportSummary> {
    if bundle::looks_like(text) {
        return Ok(ImportSummary { bundle: Some(text.trim().to_string()), ..Default::default() });
    }
    // full-access keys carry a server login, not a connection
    let mut admin = Vec::new();
    let mut rest = text.to_string();
    for token in text.split_whitespace() {
        if let Some(a) = retunl_core::links::admin_access(token) {
            admin.push(st.admin.add_access(a).await?);
            rest = rest.replace(token, "");
        }
    }
    if !admin.is_empty() {
        let mut sum = if rest.trim().is_empty() { ImportSummary::default() } else { Box::pin(import_any(st, &rest)).await.unwrap_or_default() };
        sum.admin = admin;
        return Ok(sum);
    }
    let res = subscription::parse_text(text);
    if res.profiles.is_empty() && !res.urls.is_empty() {
        let mut sum = ImportSummary::default();
        for url in res.urls.clone() {
            match subscriptions::add(st, url.clone(), None).await {
                Ok(s) => {
                    sum.added.extend(s.added);
                    sum.names.extend(s.names);
                    sum.subscriptions.extend(s.subscriptions);
                    sum.errors.extend(s.errors);
                }
                Err(e) => sum.errors.push(ImportErr { what: url, error: e }),
            }
        }
        return Ok(sum);
    }
    if res.profiles.is_empty() && res.errors.is_empty() {
        return Err("Не нашёл ни одной ссылки на сервер. Поддерживаются vless://, vmess://, trojan://, ss://, hy2://, hysteria://, tuic://, wireguard://, socks://, anytls://, ключи AmneziaVPN vpn://, ссылки на подписку, файлы WireGuard и AmneziaWG, экспорт ReTunl.".into());
    }
    let sum = apply_import(st, res)?;
    st.request_reload();
    Ok(sum)
}

#[tauri::command]
pub async fn import_text(st: St<'_>, text: String) -> R<ImportSummary> {
    import_any(st.inner(), &text).await
}

#[tauri::command]
pub async fn import_clipboard(app: AppHandle, st: St<'_>) -> R<ImportSummary> {
    let text = app.clipboard().read_text().ok().filter(|t| !t.trim().is_empty()).ok_or("В буфере обмена нет текста.")?;
    import_any(st.inner(), &text).await
}

#[tauri::command]
pub async fn import_file(app: AppHandle, st: St<'_>) -> R<Option<ImportSummary>> {
    let a = app.clone();
    let picked = blocking(move || {
        let d = a.dialog().file().set_title("Файл конфигурации");
        // Android filters by file type, and .conf has none: show everything there
        let d = if cfg!(target_os = "android") {
            d
        } else {
            d.add_filter("Конфигурации и экспорт ReTunl", &["conf", "txt", "json", bundle::EXTENSION]).add_filter("Все файлы", &["*"])
        };
        d.blocking_pick_file()
    })
    .await?;
    let Some(picked) = picked else { return Ok(None) };
    let bytes = files::read(&app, &picked)?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    if wgconf::looks_like_wg_conf(&text) {
        let stem = files::stem(&picked);
        return match wgconf::parse(&text, &stem) {
            Ok(w) => {
                let res = ImportResult {
                    profiles: vec![w.profile],
                    links: vec![None],
                    warnings: w.warnings,
                    wiresock: w.wiresock,
                    ..Default::default()
                };
                let sum = apply_import(st.inner(), res)?;
                st.request_reload();
                Ok(Some(sum))
            }
            Err(e) => Err(e.to_string()),
        };
    }
    import_any(st.inner(), &text).await.map(Some)
}
