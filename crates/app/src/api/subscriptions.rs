//! Subscriptions: lists of servers kept up to date from an address.

use std::sync::Arc;

use retunl_core::subscription;
use retunl_core::util::{new_id, now_unix};
use retunl_core::Subscription;

use super::import::{ImportErr, ImportSummary};
use super::{St, R};
use crate::fetch;
use crate::state::{forget_profiles, merge_subscription, AppState};

const SUB_USER_AGENT: &str = "v2rayN/7.10 ReTunl/0.1";

fn host_of(url: &str) -> String {
    url.split("://").nth(1).and_then(|r| r.split(['/', '?', '#']).next()).unwrap_or(url).to_string()
}

pub(super) async fn add(st: &Arc<AppState>, url: String, name: Option<String>) -> R<ImportSummary> {
    let url = url.trim().to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("Адрес подписки должен начинаться с https://".into());
    }
    if let Some(existing) = st.snapshot().subscriptions.iter().find(|s| s.url == url) {
        return update(st, &existing.id).await;
    }
    let resp = fetch::subscription(&st.http, &url, SUB_USER_AGENT).await.map_err(|e| format!("Подписка: {e}"))?;
    let parsed = subscription::parse_text(&resp.body);
    if parsed.profiles.is_empty() {
        let why = parsed.errors.first().map(|(_, e)| format!(" ({e})")).unwrap_or_default();
        return Err(format!("В подписке не нашлось серверов, которые понимает sing-box{why}."));
    }
    let id = new_id();
    let sub_name = name.filter(|n| !n.trim().is_empty()).or(resp.title).unwrap_or_else(|| host_of(&url));
    let names: Vec<String> = parsed.profiles.iter().map(|p| p.name.clone()).collect();
    let errors = parsed.errors.iter().map(|(w, e)| ImportErr { what: w.clone(), error: e.clone() }).collect();
    let profiles = parsed.profiles;
    let sid = id.clone();
    st.mutate(move |d| {
        d.subscriptions.push(Subscription {
            id: sid.clone(),
            name: sub_name,
            url,
            updated_at: Some(now_unix()),
            info: resp.info,
            last_error: None,
        });
        merge_subscription(d, &sid, profiles);
        if d.active_profile().is_none() {
            d.settings.active_profile = d.profiles.iter().find(|p| p.subscription.as_deref() == Some(&sid)).map(|p| p.id.clone());
        }
        Ok(())
    })?;
    st.request_reload();
    Ok(ImportSummary { names, errors, subscriptions: vec![id], ..Default::default() })
}

async fn update(st: &Arc<AppState>, id: &str) -> R<ImportSummary> {
    let sub = st.snapshot().subscriptions.into_iter().find(|s| s.id == id).ok_or("Подписка не найдена")?;
    let result = fetch::subscription(&st.http, &sub.url, SUB_USER_AGENT).await;
    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("Подписка «{}»: {e}", sub.name);
            let _ = st.mutate(|d| {
                if let Some(s) = d.subscriptions.iter_mut().find(|s| s.id == sub.id) {
                    s.last_error = Some(e.clone());
                }
                Ok(())
            });
            return Err(msg);
        }
    };
    let parsed = subscription::parse_text(&resp.body);
    if parsed.profiles.is_empty() {
        return Err(format!("Подписка «{}» вернула пустой список — старые серверы оставлены.", sub.name));
    }
    let names: Vec<String> = parsed.profiles.iter().map(|p| p.name.clone()).collect();
    let errors = parsed.errors.iter().map(|(w, e)| ImportErr { what: w.clone(), error: e.clone() }).collect();
    let profiles = parsed.profiles;
    let active_before = st.snapshot().settings.active_profile;
    st.mutate(|d| {
        merge_subscription(d, &sub.id, profiles);
        if let Some(s) = d.subscriptions.iter_mut().find(|s| s.id == sub.id) {
            s.updated_at = Some(now_unix());
            s.last_error = None;
            if resp.info.is_some() {
                s.info = resp.info;
            }
        }
        Ok(())
    })?;
    if st.snapshot().settings.active_profile != active_before || st.engine.is_active() {
        st.request_reload();
    }
    Ok(ImportSummary { names, errors, subscriptions: vec![sub.id], ..Default::default() })
}

pub async fn update_for(st: &Arc<AppState>, id: &str) -> R<()> {
    update(st, id).await.map(|_| ())
}

#[tauri::command]
pub async fn add_subscription(st: St<'_>, url: String, name: Option<String>) -> R<ImportSummary> {
    add(st.inner(), url, name).await
}

#[tauri::command]
pub async fn update_subscription(st: St<'_>, id: String) -> R<ImportSummary> {
    update(st.inner(), &id).await
}

#[tauri::command]
pub async fn update_all_subscriptions(st: St<'_>) -> R<Vec<String>> {
    let mut errors = Vec::new();
    for s in st.snapshot().subscriptions {
        if let Err(e) = update(st.inner(), &s.id).await {
            errors.push(e);
        }
    }
    Ok(errors)
}

#[tauri::command]
pub fn rename_subscription(st: St<'_>, id: String, name: String) -> R<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Название не может быть пустым".into());
    }
    st.mutate(|d| {
        let s = d.subscriptions.iter_mut().find(|s| s.id == id).ok_or("Подписка не найдена")?;
        s.name = name;
        Ok(())
    })
}

#[tauri::command]
pub fn delete_subscription(st: St<'_>, id: String) -> R<()> {
    st.mutate(|d| {
        let removed: Vec<String> = d.profiles.iter().filter(|p| p.subscription.as_deref() == Some(&id)).map(|p| p.id.clone()).collect();
        d.profiles.retain(|p| p.subscription.as_deref() != Some(&id));
        d.subscriptions.retain(|s| s.id != id);
        forget_profiles(d, &removed, None);
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}
