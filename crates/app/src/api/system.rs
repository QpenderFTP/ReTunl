//! The system around the app: programs and their icons, file dialogs,
//! autostart, downloads, the window.

use std::collections::HashMap;

use retunl_core::awg::CoreKind;
use retunl_core::rulesets;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

use super::{St, R};
use crate::sys::{self, Autostart, ProcInfo};
use crate::util::{blocking, locked};
use crate::{fetch, icons};

#[tauri::command]
pub async fn list_processes() -> R<Vec<ProcInfo>> {
    blocking(sys::processes).await
}

/// Icons for exe paths as data URLs (cached; missing → null).
#[tauri::command]
pub async fn get_icons(st: St<'_>, paths: Vec<String>) -> R<HashMap<String, Option<String>>> {
    let todo: Vec<String> = {
        let cache = locked(&st.icons);
        paths.iter().filter(|p| !cache.contains_key(*p)).cloned().collect()
    };
    if !todo.is_empty() {
        let found = blocking(move || {
            #[cfg(target_os = "android")]
            return icons::icons(&todo).into_iter().collect::<Vec<_>>();
            #[cfg(not(target_os = "android"))]
            todo.into_iter().map(|p| {
                let icon = icons::exe_icon_data_url(&p);
                (p, icon)
            }).collect::<Vec<_>>()
        })
        .await?;
        locked(&st.icons).extend(found);
    }
    let cache = locked(&st.icons);
    Ok(paths.into_iter().map(|p| {
        let v = cache.get(&p).cloned().flatten();
        (p, v)
    }).collect())
}

#[tauri::command]
pub async fn pick_exe(app: AppHandle) -> R<Option<String>> {
    if cfg!(target_os = "android") {
        return Err("На Android приложение выбирается из списка".into());
    }
    let picked = blocking(move || {
        let ext: &[&str] = if cfg!(windows) { &["exe"] } else { &["app"] };
        app.dialog().file().set_title("Выберите программу").add_filter("Программы", ext).blocking_pick_file()
    })
    .await?;
    Ok(picked.and_then(|p| p.into_path().ok()).map(|p| p.display().to_string()))
}

#[tauri::command]
pub async fn pick_folder(app: AppHandle) -> R<Option<String>> {
    #[cfg(target_os = "android")]
    {
        let _ = app;
        Err("На Android папки программ не выбираются".into())
    }
    #[cfg(not(target_os = "android"))]
    {
    let picked = blocking(move || {
        app.dialog().file().set_title("Папка: все программы внутри неё").blocking_pick_folder()
    })
    .await?;
    Ok(picked.and_then(|p| p.into_path().ok()).map(|p| {
        let s = p.display().to_string();
        let sep = std::path::MAIN_SEPARATOR;
        if s.ends_with(sep) { s } else { format!("{s}{sep}") }
    }))
    }
}

#[tauri::command]
pub fn copy_text(app: AppHandle, text: String) -> R<()> {
    app.clipboard().write_text(text).map_err(|e| format!("Буфер обмена недоступен: {e}"))
}

#[tauri::command]
pub async fn relaunch_admin(app: AppHandle, st: St<'_>, connect: bool) -> R<()> {
    let args = format!("--wait-pid {}{}", std::process::id(), if connect { " --connect" } else { "" });
    sys::relaunch_elevated(&args)?;
    st.engine.stop().await;
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub fn set_autostart(st: St<'_>, enabled: bool) -> R<Autostart> {
    sys::set_autostart(enabled, st.snapshot().settings.run_as_admin)
}

#[tauri::command]
pub async fn download_core(app: AppHandle, st: St<'_>, kind: Option<CoreKind>) -> R<String> {
    if cfg!(target_os = "android") {
        return Err("На Android ядро встроено в приложение и обновляется вместе с ним.".into());
    }
    let kind = kind.unwrap_or_default();
    let dir = match kind {
        CoreKind::Official => st.paths.core_dir(),
        CoreKind::Extended => st.paths.lx_core_dir(),
    };
    // the running core's files are locked by Windows
    if st.engine.is_active() && st.engine.status().core.unwrap_or_default() == kind {
        return Err("Сначала отключитесь — это ядро сейчас используется.".into());
    }
    let h = app.clone();
    let path = fetch::download_core(&st.http, kind, &dir, move |done, total| {
        let _ = h.emit("core-progress", serde_json::json!({"done": done, "total": total, "kind": kind}));
    })
    .await?;
    Ok(path.display().to_string())
}

/// All geosite/geoip tags, for hints in the rule editor.
#[tauri::command]
pub async fn geo_tags(st: St<'_>) -> R<Vec<String>> {
    fetch::geo_tags(&st.http, &st.paths.ruleset_dir().join("tags.json")).await
}

/// Re-download every list the current rules use.
#[tauri::command]
pub async fn update_rule_sets(st: St<'_>) -> R<usize> {
    let data = st.snapshot();
    let mut seen = std::collections::BTreeMap::new();
    for r in &data.rules {
        for rs in &r.rule_sets {
            if let Ok(src) = rulesets::resolve(rs) {
                seen.insert(src.tag.clone(), src);
            }
        }
    }
    let sources: Vec<_> = seen.into_values().collect();
    fetch::ensure_rule_sets(&st.http, &sources, &st.paths.ruleset_dir(), true).await?;
    Ok(sources.len())
}

#[tauri::command]
pub fn open_data_dir(st: St<'_>) {
    sys::open_in_explorer(&st.paths.data_dir.display().to_string());
}

#[tauri::command]
pub fn open_url(url: String) -> R<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Можно открыть только веб-ссылку".into());
    }
    sys::open_in_explorer(&url);
    Ok(())
}

/// Android: status and navigation bar icons dark on a light theme, light on a dark one.
#[tauri::command(async)]
pub fn set_system_bars(dark: bool) -> R<()> {
    #[cfg(target_os = "android")]
    return tauri_plugin_retunl_vpn::system_bars(dark);
    #[cfg(not(target_os = "android"))]
    {
        let _ = dark;
        Ok(())
    }
}

/// The page has loaded: show the window unless we started hidden in the tray.
#[tauri::command]
pub fn app_ready(app: AppHandle, st: St<'_>) -> Option<String> {
    if !st.hidden_launch {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.set_focus();
        }
    }
    locked(&st.update_on_ready).take()
}

#[tauri::command]
pub async fn quit_app(app: AppHandle, st: St<'_>) -> R<()> {
    st.engine.stop().await;
    app.exit(0);
    Ok(())
}
