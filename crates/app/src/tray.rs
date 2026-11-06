use std::sync::Arc;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};

use crate::engine::{Phase, Status};
use crate::state::AppState;

const ICON_ON: &[u8] = include_bytes!("../icons/tray-on.png");
const ICON_OFF: &[u8] = include_bytes!("../icons/tray-off.png");

pub struct Tray {
    toggle: MenuItem<Wry>,
}

pub fn build(app: &AppHandle) -> tauri::Result<Tray> {
    let show = MenuItem::with_id(app, "show", "Открыть ReTunl", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Подключить", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &sep, &quit_item])?;
    TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(ICON_OFF)?)
        .tooltip("ReTunl — отключено")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main(app),
            "toggle" => toggle_connection(app),
            "quit" => quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(Tray { toggle })
}

pub fn update(app: &AppHandle, status: &Status) {
    let on = status.phase == Phase::Running;
    let tooltip = match status.phase {
        Phase::Running => match &status.profile {
            Some(p) => format!("ReTunl — подключено ({p})"),
            None => "ReTunl — подключено".to_string(),
        },
        Phase::Starting => "ReTunl — подключаюсь…".into(),
        Phase::Stopping => "ReTunl — отключаюсь…".into(),
        Phase::Failed => "ReTunl — ошибка подключения".into(),
        Phase::Stopped => "ReTunl — отключено".into(),
    };
    if let Some(tray) = app.tray_by_id("main") {
        if let Ok(img) = Image::from_bytes(if on { ICON_ON } else { ICON_OFF }) {
            let _ = tray.set_icon(Some(img));
        }
        let _ = tray.set_tooltip(Some(&tooltip));
    }
    let state = app.state::<Arc<AppState>>();
    let guard = state.tray.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = guard.as_ref() {
        let text = if matches!(status.phase, Phase::Running | Phase::Starting) { "Отключить" } else { "Подключить" };
        let _ = t.toggle.set_text(text);
    }
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn toggle_connection(app: &AppHandle) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if state.engine.is_active() {
            state.engine.stop().await;
        } else if let Err(e) = state.connect().await {
            if crate::api::is_need_admin(&e) {
                show_main(&app);
            }
        }
    });
}

fn quit(app: &AppHandle) {
    let state = app.state::<Arc<AppState>>().inner().clone();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        state.engine.stop().await;
        app.exit(0);
    });
}
