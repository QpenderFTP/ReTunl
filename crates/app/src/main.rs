// No console window in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod admin;
mod api;
mod blocks;
mod clash;
mod engine;
mod fetch;
#[cfg_attr(target_os = "macos", path = "icons_mac.rs")]
mod icons;
mod paths;
mod probe;
mod speed;
mod state;
mod store;
// Windows in sys.rs, macOS in sys_mac.rs: the same functions
#[cfg_attr(target_os = "macos", path = "sys_mac.rs")]
mod sys;
mod tray;

use std::sync::Arc;
use std::time::Duration;

use retunl_core::util::now_unix;
use tauri::{Emitter, Manager, RunEvent, WindowEvent};

use crate::state::AppState;

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// Run by the installer and uninstaller: undo what a closed or removed ReTunl
/// may have left in the system, then exit without opening a window.
fn cleanup(remove_autostart: bool) {
    let paths = paths::Paths::locate();
    let port = std::fs::read_to_string(paths.data_file())
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v["settings"]["mixed_port"].as_u64())
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or_else(|| retunl_core::model::AppData::default().settings.mixed_port);
    sys::clear_system_proxy_if(port);
    if remove_autostart {
        let _ = sys::set_autostart(false);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // --cleanup: the uninstaller; --clear-proxy: the installer after closing a running copy
    if args.iter().any(|a| a == "--cleanup" || a == "--clear-proxy") {
        cleanup(args.iter().any(|a| a == "--cleanup"));
        return;
    }
    // relaunched as admin: let the old instance exit first (single instance lock)
    if let Some(pid) = arg_value(&args, "--wait-pid").and_then(|p| p.parse().ok()) {
        sys::wait_for_pid(pid, 8000);
    }
    let autostart = args.iter().any(|a| a == "--autostart");
    let connect_now = args.iter().any(|a| a == "--connect");

    sys::install_ctrl_guard();
    let paths = paths::Paths::new();
    let (data, warning) = store::load(&paths.data_file());
    let hidden = autostart && data.settings.start_minimized;
    let auto_connect = connect_now || data.settings.connect_on_launch;
    let state = Arc::new(AppState::new(paths, data, warning, hidden));

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| tray::show_main(app)))
        .plugin(tauri_plugin_dialog::init())
        .manage(state.clone())
        .setup(move |app| {
            let handle = app.handle().clone();
            let _ = state.handle.set(handle.clone());
            let tray = tray::build(&handle)?;
            *state.tray.lock().unwrap_or_else(|e| e.into_inner()) = Some(tray);

            let h = handle.clone();
            state.engine.set_listener(Box::new(move |st| {
                let _ = h.emit("status", &st);
                tray::update(&h, &st);
            }));

            // a crash last time may have left the Windows proxy pointing at us
            let port = state.snapshot().settings.mixed_port;
            if sys::clear_system_proxy_if(port) {
                state.engine.log_app("INFO", "Выключен системный прокси, оставшийся с прошлого запуска");
            }
            state.engine.log_app(
                "INFO",
                &format!(
                    "ReTunl {} запущен{}",
                    env!("CARGO_PKG_VERSION"),
                    if state.elevated { " с правами администратора" } else { "" }
                ),
            );

            if auto_connect {
                let s = state.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let _ = s.connect().await;
                });
            }

            // refresh subscriptions older than 12 hours
            let s = state.clone();
            tauri::async_runtime::spawn(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let stale: Vec<String> = s
                    .snapshot()
                    .subscriptions
                    .iter()
                    .filter(|sub| sub.updated_at.is_none_or(|t| now_unix() - t > 12 * 3600))
                    .map(|sub| sub.id.clone())
                    .collect();
                for id in stale {
                    let _ = s.handle.get().map(|h| h.emit("subscriptions-updating", &id));
                    let r = api_update_subscription(&s, &id).await;
                    if let Err(e) = r {
                        s.engine.log_app("WARN", &e);
                    }
                }
                if let Some(h) = s.handle.get() {
                    let _ = h.emit("data-changed", ());
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let state = window.state::<Arc<AppState>>();
                if state.snapshot().settings.close_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            api::get_state,
            api::get_catalog,
            api::import_text,
            api::import_clipboard,
            api::import_file,
            api::add_subscription,
            api::update_subscription,
            api::update_all_subscriptions,
            api::rename_subscription,
            api::delete_subscription,
            api::set_active,
            api::rename_profile,
            api::set_profile_json,
            api::delete_profiles,
            api::add_interface,
            api::list_adapters,
            api::test_latency,
            api::speed_test,
            api::save_rule,
            api::delete_rule,
            api::set_rule_enabled,
            api::reorder_rules,
            api::add_preset,
            api::save_preset,
            api::delete_preset,
            api::export_bundle,
            api::open_bundle,
            api::import_bundle,
            api::update_settings,
            api::preview_config,
            api::connect,
            api::disconnect,
            api::poll,
            api::close_connection,
            api::close_all_connections,
            api::get_logs,
            api::clear_logs,
            api::list_processes,
            api::get_icons,
            api::pick_exe,
            api::pick_folder,
            api::copy_text,
            api::relaunch_admin,
            api::set_autostart,
            api::download_core,
            api::update_rule_sets,
            api::geo_tags,
            api::open_data_dir,
            api::open_url,
            api::app_ready,
            api::quit_app,
            admin::commands::admin_servers,
            admin::commands::admin_add,
            admin::commands::admin_scan,
            admin::commands::admin_client_add,
            admin::commands::admin_client_remove,
            admin::commands::admin_client_rename,
            admin::commands::admin_client_key,
            admin::commands::admin_install,
            admin::commands::admin_remove_protocol,
            admin::commands::admin_start_protocol,
            admin::commands::admin_rename,
            admin::commands::admin_forget,
            admin::commands::admin_trust_key,
            admin::commands::admin_pick_key,
            admin::commands::admin_use_client,
            admin::commands::admin_save_conf,
        ])
        .build(tauri::generate_context!())
        .expect("failed to start ReTunl");

    app.run(|app, event| {
        if let RunEvent::Exit = event {
            app.state::<Arc<AppState>>().engine.shutdown_blocking();
        }
    });
}

async fn api_update_subscription(state: &Arc<AppState>, id: &str) -> Result<(), String> {
    // same path as the UI button, without a Tauri State wrapper
    api::update_subscription_for(state, id).await
}
