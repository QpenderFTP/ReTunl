//! ReTunl: the window, the commands it calls and the sing-box it runs.
//! Desktop starts here from main.rs; Android loads this library itself.

mod admin;
mod api;
mod blocks;
mod clash;
mod engine;
mod fetch;
mod files;
#[cfg_attr(target_os = "macos", path = "icons_mac.rs")]
#[cfg_attr(target_os = "android", path = "icons_android.rs")]
mod icons;
mod paths;
mod probe;
mod speed;
mod state;
mod store;
// Windows in sys.rs, macOS in sys_mac.rs, Android in sys_android.rs: the same functions
#[cfg_attr(target_os = "macos", path = "sys_mac.rs")]
#[cfg_attr(target_os = "android", path = "sys_android.rs")]
mod sys;
#[cfg(desktop)]
mod tray;

use std::sync::Arc;
use std::time::Duration;

use retunl_core::util::now_unix;
use tauri::{Emitter, Manager};

use crate::state::AppState;

#[cfg(desktop)]
fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// Run by the installer and uninstaller: undo what a closed or removed ReTunl
/// may have left in the system, then exit without opening a window.
#[cfg(desktop)]
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    #[cfg(desktop)]
    {
        // --cleanup: the uninstaller; --clear-proxy: the installer after closing a running copy
        if args.iter().any(|a| a == "--cleanup" || a == "--clear-proxy") {
            cleanup(args.iter().any(|a| a == "--cleanup"));
            return;
        }
        // relaunched as admin: let the old instance exit first (single instance lock)
        if let Some(pid) = arg_value(&args, "--wait-pid").and_then(|p| p.parse().ok()) {
            sys::wait_for_pid(pid, 8000);
        }
    }
    let autostart = args.iter().any(|a| a == "--autostart");
    let connect_now = args.iter().any(|a| a == "--connect");

    sys::install_ctrl_guard();

    let builder = tauri::Builder::default();
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| tray::show_main(app)));
    #[cfg(target_os = "android")]
    let builder = builder
        .plugin(tauri_plugin_retunl_vpn::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_barcode_scanner::init());

    let app = builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(move |app| {
            let handle = app.handle().clone();
            let paths = paths::Paths::for_app(&handle);
            let (data, warning) = store::load(&paths.data_file());
            let hidden = autostart && data.settings.start_minimized;
            let auto_connect = connect_now || data.settings.connect_on_launch;
            let state = Arc::new(AppState::new(paths, data, warning, hidden));
            app.manage(state.clone());
            let _ = state.handle.set(handle.clone());

            #[cfg(desktop)]
            {
                let tray = tray::build(&handle)?;
                *state.tray.lock().unwrap_or_else(|e| e.into_inner()) = Some(tray);
            }

            let h = handle.clone();
            state.engine.set_listener(Box::new(move |st| {
                let _ = h.emit("status", &st);
                #[cfg(desktop)]
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

            // Android: the VPN may still run from before the window was closed
            #[cfg(target_os = "android")]
            state.engine.adopt_running(&state.paths);

            if auto_connect {
                let s = state.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    if !s.engine.is_active() {
                        let _ = s.connect().await;
                    }
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
                    let r = api::update_subscription_for(&s, &id).await;
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
        .on_window_event(|_window, _event| {
            #[cfg(desktop)]
            if let tauri::WindowEvent::CloseRequested { api, .. } = _event {
                let state = _window.state::<Arc<AppState>>();
                if state.snapshot().settings.close_to_tray {
                    api.prevent_close();
                    let _ = _window.hide();
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
            api::set_system_bars,
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

    app.run(|_app, _event| {
        // Android: leaving the app (Back, swiping it away) ends the window, not
        // the VPN; the service keeps the connection and the notification stops it
        #[cfg(desktop)]
        if let tauri::RunEvent::Exit = _event {
            if let Some(state) = _app.try_state::<Arc<AppState>>() {
                state.engine.shutdown_blocking();
            }
        }
    });
}
