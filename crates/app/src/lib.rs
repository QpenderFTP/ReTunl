//! ReTunl: the window, the commands it calls and the sing-box it runs.
//! Desktop starts here from main.rs; Android loads this library itself.

mod admin;
mod api;
mod blocks;
mod cisco;
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
mod util;
mod wiresock;

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
        let _ = sys::set_autostart(false, false);
    }
}

/// Windows, a start without admin rights. True when this process should end:
/// a ReTunl that already runs took over, or the elevated copy has started.
#[cfg(windows)]
fn start_elevated(args: &[String], id: &str) -> bool {
    if sys::is_elevated() {
        return false;
    }
    if sys::show_running_instance(id) {
        return true;
    }
    // our own elevated start came out without the rights (UAC is off on a
    // standard account): go on as is instead of asking again and again
    if args.iter().any(|a| a == "--elevated-start") {
        return false;
    }
    let wanted = std::fs::read_to_string(paths::Paths::locate().data_file())
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v["settings"]["run_as_admin"].as_bool())
        .unwrap_or_else(|| retunl_core::model::AppData::default().settings.run_as_admin);
    if !wanted {
        return false;
    }
    let mut pass: Vec<&str> =
        args.iter().skip(1).map(String::as_str).filter(|a| matches!(*a, "--autostart" | "--connect")).collect();
    pass.push("--elevated-start");
    // declined in UAC: start without the rights, «Все программы» offers the restart again
    sys::relaunch_elevated(&pass.join(" ")).is_ok()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let context = tauri::generate_context!();
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
        #[cfg(windows)]
        if start_elevated(&args, &context.config().identifier) {
            return;
        }
    }
    let autostart = args.iter().any(|a| a == "--autostart");
    let connect_now = args.iter().any(|a| a == "--connect");
    #[cfg(windows)]
    let update = arg_value(&args, "--install-update").filter(|v| semver::Version::parse(v).is_ok());
    #[cfg(not(windows))]
    let update: Option<String> = None;

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
            let auto_connect = update.is_none() && (connect_now || data.settings.connect_on_launch);
            let state = Arc::new(AppState::new(paths, data, warning, hidden));
            *util::locked(&state.update_on_ready) = update;
            app.manage(state.clone());
            let _ = state.handle.set(handle.clone());

            #[cfg(desktop)]
            {
                let tray = tray::build(&handle)?;
                *util::locked(&state.tray) = Some(tray);
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

            #[cfg(windows)]
            if state.elevated {
                if !sys::allow_instance_messages(&handle.config().identifier) {
                    state.engine.log_app("WARN", "Ярлык не сможет открыть окно ReTunl, запущенного от администратора");
                }
                // autostart from before: move it to Task Scheduler, so the next logon is elevated without UAC
                if state.snapshot().settings.run_as_admin {
                    let s = state.clone();
                    std::thread::spawn(move || {
                        if sys::autostart_needs_admin() {
                            match sys::set_autostart(true, true) {
                                Ok(_) => s.engine.log_app("INFO", "Автозапуск теперь через планировщик заданий, с правами администратора"),
                                Err(e) => s.engine.log_app("WARN", &format!("Автозапуск с правами администратора не настроен: {e}")),
                            }
                        }
                    });
                }
            }

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
                    let r = api::subscriptions::update_for(&s, &id).await;
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
            api::view::get_state,
            api::view::get_catalog,
            api::import::import_text,
            api::import::import_clipboard,
            api::import::import_file,
            api::subscriptions::add_subscription,
            api::subscriptions::update_subscription,
            api::subscriptions::update_all_subscriptions,
            api::subscriptions::rename_subscription,
            api::subscriptions::delete_subscription,
            api::servers::set_active,
            api::servers::rename_profile,
            api::servers::set_wiresock,
            api::cisco::save_cisco,
            api::cisco::cisco_status,
            api::cisco::cisco_login,
            api::cisco::cisco_logout,
            api::cisco::cisco_open,
            api::servers::set_profile_json,
            api::servers::delete_profiles,
            api::servers::add_interface,
            api::servers::list_adapters,
            api::servers::test_latency,
            api::servers::speed_test,
            api::rules::save_rule,
            api::rules::delete_rule,
            api::rules::set_rule_enabled,
            api::rules::reorder_rules,
            api::rules::add_preset,
            api::rules::save_preset,
            api::rules::delete_preset,
            api::transfer::export_bundle,
            api::transfer::open_bundle,
            api::transfer::import_bundle,
            api::settings::update_settings,
            api::settings::preview_config,
            api::connection::connect,
            api::connection::disconnect,
            api::connection::poll,
            api::connection::close_connection,
            api::connection::close_all_connections,
            api::connection::get_logs,
            api::connection::clear_logs,
            api::system::list_processes,
            api::system::get_icons,
            api::system::pick_exe,
            api::system::pick_folder,
            api::system::copy_text,
            api::system::relaunch_admin,
            api::system::set_autostart,
            api::system::download_core,
            api::system::update_rule_sets,
            api::system::geo_tags,
            api::system::open_data_dir,
            api::system::open_url,
            api::system::set_system_bars,
            api::system::app_ready,
            api::system::quit_app,
            api::updates::check_update,
            api::updates::install_update,
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
        .build(context)
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
