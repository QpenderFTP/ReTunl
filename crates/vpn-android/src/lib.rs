//! ReTunl on Android: sing-box (libbox from sing-box-lx) runs inside the app.
//! The main connection lives in a VpnService; latency and speed tests run
//! as separate instances without a tunnel. Each instance has an id.
//!
//! Only ReTunl's Rust code calls this: the functions block until the Kotlin
//! side answers, so call them off the async runtime (`spawn_blocking`).

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::plugin::{Builder, TauriPlugin};
use tauri::Runtime;

type Caller = Box<dyn Fn(&str, Value) -> Result<Value, String> + Send + Sync>;

static CALL: OnceLock<Caller> = OnceLock::new();

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("retunl-vpn")
        .setup(|_app, _api| {
            #[cfg(target_os = "android")]
            {
                let handle = _api.register_android_plugin("app.retunl.vpn", "VpnPlugin")?;
                let _ = CALL.set(Box::new(move |cmd, args| {
                    handle.run_mobile_plugin::<Value>(cmd, args).map_err(|e| match e {
                        tauri::plugin::mobile::PluginInvokeError::InvokeRejected(r) => {
                            r.message.unwrap_or_else(|| "ошибка Android".into())
                        }
                        other => other.to_string(),
                    })
                }));
            }
            Ok(())
        })
        .build()
}

fn call<T: DeserializeOwned>(cmd: &str, args: Value) -> Result<T, String> {
    let f = CALL.get().ok_or("VPN-модуль Android не загружен")?;
    let v = f(cmd, args)?;
    serde_json::from_value(v).map_err(|e| format!("ответ Android не разобран: {e}"))
}

/// One sing-box instance as the Kotlin side sees it.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BoxStatus {
    /// "none", "starting", "running", "stopped" or "failed"
    pub state: String,
    /// Why it stopped or failed.
    pub error: Option<String>,
}

impl BoxStatus {
    pub fn ended(&self) -> bool {
        matches!(self.state.as_str(), "none" | "stopped" | "failed")
    }
}

/// An installed app.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AppInfo {
    pub package: String,
    pub label: String,
    /// Part of Android or the phone maker's software.
    pub system: bool,
}

/// Start an instance with this sing-box config (JSON text). `vpn`: the main
/// connection, with the Android VPN permission prompt the first time and a
/// notification while it runs. Returns once it is starting; watch [`status`].
pub fn start(id: &str, config: &str, vpn: bool) -> Result<(), String> {
    call::<Value>("start", json!({ "id": id, "config": config, "vpn": vpn })).map(|_| ())
}

pub fn stop(id: &str) -> Result<(), String> {
    call::<Value>("stop", json!({ "id": id })).map(|_| ())
}

pub fn status(id: &str) -> Result<BoxStatus, String> {
    call("status", json!({ "id": id }))
}

/// sing-box's own check of a config: the error text, if any.
pub fn check(config: &str) -> Result<(), String> {
    call::<Value>("check", json!({ "config": config })).map(|_| ())
}

/// Version of the built-in core.
pub fn version() -> Result<String, String> {
    #[derive(Deserialize)]
    struct V {
        version: String,
    }
    call::<V>("version", json!({})).map(|v| v.version)
}

pub fn apps() -> Result<Vec<AppInfo>, String> {
    #[derive(Deserialize)]
    struct L {
        apps: Vec<AppInfo>,
    }
    call::<L>("apps", json!({})).map(|l| l.apps)
}

/// App icons as `data:image/png;base64,…` (missing → none).
pub fn icons(packages: &[String]) -> Result<HashMap<String, Option<String>>, String> {
    #[derive(Deserialize)]
    struct I {
        icons: HashMap<String, Option<String>>,
    }
    call::<I>("icons", json!({ "packages": packages })).map(|i| i.icons)
}

/// Bar icons for the theme: light icons when `dark`.
pub fn system_bars(dark: bool) -> Result<(), String> {
    call::<Value>("bars", json!({ "dark": dark })).map(|_| ())
}

/// Open a web link in the phone's browser.
pub fn open_url(url: &str) -> Result<(), String> {
    call::<Value>("openUrl", json!({ "url": url })).map(|_| ())
}

pub fn allow_install_update() -> Result<(), String> {
    call::<Value>("allowInstallUpdate", json!({})).map(|_| ())
}

pub fn install_update(path: &str) -> Result<(), String> {
    call::<Value>("installUpdate", json!({ "path": path })).map(|_| ())
}
