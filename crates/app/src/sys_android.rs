//! Android: the same functions as sys.rs, but sing-box is not a separate
//! program. It runs inside the app (libbox) through the VPN plugin
//! (crates/vpn-android), and a [`Proc`] stands in for its process.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri_plugin_retunl_vpn as vpn;

/// The VPN never needs an app restart: Android asks for permission itself.
pub const TUN_NEEDS_RESTART: bool = false;

pub const STOP_GRACE_MS: u64 = 5000;

/// The id of the main connection on the Kotlin side.
pub const MAIN: &str = "main";

pub struct Stop;

/// How an instance ended.
#[derive(Clone, Debug)]
pub struct Exit {
    /// Why, when it was not asked to stop.
    pub error: Option<String>,
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.error.as_deref().unwrap_or("остановлен"))
    }
}

/// A running sing-box instance, used like a child process.
pub struct Proc {
    id: String,
    pub stdout: Option<io::Empty>,
    pub stderr: Option<io::Empty>,
    done: Option<Exit>,
}

impl Proc {
    pub fn new(id: impl Into<String>) -> Proc {
        Proc { id: id.into(), stdout: None, stderr: None, done: None }
    }

    pub fn id(&self) -> u32 {
        0
    }

    pub fn try_wait(&mut self) -> io::Result<Option<Exit>> {
        if let Some(d) = &self.done {
            return Ok(Some(d.clone()));
        }
        let st = vpn::status(&self.id).map_err(io::Error::other)?;
        if st.ended() {
            let e = Exit { error: st.error.filter(|_| st.state == "failed") };
            self.done = Some(e.clone());
            return Ok(Some(e));
        }
        Ok(None)
    }

    pub fn kill(&mut self) -> io::Result<()> {
        vpn::stop(&self.id).map_err(io::Error::other)
    }

    pub fn wait(&mut self) -> io::Result<Exit> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(e) = self.try_wait()? {
                return Ok(e);
            }
            if Instant::now() > until {
                return Ok(Exit { error: None });
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Stopped on request (the notification's «Отключить» counts): not a failure.
pub fn clean_exit(e: &Exit) -> bool {
    e.error.is_none()
}

pub fn exit_error(e: &Exit) -> Option<String> {
    e.error.clone()
}

pub struct Launch {
    pub child: Proc,
    pub log: Option<PathBuf>,
    pub slow_start: bool,
    pub stop: Stop,
}

/// sing-box writes its log to a file the engine reads as it grows.
fn with_log_file(cfg: &Path, log: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(cfg).map_err(|e| format!("Не удалось прочитать конфигурацию: {e}"))?;
    let mut v: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    v["log"]["output"] = serde_json::Value::from(log.to_string_lossy().into_owned());
    Ok(v.to_string())
}

/// The main connection, in the VPN service. The first time Android asks the
/// user to allow the VPN, and this waits for the answer.
pub fn launch_core(_core: &Path, cfg: &Path, run_dir: &Path, _tun: bool) -> Result<Launch, String> {
    let log = run_dir.join("core.log");
    let _ = std::fs::write(&log, b"");
    let config = with_log_file(cfg, &log)?;
    vpn::start(MAIN, &config, true)?;
    Ok(Launch { child: Proc::new(MAIN), log: Some(log), slow_start: false, stop: Stop })
}

/// A test instance (latency, speed): no tunnel, its sockets skip the VPN.
pub fn start_test(cfg: &Path) -> Result<Proc, String> {
    let config = std::fs::read_to_string(cfg).map_err(|e| e.to_string())?;
    let id = format!("test-{}", uuid::Uuid::new_v4().simple());
    vpn::start(&id, &config, false)?;
    Ok(Proc::new(id))
}

/// Is the main connection still up (the window was closed, the VPN was not)?
pub fn main_running() -> bool {
    vpn::status(MAIN).is_ok_and(|s| s.state == "running")
}

pub fn check_config(cfg: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(cfg).map_err(|e| e.to_string())?;
    vpn::check(&text)
}

pub fn request_stop(_stop: &Stop, _pid: u32) -> bool {
    vpn::stop(MAIN).is_ok()
}

pub fn force_stop(_stop: &Stop, child: &mut Proc) {
    let _ = child.kill();
}

/// Apps are shown by package name in sing-box's connection list.
pub fn program_name(path: &str) -> String {
    path.to_string()
}

pub fn is_elevated() -> bool {
    false
}

pub fn relaunch_elevated(_args: &str) -> Result<(), String> {
    Err("На Android права администратора не нужны.".into())
}

pub struct Job;

impl Job {
    pub fn new() -> Option<Job> {
        None
    }
    pub fn assign(&self, _child: &Proc) {}
}

pub fn install_ctrl_guard() {}

/// Android has no system proxy for ReTunl to leave behind.
pub fn clear_system_proxy_if(_port: u16) -> bool {
    false
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Autostart {
    pub enabled: bool,
    pub elevated: bool,
}

pub fn autostart_status() -> Autostart {
    Autostart::default()
}

pub fn set_autostart(_enable: bool) -> Result<Autostart, String> {
    Err("На Android ReTunl не запускается сам при включении телефона.".into())
}

/// An installed app (the "programs" of rules).
#[derive(Serialize, Clone, Debug)]
pub struct ProcInfo {
    /// What people call it: «Telegram»
    pub name: String,
    /// The package: org.telegram.messenger
    pub path: String,
    pub system: bool,
}

pub fn processes() -> Vec<ProcInfo> {
    let mut list: Vec<ProcInfo> = vpn::apps()
        .unwrap_or_default()
        .into_iter()
        .map(|a| ProcInfo { name: a.label, path: a.package, system: a.system })
        .collect();
    list.sort_by_key(|p| (p.system, p.name.to_lowercase()));
    list
}

#[derive(Serialize, Clone, Debug)]
pub struct Adapter {
    pub name: String,
    pub description: String,
    pub up: bool,
    pub addresses: Vec<String>,
    pub tunnel: bool,
}

/// sing-box follows the phone's network by itself.
pub fn adapters() -> Vec<Adapter> {
    Vec::new()
}

/// Web links open in the browser; folders cannot be shown.
pub fn open_in_explorer(path: &str) {
    if path.starts_with("https://") || path.starts_with("http://") {
        let _ = vpn::open_url(path);
    }
}
