//! Windows specifics: admin rights, stopping sing-box gracefully, the system
//! proxy, autostart, processes and network adapters.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use serde::Serialize;
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HANDLE};

use crate::util::locked;

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

pub fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// `Command` that never flashes a console window.
pub fn quiet(program: impl AsRef<OsStr>) -> Command {
    let mut c = Command::new(program);
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

/// TUN needs the whole app elevated: the UI offers a restart as admin.
pub const TUN_NEEDS_RESTART: bool = true;

// ---------- the main sing-box ----------

/// How long a graceful stop (Ctrl+Break) may take before sing-box is killed.
pub const STOP_GRACE_MS: u64 = 6000;

pub struct Stop;

/// sing-box as started for a connection.
/// The running core, as the engine holds it.
pub type Proc = std::process::Child;

pub struct Launch {
    pub child: std::process::Child,
    /// sing-box writes its log here instead of the pipes (macOS only)
    pub log: Option<std::path::PathBuf>,
    /// the start may wait for the user (macOS password prompt)
    pub slow_start: bool,
    pub stop: Stop,
}

pub fn launch_core(core: &Path, cfg: &Path, run_dir: &Path, _tun: bool) -> Result<Launch, String> {
    use std::process::Stdio;
    let child = Command::new(core)
        .args(["run", "--disable-color", "-c"])
        .arg(cfg)
        .arg("-D")
        .arg(run_dir)
        .current_dir(run_dir)
        .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Не удалось запустить sing-box: {e}"))?;
    Ok(Launch { child, log: None, slow_start: false, stop: Stop })
}

/// Ask sing-box to stop; it restores the system proxy on its way out.
pub fn request_stop(_stop: &Stop, pid: u32) -> bool {
    send_ctrl_break(pid)
}

pub fn force_stop(_stop: &Stop, child: &mut std::process::Child) {
    let _ = child.kill();
}

/// What a person calls the program at `path`.
pub fn program_name(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

pub fn is_elevated() -> bool {
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Start this exe again with the UAC prompt. Returns once the new process is created.
pub fn relaunch_elevated(args: &str) -> Result<(), String> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let file = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    let params = wide(args);
    let r = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), params.as_ptr(), std::ptr::null(), SW_SHOWNORMAL)
    } as isize;
    match r {
        r if r > 32 => Ok(()),
        5 => Err("Запуск от имени администратора отменён.".into()),
        r => Err(format!("Не удалось перезапуститься от имени администратора (код {r}).")),
    }
}

// The single-instance plugin's lock and message window: `{identifier}-sim`, `-sic`, `-siw`.
fn instance_window(id: &str) -> windows_sys::Win32::Foundation::HWND {
    use windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW;
    let class = wide(&format!("{id}-sic"));
    let title = wide(&format!("{id}-siw"));
    unsafe { FindWindowW(class.as_ptr(), title.as_ptr()) }
}

/// Bring up the window of a ReTunl that already runs; false if none does.
///
/// The single-instance plugin does this by itself between copies with the same
/// rights. A copy without admin rights cannot open the lock of an elevated one,
/// though, and would start next to it: this check runs before the plugin and
/// sends the plugin's own message (the elevated copy lets it in, see
/// `allow_instance_messages`).
pub fn show_running_instance(id: &str) -> bool {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED};
    use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
    use windows_sys::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        AllowSetForegroundWindow, GetWindowThreadProcessId, SendMessageTimeoutW, SMTO_NORMAL, WM_COPYDATA,
    };
    let name = wide(&format!("{id}-sim"));
    unsafe {
        let lock = OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr());
        if lock.is_null() {
            // denied means it exists but belongs to an elevated copy
            if GetLastError() != ERROR_ACCESS_DENIED {
                return false;
            }
        } else {
            CloseHandle(lock);
        }
        // a copy that is just starting creates the window a moment after the lock
        let mut hwnd = instance_window(id);
        for _ in 0..40 {
            if !hwnd.is_null() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
            hwnd = instance_window(id);
        }
        if hwnd.is_null() {
            return true;
        }
        let mut pid = 0;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid != 0 {
            AllowSetForegroundWindow(pid);
        }
        // the plugin's format: the working folder, then each argument, separated by NUL
        let mut data = std::env::current_dir().unwrap_or_default().to_string_lossy().into_owned();
        for arg in std::env::args() {
            data.push('\0');
            data.push_str(&arg);
        }
        let cds = COPYDATASTRUCT { dwData: 1543, cbData: data.len() as u32, lpData: data.as_ptr() as *mut _ };
        SendMessageTimeoutW(hwnd, WM_COPYDATA, 0, &cds as *const _ as isize, SMTO_NORMAL, 5000, std::ptr::null_mut());
    }
    true
}

/// Windows drops messages from a process without admin rights to an elevated
/// one. Let the plugin's "show the window" message in from a shortcut start.
pub fn allow_instance_messages(id: &str) -> bool {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        ChangeWindowMessageFilterEx, GetWindowThreadProcessId, MSGFLT_ALLOW, WM_COPYDATA,
    };
    let hwnd = instance_window(id);
    if hwnd.is_null() {
        return false;
    }
    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut pid);
        pid == std::process::id() && ChangeWindowMessageFilterEx(hwnd, WM_COPYDATA, MSGFLT_ALLOW, std::ptr::null_mut()) != 0
    }
}

pub fn wait_for_pid(pid: u32, timeout_ms: u32) {
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE};
    unsafe {
        let h = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if !h.is_null() {
            WaitForSingleObject(h, timeout_ms);
            CloseHandle(h);
        }
    }
}

/// Kills every process assigned to it when the app exits, even on a crash,
/// so sing-box never outlives ReTunl.
pub struct Job(HANDLE);
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    pub fn new() -> Option<Job> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            Some(Job(h))
        }
    }

    pub fn assign(&self, child: &std::process::Child) {
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        unsafe {
            AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE);
        }
    }
}

static CONSOLE: Mutex<()> = Mutex::new(());

unsafe extern "system" fn swallow_ctrl(_event: u32) -> BOOL {
    1
}

/// Our own process must survive the Ctrl+Break we send to sing-box.
pub fn install_ctrl_guard() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe {
        SetConsoleCtrlHandler(Some(swallow_ctrl), 1);
    }
}

/// Ask a console process (started with CREATE_NEW_PROCESS_GROUP) to exit the
/// way Ctrl+Break would: sing-box then removes its adapter, routes and the
/// system proxy itself.
pub fn send_ctrl_break(pid: u32) -> bool {
    use windows_sys::Win32::System::Console::{AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
    let _guard = locked(&CONSOLE);
    unsafe {
        FreeConsole();
        if AttachConsole(pid) == 0 {
            return false;
        }
        let ok = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) != 0;
        FreeConsole();
        ok
    }
}

const INET_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// If the Windows proxy still points at our local port (sing-box was killed
/// before it could undo it), switch it off so the internet keeps working.
pub fn clear_system_proxy_if(port: u16) -> bool {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::RegKey;
    let ours = |server: &str| [format!("127.0.0.1:{port}"), format!("localhost:{port}")].iter().any(|o| server.contains(o.as_str()));
    // sing-box sets the proxy through WinINet, which on Windows 11 updates only
    // the connection settings, not the old ProxyEnable/ProxyServer values
    let live = current_proxy().is_some_and(|(on, server)| on && ours(&server));
    let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(INET_KEY, KEY_READ | KEY_SET_VALUE);
    let legacy = key.as_ref().is_ok_and(|k| {
        k.get_value::<u32, _>("ProxyEnable").unwrap_or(0) == 1 && ours(&k.get_value::<String, _>("ProxyServer").unwrap_or_default())
    });
    if !live && !legacy {
        return false;
    }
    if legacy {
        if let Ok(k) = &key {
            let _ = k.set_value("ProxyEnable", &0u32);
        }
    }
    disable_system_proxy();
    true
}

/// The proxy WinINet uses right now: (enabled, server).
fn current_proxy() -> Option<(bool, String)> {
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::Networking::WinInet::{
        InternetQueryOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_PROXY_SERVER, PROXY_TYPE_PROXY,
    };
    unsafe {
        let mut opts: [INTERNET_PER_CONN_OPTIONW; 2] = std::mem::zeroed();
        opts[0].dwOption = INTERNET_PER_CONN_FLAGS;
        opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: std::ptr::null_mut(),
            dwOptionCount: 2,
            dwOptionError: 0,
            pOptions: opts.as_mut_ptr(),
        };
        let mut size = list.dwSize;
        if InternetQueryOptionW(std::ptr::null(), INTERNET_OPTION_PER_CONNECTION_OPTION, &mut list as *mut _ as *mut _, &mut size) == 0 {
            return None;
        }
        let flags = opts[0].Value.dwValue;
        let p = opts[1].Value.pszValue;
        let server = if p.is_null() {
            String::new()
        } else {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            GlobalFree(p as _);
            s
        };
        Some((flags & PROXY_TYPE_PROXY != 0, server))
    }
}

fn disable_system_proxy() {
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_REFRESH,
        INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTIONW,
        INTERNET_PER_CONN_OPTIONW_0, INTERNET_PER_CONN_OPTION_LISTW, PROXY_TYPE_DIRECT,
    };
    unsafe {
        let mut option = INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: PROXY_TYPE_DIRECT },
        };
        let list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: std::ptr::null_mut(),
            dwOptionCount: 1,
            dwOptionError: 0,
            pOptions: &mut option,
        };
        InternetSetOptionW(
            std::ptr::null(),
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            &list as *const _ as *const _,
            std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        );
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
        InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

// ---------- autostart ----------

const TASK_NAME: &str = "ReTunl";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[derive(Serialize, Clone, Debug, Default)]
pub struct Autostart {
    pub enabled: bool,
    /// Started through Task Scheduler with admin rights (no UAC prompt at logon).
    pub elevated: bool,
}

pub fn autostart_status() -> Autostart {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let task = quiet("schtasks").args(["/Query", "/TN", TASK_NAME]).output().map(|o| o.status.success()).unwrap_or(false);
    let run = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>(TASK_NAME))
        .is_ok();
    Autostart { enabled: task || run, elevated: task }
}

/// `admin`: start elevated at logon through Task Scheduler. Creating that task
/// needs admin rights itself, so without them autostart goes to the Run key.
pub fn set_autostart(enable: bool, admin: bool) -> Result<Autostart, String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;
    let run = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_SET_VALUE).map_err(|e| e.to_string())?;
    // clear both kinds first
    let _ = run.delete_value(TASK_NAME);
    if autostart_status().elevated {
        let _ = quiet("schtasks").args(["/Delete", "/TN", TASK_NAME, "/F"]).output();
    }
    if !enable {
        return Ok(autostart_status());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if admin && is_elevated() {
        // A scheduled task starts us elevated at logon without a UAC prompt.
        let xml = task_xml(&exe);
        let file = std::env::temp_dir().join("retunl-task.xml");
        let mut bytes = vec![0xFF, 0xFE];
        for u in xml.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        std::fs::write(&file, bytes).map_err(|e| e.to_string())?;
        let out = quiet("schtasks")
            .args(["/Create", "/TN", TASK_NAME, "/F", "/XML"])
            .arg(&file)
            .output()
            .map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&file);
        if !out.status.success() {
            return Err(format!("Планировщик заданий: {}", decode_oem(&out.stderr).trim()));
        }
    } else {
        run.set_value(TASK_NAME, &format!("\"{}\" --autostart", exe.display())).map_err(|e| e.to_string())?;
    }
    Ok(autostart_status())
}

/// Autostart that still starts this exe without admin rights (the Run key),
/// left from before ReTunl ran elevated. Another copy's entry is not ours to move.
pub fn autostart_needs_admin() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let Ok(exe) = std::env::current_exe() else { return false };
    let Ok(value) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(RUN_KEY)
        .and_then(|k| k.get_value::<String, _>(TASK_NAME))
    else {
        return false;
    };
    run_value_exe(&value).is_some_and(|t| t.to_lowercase() == exe.to_string_lossy().to_lowercase())
        && !autostart_status().elevated
}

/// The program a Run value starts: `"C:\…\retunl.exe" --autostart` → `C:\…\retunl.exe`.
fn run_value_exe(value: &str) -> Option<&str> {
    value.trim_start().strip_prefix('"')?.split('"').next()
}

fn task_xml(exe: &Path) -> String {
    let user = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").unwrap_or_default(),
        std::env::var("USERNAME").unwrap_or_default()
    );
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>ReTunl: start at logon</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>--autostart</Arguments></Exec></Actions>
</Task>"#,
        user = esc(&user),
        exe = esc(&exe.to_string_lossy()),
    )
}

/// Console tools print in the OEM code page (cp866 on Russian Windows).
fn decode_oem(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| cp866(b)).collect(),
    }
}

fn cp866(b: u8) -> char {
    match b {
        0x00..=0x7F => b as char,
        0x80..=0xAF => char::from_u32(0x0410 + (b as u32 - 0x80)).unwrap_or('?'),
        0xE0..=0xEF => char::from_u32(0x0440 + (b as u32 - 0xE0)).unwrap_or('?'),
        0xF0 => 'Ё',
        0xF1 => 'ё',
        _ => ' ',
    }
}

// ---------- processes ----------

#[derive(Serialize, Clone, Debug)]
pub struct ProcInfo {
    pub name: String,
    pub path: String,
}

/// Running programs with a known path (each path once).
pub fn processes() -> Vec<ProcInfo> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
    let mut out: Vec<ProcInfo> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == -1 {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut entry);
        while ok != 0 {
            let pid = entry.th32ProcessID;
            if pid > 4 {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if !h.is_null() {
                    let mut buf = [0u16; 1024];
                    let mut len = buf.len() as u32;
                    if QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0 {
                        let path = String::from_utf16_lossy(&buf[..len as usize]);
                        if seen.insert(path.to_lowercase()) {
                            let name = Path::new(&path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                            out.push(ProcInfo { name, path });
                        }
                    }
                    CloseHandle(h);
                }
            }
            ok = Process32NextW(snap, &mut entry);
        }
        CloseHandle(snap);
    }
    // user programs first, Windows internals last
    out.sort_by_key(|p| {
        let system = p.path.to_lowercase().starts_with(r"c:\windows\");
        (system, p.name.to_lowercase())
    });
    out
}

// ---------- network adapters ----------

#[derive(Serialize, Clone, Debug)]
pub struct Adapter {
    /// Name sing-box understands in `bind_interface`.
    pub name: String,
    pub description: String,
    pub up: bool,
    pub addresses: Vec<String>,
    /// Looks like a VPN/tunnel adapter.
    pub tunnel: bool,
}

pub fn adapters() -> Vec<Adapter> {
    let Ok(list) = ipconfig::get_adapters() else { return Vec::new() };
    let mut out: Vec<Adapter> = list
        .iter()
        .filter(|a| a.if_type() != ipconfig::IfType::SoftwareLoopback)
        .map(|a| {
            let desc = a.description().to_string();
            let lower = format!("{} {}", a.friendly_name(), desc).to_lowercase();
            let tunnel = matches!(a.if_type(), ipconfig::IfType::Tunnel | ipconfig::IfType::Ppp | ipconfig::IfType::Unsupported)
                || ["wintun", "wireguard", "amnezia", "tap-", "tun", "vpn", "tailscale", "zerotier", "openvpn", "outline"]
                    .iter()
                    .any(|k| lower.contains(k));
            Adapter {
                name: a.friendly_name().to_string(),
                description: desc,
                up: a.oper_status() == ipconfig::OperStatus::IfOperStatusUp,
                addresses: a.ip_addresses().iter().filter(|ip| !ip.is_loopback()).map(|ip| ip.to_string()).collect(),
                tunnel,
            }
        })
        .collect();
    out.sort_by_key(|a| (!a.up, !a.tunnel, a.name.to_lowercase()));
    out
}

pub fn open_in_explorer(path: &str) {
    let _ = Command::new("explorer").arg(path).spawn();
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use super::*;

    fn sing_box() -> Option<PathBuf> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.tools/sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe");
        p.exists().then_some(p)
    }

    #[test]
    fn run_value_names_the_exe() {
        assert_eq!(
            run_value_exe(r#""C:\Program Files\ReTunl\retunl.exe" --autostart"#),
            Some(r"C:\Program Files\ReTunl\retunl.exe")
        );
        assert_eq!(run_value_exe(r"C:\retunl.exe --autostart"), None);
    }

    #[test]
    fn running_instance_is_found_by_its_lock() {
        use windows_sys::Win32::System::Threading::CreateMutexW;
        let id = format!("app.retunl.test-{}", std::process::id());
        assert!(!show_running_instance(&id));
        assert!(!allow_instance_messages(&id));
        let name = wide(&format!("{id}-sim"));
        let lock = unsafe { CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
        assert!(!lock.is_null());
        // the lock without its window: a copy that is still starting
        assert!(show_running_instance(&id));
        unsafe { CloseHandle(lock) };
    }

    #[test]
    fn ctrl_break_stops_sing_box_gracefully() {
        let Some(bin) = sing_box() else { return };
        install_ctrl_guard();
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("retunl-ctrl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("c.json");
        std::fs::write(
            &cfg,
            format!(r#"{{"log":{{"level":"info"}},"inbounds":[{{"type":"mixed","listen":"127.0.0.1","listen_port":{port}}}],"outbounds":[{{"type":"direct"}}]}}"#),
        )
        .unwrap();
        let mut child = Command::new(&bin)
            .args(["run", "--disable-color", "-c"])
            .arg(&cfg)
            .creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(8);
        while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < until, "sing-box did not start");
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(send_ctrl_break(child.id()), "could not deliver Ctrl+Break");
        let until = Instant::now() + Duration::from_secs(6);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > until {
                child.kill().ok();
                panic!("sing-box ignored Ctrl+Break");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).ok();
        assert!(err.contains("sing-box started"), "{err}");
        println!("exit: {status}\n{err}");
    }

    #[test]
    fn lists_processes_and_adapters() {
        let p = processes();
        assert!(p.iter().any(|x| x.name.to_lowercase() == "explorer.exe"), "explorer.exe not found");
        let a = adapters();
        assert!(!a.is_empty());
        for x in &a {
            println!("{:<40} up={} tunnel={} {:?}", x.name, x.up, x.tunnel, x.addresses);
        }
    }

    #[test]
    fn explorer_icon() {
        let url = crate::icons::exe_icon_data_url(r"C:\Windows\explorer.exe").expect("icon");
        assert!(url.starts_with("data:image/png;base64,"));
        assert!(url.len() > 500);
    }

    #[test]
    fn oem_decoding() {
        assert_eq!(decode_oem(&[0x8E, 0xE8, 0xA8, 0xA1, 0xAA, 0xA0]), "Ошибка");
    }
}
