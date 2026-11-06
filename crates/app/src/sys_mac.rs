//! macOS specifics: running sing-box (with administrator rights for the
//! virtual adapter), the system proxy, autostart, processes and interfaces.
//!
//! The same functions as `sys.rs` on Windows.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

/// `Command` for a helper program (Windows hides its console; here nothing to do).
pub fn quiet(program: impl AsRef<OsStr>) -> Command {
    Command::new(program)
}

pub fn is_elevated() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The virtual adapter needs no restart here: macOS asks for the
/// administrator password each time it is created.
pub const TUN_NEEDS_RESTART: bool = false;

pub fn relaunch_elevated(_args: &str) -> Result<(), String> {
    Err("На macOS перезапуск не нужен: пароль администратора спрашивается при подключении.".into())
}

pub fn wait_for_pid(pid: u32, timeout_ms: u32) {
    let until = Instant::now() + Duration::from_millis(timeout_ms as u64);
    while Instant::now() < until && alive(pid) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Windows ties child processes to the app with a job object. Here the
/// wrapper script around sing-box watches the app instead (see `launch_core`).
pub struct Job;

impl Job {
    pub fn new() -> Option<Job> {
        None
    }

    pub fn assign(&self, _child: &Child) {}
}

pub fn install_ctrl_guard() {}

// ---------- the main sing-box ----------

/// How long a graceful stop may take before the app gives up waiting.
/// The wrapper itself kills sing-box 5 seconds after asking it to stop.
pub const STOP_GRACE_MS: u64 = 8000;

pub struct Stop {
    file: PathBuf,
    pid_file: PathBuf,
}

/// sing-box as started for a connection.
pub struct Launch {
    pub child: Child,
    /// sing-box writes its log here instead of the pipes
    pub log: Option<PathBuf>,
    /// the user may be typing a password before sing-box even starts
    pub slow_start: bool,
    pub stop: Stop,
}

const PASSWORD_PROMPT: &str = "ReTunl включает режим «Все программы». Для виртуального сетевого адаптера macOS нужен пароль администратора.";

/// Start sing-box through a small shell script that stops it when asked (a
/// stop file appears) or when ReTunl itself is gone. For the virtual adapter
/// the script runs as root, after macOS asks for the administrator password.
pub fn launch_core(core: &Path, cfg: &Path, run_dir: &Path, tun: bool) -> Result<Launch, String> {
    let log = run_dir.join("core.log");
    let stop = Stop { file: run_dir.join("core.stop"), pid_file: run_dir.join("core.pid") };
    let exit_file = run_dir.join("core.exit");
    for f in [&stop.file, &stop.pid_file, &exit_file] {
        let _ = std::fs::remove_file(f);
    }
    // created by us, so root only appends to a file we own
    std::fs::write(&log, b"").map_err(|e| format!("Не удалось создать журнал ядра: {e}"))?;

    let q = |p: &Path| sh_quote(&p.to_string_lossy());
    let (run, pidf, stopf, exitf) = (q(run_dir), q(&stop.pid_file), q(&stop.file), q(&exit_file));
    // root leaves files the next normal run must be able to write
    let chown = if tun { format!("chown -R {}:{} {run} 2>/dev/null\n", unsafe { libc::getuid() }, unsafe { libc::getgid() }) } else { String::new() };
    let script = format!(
        r#"cd {run} || exit 1
( {core} run --disable-color -c {cfg} -D {run} >> {log} 2>&1 &
  echo $! > {pidf}
  wait $!
  echo $? > {exitf} ) &
n=-1
while [ ! -e {exitf} ]; do
  if [ $n -lt 0 ] && {{ [ -e {stopf} ] || ! kill -0 {app} 2>/dev/null; }}; then n=0; fi
  if [ $n -ge 0 ] && [ -s {pidf} ]; then
    [ $n -eq 0 ] && kill -TERM "$(cat {pidf})" 2>/dev/null
    [ $n -eq 25 ] && kill -KILL "$(cat {pidf})" 2>/dev/null
    n=$((n+1))
  fi
  sleep 0.2
done
code=$(cat {exitf})
rm -f {stopf} {pidf} {exitf}
{chown}exit $code
"#,
        core = q(core),
        cfg = q(cfg),
        log = q(&log),
        app = std::process::id(),
    );
    let mut cmd = if tun {
        let mut c = Command::new("/usr/bin/osascript");
        c.arg("-e").arg(format!(
            "do shell script \"{}\" with prompt \"{}\" with administrator privileges",
            applescript_escape(&script),
            applescript_escape(PASSWORD_PROMPT)
        ));
        c
    } else {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(&script);
        c
    };
    let child = cmd
        .current_dir(run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Не удалось запустить sing-box: {e}"))?;
    Ok(Launch { child, log: Some(log), slow_start: tun, stop })
}

/// Ask sing-box to stop; it restores the system proxy on its way out.
pub fn request_stop(stop: &Stop, _pid: u32) -> bool {
    std::fs::write(&stop.file, b"").is_ok()
}

pub fn force_stop(stop: &Stop, child: &mut Child) {
    let _ = std::fs::write(&stop.file, b"");
    // works for our own sing-box; a root one is killed by its script
    if let Some(pid) = std::fs::read_to_string(&stop.pid_file).ok().and_then(|s| s.trim().parse::<i32>().ok()) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn applescript_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------- system proxy ----------

fn networksetup(args: &[&str]) -> Option<String> {
    let out = Command::new("/usr/sbin/networksetup").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Wi-Fi, Ethernet, …: every service the proxy settings belong to.
fn network_services() -> Vec<String> {
    networksetup(&["-listallnetworkservices"])
        .map(|s| {
            s.lines()
                .skip(1) // "An asterisk (*) denotes that a network service is disabled."
                .map(|l| l.trim_start_matches('*').trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// If a proxy setting still points at our port (sing-box crashed before
/// cleaning up), turn it off. Returns whether anything was changed.
pub fn clear_system_proxy_if(port: u16) -> bool {
    let mut cleared = false;
    for svc in network_services() {
        for (get, set) in [
            ("-getwebproxy", "-setwebproxystate"),
            ("-getsecurewebproxy", "-setsecurewebproxystate"),
            ("-getsocksfirewallproxy", "-setsocksfirewallproxystate"),
        ] {
            let Some(out) = networksetup(&[get, &svc]) else { continue };
            if proxy_is_ours(&out, port) && networksetup(&[set, &svc, "off"]).is_some() {
                cleared = true;
            }
        }
    }
    cleared
}

/// `networksetup -getwebproxy` output: "Enabled: Yes\nServer: 127.0.0.1\nPort: 2080\n…".
fn proxy_is_ours(out: &str, port: u16) -> bool {
    let field = |name: &str| {
        out.lines().find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(':')).map(|v| v.trim().to_string()))
    };
    field("Enabled").as_deref() == Some("Yes")
        && matches!(field("Server").as_deref(), Some("127.0.0.1" | "localhost"))
        && field("Port").and_then(|p| p.parse::<u16>().ok()) == Some(port)
}

// ---------- autostart ----------

const AGENT_LABEL: &str = "app.retunl.desktop";

#[derive(Serialize, Clone, Debug, Default)]
pub struct Autostart {
    pub enabled: bool,
    /// Windows only: started elevated by the task scheduler
    pub elevated: bool,
}

fn agent_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join("Library/LaunchAgents").join(format!("{AGENT_LABEL}.plist")))
}

pub fn autostart_status() -> Autostart {
    Autostart { enabled: agent_path().is_some_and(|p| p.exists()), elevated: false }
}

/// A login item as a LaunchAgent: starts ReTunl with `--autostart` at login.
pub fn set_autostart(enable: bool) -> Result<Autostart, String> {
    let path = agent_path().ok_or("Не найдена домашняя папка")?;
    if !enable {
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("Не удалось выключить автозапуск: {e}"))?;
        }
        return Ok(autostart_status());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{}</string><string>--autostart</string></array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
"#,
        esc(&exe.to_string_lossy())
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, plist).map_err(|e| format!("Не удалось включить автозапуск: {e}"))?;
    Ok(autostart_status())
}

// ---------- processes ----------

#[derive(Serialize, Clone, Debug)]
pub struct ProcInfo {
    pub name: String,
    pub path: String,
}

/// The outermost `.app` bundle a program lives in: (bundle path, app name).
pub fn app_bundle(path: &str) -> Option<(&str, &str)> {
    let lower = path.to_ascii_lowercase();
    let end = lower.find(".app/").map(|i| i + 4).or_else(|| lower.ends_with(".app").then_some(path.len()))?;
    let bundle = &path[..end];
    let name = bundle.rsplit('/').next()?;
    Some((bundle, &name[..name.len() - 4]))
}

/// What a person calls the program at `path`: the app's name for anything
/// inside an .app bundle (Chrome's helpers are "Google Chrome").
pub fn program_name(path: &str) -> String {
    match app_bundle(path) {
        Some((_, name)) => name.to_string(),
        None => Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
    }
}

/// Running programs, one entry per app bundle.
pub fn processes() -> Vec<ProcInfo> {
    let Ok(out) = Command::new("/bin/ps").args(["-axww", "-o", "comm="]).output() else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    let mut list = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let path = line.trim();
        if !path.starts_with('/') {
            continue;
        }
        let (path, name) = match app_bundle(path) {
            Some((bundle, name)) => (bundle.to_string(), name.to_string()),
            None => (path.to_string(), program_name(path)),
        };
        if seen.insert(path.to_lowercase()) {
            list.push(ProcInfo { name, path });
        }
    }
    list.sort_by_key(|p| p.name.to_lowercase());
    list
}

// ---------- network interfaces ----------

#[derive(Serialize, Clone, Debug)]
pub struct Adapter {
    /// what sing-box binds to (`en0`, `utun4`)
    pub name: String,
    pub description: String,
    pub up: bool,
    pub addresses: Vec<String>,
    /// looks like a VPN tunnel
    pub tunnel: bool,
}

pub fn adapters() -> Vec<Adapter> {
    let Ok(out) = Command::new("/sbin/ifconfig").output() else { return Vec::new() };
    // "Hardware Port: Wi-Fi\nDevice: en0"
    let ports: Vec<(String, String)> = networksetup(&["-listallhardwareports"])
        .map(|s| {
            let mut v = Vec::new();
            let mut port = None;
            for l in s.lines() {
                if let Some(p) = l.strip_prefix("Hardware Port:") {
                    port = Some(p.trim().to_string());
                } else if let (Some(d), Some(p)) = (l.strip_prefix("Device:"), port.take()) {
                    v.push((d.trim().to_string(), p));
                }
            }
            v
        })
        .unwrap_or_default();
    let mut list = parse_ifconfig(&String::from_utf8_lossy(&out.stdout));
    for a in &mut list {
        if let Some((_, p)) = ports.iter().find(|(d, _)| *d == a.name) {
            a.description = p.clone();
        }
    }
    list.sort_by_key(|a| (!a.up, !a.tunnel, a.name.to_lowercase()));
    list
}

fn parse_ifconfig(text: &str) -> Vec<Adapter> {
    const SKIP: &[&str] = &["lo", "gif", "stf", "anpi", "awdl", "llw", "ap", "bridge", "vmenet"];
    const TUNNEL: &[&str] = &["utun", "ipsec", "ppp", "tun", "tap", "wg"];
    let mut list: Vec<Adapter> = Vec::new();
    let mut active: Vec<Option<bool>> = Vec::new();
    for line in text.lines() {
        if !line.starts_with(['\t', ' ']) {
            let Some((name, rest)) = line.split_once(": ") else { continue };
            let up = rest.split(['<', '>']).nth(1).is_some_and(|f| f.split(',').any(|x| x == "UP"));
            let tunnel = TUNNEL.iter().any(|t| name.starts_with(t));
            list.push(Adapter {
                name: name.to_string(),
                description: if tunnel { "VPN-туннель".into() } else { name.to_string() },
                up,
                addresses: Vec::new(),
                tunnel,
            });
            active.push(None);
            continue;
        }
        let (Some(a), Some(st)) = (list.last_mut(), active.last_mut()) else { continue };
        let l = line.trim();
        if let Some(addr) = l.strip_prefix("inet6 ").or_else(|| l.strip_prefix("inet ")) {
            let addr = addr.split_whitespace().next().unwrap_or("");
            let addr = addr.split('%').next().unwrap_or(addr);
            if !addr.is_empty() && !addr.starts_with("fe80:") {
                a.addresses.push(addr.to_string());
            }
        } else if let Some(s) = l.strip_prefix("status: ") {
            *st = Some(s == "active");
        }
    }
    list.into_iter()
        .zip(active)
        .filter(|(a, _)| a.tunnel || !SKIP.iter().any(|s| a.name.starts_with(s) && a.name[s.len()..].chars().all(|c| c.is_ascii_digit())))
        .map(|(mut a, st)| {
            a.up = a.up && st.unwrap_or(true);
            a
        })
        .filter(|a| a.tunnel || !a.addresses.is_empty() || a.up)
        .collect()
}

pub fn open_in_explorer(path: &str) {
    let _ = Command::new("/usr/bin/open").arg(path).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundles() {
        let chrome = "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/1/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper";
        assert_eq!(app_bundle(chrome), Some(("/Applications/Google Chrome.app", "Google Chrome")));
        assert_eq!(program_name(chrome), "Google Chrome");
        assert_eq!(program_name("/usr/bin/curl"), "curl");
        assert_eq!(app_bundle("/Applications/Telegram.app"), Some(("/Applications/Telegram.app", "Telegram")));
    }

    #[test]
    fn proxy_output() {
        let on = "Enabled: Yes\nServer: 127.0.0.1\nPort: 2080\nAuthenticated Proxy Enabled: 0\n";
        assert!(proxy_is_ours(on, 2080));
        assert!(!proxy_is_ours(on, 2081));
        assert!(!proxy_is_ours(&on.replace("Yes", "No"), 2080));
        assert!(!proxy_is_ours(&on.replace("127.0.0.1", "10.0.0.1"), 2080));
    }

    #[test]
    fn ifconfig() {
        let text = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255\n\tstatus: active\n\
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tstatus: inactive\n\
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n\tinet 10.8.0.2 --> 10.8.0.2 netmask 0xffffffff\n";
        let list = parse_ifconfig(text);
        let names: Vec<&str> = list.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["en0", "utun3"]);
        assert_eq!(list[0].addresses, ["192.168.1.5"]);
        assert!(list[0].up && !list[0].tunnel);
        assert!(list[1].tunnel && list[1].up);
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("/Users/a b/it's"), r"'/Users/a b/it'\''s'");
        assert_eq!(applescript_escape(r#"say "hi" \ ok"#), r#"say \"hi\" \\ ok"#);
    }
}
