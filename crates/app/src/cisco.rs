//! Cisco Secure Client (AnyConnect) through its command line, vpncli. ReTunl
//! logs in and out and sends the traffic of its rules into Cisco's network
//! adapter: the server is `direct` bound to it. Windows only.
//!
//! vpncli logs in only while Cisco's own window (`csc_ui.exe`, `vpnui.exe`
//! before 5.0) is closed. It reads the answers to its questions from stdin in
//! `-s` mode, in the order it asks: group, user name, password. Logins that
//! need a browser (SAML) or a certificate check are done in Cisco's window.

// elsewhere every call says «Windows only»
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::PathBuf;

use retunl_core::Cisco;
use serde::Serialize;

/// Cisco's state as vpncli reports it.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Connected,
    Connecting,
    Disconnected,
    Unknown,
}

#[derive(Serialize, Clone, Debug)]
pub struct Status {
    pub state: State,
    /// Cisco's network adapter.
    pub adapter: Option<String>,
}

/// An installed Cisco Secure Client.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Client {
    pub cli: PathBuf,
    /// Its window.
    pub ui: Option<PathBuf>,
}

/// Folders of Secure Client 5 and of AnyConnect 4.
#[cfg(windows)]
const DIRS: [&str; 2] = ["Cisco\\Cisco Secure Client", "Cisco\\Cisco AnyConnect Secure Mobility Client"];
/// Cisco's window: Secure Client 5, AnyConnect 4.
#[cfg(windows)]
const UI_EXES: [&str; 2] = ["csc_ui.exe", "vpnui.exe"];

/// vpncli of an installed Cisco Secure Client (`RETUNL_VPNCLI` for tests).
#[cfg(windows)]
pub fn find() -> Option<Client> {
    let at = |cli: PathBuf| {
        let dir = cli.parent()?.to_path_buf();
        let ui = [dir.join("UI").join("csc_ui.exe"), dir.join("csc_ui.exe"), dir.join("vpnui.exe")].into_iter().find(|p| p.is_file());
        Some(Client { cli, ui })
    };
    if let Some(p) = std::env::var_os("RETUNL_VPNCLI").map(PathBuf::from).filter(|p| p.is_file()) {
        return at(p);
    }
    ["ProgramFiles(x86)", "ProgramW6432", "ProgramFiles"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .flat_map(|root| DIRS.map(|d| root.join(d).join("vpncli.exe")))
        .find(|p| p.is_file())
        .and_then(at)
}

#[cfg(not(windows))]
pub fn find() -> Option<Client> {
    None
}

/// The last state vpncli printed (`  >> state: Connected`).
pub fn parse_state(out: &str) -> State {
    let last = out.lines().rev().find_map(|l| l.trim().strip_prefix(">> state:"));
    match last.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("connected") => State::Connected,
        Some("connecting" | "reconnecting") => State::Connecting,
        Some("disconnected" | "disconnecting") => State::Disconnected,
        _ => State::Unknown,
    }
}

/// What vpncli reads in `-s` mode: the command and the answers in the order
/// it asks them. The group only when set; a second password (Duo, a one-time
/// code) when given; «y» last, for a banner to accept.
pub fn login_script(c: &Cisco, password: &str, second: &str) -> Result<String, String> {
    let fields = [c.host.trim(), c.group.trim(), c.username.trim(), password, second];
    if fields.iter().any(|f| f.contains(['\r', '\n'])) {
        return Err("Адрес, группа, логин и пароль Cisco пишутся в одну строку".into());
    }
    if c.host.trim().is_empty() {
        return Err("Не указан сервер Cisco".into());
    }
    let mut s = format!("connect {}\n", c.host.trim());
    if !c.group.trim().is_empty() {
        s.push_str(c.group.trim());
        s.push('\n');
    }
    s.push_str(c.username.trim());
    s.push('\n');
    s.push_str(password);
    s.push('\n');
    if !second.is_empty() {
        s.push_str(second);
        s.push('\n');
    }
    s.push_str("y\n");
    Ok(s)
}

/// Why a login did not work, from what vpncli said. `secrets` never show.
pub fn failure(out: &str, secrets: &[&str]) -> String {
    let lines: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| secrets.iter().filter(|s| !s.is_empty()).fold(l.to_string(), |l, s| l.replace(s, "•••")))
        .collect();
    let has = |l: &String, w: &str| l.to_ascii_lowercase().contains(w);
    if lines.iter().any(|l| has(l, "connect not available")) {
        return "Окно Cisco Secure Client не дало войти из ReTunl. Закройте его (значок у часов → Quit) и попробуйте снова.".into();
    }
    let bad = ["login failed", "login denied", "authentication failed", ">> error", "failed"];
    let said = lines
        .iter()
        .find(|l| bad.iter().any(|w| has(l, w)))
        .or_else(|| lines.iter().rev().find(|l| l.starts_with(">>") && !has(l, ">> state:")));
    let Some(said) = said else {
        return "Cisco Secure Client не подключился и ничего не объяснил. Попробуйте войти в окне Cisco.".into();
    };
    let text = said.trim_start_matches(">>").trim();
    let text = text.strip_prefix("error:").or_else(|| text.strip_prefix("notice:")).unwrap_or(text).trim();
    let hint = if has(said, "login") || has(said, "authentication") {
        " Проверьте логин, пароль и группу."
    } else if has(said, "certificate") {
        " Сертификат сервера проверяется в окне Cisco: войдите там."
    } else {
        ""
    };
    format!("Cisco Secure Client не подключился: {}.{hint}", text.trim_end_matches('.'))
}

#[cfg(windows)]
mod imp {
    use std::io::{Read, Write};
    use std::path::Path;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::sys;

    fn client() -> Result<Client, String> {
        find().ok_or_else(|| "Cisco Secure Client не установлен.".to_string())
    }

    /// Run vpncli and give all it printed. `input` goes to its stdin.
    fn run(cli: &Path, args: &[&str], input: Option<&str>, timeout: Duration) -> Result<String, String> {
        let mut child = sys::quiet(cli)
            .args(args)
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Не удалось запустить vpncli Cisco: {e}"))?;
        if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
            // dropped here: vpncli sees the end of its input
            let _ = stdin.write_all(text.as_bytes());
        }
        let read = |r: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut b = Vec::new();
                if let Some(mut r) = r {
                    let _ = r.read_to_end(&mut b);
                }
                b
            })
        };
        let out = read(child.stdout.take().map(|r| Box::new(r) as Box<dyn Read + Send>));
        let err = read(child.stderr.take().map(|r| Box::new(r) as Box<dyn Read + Send>));
        let until = Instant::now() + timeout;
        while matches!(child.try_wait(), Ok(None)) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
            let _ = child.wait();
        }
        let mut text = String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned();
        text.push_str(&String::from_utf8_lossy(&err.join().unwrap_or_default()));
        Ok(text)
    }

    /// Cisco's network adapter: «Cisco … Virtual Miniport Adapter», the working one first.
    pub fn adapter() -> Option<String> {
        let is_cisco = |a: &&sys::Adapter| {
            let d = a.description.to_ascii_lowercase();
            d.contains("cisco") && ["anyconnect", "secure client", "virtual miniport"].iter().any(|w| d.contains(w))
        };
        let list = sys::adapters();
        let found: Vec<&sys::Adapter> = list.iter().filter(is_cisco).collect();
        found.iter().find(|a| a.up).or(found.first()).map(|a| a.name.clone())
    }

    pub fn status() -> Result<Status, String> {
        status_of(&client()?)
    }

    pub(super) fn status_of(c: &Client) -> Result<Status, String> {
        let out = run(&c.cli, &["state"], None, Duration::from_secs(20))?;
        Ok(Status { state: parse_state(&out), adapter: adapter() })
    }

    fn ui_running() -> bool {
        sys::processes().iter().any(|p| UI_EXES.iter().any(|e| p.name.eq_ignore_ascii_case(e)))
    }

    fn close_ui() {
        for exe in UI_EXES {
            let _ = sys::quiet("taskkill").args(["/IM", exe, "/F"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
    }

    /// Cisco's window, started as the signed-in user (ReTunl may be elevated).
    pub fn open_ui() -> Result<(), String> {
        let ui = client()?.ui.ok_or("Окно Cisco Secure Client не найдено.")?;
        sys::quiet("explorer.exe").arg(&ui).spawn().map_err(|e| format!("Не удалось открыть Cisco Secure Client: {e}"))?;
        Ok(())
    }

    /// Log in with vpncli and wait for the tunnel. Cisco's window is closed
    /// for that and opened again after, if it was open.
    pub fn login(c: &Cisco, password: &str, second: &str, log: &dyn Fn(&str, &str)) -> Result<(), String> {
        login_via(&client()?, c, password, second, log)
    }

    pub(super) fn login_via(client: &Client, c: &Cisco, password: &str, second: &str, log: &dyn Fn(&str, &str)) -> Result<(), String> {
        // the way a file made in Windows has it: `vpncli -s < answers.txt`
        let script = login_script(c, password, second)?.replace('\n', "\r\n");
        if parse_state(&run(&client.cli, &["state"], None, Duration::from_secs(20))?) == State::Connected {
            log("INFO", "Cisco Secure Client уже подключён");
            return Ok(());
        }
        let had_ui = ui_running();
        if had_ui {
            log("INFO", "Cisco: закрываю окно Cisco Secure Client, иначе vpncli не войдёт");
            close_ui();
            std::thread::sleep(Duration::from_millis(500));
        }
        let user = if c.username.trim().is_empty() { String::new() } else { format!(" как {}", c.username.trim()) };
        log("INFO", &format!("Cisco: вхожу на {}{user}", c.host.trim()));
        let out = run(&client.cli, &["-s"], Some(&script), Duration::from_secs(120))?;
        // vpncli may be done before the tunnel is up
        let until = Instant::now() + Duration::from_secs(45);
        let mut state = parse_state(&out);
        // a refused login stays disconnected: no need to wait it out
        let mut down = 0;
        while state != State::Connected && down < 5 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1000));
            state = parse_state(&run(&client.cli, &["state"], None, Duration::from_secs(20))?);
            down = if state == State::Disconnected { down + 1 } else { 0 };
        }
        if had_ui {
            let _ = open_ui();
        }
        if state == State::Connected {
            log("INFO", "Cisco Secure Client подключён");
            Ok(())
        } else {
            let why = failure(&out, &[password, second]);
            log("ERROR", &why);
            Err(why)
        }
    }

    pub fn logout() -> Result<(), String> {
        logout_via(&client()?)
    }

    pub(super) fn logout_via(c: &Client) -> Result<(), String> {
        run(&c.cli, &["disconnect"], None, Duration::from_secs(30))?;
        Ok(())
    }
}

#[cfg(windows)]
pub use imp::{adapter, login, logout, open_ui, status};

#[cfg(not(windows))]
mod imp {
    use super::*;
    const ONLY: &str = "Cisco Secure Client ReTunl подключает только в Windows.";
    pub fn adapter() -> Option<String> {
        None
    }
    pub fn status() -> Result<Status, String> {
        Err(ONLY.into())
    }
    pub fn open_ui() -> Result<(), String> {
        Err(ONLY.into())
    }
    pub fn login(_: &Cisco, _: &str, _: &str, _: &dyn Fn(&str, &str)) -> Result<(), String> {
        Err(ONLY.into())
    }
    pub fn logout() -> Result<(), String> {
        Err(ONLY.into())
    }
}

#[cfg(not(windows))]
#[allow(unused_imports)]
pub use imp::{adapter, login, logout, open_ui, status};

#[cfg(test)]
mod tests {
    use super::*;

    /// What `vpncli state` prints (Secure Client 5).
    const STATE: &str = "Cisco Secure Client (version 5.1.2.42) .\r\n\r\nCopyright (c) 2004 - 2023 Cisco Systems, Inc.  All Rights Reserved.\r\n\r\n\r\n  >> state: Disconnected\r\n  >> state: Disconnected\r\n  >> notice: Ready to connect.\r\n  >> registered with local VPN subsystem.\r\n  >> state: Connected\r\n";

    #[test]
    fn reads_the_last_state() {
        assert_eq!(parse_state(STATE), State::Connected);
        assert_eq!(parse_state("  >> state: Connected\n  >> state: Reconnecting\n"), State::Connecting);
        assert_eq!(parse_state("  >> state: Disconnected\n"), State::Disconnected);
        assert_eq!(parse_state("nothing"), State::Unknown);
    }

    #[test]
    fn the_script_answers_in_order() {
        let c = Cisco { host: "vpn.example.com".into(), group: "Staff".into(), username: "ivanov".into(), disconnect: false };
        assert_eq!(login_script(&c, "p@ss", "").unwrap(), "connect vpn.example.com\nStaff\nivanov\np@ss\ny\n");
        let c = Cisco { group: String::new(), ..c };
        assert_eq!(login_script(&c, "p@ss", "push").unwrap(), "connect vpn.example.com\nivanov\np@ss\npush\ny\n");
        assert!(login_script(&c, "a\nb", "").is_err());
        assert!(login_script(&Cisco::default(), "x", "").is_err());
    }

    /// A stand-in for vpncli: `state`, `disconnect`, and a login in `-s` mode
    /// that takes the password «right» and writes down what it was told.
    #[cfg(windows)]
    const FAKE: &str = r#"@echo off
setlocal
set here=%~dp0
if /i "%~1"=="state" goto state
if /i "%~1"=="disconnect" goto down
if /i "%~1"=="-s" goto script
exit /b 1
:state
echo   ^>^> state: Disconnected
if exist "%here%up" echo   ^>^> state: Connected
exit /b 0
:down
del "%here%up" 2>nul
echo   ^>^> state: Disconnected
exit /b 0
:script
findstr "^" > "%here%got.txt"
set "pass="
for /f "usebackq skip=2 delims=" %%L in ("%here%got.txt") do if not defined pass set "pass=%%L"
if "%pass%"=="right" (
  type nul > "%here%up"
  echo   ^>^> state: Connected
) else (
  echo   ^>^> Login failed.
  echo   ^>^> state: Disconnected
)
exit /b 0
"#;

    #[cfg(windows)]
    #[test]
    fn logs_in_and_out_with_vpncli() {
        let dir = std::env::temp_dir().join(format!("retunl-cisco-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let cli = dir.join("vpncli.cmd");
        std::fs::write(&cli, FAKE.replace('\n', "\r\n")).unwrap();
        let client = Client { cli, ui: None };
        let c = Cisco { host: "vpn.example.com".into(), group: String::new(), username: "ivanov".into(), disconnect: true };
        let quiet = |_: &str, _: &str| {};

        let err = imp::login_via(&client, &c, "wrong", "", &quiet).unwrap_err();
        assert!(err.contains("Login failed") && !err.contains("wrong"), "{err}");
        assert_eq!(imp::status_of(&client).unwrap().state, State::Disconnected);

        imp::login_via(&client, &c, "right", "", &quiet).unwrap();
        let got = std::fs::read_to_string(dir.join("got.txt")).unwrap();
        assert_eq!(got.lines().collect::<Vec<_>>(), ["connect vpn.example.com", "ivanov", "right", "y"]);
        assert_eq!(imp::status_of(&client).unwrap().state, State::Connected);
        // already in: nothing is sent again
        std::fs::remove_file(dir.join("got.txt")).unwrap();
        imp::login_via(&client, &c, "right", "", &quiet).unwrap();
        assert!(!dir.join("got.txt").exists());

        imp::logout_via(&client).unwrap();
        assert_eq!(imp::status_of(&client).unwrap().state, State::Disconnected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explains_a_failed_login_without_the_password() {
        let out = "  >> state: Connecting\n  >> Login failed.\n  >> notice: secret123 was rejected\n  >> state: Disconnected\n";
        let why = failure(out, &["secret123"]);
        assert!(why.contains("Login failed") && why.contains("Проверьте логин"), "{why}");
        assert!(!failure("  >> error: bad secret123\n", &["secret123"]).contains("secret123"));
        let busy = "  >> error: Connect not available. Another Cisco Secure Client application is running\n";
        assert!(failure(busy, &[]).contains("Закройте его"));
        assert!(failure("", &[]).contains("ничего не объяснил"));
    }
}
