//! WireGuard through WireSock VPN Client (Windows only).
//!
//! WireSock tunnels the traffic of the programs its config names. ReTunl
//! starts a second sing-box under its own name ([`WIRESOCK_HELPER`]) that
//! sends everything straight out, and names only that program to WireSock.
//! The main core reaches the server through the helper's local proxy, so the
//! server's traffic passes ReTunl's rules first and WireSock after them.

use std::path::{Path, PathBuf};

use retunl_core::singbox::WireSockLink;
#[cfg(windows)]
use retunl_core::singbox::{build_wiresock_helper, WIRESOCK_HELPER};
use retunl_core::{Profile, Settings};

#[cfg(windows)]
use crate::sys;

/// Where a line of the log goes: (level, text).
pub type Log = std::sync::Arc<dyn Fn(&str, &str) + Send + Sync>;

/// wiresock-client.exe of an installed WireSock VPN Client.
#[cfg(windows)]
pub fn find_client() -> Option<PathBuf> {
    const EXE: &str = "wiresock-client.exe";
    let roots = ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"].iter().filter_map(std::env::var_os).map(PathBuf::from);
    for root in roots {
        for dir in ["WireSock VPN Client", "WireSock Secure Connect"] {
            let p = root.join(dir).join("bin").join(EXE);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(EXE)).find(|p| p.is_file())
}

#[cfg(not(windows))]
pub fn find_client() -> Option<PathBuf> {
    None
}

/// What [`start`] needs, worked out before the main config is built (that
/// config already points at the helper's port).
// only Windows runs WireSock
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Plan {
    pub link: WireSockLink,
    /// The server's name, for messages.
    pub name: String,
    conf: String,
    client: PathBuf,
    /// The network adapter the server is reached through.
    iface: Option<String>,
}

/// Check that WireSock can take `p` now and prepare its file.
#[cfg(windows)]
pub async fn plan(p: &Profile, elevated: bool) -> Result<Plan, String> {
    use std::net::{IpAddr, SocketAddr};

    let name = p.name.clone();
    let client = find_client().ok_or_else(|| {
        format!(
            "Сервер «{name}» подключается через WireSock, а WireSock VPN Client не установлен. \
             Установите его с сайта wiresock.net или выключите WireSock у сервера: «Серверы» → «…» → «WireSock»."
        )
    })?;
    if !elevated {
        return Err("WireSock работает только с правами администратора. Включите «Запускать с правами администратора» в настройках и перезапустите ReTunl.".into());
    }
    if let Some(why) = retunl_core::wgconf::wiresock_unsupported(&p.outbound) {
        return Err(format!("«{name}»: {why}"));
    }
    busy()?;
    let (host, port) = p.address().ok_or_else(|| format!("У сервера «{name}» нет адреса."))?;
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => resolve(&host, port).await.map_err(|e| format!("Не удалось найти адрес сервера «{name}» ({host}): {e}"))?,
    };
    let endpoint = SocketAddr::new(ip, port).to_string();
    let link = WireSockLink {
        profile_id: p.id.clone(),
        port: crate::probe::free_port()?,
        username: "retunl".into(),
        password: uuid::Uuid::new_v4().simple().to_string(),
        keep_out: vec![format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })],
    };
    let conf = retunl_core::wgconf::wiresock_conf(p, &[WIRESOCK_HELPER], Some(&endpoint)).map_err(|e| format!("«{name}»: {e}"))?;
    Ok(Plan { link, name, conf, client, iface: best_interface(ip) })
}

#[cfg(not(windows))]
pub async fn plan(_p: &Profile, _elevated: bool) -> Result<Plan, String> {
    Err("WireSock есть только в Windows.".into())
}

/// WireSock runs one tunnel: not while its service or another copy is up.
#[cfg(windows)]
fn busy() -> Result<(), String> {
    for service in ["wiresock-client-service", "wiresock-pro-client-service"] {
        let Ok(out) = sys::quiet("sc").args(["query", service]).output() else { continue };
        let text = String::from_utf8_lossy(&out.stdout);
        // "STATE : 4  RUNNING": the word is translated, the number is not
        let running = text
            .lines()
            .find(|l| l.trim_start().starts_with("STATE"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.split_whitespace().next())
            .is_some_and(|n| n != "1");
        if running {
            return Err(format!(
                "Запущена служба WireSock ({service}): одновременно WireSock держит один туннель. \
                 Остановите службу (от администратора: sc stop {service}) и подключитесь снова."
            ));
        }
    }
    if sys::processes().iter().any(|p| p.name.eq_ignore_ascii_case("wiresock-client.exe")) {
        return Err("WireSock уже запущен в другом окне: одновременно он держит один туннель. Закройте его и подключитесь снова.".into());
    }
    Ok(())
}

#[cfg(windows)]
async fn resolve(host: &str, port: u16) -> Result<std::net::IpAddr, String> {
    let found = tokio::time::timeout(std::time::Duration::from_secs(8), tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| "DNS не ответил".to_string())?
        .map_err(|e| e.to_string())?;
    let all: Vec<std::net::IpAddr> = found.map(|a| a.ip()).collect();
    all.iter().find(|ip| ip.is_ipv4()).or(all.first()).copied().ok_or_else(|| "адрес не найден".into())
}

/// The network adapter Windows sends to `ip` through (before ReTunl's own
/// virtual adapter is up), by the name sing-box binds to.
#[cfg(windows)]
fn best_interface(ip: std::net::IpAddr) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias, GetBestInterfaceEx};
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

    let mut index = 0u32;
    let ok = unsafe {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let mut sa: SOCKADDR_IN = std::mem::zeroed();
                sa.sin_family = AF_INET;
                sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
                GetBestInterfaceEx(&sa as *const _ as *const SOCKADDR, &mut index)
            }
            std::net::IpAddr::V6(v6) => {
                let mut sa: SOCKADDR_IN6 = std::mem::zeroed();
                sa.sin6_family = AF_INET6;
                sa.sin6_addr.u.Byte = v6.octets();
                GetBestInterfaceEx(&sa as *const _ as *const SOCKADDR, &mut index)
            }
        }
    };
    if ok != 0 {
        return None;
    }
    unsafe {
        let mut luid: NET_LUID_LH = std::mem::zeroed();
        if ConvertInterfaceIndexToLuid(index, &mut luid) != 0 {
            return None;
        }
        let mut buf = [0u16; 257];
        if ConvertInterfaceLuidToAlias(&luid, buf.as_mut_ptr(), buf.len()) != 0 {
            return None;
        }
        let len = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..len])).filter(|s| !s.is_empty())
    }
}

/// The helper and WireSock, running. Dropping it stops both.
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Tunnel {
    pub link: WireSockLink,
    pub name: String,
    /// Something the user should see, though the tunnel works.
    pub warning: Option<String>,
    client: Option<std::process::Child>,
    helper: Option<std::process::Child>,
    conf: PathBuf,
    /// WireSock's output (`wiresock.log` next to its config).
    out: PathBuf,
    /// WireSock said its tunnel is up.
    started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set when the tunnel is stopped: the reader of `out` finishes.
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Start the helper and WireSock, and check that the server answers.
#[cfg(windows)]
pub async fn start(plan: Plan, core: &Path, run_dir: &Path, settings: &Settings, job: Option<&sys::Job>, log: Log) -> Result<Tunnel, String> {
    use std::io::{BufRead, BufReader};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let Plan { link, name, conf, client, iface } = plan;
    let mut t = Tunnel {
        link,
        name,
        warning: None,
        client: None,
        helper: None,
        conf: run_dir.join("wiresock.conf"),
        out: run_dir.join("wiresock.log"),
        started: Arc::new(AtomicBool::new(false)),
        done: Arc::new(AtomicBool::new(false)),
    };
    match &iface {
        Some(i) => log("INFO", &format!("WireSock: сервер «{}» доступен через адаптер «{i}»", t.name)),
        None => log("WARN", "WireSock: не удалось узнать сетевой адаптер, помощник выберет его сам"),
    }

    // 1. the helper: a copy of the core under its own name, so WireSock can tell it apart
    let exe = run_dir.join(format!("{WIRESOCK_HELPER}.exe"));
    copy_if_changed(core, &exe).map_err(|e| format!("Не удалось подготовить помощника WireSock: {e}"))?;
    let cfg = build_wiresock_helper(settings, &t.link, iface.as_deref()).map_err(|e| e.0)?;
    let cfg_path = run_dir.join("wiresock-helper.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?)
        .map_err(|e| format!("Не удалось записать настройки помощника WireSock: {e}"))?;
    let mut helper = Command::new(&exe)
        .args(["run", "--disable-color", "-c"])
        .arg(&cfg_path)
        .arg("-D")
        .arg(run_dir)
        .current_dir(run_dir)
        .creation_flags(sys::CREATE_NO_WINDOW | sys::CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Не удалось запустить помощника WireSock: {e}"))?;
    if let Some(job) = job {
        job.assign(&helper);
    }
    for pipe in [helper.stdout.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>), helper.stderr.take().map(|p| Box::new(p) as _)]
        .into_iter()
        .flatten()
    {
        let log = log.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                let level = if line.contains("ERROR") || line.contains("FATAL") { "ERROR" } else { "WARN" };
                log(level, &format!("Помощник WireSock: {}", line.trim()));
            }
        });
    }
    t.helper = Some(helper);
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], t.link.port).into();
    let until = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(why) = t.exited() {
            return Err(why);
        }
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            break;
        }
        if Instant::now() > until {
            return Err("Помощник WireSock не запустился за 6 секунд.".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 2. WireSock, for the helper only. Its output goes to a file: WireSock
    // holds back what it prints (into a pipe too) until there is a lot of it
    // or it exits, so mostly the file tells why it stopped
    std::fs::write(&t.conf, &conf).map_err(|e| format!("Не удалось записать конфигурацию WireSock: {e}"))?;
    let out = std::fs::File::create(&t.out).map_err(|e| format!("Не удалось создать журнал WireSock: {e}"))?;
    let err = out.try_clone().map_err(|e| format!("Не удалось создать журнал WireSock: {e}"))?;
    log("INFO", &format!("WireSock: запускаю {}", client.display()));
    let child = Command::new(&client)
        .args(["run", "-config"])
        .arg(&t.conf)
        .args(["-log-level", "info"])
        .current_dir(run_dir)
        .creation_flags(sys::CREATE_NO_WINDOW | sys::CREATE_NEW_PROCESS_GROUP)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|e| format!("Не удалось запустить WireSock: {e}"))?;
    if let Some(job) = job {
        job.assign(&child);
    }
    t.client = Some(child);
    {
        let (path, started, done, log) = (t.out.clone(), t.started.clone(), t.done.clone(), log.clone());
        std::thread::spawn(move || {
            follow(&path, &done, |line| {
                let Some(line) = said(line) else { return };
                let lower = line.to_ascii_lowercase();
                if lower.contains("tunnel has started") || lower.contains("tunnel has been started") {
                    started.store(true, Ordering::Relaxed);
                }
                log(if bad(&lower) { "ERROR" } else { "INFO" }, &format!("WireSock: {line}"));
            })
        });
    }
    // a bad config ends it at once; the tunnel is up in about a second
    let until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < until && !t.started.load(Ordering::Relaxed) {
        if let Some(why) = t.exited() {
            return Err(why);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 3. the server answers through the helper
    let begun = Instant::now();
    let tunnel = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{}", t.link.port))
                .map_err(|e| e.to_string())?
                .basic_auth(&t.link.username, &t.link.password),
        )
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|e| e.to_string())?;
    let mut last = String::new();
    let mut answered = false;
    for _ in 0..3 {
        match tunnel.get(&settings.test_url).send().await {
            Ok(r) if r.status().is_success() || r.status().is_redirection() => {
                answered = true;
                break;
            }
            Ok(r) => last = format!("ответ {}", r.status()),
            Err(e) if e.is_timeout() => last = "нет ответа".into(),
            Err(e) => last = e.to_string(),
        }
        if let Some(why) = t.exited() {
            return Err(why);
        }
    }
    if !answered {
        return Err(format!(
            "Сервер «{}» не ответил через WireSock ({last}). Проверьте, что сервер работает, или попробуйте другую маскировку.",
            t.name
        ));
    }
    let ms = begun.elapsed().as_millis();

    // 4. and the internet sees the server's address, not this computer's:
    // else WireSock let the helper past the tunnel
    let direct = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build().map_err(|e| e.to_string())?;
    match tokio::join!(exit_ip(&tunnel), exit_ip(&direct)) {
        (Some(via), Some(home)) if via == home => {
            let w = format!(
                "Через WireSock адрес в интернете тот же, что и без него ({via}). Если сервер «{}» не стоит у вас дома, \
                 значит WireSock пропустил трафик мимо туннеля: отключитесь и проверьте, что другие программы WireSock закрыты.",
                t.name
            );
            log("WARN", &w);
            t.warning = Some(w);
        }
        (Some(via), _) => log("INFO", &format!("WireSock: сервер «{}» ответил за {ms} мс, адрес в интернете {via}", t.name)),
        (None, _) => log("INFO", &format!("WireSock: сервер «{}» ответил за {ms} мс", t.name)),
    }
    Ok(t)
}

/// The address the internet sees, from Cloudflare's trace page (by IP: no DNS).
#[cfg(windows)]
async fn exit_ip(http: &reqwest::Client) -> Option<std::net::IpAddr> {
    let text = http.get("https://1.1.1.1/cdn-cgi/trace").send().await.ok()?.text().await.ok()?;
    text.lines().find_map(|l| l.strip_prefix("ip=")).and_then(|ip| ip.trim().parse().ok())
}

/// Read a growing file line by line until `done` is set and nothing is left.
#[cfg(windows)]
fn follow(path: &Path, done: &std::sync::atomic::AtomicBool, mut each: impl FnMut(&str)) {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else { return };
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let finished = done.load(std::sync::atomic::Ordering::Relaxed);
        match file.read(&mut buf) {
            Ok(n) if n > 0 => {
                pending.extend_from_slice(&buf[..n]);
                while let Some(i) = pending.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = pending.drain(..=i).collect();
                    each(&String::from_utf8_lossy(&line));
                }
            }
            _ if finished => break,
            _ => std::thread::sleep(std::time::Duration::from_millis(250)),
        }
    }
    if !pending.is_empty() {
        each(&String::from_utf8_lossy(&pending));
    }
}

/// A line of WireSock's output worth showing, without its date: none of the
/// per-connection `[FILTER]` lines (every program's every connection).
fn said(line: &str) -> Option<&str> {
    let line = line.trim();
    let b = line.as_bytes();
    let line = if b.len() > 20 && b[4] == b'-' && b[10] == b' ' && b[13] == b':' { line[20..].trim_start() } else { line };
    (!line.is_empty() && !line.contains("[FILTER]")).then_some(line)
}

fn bad(lower: &str) -> bool {
    ["fail", "not present", "invalid", "error", "unable"].iter().any(|w| lower.contains(w))
}

/// Why WireSock stopped, from its output: the first error, else the last line.
fn last_words(out: &Path) -> Option<String> {
    let text = String::from_utf8_lossy(&std::fs::read(out).ok()?).into_owned();
    let lines: Vec<&str> = text.lines().filter_map(said).collect();
    lines.iter().find(|l| bad(&l.to_ascii_lowercase())).or(lines.last()).map(|l| l.to_string())
}

#[cfg(not(windows))]
pub async fn start(_plan: Plan, _core: &Path, _run_dir: &Path, _settings: &Settings, _job: Option<&crate::sys::Job>, _log: Log) -> Result<Tunnel, String> {
    Err("WireSock есть только в Windows.".into())
}

/// Copy the core unless an identical copy is already there.
#[cfg(windows)]
fn copy_if_changed(from: &Path, to: &Path) -> std::io::Result<()> {
    let (a, b) = (std::fs::metadata(from)?, std::fs::metadata(to).ok());
    let same = b.is_some_and(|b| b.len() == a.len() && b.modified().ok() >= a.modified().ok());
    if !same {
        std::fs::copy(from, to)?;
    }
    Ok(())
}

impl Tunnel {
    /// Why WireSock or the helper is gone, if one of them is.
    pub fn exited(&mut self) -> Option<String> {
        if let Some(code) = self.client.as_mut().and_then(|c| c.try_wait().ok().flatten()) {
            let why = last_words(&self.out).map(|l| format!(": {l}")).unwrap_or_default();
            return Some(format!("WireSock завершился ({code}){why}"));
        }
        if let Some(code) = self.helper.as_mut().and_then(|c| c.try_wait().ok().flatten()) {
            return Some(format!("Помощник WireSock завершился ({code}). Подробности — в «Журнале»."));
        }
        None
    }

    /// Stop WireSock (it closes the tunnel on Ctrl+Break), then the helper.
    fn shutdown(&mut self) {
        if let Some(mut c) = self.client.take() {
            #[cfg(windows)]
            if crate::sys::send_ctrl_break(c.id()) {
                let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
                while std::time::Instant::now() < until && c.try_wait().ok().flatten().is_none() {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(mut h) = self.helper.take() {
            let _ = h.kill();
            let _ = h.wait();
        }
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        // the file holds the server's private key
        let _ = std::fs::remove_file(&self.conf);
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// `p` as the latency and speed tests see it: through the running WireSock
/// tunnel when it is this server's, else unchanged.
pub fn through_tunnel(p: Profile, link: Option<&WireSockLink>) -> Profile {
    match link {
        Some(l) if l.profile_id == p.id => {
            let mut ob = l.outbound("");
            if let Some(o) = ob.as_object_mut() {
                o.remove("tag");
            }
            Profile { outbound: ob, ..p }
        }
        _ => p,
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn reads_what_wiresock_says() {
        assert_eq!(said("2026-11-11 00:05:31 [MGR]: Tunnel has started
"), Some("[MGR]: Tunnel has started"));
        assert_eq!(said("WireSock WireGuard VPN Client 1.4.7 is running as a regular process."), Some("WireSock WireGuard VPN Client 1.4.7 is running as a regular process."));
        assert_eq!(said("2026-11-11 00:05:42 [FILTER]: Skipping Dnscache : UDP : 192.168.1.2:65396 -> 192.168.1.1:53"), None);
        assert_eq!(said("   
"), None);

        let out = std::env::temp_dir().join(format!("retunl-ws-out-{}.log", uuid::Uuid::new_v4().simple()));
        std::fs::write(&out, "2026-11-11 00:05:31 WireSock Service has started.
2026-11-11 00:05:31 Failed to parse the configuration
2026-11-11 00:05:32 Service stopped
").unwrap();
        assert_eq!(last_words(&out).as_deref(), Some("Failed to parse the configuration"));
        std::fs::write(&out, "2026-11-11 00:05:31 WireSock Service has started.
2026-11-11 00:05:42 [FILTER]: x
").unwrap();
        assert_eq!(last_words(&out).as_deref(), Some("WireSock Service has started."));
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    fn finds_an_adapter_for_a_public_address() {
        // any PC with internet has a route to 1.1.1.1
        let name = best_interface("1.1.1.1".parse().unwrap());
        eprintln!("{name:?}");
        assert!(name.is_some_and(|n| !n.is_empty()));
    }

    #[test]
    fn tests_go_through_the_tunnel_of_their_server() {
        let link = WireSockLink { profile_id: "a".into(), port: 1080, username: "u".into(), password: "p".into(), keep_out: vec![] };
        let p = |id: &str| Profile {
            id: id.into(),
            name: id.into(),
            outbound: serde_json::json!({"type": "wireguard"}),
            subscription: None,
            link: None,
            created_at: 0,
            wiresock: None,
        };
        let a = through_tunnel(p("a"), Some(&link));
        assert_eq!(a.outbound["type"], "socks");
        assert_eq!(a.outbound["server_port"], 1080);
        assert!(a.outbound.get("tag").is_none());
        assert_eq!(through_tunnel(p("b"), Some(&link)).outbound["type"], "wireguard");
        assert_eq!(through_tunnel(p("a"), None).outbound["type"], "wireguard");
    }
}
