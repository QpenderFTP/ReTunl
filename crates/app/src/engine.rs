//! The sing-box process: start, watch, stop, logs and live statistics.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::Child;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use retunl_core::awg::CoreKind;
use retunl_core::singbox::{self, BuildOptions};
use retunl_core::util::now_unix;
use retunl_core::{AppData, InboundMode, Route};
use serde::Serialize;
use serde_json::Value;

use crate::clash::Clash;
use crate::fetch;
use crate::paths::Paths;
use crate::sys;

/// Error text meaning "TUN needs admin rights" — the UI offers a restart.
pub const NEED_ADMIN: &str = "need_admin";
const LOG_CAPACITY: usize = 4000;

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Serialize, Clone, Debug)]
pub struct Status {
    pub phase: Phase,
    pub since: Option<i64>,
    pub mode: Option<InboundMode>,
    /// Name of the selected server, if traffic goes through one.
    pub profile: Option<String>,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    /// What is happening while starting.
    pub step: Option<String>,
    /// Which core runs the connection.
    pub core: Option<CoreKind>,
}

impl Status {
    fn new(phase: Phase) -> Status {
        Status { phase, since: None, mode: None, profile: None, error: None, warnings: Vec::new(), step: None, core: None }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct LogLine {
    pub seq: u64,
    pub time: String,
    pub level: String,
    /// "core" (sing-box) or "app"
    pub source: &'static str,
    pub text: String,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Traffic {
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
    pub connections: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct Conn {
    pub id: String,
    pub process: String,
    pub path: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub network: String,
    /// Outbound tag the connection went to ("direct" = bypass).
    pub outbound: String,
    /// Our rule name, or a short description.
    pub rule: String,
    pub up: u64,
    pub down: u64,
    pub start: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Poll {
    pub status: Status,
    pub traffic: Option<Traffic>,
    pub connections: Option<Vec<Conn>>,
}

pub struct StartRequest {
    pub data: AppData,
    pub paths: Paths,
    pub http: reqwest::Client,
    pub elevated: bool,
}

struct Session {
    id: u64,
    clash: Clash,
    mode: InboundMode,
    mixed_port: u16,
    /// (rule name, text fragments identifying it in sing-box's rule string)
    signatures: Vec<(String, Vec<String>)>,
}

struct Inner {
    status: Status,
    child: Option<Child>,
    stop: Option<sys::Stop>,
    session: Option<Arc<Session>>,
    stopping: bool,
    last_sample: Option<(Instant, u64, u64)>,
}

type Listener = Box<dyn Fn(Status) + Send + Sync>;

/// sing-box's log file, read as it grows (macOS: a root sing-box has no pipes to us).
struct LogTail {
    file: std::fs::File,
    partial: Vec<u8>,
}

pub struct Engine {
    inner: Mutex<Inner>,
    logs: Mutex<(VecDeque<LogLine>, u64)>,
    tail: Mutex<Option<LogTail>>,
    op: tokio::sync::Mutex<()>,
    job: Option<sys::Job>,
    listener: OnceLock<Listener>,
    next_id: AtomicU64,
}

impl Engine {
    pub fn new() -> Engine {
        Engine {
            inner: Mutex::new(Inner {
                status: Status::new(Phase::Stopped),
                child: None,
                stop: None,
                session: None,
                stopping: false,
                last_sample: None,
            }),
            logs: Mutex::new((VecDeque::with_capacity(LOG_CAPACITY), 1)),
            tail: Mutex::new(None),
            op: tokio::sync::Mutex::new(()),
            job: sys::Job::new(),
            listener: OnceLock::new(),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn job(&self) -> Option<&sys::Job> {
        self.job.as_ref()
    }

    pub fn set_listener(&self, f: Listener) {
        let _ = self.listener.set(f);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn status(&self) -> Status {
        self.lock().status.clone()
    }

    /// Running or about to be.
    pub fn is_active(&self) -> bool {
        matches!(self.lock().status.phase, Phase::Running | Phase::Starting)
    }

    fn set_status(&self, s: Status) {
        self.lock().status = s.clone();
        if let Some(l) = self.listener.get() {
            l(s);
        }
    }

    fn set_step(&self, step: &str) {
        let mut s = self.status();
        s.step = Some(step.to_string());
        self.set_status(s);
    }

    // ---------- logs ----------

    pub fn log_app(&self, level: &str, text: &str) {
        let time = clock();
        self.push_log(time, level.to_string(), "app", text.to_string());
    }

    fn push_core_line(&self, line: &str) {
        let line = line.trim_end();
        if line.is_empty() {
            return;
        }
        // "+0300 2026-11-06 12:01:35 ERROR [id 50ms] inbound/…: text"
        let parts: Vec<&str> = line.splitn(5, ' ').collect();
        let (time, level, text) = if parts.len() == 5 && parts[0].starts_with(['+', '-']) {
            (parts[2].to_string(), parts[3].to_string(), parts[4].to_string())
        } else if let Some((_, msg)) = line.split_once("execution error: ") {
            // osascript, which asks for the macOS administrator password
            if msg.contains("(-128)") {
                (clock(), "ERROR".to_string(), "Пароль администратора не введён. Без него macOS не даёт включить режим «Все программы».".to_string())
            } else if msg.contains("non-zero status") {
                return; // the reason is in sing-box's own lines
            } else {
                (clock(), "ERROR".to_string(), msg.trim().to_string())
            }
        } else if let Some(rest) = line.strip_prefix("FATAL") {
            (clock(), "FATAL".to_string(), rest.trim_start_matches(|c: char| c == '[' || c.is_ascii_digit() || c == ']').trim().to_string())
        } else {
            (clock(), "INFO".to_string(), line.to_string())
        };
        self.push_log(time, level, "core", text);
    }

    /// Read whatever sing-box added to its log file.
    fn drain_tail(&self) {
        let mut g = self.tail.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = g.as_mut() else { return };
        let mut buf = Vec::new();
        if t.file.read_to_end(&mut buf).is_err() || buf.is_empty() {
            return;
        }
        t.partial.extend_from_slice(&buf);
        while let Some(i) = t.partial.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = t.partial.drain(..=i).collect();
            self.push_core_line(&String::from_utf8_lossy(&line));
        }
    }

    fn start_tail(self: &Arc<Self>, path: PathBuf, id: u64) {
        let Ok(file) = std::fs::File::open(&path) else { return };
        *self.tail.lock().unwrap_or_else(|e| e.into_inner()) = Some(LogTail { file, partial: Vec::new() });
        let me = self.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(150));
            me.drain_tail();
            if me.lock().session.as_ref().map(|s| s.id) != Some(id) {
                me.drain_tail();
                return;
            }
        });
    }

    fn push_log(&self, time: String, level: String, source: &'static str, text: String) {
        let mut g = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        let seq = g.1;
        g.1 += 1;
        if g.0.len() >= LOG_CAPACITY {
            g.0.pop_front();
        }
        g.0.push_back(LogLine { seq, time, level, source, text });
    }

    pub fn logs_after(&self, after: u64) -> (Vec<LogLine>, u64) {
        let g = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        let lines: Vec<LogLine> = g.0.iter().filter(|l| l.seq > after).cloned().collect();
        (lines, g.1 - 1)
    }

    pub fn clear_logs(&self) {
        self.logs.lock().unwrap_or_else(|e| e.into_inner()).0.clear();
    }

    /// The most recent sing-box error, in plain words where we know it.
    fn last_error(&self) -> Option<String> {
        let g = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        g.0.iter()
            .rev()
            .take(60)
            .find(|l| l.source == "core" && (l.level == "FATAL" || l.level == "ERROR"))
            .map(|l| humanize(&l.text))
    }

    // ---------- start / stop ----------

    pub async fn start(self: &Arc<Self>, req: StartRequest) -> Result<(), String> {
        let _op = self.op.lock().await;
        if self.lock().child.is_some() {
            return Ok(());
        }
        let r = self.start_inner(req).await;
        if let Err(e) = &r {
            self.kill_current();
            if e == NEED_ADMIN {
                self.set_status(Status::new(Phase::Stopped));
            } else {
                self.log_app("ERROR", e);
                let mut s = Status::new(Phase::Failed);
                s.error = Some(e.clone());
                self.set_status(s);
            }
        }
        r
    }

    /// Strict route on Windows blocks DNS port 53 outside the tunnel, and on
    /// some PCs that hits sing-box's own queries as well: direct sites then
    /// never resolve. A known public resolver can answer on its TLS port
    /// (853) instead, if this network lets that port through.
    async fn direct_dns_tls(&self, data: &AppData) -> bool {
        let s = &data.settings;
        if !cfg!(windows) || s.mode != InboundMode::Tun || !s.tun.strict_route {
            return false;
        }
        let Some(ip) = retunl_core::dns::dot_ip(&s.dns.direct) else { return false };
        let addr: std::net::SocketAddr = match format!("{ip}:853").parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let open = tokio::task::spawn_blocking(move || {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(1500)).is_ok()
        })
        .await
        .unwrap_or(false);
        if open {
            self.log_app("INFO", &format!("DNS для прямых соединений ({ip}) — через TLS, порт 853: строгая маршрутизация закрывает порт 53."));
        } else {
            self.log_app("INFO", &format!("Порт 853 у DNS {ip} не отвечает, DNS для прямых соединений идёт через порт 53."));
        }
        open
    }

    async fn start_inner(self: &Arc<Self>, req: StartRequest) -> Result<(), String> {
        let StartRequest { mut data, paths, http, elevated } = req;
        let mode = data.settings.mode;
        if mode == InboundMode::Tun && !elevated && sys::TUN_NEEDS_RESTART {
            return Err(NEED_ADMIN.into());
        }
        if paths.find_core().is_none() && paths.find_lx_core().is_none() {
            return Err("Не найдено ядро sing-box. Скачайте его: «Настройки» → «Ядро и списки».".into());
        }
        let mut st = Status::new(Phase::Starting);
        st.mode = Some(mode);
        st.step = Some("Готовлю настройки…".into());
        self.set_status(st);
        self.log_app("INFO", &format!("Подключение: {}", mode_label(mode)));

        data.settings.controller_port = pick_port(data.settings.controller_port);
        if mode == InboundMode::SystemProxy && !port_free(data.settings.mixed_port) {
            return Err(format!(
                "Порт {} уже занят другой программой. Укажите другой порт в настройках.",
                data.settings.mixed_port
            ));
        }
        let direct_dns_tls = self.direct_dns_tls(&data).await;
        let secret = uuid::Uuid::new_v4().simple().to_string();
        let built = singbox::build(
            &data,
            &BuildOptions {
                ruleset_dir: paths.ruleset_dir(),
                controller_secret: secret.clone(),
                cache_file: Some(paths.run_dir().join("cache.db")),
                extended_available: paths.find_lx_core().is_some(),
                direct_dns_tls,
            },
        )
        .map_err(|e| e.0)?;
        let core = paths.core_for(built.core).ok_or(match built.core {
            CoreKind::Official => "Не найдено официальное ядро sing-box. Скачайте его: «Настройки» → «Ядро и списки».",
            CoreKind::Extended => "Не найдено ядро sing-box-lx. Скачайте его: «Настройки» → «Ядро и списки».",
        })?;
        let core_kind = built.core;
        if core_kind == CoreKind::Extended {
            self.log_app("INFO", &format!("Ядро: sing-box-lx {}", retunl_core::SING_BOX_LX_VERSION));
        }
        let mut built = built;
        // for development: run proxy mode without touching the Windows proxy setting
        if std::env::var_os("RETUNL_NO_SYSTEM_PROXY").is_some() {
            if let Some(list) = built.config.get_mut("inbounds").and_then(Value::as_array_mut) {
                for ib in list {
                    if let Some(o) = ib.as_object_mut() {
                        o.remove("set_system_proxy");
                    }
                }
            }
        }
        let mut warnings = built.warnings.clone();
        for w in &warnings {
            self.log_app("WARN", w);
        }
        if !built.rule_sets.is_empty() {
            self.set_step(&format!("Проверяю списки сайтов ({})…", built.rule_sets.len()));
            let w = fetch::ensure_rule_sets(&http, &built.rule_sets, &paths.ruleset_dir(), false).await?;
            for x in &w {
                self.log_app("WARN", x);
            }
            warnings.extend(w);
        }

        let cfg_path = paths.run_dir().join("config.json");
        let json = serde_json::to_vec_pretty(&built.config).map_err(|e| e.to_string())?;
        std::fs::write(&cfg_path, json).map_err(|e| format!("Не удалось записать конфигурацию: {e}"))?;

        self.set_step("Проверяю конфигурацию…");
        let check = {
            let (core, cfg, dir) = (core.clone(), cfg_path.clone(), paths.run_dir());
            tokio::task::spawn_blocking(move || {
                sys::quiet(&core).args(["check", "--disable-color", "-c"]).arg(&cfg).current_dir(&dir).output()
            })
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| format!("Не удалось запустить sing-box: {e}"))?
        };
        if !check.status.success() {
            let err = String::from_utf8_lossy(&check.stderr);
            let line = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").to_string();
            return Err(format!("sing-box не принял конфигурацию: {}", humanize(&line)));
        }

        let tun = mode == InboundMode::Tun;
        self.set_step(match mode {
            InboundMode::Tun if !sys::TUN_NEEDS_RESTART && !elevated => "Введите пароль администратора macOS…",
            InboundMode::Tun => "Поднимаю виртуальный адаптер…",
            InboundMode::SystemProxy => "Включаю системный прокси…",
        });
        let sys::Launch { mut child, log, slow_start, stop } = sys::launch_core(&core, &cfg_path, &paths.run_dir(), tun && !elevated)?;
        if let Some(job) = &self.job {
            job.assign(&child);
        }
        for pipe in [child.stdout.take().map(|p| Box::new(p) as Box<dyn std::io::Read + Send>), child.stderr.take().map(|p| Box::new(p) as _)]
            .into_iter()
            .flatten()
        {
            let me = self.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines() {
                    match line {
                        Ok(l) => me.push_core_line(&l),
                        Err(_) => break,
                    }
                }
            });
        }

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let signatures = data
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| (r.name.clone(), singbox::rule_signatures(r)))
            .collect();
        let session = Arc::new(Session {
            id,
            clash: Clash::new(data.settings.controller_port, &secret),
            mode,
            mixed_port: data.settings.mixed_port,
            signatures,
        });
        {
            let mut g = self.lock();
            g.child = Some(child);
            g.stop = Some(stop);
            g.session = Some(session.clone());
            g.stopping = false;
            g.last_sample = None;
        }
        if let Some(log) = log {
            self.start_tail(log, id);
        }
        let me = self.clone();
        std::thread::spawn(move || me.watch(id));

        // a password prompt can take a while
        let wait_secs = if slow_start { 180 } else { 20 };
        let deadline = Instant::now() + Duration::from_secs(wait_secs);
        let mut asked = slow_start;
        loop {
            if self.lock().session.as_ref().map(|s| s.id) != Some(id) {
                return Err(self.last_error().unwrap_or_else(|| "sing-box завершился при запуске.".into()));
            }
            if session.clash.alive().await {
                break;
            }
            // sing-box has started writing: the password was accepted
            if asked && std::fs::metadata(paths.run_dir().join("core.log")).is_ok_and(|m| m.len() > 0) {
                asked = false;
                self.set_step("Поднимаю виртуальный адаптер…");
            }
            if Instant::now() > deadline {
                return Err(format!("sing-box не ответил за {wait_secs} секунд."));
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        // late start errors (e.g. TUN creation) end the process right away
        tokio::time::sleep(Duration::from_millis(400)).await;
        if self.lock().session.as_ref().map(|s| s.id) != Some(id) {
            return Err(self.last_error().unwrap_or_else(|| "sing-box завершился при запуске.".into()));
        }

        let mut st = Status::new(Phase::Running);
        st.since = Some(now_unix());
        st.mode = Some(mode);
        st.core = Some(core_kind);
        st.profile = describe_route(&data);
        st.warnings = warnings;
        self.set_status(st);
        self.log_app("INFO", "Подключено");
        Ok(())
    }

    /// Reap the process; on an unexpected exit report the error.
    fn watch(self: Arc<Self>, id: u64) {
        loop {
            std::thread::sleep(Duration::from_millis(250));
            let mut g = self.lock();
            if g.session.as_ref().map(|s| s.id) != Some(id) {
                return;
            }
            let exited = match g.child.as_mut() {
                Some(c) => c.try_wait().ok().flatten(),
                None => return,
            };
            let Some(code) = exited else { continue };
            let session = g.session.take().expect("session");
            g.child = None;
            g.stop = None;
            let stopping = g.stopping;
            drop(g);
            // the last lines explain why it ended
            self.drain_tail();
            if session.mode == InboundMode::SystemProxy && sys::clear_system_proxy_if(session.mixed_port) {
                self.log_app("INFO", "Системный прокси выключен");
            }
            if stopping {
                self.log_app("INFO", "Отключено");
                self.set_status(Status::new(Phase::Stopped));
            } else {
                let msg = self.last_error().unwrap_or_else(|| format!("sing-box неожиданно завершился ({code})."));
                self.log_app("ERROR", &format!("Соединение прервано: {msg}"));
                let mut s = Status::new(Phase::Failed);
                s.error = Some(msg);
                self.set_status(s);
            }
            return;
        }
    }

    fn kill_current(&self) {
        let mut g = self.lock();
        g.stopping = true;
        let g = &mut *g;
        if let (Some(c), Some(stop)) = (g.child.as_mut(), g.stop.as_ref()) {
            sys::force_stop(stop, c);
        } else if let Some(c) = g.child.as_mut() {
            let _ = c.kill();
        }
    }

    pub async fn stop(self: &Arc<Self>) {
        let _op = self.op.lock().await;
        let pid = {
            let mut g = self.lock();
            match g.child.as_ref().map(|c| c.id()) {
                Some(pid) => {
                    g.stopping = true;
                    pid
                }
                None => {
                    drop(g);
                    if self.status().phase != Phase::Stopped {
                        self.set_status(Status::new(Phase::Stopped));
                    }
                    return;
                }
            }
        };
        let mut s = self.status();
        s.phase = Phase::Stopping;
        s.step = Some("Отключаюсь…".into());
        self.set_status(s);
        let me = self.clone();
        let _ = tokio::task::spawn_blocking(move || me.terminate(pid)).await;
    }

    /// Graceful stop (Ctrl+Break, or the stop file on macOS), then kill after a few seconds.
    fn terminate(&self, pid: u32) {
        let sent = self.lock().stop.as_ref().is_some_and(|s| sys::request_stop(s, pid));
        let wait = |ms: u64| {
            let until = Instant::now() + Duration::from_millis(ms);
            while Instant::now() < until {
                if self.lock().child.is_none() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            false
        };
        if sent && wait(sys::STOP_GRACE_MS) {
            return;
        }
        self.log_app("WARN", "sing-box не закрылся сам, завершаю принудительно");
        self.kill_current();
        wait(3000);
    }

    /// For app exit: stop synchronously and leave the system clean.
    pub fn shutdown_blocking(&self) {
        let info = {
            let g = self.lock();
            g.child.as_ref().map(|c| c.id()).zip(g.session.clone())
        };
        if let Some((pid, session)) = info {
            self.lock().stopping = true;
            self.terminate(pid);
            if session.mode == InboundMode::SystemProxy {
                sys::clear_system_proxy_if(session.mixed_port);
            }
        }
    }

    // ---------- live data ----------

    fn session(&self) -> Option<Arc<Session>> {
        let g = self.lock();
        if g.status.phase == Phase::Running {
            g.session.clone()
        } else {
            None
        }
    }

    pub async fn poll(&self, with_connections: bool) -> Poll {
        let status = self.status();
        let Some(session) = self.session() else {
            return Poll { status, traffic: None, connections: None };
        };
        let Ok(v) = session.clash.connections().await else {
            return Poll { status, traffic: None, connections: None };
        };
        let up_total = v.get("uploadTotal").and_then(Value::as_u64).unwrap_or(0);
        let down_total = v.get("downloadTotal").and_then(Value::as_u64).unwrap_or(0);
        let list = v.get("connections").and_then(Value::as_array).cloned().unwrap_or_default();
        let now = Instant::now();
        let (up, down) = {
            let mut g = self.lock();
            let speed = match g.last_sample {
                Some((t, u, d)) if now > t => {
                    let secs = now.duration_since(t).as_secs_f64().max(0.2);
                    (
                        (up_total.saturating_sub(u) as f64 / secs) as u64,
                        (down_total.saturating_sub(d) as f64 / secs) as u64,
                    )
                }
                _ => (0, 0),
            };
            g.last_sample = Some((now, up_total, down_total));
            speed
        };
        let traffic = Traffic { up, down, up_total, down_total, connections: list.len() };
        let connections = with_connections.then(|| list.iter().map(|c| conn_view(c, &session)).collect());
        Poll { status, traffic: Some(traffic), connections }
    }

    pub async fn close_connection(&self, id: &str) -> Result<(), String> {
        match self.session() {
            Some(s) => s.clash.close(id).await,
            None => Ok(()),
        }
    }

    pub async fn close_all(&self) -> Result<(), String> {
        match self.session() {
            Some(s) => s.clash.close_all().await,
            None => Ok(()),
        }
    }
}

fn conn_view(c: &Value, session: &Session) -> Conn {
    let md = &c["metadata"];
    let s = |v: &Value| match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let path = s(&md["processPath"]);
    let process = sys::program_name(&path);
    let outbound = c["chains"].as_array().and_then(|a| a.first()).map(s).unwrap_or_default();
    let raw_rule = s(&c["rule"]);
    Conn {
        id: s(&c["id"]),
        process,
        path,
        host: s(&md["host"]),
        ip: s(&md["destinationIP"]),
        port: s(&md["destinationPort"]).parse().unwrap_or(0),
        network: s(&md["network"]),
        outbound,
        rule: rule_label(&raw_rule, &session.signatures),
        up: c["upload"].as_u64().unwrap_or(0),
        down: c["download"].as_u64().unwrap_or(0),
        start: s(&c["start"]),
    }
}

fn rule_label(raw: &str, signatures: &[(String, Vec<String>)]) -> String {
    let cond = raw.split(" => ").next().unwrap_or(raw).trim();
    if cond.is_empty() || cond == "final" {
        return "Остальной трафик".into();
    }
    if cond.contains("ip_is_private") {
        return "Локальная сеть".into();
    }
    if cond.contains("protocol=dns") {
        return "DNS".into();
    }
    for (name, tokens) in signatures {
        if tokens.iter().any(|t| !t.is_empty() && cond.contains(t.as_str())) {
            return name.clone();
        }
    }
    cond.chars().take(80).collect()
}

fn describe_route(data: &AppData) -> Option<String> {
    let name = |id: &str| data.profile(id).map(|p| p.name.clone());
    match &data.settings.final_route {
        Route::Proxy => data.active_profile().map(|p| p.name.clone()),
        Route::Profile { id } => name(id),
        Route::Direct | Route::Block => data.active_profile().map(|p| p.name.clone()),
    }
}

fn mode_label(m: InboundMode) -> &'static str {
    match m {
        InboundMode::Tun => "виртуальный адаптер (весь компьютер)",
        InboundMode::SystemProxy => "системный прокси",
    }
}

/// Plain-language versions of common sing-box errors.
pub fn humanize(err: &str) -> String {
    let e = err.trim();
    let lower = e.to_lowercase();
    if lower.contains("access is denied") || lower.contains("access denied") || lower.contains("отказано в доступе") {
        return "Нет прав администратора для создания виртуального адаптера.".into();
    }
    if lower.contains("only one usage of each socket address") || lower.contains("address already in use") {
        return format!("Порт уже занят другой программой ({e}).");
    }
    if lower.contains("cannot create a file when that file already exists") || lower.contains("already exists") && lower.contains("tun") {
        return "Адаптер с таким именем уже существует — возможно, запущена вторая копия ReTunl или другой VPN.".into();
    }
    e.to_string()
}

fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
}

fn pick_port(preferred: u16) -> u16 {
    if preferred != 0 && port_free(preferred) {
        return preferred;
    }
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(preferred)
}

fn clock() -> String {
    // local time is not in std; seconds since midnight UTC are good enough for app lines
    let secs = now_unix().rem_euclid(86400) + local_offset_secs();
    let secs = secs.rem_euclid(86400);
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

#[cfg(windows)]
fn local_offset_secs() -> i64 {
    static OFFSET: OnceLock<i64> = OnceLock::new();
    *OFFSET.get_or_init(|| {
        use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
        unsafe {
            let mut tz: TIME_ZONE_INFORMATION = std::mem::zeroed();
            let r = GetTimeZoneInformation(&mut tz);
            let bias = tz.Bias + if r == 2 { tz.DaylightBias } else { tz.StandardBias };
            -(bias as i64) * 60
        }
    })
}

#[cfg(unix)]
fn local_offset_secs() -> i64 {
    static OFFSET: OnceLock<i64> = OnceLock::new();
    *OFFSET.get_or_init(|| unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            0
        } else {
            tm.tm_gmtoff as i64
        }
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use retunl_core::{AppData, InboundMode, Route};

    use super::*;

    fn test_core() -> Option<PathBuf> {
        if let Ok(p) = std::env::var("SING_BOX") {
            return Some(PathBuf::from(p)).filter(|p| p.exists());
        }
        let rel = if cfg!(windows) {
            "../../.tools/sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe"
        } else {
            "../../.tools/sing-box/sing-box-1.14.4-darwin-arm64/sing-box"
        };
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        p.exists().then_some(p)
    }

    /// A real connection in proxy mode, without touching the system proxy.
    #[tokio::test(flavor = "multi_thread")]
    async fn connect_and_disconnect() {
        let Some(core) = test_core() else {
            eprintln!("sing-box not found, skipping");
            return;
        };
        std::env::set_var("RETUNL_NO_SYSTEM_PROXY", "1");
        let dir = std::env::temp_dir().join(format!("retunl-engine-{}", uuid::Uuid::new_v4().simple()));
        let paths = Paths { exe_dir: dir.clone(), data_dir: dir.join("data"), local_dir: dir.join("local"), portable: false };
        for d in [paths.data_dir.clone(), paths.core_dir(), paths.ruleset_dir(), paths.run_dir()] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::copy(&core, paths.core_dir().join(crate::paths::CORE_EXE)).unwrap();

        let mut data = AppData::default();
        data.settings.mode = InboundMode::SystemProxy;
        data.settings.final_route = Route::Direct;
        data.settings.mixed_port = pick_port(0);
        let port = data.settings.mixed_port;

        let engine = Arc::new(Engine::new());
        let req = StartRequest { data, paths: paths.clone(), http: crate::fetch::http_client(), elevated: false };
        engine.start(req).await.expect("connect");
        assert_eq!(engine.status().phase, Phase::Running);
        assert!(!port_free(port), "proxy port is not listening");
        assert!(engine.poll(true).await.traffic.is_some());

        engine.stop().await;
        let until = Instant::now() + Duration::from_secs(10);
        while engine.status().phase != Phase::Stopped && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(engine.status().phase, Phase::Stopped);
        assert!(port_free(port), "sing-box still holds the port");
        let (lines, _) = engine.logs_after(0);
        assert!(lines.iter().any(|l| l.source == "core"), "no sing-box output in the log");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
