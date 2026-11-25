//! Real latency tests: a separate sing-box without inbounds runs every server
//! as an outbound and measures an HTTP request through each. Works for UDP
//! protocols too and never touches system networking.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use retunl_core::awg::{pick_core, CoreKind, CoreNeed, CorePref};
use retunl_core::singbox::build_probe;
use retunl_core::util::now_unix;
use retunl_core::{Profile, Settings};
use serde::Serialize;
use serde_json::Value;

use crate::clash::Clash;
use crate::paths::Paths;
use crate::sys;

#[derive(Serialize, Clone, Debug)]
pub struct Latency {
    pub ms: Option<u32>,
    pub error: Option<String>,
    pub at: i64,
}

const PARALLEL: usize = 8;

/// A sing-box started for a test; it is stopped when this is dropped.
pub struct ProbeCore {
    child: sys::Proc,
    pub clash: Clash,
}

impl Drop for ProbeCore {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The core for a test of `profiles`: sing-box-lx runs everything the
/// official core does, plus AmneziaWG and XHTTP.
pub fn pick(paths: &Paths, settings: &Settings, profiles: &[Profile]) -> Result<(CoreKind, PathBuf), String> {
    let lx_ok = paths.find_lx_core().is_some();
    let need = profiles.iter().filter(|p| !p.uses_xray()).map(Profile::core_need).max().unwrap_or(CoreNeed::Any);
    let mut kind = pick_core(settings.core, need, lx_ok).unwrap_or(
        if lx_ok && settings.core != CorePref::Official { CoreKind::Extended } else { CoreKind::Official },
    );
    if paths.core_for(kind).is_none() && lx_ok && settings.core != CorePref::Official {
        kind = CoreKind::Extended;
    }
    let core = paths.core_for(kind).ok_or("Не найдено ядро sing-box.")?;
    Ok((kind, core))
}

/// Why a server can't be tested on `kind`, if it can't.
pub fn unsupported(paths: &Paths, kind: CoreKind, p: &Profile) -> Option<String> {
    if p.uses_xray() {
        return if paths.xray_path().is_file() { retunl_core::xray::vless(&p.outbound).err() } else {
            Some("Установите Xray-core в меню VLESS-сервера.".into())
        };
    }
    if kind == CoreKind::Extended || p.core_need() != CoreNeed::Extended {
        return None;
    }
    Some(if paths.find_lx_core().is_some() { "Включите ядро sing-box-lx в настройках" } else { "Нужно ядро sing-box-lx" }.into())
}

#[cfg(not(target_os = "android"))]
fn spawn(paths: &Paths, core: &Path, file: &Path) -> Result<sys::Proc, String> {
    use std::process::Stdio;
    sys::quiet(core)
        .args(["run", "--disable-color", "-c"])
        .arg(file)
        .arg("-D")
        .arg(paths.run_dir())
        .current_dir(paths.run_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Не удалось запустить sing-box: {e}"))
}

/// The test runs inside the app, next to the VPN, without a tunnel of its own.
#[cfg(target_os = "android")]
fn spawn(_paths: &Paths, _core: &Path, file: &Path) -> Result<sys::Proc, String> {
    sys::start_test(file).map_err(|e| format!("Проверка не запустилась: {}", crate::engine::humanize(&e)))
}

/// A free port on 127.0.0.1.
pub fn free_port() -> Result<u16, String> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| e.to_string())
}

/// Write `cfg` as `file_name` in the run folder, start sing-box with it and
/// wait until its control API on `port` answers.
pub async fn launch(
    paths: &Paths,
    core: &Path,
    cfg: &Value,
    file_name: &str,
    port: u16,
    secret: &str,
    job: Option<&sys::Job>,
) -> Result<ProbeCore, String> {
    // Simultaneous measurements have different ports and SOCKS credentials.
    let mut file = tempfile::Builder::new().prefix("test-").suffix(file_name)
        .tempfile_in(paths.run_dir()).map_err(|e| e.to_string())?;
    serde_json::to_writer(file.as_file_mut(), cfg).map_err(|e| e.to_string())?;
    let child = spawn(paths, core, file.path())?;
    if let Some(job) = job {
        job.assign(&child);
    }
    let mut probe = ProbeCore { child, clash: Clash::new(port, secret) };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(_exit)) = probe.child.try_wait() {
            #[cfg(target_os = "android")]
            let err = _exit.error.unwrap_or_default();
            #[cfg(not(target_os = "android"))]
            let err = {
                let mut err = String::new();
                if let Some(mut e) = probe.child.stderr.take() {
                    use std::io::Read;
                    let _ = e.read_to_string(&mut err);
                }
                err
            };
            let line = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("неизвестная ошибка");
            return Err(format!("Проверка не запустилась: {}", crate::engine::humanize(line)));
        }
        if probe.clash.alive().await {
            return Ok(probe);
        }
        if Instant::now() > deadline {
            return Err("Проверка не запустилась: sing-box не ответил.".into());
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

pub async fn measure(
    paths: &Paths,
    settings: &Settings,
    profiles: Vec<Profile>,
    job: Option<&sys::Job>,
) -> Result<HashMap<String, Latency>, String> {
    let (kind, core) = pick(paths, settings, &profiles)?;
    let mut results = HashMap::new();
    let mut runnable = Vec::new();
    for p in profiles {
        match unsupported(paths, kind, &p) {
            Some(error) => {
                results.insert(p.id, Latency { ms: None, error: Some(error), at: now_unix() });
            }
            None => runnable.push(p),
        }
    }
    if runnable.is_empty() {
        return Ok(results);
    }
    let port = free_port()?;
    let secret = uuid::Uuid::new_v4().simple().to_string();
    let refs: Vec<&Profile> = runnable.iter().collect();
    let mut cfg = build_probe(&refs, settings, port, &secret, kind).map_err(|e| e.0)?;
    let plan = crate::xray::for_test(&mut cfg, &refs, settings)?;
    let _transport = crate::xray::start(plan, paths, job).await?;
    let probe = launch(paths, &core, &cfg, "probe.json", port, &secret, job).await?;

    let url = settings.test_url.clone();
    for chunk in runnable.chunks(PARALLEL) {
        let tasks: Vec<_> = chunk
            .iter()
            .map(|p| {
                let (clash, id, url) = (probe.clash.clone(), p.id.clone(), url.clone());
                tokio::spawn(async move {
                    let r = clash.delay(&id, &url, 6000).await;
                    (id, r)
                })
            })
            .collect();
        for t in tasks {
            if let Ok((id, r)) = t.await {
                let at = now_unix();
                let lat = match r {
                    Ok(ms) => Latency { ms: Some(ms), error: None, at },
                    Err(e) => Latency { ms: None, error: Some(e), at },
                };
                results.insert(id, lat);
            }
        }
    }
    drop(probe);
    Ok(results)
}
