//! Real latency tests: a separate sing-box without inbounds runs every server
//! as an outbound and measures an HTTP request through each. Works for UDP
//! protocols too and never touches system networking.

use std::collections::HashMap;
use std::process::Stdio;
use std::time::{Duration, Instant};

use retunl_core::awg::{pick_core, CoreKind, CoreNeed, CorePref};
use retunl_core::singbox::build_probe;
use retunl_core::util::now_unix;
use retunl_core::{Profile, Settings};
use serde::Serialize;

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

pub async fn measure(
    paths: &Paths,
    settings: &Settings,
    profiles: Vec<Profile>,
    job: Option<&sys::Job>,
) -> Result<HashMap<String, Latency>, String> {
    // sing-box-lx runs everything the official core does, plus AmneziaWG and XHTTP
    let lx_ok = paths.find_lx_core().is_some();
    let need = profiles.iter().map(Profile::core_need).max().unwrap_or(CoreNeed::Any);
    let mut kind = pick_core(settings.core, need, lx_ok).unwrap_or(
        if lx_ok && settings.core != CorePref::Official { CoreKind::Extended } else { CoreKind::Official },
    );
    if paths.core_for(kind).is_none() && lx_ok && settings.core != CorePref::Official {
        kind = CoreKind::Extended;
    }
    let core = paths.core_for(kind).ok_or("Не найдено ядро sing-box.")?;
    let mut results = HashMap::new();
    let (profiles, skipped): (Vec<Profile>, Vec<Profile>) = profiles
        .into_iter()
        .partition(|p| kind == CoreKind::Extended || p.core_need() != CoreNeed::Extended);
    for p in skipped {
        let error = if lx_ok { "Включите ядро sing-box-lx в настройках" } else { "Нужно ядро sing-box-lx" };
        results.insert(p.id, Latency { ms: None, error: Some(error.into()), at: now_unix() });
    }
    if profiles.is_empty() {
        return Ok(results);
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| e.to_string())?;
    let secret = uuid::Uuid::new_v4().simple().to_string();
    let refs: Vec<&Profile> = profiles.iter().collect();
    let cfg = build_probe(&refs, settings, port, &secret, kind).map_err(|e| e.0)?;
    let file = paths.run_dir().join("probe.json");
    std::fs::write(&file, serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let mut child = sys::quiet(&core)
        .args(["run", "--disable-color", "-c"])
        .arg(&file)
        .arg("-D")
        .arg(paths.run_dir())
        .current_dir(paths.run_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Не удалось запустить sing-box: {e}"))?;
    if let Some(job) = job {
        job.assign(&child);
    }
    let clash = Clash::new(port, &secret);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            let mut err = String::new();
            if let Some(mut e) = child.stderr.take() {
                use std::io::Read;
                let _ = e.read_to_string(&mut err);
            }
            let line = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("неизвестная ошибка");
            return Err(format!("Проверка не запустилась: {}", crate::engine::humanize(line)));
        }
        if clash.alive().await {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err("Проверка не запустилась: sing-box не ответил.".into());
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    let url = settings.test_url.clone();
    for chunk in profiles.chunks(PARALLEL) {
        let tasks: Vec<_> = chunk
            .iter()
            .map(|p| {
                let (clash, id, url) = (clash.clone(), p.id.clone(), url.clone());
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
    let _ = child.kill();
    let _ = child.wait();
    Ok(results)
}
