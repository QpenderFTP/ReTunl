//! Download speed and ping, straight and through the selected server. A
//! separate sing-box serves two local proxies: one goes out directly, past
//! the tunnel like sing-box's own traffic, the other through the server.
//! Each path picks the test server that answers it fastest.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use retunl_core::singbox::build_probe;
use retunl_core::util::now_unix;
use retunl_core::{Profile, Settings};
use serde::Serialize;
use serde_json::json;
use tokio::time::timeout_at;

use crate::paths::Paths;
use crate::probe;
use crate::sys;

struct Target {
    name: &'static str,
    url: &'static str,
    /// For the ping: an empty answer, else one byte of `url`.
    ping: Option<&'static str>,
}

/// Large files on fast public servers, in different networks: one of them is
/// usually close to wherever the traffic leaves.
const TARGETS: &[Target] = &[
    Target {
        name: "Cloudflare",
        url: "https://speed.cloudflare.com/__down?bytes=50000000",
        ping: Some("https://speed.cloudflare.com/__down?bytes=0"),
    },
    Target { name: "OVH, Франция", url: "https://proof.ovh.net/files/100Mb.dat", ping: None },
    Target { name: "Hetzner, Финляндия", url: "https://hel1-speed.hetzner.com/100MB.bin", ping: None },
    Target { name: "Selectel, Россия", url: "https://speedtest.selectel.ru/100MB", ping: None },
];

/// How long all servers race before the fastest one is picked.
const PICK_TIME: Duration = Duration::from_millis(2500);
const DOWNLOAD_TIME: Duration = Duration::from_secs(8);
/// Speed before this point of the download is not counted (connections ramp up).
const WARM_UP: Duration = Duration::from_millis(1200);
/// One measurement downloads at most this much.
const MAX_BYTES: u64 = 200 << 20;
const STREAMS: usize = 4;

#[derive(Serialize, Clone, Debug, Default)]
pub struct SpeedPart {
    /// Download speed, megabits per second.
    pub mbps: Option<f64>,
    pub ping_ms: Option<u32>,
    /// The test server that was used.
    pub server: Option<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SpeedResult {
    pub direct: SpeedPart,
    /// `None`: no server is selected.
    pub vpn: Option<SpeedPart>,
    /// Name of the server the VPN part went through.
    pub profile: Option<String>,
    pub at: i64,
}

/// What is happening now, for the live readout.
#[derive(Serialize, Clone, Debug)]
pub struct Progress {
    /// "direct" or "vpn"
    pub stage: &'static str,
    /// "pick", "ping" or "download"
    pub step: &'static str,
    pub mbps: Option<f64>,
    pub server: Option<String>,
}

pub async fn run(
    paths: &Paths,
    settings: &Settings,
    profile: Option<Profile>,
    job: Option<&sys::Job>,
    progress: impl Fn(Progress) + Send + Sync,
) -> Result<SpeedResult, String> {
    let profiles: Vec<Profile> = profile.iter().cloned().collect();
    let (kind, core) = probe::pick(paths, settings, &profiles)?;
    let profile_name = profile.as_ref().map(|p| p.name.clone());
    let mut vpn_error = None;
    let vpn_profile = match profile {
        Some(p) => match probe::unsupported(paths, kind, &p) {
            Some(e) => {
                vpn_error = Some(e.to_string());
                None
            }
            None => Some(p),
        },
        None => None,
    };

    let ctrl = probe::free_port()?;
    let direct_port = probe::free_port()?;
    let vpn_port = probe::free_port()?;
    let secret = uuid::Uuid::new_v4().simple().to_string();
    let refs: Vec<&Profile> = vpn_profile.iter().collect();
    let mut cfg = build_probe(&refs, settings, ctrl, &secret, kind).map_err(|e| e.0)?;
    let mut inbounds = vec![json!({"type": "mixed", "tag": "in-direct", "listen": "127.0.0.1", "listen_port": direct_port})];
    if let Some(p) = &vpn_profile {
        inbounds.push(json!({"type": "mixed", "tag": "in-vpn", "listen": "127.0.0.1", "listen_port": vpn_port}));
        cfg["route"]["rules"] = json!([{"inbound": "in-vpn", "action": "route", "outbound": p.id}]);
    }
    cfg["inbounds"] = json!(inbounds);
    let core = probe::launch(paths, &core, &cfg, "speed.json", ctrl, &secret, job).await?;

    let direct = measure_path(direct_port, "direct", &progress).await;
    let vpn = match (&vpn_profile, vpn_error) {
        (Some(_), _) => Some(measure_path(vpn_port, "vpn", &progress).await),
        (None, Some(error)) => Some(SpeedPart { error: Some(error), ..SpeedPart::default() }),
        (None, None) => None,
    };
    drop(core);
    Ok(SpeedResult { direct, vpn, profile: profile_name, at: now_unix() })
}

fn client(port: u16) -> Result<reqwest::Client, String> {
    let proxy = reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).map_err(|e| e.to_string())?;
    reqwest::Client::builder()
        .proxy(proxy)
        .no_gzip()
        .user_agent(concat!("ReTunl/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())
}

async fn measure_path(port: u16, stage: &'static str, progress: &(impl Fn(Progress) + Send + Sync)) -> SpeedPart {
    let fail = |e: &str| SpeedPart { error: Some(e.to_string()), ..SpeedPart::default() };
    let http = match client(port) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    progress(Progress { stage, step: "pick", mbps: None, server: None });
    let ranked = race(&http).await;
    let mut result = fail(if stage == "vpn" {
        "Через сервер не открылся ни один тестовый сервер. Проверьте задержку сервера на экране «Серверы»."
    } else {
        "Не открылся ни один тестовый сервер. Проверьте подключение к интернету."
    });
    // a test server may refuse in the middle (they limit how much one address takes)
    for target in ranked.into_iter().take(2) {
        let server = Some(target.name.to_string());
        progress(Progress { stage, step: "ping", mbps: None, server: server.clone() });
        let ping_ms = ping(&http, target).await;
        let mbps = download(&http, target.url, |mbps| {
            progress(Progress { stage, step: "download", mbps: Some(mbps), server: server.clone() })
        })
        .await;
        if let Some(mbps) = mbps {
            return SpeedPart { mbps: Some(mbps), ping_ms, server, error: None };
        }
        result = SpeedPart { ping_ms, server, ..fail("Загрузка оборвалась. Попробуйте ещё раз.") };
    }
    result
}

/// Read `url` into `counter` until `until`.
async fn pull(http: reqwest::Client, url: &'static str, counter: Arc<AtomicU64>, until: Instant, cap: u64) -> bool {
    let until = tokio::time::Instant::from_std(until);
    let Ok(Ok(mut r)) = timeout_at(until, http.get(url).send()).await else { return false };
    if !r.status().is_success() {
        return false;
    }
    while let Ok(Ok(Some(chunk))) = timeout_at(until, r.chunk()).await {
        if counter.fetch_add(chunk.len() as u64, Ordering::Relaxed) >= cap {
            break;
        }
    }
    true
}

/// Targets that answered a short race, fastest first.
async fn race(http: &reqwest::Client) -> Vec<&'static Target> {
    let until = Instant::now() + PICK_TIME;
    let counters: Vec<Arc<AtomicU64>> = TARGETS.iter().map(|_| Arc::new(AtomicU64::new(0))).collect();
    let tasks: Vec<_> = TARGETS
        .iter()
        .zip(&counters)
        .map(|(t, c)| tokio::spawn(pull(http.clone(), t.url, c.clone(), until, u64::MAX)))
        .collect();
    for t in tasks {
        let _ = t.await;
    }
    let mut got: Vec<(&'static Target, u64)> = TARGETS
        .iter()
        .zip(&counters)
        .map(|(t, c)| (t, c.load(Ordering::Relaxed)))
        .filter(|(_, n)| *n >= 32 << 10)
        .collect();
    got.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    got.into_iter().map(|(t, _)| t).collect()
}

/// Round trip to the test server over an open connection, in milliseconds.
async fn ping(http: &reqwest::Client, target: &Target) -> Option<u32> {
    let mut times = Vec::new();
    for i in 0..4 {
        let t = Instant::now();
        let req = match target.ping {
            Some(url) => http.get(url),
            None => http.get(target.url).header(reqwest::header::RANGE, "bytes=0-0"),
        };
        // the body is read so the connection stays open for the next round
        let r = tokio::time::timeout(Duration::from_secs(5), async { req.send().await?.bytes().await }).await;
        if !matches!(r, Ok(Ok(_))) {
            break;
        }
        // the first request also opens the connection
        if i > 0 {
            times.push(t.elapsed().as_millis() as u32);
        }
    }
    times.sort_unstable();
    times.get(times.len() / 2).copied()
}

/// Several parallel downloads for a few seconds; megabits per second.
async fn download(http: &reqwest::Client, url: &'static str, live: impl Fn(f64) + Send + Sync) -> Option<f64> {
    let start = Instant::now();
    let until = start + DOWNLOAD_TIME;
    let total = Arc::new(AtomicU64::new(0));
    let tasks: Vec<_> = (0..STREAMS)
        .map(|_| {
            let (http, total) = (http.clone(), total.clone());
            tokio::spawn(async move {
                // a stream that finishes its file starts another one
                while Instant::now() < until && total.load(Ordering::Relaxed) < MAX_BYTES {
                    if !pull(http.clone(), url, total.clone(), until, MAX_BYTES).await {
                        return;
                    }
                }
            })
        })
        .collect();
    let mut samples: Vec<(Instant, u64)> = vec![(start, 0)];
    let mut warm: Option<(Instant, u64)> = None;
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let now = Instant::now();
        let n = total.load(Ordering::Relaxed);
        samples.push((now, n));
        if warm.is_none() && now.duration_since(start) >= WARM_UP {
            warm = Some((now, n));
        }
        // the last second, so the number moves but does not jump
        let from = samples.iter().find(|(t, _)| now.duration_since(*t) <= Duration::from_secs(1)).copied().unwrap_or((start, 0));
        let secs = now.duration_since(from.0).as_secs_f64();
        if secs > 0.0 {
            live(mbits(n - from.1, secs));
        }
        if tasks.iter().all(|t| t.is_finished()) {
            break;
        }
    }
    let end = Instant::now();
    let n = total.load(Ordering::Relaxed);
    if n < 64 << 10 {
        return None;
    }
    let (t0, n0) = match warm {
        Some((t, b)) if end.duration_since(t) >= Duration::from_millis(1500) => (t, b),
        _ => (start, 0),
    };
    Some(mbits(n - n0, end.duration_since(t0).as_secs_f64().max(0.25)))
}

fn mbits(bytes: u64, secs: f64) -> f64 {
    (bytes as f64 * 8.0 / secs / 1e6 * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs the internet and sing-box in .tools: `cargo test -p retunl speed -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn direct_speed() {
        let rel = if cfg!(windows) {
            "../../.tools/sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe"
        } else {
            "../../.tools/sing-box/sing-box-1.14.4-darwin-arm64/sing-box"
        };
        let core = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        let dir = std::env::temp_dir().join(format!("retunl-speed-{}", uuid::Uuid::new_v4().simple()));
        let paths = Paths { exe_dir: dir.clone(), data_dir: dir.join("data"), local_dir: dir.join("local"), portable: false };
        std::fs::create_dir_all(paths.core_dir()).unwrap();
        std::fs::create_dir_all(paths.run_dir()).unwrap();
        std::fs::copy(&core, paths.core_dir().join(crate::paths::CORE_EXE)).unwrap();
        let r = run(&paths, &Settings::default(), None, None, |p| eprintln!("{p:?}")).await.unwrap();
        eprintln!("{r:?}");
        assert!(r.direct.mbps.unwrap_or(0.0) > 0.0, "{:?}", r.direct.error);
        assert!(r.vpn.is_none());

        // "through the server": a local Shadowsocks server stands in for a VPN
        let port = probe::free_port().unwrap();
        let server_cfg = dir.join("ss.json");
        let ss = json!({"log": {"level": "warn"}, "inbounds": [{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": port,
            "method": "aes-128-gcm", "password": "test-password"}], "outbounds": [{"type": "direct"}]});
        std::fs::write(&server_cfg, serde_json::to_vec(&ss).unwrap()).unwrap();
        let mut server = std::process::Command::new(&core).args(["run", "-c"]).arg(&server_cfg).spawn().unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        let profile = Profile {
            id: "p1".into(),
            name: "Local SS".into(),
            outbound: json!({"type": "shadowsocks", "server": "127.0.0.1", "server_port": port, "method": "aes-128-gcm", "password": "test-password"}),
            subscription: None,
            link: None,
            created_at: 0,
        };
        let r = run(&paths, &Settings::default(), Some(profile), None, |_| {}).await.unwrap();
        let _ = server.kill();
        let _ = server.wait();
        eprintln!("{r:?}");
        let vpn = r.vpn.expect("vpn part");
        assert!(vpn.mbps.unwrap_or(0.0) > 0.0, "{:?}", vpn.error);
        assert_eq!(r.profile.as_deref(), Some("Local SS"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
