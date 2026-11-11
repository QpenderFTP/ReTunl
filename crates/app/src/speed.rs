//! Download speed and ping, straight and through a server. A separate
//! sing-box serves two local proxies: one goes out directly, past the tunnel
//! like sing-box's own traffic, the other through the server.
//!
//! The file comes from a test server: the user's choice ([`SpeedPrefs`]), or
//! the one of ReTunl's usual set that answers the path fastest.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use retunl_core::singbox::build_probe;
use retunl_core::util::now_unix;
use retunl_core::{Profile, Settings, SpeedPrefs};
use serde::Serialize;
use serde_json::json;
use tokio::time::timeout_at;

use crate::paths::Paths;
use crate::probe;
use crate::sys;

/// A built-in test server: a large file a hosting company keeps for speed tests.
struct Builtin {
    id: &'static str,
    name: &'static str,
    city: &'static str,
    country: &'static str,
    /// "any" (the nearest node of a worldwide network), "ru", "eu" or "us".
    region: &'static str,
    url: &'static str,
    /// For the ping: an empty answer, else one byte of `url`.
    ping: Option<&'static str>,
    /// Takes part when the choice is left to ReTunl: in different networks, so
    /// one of them is usually close to wherever the traffic leaves.
    auto: bool,
}

const fn file(
    id: &'static str,
    name: &'static str,
    city: &'static str,
    country: &'static str,
    region: &'static str,
    url: &'static str,
    auto: bool,
) -> Builtin {
    Builtin { id, name, city, country, region, url, ping: None, auto }
}

/// Only servers that open from Russian networks without a VPN: the direct
/// measurement needs them too.
const BUILTIN: &[Builtin] = &[
    Builtin {
        id: "cloudflare",
        name: "Cloudflare",
        city: "",
        country: "",
        region: "any",
        url: "https://speed.cloudflare.com/__down?bytes=50000000",
        ping: Some("https://speed.cloudflare.com/__down?bytes=0"),
        auto: true,
    },
    file("selectel-spb", "Selectel", "Санкт-Петербург", "Россия", "ru", "https://speedtest.selectel.ru/100MB", true),
    file("hostkey-msk", "HOSTKEY", "Москва", "Россия", "ru", "https://speedtest.hostkey.ru/files/100mb.bin", false),
    file("hetzner-hel", "Hetzner", "Хельсинки", "Финляндия", "eu", "https://hel1-speed.hetzner.com/100MB.bin", true),
    file("hetzner-fsn", "Hetzner", "Фалькенштайн", "Германия", "eu", "https://fsn1-speed.hetzner.com/100MB.bin", false),
    file("hetzner-nbg", "Hetzner", "Нюрнберг", "Германия", "eu", "https://nbg1-speed.hetzner.com/100MB.bin", false),
    file("hostkey-ams", "HOSTKEY", "Амстердам", "Нидерланды", "eu", "https://speedtest.hostkey.com/files/100mb.bin", false),
    file("ovh-gra", "OVH", "Гравелин", "Франция", "eu", "https://proof.ovh.net/files/100Mb.dat", true),
    file("scaleway-par", "Scaleway", "Париж", "Франция", "eu", "https://scaleway.testdebit.info/100M.iso", false),
    file("hetzner-ash", "Hetzner", "Эшберн", "США, восток", "us", "https://ash-speed.hetzner.com/100MB.bin", false),
    file("hetzner-hil", "Hetzner", "Хиллсборо", "США, запад", "us", "https://hil-speed.hetzner.com/100MB.bin", false),
];

/// A built-in test server as the list in the UI shows it.
#[derive(Serialize, Clone, Debug)]
pub struct TargetInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub city: &'static str,
    pub country: &'static str,
    pub region: &'static str,
    pub auto: bool,
}

pub fn catalog() -> Vec<TargetInfo> {
    BUILTIN
        .iter()
        .map(|b| TargetInfo { id: b.id, name: b.name, city: b.city, country: b.country, region: b.region, auto: b.auto })
        .collect()
}

/// A test server a measurement can use.
#[derive(Clone, Debug, PartialEq)]
struct Target {
    /// "Hetzner, Хельсинки": how the result names it.
    name: String,
    url: String,
    ping: Option<String>,
}

impl From<&Builtin> for Target {
    fn from(b: &Builtin) -> Self {
        let name = if b.city.is_empty() { b.name.to_string() } else { format!("{}, {}", b.name, b.city) };
        Target { name, url: b.url.to_string(), ping: b.ping.map(str::to_string) }
    }
}

/// The servers a measurement chooses from: the ones the user ticked, or
/// ReTunl's usual set when nothing is ticked (or what was ticked is gone).
fn candidates(prefs: &SpeedPrefs) -> Vec<Target> {
    let picked = |id: &str| prefs.targets.iter().any(|t| t == id);
    let mut list: Vec<Target> = BUILTIN.iter().filter(|b| picked(b.id)).map(Target::from).collect();
    list.extend(
        prefs
            .custom
            .iter()
            .filter(|c| picked(&c.id))
            .map(|c| Target { name: c.name.clone(), url: c.url.clone(), ping: None }),
    );
    if list.is_empty() {
        list = BUILTIN.iter().filter(|b| b.auto).map(Target::from).collect();
    }
    list
}

/// Why `url` cannot be a test server, if it cannot.
pub fn check_custom_url(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url.trim()).map_err(|_| "Адрес тестового сервера должен быть ссылкой на файл, например https://example.com/100MB.bin".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err("Адрес тестового сервера должен начинаться с http:// или https://".into());
    }
    Ok(())
}

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

    let targets = candidates(&settings.speed);
    let direct = measure_path(direct_port, "direct", &targets, &progress).await;
    let vpn = match (&vpn_profile, vpn_error) {
        (Some(_), _) => Some(measure_path(vpn_port, "vpn", &targets, &progress).await),
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

async fn measure_path(
    port: u16,
    stage: &'static str,
    targets: &[Target],
    progress: &(impl Fn(Progress) + Send + Sync),
) -> SpeedPart {
    let fail = |e: &str| SpeedPart { error: Some(e.to_string()), ..SpeedPart::default() };
    let http = match client(port) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    // one server to use: nothing to choose
    let only = targets.len() == 1;
    let ranked = if only {
        targets.to_vec()
    } else {
        progress(Progress { stage, step: "pick", mbps: None, server: None });
        race(&http, targets).await
    };
    let mut result = fail(if stage == "vpn" {
        "Через сервер не открылся ни один тестовый сервер. Проверьте задержку сервера на экране «Серверы»."
    } else {
        "Не открылся ни один тестовый сервер. Проверьте подключение к интернету."
    });
    // a test server may refuse in the middle (they limit how much one address takes)
    for target in ranked.into_iter().take(2) {
        let server = Some(target.name.clone());
        progress(Progress { stage, step: "ping", mbps: None, server: server.clone() });
        let ping_ms = ping(&http, &target).await;
        let mbps = download(&http, &target.url, |mbps| {
            progress(Progress { stage, step: "download", mbps: Some(mbps), server: server.clone() })
        })
        .await;
        if let Some(mbps) = mbps {
            return SpeedPart { mbps: Some(mbps), ping_ms, server, error: None };
        }
        result = SpeedPart {
            ping_ms,
            server,
            ..fail(if only {
                "Тестовый сервер не отдал файл. Выберите другой в настройках проверки."
            } else {
                "Загрузка оборвалась. Попробуйте ещё раз."
            })
        };
    }
    result
}

/// Read `url` into `counter` until `until`.
async fn pull(http: reqwest::Client, url: Arc<str>, counter: Arc<AtomicU64>, until: Instant, cap: u64) -> bool {
    let until = tokio::time::Instant::from_std(until);
    let Ok(Ok(mut r)) = timeout_at(until, http.get(&*url).send()).await else { return false };
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
async fn race(http: &reqwest::Client, targets: &[Target]) -> Vec<Target> {
    let until = Instant::now() + PICK_TIME;
    let counters: Vec<Arc<AtomicU64>> = targets.iter().map(|_| Arc::new(AtomicU64::new(0))).collect();
    let tasks: Vec<_> = targets
        .iter()
        .zip(&counters)
        .map(|(t, c)| tokio::spawn(pull(http.clone(), t.url.as_str().into(), c.clone(), until, u64::MAX)))
        .collect();
    for t in tasks {
        let _ = t.await;
    }
    let mut got: Vec<(&Target, u64)> = targets
        .iter()
        .zip(&counters)
        .map(|(t, c)| (t, c.load(Ordering::Relaxed)))
        .filter(|(_, n)| *n >= 32 << 10)
        .collect();
    got.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    got.into_iter().map(|(t, _)| t.clone()).collect()
}

/// Round trip to the test server over an open connection, in milliseconds.
async fn ping(http: &reqwest::Client, target: &Target) -> Option<u32> {
    let mut times = Vec::new();
    for i in 0..4 {
        let t = Instant::now();
        let req = match &target.ping {
            Some(url) => http.get(url),
            None => http.get(&target.url).header(reqwest::header::RANGE, "bytes=0-0"),
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
async fn download(http: &reqwest::Client, url: &str, live: impl Fn(f64) + Send + Sync) -> Option<f64> {
    let start = Instant::now();
    let until = start + DOWNLOAD_TIME;
    let total = Arc::new(AtomicU64::new(0));
    let url: Arc<str> = url.into();
    let tasks: Vec<_> = (0..STREAMS)
        .map(|_| {
            let (http, total, url) = (http.clone(), total.clone(), url.clone());
            tokio::spawn(async move {
                // a stream that finishes its file starts another one
                while Instant::now() < until && total.load(Ordering::Relaxed) < MAX_BYTES {
                    if !pull(http.clone(), url.clone(), total.clone(), until, MAX_BYTES).await {
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
    use retunl_core::SpeedCustom;

    use super::*;

    fn names(prefs: &SpeedPrefs) -> Vec<String> {
        candidates(prefs).into_iter().map(|t| t.name).collect()
    }

    #[test]
    fn nothing_ticked_means_the_usual_set() {
        let auto = names(&SpeedPrefs::default());
        assert_eq!(auto, ["Cloudflare", "Selectel, Санкт-Петербург", "Hetzner, Хельсинки", "OVH, Гравелин"]);
        // a server that is no longer in the list does not leave the test without servers
        let stale = SpeedPrefs { targets: vec!["gone".into()], ..SpeedPrefs::default() };
        assert_eq!(names(&stale), auto);
    }

    #[test]
    fn ticked_servers_are_the_only_candidates() {
        let own = SpeedCustom { id: "c1".into(), name: "Мой VPS".into(), url: "https://vps.example/1g.bin".into() };
        let other = SpeedCustom { id: "c2".into(), name: "Не отмечен".into(), url: "https://x.example/f".into() };
        let prefs = SpeedPrefs {
            targets: vec!["c1".into(), "hetzner-ash".into()],
            custom: vec![own, other],
            profile: None,
        };
        let got = candidates(&prefs);
        assert_eq!(got.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["Hetzner, Эшберн", "Мой VPS"]);
        assert_eq!(got[1].url, "https://vps.example/1g.bin");
        assert_eq!(got[1].ping, None);
    }

    #[test]
    fn builtin_ids_are_unique_and_urls_are_https() {
        let mut ids: Vec<_> = BUILTIN.iter().map(|b| b.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), BUILTIN.len());
        assert!(BUILTIN.iter().all(|b| b.url.starts_with("https://")));
    }

    #[test]
    fn custom_url_must_be_http() {
        assert!(check_custom_url("https://example.com/100MB.bin").is_ok());
        assert!(check_custom_url(" http://10.0.0.5:8080/big ").is_ok());
        assert!(check_custom_url("example.com/100MB.bin").is_err());
        assert!(check_custom_url("ftp://example.com/f").is_err());
        assert!(check_custom_url("").is_err());
    }

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

        // one ticked server: nothing to pick, and the result names it
        let mut one = Settings::default();
        one.speed.targets = vec!["selectel-spb".into()];
        let r = run(&paths, &one, None, None, |p| assert_ne!(p.step, "pick")).await.unwrap();
        eprintln!("{r:?}");
        assert_eq!(r.direct.server.as_deref(), Some("Selectel, Санкт-Петербург"));
        assert!(r.direct.mbps.unwrap_or(0.0) > 0.0, "{:?}", r.direct.error);

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
            wiresock: None,
            cisco: None,
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
