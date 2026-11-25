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

    let engine = Arc::new(Engine::new(None));
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

#[cfg(windows)]
mod vless_compare;

/// A block rule: the request is counted, and the debug lines sing-box
/// prints for it stay out of a log set to the normal level.
#[tokio::test(flavor = "multi_thread")]
async fn counts_blocked_requests() {
    let Some(core) = test_core() else {
        eprintln!("sing-box not found, skipping");
        return;
    };
    std::env::set_var("RETUNL_NO_SYSTEM_PROXY", "1");
    let dir = std::env::temp_dir().join(format!("retunl-blocks-{}", uuid::Uuid::new_v4().simple()));
    let paths = Paths { exe_dir: dir.clone(), data_dir: dir.join("data"), local_dir: dir.join("local"), portable: false };
    for d in [paths.data_dir.clone(), paths.core_dir(), paths.ruleset_dir(), paths.run_dir()] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::copy(&core, paths.core_dir().join(crate::paths::CORE_EXE)).unwrap();

    let mut data = AppData::default();
    data.settings.mode = InboundMode::SystemProxy;
    data.settings.final_route = Route::Direct;
    data.settings.mixed_port = pick_port(0);
    data.settings.log_level = "info".into();
    // the other test runs at the same time: its own control port
    data.settings.controller_port = pick_port(0);
    data.rules.push(retunl_core::Rule {
        id: "ads".into(),
        name: "Реклама".into(),
        enabled: true,
        domains: vec!["blocked.example".into()],
        route: Route::Block,
        ..Default::default()
    });
    let port = data.settings.mixed_port;

    let stats = paths.data_dir.join("stats.json");
    let engine = Arc::new(Engine::new(Some(stats.clone())));
    let req = StartRequest { data, paths: paths.clone(), http: crate::fetch::http_client(), elevated: false };
    engine.start(req).await.expect("connect");
    let http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let r = http.get("http://ads.blocked.example/pixel").send().await;
    assert!(r.as_ref().map_or(true, |r| !r.status().is_success()), "the blocked request went through: {r:?}");
    let until = Instant::now() + Duration::from_secs(5);
    while engine.blocks.stats().session == 0 && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let s = engine.poll(false).await.blocks;
    assert_eq!(s.session, 1);
    assert!(s.counting);
    assert_eq!(s.top, vec![("ads.blocked.example".to_string(), 1)]);

    engine.stop().await;
    let until = Instant::now() + Duration::from_secs(10);
    while engine.status().phase != Phase::Stopped && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (lines, _) = engine.logs_after(0);
    assert!(lines.iter().any(|l| l.source == "core"), "no sing-box output in the log");
    assert!(!lines.iter().any(|l| l.level == "DEBUG"), "debug lines leaked into the log");
    // the total is saved when the connection ends
    assert_eq!(Engine::new(Some(stats)).blocks.stats().total, 1);
    let _ = std::fs::remove_dir_all(&dir);
}
/// WireSock for real, in proxy mode. `RETUNL_WS_CONF`: a WireGuard `.conf`
/// (masking in `#@ws:` lines), `RETUNL_WS_IP`: the address its server goes
/// out from, `RETUNL_WS_LOG`: where the report goes (the Ctrl+Break sent
/// to WireSock takes this process's console, and its output with it).
/// Needs WireSock VPN Client and a prompt run as administrator:
///
/// ```text
/// cargo test -p retunl wiresock_live -- --ignored --nocapture
/// ```
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn wiresock_live() {
    wiresock_live_in(false).await;
}

/// The same with the virtual adapter: curl.exe goes to the server by a
/// rule, the rest of the computer straight out.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn wiresock_live_tun() {
    wiresock_live_in(true).await;
}

#[cfg(windows)]
async fn wiresock_live_in(tun: bool) {
    let report = std::env::var("RETUNL_WS_LOG").expect("RETUNL_WS_LOG");
    let say = {
        let report = report.clone();
        move |text: &str| {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&report) {
                let _ = writeln!(f, "{text}");
            }
        }
    };
    let said = say.clone();
    std::panic::set_hook(Box::new(move |info| said(&format!("FAILED: {info}"))));
    let conf = std::fs::read_to_string(std::env::var("RETUNL_WS_CONF").expect("RETUNL_WS_CONF")).unwrap();
    let want_ip = std::env::var("RETUNL_WS_IP").expect("RETUNL_WS_IP");
    let core = test_core().expect("sing-box");
    assert!(sys::is_elevated(), "run it as administrator");
    std::env::set_var("RETUNL_NO_SYSTEM_PROXY", "1");
    let dir = std::env::temp_dir().join(format!("retunl-wiresock-{}", uuid::Uuid::new_v4().simple()));
    let paths = Paths { exe_dir: dir.clone(), data_dir: dir.join("data"), local_dir: dir.join("local"), portable: false };
    for d in [paths.data_dir.clone(), paths.core_dir(), paths.ruleset_dir(), paths.run_dir()] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::copy(&core, paths.core_dir().join(crate::paths::CORE_EXE)).unwrap();

    let wg = retunl_core::wgconf::parse(&conf, "WireSock").unwrap();
    let ws = retunl_core::WireSock { enabled: true, ..wg.wiresock.unwrap_or_default() };
    say(&format!("masking: {ws:?}"));
    let mut data = AppData::default();
    data.profiles.push(retunl_core::Profile { wiresock: Some(ws), ..retunl_core::Profile::new("ws", wg.profile.name, wg.profile.outbound) });
    data.settings.active_profile = Some("ws".into());
    if tun {
        data.settings.mode = InboundMode::Tun;
        data.settings.final_route = Route::Direct;
        data.rules.push(retunl_core::Rule {
            id: "curl".into(),
            name: "curl".into(),
            enabled: true,
            apps: vec!["curl.exe".into()],
            route: Route::Profile { id: "ws".into() },
            ..Default::default()
        });
    } else {
        data.settings.mode = InboundMode::SystemProxy;
        data.settings.final_route = Route::Proxy;
    }
    data.settings.mixed_port = pick_port(0);
    data.settings.controller_port = pick_port(0);
    let port = data.settings.mixed_port;

    let engine = Arc::new(Engine::new(None));
    let req = StartRequest { data: data.clone(), paths: paths.clone(), http: crate::fetch::http_client(), elevated: true };
    let started = engine.start(req).await;
    let print_log = |from: u64| {
        let (lines, _) = engine.logs_after(from);
        for l in &lines {
            say(&format!("  [{} {}] {}", l.source, l.level, l.text));
        }
        lines.last().map_or(from, |l| l.seq)
    };
    let seen = print_log(0);
    started.expect("connect");
    let warnings = engine.status().warnings;
    say(&format!("warnings: {warnings:?}"));
    assert!(warnings.is_empty());
    let link = engine.wiresock_link().expect("WireSock is up");
    let running = |name: &str| sys::processes().iter().any(|p| p.name.eq_ignore_ascii_case(name));
    assert!(running("wiresock-client.exe") && running("retunl-wiresock-out.exe"));

    if tun {
        // curl.exe goes to the server by its rule, this test straight out
        let out = std::process::Command::new("curl.exe").args(["-s", "--max-time", "15", "https://api.ipify.org"]).output().unwrap();
        let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
        say(&format!("curl.exe goes out from {ip}"));
        assert_eq!(ip, want_ip);
        let direct = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(15)).build().unwrap();
        let ip = direct.get("https://api.ipify.org").send().await.unwrap().text().await.unwrap();
        say(&format!("the rest goes out from {ip}"));
        assert_ne!(ip.trim(), want_ip);
    } else {
        // the proxy goes out from the server
        let http = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).unwrap())
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let ip = http.get("https://api.ipify.org").send().await.unwrap().text().await.unwrap();
        say(&format!("goes out from {ip}"));
        assert_eq!(ip.trim(), want_ip);
    }

    // latency and speed of the server go through WireSock too
    let through = crate::wiresock::through_tunnel(data.profiles[0].clone(), Some(&link));
    let lat = crate::probe::measure(&paths, &data.settings, vec![through.clone()], engine.job()).await.unwrap();
    say(&format!("latency: {:?}", lat["ws"]));
    assert!(lat["ws"].ms.is_some(), "{:?}", lat["ws"]);
    let speed = crate::speed::run(&paths, &data.settings, Some(through), engine.job(), |_| {}).await.unwrap();
    say(&format!("speed: direct {:?}; vpn {:?}", speed.direct, speed.vpn));
    assert!(speed.vpn.as_ref().is_some_and(|v| v.mbps.is_some()), "{:?}", speed.vpn);

    engine.stop().await;
    let until = Instant::now() + Duration::from_secs(10);
    while engine.status().phase != Phase::Stopped && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    print_log(seen);
    assert_eq!(engine.status().phase, Phase::Stopped);
    // WireSock and the helper end with the connection
    let until = Instant::now() + Duration::from_secs(5);
    while (running("wiresock-client.exe") || running("retunl-wiresock-out.exe")) && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(!running("wiresock-client.exe"), "WireSock is still running");
    assert!(!running("retunl-wiresock-out.exe"), "the helper is still running");
    say("PASSED");
    let _ = std::fs::remove_dir_all(&dir);
}
