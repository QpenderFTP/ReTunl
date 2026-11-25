use super::*;
use crate::probe;
use retunl_core::Profile;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn xray_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../.tools/xray-{}/xray.exe", fetch::XRAY_VERSION))
}

#[test]
fn real_core_accepts_the_imported_transports() {
    use std::process::Stdio;
    let exe = xray_fixture();
    if !exe.is_file() {
        return;
    }
    let security =
        "security=reality&pbk=aeRrTURClgKysZVCOjPaP7wLeV8NO-oOSl21C9MueAQ&sid=ab&sni=example.org&fp=chrome";
    let mut outs = Vec::new();
    for (i, params) in [
        format!("{security}&type=tcp&flow=xtls-rprx-vision"),
        format!("{security}&type=xhttp&path=/data&mode=auto"),
        "security=tls&type=ws&host=example.org&path=%2Fdata&ed=2048".into(),
        "security=tls&type=grpc&serviceName=svc".into(),
        "security=tls&type=httpupgrade&host=example.org&path=%2Fdata".into(),
    ]
    .iter()
    .enumerate()
    {
        let uri = format!("vless://7ef29c14-680a-4a42-8801-6f05fcd73474@example.org:443?{params}");
        let profile = retunl_core::links::parse_link(&uri).unwrap();
        let mut out = retunl_core::xray::vless(&profile.outbound).unwrap();
        out["tag"] = json!(format!("test-{i}"));
        outs.push(out);
    }
    let mut child = sys::quiet(exe)
        .args(["run", "-test", "-format", "json", "-c", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(child.stdin.take().unwrap(), &json!({"outbounds":outs})).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tun_routes_selected_profiles_only() {
    let Some(core) = test_core() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut data = AppData::default();
    let parsed = retunl_core::links::parse_link(
        "vless://7ef29c14-680a-4a42-8801-6f05fcd73474@vpn.test:443?type=xhttp&security=tls",
    )
    .unwrap();
    data.profiles.push(Profile::new("selected", "XHTTP", parsed.outbound.clone()));
    data.profiles.push(Profile::new("unused", "Unused", parsed.outbound));
    data.settings.mode = InboundMode::Tun;
    data.settings.active_profile = Some("selected".into());
    data.settings.final_route = Route::Proxy;
    let options = BuildOptions {
        ruleset_dir: dir.path().into(),
        controller_secret: "fixture".into(),
        cache_file: None,
        extended_available: false,
        direct_dns_tls: true,
        wiresock: None,
    };
    let mut built = singbox::build(&data, &options).unwrap();
    let _plan = xray::for_connection(&mut built, &data).unwrap().unwrap();
    let config = &built.config;
    assert_eq!(config["inbounds"][0]["type"], "tun");
    assert_eq!(config["route"]["final"], "XHTTP");
    let out = config["outbounds"].as_array().unwrap();
    assert!(out.iter().any(|o| o["tag"] == "XHTTP" && o["type"] == "socks"));
    assert!(!out.iter().any(|o| o["tag"] == "Unused"));
    let file = dir.path().join("tun.json");
    std::fs::write(&file, serde_json::to_vec(config).unwrap()).unwrap();
    check_config(&core, &file, dir.path()).unwrap();
}

/// Real A/B comparison: only the loopback VLESS server redirects the test IP
/// to the HTTP fixture. An accidental direct route cannot pass this check.
#[tokio::test(flavor = "multi_thread")]
async fn switch_and_measure() {
    let Some(core) = test_core() else { return };
    let xray = xray_fixture();
    if !xray.is_file() {
        eprintln!("Xray fixture missing, skipping");
        return;
    }
    std::env::set_var("RETUNL_NO_SYSTEM_PROXY", "1");
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_owned();
    let paths = Paths {
        exe_dir: dir.clone(),
        data_dir: dir.clone(),
        local_dir: dir,
        portable: true,
    };
    std::fs::create_dir_all(paths.run_dir()).unwrap();
    let exe = paths.xray_path();
    std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
    std::fs::copy(xray, exe).unwrap();
    std::fs::copy(&core, paths.core_dir().join(crate::paths::CORE_EXE)).unwrap();

    let web = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let web_port = web.local_addr().unwrap().port();
    let fixture = tokio::spawn(async move {
        while let Ok((mut s, _)) = web.accept().await {
            tokio::spawn(async move {
                let mut request = [0; 2048];
                let _ = s.read(&mut request).await;
                if request.starts_with(b"GET /speed ") {
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n")
                        .await;
                    let _ = s.write_all(&vec![0; 1 << 20]).await;
                    return;
                }
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nvless")
                    .await;
            });
        }
    });
    // The synthetic gateway name exists only in this DNS fixture. Both
    // transports must ask the profile's configured resolver to reach it.
    let dns = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let dns_port = dns.local_addr().unwrap().port();
    let resolver = tokio::spawn(async move {
        while let Ok((mut s, _)) = dns.accept().await {
            tokio::spawn(async move {
                let Ok(size) = s.read_u16().await else { return };
                let mut query = vec![0; size as usize];
                if s.read_exact(&mut query).await.is_err()
                    || !query.get(12..).is_some_and(|q| q.starts_with(b"\x05vless\x04test\x00"))
                {
                    return;
                }
                // Echo one question and return A 127.0.0.1. Strip EDNS records.
                query.truncate(12 + 12 + 4);
                query[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                query.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
                let _ = s.write_u16(query.len() as u16).await;
                let _ = s.write_all(&query).await;
            });
        }
    });
    let addr = probe::free_port().unwrap();
    let api = probe::free_port().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let cfg = json!({
        "log":{"level":"error"},
        "inbounds":[{"type":"vless","tag":"vpn","listen":"127.0.0.1","listen_port":addr,"users":[{"uuid":id}]}],
        "outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"rules":[{"inbound":"vpn","action":"route","outbound":"direct","override_address":"127.0.0.1","override_port":web_port}]},
        "experimental":{"clash_api":{"external_controller":format!("127.0.0.1:{api}"),"secret":"fixture"}}
    });
    let _server = probe::launch(&paths, &core, &cfg, "fixture.json", api, "fixture", None)
        .await
        .unwrap();
    let mut data = AppData::default();
    data.settings.mode = InboundMode::SystemProxy;
    data.settings.final_route = Route::Proxy;
    data.settings.dns.direct = format!("tcp://127.0.0.1:{dns_port}");
    data.settings.ipv6 = false;
    data.settings.bypass_lan = false;
    data.settings.active_profile = Some("ab".into());
    data.settings.test_url = "http://192.0.2.77/ab".into();
    data.settings.mixed_port = probe::free_port().unwrap();
    data.settings.controller_port = probe::free_port().unwrap();
    data.profiles.push(Profile::new(
        "ab",
        "Test",
        json!({"type":"vless","server":"vless.test","server_port":addr,"uuid":id}),
    ));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", data.settings.mixed_port)).unwrap())
        .build()
        .unwrap();
    let engine = Arc::new(Engine::new(None));
    for choice in [None, Some(false), Some(true)] {
        data.profiles[0].xray = choice;
        let enabled = choice.unwrap_or(true);
        let req = StartRequest {
            data: data.clone(),
            paths: paths.clone(),
            http: fetch::http_client(),
            elevated: false,
        };
        engine.start(req).await.unwrap();
        let response = client
            .get(&data.settings.test_url)
            .send()
            .await
            .expect("HTTP through the selected VLESS transport");
        assert_eq!(response.text().await.unwrap(), "vless");
        assert_eq!(engine.lock().xray.is_some(), enabled);
        engine.stop().await;
        if enabled {
            // The speed test launches its own transport with the main VPN stopped.
            data.settings.speed.targets = vec!["local".into()];
            data.settings.speed.custom = vec![retunl_core::SpeedCustom {
                id: "local".into(),
                name: "Loopback".into(),
                url: format!("http://127.0.0.1:{web_port}/speed"),
            }];
            let r = crate::speed::run(
                &paths,
                &data.settings,
                Some(data.profiles[0].clone()),
                engine.job(),
                |_| {},
            )
            .await
            .unwrap();
            let vpn = r.vpn.unwrap();
            assert!(vpn.mbps.is_some(), "{:?}", vpn.error);
            assert_eq!(r.profile.as_deref(), Some("Test (Xray-core)"));
        }
    }
    fixture.abort();
    resolver.abort();
}
