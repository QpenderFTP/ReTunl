//! Feeds generated configs to the real `sing-box check`.
//! Needs sing-box: env `SING_BOX`, or `.tools/sing-box/…/sing-box.exe` in the repo.
//! Skips (with a message) when the binary is missing.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use retunl_core::links::parse_link;
use retunl_core::model::*;
use retunl_core::singbox::{build, build_probe, BuildOptions};
use retunl_core::{presets, wgconf};
use retunl_core::awg::CoreKind;

fn sing_box() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SING_BOX") {
        return Some(PathBuf::from(p));
    }
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe");
    p.exists().then_some(p)
}

fn work_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("retunl-check-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Real but tiny `.srs` files compiled by sing-box itself: domains only for
/// `geosite-*`, IP ranges only for `geoip-*`, like the real lists.
fn make_rule_sets(bin: &Path, dir: &Path, names: &[String]) {
    let domains = dir.join("src-domain.json");
    std::fs::write(&domains, r#"{"version": 3, "rules": [{"domain_suffix": ["example.com"]}]}"#).unwrap();
    let ips = dir.join("src-ip.json");
    std::fs::write(&ips, r#"{"version": 3, "rules": [{"ip_cidr": ["203.0.113.0/24"]}]}"#).unwrap();
    for n in names {
        let out = dir.join(n);
        if out.exists() {
            continue;
        }
        let src = if n.starts_with("geoip-") { &ips } else { &domains };
        let st = Command::new(bin).args(["rule-set", "compile", "-o"]).arg(&out).arg(src).output().unwrap();
        assert!(st.status.success(), "compile {n}: {}", String::from_utf8_lossy(&st.stderr));
    }
}

/// `sing-box check`, then a real start: `check` only validates the schema,
/// dangling tags (route.final, rule sets, DNS detours) show up at start.
fn check(bin: &Path, dir: &Path, name: &str, config: &serde_json::Value) {
    let file = dir.join(format!("{name}.json"));
    std::fs::write(&file, serde_json::to_string_pretty(config).unwrap()).unwrap();
    let out = Command::new(bin).arg("check").arg("-c").arg(&file).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "sing-box check failed for {name}:\n{stderr}\nconfig: {}", file.display());
    let noisy: Vec<&str> = stderr.lines().filter(|l| l.contains("WARN") || l.contains("deprecated")).collect();
    assert!(noisy.is_empty(), "{name}: sing-box warnings:\n{}", noisy.join("\n"));
    run_briefly(bin, dir, name, config);
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Start sing-box without admin rights: TUN (and the system proxy switch) are
/// replaced by a plain local proxy, the control API moves to a free port.
fn run_briefly(bin: &Path, dir: &Path, name: &str, config: &serde_json::Value) {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let mut cfg = config.clone();
    let proxy_port = free_port();
    if cfg.get("inbounds").is_some() {
        cfg["inbounds"] = serde_json::json!([{"type": "mixed", "tag": "test-in", "listen": "127.0.0.1", "listen_port": proxy_port}]);
    }
    let api_port = free_port();
    cfg["experimental"]["clash_api"]["external_controller"] = serde_json::json!(format!("127.0.0.1:{api_port}"));
    let file = dir.join(format!("{name}.run.json"));
    std::fs::write(&file, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
    let mut child = Command::new(bin)
        .args(["run", "--disable-color", "-c"])
        .arg(&file)
        .arg("-D")
        .arg(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut up = false;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            child.stderr.take().unwrap().read_to_string(&mut err).ok();
            panic!("{name}: sing-box exited at start ({status}):\n{err}\nconfig: {}", file.display());
        }
        if std::net::TcpStream::connect_timeout(&format!("127.0.0.1:{api_port}").parse().unwrap(), Duration::from_millis(200)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // give late start errors a moment to surface
    std::thread::sleep(Duration::from_millis(400));
    let exited = child.try_wait().unwrap();
    child.kill().ok();
    let mut err = String::new();
    child.stderr.take().unwrap().read_to_string(&mut err).ok();
    child.wait().ok();
    assert!(exited.is_none() && up, "{name}: sing-box did not stay up:\n{err}");
    let bad: Vec<&str> = err.lines().filter(|l| l.contains("ERROR") || l.contains("FATAL") || l.contains("deprecated")).collect();
    assert!(bad.is_empty(), "{name}: errors while starting:\n{}", bad.join("\n"));
}

fn profile(id: &str, link: &str) -> Profile {
    let p = parse_link(link).unwrap_or_else(|e| panic!("{link}: {e}"));
    Profile::new(id, p.name, p.outbound)
}

// Real-looking keys so sing-box accepts them.
const WG_PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const WG_PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const REALITY_PBK: &str = "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc";

fn all_links() -> Vec<String> {
    let vmess = serde_json::json!({"v": "2", "ps": "vm", "add": "vm.example.com", "port": "443", "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "vm.example.com", "path": "/ray", "tls": "tls"});
    vec![
        format!("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={REALITY_PBK}&sid=6ba85179e30d4fc2&type=tcp#reality"),
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com#ws".into(),
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=grpc&serviceName=svc#grpc".into(),
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=h2&path=%2Fh2&host=example.com#h2".into(),
        "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:80?type=httpupgrade&path=%2Fup&host=example.com#hu".into(),
        format!("vmess://{}", STANDARD.encode(vmess.to_string())),
        "trojan://password@example.com:443?sni=example.com&fp=firefox#trojan".into(),
        format!("ss://{}@1.2.3.4:8388#ss", STANDARD.encode("chacha20-ietf-poly1305:password")),
        "ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@1.2.3.4:443#ss2022".into(),
        format!("ss://{}@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#ssobfs", STANDARD.encode("aes-256-gcm:pw")),
        "hysteria2://letmein@example.com:443/?insecure=1&obfs=salamander&obfs-password=gawrgura&sni=real.example.com#hy2".into(),
        "hy2://pass@example.com:20000-30000?sni=example.com#hop".into(),
        "hysteria://example.com:36712?auth=pw&peer=example.com&upmbps=50&downmbps=200&obfsParam=xyz#hy1".into(),
        "tuic://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365:pass@example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=example.com#tuic".into(),
        format!("wireguard://{}@162.159.192.1:2408?publickey={}&address=172.16.0.2%2F32&reserved=1,2,3&mtu=1280#wg", urlenc(WG_PRIV), urlenc(WG_PUB)),
        "socks5://user:pw@127.0.0.1:1080#socks".into(),
        "anytls://secret@example.com:443#anytls".into(),
    ]
}

fn urlenc(s: &str) -> String {
    s.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
}

#[test]
fn every_protocol_as_the_active_server() {
    let Some(bin) = sing_box() else {
        eprintln!("sing-box not found, skipping");
        return;
    };
    let dir = work_dir("proto");
    for (i, link) in all_links().iter().enumerate() {
        let mut d = AppData::default();
        let p = profile(&format!("p{i}"), link);
        let name = p.name.clone();
        d.settings.active_profile = Some(p.id.clone());
        d.profiles.push(p);
        let opts = BuildOptions { ruleset_dir: dir.clone(), controller_secret: "x".into(), cache_file: None, extended_available: false, direct_dns_tls: false, wiresock: None };
        let built = build(&d, &opts).unwrap();
        check(&bin, &dir, &format!("proto-{i}-{}", name.replace(['/', ':'], "_")), &built.config);
    }
}

#[test]
fn rules_presets_and_modes() {
    let Some(bin) = sing_box() else {
        eprintln!("sing-box not found, skipping");
        return;
    };
    let dir = work_dir("rules");
    let mut d = AppData::default();
    for (i, link) in all_links().iter().enumerate() {
        d.profiles.push(profile(&format!("p{i}"), link));
    }
    d.settings.active_profile = Some("p0".into());
    // every preset, plus custom rules of each shape
    for p in presets::PRESETS {
        d.rules.push(presets::instantiate(p));
    }
    d.rules.push(Rule {
        id: "c1".into(),
        name: "Chrome только YouTube".into(),
        enabled: true,
        match_all: true,
        apps: vec!["chrome.exe".into(), "C:\\Program Files\\App\\app.exe".into()],
        domains: vec!["full:www.youtube.com".into(), "keyword:googlevideo".into(), "regex:^yt[0-9]+\\.example\\.com$".into()],
        ips: vec!["203.0.113.7".into(), "2001:db8::/32".into()],
        ports: vec!["443".into(), "50000-50100".into()],
        rule_sets: vec!["geoip-ru".into()],
        network: Some("udp".into()),
        route: Route::Profile { id: "p10".into() },
        preset: None,
    });
    d.rules.push(Rule {
        id: "c2".into(),
        name: "Через WireGuard".into(),
        enabled: true,
        apps: vec!["game.exe".into()],
        route: Route::Profile { id: "p14".into() },
        ..Default::default()
    });
    let names: Vec<String> = {
        let opts = BuildOptions { ruleset_dir: dir.clone(), controller_secret: "x".into(), cache_file: None, extended_available: false, direct_dns_tls: false, wiresock: None };
        build(&d, &opts).unwrap().rule_sets.iter().map(|r| r.file_name.clone()).collect()
    };
    make_rule_sets(&bin, &dir, &names);

    type Variant = (&'static str, Box<dyn Fn(&mut AppData)>);
    let variants: Vec<Variant> = vec![
        ("tun-full", Box::new(|_d: &mut AppData| {})),
        ("tun-selective", Box::new(|d: &mut AppData| d.settings.final_route = Route::Direct)),
        ("tun-block-rest", Box::new(|d: &mut AppData| d.settings.final_route = Route::Block)),
        ("proxy-mode-ipv6", Box::new(|d: &mut AppData| {
            d.settings.mode = InboundMode::SystemProxy;
            d.settings.ipv6 = true;
        })),
        ("dns-variants", Box::new(|d: &mut AppData| {
            d.settings.dns.direct = "https://dns.adguard-dns.com/dns-query".into();
            d.settings.dns.remote = "tls://dns.google".into();
            d.settings.dns.policy = DnsPolicy::Remote;
            d.settings.tun.stack = "gvisor".into();
            d.settings.tun.strict_route = false;
            d.settings.direct_interface = Some("Ethernet".into());
        })),
        ("dns-local", Box::new(|d: &mut AppData| {
            d.settings.dns.direct = "local".into();
            d.settings.final_route = Route::Profile { id: "p14".into() };
        })),
    ];
    for (name, change) in variants {
        let mut d2 = d.clone();
        change(&mut d2);
        let opts = BuildOptions {
            ruleset_dir: dir.clone(),
            controller_secret: "x".into(),
            cache_file: Some(dir.join("cache.db")),
            extended_available: false,
            direct_dns_tls: false,
            wiresock: None,
        };
        let built = build(&d2, &opts).unwrap_or_else(|e| panic!("{name}: {e}"));
        check(&bin, &dir, name, &built.config);
    }
}

#[test]
fn interface_profile_and_wg_conf() {
    let Some(bin) = sing_box() else {
        eprintln!("sing-box not found, skipping");
        return;
    };
    let dir = work_dir("iface");
    let conf = format!(
        "[Interface]\nPrivateKey = {WG_PRIV}\nAddress = 10.8.0.2/32, fd42::2/128\nDNS = 1.1.1.1\nJc = 3\n\n[Peer]\nPublicKey = {WG_PUB}\nPresharedKey = {WG_PUB}\nEndpoint = 192.0.2.10:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
    );
    let wg = wgconf::parse(&conf, "AWG compatible").unwrap();
    let mut d = AppData::default();
    d.profiles.push(Profile::new("wg", wg.profile.name, wg.profile.outbound));
    d.profiles.push(Profile::new("if", "AmneziaVPN", serde_json::json!({"type": "direct", "bind_interface": "AmneziaVPN"})));
    d.settings.active_profile = Some("wg".into());
    d.rules.push(Rule {
        id: "r".into(),
        name: "Телеграм в Амнезию".into(),
        enabled: true,
        apps: vec!["Telegram.exe".into()],
        route: Route::Profile { id: "if".into() },
        ..Default::default()
    });
    let opts = BuildOptions { ruleset_dir: dir.clone(), controller_secret: "x".into(), cache_file: None, extended_available: false, direct_dns_tls: false, wiresock: None };
    check(&bin, &dir, "iface", &build(&d, &opts).unwrap().config);
}

#[test]
fn probe_with_all_protocols() {
    let Some(bin) = sing_box() else {
        eprintln!("sing-box not found, skipping");
        return;
    };
    let dir = work_dir("probe");
    let profiles: Vec<Profile> = all_links().iter().enumerate().map(|(i, l)| profile(&format!("p{i}"), l)).collect();
    let refs: Vec<&Profile> = profiles.iter().collect();
    let cfg = build_probe(&refs, &Settings::default(), 23999, "x", CoreKind::Official).unwrap();
    check(&bin, &dir, "probe", &cfg);
}

fn sing_box_lx() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SING_BOX_LX") {
        return Some(PathBuf::from(p));
    }
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/sing-box-lx/sing-box-1.14.4-lx.32-windows-amd64/sing-box.exe");
    p.exists().then_some(p)
}

/// AmneziaWG 3.1 and XHTTP servers: the full config goes to sing-box-lx and
/// passes its check; without sing-box-lx the build explains what is missing.
#[test]
fn amneziawg_and_xhttp_need_sing_box_lx() {
    let Some(lx) = sing_box_lx() else {
        eprintln!("sing-box-lx not found, skipping");
        return;
    };
    let dir = work_dir("lx");
    let conf = "[Interface]\nPrivateKey = OOrcz46udUCWEuue7YueYT6OGhchZ91v0NqtRu+W2FI=\nAddress = 10.8.1.2/32\nJc = 3\nJmin = 10\nJmax = 40\nS1 = 20\nS2 = 30\nS3 = 16\nS4 = 12\nHeaderProtectionKey = KIKOZNzj+d+G5Gw84nfLm49oM/f+xMoThA4AEOqyZkc=\nRandomTrailers = on\n\n[Peer]\nPublicKey = xqz8eGLSa0P5JHkSTGnKoczKZjmonaUDbbx8bUqRjWw=\nEndpoint = 203.0.113.7:39000\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 22-30\n";
    let awg = wgconf::parse(conf, "AWG 3.1").unwrap().profile;
    let mut d = AppData::default();
    d.profiles.push(Profile::new("awg", awg.name, awg.outbound));
    d.profiles.push(Profile {
        xray: Some(false),
        ..profile("xh", "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=tls&type=xhttp&path=%2Fxh&mode=auto&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#XHTTP")
    });
    d.settings.active_profile = Some("awg".into());
    d.rules.push(Rule { id: "r".into(), name: "curl".into(), enabled: true, apps: vec!["curl.exe".into()], route: Route::Profile { id: "xh".into() }, ..Default::default() });
    let opts = |lx: bool| BuildOptions { ruleset_dir: dir.clone(), controller_secret: "x".into(), cache_file: None, extended_available: lx, direct_dns_tls: false, wiresock: None };
    for mode in [InboundMode::Tun, InboundMode::SystemProxy] {
        d.settings.mode = mode;
        let built = build(&d, &opts(true)).unwrap();
        assert_eq!(built.core, CoreKind::Extended);
        check(&lx, &dir, &format!("lx-{mode:?}"), &built.config);
    }
    let e = build(&d, &opts(false)).unwrap_err();
    assert!(e.0.contains("«AWG 3.1» (AmneziaWG)") && e.0.contains("«XHTTP» (XHTTP)") && e.0.contains("sing-box-lx"), "{}", e.0);
    d.settings.core = retunl_core::awg::CorePref::Official;
    assert!(build(&d, &opts(true)).unwrap_err().0.contains("официальное ядро"));
}

/// WireSock runs only on Windows: elsewhere its server is plain AmneziaWG,
/// which wants sing-box-lx.
#[cfg(windows)]
#[test]
fn wiresock_configs() {
    use retunl_core::singbox::{build_wiresock_helper, WireSockLink};
    let Some(bin) = sing_box() else {
        eprintln!("sing-box not found, skipping");
        return;
    };
    let dir = work_dir("wiresock");
    let conf = format!(
        "[Interface]\nPrivateKey = {WG_PRIV}\nAddress = 10.8.0.2/32\nJc = 3\nS1 = 15\nS2 = 20\nH1 = 11\nH2 = 12\nH3 = 13\nH4 = 14\nId = ozon.ru\nIp = QUIC\n\n[Peer]\nPublicKey = {WG_PUB}\nEndpoint = 192.0.2.10:51820\nAllowedIPs = 0.0.0.0/0\n"
    );
    let wg = wgconf::parse(&conf, "WS").unwrap();
    let mut d = AppData::default();
    d.profiles.push(Profile { wiresock: wg.wiresock, ..Profile::new("ws", wg.profile.name, wg.profile.outbound) });
    d.profiles.push(profile("nl", &format!("vless://id@nl.example.com:443?security=reality&pbk={REALITY_PBK}&sni=www.microsoft.com#NL")));
    d.settings.active_profile = Some("ws".into());
    d.rules.push(Rule { id: "r".into(), name: "Telegram".into(), enabled: true, apps: vec!["Telegram.exe".into()], route: Route::Profile { id: "nl".into() }, ..Default::default() });
    let link = WireSockLink { profile_id: "ws".into(), port: free_port(), username: "u".into(), password: "p".into(), keep_out: vec!["192.0.2.10/32".into()] };
    for (name, mode) in [("wiresock-tun", InboundMode::Tun), ("wiresock-proxy", InboundMode::SystemProxy)] {
        d.settings.mode = mode;
        let opts = BuildOptions { ruleset_dir: dir.clone(), controller_secret: "x".into(), cache_file: None, extended_available: false, direct_dns_tls: false, wiresock: Some(link.clone()) };
        let built = build(&d, &opts).unwrap();
        check(&bin, &dir, name, &built.config);
    }
    // the helper itself, and its DNS through a DoH server by name
    let mut s = Settings::default();
    s.dns.remote = "https://dns.google/dns-query".into();
    check(&bin, &dir, "wiresock-helper", &build_wiresock_helper(&s, &link, None).unwrap());
}
