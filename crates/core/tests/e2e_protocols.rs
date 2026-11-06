//! End-to-end: a local sing-box *server* with one inbound per protocol, a
//! client built from share links by our parser, and real HTTP requests
//! through every protocol (via the same latency probe the app uses).
//! Skips when sing-box is missing.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use retunl_core::links::parse_link;
use retunl_core::model::{Profile, Settings};
use retunl_core::singbox::build_probe;
use serde_json::{json, Value};
use retunl_core::awg::CoreKind;

fn sing_box() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SING_BOX") {
        return Some(PathBuf::from(p));
    }
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe");
    p.exists().then_some(p)
}

fn sing_box_lx() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SING_BOX_LX") {
        return Some(PathBuf::from(p));
    }
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/sing-box-lx/sing-box-1.14.4-lx.32-windows-amd64/sing-box.exe");
    p.exists().then_some(p)
}

fn tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn keypair(bin: &Path, kind: &str) -> (String, String) {
    let out = Command::new(bin).args(["generate", kind]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).unwrap().trim().to_string();
    (get("PrivateKey:"), get("PublicKey:"))
}

struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

fn start(bin: &Path, dir: &Path, name: &str, cfg: &Value) -> Killer {
    let file = dir.join(format!("{name}.json"));
    std::fs::write(&file, serde_json::to_string_pretty(cfg).unwrap()).unwrap();
    let log = std::fs::File::create(dir.join(format!("{name}.log"))).unwrap();
    let child = Command::new(bin)
        .args(["run", "--disable-color", "-c"])
        .arg(&file)
        .arg("-D")
        .arg(dir)
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    Killer(child)
}

fn wait_tcp(port: u16, killer: &mut Killer, dir: &Path, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(st) = killer.0.try_wait().unwrap() {
            let log = std::fs::read_to_string(dir.join(format!("{name}.log"))).unwrap_or_default();
            panic!("{name} exited ({st}):\n{log}");
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{name}: port {port} never opened");
}

fn http_get(port: u16, path: &str, secret: &str) -> (u16, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\n\r\n").unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok();
    let code = buf.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = buf.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    (code, body)
}

/// Address of this machine on the LAN: traffic that leaves a WireGuard
/// tunnel can't reach 127.0.0.1 of the "server".
fn lan_ip() -> String {
    let s = UdpSocket::bind("0.0.0.0:0").unwrap();
    match s.connect("192.0.2.1:9").and_then(|_| s.local_addr()) {
        Ok(a) if !a.ip().is_unspecified() => a.ip().to_string(),
        _ => "127.0.0.1".into(),
    }
}

fn serve_204() -> u16 {
    let l = TcpListener::bind("0.0.0.0:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                c.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let _ = c.read(&mut buf);
                let _ = c.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            });
        }
    });
    port
}

#[test]
fn traffic_flows_through_every_protocol() {
    let Some(bin) = sing_box() else {
        eprintln!("sing-box not found, skipping");
        return;
    };
    let dir = std::env::temp_dir().join(format!("retunl-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // keys and certificate
    let out = Command::new(&bin).args(["generate", "tls-keypair", "test.local"]).output().unwrap();
    let pem = String::from_utf8(out.stdout).unwrap();
    let split = pem.find("-----BEGIN CERTIFICATE-----").expect("certificate in output");
    let (key_pem, cert_pem) = pem.split_at(split);
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, cert_pem).unwrap();
    std::fs::write(&key, key_pem).unwrap();
    let (reality_priv, reality_pub) = keypair(&bin, "reality-keypair");
    let (wg_srv_priv, wg_srv_pub) = keypair(&bin, "wg-keypair");
    let (wg_cli_priv, wg_cli_pub) = keypair(&bin, "wg-keypair");
    let uuid = "75f09ec0-fb90-4fca-a44f-755c91cd4f97";
    let ss_key = "Z2lkazBvL1RQOUYzVnk5NQ=="; // 16 bytes, base64
    let tls = json!({"enabled": true, "server_name": "test.local", "certificate_path": cert, "key_path": key});

    let p = |_: &str| tcp_port();
    let (vless_ws, vmess_grpc, trojan, ss, anytls, socks, reality) =
        (p("vless"), p("vmess"), p("trojan"), p("ss"), p("anytls"), p("socks"), p("reality"));
    let (hy2, hy1, tuic, wg) = (udp_port(), udp_port(), udp_port(), udp_port());

    let server = json!({
        "log": {"level": "warn", "timestamp": true},
        "inbounds": [
            {"type": "vless", "tag": "vless-ws", "listen": "127.0.0.1", "listen_port": vless_ws, "users": [{"uuid": uuid}], "tls": tls, "transport": {"type": "ws", "path": "/ws"}},
            {"type": "vmess", "tag": "vmess-grpc", "listen": "127.0.0.1", "listen_port": vmess_grpc, "users": [{"uuid": uuid, "alterId": 0}], "tls": tls, "transport": {"type": "grpc", "service_name": "svc"}},
            {"type": "trojan", "tag": "trojan", "listen": "127.0.0.1", "listen_port": trojan, "users": [{"password": "pw"}], "tls": tls},
            {"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": ss, "method": "2022-blake3-aes-128-gcm", "password": ss_key},
            {"type": "anytls", "tag": "anytls", "listen": "127.0.0.1", "listen_port": anytls, "users": [{"password": "pw"}], "tls": tls},
            {"type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": socks},
            {"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": hy2, "users": [{"password": "pw"}], "obfs": {"type": "salamander", "password": "ob"}, "tls": tls},
            {"type": "hysteria", "tag": "hy1", "listen": "127.0.0.1", "listen_port": hy1, "up_mbps": 100, "down_mbps": 100, "users": [{"auth_str": "pw"}], "obfs": "xx", "tls": {"enabled": true, "server_name": "test.local", "certificate_path": cert, "key_path": key, "alpn": ["hysteria"]}},
            {"type": "tuic", "tag": "tuic", "listen": "127.0.0.1", "listen_port": tuic, "users": [{"uuid": uuid, "password": "pw"}], "congestion_control": "bbr", "tls": {"enabled": true, "server_name": "test.local", "certificate_path": cert, "key_path": key, "alpn": ["h3"]}},
            {"type": "vless", "tag": "reality", "listen": "127.0.0.1", "listen_port": reality, "users": [{"uuid": uuid, "flow": "xtls-rprx-vision"}],
             "tls": {"enabled": true, "server_name": "test.local", "reality": {"enabled": true, "handshake": {"server": "127.0.0.1", "server_port": trojan}, "private_key": reality_priv, "short_id": ["a1b2c3d4"]}}}
        ],
        "endpoints": [
            {"type": "wireguard", "tag": "wg-srv", "address": ["10.77.0.1/32"], "private_key": wg_srv_priv, "listen_port": wg, "mtu": 1280,
             "peers": [{"public_key": wg_cli_pub, "allowed_ips": ["10.77.0.2/32"]}]}
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}]
    });
    let mut srv = start(&bin, &dir, "server", &server);
    wait_tcp(vless_ws, &mut srv, &dir, "server");

    let enc = |s: &str| s.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D");
    let vmess = json!({"add": "127.0.0.1", "port": vmess_grpc, "id": uuid, "aid": 0, "net": "grpc", "path": "svc", "tls": "tls", "sni": "test.local", "allowInsecure": "1", "ps": "vmess-grpc"});
    let links = vec![
        format!("vless://{uuid}@127.0.0.1:{vless_ws}?security=tls&sni=test.local&allowInsecure=1&type=ws&path=%2Fws#vless-ws"),
        format!("vmess://{}", STANDARD.encode(vmess.to_string())),
        format!("trojan://pw@127.0.0.1:{trojan}?sni=test.local&allowInsecure=1#trojan"),
        format!("ss://2022-blake3-aes-128-gcm:{}@127.0.0.1:{ss}#ss2022", enc(ss_key)),
        format!("anytls://pw@127.0.0.1:{anytls}?sni=test.local&insecure=1#anytls"),
        format!("socks5://127.0.0.1:{socks}#socks"),
        format!("hy2://pw@127.0.0.1:{hy2}?sni=test.local&insecure=1&obfs=salamander&obfs-password=ob#hysteria2"),
        format!("hysteria://127.0.0.1:{hy1}?auth=pw&peer=test.local&insecure=1&upmbps=100&downmbps=100&obfsParam=xx&alpn=hysteria#hysteria1"),
        format!("tuic://{uuid}:pw@127.0.0.1:{tuic}?sni=test.local&allow_insecure=1&congestion_control=bbr&alpn=h3#tuic"),
        format!("vless://{uuid}@127.0.0.1:{reality}?security=reality&sni=test.local&fp=chrome&pbk={reality_pub}&sid=a1b2c3d4&flow=xtls-rprx-vision&type=tcp#reality"),
        // UDP from an interface-bound socket can't go to 127.0.0.1, so WireGuard uses the LAN address
        format!("wireguard://{}@{}:{wg}?publickey={}&address=10.77.0.2%2F32&mtu=1280#wireguard", enc(&wg_cli_priv), lan_ip(), enc(&wg_srv_pub)),
    ];
    let profiles: Vec<Profile> = links
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let p = parse_link(l).unwrap_or_else(|e| panic!("{l}: {e}"));
            Profile { id: format!("p{i}"), name: p.name, outbound: p.outbound, subscription: None, link: None, created_at: 0 }
        })
        .collect();
    let refs: Vec<&Profile> = profiles.iter().collect();
    let api = tcp_port();
    let cfg = build_probe(&refs, &Settings::default(), api, "sec", CoreKind::Official).unwrap();
    let mut cli = start(&bin, &dir, "client", &cfg);
    wait_tcp(api, &mut cli, &dir, "client");

    let target = format!("http://{}:{}/generate_204", lan_ip(), serve_204());
    let mut failed = Vec::new();
    for p in &profiles {
        let mut result = (0, String::new());
        for _attempt in 0..3 {
            result = http_get(api, &format!("/proxies/{}/delay?timeout=5000&url={}", p.id, enc(&target).replace(':', "%3A")), "sec");
            if result.0 == 200 {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        println!("{:<12} {} {}", p.name, result.0, result.1.trim());
        if result.0 != 200 {
            failed.push(format!("{}: {} {}", p.name, result.0, result.1.trim()));
        }
    }
    drop(cli);
    drop(srv);
    if !failed.is_empty() {
        let srv_log = std::fs::read_to_string(dir.join("server.log")).unwrap_or_default();
        let cli_log = std::fs::read_to_string(dir.join("client.log")).unwrap_or_default();
        panic!("no traffic through:\n{}\n--- server log ---\n{srv_log}\n--- client log ---\n{cli_log}", failed.join("\n"));
    }
}

/// AmneziaWG 2.0 and 3.1 servers imported from `.conf` files, run through
/// sing-box-lx: one sing-box-lx plays the AWG server, another the client.
#[test]
fn amneziawg_through_sing_box_lx() {
    let Some(bin) = sing_box_lx() else {
        eprintln!("sing-box-lx not found, skipping");
        return;
    };
    let dir = std::env::temp_dir().join(format!("retunl-e2e-awg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (srv_priv, srv_pub) = keypair(&bin, "wg-keypair");
    let (cli_priv, cli_pub) = keypair(&bin, "wg-keypair");
    let (hpk, _) = keypair(&bin, "wg-keypair");
    let (port2, port3) = (udp_port(), udp_port());

    // the obfuscation as the server has it, and the same in .conf syntax
    let awg2 = json!({"jc": 4, "jmin": 10, "jmax": 50, "s1": 31, "s2": 47, "s3": 22, "s4": 9,
        "h1": "100000-200000", "h2": "300000-400000", "h3": "500000-600000", "h4": "700000-800000",
        "i1": "<b 0xc700000001><r 16><t>"});
    let awg2_conf = "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 31\nS2 = 47\nS3 = 22\nS4 = 9\nH1 = 100000-200000\nH2 = 300000-400000\nH3 = 500000-600000\nH4 = 700000-800000\nI1 = <b 0xc700000001><r 16><t>";
    let awg3 = json!({"jc": 3, "jmin": 10, "jmax": 40, "s1": 20, "s2": 30, "s3": 16, "s4": 12,
        "header_protection_key": hpk, "content_padding_addition": "0-32", "rekey_after_time": "100-120",
        "random_trailers": true, "disable_cookies": true});
    let awg3_conf = format!("Jc = 3\nJmin = 10\nJmax = 40\nS1 = 20\nS2 = 30\nS3 = 16\nS4 = 12\nHeaderProtectionKey = {hpk}\nContentPaddingAddition = 0-32\nRekeyAfterTime = 100-120\nRandomTrailers = on\nDisableCookies = on");

    let endpoint = |tag: &str, addr: &str, port: u16, awg: &Value| {
        let mut e = json!({"type": "wireguard", "tag": tag, "system": false, "mtu": 1280, "address": [format!("{addr}1/32")],
            "private_key": srv_priv, "listen_port": port,
            "peers": [{"public_key": cli_pub, "allowed_ips": [format!("{addr}2/32")]}]});
        e.as_object_mut().unwrap().extend(awg.as_object().unwrap().clone());
        e
    };
    let server = json!({
        "log": {"level": "warn", "timestamp": true},
        "endpoints": [endpoint("awg2", "10.78.0.", port2, &awg2), endpoint("awg3", "10.79.0.", port3, &awg3)],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    });
    let _srv = start(&bin, &dir, "awg-server", &server);

    let conf = |addr: &str, port: u16, extra: &str, keepalive: &str| {
        format!("[Interface]\nPrivateKey = {cli_priv}\nAddress = {addr}2/32\nMTU = 1280\n{extra}\n\n[Peer]\nPublicKey = {srv_pub}\nEndpoint = {}:{port}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = {keepalive}\n", lan_ip())
    };
    let profiles: Vec<Profile> = [
        ("awg-2.0", conf("10.78.0.", port2, awg2_conf, "25")),
        ("awg-3.1", conf("10.79.0.", port3, &awg3_conf, "20-30")),
    ]
    .into_iter()
    .map(|(name, text)| {
        let w = retunl_core::wgconf::parse(&text, name).unwrap();
        assert_eq!(w.profile.outbound["type"], "wireguard");
        Profile { id: name.into(), name: name.into(), outbound: w.profile.outbound, subscription: None, link: None, created_at: 0 }
    })
    .collect();
    for p in &profiles {
        assert_eq!(p.core_need(), retunl_core::awg::CoreNeed::Extended, "{}", p.name);
    }
    let refs: Vec<&Profile> = profiles.iter().collect();
    let api = tcp_port();
    let cfg = build_probe(&refs, &Settings::default(), api, "sec", CoreKind::Extended).unwrap();
    let mut cli = start(&bin, &dir, "awg-client", &cfg);
    wait_tcp(api, &mut cli, &dir, "awg-client");

    let target = format!("http://{}:{}/generate_204", lan_ip(), serve_204());
    let enc = |s: &str| s.replace(':', "%3A").replace('/', "%2F");
    let mut failed = Vec::new();
    for p in &profiles {
        let mut result = (0, String::new());
        for _attempt in 0..3 {
            result = http_get(api, &format!("/proxies/{}/delay?timeout=5000&url={}", p.id, enc(&target)), "sec");
            if result.0 == 200 {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        println!("{:<10} {} {}", p.name, result.0, result.1.trim());
        if result.0 != 200 {
            failed.push(format!("{}: {} {}", p.name, result.0, result.1.trim()));
        }
    }
    drop(cli);
    if !failed.is_empty() {
        let srv_log = std::fs::read_to_string(dir.join("awg-server.log")).unwrap_or_default();
        let cli_log = std::fs::read_to_string(dir.join("awg-client.log")).unwrap_or_default();
        panic!("no traffic through:\n{}\n--- server log ---\n{srv_log}\n--- client log ---\n{cli_log}", failed.join("\n"));
    }
}
