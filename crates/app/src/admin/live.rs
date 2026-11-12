//! A check against a real server, skipped unless asked for:
//!
//! ```text
//! RETUNL_LIVE_HOST=203.0.113.10 RETUNL_LIVE_KEY=C:\Users\me\.ssh\id_ed25519 \
//!   cargo test -p retunl live_server -- --ignored --nocapture
//! ```
//!
//! Logs in, installs AmneziaWG, VLESS Reality and WireGuard where missing,
//! makes a client on each, sends traffic through it with a local sing-box
//! (a proxy on 127.0.0.1 only, nothing on this computer's routes changes),
//! then renames and removes the test clients. Installed protocols stay.
//! Optional: RETUNL_LIVE_USER, RETUNL_LIVE_PORT, RETUNL_LIVE_AWG_PORT, and
//! RETUNL_LIVE_REINSTALL=amnezia-xray,… to remove those protocols and install
//! them again (an Xray too new for sing-box is always reinstalled).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use retunl_core::awg::{core_need, CoreKind, CoreNeed};
use retunl_core::links::{parse_link, ParsedLink};
use retunl_core::model::{Profile, Settings};
use retunl_core::singbox::build_probe;
use retunl_core::wgconf;
use serde_json::json;

use super::*;

const NAME: &str = "retunl-live";

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

fn core(extended: bool) -> PathBuf {
    let tools = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.tools");
    if extended {
        tools.join("sing-box-lx/sing-box-1.14.4-lx.32-windows-amd64/sing-box.exe")
    } else {
        tools.join("sing-box/sing-box-1.14.4-windows-amd64/sing-box.exe")
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn profile(key: &ClientKey) -> Profile {
    let l: ParsedLink = if wgconf::looks_like_wg_conf(&key.text) {
        wgconf::parse(&key.text, &key.name).expect("the .conf parses").profile
    } else {
        parse_link(&key.text).expect("the link parses")
    };
    Profile::new("live", l.name, l.outbound)
}

/// This computer's public address as the internet sees it through `key`.
async fn exit_ip(key: &ClientKey, dir: &Path) -> String {
    let p = profile(key);
    let extended = core_need(&p.outbound) != CoreNeed::Any;
    let bin = core(extended);
    assert!(bin.exists(), "no sing-box at {}", bin.display());
    let (api, mixed) = (free_port(), free_port());
    let mut cfg = build_probe(&[&p], &Settings::default(), api, "s", if extended { CoreKind::Extended } else { CoreKind::Official }).unwrap();
    cfg["inbounds"] = json!([{ "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": mixed }]);
    cfg["route"]["final"] = json!("live");
    let file = dir.join(format!("{:?}.json", key.kind));
    let log = dir.join(format!("{:?}.log", key.kind));
    std::fs::write(&file, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
    let mut child = Killer(
        Command::new(&bin)
            .args(["run", "--disable-color", "-c"])
            .arg(&file)
            .arg("-D")
            .arg(dir)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", mixed)).is_ok() {
            break;
        }
        if let Some(st) = child.0.try_wait().unwrap() {
            panic!("sing-box exited ({st}):\n{}", std::fs::read_to_string(&log).unwrap_or_default());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{mixed}")).unwrap())
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    let mut last = String::new();
    for _ in 0..6 {
        match http.get("https://api.ipify.org").send().await {
            Ok(r) => return r.text().await.unwrap().trim().to_string(),
            Err(e) => last = format!("{e:?}"),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    drop(child);
    panic!("no traffic through {:?}: {last}\n{}", key.kind, std::fs::read_to_string(&log).unwrap_or_default());
}

fn proto<'a>(v: &'a ServerView, container: &str) -> Option<&'a scan::Proto> {
    v.scan.as_ref()?.protocols.iter().find(|p| p.container == container)
}

fn client<'a>(v: &'a ServerView, container: &str, name: &str) -> Option<&'a scan::Client> {
    proto(v, container)?.clients.as_ref()?.iter().find(|c| c.name == name)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a real server: RETUNL_LIVE_HOST and RETUNL_LIVE_KEY"]
async fn live_server() {
    let (Some(host), Some(key)) = (env("RETUNL_LIVE_HOST"), env("RETUNL_LIVE_KEY")) else {
        panic!("set RETUNL_LIVE_HOST and RETUNL_LIVE_KEY");
    };
    let dir = std::env::temp_dir().join(format!("retunl-live-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let admin = Admin::new(dir.join("servers.json"));
    let v = admin
        .add(AddForm {
            name: Some("live".into()),
            host: host.clone(),
            port: env("RETUNL_LIVE_PORT").and_then(|p| p.parse().ok()),
            user: env("RETUNL_LIVE_USER"),
            password: None,
            key_path: Some(key),
            passphrase: None,
        })
        .await
        .expect("log in");
    let id = v.id.clone();
    let sc = v.scan.as_ref().unwrap_or_else(|| panic!("scan failed: {:?}", v.error));
    println!("server: {:?} {:?}, docker: {}, key {:?}", sc.os, sc.arch, sc.docker, v.host_key);
    for p in &sc.protocols {
        println!("  found {} ({}) {} port {:?}, {} clients", p.title, p.container, p.state, p.port, p.clients.as_ref().map_or(0, Vec::len));
    }

    let awg_port = env("RETUNL_LIVE_AWG_PORT").and_then(|p| p.parse().ok()).unwrap_or_else(|| {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
        30000 + (n % 30000) as u16
    });
    let progress = |p: Progress| println!("    [{}] {} {}", p.step, p.state, p.detail.unwrap_or_default());
    for (kind, container, port) in [(Kind::Awg, "amnezia-awg2", awg_port), (Kind::Xray, "amnezia-xray", 443), (Kind::WireGuard, "amnezia-wireguard", 51820)] {
        println!("== {container}");
        let mut v = admin.scan(&id).await.expect("scan");
        let again = env("RETUNL_LIVE_REINSTALL").is_some_and(|r| r.split(',').any(|c| c.trim() == container));
        let broken = proto(&v, container).and_then(|p| p.problem.clone()).filter(|p| p.contains("sing-box"));
        if proto(&v, container).is_some() && (again || broken.is_some()) {
            println!("  removing it first: {}", broken.as_deref().unwrap_or("asked to reinstall"));
            v = admin.remove_protocol(&id, container).await.expect("remove the protocol");
            assert!(proto(&v, container).is_none(), "the protocol is gone");
        }
        if let Some(old) = client(&v, container, NAME) {
            // left over from an interrupted run
            admin.client_remove(&id, container, &old.id.clone()).await.expect("remove the old test client");
        }
        let started = std::time::Instant::now();
        let (v, key) = if proto(&v, container).is_some() {
            let (v, k) = admin.client_add(&id, container, NAME).await.expect("add a client");
            (v, k)
        } else {
            let (v, k) = admin.install(&id, Plan { kind, port, site: String::new() }, Some(NAME.into()), &progress).await.expect("install");
            (v, k.expect("first client"))
        };
        println!("  ready in {:.0?}; client file {:?}, once {}, qr {}", started.elapsed(), key.file_name, key.once, key.qr.is_some());
        let p = proto(&v, container).expect("the protocol is there");
        assert_eq!(p.state, "running");
        let c = client(&v, container, NAME).expect("the client is listed").clone();

        let ip = exit_ip(&key, &dir).await;
        println!("  exit address through it: {ip}");
        if host.parse::<std::net::IpAddr>().is_ok() {
            assert_eq!(ip, host, "traffic leaves through the server");
        }

        let v = admin.scan(&id).await.expect("scan");
        let seen = client(&v, container, NAME).unwrap();
        if kind != Kind::Xray {
            assert!(seen.handshake.is_some(), "the server saw the handshake");
            println!("  server sees: handshake {:?}, rx {} tx {}", seen.handshake, seen.rx, seen.tx);
        } else {
            let again = admin.client_key(&id, container, &c.id).await.expect("show the key again");
            assert_eq!(parse_link(&again.text).unwrap().outbound, parse_link(&key.text).unwrap().outbound);
        }

        let v = admin.client_rename(&id, container, &c.id, "retunl-live-2").await.expect("rename");
        assert!(client(&v, container, "retunl-live-2").is_some());
        let v = admin.client_remove(&id, container, &c.id).await.expect("remove");
        let left = proto(&v, container).unwrap().clients.as_ref().unwrap();
        assert!(left.iter().all(|x| x.id != c.id), "the client is gone");
        println!("  renamed and removed; {} clients left", left.len());
    }
    admin.forget(&id).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
