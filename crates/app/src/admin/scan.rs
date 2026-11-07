//! What is installed on a server: AmneziaVPN containers, their settings and
//! clients. Everything is read with one script whose output is split by
//! `@@` marker lines; file contents travel as base64 so they can't clash
//! with the markers.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Serialize;

use super::ssh::{q, Session};
use super::{spec, table, wg, xray, Kind, Spec, SPECS};

#[derive(Serialize, Clone, Debug)]
pub struct Scan {
    pub os: Option<String>,
    pub arch: Option<String>,
    pub docker: bool,
    pub protocols: Vec<Proto>,
    pub at: i64,
}

#[derive(Serialize, Clone, Debug)]
pub struct Proto {
    pub container: String,
    pub kind: Kind,
    pub title: String,
    /// Docker's state: running, exited, restarting …
    pub state: String,
    pub port: Option<u16>,
    pub transport: Option<String>,
    /// A short line about the setup, e.g. the site Reality pretends to be.
    pub detail: Option<String>,
    /// `None` when ReTunl can't manage clients of this protocol.
    pub clients: Option<Vec<Client>>,
    pub problem: Option<String>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Client {
    /// The WireGuard public key or the VLESS id.
    pub id: String,
    pub name: String,
    pub created: Option<String>,
    pub ip: Option<String>,
    /// Unix time of the last handshake (WireGuard only).
    pub handshake: Option<i64>,
    pub rx: u64,
    pub tx: u64,
    /// The VLESS id AmneziaVPN keeps for itself (`xray_uuid.key`).
    pub primary: bool,
}

/// Output split at `@@name args` lines: (name args) → the lines after it.
pub fn sections(out: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut cur: Option<String> = None;
    let mut body = String::new();
    for line in out.lines() {
        if let Some(head) = line.strip_prefix("@@") {
            if let Some(k) = cur.take() {
                map.insert(k, std::mem::take(&mut body));
            }
            cur = Some(head.trim().to_string());
            continue;
        }
        if cur.is_some() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(k) = cur {
        map.insert(k, body);
    }
    map
}

/// A base64 section back to text.
pub fn unb64(s: Option<&String>) -> Option<String> {
    let t = s?.trim();
    if t.is_empty() {
        return None;
    }
    B64.decode(t).ok().map(|b| String::from_utf8_lossy(&b).into_owned()).filter(|s| !s.is_empty())
}

/// Shell lines printing a file from a container as `@@file <container> <path>` + base64.
pub fn file_cmd(container: &str, path: &str) -> String {
    format!("echo {}; docker exec -i {} cat {} 2>/dev/null | base64 | tr -d '\\n'; echo\n", q(&format!("@@file {container} {path}")), q(container), q(path))
}

pub fn file_key(container: &str, path: &str) -> String {
    format!("file {container} {path}")
}

/// From this Xray version on, a Reality server wants an X25519MLKEM768 key
/// share, and sing-box (so ReTunl itself) can no longer connect.
const REALITY_NEEDS_MLKEM: (u32, u32, u32) = (26, 9, 8);

/// `Xray 26.3.27 (Xray, Penetrates Everything.) …` → (26, 3, 27).
fn xray_version(line: &str) -> Option<(u32, u32, u32)> {
    let v = line.split_whitespace().skip_while(|w| !w.eq_ignore_ascii_case("xray")).nth(1)?;
    let mut n = v.trim_start_matches('v').split('.').map(|x| x.parse::<u32>().ok());
    Some((n.next()??, n.next()??, n.next().flatten().unwrap_or(0)))
}

pub fn table_path(s: &Spec) -> String {
    format!("{}/clientsTable", s.dir)
}

fn script() -> String {
    let mut s = String::from(
        "export LC_ALL=C\n\
         echo @@os; ( . /etc/os-release 2>/dev/null; echo \"${PRETTY_NAME:-$(uname -sr)}\" )\n\
         echo @@arch; uname -m\n\
         if ! command -v docker >/dev/null 2>&1; then echo @@nodocker; exit 0; fi\n\
         echo @@ps; docker ps -a --filter name=amnezia --format '{{.Names}}|{{.State}}|{{.Ports}}' 2>&1\n\
         up() { [ \"$(docker inspect -f '{{.State.Running}}' \"$1\" 2>/dev/null)\" = true ]; }\n",
    );
    for sp in SPECS {
        let c = sp.container;
        s.push_str(&format!("if up {}; then\n", q(c)));
        s.push_str(&file_cmd(c, sp.conf));
        s.push_str(&file_cmd(c, &table_path(sp)));
        match sp.kind {
            Kind::Xray => {
                s.push_str(&file_cmd(c, &format!("{}/xray_uuid.key", sp.dir)));
                s.push_str(&format!("echo @@xrayver; docker exec -i {} xray version 2>/dev/null | head -1\n", q(c)));
            }
            _ => s.push_str(&format!(
                "echo {}; docker exec -i {c} {} show {} dump 2>/dev/null | base64 | tr -d '\\n'; echo\n",
                q(&format!("@@dump {c}")),
                sp.tool,
                sp.iface
            )),
        }
        s.push_str("fi\n");
    }
    s
}

pub async fn run(ssh: &Session, host: &str) -> Result<Scan, String> {
    let out = ssh.run(&script()).await?;
    let sec = sections(&out.out);
    let line = |k: &str| sec.get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let mut scan = Scan { os: line("os"), arch: line("arch"), docker: !sec.contains_key("nodocker"), protocols: Vec::new(), at: retunl_core::util::now_unix() };
    if !scan.docker {
        return Ok(scan);
    }
    let ps = sec.get("ps").cloned().unwrap_or_default();
    if ps.contains("Cannot connect to the Docker daemon") || ps.contains("permission denied") {
        return Err(format!("Docker на сервере не отвечает: {}", ps.trim()));
    }
    for row in ps.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = row.splitn(3, '|');
        let name = parts.next().unwrap_or("").trim().to_string();
        if !name.starts_with("amnezia") {
            continue;
        }
        let state = parts.next().unwrap_or("").trim().to_string();
        let (port, transport) = published(parts.next().unwrap_or(""));
        let mut p = Proto {
            title: spec(&name).map(|s| s.title.to_string()).unwrap_or_else(|| other_title(&name)),
            kind: spec(&name).map(|s| s.kind).unwrap_or(Kind::Other),
            container: name,
            state,
            port,
            transport,
            detail: None,
            clients: None,
            problem: None,
        };
        if let Some(sp) = spec(&p.container) {
            if p.state == "running" {
                if let Err(e) = read_clients(sp, &sec, &mut p, host) {
                    p.problem = Some(e);
                }
            } else {
                p.problem = Some("контейнер не запущен".into());
            }
        }
        scan.protocols.push(p);
    }
    let order = |p: &Proto| SPECS.iter().position(|s| s.container == p.container).unwrap_or(SPECS.len());
    scan.protocols.sort_by_key(order);
    Ok(scan)
}

fn read_clients(sp: &Spec, sec: &HashMap<String, String>, p: &mut Proto, _host: &str) -> Result<(), String> {
    let conf = unb64(sec.get(&file_key(sp.container, sp.conf))).ok_or("не удалось прочитать настройки сервера")?;
    let names = unb64(sec.get(&file_key(sp.container, &table_path(sp)))).map(|t| table::read(&t)).unwrap_or_default();
    let mut clients = Vec::new();
    match sp.kind {
        Kind::Xray => {
            let ib = xray::parse_server(&conf)?;
            let primary = unb64(sec.get(&file_key(sp.container, &format!("{}/xray_uuid.key", sp.dir)))).map(|s| s.trim().to_string());
            p.port = p.port.or(Some(ib.port));
            p.detail = Some(match (ib.security.as_str(), &ib.sni) {
                ("reality", Some(sni)) => format!("Reality, маскировка под {sni}"),
                ("reality", None) => "Reality".into(),
                ("tls", _) => "TLS".into(),
                (s, _) => s.to_string(),
            });
            if !matches!(ib.network.as_str(), "raw" | "tcp") {
                p.detail = Some(format!("{}, транспорт {}", p.detail.take().unwrap_or_default(), ib.network));
            }
            if let Some(v) = sec.get("xrayver").and_then(|l| xray_version(l)) {
                p.detail = Some(format!("{}, Xray {}.{}.{}", p.detail.take().unwrap_or_default(), v.0, v.1, v.2));
                if ib.security == "reality" && v >= REALITY_NEEDS_MLKEM {
                    p.problem = Some(format!(
                        "Xray {}.{}.{} принимает Reality только с постквантовым обменом ключами, которого нет в sing-box. Поэтому ReTunl через этот протокол не подключится, а AmneziaVPN, v2rayNG и другие клиенты на Xray подключатся. Протокол, поставленный ReTunl, работает со всеми.",
                        v.0, v.1, v.2
                    ));
                }
            }
            for (i, id) in ib.clients.iter().enumerate() {
                let e = names.get(id);
                let is_primary = primary.as_deref() == Some(id.as_str());
                clients.push(Client {
                    id: id.clone(),
                    name: e.map(|e| e.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| {
                        if is_primary { "Основной ключ сервера".into() } else { format!("Клиент {}", i + 1) }
                    }),
                    created: e.and_then(|e| e.created.clone()),
                    primary: is_primary,
                    ..Default::default()
                });
            }
        }
        _ => {
            let c = wg::parse(&conf);
            let stats = unb64(sec.get(&format!("dump {}", sp.container))).map(|d| wg::parse_dump(&d)).unwrap_or_default();
            p.port = p.port.or(c.listen_port());
            if sp.kind != Kind::WireGuard {
                p.detail = c.get("HeaderProtectionKey").map(|_| "AmneziaWG 2 с защитой заголовков".to_string()).or_else(|| {
                    c.get("Jc").map(|_| "маскировка мусорными пакетами".to_string())
                });
            }
            for (i, peer) in c.peers.iter().enumerate() {
                let e = names.get(&peer.public_key);
                let st = stats.get(&peer.public_key);
                clients.push(Client {
                    id: peer.public_key.clone(),
                    name: e.map(|e| e.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| format!("Клиент {}", i + 1)),
                    created: e.and_then(|e| e.created.clone()),
                    ip: peer.ip.map(|ip| ip.to_string()),
                    handshake: st.and_then(|s| s.handshake),
                    rx: st.map_or(0, |s| s.rx),
                    tx: st.map_or(0, |s| s.tx),
                    primary: false,
                });
            }
        }
    }
    p.clients = Some(clients);
    Ok(())
}

/// `0.0.0.0:39000->39000/udp, [::]:39000->39000/udp` → (39000, "udp")
fn published(ports: &str) -> (Option<u16>, Option<String>) {
    for m in ports.split(',') {
        let Some((outside, inside)) = m.trim().split_once("->") else { continue };
        let port = outside.rsplit(':').next().and_then(|p| p.parse().ok());
        let proto = inside.split('/').nth(1).map(|s| s.trim().to_string());
        if port.is_some() {
            return (port, proto);
        }
    }
    (None, None)
}

fn other_title(name: &str) -> String {
    match name {
        "amnezia-openvpn" => "OpenVPN",
        "amnezia-shadowsocks" => "OpenVPN поверх Shadowsocks",
        "amnezia-openvpn-cloak" => "OpenVPN поверх Cloak",
        "amnezia-ipsec" => "IPsec / IKEv2",
        "amnezia-dns" => "AmneziaDNS",
        "amnezia-sftp" => "Файлы по SFTP",
        "amnezia-tor" => "Сайт в Tor",
        "amnezia-socks5proxy" => "SOCKS5-прокси",
        "amnezia-ssxray" => "Shadowsocks (Xray)",
        "amnezia-mtproxy" | "amnezia-telemt" => "Прокси для Telegram",
        _ => return name.to_string(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_sections() {
        let s = sections("noise\n@@os\nUbuntu 24.04 LTS\n@@ps\na|running|x\nb|exited|\n@@file c /p\nSGk=\n");
        assert_eq!(s["os"].trim(), "Ubuntu 24.04 LTS");
        assert_eq!(s["ps"].lines().count(), 2);
        assert_eq!(unb64(s.get("file c /p")).as_deref(), Some("Hi"));
        assert_eq!(unb64(None), None);
    }

    #[test]
    fn xray_versions() {
        let v = xray_version("Xray 26.10.21 (Xray, Penetrates Everything.) 1b1647c (go1.27.3 linux/amd64)").unwrap();
        assert_eq!(v, (26, 10, 21));
        assert!(v >= REALITY_NEEDS_MLKEM);
        assert!(xray_version("Xray 26.3.27 (Xray, Penetrates Everything.)").unwrap() < REALITY_NEEDS_MLKEM);
        assert!(xray_version("Xray 1.8.24 (Xray, Penetrates Everything.)").unwrap() < REALITY_NEEDS_MLKEM);
        assert_eq!(xray_version(""), None);
        assert_eq!(xray_version("sh: xray: not found"), None);
    }

    #[test]
    fn ports() {
        assert_eq!(published("0.0.0.0:39000->39000/udp, [::]:39000->39000/udp"), (Some(39000), Some("udp".into())));
        assert_eq!(published(":::443->443/tcp"), (Some(443), Some("tcp".into())));
        assert_eq!(published(""), (None, None));
    }

    #[test]
    fn reads_awg_clients() {
        let sp = spec("amnezia-awg2").unwrap();
        let conf = "[Interface]\nAddress = 10.8.1.0/24\nListenPort = 39000\nJc = 4\nHeaderProtectionKey = k\n\n[Peer]\nPublicKey = AAA=\nAllowedIPs = 10.8.1.1/32\n\n[Peer]\nPublicKey = BBB=\nAllowedIPs = 10.8.1.2/32\n";
        let tbl = r#"[{"clientId":"AAA=","userData":{"clientName":"Phone"}}]"#;
        let mut sec = HashMap::new();
        sec.insert(file_key(sp.container, sp.conf), B64.encode(conf));
        sec.insert(file_key(sp.container, &table_path(sp)), B64.encode(tbl));
        sec.insert("dump amnezia-awg2".into(), B64.encode("i\tj\t1\toff\nAAA=\tp\te\t10.8.1.1/32\t1700000000\t5\t6\t25\n"));
        let mut p = Proto { container: sp.container.into(), kind: sp.kind, title: "".into(), state: "running".into(), port: None, transport: None, detail: None, clients: None, problem: None };
        read_clients(sp, &sec, &mut p, "h").unwrap();
        let c = p.clients.unwrap();
        assert_eq!((c[0].name.as_str(), c[0].handshake, c[0].rx), ("Phone", Some(1700000000), 5));
        assert_eq!((c[1].name.as_str(), c[1].ip.as_deref()), ("Клиент 2", Some("10.8.1.2")));
        assert_eq!(p.port, Some(39000));
    }
}
