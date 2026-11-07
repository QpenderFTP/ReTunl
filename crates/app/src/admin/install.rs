//! Installing a protocol from scratch, in the layout AmneziaVPN uses (same
//! container names, files and network), so AmneziaVPN can manage the result
//! and the other way round. Keys are made here, not on the server.

use std::time::Duration;

use rand_core::{OsRng, RngCore};
use serde::Serialize;

use super::scan::sections;
use super::ssh::{q, Out, Session};
use super::{put_file_cmd, spec, wg, xray, Kind};

/// Pinned Xray release and the SHA-256 of its Linux archives.
///
/// Not newer: since 26.9.8 a Reality server needs an X25519MLKEM768 key
/// share, which sing-box 1.14 does not send, so ReTunl itself could not
/// connect (SagerNet/sing-box#4520). Move up once sing-box can.
const XRAY_VERSION: &str = "v26.3.27";
const XRAY_SHA_AMD64: &str = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae";
const XRAY_SHA_ARM64: &str = "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c";

const DNS_NET: &str = "docker network inspect amnezia-dns-net >/dev/null 2>&1 || docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net";

#[derive(Serialize, Clone, Debug)]
pub struct Progress {
    pub server: String,
    /// connect, check, docker, build, start, client
    pub step: &'static str,
    /// run, done, skip
    pub state: &'static str,
    pub detail: Option<String>,
}

pub struct Plan {
    pub kind: Kind,
    pub port: u16,
    /// The site VLESS Reality pretends to be.
    pub site: String,
}

pub fn container_of(kind: Kind) -> Result<&'static str, String> {
    Ok(match kind {
        Kind::Awg => "amnezia-awg2",
        Kind::Xray => "amnezia-xray",
        Kind::WireGuard => "amnezia-wireguard",
        _ => return Err("этот протокол ReTunl не устанавливает".into()),
    })
}

fn transport(kind: Kind) -> &'static str {
    if kind == Kind::Xray {
        "tcp"
    } else {
        "udp"
    }
}

fn fail(step: &str, out: &Out) -> String {
    let tail = out.tail(12);
    if tail.is_empty() {
        format!("{step} (код {})", out.code)
    } else {
        format!("{step}:\n{tail}")
    }
}

/// Install `plan` on the server. `progress` gets every step.
pub async fn run(ssh: &Session, server: &str, plan: &Plan, progress: &(dyn Fn(Progress) + Send + Sync)) -> Result<(), String> {
    let name = container_of(plan.kind)?;
    let step = |step: &'static str, state: &'static str, detail: Option<String>| {
        progress(Progress { server: server.to_string(), step, state, detail })
    };

    step("check", "run", None);
    let proto = transport(plan.kind);
    let check = format!(
        "export LC_ALL=C\n\
         echo @@arch; uname -m\n\
         echo @@docker; command -v docker >/dev/null 2>&1 && echo yes\n\
         echo @@exists; docker ps -a --format '{{{{.Names}}}}' 2>/dev/null | grep -qx {name} && echo yes\n\
         echo @@port; ss -Hln{flag} 'sport = :{port}' 2>/dev/null | head -2; docker ps --format '{{{{.Names}}}} {{{{.Ports}}}}' 2>/dev/null | grep -E ':{port}->[0-9]+/{proto}' | head -2\n\
         echo @@wg; modprobe wireguard 2>/dev/null; [ -d /sys/module/wireguard ] && echo yes\n\
         echo @@pm; for m in apt-get dnf yum; do command -v $m >/dev/null 2>&1 && {{ echo $m; break; }}; done\n",
        name = q(name),
        flag = if proto == "udp" { "u" } else { "t" },
        port = plan.port,
    );
    let out = ssh.run(&check).await?;
    let sec = sections(&out.out);
    let has = |k: &str| sec.get(k).is_some_and(|s| s.trim() == "yes");
    let arch = sec.get("arch").map(|s| s.trim().to_string()).unwrap_or_default();
    if has("exists") {
        return Err(format!("{} уже установлен на этом сервере", spec(name).map_or(name, |s| s.title)));
    }
    let busy = sec.get("port").map(|s| s.trim().to_string()).unwrap_or_default();
    if !busy.is_empty() {
        return Err(format!("Порт {}/{proto} на сервере уже занят:\n{busy}\nВыберите другой порт.", plan.port));
    }
    if plan.kind == Kind::Xray && !matches!(arch.as_str(), "x86_64" | "aarch64") {
        return Err(format!("Xray для процессора {arch} ReTunl не ставит"));
    }
    if plan.kind == Kind::WireGuard && !has("wg") {
        return Err("Ядро системы на сервере не поддерживает WireGuard. Поставьте AmneziaWG — ему модуль ядра не нужен.".into());
    }
    step("check", "done", Some(arch.clone()));

    if has("docker") {
        step("docker", "skip", None);
    } else {
        step("docker", "run", None);
        let pm = sec.get("pm").map(|s| s.trim().to_string()).unwrap_or_default();
        if pm.is_empty() {
            return Err("Не нашёл apt, dnf или yum: поставьте Docker на сервер вручную и повторите".into());
        }
        let out = ssh.run_with(&docker_script(), Duration::from_secs(900), &mut |l| step("docker", "run", Some(l.to_string()))).await?;
        if out.out.contains("@@podman") {
            return Err("Вместо Docker на сервере Podman — с ним контейнеры AmneziaVPN не работают".into());
        }
        if !out.ok() {
            return Err(fail("Не удалось поставить Docker", &out));
        }
        step("docker", "done", None);
    }

    step("build", "run", None);
    let dir = format!("/opt/amnezia/{name}");
    let build = format!(
        "set -e\nmkdir -p {d}\n{put}\n{DNS_NET}\ndocker build --pull -t {n} {d} 2>&1\n",
        d = q(&dir),
        n = q(name),
        put = put_host_file(&format!("{dir}/Dockerfile"), &dockerfile(plan.kind)),
    );
    let out = ssh.run_with(&build, Duration::from_secs(1200), &mut |l| step("build", "run", Some(l.to_string()))).await?;
    if !out.ok() {
        let mut e = fail("Не удалось собрать контейнер", &out);
        if out.out.contains("pull rate limit") {
            e = "Docker Hub ограничил скачивание образов с этого сервера. Подождите несколько часов и повторите.".into();
        }
        return Err(e);
    }
    step("build", "done", None);

    step("start", "run", None);
    let start = start_script(plan)?;
    let out = ssh.run_with(&start, Duration::from_secs(180), &mut |_| {}).await?;
    if !out.ok() {
        let e = fail("Контейнер не запустился", &out);
        let _ = ssh.run(&remove_script(name, true)).await;
        return Err(e);
    }
    step("start", "done", None);
    Ok(())
}

fn docker_script() -> String {
    "set -e\n\
     export DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l LC_ALL=C\n\
     if command -v apt-get >/dev/null 2>&1; then\n\
       apt-get -o DPkg::Lock::Timeout=300 update -q\n\
       apt-get -o DPkg::Lock::Timeout=300 install -y -q docker.io\n\
     elif command -v dnf >/dev/null 2>&1; then dnf install -y -q docker\n\
     else yum install -y -q docker\n\
     fi\n\
     if docker --version 2>&1 | grep -qi podman; then echo @@podman; exit 4; fi\n\
     systemctl enable --now docker\n\
     docker info >/dev/null\n\
     docker --version\n"
        .to_string()
}

/// Write a file on the host from base64, so its content never meets the shell.
fn put_host_file(path: &str, content: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(content);
    format!("printf '%s' {} | base64 -d > {}", q(&b64), q(path))
}

fn dockerfile(kind: Kind) -> String {
    let head = "# Built by ReTunl in the layout AmneziaVPN uses.\n";
    let tail = "RUN mkdir -p /opt/amnezia && printf '#!/bin/sh\\ntail -f /dev/null\\n' > /opt/amnezia/start.sh && chmod +x /opt/amnezia/start.sh\n\
                ENTRYPOINT [\"dumb-init\", \"/opt/amnezia/start.sh\"]\n";
    match kind {
        Kind::Awg => format!("{head}FROM amneziavpn/amneziawg-go:latest\nRUN apk add --no-cache bash dumb-init iptables\n{tail}"),
        Kind::WireGuard => format!("{head}FROM alpine:3.22\nRUN apk add --no-cache bash dumb-init iptables wireguard-tools\n{tail}"),
        _ => format!(
            "{head}FROM alpine:3.22\n\
             ARG XRAY_VERSION={XRAY_VERSION}\n\
             RUN apk add --no-cache bash curl unzip dumb-init && \\\n\
             \x20   case \"$(uname -m)\" in \\\n\
             \x20     x86_64) a=64; h={XRAY_SHA_AMD64} ;; \\\n\
             \x20     aarch64) a=arm64-v8a; h={XRAY_SHA_ARM64} ;; \\\n\
             \x20     *) echo \"unsupported CPU $(uname -m)\"; exit 1 ;; \\\n\
             \x20   esac && \\\n\
             \x20   curl -fsSL -o /tmp/xray.zip \"https://github.com/XTLS/Xray-core/releases/download/${{XRAY_VERSION}}/Xray-linux-$a.zip\" && \\\n\
             \x20   echo \"$h  /tmp/xray.zip\" | sha256sum -c - && \\\n\
             \x20   unzip -o /tmp/xray.zip xray -d /usr/bin && chmod +x /usr/bin/xray && rm /tmp/xray.zip\n\
             RUN mkdir -p /opt/amnezia/xray\n{tail}"
        ),
    }
}

/// Runs inside the container every time it starts.
fn start_sh(kind: Kind) -> String {
    let head = "#!/bin/bash\n# Written by ReTunl. Runs every time the container starts.\n";
    let wg = |tool: &str, conf: &str, iface: &str| {
        format!(
            "{head}CONF={conf}\nSUBNET=10.8.1.0/24\n\
             {tool}-quick down $CONF 2>/dev/null\n\
             [ -f $CONF ] && {tool}-quick up $CONF\n\
             add() {{ iptables -C \"$@\" 2>/dev/null || iptables -A \"$@\"; }}\n\
             add INPUT -i {iface} -j ACCEPT\n\
             add FORWARD -i {iface} -j ACCEPT\n\
             add OUTPUT -o {iface} -j ACCEPT\n\
             add FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n\
             for o in eth0 eth1; do iptables -t nat -C POSTROUTING -s $SUBNET -o $o -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $SUBNET -o $o -j MASQUERADE; done\n\
             exec tail -f /dev/null\n"
        )
    };
    match kind {
        Kind::Awg => wg("awg", "/opt/amnezia/awg/awg0.conf", "awg0"),
        Kind::WireGuard => wg("wg", "/opt/amnezia/wireguard/wg0.conf", "wg0"),
        _ => format!(
            "{head}while true; do\n  [ -f /opt/amnezia/xray/server.json ] && xray run -config /opt/amnezia/xray/server.json\n  sleep 3\ndone\n"
        ),
    }
}

/// The AmneziaWG settings AmneziaVPN gives a new server (protocol 3.1).
pub fn awg_server_conf(private_key: &str, port: u16) -> String {
    let jc = 4 + OsRng.next_u32() % 3;
    format!(
        "[Interface]\nPrivateKey = {private_key}\nAddress = 10.8.1.0/24\nListenPort = {port}\n\
         Jc = {jc}\nJmin = 10\nJmax = 50\nS1 = 12\nS2 = 12\nS3 = 12\nS4 = 12\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n\
         HeaderProtectionKey = {}\nRekeyAfterTime = 100-120\nRekeyTimeout = 3-7\nRejectAfterTime = 150-180\n\
         KeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\nRandomTrailers = on\nDisableCookies = on\n",
        wg::keypair().0
    )
}

fn start_script(plan: &Plan) -> Result<String, String> {
    let name = container_of(plan.kind)?;
    let sp = spec(name).ok_or("нет описания контейнера")?;
    let n = q(name);
    let port = plan.port;
    let mut files: Vec<(String, String)> = Vec::new();
    let run = match plan.kind {
        Kind::Awg | Kind::WireGuard => {
            let (private, public) = wg::keypair();
            let conf = if plan.kind == Kind::Awg {
                awg_server_conf(&private, port)
            } else {
                format!("[Interface]\nPrivateKey = {private}\nAddress = 10.8.1.0/24\nListenPort = {port}\n")
            };
            files.push((sp.conf.to_string(), conf));
            files.push((format!("{}/wireguard_server_private_key.key", sp.dir), format!("{private}\n")));
            files.push((format!("{}/wireguard_server_public_key.key", sp.dir), format!("{public}\n")));
            files.push((format!("{}/wireguard_psk.key", sp.dir), format!("{}\n", wg::random_key())));
            format!(
                "docker run -d --log-driver none --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE \
                 -p {port}:{port}/udp -v /lib/modules:/lib/modules --sysctl net.ipv4.conf.all.src_valid_mark=1 --name {n} {n}"
            )
        }
        _ => {
            let (private, public) = xray::reality_keypair();
            let first = uuid::Uuid::new_v4().to_string();
            let sid = xray::short_id();
            let site = plan.site.trim();
            let site = if site.is_empty() { xray::DEFAULT_SITE } else { site };
            if site.contains(['/', ' ', ':', '\'', '"']) {
                return Err("Сайт для маскировки — это только имя, например www.microsoft.com".into());
            }
            files.push((sp.conf.to_string(), xray::server_json(port, &first, &private, &sid, site)));
            files.push((format!("{}/xray_uuid.key", sp.dir), format!("{first}\n")));
            files.push((format!("{}/xray_short_id.key", sp.dir), format!("{sid}\n")));
            files.push((format!("{}/xray_private.key", sp.dir), format!("{private}\n")));
            files.push((format!("{}/xray_public.key", sp.dir), format!("{public}\n")));
            format!(
                "docker volume rm {v} >/dev/null 2>&1 || true\n\
                 docker run -d --log-driver none --restart always --cap-add=NET_ADMIN -p {port}:{port}/tcp -v {v}:/opt/amnezia/xray --name {n} {n}",
                v = q(&format!("{name}-data"))
            )
        }
    };
    files.push((format!("{}/clientsTable", sp.dir), "[]\n".into()));
    files.push(("/opt/amnezia/start.sh".into(), start_sh(plan.kind)));

    let mut s = format!("set -e\n{run}\ndocker network connect amnezia-dns-net {n} 2>/dev/null || true\ndocker exec -i {n} mkdir -p {}\n", q(sp.dir));
    for (path, content) in &files {
        s.push_str(&put_file_cmd(name, path, content));
        s.push('\n');
    }
    s.push_str(&format!("docker exec -d {n} sh -c 'chmod +x /opt/amnezia/start.sh && /opt/amnezia/start.sh'\n"));
    let probe = match plan.kind {
        Kind::Awg => format!("docker exec {n} awg show awg0 >/dev/null 2>&1"),
        Kind::WireGuard => format!("docker exec {n} wg show wg0 >/dev/null 2>&1"),
        _ => format!("docker exec {n} pgrep xray >/dev/null 2>&1"),
    };
    let why = match plan.kind {
        Kind::Awg => format!("docker exec {n} awg-quick up {} 2>&1 | tail -8", q(sp.conf)),
        Kind::WireGuard => format!("docker exec {n} wg-quick up {} 2>&1 | tail -8", q(sp.conf)),
        _ => format!("docker exec {n} xray run -test -config {} 2>&1 | tail -8", q(sp.conf)),
    };
    s.push_str(&format!(
        "set +e\nfor i in 1 2 3 4 5 6 7 8 9 10; do {probe} && exit 0; sleep 1; done\n{why}\nexit 5\n"
    ));
    Ok(s)
}

/// Stop and delete a container with its image (and, for Xray, its keys).
pub fn remove_script(name: &str, with_data: bool) -> String {
    let n = q(name);
    let mut s = format!("docker stop {n} >/dev/null 2>&1; docker rm -fv {n} >/dev/null 2>&1; docker rmi {n} >/dev/null 2>&1\n");
    if with_data {
        s.push_str(&format!("docker volume rm {} >/dev/null 2>&1\n", q(&format!("{name}-data"))));
        s.push_str(&format!("rm -rf {}\n", q(&format!("/opt/amnezia/{name}"))));
    }
    s.push_str(&format!("! docker ps -a --format '{{{{.Names}}}}' | grep -qx {n}\n"));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn awg_server_file_reads_back() {
        let conf = awg_server_conf("cHJpdg==", 41234);
        let c = wg::parse(&conf);
        assert_eq!(c.listen_port(), Some(41234));
        assert!(c.get("HeaderProtectionKey").is_some());
        let jc: u32 = c.get("Jc").unwrap().parse().unwrap();
        assert!((4..=6).contains(&jc));
        // a client of it is a valid AmneziaWG 3.1 profile
        let k = wg::ClientKeys { private_key: "cHJpdg==", ip: wg::next_ip(&c).unwrap(), server_public_key: "cHVi", psk: Some("cHNr"), host: "h.example", port: 41234 };
        let p = retunl_core::wgconf::parse(&wg::client_conf(&c, &k), "x").unwrap().profile;
        assert_eq!(p.outbound["random_trailers"], true);
        assert_eq!(retunl_core::awg::core_need(&p.outbound), retunl_core::awg::CoreNeed::Extended);
    }

    #[test]
    fn scripts_name_the_container() {
        for kind in [Kind::Awg, Kind::Xray, Kind::WireGuard] {
            let plan = Plan { kind, port: 40000, site: String::new() };
            let s = start_script(&plan).unwrap();
            let name = container_of(kind).unwrap();
            assert!(s.contains(&format!("--name '{name}' '{name}'")));
            assert!(s.contains("/opt/amnezia/start.sh"));
            assert!(dockerfile(kind).contains("ENTRYPOINT [\"dumb-init\", \"/opt/amnezia/start.sh\"]"));
        }
        assert!(start_script(&Plan { kind: Kind::Xray, port: 443, site: "a.com/x".into() }).is_err());
        assert!(container_of(Kind::Other).is_err());
        assert!(remove_script("amnezia-xray", true).contains("amnezia-xray-data"));
    }

    #[test]
    fn xray_dockerfile_checks_the_download() {
        let d = dockerfile(Kind::Xray);
        assert!(d.contains("sha256sum -c -"));
        assert!(d.contains(XRAY_SHA_AMD64));
        assert!(d.contains("releases/download/${XRAY_VERSION}/Xray-linux-$a.zip"));
    }
}
