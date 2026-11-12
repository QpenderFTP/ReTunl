//! «Мои серверы»: VPS you manage over SSH. Protocols live in Docker
//! containers named and laid out the way AmneziaVPN does it, so a server set
//! up by either app can be managed by both.

pub mod commands;
mod install;
mod scan;
mod secret;
mod ssh;
mod table;
mod wg;
mod xray;
#[cfg(test)]
mod live;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use retunl_core::links::AdminAccess;
use retunl_core::util::{new_id, now_unix};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use install::{Plan, Progress};
pub use scan::Scan;
use ssh::{q, Auth, Session, Target};

use crate::util::locked;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    #[serde(rename = "awg")]
    Awg,
    #[serde(rename = "awg_legacy")]
    AwgLegacy,
    #[serde(rename = "wireguard")]
    WireGuard,
    #[serde(rename = "xray")]
    Xray,
    #[serde(rename = "other")]
    Other,
}

/// An AmneziaVPN container ReTunl can manage clients of.
pub struct Spec {
    pub container: &'static str,
    pub kind: Kind,
    pub title: &'static str,
    /// Folder inside the container with the config and `clientsTable`.
    pub dir: &'static str,
    pub conf: &'static str,
    /// `wg`-like tool and interface (WireGuard kinds).
    pub tool: &'static str,
    pub iface: &'static str,
}

pub const SPECS: &[Spec] = &[
    Spec { container: "amnezia-awg2", kind: Kind::Awg, title: "AmneziaWG", dir: "/opt/amnezia/awg", conf: "/opt/amnezia/awg/awg0.conf", tool: "awg", iface: "awg0" },
    Spec { container: "amnezia-xray", kind: Kind::Xray, title: "VLESS", dir: "/opt/amnezia/xray", conf: "/opt/amnezia/xray/server.json", tool: "", iface: "" },
    Spec { container: "amnezia-wireguard", kind: Kind::WireGuard, title: "WireGuard", dir: "/opt/amnezia/wireguard", conf: "/opt/amnezia/wireguard/wg0.conf", tool: "wg", iface: "wg0" },
    Spec { container: "amnezia-awg", kind: Kind::AwgLegacy, title: "AmneziaWG (старая версия)", dir: "/opt/amnezia/awg", conf: "/opt/amnezia/awg/wg0.conf", tool: "wg", iface: "wg0" },
];

pub fn spec(container: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|s| s.container == container)
}

/// Write a file inside a container from base64, through a temporary file.
pub fn put_file_cmd(container: &str, path: &str, content: &str) -> String {
    let inner = format!("cat > {p}.tmp && mv {p}.tmp {p}", p = q(path));
    format!("printf '%s' {} | base64 -d | docker exec -i {} sh -c {}", q(&B64.encode(content)), q(container), q(&inner))
}

/// Stop the script if the file changed since it was read (AmneziaVPN or a
/// second ReTunl may be editing the same server).
fn guard_cmd(container: &str, path: &str, seen: &str) -> String {
    let hash: String = Sha256::digest(seen.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "[ \"$(docker exec -i {} cat {} 2>/dev/null | sha256sum | cut -d' ' -f1)\" = {hash} ] || {{ echo @@changed; exit 7; }}",
        q(container),
        q(path)
    )
}

// ---------- saved servers ----------

#[derive(Serialize, Deserialize, Clone)]
struct Saved {
    id: String,
    name: String,
    host: String,
    port: u16,
    user: String,
    /// "password" or "key"
    auth: String,
    /// The `Secret` JSON, sealed for this Windows user.
    sealed: String,
    #[serde(default)]
    host_key: Option<String>,
    #[serde(default)]
    added_at: i64,
}

#[derive(Serialize, Deserialize, Default)]
struct Secret {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    passphrase: Option<String>,
}

impl Secret {
    fn auth(&self) -> Result<Auth, String> {
        if let Some(k) = self.key.as_deref().filter(|k| !k.trim().is_empty()) {
            return Ok(Auth::Key { pem: k.to_string(), passphrase: self.passphrase.clone().filter(|p| !p.is_empty()) });
        }
        match self.password.as_deref().filter(|p| !p.is_empty()) {
            Some(p) => Ok(Auth::Password(p.to_string())),
            None => Err("Нужен пароль или SSH-ключ".into()),
        }
    }

    fn kind(&self) -> &'static str {
        if self.key.as_deref().is_some_and(|k| !k.trim().is_empty()) {
            "key"
        } else {
            "password"
        }
    }

    /// AmneziaVPN keeps a private key in its password field.
    fn from_amnezia(secret: &str) -> Secret {
        if secret.trim_start().starts_with("-----BEGIN") {
            Secret { key: Some(secret.to_string()), ..Default::default() }
        } else {
            Secret { password: Some(secret.to_string()), ..Default::default() }
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct SavedFile {
    #[serde(default)]
    servers: Vec<Saved>,
}

#[derive(Serialize, Clone)]
pub struct ServerView {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: String,
    pub host_key: Option<String>,
    pub added_at: i64,
    pub scan: Option<Scan>,
    /// Why the last look at the server failed.
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct AddForm {
    #[serde(default)]
    pub name: Option<String>,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// A private key file to read.
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct Qr {
    pub size: usize,
    /// `size × size` cells, row by row: '1' is dark.
    pub bits: String,
}

/// What a client needs to connect: a `.conf` or a `vless://` link.
#[derive(Serialize, Clone)]
pub struct ClientKey {
    pub name: String,
    pub kind: Kind,
    pub text: String,
    pub file_name: Option<String>,
    pub qr: Option<Qr>,
    /// The server keeps no copy (WireGuard private keys): shown only now.
    pub once: bool,
}

fn qr(text: &str) -> Option<Qr> {
    let code = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::L).ok()?;
    let bits = code.to_colors().iter().map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' }).collect();
    Some(Qr { size: code.width(), bits })
}

fn file_name_for(name: &str) -> String {
    let clean: String = name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let clean = clean.trim_matches('_');
    format!("{}.conf", if clean.is_empty() { "client" } else { clean })
}

/// `root@host:2222`, `ssh://host`, `[2001:db8::1]:22` → (user, host, port)
fn split_address(raw: &str) -> Result<(Option<String>, String, Option<u16>), String> {
    let mut s = raw.trim().trim_start_matches("ssh://").trim_end_matches('/').to_string();
    let mut user = None;
    if let Some((u, rest)) = s.split_once('@') {
        user = Some(u.to_string()).filter(|u| !u.is_empty());
        s = rest.to_string();
    }
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or("в адресе IPv6 не хватает «]»")?;
        (h.to_string(), tail.strip_prefix(':').map(str::to_string))
    } else if s.matches(':').count() == 1 {
        let (h, p) = s.split_once(':').expect("one colon");
        (h.to_string(), Some(p.to_string()))
    } else {
        (s.clone(), None)
    };
    let port = match port {
        Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0).ok_or("порт — число от 1 до 65535")?),
        None => None,
    };
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err("Укажите адрес сервера: IP или домен".into());
    }
    Ok((user, host, port))
}

#[derive(Default, Clone)]
struct Look {
    scan: Option<Scan>,
    error: Option<String>,
}

pub struct Admin {
    file: PathBuf,
    saved: Mutex<Vec<Saved>>,
    looks: Mutex<HashMap<String, Look>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Admin {
    pub fn new(file: PathBuf) -> Admin {
        let saved = std::fs::read(&file)
            .ok()
            .and_then(|b| serde_json::from_slice::<SavedFile>(&b).ok())
            .map(|f| f.servers)
            .unwrap_or_default();
        Admin { file, saved: Mutex::new(saved), looks: Mutex::new(HashMap::new()), locks: Mutex::new(HashMap::new()) }
    }

    fn saved(&self) -> std::sync::MutexGuard<'_, Vec<Saved>> {
        locked(&self.saved)
    }

    /// Change the list and write it; nothing changes if writing fails.
    fn edit<R>(&self, f: impl FnOnce(&mut Vec<Saved>) -> Result<R, String>) -> Result<R, String> {
        let mut guard = self.saved();
        let mut copy = guard.clone();
        let r = f(&mut copy)?;
        let body = serde_json::to_vec_pretty(&SavedFile { servers: copy.clone() }).map_err(|e| e.to_string())?;
        let tmp = self.file.with_extension("json.tmp");
        std::fs::write(&tmp, body)
            .and_then(|_| std::fs::rename(&tmp, &self.file))
            .map_err(|e| format!("Не удалось сохранить список серверов: {e}"))?;
        *guard = copy;
        Ok(r)
    }

    fn get(&self, id: &str) -> Result<Saved, String> {
        self.saved().iter().find(|s| s.id == id).cloned().ok_or_else(|| "Сервер не найден".to_string())
    }

    fn lock_for(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        locked(&self.locks).entry(id.to_string()).or_default().clone()
    }

    fn view(&self, s: &Saved) -> ServerView {
        let look = locked(&self.looks).get(&s.id).cloned().unwrap_or_default();
        ServerView {
            id: s.id.clone(),
            name: s.name.clone(),
            host: s.host.clone(),
            port: s.port,
            user: s.user.clone(),
            auth: s.auth.clone(),
            host_key: s.host_key.clone(),
            added_at: s.added_at,
            scan: look.scan,
            error: look.error,
        }
    }

    fn view_of(&self, id: &str) -> Result<ServerView, String> {
        Ok(self.view(&self.get(id)?))
    }

    pub fn list(&self) -> Vec<ServerView> {
        let all = self.saved().clone();
        all.iter().map(|s| self.view(s)).collect()
    }

    fn remember(&self, id: &str, r: &Result<Scan, String>) {
        let mut looks = locked(&self.looks);
        let look = looks.entry(id.to_string()).or_default();
        match r {
            Ok(s) => {
                look.scan = Some(s.clone());
                look.error = None;
            }
            Err(e) => look.error = Some(e.clone()),
        }
    }

    async fn open(&self, s: &Saved) -> Result<Session, String> {
        let plain = secret::open(&s.sealed)?;
        let secret: Secret = serde_json::from_slice(&plain).map_err(|_| "сохранённый пароль повреждён".to_string())?;
        let auth = secret.auth()?;
        let sess = ssh::connect(Target { host: &s.host, port: s.port, user: &s.user, auth: &auth, pinned: s.host_key.as_deref() }).await?;
        if s.host_key.is_none() {
            let fp = sess.fingerprint.clone();
            let id = s.id.clone();
            self.edit(|all| {
                if let Some(x) = all.iter_mut().find(|x| x.id == id) {
                    x.host_key = Some(fp);
                }
                Ok(())
            })?;
        }
        Ok(sess)
    }

    /// Store a server (or new credentials for one already in the list).
    fn store(&self, name: Option<String>, host: String, port: u16, user: String, secret: &Secret, host_key: Option<String>) -> Result<String, String> {
        let sealed = secret::seal(&serde_json::to_vec(secret).map_err(|e| e.to_string())?)?;
        let auth = secret.kind().to_string();
        self.edit(|all| {
            if let Some(x) = all.iter_mut().find(|x| x.host.eq_ignore_ascii_case(&host) && x.port == port && x.user == user) {
                x.sealed = sealed;
                x.auth = auth;
                if host_key.is_some() {
                    x.host_key = host_key;
                }
                if let Some(n) = name.filter(|n| !n.trim().is_empty()) {
                    x.name = n.trim().to_string();
                }
                return Ok(x.id.clone());
            }
            let id = new_id();
            let name = name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()).unwrap_or_else(|| host.clone());
            all.push(Saved { id: id.clone(), name, host, port, user, auth, sealed, host_key, added_at: now_unix() });
            Ok(id)
        })
    }

    /// Check the login, then keep the server and look at what is on it.
    pub async fn add(&self, f: AddForm) -> Result<ServerView, String> {
        let (u, host, p) = split_address(&f.host)?;
        let port = f.port.or(p).unwrap_or(22);
        let user = f.user.map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).or(u).unwrap_or_else(|| "root".into());
        let secret = match f.key_path.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            Some(path) => {
                let meta = std::fs::metadata(path).map_err(|e| format!("Не удалось открыть ключ: {e}"))?;
                if meta.len() > 64 * 1024 {
                    return Err("Это не похоже на SSH-ключ: файл слишком большой".into());
                }
                let key = std::fs::read_to_string(path).map_err(|e| format!("Не удалось прочитать ключ: {e}"))?;
                Secret { key: Some(key), passphrase: f.passphrase.filter(|p| !p.is_empty()), ..Default::default() }
            }
            None => Secret { password: f.password.filter(|p| !p.is_empty()), ..Default::default() },
        };
        let auth = secret.auth()?;
        let sess = ssh::connect(Target { host: &host, port, user: &user, auth: &auth, pinned: None }).await?;
        let id = self.store(f.name, host.clone(), port, user, &secret, Some(sess.fingerprint.clone()))?;
        let r = scan::run(&sess, &host).await;
        sess.close().await;
        self.remember(&id, &r);
        self.view_of(&id)
    }

    /// Keep a server from an AmneziaVPN full-access key, then look at it.
    /// It is kept even if it can't be reached right now.
    pub async fn add_access(&self, a: AdminAccess) -> Result<ServerView, String> {
        let id = self.store(Some(a.name), a.host, a.port, a.user, &Secret::from_amnezia(&a.secret), None)?;
        let _ = self.scan(&id).await;
        self.view_of(&id)
    }

    pub async fn scan(&self, id: &str) -> Result<ServerView, String> {
        let lock = self.lock_for(id);
        let _held = lock.lock().await;
        let s = self.get(id)?;
        let r = match self.open(&s).await {
            Ok(sess) => {
                let r = scan::run(&sess, &s.host).await;
                sess.close().await;
                r
            }
            Err(e) => Err(e),
        };
        self.remember(id, &r);
        r.map(|_| self.view(&s))
    }

    /// Run `f` with a session to the server, then look at the server again.
    async fn with_session<T>(&self, id: &str, f: impl AsyncFnOnce(&Saved, &Session) -> Result<T, String>) -> Result<(ServerView, T), String> {
        let lock = self.lock_for(id);
        let _held = lock.lock().await;
        let s = self.get(id)?;
        let sess = self.open(&s).await?;
        let r = f(&s, &sess).await;
        let look = scan::run(&sess, &s.host).await;
        sess.close().await;
        self.remember(id, &look);
        let v = r?;
        Ok((self.view_of(id)?, v))
    }

    pub async fn client_add(&self, id: &str, container: &str, name: &str) -> Result<(ServerView, ClientKey), String> {
        let name = clean_name(name)?;
        self.with_session(id, async |s: &Saved, sess: &Session| add_client(s, sess, container, &name).await).await
    }

    pub async fn client_remove(&self, id: &str, container: &str, client: &str) -> Result<ServerView, String> {
        self.with_session(id, async |_: &Saved, sess: &Session| remove_client(sess, container, client).await).await.map(|r| r.0)
    }

    pub async fn client_rename(&self, id: &str, container: &str, client: &str, name: &str) -> Result<ServerView, String> {
        let name = clean_name(name)?;
        self.with_session(id, async |_: &Saved, sess: &Session| {
            let sp = managed(container)?;
            let tp = scan::table_path(sp);
            let files = read_files(sess, container, &[&tp]).await?;
            let old = files.get(&tp).cloned().unwrap_or_default();
            let next = table::set(&old, client, &name, Some(&table::qt_date(now_unix())));
            run_ok(sess, &format!("set -e\n{}\n", put_file_cmd(container, &tp, &next)), "Не удалось сохранить имя").await
        })
        .await
        .map(|r| r.0)
    }

    /// The link of an existing VLESS client (WireGuard keys can't be shown again).
    pub async fn client_key(&self, id: &str, container: &str, client: &str) -> Result<ClientKey, String> {
        let lock = self.lock_for(id);
        let _held = lock.lock().await;
        let s = self.get(id)?;
        let sp = managed(container)?;
        if sp.kind != Kind::Xray {
            return Err("Ключ WireGuard показывается только при создании: сервер хранит лишь его открытую часть".into());
        }
        let sess = self.open(&s).await?;
        let tp = scan::table_path(sp);
        let files = read_files(&sess, container, &[sp.conf, &tp]).await;
        sess.close().await;
        let files = files?;
        let ib = xray::parse_server(files.get(sp.conf).ok_or("не удалось прочитать server.json")?)?;
        let name = files.get(&tp).and_then(|t| table::read(t).get(client).map(|e| e.name.clone())).filter(|n| !n.is_empty()).unwrap_or_else(|| s.name.clone());
        let text = xray::link(&ib, &s.host, client, &name)?;
        Ok(ClientKey { qr: qr(&text), name, kind: Kind::Xray, text, file_name: None, once: false })
    }

    pub async fn install(&self, id: &str, plan: Plan, first_client: Option<String>, progress: &(dyn Fn(Progress) + Send + Sync)) -> Result<(ServerView, Option<ClientKey>), String> {
        let first = first_client.map(|n| clean_name(&n)).transpose()?;
        progress(Progress { server: id.to_string(), step: "connect", state: "run", detail: None });
        self.with_session(id, async |s: &Saved, sess: &Session| {
            progress(Progress { server: id.to_string(), step: "connect", state: "done", detail: None });
            install::run(sess, id, &plan, progress).await?;
            let Some(name) = first else { return Ok(None) };
            progress(Progress { server: id.to_string(), step: "client", state: "run", detail: None });
            let container = install::container_of(plan.kind)?;
            let key = add_client(s, sess, container, &name).await?;
            progress(Progress { server: id.to_string(), step: "client", state: "done", detail: None });
            Ok(Some(key))
        })
        .await
    }

    pub async fn remove_protocol(&self, id: &str, container: &str) -> Result<ServerView, String> {
        if !container.starts_with("amnezia-") || container.contains(['\'', ' ', '/']) {
            return Err("Неизвестный контейнер".into());
        }
        let c = container.to_string();
        self.with_session(id, async |_: &Saved, sess: &Session| run_ok(sess, &install::remove_script(&c, true), "Не удалось удалить контейнер").await)
            .await
            .map(|r| r.0)
    }

    pub async fn start_protocol(&self, id: &str, container: &str) -> Result<ServerView, String> {
        if !container.starts_with("amnezia-") {
            return Err("Неизвестный контейнер".into());
        }
        let c = container.to_string();
        self.with_session(id, async |_: &Saved, sess: &Session| run_ok(sess, &format!("docker start {}", q(&c)), "Контейнер не запустился").await)
            .await
            .map(|r| r.0)
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<(), String> {
        let name = clean_name(name)?;
        self.edit(|all| {
            let x = all.iter_mut().find(|x| x.id == id).ok_or("Сервер не найден")?;
            x.name = name;
            Ok(())
        })
    }

    pub fn forget(&self, id: &str) -> Result<(), String> {
        self.edit(|all| {
            all.retain(|x| x.id != id);
            Ok(())
        })?;
        locked(&self.looks).remove(id);
        Ok(())
    }

    /// The server was reinstalled: remember its new host key on the next connect.
    pub fn trust_new_key(&self, id: &str) -> Result<(), String> {
        self.edit(|all| {
            let x = all.iter_mut().find(|x| x.id == id).ok_or("Сервер не найден")?;
            x.host_key = None;
            Ok(())
        })
    }
}

fn clean_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("Введите имя".into());
    }
    Ok(n.chars().filter(|c| !c.is_control()).take(64).collect())
}

fn managed(container: &str) -> Result<&'static Spec, String> {
    spec(container).ok_or_else(|| "Клиентами этого протокола ReTunl не управляет".to_string())
}

async fn run_ok(sess: &Session, script: &str, what: &str) -> Result<(), String> {
    let out = sess.run(script).await?;
    if out.out.contains("@@changed") {
        return Err("Пока ReTunl работал, настройки на сервере изменились (например, в AmneziaVPN). Обновите список и повторите.".into());
    }
    if !out.ok() {
        let tail = out.tail(8);
        return Err(if tail.is_empty() { format!("{what} (код {})", out.code) } else { format!("{what}:\n{tail}") });
    }
    Ok(())
}

/// Files of one container by path; missing or empty ones are left out.
async fn read_files(sess: &Session, container: &str, paths: &[&str]) -> Result<HashMap<String, String>, String> {
    let script: String = paths.iter().map(|p| scan::file_cmd(container, p)).collect();
    let out = sess.run(&script).await?;
    let sec = scan::sections(&out.out);
    Ok(paths
        .iter()
        .filter_map(|p| scan::unb64(sec.get(&scan::file_key(container, p))).map(|t| (p.to_string(), t)))
        .collect())
}

async fn add_client(s: &Saved, sess: &Session, container: &str, name: &str) -> Result<ClientKey, String> {
    let sp = managed(container)?;
    let tp = scan::table_path(sp);
    let created = table::qt_date(now_unix());
    if sp.kind == Kind::Xray {
        let files = read_files(sess, container, &[sp.conf, &tp]).await?;
        let json = files.get(sp.conf).ok_or("не удалось прочитать server.json — контейнер запущен?")?;
        let ib = xray::parse_server(json)?;
        let id = uuid::Uuid::new_v4().to_string();
        let flow = ib.flow.clone().or_else(|| (ib.security == "reality").then(|| xray::FLOW.to_string()));
        let next = xray::add_client(json, &id, flow.as_deref())?;
        let ib = xray::parse_server(&next)?;
        let text = xray::link(&ib, &s.host, &id, name)?;
        let tbl = table::set(files.get(&tp).map_or("", |t| t.as_str()), &id, name, Some(&created));
        let c = q(container);
        let script = format!(
            "set -e\n{}\n{}\n{}\ndocker restart {c} >/dev/null\nfor i in 1 2 3 4 5 6; do docker exec {c} pgrep xray >/dev/null 2>&1 && exit 0; sleep 1; done\necho 'xray не запустился с новыми настройками'; exit 5\n",
            guard_cmd(container, sp.conf, json),
            put_file_cmd(container, sp.conf, &next),
            put_file_cmd(container, &tp, &tbl),
        );
        run_ok(sess, &script, "Не удалось добавить клиента").await?;
        return Ok(ClientKey { qr: qr(&text), name: name.to_string(), kind: sp.kind, text, file_name: None, once: false });
    }

    let psk_path = format!("{}/wireguard_psk.key", sp.dir);
    let files = read_files(sess, container, &[sp.conf, &tp, &psk_path]).await?;
    let text = files.get(sp.conf).ok_or("не удалось прочитать настройки сервера — контейнер запущен?")?;
    let conf = wg::parse(text);
    let ip = wg::next_ip(&conf)?;
    let server_public = wg::server_public_key(&conf).ok_or("в настройках сервера нет ключа")?;
    let psk = files.get(&psk_path).map(|k| k.trim().to_string()).filter(|k| !k.is_empty());
    let port = conf.listen_port().ok_or("в настройках сервера нет порта")?;
    let (private, public) = wg::keypair();
    let tbl = table::set(files.get(&tp).map_or("", |t| t.as_str()), &public, name, Some(&created));
    let (c, tool, iface, cf) = (q(container), sp.tool, sp.iface, q(sp.conf));
    let peer = wg::peer_block(&public, psk.as_deref(), ip);
    let append = format!(
        "printf '%s' {} | base64 -d | docker exec -i {c} sh -c {}",
        q(&B64.encode(&peer)),
        q(&format!("cat >> {cf}"))
    );
    let sync = q(&format!("{tool} syncconf {iface} <({tool}-quick strip {cf})"));
    let script = format!(
        "set -e\n{}\n{append}\n{}\ndocker exec -i {c} bash -c {sync}\ndocker exec -i {c} {tool} show {iface} peers | grep -qx {}\n",
        guard_cmd(container, sp.conf, text),
        put_file_cmd(container, &tp, &tbl),
        q(&public),
    );
    run_ok(sess, &script, "Не удалось добавить клиента").await?;
    let client = wg::client_conf(&conf, &wg::ClientKeys { private_key: &private, ip, server_public_key: &server_public, psk: psk.as_deref(), host: &s.host, port });
    Ok(ClientKey { qr: qr(&client), name: name.to_string(), kind: sp.kind, text: client, file_name: Some(file_name_for(name)), once: true })
}

async fn remove_client(sess: &Session, container: &str, client: &str) -> Result<(), String> {
    let sp = managed(container)?;
    let tp = scan::table_path(sp);
    let files = read_files(sess, container, &[sp.conf, &tp]).await?;
    let text = files.get(sp.conf).ok_or("не удалось прочитать настройки сервера — контейнер запущен?")?;
    let tbl = table::remove(files.get(&tp).map_or("", |t| t.as_str()), client);
    let c = q(container);
    let mut script = format!("set -e\n{}\n", guard_cmd(container, sp.conf, text));
    if sp.kind == Kind::Xray {
        let next = xray::remove_client(text, client)?;
        script.push_str(&format!(
            "{}\n{}\ndocker restart {c} >/dev/null\n",
            put_file_cmd(container, sp.conf, &next),
            put_file_cmd(container, &tp, &tbl)
        ));
    } else {
        let next = wg::remove_peer(text, client).ok_or("такого клиента на сервере уже нет")?;
        let (tool, iface, cf) = (sp.tool, sp.iface, q(sp.conf));
        let sync = q(&format!("{tool} syncconf {iface} <({tool}-quick strip {cf})"));
        script.push_str(&format!(
            "{}\n{}\ndocker exec -i {c} bash -c {sync}\n",
            put_file_cmd(container, sp.conf, &next),
            put_file_cmd(container, &tp, &tbl)
        ));
    }
    run_ok(sess, &script, "Не удалось удалить клиента").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(split_address("1.2.3.4").unwrap(), (None, "1.2.3.4".into(), None));
        assert_eq!(split_address(" root@vps.example:2222 ").unwrap(), (Some("root".into()), "vps.example".into(), Some(2222)));
        assert_eq!(split_address("ssh://[2001:db8::1]:22").unwrap(), (None, "2001:db8::1".into(), Some(22)));
        assert_eq!(split_address("2001:db8::1").unwrap(), (None, "2001:db8::1".into(), None));
        assert!(split_address("host:99999").is_err());
        assert!(split_address("  ").is_err());
    }

    #[test]
    fn secrets_from_amnezia() {
        assert_eq!(Secret::from_amnezia("pw").kind(), "password");
        assert_eq!(Secret::from_amnezia("-----BEGIN OPENSSH PRIVATE KEY-----\nx").kind(), "key");
        assert!(Secret::default().auth().is_err());
    }

    #[test]
    fn store_dedupes_and_survives_restart() {
        let dir = std::env::temp_dir().join(format!("retunl-admin-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("servers.json");
        let a = Admin::new(file.clone());
        let pw = Secret { password: Some("one".into()), ..Default::default() };
        let id = a.store(None, "1.2.3.4".into(), 22, "root".into(), &pw, Some("SHA256:x".into())).unwrap();
        let pw2 = Secret { password: Some("two".into()), ..Default::default() };
        assert_eq!(a.store(Some("VPS".into()), "1.2.3.4".into(), 22, "root".into(), &pw2, None).unwrap(), id);
        let b = Admin::new(file);
        let list = b.list();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].name.as_str(), list[0].host_key.as_deref()), ("VPS", Some("SHA256:x")));
        let raw = std::fs::read_to_string(dir.join("servers.json")).unwrap();
        assert!(!raw.contains("two"), "the password is sealed");
        let s = b.get(&id).unwrap();
        let secret: Secret = serde_json::from_slice(&secret::open(&s.sealed).unwrap()).unwrap();
        assert_eq!(secret.password.as_deref(), Some("two"));
        b.forget(&id).unwrap();
        assert!(b.list().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shell_helpers() {
        let put = put_file_cmd("amnezia-awg2", "/opt/amnezia/awg/clientsTable", "[]\n");
        assert!(put.starts_with("printf '%s' 'W10K' | base64 -d | docker exec -i 'amnezia-awg2' sh -c"));
        let g = guard_cmd("c", "/p", "");
        assert!(g.contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert_eq!(file_name_for("Мой телефон!"), "Мой_телефон.conf");
        assert_eq!(file_name_for("***"), "client.conf");
        let q = qr("vless://x").unwrap();
        assert_eq!(q.bits.len(), q.size * q.size);
    }
}
