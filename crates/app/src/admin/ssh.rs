//! One SSH session to a managed server. Scripts go to `sh -s` on stdin and run
//! as root: as the login itself, or through passwordless sudo.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client::{self, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{self, HashAlg, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};

/// Start of the error when the server's host key is not the remembered one.
pub const HOST_KEY_CHANGED: &str = "Ключ SSH сервера изменился";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub enum Auth {
    Password(String),
    Key { pem: String, passphrase: Option<String> },
}

pub struct Target<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub auth: &'a Auth,
    /// `SHA256:…` of the host key seen before; `None` trusts the first one.
    pub pinned: Option<&'a str>,
}

pub struct Out {
    pub code: u32,
    pub out: String,
    pub err: String,
}

impl Out {
    pub fn ok(&self) -> bool {
        self.code == 0
    }

    /// The last lines of what the script printed, for an error message.
    pub fn tail(&self, lines: usize) -> String {
        let all = format!("{}\n{}", self.out, self.err);
        let kept: Vec<&str> = all.lines().map(str::trim_end).filter(|l| !l.trim().is_empty() && !l.starts_with("@@")).collect();
        kept[kept.len().saturating_sub(lines)..].join("\n")
    }
}

struct Client {
    pinned: Option<String>,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        let ok = self.pinned.as_deref().is_none_or(|p| p == fp);
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some(fp);
        Ok(ok)
    }
}

pub struct Session {
    handle: Handle<Client>,
    sudo: bool,
    /// The server's host key, `SHA256:…`.
    pub fingerprint: String,
}

fn ssh_err(e: russh::Error) -> String {
    match e {
        russh::Error::IO(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => "сервер не принимает подключения по SSH на этом порту".into(),
            std::io::ErrorKind::TimedOut => "сервер не ответил".into(),
            _ => format!("сеть: {e}"),
        },
        russh::Error::ConnectionTimeout | russh::Error::InactivityTimeout => "сервер перестал отвечать".into(),
        russh::Error::Disconnect => "сервер закрыл соединение".into(),
        e => e.to_string(),
    }
}

pub async fn connect(t: Target<'_>) -> Result<Session, String> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(900)),
        keepalive_interval: Some(Duration::from_secs(15)),
        keepalive_max: 4,
        nodelay: true,
        ..Default::default()
    });
    let seen = Arc::new(Mutex::new(None));
    let handler = Client { pinned: t.pinned.map(str::to_string), seen: seen.clone() };
    let addr = (t.host.trim_start_matches('[').trim_end_matches(']'), t.port);
    let connected = tokio::time::timeout(CONNECT_TIMEOUT, client::connect(config, addr, handler)).await;
    let fingerprint = || seen.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default();
    let mut handle = match connected {
        Err(_) => return Err(format!("{}:{} не ответил за {} с", t.host, t.port, CONNECT_TIMEOUT.as_secs())),
        Ok(Err(russh::Error::UnknownKey)) => {
            return Err(format!(
                "{HOST_KEY_CHANGED}: был {}, теперь {}. Если вы переустанавливали систему на сервере, доверьтесь новому ключу; если нет — кто-то может подменять сервер.",
                t.pinned.unwrap_or("?"),
                fingerprint()
            ))
        }
        Ok(Err(e)) => return Err(format!("Не удалось подключиться к {}: {}", t.host, ssh_err(e))),
        Ok(Ok(h)) => h,
    };
    let fingerprint = fingerprint();

    let ok = match t.auth {
        Auth::Password(password) => {
            let r = handle.authenticate_password(t.user, password).await.map_err(ssh_err)?;
            if r.success() {
                true
            } else {
                keyboard_interactive(&mut handle, t.user, password).await?
            }
        }
        Auth::Key { pem, passphrase } => {
            let key = keys::decode_secret_key(pem, passphrase.as_deref()).map_err(|e| match e {
                keys::Error::KeyIsEncrypted => "SSH-ключ защищён паролем — укажите его".to_string(),
                e => format!("Не удалось прочитать SSH-ключ: {e}"),
            })?;
            let hash = handle.best_supported_rsa_hash().await.map_err(ssh_err)?.flatten();
            handle
                .authenticate_publickey(t.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(ssh_err)?
                .success()
        }
    };
    if !ok {
        return Err(match t.auth {
            Auth::Password(_) => format!("Сервер не принял логин {} и пароль", t.user),
            Auth::Key { .. } => format!("Сервер не принял SSH-ключ для {}", t.user),
        });
    }

    let mut s = Session { handle, sudo: false, fingerprint };
    let who = s.raw("id -u").await?;
    if who.out.trim() != "0" {
        let probe = s.raw("sudo -n true").await?;
        if !probe.ok() {
            return Err(format!(
                "У пользователя {} нет прав root, а sudo просит пароль. Войдите как root или разрешите ему sudo без пароля.",
                t.user
            ));
        }
        s.sudo = true;
    }
    Ok(s)
}

async fn keyboard_interactive(handle: &mut Handle<Client>, user: &str, password: &str) -> Result<bool, String> {
    let mut r = handle.authenticate_keyboard_interactive_start(user, None).await.map_err(ssh_err)?;
    for _ in 0..4 {
        match r {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = prompts.iter().map(|_| password.to_string()).collect();
                r = handle.authenticate_keyboard_interactive_respond(answers).await.map_err(ssh_err)?;
            }
        }
    }
    Ok(false)
}

impl Session {
    /// Run one command line as the login user.
    async fn raw(&self, cmd: &str) -> Result<Out, String> {
        self.exec(cmd, None, Duration::from_secs(30), &mut |_| {}).await
    }

    /// Run a shell script as root.
    pub async fn run(&self, script: &str) -> Result<Out, String> {
        self.run_with(script, Duration::from_secs(120), &mut |_| {}).await
    }

    /// Run a shell script as root, handing each printed line to `line`.
    pub async fn run_with(&self, script: &str, limit: Duration, line: &mut (dyn FnMut(&str) + Send)) -> Result<Out, String> {
        let cmd = if self.sudo { "sudo -n sh -s" } else { "sh -s" };
        self.exec(cmd, Some(script.as_bytes()), limit, line).await
    }

    async fn exec(&self, cmd: &str, stdin: Option<&[u8]>, limit: Duration, line: &mut (dyn FnMut(&str) + Send)) -> Result<Out, String> {
        let work = async {
            let mut ch = self.handle.channel_open_session().await.map_err(ssh_err)?;
            ch.exec(true, cmd).await.map_err(ssh_err)?;
            if let Some(input) = stdin {
                ch.data(input).await.map_err(ssh_err)?;
            }
            ch.eof().await.map_err(ssh_err)?;
            let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
            let mut pending = String::new();
            let mut feed = |bytes: &[u8], pending: &mut String| {
                pending.push_str(&String::from_utf8_lossy(bytes));
                while let Some(i) = pending.find('\n') {
                    let l: String = pending.drain(..=i).collect();
                    line(l.trim_end());
                }
            };
            while let Some(msg) = ch.wait().await {
                match msg {
                    ChannelMsg::Data { data } => {
                        out.extend_from_slice(&data);
                        feed(&data, &mut pending);
                    }
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        err.extend_from_slice(&data);
                        feed(&data, &mut pending);
                    }
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            if !pending.trim().is_empty() {
                line(pending.trim_end());
            }
            Ok::<Out, String>(Out {
                code: code.unwrap_or(255),
                out: String::from_utf8_lossy(&out).into_owned(),
                err: String::from_utf8_lossy(&err).into_owned(),
            })
        };
        match tokio::time::timeout(limit, work).await {
            Ok(r) => r,
            Err(_) => Err(format!("команда на сервере не закончилась за {} мин", limit.as_secs().div_ceil(60))),
        }
    }

    pub async fn close(self) {
        let _ = self.handle.disconnect(Disconnect::ByApplication, "", "en").await;
    }
}

/// `it's` → `'it'\''s'`
pub fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(q("a b"), "'a b'");
        assert_eq!(q("it's"), r"'it'\''s'");
    }

    #[test]
    fn tail_skips_markers_and_blanks() {
        let o = Out { code: 1, out: "@@step\none\n\ntwo\n".into(), err: "three\n".into() };
        assert_eq!(o.tail(2), "two\nthree");
    }
}

/// A real SSH conversation with a small server in the test: logins, host-key
/// pinning, and a script's output, error output and exit code.
#[cfg(test)]
mod conversation {
    use super::*;
    use russh::server::{self, Auth as Verdict, ChannelOpenHandle, Msg};
    use russh::{Channel, ChannelId};

    /// A throwaway key made for this test only: the server's host key and the client's login key.
    const TEST_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB86/roo92j73O4BhfTPVLUC9ETUhwv/ehY30QI3hHmrAAAAIiFyrJDhcqy
QwAAAAtzc2gtZWQyNTUxOQAAACB86/roo92j73O4BhfTPVLUC9ETUhwv/ehY30QI3hHmrA
AAAECf35zJJrSIec6PsLVTzCaayXvdqlqUiXbDSNTVh3yUR3zr+uij3aPvc7gGF9M9UtQL
0RNSHC/96FjfRAjeEeasAAAABHRlc3QB
-----END OPENSSH PRIVATE KEY-----
";

    #[derive(Default)]
    struct Fake {
        cmd: String,
        input: Vec<u8>,
    }

    impl server::Handler for Fake {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Verdict, Self::Error> {
            Ok(if user == "root" && password == "pw" { Verdict::Accept } else { Verdict::reject() })
        }

        async fn auth_publickey(&mut self, user: &str, _: &keys::PublicKey) -> Result<Verdict, Self::Error> {
            Ok(if user == "root" { Verdict::Accept } else { Verdict::reject() })
        }

        async fn channel_open_session(&mut self, _: Channel<Msg>, reply: ChannelOpenHandle, _: &mut server::Session) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn exec_request(&mut self, ch: ChannelId, data: &[u8], s: &mut server::Session) -> Result<(), Self::Error> {
            self.cmd = String::from_utf8_lossy(data).into_owned();
            self.input.clear();
            s.channel_success(ch)?;
            if self.cmd == "id -u" {
                s.data(ch, b"0\n".to_vec())?;
                s.exit_status_request(ch, 0)?;
                s.eof(ch)?;
                s.close(ch)?;
            }
            Ok(())
        }

        async fn data(&mut self, _: ChannelId, data: &[u8], _: &mut server::Session) -> Result<(), Self::Error> {
            self.input.extend_from_slice(data);
            Ok(())
        }

        async fn channel_eof(&mut self, ch: ChannelId, s: &mut server::Session) -> Result<(), Self::Error> {
            if self.cmd == "sh -s" {
                let script = String::from_utf8_lossy(&self.input).into_owned();
                s.data(ch, format!("ran {} bytes\n{script}", self.input.len()).into_bytes())?;
                s.extended_data(ch, 1, b"warn\n".to_vec())?;
                s.exit_status_request(ch, 3)?;
                s.eof(ch)?;
                s.close(ch)?;
            }
            Ok(())
        }
    }

    async fn serve() -> u16 {
        let cfg = Arc::new(server::Config {
            keys: vec![keys::decode_secret_key(TEST_KEY, None).unwrap()],
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Ok(s) = server::run_stream(cfg, sock, Fake::default()).await {
                        let _ = s.await;
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn logins_pinning_and_scripts() {
        let port = serve().await;
        let to = |auth, pinned| Target { host: "127.0.0.1", port, user: "root", auth, pinned };

        let pw = Auth::Password("pw".into());
        let s = connect(to(&pw, None)).await.unwrap();
        assert!(s.fingerprint.starts_with("SHA256:"));
        let mut lines = Vec::new();
        let out = s.run_with("echo hi\n", Duration::from_secs(5), &mut |l| lines.push(l.to_string())).await.unwrap();
        assert_eq!((out.code, out.out.as_str(), out.err.as_str()), (3, "ran 8 bytes\necho hi\n", "warn\n"));
        assert!(lines.iter().any(|l| l == "echo hi") && lines.iter().any(|l| l == "warn"));
        let fp = s.fingerprint.clone();
        s.close().await;

        let wrong = Auth::Password("nope".into());
        assert!(connect(to(&wrong, None)).await.err().unwrap().contains("не принял"));
        let e = connect(to(&pw, Some("SHA256:something-else"))).await.err().unwrap();
        assert!(e.starts_with(HOST_KEY_CHANGED), "{e}");
        assert!(e.contains(&fp));
        assert!(connect(to(&pw, Some(&fp))).await.is_ok());

        let key = Auth::Key { pem: TEST_KEY.into(), passphrase: None };
        assert!(connect(to(&key, Some(&fp))).await.is_ok());
        let junk = Auth::Key { pem: "not a key".into(), passphrase: None };
        assert!(connect(to(&junk, None)).await.err().unwrap().contains("SSH-ключ"));

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = closed.local_addr().unwrap().port();
        drop(closed);
        let e = connect(Target { port: dead, ..to(&pw, None) }).await.err().unwrap();
        assert!(e.contains("не принимает"), "{e}");
    }
}
