//! Downloads: rule sets, the sing-box core, subscriptions.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use retunl_core::awg::CoreKind;
use retunl_core::rulesets::{self, RuleSetSource};
use retunl_core::subscription;
use retunl_core::SubscriptionInfo;
use sha2::{Digest, Sha256};

const CORE_BASE: &str = "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/";
/// sing-box-lx by Leadaxe (GPL-3.0): AmneziaWG 2.0–3.1 and XHTTP.
const LX_CORE_BASE: &str = "https://github.com/Leadaxe/sing-box-lx/releases/download/v1.14.4-lx.32/";

/// Release archives for this system: (official, sing-box-lx), each (file name, SHA-256).
#[cfg(windows)]
const CORE_ASSETS: [(&str, &str); 2] = [
    ("sing-box-1.14.4-windows-amd64.zip", "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df"),
    ("sing-box-1.14.4-lx.32-windows-amd64.zip", "5eff0f5fba576d3eb57b7ce9c6b60a90125d0a716138ffcd7db47e04e3db2e1a"),
];
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const CORE_ASSETS: [(&str, &str); 2] = [
    ("sing-box-1.14.4-darwin-arm64.tar.gz", "0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838"),
    ("sing-box-1.14.4-lx.32-darwin-arm64.tar.gz", "c4f4eddab7513e970f614766ea03c028de88ef5477f8dea629c9e63c2fb7c2b5"),
];
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const CORE_ASSETS: [(&str, &str); 2] = [
    ("sing-box-1.14.4-darwin-amd64.tar.gz", "eae86b9b033bba50b7c44ab719e4bfac0aca05efd28483390ed3aa510f32db25"),
    ("sing-box-1.14.4-lx.32-darwin-amd64.tar.gz", "f81fc2b73c5f89d3f6a2069fbcde0e716b8204016593ff155eaec0cc26063c9f"),
];

/// Android: the core is built into the app, nothing is downloaded.
#[cfg(target_os = "android")]
const CORE_ASSETS: [(&str, &str); 2] = [("", ""), ("", "")];

/// Download address and checksum of a core for this system.
pub fn core_asset(kind: CoreKind) -> (String, &'static str) {
    let (base, (file, sha)) = match kind {
        CoreKind::Official => (CORE_BASE, CORE_ASSETS[0]),
        CoreKind::Extended => (LX_CORE_BASE, CORE_ASSETS[1]),
    };
    (format!("{base}{file}"), sha)
}

/// Lists older than this are refreshed on connect (the old copy is kept if that fails).
const RULESET_MAX_AGE: Duration = Duration::from_secs(3 * 24 * 3600);

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("ReTunl/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .gzip(true)
        .build()
        .expect("http client")
}

async fn get_bytes(http: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let r = http.get(url).send().await.map_err(|e| short_err(&e))?;
    if !r.status().is_success() {
        return Err(format!("сервер ответил {}", r.status().as_u16()));
    }
    r.bytes().await.map(|b| b.to_vec()).map_err(|e| short_err(&e))
}

/// Every geosite/geoip tag the rule-set sources have — hints for the rule
/// editor. Cached for a week; a stale copy is better than none.
pub async fn geo_tags(http: &reqwest::Client, cache: &Path) -> Result<Vec<String>, String> {
    let read_cache = || -> Option<Vec<String>> { serde_json::from_slice(&std::fs::read(cache).ok()?).ok() };
    let age = std::fs::metadata(cache).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok());
    if age.is_some_and(|a| a < Duration::from_secs(7 * 24 * 3600)) {
        if let Some(tags) = read_cache() {
            return Ok(tags);
        }
    }
    let mut tags: Vec<String> = rulesets::RUNETFREEDOM_ONLY.iter().map(|t| t.to_string()).collect();
    for repo in [rulesets::SAGERNET_GEOSITE, rulesets::SAGERNET_GEOIP] {
        let url = format!("https://api.github.com/repos/{repo}/git/trees/rule-set");
        let tree = match get_bytes(http, &url).await.and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).map_err(|e| e.to_string())) {
            Ok(v) => v,
            Err(e) => return read_cache().ok_or(format!("Не удалось получить список тегов: {e}")),
        };
        let paths = tree.get("tree").and_then(|t| t.as_array()).into_iter().flatten();
        tags.extend(paths.filter_map(|e| e.get("path")?.as_str()?.strip_suffix(".srs").map(str::to_string)));
    }
    tags.sort();
    tags.dedup();
    if let Some(dir) = cache.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(cache, serde_json::to_vec(&tags).unwrap_or_default());
    Ok(tags)
}

fn short_err(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "превышено время ожидания".into()
    } else if e.is_connect() {
        "не удалось подключиться".into()
    } else {
        e.to_string()
    }
}

/// Make sure every rule set is on disk. Returns warnings for stale copies.
pub async fn ensure_rule_sets(
    http: &reqwest::Client,
    sources: &[RuleSetSource],
    dir: &Path,
    force: bool,
) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut warnings = Vec::new();
    let mut missing = Vec::new();
    for src in sources {
        let path = dir.join(&src.file_name);
        let age = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok());
        let fresh = matches!(age, Some(a) if a < RULESET_MAX_AGE);
        if fresh && !force {
            continue;
        }
        match download_rule_set(http, src).await {
            Ok(bytes) => write_atomic(&path, &bytes).map_err(|e| format!("{}: {e}", src.tag))?,
            Err(e) if age.is_some() => warnings.push(format!("Список {} не обновился ({e}), использую сохранённый.", src.tag)),
            Err(e) => missing.push(format!("{} ({e})", src.tag)),
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "Не удалось скачать списки: {}. Проверьте интернет или уберите эти списки из правил.",
            missing.join(", ")
        ));
    }
    Ok(warnings)
}

async fn download_rule_set(http: &reqwest::Client, src: &RuleSetSource) -> Result<Vec<u8>, String> {
    let mut last = String::from("нет адресов");
    for url in &src.urls {
        match get_bytes(http, url).await {
            // a real .srs starts with the "SRS" magic
            Ok(b) if b.starts_with(b"SRS") => return Ok(b),
            Ok(_) => last = "получен не .srs файл".into(),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("part");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

pub const XRAY_VERSION: &str = "26.11.9";

/// Download the pinned Xray release and publish only the verified executable.
pub async fn install_xray(http: &reqwest::Client, path: &Path) -> Result<(), String> {
    let (asset, sha) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => ("Xray-windows-64.zip", "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d"),
        ("windows", "aarch64") => ("Xray-windows-arm64-v8a.zip", "9fdd48ff890e54ffdc37f92df9037c940fe4d4f914755b70cc644b97e9678a83"),
        _ => return Err("Xray-core доступен в Windows x64 и ARM64.".into()),
    };
    if path.is_file() { return Ok(()); }
    let url = format!("https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{asset}");
    let bytes = verified_archive(http, &url, sha, |_, _| {}).await?;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let mut exe = zip.by_name("xray.exe").map_err(|e| e.to_string())?;
    let dir = path.parent().ok_or("Нет папки для Xray-core")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    std::io::copy(&mut exe, &mut tmp).map_err(|e| e.to_string())?;
    match tmp.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Download a core, check its SHA-256 and unpack it into `dir`.
pub async fn download_core(
    http: &reqwest::Client,
    kind: CoreKind,
    dir: &Path,
    progress: impl Fn(u64, Option<u64>),
) -> Result<PathBuf, String> {
    let (url, sha) = core_asset(kind);
    let buf = verified_archive(http, &url, sha, progress).await?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut exe = None;
    for (name, data) in unpack_core(buf)? {
        let target = dir.join(&name);
        write_atomic(&target, &data).map_err(|e| {
            format!("Не удалось записать {name}: {e}. Если ReTunl подключён — сначала отключитесь.")
        })?;
        if name == crate::paths::CORE_EXE {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
            }
            exe = Some(target);
        }
    }
    exe.ok_or_else(|| format!("в архиве нет {}", crate::paths::CORE_EXE))
}

async fn verified_archive(http: &reqwest::Client, url: &str, sha: &str, progress: impl Fn(u64, Option<u64>)) -> Result<Vec<u8>, String> {
    let mut r = http.get(url).send().await.map_err(|e| short_err(&e))?;
    if !r.status().is_success() {
        return Err(format!("GitHub ответил {}", r.status().as_u16()));
    }
    let total = r.content_length();
    let mut buf = Vec::new();
    while let Some(chunk) = r.chunk().await.map_err(|e| short_err(&e))? {
        buf.extend_from_slice(&chunk);
        progress(buf.len() as u64, total);
    }
    if format!("{:x}", Sha256::digest(&buf)) != sha {
        return Err("Контрольная сумма архива не совпала — файл повреждён или подменён. Попробуйте ещё раз.".into());
    }
    Ok(buf)
}

/// The files we need from a release archive: the core, its library, the license.
fn wanted(name: &str) -> bool {
    matches!(name, "sing-box.exe" | "sing-box" | "libcronet.dll" | "LICENSE")
}

#[cfg(windows)]
fn unpack_core(buf: Vec<u8>) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(buf)).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = f.name().rsplit('/').next().unwrap_or("").to_string();
        if wanted(&name) {
            let mut data = Vec::new();
            f.read_to_end(&mut data).map_err(|e| e.to_string())?;
            out.push((name, data));
        }
    }
    Ok(out)
}

#[cfg(unix)]
fn unpack_core(buf: Vec<u8>) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(std::io::Cursor::new(buf)));
    let mut out = Vec::new();
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut f = entry.map_err(|e| e.to_string())?;
        if !f.header().entry_type().is_file() {
            continue;
        }
        let name = f.path().map_err(|e| e.to_string())?.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if wanted(&name) {
            let mut data = Vec::new();
            f.read_to_end(&mut data).map_err(|e| e.to_string())?;
            out.push((name, data));
        }
    }
    Ok(out)
}

pub struct SubResponse {
    pub body: String,
    pub info: Option<SubscriptionInfo>,
    pub title: Option<String>,
}

pub async fn subscription(http: &reqwest::Client, url: &str, user_agent: &str) -> Result<SubResponse, String> {
    let r = http
        .get(url)
        .header(reqwest::header::USER_AGENT, user_agent)
        .send()
        .await
        .map_err(|e| short_err(&e))?;
    if !r.status().is_success() {
        return Err(format!("сервер подписки ответил {}", r.status().as_u16()));
    }
    let header = |name: &str| r.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    let info = header("subscription-userinfo").map(|h| subscription::parse_userinfo(&h));
    let title = header("profile-title").and_then(|h| subscription::decode_title(&h));
    let body = r.text().await.map_err(|e| short_err(&e))?;
    Ok(SubResponse { body, info, title })
}
