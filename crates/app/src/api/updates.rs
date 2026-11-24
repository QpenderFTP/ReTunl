//! Stable GitHub releases. The UI can request a version, never a URL or executable.
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

use super::{St, R};

const API: &str = "https://api.github.com/repos/QpenderFTP/ReTunl/releases/latest";
const DOWNLOAD: &str = "https://github.com/QpenderFTP/ReTunl/releases/download";
const MAX_SIZE: u64 = 160 * 1024 * 1024;
static INSTALL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    size: u64,
    digest: Option<String>,
}

impl Release {
    fn newer(&self, current: &Version) -> R<Option<Version>> {
        if self.draft || self.prerelease {
            return Ok(None);
        }
        let v = self
            .tag_name
            .strip_prefix('v')
            .and_then(|s| Version::parse(s).ok())
            .ok_or("Некорректный тег релиза ReTunl на GitHub")?;
        Ok((v.pre.is_empty() && v.build.is_empty() && &v > current).then_some(v))
    }

    fn asset(&self, version: &Version, suffix: &str) -> R<&Asset> {
        let name = format!("ReTunl_{version}_{suffix}");
        let a = self
            .assets
            .iter()
            .find(|a| a.name == name)
            .ok_or_else(|| format!("В релизе пока нет файла {name}. Попробуйте позже."))?;
        if a.size == 0
            || a.size > MAX_SIZE
            || !a
                .digest
                .as_deref()
                .and_then(|d| d.strip_prefix("sha256:"))
                .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("GitHub не предоставил допустимый размер или SHA-256 установщика.".into());
        }
        Ok(a)
    }
}

fn suffix() -> R<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Ok("x64-setup.exe"),
        ("macos", "x86_64" | "aarch64") => Ok("universal.pkg"),
        ("android", "aarch64") => Ok("arm64.apk"),
        ("android", "arm") => Ok("armv7.apk"),
        _ => Err("Для этой архитектуры пока нет установщика в GitHub Releases.".into()),
    }
}

async fn latest(http: &Client) -> R<Release> {
    http.get(API)
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("Не удалось проверить релиз на GitHub: {e}"))?
        .json()
        .await
        .map_err(|e| format!("Не удалось прочитать ответ GitHub: {e}"))
}

fn current() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("Cargo package version")
}

#[tauri::command]
pub async fn check_update(st: St<'_>) -> R<Option<String>> {
    let release = latest(&st.http).await?;
    let Some(v) = release.newer(&current())? else {
        return Ok(None);
    };
    release.asset(&v, suffix()?)?;
    Ok(Some(v.to_string()))
}

async fn download(http: &Client, release: &Release, asset: &Asset, dir: &Path) -> R<PathBuf> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut temp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    let url = format!("{DOWNLOAD}/{}/{}", release.tag_name, asset.name);
    let mut response = http
        .get(url)
        .timeout(Duration::from_secs(600))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("Не удалось скачать обновление: {e}"))?;
    let mut hash = Sha256::new();
    let mut received = 0u64;
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        received += chunk.len() as u64;
        if received > asset.size {
            return Err("Размер загружаемого файла превышает размер из релиза.".into());
        }
        hash.update(&chunk);
        temp.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    persist_verified(temp, asset, received, hash)
}

fn persist_verified(
    temp: tempfile::NamedTempFile,
    asset: &Asset,
    received: u64,
    hash: Sha256,
) -> R<PathBuf> {
    let digest = format!("sha256:{:x}", hash.finalize());
    if received != asset.size
        || !asset
            .digest
            .as_deref()
            .is_some_and(|d| d.eq_ignore_ascii_case(&digest))
    {
        return Err("Размер или SHA-256 установщика не совпал с релизом GitHub.".into());
    }
    let ext = Path::new(&asset.name)
        .extension()
        .ok_or("У установщика нет расширения")?;
    let dest = temp
        .path()
        .with_file_name("ReTunl-update")
        .with_extension(ext);
    temp.persist(&dest).map_err(|e| e.to_string())?;
    Ok(dest)
}

fn staging(app: &AppHandle) -> R<PathBuf> {
    // An elevated process must never execute a download from a user-writable cache.
    #[cfg(windows)]
    if crate::sys::is_elevated() {
        use winreg::{enums::*, RegKey};
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion",
                KEY_READ | KEY_WOW64_64KEY,
            )
            .map_err(|e| e.to_string())?;
        let base: String = key
            .get_value("ProgramFilesDir")
            .map_err(|e| e.to_string())?;
        return Ok(PathBuf::from(base).join("ReTunl Update Cache"));
    }
    app.path()
        .app_cache_dir()
        .map(|p| p.join("updates"))
        .map_err(|e| e.to_string())
}

fn launch(path: &Path) -> R<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};
        let file: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                crate::sys::wide("runas").as_ptr(),
                file.as_ptr(),
                crate::sys::wide("/UPDATE /P /R").as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        } as isize;
        if result <= 32 {
            return Err(format!("Установщик Windows не запущен (код {result})."));
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("/usr/bin/open")
            .arg("-b")
            .arg("com.apple.installer")
            .arg(path)
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err("Не удалось открыть установщик macOS.".into())
        }
    }
    #[cfg(target_os = "android")]
    {
        tauri_plugin_retunl_vpn::install_update(path.to_str().ok_or("Некорректный путь APK")?)
    }
}

#[tauri::command]
pub async fn install_update(app: AppHandle, st: St<'_>, version: String) -> R<()> {
    let _guard = INSTALL
        .try_lock()
        .map_err(|_| "Обновление уже загружается")?;
    if st.paths.portable {
        return Err("Для портативной копии установите новую версию отдельно.".into());
    }
    let release = latest(&st.http).await?;
    let v = release
        .newer(&current())?
        .filter(|v| v.to_string() == version)
        .ok_or("Релиз изменился. Проверьте обновления ещё раз.")?;
    let asset = release.asset(&v, suffix()?)?;
    #[cfg(windows)]
    if !st.elevated {
        if std::env::args().any(|a| a == "--install-update") {
            return Err("Windows не предоставила права для обновления ReTunl.".into());
        }
        let args = format!("--wait-pid {} --install-update {v}", std::process::id());
        crate::util::blocking(move || crate::sys::relaunch_elevated(&args)).await??;
        st.engine.stop().await;
        app.exit(0);
        return Ok(());
    }
    #[cfg(target_os = "android")]
    crate::util::blocking(tauri_plugin_retunl_vpn::allow_install_update).await??;
    let path = download(&st.http, &release, asset, &staging(&app)?).await?;
    #[cfg(desktop)]
    st.engine.stop().await;
    crate::util::blocking(move || launch(&path)).await??;
    #[cfg(desktop)]
    app.exit(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str) -> Release {
        Release {
            tag_name: tag.into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        }
    }

    #[test]
    fn only_newer_stable_releases() {
        let current = Version::new(0, 2, 9);
        assert_eq!(
            release("v0.2.10").newer(&current).unwrap(),
            Some(Version::new(0, 2, 10))
        );
        for tag in ["v0.2.8", "v0.2.9", "v1.0.0-beta.1"] {
            assert!(release(tag).newer(&current).unwrap().is_none());
        }
        assert!(release("v../setup").newer(&current).is_err());
        let mut r = release("v1.0.0");
        r.draft = true;
        assert!(r.newer(&current).unwrap().is_none());
        r.draft = false;
        r.prerelease = true;
        assert!(r.newer(&current).unwrap().is_none());
    }

    #[test]
    fn rejects_incomplete_and_wrong_assets() {
        let mut r = release("v1.2.3");
        let v = Version::new(1, 2, 3);
        r.assets.push(Asset {
            name: "ReTunl_1.2.3_arm64.apk".into(),
            size: 3,
            digest: None,
        });
        assert!(r.asset(&v, "arm64.apk").is_err());
        r.assets[0].digest = Some(format!("sha256:{:x}", Sha256::digest(b"apk")));
        assert!(r.asset(&v, "arm64.apk").is_ok());
        assert!(r.asset(&v, "armv7.apk").is_err());
        r.assets[0].size = MAX_SIZE + 1;
        assert!(r.asset(&v, "arm64.apk").is_err());
    }

    #[test]
    fn failed_verification_preserves_previous_download() {
        let dir = tempfile::tempdir().unwrap();
        let a = Asset {
            name: "test.pkg".into(),
            size: 3,
            digest: Some(format!("sha256:{:x}", Sha256::digest(b"pkg"))),
        };
        let save = |data: &[u8]| {
            let mut f = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
            f.write_all(data).unwrap();
            persist_verified(f, &a, data.len() as u64, Sha256::new().chain_update(data))
        };
        let dest = save(b"pkg").unwrap();
        assert!(save(b"bad").is_err());
        assert!(save(b"p").is_err());
        assert_eq!(fs::read(dest).unwrap(), b"pkg");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    #[ignore = "downloads a public installer from GitHub without launching it"]
    async fn public_release_download() {
        let http = crate::fetch::http_client();
        let r = latest(&http).await.unwrap();
        let v = r.newer(&Version::new(0, 0, 0)).unwrap().unwrap();
        let asset = r.asset(&v, "x64-setup.exe").unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = download(&http, &r, asset, dir.path()).await.unwrap();
        assert_eq!(fs::metadata(path).unwrap().len(), asset.size);
    }
}
