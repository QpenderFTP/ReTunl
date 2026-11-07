use std::path::PathBuf;

use retunl_core::awg::CoreKind;

/// The sing-box executable's file name.
pub const CORE_EXE: &str = if cfg!(windows) { "sing-box.exe" } else { "sing-box" };

/// What [`Paths::find_core`] gives on Android, where the core is part of the app.
pub const BUILT_IN: &str = "встроено в приложение";

/// Where ReTunl keeps things.
///
/// * settings, servers, rules — `%APPDATA%\ReTunl\data.json`
///   (macOS: `~/Library/Application Support/ReTunl`);
/// * sing-box, rule sets, runtime files — `%LOCALAPPDATA%\ReTunl` (macOS: the same folder);
/// * portable mode: a file named `portable` next to the exe puts all of it
///   into `<exe folder>\data`.
#[derive(Clone, Debug)]
pub struct Paths {
    pub exe_dir: PathBuf,
    pub data_dir: PathBuf,
    pub local_dir: PathBuf,
    pub portable: bool,
}

#[cfg(target_os = "android")]
static ANDROID_DIRS: std::sync::OnceLock<(PathBuf, PathBuf)> = std::sync::OnceLock::new();

impl Paths {
    /// The folders for this app, created if missing. Android keeps them in
    /// the app's private storage, which only the system tells us.
    pub fn for_app(_app: &tauri::AppHandle) -> Paths {
        #[cfg(target_os = "android")]
        {
            use tauri::Manager;
            let path = _app.path();
            let data = path.app_data_dir().unwrap_or_else(|_| PathBuf::from("/data/local/tmp/retunl"));
            let local = path.app_local_data_dir().unwrap_or_else(|_| data.clone());
            let _ = ANDROID_DIRS.set((data, local));
        }
        Paths::new()
    }

    /// The folders, created if missing.
    pub fn new() -> Paths {
        let p = Paths::resolve(true);
        for d in [&p.data_dir, &p.core_dir(), &p.ruleset_dir(), &p.run_dir()] {
            let _ = std::fs::create_dir_all(d);
        }
        p
    }

    /// The folders as they are: nothing is created or moved.
    pub fn locate() -> Paths {
        Paths::resolve(false)
    }

    fn resolve(migrate: bool) -> Paths {
        #[cfg(target_os = "android")]
        if let Some((data, local)) = ANDROID_DIRS.get() {
            return Paths { exe_dir: data.clone(), data_dir: data.clone(), local_dir: local.clone(), portable: false };
        }
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        let portable = exe_dir.join("portable").exists();
        let (data_dir, local_dir) = if portable {
            (exe_dir.join("data"), exe_dir.join("data"))
        } else {
            let roaming = dirs::config_dir().unwrap_or_else(|| exe_dir.clone()).join("ReTunl");
            let local = dirs::data_local_dir().unwrap_or_else(|| exe_dir.clone()).join("ReTunl");
            // The app used to be called «Развилка»: pick up its folders once.
            for dir in [&roaming, &local] {
                let old = dir.with_file_name("Razvilka");
                if migrate && !dir.exists() && old.is_dir() {
                    let _ = std::fs::rename(&old, dir);
                }
            }
            (roaming, local)
        };
        Paths { exe_dir, data_dir, local_dir, portable }
    }

    pub fn data_file(&self) -> PathBuf {
        self.data_dir.join("data.json")
    }

    pub fn core_dir(&self) -> PathBuf {
        self.local_dir.join("core")
    }

    pub fn ruleset_dir(&self) -> PathBuf {
        self.local_dir.join("rule-sets")
    }

    pub fn run_dir(&self) -> PathBuf {
        self.local_dir.join("run")
    }

    /// sing-box: `RETUNL_CORE`, next to the app, or the downloaded copy.
    /// On Android it is built into the app (both kinds: sing-box-lx).
    pub fn find_core(&self) -> Option<PathBuf> {
        if cfg!(target_os = "android") {
            return Some(PathBuf::from(BUILT_IN));
        }
        if let Ok(p) = std::env::var("RETUNL_CORE") {
            let p = PathBuf::from(p);
            if p.exists() {
                return Some(p);
            }
        }
        [
            self.exe_dir.join("core").join(CORE_EXE),
            self.exe_dir.join(CORE_EXE),
            self.core_dir().join(CORE_EXE),
        ]
        .into_iter()
        .find(|p| p.exists())
    }

    /// Where the downloaded sing-box-lx goes.
    pub fn lx_core_dir(&self) -> PathBuf {
        self.core_dir().join("lx")
    }

    /// sing-box-lx: `RETUNL_CORE_LX`, `core-lx` next to the app, or the downloaded copy.
    pub fn find_lx_core(&self) -> Option<PathBuf> {
        if cfg!(target_os = "android") {
            return Some(PathBuf::from(BUILT_IN));
        }
        if let Ok(p) = std::env::var("RETUNL_CORE_LX") {
            let p = PathBuf::from(p);
            if p.exists() {
                return Some(p);
            }
        }
        [self.exe_dir.join("core-lx").join(CORE_EXE), self.lx_core_dir().join(CORE_EXE)]
            .into_iter()
            .find(|p| p.exists())
    }

    pub fn core_for(&self, kind: CoreKind) -> Option<PathBuf> {
        match kind {
            CoreKind::Official => self.find_core(),
            CoreKind::Extended => self.find_lx_core(),
        }
    }
}
