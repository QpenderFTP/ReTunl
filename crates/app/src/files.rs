//! Files the user picks in a system dialog. On a computer they are paths;
//! on Android they are content:// links only the system can open.

use tauri::AppHandle;
use tauri_plugin_dialog::FilePath;

/// The file's name without the extension: `wg0` for `…/wg0.conf`.
pub fn stem(picked: &FilePath) -> String {
    let full = match picked {
        FilePath::Path(p) => p.to_string_lossy().into_owned(),
        FilePath::Url(u) => percent_encoding::percent_decode_str(u.as_str()).decode_utf8_lossy().into_owned(),
    };
    let name = full.rsplit(['/', '\\', ':']).next().unwrap_or("").to_string();
    match name.rsplit_once('.') {
        Some((s, _)) if !s.is_empty() => s.to_string(),
        _ => name,
    }
}

/// How to name the file to the user.
pub fn shown(picked: &FilePath) -> String {
    match picked {
        FilePath::Path(p) => p.display().to_string(),
        FilePath::Url(_) => format!("{}…", stem(picked)),
    }
}

pub fn read(_app: &AppHandle, picked: &FilePath) -> Result<Vec<u8>, String> {
    let fail = |e: std::io::Error| format!("Не удалось прочитать файл: {e}");
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_fs::FsExt;
        _app.fs().read(picked.clone()).map_err(fail)
    }
    #[cfg(not(target_os = "android"))]
    {
        let path = picked.clone().into_path().map_err(|e| e.to_string())?;
        std::fs::read(path).map_err(fail)
    }
}

pub fn write(_app: &AppHandle, picked: &FilePath, bytes: &[u8]) -> Result<(), String> {
    let fail = |e: std::io::Error| format!("Не удалось сохранить файл: {e}");
    #[cfg(target_os = "android")]
    {
        use std::io::Write;
        use tauri_plugin_fs::{FsExt, OpenOptions};
        let mut o = OpenOptions::new();
        o.write(true).create(true).truncate(true);
        let mut f = _app.fs().open(picked.clone(), o).map_err(fail)?;
        f.write_all(bytes).map_err(fail)
    }
    #[cfg(not(target_os = "android"))]
    {
        let path = picked.clone().into_path().map_err(|e| e.to_string())?;
        std::fs::write(path, bytes).map_err(fail)
    }
}
