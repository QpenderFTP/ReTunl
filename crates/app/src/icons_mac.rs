//! Program icons for the app picker and the activity list (macOS: the app
//! bundle's .icns → PNG data URL, converted by the system's `sips`).

use std::path::Path;
use std::process::Command;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub fn exe_icon_data_url(path: &str) -> Option<String> {
    let (bundle, _) = crate::sys::app_bundle(path)?;
    let contents = Path::new(bundle).join("Contents");
    let plist = contents.join("Info.plist");
    let out = Command::new("/usr/bin/plutil")
        .args(["-extract", "CFBundleIconFile", "raw", "-o", "-"])
        .arg(&plist)
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || name.is_empty() {
        return None; // apps with only an asset catalog icon
    }
    let file = if name.ends_with(".icns") { name } else { format!("{name}.icns") };
    let icns = contents.join("Resources").join(file);
    if !icns.exists() {
        return None;
    }
    let tmp = std::env::temp_dir().join(format!("retunl-icon-{}.png", uuid::Uuid::new_v4().simple()));
    let ok = Command::new("/usr/bin/sips")
        .args(["-s", "format", "png", "-Z", "64"])
        .arg(&icns)
        .arg("--out")
        .arg(&tmp)
        .output()
        .is_ok_and(|o| o.status.success());
    let png = ok.then(|| std::fs::read(&tmp).ok()).flatten();
    let _ = std::fs::remove_file(&tmp);
    Some(format!("data:image/png;base64,{}", STANDARD.encode(png?)))
}
