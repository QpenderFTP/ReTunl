use std::path::Path;

use retunl_core::AppData;

/// Read saved data. A damaged file is kept aside and the app starts clean.
pub fn load(path: &Path) -> (AppData, Option<String>) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (AppData::default(), None),
        Err(e) => return (AppData::default(), Some(format!("Не удалось прочитать {}: {e}", path.display()))),
    };
    match serde_json::from_str::<AppData>(&text) {
        Ok(d) => (d, None),
        Err(e) => {
            let aside = path.with_extension(format!("broken-{}.json", retunl_core::util::now_unix()));
            let _ = std::fs::copy(path, &aside);
            (
                AppData::default(),
                Some(format!("Файл настроек повреждён ({e}). Копия сохранена как {}", aside.display())),
            )
        }
    }
}

/// Write through a temporary file so a crash never leaves half a file.
pub fn save(path: &Path, data: &AppData) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(data).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    if path.exists() {
        let _ = std::fs::copy(path, path.with_extension("json.bak"));
    }
    std::fs::rename(&tmp, path)
}
