//! Moving to another computer: an encrypted export and its import.

use retunl_core::bundle::{self, Bundle};
use retunl_core::util::now_unix;
use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;

use super::{St, R};
use crate::files;
use crate::util::blocking;

#[derive(Deserialize)]
pub struct ExportRequest {
    subscription_ids: Vec<String>,
    profile_ids: Vec<String>,
    rules: bool,
    presets: bool,
    password: String,
    to_file: bool,
}

#[derive(Serialize)]
pub struct ExportResult {
    /// The text form, when not saved to a file.
    text: Option<String>,
    path: Option<String>,
}

/// `2026-11-06` for a unix time (UTC).
fn ymd(t: i64) -> String {
    // Howard Hinnant's days-to-civil
    let z = t.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Encrypts the chosen subscriptions, servers, rules and templates.
#[tauri::command]
pub async fn export_bundle(app: AppHandle, st: St<'_>, request: ExportRequest) -> R<Option<ExportResult>> {
    let ExportRequest { subscription_ids, profile_ids, rules, presets, password, to_file } = request;
    if password.chars().count() < 6 {
        return Err("Пароль должен быть не короче 6 символов".into());
    }
    let data = st.snapshot();
    let b = bundle::collect(&data, &subscription_ids, &profile_ids, rules, presets);
    if b.subscriptions.is_empty() && b.profiles.is_empty() && b.rules.is_empty() && b.presets.is_empty() {
        return Err("Выберите, что перенести".into());
    }
    let text = blocking(move || bundle::seal(&b, &password))
        .await?
        .map_err(|e| e.to_string())?;
    if !to_file {
        return Ok(Some(ExportResult { text: Some(text), path: None }));
    }
    let name = format!("ReTunl {}.{}", ymd(now_unix()), bundle::EXTENSION);
    let a = app.clone();
    let picked = blocking(move || {
        a.dialog()
            .file()
            .set_title("Сохранить экспорт ReTunl")
            .set_file_name(&name)
            .add_filter("Экспорт ReTunl", &[bundle::EXTENSION])
            .blocking_save_file()
    })
    .await?;
    let Some(picked) = picked else { return Ok(None) };
    files::write(&app, &picked, text.as_bytes())?;
    Ok(Some(ExportResult { text: None, path: Some(files::shown(&picked)) }))
}

#[derive(Serialize)]
pub struct OpenedBundle {
    bundle: Bundle,
    /// Parts already on this computer.
    existing: bundle::Overlap,
}

/// Decrypts an export to show what is inside before importing.
#[tauri::command]
pub async fn open_bundle(st: St<'_>, text: String, password: String) -> R<OpenedBundle> {
    let b = blocking(move || bundle::open(&text, &password))
        .await?
        .map_err(|e| {
            let msg = e.to_string();
            let mut c = msg.chars();
            c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or(msg)
        })?;
    let existing = bundle::overlap(&st.snapshot(), &b);
    Ok(OpenedBundle { bundle: b, existing })
}

/// Adds the chosen parts of an opened export.
#[tauri::command]
pub fn import_bundle(st: St<'_>, bundle: Bundle) -> R<bundle::Merged> {
    let m = st.mutate(|d| Ok(bundle::merge(d, bundle)))?;
    st.request_reload();
    Ok(m)
}

#[cfg(test)]
mod tests {
    use retunl_core::{AppData, CustomPreset, Profile, Route, Rule, Subscription};
    use serde_json::json;

    use super::*;

    /// The shapes ui/js sends must deserialize as they are.
    #[test]
    fn ui_payloads() {
        let req: ExportRequest = serde_json::from_value(json!({
            "subscription_ids": ["s1"], "profile_ids": [], "rules": true, "presets": false,
            "password": "secret-1", "to_file": false,
        }))
        .unwrap();
        assert_eq!(req.subscription_ids, ["s1"]);
        assert!(req.rules && !req.to_file);

        // rules.js, template mode
        let p: CustomPreset = serde_json::from_value(json!({
            "id": "", "title": "Стриминг", "description": "", "match_all": false, "apps": [],
            "domains": ["netflix.com"], "ips": [], "ports": [], "rule_sets": ["geosite-netflix"],
            "network": null, "route": {"kind": "profile", "id": "p1"}, "created_at": 0,
        }))
        .unwrap();
        assert_eq!(p.route, Route::Profile { id: "p1".into() });

        // transfer.js sends back what open_bundle gave it, minus unchecked parts
        let mut data = AppData::default();
        data.subscriptions.push(Subscription { id: "s1".into(), name: "Sub".into(), url: "https://x.example/s".into(), ..Default::default() });
        data.profiles.push(Profile { subscription: Some("s1".into()), ..Profile::new("p1", "NL", json!({"type": "wireguard", "jc": 4, "h1": "1-9"})) });
        data.rules.push(Rule { id: "r1".into(), name: "x".into(), apps: vec!["a.exe".into()], ..Default::default() });
        data.presets.push(p);
        let b = bundle::collect(&data, &["s1".into()], &[], true, true);
        let opened = serde_json::to_value(OpenedBundle { existing: bundle::overlap(&data, &b), bundle: b.clone() }).unwrap();
        let mut back = opened["bundle"].clone();
        back["rules"] = json!([]);
        let b2: Bundle = serde_json::from_value(back).unwrap();
        assert_eq!(b2.subscriptions, b.subscriptions);
        assert!(b2.rules.is_empty());
        assert_eq!(opened["existing"]["subscriptions"], json!(["s1"]));
    }

    #[test]
    fn dates() {
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(ymd(1_762_387_200), "2025-11-06");
        assert_eq!(ymd(951_782_400), "2000-02-29");
    }
}
