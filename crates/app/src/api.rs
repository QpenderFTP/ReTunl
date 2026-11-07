//! Commands the UI calls. Thin: checks input, changes data, asks the engine.

use std::collections::HashMap;
use std::sync::Arc;

use retunl_core::awg::CoreKind;
use retunl_core::bundle::{self, Bundle};
use retunl_core::links::ParsedLink;
use retunl_core::presets::{self, Preset};
use retunl_core::rulesets::{self, CatalogEntry};
use retunl_core::singbox::{self, validate_rule, BuildOptions};
use retunl_core::subscription::{self, ImportResult};
use retunl_core::util::{new_id, now_unix};
use retunl_core::{dns, wgconf, AppData, CustomPreset, Profile, Route, Rule, Settings, Subscription};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

use crate::blocks::BlockStats;
use crate::engine::{LogLine, Poll, Status, NEED_ADMIN};
use crate::probe::{self, Latency};
use crate::speed::{self, SpeedResult};
use crate::state::{add_profiles, forget_profiles, merge_subscription, AppState};
use crate::sys::{self, Adapter, Autostart, ProcInfo};
use crate::{fetch, files, icons};

type St<'a> = State<'a, Arc<AppState>>;
type R<T> = Result<T, String>;

const SUB_USER_AGENT: &str = "v2rayN/7.10 ReTunl/0.1";

// ---------- state ----------

#[derive(Serialize)]
pub struct CoreInfo {
    path: Option<String>,
    expected: &'static str,
    /// sing-box-lx (AmneziaWG, XHTTP).
    lx_path: Option<String>,
    lx_expected: &'static str,
    /// Profiles that want sing-box-lx: id → "extended" (only runs there) or
    /// "prefer" (runs on the official core with AmneziaWG junk dropped).
    needs: HashMap<String, &'static str>,
}

fn core_needs(d: &AppData) -> HashMap<String, &'static str> {
    use retunl_core::awg::CoreNeed;
    d.profiles
        .iter()
        .filter_map(|p| match p.core_need() {
            CoreNeed::Extended => Some((p.id.clone(), "extended")),
            CoreNeed::PreferExtended => Some((p.id.clone(), "prefer")),
            CoreNeed::Any => None,
        })
        .collect()
}

#[derive(Serialize)]
pub struct View {
    data: AppData,
    status: Status,
    elevated: bool,
    core: CoreInfo,
    latency: HashMap<String, Latency>,
    autostart: Autostart,
    version: &'static str,
    data_dir: String,
    portable: bool,
    warning: Option<String>,
    /// "windows" or "macos": the UI words things for the system
    platform: &'static str,
    blocks: BlockStats,
    /// The last speed test.
    speed: Option<SpeedResult>,
}

#[tauri::command]
pub fn get_state(st: St<'_>) -> View {
    let data = st.snapshot();
    let needs = core_needs(&data);
    View {
        data,
        status: st.engine.status(),
        elevated: st.elevated,
        core: CoreInfo {
            path: st.paths.find_core().map(|p| p.display().to_string()),
            expected: retunl_core::SING_BOX_VERSION,
            lx_path: st.paths.find_lx_core().map(|p| p.display().to_string()),
            lx_expected: retunl_core::SING_BOX_LX_VERSION,
            needs,
        },
        latency: st.latency.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        autostart: sys::autostart_status(),
        version: env!("CARGO_PKG_VERSION"),
        data_dir: st.paths.data_dir.display().to_string(),
        portable: st.paths.portable,
        warning: st.warning.lock().unwrap_or_else(|e| e.into_inner()).take(),
        platform: std::env::consts::OS,
        blocks: st.engine.blocks.stats(),
        speed: st.speed.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    }
}

#[derive(Serialize)]
pub struct DnsChoice {
    value: &'static str,
    label: &'static str,
}

#[derive(Serialize)]
pub struct Catalog {
    presets: Vec<Preset>,
    rule_sets: &'static [CatalogEntry],
    dns: Vec<DnsChoice>,
}

#[tauri::command]
pub fn get_catalog() -> Catalog {
    Catalog {
        presets: presets::available(),
        rule_sets: rulesets::CATALOG,
        dns: dns::PRESETS.iter().map(|(value, label)| DnsChoice { value, label }).collect(),
    }
}

// ---------- import ----------

#[derive(Serialize, Default)]
pub struct ImportErr {
    what: String,
    error: String,
}

#[derive(Serialize, Default)]
pub struct ImportSummary {
    added: Vec<String>,
    names: Vec<String>,
    duplicates: usize,
    errors: Vec<ImportErr>,
    warnings: Vec<String>,
    subscriptions: Vec<String>,
    /// The text is an encrypted ReTunl export: the UI asks for its password.
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle: Option<String>,
    /// AmneziaVPN full-access keys: these servers went to «Мои серверы».
    admin: Vec<crate::admin::ServerView>,
}

fn apply_import(st: &Arc<AppState>, res: ImportResult) -> R<ImportSummary> {
    let mut sum = ImportSummary {
        errors: res.errors.into_iter().map(|(what, error)| ImportErr { what, error }).collect(),
        warnings: res.warnings,
        ..Default::default()
    };
    let names: Vec<String> = res.profiles.iter().map(|p| p.name.clone()).collect();
    let links = res.links;
    let profiles = res.profiles;
    let (added, dups) = st.mutate(|d| Ok(add_profiles(d, profiles, None, &links)))?;
    sum.names = names;
    sum.added = added;
    sum.duplicates = dups;
    Ok(sum)
}

async fn import_any(st: &Arc<AppState>, text: &str) -> R<ImportSummary> {
    if bundle::looks_like(text) {
        return Ok(ImportSummary { bundle: Some(text.trim().to_string()), ..Default::default() });
    }
    // full-access keys carry a server login, not a connection
    let mut admin = Vec::new();
    let mut rest = text.to_string();
    for token in text.split_whitespace() {
        if let Some(a) = retunl_core::links::admin_access(token) {
            admin.push(st.admin.add_access(a).await?);
            rest = rest.replace(token, "");
        }
    }
    if !admin.is_empty() {
        let mut sum = if rest.trim().is_empty() { ImportSummary::default() } else { Box::pin(import_any(st, &rest)).await.unwrap_or_default() };
        sum.admin = admin;
        return Ok(sum);
    }
    let res = subscription::parse_text(text);
    if res.profiles.is_empty() && !res.urls.is_empty() {
        let mut sum = ImportSummary::default();
        for url in res.urls.clone() {
            match add_subscription_inner(st, url.clone(), None).await {
                Ok(s) => {
                    sum.added.extend(s.added);
                    sum.names.extend(s.names);
                    sum.subscriptions.extend(s.subscriptions);
                    sum.errors.extend(s.errors);
                }
                Err(e) => sum.errors.push(ImportErr { what: url, error: e }),
            }
        }
        return Ok(sum);
    }
    if res.profiles.is_empty() && res.errors.is_empty() {
        return Err("Не нашёл ни одной ссылки на сервер. Поддерживаются vless://, vmess://, trojan://, ss://, hy2://, hysteria://, tuic://, wireguard://, socks://, anytls://, ключи AmneziaVPN vpn://, ссылки на подписку, файлы WireGuard и AmneziaWG, экспорт ReTunl.".into());
    }
    let sum = apply_import(st, res)?;
    st.request_reload();
    Ok(sum)
}

#[tauri::command]
pub async fn import_text(st: St<'_>, text: String) -> R<ImportSummary> {
    import_any(st.inner(), &text).await
}

#[tauri::command]
pub async fn import_clipboard(app: AppHandle, st: St<'_>) -> R<ImportSummary> {
    let text = app.clipboard().read_text().ok().filter(|t| !t.trim().is_empty()).ok_or("В буфере обмена нет текста.")?;
    import_any(st.inner(), &text).await
}

#[tauri::command]
pub async fn import_file(app: AppHandle, st: St<'_>) -> R<Option<ImportSummary>> {
    let a = app.clone();
    let picked = tokio::task::spawn_blocking(move || {
        let d = a.dialog().file().set_title("Файл конфигурации");
        // Android filters by file type, and .conf has none: show everything there
        let d = if cfg!(target_os = "android") {
            d
        } else {
            d.add_filter("Конфигурации и экспорт ReTunl", &["conf", "txt", "json", bundle::EXTENSION]).add_filter("Все файлы", &["*"])
        };
        d.blocking_pick_file()
    })
    .await
    .map_err(|e| e.to_string())?;
    let Some(picked) = picked else { return Ok(None) };
    let bytes = files::read(&app, &picked)?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    if wgconf::looks_like_wg_conf(&text) {
        let stem = files::stem(&picked);
        return match wgconf::parse(&text, &stem) {
            Ok(w) => {
                let res = ImportResult { profiles: vec![w.profile], links: vec![None], warnings: w.warnings, ..Default::default() };
                let sum = apply_import(st.inner(), res)?;
                st.request_reload();
                Ok(Some(sum))
            }
            Err(e) => Err(e.to_string()),
        };
    }
    import_any(st.inner(), &text).await.map(Some)
}

// ---------- subscriptions ----------

fn host_of(url: &str) -> String {
    url.split("://").nth(1).and_then(|r| r.split(['/', '?', '#']).next()).unwrap_or(url).to_string()
}

async fn add_subscription_inner(st: &Arc<AppState>, url: String, name: Option<String>) -> R<ImportSummary> {
    let url = url.trim().to_string();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("Адрес подписки должен начинаться с https://".into());
    }
    if let Some(existing) = st.snapshot().subscriptions.iter().find(|s| s.url == url) {
        return update_subscription_inner(st, &existing.id).await;
    }
    let resp = fetch::subscription(&st.http, &url, SUB_USER_AGENT).await.map_err(|e| format!("Подписка: {e}"))?;
    let parsed = subscription::parse_text(&resp.body);
    if parsed.profiles.is_empty() {
        let why = parsed.errors.first().map(|(_, e)| format!(" ({e})")).unwrap_or_default();
        return Err(format!("В подписке не нашлось серверов, которые понимает sing-box{why}."));
    }
    let id = new_id();
    let sub_name = name.filter(|n| !n.trim().is_empty()).or(resp.title).unwrap_or_else(|| host_of(&url));
    let names: Vec<String> = parsed.profiles.iter().map(|p| p.name.clone()).collect();
    let errors = parsed.errors.iter().map(|(w, e)| ImportErr { what: w.clone(), error: e.clone() }).collect();
    let profiles = parsed.profiles;
    let sid = id.clone();
    st.mutate(move |d| {
        d.subscriptions.push(Subscription {
            id: sid.clone(),
            name: sub_name,
            url,
            updated_at: Some(now_unix()),
            info: resp.info,
            last_error: None,
        });
        merge_subscription(d, &sid, profiles);
        if d.active_profile().is_none() {
            d.settings.active_profile = d.profiles.iter().find(|p| p.subscription.as_deref() == Some(&sid)).map(|p| p.id.clone());
        }
        Ok(())
    })?;
    st.request_reload();
    Ok(ImportSummary { names, errors, subscriptions: vec![id], ..Default::default() })
}

async fn update_subscription_inner(st: &Arc<AppState>, id: &str) -> R<ImportSummary> {
    let sub = st.snapshot().subscriptions.into_iter().find(|s| s.id == id).ok_or("Подписка не найдена")?;
    let result = fetch::subscription(&st.http, &sub.url, SUB_USER_AGENT).await;
    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("Подписка «{}»: {e}", sub.name);
            let _ = st.mutate(|d| {
                if let Some(s) = d.subscriptions.iter_mut().find(|s| s.id == sub.id) {
                    s.last_error = Some(e.clone());
                }
                Ok(())
            });
            return Err(msg);
        }
    };
    let parsed = subscription::parse_text(&resp.body);
    if parsed.profiles.is_empty() {
        return Err(format!("Подписка «{}» вернула пустой список — старые серверы оставлены.", sub.name));
    }
    let names: Vec<String> = parsed.profiles.iter().map(|p| p.name.clone()).collect();
    let errors = parsed.errors.iter().map(|(w, e)| ImportErr { what: w.clone(), error: e.clone() }).collect();
    let profiles = parsed.profiles;
    let active_before = st.snapshot().settings.active_profile;
    st.mutate(|d| {
        merge_subscription(d, &sub.id, profiles);
        if let Some(s) = d.subscriptions.iter_mut().find(|s| s.id == sub.id) {
            s.updated_at = Some(now_unix());
            s.last_error = None;
            if resp.info.is_some() {
                s.info = resp.info;
            }
        }
        Ok(())
    })?;
    if st.snapshot().settings.active_profile != active_before || st.engine.is_active() {
        st.request_reload();
    }
    Ok(ImportSummary { names, errors, subscriptions: vec![sub.id], ..Default::default() })
}

pub async fn update_subscription_for(st: &Arc<AppState>, id: &str) -> R<()> {
    update_subscription_inner(st, id).await.map(|_| ())
}

#[tauri::command]
pub async fn add_subscription(st: St<'_>, url: String, name: Option<String>) -> R<ImportSummary> {
    add_subscription_inner(st.inner(), url, name).await
}

#[tauri::command]
pub async fn update_subscription(st: St<'_>, id: String) -> R<ImportSummary> {
    update_subscription_inner(st.inner(), &id).await
}

#[tauri::command]
pub async fn update_all_subscriptions(st: St<'_>) -> R<Vec<String>> {
    let mut errors = Vec::new();
    for s in st.snapshot().subscriptions {
        if let Err(e) = update_subscription_inner(st.inner(), &s.id).await {
            errors.push(e);
        }
    }
    Ok(errors)
}

#[tauri::command]
pub fn rename_subscription(st: St<'_>, id: String, name: String) -> R<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Название не может быть пустым".into());
    }
    st.mutate(|d| {
        let s = d.subscriptions.iter_mut().find(|s| s.id == id).ok_or("Подписка не найдена")?;
        s.name = name;
        Ok(())
    })
}

#[tauri::command]
pub fn delete_subscription(st: St<'_>, id: String) -> R<()> {
    st.mutate(|d| {
        let removed: Vec<String> = d.profiles.iter().filter(|p| p.subscription.as_deref() == Some(&id)).map(|p| p.id.clone()).collect();
        d.profiles.retain(|p| p.subscription.as_deref() != Some(&id));
        d.subscriptions.retain(|s| s.id != id);
        forget_profiles(d, &removed, None);
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

// ---------- servers ----------

#[tauri::command]
pub fn set_active(st: St<'_>, id: String) -> R<()> {
    st.mutate(|d| {
        if d.profile(&id).is_none() {
            return Err("Сервер не найден".into());
        }
        d.settings.active_profile = Some(id.clone());
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

#[tauri::command]
pub fn rename_profile(st: St<'_>, id: String, name: String) -> R<()> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Название не может быть пустым".into());
    }
    st.mutate(|d| {
        let p = d.profiles.iter_mut().find(|p| p.id == id).ok_or("Сервер не найден")?;
        p.name = name;
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

/// Replace a server's sing-box settings with edited JSON.
#[tauri::command]
pub fn set_profile_json(st: St<'_>, id: String, json: String) -> R<()> {
    let mut v: Value = serde_json::from_str(&json).map_err(|e| format!("Ошибка в JSON: {e}"))?;
    let obj = v.as_object_mut().ok_or("Нужен JSON-объект { … }")?;
    obj.remove("tag");
    let ty = obj.get("type").and_then(Value::as_str).ok_or("Не указан \"type\" (протокол)")?;
    if !retunl_core::PROXY_TYPES.contains(&ty) {
        return Err(format!("Неизвестный протокол «{ty}»"));
    }
    st.mutate(|d| {
        let p = d.profiles.iter_mut().find(|p| p.id == id).ok_or("Сервер не найден")?;
        p.outbound = v;
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

#[tauri::command]
pub fn delete_profiles(st: St<'_>, ids: Vec<String>) -> R<usize> {
    let fixed = st.mutate(|d| {
        d.profiles.retain(|p| !ids.contains(&p.id));
        Ok(forget_profiles(d, &ids, None))
    })?;
    st.request_reload();
    Ok(fixed)
}

#[tauri::command]
pub fn add_interface(st: St<'_>, name: String) -> R<String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Выберите адаптер".into());
    }
    let item = ParsedLink { name: name.clone(), outbound: serde_json::json!({"type": "direct", "bind_interface": name}) };
    let (added, _) = st.mutate(|d| Ok(add_profiles(d, vec![item], None, &[None])))?;
    added.first().cloned().ok_or_else(|| "Такой адаптер уже добавлен".into())
}

#[tauri::command]
pub async fn list_adapters() -> R<Vec<Adapter>> {
    tokio::task::spawn_blocking(sys::adapters).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn test_latency(st: St<'_>, ids: Option<Vec<String>>) -> R<HashMap<String, Latency>> {
    let data = st.snapshot();
    let profiles: Vec<Profile> = data
        .profiles
        .iter()
        .filter(|p| ids.as_ref().is_none_or(|ids| ids.contains(&p.id)))
        .cloned()
        .collect();
    if profiles.is_empty() {
        return Ok(HashMap::new());
    }
    let results = probe::measure(&st.paths, &data.settings, profiles, st.engine.job()).await?;
    st.latency.lock().unwrap_or_else(|e| e.into_inner()).extend(results.clone());
    Ok(results)
}

/// Download speed and ping without the VPN and through the selected server.
/// Progress comes as `speed-progress` events.
#[tauri::command]
pub async fn speed_test(app: AppHandle, st: St<'_>) -> R<SpeedResult> {
    let Ok(_running) = st.speed_lock.try_lock() else {
        return Err("Проверка скорости уже идёт.".into());
    };
    let data = st.snapshot();
    let profile = data.active_profile().cloned();
    let h = app.clone();
    let r = speed::run(&st.paths, &data.settings, profile, st.engine.job(), move |p| {
        let _ = h.emit("speed-progress", &p);
    })
    .await?;
    *st.speed.lock().unwrap_or_else(|e| e.into_inner()) = Some(r.clone());
    Ok(r)
}

// ---------- rules ----------

fn clean(list: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in list {
        let t = item.trim().to_string();
        if !t.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
            out.push(t);
        }
    }
    out
}

#[tauri::command]
pub fn save_rule(st: St<'_>, rule: Rule) -> R<Rule> {
    let mut rule = rule;
    rule.name = rule.name.trim().to_string();
    rule.apps = clean(rule.apps);
    rule.domains = clean(rule.domains);
    rule.ips = clean(rule.ips);
    rule.ports = clean(rule.ports);
    rule.rule_sets = clean(rule.rule_sets);
    rule.network = rule.network.map(|n| n.trim().to_lowercase()).filter(|n| !n.is_empty());
    validate_rule(&rule)?;
    if let Route::Profile { id } = &rule.route {
        if st.snapshot().profile(id).is_none() {
            return Err("Выбранный в правиле сервер не найден".into());
        }
    }
    if rule.id.is_empty() {
        rule.id = new_id();
    }
    let saved = rule.clone();
    st.mutate(|d| {
        match d.rules.iter_mut().find(|r| r.id == rule.id) {
            Some(r) => *r = rule,
            None => d.rules.push(rule),
        }
        Ok(())
    })?;
    st.request_reload();
    Ok(saved)
}

#[tauri::command]
pub fn delete_rule(st: St<'_>, id: String) -> R<()> {
    st.mutate(|d| {
        d.rules.retain(|r| r.id != id);
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

#[tauri::command]
pub fn set_rule_enabled(st: St<'_>, id: String, enabled: bool) -> R<()> {
    st.mutate(|d| {
        let r = d.rules.iter_mut().find(|r| r.id == id).ok_or("Правило не найдено")?;
        r.enabled = enabled;
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

/// New order of rules (first match wins).
#[tauri::command]
pub fn reorder_rules(st: St<'_>, ids: Vec<String>) -> R<()> {
    st.mutate(|d| {
        let mut rules = std::mem::take(&mut d.rules);
        let mut ordered = Vec::with_capacity(rules.len());
        for id in &ids {
            if let Some(i) = rules.iter().position(|r| &r.id == id) {
                ordered.push(rules.remove(i));
            }
        }
        ordered.extend(rules);
        d.rules = ordered;
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

/// Adds a rule from a built-in template or one of the user's own.
#[tauri::command]
pub fn add_preset(st: St<'_>, id: String) -> R<Rule> {
    let saved = st.mutate(|d| {
        let mut rule = match d.presets.iter().find(|p| p.id == id) {
            Some(own) => own.to_rule(new_id()),
            None => presets::instantiate(&presets::find(&id).ok_or("Шаблон не найден")?),
        };
        // the template may point at a server that is gone by now
        if let Route::Profile { id } = &rule.route {
            if d.profile(id).is_none() {
                rule.route = Route::Proxy;
            }
        }
        d.rules.push(rule.clone());
        Ok(rule)
    })?;
    st.request_reload();
    Ok(saved)
}

/// Creates or updates one of the user's own templates.
#[tauri::command]
pub fn save_preset(st: St<'_>, preset: CustomPreset) -> R<CustomPreset> {
    let mut p = preset;
    p.title = p.title.trim().to_string();
    p.description = p.description.trim().to_string();
    if p.title.is_empty() {
        return Err("Укажите название шаблона".into());
    }
    p.apps = clean(p.apps);
    p.domains = clean(p.domains);
    p.ips = clean(p.ips);
    p.ports = clean(p.ports);
    p.rule_sets = clean(p.rule_sets);
    p.network = p.network.map(|n| n.trim().to_lowercase()).filter(|n| !n.is_empty());
    validate_rule(&p.to_rule(String::new()))?;
    if let Route::Profile { id } = &p.route {
        if st.snapshot().profile(id).is_none() {
            return Err("Выбранный в шаблоне сервер не найден".into());
        }
    }
    if p.id.is_empty() {
        p.id = format!("my-{}", new_id());
    }
    let saved = st.mutate(|d| {
        match d.presets.iter_mut().find(|x| x.id == p.id) {
            Some(x) => {
                p.created_at = x.created_at;
                *x = p.clone();
            }
            None => {
                p.created_at = now_unix();
                d.presets.push(p.clone());
            }
        }
        Ok(p)
    })?;
    Ok(saved)
}

#[tauri::command]
pub fn delete_preset(st: St<'_>, id: String) -> R<()> {
    st.mutate(|d| {
        d.presets.retain(|p| p.id != id);
        Ok(())
    })
}

// ---------- moving to another computer ----------

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
    let text = tokio::task::spawn_blocking(move || bundle::seal(&b, &password))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if !to_file {
        return Ok(Some(ExportResult { text: Some(text), path: None }));
    }
    let name = format!("ReTunl {}.{}", ymd(now_unix()), bundle::EXTENSION);
    let a = app.clone();
    let picked = tokio::task::spawn_blocking(move || {
        a.dialog()
            .file()
            .set_title("Сохранить экспорт ReTunl")
            .set_file_name(&name)
            .add_filter("Экспорт ReTunl", &[bundle::EXTENSION])
            .blocking_save_file()
    })
    .await
    .map_err(|e| e.to_string())?;
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
    let b = tokio::task::spawn_blocking(move || bundle::open(&text, &password))
        .await
        .map_err(|e| e.to_string())?
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

// ---------- settings ----------

fn config_part(s: &Settings) -> Settings {
    let mut c = s.clone();
    c.connect_on_launch = false;
    c.close_to_tray = false;
    c.start_minimized = false;
    c.test_url = String::new();
    c
}

/// Merge a partial settings object (`{"mode": "tun"}`) into the current ones.
#[tauri::command]
pub fn update_settings(st: St<'_>, patch: Value) -> R<Settings> {
    let (before, after) = st.mutate(|d| {
        let before = d.settings.clone();
        let mut current = serde_json::to_value(&d.settings).map_err(|e| e.to_string())?;
        merge_json(&mut current, patch);
        let next: Settings = serde_json::from_value(current).map_err(|e| format!("Неверные настройки: {e}"))?;
        dns::server(&next.dns.direct, "x", None, "y").map_err(|e| format!("DNS для прямого трафика: {e}"))?;
        dns::server(&next.dns.remote, "x", None, "y").map_err(|e| format!("DNS через VPN: {e}"))?;
        if next.mixed_port < 1024 || next.controller_port < 1024 {
            return Err("Порты должны быть от 1024 до 65535".into());
        }
        d.settings = next.clone();
        Ok((before, next))
    })?;
    if config_part(&before) != config_part(&after) {
        st.request_reload();
    }
    Ok(after)
}

fn merge_json(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(t), Value::Object(p)) => {
            for (k, v) in p {
                match t.get_mut(&k) {
                    // tagged values like a Route are replaced whole, not merged
                    Some(slot) if slot.is_object() && v.is_object() && v.get("kind").is_none() => merge_json(slot, v),
                    _ => {
                        t.insert(k, v);
                    }
                }
            }
        }
        (t, p) => *t = p,
    }
}

/// The config that would be used right now (for the "show config" button).
#[tauri::command]
pub fn preview_config(st: St<'_>) -> R<String> {
    let built = singbox::build(
        &st.snapshot(),
        &BuildOptions {
            ruleset_dir: st.paths.ruleset_dir(),
            controller_secret: "••••".into(),
            cache_file: None,
            extended_available: st.paths.find_lx_core().is_some(),
            // the preview shows the settings as chosen; the TLS switch happens on connect
            direct_dns_tls: false,
        },
    )
    .map_err(|e| e.0)?;
    serde_json::to_string_pretty(&built.config).map_err(|e| e.to_string())
}

// ---------- connection ----------

#[tauri::command]
pub async fn connect(st: St<'_>) -> R<()> {
    st.connect().await
}

#[tauri::command]
pub async fn disconnect(st: St<'_>) -> R<()> {
    st.engine.stop().await;
    Ok(())
}

#[tauri::command]
pub async fn poll(st: St<'_>, connections: bool) -> R<Poll> {
    Ok(st.engine.poll(connections).await)
}

#[tauri::command]
pub async fn close_connection(st: St<'_>, id: String) -> R<()> {
    st.engine.close_connection(&id).await
}

#[tauri::command]
pub async fn close_all_connections(st: St<'_>) -> R<()> {
    st.engine.close_all().await
}

#[derive(Serialize)]
pub struct Logs {
    lines: Vec<LogLine>,
    last: u64,
}

#[tauri::command]
pub fn get_logs(st: St<'_>, after: u64) -> Logs {
    let (lines, last) = st.engine.logs_after(after);
    Logs { lines, last }
}

#[tauri::command]
pub fn clear_logs(st: St<'_>) {
    st.engine.clear_logs();
}

// ---------- system ----------

#[tauri::command]
pub async fn list_processes() -> R<Vec<ProcInfo>> {
    tokio::task::spawn_blocking(sys::processes).await.map_err(|e| e.to_string())
}

/// Icons for exe paths as data URLs (cached; missing → null).
#[tauri::command]
pub async fn get_icons(st: St<'_>, paths: Vec<String>) -> R<HashMap<String, Option<String>>> {
    let todo: Vec<String> = {
        let cache = st.icons.lock().unwrap_or_else(|e| e.into_inner());
        paths.iter().filter(|p| !cache.contains_key(*p)).cloned().collect()
    };
    if !todo.is_empty() {
        let found = tokio::task::spawn_blocking(move || {
            #[cfg(target_os = "android")]
            return icons::icons(&todo).into_iter().collect::<Vec<_>>();
            #[cfg(not(target_os = "android"))]
            todo.into_iter().map(|p| {
                let icon = icons::exe_icon_data_url(&p);
                (p, icon)
            }).collect::<Vec<_>>()
        })
        .await
        .map_err(|e| e.to_string())?;
        st.icons.lock().unwrap_or_else(|e| e.into_inner()).extend(found);
    }
    let cache = st.icons.lock().unwrap_or_else(|e| e.into_inner());
    Ok(paths.into_iter().map(|p| {
        let v = cache.get(&p).cloned().flatten();
        (p, v)
    }).collect())
}

#[tauri::command]
pub async fn pick_exe(app: AppHandle) -> R<Option<String>> {
    if cfg!(target_os = "android") {
        return Err("На Android приложение выбирается из списка".into());
    }
    let picked = tokio::task::spawn_blocking(move || {
        let ext: &[&str] = if cfg!(windows) { &["exe"] } else { &["app"] };
        app.dialog().file().set_title("Выберите программу").add_filter("Программы", ext).blocking_pick_file()
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(picked.and_then(|p| p.into_path().ok()).map(|p| p.display().to_string()))
}

#[tauri::command]
pub async fn pick_folder(app: AppHandle) -> R<Option<String>> {
    #[cfg(target_os = "android")]
    {
        let _ = app;
        Err("На Android папки программ не выбираются".into())
    }
    #[cfg(not(target_os = "android"))]
    {
    let picked = tokio::task::spawn_blocking(move || {
        app.dialog().file().set_title("Папка: все программы внутри неё").blocking_pick_folder()
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok(picked.and_then(|p| p.into_path().ok()).map(|p| {
        let s = p.display().to_string();
        let sep = std::path::MAIN_SEPARATOR;
        if s.ends_with(sep) { s } else { format!("{s}{sep}") }
    }))
    }
}

#[tauri::command]
pub fn copy_text(app: AppHandle, text: String) -> R<()> {
    app.clipboard().write_text(text).map_err(|e| format!("Буфер обмена недоступен: {e}"))
}

#[tauri::command]
pub async fn relaunch_admin(app: AppHandle, st: St<'_>, connect: bool) -> R<()> {
    let args = format!("--wait-pid {}{}", std::process::id(), if connect { " --connect" } else { "" });
    sys::relaunch_elevated(&args)?;
    st.engine.stop().await;
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub fn set_autostart(enabled: bool) -> R<Autostart> {
    sys::set_autostart(enabled)
}

#[tauri::command]
pub async fn download_core(app: AppHandle, st: St<'_>, kind: Option<CoreKind>) -> R<String> {
    if cfg!(target_os = "android") {
        return Err("На Android ядро встроено в приложение и обновляется вместе с ним.".into());
    }
    let kind = kind.unwrap_or_default();
    let dir = match kind {
        CoreKind::Official => st.paths.core_dir(),
        CoreKind::Extended => st.paths.lx_core_dir(),
    };
    // the running core's files are locked by Windows
    if st.engine.is_active() && st.engine.status().core.unwrap_or_default() == kind {
        return Err("Сначала отключитесь — это ядро сейчас используется.".into());
    }
    let h = app.clone();
    let path = fetch::download_core(&st.http, kind, &dir, move |done, total| {
        let _ = h.emit("core-progress", serde_json::json!({"done": done, "total": total, "kind": kind}));
    })
    .await?;
    Ok(path.display().to_string())
}

/// All geosite/geoip tags, for hints in the rule editor.
#[tauri::command]
pub async fn geo_tags(st: St<'_>) -> R<Vec<String>> {
    fetch::geo_tags(&st.http, &st.paths.ruleset_dir().join("tags.json")).await
}

/// Re-download every list the current rules use.
#[tauri::command]
pub async fn update_rule_sets(st: St<'_>) -> R<usize> {
    let data = st.snapshot();
    let mut seen = std::collections::BTreeMap::new();
    for r in &data.rules {
        for rs in &r.rule_sets {
            if let Ok(src) = rulesets::resolve(rs) {
                seen.insert(src.tag.clone(), src);
            }
        }
    }
    let sources: Vec<_> = seen.into_values().collect();
    fetch::ensure_rule_sets(&st.http, &sources, &st.paths.ruleset_dir(), true).await?;
    Ok(sources.len())
}

#[tauri::command]
pub fn open_data_dir(st: St<'_>) {
    sys::open_in_explorer(&st.paths.data_dir.display().to_string());
}

#[tauri::command]
pub fn open_url(url: String) -> R<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Можно открыть только веб-ссылку".into());
    }
    sys::open_in_explorer(&url);
    Ok(())
}

/// Android: status and navigation bar icons dark on a light theme, light on a dark one.
#[tauri::command(async)]
pub fn set_system_bars(dark: bool) -> R<()> {
    #[cfg(target_os = "android")]
    return tauri_plugin_retunl_vpn::system_bars(dark);
    #[cfg(not(target_os = "android"))]
    {
        let _ = dark;
        Ok(())
    }
}

/// The page has loaded: show the window unless we started hidden in the tray.
#[tauri::command]
pub fn app_ready(app: AppHandle, st: St<'_>) {
    if !st.hidden_launch {
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.set_focus();
        }
    }
}

#[tauri::command]
pub async fn quit_app(app: AppHandle, st: St<'_>) -> R<()> {
    st.engine.stop().await;
    app.exit(0);
    Ok(())
}

#[cfg_attr(mobile, allow(dead_code))]
pub fn is_need_admin(e: &str) -> bool {
    e == NEED_ADMIN
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        data.profiles.push(Profile {
            id: "p1".into(),
            name: "NL".into(),
            outbound: json!({"type": "wireguard", "jc": 4, "h1": "1-9"}),
            subscription: Some("s1".into()),
            link: None,
            created_at: 0,
        });
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
