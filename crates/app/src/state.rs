use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use retunl_core::links::ParsedLink;
use retunl_core::util::{new_id, now_unix};
use retunl_core::{AppData, Profile, Route};
use tauri::AppHandle;

use crate::engine::{Engine, StartRequest};
use crate::paths::Paths;
use crate::probe::Latency;
use crate::speed::SpeedResult;
#[cfg(desktop)]
use crate::tray::Tray;
use crate::{fetch, store};

pub struct AppState {
    pub paths: Paths,
    pub data: Mutex<AppData>,
    pub engine: Arc<Engine>,
    pub http: reqwest::Client,
    pub elevated: bool,
    pub latency: Mutex<HashMap<String, Latency>>,
    pub icons: Mutex<HashMap<String, Option<String>>>,
    pub reload_gen: AtomicU64,
    pub handle: OnceLock<AppHandle>,
    #[cfg(desktop)]
    pub tray: Mutex<Option<Tray>>,
    pub warning: Mutex<Option<String>>,
    /// Started by autostart / minimized: keep the window in the tray.
    pub hidden_launch: bool,
    pub speed: Mutex<Option<SpeedResult>>,
    /// Held while a speed test runs.
    pub speed_lock: tokio::sync::Mutex<()>,
    /// «Мои серверы»
    pub admin: crate::admin::Admin,
}

impl AppState {
    pub fn new(paths: Paths, data: AppData, warning: Option<String>, hidden_launch: bool) -> AppState {
        let engine = Arc::new(Engine::new(Some(paths.data_dir.join("stats.json"))));
        let admin = crate::admin::Admin::new(paths.data_dir.join("my-servers.json"));
        AppState {
            hidden_launch,
            paths,
            data: Mutex::new(data),
            engine,
            http: fetch::http_client(),
            elevated: crate::sys::is_elevated(),
            latency: Mutex::new(HashMap::new()),
            icons: Mutex::new(HashMap::new()),
            reload_gen: AtomicU64::new(0),
            handle: OnceLock::new(),
            #[cfg(desktop)]
            tray: Mutex::new(None),
            warning: Mutex::new(warning),
            speed: Mutex::new(None),
            speed_lock: tokio::sync::Mutex::new(()),
            admin,
        }
    }

    pub fn snapshot(&self) -> AppData {
        self.data.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Change data and save it; nothing changes if `f` fails or saving fails.
    pub fn mutate<R>(&self, f: impl FnOnce(&mut AppData) -> Result<R, String>) -> Result<R, String> {
        let mut guard = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let mut copy = guard.clone();
        let r = f(&mut copy)?;
        store::save(&self.paths.data_file(), &copy).map_err(|e| format!("Не удалось сохранить данные: {e}"))?;
        *guard = copy;
        Ok(r)
    }

    pub fn start_request(&self) -> StartRequest {
        StartRequest { data: self.snapshot(), paths: self.paths.clone(), http: self.http.clone(), elevated: self.elevated }
    }

    pub async fn connect(&self) -> Result<(), String> {
        let r = self.engine.start(self.start_request()).await;
        if let Err(e) = &r {
            if e == crate::engine::NEED_ADMIN {
                if let Some(h) = self.handle.get() {
                    use tauri::Emitter;
                    let _ = h.emit("need-admin", ());
                }
            }
        }
        r
    }

    /// Apply changed settings to a running connection (debounced restart).
    pub fn request_reload(self: &Arc<Self>) {
        let gen = self.reload_gen.fetch_add(1, Ordering::SeqCst) + 1;
        let me = self.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_millis(700)).await;
            if me.reload_gen.load(Ordering::SeqCst) != gen || !me.engine.is_active() {
                return;
            }
            me.engine.log_app("INFO", "Применяю изменения — переподключаюсь");
            me.engine.stop().await;
            let _ = me.connect().await;
        });
    }
}

/// Add imported servers. Exact duplicates are skipped. Returns (added ids, duplicates).
pub fn add_profiles(data: &mut AppData, items: Vec<ParsedLink>, subscription: Option<&str>, links: &[Option<String>]) -> (Vec<String>, usize) {
    let mut added = Vec::new();
    let mut dups = 0;
    for (i, item) in items.into_iter().enumerate() {
        if data.profiles.iter().any(|p| p.outbound == item.outbound) {
            dups += 1;
            continue;
        }
        let id = new_id();
        data.profiles.push(Profile {
            id: id.clone(),
            name: item.name,
            outbound: item.outbound,
            subscription: subscription.map(str::to_string),
            link: links.get(i).cloned().flatten(),
            created_at: now_unix(),
            wiresock: None,
        });
        added.push(id);
    }
    if data.settings.active_profile.as_ref().and_then(|id| data.profile(id)).is_none() {
        data.settings.active_profile = added.first().cloned();
    }
    (added, dups)
}

/// Replace a subscription's servers, keeping ids of servers that stayed
/// (so the selected server and rules keep pointing at them).
pub fn merge_subscription(data: &mut AppData, sub_id: &str, items: Vec<ParsedLink>) -> (usize, usize, usize) {
    let old: Vec<Profile> = data.profiles.iter().filter(|p| p.subscription.as_deref() == Some(sub_id)).cloned().collect();
    let key = |o: &serde_json::Value| {
        (
            o.get("type").cloned(),
            o.get("server").cloned().or_else(|| o.pointer("/peers/0/address").cloned()),
            o.get("server_port").cloned().or_else(|| o.pointer("/peers/0/port").cloned()),
        )
    };
    let mut used = std::collections::HashSet::new();
    let mut fresh = Vec::new();
    let (mut added, mut kept) = (0, 0);
    for item in items {
        let found = old
            .iter()
            .find(|p| !used.contains(&p.id) && p.name == item.name)
            .or_else(|| old.iter().find(|p| !used.contains(&p.id) && key(&p.outbound) == key(&item.outbound)));
        let (id, created, wiresock) = match found {
            Some(p) => {
                used.insert(p.id.clone());
                kept += 1;
                (p.id.clone(), p.created_at, p.wiresock.clone())
            }
            None => {
                added += 1;
                (new_id(), now_unix(), None)
            }
        };
        fresh.push(Profile {
            id,
            name: item.name,
            outbound: item.outbound,
            subscription: Some(sub_id.to_string()),
            link: None,
            created_at: created,
            wiresock,
        });
    }
    let removed: Vec<String> = old.iter().filter(|p| !used.contains(&p.id)).map(|p| p.id.clone()).collect();
    // keep the subscription's block where it was in the list
    let pos = data.profiles.iter().position(|p| p.subscription.as_deref() == Some(sub_id)).unwrap_or(data.profiles.len());
    data.profiles.retain(|p| p.subscription.as_deref() != Some(sub_id));
    let pos = pos.min(data.profiles.len());
    let first_new = fresh.first().map(|p| p.id.clone());
    data.profiles.splice(pos..pos, fresh);
    forget_profiles(data, &removed, first_new);
    (added, kept, removed.len())
}

/// After servers are removed: fix the selected server and rules that used them.
pub fn forget_profiles(data: &mut AppData, removed: &[String], fallback: Option<String>) -> usize {
    if let Some(active) = &data.settings.active_profile {
        if removed.contains(active) {
            data.settings.active_profile = fallback.or_else(|| data.profiles.first().map(|p| p.id.clone()));
        }
    }
    let mut fixed = 0;
    for r in &mut data.rules {
        if let Route::Profile { id } = &r.route {
            if removed.contains(id) {
                r.route = Route::Proxy;
                fixed += 1;
            }
        }
    }
    if let Route::Profile { id } = &data.settings.final_route {
        if removed.contains(id) {
            data.settings.final_route = Route::Proxy;
        }
    }
    fixed
}
