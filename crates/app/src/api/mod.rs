//! Commands the UI calls. Thin: they check input, change data, ask the engine.

use std::sync::Arc;

use tauri::State;

use crate::engine::NEED_ADMIN;
use crate::state::AppState;

pub mod cisco;
pub mod connection;
pub mod import;
pub mod rules;
pub mod servers;
pub mod settings;
pub mod subscriptions;
pub mod system;
pub mod transfer;
pub mod updates;
pub mod view;

type St<'a> = State<'a, Arc<AppState>>;
type R<T> = Result<T, String>;

#[cfg_attr(mobile, allow(dead_code))]
pub fn is_need_admin(e: &str) -> bool {
    e == NEED_ADMIN
}
