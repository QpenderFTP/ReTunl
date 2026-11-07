//! App icons on Android come from the system, many at once.

use std::collections::HashMap;

pub fn icons(packages: &[String]) -> HashMap<String, Option<String>> {
    tauri_plugin_retunl_vpn::icons(packages).unwrap_or_default()
}
