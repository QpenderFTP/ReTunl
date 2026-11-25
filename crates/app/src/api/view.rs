//! What the window gets when it opens: the data, the status and the lists to
//! choose from.

use std::collections::HashMap;

use retunl_core::presets::{self, Preset};
use retunl_core::rulesets::{self, CatalogEntry};
use retunl_core::{dns, AppData};
use serde::Serialize;

use super::St;
use crate::blocks::BlockStats;
use crate::engine::Status;
use crate::probe::Latency;
use crate::speed::{self, SpeedResult};
use crate::sys::{self, Autostart};
use crate::util::locked;
use crate::{cisco, wiresock};

#[derive(Serialize)]
pub struct CoreInfo {
    path: Option<String>,
    expected: &'static str,
    /// sing-box-lx (AmneziaWG, XHTTP).
    lx_path: Option<String>,
    lx_expected: &'static str,
    xray_installed: bool,
    xray_version: &'static str,
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
    /// Built-in test servers the speed test can use.
    speed_targets: Vec<speed::TargetInfo>,
    /// Windows: wiresock-client.exe of an installed WireSock VPN Client.
    wiresock: Option<String>,
    /// Windows: vpncli.exe of an installed Cisco Secure Client.
    cisco: Option<String>,
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
            xray_installed: cfg!(windows) && st.paths.xray_path().is_file(),
            xray_version: crate::fetch::XRAY_VERSION,
            needs,
        },
        latency: locked(&st.latency).clone(),
        autostart: sys::autostart_status(),
        version: env!("CARGO_PKG_VERSION"),
        data_dir: st.paths.data_dir.display().to_string(),
        portable: st.paths.portable,
        warning: locked(&st.warning).take(),
        platform: std::env::consts::OS,
        blocks: st.engine.blocks.stats(),
        speed: locked(&st.speed).clone(),
        speed_targets: speed::catalog(),
        wiresock: wiresock::find_client().map(|p| p.display().to_string()),
        cisco: cisco::find().map(|c| c.cli.display().to_string()),
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
