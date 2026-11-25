//! ReTunl core: everything that does not touch the OS.
//!
//! * [`model`] — profiles (servers), split-tunnel rules, settings;
//! * [`links`] / [`wgconf`] / [`subscription`] — importing servers;
//! * [`singbox`] — turning all of that into a sing-box 1.14 config;
//! * [`rulesets`] / [`presets`] — ready-made domain and IP lists;
//! * [`awg`] — AmneziaWG / XHTTP and the choice of core (official or sing-box-lx);
//! * [`bundle`] — encrypted export of servers and subscriptions.

pub mod awg;
pub mod bundle;
pub mod dns;
pub mod links;
pub mod model;
pub mod presets;
pub mod rulesets;
pub mod singbox;
pub mod subscription;
pub mod util;
pub mod wgconf;
pub mod xray;

pub use model::*;

/// sing-box version the generated configs are written for.
pub const SING_BOX_VERSION: &str = "1.14.4";
/// sing-box-lx (AmneziaWG 3.1, XHTTP) release the app downloads.
pub const SING_BOX_LX_VERSION: &str = "1.14.4-lx.32";
