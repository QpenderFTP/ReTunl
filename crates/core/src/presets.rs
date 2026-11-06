//! Ready-made rules for the "Шаблоны" gallery.

use serde::Serialize;

use crate::model::{Route, Rule};
use crate::util::{new_id, Os};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PresetRoute {
    Proxy,
    Direct,
    Block,
}

#[derive(Clone, Debug, Serialize)]
pub struct Preset {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    /// Windows programs
    pub apps: &'static [&'static str],
    /// the same programs on macOS: app bundles, folders (`~/…` is the home folder)
    #[serde(skip)]
    pub mac_apps: &'static [&'static str],
    #[serde(skip)]
    pub mac_description: Option<&'static str>,
    /// shown only on this system
    #[serde(skip)]
    pub only: Option<Os>,
    pub domains: &'static [&'static str],
    pub ips: &'static [&'static str],
    pub rule_sets: &'static [&'static str],
    pub route: PresetRoute,
}

/// Telegram data centres (from core.telegram.org/resources/cidr.txt).
const TELEGRAM_IPS: &[&str] = &[
    "91.105.192.0/23",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "95.161.64.0/20",
    "149.154.160.0/20",
    "185.76.151.0/24",
    "2001:67c:4e8::/48",
    "2001:b28:f23c::/48",
    "2001:b28:f23d::/48",
    "2001:b28:f23f::/48",
    "2a0a:f280::/32",
];

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "ru-blocked",
        title: "Заблокированное в России — через VPN",
        description: "Сайты и IP из реестра блокировок (списки runetfreedom). Удобно вместе с «Остальное — напрямую»: российские сайты и банки работают как обычно.",
        apps: &[],
        mac_apps: &[],
        mac_description: None,
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &["geosite-ru-blocked", "geoip-ru-blocked"],
        route: PresetRoute::Proxy,
    },
    Preset {
        id: "ru-direct",
        title: "Российские сайты — напрямую",
        description: "Домены .ru/.рф/.su, российские сервисы и IP-адреса России идут мимо VPN. Нужно, когда остальное идёт через VPN: Госуслуги и банки не любят зарубежные адреса.",
        apps: &[],
        mac_apps: &[],
        mac_description: None,
        only: None,
        domains: &["ru", "su", "xn--p1ai", "xn--d1acj3b", "xn--80asehdb"],
        ips: &[],
        rule_sets: &["geosite-category-ru", "geosite-ru-available-only-inside", "geoip-ru"],
        route: PresetRoute::Direct,
    },
    Preset {
        id: "youtube",
        title: "YouTube — через VPN",
        description: "Сайт, приложение и видеосерверы YouTube.",
        apps: &[],
        mac_apps: &[],
        mac_description: None,
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &["geosite-youtube"],
        route: PresetRoute::Proxy,
    },
    Preset {
        id: "discord",
        title: "Discord — через VPN",
        description: "Приложение Discord целиком (включая голос) и discord.com в браузере.",
        apps: &["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"],
        mac_apps: &["Discord.app", "Discord PTB.app", "Discord Canary.app"],
        mac_description: None,
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &["geosite-discord"],
        route: PresetRoute::Proxy,
    },
    Preset {
        id: "telegram",
        title: "Telegram — через VPN",
        description: "Telegram Desktop, web.telegram.org и серверы Telegram.",
        apps: &["Telegram.exe", "AyuGram.exe", "Kotatogram.exe"],
        mac_apps: &["Telegram.app", "Telegram Desktop.app", "AyuGram.app", "Kotatogram.app"],
        mac_description: None,
        only: None,
        domains: &[],
        ips: TELEGRAM_IPS,
        rule_sets: &["geosite-telegram"],
        route: PresetRoute::Proxy,
    },
    Preset {
        id: "meta",
        title: "Instagram, Facebook, WhatsApp — через VPN",
        description: "Все сервисы Meta.",
        apps: &["WhatsApp.exe"],
        mac_apps: &["WhatsApp.app"],
        mac_description: None,
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &["geosite-meta", "geosite-instagram", "geosite-facebook", "geosite-whatsapp"],
        route: PresetRoute::Proxy,
    },
    Preset {
        id: "ai",
        title: "Нейросети — через VPN",
        description: "ChatGPT, Claude, Gemini и другие сервисы, недоступные из России.",
        apps: &["ChatGPT.exe", "Claude.exe"],
        mac_apps: &["ChatGPT.app", "Claude.app"],
        mac_description: None,
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &["geosite-category-ai-!cn", "geosite-openai", "geosite-anthropic", "geosite-google-gemini"],
        route: PresetRoute::Proxy,
    },
    Preset {
        id: "x",
        title: "X (Twitter) — через VPN",
        description: "x.com, twitter.com и их серверы.",
        apps: &[],
        mac_apps: &[],
        mac_description: None,
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &["geosite-x", "geosite-twitter"],
        route: PresetRoute::Proxy,
    },
    Preset {
        id: "browsers",
        title: "Только браузеры — через VPN",
        description: "Chrome, Edge, Firefox, Яндекс Браузер, Opera, Brave, Vivaldi. Остальные программы идут как настроено ниже.",
        apps: &["chrome.exe", "msedge.exe", "firefox.exe", "browser.exe", "opera.exe", "brave.exe", "vivaldi.exe", "zen.exe"],
        mac_apps: &["Google Chrome.app", "Microsoft Edge.app", "Firefox.app", "Yandex.app", "Opera.app", "Brave Browser.app", "Vivaldi.app", "Zen.app", "Zen Browser.app", "Arc.app"],
        mac_description: Some("Chrome, Edge, Firefox, Яндекс Браузер, Opera, Brave, Vivaldi, Arc. Safari сюда не входит: за него в сеть ходит служба macOS. Остальные программы идут как настроено ниже."),
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &[],
        route: PresetRoute::Proxy,
    },
    Preset {
        id: "torrents",
        title: "Торрент-клиенты — напрямую",
        description: "qBittorrent, uTorrent, BitTorrent, Transmission и др. не тратят трафик VPN.",
        apps: &["qbittorrent.exe", "uTorrent.exe", "BitTorrent.exe", "transmission-qt.exe", "tixati.exe", "Motrix.exe", "biglybt.exe"],
        mac_apps: &["qBittorrent.app", "Transmission.app", "Motrix.app", "BiglyBT.app", "Folx.app", "uTorrent Web.app"],
        mac_description: Some("qBittorrent, Transmission, Motrix, BiglyBT и др. не тратят трафик VPN."),
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &[],
        route: PresetRoute::Direct,
    },
    Preset {
        id: "games",
        title: "Игры и лаунчеры — напрямую",
        description: "Steam (и все игры из его папки), Epic, Battle.net, EA, Riot, GOG — без лишней задержки.",
        apps: &[
            "C:\\Program Files (x86)\\Steam\\",
            "steam.exe",
            "steamwebhelper.exe",
            "EpicGamesLauncher.exe",
            "Battle.net.exe",
            "EADesktop.exe",
            "RiotClientServices.exe",
            "GalaxyClient.exe",
        ],
        mac_apps: &["~/Library/Application Support/Steam/", "Steam.app", "Epic Games Launcher.app", "Battle.net.app", "Riot Client.app", "GOG Galaxy.app"],
        mac_description: Some("Steam (и все игры из его папки), Epic, Battle.net, Riot, GOG — без лишней задержки."),
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &[],
        route: PresetRoute::Direct,
    },
    Preset {
        id: "ads",
        title: "Блокировать рекламу и трекеры",
        description: "Рекламные и следящие домены не загружаются ни через VPN, ни напрямую.",
        apps: &[],
        mac_apps: &[],
        mac_description: None,
        only: None,
        domains: &[],
        ips: &[],
        rule_sets: &["geosite-category-ads-all"],
        route: PresetRoute::Block,
    },
    Preset {
        id: "win-spy",
        title: "Блокировать телеметрию Windows",
        description: "Домены сбора данных Microsoft. Может мешать обновлениям Windows.",
        apps: &[],
        mac_apps: &[],
        mac_description: None,
        only: Some(Os::Windows),
        domains: &[],
        ips: &[],
        rule_sets: &["geosite-win-spy"],
        route: PresetRoute::Block,
    },
];

impl Preset {
    /// The preset as this system sees it: its programs and wording.
    pub fn for_os(&self, os: Os) -> Preset {
        let mut p = self.clone();
        if os == Os::MacOs {
            p.apps = self.mac_apps;
            if let Some(d) = self.mac_description {
                p.description = d;
            }
        }
        p
    }
}

/// The gallery for this system.
pub fn available() -> Vec<Preset> {
    PRESETS.iter().filter(|p| p.only.is_none_or(|o| o == Os::CURRENT)).map(|p| p.for_os(Os::CURRENT)).collect()
}

pub fn find(id: &str) -> Option<Preset> {
    PRESETS.iter().find(|p| p.id == id).map(|p| p.for_os(Os::CURRENT))
}

/// A new rule from a preset.
pub fn instantiate(preset: &Preset) -> Rule {
    let own = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    Rule {
        id: new_id(),
        name: preset.title.split(" — ").next().unwrap_or(preset.title).to_string(),
        enabled: true,
        match_all: false,
        apps: own(preset.apps),
        domains: own(preset.domains),
        ips: own(preset.ips),
        ports: Vec::new(),
        rule_sets: own(preset.rule_sets),
        network: None,
        route: match preset.route {
            PresetRoute::Proxy => Route::Proxy,
            PresetRoute::Direct => Route::Direct,
            PresetRoute::Block => Route::Block,
        },
        preset: Some(preset.id.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_valid() {
        let mut ids = std::collections::HashSet::new();
        for p in PRESETS {
            assert!(ids.insert(p.id), "duplicate preset {}", p.id);
            let r = instantiate(p);
            assert!(!r.is_empty());
            for rs in &r.rule_sets {
                crate::rulesets::resolve(rs).unwrap();
            }
        }
        assert_eq!(instantiate(&find("youtube").unwrap()).name, "YouTube");
    }

    #[test]
    fn mac_presets() {
        for p in PRESETS {
            let mac = p.for_os(Os::MacOs);
            // every Windows program list has its macOS counterpart
            assert_eq!(p.apps.is_empty(), mac.apps.is_empty(), "{}", p.id);
            for a in mac.apps {
                let re = crate::singbox::app_regex_for(a, Os::MacOs).unwrap();
                assert!(!re.contains(".exe"), "{a} → {re}");
            }
        }
        let names: Vec<_> = PRESETS.iter().filter(|p| p.only.is_none_or(|o| o == Os::MacOs)).map(|p| p.id).collect();
        assert!(!names.contains(&"win-spy"));
    }
}
