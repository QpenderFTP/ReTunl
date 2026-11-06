//! Rule sets: ready lists of domains or IP ranges in sing-box binary format
//! (`.srs`). The app downloads them; the config points at local files.

use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleSetKind {
    Domain,
    Ip,
    Unknown,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct RuleSetSource {
    /// Tag used inside the sing-box config.
    pub tag: String,
    pub kind: RuleSetKind,
    /// Download addresses, best first.
    pub urls: Vec<String>,
    pub file_name: String,
}

pub const SAGERNET_GEOSITE: &str = "SagerNet/sing-geosite";
pub const SAGERNET_GEOIP: &str = "SagerNet/sing-geoip";
const RUNETFREEDOM: &str = "runetfreedom/russia-v2ray-rules-dat";

/// Lists that exist only in runetfreedom/russia-v2ray-rules-dat (Russian blocklists).
pub const RUNETFREEDOM_ONLY: &[&str] = &[
    "geosite-ru-blocked",
    "geosite-ru-blocked-all",
    "geosite-ru-available-only-inside",
    "geosite-win-spy",
    "geoip-ru-blocked",
    "geoip-ru-blocked-community",
    "geoip-re-filter",
    "geoip-telegram",
];

/// `geosite-youtube`, `geoip-ru` or an `https://…/list.srs` address.
pub fn resolve(entry: &str) -> Result<RuleSetSource, String> {
    let entry = entry.trim();
    let lower = entry.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        let tag = format!("custom-{:016x}", fnv1a(entry));
        return Ok(RuleSetSource {
            file_name: format!("{tag}.srs"),
            tag,
            kind: RuleSetKind::Unknown,
            urls: vec![entry.to_string()],
        });
    }
    let kind = if lower.starts_with("geosite-") {
        RuleSetKind::Domain
    } else if lower.starts_with("geoip-") {
        RuleSetKind::Ip
    } else {
        return Err(format!(
            "«{entry}» — неизвестный набор: имя должно начинаться с geosite- или geoip-, либо это ссылка на .srs"
        ));
    };
    if !lower.chars().all(|c| c.is_ascii_alphanumeric() || "-_!@.".contains(c)) {
        return Err(format!("в имени набора «{entry}» недопустимые символы"));
    }
    let urls = if RUNETFREEDOM_ONLY.contains(&lower.as_str()) {
        let dir = if kind == RuleSetKind::Domain { "rule-set-geosite" } else { "rule-set-geoip" };
        vec![
            format!("https://raw.githubusercontent.com/{RUNETFREEDOM}/release/sing-box/{dir}/{lower}.srs"),
            format!("https://cdn.jsdelivr.net/gh/{RUNETFREEDOM}@release/sing-box/{dir}/{lower}.srs"),
        ]
    } else {
        let repo = if kind == RuleSetKind::Domain { SAGERNET_GEOSITE } else { SAGERNET_GEOIP };
        vec![
            format!("https://raw.githubusercontent.com/{repo}/rule-set/{lower}.srs"),
            format!("https://cdn.jsdelivr.net/gh/{repo}@rule-set/{lower}.srs"),
        ]
    };
    Ok(RuleSetSource { file_name: format!("{lower}.srs"), tag: lower, kind, urls })
}

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[derive(Clone, Debug, Serialize)]
pub struct CatalogEntry {
    pub tag: &'static str,
    pub label: &'static str,
    pub group: &'static str,
}

/// Lists shown in the rule editor. Any other `geosite-*` / `geoip-*` name
/// from SagerNet works too.
pub const CATALOG: &[CatalogEntry] = &[
    CatalogEntry { tag: "geosite-ru-blocked", label: "Заблокированное в РФ — сайты", group: "Россия" },
    CatalogEntry { tag: "geoip-ru-blocked", label: "Заблокированное в РФ — IP-адреса", group: "Россия" },
    CatalogEntry { tag: "geosite-ru-blocked-all", label: "Весь реестр блокировок РФ (большой, 11 МБ)", group: "Россия" },
    CatalogEntry { tag: "geoip-ru-blocked-community", label: "Блокировки РФ — IP от сообщества", group: "Россия" },
    CatalogEntry { tag: "geoip-re-filter", label: "Блокировки РФ — Re:filter", group: "Россия" },
    CatalogEntry { tag: "geosite-ru-available-only-inside", label: "Работает только из России", group: "Россия" },
    CatalogEntry { tag: "geosite-category-ru", label: "Российские сайты", group: "Россия" },
    CatalogEntry { tag: "geosite-category-gov-ru", label: "Госсайты РФ", group: "Россия" },
    CatalogEntry { tag: "geosite-category-media-ru", label: "Российские СМИ", group: "Россия" },
    CatalogEntry { tag: "geosite-yandex", label: "Яндекс", group: "Россия" },
    CatalogEntry { tag: "geosite-vk", label: "ВКонтакте", group: "Россия" },
    CatalogEntry { tag: "geoip-ru", label: "IP-адреса России", group: "Россия" },
    CatalogEntry { tag: "geosite-youtube", label: "YouTube", group: "Видео и музыка" },
    CatalogEntry { tag: "geosite-twitch", label: "Twitch", group: "Видео и музыка" },
    CatalogEntry { tag: "geosite-netflix", label: "Netflix", group: "Видео и музыка" },
    CatalogEntry { tag: "geosite-spotify", label: "Spotify", group: "Видео и музыка" },
    CatalogEntry { tag: "geosite-soundcloud", label: "SoundCloud", group: "Видео и музыка" },
    CatalogEntry { tag: "geosite-tiktok", label: "TikTok", group: "Видео и музыка" },
    CatalogEntry { tag: "geosite-discord", label: "Discord", group: "Общение" },
    CatalogEntry { tag: "geosite-telegram", label: "Telegram — сайты", group: "Общение" },
    CatalogEntry { tag: "geoip-telegram", label: "Telegram — IP-адреса", group: "Общение" },
    CatalogEntry { tag: "geosite-whatsapp", label: "WhatsApp", group: "Общение" },
    CatalogEntry { tag: "geosite-instagram", label: "Instagram", group: "Общение" },
    CatalogEntry { tag: "geosite-facebook", label: "Facebook", group: "Общение" },
    CatalogEntry { tag: "geosite-meta", label: "Meta (все сервисы)", group: "Общение" },
    CatalogEntry { tag: "geosite-x", label: "X (Twitter)", group: "Общение" },
    CatalogEntry { tag: "geosite-linkedin", label: "LinkedIn", group: "Общение" },
    CatalogEntry { tag: "geosite-reddit", label: "Reddit", group: "Общение" },
    CatalogEntry { tag: "geosite-category-ai-!cn", label: "Нейросети (ChatGPT, Claude, Gemini…)", group: "Работа" },
    CatalogEntry { tag: "geosite-openai", label: "OpenAI / ChatGPT", group: "Работа" },
    CatalogEntry { tag: "geosite-anthropic", label: "Anthropic / Claude", group: "Работа" },
    CatalogEntry { tag: "geosite-google-gemini", label: "Google Gemini", group: "Работа" },
    CatalogEntry { tag: "geosite-github", label: "GitHub", group: "Работа" },
    CatalogEntry { tag: "geosite-google", label: "Google", group: "Работа" },
    CatalogEntry { tag: "geosite-microsoft", label: "Microsoft", group: "Работа" },
    CatalogEntry { tag: "geosite-apple", label: "Apple", group: "Работа" },
    CatalogEntry { tag: "geosite-notion", label: "Notion", group: "Работа" },
    CatalogEntry { tag: "geosite-figma", label: "Figma", group: "Работа" },
    CatalogEntry { tag: "geosite-jetbrains", label: "JetBrains", group: "Работа" },
    CatalogEntry { tag: "geosite-docker", label: "Docker", group: "Работа" },
    CatalogEntry { tag: "geosite-cloudflare", label: "Cloudflare", group: "Работа" },
    CatalogEntry { tag: "geosite-steam", label: "Steam", group: "Игры" },
    CatalogEntry { tag: "geosite-category-games", label: "Игровые сервисы", group: "Игры" },
    CatalogEntry { tag: "geosite-category-ads-all", label: "Реклама и трекеры", group: "Прочее" },
    CatalogEntry { tag: "geosite-win-spy", label: "Телеметрия Windows", group: "Прочее" },
    CatalogEntry { tag: "geosite-category-porn", label: "Сайты 18+", group: "Прочее" },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources() {
        let r = resolve("geosite-youtube").unwrap();
        assert_eq!(r.kind, RuleSetKind::Domain);
        assert_eq!(r.urls[0], "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-youtube.srs");
        let r = resolve("geoip-ru-blocked").unwrap();
        assert_eq!(r.kind, RuleSetKind::Ip);
        assert!(r.urls[0].contains("runetfreedom") && r.urls[0].contains("rule-set-geoip"));
        let r = resolve("GeoIP-RU").unwrap();
        assert_eq!(r.tag, "geoip-ru");
        let r = resolve("https://example.com/my.srs").unwrap();
        assert!(r.tag.starts_with("custom-"));
        assert_eq!(r, resolve("https://example.com/my.srs").unwrap());
        assert!(resolve("youtube").is_err());
        assert!(resolve("geosite-a b").is_err());
    }

    #[test]
    fn catalog_resolves() {
        for e in CATALOG {
            resolve(e.tag).unwrap();
        }
    }
}
