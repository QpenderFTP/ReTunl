//! What block rules stopped. sing-box only says so at debug level:
//! `router: match[n] … => reject` for a connection and `dns: match[n] … => reject`
//! for a name lookup, with the domain on an earlier line of the same
//! connection id. The all-time total is kept in `stats.json`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Lookups of one domain within this time (A, AAAA, HTTPS, retries) count once.
const SAME_VISIT: Duration = Duration::from_secs(2);
const SAVE_EVERY: Duration = Duration::from_secs(20);
const MAX_TRACKED: usize = 4000;
const TOP: usize = 5;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct BlockStats {
    /// Since the current connection started.
    pub session: u64,
    pub total: u64,
    /// The most blocked domains this session, most first.
    pub top: Vec<(String, u64)>,
    /// Blocks are being counted (there are block rules and the core reports them).
    pub counting: bool,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Saved {
    blocked_total: u64,
}

#[derive(Default)]
struct State {
    counting: bool,
    session: u64,
    total: u64,
    saved_total: u64,
    last_save: Option<Instant>,
    /// connection id → the domain it is about
    hosts: HashMap<u64, String>,
    /// domain (or `#id` when unknown) → when it was last counted
    recent: HashMap<String, Instant>,
    top: HashMap<String, u64>,
}

pub struct Blocks {
    file: Option<PathBuf>,
    state: Mutex<State>,
}

impl Blocks {
    pub fn new(file: Option<PathBuf>) -> Blocks {
        let total = file
            .as_ref()
            .and_then(|f| std::fs::read(f).ok())
            .and_then(|b| serde_json::from_slice::<Saved>(&b).ok())
            .map(|s| s.blocked_total)
            .unwrap_or(0);
        Blocks { file, state: Mutex::new(State { total, saved_total: total, ..State::default() }) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A new connection: the session count starts from zero.
    pub fn begin(&self, counting: bool) {
        let mut s = self.lock();
        s.counting = counting;
        s.session = 0;
        s.hosts.clear();
        s.recent.clear();
        s.top.clear();
    }

    /// The connection ended: keep the total.
    pub fn end(&self) {
        self.lock().counting = false;
        self.save();
    }

    pub fn stats(&self) -> BlockStats {
        let s = self.lock();
        let mut top: Vec<(String, u64)> = s.top.iter().map(|(k, v)| (k.clone(), *v)).collect();
        top.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top.truncate(TOP);
        BlockStats { session: s.session, total: s.total, top, counting: s.counting }
    }

    /// One sing-box message, without time and level:
    /// `[2427280928 26ms] router: match[2] domain_suffix=doubleclick.net => reject`.
    pub fn observe(&self, text: &str) {
        let Some((id, msg)) = split_id(text) else { return };
        let mut s = self.lock();
        if !s.counting {
            return;
        }
        if let Some(host) = host_in(msg) {
            if s.hosts.len() >= MAX_TRACKED {
                s.hosts.clear();
            }
            s.hosts.insert(id, host.to_ascii_lowercase());
            return;
        }
        if !(msg.ends_with("=> reject") && (msg.starts_with("router: match[") || msg.starts_with("dns: match["))) {
            return;
        }
        let host = s.hosts.get(&id).cloned();
        let key = host.clone().unwrap_or_else(|| format!("#{id}"));
        let now = Instant::now();
        if s.recent.get(&key).is_some_and(|t| now.duration_since(*t) < SAME_VISIT) {
            return;
        }
        if s.recent.len() >= MAX_TRACKED {
            s.recent.retain(|_, t| now.duration_since(*t) < SAME_VISIT);
        }
        s.recent.insert(key, now);
        s.session += 1;
        s.total += 1;
        if let Some(h) = host {
            *s.top.entry(h).or_insert(0) += 1;
        }
        let due = s.last_save.is_none_or(|t| now.duration_since(t) >= SAVE_EVERY);
        drop(s);
        if due {
            self.save();
        }
    }

    pub fn save(&self) {
        let Some(file) = &self.file else { return };
        let total = {
            let mut s = self.lock();
            s.last_save = Some(Instant::now());
            if s.total == s.saved_total {
                return;
            }
            s.total
        };
        let body = serde_json::to_vec(&Saved { blocked_total: total }).unwrap_or_default();
        let tmp = file.with_extension("json.tmp");
        if std::fs::write(&tmp, body).is_ok() && std::fs::rename(&tmp, file).is_ok() {
            self.lock().saved_total = total;
        }
    }
}

/// `[2427280928 26ms] text` → (2427280928, "text")
fn split_id(text: &str) -> Option<(u64, &str)> {
    let rest = text.strip_prefix('[')?;
    let (inside, msg) = rest.split_once("] ")?;
    let id = inside.split(' ').next()?.parse().ok()?;
    Some((id, msg))
}

/// The domain a line names, if it is one of the lines that come before a match.
fn host_in(msg: &str) -> Option<&str> {
    let host = if let Some((_, d)) = msg.strip_prefix("router: sniffed").and_then(|m| m.split_once(", domain: ")) {
        d.trim()
    } else if let Some(name) = msg.strip_prefix("dns: exchange ") {
        name.split(' ').next()?.trim_end_matches('.')
    } else if let Some((_, to)) = msg.split_once(": inbound connection to ") {
        let to = to.trim();
        if to.starts_with('[') {
            return None; // an IPv6 address
        }
        to.rsplit_once(':').map_or(to, |(h, _)| h)
    } else {
        return None;
    };
    let is_name = !host.is_empty() && host.parse::<std::net::IpAddr>().is_err() && host.contains('.');
    is_name.then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(b: &Blocks, lines: &[&str]) {
        for l in lines {
            b.observe(l);
        }
    }

    #[test]
    fn counts_connections_and_lookups() {
        let b = Blocks::new(None);
        b.begin(true);
        feed(
            &b,
            &[
                "[2427280928 22ms] inbound/mixed[mixed-in]: inbound connection to ad.doubleclick.net:443",
                "[2427280928 22ms] router: match[0] => sniff",
                "[2427280928 26ms] router: sniffed protocol: tls, domain: ad.doubleclick.net",
                "[2427280928 26ms] router: match[2] domain_suffix=doubleclick.net => reject",
                "[1724142893 4ms] router: sniffed protocol: tls, domain: ya.ru",
                "[1724142893 4ms] outbound/direct[direct]: outbound connection to ya.ru:443",
                "[1892588326 0ms] dns: exchange stats.doubleclick.net. IN A",
                "[1892588326 0ms] dns: match[0] rule_set=geosite-category-ads-all => reject",
                // the AAAA lookup of the same visit
                "[1892588327 0ms] dns: exchange stats.doubleclick.net. IN AAAA",
                "[1892588327 0ms] dns: match[0] rule_set=geosite-category-ads-all => reject",
                // a reject without a known name still counts
                "[555 0ms] router: match[4] network=[tcp udp] => reject",
                "[4220005870 46ms] dns: exchanged ya.ru NOERROR 81",
            ],
        );
        let s = b.stats();
        assert_eq!(s.session, 3);
        assert_eq!(s.total, 3);
        assert_eq!(s.top, vec![("ad.doubleclick.net".to_string(), 1), ("stats.doubleclick.net".to_string(), 1)]);

        b.begin(true);
        assert_eq!(b.stats().session, 0);
        assert_eq!(b.stats().total, 3);
    }

    #[test]
    fn ignores_lines_when_not_counting() {
        let b = Blocks::new(None);
        b.begin(false);
        feed(&b, &["[1 0ms] dns: exchange x.com. IN A", "[1 0ms] dns: match[0] domain=x.com => reject"]);
        assert_eq!(b.stats().session, 0);
    }

    #[test]
    fn hosts_from_lines() {
        assert_eq!(host_in("router: sniffed protocol: tls, domain: a.b.com"), Some("a.b.com"));
        assert_eq!(host_in("dns: exchange mc.yandex.ru. IN HTTPS"), Some("mc.yandex.ru"));
        assert_eq!(host_in("inbound/mixed[mixed-in]: inbound connection to x.org:80"), Some("x.org"));
        assert_eq!(host_in("inbound/tun[tun-in]: inbound connection to 1.2.3.4:443"), None);
        assert_eq!(host_in("inbound/tun[tun-in]: inbound connection to [2a00::1]:443"), None);
        assert_eq!(host_in("dns: exchanged ya.ru NOERROR 81"), None);
        assert_eq!(split_id("[42 0ms] hello"), Some((42, "hello")));
        assert_eq!(split_id("no id"), None);
    }

    #[test]
    fn total_survives_restart() {
        let dir = std::env::temp_dir().join(format!("retunl-blocks-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("stats.json");
        let b = Blocks::new(Some(file.clone()));
        b.begin(true);
        feed(&b, &["[7 0ms] dns: exchange t.co. IN A", "[7 0ms] dns: match[1] domain=t.co => reject"]);
        b.end();
        assert_eq!(Blocks::new(Some(file)).stats().total, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
