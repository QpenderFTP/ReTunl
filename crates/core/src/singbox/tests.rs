use serde_json::json;

use super::*;
use crate::links::parse_link;
use crate::awg::CoreKind;

fn profile(id: &str, link: &str) -> Profile {
    let p = parse_link(link).unwrap();
    Profile { id: id.into(), name: p.name, outbound: p.outbound, subscription: None, link: Some(link.into()), created_at: 0 }
}

fn opts() -> BuildOptions {
    BuildOptions { ruleset_dir: PathBuf::from("C:\\rs"), controller_secret: "s3cret".into(), cache_file: None, extended_available: false, direct_dns_tls: false }
}

fn base() -> AppData {
    let mut d = AppData::default();
    d.profiles.push(profile("p1", "vless://id@nl.example.com:443?security=reality&pbk=K&sni=www.microsoft.com#Нидерланды"));
    d.profiles.push(profile("p2", "hy2://pw@fi.example.com:443?sni=fi.example.com#Финляндия"));
    d.settings.active_profile = Some("p1".into());
    d
}

fn rule(name: &str, route: Route) -> Rule {
    Rule { id: crate::util::new_id(), name: name.into(), enabled: true, route, ..Default::default() }
}

#[test]
fn full_tunnel_by_default() {
    let b = build(&base(), &opts()).unwrap();
    let c = &b.config;
    assert_eq!(c["route"]["final"], "Нидерланды");
    assert_eq!(c["outbounds"].as_array().unwrap().len(), 2, "only used servers are included");
    assert_eq!(c["outbounds"][1]["tag"], "Нидерланды");
    assert_eq!(c["dns"]["final"], DNS_REMOTE);
    assert_eq!(c["dns"]["servers"][1]["detour"], "Нидерланды");
    assert_eq!(c["dns"]["strategy"], "ipv4_only");
    assert_eq!(c["inbounds"][0]["type"], "tun");
    assert_eq!(c["inbounds"][0]["address"], json!(["172.19.0.1/30"]));
    assert_eq!(c["route"]["rules"][0], json!({"action": "sniff"}));
    assert_eq!(c["route"]["rules"][1], json!({"protocol": "dns", "action": "hijack-dns"}));
    assert_eq!(c["route"]["rules"][2]["ip_is_private"], true);
    assert_eq!(c["experimental"]["clash_api"]["secret"], "s3cret");
    assert_eq!(b.tags["Нидерланды"], "p1");
}

#[test]
fn selective_mode_and_rules() {
    let mut d = base();
    d.settings.final_route = Route::Direct;
    let mut yt = rule("YouTube", Route::Proxy);
    yt.rule_sets = vec!["geosite-youtube".into()];
    let mut discord = rule("Discord", Route::Profile { id: "p2".into() });
    // a program and a folder, written the way this system writes them
    let (apps, want) = match Os::CURRENT {
        Os::Windows => (["Discord.exe", "C:\\Games\\"], json!(["(?i)\\\\Discord\\.exe$", "(?i)^C:\\\\Games\\\\"])),
        Os::MacOs => (["Discord.app", "/Applications/Games/"], json!(["(?i)/Discord(?:\\.app/|$)", "(?i)^/Applications/Games/"])),
    };
    discord.apps = apps.map(String::from).to_vec();
    discord.rule_sets = vec!["geosite-discord".into()];
    let mut ads = rule("Реклама", Route::Block);
    ads.domains = vec!["ads.example.com".into(), "keyword:tracker".into()];
    let mut off = rule("Выключено", Route::Proxy);
    off.enabled = false;
    off.domains = vec!["off.example.com".into()];
    d.rules = vec![yt, discord, ads, off];

    let b = build(&d, &opts()).unwrap();
    let c = &b.config;
    let rules = c["route"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 3 + 3);
    assert_eq!(rules[3], json!({"rule_set": ["geosite-youtube"], "action": "route", "outbound": "Нидерланды"}));
    assert_eq!(rules[4]["type"], "logical");
    assert_eq!(rules[4]["mode"], "or");
    assert_eq!(rules[4]["rules"][0]["process_path_regex"], want);
    assert_eq!(rules[4]["rules"][1]["rule_set"], json!(["geosite-discord"]));
    assert_eq!(rules[4]["outbound"], "Финляндия");
    assert_eq!(rules[5], json!({"domain_keyword": ["tracker"], "domain_suffix": ["ads.example.com"], "action": "reject"}));
    assert_eq!(c["route"]["final"], "direct");
    // both servers are used
    assert_eq!(c["outbounds"].as_array().unwrap().len(), 3);
    // DNS: direct by default, rule sets and domains get their own resolvers
    assert_eq!(c["dns"]["final"], DNS_DIRECT);
    let dns_rules = c["dns"]["rules"].as_array().unwrap();
    assert_eq!(dns_rules[0], json!({"rule_set": ["geosite-youtube"], "action": "route", "server": DNS_REMOTE}));
    assert_eq!(dns_rules[1], json!({"rule_set": ["geosite-discord"], "action": "route", "server": DNS_REMOTE}));
    assert_eq!(dns_rules[2]["action"], "reject");
    // rule sets point to local files
    let rs = c["route"]["rule_set"].as_array().unwrap();
    assert_eq!(rs.len(), 2);
    // joined with this system's separator
    assert_eq!(rs[0]["path"], opts().ruleset_dir.join("geosite-discord.srs").to_string_lossy().into_owned());
    assert_eq!(b.rule_sets.len(), 2);
}

#[test]
fn match_all_makes_one_rule_and_no_dns_rule() {
    let mut d = base();
    let mut r = rule("Chrome только YouTube", Route::Proxy);
    r.match_all = true;
    r.apps = vec!["chrome".into()];
    r.rule_sets = vec!["geosite-youtube".into()];
    r.ports = vec!["443".into(), "8000-9000".into()];
    r.network = Some("tcp".into());
    d.rules = vec![r];
    d.settings.final_route = Route::Direct;
    let c = build(&d, &opts()).unwrap().config;
    let chrome = match Os::CURRENT {
        Os::Windows => "(?i)\\\\chrome\\.exe$",
        Os::MacOs => "(?i)/chrome(?:\\.app/|$)",
    };
    assert_eq!(
        c["route"]["rules"][3],
        json!({
            "process_path_regex": [chrome],
            "rule_set": ["geosite-youtube"],
            "port": [443],
            "port_range": ["8000:9000"],
            "network": ["tcp"],
            "action": "route",
            "outbound": "Нидерланды"
        })
    );
    assert!(c["dns"].get("rules").is_none());
}

#[test]
fn errors_are_clear() {
    let mut d = base();
    d.settings.active_profile = None;
    let e = build(&d, &opts()).unwrap_err();
    assert!(e.0.contains("сервер не выбран"), "{e}");

    let mut d = base();
    let mut r = rule("Сломанное", Route::Profile { id: "gone".into() });
    r.domains = vec!["x.com".into()];
    d.rules = vec![r];
    assert!(build(&d, &opts()).unwrap_err().0.contains("удалённый сервер"));

    let mut d = base();
    let mut r = rule("Порт", Route::Direct);
    r.ports = vec!["99999".into()];
    d.rules = vec![r];
    assert!(build(&d, &opts()).unwrap_err().0.contains("Порт"));
}

#[test]
fn everything_direct_needs_no_server() {
    let mut d = base();
    d.settings.active_profile = None;
    d.settings.final_route = Route::Direct;
    let mut r = rule("Торренты", Route::Direct);
    r.apps = vec!["qbittorrent.exe".into()];
    d.rules = vec![r];
    let c = build(&d, &opts()).unwrap().config;
    assert_eq!(c["outbounds"].as_array().unwrap().len(), 1);
    assert_eq!(c["dns"]["servers"].as_array().unwrap().len(), 1);
}

#[test]
fn block_everything_else() {
    let mut d = base();
    d.settings.final_route = Route::Block;
    let mut r = rule("Браузер", Route::Proxy);
    r.apps = vec!["firefox.exe".into()];
    d.rules = vec![r];
    let c = build(&d, &opts()).unwrap().config;
    let rules = c["route"]["rules"].as_array().unwrap();
    assert_eq!(rules.last().unwrap(), &json!({"network": ["tcp", "udp"], "action": "reject"}));
}

#[test]
fn wireguard_goes_to_endpoints_and_proxy_mode() {
    let mut d = base();
    d.profiles.push(profile(
        "wg",
        "wireguard://cHJpdg%3D%3D@wg.example.com:51820?publickey=cHVi&address=10.0.0.2#WG",
    ));
    d.settings.active_profile = Some("wg".into());
    d.settings.mode = InboundMode::SystemProxy;
    d.settings.ipv6 = true;
    let c = build(&d, &opts()).unwrap().config;
    assert_eq!(c["endpoints"][0]["tag"], "WG");
    assert_eq!(c["endpoints"][0]["address"], json!(["10.0.0.2/32"]));
    assert_eq!(c["outbounds"].as_array().unwrap().len(), 1);
    assert_eq!(c["inbounds"][0], json!({"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080, "set_system_proxy": true}));
    assert_eq!(c["dns"]["strategy"], "prefer_ipv4");
    // no DNS hijack rule without TUN
    assert!(c["route"]["rules"].as_array().unwrap().iter().all(|r| r.get("protocol").is_none()));
}

#[test]
fn duplicate_names_get_unique_tags() {
    let mut d = base();
    d.profiles[1].name = "Нидерланды".into();
    d.profiles.push(profile("p3", "trojan://pw@x.example.com:443#direct"));
    let mut r1 = rule("a", Route::Profile { id: "p2".into() });
    r1.domains = vec!["a.com".into()];
    let mut r2 = rule("b", Route::Profile { id: "p3".into() });
    r2.domains = vec!["b.com".into()];
    d.rules = vec![r1, r2];
    let b = build(&d, &opts()).unwrap();
    let mut tags: Vec<_> = b.tags.keys().cloned().collect();
    tags.sort();
    assert_eq!(tags, vec!["direct #2", "Нидерланды", "Нидерланды #2"]);
}

#[test]
fn matchers() {
    let win = |e: &str| app_regex_for(e, Os::Windows).unwrap();
    assert_eq!(win("Discord"), "(?i)\\\\Discord\\.exe$");
    assert_eq!(win("C:/Tools/x.exe"), "(?i)^C:\\\\Tools\\\\x\\.exe$");
    assert_eq!(win("D:\\Games\\"), "(?i)^D:\\\\Games\\\\");
    // rules made on a Mac keep working by program name
    assert_eq!(win("/Applications/Telegram.app"), "(?i)\\\\Telegram\\.exe$");
    assert_eq!(win("Discord.app"), "(?i)\\\\Discord\\.exe$");

    let mac = |e: &str| app_regex_for(e, Os::MacOs).unwrap();
    // a bare name: the binary, or anything inside its bundle (helper processes)
    assert_eq!(mac("Discord"), "(?i)/Discord(?:\\.app/|$)");
    assert_eq!(mac("Google Chrome.app"), "(?i)/Google Chrome(?:\\.app/|$)");
    assert_eq!(mac("/Applications/Telegram.app"), "(?i)^/Applications/Telegram\\.app/");
    assert_eq!(mac("/Applications/Telegram.app/"), "(?i)^/Applications/Telegram\\.app/");
    assert_eq!(mac("/usr/bin/curl"), "(?i)^/usr/bin/curl$");
    assert_eq!(mac("/opt/tools/"), "(?i)^/opt/tools/");
    // rules made on Windows keep working by program name
    assert_eq!(mac("Telegram.exe"), "(?i)/Telegram(?:\\.app/|$)");
    assert_eq!(mac("C:\\Program Files (x86)\\Steam\\"), "(?i)/Steam(?:\\.app/|$)");
    assert!(app_regex_for(" ", Os::MacOs).is_err());
    assert!(app_regex_for(".exe", Os::MacOs).is_err());
    assert_eq!(domain_matcher("https://www.Example.com:8443/path?q").unwrap(), ("domain_suffix", "www.example.com".into()));
    assert_eq!(domain_matcher("*.example.com").unwrap(), ("domain_suffix", "example.com".into()));
    assert_eq!(domain_matcher("full:a.example.com").unwrap(), ("domain", "a.example.com".into()));
    assert_eq!(domain_matcher("10.0.0.0/8").unwrap(), ("ip_cidr", "10.0.0.0/8".into()));
    // Cyrillic names become punycode, the form sing-box sees in traffic
    assert_eq!(domain_matcher("рф").unwrap(), ("domain_suffix", "xn--p1ai".into()));
    assert_eq!(domain_matcher("*.РФ").unwrap(), ("domain_suffix", "xn--p1ai".into()));
    assert_eq!(domain_matcher("https://Президент.рф/news").unwrap(), ("domain_suffix", "xn--d1abbgf6aiiy.xn--p1ai".into()));
    assert_eq!(domain_matcher("full:президент.рф").unwrap(), ("domain", "xn--d1abbgf6aiiy.xn--p1ai".into()));
    assert!(domain_matcher("not a domain").is_err());
    assert_eq!(cidr("1.2.3.4").unwrap(), "1.2.3.4/32");
    assert_eq!(cidr("2001:db8::/32").unwrap(), "2001:db8::/32");
    assert!(cidr("1.2.3.4/33").is_err());
}

#[test]
fn probe_config() {
    let d = base();
    let refs: Vec<&Profile> = d.profiles.iter().collect();
    let c = build_probe(&refs, &d.settings, 23456, "x", CoreKind::Official).unwrap();
    assert_eq!(c["outbounds"][1]["tag"], "p1");
    assert_eq!(c["outbounds"][2]["tag"], "p2");
    assert!(c.get("inbounds").is_none());
}

#[test]
fn strict_tun_sends_direct_dns_over_tls() {
    let mut d = base();
    d.settings.mode = InboundMode::Tun;
    d.settings.tun.strict_route = true;
    let tls = BuildOptions { direct_dns_tls: true, ..opts() };
    let c = build(&d, &tls).unwrap().config;
    assert_eq!(c["dns"]["servers"][0], json!({"type": "tls", "tag": DNS_DIRECT, "server": "77.88.8.8"}));
    // the engine's check is required
    let c = build(&d, &opts()).unwrap().config;
    assert_eq!(c["dns"]["servers"][0]["type"], "udp");
    // only TUN with strict route needs it
    d.settings.tun.strict_route = false;
    assert_eq!(build(&d, &tls).unwrap().config["dns"]["servers"][0]["type"], "udp");
    d.settings.tun.strict_route = true;
    d.settings.mode = InboundMode::SystemProxy;
    assert_eq!(build(&d, &tls).unwrap().config["dns"]["servers"][0]["type"], "udp");
    // a resolver without a TLS port stays as chosen
    d.settings.mode = InboundMode::Tun;
    d.settings.dns.direct = "192.168.0.1".into();
    assert_eq!(build(&d, &tls).unwrap().config["dns"]["servers"][0], json!({"type": "udp", "tag": DNS_DIRECT, "server": "192.168.0.1"}));
}
