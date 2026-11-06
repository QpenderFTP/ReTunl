use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::json;

use super::*;

fn ob(link: &str) -> Value {
    parse_link(link).unwrap_or_else(|e| panic!("{link}: {e}")).outbound
}

#[test]
fn vless_reality_vision() {
    let link = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&type=tcp&headerType=none#RU%20Reality";
    let p = parse_link(link).unwrap();
    assert_eq!(p.name, "RU Reality");
    assert_eq!(
        p.outbound,
        json!({
            "type": "vless",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "flow": "xtls-rprx-vision",
            "packet_encoding": "xudp",
            "tls": {
                "enabled": true,
                "server_name": "www.microsoft.com",
                "utls": {"enabled": true, "fingerprint": "chrome"},
                "reality": {
                    "enabled": true,
                    "public_key": "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
                    "short_id": "6ba85179e30d4fc2"
                }
            }
        })
    );
}

#[test]
fn vless_reality_without_fp_gets_chrome() {
    let o = ob("vless://id@h.example:443?security=reality&pbk=KEY&sni=a.com");
    assert_eq!(o["tls"]["utls"]["fingerprint"], "chrome");
    assert!(o["tls"]["reality"]["short_id"].is_null());
}

#[test]
fn vless_reality_requires_pbk() {
    assert!(matches!(
        parse_link("vless://id@h.example:443?security=reality&sni=a.com"),
        Err(LinkError::Invalid(_))
    ));
}

#[test]
fn vless_ws_tls_with_early_data() {
    let o = ob("vless://id@example.com:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1#WS");
    assert_eq!(o["transport"], json!({
        "type": "ws",
        "path": "/ws",
        "headers": {"Host": "cdn.example.com"},
        "max_early_data": 2048,
        "early_data_header_name": "Sec-WebSocket-Protocol"
    }));
    assert_eq!(o["tls"]["server_name"], "cdn.example.com");
    assert_eq!(o["tls"]["alpn"], json!(["h2", "http/1.1"]));
}

#[test]
fn vless_grpc_and_httpupgrade() {
    let o = ob("vless://id@example.com:443?security=tls&type=grpc&serviceName=svc&mode=gun");
    assert_eq!(o["transport"], json!({"type": "grpc", "service_name": "svc"}));
    let o = ob("vless://id@example.com:80?type=httpupgrade&path=%2Fup&host=h.example.com");
    assert_eq!(o["transport"], json!({"type": "httpupgrade", "host": "h.example.com", "path": "/up"}));
    assert!(o.get("tls").is_none());
}

#[test]
fn vless_xhttp() {
    let extra = r#"{"xPaddingBytes":"100-1000","scMaxEachPostBytes":{"from":500000,"to":1000000},"noGRPCHeader":true,"xmux":{"maxConcurrency":"16-32","cMaxReuseTimes":0}}"#;
    let link = format!(
        "vless://id@example.com:443?security=tls&type=xhttp&path=%2Fxh&host=cdn.example.com&mode=packet-up&extra={}#X",
        percent_encoding::utf8_percent_encode(extra, percent_encoding::NON_ALPHANUMERIC)
    );
    let ob = parse_link(&link).unwrap().outbound;
    assert_eq!(
        ob["transport"],
        json!({
            "type": "xhttp", "path": "/xh", "host": "cdn.example.com", "mode": "packet-up",
            "x_padding_bytes": "100-1000", "sc_max_each_post_bytes": "500000-1000000", "no_grpc_header": true,
            "xmux": {"max_concurrency": "16-32", "c_max_reuse_times": 0},
        })
    );
    assert_eq!(crate::awg::core_need(&ob), crate::awg::CoreNeed::Extended);
    assert!(matches!(
        parse_link("vless://id@example.com:443?security=tls&type=xhttp&mode=bogus"),
        Err(LinkError::Unsupported(_))
    ));
    assert!(matches!(
        parse_link("vless://id@example.com:443?security=tls&type=xhttp&extra=%7B%22downloadSettings%22%3A%7B%7D%7D"),
        Err(LinkError::Unsupported(_))
    ));
}

#[test]
fn vless_ipv6_server() {
    let o = ob("vless://id@[2001:db8::5]:8443?security=none#v6");
    assert_eq!(o["server"], "2001:db8::5");
    assert_eq!(o["server_port"], 8443);
}

#[test]
fn vmess_v2rayn_json() {
    let cfg = json!({
        "v": "2", "ps": "Мой VMess", "add": "vm.example.com", "port": "443",
        "id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "aid": "0", "scy": "auto",
        "net": "ws", "type": "none", "host": "vm.example.com", "path": "/ray",
        "tls": "tls", "sni": "vm.example.com", "fp": "firefox"
    });
    let link = format!("vmess://{}", STANDARD.encode(cfg.to_string()));
    let p = parse_link(&link).unwrap();
    assert_eq!(p.name, "Мой VMess");
    assert_eq!(p.outbound["type"], "vmess");
    assert_eq!(p.outbound["server_port"], 443);
    assert_eq!(p.outbound["alter_id"], 0);
    assert_eq!(p.outbound["transport"]["path"], "/ray");
    assert_eq!(p.outbound["tls"]["utls"]["fingerprint"], "firefox");
}

#[test]
fn vmess_numeric_port_and_grpc() {
    let cfg = json!({"add": "1.1.1.1", "port": 8080, "id": "u", "net": "grpc", "path": "svc", "tls": ""});
    let o = ob(&format!("vmess://{}", URL_SAFE_NO_PAD.encode(cfg.to_string())));
    assert_eq!(o["server_port"], 8080);
    assert_eq!(o["transport"]["service_name"], "svc");
    assert!(o.get("tls").is_none());
}

#[test]
fn trojan_defaults_to_tls() {
    let o = ob("trojan://p%40ss@example.com:443?sni=front.example.com#T");
    assert_eq!(o["password"], "p@ss");
    assert_eq!(o["tls"]["enabled"], true);
    assert_eq!(o["tls"]["server_name"], "front.example.com");
    let o = ob("trojan://pass@example.com:443?security=none");
    assert!(o.get("tls").is_none());
}

#[test]
fn shadowsocks_formats() {
    // SIP002 with base64 user info
    let ui = URL_SAFE_NO_PAD.encode("aes-256-gcm:password");
    let o = ob(&format!("ss://{ui}@1.2.3.4:8388#SS"));
    assert_eq!(o, json!({"type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388, "method": "aes-256-gcm", "password": "password"}));

    // SIP022 clear text with percent-encoded key
    let o = ob("ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@1.2.3.4:443#ss22");
    assert_eq!(o["method"], "2022-blake3-aes-128-gcm");
    assert_eq!(o["password"], "YWJjZGVmZ2hpamtsbW5vcA==");

    // legacy: everything in base64
    let all = STANDARD.encode("chacha20-ietf-poly1305:test@192.168.100.1:8888");
    let p = parse_link(&format!("ss://{all}#legacy")).unwrap();
    assert_eq!(p.name, "legacy");
    assert_eq!(p.outbound["server"], "192.168.100.1");
    assert_eq!(p.outbound["server_port"], 8888);

    // plugin
    let o = ob(&format!("ss://{ui}@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#p"));
    assert_eq!(o["plugin"], "obfs-local");
    assert_eq!(o["plugin_opts"], "obfs=http;obfs-host=example.com");
}

#[test]
fn shadowsocks_unknown_method() {
    let ui = STANDARD.encode("bf-cfb:pw");
    assert!(matches!(parse_link(&format!("ss://{ui}@1.2.3.4:1#x")), Err(LinkError::Unsupported(_))));
}

#[test]
fn hysteria2_full() {
    let o = ob("hysteria2://letmein@example.com:443/?insecure=1&obfs=salamander&obfs-password=gawrgura&sni=real.example.com#hy2");
    assert_eq!(o, json!({
        "type": "hysteria2",
        "server": "example.com",
        "server_port": 443,
        "password": "letmein",
        "obfs": {"type": "salamander", "password": "gawrgura"},
        "tls": {"enabled": true, "server_name": "real.example.com", "insecure": true, "alpn": ["h3"]}
    }));
}

#[test]
fn hysteria2_port_hopping() {
    let o = ob("hy2://pass@example.com:20000-30000?sni=x.example.com#r");
    assert_eq!(o["server_ports"], json!(["20000:30000"]));
    assert!(o.get("server_port").is_none());
    let o = ob("hy2://pass@example.com:443?mport=443,5000-6000");
    assert_eq!(o["server_ports"], json!(["443:443", "5000:6000"]));
}

#[test]
fn hysteria2_user_pass_auth() {
    let o = ob("hy2://user:secret@1.2.3.4:443");
    assert_eq!(o["password"], "user:secret");
    // IP without sni → no server_name
    assert!(o["tls"].get("server_name").is_none());
}

#[test]
fn hysteria_v1() {
    let o = ob("hysteria://hy.example.com:36712?protocol=udp&auth=pw&peer=hy.example.com&insecure=1&upmbps=50&downmbps=200&alpn=hysteria&obfsParam=xyz#h1");
    assert_eq!(o["type"], "hysteria");
    assert_eq!(o["up_mbps"], 50);
    assert_eq!(o["down_mbps"], 200);
    assert_eq!(o["auth_str"], "pw");
    assert_eq!(o["obfs"], "xyz");
    assert_eq!(o["tls"]["alpn"], json!(["hysteria"]));
}

#[test]
fn tuic_v5() {
    let o = ob("tuic://2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365:pa%3Ass@example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=example.com&allow_insecure=0#tuic");
    assert_eq!(o["uuid"], "2DD61D93-75D8-4DA4-AC0E-6AECE7EAC365");
    assert_eq!(o["password"], "pa:ss");
    assert_eq!(o["congestion_control"], "bbr");
    assert_eq!(o["udp_relay_mode"], "native");
    assert!(o["tls"].get("insecure").is_none());
}

#[test]
fn wireguard_link() {
    let o = ob("wireguard://kBmW3Hn5vN%2F8%2BqTq0xTm2C2yHn1m8xQdW6zX5e9T0Ug%3D@162.159.192.1:2408?publickey=bmXOC%2BF1FxEMF9dyiK2H5%2F1SUtzH0JuVo51h2wPfgyo%3D&address=172.16.0.2%2F32%2C2606%3A4700%3A110%3A8a36%3A%3A1%2F128&reserved=1%2C2%2C3&mtu=1280#warp");
    assert_eq!(o["type"], "wireguard");
    assert_eq!(o["private_key"], "kBmW3Hn5vN/8+qTq0xTm2C2yHn1m8xQdW6zX5e9T0Ug=");
    assert_eq!(o["address"], json!(["172.16.0.2/32", "2606:4700:110:8a36::1/128"]));
    assert_eq!(o["mtu"], 1280);
    assert_eq!(o["peers"][0]["public_key"], "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=");
    assert_eq!(o["peers"][0]["reserved"], json!([1, 2, 3]));
    assert_eq!(o["peers"][0]["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));
}

#[test]
fn socks_and_anytls() {
    let o = ob("socks5://user:pw@127.0.0.1:1080#local");
    assert_eq!(o, json!({"type": "socks", "server": "127.0.0.1", "server_port": 1080, "version": "5", "username": "user", "password": "pw"}));
    let o = ob("anytls://secret@any.example.com:443?insecure=1#a");
    assert_eq!(o["tls"], json!({"enabled": true, "server_name": "any.example.com", "insecure": true}));
}

#[test]
fn unknown_and_garbage() {
    assert!(matches!(parse_link("foo://bar"), Err(LinkError::UnknownScheme(_))));
    assert!(matches!(parse_link("just text"), Err(LinkError::Invalid(_))));
    assert!(matches!(parse_link("ssr://abc"), Err(LinkError::Unsupported(_))));
    assert!(parse_link("vless://@example.com:443").is_err());
    assert!(parse_link("vless://id@example.com").is_err());
}
