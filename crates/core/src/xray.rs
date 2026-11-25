//! Translate a saved VLESS outbound, including edits made after import.
//! Reject unknown options rather than silently changing the connection.
use serde_json::{json, Map, Value};

fn fields(value: &Value, allowed: &[&str], section: &str) -> Result<(), String> {
    let obj = value
        .as_object()
        .ok_or_else(|| format!("Xray: неверный формат {section}"))?;
    if let Some(key) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!(
            "Параметр {section}.{key} пока нельзя перенести в Xray. Выберите sing-box для этого профиля."
        ));
    }
    Ok(())
}

fn copy(src: &Value, dst: &mut Value, names: &[(&str, &str)]) {
    for &(from, to) in names {
        if let Some(v) = src.get(from) {
            dst[to] = v.clone();
        }
    }
}

pub fn vless(ob: &Value) -> Result<Value, String> {
    if ob["type"] != "vless" {
        return Err("Выбор Xray доступен для VLESS.".into());
    }
    fields(
        ob,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "uuid",
            "flow",
            "packet_encoding",
            "tls",
            "transport",
        ],
        "VLESS",
    )?;
    if ob["server"].as_str().is_none_or(str::is_empty)
        || ob["uuid"].as_str().is_none_or(str::is_empty)
        || !ob["server_port"].as_u64().is_some_and(|p| (1..=65535).contains(&p))
    {
        return Err("Для Xray нужны адрес, порт и UUID VLESS-сервера.".into());
    }
    if ob.get("packet_encoding").is_some_and(|v| v != "xudp") {
        return Err("Для сравнения с Xray выберите кодирование пакетов xudp.".into());
    }
    let mut settings =
        json!({"address": ob["server"], "port": ob["server_port"], "id": ob["uuid"], "encryption": "none"});
    copy(ob, &mut settings, &[("flow", "flow")]);
    let mut stream = json!({"network": "raw", "security": "none"});
    if let Some(tls) = ob.get("tls") {
        fields(
            tls,
            &["enabled", "server_name", "utls", "alpn", "reality", "insecure"],
            "tls",
        )?;
        if tls.get("enabled").is_some_and(|v| !v.is_boolean()) {
            return Err("Поле tls.enabled должно быть логическим значением.".into());
        }
        if tls["enabled"] == true {
            if tls["insecure"] == true {
                return Err("Для этого сравнения Xray требует проверку сертификата TLS.".into());
            }
            let mut params = json!({});
            copy(tls, &mut params, &[("server_name", "serverName")]);
            if let Some(u) = tls.get("utls") {
                fields(u, &["enabled", "fingerprint"], "utls")?;
                if u["enabled"] == true {
                    copy(u, &mut params, &[("fingerprint", "fingerprint")]);
                }
            }
            if tls.pointer("/reality/enabled").is_some_and(|v| !v.is_boolean()) {
                return Err("Поле reality.enabled должно быть логическим значением.".into());
            }
            if tls.pointer("/reality/enabled") == Some(&Value::Bool(true)) {
                let reality = &tls["reality"];
                fields(reality, &["enabled", "public_key", "short_id"], "reality")?;
                if reality["public_key"].as_str().is_none_or(str::is_empty) {
                    return Err("У профиля REALITY нет публичного ключа.".into());
                }
                if tls.get("alpn").is_some() {
                    return Err("Xray задаёт ALPN для REALITY через отпечаток клиента. Для профиля с явным ALPN выберите sing-box.".into());
                }
                copy(
                    reality,
                    &mut params,
                    &[("public_key", "password"), ("short_id", "shortId")],
                );
                stream["security"] = json!("reality");
                stream["realitySettings"] = params;
            } else {
                copy(tls, &mut params, &[("alpn", "alpn")]);
                stream["security"] = json!("tls");
                stream["tlsSettings"] = params;
            }
        }
    }
    if let Some(tr) = ob.get("transport") {
        transport(tr, &mut stream)?;
    }
    Ok(json!({"protocol": "vless", "settings": settings, "streamSettings": stream}))
}

fn transport(tr: &Value, stream: &mut Value) -> Result<(), String> {
    let network = tr["type"].as_str().ok_or("У транспорта VLESS нет типа")?;
    let mut params = Value::Object(Map::new());
    match network {
        "ws" => {
            fields(
                tr,
                &["type", "path", "headers", "max_early_data", "early_data_header_name"],
                "ws",
            )?;
            copy(tr, &mut params, &[("path", "path"), ("headers", "headers")]);
            if let Some(host) = params["headers"].as_object_mut().and_then(|h| h.remove("Host")) {
                params["host"] = host;
            }
            if let Some(n) = tr["max_early_data"].as_u64().filter(|n| *n > 0) {
                if tr["early_data_header_name"] != "Sec-WebSocket-Protocol" {
                    return Err("Xray поддерживает ранние данные WebSocket в Sec-WebSocket-Protocol.".into());
                }
                let path = tr["path"].as_str().unwrap_or("/");
                let sep = if path.contains('?') { '&' } else { '?' };
                params["path"] = json!(format!("{path}{sep}ed={n}"));
            }
        }
        "grpc" => {
            fields(tr, &["type", "service_name"], "grpc")?;
            copy(tr, &mut params, &[("service_name", "serviceName")]);
        }
        "httpupgrade" => {
            fields(tr, &["type", "path", "host", "headers"], "httpupgrade")?;
            copy(
                tr,
                &mut params,
                &[("path", "path"), ("host", "host"), ("headers", "headers")],
            );
        }
        "xhttp" => {
            fields(
                tr,
                &[
                    "type",
                    "path",
                    "host",
                    "mode",
                    "headers",
                    "x_padding_bytes",
                    "sc_max_each_post_bytes",
                    "sc_min_posts_interval_ms",
                    "sc_max_buffered_posts",
                    "no_grpc_header",
                    "xmux",
                ],
                "xhttp",
            )?;
            copy(
                tr,
                &mut params,
                &[
                    ("path", "path"),
                    ("host", "host"),
                    ("mode", "mode"),
                    ("headers", "headers"),
                    ("x_padding_bytes", "xPaddingBytes"),
                    ("sc_max_each_post_bytes", "scMaxEachPostBytes"),
                    ("sc_min_posts_interval_ms", "scMinPostsIntervalMs"),
                    ("sc_max_buffered_posts", "scMaxBufferedPosts"),
                    ("no_grpc_header", "noGRPCHeader"),
                ],
            );
            if let Some(m) = tr.get("xmux") {
                fields(
                    m,
                    &[
                        "max_concurrency",
                        "max_connections",
                        "c_max_reuse_times",
                        "h_max_request_times",
                        "h_max_reusable_secs",
                        "h_keep_alive_period",
                    ],
                    "xmux",
                )?;
                let mut xmux = json!({});
                copy(
                    m,
                    &mut xmux,
                    &[
                        ("max_concurrency", "maxConcurrency"),
                        ("max_connections", "maxConnections"),
                        ("c_max_reuse_times", "cMaxReuseTimes"),
                        ("h_max_request_times", "hMaxRequestTimes"),
                        ("h_max_reusable_secs", "hMaxReusableSecs"),
                        ("h_keep_alive_period", "hKeepAlivePeriod"),
                    ],
                );
                params["xmux"] = xmux;
            }
        }
        other => {
            return Err(format!(
                "Для транспорта «{other}» переключение на Xray пока недоступно."
            ))
        }
    }
    stream["network"] = json!(network);
    stream[format!("{network}Settings")] = params;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::parse_link;

    #[test]
    fn imported_reality_xhttp_keeps_transport_options() {
        let p = parse_link("vless://a1bcd215-f583-4c13-bc56-42e19be82b83@example.org:443?security=reality&sni=example.net&pbk=test&sid=ac&fp=firefox&type=xhttp&path=%2Fmy-path&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%22100-500%22%7D").unwrap();
        let out = vless(&p.outbound).unwrap();
        let stream = &out["streamSettings"];
        assert_eq!(
            stream["realitySettings"],
            json!({"serverName":"example.net","password":"test","shortId":"ac","fingerprint":"firefox"})
        );
        assert_eq!(
            stream["xhttpSettings"],
            json!({"path":"/my-path","mode":"stream-up","xPaddingBytes":"100-500"})
        );
        assert_eq!(out["settings"]["address"], "example.org");
    }

    #[test]
    fn switching_keeps_tls_pins_or_refuses_the_profile() {
        let p = parse_link("vless://a1bcd215-f583-4c13-bc56-42e19be82b83@example.org:443?security=tls&type=ws&host=web.example.org").unwrap();
        let mut ob = p.outbound;
        assert_eq!(
            vless(&ob).unwrap()["streamSettings"]["wsSettings"]["host"],
            "web.example.org"
        );
        ob["tls"]["certificate_public_key_sha256"] = json!(["pin"]);
        assert!(vless(&ob).unwrap_err().contains("certificate_public_key_sha256"));
    }
}
