//! Client for sing-box's control API (Clash-compatible) on 127.0.0.1.

use std::time::Duration;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use reqwest::Method;
use serde_json::Value;

#[derive(Clone)]
pub struct Clash {
    base: String,
    secret: String,
    http: reqwest::Client,
}

impl Clash {
    pub fn new(port: u16, secret: &str) -> Clash {
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("http client");
        Clash { base: format!("http://127.0.0.1:{port}"), secret: secret.to_string(), http }
    }

    fn req(&self, m: Method, path: &str) -> reqwest::RequestBuilder {
        self.http.request(m, format!("{}{}", self.base, path)).bearer_auth(&self.secret)
    }

    pub async fn alive(&self) -> bool {
        self.req(Method::GET, "/version")
            .timeout(Duration::from_millis(800))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    pub async fn connections(&self) -> Result<Value, String> {
        let r = self
            .req(Method::GET, "/connections")
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        r.json().await.map_err(|e| e.to_string())
    }

    pub async fn close(&self, id: &str) -> Result<(), String> {
        let path = format!("/connections/{}", utf8_percent_encode(id, NON_ALPHANUMERIC));
        self.req(Method::DELETE, &path).send().await.map(|_| ()).map_err(|e| e.to_string())
    }

    pub async fn close_all(&self) -> Result<(), String> {
        self.req(Method::DELETE, "/connections").send().await.map(|_| ()).map_err(|e| e.to_string())
    }

    /// Real request through an outbound; milliseconds or an error text.
    pub async fn delay(&self, outbound: &str, url: &str, timeout_ms: u32) -> Result<u32, String> {
        let path = format!("/proxies/{}/delay", utf8_percent_encode(outbound, NON_ALPHANUMERIC));
        let r = self
            .req(Method::GET, &path)
            .query(&[("url", url.to_string()), ("timeout", timeout_ms.to_string())])
            .timeout(Duration::from_millis(timeout_ms as u64 + 4000))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let ok = r.status().is_success();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if ok {
            v.get("delay").and_then(Value::as_u64).map(|d| d as u32).ok_or_else(|| "пустой ответ".into())
        } else {
            let msg = v.get("message").and_then(Value::as_str).unwrap_or("ошибка");
            Err(match msg {
                "Timeout" | "timeout" => "нет ответа".into(),
                m => m.to_string(),
            })
        }
    }
}
