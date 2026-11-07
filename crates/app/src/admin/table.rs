//! `clientsTable`: the names AmneziaVPN gives clients, kept next to the server
//! config inside the container. A JSON array of
//! `{"clientId": key or id, "userData": {"clientName": …, "creationDate": …}}`;
//! very old servers have an object `{id: {"clientName": …}}` instead.

use std::collections::HashMap;

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub created: Option<String>,
}

fn rows(text: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Array(a)) => a,
        Ok(Value::Object(o)) => o
            .into_iter()
            .map(|(id, v)| json!({ "clientId": id, "userData": { "clientName": v["clientName"] } }))
            .collect(),
        _ => Vec::new(),
    }
}

pub fn read(text: &str) -> HashMap<String, Entry> {
    rows(text)
        .into_iter()
        .filter_map(|r| {
            let id = r["clientId"].as_str()?.to_string();
            let u = &r["userData"];
            let name = u["clientName"].as_str().unwrap_or("").to_string();
            let created = u["creationDate"].as_str().map(str::to_string).filter(|s| !s.is_empty());
            Some((id, Entry { name, created }))
        })
        .collect()
}

/// Add a client or rename one; other fields of its row stay.
pub fn set(text: &str, id: &str, name: &str, created: Option<&str>) -> String {
    let mut all = rows(text);
    match all.iter_mut().find(|r| r["clientId"] == id) {
        Some(r) => {
            if !r["userData"].is_object() {
                r["userData"] = json!({});
            }
            r["userData"]["clientName"] = json!(name);
        }
        None => {
            let mut user = json!({ "clientName": name });
            if let Some(c) = created {
                user["creationDate"] = json!(c);
            }
            all.push(json!({ "clientId": id, "userData": user }));
        }
    }
    serde_json::to_string_pretty(&all).expect("plain JSON")
}

pub fn remove(text: &str, id: &str) -> String {
    let mut all = rows(text);
    all.retain(|r| r["clientId"] != id);
    serde_json::to_string_pretty(&all).expect("plain JSON")
}

/// The date the way AmneziaVPN writes it (Qt's default, `Sat Nov 7 14:03:12 2026`), in UTC.
pub fn qt_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // civil-from-days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    format!(
        "{} {} {} {:02}:{:02}:{:02} {}",
        WD[days.rem_euclid(7) as usize],
        MON[(month - 1) as usize],
        day,
        secs / 3600,
        secs % 3600 / 60,
        secs % 60,
        year
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_edit() {
        let t = r#"[{"clientId":"AAA=","userData":{"clientName":"Phone","creationDate":"Mon Oct 5 10:00:00 2026","latestHandshake":"x"}}]"#;
        assert_eq!(read(t)["AAA="], Entry { name: "Phone".into(), created: Some("Mon Oct 5 10:00:00 2026".into()) });
        let t2 = set(t, "BBB=", "Laptop", Some("now"));
        assert_eq!(read(&t2).len(), 2);
        let t3 = set(&t2, "AAA=", "Old phone", None);
        assert_eq!(read(&t3)["AAA="].name, "Old phone");
        assert!(t3.contains("latestHandshake"), "other fields stay");
        let t4 = remove(&t3, "AAA=");
        assert_eq!(read(&t4).keys().collect::<Vec<_>>(), ["BBB="]);
        // old object format and garbage
        assert_eq!(read(r#"{"X":{"clientName":"Old"}}"#)["X"].name, "Old");
        assert!(read("").is_empty());
        assert_eq!(read(&set("", "Z", "z", None)).len(), 1);
    }

    #[test]
    fn dates() {
        assert_eq!(qt_date(0), "Thu Jan 1 00:00:00 1970");
        assert_eq!(qt_date(1_794_060_192), "Sat Nov 7 14:03:12 2026");
    }
}
