//! Rules and the user's own templates for them.

use retunl_core::presets;
use retunl_core::singbox::validate_rule;
use retunl_core::util::{new_id, now_unix};
use retunl_core::{CustomPreset, Route, Rule};

use super::{St, R};

fn clean(list: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in list {
        let t = item.trim().to_string();
        if !t.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(&t)) {
            out.push(t);
        }
    }
    out
}

#[tauri::command]
pub fn save_rule(st: St<'_>, rule: Rule) -> R<Rule> {
    let mut rule = rule;
    rule.name = rule.name.trim().to_string();
    rule.apps = clean(rule.apps);
    rule.domains = clean(rule.domains);
    rule.ips = clean(rule.ips);
    rule.ports = clean(rule.ports);
    rule.rule_sets = clean(rule.rule_sets);
    rule.network = rule.network.map(|n| n.trim().to_lowercase()).filter(|n| !n.is_empty());
    validate_rule(&rule)?;
    if let Route::Profile { id } = &rule.route {
        if st.snapshot().profile(id).is_none() {
            return Err("Выбранный в правиле сервер не найден".into());
        }
    }
    if rule.id.is_empty() {
        rule.id = new_id();
    }
    let saved = rule.clone();
    st.mutate(|d| {
        match d.rules.iter_mut().find(|r| r.id == rule.id) {
            Some(r) => *r = rule,
            None => d.rules.push(rule),
        }
        Ok(())
    })?;
    st.request_reload();
    Ok(saved)
}

#[tauri::command]
pub fn delete_rule(st: St<'_>, id: String) -> R<()> {
    st.mutate(|d| {
        d.rules.retain(|r| r.id != id);
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

#[tauri::command]
pub fn set_rule_enabled(st: St<'_>, id: String, enabled: bool) -> R<()> {
    st.mutate(|d| {
        let r = d.rules.iter_mut().find(|r| r.id == id).ok_or("Правило не найдено")?;
        r.enabled = enabled;
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

/// New order of rules (first match wins).
#[tauri::command]
pub fn reorder_rules(st: St<'_>, ids: Vec<String>) -> R<()> {
    st.mutate(|d| {
        let mut rules = std::mem::take(&mut d.rules);
        let mut ordered = Vec::with_capacity(rules.len());
        for id in &ids {
            if let Some(i) = rules.iter().position(|r| &r.id == id) {
                ordered.push(rules.remove(i));
            }
        }
        ordered.extend(rules);
        d.rules = ordered;
        Ok(())
    })?;
    st.request_reload();
    Ok(())
}

/// Adds a rule from a built-in template or one of the user's own.
#[tauri::command]
pub fn add_preset(st: St<'_>, id: String) -> R<Rule> {
    let saved = st.mutate(|d| {
        let mut rule = match d.presets.iter().find(|p| p.id == id) {
            Some(own) => own.to_rule(new_id()),
            None => presets::instantiate(&presets::find(&id).ok_or("Шаблон не найден")?),
        };
        // the template may point at a server that is gone by now
        if let Route::Profile { id } = &rule.route {
            if d.profile(id).is_none() {
                rule.route = Route::Proxy;
            }
        }
        d.rules.push(rule.clone());
        Ok(rule)
    })?;
    st.request_reload();
    Ok(saved)
}

/// Creates or updates one of the user's own templates.
#[tauri::command]
pub fn save_preset(st: St<'_>, preset: CustomPreset) -> R<CustomPreset> {
    let mut p = preset;
    p.title = p.title.trim().to_string();
    p.description = p.description.trim().to_string();
    if p.title.is_empty() {
        return Err("Укажите название шаблона".into());
    }
    p.apps = clean(p.apps);
    p.domains = clean(p.domains);
    p.ips = clean(p.ips);
    p.ports = clean(p.ports);
    p.rule_sets = clean(p.rule_sets);
    p.network = p.network.map(|n| n.trim().to_lowercase()).filter(|n| !n.is_empty());
    validate_rule(&p.to_rule(String::new()))?;
    if let Route::Profile { id } = &p.route {
        if st.snapshot().profile(id).is_none() {
            return Err("Выбранный в шаблоне сервер не найден".into());
        }
    }
    if p.id.is_empty() {
        p.id = format!("my-{}", new_id());
    }
    let saved = st.mutate(|d| {
        match d.presets.iter_mut().find(|x| x.id == p.id) {
            Some(x) => {
                p.created_at = x.created_at;
                *x = p.clone();
            }
            None => {
                p.created_at = now_unix();
                d.presets.push(p.clone());
            }
        }
        Ok(p)
    })?;
    Ok(saved)
}

#[tauri::command]
pub fn delete_preset(st: St<'_>, id: String) -> R<()> {
    st.mutate(|d| {
        d.presets.retain(|p| p.id != id);
        Ok(())
    })
}
