//! Sing-box routes each selected profile to an authenticated Xray SOCKS port.
//! Xray dials the VLESS server on the underlying adapter, outside ReTunl's TUN.
use std::net::{IpAddr, TcpListener};
#[cfg(windows)]
use std::time::{Duration, Instant};

use retunl_core::{singbox::Built, AppData, Profile, Settings};
use serde_json::{json, Value};

use crate::{paths::Paths, sys};

#[cfg_attr(not(windows), allow(dead_code))]
pub struct Plan {
    config: Value,
    ports: Vec<TcpListener>,
    ready_port: u16,
}

pub fn for_connection(built: &mut Built, data: &AppData) -> Result<Option<Plan>, String> {
    let selected = built
        .tags
        .iter()
        .filter_map(|(tag, id)| Some((tag.as_str(), data.profile(id)?)));
    configure(&mut built.config, selected, &data.settings)
}

pub fn for_test(cfg: &mut Value, profiles: &[&Profile], settings: &Settings) -> Result<Option<Plan>, String> {
    configure(cfg, profiles.iter().map(|&p| (p.id.as_str(), p)), settings)
}

fn port(ports: &mut Vec<TcpListener>) -> Result<u16, String> {
    let l = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    ports.push(l);
    Ok(port)
}

#[cfg(windows)]
fn adapter(ip: IpAddr, tun: &str) -> Result<String, String> {
    if let Some(iface) = sys::best_interface(ip).filter(|name| !name.eq_ignore_ascii_case(tun)) {
        return Ok(iface);
    }
    // Independent tests can start while ReTunl already owns the best route.
    let adapters = ipconfig::get_adapters().map_err(|e| e.to_string())?;
    adapters
        .iter()
        .filter(|a| {
            a.oper_status() == ipconfig::OperStatus::IfOperStatusUp
                && !a.friendly_name().eq_ignore_ascii_case(tun)
                && a.gateways().iter().any(|g| g.is_ipv4() == ip.is_ipv4())
        })
        .min_by_key(|a| if ip.is_ipv4() { a.ipv4_metric() } else { a.ipv6_metric() })
        .map(|a| a.friendly_name().to_owned())
        .ok_or_else(|| "Xray не нашёл сетевой адаптер для соединения с сервером.".into())
}

fn array(value: &mut Value) -> Result<&mut Vec<Value>, String> {
    if value.is_null() {
        *value = json!([]);
    }
    value
        .as_array_mut()
        .ok_or_else(|| "Повреждена конфигурация маршрутизатора".into())
}

fn configure<'a>(
    router: &mut Value,
    profiles: impl IntoIterator<Item = (&'a str, &'a Profile)>,
    settings: &Settings,
) -> Result<Option<Plan>, String> {
    let mut ports = Vec::new();
    let mut outs = Vec::new();
    let mut ins = Vec::new();
    let mut routes = Vec::new();
    let mut domains = Vec::new();
    for (i, (tag, p)) in profiles.into_iter().filter(|(_, p)| p.uses_xray()).enumerate() {
        let mut vless = retunl_core::xray::vless(&p.outbound).map_err(|e| format!("Сервер «{}»: {e}", p.name))?;
        let address = p.outbound["server"].as_str().expect("validated VLESS address");
        let ip = address.parse::<IpAddr>().ok();
        if ip.is_none() {
            domains.push(address);
            vless["streamSettings"]["sockopt"]["domainStrategy"] =
                json!(if settings.ipv6 { "ForceIPv4v6" } else { "ForceIPv4" });
        }
        #[cfg(windows)]
        if settings.mode == retunl_core::InboundMode::Tun && !ip.is_some_and(|ip| ip.is_loopback()) {
            // Reading the routing table does not send a packet to this address.
            let route = ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
            vless["streamSettings"]["sockopt"]["interface"] = json!(adapter(route, &settings.tun.interface_name)?);
        }
        let listen = port(&mut ports)?;
        let name = format!("vless-{i}");
        let pass = uuid::Uuid::new_v4().simple().to_string();
        let socks = router["outbounds"]
            .as_array_mut()
            .and_then(|out| out.iter_mut().find(|o| o["tag"] == tag))
            .ok_or("Не найден маршрут для профиля Xray")?;
        *socks = json!({"type":"socks","tag":tag,"version":"5","server":"127.0.0.1","server_port":listen,
            "username":"retunl","password":pass});
        vless["tag"] = json!(name);
        outs.push(vless);
        ins.push(json!({"protocol":"socks","tag":name,"listen":"127.0.0.1","port":listen,
            "settings":{"auth":"password","users":[{"user":"retunl","pass":pass}],"udp":true,"ip":"127.0.0.1"}}));
        routes.push(json!({"type":"field","inboundTag":[name],"outboundTag":name}));
    }
    if ins.is_empty() {
        return Ok(None);
    }
    let mut config = json!({"log":{"loglevel":"warning"}});
    if !domains.is_empty() {
        // Resolve only the VPN gateways with the same direct resolver as
        // native VLESS. User DNS still follows the router's ordinary rules.
        let dns_port = port(&mut ports)?;
        let tag = "xray-bootstrap";
        array(&mut router["inbounds"])?
            .push(json!({"type":"direct","tag":tag,"listen":"127.0.0.1","listen_port":dns_port,"network":"tcp"}));
        array(&mut router["route"]["rules"])?.insert(0, json!({"inbound":tag,"action":"hijack-dns"}));
        let dns_rules = array(&mut router["dns"]["rules"])?;
        dns_rules.insert(0, json!({"inbound":tag,"action":"reject"}));
        dns_rules.insert(
            0,
            json!({"inbound":tag,"domain":domains,"action":"route","server":"dns-direct"}),
        );
        config["dns"] = json!({"servers":[format!("tcp+local://127.0.0.1:{dns_port}")], "disableFallback":true});
    }
    let ready_port = ins[0]["port"].as_u64().expect("allocated port") as u16;
    config["inbounds"] = json!(ins);
    config["outbounds"] = json!(outs);
    config["routing"] = json!({"rules":routes});
    Ok(Some(Plan {
        config,
        ports,
        ready_port,
    }))
}

pub struct Running(std::process::Child);

impl Running {
    pub fn exited(&mut self) -> Option<String> {
        match self.0.try_wait() {
            Ok(None) => None,
            Ok(Some(code)) => Some(format!("Xray-core завершился ({code}).")),
            Err(e) => Some(format!("Не удалось проверить Xray-core: {e}")),
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(windows)]
pub async fn start(plan: Option<Plan>, paths: &Paths, job: Option<&sys::Job>) -> Result<Option<Running>, String> {
    use std::process::Stdio;
    let Some(Plan {
        config,
        ports,
        ready_port,
    }) = plan
    else {
        return Ok(None);
    };
    let exe = paths.xray_path();
    if !exe.is_file() {
        return Err("Xray-core не установлен. Откройте меню VLESS-сервера и выберите Xray-core.".into());
    }
    drop(ports);
    let child = sys::quiet(&exe)
        .args(["run", "-format", "json", "-c", "stdin:"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Не удалось запустить Xray-core: {e}"))?;
    let mut run = Running(child);
    if let Some(job) = job {
        job.assign(&run.0);
    }
    // Keep credentials off disk and off the command line. Closing stdin signals EOF.
    serde_json::to_writer(run.0.stdin.take().ok_or("Нет входного канала Xray")?, &config)
        .map_err(|e| format!("Xray-core не принял конфигурацию: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(e) = run.exited() {
            return Err(e);
        }
        if tokio::net::TcpStream::connect(("127.0.0.1", ready_port)).await.is_ok() {
            return Ok(Some(run));
        }
        if Instant::now() >= deadline {
            return Err("Xray-core не открыл локальный порт.".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(not(windows))]
pub async fn start(plan: Option<Plan>, _: &Paths, _: Option<&sys::Job>) -> Result<Option<Running>, String> {
    if plan.is_some() {
        return Err("Xray-core доступен только в Windows.".into());
    }
    Ok(None)
}
