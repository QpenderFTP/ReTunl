//! WireGuard and AmneziaWG server files as AmneziaVPN keeps them: the
//! `[Interface]` of the server, one `[Peer]` per client, and `wg show dump`.
//! New clients get the address after the highest one in use, which is what
//! AmneziaVPN assumes too, so both apps can add clients to the same server.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use curve25519_dalek::montgomery::MontgomeryPoint;
use rand_core::{OsRng, RngCore};

/// `[Interface]` fields a client must share with an AmneziaWG server, in the
/// order AmneziaVPN writes them.
const AWG_KEYS: &[&str] = &[
    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
    "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
    "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
];

pub const CLIENT_DNS: &str = "1.1.1.1, 1.0.0.1";
const CLIENT_MTU: u32 = 1376;
const KEEPALIVE: u32 = 25;

#[derive(Debug, Default, Clone)]
pub struct Conf {
    /// `[Interface]` fields as written; I1–I5 also come from `# I1 = …`,
    /// where AmneziaVPN keeps them because only clients send them.
    iface: Vec<(String, String)>,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub public_key: String,
    pub ip: Option<Ipv4Addr>,
}

impl Conf {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.iface.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
    }

    pub fn listen_port(&self) -> Option<u16> {
        self.get("ListenPort").and_then(|p| p.parse().ok())
    }

    /// The server's own address and the subnet length, from `Address = 10.8.1.0/24`.
    fn subnet(&self) -> Option<(Ipv4Addr, u8)> {
        self.get("Address")?.split(',').find_map(|a| {
            let (ip, len) = a.trim().split_once('/').unwrap_or((a.trim(), "24"));
            Some((ip.parse().ok()?, len.parse().ok().filter(|l| *l <= 30)?))
        })
    }
}

pub fn parse(text: &str) -> Conf {
    let mut conf = Conf::default();
    let mut section = "";
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            section = if line.eq_ignore_ascii_case("[Interface]") { "i" } else if line.eq_ignore_ascii_case("[Peer]") { "p" } else { "" };
            if section == "p" {
                conf.peers.push(Peer { public_key: String::new(), ip: None });
            }
            continue;
        }
        let commented = line.strip_prefix('#').map(str::trim);
        let Some((k, v)) = commented.unwrap_or(line).split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match section {
            "i" if commented.is_none() => conf.iface.push((k.to_string(), v.to_string())),
            "i" if is_decoy(k) => conf.iface.push((k.to_string(), v.to_string())),
            "p" if commented.is_none() => {
                let peer = conf.peers.last_mut().expect("a [Peer] line came first");
                if k.eq_ignore_ascii_case("PublicKey") {
                    peer.public_key = v.to_string();
                } else if k.eq_ignore_ascii_case("AllowedIPs") {
                    peer.ip = v.split(',').find_map(|a| a.trim().split('/').next()?.parse().ok());
                }
            }
            _ => {}
        }
    }
    conf.peers.retain(|p| !p.public_key.is_empty());
    conf
}

fn is_decoy(k: &str) -> bool {
    matches!(k.to_ascii_uppercase().as_str(), "I1" | "I2" | "I3" | "I4" | "I5")
}

/// The address for a new client: one past the highest in use (skipping
/// `.255` and `.0`), or the first free one if that runs out of the subnet.
pub fn next_ip(conf: &Conf) -> Result<Ipv4Addr, String> {
    let (server, len) = conf.subnet().ok_or("в настройках сервера нет адреса подсети (Address)")?;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    let net = u32::from(server) & mask;
    let last = net | !mask;
    let used: Vec<u32> = conf.peers.iter().filter_map(|p| p.ip).map(u32::from).chain([u32::from(server)]).collect();
    let fits = |n: u32| n > net && n < last && n & 0xff != 0 && n & 0xff != 255 && !used.contains(&n);
    let mut n = used.iter().copied().max().unwrap_or(net) + 1;
    while n & 0xff == 0 || n & 0xff == 255 {
        n += 1;
    }
    if fits(n) {
        return Ok(Ipv4Addr::from(n));
    }
    (net + 1..last).find(|n| fits(*n)).map(Ipv4Addr::from).ok_or_else(|| "в подсети сервера закончились свободные адреса".to_string())
}

/// The block AmneziaVPN appends for a client.
pub fn peer_block(public_key: &str, psk: Option<&str>, ip: Ipv4Addr) -> String {
    let psk = psk.map(|k| format!("PresharedKey = {k}\n")).unwrap_or_default();
    format!("\n[Peer]\nPublicKey = {public_key}\n{psk}AllowedIPs = {ip}/32\n\n")
}

/// The file without the client's `[Peer]` block, or `None` if it has none.
pub fn remove_peer(text: &str, public_key: &str) -> Option<String> {
    let mut blocks: Vec<Vec<&str>> = vec![Vec::new()];
    for line in text.lines() {
        if line.trim().starts_with('[') {
            blocks.push(Vec::new());
        }
        blocks.last_mut().expect("never empty").push(line);
    }
    let is_target = |b: &Vec<&str>| {
        b.first().is_some_and(|h| h.trim().eq_ignore_ascii_case("[Peer]"))
            && b.iter().any(|l| l.split_once('=').is_some_and(|(k, v)| k.trim().eq_ignore_ascii_case("PublicKey") && v.trim() == public_key))
    };
    let before = blocks.len();
    blocks.retain(|b| !is_target(b));
    if blocks.len() == before {
        return None;
    }
    let mut out = String::new();
    for b in blocks.iter().filter(|b| !b.is_empty()) {
        let body = b.join("\n");
        let body = body.trim_end();
        if body.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(body);
    }
    out.push('\n');
    Some(out)
}

pub struct ClientKeys<'a> {
    pub private_key: &'a str,
    pub ip: Ipv4Addr,
    pub server_public_key: &'a str,
    pub psk: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
}

/// A client `.conf` for this server; AmneziaWG fields are copied from it.
pub fn client_conf(server: &Conf, k: &ClientKeys) -> String {
    let mut s = format!(
        "[Interface]\nAddress = {}/32\nDNS = {CLIENT_DNS}\nPrivateKey = {}\nMTU = {CLIENT_MTU}\n",
        k.ip, k.private_key
    );
    for key in AWG_KEYS {
        if let Some(v) = server.get(key) {
            s.push_str(&format!("{key} = {v}\n"));
        }
    }
    let host = if k.host.contains(':') && !k.host.starts_with('[') { format!("[{}]", k.host) } else { k.host.to_string() };
    let psk = k.psk.map(|p| format!("PresharedKey = {p}\n")).unwrap_or_default();
    s.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\n{psk}AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {host}:{}\nPersistentKeepalive = {KEEPALIVE}\n",
        k.server_public_key, k.port
    ));
    s
}

pub struct PeerStats {
    pub handshake: Option<i64>,
    pub rx: u64,
    pub tx: u64,
}

/// `wg show <iface> dump`: the interface line, then one tab-separated line
/// per peer: key, psk, endpoint, allowed ips, handshake, rx, tx, keepalive.
pub fn parse_dump(text: &str) -> HashMap<String, PeerStats> {
    let mut out = HashMap::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 8 {
            continue;
        }
        let hs = f[4].parse::<i64>().ok().filter(|t| *t > 0);
        out.insert(f[0].to_string(), PeerStats { handshake: hs, rx: f[5].parse().unwrap_or(0), tx: f[6].parse().unwrap_or(0) });
    }
    out
}

fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// A new X25519 key pair as raw bytes (private, public).
pub fn raw_keypair() -> ([u8; 32], [u8; 32]) {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    let k = clamp(k);
    (k, MontgomeryPoint::mul_base_clamped(k).to_bytes())
}

pub fn public_of(private: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*private).to_bytes()
}

/// The server's public key, from the `PrivateKey` in its file.
pub fn server_public_key(conf: &Conf) -> Option<String> {
    let raw: [u8; 32] = B64.decode(conf.get("PrivateKey")?).ok()?.try_into().ok()?;
    Some(B64.encode(public_of(&raw)))
}

/// A WireGuard key pair in base64 (private, public).
pub fn keypair() -> (String, String) {
    let (p, q) = raw_keypair();
    (B64.encode(p), B64.encode(q))
}

/// A preshared key, or any other random 32-byte key in base64.
pub fn random_key() -> String {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    B64.encode(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "[Interface]\nPrivateKey = cGFzcw==\nAddress = 10.8.1.0/24\nListenPort = 39000\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 12\nH1 = 1\nHeaderProtectionKey = aHBr\n# I1 = <r 2><b 0x85>\n\n[Peer]\nPublicKey = AAA=\nPresharedKey = PSK=\nAllowedIPs = 10.8.1.1/32\n\n[Peer]\nPublicKey = BBB=\nPresharedKey = PSK=\nAllowedIPs = 10.8.1.7/32\n";

    #[test]
    fn reads_server_and_peers() {
        let c = parse(SERVER);
        assert_eq!(c.listen_port(), Some(39000));
        assert_eq!(c.get("jc"), Some("4"));
        assert_eq!(c.get("I1"), Some("<r 2><b 0x85>"));
        assert_eq!(c.peers.len(), 2);
        assert_eq!(c.peers[1], Peer { public_key: "BBB=".into(), ip: Some("10.8.1.7".parse().unwrap()) });
    }

    #[test]
    fn next_address() {
        assert_eq!(next_ip(&parse(SERVER)).unwrap().to_string(), "10.8.1.8");
        // an empty server gives the first one after its own address
        let empty = parse("[Interface]\nAddress = 10.8.1.0/24\n");
        assert_eq!(next_ip(&empty).unwrap().to_string(), "10.8.1.1");
        // past .254 it falls back to a gap
        let full = parse("[Interface]\nAddress = 10.8.1.0/24\n[Peer]\nPublicKey = X\nAllowedIPs = 10.8.1.254/32\n");
        assert_eq!(next_ip(&full).unwrap().to_string(), "10.8.1.1");
        assert!(next_ip(&parse("[Interface]\nListenPort = 1\n")).is_err());
    }

    #[test]
    fn removes_one_peer() {
        let out = remove_peer(SERVER, "AAA=").unwrap();
        let c = parse(&out);
        assert_eq!(c.peers.iter().map(|p| p.public_key.as_str()).collect::<Vec<_>>(), ["BBB="]);
        assert!(out.contains("# I1 = <r 2><b 0x85>"));
        assert!(out.starts_with("[Interface]\nPrivateKey"));
        assert!(remove_peer(SERVER, "nope").is_none());
    }

    #[test]
    fn client_file_matches_server() {
        let c = parse(SERVER);
        let k = ClientKeys { private_key: "CLIENT=", ip: "10.8.1.8".parse().unwrap(), server_public_key: "SRV=", psk: Some("PSK="), host: "203.0.113.7", port: 39000 };
        let conf = client_conf(&c, &k);
        assert!(conf.contains("Address = 10.8.1.8/32\n"));
        assert!(conf.contains("Jc = 4\nJmin = 10\nJmax = 50\nS1 = 12\nH1 = 1\nI1 = <r 2><b 0x85>\nHeaderProtectionKey = aHBr\n"));
        assert!(conf.contains("Endpoint = 203.0.113.7:39000\n"));
        let parsed = retunl_core::wgconf::parse(&conf, "test").unwrap();
        assert_eq!(parsed.profile.outbound["header_protection_key"], "aHBr");
        let v6 = client_conf(&c, &ClientKeys { host: "2001:db8::1", ..k });
        assert!(v6.contains("Endpoint = [2001:db8::1]:39000"));
    }

    #[test]
    fn dump_stats() {
        let d = "priv\tpub\t39000\toff\nAAA=\tpsk\t1.2.3.4:5\t10.8.1.1/32\t1730000000\t100\t200\t25\nBBB=\t(none)\t(none)\t10.8.1.7/32\t0\t0\t0\toff\n";
        let s = parse_dump(d);
        assert_eq!(s["AAA="].handshake, Some(1730000000));
        assert_eq!((s["AAA="].rx, s["AAA="].tx), (100, 200));
        assert_eq!(s["BBB="].handshake, None);
    }

    #[test]
    fn keys_are_x25519() {
        let (p, q) = keypair();
        let raw: [u8; 32] = B64.decode(&p).unwrap().try_into().unwrap();
        assert_eq!(B64.encode(public_of(&raw)), q);
        // RFC 7748 test vector
        let a: [u8; 32] = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assert_eq!(public_of(&clamp(a)), hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    }

    fn hex(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect();
        v.try_into().unwrap()
    }
}
