// Fake backend for previewing the UI in a plain browser. Does nothing inside the app.
(function () {
  if (window.__TAURI__) return;

  const now = () => Math.floor(Date.now() / 1000);
  const id = () => Math.random().toString(16).slice(2, 14);
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const listeners = {};
  const emit = (name, payload) => (listeners[name] || []).forEach((fn) => fn({ payload }));

  const data = {
    version: 1,
    profiles: [
      { id: 'p1', name: 'Нидерланды Reality', subscription: 's1', link: 'vless://uuid@nl1.example.net:443?security=reality#NL',
        outbound: { type: 'vless', server: 'nl1.example.net', server_port: 443, uuid: '9f1c…', flow: 'xtls-rprx-vision',
          tls: { enabled: true, server_name: 'www.microsoft.com', utls: { enabled: true, fingerprint: 'chrome' }, reality: { enabled: true, public_key: 'Pk…', short_id: 'ab' } } } },
      { id: 'p2', name: 'Финляндия Hysteria2', subscription: 's1', link: 'hy2://pass@fi.example.net:443#FI',
        outbound: { type: 'hysteria2', server: 'fi.example.net', server_port: 443, password: 'x', tls: { enabled: true, server_name: 'fi.example.net', alpn: ['h3'] } } },
      { id: 'p3', name: 'Германия WebSocket', subscription: 's1', link: 'vmess://…',
        outbound: { type: 'vmess', server: 'de.example.net', server_port: 443, uuid: '…', transport: { type: 'ws', path: '/ws' }, tls: { enabled: true } } },
      { id: 'p4', name: 'Домашний WireGuard', outbound: { type: 'wireguard', address: ['10.8.0.2/32'], private_key: '…', peers: [{ address: '203.0.113.7', port: 51820, public_key: '…', allowed_ips: ['0.0.0.0/0'] }] } },
      { id: 'p5', name: 'AmneziaVPN', outbound: { type: 'direct', bind_interface: 'AmneziaVPN' } },
      { id: 'p6', name: 'Амстердам AmneziaWG 3.1', outbound: { type: 'wireguard', address: ['10.9.0.2/32'], private_key: '…', jc: 4, jmin: 10, jmax: 50, s1: 12, s2: 34, h1: '100000-100500', i1: '<b 0xc6000000>', peers: [{ address: '198.51.100.24', port: 34567, public_key: '…', allowed_ips: ['0.0.0.0/0'] }] } },
      { id: 'p7', name: 'Швеция XHTTP', subscription: 's1', link: 'vless://…?type=xhttp',
        outbound: { type: 'vless', server: 'se.example.net', server_port: 443, uuid: '…', transport: { type: 'xhttp', path: '/x', mode: 'auto' }, tls: { enabled: true, server_name: 'se.example.net' } } },
    ],
    subscriptions: [
      { id: 's1', name: 'Мой провайдер', url: 'https://sub.example.net/u/abc', updated_at: now() - 7300,
        info: { upload: 1.3e9, download: 23.7e9, total: 100e9, expire: now() + 41 * 86400 }, last_error: null },
    ],
    rules: [
      { id: 'r1', name: 'YouTube', enabled: true, match_all: false, apps: [], domains: [], ips: [], ports: [], rule_sets: ['geosite-youtube'], route: { kind: 'proxy' }, preset: 'youtube' },
      { id: 'r2', name: 'Discord', enabled: true, match_all: false, apps: ['Discord.exe', 'Update.exe'], domains: [], ips: [], ports: [], rule_sets: ['geosite-discord'], route: { kind: 'proxy' } },
      { id: 'r3', name: 'Telegram через Финляндию', enabled: true, match_all: false, apps: ['Telegram.exe'], domains: [], ips: ['91.108.4.0/22', '149.154.160.0/20'], ports: [], rule_sets: [], route: { kind: 'profile', id: 'p2' } },
      { id: 'r4', name: 'Российские сайты', enabled: true, match_all: false, apps: [], domains: ['ru', 'su', 'xn--p1ai'], ips: [], ports: [], rule_sets: ['geosite-category-ru', 'geoip-ru'], route: { kind: 'direct' }, preset: 'ru-direct' },
      { id: 'r5', name: 'Игры напрямую', enabled: true, match_all: false, apps: ['C:\\Program Files (x86)\\Steam\\'], domains: [], ips: [], ports: [], rule_sets: [], route: { kind: 'direct' } },
      { id: 'r6', name: 'Реклама и трекеры', enabled: true, match_all: false, apps: [], domains: [], ips: [], ports: [], rule_sets: ['geosite-category-ads-all'], route: { kind: 'block' }, preset: 'ads' },
      { id: 'r7', name: 'YouTube только в Chrome', enabled: false, match_all: true, apps: ['chrome.exe'], domains: ['youtube.com', 'googlevideo.com'], ips: [], ports: ['443'], rule_sets: [], route: { kind: 'proxy' } },
    ],
    presets: [
      { id: 'my-work', title: 'Рабочие программы напрямую', description: 'Zoom, Teams и корпоративный VPN мимо туннеля', match_all: false, apps: ['Zoom.exe', 'ms-teams.exe'], domains: ['corp.example.com'], ips: [], ports: [], rule_sets: [], route: { kind: 'direct' }, created_at: now() - 86400 },
    ],
    settings: {
      mode: 'tun', final_route: { kind: 'proxy' }, active_profile: 'p1', bypass_lan: true, ipv6: false, sniff: true,
      dns: { direct: '77.88.8.8', remote: 'https://1.1.1.1/dns-query', policy: 'auto' },
      tun: { interface_name: 'ReTunl', stack: 'mixed', mtu: 9000, strict_route: false },
      mixed_port: 2080, controller_port: 19190, direct_interface: null, log_level: 'info',
      test_url: 'https://www.gstatic.com/generate_204', connect_on_launch: false, close_to_tray: true, start_minimized: true, core: 'auto',
    },
  };
  if (/empty/.test(location.hash)) { data.profiles = []; data.subscriptions = []; data.rules = []; data.settings.active_profile = null; }

  let status = { phase: 'stopped', since: null, mode: null, profile: null, error: null, warnings: [], step: null };
  let latency = { p1: { ms: 84, error: null, at: now() }, p2: { ms: 61, error: null, at: now() }, p3: { ms: null, error: 'нет ответа', at: now() } };
  let core = /nocore/.test(location.hash) ? null : 'C:\\Users\\me\\AppData\\Local\\ReTunl\\core\\sing-box.exe';
  let lxCore = /lx/.test(location.hash) ? 'C:\\Users\\me\\AppData\\Local\\ReTunl\\core\\lx\\sing-box.exe' : null;
  const AWG = ['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5'];
  const needs = () => {
    const out = {};
    for (const p of data.profiles) {
      const o = p.outbound;
      if (o.transport && o.transport.type === 'xhttp') out[p.id] = 'extended';
      else if (o.type === 'wireguard' && AWG.slice(3).some((k) => k in o)) out[p.id] = 'extended';
      else if (o.type === 'wireguard' && AWG.some((k) => k in o)) out[p.id] = 'prefer';
    }
    return out;
  };
  let autostart = { enabled: false, elevated: false };
  // #mac: the macOS build (its texts, no restart as admin)
  const MAC = /mac/.test(location.hash);
  // #android: the phone build (packages instead of programs, the core built in)
  const ANDROID = /android/.test(location.hash);
  if (ANDROID) { core = 'встроено'; lxCore = 'встроено'; }
  let logs = [];
  let seq = 0;
  let totals = { up: 0, down: 0 };
  // blocked requests; #noblocks = nothing blocked yet
  const AD_HOSTS = ['mc.yandex.ru', 'an.yandex.ru', 'googleads.g.doubleclick.net', 'www.google-analytics.com', 'ads.vk.com', 'top-fwz1.mail.ru', 'pagead2.googlesyndication.com'];
  const blocks = /noblocks/.test(location.hash) ? { session: 0, total: 0, top: [], counting: false } : { session: 214, total: 48213, top: [['mc.yandex.ru', 61], ['googleads.g.doubleclick.net', 44], ['top-fwz1.mail.ru', 30], ['www.google-analytics.com', 22], ['ads.vk.com', 9]], counting: false };
  const blockTop = new Map(blocks.top);
  let speed = /speed/.test(location.hash) ? { direct: { mbps: 187.4, ping_ms: 24, server: 'Selectel, Россия', error: null }, vpn: { mbps: 142.9, ping_ms: 61, server: 'Cloudflare', error: null }, profile: 'Нидерланды Reality', at: now() - 300 } : null;
  let conns = [];

  const log = (level, text, source = 'core') => {
    const d = new Date();
    logs.push({ seq: ++seq, time: d.toTimeString().slice(0, 8), level, source, text });
    if (logs.length > 4000) logs.shift();
  };
  log('info', 'ReTunl 0.2.0 запущен', 'app');

  const setStatus = (s) => { status = { ...status, ...s }; emit('status', clone(status)); };

  const PROCS = [
    ['chrome.exe', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'],
    ['Discord.exe', 'C:\\Users\\me\\AppData\\Local\\Discord\\app-1.0.9175\\Discord.exe'],
    ['Telegram.exe', 'C:\\Users\\me\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe'],
    ['steam.exe', 'C:\\Program Files (x86)\\Steam\\steam.exe'],
    ['svchost.exe', 'C:\\Windows\\System32\\svchost.exe'],
    ['Code.exe', 'C:\\Users\\me\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe'],
    ['firefox.exe', 'C:\\Program Files\\Mozilla Firefox\\firefox.exe'],
    ['explorer.exe', 'C:\\Windows\\explorer.exe'],
  ];
  const APPS = [
    ['Chrome', 'com.android.chrome', false], ['Discord', 'com.discord', false], ['Telegram', 'org.telegram.messenger', false],
    ['YouTube', 'com.google.android.youtube', false], ['Steam', 'com.valvesoftware.android.steam.community', false],
    ['Сбербанк Онлайн', 'ru.sberbankmobile', false], ['Firefox', 'org.mozilla.firefox', false],
    ['Сервисы Google Play', 'com.google.android.gms', true], ['Android System WebView', 'com.google.android.webview', true],
  ];
  if (ANDROID) {
    PROCS.splice(0, PROCS.length, ['chrome.exe', 'com.android.chrome'], ['Discord.exe', 'com.discord'], ['Telegram.exe', 'org.telegram.messenger'],
      ['steam.exe', 'com.valvesoftware.android.steam.community'], ['svchost.exe', 'com.google.android.gms'], ['Code.exe', 'org.mozilla.firefox'],
      ['firefox.exe', 'org.mozilla.firefox']);
    const pkg = { 'Discord.exe': 'com.discord', 'Update.exe': 'com.discord', 'Telegram.exe': 'org.telegram.messenger', 'chrome.exe': 'com.android.chrome' };
    for (const r of data.rules) r.apps = [...new Set(r.apps.map((a) => pkg[a] || 'com.valvesoftware.android.steam.community'))];
    for (const pr of data.presets) pr.apps = ['us.zoom.videomeetings'];
  }
  const HOSTS = [
    ['chrome.exe', 'www.youtube.com', 'YouTube', 'Нидерланды Reality'],
    ['chrome.exe', 'rr3---sn-4g5e6nsz.googlevideo.com', 'YouTube', 'Нидерланды Reality'],
    ['chrome.exe', 'ya.ru', 'Российские сайты', 'direct'],
    ['chrome.exe', 'online.sberbank.ru', 'Российские сайты', 'direct'],
    ['chrome.exe', 'github.com', 'Остальной трафик', 'Нидерланды Reality'],
    ['Discord.exe', 'gateway.discord.gg', 'Discord', 'Нидерланды Reality'],
    ['Discord.exe', 'cdn.discordapp.com', 'Discord', 'Нидерланды Reality'],
    ['Telegram.exe', '149.154.167.51', 'Telegram через Финляндию', 'Финляндия Hysteria2'],
    ['steam.exe', 'api.steampowered.com', 'Игры напрямую', 'direct'],
    ['svchost.exe', '192.168.1.1', 'Локальная сеть', 'direct'],
    ['Code.exe', 'marketplace.visualstudio.com', 'Остальной трафик', 'Нидерланды Reality'],
    ['firefox.exe', 'news.ycombinator.com', 'Остальной трафик', 'Нидерланды Reality'],
  ];
  const makeConn = (i) => {
    const [proc, host, rule, outbound] = HOSTS[i % HOSTS.length];
    const path = (PROCS.find((p) => p[0] === proc) || [proc, ''])[1];
    const isIp = /^[\d.]+$/.test(host);
    return {
      id: id(), process: ANDROID ? path : proc, path, host: isIp ? '' : host, ip: isIp ? host : '203.0.113.' + (i % 250), port: host.startsWith('192.') ? 53 : 443,
      network: i % 5 === 0 ? 'udp' : 'tcp', outbound, rule, up: Math.floor(Math.random() * 40000), down: Math.floor(Math.random() * 900000),
      start: new Date(Date.now() - Math.random() * 600000).toISOString(),
    };
  };

  const CATALOG = {
    presets: [
      { id: 'ru-blocked', title: 'Заблокированное в России — через VPN', description: 'Сайты и IP из реестра блокировок (списки runetfreedom). Удобно вместе с «Остальное — напрямую».', apps: [], domains: [], ips: [], rule_sets: ['geosite-ru-blocked', 'geoip-ru-blocked'], route: 'proxy' },
      { id: 'ru-direct', title: 'Российские сайты — напрямую', description: 'Домены .ru/.рф/.su, российские сервисы и IP-адреса России идут мимо VPN.', apps: [], domains: ['ru'], ips: [], rule_sets: ['geosite-category-ru'], route: 'direct' },
      { id: 'youtube', title: 'YouTube — через VPN', description: 'Сайт, приложение и видеосерверы YouTube.', apps: [], domains: [], ips: [], rule_sets: ['geosite-youtube'], route: 'proxy' },
      { id: 'discord', title: 'Discord — через VPN', description: 'Приложение Discord и его сайты, включая голосовые серверы.', apps: ['Discord.exe'], domains: [], ips: [], rule_sets: ['geosite-discord'], route: 'proxy' },
      { id: 'telegram', title: 'Telegram — через VPN', description: 'Приложение, сайты и дата-центры Telegram.', apps: ['Telegram.exe'], domains: [], ips: [], rule_sets: ['geosite-telegram'], route: 'proxy' },
      { id: 'ai', title: 'Нейросети — через VPN', description: 'ChatGPT, Claude, Gemini и другие сервисы, недоступные из России.', apps: [], domains: [], ips: [], rule_sets: ['geosite-category-ai-!cn'], route: 'proxy' },
      { id: 'torrents', title: 'Торренты — напрямую', description: 'qBittorrent, Transmission и другие клиенты не нагружают VPN.', apps: ['qbittorrent.exe'], domains: [], ips: [], rule_sets: [], route: 'direct' },
      { id: 'ads', title: 'Реклама и трекеры — блокировать', description: 'Рекламные сети и счётчики не загружаются.', apps: [], domains: [], ips: [], rule_sets: ['geosite-category-ads-all'], route: 'block' },
    ],
    rule_sets: [
      { tag: 'geosite-ru-blocked', label: 'Заблокированное в РФ — сайты', group: 'Россия' },
      { tag: 'geoip-ru-blocked', label: 'Заблокированное в РФ — IP-адреса', group: 'Россия' },
      { tag: 'geosite-category-ru', label: 'Российские сайты', group: 'Россия' },
      { tag: 'geoip-ru', label: 'IP-адреса России', group: 'Россия' },
      { tag: 'geosite-youtube', label: 'YouTube', group: 'Видео и музыка' },
      { tag: 'geosite-twitch', label: 'Twitch', group: 'Видео и музыка' },
      { tag: 'geosite-spotify', label: 'Spotify', group: 'Видео и музыка' },
      { tag: 'geosite-discord', label: 'Discord', group: 'Общение' },
      { tag: 'geosite-telegram', label: 'Telegram — сайты', group: 'Общение' },
      { tag: 'geosite-instagram', label: 'Instagram', group: 'Общение' },
      { tag: 'geosite-category-ai-!cn', label: 'Нейросети (ChatGPT, Claude, Gemini…)', group: 'Работа' },
      { tag: 'geosite-github', label: 'GitHub', group: 'Работа' },
      { tag: 'geosite-steam', label: 'Steam', group: 'Игры' },
      { tag: 'geosite-category-ads-all', label: 'Реклама и трекеры', group: 'Прочее' },
    ],
    dns: [
      { value: '77.88.8.8', label: 'Яндекс (77.88.8.8)' }, { value: '1.1.1.1', label: 'Cloudflare (1.1.1.1)' },
      { value: '8.8.8.8', label: 'Google (8.8.8.8)' }, { value: 'https://1.1.1.1/dns-query', label: 'Cloudflare DoH' },
      { value: 'https://dns.google/dns-query', label: 'Google DoH' }, { value: 'tls://1.1.1.1', label: 'Cloudflare DoT' },
      { value: 'local', label: 'Системный DNS' },
    ],
  };

  const merge = (t, p) => {
    for (const k in p) {
      if (t[k] && typeof t[k] === 'object' && !Array.isArray(t[k]) && p[k] && typeof p[k] === 'object' && !('kind' in p[k])) merge(t[k], p[k]);
      else t[k] = p[k];
    }
  };

  const parseLinks = (text) => {
    const out = [];
    for (const line of text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)) {
      const m = /^([a-z0-9]+):\/\/[^#]*?(?:@)?([^:@/?#]+)?(?::(\d+))?[^#]*(?:#(.*))?$/i.exec(line);
      if (!m) continue;
      const scheme = m[1].toLowerCase();
      const types = { vless: 'vless', vmess: 'vmess', trojan: 'trojan', ss: 'shadowsocks', hy2: 'hysteria2', hysteria2: 'hysteria2', tuic: 'tuic', wireguard: 'wireguard', socks: 'socks', anytls: 'anytls' };
      if (!types[scheme]) continue;
      out.push({ id: id(), name: decodeURIComponent(m[4] || m[2] || scheme), link: line, outbound: { type: types[scheme], server: m[2] || 'example.net', server_port: Number(m[3] || 443) } });
    }
    return out;
  };

  const summary = (o) => ({ added: [], names: [], duplicates: 0, errors: [], warnings: [], subscriptions: [], admin: [], ...o });

  // ---------- «Мои серверы» ----------
  const fakeQr = (seed) => {
    const size = 45;
    let x = seed;
    let bits = '';
    const finder = (a, b) => a === 0 || a === 6 || b === 0 || b === 6 || (a > 1 && a < 5 && b > 1 && b < 5);
    for (let i = 0; i < size * size; i++) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      const r = Math.floor(i / size);
      const c = i % size;
      const inF = (r < 7 && c < 7) || (r < 7 && c >= size - 7) || (r >= size - 7 && c < 7);
      if (inF) bits += finder(r < 7 ? r : r - (size - 7), c < 7 ? c : c - (size - 7)) ? '1' : '0';
      else if ((r < 8 && (c < 8 || c >= size - 8)) || (r >= size - 8 && c < 8)) bits += '0';
      else bits += (x >> 16) & 1 ? '1' : '0';
    }
    return { size, bits };
  };
  const qtDate = (d) => d.toString().slice(0, 24).replace(/ 0(\d) /, ' $1 ');
  const awgClient = (name, ip, hs, rx, tx, days) => ({ id: id() + 'AbC=', name, created: qtDate(new Date(Date.now() - days * 86400000)), ip, handshake: hs, rx, tx, primary: false });
  const fullScan = () => ({
    os: 'Ubuntu 24.04.1 LTS', arch: 'x86_64', docker: true, at: now(),
    protocols: [
      { container: 'amnezia-awg2', kind: 'awg', title: 'AmneziaWG', state: 'running', port: 41532, transport: 'udp', detail: null, problem: null,
        clients: [awgClient('Ноутбук', '10.8.1.2', now() - 45, 3.1e9, 48.2e9, 40), awgClient('Телефон Маши', '10.8.1.3', now() - 3 * 3600, 210e6, 2.4e9, 12), awgClient('Телевизор', '10.8.1.4', null, 0, 0, 2)] },
      { container: 'amnezia-xray', kind: 'xray', title: 'VLESS Reality', state: 'running', port: 443, transport: 'tcp', detail: 'маскировка под www.googletagmanager.com', problem: null,
        clients: [{ id: '5b1e2c4a-1111-4a5b-9c3d-0f1e2d3c4b5a', name: 'Основной ключ сервера', created: null, ip: null, handshake: null, rx: 0, tx: 0, primary: true },
          { id: '7c2d3e4f-2222-4b6c-8d4e-1a2b3c4d5e6f', name: 'Папа', created: 'Sat Oct 17 09:12:44 2026', ip: null, handshake: null, rx: 0, tx: 0, primary: false }] },
      { container: 'amnezia-openvpn', kind: 'other', title: 'OpenVPN', state: 'exited', port: 1194, transport: 'udp', detail: null, problem: null, clients: null },
    ],
  });
  let hosts = /nohosts/.test(location.hash) ? [] : [
    { id: 'h1', name: 'Амстердам', host: '198.51.100.24', port: 22, user: 'root', auth: 'password', host_key: 'SHA256:q3Jx…', added_at: now() - 86400 * 30, scan: null, error: null },
    { id: 'h2', name: 'Франкфурт', host: '203.0.113.80', port: 2222, user: 'admin', auth: 'key', host_key: 'SHA256:Lk2p…', added_at: now() - 86400 * 3, scan: null, error: null },
  ];
  const host = (hid) => {
    const x = hosts.find((v) => v.id === hid);
    if (!x) throw 'Сервер не найден';
    return x;
  };
  const proto = (x, c) => x.scan.protocols.find((p) => p.container === c);
  const confText = (ip) => `[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = ${ip}/32\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1376\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 86\nS2 = 112\nH1 = 1820587466\nH2 = 1129431853\nH3 = 2001398341\nH4 = 862190527\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nPresharedKey = 7wq0h5YUMV3qNzb9dGNikGUGQ9I6uKsNptTdOeD0uYM=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 198.51.100.24:41532\nPersistentKeepalive = 25\n`;
  const keyFor = (x, p, c, once) => (p.kind === 'xray'
    ? { name: c.name, kind: 'xray', text: `vless://${c.id}@${x.host}:${p.port}?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality&pbk=Q5n2m0Zr7r4xYk3o8b1sXfV9gH6cJ2dLwT0aEqPuMjA&fp=chrome&sni=www.googletagmanager.com&sid=3f9a1c7e5b2d4086#${encodeURIComponent(c.name)}`, file_name: null, qr: fakeQr(c.name.length * 7919), once: false }
    : { name: c.name, kind: p.kind, text: confText(c.ip), file_name: x.name + '-' + c.name + '.conf', qr: /длинн/i.test(c.name) ? null : fakeQr(c.name.length * 104729), once });
  const adminHandlers = {
    admin_servers: () => hosts,
    admin_add: async ({ form }) => {
      await wait(1100);
      if (form.password === 'bad') throw 'Сервер не принял пароль для root';
      const m = /^(?:([^@]+)@)?([^:]+)(?::(\d+))?$/.exec(form.host.trim());
      const x = { id: id(), name: form.name || m[2], host: m[2], port: form.port || 22, user: form.user || 'root', auth: form.key_path ? 'key' : 'password', host_key: 'SHA256:new…', added_at: now(),
        scan: { os: 'Debian GNU/Linux 12 (bookworm)', arch: 'x86_64', docker: false, at: now(), protocols: [] }, error: null };
      hosts.push(x);
      return x;
    },
    admin_scan: async ({ id: hid }) => {
      await wait(1300);
      const x = host(hid);
      if (x.id === 'h2' && !x.trusted) {
        x.error = 'Ключ SSH сервера изменился: был SHA256:Lk2pW8…, теперь SHA256:9fQv1R…. Если вы переустанавливали систему на сервере, доверьтесь новому ключу; если нет — кто-то может подменять сервер.';
        throw x.error;
      }
      x.error = null;
      if (!x.scan) x.scan = x.id === 'h1' ? fullScan() : { os: 'Debian GNU/Linux 12 (bookworm)', arch: 'aarch64', docker: true, at: now(), protocols: [] };
      x.scan.at = now();
      return x;
    },
    admin_trust_key: ({ id: hid }) => { const x = host(hid); x.trusted = true; x.error = null; },
    admin_rename: ({ id: hid, name }) => { host(hid).name = name; },
    admin_forget: ({ id: hid }) => { hosts = hosts.filter((x) => x.id !== hid); },
    admin_client_add: async ({ id: hid, container, name }) => {
      await wait(900);
      const x = host(hid);
      const p = proto(x, container);
      const used = p.clients.map((c) => Number((c.ip || '0.0.0.1').split('.')[3]));
      const c = p.kind === 'xray'
        ? { id: crypto.randomUUID(), name, created: qtDate(new Date()), ip: null, handshake: null, rx: 0, tx: 0, primary: false }
        : awgClient(name, '10.8.1.' + (Math.max(1, ...used) + 1), null, 0, 0, 0);
      p.clients.push(c);
      return { server: x, key: keyFor(x, p, c, p.kind !== 'xray') };
    },
    admin_client_remove: async ({ id: hid, container, client }) => {
      await wait(700);
      const x = host(hid);
      const p = proto(x, container);
      p.clients = p.clients.filter((c) => c.id !== client);
      return x;
    },
    admin_client_rename: async ({ id: hid, container, client, name }) => {
      await wait(600);
      const x = host(hid);
      proto(x, container).clients.find((c) => c.id === client).name = name;
      return x;
    },
    admin_client_key: async ({ id: hid, container, client }) => {
      await wait(600);
      const x = host(hid);
      const p = proto(x, container);
      return keyFor(x, p, p.clients.find((c) => c.id === client), false);
    },
    admin_install: async ({ id: hid, kind, port, site, client }) => {
      const x = host(hid);
      const step = async (s, state, detail, ms) => { emit('admin-progress', { server: hid, step: s, state, detail: detail || null }); if (ms) await wait(ms); };
      await step('connect', 'run', null, 500);
      await step('connect', 'done');
      await step('check', 'run', null, 700);
      if (port === 1) throw 'Порт 1/udp на сервере уже занят:\nUNCONN 0 0 0.0.0.0:1 0.0.0.0:*\nВыберите другой порт.';
      await step('check', 'done', x.scan.arch);
      if (x.scan.docker) await step('docker', 'skip');
      else {
        for (const l of ['Reading package lists...', 'Setting up containerd (1.7.24)...', 'Setting up docker.io (26.1.5)...']) await step('docker', 'run', l, 900);
        await step('docker', 'done');
        x.scan.docker = true;
      }
      for (const l of ['Step 1/6 : FROM amneziavpn/amneziawg-go:latest', 'Step 3/6 : RUN apk add --no-cache bash dumb-init iptables', 'Successfully built 3b7f1c2a9e44']) await step('build', 'run', l, 1000);
      if (/fail/.test(location.hash)) throw 'Не удалось собрать контейнер:\nerror pulling image configuration: toomanyrequests';
      await step('build', 'done');
      await step('start', 'run', null, 1200);
      await step('start', 'done');
      const title = { awg: 'AmneziaWG', xray: 'VLESS Reality', wireguard: 'WireGuard' }[kind];
      const container = { awg: 'amnezia-awg2', xray: 'amnezia-xray', wireguard: 'amnezia-wireguard' }[kind];
      const p = { container, kind, title, state: 'running', port, transport: kind === 'xray' ? 'tcp' : 'udp', detail: kind === 'xray' ? 'маскировка под ' + site : null, problem: null, clients: [] };
      if (kind === 'xray') p.clients.push({ id: crypto.randomUUID(), name: 'Основной ключ сервера', created: null, ip: null, handshake: null, rx: 0, tx: 0, primary: true });
      x.scan.protocols.push(p);
      let key = null;
      if (client) {
        await step('client', 'run', null, 700);
        const r = await adminHandlers.admin_client_add({ id: hid, container, name: client });
        key = r.key;
        await step('client', 'done');
      }
      return { server: x, key };
    },
    admin_remove_protocol: async ({ id: hid, container }) => {
      await wait(1200);
      const x = host(hid);
      x.scan.protocols = x.scan.protocols.filter((p) => p.container !== container);
      return x;
    },
    admin_start_protocol: async ({ id: hid, container }) => {
      await wait(1000);
      const x = host(hid);
      proto(x, container).state = 'running';
      return x;
    },
    admin_pick_key: () => 'C:\\Users\\me\\.ssh\\id_ed25519',
    admin_use_client: ({ text, name }) => {
      const p = { id: id(), name, outbound: /^vless:/.test(text) ? { type: 'vless', server: '198.51.100.24', server_port: 443 } : { type: 'wireguard', address: ['10.8.1.5/32'], peers: [{ address: '198.51.100.24', port: 41532 }] } };
      data.profiles.push(p);
      return p.id;
    },
    admin_save_conf: ({ name }) => 'C:\\Users\\me\\Documents\\' + name,
  };

  const handlers = {
    ...adminHandlers,
    get_state:() => ({ data, status, elevated: !/user/.test(location.hash), core: { path: core, expected: '1.14.4', lx_path: lxCore, lx_expected: '1.14.4-lx.32', needs: needs() }, latency, autostart, version: '0.2.0', data_dir: ANDROID ? '/data/user/0/app.retunl/files' : MAC ? '/Users/me/Library/Application Support/ReTunl' : 'C:\\Users\\me\\AppData\\Roaming\\ReTunl', portable: false, warning: null, platform: ANDROID ? 'android' : MAC ? 'macos' : 'windows', blocks: clone(blocks), speed }),
    get_catalog: () => CATALOG,
    import_text: ({ text }) => {
      if (text.trim().startsWith('retunl-bundle:')) return summary({ bundle: text.trim() });
      if (text.trim().startsWith('vpn://full')) {
        const x = { id: id(), name: 'Сервер из AmneziaVPN', host: '192.0.2.15', port: 22, user: 'root', auth: 'password', host_key: 'SHA256:amn…', added_at: now(), scan: fullScan(), error: null };
        hosts.push(x);
        return summary({ admin: [x] });
      }
      if (/^https?:\/\//.test(text.trim())) {
        const sid = id();
        data.subscriptions.push({ id: sid, name: new URL(text.trim()).host, url: text.trim(), updated_at: now(), info: null, last_error: null });
        const ps = [1, 2, 3].map((i) => ({ id: id(), name: `Сервер ${i}`, subscription: sid, outbound: { type: 'vless', server: `s${i}.example.org`, server_port: 443 } }));
        data.profiles.push(...ps);
        if (!data.settings.active_profile) data.settings.active_profile = ps[0].id;
        return summary({ names: ps.map((p) => p.name), subscriptions: [sid] });
      }
      const ps = parseLinks(text);
      if (!ps.length) throw 'Не нашёл ни одной ссылки на сервер. Поддерживаются vless://, vmess://, trojan://, ss://, hy2://, hysteria://, tuic://, wireguard://, socks://, anytls://, ссылки на подписку и файлы WireGuard.';
      data.profiles.push(...ps);
      if (!data.settings.active_profile) data.settings.active_profile = ps[0].id;
      return summary({ added: ps.map((p) => p.id), names: ps.map((p) => p.name), errors: text.includes('ssr://') ? [{ what: 'ssr://…', error: 'ShadowsocksR не поддерживается sing-box' }] : [] });
    },
    import_clipboard: () => handlers.import_text({ text: 'vless://u@pl.example.com:443?security=reality#Польша%20Reality\nhy2://p@se.example.com:8443#Швеция%20Hy2' }),
    import_file: () => null,
    add_subscription: ({ url }) => handlers.import_text({ text: url }),
    update_subscription: async ({ id: sid }) => { await wait(700); const s = data.subscriptions.find((x) => x.id === sid); s.updated_at = now(); return summary({ names: data.profiles.filter((p) => p.subscription === sid).map((p) => p.name), subscriptions: [sid] }); },
    update_all_subscriptions: async () => { await wait(900); data.subscriptions.forEach((s) => { s.updated_at = now(); }); return []; },
    rename_subscription: ({ id: sid, name }) => { data.subscriptions.find((s) => s.id === sid).name = name; },
    delete_subscription: ({ id: sid }) => { data.profiles = data.profiles.filter((p) => p.subscription !== sid); data.subscriptions = data.subscriptions.filter((s) => s.id !== sid); },
    set_active: ({ id: pid }) => { data.settings.active_profile = pid; },
    rename_profile: ({ id: pid, name }) => { data.profiles.find((p) => p.id === pid).name = name; },
    set_profile_json: ({ id: pid, json }) => { const v = JSON.parse(json); data.profiles.find((p) => p.id === pid).outbound = v; },
    delete_profiles: ({ ids }) => { data.profiles = data.profiles.filter((p) => !ids.includes(p.id)); let n = 0; data.rules.forEach((r) => { if (r.route.kind === 'profile' && ids.includes(r.route.id)) { r.route = { kind: 'proxy' }; n++; } }); if (ids.includes(data.settings.active_profile)) data.settings.active_profile = data.profiles[0] ? data.profiles[0].id : null; return n; },
    add_interface: ({ name }) => { const p = { id: id(), name, outbound: { type: 'direct', bind_interface: name } }; data.profiles.push(p); return p.id; },
    list_adapters: () => [
      { name: 'Ethernet', description: 'Realtek PCIe 2.5GbE', up: true, addresses: ['192.168.1.2', 'fe80::1'], tunnel: false },
      { name: 'AmneziaVPN', description: 'AmneziaWG Tunnel', up: true, addresses: ['10.8.1.3'], tunnel: true },
      { name: 'Беспроводная сеть', description: 'Intel Wi-Fi 6 AX201', up: false, addresses: ['169.254.96.62'], tunnel: false },
    ],
    test_latency: async ({ ids }) => {
      await wait(900);
      const res = {};
      for (const p of data.profiles) if (!ids || ids.includes(p.id)) res[p.id] = Math.random() < 0.15 ? { ms: null, error: 'нет ответа', at: now() } : { ms: 40 + Math.floor(Math.random() * 300), error: null, at: now() };
      Object.assign(latency, res);
      return res;
    },
    save_rule: ({ rule }) => {
      if (!rule.name) throw 'Укажите название правила';
      if (!rule.apps.length && !rule.domains.length && !rule.ips.length && !rule.rule_sets.length && !rule.ports.length && !rule.network) throw 'Добавьте хотя бы одно условие: программу, сайт, адрес, список или порт';
      if (!rule.id) { rule.id = id(); data.rules.push(rule); } else data.rules = data.rules.map((r) => (r.id === rule.id ? rule : r));
      return rule;
    },
    delete_rule: ({ id: rid }) => { data.rules = data.rules.filter((r) => r.id !== rid); },
    set_rule_enabled: ({ id: rid, enabled }) => { data.rules.find((r) => r.id === rid).enabled = enabled; },
    reorder_rules: ({ ids }) => { data.rules.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id)); },
    add_preset: ({ id: pid }) => { const own = data.presets.find((x) => x.id === pid); if (own) { const r = { ...structuredClone(own), id: id(), name: own.title, enabled: true, preset: own.id }; delete r.title; delete r.description; delete r.created_at; data.rules.push(r); return r; } const p = CATALOG.presets.find((x) => x.id === pid); const r = { id: id(), name: p.title.split(' — ')[0], enabled: true, match_all: false, apps: [...p.apps], domains: [...p.domains], ips: [...p.ips], ports: [], rule_sets: [...p.rule_sets], route: { kind: p.route }, preset: p.id }; data.rules.push(r); return r; },
    save_preset: ({ preset }) => {
      if (!preset.title) throw 'Укажите название шаблона';
      if (!preset.id) { preset.id = 'my-' + id(); preset.created_at = now(); data.presets.push(preset); } else data.presets = data.presets.map((x) => (x.id === preset.id ? preset : x));
      return preset;
    },
    delete_preset: ({ id: pid }) => { data.presets = data.presets.filter((x) => x.id !== pid); },
    geo_tags: async () => { await wait(300); return ['geoip-cn', 'geoip-ru', 'geoip-telegram', 'geosite-apple', 'geosite-category-ads-all', 'geosite-discord', 'geosite-github', 'geosite-google', 'geosite-netflix', 'geosite-openai', 'geosite-spotify', 'geosite-steam', 'geosite-twitch', 'geosite-youtube']; },
    export_bundle: async ({ request }) => {
      if (request.password.length < 6) throw 'Пароль должен быть не короче 6 символов';
      await wait(600);
      const bundle = {
        app: 'ReTunl', created_at: now(),
        subscriptions: data.subscriptions.filter((x) => request.subscription_ids.includes(x.id)).map((x) => ({ subscription: x, profiles: data.profiles.filter((q) => q.subscription === x.id) })),
        profiles: data.profiles.filter((q) => !q.subscription && request.profile_ids.includes(q.id)),
        rules: request.rules ? data.rules : [], presets: request.presets ? data.presets : [],
      };
      const text = 'retunl-bundle:1:' + btoa(unescape(encodeURIComponent(JSON.stringify({ pw: request.password, bundle }))));
      return request.to_file ? { path: 'C:\\Users\\me\\Documents\\ReTunl 2026-11-06.retunl', text: null } : { text, path: null };
    },
    open_bundle: async ({ text, password }) => {
      await wait(500);
      let v;
      try { v = JSON.parse(decodeURIComponent(escape(atob(text.slice('retunl-bundle:1:'.length))))); } catch { throw 'Файл экспорта повреждён'; }
      if (v.pw !== password) throw 'Неверный пароль или файл повреждён';
      return {
        bundle: v.bundle,
        existing: {
          subscriptions: v.bundle.subscriptions.filter((bs) => data.subscriptions.some((x) => x.url === bs.subscription.url)).map((bs) => bs.subscription.id),
          profiles: v.bundle.profiles.filter((q) => data.profiles.some((x) => JSON.stringify(x.outbound) === JSON.stringify(q.outbound))).map((q) => q.id),
        },
      };
    },
    import_bundle: ({ bundle }) => {
      const m = { subscriptions: 0, subscriptions_existing: 0, profiles: 0, profiles_existing: 0, rules: 0, rules_existing: 0, presets: 0, routes_reset: 0 };
      for (const bs of bundle.subscriptions) {
        const sid = id();
        data.subscriptions.push({ ...bs.subscription, id: sid });
        bs.profiles.forEach((q) => { data.profiles.push({ ...q, id: id(), subscription: sid }); m.profiles++; });
        m.subscriptions++;
      }
      bundle.profiles.forEach((q) => { data.profiles.push({ ...q, id: id() }); m.profiles++; });
      bundle.rules.forEach((r) => { if (data.rules.some((x) => x.name === r.name)) m.rules_existing++; else { data.rules.push({ ...r, id: id() }); m.rules++; } });
      bundle.presets.forEach((x) => { if (!data.presets.some((y) => y.id === x.id)) { data.presets.push(x); m.presets++; } });
      return m;
    },
    update_settings: ({ patch }) => { merge(data.settings, patch); return data.settings; },
    preview_config: () => JSON.stringify({ log: { level: data.settings.log_level }, dns: { servers: [{ type: 'udp', tag: 'dns-direct', server: data.settings.dns.direct }] }, inbounds: [{ type: 'tun', tag: 'tun-in', interface_name: 'ReTunl', address: ['172.19.0.1/30'], auto_route: true, strict_route: true, stack: 'mixed' }], route: { rules: data.rules.filter((r) => r.enabled).map((r) => ({ rule_set: r.rule_sets, action: 'route' })), final: 'Нидерланды Reality' }, experimental: { clash_api: { external_controller: '127.0.0.1:19190', secret: '••••' } } }, null, 2),
    connect: async () => {
      if (!core) throw 'Не найдено ядро sing-box. Скачайте его на вкладке «Обзор» или в настройках.';
      if (data.settings.mode === 'tun' && /user/.test(location.hash) && !MAC) { emit('need-admin', null); throw 'need_admin'; }
      if (!data.profiles.length && data.settings.final_route.kind === 'proxy') { setStatus({ phase: 'failed', error: 'Не выбран сервер. Добавьте сервер на вкладке «Серверы».' }); throw status.error; }
      setStatus({ phase: 'starting', step: 'Скачиваю списки правил', error: null });
      log('info', 'подключение: ' + (data.settings.mode === 'tun' ? 'виртуальный адаптер' : 'системный прокси'), 'app');
      await wait(700);
      setStatus({ step: 'Запускаю sing-box' });
      await wait(800);
      log('info', 'inbound/tun[tun-in]: started at ReTunl');
      log('info', 'sing-box started (0.41s)');
      log('warn', 'dns: lookup failed for telemetry.example: context deadline exceeded');
      const ap = data.profiles.find((p) => p.id === data.settings.active_profile);
      if (ap && needs()[ap.id] === 'extended' && !lxCore) {
        const why = ap.outbound.type === 'wireguard' ? 'AmneziaWG' : 'XHTTP';
        setStatus({ phase: 'failed', step: null, error: `Сервер «${ap.name}» (${why}) работает только через ядро sing-box-lx. Скачайте его в «Настройки» → «Ядро и списки».` });
        throw status.error;
      }
      conns = Array.from({ length: 18 }, (_, i) => makeConn(i));
      Object.assign(blocks, { session: 0, top: [], counting: true }); blockTop.clear();
      setStatus({ phase: 'running', since: now(), mode: data.settings.mode, profile: ap ? ap.name : null, step: null, warnings: [], core: ap && needs()[ap.id] && lxCore && data.settings.core !== 'official' ? 'extended' : 'official' });
    },
    disconnect: async () => {
      if (status.phase === 'stopped') return;
      setStatus({ phase: 'stopping' });
      await wait(500);
      log('info', 'sing-box stopped', 'app');
      setStatus({ phase: 'stopped', since: null, profile: null, mode: null });
    },
    poll: ({ connections }) => {
      if (status.phase !== 'running') return { status, traffic: null, connections: null };
      const up = Math.floor(20000 + Math.random() * 90000);
      const down = Math.floor(300000 + Math.random() * 2400000);
      totals.up += up; totals.down += down;
      if (Math.random() < 0.3) conns.shift();
      if (Math.random() < 0.5) conns.push(makeConn(Math.floor(Math.random() * 100)));
      conns.forEach((c) => { c.up += Math.floor(Math.random() * 3000); c.down += Math.floor(Math.random() * 60000); });
      if (Math.random() < 0.3) log(Math.random() < 0.1 ? 'error' : 'info', `[${Math.floor(Math.random() * 1e9)} ${Math.floor(Math.random() * 300)}ms] outbound/vless[Нидерланды Reality]: outbound connection to ${HOSTS[Math.floor(Math.random() * HOSTS.length)][1]}:443`);
      if (Math.random() < 0.6) {
        const host = AD_HOSTS[Math.floor(Math.random() * AD_HOSTS.length)];
        blockTop.set(host, (blockTop.get(host) || 0) + 1);
        blocks.session += 1; blocks.total += 1;
        blocks.top = [...blockTop].sort((a, b) => b[1] - a[1]).slice(0, 5);
      }
      return { status, traffic: { up, down, up_total: totals.up, down_total: totals.down, connections: conns.length }, connections: connections ? clone(conns) : null, blocks: clone(blocks) };
    },
    close_connection: ({ id: cid }) => { conns = conns.filter((c) => c.id !== cid); },
    close_all_connections: () => { conns = []; },
    get_logs: ({ after }) => ({ lines: logs.filter((l) => l.seq > after), last: seq }),
    clear_logs: () => { logs = []; },
    list_processes: () => (ANDROID ? APPS.map(([name, path, system]) => ({ name, path, system })) : PROCS.map(([name, path]) => ({ name, path })).concat([{ name: 'qbittorrent.exe', path: 'C:\\Program Files\\qBittorrent\\qbittorrent.exe' }])),
    get_icons: ({ paths }) => Object.fromEntries(paths.map((p) => [p, null])),
    pick_exe: () => 'C:\\Games\\Genshin Impact\\GenshinImpact.exe',
    pick_folder: () => 'C:\\Games\\',
    copy_text: ({ text }) => { window.__lastCopy = text; return navigator.clipboard && navigator.clipboard.writeText(text).catch(() => {}); },
    relaunch_admin: async () => { await wait(400); throw 'Операция отменена пользователем.'; },
    set_autostart: ({ enabled }) => { autostart = { enabled, elevated: enabled && !/user/.test(location.hash) }; return autostart; },
    download_core: async ({ kind = 'official' }) => {
      const total = kind === 'extended' ? 31_200_000 : 18_400_000;
      for (let d = 0; d <= total; d += 1_400_000) { emit('core-progress', { done: d, total, kind }); await wait(120); }
      if (kind === 'extended') {
        lxCore = 'C:\\Users\\me\\AppData\\Local\\ReTunl\\core\\lx\\sing-box.exe';
        return lxCore;
      }
      core = 'C:\\Users\\me\\AppData\\Local\\ReTunl\\core\\sing-box.exe';
      return core;
    },
    update_rule_sets: async () => { await wait(800); return 6; },
    speed_test: async () => {
      const ap = data.profiles.find((p) => p.id === data.settings.active_profile);
      const part = async (stage, top, server, ping) => {
        emit('speed-progress', { stage, step: 'pick', mbps: null, server: null }); await wait(900);
        emit('speed-progress', { stage, step: 'ping', mbps: null, server }); await wait(500);
        let v = 0;
        for (let i = 0; i < 16; i++) { v = top * (0.55 + 0.45 * Math.min(1, i / 5)) * (0.95 + Math.random() * 0.1); emit('speed-progress', { stage, step: 'download', mbps: Math.round(v * 10) / 10, server }); await wait(250); }
        return { mbps: Math.round(v * 10) / 10, ping_ms: ping, server, error: null };
      };
      const direct = await part('direct', 190, 'Selectel, Россия', 23);
      const vpn = ap ? await part('vpn', 120, 'Cloudflare', 58) : null;
      speed = { direct, vpn, profile: ap ? ap.name : null, at: now() };
      return speed;
    },
    open_data_dir: () => {},
    open_url: () => {},
    app_ready: () => {},
    quit_app: () => {},
  };

  window.__TAURI__ = {
    core: {
      invoke: async (cmd, args) => {
        await wait(60);
        const fn = handlers[cmd];
        if (!fn) throw `mock: нет команды ${cmd}`;
        return clone(await fn(clone(args || {})) ?? null);
      },
    },
    event: {
      listen: async (name, fn) => {
        (listeners[name] = listeners[name] || []).push(fn);
        return () => { listeners[name] = listeners[name].filter((f) => f !== fn); };
      },
    },
  };
  window.__RETUNL_MOCK__ = true;
})();
