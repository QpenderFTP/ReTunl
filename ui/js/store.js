// App state shared by all screens, plus helpers that read it.

import {
  h, invoke, toast, errorToast, errText, dialog, busy, seg, plural,
} from './lib.js';

export const store = {
  view: null, // get_state result
  catalog: { presets: [], rule_sets: [], dns: [] },
  traffic: null,
  conns: null,
  blocks: null, // blocked requests: session, total, top
  speedRun: null, // the speed test in progress
  coreProgress: null,
  startupWarning: null,
  icons: new Map(), // exe path -> data URL | null
  procIndex: null, // lower-case exe name -> path
  appNames: new Map(), // Android: package -> what the phone calls the app
  procIndexAt: 0,
  subUpdating: new Set(),
  openBundle: null, // set by transfer.js
  page: 'overview',
  navigate: () => {},
};

const subs = new Set();
export const on = (fn) => { subs.add(fn); return () => subs.delete(fn); };
export const emit = (what) => subs.forEach((fn) => {
  try { fn(what); } catch (e) { console.error(e); }
});

export async function refresh() {
  const v = await invoke('get_state');
  if (v.warning) store.startupWarning = v.warning;
  store.view = v;
  if (v.blocks) store.blocks = v.blocks;
  emit('data');
}

/** Run a command, then reload state; errors become a toast. */
export async function act(fn) {
  try {
    const r = await fn();
    await refresh();
    return r;
  } catch (e) {
    errorToast(e);
    await refresh().catch(() => {});
    return undefined;
  }
}

export const D = () => store.view.data;
export const S = () => store.view.data.settings;
export const ST = () => store.view.status;

export const profile = (id) => D().profiles.find((p) => p.id === id);
export const activeProfile = () => (S().active_profile ? profile(S().active_profile) : undefined);
export const isOn = (phase) => phase === 'running' || phase === 'starting';

// ---------- servers ----------

const PROTO = {
  vless: 'VLESS', vmess: 'VMess', trojan: 'Trojan', shadowsocks: 'Shadowsocks', hysteria: 'Hysteria',
  hysteria2: 'Hysteria2', tuic: 'TUIC', wireguard: 'WireGuard', socks: 'SOCKS', http: 'HTTP',
  anytls: 'AnyTLS', shadowtls: 'ShadowTLS', ssh: 'SSH', naive: 'Naive', tailscale: 'Tailscale',
  direct: 'Сетевой адаптер',
};
const TRANSPORT = {
  ws: 'WebSocket', grpc: 'gRPC', http: 'HTTP/2', httpupgrade: 'HTTPUpgrade', quic: 'QUIC', xhttp: 'XHTTP',
};

/** 'extended' — runs only on sing-box-lx, 'prefer' — runs better there, undefined — anywhere. */
export const coreNeed = (p) => (store.view.core.needs || {})[p.id];
export const hasLx = () => !!store.view.core.lx_path;
export const isWindows = () => !!store.view && store.view.platform === 'windows';
/** Cisco Secure Client's adapter: ReTunl logs in to Cisco with vpncli (Windows). */
export const isCisco = (p) => !!(p && p.cisco);
/** Windows: WireSock VPN Client runs this WireGuard server, sing-box only reaches it. */
export const viaWireSock = (p) => isWindows() && !!(p && p.wiresock && p.wiresock.enabled);
/** The server runs only on sing-box-lx, and ReTunl has none. */
export const needsLx = (p) => coreNeed(p) === 'extended' && !hasLx() && !viaWireSock(p) && !(isWindows() && p.xray && p.outbound.type === 'vless');

export function protoParts(p) {
  if (isCisco(p)) return { base: 'Cisco Secure Client', extra: '' };
  const o = p.outbound || {};
  const base = o.type === 'wireguard' && coreNeed(p) ? 'AmneziaWG' : PROTO[o.type] || o.type || '?';
  const extra = [];
  if (o.tls && o.tls.reality && o.tls.reality.enabled) extra.push('Reality');
  if (o.transport && o.transport.type) extra.push(TRANSPORT[o.transport.type] || o.transport.type);
  if (o.type === 'shadowsocks' && o.method) extra.push(o.method);
  if (o.server_ports && o.server_ports.length) extra.push('смена портов');
  return { base, extra: extra.join(' ') };
}

const hostPort = (host, port) => (host && host.includes(':') ? `[${host}]` : host || '') + (port ? ':' + port : '');

export function addressOf(p) {
  if (isCisco(p)) return p.cisco.host;
  const o = p.outbound || {};
  if (o.type === 'direct') return o.bind_interface || '';
  if (o.type === 'wireguard') {
    const peer = o.peers && o.peers[0];
    return peer ? hostPort(peer.address, peer.port) : '';
  }
  const port = o.server_port || (o.server_ports && o.server_ports[0]);
  return hostPort(o.server, port);
}

/** The outbound tag sing-box shows is the server name (made unique with " #2"). */
export function profileByTag(tag) {
  const ps = D().profiles;
  return ps.find((p) => p.name === tag) || ps.find((p) => tag.startsWith(p.name + ' #'));
}

export function profileOptions() {
  const d = D();
  const out = [];
  const opt = (p) => h('option', { value: p.id }, p.name);
  const manual = d.profiles.filter((p) => !p.subscription);
  if (manual.length) out.push(d.subscriptions.length ? h('optgroup', { label: 'Добавлены вручную' }, manual.map(opt)) : manual.map(opt));
  for (const sub of d.subscriptions) {
    const ps = d.profiles.filter((p) => p.subscription === sub.id);
    if (ps.length) out.push(h('optgroup', { label: sub.name }, ps.map(opt)));
  }
  return out;
}

// ---------- routes ----------

/** Which road a route takes: 'proxy' | 'profile:<id>' | 'direct' | 'block'. */
export function routeKey(route) {
  const ap = activeProfile();
  if (!route || route.kind === 'proxy') return 'proxy';
  if (route.kind === 'profile') return ap && route.id === ap.id ? 'proxy' : 'profile:' + route.id;
  return route.kind;
}

export function routeView(route) {
  switch (route && route.kind) {
    case 'direct': return { cls: 'direct', label: 'Напрямую, мимо VPN', short: 'Напрямую' };
    case 'block': return { cls: 'block', label: 'Блокировать', short: 'Блок' };
    case 'profile': {
      const p = profile(route.id);
      return { cls: 'tunnel', label: p ? `Через сервер «${p.name}»` : 'Через удалённый сервер', short: p ? p.name : 'нет сервера' };
    }
    default: {
      const ap = activeProfile();
      return { cls: 'tunnel', label: ap ? `Через VPN (сейчас «${ap.name}»)` : 'Через VPN', short: 'VPN' };
    }
  }
}

export function routeChip(route) {
  const v = routeView(route);
  return h('span.chip.r-' + v.cls, { title: v.label }, v.short);
}

/** Road a live connection took, in routeKey terms. */
export function connBranch(c) {
  if (!c.outbound || c.outbound === 'direct') return 'direct';
  const p = profileByTag(c.outbound);
  const ap = activeProfile();
  if (!p || (ap && p.id === ap.id)) return 'proxy';
  return 'profile:' + p.id;
}

/** Three-way route choice plus "another server". */
export function routePicker(route, onChange, { label = 'Маршрут' } = {}) {
  let cur = route || { kind: 'proxy' };
  const ps = D().profiles;
  const sel = h('select.select.route-server', { 'aria-label': 'Определённый сервер' },
    h('option', { value: '' }, ps.length ? 'Определённый сервер…' : 'Нет серверов'), profileOptions());
  sel.disabled = !ps.length;
  const segEl = seg([
    { value: 'proxy', label: 'Через VPN', title: 'Через выбранный сейчас сервер' },
    { value: 'direct', label: 'Напрямую', title: 'Мимо VPN, как без него' },
    { value: 'block', label: 'Блокировать', title: 'Сбрасывать соединения' },
  ], cur.kind === 'profile' ? '' : cur.kind, (v) => {
    cur = { kind: v };
    sel.value = '';
    wrap.classList.remove('on-server');
    onChange(cur);
  }, { label, cls: 'route-seg' });
  sel.value = cur.kind === 'profile' ? cur.id : '';
  sel.addEventListener('change', () => {
    if (!sel.value) return;
    cur = { kind: 'profile', id: sel.value };
    segEl.setValue('');
    wrap.classList.add('on-server');
    onChange(cur);
  });
  const wrap = h('div.route-picker' + (cur.kind === 'profile' ? '.on-server' : ''), segEl, sel);
  return wrap;
}

// ---------- the system ----------

export const isMac = () => !!store.view && store.view.platform === 'macos';
export const isAndroid = () => !!store.view && store.view.platform === 'android';
/** "Windows", "macOS" or "Android", for texts. */
export const osName = () => (isMac() ? 'macOS' : isAndroid() ? 'Android' : 'Windows');
/** How texts name the device ReTunl runs on. */
export const here = () => (isAndroid()
  ? { This: 'Этот телефон', this: 'этот телефон', onThis: 'на этом телефоне', toOther: 'на другое устройство', onOther: 'на другом устройстве' }
  : { This: 'Этот компьютер', this: 'этот компьютер', onThis: 'на этом компьютере', toOther: 'на другой компьютер', onOther: 'на другом компьютере' });
/** An Android app id: org.telegram.messenger */
export const isPackage = (a) => /^[a-z]\w*(\.[a-z]\w*)+$/i.test(a || '') && !/\.(exe|app)$/i.test(a);

// ---------- apps and icons ----------

export const baseName = (p) => (p || '').replace(/[\\/]+$/, '').split(/[\\/]/).pop();
export const isFolder = (a) => /[\\/]$/.test(a);
export function appLabel(a) {
  if (isAndroid() && isPackage(a)) return store.appNames.get(a) || a;
  return isFolder(a) ? 'папка ' + baseName(a) : baseName(a).replace(/\.(exe|app)$/i, '');
}

export async function ensureProcIndex(maxAge = 60) {
  if (store.procIndex && Date.now() / 1000 - store.procIndexAt < maxAge) return store.procIndex;
  try {
    const list = await invoke('list_processes');
    const idx = new Map();
    for (const p of list) if (p.path && !idx.has(p.name.toLowerCase())) idx.set(p.name.toLowerCase(), p.path);
    // Android: the name is the app's title, the path its package
    if (isAndroid()) for (const p of list) store.appNames.set(p.path, p.name);
    store.procIndex = idx;
    store.procIndexAt = Date.now() / 1000;
  } catch {
    store.procIndex = store.procIndex || new Map();
  }
  return store.procIndex;
}

/** Fetch icons for exe paths we have not seen yet. Emits 'icons' when new ones arrive. */
export async function loadIcons(paths) {
  // Windows: any .exe; macOS: anything inside an .app bundle
  const iconic = (p) => (isAndroid() ? isPackage(p) : isMac() ? /\.app(\/|$)/i.test(p) : /\.exe$/i.test(p));
  const need = [...new Set(paths.filter((p) => p && iconic(p) && !store.icons.has(p)))];
  if (!need.length) return false;
  need.forEach((p) => store.icons.set(p, null));
  try {
    const res = await invoke('get_icons', { paths: need });
    let got = false;
    for (const k in res) {
      store.icons.set(k, res[k]);
      if (res[k]) got = true;
    }
    if (got) emit('icons');
    return got;
  } catch {
    return false;
  }
}

/** Path to look an icon up by: the exe itself, or a running process with that name. */
export function iconPath(app) {
  if (!app || isFolder(app)) return null;
  if (/[\\/]/.test(app) || (isAndroid() && isPackage(app))) return app;
  return store.procIndex ? store.procIndex.get(app.toLowerCase()) || null : null;
}

export function appIcon(app) {
  const url = store.icons.get(iconPath(app));
  if (url) return h('img.app-ic', { src: url, alt: '' });
  if (app && isFolder(app)) return h('span.app-ic.ph.folder', { 'aria-hidden': 'true' });
  const letter = (appLabel(app || '?')[0] || '?').toUpperCase();
  return h('span.app-ic.ph', { 'aria-hidden': 'true' }, letter);
}

// ---------- connection ----------

export async function connect() {
  try {
    await invoke('connect');
  } catch (e) {
    // Cisco Secure Client wants a login: the «cisco-login» event opens it
    if (e !== 'need_admin' && !String(e).startsWith('cisco_login:')) errorToast(e);
  }
}

export async function disconnect() {
  try {
    await invoke('disconnect');
  } catch (e) {
    errorToast(e);
  }
}

export function toggleConnection() {
  return isOn(ST().phase) ? disconnect() : connect();
}

let adminOpen = false;
export function adminDialog() {
  if (adminOpen) return;
  adminOpen = true;
  const dl = dialog({
    title: 'Нужны права администратора',
    body: [
      h('p.dlg-text', 'Режим «Все программы» создаёт виртуальный сетевой адаптер, а Windows разрешает это только администратору.'),
      h('p.dlg-text.muted', 'ReTunl перезапустится с правами администратора и сразу подключится. Windows попросит подтверждение.'
        + (S().run_as_admin ? '' : ' Чтобы ReTunl всегда запускался с этими правами, включите это в настройках.')),
    ],
    actions: [
      h('button.btn', {
        onclick: async () => {
          dl.close();
          await act(() => invoke('update_settings', { patch: { mode: 'system_proxy' } }));
          connect();
        },
      }, 'Подключить через системный прокси'),
      h('button.btn.primary', {
        onclick: (e) => busy(e.currentTarget, () => invoke('relaunch_admin', { connect: true }).catch((er) => toast(
          'Перезапуск отменён', { kind: 'error', detail: errText(er) }))),
      }, 'Перезапустить от администратора'),
    ],
    onClose: () => { adminOpen = false; },
  });
}

// ---------- import ----------

export function reportImport(sum) {
  if (!sum) return;
  if (sum.bundle) {
    // an encrypted ReTunl export: transfer.js asks for the password
    if (store.openBundle) store.openBundle(sum.bundle);
    return;
  }
  const n = sum.added.length;
  const many = (k) => plural(k, 'сервер', 'сервера', 'серверов');
  const admin = sum.admin || [];
  if (admin.length) {
    // AmneziaVPN full-access keys go to «Мои серверы»
    if (store.adminImported) store.adminImported(admin);
    const failed = admin.filter((v) => v.error);
    toast(admin.length === 1 ? `«${admin[0].name}» добавлен в «Мои серверы»` : `В «Мои серверы» добавлено: ${many(admin.length)}`, {
      kind: failed.length === admin.length ? 'error' : 'info',
      detail: failed.length ? 'Не удалось зайти на сервер: ' + failed[0].error : null,
      timeout: failed.length ? 10000 : 5000,
      action: store.page === 'hosts' ? null : { label: 'Открыть', run: () => store.navigate('hosts') },
    });
    if (!n && !sum.subscriptions.length && !sum.errors.length && !sum.duplicates && !sum.warnings.length) return;
  }
  let text;
  if (sum.subscriptions.length) text = `Подписка добавлена: ${many(sum.names.length)}`;
  else if (n) text = `Добавлено: ${many(n)}`;
  else if (sum.duplicates) text = 'Эти серверы уже есть в списке';
  else text = 'Новых серверов нет';
  const notes = [];
  if (sum.duplicates && n) notes.push(`ещё ${sum.duplicates} уже были в списке`);
  notes.push(...sum.warnings);
  if (sum.errors.length) notes.push(`не удалось разобрать: ${sum.errors.length}`);
  const failed = sum.errors.length && !n && !sum.subscriptions.length;
  toast(text, {
    kind: failed ? 'error' : 'info',
    detail: notes.join('; '),
    timeout: sum.errors.length || sum.warnings.length ? 10000 : 5000,
    action: sum.errors.length ? { label: 'Подробнее', run: () => importErrors(sum.errors) } : null,
  });
}

function importErrors(errors) {
  dialog({
    title: 'Что не удалось добавить',
    body: h('ul.err-list', errors.map((e) => h('li',
      h('div.err-what.mono', e.what.length > 100 ? e.what.slice(0, 100) + '…' : e.what),
      h('div.err-why', e.error)))),
  });
}

export async function importText(text) {
  try {
    const sum = await invoke('import_text', { text });
    await refresh();
    reportImport(sum);
    return sum;
  } catch (e) {
    errorToast(e);
    return null;
  }
}

export async function importClipboard() {
  try {
    const sum = await invoke('import_clipboard');
    await refresh();
    reportImport(sum);
  } catch (e) {
    errorToast(e);
  }
}

// ---------- QR codes (Android) ----------

let scanning = false;
export const isScanning = () => scanning;
export const cancelScan = () => invoke('plugin:barcode-scanner|cancel').catch(() => { /* already closed */ });

/**
 * A server link or subscription address from a QR code. The camera is under the page:
 * the page turns transparent and shows only a frame, a hint and «Отмена».
 */
export async function scanQr() {
  if (scanning) return;
  // asks only the first time; after «Запретить» Android answers by itself
  const perm = await invoke('plugin:barcode-scanner|request_permissions').catch(() => null);
  if (!perm || perm.camera !== 'granted') {
    errorToast('Нет доступа к камере. Его можно включить в настройках Android: Приложения → ReTunl → Разрешения.');
    return;
  }
  const cover = h('div.scan', { role: 'dialog', 'aria-label': 'Сканирование QR-кода' },
    h('div.scan-frame'),
    h('p.scan-text', 'Наведите камеру на QR-код со ссылкой на сервер или адресом подписки'),
    h('button.btn.big.scan-cancel', { type: 'button', onclick: cancelScan }, 'Отмена'));
  document.body.append(cover);
  document.documentElement.classList.add('scanning');
  scanning = true;
  let text = '';
  try {
    const res = await invoke('plugin:barcode-scanner|scan', { windowed: true, formats: ['QR_CODE'] });
    text = ((res && res.content) || '').trim();
  } catch (e) {
    if (!/cancel/i.test(errText(e))) errorToast(e);
  } finally {
    scanning = false;
    cover.remove();
    document.documentElement.classList.remove('scanning');
  }
  if (text) await importText(text);
}

export async function importFile() {
  try {
    const sum = await invoke('import_file');
    if (!sum) return;
    await refresh();
    reportImport(sum);
  } catch (e) {
    errorToast(e);
  }
}

export const CORE_NAMES = { official: 'sing-box', extended: 'sing-box-lx' };

/** kind: 'official' (SagerNet) | 'extended' (sing-box-lx, AmneziaWG and XHTTP). */
export async function downloadCore(btn, kind = 'official') {
  await busy(btn, async () => {
    store.coreProgress = { done: 0, total: 0, kind };
    emit('core');
    try {
      await invoke('download_core', { kind });
      const c = store.view.core;
      toast(`Ядро ${CORE_NAMES[kind]} ${kind === 'extended' ? c.lx_expected : c.expected} установлено`);
    } catch (e) {
      errorToast(e);
    }
    store.coreProgress = null;
    await refresh();
  });
}

/** Paint a progress bar for downloads of one core kind. */
export function paintCoreBar(bar, kind) {
  if (!bar || !bar.isConnected) return;
  const p = store.coreProgress;
  const mine = p && (p.kind || 'official') === kind;
  bar.hidden = !mine;
  if (mine) {
    bar.classList.toggle('indeterminate', !p.total);
    bar.firstChild.style.transform = p.total ? 'scaleX(' + Math.min(1, p.done / p.total) + ')' : '';
  }
}

export async function copyText(text, what = 'Скопировано') {
  try {
    await invoke('copy_text', { text });
    toast(what);
  } catch (e) {
    errorToast(e);
  }
}
