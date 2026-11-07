// Обзор: the connect switch and the fork — where each kind of traffic goes.

import {
  h, s, add, icon, seg, invoke, fmtRate, fmtBytes, fmtClock, fmtAgo, now, plural, banner, errorToast,
} from './lib.js';
import {
  store, D, S, ST, act, isOn, activeProfile, profile, toggleConnection, profileOptions, routePicker,
  routeKey, connBranch, protoParts, addressOf, importClipboard, downloadCore, paintCoreBar, coreNeed, hasLx,
  isMac, isAndroid, osName, here,
} from './store.js';

const ROW = 74; // height of one branch row, px
// the road drawing: its width and where the roads part; a phone gets a shorter one
const geometry = () => (matchMedia('(max-width: 720px)').matches ? { W: 124, J: 30 } : { W: 236, J: 64 });

let refs = {};

const PHASE = {
  stopped: { title: 'Отключено', sub: () => 'Трафик идёт напрямую, как без VPN.' },
  starting: { title: 'Подключаюсь…', sub: (st) => st.step || 'Запускаю ядро sing-box.' },
  running: { title: 'Подключено', sub: null },
  stopping: { title: 'Отключаюсь…', sub: () => 'Останавливаю ядро и возвращаю сетевые настройки.' },
  failed: { title: 'Не подключено', sub: () => 'Подключиться не удалось. Причина ниже.' },
};

export const overview = {
  id: 'overview',
  title: 'Обзор',
  icon: 'overview',
  statusRerender: true,
  render(root) {
    refs = {};
    const st = ST();
    add(root, [head(st), banners(st),
      h('div.ov-grid',
        h('div.ov-main', controls(st), forkPanel(st), readouts(st)),
        h('aside.ov-side', { 'aria-label': 'Проверки' }, speedCard(), blocksCard(st)))]);
    this.onTraffic();
  },
  onSpeed() {
    if (refs.speed && refs.speed.isConnected) refs.speed.replaceWith(speedCard());
  },
  onTraffic() {
    paintBlocks();
    const t = store.traffic;
    if (refs.up && t) {
      refs.up.textContent = fmtRate(t.up);
      refs.down.textContent = fmtRate(t.down);
      refs.sent.textContent = fmtBytes(t.up_total);
      refs.got.textContent = fmtBytes(t.down_total);
    }
    const counts = {};
    for (const c of store.conns || []) {
      const k = connBranch(c);
      counts[k] = (counts[k] || 0) + 1;
    }
    for (const el of document.querySelectorAll('[data-live]')) {
      const n = counts[el.dataset.live];
      if (!n) { el.textContent = ''; el.title = ''; continue; }
      const full = plural(n, 'соединение', 'соединения', 'соединений');
      const [, num, word] = full.match(/^(.*?)(\s\S+)$/) || [, full, ''];
      el.title = full;
      // The word is hidden on a narrow fork, the number stays.
      el.replaceChildren(num, h('span.live-word', word));
    }
  },
  onCore() {
    paintCoreBar(refs.coreBar, 'official');
    paintCoreBar(refs.lxBar, 'extended');
  },
};

function head(st) {
  const ph = PHASE[st.phase] || PHASE.stopped;
  let sub;
  if (st.phase === 'running') {
    const how = isAndroid() ? 'Все приложения через VPN Android'
      : st.mode === 'system_proxy' ? `Системный прокси ${osName()}` : 'Все программы через виртуальный адаптер';
    sub = st.profile ? `${how}, сервер «${st.profile}»` : how;
    sub += st.core === 'extended' ? ', ядро sing-box-lx.' : '.';
  } else {
    sub = ph.sub(st);
  }
  const label = { running: 'Отключить', starting: 'Отменить', stopping: 'Отключаюсь…' }[st.phase] || 'Подключить';
  return h('section.ov-head.ph-' + st.phase,
    h('div.ov-state',
      h('div.ov-title-line',
        h('span.state-dot', { 'aria-hidden': 'true' }),
        h('h1.state-title', ph.title),
        st.phase === 'running' && st.since ? h('span.state-time.uptime', { title: 'Время подключения' }, fmtClock(now() - st.since)) : null),
      h('p.state-sub', sub)),
    h('button.btn.big' + (isOn(st.phase) ? '' : '.primary'), {
      id: 'ov-toggle', disabled: st.phase === 'stopping', onclick: toggleConnection,
    }, icon('power'), label));
}

function banners(st) {
  const v = store.view;
  const out = [];
  if (store.startupWarning) {
    const b = banner('warn', 'Файл настроек был повреждён', store.startupWarning, [
      h('button.btn.small', { onclick: () => { store.startupWarning = null; b.remove(); } }, 'Понятно'),
    ]);
    out.push(b);
  }
  if (!v.core.path) {
    const bar = h('div.progress', { hidden: true }, h('div.progress-bar'));
    refs.coreBar = bar;
    queueMicrotask(() => paintCoreBar(bar, 'official'));
    const b = banner('warn', `Нужно ядро sing-box ${v.core.expected}`,
      'Соединения с серверами устанавливает sing-box. ReTunl скачает его с GitHub проекта SagerNet и проверит контрольную сумму.',
      [h('button.btn.small.primary', { onclick: (e) => downloadCore(e.currentTarget, 'official') }, 'Скачать ядро')]);
    b.append(bar);
    out.push(b);
  }
  const ap = activeProfile();
  const lxFailed = st.phase === 'failed' && st.error && st.error.includes('sing-box-lx');
  if (!hasLx() && (lxFailed || (ap && coreNeed(ap) === 'extended' && st.phase !== 'failed'))) {
    const bar = h('div.progress', { hidden: true }, h('div.progress-bar'));
    refs.lxBar = bar;
    const b = banner(lxFailed ? 'error' : 'warn', lxFailed ? 'Не удалось подключиться' : `Серверу «${ap.name}» нужно ядро sing-box-lx`,
      h('span', lxFailed ? st.error + ' ' : 'Официальный sing-box не умеет AmneziaWG 3.1 и XHTTP. ',
        `sing-box-lx ${v.core.lx_expected} — сторонняя сборка от Leadaxe. ReTunl скачает её с GitHub и проверит контрольную сумму.`),
      [h('button.btn.small.primary', { onclick: (e) => downloadCore(e.currentTarget, 'extended') }, 'Скачать sing-box-lx')]);
    b.append(bar);
    out.push(b);
    queueMicrotask(() => paintCoreBar(bar, 'extended'));
  }
  if (st.phase === 'failed' && st.error && !(lxFailed && !hasLx())) {
    out.push(banner('error', 'Не удалось подключиться', st.error, [
      h('button.btn.small', { onclick: () => store.navigate('logs') }, 'Открыть журнал'),
    ]));
  }
  if (st.phase === 'running' && st.warnings && st.warnings.length) {
    out.push(banner('warn', 'Подключено, но есть замечания', h('ul.plain', st.warnings.map((w) => h('li', w)))));
  }
  if (!D().profiles.length) {
    out.push(banner('info', 'Добавьте сервер',
      'Скопируйте ссылку на сервер (vless://, hy2://, trojan://…) или адрес подписки и вставьте её сюда. Подойдёт и файл WireGuard.',
      [
        h('button.btn.small.primary', { onclick: importClipboard }, 'Вставить из буфера'),
        h('button.btn.small', { onclick: () => store.navigate('servers') }, 'Другие способы'),
      ]));
  }
  return out;
}

function controls() {
  const d = D();
  const set = S();
  const sel = h('select.select#ov-server', {
    disabled: !d.profiles.length,
    onchange: () => act(() => invoke('set_active', { id: sel.value })),
  }, d.profiles.length ? profileOptions() : h('option', 'Серверов пока нет'));
  if (set.active_profile) sel.value = set.active_profile;
  const ap = activeProfile();
  let meta = null;
  if (ap) {
    const { base, extra } = protoParts(ap);
    const lat = store.view.latency[ap.id];
    meta = h('p.field-note.server-meta',
      h('span', base), extra && h('span', extra), h('span.mono-ish', addressOf(ap)),
      lat && lat.ms != null ? h('span', `${lat.ms} мс`) : null);
  }
  let modeNote = `Через прокси ${osName()}. Его учитывают браузеры и многие программы, но не игры.`;
  if (set.mode === 'tun') {
    if (isMac()) modeNote = 'Виртуальный адаптер ловит трафик всех программ. При подключении macOS спросит пароль администратора.';
    else if (store.view.elevated) modeNote = 'Виртуальный адаптер ловит трафик всех программ, включая игры.';
    else modeNote = 'Нужны права администратора: при подключении ReTunl предложит перезапуститься.';
  }
  return h('section.ov-controls',
    h('div.field',
      h('label.field-label', { htmlFor: 'ov-server' }, 'Сервер'),
      sel, meta),
    // Android: there is only the system VPN
    isAndroid() ? null : h('div.field',
      h('span.field-label', 'Что перехватывать'),
      seg([
        { value: 'tun', label: 'Все программы' },
        { value: 'system_proxy', label: 'Системный прокси' },
      ], set.mode, (v) => act(() => invoke('update_settings', { patch: { mode: v } })), { label: 'Что перехватывать' }),
      h('p.field-note', modeNote)));
}

// ---------- the fork ----------

function forkModel() {
  const d = D();
  const set = S();
  const ap = activeProfile();
  const map = new Map();
  const make = (key) => {
    if (key === 'proxy') return { cls: 'tunnel', title: 'Через VPN', sub: ap ? ap.name : 'сервер не выбран' };
    if (key === 'direct') return { cls: 'direct', title: 'Напрямую', sub: 'мимо VPN' };
    if (key === 'block') return { cls: 'block', title: 'Блокируется', sub: 'соединение сбрасывается' };
    const p = profile(key.slice(8));
    return { cls: 'tunnel', title: p ? `Через «${p.name}»` : 'Через удалённый сервер', sub: p ? protoParts(p).base : '' };
  };
  const get = (key) => {
    if (!map.has(key)) map.set(key, { key, rules: [], final: false, ...make(key) });
    return map.get(key);
  };
  get('proxy');
  for (const r of d.rules) if (r.enabled) get(routeKey(r.route)).rules.push(r.name);
  const direct = get('direct');
  if (set.bypass_lan) direct.rules.unshift('Локальная сеть');
  get(routeKey(set.final_route)).final = true;
  const order = (k) => (k === 'proxy' ? 0 : k.startsWith('profile:') ? 1 : k === 'direct' ? 2 : 3);
  return [...map.values()].sort((a, b) => order(a.key) - order(b.key));
}

function roadPath({ W, J }, y, mid, end) {
  const k = (W - J) / 172; // the curve was drawn for 172 px of road
  const x = (d) => Math.round(J + d * k);
  return `M${J} ${mid} C${x(64)} ${mid} ${x(40)} ${y} ${x(110)} ${y} L${end} ${y}`;
}

function forkPanel(st) {
  const branches = forkModel();
  const n = branches.length;
  const H = n * ROW;
  const mid = H / 2;
  const g = geometry();
  const { W } = g;
  const svg = s('svg', { class: 'fork-roads', viewBox: `0 0 ${W} ${H}`, width: W, height: H, 'aria-hidden': 'true' });
  const paths = branches.map((b, i) => roadPath(g, ROW / 2 + i * ROW, mid, b.cls === 'block' ? W - 26 : W - 6));
  branches.forEach((b, i) => svg.append(s('path', { d: paths[i], class: `road r-${b.cls}${b.final ? ' main' : ''}` })));
  branches.forEach((b, i) => {
    svg.append(s('path', { d: paths[i], class: 'road-mark' + (b.cls === 'block' ? ' still' : '') }));
    if (b.cls === 'block') {
      const y = ROW / 2 + i * ROW;
      svg.append(s('path', { d: `M${W - 12} ${y - 12} L${W - 12} ${y + 12}`, class: 'road-stop' }));
    }
  });
  const trunk = `M4 ${mid} L${g.J + 10} ${mid}`;
  svg.append(s('path', { d: trunk, class: 'road trunk main' }));
  svg.append(s('path', { d: trunk, class: 'road-mark trunk-mark' }));
  svg.append(s('circle', { cx: g.J + 10, cy: mid, r: 9, class: 'junction' }));

  const fork = h('div.fork' + (st.phase === 'running' ? '.live' : '') + (st.phase === 'starting' ? '.starting' : ''),
    h('div.fork-origin',
      h('span.origin-ic', icon(isAndroid() ? 'phone' : 'monitor')),
      h('div.origin-title', here().This),
      h('div.origin-sub', isAndroid() ? 'все приложения' : S().mode === 'tun' ? 'все программы' : 'системный прокси')),
    h('div.fork-roads-wrap', svg),
    h('div.fork-branches', branches.map(branchEl)));

  return h('section.panel.fork-panel',
    h('h2.visually-hidden', 'Куда идёт трафик'),
    fork,
    h('div.fork-final',
      h('span.fork-final-label', 'Всё, что не подошло под правила'),
      routePicker(S().final_route, (r) => act(() => invoke('update_settings', { patch: { final_route: r } })), { label: 'Маршрут для остального трафика' }),
      h('button.btn.ghost.small', { onclick: () => store.navigate('rules') }, 'Правила')));
}

function branchEl(b) {
  const names = b.rules;
  let rules = '';
  if (names.length) rules = names.length <= 4 ? names.join(', ') : `${names.slice(0, 4).join(', ')} и ещё ${names.length - 4}`;
  else if (!b.final) rules = 'Пока нет правил';
  return h('div.branch.r-' + b.cls + (b.final ? '.final' : ''), { style: { height: ROW + 'px' } },
    h('div.branch-head',
      h('span.branch-title', { title: b.sub ? `${b.title} — ${b.sub}` : b.title }, b.title),
      b.sub && h('span.branch-sub', b.sub),
      b.final && h('span.branch-final', { title: 'Сюда идёт трафик, для которого нет правила' }, 'и всё остальное'),
      h('span.branch-live', { data: { live: b.key } })),
    h('div.branch-rules' + (names.length ? '' : '.none'), { title: names.join(', ') }, rules || ' '));
}

function readouts(st) {
  if (st.phase !== 'running') return null;
  refs.up = h('span.ro-val', '—');
  refs.down = h('span.ro-val', '—');
  refs.sent = h('span.ro-val', '—');
  refs.got = h('span.ro-val', '—');
  const ro = (label, val, ic) => h('div.ro', h('span.ro-label', ic && icon(ic), label), val);
  return h('section.readouts', { 'aria-label': 'Трафик' },
    ro('Отправка', refs.up, 'up'),
    ro('Загрузка', refs.down, 'down'),
    ro('Отправлено за сеанс', refs.sent),
    ro('Получено за сеанс', refs.got));
}

// ---------- speed test ----------

const STEP_TEXT = { pick: 'Ищу тестовый сервер…', ping: 'Измеряю пинг…', download: 'Скачиваю…' };
const DOWNLOAD_SECS = 8;

function fmtMbps(v) {
  if (v == null) return '—';
  return v.toLocaleString('ru-RU', { maximumFractionDigits: v < 10 ? 1 : 0 });
}

/** A round road sign with the speed in it; the ring fills while measuring. */
function speedSign(route, value, fill, label) {
  const R = 44;
  const C = 2 * Math.PI * R;
  const text = fmtMbps(value);
  const ring = s('svg', { class: 'sign-ring', viewBox: '0 0 100 100', 'aria-hidden': 'true' },
    s('circle', { cx: 50, cy: 50, r: R, class: 'ring-bg' }),
    s('circle', {
      cx: 50, cy: 50, r: R, class: 'ring-fg', transform: 'rotate(-90 50 50)',
      'stroke-dasharray': C.toFixed(1), 'stroke-dashoffset': (C * (1 - fill)).toFixed(1),
    }));
  return h('div.sign.r-' + route + (value == null ? '.empty' : ''), { role: 'img', 'aria-label': label },
    ring,
    h('div.sign-face',
      h('span.sign-num' + (text.replace(/\s/g, '').length > 3 ? '.long' : ''), text),
      h('span.sign-unit', 'Мбит/с')));
}

function speedColumn(stage, part, run) {
  const ap = activeProfile();
  const vpn = stage === 'vpn';
  const route = vpn ? 'tunnel' : 'direct';
  const title = vpn ? 'Через VPN' : 'Без VPN';
  const live = run && run.stage === stage;
  let value = part ? part.mbps : null;
  let fill = value != null ? 1 : 0;
  let lines;
  if (live) {
    value = run.step === 'download' ? run.mbps : null;
    fill = run.step === 'download' ? Math.min(1, (Date.now() - run.t0) / (DOWNLOAD_SECS * 1000)) : 0;
    lines = [h('span.speed-step', STEP_TEXT[run.step] || 'Готовлюсь…'), run.server && h('span', run.server)];
  } else if (run && vpn) {
    lines = [h('span', ap ? 'Следующий замер' : 'Сервер не выбран')];
  } else if (vpn && !ap && !(part && part.error)) {
    lines = [h('span', 'Сервер не выбран')];
  } else if (part && part.error) {
    lines = [h('span.speed-error', part.error)];
  } else if (part) {
    lines = [part.ping_ms != null && h('span', `Пинг ${part.ping_ms} мс`), part.server && h('span', { title: 'Тестовый сервер' }, part.server)];
  } else {
    lines = [h('span', vpn ? 'Через выбранный сервер' : 'Напрямую, мимо туннеля')];
  }
  const sub = vpn && ap ? ap.name : null;
  return h('div.speed-col' + (live ? '.live' : ''),
    speedSign(route, value, fill, `${title}: ${value == null ? 'нет данных' : fmtMbps(value) + ' Мбит/с'}`),
    h('div.speed-name.r-' + route, title),
    sub && h('div.speed-server', { title: sub }, sub),
    h('div.speed-meta', lines));
}

function speedVerdict(r) {
  const d = r.direct && r.direct.mbps;
  const v = r.vpn && r.vpn.mbps;
  if (!d || !v) return null;
  const pct = Math.round((v / d) * 100);
  if (pct >= 105) return `Через VPN быстрее на ${pct - 100}%.`;
  if (pct >= 95) return 'Через VPN скорость почти такая же.';
  return `Через VPN — ${pct}% от скорости без VPN.`;
}

function speedCard() {
  const run = store.speedRun;
  const r = store.view.speed;
  const btn = h('button.btn.small', { disabled: !!run, onclick: runSpeedTest },
    icon('speed'), run ? 'Проверяю…' : r ? 'Проверить снова' : 'Проверить');
  let foot;
  if (run) foot = 'Около 25 секунд. На каждый замер скачивается до 200 МБ.';
  else if (r) foot = [speedVerdict(r), `Проверено ${fmtAgo(r.at)}.`].filter(Boolean).join(' ');
  else foot = 'Сравнит скорость загрузки и пинг без VPN и через выбранный сервер.';
  const directPart = run ? run.direct : r && r.direct;
  const vpnPart = run ? null : r && r.vpn;
  const el = h('section.panel.card.speed-card', { 'aria-busy': run ? 'true' : 'false' },
    h('div.card-head', h('h2.card-title', 'Скорость'), btn),
    h('div.speed-cols', speedColumn('direct', directPart, run), speedColumn('vpn', vpnPart, run)),
    h('p.card-foot', foot));
  refs.speed = el;
  return el;
}

let ticker = null;
async function runSpeedTest() {
  if (store.speedRun) return;
  store.speedRun = { stage: 'direct', step: 'pick', mbps: null, server: null, t0: Date.now(), direct: null };
  overview.onSpeed();
  // the ring keeps moving between progress events
  ticker = setInterval(() => overview.onSpeed(), 250);
  try {
    store.view.speed = await invoke('speed_test');
  } catch (e) {
    errorToast(e);
  } finally {
    clearInterval(ticker);
    store.speedRun = null;
    overview.onSpeed();
  }
}

/** A `speed-progress` event from the backend. */
export function speedProgress(p) {
  const run = store.speedRun;
  if (!run) return;
  if (p.stage === 'vpn' && run.stage === 'direct') {
    run.direct = { mbps: run.mbps, server: run.server, ping_ms: null };
  }
  if (p.step === 'download' && (run.step !== 'download' || run.stage !== p.stage)) run.t0 = Date.now();
  Object.assign(run, { stage: p.stage, step: p.step, mbps: p.mbps, server: p.server });
}

// ---------- blocked ----------

function blockSign() {
  return s('svg', { class: 'no-entry', viewBox: '0 0 24 24', 'aria-hidden': 'true' },
    s('circle', { cx: 12, cy: 12, r: 11 }),
    s('rect', { x: 5, y: 10, width: 14, height: 4, rx: 1 }));
}

const hasBlockRule = () => S().final_route.kind === 'block' || D().rules.some((r) => r.enabled && r.route.kind === 'block');

function blocksCard(st) {
  const running = st.phase === 'running';
  const b = store.blocks || { session: 0, total: 0, top: [], counting: false };
  refs.blkSession = h('span.blk-val', b.session.toLocaleString('ru-RU'));
  refs.blkTotal = h('span.blk-val', b.total.toLocaleString('ru-RU'));
  refs.blkTop = h('div.blk-top');
  const nums = h('div.blk-nums',
    h('div.blk-num', refs.blkSession, h('span.blk-label', running ? 'за этот сеанс' : 'за последний сеанс')),
    h('div.blk-num', refs.blkTotal, h('span.blk-label', 'за всё время')));
  let foot = null;
  if (!hasBlockRule()) {
    foot = h('div.blk-off',
      h('p.card-foot', 'Реклама и трекеры сейчас не блокируются.'),
      h('button.btn.small', { onclick: addAdsRule }, 'Блокировать рекламу'));
  } else if (!running) {
    foot = h('p.card-foot', 'Считаются запросы, закрытые правилами «Блокировать», пока ReTunl подключён.');
  }
  const el = h('section.panel.card.blocks-card',
    h('div.card-head', h('h2.card-title', blockSign(), 'Заблокировано')),
    nums, refs.blkTop, foot);
  queueMicrotask(paintBlocks);
  return el;
}

function paintBlocks() {
  const b = store.blocks;
  if (!b || !refs.blkSession || !refs.blkSession.isConnected) return;
  refs.blkSession.textContent = b.session.toLocaleString('ru-RU');
  refs.blkTotal.textContent = b.total.toLocaleString('ru-RU');
  const top = (b.top || []).filter(([, n]) => n > 0);
  if (!top.length) { refs.blkTop.replaceChildren(); return; }
  const max = top[0][1];
  refs.blkTop.replaceChildren(
    h('div.blk-top-title', 'Чаще всего'),
    h('ol.blk-list', top.map(([host, n]) => h('li.blk-row', { style: { '--w': `${Math.max(4, (n / max) * 100)}%` } },
      h('span.blk-host', { title: host }, host),
      h('span.blk-count', n.toLocaleString('ru-RU'))))));
}

async function addAdsRule(e) {
  e.currentTarget.disabled = true;
  // an «Реклама и трекеры» rule that was switched off is switched back on
  const old = D().rules.find((r) => r.preset === 'ads');
  await act(() => (old ? invoke('set_rule_enabled', { id: old.id, enabled: true }) : invoke('add_preset', { id: 'ads' })));
}
