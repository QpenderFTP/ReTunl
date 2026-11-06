// Обзор: the connect switch and the fork — where each kind of traffic goes.

import {
  h, s, add, icon, seg, invoke, fmtRate, fmtBytes, fmtClock, now, plural, banner,
} from './lib.js';
import {
  store, D, S, ST, act, isOn, activeProfile, profile, toggleConnection, profileOptions, routePicker,
  routeKey, connBranch, protoParts, addressOf, importClipboard, downloadCore, paintCoreBar, coreNeed, hasLx,
  isMac, osName,
} from './store.js';

const ROW = 74; // height of one branch row, px
const W = 236; // width of the road drawing
const JUNCTION = 64;

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
    add(root, [head(st), banners(st), controls(st), forkPanel(st), readouts(st)]);
    this.onTraffic();
  },
  onTraffic() {
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
    const how = st.mode === 'system_proxy' ? `Системный прокси ${osName()}` : 'Все программы через виртуальный адаптер';
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
    h('div.field',
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

function roadPath(y, mid, end) {
  const x0 = JUNCTION;
  return `M${x0} ${mid} C${x0 + 64} ${mid} ${W - 132} ${y} ${W - 62} ${y} L${end} ${y}`;
}

function forkPanel(st) {
  const branches = forkModel();
  const n = branches.length;
  const H = n * ROW;
  const mid = H / 2;
  const svg = s('svg', { class: 'fork-roads', viewBox: `0 0 ${W} ${H}`, width: W, height: H, 'aria-hidden': 'true' });
  const paths = branches.map((b, i) => roadPath(ROW / 2 + i * ROW, mid, b.cls === 'block' ? W - 26 : W - 6));
  branches.forEach((b, i) => svg.append(s('path', { d: paths[i], class: `road r-${b.cls}${b.final ? ' main' : ''}` })));
  branches.forEach((b, i) => {
    svg.append(s('path', { d: paths[i], class: 'road-mark' + (b.cls === 'block' ? ' still' : '') }));
    if (b.cls === 'block') {
      const y = ROW / 2 + i * ROW;
      svg.append(s('path', { d: `M${W - 12} ${y - 12} L${W - 12} ${y + 12}`, class: 'road-stop' }));
    }
  });
  const trunk = `M4 ${mid} L${JUNCTION + 10} ${mid}`;
  svg.append(s('path', { d: trunk, class: 'road trunk main' }));
  svg.append(s('path', { d: trunk, class: 'road-mark trunk-mark' }));
  svg.append(s('circle', { cx: JUNCTION + 10, cy: mid, r: 9, class: 'junction' }));

  const fork = h('div.fork' + (st.phase === 'running' ? '.live' : '') + (st.phase === 'starting' ? '.starting' : ''),
    h('div.fork-origin',
      h('span.origin-ic', icon('monitor')),
      h('div.origin-title', 'Этот компьютер'),
      h('div.origin-sub', S().mode === 'tun' ? 'все программы' : 'системный прокси')),
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
