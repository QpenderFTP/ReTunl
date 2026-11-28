// Обзор: the connect switch and the fork — where each kind of traffic goes.

import {
  h, s, add, setText, icon, seg, invoke, fmtRate, fmtBytes, fmtClock, fmtAgo, now, plural, banner, errorToast, dialog,
} from './lib.js';
import {
  store, D, S, ST, act, isOn, activeProfile, profile, toggleConnection, profileOptions, routePicker,
  routeKey, connBranch, protoParts, addressOf, importClipboard, downloadCore, paintCoreBar, needsLx, hasLx,
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
    if (refs.speed?.isConnected && !document.hidden) paintSpeed();
  },
  onTraffic() {
    paintBlocks();
    const t = store.traffic;
    if (refs.up && t) {
      setText(refs.up, fmtRate(t.up));
      setText(refs.down, fmtRate(t.down));
      setText(refs.sent, fmtBytes(t.up_total));
      setText(refs.got, fmtBytes(t.down_total));
    }
    const counts = {};
    for (const [outbound, n] of Object.entries(t?.outbounds || {})) {
      const k = connBranch({ outbound });
      counts[k] = (counts[k] || 0) + n;
    }
    for (const el of document.querySelectorAll('[data-live]')) {
      const n = counts[el.dataset.live];
      if ((Number(el.dataset.count) || 0) === (n || 0)) continue;
      el.dataset.count = n || 0;
      if (!n) { el.textContent = ''; el.title = ''; continue; }
      const full = plural(n, 'соединение', 'соединения', 'соединений');
      const [, num, word] = full.match(/^(.*?)(\s\S+)$/) || [, full, ''];
      el.title = full;
      // The word is hidden on a narrow fork, the number stays.
      el.replaceChildren(num, h('span.live-word', word));
    }
  },
  leave() { refs = {}; },
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
  if (!hasLx() && (lxFailed || (ap && needsLx(ap) && st.phase !== 'failed'))) {
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
const mbpsFormat = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });

function fmtMbps(v) {
  if (v == null) return '—';
  return mbpsFormat.format(v < 10 ? v : Math.round(v));
}

/** A round road sign with the speed in it; the ring fills while measuring. */
function speedSign(route) {
  return h('div.sign.r-' + route, { role: 'img' },
    s('svg', { class: 'sign-ring', viewBox: '0 0 100 100', 'aria-hidden': 'true' },
      s('circle', { cx: 50, cy: 50, r: 44, class: 'ring-bg' }),
      s('circle', { cx: 50, cy: 50, r: 44, class: 'ring-fg', transform: 'rotate(-90 50 50)', pathLength: 100,
        'stroke-dasharray': 100, 'stroke-dashoffset': 100 })),
    h('div.sign-face', h('span.sign-num'), h('span.sign-unit', 'Мбит/с')));
}

/** "Hetzner, Хельсинки": a built-in test server as results name it. */
const targetName = (t) => (t.city ? `${t.name}, ${t.city}` : t.name);
const speedPrefs = () => S().speed || { targets: [], custom: [], profile: null };

/** The server the VPN measurement goes through: the one chosen for the test, else the selected one. */
function speedProfile() {
  const id = speedPrefs().profile;
  return (id && profile(id)) || activeProfile();
}

/** The saved choice of test servers in a few words. */
function targetSummary() {
  const sp = speedPrefs();
  const all = [...store.view.speed_targets.map((t) => ({ id: t.id, name: targetName(t) })), ...sp.custom];
  const picked = all.filter((t) => sp.targets.includes(t.id));
  if (!picked.length) return 'Авто';
  return picked.length === 1 ? picked[0].name : plural(picked.length, 'сервер', 'сервера', 'серверов');
}

function speedColumn(stage) {
  const vpn = stage === 'vpn';
  const route = vpn ? 'tunnel' : 'direct';
  const title = vpn ? 'Через VPN' : 'Без VPN';
  const sign = speedSign(route);
  const profileName = h('div.speed-server');
  const detail = h('span');
  const endpoint = h('span');
  const el = h('div.speed-col', sign, h('div.speed-name.r-' + route, title), profileName, h('div.speed-meta', detail, endpoint));
  const number = sign.querySelector('.sign-num');
  const ring = sign.querySelector('.ring-fg');
  function paint(part, run, name) {
    const live = run?.stage === stage && run.step !== 'done';
    const value = live ? run.mbps : part?.mbps;
    const fill = live ? run.fraction : value != null ? 1 : 0;
    const text = fmtMbps(value);
    setText(number, text);
    number.classList.toggle('long', text.replace(/\s/g, '').length > 3);
    sign.classList.toggle('empty', value == null);
    const offset = (100 * (1 - fill)).toFixed(1);
    if (ring.getAttribute('stroke-dashoffset') !== offset) ring.setAttribute('stroke-dashoffset', offset);
    const label = title + (value == null ? ', нет данных' : ', ' + text + ' Мбит/с');
    if (sign.getAttribute('aria-label') !== label) sign.setAttribute('aria-label', label);
    const sub = vpn && name || '';
    if (profileName.hidden !== !sub) profileName.hidden = !sub;
    setText(profileName, sub);
    if (profileName.title !== sub) profileName.title = sub;
    let message = '';
    if (live) message = STEP_TEXT[run.step] || 'Готовлюсь…';
    else if (part?.error) message = part.error;
    else if (part?.ping_ms != null) message = 'HTTP-пинг ' + part.ping_ms + ' мс';
    else if (!part) {
      if (!vpn) message = 'Напрямую, мимо туннеля';
      else if (!name) message = 'Сервер не выбран';
      else message = run ? 'Следующий замер' : 'Через выбранный сервер';
    }
    setText(detail, message);
    detail.classList.toggle('speed-error', !live && !!part?.error);
    detail.classList.toggle('speed-step', live);
    setText(endpoint, (live ? run.server : part?.server) || '');
  }
  return { el, paint };
}

function speedVerdict(r) {
  const d = r.direct && r.direct.mbps;
  const v = r.vpn && r.vpn.mbps;
  if (!d || !v || r.direct.server !== r.vpn.server) return null;
  const pct = Math.round((v / d) * 100);
  if (pct >= 105) return `Через VPN быстрее на ${pct - 100}%.`;
  if (pct >= 95) return 'Через VPN скорость почти такая же.';
  return `Через VPN — ${pct}% от скорости без VPN.`;
}

function speedCard() {
  const next = speedProfile();
  const btn = h('button.btn.small', { onclick: () => runSpeedTest() }, icon('speed'), h('span'));
  const opt = (label, value) => h('button.speed-opt', { type: 'button', onclick: speedDialog },
    h('span.speed-opt-label', label), h('span.speed-opt-value', { title: value }, value), icon('chevron'));
  const options = [opt('Тестовый сервер', targetSummary()), opt('Через сервер', next?.name || 'не выбран')];
  const direct = speedColumn('direct');
  const vpn = speedColumn('vpn');
  const foot = h('p.card-foot');
  refs.speed = h('section.panel.card.speed-card', h('div.card-head', h('h2.card-title', 'Скорость'), btn),
    h('div.speed-cols', direct.el, vpn.el), h('div.speed-setup', options), foot);
  refs.speedParts = { btn, caption: btn.lastChild, options, direct, vpn, foot, next: next?.name };
  paintSpeed();
  return refs.speed;
}

function paintSpeed() {
  const { btn, caption, options, direct, vpn, foot, next } = refs.speedParts;
  const run = store.speedRun;
  const r = store.view.speed;
  if (refs.speed.getAttribute('aria-busy') !== String(!!run)) {
    refs.speed.setAttribute('aria-busy', String(!!run));
    btn.disabled = !!run;
    for (const o of options) o.disabled = !!run;
  }
  setText(caption, run ? 'Проверяю…' : r ? 'Проверить снова' : 'Проверить');
  direct.paint(run ? run.direct : r?.direct, run, null);
  vpn.paint(run ? null : r?.vpn, run, run ? run.profile : r?.vpn ? r.profile : next);
  setText(foot, run ? 'Загрузка длится до 8 секунд и расходует до 200 МиБ за попытку.' :
    r ? [speedVerdict(r), 'Проверено ' + fmtAgo(r.at) + '.'].filter(Boolean).join(' ') :
    'Сравнит скорость загрузки и пинг без VPN и через сервер.');
}

const REGIONS = [['any', 'По всему миру'], ['ru', 'Россия'], ['eu', 'Европа'], ['us', 'США']];

/** Which test servers to use and through which server to measure. */
function speedDialog() {
  const sp = speedPrefs();
  const builtin = store.view.speed_targets;
  const custom = sp.custom.map((c) => ({ ...c }));
  const known = (id) => builtin.some((t) => t.id === id) || custom.some((c) => c.id === id);
  const picked = new Set(sp.targets.filter(known));
  let manual = picked.size > 0;

  const list = h('div.speed-pick');
  const note = h('p.field-note');
  const save = h('button.btn.primary', { onclick: submit }, 'Сохранить');
  const name = h('input.input', { placeholder: 'Название', 'aria-label': 'Название своего сервера', maxLength: 40 });
  const url = h('input.input.grow', { placeholder: 'https://example.com/100MB.bin', 'aria-label': 'Адрес большого файла', inputMode: 'url' });
  const through = h('select.select#speed-through',
    h('option', { value: '' }, activeProfile() ? `Выбранный сервер (сейчас «${activeProfile().name}»)` : 'Выбранный сервер'),
    profileOptions());
  through.value = sp.profile && profile(sp.profile) ? sp.profile : '';

  const option = (id, title, place, extra) => h('label.speed-target',
    h('input', {
      type: 'checkbox', checked: picked.has(id),
      onchange: (e) => { if (e.target.checked) picked.add(id); else picked.delete(id); paintNote(); },
    }),
    h('span.speed-target-name', title), place && h('span.speed-target-place', place), extra);

  function paintNote() {
    const auto = builtin.filter((t) => t.auto).map((t) => t.name);
    if (!manual) note.textContent = `ReTunl сравнит задержку и выберет один узел для обоих замеров: ${auto.join(', ')}.`;
    else if (!picked.size) note.textContent = 'Отметьте хотя бы один сервер.';
    else if (picked.size === 1) note.textContent = 'Оба замера, без VPN и через сервер, пойдут на этот сервер.';
    else note.textContent = 'ReTunl выберет по задержке один сервер для обоих замеров.';
    save.disabled = manual && !picked.size;
  }

  function paint() {
    const groups = REGIONS
      .map(([key, title]) => [title, builtin.filter((t) => t.region === key)])
      .filter(([, items]) => items.length)
      .map(([title, items]) => h('div.speed-group',
        h('div.speed-group-title', title),
        items.map((t) => option(t.id, t.name, [t.city, t.country].filter(Boolean).join(', ') || 'ближайший узел сети'))));
    if (custom.length) {
      groups.push(h('div.speed-group',
        h('div.speed-group-title', 'Свои серверы'),
        custom.map((c) => option(c.id, c.name, c.url.replace(/^https?:\/\//, ''),
          h('button.icon-btn.small', {
            type: 'button', 'aria-label': 'Удалить «' + c.name + '»', title: 'Удалить',
            onclick: (e) => { e.preventDefault(); custom.splice(custom.indexOf(c), 1); picked.delete(c.id); paint(); },
          }, icon('trash'))))));
    }
    list.hidden = !manual;
    list.replaceChildren(...groups);
    paintNote();
  }

  function addOwn() {
    const link = url.value.trim();
    let host;
    try {
      const u = new URL(link);
      if (!/^https?:$/.test(u.protocol)) throw new Error('scheme');
      host = u.host;
    } catch {
      errorToast('Адрес должен быть ссылкой на файл: https://example.com/100MB.bin');
      url.focus();
      return;
    }
    const own = { id: 'own-' + Math.random().toString(36).slice(2, 10), name: name.value.trim() || host, url: link };
    custom.push(own);
    picked.add(own.id);
    name.value = '';
    url.value = '';
    manual = true;
    mode.replaceWith(mode = modeSeg());
    paint();
  }
  url.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addOwn(); } });

  const modeSeg = () => seg([{ value: 'auto', label: 'Авто' }, { value: 'manual', label: 'Выбрать серверы' }],
    manual ? 'manual' : 'auto', (v) => { manual = v === 'manual'; paint(); }, { label: 'Тестовый сервер' });
  let mode = modeSeg();

  async function submit() {
    const patch = { speed: { targets: manual ? [...picked] : [], custom, profile: through.value || null } };
    const ok = await act(() => invoke('update_settings', { patch }));
    if (ok !== undefined) dl.close();
  }

  const dl = dialog({
    title: 'Проверка скорости',
    body: h('div.form-stack.speed-form',
      h('div.field',
        h('span.field-label', 'Тестовый сервер'),
        h('p.field-note', 'С него скачивается файл во время замера.'),
        mode, note, list),
      h('div.field.speed-own',
        h('span.field-label', 'Свой сервер'),
        h('div.speed-own-row', name, url, h('button.btn', { type: 'button', onclick: addOwn }, icon('plus'), 'Добавить')),
        h('p.field-note', 'Ссылка на большой файл, от 50 МБ: например, на вашем собственном сервере.')),
      h('div.field',
        h('label.field-label', { htmlFor: 'speed-through' }, 'Через какой сервер мерить'),
        through,
        h('p.field-note', 'Замер «Через VPN» идёт через него, даже когда подключён другой.'))),
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), save],
  });
  paint();
}

/** `through`: a server id for this run only (the server's own menu asks for it). */
async function runSpeedTest(through) {
  if (store.speedRun) return;
  const via = (through && profile(through)) || speedProfile();
  store.speedRun = { stage: 'direct', step: null, mbps: null, server: null, fraction: 0, direct: null, profile: via ? via.name : null };
  overview.onSpeed();
  try {
    store.view.speed = await invoke('speed_test', { profile: through || null });
  } catch (e) {
    errorToast(e);
  } finally {
    store.speedRun = null;
    overview.onSpeed();
  }
}

/** Open the overview and measure through the server `id`, whatever the speed settings say. */
export function speedTestThrough(id) {
  if (store.speedRun) return;
  store.navigate('overview');
  runSpeedTest(id);
}

/** A `speed-progress` event from the backend. */
export function speedProgress(p) {
  const run = store.speedRun;
  if (!run) return;
  if (p.stage === 'direct' && p.step === 'done') run.direct = p.part;
  // Smooth the live display across backend samples. Completed readings always
  // come straight from the byte counter, including after returning to this page.
  const now = performance.now();
  let mbps = p.mbps;
  if (p.step === 'download' && run.step === 'download' && run.stage === p.stage && run.server === p.server && run.mbps != null) {
    const weight = 1 - Math.exp(-(now - run.sampleAt) / 400);
    mbps = run.mbps + (p.mbps - run.mbps) * weight;
  }
  Object.assign(run, { stage: p.stage, step: p.step, mbps, sampleAt: now, server: p.server, fraction: p.fraction || 0 });
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
  if (refs.blockSession === b.session && refs.blockTotal === b.total) return;
  refs.blockSession = b.session;
  refs.blockTotal = b.total;
  setText(refs.blkSession, b.session.toLocaleString('ru-RU'));
  setText(refs.blkTotal, b.total.toLocaleString('ru-RU'));
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
