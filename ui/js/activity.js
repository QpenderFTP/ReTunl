// Активность: live connections, which rule caught them and where they went.

import {
  h, icon, invoke, seg, pageHead, popMenu, fmtBytes, fmtClock, toast, errorToast, plural,
} from './lib.js';
import {
  store, ST, connBranch, appIcon, loadIcons, connect, profileByTag,
} from './store.js';
import { openRuleEditor } from './rules.js';

let paused = false;
let query = '';
let routeFilter = 'all';
let groupBy = 'conn';
let rows = new Map();
let tbody = null;
let empty = null;
let pauseBtn = null;

export const activity = {
  id: 'activity',
  title: 'Активность',
  icon: 'activity',
  statusRerender: true,
  count: () => (store.traffic ? store.traffic.connections || '' : ''),
  render(root) {
    rows = new Map();
    const running = ST().phase === 'running';
    pauseBtn = h('button.btn', { onclick: togglePause }, icon(paused ? 'play' : 'pause'), paused ? 'Продолжить' : 'Пауза');
    root.append(pageHead('Активность', running ? [
      pauseBtn,
      h('button.btn', { onclick: closeAll, title: 'Программы переподключатся заново — уже по новым правилам' }, icon('close'), 'Закрыть все'),
    ] : [], 'Соединения программ прямо сейчас: куда идут и по какому правилу. Отсюда удобно создавать правила.'));
    if (!running) {
      root.append(h('section.empty',
        h('h2.empty-title', 'Нет подключения'),
        h('p.empty-text', 'Подключитесь, и здесь появятся соединения всех программ.'),
        h('div.empty-actions', h('button.btn.primary', { onclick: connect }, icon('power'), 'Подключить'))));
      return;
    }
    const search = h('input.input.search', {
      type: 'search', value: query, placeholder: 'Программа, сайт или правило', 'aria-label': 'Фильтр соединений',
      oninput: () => { query = search.value.trim().toLowerCase(); rebuild(); },
    });
    root.append(h('div.toolbar',
      h('div.search-wrap', icon('search'), search),
      seg([{ value: 'all', label: 'Все' }, { value: 'tunnel', label: 'Через VPN' }, { value: 'direct', label: 'Напрямую' }],
        routeFilter, (v) => { routeFilter = v; rebuild(); }, { label: 'Маршрут' }),
      seg([{ value: 'conn', label: 'Соединения' }, { value: 'app', label: 'Программы' }],
        groupBy, (v) => { groupBy = v; store.navigate('activity', true); }, { label: 'Группировка' })));
    const head = groupBy === 'conn'
      ? ['Программа', 'Куда', 'Правило', 'Маршрут', 'Трафик', 'Время', '']
      : ['Программа', 'Соединений', 'Куда чаще всего', 'Маршрут', 'Трафик', '', ''];
    tbody = h('tbody');
    empty = h('div.table-empty', { hidden: true });
    root.append(h('div.panel.table-wrap',
      h('table.conn-table.' + groupBy,
        h('colgroup', groupBy === 'conn'
          ? [h('col.c1'), h('col.c2'), h('col.c3'), h('col.c4'), h('col.c5'), h('col.c6'), h('col.c7')]
          : [h('col.c1'), h('col.c2n'), h('col.c2'), h('col.c4'), h('col.c5'), h('col.c6'), h('col.c7')]),
        h('thead', h('tr', head.map((t, i) => h('th' + (i === 4 || (groupBy === 'conn' && i === 5) || (groupBy === 'app' && i === 1) ? '.num' : ''), t)))),
        tbody),
      empty));
    rebuild();
  },
  onTraffic() {
    if (!paused && tbody) update();
  },
  onIcons() {
    if (!tbody) return;
    for (const el of tbody.querySelectorAll('span.app-ic[data-app]')) {
      const fresh = appIcon(el.dataset.app);
      if (fresh.tagName === 'IMG') {
        fresh.dataset.app = el.dataset.app;
        el.replaceWith(fresh);
      }
    }
  },
  leave() {
    tbody = null;
  },
};

function togglePause() {
  paused = !paused;
  pauseBtn.replaceChildren(icon(paused ? 'play' : 'pause'), paused ? 'Продолжить' : 'Пауза');
  if (!paused) update();
}

function rebuild() {
  if (!tbody) return;
  rows = new Map();
  tbody.replaceChildren();
  update();
}

function matches(c) {
  const b = connBranch(c);
  if (routeFilter === 'direct' && b !== 'direct') return false;
  if (routeFilter === 'tunnel' && b === 'direct') return false;
  if (!query) return true;
  return [c.process, c.host, c.ip, c.rule, c.outbound].some((x) => x && x.toLowerCase().includes(query));
}

function routeChipFor(c) {
  const b = connBranch(c);
  if (b === 'direct') return h('span.chip.r-direct', 'Напрямую');
  const p = profileByTag(c.outbound);
  return h('span.chip.r-tunnel', { title: 'Через сервер «' + (p ? p.name : c.outbound) + '»' }, p ? p.name : c.outbound);
}

function iconFor(c) {
  const el = appIcon(c.path || c.process);
  el.dataset.app = c.path || c.process || '';
  return el;
}

const since = (iso) => {
  const t = Date.parse(iso);
  return Number.isFinite(t) ? (Date.now() - t) / 1000 : 0;
};

function update() {
  const list = (store.conns || []).filter(matches);
  const view = groupBy === 'conn' ? list.sort((a, b) => (a.start < b.start ? 1 : a.start > b.start ? -1 : 0)).map(connItem) : appItems(list);
  const seen = new Set();
  let prev = null;
  for (const item of view) {
    seen.add(item.key);
    let tr = rows.get(item.key);
    if (!tr) {
      tr = item.build();
      rows.set(item.key, tr);
    }
    const want = prev ? prev.nextSibling : tbody.firstChild;
    if (want !== tr) tbody.insertBefore(tr, want);
    item.fill(tr);
    prev = tr;
  }
  for (const [k, tr] of rows) {
    if (!seen.has(k)) {
      tr.remove();
      rows.delete(k);
    }
  }
  empty.hidden = view.length > 0;
  empty.textContent = (store.conns || []).length ? 'Под фильтр ничего не подходит.' : 'Соединений пока нет.';
  loadIcons(list.map((c) => c.path));
}

function connItem(c) {
  return {
    key: c.id,
    build: () => h('tr',
      h('td.c-app', iconFor(c), h('span.c-proc', { title: c.path || '' }, c.process || 'система')),
      h('td.c-dest', h('div.cell-flex',
        h('span.c-host', { title: c.ip ? `${c.host || c.ip} (${c.ip})` : c.host }, c.host || c.ip),
        h('span.c-port', ':' + c.port), h('span.c-net', c.network))),
      h('td.c-rule', { title: c.rule }, c.rule),
      h('td.c-route', routeChipFor(c)),
      h('td.num.c-traffic'),
      h('td.num.c-time'),
      h('td.c-act',
        h('button.icon-btn.small', { title: 'Создать правило', 'aria-label': 'Создать правило', onclick: (e) => ruleMenu(e.currentTarget, c) }, icon('plus')),
        h('button.icon-btn.small', { title: 'Закрыть соединение', 'aria-label': 'Закрыть соединение', onclick: () => closeOne(c.id) }, icon('close')))),
    fill: (tr) => {
      tr.cells[4].textContent = `${fmtBytes(c.up)} / ${fmtBytes(c.down)}`;
      tr.cells[5].textContent = fmtClock(since(c.start));
    },
  };
}

function appItems(list) {
  const map = new Map();
  for (const c of list) {
    const key = (c.path || c.process || 'система').toLowerCase();
    let g = map.get(key);
    if (!g) {
      g = { key: 'app:' + key, sample: c, n: 0, up: 0, down: 0, hosts: new Map(), routes: new Map() };
      map.set(key, g);
    }
    g.n++;
    g.up += c.up;
    g.down += c.down;
    const host = c.host || c.ip;
    g.hosts.set(host, (g.hosts.get(host) || 0) + 1);
    const rk = connBranch(c) === 'direct' ? 'direct' : c.outbound;
    if (!g.routes.has(rk)) g.routes.set(rk, c);
  }
  const groups = [...map.values()].sort((a, b) => (b.up + b.down) - (a.up + a.down));
  return groups.map((g) => ({
    key: g.key,
    build: () => h('tr',
      h('td.c-app', iconFor(g.sample), h('span.c-proc', { title: g.sample.path || '' }, g.sample.process || 'система')),
      h('td.num.c-count'),
      h('td.c-dest.c-hosts'),
      h('td.c-route'),
      h('td.num.c-traffic'),
      h('td'),
      h('td.c-act',
        h('button.icon-btn.small', { title: 'Создать правило для программы', 'aria-label': 'Создать правило для программы', onclick: () => ruleFor(g.sample, 'app') }, icon('plus')))),
    fill: (tr) => {
      tr.cells[1].textContent = String(g.n);
      const top = [...g.hosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k]) => k);
      tr.cells[2].textContent = top.join(', ');
      tr.cells[2].title = top.join('\n');
      tr.cells[3].replaceChildren(...[...g.routes.values()].map(routeChipFor));
      tr.cells[4].textContent = `${fmtBytes(g.up)} / ${fmtBytes(g.down)}`;
    },
  }));
}

function rootDomain(host) {
  const parts = host.toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const second = parts[parts.length - 2];
  const take = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'msk', 'spb'].includes(second) && parts[parts.length - 1].length <= 3 ? 3 : 2;
  return parts.slice(-take).join('.');
}

const isIp = (x) => /^[\d.]+$/.test(x) || x.includes(':');

function ruleFor(c, what) {
  const route = connBranch(c) === 'direct' ? { kind: 'proxy' } : { kind: 'direct' };
  if (what === 'app') openRuleEditor({ name: (c.process || '').replace(/\.exe$/i, ''), apps: [c.process || c.path], route });
  if (what === 'site') { const d = rootDomain(c.host); openRuleEditor({ name: d, domains: [d], route }); }
  if (what === 'ip') openRuleEditor({ name: c.ip, ips: [c.ip], route });
}

function ruleMenu(anchor, c) {
  popMenu(anchor, [
    c.process && { label: `Для программы ${c.process}`, icon: 'servers', run: () => ruleFor(c, 'app') },
    c.host && !isIp(c.host) && { label: `Для сайта ${rootDomain(c.host)}`, icon: 'external', run: () => ruleFor(c, 'site') },
    c.ip && { label: `Для адреса ${c.ip}`, icon: 'list', run: () => ruleFor(c, 'ip') },
  ]);
}

async function closeOne(id) {
  try {
    await invoke('close_connection', { id });
    const tr = rows.get(id);
    if (tr) {
      tr.remove();
      rows.delete(id);
    }
    store.conns = (store.conns || []).filter((c) => c.id !== id);
  } catch (e) {
    errorToast(e);
  }
}

async function closeAll() {
  try {
    const n = (store.conns || []).length;
    await invoke('close_all_connections');
    toast(n ? `Закрыто: ${plural(n, 'соединение', 'соединения', 'соединений')}` : 'Соединения закрыты');
  } catch (e) {
    errorToast(e);
  }
}
