// Entry point: navigation (a rail; on phones a tab bar), page switching, events and polling.

import {
  h, setText, icon, logo, invoke, listen, fmtClock, now, closeMenu, menuOpen, dialog,
} from './lib.js';
import {
  store, on, emit, refresh, ST, D, activeProfile, toggleConnection, adminDialog, isOn, isAndroid,
  isScanning, cancelScan, profile, connect,
} from './store.js';
import { overview, speedProgress } from './overview.js';
import { servers } from './servers.js';
import { ciscoLogin } from './cisco.js';
import { myServers, loadHosts } from './hosts.js';
import { rules } from './rules.js';
import { activity } from './activity.js';
import { logs } from './logs.js';
import { settingsPage, applyTheme } from './settings.js';
import { checkUpdate, installUpdate } from './updates.js';

const PAGES = [overview, servers, myServers, rules, activity, logs, settingsPage];
const page = () => PAGES.find((p) => p.id === store.page) || overview;
const byId = (id) => PAGES.find((p) => p.id === id);

// Phones: four sections in the tab bar, the rest under «Ещё»
const TABS = ['overview', 'servers', 'rules', 'activity'];
const MORE = [
  ['hosts', 'Свои VPS: установка VPN и клиенты'],
  ['logs', 'Сообщения ядра и ReTunl'],
  ['settings', 'DNS, оформление, перенос на другое устройство'],
];
const phone = matchMedia('(max-width: 720px)');

const PHASE_LABEL = {
  stopped: 'Отключено', starting: 'Подключаюсь…', running: 'Подключено', stopping: 'Отключаюсь…', failed: 'Ошибка',
};

// ---------- rail ----------

function renderRail() {
  const rail = document.getElementById('rail');
  rail.replaceChildren(
    h('div.brand', logo(), h('span.brand-name', 'ReTunl')),
    h('ul.nav', PAGES.map((p, i) => h('li',
      h('button.nav-btn', { id: 'nav-' + p.id, title: `${p.title} (Ctrl+${i + 1})`, onclick: () => navigate(p.id) },
        icon(p.icon), h('span.nav-label', p.title), h('span.nav-count', { id: 'navc-' + p.id }))))),
    h('div.rail-status#rail-status'));
  markNav();
  updateCounts();
  updateRailStatus();
}

function markNav() {
  const mark = (el, on) => { if (el) { if (on) el.setAttribute('aria-current', 'page'); else el.removeAttribute('aria-current'); } };
  for (const p of PAGES) mark(document.getElementById('nav-' + p.id), p.id === store.page);
  for (const id of TABS) mark(document.getElementById('tab-' + id), id === store.page);
  mark(document.getElementById('tab-more'), !TABS.includes(store.page));
}

// ---------- tab bar (phones) ----------

function renderTabbar() {
  const tab = (id, label, ic, onclick) => h('button.tab', { id: 'tab-' + id, type: 'button', onclick },
    h('span.tab-ic', icon(ic), id === 'overview' ? h('span.state-dot.tab-dot', { 'aria-hidden': 'true' }) : null),
    h('span.tab-label', label));
  document.getElementById('tabbar').replaceChildren(
    ...TABS.map((id) => tab(id, byId(id).title, byId(id).icon, () => navigate(id))),
    tab('more', 'Ещё', 'more', openMore));
}

function openMore() {
  const dl = dialog({
    title: 'Ещё',
    body: h('div.more-list', MORE.map(([id, note]) => {
      const p = byId(id);
      const count = p.count ? p.count() : 0;
      return h('button.more-item', {
        type: 'button',
        'aria-current': store.page === id ? 'page' : null,
        onclick: () => { dl.close(); navigate(id); },
      }, icon(p.icon), h('span.more-label', p.title), h('span.more-note', note), count ? h('span.nav-count', String(count)) : null);
    })),
  });
}

// ---------- Android's back button ----------

// Called by the app (VpnPlugin.kt) on «Назад». "done": handled here;
// anything else: ReTunl goes to the background, like Home (the VPN keeps running).
function backButton() {
  if (!isAndroid()) return;
  window.retunlBack = () => {
    const open = [...document.querySelectorAll('dialog[open]')].pop();
    if (isScanning()) cancelScan();
    else if (open) open.close();
    else if (menuOpen()) closeMenu();
    else if (store.page !== 'overview') navigate('overview');
    else return 'background';
    return 'done';
  };
}

function updateCounts() {
  for (const p of PAGES) {
    const el = document.getElementById('navc-' + p.id);
    if (el) setText(el, p.count ? String(p.count() || '') : '');
  }
}

function updateRailStatus() {
  const el = document.getElementById('rail-status');
  if (!el) return;
  const st = ST();
  const ph = st.phase;
  const ap = activeProfile();
  const server = ph === 'running' ? (st.profile || 'без сервера') : (ap ? ap.name : 'сервер не выбран');
  const bar = document.getElementById('tabbar');
  if (bar) bar.className = 'tabbar ph-' + ph;
  el.className = 'rail-status ph-' + ph;
  el.replaceChildren(
    h('div.rs-line',
      h('span.state-dot', { 'aria-hidden': 'true' }),
      h('span.rs-label', PHASE_LABEL[ph] || ph),
      ph === 'running' && st.since ? h('span.rs-time.uptime', fmtClock(now() - st.since)) : null),
    h('div.rs-server', { title: server }, server),
    h('button.btn.small.rs-btn' + (isOn(ph) ? '' : '.primary'), {
      disabled: ph === 'stopping', onclick: toggleConnection,
    }, icon('power'), ph === 'running' ? 'Отключить' : ph === 'starting' ? 'Отменить' : 'Подключить'));
}

// ---------- pages ----------

function renderPage(keep) {
  const main = document.getElementById('main');
  const top = keep ? main.scrollTop : 0;
  const focusId = keep && document.activeElement && main.contains(document.activeElement) ? document.activeElement.id : '';
  closeMenu();
  const p = page();
  const root = h('div.page.page-' + p.id);
  main.replaceChildren(root);
  try {
    p.render(root);
  } catch (e) {
    console.error(e);
    root.append(h('p.form-error', 'Не удалось показать экран: ' + (e.message || e)));
  }
  main.scrollTop = top;
  if (focusId) document.getElementById(focusId)?.focus({ preventScroll: true });
}

function navigate(id, rerender) {
  const next = PAGES.find((p) => p.id === id) || overview;
  if (next.id === store.page && !rerender && document.querySelector('#main .page')) return;
  const prev = page();
  if (prev !== next && prev.leave) prev.leave();
  const changed = prev !== next || !document.querySelector('#main .page');
  store.page = next.id;
  try { localStorage.setItem('page', next.id); } catch { /* storage off */ }
  markNav();
  renderPage(!changed);
  if (changed && next.enter) next.enter();
  if (changed) document.getElementById('main').focus({ preventScroll: true });
  syncTicks();
  if (changed) poll();
}

// ---------- events ----------

on((what) => {
  const p = page();
  if (what === 'data' || what === 'status') syncTicks();
  if (document.hidden) return;
  if (what === 'data') {
    updateCounts();
    updateRailStatus();
    if (p.onData) p.onData();
    else renderPage(true);
  } else if (what === 'status') {
    updateRailStatus();
    if (p.onStatus) p.onStatus();
    else if (p.statusRerender) renderPage(true);
  } else if (what === 'traffic') {
    updateCounts();
    if (p.onTraffic) p.onTraffic();
  } else if (what === 'icons') {
    if (p.onIcons) p.onIcons();
  } else if (what === 'core') {
    if (p.onCore) p.onCore();
  }
});

let polling = false;
async function poll() {
  if (polling || document.hidden || !store.view) return;
  const st = ST();
  if (st.phase !== 'running') {
    if (store.traffic) {
      store.traffic = null;
      store.conns = null;
      emit('traffic');
    }
    return;
  }
  polling = true;
  const requestedPage = store.page;
  try {
    const wantConns = requestedPage === 'activity' && activity.needsConnections();
    const res = await invoke('poll', { connections: wantConns, summary: requestedPage === 'overview' });
    if (document.hidden || ST().phase !== 'running' || ST().since !== st.since || requestedPage !== store.page) return;
    const before = ST();
    store.traffic = res.traffic;
    if (res.blocks) store.blocks = res.blocks;
    if (requestedPage !== 'activity') store.conns = null;
    else if (wantConns && activity.needsConnections()) store.conns = res.connections || [];
    if (res.status.phase !== before.phase || res.status.since !== before.since) {
      store.view.status = res.status;
      emit('status');
    }
    emit('traffic');
  } catch {
    // core restarting — next tick will catch up
  } finally {
    polling = false;
    if (requestedPage !== store.page) poll();
  }
}

let ticks = null;
function syncTicks() {
  const active = !document.hidden && store.view && (ST().phase === 'running' || store.page === 'logs');
  if (active && ticks === null) {
    ticks = setInterval(() => {
      poll();
      tickClock();
      if (store.page === 'logs') logs.tick();
    }, 1000);
  } else if (!active && ticks !== null) {
    clearInterval(ticks);
    ticks = null;
  }
}

function tickClock() {
  const st = store.view && ST();
  if (!st || st.phase !== 'running' || !st.since) return;
  const t = fmtClock(now() - st.since);
  for (const el of document.querySelectorAll('.uptime')) el.textContent = t;
}

function keyboard(e) {
  if (e.ctrlKey && !e.altKey && !e.shiftKey && /^[1-7]$/.test(e.key) && !document.querySelector('dialog[open]')) {
    e.preventDefault();
    navigate(PAGES[Number(e.key) - 1].id);
  }
}

// ---------- start ----------

async function init() {
  applyTheme();
  document.addEventListener('contextmenu', (e) => {
    if (!e.target.closest('input, textarea, .selectable')) e.preventDefault();
  });
  document.addEventListener('keydown', keyboard);
  try {
    await refresh();
  } catch (e) {
    document.getElementById('main').replaceChildren(h('p.form-error', 'Не удалось загрузить данные: ' + e));
    invoke('app_ready');
    return;
  }
  try {
    store.catalog = await invoke('get_catalog');
  } catch { /* keep the empty catalog */ }
  store.navigate = navigate;
  applyTheme(); // again, now that the platform is known
  renderTabbar();
  renderRail();
  backButton();
  // the fork is drawn for the width: redraw when a phone turns or a window narrows
  phone.addEventListener('change', () => renderPage(true));
  loadHosts().then(updateCounts).catch(() => { /* shown when the page opens */ });
  let saved = 'overview';
  try { saved = localStorage.getItem('page') || 'overview'; } catch { /* storage off */ }
  if (!D().profiles.length) saved = 'overview';
  navigate(saved, true);

  listen('status', (st) => {
    store.view.status = st;
    if (st.phase !== 'running') {
      store.traffic = null;
      store.conns = null;
    }
    emit('status');
    if (st.phase === 'running') poll();
  });
  listen('need-admin', () => adminDialog());
  // Cisco Secure Client wants a login before ReTunl can connect
  listen('cisco-login', (id) => { const p = profile(id); if (p) ciscoLogin(p, connect); });
  listen('speed-progress', (p) => { speedProgress(p); if (store.page === 'overview') overview.onSpeed(); });
  listen('core-progress', (p) => { store.coreProgress = p; emit('core'); });
  listen('subscriptions-updating', (id) => { store.subUpdating.add(id); emit('data'); });
  listen('data-changed', () => { store.subUpdating.clear(); refresh(); });
  document.addEventListener('visibilitychange', () => {
    syncTicks();
    if (!document.hidden) {
      refresh().then(poll).catch(() => {});
      if (store.page === 'logs') logs.tick();
    }
  });
  const update = await invoke('app_ready');
  if (update) {
    navigate('settings');
    installUpdate(update);
  } else checkUpdate();
  setInterval(checkUpdate, 12 * 60 * 60 * 1000);
}

init();
