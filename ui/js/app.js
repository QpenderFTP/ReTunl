// Entry point: navigation rail, page switching, events and polling.

import {
  h, icon, logo, invoke, listen, fmtClock, now, closeMenu,
} from './lib.js';
import {
  store, on, emit, refresh, ST, D, activeProfile, toggleConnection, adminDialog, isOn,
} from './store.js';
import { overview } from './overview.js';
import { servers } from './servers.js';
import { rules } from './rules.js';
import { activity } from './activity.js';
import { logs } from './logs.js';
import { settingsPage, applyTheme } from './settings.js';

const PAGES = [overview, servers, rules, activity, logs, settingsPage];
const page = () => PAGES.find((p) => p.id === store.page) || overview;

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
  for (const p of PAGES) {
    const b = document.getElementById('nav-' + p.id);
    if (!b) continue;
    if (p.id === store.page) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  }
}

function updateCounts() {
  for (const p of PAGES) {
    const el = document.getElementById('navc-' + p.id);
    if (el) el.textContent = p.count ? String(p.count() || '') : '';
  }
}

function updateRailStatus() {
  const el = document.getElementById('rail-status');
  if (!el) return;
  const st = ST();
  const ph = st.phase;
  const ap = activeProfile();
  const server = ph === 'running' ? (st.profile || 'без сервера') : (ap ? ap.name : 'сервер не выбран');
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
  if (changed) poll();
}

// ---------- events ----------

on((what) => {
  const p = page();
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
  try {
    const wantConns = store.page === 'overview' || store.page === 'activity';
    const res = await invoke('poll', { connections: wantConns });
    const before = ST();
    store.traffic = res.traffic;
    store.conns = wantConns ? res.connections || [] : null;
    if (res.status.phase !== before.phase || res.status.since !== before.since) {
      store.view.status = res.status;
      emit('status');
    }
    emit('traffic');
  } catch {
    // core restarting — next tick will catch up
  } finally {
    polling = false;
  }
}

function tickClock() {
  const st = store.view && ST();
  if (!st || st.phase !== 'running' || !st.since) return;
  const t = fmtClock(now() - st.since);
  for (const el of document.querySelectorAll('.uptime')) el.textContent = t;
}

function keyboard(e) {
  if (e.ctrlKey && !e.altKey && !e.shiftKey && /^[1-6]$/.test(e.key) && !document.querySelector('dialog[open]')) {
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
  renderRail();
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
  listen('core-progress', (p) => { store.coreProgress = p; emit('core'); });
  listen('subscriptions-updating', (id) => { store.subUpdating.add(id); emit('data'); });
  listen('data-changed', () => { store.subUpdating.clear(); refresh(); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh().then(poll); });

  setInterval(poll, 1000);
  setInterval(tickClock, 1000);
  invoke('app_ready');
}

init();
