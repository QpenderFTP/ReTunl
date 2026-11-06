// Small DOM, formatting and dialog helpers. No framework: the app is a few
// screens that re-render from one state object.

const T = window.__TAURI__;

export function invoke(cmd, args) {
  return T.core.invoke(cmd, args || {});
}

export function listen(name, fn) {
  return T.event.listen(name, (e) => fn(e.payload));
}

// ---------- DOM ----------

const PROPS = new Set([
  'value', 'checked', 'disabled', 'selected', 'hidden', 'open', 'type', 'name', 'placeholder',
  'rows', 'min', 'max', 'step', 'title', 'href', 'src', 'alt', 'htmlFor', 'tabIndex', 'spellcheck',
  'draggable', 'readOnly', 'id', 'maxLength', 'autocomplete',
]);

function setProps(el, props) {
  for (const k in props) {
    const v = props[k];
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.classList.add(...String(v).split(/\s+/).filter(Boolean));
    else if (k === 'style') {
      if (typeof v === 'string') el.style.cssText = v;
      else for (const sk in v) sk.startsWith('--') ? el.style.setProperty(sk, v[sk]) : (el.style[sk] = v[sk]);
    } else if (k === 'data') for (const d in v) el.dataset[d] = v[d];
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'ref') v(el);
    else if (PROPS.has(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
}

export function add(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false || k === true || k === '') continue;
    el.append(k instanceof Node ? k : String(k));
  }
  return el;
}

/** h('button.btn.primary', {onclick}, 'Текст') */
export function h(sel, ...rest) {
  let props = null;
  const first = rest[0];
  if (first && typeof first === 'object' && !(first instanceof Node) && !Array.isArray(first)) props = rest.shift();
  const tag = /^[a-z][a-z0-9-]*/i.exec(sel);
  const el = document.createElement(tag ? tag[0] : 'div');
  const id = /#([\w-]+)/.exec(sel);
  if (id) el.id = id[1];
  const classes = [...sel.matchAll(/\.([\w-]+)/g)].map((m) => m[1]);
  if (classes.length) el.className = classes.join(' ');
  if (props) setProps(el, props);
  return add(el, rest);
}

const NS = 'http://www.w3.org/2000/svg';
export function s(tag, attrs = {}, ...kids) {
  const el = document.createElementNS(NS, tag);
  for (const k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) el.setAttribute(k, attrs[k]);
  for (const k of kids.flat()) if (k) el.append(k);
  return el;
}

// 24×24 line icons
const ICONS = {
  overview: 'M12 21v-7.5M12 14c0-4.5-6-4.5-6-10M12 14c0-4.5 6-4.5 6-10',
  servers: 'M4 4.5h16v6H4zM4 13.5h16v6H4zM8 7.5h.01M8 16.5h.01',
  rules: 'M4 6h9M4 12h6M4 18h9M15 9l4 3-4 3M19 12h-6',
  activity: 'M3 12h4l3-7 4 14 3-7h4',
  logs: 'M6 3.5h8.5L18 7v13.5H6zM9 11h6M9 14.5h6M9 18h3.5',
  settings: 'M4 7h9M17 7h3M4 17h3M11 17h9M15 5v4M9 15v4',
  plus: 'M12 5v14M5 12h14',
  clipboard: 'M9 3.5h6v3H9zM7.5 5H5v15.5h14V5h-2.5',
  file: 'M6.5 3.5H14L18.5 8v12.5h-12zM14 3.5V8h4.5',
  plug: 'M9 3v5M15 3v5M6.5 8h11v3a5.5 5.5 0 0 1-11 0zM12 16.5V21',
  refresh: 'M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4',
  trash: 'M4.5 7h15M9.5 7V4h5v3M6.5 7l1 13.5h9l1-13.5',
  edit: 'M4 20h4L19 9l-4-4L4 16zM13 7l4 4',
  more: 'M5.5 12h.01M12 12h.01M18.5 12h.01',
  copy: 'M9 9h11v11H9zM15 5V4H4v11h1',
  close: 'M6.5 6.5l11 11M17.5 6.5l-11 11',
  grip: 'M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01',
  search: 'M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM20 20l-4.8-4.8',
  folder: 'M3 6h6.5l2 2H21v11H3z',
  power: 'M12 3v8M6.3 6.8a7.5 7.5 0 1 0 11.4 0',
  pause: 'M8.5 5v14M15.5 5v14',
  play: 'M7.5 5l11 7-11 7z',
  up: 'M12 19V5M6 11l6-6 6 6',
  down: 'M12 5v14M6 13l6 6 6-6',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  speed: 'M4.5 16a7.5 7.5 0 1 1 15 0M12 16l4-5',
  monitor: 'M3 4.5h18v11.5H3zM8 20h8M12 16v4',
  list: 'M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01',
  external: 'M14 4h6v6M20 4l-8.5 8.5M18 14v6H4V6h6',
  lock: 'M6 10.5h12v10H6zM8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3M12 14.5v2',
};

export function icon(name, cls) {
  return s('svg', { viewBox: '0 0 24 24', class: 'ic' + (cls ? ' ' + cls : ''), 'aria-hidden': 'true' }, s('path', { d: ICONS[name] || '' }));
}

/** The app mark: a road forking into two routes (same drawing as the icon). */
export function logo() {
  const road = (d, c) => s('path', { d, stroke: c, 'stroke-width': 3.9, 'stroke-linecap': 'round', fill: 'none' });
  return s('svg', { viewBox: '0 0 32 32', class: 'logo', 'aria-hidden': 'true' },
    s('rect', { x: 0.5, y: 0.5, width: 31, height: 31, rx: 7.5, fill: '#111820', stroke: 'rgba(226,232,238,.16)' }),
    road('M16 27V17.5', '#E2E8EE'),
    road('M16 17.5C16 12.6 9.4 12.2 9.4 6.1', '#E2E8EE'),
    road('M16 17.5C16 12.6 22.6 12.2 22.6 6.1', '#F5A524'),
    s('circle', { cx: 9.4, cy: 6.1, r: 2.9, fill: '#E2E8EE' }),
    s('circle', { cx: 22.6, cy: 6.1, r: 2.9, fill: '#F5A524' }));
}

// ---------- formatting ----------

const nf0 = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 0 });
const nf1 = new Intl.NumberFormat('ru-RU', { maximumFractionDigits: 1 });

export function fmtBytes(n) {
  if (n === null || n === undefined) return '—';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return (i === 0 || v >= 100 ? nf0 : nf1).format(v) + ' ' + units[i];
}

export const fmtRate = (n) => fmtBytes(n) + '/с';

export function fmtClock(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  const hh = Math.floor(sec / 3600);
  const mm = Math.floor((sec % 3600) / 60);
  const ss = sec % 60;
  const p = (x) => String(x).padStart(2, '0');
  return (hh ? hh + ':' : '') + p(mm) + ':' + p(ss);
}

export function plural(n, one, few, many) {
  const m10 = n % 10;
  const m100 = n % 100;
  const w = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
  return `${nf0.format(n)} ${w}`;
}

export const now = () => Math.floor(Date.now() / 1000);
export const fmtDate = (unix) => new Date(unix * 1000).toLocaleDateString('ru-RU');

export function fmtAgo(unix) {
  if (!unix) return 'никогда';
  const d = now() - unix;
  if (d < 60) return 'только что';
  if (d < 3600) return Math.floor(d / 60) + ' мин назад';
  if (d < 86400) return Math.floor(d / 3600) + ' ч назад';
  if (d < 86400 * 7) return plural(Math.floor(d / 86400), 'день', 'дня', 'дней') + ' назад';
  return fmtDate(unix);
}

export function errText(e) {
  if (e === null || e === undefined) return 'Неизвестная ошибка';
  if (typeof e === 'string') return e;
  return e.message || String(e);
}

// ---------- toasts ----------

export function toast(text, opts = {}) {
  const { kind = 'info', detail, action } = opts;
  const timeout = opts.timeout ?? (kind === 'error' ? 9000 : 4500);
  // a modal dialog sits in the top layer, so toasts go inside it while it is open
  const top = [...document.querySelectorAll('dialog[open]')].pop();
  let root = document.getElementById('toasts');
  if (top) root = top.querySelector(':scope > .toasts') || top.appendChild(h('div.toasts', { 'aria-live': 'polite' }));
  let timer;
  const el = h('div.toast.' + kind, { role: kind === 'error' ? 'alert' : 'status' },
    h('div.toast-body', h('div.toast-text', text), detail && h('div.toast-detail', detail)),
    action && h('button.btn.small', { onclick: () => { close(); action.run(); } }, action.label),
    h('button.icon-btn.small', { 'aria-label': 'Скрыть', onclick: () => close() }, icon('close')));
  function close() {
    clearTimeout(timer);
    el.classList.add('out');
    setTimeout(() => el.remove(), 160);
  }
  el.addEventListener('mouseenter', () => clearTimeout(timer));
  el.addEventListener('mouseleave', () => { timer = setTimeout(close, 2500); });
  root.append(el);
  while (root.children.length > 4) root.firstChild.remove();
  timer = setTimeout(close, timeout);
  return close;
}

export const errorToast = (e) => toast(errText(e), { kind: 'error' });

// ---------- dialogs ----------

/** Modal dialog. Returns {el, body, close}. */
export function dialog({ title, body, actions = [], wide = false, onClose, lead }) {
  const d = h('dialog.dlg' + (wide ? '.wide' : ''), { 'aria-label': title });
  const content = h('div.dlg-body', body);
  const close = () => { if (d.open) d.close(); };
  d.append(h('div.dlg-inner',
    h('header.dlg-head', h('div', h('h2.dlg-title', title), lead && h('p.dlg-lead', lead)),
      h('button.icon-btn', { 'aria-label': 'Закрыть', onclick: close }, icon('close'))),
    content,
    actions.length ? h('footer.dlg-foot', actions) : null));
  d.addEventListener('close', () => { d.remove(); if (onClose) onClose(); });
  let downOnBackdrop = false;
  d.addEventListener('mousedown', (e) => { downOnBackdrop = e.target === d; });
  d.addEventListener('mouseup', (e) => { if (downOnBackdrop && e.target === d && !wide) close(); downOnBackdrop = false; });
  document.body.append(d);
  d.showModal();
  const focus = d.querySelector('.dlg-body input:not([type=checkbox]):not([type=radio]), .dlg-body textarea, .dlg-body select');
  if (focus) focus.focus();
  return { el: d, body: content, close };
}

export function confirmDialog({ title, text, ok = 'Удалить', danger = true }) {
  return new Promise((resolve) => {
    let result = false;
    const dl = dialog({
      title,
      body: h('p.dlg-text', text),
      actions: [
        h('button.btn', { onclick: () => dl.close() }, 'Отмена'),
        h('button.btn' + (danger ? '.danger-solid' : '.primary'), { onclick: () => { result = true; dl.close(); } }, ok),
      ],
      onClose: () => resolve(result),
    });
  });
}

export function promptDialog({ title, value = '', label, ok = 'Сохранить', placeholder }) {
  return new Promise((resolve) => {
    let result = null;
    const input = h('input.input.wide', { value, placeholder, 'aria-label': label || title });
    const submit = () => { result = input.value.trim(); dl.close(); };
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
    const dl = dialog({
      title,
      body: [label && h('label.field-label', label), input],
      actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), h('button.btn.primary', { onclick: submit }, ok)],
      onClose: () => resolve(result),
    });
    input.select();
  });
}

// ---------- popup menu ----------

let openMenu = null;

export function closeMenu() {
  if (!openMenu) return;
  openMenu.cleanup();
  openMenu = null;
}

/** items: {label, icon, run, danger, disabled} | '-' */
export function popMenu(anchor, items) {
  if (openMenu && openMenu.anchor === anchor) return closeMenu();
  closeMenu();
  const host = anchor.closest('dialog') || document.body;
  const m = h('div.menu', { role: 'menu' }, items.filter(Boolean).map((it) => it === '-'
    ? h('div.menu-sep', { role: 'separator' })
    : h('button.menu-item' + (it.danger ? '.danger' : ''), {
      role: 'menuitem', type: 'button', disabled: it.disabled,
      onclick: () => { closeMenu(); it.run(); },
    }, it.icon ? icon(it.icon) : h('span.ic'), h('span', it.label))));
  host.append(m);
  const r = anchor.getBoundingClientRect();
  const mw = m.offsetWidth;
  const mh = m.offsetHeight;
  let left = r.right - mw;
  if (left < 8) left = Math.min(r.left, innerWidth - mw - 8);
  let top = r.bottom + 4;
  if (top + mh > innerHeight - 8) top = r.top - mh - 4;
  m.style.left = left + 'px';
  m.style.top = Math.max(8, top) + 'px';
  const onDown = (e) => { if (!m.contains(e.target) && !anchor.contains(e.target)) closeMenu(); };
  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); closeMenu(); anchor.focus(); }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const btns = [...m.querySelectorAll('button:not([disabled])')];
      const i = btns.indexOf(document.activeElement);
      btns[(i + (e.key === 'ArrowDown' ? 1 : -1) + btns.length) % btns.length]?.focus();
    }
  };
  const onScroll = () => closeMenu();
  setTimeout(() => {
    document.addEventListener('mousedown', onDown, true);
    document.addEventListener('keydown', onKey, true);
    document.getElementById('main')?.addEventListener('scroll', onScroll);
  });
  openMenu = {
    anchor,
    cleanup() {
      document.removeEventListener('mousedown', onDown, true);
      document.removeEventListener('keydown', onKey, true);
      document.getElementById('main')?.removeEventListener('scroll', onScroll);
      m.remove();
    },
  };
  m.querySelector('button:not([disabled])')?.focus();
}

// ---------- controls ----------

/** Segmented control (radio group). options: [{value, label, title}] */
export function seg(options, value, onChange, { label, cls } = {}) {
  const el = h('div.seg' + (cls ? '.' + cls : ''), { role: 'radiogroup', 'aria-label': label });
  const set = (v) => {
    for (const b of el.children) {
      const on = b.dataset.v === String(v);
      b.setAttribute('aria-checked', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
    }
    if (![...el.children].some((b) => b.tabIndex === 0) && el.firstChild) el.firstChild.tabIndex = 0;
  };
  for (const o of options) {
    const b = h('button.seg-btn', {
      type: 'button', role: 'radio', title: o.title, data: { v: String(o.value) }, disabled: !!o.disabled,
      onclick: () => {
        if (b.getAttribute('aria-checked') === 'true') return;
        set(o.value);
        onChange(o.value);
      },
    }, o.label);
    el.append(b);
  }
  el.addEventListener('keydown', (e) => {
    if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
    const btns = [...el.children].filter((b) => !b.disabled);
    const i = btns.indexOf(document.activeElement);
    const next = btns[(i + (e.key === 'ArrowRight' ? 1 : -1) + btns.length) % btns.length];
    next.focus();
    next.click();
  });
  set(value);
  el.setValue = set;
  return el;
}

export function toggle(checked, onChange, attrs = {}) {
  return h('input.switch', { type: 'checkbox', role: 'switch', checked, ...attrs, onchange: (e) => onChange(e.target.checked) });
}

/** Disable a button while an async action runs. */
export async function busy(btn, fn) {
  if (!btn || btn.disabled) return undefined;
  btn.disabled = true;
  btn.classList.add('busy');
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.classList.remove('busy');
  }
}

export function pageHead(title, actions = [], lead) {
  return h('header.page-head',
    h('div.page-head-row', h('h1.page-title', title), h('div.page-actions', actions)),
    lead && h('p.page-lead', lead));
}

export function banner(kind, title, text, actions = []) {
  return h('div.banner.' + kind, { role: kind === 'error' ? 'alert' : null },
    h('div.banner-body', h('div.banner-title', title), text && h('div.banner-text', text)),
    actions.length ? h('div.banner-actions', actions) : null);
}
