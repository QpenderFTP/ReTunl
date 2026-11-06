// Журнал: messages from sing-box and from the app.

import { h, icon, invoke, seg, pageHead, toast, errorToast } from './lib.js';
import { copyText } from './store.js';

let lines = [];
let last = 0;
let timer = null;
let level = 'all';
let query = '';
let view = null;
let inFlight = false;
const MAX = 4000;

const lvl = (l) => {
  const x = (l.level || '').toLowerCase();
  if (x.startsWith('err') || x === 'fatal' || x === 'panic') return 'error';
  if (x.startsWith('warn')) return 'warn';
  if (x === 'debug' || x === 'trace') return 'debug';
  return 'info';
};

const visible = (l) => {
  const v = lvl(l);
  if (level === 'warn' && v !== 'warn' && v !== 'error') return false;
  if (level === 'error' && v !== 'error') return false;
  return !query || l.text.toLowerCase().includes(query);
};

const LEVEL_LABEL = { error: 'ошибка', warn: 'внимание', info: 'инфо', debug: 'отладка' };

function lineEl(l) {
  const v = lvl(l);
  return h('div.log-line.lv-' + v,
    h('span.log-time', l.time),
    h('span.log-lv', LEVEL_LABEL[v]),
    h('span.log-src', l.source === 'app' ? 'ReTunl' : 'sing-box'),
    h('span.log-text', l.text));
}

export const logs = {
  id: 'logs',
  title: 'Журнал',
  icon: 'logs',
  render(root) {
    root.append(pageHead('Журнал', [
      h('button.btn', { onclick: copyVisible }, icon('copy'), 'Копировать'),
      h('button.btn', { onclick: clear }, icon('trash'), 'Очистить'),
    ]));
    const search = h('input.input.search', {
      type: 'search', value: query, placeholder: 'Найти в журнале', 'aria-label': 'Поиск в журнале',
      oninput: () => { query = search.value.trim().toLowerCase(); renderAll(); },
    });
    root.append(h('div.toolbar',
      h('div.search-wrap', icon('search'), search),
      seg([{ value: 'all', label: 'Всё' }, { value: 'warn', label: 'Предупреждения' }, { value: 'error', label: 'Ошибки' }],
        level, (v) => { level = v; renderAll(); }, { label: 'Уровень' })));
    view = h('div.panel.log-view.selectable', { tabIndex: 0, role: 'log', 'aria-label': 'Журнал' });
    root.append(view);
    renderAll();
  },
  onData() {},
  enter() {
    fetchLogs();
    timer = setInterval(fetchLogs, 1000);
  },
  leave() {
    clearInterval(timer);
    timer = null;
    view = null;
  },
};

function renderAll() {
  if (!view) return;
  const shown = lines.filter(visible).slice(-2000);
  view.replaceChildren(...shown.map(lineEl));
  if (!shown.length) view.append(h('div.log-empty', lines.length ? 'Под фильтр ничего не подходит.' : 'Журнал пуст. Сообщения ядра появятся здесь после подключения.'));
  view.scrollTop = view.scrollHeight;
}

async function fetchLogs() {
  if (inFlight) return;
  inFlight = true;
  try {
    const res = await invoke('get_logs', { after: last });
    if (res.last < last) lines = [];
    last = res.last;
    if (!res.lines.length) return;
    lines.push(...res.lines);
    if (lines.length > MAX) lines.splice(0, lines.length - MAX);
    if (!view) return;
    const atBottom = view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    const fresh = res.lines.filter(visible);
    if (!fresh.length) return;
    view.querySelector('.log-empty')?.remove();
    view.append(...fresh.map(lineEl));
    while (view.childElementCount > 2000) view.firstChild.remove();
    if (atBottom) view.scrollTop = view.scrollHeight;
  } catch {
    // the backend is busy shutting down; try again next tick
  } finally {
    inFlight = false;
  }
}

function copyVisible() {
  const text = lines.filter(visible).map((l) => `${l.time} ${l.level} [${l.source}] ${l.text}`).join('\n');
  if (!text) { toast('В журнале пусто'); return; }
  copyText(text, 'Журнал скопирован');
}

async function clear() {
  try {
    await invoke('clear_logs');
    lines = [];
    renderAll();
  } catch (e) {
    errorToast(e);
  }
}
