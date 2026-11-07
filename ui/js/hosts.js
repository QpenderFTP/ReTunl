// Мои серверы: VPS the user has root on. ReTunl logs in over SSH, reads the
// protocols AmneziaVPN (or ReTunl) installed, manages their clients and
// installs new protocols on a clean server.

import {
  h, s, icon, invoke, listen, busy, toast, errorToast, errText, dialog, confirmDialog, promptDialog, popMenu,
  pageHead, fmtAgo, fmtBytes, plural, banner, seg, now,
} from './lib.js';
import { store, refresh, copyText, reportImport, here } from './store.js';

let list = null; // ServerView[] once loaded
let autoScanned = false;
const pending = new Set(); // 'scan:id', 'proto:id:container', 'client:id:container:client'
const installs = new Map(); // server id → install in progress or failed

const TITLE = { awg: 'AmneziaWG', awg_legacy: 'AmneziaWG', wireguard: 'WireGuard', xray: 'VLESS Reality' };
const STATE = { exited: 'остановлен', created: 'не запущен', restarting: 'перезапускается', paused: 'приостановлен', dead: 'сломан' };
const KEY_CHANGED = 'Ключ SSH сервера изменился';

const OFFER = [
  {
    kind: 'awg', container: 'amnezia-awg2', title: 'AmneziaWG', net: 'UDP',
    text: 'WireGuard с маскировкой трафика: его сложнее распознать и заблокировать, а скорость почти та же.',
    port: () => 30000 + Math.floor(Math.random() * 30000),
  },
  {
    kind: 'xray', container: 'amnezia-xray', title: 'VLESS Reality', net: 'TCP',
    text: 'Выглядит как HTTPS-соединение с чужим сайтом. Выручает там, где UDP режут или замедляют.',
    port: () => 443,
  },
  {
    kind: 'wireguard', container: 'amnezia-wireguard', title: 'WireGuard', net: 'UDP',
    text: 'Обычный WireGuard: быстрый и простой, но его легко заблокировать. Подходит, где блокировок нет.',
    port: () => 51820,
  },
];

const STEPS = [
  ['connect', 'Подключение по SSH'],
  ['check', 'Проверка сервера'],
  ['docker', 'Установка Docker'],
  ['build', 'Сборка контейнера'],
  ['start', 'Запуск'],
  ['client', 'Создание клиента'],
];

// ---------- data ----------

export async function loadHosts() {
  list = await invoke('admin_servers');
  paintCount();
  return list;
}

function paintCount() {
  const el = document.getElementById('navc-hosts');
  if (el) el.textContent = list && list.length ? String(list.length) : '';
}

function redraw() {
  paintCount();
  if (store.page === 'hosts' && store.navigate) store.navigate('hosts', true);
}

function put(view) {
  if (!list) list = [];
  const i = list.findIndex((x) => x.id === view.id);
  if (i >= 0) list[i] = view;
  else list.push(view);
  redraw();
}

/** Run an action on a server; the key marks what shows as busy meanwhile. */
async function work(key, fn) {
  if (pending.has(key)) return undefined;
  pending.add(key);
  redraw();
  try {
    return await fn();
  } catch (e) {
    errorToast(e);
    // the action failed, but the server may still have changed or become unreachable
    await loadHosts().catch(() => {});
    return undefined;
  } finally {
    pending.delete(key);
    redraw();
  }
}

store.adminImported = (views) => views.forEach(put);

listen('admin-progress', (p) => {
  const it = installs.get(p.server);
  if (!it) return;
  const old = it.steps[p.step];
  const moved = !old || old.state !== p.state;
  it.steps[p.step] = { state: p.state, detail: p.detail || (moved ? null : old.detail) };
  if (it.paint) it.paint();
  if (moved) redraw();
});

// ---------- page ----------

export const myServers = {
  id: 'hosts',
  title: 'Мои серверы',
  icon: 'terminal',
  count: () => (list && list.length) || '',
  render(root) {
    const has = list && list.length > 0;
    root.append(pageHead('Мои серверы', [
      has && h('button.btn', { onclick: scanAll }, icon('refresh'), 'Проверить все'),
      h('button.btn.primary', { onclick: () => addDialog() }, icon('plus'), 'Добавить сервер'),
    ], has ? 'ReTunl заходит на сервер по SSH и управляет протоколами, которые поставил AmneziaVPN или он сам. Изменения сразу видны и в AmneziaVPN.' : null));
    if (!list) {
      root.append(h('p.muted', 'Загружаю…'));
      return;
    }
    if (!has) {
      root.append(emptyState());
      return;
    }
    for (const sv of list) root.append(serverCard(sv));
  },
  enter() {
    loadHosts().then(() => {
      redraw();
      if (autoScanned) return;
      autoScanned = true;
      for (const sv of list) if (!sv.scan && !sv.error) scan(sv.id);
    }).catch(errorToast);
  },
  onData() {
    // the VPN servers list does not change this page
  },
};

function emptyState() {
  return h('section.empty',
    h('h2.empty-title', 'Своих серверов пока нет'),
    h('p.empty-text', 'Добавьте VPS, на котором у вас есть root. ReTunl зайдёт на него по SSH, покажет протоколы, которые уже поставил AmneziaVPN, и будет создавать для них клиентов. На чистый сервер ReTunl сам поставит Docker и AmneziaWG, VLESS Reality или WireGuard.'),
    h('div.empty-actions',
      h('button.btn.primary', { onclick: () => addDialog('password') }, icon('terminal'), 'Войти по паролю'),
      h('button.btn', { onclick: () => addDialog('key') }, icon('lock'), 'Войти по SSH-ключу'),
      h('button.btn', { onclick: () => addDialog('amnezia') }, icon('clipboard'), 'Вставить ключ AmneziaVPN')),
    h('p.field-note.empty-foot', 'Ключ AmneziaVPN с полным доступом: в AmneziaVPN откройте сервер, «Поделиться» → «Полный доступ».'));
}

function serverCard(sv) {
  const sc = sv.scan;
  const checking = pending.has('scan:' + sv.id);
  const inst = installs.get(sv.id);
  const addr = sv.user + '@' + sv.host + (sv.port !== 22 ? ':' + sv.port : '');
  const body = [];
  if (inst) body.push(installBanner(sv, inst));
  if (sv.error && !checking) body.push(errorBanner(sv));
  if (sc) {
    if (sc.protocols.length) body.push(h('div.protos', sc.protocols.map((p) => protoBlock(sv, p))));
    else {
      body.push(h('div.panel.host-empty',
        h('p', sc.docker ? 'Протоколов AmneziaVPN на сервере нет.' : 'На сервере нет Docker и протоколов AmneziaVPN. ReTunl поставит Docker вместе с первым протоколом.'),
        !inst && h('button.btn.small.primary', { onclick: () => installDialog(sv) }, icon('plus'), 'Установить протокол')));
    }
  } else if (!sv.error || checking) {
    body.push(h('div.panel.host-empty', h('p.muted', checking ? 'Подключаюсь к серверу…' : 'Сервер ещё не проверяли.')));
  }
  return h('section.group.host',
    h('div.group-head',
      h('div.group-info',
        h('h2.group-title', sv.name),
        h('div.group-meta',
          h('span.selectable', addr),
          sc && sc.os && h('span', sc.os),
          checking ? h('span', 'проверяю…') : sc ? h('span', 'проверен ' + fmtAgo(sc.at)) : null)),
      h('div.group-actions',
        sc && sc.protocols.length > 0 && h('button.btn.small', { disabled: !!(inst && inst.running), onclick: () => installDialog(sv) }, icon('plus'), 'Установить протокол'),
        h('button.btn.small' + (checking ? '.busy' : ''), { disabled: checking, onclick: () => scan(sv.id) }, icon('refresh'), 'Обновить'),
        h('button.icon-btn', {
          'aria-label': 'Действия с сервером «' + sv.name + '»', title: 'Ещё',
          onclick: (e) => popMenu(e.currentTarget, [
            { label: 'Переименовать', icon: 'edit', run: () => renameServer(sv) },
            { label: 'Копировать адрес', icon: 'copy', run: () => copyText(sv.host, 'Адрес скопирован') },
            '-',
            { label: 'Забыть сервер', icon: 'trash', danger: true, run: () => forgetServer(sv) },
          ]),
        }, icon('more', 'dots')))),
    body);
}

function errorBanner(sv) {
  if (sv.error.startsWith(KEY_CHANGED)) {
    const rest = sv.error.slice(KEY_CHANGED.length).replace(/^[.:]\s*/, '');
    return banner('error', KEY_CHANGED, rest.charAt(0).toUpperCase() + rest.slice(1),
      [h('button.btn.small', { onclick: () => trustKey(sv) }, 'Доверять новому ключу')]);
  }
  return banner('error', 'Не удалось проверить сервер', sv.error);
}

function installBanner(sv, it) {
  if (it.running) {
    const cur = STEPS.find(([k]) => it.steps[k] && it.steps[k].state === 'run');
    return banner('info', `Устанавливаю ${it.title}`, cur ? cur[1] + '…' : 'Начинаю…',
      [h('button.btn.small', { onclick: () => progressDialog(sv) }, 'Показать ход')]);
  }
  return banner('error', `${it.title} не установился`, brief(it.error),
    [
      h('button.btn.small', { onclick: () => progressDialog(sv) }, 'Подробнее'),
      h('button.btn.small.ghost', { onclick: () => { installs.delete(sv.id); redraw(); } }, 'Скрыть'),
    ]);
}

function protoBlock(sv, p) {
  const managed = p.kind !== 'other';
  const running = p.state === 'running';
  const stats = p.kind !== 'xray';
  const key = 'proto:' + sv.id + ':' + p.container;
  const working = pending.has(key);
  const where = [
    p.port ? (p.transport ? p.transport.toUpperCase() + ' ' : 'порт ') + p.port : null,
    p.detail,
  ].filter(Boolean);
  let clients;
  if (!managed) clients = h('div.list-empty', 'Клиентами этого протокола ReTunl не управляет: используйте AmneziaVPN.');
  else if (!p.clients) clients = h('div.list-empty', running ? 'Не удалось прочитать список клиентов.' : 'Контейнер остановлен, клиентов не видно.');
  else if (!p.clients.length) clients = h('div.list-empty', 'Клиентов пока нет.');
  else clients = p.clients.map((c) => clientRow(sv, p, c, stats));
  return h('div.panel.proto',
    h('div.proto-head',
      h('div.proto-info',
        h('h3.proto-title', p.title, !running && h('span.tag.warn', STATE[p.state] || p.state)),
        where.length > 0 && h('div.proto-meta', where.map((w) => h('span', w))),
        p.problem && h('div.proto-problem', p.problem)),
      h('div.group-actions',
        managed && running && p.clients && h('button.btn.small' + (working ? '.busy' : ''), {
          disabled: working, onclick: () => newClient(sv, p),
        }, icon('plus'), 'Новый клиент'),
        !running && h('button.btn.small' + (working ? '.busy' : ''), {
          disabled: working, onclick: () => work(key, async () => put(await invoke('admin_start_protocol', { id: sv.id, container: p.container }))),
        }, icon('play'), 'Запустить'),
        h('button.icon-btn', {
          'aria-label': 'Действия с протоколом ' + p.title, title: 'Ещё', disabled: working,
          onclick: (e) => popMenu(e.currentTarget, [
            { label: 'Удалить протокол', icon: 'trash', danger: true, run: () => removeProto(sv, p) },
          ]),
        }, icon('more', 'dots')))),
    h('div.list.cl-list', clients));
}

/** A long multi-line error as one short line. */
function brief(text) {
  const t = text.replace(/\s*\n\s*/g, ' ').trim();
  return t.length > 200 ? t.slice(0, 200) + '…' : t;
}

function created(text) {
  if (!text) return null;
  const d = new Date(text);
  return Number.isNaN(d.getTime()) ? text : d.toLocaleDateString('ru-RU');
}

function clientRow(sv, p, c, stats) {
  const key = 'client:' + sv.id + ':' + p.container + ':' + c.id;
  const working = pending.has(key);
  const online = c.handshake && now() - c.handshake < 180;
  const made = created(c.created);
  return h('div.cl-row' + (working ? '.pending' : ''),
    h('div.cl-main',
      h('span.cl-name', c.name, c.primary && !/^основной/i.test(c.name) && h('span.tag.muted', { title: 'Ключ, которым подключается AmneziaVPN, где этот сервер настраивали' }, 'основной')),
      h('span.cl-meta', c.ip && h('span.selectable', c.ip), made && h('span', 'создан ' + made))),
    stats && h('span.cl-seen' + (online ? '.on' : ''), online ? 'на связи' : c.handshake ? fmtAgo(c.handshake) : 'не подключался'),
    stats && h('span.cl-traffic', { title: 'Скачано клиентом и отправлено им' },
      h('span', icon('down'), fmtBytes(c.tx)), h('span', icon('up'), fmtBytes(c.rx))),
    h('button.icon-btn', {
      'aria-label': 'Действия с клиентом «' + c.name + '»', title: 'Ещё', disabled: working,
      onclick: (e) => popMenu(e.currentTarget, [
        p.kind === 'xray' && { label: 'Показать ключ', icon: 'lock', run: () => showKey(sv, p, c) },
        { label: 'Переименовать', icon: 'edit', run: () => renameClient(sv, p, c) },
        '-',
        { label: 'Удалить клиента', icon: 'trash', danger: true, run: () => removeClient(sv, p, c) },
      ]),
    }, icon('more', 'dots')));
}

// ---------- server actions ----------

async function scan(id) {
  const key = 'scan:' + id;
  if (pending.has(key)) return;
  pending.add(key);
  redraw();
  try {
    put(await invoke('admin_scan', { id }));
  } catch {
    // the error is kept with the server and shown on its card
    await loadHosts().catch(() => {});
  } finally {
    pending.delete(key);
    redraw();
  }
}

function scanAll() {
  for (const sv of list || []) scan(sv.id);
}

async function renameServer(sv) {
  const name = await promptDialog({ title: 'Название сервера', value: sv.name });
  if (!name) return;
  try {
    await invoke('admin_rename', { id: sv.id, name });
    sv.name = name;
    redraw();
  } catch (e) {
    errorToast(e);
  }
}

async function forgetServer(sv) {
  const ok = await confirmDialog({
    title: 'Забыть сервер?',
    text: `ReTunl удалит сохранённый пароль или ключ от «${sv.name}». На самом сервере ничего не изменится, клиенты продолжат работать.`,
    ok: 'Забыть',
  });
  if (!ok) return;
  try {
    await invoke('admin_forget', { id: sv.id });
    list = list.filter((x) => x.id !== sv.id);
    installs.delete(sv.id);
    redraw();
  } catch (e) {
    errorToast(e);
  }
}

async function trustKey(sv) {
  const ok = await confirmDialog({
    title: 'Доверять новому ключу?',
    text: 'Ключ сервера меняется, когда на нём переустанавливают систему. Если вы этого не делали, соединение может перехватывать кто-то другой: тогда не продолжайте и напишите хостеру.',
    ok: 'Доверять новому ключу',
  });
  if (!ok) return;
  try {
    await invoke('admin_trust_key', { id: sv.id });
    await scan(sv.id);
  } catch (e) {
    errorToast(e);
  }
}

// ---------- protocol and client actions ----------

async function newClient(sv, p) {
  const name = await promptDialog({
    title: 'Новый клиент ' + p.title,
    label: 'Имя, по которому вы узнаете клиента в списке',
    placeholder: 'Например, Телефон',
    ok: 'Создать',
  });
  if (!name) return;
  await work('proto:' + sv.id + ':' + p.container, async () => {
    const r = await invoke('admin_client_add', { id: sv.id, container: p.container, name });
    put(r.server);
    if (r.key) keyDialog(r.key, sv);
  });
}

async function removeProto(sv, p) {
  const n = p.clients ? p.clients.length : 0;
  const ok = await confirmDialog({
    title: `Удалить ${p.title}?`,
    text: `Контейнер ${p.container}${n ? ' и ' + plural(n, 'его клиент', 'его клиента', 'его клиентов') : ''} будут удалены с «${sv.name}». Подключения через этот протокол перестанут работать.`,
    ok: 'Удалить протокол',
  });
  if (!ok) return;
  await work('proto:' + sv.id + ':' + p.container, async () => {
    put(await invoke('admin_remove_protocol', { id: sv.id, container: p.container }));
    toast(`${p.title} удалён с «${sv.name}»`);
  });
}

async function showKey(sv, p, c) {
  await work('client:' + sv.id + ':' + p.container + ':' + c.id, async () => {
    keyDialog(await invoke('admin_client_key', { id: sv.id, container: p.container, client: c.id }), sv);
  });
}

async function renameClient(sv, p, c) {
  const name = await promptDialog({ title: 'Имя клиента', value: c.name });
  if (!name || name === c.name) return;
  await work('client:' + sv.id + ':' + p.container + ':' + c.id, async () => {
    put(await invoke('admin_client_rename', { id: sv.id, container: p.container, client: c.id, name }));
  });
}

async function removeClient(sv, p, c) {
  const ok = await confirmDialog({
    title: 'Удалить клиента?',
    text: c.primary
      ? `Это основной ключ ${p.title}: им подключается AmneziaVPN, в котором сервер настраивали. После удаления это подключение перестанет работать.`
      : `«${c.name}» больше не сможет подключаться к ${p.title} на «${sv.name}».`,
    ok: 'Удалить клиента',
  });
  if (!ok) return;
  await work('client:' + sv.id + ':' + p.container + ':' + c.id, async () => {
    put(await invoke('admin_client_remove', { id: sv.id, container: p.container, client: c.id }));
    toast(`Клиент «${c.name}» удалён`);
  });
}

// ---------- the client's key ----------

function qrSvg({ size, bits }) {
  let d = '';
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size;) {
      if (bits[y * size + x] !== '1') { x++; continue; }
      let run = 1;
      while (x + run < size && bits[y * size + x + run] === '1') run++;
      d += `M${x} ${y}h${run}v1h-${run}z`;
      x += run;
    }
  }
  const q = 4; // the quiet zone scanners need
  const full = size + q * 2;
  return s('svg', { viewBox: `${-q} ${-q} ${full} ${full}`, class: 'qr', role: 'img', 'aria-label': 'QR-код с настройками клиента', 'shape-rendering': 'crispEdges' },
    s('rect', { x: -q, y: -q, width: full, height: full, fill: '#fff' }),
    s('path', { d, fill: '#111820' }));
}

const SCAN_APPS = {
  awg: 'AmneziaVPN или AmneziaWG',
  awg_legacy: 'AmneziaVPN или AmneziaWG',
  wireguard: 'WireGuard или AmneziaVPN',
  xray: 'AmneziaVPN, v2rayNG, Hiddify или Streisand',
};

function keyDialog(key, sv) {
  let kept = !key.once;
  const conf = !!key.file_name;
  const copy = h('button.btn', {
    onclick: () => { kept = true; copyText(key.text, conf ? 'Настройки скопированы' : 'Ссылка скопирована'); },
  }, icon('copy'), conf ? 'Копировать' : 'Копировать ссылку');
  const save = conf && h('button.btn', {
    onclick: () => busy(save, async () => {
      try {
        const path = await invoke('admin_save_conf', { name: key.file_name, text: key.text });
        if (path) { kept = true; toast('Файл сохранён', { detail: path }); }
      } catch (e) {
        errorToast(e);
      }
    }),
  }, icon('file'), 'Сохранить .conf');
  const use = h('button.btn', {
    onclick: () => busy(use, async () => {
      try {
        await invoke('admin_use_client', { text: key.text, name: `${sv.name} ${TITLE[key.kind] || ''}`.trim() });
        kept = true;
        await refresh();
        use.replaceChildren(icon('check'), 'Добавлен в «Серверы»');
        setTimeout(() => { use.disabled = true; });
        toast('Сервер добавлен в «Серверы»', { detail: 'Выберите его там, чтобы подключаться через свой сервер.' });
      } catch (e) {
        errorToast(e);
      }
    }),
  }, icon('plug'), `Подключить ${here().this}`);
  const dl = dialog({
    title: `Клиент «${key.name}»`,
    lead: `Настройки для подключения к «${sv.name}».`,
    wide: true,
    body: [
      key.once && banner('warn', 'Сохраните настройки сейчас', 'Сервер хранит только открытую часть ключа WireGuard: после закрытия окна показать эти настройки снова не получится.'),
      h('div.key-grid',
        h('figure.qr-box',
          key.qr ? qrSvg(key.qr) : h('div.qr-none', 'Настройки не помещаются в QR-код. Сохраните файл и откройте его в приложении.'),
          key.qr && h('figcaption', 'Отсканируйте в ' + SCAN_APPS[key.kind])),
        h('div.key-side',
          h('pre.code.key-text.selectable', key.text),
          h('div.inline-actions', copy, save, use))),
    ],
    actions: [h('button.btn.primary', { onclick: () => finish() }, 'Готово')],
  });
  async function finish() {
    if (!kept) {
      const ok = await confirmDialog({
        title: 'Закрыть без сохранения?',
        text: 'Настройки этого клиента больше нигде не сохранились. Чтобы подключить устройство потом, клиента придётся создать заново.',
        ok: 'Закрыть',
      });
      if (!ok) return;
    }
    dl.close();
  }
  // Esc and the close button would lose a key that is shown only once
  dl.el.addEventListener('cancel', (e) => { e.preventDefault(); finish(); });
  const x = dl.el.querySelector('.dlg-head > .icon-btn');
  if (x) x.replaceWith(h('button.icon-btn', { 'aria-label': 'Закрыть', onclick: () => finish() }, icon('close')));
}

// ---------- adding a server ----------

export function addDialog(mode = 'password') {
  let m = mode;
  let n = 0;
  const field = (label, ctl, note) => {
    ctl.id = ctl.id || 'adm-f' + ++n;
    return h('div.field', h('label.field-label', { htmlFor: ctl.id }, label), ctl, note && h('p.field-note', note));
  };
  const f = {
    host: h('input.input.wide', { placeholder: '203.0.113.10', autocomplete: 'off', spellcheck: false }),
    port: h('input.input.num-input', { type: 'number', min: 1, max: 65535, value: '22' }),
    user: h('input.input.wide', { value: 'root', autocomplete: 'off', spellcheck: false }),
    password: h('input.input.wide', { type: 'password', autocomplete: 'off' }),
    key: h('input.input.wide.mono', { readOnly: true, placeholder: 'Файл не выбран' }),
    phrase: h('input.input.wide', { type: 'password', autocomplete: 'off', placeholder: 'Пусто, если у ключа нет пароля' }),
    name: h('input.input.wide', { placeholder: 'Необязательно', maxLength: 64 }),
    link: h('textarea.textarea.mono', { rows: 5, spellcheck: false, placeholder: 'vpn://…' }),
  };
  const pick = h('button.btn', {
    onclick: async () => {
      try {
        const p = await invoke('admin_pick_key');
        if (p) f.key.value = p;
      } catch (e) {
        errorToast(e);
      }
    },
  }, icon('folder'), 'Выбрать…');
  const pwBox = h('div.form-stack', field('Пароль', f.password));
  const keyBox = h('div.form-stack',
    h('div.field', h('label.field-label', { htmlFor: 'adm-key' }, 'Файл закрытого ключа'), h('div.key-pick', Object.assign(f.key, { id: 'adm-key' }), pick)),
    field('Пароль от ключа', f.phrase));
  const sshBox = h('div.form-stack',
    h('div.form-row', h('div.grow', field('Адрес сервера', f.host)), field('Порт SSH', f.port)),
    field('Пользователь', f.user, 'Нужен root или пользователь, которому sudo разрешён без пароля.'),
    pwBox, keyBox,
    field('Название', f.name));
  const amBox = h('div.form-stack',
    field('Ключ AmneziaVPN с полным доступом', f.link, 'В AmneziaVPN откройте сервер, «Поделиться» → «Полный доступ». В таком ключе есть логин и пароль от сервера; обычный ключ для подключения не подойдёт.'));
  const err = h('p.form-error', { hidden: true });
  const paint = () => {
    sshBox.hidden = m === 'amnezia';
    pwBox.hidden = m !== 'password';
    keyBox.hidden = m !== 'key';
    amBox.hidden = m !== 'amnezia';
    err.hidden = true;
  };
  const submit = h('button.btn.primary', { onclick: () => go() }, 'Подключиться');
  const fail = (e) => { err.hidden = false; err.textContent = errText(e); };
  function go() {
    if (m === 'amnezia') {
      const text = f.link.value.trim();
      if (!text) return f.link.focus();
      return busy(submit, async () => {
        try {
          const sum = await invoke('import_text', { text });
          await refresh();
          if (!sum.admin || !sum.admin.length) {
            if (sum.added.length) {
              dl.close();
              reportImport(sum);
              toast('Это ключ для подключения, а не для управления', { kind: 'error', detail: 'Он добавлен в «Серверы». Чтобы управлять сервером, нужен ключ «Полный доступ».', timeout: 10000 });
              return;
            }
            return fail(sum.errors.length ? sum.errors[0].error : 'В тексте нет ключа AmneziaVPN с полным доступом');
          }
          dl.close();
          reportImport(sum);
          store.navigate('hosts');
        } catch (e) {
          fail(e);
        }
      });
    }
    const host = f.host.value.trim();
    if (!host) return f.host.focus();
    const port = Number(f.port.value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return f.port.focus();
    const form = { host, port, user: f.user.value.trim() || 'root', name: f.name.value.trim() || null };
    if (m === 'password') {
      if (!f.password.value) return f.password.focus();
      form.password = f.password.value;
    } else {
      if (!f.key.value) return pick.focus();
      form.key_path = f.key.value;
      form.passphrase = f.phrase.value || null;
    }
    return busy(submit, async () => {
      try {
        const sv = await invoke('admin_add', { form });
        dl.close();
        put(sv);
        const found = sv.scan ? (sv.scan.protocols.length ? 'Найдено: ' + plural(sv.scan.protocols.length, 'протокол', 'протокола', 'протоколов') : 'Протоколов AmneziaVPN на нём нет') : sv.error;
        toast(`Сервер «${sv.name}» добавлен`, { detail: found });
        store.navigate('hosts');
      } catch (e) {
        fail(e);
      }
    });
  }
  for (const el of [f.host, f.port, f.user, f.password, f.phrase, f.name]) {
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  }
  f.link.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.ctrlKey) go(); });
  const dl = dialog({
    title: 'Добавить сервер',
    lead: `Пароль и ключ хранятся только ${here().onThis} в зашифрованном виде и уходят только на сам сервер.`,
    body: [
      seg([
        { value: 'password', label: 'Пароль' },
        { value: 'key', label: 'SSH-ключ' },
        { value: 'amnezia', label: 'Ключ AmneziaVPN' },
      ], m, (v) => { m = v; paint(); (m === 'amnezia' ? f.link : f.host).focus(); }, { label: 'Способ входа', cls: 'add-mode' }),
      sshBox, amBox, err,
    ],
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), submit],
  });
  paint();
  (m === 'amnezia' ? f.link : f.host).focus();
}

// ---------- installing a protocol ----------

function installDialog(sv, prev) {
  const have = new Set((sv.scan ? sv.scan.protocols : []).map((p) => p.container));
  const free = OFFER.filter((o) => !have.has(o.container));
  if (!free.length) {
    toast('На этом сервере уже стоят все протоколы, которые умеет ставить ReTunl');
    return;
  }
  let pick = (prev && free.find((o) => o.kind === prev.kind)) || free[0];
  const port = h('input.input.num-input#inst-port', { type: 'number', min: 1, max: 65535 });
  const site = h('input.input.wide#inst-site', { value: (prev && prev.site) || 'www.googletagmanager.com', spellcheck: false });
  const withClient = h('input', { type: 'checkbox', checked: prev ? !!prev.client : true });
  const clientName = h('input.input#inst-client', { value: (prev && prev.client) || here().This, maxLength: 64, 'aria-label': 'Имя первого клиента' });
  const netNote = h('p.field-note');
  const siteBox = h('div.field.grow',
    h('label.field-label', { htmlFor: 'inst-site' }, 'Сайт для маскировки'),
    site,
    h('p.field-note', 'Чужой сайт с HTTPS и TLS 1.3. Для постороннего глаза соединение будет выглядеть как заход на него.'));
  const err = h('p.form-error', { hidden: true });
  const setPick = (o, keepPort) => {
    pick = o;
    if (!keepPort) port.value = String(o.port());
    netNote.textContent = 'Протокол ' + o.net + (o.kind === 'xray' ? '. Если на 443 уже работает сайт, выберите другой.' : '.');
    siteBox.hidden = o.kind !== 'xray';
  };
  const options = h('div.inst-options', { role: 'radiogroup', 'aria-label': 'Протокол' }, OFFER.map((o) => {
    const taken = have.has(o.container);
    return h('label.match-opt' + (taken ? '.taken' : ''),
      h('input.radio', { type: 'radio', name: 'inst-kind', checked: o === pick, disabled: taken, onchange: () => setPick(o) }),
      h('span', h('span.match-title', o.title, taken && h('span.tag.muted', 'уже установлен')), h('span.match-text', o.text)));
  }));
  setPick(pick, false);
  if (prev && prev.kind === pick.kind) port.value = String(prev.port);
  withClient.addEventListener('change', () => { clientName.disabled = !withClient.checked; });
  clientName.disabled = !withClient.checked;
  const submit = h('button.btn.primary', {
    onclick: () => {
      const p = Number(port.value);
      if (!Number.isInteger(p) || p < 1 || p > 65535) { port.focus(); return; }
      if (pick.kind === 'xray' && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(site.value.trim())) {
        err.hidden = false;
        err.textContent = 'Укажите адрес сайта без https:// и пути, например www.googletagmanager.com';
        site.focus();
        return;
      }
      const client = withClient.checked ? clientName.value.trim() || here().This : null;
      dl.close();
      startInstall(sv, pick, { kind: pick.kind, port: p, site: site.value.trim(), client });
    },
  }, 'Установить');
  const dl = dialog({
    title: 'Установить протокол',
    lead: `На «${sv.name}». Займёт несколько минут: ReTunl поставит Docker, если его нет, соберёт контейнер и запустит его. Потом этим протоколом можно управлять и из AmneziaVPN.`,
    body: [
      options,
      h('div.form-row.inst-fields',
        h('div.field', h('label.field-label', { htmlFor: 'inst-port' }, 'Порт'), port, netNote),
        siteBox),
      h('label.check.inst-client', withClient, 'Сразу создать клиента', clientName),
      err,
    ],
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), submit],
  });
}

async function startInstall(sv, offer, plan) {
  const it = { title: offer.title, plan, steps: {}, client: !!plan.client, running: true, error: null, paint: null, close: null };
  installs.set(sv.id, it);
  redraw();
  progressDialog(sv);
  try {
    const r = await invoke('admin_install', { id: sv.id, kind: plan.kind, port: plan.port, site: plan.kind === 'xray' ? plan.site : null, client: plan.client });
    installs.delete(sv.id);
    if (it.close) it.close();
    put(r.server);
    toast(`${offer.title} установлен на «${sv.name}»`);
    if (r.key) keyDialog(r.key, sv);
  } catch (e) {
    it.running = false;
    it.error = errText(e);
    if (it.paint) it.paint();
    else if (store.page !== 'hosts') {
      toast(`${offer.title} не установился на «${sv.name}»`, { kind: 'error', detail: brief(it.error), action: { label: 'Открыть', run: () => store.navigate('hosts') } });
    }
    redraw();
    loadHosts().then(redraw).catch(() => {});
  }
}

function stepsView(it) {
  const failedAt = it.error && (STEPS.find(([k]) => it.steps[k] && it.steps[k].state === 'run') || STEPS.find(([k]) => !it.steps[k]));
  return h('ol.steps', STEPS.filter(([k]) => k !== 'client' || it.client).map(([k, label]) => {
    const st = it.steps[k] || {};
    let state = st.state || 'wait';
    if (failedAt && failedAt[0] === k) state = 'fail';
    const mark = state === 'done' || state === 'skip' ? icon('check') : state === 'fail' ? icon('close') : null;
    return h('li.step.' + state,
      h('span.step-mark', { 'aria-hidden': 'true' }, mark),
      h('div.step-body',
        h('span.step-label', k === 'docker' && state === 'skip' ? 'Docker уже установлен' : label),
        state === 'run' && st.detail && h('span.step-detail.mono', st.detail)));
  }));
}

function progressDialog(sv) {
  const it = installs.get(sv.id);
  if (!it) return;
  if (it.close) return; // already open
  const box = h('div.inst-progress');
  const foot = h('div.inst-foot');
  let footFor = null;
  const paint = () => {
    box.replaceChildren(...[stepsView(it), it.error && h('pre.code.inst-error.selectable', it.error)].filter(Boolean));
    if (footFor === it.running) return;
    footFor = it.running;
    const lead = dl && dl.el.querySelector('.dlg-lead');
    if (lead) lead.textContent = it.running ? `На «${sv.name}». Окно можно скрыть: установка продолжится.` : `На «${sv.name}».`;
    foot.replaceChildren(...(it.running
      ? [h('button.btn', { onclick: () => dl.close() }, 'Скрыть')]
      : [
        h('button.btn', { onclick: () => { installs.delete(sv.id); dl.close(); redraw(); } }, 'Закрыть'),
        h('button.btn.primary', { onclick: () => { installs.delete(sv.id); dl.close(); redraw(); installDialog(list.find((x) => x.id === sv.id) || sv, it.plan); } }, 'Изменить и повторить'),
      ]));
  };
  const dl = dialog({
    title: `Установка ${it.title}`,
    lead: it.running ? `На «${sv.name}». Окно можно скрыть: установка продолжится.` : `На «${sv.name}».`,
    body: box,
    actions: [foot],
    onClose: () => { it.paint = null; it.close = null; },
  });
  it.paint = paint;
  it.close = () => dl.close();
  paint();
}
