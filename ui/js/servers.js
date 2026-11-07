// Серверы: import, subscriptions, latency, the active server.

import {
  h, icon, invoke, busy, toast, errorToast, errText, dialog, confirmDialog, promptDialog, popMenu,
  pageHead, fmtAgo, fmtBytes, fmtDate, now, plural, banner,
} from './lib.js';
import {
  store, D, S, act, refresh, protoParts, addressOf, importText, importClipboard, importFile, copyText,
  reportImport, coreNeed, hasLx, downloadCore, paintCoreBar, isAndroid, scanQr,
} from './store.js';
import { exportDialog } from './transfer.js';

let pasteHandler = null;
let lxBar = null;

export const servers = {
  id: 'servers',
  title: 'Серверы',
  icon: 'servers',
  count: () => D().profiles.length || '',
  render(root) {
    const d = D();
    const has = d.profiles.length > 0;
    root.append(pageHead('Серверы', [
      has && h('button.btn', { onclick: (e) => testLatency(e.currentTarget, null) }, icon('speed'), 'Проверить задержку'),
      d.subscriptions.length > 0 && h('button.btn', { onclick: (e) => updateAll(e.currentTarget) }, icon('refresh'), 'Обновить подписки'),
      has && h('button.btn', { onclick: exportDialog, title: 'Зашифровать выбранные подписки и серверы паролем, чтобы перенести на другой компьютер' }, icon('lock'), 'Экспорт'),
      h('button.btn.primary', { onclick: addDialog }, icon('plus'), 'Добавить'),
    ], has ? `Выбранный сервер используется для правил «Через VPN».${isAndroid() ? '' : ' Ссылку или файл можно просто перетащить в окно.'}` : null));
    lxBar = null;
    if (!hasLx() && d.profiles.some((p) => coreNeed(p) === 'extended')) {
      lxBar = h('div.progress', { hidden: true }, h('div.progress-bar'));
      const b = banner('warn', 'Для части серверов нужно ядро sing-box-lx',
        `Официальный sing-box не запускает AmneziaWG 3.1 и XHTTP. sing-box-lx ${store.view.core.lx_expected} — сторонняя сборка от Leadaxe, ReTunl скачает её с GitHub и проверит контрольную сумму.`,
        [h('button.btn.small.primary', { onclick: (e) => downloadCore(e.currentTarget, 'extended') }, icon('down'), 'Скачать sing-box-lx')]);
      b.append(lxBar);
      root.append(b);
      queueMicrotask(() => paintCoreBar(lxBar, 'extended'));
    }
    if (!has && !d.subscriptions.length) {
      root.append(emptyState());
    } else {
      const manual = d.profiles.filter((p) => !p.subscription);
      if (manual.length) root.append(group(null, manual));
      for (const sub of d.subscriptions) root.append(group(sub, d.profiles.filter((p) => p.subscription === sub.id)));
    }
    attachDrop(root);
  },
  enter() {
    pasteHandler = (e) => {
      if (e.target.closest && e.target.closest('input, textarea, dialog')) return;
      const text = e.clipboardData && e.clipboardData.getData('text/plain');
      if (text && text.trim()) {
        e.preventDefault();
        importText(text);
      }
    };
    document.addEventListener('paste', pasteHandler);
  },
  leave() {
    document.removeEventListener('paste', pasteHandler);
  },
  onCore() {
    paintCoreBar(lxBar, 'extended');
  },
};

function emptyState() {
  return h('section.empty.drop',
    h('h2.empty-title', 'Серверов пока нет'),
    h('p.empty-text', 'Добавьте ссылку на сервер VLESS, VMess, Trojan, Shadowsocks, Hysteria, TUIC, WireGuard, AmneziaWG, SOCKS или AnyTLS, ключ AmneziaVPN (vpn://), адрес подписки или файл WireGuard и AmneziaWG.'
      + (isAndroid() ? ' Ссылку можно скопировать или показать QR-кодом.' : ' Файл можно перетащить сюда, а ссылку — вставить сочетанием Ctrl+V.')),
    h('div.empty-actions',
      h('button.btn.primary', { onclick: importClipboard }, icon('clipboard'), 'Вставить из буфера'),
      isAndroid() && h('button.btn', { onclick: scanQr }, icon('qr'), 'Сканировать QR-код'),
      h('button.btn', { onclick: addDialog }, icon('plus'), 'Ввести ссылку или подписку'),
      h('button.btn', { onclick: importFile }, icon('file'), 'Открыть файл…'),
      !isAndroid() && h('button.btn', { onclick: adapterDialog }, icon('plug'), 'Через другой VPN-клиент')));
}

function group(sub, list) {
  return h('section.group',
    sub ? subHead(sub) : h('div.group-head', h('div.group-info', h('h2.group-title', 'Добавлены вручную'))),
    h('div.panel.list', list.length ? list.map(row) : h('div.list-empty', 'В подписке нет серверов, которые понимает sing-box.')));
}

function subHead(sub) {
  const i = sub.info || {};
  const used = (i.upload || 0) + (i.download || 0);
  const expired = i.expire && i.expire < now();
  const updating = store.subUpdating.has(sub.id);
  return h('div.group-head',
    h('div.group-info',
      h('h2.group-title', sub.name),
      h('div.group-meta',
        h('span', updating ? 'обновляется…' : 'обновлена ' + fmtAgo(sub.updated_at)),
        i.total ? h('span', `${fmtBytes(used)} из ${fmtBytes(i.total)}`) : used ? h('span', 'израсходовано ' + fmtBytes(used)) : null,
        i.expire ? h('span' + (expired ? '.bad' : ''), (expired ? 'истекла ' : 'действует до ') + fmtDate(i.expire)) : null),
      i.total ? h('div.meter', { title: `Израсходовано ${Math.round((used / i.total) * 100)}%` },
        h('div.meter-bar', { style: { width: Math.min(100, (used / i.total) * 100) + '%' } })) : null,
      sub.last_error && h('div.group-error', 'Последнее обновление не удалось: ' + sub.last_error)),
    h('div.group-actions',
      h('button.btn.small', { onclick: (e) => updateSub(e.currentTarget, sub) }, icon('refresh'), 'Обновить'),
      h('button.icon-btn', {
        'aria-label': 'Действия с подпиской', title: 'Ещё',
        onclick: (e) => popMenu(e.currentTarget, [
          { label: 'Переименовать', icon: 'edit', run: () => renameSub(sub) },
          { label: 'Копировать адрес подписки', icon: 'copy', run: () => copyText(sub.url, 'Адрес подписки скопирован') },
          '-',
          { label: 'Удалить подписку', icon: 'trash', danger: true, run: () => removeSub(sub) },
        ]),
      }, icon('more', 'dots'))));
}

function latencyEl(lat) {
  if (!lat) return h('span.lat.none', { title: 'Задержку ещё не проверяли' }, '—');
  if (lat.ms === null || lat.ms === undefined) return h('span.lat.bad', { title: lat.error || '' }, 'нет ответа');
  return h('span.lat' + (lat.ms > 600 ? '.slow' : ''), { title: 'Время ответа через этот сервер' }, `${lat.ms} мс`);
}

function row(p) {
  const active = S().active_profile === p.id;
  const { base, extra } = protoParts(p);
  const id = 'srv-' + p.id;
  return h('div.srv-row' + (active ? '.active' : ''),
    h('input.radio', {
      type: 'radio', name: 'active-server', id, checked: active,
      onchange: () => act(() => invoke('set_active', { id: p.id })),
    }),
    h('label.srv-main', { htmlFor: id },
      h('span.srv-name', p.name),
      h('span.srv-meta', h('span.srv-proto', base), extra && h('span', extra), h('span.srv-addr', addressOf(p)),
        coreNeed(p) === 'extended' && !hasLx() ? h('span.tag.warn', { title: 'Официальный sing-box не умеет этот сервер' }, 'нужно ядро sing-box-lx') : null)),
    latencyEl(store.view.latency[p.id]),
    h('button.icon-btn.srv-test', {
      'aria-label': 'Проверить задержку «' + p.name + '»', title: 'Проверить задержку',
      onclick: (e) => testLatency(e.currentTarget, [p.id]),
    }, icon('speed')),
    h('button.icon-btn', {
      'aria-label': 'Действия с сервером «' + p.name + '»', title: 'Ещё',
      onclick: (e) => { const more = e.currentTarget; popMenu(more, [
        { label: 'Проверить задержку', icon: 'speed', run: () => testLatency(more, [p.id]) },
        { label: 'Переименовать', icon: 'edit', run: () => renameProfile(p) },
        { label: 'Настройки sing-box (JSON)', icon: 'file', run: () => editJson(p) },
        p.link && { label: 'Копировать ссылку', icon: 'copy', run: () => copyText(p.link, 'Ссылка скопирована') },
        '-',
        { label: 'Удалить', icon: 'trash', danger: true, run: () => removeProfile(p) },
      ]); },
    }, icon('more', 'dots')));
}

// ---------- actions ----------

async function testLatency(btn, ids) {
  await busy(btn, async () => {
    try {
      const res = await invoke('test_latency', { ids });
      Object.assign(store.view.latency, res);
      await refresh();
      if (!ids) {
        const ok = Object.values(res).filter((l) => l.ms != null).length;
        toast(`Отвечают ${ok} из ${Object.keys(res).length}`);
      }
    } catch (e) {
      errorToast(e);
    }
  });
}

async function updateSub(btn, sub) {
  await busy(btn, async () => {
    try {
      const sum = await invoke('update_subscription', { id: sub.id });
      await refresh();
      toast(`Подписка «${sub.name}» обновлена`, { detail: plural(sum.names.length, 'сервер', 'сервера', 'серверов') });
    } catch (e) {
      errorToast(e);
      await refresh();
    }
  });
}

async function updateAll(btn) {
  await busy(btn, async () => {
    try {
      const errors = await invoke('update_all_subscriptions');
      await refresh();
      if (errors.length) toast('Не все подписки обновились', { kind: 'error', detail: errors.join('\n') });
      else toast('Подписки обновлены');
    } catch (e) {
      errorToast(e);
    }
  });
}

async function renameSub(sub) {
  const name = await promptDialog({ title: 'Название подписки', value: sub.name });
  if (name) act(() => invoke('rename_subscription', { id: sub.id, name }));
}

async function removeSub(sub) {
  const n = D().profiles.filter((p) => p.subscription === sub.id).length;
  const ok = await confirmDialog({
    title: 'Удалить подписку?',
    text: `Подписка «${sub.name}» и ${plural(n, 'её сервер', 'её сервера', 'её серверов')} будут удалены. Правила, которые вели на эти серверы, переключатся на выбранный сервер.`,
    ok: 'Удалить подписку',
  });
  if (ok) act(() => invoke('delete_subscription', { id: sub.id }));
}

async function renameProfile(p) {
  const name = await promptDialog({ title: 'Название сервера', value: p.name });
  if (name) act(() => invoke('rename_profile', { id: p.id, name }));
}

async function removeProfile(p) {
  const ok = await confirmDialog({
    title: 'Удалить сервер?',
    text: p.subscription
      ? `«${p.name}» пропадёт из списка, но вернётся при следующем обновлении подписки.`
      : `«${p.name}» будет удалён. Правила, которые вели на него, переключатся на выбранный сервер.`,
  });
  if (!ok) return;
  const fixed = await act(() => invoke('delete_profiles', { ids: [p.id] }));
  if (fixed) toast(`Правил переключено на выбранный сервер: ${fixed}`);
}

function editJson(p) {
  const ta = h('textarea.textarea.mono.code', { rows: 18, spellcheck: false, value: JSON.stringify(p.outbound, null, 2) });
  const err = h('p.form-error', { hidden: true });
  const save = h('button.btn.primary', {
    onclick: () => busy(save, async () => {
      try {
        await invoke('set_profile_json', { id: p.id, json: ta.value });
        dl.close();
        await refresh();
        toast('Настройки сервера сохранены');
      } catch (e) {
        err.hidden = false;
        err.textContent = errText(e);
      }
    }),
  }, 'Сохранить');
  const dl = dialog({
    title: `Настройки «${p.name}»`,
    lead: 'Это outbound sing-box без поля tag. Здесь можно поправить то, чего нет в ссылке.',
    wide: true,
    body: [ta, err],
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), save],
  });
}

export function addDialog() {
  const ta = h('textarea.textarea.mono#add-text', {
    rows: 7, spellcheck: false,
    placeholder: 'vless://…\nhy2://…\nvpn://… (ключ AmneziaVPN)\nhttps://… (адрес подписки)\nили содержимое файла WireGuard или AmneziaWG .conf',
  });
  const err = h('p.form-error', { hidden: true });
  const submit = h('button.btn.primary', {
    onclick: () => {
      const text = ta.value.trim();
      if (!text) { ta.focus(); return; }
      busy(submit, async () => {
        try {
          const sum = await invoke('import_text', { text });
          dl.close();
          await refresh();
          reportImport(sum);
        } catch (e) {
          err.hidden = false;
          err.textContent = errText(e);
        }
      });
    },
  }, 'Добавить');
  ta.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.ctrlKey) submit.click(); });
  const dl = dialog({
    title: 'Добавить серверы',
    lead: 'Ссылки на серверы, адрес подписки, конфигурация WireGuard или AmneziaWG, файл экспорта ReTunl. Каждая ссылка — с новой строки.',
    body: [
      ta, err,
      h('div.add-alt',
        h('span.add-alt-label', 'Или'),
        h('button.btn.small', { onclick: () => { dl.close(); importClipboard(); } }, icon('clipboard'), 'Вставить из буфера'),
        isAndroid() && h('button.btn.small', { onclick: () => { dl.close(); scanQr(); } }, icon('qr'), 'Сканировать QR-код'),
        h('button.btn.small', { onclick: () => { dl.close(); importFile(); } }, icon('file'), 'Открыть файл…'),
        !isAndroid() && h('button.btn.small', { onclick: () => { dl.close(); adapterDialog(); } }, icon('plug'), 'Через другой VPN-клиент')),
    ],
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), submit],
  });
}

export async function adapterDialog() {
  const list = h('div.adapter-list', h('p.muted', 'Ищу сетевые адаптеры…'));
  const dl = dialog({
    title: 'Через другой VPN-клиент',
    lead: 'Если подключён другой VPN (AmneziaVPN, OpenVPN, Tailscale), ReTunl может отправлять выбранный трафик через его адаптер. Пока ReTunl работает, тот клиент должен оставаться подключённым.',
    body: list,
  });
  let ads;
  try {
    ads = await invoke('list_adapters');
  } catch (e) {
    list.replaceChildren(h('p.form-error', errText(e)));
    return;
  }
  const own = S().tun.interface_name;
  ads = ads.filter((a) => a.name !== own);
  ads.sort((a, b) => (b.tunnel - a.tunnel) || (b.up - a.up) || a.name.localeCompare(b.name, 'ru'));
  if (!ads.length) {
    list.replaceChildren(h('p.muted', 'Подходящих адаптеров не нашлось.'));
    return;
  }
  list.replaceChildren(...ads.map((a) => {
    const btn = h('button.btn.small', {
      onclick: () => busy(btn, async () => {
        try {
          await invoke('add_interface', { name: a.name });
          dl.close();
          await refresh();
          toast(`Адаптер «${a.name}» добавлен в серверы`);
        } catch (e) {
          errorToast(e);
        }
      }),
    }, 'Выбрать');
    const addrs = a.addresses.filter((x) => !x.startsWith('fe80') && !x.startsWith('169.254'));
    return h('div.adapter' + (a.up ? '' : '.down'),
      h('div.adapter-main',
        h('div.adapter-name', a.name, a.tunnel && h('span.tag', 'похоже на VPN'), !a.up && h('span.tag.muted', 'отключён')),
        h('div.adapter-desc', a.description),
        h('div.adapter-addr', addrs.join(', ') || 'нет адресов')),
      btn);
  }));
}

function attachDrop(el) {
  const hasPayload = (e) => [...(e.dataTransfer?.types || [])].some((t) => t === 'Files' || t === 'text/plain');
  el.addEventListener('dragover', (e) => {
    if (!hasPayload(e) || e.dataTransfer.types.includes('text/x-rule')) return;
    e.preventDefault();
    el.classList.add('dropping');
  });
  el.addEventListener('dragleave', (e) => { if (!el.contains(e.relatedTarget)) el.classList.remove('dropping'); });
  el.addEventListener('drop', async (e) => {
    e.preventDefault();
    el.classList.remove('dropping');
    const files = [...e.dataTransfer.files];
    if (files.length) {
      for (const f of files) {
        if (f.size > 4 * 1024 * 1024) { toast(`«${f.name}» слишком большой для конфигурации`, { kind: 'error' }); continue; }
        await importText(await f.text());
      }
    } else {
      const t = e.dataTransfer.getData('text/plain');
      if (t.trim()) importText(t);
    }
  });
}
