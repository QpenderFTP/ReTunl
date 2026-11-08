// Настройки.

import {
  h, icon, invoke, seg, toggle, pageHead, toast, errorToast, busy, dialog,
} from './lib.js';
import {
  store, S, ST, act, refresh, downloadCore, copyText, isOn, paintCoreBar, importFile, isMac, isAndroid, osName, here,
} from './store.js';
import { exportDialog } from './transfer.js';

const coreBars = { official: null, extended: null };

const patch = (p) => act(() => invoke('update_settings', { patch: p }));

function setRow(label, note, control, id) {
  return h('div.set-row',
    h('div.set-text', h(id ? 'label.set-label' : 'div.set-label', id ? { htmlFor: id } : {}, label), note && h('div.set-note', note)),
    h('div.set-ctl', control));
}

function section(title, rows, lead) {
  return h('section.set-section', h('h2.section-title', title), lead && h('p.section-lead', lead), h('div.panel.set-panel', rows));
}

function num(id, value, min, max, commit) {
  const el = h('input.input.num-input', { id, type: 'number', value: String(value), min: String(min), max: String(max) });
  el.addEventListener('change', () => {
    const v = parseInt(el.value, 10);
    if (Number.isFinite(v) && v >= min && v <= max) commit(v);
    else {
      el.value = String(value);
      toast(`Допустимо от ${min} до ${max}`, { kind: 'error' });
    }
  });
  return el;
}

function text(id, value, commit, attrs = {}) {
  const el = h('input.input', { id, value, ...attrs });
  el.addEventListener('change', () => commit(el.value.trim()));
  el.addEventListener('keydown', (e) => { if (e.key === 'Enter') el.blur(); });
  return el;
}

function dnsControl(id, value, commit) {
  const presets = store.catalog.dns;
  const known = presets.some((p) => p.value === value);
  const sel = h('select.select', { id }, presets.map((p) => h('option', { value: p.value }, p.label)), h('option', { value: '__custom' }, 'Свой адрес…'));
  const custom = h('input.input.mono', { value: known ? '' : value, placeholder: '1.1.1.1, tls://…, https://…/dns-query', hidden: known, 'aria-label': 'Свой адрес DNS' });
  sel.value = known ? value : '__custom';
  sel.addEventListener('change', () => {
    if (sel.value === '__custom') {
      custom.hidden = false;
      custom.focus();
    } else {
      custom.hidden = true;
      commit(sel.value);
    }
  });
  custom.addEventListener('change', () => { if (custom.value.trim()) commit(custom.value.trim()); });
  custom.addEventListener('keydown', (e) => { if (e.key === 'Enter') custom.blur(); });
  return h('div.dns-ctl', sel, custom);
}

function adapterSelect(id, value) {
  const sel = h('select.select', { id }, h('option', { value: '' }, 'Определять автоматически'), value && h('option', { value }, value));
  sel.value = value || '';
  sel.addEventListener('change', () => patch({ direct_interface: sel.value || null }));
  invoke('list_adapters').then((list) => {
    const own = S().tun.interface_name;
    for (const a of list) {
      if (a.name === own || a.name === value || !a.up) continue;
      sel.append(h('option', { value: a.name }, a.description ? `${a.name} (${a.description})` : a.name));
    }
  }).catch(() => {});
  return sel;
}

function getTheme() {
  try { return localStorage.getItem('theme') || 'system'; } catch { return 'system'; }
}

const systemDark = matchMedia('(prefers-color-scheme: dark)');

export function applyTheme(t = getTheme()) {
  const root = document.documentElement;
  if (t === 'light' || t === 'dark') root.dataset.theme = t;
  else delete root.dataset.theme;
  // Android draws its status bar over the page: icons to match the theme
  if (isAndroid()) {
    const dark = t === 'dark' || (t !== 'light' && systemDark.matches);
    invoke('set_system_bars', { dark }).catch(() => { /* old icons stay */ });
  }
}
systemDark.addEventListener('change', () => applyTheme());

export const settingsPage = {
  id: 'settings',
  title: 'Настройки',
  icon: 'settings',
  render(root) {
    const v = store.view;
    const set = S();
    const running = isOn(ST().phase);
    root.append(pageHead('Настройки', [], running ? 'Изменения применяются сразу: подключение перезапустится на пару секунд.' : null));

    const auto = v.autostart;
    let autoNote = 'ReTunl запустится в трее при входе в Windows.';
    if (isMac()) autoNote = 'ReTunl запустится в строке меню при входе в macOS.' + (set.mode === 'tun' && set.connect_on_launch ? ' Для режима «Все программы» macOS спросит пароль администратора.' : '');
    else if (auto.enabled && auto.elevated) autoNote = 'Запускается через планировщик заданий с правами администратора, без запроса Windows.';
    else if (set.run_as_admin && v.elevated) autoNote = 'ReTunl запустится в трее с правами администратора, без запроса Windows.';
    else if (set.run_as_admin) autoNote = 'При входе Windows спросит подтверждение. Чтобы автозапуск обходился без него, запустите ReTunl с правами администратора.';
    else if (set.mode === 'tun') autoNote = 'ReTunl запустится без прав администратора, поэтому режим «Все программы» сам не подключится.';

    let adminNote = 'Права нужны только режиму «Все программы»: при подключении ReTunl предложит перезапуститься с ними.';
    if (set.run_as_admin && v.elevated) adminNote = 'Windows спрашивает подтверждение, когда ReTunl запускают вручную. Автозапуск обходится без него.';
    else if (set.run_as_admin) adminNote = 'Сейчас ReTunl работает без этих прав: запуск не подтвердили. Windows спросит снова при следующем запуске.';

    const phone = isAndroid();
    // Android: always the system VPN, no tray, no autostart, the core is built in
    if (phone) {
      root.append(section('Подключение', [
        setRow('Подключаться при запуске ReTunl', null, toggle(set.connect_on_launch, (on) => patch({ connect_on_launch: on }), { id: 'set-col' }), 'set-col'),
      ], 'ReTunl работает как VPN Android: весь трафик телефона проходит через него, а правила решают, что идёт через сервер.'));
    } else root.append(section('Подключение', [
      setRow('Что перехватывать',
        set.mode === 'tun'
          ? (isMac() ? 'Все программы — через виртуальный адаптер. macOS спрашивает пароль администратора при каждом подключении.' : 'Все программы — через виртуальный адаптер, нужны права администратора.')
          : `Системный прокси ${osName()}. Его учитывают браузеры и многие программы, но не игры.`,
        seg([{ value: 'tun', label: 'Все программы' }, { value: 'system_proxy', label: 'Системный прокси' }], set.mode,
          (m) => patch({ mode: m }), { label: 'Что перехватывать' })),
      setRow('Подключаться при запуске ReTunl', null, toggle(set.connect_on_launch, (on) => patch({ connect_on_launch: on }), { id: 'set-col' }), 'set-col'),
      isMac() ? null : setRow('Запускать с правами администратора', adminNote, toggle(set.run_as_admin, (on) => patch({ run_as_admin: on }), { id: 'set-admin' }), 'set-admin'),
      setRow(`Запускать вместе с ${osName()}`, autoNote, toggle(auto.enabled, async (on) => {
        try {
          await invoke('set_autostart', { enabled: on });
        } catch (e) {
          errorToast(e);
        }
        refresh();
      }, { id: 'set-auto' }), 'set-auto'),
      setRow('При автозапуске сразу в трей', 'Окно не показывается, ReTunl ждёт в области уведомлений.', toggle(set.start_minimized, (on) => patch({ start_minimized: on }), { id: 'set-min' }), 'set-min'),
      setRow('Крестик сворачивает в трей', 'Если выключить, закрытие окна отключит VPN и завершит программу.', toggle(set.close_to_tray, (on) => patch({ close_to_tray: on }), { id: 'set-tray' }), 'set-tray'),
    ].filter(Boolean)));

    root.append(section('Маршрутизация', [
      setRow('Локальная сеть мимо VPN', 'Роутер, принтеры, общие папки и другие устройства дома.', toggle(set.bypass_lan, (on) => patch({ bypass_lan: on }), { id: 'set-lan' }), 'set-lan'),
      setRow('Узнавать сайт по соединению', 'Нужно для правил по сайтам, когда программа подключается сразу по IP-адресу. Обычно не выключают.', toggle(set.sniff, (on) => patch({ sniff: on }), { id: 'set-sniff' }), 'set-sniff'),
      setRow('IPv6', 'Включайте, если IPv6 поддерживают и провайдер, и VPN-сервер.', toggle(set.ipv6, (on) => patch({ ipv6: on }), { id: 'set-ipv6' }), 'set-ipv6'),
      phone ? null : setRow('Сетевая карта для прямого трафика', 'Автоматически — та, через которую сейчас работает интернет.', adapterSelect('set-iface', set.direct_interface), 'set-iface'),
    ].filter(Boolean)));

    root.append(section('DNS', [
      setRow('Для прямых соединений', 'Им же определяются адреса VPN-серверов.', dnsControl('set-dns-d', set.dns.direct, (x) => patch({ dns: { direct: x } })), 'set-dns-d'),
      setRow('Через VPN', 'Для сайтов, которые идут через VPN: провайдер не видит запросов.', dnsControl('set-dns-r', set.dns.remote, (x) => patch({ dns: { remote: x } })), 'set-dns-r'),
      setRow('Сайты без правила', '«Авто» — через VPN, если всё остальное идёт через VPN, иначе напрямую.',
        seg([{ value: 'auto', label: 'Авто' }, { value: 'remote', label: 'Через VPN' }, { value: 'direct', label: 'Напрямую' }], set.dns.policy,
          (p) => patch({ dns: { policy: p } }), { label: 'DNS для сайтов без правила' })),
    ]));

    root.append(section(phone ? 'VPN' : 'Виртуальный адаптер', [
      phone ? null : setRow('Строгая маршрутизация', 'Не даёт программам обходить адаптер и защищает от утечек DNS. Если с ней не открываются сайты, которые идут напрямую, или перестал работать локальный сервис — выключите.', toggle(set.tun.strict_route, (on) => patch({ tun: { strict_route: on } }), { id: 'set-strict' }), 'set-strict'),
      setRow('Сетевой стек', 'Смешанный подходит почти всем. gVisor надёжнее с некоторыми антивирусами, системный быстрее.',
        (() => {
          const sel = h('select.select', { id: 'set-stack' },
            h('option', { value: 'mixed' }, 'Смешанный'), h('option', { value: 'system' }, 'Системный'), h('option', { value: 'gvisor' }, 'gVisor'));
          sel.value = set.tun.stack;
          sel.addEventListener('change', () => patch({ tun: { stack: sel.value } }));
          return sel;
        })(), 'set-stack'),
      setRow('MTU', 'Размер пакета. Уменьшите до 1400, если сайты открываются через раз.', num('set-mtu', set.tun.mtu, 1280, 65535, (x) => patch({ tun: { mtu: x } })), 'set-mtu'),
      // macOS names tunnels itself (utun…)
      isMac() || phone ? null : setRow('Имя адаптера', 'Так он называется в сетевых подключениях Windows.', text('set-ifname', set.tun.interface_name, (x) => x && patch({ tun: { interface_name: x } }), { maxLength: 32 }), 'set-ifname'),
    ].filter(Boolean)));

    root.append(section('Порты', [
      phone ? null : setRow('Порт прокси', 'В режиме «Системный прокси» программы подключаются к 127.0.0.1 на этот порт.', num('set-mixed', set.mixed_port, 1024, 65535, (x) => patch({ mixed_port: x })), 'set-mixed'),
      setRow('Порт управления ядром', `Доступен только ${here().onThis.replace('на ', 'с ')}.`, num('set-ctl', set.controller_port, 1024, 65535, (x) => patch({ controller_port: x })), 'set-ctl'),
    ].filter(Boolean)));

    const coreRow = (kind, title, path, note) => {
      const bar = h('div.progress', { hidden: true }, h('div.progress-bar'));
      coreBars[kind] = bar;
      const btn = h('button.btn.small', { onclick: () => downloadCore(btn, kind) }, icon('down'), path ? 'Скачать заново' : 'Скачать ядро');
      const row = setRow(title, note, h('div.ctl-stack', btn, bar));
      queueMicrotask(() => paintCoreBar(bar, kind));
      return row;
    };
    const lxNeeded = Object.values(v.core.needs || {}).includes('extended');
    const corePref = seg([
      { value: 'auto', label: 'Авто', title: 'sing-box-lx, только если без него сервер не заработает' },
      { value: 'official', label: 'sing-box' },
      { value: 'extended', label: 'sing-box-lx', disabled: !v.core.lx_path },
    ], set.core || 'auto', (c) => patch({ core: c }), { label: 'Какое ядро запускать' });
    const rsBtn = h('button.btn.small', {
      onclick: () => busy(rsBtn, async () => {
        try {
          const n = await invoke('update_rule_sets');
          toast(n ? `Списки обновлены: ${n}` : 'Правила не используют готовые списки');
        } catch (e) {
          errorToast(e);
        }
      }),
    }, icon('refresh'), 'Обновить');
    const level = h('select.select', { id: 'set-log' },
      h('option', { value: 'error' }, 'Только ошибки'), h('option', { value: 'warn' }, 'Предупреждения'),
      h('option', { value: 'info' }, 'Обычный'), h('option', { value: 'debug' }, 'Подробный'), h('option', { value: 'trace' }, 'Всё подряд'));
    level.value = set.log_level;
    level.addEventListener('change', () => patch({ log_level: level.value }));
    root.append(section('Ядро и списки', [
      phone ? setRow(`Ядро sing-box-lx ${v.core.lx_expected}`, 'Встроено в приложение: AmneziaWG, XHTTP и всё, что умеет официальный sing-box.', null) : null,
      phone ? null : coreRow('official', `Ядро sing-box ${v.core.expected}`, v.core.path,
        v.core.path || 'Не найдено. Скачивается с GitHub проекта SagerNet.'),
      phone ? null : coreRow('extended', `Ядро sing-box-lx ${v.core.lx_expected}`, v.core.lx_path,
        h('span', 'Сторонняя сборка sing-box от Leadaxe: добавляет AmneziaWG 3.1 и транспорт XHTTP. ',
          v.core.lx_path ? h('span.mono', v.core.lx_path) : lxNeeded ? h('b', 'Нужна для ваших серверов AmneziaWG или XHTTP.') : 'Не скачана.')),
      phone ? null : setRow('Какое ядро запускать',
        '«Авто» берёт sing-box-lx, только когда без него не обойтись или в серверах AmneziaWG есть параметры, которые официальное ядро пропустит.',
        corePref),
      setRow('Списки сайтов и адресов', 'Обновляются сами раз в три дня. Кнопка скачивает их заново прямо сейчас.', rsBtn),
      setRow('Адрес для проверки задержки', 'Запрос к нему через сервер показывает время ответа.', text('set-test', set.test_url, (x) => x && patch({ test_url: x }), { spellcheck: false, class: 'mono' }), 'set-test'),
      setRow('Подробность журнала', null, level, 'set-log'),
    ].filter(Boolean)));

    root.append(section(`Перенос ${here().toOther}`, [
      setRow('Экспорт', 'Подписки, серверы, правила и ваши шаблоны в файле или тексте, зашифрованном паролем. Можно выбрать, какие подписки взять.',
        h('button.btn.small', { onclick: exportDialog }, icon('lock'), 'Экспортировать…')),
      setRow('Импорт', 'Откройте файл .retunl или вставьте текст экспорта на вкладке «Серверы» — ReTunl спросит пароль и покажет, что внутри.',
        h('button.btn.small', { onclick: importFile }, icon('file'), 'Открыть файл…')),
    ]));

    root.append(section('Программа', [
      setRow('Оформление', null, seg([{ value: 'system', label: `Как в ${osName()}` }, { value: 'light', label: 'Светлое' }, { value: 'dark', label: 'Тёмное' }], getTheme(), (t) => {
        try { localStorage.setItem('theme', t); } catch { /* private mode */ }
        applyTheme(t);
      }, { label: 'Оформление' })),
      phone ? null : setRow('Папка с данными', v.portable ? `${v.data_dir} — портативный режим, всё хранится рядом с программой.` : v.data_dir,
        h('button.btn.small', { onclick: () => invoke('open_data_dir') }, icon('folder'), 'Открыть')),
      setRow('Конфигурация sing-box', 'То, что получит ядро при подключении. Полезно, если что-то идёт не так.',
        h('button.btn.small', { onclick: showConfig }, icon('file'), 'Показать')),
      setRow(`ReTunl ${v.version}`, phone ? 'Выход отключает VPN и закрывает приложение.' : isMac() ? 'Права администратора спрашиваются только для режима «Все программы».' : v.elevated ? 'Запущен с правами администратора.' : 'Запущен без прав администратора.',
        h('button.btn.small.danger', { onclick: () => invoke('quit_app') }, icon('power'), 'Выйти')),
    ].filter(Boolean)));
  },
  onCore() {
    paintCoreBar(coreBars.official, 'official');
    paintCoreBar(coreBars.extended, 'extended');
  },
};

async function showConfig() {
  let cfg;
  try {
    cfg = await invoke('preview_config');
  } catch (e) {
    errorToast(e);
    return;
  }
  const dl = dialog({
    title: 'Конфигурация sing-box',
    lead: 'Ключ доступа к ядру скрыт. Остальное — ровно то, что будет запущено.',
    wide: true,
    body: h('pre.code.selectable', cfg),
    actions: [
      h('button.btn', { onclick: () => copyText(cfg, 'Конфигурация скопирована') }, icon('copy'), 'Копировать'),
      h('button.btn.primary', { onclick: () => dl.close() }, 'Закрыть'),
    ],
  });
}
