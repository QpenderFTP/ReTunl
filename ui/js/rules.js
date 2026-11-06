// Правила: ordered list (first match wins), the rule editor and templates.

import {
  h, s, icon, invoke, busy, toast, errorToast, errText, dialog, confirmDialog, popMenu, pageHead, seg, plural,
} from './lib.js';
import {
  store, D, S, act, refresh, routeChip, routePicker, appIcon, appLabel, iconPath, loadIcons, ensureProcIndex, isMac,
} from './store.js';

const PUNY = { 'xn--p1ai': 'рф', 'xn--d1acj3b': 'дети', 'xn--80asehdb': 'онлайн', 'xn--p1acf': 'рус' };
const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?|[0-9a-f]*:[0-9a-f:]*:[0-9a-f:]*(\/\d{1,3})?)$/i;
const SET_RE = /^(geosite|geoip)-[\w!.@-]+$/i;

export const rules = {
  id: 'rules',
  title: 'Правила',
  icon: 'rules',
  count: () => D().rules.filter((r) => r.enabled).length || '',
  render(root) {
    const d = D();
    root.append(pageHead('Правила', [
      h('button.btn', { onclick: gallery }, icon('list'), 'Шаблоны'),
      h('button.btn.primary', { onclick: () => openRuleEditor() }, icon('plus'), 'Новое правило'),
    ], 'Правила проверяются сверху вниз: соединение идёт по первому подходящему. Порядок меняется перетаскиванием за ручку слева.'));
    if (!d.rules.length) root.append(quickStart());
    const list = h('ol.rule-list', { 'aria-label': 'Правила по порядку' }, d.rules.map(ruleRow));
    if (d.rules.length) {
      root.append(list);
      enableReorder(list);
    }
    root.append(finalCard(d.rules.length));
    loadRuleIcons();
  },
  onIcons() {
    for (const el of document.querySelectorAll('.page-rules [data-app]')) {
      const fresh = appIcon(el.dataset.app);
      fresh.dataset.app = el.dataset.app;
      if (fresh.tagName === 'IMG') el.replaceWith(fresh);
    }
  },
};

async function loadRuleIcons() {
  const apps = D().rules.flatMap((r) => r.apps);
  if (!apps.length) return;
  if (apps.some((a) => !/[\\/]/.test(a))) await ensureProcIndex();
  loadIcons(apps.map(iconPath).filter(Boolean));
}

// ---------- list ----------

function setLabel(tag) {
  const e = store.catalog.rule_sets.find((x) => x.tag === tag);
  if (e) return e.label;
  if (/^https?:/i.test(tag)) return 'свой список';
  return tag.replace(/^(geosite|geoip)-/, '');
}

const domainLabel = (d) => PUNY[d] || d;

function listOf(items, max) {
  return items.length <= max ? items.join(', ') : `${items.slice(0, max).join(', ')} и ещё ${items.length - max}`;
}

export function ruleSummary(r) {
  const parts = [];
  if (r.apps.length) {
    const icons = r.apps.slice(0, 4).map((a) => {
      const el = appIcon(a);
      el.dataset.app = a;
      return el;
    });
    parts.push(h('span.sum-apps', h('span.sum-icons', icons), h('span', listOf(r.apps.map(appLabel), 3))));
  }
  const dest = [];
  if (r.domains.length) dest.push(r.domains.length <= 3 ? r.domains.map(domainLabel).join(', ') : plural(r.domains.length, 'домен', 'домена', 'доменов'));
  if (r.ips.length) dest.push(r.ips.length <= 2 ? r.ips.join(', ') : plural(r.ips.length, 'подсеть', 'подсети', 'подсетей'));
  if (r.rule_sets.length) dest.push(listOf(r.rule_sets.map(setLabel), 2));
  if (dest.length) parts.push(h('span.sum-dest', r.apps.length ? h('span.sum-join', r.match_all ? 'и' : 'или') : null, dest.join(', ')));
  if (r.ports.length) parts.push(h('span', (r.ports.length > 1 ? 'порты ' : 'порт ') + r.ports.join(', ')));
  if (r.network) parts.push(h('span', 'только ' + r.network.toUpperCase()));
  return parts.length ? parts : h('span', 'без условий');
}

function ruleRow(r, i) {
  const total = D().rules.length;
  return h('li.rule-row' + (r.enabled ? '' : '.off'), { data: { id: r.id } },
    h('span.grip', { title: 'Перетащите, чтобы изменить порядок' }, icon('grip', 'dots')),
    h('span.rule-num', String(i + 1)),
    h('input.switch', {
      type: 'checkbox', role: 'switch', checked: r.enabled, 'aria-label': `Правило «${r.name}» включено`,
      onchange: (e) => act(() => invoke('set_rule_enabled', { id: r.id, enabled: e.target.checked })),
    }),
    h('button.rule-main', { id: 'rule-' + r.id, onclick: () => openRuleEditor(r), title: 'Изменить правило' },
      h('span.rule-name', r.name),
      h('span.rule-sum', ruleSummary(r))),
    routeChip(r.route),
    h('button.icon-btn', {
      'aria-label': `Действия с правилом «${r.name}»`, title: 'Ещё',
      onclick: (e) => popMenu(e.currentTarget, [
        { label: 'Изменить', icon: 'edit', run: () => openRuleEditor(r) },
        { label: 'Дублировать', icon: 'copy', run: () => duplicate(r) },
        { label: 'Сохранить как шаблон', icon: 'list', run: () => openRuleEditor({ ...r, id: '', preset: null }, { asPreset: true }) },
        i > 0 && { label: 'Выше', icon: 'up', run: () => move(r.id, -1) },
        i < total - 1 && { label: 'Ниже', icon: 'down', run: () => move(r.id, 1) },
        '-',
        { label: 'Удалить', icon: 'trash', danger: true, run: () => removeRule(r) },
      ]),
    }, icon('more', 'dots')));
}

function finalCard(n) {
  return h('div.final-card',
    h('span.rule-num', String(n + 1)),
    h('div.final-text',
      h('div.rule-name', 'Всё остальное'),
      h('div.rule-sum', 'Трафик, который не подошёл ни под одно правило')),
    routePicker(S().final_route, (r) => act(() => invoke('update_settings', { patch: { final_route: r } })), { label: 'Маршрут для остального трафика' }));
}

function enableReorder(list) {
  let dragging = null;
  let before = '';
  const ids = () => [...list.querySelectorAll('.rule-row')].map((li) => li.dataset.id);
  const renumber = () => list.querySelectorAll('.rule-num').forEach((n, i) => { n.textContent = String(i + 1); });
  list.addEventListener('mousedown', (e) => {
    const li = e.target.closest('.rule-row');
    if (li) li.draggable = !!e.target.closest('.grip');
  });
  list.addEventListener('dragstart', (e) => {
    dragging = e.target.closest('.rule-row');
    if (!dragging) return;
    before = ids().join();
    dragging.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/x-rule', dragging.dataset.id);
  });
  list.addEventListener('dragover', (e) => {
    if (!dragging) return;
    e.preventDefault();
    const next = [...list.querySelectorAll('.rule-row:not(.dragging)')].find((li) => {
      const r = li.getBoundingClientRect();
      return e.clientY < r.top + r.height / 2;
    });
    if (next) { if (next !== dragging.nextSibling) list.insertBefore(dragging, next); } else if (list.lastChild !== dragging) list.append(dragging);
    renumber();
  });
  list.addEventListener('drop', (e) => { if (dragging) e.preventDefault(); });
  list.addEventListener('dragend', () => {
    if (!dragging) return;
    dragging.classList.remove('dragging');
    dragging.draggable = false;
    dragging = null;
    const order = ids();
    if (order.join() !== before) act(() => invoke('reorder_rules', { ids: order }));
  });
  list.addEventListener('keydown', (e) => {
    if (!e.altKey || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown')) return;
    const li = e.target.closest('.rule-row');
    if (!li) return;
    e.preventDefault();
    move(li.dataset.id, e.key === 'ArrowUp' ? -1 : 1);
  });
}

async function move(id, delta) {
  const order = D().rules.map((r) => r.id);
  const i = order.indexOf(id);
  const j = i + delta;
  if (i < 0 || j < 0 || j >= order.length) return;
  [order[i], order[j]] = [order[j], order[i]];
  await act(() => invoke('reorder_rules', { ids: order }));
  document.getElementById('rule-' + id)?.focus();
}

async function duplicate(r) {
  const copy = { ...structuredClone(r), id: '', name: r.name + ' (копия)', preset: null };
  await act(() => invoke('save_rule', { rule: copy }));
}

async function removeRule(r) {
  const ok = await confirmDialog({ title: 'Удалить правило?', text: `Правило «${r.name}» будет удалено.` });
  if (ok) act(() => invoke('delete_rule', { id: r.id }));
}

// ---------- first run ----------

function miniFork(top, bottom) {
  return s('svg', { viewBox: '0 0 56 36', class: 'mini-fork', 'aria-hidden': 'true' },
    s('path', { d: 'M3 18H18', class: 'mf trunk' }),
    s('path', { d: 'M18 18C28 18 28 7 40 7H53', class: 'mf r-' + top }),
    s('path', { d: 'M18 18C28 18 28 29 40 29H53', class: 'mf r-' + bottom }));
}

function quickStart() {
  const option = (fork, title, text, run) => {
    const b = h('button.qs-option', { onclick: () => busy(b, run) }, fork, h('span.qs-title', title), h('span.qs-text', text));
    return b;
  };
  const setup = async (preset, final, done) => {
    try {
      await invoke('add_preset', { id: preset });
      await invoke('update_settings', { patch: { final_route: final } });
      await refresh();
      toast(done);
    } catch (e) {
      errorToast(e);
    }
  };
  return h('section.quick',
    h('h2.section-title', 'Как разделить трафик'),
    h('p.section-lead', 'Выберите готовую схему — потом её можно дополнить своими правилами.'),
    h('div.qs-grid',
      option(miniFork('tunnel', 'direct'), 'Через VPN — только заблокированное',
        'Сайты из реестра блокировок идут через VPN, остальное — напрямую. Российские сервисы и скорость не страдают.',
        () => setup('ru-blocked', { kind: 'direct' }, 'Готово: заблокированное пойдёт через VPN')),
      option(miniFork('direct', 'tunnel'), 'Всё через VPN, кроме российского',
        'Российские сайты, банки и Госуслуги идут напрямую, всё остальное — через VPN.',
        () => setup('ru-direct', { kind: 'proxy' }, 'Готово: российское пойдёт напрямую')),
      option(h('span.qs-ic', icon('list')), 'Выбрать сервисы самому',
        'YouTube, Discord, Telegram, нейросети, игры, блокировка рекламы и другие шаблоны.',
        async () => gallery())));
}

// ---------- templates ----------

export function gallery() {
  const used = new Set(D().rules.map((r) => r.preset).filter(Boolean));
  const addBtn = (p, own) => {
    const added = used.has(p.id);
    // your own template can be applied again, a built-in one once
    const btn = h('button.btn.small' + (added ? '' : '.primary'), { disabled: added && !own }, added ? (own ? 'Добавить ещё раз' : 'Добавлено') : 'Добавить');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      btn.classList.add('busy');
      try {
        await invoke('add_preset', { id: p.id });
        used.add(p.id);
        btn.textContent = 'Добавлено';
        btn.classList.remove('primary');
        await refresh();
        toast(`Правило «${p.title}» добавлено в конец списка`);
        if (own) setTimeout(() => { btn.disabled = false; btn.textContent = 'Добавить ещё раз'; }, 1200);
      } catch (e) {
        btn.disabled = false;
        errorToast(e);
      }
      btn.classList.remove('busy');
    });
    return btn;
  };
  const builtIn = (p) => h('article.preset',
    h('div.preset-head', h('h3.preset-title', p.title), routeChip({ kind: p.route })),
    h('p.preset-desc', p.description),
    h('div.preset-foot', addBtn(p, false)));
  const ownCard = (p) => h('article.preset.own',
    h('div.preset-head', h('h3.preset-title', p.title), routeChip(p.route)),
    p.description ? h('p.preset-desc', p.description) : h('p.preset-desc.rule-sum', ruleSummary(p)),
    h('div.preset-foot',
      addBtn(p, true),
      h('button.icon-btn', {
        'aria-label': `Действия с шаблоном «${p.title}»`, title: 'Ещё',
        onclick: (e) => popMenu(e.currentTarget, [
          { label: 'Изменить', icon: 'edit', run: () => openRuleEditor({ ...p, name: p.title }, { asPreset: true, onSaved: paint }) },
          '-',
          { label: 'Удалить шаблон', icon: 'trash', danger: true, run: () => removePreset(p, paint) },
        ]),
      }, icon('more', 'dots'))));
  const mine = h('section.gallery-sec');
  function paint() {
    const own = D().presets || [];
    mine.replaceChildren(
      h('div.gallery-head',
        h('h3.gallery-title', 'Мои шаблоны'),
        h('button.btn.small', { onclick: () => openRuleEditor(null, { asPreset: true, onSaved: paint }) }, icon('plus'), 'Новый шаблон')),
      own.length
        ? h('div.gallery', own.map(ownCard))
        : h('p.gallery-empty', 'Здесь появятся ваши шаблоны. Создайте новый или сохраните любое правило через меню «Ещё» → «Сохранить как шаблон». Шаблоны переносятся на другой компьютер вместе с экспортом.'));
  }
  paint();
  dialog({
    title: 'Шаблоны правил',
    lead: 'Шаблон добавляется правилом в конец списка, правило потом можно изменить.',
    wide: true,
    body: [
      mine,
      h('section.gallery-sec',
        h('div.gallery-head', h('h3.gallery-title', 'Готовые шаблоны')),
        h('div.gallery', store.catalog.presets.map(builtIn))),
    ],
  });
}

async function removePreset(p, after) {
  const ok = await confirmDialog({ title: 'Удалить шаблон?', text: `Шаблон «${p.title}» будет удалён. Правила, уже добавленные из него, останутся.` });
  if (!ok) return;
  await act(() => invoke('delete_preset', { id: p.id }));
  if (after) after();
}

// ---------- editor ----------

function splitDest(text) {
  const domains = [];
  const ips = [];
  for (const line of text.split(/\r?\n/)) {
    const pieces = /^\s*regex:/i.test(line) ? [line] : line.split(/[,;]/);
    for (const raw of pieces) {
      const t = raw.trim();
      if (!t) continue;
      (IP_RE.test(t) ? ips : domains).push(t);
    }
  }
  return { domains, ips };
}

function normalizeApp(v) {
  let a = v.trim().replace(/^"|"$/g, '');
  if (!a) return '';
  // a bare name: Windows needs the .exe, macOS matches the program or its .app
  if (!isMac() && !/[\\/]/.test(a) && !/\.[a-z0-9]{2,4}$/i.test(a)) a += '.exe';
  return a;
}

function autoName(r) {
  if (r.apps.length) return appLabel(r.apps[0]);
  if (r.rule_sets.length) return setLabel(r.rule_sets[0]);
  if (r.domains.length) return domainLabel(r.domains[0]);
  if (r.ips.length) return r.ips[0];
  return 'Правило';
}

/**
 * Open the editor for an existing rule, or a new one with some fields filled in.
 * With `asPreset` it edits one of the user's own templates instead.
 */
export function openRuleEditor(rule, { asPreset = false, onSaved } = {}) {
  const isNew = !rule || !rule.id;
  const r = {
    id: '', name: '', enabled: true, match_all: false, apps: [], domains: [], ips: [], ports: [], rule_sets: [],
    network: null, route: { kind: 'proxy' }, preset: null, description: '', ...structuredClone(rule || {}),
  };

  const name = h('input.input.wide#re-name', {
    value: r.name, maxLength: 80,
    placeholder: asPreset ? 'Например: Рабочие программы напрямую' : 'Например: Discord через VPN',
  });
  const descr = asPreset && h('input.input.wide#re-descr', { value: r.description || '', maxLength: 200, placeholder: 'Необязательно: для чего этот шаблон' });

  // apps
  const appsBox = h('div.chips');
  const appInput = h('input.input.app-input', { placeholder: isMac() ? 'Название.app или путь' : 'имя.exe или путь', 'aria-label': 'Имя программы или путь к ней' });
  const addApp = (v) => {
    const a = normalizeApp(v);
    if (!a || r.apps.some((x) => x.toLowerCase() === a.toLowerCase())) return;
    r.apps.push(a);
    renderApps();
    renderMatch();
    if (/[\\/]/.test(a)) loadIcons([a]).then(renderApps);
  };
  appInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addApp(appInput.value);
      appInput.value = '';
    }
  });
  function renderApps() {
    appsBox.replaceChildren(...r.apps.map((a, i) => h('span.chip-app', { title: a },
      appIcon(a), h('span', appLabel(a)),
      h('button.chip-x', {
        type: 'button', 'aria-label': 'Убрать ' + appLabel(a),
        onclick: () => { r.apps.splice(i, 1); renderApps(); renderMatch(); },
      }, icon('close')))));
    if (!r.apps.length) appsBox.append(h('span.chips-empty', 'Любая программа'));
  }

  // destinations
  const dest = h('textarea.textarea.mono#re-dest', {
    rows: 4, spellcheck: false, value: [...r.domains, ...r.ips].join('\n'),
    placeholder: 'youtube.com\nfull:api.example.com\nkeyword:google\n203.0.113.0/24',
  });
  dest.addEventListener('input', () => renderMatch());

  // rule sets
  const setsBox = h('div.chips');
  const catalogChecks = new Map();
  function renderSets() {
    setsBox.replaceChildren(...r.rule_sets.map((t, i) => h('span.chip-set', { title: t },
      h('span', setLabel(t)),
      h('button.chip-x', {
        type: 'button', 'aria-label': 'Убрать ' + setLabel(t),
        onclick: () => { r.rule_sets.splice(i, 1); syncChecks(); renderSets(); renderMatch(); },
      }, icon('close')))));
    if (!r.rule_sets.length) setsBox.append(h('span.chips-empty', 'Не выбраны'));
    catalogSummary.textContent = r.rule_sets.length ? `Каталог списков, выбрано ${r.rule_sets.length}` : 'Каталог списков';
  }
  const syncChecks = () => catalogChecks.forEach((cb, tag) => { cb.checked = r.rule_sets.includes(tag); });
  const toggleSet = (tag, on) => {
    const has = r.rule_sets.includes(tag);
    if (on && !has) r.rule_sets.push(tag);
    if (!on && has) r.rule_sets.splice(r.rule_sets.indexOf(tag), 1);
    renderSets();
    renderMatch();
  };
  const catalogSummary = h('span');
  const catSearch = h('input.input', { type: 'search', placeholder: 'Найти: youtube, игры, реклама…', 'aria-label': 'Поиск по каталогу' });
  const groups = [...new Set(store.catalog.rule_sets.map((e) => e.group))];
  const groupEls = groups.map((g) => {
    const items = store.catalog.rule_sets.filter((e) => e.group === g).map((e) => {
      const cb = h('input', { type: 'checkbox', checked: r.rule_sets.includes(e.tag), onchange: () => toggleSet(e.tag, cb.checked) });
      catalogChecks.set(e.tag, cb);
      return h('label.cat-item', { data: { q: (e.label + ' ' + e.tag).toLowerCase() } }, cb, h('span', e.label));
    });
    return h('div.cat-group', h('div.cat-group-title', g), h('div.cat-items', items));
  });
  catSearch.addEventListener('input', () => {
    const q = catSearch.value.trim().toLowerCase();
    for (const gEl of groupEls) {
      let any = false;
      for (const it of gEl.querySelectorAll('.cat-item')) {
        const hit = !q || it.dataset.q.includes(q);
        it.hidden = !hit;
        any = any || hit;
      }
      gEl.hidden = !any;
    }
  });
  const tagList = h('datalist#re-tags');
  const customSet = h('input.input.mono', { placeholder: 'geosite-… или https://…/list.srs', 'aria-label': 'Свой список', list: 're-tags', autocomplete: 'off' });
  customSet.addEventListener('focus', () => fillTags(tagList), { once: true });
  const addCustom = () => {
    const v = customSet.value.trim();
    if (!v) return;
    if (!SET_RE.test(v) && !/^https:\/\/\S+$/i.test(v)) {
      toast('Нужен тег вида geosite-имя / geoip-имя или ссылка https:// на файл .srs', { kind: 'error' });
      return;
    }
    toggleSet(v, true);
    syncChecks();
    customSet.value = '';
  };
  customSet.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); addCustom(); } });

  // advanced
  const ports = h('input.input#re-ports', { value: r.ports.join(', '), placeholder: '443, 27000-27100' });
  const net = seg([{ value: '', label: 'Любой' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }], r.network || '',
    (v) => { r.network = v || null; }, { label: 'Протокол' });

  const matchBox = h('div.match-box');
  const matchOpt = (val, title, text) => h('label.match-opt',
    h('input', { type: 'radio', name: 're-match', checked: r.match_all === val, onchange: () => { r.match_all = val; } }),
    h('span', h('span.match-title', title), h('span.match-text', text)));
  matchBox.append(
    h('div.field-label', 'Когда срабатывает'),
    matchOpt(false, 'Программа или адрес', 'Ловит всё, что делают выбранные программы, и любые соединения с указанными адресами.'),
    matchOpt(true, 'Программа и адрес вместе', 'Например, только YouTube в Chrome — остальные сайты Chrome пойдут по другим правилам.'));
  function renderMatch() {
    const { domains, ips } = splitDest(dest.value);
    matchBox.hidden = !(r.apps.length && (domains.length || ips.length || r.rule_sets.length));
  }

  const err = h('p.form-error', { hidden: true });
  const save = h('button.btn.primary', { onclick: () => submit() }, asPreset ? 'Сохранить шаблон' : isNew ? 'Добавить правило' : 'Сохранить');
  async function submit() {
    const { domains, ips } = splitDest(dest.value);
    if (appInput.value.trim()) { addApp(appInput.value); appInput.value = ''; }
    const out = {
      ...r,
      name: name.value.trim(),
      domains,
      ips,
      ports: ports.value.split(/[,;\s]+/).map((p) => p.trim()).filter(Boolean),
    };
    if (!out.name) out.name = autoName(out);
    await busy(save, async () => {
      try {
        if (asPreset) {
          const preset = {
            id: r.id, title: out.name, description: descr.value.trim(), match_all: out.match_all, apps: out.apps,
            domains: out.domains, ips: out.ips, ports: out.ports, rule_sets: out.rule_sets, network: out.network,
            route: out.route, created_at: r.created_at || 0,
          };
          await invoke('save_preset', { preset });
          dl.close();
          await refresh();
          toast(isNew ? `Шаблон «${preset.title}» сохранён` : 'Шаблон сохранён', { detail: isNew && !onSaved ? 'Он в «Шаблоны» → «Мои шаблоны».' : '' });
          if (onSaved) onSaved();
          return;
        }
        delete out.description;
        await invoke('save_rule', { rule: out });
        dl.close();
        await refresh();
        toast(isNew ? `Правило «${out.name}» добавлено` : 'Правило сохранено');
      } catch (e) {
        err.hidden = false;
        err.textContent = errText(e);
      }
    });
  }

  const field = (label, note, ...controls) => h('div.field', h('div.field-label', label), controls, note && h('p.field-note', note));
  const body = [
    h('div.editor-top',
      h('div.field.grow', h('label.field-label', { htmlFor: 're-name' }, asPreset ? 'Название шаблона' : 'Название'), name),
      h('div.field', h('div.field-label', 'Куда направить'), routePicker(r.route, (v) => { r.route = v; }))),
    descr && h('div.field', h('label.field-label', { htmlFor: 're-descr' }, 'Описание'), descr),
    h('section.editor-sec',
      h('h3.editor-h', 'Программы'),
      appsBox,
      h('div.inline-actions',
        h('button.btn.small', { type: 'button', onclick: () => processPicker((list) => list.forEach(addApp)) }, icon('activity'), 'Из запущенных…'),
        h('button.btn.small', {
          type: 'button',
          onclick: async () => { try { const p = await invoke('pick_exe'); if (p) addApp(p); } catch (e) { errorToast(e); } },
        }, icon('file'), 'Файл программы…'),
        h('button.btn.small', {
          type: 'button',
          onclick: async () => { try { const p = await invoke('pick_folder'); if (p) addApp(p); } catch (e) { errorToast(e); } },
        }, icon('folder'), 'Папка…'),
        appInput),
      h('p.field-note', 'Папка охватывает все программы внутри неё, например всю библиотеку Steam.')),
    h('section.editor-sec',
      h('h3.editor-h', 'Сайты и IP-адреса'),
      dest,
      h('p.field-note', 'По одному в строке. example.com — вместе с поддоменами, full:a.example.com — только этот адрес, keyword:слово — адрес содержит слово, 10.0.0.0/8 — подсеть.')),
    h('section.editor-sec',
      h('h3.editor-h', 'Готовые списки'),
      setsBox,
      h('details.catalog', h('summary', catalogSummary),
        h('div.catalog-body', catSearch, h('div.cat-groups', groupEls),
          h('div.custom-set', customSet, tagList, h('button.btn.small', { type: 'button', onclick: addCustom }, 'Добавить')),
          h('p.field-note', 'Любой тег из баз sing-geosite и sing-geoip: начните вводить geosite- или geoip-, появятся подсказки.'))),
      h('p.field-note', 'Списки скачиваются из открытых баз sing-geosite и runetfreedom и обновляются раз в три дня.')),
    matchBox,
    h('details.advanced', h('summary', 'Порты и протокол'),
      h('div.adv-body',
        field('Порты', 'Через запятую, можно диапазоны.', ports),
        field('Протокол', null, net))),
    err,
  ];

  const actions = [
    !isNew && h('button.btn.danger.push-left', {
      onclick: async () => {
        if (asPreset) {
          dl.close();
          removePreset({ id: r.id, title: r.name }, onSaved);
          return;
        }
        const ok = await confirmDialog({ title: 'Удалить правило?', text: `Правило «${r.name}» будет удалено.` });
        if (ok) { dl.close(); act(() => invoke('delete_rule', { id: r.id })); }
      },
    }, 'Удалить'),
    h('button.btn', { onclick: () => dl.close() }, 'Отмена'),
    save,
  ];

  const title = asPreset ? (isNew ? 'Новый шаблон' : 'Шаблон') : (isNew ? 'Новое правило' : 'Правило');
  const dl = dialog({
    title, wide: true, body, actions,
    lead: asPreset ? 'Условия и маршрут, из которых в один клик получается правило.' : undefined,
  });
  renderApps();
  renderSets();
  renderMatch();
  if (r.apps.some((a) => !/[\\/]/.test(a))) ensureProcIndex().then(() => loadIcons(r.apps.map(iconPath).filter(Boolean))).then(renderApps);
  else loadIcons(r.apps.filter((a) => /[\\/]/.test(a))).then(renderApps);
  if (!isNew) name.blur();
}

let geoTags = null;
/** Hints for the custom list field: every geosite/geoip tag (loaded once, cached by the app for a week). */
async function fillTags(list) {
  if (!geoTags) {
    try {
      geoTags = await invoke('geo_tags');
    } catch {
      geoTags = store.catalog.rule_sets.map((e) => e.tag);
    }
  }
  if (list.isConnected) list.replaceChildren(...geoTags.map((t) => h('option', { value: t })));
}

const SYSTEM = new Set(['svchost.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe',
  'dwm.exe', 'fontdrvhost.exe', 'conhost.exe', 'sihost.exe', 'ctfmon.exe', 'runtimebroker.exe', 'dllhost.exe',
  'taskhostw.exe', 'searchindexer.exe', 'spoolsv.exe', 'registry', 'system', 'wudfhost.exe', 'audiodg.exe',
  'searchhost.exe', 'startmenuexperiencehost.exe', 'textinputhost.exe', 'shellexperiencehost.exe',
  'securityhealthservice.exe', 'smartscreen.exe', 'backgroundtaskhost.exe', 'applicationframehost.exe', 'lsaiso.exe',
  'msmpeng.exe', 'nissrv.exe', 'wmiprvse.exe', 'sing-box.exe', 'retunl.exe', 'memory compression', 'secure system',
  'msedgewebview2.exe', 'crashpad_handler.exe', 'securityhealthsystray.exe', 'widgets.exe', 'widgetservice.exe',
  // macOS
  'kernel_task', 'launchd', 'windowserver', 'loginwindow', 'retunl', 'sing-box', 'finder', 'dock', 'systemuiserver',
  'controlcenter', 'notificationcenter', 'spotlight', 'mds', 'mds_stores', 'mdworker', 'cfprefsd', 'distnoted']);
// system programs live here on macOS
const SYSTEM_DIR = /^\/(System|usr\/(libexec|sbin)|sbin|Library\/Apple)\//;

async function processPicker(onPick) {
  const search = h('input.input.wide', { type: 'search', placeholder: 'Найти программу', 'aria-label': 'Поиск программы' });
  const list = h('div.proc-list', h('p.muted', 'Загружаю список…'));
  const showSys = h('input', { type: 'checkbox' });
  const chosen = new Set();
  const add = h('button.btn.primary', { disabled: true, onclick: () => { onPick([...chosen]); dl.close(); } }, 'Добавить');
  const dl = dialog({
    title: 'Запущенные программы',
    body: [h('div.proc-tools', search, h('label.check', showSys, 'Показать системные')), list],
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), add],
  });
  let procs;
  try {
    procs = await invoke('list_processes');
  } catch (e) {
    list.replaceChildren(h('p.form-error', errText(e)));
    return;
  }
  const seen = new Map();
  for (const p of procs) if (!seen.has(p.name.toLowerCase())) seen.set(p.name.toLowerCase(), p);
  procs = [...seen.values()].sort((a, b) => a.name.localeCompare(b.name, 'ru', { sensitivity: 'base' }));
  const render = () => {
    const q = search.value.trim().toLowerCase();
    const items = procs.filter((p) => (showSys.checked || (!SYSTEM.has(p.name.toLowerCase()) && !/\\windows\\system32\\/i.test(p.path) && !SYSTEM_DIR.test(p.path)))
      && (!q || p.name.toLowerCase().includes(q) || p.path.toLowerCase().includes(q)));
    list.replaceChildren(...items.map((p) => {
      const cb = h('input', {
        type: 'checkbox', checked: chosen.has(p.name),
        onchange: () => {
          cb.checked ? chosen.add(p.name) : chosen.delete(p.name);
          add.disabled = !chosen.size;
          add.textContent = chosen.size ? `Добавить (${chosen.size})` : 'Добавить';
        },
      });
      return h('label.proc', cb, appIcon(p.path || p.name), h('span.proc-name', p.name), h('span.proc-path', { title: p.path }, p.path));
    }));
    if (!items.length) list.append(h('p.muted', 'Ничего не найдено.'));
  };
  search.addEventListener('input', render);
  showSys.addEventListener('change', render);
  render();
  if (await loadIcons(procs.map((p) => p.path))) render();
}
