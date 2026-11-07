// Moving servers, subscriptions, rules and templates to another computer:
// an export sealed with a password, and its import.

import {
  h, icon, invoke, busy, toast, errText, dialog, fmtDate, plural,
} from './lib.js';
import {
  store, D, refresh, protoParts, copyText, here,
} from './store.js';

const servers = (n) => plural(n, 'сервер', 'сервера', 'серверов');
const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };

/** A checkbox row: title, a quiet note on the right, maybe a tag. */
function pick({ checked = true, disabled = false, title, note, tag, onChange }) {
  const cb = h('input', { type: 'checkbox', checked: checked && !disabled, disabled, onchange: () => onChange && onChange(cb.checked) });
  return {
    cb,
    el: h('label.tr-item' + (disabled ? '.off' : ''), cb,
      h('span.tr-title', title, tag && h('span.tag.muted', tag)),
      note && h('span.tr-note', note)),
  };
}

function group(title, items, { all = true } = {}) {
  if (!items.length) return null;
  const live = items.filter((i) => !i.cb.disabled);
  const toggle = live.length > 1 && all && h('button.link-btn', {
    type: 'button',
    onclick: () => {
      const on = !live.every((i) => i.cb.checked);
      live.forEach((i) => { i.cb.checked = on; });
    },
  }, 'Все / ничего');
  return h('section.tr-group', h('div.tr-group-head', h('h3.tr-group-title', title), toggle), h('div.tr-list', items.map((i) => i.el)));
}

function passwordFields(confirm) {
  const pw = h('input.input.wide#tr-pw', { type: 'password', autocomplete: 'new-password', placeholder: 'Не короче 6 символов' });
  const pw2 = confirm && h('input.input.wide#tr-pw2', { type: 'password', autocomplete: 'new-password', placeholder: 'Ещё раз' });
  const show = h('label.check', h('input', {
    type: 'checkbox',
    onchange: (e) => { pw.type = e.target.checked ? 'text' : 'password'; if (pw2) pw2.type = pw.type; },
  }), 'Показать пароль');
  return { pw, pw2, show };
}

// ---------- export ----------

export function exportDialog() {
  const d = D();
  const subs = d.subscriptions.map((s) => {
    const n = d.profiles.filter((p) => p.subscription === s.id).length;
    return { id: s.id, ...pick({ title: s.name, note: `${hostOf(s.url)}, ${servers(n)}` }) };
  });
  const manual = d.profiles.filter((p) => !p.subscription).map((p) => {
    const adapter = p.outbound && p.outbound.type === 'direct';
    const { base } = protoParts(p);
    // another computer has its own network adapters
    return { id: p.id, ...pick({ title: p.name, note: adapter ? 'сетевой адаптер этого компьютера' : base, checked: !adapter }) };
  });
  const presets = d.presets || [];
  const rulesPick = d.rules.length ? pick({ title: 'Правила', note: plural(d.rules.length, 'правило', 'правила', 'правил') }) : null;
  const presetsPick = presets.length ? pick({ title: 'Мои шаблоны', note: plural(presets.length, 'шаблон', 'шаблона', 'шаблонов') }) : null;
  const extra = [rulesPick, presetsPick].filter(Boolean);

  if (!subs.length && !manual.length && !extra.length) {
    toast('Пока нечего переносить: нет ни серверов, ни правил');
    return;
  }

  const { pw, pw2, show } = passwordFields(true);
  const err = h('p.form-error', { hidden: true });
  const fail = (text) => { err.hidden = false; err.textContent = text; };

  async function run(btn, toFile) {
    err.hidden = true;
    const request = {
      subscription_ids: subs.filter((s) => s.cb.checked).map((s) => s.id),
      profile_ids: manual.filter((p) => p.cb.checked).map((p) => p.id),
      rules: !!(rulesPick && rulesPick.cb.checked),
      presets: !!(presetsPick && presetsPick.cb.checked),
      password: pw.value,
      to_file: toFile,
    };
    if (!request.subscription_ids.length && !request.profile_ids.length && !request.rules && !request.presets) return fail('Отметьте, что перенести.');
    if ([...pw.value].length < 6) { pw.focus(); return fail('Пароль должен быть не короче 6 символов.'); }
    if (pw.value !== pw2.value) { pw2.focus(); return fail('Пароли не совпадают.'); }
    await busy(btn, async () => {
      try {
        const res = await invoke('export_bundle', { request });
        if (!res) return; // save dialog cancelled
        dl.close();
        if (res.path) {
          toast('Экспорт сохранён', { detail: res.path + `\nОткройте этот файл в ReTunl ${here().onOther}: «Серверы» → «Добавить» → «Открыть файл…».`, timeout: 10000 });
        } else {
          await copyText(res.text, 'Экспорт скопирован в буфер обмена');
        }
      } catch (e) {
        fail(errText(e));
      }
    });
  }

  const toFile = h('button.btn.primary', { onclick: (e) => run(e.currentTarget, true) }, icon('file'), 'Сохранить в файл');
  const toText = h('button.btn', { onclick: (e) => run(e.currentTarget, false) }, icon('copy'), 'Скопировать текстом');
  const dl = dialog({
    title: `Экспорт ${here().toOther}`,
    lead: `Выбранное шифруется паролем. ${here().onOther[0].toUpperCase() + here().onOther.slice(1)} откройте файл в ReTunl или вставьте скопированный текст и введите тот же пароль.`,
    wide: true,
    body: [
      h('div.tr-groups',
        group('Подписки', subs),
        group('Добавлены вручную', manual),
        extra.length ? group('Ещё', extra, { all: false }) : null),
      h('div.tr-password',
        h('div.field', h('label.field-label', { htmlFor: 'tr-pw' }, 'Пароль'), pw),
        h('div.field', h('label.field-label', { htmlFor: 'tr-pw2' }, 'Повторите пароль'), pw2),
        show),
      h('p.field-note', 'Пароль нигде не сохраняется, без него экспорт не открыть. Шифрование — Argon2id и XChaCha20-Poly1305; чем длиннее пароль, тем труднее его подобрать.'),
      err,
    ],
    actions: [h('button.btn.push-left', { onclick: () => dl.close() }, 'Отмена'), toText, toFile],
  });
  pw.focus();
}

// ---------- import ----------

/** The text is an encrypted export: ask for the password, then what to take. */
export function openBundleImport(text) {
  const { pw, show } = passwordFields(false);
  pw.autocomplete = 'current-password';
  pw.placeholder = '';
  const err = h('p.form-error', { hidden: true });
  const open = h('button.btn.primary', {
    onclick: () => {
      if (!pw.value) { pw.focus(); return; }
      err.hidden = true;
      busy(open, async () => {
        try {
          const opened = await invoke('open_bundle', { text, password: pw.value });
          dl.close();
          chooseDialog(opened);
        } catch (e) {
          err.hidden = false;
          err.textContent = errText(e);
          pw.select();
        }
      });
    },
  }, 'Открыть');
  pw.addEventListener('keydown', (e) => { if (e.key === 'Enter') open.click(); });
  const dl = dialog({
    title: 'Экспорт ReTunl',
    lead: 'Введите пароль, который задали при экспорте.',
    body: [h('div.field', h('label.field-label', { htmlFor: 'tr-pw' }, 'Пароль'), pw), h('div.tr-show', show), err],
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), open],
  });
  pw.focus();
}

function chooseDialog({ bundle: b, existing }) {
  const here = 'уже есть';
  const subs = b.subscriptions.map((bs) => {
    const dup = existing.subscriptions.includes(bs.subscription.id);
    return { item: bs, ...pick({ title: bs.subscription.name, note: `${hostOf(bs.subscription.url)}, ${servers(bs.profiles.length)}`, tag: dup && here, disabled: dup }) };
  });
  const manual = b.profiles.map((p) => {
    const dup = existing.profiles.includes(p.id);
    return { item: p, ...pick({ title: p.name, note: protoParts(p).base, tag: dup && here, disabled: dup }) };
  });
  const rulesPick = b.rules.length ? pick({ title: 'Правила', note: plural(b.rules.length, 'правило', 'правила', 'правил') + ', добавятся в конец списка' }) : null;
  const presetsPick = b.presets.length ? pick({ title: 'Шаблоны правил', note: plural(b.presets.length, 'шаблон', 'шаблона', 'шаблонов') }) : null;
  const extra = [rulesPick, presetsPick].filter(Boolean);
  const nothingNew = [...subs, ...manual].every((x) => x.cb.disabled) && !extra.length;

  const err = h('p.form-error', { hidden: true });
  const go = h('button.btn.primary', {
    disabled: nothingNew,
    onclick: () => busy(go, async () => {
      const chosen = {
        ...b,
        subscriptions: subs.filter((s) => s.cb.checked).map((s) => s.item),
        profiles: manual.filter((p) => p.cb.checked).map((p) => p.item),
        rules: rulesPick && rulesPick.cb.checked ? b.rules : [],
        presets: presetsPick && presetsPick.cb.checked ? b.presets : [],
      };
      try {
        const m = await invoke('import_bundle', { bundle: chosen });
        dl.close();
        await refresh();
        reportMerged(m);
      } catch (e) {
        err.hidden = false;
        err.textContent = errText(e);
      }
    }),
  }, 'Импортировать');
  const dl = dialog({
    title: 'Что импортировать',
    lead: b.created_at ? `Экспорт от ${fmtDate(b.created_at)}. То, что уже есть ${here().onThis}, не продублируется.` : `То, что уже есть ${here().onThis}, не продублируется.`,
    wide: true,
    body: [
      h('div.tr-groups',
        group('Подписки', subs),
        group('Серверы, добавленные вручную', manual),
        extra.length ? group('Ещё', extra, { all: false }) : null),
      nothingNew ? h('p.field-note', `Всё из этого экспорта уже есть ${here().onThis}.`) : null,
      err,
    ],
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), go],
  });
  if (!nothingNew) go.focus();
}

function reportMerged(m) {
  const parts = [];
  if (m.subscriptions) parts.push(plural(m.subscriptions, 'подписка', 'подписки', 'подписок'));
  if (m.profiles) parts.push(servers(m.profiles));
  if (m.rules) parts.push(plural(m.rules, 'правило', 'правила', 'правил'));
  if (m.presets) parts.push(plural(m.presets, 'шаблон', 'шаблона', 'шаблонов'));
  const notes = [];
  const dups = m.subscriptions_existing + m.profiles_existing + m.rules_existing;
  if (dups) notes.push(`уже были: ${dups}`);
  if (m.routes_reset) notes.push(`${plural(m.routes_reset, 'правило ведёт', 'правила ведут', 'правил ведут')} теперь через выбранный сервер — их сервер не перенесён`);
  toast(parts.length ? 'Импортировано: ' + parts.join(', ') : 'Ничего нового — всё уже было', { detail: notes.join('; '), timeout: notes.length ? 10000 : 5000 });
  if (m.profiles && store.page !== 'servers') store.navigate('servers');
}

store.openBundle = openBundleImport;
