// Cisco Secure Client as a server: its state in the list, settings, logging in and out.

import {
  h, icon, invoke, busy, toast, errorToast, dialog, banner, toggle, field, formError, showError,
} from './lib.js';
import { store, refresh } from './store.js';

const STATES = {
  connected: ['Cisco: вход выполнен', ''],
  connecting: ['Cisco: подключается', ' muted'],
  disconnected: ['Cisco: не подключён', ' muted'],
};

/** The tag on a Cisco server: Cisco's state, filled in when it is known. */
export function ciscoTag() {
  const t = h('span.tag.cisco-state', { title: 'Состояние Cisco Secure Client' });
  paintTag(t);
  return t;
}

function paintTag(t) {
  if (!store.view.cisco) {
    t.className = 'tag warn cisco-state';
    t.textContent = 'Cisco не установлен';
    return;
  }
  const st = store.cisco && STATES[store.cisco.state];
  t.className = 'tag cisco-state' + (st ? st[1] : ' muted');
  t.textContent = st ? st[0] : 'Cisco';
}

const paintTags = () => document.querySelectorAll('.cisco-state').forEach(paintTag);

/** Ask vpncli for Cisco's state (at most every 15 seconds unless `force`). */
export async function loadCisco(force) {
  if (!store.view.cisco) return;
  if (!force && store.ciscoAt && Date.now() - store.ciscoAt < 15000) return;
  store.ciscoAt = Date.now();
  try {
    store.cisco = await invoke('cisco_status');
  } catch {
    store.cisco = null;
  }
  paintTags();
}

function setState(state) {
  store.cisco = { ...(store.cisco || {}), state };
  store.ciscoAt = Date.now();
  paintTags();
}

function missing() {
  return store.view.cisco ? null : banner('warn', 'Cisco Secure Client не установлен',
    'Его выдаёт ваша организация. Установите программу, и ReTunl найдёт её сам. Сервер можно добавить заранее.');
}

/** Add a Cisco Secure Client server (`p` = null) or change one. */
export function ciscoDialog(p) {
  const c = { host: '', group: '', username: '', disconnect: false, ...((p && p.cisco) || {}) };
  const input = (id, value, attrs = {}) => h('input.input#' + id, { value, spellcheck: false, autocapitalize: 'off', maxLength: 200, ...attrs });
  const name = input('cs-name', p ? p.name : 'Cisco', { maxLength: 80 });
  const host = input('cs-host', c.host, { placeholder: 'vpn.company.ru' });
  const grp = input('cs-group', c.group, { placeholder: 'Если сервер спрашивает' });
  const user = input('cs-user', c.username, { autocomplete: 'username' });
  const off = toggle(c.disconnect, () => {}, { id: 'cs-off' });
  const err = formError();

  const save = h('button.btn.primary', {
    onclick: () => busy(save, async () => {
      err.hidden = true;
      const cisco = { host: host.value.trim(), group: grp.value.trim(), username: user.value.trim(), disconnect: off.checked };
      try {
        await invoke('save_cisco', { id: p ? p.id : null, name: name.value.trim(), cisco });
        dl.close();
        await refresh();
        toast(p ? 'Настройки Cisco сохранены' : `«${name.value.trim() || 'Cisco'}» добавлен в серверы`);
      } catch (e) {
        showError(err, e);
      }
    }),
  }, p ? 'Сохранить' : 'Добавить');

  const dl = dialog({
    title: p ? `Cisco для «${p.name}»` : 'Cisco Secure Client',
    lead: 'ReTunl сам входит в Cisco Secure Client и отправляет в него трафик правил, которые ведут на этот сервер. Остальное идёт как раньше.',
    body: h('div.form-stack.cisco-form',
      missing(),
      field('cs-name', 'Название в ReTunl', name),
      field('cs-host', 'Сервер Cisco', host, 'Адрес или название из списка в окне Cisco.'),
      h('div.form-row.cisco-pair',
        field('cs-group', 'Группа', grp),
        field('cs-user', 'Логин', user)),
      h('label.ws-on', { htmlFor: 'cs-off' },
        h('span.ws-on-text', h('span.field-label', 'Выходить из Cisco при отключении ReTunl'),
          h('span.field-note', 'Иначе Cisco остаётся подключённым.')),
        off),
      h('p.field-note', 'Пароль ReTunl спрашивает при каждом входе и нигде не хранит.'),
      err),
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), save],
  });
}

/** Log in to Cisco Secure Client for `p`; `after` runs once logged in (a connection). */
export function ciscoLogin(p, after) {
  const c = p.cisco || {};
  const pass = h('input.input#cs-pass', { type: 'password', autocomplete: 'current-password' });
  const second = h('input.input#cs-second', { autocomplete: 'one-time-code', spellcheck: false, autocapitalize: 'off', placeholder: 'push или код' });
  const err = formError();

  const go = h('button.btn.primary', {
    disabled: !store.view.cisco,
    onclick: () => busy(go, async () => {
      err.hidden = true;
      try {
        await invoke('cisco_login', { id: p.id, password: pass.value, second: second.value.trim() });
        pass.value = '';
        dl.close();
        setState('connected');
        toast('Вход в Cisco Secure Client выполнен');
        if (after) after();
      } catch (e) {
        showError(err, e);
        loadCisco(true);
      }
    }),
  }, after ? 'Войти и подключить' : 'Войти');
  pass.addEventListener('keydown', (e) => { if (e.key === 'Enter') go.click(); });
  second.addEventListener('keydown', (e) => { if (e.key === 'Enter') go.click(); });

  const inUi = h('button.btn', {
    disabled: !store.view.cisco,
    onclick: async () => {
      try {
        await invoke('cisco_open');
        dl.close();
        toast('Войдите в окне Cisco Secure Client', { detail: after ? 'Потом снова нажмите «Подключить» в ReTunl.' : '' });
      } catch (e) {
        errorToast(e);
      }
    },
  }, icon('external'), 'Войти в окне Cisco');

  const dl = dialog({
    title: 'Вход в Cisco Secure Client',
    lead: `Сервер ${c.host}${c.group ? ', группа ' + c.group : ''}${c.username ? ', логин ' + c.username : ''}. Пароль уйдёт только в Cisco и нигде не сохранится.`,
    body: h('div.form-stack.cisco-form',
      missing(),
      field('cs-pass', 'Пароль', pass),
      field('cs-second', 'Второй пароль', second, 'Если сервер просит подтверждение: push для Duo или код из SMS или приложения.'),
      h('p.field-note', 'Вход через браузер (SAML), по сертификату или с проверкой компьютера (ISE Posture) работает только в окне Cisco. Если окно Cisco открыто, на время входа ReTunl его закроет.'),
      err),
    actions: [inUi, h('button.btn', { onclick: () => dl.close() }, 'Отмена'), go],
  });
  setTimeout(() => pass.focus(), 50);
}

export async function ciscoLogout() {
  try {
    await invoke('cisco_logout');
    setState('disconnected');
    toast('Выход из Cisco Secure Client выполнен');
  } catch (e) {
    errorToast(e);
  }
}
