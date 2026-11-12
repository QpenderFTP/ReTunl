// A WireGuard server through WireSock VPN Client (Windows): masking and junk packets.

import {
  h, icon, invoke, busy, toast, errorToast, dialog, banner, seg, toggle, field, formError, showError,
} from './lib.js';
import { store, refresh } from './store.js';

const SITE = 'https://www.wiresock.net/';
const MASKS = [
  { value: '', label: 'Нет' },
  { value: 'quic', label: 'QUIC' },
  { value: 'dns', label: 'DNS' },
  { value: 'sip', label: 'SIP' },
  { value: 'stun', label: 'STUN' },
];
const BROWSERS = [['', 'Как решит WireSock'], ['chrome', 'Chrome'], ['firefox', 'Firefox'], ['curl', 'curl']];

export function wiresockDialog(p) {
  const ws = { enabled: false, domain: '', protocol: '', browser: '', junk_delay: 0, ...(p.wiresock || {}) };
  const o = p.outbound;
  let mask = ws.protocol;

  const num = (id, value, max, label) => h('input.input.num-input', {
    id, type: 'number', min: 0, max, step: 1, inputMode: 'numeric', value: String(value || 0), 'aria-label': label,
  });
  const on = toggle(ws.enabled, paint, { id: 'ws-on' });
  const domain = h('input.input#ws-domain', { value: ws.domain, placeholder: 'ozon.ru', spellcheck: false, autocapitalize: 'off', maxLength: 253 });
  const browser = h('select.select#ws-browser', BROWSERS.map(([v, label]) => h('option', { value: v }, label)));
  browser.value = ws.browser;
  const jc = num('ws-jc', o.jc, 128);
  const jmin = num('ws-jmin', o.jmin, 1280, 'Наименьший размер, байт');
  const jmax = num('ws-jmax', o.jmax, 1280, 'Наибольший размер, байт');
  const jd = num('ws-jd', ws.junk_delay, 1000);
  const err = formError();

  const domainField = field('ws-domain', 'Сайт', domain, 'Популярный в вашей стране сайт: пакеты будут похожи на обращения к нему.');
  const browserField = field('ws-browser', 'Как браузер', browser);
  const junkSize = h('div.ws-junk-size', jmin, h('span', '—'), jmax);
  const opts = h('div.form-stack.ws-opts',
    h('div.field',
      h('span.field-label#ws-mask-label', 'Маскировка'),
      seg(MASKS, mask, (v) => { mask = v; paint(); }, { label: 'Маскировка' }),
      h('p.field-note', 'Под что WireSock подделывает пакеты перед рукопожатием WireGuard.')),
    h('div.form-row.ws-mask', domainField, browserField),
    h('div.field',
      h('span.field-label', 'Мусорные пакеты'),
      h('div.form-row.ws-junk',
        field('ws-jc', 'Сколько', jc),
        h('div.field', h('span.field-label', 'Размер, байт'), junkSize),
        field('ws-jd', 'Пауза, мс', jd)),
      h('p.field-note', 'Случайные пакеты перед рукопожатием, их шлёт только клиент: сервер настраивать не нужно. 0 — без них.')));

  function paint() {
    domainField.hidden = !mask;
    browserField.hidden = mask !== 'quic';
  }

  const installed = !!store.view.wiresock;
  const notes = [];
  if (!installed) {
    notes.push(banner('warn', 'WireSock VPN Client не установлен',
      'Поставьте его с сайта WireSock: ReTunl найдёт программу сам. Настройки можно сохранить заранее.',
      [h('button.btn.small', { type: 'button', onclick: () => invoke('open_url', { url: SITE }).catch(errorToast) }, icon('external'), 'Открыть сайт')]));
  } else if (!store.view.elevated) {
    notes.push(banner('warn', 'Нужны права администратора',
      'WireSock работает только когда ReTunl запущен с правами администратора: включите это в настройках.'));
  }

  const save = h('button.btn.primary', {
    onclick: () => busy(save, async () => {
      err.hidden = true;
      const int = (el) => Math.max(0, Math.floor(Number(el.value) || 0));
      const wiresock = {
        enabled: on.checked,
        protocol: mask,
        domain: mask ? domain.value.trim() : '',
        browser: mask === 'quic' ? browser.value : '',
        junk_delay: int(jd),
      };
      try {
        await invoke('set_wiresock', { id: p.id, wiresock, junk: { jc: int(jc), jmin: int(jmin), jmax: int(jmax) } });
        dl.close();
        await refresh();
        toast(wiresock.enabled ? `«${p.name}» подключается через WireSock` : 'Настройки WireSock сохранены');
      } catch (e) {
        showError(err, e);
      }
    }),
  }, 'Сохранить');

  const dl = dialog({
    title: `WireSock для «${p.name}»`,
    lead: 'WireSock VPN Client сам подключает этот сервер и прячет WireGuard от блокировок. Остальные серверы и правила работают как прежде.',
    body: h('div.form-stack.ws-form',
      notes,
      h('label.ws-on', { htmlFor: 'ws-on' },
        h('span.ws-on-text', h('span.field-label', 'Подключать через WireSock'),
          h('span.field-note', 'Через WireSock идёт один сервер за раз.')),
        on),
      opts, err),
    actions: [h('button.btn', { onclick: () => dl.close() }, 'Отмена'), save],
  });
  paint();
}
