import { dialog, errText, h, invoke, toast } from './lib.js';
import { isAndroid, store } from './store.js';

let available = null;
let announced = null;
let checking = false;
let installing = false;
let message = '';

function paint(root = document.getElementById('app-update')) {
  if (!root) return;
  const check = h('button.btn.small', { disabled: checking || installing, onclick: () => checkUpdate(true) },
    checking ? 'Проверяю…' : 'Проверить обновления');
  const install = available && h('button.btn.small.primary', {
    disabled: installing || checking, onclick: confirmUpdate,
  }, installing ? 'Загружаю…' : store.view.portable ? 'Открыть релиз' : 'Установить');
  root.replaceChildren(h('span.set-note', { role: 'status' }, message || (available ? 'Доступна версия ' + available : '')), check);
  if (install) root.append(install);
}

export function updateControl() {
  const root = h('div.ctl-stack#app-update');
  paint(root);
  return root;
}

export async function checkUpdate(manual = false) {
  if (checking || installing) return;
  checking = true;
  message = '';
  paint();
  try {
    available = await invoke('check_update');
    if (available && announced !== available && !manual) {
      announced = available;
      toast('Доступен ReTunl ' + available, { action: { label: 'Посмотреть', run: () => store.navigate('settings') } });
    }
    if (!available && manual) message = 'Установлена актуальная версия';
  } catch (e) {
    if (manual) message = errText(e);
  } finally {
    checking = false;
    paint();
  }
}

function confirmUpdate() {
  const version = available;
  if (store.view.portable) {
    invoke('open_url', { url: 'https://github.com/QpenderFTP/ReTunl/releases/tag/v' + version })
      .catch(e => toast(errText(e), { kind: 'error' }));
    return;
  }
  const d = dialog({
    title: 'Обновить ReTunl до ' + version + '?',
    body: h('p', isAndroid() ? 'После загрузки APK Android попросит подтвердить установку.'
      : 'На время установки ReTunl отключит VPN. Система может запросить права администратора.'),
    actions: [
      h('button.btn', { onclick: () => d.close() }, 'Позже'),
      h('button.btn.primary', { onclick: () => {
        d.close();
        installUpdate(version);
      } }, 'Установить'),
    ],
  });
}

export async function installUpdate(version) {
  if (installing) return;
  available = version;
  installing = true;
  message = 'Скачиваю и проверяю установщик…';
  paint();
  try {
    await invoke('install_update', { version });
    message = 'Установщик открыт';
  } catch (e) {
    message = errText(e);
    toast(message, { kind: 'error' });
  } finally {
    installing = false;
    paint();
  }
}
