'use strict';
const form = document.querySelector('#config-form');
if (form) {
  const parts = JSON.parse(document.querySelector('#parts-data').textContent);
  const total = document.querySelector('#total');
  const box = document.querySelector('#compatibility');
  const button = document.querySelector('#add-button');
  const rub = value => new Intl.NumberFormat('ru-RU').format(value) + ' ₽';
  let controller;
  async function update() {
    if (controller) controller.abort();
    controller = new AbortController();
    button.disabled = true;
    total.textContent = '…';
    box.textContent = 'Проверяем совместимость…';
    box.className = 'compatibility';
    document.querySelector('#watts').textContent = '';
    for (const [key, options] of Object.entries(parts)) {
      const item = options.find(p => p.id === form.elements[key].value);
      document.querySelector('#detail-' + key).textContent = item.detail;
    }
    try {
      const response = await fetch('/api/quote', {method:'POST', body:new FormData(form), signal:controller.signal});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Не удалось обновить цену');
      total.textContent = rub(data.total);
      box.className = 'compatibility ' + (data.errors.length ? 'incompatible' : 'compatible');
      box.replaceChildren();
      if (data.errors.length) {
        const heading = document.createElement('strong');
        heading.textContent = 'Нужно изменить сборку';
        const list = document.createElement('ul');
        data.errors.forEach(message => { const li = document.createElement('li'); li.textContent = message; list.append(li); });
        box.append(heading, list);
      } else {
        box.textContent = '✓ Основные параметры совместимы';
        button.disabled = false;
      }
      document.querySelector('#watts').textContent = 'Расчётная мощность БП с запасом: от ' + data.watts + ' Вт';
    } catch (error) {
      if (error.name === 'AbortError') return;
      box.textContent = 'Не удалось проверить сборку. Обновите страницу или выберите детали ещё раз.';
      box.className = 'compatibility incompatible';
    }
  }
  form.addEventListener('change', update);
  update();
}
