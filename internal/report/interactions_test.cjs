const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function element(textContent = '') {
  return {
    textContent, dataset: {}, style: {}, attributes: {}, events: {},
    classList: { contains: () => false },
    setAttribute(key, value) { this.attributes[key] = value; },
    addEventListener(key, handler) { this.events[key] = handler; },
    querySelector() { return null; }
  };
}

function fixture({ sensitive = false, count = 55, details = false, parameter = false } = {}) {
  const rows = Array.from({ length: count }, (_, index) => {
    const row = element('secret-' + index);
    row.dataset = { severity: index % 2 ? 'high' : 'low', rule: 'Token', source: 'app.js' };
    row.cells = [element(String(count - index))];
    row.nextElementSibling = null;
    return row;
  });
  const allRows = rows.flatMap(row => {
    if (!details) return [row];
    const detail = element('context');
    detail.classList.contains = name => ['ctx-row', 'open'].includes(name);
    row.nextElementSibling = detail;
    return [row, detail];
  });
  const tbody = { rows: allRows, appendChild(row) {
    this.rows.splice(this.rows.indexOf(row), 1); this.rows.push(row);
  } };
  const header = element('次数');
  const table = element();
  table.id = sensitive ? 'sensitive-table' : parameter ? 'param-table' : '';
  table.tBodies = [tbody]; table.tHead = { rows: [{ cells: [header] }] };
  table.classList.contains = name => name === 'paginated';
  table.after = pager => { table.pager = pager; };
  const controls = ['severity', 'rule', 'source'].map(key => {
    const control = element(); control.dataset.filter = key; control.value = '';
    control.appendChild = () => {}; return control;
  });
  const search = element(); search.value = '';
  const reset = element(), counter = element(), filters = element();
  filters.querySelector = selector => selector === 'input' ? search : selector === 'button' ? reset : controls.find(c => selector.includes('"' + c.dataset.filter + '"'));
  filters.querySelectorAll = selector => selector === '[data-filter]' ? controls : [...controls, search];
  const document = {
    querySelectorAll: () => [table], createElement: () => element(),
    getElementById: id => id === 'sensitive-filters' ? filters : counter
  };
  const helpers = fs.readFileSync(path.join(__dirname, 'assets/interactions.js'), 'utf8');
  const split = fs.readFileSync(path.join(__dirname, 'split.go'), 'utf8');
  const controller = split.slice(split.indexOf("  document.querySelectorAll('table').forEach"), split.indexOf('  // Row detail panel:'));
  vm.runInNewContext(helpers + '\n' + controller, { document, Intl });
  return { rows, tbody, header, table, controls, search, reset, filters, counter };
}

test('sorting uses all pages, toggles direction, and supports the keyboard', () => {
  const f = fixture();
  assert.equal(f.rows.filter(row => row.style.display !== 'none').length, 50);
  f.header.events.click();
  assert.equal(f.tbody.rows[0].cells[0].textContent, '1');
  assert.equal(f.rows[54].style.display, '');
  assert.equal(f.header.attributes['aria-sort'], 'ascending');
  f.header.events.keydown({ key: 'Enter', preventDefault() {} });
  assert.equal(f.tbody.rows[0].cells[0].textContent, '55');
  assert.equal(f.header.attributes['aria-sort'], 'descending');
});

test('sensitive filters combine with search, sorting, pagination and reset', () => {
  const f = fixture({ sensitive: true });
  f.controls[0].value = 'high'; f.filters.events.change();
  assert.equal(f.counter.textContent, '显示 27 / 55 条');
  f.header.events.click();
  assert.equal(f.rows.filter(row => row.style.display !== 'none').length, 27);
  f.search.value = 'secret-1'; f.filters.events.input();
  assert.equal(f.counter.textContent, '显示 6 / 55 条');
  f.search.value = 'missing'; f.filters.events.input();
  assert.equal(f.counter.textContent, '显示 0 / 55 条');
  f.reset.events.click();
  assert.equal(f.counter.textContent, '显示 55 / 55 条');
  f.table.pager.events.click({ target: { dataset: { go: 'next' } } });
  assert.equal(f.rows.filter(row => row.style.display !== 'none').length, 5);
  f.header.events.click();
  assert.equal(f.rows.filter(row => row.style.display !== 'none').length, 50);
});

test('API details stay with their parent rows through sorting and pagination', () => {
  const f = fixture({ details: true });
  f.header.events.click();
  for (let i = 0; i < f.tbody.rows.length; i += 2) {
    const row = f.tbody.rows[i], detail = f.tbody.rows[i + 1];
    assert.equal(detail, row.nextElementSibling);
    assert.equal(detail.style.display, row.style.display);
  }
  assert.equal(f.rows.filter(row => row.style.display !== 'none').length, 50);
});

test('parameter sorting preserves the visibility set by existing filters', () => {
  const f = fixture({ parameter: true, count: 3 });
  f.rows[1].style.display = 'none';
  f.header.events.click();
  assert.equal(f.rows[1].style.display, 'none');
  assert.equal(f.tbody.rows[0], f.rows[2]);
});
