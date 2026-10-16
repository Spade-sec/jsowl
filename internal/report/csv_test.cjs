const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

// csv.js is a plain browser module that attaches itself to `window`; loading
// it in a VM with a minimal global is enough to exercise it directly.
function load() {
  const source = fs.readFileSync(path.join(__dirname, 'assets/csv.js'), 'utf8');
  const sandbox = { window: {} };
  vm.runInNewContext(source, sandbox);
  return sandbox.window.JsOwlCSV;
}

test('plain fields are emitted unchanged', () => {
  const csv = load();
  assert.equal(csv.cell('high'), 'high');
  assert.equal(csv.cell('https://example.test/api/users?id=1'), 'https://example.test/api/users?id=1');
  assert.equal(csv.cell(42), '42');
  assert.equal(csv.cell(null), '');
  assert.equal(csv.cell(undefined), '');
});

test('commas, quotes and newlines are quoted per RFC 4180', () => {
  const csv = load();
  assert.equal(csv.cell('a,b'), '"a,b"');
  assert.equal(csv.cell('say "hi"'), '"say ""hi"""');
  assert.equal(csv.cell('line1\nline2'), '"line1\nline2"');
  assert.equal(csv.cell('line1\r\nline2'), '"line1\r\nline2"');
});

test('spreadsheet formula prefixes are neutralised', () => {
  const csv = load();
  for (const dangerous of ['=1+1', '=cmd|\' /c calc\'!A0', '+1', '-1', '@SUM(1)', '\ttab', '\rcr']) {
    const cell = csv.cell(dangerous);
    assert.equal(cell.startsWith("'") || cell.startsWith('"\''), true, `not neutralised: ${JSON.stringify(cell)}`);
  }
  assert.equal(csv.cell('=1+1'), "'=1+1");
  // A quoted formula keeps both the guard and the quoting.
  assert.equal(csv.cell('=a,b'), '"\'=a,b"');
});

test('the guard is applied to the export only, never to the source rows', () => {
  const csv = load();
  const rows = [['=1+1', 'name', 'a,b']];
  const snapshot = JSON.stringify(rows);
  const text = csv.build(['值', '规则', '备注'], rows);
  assert.equal(JSON.stringify(rows), snapshot, 'build must not mutate the caller\'s rows');
  assert.ok(text.includes("'=1+1"), text);
  // The unguarded original is still exactly what the caller passed in.
  assert.equal(rows[0][0], '=1+1');
});

test('build joins header and rows with CRLF and keeps the header order', () => {
  const csv = load();
  const text = csv.build(['编号', '完整值'], [['G001', 'x'], ['G002', 'y']]);
  assert.equal(text, '编号,完整值\r\nG001,x\r\nG002,y');
  assert.equal(text.split('\r\n').length, 3);
});

test('file names stay inside a safe character set and pin the scope', () => {
  const csv = load();
  const name = csv.fileName('findings-grouped', 'https://shop.example.test/app?from=scan', 12);
  assert.ok(name.startsWith('jsowl-findings-grouped-'), name);
  assert.ok(name.endsWith('-12.csv'), name);
  assert.ok(name.includes('shop.example.test'), name);
  assert.ok(!/[\\/:*?"<>|]/.test(name), name);
  assert.equal(csv.fileName('endpoints', '', 0), 'jsowl-endpoints-report-0.csv');
});
