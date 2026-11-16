const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

// Capture fetch arguments without making network requests. Run both branch values.
const fixtures = path.resolve(__dirname, '../../testdata/api-restore-counterexamples');
for (const file of fs.readdirSync(fixtures).filter(name => name.endsWith('.js')).sort()) {
  const values = new Set();
  for (const flag of [false, true]) {
    vm.runInNewContext(fs.readFileSync(path.join(fixtures, file), 'utf8'), {
      URL, flag, getRuntimeBase: () => '/runtime',
      fetch: value => { values.add(String(value)); },
    }, { timeout: 1000, filename: file });
  }
  console.log(`${file}\t${JSON.stringify([...values])}`);
}
