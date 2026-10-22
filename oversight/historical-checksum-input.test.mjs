import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
test('historical preflight supplies five canonical checksum records matching actual diagnostic bytes', () => {
  const workflow = fs.readFileSync(new URL('.github/workflows/independent-oversight.yml', root), 'utf8');
  const block = workflow.match(/sha256sum --check <<'PINNED'\n([\s\S]*?)\n {10}PINNED/);
  assert.ok(block, 'required checksum guard must exist');
  const rows = block[1].split('\n').map(line => line.slice(10));
  assert.equal(rows.length, 5);
  const paths = [];
  for (const row of rows) {
    const record = row.match(/^([a-f0-9]{64})  (oversight\/[a-z0-9.-]+)$/);
    assert.ok(record, 'checksum records must start with the digest after YAML indentation is removed');
    paths.push(record[2]);
    const bytes = fs.readFileSync(fileURLToPath(new URL(record[2], root)));
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), record[1], record[2]);
  }
  assert.deepEqual(paths.sort(), ['oversight/encrypted-custody.mjs', 'oversight/historical-key-batch.mjs', 'oversight/historical-key-probe.mjs', 'oversight/raw-history-pins.json', 'oversight/verify.mjs'].sort());
});
