import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { enforce } from './firewall.mjs';

const ALLOWED = ['encrypted-custody.mjs', 'encrypted-custody.test.mjs', 'firewall.mjs', 'firewall.test.mjs', 'verify.mjs', 'verify.test.mjs', 'worker-export.mjs', 'worker-export.test.mjs', 'workflow.test.mjs', 'historical-key-batch.mjs', 'historical-key-batch.test.mjs', 'historical-key-probe.mjs', 'historical-key-probe.test.mjs', 'historical-key-probe-race.test.mjs'];
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oversight-firewall-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.mkdirSync(path.join(root, 'oversight'));
  const target = path.join(root, 'target');
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'scientificLearning.js'), '');
  fs.writeFileSync(path.join(root, '.github', 'workflows', 'independent-oversight.yml'), 'permissions:\n  contents: read\nrepository: 6076446993/The-Crucible\nrepository: 6076446993/Learning-Worker\npersist-credentials: false\npersist-credentials: false\npersist-credentials: false\narchive-oversight-report:\n  environment: vetted-return\n  permissions:\n    contents: write\nreturn-vetted-data:\n  environment: vetted-return\n  permissions:\n    contents: read\n');
  // The exceptional read-only Git history adapter must exactly match the
  // reviewed deployed source; synthetic copies would correctly be rejected.
  for (const file of ALLOWED) {
    const content = file === 'historical-key-batch.mjs'
      ? fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), file), 'utf8')
      : 'export const independent = true;';
    fs.writeFileSync(path.join(root, 'oversight', file), content);
  }
  return { root, target };
}

test('oversight remains non-assimilating and read-only', () => {
  const { root, target } = fixture();
  try {
    const result = enforce(root, target);
    assert.equal(result.state, 'isolated');
    assert.equal(result.assimilatesData, false);
    assert.equal(result.targetMutationAuthorized, false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('firewall rejects undeclared executable modules', () => {
  const { root, target } = fixture();
  try {
    fs.writeFileSync(path.join(root, 'oversight', 'unsafe.mjs'), "import '../../target/src/scientificLearning.js';");
    assert.throws(() => enforce(root, target), /unauthorized modules/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

for (const repository of ['6076446993/The-Crucible', '6076446993/Learning-Worker']) {
  test(`firewall rejects a stale or unrelated checkout for ${repository}`, () => {
    const { root, target } = fixture();
    try {
      const workflow = path.join(root, '.github', 'workflows', 'independent-oversight.yml');
      const source = fs.readFileSync(workflow, 'utf8');
      for (const owner of ['jonathanblunt1214-lgtm', 'unrelated-owner']) {
        fs.writeFileSync(workflow, source.replace(repository, repository.replace('6076446993', owner)));
        assert.throws(() => enforce(root, target), /checkout identity/);
      }
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
}

test('firewall still rejects persisted checkout credentials', () => {
  const { root, target } = fixture();
  try {
    const workflow = path.join(root, '.github', 'workflows', 'independent-oversight.yml');
    fs.writeFileSync(workflow, fs.readFileSync(workflow, 'utf8').replace('persist-credentials: false', 'persist-credentials: true'));
    assert.throws(() => enforce(root, target), /credential isolation/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});


test('firewall rejects any change to the narrowly approved historical Git reader', () => {
  const { root, target } = fixture();
  try {
    fs.appendFileSync(path.join(root, 'oversight', 'historical-key-batch.mjs'), '\n// change after independent review');
    assert.throws(() => enforce(root, target), /Historical batch integrity mismatch/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('firewall continues to reject subprocess access from other diagnostic modules', () => {
  const { root, target } = fixture();
  try {
    fs.writeFileSync(path.join(root, 'oversight', 'historical-key-probe.mjs'), "import {spawnSync} from 'node:child_process';");
    assert.throws(() => enforce(root, target), /capability/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});


test('actual repository tree satisfies the production separation firewall', t => {
  const actualRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'oversight-actual-tree-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const target = path.join(temporary, 'target');
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'scientificLearning.js'), '');
  const result = enforce(actualRoot, target);
  assert.equal(result.state, 'isolated');
  assert.equal(result.targetMutationAuthorized, false);
});
