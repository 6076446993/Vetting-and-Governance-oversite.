import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { enforce } from './firewall.mjs';

const ALLOWED = ['encrypted-custody.mjs', 'encrypted-custody.test.mjs', 'firewall.mjs', 'firewall.test.mjs', 'verify.mjs', 'verify.test.mjs', 'worker-export.mjs', 'worker-export.test.mjs', 'workflow.test.mjs'];
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oversight-firewall-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.mkdirSync(path.join(root, 'oversight'));
  const target = path.join(root, 'target');
  fs.mkdirSync(path.join(target, 'src'), { recursive: true });
  fs.writeFileSync(path.join(target, 'src', 'scientificLearning.js'), '');
  fs.writeFileSync(path.join(root, '.github', 'workflows', 'independent-oversight.yml'), 'permissions:\n  contents: read\nrepository: 6076446993/The-Crucible\nrepository: 6076446993/Learning-Worker\npersist-credentials: false\npersist-credentials: false\npersist-credentials: false\narchive-oversight-report:\n  environment: vetted-return\n  permissions:\n    contents: write\nreturn-vetted-data:\n  environment: vetted-return\n  permissions:\n    contents: read\n');
  for (const file of ALLOWED) fs.writeFileSync(path.join(root, 'oversight', file), 'export const independent = true;');
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
