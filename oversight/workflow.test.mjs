import crypto from 'node:crypto';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'independent-oversight.yml'), 'utf8');

function runHistoricalSummary(t,version){
  const temporary=fs.mkdtempSync(path.join(os.tmpdir(),'historical-summary-'));
  t.after(()=>fs.rmSync(temporary,{recursive:true,force:true}));
  const match=workflow.match(/node --input-type=module <<'EVIDENCE'\n([\s\S]*?)\n          EVIDENCE/);
  assert.ok(match);
  fs.writeFileSync(path.join(temporary,'historical-key-report.json'),JSON.stringify({schemaVersion:1,state:'HELD',versions:[version]}));
  const summary=path.join(temporary,'summary.md');
  const result=spawnSync(process.execPath,['--input-type=module'],{input:match[1].replace(/^          /gm,''),cwd:temporary,encoding:'utf8',env:{...process.env,GITHUB_STEP_SUMMARY:summary}});
  return {result,text:fs.existsSync(summary)?fs.readFileSync(summary,'utf8'):''};
}
test('actual historical summary preserves pre-key phase and boolean identity evidence',t=>{
  const {result,text}=runHistoricalSummary(t,{encryptedSha256:'a'.repeat(64),state:'HELD',attempts:[],phase:'header-identity',identityMatches:{projectId:true,repository:false,ref:true}});
  assert.equal(result.status,0,result.stderr);
  assert.match(text,/not-tested.*header-identity.*repository:mismatch/);
});
test('actual historical summary rejects unbounded phase text before publication',t=>{
  const {result,text}=runHistoricalSummary(t,{encryptedSha256:'a'.repeat(64),state:'HELD',attempts:[],phase:'untrusted-source-content'});
  assert.notEqual(result.status,0);assert.equal(text,'');
});

test('custody publication does not depend on Actions artifact quota', () => {
  assert.doesNotMatch(workflow, /actions\/(?:upload|download)-artifact/);
  assert.match(workflow, /archive-oversight-report:[\s\S]*?if: always\(\)/);
  assert.match(workflow, /return-vetted-data:[\s\S]*?needs\.oversight\.result == 'success'/);
});

test('additive report preservation occurs before the original oversight failure', () => {
  const preserve = workflow.indexOf('Preserve the original oversight report as an additive job output');
  const fail = workflow.indexOf('Fail after preserving independent evidence');
  assert.ok(preserve > 0 && fail > preserve);
  assert.match(workflow, /steps\.audit\.outcome == 'failure'[\s\S]*?run: exit 1/);
});

test('worker custody is exact-tip and stale-lineage bound before publication', () => {
  assert.match(workflow, /ref: oversight-export/);
  assert.match(workflow, /python oversight\/worker_archive\.py[^\r\n]+worker-state\.zip[^\r\n]+worker-root/);
  assert.doesNotMatch(workflow, /unzip -q[^\r\n]+worker-state\.zip/);
  assert.match(workflow, /worker_sha=\$\(git -C learning-worker rev-parse HEAD\)/);
  assert.match(workflow, /vetted_state_sha=\$\(git -C "\$RUNNER_TEMP\/vetted-state" rev-parse HEAD\)/);
  assert.match(workflow, /worker-export\.mjs merge[^\r\n]+--worker-sha "\$worker_sha"[^\r\n]+--vetted-state-sha "\$vetted_state_sha"/);
  const merge = workflow.indexOf('worker-export.mjs merge');
  const enforce = workflow.indexOf('encrypted-custody.mjs enforce-vetting');
  const postMergeVerification = workflow.indexOf('post-merge-custody.json');
  const encrypt = workflow.indexOf('encrypted-custody.mjs encrypt-vetted');
  assert.ok(enforce > 0 && merge > enforce && postMergeVerification > merge && encrypt > postMergeVerification);
});

test('worker archive compatibility and safety tests run before custody merge', () => {
  assert.match(workflow, /python -m unittest oversight\.worker_archive_test/);
  assert.ok(workflow.indexOf('python -m unittest oversight.worker_archive_test') < workflow.indexOf('python oversight/worker_archive.py'));
  assert.match(workflow, /Erase temporary plaintext custody[\s\S]*?if:\s*always\(\)[\s\S]*?rm -rf[^\r\n]+RUNNER_TEMP\/custody/);
  assert.ok(workflow.indexOf('Sign and publish only the independently approved ciphertext') < workflow.indexOf('Erase temporary plaintext custody'));
});

test('historical preflight supplies five canonical checksum records matching actual diagnostic bytes', () => {
  const block = workflow.match(/sha256sum --check <<'PINNED'\n([\s\S]*?)\n {10}PINNED/);
  assert.ok(block, 'required checksum guard must exist');
  const rows = block[1].split('\n').map(line => line.slice(10));
  assert.equal(rows.length, 5);
  const paths = [];
  for (const row of rows) {
    const record = row.match(/^([a-f0-9]{64})  (oversight\/[a-z0-9.-]+)$/);
    assert.ok(record, 'checksum records must start with the digest after YAML indentation is removed');
    paths.push(record[2]);
    const bytes = fs.readFileSync(path.join(root, record[2]));
    assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), record[1], record[2]);
  }
  assert.deepEqual(paths.sort(), ['oversight/encrypted-custody.mjs', 'oversight/historical-key-batch.mjs', 'oversight/historical-key-probe.mjs', 'oversight/raw-history-pins.json', 'oversight/verify.mjs'].sort());
});
