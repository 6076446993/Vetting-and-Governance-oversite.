import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ALLOWED_MODULES = new Set(['encrypted-custody.mjs', 'encrypted-custody.test.mjs', 'firewall.mjs', 'firewall.test.mjs', 'verify.mjs', 'verify.test.mjs', 'worker-export.mjs', 'worker-export.test.mjs', 'workflow.test.mjs', 'historical-key-batch.mjs', 'historical-key-batch.test.mjs', 'historical-key-probe.mjs', 'historical-key-probe.test.mjs', 'historical-key-probe-race.test.mjs']);
const PINNED_HISTORICAL_BATCH_SHA256 = '4cea5daa0884d725e5914a0e74335b00bb0decd59b6e707c253604fdb625410f';
const APPROVED_GIT_SUBPROCESS_IMPORT = /node:child_process/i;
const FORBIDDEN_RUNTIME_PATTERNS = [
  /from\s+['"](?:\.\.\/)*target/i,
  /require\s*\([^)]*target/i,
  APPROVED_GIT_SUBPROCESS_IMPORT,
  /process\.env\.(?:GITHUB_TOKEN|GH_TOKEN)/i,
  /secrets\./i,
  /https?:\/\/(?!github\.com\/6076446993\/The-Crucible)/i,
];

export function enforce(oversightRoot, targetRoot, workerRoot = null) {
  const workflow = fs.readFileSync(path.join(oversightRoot, '.github', 'workflows', 'independent-oversight.yml'), 'utf8');
  const writePermissions = workflow.match(/contents:\s*write/g) || [];
  if (!/^permissions:\s*\r?\n\s*contents:\s*read/m.test(workflow)
      || writePermissions.length !== 1
      || !/archive-oversight-report:[\s\S]*?environment:\s*vetted-return[\s\S]*?permissions:\s*\r?\n\s*contents:\s*write/.test(workflow)
      || !/return-vetted-data:[\s\S]*?environment:\s*vetted-return[\s\S]*?permissions:\s*\r?\n\s*contents:\s*read/.test(workflow)
      || /issues:\s*write|actions:\s*write/.test(workflow)) {
    throw new Error('Oversight workflow permissions exceed read-only.');
  }
  if (!/repository:\s*6076446993\/The-Crucible/.test(workflow)
      || !/repository:\s*6076446993\/Learning-Worker/.test(workflow)
      || (workflow.match(/persist-credentials:\s*false/g) || []).length < 3) {
    throw new Error('Oversight checkout identity or credential isolation failed.');
  }
  const moduleNames = fs.readdirSync(path.join(oversightRoot, 'oversight')).filter((item) => /\.(?:mjs|js)$/.test(item));
  const unexpected = moduleNames.filter((item) => !ALLOWED_MODULES.has(item));
  if (unexpected.length > 0) throw new Error(`Oversight firewall rejected unauthorized modules: ${unexpected.join(', ')}.`);
  // Only the exact independently reviewed historical Git reader can import
  // node:child_process. Any byte change fails closed before capability scanning.
  if (!moduleNames.includes('historical-key-batch.mjs')) throw new Error('Historical batch module is missing.');
  const historicalBatch = fs.readFileSync(path.join(oversightRoot, 'oversight', 'historical-key-batch.mjs'));
  const actualDigest = crypto.createHash('sha256').update(historicalBatch).digest('hex');
  if (actualDigest !== PINNED_HISTORICAL_BATCH_SHA256) throw new Error('Historical batch integrity mismatch.');
  // The firewall declares the forbidden patterns, so scanning its own policy
  // source would treat those declarations as runtime capabilities. Its
  // behavior is covered by firewall.test.mjs; scan every operational module.
  for (const moduleName of moduleNames.filter((item) => !item.includes('.test.') && item !== 'firewall.mjs')) {
    const source = fs.readFileSync(path.join(oversightRoot, 'oversight', moduleName), 'utf8');
    for (const pattern of FORBIDDEN_RUNTIME_PATTERNS) {
      if (moduleName === 'historical-key-batch.mjs' && pattern === APPROVED_GIT_SUBPROCESS_IMPORT) continue;
      if (pattern.test(source)) throw new Error(`Oversight firewall rejected ${moduleName} capability: ${pattern}.`);
    }
  }
  if (!fs.existsSync(path.join(targetRoot, 'src', 'scientificLearning.js'))) throw new Error('Exact Crucible target checkout is unavailable.');
  if (workerRoot && !fs.existsSync(workerRoot)) throw new Error('Exact Learning Worker checkout is unavailable.');
  return { state: 'isolated', assimilatesData: false, sharedRuntimeImports: 0, writePermissions: 0, persistedCredentials: 0, targetMutationAuthorized: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(enforce(path.resolve(process.argv[2]), path.resolve(process.argv[3]), process.argv[4] ? path.resolve(process.argv[4]) : null)));
}
