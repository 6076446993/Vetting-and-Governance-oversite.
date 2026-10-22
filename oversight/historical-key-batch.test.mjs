import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {runBatch} from './historical-key-batch.mjs';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(t,{tamper=false,foreign=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'pinned-batch-fixture-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const git=(...a)=>execFileSync('git',['-C',root,...a],{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
 git('init','-b','main');git('config','user.name','Synthetic Test');git('config','user.email','synthetic@example.invalid');
 const pins=[],keys=[];
 for(let i=0;i<2;i++){
  const key=crypto.randomBytes(32),iv=crypto.randomBytes(12),plain=Buffer.from(`synthetic private fixture ${i}`);keys.push(key.toString('base64'));
  const h={magic:'CRUCIBLE-SOURCE-BUNDLE-V1',algorithm:'aes-256-gcm',projectId:'github:jonathanblunt1214-lgtm/The-Crucible',repository:foreign&&i===1?'other/repo':'6076446993/The-Crucible',ref:'refs/heads/development',iv:iv.toString('base64'),plaintextBytes:plain.length,plaintextSha256:sha(plain)};
  const aad=Buffer.from(JSON.stringify(h)+'\n'),c=crypto.createCipheriv('aes-256-gcm',key,iv);c.setAAD(aad);
  const bytes=Buffer.concat([aad,c.update(plain),c.final(),c.getAuthTag()]);if(tamper&&i===1)bytes[bytes.length-1]^=1;
  const name='source-bundle.part-0000.enc',m={schemaVersion:1,format:'CRUCIBLE-SOURCE-BUNDLE-V1',encryptedSha256:sha(bytes),encryptedBytes:bytes.length,chunks:[{name,bytes:bytes.length,sha256:sha(bytes)}]};
  const manifest=JSON.stringify(m)+'\n';fs.writeFileSync(path.join(root,name),bytes);fs.writeFileSync(path.join(root,'encrypted-chunks.json'),manifest);
  git('add','.');git('commit','-m',`synthetic version ${i}`);
  pins.push({commit:git('rev-parse','HEAD'),manifestPath:'encrypted-chunks.json',manifestSha256:sha(manifest),encryptedSha256:sha(bytes)});
 }
 return {root,git,pins,keys,expectedHead:git('rev-parse','HEAD'),env:{CRUCIBLE_SOURCE_BUNDLE_KEY:keys[0],CRUCIBLE_SOURCE_BUNDLE_KEY_PREVIOUS:keys[1]}};
}
test('real isolated Git versions reuse existing joiner and probe with both retained slots',t=>{
 const f=fixture(t),before=f.git('status','--porcelain');const r=runBatch({stateRoot:f.root,...f});
 assert.equal(r.state,'AUTHENTICATED_ONLY');assert.equal(r.versions.length,2);assert.ok(r.cleanupVerified);
 assert.ok(r.versions.every(v=>v.attempts.some(a=>a.state==='authenticated')));
 assert.equal(r.independentRecoveryAccepted,false);assert.equal(r.populationVerified,false);assert.equal(r.escrowVerified,false);assert.equal(r.restartAuthorized,false);
 assert.equal(f.git('status','--porcelain'),before);assert.ok(!JSON.stringify(r).includes('synthetic private fixture'));
 for(const k of f.keys)assert.ok(!JSON.stringify(r).includes(k));
});
test('one altered authenticated tag retains partial results and refuses batch success',t=>{
 const f=fixture(t,{tamper:true}),r=runBatch({stateRoot:f.root,...f});
 assert.equal(r.state,'HELD');assert.equal(r.versions[0].state,'AUTHENTICATED_ONLY');assert.equal(r.versions[1].state,'HELD');assert.ok(r.cleanupVerified);
});
test('unknown historical identity stays held without widening the probe boundary',t=>{
 const f=fixture(t,{foreign:true}),r=runBatch({stateRoot:f.root,...f});assert.equal(r.state,'HELD');assert.equal(r.versions[1].state,'HELD');
 assert.equal(r.versions[1].phase,'header-identity');
 assert.deepEqual(r.versions[1].identityMatches,{projectId:true,repository:false,ref:true});
 assert.equal(r.versions[1].reason,'INPUT_OR_AUTHENTICATION_REFUSED');
});
test('wrong manifest hash refuses before reading a candidate secret',t=>{
 const f=fixture(t);f.pins=[{...f.pins[0],manifestSha256:'0'.repeat(64)}];let reads=0;
 const env=new Proxy({},{get(){reads++;return f.keys[0];}}),r=runBatch({stateRoot:f.root,...f,env});
 assert.equal(r.state,'HELD');assert.equal(reads,0);assert.equal(r.versions[0].reason,'PINNED_INPUT_OR_AUTHENTICATION_REFUSED');
});
test('wrong captured head and duplicate ciphertext pins refuse before processing',t=>{
 const f=fixture(t);
 assert.equal(runBatch({stateRoot:f.root,...f,expectedHead:'0'.repeat(40)}).versions.length,0);
 assert.equal(runBatch({stateRoot:f.root,...f,pins:[f.pins[0],f.pins[0]]}).versions.length,0);
});
test('all missing keys remain bounded, retain both failures and grant no acceptance',t=>{
 const f=fixture(t),r=runBatch({stateRoot:f.root,...f,env:{}});assert.equal(r.state,'HELD');assert.equal(r.versions.length,2);assert.ok(r.versions.every(v=>v.attempts.every(a=>a.state==='unavailable')));assert.equal(r.restartAuthorized,false);
});
