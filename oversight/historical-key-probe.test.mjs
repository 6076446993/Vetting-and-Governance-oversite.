import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {probe} from './historical-key-probe.mjs';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function fixture(t,changes={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'custody-probe-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const key=crypto.randomBytes(32),plain=Buffer.from('synthetic historical custody'),iv=crypto.randomBytes(12);
 const h={magic:'CRUCIBLE-SOURCE-BUNDLE-V1',algorithm:'aes-256-gcm',projectId:'github:jonathanblunt1214-lgtm/The-Crucible',repository:'6076446993/The-Crucible',ref:'refs/heads/development',iv:iv.toString('base64'),plaintextBytes:plain.length,plaintextSha256:sha(plain),...changes};
 const aad=Buffer.from(JSON.stringify(h)+'\n'),c=crypto.createCipheriv('aes-256-gcm',key,iv);c.setAAD(aad);
 const bytes=Buffer.concat([aad,c.update(plain),c.final(),c.getAuthTag()]),input=path.join(root,'input.enc');fs.writeFileSync(input,bytes);
 return {root,input,bytes,expectedSha256:sha(bytes),env:{CRUCIBLE_SOURCE_BUNDLE_KEY:key.toString('base64')},plain};
}
test('retained key authenticates without creating plaintext or authorizing recovery',t=>{const f=fixture(t),r=probe(f);assert.equal(r.state,'AUTHENTICATED_ONLY');assert.equal(r.restartAuthorized,false);assert.equal(r.populationVerified,false);assert.deepEqual(fs.readdirSync(f.root),['input.enc']);assert.ok(!JSON.stringify(r).includes(f.env.CRUCIBLE_SOURCE_BUNDLE_KEY));assert.ok(!JSON.stringify(r).includes(f.plain.toString()));});
test('old key in previous slot works when current does not',t=>{const f=fixture(t);f.env.CRUCIBLE_SOURCE_BUNDLE_KEY_PREVIOUS=f.env.CRUCIBLE_SOURCE_BUNDLE_KEY;f.env.CRUCIBLE_SOURCE_BUNDLE_KEY=crypto.randomBytes(32).toString('base64');const r=probe(f);assert.deepEqual(r.attempts.map(a=>a.state),['authentication-refused','authenticated']);});
test('wrong key stays held',t=>{const f=fixture(t);f.env.CRUCIBLE_SOURCE_BUNDLE_KEY=crypto.randomBytes(32).toString('base64');assert.equal(probe(f).state,'HELD');});
test('hash mismatch is refused before key attempts',t=>{const f=fixture(t);f.expectedSha256='0'.repeat(64);assert.deepEqual(probe(f).attempts,[]);});
test('tampered ciphertext with updated external hash still fails AEAD',t=>{const f=fixture(t);f.bytes[f.bytes.length-18]^=1;fs.writeFileSync(f.input,f.bytes);f.expectedSha256=sha(f.bytes);assert.equal(probe(f).state,'HELD');});
for(const [name,changes] of Object.entries({wrongRepository:{repository:'other/repo'},wrongRef:{ref:'refs/heads/main'},wrongProject:{projectId:'other'},wrongLength:{plaintextBytes:1},wrongDigest:{plaintextSha256:'0'.repeat(64)},invalidIv:{iv:'invalid'}}))test(name+' is refused',t=>assert.equal(probe(fixture(t,changes)).state,'HELD'));
test('missing and malformed keys remain unavailable',t=>{const f=fixture(t);f.env={CRUCIBLE_SOURCE_BUNDLE_KEY:'malformed'};const r=probe(f);assert.equal(r.state,'HELD');assert.ok(r.attempts.every(a=>a.state==='unavailable'));});
test('symlinks are refused',t=>{const f=fixture(t),link=path.join(f.root,'link');fs.symlinkSync(f.input,link);f.input=link;assert.equal(probe(f).state,'HELD');});
test('truncation is refused',t=>{const f=fixture(t);fs.writeFileSync(f.input,f.bytes.subarray(0,-1));f.expectedSha256=sha(fs.readFileSync(f.input));assert.equal(probe(f).state,'HELD');});
test('authenticated attempt identifies the actual candidate key by fingerprint only',t=>{
 const f=fixture(t),r=probe(f);
 assert.equal(r.attempts.find(a=>a.state==='authenticated').keyFingerprint,sha(Buffer.from(f.env.CRUCIBLE_SOURCE_BUNDLE_KEY,'base64')));
 assert.ok(!JSON.stringify(r).includes(f.env.CRUCIBLE_SOURCE_BUNDLE_KEY));
});
