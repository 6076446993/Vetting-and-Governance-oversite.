import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {probe} from './historical-key-probe.mjs';

const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
for(const region of ['header','tag']) test(`reject ${region} mutation after initial hash despite restored mtime`,t=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'custody-probe-race-'));
  t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
  const key=crypto.randomBytes(32),plain=Buffer.from('synthetic only'),iv=crypto.randomBytes(12);
  const h={magic:'CRUCIBLE-SOURCE-BUNDLE-V1',algorithm:'aes-256-gcm',projectId:'github:jonathanblunt1214-lgtm/The-Crucible',repository:'6076446993/The-Crucible',ref:'refs/heads/development',iv:iv.toString('base64'),plaintextBytes:plain.length,plaintextSha256:sha(plain)};
  const aad=Buffer.from(JSON.stringify(h)+'\n'),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);
  cipher.setAAD(aad);
  const original=Buffer.concat([aad,cipher.update(plain),cipher.final(),cipher.getAuthTag()]);
  const input=path.join(root,'input.enc');fs.writeFileSync(input,original);
  const fixed=new Date('2026-10-19T10:00:00.000Z');fs.utimesSync(input,fixed,fixed);
  const env={};let changed=false;
  Object.defineProperty(env,'CRUCIBLE_SOURCE_BUNDLE_KEY',{get(){
    if(!changed){const fd=fs.openSync(input,'r+');try{const b=Buffer.from(original);b[region==='tag'?b.length-1:0]^=1;fs.writeSync(fd,b,0,b.length,0);}finally{fs.closeSync(fd);}fs.utimesSync(input,fixed,fixed);changed=true;}
    return key.toString('base64');
  }});
  const r=probe({input,expectedSha256:sha(original),env});
  assert.notEqual(sha(fs.readFileSync(input)),sha(original));
  assert.equal(r.state,'HELD','changed original must not retain a successful authentication result');
  assert.ok(r.attempts.every(a=>a.state!=='authenticated'),'invalidate any partial successful attempt');
});
