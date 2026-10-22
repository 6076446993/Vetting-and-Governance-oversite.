// Isolated proposal for independent Oversight review. No publication authority.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const HEX=/^[a-f0-9]{64}$/;
const LIMIT=1024*1024*1024;
const ID={projectId:'github:jonathanblunt1214-lgtm/The-Crucible',repository:'6076446993/The-Crucible',ref:'refs/heads/development'};
const SLOTS=['CRUCIBLE_SOURCE_BUNDLE_KEY','CRUCIBLE_SOURCE_BUNDLE_KEY_PREVIOUS'];
const hash=()=>crypto.createHash('sha256');
const denied=()=>{throw new Error('REFUSED');};
export function probe({input,expectedSha256,env=process.env}) {
  const result={schemaVersion:1,kind:'historical-key-authentication-only',state:'HELD',ciphertextSha256:null,attempts:[],plaintextPersisted:false,keysExported:false,populationVerified:false,escrowVerified:false,independentRecoveryAccepted:false,restartAuthorized:false};
  let fd;
  result.phase='input-open';
  try {
    if(!HEX.test(expectedSha256||''))denied();
    // One pinned descriptor, regular files only. Recheck ciphertext after auth too.
    fd=fs.openSync(input,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
    const initial=fs.fstatSync(fd);
    if(!initial.isFile()||initial.size<20||initial.size>LIMIT)denied();
    result.phase='ciphertext-hash';
    const buffer=Buffer.alloc(1024*1024),cipherHash=hash();
    for(let pos=0;pos<initial.size;){const n=fs.readSync(fd,buffer,0,Math.min(buffer.length,initial.size-pos),pos);if(!n)denied();cipherHash.update(buffer.subarray(0,n));pos+=n;}
    if(cipherHash.digest('hex')!==expectedSha256)denied();
    result.ciphertextSha256=expectedSha256;
    result.phase='header-format';
    const prefix=Buffer.alloc(8192),count=fs.readSync(fd,prefix,0,prefix.length,0),newline=prefix.subarray(0,count).indexOf(10);
    if(newline<0)denied();
    const aad=prefix.subarray(0,newline+1),h=JSON.parse(aad.toString('utf8'));
    if(!h||h.magic!=='CRUCIBLE-SOURCE-BUNDLE-V1'||h.algorithm!=='aes-256-gcm')denied();
    result.phase='header-identity';
    result.identityMatches=Object.fromEntries(Object.entries(ID).map(([k,v])=>[k,h[k]===v]));
    if(Object.values(result.identityMatches).some(v=>!v))denied();
    result.phase='header-length';
    if(!HEX.test(h.plaintextSha256||'')||!Number.isSafeInteger(h.plaintextBytes)||h.plaintextBytes<1||h.plaintextBytes>LIMIT)denied();
    if(typeof h.iv!=='string'||!/^[A-Za-z0-9+/]{16}$/.test(h.iv))denied();
    if(initial.size-aad.length-16!==h.plaintextBytes)denied();
    const tag=Buffer.alloc(16);if(fs.readSync(fd,tag,0,16,initial.size-16)!==16)denied();
    result.phase='key-authentication';
    for(const slot of SLOTS){
      const attempt={slot,state:'unavailable'};result.attempts.push(attempt);
      let key;
      try {
        const encoded=env[slot];
        if(typeof encoded!=='string'||!/^[A-Za-z0-9+/]{43}=$/.test(encoded))continue;
        key=Buffer.from(encoded,'base64');if(key.length!==32)continue;
        attempt.state='authentication-refused';
        attempt.keyFingerprint=hash().update(key).digest('hex');
        const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(h.iv,'base64'));
        decipher.setAAD(aad);decipher.setAuthTag(tag);
        const plainHash=hash(),recheck=hash();recheck.update(aad);let bytes=0;
        for(let pos=aad.length;pos<initial.size-16;){
          const n=fs.readSync(fd,buffer,0,Math.min(buffer.length,initial.size-16-pos),pos);if(!n)denied();
          const ciphertext=buffer.subarray(0,n);recheck.update(ciphertext);
          const chunk=decipher.update(ciphertext);bytes+=chunk.length;if(bytes>h.plaintextBytes)denied();plainHash.update(chunk);chunk.fill(0);pos+=n;
        }
        const final=decipher.final();bytes+=final.length;plainHash.update(final);final.fill(0);
        recheck.update(tag);
        const after=fs.fstatSync(fd);
        if(bytes!==h.plaintextBytes||plainHash.digest('hex')!==h.plaintextSha256||recheck.digest('hex')!==expectedSha256||after.size!==initial.size||after.mtimeMs!==initial.mtimeMs)denied();
        attempt.state='authenticated';result.state='AUTHENTICATED_ONLY';
      }catch { attempt.state='authentication-refused'; }
      finally {key?.fill(0);}
    }
    // Re-read the whole pinned descriptor. Reusing the saved AAD/tag would
    // miss header/tag mutation when a writer restores the original mtime.
    result.phase='post-authentication-integrity';
    const finalHash=hash();
    const beforeFinal=fs.fstatSync(fd);
    if(beforeFinal.size!==initial.size)denied();
    for(let pos=0;pos<initial.size;){
      const n=fs.readSync(fd,buffer,0,Math.min(buffer.length,initial.size-pos),pos);
      if(!n)denied();finalHash.update(buffer.subarray(0,n));pos+=n;
    }
    const finalStat=fs.fstatSync(fd);
    if(finalHash.digest('hex')!==expectedSha256||finalStat.size!==initial.size||
      finalStat.mtimeMs!==initial.mtimeMs||finalStat.ctimeMs!==initial.ctimeMs||
      finalStat.ctimeMs!==beforeFinal.ctimeMs)denied();
    buffer.fill(0);
    result.phase='complete';
    return result;
  }catch {
    for(const attempt of result.attempts)if(attempt.state==='authenticated')attempt.state='authentication-refused';
    return {...result,state:'HELD',reason:'INPUT_OR_AUTHENTICATION_REFUSED'};
  }
  finally {if(fd!==undefined)fs.closeSync(fd);}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2),value=n=>args[args.indexOf(n)+1];
  const result=probe({input:value('--input'),expectedSha256:value('--expected-sha256')});
  console.log(JSON.stringify(result));process.exitCode=result.state==='AUTHENTICATED_ONLY'?0:2;
}
