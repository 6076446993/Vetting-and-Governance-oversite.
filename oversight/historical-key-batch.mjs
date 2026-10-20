// Integration adapter for the existing independent joiner + reviewed probe.
// Fixed pinned RAW versions only; no history discovery, signing or publication.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {joinChunks} from './encrypted-custody.mjs';
import {probe} from './historical-key-probe.mjs';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const hex=(s,n)=>typeof s==='string'&&new RegExp(`^[a-f0-9]{${n}}$`).test(s);
const refused=()=>{throw Error('REFUSED');};
function git(root,args,options={}){
 const r=spawnSync('git',['--no-replace-objects','-C',root,...args],{encoding:'utf8',timeout:180000,maxBuffer:1024*1024,...options});
 if(r.error||r.status!==0)refused();return typeof r.stdout==='string'?r.stdout:'';
}
export function runBatch({stateRoot,pins,expectedHead,env=process.env}){
 const report={schemaVersion:1,kind:'pinned-historical-raw-authentication-only',state:'HELD',versions:[],cleanupVerified:false,plaintextPersisted:false,keysExported:false,populationVerified:false,escrowVerified:false,independentRecoveryAccepted:false,restartAuthorized:false};
 let temp;
 try{
  if(!hex(expectedHead,40)||!Array.isArray(pins)||!pins.length||pins.length>6||new Set(pins.map(p=>p.encryptedSha256)).size!==pins.length)refused();
  for(const p of pins)if(!hex(p.commit,40)||!hex(p.manifestSha256,64)||!hex(p.encryptedSha256,64)||typeof p.manifestPath!=='string'||!/^[A-Za-z0-9_./-]+$/.test(p.manifestPath)||p.manifestPath.split('/').some(n=>!n||n==='.'||n==='..'))refused();
  if(git(stateRoot,['rev-parse','HEAD']).trim()!==expectedHead||git(stateRoot,['rev-parse','--is-shallow-repository']).trim()!=='false')refused();
  temp=fs.mkdtempSync(path.join(os.tmpdir(),'oversight-pinned-history-'));fs.chmodSync(temp,0o700);
  for(const [index,p] of pins.entries()){
   const entry={...p,state:'HELD',attempts:[],phase:'manifest-read'};report.versions.push(entry);
   const stage=path.join(temp,String(index));fs.mkdirSync(stage,{mode:0o700});
   try{
    const bytes=git(stateRoot,['show',`${p.commit}:${p.manifestPath}`]);entry.phase='manifest-hash';if(sha(bytes)!==p.manifestSha256)refused();
    entry.phase='manifest-schema';
    const m=JSON.parse(bytes);
    if(m.encryptedSha256!==p.encryptedSha256||!Number.isSafeInteger(m.encryptedBytes)||m.encryptedBytes<1||m.encryptedBytes>1024**3||!Array.isArray(m.chunks)||!m.chunks.length||m.chunks.length>32)refused();
    fs.writeFileSync(path.join(stage,'encrypted-chunks.json'),bytes,{flag:'wx',mode:0o600});
    const dir=path.posix.dirname(p.manifestPath);
    for(const c of m.chunks){
     // Containment/resource checks before copying; existing joiner validates
     // exact ordering, naming scheme, per-chunk hashes and aggregate hash.
     if(typeof c.name!=='string'||!/^source-bundle(?:\.part-\d{4}|-[a-f0-9]{64})\.enc$/.test(c.name)||!Number.isSafeInteger(c.bytes)||c.bytes<1||c.bytes>96*1024**2)refused();
     const member=dir==='.'?c.name:`${dir}/${c.name}`;
     entry.phase='chunk-size';
     if(git(stateRoot,['cat-file','-s',`${p.commit}:${member}`]).trim()!==String(c.bytes))refused();
     entry.phase='chunk-read';
     const fd=fs.openSync(path.join(stage,c.name),'wx',0o600);
     try{git(stateRoot,['show',`${p.commit}:${member}`],{stdio:['ignore',fd,'pipe']});}finally{fs.closeSync(fd);}
    }
    entry.phase='chunk-join';
    const input=path.join(stage,'pinned.enc');joinChunks(stage,input);
    const result=probe({input,expectedSha256:p.encryptedSha256,env});
    entry.state=result.state;entry.attempts=result.attempts;entry.phase=result.phase;
    if(result.reason)entry.reason=result.reason;
    if(result.identityMatches)entry.identityMatches=result.identityMatches;
   }catch{entry.reason='PINNED_INPUT_OR_AUTHENTICATION_REFUSED';}
   finally{fs.rmSync(stage,{recursive:true,force:true});}
  }
  if(git(stateRoot,['rev-parse','HEAD']).trim()!==expectedHead)refused();
  if(report.versions.length===pins.length&&report.versions.every(v=>v.state==='AUTHENTICATED_ONLY'))report.state='AUTHENTICATED_ONLY';
 }catch{report.state='HELD';report.reason='PINNED_BATCH_REFUSED';}
 finally{
  try{if(temp)fs.rmSync(temp,{recursive:true,force:true});report.cleanupVerified=true;}
  catch{report.state='HELD';report.reason='TEMPORARY_CIPHERTEXT_CLEANUP_REFUSED';}
 }
 return report;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 let report;
 try{
  if(process.env.GITHUB_REPOSITORY!=='6076446993/Vetting-and-Governance-oversite.'||process.env.GITHUB_REF!=='refs/heads/main'||process.env.GITHUB_EVENT_NAME!=='workflow_dispatch'||process.env.CRUCIBLE_RECOVERY_OPERATION!=='historical-key-authentication')refused();
  const pins=JSON.parse(fs.readFileSync(new URL('./raw-history-pins.json',import.meta.url),'utf8'));
  if(pins.schemaVersion!==1||pins.custodyRepositoryId!==1352932373||pins.custodyRepository!=='6076446993/Crucible-Learning-State')refused();
  const stateRoot=path.join(process.env.RUNNER_TEMP,'historical-raw-input');
  report=runBatch({stateRoot,pins:pins.pins,expectedHead:pins.head});
 }catch{report={schemaVersion:1,state:'HELD',reason:'INDEPENDENT_EXECUTION_CONTEXT_REFUSED',restartAuthorized:false,independentRecoveryAccepted:false};}
 try{fs.writeFileSync('historical-key-report.json',JSON.stringify(report,null,2)+'\n',{flag:'wx',mode:0o600});}
 catch{console.error('HISTORICAL_REPORT_REFUSED');process.exitCode=2;}
 console.log(JSON.stringify({state:report.state,restartAuthorized:false,independentRecoveryAccepted:false}));
 if(report.state!=='AUTHENTICATED_ONLY')process.exitCode=2;
}
