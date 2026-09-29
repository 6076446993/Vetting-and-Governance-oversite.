const crypto=require('node:crypto');const PROJECT_ID='github:jonathanblunt1214-lgtm/The-Crucible';const DECISIONS=new Set(['PROMOTE','QUARANTINE','REVOKE','ROLLBACK']);
function sha(v){return crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');}function text(v,n){if(typeof v!=='string'||!v.trim())throw new Error(n+' is required.');return v.trim();}
function decide({candidateEnvelope,proof,decision,approvedBy,reason,decidedAt=new Date().toISOString()}){
 if(!candidateEnvelope||candidateEnvelope.projectId!==PROJECT_ID||candidateEnvelope.promotionAuthorized!==false)throw new Error('Candidate-only envelope is required.');
 if(!DECISIONS.has(decision))throw new Error('Unknown oversight decision.');text(approvedBy,'approvedBy');text(reason,'reason');
 if(decision==='PROMOTE'){if(!proof||proof.state!=='verified'||proof.candidateId!==candidateEnvelope.candidateId||proof.experimentBoundary!==candidateEnvelope.claimBoundary)throw new Error('PROMOTE requires independently verified exact-boundary proof.');}
 if(decision==='ROLLBACK'&&!proof?.rollbackTargetKnowledgeId)throw new Error('ROLLBACK requires an explicit prior knowledge target.');
 const body={schemaVersion:1,projectId:PROJECT_ID,candidateId:candidateEnvelope.candidateId,candidateEnvelopeSha256:candidateEnvelope.envelopeSha256,decision,independentOversight:true,approvedBy,reason,decidedAt,proofSha256:proof?sha(proof):null,rollbackTargetKnowledgeId:proof?.rollbackTargetKnowledgeId||null};
 return Object.freeze({...body,decisionSha256:sha(body)});
}
module.exports={PROJECT_ID,DECISIONS,decide};
