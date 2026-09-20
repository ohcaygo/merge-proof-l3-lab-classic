"use strict";
const { test } = require("node:test"), a = require("node:assert/strict");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path"), crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { capture, H, B, M } = require("./fixtures");
const { prove, freshness } = require("../proof"), bundle = require("../bundle");
test("portable receipt replays offline; tampering and untrusted self-signed keys do not pass", async () => {
  const receipt = prove(capture()), unsigned = await bundle.create(receipt);
  a.equal(bundle.verify(unsigned).state, "SIGNATURE_UNVERIFIED");
  a.equal(bundle.verify(unsigned, { allowUnsigned: true }).state, "CONSISTENT_OFFLINE");
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "fixture", nbf: "2026-01-01T00:00:00Z", exp: "2027-01-01T00:00:00Z" };
  const signed = await bundle.create(receipt, { signer: async bytes => ({ keyid: "fixture", sig: crypto.sign("sha256", bytes, privateKey).toString("base64") }), keys: { keys: [jwk] } });
  a.equal(bundle.verify(signed).state, "SIGNATURE_UNVERIFIED");
  a.equal(bundle.verify(signed, { trustedKeys: [jwk] }).signature, "VALID_TRUSTED_KEY");
  for (const mutate of [b => b.receipt.verdict = "FAIL", b => b.receipt.evidence.reviews.value[0].sha = B, b => b.policy.proofOptions.appId = 10,
    b => b.envelope.signatures[0].sig = "AAAA"]) {
    const altered = structuredClone(signed); mutate(altered);
    a.notEqual(bundle.verify(altered, { trustedKeys: [jwk] }).state, "CONSISTENT_OFFLINE");
  }
  const future = structuredClone(unsigned); future.receipt.policy = "future";
  a.equal(bundle.replay(future.receipt, future.policy).state, "UNSUPPORTED");
});
test("machine contract holds wrong subject, stale receipt and queue admission", () => {
  const c = capture(), r = prove(c), req = { repositoryId: 1, pr: 1, expectedHeadSha: H, expectedBaseSha: B, expectedTargetSha: H };
  const { decide } = require("../decision");
  a.equal(decide(r, freshness(r,c), req).proceed, true);
  a.equal(decide(r, freshness(r,c), {...req, expectedBaseSha:M}).proceed, false);
  a.equal(decide(r, {state:"STALE"}, req).proceed, false);
  r.summary.queueStage = "ADMISSION_ONLY"; a.equal(decide(r, freshness(r,c), req).proceed,false);
});
test("landing checks content, proof, head and method parentage; squash SHA may differ", () => {
  const r = prove(capture()), record = { proof: { receiptSnapshot: r }, mergedHeadSha: H, mergeCommitSha: M };
  const landed = { sha: M, tree: r.summary.target.value.tree, parents: [B] }, { compare } = require("../landing");
  a.equal(compare(record, landed).state, "LANDED_VERIFIED");
  a.equal(compare(record, { ...landed, tree: B }).state, "LANDED_MISMATCH");
  a.equal(compare(record, { ...landed, parents: [H] }).state, "LANDED_UNRESOLVED");
  a.equal(compare({ ...record, mergedHeadSha: B }, landed).state, "LANDED_UNRESOLVED");
  a.equal(compare({ ...record, proof: null }, landed).state, "NO_PROOF_RECORDED");
});
function lab(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mp-differential-")), repo = path.join(root,"work"), bare = path.join(root,"bare");
  fs.mkdirSync(repo);
  t.after(() => fs.rmSync(root,{recursive:true,force:true}));
  const env = { ...process.env, GIT_CONFIG_NOSYSTEM:"1", GIT_CONFIG_GLOBAL:"/dev/null", GIT_AUTHOR_NAME:"fixture", GIT_COMMITTER_NAME:"fixture", GIT_AUTHOR_EMAIL:"fixture@invalid", GIT_COMMITTER_EMAIL:"fixture@invalid" };
  const git = (...args) => { const r=spawnSync("/usr/bin/git",["-C",repo,...args],{env,encoding:"utf8"}); a.equal(r.status,0,r.stderr); return r.stdout.trim(); };
  git("init","-b","main"); git("config","core.hooksPath","/dev/null");
  const write = (file,body) => { fs.mkdirSync(path.dirname(path.join(repo,file)),{recursive:true}); fs.writeFileSync(path.join(repo,file),body); };
  const commit = () => {git("add","-A");git("commit","-m","fixture");return git("rev-parse","HEAD");};
  const mirror = () => {const r=spawnSync("/usr/bin/git",["clone","--bare",repo,bare],{env,encoding:"utf8"});a.equal(r.status,0,r.stderr);};
  return { root,repo,bare,git,write,commit,mirror,config:{binary:"/usr/bin/git",version:git("--version"),sha256:crypto.createHash("sha256").update(fs.readFileSync("/usr/bin/git")).digest("hex")} };
}
for (const method of ["merge","squash","rebase"]) test(`local differential lab: clean ${method} expected tree matches Git`,t=>{
  const l=lab(t);l.write("base","base\n");l.commit();l.git("checkout","-b","feature");l.write("feature","feature\n");const head=l.commit();
  l.git("checkout","main");l.write("main","main\n");const base=l.commit();l.mirror();
  const result=require("../reconstruct").reconstruct(l.bare,{base,head,method},l.config);
  a.equal(result.status,"RECONSTRUCTED",JSON.stringify(result));
  if(method==="rebase"){l.git("checkout","feature");l.git("rebase","main");}
  else {l.git("merge",...(method==="squash"?["--squash"]:["--no-ff"]),"feature");if(method==="squash")l.commit();}
  a.equal(result.tree,l.git("rev-parse","HEAD^{tree}"));
  const divergent=require("../reconstruct").reconstruct(l.bare,{base,head,method,providerTree:B},l.config);
  a.equal(divergent.comparison,"CANDIDATE_MISMATCH");
});
test("conflicted reconstruction emits no expected tree",t=>{
  const l=lab(t);l.write("f","original\n");l.commit();l.git("checkout","-b","feature");l.write("f","feature\n");const head=l.commit();
  l.git("checkout","main");l.write("f","main\n");const base=l.commit();l.mirror();
  const r=require("../reconstruct").reconstruct(l.bare,{base,head,method:"merge"},l.config);
  a.equal(r.status,"NOT_RECONSTRUCTABLE");a.equal(r.tree,null);
});
test("rebase with a merge commit is explicitly refused",t=>{
  const l=lab(t);l.write("base","b");l.commit();l.git("checkout","-b","feature");l.write("f","f");l.commit();l.git("checkout","-b","side");l.write("s","s");l.commit();l.git("checkout","feature");l.git("merge","--no-ff","side");const head=l.git("rev-parse","HEAD"),base=l.git("rev-parse","main");l.mirror();
  a.equal(require("../reconstruct").reconstruct(l.bare,{base,head,method:"rebase"},l.config).reason,"REBASE_MERGE_COMMIT_OR_ROOT_UNSUPPORTED");
});

test("queue reconstruction follows confirmed order and refuses missing membership",t=>{
  const l=lab(t);l.write("base","b");const base=l.commit();
  l.git("checkout","-b","first");l.write("a","a");const first=l.commit();
  l.git("checkout","main");l.git("checkout","-b","second");l.write("b","b");const second=l.commit();l.mirror();
  const input={method:"queue",base,head:second,entries:[{head:first},{head:second}],providerOrderConfirmed:true};
  const result=require("../reconstruct").reconstruct(l.bare,input,l.config);
  l.git("checkout","main");l.git("merge","--no-ff","first");l.git("merge","--no-ff","second");
  a.equal(result.status,"RECONSTRUCTED");a.equal(result.tree,l.git("rev-parse","HEAD^{tree}"));a.equal(result.steps.length,2);
  a.equal(require("../reconstruct").reconstruct(l.bare,{...input,providerOrderConfirmed:false},l.config).reason,"QUEUE_MEMBERSHIP_ORDER_UNAVAILABLE");
});
test("clean binary, executable mode and symlink changes preserve Git tree identity",t=>{
  const l=lab(t);l.write("base","b");const base=l.commit();l.git("checkout","-b","feature");
  l.write("binary",Buffer.from([0,255,8,0]));l.write("run","#!/bin/sh\nexit 0\n");fs.chmodSync(path.join(l.repo,"run"),0o755);
  fs.symlinkSync("base",path.join(l.repo,"link"));const head=l.commit();l.mirror();
  const r=require("../reconstruct").reconstruct(l.bare,{base,head,method:"merge"},l.config);
  a.equal(r.tree,l.git("rev-parse","HEAD^{tree}"));
});
test("attribute-dependent conflict and both-sided gitlinks refuse a definitive tree",t=>{
  const l=lab(t);l.write("f","original\n");l.write(".gitattributes","f merge=union\n");l.commit();
  l.git("checkout","-b","feature");l.write("f","feature\n");const head=l.commit();
  l.git("checkout","main");l.write("f","base\n");const base=l.commit();l.mirror();
  const r=require("../reconstruct").reconstruct(l.bare,{base,head,method:"merge"},l.config);
  a.equal(r.tree,null);a.equal(r.status,"NOT_RECONSTRUCTABLE");
});
test("both-sided gitlinks retain the researched refusal boundary",t=>{
  const l=lab(t);l.write("base","b");const ancestor=l.commit();
  l.git("update-index","--add","--cacheinfo",`160000,${ancestor},module`);l.git("commit","-m","gitlink");
  l.git("checkout","-b","feature");l.write("Case","a");const x=l.commit();l.git("update-index","--add","--cacheinfo",`160000,${x},module`);l.git("commit","-m","head module");const head=l.git("rev-parse","HEAD");
  l.git("checkout","main");l.write("case","b");const y=l.commit();l.git("update-index","--add","--cacheinfo",`160000,${y},module`);l.git("commit","-m","base module");const base=l.git("rev-parse","HEAD");l.mirror();
  const r=require("../reconstruct").reconstruct(l.bare,{base,head,method:"merge"},l.config);
  a.equal(r.reason,"BOTH_SIDES_GITLINK_CHANGED");a.equal(r.tree,null);
});
test("frozen pure engine matches current policy across passing and failing captures",()=>{
  const old=require("../verifier/v2/proof");
  for(const change of [c=>{},c=>c.execution.value[0].event="schedule",c=>c.checks.value[0].conclusion="failure",c=>c.reviews.value[0].sha=B]) {
    const c=capture();change(c);const now=prove(c),archived=old.prove(c);
    for(const key of ["verdict","gaps","claims","summary","bindings","local","expectedTree"])
      a.deepEqual(archived[key],now[key],key);
  }
});
test("online verifier distinguishes provider divergence from record retention uncertainty",async()=>{
  const b=await bundle.create(prove(capture()));
  const missing={authorize:async()=>{},get:async()=>{throw Object.assign(Error(),{status:404});}};
  const r=await require('../reverify').online(b,missing);a.equal(r.state,'PARTIALLY_REVERIFIED');a.ok(r.rows.every(x=>['RECORD_UNAVAILABLE_RETENTION_POSSIBLE','UNAVAILABLE'].includes(x.state)));
  const changed=await require('../reverify').online(b,{authorize:async()=>{},get:async()=>({})});a.equal(changed.exitCode,5);
});
test("MCP advertises only a read-only decision tool and bounds incoming messages",async()=>{
  const {Readable,Writable}=require('node:stream');let bytes='';
  const out=new Writable({write(chunk,_encoding,done){bytes+=chunk;done();}});
  await require('../verify-cli').mcp(Readable.from([JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list'})+'\n']),out);
  const tool=JSON.parse(bytes).result.tools[0];a.equal(tool.name,'merge_proof_decision');a.equal(tool.annotations.readOnlyHint,true);a.ok(tool.outputSchema);
  await a.rejects(require('../verify-cli').mcp(Readable.from(['a'.repeat(65537)]),out),{code:'MCP_MESSAGE_LIMIT'});
});
test("decision with a changed provider head cannot pass the provider SHA guard",()=>{
  const c=capture(),r=prove(c),d=require('../decision').decide(r,freshness(r,c),{repositoryId:1,pr:1,expectedHeadSha:H,expectedBaseSha:B,expectedTargetSha:H});
  a.equal(d.proceed,true);
  const providerMerge=(head,guard)=>head===guard.sha?200:409;
  a.equal(providerMerge(B,d.nextAction.mergeArguments),409);
});
test("ambient attributes cannot turn a conflicted merge into an uncaveated expected tree",t=>{
  const l=lab(t);l.write('f.txt','original\n');l.commit();l.git('checkout','-b','feature');l.write('f.txt','feature\n');const head=l.commit();
  l.git('checkout','main');l.write('f.txt','main\n');const base=l.commit();l.mirror();
  const reconstruct=()=>require('../reconstruct').reconstruct(l.bare,{base,head,method:'merge'},l.config);
  a.equal(reconstruct().status,'NOT_RECONSTRUCTABLE');
  fs.writeFileSync(path.join(l.bare,'info/attributes'),'*.txt merge=union\n');
  a.equal(reconstruct().reason,'LOCAL_ATTRIBUTES_OUTSIDE_ENVELOPE');a.equal(reconstruct().tree,null);
  fs.unlinkSync(path.join(l.bare,'info/attributes'));
  const file=path.join(l.root,'ambient-attributes');fs.writeFileSync(file,'*.txt merge=union\n');
  const configured=spawnSync('/usr/bin/git',['-C',l.bare,'config','core.attributesFile',file],{encoding:'utf8'});a.equal(configured.status,0);
  a.equal(reconstruct().status,'NOT_RECONSTRUCTABLE');a.equal(reconstruct().tree,null);
});
test("CLI/MCP reject contradictory, malformed or wrong-subject decision contracts",()=>{
  const c=capture(),r=prove(c),input={repository:'fixture/public',repositoryId:1,pr:1,expectedHeadSha:H,expectedBaseSha:B,expectedTargetSha:H};
  const d=require('../decision').decide(r,freshness(r,c),input),{validateDecision}=require('../verify-cli');
  a.equal(validateDecision(d,input).proceed,true);
  for(const change of [x=>x.outcome='HOLD',x=>x.verdict='NOT_PROVEN',x=>x.currentness='STALE',x=>x.proceed='true',x=>delete x.subject,x=>x.subject.value.commit=B,x=>x.request.pr=2,x=>x.nextAction.mergeArguments.sha=B,x=>delete x.receipt]) {
    const bad=structuredClone(d);change(bad);a.throws(()=>validateDecision(bad,input),{code:'INVALID_DECISION_CONTRACT'});
  }
});
test("offline verifier recomputes supplied Git objects and detects a consistently recorded false tree",async t=>{
  const l=lab(t);l.write('base','b');const base=l.commit();l.git('checkout','-b','feature');l.write('feature','f');const head=l.commit(),headTree=l.git('rev-parse','HEAD^{tree}'),baseTree=l.git('rev-parse','main^{tree}');l.mirror();
  const c=JSON.parse(JSON.stringify(capture()).replaceAll(H,head).replaceAll(B,base));
  c.target.value.tree=headTree;c.git.value.headTree=headTree;c.git.value.baseTree=baseTree;
  c.expectedTree=require('../reconstruct').reconstruct(l.bare,{base,head,method:'merge',providerTree:headTree},l.config);
  const receipt=prove(c),b=await bundle.create(receipt),{independent}=require('../reverify');
  const checked=independent(b,l.bare);a.equal(checked.state,'INDEPENDENTLY_RECOMPUTED',JSON.stringify(checked));
  const changed=structuredClone(b);changed.receipt.expectedTree.tree=B;
  a.equal(independent(changed,l.bare).state,'INDEPENDENT_VERIFICATION_DIVERGED');
  const directory=path.join(l.root,'bundle');bundle.write(directory,b);
  const run=spawnSync(process.execPath,[path.join(__dirname,'../../bin/merge-proof.js'),'verify','--bundle',directory,'--allow-unsigned','--git-dir',l.bare],{encoding:'utf8'});
  a.equal(run.status,0,run.stderr+run.stdout);a.equal(JSON.parse(run.stdout).independent.state,'INDEPENDENTLY_RECOMPUTED');
  const missing=structuredClone(b);missing.receipt.evidence.target.value.sha=M;missing.receipt.evidence.target.value.kind='MERGE_GROUP';
  a.equal(independent(missing,l.bare).state,'INDEPENDENT_VERIFICATION_UNAVAILABLE');
  const wrongPin=structuredClone(b);wrongPin.receipt.expectedTree.gitBinaryDigest='0'.repeat(64);
  a.equal(independent(wrongPin,l.bare).reason,'PINNED_GIT_BINARY_MISMATCH');
});
test('every ordered provider candidate tree is compared even when final queue content matches',t=>{
 const l=lab(t);l.write('base','b');const base=l.commit();l.git('checkout','-b','first');l.write('a','a');const first=l.commit();l.git('checkout','main');l.git('checkout','-b','second');l.write('b','b');const second=l.commit();
 l.git('checkout','main');l.git('merge','--no-ff','first');const firstCandidate=l.git('rev-parse','HEAD');l.git('merge','--no-ff','second');const finalCandidate=l.git('rev-parse','HEAD'),providerTree=l.git('rev-parse','HEAD^{tree}');l.mirror();
 const input={method:'queue',base,head:second,providerOrderConfirmed:true,providerTree,entries:[{head:first,candidate:firstCandidate},{head:second,candidate:finalCandidate}]},reconstruct=require('../reconstruct').reconstruct;
 const good=reconstruct(l.bare,input,l.config);a.equal(good.comparison,'MATCH');a.deepEqual(good.steps.map(s=>s.comparison),['MATCH','MATCH']);a.ok(good.steps.every(s=>s.candidate&&s.providerTree));
 const wrong=reconstruct(l.bare,{...input,entries:[{head:first,candidate:base},{head:second,candidate:finalCandidate}]},l.config);a.equal(wrong.tree,providerTree);a.equal(wrong.comparison,'CANDIDATE_MISMATCH');a.equal(wrong.steps[0].comparison,'CANDIDATE_MISMATCH');
 const c=JSON.parse(JSON.stringify(capture()).replaceAll(B,base).replaceAll(H,second));c.expectedTree=wrong;const receipt=prove(c);a.equal(receipt.verdict,'FAIL');a.ok(receipt.gaps.includes('CANDIDATE_MISMATCH'));
});
