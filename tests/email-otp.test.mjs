import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
const temp=mkdtempSync(resolve(tmpdir(),'lumi-otp-test-'));
process.env.DATA_DIR=temp;
const {createEmailRegistration}=await import('../email-otp.mjs');
const {db,get,run,hashPassword,checkPassword}=await import('../db.mjs');
test('OTP delivery contract, migration, expiration, resend, attempts and one-time consumption',async()=>{
 try{
  run('INSERT INTO users(id,username,password,role) VALUES(?,?,?,?)','123456','legacyAdmin',await hashPassword('old-admin-password'),'admin');
  const outbox=[];let clock=Date.now();const flow=createEmailRegistration({send:async m=>outbox.push(m),now:()=>clock});
  const b={email:'New@Example.com',username:'newviewer',password:'my-password123'};
  const c=await flow.start(b,'ip1');assert.equal(c.email,'new@example.com');assert.equal(get('SELECT id FROM users WHERE username=?','newviewer'),undefined);
  assert.match(outbox[0].code,/^\d{6}$/);assert.equal(JSON.stringify(c).includes(outbox[0].code),false);
  const pending=get('SELECT * FROM email_signups WHERE id=?',c.challengeId);assert.notEqual(pending.code_hash,outbox[0].code);assert.notEqual(pending.password,b.password);
  assert.throws(()=>flow.verify({challengeId:c.challengeId,code:'000000'},'ip1'),/Код буруу/);
  await assert.rejects(()=>flow.resend({challengeId:c.challengeId},'ip1'),/60 секунд/);
  const oldCode=outbox[0].code;clock+=61000;await flow.resend({challengeId:c.challengeId},'ip1');const fresh=outbox.at(-1).code;
  if(fresh!==oldCode)assert.throws(()=>flow.verify({challengeId:c.challengeId,code:oldCode},'ip1'),/Код буруу/);
  const user=flow.verify({challengeId:c.challengeId,code:fresh},'ip1');assert.match(user.id,/^\d{6}$/);
  const saved=get('SELECT * FROM users WHERE id=?',user.id);assert.equal(saved.email,'new@example.com');assert.ok(saved.email_verified_at);assert.ok(await checkPassword(b.password,saved.password));
  assert.throws(()=>flow.verify({challengeId:c.challengeId,code:fresh},'ip1'),/ашиглагдсан/);
  await assert.rejects(()=>flow.start({...b,email:'NEW@example.com',username:'another'},'ip2'),/бүртгэлтэй/);
  const expired=await flow.start({email:'expired@example.com',username:'expired',password:b.password},'ip3');clock+=600001;assert.throws(()=>flow.verify({challengeId:expired.challengeId,code:outbox.at(-1).code},'ip3'),/хугацаа/);
  const locked=await flow.start({email:'locked@example.com',username:'locked',password:b.password},'ip4');for(let i=0;i<5;i++)assert.throws(()=>flow.verify({challengeId:locked.challengeId,code:'000000'},'ip4'),/Код буруу/);
  assert.throws(()=>flow.verify({challengeId:locked.challengeId,code:outbox.at(-1).code},'ip4'),/5 удаа/);
  const failed=createEmailRegistration({send:async()=>{throw Error('smtp unavailable');},now:()=>clock});await assert.rejects(()=>failed.start({email:'fail@example.com',username:'failed',password:b.password},'ip5'),/smtp unavailable/);assert.equal(get('SELECT id FROM users WHERE username=?','failed'),undefined);assert.equal(get('SELECT id FROM email_signups WHERE email=?','fail@example.com'),undefined);
  assert.equal(get('SELECT role FROM users WHERE id=?','123456').role,'admin');
 }finally{db.close();rmSync(temp,{recursive:true,force:true});}
});
