import {randomBytes,randomInt,createHmac,timingSafeEqual} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {db,get,run,dataDir,userId,hashPassword} from './db.mjs';

// Additive migration: existing accounts, IDs, purchases and sessions are preserved.
if(!db.prepare('PRAGMA table_info(users)').all().some(c=>c.name==='email'))db.exec('ALTER TABLE users ADD COLUMN email TEXT COLLATE NOCASE');
if(!db.prepare('PRAGMA table_info(users)').all().some(c=>c.name==='email_verified_at'))db.exec('ALTER TABLE users ADD COLUMN email_verified_at TEXT');
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE TABLE IF NOT EXISTS email_signups(id TEXT PRIMARY KEY,email TEXT NOT NULL COLLATE NOCASE UNIQUE,username TEXT NOT NULL,password TEXT NOT NULL,code_hash TEXT NOT NULL,expires INTEGER NOT NULL,sent INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,sends INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS email_limits(key TEXT PRIMARY KEY,count INTEGER NOT NULL,until INTEGER NOT NULL);`);
const secretPath=resolve(dataDir,'otp.key');
try{writeFileSync(secretPath,randomBytes(32),{flag:'wx',mode:0o600});}catch(e){if(e.code!=='EEXIST')throw e;}
const secret=readFileSync(secretPath);
function fail(message,status=400){throw Object.assign(Error(message),{status});}
const digest=v=>createHmac('sha256',secret).update(v).digest('hex');
const emailOf=v=>typeof v==='string'?v.trim().toLowerCase():'';
const validEmail=e=>e.length<=254&&/^[a-z0-9][a-z0-9._%+-]*@[a-z0-9.-]+\.[a-z]{2,63}$/.test(e);
export function emailReady(){return Boolean(process.env.SMTP_HOST&&process.env.SMTP_USER&&process.env.SMTP_PASS);}
let transport;
export async function sendOtpEmail({email,code}){
 if(!emailReady())fail('Имэйл баталгаажуулалт хараахан тохируулаагүй байна. Админтай холбогдоно уу.',503);
 try{
  if(!transport){const {default:nodemailer}=await import('nodemailer');const port=Number(process.env.SMTP_PORT||465);transport=nodemailer.createTransport({host:process.env.SMTP_HOST,port,secure:port===465,requireTLS:port!==465,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS},connectionTimeout:15000,greetingTimeout:15000,socketTimeout:20000});}
  await transport.sendMail({from:process.env.MAIL_FROM||process.env.SMTP_USER,to:{address:email},subject:'Lumi — Бүртгэл баталгаажуулах код',text:`Таны баталгаажуулах код: ${code}\n\nКод 10 минут хүчинтэй, нэг удаа ашиглагдана. Кодоо бусдад бүү дамжуулаарай.\n\nТа бүртгүүлэх хүсэлт гаргаагүй бол энэ имэйлийг үл тоомсорлож болно.`});
 }catch(e){console.error('Email delivery failed:',String(e.code||'SMTP_ERROR'));fail('Код илгээж чадсангүй. Түр хүлээгээд дахин оролдоно уу.',503);}
}
export function createEmailRegistration({send=sendOtpEmail,now=Date.now}={}){
 function limit(label,max,windowMs=600000){const key=digest(label),t=now();run('DELETE FROM email_limits WHERE until<?',t);run('INSERT INTO email_limits(key,count,until) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1',key,t+windowMs);if(get('SELECT count FROM email_limits WHERE key=?',key).count>max)fail('Олон удаа оролдлоо. 10 минутын дараа дахин оролдоно уу.',429);}
 function cleanup(){run('DELETE FROM email_signups WHERE expires<?',now()-3600000);}
 return {
  async start(b,ip){
   cleanup();const email=emailOf(b.email),username=typeof b.username==='string'?b.username.trim():'',password=b.password;
   if(!validEmail(email))fail('Имэйл хаягаа зөв оруулна уу.');
   if(!/^[a-zA-Z0-9_]{3,30}$/.test(username)||typeof password!=='string'||password.length<8||password.length>128)fail('Нэр 3–30 латин үсэг/тоо/_, нууц үг 8–128 тэмдэгт байна.');
   limit('send-ip:'+ip,30);limit('send-email:'+email,5);
   if(get('SELECT id FROM users WHERE email=? OR username=?',email,username))fail('Имэйл эсвэл нэр бүртгэлтэй байна. Нэвтрэх хэсгийг ашиглана уу.',409);
   const previous=get('SELECT sent FROM email_signups WHERE email=?',email);
   if(previous&&now()-previous.sent<60000)fail('Код дахин авахын өмнө 60 секунд хүлээнэ үү.',429);
   const passwordHash=await hashPassword(password),id=randomBytes(24).toString('hex'),code=String(randomInt(100000,1000000)),t=now();
   // Reserve synchronously after password hashing to prevent overlapping sends.
   const latest=get('SELECT sent FROM email_signups WHERE email=?',email);
   if(latest&&t-latest.sent<60000)fail('Код дахин авахын өмнө 60 секунд хүлээнэ үү.',429);
   run('INSERT INTO email_signups(id,email,username,password,code_hash,expires,sent) VALUES(?,?,?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET id=excluded.id,username=excluded.username,password=excluded.password,code_hash=excluded.code_hash,expires=excluded.expires,sent=excluded.sent,attempts=0,sends=1',id,email,username,passwordHash,digest(id+':'+code),t+600000,t);
   try{await send({email,code});}catch(e){run('DELETE FROM email_signups WHERE id=?',id);throw e;}
   return {challengeId:id,email,expiresIn:600,resendAfter:60};
  },
  async resend(b,ip){
   const id=typeof b.challengeId==='string'?b.challengeId:'',p=get('SELECT * FROM email_signups WHERE id=?',id);
   if(!p||p.expires<now())fail('Кодын хугацаа дууссан. Бүртгэлээ дахин эхлүүлнэ үү.');
   if(p.attempts>=5)fail('Кодыг олон удаа буруу оруулсан. Бүртгэлээ дахин эхлүүлнэ үү.',429);
   if(now()-p.sent<60000)fail('Дахин илгээхийн өмнө 60 секунд хүлээнэ үү.',429);
   if(p.sends>=5)fail('Дахин илгээх хязгаарт хүрсэн. Түр хүлээнэ үү.',429);
   limit('send-ip:'+ip,30);limit('send-email:'+p.email,5);
   const code=String(randomInt(100000,1000000)),t=now();
   run('UPDATE email_signups SET code_hash=?,expires=?,sent=?,sends=sends+1 WHERE id=?',digest(id+':'+code),t+600000,t,id);
   try{await send({email:p.email,code});}catch(e){run('UPDATE email_signups SET code_hash=?,expires=? WHERE id=?',digest(randomBytes(32)),now()-1,id);throw e;}
   return {challengeId:id,email:p.email,expiresIn:600,resendAfter:60};
  },
  verify(b,ip){
   limit('verify-ip:'+ip,60);
   const id=typeof b.challengeId==='string'?b.challengeId:'',code=typeof b.code==='string'?b.code.trim():'';
   if(!/^[0-9]{6}$/.test(code))fail('6 оронтой кодоо оруулна уу.');
   const p=get('SELECT * FROM email_signups WHERE id=?',id);
   if(!p||p.expires<now())fail('Кодын хугацаа дууссан эсвэл ашиглагдсан. Бүртгэлээ дахин эхлүүлнэ үү.');
   if(p.attempts>=5)fail('Кодыг 5 удаа буруу оруулсан. Түр хүлээгээд бүртгэлээ дахин эхлүүлнэ үү.',429);
   limit('verify-email:'+p.email,15);
   if(!timingSafeEqual(Buffer.from(p.code_hash,'hex'),Buffer.from(digest(id+':'+code),'hex'))){run('UPDATE email_signups SET attempts=attempts+1 WHERE id=?',id);fail('Код буруу байна. Дахин шалгана уу.');}
   db.exec('BEGIN IMMEDIATE');
   try{
    if(get('SELECT id FROM users WHERE email=? OR username=?',p.email,p.username))fail('Имэйл эсвэл нэр бүртгэлтэй болсон байна.',409);
    const user={id:userId(),username:p.username,role:'user'};
    run('INSERT INTO users(id,username,password,email,email_verified_at) VALUES(?,?,?,?,?)',user.id,p.username,p.password,p.email,new Date(now()).toISOString());
    run('DELETE FROM email_signups WHERE id=?',id);db.exec('COMMIT');return user;
   }catch(e){db.exec('ROLLBACK');throw e;}
  }
 };
}
