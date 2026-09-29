import {randomBytes,randomInt,createHmac,timingSafeEqual} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {db,get,run,dataDir,hashPassword} from './db.mjs';
import {sendOtpEmail,emailReady} from './email-otp.mjs';

db.exec(`
CREATE TABLE IF NOT EXISTS password_resets(
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  email TEXT NOT NULL COLLATE NOCASE,
  code_hash TEXT NOT NULL,
  expires INTEGER NOT NULL,
  sent INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  sends INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_password_resets_user
ON password_resets(user_id);
`);

const secret=readFileSync(resolve(dataDir,'otp.key'));

function fail(message,status=400){
  throw Object.assign(Error(message),{status});
}

const digest=v=>createHmac('sha256',secret).update(v).digest('hex');

const emailOf=v=>
  typeof v==='string' ? v.trim().toLowerCase() : '';

export function createPasswordReset({send=sendOtpEmail,now=Date.now}={}){

  function cleanup(){
    run('DELETE FROM password_resets WHERE expires<?',now()-3600000);
  }

  return {
    async start(b){
      cleanup();

      if(!emailReady())
        fail('Имэйл үйлчилгээ тохируулагдаагүй байна.',503);

      const email=emailOf(b.email);

      if(!email)
        fail('Имэйл хаягаа оруулна уу.');

      const user=get(
        'SELECT id,email FROM users WHERE email=?',
        email
      );

      // Account enumeration-оос хамгаална.
      if(!user)
        return {ok:true};

      const previous=get(
        'SELECT sent FROM password_resets WHERE user_id=? ORDER BY sent DESC LIMIT 1',
        user.id
      );

      if(previous && now()-previous.sent<60000)
        fail('Код дахин авахын өмнө 60 секунд хүлээнэ үү.',429);

      run('DELETE FROM password_resets WHERE user_id=?',user.id);

      const id=randomBytes(24).toString('hex');
      const code=String(randomInt(100000,1000000));
      const t=now();

      run(
        `INSERT INTO password_resets
        (id,user_id,email,code_hash,expires,sent)
        VALUES(?,?,?,?,?,?)`,
        id,user.id,email,digest(id+':'+code),t+600000,t
      );

      try{
        await send({email,code});
      }catch(e){
        run('DELETE FROM password_resets WHERE id=?',id);
        throw e;
      }

      return {
        ok:true,
        challengeId:id,
        expiresIn:600,
        resendAfter:60
      };
    },

    async resend(b){
      const id=typeof b.challengeId==='string'
        ? b.challengeId
        : '';

      const p=get(
        'SELECT * FROM password_resets WHERE id=?',
        id
      );

      if(!p || p.expires<now())
        fail('Кодын хугацаа дууссан. Дахин эхлүүлнэ үү.');

      if(p.attempts>=5)
        fail('Кодыг олон удаа буруу оруулсан. Дахин эхлүүлнэ үү.',429);

      if(now()-p.sent<60000)
        fail('Дахин илгээхийн өмнө 60 секунд хүлээнэ үү.',429);

      if(p.sends>=5)
        fail('Дахин илгээх хязгаарт хүрсэн байна.',429);

      const code=String(randomInt(100000,1000000));
      const t=now();

      run(
        `UPDATE password_resets
         SET code_hash=?,expires=?,sent=?,sends=sends+1
         WHERE id=?`,
        digest(id+':'+code),
        t+600000,
        t,
        id
      );

      try{
        await send({email:p.email,code});
      }catch(e){
        run(
          'UPDATE password_resets SET expires=? WHERE id=?',
          now()-1,id
        );
        throw e;
      }

      return {
        ok:true,
        challengeId:id,
        expiresIn:600,
        resendAfter:60
      };
    },

    async verify(b){
      const id=typeof b.challengeId==='string'
        ? b.challengeId
        : '';

      const code=typeof b.code==='string'
        ? b.code.trim()
        : '';

      const password=b.password;

      if(!/^[0-9]{6}$/.test(code))
        fail('6 оронтой кодоо оруулна уу.');

      if(typeof password!=='string' ||
         password.length<8 ||
         password.length>128)
        fail('Шинэ нууц үг 8–128 тэмдэгт байна.');

      const p=get(
        'SELECT * FROM password_resets WHERE id=?',
        id
      );

      if(!p || p.expires<now())
        fail('Кодын хугацаа дууссан эсвэл ашиглагдсан байна.');

      if(p.attempts>=5)
        fail('Кодыг олон удаа буруу оруулсан байна.',429);

      const expected=Buffer.from(p.code_hash,'hex');
      const actual=Buffer.from(digest(id+':'+code),'hex');

      if(expected.length!==actual.length ||
         !timingSafeEqual(expected,actual)){
        run(
          'UPDATE password_resets SET attempts=attempts+1 WHERE id=?',
          id
        );
        fail('Код буруу байна.');
      }

      const passwordHash=await hashPassword(password);

      db.exec('BEGIN IMMEDIATE');

      try{
        run(
          'UPDATE users SET password=? WHERE id=?',
          passwordHash,
          p.user_id
        );

        // Нууц үг солигдоход хуучин login-уудыг гаргана.
        run(
          'DELETE FROM sessions WHERE user_id=?',
          p.user_id
        );

        run(
          'DELETE FROM password_resets WHERE user_id=?',
          p.user_id
        );

        db.exec('COMMIT');
      }catch(e){
        db.exec('ROLLBACK');
        throw e;
      }

      return {ok:true};
    }
  };
}
