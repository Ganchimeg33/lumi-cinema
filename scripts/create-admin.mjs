import {get,run,userId,hashPassword} from '../db.mjs';
import {createInterface} from 'node:readline/promises';
const r=createInterface({input:process.stdin,output:process.stdout});
try{
 const username=(process.env.ADMIN_USER||await r.question('Admin username: ')).trim();
 const password=process.env.ADMIN_PASSWORD||await r.question('Admin password (12+ characters; visible while typing): ');
 if(!/^[a-zA-Z0-9_]{3,30}$/.test(username)||password.length<12)throw Error('Use username 3–30 letters/numbers/underscore, password 12+ characters.');
 if(get('SELECT id FROM users WHERE username=?',username))throw Error('Username already exists. Use another username.');
 run('INSERT INTO users(id,username,password,role) VALUES(?,?,?,?)',userId(),username,await hashPassword(password),'admin');
 console.log('Admin created. Sign in with your credentials; open /#admin.');
}catch(e){console.error(e.message);process.exitCode=1;}finally{r.close();}
