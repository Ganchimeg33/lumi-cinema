import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {createServer} from 'node:net';
test('register, upload, purchase approval, protected streaming, authorization',async()=>{
 const data=mkdtempSync(resolve(tmpdir(),'lumi-test-'));
 const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
 const origin=`http://localhost:${port}`;
 const env={...process.env,DATA_DIR:data,PORT:String(port),PUBLIC_ORIGIN:origin,ADMIN_USER:'owner',ADMIN_PASSWORD:'test-admin-password-123'};
 const admin=spawnSync(process.execPath,['scripts/create-admin.mjs'],{env,encoding:'utf8'});assert.equal(admin.status,0,admin.stderr);
 const seed=spawnSync(process.execPath,['--input-type=module','-e',"import {run,hashPassword} from './db.mjs'; for(const [id,name] of [['111111','viewer'],['222222','other']])run('INSERT INTO users(id,username,password) VALUES(?,?,?)',id,name,await hashPassword('my-password123'));"],{env,encoding:'utf8'});assert.equal(seed.status,0,seed.stderr);
 const child=spawn(process.execPath,['server.mjs'],{env,stdio:['ignore','pipe','pipe']});
 try{
 await new Promise((res,rej)=>{const t=setTimeout(()=>rej(Error('startup timeout')),5000);child.stdout.once('data',()=>{clearTimeout(t);res();});child.once('exit',()=>{clearTimeout(t);rej(Error('server failed'));});});
 async function request(path,method='GET',body,cookie='',extra={}){return fetch(origin+path,{method,headers:{Origin:origin,'X-Lumi-Request':'1',...(body?{'Content-Type':'application/json'}:{}),Cookie:cookie,...extra},body:body===undefined?undefined:typeof body==='string'||Buffer.isBuffer(body)?body:JSON.stringify(body)});}
 async function login(name,password){const r=await request('/api/login','POST',{username:name,password});assert.equal(r.status,200);return r.headers.get('set-cookie').split(';')[0];}
 let r;const viewer=await login('viewer','my-password123');const other=await login('other','my-password123');
 assert.equal((await request('/api/admin/data','GET',undefined,viewer)).status,403);
 assert.equal((await request('/api/admin/data')).status,401);
 const owner=await login('owner',env.ADMIN_PASSWORD);
 assert.equal((await request('/api/admin/settings','PUT',{bank:'Test bank',account:'TEST-ACCOUNT',holder:'Test owner'},owner)).status,200);
 // Signature-valid minimal fixtures test file authorization and byte ranges, not codecs.
 const png=Buffer.from([137,80,78,71,13,10,26,10,0,0,0,0,0,0,0,0]);
 const video=Buffer.from('0000ftypisom00000000000000000000');
 async function upload(bytes,kind,mime){const r=await request('/api/admin/upload','POST',bytes,owner,{'Content-Type':mime,'X-File-Kind':kind});assert.equal(r.status,201);return (await r.json()).id;}
 const poster=await upload(png,'poster','image/png'),vid=await upload(video,'video','video/mp4');
 assert.equal((await request('/api/admin/upload','POST',png,viewer,{'Content-Type':'image/png','X-File-Kind':'poster'})).status,403);
 r=await request('/api/admin/movies','POST',{title:'Test movie',category:'Романтик',price:5000,year:2026,duration:'2 min',poster,video:vid,published:true},owner);assert.equal(r.status,200);const movie=(await r.json()).id;
 const list=await (await request('/api/movies')).json();assert.equal(list.length,1);assert.equal(list[0].video,undefined);
 assert.equal((await request('/media/'+vid)).status,404);
 assert.equal((await request('/stream/'+movie,'GET',undefined,viewer)).status,403);
 assert.equal((await request('/stream/'+movie)).status,403);
 assert.equal((await request('/api/orders','POST',{movieId:movie},viewer,{Origin:'https://evil.example'})).status,403);
 r=await request('/api/orders','POST',{movieId:movie,amount:1,note:'test transfer'},viewer);assert.equal(r.status,201);const order=(await r.json()).id;
 assert.equal((await request('/api/orders','POST',{movieId:movie},viewer)).status,409);
 const orders=await (await request('/api/orders','GET',undefined,viewer)).json();assert.equal(orders[0].amount,5000);
 assert.equal((await request('/api/admin/review','POST',{id:order,status:'approved'},viewer)).status,403);
 assert.equal((await request('/api/admin/review','POST',{id:order,status:'approved'},owner)).status,200);
 assert.equal((await request('/api/admin/review','POST',{id:order,status:'approved'},owner)).status,409);
 assert.equal((await request('/api/watch/'+movie,'GET',undefined,viewer)).status,200);
 r=await request('/stream/'+movie,'GET',undefined,viewer,{Range:'bytes=4-7'});assert.equal(r.status,206);assert.equal(await r.text(),'ftyp');
 assert.equal((await request('/stream/'+movie,'GET',undefined,viewer,{Range:'bytes=9999-'})).status,416);
 assert.equal((await request('/stream/'+movie,'GET',undefined,other)).status,403);
 r=await request('/api/orders','POST',{movieId:movie},other);const second=(await r.json()).id;
 assert.equal((await request('/api/admin/review','POST',{id:second,status:'rejected',reason:'No payment'},owner)).status,200);
 assert.equal((await request('/stream/'+movie,'GET',undefined,other)).status,403);
 assert.equal((await request('/api/orders','POST',{movieId:movie},other)).status,201);
 assert.equal((await request('/api/logout','POST',{},viewer)).status,200);
 assert.equal((await request('/stream/'+movie,'GET',undefined,viewer)).status,403);
 }finally{child.kill();await new Promise(r=>child.once('exit',r));rmSync(data,{recursive:true,force:true});}
});
