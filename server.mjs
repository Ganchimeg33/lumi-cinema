import {createEmailRegistration,emailReady} from './email-otp.mjs';
import http from 'node:http';
import {randomBytes,createHash} from 'node:crypto';
import {createReadStream,createWriteStream,statSync,existsSync,unlinkSync,openSync,readSync,closeSync} from 'node:fs';
import {resolve,extname} from 'node:path';
import {pipeline} from 'node:stream/promises';
import {Transform} from 'node:stream';
import {db,get,all,run,dataDir,userId,hashPassword,checkPassword,settings} from './db.mjs';
const emailRegistration=createEmailRegistration();
const port=Number(process.env.PORT||8080), origin=process.env.PUBLIC_ORIGIN||`http://localhost:${port}`;
const secure=process.env.COOKIE_SECURE==='true';
const pub=resolve('public'), media=resolve(dataDir,'media');
const uid=()=>randomBytes(16).toString('hex'), digest=t=>createHash('sha256').update(t).digest('hex');
const rates=new Map();
function fail(message,status=400){throw Object.assign(Error(message),{status});}
function rate(key,limit=30){const now=Date.now();let r=rates.get(key);if(!r||r.until<now){r={n:0,until:now+600000};rates.set(key,r);}if(++r.n>limit)fail('Түр хүлээгээд дахин оролдоно уу.',429);}
setInterval(()=>{const now=Date.now();for(const [k,v] of rates)if(v.until<now)rates.delete(k);run('DELETE FROM sessions WHERE expires<?',now);},600000).unref();
function json(res,value,status=200){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(value));}
async function body(req){let b='',n=0;for await(const c of req){n+=c.length;if(n>32768)fail('Мэдээлэл хэт том байна.',413);b+=c;}try{return JSON.parse(b||'{}');}catch{fail('Мэдээлэл буруу байна.');}}
function text(v,max=200){return typeof v==='string'?v.trim().slice(0,max):'';}
function auth(req){const match=(req.headers.cookie||'').match(/(?:^|;\s*)lumi_session=([a-f0-9]{64})(?:;|$)/);return match?get('SELECT u.id,u.username,u.role FROM users u JOIN sessions s ON u.id=s.user_id WHERE s.token=? AND s.expires>?',digest(match[1]),Date.now()):null;}
function required(u){if(!u)fail('Эхлээд нэвтэрнэ үү.',401);return u;}
function admin(u){required(u);if(u.role!=='admin')fail('Админ эрх шаардлагатай.',403);}
function canWatch(u,m){return u&&(u.role==='admin'||(m.published&&(m.price===0||get('SELECT 1 FROM access WHERE user_id=? AND movie_id=?',u.id,m.id))));}
function movieView(m,u){const {video,...safe}=m;return {...safe,ready:!!video,owned:!!canWatch(u,m),poster: m.poster?'/media/'+m.poster:null};}
function transaction(fn){db.exec('BEGIN IMMEDIATE');try{const value=fn();db.exec('COMMIT');return value;}catch(e){db.exec('ROLLBACK');throw e;}}
function log(u,action,target){run('INSERT INTO audit(actor,action,target) VALUES(?,?,?)',u.id,action,target);}
function sendFile(req,res,path,mime,privateFile=false){if(!existsSync(path))fail('Файл олдсонгүй.',404);const size=statSync(path).size;let start=0,end=size-1,status=200;const range=req.headers.range;if(range){const m=/^bytes=(\d*)-(\d*)$/.exec(range);if(!m||(!m[1]&&!m[2])){res.writeHead(416,{'Content-Range':`bytes */${size}`});return res.end();}if(!m[1])start=Math.max(0,size-Number(m[2]));else start=Number(m[1]);if(m[1]&&m[2])end=Math.min(size-1,Number(m[2]));if(start>end||start>=size){res.writeHead(416,{'Content-Range':`bytes */${size}`});return res.end();}status=206;}const headers={'Content-Type':mime,'Content-Length':end-start+1,'Accept-Ranges':'bytes','Cache-Control':privateFile?'private, no-store':'public, max-age=300'};if(status===206)headers['Content-Range']=`bytes ${start}-${end}/${size}`;res.writeHead(status,headers);if(req.method==='HEAD')return res.end();const stream=createReadStream(path,{start,end});stream.on('error',()=>res.destroy());res.on('close',()=>stream.destroy());stream.pipe(res);}
async function upload(req,res,u){admin(u);const kind=req.headers['x-file-kind'];const mime=req.headers['content-type']?.split(';')[0];const allowed=kind==='poster'?['image/jpeg','image/png','image/webp']:kind==='video'?['video/mp4','video/webm']:[];if(!allowed.includes(mime))fail('Зураг JPG/PNG/WebP, видео MP4/WebM байна.');const max=(kind==='poster'?8:Number(process.env.MAX_VIDEO_MB||4096))*1024*1024;if(Number(req.headers['content-length'])>max)fail('Файлын хэмжээ хэтэрсэн.',413);const id=uid(),path=resolve(media,id);let n=0;try{await pipeline(req,new Transform({transform(c,e,cb){n+=c.length;cb(n>max?Object.assign(Error('Файлын хэмжээ хэтэрсэн.'),{status:413}):null,c);}}),createWriteStream(path,{flags:'wx',mode:0o600}));const fd=openSync(path,'r'),h=Buffer.alloc(16);readSync(fd,h,0,16,0);closeSync(fd);const valid=mime==='image/png'?h.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):mime==='image/jpeg'?h[0]===255&&h[1]===216&&h[2]===255:mime==='image/webp'?h.toString('ascii',0,4)==='RIFF'&&h.toString('ascii',8,12)==='WEBP':mime==='video/mp4'?h.toString('ascii',4,8)==='ftyp':h.subarray(0,4).equals(Buffer.from([26,69,223,163]));if(!valid)fail('Файлын формат тохирохгүй байна.');run('INSERT INTO assets VALUES(?,?,?,?)',id,kind,mime,n);json(res,{id},201);}catch(e){if(existsSync(path))unlinkSync(path);throw e;}}
const server=http.createServer(async(req,res)=>{try{
res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
const url=new URL(req.url,origin),p=url.pathname,u=auth(req);
if(!['GET','HEAD','POST','PUT','DELETE'].includes(req.method))fail('Method not allowed',405);

if(!['GET','HEAD'].includes(req.method)){
  const space = process.env.CODESPACE_NAME;
  const domain = process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN || 'app.github.dev';
  const forwarded = Boolean(space) &&
    origin === `https://${space}-${port}.${domain}` &&
    req.headers.origin === `https://localhost:${port}` &&
    req.headers.host === `localhost:${port}`;

  if(req.headers['x-lumi-request'] !== '1' ||
     (req.headers.origin !== origin && !forwarded)){
    fail('Хүсэлтийг баталгаажуулж чадсангүй. Хуудсаа шинэчлээд дахин оролдоно уу.',403);
  }
}
if(p==='/api/session'&&req.method==='GET')return json(res,{user:u||null,settings:settings()});
if(p==='/api/register'&&req.method==='POST'){
 if(!emailReady())fail('Имэйл баталгаажуулалт хараахан тохируулаагүй байна. Админтай холбогдоно уу.',503);
 return json(res,await emailRegistration.start(await body(req),req.socket.remoteAddress),202);
}
if(p==='/api/register/resend'&&req.method==='POST')return json(res,await emailRegistration.resend(await body(req),req.socket.remoteAddress));
if(p==='/api/register/verify'&&req.method==='POST'){
 const user=emailRegistration.verify(await body(req),req.socket.remoteAddress);
 const token=randomBytes(32).toString('hex');run('INSERT INTO sessions VALUES(?,?,?)',digest(token),user.id,Date.now()+604800000);
 res.setHeader('Set-Cookie',`lumi_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secure?'; Secure':''}`);
 return json(res,{ok:true});
}
if(p==='/api/login'&&req.method==='POST'){
 rate(req.socket.remoteAddress+':auth');const b=await body(req),identifier=text(b.username,254),password=b.password;
 if(!identifier||typeof password!=='string'||password.length<8||password.length>128)fail('Имэйл/нэр болон нууц үгээ оруулна уу.');
 const user=get('SELECT * FROM users WHERE username=? OR email=?',identifier,identifier.toLowerCase());
 if(!user||!await checkPassword(password,user.password))fail('Нэвтрэх нэр эсвэл нууц үг буруу.',401);
 const token=randomBytes(32).toString('hex');run('INSERT INTO sessions VALUES(?,?,?)',digest(token),user.id,Date.now()+604800000);
 res.setHeader('Set-Cookie',`lumi_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${secure?'; Secure':''}`);
 return json(res,{ok:true});
}
if(p==='/api/logout'&&req.method==='POST'){const token=(req.headers.cookie||'').match(/lumi_session=([a-f0-9]{64})/)?.[1];if(token)run('DELETE FROM sessions WHERE token=?',digest(token));res.setHeader('Set-Cookie',`lumi_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure?'; Secure':''}`);return json(res,{ok:true});}
if(p==='/api/movies'&&req.method==='GET')return json(res,all('SELECT * FROM movies WHERE published=1 ORDER BY created DESC').map(m=>movieView(m,u)));
if(p==='/api/orders'&&req.method==='GET'){required(u);return json(res,all('SELECT o.*,m.title FROM orders o JOIN movies m ON o.movie_id=m.id WHERE user_id=? ORDER BY o.created DESC',u.id));}
if(p==='/api/orders'&&req.method==='POST'){required(u);rate(u.id+':order',20);const b=await body(req),m=get('SELECT * FROM movies WHERE id=? AND published=1',text(b.movieId));if(!m||!m.video)fail('Кино одоогоор бэлэн биш байна.');if(canWatch(u,m))fail('Танд энэ киноны эрх байна.');const s=settings();if(!s.account||!s.holder||!s.bank)fail('Төлбөрийн данс хараахан тохируулаагүй байна.');if(get("SELECT id FROM orders WHERE user_id=? AND movie_id=? AND status='pending'",u.id,m.id))fail('Таны хүсэлтийг шалгаж байна.',409);const id=uid();run('INSERT INTO orders(id,user_id,movie_id,amount,note) VALUES(?,?,?,?,?)',id,u.id,m.id,m.price,text(b.note,500));return json(res,{id},201);}
if(p.startsWith('/api/watch/')&&req.method==='GET'){const m=get('SELECT * FROM movies WHERE id=?',p.split('/').pop());if(!m)fail('Кино олдсонгүй.',404);if(!canWatch(u,m))fail('Кино үзэх эрх шаардлагатай.',403);if(!m.video)fail('Видео хараахан ороогүй байна.',404);run('UPDATE movies SET views=views+1 WHERE id=?',m.id);return json(res,{src:'/stream/'+m.id,title:m.title});}
if(p.startsWith('/stream/')&&['GET','HEAD'].includes(req.method)){const m=get('SELECT * FROM movies WHERE id=?',p.split('/').pop());if(!m||!canWatch(u,m))fail('Кино үзэх эрх шаардлагатай.',403);const a=get("SELECT * FROM assets WHERE id=? AND kind='video'",m.video);if(!a)fail('Видео олдсонгүй.',404);return sendFile(req,res,resolve(media,a.id),a.mime,true);}
if(p.startsWith('/media/')&&['GET','HEAD'].includes(req.method)){const a=get("SELECT * FROM assets WHERE id=? AND kind='poster'",p.split('/').pop());if(!a)fail('Зураг олдсонгүй.',404);return sendFile(req,res,resolve(media,a.id),a.mime);}
if(p.startsWith('/api/admin')){
 admin(u);
 if(p==='/api/admin/upload'&&req.method==='POST')return await upload(req,res,u);
 if(p==='/api/admin/data'&&req.method==='GET')return json(res,{movies:all('SELECT * FROM movies ORDER BY created DESC'),orders:all('SELECT o.*,u.username,m.title FROM orders o JOIN users u ON o.user_id=u.id JOIN movies m ON o.movie_id=m.id ORDER BY o.created DESC'),users:all('SELECT id,username,role,created FROM users ORDER BY created DESC'),settings:settings()});
 if(p==='/api/admin/settings'&&req.method==='PUT'){const b=await body(req);transaction(()=>{for(const key of ['brand','bank','account','holder','contact'])run('INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',key,text(b[key],150));log(u,'settings','site');});return json(res,{ok:true});}
 if(p==='/api/admin/movies'&&req.method==='POST'){
 const b=await body(req),id=text(b.id)||uid();const title=text(b.title,120),description=text(b.description,4000),category=text(b.category),price=Number(b.price),year=Number(b.year),duration=text(b.duration,40),poster=text(b.poster)||null,video=text(b.video)||null;
 if(!title||!['Орчин үеийн','Түүхэн','Романтик','Триллер'].includes(category)||!Number.isSafeInteger(price)||price<0||price>10000000||!Number.isInteger(year)||year<1900||year>2100)fail('Киноны нэр, төрөл, үнэ, оныг зөв оруулна уу.');
 for(const [asset,kind] of [[poster,'poster'],[video,'video']])if(asset&&!get('SELECT id FROM assets WHERE id=? AND kind=?',asset,kind))fail('Файл олдсонгүй.');
 if(b.published&&(!poster||!video))fail('Нийтлэхийн өмнө постер болон видео оруулна уу.');
 run(`INSERT INTO movies(id,title,description,category,price,year,duration,poster,video,featured,published) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,description=excluded.description,category=excluded.category,price=excluded.price,year=excluded.year,duration=excluded.duration,poster=excluded.poster,video=excluded.video,featured=excluded.featured,published=excluded.published`,id,title,description,category,price,year,duration,poster,video,b.featured?1:0,b.published?1:0);log(u,'movie.save',id);return json(res,{id});
 }
 if(p==='/api/admin/review'&&req.method==='POST'){const b=await body(req);if(!['approved','rejected'].includes(b.status))fail('Төлөв буруу.');transaction(()=>{const o=get('SELECT * FROM orders WHERE id=?',text(b.id));if(!o||o.status!=='pending')fail('Энэ хүсэлтийг аль хэдийн шалгасан байна.',409);run('UPDATE orders SET status=?,reason=?,reviewed=CURRENT_TIMESTAMP,reviewer=? WHERE id=?',b.status,text(b.reason,500),u.id,o.id);if(b.status==='approved')run('INSERT OR IGNORE INTO access(user_id,movie_id) VALUES(?,?)',o.user_id,o.movie_id);log(u,'order.'+b.status,o.id);});return json(res,{ok:true});}
 fail('Олдсонгүй.',404);
}
if(p.startsWith('/api/')||p.startsWith('/stream/'))fail('Олдсонгүй.',404);
if(!['GET','HEAD'].includes(req.method))fail('Олдсонгүй.',404);
const path=resolve(pub,'.'+decodeURIComponent(p==='/'?'/index.html':p));if(!path.startsWith(pub+'/'))fail('Олдсонгүй.',404);const types={'.html':'text/html; charset=utf-8','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.png':'image/png','.webmanifest':'application/manifest+json'};return sendFile(req,res,path,types[extname(path)]||'application/octet-stream');
}catch(e){if(res.headersSent||res.destroyed)return;if(!e.status)console.error(e);json(res,{error:e.status?e.message:'Серверийн алдаа гарлаа. Дахин оролдоно уу.'},e.status||500);}});
server.requestTimeout=3600000;
server.listen(port,'0.0.0.0',()=>console.log(`Lumi: http://localhost:${port}`));
