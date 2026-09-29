import {DatabaseSync} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {resolve} from 'node:path';
import {randomBytes,scrypt as rawScrypt,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
const scrypt=promisify(rawScrypt);
export const dataDir=resolve(process.env.DATA_DIR||'./data');
mkdirSync(resolve(dataDir,'media'),{recursive:true,mode:0o700});
export const db=new DatabaseSync(resolve(dataDir,'lumi.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT NOT NULL COLLATE NOCASE UNIQUE,password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY,kind TEXT NOT NULL,mime TEXT NOT NULL,size INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS movies(id TEXT PRIMARY KEY,title TEXT NOT NULL,description TEXT NOT NULL,category TEXT NOT NULL,price INTEGER NOT NULL CHECK(price>=0),year INTEGER NOT NULL,duration TEXT NOT NULL,poster TEXT REFERENCES assets(id),video TEXT REFERENCES assets(id),featured INTEGER NOT NULL DEFAULT 0,published INTEGER NOT NULL DEFAULT 0,views INTEGER NOT NULL DEFAULT 0,created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),movie_id TEXT NOT NULL REFERENCES movies(id),amount INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',note TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,reviewed TEXT,reviewer TEXT REFERENCES users(id));
CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_pending ON orders(user_id,movie_id) WHERE status='pending';
CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id);
CREATE TABLE IF NOT EXISTS access(user_id TEXT NOT NULL REFERENCES users(id),movie_id TEXT NOT NULL REFERENCES movies(id),created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(user_id,movie_id));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
`);
export const get=(q,...p)=>db.prepare(q).get(...p);
export const all=(q,...p)=>db.prepare(q).all(...p);
export const run=(q,...p)=>db.prepare(q).run(...p);
export async function hashPassword(p){const salt=randomBytes(16).toString('hex');const hash=await scrypt(p,salt,64);return salt+':'+hash.toString('hex');}
export async function checkPassword(p,stored){const [salt,h]=stored.split(':');const actual=await scrypt(p,salt,64);return timingSafeEqual(actual,Buffer.from(h,'hex'));}
export function userId(){for(let i=0;i<100;i++){const id=String(100000+randomBytes(4).readUInt32BE()%900000);if(!get('SELECT id FROM users WHERE id=?',id))return id;}throw Error('ID allocation failed');}
export function settings(){return Object.fromEntries(all('SELECT * FROM settings').map(x=>[x.key,x.value]));}
