const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {promisify} = require('util');
const {sealData, unsealData} = require('iron-session');

const scrypt = promisify(crypto.scrypt);
const SESSION_COOKIE = 'admin_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;
const loginAttempts = new Map();
let adminPasswordVerifier = null;
const GITHUB_REPOSITORY = 'Rinna1oveu/posmertie-admin-test';
const GITHUB_BRANCH = 'poems-data';
const GITHUB_FILE_PATH = 'data/poems.json';
const GITHUB_FILE_URL = `https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${GITHUB_FILE_PATH}`;
const GITHUB_CYCLES_FILE_PATH = 'data/cycles.json';
const GITHUB_CYCLES_FILE_URL = `https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/${GITHUB_CYCLES_FILE_PATH}`;
let poemWriteQueue = Promise.resolve();
let cycleWriteQueue = Promise.resolve();

async function initializeAdminPasswordVerifier(){
  let password = process.env.ADMIN_PASSWORD || '';
  delete process.env.ADMIN_PASSWORD;

  if(!password || !process.env.ADMIN_USERNAME){
    password = '';
    return;
  }

  const salt = crypto.randomBytes(16);
  try{
    const key = await scrypt(password, salt, 64, {N:32768, r:8, p:1, maxmem:64 * 1024 * 1024});
    adminPasswordVerifier = {salt, key};
  }finally{
    password = '';
  }
}

function getSessionPassword(){
  return process.env.ADMIN_SESSION_SECRET || '';
}

function getSessionCookie(req){
  const cookies = (req.headers.cookie || '').split(';');
  const prefix = SESSION_COOKIE + '=';
  const entry = cookies.find(cookie=>cookie.trim().startsWith(prefix));
  if(!entry) return '';
  try{
    return decodeURIComponent(entry.trim().slice(prefix.length));
  }catch{
    return '';
  }
}

function setSessionCookie(res, value, maxAge=SESSION_TTL_SECONDS){
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`);
}

async function getSession(req){
  const cookie = getSessionCookie(req);
  const password = getSessionPassword();
  if(!cookie || password.length < 32) return null;

  try{
    const session = await unsealData(cookie, {password, ttl:SESSION_TTL_SECONDS});
    if(session.username !== process.env.ADMIN_USERNAME) return null;
    return session;
  }catch{
    return null;
  }
}

function getClientIp(req){
  const forwardedFor = req.headers['x-forwarded-for'];
  if(typeof forwardedFor === 'string' && forwardedFor.trim()){
    return forwardedFor.split(',')[0].trim().slice(0, 100);
  }
  return req.socket.remoteAddress || 'unknown';
}

function isSameOrigin(req){
  const origin = req.headers.origin;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  if(typeof origin !== 'string' || typeof host !== 'string') return false;

  try{
    const parsedOrigin = new URL(origin);
    return parsedOrigin.protocol === 'https:' && parsedOrigin.host.toLowerCase() === host.toLowerCase();
  }catch{
    return false;
  }
}

function getLoginAttempt(ip){
  const now = Date.now();
  for(const [key, attempt] of loginAttempts){
    if(now - attempt.windowStartedAt >= LOGIN_WINDOW_MS) loginAttempts.delete(key);
  }

  let attempt = loginAttempts.get(ip);
  if(!attempt || now - attempt.windowStartedAt >= LOGIN_WINDOW_MS){
    attempt = {count:0, windowStartedAt:now};
    loginAttempts.set(ip, attempt);
    if(loginAttempts.size > 10000){
      const oldestIp = loginAttempts.keys().next().value;
      loginAttempts.delete(oldestIp);
    }
  }

  return attempt;
}

async function verifyAdminPassword(password){
  if(!adminPasswordVerifier) return false;

  try{
    const actual = await scrypt(password, adminPasswordVerifier.salt, 64, {N:32768, r:8, p:1, maxmem:64 * 1024 * 1024});
    return crypto.timingSafeEqual(actual, adminPasswordVerifier.key);
  }catch{
    return false;
  }
}

function sendJson(res, status, value){
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store'});
  res.end(JSON.stringify(value));
}

function githubApiError(status, code){
  const error = new Error('GitHub API request failed');
  error.status = status;
  error.code = code;
  return error;
}

function getPoemId(poem, index){
  if(typeof poem.id === 'string' && poem.id) return poem.id;
  const legacyData = {...poem};
  delete legacyData.id;
  const signature = `${index}\0${JSON.stringify(legacyData)}`;
  return `legacy-${crypto.createHash('sha256').update(signature).digest('hex').slice(0, 24)}`;
}

async function githubRequest(method, body, fileUrl=GITHUB_FILE_URL){
  const token = process.env.GITHUB_TOKEN;
  if(!token) throw githubApiError(503, 'GITHUB_TOKEN_MISSING');

  const headers = {
    'Accept':'application/vnd.github+json',
    'Authorization':`Bearer ${token}`,
    'X-GitHub-Api-Version':'2022-11-28'
  };
  const options = {
    method,
    headers,
    signal:AbortSignal.timeout(15000)
  };

  if(body){
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }

  const url = method === 'GET'
    ? `${fileUrl}?ref=${encodeURIComponent(GITHUB_BRANCH)}`
    : fileUrl;
  return fetch(url, options);
}

async function readPoemsFromGitHub(){
  const response = await githubRequest('GET');
  if(response.status === 404) return {poems:[], sha:null};
  if(!response.ok) throw githubApiError(response.status);

  try{
    const file = await response.json();
    if(file.encoding !== 'base64' || typeof file.content !== 'string' || typeof file.sha !== 'string'){
      throw new Error('Invalid file response');
    }
    const content = Buffer.from(file.content.replace(/\s/g, ''), 'base64').toString('utf8');
    const poems = JSON.parse(content);
    if(!Array.isArray(poems) || poems.some(poem=>!poem || typeof poem !== 'object' || Array.isArray(poem))){
      throw new Error('Invalid poems data');
    }
    const poemsWithIds = poems.map((poem,index)=>({...poem,id:getPoemId(poem,index)}));
    return {poems:poemsWithIds, sha:file.sha};
  }catch{
    throw githubApiError(502, 'INVALID_GITHUB_FILE');
  }
}

async function writePoemsToGitHub(poems, sha, message='Update poems from admin panel'){
  const body = {
    message,
    content:Buffer.from(JSON.stringify(poems, null, 2) + '\n', 'utf8').toString('base64'),
    branch:GITHUB_BRANCH
  };
  if(sha) body.sha = sha;

  const response = await githubRequest('PUT', body);
  if(!response.ok) throw githubApiError(response.status);
}

async function mutatePoemsOnGitHub(mutate, message){
  for(let attempt=0;attempt<3;attempt++){
    const current = await readPoemsFromGitHub();
    const poems = mutate(current.poems);

    try{
      await writePoemsToGitHub(poems, current.sha, message);
      return poems;
    }catch(error){
      if((error.status === 409 || error.status === 422) && attempt < 2) continue;
      throw error;
    }
  }

  throw githubApiError(409, 'GITHUB_WRITE_CONFLICT');
}

function queuePoemMutation(mutate, message){
  const operation = poemWriteQueue.then(()=>mutatePoemsOnGitHub(mutate, message));
  poemWriteQueue = operation.then(()=>undefined, ()=>undefined);
  return operation;
}

function validatePoem(input){
  const title = typeof input.title === 'string' ? input.title.trim() : '';
  const text = typeof input.text === 'string' ? input.text.trim() : '';
  const date = typeof input.date === 'string' ? input.date.trim() : '';
  const status = input.status === undefined ? 'published' : input.status;
  const image = typeof input.image === 'string' ? input.image.trim() : '';
  const caption = typeof input.caption === 'string' ? input.caption.trim() : '';

  if(!title || !text) return {error:'Название и текст обязательны'};
  if(title.length > 300 || text.length > 1000000) return {error:'Название или текст слишком длинные'};
  if(date){
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date)) return {error:'Укажите корректную дату'};
    const parsedDate = new Date(date + 'T00:00:00.000Z');
    if(Number.isNaN(parsedDate.getTime()) || parsedDate.toISOString().slice(0,10) !== date) return {error:'Укажите корректную дату'};
  }
  if(status !== 'published' && status !== 'draft') return {error:'Неизвестный статус стихотворения'};
  if(image.length > 2048 || caption.length > 500) return {error:'Ссылка или подпись к иллюстрации слишком длинная'};
  const hasUnsupportedScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(image) && !image.startsWith('http://') && !image.startsWith('https://');
  if(image && (hasUnsupportedScheme || !(image.startsWith('http://') || image.startsWith('https://') || image.startsWith('/') || /^[a-zA-Z0-9._-]/.test(image)))) return {error:'Укажите ссылку или путь к изображению'};

  return {poem:{title,text,date,status,image,caption}};
}

function sendPoemMutationError(res, error){
  if(error.code === 'POEM_NOT_FOUND'){
    sendJson(res, 404, {error:'Стихотворение не найдено'});
    return;
  }
  sendGitHubError(res, error, 'write');
}

function getCycleId(cycle, index){
  if(typeof cycle.id === 'string' && cycle.id) return cycle.id;
  const legacyData = {...cycle};
  delete legacyData.id;
  const signature = `${index}\0${JSON.stringify(legacyData)}`;
  return `legacy-cycle-${crypto.createHash('sha256').update(signature).digest('hex').slice(0, 24)}`;
}

async function readCyclesFromGitHub(){
  const response = await githubRequest('GET', undefined, GITHUB_CYCLES_FILE_URL);
  if(response.status === 404) return {cycles:[], sha:null};
  if(!response.ok) throw githubApiError(response.status);

  try{
    const file = await response.json();
    if(file.encoding !== 'base64' || typeof file.content !== 'string' || typeof file.sha !== 'string'){
      throw new Error('Invalid file response');
    }
    const content = Buffer.from(file.content.replace(/\s/g, ''), 'base64').toString('utf8');
    const cycles = JSON.parse(content);
    if(!Array.isArray(cycles) || cycles.some(cycle=>!cycle || typeof cycle !== 'object' || Array.isArray(cycle))){
      throw new Error('Invalid cycles data');
    }
    const cyclesWithIds = cycles.map((cycle,index)=>({
      ...cycle,
      id:getCycleId(cycle,index),
      poemIds:Array.isArray(cycle.poemIds) ? cycle.poemIds.filter(id=>typeof id === 'string') : []
    }));
    return {cycles:cyclesWithIds, sha:file.sha};
  }catch{
    throw githubApiError(502, 'INVALID_GITHUB_CYCLES_FILE');
  }
}

async function writeCyclesToGitHub(cycles, sha, message='Update cycles from admin panel'){
  const body = {
    message,
    content:Buffer.from(JSON.stringify(cycles, null, 2) + '\n', 'utf8').toString('base64'),
    branch:GITHUB_BRANCH
  };
  if(sha) body.sha = sha;

  const response = await githubRequest('PUT', body, GITHUB_CYCLES_FILE_URL);
  if(!response.ok) throw githubApiError(response.status);
}

async function mutateCyclesOnGitHub(mutate, message){
  for(let attempt=0;attempt<3;attempt++){
    const current = await readCyclesFromGitHub();
    const cycles = mutate(current.cycles);

    try{
      await writeCyclesToGitHub(cycles, current.sha, message);
      return cycles;
    }catch(error){
      if((error.status === 409 || error.status === 422) && attempt < 2) continue;
      throw error;
    }
  }

  throw githubApiError(409, 'GITHUB_CYCLES_WRITE_CONFLICT');
}

function queueCycleMutation(mutate, message){
  const operation = cycleWriteQueue.then(()=>mutateCyclesOnGitHub(mutate, message));
  cycleWriteQueue = operation.then(()=>undefined, ()=>undefined);
  return operation;
}

function validateCycle(input, existingPoemIds){
  const title = typeof input.title === 'string' ? input.title.trim() : '';
  const description = typeof input.description === 'string' ? input.description.trim() : '';
  const status = input.status === undefined ? 'published' : input.status;
  const cover = typeof input.cover === 'string' ? input.cover.trim() : '';
  const poemIds = input.poemIds;

  if(!title) return {error:'Название цикла обязательно'};
  if(title.length > 300 || description.length > 10000) return {error:'Название или описание цикла слишком длинные'};
  if(status !== 'published' && status !== 'draft') return {error:'Неизвестный статус цикла'};
  const hasUnsupportedScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(cover) && !cover.startsWith('http://') && !cover.startsWith('https://');
  if(cover.length > 2048 || (cover && (hasUnsupportedScheme || !(cover.startsWith('http://') || cover.startsWith('https://') || cover.startsWith('/') || /^[a-zA-Z0-9._-]/.test(cover))))) return {error:'Укажите ссылку или путь к обложке'};
  if(!Array.isArray(poemIds) || poemIds.length > 500 || poemIds.some(id=>typeof id !== 'string' || !id)) return {error:'Неверный список стихотворений'};
  if(new Set(poemIds).size !== poemIds.length) return {error:'Стихотворение уже добавлено в цикл'};
  if(poemIds.some(id=>!existingPoemIds.has(id))) return {error:'В цикле могут быть только существующие стихотворения'};

  return {cycle:{title,description,status,cover,poemIds:[...poemIds]}};
}

function sendCycleMutationError(res, error){
  if(error.code === 'CYCLE_NOT_FOUND'){
    sendJson(res, 404, {error:'Цикл не найден'});
    return;
  }
  sendGitHubError(res, error, 'write');
}

function sendGitHubError(res, error, action){
  if(error.code === 'GITHUB_TOKEN_MISSING'){
    sendJson(res, 503, {error:'Хранилище стихотворений не настроено'});
    return;
  }

  if(error.status) console.error(`GitHub ${action} failed with status ${error.status}`);
  else console.error(`GitHub ${action} failed`);
  sendJson(res, 502, {error:action === 'read' ? 'Не удалось загрузить стихотворения' : 'Не удалось сохранить стихотворение'});
}

function readRequestBody(req){
  return new Promise((resolve, reject)=>{
    let body = '';
    req.setEncoding('utf8');
    req.on('data', chunk=>{
      body += chunk;
      if(body.length > 1024 * 1024){
        reject(new Error('Request body is too large'));
        req.destroy();
      }
    });
    req.on('end', ()=>resolve(body));
    req.on('error', reject);
  });
}

const html = `
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#17171c">
<title>Посмертие Ринны — Архив</title>
<style>
:root{
  color-scheme:dark;
  --ink:#f5eff0;
  --muted:#ae9ca0;
  --dim:#79666b;
  --line:#45141f;
  --nav:#0a0709;
  --nav-hover:#241015;
  --canvas:#0d0709;
  --panel:#160c10;
  --panel-soft:#1c0d12;
  --accent:#ee2349;
  --accent-bright:#ff365a;
  --accent-dark:#3a0d18;
  --success:#a0ae8b;
  --danger:#ff7180;
}
*{box-sizing:border-box}
body{
  position:relative;
  margin:0;
  background:
    radial-gradient(ellipse at 78% 0%,#310c1938 0,transparent 38%),
    radial-gradient(ellipse at 10% 38%,#2109102c 0,transparent 45%),
    var(--canvas);
  color:var(--ink);
  font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  font-size:15px;
  line-height:1.5;
}
body:before{
  content:"";
  position:fixed;
  z-index:0;
  inset:0;
  pointer-events:none;
  opacity:.15;
  background:
    linear-gradient(90deg,transparent 0,transparent 79px,#8d1a321f 80px,transparent 81px),
    linear-gradient(0deg,transparent 0,transparent 79px,#8d1a3212 80px,transparent 81px);
  background-size:80px 80px;
}
button,input,textarea{font:inherit}
button{cursor:pointer}
.login,.app{position:relative;z-index:1}
.login{
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:24px;
  background:radial-gradient(ellipse at 50% 0,#3a101c88 0,transparent 56%);
}
.login-box{
  width:min(100%,430px);
  padding:38px;
  background:#130a0e;
  border:1px solid #6a1c2d;
  border-radius:3px;
  box-shadow:0 28px 90px #0009,0 0 55px #5c0c2018;
}
.login-mark,.brand-mark{
  display:grid;
  place-items:center;
  width:42px;
  height:42px;
  border:1px solid #8d2038;
  border-radius:2px;
  color:var(--accent-bright);
  font-family:Georgia,"Times New Roman",serif;
  font-size:23px;
}
.login-box .login-mark{margin-bottom:22px}
.logo{font:700 29px Georgia,"Times New Roman",serif;letter-spacing:.01em}
.muted{color:var(--muted)}
.login .muted{margin:8px 0 28px}
label{display:block;color:#cbbdc0;font-size:13px;margin:18px 0 7px}
input,textarea{
  width:100%;
  background:#0b0709;
  color:#fff;
  border:1px solid #51202a;
  border-radius:2px;
  padding:13px 14px;
  outline:none;
  transition:border-color .16s,box-shadow .16s,background .16s;
}
input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 2px #ee234922;background:#10080b}
.btn{
  border:1px solid var(--accent);
  border-radius:2px;
  padding:12px 17px;
  background:var(--accent);
  color:#fff7f8;
  font-weight:750;
  letter-spacing:.015em;
  transition:background .16s,border-color .16s,color .16s,transform .16s,box-shadow .16s;
}
.btn:hover{background:var(--accent-bright);border-color:var(--accent-bright);transform:translateY(-1px);box-shadow:0 5px 18px #ee23492e}
.btn:disabled{opacity:.55;cursor:wait;transform:none;box-shadow:none}
.login .btn{width:100%;margin-top:22px}
.error{color:#ff9ca7;margin-top:14px;display:none}
.app{display:none;min-height:100vh}
.sidebar{
  position:fixed;
  z-index:5;
  inset:0 auto 0 0;
  width:254px;
  display:flex;
  flex-direction:column;
  padding:26px 17px 18px;
  background:linear-gradient(180deg,#0d080a 0,#0a0709 100%);
  border-right:1px solid #571827;
}
.brand{display:flex;align-items:center;gap:12px;padding:1px 9px 30px}
.brand-mark{flex:0 0 42px}
.brand-name{font:700 17px Georgia,"Times New Roman",serif;letter-spacing:.015em}
.brand-caption{color:#8d6a73;font-size:10px;letter-spacing:.17em;text-transform:uppercase;margin-top:3px}
.nav{display:grid;gap:5px}
.nav-link{
  position:relative;
  display:flex;
  align-items:center;
  gap:13px;
  width:100%;
  padding:11px 12px;
  color:#a9969b;
  text-align:left;
  background:transparent;
  border:1px solid transparent;
  border-radius:2px;
  transition:background .16s,color .16s,border-color .16s;
}
.nav-link:hover{background:#210d13;color:#fff;border-color:#4e1624}
.nav-link.active{background:linear-gradient(90deg,#3a101b,#200d12);border-color:#711d31;color:#fff}
.nav-link.active:before{content:"";position:absolute;inset:7px auto 7px -1px;width:2px;background:var(--accent)}
.nav-icon{width:20px;text-align:center;color:#a15a69;font-size:17px}
.nav-link:hover .nav-icon,.nav-link.active .nav-icon{color:var(--accent-bright)}
.sidebar-bottom{margin-top:auto}
.sidebar-note{margin:0 8px 14px;padding:13px 11px;border-top:1px solid #4a1724;color:#866e74;font:italic 13px Georgia,"Times New Roman",serif}
.logout{color:#c9828f}
.logout:hover{background:#300d18;color:#ffdfe4;border-color:#83223a}
.content{margin-left:254px;max-width:1500px;padding:30px 42px 52px}
.topbar{
  display:flex;
  justify-content:space-between;
  align-items:center;
  min-height:53px;
  margin-bottom:34px;
  padding-bottom:19px;
  border-bottom:1px solid #4e1725;
}
.crumb{color:#c4adb2;font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.crumb:before{
  content:"ARCHIVE / PERSONAL / 2026";
  display:block;
  margin-bottom:5px;
  color:#a93a51;
  font-size:9px;
  font-weight:700;
  letter-spacing:.2em;
}
.topbar-user{display:flex;align-items:center;gap:10px;color:#c9b8bc;font-size:12px;letter-spacing:.04em}
.avatar{display:grid;place-items:center;width:34px;height:34px;border:1px solid #792039;border-radius:2px;color:var(--accent-bright);font-family:Georgia,serif}
.section{display:none;animation:appear .22s ease}
.section.active{display:block}
@keyframes appear{from{opacity:.3;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.page-heading{margin-bottom:25px}
h1{margin:0;font:800 clamp(30px,3.2vw,43px)/1.08 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:-.045em}
.subtitle{margin-top:9px;color:#a9959a;font:italic 16px Georgia,"Times New Roman",serif}
.eyebrow{margin-bottom:10px;color:#d24660;font-size:10px;font-weight:750;letter-spacing:.2em;text-transform:uppercase}
#dashboard .hero .eyebrow:before{
  content:"00 / ARCHIVE";
  display:block;
  margin-bottom:10px;
  color:#c44159;
  font-size:9px;
  letter-spacing:.2em;
}
#poems .page-heading .eyebrow:before{content:"01 / POETRY  ·  "}
#cycles .page-heading .eyebrow:before{content:"02 / CYCLES  ·  "}
#prose .page-heading .eyebrow:before{content:"03 / PROSE  ·  "}
#settings .page-heading .eyebrow:before{content:"04 / SETTINGS  ·  "}
.hero{
  position:relative;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:24px;
  overflow:hidden;
  padding:34px 36px;
  border:1px solid #702033;
  border-radius:2px;
  background:linear-gradient(112deg,#260b13 0,#1b0a10 55%,#16090e 100%);
  margin-bottom:20px;
  box-shadow:inset 0 1px #e43a581c,0 16px 38px #0003;
}
.hero:before{content:"";position:absolute;inset:0 auto 0 0;width:2px;background:linear-gradient(180deg,transparent,var(--accent),transparent)}
.hero-content{position:relative;z-index:1;flex:1;min-width:0}
.hero-mascot{position:relative;z-index:1;display:block;flex:0 0 auto;width:auto;height:128px;max-width:25%;object-fit:contain;opacity:.72;filter:saturate(.72) brightness(.78);pointer-events:none;user-select:none}
.hero h1{position:relative;z-index:1}
.hero p{position:relative;z-index:1;max-width:600px;margin:12px 0 22px;color:#c6b3b7;font:italic 16px/1.65 Georgia,"Times New Roman",serif}
.quick-actions{position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:9px}
.btn-secondary{
  padding:10px 14px;
  background:#11080c;
  border:1px solid #662034;
  border-radius:2px;
  color:#e7d9dc;
  font-weight:650;
  transition:background .16s,border-color .16s,color .16s,transform .16s;
}
.btn-secondary:hover{background:#3b0e1b;border-color:var(--accent);color:#fff;transform:translateY(-1px)}
.btn-secondary:after{content:" ↗";color:#c5405b}
.btn-secondary .plus{color:var(--accent-bright);margin-right:7px}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:20px}
.stat-card,.panel,.storage-card{position:relative;background:linear-gradient(145deg,#1a0d12,#130a0e);border:1px solid #431722;border-radius:2px;box-shadow:0 10px 26px #0002}
.stat-card:before,.panel:before{content:"";position:absolute;top:-1px;left:18px;width:38px;height:1px;background:#b52a46}
.stat-card{padding:19px 21px;transition:border-color .18s,transform .18s,background .18s}
.stat-card:hover{transform:translateY(-2px);border-color:#84233b;background:#210d13}
.stat-top{display:flex;align-items:center;justify-content:space-between;color:#b7a5aa;font-size:12px;letter-spacing:.13em;text-transform:uppercase}
.stat-symbol{color:#d33755;font-size:18px}
.stat-number{margin-top:9px;color:#fff5f6;font:700 36px Georgia,"Times New Roman",serif}
.stat-foot{margin-top:2px;color:#806c72;font-size:11px;letter-spacing:.04em}
.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(250px,.85fr);gap:16px}
.panel{padding:21px 22px}
.panel-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:13px}
.panel h2{margin:0;color:#f2e8ea;font:600 21px Georgia,"Times New Roman",serif}
.panel-kicker{color:#946c75;font-size:10px;letter-spacing:.15em;text-transform:uppercase}
.recent-list{display:grid}
.recent-entry{display:grid;grid-template-columns:34px minmax(0,1fr);gap:12px;padding:13px 0;border-bottom:1px solid #3a151f;transition:padding .16s}
.recent-entry:hover{padding-left:5px}
.recent-entry:last-child{border-bottom:0}
.recent-icon{display:grid;place-items:center;width:32px;height:32px;border:1px solid #642033;border-radius:2px;background:#230c13;color:#ee3656}
.recent-title{overflow:hidden;color:#f1e7e9;text-overflow:ellipsis;white-space:nowrap;font-weight:650}
.recent-copy{display:-webkit-box;overflow:hidden;margin-top:3px;color:#a08d92;font:13px/1.45 Georgia,"Times New Roman",serif;-webkit-box-orient:vertical;-webkit-line-clamp:2}
.empty-note{padding:18px 0;color:#9a858b;font:italic 14px Georgia,"Times New Roman",serif}
.draft-empty{padding:14px 0 8px}
.draft-mark{display:grid;place-items:center;width:40px;height:40px;margin-bottom:12px;border:1px solid #5b1a2c;border-radius:2px;color:#dc3655;font-size:18px}
.draft-empty p{margin:5px 0 0;color:#9c888e;font:italic 13px Georgia,"Times New Roman",serif}
.storage-card{display:flex;align-items:flex-start;gap:13px;margin-top:15px;padding:16px;border-color:#4a1925}
.status-dot{flex:0 0 9px;width:9px;height:9px;margin-top:6px;border-radius:50%;background:#aa7f83;box-shadow:0 0 0 4px #aa7f8318}
.status-dot.online{background:var(--success);box-shadow:0 0 0 4px #a0ae8b1b}
.status-dot.offline{background:var(--danger);box-shadow:0 0 0 4px #ff71801b}
.storage-title{font-size:13px;font-weight:700}
.storage-copy{margin-top:3px;color:#9a858b;font-size:11px}
.section-top{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:22px}
.section-top .page-heading{margin:0}
.add{white-space:nowrap}
.add:after{content:"  →";font-size:15px}
.poem-panel{padding:22px}
#poem-form{max-width:780px;margin-bottom:21px;padding-bottom:21px;border-bottom:1px solid #592031}
#poem-form textarea{resize:vertical;min-height:160px}
.editor-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 16px}
.editor-field-wide{grid-column:1/-1}
.editor-fields select{width:100%;padding:13px 14px;background:#0b0709;color:#f5eff0;border:1px solid #51202a;border-radius:2px}
.editor-fields select:focus{outline:2px solid #ee234922;border-color:var(--accent)}
.optional{margin-left:5px;color:#927d83;font-size:11px}
.editor-actions{display:flex;flex-wrap:wrap;gap:9px;margin-top:22px}
.editor-actions .btn{width:auto}
.btn-danger{padding:10px 14px;background:#1c0a0f;border:1px solid #772036;border-radius:2px;color:#ed8797;font-weight:650}
.btn-danger:hover{background:#3b0d18;border-color:#e33454;color:#fff}
.poem-item-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.poem-item-date{margin-top:5px;color:#987d84;font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.poem-status{display:inline-block;padding:4px 8px;border:1px solid #783047;color:#f18ba0;font-size:10px;letter-spacing:.12em;text-transform:uppercase;white-space:nowrap}
.poem-status.draft{border-color:#69502a;color:#d8b777}
.poem-snippet{display:-webkit-box;overflow:hidden;margin-top:10px;color:#b4a1a6;font:14px/1.55 Georgia,"Times New Roman",serif;white-space:pre-wrap;-webkit-box-orient:vertical;-webkit-line-clamp:2}
.poem-item-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.poem-item-actions .btn-secondary,.poem-item-actions .btn-danger{padding:7px 10px;font-size:12px}
.poem-item-actions .btn-secondary:after{content:""}
.preview-overlay{position:fixed;z-index:20;inset:0;display:grid;place-items:center;padding:24px;background:#050305e8;backdrop-filter:blur(5px)}
.preview-overlay[hidden]{display:none}
.preview-dialog{width:min(100%,850px);max-height:min(90vh,900px);overflow:auto;background:#10080b;border:1px solid #762038;box-shadow:0 24px 100px #000b}
.preview-toolbar{position:sticky;top:0;z-index:2;display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:#10080bf2;border-bottom:1px solid #501725;color:#c54a62;font-size:10px;font-weight:700;letter-spacing:.18em}
.preview-poem{position:relative;max-width:700px;margin:0 auto;padding:clamp(28px,7vw,76px) clamp(22px,7vw,72px) 64px}
.preview-poem:before{content:"";position:absolute;top:28px;left:0;width:28px;height:1px;background:var(--accent)}
.preview-index{color:#ac4057;font-size:9px;font-weight:700;letter-spacing:.2em}
.preview-date{margin-top:24px;color:#a78e94;font-size:11px;letter-spacing:.12em;text-transform:uppercase}
.preview-poem h2{margin:12px 0 27px;color:#fff1f3;font:700 clamp(30px,5vw,48px)/1.12 Georgia,"Times New Roman",serif}
.preview-body{color:#e3d5d9;font:18px/1.9 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.preview-figure{margin:36px 0 0}
.preview-figure img{display:block;max-width:100%;max-height:440px;margin:0 auto;object-fit:contain}
.preview-figure figcaption{margin-top:10px;color:#a58a91;text-align:center;font:italic 13px Georgia,"Times New Roman",serif}
.preview-status{margin-top:26px;color:#a83b53;font-size:9px;font-weight:700;letter-spacing:.2em;text-transform:uppercase}
.cycle-picker{display:flex;align-items:stretch;gap:9px}
.cycle-picker select{flex:1;min-width:0;padding:11px 12px;background:#0b0709;color:#f5eff0;border:1px solid #51202a;border-radius:2px}
.cycle-picker button:disabled{opacity:.45;cursor:not-allowed}
.cycle-selection-heading{display:flex;justify-content:space-between;gap:12px;margin:22px 0 8px;color:#f0e4e7;font-size:13px;font-weight:700}
.cycle-selection-heading span{color:#90777e;font-size:11px;font-weight:400}
.cycle-selected-list{display:grid;gap:7px}
.cycle-selected-row{display:grid;grid-template-columns:34px minmax(0,1fr) auto;align-items:center;gap:10px;padding:9px 10px;border:1px solid #401722;background:#12090d}
.cycle-order{color:#a83d55;font:11px Georgia,serif;text-align:center}
.cycle-poem-name{overflow:hidden;color:#e9dce0;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.cycle-poem-missing{color:#d77b88}
.cycle-order-actions{display:flex;gap:5px}
.cycle-order-actions button{width:29px;height:29px;padding:0;border:1px solid #612034;border-radius:2px;background:#1a0b10;color:#dbaab3}
.cycle-order-actions button:hover:not(:disabled){border-color:var(--accent);background:#3b0e1b;color:#fff}
.cycle-order-actions button:disabled{opacity:.35;cursor:not-allowed}
.cycle-list{display:grid;gap:12px}
.cycle-card{display:grid;grid-template-columns:100px minmax(0,1fr);gap:17px;padding:17px 0;border-bottom:1px solid #401722}
.cycle-card:last-child{border-bottom:0}
.cycle-card-cover{width:100px;height:100px;object-fit:cover;border:1px solid #672034;background:#0c0709}
.cycle-card-cover[hidden]{display:none}
.cycle-card-body{min-width:0}
.cycle-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.cycle-card-description{margin:8px 0 0;color:#aa969c;font:14px/1.55 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.cycle-card-count{margin-top:8px;color:#946c75;font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.cycle-card-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:13px}
.cycle-card-actions button{padding:7px 10px;font-size:12px}
.cycle-card-actions .btn-secondary:after{content:""}
.cycle-empty{padding:20px 0;color:#a08a91;font:italic 15px Georgia,"Times New Roman",serif}
.cycle-preview-content{position:relative;max-width:760px;margin:0 auto;padding:clamp(28px,6vw,64px)}
.cycle-preview-cover{display:block;max-width:100%;max-height:300px;margin:0 auto 30px;object-fit:contain}
.cycle-preview-cover[hidden]{display:none}
.cycle-preview-content h2{margin:13px 0;color:#fff1f3;font:700 clamp(32px,5vw,50px)/1.1 Georgia,"Times New Roman",serif}
.cycle-preview-description{color:#c9b5bb;font:italic 16px/1.7 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.cycle-preview-poems{display:grid;margin-top:30px;border-top:1px solid #501725}
.cycle-preview-poem{padding:16px 0;border-bottom:1px solid #501725}
.cycle-preview-poem strong{display:block;color:#f2e4e7;font:600 19px Georgia,"Times New Roman",serif}
.cycle-preview-poem p{margin:6px 0 0;color:#a9959a;font:14px/1.55 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.poem-list .item{padding:18px 0;border-bottom:1px solid #401722}
.poem-list .item:last-child{border-bottom:0}
.item-title{margin-bottom:6px;color:#f4e9eb;font:600 21px Georgia,"Times New Roman",serif}
.item-meta{color:#b4a1a6;font:14px/1.65 Georgia,"Times New Roman",serif;white-space:pre-wrap}
.item-meta.empty-copy{color:#927d83}
.placeholder-panel{max-width:820px}
.placeholder-glyph{display:grid;place-items:center;width:48px;height:48px;margin-bottom:15px;border:1px solid #76223a;border-radius:2px;color:var(--accent-bright);font:24px Georgia,serif}
.placeholder-panel p{max-width:590px;margin:8px 0 0;color:#aa969c;font:italic 15px/1.65 Georgia,"Times New Roman",serif}
.settings-row{display:flex;justify-content:space-between;gap:16px;padding:15px 0;border-bottom:1px solid #401722;color:#cbb9bd}
.settings-row:last-child{border-bottom:0}
.settings-value{color:#a77c85;font-family:Georgia,"Times New Roman",serif}
@media(max-width:1000px){
  .content{padding:27px 28px}
  .sidebar{width:225px}
  .content{margin-left:225px}
  .dashboard-grid{grid-template-columns:1fr}
  .brand-name{font-size:15px}
}
@media(max-width:700px){
  .sidebar{position:sticky;inset:0 0 auto;width:100%;padding:12px 14px 10px;border-right:0;border-bottom:1px solid #571827}
  .brand{padding:0 4px 12px}
  .brand-mark{width:34px;height:34px;flex-basis:34px;border-radius:2px;font-size:19px}
  .brand-caption{display:none}
  .nav{display:flex;gap:5px;overflow-x:auto;padding-bottom:2px}
  .nav-link{width:auto;flex:0 0 auto;padding:9px 10px;font-size:13px}
  .nav-icon{width:auto}
  .nav-link.logout{margin-left:auto}
  .sidebar-bottom{display:none}
  .content{margin-left:0;padding:22px 17px 40px}
  .topbar{margin-bottom:25px}
  .topbar-user span:last-child{display:none}
  .hero{padding:25px 22px;gap:14px}
  .hero-mascot{height:100px;max-width:24%}
  .editor-fields{grid-template-columns:1fr}
  .editor-field-wide{grid-column:auto}
  .cycle-picker{flex-direction:column}
  .stats{gap:9px}
  .stat-card{padding:15px 13px}
  .stat-top{align-items:flex-start;gap:5px;font-size:11px}
  .stat-number{font-size:29px}
  .stat-foot{font-size:10px}
  .section-top{align-items:flex-start;flex-direction:column}
  .add{width:auto}
  .poem-panel,.panel{padding:18px}
  .login-box{padding:29px 24px}
}
@media(max-width:480px){
  .hero{display:block;padding:22px 19px}
  .hero-mascot{height:76px;max-width:100%;margin:14px 0 0 auto}
  .preview-overlay{padding:10px}
  .preview-body{font-size:16px}
  .cycle-card{grid-template-columns:72px minmax(0,1fr);gap:12px}
  .cycle-card-cover{width:72px;height:72px}
  .cycle-selection-heading{flex-direction:column;gap:3px}
}
@media(max-width:420px){
  .nav-link{gap:7px;padding:8px;font-size:12px}
  .nav-icon{display:none}
  .stats{grid-template-columns:1fr}
  .stat-card{display:flex;align-items:center;justify-content:space-between}
  .stat-number{margin:0}
  .stat-foot{display:none}
  .quick-actions{display:grid;grid-template-columns:1fr}
  .btn-secondary{text-align:left}
}
</style>
</head>
<body>
<div class="login" id="login">
  <div class="login-box">
    <div class="login-mark" aria-hidden="true">Р</div>
    <div class="logo">Посмертие Ринны</div>
    <div class="muted">Личный кабинет литературного архива</div>
    <label for="user">Логин</label>
    <input id="user" autocomplete="username" placeholder="Введите логин">
    <label for="pass">Пароль</label>
    <input id="pass" type="password" autocomplete="current-password" placeholder="Введите пароль" onkeydown="if(event.key==='Enter')login()">
    <button class="btn" type="button" onclick="login()">Войти в архив</button>
    <div class="error" id="error" role="alert">Неверный логин или пароль</div>
  </div>
</div>
<div class="app" id="app">
  <aside class="sidebar">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">Р</div>
      <div><div class="brand-name">Посмертие Ринны</div><div class="brand-caption">Литературный архив</div></div>
    </div>
    <nav class="nav" aria-label="Основная навигация">
      <button class="nav-link active" type="button" data-view="dashboard" onclick="show('dashboard',this)"><span class="nav-icon" aria-hidden="true">⌂</span>Главная</button>
      <button class="nav-link" type="button" data-view="poems" onclick="show('poems',this)"><span class="nav-icon" aria-hidden="true">✎</span>Стихи</button>
      <button class="nav-link" type="button" data-view="cycles" onclick="show('cycles',this)"><span class="nav-icon" aria-hidden="true">◌</span>Циклы</button>
      <button class="nav-link" type="button" data-view="prose" onclick="show('prose',this)"><span class="nav-icon" aria-hidden="true">▤</span>Проза</button>
      <button class="nav-link" type="button" data-view="settings" onclick="show('settings',this)"><span class="nav-icon" aria-hidden="true">⚙</span>Настройки</button>
    </nav>
    <div class="sidebar-bottom">
      <div class="sidebar-note">Тихое место для слов, которые остаются.</div>
      <button class="nav-link logout" type="button" onclick="logout()"><span class="nav-icon" aria-hidden="true">↪</span>Выйти</button>
    </div>
  </aside>
  <main class="content">
    <div class="topbar">
      <div class="crumb">Архив <span aria-hidden="true">/</span> <span id="view-title">Главная</span></div>
      <div class="topbar-user"><span class="avatar" aria-hidden="true">Р</span><span>Администратор</span></div>
    </div>
    <section class="section active" id="dashboard">
      <div class="hero">
        <div class="hero-content">
          <div class="eyebrow">Личный архив</div>
          <h1>Добро пожаловать</h1>
          <p>Здесь собраны тексты Посмертия Ринны. Продолжайте работу с архивом или начните новую запись.</p>
          <div class="quick-actions">
            <button class="btn-secondary" type="button" onclick="startPoem()"><span class="plus">＋</span>Новый стих</button>
          <button class="btn-secondary" type="button" onclick="startCycle()"><span class="plus">＋</span>Новый цикл</button>
            <button class="btn-secondary" type="button" onclick="showSection('prose')"><span class="plus">＋</span>Новая проза</button>
          </div>
        </div>
        <img class="hero-mascot" src="/mascot.png" alt="" aria-hidden="true" width="128" height="128">
      </div>
      <div class="stats">
        <div class="stat-card"><div><div class="stat-top">Стихи <span class="stat-symbol">✎</span></div><div class="stat-number" id="poem-count">—</div><div class="stat-foot">в архиве</div></div></div>
        <div class="stat-card"><div><div class="stat-top">Циклы <span class="stat-symbol">◌</span></div><div class="stat-number" id="cycle-count">0</div><div class="stat-foot">раздел в разработке</div></div></div>
        <div class="stat-card"><div><div class="stat-top">Проза <span class="stat-symbol">▤</span></div><div class="stat-number" id="prose-count">0</div><div class="stat-foot">раздел в разработке</div></div></div>
      </div>
      <div class="dashboard-grid">
        <div class="panel">
          <div class="panel-heading"><h2>Последние изменения</h2><span class="panel-kicker">Недавние записи</span></div>
          <div class="recent-list" id="recent-list"><div class="empty-note">Загружаем архив…</div></div>
        </div>
        <div>
          <div class="panel">
            <div class="panel-heading"><h2>Черновики</h2><span class="panel-kicker">Личные заметки</span></div>
            <div class="draft-empty"><div class="draft-mark" aria-hidden="true">⌁</div><strong>Пока нет черновиков</strong><p>Сохранённые стихотворения сразу попадают в архив.</p></div>
          </div>
          <div class="storage-card" aria-live="polite">
            <span class="status-dot" id="storage-dot"></span>
            <div><div class="storage-title" id="storage-title">Проверяем хранилище</div><div class="storage-copy" id="storage-copy">Связь с архивом GitHub</div></div>
          </div>
        </div>
      </div>
    </section>
    <section class="section" id="poems">
      <div class="section-top">
        <div class="page-heading"><div class="eyebrow">Коллекция</div><h1>Стихи</h1><div class="subtitle">Стихотворения в литературном архиве</div></div>
        <button class="btn add" type="button" onclick="openPoemForm()">＋ Новое стихотворение</button>
      </div>
      <div class="panel poem-panel">
        <form id="poem-form" onsubmit="savePoem(event)" style="display:none">
          <input id="poem-id" type="hidden">
          <div class="panel-heading"><h2 id="poem-form-heading">Новое стихотворение</h2></div>
          <div class="editor-fields">
            <div class="editor-field editor-field-wide">
              <label for="poem-title">Название</label>
              <input id="poem-title" name="title" required maxlength="300" placeholder="Название стихотворения">
            </div>
            <div class="editor-field editor-field-wide">
              <label for="poem-text">Текст</label>
              <textarea id="poem-text" name="text" rows="10" required placeholder="Начните писать…"></textarea>
            </div>
            <div class="editor-field">
              <label for="poem-date">Дата</label>
              <input id="poem-date" name="date" type="date">
            </div>
            <div class="editor-field">
              <label for="poem-status">Статус</label>
              <select id="poem-status" name="status">
                <option value="published">Опубликовано</option>
                <option value="draft">Черновик</option>
              </select>
            </div>
            <div class="editor-field editor-field-wide">
              <label for="poem-image">Иллюстрация — ссылка или путь</label>
              <input id="poem-image" name="image" type="text" inputmode="url" maxlength="2048" placeholder="/images/poem.jpg или https://…">
            </div>
            <div class="editor-field editor-field-wide">
              <label for="poem-caption">Подпись к иллюстрации <span class="optional">необязательно</span></label>
              <input id="poem-caption" name="caption" type="text" maxlength="500" placeholder="Подпись">
            </div>
          </div>
          <div class="editor-actions">
            <button class="btn" type="submit">Сохранить</button>
            <button class="btn-secondary" type="submit" data-save-status="draft">Сохранить как черновик</button>
            <button class="btn-secondary" type="button" onclick="previewPoemForm()">Предпросмотр</button>
            <button class="btn-secondary" type="button" onclick="closePoemForm()">Закрыть</button>
            <button class="btn-danger" id="poem-delete" type="button" onclick="deleteEditingPoem()" hidden>Удалить</button>
          </div>
        </form>
        <div class="error" id="poem-error" role="alert"></div>
        <div class="poem-list" id="poem-list"></div>
      </div>
      <div class="preview-overlay" id="poem-preview" hidden onclick="if(event.target===this)closePoemPreview()">
      <article class="preview-dialog" role="dialog" aria-modal="true" aria-labelledby="preview-title">
        <div class="preview-toolbar"><span>PREVIEW / POETRY</span><button class="btn-secondary" type="button" onclick="closePoemPreview()">Закрыть <span aria-hidden="true">×</span></button></div>
        <div class="preview-poem">
          <div class="preview-index">ПОСМЕРТИЕ РИННЫ · АРХИВ</div>
          <div class="preview-date" id="preview-date"></div>
          <h2 id="preview-title"></h2>
          <div class="preview-body" id="preview-body"></div>
          <figure class="preview-figure" id="preview-figure" hidden><img id="preview-image" alt=""><figcaption id="preview-caption"></figcaption></figure>
          <div class="preview-status" id="preview-status"></div>
        </div>
      </article>
    </div>
    </section>
    <section class="section" id="cycles">
      <div class="section-top">
        <div class="page-heading"><div class="eyebrow">Структура архива</div><h1>Циклы</h1><div class="subtitle">Тематические собрания стихотворений</div></div>
        <button class="btn add" type="button" onclick="openCycleForm()">＋ Новый цикл</button>
      </div>
      <div class="panel cycle-panel">
        <form id="cycle-form" onsubmit="saveCycle(event)" style="display:none">
          <input id="cycle-id" type="hidden">
          <div class="panel-heading"><h2 id="cycle-form-heading">Новый цикл</h2></div>
          <div class="editor-fields">
            <div class="editor-field editor-field-wide">
              <label for="cycle-title">Название</label>
              <input id="cycle-title" name="title" required maxlength="300" placeholder="Название цикла">
            </div>
            <div class="editor-field editor-field-wide">
              <label for="cycle-description">Описание</label>
              <textarea id="cycle-description" name="description" rows="4" maxlength="10000" placeholder="Коротко о цикле"></textarea>
            </div>
            <div class="editor-field">
              <label for="cycle-status">Статус</label>
              <select id="cycle-status" name="status">
                <option value="published">Опубликован</option>
                <option value="draft">Черновик</option>
              </select>
            </div>
            <div class="editor-field">
              <label for="cycle-cover">Обложка — ссылка или путь</label>
              <input id="cycle-cover" name="cover" type="text" inputmode="url" maxlength="2048" placeholder="/images/cycle.jpg или https://…">
            </div>
            <div class="editor-field editor-field-wide">
              <label for="cycle-poem-picker">Добавить существующее стихотворение</label>
              <div class="cycle-picker">
                <select id="cycle-poem-picker" aria-label="Выберите стихотворение"></select>
                <button class="btn-secondary" id="cycle-add-poem" type="button" onclick="addPoemToCycle()">Добавить стих</button>
              </div>
              <div class="cycle-selection-heading">Стихи в цикле <span>Порядок можно менять кнопками ↑ и ↓</span></div>
              <div class="cycle-selected-list" id="cycle-selected-poems"></div>
            </div>
          </div>
          <div class="editor-actions">
            <button class="btn" type="submit">Сохранить цикл</button>
            <button class="btn-secondary" type="button" onclick="previewCycleForm()">Предпросмотр</button>
            <button class="btn-secondary" type="button" onclick="closeCycleForm()">Закрыть</button>
            <button class="btn-danger" id="cycle-delete" type="button" onclick="deleteEditingCycle()" hidden>Удалить цикл</button>
          </div>
        </form>
        <div class="error" id="cycle-error" role="alert"></div>
        <div class="cycle-list" id="cycle-list"></div>
      </div>
      <div class="preview-overlay" id="cycle-preview" hidden onclick="if(event.target===this)closeCyclePreview()">
        <article class="preview-dialog cycle-preview-dialog" role="dialog" aria-modal="true" aria-labelledby="cycle-preview-title">
          <div class="preview-toolbar"><span>PREVIEW / CYCLE</span><button class="btn-secondary" type="button" onclick="closeCyclePreview()">Закрыть <span aria-hidden="true">×</span></button></div>
          <div class="cycle-preview-content">
            <img class="cycle-preview-cover" id="cycle-preview-cover" alt="" hidden>
            <div class="preview-index">ПОСМЕРТИЕ РИННЫ · ЦИКЛ</div>
            <h2 id="cycle-preview-title"></h2>
            <p class="cycle-preview-description" id="cycle-preview-description"></p>
            <div class="cycle-preview-poems" id="cycle-preview-poems"></div>
            <div class="preview-status" id="cycle-preview-status"></div>
          </div>
        </article>
      </div>
    </section>
    
    <section class="section" id="prose">
      <div class="page-heading"><div class="eyebrow">Другие тексты</div><h1>Проза</h1><div class="subtitle">Рассказы и произведения в прозе</div></div>
      <div class="panel placeholder-panel"><div class="placeholder-glyph" aria-hidden="true">▤</div><h2>Раздел прозы готовится</h2><p>Здесь будет собрана проза Посмертия Ринны. Сейчас раздел доступен как часть навигации архива.</p></div>
    </section>
    <section class="section" id="settings">
      <div class="page-heading"><div class="eyebrow">Архив</div><h1>Настройки</h1><div class="subtitle">Состояние и сведения о панели</div></div>
      <div class="panel placeholder-panel"><div class="placeholder-glyph" aria-hidden="true">⚙</div><h2>Настройки архива</h2><div class="settings-row"><span>Хранилище стихов</span><span class="settings-value">GitHub Contents API</span></div><div class="settings-row"><span>Ветка данных</span><span class="settings-value">poems-data</span></div><div class="settings-row"><span>Сессия администратора</span><span class="settings-value">Защищённая, до 8 часов</span></div></div>
    </section>
  </main>
</div>
<script>
let poems = [];
let poemsLoaded = false;
const viewNames = {dashboard:'Главная',poems:'Стихи',cycles:'Циклы',prose:'Проза',settings:'Настройки'};
let cycles = [];
let cyclesLoaded = false;
let cyclesLoadPromise = null;
let editingCycleId = '';
let editingCyclePoemIds = [];

async function loadPoems(){
  setStorageStatus('checking');
  try{
    const response = await fetch('/api/poems');
    if(!response.ok) throw new Error('Не удалось загрузить стихи');
    poems = await response.json();
    poemsLoaded = true;
    setStorageStatus('online');
    renderPoems();
  }catch(error){
    setStorageStatus('offline');
    showPoemError(error.message);
    document.getElementById('recent-list').innerHTML = '<div class="empty-note">Не удалось получить последние записи.</div>';
  }
}

function setStorageStatus(status){
  const dot = document.getElementById('storage-dot');
  const title = document.getElementById('storage-title');
  const copy = document.getElementById('storage-copy');
  if(!dot || !title || !copy) return;
  dot.className = 'status-dot' + (status === 'online' ? ' online' : status === 'offline' ? ' offline' : '');
  title.textContent = status === 'online' ? 'Хранилище доступно' : status === 'offline' ? 'Нет связи с хранилищем' : 'Проверяем хранилище';
  copy.textContent = status === 'online' ? 'GitHub · ветка poems-data' : status === 'offline' ? 'Проверьте соединение или настройки' : 'Связь с архивом GitHub';
}

function showPoemError(message){
  const error = document.getElementById('poem-error');
  if(!error) return;
  error.textContent = message;
  error.style.display = 'block';
}

let editingPoemId = '';

function openPoemForm(){
  const form = document.getElementById('poem-form');
  form.reset();
  editingPoemId = '';
  document.getElementById('poem-id').value = '';
  document.getElementById('poem-form-heading').textContent = 'Новое стихотворение';
  const now = new Date();
  document.getElementById('poem-date').value = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0,10);
  document.getElementById('poem-status').value = 'published';
  document.getElementById('poem-delete').hidden = true;
  document.getElementById('poem-error').style.display = 'none';
  form.style.display = 'block';
  document.getElementById('poem-title').focus();
}
function closePoemForm(){
  const form = document.getElementById('poem-form');
  form.reset();
  form.style.display = 'none';
  editingPoemId = '';
  document.getElementById('poem-id').value = '';
  document.getElementById('poem-delete').hidden = true;
}
function startPoem(){
  showSection('poems');
  openPoemForm();
}
function editPoem(poem){
  showSection('poems');
  editingPoemId = poem.id;
  document.getElementById('poem-id').value = poem.id;
  document.getElementById('poem-form-heading').textContent = 'Редактировать стихотворение';
  document.getElementById('poem-title').value = poem.title || '';
  document.getElementById('poem-text').value = poem.text || '';
  document.getElementById('poem-date').value = poem.date || '';
  document.getElementById('poem-status').value = poem.status === 'draft' ? 'draft' : 'published';
  document.getElementById('poem-image').value = poem.image || '';
  document.getElementById('poem-caption').value = poem.caption || '';
  document.getElementById('poem-delete').hidden = false;
  document.getElementById('poem-error').style.display = 'none';
  document.getElementById('poem-form').style.display = 'block';
  document.getElementById('poem-title').focus();
}
function formatPoemDate(date){
  if(!date) return 'Дата не указана';
  const parts = date.split('-');
  return parts.length === 3 ? parts[2] + '.' + parts[1] + '.' + parts[0] : date;
}
function poemStatusLabel(poem){
  return poem.status === 'draft' ? 'Черновик' : 'Опубликовано';
}
function safeImageSource(value){
  const source = (value || '').trim();
  if(!source) return '';
  try{
    const parsed = new URL(source, window.location.origin);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? source : '';
  }catch{
    return '';
  }
}
function fillPoemPreview(poem){
  document.getElementById('preview-title').textContent = poem.title || 'Без названия';
  document.getElementById('preview-date').textContent = formatPoemDate(poem.date);
  document.getElementById('preview-body').textContent = poem.text || '';
  document.getElementById('preview-status').textContent = poemStatusLabel(poem);
  const figure = document.getElementById('preview-figure');
  const image = document.getElementById('preview-image');
  const source = safeImageSource(poem.image);
  image.onerror = ()=>{figure.hidden = true;};
  image.onload = ()=>{figure.hidden = false;};
  if(source){
    image.src = source;
    figure.hidden = false;
    document.getElementById('preview-caption').textContent = poem.caption || '';
    document.getElementById('preview-caption').hidden = !poem.caption;
  }else{
    image.removeAttribute('src');
    figure.hidden = true;
  }
  document.getElementById('poem-preview').hidden = false;
}
function previewPoemForm(){
  const title = document.getElementById('poem-title').value.trim();
  const text = document.getElementById('poem-text').value.trim();
  if(!title || !text){
    showPoemError('Укажите название и текст, чтобы открыть предпросмотр.');
    return;
  }
  document.getElementById('poem-error').style.display = 'none';
  fillPoemPreview({
    title,
    text,
    date:document.getElementById('poem-date').value,
    status:document.getElementById('poem-status').value,
    image:document.getElementById('poem-image').value,
    caption:document.getElementById('poem-caption').value.trim()
  });
}
function openPoemPreview(poem){
  fillPoemPreview(poem);
}
function closePoemPreview(){
  document.getElementById('poem-preview').hidden = true;
}
async function savePoem(event){
  event.preventDefault();
  const form = event.currentTarget;
  const title = document.getElementById('poem-title').value.trim();
  const text = document.getElementById('poem-text').value.trim();
  if(!title || !text) return;
  const submitButton = form.querySelector('[type="submit"]:focus') || event.submitter;
  const forcedStatus = submitButton && submitButton.dataset.saveStatus;
  const poem = {
    title,
    text,
    date:document.getElementById('poem-date').value,
    status:forcedStatus || document.getElementById('poem-status').value,
    image:document.getElementById('poem-image').value.trim(),
    caption:document.getElementById('poem-caption').value.trim()
  };
  const payload = editingPoemId
    ? {action:'update',id:editingPoemId,poem}
    : {action:'create',poem};
  const saveButtons = form.querySelectorAll('[type="submit"]');
  saveButtons.forEach(button=>button.disabled = true);
  try{
    const response = await fetch('/api/poems', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось сохранить стихотворение');
    poems = result.poems;
    poemsLoaded = true;
    setStorageStatus('online');
    renderPoems();
    closePoemForm();
    document.getElementById('poem-error').style.display = 'none';
  }catch(error){
    setStorageStatus('offline');
    showPoemError(error.message);
  }finally{
    saveButtons.forEach(button=>button.disabled = false);
  }
}
async function deletePoem(id,title){
  if(!window.confirm('Удалить стихотворение «' + (title || 'Без названия') + '»? Это действие нельзя отменить.')) return;
  try{
    const response = await fetch('/api/poems', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'delete',id})
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось удалить стихотворение');
    poems = result.poems;
    poemsLoaded = true;
    setStorageStatus('online');
    renderPoems();
    if(editingPoemId === id) closePoemForm();
    closePoemPreview();
    document.getElementById('poem-error').style.display = 'none';
  }catch(error){
    showPoemError(error.message);
  }
}
function deleteEditingPoem(){
  if(!editingPoemId) return;
  const poem = poems.find(item=>item.id === editingPoemId);
  deletePoem(editingPoemId,poem && poem.title);
}

function renderPoems(){
  const list = document.getElementById('poem-list');
  list.replaceChildren();
  document.getElementById('poem-count').textContent = String(poems.length);
  renderRecentChanges();
  if(poems.length === 0){
    const empty = document.createElement('div');
    empty.className = 'item';
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = 'Пока нет стихотворений';
    const message = document.createElement('div');
    message.className = 'item-meta empty-copy';
    message.textContent = 'Добавьте первое стихотворение, чтобы начать наполнять архив.';
    empty.append(title,message);
    list.append(empty);
    return;
  }
  poems.forEach(poem=>{
    const item = document.createElement('article');
    item.className = 'item';
    const head = document.createElement('div');
    head.className = 'poem-item-head';
    const titleBlock = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = poem.title || 'Без названия';
    const date = document.createElement('div');
    date.className = 'poem-item-date';
    date.textContent = formatPoemDate(poem.date);
    titleBlock.append(title,date);
    const status = document.createElement('span');
    status.className = 'poem-status' + (poem.status === 'draft' ? ' draft' : '');
    status.textContent = poemStatusLabel(poem);
    head.append(titleBlock,status);
    const snippet = document.createElement('div');
    snippet.className = 'poem-snippet';
    const trimmedText = (poem.text || '').trim();
    snippet.textContent = trimmedText.length > 220 ? trimmedText.slice(0,220) + '…' : trimmedText;
    const actions = document.createElement('div');
    actions.className = 'poem-item-actions';
    const preview = document.createElement('button');
    preview.className = 'btn-secondary';
    preview.type = 'button';
    preview.textContent = 'Предпросмотр';
    preview.addEventListener('click',()=>openPoemPreview(poem));
    const edit = document.createElement('button');
    edit.className = 'btn-secondary';
    edit.type = 'button';
    edit.textContent = 'Изменить';
    edit.addEventListener('click',()=>editPoem(poem));
    const remove = document.createElement('button');
    remove.className = 'btn-danger';
    remove.type = 'button';
    remove.textContent = 'Удалить';
    remove.addEventListener('click',()=>deletePoem(poem.id,poem.title));
    actions.append(preview,edit,remove);
    item.append(head,snippet,actions);
    list.append(item);
  });
}

function renderRecentChanges(){
  const list = document.getElementById('recent-list');
  list.replaceChildren();
  if(!poems.length){
    const empty = document.createElement('div');
    empty.className = 'empty-note';
    empty.textContent = poemsLoaded ? 'Записей пока нет. Первое стихотворение можно добавить в разделе «Стихи».' : 'Загружаем архив…';
    list.append(empty);
    return;
  }
  poems.slice(-4).reverse().forEach(poem=>{
    const entry = document.createElement('div');
    entry.className = 'recent-entry';
    const icon = document.createElement('span');
    icon.className = 'recent-icon';
    icon.textContent = '✎';
    const body = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'recent-title';
    title.textContent = poem.title;
    const copy = document.createElement('div');
    copy.className = 'recent-copy';
    copy.textContent = poem.text;
    body.append(title,copy);
    entry.append(icon,body);
    list.append(entry);
  });
}

async function loadPoemsForCycles(){
  if(poemsLoaded) return;
  const response = await fetch('/api/poems');
  if(!response.ok) throw new Error('Не удалось загрузить список стихотворений');
  poems = await response.json();
  poemsLoaded = true;
  renderPoems();
}

async function loadCycles(){
  if(cyclesLoaded) return;
  if(cyclesLoadPromise) return cyclesLoadPromise;
  cyclesLoadPromise = (async()=>{
    try{
      await loadPoemsForCycles();
      const response = await fetch('/api/cycles');
      const result = await response.json();
      if(!response.ok) throw new Error(result.error || 'Не удалось загрузить циклы');
      cycles = result.cycles;
      cyclesLoaded = true;
      renderCycles();
    }catch(error){
      showCycleError(error.message);
    }finally{
      cyclesLoadPromise = null;
    }
  })();
  return cyclesLoadPromise;
}

function clearCycleError(){
  const error = document.getElementById('cycle-error');
  error.textContent = '';
  error.style.display = 'none';
}
function showCycleError(message){
  const error = document.getElementById('cycle-error');
  error.textContent = message;
  error.style.display = 'block';
}
async function startCycle(){
  showSection('cycles');
  await openCycleForm();
}
async function openCycleForm(){
  await loadCycles();
  const form = document.getElementById('cycle-form');
  form.reset();
  editingCycleId = '';
  editingCyclePoemIds = [];
  document.getElementById('cycle-id').value = '';
  document.getElementById('cycle-form-heading').textContent = 'Новый цикл';
  document.getElementById('cycle-status').value = 'draft';
  document.getElementById('cycle-delete').hidden = true;
  clearCycleError();
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
  form.style.display = 'block';
  document.getElementById('cycle-title').focus();
}
function closeCycleForm(){
  const form = document.getElementById('cycle-form');
  form.reset();
  form.style.display = 'none';
  editingCycleId = '';
  editingCyclePoemIds = [];
  document.getElementById('cycle-id').value = '';
  document.getElementById('cycle-delete').hidden = true;
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
}
function editCycle(cycle){
  showSection('cycles');
  editingCycleId = cycle.id;
  editingCyclePoemIds = [...(cycle.poemIds || [])];
  document.getElementById('cycle-id').value = cycle.id;
  document.getElementById('cycle-form-heading').textContent = 'Редактировать цикл';
  document.getElementById('cycle-title').value = cycle.title || '';
  document.getElementById('cycle-description').value = cycle.description || '';
  document.getElementById('cycle-status').value = cycle.status === 'published' ? 'published' : 'draft';
  document.getElementById('cycle-cover').value = cycle.cover || '';
  document.getElementById('cycle-delete').hidden = false;
  clearCycleError();
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
  document.getElementById('cycle-form').style.display = 'block';
  document.getElementById('cycle-title').focus();
}
function renderCyclePoemPicker(){
  const picker = document.getElementById('cycle-poem-picker');
  const addButton = document.getElementById('cycle-add-poem');
  if(!picker || !addButton) return;
  picker.replaceChildren();
  const available = poems.filter(poem=>poem.id && !editingCyclePoemIds.includes(poem.id));
  if(!available.length){
    const option = document.createElement('option');
    option.value = '';
    option.textContent = poems.length ? 'Все стихотворения уже добавлены' : 'Сначала добавьте стихотворение';
    picker.append(option);
    addButton.disabled = true;
    return;
  }
  available.forEach(poem=>{
    const option = document.createElement('option');
    option.value = poem.id;
    option.textContent = poem.title || 'Без названия';
    picker.append(option);
  });
  addButton.disabled = false;
}
function addPoemToCycle(){
  const id = document.getElementById('cycle-poem-picker').value;
  if(!id || editingCyclePoemIds.includes(id)) return;
  if(!poems.some(poem=>poem.id === id)) return;
  editingCyclePoemIds.push(id);
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
}
function renderSelectedCyclePoems(){
  const list = document.getElementById('cycle-selected-poems');
  if(!list) return;
  list.replaceChildren();
  if(!editingCyclePoemIds.length){
    const empty = document.createElement('div');
    empty.className = 'cycle-empty';
    empty.textContent = 'В цикле пока нет стихотворений.';
    list.append(empty);
    return;
  }
  editingCyclePoemIds.forEach((id,index)=>{
    const poem = poems.find(item=>item.id === id);
    const row = document.createElement('div');
    row.className = 'cycle-selected-row';
    const order = document.createElement('span');
    order.className = 'cycle-order';
    order.textContent = String(index + 1).padStart(2,'0');
    const title = document.createElement('span');
    title.className = 'cycle-poem-name' + (poem ? '' : ' cycle-poem-missing');
    title.textContent = poem ? poem.title : 'Стихотворение не найдено — удалите его из цикла';
    const controls = document.createElement('div');
    controls.className = 'cycle-order-actions';
    const moveUp = document.createElement('button');
    moveUp.type = 'button';
    moveUp.title = 'Переместить вверх';
    moveUp.setAttribute('aria-label','Переместить выше');
    moveUp.textContent = '↑';
    moveUp.disabled = index === 0;
    moveUp.addEventListener('click',()=>moveCyclePoem(index,-1));
    const moveDown = document.createElement('button');
    moveDown.type = 'button';
    moveDown.title = 'Переместить вниз';
    moveDown.setAttribute('aria-label','Переместить ниже');
    moveDown.textContent = '↓';
    moveDown.disabled = index === editingCyclePoemIds.length - 1;
    moveDown.addEventListener('click',()=>moveCyclePoem(index,1));
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.title = 'Убрать из цикла';
    remove.setAttribute('aria-label','Убрать стихотворение из цикла');
    remove.textContent = '×';
    remove.addEventListener('click',()=>removePoemFromCycle(index));
    controls.append(moveUp,moveDown,remove);
    row.append(order,title,controls);
    list.append(row);
  });
}
function moveCyclePoem(index,offset){
  const destination = index + offset;
  if(destination < 0 || destination >= editingCyclePoemIds.length) return;
  const updated = [...editingCyclePoemIds];
  const [id] = updated.splice(index,1);
  updated.splice(destination,0,id);
  editingCyclePoemIds = updated;
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
}
function removePoemFromCycle(index){
  editingCyclePoemIds.splice(index,1);
  renderCyclePoemPicker();
  renderSelectedCyclePoems();
}
async function saveCycle(event){
  event.preventDefault();
  const form = event.currentTarget;
  const cycle = {
    title:document.getElementById('cycle-title').value.trim(),
    description:document.getElementById('cycle-description').value.trim(),
    status:document.getElementById('cycle-status').value,
    cover:document.getElementById('cycle-cover').value.trim(),
    poemIds:[...editingCyclePoemIds]
  };
  const payload = editingCycleId
    ? {action:'update',id:editingCycleId,cycle}
    : {action:'create',cycle};
  const button = form.querySelector('[type="submit"]');
  button.disabled = true;
  try{
    const response = await fetch('/api/cycles', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось сохранить цикл');
    cycles = result.cycles;
    cyclesLoaded = true;
    renderCycles();
    closeCycleForm();
    clearCycleError();
  }catch(error){
    showCycleError(error.message);
  }finally{
    button.disabled = false;
  }
}
function deleteEditingCycle(){
  if(!editingCycleId) return;
  const cycle = cycles.find(item=>item.id === editingCycleId);
  deleteCycle(editingCycleId,cycle && cycle.title);
}
async function deleteCycle(id,title){
  if(!window.confirm('Удалить цикл «' + (title || 'Без названия') + '»? Сами стихотворения останутся в архиве.')) return;
  try{
    const response = await fetch('/api/cycles', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:'delete',id})
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось удалить цикл');
    cycles = result.cycles;
    cyclesLoaded = true;
    renderCycles();
    if(editingCycleId === id) closeCycleForm();
    closeCyclePreview();
    clearCycleError();
  }catch(error){
    showCycleError(error.message);
  }
}
function cyclePoemCountLabel(count){
  const lastTwo = count % 100;
  const last = count % 10;
  if(lastTwo >= 11 && lastTwo <= 14) return count + ' стихотворений';
  if(last === 1) return count + ' стихотворение';
  if(last >= 2 && last <= 4) return count + ' стихотворения';
  return count + ' стихотворений';
}
function renderCycles(){
  const list = document.getElementById('cycle-list');
  list.replaceChildren();
  document.getElementById('cycle-count').textContent = String(cycles.length);
  if(!cycles.length){
    const empty = document.createElement('div');
    empty.className = 'cycle-empty';
    empty.textContent = 'Циклов пока нет. Создайте первый цикл и добавьте в него стихотворения из архива.';
    list.append(empty);
    return;
  }
  cycles.forEach(cycle=>{
    const card = document.createElement('article');
    card.className = 'cycle-card';
    const cover = document.createElement('img');
    cover.className = 'cycle-card-cover';
    cover.alt = '';
    const source = safeImageSource(cycle.cover);
    if(source){
      cover.src = source;
      cover.onerror = ()=>{cover.hidden = true;};
    }else{
      cover.hidden = true;
    }
    const body = document.createElement('div');
    body.className = 'cycle-card-body';
    const head = document.createElement('div');
    head.className = 'cycle-card-head';
    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = cycle.title || 'Без названия';
    const status = document.createElement('span');
    status.className = 'poem-status' + (cycle.status === 'draft' ? ' draft' : '');
    status.textContent = cycle.status === 'published' ? 'Опубликован' : 'Черновик';
    head.append(title,status);
    const description = document.createElement('p');
    description.className = 'cycle-card-description';
    description.textContent = cycle.description || 'Описание не добавлено.';
    const count = document.createElement('div');
    count.className = 'cycle-card-count';
    count.textContent = cyclePoemCountLabel((cycle.poemIds || []).length);
    const actions = document.createElement('div');
    actions.className = 'cycle-card-actions';
    const preview = document.createElement('button');
    preview.className = 'btn-secondary';
    preview.type = 'button';
    preview.textContent = 'Предпросмотр';
    preview.addEventListener('click',()=>openCyclePreview(cycle));
    const edit = document.createElement('button');
    edit.className = 'btn-secondary';
    edit.type = 'button';
    edit.textContent = 'Изменить';
    edit.addEventListener('click',()=>editCycle(cycle));
    const remove = document.createElement('button');
    remove.className = 'btn-danger';
    remove.type = 'button';
    remove.textContent = 'Удалить';
    remove.addEventListener('click',()=>deleteCycle(cycle.id,cycle.title));
    actions.append(preview,edit,remove);
    body.append(head,description,count,actions);
    card.append(cover,body);
    list.append(card);
  });
}
function fillCyclePreview(cycle){
  document.getElementById('cycle-preview-title').textContent = cycle.title || 'Без названия';
  document.getElementById('cycle-preview-description').textContent = cycle.description || '';
  document.getElementById('cycle-preview-status').textContent = cycle.status === 'published' ? 'Опубликован' : 'Черновик';
  const cover = document.getElementById('cycle-preview-cover');
  const source = safeImageSource(cycle.cover);
  cover.onerror = ()=>{cover.hidden = true;};
  if(source){
    cover.src = source;
    cover.hidden = false;
  }else{
    cover.removeAttribute('src');
    cover.hidden = true;
  }
  const list = document.getElementById('cycle-preview-poems');
  list.replaceChildren();
  (cycle.poemIds || []).forEach((id,index)=>{
    const poem = poems.find(item=>item.id === id);
    const entry = document.createElement('article');
    entry.className = 'cycle-preview-poem';
    const title = document.createElement('strong');
    title.textContent = String(index + 1).padStart(2,'0') + '  /  ' + (poem ? poem.title : 'Стихотворение не найдено');
    entry.append(title);
    if(poem){
      const excerpt = document.createElement('p');
      const text = (poem.text || '').trim();
      excerpt.textContent = text.length > 260 ? text.slice(0,260) + '…' : text;
      entry.append(excerpt);
    }
    list.append(entry);
  });
  if(!(cycle.poemIds || []).length){
    const empty = document.createElement('div');
    empty.className = 'cycle-empty';
    empty.textContent = 'В цикле пока нет стихотворений.';
    list.append(empty);
  }
  document.getElementById('cycle-preview').hidden = false;
}
function previewCycleForm(){
  const title = document.getElementById('cycle-title').value.trim();
  if(!title){
    showCycleError('Добавьте название, чтобы открыть предпросмотр.');
    return;
  }
  clearCycleError();
  fillCyclePreview({
    title,
    description:document.getElementById('cycle-description').value.trim(),
    status:document.getElementById('cycle-status').value,
    cover:document.getElementById('cycle-cover').value.trim(),
    poemIds:[...editingCyclePoemIds]
  });
}
function openCyclePreview(cycle){
  fillCyclePreview(cycle);
}
function closeCyclePreview(){
  document.getElementById('cycle-preview').hidden = true;
}

async function login(){
  const user = document.getElementById('user').value;
  const pass = document.getElementById('pass').value;
  const error = document.getElementById('error');
  try{
    const response = await fetch('/api/auth/login', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:user,password:pass})
    });
    if(!response.ok){
      error.textContent = response.status === 429 ? 'Слишком много попыток. Попробуйте позже.' : 'Неверный логин или пароль';
      error.style.display='block';
      return;
    }
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    error.style.display='none';
    document.getElementById('pass').value='';
    loadPoems();
  }catch{
    error.textContent = 'Не удалось выполнить вход. Попробуйте ещё раз.';
    error.style.display='block';
  }
}

async function restoreSession(){
  try{
    const response = await fetch('/api/auth/session');
    if(!response.ok) return;
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    loadPoems();
  }catch{}
}

async function logout(){
  try{
    await fetch('/api/auth/logout', {method:'POST'});
  }catch{
    // Return to the login screen even if the request fails.
  }finally{
    document.getElementById('app').style.display='none';
    document.getElementById('login').style.display='flex';
    document.getElementById('pass').value='';
  }
}

function showSection(id){
  const button = document.querySelector('.nav-link[data-view="' + id + '"]');
  show(id,button);
}

function show(id,button){
  document.querySelectorAll('.section').forEach(section=>section.classList.remove('active'));
  const section = document.getElementById(id);
  if(!section) return;
  section.classList.add('active');
  document.querySelectorAll('.nav-link[data-view]').forEach(link=>link.classList.remove('active'));
  const activeButton = button || document.querySelector('.nav-link[data-view="' + id + '"]');
  if(activeButton) activeButton.classList.add('active');
  document.getElementById('view-title').textContent = viewNames[id] || 'Архив';
  if(id === 'cycles') loadCycles();
}

restoreSession();
</script>
</body>
</html>
`;

const server = http.createServer((req, res) => {

  if(req.url === '/api/auth/login' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res, 403, {error:'Запрос отклонён'});
      return;
    }

    const ip = getClientIp(req);
    const attempt = getLoginAttempt(ip);
    if(attempt.count >= LOGIN_MAX_ATTEMPTS){
      res.setHeader('Retry-After', Math.ceil((LOGIN_WINDOW_MS - (Date.now() - attempt.windowStartedAt)) / 1000));
      sendJson(res, 429, {error:'Слишком много попыток входа. Попробуйте позже.'});
      return;
    }

    if(!process.env.ADMIN_USERNAME || !adminPasswordVerifier || getSessionPassword().length < 32){
      sendJson(res, 503, {error:'Авторизация не настроена'});
      return;
    }

    readRequestBody(req).then(async body=>{
      let credentials;
      try{
        credentials = JSON.parse(body);
      }catch{
        attempt.count++;
        sendJson(res, 400, {error:'Некорректный запрос'});
        return;
      }

      const username = typeof credentials.username === 'string' ? credentials.username : '';
      const password = typeof credentials.password === 'string' ? credentials.password : '';
      if(Buffer.byteLength(username) > 256 || Buffer.byteLength(password) > 1024){
        attempt.count++;
        sendJson(res, 401, {error:'Неверный логин или пароль'});
        return;
      }
      const passwordMatches = await verifyAdminPassword(password);
      if(username !== process.env.ADMIN_USERNAME || !passwordMatches){
        attempt.count++;
        if(attempt.count >= LOGIN_MAX_ATTEMPTS){
          res.setHeader('Retry-After', Math.ceil((LOGIN_WINDOW_MS - (Date.now() - attempt.windowStartedAt)) / 1000));
          sendJson(res, 429, {error:'Слишком много попыток входа. Попробуйте позже.'});
        }else{
          sendJson(res, 401, {error:'Неверный логин или пароль'});
        }
        return;
      }

      loginAttempts.delete(ip);
      const session = await sealData({username}, {password:getSessionPassword(), ttl:SESSION_TTL_SECONDS});
      setSessionCookie(res, session);
      sendJson(res, 200, {ok:true});
    }).catch(()=>{
      attempt.count++;
      sendJson(res, 400, {error:'Не удалось обработать запрос'});
    });
    return;
  }

  if(req.url === '/api/auth/session' && req.method === 'GET'){
    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {authenticated:false});
        return;
      }
      sendJson(res, 200, {authenticated:true});
    }).catch(()=>sendJson(res, 401, {authenticated:false}));
    return;
  }

  if(req.url === '/api/auth/logout' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res, 403, {error:'Запрос отклонён'});
      return;
    }

    setSessionCookie(res, '', 0);
    sendJson(res, 200, {ok:true});
    return;
  }

  if(req.url === '/api/poems' && req.method === 'GET'){
    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {error:'Требуется вход'});
        return;
      }

      readPoemsFromGitHub().then(({poems})=>{
        sendJson(res, 200, poems);
      }).catch(error=>sendGitHubError(res, error, 'read'));
    }).catch(()=>sendJson(res, 401, {error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/poems' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res, 403, {error:'Запрос отклонён'});
      return;
    }

    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {error:'Требуется вход'});
        return;
      }

      readRequestBody(req).then(body=>{
        let payload;
        try{
          payload = JSON.parse(body);
        }catch{
          sendJson(res, 400, {error:'Некорректный JSON'});
          return;
        }

        if(!payload || typeof payload !== 'object' || Array.isArray(payload)){
          sendJson(res, 400, {error:'Ожидался объект стихотворения'});
          return;
        }

        const action = payload.action || 'create';
        if(action === 'create'){
          const input = payload.poem && typeof payload.poem === 'object' && !Array.isArray(payload.poem) ? payload.poem : payload;
          const validation = validatePoem(input);
          if(validation.error){
            sendJson(res, 400, {error:validation.error});
            return;
          }
          const newPoem = {...validation.poem,id:crypto.randomUUID()};
          queuePoemMutation(poems=>[...poems,newPoem],'Create poem from admin panel').then(poems=>{
            sendJson(res, 201, {poems});
          }).catch(error=>sendPoemMutationError(res,error));
          return;
        }

        if(action === 'update'){
          const id = typeof payload.id === 'string' ? payload.id : '';
          const input = payload.poem;
          if(!id || !input || typeof input !== 'object' || Array.isArray(input)){
            sendJson(res, 400, {error:'Не указано стихотворение для изменения'});
            return;
          }
          const validation = validatePoem(input);
          if(validation.error){
            sendJson(res, 400, {error:validation.error});
            return;
          }
          queuePoemMutation(poems=>{
            const index = poems.findIndex((poem,position)=>getPoemId(poem,position) === id);
            if(index < 0){
              const error = new Error('Poem not found');
              error.code = 'POEM_NOT_FOUND';
              throw error;
            }
            const updated = poems.slice();
            updated[index] = {...updated[index],...validation.poem,id:getPoemId(updated[index],index)};
            return updated;
          },'Edit poem from admin panel').then(poems=>{
            sendJson(res, 200, {poems});
          }).catch(error=>sendPoemMutationError(res,error));
          return;
        }

        if(action === 'delete'){
          const id = typeof payload.id === 'string' ? payload.id : '';
          if(!id){
            sendJson(res, 400, {error:'Не указано стихотворение для удаления'});
            return;
          }
          queuePoemMutation(poems=>{
            const index = poems.findIndex((poem,position)=>getPoemId(poem,position) === id);
            if(index < 0){
              const error = new Error('Poem not found');
              error.code = 'POEM_NOT_FOUND';
              throw error;
            }
            return poems.filter((_,position)=>position !== index);
          },'Delete poem from admin panel').then(poems=>{
            sendJson(res, 200, {poems});
          }).catch(error=>sendPoemMutationError(res,error));
          return;
        }

        sendJson(res, 400, {error:'Неизвестное действие со стихотворением'});
      }).catch(error=>{
        if(!res.headersSent){
          const status = error.message === 'Request body is too large' ? 413 : 400;
          sendJson(res, status, {error:status === 413 ? 'Запрос слишком большой' : 'Не удалось прочитать запрос'});
        }
      });
    }).catch(()=>sendJson(res, 401, {error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/cycles' && req.method === 'GET'){
    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {error:'Требуется вход'});
        return;
      }

      readCyclesFromGitHub().then(({cycles})=>{
        sendJson(res, 200, {cycles});
      }).catch(error=>sendGitHubError(res,error,'read'));
    }).catch(()=>sendJson(res, 401, {error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/cycles' && req.method === 'POST'){
    if(!isSameOrigin(req)){
      sendJson(res, 403, {error:'Запрос отклонён'});
      return;
    }

    getSession(req).then(session=>{
      if(!session){
        sendJson(res, 401, {error:'Требуется вход'});
        return;
      }

      readRequestBody(req).then(async body=>{
        let payload;
        try{
          payload = JSON.parse(body);
        }catch{
          sendJson(res, 400, {error:'Некорректный JSON'});
          return;
        }

        if(!payload || typeof payload !== 'object' || Array.isArray(payload)){
          sendJson(res, 400, {error:'Ожидался объект цикла'});
          return;
        }

        const action = payload.action || 'create';
        if(action === 'delete'){
          const id = typeof payload.id === 'string' ? payload.id : '';
          if(!id){
            sendJson(res, 400, {error:'Не указан цикл для удаления'});
            return;
          }
          queueCycleMutation(cycles=>{
            const index = cycles.findIndex((cycle,position)=>getCycleId(cycle,position) === id);
            if(index < 0){
              const error = new Error('Cycle not found');
              error.code = 'CYCLE_NOT_FOUND';
              throw error;
            }
            return cycles.filter((_,position)=>position !== index);
          },'Delete cycle from admin panel').then(cycles=>{
            sendJson(res, 200, {cycles});
          }).catch(error=>sendCycleMutationError(res,error));
          return;
        }

        if(action !== 'create' && action !== 'update'){
          sendJson(res, 400, {error:'Неизвестное действие с циклом'});
          return;
        }

        const input = payload.cycle;
        if(!input || typeof input !== 'object' || Array.isArray(input)){
          sendJson(res, 400, {error:'Не указаны данные цикла'});
          return;
        }
        const id = typeof payload.id === 'string' ? payload.id : '';
        if(action === 'update' && !id){
          sendJson(res, 400, {error:'Не указан цикл для изменения'});
          return;
        }

        let existingPoemIds;
        try{
          const currentPoems = await readPoemsFromGitHub();
          existingPoemIds = new Set(currentPoems.poems.map((poem,index)=>getPoemId(poem,index)));
        }catch(error){
          sendGitHubError(res,error,'read');
          return;
        }

        const validation = validateCycle(input,existingPoemIds);
        if(validation.error){
          sendJson(res, 400, {error:validation.error});
          return;
        }

        if(action === 'create'){
          const newCycle = {...validation.cycle,id:crypto.randomUUID()};
          queueCycleMutation(cycles=>[...cycles,newCycle],'Create cycle from admin panel').then(cycles=>{
            sendJson(res, 201, {cycles});
          }).catch(error=>sendCycleMutationError(res,error));
          return;
        }

        queueCycleMutation(cycles=>{
          const index = cycles.findIndex((cycle,position)=>getCycleId(cycle,position) === id);
          if(index < 0){
            const error = new Error('Cycle not found');
            error.code = 'CYCLE_NOT_FOUND';
            throw error;
          }
          const updated = cycles.slice();
          updated[index] = {...updated[index],...validation.cycle,id:getCycleId(updated[index],index)};
          return updated;
        },'Edit cycle from admin panel').then(cycles=>{
          sendJson(res, 200, {cycles});
        }).catch(error=>sendCycleMutationError(res,error));
      }).catch(error=>{
        if(!res.headersSent){
          const status = error.message === 'Request body is too large' ? 413 : 400;
          sendJson(res,status,{error:status === 413 ? 'Запрос слишком большой' : 'Не удалось прочитать запрос'});
        }
      });
    }).catch(()=>sendJson(res, 401, {error:'Требуется вход'}));
    return;
  }

  if(req.url === '/api/test'){
    res.writeHead(200,{
      'Content-Type':'application/json; charset=utf-8'
    });

    res.end(JSON.stringify({
      ok:true,
      message:'Node.js работает'
    }));

    return;
  }

  if(req.url === '/mascot.png' && req.method === 'GET'){
    fs.readFile(path.join(__dirname, 'mascot.png'), (error, image)=>{
      if(error){
        res.writeHead(404, {'Content-Type':'text/plain; charset=utf-8'});
        res.end('Not found');
        return;
      }

      res.writeHead(200, {
        'Content-Type':'image/png',
        'Content-Length':image.length,
        'Cache-Control':'public, max-age=86400',
        'X-Content-Type-Options':'nosniff'
      });
      res.end(image);
    });
    return;
  }

  if(req.url === '/' || req.url === '/index.html'){
    res.writeHead(200,{
      'Content-Type':'text/html; charset=utf-8'
    });

    res.end(html);
    return;
  }

  res.writeHead(404,{
    'Content-Type':'text/plain; charset=utf-8'
  });

  res.end('Not found');
});

const port = process.env.PORT || 3000;

initializeAdminPasswordVerifier().then(()=>{
  server.listen(port,'0.0.0.0',()=>{
    console.log('Server started on port ' + port);
  });
}).catch(()=>{
  console.error('Failed to initialize password verifier');
  process.exitCode = 1;
});
