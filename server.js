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
let poemWriteQueue = Promise.resolve();

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

async function githubRequest(method, body){
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
    ? `${GITHUB_FILE_URL}?ref=${encodeURIComponent(GITHUB_BRANCH)}`
    : GITHUB_FILE_URL;
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
    if(!Array.isArray(poems)) throw new Error('Invalid poems data');
    return {poems, sha:file.sha};
  }catch{
    throw githubApiError(502, 'INVALID_GITHUB_FILE');
  }
}

async function writePoemsToGitHub(poems, sha){
  const body = {
    message:'Update poems from admin panel',
    content:Buffer.from(JSON.stringify(poems, null, 2) + '\n', 'utf8').toString('base64'),
    branch:GITHUB_BRANCH
  };
  if(sha) body.sha = sha;

  const response = await githubRequest('PUT', body);
  if(!response.ok) throw githubApiError(response.status);
}

async function appendPoemToGitHub(poem){
  for(let attempt=0;attempt<3;attempt++){
    const current = await readPoemsFromGitHub();
    const poems = [...current.poems, poem];

    try{
      await writePoemsToGitHub(poems, current.sha);
      return poems;
    }catch(error){
      if((error.status === 409 || error.status === 422) && attempt < 2) continue;
      throw error;
    }
  }

  throw githubApiError(409, 'GITHUB_WRITE_CONFLICT');
}

function queuePoemWrite(poem){
  const operation = poemWriteQueue.then(()=>appendPoemToGitHub(poem));
  poemWriteQueue = operation.then(()=>undefined, ()=>undefined);
  return operation;
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
:root{color-scheme:dark;--ink:#f4f0eb;--muted:#a6a0a0;--dim:#716e72;--line:#343239;--nav:#17171c;--nav-hover:#29272e;--canvas:#101014;--panel:#1b1a20;--panel-soft:#211f26;--accent:#d7a79d;--accent-dark:#301f21;--success:#87b99b;--danger:#e18c8c}
*{box-sizing:border-box}
body{margin:0;background:var(--canvas);color:var(--ink);font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:15px;line-height:1.5}
button,input,textarea{font:inherit}
button{cursor:pointer}
.login{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(ellipse at 50% 0,#292129 0,transparent 55%),var(--canvas)}
.login-box{width:min(100%,430px);padding:38px;background:#1b1a20;border:1px solid #39353c;border-radius:20px;box-shadow:0 28px 90px #0008}
.login-mark,.brand-mark{display:grid;place-items:center;width:42px;height:42px;border:1px solid #65504f;border-radius:14px;color:var(--accent);font-family:Georgia,serif;font-size:23px}
.login-box .login-mark{margin-bottom:22px}
.logo{font:600 29px Georgia,"Times New Roman",serif;letter-spacing:.01em}
.muted{color:var(--muted)}
.login .muted{margin:8px 0 28px}
label{display:block;color:#c8c1c0;font-size:13px;margin:18px 0 7px}
input,textarea{width:100%;background:#121116;color:#fff;border:1px solid #3a3740;border-radius:10px;padding:13px 14px;outline:none;transition:border-color .15s,box-shadow .15s}
input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px #d7a79d22}
.btn{border:0;border-radius:10px;padding:12px 17px;background:var(--accent);color:#211719;font-weight:700;transition:transform .15s,background .15s}
.btn:hover{background:#e5b9af;transform:translateY(-1px)}
.btn:disabled{opacity:.55;cursor:wait;transform:none}
.login .btn{width:100%;margin-top:22px}
.error{color:#efaaaa;margin-top:14px;display:none}
.app{display:none;min-height:100vh}
.sidebar{position:fixed;z-index:5;inset:0 auto 0 0;width:254px;display:flex;flex-direction:column;padding:26px 17px 18px;background:var(--nav);border-right:1px solid #302d34}
.brand{display:flex;align-items:center;gap:12px;padding:1px 9px 30px}
.brand-mark{flex:0 0 42px}
.brand-name{font:600 17px Georgia,"Times New Roman",serif;letter-spacing:.015em}
.brand-caption{color:#88838a;font-size:11px;letter-spacing:.12em;text-transform:uppercase;margin-top:2px}
.nav{display:grid;gap:5px}
.nav-link{display:flex;align-items:center;gap:13px;width:100%;padding:11px 12px;color:#aaa5ad;text-align:left;background:transparent;border:1px solid transparent;border-radius:10px;transition:background .15s,color .15s}
.nav-link:hover{background:#211f26;color:#eee}
.nav-link.active{background:var(--nav-hover);border-color:#38343d;color:#fff}
.nav-icon{width:20px;text-align:center;color:#a99b9a;font-size:17px}
.nav-link.active .nav-icon{color:var(--accent)}
.sidebar-bottom{margin-top:auto}
.sidebar-note{margin:0 8px 14px;padding:13px 11px;border-top:1px solid #302d34;color:#817c84;font-size:12px}
.logout{color:#c8a9a4}
.logout:hover{background:#342426;color:#f0c2ba}
.content{margin-left:254px;max-width:1500px;padding:30px 42px 52px}
.topbar{display:flex;justify-content:space-between;align-items:center;min-height:53px;margin-bottom:34px;padding-bottom:19px;border-bottom:1px solid #29272e}
.crumb{color:#817d84;font-size:11px;letter-spacing:.15em;text-transform:uppercase}
.topbar-user{display:flex;align-items:center;gap:10px;color:#c5bfc3;font-size:13px}
.avatar{display:grid;place-items:center;width:34px;height:34px;border:1px solid #54464a;border-radius:50%;color:var(--accent);font-family:Georgia,serif}
.section{display:none;animation:appear .22s ease}
.section.active{display:block}
@keyframes appear{from{opacity:.3;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.page-heading{margin-bottom:25px}
h1{margin:0;font:500 clamp(28px,3vw,38px) Georgia,"Times New Roman",serif;letter-spacing:-.02em}
.subtitle{margin-top:7px;color:#a6a0a0}
.eyebrow{margin-bottom:8px;color:var(--accent);font-size:11px;font-weight:700;letter-spacing:.16em;text-transform:uppercase}
.hero{display:flex;align-items:center;justify-content:space-between;gap:24px;overflow:hidden;padding:34px 36px;border:1px solid #514148;border-radius:18px;background:linear-gradient(110deg,#30252b 0,#211e24 62%,#1d1b20 100%);margin-bottom:20px}
.hero-content{flex:1;min-width:0}
.hero-mascot{display:block;flex:0 0 auto;width:auto;height:128px;max-width:25%;object-fit:contain;opacity:.72;filter:saturate(.72) brightness(.78);pointer-events:none;user-select:none}
.hero h1{position:relative;z-index:1}
.hero p{position:relative;z-index:1;max-width:600px;margin:12px 0 22px;color:#c1b6b8}
.quick-actions{position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:9px}
.btn-secondary{padding:10px 14px;background:#ffffff0b;border:1px solid #65545a;border-radius:9px;color:#f0e7e6;font-weight:600}
.btn-secondary:hover{background:#ffffff16;border-color:#9b7677}
.btn-secondary .plus{color:var(--accent);margin-right:7px}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:20px}
.stat-card,.panel,.storage-card{background:var(--panel);border:1px solid #302d35;border-radius:14px}
.stat-card{padding:19px 21px}
.stat-top{display:flex;align-items:center;justify-content:space-between;color:#aaa4aa;font-size:13px}
.stat-symbol{color:var(--accent);font-size:18px}
.stat-number{margin-top:9px;font:500 34px Georgia,serif}
.stat-foot{margin-top:2px;color:#77737c;font-size:12px}
.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(250px,.85fr);gap:16px}
.panel{padding:21px 22px}
.panel-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:13px}
.panel h2{margin:0;font:500 20px Georgia,"Times New Roman",serif}
.panel-kicker{color:#77737c;font-size:12px}
.recent-list{display:grid}
.recent-entry{display:grid;grid-template-columns:34px minmax(0,1fr);gap:12px;padding:13px 0;border-bottom:1px solid #302d35}
.recent-entry:last-child{border-bottom:0}
.recent-icon{display:grid;place-items:center;width:32px;height:32px;border-radius:10px;background:#32272b;color:var(--accent)}
.recent-title{overflow:hidden;color:#eee7e6;text-overflow:ellipsis;white-space:nowrap;font-weight:600}
.recent-copy{display:-webkit-box;overflow:hidden;margin-top:3px;color:#88838a;font-size:12px;-webkit-box-orient:vertical;-webkit-line-clamp:2}
.empty-note{padding:18px 0;color:#8d8790;font-size:13px}
.draft-empty{padding:14px 0 8px}
.draft-mark{display:grid;place-items:center;width:40px;height:40px;margin-bottom:12px;border:1px solid #443c45;border-radius:12px;color:#a995a0;font-size:18px}
.draft-empty p{margin:5px 0 0;color:#89838b;font-size:13px}
.storage-card{display:flex;align-items:flex-start;gap:13px;margin-top:15px;padding:16px}
.status-dot{flex:0 0 9px;width:9px;height:9px;margin-top:6px;border-radius:50%;background:#908992;box-shadow:0 0 0 4px #90899218}
.status-dot.online{background:var(--success);box-shadow:0 0 0 4px #87b99b1b}
.status-dot.offline{background:var(--danger);box-shadow:0 0 0 4px #e18c8c1b}
.storage-title{font-size:13px;font-weight:650}
.storage-copy{margin-top:3px;color:#89838b;font-size:12px}
.section-top{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:22px}
.section-top .page-heading{margin:0}
.add{white-space:nowrap}
.poem-panel{padding:22px}
#poem-form{max-width:780px;margin-bottom:21px;padding-bottom:21px;border-bottom:1px solid #302d35}
#poem-form textarea{resize:vertical;min-height:160px}
.poem-list .item{padding:18px 0;border-bottom:1px solid #302d35}
.poem-list .item:last-child{border-bottom:0}
.item-title{margin-bottom:6px;color:#f1e8e6;font:500 20px Georgia,"Times New Roman",serif}
.item-meta{color:#aaa3aa;font-size:13px;white-space:pre-wrap}
.item-meta.empty-copy{color:#85808a}
.placeholder-panel{max-width:820px}
.placeholder-glyph{display:grid;place-items:center;width:48px;height:48px;margin-bottom:15px;border:1px solid #4b3d42;border-radius:15px;color:var(--accent);font:24px Georgia,serif}
.placeholder-panel p{max-width:590px;margin:8px 0 0;color:#a19ba2}
.settings-row{display:flex;justify-content:space-between;gap:16px;padding:15px 0;border-bottom:1px solid #302d35;color:#bcb5bb}
.settings-row:last-child{border-bottom:0}
.settings-value{color:#89838b}
@media(max-width:1000px){.content{padding:27px 28px}.sidebar{width:225px}.content{margin-left:225px}.dashboard-grid{grid-template-columns:1fr}.brand-name{font-size:15px}}
@media(max-width:700px){.sidebar{position:sticky;inset:0 0 auto;width:100%;padding:12px 14px 10px;border-right:0;border-bottom:1px solid #302d34}.brand{padding:0 4px 12px}.brand-mark{width:34px;height:34px;flex-basis:34px;border-radius:11px;font-size:19px}.brand-caption{display:none}.nav{display:flex;gap:5px;overflow-x:auto;padding-bottom:2px}.nav-link{width:auto;flex:0 0 auto;padding:9px 10px;font-size:13px}.nav-icon{width:auto}.nav-link.logout{margin-left:auto}.sidebar-bottom{display:none}.content{margin-left:0;padding:22px 17px 40px}.topbar{margin-bottom:25px}.topbar-user span:last-child{display:none}.hero{padding:25px 22px;gap:14px}.hero-mascot{height:100px;max-width:24%}.stats{gap:9px}.stat-card{padding:15px 13px}.stat-top{align-items:flex-start;gap:5px;font-size:12px}.stat-number{font-size:29px}.stat-foot{font-size:11px}.section-top{align-items:flex-start;flex-direction:column}.add{width:auto}.poem-panel,.panel{padding:18px}.login-box{padding:29px 24px}}
@media(max-width:480px){.hero{display:block;padding:22px 19px}.hero-mascot{height:76px;max-width:100%;margin:14px 0 0 auto}}
@media(max-width:420px){.nav-link{gap:7px;padding:8px;font-size:12px}.nav-icon{display:none}.stats{grid-template-columns:1fr}.stat-card{display:flex;align-items:center;justify-content:space-between}.stat-number{margin:0}.stat-foot{display:none}.quick-actions{display:grid;grid-template-columns:1fr}.btn-secondary{text-align:left}}
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
            <button class="btn-secondary" type="button" onclick="showSection('cycles')"><span class="plus">＋</span>Новый цикл</button>
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
          <div class="panel-heading"><h2>Новое стихотворение</h2><button class="btn-secondary" type="button" onclick="closePoemForm()">Закрыть</button></div>
          <label for="poem-title">Название</label>
          <input id="poem-title" name="title" required maxlength="300" placeholder="Название стихотворения">
          <label for="poem-text">Текст</label>
          <textarea id="poem-text" name="text" rows="8" required placeholder="Начните писать…"></textarea>
          <button class="btn" type="submit">Сохранить в архив</button>
        </form>
        <div class="error" id="poem-error" role="alert"></div>
        <div class="poem-list" id="poem-list"></div>
      </div>
    </section>
    <section class="section" id="cycles">
      <div class="page-heading"><div class="eyebrow">Структура архива</div><h1>Циклы</h1><div class="subtitle">Тематические собрания стихотворений</div></div>
      <div class="panel placeholder-panel"><div class="placeholder-glyph" aria-hidden="true">◌</div><h2>Раздел циклов готовится</h2><p>Здесь появятся тематические подборки и поэтические циклы. Пока можно продолжить работу со стихотворениями.</p></div>
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

function openPoemForm(){
  const form = document.getElementById('poem-form');
  form.reset();
  form.style.display='block';
  document.getElementById('poem-title').focus();
}
function closePoemForm(){
  const form = document.getElementById('poem-form');
  form.reset();
  form.style.display='none';
}
function startPoem(){
  showSection('poems');
  openPoemForm();
}

async function savePoem(event){
  event.preventDefault();
  const form = event.currentTarget;
  const title = document.getElementById('poem-title').value.trim();
  const text = document.getElementById('poem-text').value.trim();
  if(!title || !text) return;
  const submitButton = form.querySelector('[type="submit"]');
  submitButton.disabled = true;
  try{
    const response = await fetch('/api/poems', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({title,text})
    });
    const result = await response.json();
    if(!response.ok) throw new Error(result.error || 'Не удалось сохранить стихотворение');
    poems = result.poems;
    poemsLoaded = true;
    setStorageStatus('online');
    renderPoems();
    form.reset();
    form.style.display='none';
    document.getElementById('poem-error').style.display='none';
  }catch(error){
    setStorageStatus('offline');
    showPoemError(error.message);
  }finally{
    submitButton.disabled = false;
  }
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
    item.className='item';
    const title = document.createElement('div');
    title.className='item-title';
    title.textContent=poem.title;
    const text = document.createElement('div');
    text.className='item-meta';
    text.textContent=poem.text;
    item.append(title,text);
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
        let poem;
        try{
          poem = JSON.parse(body);
        }catch{
          sendJson(res, 400, {error:'Некорректный JSON'});
          return;
        }

        if(!poem || typeof poem !== 'object' || Array.isArray(poem)){
          sendJson(res, 400, {error:'Ожидался объект стихотворения'});
          return;
        }

        const title = typeof poem.title === 'string' ? poem.title.trim() : '';
        const text = typeof poem.text === 'string' ? poem.text.trim() : '';
        if(!title || !text){
          sendJson(res, 400, {error:'Название и текст обязательны'});
          return;
        }

        queuePoemWrite({title, text}).then(poems=>{
          sendJson(res, 201, {poems});
        }).catch(error=>sendGitHubError(res, error, 'write'));
      }).catch(error=>{
        if(!res.headersSent){
          const status = error.message === 'Request body is too large' ? 413 : 400;
          sendJson(res, status, {error:status === 413 ? 'Запрос слишком большой' : 'Не удалось прочитать запрос'});
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
