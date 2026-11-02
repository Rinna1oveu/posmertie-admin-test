const http = require('http');
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

  return fetch(`${GITHUB_FILE_URL}?ref=${encodeURIComponent(GITHUB_BRANCH)}`, options);
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
<title>Посмертие Ринны — Админка</title>

<style>
*{box-sizing:border-box}

body{
  margin:0;
  background:#0b0b0d;
  color:#eee;
  font-family:Arial,sans-serif;
}

button,input,textarea{
  font:inherit;
}

.login{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:24px;
}

.login-box{
  width:100%;
  max-width:420px;
  background:#151519;
  border:1px solid #29292f;
  border-radius:20px;
  padding:30px;
  box-shadow:0 20px 60px #0008;
}

.logo{
  font-size:30px;
  font-weight:700;
  margin-bottom:8px;
}

.muted{
  color:#85858e;
  margin-bottom:28px;
}

label{
  display:block;
  color:#aaa;
  font-size:14px;
  margin:18px 0 7px;
}

input,textarea{
  width:100%;
  background:#0d0d10;
  color:#fff;
  border:1px solid #303038;
  border-radius:10px;
  padding:13px;
  outline:none;
}

input:focus,textarea:focus{
  border-color:#777;
}

.btn{
  width:100%;
  margin-top:22px;
  border:0;
  border-radius:10px;
  padding:14px;
  background:#eee;
  color:#111;
  font-weight:700;
  cursor:pointer;
}

.error{
  color:#e88;
  margin-top:15px;
  display:none;
}

.app{
  display:none;
  min-height:100vh;
}

.sidebar{
  position:fixed;
  left:0;
  top:0;
  bottom:0;
  width:240px;
  background:#111114;
  border-right:1px solid #28282d;
  padding:24px 16px;
}

.brand{
  font-size:21px;
  font-weight:700;
  padding:8px 10px 28px;
}

.nav button{
  width:100%;
  text-align:left;
  border:0;
  background:transparent;
  color:#9999a2;
  padding:13px 12px;
  border-radius:9px;
  margin-bottom:4px;
  cursor:pointer;
}

.nav button:hover,
.nav button.active{
  background:#222228;
  color:#fff;
}

.logout{
  position:absolute;
  bottom:20px;
  left:16px;
  right:16px;
  background:#1b1b20;
  color:#aaa;
  border:1px solid #2d2d33;
  border-radius:9px;
  padding:11px;
}

.content{
  margin-left:240px;
  padding:38px;
  max-width:1200px;
}

.top{
  display:flex;
  justify-content:space-between;
  align-items:center;
  margin-bottom:30px;
}

h1{
  margin:0 0 7px;
  font-size:32px;
}

.subtitle{
  color:#777780;
}

.cards{
  display:grid;
  grid-template-columns:repeat(3,1fr);
  gap:16px;
}

.card{
  background:#151519;
  border:1px solid #29292f;
  border-radius:15px;
  padding:22px;
}

.card-title{
  color:#888891;
  font-size:14px;
}

.card-number{
  font-size:34px;
  margin-top:12px;
}

.panel{
  margin-top:24px;
  background:#151519;
  border:1px solid #29292f;
  border-radius:15px;
  padding:24px;
}

.panel h2{
  margin-top:0;
}

.section{
  display:none;
}

.section.active{
  display:block;
}

.item{
  padding:16px 0;
  border-bottom:1px solid #29292f;
}

.item:last-child{
  border-bottom:0;
}

.item-title{
  font-size:18px;
  margin-bottom:5px;
}

.item-meta{
  color:#777780;
  font-size:14px;
}

.add{
  background:#eee;
  color:#111;
  border:0;
  border-radius:9px;
  padding:11px 16px;
  font-weight:700;
}

@media(max-width:700px){
  .sidebar{
    position:static;
    width:100%;
    height:auto;
    border-right:0;
    border-bottom:1px solid #28282d;
  }

  .logout{
    position:static;
    margin-top:20px;
  }

  .content{
    margin-left:0;
    padding:22px;
  }

  .cards{
    grid-template-columns:1fr;
  }

  .top{
    display:block;
  }

  .top .add{
    margin-top:15px;
  }
}
</style>
</head>

<body>

<div class="login" id="login">
  <div class="login-box">
    <div class="logo">Посмертие Ринны</div>
    <div class="muted">Панель управления архивом</div>

    <label>Логин</label>
    <input id="user" placeholder="Введите логин">

    <label>Пароль</label>
    <input id="pass" type="password" placeholder="Введите пароль">

    <button class="btn" onclick="login()">Войти</button>

    <div class="error" id="error">
      Неверный логин или пароль
    </div>
  </div>
</div>

<div class="app" id="app">

  <aside class="sidebar">
    <div class="brand">Посмертие Ринны</div>

    <div class="nav">
      <button class="active" onclick="show('dashboard',this)">
        Главная
      </button>

      <button onclick="show('poems',this)">
        Стихи
      </button>

      <button onclick="show('cycles',this)">
        Циклы
      </button>

      <button onclick="show('prose',this)">
        Проза
      </button>

      <button onclick="show('settings',this)">
        Настройки
      </button>
    </div>

    <button class="logout" onclick="logout()">Выйти</button>
  </aside>

  <main class="content">

    <section class="section active" id="dashboard">
      <div class="top">
        <div>
          <h1>Главная</h1>
          <div class="subtitle">
            Управление литературным архивом
          </div>
        </div>
      </div>

      <div class="cards">
        <div class="card">
          <div class="card-title">СТИХИ</div>
          <div class="card-number">0</div>
        </div>

        <div class="card">
          <div class="card-title">ЦИКЛЫ</div>
          <div class="card-number">0</div>
        </div>

        <div class="card">
          <div class="card-title">ПРОЗА</div>
          <div class="card-number">0</div>
        </div>
      </div>

      <div class="panel">
        <h2>Админка работает</h2>
        <p class="muted">
          Это первый безопасный прототип.
          Основной сайт «Посмертие Ринны» пока не затронут.
        </p>
      </div>
    </section>

    <section class="section" id="poems">
      <div class="top">
        <div>
          <h1>Стихи</h1>
          <div class="subtitle">Управление стихотворениями</div>
        </div>

        <button class="add" type="button" onclick="openPoemForm()">+ Новое стихотворение</button>
      </div>

      <div class="panel">
  <form id="poem-form" onsubmit="savePoem(event)" style="display:none">
    <label for="poem-title">Название</label>
    <input id="poem-title" name="title" required>

    <label for="poem-text">Текст</label>
    <textarea id="poem-text" name="text" rows="8" required></textarea>

    <button class="btn" type="submit">Сохранить</button>
  </form>

  <div id="poem-list">
    <div class="item" id="empty-poems">
      <div class="item-title">Пока нет произведений</div>
      <div class="item-meta">
        Здесь появится список стихотворений.
      </div>
    </div>
  </div>
</div>
    </section>

    <section class="section" id="cycles">
      <div class="top">
        <div>
          <h1>Циклы</h1>
          <div class="subtitle">Сборники и тематические циклы</div>
        </div>

        <button class="add">+ Новый цикл</button>
      </div>

      <div class="panel">
        <div class="item">
          <div class="item-title">Пока нет циклов</div>
          <div class="item-meta">
            Здесь появятся литературные циклы.
          </div>
        </div>
      </div>
    </section>

    <section class="section" id="prose">
      <div class="top">
        <div>
          <h1>Проза</h1>
          <div class="subtitle">Рассказы и другие тексты</div>
        </div>

        <button class="add">+ Новое произведение</button>
      </div>

      <div class="panel">
        <div class="item">
          <div class="item-title">Пока нет произведений</div>
          <div class="item-meta">
            Здесь появится список прозы.
          </div>
        </div>
      </div>
    </section>

    <section class="section" id="settings">
      <h1>Настройки</h1>

      <div class="panel">
        <h2>Тестовая версия</h2>
        <p class="muted">
          Настройки публикации и GitHub подключим позже,
          после проверки самой админки.
        </p>
      </div>
    </section>

  </main>
</div>

<script>
let poems = [];
let poemsLoaded = false;

async function loadPoems(){
  try{
    const response = await fetch('/api/poems');
    if(!response.ok) throw new Error('Could not load poems');
    poems = await response.json();
    poemsLoaded = true;
    renderPoems();
  }catch(error){
    showPoemError(error.message);
  }
}

function showPoemError(message){
  const list = document.getElementById('poem-list');
  let error = document.getElementById('poem-error');
  if(!error){
    error = document.createElement('div');
    error.id = 'poem-error';
    error.className = 'error';
    error.style.display = 'block';
    list.before(error);
  }
  error.textContent = message;
}

function openPoemForm(){
  const form = document.getElementById('poem-form');
  form.reset();
  form.style.display='block';
  document.getElementById('poem-title').focus();
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
    if(!response.ok) throw new Error(result.error || 'Could not save poem');
    poems = result.poems;
    renderPoems();
    form.reset();
    form.style.display='none';
    const error = document.getElementById('poem-error');
    if(error) error.remove();
  }catch(error){
    showPoemError(error.message);
  }finally{
    submitButton.disabled = false;
  }
}

function renderPoems(){
  const list = document.getElementById('poem-list');
  list.replaceChildren();

  if(poems.length === 0){
    const empty = document.createElement('div');
    empty.className = 'item';

    const title = document.createElement('div');
    title.className = 'item-title';
    title.textContent = 'Пока нет произведений';

    const message = document.createElement('div');
    message.className = 'item-meta';
    message.textContent = 'Здесь появится список стихотворений.';

    empty.append(title, message);
    list.append(empty);
    return;
  }

  poems.forEach(poem=>{
    const item = document.createElement('div');
    item.className='item';

    const title = document.createElement('div');
    title.className='item-title';
    title.textContent=poem.title;

    const text = document.createElement('div');
    text.className='item-meta';
    text.style.whiteSpace='pre-wrap';
    text.textContent=poem.text;

    item.append(title,text);
    list.append(item);
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
      body:JSON.stringify({username:user, password:pass})
    });

    if(!response.ok){
      error.textContent = response.status === 429
        ? 'Слишком много попыток входа. Попробуйте позже.'
        : 'Неверный логин или пароль';
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

function show(id,button){
  document.querySelectorAll('.section')
    .forEach(x=>x.classList.remove('active'));

  document.getElementById(id).classList.add('active');

  document.querySelectorAll('.nav button')
    .forEach(x=>x.classList.remove('active'));

  button.classList.add('active');
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
