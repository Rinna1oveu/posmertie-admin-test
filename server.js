const http = require('http');

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
        <div class="item">
          <div class="item-title">Пока нет произведений</div>
          <div class="item-meta">
            Здесь появится список стихотворений.
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
function login(){
  const user = document.getElementById('user').value;
  const pass = document.getElementById('pass').value;
  const error = document.getElementById('error');

  if(user === 'admin' && pass === 'rinna'){
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    error.style.display='none';
  }else{
    error.style.display='block';
  }
}

function logout(){
  document.getElementById('app').style.display='none';
  document.getElementById('login').style.display='flex';
}

function show(id,button){
  document.querySelectorAll('.section')
    .forEach(x=>x.classList.remove('active'));

  document.getElementById(id).classList.add('active');

  document.querySelectorAll('.nav button')
    .forEach(x=>x.classList.remove('active'));

  button.classList.add('active');
}
</script>

</body>
</html>
`;

const server = http.createServer((req, res) => {

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

server.listen(port,'0.0.0.0',()=>{
  console.log('Server started on port ' + port);
});
