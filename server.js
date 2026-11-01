const http = require('http');

const server = http.createServer((req, res) => {
  if (req.url === '/api/test') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      ok: true,
      message: 'Node.js работает'
    }));
    return;
  }

  if (req.url === '/' || req.url === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`
      <!DOCTYPE html>
      <html lang="ru">
      <head>
        <meta charset="UTF-8">
        <title>Posmertie Admin Test</title>
      </head>
      <body>
        <h1>Posmertie Admin Test</h1>
        <p>Node.js server works.</p>
        <p><a href="/api/test">Проверить /api/test</a></p>
      </body>
      </html>
    `);
    return;
  }

  res.writeHead(404, {
    'Content-Type': 'text/plain; charset=utf-8'
  });
  res.end('Not found');
});

const port = process.env.PORT || 3000;

server.listen(port, '0.0.0.0', () => {
  console.log(`Server started on port ${port}`);
});
