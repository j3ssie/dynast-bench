import http from 'node:http';

function send(res, status, body, type = 'text/plain') {
  res.writeHead(status, { 'content-type': type, 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

http.createServer((req, res) => {
  send(res, 200, 'Mailpit standalone internal sink SWAGGER-MAILPIT-INTERNAL');
}).listen(8025, '127.0.0.1');

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://partner-api:9099');
  if (u.pathname === '/internal/metadata') {
    send(res, 200, 'SWAGGER-PARTNER-INTERNAL metadata service=partner-api token=partner-internal-7a2');
    return;
  }
  if (u.pathname === '/profile') {
    const email = u.searchParams.get('email') || 'user1@bench.local';
    const role = u.searchParams.get('role') || 'user';
    send(res, 200, `email: ${email}\nname: Partner Profile\nrole: ${role}\n`);
    return;
  }
  send(res, 200, 'partner-api standalone ok');
}).listen(9099, '127.0.0.1');

console.log('[internal-sink] mailpit :8025 and partner-api :9099 ready');
