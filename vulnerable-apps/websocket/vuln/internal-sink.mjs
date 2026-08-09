import http from 'node:http';
const server = http.createServer((req, res) => {
  if (req.url === '/secret' || req.url === '/billing') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('INTERNAL-SERVICE-SECRET websocket internal sink\n');
  } else {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ service: 'internal-svc', ok: true }));
  }
});
server.listen(9099, '0.0.0.0');
