import http from 'node:http';
const server = http.createServer((req, res) => {
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify({ service: 'internal-svc', marker: 'INTERNAL-HR-SSRF-OK', path: req.url }));
});
server.listen(9099, '127.0.0.1');
