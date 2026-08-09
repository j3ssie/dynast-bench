import http from 'node:http';

const server = http.createServer((req, res) => {
  const body = 'NestJS standalone/compose internal sink NESTJS-INTERNAL-SINK';
  res.writeHead(200, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(body) });
  res.end(body);
});
server.listen(8025, '0.0.0.0');
