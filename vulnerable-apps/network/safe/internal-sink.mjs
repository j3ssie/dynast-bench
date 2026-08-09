import http from 'node:http';
const marker = 'GLOBEX-CONFIDENTIAL-MARKER-7f3a';
http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(`network internal sink ${marker}\n`);
}).listen(8025, '127.0.0.1');
