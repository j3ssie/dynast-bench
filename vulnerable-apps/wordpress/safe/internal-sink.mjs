import http from 'node:http';

const server = http.createServer((req, res) => {
  res.writeHead(200, {'content-type': 'text/plain'});
  res.end('INTERNAL-SINK: mailpit-admin-token=MAILPIT-INTERNAL-ONLY\n');
});
server.listen(8025, '0.0.0.0');
