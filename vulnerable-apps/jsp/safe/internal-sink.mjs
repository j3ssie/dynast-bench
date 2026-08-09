import http from 'node:http';
http.createServer((req, res) => {
  res.writeHead(200, {'content-type':'text/plain'});
  res.end(req.url === '/secret' ? 'INTERNAL-SINK-MARKER-jsp\n' : 'internal sink ok\n');
}).listen(8025, '0.0.0.0');
