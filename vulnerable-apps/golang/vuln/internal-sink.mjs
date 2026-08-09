import http from "node:http";

const server = http.createServer((req, res) => {
  const body = "GO-INTERNAL-SINK standalone metadata surrogate";
  res.writeHead(200, { "content-type": "text/plain", "content-length": Buffer.byteLength(body) });
  res.end(body);
});
server.listen(8025, "127.0.0.1");
