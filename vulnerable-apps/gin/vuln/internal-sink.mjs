import http from "node:http";

// Internal-only SSRF target surrogate used by the standalone (solo) image.
// Not published on the host; reachable only from inside the container.
const server = http.createServer((req, res) => {
  const body = "GIN-INTERNAL-SINK standalone metadata surrogate";
  res.writeHead(200, { "content-type": "text/plain", "content-length": Buffer.byteLength(body) });
  res.end(body);
});
server.listen(8025, "127.0.0.1");
