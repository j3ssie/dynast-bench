// Standalone-image only: a tiny internal-only HTTP service bound to 127.0.0.1,
// standing in for the compose "mailpit" service so the SSRF PoC has an
// internal target to reach. Not exposed to the host.
import http from "node:http";
const page =
  "<!doctype html><html><head><title>Mailpit</title></head>" +
  "<body>Mailpit internal mail UI. INTERNAL-SECRET-do-not-expose</body></html>";
http
  .createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(page);
  })
  .listen(8025, "127.0.0.1", () => console.log("[sink] internal mailpit mock on 127.0.0.1:8025"));
