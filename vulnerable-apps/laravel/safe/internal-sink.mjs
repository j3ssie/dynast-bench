// Internal-only services for solo mode: a fake Mailpit (the SSRF target) and a
// fake phpMyAdmin surface. In compose these are real sidecars; here the
// standalone entrypoint aliases their hostnames to 127.0.0.1 so the SSRF PoC and
// the phpMyAdmin PoC reach these stand-ins unchanged.
import http from "node:http";
const serve = (port, body) =>
  http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(body);
  }).listen(port, "127.0.0.1", () => console.log(`[sink] listening on ${port}`));

serve(8025, "<!doctype html><title>Mailpit</title><body>Mailpit LARAVEL-INTERNAL-SINK</body>");
serve(8081, "<!doctype html><title>phpMyAdmin</title><body>phpMyAdmin weak bench/bench side surface</body>");
