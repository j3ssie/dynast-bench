import http from "node:http";
const page = "<!doctype html><title>Mailpit</title><body>Mailpit internal mail UI. INTERNAL-SECRET-do-not-expose</body>";
http.createServer((_req, res) => { res.writeHead(200, { "content-type": "text/html" }); res.end(page); }).listen(8025, "127.0.0.1", () => console.log("[sink] internal mailpit mock on 127.0.0.1:8025"));
