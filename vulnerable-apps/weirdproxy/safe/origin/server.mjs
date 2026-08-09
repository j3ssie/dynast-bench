// Origin backend for the weirdproxy bench. It is INTERNAL ONLY — never published
// on a host port. The three reverse proxies in front of it are the security
// boundary; this backend has no ACL of its own. The whole point of the app is
// that this backend normalizes a request path (decode, resolve dot-segments,
// collapse slashes, strip ;params, case-fold) MORE aggressively than a proxy's
// ACL does, so a request that slips past the proxy still resolves here to a
// protected path.
//
// The confidential marker (shared across the suite) lives behind /admin,
// /internal/*, and /metrics. A correct proxy denies those; a normalization
// discrepancy leaks the marker.
import http from "node:http";

const MARKER = "GLOBEX-CONFIDENTIAL-MARKER-7f3a";
const PORT = Number(process.env.ORIGIN_PORT || 9000);

// Decode percent-escapes up to twice (so %252e-style double-encoding resolves),
// swap backslashes, strip ;params, resolve ./.. segments, collapse //, case-fold,
// and drop a trailing slash. This mimics a permissive framework router.
function normalize(rawPath) {
  let p = rawPath;
  for (let i = 0; i < 2; i++) {
    try {
      const dec = decodeURIComponent(p);
      if (dec === p) break;
      p = dec;
    } catch {
      break;
    }
  }
  p = p.replace(/\\/g, "/");
  const segsIn = p.split("/");
  const out = [];
  for (let seg of segsIn) {
    seg = seg.split(";")[0]; // strip path parameters
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      out.pop();
      continue;
    }
    out.push(seg.toLowerCase());
  }
  return "/" + out.join("/");
}

function isProtected(norm) {
  return norm === "/admin"
    || norm === "/internal"
    || norm.startsWith("/internal/")
    || norm === "/metrics";
}

const server = http.createServer((req, res) => {
  const rawPath = (req.url || "/").split("?")[0].split("#")[0];
  const norm = normalize(rawPath);

  res.setHeader("X-Origin-Raw", rawPath.slice(0, 256));
  res.setHeader("X-Origin-Normalized", norm.slice(0, 256));

  // Health (no token) — proxies forward it through.
  if (norm === "/api/_verify/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok", app: "weirdproxy" }));
    return;
  }

  // HEADER-TRUST: the backend trusts an "internal" marker header that a correct
  // proxy MUST strip from client requests. If the proxy forwards a client-supplied
  // X-Internal-Auth, this grants access regardless of path.
  const internalHeader = String(req.headers["x-internal-auth"] || "").toLowerCase();
  if (internalHeader === "trusted") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`admin ok via header\n${MARKER}\n`);
    return;
  }

  if (isProtected(norm)) {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(`protected area ${norm}\n${MARKER}\n`);
    return;
  }

  res.writeHead(200, { "content-type": "text/plain" });
  res.end(`public page ${norm}\nnothing secret here\n`);
});

server.listen(PORT, "0.0.0.0", () => console.log(`[origin] listening on ${PORT}`));
