/**
 * Canonical keys - turning what a scanner reports and what an answer key says
 * into two things that can be compared.
 *
 * Three rules learned from the 18 answer keys:
 *
 *  1. Concrete ids get templated. A scanner hits /api/posts/7; the key says
 *     /api/posts/{id}.
 *  2. Case and trailing slashes are NEVER folded in the strict pass. The
 *     weirdproxy app plants /admin/ and /ADMIN as *distinct* bugs, so folding
 *     them would merge two different findings. A loose pass exists, and every
 *     match records which pass produced it.
 *  3. Percent-encoding is preserved. /admin%2f is its own bug there too.
 */

/** A parsed HTTP anchor, from either side of the comparison. */
export interface HttpKey {
  method: string | null;
  path: string | null;
  /** query pairs with a concrete value - these disambiguate ?action=x routes */
  query: Record<string, string>;
  /** parameter names carrying no value - the injectable ones */
  params: string[];
  /**
   * Host port, when the anchor named one. Only set for sidecar routes (a bug on
   * Jenkins/phpMyAdmin rather than on the app under test), where it is the whole
   * point of the anchor.
   */
  port: number | null;
}

export interface NetKey {
  host: string | null;
  port: number | null;
  proto: string;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX24_RE = /^[0-9a-f]{24,}$/i;
const NUM_RE = /^\d+$/;
const CUID_RE = /^c[a-z0-9]{20,}$/i;
const PLACEHOLDER_RE = /^(?:\{[^}]*\}|:[A-Za-z_][\w-]*|<[^>]*>|\[[^\]]*\]|%7B[^%]*%7D)$/i;

/** One path segment -> itself, or `{id}` if it looks like an identifier. */
function templateSegment(seg: string): string {
  if (!seg) return seg;
  if (PLACEHOLDER_RE.test(seg)) return "{id}";
  if (NUM_RE.test(seg)) return "{id}";
  if (UUID_RE.test(seg)) return "{id}";
  if (HEX24_RE.test(seg)) return "{id}";
  if (CUID_RE.test(seg)) return "{id}";
  return seg;
}

/**
 * Template the identifier-looking segments of a path, preserving everything
 * else exactly (case, trailing slash, percent-encoding).
 *
 * Memoized: the matcher compares every finding against every bug, so this runs
 * ~84k times per scoring pass over only a few hundred distinct strings.
 */
export function templatePath(path: string): string {
  const hit = templateCache.get(path);
  if (hit !== undefined) return hit;
  const out = computeTemplatePath(path);
  templateCache.set(path, out);
  return out;
}

const templateCache = new Map<string, string>();

function computeTemplatePath(path: string): string {
  if (!path) return path;
  const trailing = path.length > 1 && path.endsWith("/");
  const body = trailing ? path.slice(0, -1) : path;
  const out = body.split("/").map(templateSegment).join("/");
  return trailing ? out + "/" : out;
}

/** Strict key: templated, case- and slash-preserving. */
export const pathKeyStrict = (path: string): string => templatePath(path);

/** Loose key: also folds case and a trailing slash. Only for the fallback pass. */
export const pathKeyLoose = (path: string): string => {
  const t = templatePath(path).toLowerCase();
  return t.length > 1 && t.endsWith("/") ? t.slice(0, -1) : t;
};

/**
 * Compare a ground-truth path against a found one. Answer keys sometimes carry a
 * glob ("/_next/static/chunks/*.js.map"), so `*` matches within a segment and
 * `**` across segments.
 */
export function pathGlobMatches(gtPath: string, foundPath: string, loose = false): boolean {
  const key = loose ? pathKeyLoose : pathKeyStrict;
  const want = key(gtPath);
  const got = key(foundPath);
  if (!want.includes("*")) return want === got;
  const rx =
    "^" +
    want
      .split("**")
      .map((chunk) =>
        chunk
          .split("*")
          .map((lit) => lit.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
          .join("[^/]*"),
      )
      .join(".*") +
    "$";
  return new RegExp(rx).test(got);
}

const METHODS = new Set([
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
  "WS", "WSS", "GRAPHQL", "TCP", "UDP", "SMTP", "ANY",
]);

export const normalizeMethod = (m: unknown): string | null => {
  if (!m) return null;
  const s = String(m).trim().toUpperCase();
  return s ? s : null;
};

/** Split "a=1&b=&c" into required pairs (a) and bare/injectable names (b, c). */
function splitQuery(qs: string): { query: Record<string, string>; params: string[] } {
  const query: Record<string, string> = {};
  const params: string[] = [];
  for (const part of qs.split("&")) {
    if (!part) continue;
    const eq = part.indexOf("=");
    const name = (eq === -1 ? part : part.slice(0, eq)).trim();
    if (!name) continue;
    const value = eq === -1 ? "" : part.slice(eq + 1).trim();
    if (value) query[name] = value;
    else params.push(name);
  }
  return { query, params };
}

/** Parse a URL or a bare path into an HTTP key. */
export function httpKeyFromUrl(url: string, method?: unknown): HttpKey {
  let rest = url.trim();
  let port: number | null = null;
  // strip scheme://host[:port], remembering the port
  const schemeAt = rest.match(/^[a-z][a-z0-9+.-]*:\/\//i);
  if (schemeAt) {
    const afterScheme = rest.slice(schemeAt[0].length);
    const slash = afterScheme.indexOf("/");
    const authority = slash === -1 ? afterScheme : afterScheme.slice(0, slash);
    const portMatch = authority.match(/:(\d{1,5})$/);
    if (portMatch) port = Number(portMatch[1]);
    rest = slash === -1 ? "/" : afterScheme.slice(slash);
  }
  const hash = rest.indexOf("#");
  if (hash !== -1) rest = rest.slice(0, hash);
  const q = rest.indexOf("?");
  const path = q === -1 ? rest : rest.slice(0, q);
  const { query, params } = q === -1 ? { query: {}, params: [] } : splitQuery(rest.slice(q + 1));
  return {
    method: normalizeMethod(method),
    path: path.startsWith("/") ? path : "/" + path,
    query,
    params,
    port,
  };
}

/**
 * Best-effort parse of a human `route:` string from VULNERABILITIES.yaml.
 * Handles every shape the 18 keys actually use:
 *
 *   "GET /api/posts/search?q="                          -> GET /api/posts/search, param q
 *   "POST /api/settings/import"                         -> POST /api/settings/import
 *   "GET /posts/{id}"                                   -> GET /posts/{id}
 *   "GET /api/admin/users (header: x-...)"              -> parenthetical dropped
 *   "GET /wp-admin/admin-ajax.php?action=bench_upload"  -> required query pair
 *   "POST /graphql { __schema }"                        -> POST /graphql
 *   "WS /ws token"                                      -> WS /ws
 *   "edge-proxy:443/tcp"                                -> net anchor, not http
 */
export function parseRoute(route: string): { http: HttpKey | null; net: NetKey | null } {
  const raw = (route ?? "").trim();
  if (!raw) return { http: null, net: null };

  // host:port/proto  (the network app)
  const net = raw.match(/^([A-Za-z0-9_.-]+):(\d{1,5})\/(tcp|udp)\b/i);
  if (net) {
    return {
      http: null,
      net: { host: net[1]!, port: Number(net[2]), proto: net[3]!.toLowerCase() },
    };
  }

  // drop trailing parentheticals and brace/prose annotations
  let s = raw.replace(/\s*\([^)]*\)\s*$/g, "").trim();
  s = s.replace(/\s*\{[^}]*\}\s*$/g, (m) => (/^\s*\{id\}\s*$/.test(m) ? m : " ")).trim();

  const parts = s.split(/\s+/);
  let method: string | null = null;
  let target = s;
  const head = parts[0]!.toUpperCase();
  // "GET/POST /export.php" - either verb reaches the sink, so pin neither
  const dual = head.split("/").filter(Boolean);
  if (parts.length > 1 && dual.length > 1 && dual.every((m) => METHODS.has(m))) {
    target = parts.slice(1).join(" ");
  } else if (parts.length > 1 && METHODS.has(head)) {
    method = head;
    target = parts.slice(1).join(" ");
  } else if (parts.length === 1 && METHODS.has(head)) {
    return { http: null, net: null }; // a bare method is not a route
  }

  // an absolute sidecar URL ("http://127.0.0.1:13313") carries its own port
  const abs = target.match(/^[a-z][a-z0-9+.-]*:\/\/\S+/i);
  if (abs) return { http: httpKeyFromUrl(abs[0], method), net: null };

  // "/ws token", "/api/schema/ and /api/docs/" -> take the first path-looking token
  const tokens = target.split(/\s+/).filter(Boolean);
  const first = tokens.find((t) => t.startsWith("/")) ?? tokens[0];
  if (!first || !first.startsWith("/")) return { http: null, net: null };

  const key = httpKeyFromUrl(first, method);
  // a second path in the same route string ("/api/schema/ and /api/docs/") is
  // recorded as an alternate by the caller if it wants it; the primary wins here
  return { http: key, net: null };
}

/** Every path-looking token in a route string, for multi-path routes. */
export function routePaths(route: string): string[] {
  return (route ?? "")
    .replace(/\s*\([^)]*\)\s*/g, " ")
    .split(/[\s,]+/)
    .filter((t) => t.startsWith("/"))
    .map((t) => t.replace(/[.,;]+$/, ""));
}

// ---------------------------------------------------------------- file keys ---

/**
 * Normalize a source path for comparison: drop any absolute prefix, the
 * `vulnerable-apps/<app>/` prefix and the leading `vuln/` or `safe/` so a
 * finding against either twin lines up with the key.
 */
export function fileKey(path: string): string {
  const hit = fileKeyCache.get(path);
  if (hit !== undefined) return hit;
  const out = computeFileKey(path);
  fileKeyCache.set(path, out);
  return out;
}

const fileKeyCache = new Map<string, string>();

function computeFileKey(path: string): string {
  let p = (path ?? "").trim().replace(/\\/g, "/");
  if (!p) return "";
  p = p.replace(/^\.\//, "");
  const apps = p.indexOf("vulnerable-apps/");
  if (apps !== -1) {
    p = p.slice(apps + "vulnerable-apps/".length);
    const slash = p.indexOf("/");
    if (slash !== -1) p = p.slice(slash + 1); // drop <app>/
  }
  p = p.replace(/^\/+/, "");
  p = p.replace(/^(?:vuln|safe)\//, "");
  return p;
}

/** Do two file paths refer to the same file? Suffix match on segment boundaries. */
export function fileMatches(a: string, b: string): boolean {
  const x = fileKey(a);
  const y = fileKey(b);
  if (!x || !y) return false;
  if (x === y) return true;
  if (x.endsWith("/" + y) || y.endsWith("/" + x)) return true;
  const xl = x.toLowerCase();
  const yl = y.toLowerCase();
  return xl === yl || xl.endsWith("/" + yl) || yl.endsWith("/" + xl);
}

/**
 * Is this path the harness's own verification API rather than app surface?
 *
 * Anchored on the `_verify` SEGMENT, not on "verify" anywhere: seven apps serve a
 * genuine `/api/signup/verify`, and excluding a real app route would cap endpoint
 * coverage below 100% forever. Defined once because the generator and the CI gate
 * both need it and a looser copy on either side is invisible until it fires.
 */
export const isHarnessPath = (path: string): boolean =>
  /\/(?:_|%5F)verify(?:\/|$|\.)/i.test(path);

/**
 * Is a reported port state a live claim? Anything else ("closed", "filtered") is a
 * negative observation, which must not match a bug and must not count against
 * precision. Defined once - three call sites used to disagree about it.
 */
export const isOpenState = (state?: string): boolean =>
  !state || /^open/i.test(state.trim());

/** Loose symbol comparison: "GET (empty-q branch)" ~ "GET", "search_posts" ~ "searchPosts". */
export function symbolMatches(a: string | undefined, b: string | undefined): boolean {
  const norm = (s: string) =>
    s
      .replace(/\([^)]*\)/g, " ")
      .replace(/[^A-Za-z0-9]+/g, " ")
      .trim()
      .toLowerCase();
  if (!a || !b) return false;
  const x = norm(a);
  const y = norm(b);
  if (!x || !y) return false;
  if (x === y) return true;
  const xs = new Set(x.split(" "));
  const ys = new Set(y.split(" "));
  // one symbol's tokens fully contained in the other's ("GET" vs "GET empty q branch")
  const sub = (s: Set<string>, t: Set<string>) => [...s].every((tok) => t.has(tok));
  return sub(xs, ys) || sub(ys, xs);
}
