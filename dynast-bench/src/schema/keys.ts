/**
 * Canonical keys - turning what a scanner reports and what an answer key says
 * into two things that can be compared.
 *
 * Three rules learned from the 18 answer keys:
 *
 *  1. Concrete ids get templated. A scanner hits /api/posts/7; the key says
 *     /api/posts/{id}. And a placeholder the KEY writes (`{org}`, `{token}`,
 *     `:slug`) stands for any one concrete segment, so /api/orgs/globex/drafts
 *     reaches /api/orgs/{org}/drafts - an id-shaped guess on the tool's side
 *     cannot recognise a slug or a share token, but the key already says the
 *     segment is a parameter. See `pathMatch`.
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
   * Request headers the bug is reached THROUGH, lowercased (a header name is
   * case-insensitive, RFC 9110 §5.1). Answer-key side only: a finding on the
   * route that never names the header is a different claim about that route -
   * "admin list readable by any user" is not "a spoofed x-middleware-subrequest
   * skips the gate". See `httpHit` in match.ts.
   */
  headers?: string[];
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
 * How a found path lined up with an answer-key path:
 *
 *   exact   segment for segment after templating (`/api/posts/7` vs `/api/posts/{id}`),
 *           or through a `*` / `**` glob the key wrote
 *   param   only because a placeholder the KEY wrote stood in for a concrete
 *           segment that does not look like an id (`globex` for `{org}`)
 *
 * The two are kept apart because they are not equally precise: a near-miss anchored
 * on the literal `/api/orgs/globex/drafts` must outrank a bug anchored on
 * `/api/orgs/{org}/drafts` for a finding at that literal path (`match.ts` weighs it).
 */
export type PathMatch = "exact" | "param";

/**
 * Compare a ground-truth path against a found one. Answer keys sometimes carry a
 * glob ("/_next/static/chunks/*.js.map"), so `*` matches within a segment and
 * `**` across segments. A placeholder segment in the key (`{org}`, `:slug`,
 * `<token>`, `[id]`) matches any one non-empty segment of the found path.
 */
export function pathMatch(gtPath: string, foundPath: string, loose = false): PathMatch | null {
  const key = loose ? pathKeyLoose : pathKeyStrict;
  const want = key(gtPath);
  const got = key(foundPath);
  if (want.includes("*") ? globRegex(want).test(got) : want === got) return "exact";
  const anySegment = placeholderRegex(gtPath, loose);
  return anySegment?.test(got) ? "param" : null;
}

/** {@link pathMatch} as a yes/no, for callers that do not weigh the two kinds. */
export function pathGlobMatches(gtPath: string, foundPath: string, loose = false): boolean {
  return pathMatch(gtPath, foundPath, loose) !== null;
}

/**
 * {@link pathMatch} with a router's precedence: a static route beats a parameter.
 * When `routes` (the app's route table - every anchor in the answer key, plus the
 * SURFACE catalog when there is one) names the found path exactly, the found path
 * IS that route, so a placeholder elsewhere does not also claim it.
 * `/api/posts/search` is the search route, not `/api/posts/{id}` with id=search -
 * which is how every framework the suite ships resolves it, and the only reading
 * under which a marker leaked by the search bug cannot be credited to the IDOR.
 */
export function routedPathMatch(
  gtPath: string,
  foundPath: string,
  loose: boolean,
  routes: readonly string[],
): PathMatch | null {
  const hit = pathMatch(gtPath, foundPath, loose);
  if (hit !== "param") return hit;
  return routes.some((r) => pathMatch(r, foundPath, loose) === "exact") ? null : hit;
}

/** One key segment (already templated) as regex source: `*` within it, `**` across. */
const globSource = (pattern: string): string =>
  pattern
    .split("**")
    .map((chunk) =>
      chunk
        .split("*")
        .map((lit) => lit.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
        .join("[^/]*"),
    )
    .join(".*");

const globRegex = (want: string): RegExp => {
  const hit = globCache.get(want);
  if (hit) return hit;
  const rx = new RegExp("^" + globSource(want) + "$");
  globCache.set(want, rx);
  return rx;
};
const globCache = new Map<string, RegExp>();

/**
 * The key path with every placeholder segment opened up to "any one segment", or
 * null when the key writes no placeholder. Built from the RAW key path, not the
 * templated one: templating also folds a literal `7` to `{id}`, and a literal in
 * the key is a claim about that segment, not a parameter. Every other segment goes
 * through the same templating (and, in the loose pass, the same case and trailing
 * slash folding) the found path does. Memoized like `templatePath`.
 */
function placeholderRegex(gtPath: string, loose: boolean): RegExp | null {
  const cacheKey = (loose ? "L" : "S") + gtPath;
  const hit = placeholderCache.get(cacheKey);
  if (hit !== undefined) return hit;
  const out = computePlaceholderRegex(gtPath, loose);
  placeholderCache.set(cacheKey, out);
  return out;
}

const placeholderCache = new Map<string, RegExp | null>();

function computePlaceholderRegex(gtPath: string, loose: boolean): RegExp | null {
  let path = gtPath;
  if (loose && path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  const trailing = path.length > 1 && path.endsWith("/");
  const segs = (trailing ? path.slice(0, -1) : path).split("/");
  if (!segs.some((seg) => PLACEHOLDER_RE.test(seg))) return null;
  const parts = segs.map((seg) => {
    if (PLACEHOLDER_RE.test(seg)) return "[^/]+";
    const t = templateSegment(seg);
    return globSource(loose ? t.toLowerCase() : t);
  });
  return new RegExp("^" + parts.join("/") + (trailing ? "/" : "") + "$");
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
 *   "GET /api/admin/users (header: x-...)"              -> required header x-...
 *   "GET /api/reports/admin-summary (Bearer)"           -> other parentheticals dropped
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

  // a "(header: a, b)" parenthetical names the request headers the bug is
  // reached through; every other trailing parenthetical is prose
  const headers = routeHeaders(raw);

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
  if (abs) return { http: withHeaders(httpKeyFromUrl(abs[0], method), headers), net: null };

  // "/ws token", "/api/schema/ and /api/docs/" -> take the first path-looking token
  const tokens = target.split(/\s+/).filter(Boolean);
  const first = tokens.find((t) => t.startsWith("/")) ?? tokens[0];
  if (!first || !first.startsWith("/")) return { http: null, net: null };

  const key = httpKeyFromUrl(first, method);
  // a second path in the same route string ("/api/schema/ and /api/docs/") is
  // recorded as an alternate by the caller if it wants it; the primary wins here
  return { http: withHeaders(key, headers), net: null };
}

/**
 * The header names a route's "(header: a, b)" parenthetical declares, lowercased.
 * Anchored on the literal `header:` / `headers:` label the answer keys write, so
 * prose parentheticals ("(Bearer)", "(twice)") never become requirements.
 */
export function routeHeaders(route: string): string[] {
  const m = (route ?? "").match(/\(\s*headers?\s*:\s*([^)]*)\)\s*$/i);
  if (!m) return [];
  return [...new Set(m[1]!.split(/[\s,]+/).map((h) => h.trim().toLowerCase()).filter(Boolean))];
}

const withHeaders = (key: HttpKey, headers: string[]): HttpKey =>
  headers.length ? { ...key, headers } : key;

/**
 * An `http_alt` entry: a bare path ("/api/docs/"), or a path pinned to its own
 * verb ("POST /api/posts/{id}/publish"). The pinned form is for a multi-step
 * bug whose later step is a different request - inheriting the primary verb
 * there anchors a request the app answers with 405.
 */
export function splitAlt(alt: string): { method: string | null; path: string } {
  const m = alt.trim().match(/^([A-Za-z]+)\s+(\/\S*)$/);
  if (m && METHODS.has(m[1]!.toUpperCase())) return { method: m[1]!.toUpperCase(), path: m[2]! };
  return { method: null, path: alt.trim() };
}

/**
 * Every path in a route string, with the verb written right in front of it when
 * there is one: "GET /a then POST /b" -> [{GET, /a}, {POST, /b}].
 */
export function routeSteps(route: string): { method: string | null; path: string }[] {
  const tokens = (route ?? "").replace(/\s*\([^)]*\)\s*/g, " ").split(/[\s,]+/).filter(Boolean);
  const out: { method: string | null; path: string }[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (!t.startsWith("/")) continue;
    const prev = tokens[i - 1]?.toUpperCase();
    out.push({ method: prev && METHODS.has(prev) ? prev : null, path: t.replace(/[.,;]+$/, "") });
  }
  return out;
}

/** Every path-looking token in a route string, for multi-path routes. */
export function routePaths(route: string): string[] {
  return routeSteps(route).map((s) => s.path);
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
