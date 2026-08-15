#!/usr/bin/env bun
/**
 * derive-surface - draft an app's ground-truth/SURFACE.yaml, the endpoint
 * coverage denominator.
 *
 *   bun dynast-bench/tools/derive-surface.ts nextjs           # dry run, prints the draft
 *   bun dynast-bench/tools/derive-surface.ts --all --write
 *   bun dynast-bench/tools/derive-surface.ts --all --check    # CI: fail if stale
 *
 * A DRAFT, not an answer. It gets the mechanical part right - every vulnerable
 * operation, from `route:` in the answer key, already tiered and already mapped
 * back to the bug id - and takes a best-effort pass over the app source for the
 * benign routes. The benign half is what needs human review: a route regex
 * cannot tell a real endpoint from a string that looks like one, and it cannot
 * know which discovery tier a URL sits behind.
 *
 * Two rules keep re-running safe:
 *
 *  1. An entry that already exists is NEVER rewritten. Hand review is the
 *     expensive input; a regenerate that clobbered a corrected tier would throw
 *     it away silently.
 *  2. An entry the derivation no longer produces is never deleted, only
 *     reported. A catalog that shrinks makes a tool look better without anyone
 *     touching the tool, which is the one failure mode a coverage benchmark
 *     cannot survive.
 */

import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { appsDir, groundTruthPath, listApps, repoRoot } from "../src/repo.ts";
import { parseGroundTruthFile } from "../src/schema/ground-truth.ts";
import { isHarnessPath, parseRoute, routePaths, templatePath } from "../src/schema/keys.ts";
import { opKey } from "../src/schema/operations.ts";
import { parseSurfaceFile } from "../src/schema/surface.ts";
import { flowMap, flowSeq, q } from "./yaml-emit.ts";
import type { GroundTruth, SurfaceOperation } from "../src/schema/types.ts";

// Same root resolution as derive-match: honours $DYNAST_BENCH_ROOT and the
// walk-up fallback, so the tool works from a compiled binary or another cwd.
const ROOT = repoRoot(import.meta.dir);
const APPS = appsDir(ROOT);

// ------------------------------------------------------------ source rules ---

interface RouteHit {
  method?: string;
  path: string;
  /** file it was found in, for the reviewer */
  from: string;
}

/**
 * Per-stack route extraction. Each rule is (file glob, regex, how to read the
 * match). Deliberately conservative: a missed benign route is a review note, a
 * hallucinated one is a permanently unreachable denominator entry.
 */
interface StackRule {
  /** which files to read, by extension or exact name */
  files: RegExp;
  /** [regex, methodGroup | literal method, pathGroup] */
  patterns: [RegExp, string | number, number][];
}

const RULES: Record<string, StackRule> = {
  // FastAPI / Flask: @app.get("/x"), @router.post("/x")
  py: {
    files: /\.py$/,
    patterns: [[/@(?:app|router|bp)\.(get|post|put|patch|delete|head|options)\(\s*["'`]([^"'`]+)/gi, 1, 2]],
  },
  // Express / NestJS / Fastify, plus hand-rolled http.createServer dispatch
  // (graphql routes on `url.pathname === '/graphql'`, with no framework at all)
  ts: {
    files: /\.(?:ts|js|mjs)$/,
    patterns: [
      [/@(Get|Post|Put|Patch|Delete|Head|Options|All)\(\s*["'`]([^"'`]*)/g, 1, 2],
      [/\b(?:app|router|server|r)\.(get|post|put|patch|delete|head|options|all)\(\s*["'`](\/[^"'`]*)/g, 1, 2],
      [/\b(?:pathname|url|path)\s*===?\s*["'`](\/[^"'`]*)["'`]/g, "ANY", 1],
      [/\b(?:pathname|url|path)\.startsWith\(\s*["'`](\/[^"'`]*)["'`]/g, "ANY", 1],
    ],
  },
  // Gin / net-http / gorilla
  go: {
    files: /\.go$/,
    patterns: [
      [/\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|Any)\(\s*"([^"]+)"/g, 1, 2],
      [/\.(?:HandleFunc|Handle)\(\s*"(\/[^"]*)"/g, "ANY", 1],
    ],
  },
  // Spring Boot is handled by springRoutes() - a method-level @GetMapping is
  // only half a path, and the class-level @RequestMapping that completes it is
  // out of regex range.
  // ASP.NET minimal API + attributes
  cs: {
    files: /\.cs$/,
    patterns: [
      [/\bMap(Get|Post|Put|Patch|Delete)\(\s*"([^"]+)"/g, 1, 2],
      [/\[Http(Get|Post|Put|Patch|Delete)\(\s*"([^"]*)"/g, 1, 2],
    ],
  },
  // Laravel + WordPress + plain PHP.
  //
  // Deliberately no rule for `register_rest_route` or `add_action('wp_ajax_x')`:
  // both give a namespace or an action NAME rather than a path, so turning one
  // into an operation identity needs a human. The apps that use them dispatch
  // through a front controller, which the `$path ===` rule below does catch.
  php: {
    files: /\.php$/,
    patterns: [
      [/Route::(get|post|put|patch|delete|any|match)\(\s*['"]([^'"]+)/gi, 1, 2],
      [/\$(?:path|uri|route|request)\s*===?\s*['"](\/[^'"]*)['"]/g, "ANY", 1],
    ],
  },
  // Rails routes.rb
  rb: {
    files: /routes\.rb$/,
    patterns: [[/^\s*(get|post|put|patch|delete)\s+["']([^"']+)/gim, 1, 2]],
  },
};

/**
 * The build contexts of compose services that publish a host port.
 *
 * Only these are attack surface. A service declared with `expose:` alone -
 * swagger's `partner-api`, every app's `internal-sink` - is reachable from
 * inside the network and nowhere else, so it exists to be an SSRF target, not
 * to be crawled. Cataloging its routes would put endpoints in the denominator
 * that no tool can reach from the outside, permanently capping coverage below
 * 100% and making every tool look worse than it is.
 *
 * Returns null when the compose file cannot be read, meaning "scan everything" -
 * over-collecting is a review problem, under-collecting is a silent one.
 */
function publishedContexts(variantDir: string): { roots: string[]; exclude: string[] } | null {
  const compose = join(variantDir, "docker-compose.yml");
  if (!existsSync(compose)) return null;
  let doc: any;
  try {
    doc = Bun.YAML.parse(readFileSync(compose, "utf8"));
  } catch {
    return null;
  }
  const services = doc?.services;
  if (!services || typeof services !== "object") return null;

  const roots: string[] = [];
  const exclude: string[] = [];
  for (const svc of Object.values<any>(services)) {
    const build = svc?.build;
    if (!build) continue;
    const ctx = typeof build === "string" ? build : (build?.context ?? ".");
    const dir = join(variantDir, ctx);
    const published = Array.isArray(svc.ports) && svc.ports.length > 0;
    (published ? roots : exclude).push(dir);
  }
  // The app's context is usually the whole variant directory, so an internal
  // service's context nests INSIDE it - subtracting is what actually removes it.
  return roots.length ? { roots: [...new Set(roots)], exclude: [...new Set(exclude)] } : null;
}

/**
 * Rewrite a framework's typed path converter into something a real request can
 * match.
 *
 * `templatePath` folds `{anything}` to `{id}`, and `{id}` only matches segments
 * that LOOK like an identifier - a number, a UUID, a CUID. FastAPI's
 * `/uploads/avatars/{name:path}` carries a filename, so the cataloged entry
 * would never match the `/uploads/avatars/user1.png` a tool actually reports:
 * an endpoint nobody can reach, permanently capping coverage. A glob matches
 * whatever the segment really holds.
 */
const normalizePath = (path: string): string => path.replace(/\{[^}]*:[^}]*\}/g, "*");

/** Every source file under a directory, skipping vendored trees. */
function walk(dir: string, out: string[] = []): string[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (/^(?:node_modules|vendor|\.git|target|bin|obj|dist|\.next|uploads)$/.test(name)) continue;
    const p = join(dir, name);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

/** Next.js app router: the file tree IS the route table. */
function nextjsRoutes(root: string): RouteHit[] {
  const out: RouteHit[] = [];
  for (const file of walk(join(root, "src", "app"))) {
    const rel = file.slice(join(root, "src", "app").length).replace(/\\/g, "/");
    const base = rel.replace(/\/(route|page)\.[tj]sx?$/, "") || "/";
    if (/\/route\.[tj]sx?$/.test(rel)) {
      const src = readFileSync(file, "utf8");
      const verbs = [...src.matchAll(/export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)/g)]
        .map((m) => m[1]!);
      const path = decodeURIComponent(base).replace(/\[(\.\.\.)?(\w+)\]/g, "{id}");
      for (const method of verbs.length ? verbs : ["GET"]) out.push({ method, path, from: rel });
    } else if (/\/page\.[tj]sx?$/.test(rel)) {
      out.push({ method: "GET", path: base.replace(/\[(\.\.\.)?(\w+)\]/g, "{id}") || "/", from: rel });
    }
  }
  return out;
}

/**
 * Spring Boot: a route is the class-level @RequestMapping plus the method-level
 * mapping. Taking only the method half yields `/posts/search` for what is really
 * `/api/posts/search` - an endpoint no tool can ever reach, which would cap
 * coverage below 100% permanently. The class prefix on its own is not a route
 * either, so it is never emitted.
 */
function springRoutes(root: string): RouteHit[] {
  const out: RouteHit[] = [];
  for (const file of walk(root).filter((f) => /\.java$/.test(f))) {
    const src = readFileSync(file, "utf8");
    const rel = file.slice(root.length + 1).replace(/\\/g, "/");
    const lines = src.split("\n");
    let prefix = "";
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const cls = line.match(/^\s*@RequestMapping\(\s*(?:value\s*=\s*)?["']([^"']*)/);
      if (cls) {
        prefix = cls[1]!.replace(/\/$/, "");
        continue;
      }
      // a class declaration with no @RequestMapping above it resets the prefix
      if (/^\s*(?:public\s+)?(?:class|record)\s+\w/.test(line) && !/@/.test(line)) {
        const above = lines.slice(Math.max(0, i - 4), i).join("\n");
        if (i > 0 && !/@RequestMapping/.test(above)) prefix = "";
      }
      const m = line.match(/@(Get|Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*)?["']([^"']*)/);
      if (!m) continue;
      const tail = m[2]!;
      const path = (prefix + (tail.startsWith("/") || !tail ? tail : "/" + tail)) || "/";
      out.push({ method: m[1]!.toUpperCase(), path, from: rel });
    }
  }
  return out;
}

/** Plain-PHP / JSP apps: a served file is a route. */
function fileTreeRoutes(root: string, sub: string, ext: RegExp): RouteHit[] {
  const base = join(root, sub);
  if (!existsSync(base)) return [];
  return walk(base)
    .filter((f) => ext.test(f))
    .map((f) => {
      const rel = f.slice(base.length).replace(/\\/g, "/");
      return { method: "GET" as const, path: rel, from: rel };
    });
}

function scanSource(app: string, root: string): RouteHit[] {
  if (app === "nextjs") return nextjsRoutes(root);
  if (app === "springboot") return springRoutes(root);
  if (app === "php") return fileTreeRoutes(root, join("app", "public"), /\.php$/);
  if (app === "jsp") return fileTreeRoutes(root, join("src", "main", "webapp"), /\.jsp$/);

  const ctx = publishedContexts(root);
  const hits: RouteHit[] = [];
  const files = (ctx?.roots ?? [root])
    .flatMap((r) => walk(r))
    .filter((f) => !(ctx?.exclude ?? []).some((d) => f.startsWith(d + "/")))
    // the internal-only SSRF target ships next to the app but is not surface
    .filter((f) => !/internal-sink\.[a-z]+$/.test(f));
  for (const rule of Object.values(RULES)) {
    for (const file of files.filter((f) => rule.files.test(f))) {
      let src: string;
      try {
        src = readFileSync(file, "utf8");
      } catch {
        continue;
      }
      const rel = file.slice(root.length + 1).replace(/\\/g, "/");
      for (const [re, methodAt, pathAt] of rule.patterns) {
        re.lastIndex = 0;
        for (const m of src.matchAll(re)) {
          const path = m[pathAt];
          if (!path || !path.startsWith("/")) continue;
          const method =
            typeof methodAt === "string" ? methodAt : (m[methodAt] ?? "GET").toUpperCase();
          hits.push({ method, path: normalizePath(path), from: rel });
        }
      }
    }
  }
  return hits;
}

// -------------------------------------------------------- answer-key seeds ---

const slug = (s: string) =>
  s.toLowerCase().replace(/\{[^}]*\}/g, "id").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") ||
  "root";

/**
 * The vulnerable half of the catalog, straight from VULNERABILITIES.yaml. This
 * part is trustworthy: the routes are already hand-written, already tiered, and
 * the vulns: mapping is exact rather than inferred.
 */
function seedsFromGroundTruth(gt: GroundTruth): SurfaceOperation[] {
  const byKey = new Map<string, SurfaceOperation>();

  const push = (op: SurfaceOperation) => {
    const k = opKey(op);
    const prev = byKey.get(k);
    if (prev) {
      // two bugs on one endpoint is normal - one operation, both ids
      prev.vulns = [...new Set([...(prev.vulns ?? []), ...(op.vulns ?? [])])];
      return;
    }
    byKey.set(k, op);
  };

  for (const v of gt.vulnerabilities) {
    const m = v.match ?? {};
    const common = {
      discovery: v.discovery,
      reachability: v.reachability,
      vulns: [v.id],
    };

    if (m.net || v.expected_open !== undefined) {
      const n = m.net ?? {};
      if (n.port !== undefined) {
        push({
          id: `net.${slug(String(n.host ?? "host"))}-${n.port}`,
          kind: "net",
          host: n.host,
          port: Number(n.port),
          proto: (n.proto ?? "tcp").toLowerCase(),
          ...common,
        });
      }
      continue;
    }
    if (m.graphql?.op) {
      push({
        id: `gql.${(m.graphql.kind ?? "query").toLowerCase()}.${slug(m.graphql.op)}`,
        kind: "graphql",
        op: m.graphql.op,
        graphql_kind: (m.graphql.kind ?? "query").toLowerCase(),
        ...common,
      });
      continue;
    }
    if (m.ws?.event || m.ws?.endpoint) {
      push({
        id: `ws.${slug(m.ws.event ?? m.ws.endpoint ?? "connect")}`,
        kind: "ws",
        endpoint: m.ws.endpoint,
        event: m.ws.event,
        channel: m.ws.channel,
        ...common,
      });
      continue;
    }
    if (m.llm?.tool) {
      push({ id: `llm.${slug(m.llm.tool)}`, kind: "llm", tool: m.llm.tool, ...common });
      continue;
    }

    const http = m.http ?? parseRoute(v.route ?? "").http;
    if (!http?.path) continue;
    // A bug the answer key demonstrates on a harness endpoint (php's app-wide
    // CORS header, probed via /api/_verify/health.php) is real, but the harness
    // route is not attack surface. Skip it here and let `check` report the bug
    // as unmapped, so a human attaches it to a route the app actually serves.
    //
    // Only the harness rule applies to a SEED: the rest of EXCLUDED drops
    // artifacts a route regex invented, and nothing the answer key names is an
    // artifact. golang deliberately anchors its app-wide CORS bug at `OPTIONS
    // /*`, and a glob is matchable, so it belongs in the denominator.
    if (isHarnessPath(http.path)) continue;
    const method = (m.http?.method ?? http.method ?? undefined) as string | undefined;
    push({
      id: `http.${slug(http.path)}${method ? "." + method.toLowerCase() : ""}`,
      kind: "http",
      method,
      path: http.path,
      query: Object.keys(m.http?.query ?? http.query ?? {}).length
        ? (m.http?.query ?? http.query)
        : undefined,
      params: (m.http?.params ?? http.params ?? []).length
        ? (m.http?.params ?? http.params)
        : undefined,
      port: m.http?.port ?? http.port ?? undefined,
      ...common,
    });

    // A bug reachable at more than one URL: each alternate is its own operation
    // to discover. Method-less on purpose - `http_alt` asserts "this path also
    // reaches the sink", never that it takes the same verb. nextjs's
    // CREDS-BUNDLE-001 is `GET /integrations (-> chunk) then POST
    // /api/integrations/sync`, so inheriting GET produced a catalog entry the
    // app answers with 405: unreachable, and a permanent cap on coverage.
    for (const alt of m.http_alt ?? []) {
      push({ id: `http.${slug(alt)}`, kind: "http", path: alt, ...common });
    }
    // A second path in a prose `route:` is usually a SEQUENCE, not an alias:
    // "GET /integrations (-> chunk) then POST /api/integrations/sync" names two
    // steps with two different verbs. Inheriting the first verb invented a
    // `GET /api/integrations/sync` that 405s - a cataloged endpoint no tool can
    // ever reach, capping coverage below 100% forever. Emit these method-less
    // and let collapseMethodless fold them onto the real handler.
    for (const p of routePaths(v.route ?? "").slice(1)) {
      if (p === http.path) continue;
      push({ id: `http.${slug(p)}`, kind: "http", path: p, ...common });
    }
  }

  return [...byKey.values()];
}

// -------------------------------------------------------------- emit + merge --

/**
 * Not attack surface: assets, framework chunks, and catch-all mounts. The
 * harness's own `_verify` API is excluded too, via the shared `isHarnessPath`
 * so the CI gate cannot disagree with this list about what counts as harness.
 */
const EXCLUDED = [
  /\/(?:favicon\.ico|robots\.txt)$/i,
  /\.(?:css|png|jpe?g|gif|svg|woff2?|ttf|ico)$/i,
  /^\/_next\/static\/(?!.*\.map$)/,
  // a catch-all mount (FastAPI's `@app.options("/{path:path}")` CORS preflight)
  // is not a discrete endpoint - it answers for every path at once, so it can
  // neither be discovered nor missed
  /^\/(?:\{[^}]*\}|\*)\/?$/,
];

const isExcluded = (path: string | undefined): boolean =>
  Boolean(path) && (isHarnessPath(path!) || EXCLUDED.some((re) => re.test(path!)));

function emitYaml(app: string, entry: string | undefined, ops: SurfaceOperation[]): string {
  const lines: string[] = [
    `# Attack-surface catalog for ${app} - the endpoint-coverage denominator.`,
    `#`,
    `# Every operation a tool is expected to DISCOVER. Coverage is measured against`,
    `# this list, so it must stay complete: an entry removed here makes every tool`,
    `# look better without anyone touching a tool.`,
    `#`,
    `# Drafted by dynast-bench/tools/derive-surface.ts, then reviewed by hand.`,
    `app: ${app}`,
  ];
  if (entry) lines.push(`entry: ${entry}`);
  lines.push("", "operations:");

  const field = (k: string, v: unknown) => {
    if (v === undefined || v === null || v === "") return;
    if (Array.isArray(v)) {
      if (!v.length) return;
      lines.push(`    ${k}: ${flowSeq(v.map((x) => q(String(x))))}`);
      return;
    }
    if (typeof v === "object") {
      const e = Object.entries(v as Record<string, unknown>);
      if (!e.length) return;
      lines.push(`    ${k}: ${flowMap(e.map(([a, b]) => [a, q(String(b))]))}`);
      return;
    }
    lines.push(`    ${k}: ${q(String(v))}`);
  };

  for (const op of ops) {
    lines.push(`  - id: ${op.id}`);
    field("kind", op.kind);
    for (const k of [
      "method", "path", "query", "params", "port",
      "op", "graphql_kind", "field",
      "endpoint", "event", "channel", "namespace",
      "tool", "injection_channel",
      "host", "proto",
      "via", "discovery", "reachability", "variant",
    ] as const) {
      if (k === "variant" && (op.variant ?? "both") === "both") continue;
      field(k, (op as Record<string, unknown>)[k]);
    }
    field("vulns", op.vulns);
    if (op.notes) field("notes", op.notes);
  }
  return lines.join("\n") + "\n";
}

/**
 * Drop `ANY /x` when `GET /x` (or any other verb) is also cataloged, moving its
 * vulns onto every concrete sibling. Mutates in place.
 */
function collapseMethodless(ops: SurfaceOperation[]): void {
  const byPath = new Map<string, SurfaceOperation[]>();
  for (const op of ops) {
    if (op.kind !== "http" || !op.path) continue;
    byPath.set(op.path, [...(byPath.get(op.path) ?? []), op]);
  }
  for (const group of byPath.values()) {
    const loose = group.filter((o) => !o.method);
    const concrete = group.filter((o) => o.method);
    if (!loose.length || !concrete.length) continue;
    for (const l of loose) {
      // a required query pair makes it a different operation, not a looser one
      if (Object.keys(l.query ?? {}).length) continue;
      for (const cRef of concrete) {
        // the loose entry has no query (guarded above), so a concrete sibling
        // that DOES carry one is a narrower operation, not the same one
        if (Object.keys(cRef.query ?? {}).length) continue;
        cRef.vulns = [...new Set([...(cRef.vulns ?? []), ...(l.vulns ?? [])])];
        cRef.discovery ??= l.discovery;
        cRef.reachability ??= l.reachability;
      }
      const at = ops.indexOf(l);
      if (at !== -1) ops.splice(at, 1);
    }
  }
}

/**
 * Give the source-derived operations a discovery tier.
 *
 * Tiering is all-or-nothing per app (see `check`), so a benign route left blank
 * blocks the whole catalog - but guessing a tier is worse than leaving it, since
 * a wrong tier silently moves a bucket boundary. Two rules, both defensible:
 *
 *  1. If every vulnerable operation in the app carries the SAME tier, the app
 *     has no gradient and neither does anything else in it. Uniform is the
 *     truthful answer, not a guess (see the "honest single tier" note in
 *     CLAUDE.md - a pure API app is uniformly static-html).
 *  2. Otherwise inherit from the nearest already-tiered sibling by shared path
 *     prefix. `/api/signup/resend` sits under `/api/signup/`, whose other
 *     members are all `flow`, because you only reach any of them mid-signup.
 *     A tie between two different tiers inherits nothing and stays blank for a
 *     human, which is the case where a guess would actually be wrong.
 */
/**
 * Hand review, kept in code so it survives a regenerate.
 *
 * Every entry below is a route the two automatic rules could not tier, resolved
 * by reading the app. They live here rather than only in the YAML because the
 * YAML is regenerated: a decision recorded only there is one deletion away from
 * being silently re-guessed.
 *
 * `[app, method|null, path, tier, why]`.
 */
const TIER_REVIEW: [string, string | null, string, string, string][] = [
  // nextjs - every client call is assembled by api() from lib/routes.ts, so an
  // /api path only exists once the page runs. What is NOT in that registry, or
  // is a literal href in the served HTML, is the exception.
  ["nextjs", "GET", "/signup", "static-html", 'literal <a href="/signup"> on / and /login'],
  ["nextjs", "GET", "/admin/users", "js-runtime", "only appears in the /api/nav response"],
  ["nextjs", "GET", "/api/nav", "js-runtime", "fetched as api(\"nav\") - path assembled at runtime"],
  ["nextjs", "POST", "/api/comments", "js-runtime", "in the lib/routes.ts registry"],
  ["nextjs", "POST", "/api/signup/resend", "flow", "only reachable mid-signup"],
  ["nextjs", "GET", "/api/cache-scoped", "js-runtime", "NM-CACHE endpoint, unlinked sibling of /api/cache"],
  ["nextjs", "GET", "/api/preview-internal", "js-runtime", "NM-FETCH endpoint, unlinked sibling of /api/preview"],

  // laravel - same shape: home.blade.php fetches /nav with a literal URL, and
  // the nav response is what reveals the rest.
  ["laravel", "GET", "/nav", "static-html", "literal fetch(\"/nav\") inline in home.blade.php"],
  ["laravel", "GET", "/register", "static-html", "auth page, like /login"],
  ["laravel", "POST", "/register", "static-html", "auth form post, like POST /login"],
  ["laravel", "POST", "/logout", "interaction", "form submit"],
  ["laravel", "GET", "/signup", "interaction", "matches POST /api/signup/start"],
  ["laravel", "POST", "/api/signup/resend", "flow", "only reachable mid-signup"],
  ["laravel", "GET", "/posts", "js-runtime", "reached from the nav response, like /posts/{id}"],
  ["laravel", "POST", "/posts", "interaction", "form submit, like POST /posts/{id}"],
  ["laravel", "GET", "/posts/{id}/audit", "js-runtime", "NM-IDOR-001 endpoint beside /posts/{id}"],

  // the pure-API apps: one signup flow, everything else conventional
  ["fastapi", "GET", "/", "static-html", "landing page"],
  ["fastapi", "POST", "/api/comments", "static-html", "conventional API route"],
  ["fastapi", "GET", "/uploads/avatars/*", "static-html", "served upload path"],
  ["fastapi", "POST", "/api/signup/resend", "flow", "only reachable mid-signup"],
  ["nestjs", "POST", "/api/signup/resend", "flow", "only reachable mid-signup"],
  ["springboot", "POST", "/api/signup/resend", "flow", "only reachable mid-signup"],
  ["rails", "POST", "/api/signup/resend", "flow", "only reachable mid-signup"],
  ["rails", "PATCH", "/api/profile", "static-html", "conventional API route"],
  ["php", "GET", "/api/signup/resend.php", "flow", "only reachable mid-signup"],
  ["php", "GET", "/index.php", "static-html", "landing page"],
  ["php", "GET", "/me.php", "static-html", "conventional page"],
  ["php", "GET", "/logout.php", "static-html", "conventional page"],
  ["php", "GET", "/pages/home.php", "static-html", "conventional page"],

  // graphql routes on `url.pathname ===` with no framework, so every path is a
  // conventional top-level one a request fuzzer reaches. Introspection is on,
  // which is what makes the schema itself static-html; faking a gradient on top
  // of that would be inventing a front-end the app does not have.
  ["graphql", null, "/graphql", "static-html", "the GraphQL transport itself"],
  ["graphql", null, "/graphql/public", "static-html", "second GraphQL mount"],
  ["graphql", null, "/api/export", "static-html", "conventional top-level route"],
  ["graphql", null, "/auth/callback", "static-html", "conventional oauth callback path"],
  ["graphql", null, "/", "static-html", "landing page"],

  // swagger grades documented-vs-shadow: in the OpenAPI schema -> static-html,
  // reachable but undocumented -> js-runtime
  ["swagger", "GET", "/", "static-html", "landing page"],
  ["swagger", "POST", "/api/auth/login", "static-html", "documented auth route"],
  ["swagger", "GET", "/api/redoc/", "js-runtime", "hidden behind the x-admin-docs header"],
  ["swagger", "GET", "/api/v1/exports/legacy", "js-runtime", "undocumented legacy export"],
];

/**
 * Bugs the answer key demonstrates on a harness endpoint, remapped to a route
 * the app actually serves.
 *
 * These are app-WIDE misconfigurations - a CORS policy set in one config file
 * and applied to every response. The PoC probes them at `/api/_verify/health`
 * because that endpoint is guaranteed to exist, but the harness API is not
 * attack surface, so the operation carrying the bug has to be a real one. Any
 * response would do; the landing page is the one every tool reaches first.
 *
 * `[app, vulnId, path]`.
 */
const VULN_REMAP: [string, string, string][] = [
  ["laravel", "CORS-001", "/"],
  ["php", "CORS-001", "/index.php"],
];

/**
 * Operations no extraction rule can see, added by hand.
 *
 * A WebSocket handshake is mounted on an already-created HTTP server
 * (`new WebSocketServer({ server, path: '/graphql/ws' })`), so it is not a route
 * in any route table - but it is a distinct thing to discover, and a tool that
 * never opens it cannot reach the subscription operations behind it. That is
 * exactly the transport-versus-operation split this catalog exists to measure.
 */
const EXTRA_OPS: Record<string, SurfaceOperation[]> = {
  graphql: [
    {
      id: "ws.graphql-transport",
      kind: "ws",
      endpoint: "/graphql/ws",
      discovery: "interaction",
      reachability: "pre-auth",
      notes: "graphql-ws handshake; the subscription operations ride on it",
    },
  ],
};

function remapVulns(app: string, ops: SurfaceOperation[]): void {
  for (const [a, id, path] of VULN_REMAP) {
    if (a !== app) continue;
    const target = ops.find((o) => o.kind === "http" && o.path === path);
    if (!target) continue;
    target.vulns = [...new Set([...(target.vulns ?? []), id])];
  }
}

/** Apply the hand review. Returns how many entries it resolved. */
function applyReview(app: string, ops: SurfaceOperation[]): number {
  let n = 0;
  for (const op of ops) {
    if (op.discovery || op.kind !== "http") continue;
    // compare templated: the catalog stores the framework's own placeholder
    // name (`/uploads/avatars/{filename}`), the table names the shape
    const mine = templatePath(op.path ?? "");
    const hit = TIER_REVIEW.find(
      ([a, m, p]) =>
        a === app && templatePath(p) === mine && (m === null || m === (op.method ?? null)),
    );
    if (!hit) continue;
    op.discovery = hit[3];
    op.notes = hit[4];
    n++;
  }
  return n;
}

function tierBenign(ops: SurfaceOperation[]): number {
  const tiered = ops.filter((o) => o.discovery);
  const untiered = ops.filter((o) => !o.discovery);
  if (!tiered.length || !untiered.length) return 0;

  const tiers = new Set(tiered.map((o) => o.discovery!));
  let filled = 0;

  if (tiers.size === 1) {
    const only = [...tiers][0]!;
    for (const op of untiered) {
      op.discovery = only;
      op.reachability ??= "pre-auth";
      filled++;
    }
    return filled;
  }

  const segs = (p: string) => p.split("/").filter(Boolean);
  for (const op of untiered) {
    if (!op.path) continue;
    const mine = segs(op.path);
    let best = -1;
    let winners = new Set<string>();
    for (const other of tiered) {
      if (!other.path) continue;
      const theirs = segs(other.path);
      let n = 0;
      while (n < mine.length && n < theirs.length && mine[n] === theirs[n]) n++;
      if (n === 0 || n < best) continue;
      if (n > best) {
        best = n;
        winners = new Set([other.discovery!]);
      } else winners.add(other.discovery!);
    }
    if (winners.size === 1) {
      op.discovery = [...winners][0]!;
      filled++;
    }
  }
  return filled;
}

interface Result {
  app: string;
  kept: number;
  added: SurfaceOperation[];
  orphaned: string[];
  total: number;
  /** benign operations that inherited a tier rather than needing a human */
  tiered: number;
  /** ids still needing a tier by hand - `check` fails until these are gone */
  untiered: string[];
  wrote: boolean;
}

function deriveApp(app: string, opts: { write?: boolean }): Result | null {
  const dir = join(APPS, app);
  const gtPath = groundTruthPath(ROOT, app);
  if (!existsSync(gtPath)) return null;
  const gtRes = parseGroundTruthFile(gtPath);
  const gt = gtRes.value;
  if (!gt?.vulnerabilities.length) return null;

  const surfacePath = join(dir, "ground-truth", "SURFACE.yaml");
  const existing = existsSync(surfacePath) ? parseSurfaceFile(surfacePath).value : null;
  const existingByKey = new Map((existing?.operations ?? []).map((o) => [opKey(o), o]));

  // vulnerable operations from the key, then benign ones from the source
  const derived = seedsFromGroundTruth(gt);
  const derivedKeys = new Set(derived.map(opKey));
  for (const extra of EXTRA_OPS[app] ?? []) {
    const k = opKey(extra);
    if (derivedKeys.has(k)) continue;
    derived.push({ ...extra });
    derivedKeys.add(k);
  }

  for (const hit of scanSource(app, join(dir, "vuln"))) {
    if (isExcluded(hit.path)) continue;
    const op: SurfaceOperation = {
      id: `http.${slug(hit.path)}${hit.method && hit.method !== "ANY" ? "." + hit.method.toLowerCase() : ""}`,
      kind: "http",
      method: hit.method === "ANY" ? undefined : hit.method,
      path: hit.path,
      notes: `benign? derived from ${hit.from} - REVIEW`,
    };
    const k = opKey(op);
    if (derivedKeys.has(k)) continue;
    derived.push(op);
    derivedKeys.add(k);
  }

  // A method-less entry ("any verb reaches this sink") and a concrete-verb entry
  // on the same path are not two endpoints - the first matches everything the
  // second does, so keeping both double-counts one route in the denominator AND
  // lets one report tick two boxes. Fold the loose one into the concrete ones,
  // carrying its bug ids across.
  collapseMethodless(derived);

  // existing entries win outright; new ones are appended
  const merged: SurfaceOperation[] = [];
  const added: SurfaceOperation[] = [];
  for (const op of derived) {
    const k = opKey(op);
    const prev = existingByKey.get(k);
    if (prev) {
      merged.push(prev);
      existingByKey.delete(k);
    } else {
      merged.push(op);
      added.push(op);
    }
  }
  // anything hand-added that the derivation does not produce stays, untouched
  const orphaned = [...existingByKey.values()];
  merged.push(...orphaned);

  // hand review first - it is the authority the automatic rules fall back from
  const tiered = applyReview(app, merged) + tierBenign(merged);
  remapVulns(app, merged);

  // stable ids: a collision would make the catalog unparseable
  const ids = new Map<string, number>();
  for (const op of merged) {
    const n = (ids.get(op.id) ?? 0) + 1;
    ids.set(op.id, n);
    if (n > 1) op.id = `${op.id}-${n}`;
  }

  const text = emitYaml(app, gt.entry, merged);
  const changed = !existsSync(surfacePath) || readFileSync(surfacePath, "utf8") !== text;
  if (opts.write && changed) writeFileSync(surfacePath, text);

  return {
    app,
    kept: merged.length - added.length,
    added,
    orphaned: orphaned.map((o) => o.id),
    total: merged.length,
    tiered,
    untiered: merged.filter((o) => !o.discovery).map((o) => o.id),
    wrote: Boolean(opts.write && changed),
  };
}

// ---------------------------------------------------------------------- cli --

const argv = process.argv.slice(2);
const write = argv.includes("--write");
const check = argv.includes("--check");
const all = argv.includes("--all");
const names = argv.filter((a) => !a.startsWith("--"));

const apps = all || !names.length
  ? listApps(ROOT).map((a) => a.name)
  : names;

let stale = 0;
for (const app of apps.sort()) {
  const r = deriveApp(app, { write });
  if (!r) continue;
  const note = r.added.length ? `+${r.added.length} new` : "up to date";
  console.log(
    `${app.padEnd(12)} ${String(r.total).padStart(3)} ops  ${r.kept} kept  ${note}` +
      // say how many tiers were assigned rather than read off an existing entry -
      // those are the ones a reviewer has not personally signed off on
      (r.tiered ? `  (${r.tiered} tiered automatically)` : "") +
      (r.orphaned.length ? `  (${r.orphaned.length} hand-added kept)` : "") +
      (r.wrote ? "  [written]" : ""),
  );
  for (const op of r.added.slice(0, all ? 3 : 100)) {
    console.log(`  + ${op.id.padEnd(34)} ${opKey(op)}`);
  }
  if (all && r.added.length > 3) console.log(`  … ${r.added.length - 3} more`);
  for (const id of r.untiered) console.log(`  ? ${id.padEnd(34)} needs a discovery: tier by hand`);
  if (r.added.length) stale++;
}

if (check && stale) {
  console.error(`\n${stale} app(s) have un-derived operations - run with --write`);
  process.exit(1);
}
