#!/usr/bin/env bun
/**
 * derive-match - write machine-readable `match:` blocks into every
 * ground-truth/VULNERABILITIES.yaml.
 *
 *   bun dynast-bench/tools/derive-match.ts --all --write
 *   bun dynast-bench/tools/derive-match.ts nextjs            # dry run, prints the diff
 *
 * The human `route:` string stays exactly as it is - this only ADDS the anchors a
 * scorer needs: method/path/query/params, the source file + the line range of the
 * vuln↔safe delta, the proof markers the PoC greps for, and the stack-specific
 * keys (net / graphql / ws / llm).
 *
 * Line attribution. The range must cover the bug's BODY, because that is what a
 * tool reports - not the comment above it, and not necessarily the diff hunk
 * (graphql flips 31 flags inside one hunk; llmagent gates all 29 bugs behind a
 * single `SECURE` flag). So: find where the bug starts, then run to whatever comes
 * next in that file.
 *
 *   start, most trustworthy first:
 *     1. a `VULN <ID>` comment in the vuln source pins the bug exactly
 *     2. the line where the entry's `symbol` is defined
 *     3. the file holds exactly one bug, so every change in it belongs to it
 *     4. exactly one diff hunk carrying a distinctive token from the route
 *   end: the next bug or near-miss anchor in the same file, capped at
 *     MAX_BODY_SPAN. Bounding on the next NEAR-MISS matters most - a range that
 *     swallowed its safe sibling would score a false positive as a true one.
 *
 * Two anchors in one file may never overlap; when they would, the later one gets
 * no `lines:` at all and the matcher falls back to its symbol. A wrong range would
 * mis-score every tool forever, so none is better.
 *
 * Editing is textual (splice lines into the YAML), never a re-serialize: the
 * files carry comments, block scalars and a deliberate key order that a
 * round-trip through a YAML emitter would destroy. Re-running replaces the
 * blocks it wrote before, so it is idempotent.
 */

import { existsSync, readdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { cweFamily } from "../src/schema/cwe.ts";
import { fileKey, httpKeyFromUrl, parseRoute, routePaths, templatePath } from "../src/schema/keys.ts";
import { appsDir, listApps, repoRoot, vulnTagsIn } from "../src/repo.ts";
import { flowMap, flowSeq, q } from "./yaml-emit.ts";
import { parseUnifiedDiff, type Hunk } from "../src/twin-diff.ts";

const ROOT = repoRoot(import.meta.dir);

// ------------------------------------------------------------------- helpers --

const GENERIC_SYMBOLS = new Set([
  "get", "post", "put", "patch", "delete", "head", "options", "index", "show", "create",
  "update", "destroy", "main", "handler", "route", "routes", "app", "config", "static",
  "new", "edit", "call", "run", "do", "process", "init", "setup", "page", "view", "render",
]);
const GENERIC_ROUTE_TOKENS = new Set([
  "api", "v1", "v2", "www", "index", "php", "html", "jsp", "aspx", "graphql", "admin",
  "wp", "wp-admin", "wp-json", "public", "app", "auth", "users", "user", "posts", "post",
]);

/** `vuln/x` and `safe/x` are the same file; line numbers are vuln-side. */
const vulnSide = (p: string): string => p.replace(/^safe\//, "vuln/");

/**
 * Distinctive tokens of a symbol, most specific first. For a qualified symbol
 * ("PostsController#search", "AuthController@login") the LAST component is the
 * member, which is what identifies the bug - the class name is shared by every
 * bug in the file.
 */
const tokensOf = (s: string, generic: Set<string>): string[] => {
  const raw = s || "";
  const member = raw.split(/[#@]|::|->/).pop() ?? raw;
  const rank = (t: string) => (member.includes(t) ? 0 : 1);
  return [...new Set(raw.split(/[^A-Za-z0-9_]+/).filter(Boolean))]
    .filter((t) => t.length >= 4 && !generic.has(t.toLowerCase()))
    .sort((a, b) => rank(a) - rank(b) || b.length - a.length);
};

// ------------------------------------------------------------------ the diff --

const srcCache = new Map<string, string[]>();

/** Lines of a vuln-side source file (empty when it is not readable). */
function sourceLines(appDir: string, path: string): string[] {
  const vulnPath = vulnSide(path);
  const key = `${appDir}::${vulnPath}`;
  const hit = srcCache.get(key);
  if (hit) return hit;
  let lines: string[] = [];
  try {
    lines = readFileSync(join(appDir, vulnPath), "utf8").split("\n");
  } catch {
    lines = [];
  }
  srcCache.set(key, lines);
  return lines;
}

/** Does this line look like where a symbol is defined rather than just used? */
const DEFINITION_RE =
  /\b(?:function|def|class|const|let|var|public|private|protected|static|void|func|sub|proc)\b|=>|:\s*(?:async\s*)?\(|^\s*[A-Z_][A-Z0-9_]*\s*:/;

/** vuln-side changed ranges, from ONE `diff -ru` for the whole app. */
const hunkCache = new Map<string, Map<string, Hunk[]>>();

function appHunks(appDir: string): Map<string, Hunk[]> {
  const hit = hunkCache.get(appDir);
  if (hit) return hit;
  const proc = Bun.spawnSync(["diff", "-r", "-U", "0", "vuln", "safe"], { cwd: appDir });
  const files = parseUnifiedDiff(new TextDecoder().decode(proc.stdout));
  const out = new Map<string, Hunk[]>();
  for (const [path, f] of files) out.set(path, f.hunks);
  hunkCache.set(appDir, out);
  return out;
}

const hunksFor = (appDir: string, path: string): Hunk[] =>
  appHunks(appDir).get(fileKey(vulnSide(path))) ?? [];

/** The vuln-side text a hunk covers, from the already-cached source. */
const hunkText = (appDir: string, path: string, h: Hunk): string =>
  sourceLines(appDir, path).slice(h.start - 1, h.end).join("\n");

/** Line of a `VULN <ID>` comment in the vuln tree, if the app tags its bugs. */
const tagCache = new Map<string, Map<string, { path: string; line: number }>>();

function tagIndex(appDir: string): Map<string, { path: string; line: number }> {
  const hit = tagCache.get(appDir);
  if (hit) return hit;
  const SKIP = new Set(["node_modules", ".next", "vendor", "dist", "build", "target", "obj", "bin", ".git"]);
  const index = new Map<string, { path: string; line: number }>();
  const walk = (dir: string) => {
    let entries: ReturnType<typeof readdirSync>;
    try {
      entries = readdirSync(dir, { withFileTypes: true }) as any;
    } catch {
      return;
    }
    for (const e of entries as any[]) {
      if (SKIP.has(e.name)) continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) {
        walk(p);
        continue;
      }
      let text: string;
      try {
        if (statSync(p).size > 2_000_000) continue;
        text = readFileSync(p, "utf8");
      } catch {
        continue;
      }
      if (!text.includes("VULN")) continue;
      text.split("\n").forEach((line, i) => {
        // only a VULN tag marks where a bug lives; FIXED tags sit in the safe twin
        if (!/\bVULN[:\s-]/.test(line)) return;
        for (const id of vulnTagsIn(line)) {
          if (!index.has(id)) index.set(id, { path: p.slice(appDir.length + 1), line: i + 1 });
        }
      });
    }
  };
  walk(join(appDir, "vuln"));
  tagCache.set(appDir, index);
  return index;
}

/** Longest a single bug's body may be taken to run. */
const MAX_BODY_SPAN = 60;

/**
 * Reserve a line range for one entry. Returns false when it would overlap a range
 * already reserved in that file - the caller then emits no `lines:` and the
 * matcher falls back to the symbol.
 */
function claim(
  claimed: Map<string, [number, number, string][]>,
  path: string,
  range: [number, number],
  id: string,
): boolean {
  const key = vulnSide(path);
  const taken = claimed.get(key) ?? [];
  for (const [s, e, owner] of taken) {
    if (owner === id) continue;
    if (range[0] <= e && range[1] >= s) return false;
  }
  claimed.set(key, [...taken, [range[0], range[1], id]]);
  return true;
}

/**
 * The line a bug starts at: its `VULN <ID>` comment if the app tags bugs,
 * otherwise where its `symbol` is defined. `symbol~` means the symbol appears on
 * several lines and one was chosen (inside a diff hunk, or the one that looks
 * like a definition).
 */
function anchorLine(
  appDir: string,
  v: any,
  vulnPath: string,
): { line: number; source: string } | null {
  const tag = tagIndex(appDir).get(String(v.id));
  if (tag && tag.path === vulnPath) return { line: tag.line, source: "tag" };

  const src = sourceLines(appDir, vulnPath);
  const token = tokensOf(String(v.symbol ?? ""), GENERIC_SYMBOLS)[0];
  if (!token || !src.length) return null;

  const hunks = hunksFor(appDir, vulnPath);
  const hits = src.flatMap((line, i) => (line.includes(token) ? [i + 1] : []));
  if (!hits.length) return null;
  if (hits.length === 1) return { line: hits[0]!, source: "symbol" };
  const pick =
    hits.find((n) => DEFINITION_RE.test(src[n - 1]!)) ??
    hits.find((n) => hunks.some((h) => n >= h.start && n <= h.end)) ??
    hits[0]!;
  return { line: pick, source: "symbol~" };
}

/** Where a bug's body stops: the next anchor in the file, or MAX_BODY_SPAN. */
function bodyEnd(
  appDir: string,
  vulnPath: string,
  start: number,
  boundaries: Map<string, number[]>,
): number {
  const eof = Math.max(1, sourceLines(appDir, vulnPath).length);
  const next = (boundaries.get(vulnSide(vulnPath)) ?? []).find((n) => n > start);
  const cap = Math.min(start + MAX_BODY_SPAN, eof);
  return next ? Math.max(start, Math.min(next - 1, cap)) : cap;
}

/**
 * Every line in a file that starts something the scorer must not confuse with
 * something else: each planted bug and each near-miss.
 */
function anchorBoundaries(appDir: string, vulns: any[], nearMisses: any[]): Map<string, number[]> {
  const byFile = new Map<string, number[]>();
  const push = (path: string, line: number) => {
    const key = vulnSide(path.replace(/^\.\//, ""));
    byFile.set(key, [...(byFile.get(key) ?? []), line]);
  };
  for (const v of vulns) {
    const p = String(v.variant_paths?.vuln ?? "");
    if (!p || p.startsWith("(")) continue;
    const a = anchorLine(appDir, v, p);
    if (a) push(p, a.line);
  }
  for (const nm of nearMisses) {
    const p = String(nm.path ?? "");
    if (!p || p.startsWith("(")) continue;
    // near-misses have no id comment; find their symbol the same way
    const a = anchorLine(appDir, { id: nm.id, symbol: nm.symbol }, p);
    if (a) push(p, a.line);
  }
  for (const [k, v] of byFile) byFile.set(k, [...new Set(v)].sort((a, b) => a - b));
  return byFile;
}

/**
 * A near-miss in its own file usually IS its own endpoint (nextjs plants
 * /api/preview-internal next to /api/preview), but the answer key records only a
 * path. Without a route anchor a black-box tool can never be charged for flagging
 * safe code, which is half the point of the near-misses - so infer the route from
 * the file-routing conventions these apps use.
 *
 * A wrong guess is harmless: it yields an anchor at a route nothing serves, which
 * simply never matches. Anything that collides with a real bug's route is dropped
 * by the caller rather than risk stealing that bug's findings.
 */
function routeFromPath(path: string): string | null {
  const p = path.replace(/^(?:vuln|safe)\//, "");
  const rules: [RegExp, (m: RegExpMatchArray) => string][] = [
    [/^src\/app\/(.+)\/route\.[tj]sx?$/, (m) => `/${m[1]}`], // Next.js app router API
    [/^src\/app\/(.+)\/page\.[tj]sx?$/, (m) => `/${m[1]}`], // Next.js app router page
    [/^src\/app\/page\.[tj]sx?$/, () => `/`],
    [/^src\/pages\/(.+)\.[tj]sx?$/, (m) => `/${m[1].replace(/\/index$/, "")}`],
    [/^(?:app\/)?public\/(.+)$/, (m) => `/${m[1]}`], // served from the web root
    [/^Pages\/(.+)\.cshtml$/, (m) => `/${m[1]}`], // ASP.NET Razor Pages
    [/^src\/main\/webapp\/(.+\.jsp)$/, (m) => `/${m[1]}`], // JSP
  ];
  for (const [re, out] of rules) {
    const m = p.match(re);
    if (m) {
      const route = out(m);
      // route groups and private folders are not URL segments
      if (/\(|\)|\[\.{3}/.test(route)) return null;
      return route.replace(/\/index$/, "") || "/";
    }
  }
  return null;
}

/** Markers a PoC greps for - the strings that prove this specific bug. */
function markersFromPoc(appDir: string, poc: string | undefined): string[] {
  if (!poc) return [];
  const file = join(appDir, poc);
  if (!existsSync(file)) return [];
  const text = readFileSync(file, "utf8");
  const out = new Set<string>();
  for (const m of text.matchAll(/['"]([^'"\s]{8,60})['"]/g)) {
    // a grep pattern may be an alternation ("STACKTRACE-MARKER|RuntimeException"),
    // which is several markers - the matcher compares literals, not regexes
    for (const alt of m[1]!.split("|")) {
      const s = alt.trim();
      if (s.length < 8 || !/MARKER|SECRET|SINK|CONFIDENTIAL/i.test(s)) continue;
      if (/[\/\\?=&{}$*^]/.test(s)) continue; // urls, regexes, shell expansions
      out.add(s);
    }
  }
  return [...out].sort();
}

// -------------------------------------------------------------- match blocks --

interface Derived {
  lines: string[];
  hasHttp: boolean;
  hasFile: boolean;
  hasLines: boolean;
  hasMarkers: boolean;
  lineSource: string;
}

function deriveOne(
  appDir: string,
  v: any,
  bugCount: Map<string, number>,
  claimed: Map<string, [number, number, string][]>,
  boundaries: Map<string, number[]>,
): Derived {
  const body: string[] = [];
  const route = String(v.route ?? "");
  const parsed = parseRoute(route);

  // ---- http ---------------------------------------------------------------
  let hasHttp = false;
  if (parsed.http?.path) {
    const h = parsed.http;
    const pairs: [string, string][] = [];
    if (h.method) pairs.push(["method", h.method]);
    pairs.push(["path", q(h.path!)]);
    if (Object.keys(h.query).length) {
      pairs.push([
        "query",
        flowMap(Object.entries(h.query).map(([k, val]) => [k, q(val)] as [string, string])),
      ]);
    }
    if (h.params.length) pairs.push(["params", flowSeq(h.params.map((p) => q(p)))]);
    if (h.port !== null) pairs.push(["port", String(h.port)]);
    body.push(`  http: ${flowMap(pairs)}`);
    hasHttp = true;

    // a route naming a second endpoint keeps it as an alternate path
    const extras = routePaths(route)
      .map((p) => httpKeyFromUrl(p).path!)
      .filter((p) => p !== h.path);
    if (extras.length) {
      body.push(`  http_alt: ${flowSeq([...new Set(extras)].map((p) => q(p)))}`);
    }
  }

  // ---- net ----------------------------------------------------------------
  if (parsed.net || v.host) {
    const host = parsed.net?.host ?? String(v.host ?? "");
    const port = parsed.net?.port ?? (Number(route.match(/:(\d{1,5})\b/)?.[1] ?? 0) || null);
    const proto = (parsed.net?.proto ?? v.proto ?? "tcp").toString().toLowerCase();
    const pairs: [string, string][] = [];
    if (host) pairs.push(["host", q(host)]);
    if (port) pairs.push(["port", String(port)]);
    pairs.push(["proto", proto]);
    body.push(`  net: ${flowMap(pairs)}`);
  }

  // ---- file + lines -------------------------------------------------------
  let hasFile = false;
  let hasLines = false;
  let lineSource = "-";
  const vulnPath = String(v.variant_paths?.vuln ?? "");
  if (vulnPath && !vulnPath.startsWith("(")) {
    const pairs: [string, string][] = [["path", q(vulnPath)]];
    if (v.symbol) pairs.push(["symbol", q(String(v.symbol))]);

    const hunks = hunksFor(appDir, vulnPath);

    let range: [number, number] | null = null;

    const anchor = anchorLine(appDir, v, vulnPath);
    if (anchor) {
      // A tool reports the SINK, which is inside the bug's body - not the comment
      // above it and not necessarily the diff hunk. So the range runs from the
      // anchor to whatever comes next in that file: the next planted bug, the next
      // near-miss, or MAX_BODY_SPAN lines. Bounding on the next NEAR-MISS matters
      // most - a range that swallowed its safe sibling would score a false
      // positive as a true one.
      range = [anchor.line, bodyEnd(appDir, vulnPath, anchor.line, boundaries)];
      lineSource = anchor.source;
    }

    if (!range && hunks.length) {
      if (bugCount.get(vulnPath) === 1) {
        range = [Math.min(...hunks.map((h) => h.start)), Math.max(...hunks.map((h) => h.end))];
        lineSource = "only-bug";
      } else {
        const routeTokens = tokensOf(
          [route, ...Object.values(parsed.http?.query ?? {})].join(" "),
          GENERIC_ROUTE_TOKENS,
        );
        const byRoute = hunks.filter((h) =>
          routeTokens.some((t) => hunkText(appDir, vulnPath, h).includes(t)),
        );
        if (routeTokens.length && byRoute.length === 1) {
          range = [byRoute[0]!.start, byRoute[0]!.end];
          lineSource = "route-token";
        }
      }
    }

    // Two anchors in one file must not overlap: an ambiguous range is worse than
    // none, because the matcher would credit whichever it happened to try first.
    if (range) {
      if (!claim(claimed, vulnPath, range, String(v.id))) {
        range = null;
        lineSource = "clash";
      }
    }
    if (range) {
      pairs.push(["lines", `[${range[0]}, ${range[1]}]`]);
      hasLines = true;
    }
    body.push(`  file: ${flowMap(pairs)}`);
    hasFile = true;
  }

  // ---- graphql / ws / llm -------------------------------------------------
  if (v.graphql_op) {
    const pairs: [string, string][] = [["op", q(String(v.graphql_op))]];
    if (v.graphql_kind) pairs.push(["kind", q(String(v.graphql_kind))]);
    body.push(`  graphql: ${flowMap(pairs)}`);
  }
  if (v.transport) {
    // "WS /ws {type: subscribe, channel: org:globex:posts}" - the frame type and
    // the channel are the only things separating several bugs on one endpoint
    const pairs: [string, string][] = [["transport", q(String(v.transport))]];
    const event = route.match(/\{\s*type:\s*([^,}\s]+)/)?.[1];
    const channel = route.match(/\bchannel:\s*([^,}\s]+)/)?.[1];
    if (event) pairs.push(["event", q(event)]);
    if (channel) pairs.push(["channel", q(channel)]);
    body.push(`  ws: ${flowMap(pairs)}`);
  }
  if (v.tool || v.injection_channel) {
    const pairs: [string, string][] = [];
    if (v.tool) pairs.push(["tool", q(String(v.tool))]);
    if (v.injection_channel) pairs.push(["channel", q(String(v.injection_channel))]);
    if (pairs.length) body.push(`  llm: ${flowMap(pairs)}`);
  }

  // ---- markers + cwe family ----------------------------------------------
  const markers = markersFromPoc(appDir, v.poc);
  if (markers.length) body.push(`  markers: ${flowSeq(markers.map((m) => q(m)))}`);
  if (!cweFamily(v.cwe)) {
    body.push(`  cwe_family: ${q(String(v.cwe ?? "unclassified"))}`);
  }

  return {
    // entry keys sit at 4 spaces, their children at 6
    lines: body.length ? ["    match:", ...body.map((l) => "    " + l)] : [],
    hasHttp,
    hasFile,
    hasLines,
    hasMarkers: markers.length > 0,
    lineSource,
  };
}

// --------------------------------------------------------------- yaml splice --

/**
 * Insert (or replace) each entry's `match:` block. Entries are found by their
 * `- id:` line; the block goes immediately before `poc:` so the human fields stay
 * on top and the anchors sit next to the PoC that proves them.
 */
function spliceMatchBlocks(
  text: string,
  blocks: Map<string, string[]>,
): { text: string; inserted: number; replaced: number } {
  const lines = text.split("\n");
  const out: string[] = [];
  let i = 0;
  let inserted = 0;
  let replaced = 0;
  let inNearMisses = false;

  while (i < lines.length) {
    const line = lines[i]!;
    if (/^near_misses:/.test(line)) inNearMisses = true;
    else if (/^[A-Za-z_]/.test(line)) inNearMisses = false;

    const idMatch = line.match(/^  - id:\s*(\S+)\s*$/);
    if (!idMatch) {
      out.push(line);
      i++;
      continue;
    }

    const id = idMatch[1]!;
    const block = blocks.get(id);
    // collect the whole entry
    const entry: string[] = [line];
    i++;
    while (i < lines.length && !/^  - /.test(lines[i]!) && !/^[A-Za-z_]/.test(lines[i]!)) {
      entry.push(lines[i]!);
      i++;
    }

    // drop any match: block a previous run wrote
    const kept: string[] = [];
    let hadMatch = false;
    for (let j = 0; j < entry.length; j++) {
      if (/^    match:\s*$/.test(entry[j]!)) {
        hadMatch = true;
        j++;
        while (j < entry.length && /^      \S/.test(entry[j]!)) j++;
        j--;
        continue;
      }
      kept.push(entry[j]!);
    }

    if (!block?.length) {
      out.push(...kept);
      continue;
    }
    if (hadMatch) replaced++;
    else inserted++;

    const anchor = kept.findIndex((l) => /^    (?:poc|notes):/.test(l));
    if (anchor === -1) {
      out.push(...kept, ...block);
    } else {
      out.push(...kept.slice(0, anchor), ...block, ...kept.slice(anchor));
    }
  }

  return { text: out.join("\n"), inserted, replaced };
}

// --------------------------------------------------------------------- main ----

const argv = process.argv.slice(2);
const write = argv.includes("--write");
/** CI mode: fail if any answer key's anchors are stale (a source edit shifts lines). */
const checkOnly = argv.includes("--check");
const wantAll = argv.includes("--all");
const named = argv.filter((a) => !a.startsWith("-"));

const APPS = appsDir(ROOT);
const apps = (wantAll || !named.length ? listApps(ROOT).map((a) => a.name) : named).filter((n) =>
  existsSync(join(APPS, n, "ground-truth", "VULNERABILITIES.yaml")),
);

console.log(
  `derive-match  ${checkOnly ? "CHECK" : write ? "WRITE" : "dry run"}  ·  ${apps.length} app(s)\n`,
);
const rows: string[][] = [];
let totalNoLines = 0;
const stale: string[] = [];

for (const app of apps) {
  const appDir = join(APPS, app);
  const gtPath = join(appDir, "ground-truth", "VULNERABILITIES.yaml");
  const raw = readFileSync(gtPath, "utf8");
  const doc: any = Bun.YAML.parse(raw);
  const vulns: any[] = doc?.vulnerabilities ?? [];

  const bugCount = new Map<string, number>();
  for (const v of vulns) {
    const p = String(v.variant_paths?.vuln ?? "");
    if (p) bugCount.set(p, (bugCount.get(p) ?? 0) + 1);
  }

  const claimed = new Map<string, [number, number, string][]>();
  const nearMisses: any[] = doc?.near_misses ?? [];
  const boundaries = anchorBoundaries(appDir, vulns, nearMisses);
  // templated and case-folded, because the matcher normalizes both sides: an
  // inferred "/posts/[id]" IS the bug's "/posts/{id}" once normalized
  const bugRoutes = new Set(
    vulns.flatMap((v: any) => {
      const h = parseRoute(String(v.route ?? "")).http;
      return h?.path ? [templatePath(h.path).toLowerCase()] : [];
    }),
  );
  // Files a real bug lives in. A route inferred from such a file belongs to the
  // bug, not to a near-miss that happens to sit in the same file.
  const bugFiles = new Set(
    vulns.map((v: any) => String(v.variant_paths?.vuln ?? "").replace(/^(?:vuln|safe)\//, "")),
  );
  const blocks = new Map<string, string[]>();

  let http = 0;
  let file = 0;
  let withLines = 0;
  let markers = 0;
  const sources = new Map<string, number>();

  // Bugs first: they own their line ranges, and a near-miss that would overlap one
  // gets no range rather than shadowing the bug.
  for (const v of vulns) {
    const d = deriveOne(appDir, v, bugCount, claimed, boundaries);
    blocks.set(String(v.id), d.lines);
    if (d.hasHttp) http++;
    if (d.hasFile) file++;
    if (d.hasLines) withLines++;
    if (d.hasMarkers) markers++;
    sources.set(d.lineSource, (sources.get(d.lineSource) ?? 0) + 1);
  }

  for (const nm of nearMisses) {
    const path = String(nm.path ?? "");
    if (!path || path.startsWith("(")) continue;
    const pairs: [string, string][] = [["path", q(path)]];
    if (nm.symbol) pairs.push(["symbol", q(String(nm.symbol))]);
    const a = anchorLine(appDir, { id: nm.id, symbol: nm.symbol }, path);
    if (a) {
      const range: [number, number] = [a.line, bodyEnd(appDir, path, a.line, boundaries)];
      if (claim(claimed, path, range, String(nm.id))) {
        pairs.push(["lines", `[${range[0]}, ${range[1]}]`]);
      }
    }
    const nmBody = [`  file: ${flowMap(pairs)}`];
    const declared = nm.route ? parseRoute(String(nm.route)).http : null;
    const sameFileAsABug = bugFiles.has(path.replace(/^(?:vuln|safe)\//, ""));
    const guessed = declared?.path || sameFileAsABug ? null : routeFromPath(path);
    // never anchor a near-miss on a route a real bug owns - that would let it
    // steal that bug's findings and turn true positives into false alarms
    const collides = guessed !== null && bugRoutes.has(templatePath(guessed).toLowerCase());
    const nmPath = declared?.path ?? (collides ? null : guessed);
    if (nmPath) {
      const hp: [string, string][] = [];
      if (declared?.method) hp.push(["method", declared.method]);
      hp.push(["path", q(nmPath)]);
      if (declared?.params.length) {
        hp.push(["params", flowSeq(declared.params.map((x) => q(x)))]);
      }
      nmBody.unshift(`  http: ${flowMap(hp)}`);
    }
    blocks.set(String(nm.id), ["    match:", ...nmBody.map((l) => "    " + l)]);
  }

  const res = spliceMatchBlocks(raw, blocks);
  // never write something that stops parsing
  let ok = true;
  let err = "";
  try {
    const reparsed: any = Bun.YAML.parse(res.text);
    if ((reparsed?.vulnerabilities ?? []).length !== vulns.length) {
      ok = false;
      err = "entry count changed";
    }
  } catch (e) {
    ok = false;
    err = (e as Error).message.slice(0, 80);
    if (process.env.DERIVE_DEBUG) {
      writeFileSync(`/tmp/derive-${app}.yaml`, res.text);
      console.error(`\n[debug] wrote /tmp/derive-${app}.yaml - ${(e as Error).message}\n`);
    }
  }
  if (ok && res.text !== raw) stale.push(app);
  if (ok && write) writeFileSync(gtPath, res.text);

  const anchorable = vulns.filter((v) => bugCount.has(String(v.variant_paths?.vuln ?? ""))).length;
  totalNoLines += Math.max(0, anchorable - withLines);
  rows.push([
    app,
    String(vulns.length),
    String(http),
    String(file),
    `${withLines}`,
    String(markers),
    [...sources.entries()].filter(([k]) => k !== "-").map(([k, n]) => `${k}:${n}`).join(" "),
    ok ? (write ? "written" : res.text === raw ? "current" : "STALE") : `FAILED ${err}`,
  ]);
}

const head = ["APP", "VULNS", "HTTP", "FILE", "LINES", "MARKERS", "LINE SOURCE", "STATUS"];
const widths = head.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)));
console.log(head.map((h, i) => h.padEnd(widths[i]!)).join("  "));
for (const r of rows) console.log(r.map((c, i) => (c ?? "").padEnd(widths[i]!)).join("  "));
console.log(
  `\n${rows.reduce((s, r) => s + Number(r[4]), 0)} entries got a line range; ${totalNoLines} fall back to symbol matching.`,
);
if (checkOnly) {
  if (stale.length) {
    console.error(
      `\n!! ${stale.length} answer key(s) have stale match: anchors - ${stale.join(", ")}\n` +
        `   a source edit moved lines the anchors point at; regenerate:\n` +
        `   bun dynast-bench/tools/derive-match.ts --all --write`,
    );
    process.exit(1);
  }
  console.log("all match: anchors are current.");
} else if (!write) {
  console.log(stale.length ? "re-run with --write to apply." : "nothing to change.");
}
