/**
 * Endpoint-coverage tests.
 *
 * Two layers, matching the two ways this metric can go quietly wrong:
 *
 *  1. Identity - does `opMatches` agree with the catalog about what "the same
 *     endpoint" means? A disagreement here does not throw; it just returns a
 *     number that is too low, forever, for every tool.
 *  2. Arithmetic - does a missing trace read as "not measured" rather than as
 *     "reached nothing"? Those are opposite claims about a tool and the
 *     difference has to be structural, not a rendering convention.
 */

import { describe, expect, test } from "bun:test";

import { validateEndpoints, endpointsFromFindings } from "../src/schema/endpoints.ts";
import { opKey, opMatches, refKind } from "../src/schema/operations.ts";
import { validateSurface } from "../src/schema/surface.ts";
import type { Surface, SurfaceOperation } from "../src/schema/types.ts";
import { gtAnchors, isSourceOnly } from "../src/scorer/anchors.ts";
import { coverageTrack } from "../src/scorer/coverage.ts";
import { scoreApp } from "../src/scorer/score.ts";
import { appNames, envelope, loadGt, loadSurface, perfectTrace } from "./helpers.ts";

const op = (o: Partial<SurfaceOperation>): SurfaceOperation =>
  ({ id: o.id ?? "x", kind: "http", ...o }) as SurfaceOperation;

const surfaceOf = (ops: SurfaceOperation[]): Surface => ({ app: "t", operations: ops });

// ----------------------------------------------------------------- identity --

describe("operation identity", () => {
  test("method separates two operations on one path", () => {
    const get = op({ method: "GET", path: "/a" });
    expect(opMatches(get, { method: "GET", path: "/a" })).toBe("strict");
    expect(opMatches(get, { method: "POST", path: "/a" })).toBeNull();
  });

  test("a catalog entry with no method is reached by any verb", () => {
    const any = op({ path: "/a" });
    expect(opMatches(any, { method: "DELETE", path: "/a" })).toBe("strict");
  });

  test("an unstated verb against a pinned one is a loose hit, not a miss", () => {
    // credited, but flagged - the tool never said what it sent
    expect(opMatches(op({ method: "POST", path: "/a" }), { path: "/a" })).toBe("loose");
  });

  test("concrete ids template onto the catalog's placeholder", () => {
    const o = op({ method: "GET", path: "/api/posts/{id}" });
    expect(opMatches(o, { method: "GET", path: "/api/posts/7" })).toBe("strict");
    expect(opMatches(o, { method: "GET", path: "/api/posts/c0ffee00deadbeef12345678" })).toBe("strict");
  });

  test("case and trailing slash survive the strict pass (weirdproxy plants both)", () => {
    const admin = op({ method: "GET", path: "/admin/" });
    expect(opMatches(admin, { method: "GET", path: "/ADMIN" })).toBe("loose");
    expect(opMatches(op({ method: "GET", path: "/admin%2f" }), { method: "GET", path: "/admin/" }))
      .toBeNull();
  });

  test("a required query discriminator must be present", () => {
    const upload = op({ method: "POST", path: "/wp-admin/admin-ajax.php", query: { action: "bench_upload" } });
    expect(opMatches(upload, { method: "POST", path: "/wp-admin/admin-ajax.php" })).toBeNull();
    expect(opMatches(upload, { method: "POST", url: "/wp-admin/admin-ajax.php?action=bench_upload" }))
      .toBe("strict");
    expect(opMatches(upload, { method: "POST", path: "/wp-admin/admin-ajax.php", query: { action: "other" } }))
      .toBeNull();
  });

  test("ordinary parameter values do not create separate endpoints", () => {
    const search = op({ method: "GET", path: "/api/posts/search", params: ["q"] });
    expect(opMatches(search, { method: "GET", url: "/api/posts/search?q=anything" })).toBe("strict");
    expect(opMatches(search, { method: "GET", url: "/api/posts/search?q=else" })).toBe("strict");
  });

  test("a graphql POST does not touch every graphql operation", () => {
    const transport = op({ id: "t", kind: "http", method: "POST", path: "/graphql" });
    const posts = op({ id: "p", kind: "graphql", op: "posts", graphql_kind: "query" });
    expect(opMatches(transport, { method: "POST", path: "/graphql" })).toBe("strict");
    expect(opMatches(posts, { method: "POST", path: "/graphql" })).toBeNull();
    expect(opMatches(posts, { kind: "graphql", op: "posts" })).toBe("strict");
  });

  test("graphql kind separates a query from a mutation of the same name", () => {
    const mut = op({ kind: "graphql", op: "updatePost", graphql_kind: "mutation" });
    expect(opMatches(mut, { kind: "graphql", op: "updatePost", graphql_kind: "query" })).toBeNull();
    expect(opMatches(mut, { kind: "graphql", op: "updatePost", graphql_kind: "mutation" })).toBe("strict");
  });

  test("a websocket handshake does not touch every message event", () => {
    const handshake = op({ id: "h", kind: "ws", endpoint: "/ws" });
    const del = op({ id: "d", kind: "ws", endpoint: "/ws", event: "admin.userDelete" });
    expect(opMatches(handshake, { kind: "ws", endpoint: "/ws" })).toBe("strict");
    expect(opMatches(del, { kind: "ws", endpoint: "/ws" })).toBeNull();
    expect(opMatches(del, { kind: "ws", endpoint: "/ws", event: "admin.userDelete" })).toBe("strict");
    // and connecting is not the same as sending
    expect(opMatches(handshake, { kind: "ws", endpoint: "/ws", event: "admin.userDelete" })).toBeNull();
  });

  test("a channel pins a subscribe frame to one room", () => {
    const sub = op({ kind: "ws", endpoint: "/ws", event: "subscribe", channel: "org:globex:posts" });
    expect(opMatches(sub, { kind: "ws", event: "subscribe" })).toBeNull();
    expect(opMatches(sub, { kind: "ws", event: "subscribe", channel: "org:globex:posts" })).toBe("loose");
  });

  test("an agent run endpoint does not exercise every tool", () => {
    const shell = op({ kind: "llm", tool: "run_shell" });
    expect(opMatches(shell, { method: "POST", path: "/api/runs" })).toBeNull();
    expect(opMatches(shell, { kind: "llm", tool: "run_shell" })).toBe("strict");
    // cosmetic naming differences still land, as a loose hit
    expect(opMatches(shell, { kind: "llm", tool: "runShell" })).toBe("loose");
  });

  test("net identity is host, port and protocol", () => {
    const redis = op({ kind: "net", host: "cache", port: 6379, proto: "tcp" });
    expect(opMatches(redis, { kind: "net", host: "cache", port: 6379, proto: "tcp" })).toBe("strict");
    expect(opMatches(redis, { kind: "net", host: "cache", port: 6379, proto: "udp" })).toBeNull();
    expect(opMatches(redis, { kind: "net", host: "other", port: 6379 })).toBeNull();
  });

  test("a sidecar port is only reached on its own port", () => {
    const jenkins = op({ method: "GET", path: "/", port: 13315 });
    expect(opMatches(jenkins, { method: "GET", path: "/", port: 13316 })).toBeNull();
    expect(opMatches(jenkins, { method: "GET", path: "/", port: 13315 })).toBe("strict");
  });

  test("opKey is stable and distinguishes what opMatches distinguishes", () => {
    expect(opKey(op({ method: "GET", path: "/api/posts/7" }))).toBe("GET /api/posts/{id}");
    expect(opKey(op({ kind: "graphql", op: "posts", graphql_kind: "query" }))).toBe("graphql query.posts");
    expect(opKey(op({ kind: "ws", endpoint: "/ws", event: "x" }))).toBe("ws /ws x");
    expect(opKey(op({ kind: "net", host: "h", port: 22, proto: "tcp" }))).toBe("net h:22/tcp");
  });
});

// --------------------------------------------------------------- arithmetic --

describe("coverage arithmetic", () => {
  const base = surfaceOf([
    op({ id: "a", method: "GET", path: "/a", discovery: "static-html", vulns: ["V1"] }),
    op({ id: "b", method: "GET", path: "/b", discovery: "js-runtime", vulns: ["V2"] }),
    op({ id: "c", method: "GET", path: "/c", discovery: "js-runtime" }),
  ]);

  test("an empty expected set is null, not a division by zero", () => {
    const t = coverageTrack({ surface: surfaceOf([]), reported: [], evidenceSource: "reported" });
    expect(t.operations.coverage).toBeNull();
    expect(t.precision).toBeNull();
  });

  test("duplicate observations count once", () => {
    const t = coverageTrack({
      surface: base,
      reported: [{ path: "/a" }, { path: "/a" }, { path: "/a" }],
      evidenceSource: "reported",
    });
    expect(t.operations.touched).toBe(1);
  });

  test("unknown observations do not reduce coverage, only precision", () => {
    const t = coverageTrack({
      surface: base,
      reported: [{ path: "/a" }, { path: "/nope" }],
      evidenceSource: "reported",
    });
    expect(t.operations.touched).toBe(1);
    expect(t.operations.coverage).toBeCloseTo(1 / 3);
    expect(t.unknown).toEqual(["ANY /nope"]);
    expect(t.precision).toBe(0.5);
  });

  test("vulnerable and benign operations are counted separately", () => {
    const t = coverageTrack({ surface: base, reported: [{ path: "/c" }], evidenceSource: "reported" });
    expect(t.vulnerable_operations).toMatchObject({ expected: 2, touched: 0 });
    expect(t.benign_operations).toMatchObject({ expected: 1, touched: 1 });
  });

  test("an operation the safe twin removes is not expected there", () => {
    const s = surfaceOf([
      op({ id: "gone", method: "GET", path: "/legacy", variant: "vuln", discovery: "static-html" }),
      op({ id: "kept", method: "GET", path: "/a", discovery: "static-html" }),
    ]);
    expect(coverageTrack({ surface: s, reported: [], evidenceSource: "reported", variant: "vuln" })
      .operations.expected).toBe(2);
    expect(coverageTrack({ surface: s, reported: [], evidenceSource: "reported", variant: "safe" })
      .operations.expected).toBe(1);
  });

  test("a miss splits into discovery vs analysis by whether the operation was reached", () => {
    const vulns = [{ id: "V1" }, { id: "V2" }] as any;
    const t = coverageTrack({
      surface: base,
      reported: [{ path: "/a" }], // reached V1's operation, not V2's
      evidenceSource: "reported",
      vulns,
      foundVulnIds: new Set<string>(), // found neither
    });
    expect(t.analysis_misses).toEqual(["V1"]); // reached it, did not report
    expect(t.discovery_misses).toEqual(["V2"]); // never got there
    expect(t.detection_given_touch).toBe(0);
  });

  test("detection_given_touch grades only the part of the app that was reached", () => {
    const t = coverageTrack({
      surface: base,
      reported: [{ path: "/a" }],
      evidenceSource: "reported",
      vulns: [{ id: "V1" }, { id: "V2" }] as any,
      foundVulnIds: new Set(["V1"]),
    });
    // 1 of 1 bug on a touched operation, even though overall recall is 1/2
    expect(t.detection_given_touch).toBe(1);
    expect(t.discovery_misses).toEqual(["V2"]);
    expect(t.analysis_misses).toEqual([]);
  });

  test("with no findings supplied the miss split is not invented", () => {
    const t = coverageTrack({ surface: base, reported: [{ path: "/a" }], evidenceSource: "reported" });
    expect(t.detection_given_touch).toBeNull();
    expect(t.discovery_misses).toEqual([]);
    expect(t.analysis_misses).toEqual([]);
  });

  test("a bug on no cataloged operation is excluded, not silently counted as found", () => {
    const t = coverageTrack({
      surface: base,
      reported: [{ path: "/a" }],
      evidenceSource: "reported",
      vulns: [{ id: "V1" }, { id: "V9" }] as any,
      foundVulnIds: new Set<string>(),
    });
    expect(t.unmapped_vulns).toEqual(["V9"]);
    expect(t.discovery_misses).toEqual([]);
    expect(t.warnings.some((w) => w.includes("no SURFACE.yaml operation"))).toBe(true);
  });

  test("a loose-only hit is credited but reported as loose", () => {
    const s = surfaceOf([op({ id: "a", method: "POST", path: "/a", discovery: "static-html" })]);
    const t = coverageTrack({ surface: s, reported: [{ path: "/a" }], evidenceSource: "reported" });
    expect(t.operations.touched).toBe(1);
    expect(t.loose_hits).toBe(1);
    expect(t.warnings.some((w) => w.includes("loose pass"))).toBe(true);
  });

  test("findings-derived evidence is labelled as a floor", () => {
    const t = coverageTrack({ surface: base, reported: [{ path: "/a" }], evidenceSource: "findings" });
    expect(t.evidence_source).toBe("findings");
    expect(t.warnings.some((w) => w.includes("floor, not a measurement"))).toBe(true);
  });
});

describe("score integration", () => {
  const gtStub = { vulnerabilities: [], near_misses: [] } as any;

  test("no trace means no coverage track, never a zero", () => {
    const r = scoreApp({ app: "t", groundTruth: gtStub, runs: [envelope("t", [])] });
    expect(r.tracks.coverage).toBeNull();
  });

  test("a trace with no catalog is also no track", () => {
    const r = scoreApp({
      app: "t",
      groundTruth: gtStub,
      runs: [envelope("t", [])],
      endpoints: [{ path: "/a" }],
    });
    expect(r.tracks.coverage).toBeNull();
  });

  test("an empty trace against a real catalog is a genuine zero", () => {
    const r = scoreApp({
      app: "t",
      groundTruth: gtStub,
      runs: [envelope("t", [])],
      surface: surfaceOf([op({ id: "a", path: "/a", discovery: "static-html" })]),
      endpoints: [],
    });
    expect(r.tracks.coverage?.operations.coverage).toBe(0);
  });
});

// ---------------------------------------------------------------- the files --

describe("endpoints/v1", () => {
  const read = (doc: unknown) => validateEndpoints(doc).value!.endpoints;

  test("a bare array of strings is accepted", () => {
    const eps = read(["GET /a", "POST /b", "http://127.0.0.1:13311/c?q="]);
    expect(eps).toHaveLength(3);
    expect(eps[0]).toMatchObject({ method: "GET", path: "/a" });
    expect(refKind(eps[2]!)).toBe("http");
  });

  test("protocol-tagged strings parse to the right kind", () => {
    expect(read(["graphql mutation.updatePost"])[0]).toMatchObject({
      kind: "graphql",
      graphql_kind: "mutation",
      op: "updatePost",
    });
    expect(read(["ws /ws post.search"])[0]).toMatchObject({ kind: "ws", endpoint: "/ws", event: "post.search" });
    expect(read(["llm run_shell"])[0]).toMatchObject({ kind: "llm", tool: "run_shell" });
    expect(read(["db:5432/tcp"])[0]).toMatchObject({ kind: "net", port: 5432, proto: "tcp" });
  });

  test("a findings-style nested location is lifted", () => {
    expect(read([{ location: { http: { method: "get", path: "/a" } } }])[0]).toMatchObject({
      method: "GET",
      path: "/a",
    });
  });

  test("an entry identifying nothing is dropped with a warning, not counted", () => {
    const res = validateEndpoints({ endpoints: [{ note: "I looked around" }, "GET /a"] });
    expect(res.value!.endpoints).toHaveLength(1);
    expect(res.warnings.some((w) => w.msg.includes("identifies no operation"))).toBe(true);
  });

  test("a safe-twin trace must say so", () => {
    expect(validateEndpoints({ run: { variant: "nonsense" }, endpoints: [] }).ok).toBe(false);
  });

  test("endpointsFromFindings only reports where a bug was filed", () => {
    const f = envelope("t", [
      { id: "1", location: { http: { method: "GET", path: "/a" } } },
      { id: "2", location: { file: { path: "src/x.ts", line: 3 } } },
    ]);
    // the source-only finding contributes no endpoint - that is the floor
    expect(endpointsFromFindings(f)).toEqual([{ kind: "http", method: "GET", path: "/a", url: undefined }]);
  });
});

describe("SURFACE.yaml validation", () => {
  test("two entries with the same identity are rejected", () => {
    const res = validateSurface({
      app: "t",
      operations: [
        { id: "one", kind: "http", method: "GET", path: "/a" },
        { id: "two", kind: "http", method: "GET", path: "/a" },
      ],
    });
    expect(res.ok).toBe(false);
    expect(res.errors[0]!.msg).toContain("identical operation identity");
  });

  test("a partial discovery breakdown is rejected", () => {
    const res = validateSurface({
      app: "t",
      operations: [
        { id: "one", kind: "http", path: "/a", discovery: "static-html" },
        { id: "two", kind: "http", path: "/b" },
      ],
    });
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.msg.includes("no discovery: tier"))).toBe(true);
  });

  test("an unknown discovery tier is an error, not a dropped bucket", () => {
    const res = validateSurface({
      app: "t",
      operations: [{ id: "one", kind: "http", path: "/a", discovery: "vibes" }],
    });
    expect(res.ok).toBe(false);
  });

  test("via: must resolve", () => {
    const res = validateSurface({
      app: "t",
      operations: [{ id: "one", kind: "graphql", op: "posts", via: "nope" }],
    });
    expect(res.errors.some((e) => e.msg.includes("unknown operation"))).toBe(true);
  });
});

// ------------------------------------------------------------- per-app gate --

const apps = appNames();

describe.each(apps)("%s surface", (app) => {
  const surface = loadSurface(app);

  test("has an endpoint catalog", () => {
    expect(surface, `${app} has no SURFACE.yaml - it is not coverage-scoreable`).not.toBeNull();
  });

  test("a perfect trace scores 100% coverage", () => {
    if (!surface) return;
    const t = coverageTrack({
      surface,
      reported: perfectTrace(surface),
      evidenceSource: "reported",
    });
    expect(t.untouched, `${app}: cataloged but unreachable by its own identity`).toEqual([]);
    expect(t.operations.coverage).toBe(1);
    expect(t.unknown).toEqual([]);
  });

  test("a perfect trace needs no loose matching", () => {
    if (!surface) return;
    // a catalog entry that only its own restatement can reach loosely means the
    // identity is ambiguous - two operations could be sharing a key
    const t = coverageTrack({ surface, reported: perfectTrace(surface), evidenceSource: "reported" });
    expect(t.loose_hits).toBe(0);
  });

  test("an empty trace scores zero, and it is a real zero", () => {
    if (!surface) return;
    const t = coverageTrack({ surface, reported: [], evidenceSource: "reported" });
    expect(t.operations.coverage).toBe(0);
    expect(t.operations.expected).toBeGreaterThan(0);
  });

  test("every reachable bug maps to an operation", () => {
    if (!surface) return;
    const gt = loadGt(app);
    const t = coverageTrack({
      surface,
      reported: [],
      evidenceSource: "reported",
      vulns: gt.vulnerabilities,
      foundVulnIds: new Set(),
    });
    // Source-only entries have no endpoint to reach, so they are exempt - and
    // "source-only" means what the matcher means by it, not what `route:` looks
    // like. golang's SESSION-001 says `route: "Cookie session"`, which is prose
    // describing a cross-cutting weakness, and carries no http anchor at all.
    const reachable = new Set(
      gt.vulnerabilities.filter((v) => !isSourceOnly(gtAnchors(v))).map((v) => v.id),
    );
    expect(t.unmapped_vulns.filter((id) => reachable.has(id))).toEqual([]);
  });

  /**
   * The perfect-trace tests above restate the catalog, so they pass however the
   * catalog spells a path - including in framework syntax no client would ever
   * send. `/uploads/avatars/{name:path}` templates to `/uploads/avatars/{id}`,
   * which only matches id-LOOKING segments, so a real `user1.png` never lands
   * and the operation is uncatchable forever. Check the spelling independently.
   */
  test("no cataloged path uses framework syntax a real request cannot produce", () => {
    if (!surface) return;
    for (const op of surface.operations) {
      // Bare placeholders (`{id}`, `:id`, `<id>`) are fine - templatePath folds
      // both sides. A TYPED converter is not: `{name:path}` folds to `{id}`,
      // which then only matches id-looking segments, never a filename.
      if (!op.path) continue;
      expect(op.path, `${op.id}: typed converter - use a * glob instead`).not.toMatch(
        /\{[^}]*:[^}]*\}/,
      );
    }
  });
});
