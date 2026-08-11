/**
 * Scorer unit tests. Each case pins ONE rule, so a failure names the rule that
 * broke rather than "the score changed".
 */

import { describe, expect, test } from "bun:test";

import { bestCweCredit, cweCredit, cweFamily, normalizeCwe } from "../src/schema/cwe.ts";
import { fileKey, fileMatches, parseRoute, pathGlobMatches, symbolMatches, templatePath } from "../src/schema/keys.ts";
import { validateFindings } from "../src/schema/findings.ts";
import { validateGroundTruth } from "../src/schema/ground-truth.ts";
import { scoreApp } from "../src/scorer/score.ts";
import { envelope, loadGt } from "./helpers.ts";

// ------------------------------------------------------------------- keys ----

describe("path templating", () => {
  test("identifier segments collapse to {id}", () => {
    expect(templatePath("/api/posts/7")).toBe("/api/posts/{id}");
    expect(templatePath("/api/posts/9f8a7b6c-1234-4321-8888-0123456789ab")).toBe("/api/posts/{id}");
    expect(templatePath("/api/posts/{id}")).toBe("/api/posts/{id}");
    expect(templatePath("/api/posts/:id")).toBe("/api/posts/{id}");
  });

  test("case and trailing slash survive - weirdproxy plants those as distinct bugs", () => {
    expect(templatePath("/admin/")).toBe("/admin/");
    expect(templatePath("/ADMIN")).toBe("/ADMIN");
    expect(pathGlobMatches("/admin", "/admin/")).toBe(false);
    expect(pathGlobMatches("/admin", "/ADMIN")).toBe(false);
    expect(pathGlobMatches("/admin", "/ADMIN", true)).toBe(true); // loose pass only
  });

  test("percent-encoding survives", () => {
    expect(pathGlobMatches("/admin%2f", "/admin/")).toBe(false);
  });

  test("globs in an answer key match", () => {
    expect(pathGlobMatches("/_next/static/chunks/*.js.map", "/_next/static/chunks/main.js.map")).toBe(true);
    expect(pathGlobMatches("/_next/static/chunks/*.js.map", "/other/main.js.map")).toBe(false);
  });
});

describe("route parsing", () => {
  test("verb, path, injectable param", () => {
    const r = parseRoute("GET /api/posts/search?q=");
    expect(r.http?.method).toBe("GET");
    expect(r.http?.path).toBe("/api/posts/search");
    expect(r.http?.params).toEqual(["q"]);
  });

  test("a query value is a required pair, not a param", () => {
    const r = parseRoute("GET /wp-admin/admin-ajax.php?action=bench_upload");
    expect(r.http?.query).toEqual({ action: "bench_upload" });
    expect(r.http?.params).toEqual([]);
  });

  test("prose annotations are dropped", () => {
    expect(parseRoute("GET /api/admin/users (header: x-middleware-subrequest)").http?.path).toBe(
      "/api/admin/users",
    );
    expect(parseRoute("POST /graphql { __schema }").http?.path).toBe("/graphql");
    expect(parseRoute("GET /posts/{id}").http?.path).toBe("/posts/{id}");
  });

  test("host:port/proto is a net anchor", () => {
    const r = parseRoute("edge-proxy:443/tcp");
    expect(r.http).toBeNull();
    expect(r.net).toEqual({ host: "edge-proxy", port: 443, proto: "tcp" });
  });

  test("a sidecar URL keeps its port", () => {
    expect(parseRoute("http://127.0.0.1:13313").http?.port).toBe(13313);
  });

  test("either-verb routes pin no verb", () => {
    expect(parseRoute("GET/POST /export.php?format=").http?.method).toBeNull();
  });
});

describe("file + symbol comparison", () => {
  test("variant prefix and repo prefix are stripped", () => {
    expect(fileKey("vuln/src/app.ts")).toBe("src/app.ts");
    expect(fileKey("/repo/vulnerable-apps/nextjs/safe/src/app.ts")).toBe("src/app.ts");
    expect(fileMatches("vuln/src/lib/merge.ts", "safe/src/lib/merge.ts")).toBe(true);
    expect(fileMatches("vuln/src/lib/merge.ts", "src/lib/other.ts")).toBe(false);
  });

  test("symbols compare loosely but not wildly", () => {
    expect(symbolMatches("GET", "GET (empty-q branch)")).toBe(true);
    expect(symbolMatches("AuthController@login", "AuthController.login")).toBe(true);
    expect(symbolMatches("deepMerge", "safeApplySettings")).toBe(false);
  });
});

// -------------------------------------------------------------------- cwe ----

describe("cwe credit", () => {
  test("normalizes any spelling", () => {
    expect(normalizeCwe("cwe-89")).toBe("CWE-89");
    expect(normalizeCwe(89)).toBe("CWE-89");
    expect(normalizeCwe("A03:2021-Injection")).toBeNull();
  });

  test("exact 1.0, family 0.5, generic 0.25, unrelated 0", () => {
    expect(cweCredit("CWE-89", "CWE-89").weight).toBe(1);
    expect(cweCredit("CWE-639", "CWE-862").weight).toBe(0.5); // both authz
    expect(cweCredit("CWE-20", "CWE-89").weight).toBe(0.25); // generic parent
    expect(cweCredit("CWE-327", "CWE-601").weight).toBe(0); // crypto vs redirect
  });

  test("declared aliases count as exact", () => {
    expect(cweCredit("CWE-943", "CWE-89", { aliases: ["CWE-943"] }).kind).toBe("alias");
  });

  test("best-of across alternates", () => {
    expect(bestCweCredit(["CWE-327", "CWE-89"], "CWE-89").weight).toBe(1);
  });

  test("every family member resolves to its family", () => {
    expect(cweFamily("CWE-89")).toBe("sqli");
    expect(cweFamily("CWE-1427")).toBe("prompt-injection");
    expect(cweFamily("CWE-99999")).toBeNull();
  });
});

// --------------------------------------------------------------- validation --

describe("findings validation", () => {
  test("a finding with no location is unscoreable", () => {
    const res = validateFindings({ findings: [{ id: "x", cwe: "CWE-89" }] });
    expect(res.ok).toBe(false);
    expect(res.errors[0]?.msg).toContain("no usable location");
  });

  test("flat fields are lifted, severities and CWEs coerced", () => {
    const res = validateFindings({
      findings: [{ id: "x", cwe: 89, severity: "High", url: "http://h/p?q=1", param: "q" }],
    });
    expect(res.ok).toBe(true);
    const f = res.value!.findings[0]!;
    expect(f.cwe).toBe("CWE-89");
    expect(f.severity).toBe("high");
    expect(f.location.http?.param).toBe("q");
  });

  test("a bad variant is an error, a missing one a loud warning", () => {
    expect(validateFindings({ run: { variant: "prod" }, findings: [] }).ok).toBe(false);
    const res = validateFindings({ findings: [] });
    expect(res.value!.run.variant).toBe("vuln");
    expect(res.warnings.some((w) => w.at === "run.variant")).toBe(true);
  });

  test("duplicate ids are renamed, not merged", () => {
    const res = validateFindings({
      findings: [
        { id: "a", location: { http: { path: "/x" } } },
        { id: "a", location: { http: { path: "/y" } } },
      ],
    });
    expect(res.value!.findings.map((f) => f.id)).toEqual(["a", "a#2"]);
  });
});

describe("ground-truth validation", () => {
  test("a dangling near_miss reference is an error", () => {
    const res = validateGroundTruth({
      app: "t",
      vulnerabilities: [
        {
          id: "SQLI-001",
          cwe: "CWE-89",
          severity: "high",
          difficulty: "E",
          route: "GET /x",
          near_miss: "NM-NOPE",
        },
      ],
      near_misses: [],
    });
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.msg.includes("NM-NOPE"))).toBe(true);
  });

  test("an entry with neither route nor paths has nothing to anchor to", () => {
    const res = validateGroundTruth({
      app: "t",
      vulnerabilities: [{ id: "X-001", cwe: "CWE-89", severity: "high", difficulty: "E" }],
    });
    expect(res.errors.some((e) => e.msg.includes("nothing to anchor"))).toBe(true);
  });

  test("a discovery tier outside the vocabulary is an error", () => {
    const res = validateGroundTruth({
      app: "t",
      vulnerabilities: [
        {
          id: "X-001",
          cwe: "CWE-89",
          severity: "high",
          difficulty: "E",
          discovery: "needs-a-browser",
          route: "GET /x",
        },
      ],
    });
    expect(res.ok).toBe(false);
    expect(res.errors.some((e) => e.at === "vulnerabilities[0].discovery")).toBe(true);
  });
});

describe("alternate http anchors", () => {
  const key = {
    app: "t",
    entry: "http://127.0.0.1:13311",
    vulnerabilities: [
      {
        id: "DOCS-001",
        cwe: "CWE-200",
        severity: "medium",
        difficulty: "E",
        route: "GET /api/schema/ and /api/docs/",
        match: { http: { method: "GET", path: "/api/schema/" }, http_alt: ["/api/docs/"] },
      },
    ],
    near_misses: [],
  };
  const at = (path: string) =>
    scoreApp({
      app: "t",
      groundTruth: validateGroundTruth(key).value!,
      runs: [
        envelope("t", [
          { id: "f", cwe: "CWE-200", severity: "medium", location: { http: { method: "GET", path } } } as any,
        ]),
      ],
    });

  test("either path a route names is the correct answer", () => {
    // /api/docs/ is the Swagger UI - the URL a crawler actually finds. Scoring
    // it as a miss AND a false positive charged the tool twice for being right.
    expect(at("/api/schema/").counts.tp).toBe(1);
    expect(at("/api/docs/").counts.tp).toBe(1);
  });

  test("a path the key never named is still a false positive", () => {
    expect(at("/api/elsewhere/").counts.tp).toBe(0);
    expect(at("/api/elsewhere/").counts.fp).toBe(1);
  });

  test("an alternate with no primary anchor is a key error", () => {
    const res = validateGroundTruth({
      app: "t",
      vulnerabilities: [
        { id: "X-001", cwe: "CWE-200", severity: "medium", difficulty: "E", route: "GET /x",
          match: { http_alt: ["/y"] } },
      ],
    });
    expect(res.errors.some((e) => e.at.endsWith("http_alt"))).toBe(true);
  });

  test("an alternate that is not a path is a key error", () => {
    const res = validateGroundTruth({
      app: "t",
      vulnerabilities: [
        { id: "X-001", cwe: "CWE-200", severity: "medium", difficulty: "E", route: "GET /x",
          match: { http: { path: "/x" }, http_alt: ["docs"] } },
      ],
    });
    expect(res.errors.some((e) => e.at.endsWith("http_alt"))).toBe(true);
  });
});

describe("websocket channel discrimination", () => {
  const gt = validateGroundTruth({
    app: "t",
    entry: "http://127.0.0.1:13311",
    vulnerabilities: ["org:globex:posts", "internal:billing"].map((channel, i) => ({
      id: `CHAN-00${i + 1}`,
      cwe: "CWE-639",
      severity: "high",
      difficulty: "M",
      route: "WS /ws",
      match: { ws: { transport: "ws", event: "subscribe", channel } },
    })),
    near_misses: [],
  }).value!;
  const report = (ws: any) =>
    scoreApp({
      app: "t",
      groundTruth: gt,
      runs: [envelope("t", [{ id: "f", cwe: "CWE-639", severity: "high", location: { ws } } as any])],
    });

  test("the channel survives validation", () => {
    const res = validateFindings({
      findings: [{ id: "x", cwe: "CWE-639", location: { ws: { transport: "ws", channel: "org:*" } } }],
    });
    expect(res.value!.findings[0]!.location.ws?.channel).toBe("org:*");
  });

  test("naming the channel picks out the one bug on that frame", () => {
    const r = report({ transport: "ws", event: "subscribe", channel: "internal:billing" });
    expect(r.matches.map((m) => m.gt_id)).toEqual(["CHAN-002"]);
  });

  test("a channel the key never names is a false positive", () => {
    // dropping `channel` in coercion made this score as a true positive
    expect(report({ transport: "ws", event: "subscribe", channel: "totally:bogus" }).counts.tp).toBe(0);
  });

  test("'subscribe frames are unauthenticated' identifies neither bug", () => {
    expect(report({ transport: "ws", event: "subscribe" }).counts.tp).toBe(0);
  });
});

describe("recall by discovery tier", () => {
  const key = (tiers: (string | undefined)[]) => ({
    app: "t",
    entry: "http://127.0.0.1:13311",
    vulnerabilities: tiers.map((discovery, i) => ({
      id: `BUG-00${i + 1}`,
      cwe: "CWE-89",
      severity: "high",
      difficulty: "E",
      ...(discovery ? { discovery } : {}),
      route: `GET /bug${i + 1}`,
      match: { http: { method: "GET", path: `/bug${i + 1}` } },
    })),
    near_misses: [],
  });
  /** a tool that found only /bug1 */
  const run = envelope("t", [
    {
      id: "f1",
      title: "sqli",
      cwe: "CWE-89",
      severity: "high",
      location: { http: { method: "GET", path: "/bug1" } },
    } as any,
  ]);

  test("splits recall across the tiers a key declares", () => {
    const gt = validateGroundTruth(key(["static-html", "js-runtime", "flow"])).value!;
    const r = scoreApp({ app: "t", groundTruth: gt, runs: [run] });
    expect(r.by_discovery["static-html"]).toEqual({ gt: 1, tp: 1, recall: 1 });
    expect(r.by_discovery["js-runtime"]).toEqual({ gt: 1, tp: 0, recall: 0 });
    expect(r.by_discovery["flow"]).toEqual({ gt: 1, tp: 0, recall: 0 });
  });

  test("orders tiers cheapest-crawl first, not alphabetically", () => {
    const gt = validateGroundTruth(key(["flow", "static-html", "interaction"])).value!;
    const r = scoreApp({ app: "t", groundTruth: gt, runs: [run] });
    expect(Object.keys(r.by_discovery)).toEqual(["static-html", "interaction", "flow"]);
  });

  test("an untiered key reports nothing rather than one all-unknown bucket", () => {
    const gt = validateGroundTruth(key([undefined, undefined])).value!;
    const r = scoreApp({ app: "t", groundTruth: gt, runs: [run] });
    expect(r.by_discovery).toEqual({});
  });
});

// ------------------------------------------------------------- the matcher ---

describe("classification (nextjs answer key)", () => {
  const gt = loadGt("nextjs");
  const score = (findings: any[], safe: any[] = []) =>
    scoreApp({
      app: "nextjs",
      groundTruth: gt,
      runs: [
        envelope("nextjs", findings),
        ...(safe.length ? [envelope("nextjs", safe, "safe")] : []),
      ],
    });

  const sqli = (id: string, extra: any = {}) => ({
    id,
    cwe: "CWE-89",
    severity: "high",
    location: { http: { method: "GET", path: "/api/posts/search", param: "q" } },
    ...extra,
  });

  test("a marker match beats every other tier", () => {
    const r = score([
      sqli("m1", { evidence: { markers: ["GLOBEX-CONFIDENTIAL-MARKER-7f3a"] } }),
    ]);
    expect(r.matches[0]!.tier).toBe("proof");
  });

  test("repeat findings on one bug are noise, not false positives", () => {
    const r = score([sqli("a"), sqli("b"), sqli("c")]);
    expect(r.counts.tp).toBe(1);
    expect(r.counts.duplicates).toBe(2);
    expect(r.counts.fp).toBe(0);
    expect(r.metrics.precision).toBe(1);
    expect(r.metrics.noise_ratio).toBeCloseTo(2 / 3, 3);
  });

  test("a near-miss with its own route is a false positive and costs discrimination", () => {
    // NM-FETCH-001: /api/preview-internal fetches a fixed allow-listed URL.
    // Flagging it as SSRF is the classic false alarm the near-misses exist for.
    const r = score([
      {
        id: "nm",
        cwe: "CWE-918",
        severity: "high",
        location: { http: { method: "GET", path: "/api/preview-internal" } },
      },
    ]);
    expect(r.counts.tp).toBe(0);
    expect(r.counts.fp_near_miss).toBe(1);
    expect(r.false_positives[0]!.hit).toBe("NM-FETCH-001");
    expect(r.metrics.discrimination).toBeCloseTo(1 - 1 / gt.near_misses.length, 3);
  });

  test("a near-miss pinned by line beats a weak claim on the bug next door", () => {
    // merge.ts holds deepMerge (PROTO-001, lines 4-18) and safeApplySettings
    // (NM-MERGE-001, lines 19-25). A finding at line 20 is the SAFE one.
    const r = score([
      { id: "nm2", cwe: "CWE-1321", location: { file: { path: "vuln/src/lib/merge.ts", line: 20 } } },
    ]);
    expect(r.counts.fp_near_miss).toBe(1);
    expect(r.matches.find((m) => m.gt_id === "PROTO-001")).toBeUndefined();
  });

  test("the same finding on the vulnerable function IS the bug", () => {
    const r = score([
      { id: "ok", cwe: "CWE-1321", location: { file: { path: "vuln/src/lib/merge.ts", line: 8 } } },
    ]);
    expect(r.matches.map((m) => m.gt_id)).toEqual(["PROTO-001"]);
    expect(r.counts.fp_near_miss).toBe(0);
  });

  test("a sibling CWE still finds the bug, at half classification credit", () => {
    const r = score([
      { id: "c1", cwe: "CWE-862", location: { http: { method: "GET", path: "/api/posts/7" } } },
    ]);
    expect(r.matches.map((m) => m.gt_id)).toEqual(["IDOR-001"]);
    expect(r.matches[0]!.cwe_credit).toBe(0.5);
    expect(r.metrics.recall_exact_cwe).toBe(0);
  });

  test("an unrelated CWE on a real route is a wrong answer, not a hit", () => {
    const r = score([
      { id: "d1", cwe: "CWE-327", location: { http: { method: "GET", path: "/goto", param: "next" } } },
    ]);
    expect(r.counts.tp).toBe(0);
    expect(r.counts.fp_other).toBe(1);
    expect(r.misses.find((m) => m.gt_id === "REDIRECT-001")).toBeDefined();
  });

  test("no CWE at all still earns the bug, with zero credit", () => {
    const r = score([
      { id: "n1", location: { http: { method: "GET", path: "/goto", param: "next" } } },
    ]);
    expect(r.matches.map((m) => m.gt_id)).toEqual(["REDIRECT-001"]);
    expect(r.matches[0]!.cwe_credit).toBe(0);
  });

  test("everything on the patched twin is a false alarm", () => {
    const r = score([], [sqli("s1")]);
    expect(r.counts.tp).toBe(0);
    expect(r.counts.fp_fixed_bug).toBe(1);
    expect(r.false_positives[0]!.hit).toBe("SQLI-001");
    expect(r.metrics.precision).toBe(0);
  });

  test("scoring a safe-only run says recall is meaningless", () => {
    const r = scoreApp({
      app: "nextjs",
      groundTruth: gt,
      runs: [envelope("nextjs", [sqli("s1")], "safe")],
    });
    expect(r.warnings.some((w) => w.includes("no vuln-variant run"))).toBe(true);
  });

  test("a closed port is an observation, not a false positive", () => {
    const r = score([
      { id: "p1", location: { net: { host: "edge", port: 31337, proto: "tcp", state: "closed" } } },
    ]);
    expect(r.counts.fp).toBe(0);
    expect(r.counts.informational).toBe(1);
  });

  test("one finding cannot take two bugs", () => {
    // SECRET-002 and CREDS-BUNDLE-001 share a file; two findings, two bugs
    const r = score([
      {
        id: "s2",
        cwe: "CWE-798",
        location: { file: { path: "vuln/src/lib/integrations.ts", symbol: "OBJECT_STORE_KEY_B64" } },
      },
      {
        id: "s3",
        cwe: "CWE-522",
        location: { file: { path: "vuln/src/lib/integrations.ts", symbol: "SYNC_BASIC_AUTH" } },
      },
    ]);
    expect(r.counts.tp).toBe(2);
    expect(new Set(r.matches.map((m) => m.gt_id)).size).toBe(2);
  });

  test("precision, recall and f1 agree with the counts", () => {
    const r = score([
      sqli("a"),
      { id: "junk", cwe: "CWE-79", location: { http: { method: "GET", path: "/nope", param: "x" } } },
    ]);
    expect(r.metrics.precision).toBeCloseTo(1 / 2, 3);
    expect(r.metrics.recall).toBeCloseTo(1 / gt.vulnerabilities.length, 3);
    const p = r.metrics.precision!;
    const rc = r.metrics.recall!;
    expect(r.metrics.f1).toBeCloseTo((2 * p * rc) / (p + rc), 4);
  });
});
