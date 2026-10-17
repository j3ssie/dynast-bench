/**
 * Scorer unit tests. Each case pins ONE rule, so a failure names the rule that
 * broke rather than "the score changed".
 */

import { describe, expect, test } from "bun:test";

import { bestCweCredit, cweCredit, cweFamily, normalizeCwe } from "../src/schema/cwe.ts";
import { fileKey, fileMatches, parseRoute, pathGlobMatches, pathMatch, routedPathMatch, routeSteps, splitAlt, symbolMatches, templatePath } from "../src/schema/keys.ts";
import { opMatches, surfaceRoutes } from "../src/schema/operations.ts";
import { validateFindings } from "../src/schema/findings.ts";
import { validateGroundTruth } from "../src/schema/ground-truth.ts";
import { guessCwe } from "../src/normalize/guess.ts";
import { scoreApp } from "../src/scorer/score.ts";
import { extraBreakdowns } from "../src/scorer/tracks.ts";
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

describe("answer-key placeholders", () => {
  // The tool reports what it hit; only the KEY knows a segment is a parameter. A
  // slug or a share token is not id-shaped, so tool-side templating alone can
  // never reach `/api/orgs/{org}/drafts` from `/api/orgs/globex/drafts`.
  test("a key placeholder matches any one concrete segment", () => {
    expect(pathMatch("/api/orgs/{org}/drafts", "/api/orgs/globex/drafts")).toBe("param");
    expect(pathMatch("/api/share/{token}/redeem", "/api/share/q3J-x9_aZ2bV0kLm/redeem")).toBe("param");
    expect(pathMatch("/api/orgs/:org/drafts", "/api/orgs/acme/drafts")).toBe("param");
    expect(pathMatch("/posts/[id]/edit", "/posts/my-first-post/edit")).toBe("param");
  });

  test("an id-shaped segment is still an exact match, and literals still decide", () => {
    expect(pathMatch("/api/exports/{id}/download", "/api/exports/7/download")).toBe("exact");
    expect(pathMatch("/api/orgs/{org}/drafts", "/api/orgs/globex/posts")).toBeNull();
    // one segment, never zero and never two
    expect(pathMatch("/api/orgs/{org}/drafts", "/api/orgs//drafts")).toBeNull();
    expect(pathMatch("/api/orgs/{org}/drafts", "/api/orgs/a/b/drafts")).toBeNull();
    // a literal number in the key is not a placeholder: it still templates as an id
    expect(pathMatch("/api/v1/posts", "/api/v2/posts")).toBeNull();
  });

  test("case and trailing-slash folding stay in the loose pass", () => {
    expect(pathMatch("/api/orgs/{org}/drafts", "/API/orgs/globex/drafts")).toBeNull();
    expect(pathMatch("/api/orgs/{org}/drafts", "/API/orgs/globex/drafts/", true)).toBe("param");
  });

  test("a static route wins over a placeholder (router precedence)", () => {
    const routes = ["/api/posts/search", "/api/posts/{id}"];
    expect(routedPathMatch("/api/posts/{id}", "/api/posts/search", false, routes)).toBeNull();
    expect(routedPathMatch("/api/posts/search", "/api/posts/search", false, routes)).toBe("exact");
    expect(routedPathMatch("/api/posts/{id}", "/api/posts/feed", false, routes)).toBe("param");
    expect(routedPathMatch("/api/posts/{id}", "/api/posts/7", false, routes)).toBe("exact");
  });

  test("endpoint coverage applies the same precedence to the catalog", () => {
    const surface = {
      operations: [
        { id: "op-search", kind: "http" as const, method: "GET", path: "/api/posts/search" },
        { id: "op-post", kind: "http" as const, method: "GET", path: "/api/posts/{id}" },
        { id: "op-drafts", kind: "http" as const, method: "GET", path: "/api/orgs/{org}/drafts" },
      ],
    };
    const routes = surfaceRoutes(surface);
    const [search, post, drafts] = surface.operations;
    const got = (path: string) => ({ method: "GET", path });
    expect(opMatches(search!, got("/api/posts/search"), routes)).toBe("strict");
    expect(opMatches(post!, got("/api/posts/search"), routes)).toBeNull();
    expect(opMatches(drafts!, got("/api/orgs/globex/drafts"), routes)).toBe("strict");
  });
});

describe("placeholder anchors in the scorer (gin answer key)", () => {
  const gt = loadGt("gin");
  const MARKER = "GLOBEX-CONFIDENTIAL-MARKER-7f3a";
  const finding = (id: string, method: string, url: string, cwe: string, extra: any = {}) => ({
    id,
    cwe,
    severity: "high",
    location: { http: { method, url: `http://127.0.0.1:13311${url}`, ...(extra.param ? { param: extra.param } : {}) } },
    ...(extra.marker ? { evidence: { markers: [MARKER] } } : {}),
  });

  test("concrete slug and token paths land on their {param} anchors", () => {
    const r = scoreApp({
      app: "gin",
      groundTruth: gt,
      runs: [
        envelope("gin", [
          finding("f-group", "GET", "/api/orgs/globex/drafts", "CWE-862", { marker: true }),
          finding("f-tenant", "GET", "/api/orgs/acme/posts?org_id=2", "CWE-639", { param: "org_id" }),
          finding("f-share", "POST", "/api/share/q3J-x9_aZ2bV0kLm/redeem", "CWE-269"),
          finding("f-grant", "GET", "/api/grants/Zm9vYmFyYmF6cXV4MTI", "CWE-639", { marker: true }),
        ] as any),
      ],
    });
    const byFinding = new Map(r.matches.map((m) => [m.finding_id, m.gt_id]));
    expect(byFinding.get("f-group")).toBe("GROUP-ORDER-001");
    expect(byFinding.get("f-tenant")).toBe("TENANT-SRC-001");
    expect(byFinding.get("f-share")).toBe("SHARE-ESCALATE-001");
    expect(byFinding.get("f-grant")).toBe("IDOR-001");
    expect(r.counts.fp).toBe(0);
  });

  test("a near-miss still vetoes the finding that fits it more precisely", () => {
    const r = scoreApp({
      app: "gin",
      groundTruth: gt,
      runs: [envelope("gin", [finding("f-export", "GET", "/api/exports/7", "CWE-639")] as any)],
    });
    expect(r.counts.tp).toBe(0);
    expect(r.false_positives.find((f) => f.finding_id === "f-export")?.hit).toBe("NM-EXPORT-001");
  });

  test("a literal near-miss outranks a {param} bug on the same path", () => {
    // Synthetic: the bug is the placeholder route, the safe sibling is one literal
    // instance of it. A finding AT the literal is the near-miss, not the bug.
    const key = validateGroundTruth({
      app: "t",
      entry: "http://127.0.0.1:13311",
      vulnerabilities: [
        { id: "ORG-001", cwe: "CWE-862", severity: "high", difficulty: "M",
          route: "GET /api/orgs/{org}/drafts",
          match: { http: { method: "GET", path: "/api/orgs/{org}/drafts" } } },
      ],
      near_misses: [
        { id: "NM-ORG-001", of: "ORG-001", route: "GET /api/orgs/public/drafts",
          match: { http: { method: "GET", path: "/api/orgs/public/drafts" } } },
      ],
    }).value!;
    const at = (path: string) =>
      scoreApp({
        app: "t",
        groundTruth: key,
        runs: [envelope("t", [{ id: "f", cwe: "CWE-862", severity: "high", location: { http: { method: "GET", path } } }] as any)],
      });
    expect(at("/api/orgs/globex/drafts").counts.tp).toBe(1);
    expect(at("/api/orgs/public/drafts").counts.tp).toBe(0);
    expect(at("/api/orgs/public/drafts").false_positives[0]?.hit).toBe("NM-ORG-001");
  });

  test("a marker leaked at a static route is not credited to a {param} sibling", () => {
    // nextjs: the search SQLi leaks the seed marker; /api/posts/{id} (IDOR-001)
    // carries the same marker. The search path contradicts the IDOR anchor.
    const r = scoreApp({
      app: "nextjs",
      groundTruth: loadGt("nextjs"),
      runs: [
        envelope("nextjs", [
          { id: "f", cwe: "CWE-89", severity: "high", evidence: { markers: [MARKER] },
            location: { http: { method: "GET", path: "/api/posts/search", param: "q" } } },
        ] as any),
      ],
    });
    expect(r.matches.map((m) => m.gt_id)).toEqual(["SQLI-001"]);
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

  test("a (header: x) parenthetical is a required header; other parentheticals are prose", () => {
    expect(parseRoute("GET /api/admin/users (header: X-Middleware-Subrequest)").http?.headers).toEqual([
      "x-middleware-subrequest",
    ]);
    expect(parseRoute("GET /api/reports/admin-summary (Bearer)").http?.headers).toBeUndefined();
    expect(parseRoute("GET /api/posts/search?q=").http?.headers).toBeUndefined();
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

describe("verb-pinned alternates (multi-step bugs)", () => {
  // A chain's broken step and the step where its impact shows are different
  // requests with different verbs. The alternate names its own.
  const key = {
    app: "t",
    entry: "http://127.0.0.1:13311",
    vulnerabilities: [
      {
        id: "CART-001",
        cwe: "CWE-840",
        severity: "high",
        difficulty: "H",
        route: "PUT /api/cart/plan then POST /api/checkout",
        match: { http: { method: "PUT", path: "/api/cart/plan" }, http_alt: ["POST /api/checkout"] },
      },
    ],
    near_misses: [],
  };
  const at = (method: string, path: string) =>
    scoreApp({
      app: "t",
      groundTruth: validateGroundTruth(key).value!,
      runs: [
        envelope("t", [
          { id: "f", cwe: "CWE-840", severity: "high", location: { http: { method, path } } } as any,
        ]),
      ],
    });

  test("the impact step, on its own verb, is a correct answer", () => {
    expect(at("PUT", "/api/cart/plan").counts.tp).toBe(1);
    expect(at("POST", "/api/checkout").counts.tp).toBe(1);
  });

  test("the alternate does not inherit the primary's verb", () => {
    // a wrong verb on the right path is kept only as a weak signal - so the
    // alternate's own verb is what makes the match exact
    expect(at("POST", "/api/checkout").matches[0]!.why).toContain("POST");
    expect(at("POST", "/api/checkout").matches[0]!.why).not.toContain("verb!=");
    expect(at("PUT", "/api/checkout").matches[0]!.why).toContain("verb!=POST");
  });

  test("splitAlt reads the optional verb; a bare path stays bare", () => {
    expect(splitAlt("POST /api/checkout")).toEqual({ method: "POST", path: "/api/checkout" });
    expect(splitAlt("/api/docs/")).toEqual({ method: null, path: "/api/docs/" });
  });

  test("routeSteps keeps the verb written in front of each path", () => {
    expect(routeSteps("GET /integrations (-> chunk) then POST /api/integrations/sync")).toEqual([
      { method: "GET", path: "/integrations" },
      { method: "POST", path: "/api/integrations/sync" },
    ]);
    expect(routeSteps("GET /api/schema/ and /api/docs/")[1]).toEqual({ method: null, path: "/api/docs/" });
  });

  test("a pinned alternate must still be a path", () => {
    const res = validateGroundTruth({
      app: "t",
      vulnerabilities: [
        { id: "X-001", cwe: "CWE-200", severity: "medium", difficulty: "E", route: "GET /x",
          match: { http: { path: "/x" }, http_alt: ["POST docs"] } },
      ],
    });
    expect(res.errors.some((e) => e.at.endsWith("http_alt"))).toBe(true);
  });
});

describe("business-logic tags", () => {
  const entry = (extra: Record<string, unknown>) => ({
    id: "X-001", cwe: "CWE-639", severity: "high", difficulty: "M", route: "GET /x", ...extra,
  });
  const errs = (extra: Record<string, unknown>) =>
    validateGroundTruth({ app: "t", vulnerabilities: [entry(extra)] }).errors;

  test("logic, actors and steps go together", () => {
    expect(errs({ logic: "state", actors: 2, steps: 3 })).toEqual([]);
    expect(errs({ logic: "state" }).some((e) => e.msg.includes("go together"))).toBe(true);
    expect(errs({ actors: 2, steps: 3 }).some((e) => e.msg.includes("go together"))).toBe(true);
  });

  test("the logic class is a closed vocabulary", () => {
    expect(errs({ logic: "weird", actors: 1, steps: 1 }).some((e) => e.at.endsWith(".logic"))).toBe(true);
  });

  test("actors and steps are small whole numbers", () => {
    expect(errs({ logic: "state", actors: 0, steps: 1 }).some((e) => e.at.endsWith(".actors"))).toBe(true);
    expect(errs({ logic: "state", actors: 1, steps: 1.5 }).some((e) => e.at.endsWith(".steps"))).toBe(true);
  });

  test("recall splits by class, sessions and steps - over tagged entries only", () => {
    const vulns = [
      entry({ id: "A-001", logic: "state", actors: 2, steps: 3 }),
      entry({ id: "B-001", logic: "binding", actors: 1, steps: 1 }),
      entry({ id: "C-001" }), // an injection bug: no logic tags, in no bucket
    ] as any[];
    const found = (v: any) => v.id === "B-001";
    const x = extraBreakdowns(vulns, found);
    expect(x.by_logic).toEqual({
      state: { gt: 1, tp: 0, recall: 0 },
      binding: { gt: 1, tp: 1, recall: 1 },
    });
    expect(Object.keys(x.by_actors!).sort()).toEqual(["1 actor", "2 actors"]);
    expect(x.by_steps!["multi-step"]!.tp).toBe(0);
    expect(x.by_steps!["single request"]!.tp).toBe(1);
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

  test("no CWE but a title naming the class still earns the bug, with zero credit", () => {
    const r = score([
      { id: "n1", title: "Open redirect via next", location: { http: { method: "GET", path: "/goto", param: "next" } } },
    ]);
    expect(r.matches.map((m) => m.gt_id)).toEqual(["REDIRECT-001"]);
    expect(r.matches[0]!.cwe_credit).toBe(0);
    expect(r.matches[0]!.why).toContain("claim CWE-601");
  });

  test("no CWE and nothing nameable on a bug's route is unclassified - neither tp nor fp", () => {
    const r = score([
      { id: "n2", location: { http: { method: "GET", path: "/goto", param: "next" } } },
    ]);
    expect(r.counts.tp).toBe(0);
    expect(r.counts.fp).toBe(0);
    expect(r.counts.unclassified).toBe(1);
    expect(r.unclassified).toEqual([
      { finding_id: "n2", gt_id: "REDIRECT-001", where: "GET /goto", why: "path, param next, GET" },
    ]);
    // the miss says how close it came
    const miss = r.misses.find((m) => m.gt_id === "REDIRECT-001")!;
    expect(miss.closest?.finding_id).toBe("n2");
    expect(miss.closest?.why).toContain("unclassified");
    expect(r.metrics.precision).toBeNull();
  });

  test("no CWE and a title naming another class is a wrong answer", () => {
    const r = score([
      { id: "n3", title: "Reflected XSS in next", location: { http: { method: "GET", path: "/goto", param: "next" } } },
    ]);
    expect(r.counts.tp).toBe(0);
    expect(r.counts.fp_other).toBe(1);
  });

  test("a no-CWE finding pinned by line in the bug's own range still earns it", () => {
    // the source tier is exact about WHICH code; only the route tier needs a claim
    const r = score([{ id: "n4", location: { file: { path: "vuln/src/lib/merge.ts", line: 8 } } }]);
    expect(r.matches.map((m) => m.gt_id)).toEqual(["PROTO-001"]);
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


// ------------------------------------------------- claim compatibility ----

describe("a route match must be the same claim", () => {
  // Each case is shaped like a row of a gimorra export: a standing claim about
  // one defect on a route, next to a different planted bug on the same route.
  const gin = loadGt("gin");
  const nextjs = loadGt("nextjs");
  const run = (app: string, gt: ReturnType<typeof loadGt>, findings: any[]) =>
    scoreApp({ app, groundTruth: gt, runs: [envelope(app, findings)] });
  const login = (id: string, title: string, tag: string, extra: any = {}) => ({
    id,
    title,
    tags: [tag, "severity-indicative"],
    severity: "low",
    location: { http: { url: "http://127.0.0.1:13313/api/auth/login", path: "/api/auth/login", ...extra } },
    ...(extra.cwe ? { cwe: extra.cwe } : {}),
  });

  test("gin: an unvalidated tenant field on the login route is not default credentials", () => {
    const r = run("gin", gin, [
      login(
        "tenant",
        "Login honors an unvalidated client-supplied tenant field - admin logs in with tenant=Globex",
        "login-tenant-field-not-validated",
        { param: "tenant" },
      ),
    ]);
    expect(r.matches).toEqual([]);
    expect(r.counts.fp).toBe(0);
    expect(r.unclassified.map((u) => [u.finding_id, u.gt_id])).toEqual([["tenant", "DEFAULT-CREDS-001"]]);
  });

  test("gin: deterministic session cookies on the login route are not default credentials", () => {
    const r = run("gin", gin, [
      login(
        "cookie",
        "Session cookies are deterministic per user (identical value on every login), never revoked on re-login, and issued without Secure or SameSite flags",
        "session-handling-static-nonrevoked",
      ),
    ]);
    expect(r.matches).toEqual([]);
    expect(r.counts.unclassified).toBe(1);
    expect(r.misses.find((m) => m.gt_id === "DEFAULT-CREDS-001")?.closest?.why).toContain("unclassified");
  });

  test("gin: default credentials on the login route ARE the bug, with or without a CWE", () => {
    const untagged = run("gin", gin, [
      login("creds", "Default credentials admin/admin accepted on the login form", "default-credentials"),
    ]);
    expect(untagged.matches.map((m) => [m.gt_id, m.tier, m.cwe_credit])).toEqual([["DEFAULT-CREDS-001", "route", 0]]);

    // a same-family CWE (CWE-798 for CWE-1392) is the legitimate route match it always was
    const sibling = run("gin", gin, [
      login("creds", "Seeded service account accepts a weak password", "weak-secret", { cwe: "CWE-798" }),
    ]);
    expect(sibling.matches.map((m) => [m.gt_id, m.tier, m.cwe_credit_kind])).toEqual([
      ["DEFAULT-CREDS-001", "route", "family"],
    ]);
  });

  test("gin: a reported CWE of another family on the login route stays a wrong answer", () => {
    const r = run("gin", gin, [
      login("flags", "Session cookie issued without Secure", "cookie-flags", { cwe: "CWE-614" }),
    ]);
    expect(r.matches).toEqual([]);
    expect(r.counts.fp_other).toBe(1);
  });

  const adminUsers = (id: string, cwe: string, extra: any = {}, evidence?: any) => ({
    id,
    title: extra.title ?? "GET /api/admin/users serves the full cross-tenant user list to any authenticated account",
    cwe,
    tags: ["function-level-authorization"],
    severity: "low",
    location: {
      http: {
        url: "http://127.0.0.1:13322/api/admin/users",
        path: "/api/admin/users",
        ...(extra.param ? { param: extra.param, param_in: "header" } : {}),
      },
    },
    ...(evidence ? { evidence } : {}),
  });

  test("nextjs: a function-level authz finding on /api/admin/users is not the middleware bypass", () => {
    // same route, same authz family (CWE-862 vs CWE-285) - but it never sent the header
    const r = run("nextjs", nextjs, [adminUsers("fla", "CWE-862")]);
    expect(r.matches.find((m) => m.gt_id === "MW-BYPASS-001")).toBeUndefined();
    expect(r.misses.find((m) => m.gt_id === "MW-BYPASS-001")).toBeDefined();
    expect(r.counts.fp_other).toBe(1);
  });

  test("nextjs: the same finding naming the header IS the middleware bypass", () => {
    const asParam = run("nextjs", nextjs, [adminUsers("mw", "CWE-862", { param: "x-middleware-subrequest" })]);
    expect(asParam.matches.map((m) => [m.gt_id, m.cwe_credit_kind])).toEqual([["MW-BYPASS-001", "family"]]);
    expect(asParam.matches[0]!.why).toContain("header x-middleware-subrequest");

    // named in the reproduction instead, in any case - a header name is case-insensitive
    const inNote = run("nextjs", nextjs, [
      adminUsers("mw2", "CWE-285", {}, {
        note: "curl -H 'X-Middleware-Subrequest: middleware' http://127.0.0.1:13322/api/admin/users -> 200",
      }),
    ]);
    expect(inNote.matches.map((m) => [m.gt_id, m.cwe_credit_kind])).toEqual([["MW-BYPASS-001", "exact"]]);
  });

  test("nextjs: a longer header that merely starts with the name does not count", () => {
    const r = run("nextjs", nextjs, [
      adminUsers("mw3", "CWE-285", {}, { request: "GET /api/admin/users\nx-middleware-subrequest-id: 7" }),
    ]);
    expect(r.matches.find((m) => m.gt_id === "MW-BYPASS-001")).toBeUndefined();
  });

  test("nextjs: an untagged finding whose own words name the class keeps its route credit", () => {
    // the export's source-map and step-skip rows carry no CWE; their slug and title do
    const r = run("nextjs", nextjs, [
      {
        id: "map",
        title: "source-map-exposure at 127.0.0.1:13322/_next/static/chunks/main-app-54b3ae81f26fc944.js.map",
        tags: ["source-map-exposure"],
        location: { http: { method: "GET", path: "/_next/static/chunks/main-app-54b3ae81f26fc944.js.map" } },
      },
      {
        id: "skip",
        title: "signup/complete succeeds without a verified code (skips the verify step)",
        tags: ["signup-verification-bypass"],
        location: { http: { path: "/api/signup/complete" } },
      },
    ]);
    expect(new Map(r.matches.map((m) => [m.finding_id, m.gt_id]))).toEqual(
      new Map([
        ["map", "SOURCEMAP-001"],
        ["skip", "SIGNUP-STEPSKIP-001"],
      ]),
    );
  });
});

describe("cwe guessing from a title", () => {
  test("short acronyms only match as whole words", () => {
    // "source" ends in "rce", "retrieval" in "eval", "spelling" starts with "spel"
    expect(guessCwe("Source code disclosure")).toBe("CWE-540");
    expect(guessCwe("source-map-exposure")).toBe("CWE-540");
    expect(guessCwe("Document retrieval is slow")).toBeNull();
    expect(guessCwe("spelling mistakes on the page")).toBeNull();
    expect(guessCwe("RCE via upload")).toBe("CWE-78");
    expect(guessCwe("eval() of user input")).toBe("CWE-94");
  });

  test("a skipped workflow step is CWE-841", () => {
    expect(guessCwe("checkout skips the payment step")).toBe("CWE-841");
    expect(guessCwe("workflow-bypass")).toBe("CWE-841");
  });
});
