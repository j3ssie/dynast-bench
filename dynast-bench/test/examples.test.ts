/**
 * The `examples/` folder, asserted.
 *
 * Its README quotes exact numbers, and an example that no longer produces them
 * is worse than no example at all: someone copies it, gets something different,
 * and cannot tell whether their tool or the doc is wrong. So the files are
 * scored here and the documented figures are the assertions.
 *
 * The templates are checked only for parsing - they carry an `<app>` placeholder
 * and `_comment` keys on purpose, and proving those survive validation IS the
 * property that matters for them.
 */

import { describe, expect, test } from "bun:test";

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { validateEndpoints } from "../src/schema/endpoints.ts";
import { validateFindings } from "../src/schema/findings.ts";
import { coverageTrack } from "../src/scorer/coverage.ts";
import { scoreApp } from "../src/scorer/score.ts";
import { loadGt, loadSurface, ROOT } from "./helpers.ts";

const EXAMPLES = join(ROOT, "examples");
const read = (name: string) => JSON.parse(readFileSync(join(EXAMPLES, name), "utf8"));

const findings = (name: string) => {
  const res = validateFindings(read(name));
  if (!res.value) throw new Error(`${name}: ${JSON.stringify(res.errors)}`);
  expect(res.errors, `${name} must validate cleanly`).toEqual([]);
  return res.value;
};

const endpoints = (name: string) => {
  const res = validateEndpoints(read(name));
  if (!res.value) throw new Error(`${name}: ${JSON.stringify(res.errors)}`);
  expect(res.errors, `${name} must validate cleanly`).toEqual([]);
  return res.value;
};

test("the folder is present and self-describing", () => {
  expect(existsSync(EXAMPLES)).toBe(true);
  expect(existsSync(join(EXAMPLES, "README.md"))).toBe(true);
});

test("every .json in examples/ parses and validates as one of the two schemas", () => {
  const files = readdirSync(EXAMPLES).filter((f) => f.endsWith(".json"));
  expect(files.length).toBeGreaterThan(0);
  for (const f of files) {
    const doc = read(f);
    const asFindings = validateFindings(doc);
    const asEndpoints = validateEndpoints(doc);
    const ok = (asFindings.ok && "findings" in doc) || (asEndpoints.ok && "endpoints" in doc);
    expect(ok, `${f} validates as neither findings/v1 nor endpoints/v1`).toBe(true);
  }
});

describe("findings.json", () => {
  const report = () =>
    scoreApp({ app: "nextjs", groundTruth: loadGt("nextjs"), runs: [findings("findings.json")] });

  test("scores exactly what the README says", () => {
    const r = report();
    expect(r.counts.tp).toBe(6);
    expect(r.counts.fp).toBe(0);
    expect(r.counts.duplicates).toBe(0);
    expect(r.metrics.precision).toBe(1);
    expect(r.metrics.discrimination).toBe(1);
  });

  test("every finding lands on a real bug - an example that misses teaches nothing", () => {
    const r = report();
    expect(r.matches).toHaveLength(6);
    expect(r.false_positives).toEqual([]);
  });

  test("f-04 matches on source alone, with no route", () => {
    const r = report();
    const m = r.matches.find((x) => x.finding_id === "f-04");
    expect(m?.tier).toBe("source");
    expect(m?.exploited).toBe(false);
  });

  test("f-06's CWE alternates are scored best-of, at full credit", () => {
    const r = report();
    expect(r.matches.find((x) => x.finding_id === "f-06")?.cwe_credit).toBe(1);
  });
});

describe("findings-safe.json", () => {
  const report = () =>
    scoreApp({
      app: "nextjs",
      groundTruth: loadGt("nextjs"),
      runs: [findings("findings.json"), findings("findings-safe.json")],
    });

  test("is a safe-twin run, or it would score as true positives", () => {
    expect(findings("findings-safe.json").run.variant).toBe("safe");
  });

  test("demonstrates both false-positive kinds, as the README claims", () => {
    const r = report();
    expect(r.counts.fp).toBe(2);
    expect(r.counts.fp_fixed_bug).toBe(1);
    expect(r.counts.fp_near_miss).toBe(1);
    expect(r.counts.fp_other).toBe(0);
    expect(r.metrics.precision).toBe(0.75);
  });
});

describe("endpoints.json", () => {
  const track = (file: string, app = "nextjs", withFindings = false) =>
    coverageTrack({
      surface: loadSurface(app)!,
      reported: endpoints(file).endpoints,
      evidenceSource: "reported",
      vulns: withFindings ? loadGt(app).vulnerabilities : undefined,
      foundVulnIds: withFindings
        ? new Set(
            scoreApp({
              app,
              groundTruth: loadGt(app),
              runs: [findings("findings.json")],
            }).matches.map((m) => m.gt_id),
          )
        : undefined,
    });

  test("reaches the shallow surface completely and the deep flow not at all", () => {
    const t = track("endpoints.json");
    expect(t.by_discovery["static-html"]?.recall).toBe(1);
    expect(t.by_discovery["js-static"]?.recall).toBe(1);
    // the whole point of the example: a crawler that cannot drive a multi-step
    // flow reaches none of it, and that is a discovery failure, not an analysis one
    expect(t.by_discovery["flow"]?.recall).toBe(0);
  });

  test("the invented endpoint costs precision but not coverage", () => {
    const t = track("endpoints.json");
    expect(t.unknown).toEqual(["GET /api/notifications"]);
    expect(t.precision).toBeLessThan(1);
    // coverage is computed over the catalog, so an extra guess cannot move it
    const clean = coverageTrack({
      surface: loadSurface("nextjs")!,
      reported: endpoints("endpoints.json").endpoints.filter(
        (e) => e.path !== "/api/notifications",
      ),
      evidenceSource: "reported",
    });
    expect(clean.operations.coverage).toBe(t.operations.coverage);
  });

  test("splits the misses the way the README reports", () => {
    const t = track("endpoints.json", "nextjs", true);
    expect(t.detection_given_touch).toBe(0.25);
    expect(t.discovery_misses.length).toBe(11);
    expect(t.analysis_misses.length).toBe(18);
    expect(t.unmapped_vulns).toEqual([]);
  });

  test("the shorthand string form is equivalent to the object form", () => {
    const short = endpoints("endpoints-shorthand.json").endpoints;
    // every string entry resolved to something the catalog recognises
    const t = coverageTrack({
      surface: loadSurface("nextjs")!,
      reported: short,
      evidenceSource: "reported",
    });
    expect(t.unknown, "a shorthand entry that parses to nothing is a broken example").toEqual([]);
    expect(t.precision).toBe(1);
  });
});

describe("endpoints-graphql.json", () => {
  test("route coverage far outruns operation coverage - the whole lesson", () => {
    const t = coverageTrack({
      surface: loadSurface("graphql")!,
      reported: endpoints("endpoints-graphql.json").endpoints,
      evidenceSource: "reported",
    });
    expect(t.routes.coverage).toBe(0.8);
    expect(t.operations.coverage).toBeLessThan(0.5);
    expect(t.by_kind["graphql"]!.recall).toBe(0.4);
    expect(t.precision).toBe(1);
  });
});

describe("templates", () => {
  test("parse despite the _comment keys and the <app> placeholder", () => {
    const f = validateFindings(read("template-findings.json"));
    expect(f.errors).toEqual([]);
    expect(f.value!.findings).toHaveLength(1);

    const e = validateEndpoints(read("template-endpoints.json"));
    expect(e.errors).toEqual([]);
    // every commented entry must survive - one dropped silently would teach a
    // shape that does not work
    expect(e.value!.endpoints).toHaveLength(12);
    expect(e.warnings).toEqual([]);
  });

  test("the findings template exercises every location kind", () => {
    const loc = validateFindings(read("template-findings.json")).value!.findings[0]!.location;
    for (const kind of ["http", "file", "net", "graphql", "ws", "llm"] as const) {
      expect(loc[kind], `template is missing a ${kind} location`).toBeDefined();
    }
  });

  test("the endpoints template exercises every operation kind", () => {
    const eps = validateEndpoints(read("template-endpoints.json")).value!.endpoints;
    const kinds = new Set(eps.map((e) => e.kind ?? "http"));
    for (const kind of ["http", "graphql", "ws", "llm", "net"]) {
      expect(kinds.has(kind), `template is missing a ${kind} endpoint`).toBe(true);
    }
  });
});
