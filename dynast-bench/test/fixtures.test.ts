/**
 * Golden fixtures. `vulnerable-apps/nextjs/ground-truth/expected/` holds two
 * hand-maintained findings files with the exact scores they must produce, so a
 * change in how the scorer grades fails here instead of silently moving every
 * tool's benchmark numbers.
 *
 * These two files are also the worked example an app author copies: `perfect.json`
 * shows what a fully-anchored finding looks like, `sloppy.json` shows one case per
 * scoring rule.
 */

import { describe, expect, test } from "bun:test";

import { scoreApp } from "../src/scorer/score.ts";
import { loadFixture, loadGt } from "./helpers.ts";

describe("nextjs golden fixtures", () => {
  const gt = loadGt("nextjs");

  test("perfect.json scores a clean sweep", () => {
    const r = scoreApp({ app: "nextjs", groundTruth: gt, runs: [loadFixture("nextjs", "perfect.json")] });
    expect(r.metrics.recall).toBe(1);
    expect(r.metrics.precision).toBe(1);
    expect(r.metrics.f1).toBe(1);
    expect(r.metrics.cwe_credit).toBe(1);
    expect(r.metrics.discrimination).toBe(1);
    expect(r.metrics.exploit_rate).toBe(1);
    expect(r.counts.fp).toBe(0);
    expect(r.counts.duplicates).toBe(0);
    expect(r.misses).toEqual([]);
  });

  test("sloppy.json scores exactly what its comment claims", () => {
    const r = scoreApp({ app: "nextjs", groundTruth: gt, runs: [loadFixture("nextjs", "sloppy.json")] });

    expect(r.counts.tp).toBe(4);
    expect(r.counts.fn).toBe(gt.vulnerabilities.length - 4);
    expect(r.counts.duplicates).toBe(2);
    expect(r.counts.fp).toBe(3);
    expect(r.counts.fp_near_miss).toBe(1);
    expect(r.counts.fp_other).toBe(2);
    expect(r.counts.informational).toBe(1);

    // 4 tp / (4 tp + 3 fp); the 2 duplicates and the closed port count in neither
    expect(r.metrics.precision).toBeCloseTo(4 / 7, 3);
    expect(r.metrics.recall).toBeCloseTo(4 / gt.vulnerabilities.length, 3);
    expect(r.metrics.noise_ratio).toBeCloseTo(2 / 10, 3);
    expect(r.metrics.discrimination).toBeCloseTo(1 - 1 / gt.near_misses.length, 3);

    const byId = new Map(r.matches.map((m) => [m.gt_id, m]));
    expect(byId.get("SQLI-001")!.tier).toBe("proof");
    expect(byId.get("SQLI-001")!.cwe_credit).toBe(1);
    expect(byId.get("IDOR-001")!.cwe_credit).toBe(0.5); // CWE-862 is authz family
    expect(byId.get("TRAVERSAL-001")!.cwe_credit).toBe(0.25); // CWE-20 is generic
    expect(byId.get("PROTO-001")!.tier).toBe("source");
    expect(byId.get("XSS-REFLECT-002")).toBeUndefined();

    expect(r.false_positives.find((f) => f.finding_id === "s-08")!.hit).toBe("NM-FETCH-001");
    expect(r.misses.some((m) => m.gt_id === "REDIRECT-001")).toBe(true);
  });
});
