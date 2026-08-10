/**
 * Per-app invariants. These run against every answer key in the suite, so a new
 * app is covered the moment it lands - and a key that drifts out of scoreable
 * shape fails here rather than silently mis-scoring a tool.
 */

import { describe, expect, test } from "bun:test";

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { parseGroundTruthFile } from "../src/schema/ground-truth.ts";
import { anchorFingerprint, gtAnchors, isSourceOnly } from "../src/scorer/anchors.ts";
import { scoreApp } from "../src/scorer/score.ts";
import { APPS_DIR, appNames, gtPath, loadGt, synthetic } from "./helpers.ts";

const apps = appNames();

test("the suite has every app the repo ships", () => {
  expect(apps.length).toBeGreaterThanOrEqual(18);
});

describe.each(apps)("%s", (app) => {
  const gt = loadGt(app);

  test("answer key validates", () => {
    expect(parseGroundTruthFile(gtPath(app)).errors).toEqual([]);
  });

  test("every entry has anchors a finding can hit", () => {
    for (const v of gt.vulnerabilities) {
      const a = gtAnchors(v);
      const hasAny = !isSourceOnly(a) || a.file.length > 0;
      expect(hasAny, `${v.id} has no anchors at all`).toBe(true);
    }
  });

  test("declared match.file paths and line ranges exist on disk", () => {
    for (const v of gt.vulnerabilities) {
      const f = v.match?.file;
      if (!f?.path) continue;
      const text = readFileSync(join(APPS_DIR, app, f.path), "utf8");
      if (f.lines) {
        expect(f.lines[1], `${v.id} lines past EOF of ${f.path}`).toBeLessThanOrEqual(
          text.split("\n").length,
        );
        expect(f.lines[0]).toBeLessThanOrEqual(f.lines[1]);
      }
    }
  });

  test("a tool that reports exactly the answer key scores 1.0/1.0", () => {
    const r = scoreApp({ app, groundTruth: gt, runs: [synthetic(app, gt, "perfect")] });
    expect(r.metrics.recall).toBe(1);
    expect(r.metrics.precision).toBe(1);
    expect(r.metrics.cwe_credit).toBe(1);
    expect(r.counts.duplicates).toBe(0);
    expect(r.counts.fp_near_miss).toBe(0);
    if (gt.near_misses.length) expect(r.metrics.discrimination).toBe(1);
  });

  test("a black-box tool can reach every route-anchored bug", () => {
    const r = scoreApp({ app, groundTruth: gt, runs: [synthetic(app, gt, "dast")] });
    expect(r.metrics.recall_reachable).toBe(1);
    expect(r.counts.fp).toBe(0);
  });

  test("a source-only tool never trips a near-miss", () => {
    const r = scoreApp({ app, groundTruth: gt, runs: [synthetic(app, gt, "sast")] });
    expect(r.counts.fp_near_miss).toBe(0);
    expect(r.counts.fp).toBe(0);
  });

  test("no two bugs are indistinguishable (same CWE and same anchors)", () => {
    const seen = new Map<string, string[]>();
    for (const v of gt.vulnerabilities) {
      const key = anchorFingerprint(v);
      seen.set(key, [...(seen.get(key) ?? []), v.id]);
    }
    const clashes = [...seen.values()].filter((ids) => ids.length > 1);
    expect(clashes, `indistinguishable: ${JSON.stringify(clashes)}`).toEqual([]);
  });

  // The tier vocabulary itself is not re-checked here: an out-of-vocabulary
  // value is a hard error from the validator, which "answer key validates"
  // above already asserts is empty for every app.
  test("discovery tiers are all-or-nothing", () => {
    const tiered = gt.vulnerabilities.filter((v) => v.discovery);
    if (!tiered.length) return; // app not migrated to the discovery axis yet
    const untiered = gt.vulnerabilities.filter((v) => !v.discovery).map((v) => v.id);
    expect(untiered, "recall by tier would cover only the labelled subset").toEqual([]);
  });

  test("near-miss anchors never collide with a bug's route", () => {
    const bugPaths = new Set(
      gt.vulnerabilities.flatMap((v) => gtAnchors(v).http.map((h) => h.path)),
    );
    for (const nm of gt.near_misses) {
      const p = nm.match?.http?.path;
      if (!p) continue;
      expect(bugPaths.has(p), `${nm.id} anchors on a bug's own route ${p}`).toBe(false);
    }
  });
});
