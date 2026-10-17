/**
 * Per-app invariants. These run against every answer key in the suite, so a new
 * app is covered the moment it lands - and a key that drifts out of scoreable
 * shape fails here rather than silently mis-scoring a tool.
 */

import { describe, expect, test } from "bun:test";

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { parseGroundTruthFile } from "../src/schema/ground-truth.ts";
import { anchorFingerprint, gtAnchors, isSourceOnly } from "../src/scorer/anchors.ts";
import { scoreApp } from "../src/scorer/score.ts";
import { APPS_DIR, appNames, envelope, gtPath, loadGt, synthetic } from "./helpers.ts";

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

  // Same path, different verb is a different operation: PATCH /api/comments/{id}
  // (the bug) and DELETE /api/comments/{id} (its near-miss) are told apart by
  // the method on both anchors. Same path with either verb missing is not.
  test("near-miss anchors never collide with a bug's route", () => {
    const bugHttp = gt.vulnerabilities.flatMap((v) => gtAnchors(v).http);
    for (const nm of gt.near_misses) {
      const p = nm.match?.http?.path;
      if (!p) continue;
      const verb = nm.match?.http?.method ?? null;
      const clash = bugHttp.find(
        (h) => h.path === p && (!verb || !h.method || h.method === verb),
      );
      expect(clash, `${nm.id} anchors on a bug's own route ${verb ?? "ANY"} ${p}`).toBeUndefined();
    }
  });

  // An incidental entry is a true finding in both twins. Reported at its own
  // anchors with its own CWE, on either twin, it must score as neither a true
  // nor a false positive - and must never be mistaken for a planted bug.
  test("an incidental reported on either twin is neither a hit nor a false alarm", () => {
    const incidental = gt.incidental ?? [];
    if (!incidental.length) return;
    const bugPrints = new Set(gt.vulnerabilities.map(anchorFingerprint));
    const findings = incidental.map((inc, i) => {
      expect(bugPrints.has(anchorFingerprint(inc)), `${inc.id} is indistinguishable from a bug`).toBe(false);
      const a = gtAnchors(inc);
      const h = a.http[0];
      const f = a.file[0];
      return {
        id: `inc-${i}`,
        cwe: inc.cwe,
        severity: "low",
        location: {
          ...(h ? { http: { method: h.method ?? undefined, path: h.path!, ...(h.params[0] ? { param: h.params[0] } : {}) } } : {}),
          ...(f ? { file: { path: f.path, ...(f.symbol ? { symbol: f.symbol } : {}) } } : {}),
        },
      };
    });
    const r = scoreApp({
      app,
      groundTruth: gt,
      runs: [envelope(app, findings as any), envelope(app, findings as any, "safe")],
    });
    expect(r.counts.tp).toBe(0);
    expect(r.counts.fp).toBe(0);
    expect(r.counts.incidental).toBe(2 * incidental.length);
  });

  // Several apps plant resource-exhaustion bugs on purpose, and more spawn a
  // process per request. Uncapped, fuzzing any of them exhausts the Docker VM
  // and every OTHER app on the daemon dies too - which reads as "the benchmark
  // is flaky" rather than "this app has a DoS". The caps are what keep a
  // planted bug's blast radius inside its own container, so a new app silently
  // shipping without them is a regression in the whole suite, not just itself.
  test.each(["vuln", "safe"])("%s compose caps every service", (variant) => {
    const file = join(APPS_DIR, app, variant, "docker-compose.yml");
    if (!existsSync(file)) return; // not every app ships both twins
    const lines = readFileSync(file, "utf8").split("\n");

    const start = lines.findIndex((l) => /^services:\s*$/.test(l));
    expect(start, `${variant}/docker-compose.yml has no services: block`).toBeGreaterThan(-1);
    let end = lines.length;
    for (let i = start + 1; i < lines.length; i++) {
      if (/^[A-Za-z]/.test(lines[i]!)) { end = i; break; }
    }

    // service keys are exactly 2-space indented with nothing after the colon
    const svcs: { name: string; line: number }[] = [];
    for (let i = start + 1; i < end; i++) {
      const m = /^ {2}([A-Za-z0-9_.-]+):\s*$/.exec(lines[i]!);
      if (m) svcs.push({ name: m[1]!, line: i });
    }
    expect(svcs.length, `${variant}/docker-compose.yml declares no services`).toBeGreaterThan(0);

    for (const [i, svc] of svcs.entries()) {
      const body = lines.slice(svc.line + 1, svcs[i + 1]?.line ?? end).join("\n");
      for (const key of ["mem_limit", "cpus", "pids_limit"]) {
        expect(
          new RegExp(`^\\s*${key}:`, "m").test(body),
          `${app}/${variant} service "${svc.name}" has no ${key} (see CLAUDE.md "Resource limits")`,
        ).toBe(true);
      }

      // Caps stop a planted bug taking the machine down; they do NOT bring the
      // app back. Docker's default restart policy is "no", so the first PoC or
      // scanner request that crashes an app left it down for the whole rest of
      // the run - which is the "the benchmark is flaky" report, and is why every
      // service now declares one. See CLAUDE.md "Surviving the run".
      expect(
        /^\s*restart:\s*unless-stopped\s*$/m.test(body),
        `${app}/${variant} service "${svc.name}" has no "restart: unless-stopped" ` +
          `(see CLAUDE.md "Surviving the run")`,
      ).toBe(true);

      // json-file has no default size cap, so an app logging per request under a
      // scanner fills the daemon's disk and takes every OTHER app with it. The
      // solo path has capped this since it existed; compose had not.
      expect(
        /^\s*logging:/m.test(body) && /max-size/.test(body),
        `${app}/${variant} service "${svc.name}" has no bounded logging: ` +
          `(see CLAUDE.md "Surviving the run")`,
      ).toBe(true);

      // A service we build runs app code that forks per request (gin's headless
      // chrome, the exec/shell sinks in php/laravel/jsp). Chrome's renderers
      // outlive the parent the context timeout kills, reparent to PID 1 - the
      // app itself, which reaps nothing - and pile up as zombies until
      // pids_limit is hit and the app can no longer fork. Stock datastore images
      // reap their own children, so this is only asked of the ones we build.
      if (/^\s*build:/m.test(body)) {
        expect(
          /^\s*init:\s*true\s*$/m.test(body),
          `${app}/${variant} service "${svc.name}" builds app code but has no "init: true" ` +
            `(see CLAUDE.md "Surviving the run")`,
        ).toBe(true);
      }
    }
  });
});
