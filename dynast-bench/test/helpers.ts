/** Shared fixtures + loaders for the scorer tests. */

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { appsDir, builtApps, groundTruthPath, repoRoot } from "../src/repo.ts";
import { validateFindings } from "../src/schema/findings.ts";
import { parseGroundTruthFile } from "../src/schema/ground-truth.ts";
import type { Finding, FindingsFile, GroundTruth, Variant } from "../src/schema/types.ts";
import { gtAnchors } from "../src/scorer/anchors.ts";

export const ROOT = repoRoot(import.meta.dir);
export const APPS_DIR = appsDir(ROOT);

/** Apps with a real answer key. A half-created skeleton is not a failing app. */
export const appNames = (): string[] => builtApps(ROOT);

export const gtPath = (app: string) => groundTruthPath(ROOT, app);

export function loadGt(app: string): GroundTruth {
  const res = parseGroundTruthFile(gtPath(app));
  if (!res.value) throw new Error(`${app}: ${JSON.stringify(res.errors)}`);
  return res.value;
}

export function envelope(
  app: string,
  findings: Finding[],
  variant: Variant = "vuln",
  tool = "test",
): FindingsFile {
  const res = validateFindings(
    {
      schema: "dynast-bench.findings/v1",
      tool: { name: tool, mode: "hybrid" },
      run: { app, variant, target: "http://127.0.0.1:13311" },
      findings,
    },
    { app },
  );
  if (!res.value) throw new Error(`invalid fixture: ${JSON.stringify(res.errors)}`);
  return res.value;
}

export type SyntheticMode = "perfect" | "dast" | "sast";

/**
 * A synthetic tool built from the answer key's own anchors.
 *
 *   perfect  everything the key knows: route, source, markers, discriminators
 *   dast     only what a black-box run can see (no file, no markers)
 *   sast     only what a source scan can see (file + line, no route)
 */
export function synthetic(app: string, gt: GroundTruth, mode: SyntheticMode): FindingsFile {
  const findings: Finding[] = [];
  gt.vulnerabilities.forEach((v, i) => {
    const a = gtAnchors(v);
    const h = a.http[0];
    const n = a.net[0];
    const f = a.file[0];
    const location: Finding["location"] = {};

    if (mode !== "sast") {
      if (h) {
        const qs = Object.entries(h.query)
          .map(([k, val], j) => `${j ? "&" : "?"}${k}=${val}`)
          .join("");
        location.http = {
          method: h.method ?? "GET",
          path: h.path ?? undefined,
          param: h.params[0],
          url: `http://127.0.0.1:${h.port ?? 13311}${h.path}${qs}`,
        };
      }
      if (n) location.net = { host: n.host ?? undefined, port: n.port ?? undefined, proto: n.proto, state: "open" };
    }
    if (mode !== "dast" && f) {
      location.file = { path: f.path, symbol: f.symbol, line: f.lines?.[0] };
    }
    if (mode === "perfect") {
      if (a.graphql[0]) location.graphql = a.graphql[0];
      if (a.ws[0]) location.ws = a.ws[0];
      if (a.llm[0]) location.llm = a.llm[0];
    }
    if (!Object.keys(location).length) return; // unreachable in this mode

    findings.push({
      id: `${mode}-${i + 1}`,
      title: v.id,
      cwe: v.cwe,
      severity: v.severity,
      confidence: "certain",
      location,
      evidence: mode === "perfect" ? { markers: a.markers } : undefined,
      exploited: mode !== "sast",
    });
  });
  return envelope(app, findings, "vuln", mode);
}

/** Load a checked-in golden fixture. */
export function loadFixture(app: string, name: string): FindingsFile {
  const path = join(APPS_DIR, app, "ground-truth", "expected", name);
  const res = validateFindings(JSON.parse(readFileSync(path, "utf8")));
  if (!res.value) throw new Error(`${app}/${name}: ${JSON.stringify(res.errors)}`);
  return res.value;
}
