/**
 * scoreApp - normalized findings + answer key -> the report.
 *
 * Classification order per finding, and the reason for it:
 *
 *   1. pins a near-miss precisely AND has no better claim than `weak` on a real
 *      bug                        -> false positive (the discrimination test)
 *   2. matched a bug              -> true positive
 *   3. admissible against a bug
 *      someone else already won   -> duplicate (noise, not a false alarm)
 *   4. anything else              -> false positive
 *
 * (1) outranks (2) because a near-miss sits in the same FILE as its vulnerable
 * sibling: without the veto, a tool could flag the safe function and still be
 * paid for the bug next door. It only fires when the finding pins the near-miss
 * by route, symbol or line - a file-level finding that could be either sibling is
 * treated as noise against the real bug instead.
 *
 * Two near-misses cannot be told apart from their sibling at all when they share
 * the route AND the file AND no line is reported (nextjs NM-SQL-001 is one); those
 * are only caught when a tool reports a line or the exact symbol.
 */

import { isOpenState } from "../schema/keys.ts";
import type {
  Finding,
  FindingsFile,
  GroundTruth,
  ReportedEndpoint,
  Surface,
  Variant,
} from "../schema/types.ts";
import { gtAnchors, isSourceOnly, nearMissAnchors, type GtAnchors } from "./anchors.ts";
import { coverageTrack, type CoverageTrack, type EvidenceSource } from "./coverage.ts";
import { assign, candidatesFor, type Candidate, type Tier } from "./match.ts";
import {
  bucketize,
  DIFFICULTY_ORDER,
  DISCOVERY_ORDER,
  f1 as harmonic,
  orderBuckets,
  ratio,
  REACHABILITY_ORDER,
  SEVERITY_ORDER,
  TAINT_ORDER,
  type Bucket,
} from "./metrics.ts";
import { discoveryTrack, extraBreakdowns, type DiscoveryTrack } from "./tracks.ts";

export interface MatchRow {
  gt_id: string;
  finding_id: string;
  tier: Tier;
  cwe_expected: string | null;
  cwe_reported: string | null;
  cwe_credit: number;
  cwe_credit_kind: string;
  exploited: boolean;
  why: string;
}

export interface MissRow {
  gt_id: string;
  cwe: string | null;
  severity?: string;
  difficulty?: string;
  reachability?: string;
  route?: string;
  source_only: boolean;
  /** set when some finding was close but inadmissible - the near-hit diagnosis */
  closest?: { finding_id: string; tier: Tier; cwe_reported: string | null; why: string };
}

export type FpKind = "near-miss" | "fixed-bug" | "other";

export interface FpRow {
  finding_id: string;
  variant: Variant;
  kind: FpKind;
  cwe: string | null;
  severity?: string;
  where: string;
  /** which near-miss or patched bug it landed on */
  hit?: string;
}

export interface DupRow {
  finding_id: string;
  gt_id: string;
  variant: Variant;
}

export interface ScoreReport {
  app: string;
  tool: { name: string; version?: string; mode?: string };
  runs: {
    variant: Variant;
    target?: string;
    findings: number;
    duration_s?: number;
  }[];
  counts: {
    gt_total: number;
    gt_reachable: number;
    gt_source_only: number;
    near_misses: number;
    findings_total: number;
    tp: number;
    fn: number;
    fp: number;
    fp_near_miss: number;
    fp_fixed_bug: number;
    fp_other: number;
    duplicates: number;
    /** negative observations (a port reported closed) - excluded from precision */
    informational: number;
  };
  metrics: {
    precision: number | null;
    recall: number | null;
    f1: number | null;
    /** recall counting only bugs a black-box run could reach */
    recall_reachable: number | null;
    /** share of found bugs whose CWE was exactly right */
    recall_exact_cwe: number | null;
    /** mean CWE credit over all bugs (1 exact, 0.5 family, 0.25 generic) */
    cwe_credit: number | null;
    /** 1 - near-miss hits / near-misses: does the tool tell safe code apart */
    discrimination: number | null;
    /** duplicate findings / all findings */
    noise_ratio: number | null;
    /** share of true positives the tool actually proved */
    exploit_rate: number | null;
  };
  by_difficulty: Record<string, Bucket>;
  by_severity: Record<string, Bucket>;
  by_reachability: Record<string, Bucket>;
  by_taint: Record<string, Bucket>;
  /** recall per crawl tier; empty for an app whose key declares no tiers */
  by_discovery: Record<string, Bucket>;
  by_cwe: Record<string, Bucket>;
  by_family: Record<string, Bucket>;
  extra: Record<string, Record<string, Bucket>>;
  tracks: { discovery: DiscoveryTrack | null; coverage: CoverageTrack | null };
  matches: MatchRow[];
  misses: MissRow[];
  false_positives: FpRow[];
  duplicates: DupRow[];
  warnings: string[];
}

export interface ScoreInput {
  app: string;
  groundTruth: GroundTruth;
  /** one entry per scanned twin; a safe-variant run contributes only false positives */
  runs: FindingsFile[];
  lenientCwe?: boolean;
  /**
   * The app's endpoint catalog. Absent = no coverage track at all, which is the
   * point: a missing trace must read as "not measured", never as "reached 0%".
   */
  surface?: Surface;
  /** what the tool says it discovered */
  endpoints?: ReportedEndpoint[];
  endpointsSource?: EvidenceSource;
  /**
   * Which twin the endpoint trace came from. Only the coverage track reads it -
   * an operation a fix removes is not expected on `safe`. Findings carry their
   * own variant per run.
   */
  endpointsVariant?: Variant;
}

interface Tagged {
  finding: Finding;
  variant: Variant;
  /** index into the flattened list handed to the matcher */
  index: number;
}

/**
 * A port reported closed or filtered is a negative observation, not a claim that
 * something is wrong - it must not count against precision. (A port reported OPEN
 * that is not open still does: see the discovery track.)
 */
const isPortState = (f: Finding): boolean => {
  const kinds = Object.keys(f.location);
  return kinds.length === 1 && kinds[0] === "net" && !isOpenState(f.location.net?.state);
};

/** Shortest human description of where a finding pointed. */
function where(f: Finding): string {
  const h = f.location.http;
  if (h?.path || h?.url) return `${h.method ?? "?"} ${h.path ?? h.url}`;
  const fl = f.location.file;
  if (fl?.path) return `${fl.path}${fl.line ? ":" + fl.line : ""}`;
  const n = f.location.net;
  if (n) return `${n.host ?? "*"}:${n.port ?? "?"}`;
  const g = f.location.graphql;
  if (g) return `graphql ${g.op ?? g.field}`;
  const l = f.location.llm;
  if (l) return `tool ${l.tool ?? l.channel}`;
  const w = f.location.ws;
  if (w) return `ws ${w.endpoint ?? w.event ?? w.transport}`;
  return "(no location)";
}

export function scoreApp(input: ScoreInput): ScoreReport {
  const { app, groundTruth: gt } = input;
  const warnings: string[] = [];

  const vulns = gt.vulnerabilities;
  const anchors: GtAnchors[] = vulns.map(gtAnchors);
  const nmAnchors = gt.near_misses.map(nearMissAnchors);

  const all: Tagged[] = [];
  for (const run of input.runs) {
    const variant = (run.run.variant ?? "vuln") as Variant;
    for (const f of run.findings) all.push({ finding: f, variant, index: all.length });
  }
  const vulnRun = all.filter((t) => t.variant === "vuln");
  const safeRun = all.filter((t) => t.variant === "safe");
  if (!input.runs.some((r) => (r.run.variant ?? "vuln") === "vuln")) {
    warnings.push(
      "no vuln-variant run supplied - recall is undefined and every finding scores as a false positive",
    );
  }

  // --- near-miss detection, first: it can veto a weak bug match ---------------
  // Reuse the matcher with the near-miss anchors as the "truth" side. CWE is not
  // a gate here: landing on safe code is wrong whatever it is called.
  const nmAsGt: GtAnchors[] = nmAnchors.map((n) => ({ ...n, cwe: null, family: null, cweAliases: [] }));

  const nmHitsByFinding = new Map<
    number,
    { id: string; specific: boolean; spec: number; why: string }
  >();
  if (nmAsGt.length) {
    const nmCands = candidatesFor(
      all.map((t) => t.finding),
      nmAsGt,
      { lenientCwe: true },
    );
    for (const c of nmCands) {
      if (nmHitsByFinding.has(c.findingIndex)) continue;
      // "specific" = pinned by route, symbol or line, not merely the same file
      const specific =
        c.tier === "route" ||
        c.tier === "proof" ||
        c.tier === "api" ||
        (c.tier === "source" && c.why.some((w) => w.startsWith("symbol ") || w.startsWith("line ")));
      nmHitsByFinding.set(c.findingIndex, {
        id: nmAsGt[c.gtIndex]!.id,
        specific,
        spec: c.spec,
        why: c.why.join(", "),
      });
    }
  }

  // --- true positives: only the vuln twin can hold a real bug -----------------
  const allCands = candidatesFor(
    vulnRun.map((t) => t.finding),
    anchors,
    { lenientCwe: input.lenientCwe },
  );
  /**
   * The near-miss veto. A finding whose anchors fit a near-miss MORE precisely
   * than any real bug is charged for the near-miss, and its claims on real bugs
   * are dropped so those bugs are honestly reported as missed. Specificity is
   * anchor-only (see Candidate.spec) because the near-miss anchors carry no CWE -
   * comparing raw scores would let the bug's CWE credit win every time.
   */
  const bestSpecPerFinding = new Map<number, number>();
  for (const c of allCands) {
    const prev = bestSpecPerFinding.get(c.findingIndex);
    if (prev === undefined || c.spec > prev) bestSpecPerFinding.set(c.findingIndex, c.spec);
  }
  const vetoed = new Set<number>();
  for (const [fi, t] of vulnRun.entries()) {
    const nm = nmHitsByFinding.get(t.index);
    if (!nm?.specific) continue;
    if (nm.spec > (bestSpecPerFinding.get(fi) ?? -Infinity)) vetoed.add(fi);
  }
  const cands = allCands.filter((c) => !vetoed.has(c.findingIndex));
  const asg = assign(cands, vulnRun.length);

  const matches: MatchRow[] = [];
  const matchedGt = new Set<number>();
  let exploitedTp = 0;
  let exactCwe = 0;
  let creditSum = 0;

  for (const [fi, cand] of [...asg.byFinding].sort((a, b) => a[1].gtIndex - b[1].gtIndex)) {
    const t = vulnRun[fi]!;
    const v = vulns[cand.gtIndex]!;
    matchedGt.add(cand.gtIndex);
    if (t.finding.exploited) exploitedTp++;
    if (cand.cwe.weight === 1) exactCwe++;
    creditSum += cand.cwe.weight;
    matches.push({
      gt_id: v.id,
      finding_id: t.finding.id,
      tier: cand.tier,
      cwe_expected: anchors[cand.gtIndex]!.cwe,
      cwe_reported: t.finding.cwe ?? null,
      cwe_credit: cand.cwe.weight,
      cwe_credit_kind: cand.cwe.kind,
      exploited: t.finding.exploited === true,
      why: cand.why.join(", "),
    });
  }

  // --- classify every finding -------------------------------------------------
  const falsePositives: FpRow[] = [];
  const duplicates: DupRow[] = [];
  const nmHit = new Set<string>();


  let informational = 0;

  const fpRow = (t: Tagged, kind: FpKind, hit?: string): FpRow => ({
    finding_id: t.finding.id,
    variant: t.variant,
    kind,
    cwe: t.finding.cwe ?? null,
    severity: t.finding.severity,
    where: where(t.finding),
    hit,
  });

  /** Port-state observation, or a near-miss the finding pinned. True = handled. */
  const preClassify = (t: Tagged): boolean => {
    if (isPortState(t.finding)) {
      informational++;
      return true;
    }
    const nm = nmHitsByFinding.get(t.index);
    if (nm?.specific) {
      nmHit.add(nm.id);
      falsePositives.push(fpRow(t, "near-miss", nm.id));
      return true;
    }
    return false;
  };

  vulnRun.forEach((t, localIndex) => {
    if (asg.byFinding.has(localIndex)) return; // true positive
    if (preClassify(t)) return;
    const dup = asg.duplicates.get(localIndex);
    if (dup) {
      duplicates.push({ finding_id: t.finding.id, gt_id: vulns[dup.gtIndex]!.id, variant: "vuln" });
      return;
    }
    falsePositives.push(fpRow(t, "other"));
  });

  // Every finding against the patched twin is a false alarm by construction.
  if (safeRun.length) {
    const safeCands = candidatesFor(
      safeRun.map((t) => t.finding),
      anchors,
      { lenientCwe: input.lenientCwe },
    );
    const onFixedBug = new Map<number, string>();
    for (const c of safeCands) {
      if (!onFixedBug.has(c.findingIndex)) onFixedBug.set(c.findingIndex, vulns[c.gtIndex]!.id);
    }
    safeRun.forEach((t, i) => {
      if (preClassify(t)) return;
      const fixed = onFixedBug.get(i);
      falsePositives.push(fpRow(t, fixed ? "fixed-bug" : "other", fixed));
    });
  }

  // --- misses, with a diagnosis where one is available ------------------------
  const closestFor = (gi: number) => {
    const near = cands.find((c) => c.gtIndex === gi);
    if (!near) return undefined;
    const t = vulnRun[near.findingIndex]!;
    return {
      finding_id: t.finding.id,
      tier: near.tier,
      cwe_reported: t.finding.cwe ?? null,
      why: near.why.join(", "),
    };
  };
  const misses: MissRow[] = [];
  vulns.forEach((v, i) => {
    if (matchedGt.has(i)) return;
    misses.push({
      gt_id: v.id,
      cwe: anchors[i]!.cwe,
      severity: v.severity,
      difficulty: v.difficulty,
      reachability: v.reachability,
      route: v.route,
      source_only: isSourceOnly(anchors[i]!),
      closest: closestFor(i),
    });
  });

  // --- counts + metrics ------------------------------------------------------
  const tp = matchedGt.size;
  const fn = vulns.length - tp;
  const fpByKind: Record<FpKind, number> = { "near-miss": 0, "fixed-bug": 0, other: 0 };
  for (const f of falsePositives) fpByKind[f.kind]++;
  const fp = falsePositives.length;
  const reachable = anchors.filter((a) => !isSourceOnly(a)).length;
  const reachableTp = [...matchedGt].filter((i) => !isSourceOnly(anchors[i]!)).length;

  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, vulns.length);

  const found = (_v: unknown, i: number) => matchedGt.has(i);
  const report: ScoreReport = {
    app,
    tool: {
      name: input.runs[0]?.tool.name ?? "unknown",
      version: input.runs[0]?.tool.version,
      mode: input.runs[0]?.tool.mode,
    },
    runs: input.runs.map((r) => ({
      variant: (r.run.variant ?? "vuln") as Variant,
      target: r.run.target,
      findings: r.findings.length,
      duration_s: r.run.duration_s,
    })),
    counts: {
      gt_total: vulns.length,
      gt_reachable: reachable,
      gt_source_only: vulns.length - reachable,
      near_misses: gt.near_misses.length,
      findings_total: all.length,
      tp,
      fn,
      fp,
      fp_near_miss: fpByKind["near-miss"],
      fp_fixed_bug: fpByKind["fixed-bug"],
      fp_other: fpByKind.other,
      duplicates: duplicates.length,
      informational,
    },
    metrics: {
      precision,
      recall,
      f1: harmonic(precision, recall),
      recall_reachable: ratio(reachableTp, reachable),
      recall_exact_cwe: ratio(exactCwe, vulns.length),
      cwe_credit: ratio(creditSum, vulns.length),
      discrimination: gt.near_misses.length
        ? ratio(gt.near_misses.length - nmHit.size, gt.near_misses.length)
        : null,
      noise_ratio: ratio(duplicates.length, all.length),
      exploit_rate: ratio(exploitedTp, tp),
    },
    by_difficulty: orderBuckets(
      bucketize(vulns, found, (v) => v.difficulty ?? "?"),
      DIFFICULTY_ORDER,
    ),
    by_severity: orderBuckets(
      bucketize(vulns, found, (v) => v.severity ?? "?"),
      SEVERITY_ORDER,
    ),
    by_reachability: orderBuckets(
      bucketize(vulns, found, (v) => v.reachability ?? "?"),
      REACHABILITY_ORDER,
    ),
    by_taint: orderBuckets(bucketize(vulns, found, (v) => v.taint ?? "?"), TAINT_ORDER),
    // Opt-in: entries with no `discovery:` are dropped rather than bucketed as
    // "?", so an app that has not declared tiers reports nothing here at all
    // instead of one meaningless all-unknown row.
    by_discovery: orderBuckets(
      bucketize(vulns, found, (v) => v.discovery ?? null),
      DISCOVERY_ORDER,
    ),
    by_cwe: orderBuckets(bucketize(vulns, found, (v) => v.cwe ?? "?")),
    // the family the matcher actually credited against, not a second derivation
    by_family: orderBuckets(bucketize(anchors, found, (a) => a.family ?? "unclassified")),
    extra: extraBreakdowns(vulns, found),
    tracks: {
      discovery: discoveryTrack(
        vulns,
        vulnRun.map((t) => t.finding),
      ),
      // Needs a catalog AND a trace. Either one missing yields null rather than
      // a zero, because "we did not measure this" and "the tool reached nothing"
      // are opposite claims about the tool.
      coverage:
        input.surface && input.endpoints
          ? coverageTrack({
              surface: input.surface,
              reported: input.endpoints,
              evidenceSource: input.endpointsSource ?? "reported",
              variant: input.endpointsVariant ?? "vuln",
              vulns,
              foundVulnIds: new Set([...matchedGt].map((i) => vulns[i]!.id)),
            })
          : null,
    },
    matches,
    misses,
    false_positives: falsePositives,
    duplicates,
    warnings,
  };

  return report;
}
