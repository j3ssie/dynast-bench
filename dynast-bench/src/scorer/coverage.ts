/**
 * Endpoint coverage - did the tool reach the app's attack surface at all?
 *
 * A set diff between SURFACE.yaml (every deliberate operation the app exposes)
 * and what the tool says it discovered. Structurally the same as the network
 * discovery track next door, and kept in a separate track for the same reason:
 * it answers a different question from vulnerability F1 and must never be folded
 * into it.
 *
 * The payoff is the miss split. Vulnerability recall alone cannot tell you
 * whether a tool failed because it never found the endpoint or because it found
 * it and did not recognise the bug - and those two failures call for completely
 * different fixes. With a coverage trace they separate cleanly:
 *
 *   discovery miss   the operation carrying the bug was never reached
 *   analysis miss    the operation was reached and the bug was not reported
 *
 * `detection_given_touch` is the second number: recall restricted to the part of
 * the app the tool actually got to. A crawler that reaches 20% of an app and
 * finds every bug there scores badly on recall and perfectly here - which is the
 * honest description of a tool with a discovery problem rather than an analysis
 * one.
 */

import { opKey, opMatches, refKind, type MatchPass } from "../schema/operations.ts";
import type {
  GtVulnerability,
  ReportedEndpoint,
  Surface,
  SurfaceOperation,
  Variant,
} from "../schema/types.ts";
import { bucketize, DISCOVERY_ORDER, orderBuckets, ratio, REACHABILITY_ORDER, type Bucket } from "./metrics.ts";

/**
 * Where the coverage numbers came from. Always reported, because they are not
 * comparable across sources: `reported` is the tool's own inventory, `findings`
 * is only the operations it happened to file a bug against and so always
 * under-counts.
 */
export type EvidenceSource = "reported" | "findings";

export interface CoverageSlice {
  expected: number;
  touched: number;
  coverage: number | null;
}

export interface CoverageTrack {
  evidence_source: EvidenceSource;
  /** operations in the catalog that this variant actually exposes */
  operations: CoverageSlice;
  /** the externally addressable transport layer only - a crawler diagnostic */
  routes: CoverageSlice;
  vulnerable_operations: CoverageSlice;
  benign_operations: CoverageSlice;
  /** reported entries that hit a cataloged operation / everything reported */
  precision: number | null;
  reported: number;
  /** hits credited only after folding case, a slash or an unstated verb */
  loose_hits: number;
  by_kind: Record<string, Bucket>;
  by_discovery: Record<string, Bucket>;
  by_reachability: Record<string, Bucket>;
  touched: string[];
  untouched: string[];
  /** reported but in no catalog - diagnostics; these never reduce coverage */
  unknown: string[];
  /** recall over the bugs sitting on operations the tool actually reached */
  detection_given_touch: number | null;
  /** missed bugs whose operation was never reached */
  discovery_misses: string[];
  /** missed bugs whose operation WAS reached */
  analysis_misses: string[];
  /** bugs no catalog entry claims - excluded from the split above */
  unmapped_vulns: string[];
  warnings: string[];
}

export interface CoverageInput {
  surface: Surface;
  reported: ReportedEndpoint[];
  evidenceSource: EvidenceSource;
  /** which twin was scanned - an operation the fix removes is not expected on safe */
  variant?: Variant;
  /** the answer key, to map bugs onto operations */
  vulns?: GtVulnerability[];
  /** ids of the bugs the main matcher credited */
  foundVulnIds?: Set<string>;
}

/**
 * The transport layer: operations that are themselves externally addressable,
 * as opposed to the ones that ride on another (a GraphQL op, a WS event, an LLM
 * tool). Route coverage over this set is the crawler-level diagnostic; operation
 * coverage over everything is the headline.
 */
const isTransport = (op: SurfaceOperation): boolean =>
  !op.via && (op.kind === "http" || op.kind === "net");

const slice = (ops: SurfaceOperation[], touched: Set<string>): CoverageSlice => {
  const hit = ops.filter((o) => touched.has(o.id)).length;
  return { expected: ops.length, touched: hit, coverage: ratio(hit, ops.length) };
};

export function coverageTrack(input: CoverageInput): CoverageTrack {
  const warnings: string[] = [];
  const variant = input.variant ?? "vuln";

  // An operation a fix removes outright is not part of the safe twin's surface -
  // scoring it as missed would charge the tool for an endpoint that is not there.
  const expected = input.surface.operations.filter(
    (o) => (o.variant ?? "both") === "both" || o.variant === variant,
  );

  // keyed by operation id: presence IS "touched", the value is which pass paid
  const passById = new Map<string, MatchPass>();
  const unknown: string[] = [];
  let matchedReports = 0;

  for (const got of input.reported) {
    if (!refKind(got)) continue;
    let any = false;
    for (const want of expected) {
      const pass = opMatches(want, got);
      if (!pass) continue;
      any = true;
      // strict wins if anything ever matched strictly
      if (passById.get(want.id) !== "strict") passById.set(want.id, pass);
    }
    if (any) matchedReports++;
    else unknown.push(opKey(got));
  }

  const touchedIds = new Set(passById.keys());
  const inTrack = (op: SurfaceOperation) => touchedIds.has(op.id);
  const vulnerable = expected.filter((o) => (o.vulns ?? []).length > 0);
  const benign = expected.filter((o) => (o.vulns ?? []).length === 0);

  // --- the miss split --------------------------------------------------------
  // Only meaningful when we know both which bugs were found and which operation
  // each one sits on; without either, the two numbers would be fiction.
  const vulns = input.vulns ?? [];
  const found = input.foundVulnIds;
  const opsByVuln = new Map<string, SurfaceOperation[]>();
  for (const op of expected) {
    for (const id of op.vulns ?? []) {
      opsByVuln.set(id, [...(opsByVuln.get(id) ?? []), op]);
    }
  }

  const discoveryMisses: string[] = [];
  const analysisMisses: string[] = [];
  const unmapped: string[] = [];
  let onTouched = 0;
  let foundOnTouched = 0;

  if (vulns.length && found) {
    for (const v of vulns) {
      const ops = opsByVuln.get(v.id);
      if (!ops?.length) {
        unmapped.push(v.id);
        continue;
      }
      const reached = ops.some(inTrack);
      if (reached) {
        onTouched++;
        if (found.has(v.id)) foundOnTouched++;
      }
      if (found.has(v.id)) continue;
      (reached ? analysisMisses : discoveryMisses).push(v.id);
    }
    if (unmapped.length) {
      warnings.push(
        `${unmapped.length} vulnerability/ies map to no SURFACE.yaml operation - ` +
          `excluded from detection_given_touch and the miss split`,
      );
    }
  }

  const looseHits = [...passById.values()].filter((p) => p === "loose").length;
  if (looseHits) {
    warnings.push(
      `${looseHits} operation(s) credited on the loose pass only (folded case, a trailing ` +
        `slash or an unstated method) - on weirdproxy that can be a different endpoint`,
    );
  }
  if (input.evidenceSource === "findings") {
    warnings.push(
      "coverage derived from the findings file: only operations the tool filed a bug " +
        "against are counted, so this is a floor, not a measurement",
    );
  }
  if (!expected.length) warnings.push("SURFACE.yaml declares no operations for this variant");

  return {
    evidence_source: input.evidenceSource,
    operations: slice(expected, touchedIds),
    routes: slice(expected.filter(isTransport), touchedIds),
    vulnerable_operations: slice(vulnerable, touchedIds),
    benign_operations: slice(benign, touchedIds),
    precision: ratio(matchedReports, input.reported.length),
    reported: input.reported.length,
    loose_hits: looseHits,
    by_kind: orderBuckets(bucketize(expected, inTrack, (o) => o.kind)),
    by_discovery: orderBuckets(
      bucketize(expected, inTrack, (o) => o.discovery ?? null),
      DISCOVERY_ORDER,
    ),
    by_reachability: orderBuckets(
      bucketize(expected, inTrack, (o) => o.reachability ?? null),
      REACHABILITY_ORDER,
    ),
    touched: expected.filter(inTrack).map((o) => o.id).sort(),
    untouched: expected.filter((o) => !inTrack(o)).map((o) => o.id).sort(),
    unknown: [...new Set(unknown)].sort(),
    detection_given_touch: onTouched ? ratio(foundOnTouched, onTouched) : null,
    discovery_misses: discoveryMisses.sort(),
    analysis_misses: analysisMisses.sort(),
    unmapped_vulns: unmapped.sort(),
    warnings,
  };
}
