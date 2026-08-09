/**
 * Human rendering of a ScoreReport. Returns lines so the CLI owns printing (and
 * --json never has to route around this).
 */

import type { Bucket } from "./metrics.ts";
import type { ScoreReport } from "./score.ts";

const pct = (v: number | null): string => (v === null ? "  n/a" : `${(v * 100).toFixed(1)}%`);

const bar = (v: number | null, width = 20): string => {
  if (v === null) return " ".repeat(width);
  const n = Math.round(v * width);
  return "█".repeat(n) + "·".repeat(width - n);
};

function bucketLines(title: string, buckets: Record<string, Bucket>, indent = "  "): string[] {
  const keys = Object.keys(buckets);
  if (!keys.length) return [];
  const width = Math.max(...keys.map((k) => k.length));
  return [
    `${indent}${title}`,
    ...keys.map((k) => {
      const b = buckets[k]!;
      return `${indent}  ${k.padEnd(width)}  ${String(b.tp).padStart(3)}/${String(b.gt).padEnd(3)} ${bar(b.recall, 12)} ${pct(b.recall)}`;
    }),
  ];
}

export interface RenderOpts {
  /** show every match/miss/false-positive row, not just a summary */
  full?: boolean;
  /** cap on detail rows when not full */
  limit?: number;
}

export function renderReport(r: ScoreReport, opts: RenderOpts = {}): string[] {
  const limit = opts.limit ?? 10;
  const out: string[] = [];
  const m = r.metrics;
  const c = r.counts;

  const runs = r.runs
    .map((x) => `${x.variant}${x.findings ? `(${x.findings})` : "(0)"}`)
    .join(" + ");
  out.push(`${r.app}  ·  ${r.tool.name}${r.tool.version ? " " + r.tool.version : ""}${r.tool.mode ? ` [${r.tool.mode}]` : ""}  ·  runs: ${runs}`);
  out.push("");

  out.push(`  precision   ${bar(m.precision)}  ${pct(m.precision)}   ${c.tp} tp / ${c.fp} fp`);
  out.push(`  recall      ${bar(m.recall)}  ${pct(m.recall)}   ${c.tp} of ${c.gt_total} planted`);
  out.push(`  f1          ${bar(m.f1)}  ${pct(m.f1)}`);
  if (c.gt_source_only) {
    out.push(
      `  recall*     ${bar(m.recall_reachable)}  ${pct(m.recall_reachable)}   over the ${c.gt_reachable} reachable over http/net (${c.gt_source_only} are source-only)`,
    );
  }
  out.push("");
  out.push(`  cwe exact   ${pct(m.recall_exact_cwe)} of all planted bugs · mean credit ${pct(m.cwe_credit)}`);
  if (m.discrimination !== null) {
    const hits = c.near_misses - Math.round((m.discrimination ?? 0) * c.near_misses);
    out.push(
      `  discrim.    ${pct(m.discrimination)}   ${hits}/${c.near_misses} near-misses flagged as bugs`,
    );
  }
  out.push(
    `  noise       ${pct(m.noise_ratio)}   ${c.duplicates} duplicate findings (excluded from precision)`,
  );
  if (m.exploit_rate !== null) {
    out.push(`  proven      ${pct(m.exploit_rate)}   of true positives carried proof of impact`);
  }
  out.push("");
  out.push(
    `  false positives: ${c.fp}  (near-miss ${c.fp_near_miss} · patched-twin ${c.fp_fixed_bug} · other ${c.fp_other})`,
  );
  if (c.informational) {
    out.push(`  informational:   ${c.informational}  (closed/filtered ports - not scored)`);
  }

  out.push("");
  out.push(...bucketLines("recall by difficulty", r.by_difficulty));
  out.push("");
  out.push(...bucketLines("recall by severity", r.by_severity));
  out.push("");
  out.push(...bucketLines("recall by reachability", r.by_reachability));
  if (opts.full) {
    out.push("");
    out.push(...bucketLines("recall by taint", r.by_taint));
    out.push("");
    out.push(...bucketLines("recall by cwe family", r.by_family));
    for (const [name, buckets] of Object.entries(r.extra)) {
      out.push("");
      out.push(...bucketLines(name.replace(/_/g, " "), buckets));
    }
  }

  const d = r.tracks.discovery;
  if (d) {
    out.push("");
    out.push("  discovery track (host+port)");
    out.push(
      `    ports       ${d.hit.length}/${d.expected.length} found · ${d.spurious.length} spurious · precision ${pct(d.precision)} · recall ${pct(d.recall)}`,
    );
    if (d.version.scored) {
      out.push(
        `    versions    ${d.version.correct}/${d.version.scored} correct · ${pct(d.version.accuracy)}`,
      );
    }
    if (d.missed.length) out.push(`    missed      ${d.missed.slice(0, 12).join(" ")}`);
    if (d.spurious.length) out.push(`    spurious    ${d.spurious.slice(0, 12).join(" ")}`);
  }

  const show = <T>(rows: T[]) => (opts.full ? rows : rows.slice(0, limit));

  /** One block: heading, the rows that fit, and an honest note about the rest. */
  const section = <T>(title: string, rows: T[], fmt: (x: T) => string, fullOnly = false) => {
    if (!rows.length || (fullOnly && !opts.full)) return;
    out.push("", `  ${title} (${rows.length})`, ...show(rows).map(fmt));
    if (rows.length > limit && !opts.full) out.push(`    … ${rows.length - limit} more (--full)`);
  };

  section("matched", r.matches, (x) => {
    const credit =
      x.cwe_credit === 1 ? "" : `  cwe ${x.cwe_reported ?? "-"}≠${x.cwe_expected} (${x.cwe_credit})`;
    return `    ${x.gt_id.padEnd(22)} ${x.tier.padEnd(6)} ${x.finding_id.padEnd(14)} ${x.why}${credit}`;
  });

  section("missed", r.misses, (x) => {
    const tag = x.source_only ? " [source-only]" : "";
    const near = x.closest
      ? `  ~ ${x.closest.finding_id} (${x.closest.tier}, cwe ${x.closest.cwe_reported ?? "-"})`
      : "";
    return `    ${x.gt_id.padEnd(22)} ${(x.cwe ?? "").padEnd(9)} ${(x.difficulty ?? "").padEnd(4)} ${(x.route ?? "").slice(0, 44)}${tag}${near}`;
  });

  section(
    "false positives",
    r.false_positives,
    (x) =>
      `    ${x.finding_id.padEnd(16)} ${x.variant.padEnd(4)} ${x.kind.padEnd(10)} ${(x.cwe ?? "-").padEnd(9)} ${x.where}${x.hit ? `  -> ${x.hit}` : ""}`,
  );

  section("duplicates", r.duplicates, (x) => `    ${x.finding_id.padEnd(16)} -> ${x.gt_id}`, true);

  if (r.warnings.length) {
    out.push("");
    for (const w of r.warnings) out.push(`  !! ${w}`);
  }

  return out;
}
