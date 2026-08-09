/**
 * Derived numbers. Kept separate from the matching so the definitions are in one
 * readable place - every one of these is a claim about a tool, so it has to be
 * defensible.
 */

import { DIFFICULTIES, REACHABILITIES, SEVERITIES, TAINTS } from "../schema/types.ts";

export interface Bucket {
  gt: number;
  tp: number;
  recall: number | null;
}

export const ratio = (num: number, den: number): number | null =>
  den === 0 ? null : Math.round((num / den) * 10000) / 10000;

export const f1 = (precision: number | null, recall: number | null): number | null => {
  if (precision === null || recall === null) return null;
  if (precision + recall === 0) return 0;
  return Math.round(((2 * precision * recall) / (precision + recall)) * 10000) / 10000;
};

/**
 * Group ground-truth entries by a key and count how many were found.
 * `keyOf` returning null drops the entry from that breakdown.
 */
export function bucketize<T>(
  items: T[],
  found: (item: T, index: number) => boolean,
  keyOf: (item: T) => string | null,
): Record<string, Bucket> {
  const out: Record<string, Bucket> = {};
  items.forEach((item, i) => {
    const key = keyOf(item);
    if (key === null) return;
    const b = (out[key] ??= { gt: 0, tp: 0, recall: null });
    b.gt++;
    if (found(item, i)) b.tp++;
  });
  for (const b of Object.values(out)) b.recall = ratio(b.tp, b.gt);
  return out;
}

/** Sort a breakdown so the report reads in a fixed order, not hash order. */
export function orderBuckets(
  buckets: Record<string, Bucket>,
  order?: string[],
): Record<string, Bucket> {
  const keys = Object.keys(buckets);
  const rank = (k: string) => {
    const i = order?.indexOf(k) ?? -1;
    return i === -1 ? order?.length ?? 0 : i;
  };
  keys.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
  return Object.fromEntries(keys.map((k) => [k, buckets[k]!]));
}

// The report's sort order is the validator's vocabulary - one definition, so a new
// reachability value cannot silently sort last in every report.
export const DIFFICULTY_ORDER = DIFFICULTIES;
export const SEVERITY_ORDER = [...SEVERITIES].reverse();
export const REACHABILITY_ORDER = REACHABILITIES;
export const TAINT_ORDER = TAINTS;
