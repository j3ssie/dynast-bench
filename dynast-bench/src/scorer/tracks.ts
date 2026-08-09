/**
 * Extra scoring tracks.
 *
 * Some apps do not grade as "did you find the CWE at the route". The network
 * fleet grades as host+port discovery (benchmark-plans/network.md), and the two
 * LLM apps grade partly by which injection channel a tool can reach. Both run
 * alongside the main matcher rather than replacing it.
 */

import { isOpenState } from "../schema/keys.ts";
import type { Finding, GtVulnerability } from "../schema/types.ts";
import { findingAnchors, gtAnchors } from "./anchors.ts";
import { bucketize, ratio, type Bucket } from "./metrics.ts";

export interface DiscoveryTrack {
  /** host:port/proto the answer key says are open */
  expected: string[];
  /** what the tool reported */
  reported: string[];
  hit: string[];
  missed: string[];
  /** reported open but not in the key - a port that is not there */
  spurious: string[];
  precision: number | null;
  recall: number | null;
  /** version strings graded only where the key declares one */
  version: { scored: number; correct: number; accuracy: number | null };
}

const portKey = (host: string | null | undefined, port: number | null | undefined, proto?: string) =>
  `${(host ?? "*").toLowerCase()}:${port ?? "?"}/${(proto ?? "tcp").toLowerCase()}`;

/**
 * Set-diff on discovered ports. Only meaningful for an app whose key carries
 * `expected_open` (the network fleet); returns null otherwise.
 */
export function discoveryTrack(
  vulns: GtVulnerability[],
  findings: Finding[],
): DiscoveryTrack | null {
  const open = vulns.filter((v) => v.expected_open === true);
  if (!open.length) return null;

  const expected = new Map<string, GtVulnerability>();
  for (const v of open) {
    const a = gtAnchors(v);
    for (const n of a.net) expected.set(portKey(n.host, n.port, n.proto), v);
  }
  // ports the key explicitly marks as NOT open - reporting one is spurious
  const closed = new Set<string>();
  for (const v of vulns.filter((x) => x.expected_open === false)) {
    for (const n of gtAnchors(v).net) closed.add(portKey(n.host, n.port, n.proto));
  }

  const reported = new Map<string, string | undefined>(); // key -> version
  for (const f of findings) {
    for (const n of findingAnchors(f).net) {
      if (!isOpenState(n.state)) continue;
      reported.set(portKey(n.host, n.port, n.proto), n.version);
    }
  }

  const hit: string[] = [];
  const missed: string[] = [];
  let versionScored = 0;
  let versionCorrect = 0;

  for (const [key, v] of expected) {
    const declaredVersion = v.match?.net?.version;
    if (reported.has(key)) {
      hit.push(key);
      if (declaredVersion) {
        versionScored++;
        const got = reported.get(key) ?? "";
        if (got.toLowerCase().includes(String(declaredVersion).toLowerCase())) versionCorrect++;
      }
    } else {
      missed.push(key);
    }
  }
  const spurious = [...reported.keys()].filter((k) => !expected.has(k));

  return {
    expected: [...expected.keys()].sort(),
    reported: [...reported.keys()].sort(),
    hit: hit.sort(),
    missed: missed.sort(),
    spurious: spurious.sort(),
    precision: ratio(hit.length, hit.length + spurious.length),
    recall: ratio(hit.length, expected.size),
    version: {
      scored: versionScored,
      correct: versionCorrect,
      accuracy: ratio(versionCorrect, versionScored),
    },
  };
}

/**
 * Recall split by the stack-specific key an app happens to carry:
 * `injection_channel` and `tool` (llmagent/llmchat), `documented` (swagger),
 * `segment` (network), `transport` (websocket). Only keys present are reported.
 */
export function extraBreakdowns(
  vulns: GtVulnerability[],
  found: (v: GtVulnerability, index: number) => boolean,
): Record<string, Record<string, Bucket>> {
  const keys: [string, (v: GtVulnerability) => string | null][] = [
    ["by_injection_channel", (v) => (v.injection_channel ? String(v.injection_channel) : null)],
    ["by_tool", (v) => (v.tool ? String(v.tool) : null)],
    ["by_documented", (v) => (v.documented === undefined ? null : v.documented ? "documented" : "shadow")],
    ["by_segment", (v) => (v.segment ? String(v.segment) : null)],
    ["by_transport", (v) => (v.transport ? String(v.transport) : null)],
  ];

  const out: Record<string, Record<string, Bucket>> = {};
  for (const [name, keyOf] of keys) {
    const buckets = bucketize(vulns, found, keyOf);
    if (Object.keys(buckets).length) out[name] = buckets;
  }
  return out;
}
