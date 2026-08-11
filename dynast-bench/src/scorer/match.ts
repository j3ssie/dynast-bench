/**
 * The matcher: which reported finding corresponds to which planted bug.
 *
 * Tiers, highest signal first. A pair is only admissible if some tier fires AND
 * (for everything but proof) the reported CWE earns at least generic credit -
 * "something is wrong at /api/posts/search" with an unrelated CWE is a miss, not
 * a hit.
 *
 *   proof   a seed marker from the answer key appears in the finding's evidence
 *           and no anchor contradicts it            -> CWE-independent
 *   route   path (+ required query pairs, param, port, verb) line up
 *   net     host + port + proto line up
 *   api     graphql op / ws transport+event / llm tool+channel line up
 *   source  file matches and (symbol matches or the line sits in the bug's hunk)
 *   weak    path lines up only loosely (case/slash-folded) and the CWE agrees
 *
 * Assignment is one-to-one and maximises the number of matched bugs (Kuhn's
 * augmenting-path algorithm over admissible pairs, adjacency ordered by score),
 * so a tool cannot farm several credits from one bug and a good pairing is not
 * lost to a greedy first choice.
 */

import { bestCweCredit, type CweCredit } from "../schema/cwe.ts";
import {
  fileMatches,
  isOpenState,
  pathGlobMatches,
  symbolMatches,
  type HttpKey,
  type NetKey,
} from "../schema/keys.ts";
import type { Finding } from "../schema/types.ts";
import { findingAnchors, type Anchors, type GtAnchors } from "./anchors.ts";

export type Tier = "proof" | "route" | "net" | "api" | "source" | "weak";

/** How far a reported line may sit from the bug's own delta and still count. */
export const LINE_TOLERANCE = 2;

const TIER_WEIGHT: Record<Tier, number> = {
  proof: 6,
  route: 5,
  net: 5,
  api: 4,
  source: 4,
  weak: 1,
};

export interface Candidate {
  findingIndex: number;
  gtIndex: number;
  tier: Tier;
  score: number;
  cwe: CweCredit;
  /**
   * How precisely the ANCHORS line up, ignoring the CWE entirely. Comparable
   * between the bug anchors and the near-miss anchors, which is what lets a
   * near-miss veto a vaguer claim on the bug next door.
   */
  spec: number;
  /** short human trace of what lined up, e.g. "path+param q, marker" */
  why: string[];
}

// --------------------------------------------------------------- comparisons --

/**
 * A comparison that lined up. `null` means it did not - which removes the
 * representable-but-impossible states a `{hit, loose, why}` triple allowed.
 */
interface Verdict {
  loose: boolean;
  why: string[];
}

/** Does a found HTTP anchor satisfy a ground-truth HTTP anchor? */
function httpHit(gt: HttpKey, got: HttpKey): Verdict | null {
  const why: string[] = [];
  if (!gt.path || !got.path) return null;

  let loose = false;
  if (pathGlobMatches(gt.path, got.path, false)) {
    why.push("path");
  } else if (pathGlobMatches(gt.path, got.path, true)) {
    loose = true;
    why.push("path~"); // case- or slash-folded: weirdproxy plants those as distinct bugs
  } else {
    return null;
  }

  // a sidecar bug names its own port; a finding on a different port is elsewhere
  if (gt.port !== null && got.port !== null && gt.port !== got.port) return null;
  if (gt.port !== null && got.port === gt.port) why.push(`:${gt.port}`);

  // required query pairs (?action=bench_upload) must all be present
  for (const [k, v] of Object.entries(gt.query)) {
    const seen = got.query[k];
    // the name alone, with no value, is not enough to tell two actions apart
    if (seen === undefined || seen !== v) return null;
    why.push(`${k}=${v}`);
  }

  // the injectable parameter, when the key names one and the finding names one
  if (gt.params.length) {
    const reported = [...got.params, ...Object.keys(got.query)];
    if (reported.length) {
      const shared = gt.params.filter((p) => reported.includes(p));
      if (!shared.length) return null;
      why.push(`param ${shared.join(",")}`);
    }
  }

  if (gt.method && got.method && gt.method !== got.method) {
    // wrong verb on the right path: keep it, but only as a weak signal
    loose = true;
    why.push(`verb!=${gt.method}`);
  } else if (gt.method && got.method) {
    why.push(gt.method);
  }

  return { loose, why };
}

function netHit(gt: NetKey, got: NetKey & { state?: string }): Verdict | null {
  if (gt.port === null || got.port === null) return null;
  // "31337 closed" is an observation about a port that is not there, not a bug
  if (!isOpenState(got.state)) return null;
  if (gt.port !== got.port) return null;
  if (gt.proto && got.proto && gt.proto !== got.proto) return null;
  const why = [`:${gt.port}/${gt.proto}`];
  if (gt.host && got.host) {
    // hosts may be reported as a container name or an ip; require a loose overlap
    const a = gt.host.toLowerCase();
    const b = got.host.toLowerCase();
    if (a !== b && !a.includes(b) && !b.includes(a)) {
      return { loose: true, why: [...why, `host~${got.host}`] };
    }
    why.push(gt.host);
  }
  return { loose: false, why };
}

const looseEq = (a?: string, b?: string): boolean =>
  !!a && !!b && a.trim().toLowerCase() === b.trim().toLowerCase();

/** graphql op / ws transport+event+channel / llm tool+channel. Empty = no hit. */
function apiHit(gt: GtAnchors, got: Anchors): string[] {
  const why: string[] = [];

  for (const g of gt.graphql) {
    for (const f of got.graphql) {
      const opHit = looseEq(g.op, f.op) || looseEq(g.op, f.field) || symbolMatches(g.op, f.op);
      if (!opHit) continue;
      if (g.kind && f.kind && !looseEq(g.kind, f.kind)) continue;
      why.push(`gql ${g.op}`);
    }
  }
  for (const g of gt.ws) {
    for (const f of got.ws) {
      if (g.transport && f.transport && !looseEq(g.transport, f.transport)) continue;
      // every discriminator EITHER side names has to be corroborated by the
      // other. The channel is what separates two bugs on the same subscribe
      // frame: a key that names one is not answered by "subscribe frames are
      // unauthenticated", and a finding that names a channel the key never
      // mentions is describing some other bug on the same socket.
      const named = (["channel", "event", "endpoint"] as const);
      if (named.some((k) => (g[k] || f[k]) && !looseEq(g[k], f[k]))) continue;
      if (!g.transport && !named.some((k) => g[k])) continue;
      if (!f.transport && !named.some((k) => f[k])) continue;
      why.push(`ws ${g.channel ?? g.event ?? g.transport}`);
    }
  }
  for (const g of gt.llm) {
    for (const f of got.llm) {
      const toolHit = g.tool && f.tool ? looseEq(g.tool, f.tool) || symbolMatches(g.tool, f.tool) : false;
      const chanHit = g.channel && f.channel ? looseEq(g.channel, f.channel) : false;
      if (!toolHit && !chanHit) continue;
      // a tool name is specific; a channel alone is weak but real
      why.push(toolHit ? `tool ${g.tool}` : `channel ${g.channel}`);
    }
  }
  return why;
}

function sourceHit(gt: GtAnchors, got: Anchors): Verdict | null {
  for (const g of gt.file) {
    for (const f of got.file) {
      if (!fileMatches(g.path, f.path)) continue;
      const why = [`file ${g.path.replace(/^(?:vuln|safe)\//, "")}`];
      if (g.symbol && f.symbol && symbolMatches(g.symbol, f.symbol)) {
        return { loose: false, why: [...why, `symbol ${f.symbol}`] };
      }
      if (g.lines && f.lines) {
        // ±LINE_TOLERANCE: tools point at the sink, the call, or the assignment,
        // which are rarely the same line. Kept tight because adjacent lines are
        // adjacent BUGS in the flag-block apps (graphql plants one per line).
        const s = g.lines[0] - LINE_TOLERANCE;
        const e = g.lines[1] + LINE_TOLERANCE;
        const inside = f.lines[0] <= g.lines[1] && f.lines[1] >= g.lines[0];
        const overlaps = f.lines[0] <= e && f.lines[1] >= s;
        if (inside) return { loose: false, why: [...why, `line ${f.lines[0]}`] };
        if (overlaps) {
          // only inside once padded - real, but a near-miss owning that exact line
          // outranks it (see the veto in score.ts)
          return { loose: false, why: [...why, `line ${f.lines[0]}~`] };
        }
        // a line outside the bug's own delta, in a file holding many bugs, is not
        // this bug - keep the pair but only as a weak signal
        return { loose: true, why: [...why, `line ${f.lines[0]} outside ${g.lines[0]}-${g.lines[1]}`] };
      }
      // file agrees, nothing finer available
      return { loose: true, why };
    }
  }
  return null;
}

/** Would either side's anchors flatly contradict the other? Used to gate proof. */
function contradicts(gt: GtAnchors, got: Anchors): boolean {
  if (gt.http.length && got.http.length) {
    if (!gt.http.some((g) => got.http.some((f) => httpHit(g, f)))) return true;
  }
  if (gt.net.length && got.net.length) {
    if (!gt.net.some((g) => got.net.some((f) => netHit(g, f)))) return true;
  }
  if (gt.file.length && got.file.length && !got.http.length) {
    const any = gt.file.some((g) => got.file.some((f) => fileMatches(g.path, f.path)));
    if (!any) return true;
  }
  return false;
}

// ----------------------------------------------------------------- candidates --

export interface CandidateOpts {
  /** admit route/source matches whose CWE earns nothing (default false) */
  lenientCwe?: boolean;
}

/** Every admissible (finding, bug) pair, with its tier and CWE credit. */
export function candidatesFor(
  findings: Finding[],
  gt: GtAnchors[],
  opts: CandidateOpts = {},
): Candidate[] {
  const out: Candidate[] = [];
  const anchors = findings.map(findingAnchors);

  for (let fi = 0; fi < findings.length; fi++) {
    for (let gi = 0; gi < gt.length; gi++) {
      const c = pairFor(fi, findings[fi]!, anchors[fi]!, gi, gt[gi]!, opts);
      if (c) out.push(c);
    }
  }

  // deterministic: best score first, then tier, then stable by index
  out.sort(
    (a, b) =>
      b.score - a.score ||
      TIER_WEIGHT[b.tier] - TIER_WEIGHT[a.tier] ||
      a.findingIndex - b.findingIndex ||
      a.gtIndex - b.gtIndex,
  );
  return out;
}

/**
 * One (finding, bug) pair, or null when nothing lines up or the reported CWE
 * disqualifies it.
 *
 * The promotion order below is load-bearing and deliberately not a plain
 * best-tier-wins: proof short-circuits everything; an http hit replaces whatever
 * `why` came before it; net only upgrades a weak verdict; api and source append.
 */
function pairFor(
  fi: number,
  f: Finding,
  got: Anchors,
  gi: number,
  g: GtAnchors,
  opts: CandidateOpts,
): Candidate | null {
  const why: string[] = [];
  let tier: Tier | null = null;
  let loose = false;

  // proof: a marker this bug is known to leak
  const sharedMarkers = g.markers.filter((m) =>
    got.markers.some((x) => x.includes(m) || m.includes(x)),
  );
  if (sharedMarkers.length && !contradicts(g, got)) {
    tier = "proof";
    why.push(`marker ${sharedMarkers[0]}`);
  }

  if (!tier) {
    for (const gh of g.http) {
      for (const fh of got.http) {
        const v = httpHit(gh, fh);
        if (!v) continue;
        if (!tier || TIER_WEIGHT[tier] < TIER_WEIGHT.route) {
          tier = v.loose ? "weak" : "route";
          loose = v.loose;
          why.length = 0;
          why.push(...v.why);
        }
      }
    }
  }
  if (!tier || tier === "weak") {
    for (const gn of g.net) {
      for (const fn of got.net) {
        const v = netHit(gn, fn);
        if (!v) continue;
        tier = v.loose ? "weak" : "net";
        loose = v.loose;
        why.push(...v.why);
      }
    }
  }
  const api = apiHit(g, got);
  if (api.length) {
    why.push(...api);
    if (!tier || TIER_WEIGHT[tier] < TIER_WEIGHT.api) {
      tier = "api";
      loose = false;
    }
  }
  const src = sourceHit(g, got);
  if (src) {
    why.push(...src.why);
    if (!tier) {
      tier = src.loose ? "weak" : "source";
      loose = src.loose;
    } else if (tier === "weak" && !src.loose) {
      tier = "source";
      loose = false;
    }
  }

  if (!tier) return null;

  // Credit is only worth computing once something lined up - over half of all
  // pairs bail out above.
  const reported = [f.cwe, ...(f.cwes ?? [])];
  const cwe = bestCweCredit(reported, g.cwe, {
    aliases: g.cweAliases,
    expectedFamily: g.family,
  });

  if (tier !== "proof" && !opts.lenientCwe) {
    // A wrong claim is a wrong answer: "crypto failure at /goto" is not the
    // open redirect. But SILENCE is not a wrong answer - plenty of DAST tools
    // map CWEs poorly - so an unclassified finding still earns the bug when it
    // pins the anchor precisely, and simply earns no classification credit.
    const claimed = reported.some(Boolean);
    if (claimed && cwe.weight === 0) return null;
    if (!claimed && (tier === "weak" || (tier === "source" && loose))) return null;
  }

  return {
    findingIndex: fi,
    gtIndex: gi,
    tier,
    cwe,
    why,
    ...weigh({
      tier,
      cwe,
      why,
      loose,
      proven: f.exploited === true,
      marker: sharedMarkers.length > 0,
      api: api.length > 0,
      sourceExact: !!src && !src.loose,
    }),
  };
}

/**
 * `score` ranks candidates for the assignment; `spec` measures how precisely the
 * ANCHORS line up with the CWE excluded, so it stays comparable between the bug
 * anchors and the near-miss anchors (which carry no CWE at all).
 */
function weigh(x: {
  tier: Tier;
  cwe: CweCredit;
  why: string[];
  loose: boolean;
  proven: boolean;
  marker: boolean;
  api: boolean;
  sourceExact: boolean;
}): { score: number; spec: number } {
  const has = (prefix: string) => x.why.some((w) => w.startsWith(prefix));
  const exactLine = x.why.some((w) => /^line \d+$/.test(w));
  const base = TIER_WEIGHT[x.tier];

  const bonus =
    (x.marker ? 1 : 0) +
    (x.proven ? 0.5 : 0) +
    (has("param ") ? 0.5 : 0) +
    (has("symbol ") ? 0.5 : 0) +
    (x.why.some((w) => w.startsWith("line ") && !w.includes("outside")) ? 0.5 : 0) +
    (x.api ? 0.5 : 0) +
    (x.sourceExact ? 0.25 : 0);

  return {
    score: base + x.cwe.weight * 2 + bonus - (x.loose ? 0.5 : 0),
    spec:
      base +
      (exactLine ? 1 : 0) +
      (has("symbol ") ? 0.5 : 0) +
      (has("param ") ? 0.5 : 0) +
      (x.marker ? 1 : 0) -
      (x.loose ? 1 : 0),
  };
}

// ----------------------------------------------------------------- assignment --

export interface Assignment {
  /** findingIndex -> candidate that won it */
  byFinding: Map<number, Candidate>;
  /** gtIndex -> candidate that won it */
  byGt: Map<number, Candidate>;
  /**
   * Findings that had an admissible pair but lost it to a better finding, and
   * whose bug was matched anyway - noise, not a false alarm.
   */
  duplicates: Map<number, Candidate>;
}

/**
 * Max-cardinality one-to-one assignment (Kuhn's algorithm). Adjacency is ordered
 * by score, so among the pairings that match the most bugs we take high-signal
 * edges first.
 */
export function assign(candidates: Candidate[], findingCount: number): Assignment {
  const adj = new Map<number, Candidate[]>();
  for (const c of candidates) {
    const list = adj.get(c.findingIndex);
    if (list) list.push(c);
    else adj.set(c.findingIndex, [c]);
  }

  /** gtIndex -> findingIndex currently holding it */
  const gtOwner = new Map<number, number>();
  const chosen = new Map<number, Candidate>();

  const tryAssign = (fi: number, seen: Set<number>): boolean => {
    for (const cand of adj.get(fi) ?? []) {
      if (seen.has(cand.gtIndex)) continue;
      seen.add(cand.gtIndex);
      const owner = gtOwner.get(cand.gtIndex);
      if (owner === undefined || tryAssign(owner, seen)) {
        gtOwner.set(cand.gtIndex, fi);
        chosen.set(fi, cand);
        return true;
      }
    }
    return false;
  };

  // findings with the strongest single candidate go first
  const order = [...adj.keys()].sort((a, b) => {
    const sa = adj.get(a)![0]!.score;
    const sb = adj.get(b)![0]!.score;
    return sb - sa || a - b;
  });
  for (const fi of order) tryAssign(fi, new Set());

  const byFinding = new Map<number, Candidate>();
  const byGt = new Map<number, Candidate>();
  for (const [fi, cand] of chosen) {
    // tryAssign may have re-homed an earlier finding; trust gtOwner
    if (gtOwner.get(cand.gtIndex) !== fi) continue;
    byFinding.set(fi, cand);
    byGt.set(cand.gtIndex, cand);
  }
  // a re-homed finding keeps whichever bug it actually owns
  for (const [gi, fi] of gtOwner) {
    if (byFinding.has(fi)) continue;
    const cand = (adj.get(fi) ?? []).find((c) => c.gtIndex === gi);
    if (cand) {
      byFinding.set(fi, cand);
      byGt.set(gi, cand);
    }
  }

  const duplicates = new Map<number, Candidate>();
  for (let fi = 0; fi < findingCount; fi++) {
    if (byFinding.has(fi)) continue;
    const dup = (adj.get(fi) ?? []).find((c) => byGt.has(c.gtIndex));
    if (dup) duplicates.set(fi, dup);
  }

  return { byFinding, byGt, duplicates };
}
