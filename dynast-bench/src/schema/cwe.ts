/**
 * CWE families - the partial-credit device.
 *
 * Two CWEs in the same family are "the same bug seen slightly differently", so a
 * finding that names a sibling of the planted CWE earns HALF credit instead of
 * nothing. Every CWE used by the 18 answer keys is assigned to exactly one
 * family; the extra entries are CWEs scanners commonly emit for the same sinks.
 *
 * Generic parents (CWE-20 "improper input validation" and friends) are not a
 * family - a tool that says only "untrusted input" located the sink but did not
 * classify it, which is worth a quarter.
 */

export type CweCreditKind = "exact" | "alias" | "family" | "generic" | "none";

export interface CweCredit {
  kind: CweCreditKind;
  /** 1.0 exact/alias · 0.5 same family · 0.25 generic parent · 0 unrelated */
  weight: number;
  family: string | null;
}

/**
 * family -> the CWEs that belong to it. Every CWE appearing in an answer key is
 * here; the rest are what scanners tend to report for the same sink.
 * A CWE listed under two families keeps the FIRST one (see FAMILY_OF below).
 */
const FAMILIES: Record<string, number[]> = {
  sqli: [89, 943, 564, 90],
  "command-injection": [78, 94, 95, 917, 1336, 470],
  xss: [79, 80, 83, 87],
  traversal: [22, 98, 706, 23, 36, 73],
  ssrf: [918],
  xxe: [611, 776, 827],
  deserialization: [502, 494],
  "object-mutation": [915, 1321, 1188],
  upload: [434, 646],
  authz: [862, 863, 285, 284, 639, 269, 288, 668, 807, 425, 566],
  authn: [287, 290, 306, 307, 384, 613, 640, 347, 345, 348, 302, 620],
  credentials: [798, 1392, 522, 321, 259, 260],
  "info-leak": [200, 209, 532, 538, 540, 548, 598, 117, 215, 497, 651],
  csrf: [352, 1385, 1275],
  cors: [942, 346],
  "open-redirect": [601],
  crypto: [327, 295, 319, 330, 338, 614, 326, 328, 916, 757],
  race: [362, 367, 366],
  dos: [400, 770, 674, 406, 405, 1050],
  "proxy-desync": [436, 441, 444],
  cache: [349, 524, 525],
  logic: [840, 697, 184, 693, 625, 841],
  misconfig: [489, 1327, 1059, 16, 756, 1004],
  components: [1035, 1104, 1395, 937],
  enumeration: [204, 203, 208],
  "prompt-injection": [1427, 1426],
};

/** Real weaknesses, but too abstract to count as a classification. */
const GENERIC_PARENTS = new Set([20, 74, 116, 664, 707, 710, 1215, 1287, 1284]);

const FAMILY_OF = new Map<number, string>();
for (const [family, ids] of Object.entries(FAMILIES)) {
  for (const id of ids) if (!FAMILY_OF.has(id)) FAMILY_OF.set(id, family);
}

/** How a CWE id is written in free text, anywhere a tool might put it. */
export const CWE_ID_RE = /cwe[-_\s:]*(\d{1,5})/i;

/**
 * "cwe-89", "CWE_89", 89, " 89 " -> "CWE-89"; unparseable -> null.
 * Memoized: credit is computed for every (finding, bug) pair, so this runs
 * ~200k times per scoring pass over a vocabulary of a few hundred strings.
 */
export function normalizeCwe(raw: unknown): string | null {
  if (raw === null || raw === undefined) return null;
  const key = String(raw);
  const hit = normalizeCache.get(key);
  if (hit !== undefined) return hit;
  const out = computeNormalizeCwe(key);
  normalizeCache.set(key, out);
  return out;
}

const normalizeCache = new Map<string, string | null>();

function computeNormalizeCwe(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;
  const m = s.match(/(\d{1,5})/);
  if (!m) return null;
  // Guard against picking a year or an OWASP index out of e.g. "A03:2021".
  if (/^A\d{1,2}:\d{4}/i.test(s) || /^API\d{1,2}:\d{4}/i.test(s) || /^LLM\d{1,2}:\d{4}/i.test(s)) {
    return null;
  }
  return `CWE-${Number(m[1])}`;
}

export const cweNumber = (cwe: string | null | undefined): number | null => {
  const n = normalizeCwe(cwe);
  return n ? Number(n.slice(4)) : null;
};

/** The family a CWE belongs to, or null if it is generic/unknown. */
export function cweFamily(cwe: string | null | undefined): string | null {
  const n = cweNumber(cwe);
  return n === null ? null : (FAMILY_OF.get(n) ?? null);
}

export const isGenericCwe = (cwe: string | null | undefined): boolean => {
  const n = cweNumber(cwe);
  return n !== null && GENERIC_PARENTS.has(n);
};

/**
 * How much credit a reported CWE earns against the planted one.
 * `expectedFamily` overrides the table (VULNERABILITIES.yaml `match.cwe_family`),
 * `aliases` are extra fully-correct answers (`match.cwe_aliases`).
 */
export function cweCredit(
  reported: string | null | undefined,
  expected: string | null | undefined,
  opts: { aliases?: string[]; expectedFamily?: string | null } = {},
): CweCredit {
  const want = normalizeCwe(expected);
  const got = normalizeCwe(reported);
  const wantFamily = opts.expectedFamily ?? cweFamily(want);

  if (!got) return { kind: "none", weight: 0, family: wantFamily };
  if (want && got === want) return { kind: "exact", weight: 1, family: wantFamily };

  const aliases = (opts.aliases ?? []).map(normalizeCwe).filter(Boolean) as string[];
  if (aliases.includes(got)) return { kind: "alias", weight: 1, family: wantFamily };

  const gotFamily = cweFamily(got);
  if (wantFamily && gotFamily && gotFamily === wantFamily) {
    return { kind: "family", weight: 0.5, family: wantFamily };
  }
  if (isGenericCwe(got)) return { kind: "generic", weight: 0.25, family: wantFamily };
  return { kind: "none", weight: 0, family: wantFamily };
}

/** Best credit across a finding's primary + alternate CWEs. */
export function bestCweCredit(
  reported: (string | null | undefined)[],
  expected: string | null | undefined,
  opts: { aliases?: string[]; expectedFamily?: string | null } = {},
): CweCredit {
  let best: CweCredit = { kind: "none", weight: 0, family: opts.expectedFamily ?? cweFamily(expected) };
  for (const r of reported) {
    const c = cweCredit(r, expected, opts);
    if (c.weight > best.weight) best = c;
  }
  return best;
}
