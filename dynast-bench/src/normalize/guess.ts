/**
 * Shared helpers for the adapters.
 *
 * Most scanners hand over a title and little else, so `guessCwe` maps issue
 * names onto CWEs by keyword. It is a fallback: a tool's own CWE id always wins.
 * Order matters - the first pattern that hits wins, so put the specific phrases
 * above the general ones.
 */

import { CWE_ID_RE, normalizeCwe } from "../schema/cwe.ts";

const RULES: [RegExp, string][] = [
  [/blind\s+sql|sql\s*injection|sqli\b|sql\s+syntax/i, "CWE-89"],
  [/nosql|mongo\s*injection/i, "CWE-943"],
  [/os\s*command|command\s*injection|shell\s*injection|rce\b|remote\s+code\s+exec/i, "CWE-78"],
  [/template\s*injection|ssti\b|spel|ognl/i, "CWE-1336"],
  [/expression\s*language/i, "CWE-917"],
  [/code\s*injection|eval\b/i, "CWE-94"],
  [/deserializ|pickle|unmarshal|gadget\s*chain/i, "CWE-502"],
  [/prototype\s*pollution/i, "CWE-1321"],
  [/mass\s*assign/i, "CWE-915"],
  [/stored\s+xss|reflected\s+xss|cross[- ]site\s+script|\bxss\b/i, "CWE-79"],
  [/xxe\b|xml\s+external\s+entity/i, "CWE-611"],
  [/path\s*travers|directory\s*travers|\blfi\b|local\s+file\s+inclusion|zip\s*slip/i, "CWE-22"],
  [/remote\s+file\s+inclusion|\brfi\b/i, "CWE-98"],
  [/\bssrf\b|server[- ]side\s+request/i, "CWE-918"],
  [/open\s*redirect|unvalidated\s+redirect/i, "CWE-601"],
  [/\bcsrf\b|cross[- ]site\s+request\s+forgery/i, "CWE-352"],
  [/websocket\s+hijack|cswsh/i, "CWE-1385"],
  [/\bcors\b|cross[- ]origin\s+resource\s+sharing|access-control-allow-origin|cross[- ]domain\s+(?:misconfig|policy)/i, "CWE-942"],
  [/cache\s+poison/i, "CWE-349"],
  [/request\s+smuggl|desync|interpretation\s+conflict/i, "CWE-436"],
  [/\bidor\b|insecure\s+direct\s+object|object\s+level\s+authoriz|\bbola\b/i, "CWE-639"],
  [/missing\s+(?:function\s+level\s+)?authoriz|missing\s+access\s+control|broken\s+access/i, "CWE-862"],
  [/privilege\s+escalat|improper\s+privilege/i, "CWE-269"],
  [/auth(?:enticat|oriz)ion\s+bypass|auth\s+bypass/i, "CWE-288"],
  [/missing\s+authentication/i, "CWE-306"],
  [/brute\s*force|rate\s*limit|excessive\s+auth/i, "CWE-307"],
  [/session\s+fixation/i, "CWE-384"],
  [/session\s+(?:expir|timeout)/i, "CWE-613"],
  [/password\s+reset|password\s+recovery/i, "CWE-640"],
  [/\bjwt\b|signature\s+(?:not\s+)?verif|alg\s*[:=]\s*none/i, "CWE-347"],
  [/username\s+enumerat|user\s+enumerat|account\s+enumerat|response\s+discrepanc/i, "CWE-204"],
  [/hard[- ]?cod(?:ed)?\s+(?:credential|password|secret|key)|api\s*key\s+(?:leak|expos|disclos)/i, "CWE-798"],
  [/default\s+credential|weak\s+credential|admin\s*[:\/]\s*admin/i, "CWE-1392"],
  [/insufficiently\s+protected\s+credential|cleartext\s+password/i, "CWE-522"],
  [/private\s+key|crypto\s+key\s+hard/i, "CWE-321"],
  [/source\s*map|source\s+code\s+disclos/i, "CWE-540"],
  [/directory\s+listing|directory\s+brows/i, "CWE-548"],
  [/backup\s+file|\.bak\b|env\s+file|configuration\s+file\s+expos/i, "CWE-538"],
  [/stack\s+trace|verbose\s+error|error\s+message\s+(?:leak|disclos)|debug\s+(?:info|page)/i, "CWE-209"],
  [/log\s+injection|log\s+forging/i, "CWE-117"],
  [/sensitive\s+(?:data|info)\s+in\s+log/i, "CWE-532"],
  [/information\s+(?:leak|disclos|expos)|sensitive\s+data\s+expos/i, "CWE-200"],
  [/debug\s+(?:code|mode|enabled)|actuator|phpinfo/i, "CWE-489"],
  [/weak\s+cipher|weak\s+ssl|weak\s+tls|sslv|rc4|3des/i, "CWE-327"],
  [/(?:certificate|cert)\s+(?:expired|invalid|self[- ]signed|mismatch)/i, "CWE-295"],
  [/cleartext\s+(?:transmission|http)|unencrypted|missing\s+https/i, "CWE-319"],
  [/(?:weak|insecure|predictable)\s+(?:random|prng|token|session\s+id)/i, "CWE-330"],
  [/math\.random|rand\(\)/i, "CWE-338"],
  [/cookie\s+without\s+secure|missing\s+secure\s+flag|httponly/i, "CWE-614"],
  [/race\s+condition|toctou|check.{0,10}(?:then|before).{0,10}use/i, "CWE-362"],
  [/unrestricted\s+(?:file\s+)?upload|arbitrary\s+file\s+(?:upload|write)/i, "CWE-434"],
  [/(?:denial\s+of\s+service|\bdos\b|resource\s+exhaust|unbounded)/i, "CWE-400"],
  [/(?:query\s+)?(?:depth|complexity|cost)\s+limit|no\s+pagination/i, "CWE-770"],
  [/recursion/i, "CWE-674"],
  [/business\s+logic|negative\s+(?:quantity|amount|price)/i, "CWE-840"],
  [/prompt\s*injection|jailbreak|indirect\s+injection/i, "CWE-1427"],
  [/excessive\s+agency|unrestricted\s+tool/i, "CWE-78"],
  [/introspect|schema\s+expos|field\s+suggestion/i, "CWE-200"],
  [/outdated|known\s+vulnerab|vulnerable\s+(?:component|dependenc|librar)|\bcve-/i, "CWE-1104"],
  [/graphql\s+batch/i, "CWE-770"],
];

/** Best-effort CWE from free text. Returns null when nothing is confident. */
export function guessCwe(...texts: (string | undefined | null)[]): string | null {
  const blob = texts.filter(Boolean).join(" \n ");
  if (!blob.trim()) return null;
  // an explicit id anywhere in the text always wins over the keyword table
  const explicit = blob.match(CWE_ID_RE);
  if (explicit) return normalizeCwe(explicit[0]);
  for (const [re, cwe] of RULES) if (re.test(blob)) return cwe;
  return null;
}

/** Pull a CWE out of whatever shape a tool put it in (id, list, tag strings). */
export function cweFromAny(...values: unknown[]): string | null {
  for (const v of values) {
    if (v === null || v === undefined) continue;
    if (Array.isArray(v)) {
      for (const x of v) {
        const c = cweFromAny(x);
        if (c) return c;
      }
      continue;
    }
    const c = normalizeCwe(typeof v === "object" ? JSON.stringify(v) : v);
    if (c && c !== "CWE-0") return c;
  }
  return null;
}

/** Every CWE id mentioned, deduped and in order. */
export function allCwes(...values: unknown[]): string[] {
  const blob = values
    .map((v) => (typeof v === "object" && v !== null ? JSON.stringify(v) : String(v ?? "")))
    .join(" ");
  const out: string[] = [];
  for (const m of blob.matchAll(new RegExp(CWE_ID_RE, "gi"))) {
    const id = normalizeCwe(m[0]);
    if (id && id !== "CWE-0" && !out.includes(id)) out.push(id);
  }
  return out;
}

/**
 * The marker every app seeds (CLAUDE.md's shared domain). Per-app markers are NOT
 * listed here - they live in each answer key's `match.markers`, and the scorer
 * passes that vocabulary in, so this is only the floor.
 */
export const SEED_MARKERS = ["GLOBEX-CONFIDENTIAL-MARKER-7f3a"];

/**
 * Markers observed in a scanner's evidence text. `vocabulary` is the union of the
 * answer key's `match.markers`, which is what makes the `proof` tier reachable for
 * apps whose markers are app-specific (XXE-LOCAL-FILE-MARKER-jsp-42 and friends).
 */
export function markersIn(
  vocabulary: readonly string[],
  ...texts: (string | undefined | null)[]
): string[] {
  const blob = texts.filter(Boolean).join(" \n ");
  if (!blob) return [];
  const seen: string[] = [];
  for (const m of [...SEED_MARKERS, ...vocabulary]) {
    if (m && blob.includes(m) && !seen.includes(m)) seen.push(m);
  }
  return seen;
}

/** Trim long scanner blobs so a findings file stays readable. */
export const clip = (s: string | undefined | null, n = 600): string | undefined => {
  if (!s) return undefined;
  const t = String(s).replace(/\r/g, "").trim();
  if (!t) return undefined;
  return t.length > n ? t.slice(0, n) + "…" : t;
};

/** Strip XML/HTML tags and decode the five predefined entities. */
export const unxml = (s: string | undefined | null): string | undefined =>
  clip(
    String(s ?? "")
      .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
      .replace(/<[^>]+>/g, " ")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&apos;/g, "'")
      .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
      .replace(/&amp;/g, "&")
      .replace(/[ \t]+/g, " "),
  );

// A Burp export calls these ~11x per issue over a fixed tag vocabulary, so the
// patterns are compiled once instead of per call.
const rxCache = new Map<string, RegExp>();
const rx = (key: string, build: () => RegExp): RegExp => {
  const hit = rxCache.get(key);
  if (hit) return hit;
  const made = build();
  rxCache.set(key, made);
  return made;
};

/** All `<tag>…</tag>` bodies, for the dependency-free XML adapters. */
export function xmlBlocks(text: string, tag: string): string[] {
  const out: string[] = [];
  const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, "gi");
  for (const m of text.matchAll(re)) out.push(m[1]!);
  return out;
}

/** First `<tag>…</tag>` body inside a block. */
export function xmlValue(block: string, tag: string): string | undefined {
  const m = block.match(
    rx(`v:${tag}`, () => new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, "i")),
  );
  return m ? unxml(m[1]) : undefined;
}

/** Attribute value off the first `<tag ...>` in a block. */
export function xmlAttr(block: string, tag: string, attr: string): string | undefined {
  const m = block.match(
    rx(`a:${tag}:${attr}`, () => new RegExp(`<${tag}\\b[^>]*\\b${attr}="([^"]*)"`, "i")),
  );
  return m ? m[1] : undefined;
}
