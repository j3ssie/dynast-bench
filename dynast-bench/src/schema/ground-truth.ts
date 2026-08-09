/**
 * VULNERABILITIES.yaml validator.
 *
 * This is the answer key, so the bar is higher than for findings: a typo here
 * silently mis-scores every tool forever. `dynast-bench check` fails on errors.
 */

import { readFileSync } from "node:fs";

import { isObj, str } from "./coerce.ts";
import { normalizeCwe } from "./cwe.ts";
import {
  DIFFICULTIES,
  REACHABILITIES,
  SEVERITIES,
  TAINTS,
  type GroundTruth,
  type GtMatch,
  type GtNearMiss,
  type GtVulnerability,
  type ValidationIssue,
  type ValidationResult,
} from "./types.ts";

function validateMatch(raw: unknown, at: string, errors: ValidationIssue[]): GtMatch | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!isObj(raw)) {
    errors.push({ at, msg: "match: must be a mapping" });
    return undefined;
  }
  const m: GtMatch = {};
  if (raw.http !== undefined) {
    if (!isObj(raw.http)) errors.push({ at: `${at}.http`, msg: "must be a mapping" });
    else {
      const q = raw.http.query;
      if (q !== undefined && !isObj(q)) {
        errors.push({ at: `${at}.http.query`, msg: "must be a mapping of name -> value" });
      }
      const params = raw.http.params;
      if (params !== undefined && !Array.isArray(params)) {
        errors.push({ at: `${at}.http.params`, msg: "must be a list of parameter names" });
      }
      const port = raw.http.port === undefined ? undefined : Number(raw.http.port);
      if (port !== undefined && !Number.isFinite(port)) {
        errors.push({ at: `${at}.http.port`, msg: "must be a number" });
      }
      m.http = {
        method: str(raw.http.method)?.toUpperCase(),
        path: str(raw.http.path),
        query: isObj(q)
          ? Object.fromEntries(Object.entries(q).map(([k, v]) => [k, String(v)]))
          : undefined,
        params: Array.isArray(params) ? params.map((p) => String(p)) : undefined,
        port: Number.isFinite(port as number) ? (port as number) : undefined,
      };
      if (!m.http.path) errors.push({ at: `${at}.http`, msg: "path is required" });
    }
  }
  if (raw.file !== undefined) {
    if (!isObj(raw.file)) errors.push({ at: `${at}.file`, msg: "must be a mapping" });
    else {
      const lines = raw.file.lines;
      let range: [number, number] | undefined;
      if (lines !== undefined) {
        if (
          !Array.isArray(lines) ||
          lines.length !== 2 ||
          lines.some((n) => !Number.isFinite(Number(n)))
        ) {
          errors.push({ at: `${at}.file.lines`, msg: "must be [start, end]" });
        } else {
          range = [Number(lines[0]), Number(lines[1])];
          if (range[0] > range[1]) {
            errors.push({ at: `${at}.file.lines`, msg: `start ${range[0]} > end ${range[1]}` });
          }
        }
      }
      m.file = {
        path: str(raw.file.path),
        symbol: str(raw.file.symbol),
        lines: range,
      };
      if (!m.file.path) errors.push({ at: `${at}.file`, msg: "path is required" });
    }
  }
  for (const k of ["net", "graphql", "ws", "llm"] as const) {
    if (raw[k] === undefined) continue;
    if (!isObj(raw[k])) {
      errors.push({ at: `${at}.${k}`, msg: "must be a mapping" });
      continue;
    }
    (m as any)[k] = { ...(raw[k] as object) };
  }
  if (raw.markers !== undefined) {
    const arr = Array.isArray(raw.markers) ? raw.markers : [raw.markers];
    m.markers = arr.map((x) => String(x)).filter(Boolean);
  }
  m.cwe_family = str(raw.cwe_family);
  if (raw.cwe_aliases !== undefined) {
    const arr = Array.isArray(raw.cwe_aliases) ? raw.cwe_aliases : [raw.cwe_aliases];
    m.cwe_aliases = arr.map(normalizeCwe).filter(Boolean) as string[];
  }
  return m;
}

export function validateGroundTruth(doc: unknown): ValidationResult<GroundTruth> {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  if (!isObj(doc)) {
    return { ok: false, errors: [{ at: "$", msg: "document is not a mapping" }], warnings };
  }
  if (!str(doc.app)) warnings.push({ at: "app", msg: "missing app: key" });
  if (!str(doc.entry)) warnings.push({ at: "entry", msg: "missing entry: key" });

  const rawVulns = doc.vulnerabilities;
  if (!Array.isArray(rawVulns)) {
    errors.push({ at: "vulnerabilities", msg: "missing or not a list" });
    return { ok: false, errors, warnings };
  }

  const ids = new Set<string>();
  const vulnerabilities: GtVulnerability[] = [];
  for (let i = 0; i < rawVulns.length; i++) {
    const at = `vulnerabilities[${i}]`;
    const raw = rawVulns[i];
    if (!isObj(raw)) {
      errors.push({ at, msg: "not a mapping" });
      continue;
    }
    const id = str(raw.id);
    if (!id) {
      errors.push({ at, msg: "id is required" });
      continue;
    }
    if (ids.has(id)) errors.push({ at: `${at}.id`, msg: `duplicate id "${id}"` });
    ids.add(id);
    if (!/^[A-Z0-9]+(?:-[A-Z0-9]+)*$/.test(id)) {
      warnings.push({ at: `${at}.id`, msg: `"${id}" is not CLASS-NNN shaped` });
    }

    const cwe = normalizeCwe(raw.cwe);
    if (!cwe) errors.push({ at: `${at}.cwe`, msg: `missing or unparseable cwe (${raw.cwe})` });

    const sev = str(raw.severity)?.toLowerCase();
    if (!sev || !SEVERITIES.includes(sev as any)) {
      errors.push({ at: `${at}.severity`, msg: `must be one of ${SEVERITIES.join("|")}` });
    }
    const diff = str(raw.difficulty);
    if (!diff || !DIFFICULTIES.includes(diff)) {
      errors.push({ at: `${at}.difficulty`, msg: `must be one of ${DIFFICULTIES.join("|")}` });
    }
    const taint = str(raw.taint);
    if (taint && !TAINTS.includes(taint)) {
      warnings.push({ at: `${at}.taint`, msg: `unusual taint "${taint}"` });
    }
    const reach = str(raw.reachability);
    if (reach && !REACHABILITIES.includes(reach)) {
      warnings.push({ at: `${at}.reachability`, msg: `unusual reachability "${reach}"` });
    }
    if (!isObj(raw.variant_paths) && !str(raw.route)) {
      errors.push({ at, msg: "needs variant_paths or route - nothing to anchor a finding to" });
    }
    if (!str(raw.poc)) warnings.push({ at: `${at}.poc`, msg: "no PoC recorded" });

    const match = validateMatch(raw.match, `${at}.match`, errors);
    if (!match) {
      warnings.push({
        at: `${at}.match`,
        msg: "no match: block - anchors will be inferred from route/variant_paths",
      });
    }

    vulnerabilities.push({ ...(raw as any), id, cwe: cwe ?? undefined, match });
  }

  const rawNm = Array.isArray(doc.near_misses) ? doc.near_misses : [];
  if (doc.near_misses !== undefined && !Array.isArray(doc.near_misses)) {
    errors.push({ at: "near_misses", msg: "not a list" });
  }
  const nmIds = new Set<string>();
  const near_misses: GtNearMiss[] = [];
  for (let i = 0; i < rawNm.length; i++) {
    const at = `near_misses[${i}]`;
    const raw = rawNm[i];
    if (!isObj(raw)) {
      errors.push({ at, msg: "not a mapping" });
      continue;
    }
    const id = str(raw.id);
    if (!id) {
      errors.push({ at, msg: "id is required" });
      continue;
    }
    if (nmIds.has(id)) errors.push({ at: `${at}.id`, msg: `duplicate id "${id}"` });
    nmIds.add(id);
    if (!str(raw.path)) warnings.push({ at: `${at}.path`, msg: "no path" });
    const of = str(raw.of);
    if (of && !ids.has(of)) {
      errors.push({ at: `${at}.of`, msg: `references unknown vulnerability "${of}"` });
    }
    near_misses.push({
      ...(raw as any),
      id,
      match: validateMatch(raw.match, `${at}.match`, errors),
    });
  }

  // every near_miss: reference on a vulnerability must resolve
  for (const v of vulnerabilities) {
    const ref = str(v.near_miss);
    if (ref && !nmIds.has(ref)) {
      errors.push({
        at: `vulnerabilities[${v.id}].near_miss`,
        msg: `references unknown near-miss "${ref}"`,
      });
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    value: {
      app: str(doc.app),
      entry: str(doc.entry),
      seed_notes: str(doc.seed_notes),
      vulnerabilities,
      near_misses,
    },
  };
}

/**
 * Read + validate an answer key from disk. Every caller wants the same parse and
 * the same rules; they differ only in what they do with the errors, so they layer
 * that on top of this.
 */
export function parseGroundTruthFile(path: string): ValidationResult<GroundTruth> {
  let doc: unknown;
  try {
    doc = Bun.YAML.parse(readFileSync(path, "utf8"));
  } catch (e) {
    return { ok: false, errors: [{ at: "$", msg: `does not parse - ${(e as Error).message}` }], warnings: [] };
  }
  return validateGroundTruth(doc);
}
