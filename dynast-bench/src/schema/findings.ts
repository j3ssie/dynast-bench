/**
 * findings/v1 validator + coercer.
 *
 * Deliberately forgiving on shape and strict on meaning: an LLM agent writing
 * this file by hand should not fail on `severity: "High"` or `cwe: 89`, but it
 * MUST NOT be able to smuggle in a finding with no location at all, because that
 * is unscoreable. Anything repaired is reported as a warning.
 */

import { isObj, num, str, strArray } from "./coerce.ts";
import { normalizeCwe } from "./cwe.ts";
import { normalizeMethod } from "./keys.ts";
import {
  CONFIDENCES,
  FINDINGS_SCHEMA_ID,
  SEVERITIES,
  TOOL_MODES,
  type Confidence,
  type Finding,
  type FindingLocation,
  type FindingsFile,
  type Severity,
  type ToolMode,
  type ValidationIssue,
  type ValidationResult,
  type Variant,
} from "./types.ts";

const SEVERITY_ALIASES: Record<string, Severity> = {
  info: "info",
  informational: "info",
  information: "info",
  note: "info",
  none: "info",
  low: "low",
  minor: "low",
  warning: "low",
  "0": "info",
  "1": "low",
  "2": "medium",
  "3": "high",
  "4": "critical",
  medium: "medium",
  moderate: "medium",
  med: "medium",
  high: "high",
  major: "high",
  error: "high",
  critical: "critical",
  crit: "critical",
  severe: "critical",
  blocker: "critical",
};

const CONFIDENCE_ALIASES: Record<string, Confidence> = {
  "0": "tentative",
  "1": "tentative",
  "2": "firm",
  "3": "certain",
  certain: "certain",
  confirmed: "certain",
  high: "certain",
  firm: "firm",
  medium: "firm",
  probable: "firm",
  tentative: "tentative",
  low: "tentative",
  possible: "tentative",
  unconfirmed: "tentative",
};

/** Any spelling a scanner uses -> the canonical severity, or undefined. */
export const coerceSeverity = (raw: unknown): Severity | undefined => {
  const s = str(raw)?.toLowerCase();
  return s ? SEVERITY_ALIASES[s] : undefined;
};

/** Any spelling a scanner uses -> the canonical confidence, or undefined. */
export const coerceConfidence = (raw: unknown): Confidence | undefined => {
  const s = str(raw)?.toLowerCase();
  return s ? CONFIDENCE_ALIASES[s] : undefined;
};

const LOCATION_KINDS = ["http", "file", "net", "graphql", "ws", "llm"] as const;

function coerceLocation(
  raw: unknown,
  at: string,
  warnings: ValidationIssue[],
): FindingLocation {
  const loc: FindingLocation = {};
  if (!isObj(raw)) return loc;

  // Tolerate a flat finding: {url, method, param, file, line, symbol, host, port}
  const flatHttp = raw.url ?? raw.method ?? raw.param ?? raw.path;
  const looksFlat = LOCATION_KINDS.every((k) => raw[k] === undefined);
  const src: Record<string, unknown> = looksFlat ? { http: {}, file: {}, net: {} } : { ...raw };
  if (looksFlat) {
    if (flatHttp !== undefined) {
      src.http = {
        method: raw.method,
        url: raw.url,
        path: raw.path,
        param: raw.param,
        param_in: raw.param_in,
        status: raw.status,
      };
      warnings.push({ at, msg: "flat http fields lifted into location.http" });
    }
    if (raw.file !== undefined || raw.line !== undefined || raw.symbol !== undefined) {
      src.file = { path: raw.file, line: raw.line, symbol: raw.symbol, snippet: raw.snippet };
      warnings.push({ at, msg: "flat file fields lifted into location.file" });
    }
    if (raw.host !== undefined || raw.port !== undefined) {
      src.net = { host: raw.host, port: raw.port, proto: raw.proto, service: raw.service };
      warnings.push({ at, msg: "flat net fields lifted into location.net" });
    }
  }

  if (isObj(src.http)) {
    const h = src.http;
    const url = str(h.url);
    const path = str(h.path);
    if (url || path) {
      loc.http = {
        method: normalizeMethod(h.method) ?? undefined,
        url,
        path,
        param: str(h.param),
        param_in: str(h.param_in),
        status: num(h.status),
      };
    } else if (Object.values(h).some((v) => v !== undefined && v !== null && v !== "")) {
      warnings.push({ at: `${at}.http`, msg: "no url or path - http anchor dropped" });
    }
  }
  if (isObj(src.file)) {
    const f = src.file;
    const path = str(f.path);
    if (path) {
      loc.file = {
        path,
        line: num(f.line),
        end_line: num(f.end_line),
        symbol: str(f.symbol),
        snippet: str(f.snippet),
      };
    } else if (f.line !== undefined || f.symbol !== undefined) {
      warnings.push({ at: `${at}.file`, msg: "no path - file anchor dropped" });
    }
  }
  if (isObj(src.net)) {
    const n = src.net;
    const host = str(n.host);
    const port = num(n.port);
    if (host || port !== undefined) {
      loc.net = {
        host,
        port,
        proto: (str(n.proto) ?? "tcp").toLowerCase(),
        service: str(n.service),
        version: str(n.version),
        state: str(n.state),
      };
    }
  }
  if (isObj(src.graphql)) {
    const g = src.graphql;
    if (str(g.op) || str(g.field)) {
      loc.graphql = { op: str(g.op), kind: str(g.kind)?.toLowerCase(), field: str(g.field) };
    }
  }
  if (isObj(src.ws)) {
    const w = src.ws;
    if (str(w.transport) || str(w.event) || str(w.endpoint)) {
      loc.ws = {
        transport: str(w.transport)?.toLowerCase(),
        event: str(w.event),
        endpoint: str(w.endpoint),
      };
    }
  }
  if (isObj(src.llm)) {
    const l = src.llm;
    if (str(l.tool) || str(l.channel)) {
      loc.llm = {
        tool: str(l.tool),
        channel: str(l.channel)?.toLowerCase(),
        run_id: str(l.run_id),
      };
    }
  }
  return loc;
}

function coerceFinding(
  raw: unknown,
  index: number,
  errors: ValidationIssue[],
  warnings: ValidationIssue[],
  seenIds: Set<string>,
): Finding | null {
  const at = `findings[${index}]`;
  if (!isObj(raw)) {
    errors.push({ at, msg: "not an object" });
    return null;
  }

  let id = str(raw.id) ?? str(raw.finding_id) ?? str(raw.ref);
  if (!id) {
    id = `f-${index + 1}`;
    warnings.push({ at, msg: `no id - assigned "${id}"` });
  }
  if (seenIds.has(id)) {
    const fresh = `${id}#${index + 1}`;
    warnings.push({ at, msg: `duplicate id "${id}" - renamed "${fresh}"` });
    id = fresh;
  }
  seenIds.add(id);

  const location = coerceLocation(raw.location ?? raw, `${at}.location`, warnings);
  if (Object.keys(location).length === 0) {
    errors.push({
      at,
      msg: "no usable location - need at least one of location.{http,file,net,graphql,ws,llm}",
    });
    return null;
  }

  const cwe = normalizeCwe(raw.cwe);
  if (raw.cwe !== undefined && raw.cwe !== null && !cwe) {
    warnings.push({ at: `${at}.cwe`, msg: `unparseable CWE ${JSON.stringify(raw.cwe)} - ignored` });
  }
  const cwes = (strArray(raw.cwes) ?? []).map(normalizeCwe).filter(Boolean) as string[];

  const sevRaw = str(raw.severity)?.toLowerCase();
  let severity: Severity | undefined;
  if (sevRaw) {
    severity = SEVERITY_ALIASES[sevRaw];
    if (!severity) {
      warnings.push({
        at: `${at}.severity`,
        msg: `unknown severity "${sevRaw}" - expected ${SEVERITIES.join("|")}`,
      });
    }
  }

  const confRaw = str(raw.confidence)?.toLowerCase();
  let confidence: Confidence | undefined;
  if (confRaw) {
    confidence = CONFIDENCE_ALIASES[confRaw];
    if (!confidence) {
      warnings.push({
        at: `${at}.confidence`,
        msg: `unknown confidence "${confRaw}" - expected ${CONFIDENCES.join("|")}`,
      });
    }
  }

  const ev = isObj(raw.evidence) ? raw.evidence : {};
  const markers = strArray(ev.markers) ?? strArray((ev as any).marker);
  const evidence =
    markers || str(ev.request) || str(ev.response_excerpt) || str(ev.note)
      ? {
          markers,
          request: str(ev.request),
          response_excerpt: str(ev.response_excerpt) ?? str((ev as any).response),
          note: str(ev.note),
        }
      : undefined;

  return {
    id,
    title: str(raw.title) ?? str(raw.name),
    cwe: cwe ?? undefined,
    cwes: cwes.length ? cwes : undefined,
    severity,
    confidence,
    location,
    evidence,
    exploited: typeof raw.exploited === "boolean" ? raw.exploited : undefined,
    tags: strArray(raw.tags),
  };
}

/**
 * Validate + coerce a parsed findings document. Accepts the full envelope, a
 * bare `{findings: [...]}`, or a bare array of findings.
 */
export function validateFindings(
  doc: unknown,
  opts: { app?: string; variant?: Variant } = {},
): ValidationResult<FindingsFile> {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  let root: Record<string, unknown>;
  if (Array.isArray(doc)) {
    root = { findings: doc };
    warnings.push({ at: "$", msg: "bare array accepted as {findings: [...]}" });
  } else if (isObj(doc)) {
    root = doc;
  } else {
    return {
      ok: false,
      errors: [{ at: "$", msg: "document is not an object or array" }],
      warnings,
    };
  }

  const schema = str(root.schema);
  if (!schema) {
    warnings.push({ at: "schema", msg: `missing - assuming ${FINDINGS_SCHEMA_ID}` });
  } else if (schema !== FINDINGS_SCHEMA_ID) {
    const major = schema.match(/\/v(\d+)/)?.[1];
    if (major && major !== "1") {
      errors.push({ at: "schema", msg: `unsupported schema "${schema}" (this build reads v1)` });
    } else {
      warnings.push({ at: "schema", msg: `unrecognised schema "${schema}" - read as v1` });
    }
  }

  const rawTool = isObj(root.tool) ? root.tool : {};
  const toolName = str(rawTool.name) ?? str(root.tool) ?? "unknown";
  if (!isObj(root.tool) && !str(root.tool)) {
    warnings.push({ at: "tool", msg: 'missing - recorded as "unknown"' });
  }
  const modeRaw = str(rawTool.mode)?.toLowerCase();
  const mode = modeRaw && (TOOL_MODES as string[]).includes(modeRaw)
    ? (modeRaw as ToolMode)
    : undefined;
  if (modeRaw && !mode) {
    warnings.push({ at: "tool.mode", msg: `unknown mode "${modeRaw}" - expected ${TOOL_MODES.join("|")}` });
  }

  const rawRun = isObj(root.run) ? root.run : {};
  const app = str(rawRun.app) ?? opts.app;
  const variantRaw = str(rawRun.variant)?.toLowerCase();
  let variant: Variant | undefined;
  if (variantRaw === "vuln" || variantRaw === "safe") variant = variantRaw;
  else if (variantRaw) {
    errors.push({ at: "run.variant", msg: `must be "vuln" or "safe" (got "${variantRaw}")` });
  }
  if (!variant) {
    variant = opts.variant ?? "vuln";
    warnings.push({
      at: "run.variant",
      msg: `missing - assuming "${variant}"; a safe-twin scan MUST say so or its findings score as true positives`,
    });
  }
  if (opts.app && app && app !== opts.app) {
    errors.push({ at: "run.app", msg: `findings are for "${app}", scoring "${opts.app}"` });
  }
  if (opts.variant && variant !== opts.variant) {
    errors.push({
      at: "run.variant",
      msg: `findings are from the "${variant}" twin, scoring "${opts.variant}"`,
    });
  }

  const rawFindings = root.findings;
  if (!Array.isArray(rawFindings)) {
    errors.push({ at: "findings", msg: "missing or not an array" });
    return { ok: false, errors, warnings };
  }

  const seenIds = new Set<string>();
  const findings: Finding[] = [];
  for (let i = 0; i < rawFindings.length; i++) {
    const f = coerceFinding(rawFindings[i], i, errors, warnings, seenIds);
    if (f) findings.push(f);
  }

  const value: FindingsFile = {
    schema: FINDINGS_SCHEMA_ID,
    tool: { name: toolName, version: str(rawTool.version), mode },
    run: {
      ...rawRun,
      app,
      variant,
      target: str(rawRun.target),
      duration_s: num(rawRun.duration_s),
    },
    findings,
  };

  return { ok: errors.length === 0, errors, warnings, value };
}
