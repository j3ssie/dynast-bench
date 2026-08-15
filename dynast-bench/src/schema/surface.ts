/**
 * SURFACE.yaml validator - the endpoint-coverage denominator.
 *
 * This is an answer key, so the bar is the same as VULNERABILITIES.yaml: a typo
 * here changes every coverage score forever. The specific failure to guard
 * against is a catalog that silently SHRINKS - a dropped entry does not look
 * like an error, it looks like the agent doing better.
 */

import { readFileSync } from "node:fs";

import { isObj, num, str, strArray } from "./coerce.ts";
import { opKey } from "./operations.ts";
import {
  DISCOVERY_TIERS,
  OPERATION_KINDS,
  REACHABILITIES,
  type Surface,
  type SurfaceOperation,
  type ValidationIssue,
  type ValidationResult,
} from "./types.ts";

/** Fields that mean something for each kind - anything else is a likely typo. */
const KIND_FIELDS: Record<string, string[]> = {
  http: ["method", "path", "url", "query", "params", "port"],
  graphql: ["op", "graphql_kind", "field"],
  ws: ["endpoint", "path", "event", "channel", "namespace"],
  llm: ["tool", "injection_channel"],
  net: ["host", "port", "proto"],
};

/**
 * Meaningful on any kind. `via:` is here rather than on three kinds because an
 * http operation can legitimately ride on another (a sidecar route behind a
 * proxy), and `coverage.ts` reads `via` on http entries to decide what counts as
 * transport.
 */
const COMMON_FIELDS = ["id", "kind", "via", "discovery", "reachability", "vulns", "variant", "notes"];

const ALL_KIND_FIELDS = [...new Set(Object.values(KIND_FIELDS).flat())];

function validateOperation(
  raw: unknown,
  at: string,
  errors: ValidationIssue[],
  warnings: ValidationIssue[],
): SurfaceOperation | null {
  if (!isObj(raw)) {
    errors.push({ at, msg: "not a mapping" });
    return null;
  }
  const id = str(raw.id);
  if (!id) {
    errors.push({ at, msg: "id is required" });
    return null;
  }

  const kindRaw = str(raw.kind)?.toLowerCase();
  if (!kindRaw || !(OPERATION_KINDS as readonly string[]).includes(kindRaw)) {
    errors.push({
      at: `${at}.kind`,
      msg: `must be one of ${OPERATION_KINDS.join("|")} (got ${JSON.stringify(raw.kind)})`,
    });
    return null;
  }
  const kind = kindRaw as SurfaceOperation["kind"];

  const q = raw.query;
  if (q !== undefined && !isObj(q)) {
    errors.push({ at: `${at}.query`, msg: "must be a mapping of name -> value" });
  }

  const op: SurfaceOperation = {
    ...(raw as object),
    id,
    kind,
    method: str(raw.method)?.toUpperCase(),
    path: str(raw.path),
    query: isObj(q) ? Object.fromEntries(Object.entries(q).map(([k, v]) => [k, String(v)])) : undefined,
    params: strArray(raw.params),
    port: num(raw.port),
    op: str(raw.op),
    graphql_kind: str(raw.graphql_kind)?.toLowerCase(),
    field: str(raw.field),
    endpoint: str(raw.endpoint),
    event: str(raw.event),
    channel: str(raw.channel),
    namespace: str(raw.namespace),
    tool: str(raw.tool),
    injection_channel: str(raw.injection_channel)?.toLowerCase(),
    host: str(raw.host),
    proto: str(raw.proto)?.toLowerCase(),
    via: str(raw.via),
    discovery: str(raw.discovery),
    reachability: str(raw.reachability),
    vulns: strArray(raw.vulns) ?? [],
    notes: str(raw.notes),
  };

  // the identity must actually be expressible for its protocol
  const need: Record<string, boolean> = {
    http: Boolean(op.path),
    graphql: Boolean(op.op || op.field),
    // an event name identifies a message operation on its own; only the bare
    // handshake entry has to name the endpoint
    ws: Boolean(op.endpoint || op.path || op.event),
    llm: Boolean(op.tool || op.injection_channel),
    net: op.port !== undefined,
  };
  if (!need[kind]) {
    const want = {
      http: "path",
      graphql: "op or field",
      ws: "endpoint or event",
      llm: "tool or injection_channel",
      net: "port",
    }[kind];
    errors.push({ at, msg: `kind: ${kind} needs ${want}` });
  }
  if (op.path && !op.path.startsWith("/")) {
    errors.push({ at: `${at}.path`, msg: `"${op.path}" must start with /` });
  }

  // Discovery is what the whole benchmark reports coverage BY, so an unknown
  // tier is an error rather than a silently-dropped bucket.
  if (op.discovery && !DISCOVERY_TIERS.includes(op.discovery)) {
    errors.push({
      at: `${at}.discovery`,
      msg: `must be one of ${DISCOVERY_TIERS.join("|")} (got "${op.discovery}")`,
    });
  }
  if (op.reachability && !REACHABILITIES.includes(op.reachability)) {
    warnings.push({ at: `${at}.reachability`, msg: `unusual reachability "${op.reachability}"` });
  }
  const variant = str(raw.variant)?.toLowerCase() ?? "both";
  if (!["both", "vuln", "safe"].includes(variant)) {
    errors.push({ at: `${at}.variant`, msg: `must be both|vuln|safe (got "${variant}")` });
  }
  op.variant = variant as SurfaceOperation["variant"];

  // A field that belongs to a different protocol is nearly always a copy-paste.
  // One flat set difference: iterating the other kinds instead would warn twice
  // about a field two of them share (`path` is both http and ws).
  const allowed = new Set([...KIND_FIELDS[kind]!, ...COMMON_FIELDS]);
  for (const f of ALL_KIND_FIELDS) {
    if (allowed.has(f) || raw[f] === undefined || raw[f] === null) continue;
    warnings.push({ at: `${at}.${f}`, msg: `not meaningful for kind: ${kind} - ignored` });
  }

  return op;
}

export function validateSurface(doc: unknown): ValidationResult<Surface> {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  if (!isObj(doc)) {
    return { ok: false, errors: [{ at: "$", msg: "document is not a mapping" }], warnings };
  }
  if (!str(doc.app)) warnings.push({ at: "app", msg: "missing app: key" });

  const rawOps = doc.operations;
  if (!Array.isArray(rawOps)) {
    errors.push({ at: "operations", msg: "missing or not a list" });
    return { ok: false, errors, warnings };
  }

  const ids = new Set<string>();
  const operations: SurfaceOperation[] = [];
  for (let i = 0; i < rawOps.length; i++) {
    const op = validateOperation(rawOps[i], `operations[${i}]`, errors, warnings);
    if (!op) continue;
    if (ids.has(op.id)) errors.push({ at: `operations[${i}].id`, msg: `duplicate id "${op.id}"` });
    ids.add(op.id);
    operations.push(op);
  }

  // `via:` must resolve, or the transport-vs-operation layering is a lie
  for (const op of operations) {
    if (op.via && !ids.has(op.via)) {
      errors.push({ at: `${op.id}.via`, msg: `references unknown operation "${op.via}"` });
    }
  }

  // Two entries a tool could never tell apart would make the denominator
  // unreachable: one report credits both, or neither, forever.
  const byKey = new Map<string, string[]>();
  for (const op of operations) {
    const k = opKey(op);
    byKey.set(k, [...(byKey.get(k) ?? []), op.id]);
  }
  for (const [k, dupes] of byKey) {
    if (dupes.length > 1) {
      errors.push({
        at: dupes.join(","),
        msg: `identical operation identity "${k}" - no report could ever distinguish these`,
      });
    }
  }

  // Tiering is all-or-nothing, exactly as for VULNERABILITIES.yaml: a partial
  // breakdown reports coverage over the labelled subset while looking complete.
  const tiered = operations.filter((o) => o.discovery);
  if (tiered.length && tiered.length < operations.length) {
    const missing = operations.filter((o) => !o.discovery).map((o) => o.id);
    errors.push({
      at: missing.slice(0, 8).join(","),
      msg:
        `${missing.length} operation(s) have no discovery: tier while ${tiered.length} do - ` +
        `coverage by tier would silently cover only the labelled subset`,
    });
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    value: {
      app: str(doc.app),
      entry: str(doc.entry),
      notes: str(doc.notes),
      operations,
    },
  };
}

export function parseSurfaceFile(path: string): ValidationResult<Surface> {
  let doc: unknown;
  try {
    doc = Bun.YAML.parse(readFileSync(path, "utf8"));
  } catch (e) {
    return {
      ok: false,
      errors: [{ at: "$", msg: `does not parse - ${(e as Error).message}` }],
      warnings: [],
    };
  }
  return validateSurface(doc);
}
