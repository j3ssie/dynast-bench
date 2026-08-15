/**
 * endpoints/v1 validator + coercer - what a tool claims it discovered.
 *
 * Same posture as findings/v1: forgiving on shape, strict on meaning. An LLM
 * agent writing this by hand should not fail on a bare list of URL strings, but
 * an entry that identifies nothing must be dropped rather than counted, because
 * an unidentifiable endpoint can only ever inflate the denominator of precision
 * or match nothing at all.
 *
 * Accepted shapes, all equivalent:
 *
 *   {"schema": "...", "endpoints": [{"method": "GET", "path": "/a"}]}
 *   {"endpoints": ["GET /a", "http://127.0.0.1:13311/b?q="]}
 *   ["GET /a", "POST /b"]
 */

import { readFileSync } from "node:fs";

import { isObj, num, str, strArray } from "./coerce.ts";
import { parseEnvelope } from "./envelope.ts";
import { normalizeMethod } from "./keys.ts";
import { refKind } from "./operations.ts";
import {
  ENDPOINTS_SCHEMA_ID,
  type EndpointsFile,
  type FindingsFile,
  type ReportedEndpoint,
  type ValidationIssue,
  type ValidationResult,
  type Variant,
} from "./types.ts";

/** "GET /api/posts/search?q=" or a bare URL/path -> a ref. */
function fromString(raw: string): ReportedEndpoint | null {
  const s = raw.trim();
  if (!s) return null;

  // "ws /ws post.search" / "graphql mutation.updatePost" / "llm run_shell"
  const tagged = s.match(/^(ws|wss|graphql|gql|llm|tool)\s+(.*)$/i);
  if (tagged) {
    const tag = tagged[1]!.toLowerCase();
    const rest = tagged[2]!.trim();
    if (tag === "graphql" || tag === "gql") {
      const dotted = rest.match(/^(query|mutation|subscription)[.\s]+(\S+)$/i);
      if (dotted) return { kind: "graphql", graphql_kind: dotted[1]!.toLowerCase(), op: dotted[2] };
      return { kind: "graphql", op: rest };
    }
    if (tag === "llm" || tag === "tool") return { kind: "llm", tool: rest };
    const parts = rest.split(/\s+/).filter(Boolean);
    const endpoint = parts[0]?.startsWith("/") ? parts.shift() : undefined;
    return { kind: "ws", endpoint, event: parts.join(" ") || undefined };
  }

  // "host:port/tcp"
  const net = s.match(/^([A-Za-z0-9_.-]+):(\d{1,5})\/(tcp|udp)$/i);
  if (net) return { kind: "net", host: net[1], port: Number(net[2]), proto: net[3]!.toLowerCase() };

  const parts = s.split(/\s+/).filter(Boolean);
  let method: string | undefined;
  let target = s;
  if (parts.length > 1 && /^[A-Z]+$/i.test(parts[0]!) && normalizeMethod(parts[0])) {
    method = normalizeMethod(parts[0]) ?? undefined;
    target = parts.slice(1).join(" ");
  }
  if (!/^\/|^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return null;
  return target.includes("://") ? { method, url: target } : { method, path: target };
}

function coerceEndpoint(
  raw: unknown,
  index: number,
  warnings: ValidationIssue[],
): ReportedEndpoint | null {
  const at = `endpoints[${index}]`;
  if (typeof raw === "string") {
    const ep = fromString(raw);
    if (!ep) warnings.push({ at, msg: `cannot parse "${raw}" as an endpoint - dropped` });
    return ep;
  }
  if (!isObj(raw)) {
    warnings.push({ at, msg: "not a string or mapping - dropped" });
    return null;
  }

  // tolerate a nested findings-style location
  const src = isObj(raw.location)
    ? { ...raw, ...(raw.location as Record<string, unknown>) }
    : { ...raw };
  for (const nest of ["http", "graphql", "ws", "llm", "net"] as const) {
    if (isObj(src[nest])) Object.assign(src, src[nest], { kind: src.kind ?? nest });
  }

  const q = src.query;
  const ep: ReportedEndpoint = {
    id: str(src.id),
    kind: str(src.kind)?.toLowerCase(),
    method: normalizeMethod(src.method) ?? undefined,
    url: str(src.url),
    path: str(src.path),
    query: isObj(q)
      ? Object.fromEntries(Object.entries(q).map(([k, v]) => [k, String(v)]))
      : undefined,
    params: strArray(src.params) ?? strArray(src.param),
    port: num(src.port),
    op: str(src.op) ?? str(src.operation),
    graphql_kind: str(src.graphql_kind)?.toLowerCase(),
    field: str(src.field),
    endpoint: str(src.endpoint),
    event: str(src.event),
    channel: str(src.channel),
    namespace: str(src.namespace),
    tool: str(src.tool),
    injection_channel: str(src.injection_channel)?.toLowerCase(),
    host: str(src.host),
    proto: str(src.proto)?.toLowerCase(),
    note: str(src.note),
  };

  if (!refKind(ep)) {
    warnings.push({ at, msg: "identifies no operation - dropped" });
    return null;
  }
  return ep;
}

export function validateEndpoints(
  doc: unknown,
  opts: { app?: string; variant?: Variant } = {},
): ValidationResult<EndpointsFile> {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  const env = parseEnvelope(
    doc,
    {
      schemaId: ENDPOINTS_SCHEMA_ID,
      listKey: "endpoints",
      noun: "endpoints",
      altKeys: ["routes", "urls"],
    },
    opts,
    errors,
    warnings,
  );
  const list = env.items;
  if (!list) return { ok: false, errors, warnings };

  const endpoints: ReportedEndpoint[] = [];
  for (let i = 0; i < list.length; i++) {
    const ep = coerceEndpoint(list[i], i, warnings);
    if (ep) endpoints.push(ep);
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    value: { schema: ENDPOINTS_SCHEMA_ID, tool: env.tool, run: env.run, endpoints },
  };
}

/**
 * Fall back to the endpoints implied by a findings file.
 *
 * Deliberately labelled as a distinct evidence source in the report: a tool that
 * only tells you where it found bugs cannot be credited with everything it
 * looked at, so this always UNDER-reports coverage. It exists so a scanner with
 * no endpoint list still gets a number, not so the number is comparable.
 */
export function endpointsFromFindings(f: FindingsFile): ReportedEndpoint[] {
  const out: ReportedEndpoint[] = [];
  for (const finding of f.findings) {
    const l = finding.location;
    if (l.http?.path || l.http?.url) {
      out.push({ kind: "http", method: l.http.method, path: l.http.path, url: l.http.url });
    }
    if (l.graphql?.op || l.graphql?.field) {
      out.push({ kind: "graphql", op: l.graphql.op, graphql_kind: l.graphql.kind, field: l.graphql.field });
    }
    if (l.ws?.endpoint || l.ws?.event) {
      out.push({ kind: "ws", endpoint: l.ws.endpoint, event: l.ws.event, channel: l.ws.channel });
    }
    if (l.llm?.tool || l.llm?.channel) {
      out.push({ kind: "llm", tool: l.llm.tool, injection_channel: l.llm.channel });
    }
    if (l.net?.port !== undefined) {
      out.push({ kind: "net", host: l.net.host, port: l.net.port, proto: l.net.proto });
    }
  }
  return out;
}

export function parseEndpointsFile(
  path: string,
  opts: { app?: string; variant?: Variant } = {},
): ValidationResult<EndpointsFile> {
  let doc: unknown;
  try {
    const text = readFileSync(path, "utf8");
    const head = text.trimStart();
    // JSON is the common case; YAML is accepted so a catalog and a report can be
    // authored in the same format
    doc = head.startsWith("{") || head.startsWith("[") ? JSON.parse(text) : Bun.YAML.parse(text);
  } catch (e) {
    return {
      ok: false,
      errors: [{ at: "$", msg: `does not parse - ${(e as Error).message}` }],
      warnings: [],
    };
  }
  return validateEndpoints(doc, opts);
}
