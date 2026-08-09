/**
 * Anchors - the comparable form of "where is this bug".
 *
 * Both sides get reduced to the same shape: a set of http / file / net / graphql
 * / ws / llm anchors plus proof markers. An answer key entry uses its `match:`
 * block when it has one and otherwise derives anchors from the human `route:`,
 * `variant_paths:` and the stack-specific keys - so the scorer works on a key
 * that has never been touched, and gets sharper on one that has.
 */

import { str } from "../schema/coerce.ts";
import { cweFamily } from "../schema/cwe.ts";
import { httpKeyFromUrl, parseRoute, routePaths, type HttpKey, type NetKey } from "../schema/keys.ts";
import type { Finding, GtMatch, GtNearMiss, GtVulnerability } from "../schema/types.ts";

export interface FileAnchor {
  path: string;
  symbol?: string;
  lines?: [number, number];
}

export interface Anchors {
  http: HttpKey[];
  file: FileAnchor[];
  net: (NetKey & { service?: string; version?: string; state?: string })[];
  graphql: { op?: string; kind?: string; field?: string }[];
  ws: { transport?: string; event?: string; channel?: string; endpoint?: string }[];
  llm: { tool?: string; channel?: string }[];
  markers: string[];
}

export interface GtAnchors extends Anchors {
  id: string;
  cwe: string | null;
  family: string | null;
  cweAliases: string[];
}

/**
 * Nothing but a source anchor: unreachable for a black-box run, so `recall` and
 * `recall_reachable` differ by exactly these. One definition - the scorer, the
 * report and the tests all used to compute it slightly differently.
 */
export const isSourceOnly = (a: Anchors): boolean =>
  a.http.length === 0 &&
  a.net.length === 0 &&
  a.graphql.length === 0 &&
  a.ws.length === 0 &&
  a.llm.length === 0;

/**
 * Identity of a bug as far as a scorer can see it. Two entries sharing a
 * fingerprint cannot be told apart by any tool, which `check` and the test suite
 * both refuse - from this one definition, so they cannot drift.
 */
export const anchorFingerprint = (v: GtVulnerability): string => {
  const a = gtAnchors(v);
  return JSON.stringify([
    a.cwe,
    a.http.map((h) => [h.method, h.path, h.query, h.params]),
    a.file.map((f) => [f.path, f.symbol, f.lines]),
    a.net,
    a.graphql,
    a.ws,
    a.llm,
  ]);
};

const empty = (): Anchors => ({
  http: [],
  file: [],
  net: [],
  graphql: [],
  ws: [],
  llm: [],
  markers: [],
});

/** Anchors declared by a `match:` block. */
function fromMatch(m: GtMatch): Anchors {
  const a = empty();
  if (m.http?.path) {
    a.http.push({
      method: m.http.method ?? null,
      path: m.http.path,
      query: m.http.query ?? {},
      params: m.http.params ?? [],
      port: m.http.port ?? null,
    });
  }
  if (m.file?.path) {
    a.file.push({ path: m.file.path, symbol: m.file.symbol, lines: m.file.lines });
  }
  if (m.net && (m.net.host || m.net.port !== undefined)) {
    a.net.push({
      host: m.net.host ?? null,
      port: m.net.port ?? null,
      proto: (m.net.proto ?? "tcp").toLowerCase(),
      service: m.net.service,
      version: m.net.version,
    });
  }
  if (m.graphql?.op) a.graphql.push({ op: m.graphql.op, kind: m.graphql.kind });
  if (m.ws && (m.ws.transport || m.ws.event || m.ws.channel || m.ws.endpoint)) {
    a.ws.push({
      transport: m.ws.transport,
      event: m.ws.event,
      channel: m.ws.channel,
      endpoint: m.ws.endpoint,
    });
  }
  if (m.llm && (m.llm.tool || m.llm.channel)) {
    a.llm.push({ tool: m.llm.tool, channel: m.llm.channel });
  }
  if (m.markers?.length) a.markers.push(...m.markers);
  return a;
}

/** Anchors inferred from the human fields, for entries with no `match:` block. */
function inferred(v: GtVulnerability): Anchors {
  const a = empty();
  const route = str(v.route) ?? "";

  const parsed = parseRoute(route);
  if (parsed.http?.path) a.http.push(parsed.http);
  // a route naming two endpoints ("/api/schema/ and /api/docs/") anchors on both
  for (const p of routePaths(route)) {
    const extra = httpKeyFromUrl(p, parsed.http?.method ?? undefined);
    if (!a.http.some((h) => h.path === extra.path)) a.http.push(extra);
  }

  if (parsed.net) {
    a.net.push({ ...parsed.net, service: str(v.symbol) });
  } else if (str(v.host)) {
    // network-app entries carry host/proto as their own keys
    const port = route.match(/:(\d{1,5})\b/);
    a.net.push({
      host: str(v.host)!,
      port: port ? Number(port[1]) : null,
      proto: (str(v.proto) ?? "tcp").toLowerCase(),
    });
  }

  const file = str(v.variant_paths?.vuln);
  if (file && !file.startsWith("(")) a.file.push({ path: file, symbol: str(v.symbol) });

  if (str(v.graphql_op)) a.graphql.push({ op: str(v.graphql_op), kind: str(v.graphql_kind) });
  if (str(v.transport)) a.ws.push({ transport: str(v.transport)!.toLowerCase() });
  if (str(v.tool) || str(v.injection_channel)) {
    a.llm.push({ tool: str(v.tool), channel: str(v.injection_channel)?.toLowerCase() });
  }
  return a;
}

/** Reduce an answer-key entry to anchors. `match:` wins; gaps fall back to inference. */
export function gtAnchors(v: GtVulnerability): GtAnchors {
  const declared = v.match ? fromMatch(v.match) : empty();
  const guessed = inferred(v);
  const merged: Anchors = {
    http: declared.http.length ? declared.http : guessed.http,
    file: declared.file.length ? declared.file : guessed.file,
    net: declared.net.length ? declared.net : guessed.net,
    graphql: declared.graphql.length ? declared.graphql : guessed.graphql,
    ws: declared.ws.length ? declared.ws : guessed.ws,
    llm: declared.llm.length ? declared.llm : guessed.llm,
    markers: declared.markers.length ? declared.markers : guessed.markers,
  };
  const cwe = str(v.cwe) ?? null;
  return {
    ...merged,
    id: v.id,
    cwe,
    family: v.match?.cwe_family ?? cweFamily(cwe),
    cweAliases: v.match?.cwe_aliases ?? [],
  };
}

/** Reduce a near-miss entry to anchors (same machinery, fewer fields). */
export function nearMissAnchors(nm: GtNearMiss): Anchors & { id: string } {
  const declared = nm.match ? fromMatch(nm.match) : empty();
  const a = declared.file.length || declared.http.length ? declared : empty();
  if (!a.file.length && str(nm.path)) {
    a.file.push({ path: str(nm.path)!, symbol: str(nm.symbol) });
  }
  if (!a.http.length && str(nm.route)) {
    const p = parseRoute(str(nm.route)!);
    if (p.http?.path) a.http.push(p.http);
  }
  return { ...a, id: nm.id };
}

/** Reduce a reported finding to anchors. */
export function findingAnchors(f: Finding): Anchors {
  const a = empty();
  const h = f.location.http;
  if (h && (h.url || h.path)) {
    const key = httpKeyFromUrl(h.url ?? h.path!, h.method);
    // an explicit param overrides whatever the URL happened to carry
    if (h.param) {
      key.params = [h.param];
      delete key.query[h.param];
    }
    a.http.push(key);
  }
  const file = f.location.file;
  if (file?.path) {
    a.file.push({
      path: file.path,
      symbol: file.symbol,
      lines:
        file.line !== undefined
          ? [file.line, file.end_line ?? file.line]
          : undefined,
    });
  }
  const n = f.location.net;
  if (n && (n.host || n.port !== undefined)) {
    a.net.push({
      host: n.host ?? null,
      port: n.port ?? null,
      proto: (n.proto ?? "tcp").toLowerCase(),
      service: n.service,
      version: n.version,
      state: n.state,
    });
  }
  const g = f.location.graphql;
  if (g && (g.op || g.field)) a.graphql.push({ op: g.op, kind: g.kind, field: g.field });
  const w = f.location.ws;
  if (w) {
    a.ws.push({
      transport: w.transport,
      event: w.event,
      channel: w.channel,
      endpoint: w.endpoint,
    });
  }
  const l = f.location.llm;
  if (l && (l.tool || l.channel)) a.llm.push({ tool: l.tool, channel: l.channel });
  if (f.evidence?.markers?.length) a.markers.push(...f.evidence.markers);
  return a;
}
