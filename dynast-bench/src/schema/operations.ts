/**
 * Operation identity - what makes two operations "the same endpoint".
 *
 * Both sides of the coverage diff go through here: the SURFACE.yaml catalog and
 * whatever the agent reported. That is the whole point - if the catalog and the
 * report normalized separately they would disagree about `/api/posts/7` vs
 * `/api/posts/{id}` and the score would measure the normalizer, not the agent.
 *
 * Three rules inherited from the finding matcher (see keys.ts), plus one new:
 *
 *  1. Concrete ids get templated. The agent reports /api/posts/7, the catalog
 *     says /api/posts/{id}.
 *  2. Case, trailing slash and percent-encoding are preserved in the strict
 *     pass - weirdproxy plants /admin/ and /ADMIN as genuinely different
 *     endpoints. A loose pass exists and every hit records which one paid.
 *  3. A required query pair is part of the identity. Reporting
 *     `admin-ajax.php` must not credit every `?action=` behind it.
 *  4. NEW: transport is not operation. `POST /graphql` is one operation; every
 *     GraphQL op behind it is its own. Same for a WS handshake vs its events,
 *     and an agent-run endpoint vs the tools the agent can call.
 */

import { httpKeyFromUrl, normalizeMethod, pathGlobMatches, templatePath } from "./keys.ts";
import type { OperationKind, OperationRef, SurfaceOperation } from "./types.ts";

export type MatchPass = "strict" | "loose";

/**
 * Which protocol an operation ref is talking about. The catalog always declares
 * `kind:`; a reported endpoint usually does not, so it is inferred from which
 * fields are populated.
 */
export function refKind(ref: OperationRef): OperationKind | null {
  const k = (ref.kind ?? "").trim().toLowerCase();
  if (k === "http" || k === "graphql" || k === "ws" || k === "llm" || k === "net") return k;
  if (k === "websocket" || k === "socketio" || k === "socket.io" || k === "wss") return "ws";
  if (k === "gql") return "graphql";
  if (k === "agent" || k === "tool") return "llm";
  if (k === "tcp" || k === "udp" || k === "port") return "net";

  if (ref.op || ref.field || ref.graphql_kind) return "graphql";
  if (ref.event || ref.channel || ref.namespace) return "ws";
  if (ref.tool || ref.injection_channel) return "llm";
  if (ref.endpoint && !ref.path && !ref.url) return "ws";
  if (ref.path || ref.url) return "http";
  // host+port with no path is a service, not a URL
  if (ref.port !== undefined && (ref.host || ref.proto)) return "net";
  return null;
}

/**
 * Split a ref's URL-ish field into a path and its required query pairs, using
 * the SAME parser the finding matcher uses. Two parsers would eventually
 * disagree about a matrix param or an IPv6 authority, and the symptom would be
 * a silently lower coverage number rather than an error.
 *
 * An explicit `query:` mapping wins over anything inline, and only pairs with a
 * concrete value are discriminators - `?q=` names an injectable parameter, not a
 * different endpoint.
 */
function refUrl(ref: OperationRef): { path: string | null; query: Record<string, string> } {
  const raw = ref.path ?? ref.endpoint ?? ref.url;
  if (!raw) return { path: null, query: { ...(ref.query ?? {}) } };
  const key = httpKeyFromUrl(String(raw));
  return { path: key.path, query: { ...key.query, ...(ref.query ?? {}) } };
}

const refPath = (ref: OperationRef): string | null => refUrl(ref).path;
const refQuery = (ref: OperationRef): Record<string, string> => refUrl(ref).query;

const lower = (s: string | undefined | null): string => (s ?? "").trim().toLowerCase();

/** Tool names differ only cosmetically between frameworks: run_shell ~ runShell. */
const toolKey = (s: string | undefined): string =>
  (s ?? "").replace(/[^A-Za-z0-9]+/g, "").toLowerCase();

/**
 * A stable display id for an operation. Used for the hit/missed/unknown lists
 * and for duplicate detection in `check` - NOT for matching, which is the
 * predicate below (a catalog entry with no `method:` matches any verb, and no
 * single string can express that).
 */
export function opKey(ref: OperationRef): string {
  const kind = refKind(ref);
  switch (kind) {
    case "http": {
      const path = refPath(ref) ?? "/";
      const q = Object.entries(refQuery(ref))
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${v}`)
        .join("&");
      const port = ref.port === undefined ? "" : `:${ref.port}`;
      return `${normalizeMethod(ref.method) ?? "ANY"}${port} ${templatePath(path)}${q ? "?" + q : ""}`;
    }
    case "graphql": {
      const k = lower(ref.graphql_kind) || "query";
      if (ref.op) return `graphql ${k}.${ref.op}`;
      return `graphql field ${ref.field}`;
    }
    case "ws": {
      const ep = refPath(ref) ?? ref.endpoint ?? "*";
      const ns = ref.namespace ? ` ns:${ref.namespace}` : "";
      const ev = ref.event ? ` ${ref.event}` : "";
      const ch = ref.channel ? ` #${ref.channel}` : "";
      return `ws ${templatePath(ep)}${ns}${ev}${ch}`;
    }
    case "llm":
      return ref.tool ? `llm tool:${ref.tool}` : `llm channel:${lower(ref.injection_channel)}`;
    case "net":
      return `net ${lower(ref.host) || "*"}:${ref.port ?? "?"}/${lower(ref.proto) || "tcp"}`;
    default:
      return "(unidentifiable)";
  }
}

/** Path match, falling back to the case/slash-folding pass. */
const pathPass = (want: string, got: string): MatchPass | null =>
  pathGlobMatches(want, got) ? "strict" : pathGlobMatches(want, got, true) ? "loose" : null;

/**
 * Name match where the exact spelling is the strict answer and a folded one
 * still counts. `norm` is what "folded" means for this field - plain lowercase
 * for a GraphQL op or a WS event, punctuation-insensitive for a tool name.
 */
const namePass = (
  want: string,
  got: string | undefined,
  norm: (s: string | undefined) => string = lower,
): MatchPass | null => {
  if (!got || norm(got) !== norm(want)) return null;
  return got === want ? "strict" : "loose";
};

/**
 * An optional discriminator: it can only disqualify a match when BOTH sides
 * state it. A catalog entry that pins a field the report omitted still matches,
 * because omitting it is not a claim that it differs.
 */
const agrees = (want: string | undefined, got: string | undefined): boolean =>
  !want || !got || lower(want) === lower(got);

/** The weaker of two passes - any loose leg makes the whole match loose. */
const weakest = (...passes: (MatchPass | null)[]): MatchPass | null =>
  passes.includes(null) ? null : passes.includes("loose") ? "loose" : "strict";

/**
 * Does a reported endpoint reach a cataloged operation?
 *
 * Returns which pass paid, or null. `strict` is a real match; `loose` folded
 * case or a trailing slash, or forgave an unstated HTTP verb - still credited,
 * but the report says so, because on weirdproxy a loose hit may be the wrong
 * endpoint entirely.
 */
export function opMatches(want: SurfaceOperation, got: OperationRef): MatchPass | null {
  const kind = want.kind;
  if (refKind(got) !== kind) return null;

  switch (kind) {
    case "http": {
      const wantPath = refPath(want);
      const gotPath = refPath(got);
      if (!wantPath || !gotPath) return null;

      // every required discriminator must be present with the same value
      const wq = refQuery(want);
      const gq = refQuery(got);
      for (const [k, v] of Object.entries(wq)) {
        if (lower(gq[k]) !== lower(v)) return null;
      }

      // a catalog entry with no method is reachable by any verb
      const wm = normalizeMethod(want.method);
      const gm = normalizeMethod(got.method);
      if (wm && gm && wm !== gm) return null;
      // the agent never said which verb it used
      const methodPass: MatchPass = wm && !gm ? "loose" : "strict";

      // a sidecar operation is only reached on its own port
      let portPass: MatchPass = "strict";
      if (want.port !== undefined && want.port !== got.port) {
        if (got.port !== undefined) return null;
        portPass = "loose";
      }

      return weakest(pathPass(wantPath, gotPath), methodPass, portPass);
    }

    case "graphql": {
      if (want.op) {
        return agrees(want.graphql_kind, got.graphql_kind) && agrees(want.field, got.field)
          ? namePass(want.op, got.op)
          : null;
      }
      return want.field ? namePass(want.field, got.field) : null;
    }

    case "ws": {
      const wantEp = refPath(want);
      const gotEp = refPath(got);
      // endpoint named on the catalog side but left implicit in the report is a
      // loose hit; neither side naming one is fine
      const epPass: MatchPass | null =
        wantEp && gotEp ? pathPass(wantEp, gotEp) : wantEp ? "loose" : "strict";
      if (!epPass) return null;
      if (want.namespace && lower(got.namespace ?? "/") !== lower(want.namespace)) return null;
      if (!agrees(want.channel, got.channel) || (want.channel && !got.channel)) return null;

      // The handshake is its own operation. An entry that names an event is only
      // reached by a report that names that event - otherwise one "I connected
      // to /ws" would cover every message the app routes, and a report that DOES
      // name one must not credit the bare transport entry.
      if (!want.event) return got.event ? null : epPass;
      return weakest(epPass, namePass(want.event, got.event));
    }

    case "llm": {
      if (want.tool) {
        return agrees(want.injection_channel, got.injection_channel)
          ? namePass(want.tool, got.tool, toolKey)
          : null;
      }
      if (want.injection_channel) {
        return lower(got.injection_channel) === lower(want.injection_channel) ? "strict" : null;
      }
      return null;
    }

    case "net": {
      if (want.port === undefined || want.port !== got.port) return null;
      if ((lower(want.proto) || "tcp") !== (lower(got.proto) || "tcp")) return null;
      if (!agrees(want.host, got.host)) return null;
      return want.host && !got.host ? "loose" : "strict";
    }

    default:
      return null;
  }
}
