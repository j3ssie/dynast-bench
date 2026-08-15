/**
 * Shared types for the DynAST-Bench scoring pipeline.
 *
 *   findings/v1   what a scanner (or an LLM security agent) reports
 *   ground truth  what vulnerable-apps/<app>/ground-truth/VULNERABILITIES.yaml holds
 *
 * Deliberately dependency-free: hand-written validators live next door in
 * findings.ts / ground-truth.ts so the CLI keeps its zero-runtime-dep promise.
 */

export const FINDINGS_SCHEMA_ID = "dynast-bench.findings/v1";
export const ENDPOINTS_SCHEMA_ID = "dynast-bench.endpoints/v1";

export type Variant = "vuln" | "safe";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "certain" | "firm" | "tentative";
export type ToolMode = "dast" | "sast" | "hybrid" | "agent";

export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
export const CONFIDENCES: Confidence[] = ["certain", "firm", "tentative"];
export const TOOL_MODES: ToolMode[] = ["dast", "sast", "hybrid", "agent"];

/** Answer-key vocabularies. The validator enforces them; reports sort by them. */
export const DIFFICULTIES = ["E", "E-M", "M", "M-H", "H"];
export const TAINTS = ["in-file", "cross-file", "cross-service", "config"];
export const REACHABILITIES = ["pre-auth", "user", "admin", "service", "internal"];

/**
 * How much crawling capability it takes to *find* the endpoint at all, as
 * opposed to `difficulty`, which is how hard the bug is to recognise once you
 * are looking at it. Ordered cheapest to most capable, so recall down this axis
 * reads as "how far into the app did this tool actually get".
 *
 *   static-html   URL appears in the served HTML of a public page
 *   js-static     URL is a literal string in a bundle - greppable, no execution
 *   js-runtime    URL only exists once JS evaluates (fragments, manifest, lazy chunk)
 *   interaction   request only fires on a click/submit/scroll
 *   flow          only reachable from one state of a multi-step flow
 */
export const DISCOVERY_TIERS = [
  "static-html",
  "js-static",
  "js-runtime",
  "interaction",
  "flow",
];

// ------------------------------------------------------------- findings/v1 ---

export interface HttpLocation {
  method?: string;
  /** full URL as hit, if known - the scorer derives path + query from it */
  url?: string;
  /** path only, as hit (concrete ids are fine; the scorer templates them) */
  path?: string;
  /** the injected/abused parameter, when there is one */
  param?: string;
  param_in?: "query" | "body" | "path" | "header" | "cookie" | "json" | string;
  status?: number;
}

export interface FileLocation {
  /** repo-relative if possible; a bare suffix still matches */
  path?: string;
  line?: number;
  end_line?: number;
  symbol?: string;
  snippet?: string;
}

export interface NetLocation {
  host?: string;
  port?: number;
  proto?: string;
  service?: string;
  version?: string;
  state?: "open" | "closed" | "filtered" | string;
}

export interface GraphqlLocation {
  op?: string;
  kind?: "query" | "mutation" | "subscription" | string;
  field?: string;
}

export interface WsLocation {
  transport?: string;
  /** message type / frame name, e.g. "post.search" or "subscribe" */
  event?: string;
  /** channel or room the frame targeted, e.g. "org:globex:posts" */
  channel?: string;
  endpoint?: string;
}

export interface LlmLocation {
  tool?: string;
  /** where the untrusted text entered: user | rag | page | mcp | memory | file */
  channel?: string;
  run_id?: string;
}

export interface FindingLocation {
  http?: HttpLocation;
  file?: FileLocation;
  net?: NetLocation;
  graphql?: GraphqlLocation;
  ws?: WsLocation;
  llm?: LlmLocation;
}

export interface FindingEvidence {
  /** literal strings observed in a response - a seed marker here is near-proof */
  markers?: string[];
  request?: string;
  response_excerpt?: string;
  note?: string;
}

export interface Finding {
  /** unique within the file; used in the report so a row is traceable */
  id: string;
  title?: string;
  cwe?: string;
  /** alternates, if the tool is unsure; scored best-of */
  cwes?: string[];
  severity?: Severity;
  confidence?: Confidence;
  location: FindingLocation;
  evidence?: FindingEvidence;
  /** true = impact actually proven, false = inferred from source or behaviour */
  exploited?: boolean;
  tags?: string[];
}

export interface FindingsRun {
  app?: string;
  /** which twin was scanned - "safe" findings are false positives by construction */
  variant?: Variant;
  target?: string;
  duration_s?: number;
  [k: string]: unknown;
}

export interface FindingsToolInfo {
  name: string;
  version?: string;
  mode?: ToolMode;
}

export interface FindingsFile {
  schema: string;
  tool: FindingsToolInfo;
  run: FindingsRun;
  findings: Finding[];
}

// ------------------------------------------------------------ ground truth ---

/** Machine-readable anchors. Optional: derived from `route`/`variant_paths` when absent. */
export interface GtMatch {
  http?: {
    /** omitted = any verb reaches the sink */
    method?: string;
    path?: string;
    /** query pairs that MUST be present (they disambiguate action-style routes) */
    query?: Record<string, string>;
    /** injectable parameter names */
    params?: string[];
    /** set only for sidecar bugs (Jenkins, phpMyAdmin) that are not on the app port */
    port?: number;
  };
  /**
   * Other paths that reach the same sink, for a bug whose `route:` names more
   * than one ("GET /api/schema/ and /api/docs/"). Each anchors as its own HTTP
   * key, so reporting any one of them is the correct answer - without this a
   * tool that finds the bug at its most visible URL is charged a false positive
   * AND the bug still counts as missed.
   */
  http_alt?: string[];
  file?: {
    path?: string;
    symbol?: string;
    /** [start, end] of the vuln↔safe delta; a finding inside it matches */
    lines?: [number, number];
  };
  net?: { host?: string; port?: number; proto?: string; service?: string; version?: string };
  graphql?: { op?: string; kind?: string };
  ws?: { transport?: string; event?: string; channel?: string; endpoint?: string };
  llm?: { tool?: string; channel?: string };
  /** response strings that prove this specific bug */
  markers?: string[];
  /** overrides the CWE→family table for partial credit */
  cwe_family?: string;
  /** other CWEs that count as a fully correct answer here */
  cwe_aliases?: string[];
}

export interface GtVulnerability {
  id: string;
  variant_paths?: { vuln?: string; safe?: string };
  symbol?: string;
  route?: string;
  cwe?: string;
  owasp?: string;
  llm_owasp?: string;
  severity?: Severity;
  /** detection difficulty: E | E-M | M | M-H | H */
  difficulty?: string;
  /** crawl capability needed to reach it at all - see DISCOVERY_TIERS */
  discovery?: string;
  taint?: string;
  reachability?: string;
  near_miss?: string | null;
  poc?: string;
  notes?: string;
  match?: GtMatch;
  // stack-specific extras (network / websocket / graphql / llm / swagger)
  host?: string;
  segment?: string;
  proto?: string;
  expected_open?: boolean;
  transport?: string;
  graphql_op?: string;
  graphql_kind?: string;
  tool?: string;
  injection_channel?: string;
  documented?: boolean;
  api_version?: string;
  [k: string]: unknown;
}

export interface GtNearMiss {
  id: string;
  path?: string;
  symbol?: string;
  /** the vulnerability this safe sibling sits next to */
  of?: string;
  notes?: string;
  match?: GtMatch;
  [k: string]: unknown;
}

export interface GroundTruth {
  app?: string;
  entry?: string;
  seed_notes?: string;
  vulnerabilities: GtVulnerability[];
  near_misses: GtNearMiss[];
}

// ------------------------------------------------------ attack surface (v1) ---

/**
 * The protocols an operation can live on. `http` is the transport every other
 * kind rides on; the rest exist because "did you reach POST /graphql" and "did
 * you exercise mutation.updatePost" are different questions, and an app whose
 * whole surface hides behind one URL would otherwise score 100% coverage from a
 * single request.
 */
export const OPERATION_KINDS = ["http", "graphql", "ws", "llm", "net"] as const;
export type OperationKind = (typeof OPERATION_KINDS)[number];

/**
 * Anything that can be compared as an operation identity - one shape for both
 * sides of the coverage diff, so the catalog and the agent's report normalize
 * through exactly the same code.
 */
export interface OperationRef {
  kind?: string;
  // http
  method?: string;
  url?: string;
  path?: string;
  /** query pairs that MUST be present - `?action=x` style discriminators */
  query?: Record<string, string>;
  /** injectable parameter names; diagnostics only, never part of identity */
  params?: string[];
  /** only for sidecar operations that are not on the app port */
  port?: number;
  // graphql
  op?: string;
  graphql_kind?: string;
  field?: string;
  // ws / socket.io
  endpoint?: string;
  event?: string;
  channel?: string;
  /** socket.io namespace */
  namespace?: string;
  // llm
  tool?: string;
  injection_channel?: string;
  // net
  host?: string;
  proto?: string;
}

export interface SurfaceOperation extends OperationRef {
  id: string;
  kind: OperationKind;
  /** id of the operation this one rides on (graphql op -> its POST /graphql) */
  via?: string;
  /** crawl capability needed to reach it - see DISCOVERY_TIERS */
  discovery?: string;
  reachability?: string;
  /** vulnerability ids planted here; empty = a benign operation */
  vulns?: string[];
  /**
   * Which twin exposes it. "both" is the default and the overwhelming case; a
   * fix that removes an operation outright declares "vuln" so the safe twin is
   * not scored against an endpoint that no longer exists.
   */
  variant?: "both" | Variant;
  notes?: string;
  [k: string]: unknown;
}

export interface Surface {
  app?: string;
  entry?: string;
  notes?: string;
  operations: SurfaceOperation[];
}

// ------------------------------------------------------------ endpoints/v1 ---

/** One operation a tool claims it discovered. */
export interface ReportedEndpoint extends OperationRef {
  /** free-form, for the report only */
  id?: string;
  note?: string;
}

export interface EndpointsFile {
  schema: string;
  tool: FindingsToolInfo;
  run: FindingsRun;
  endpoints: ReportedEndpoint[];
}

// --------------------------------------------------------------- validation --

export interface ValidationIssue {
  /** dotted path into the document, e.g. findings[3].location */
  at: string;
  msg: string;
}

export interface ValidationResult<T> {
  ok: boolean;
  errors: ValidationIssue[];
  warnings: ValidationIssue[];
  /** present whenever the document was salvageable (ok, or ok-with-warnings) */
  value?: T;
}
