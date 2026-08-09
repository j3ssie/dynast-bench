/**
 * Format detection + dispatch.
 *
 *   normalizeText(raw) -> findings/v1
 *
 * A file that is already findings/v1 passes through, so `dynast-bench score` takes
 * either a normalized file or a scanner's native output without a flag.
 */

import { FINDINGS_SCHEMA_ID, type FindingsFile, type Variant } from "../schema/types.ts";
import { validateFindings } from "../schema/findings.ts";
import {
  fromBurp,
  fromNmap,
  fromNuclei,
  fromSarif,
  fromZap,
  type AdapterResult,
} from "./adapters.ts";

export type Format = "findings/v1" | "zap" | "sarif" | "nuclei" | "burp" | "nmap" | "unknown";

export const FORMATS: Format[] = ["findings/v1", "zap", "sarif", "nuclei", "burp", "nmap"];

/** JSONL (one JSON object per line) -> array. Returns null if it is not JSONL. */
function parseJsonl(text: string): any[] | null {
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return null;
  const out: any[] = [];
  for (const line of lines) {
    if (!line.startsWith("{")) return null;
    try {
      out.push(JSON.parse(line));
    } catch {
      return null;
    }
  }
  return out;
}

/** What is this file? */
export function detectFormat(text: string): { format: Format; doc?: unknown } {
  const head = text.slice(0, 4096);
  const trimmed = text.trimStart();

  if (trimmed.startsWith("<")) {
    if (/<nmaprun\b/i.test(head)) return { format: "nmap" };
    if (/<issues\b|<issue>/i.test(head)) return { format: "burp" };
    return { format: "unknown" };
  }

  let doc: unknown;
  let parsed = false;
  try {
    doc = JSON.parse(text);
    parsed = true;
  } catch {
    /* may still be JSONL */
  }

  if (parsed) {
    const d: any = doc;
    if (typeof d?.schema === "string" && d.schema.includes("dynast-bench.findings")) {
      return { format: "findings/v1", doc };
    }
    if (Array.isArray(d?.runs) && d.runs.some((r: any) => r?.tool?.driver)) {
      return { format: "sarif", doc };
    }
    if (typeof d?.$schema === "string" && d.$schema.toLowerCase().includes("sarif")) {
      return { format: "sarif", doc };
    }
    if (d?.site !== undefined && (Array.isArray(d.site) ? d.site[0]?.alerts : d.site?.alerts)) {
      return { format: "zap", doc };
    }
    if (Array.isArray(d) && d.length && d[0]?.["template-id"]) return { format: "nuclei", doc };
    if (d?.["template-id"]) return { format: "nuclei", doc: [d] };
    if (Array.isArray(d?.findings) || Array.isArray(d)) return { format: "findings/v1", doc };
    return { format: "unknown", doc };
  }

  const jsonl = parseJsonl(text);
  if (jsonl && jsonl.some((x) => x?.["template-id"])) return { format: "nuclei", doc: jsonl };
  if (jsonl && jsonl.some((x) => x?.location || x?.url)) {
    return { format: "findings/v1", doc: { findings: jsonl } };
  }
  return { format: "unknown" };
}

export interface NormalizeOpts {
  app?: string;
  variant?: Variant;
  target?: string;
  format?: Format;
  /** proof markers from the answer key, so the `proof` tier is reachable */
  markers?: readonly string[];
}

export interface NormalizeResult {
  format: Format;
  file: FindingsFile;
  notes: string[];
  errors: { at: string; msg: string }[];
  warnings: { at: string; msg: string }[];
}

/**
 * Raw text (any supported format) -> a validated findings/v1 file.
 * `app` and `variant` fill in the run metadata a native scanner cannot know.
 */
export function normalizeText(text: string, opts: NormalizeOpts = {}): NormalizeResult {
  const detected = opts.format && opts.format !== "unknown"
    ? { format: opts.format, doc: undefined as unknown }
    : detectFormat(text);
  const format = detected.format;

  const parseFor = (): unknown => {
    if (detected.doc !== undefined) return detected.doc;
    try {
      return JSON.parse(text);
    } catch {
      return parseJsonl(text) ?? undefined;
    }
  };

  let adapted: AdapterResult;
  switch (format) {
    case "findings/v1": {
      const doc: any = parseFor() ?? {};
      const res = validateFindings(doc, { app: opts.app, variant: opts.variant });
      const file = res.value ?? {
        schema: FINDINGS_SCHEMA_ID,
        tool: { name: "unknown" },
        run: {},
        findings: [],
      };
      if (opts.target && !file.run.target) file.run.target = opts.target;
      return { format, file, notes: [], errors: res.errors, warnings: res.warnings };
    }
    case "zap":
      adapted = fromZap(parseFor(), opts);
      break;
    case "sarif":
      adapted = fromSarif(parseFor(), opts);
      break;
    case "nuclei": {
      const doc = parseFor();
      adapted = fromNuclei(Array.isArray(doc) ? doc : doc ? [doc] : [], opts);
      break;
    }
    case "burp":
      adapted = fromBurp(text, opts);
      break;
    case "nmap":
      adapted = fromNmap(text);
      break;
    default:
      return {
        format: "unknown",
        file: { schema: FINDINGS_SCHEMA_ID, tool: { name: "unknown" }, run: {}, findings: [] },
        notes: [],
        errors: [
          {
            at: "$",
            msg: `unrecognised format - supported: ${FORMATS.join(", ")} (pass --format to force one)`,
          },
        ],
        warnings: [],
      };
  }

  const envelope = {
    schema: FINDINGS_SCHEMA_ID,
    tool: adapted.tool,
    run: { app: opts.app, variant: opts.variant ?? "vuln", target: opts.target },
    findings: adapted.findings,
  };
  const res = validateFindings(envelope, { app: opts.app, variant: opts.variant });
  return {
    format,
    file: res.value ?? (envelope as FindingsFile),
    notes: adapted.notes,
    errors: res.errors,
    // a converted file's warnings are about the scanner's data, not the user's
    warnings: res.warnings.filter((w) => !w.at.startsWith("run.variant")),
  };
}
