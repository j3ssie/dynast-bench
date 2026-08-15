/**
 * The `{schema, tool, run, <items>}` wrapper both report formats share.
 *
 * `findings/v1` (what you found wrong) and `endpoints/v1` (what you reached) are
 * different payloads inside one envelope spec. Written twice, they drift: the
 * second copy silently loses a rule and nobody notices until a scan is scored
 * against the wrong twin.
 *
 * Same posture as the payload validators: forgiving on shape, strict on meaning.
 * `run.variant` is the one field that MUST be strict - a safe-twin report that
 * does not say so is scored as a vuln run, which turns every false alarm into a
 * true positive.
 */

import { isObj, num, str } from "./coerce.ts";
import {
  TOOL_MODES,
  type FindingsRun,
  type FindingsToolInfo,
  type ToolMode,
  type ValidationIssue,
  type Variant,
} from "./types.ts";

export interface EnvelopeOpts {
  app?: string;
  variant?: Variant;
}

export interface Envelope {
  tool: FindingsToolInfo;
  run: FindingsRun & { variant: Variant };
  /** the payload array, still raw - the caller owns coercing its items */
  items: unknown[] | null;
}

/**
 * Parse the wrapper and hand back the payload array.
 *
 * `listKey` names the payload ("findings" / "endpoints") so a bare array can be
 * re-wrapped and the "missing or not an array" error points at the right key.
 * `noun` is how the payload is described in the variant-mismatch messages.
 */
export function parseEnvelope(
  doc: unknown,
  spec: { schemaId: string; listKey: string; noun: string; altKeys?: string[] },
  opts: EnvelopeOpts,
  errors: ValidationIssue[],
  warnings: ValidationIssue[],
): Envelope {
  let root: Record<string, unknown>;
  if (Array.isArray(doc)) {
    root = { [spec.listKey]: doc };
    warnings.push({ at: "$", msg: `bare array accepted as {${spec.listKey}: [...]}` });
  } else if (isObj(doc)) {
    root = doc;
  } else {
    errors.push({ at: "$", msg: "document is not an object or array" });
    return { tool: { name: "unknown" }, run: { variant: opts.variant ?? "vuln" }, items: null };
  }

  const schema = str(root.schema);
  if (!schema) {
    warnings.push({ at: "schema", msg: `missing - assuming ${spec.schemaId}` });
  } else if (schema !== spec.schemaId) {
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
  const mode =
    modeRaw && (TOOL_MODES as string[]).includes(modeRaw) ? (modeRaw as ToolMode) : undefined;
  if (modeRaw && !mode) {
    warnings.push({
      at: "tool.mode",
      msg: `unknown mode "${modeRaw}" - expected ${TOOL_MODES.join("|")}`,
    });
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
      msg: `missing - assuming "${variant}"; a safe-twin run MUST say so or its ${spec.noun} score against the wrong twin`,
    });
  }
  if (opts.app && app && app !== opts.app) {
    errors.push({ at: "run.app", msg: `${spec.noun} are for "${app}", scoring "${opts.app}"` });
  }
  if (opts.variant && variant !== opts.variant) {
    errors.push({
      at: "run.variant",
      msg: `${spec.noun} are from the "${variant}" twin, scoring "${opts.variant}"`,
    });
  }

  let items: unknown = root[spec.listKey];
  for (const alt of spec.altKeys ?? []) {
    if (items === undefined) items = root[alt];
  }
  if (!Array.isArray(items)) {
    errors.push({ at: spec.listKey, msg: "missing or not an array" });
    items = null;
  }

  return {
    tool: { name: toolName, version: str(rawTool.version), mode },
    run: {
      ...rawRun,
      app,
      variant,
      target: str(rawRun.target),
      duration_s: num(rawRun.duration_s),
    },
    items: items as unknown[] | null,
  };
}
