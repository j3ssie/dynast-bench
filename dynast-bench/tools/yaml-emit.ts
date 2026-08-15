/**
 * YAML flow-scalar emitting, shared by the two ground-truth generators.
 *
 * `derive-match` writes `match:` blocks into VULNERABILITIES.yaml and
 * `derive-surface` writes SURFACE.yaml. Both splice text into files a human
 * maintains, so both need the same answer to "does this value need quoting" -
 * two rules that disagree means a value safe from one generator is unsafe from
 * the other, and the quoting bug has to be found twice.
 */

/**
 * Quote anything that could be read as structure.
 *
 * The `y|n|yes|no|...` guard is the one people forget: YAML 1.1 reads a bare
 * `no` as boolean false, so an unquoted symbol or path spelled that way changes
 * type on the way back in.
 */
export function q(v: string | number | boolean): string {
  if (typeof v !== "string") return String(v);
  if (v === "") return '""';
  if (
    /^[A-Za-z0-9_][A-Za-z0-9_.\/=-]*$/.test(v) &&
    !/^(?:y|n|yes|no|true|false|on|off|null|~)$/i.test(v)
  ) {
    return v;
  }
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export const flowMap = (pairs: [string, string][]): string =>
  `{ ${pairs.map(([k, v]) => `${k}: ${v}`).join(", ")} }`;

export const flowSeq = (items: string[]): string => `[${items.join(", ")}]`;
