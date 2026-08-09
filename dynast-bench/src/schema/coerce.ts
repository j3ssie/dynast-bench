/**
 * Coercion primitives shared by the validators. Both `findings/v1` and
 * `VULNERABILITIES.yaml` lean on the same "empty means absent" semantics, so it is
 * defined once here rather than three times.
 */

export const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** Trimmed string, or undefined when absent/empty. */
export const str = (v: unknown): string | undefined => {
  if (v === null || v === undefined) return undefined;
  const s = String(v).trim();
  return s === "" ? undefined : s;
};

/** Finite number, or undefined. */
export const num = (v: unknown): number | undefined => {
  if (v === null || v === undefined || v === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
};

/** A list of non-empty strings, or undefined. Scalars are accepted as a 1-list. */
export const strArray = (v: unknown): string[] | undefined => {
  if (v === null || v === undefined) return undefined;
  const arr = Array.isArray(v) ? v : [v];
  const out = arr.map(str).filter(Boolean) as string[];
  return out.length ? out : undefined;
};
