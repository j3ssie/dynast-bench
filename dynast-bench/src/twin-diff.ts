/**
 * The vuln↔safe delta, parsed once.
 *
 * Two consumers want different things out of the same diff - `check` wants change
 * counts and the changed lines themselves, `derive-match` wants vuln-side line
 * ranges - so the spawn and the parse live here and each takes what it needs.
 * `derive-match` used to spawn `diff` once per source file (141 processes for the
 * suite); this is one per app.
 */

import { fileKey } from "./schema/keys.ts";

/** A vuln-side range that differs from the safe twin. */
export interface Hunk {
  start: number;
  end: number;
}

export interface TwinFile {
  /** path relative to the variant root, e.g. src/lib/merge.ts */
  path: string;
  hunks: Hunk[];
  /** total changed lines, counting the larger side of each hunk */
  changed: number;
  /** the `-`/`+` lines, for callers that need to look at the content */
  lines: string[];
  /** present only in one twin */
  onlyIn?: "vuln" | "safe";
}

/** Run a command in a directory. The caller decides how to spawn. */
export type Differ = (
  cwd: string,
  args: string[],
) => Promise<{ code: number; stdout: string; stderr: string }>;

/**
 * `diff -r -U 0 vuln safe`, as a map keyed by variant-relative path.
 *
 * NOT `-ru`: on BSD diff a bare `-u` re-asserts the default 3 lines of context and
 * silently overrides `-U 0`, which merges neighbouring changes into one coarse
 * hunk - and a coarse hunk is a line range that swallows the bug next door.
 */
export async function twinFiles(dir: string, run: Differ): Promise<Map<string, TwinFile>> {
  const res = await run(dir, ["diff", "-r", "-U", "0", "vuln", "safe"]);
  // diff exits 1 when files differ, >1 on trouble
  if (res.code > 1) throw new Error(`diff failed in ${dir}: ${res.stderr.trim()}`);
  return parseUnifiedDiff(res.stdout);
}

/** Parse `diff -ru -U 0` output. Ranges are vuln-side (the answer key's coordinates). */
export function parseUnifiedDiff(stdout: string): Map<string, TwinFile> {
  const out = new Map<string, TwinFile>();
  const blank = (path: string): TwinFile => ({ path, hunks: [], changed: 0, lines: [] });
  let current = "";

  for (const line of stdout.split("\n")) {
    if (line.startsWith("--- ")) {
      current = fileKey(line.slice(4).split("\t")[0]!);
      if (!out.has(current)) out.set(current, blank(current));
      continue;
    }
    if (line.startsWith("Only in ")) {
      const m = line.match(/^Only in (vuln|safe)([^:]*): (.+)$/);
      if (m) {
        const path = fileKey(`${m[2]!.replace(/^\/?/, "")}/${m[3]!}`);
        out.set(path, { ...blank(path), changed: 1, onlyIn: m[1] as "vuln" | "safe" });
      }
      continue;
    }
    if (!current || line.startsWith("+++ ")) continue;

    const e = out.get(current)!;
    const at = line.match(/^@@ -(\d+)(?:,(\d+))? \+\d+(?:,(\d+))? @@/);
    if (at) {
      const start = Number(at[1]);
      const removed = at[2] === undefined ? 1 : Number(at[2]);
      const added = at[3] === undefined ? 1 : Number(at[3]);
      // removed 0 = a pure insertion in safe/; anchor it on the line it follows
      e.hunks.push(
        removed === 0
          ? { start: Math.max(1, start), end: start + 1 }
          : { start: Math.max(1, start), end: start + removed - 1 },
      );
      e.changed += Math.max(removed, added);
      continue;
    }
    if (/^[-+]/.test(line)) e.lines.push(line);
  }
  return out;
}
