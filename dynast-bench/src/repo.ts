/**
 * Where the suite lives, and which apps are in it.
 *
 * One enumerator, because "a new app appears automatically" (CLAUDE.md) only holds
 * if everything agrees on what an app is. The CLI, the derive tool and the tests
 * used to each decide for themselves and disagreed: an app whose folder exists but
 * whose answer key is still the template's example list counted as real in some
 * places and not others.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";

/** Nearest ancestor of `from` holding a `vulnerable-apps/` directory. */
export function findRootAbove(from: string): string | null {
  let dir = from;
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, "vulnerable-apps"))) return dir;
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

/** Repo root for code running from source. The CLI layers its own fallbacks on top. */
export function repoRoot(from = import.meta.dir): string {
  const found = process.env.DYNAST_BENCH_ROOT ?? findRootAbove(from) ?? findRootAbove(process.cwd());
  if (!found) throw new Error("cannot find the vulnerable-apps/ directory");
  return found;
}

export const appsDir = (root: string) => join(root, "vulnerable-apps");
export const groundTruthPath = (root: string, app: string) =>
  join(appsDir(root), app, "ground-truth", "VULNERABILITIES.yaml");

/**
 * `built` = has a real answer key (a mapping with a `vulnerabilities:` list).
 * `skeleton` = copied from `_template` and not filled in yet; the suite must not
 * treat it as a failing app.
 */
export type AppState = "built" | "skeleton";

export interface AppEntry {
  name: string;
  state: AppState;
}

/** Every app folder, in name order, each tagged built or skeleton. */
export function listApps(root: string): AppEntry[] {
  const dir = appsDir(root);
  return readdirSync(dir)
    .filter((n) => !n.startsWith("_") && !n.startsWith("."))
    .filter((n) => existsSync(join(dir, n, "ground-truth")))
    .sort()
    .map((name) => ({ name, state: appState(root, name) }));
}

/** Names of the apps with a real answer key - what the scorer and tests iterate. */
export const builtApps = (root: string): string[] =>
  listApps(root).filter((a) => a.state === "built").map((a) => a.name);

function appState(root: string, app: string): AppState {
  const path = groundTruthPath(root, app);
  if (!existsSync(path)) return "skeleton";
  try {
    const doc = Bun.YAML.parse(readFileSync(path, "utf8")) as unknown;
    const ok =
      typeof doc === "object" &&
      doc !== null &&
      !Array.isArray(doc) &&
      Array.isArray((doc as Record<string, unknown>).vulnerabilities);
    return ok ? "built" : "skeleton";
  } catch {
    return "skeleton";
  }
}

/**
 * `// VULN <ID>` / `// FIXED <ID>` comments, the convention the apps use to label
 * their own planted bugs. It is load-bearing twice - it gives the most reliable
 * line anchor, and it lets `check` attribute a stray twin diff to a bug - so the
 * pattern is defined once.
 */
export const VULN_TAG_RE = /(?:VULN|FIXED)[:\s-]+([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*)/g;

/** Bug ids tagged in a blob of source. */
export function vulnTagsIn(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(VULN_TAG_RE)) if (!out.includes(m[1]!)) out.push(m[1]!);
  return out;
}
