/**
 * What git ships has to be what `make validate` validates.
 *
 * WHY THIS EXISTS
 *
 * An ignored file in the working copy is invisible: the app boots, every PoC
 * passes, `check` is clean - and none of it survives a clone. This bit twice at
 * once, both times on a file that was never going to show up in `git status`:
 *
 *   laravel  vuln/.env IS DEBUG-001 (APP_DEBUG=true) and a committed APP_KEY,
 *            and public/.env.backup IS SECRET-001. The stock Laravel .gitignore
 *            ignores both, so a clone shipped neither bug - nor a DB config.
 *   rails    bin/rails is the binstub entrypoint.sh runs at boot. The root
 *            `bin/` rule (there for .NET build output) swallowed it, so a clone
 *            built an image whose container exited before Puma started.
 *
 * Neither failure is visible from the working copy, which is exactly why it
 * needs a test rather than a habit.
 */

import { describe, expect, test } from "bun:test";

import { existsSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

import { APPS_DIR, ROOT, appNames, loadGt } from "./helpers.ts";

const apps = appNames();

function git(...args: string[]): string | null {
  const res = Bun.spawnSync(["git", ...args], { cwd: ROOT });
  return res.exitCode === 0 ? res.stdout.toString() : null;
}

/** Everything git knows about, staged included - `git add` is enough to fix a miss. */
const listing = git("ls-files", "-c", "--", "vulnerable-apps");
const tracked = new Set((listing ?? "").split("\n").filter(Boolean));

// A release tarball has no .git, and "git said nothing" would otherwise read as
// "nothing is tracked" and fail every case below. There is no question to answer
// without a repo, so there is nothing to assert.
const inRepo = listing !== null;
const check = inRepo ? test : test.skip;

const rel = (p: string) => relative(ROOT, p).split("\\").join("/");

/**
 * Build output and downloaded dependencies: regenerated inside the image, so
 * ignoring them is correct. Anything else that is present-but-ignored under a
 * build context is a file the clone will not have.
 */
const REGENERABLE = [
  /(^|\/)node_modules\//,
  /(^|\/)vendor\//,
  /(^|\/)\.venv\//,
  /(^|\/)__pycache__\//,
  /(^|\/)target\//,
  /(^|\/)build\//,
  // laravel: written by `composer install` / `artisan package:discover` in the Dockerfile
  /(^|\/)bootstrap\/cache\//,
  /(^|\/)storage\/(logs|framework)\//,
  /\.(pyc|class|war|exe|tsbuildinfo|pid|swp)$/,
  /(^|\/)(\.DS_Store|Thumbs\.db)$/,
];

const regenerable = (p: string) => REGENERABLE.some((re) => re.test(p));

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === ".git") continue;
    const full = join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else out.push(full);
  }
  return out;
}

describe.each(apps)("%s", (app) => {
  check("every path the answer key names is tracked", () => {
    const gt = loadGt(app);
    const missing: string[] = [];
    const want = (p: string | undefined) => {
      if (!p) return;
      const full = `vulnerable-apps/${app}/${p}`;
      if (!tracked.has(full)) missing.push(full);
    };
    for (const v of gt.vulnerabilities) {
      // variant_paths.safe is deliberately absent for a bug whose fix is
      // "delete the file" (laravel SECRET-001), so only require what is on disk.
      for (const p of [v.variant_paths?.vuln, v.variant_paths?.safe, v.match?.file?.path]) {
        if (p && existsSync(join(APPS_DIR, app, p))) want(p);
      }
      want(v.poc);
    }
    for (const n of gt.near_misses) want(n.match?.file?.path ?? n.path);
    expect(missing, `${app}: answer-key paths git will not ship`).toEqual([]);
  });

  check("nothing inside a build context is present-but-ignored", () => {
    const hidden: string[] = [];
    for (const variant of ["vuln", "safe"]) {
      const dir = join(APPS_DIR, app, variant);
      if (!existsSync(dir)) continue;
      for (const f of walk(dir)) {
        const p = rel(f);
        if (tracked.has(p) || regenerable(p)) continue;
        hidden.push(p);
      }
    }
    expect(
      hidden,
      `${app}: files docker builds from that a clone will not have — ` +
        "git add them, or add a REGENERABLE rule if the image rebuilds them",
    ).toEqual([]);
  });
});

check("the ground truth itself is tracked", () => {
  for (const app of apps) {
    for (const f of ["VULNERABILITIES.yaml", "SURFACE.yaml", "run.sh"]) {
      const p = `vulnerable-apps/${app}/ground-truth/${f}`;
      if (!existsSync(join(ROOT, p))) continue;
      expect(tracked.has(p), `${p} is not tracked`).toBe(true);
    }
  }
});
