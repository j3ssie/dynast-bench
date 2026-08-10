/**
 * The benchmark's own invariants - what CI must refuse to merge.
 *
 * These live in `src/` rather than in the CLI because they are properties of the
 * BENCHMARK, not of a command: the test suite asserts them for every app, and the
 * CLI is a thin renderer over them. The one thing that needs a subprocess (`diff`
 * between the twins) is injected, so nothing here has to know how the caller
 * prefers to spawn things.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { vulnTagsIn } from "../repo.ts";
import { twinFiles, type Differ } from "../twin-diff.ts";
import { fileKey } from "../schema/keys.ts";
import { parseGroundTruthFile } from "../schema/ground-truth.ts";
import type { GroundTruth } from "../schema/types.ts";
import { anchorFingerprint, gtAnchors } from "../scorer/anchors.ts";

export type IssueLevel = "error" | "warn";

export interface CheckIssue {
  app: string;
  level: IssueLevel;
  at: string;
  msg: string;
}

export type { Differ };

export interface DiffFile {
  /** path relative to the variant root, e.g. src/lib/merge.ts */
  path: string;
  hunks: number;
  changed: number;
  /** ids of the bugs whose entry names this file */
  claimedBy: string[];
  /** near-miss ids that name this file - a near-miss must NOT differ */
  nearMisses: string[];
  /** the twins may legitimately differ here, but only in the ways INFRA_EXEMPT allows */
  infra: boolean;
  /** bug ids named in the changed lines themselves (VULN/FIXED comments) */
  mentions: string[];
  /** changed lines that are not an allowed plumbing difference */
  unexplained: string[];
}

export interface CheckTarget {
  name: string;
  /** vulnerable-apps/<app> */
  dir: string;
}

/**
 * Files where the two twins are ALLOWED to differ, and only in these ways: the
 * compose project name and the package name have to differ or the two stacks
 * cannot exist side by side. Everything else in these files is a real change and
 * is reported as one - an earlier version of this check excused whole files by
 * name, which hid the fact that nextjs's compose also drops a leaked API key and
 * network's entrypoint flips the variant the whole app switches on.
 */
const INFRA_FILE =
  /(?:^|\/)(?:docker-compose\.ya?ml|Dockerfile(?:\..+)?|entrypoint(?:\..+)?\.sh|package(?:-lock)?\.json|bun\.lock|composer\.(?:json|lock)|Gemfile(?:\.lock)?|pom\.xml|[^/]+\.csproj|requirements\.txt|go\.(?:mod|sum))$/;

/**
 * Changed lines that are not a fix, matched by CONTENT rather than by filename:
 *
 *  1. the twin naming itself - the compose project, the container and the package
 *     have to differ or the two stacks cannot exist side by side;
 *  2. the variant selector - some apps (network, wordpress) ship one switch that
 *     picks the whole variant's behaviour instead of a per-bug code change, so
 *     flipping its default is the mechanism of every fix in that app, not of one.
 */
const INFRA_EXEMPT = [
  /^[-+]\s*(?:"?name"?|container_name):\s*"?(?:vuln|safe)-/,
  /^[-+].*\b(?:VARIANT|SECURE|SAFE_MODE)\b\s*[:=]\s*"?\$?\{?[A-Za-z_]*:?-?(?:vuln|safe|true|false)\b/,
  /^[-+]{3}\s/, // diff headers
];

const isExempt = (line: string) => INFRA_EXEMPT.some((re) => re.test(line));

/**
 * `diff -ru` between the twins, reduced to per-file change counts and
 * cross-referenced against the answer key.
 */
export async function twinDiff(
  target: CheckTarget,
  gt: GroundTruth,
  run: Differ,
): Promise<DiffFile[]> {
  const files = await twinFiles(target.dir, run);

  const claims = new Map<string, Set<string>>();
  const add = (m: Map<string, Set<string>>, path: string, id: string) => {
    const key = fileKey(path);
    if (!key) return;
    m.set(key, (m.get(key) ?? new Set()).add(id));
  };
  for (const v of gt.vulnerabilities) {
    for (const p of [v.variant_paths?.vuln, v.variant_paths?.safe, v.match?.file?.path]) {
      if (p && !p.startsWith("(")) add(claims, p, v.id);
    }
  }
  const nmClaims = new Map<string, Set<string>>();
  for (const nm of gt.near_misses) {
    const p = nm.path ?? nm.match?.file?.path;
    if (p) add(nmClaims, p, nm.id);
  }

  return [...files.values()]
    .map((f) => {
      const mentions = new Set<string>();
      const unexplained: string[] = [];
      for (const line of f.lines) {
        for (const id of vulnTagsIn(line)) mentions.add(id);
        if (!isExempt(line)) unexplained.push(line.slice(0, 120));
      }
      if (f.onlyIn) unexplained.push(`only in ${f.onlyIn}/`);
      return {
        path: f.path,
        hunks: f.hunks.length || (f.onlyIn ? 1 : 0),
        changed: f.changed,
        claimedBy: [...(claims.get(f.path) ?? [])].sort(),
        nearMisses: [...(nmClaims.get(f.path) ?? [])].sort(),
        infra: INFRA_FILE.test(f.path),
        mentions: [...mentions].sort(),
        unexplained,
      };
    })
    .sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Every invariant, for one app. `skeleton` apps (copied from `_template` and not
 * filled in) return a single informational row rather than a pile of schema errors.
 */
export async function checkApp(target: CheckTarget, run: Differ): Promise<CheckIssue[]> {
  const issues: CheckIssue[] = [];
  const add = (level: IssueLevel, at: string, msg: string) =>
    issues.push({ app: target.name, level, at, msg });

  const gtPath = join(target.dir, "ground-truth", "VULNERABILITIES.yaml");
  if (!existsSync(gtPath)) {
    add("warn", "ground-truth", "no VULNERABILITIES.yaml - not built yet");
    return issues;
  }
  const res = parseGroundTruthFile(gtPath);
  const gt = res.value;
  if (!gt || !gt.vulnerabilities.length) {
    add(
      "warn",
      "VULNERABILITIES.yaml",
      gt ? "no entries yet - skeleton, not built" : `still the template skeleton (${res.errors[0]?.msg})`,
    );
    return issues;
  }
  for (const e of res.errors) add("error", e.at, e.msg);
  for (const w of res.warnings) add("warn", w.at, w.msg);

  const lineCounts = new Map<string, number>();
  const lineCount = (abs: string): number => {
    const hit = lineCounts.get(abs);
    if (hit !== undefined) return hit;
    const n = readFileSync(abs, "utf8").split("\n").length;
    lineCounts.set(abs, n);
    return n;
  };

  // every PoC exists, and every declared anchor points at a real file and line
  for (const v of gt.vulnerabilities) {
    if (v.poc && !existsSync(join(target.dir, v.poc))) {
      add("error", `${v.id}.poc`, `missing PoC ${v.poc}`);
    }
    const f = v.match?.file;
    if (!f?.path) continue;
    const abs = join(target.dir, f.path);
    if (!existsSync(abs)) {
      add("error", `${v.id}.match.file`, `path does not exist: ${f.path}`);
      continue;
    }
    if (f.lines && f.lines[1] > lineCount(abs)) {
      add(
        "error",
        `${v.id}.match.file.lines`,
        `${f.lines[1]} is past EOF (${lineCount(abs)} lines)`,
      );
    }
  }

  // two bugs no tool could ever tell apart
  const seen = new Map<string, string[]>();
  for (const v of gt.vulnerabilities) {
    const key = anchorFingerprint(v);
    seen.set(key, [...(seen.get(key) ?? []), v.id]);
  }
  for (const ids of seen.values()) {
    if (ids.length > 1) {
      add("warn", ids.join(","), "same CWE and same anchors - a scorer cannot tell these apart");
    }
  }

  // a near-miss in its own file with no route anchor can only ever be caught by a
  // source scanner, which quietly makes `discrimination` a SAST-only metric
  const bugFiles = new Set(
    gt.vulnerabilities.map((v) => fileKey(String(v.variant_paths?.vuln ?? ""))),
  );
  for (const nm of gt.near_misses) {
    const path = nm.path ?? nm.match?.file?.path;
    if (!path || bugFiles.has(fileKey(path))) continue;
    if (!nm.match?.http?.path) {
      add(
        "warn",
        nm.id,
        "own file but no route anchor - a black-box tool can never be charged for flagging it (add route:)",
      );
    }
  }

  // Discovery tiers are all-or-nothing per app. Tiering only half a key is worse
  // than tiering none of it: the breakdown still renders, but "recall 3/3 at
  // static-html" silently means "of the three entries anyone bothered to label".
  const tiered = gt.vulnerabilities.filter((v) => v.discovery);
  if (!tiered.length) {
    add(
      "warn",
      "VULNERABILITIES.yaml",
      "no discovery: tiers - recall by crawl tier will be empty for this app",
    );
  } else if (tiered.length < gt.vulnerabilities.length) {
    const missing = gt.vulnerabilities.filter((v) => !v.discovery).map((v) => v.id);
    add(
      "error",
      missing.join(","),
      `no discovery: tier while ${tiered.length} sibling(s) have one - ` +
        `a partial breakdown reports recall over the labelled subset only`,
    );
  }

  // the twin delta stays inside the answer key
  const diff = await twinDiff(target, gt, run);
  const knownIds = new Set(gt.vulnerabilities.map((v) => v.id));
  for (const f of diff) {
    if (f.nearMisses.length && !f.claimedBy.length) {
      add("error", f.nearMisses.join(","), `near-miss file ${f.path} differs between twins`);
    }
    if (f.claimedBy.length) continue;

    const undeclared = f.mentions.filter((id) => !knownIds.has(id));
    const known = f.mentions.filter((id) => knownIds.has(id));
    if (undeclared.length) {
      // the twins fix a bug the answer key never records: a tool that finds it is
      // marked wrong, which is the one kind of drift that corrupts scores
      add(
        "error",
        f.path,
        `fixes ${undeclared.join(",")} but no VULNERABILITIES.yaml entry records it - ` +
          `a tool that finds this scores a false positive`,
      );
    } else if (known.length) {
      add(
        "warn",
        f.path,
        `part of ${known.join(",")}'s fix - add it to that entry's variant_paths or match.file`,
      );
    } else if (f.infra && !f.unexplained.length) {
      // nothing but the twins naming themselves
      continue;
    } else {
      add(
        "error",
        f.path,
        `differs between twins (${f.changed} line(s)) but no entry names it` +
          (f.unexplained.length ? `; e.g. ${f.unexplained[0]!.trim()}` : ""),
      );
    }
  }

  // the answer key must never be inside a build context, and nothing may bind
  // anything but loopback
  for (const variant of ["vuln", "safe"] as const) {
    if (existsSync(join(target.dir, variant, "ground-truth"))) {
      add("error", `${variant}/ground-truth`, "answer key inside the build context");
    }
    const compose = join(target.dir, variant, "docker-compose.yml");
    if (!existsSync(compose)) continue;
    const text = readFileSync(compose, "utf8");
    for (const line of text.split("\n")) {
      const bad = line.match(/["'](?:0\.0\.0\.0:|\*:)?(\d+):(\d+)["']/);
      if (bad && !line.includes("127.0.0.1")) {
        add("error", `${variant}/docker-compose.yml`, `publish is not pinned to 127.0.0.1:${bad[0]}`);
      }
    }
    if (!/\$\{DYNAST_PORT:-\d+\}/.test(text)) {
      add(
        "warn",
        `${variant}/docker-compose.yml`,
        "no ${DYNAST_PORT:-...} publish for the app under test",
      );
    }
  }

  return issues;
}
