/**
 * No answer-key label may reach a running app.
 *
 * The apps label their bugs in comments (`// VULN SQLI-001 (CWE-89)`) because
 * derive-match and `check` read those labels from the repo. The image must not
 * carry them: a planted traversal or LFI reads source off disk, and a label in an
 * inline <script> reaches every visitor. So every Dockerfile copies its context
 * through tools/annotations/strip.mjs, and this module proves - statically,
 * without building anything - that the two halves hold for every app:
 *
 *   1. the plumbing: every Dockerfile copies app files only from the stripped
 *      stage, and every compose build hands that stage its stripper;
 *   2. the transform: run over each build context exactly as the image build
 *      runs it, it leaves none of the app's answer-key ids or label phrases.
 *
 * The leak scan is deliberately not the stripper's own marker list: it looks for
 * the app's real ids from VULNERABILITIES.yaml, so a label the stripper's
 * patterns miss is caught here instead of shipping.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, join, relative } from "node:path";

import { VULN_TAG_RE } from "../repo.ts";
import { stripFile, walk } from "../../tools/annotations/strip.mjs";

export const VARIANTS = ["vuln", "safe"] as const;
export type Variant = (typeof VARIANTS)[number];

/** The named context and the stage every Dockerfile shares. */
export const ANNOTATIONS_CONTEXT = "dynast-annotations";
export const STRIPPED_STAGE = "dynast-src";

export interface AnnotationLeak {
  variant: Variant;
  /** path relative to the variant root */
  path: string;
  line: number;
  /** what matched: an id, or the label phrase */
  marker: string;
  text: string;
  /** set when the hit is a known label in shipped behaviour, not a comment */
  known?: string;
}

/**
 * Labels that are not comments: served strings and markup the app's behaviour
 * and its answer key both name, so stripping cannot touch them and renaming them
 * is a change to the app. Each is a real leak, reported by `check` as a warning
 * until it is renamed in both twins and the answer key. An entry that stops
 * matching fails the test suite, so this list can only shrink.
 */
export const SHIPPED_LABELS: { app: string; path: string; includes: string; why: string }[] = [
  {
    app: "jsp",
    path: "src/main/webapp/reflect.jsp",
    includes: '<div id="near-miss">',
    why: "served markup id; the answer key's NM-XSS-001 symbol names it",
  },
  {
    app: "jsp",
    path: "src/main/java/bench/web/SearchServlet.java",
    includes: '"safe-near-miss"',
    why: "the ?mode= value the near-miss route takes; NM-SQL-001's symbol names it",
  },
  {
    app: "llmchat",
    path: "app.py",
    includes: "intentionally planted LLM security bugs",
    why: "landing-page copy served to every visitor",
  },
  {
    app: "network",
    path: "simulator.mjs",
    includes: "near-miss",
    why: "service descriptions and the 8443 body; expected-ports.yaml matches them verbatim",
  },
];

/** Label phrases that never belong in shipped source, whatever the app. */
const PHRASES: RegExp[] = [
  /\bplanted\b/i,
  /\bground[- ]?truth\b/i,
  /\bnear[- ]?miss(?:es)?\b/i,
  /\banswer[- ]?key\b/i,
  /\bCWE-\d+/,
  /\b(?:VULN|FIXED|Fixed)\s*:/,
];

/**
 * Files that name the answer-key directory in order to keep it OUT of the
 * context. Mentioning `ground-truth` there is the mechanism, not a label.
 */
const EXEMPT_FILES = new Set([".dockerignore"]);

/** Every id an answer key declares: bugs, near-misses and incidentals. */
export function answerKeyIds(appDir: string): string[] {
  const path = join(appDir, "ground-truth", "VULNERABILITIES.yaml");
  if (!existsSync(path)) return [];
  const doc = Bun.YAML.parse(readFileSync(path, "utf8")) as Record<string, unknown> | null;
  const ids: string[] = [];
  for (const key of ["vulnerabilities", "near_misses", "incidental"]) {
    const list = doc?.[key];
    if (!Array.isArray(list)) continue;
    for (const e of list) if (e && typeof e === "object" && "id" in e) ids.push(String(e.id));
  }
  return ids;
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** An id as a whole token: SQLI-001 but not SQLI-0012 or X-SQLI-001. */
const idPattern = (ids: string[]): RegExp | null =>
  ids.length
    ? new RegExp(`(?<![A-Za-z0-9-])(?:${ids.map(escape).join("|")})(?![A-Za-z0-9-])`)
    : null;

/**
 * Directories the variant's .dockerignore keeps out of the context, read only
 * as far as plain names go (`node_modules`, `/.next`, `**\/target/`). A pattern
 * this cannot read just means more is scanned, which can only add findings.
 */
function ignoredDirs(variantDir: string): Set<string> {
  const path = join(variantDir, ".dockerignore");
  const out = new Set<string>();
  if (!existsSync(path)) return out;
  for (const raw of readFileSync(path, "utf8").split("\n")) {
    const line = raw.trim().replace(/^\/|^\*\*\/|\/$/g, "");
    if (!line || line.startsWith("#") || line.startsWith("!") || /[*?[\]/]/.test(line)) continue;
    out.add(line);
  }
  return out;
}

/** The files a build of this variant copies, as the strip stage walks them. */
export function contextFiles(variantDir: string): string[] {
  const ignored = ignoredDirs(variantDir);
  return walk(variantDir).filter(
    (rel: string) => !rel.split("/").some((seg) => ignored.has(seg)),
  );
}

/** Every answer-key label left in one variant's context after the strip stage. */
export function annotationLeaks(appDir: string, variant: Variant): AnnotationLeak[] {
  const variantDir = join(appDir, variant);
  if (!existsSync(variantDir)) return [];
  const app = basename(appDir);
  const ids = idPattern(answerKeyIds(appDir));
  const leaks: AnnotationLeak[] = [];

  for (const rel of contextFiles(variantDir)) {
    if (EXEMPT_FILES.has(basename(rel))) continue;
    const res = stripFile(join(variantDir, rel));
    if (!res) continue;
    res.text.split(/\r?\n/).forEach((text: string, i: number) => {
      const hit =
        text.match(new RegExp(VULN_TAG_RE.source))?.[0] ??
        (ids && text.match(ids)?.[0]) ??
        PHRASES.map((re) => text.match(re)?.[0]).find(Boolean);
      if (!hit) return;
      const known = SHIPPED_LABELS.find(
        (k) => k.app === app && k.path === rel && text.includes(k.includes),
      );
      leaks.push({
        variant,
        path: rel,
        line: i + 1,
        marker: hit,
        text: text.trim().slice(0, 160),
        ...(known ? { known: known.why } : {}),
      });
    });
  }
  return leaks;
}

export interface PlumbingIssue {
  /** path relative to the app dir */
  at: string;
  msg: string;
}

/** Every Dockerfile under a variant, relative to the app dir. */
export function dockerfiles(appDir: string, variant: Variant): string[] {
  const root = join(appDir, variant);
  if (!existsSync(root)) return [];
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules" || name === ".git") continue;
      const abs = join(dir, name);
      if (statSync(abs).isDirectory()) visit(abs);
      else if (/^Dockerfile(?:\..+)?$/.test(name)) out.push(relative(appDir, abs));
    }
  };
  visit(root);
  return out.sort();
}

/**
 * The stage is the only thing allowed to read the raw context. A `COPY` or
 * `ADD` without `--from` would copy annotated source straight past it, and a
 * second stage that copies the context itself would be the same hole.
 */
export function dockerfileIssues(appDir: string, variant: Variant): PlumbingIssue[] {
  const issues: PlumbingIssue[] = [];
  for (const rel of dockerfiles(appDir, variant)) {
    const text = readFileSync(join(appDir, rel), "utf8");
    const lines = text.split("\n");
    const stage = new RegExp(`^FROM\\s.*\\bAS\\s+${STRIPPED_STAGE}\\s*$`, "i");
    const at = lines.findIndex((l) => stage.test(l.trim()));
    const firstFrom = lines.findIndex((l) => /^\s*FROM\s/i.test(l));
    if (at < 0 || at !== firstFrom) {
      issues.push({ at: rel, msg: `the first stage must be "${STRIPPED_STAGE}" (the annotation strip)` });
      continue;
    }
    const nextFrom = lines.findIndex((l, i) => i > at && /^\s*FROM\s/i.test(l));
    const stageBody = lines.slice(at + 1, nextFrom < 0 ? undefined : nextFrom).join("\n");
    if (!stageBody.includes(`--from=${ANNOTATIONS_CONTEXT}`) || !/^RUN node \S*strip\.mjs \/src\s*$/m.test(stageBody)) {
      issues.push({ at: rel, msg: `"${STRIPPED_STAGE}" must copy strip.mjs from ${ANNOTATIONS_CONTEXT} and run it over /src` });
    }
    lines.forEach((line, i) => {
      if (i > at && i < (nextFrom < 0 ? lines.length : nextFrom)) return;
      if (/^\s*(?:COPY|ADD)\s/i.test(line) && !/--from=/.test(line)) {
        issues.push({
          at: `${rel}:${i + 1}`,
          msg: `copies from the raw build context, past the annotation strip: ${line.trim()}`,
        });
      }
    });
  }
  return issues;
}

/** Every compose `build:` has to hand the Dockerfile its stripper. */
export function composeIssues(appDir: string, variant: Variant): PlumbingIssue[] {
  const rel = join(variant, "docker-compose.yml");
  const path = join(appDir, rel);
  if (!existsSync(path)) return [];
  const doc = Bun.YAML.parse(readFileSync(path, "utf8")) as {
    services?: Record<string, { build?: unknown }>;
  } | null;
  const issues: PlumbingIssue[] = [];
  for (const [name, svc] of Object.entries(doc?.services ?? {})) {
    if (svc?.build === undefined) continue;
    const build = svc.build as { additional_contexts?: Record<string, string> } | string;
    const ctx = typeof build === "object" ? build.additional_contexts?.[ANNOTATIONS_CONTEXT] : undefined;
    if (!ctx) {
      issues.push({
        at: `${rel} services.${name}.build`,
        msg: `no additional_contexts.${ANNOTATIONS_CONTEXT} - the image build cannot strip annotations`,
      });
    } else if (!existsSync(join(appDir, variant, ctx, "strip.mjs"))) {
      issues.push({
        at: `${rel} services.${name}.build`,
        msg: `additional_contexts.${ANNOTATIONS_CONTEXT} (${ctx}) does not hold strip.mjs`,
      });
    }
  }
  return issues;
}
