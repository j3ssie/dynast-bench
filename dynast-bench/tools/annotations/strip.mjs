#!/usr/bin/env node
/**
 * strip-annotations - blank the answer-key comments out of an app's source
 * before it is built into an image.
 *
 *   node strip.mjs <dir>            # rewrite <dir> in place (the image build)
 *   node strip.mjs <dir> --dry-run  # print what would change, write nothing
 *
 * WHY THIS EXISTS
 *
 * The apps label their own bugs in comments - `// VULN SQLI-001 (CWE-89)`,
 * `# NEAR-MISS NM-SQL-001`, `<!-- VULN XSS-STORED-001 -->`, `NOTE (planted ...
 * ground-truth)` - and derive-match, `check` and the twin diff read those labels
 * from the repo. But the source is also baked into the image, and several apps
 * plant bugs that read files (TRAVERSAL, LFI) or ship source to the browser
 * (inline <script>, source maps). A scanner that reads `// VULN SQLI-001` through
 * nextjs's TRAVERSAL-001 has been handed the answer key, and inline-script
 * labels reach every visitor with no bug at all.
 *
 * So every Dockerfile copies its build context through one stage that runs this
 * file over it, and copies from that stage instead of the raw context. The repo
 * keeps every annotation; the image never has one.
 *
 * WHAT IT CHANGES
 *
 * Only comment text, and only in a comment that carries an answer-key marker
 * (ANNOTATION_MARKERS). The rest of the line - code before the opener, the
 * closer and anything after it - is kept, and no line is ever added or removed,
 * so every `match.file.lines` range in an answer key is still right about the
 * built source, and a source map still maps to the line it always did.
 *
 *   x = q(s)  // VULN SQLI-001: concatenated      ->  x = q(s)  //
 *   <div/> <!-- VULN XSS-001: rendered raw -->    ->  <div/> <!-- -->
 *   {/* NM-XSS (near-miss, safe): the title ...   ->  {/*
 *
 * and a block comment's later lines go empty up to the line holding its closer,
 * which keeps the closer and everything after it.
 *
 * A comment is one unit: the run of `//` lines around a labelled one, or the
 * whole block a labelled line sits in, because the prose that explains a bug is
 * usually on the lines after its label.
 *
 * Openers are matched by text, not by a parser per language, because the label
 * that matters most sits in a language embedded in another one (JS in an HTML
 * string in Python, Java, PHP, ERB, Blade). An opener inside a quoted string on
 * its own line is not an opener, and a language whose code uses an opener's
 * characters as an operator (`//` in Python) only accepts it at the start of a
 * line. dynast-bench/test/annotations.test.ts holds the transform to the rule
 * that every changed line is a prefix and a suffix of the original, and the
 * `check` command proves no answer-key id survives it in any app.
 */

import { lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// ------------------------------------------------------------------ markers --

/**
 * What makes a comment an answer-key annotation. Matching here only ever blanks
 * a comment, so it is deliberately broad: a benign comment caught by it costs
 * nothing, a label it misses is a leaked answer. The `check` command is the
 * precise oracle - it looks for the app's actual ids after this has run.
 */
const CASED = [
  /\b(?:VULN|FIXED)\b/, // the tag convention (src/repo.ts VULN_TAG_RE), and `# VULN: ...`
  /\bVULNERABLE\b/,
  /\bNM-[A-Z0-9]/, // near-miss ids
  /\bCWE-\d+/,
  /\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3}\b/, // a bug id: SQLI-001, SIGNUP-TOKEN-001
  /\b[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+(?=\s*[:(])/, // an id used as a label: NGINX-ADMIN-SLASH:
];
const UNCASED = [
  /\b(?:fixed|vuln)\s*:/i, // the safe twin's `// Fixed: ...`
  /\bnear[- ]?miss/i,
  /\bplanted\b/i,
  /\bground[- ]?truth\b/i,
  /\banswer[- ]?key\b/i,
  /\bvulnerab(?:le|ility|ilities)\b/i,
  /\b(?:intentional|deliberate|purposeful)(?:ly)?\b/i,
  /\b(?:safe|vuln|patched|vulnerable)\s+(?:twin|variant|sibling)s?\b/i,
  /\bboth\s+(?:twins|variants)\b/i,
];
export const ANNOTATION_MARKERS = [...CASED, ...UNCASED];

/** Start index of every marker on a line, ascending. */
function markerIndexes(line) {
  const out = new Set();
  for (const re of ANNOTATION_MARKERS) {
    const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
    for (const m of line.matchAll(g)) out.add(m.index);
  }
  return [...out].sort((a, b) => a - b);
}

export const hasAnnotationMarker = (line) => ANNOTATION_MARKERS.some((re) => re.test(line));

// ------------------------------------------------------------ comment syntax --

/**
 * Lines a tool interprets, which a comment run must never swallow even when
 * they sit right next to a label: shebangs, Dockerfile parser directives, Go
 * build and embed directives, encoding pragmas, TS/lint pragmas.
 */
const DIRECTIVE =
  /^\s*(?:#!|#\s*(?:syntax|escape|check)\s*=|#\s*(?:frozen_string_literal|-\*-|(?:en)?coding[:=])|\/\/go:|\/\/\s*\+build|\/\/\/\s*<reference|\/\/\s*@ts-|\/\/\s*(?:eslint|prettier|istanbul|nolint)|\/\*\s*eslint|#\s*(?:noqa|pylint|type:|rubocop))/;

const C_BLOCK = ["/*", "*/"];
const HTML_BLOCK = ["<!--", "-->"];

/**
 * Comment syntax per file. `line`/`block` openers are native and valid anywhere
 * on a line; `embedded` ones belong to a language carried inside this one (JS in
 * an HTML string) and only count at the start of a line, because the host uses
 * the same characters for something else (`a // b` is floor division in Python).
 */
const SYNTAX = {
  cFamily: { line: ["//"], block: [C_BLOCK], embeddedLine: [], embeddedBlock: [HTML_BLOCK] },
  css: { line: [], block: [C_BLOCK], embeddedLine: [], embeddedBlock: [] },
  hash: { line: ["#"], block: [], embeddedLine: [], embeddedBlock: [] },
  ini: { line: ["#", ";"], block: [], embeddedLine: [], embeddedBlock: [] },
  python: { line: ["#"], block: [], embeddedLine: ["//"], embeddedBlock: [C_BLOCK, HTML_BLOCK] },
  ruby: { line: ["#"], block: [], embeddedLine: ["//"], embeddedBlock: [C_BLOCK, HTML_BLOCK] },
  erb: { line: ["#", "//"], block: [["<%#", "%>"], HTML_BLOCK, C_BLOCK], embeddedLine: [], embeddedBlock: [] },
  php: {
    line: ["//", "#"],
    block: [["{{--", "--}}"], C_BLOCK, HTML_BLOCK],
    embeddedLine: [],
    embeddedBlock: [],
  },
  jsp: { line: ["//"], block: [["<%--", "--%>"], HTML_BLOCK, C_BLOCK], embeddedLine: [], embeddedBlock: [] },
  razor: { line: ["//"], block: [["@*", "*@"], HTML_BLOCK, C_BLOCK], embeddedLine: [], embeddedBlock: [] },
  html: {
    line: ["//"],
    block: [["{{!--", "--}}"], HTML_BLOCK, C_BLOCK],
    embeddedLine: [],
    embeddedBlock: [],
  },
  sql: { line: ["--", "#"], block: [C_BLOCK], embeddedLine: [], embeddedBlock: [] },
  goMod: { line: ["//"], block: [], embeddedLine: [], embeddedBlock: [] },
};

const BY_EXT = {
  js: "cFamily", mjs: "cFamily", cjs: "cFamily", jsx: "cFamily", ts: "cFamily", tsx: "cFamily",
  mts: "cFamily", cts: "cFamily", go: "cFamily", java: "cFamily", cs: "cFamily", kt: "cFamily",
  scala: "cFamily", swift: "cFamily", rs: "cFamily", c: "cFamily", h: "cFamily", cpp: "cFamily",
  prisma: "cFamily", groovy: "cFamily", gradle: "cFamily", json5: "cFamily",
  css: "css", scss: "css", less: "css",
  py: "python",
  rb: "ruby", ru: "ruby", rake: "ruby", gemspec: "ruby",
  erb: "erb",
  php: "php", phtml: "php",
  jsp: "jsp", jspf: "jsp", tag: "jsp",
  cshtml: "razor", razor: "razor",
  html: "html", htm: "html", xml: "html", svg: "html", vue: "html", hbs: "html",
  handlebars: "html", mustache: "html", csproj: "html", xhtml: "html", tld: "html",
  sh: "hash", bash: "hash", zsh: "hash", yml: "hash", yaml: "hash", conf: "hash", toml: "hash",
  properties: "hash", env: "hash", graphql: "hash", gql: "hash", htaccess: "hash",
  dockerignore: "hash", gitignore: "hash", gitattributes: "hash", editorconfig: "hash",
  cfg: "hash", r: "hash", pl: "hash", tf: "hash", mk: "hash", nginx: "hash",
  ini: "ini",
  sql: "sql",
  mod: "goMod",
};

/** Files named for what they are rather than by extension. */
const BY_NAME = [
  [/^Dockerfile(?:\..*)?$/, "hash"],
  [/^(?:Makefile|Gemfile|Rakefile|Procfile|Brewfile|Caddyfile)$/, "hash"],
  [/^\.?env(?:\..*)?$/, "hash"], // .env, .env.backup, and a served env.production
  [/^requirements.*\.txt$/, "hash"],
  [/^(?:rails|rake|bundle|setup)$/, "ruby"], // rails binstubs
  [/^artisan$/, "php"],
];

/** Prose: the whole paragraph around a marker goes, there is no syntax to keep. */
const PROSE_EXT = new Set(["md", "markdown", "txt", "rst", "adoc"]);

/**
 * JSON has no comments, so a "comment" is a conventional key whose value is
 * prose. nextjs serves one from its web root (`public/config.public.json`).
 */
const JSON_COMMENT_KEY = /^(\s*"(?:_comment|\$comment|\/\/|_note|comment|_doc)"\s*:\s*")((?:[^"\\]|\\.)*)(")/;

/** How a file carries comments, or null when it has none we can find. */
export function syntaxFor(path) {
  const name = basename(path);
  for (const [re, kind] of BY_NAME) if (re.test(name)) return { kind, ...SYNTAX[kind] };
  const parts = name.toLowerCase().split(".");
  // a dotfile with no other dot (.htaccess) is its own extension
  const ext = parts.length > 1 ? parts.at(-1) : "";
  if (name.toLowerCase().endsWith(".blade.php")) return { kind: "php", ...SYNTAX.php };
  if (ext === "json") return { kind: "json" };
  if (PROSE_EXT.has(ext)) return { kind: "prose" };
  const kind = BY_EXT[ext];
  return kind ? { kind, ...SYNTAX[kind] } : null;
}

// --------------------------------------------------------------- the lexing --

/** True when position `at` on `line` is outside every quoted string on it. */
function outsideQuotes(line, at) {
  let quote = null;
  for (let i = 0; i < at; i++) {
    const ch = line[i];
    if (ch === "\\") {
      i++;
      continue;
    }
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
    }
  }
  return quote === null;
}

/**
 * `/*!` is the banner convention minifiers keep: a library's name and version,
 * which is exactly what a component scanner reads. wordpress plants DEP-001 as
 * such a banner, so it is shipped content, never an annotation to strip.
 */
const isBanner = (line, at, token) => token === "/*" && line[at + 2] === "!";

/**
 * Every place a comment could open on `line` before `limit`, earliest first;
 * at equal positions the longer opener wins (`<%#` over `#`, `{{--` over `--`).
 */
function openersOn(line, limit, syntax) {
  const found = [];
  const lead = line.length - line.trimStart().length;
  const scan = (token, kind, closer, startOnly) => {
    let from = 0;
    for (;;) {
      const at = line.indexOf(token, from);
      if (at < 0 || at >= limit) return;
      from = at + 1;
      if (startOnly && at !== lead) continue;
      if (isBanner(line, at, token)) continue;
      if (!outsideQuotes(line, at)) continue;
      found.push({ at, token, kind, closer });
    }
  };
  for (const t of syntax.line) scan(t, "line", null, false);
  for (const [o, c] of syntax.block) scan(o, "block", c, false);
  for (const t of syntax.embeddedLine) scan(t, "line", null, true);
  for (const [o, c] of syntax.embeddedBlock) scan(o, "block", c, true);
  found.sort((a, b) => a.at - b.at || b.token.length - a.token.length);
  return found;
}

/** A line that is nothing but a `token` comment (leading whitespace allowed). */
const pureComment = (line, token) => line.trimStart().startsWith(token) && !DIRECTIVE.test(line);

/** `line` with the text after the opener at `at` dropped. */
const keepOpener = (line, at, token) => line.slice(0, at + token.length).trimEnd();

/**
 * Where the block opened at (row, col) closes: the first closer after `from`
 * on that row, or on a later one. Bounded so a stray opener can never eat a file.
 */
function findCloser(lines, row, from, closer, maxRows = 400) {
  for (let r = row; r < Math.min(lines.length, row + maxRows); r++) {
    const at = lines[r].indexOf(closer, r === row ? from : 0);
    if (at >= 0) return { row: r, at };
  }
  return null;
}

/** Blank a block comment from its opener to its closer, keeping both. */
function blankBlock(out, open, close, token) {
  if (open.row === close.row) {
    const line = out[open.row];
    out[open.row] = line.slice(0, open.at + token.length) + " " + line.slice(close.at);
    return;
  }
  out[open.row] = keepOpener(out[open.row], open.at, token);
  for (let r = open.row + 1; r < close.row; r++) out[r] = "";
  const last = out[close.row];
  const indent = last.slice(0, last.length - last.trimStart().length);
  out[close.row] = indent + last.slice(close.at);
}

/**
 * The block comment line `row` sits inside, when the line itself shows no
 * opener: a JSDoc ` * ` continuation, or a plain line inside <!-- ... -->.
 * Walks up to the nearest opener that is not closed before `col` on `row`.
 */
function enclosingBlock(lines, row, col, syntax, maxRows = 60) {
  const pairs = [...syntax.block, ...syntax.embeddedBlock];
  for (let r = row; r >= Math.max(0, row - maxRows); r--) {
    const line = lines[r];
    const limit = r === row ? col : line.length;
    // the last opener on this line that is still open at (row, col)
    let best = null;
    for (const [o, c] of pairs) {
      let at = line.lastIndexOf(o, limit - o.length);
      while (at >= 0) {
        if (!isBanner(line, at, o) && outsideQuotes(line, at)) {
          const closed = findCloser(lines, r, at + o.length, c, row - r + 1);
          const shut =
            closed && (closed.row < row || (closed.row === row && closed.at < col));
          if (!shut && (!best || at > best.at)) best = { row: r, at, token: o, closer: c };
          break;
        }
        // lastIndexOf clamps a negative start to 0, so stop by hand
        at = at > 0 ? line.lastIndexOf(o, at - 1) : -1;
      }
    }
    if (best) return best;
    // a closer above means whatever we are in is not a block opened higher up
    if (r < row && pairs.some(([, c]) => line.includes(c))) return null;
  }
  return null;
}

// ---------------------------------------------------------------- transform --

/**
 * Strip the annotation comments out of one file's text.
 * Returns the new text and the 1-based rows it changed.
 */
export function stripText(text, path) {
  const syntax = syntaxFor(path);
  if (!syntax || !text) return { text, changed: [] };
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split(eol);
  const out = [...lines];
  const done = new Set();

  if (syntax.kind === "json") {
    lines.forEach((line, r) => {
      const m = line.match(JSON_COMMENT_KEY);
      if (m && hasAnnotationMarker(m[2])) out[r] = m[1] + m[3] + line.slice(m[0].length);
    });
  } else if (syntax.kind === "prose") {
    lines.forEach((line, r) => {
      if (done.has(r) || !hasAnnotationMarker(line)) return;
      let a = r;
      let b = r;
      while (a > 0 && lines[a - 1].trim()) a--;
      while (b < lines.length - 1 && lines[b + 1].trim()) b++;
      for (let i = a; i <= b; i++) {
        out[i] = "";
        done.add(i);
      }
    });
  } else {
    lines.forEach((line, r) => {
      if (done.has(r)) return;
      const marks = markerIndexes(line);
      if (!marks.length || DIRECTIVE.test(line)) return;

      // the earliest real opener before some marker on this line
      let hit = null;
      for (const m of marks) {
        const [first] = openersOn(line, m, syntax);
        if (first) {
          hit = first;
          break;
        }
      }

      if (hit && hit.kind === "line") {
        out[r] = keepOpener(out[r], hit.at, hit.token);
        done.add(r);
        const pure = !line.slice(0, hit.at).trim();
        // the rest of the run: the comment lines around a full-line label, or
        // the continuation lines aligned under a trailing one
        for (let i = r + 1; i < lines.length; i++) {
          const next = lines[i];
          const aligned = pure || next.indexOf(hit.token) === hit.at;
          if (!aligned || !pureComment(next, hit.token)) break;
          out[i] = keepOpener(next, next.indexOf(hit.token), hit.token);
          done.add(i);
        }
        if (pure) {
          for (let i = r - 1; i >= 0 && !done.has(i); i--) {
            const prev = lines[i];
            if (!pureComment(prev, hit.token)) break;
            out[i] = keepOpener(prev, prev.indexOf(hit.token), hit.token);
            done.add(i);
          }
        }
        return;
      }

      const open = hit
        ? { row: r, at: hit.at, token: hit.token, closer: hit.closer }
        : enclosingBlock(lines, r, marks[0], syntax);
      if (!open) return;
      const close = findCloser(lines, open.row, open.at + open.token.length, open.closer);
      if (!close || close.row < r) return;
      blankBlock(out, open, close, open.token);
      for (let i = open.row; i <= close.row; i++) done.add(i);
    });
  }

  const changed = [];
  out.forEach((line, i) => {
    if (line !== lines[i]) changed.push(i + 1);
  });
  return { text: changed.length ? out.join(eol) : text, changed };
}

// --------------------------------------------------------------------- tree --

/**
 * Third-party and VCS trees: not app source, and walking a node_modules that a
 * .dockerignore forgot would cost the build minutes for nothing.
 */
export const SKIP_DIRS = new Set([".git", "node_modules"]);

/** Larger than any app source file; a blob this size is data, not code. */
const MAX_BYTES = 4_000_000;

/** Text we can safely rewrite: no NUL byte, and valid UTF-8 round-trip. */
function asText(buf) {
  if (buf.includes(0)) return null;
  const text = buf.toString("utf8");
  return Buffer.from(text, "utf8").equals(buf) ? text : null;
}

/** Every regular file under `root`, relative, in a stable order. */
export function walk(root) {
  const out = [];
  const visit = (dir) => {
    for (const name of readdirSync(dir).sort()) {
      const abs = join(dir, name);
      const st = lstatSync(abs);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        if (!SKIP_DIRS.has(name)) visit(abs);
      } else if (st.isFile() && st.size <= MAX_BYTES) {
        out.push(relative(root, abs));
      }
    }
  };
  visit(root);
  return out;
}

/** Strip one file's contents as read from disk; null when it is not text. */
export function stripFile(abs) {
  const text = asText(readFileSync(abs));
  return text === null ? null : stripText(text, abs);
}

/** Strip a whole tree in place. Returns { path: changedRows } for what changed. */
export function stripTree(root, { write = true } = {}) {
  const report = {};
  for (const rel of walk(root)) {
    const abs = join(root, rel);
    const res = stripFile(abs);
    if (!res || !res.changed.length) continue;
    if (write) writeFileSync(abs, res.text); // keeps the file's mode
    report[rel] = res.changed;
  }
  return report;
}

// ---------------------------------------------------------------------- CLI --

// Bundled into the compiled CLI (via src/check/annotations.ts), this module must
// never mistake that binary's argv for its own, hence the filename test as well.
const entry = process.argv[1];
const isMain =
  !!entry &&
  basename(entry) === "strip.mjs" &&
  import.meta.url === pathToFileURL(resolve(entry)).href;
if (isMain) {
  const args = process.argv.slice(2);
  const dir = args.find((a) => !a.startsWith("--"));
  if (!dir) {
    console.error("usage: strip.mjs <dir> [--dry-run]");
    process.exit(2);
  }
  const dry = args.includes("--dry-run");
  const report = stripTree(dir, { write: !dry });
  const files = Object.keys(report);
  const rows = files.reduce((n, f) => n + report[f].length, 0);
  for (const f of files) console.log(`${dry ? "would strip" : "stripped"} ${f}: ${report[f].length} line(s)`);
  console.log(`annotations: ${rows} line(s) in ${files.length} file(s) under ${dir}`);
}
