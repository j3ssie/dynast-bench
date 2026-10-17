/**
 * No answer-key label reaches a running app.
 *
 * WHY THIS EXISTS
 *
 * The apps label their bugs in comments (`// VULN SQLI-001 (CWE-89)`), and the
 * source is baked into each image. A scanner read nextjs's `/app/src/...` through
 * TRAVERSAL-001, saw `// VULN SQLI-001`, and reported the SQLi six seconds later -
 * the answer key, served by the app under test. Every Dockerfile now copies its
 * context through tools/annotations/strip.mjs; these tests hold both halves for
 * every app without building an image:
 *
 *   - the plumbing: no Dockerfile copies the raw context, every compose build and
 *     every `docker build` hands the stripper to the stage;
 *   - the transform: over each real build context it leaves no id from that
 *     app's answer key and no label phrase, and it changes nothing but comment
 *     text - never a line count, so every `match.file.lines` stays true.
 */

import { describe, expect, test } from "bun:test";

import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  annotationLeaks,
  composeIssues,
  contextFiles,
  dockerfileIssues,
  dockerfiles,
  SHIPPED_LABELS,
  VARIANTS,
} from "../src/check/annotations.ts";
import { stripText, syntaxFor } from "../tools/annotations/strip.mjs";
import { APPS_DIR, ROOT, appNames } from "./helpers.ts";

const apps = appNames();
const STRIP = join(ROOT, "dynast-bench", "tools", "annotations", "strip.mjs");

const strip = (text: string, path: string): string => stripText(text, path).text;

describe("stripText", () => {
  test("blanks a full-line label and the comment lines around it, keeping the opener", () => {
    const src = [
      "export function search(q) {",
      "  // VULN SQLI-001 (CWE-89): the term is concatenated",
      "  // straight into the query.",
      "  return db.raw(`SELECT * FROM posts WHERE t = '${q}'`);",
      "}",
    ].join("\n");
    expect(strip(src, "route.ts")).toBe(
      [
        "export function search(q) {",
        "  //",
        "  //",
        "  return db.raw(`SELECT * FROM posts WHERE t = '${q}'`);",
        "}",
      ].join("\n"),
    );
  });

  test("a trailing label goes, the code before it stays", () => {
    expect(strip(`post = Post.find(params[:id]) # VULN IDOR-001: no org scoping`, "c.rb")).toBe(
      "post = Post.find(params[:id]) #",
    );
    expect(strip(`r.GET("/api/v", h) // near-miss of INFO-001`, "main.go")).toBe(`r.GET("/api/v", h) //`);
  });

  test("an HTML comment keeps its delimiters and whatever follows them", () => {
    expect(
      strip(`<div><%= raw c.body %></div> <!-- VULN XSS-STORED-001: raw --> <p>x</p>`, "show.html.erb"),
    ).toBe(`<div><%= raw c.body %></div> <!-- --> <p>x</p>`);
  });

  test("a multi-line JSX block comment is emptied between its delimiters", () => {
    const src = [
      "<h1>",
      "  {/* NM-XSS (near-miss, safe): the title is escaped",
      "      by JSX. Present in both variants. */}",
      "  {post.title}",
    ].join("\n");
    expect(strip(src, "page.tsx")).toBe(["<h1>", "  {/*", "      */}", "  {post.title}"].join("\n"));
  });

  test("a JSDoc continuation line is stripped as part of its block", () => {
    const src = ["/**", " * Signs the session.", " * CWE-798: the key is hardcoded.", " */", "sign();"].join("\n");
    expect(strip(src, "jwt.ts")).toBe(["/*", "", "", " */", "sign();"].join("\n"));
  });

  test("Blade and JSP comments use their own delimiters", () => {
    expect(strip(`{{-- XSS-REFLECT-001 (CWE-79): echoed raw --}}`, "search.blade.php")).toBe("{{-- --}}");
    expect(strip(`<%-- VULN XSS-001: raw --%><b/>`, "x.jsp")).toBe("<%-- --%><b/>");
  });

  test("a label in JS embedded in a host-language string is stripped at line start", () => {
    const py = ['HTML = """<script>', "  // VULN DOMXSS-001 (CWE-79): hash into innerHTML", '</script>"""'].join("\n");
    expect(strip(py, "main.py")).toBe(['HTML = """<script>', "  //", '</script>"""'].join("\n"));
  });

  test("an opener inside a quoted string is not a comment", () => {
    const line = `fetch("http://internal/" + id); log('SQLI-001 seen')`;
    expect(strip(line, "a.ts")).toBe(line);
  });

  test("Python floor division is code, not a comment", () => {
    const line = "pages = total // per_page  # CWE-400: no cap";
    expect(strip(line, "app.py")).toBe("pages = total // per_page  #");
  });

  test("code that uses a marker word is left alone", () => {
    // network's variant switch is a variable named VULN
    const src = "if (VULN && body.includes('admin')) return send(res, 200, MARKER);";
    expect(strip(src, "simulator.mjs")).toBe(src);
  });

  test("a /*! banner is shipped content, not an annotation", () => {
    // wordpress DEP-001 IS this banner: dep_001.sh greps "lodash 4.17.11"
    const src = "/*! lodash 4.17.11 vulnerable CVE-2019-10744 */\nwindow._ = {};";
    expect(strip(src, "vulnerable-lib.js")).toBe(src);
  });

  test("directives next to a label survive", () => {
    const src = ["#!/bin/sh", "# planted: the seed runs as root", "exec app"].join("\n");
    expect(strip(src, "entrypoint.sh")).toBe(["#!/bin/sh", "#", "exec app"].join("\n"));
    const go = ["//go:embed static", "// VULN INFO-001: serves the env", "var fs embed.FS"].join("\n");
    expect(strip(go, "main.go")).toBe(["//go:embed static", "//", "var fs embed.FS"].join("\n"));
  });

  test("a JSON comment key loses its prose, not its key", () => {
    const src = `{\n  "_comment": "NEAR-MISS NM-PUBFILE-001: public by design.",\n  "app": "x"\n}`;
    expect(strip(src, "config.public.json")).toBe(`{\n  "_comment": "",\n  "app": "x"\n}`);
  });

  test("prose drops the whole paragraph around a label", () => {
    const src = "# App\n\nThe app with every planted bug.\nSee notes.\n\nRun it.";
    expect(strip(src, "README.md")).toBe("# App\n\n\n\n\nRun it.");
  });

  test("files are typed by name as well as extension", () => {
    expect(syntaxFor("Dockerfile.standalone")?.kind).toBe("hash");
    expect(syntaxFor("public/env.production")?.kind).toBe("hash");
    expect(syntaxFor("resources/views/x.blade.php")?.kind).toBe("php");
    expect(syntaxFor("logo.png")).toBeNull();
  });

  test("text without a marker comes back byte-identical, CRLF included", () => {
    const src = "a = 1\r\n# plain comment\r\nb = 2\r\n";
    expect(stripText(src, "x.py")).toEqual({ text: src, changed: [] });
    expect(strip("x = 1 # FIXED SQLI-001\r\ny = 2", "x.py")).toBe("x = 1 #\r\ny = 2");
  });
});

describe("the image build runs it", () => {
  test("node runs strip.mjs over a directory in place, as the dynast-src stage does", () => {
    const dir = mkdtempSync(join(tmpdir(), "dynast-strip-"));
    try {
      writeFileSync(join(dir, "route.ts"), "const q = 1; // VULN SQLI-001 (CWE-89)\nexport { q };\n");
      writeFileSync(join(dir, "logo.bin"), Buffer.from([0, 1, 2, 0x2f, 0x2f, 0x20, 0x56]));
      const res = Bun.spawnSync(["node", STRIP, dir]);
      expect(res.exitCode, res.stderr.toString()).toBe(0);
      expect(readFileSync(join(dir, "route.ts"), "utf8")).toBe("const q = 1; //\nexport { q };\n");
      expect([...readFileSync(join(dir, "logo.bin"))]).toEqual([0, 1, 2, 0x2f, 0x2f, 0x20, 0x56]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("--dry-run reports and writes nothing", () => {
    const dir = mkdtempSync(join(tmpdir(), "dynast-strip-"));
    try {
      writeFileSync(join(dir, "a.py"), "x = 1  # NM-SQL-001: bound\n");
      const res = Bun.spawnSync(["node", STRIP, dir, "--dry-run"]);
      expect(res.exitCode).toBe(0);
      expect(res.stdout.toString()).toContain("would strip a.py");
      expect(readFileSync(join(dir, "a.py"), "utf8")).toBe("x = 1  # NM-SQL-001: bound\n");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe.each(apps)("%s", (app) => {
  const appDir = join(APPS_DIR, app);

  describe.each([...VARIANTS])("%s", (variant) => {
    test("every Dockerfile starts with the strip stage and copies app files only from it", () => {
      expect(dockerfiles(appDir, variant).length).toBeGreaterThan(0);
      expect(dockerfileIssues(appDir, variant)).toEqual([]);
    });

    test("every compose build hands that stage the stripper", () => {
      expect(composeIssues(appDir, variant)).toEqual([]);
    });

    test("no answer-key id or label survives the strip", () => {
      const leaks = annotationLeaks(appDir, variant).filter((l) => !l.known);
      expect(leaks.map((l) => `${l.path}:${l.line} ${l.marker}: ${l.text}`)).toEqual([]);
    });

    test("the strip changes only comment text, and never a line count", () => {
      const dir = join(appDir, variant);
      for (const rel of contextFiles(dir)) {
        const buf = readFileSync(join(dir, rel));
        if (buf.includes(0)) continue;
        const before = buf.toString("utf8");
        const { text, changed } = stripText(before, rel);
        const a = before.split("\n");
        const b = text.split("\n");
        expect(b.length, `${rel} line count`).toBe(a.length);
        for (const row of changed) {
          const was = a[row - 1]!;
          const now = b[row - 1]!;
          // `now` is a prefix of `was`, optionally a space, then a suffix of it
          let k = 0;
          while (k < now.length && now[k] === was[k]) k++;
          const tail = now.slice(k).replace(/^ /, "");
          expect(was.endsWith(tail) && was.length >= now.length - 1, `${rel}:${row}: ${was} -> ${now}`).toBe(
            true,
          );
        }
      }
    });

    test("stripped JS/TS still compiles to the same program", () => {
      const dir = join(appDir, variant);
      for (const rel of contextFiles(dir)) {
        const m = rel.match(/\.(tsx?|jsx?|mjs|cjs)$/);
        if (!m) continue;
        const before = readFileSync(join(dir, rel), "utf8");
        const { text, changed } = stripText(before, rel);
        if (!changed.length) continue;
        const loader = m[1] === "mjs" || m[1] === "cjs" ? "js" : (m[1] as "ts" | "tsx" | "js" | "jsx");
        const t = new Bun.Transpiler({ loader });
        const was = t.transformSync(before).split("\n");
        const now = t.transformSync(text).split("\n");
        expect(now.length, rel).toBe(was.length);
        // comments vanish in compilation, so the only lines allowed to differ are
        // comments that live in a string: a script the page serves inline
        was.forEach((line, i) => {
          if (line === now[i]) return;
          expect(/^\s*(?:\/\/|\/\*|<!--)/.test(line) && line.startsWith(now[i]!), `${rel}: ${line}`).toBe(true);
        });
      }
    });
  });

  test("its Makefile builds the solo image with the stripper", () => {
    const mk = readFileSync(join(appDir, "Makefile"), "utf8");
    const builds = mk.split("\n").filter((l) => /\bdocker build\b/.test(l));
    expect(builds.length).toBeGreaterThan(0);
    for (const line of builds) {
      const ctx = line.match(/--build-context dynast-annotations=(\S+)/)?.[1];
      expect(ctx, line).toBeDefined();
      expect(existsSync(join(appDir, ctx!, "strip.mjs"))).toBe(true);
    }
  });
});

test("every shipped label exception still points at something real", () => {
  for (const k of SHIPPED_LABELS) {
    const hits = VARIANTS.flatMap((v) => annotationLeaks(join(APPS_DIR, k.app), v)).filter(
      (l) => l.path === k.path && l.known,
    );
    expect(hits.length, `${k.app}/${k.path} no longer ships "${k.includes}" - drop the entry`).toBeGreaterThan(0);
  }
});

test("the CLI's solo build hands docker the stripper too", () => {
  const cli = readFileSync(join(ROOT, "dynast-bench", "dynast-bench.ts"), "utf8");
  const build = cli.match(/\[\s*"build",[\s\S]*?Dockerfile\.standalone[\s\S]*?\]/)?.[0] ?? "";
  expect(build).toContain('"--build-context"');
  expect(build).toContain("ANNOTATIONS_CONTEXT");
  expect(cli).toMatch(/ANNOTATIONS_CONTEXT = `dynast-annotations=\$\{join\(ROOT, "dynast-bench", "tools", "annotations"\)\}`/);
});

test("a Dockerfile that copies the raw context is caught", () => {
  const dir = mkdtempSync(join(tmpdir(), "dynast-app-"));
  try {
    mkdirSync(join(dir, "vuln"));
    const good = readFileSync(join(APPS_DIR, "gin", "vuln", "Dockerfile"), "utf8");
    writeFileSync(join(dir, "vuln", "Dockerfile"), good);
    expect(dockerfileIssues(dir, "vuln")).toEqual([]);

    writeFileSync(join(dir, "vuln", "Dockerfile"), good.replace("COPY --from=dynast-src /src/ .", "COPY . ."));
    const issues = dockerfileIssues(dir, "vuln");
    expect(issues.map((i) => i.at)).toEqual(["vuln/Dockerfile:13"]);
    expect(issues[0]!.msg).toContain("raw build context");

    writeFileSync(join(dir, "vuln", "Dockerfile"), "FROM node:22\nCOPY . .\n");
    expect(dockerfileIssues(dir, "vuln")[0]!.msg).toContain('first stage must be "dynast-src"');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a label the stripper's patterns miss is still caught by its id", () => {
  const dir = mkdtempSync(join(tmpdir(), "dynast-app-"));
  try {
    mkdirSync(join(dir, "ground-truth"));
    mkdirSync(join(dir, "vuln"));
    cpSync(join(APPS_DIR, "gin", "ground-truth", "VULNERABILITIES.yaml"), join(dir, "ground-truth", "VULNERABILITIES.yaml"));
    // a served string, not a comment: nothing to strip, so only the id finds it
    writeFileSync(join(dir, "vuln", "main.go"), 'package main\nvar banner = "see SQLI-001"\n');
    const leaks = annotationLeaks(dir, "vuln");
    expect(leaks.map((l) => [l.path, l.line, l.marker])).toEqual([["main.go", 2, "SQLI-001"]]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
