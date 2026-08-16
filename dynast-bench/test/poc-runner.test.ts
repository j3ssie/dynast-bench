/**
 * Tests for the shared PoC runner (`tools/poc-runner.sh`).
 *
 * This shell decides whether `make validate` passes, so the case that matters
 * most is the one that used to be silently wrong: a PoC that failed because the
 * harness broke must never be recorded as "the vulnerability is fixed".
 */

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ROOT } from "./helpers.ts";

const RUNNER = join(ROOT, "dynast-bench", "tools", "poc-runner.sh");

/** Stands in for the app under test: the runner's "is the target alive" oracle. */
let server: ReturnType<typeof Bun.serve> | null = null;
let target = "";
let gtDir = "";

const poc = (name: string, body: string) => {
  const p = join(gtDir, "verify", name);
  writeFileSync(p, `#!/usr/bin/env bash\n${body}\n`);
  chmodSync(p, 0o755);
};

/** Flipped by the `g_kills_target` PoC to simulate an app dying mid-run. */
let alive = true;

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch: (req) => {
      const { pathname } = new URL(req.url);
      if (pathname === "/kill") {
        alive = false;
        return new Response("ok");
      }
      if (pathname === "/revive") {
        alive = true;
        return new Response("ok");
      }
      if (pathname !== "/api/_verify/health") return new Response("no", { status: 404 });
      return alive ? new Response("ok") : new Response("down", { status: 503 });
    },
  });
  target = `http://127.0.0.1:${server.port}`;

  gtDir = mkdtempSync(join(tmpdir(), "dynast-runner-test-"));
  mkdirSync(join(gtDir, "verify"));
  poc("a_exploited.sh", "exit 0");
  poc("b_rejected.sh", "exit 1");
  poc("c_rejected_odd_code.sh", "exit 7"); // curl's "could not connect" code
  poc("d_cannot_run.sh", "exit 2");
  poc("e_missing_cmd.sh", "definitely_not_a_real_command_xyz");
  poc("f_hangs.sh", "sleep 60");
  poc("g_kills_target.sh", `curl -s -o /dev/null "$TARGET/kill"; exit 1`);
});

/** Everything except the two slow/destructive cases, for the common assertions. */
const QUICK = "f_hangs.sh g_kills_target.sh";

afterAll(() => {
  server?.stop(true);
  if (gtDir) rmSync(gtDir, { recursive: true, force: true });
});

async function run(mode: string, env: Record<string, string> = {}) {
  const proc = Bun.spawn(
    ["bash", "-c", `set -u; . "${RUNNER}"; poc_run "${mode}"`],
    {
      env: {
        ...process.env,
        POC_GT_DIR: gtDir,
        TARGET: target,
        POC_TIMEOUT: "1",
        POC_SKIP: QUICK,
        ...env,
      },
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { code: await proc.exited, out: stdout + stderr };
}

describe("poc runner outcomes", () => {
  test("a harness failure is not a fix", async () => {
    const { code, out } = await run("expect-safe");
    // b and c are genuine rejections: nonzero while the target still answers
    expect(out).toContain("ok  b_rejected.sh (fixed)");
    expect(out).toContain("ok  c_rejected_odd_code.sh (fixed)");
    // d and e could not run - the old runner counted both as "fixed"
    expect(out).toContain("!!  d_cannot_run.sh (harness: the PoC reported it could not run)");
    expect(out).toContain("!!  e_missing_cmd.sh (harness: a command it needs is missing)");
    expect(out).toMatch(/harness=2/);
    expect(code).not.toBe(0);
  });

  test("a PoC that outlives its deadline is a harness failure, not a fix", async () => {
    const { code, out } = await run("expect-safe", { POC_SKIP: "g_kills_target.sh", POC_TIMEOUT: "1" });
    expect(out).toContain("!!  f_hangs.sh (harness: timed out after 1s)");
    expect(code).not.toBe(0);
  });

  test("captures why a PoC could not run", async () => {
    const { out } = await run("expect-safe");
    expect(out).toContain("definitely_not_a_real_command_xyz");
  });

  test("an exploit still reads as exploitable on the vuln leg", async () => {
    const { out } = await run("expect-vuln");
    expect(out).toContain("ok  a_exploited.sh (exploitable)");
    expect(out).toContain("XX  b_rejected.sh (NOT exploitable");
  });

  test("a dead target fails once, not as N false 'fixed' verdicts", async () => {
    // 127.0.0.1:1 refuses instantly. Every PoC would exit nonzero here, which is
    // exactly what a fully patched twin looks like from the outside.
    const { code, out } = await run("expect-safe", { TARGET: "http://127.0.0.1:1" });
    expect(out).toContain("is not answering");
    expect(out).not.toContain("(fixed)");
    expect(code).toBe(2);
  });

  test("a target that dies mid-run aborts rather than scoring the rest", async () => {
    // g_kills_target takes the app down and then exits 1 - which on its own is
    // indistinguishable from a clean rejection. The health re-probe is what
    // catches it, and everything after it would be equally meaningless.
    const { code, out } = await run("expect-safe", { POC_SKIP: "f_hangs.sh" });
    alive = true;
    expect(out).toContain("harness: target stopped answering");
    expect(out).toContain("aborting");
    expect(code).not.toBe(0);
  });

  test("a non-2xx health route is 'not up', not 'healthy'", async () => {
    // The oracle used to accept anything that was not empty/000/5xx, so a 404
    // satisfied it - and a wrong POC_HEALTH, a stale proxy, or some other
    // service on the port could make every PoC's nonzero exit read as "cleanly
    // rejected = fixed". Every app's own compose healthcheck requires 2xx, so
    // nothing in the suite loses a legitimate health route to this.
    const { code, out } = await run("expect-safe", { POC_HEALTH: "/not-a-health-route" });
    expect(out).toContain("is not answering");
    expect(out).not.toContain("(fixed)");
    expect(code).toBe(2);
  });

  test("rejects a mode it does not know", async () => {
    const { code, out } = await run("expect-something");
    expect(code).toBe(2);
    expect(out).toContain("usage:");
  });

  test("per-PoC timings are reported", async () => {
    const { out } = await run("expect-vuln");
    expect(out).toMatch(/a_exploited\.sh \(exploitable\)\s+\d+\.\d+s/);
  });

  test("POC_SKIP drops fixtures that are not PoCs", async () => {
    const { out } = await run("expect-vuln", { POC_SKIP: `${QUICK} a_exploited.sh b_rejected.sh` });
    expect(out).not.toContain("a_exploited.sh");
    expect(out).not.toContain("b_rejected.sh");
    expect(out).toContain("c_rejected_odd_code.sh");
  });
});
