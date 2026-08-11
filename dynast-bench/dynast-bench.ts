#!/usr/bin/env bun
/**
 * dynast-bench — one CLI to drive the DynAST-Bench vulnerable-app suite.
 *
 *   dynast-bench start nextjs           # build + boot, wait until healthy, print target
 *   dynast-bench start --count 5 --parallel   # five apps at once, one port each
 *   dynast-bench verify nextjs          # run the ground-truth PoCs against it
 *   dynast-bench stop --all             # stop everything this repo started
 *   dynast-bench clean --all --images   # remove containers, volumes, networks, images
 *
 * Everything is derived from the apps themselves (compose files, Makefiles,
 * ground-truth/VULNERABILITIES.yaml) — there is no config file to keep in sync.
 *
 * ⚠️ The apps are DELIBERATELY INSECURE and bind 127.0.0.1 only. Never expose them.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, dirname, join, relative, sep } from "node:path";

import { checkApp, twinDiff, type Differ } from "./src/check/invariants.ts";
import { normalizeText, type Format, FORMATS } from "./src/normalize/index.ts";
import { parseGroundTruthFile } from "./src/schema/ground-truth.ts";
import type {
  FindingsFile,
  GroundTruth as ScoredGroundTruth,
  Variant as GtVariant,
} from "./src/schema/types.ts";
import pkg from "./package.json";
import { gtAnchors } from "./src/scorer/anchors.ts";
import { renderReport } from "./src/scorer/report.ts";
import { scoreApp } from "./src/scorer/score.ts";

// One version source. `bun build --compile` inlines this, so the binary reports
// the same string the package does rather than a second constant that drifts.
const VERSION = pkg.version;
const DEFAULT_HEALTH_PATH = "/api/_verify/health";
const VERIFY_TOKEN = "benchsecret";
const HEALTH_TIMEOUT_S = 300; // cold builds (aspnet/springboot/jsp) are slow

/**
 * Host-port plan. The suite deliberately sits in a quiet slice of the ephemeral
 * range so it never collides with the usual suspects (3000/8000/8080/5432/...)
 * that other scanners and test targets grab.
 *
 * Every app owns a FIXED port, so a URL means the same app on every machine and
 * on every run - `nextjs` is always :13322 whether it booted alone, in a batch
 * of five, or in solo mode. The port is the app's index in the catalog (`list`
 * order), and it only moves when something else is genuinely holding it.
 *
 *   13311 .. 13339  the app under test — 13311 + its index in the catalog
 *   13340 .. 13484  that app's sidecars — 5 apiece, 13340 + 5 * index
 *   13500 .. 13599  relocation pool — where a publish goes when its port is busy
 *
 * Compose files still *default* to 13311/13312/…, which is what `make up` gets
 * when it runs one app on its own; the CLI passes the app's own ports in as
 * DYNAST_PORT* overrides.
 */
const APP_PORT = 13311;
const SIDECAR_BASE = 13340;
/** 13311 .. 13339 - one slot per app, up to where the sidecar blocks start. */
const APP_SLOT_SPAN = SIDECAR_BASE - APP_PORT;
const SIDECAR_STRIDE = 5;
const PORT_FALLBACK_BASE = 13500;
const PORT_FALLBACK_SPAN = 100;

type Variant = "vuln" | "safe";
type Mode = "compose" | "solo";

const VARIANTS: Variant[] = ["vuln", "safe"];

interface PortMap {
  hostIp: string;
  host: number;
  container: number;
  proto: string;
}

/**
 * One `ports:` entry of a compose file, e.g.
 * `127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13312}:8025`. `envVar` is what the CLI
 * sets to move that publish somewhere else; `preferred` is the baked-in default.
 */
interface PortDecl {
  service: string;
  envVar: string | null;
  preferred: number;
  container: number;
  isApp: boolean;
}

interface App {
  name: string;
  dir: string;
  /** default host port for the app itself (before any relocation) */
  composePort: number;
  /** the app's own fixed port: APP_PORT + its index in the catalog */
  slotPort: number;
  /** first port of this app's sidecar block */
  sidecarBase: number;
  /** compose service that serves the app under test */
  appService: string;
  /** port that service listens on inside its container */
  appContainerPort: number;
  /** every publish each variant's compose declares, in file order */
  ports: Record<Variant, PortDecl[]>;
  /** port the standalone image listens on inside the container */
  soloInternalPort: number;
  hasSolo: boolean;
  healthPath: string;
  pocCount: number;
  groundTruth: string;
  planDoc: string | null;
}

interface Container {
  id: string;
  name: string;
  project: string | null;
  service: string | null;
  /** compose records where it was launched from - the ownership evidence */
  workingDir: string | null;
  state: string;
  status: string;
  ports: PortMap[];
}

interface Stack {
  app: string;
  variant: Variant;
  mode: Mode;
  containers: Container[];
  running: number;
  target: string | null;
}

// ---------------------------------------------------------------- output ----

// Provisional, so that failures during module init (locating the repo) already
// respect --json. main() sets it properly once the args are parsed.
const JSON_MODE = { on: process.argv.includes("--json") || process.argv.includes("-j") };
const useColor = () =>
  !JSON_MODE.on && process.stdout.isTTY === true && !process.env.NO_COLOR;

const paint = (code: string) => (s: string) =>
  useColor() ? `\x1b[${code}m${s}\x1b[0m` : s;
const c = {
  bold: paint("1"),
  dim: paint("2"),
  red: paint("31"),
  green: paint("32"),
  yellow: paint("33"),
  blue: paint("34"),
  cyan: paint("36"),
};

/** Human progress. Silenced in --json so stdout stays pure JSON. */
function log(msg = "") {
  if (!JSON_MODE.on) console.log(msg);
}
function step(msg: string) {
  log(`${c.cyan(">>")} ${msg}`);
}
function warn(msg: string) {
  if (JSON_MODE.on) console.error(`warn: ${msg}`);
  else console.log(`${c.yellow("!!")} ${msg}`);
}

class CliError extends Error {
  constructor(message: string, readonly code = 1) {
    super(message);
  }
}
// Explicitly typed so TypeScript treats a die() call as terminating a branch.
const die: (msg: string, code?: number) => never = (msg, code = 1) => {
  throw new CliError(msg, code);
};

/** Report a CliError the way the CLI always does, and exit. Rethrows real bugs. */
function fatal(err: unknown): never {
  if (err instanceof CliError) {
    if (JSON_MODE.on) console.log(JSON.stringify({ error: err.message }, null, 2));
    else console.error(`${c.red("!!")} ${err.message}`);
    process.exit(err.code);
  }
  throw err;
}

/** Run module-init work that may die() — main()'s handler isn't up yet. */
function init<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    return fatal(err);
  }
}

function emit(payload: unknown) {
  if (JSON_MODE.on) console.log(JSON.stringify(payload, null, 2));
}

function table(rows: string[][], head?: string[]) {
  const all = head ? [head, ...rows] : rows;
  if (all.length === 0) return;
  const widths = all[0]!.map((_, i) =>
    Math.max(...all.map((r) => (r[i] ?? "").length)),
  );
  const line = (r: string[], bold = false) => {
    const s = r
      .map((cell, i) => (cell ?? "").padEnd(widths[i]!))
      .join("  ")
      .trimEnd();
    log(bold ? c.bold(s) : s);
  };
  if (head) line(head, true);
  rows.forEach((r) => line(r));
}

// ------------------------------------------------------------- processes ----

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Spawn a command. `stream` echoes the child's output live (and still captures
 * it); otherwise output is captured silently. --json always captures.
 */
async function exec(
  cmd: string[],
  opts: { cwd?: string; env?: Record<string, string>; stream?: boolean } = {},
): Promise<RunResult> {
  const stream = opts.stream && !JSON_MODE.on;
  const proc = Bun.spawn(cmd, {
    cwd: opts.cwd,
    env: { ...process.env, ...(opts.env ?? {}) },
    stdout: "pipe",
    stderr: "pipe",
  });

  const drain = async (
    rs: ReadableStream<Uint8Array>,
    sink: NodeJS.WriteStream,
  ) => {
    const chunks: Uint8Array[] = [];
    for await (const chunk of rs) {
      chunks.push(chunk);
      if (stream) sink.write(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  };

  const [stdout, stderr, code] = await Promise.all([
    drain(proc.stdout, process.stdout),
    drain(proc.stderr, process.stderr),
    proc.exited,
  ]);
  return { code, stdout, stderr };
}

/** Run a command attached to the terminal (for `logs -f`, scanner commands). */
async function execInherit(
  cmd: string[],
  opts: { cwd?: string; env?: Record<string, string> } = {},
): Promise<number> {
  const proc = Bun.spawn(cmd, {
    cwd: opts.cwd,
    env: { ...process.env, ...(opts.env ?? {}) },
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  return await proc.exited;
}

const docker = (args: string[], opts?: Parameters<typeof exec>[1]) =>
  exec(["docker", ...args], opts);

// ----------------------------------------------------------- repo + apps ----

/**
 * The checkout `make build` compiled this binary from, baked in by
 * `bun build --define`. Undefined when the CLI runs as a plain script.
 */
declare const DYNAST_REPO_ROOT: string | undefined;

const BAKED_ROOT: string | null =
  typeof DYNAST_REPO_ROOT === "string" ? DYNAST_REPO_ROOT : null;

/** Nearest ancestor of `from` that holds a `vulnerable-apps/` directory. */
function findRootAbove(from: string): string | null {
  let dir = from;
  for (let i = 0; i < 12; i++) {
    if (existsSync(join(dir, "vulnerable-apps"))) return dir;
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return null;
}

/**
 * Locate the suite. Compiled binaries live on `$PATH`, far from the apps, and
 * their `import.meta.dir` is inside bun's virtual filesystem — so the script
 * walk only works when running from source, and the fallbacks carry the rest.
 */
function repoRoot(): string {
  const explicit = process.env.DYNAST_BENCH_ROOT;
  if (explicit) {
    if (!existsSync(join(explicit, "vulnerable-apps"))) {
      die(`DYNAST_BENCH_ROOT=${explicit} has no vulnerable-apps/`, 2);
    }
    return explicit;
  }
  const found =
    findRootAbove(import.meta.dir) ?? // running from source
    findRootAbove(process.cwd()) ?? // standing inside a checkout
    (BAKED_ROOT && existsSync(join(BAKED_ROOT, "vulnerable-apps")) ? BAKED_ROOT : null);
  if (found) return found;
  return die(
    "cannot find the vulnerable-apps/ directory\n" +
      `   looked above ${process.cwd()}` +
      (BAKED_ROOT ? ` and in ${BAKED_ROOT} (moved since \`make build\`?)` : "") +
      "\n   point at it with: DYNAST_BENCH_ROOT=/path/to/dynast-bench",
    2,
  );
}

const ROOT = init(repoRoot);
const APPS_DIR = join(ROOT, "vulnerable-apps");

/**
 * Read the `ports:` publishes out of a compose file, remembering which service
 * each belongs to. A line scan (rather than a YAML parse) keeps this tolerant of
 * both the inline `ports: ["..."]` and block-list styles the suite uses, and the
 * "127.0.0.1:<host>:<container>" shape can't false-match the URLs in
 * healthchecks — those never carry that second colon.
 */
function parseComposePorts(text: string): PortDecl[] {
  const out: PortDecl[] = [];
  let service = "";
  let inServices = false;

  for (const line of text.split("\n")) {
    if (/^services:\s*$/.test(line)) {
      inServices = true;
      continue;
    }
    if (/^\S/.test(line)) {
      inServices = false;
      continue;
    }
    const svc = line.match(/^  ([A-Za-z0-9_.-]+):\s*(#.*)?$/);
    if (inServices && svc) {
      service = svc[1]!;
      continue;
    }
    for (const m of line.matchAll(
      /127\.0\.0\.1:(?:\$\{([A-Za-z_][A-Za-z0-9_]*):-(\d+)\}|(\d+)):(\d+)/g,
    )) {
      const envVar = m[1] ?? null;
      out.push({
        service,
        envVar,
        preferred: Number(m[2] ?? m[3]),
        container: Number(m[4]),
        isApp: envVar === "DYNAST_PORT",
      });
    }
  }
  return out;
}

function loadApp(name: string): App {
  const dir = join(APPS_DIR, name);
  const composeFile = join(dir, "vuln", "docker-compose.yml");
  if (!existsSync(composeFile)) die(`no such app: ${name} (see: dynast-bench list)`, 2);

  const compose = readFileSync(composeFile, "utf8");
  const ports: Record<Variant, PortDecl[]> = { vuln: [], safe: [] };
  for (const variant of VARIANTS) {
    const f = join(dir, variant, "docker-compose.yml");
    ports[variant] = existsSync(f) ? parseComposePorts(readFileSync(f, "utf8")) : [];
  }
  // DYNAST_PORT marks the app under test; fall back to the first publish.
  const appPort = ports.vuln.find((p) => p.isApp) ?? ports.vuln[0];

  const makefile = existsSync(join(dir, "Makefile"))
    ? readFileSync(join(dir, "Makefile"), "utf8")
    : "";
  const soloMatch = makefile.match(
    /docker run[^\n]*?-p 127\.0\.0\.1:\$\(PORT\):(\d+)/,
  );

  const healthMatch = compose.match(/\/api\/_verify\/health[A-Za-z0-9._-]*/);

  const verifyDir = join(dir, "ground-truth", "verify");
  // POC_SKIP is how an app declares that a verify/*.sh is a fixture rather than
  // a PoC (llmchat's ingest.sh seeds the corpus the others attack). Read the
  // same list the runner does, or `list` over-reports what `verify` will run.
  const runner = join(dir, "ground-truth", "run.sh");
  const skipped = new Set(
    (existsSync(runner)
      ? readFileSync(runner, "utf8").match(/^POC_SKIP="([^"]*)"/m)?.[1] ?? ""
      : ""
    ).split(/\s+/).filter(Boolean),
  );
  const pocs = existsSync(verifyDir)
    ? readdirSync(verifyDir).filter(
        (f) => f.endsWith(".sh") && f !== "_lib.sh" && !skipped.has(f),
      )
    : [];

  const plan = join(ROOT, "benchmark-plans", `${name}.md`);

  // The catalog is sorted, so an app's slot is stable for a given app list.
  // (Adding an app shifts the ones after it — `dynast-bench list` is the map.)
  const slot = ALL_APPS.indexOf(name);
  const idx = slot >= 0 && slot < APP_SLOT_SPAN ? slot : 0;

  return {
    name,
    dir,
    composePort: appPort?.preferred ?? APP_PORT,
    slotPort: APP_PORT + idx,
    sidecarBase: SIDECAR_BASE + idx * SIDECAR_STRIDE,
    appService: appPort?.service ?? "app",
    appContainerPort: appPort?.container ?? 3000,
    ports,
    soloInternalPort: soloMatch ? Number(soloMatch[1]) : 3000,
    hasSolo: existsSync(join(dir, "vuln", "Dockerfile.standalone")),
    healthPath: healthMatch?.[0] ?? DEFAULT_HEALTH_PATH,
    pocCount: pocs.length,
    groundTruth: join(dir, "ground-truth", "VULNERABILITIES.yaml"),
    planDoc: existsSync(plan) ? plan : null,
  };
}

function appNames(): string[] {
  return readdirSync(APPS_DIR)
    .filter((n) => !n.startsWith("_"))
    .filter((n) => existsSync(join(APPS_DIR, n, "vuln", "docker-compose.yml")))
    .sort();
}

const ALL_APPS = init(appNames);

interface GroundTruth {
  app?: string;
  entry?: string;
  seed_notes?: string;
  vulnerabilities?: Record<string, any>[];
  near_misses?: Record<string, any>[];
}

function groundTruth(app: App): GroundTruth {
  if (!existsSync(app.groundTruth)) return {};
  try {
    return (Bun.YAML.parse(readFileSync(app.groundTruth, "utf8")) ?? {}) as GroundTruth;
  } catch (e) {
    warn(`${app.name}: VULNERABILITIES.yaml did not parse (${(e as Error).message})`);
    return {};
  }
}

// -------------------------------------------------------- docker state ------

const composeProject = (app: string, variant: Variant) => `${variant}-${app}`;
const soloName = (app: string, variant: Variant) => `${variant}-${app}-solo`;

async function listContainers(): Promise<Container[]> {
  const res = await docker(["ps", "--all", "--no-trunc", "--format", "{{json .}}"]);
  if (res.code !== 0) {
    die(
      `docker is not reachable — is Docker Desktop running?\n${res.stderr.trim()}`,
    );
  }
  const out: Container[] = [];
  for (const line of res.stdout.split("\n")) {
    if (!line.trim()) continue;
    let row: any;
    try {
      row = JSON.parse(line);
    } catch {
      continue;
    }
    const labels: Record<string, string> = {};
    for (const kv of String(row.Labels ?? "").split(",")) {
      const i = kv.indexOf("=");
      if (i > 0) labels[kv.slice(0, i)] = kv.slice(i + 1);
    }
    const ports: PortMap[] = [];
    for (const m of String(row.Ports ?? "").matchAll(
      /(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+)\/(\w+)/g,
    )) {
      ports.push({
        hostIp: m[1]!,
        host: Number(m[2]),
        container: Number(m[3]),
        proto: m[4]!,
      });
    }
    out.push({
      id: String(row.ID ?? "").slice(0, 12),
      name: String(row.Names ?? "").split(",")[0]!,
      project: labels["com.docker.compose.project"] ?? null,
      service: labels["com.docker.compose.service"] ?? null,
      workingDir: labels["com.docker.compose.project.working_dir"] ?? null,
      state: String(row.State ?? ""),
      status: String(row.Status ?? ""),
      ports,
    });
  }
  return out;
}

/** Every stack (compose + solo, both variants) that currently has containers. */
function stacksOf(app: App, containers: Container[]): Stack[] {
  const stacks: Stack[] = [];
  for (const variant of VARIANTS) {
    const composed = containers.filter(
      (ct) => ct.project === composeProject(app.name, variant) && ownedByThisRepo(ct),
    );
    if (composed.length) {
      stacks.push({
        app: app.name,
        variant,
        mode: "compose",
        containers: composed,
        running: composed.filter((ct) => ct.state === "running").length,
        target: composeTargetOf(app, composed),
      });
    }
    const solo = containers.filter((ct) => ct.name === soloName(app.name, variant));
    if (solo.length) {
      stacks.push({
        app: app.name,
        variant,
        mode: "solo",
        containers: solo,
        running: solo.filter((ct) => ct.state === "running").length,
        target: targetOf(solo, app.soloInternalPort, true),
      });
    }
  }
  return stacks;
}

function targetOf(
  containers: Container[],
  port: number,
  byContainerPort = false,
): string | null {
  for (const ct of containers) {
    if (ct.state !== "running") continue;
    const hit = byContainerPort
      ? ct.ports.find((p) => p.container === port)
      : ct.ports.find((p) => p.host === port);
    if (hit) return `http://127.0.0.1:${hit.host}`;
  }
  return null;
}

/**
 * Where a compose stack actually answers. Resolved through the app's compose
 * *service* rather than a fixed host port, because a busy default gets
 * relocated at start time — the published port is whatever docker reports.
 */
function composeTargetOf(app: App, containers: Container[]): string | null {
  const ct = containers.find(
    (x) => x.state === "running" && x.service === app.appService,
  );
  if (!ct) return targetOf(containers, app.appContainerPort, true);
  const hit =
    ct.ports.find((p) => p.container === app.appContainerPort) ?? ct.ports[0];
  return hit ? `http://127.0.0.1:${hit.host}` : null;
}

/** Stacks that are actually up, for one app. */
function liveStacks(app: App, containers: Container[]): Stack[] {
  return stacksOf(app, containers).filter((s) => s.running > 0);
}

const isBenchContainer = (ct: Container) =>
  (ct.project !== null &&
    VARIANTS.some((v) => ALL_APPS.some((a) => ct.project === `${v}-${a}`))) ||
  VARIANTS.some((v) => ALL_APPS.some((a) => ct.name === soloName(a, v)));

/**
 * A stack found by looking at docker rather than at the apps directory.
 *
 * `known: false` means nothing named this app exists in vulnerable-apps/ any
 * more — it was renamed or deleted while its containers were still up. The
 * registry-driven walk can never see those, so they leak forever; this is the
 * only way to reclaim them.
 */
interface DiscoveredStack {
  app: string;
  variant: Variant;
  mode: Mode;
  known: boolean;
  containers: Container[];
  running: number;
}

/** `<variant>-<app>` for compose projects, `<variant>-<app>-solo` for solo. */
const BENCH_NAME_RE = new RegExp(`^(${VARIANTS.join("|")})-(.+)$`);

/**
 * `vuln-`/`safe-` is this repo's naming convention, not a claim of ownership: a
 * user can perfectly well have their own compose project called `vuln-api`.
 * Compose stamps every container with the directory it was launched from, so
 * require that to be inside this checkout before anything destructive runs.
 *
 * A solo container is a bare `docker run` with no compose labels at all, so it
 * is matched on its (much more specific) full name instead.
 */
function ownedByThisRepo(ct: Container): boolean {
  if (ct.workingDir !== null) return ct.workingDir === ROOT || ct.workingDir.startsWith(ROOT + sep);
  return ct.project === null;
}

/**
 * Every stack this repo's naming convention claims, whether or not the app is
 * still on disk. Scoped to the `vuln-`/`safe-` prefixes, so unrelated stacks a
 * user happens to be running are never candidates.
 */
function discoverStacks(containers: Container[]): DiscoveredStack[] {
  const byKey = new Map<string, DiscoveredStack>();
  const add = (app: string, variant: Variant, mode: Mode, ct: Container) => {
    const key = `${variant}/${app}/${mode}`;
    let s = byKey.get(key);
    if (!s) {
      s = {
        app,
        variant,
        mode,
        known: ALL_APPS.includes(app),
        containers: [],
        running: 0,
      };
      byKey.set(key, s);
    }
    s.containers.push(ct);
    if (ct.state === "running") s.running++;
  };

  for (const ct of containers) {
    if (!ownedByThisRepo(ct)) continue;
    // Solo first: it is a bare container with no compose project at all, and
    // its name would otherwise read as a project called "<variant>-<app>-solo".
    const solo = ct.name.match(BENCH_NAME_RE);
    if (solo && !ct.project && solo[2]!.endsWith("-solo")) {
      add(solo[2]!.slice(0, -"-solo".length), solo[1] as Variant, "solo", ct);
      continue;
    }
    const proj = ct.project?.match(BENCH_NAME_RE);
    if (proj) add(proj[2]!, proj[1] as Variant, "compose", ct);
  }

  return [...byKey.values()].sort(
    (a, b) => a.app.localeCompare(b.app) || a.variant.localeCompare(b.variant),
  );
}

// ------------------------------------------------------------- net probes ---

/** True when 127.0.0.1:<port> can be bound right now. */
function portBindable(port: number): boolean {
  try {
    const server = Bun.listen({
      hostname: "127.0.0.1",
      port,
      socket: { data() {} },
    });
    server.stop(true);
    return true;
  } catch {
    return false;
  }
}

/** Best-effort name of whatever is listening on a port (any address family). */
async function processHolder(port: number): Promise<string | null> {
  let res: RunResult;
  try {
    res = await exec(["lsof", "-nP", `-iTCP:${port}`, "-sTCP:LISTEN"]);
  } catch {
    return null; // no lsof on this box
  }
  if (res.code !== 0) return null;
  const line = res.stdout.split("\n")[1];
  if (!line) return null;
  const [cmd, pid] = line.split(/\s+/);
  return cmd ? `${cmd} (pid ${pid})` : null;
}

interface PortStatus {
  port: number;
  free: boolean;
  bindable: boolean;
  dockerHolders: Container[];
  otherHolder: string | null;
}

/**
 * Is this host port really ours to take?
 *
 * A bind test alone is not enough: Docker Desktop publishes containers on the
 * IPv6 wildcard (`*:3000`), which leaves IPv4 `127.0.0.1:3000` bindable. A
 * second app could then bind it and `localhost:3000` would resolve to either
 * one — exactly the ambiguity a benchmark must not have. So a port counts as
 * free only when it is bindable AND nothing else is published/listening on it.
 */
async function portStatus(port: number, containers: Container[]): Promise<PortStatus> {
  const bindable = portBindable(port);
  const dockerHolders = containers.filter(
    (ct) => ct.state === "running" && ct.ports.some((p) => p.host === port),
  );
  const otherHolder = dockerHolders.length ? null : await processHolder(port);
  return {
    port,
    bindable,
    dockerHolders,
    otherHolder,
    free: bindable && !dockerHolders.length && !otherHolder,
  };
}

async function probeHealth(
  target: string,
  path: string,
  timeoutMs = 2500,
): Promise<{ ok: boolean; status: number | null }> {
  try {
    const res = await fetch(target + path, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "X-Verify-Token": VERIFY_TOKEN },
    });
    return { ok: res.ok, status: res.status };
  } catch {
    return { ok: false, status: null };
  }
}

// ------------------------------------------------------------ arg parsing ---

interface Args {
  cmd: string;
  positional: string[];
  passthrough: string[]; // everything after `--`
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const passthrough: string[] = [];
  const flags: Record<string, string | boolean> = {};
  let afterDoubleDash = false;

  const wantsValue = new Set([
    "variant",
    "port",
    "timeout",
    "target",
    "tail",
    "expect",
    "format",
    "safe",
    "limit",
    "count",
  ]);

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (afterDoubleDash) {
      passthrough.push(a);
      continue;
    }
    if (a === "--") {
      afterDoubleDash = true;
      continue;
    }
    if (a.startsWith("--")) {
      const [rawKey, inlineVal] = a.slice(2).split(/=(.*)/s);
      const key = rawKey!;
      if (inlineVal !== undefined) flags[key] = inlineVal;
      else if (wantsValue.has(key)) flags[key] = argv[++i] ?? "";
      else flags[key] = true;
      continue;
    }
    if (a.startsWith("-") && a.length > 1) {
      const short: Record<string, string> = {
        h: "help",
        v: "version",
        f: "follow",
        y: "yes",
        j: "json",
        n: "tail",
        c: "count",
      };
      const key = short[a.slice(1)] ?? a.slice(1);
      if (wantsValue.has(key)) flags[key] = argv[++i] ?? "";
      else flags[key] = true;
      continue;
    }
    positional.push(a);
  }
  return { cmd: positional.shift() ?? "", positional, passthrough, flags };
}

function flagStr(args: Args, key: string): string | undefined {
  const v = args.flags[key];
  return typeof v === "string" ? v : undefined;
}
const flagBool = (args: Args, key: string) => args.flags[key] === true;

function wantVariant(args: Args): Variant {
  const v = flagStr(args, "variant") ?? "vuln";
  if (v !== "vuln" && v !== "safe") die(`--variant must be vuln or safe (got: ${v})`, 2);
  return v;
}

function wantMode(args: Args): Mode {
  return flagBool(args, "solo") ? "solo" : "compose";
}

/** Resolve app arguments (or --all) into App objects. */
function resolveApps(args: Args, opts: { allowAll: boolean; min?: number }): App[] {
  if (flagBool(args, "all")) {
    if (!opts.allowAll) die("--all is not supported for this command", 2);
    return ALL_APPS.map(loadApp);
  }
  if (args.positional.length === 0) {
    if ((opts.min ?? 1) === 0) return [];
    die("which app? (see: dynast-bench list)", 2);
  }
  return args.positional.map(loadApp);
}

/** How many apps `--count N` takes when the flag is absent but apps are named. */
const PARALLEL_DEFAULT = 3;

/**
 * Which apps to start: the named ones, or the first N of the catalog.
 *
 * `--count N` is the "just give me a few targets" path. It picks in catalog
 * order so the same N apps come up on every machine, and skips apps that cannot
 * run in the requested mode — `--count 5 --solo` should still hand back five.
 * Naming apps stays the way to choose exactly which; combining the two caps a
 * named list.
 */
function startApps(args: Args, mode: Mode): App[] {
  const raw = flagStr(args, "count");
  if (raw === undefined) return resolveApps(args, { allowAll: true });

  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) {
    die(`--count wants a positive integer (got: ${raw || "nothing"})`, 2);
  }
  const named = args.positional.length > 0;
  let pool = (named ? args.positional : ALL_APPS).map(loadApp);
  if (mode === "solo") {
    const skipped = pool.filter((a) => !a.hasSolo);
    pool = pool.filter((a) => a.hasSolo);
    if (skipped.length && named) {
      warn(`no Dockerfile.standalone: ${skipped.map((a) => a.name).join(" ")} — skipped`);
    }
  }
  if (!pool.length) die(`no app can run in ${mode} mode`, 2);
  if (n > pool.length) {
    warn(`--count ${n} but only ${pool.length} app${pool.length === 1 ? "" : "s"} to pick from`);
  }
  return pool.slice(0, n);
}

/** `--parallel` / `--parallel=N` → how many apps to bring up at once. */
function wantJobs(args: Args, apps: number): number {
  const v = args.flags["parallel"];
  if (v === undefined) return 1;
  if (v === true) return Math.min(PARALLEL_DEFAULT, apps);
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) {
    die(`--parallel wants a positive integer (got: ${v || "nothing"})`, 2);
  }
  return Math.min(n, apps);
}

/** The knobs every start-ish command forwards to `startApp`, parsed once. */
const startFlags = (args: Args) => ({
  port: flagStr(args, "port"),
  build: !flagBool(args, "no-build"),
  timeout: Number(flagStr(args, "timeout") ?? HEALTH_TIMEOUT_S),
  takeover: !flagBool(args, "no-takeover"),
});

/** Run `fn` over every item, at most `limit` in flight. Results keep input order. */
async function pooled<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!, i);
    }
  };
  const width = Math.max(1, Math.min(limit, items.length));
  await Promise.all(Array.from({ length: width }, worker));
  return out;
}

// ------------------------------------------------------- lifecycle: start ---

function composeArgs(app: App, variant: Variant, rest: string[]): string[] {
  return [
    "compose",
    "-f",
    `${variant}/docker-compose.yml`,
    "-p",
    composeProject(app.name, variant),
    ...rest,
  ];
}

/** Names of every docker volume that currently exists. */
async function existingVolumes(): Promise<Set<string>> {
  const res = await docker(["volume", "ls", "-q"]);
  if (res.code !== 0) return new Set();
  return new Set(res.stdout.split("\n").map((v) => v.trim()).filter(Boolean));
}

const volumeNamesFrom = (out: string) =>
  out.split("\n").map((v) => v.trim()).filter(Boolean);

const MOUNT_FORMAT = '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{"\\n"}}{{end}}{{end}}';

/**
 * Every volume a stack is holding.
 *
 * Two sources, because neither is complete alone: compose labels *named* volumes
 * with the project, but what these apps actually accumulate are the anonymous
 * volumes their datastore images declare (`VOLUME /var/lib/postgresql/data`),
 * and those carry no project label — the only link back is a container's mount
 * list. So read that while the containers still exist, or the disk they hold
 * becomes unattributable.
 */
async function stackVolumes(project: string): Promise<string[]> {
  const labelled = await docker([
    "volume",
    "ls",
    "-q",
    "--filter",
    `label=com.docker.compose.project=${project}`,
  ]);
  const out = new Set(labelled.code === 0 ? volumeNamesFrom(labelled.stdout) : []);

  const ps = await docker([
    "ps",
    "-aq",
    "--filter",
    `label=com.docker.compose.project=${project}`,
  ]);
  const ids = volumeNamesFrom(ps.stdout);
  if (ids.length) {
    const insp = await docker(["inspect", "--format", MOUNT_FORMAT, ...ids]);
    for (const v of volumeNamesFrom(insp.stdout)) out.add(v);
  }
  return [...out];
}

/** Volumes one container mounts (used for the solo stacks). */
async function containerVolumes(name: string): Promise<string[]> {
  const insp = await docker(["inspect", "--format", MOUNT_FORMAT, name]);
  return insp.code === 0 ? volumeNamesFrom(insp.stdout) : [];
}

/** What a stack is holding, found the way its mode stores it. */
const heldVolumes = (app: string, variant: Variant, mode: Mode): Promise<string[]> =>
  mode === "compose"
    ? stackVolumes(composeProject(app, variant))
    : containerVolumes(soloName(app, variant));

/**
 * Stop a stack. With `volumes`, its seeded data goes too: `compose down -v`
 * removes what it can see, then anything still standing is deleted by name.
 * Returns the volumes that actually disappeared.
 */
async function stopStack(
  app: App,
  variant: Variant,
  mode: Mode,
  opts: { volumes?: boolean; images?: boolean } = {},
): Promise<{ volumes: string[] }> {
  const held = opts.volumes ? await heldVolumes(app.name, variant, mode) : [];

  if (mode === "compose") {
    const rest = ["down", "--remove-orphans"];
    if (opts.volumes) rest.push("--volumes");
    if (opts.images) rest.push("--rmi", "local");
    await docker(composeArgs(app, variant, rest), { cwd: app.dir, stream: false });
  } else {
    // -v drops the container's anonymous volumes with it.
    await docker(["rm", "-f", "-v", soloName(app.name, variant)]);
    if (opts.images) await docker(["rmi", "-f", soloName(app.name, variant)]);
  }

  return { volumes: await reapVolumes(held) };
}

/** Drop volumes that outlived the containers holding them. Shared tail. */
async function reapVolumes(held: string[]): Promise<string[]> {
  if (!held.length) return [];
  const alive = await existingVolumes();
  const survivors = held.filter((v) => alive.has(v));
  if (survivors.length) await docker(["volume", "rm", "-f", ...survivors]);
  const after = survivors.length ? await existingVolumes() : alive;
  return held.filter((v) => !after.has(v));
}

/**
 * Tear a stack down without `docker compose`.
 *
 * Two callers need this: `--force` (one `docker rm -f` for every container beats
 * a `compose down` per stack) and orphaned stacks, where the compose file that
 * created them is no longer on disk so there is nothing to hand `-f`.
 */
async function forceStopStack(
  s: DiscoveredStack,
  opts: { volumes?: boolean } = {},
): Promise<{ volumes: string[] }> {
  const project = composeProject(s.app, s.variant);
  const held = opts.volumes ? await heldVolumes(s.app, s.variant, s.mode) : [];

  const ids = s.containers.map((ct) => ct.id);
  if (ids.length) {
    await docker(["rm", "-f", ...(opts.volumes ? ["-v"] : []), ...ids]);
  }
  if (s.mode === "compose") {
    const nets = await docker([
      "network",
      "ls",
      "-q",
      "--filter",
      `label=com.docker.compose.project=${project}`,
    ]);
    const list = volumeNamesFrom(nets.stdout);
    if (list.length) await docker(["network", "rm", ...list]);
  }
  return { volumes: await reapVolumes(held) };
}

/** Stop a discovered stack the best way available for it. */
async function stopDiscovered(
  s: DiscoveredStack,
  opts: { volumes?: boolean; force?: boolean } = {},
): Promise<{ volumes: string[] }> {
  if (s.known && !opts.force) {
    return stopStack(loadApp(s.app), s.variant, s.mode, { volumes: opts.volumes });
  }
  return forceStopStack(s, { volumes: opts.volumes });
}

interface PortPlan {
  /** env overrides to hand docker compose (empty when every default was free) */
  env: Record<string, string>;
  /** host port the app itself ended up on */
  appPort: number;
  /** publishes that had to move, for reporting */
  moved: { service: string; from: number; to: number }[];
  /** bench stacks stopped to reclaim a port */
  stopped: string[];
  /** every host port this plan took — released once docker has bound them */
  claimed: number[];
}

/**
 * Ports promised to a stack that has not bound them yet.
 *
 * `portStatus()` asks docker and the kernel, so it only knows about ports that
 * are already published. Under `--parallel` two starts plan before either binds,
 * and both would happily pick 13311. A planned port therefore counts as taken
 * until `docker up` returns, at which point the real bind takes over the job.
 */
const RESERVED_PORTS = new Set<number>();

let portQueue: Promise<unknown> = Promise.resolve();

/** Serialize port planning — concurrent planners must not hand out one port twice. */
function withPortLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = portQueue.then(fn, fn);
  portQueue = run.then(
    () => {},
    () => {},
  );
  return run;
}

/**
 * Decide which host ports this stack will publish on.
 *
 * Every app has ports of its own (`slotPort` + its sidecar block), so the same
 * app lands on the same URL every run, whatever else is up. A port that is free
 * is taken as-is; one held by anything else — another benchmark app, an
 * unrelated container, a stray process — is relocated into the fallback pool
 * rather than failing or evicting the squatter. The one exception is this app's
 * *other* stack (the vuln/safe twin, or the same app in the other mode): those
 * are the same app and are swapped in place, which is what the twin loop wants.
 */
async function planPorts(
  app: App,
  decls: PortDecl[],
  self: { variant: Variant; mode: Mode },
  opts: { takeover: boolean; requestedAppPort?: number; containers?: Container[] },
): Promise<PortPlan> {
  const plan: PortPlan = {
    env: {},
    appPort: app.slotPort,
    moved: [],
    stopped: [],
    claimed: [],
  };
  let containers = opts.containers ?? (await listContainers());
  const claimed = new Set<number>(RESERVED_PORTS);

  const isOwn = (ct: Container) =>
    self.mode === "compose"
      ? ct.project === composeProject(app.name, self.variant)
      : ct.name === soloName(app.name, self.variant);
  /** Which of this app's stacks a container belongs to, if any. */
  const sameAppStack = (ct: Container): { variant: Variant; mode: Mode } | null => {
    for (const v of VARIANTS) {
      if (ct.name === soloName(app.name, v)) return { variant: v, mode: "solo" };
      if (ct.project === composeProject(app.name, v)) return { variant: v, mode: "compose" };
    }
    return null;
  };

  // Sidecars fill this app's own block in compose-file order, so mailpit is the
  // same port on every run too.
  let sidecar = 0;
  for (const decl of decls) {
    const nth = decl.isApp ? -1 : sidecar++;
    const wanted = decl.isApp
      ? (opts.requestedAppPort ?? app.slotPort)
      : // A block holds SIDECAR_STRIDE of them; anything past that (no app is
        // close today) starts from the pool rather than into the next app.
        nth < SIDECAR_STRIDE
        ? app.sidecarBase + nth
        : PORT_FALLBACK_BASE + nth - SIDECAR_STRIDE;

    let chosen: number | null = null;
    if (!claimed.has(wanted)) {
      const status = await portStatus(wanted, containers);
      if (status.free) {
        chosen = wanted;
      } else if (status.dockerHolders.length && status.dockerHolders.every(isOwn)) {
        // The very stack we are about to (re)start — compose reuses the port.
        chosen = wanted;
      } else if (
        opts.takeover &&
        status.dockerHolders.length &&
        status.dockerHolders.every((ct) => sameAppStack(ct) !== null)
      ) {
        // The twin (or the same app in the other mode) — swap it out in place.
        const others = new Map<string, { variant: Variant; mode: Mode }>();
        for (const ct of status.dockerHolders) {
          const s = sameAppStack(ct)!;
          others.set(`${s.variant}/${s.mode}`, s);
        }
        for (const other of others.values()) {
          step(
            `port ${wanted} busy — stopping ${c.dim(`${app.name}/${other.variant} (${other.mode})`)}`,
          );
          await stopStack(app, other.variant, other.mode);
          plan.stopped.push(`${app.name}/${other.variant}/${other.mode}`);
        }
        containers = await listContainers();
        if ((await portStatus(wanted, containers)).free) chosen = wanted;
      }
    }

    if (chosen === null) {
      // Relocate. An explicit --port is the user's call, so say so and move on.
      for (let i = 0; i < PORT_FALLBACK_SPAN; i++) {
        const p = PORT_FALLBACK_BASE + i;
        if (claimed.has(p)) continue;
        const st = await portStatus(p, containers);
        // Where this very service already sits. `wanted` is always the compose
        // default, so without this a stack that relocated once would drift one
        // slot further up the pool on every re-up — and a batch would hand back
        // different URLs each run.
        const ours =
          st.dockerHolders.length > 0 &&
          st.dockerHolders.every(
            (ct) => isOwn(ct) && (self.mode === "solo" || ct.service === decl.service),
          );
        if (st.free || ours) {
          chosen = p;
          break;
        }
      }
      if (chosen === null) {
        die(
          `no free host port for ${app.name}/${decl.service}:${decl.container} — ` +
            `${wanted} is taken and the ${PORT_FALLBACK_BASE}-${PORT_FALLBACK_BASE + PORT_FALLBACK_SPAN - 1} pool is full`,
        );
      }
      plan.moved.push({ service: decl.service, from: wanted, to: chosen });
      if (decl.envVar) plan.env[decl.envVar] = String(chosen);
      warn(
        `port ${wanted} is in use — publishing ${c.bold(`${app.name}/${decl.service}`)} on ${chosen} instead`,
      );
    } else if (decl.envVar && chosen !== decl.preferred) {
      plan.env[decl.envVar] = String(chosen);
    }

    claimed.add(chosen);
    RESERVED_PORTS.add(chosen);
    plan.claimed.push(chosen);
    if (decl.isApp) plan.appPort = chosen;
  }
  return plan;
}

/** Solo has no sidecars, so it just wants the app's own port — same URL as compose. */
async function pickSoloPort(
  app: App,
  variant: Variant,
  containers: Container[],
  requested?: string,
): Promise<number> {
  if (requested) {
    const p = Number(requested);
    if (!Number.isInteger(p) || p < 1 || p > 65535) die(`bad --port: ${requested}`, 2);
    return p;
  }
  const candidates = [
    app.slotPort,
    ...Array.from({ length: PORT_FALLBACK_SPAN }, (_, i) => PORT_FALLBACK_BASE + i),
  ];
  for (const p of candidates) {
    if (RESERVED_PORTS.has(p)) continue; // promised to a stack still coming up
    const st = await portStatus(p, containers);
    // A restart should land back where it was, so our own container doesn't
    // count as an obstacle.
    const ours =
      st.dockerHolders.length > 0 &&
      st.dockerHolders.every((ct) => ct.name === soloName(app.name, variant));
    if (st.free || ours) return p;
  }
  return die("no free port found for solo mode — pass --port");
}

async function waitHealthy(
  app: App,
  target: string,
  timeoutS: number,
  // The spinner rewrites its own line, so several of them at once would fight
  // over it — parallel starts wait silently instead.
  spinner = true,
): Promise<boolean> {
  const deadline = Date.now() + timeoutS * 1000;
  const spin = ["|", "/", "-", "\\"];
  let i = 0;
  const started = Date.now();
  while (Date.now() < deadline) {
    const { ok } = await probeHealth(target, app.healthPath, 3000);
    if (ok) {
      if (useColor() && spinner) process.stdout.write("\r\x1b[K");
      return true;
    }
    if (useColor() && spinner) {
      const secs = Math.round((Date.now() - started) / 1000);
      process.stdout.write(
        `\r\x1b[K${c.dim(`   ${spin[i++ % 4]} waiting for ${target}${app.healthPath} (${secs}s)`)}`,
      );
    }
    await Bun.sleep(1500);
  }
  if (useColor() && spinner) process.stdout.write("\r\x1b[K");
  return false;
}

async function dumpDiagnostics(app: App, variant: Variant, mode: Mode) {
  warn(`${app.name}/${variant} never became healthy — last 40 log lines:`);
  if (mode === "compose") {
    const ps = await docker(composeArgs(app, variant, ["ps"]), { cwd: app.dir });
    log(ps.stdout.trimEnd());
    const logs = await docker(composeArgs(app, variant, ["logs", "--tail", "40"]), {
      cwd: app.dir,
    });
    log(logs.stdout.trimEnd());
  } else {
    const logs = await docker(["logs", "--tail", "40", soloName(app.name, variant)]);
    log(logs.stdout.trimEnd() + logs.stderr.trimEnd());
  }
}

interface StartResult {
  app: string;
  variant: Variant;
  mode: Mode;
  target: string;
  port: number;
  health: string;
  healthy: boolean;
  stopped: string[];
  relocated: { service: string; from: number; to: number }[];
}

async function startApp(
  app: App,
  opts: {
    variant: Variant;
    mode: Mode;
    port?: string;
    build: boolean;
    timeout: number;
    takeover: boolean;
    /** several apps coming up at once: no live build output, no spinner */
    quiet?: boolean;
    /** name the app on the success line — one URL among several needs its owner */
    label?: boolean;
  },
): Promise<StartResult> {
  const { variant, mode, quiet = false } = opts;

  if (mode === "solo" && !app.hasSolo) {
    die(`${app.name} has no ${variant}/Dockerfile.standalone — drop --solo`);
  }

  // Planning is serialized even under --parallel: it reads the live port map,
  // so two planners running at once would both see the same port free.
  const plan: PortPlan = await withPortLock(async () => {
    if (mode === "compose") {
      if (opts.port && !/^\d+$/.test(opts.port)) die(`bad --port: ${opts.port}`, 2);
      return planPorts(app, app.ports[variant], { variant, mode }, {
        takeover: opts.takeover,
        requestedAppPort: opts.port ? Number(opts.port) : undefined,
      });
    }
    // One port map serves both the pick and the claim - nothing binds in between.
    const containers = await listContainers();
    const solo = await pickSoloPort(app, variant, containers, opts.port);
    return planPorts(
      app,
      [
        {
          service: app.appService,
          envVar: null,
          preferred: solo,
          container: app.soloInternalPort,
          isApp: true,
        },
      ],
      { variant, mode },
      // pickSoloPort has already arbitrated (and honoured --port) — planPorts is
      // only here to record the claim and stop a twin if it holds the port.
      { takeover: opts.takeover, requestedAppPort: solo, containers },
    );
  });
  const port = plan.appPort;

  step(
    `starting ${c.bold(app.name)} ${c.dim(`(${variant}, ${mode})`)} on 127.0.0.1:${port}`,
  );

  try {
    if (mode === "compose") {
      const rest = ["up", "-d", "--remove-orphans"];
      if (opts.build) rest.push("--build");
      const res = await docker(composeArgs(app, variant, rest), {
        cwd: app.dir,
        env: plan.env,
        stream: !quiet,
      });
      if (res.code !== 0) die(`docker compose up failed for ${app.name}/${variant}`);
    } else {
      const img = soloName(app.name, variant);
      if (opts.build) {
        const build = await docker(
          ["build", "-f", `${variant}/Dockerfile.standalone`, "-t", img, variant],
          { cwd: app.dir, stream: !quiet },
        );
        if (build.code !== 0) die(`docker build failed for ${app.name}/${variant}`);
      }
      await docker(["rm", "-f", "-v", img]);
      const run = await docker([
        "run",
        "-d",
        "--rm",
        "-p",
        `127.0.0.1:${port}:${app.soloInternalPort}`,
        "--name",
        img,
        img,
      ]);
      if (run.code !== 0) die(`docker run failed for ${img}: ${run.stderr.trim()}`);
    }
  } finally {
    // Bound (or dead) — either way the reservation has done its job, and holding
    // it would make a later start in this same process relocate for no reason.
    for (const p of plan.claimed) RESERVED_PORTS.delete(p);
  }

  const target = `http://127.0.0.1:${port}`;
  const healthy = await waitHealthy(app, target, opts.timeout, !quiet);
  if (!healthy) {
    await dumpDiagnostics(app, variant, mode);
    die(`${app.name}/${variant} did not answer ${app.healthPath} within ${opts.timeout}s`);
  }

  log(
    `${c.green("ok")}   ${opts.label ? c.bold(app.name) + "  " : ""}${c.bold(target)}  ${c.dim(`health ${app.healthPath} · ${app.pocCount} PoCs · verify: dynast-bench verify ${app.name}`)}`,
  );
  return {
    app: app.name,
    variant,
    mode,
    target,
    port,
    health: target + app.healthPath,
    healthy,
    stopped: plan.stopped,
    relocated: plan.moved,
  };
}

// ----------------------------------------------------------- ground truth ---

function gtSummary(app: App) {
  const gt = groundTruth(app);
  const vulns = gt.vulnerabilities ?? [];
  const tally = (key: string) => {
    const out: Record<string, number> = {};
    for (const v of vulns) {
      const k = String(v[key] ?? "?");
      out[k] = (out[k] ?? 0) + 1;
    }
    return out;
  };
  return {
    app: app.name,
    entry: gt.entry ?? `http://127.0.0.1:${app.composePort}`,
    seed_notes: (gt.seed_notes ?? "").trim(),
    counts: {
      vulnerabilities: vulns.length,
      near_misses: (gt.near_misses ?? []).length,
      pocs: app.pocCount,
    },
    by_severity: tally("severity"),
    by_difficulty: tally("difficulty"),
    by_reachability: tally("reachability"),
    by_discovery: tally("discovery"),
    cwes: [...new Set(vulns.map((v) => String(v.cwe ?? "")).filter(Boolean))].sort(),
    vulnerabilities: vulns,
    near_misses: gt.near_misses ?? [],
  };
}

/** Parse + validate an app's answer key, dying on anything unusable. */
function loadGroundTruth(app: App): ScoredGroundTruth {
  if (!existsSync(app.groundTruth)) {
    die(`${app.name} has no ground-truth/VULNERABILITIES.yaml`);
  }
  const res = parseGroundTruthFile(app.groundTruth);
  if (!res.value) {
    die(
      `${app.name}: VULNERABILITIES.yaml is not scoreable\n` +
        res.errors.map((e) => `   ${e.at}: ${e.msg}`).join("\n"),
    );
  }
  for (const e of res.errors) warn(`${app.name} ground truth ${e.at}: ${e.msg}`);
  return res.value;
}

// ---------------------------------------------------------------- commands --

async function cmdList(args: Args) {
  const containers = await listContainers();
  const rows: string[][] = [];
  const payload: any[] = [];

  for (const name of ALL_APPS) {
    const app = loadApp(name);
    const gt = groundTruth(app);
    const live = liveStacks(app, containers);
    const state = live.length
      ? live.map((s) => `${s.variant}/${s.mode}`).join(",")
      : "-";
    rows.push([
      app.name,
      String((gt.vulnerabilities ?? []).length),
      String(app.pocCount),
      String((gt.near_misses ?? []).length),
      app.hasSolo ? "yes" : "-",
      live.length ? c.green(state) : c.dim(state),
      live[0]?.target ?? c.dim(`(:${app.slotPort})`),
    ]);
    payload.push({
      app: app.name,
      vulnerabilities: (gt.vulnerabilities ?? []).length,
      pocs: app.pocCount,
      near_misses: (gt.near_misses ?? []).length,
      solo: app.hasSolo,
      port: app.slotPort,
      sidecar_ports: `${app.sidecarBase}-${app.sidecarBase + SIDECAR_STRIDE - 1}`,
      compose_port: app.composePort,
      health_path: app.healthPath,
      plan: app.planDoc ? app.planDoc.replace(ROOT + "/", "") : null,
      running: live.map((s) => ({
        variant: s.variant,
        mode: s.mode,
        target: s.target,
      })),
    });
  }

  emit({ apps: payload });
  table(rows, ["APP", "VULNS", "POCS", "NEAR", "SOLO", "RUNNING", "TARGET"]);
  log();
  log(
    c.dim(
      `${ALL_APPS.length} apps · start one:  dynast-bench start <app>` +
        `  ·  each app owns its port, taken only if free`,
    ),
  );
}

async function cmdInfo(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  const s = gtSummary(app!);
  emit(s);
  if (JSON_MODE.on) return;

  log(
    c.bold(`${s.app}  ${c.dim(`http://127.0.0.1:${app!.slotPort}`)}`) +
      c.dim(`  (its fixed port; ${s.entry} is the compose default a bare \`make up\` uses)`),
  );
  log();
  log(
    `  ${s.counts.vulnerabilities} planted vulns · ${s.counts.pocs} PoCs · ${s.counts.near_misses} near-misses`,
  );
  const fmt = (o: Record<string, number>) =>
    Object.entries(o)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `${k}=${v}`)
      .join("  ");
  log(`  severity      ${fmt(s.by_severity)}`);
  log(`  difficulty    ${fmt(s.by_difficulty)}`);
  log(`  reachability  ${fmt(s.by_reachability)}`);
  if (Object.keys(s.by_discovery).length) log(`  discovery     ${fmt(s.by_discovery)}`);
  log(`  cwes          ${s.cwes.join(" ")}`);
  if (s.seed_notes) {
    log();
    log(c.dim("  seed: " + s.seed_notes.replace(/\n/g, "\n        ")));
  }
  if (flagBool(args, "full")) {
    log();
    table(
      s.vulnerabilities.map((v: any) => [
        String(v.id ?? ""),
        String(v.cwe ?? ""),
        String(v.severity ?? ""),
        String(v.difficulty ?? ""),
        String(v.reachability ?? ""),
        String(v.discovery ?? ""),
        String(v.route ?? "").slice(0, 60),
      ]),
      ["ID", "CWE", "SEV", "DIFF", "REACH", "DISCOVERY", "ROUTE"],
    );
  } else {
    log();
    log(
      c.dim(
        `  answer key: ${app!.groundTruth.replace(ROOT + "/", "")}` +
          `  (--full to list entries · dynast-bench vulns ${app!.name} for titles)`,
      ),
    );
  }
}

/** notes: is folded YAML — one line, and short enough to sit in a table cell. */
const oneLine = (s: unknown) => String(s ?? "").replace(/\s+/g, " ").trim();

/** The first sentence of `notes:`, which is written as the summary of the bug. */
function titleOf(v: Record<string, any>): string {
  const n = oneLine(v.notes);
  const stop = n.search(/\.\s/);
  return stop > 0 ? n.slice(0, stop + 1) : n;
}

const fit = (s: string, width: number) =>
  s.length <= width ? s : s.slice(0, Math.max(1, width - 1)) + "…";

/**
 * The planted bugs of an app as a checklist — what a scanner run gets compared
 * against. Titles by default (`--full` for route + PoC + the whole note), and
 * `--ids` for the bare list a coverage diff wants.
 */
async function cmdVulns(args: Args) {
  const apps = resolveApps(args, { allowAll: true });
  const withNear = flagBool(args, "near");
  const full = flagBool(args, "full");

  const payload = apps.map((app) => {
    const gt = groundTruth(app);
    return {
      app: app.name,
      counts: {
        vulnerabilities: (gt.vulnerabilities ?? []).length,
        near_misses: (gt.near_misses ?? []).length,
        pocs: app.pocCount,
      },
      vulnerabilities: (gt.vulnerabilities ?? []).map((v) => ({
        id: v.id ?? "",
        title: titleOf(v),
        cwe: v.cwe ?? "",
        owasp: v.owasp ?? "",
        severity: v.severity ?? "",
        difficulty: v.difficulty ?? "",
        reachability: v.reachability ?? "",
        discovery: v.discovery ?? "",
        route: v.route ?? "",
        symbol: v.symbol ?? "",
        near_miss: v.near_miss ?? null,
        poc: v.poc ?? "",
        notes: oneLine(v.notes),
      })),
      near_misses: (gt.near_misses ?? []).map((n) => ({
        id: n.id ?? "",
        of: n.of ?? "",
        title: titleOf(n),
        route: n.route ?? "",
        symbol: n.symbol ?? "",
        path: n.path ?? "",
        notes: oneLine(n.notes),
      })),
    };
  });

  emit(payload.length === 1 ? payload[0] : { apps: payload });
  if (JSON_MODE.on) return;

  // Bare ids, one per line: `comm -13` this against what a scanner reported.
  if (flagBool(args, "ids")) {
    for (const a of payload) {
      for (const v of a.vulnerabilities) console.log(v.id);
      if (withNear) for (const n of a.near_misses) console.log(n.id);
    }
    return;
  }

  const width = process.stdout.columns && process.stdout.columns > 60
    ? process.stdout.columns
    : 120;

  for (const [i, a] of payload.entries()) {
    if (i) log();
    log(
      `${c.bold(a.app)}  ${c.dim(`${a.counts.vulnerabilities} vulns · ${a.counts.pocs} PoCs · ${a.counts.near_misses} near-misses`)}`,
    );
    log();

    if (full) {
      for (const v of a.vulnerabilities) {
        log(
          `${c.bold(v.id)}  ${c.dim(`${v.cwe} · ${v.severity} · difficulty ${v.difficulty} · ${v.reachability} · ${v.discovery}`)}`,
        );
        if (v.route) log(`  ${c.cyan(v.route)}`);
        else if (v.symbol) log(`  ${c.dim("source-only:")} ${v.symbol}`);
        log(`  ${v.notes}`);
        if (v.poc) log(`  ${c.dim(v.poc)}`);
        log();
      }
    } else {
      // ID + CWE + SEV are fixed-ish; the title takes whatever is left.
      const idW = Math.max(2, ...a.vulnerabilities.map((v) => v.id.length));
      const cweW = Math.max(3, ...a.vulnerabilities.map((v) => String(v.cwe).length));
      const sevW = Math.max(3, ...a.vulnerabilities.map((v) => String(v.severity).length));
      const titleW = Math.max(24, width - (idW + cweW + sevW + 8));
      table(
        a.vulnerabilities.map((v) => [
          v.id,
          String(v.cwe),
          String(v.severity),
          fit(v.title, titleW),
        ]),
        ["ID", "CWE", "SEV", "TITLE"],
      );
    }

    if (withNear && a.near_misses.length) {
      log();
      log(c.dim(`  near-misses — safe code of the same shape; flagging one is a false positive`));
      table(
        a.near_misses.map((n) => [
          n.id,
          `of ${n.of}`,
          fit(n.title, Math.max(24, width - 40)),
        ]),
        ["ID", "OF", "WHY IT IS SAFE"],
      );
    }
  }

  if (!full) {
    log();
    log(
      c.dim(
        `  --full for route + PoC · --near for the near-misses · --ids for a bare list`,
      ),
    );
  }
}

async function cmdStart(args: Args) {
  const mode = wantMode(args);
  const apps = startApps(args, mode);
  if (flagBool(args, "all") && !flagStr(args, "count") && mode === "compose") {
    die(
      `booting all ${ALL_APPS.length} compose stacks at once means every datastore they ship, ` +
        "which is more than a laptop wants.\n" +
        "   use: dynast-bench start --all --solo   (one image per app, auto-assigned ports)\n" +
        "   or take a few: dynast-bench start --count 5 --parallel\n" +
        "   or name the apps you want: dynast-bench start nextjs golang",
    );
  }
  if (apps.length > 1 && flagStr(args, "port")) {
    die("--port names one host port, so it only makes sense for a single app", 2);
  }

  const jobs = wantJobs(args, apps.length);
  const opts = { variant: wantVariant(args), mode, ...startFlags(args) };

  // One app keeps the old contract exactly: live build output, and a failure is
  // the command's failure.
  if (apps.length === 1) {
    emit(await startApp(apps[0]!, opts));
    return;
  }

  if (jobs > 1) {
    step(
      `starting ${apps.length} apps ${c.dim(`(${jobs} at a time)`)}: ${apps.map((a) => a.name).join(" ")}`,
    );
  }

  // A batch reports on the whole batch: one app that will not boot must not cost
  // the caller the ports of the ones that did.
  const failed: { app: string; error: string }[] = [];
  const settled = await pooled(apps, jobs, async (app) => {
    try {
      return await startApp(app, { ...opts, quiet: jobs > 1, label: true });
    } catch (err) {
      if (!(err instanceof CliError)) throw err;
      failed.push({ app: app.name, error: err.message });
      warn(`${app.name} failed to start: ${err.message.split("\n")[0]}`);
      return null;
    }
  });
  const started = settled.filter((r): r is StartResult => r !== null);

  emit({ started, failed });
  log();
  table(
    started.map((r) => [
      r.app,
      r.variant,
      r.mode,
      String(r.port),
      r.target,
      r.healthy ? c.green("ok") : c.red("down"),
    ]),
    ["APP", "VARIANT", "MODE", "PORT", "TARGET", "HEALTH"],
  );
  if (failed.length) {
    log();
    warn(`${failed.length} of ${apps.length} did not start: ${failed.map((f) => f.app).join(" ")}`);
    process.exitCode = 1;
  }
}

/**
 * Stop stacks.
 *
 *   stop <app...>   just those apps
 *   stop            everything running (confirms when more than one is up)
 *   stop --all      everything, including stacks whose app is gone from disk
 *
 * Targets come from docker, not from the apps directory: "everything" has to
 * mean every stack that is actually there, including one whose app was renamed
 * or deleted out from under it. Naming apps just filters that same set.
 */
async function cmdStop(args: Args) {
  const containers = await listContainers();
  const dropVolumes = flagBool(args, "volumes");
  const force = flagBool(args, "force");
  const only = flagStr(args, "variant") as Variant | undefined;
  const sweep = flagBool(args, "all") || args.positional.length === 0;

  let targets: DiscoveredStack[];
  if (sweep) {
    targets = discoverStacks(containers);
  } else {
    const wanted = new Set(resolveApps(args, { allowAll: false }).map((a) => a.name));
    targets = discoverStacks(containers).filter((s) => wanted.has(s.app));
  }
  if (only) targets = targets.filter((s) => s.variant === only);

  if (!targets.length) {
    log(c.dim("nothing to stop"));
    emit({ stopped: [], volumes_removed: dropVolumes, volumes_deleted: 0 });
    return;
  }

  // An explicit `--all` or a named app is already a statement of intent. A bare
  // `stop` is not, so anything beyond a single obvious stack gets a prompt.
  if (!flagBool(args, "all") && !flagBool(args, "yes") && targets.length > 1) {
    const list = targets.map((s) => `${s.app} (${s.variant}, ${s.mode})`).join(", ");
    if (!(await confirm(`stop ${targets.length} stacks — ${list}?`))) {
      die("aborted", 130);
    }
  }

  // Stacks are independent projects, so tearing them down one at a time just
  // adds up N `compose down`s of latency. Held volumes are collected per stack
  // before anything is removed, so a concurrent reap can't cross-attribute.
  const results = await pooled(targets, 4, async (s) => {
    const tags = [s.variant, s.mode, ...(s.known ? [] : ["orphan"])].join(", ");
    step(`stopping ${s.app} ${c.dim(`(${tags})`)}`);
    return stopDiscovered(s, { volumes: dropVolumes, force });
  });

  const stopped = targets.map((s) => ({
    app: s.app,
    variant: s.variant,
    mode: s.mode,
    orphan: !s.known,
  }));
  const volumes = results.reduce((n, r) => n + r.volumes.length, 0);
  emit({ stopped, volumes_removed: dropVolumes, volumes_deleted: volumes });
}

async function cmdReset(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  const containers = await listContainers();
  const live = liveStacks(app!, containers);
  const variant = flagStr(args, "variant")
    ? wantVariant(args)
    : ((live[0]?.variant ?? "vuln") as Variant);
  const mode: Mode = flagBool(args, "solo")
    ? "solo"
    : ((live[0]?.mode ?? "compose") as Mode);

  step(`resetting ${app!.name} ${c.dim(`(${variant}, ${mode})`)} — dropping volumes`);
  await stopStack(app!, variant, mode, { volumes: true });

  const res = await startApp(app!, { variant, mode, ...startFlags(args) });
  emit({ ...res, reset: true });
}

async function cmdRestart(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  const containers = await listContainers();
  const live = liveStacks(app!, containers);
  const variant = flagStr(args, "variant") ? wantVariant(args) : (live[0]?.variant ?? "vuln");
  const mode: Mode = flagBool(args, "solo") ? "solo" : (live[0]?.mode ?? "compose");

  await stopStack(app!, variant, mode);
  const res = await startApp(app!, { variant, mode, ...startFlags(args) });
  emit(res);
}

async function cmdStatus(args: Args) {
  const apps = args.positional.length ? resolveApps(args, { allowAll: true }) : ALL_APPS.map(loadApp);
  const containers = await listContainers();
  const rows: string[][] = [];
  const payload: any[] = [];

  for (const app of apps) {
    for (const stack of stacksOf(app, containers)) {
      const showAll = flagBool(args, "all");
      if (!stack.running && !showAll) continue;
      const health = stack.target
        ? await probeHealth(stack.target, app.healthPath)
        : { ok: false, status: null };
      rows.push([
        app.name,
        stack.variant,
        stack.mode,
        `${stack.running}/${stack.containers.length}`,
        stack.target ?? "-",
        health.ok ? c.green("healthy") : c.red(health.status ? `http ${health.status}` : "down"),
        stack.containers[0]?.status ?? "",
      ]);
      payload.push({
        app: app.name,
        variant: stack.variant,
        mode: stack.mode,
        containers_running: stack.running,
        containers_total: stack.containers.length,
        target: stack.target,
        healthy: health.ok,
        health_status: health.status,
      });
    }
  }

  emit({ stacks: payload });
  if (!rows.length) {
    log(c.dim("no benchmark app is running  (dynast-bench start <app>)"));
    return;
  }
  table(rows, ["APP", "VARIANT", "MODE", "UP", "TARGET", "HEALTH", "STATUS"]);
}

async function cmdTarget(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  const containers = await listContainers();
  const live = liveStacks(app!, containers);
  const want = flagStr(args, "variant") as Variant | undefined;
  const stack = want ? live.find((s) => s.variant === want) : live[0];
  if (!stack?.target) {
    die(`${app!.name} is not running (dynast-bench start ${app!.name})`);
  }
  emit({
    app: app!.name,
    variant: stack.variant,
    mode: stack.mode,
    target: stack.target,
    health: stack.target + app!.healthPath,
    ground_truth: app!.groundTruth,
  });
  if (!JSON_MODE.on) console.log(stack.target);
}

interface VerifyResult {
  app: string;
  target: string;
  expect: Variant;
  ok: number;
  bad: number;
  /** PoCs the harness could not run at all - never the same as "fixed" */
  harness: number;
  failures: string[];
  broken: string[];
  passed: boolean;
}

/**
 * The ports the stack actually published, named the way the compose files name
 * them (`DYNAST_PORT_<SERVICE>_<CONTAINERPORT>`).
 *
 * A PoC for a bug that lives on a sidecar - weirdproxy's Apache and Traefik,
 * laravel's phpMyAdmin - cannot assume the compose default, because the CLI
 * gives every app its own port block and 13312 is then some other app entirely.
 * Read from docker rather than from the port plan: the plan only records the
 * publishes it had to move.
 */
async function publishedPortEnv(
  app: App,
  variant: Variant,
  mode: Mode,
  known?: Container[],
): Promise<Record<string, string>> {
  const env: Record<string, string> = {};
  const containers = known ?? (await listContainers());
  for (const stack of stacksOf(app, containers)) {
    if (stack.variant !== variant || stack.mode !== mode) continue;
    for (const ct of stack.containers) {
      const service = (ct.service ?? "").toUpperCase().replace(/[^A-Z0-9]+/g, "_");
      if (!service) continue;
      for (const p of ct.ports) env[`DYNAST_PORT_${service}_${p.container}`] = String(p.host);
    }
  }
  return env;
}

async function runVerify(
  app: App,
  target: string,
  expect: Variant,
  ports: Record<string, string> = {},
): Promise<VerifyResult> {
  const res = await exec(["bash", "ground-truth/run.sh", `expect-${expect}`], {
    cwd: app.dir,
    env: { ...ports, TARGET: target },
    stream: true,
  });
  const out = res.stdout + res.stderr;
  const summary = out.match(/ok=(\d+)\s+bad=(\d+)(?:\s+harness=(\d+))?/);
  const names = (re: RegExp) =>
    (out.match(re)?.[1] ?? "").trim().split(/\s+/).filter(Boolean);
  return {
    app: app.name,
    target,
    expect,
    ok: Number(summary?.[1] ?? 0),
    bad: Number(summary?.[2] ?? 0),
    harness: Number(summary?.[3] ?? 0),
    failures: names(/FAILURES:(.*)/),
    broken: names(/HARNESS:(.*)/),
    passed: res.code === 0,
  };
}

async function cmdVerify(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  const containers = await listContainers();
  const live = liveStacks(app!, containers);

  const target = flagStr(args, "target") ?? live[0]?.target;
  if (!target) {
    die(
      `${app!.name} is not running — start it first (dynast-bench start ${app!.name}) or pass --target`,
    );
  }
  const expectFlag = flagStr(args, "expect");
  if (expectFlag && expectFlag !== "vuln" && expectFlag !== "safe") {
    die(`--expect must be vuln or safe (got: ${expectFlag})`, 2);
  }
  const expect = (expectFlag ?? live[0]?.variant ?? "vuln") as Variant;

  step(
    `verifying ${app!.name} against ${target} ${c.dim(`(expect all ${expect === "vuln" ? "exploitable" : "fixed"})`)}`,
  );
  const result = await runVerify(
    app!, target!, expect,
    await publishedPortEnv(app!, expect, live[0]?.mode ?? "compose", containers),
  );
  emit(result);
  if (!result.passed) {
    // In --json the result object above is the machine answer; don't also emit
    // an error document. Just fail the exit code.
    if (JSON_MODE.on) process.exitCode = 1;
    else {
      const parts = [];
      if (result.bad) parts.push(`${result.bad} PoC(s) off-expectation`);
      if (result.harness) parts.push(`${result.harness} the harness could not run`);
      die(`verify failed: ${parts.join(", ") || "the runner could not start"}`);
    }
  }
}

async function cmdValidate(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  const timeout = Number(flagStr(args, "timeout") ?? HEALTH_TIMEOUT_S);
  const keep = flagBool(args, "keep");
  const common = {
    mode: "compose" as Mode,
    // both images are built up front, so neither start rebuilds
    build: false,
    timeout,
    takeover: !flagBool(args, "no-takeover"),
  };

  // Both twins first, and concurrently: they are independent compose projects
  // building independent images, so nothing but the loop was serialising them.
  // Doing it up front also means a broken safe/ build is reported before the
  // vuln leg runs rather than after it. Output is captured rather than streamed
  // (two interleaved build logs are unreadable) and printed for whichever failed.
  if (!flagBool(args, "no-build")) {
    step(`validate ${app!.name}: building both twins ${c.dim("(in parallel; log shown only on failure)")}`);
    const builds = await Promise.all(
      (["vuln", "safe"] as const).map((variant) =>
        docker(composeArgs(app!, variant, ["build"]), { cwd: app!.dir })
          .then((res) => ({ variant, res })),
      ),
    );
    for (const { variant, res } of builds) {
      if (res.code !== 0) {
        log(res.stdout + res.stderr);
        die(`docker compose build failed for ${app!.name}/${variant}`);
      }
    }
  }

  let vulnRes: VerifyResult;
  let safeRes: VerifyResult;
  try {
    step(`validate ${app!.name}: fresh vuln → all exploitable`);
    await stopStack(app!, "vuln", "compose", { volumes: true });
    const vulnUp = await startApp(app!, { ...common, variant: "vuln" });
    vulnRes = await runVerify(
      app!, vulnUp.target, "vuln", await publishedPortEnv(app!, "vuln", "compose"),
    );

    step(`validate ${app!.name}: safe twin → all fixed`);
    const safeUp = await startApp(app!, { ...common, variant: "safe" });
    safeRes = await runVerify(
      app!, safeUp.target, "safe", await publishedPortEnv(app!, "safe", "compose"),
    );
  } finally {
    // A failed health wait or a PoC run that threw used to leave the stack up.
    // Teardown belongs here so the original failure is what the user sees.
    if (!keep) {
      for (const variant of ["safe", "vuln"] as const) {
        await stopStack(app!, variant, "compose", { volumes: true }).catch(() => {});
      }
    }
  }

  const passed = vulnRes.passed && safeRes.passed;
  emit({ app: app!.name, passed, vuln: vulnRes, safe: safeRes });
  log();
  const trouble = (r: VerifyResult) =>
    `bad=${r.bad}` + (r.harness ? `, harness=${r.harness}` : "");
  log(
    passed
      ? c.green(`ok   ${app!.name}: ${vulnRes.ok} exploitable on vuln/, ${safeRes.ok} fixed on safe/`)
      : c.red(`FAIL ${app!.name}: vuln ${trouble(vulnRes)}, safe ${trouble(safeRes)}`),
  );
  if (!passed) {
    if (JSON_MODE.on) process.exitCode = 1;
    else die("validation failed");
  }
}

// ------------------------------------------------------------------ scoring --

/** Read one findings file, converting from a native scanner format if needed. */
function readFindings(
  path: string,
  app: App,
  variant: GtVariant,
  format: Format | undefined,
  markers: readonly string[],
): FindingsFile {
  if (!existsSync(path)) die(`no such findings file: ${path}`, 2);
  const res = normalizeText(readFileSync(path, "utf8"), {
    app: app.name,
    variant,
    format,
    markers,
  });
  for (const e of res.errors) {
    if (e.at === "$") die(`${basename(path)}: ${e.msg}`);
    warn(`${basename(path)} ${e.at}: ${e.msg}`);
  }
  for (const n of res.notes) warn(`${basename(path)}: ${n}`);
  const warnLimit = 5;
  res.warnings.slice(0, warnLimit).forEach((w) => warn(`${basename(path)} ${w.at}: ${w.msg}`));
  if (res.warnings.length > warnLimit) {
    warn(`${basename(path)}: ${res.warnings.length - warnLimit} more schema warnings`);
  }
  step(
    `${basename(path)} → ${res.file.findings.length} findings ` +
      c.dim(`(${res.format}, ${res.file.run.variant} twin)`),
  );
  return res.file;
}

async function cmdScore(args: Args) {
  const [appName, ...paths] = args.positional;
  if (!appName) die("usage: dynast-bench score <app> <findings.json...> [--safe f.json]", 2);
  const app = loadApp(appName);
  const gt = loadGroundTruth(app);

  const format = flagStr(args, "format") as Format | undefined;
  if (format && !FORMATS.includes(format)) {
    die(`--format must be one of ${FORMATS.join(", ")}`, 2);
  }
  const defaultVariant = wantVariant(args);
  const safePaths = [flagStr(args, "safe")].filter(Boolean) as string[];
  if (!paths.length && !safePaths.length) {
    die("no findings file given — dynast-bench score <app> <findings.json>", 2);
  }

  // the answer key's proof markers, so a scanner's evidence text can reach the
  // matcher's `proof` tier for apps whose markers are app-specific
  const markers = [
    ...new Set(gt.vulnerabilities.flatMap((v) => v.match?.markers ?? [])),
  ];

  const runs: FindingsFile[] = [
    ...paths.map((p) => readFindings(p, app, defaultVariant, format, markers)),
    ...safePaths.map((p) => {
      const f = readFindings(p, app, "safe", format, markers);
      f.run.variant = "safe"; // --safe wins over whatever the file claims
      return f;
    }),
  ];

  const report = scoreApp({
    app: app.name,
    groundTruth: gt,
    runs,
    lenientCwe: flagBool(args, "lenient-cwe"),
  });

  emit(report);
  if (!JSON_MODE.on) {
    log();
    log(
      renderReport(report, {
        full: flagBool(args, "full"),
        limit: Number(flagStr(args, "limit") ?? 10),
      }).join("\n"),
    );
    log();
  }
}

// --------------------------------------------------------- diff + invariants --

/** How the invariant checks shell out - the one thing they cannot do themselves. */
const differ: Differ = async (cwd, args) => exec(args, { cwd });

async function cmdDiff(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  const gt = loadGroundTruth(app!);
  const files = await twinDiff({ name: app!.name, dir: app!.dir }, gt, differ);
  const unclaimed = files.filter((f) => !f.claimedBy.length && (!f.infra || f.unexplained.length));

  emit({
    app: app!.name,
    files,
    unclaimed: unclaimed.map((f) => f.path),
    in_scope: unclaimed.length === 0,
  });

  if (!JSON_MODE.on) {
    log(c.bold(`${app!.name}  vuln ↔ safe`));
    log();
    table(
      files.map((f) => [
        f.path,
        String(f.hunks),
        String(f.changed),
        f.claimedBy.length
          ? f.claimedBy.join(",")
          : f.infra && !f.unexplained.length
            ? c.dim("(twin naming)")
            : c.red("UNCLAIMED"),
        f.nearMisses.length ? c.yellow(f.nearMisses.join(",")) : "",
      ]),
      ["FILE", "HUNKS", "LINES", "CLAIMED BY", "NEAR-MISS IN FILE"],
    );
    log();
    log(
      `  ${files.length} file(s) differ · ${files.reduce((s, f) => s + f.changed, 0)} line(s) · ` +
        (unclaimed.length
          ? c.red(`${unclaimed.length} not named in VULNERABILITIES.yaml`)
          : c.green("every changed file is named in VULNERABILITIES.yaml")),
    );
    if (flagBool(args, "full")) {
      log();
      await execInherit(["diff", "-ru", "vuln", "safe"], { cwd: app!.dir });
    }
  }
  if (unclaimed.length) process.exitCode = 1;
}

async function cmdCheck(args: Args) {
  const apps = resolveApps(args, { allowAll: true });
  // each app's check spawns a diff; they are independent
  const perApp = await Promise.all(
    apps.map((app) => checkApp({ name: app.name, dir: app.dir }, differ)),
  );
  const all = perApp.flat();

  const errors = all.filter((i) => i.level === "error");
  const warns = all.filter((i) => i.level === "warn");
  emit({ apps: apps.map((a) => a.name), ok: errors.length === 0, errors, warnings: warns });

  if (!JSON_MODE.on) {
    const limit = flagBool(args, "full") ? Infinity : 12;
    apps.forEach((app, i) => {
      const mine = perApp[i]!;
      const e = mine.filter((x) => x.level === "error").length;
      const w = mine.length - e;
      const status = e ? c.red(`${e} error(s)`) : w ? c.yellow(`${w} warning(s)`) : c.green("ok");
      log(`${app.name.padEnd(12)} ${status}`);
      for (const x of mine.slice(0, limit)) {
        log(`${x.level === "error" ? c.red("  ✗") : c.yellow("  !")} ${x.at}: ${x.msg}`);
      }
      if (mine.length > limit) log(c.dim(`    … ${mine.length - limit} more (--full)`));
    });
    log();
    log(
      errors.length
        ? c.red(`${errors.length} error(s) across ${apps.length} app(s)`)
        : c.green(
            `${apps.length} app(s) clean` + (warns.length ? ` (${warns.length} warning(s))` : ""),
          ),
    );
  }
  if (errors.length) process.exitCode = 1;
}

async function cmdLogs(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  const containers = await listContainers();
  const live = liveStacks(app!, containers);
  const want = flagStr(args, "variant") as Variant | undefined;
  const stack = want ? live.find((s) => s.variant === want) : live[0];
  if (!stack) die(`${app!.name} is not running`);

  const tail = flagStr(args, "tail") ?? "80";
  const follow = flagBool(args, "follow");
  if (stack.mode === "compose") {
    const rest = ["logs", "--tail", tail];
    if (follow) rest.push("-f");
    process.exitCode = await execInherit(
      ["docker", ...composeArgs(app!, stack.variant, rest)],
      { cwd: app!.dir },
    );
  } else {
    const cmd = ["docker", "logs", "--tail", tail];
    if (follow) cmd.push("-f");
    cmd.push(soloName(app!.name, stack.variant));
    process.exitCode = await execInherit(cmd);
  }
}

async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) {
    die(`${question}\n   refusing without a terminal — pass --yes to confirm`, 2);
  }
  const answer = prompt(`${question} [y/N]`) ?? "";
  return /^y(es)?$/i.test(answer.trim());
}

/** Disk each volume is holding, best-effort (`docker system df` is optional). */
async function volumeSizes(): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const res = await docker(["system", "df", "-v", "--format", "{{json .Volumes}}"]);
  if (res.code !== 0) return out;
  let rows: any[];
  try {
    rows = JSON.parse(res.stdout.trim() || "[]");
  } catch {
    return out;
  }
  const UNITS: Record<string, number> = {
    B: 1,
    KB: 1e3,
    KIB: 1024,
    MB: 1e6,
    MIB: 1024 ** 2,
    GB: 1e9,
    GIB: 1024 ** 3,
    TB: 1e12,
  };
  for (const row of rows) {
    const m = String(row?.Size ?? "").match(/^([\d.]+)\s*([A-Za-z]+)$/);
    if (row?.Name && m) out.set(row.Name, Number(m[1]) * (UNITS[m[2]!.toUpperCase()] ?? 1));
  }
  return out;
}

/**
 * Anonymous volumes no container references any more — what a stack leaves
 * behind when it was torn down without `-v`. Docker gives them no owner, so
 * they can't be attributed to an app; `docker volume prune` treats exactly this
 * set as safe to drop, and so does `clean --orphan-volumes`. Named volumes are
 * never touched: those belong to somebody.
 */
async function orphanVolumes(): Promise<string[]> {
  const res = await docker([
    "volume",
    "ls",
    "-q",
    "--filter",
    "dangling=true",
    "--filter",
    "label=com.docker.volume.anonymous",
  ]);
  return res.code === 0 ? volumeNamesFrom(res.stdout) : [];
}

function humanBytes(n: number): string {
  if (n < 1e3) return `${Math.round(n)}B`;
  if (n < 1e6) return `${(n / 1e3).toFixed(1)}kB`;
  if (n < 1e9) return `${(n / 1e6).toFixed(1)}MB`;
  return `${(n / 1e9).toFixed(2)}GB`;
}

async function cmdClean(args: Args) {
  const apps = resolveApps(args, { allowAll: true });
  const withImages = flagBool(args, "images");
  const containers = await listContainers();

  // Only touch projects that still own something. Match on compose's project
  // label rather than the name prefix — a stack whose containers are gone can
  // still be holding a network or a named volume.
  const projectsWithLeftovers = new Set<string>();
  const [vols, nets] = await Promise.all([
    docker(["volume", "ls", "--format", "{{.Labels}}"]),
    docker(["network", "ls", "--format", "{{.Labels}}"]),
  ]);
  for (const labelBlob of [vols.stdout, nets.stdout].join("\n").split("\n")) {
    const proj = labelBlob.match(/com\.docker\.compose\.project=([^,\s]+)/)?.[1];
    if (proj) projectsWithLeftovers.add(proj);
  }

  // Built images outlive their stacks: solo containers run with --rm, and a
  // finished `validate` leaves safe-<app>-app behind. Find them by repo name.
  const imgList = await docker(["images", "--format", "{{.Repository}}"]);
  const repos = new Set(imgList.stdout.split("\n").map((r) => r.trim()).filter(Boolean));
  const soloImage = (app: string, v: Variant) => repos.has(soloName(app, v));
  const composeImages = (app: string, v: Variant) =>
    [...repos].filter((r) => r.startsWith(`${v}-${app}-`) && r !== soloName(app, v));

  let keptImages = 0;
  const targets: { app: App; variant: Variant; mode: Mode }[] = [];
  for (const app of apps) {
    for (const variant of VARIANTS) {
      const proj = composeProject(app.name, variant);
      const hasContainers = containers.some((ct) => ct.project === proj);
      const imgs = composeImages(app.name, variant);
      if (hasContainers || projectsWithLeftovers.has(proj) || (withImages && imgs.length)) {
        targets.push({ app, variant, mode: "compose" });
      } else if (imgs.length) keptImages += imgs.length;

      const hasSolo = containers.some((ct) => ct.name === soloName(app.name, variant));
      if (hasSolo || (withImages && soloImage(app.name, variant))) {
        targets.push({ app, variant, mode: "solo" });
      } else if (soloImage(app.name, variant)) keptImages += 1;
    }
  }

  const withOrphans = flagBool(args, "orphan-volumes");
  // Size everything up front — once it's gone there is nothing left to ask.
  const sizes = await volumeSizes();
  const bytesOf = (names: string[]) => names.reduce((n, v) => n + (sizes.get(v) ?? 0), 0);

  // What each target is actually holding. Anonymous volumes are only reachable
  // through their containers, so this has to happen before anything is torn down.
  const held = new Map<string, string[]>();
  for (const t of targets) {
    const key = `${t.app.name}/${t.variant}/${t.mode}`;
    held.set(key, await heldVolumes(t.app.name, t.variant, t.mode));
  }

  // Volumes from earlier runs whose containers are long gone: nothing links them
  // to an app any more, so they only go when explicitly asked for.
  const orphans = withOrphans ? await orphanVolumes() : [];

  if (!targets.length && !orphans.length) {
    log(
      c.dim(
        keptImages
          ? `nothing to clean (${keptImages} built image(s) kept — add --images)`
          : "nothing to clean",
      ),
    );
    emit({ cleaned: [], images_removed: withImages, images_kept: keptImages });
    return;
  }

  if (!flagBool(args, "yes") && !JSON_MODE.on) {
    log(c.bold("about to remove:"));
    for (const t of targets) {
      const mine = held.get(`${t.app.name}/${t.variant}/${t.mode}`) ?? [];
      const disk = mine.length
        ? ` ${c.dim(`[${mine.length} volume(s), ${humanBytes(bytesOf(mine))}]`)}`
        : "";
      log(
        `  ${t.app.name}/${t.variant} (${t.mode}) — containers, volumes, networks${withImages ? ", images" : ""}${disk}`,
      );
    }
    if (orphans.length) {
      log(
        `  ${orphans.length} orphaned anonymous volume(s) ${c.dim(`[${humanBytes(bytesOf(orphans))}]`)} — not attached to any container`,
      );
    }
    if (!(await confirm("this deletes all seeded data. continue?"))) {
      log("aborted");
      return;
    }
  } else if (!flagBool(args, "yes") && JSON_MODE.on) {
    die("clean is destructive — pass --yes in --json mode", 2);
  }

  const cleaned: any[] = [];
  let reclaimed = 0;
  let volumesDeleted = 0;
  for (const t of targets) {
    step(`cleaning ${t.app.name}/${t.variant} ${c.dim(`(${t.mode})`)}`);
    const res = await stopStack(t.app, t.variant, t.mode, {
      volumes: true,
      images: withImages,
    });
    volumesDeleted += res.volumes.length;
    reclaimed += bytesOf(res.volumes);
    cleaned.push({
      app: t.app.name,
      variant: t.variant,
      mode: t.mode,
      volumes_deleted: res.volumes.length,
    });
  }
  if (orphans.length) {
    step(`removing ${orphans.length} orphaned anonymous volume(s)`);
    const gone = await reapVolumes(orphans);
    volumesDeleted += gone.length;
    reclaimed += bytesOf(gone);
  }
  emit({
    cleaned,
    volumes_deleted: volumesDeleted,
    orphan_volumes_deleted: orphans.length,
    bytes_reclaimed: Math.round(reclaimed),
    images_removed: withImages,
    images_kept: withImages ? 0 : keptImages,
  });
  log(
    c.green(
      `ok   removed ${cleaned.length} stack(s), ${volumesDeleted} volume(s)` +
        (reclaimed ? ` (~${humanBytes(reclaimed)} reclaimed)` : ""),
    ),
  );
  if (!withImages) log(c.dim("     built images kept — add --images to drop them too"));
  if (!withOrphans) {
    const left = await orphanVolumes();
    if (left.length) {
      const size = bytesOf(left);
      log(
        c.dim(
          `     ${left.length} orphaned anonymous volume(s)${size ? ` (~${humanBytes(size)})` : ""} ` +
            "from earlier runs — add --orphan-volumes to drop those too",
        ),
      );
    }
  }
}

async function cmdRun(args: Args) {
  const [app] = resolveApps(args, { allowAll: false });
  if (!args.passthrough.length) {
    die("nothing to run — usage: dynast-bench run <app> -- <command...>", 2);
  }
  const variant = wantVariant(args);
  const mode = wantMode(args);

  const started = await startApp(app!, { variant, mode, ...startFlags(args) });

  step(`running: ${c.dim(args.passthrough.join(" "))}`);
  // The command under `run` is the thing being measured, so by default it gets
  // target metadata and nothing else. Handing it the answer key or the harness
  // token would let a scanner read the expected findings, or ask /api/_verify/*
  // for the seeded ids instead of discovering them - either way the score stops
  // meaning what it claims to mean.
  const trusted = flagBool(args, "trusted");
  const env: Record<string, string> = {
    TARGET: started.target,
    DYNAST_BENCH_APP: app!.name,
    DYNAST_BENCH_VARIANT: variant,
    DYNAST_BENCH_TARGET: started.target,
    DYNAST_BENCH_HEALTH: started.health,
  };
  if (trusted) {
    env.DYNAST_BENCH_GROUND_TRUTH = app!.groundTruth;
    env.DYNAST_BENCH_VERIFY_TOKEN = VERIFY_TOKEN;
    log(c.dim("   --trusted: answer key + verify token exported (not a scoreable run)"));
  }
  const code = await execInherit(args.passthrough, { env });

  if (!flagBool(args, "keep")) {
    step(`stopping ${app!.name}`);
    await stopStack(app!, variant, mode, { volumes: flagBool(args, "volumes") });
  } else {
    log(c.dim(`   left running at ${started.target} (--keep)`));
  }

  emit({ ...started, command: args.passthrough, trusted, exit_code: code });
  process.exitCode = code;
}

async function cmdDoctor(_args: Args) {
  const checks: { name: string; ok: boolean; detail: string }[] = [];
  const add = (name: string, ok: boolean, detail: string) =>
    checks.push({ name, ok, detail });

  add("bun", true, Bun.version);
  const dv = await exec(["docker", "--version"]);
  add("docker", dv.code === 0, dv.stdout.trim() || dv.stderr.trim());
  const cv = await exec(["docker", "compose", "version"]);
  add("docker compose", cv.code === 0, cv.stdout.trim().split("\n")[0] ?? "");
  const info = await exec(["docker", "info", "--format", "{{.ServerVersion}}"]);
  add("docker daemon", info.code === 0, info.code === 0 ? `server ${info.stdout.trim()}` : "not reachable");
  add("repo", true, ROOT);
  add("apps", ALL_APPS.length > 0, `${ALL_APPS.length} found`);

  const containers = info.code === 0 ? await listContainers() : [];
  // One row per app: the port it owns, and whether anything is sitting on it.
  const apps = ALL_APPS.map(loadApp);
  const states = await Promise.all(
    apps.map((app) => portStatus(app.slotPort, containers)),
  );
  const portRows: string[][] = [];
  const portPayload: any[] = [];
  for (const [i, app] of apps.entries()) {
    const st = states[i]!;
    const holder = st.dockerHolders[0];
    const who = st.free
      ? "-"
      : holder
        ? `${holder.name}${isBenchContainer(holder) ? " (bench)" : c.yellow(" (foreign)")}`
        : (st.otherHolder ?? "unknown listener");
    portRows.push([
      String(app.slotPort),
      app.name,
      st.free ? c.green("free") : c.yellow("in use"),
      who,
      `${app.sidecarBase}-${app.sidecarBase + SIDECAR_STRIDE - 1}`,
    ]);
    portPayload.push({
      port: app.slotPort,
      app: app.name,
      free: st.free,
      holder: st.free ? null : who,
      sidecars: `${app.sidecarBase}-${app.sidecarBase + SIDECAR_STRIDE - 1}`,
    });
  }

  emit({
    checks,
    ports: portPayload,
    port_plan: {
      apps: `${APP_PORT}-${APP_PORT + APP_SLOT_SPAN - 1}`,
      sidecars: `${SIDECAR_BASE}-${SIDECAR_BASE + APP_SLOT_SPAN * SIDECAR_STRIDE - 1}`,
      relocation: `${PORT_FALLBACK_BASE}-${PORT_FALLBACK_BASE + PORT_FALLBACK_SPAN - 1}`,
    },
    root: ROOT,
    apps: ALL_APPS,
  });
  for (const ch of checks) {
    log(`${ch.ok ? c.green(" ok ") : c.red("FAIL")}  ${ch.name.padEnd(16)} ${c.dim(ch.detail)}`);
  }
  log();
  log(
    c.bold("the port each app owns") +
      c.dim("  (kept when free, relocated only when something else holds it)"),
  );
  table(portRows, ["PORT", "APP", "STATE", "HOLDER", "SIDECARS"]);
  log();
  log(
    c.dim(
      `  apps ${APP_PORT}-${APP_PORT + APP_SLOT_SPAN - 1} · ` +
        `sidecars ${SIDECAR_BASE}-${SIDECAR_BASE + APP_SLOT_SPAN * SIDECAR_STRIDE - 1} · ` +
        `relocation pool ${PORT_FALLBACK_BASE}-${PORT_FALLBACK_BASE + PORT_FALLBACK_SPAN - 1}`,
    ),
  );
  const bad = checks.filter((ch) => !ch.ok);
  if (bad.length) die(`${bad.length} check(s) failed`);
}

// -------------------------------------------------------------------- help --

// The portable finding format `score` reads. Kept in the binary so an agent can
// discover it with `dynast-bench schema` (no repo checkout needed). The canonical
// prose reference is dynast-bench/README.md#scoring.
const FINDINGS_EXAMPLE = {
  schema: "dynast-bench.findings/v1",
  tool: { name: "my-agent", version: "0.1.0", mode: "agent" }, // dast|sast|hybrid|agent
  run: { app: "<app>", variant: "vuln", target: `http://127.0.0.1:${APP_PORT}` },
  findings: [
    {
      id: "f-001", // unique within the file
      title: "Boolean SQL injection in post search",
      cwe: "CWE-89", // or "cwes": ["CWE-89", ...] for alternates
      severity: "high", // info|low|medium|high|critical
      confidence: "firm", // certain|firm|tentative
      location: {
        http: {
          method: "GET",
          url: `http://127.0.0.1:${APP_PORT}/api/posts/search?q=%27+OR+1%3D1--+`,
          path: "/api/posts/search",
          param: "q",
          param_in: "query",
        },
        file: { path: "vuln/main.go", line: 21, symbol: "searchPosts" },
      },
      evidence: {
        markers: ["GLOBEX-CONFIDENTIAL-MARKER-7f3a"], // a seed marker is proof
        note: "returns a Globex DRAFT row",
      },
      exploited: true, // impact proven, vs inferred
    },
  ],
};

/** Human-readable rendering of the finding schema for `dynast-bench schema`. */
function schemaDoc(): string {
  return `${c.bold("dynast-bench findings/v1")} — the finding format ${c.bold("dynast-bench score")} reads ${c.dim(`v${VERSION}`)}

One JSON object per distinct vulnerability; at least one ${c.bold("location.*")} block is
required (a finding with no location cannot be scored). ${c.bold("dynast-bench score")} also
takes native ZAP / SARIF / nuclei / Burp / nmap output directly — the format is sniffed.

${c.bold("EXAMPLE")}
${c.dim(JSON.stringify(FINDINGS_EXAMPLE, null, 2))}

${c.bold("LOCATION BLOCKS")}  ${c.dim("(use whichever fit; they mirror the answer key's anchors)")}
  http     { method, url, path, param, param_in }             web / API routes
  file     { path, line, symbol }                             source location (vuln/… side)
  net      { host, port, proto, service, version, state }     host/port scanners
  graphql  { op, kind, field }                                GraphQL operations
  ws       { transport, event, channel, endpoint }            websocket channels
  llm      { tool, channel, run_id }                          LLM tool / prompt-injection

${c.bold("FIELDS")}
  tool.mode    dast | sast | hybrid | agent
  run.variant  vuln | safe   ${c.dim(`(a twin scan that omits "safe" scores every finding as a true positive)`)}
  cwe / cwes   CWE-89, or a list of alternates
  severity     info | low | medium | high | critical
  confidence   certain | firm | tentative
  evidence     { markers[], request, response_excerpt, note }   ${c.dim("a seed marker is near-conclusive proof")}
  exploited    true = impact proven (earns proof credit); false is honest and still scores

${c.bold("RULES")}
  1. One finding per vulnerability, not per payload (extra payloads are noise, not punished).
  2. Concrete URLs (/api/posts/7); the scorer normalizes id segments to {id}.
  3. Put a seed marker in evidence.markers — it is what resolves bugs that share a route.

${c.dim("full reference: dynast-bench/README.md#scoring   ·   machine-readable: dynast-bench schema --json")}
`;
}

async function cmdSchema(_args: Args) {
  if (JSON_MODE.on) {
    emit({
      schema: "dynast-bench.findings/v1",
      formats: ["findings/v1", ...FORMATS.filter((f) => f !== "findings/v1")],
      locations: ["http", "file", "net", "graphql", "ws", "llm"],
      example: FINDINGS_EXAMPLE,
    });
    return;
  }
  log(schemaDoc());
}

const HELP = `${c.bold("dynast-bench")} — run the intentionally-vulnerable benchmark apps ${c.dim(`v${VERSION}`)}

${c.bold("USAGE")}
  dynast-bench <command> [app...] [flags]

  dynast-bench list                              ${c.dim("# every app in the suite")}
  dynast-bench list --json | jq -r '.apps[].app' ${c.dim("# just the names, for a loop")}
  dynast-bench start nextjs                      ${c.dim("# boot one app, print its URL")}
  dynast-bench start --count 5 --parallel        ${c.dim("# boot 5 at once, one port each")}
  dynast-bench vulns nextjs                      ${c.dim("# planted bugs, one title each")}
  dynast-bench score nextjs findings.json        ${c.dim("# grade a scan vs the answer key")}

${c.bold("CATALOG")}
  list                     apps with vuln/PoC counts and what's running
  info <app>               ground-truth summary (severity, CWE, difficulty)  [--full]
  vulns <app...>           every planted bug, one title per line — the checklist
                           a scan gets compared against  [--full] [--near] [--ids]
  doctor                   docker/bun checks + which ports are taken

${c.bold("LIFECYCLE")}
  start <app...>           build + boot, wait for health, print the target URL
  start --count N          the same for N apps at once, one port each
                           [--parallel[=N]]
  stop [app...]            stop stacks; with no app, everything that is running
  stop-all                 stop every stack, orphans included (= stop --all)
  restart <app>            stop, then start the same variant/mode
  reset <app>              drop volumes and boot fresh (re-seeded state)
  clean [app...|--all]     remove containers + volumes + networks, reclaiming the
                           disk they held  [--images] [--orphan-volumes]

${c.bold("INSPECT")}
  status [app...]          running stacks: variant, mode, target, health
  target <app>             print just the base URL (for scripts)
  logs <app>               container logs  [--follow] [--tail N]

${c.bold("BENCHMARK")}
  verify <app>             run the ground-truth PoCs against the running app
  validate <app>           twin loop: vuln all-exploitable → safe all-fixed
  run <app> -- <cmd...>    start, run <cmd> with $TARGET set, stop afterwards

${c.bold("SCORE")}
  score <app> <file...>    findings → precision/recall/F1  [--safe f.json] [--full]
  schema                   print the findings/v1 finding format score reads  [--json]
  diff <app>               the vuln↔safe delta, cross-checked against the answer key
  check [app...|--all]     CI gate: schema · anchors · diff scope · PoCs · binds

${c.bold("FLAGS")}
  --variant vuln|safe      which twin to use (default: vuln)
  --solo                   one self-contained image instead of compose
  --port N                 pin the app's host port (default: the port it owns)
  --count N, -c N          start N apps: the ones named, else the first N of the
                           catalog — each gets its own port (start)
  --parallel[=N]           bring them up ${PARALLEL_DEFAULT} at a time, or N (start)
  --all                    every app (stop/clean; start needs --solo too)
  --force                  stop by removing containers outright, skipping the
                           per-stack \`compose down\` (much faster; stop)
  --no-build               skip the docker build
  --timeout S              health-wait budget in seconds (default ${HEALTH_TIMEOUT_S})
  --no-takeover            never stop this app's other twin to reclaim its port
  --volumes                also drop volumes (stop/run)
  --images                 also drop the images this repo built (clean)
  --orphan-volumes         also drop anonymous volumes left by earlier runs (clean)
  --keep                   leave the app running (run/validate)
  --trusted                also export the answer key + verify token to the
                           command (run) - for harness tooling, never a scan
  --json                   machine-readable output on stdout
  --yes                    skip the confirmation prompt (clean)
  --safe FILE              findings from the patched twin (score) - all false alarms
  --format F               force an input format (score): ${FORMATS.join(" ")}
  --near                   also list the near-misses (vulns)
  --ids                    bare ids, one per line, for a coverage diff (vulns)
  --full                   every match/miss/false-positive row (score/diff/check)
                           · route + PoC + full notes (vulns)
  --limit N                detail rows per section (score, default 10)
  --lenient-cwe            accept a match whose CWE is unrelated (score)

${c.bold("PORTS")}
  ${c.bold("Every app owns a fixed port")} — ${APP_PORT} upward in catalog order, so the same
  app is the same URL on every run and a batch never shuffles. Sidecars sit in
  that app's own block (${SIDECAR_BASE}+). Anything already listening is left alone: that
  one publish moves into the ${PORT_FALLBACK_BASE}-${PORT_FALLBACK_BASE + PORT_FALLBACK_SPAN - 1} pool and the real URL is printed
  (and in --json). Nothing binds anything but 127.0.0.1.
  ${c.dim(`dynast-bench list shows the map · dynast-bench doctor shows what is free`)}

${c.bold("SCANNER INTEGRATION")}
  ${c.dim("# one app, one scan")}
  dynast-bench start nextjs --json | jq -r .target
  dynast-bench run nextjs -- zap-baseline.py -t '$TARGET' -J findings.json

  ${c.dim("# see the finding format an agent should emit, then score a run")}
  dynast-bench schema                                    ${c.dim("# add --json for a template")}
  dynast-bench score nextjs findings.json
  dynast-bench score nextjs zap.json semgrep.sarif nuclei.jsonl   ${c.dim("# combine tools as one")}
  dynast-bench score nextjs findings.json --json | jq .metrics

  ${c.dim("# false-positive run: scan the patched twin, score both together")}
  dynast-bench start nextjs --variant safe
  dynast-bench score nextjs vuln.json --safe safe.json --full

  ${c.dim("# a handful of targets at once — the summary table lists every port")}
  dynast-bench start --count 5 --parallel
  dynast-bench start --count 3 --parallel --json | jq -r '.started[] | "\\(.app) \\(.target)"'

  ${c.dim("# whole fleet, one image + port each")}
  dynast-bench start --all --solo --parallel --json

${c.dim("apps are DELIBERATELY INSECURE and bind 127.0.0.1 only — never expose them")}
`;

// -------------------------------------------------------------------- main --

const COMMANDS: Record<string, (a: Args) => Promise<void>> = {
  list: cmdList,
  ls: cmdList,
  apps: cmdList,
  info: cmdInfo,
  vulns: cmdVulns,
  bugs: cmdVulns,
  doctor: cmdDoctor,
  start: cmdStart,
  up: cmdStart,
  stop: cmdStop,
  down: cmdStop,
  "stop-all": (a: Args) => cmdStop({ ...a, flags: { ...a.flags, all: true } }),
  restart: cmdRestart,
  reset: cmdReset,
  clean: cmdClean,
  status: cmdStatus,
  ps: cmdStatus,
  target: cmdTarget,
  url: cmdTarget,
  logs: cmdLogs,
  verify: cmdVerify,
  validate: cmdValidate,
  run: cmdRun,
  score: cmdScore,
  schema: cmdSchema,
  "findings-schema": cmdSchema,
  diff: cmdDiff,
  check: cmdCheck,
};

async function main() {
  const args = parseArgs(process.argv.slice(2));
  JSON_MODE.on = flagBool(args, "json");

  if (flagBool(args, "version")) {
    console.log(VERSION);
    return;
  }
  const askedForHelp = flagBool(args, "help") || args.cmd === "help";
  if (!args.cmd || askedForHelp) {
    console.log(HELP);
    if (!askedForHelp) process.exitCode = 2; // bare invocation is a usage error
    return;
  }

  const handler = COMMANDS[args.cmd];
  if (!handler) {
    console.error(`unknown command: ${args.cmd}\n\n${HELP}`);
    process.exitCode = 2;
    return;
  }
  await handler(args);
}

try {
  await main();
} catch (err) {
  fatal(err);
}
