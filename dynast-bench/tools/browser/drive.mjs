#!/usr/bin/env node
/**
 * Drive a real browser at one page and report what happened, as JSON on stdout.
 *
 * This exists for the small set of bugs that a curl PoC cannot prove: DOM XSS,
 * postMessage handlers, anything whose sink is reached only by evaluating the
 * page's own JavaScript. Everything else in the suite stays on curl - see
 * "Browser PoCs" in CLAUDE.md.
 *
 * It is deliberately a *probe*, not a test framework: it navigates, optionally
 * pokes the page, and dumps observations. Deciding whether those observations
 * mean "vulnerable" is the PoC's job, so the pass/fail rule stays readable in
 * the PoC itself rather than hiding in here.
 *
 *   node drive.mjs --url http://host/page#payload
 *                  [--click <selector>]      click it (repeatable)
 *                  [--type <selector> --value <text>]  fill an input
 *                  [--wait-for <selector>]   wait for it to appear first
 *                  [--eval <js>]             run in page context, JSON in .result
 *                  [--wait <ms>]             settle budget before reading (default 1500)
 *                  [--until dialog:<s>]      stop settling once that oracle fires
 *                  [--until request:<s>]     (same, for a requested URL)
 *                  [--timeout <ms>]          navigation budget (default 20000)
 *
 * Output:
 *   { url, dialogs: [{type,message}], console: [string], requests: ["GET url"],
 *     result: <--eval return value>, errors: [string] }
 *
 * Always exits 0 when the browser ran at all; a page-level failure is reported
 * in `errors` rather than as an exit code, because "the page threw" is data a
 * PoC may well be asserting on. Exit 1 means the browser itself never started.
 */

import puppeteer from "puppeteer-core";

const argv = process.argv.slice(2);
const one = (name, def = undefined) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? def : argv[i + 1];
};
const many = (name) =>
  argv.reduce((acc, a, i) => (a === `--${name}` ? [...acc, argv[i + 1]] : acc), []);

// `--cookie name=value` (repeatable): seat cookies for the target host before the
// first navigation, so a PoC can log in with curl and hand the resulting session
// to the browser to drive an authenticated page.
const cookieHost = (() => {
  try {
    return new URL(one("url", "http://127.0.0.1")).hostname;
  } catch {
    return "127.0.0.1";
  }
})();
const cookies = many("cookie")
  .filter(Boolean)
  .map((kv) => {
    const i = kv.indexOf("=");
    return { name: kv.slice(0, i), value: kv.slice(i + 1), domain: cookieHost, path: "/" };
  });

const url = one("url");
if (!url) {
  console.error("drive.mjs: --url is required");
  process.exit(1);
}

const out = { url, dialogs: [], console: [], requests: [], result: null, errors: [] };
const note = (e) => out.errors.push(String(e && e.message ? e.message : e));

// The settle waits below exist because the interesting thing usually happens
// after navigate/evaluate returns. `--until` names what we are actually waiting
// for, so the budget becomes a ceiling rather than the normal path: a fired
// oracle ends the wait immediately. Without it the behaviour is the old fixed
// sleep, which is still the right answer when a PoC asserts on the absence of
// something (the safe twin) - you cannot short-circuit proving a negative.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = one("until") ?? "";
const untilAt = until.indexOf(":");
const untilKind = until.slice(0, untilAt);
const untilWant = until.slice(untilAt + 1);
const satisfied =
  untilKind === "dialog"
    ? () => out.dialogs.some((d) => String(d.message).includes(untilWant))
    : untilKind === "request"
      ? () => out.requests.some((r) => r.includes(untilWant))
      : null;
const settle = async (ms) => {
  if (!satisfied) return sleep(ms); // nothing to watch for: just wait it out
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (satisfied()) return;
    await sleep(25);
  }
};

let browser;
try {
  browser = await puppeteer.launch({
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium",
    // No sandbox: this is a throwaway container pointed at a local benchmark
    // app, and the alternative is running the whole thing --cap-add=SYS_ADMIN.
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
  });
} catch (e) {
  console.error(`drive.mjs: could not start chrome - ${e}`);
  process.exit(1);
}

try {
  const page = await browser.newPage();

  // A dialog blocks the page until it is answered, so this handler is what keeps
  // an alert() from hanging the run. It is also the actual XSS oracle: a fired
  // dialog is proof the injected script executed, not just that it was echoed.
  page.on("dialog", async (d) => {
    out.dialogs.push({ type: d.type(), message: d.message() });
    await d.dismiss().catch(() => {});
  });
  page.on("console", (m) => out.console.push(m.text()));
  page.on("pageerror", (e) => note(`pageerror: ${e}`));
  // Every request the page makes, which is how a PoC proves an endpoint is only
  // reachable once the JS has run.
  page.on("request", (r) => out.requests.push(`${r.method()} ${r.url()}`));

  if (cookies.length) await page.setCookie(...cookies).catch(note);

  const timeout = Number(one("timeout", "20000"));
  await page.goto(url, { waitUntil: "networkidle2", timeout }).catch(note);

  const waitFor = one("wait-for");
  if (waitFor) await page.waitForSelector(waitFor, { timeout }).catch(note);

  const typeSel = one("type");
  if (typeSel) {
    await page
      .type(typeSel, one("value", ""))
      .catch(() => note(`no input matching ${typeSel}`));
  }

  for (const sel of many("click")) {
    await page.click(sel).catch(() => note(`nothing to click at ${sel}`));
    await settle(250);
  }

  await settle(Number(one("wait", "1500")));

  const js = one("eval");
  if (js) {
    // Wrapped in an async IIFE so a PoC can `await` inside its snippet (e.g. a
    // short delay for React to flush before reading the DOM back).
    out.result = await page.evaluate(`(async () => { ${js} })()`).catch((e) => {
      note(`eval: ${e}`);
      return null;
    });
    // Whatever the script kicked off is usually asynchronous - a state update
    // that re-renders, an image that has to fail before onerror runs. Reading
    // the observations straight after evaluate() would miss all of it.
    await settle(Number(one("settle", "800")));
  }
} catch (e) {
  note(e);
} finally {
  await browser.close().catch(() => {});
}

process.stdout.write(JSON.stringify(out, null, 2) + "\n");
