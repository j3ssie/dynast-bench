# nextjs - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**TaskFlow** - a tiny multi-tenant task/blog app (Next.js 15 App Router +
TypeScript + Prisma/Postgres + Redis sessions + Mailpit) with **33 planted,
documented vulnerabilities** and a machine-checkable ground truth. See the
design catalog in [`../../benchmark-plans/nextjs.md`](../../benchmark-plans/nextjs.md).

This app is also the reference for **discovery tiers**: its attack surface is
deliberately hard to *find*, not just hard to recognise. The homepage links
almost nothing, the nav and every API path are assembled client-side from a
route registry (so the full URLs exist nowhere as literals), one endpoint lives
only in a lazily-loaded chunk behind a button, and registration is a four-step
flow. A request-only fuzzer sees a fraction of the app; a browser-driven agent
sees the rest. Every bug's `discovery:` tier records which.

## Layout

```
nextjs/
├── vuln/          # vulnerable variant (Next.js prod build; the default target)
├── safe/          # patched twin - same app, every planted bug fixed
├── ground-truth/  # VULNERABILITIES.yaml + verify/ PoCs (never baked into images)
└── Makefile       # up · reset · safe · verify · validate · diff
```

Both variants run as a production build (`next build` + `next start`) so a
scanner sees realistic error handling, and so the prototype-pollution PoC
doesn't trip the dev-mode type-checker.

## Run

```bash
make up          # build + start vuln/ on http://127.0.0.1:13311 (waits for health)
make verify      # run all 33 PoCs; expect ALL exploitable
make safe        # switch to the patched twin (stops vuln - shared host port)
make verify-safe # run all 33 PoCs; expect ALL fixed
make validate    # the whole loop automatically: vuln→all pass, safe→all fixed
make diff        # ground-truth diff (vuln vs safe)
make reset       # fresh seeded state
```

`make validate` is the money target - it proves the ground truth end to end.
**Status: validated - 33/33 exploitable on `vuln/`, 33/33 fixed on `safe/`.**

Three PoCs (`domxss_001`, `postmsg_001`, and the credential harvest in
`creds_js_001`/`session_001`'s cousins) drive a **real headless browser** from a
shared Docker image. `make verify` builds that image once on first use; it needs
Docker but no other host setup. See
[`../../dynast-bench/tools/browser/`](../../dynast-bench/tools/browser/).

### Run as a single self-contained image (no compose)

Each variant also ships an all-in-one `Dockerfile.standalone` that embeds
Postgres + Redis + an internal SSRF sink, so it runs from one image:

```bash
make solo            # build + run vuln/Dockerfile.standalone on :13311
make solo VARIANT=safe PORT=13320
make solo-down       # stop it
# or by hand:
docker build -f vuln/Dockerfile.standalone -t vuln-nextjs vuln/
docker run --rm -p 127.0.0.1:13311:3000 vuln-nextjs
```

Inside the image the compose service names (`postgres`, `redis`, `mailpit`) are
aliased to `127.0.0.1`, so the app config, env values, and **every PoC are
identical** to the compose topology - validated 33/33 exploitable in solo mode.

## Discovery tiers

`difficulty` is how hard a bug is to recognise once you are looking at it;
`discovery` is how much crawling capability it takes to reach the endpoint at
all. Every bug stays exploitable over plain HTTP once its URL is known - the tier
only gates *finding* it.

| tier | count | reach it by |
|------|-------|-------------|
| `static-html` | 6 | request-only crawl/fuzz: it's in `/` HTML or a conventional path |
| `js-static` | 4 | reading a bundle as text (grep the JS) |
| `js-runtime` | 14 | modelling the route registry / fetching a lazy chunk |
| `interaction` | 5 | driving the UI - a click, a submit, a browser event |
| `flow` | 4 | reaching one state of the multi-step signup |

`dynast-bench score` reports **recall by discovery tier**, so "found everything
at `static-html`, nothing past it" reads as a fact about the tool's crawler
rather than an unexplained low F1.

## What's planted (33 bugs + 13 near-misses)

Full metadata (CWE, OWASP, severity, taint distance, reachability, discovery
tier, PoC path) is in
[`ground-truth/VULNERABILITIES.yaml`](ground-truth/VULNERABILITIES.yaml).

| id | class | CWE | discovery | where |
|----|-------|-----|-----------|-------|
| MW-BYPASS-001 | middleware auth bypass (`x-middleware-subrequest`) | 285 | js-runtime | `src/middleware.ts` |
| PROTO-001 | prototype pollution (deep-merge) | 1321 | js-runtime | `src/lib/merge.ts` |
| SQLI-001 | SQLi (`$queryRawUnsafe`) | 89 | js-runtime | `api/posts/search` |
| SSRF-001 | SSRF (server fetch) → internal Mailpit | 918 | js-runtime | `api/preview` |
| IDOR-001 | cross-tenant object read | 639 | js-runtime | `api/posts/[id]` |
| MASSASSIGN-001 | overposting `role`/`isAdmin` | 915 | js-runtime | `api/users/me` |
| AUTHZ-001 | missing function-level authz | 862 | js-runtime | `api/users/[id]/promote` |
| JWT-001 | `alg:none` + hardcoded secret + no `exp` | 347 | js-runtime | `src/lib/jwt.ts` |
| XSS-STORED-001 | stored XSS (`dangerouslySetInnerHTML`) | 79 | interaction | `posts/[id]/page.tsx` |
| XSS-REFLECT-002 | reflected XSS | 79 | js-runtime | `posts/search/page.tsx` |
| TRAVERSAL-001 | path traversal on download | 22 | js-runtime | `api/attachments/download` |
| CORS-001 | reflected Origin + credentials | 942 | js-runtime | `src/lib/cors.ts` |
| REDIRECT-001 | open redirect | 601 | static-html | `app/goto` |
| SECRET-001 | `NEXT_PUBLIC_` secret leak + hardcoded key | 200 | static-html | `src/lib/config.ts` |
| SECRET-002 | base64-encoded cloud key shipped in the JS bundle | 798 | js-static | `src/lib/integrations.ts` |
| CREDS-BUNDLE-001 | working service creds (`Basic …`) in the JS bundle | 522 | js-static | `src/lib/integrations.ts` |
| CREDS-JS-001 | working QA account creds committed in a client component | 798 | js-static | `_components/DevAutofill.tsx` |
| SOURCEMAP-001 | production source maps published (`*.js.map`) | 540 | js-static | `next.config.js` |
| ENVFILE-001 | prod env file served from the web root | 538 | static-html | `public/env.production` |
| CONFIG-LEAK-001 | full runtime config in `script#app-config` | 200 | static-html | `src/app/layout.tsx` |
| ENUM-001 | user enumeration (distinct errors) | 204 | static-html | `api/auth/login` |
| SESSION-001 | predictable session id (`Math.random`) | 330 | static-html | `src/lib/session.ts` |
| BILLING-001 | negative/huge seat quantity | 840 | js-runtime | `api/billing/seats` |
| RACE-001 | seat-limit race (concurrent invites) | 362 | js-runtime | `api/invites` |
| CACHE-POISON-001 | web cache poisoning on unkeyed header | 349 | js-runtime | `api/cache` |
| CODEINJ-001 | RCE via `new Function` on a "computed column" | 94 | interaction | `api/_debug/report` |
| DOMXSS-001 | DOM XSS via `location.hash` → `innerHTML` | 79 | interaction | `_components/PostFilter.tsx` |
| POSTMSG-001 | `postMessage` handler with no origin check → HTML sink | 346 | interaction | `profile/page.tsx` |
| SIGNUP-ENUM-001 | account enumeration at signup step 1 | 204 | interaction | `api/signup/start` |
| SIGNUP-TOKEN-001 | clock-derived email verification code | 330 | flow | `src/lib/signup.ts` |
| SIGNUP-MASSASSIGN-001 | overpost `role`/`orgSlug` at signup step 3 | 915 | flow | `api/signup/profile` |
| SIGNUP-STEPSKIP-001 | complete signup without verifying (step-skip) | 841 | flow | `api/signup/complete` |
| SIGNUP-IDOR-001 | any draft (email + code) readable by sequential id | 639 | flow | `api/signup/draft/[id]` |

### The hidden endpoint

**CODEINJ-001** (`POST /api/_debug/report`) is referenced from nowhere in the
served HTML and from no chunk the app loads on arrival. The only reference is
inside a `next/dynamic` "report builder" chunk that the browser fetches the first
time you open the **Advanced** panel on `/profile`. Its "computed column"
expression is run through `new Function` on the server, so the request body is a
full server-side JavaScript runtime. Finding it at all requires either executing
the page and clicking, or reading the source. Its allow-listed aggregate path
(named `count`/`sum`/`max`, unknown names rejected) is the near-miss.

### The multi-step signup

Registration is four independent requests over a server-side draft row
(`start → verify → profile → complete`), which is where four bugs live:
enumeration at step 1, a clock-derived verification code at step 2 (recomputable,
not received), `role`/`orgSlug` mass assignment at step 3 (register an admin, or
join Globex), and a step-skip at step 4 (finish a draft that was never verified).
A fifth, `SIGNUP-IDOR-001`, reads any in-progress draft - email **and**
verification code - by counting through the sequential draft ids. The
rate-limited, constant-response `/api/signup/resend` is the near-miss for the
enumeration.

### The client-side exposure cluster

Several bugs are things a scanner finds by reading what the app *ships* rather
than by fuzzing an endpoint, and they are deliberately layered:

- `GET /env.production` hands over `DATABASE_URL` and `JWT_SECRET` outright.
- `GET /` embeds `script#app-config` with the internal API base, SMTP
  credentials and an internal admin token.
- `GET /integrations` pulls a chunk containing a base64 cloud key **and** a
  `Basic` header that really authenticates as the `service` account - the PoC
  harvests it, replays it, then decodes it and logs in.
- The homepage no longer lists seed accounts; the sign-in page's chunk carries
  working QA credentials (`CREDS-JS-001`) behind a `?debug=1` autofill helper.
- Every chunk has a matching `*.js.map` whose `sourcesContent` is the original
  TypeScript, planted-bug comments included.

Each sits next to a near-miss of the same shape, so grep-only tooling pays for
it in false positives.

**Near-misses** (safe code beside a vulnerable sibling - flagging any is a false
positive): parameterized `$queryRaw` (empty-q branch of search), `safeApplySettings`
allow-list, `api/preview-internal` (fixed allow-listed fetch), the escaped post
title on the detail page, `WIDGET_THEME_B64` (base64 literal that is only UI
config), `fetchSyncToken` (credential-shaped but server-minted per request),
`PUBLIC_RUNTIME_CONFIG` (allow-listed config that *is* safe to serialize),
`public/config.public.json` (a web-root config file that is public by design),
`SAMPLE_ACCOUNTS` (`.invalid` placeholder creds beside the real ones), the
allow-listed aggregate in the report builder, `api/signup/resend` (constant +
rate limited), and `newInviteToken` (CSPRNG beside the clock-derived code).

## Notes / caveats

- The **PROTO-001** route probes pollution within a single request and then
  removes the injected key, purely so the long-lived server isn't left broken
  for later scans; the vulnerable `deepMerge` sink is unchanged.
- **RACE-001** needs fresh seed state (`make reset`), and **BILLING-001** restores
  the seat limit after itself, so PoC ordering doesn't matter.
- **DOMXSS-001** and **POSTMSG-001** are proven by an actual fired `alert()` in a
  headless browser - reflection alone never produces a dialog. Their payloads
  live in the URL fragment / a `postMessage`, so no server response ever contains
  them and a request-only tool cannot observe the sink.
- `/api/_verify/*` is the harness verification API (guarded by
  `X-Verify-Token: benchsecret`). On disk the folder is `%5Fverify` because Next
  treats `_`-prefixed folders as private; the URL is still `/api/_verify/*`. The
  hidden `%5Fdebug/report` folder uses the same trick for `/api/_debug/report`.
- **ENVFILE-001** uses `public/env.production`, not `public/.env.production`:
  Next answers `400` for any request path with a dot-prefixed segment, so a
  literal `/.env` is unreachable no matter what is on disk. The bug (production
  env file published at the web root) and its PoC are otherwise unchanged.
- **SOURCEMAP-001** is a build-config bug, so it only exists in a real build -
  re-run `make up` / `make solo` after editing, and note that the maps expose
  the `VULN …` comments in `vuln/src/**`.
