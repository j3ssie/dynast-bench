# nextjs - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**TaskFlow** - a tiny multi-tenant task/blog app (Next.js 15 App Router +
TypeScript + Prisma/Postgres + Redis sessions + Mailpit) with **22 planted,
documented vulnerabilities** and a machine-checkable ground truth. See the
design catalog in [`../../benchmark-plans/nextjs.md`](../../benchmark-plans/nextjs.md).

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
make verify      # run all 22 PoCs; expect ALL exploitable
make safe        # switch to the patched twin (stops vuln - shared host port)
make verify-safe # run all 22 PoCs; expect ALL fixed
make validate    # the whole loop automatically: vuln→all pass, safe→all fixed
make diff        # ground-truth diff (vuln vs safe)
make reset       # fresh seeded state
```

`make validate` is the money target - it proves the ground truth end to end.
**Status: validated - 22/22 exploitable on `vuln/`, 22/22 fixed on `safe/`.**

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
identical** to the compose topology - validated 22/22 exploitable in solo mode.

## What's planted (22 bugs + 8 near-misses)

Full metadata (CWE, OWASP, severity, taint distance, reachability, PoC path) is
in [`ground-truth/VULNERABILITIES.yaml`](ground-truth/VULNERABILITIES.yaml).

| id | class | CWE | where |
|----|-------|-----|-------|
| MW-BYPASS-001 | middleware auth bypass (`x-middleware-subrequest`) | 285 | `src/middleware.ts` |
| PROTO-001 | prototype pollution (deep-merge) | 1321 | `src/lib/merge.ts` |
| SQLI-001 | SQLi (`$queryRawUnsafe`) | 89 | `api/posts/search` |
| SSRF-001 | SSRF (server fetch) → internal Mailpit | 918 | `api/preview` |
| IDOR-001 | cross-tenant object read | 639 | `api/posts/[id]` |
| MASSASSIGN-001 | overposting `role`/`isAdmin` | 915 | `api/users/me` |
| AUTHZ-001 | missing function-level authz | 862 | `api/users/[id]/promote` |
| JWT-001 | `alg:none` + hardcoded secret + no `exp` | 347 | `src/lib/jwt.ts` |
| XSS-STORED-001 | stored XSS (`dangerouslySetInnerHTML`) | 79 | `posts/[id]/page.tsx` |
| XSS-REFLECT-002 | reflected XSS | 79 | `posts/search/page.tsx` |
| TRAVERSAL-001 | path traversal on download | 22 | `api/attachments/download` |
| CORS-001 | reflected Origin + credentials | 942 | `src/lib/cors.ts` |
| REDIRECT-001 | open redirect | 601 | `app/goto` |
| SECRET-001 | `NEXT_PUBLIC_` secret leak + hardcoded key | 200 | `src/lib/config.ts` |
| SECRET-002 | base64-encoded cloud key shipped in the JS bundle | 798 | `src/lib/integrations.ts` |
| CREDS-BUNDLE-001 | working service creds (`Basic …`) in the JS bundle | 522 | `src/lib/integrations.ts` |
| SOURCEMAP-001 | production source maps published (`*.js.map`) | 540 | `next.config.js` |
| ENVFILE-001 | prod env file served from the web root | 538 | `public/env.production` |
| CONFIG-LEAK-001 | full runtime config in `script#app-config` | 200 | `src/app/layout.tsx` |
| ENUM-001 | user enumeration (distinct errors) | 204 | `api/auth/login` |
| BILLING-001 | negative/huge seat quantity | 840 | `api/billing/seats` |
| RACE-001 | seat-limit race (concurrent invites) | 362 | `api/invites` |

### The client-side exposure cluster

Five of the bugs are things a scanner finds by reading what the app *ships*
rather than by fuzzing an endpoint, and they are deliberately layered:

- `GET /env.production` hands over `DATABASE_URL` and `JWT_SECRET` outright.
- `GET /` embeds `script#app-config` with the internal API base, SMTP
  credentials and an internal admin token.
- `GET /integrations` pulls a chunk containing a base64 cloud key **and** a
  `Basic` header that really authenticates as the `service` account - the PoC
  harvests it, replays it, then decodes it and logs in.
- Every chunk has a matching `*.js.map` whose `sourcesContent` is the original
  TypeScript, planted-bug comments included.

Each sits next to a near-miss of the same shape, so grep-only tooling pays for
it in false positives.

**Near-misses** (safe code beside a vulnerable sibling - flagging any is a false
positive): parameterized `$queryRaw` (empty-q branch of search), `safeApplySettings`
allow-list, `api/preview-internal` (fixed allow-listed fetch), the escaped post
title on the detail page, `WIDGET_THEME_B64` (base64 literal that is only UI
config), `fetchSyncToken` (credential-shaped but server-minted per request),
`PUBLIC_RUNTIME_CONFIG` (allow-listed config that *is* safe to serialize), and
`public/config.public.json` (a web-root config file that is public by design).

## Notes / caveats

- The **PROTO-001** route probes pollution within a single request and then
  removes the injected key, purely so the long-lived server isn't left broken
  for later scans; the vulnerable `deepMerge` sink is unchanged.
- **RACE-001** needs fresh seed state (`make reset`), and **BILLING-001** restores
  the seat limit after itself, so PoC ordering doesn't matter.
- `/api/_verify/*` is the harness verification API (guarded by
  `X-Verify-Token: benchsecret`). On disk the folder is `%5Fverify` because Next
  treats `_`-prefixed folders as private; the URL is still `/api/_verify/*`.
- **ENVFILE-001** uses `public/env.production`, not `public/.env.production`:
  Next answers `400` for any request path with a dot-prefixed segment, so a
  literal `/.env` is unreachable no matter what is on disk. The bug (production
  env file published at the web root) and its PoC are otherwise unchanged.
- **SOURCEMAP-001** is a build-config bug, so it only exists in a real build -
  re-run `make up` / `make solo` after editing, and note that the maps expose
  the `VULN …` comments in `vuln/src/**`.
