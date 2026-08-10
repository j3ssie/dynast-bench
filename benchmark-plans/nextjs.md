# Next.js Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **modern-JS footgun** app. Signature bugs are the ones that only
exist in the Node/Next ecosystem - **middleware auth bypass**
(`x-middleware-subrequest`, CVE-2025-29927 style), **prototype pollution**
(deep-merge of request bodies), **SSRF via server-side `fetch` / the image
optimizer**, Prisma raw-query SQLi, and `dangerouslySetInnerHTML` XSS. Redis
sessions + Mailpit make session and reset-token bugs real.

**Second angle (discovery):** this app is also the reference for **hard-to-crawl
surface**. The homepage links almost nothing, the nav and every API path are
assembled client-side from a route registry (so the full URLs are never string
literals), one RCE endpoint lives only in a lazily-loaded chunk behind a button,
DOM XSS and a `postMessage` sink need a real browser, and registration is a
four-step flow. Each bug carries a `discovery:` tier
(`static-html | js-static | js-runtime | interaction | flow`), and the scorer
reports recall per tier - so a request-only fuzzer's low score reads as "its
crawler stops at static HTML", not as an unexplained miss. Keep ~5-6 bugs at
`static-html` so a dumb scanner still scores; that partial credit is what makes
the higher tiers mean something. The browser-driven PoCs use the shared
`dynast-bench/tools/browser/` image.

## Services (4 containers) - independent `docker-compose.yml`

| Service  | Image                 | Host port   | Purpose                     |
|----------|-----------------------|-------------|-----------------------------|
| app      | build ./app           | 3000        | Next.js 15 (App Router, TS) |
| postgres | postgres:16.4         | 5432        | Data                        |
| redis    | redis:7.4.0           | 6379        | Session store               |
| mailpit  | axllent/mailpit:v1.20 | 8025 (1025) | Verification + reset mail   |

## Stack choices (bugs live inside these idioms)

- **Next.js 15, App Router, TypeScript**, standalone output, single instance
- DB: **Prisma**; most queries typed, the search/report paths use
  `$queryRawUnsafe` with template-string concatenation (planted SQLi)
- Auth: **hand-rolled** - opaque session ID in an httpOnly cookie, session data
  in Redis; a `middleware.ts` gate on `/admin` and `/api/admin`; a JWT path
  (`jsonwebtoken`) with a hardcoded secret for API tokens
- Email: **nodemailer** → `mailpit:1025`; reset link `…/reset?token=…`
- Uploads: avatar to a volume, served through a route handler that joins the
  user-supplied filename (traversal)
- Server Actions + route handlers for mutations; a deep-merge util
  (`lodash.merge` / hand-rolled) merges request bodies into option objects
  (prototype pollution); an "image preview / fetch" feature (SSRF)

## Domain model

Standard shared domain, cross-tenant `user2` (org Globex) for IDOR PoCs.

## Vulnerability catalog (~34 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · middleware | **Auth bypass** via `x-middleware-subrequest` header | 285/290 | A01 | C | H | cross-file |
| app · middleware | Matcher misses `/api/admin` sub-paths | 862 | A01 | H | M | in-file |
| app · body merge | **Prototype pollution** (deep-merge req body) | 1321 | A08 | H | H | cross-file |
| app · login | No rate limit → brute force | 307 | A07 | M | E | in-file |
| app · login | User enumeration (distinct errors) | 204 | A07 | L | E-M | in-file |
| app · JWT | Hardcoded secret; `exp`/alg unchecked | 321/347 | A07 | H | M | in-file |
| app · session | Predictable/short session ID (`Math.random`) | 330/384 | A07 | M | M | in-file |
| app · reset | Predictable reset token (timestamp-based) | 640/330 | A07 | M | M | cross-file |
| app · posts/tasks | IDOR/BOLA - no org check in route handler | 639/863 | A01 | H | E-M | in-file |
| app · PATCH /users/me | Mass assignment via `{...body}` into Prisma | 915 | A01 | M | M | in-file |
| app · /posts/search | SQLi via `$queryRawUnsafe` concatenation | 89 | A03 | H | E | in-file |
| app · report query | **Second-order** SQLi via stored name | 89 | A03 | H | H | cross-file |
| app · comments | Stored XSS via `dangerouslySetInnerHTML` | 79 | A03 | M | E-M | cross-file |
| app · search page | Reflected XSS (unsanitized param render) | 79 | A03 | M | E | in-file |
| app · image/fetch | **SSRF** via server `fetch(userUrl)` | 918 | A10 | H | M-H | cross-service |
| app · next/image | SSRF via unrestricted `remotePatterns` / loader | 918 | A10 | M | M-H | cross-service |
| app · login `?next=` | Open redirect (`redirect(searchParams.next)`) | 601 | A01 | L | E | in-file |
| app · CORS | Reflects `Origin` + credentials | 942 | A05 | M | M | in-file |
| app · attachments | Path traversal in route handler | 22 | A01 | M | M | in-file |
| app · config | Secret leaked via `NEXT_PUBLIC_` env | 200/798 | A02 | M | E-M | in-file |
| app · config | Hardcoded secrets in committed source | 798 | A05 | M | E | in-file |
| app · integrations | Base64-encoded cloud key shipped in the client bundle | 798/200 | A02 | H | E-M | cross-file |
| app · integrations | Working service creds (`Basic …`) in the client bundle | 522/798 | A07 | C | E-M | cross-file |
| app · build config | `productionBrowserSourceMaps` publishes `*.js.map` | 540 | A05 | M | E | config |
| app · public/ | Production env file served from the web root | 538/540 | A05 | C | E | config |
| app · layout | Full runtime config in a `script#app-config` blob | 200/215 | A05 | H | E-M | cross-file |
| app · errors | Verbose errors / stack in response | 209 | A05 | L | E | in-file |
| app · billing/seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| app · invites | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| app · forms | CSRF on Server Actions (no token, cookie auth) | 352 | A01 | M | M | in-file |
| app · upload | SVG stored XSS + unrestricted type | 434/79 | A05 | M | M | in-file |
| app · deps | `npm audit` high in a pinned transitive dep | 1035 | A06 | M | E | config |
| app · admin | Missing function-level authz on an action | 862 | A01 | M | M | in-file |
| seed data | Default `admin/admin` service creds | 798 | A07 | M | E | in-file |

## Stack-specific highlights (only make sense in Next/Node)

- **Middleware auth bypass** - `middleware.ts` trusts requests carrying the
  internal `x-middleware-subrequest` header (the CVE-2025-29927 shape). A
  request to `/admin/users` with that header spoofed skips the gate entirely.
  Safe twin removes the header trust and re-checks the session in the route.
- **Prototype pollution** - a settings/import endpoint deep-merges the raw JSON
  body into a config object; `{"__proto__":{"isAdmin":true}}` pollutes
  `Object.prototype`. The near-miss endpoint copies only allowlisted keys.
- **SSRF two ways** - a server-side `fetch(userUrl)` "link preview" and an
  over-broad `next/image` `remotePatterns`/custom loader; both reach the Redis
  port and `169.254.169.254`.
- **`$queryRawUnsafe`** - Prisma's escape hatch used with a concatenated string,
  right beside a safe `$queryRaw` tagged-template call.
- **`dangerouslySetInnerHTML`** - comment body rendered raw; near-miss renders
  the same field as text.

## Near-misses (safe beside vulnerable)

- `searchPosts` (`$queryRawUnsafe`) beside `listPosts` (`$queryRaw` tagged).
- `mergeSettings` (deep-merge) beside `applySettings` (allowlist copy).
- `previewLink` (raw `fetch`) beside `fetchInternal` (URL allowlist + IP block).
- `<Comment dangerouslySetInnerHTML>` beside `<Post>{text}</Post>`.

## Logic-only bugs

- **Invite race (CWE-362):** seat check + insert not transactional across async
  handlers; parallel PoST beats the limit.
- **Billing (CWE-840):** negative/huge `seats` accepted.

## Discovery-hardening + newer bugs (built since v1)

The surface was reworked so most endpoints are no longer trivially crawlable,
and the following bugs were added on top of the original catalog:

- **CODEINJ-001 (CWE-94)** - a hidden `POST /api/_debug/report` referenced only
  from a `next/dynamic` devtools chunk (profile → Advanced), running its
  "computed column" through `new Function`. `discovery: interaction`. Near-miss:
  an allow-listed aggregate (`count`/`sum`/`max`) in the same file.
- **CREDS-JS-001 (CWE-798)** - working QA credentials committed in a client
  component (`_components/DevAutofill.tsx`), shipped in the sign-in chunk; the
  homepage that used to print seed accounts now prints none. `discovery:
  js-static`. Near-miss: `SAMPLE_ACCOUNTS` `.invalid` placeholders.
- **DOMXSS-001 (CWE-79)** - `location.hash` → `innerHTML` on the posts list.
  **POSTMSG-001 (CWE-346)** - a `postMessage` handler with no origin check that
  renders to HTML. Both `discovery: interaction`, both proven by a fired dialog
  in a headless browser.
- **SESSION-001 (CWE-330)** - the predictable `Math.random` session id (present
  in source since v1) now carries a dynamic PoC that observes the sid cookie's
  variable width. `discovery: static-html`.
- **Multi-step signup** (`start → verify → profile → complete`, server-side draft
  row): `SIGNUP-ENUM-001` (CWE-204, `interaction`), `SIGNUP-TOKEN-001` (CWE-330,
  clock-derived code, `flow`), `SIGNUP-MASSASSIGN-001` (CWE-915, `role`/`orgSlug`
  overpost, `flow`), `SIGNUP-STEPSKIP-001` (CWE-841, complete-without-verify,
  `flow`), `SIGNUP-IDOR-001` (CWE-639, any draft's email+code by sequential id,
  `flow`). Near-miss: rate-limited constant-response `/api/signup/resend`, and
  the CSPRNG `newInviteToken` beside the clock-derived code.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs
  (`mw_bypass.sh` sends the spoofed header; `proto_pollution.sh` posts the
  `__proto__` body then checks admin access; `ssrf_preview.sh`;
  `race_invite.sh`). PASS on `main-vuln`, FAIL on `main-safe`.
- Scorer → P/R/F1 + per-CWE. `ground-truth/` `.dockerignore`d.

## Patched twin (`main-safe`)

Middleware ignores internal headers + re-checks in route, matcher covers all
sub-paths, allowlist-copy instead of deep-merge, rate limit, constant-time
login, verified JWT + strong secret, `crypto.randomUUID` sessions, random reset
tokens, org checks, `$queryRaw` tagged templates, text rendering, SSRF allowlist
+ metadata block, constrained `remotePatterns`, redirect allowlist, locked CORS,
containment-checked downloads, server-only secrets, generic errors, validated
billing, atomic seat reservation, CSRF tokens, MIME/size upload checks, patched
dep, function-level authz.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-nextjs
services:
  app:
    build: ./app
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:3000"]
    environment:
      DATABASE_URL: postgresql://bench:bench@postgres:5432/bench
      REDIS_URL: redis://redis:6379
      SMTP_HOST: mailpit
      APP_URL: http://localhost:13311
      JWT_SECRET: "hardcoded-weak-secret"          # planted CWE-798
      NEXT_PUBLIC_API_KEY: "leaked-to-browser"     # planted CWE-200
    volumes: [uploads:/data/uploads]
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }
  postgres:
    image: postgres:16.4
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  redis:
    image: redis:7.4.0
    healthcheck: { test: ["CMD", "redis-cli", "ping"] }
  mailpit:
    image: axllent/mailpit:v1.20
    ports: ["127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13312}:8025", "127.0.0.1:${DYNAST_PORT_MAILPIT_1025:-13313}:1025"]
volumes: { uploads: {} }
```

## Build milestones

1. Compose + healthchecks + Makefile; Prisma schema + seed (cross-tenant + weak
   service cred).
2. Auth core: Redis sessions, `middleware.ts` gate **with** the header-bypass +
   matcher-gap bugs and safe twins; JWT path.
3. Posts CRUD + IDOR + `$queryRawUnsafe` SQLi (+ near-miss); comments XSS.
4. Reports: second-order SQLi; SSRF preview + `next/image`; prototype-pollution
   merge - each with a safe twin.
5. Billing/invite logic bugs; redirect/CORS/traversal/upload/env-leak misconfigs.
6. `VULNERABILITIES.yaml` + `verify/` PoCs; all PASS on `main-vuln`; branch
   `main-safe`, fix all, all PoCs FAIL; wire scorer.
