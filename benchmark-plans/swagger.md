# Swagger / OpenAPI Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **documented-API** app, catalogued against the **OWASP API
Security Top 10 (2023)** instead of the web Top 10 - the other apps cover the
web list, this one covers the API list. Its signature class is **API9: Improper
Inventory Management**. The app publishes a Swagger UI and an OpenAPI document,
and the document is *wrong on purpose*:

- a **shadow API** that is implemented but excluded from the spec,
- a **zombie API** (`/api/v0/…`) still routed, still missing the authz that `v1`
  later added,
- **drift** between what the spec says is writable/allowed and what the code
  accepts.

That makes it the discrimination test no other app in the suite runs: a
spec-driven scanner (feed it `/api/schema/`) gets enormous coverage cheaply but
is *blind* to the shadow and zombie routes; a crawler/brute-forcer finds those
but misses the parameter-level bugs. Neither strategy alone scores well. The
Swagger UI itself is also a sink - an old `swagger-ui-dist` with the `?url=`
spec-load bug.

## Services (5 containers) - independent `docker-compose.yml`

| Service     | Image                        | Host port   | Purpose                                       |
|-------------|------------------------------|-------------|-----------------------------------------------|
| app         | build ./ (python:3.12-slim)  | 3000        | Django 5.1 + DRF + gunicorn; Swagger UI/ReDoc |
| postgres    | postgres:16.4                | 5432        | Data                                          |
| redis       | redis:7.4.0                  | 6379        | Cache + session backend (pickle-serialized)   |
| mailpit     | axllent/mailpit:v1.20        | 8025 (1025) | Reset mail - target of the Host-header PoC    |
| partner-api | build ./partner (python)     | *internal only* | Third-party API stand-in - SSRF target + API10 |

## Stack choices (bugs live inside these idioms)

- **Django 5.1 + Django REST Framework 3.15**, JSON only - no templates, no
  server-rendered pages. `ModelViewSet`s under `/api/v1/`, a frozen `/api/v0/`
  urlconf still `include()`d
- **drf-spectacular** generates the OpenAPI 3.1 document at `/api/schema/`;
  Swagger UI at `/api/docs/`, ReDoc at `/api/redoc/`
- Swagger UI is **self-hosted from a pinned vulnerable `swagger-ui-dist` 3.x**
  (an `A06 Vulnerable Components` row in its own right) with `?url=`/`?configUrl=`
  spec loading left enabled
- Auth: **`djangorestframework-simplejwt`** bearer tokens for the API + Django
  sessions for `/admin/`; `SIGNING_KEY` hardcoded, `VERIFY_EXP` off
- Cache/session: **Redis with the pickle serializer** - combined with the
  hardcoded `SECRET_KEY`, that is a signed-cookie → RCE chain
- Outbound: `requests` in the integrations endpoint (SSRF) and in the
  `partner-api` client whose response is `yaml.load`ed and trusted (API10)
- Verification API per the shared convention:
  `GET /api/_verify/health|user|post` behind `X-Verify-Token: benchsecret`,
  documented nowhere in the spec

## Domain model

Standard shared domain (`Org → Team → Project → Post → Comment/Attachment`,
`Users` with roles, `Invitations`, `Webhooks`, `Reports`) as DRF resources.
Cross-tenant `user2` in Globex; the Globex DRAFT carrying
`GLOBEX-CONFIDENTIAL-MARKER-7f3a` is reachable via the zombie `v0` endpoint, the
`ordering` SQLi, or the BOLA on `/api/v1/posts/{id}/`.

## Vulnerability catalog (~33 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP API 2023 | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · docs | Swagger UI + ReDoc + `/api/schema/` public in prod | 200/489 | API8 | M | E | config |
| app · swagger-ui | Pinned vulnerable `swagger-ui-dist` 3.x - `?url=` loads an attacker spec (spoof + DOM XSS) | 79/601 | API8 | H | M | config |
| app · swagger-ui | `oauth2-redirect.html` open redirect / DOM XSS | 601/79 | API8 | M | M-H | config |
| app · spec | `example` values + `x-internal-token` extension leak a live token | 798/200 | API8 | H | E-M | in-file |
| app · spec | `servers:` + descriptions leak internal hostnames/paths | 200 | API9 | L | E | in-file |
| app · `/api/v1/internal/debug/config` | **Shadow API** - implemented, `exclude=True`, unauthenticated, dumps settings | 200/489 | API9 | C | H | cross-file |
| app · `/api/v0/users/{id}/` | **Zombie API** - old version still routed, predates the `IsOrgMember` fix | 639/1059 | API9 | H | H | cross-file |
| app · `PATCH /api/v1/users/me/` | **Drift** - spec lists 3 writable fields, serializer is `fields="__all__"` | 915 | API3 | H | M-H | cross-file |
| app · parsers | Validation bound to `application/json`; `text/plain` parser skips it | 20 | API8 | H | H | cross-file |
| app · `POST /api/v1/reports/` | Spec says `security: [bearerAuth]`; view is `AllowAny` | 862 | API5 | M | M | cross-file |
| app · `/api/v1/posts/{id}/` | Spec documents `GET`; the `ModelViewSet` also serves `PUT`/`DELETE` | 862 | API5 | H | M-H | cross-file |
| app · `/api/v1/exports/legacy/` | Deprecated-but-live, unthrottled, unauthenticated | 1059/770 | API9 | M | M | in-file |
| app · settings | `DEFAULT_PERMISSION_CLASSES = [AllowAny]` global default | 862 | API5 | H | E-M | config |
| app · `UserAdminSerializer` | `fields = "__all__"` leaks `password` hash + `reset_token` | 200 | API3 | H | E-M | in-file |
| app · `?ordering=` | **SQLi** via `.extra(order_by=…)` on a raw param | 89 | API8 | H | E | in-file |
| app · report runner | **Second-order SQLi** - stored project name into `cursor.execute(f"…")` | 89 | API8 | H | H | cross-file |
| app · settings | `DEBUG = True` → technical 500 page leaks settings, SQL, env | 209/489 | API8 | H | E | config |
| app · settings | Hardcoded `SECRET_KEY` → forge `django.core.signing` reset tokens / session cookie | 798/347 | API2 | H | M-H | in-file |
| app · sessions | `SESSION_SERIALIZER = PickleSerializer` + known key → **deser RCE** | 502 | API8 | C | H | cross-file |
| app · cache | Pickle-serialized Redis cache poisonable via the SSRF sink → RCE | 502 | API8 | C | H | cross-service |
| app · `/admin/` | Django admin exposed; weak `admin/admin` service cred | 1392/798 | API2 | H | E | config |
| app · settings | `ALLOWED_HOSTS=["*"]` + Host-built reset link → **host-header poisoning** | 644/601 | API2 | M | M-H | cross-service |
| app · CORS | `CORS_ALLOW_ALL_ORIGINS` + `CORS_ALLOW_CREDENTIALS` | 942 | API8 | M | M | config |
| app · `GET /api/v1/posts/{id}/` | **BOLA** - `get_object()` overridden without the org filter | 639 | API1 | H | E-M | in-file |
| app · `POST /api/v1/admin/users/{id}/role/` | **BFLA** - checks `is_authenticated` only | 862 | API5 | H | M | in-file |
| app · pagination | `?page_size=100000` honored; no throttle on list endpoints | 770/400 | API4 | M | E-M | in-file |
| app · JWT | Hardcoded `SIGNING_KEY`; `VERIFY_EXP: False`; no `aud`/`iss` check | 321/347 | API2 | H | M | config |
| app · `POST /api/v1/auth/token/` | No rate limit → credential stuffing; enumeration via distinct errors | 307/204 | API2 | M | E | in-file |
| app · `POST /api/v1/integrations/fetch/` | **SSRF** → `partner-api` / `169.254.169.254` | 918 | API7 | H | M-H | cross-service |
| app · partner client | **Unsafe consumption** - upstream YAML `yaml.load`ed, its `role` trusted | 502/1104 | API10 | H | H | cross-service |
| app · uploads | `default_storage.save(request.FILES['f'].name)` → traversal + any type | 22/434 | API8 | M | M | in-file |
| app · `POST /api/v1/invites/` | **Race condition** exceeds seat limit; negative `quantity` on seats | 362/840 | API6 | H | H | in-file |
| app · audit log | Bearer token written to the log in plaintext | 532 | API8 | L | M | cross-file |

## Stack-specific highlights

### Swagger/OpenAPI technology

- **The spec is an attack surface, not just documentation.** `/api/schema/` is
  unauthenticated and enumerates every parameter, enum, and internal hostname -
  reconnaissance a crawler would need hours to reconstruct. One `example` block
  carries a real service token (people paste real values into examples).
- **`?url=` spec loading.** The pinned Swagger UI 3.x renders whatever spec the
  `url`/`configUrl` query parameter points at (the CVE-2021-46708 class), so
  `…/api/docs/?url=https://evil.test/spec.json` gives an attacker a
  same-origin-looking API console - spoofing plus DOM XSS through crafted spec
  fields. The near-miss: a second docs mount pinned to a current
  `swagger-ui-dist` with `queryConfigEnabled: false` and the spec URL hardcoded.
- **Shadow / zombie / drift** are three distinct failures with three distinct
  detection strategies, so score them separately:
  - *shadow* - in the code, not in the spec (spec-driven scanners are blind),
  - *zombie* - `/api/v0/` still mounted after `v1` fixed the authz,
  - *drift* - spec and code disagree about writable fields, allowed methods, and
    whether auth is required.
  A useful side-metric: for every finding a tool reports, was the endpoint
  documented? Recall on undocumented endpoints is the number that separates API
  security tools from each other.
- **Content-type validation gap.** DRF validates the request body against the
  serializer for `application/json`, but the view also lists a permissive parser,
  so `Content-Type: text/plain` (or a `+json` suffix) reaches the handler with an
  unvalidated dict. Same endpoint, same body, different header, no validation.

### Django/DRF technology

- **`SECRET_KEY` → pickle sessions → RCE.** The key is hardcoded in a committed
  `settings.py`; sessions are signed with it and deserialized with `pickle`.
  Forge a cookie, get code execution. Two rows, one chain, and the chain is the
  interesting part - a tool that reports only "hardcoded secret" gets partial
  credit.
- **`fields = "__all__"`.** The single most common DRF mistake, in both
  directions: it over-*reads* (password hash in the response) and over-*writes*
  (`role`, `is_staff` accepted on `PATCH`). The near-miss serializer next to it
  lists fields explicitly.
- **`.extra(order_by=…)`.** DRF's `OrderingFilter` is safe; the hand-rolled
  ordering that falls back to `.extra()` is not. Plant them in the same viewset.
- **`AllowAny` as the global default.** Every view that forgets
  `permission_classes` is public by construction - a config-level bug that makes
  several route-level bugs reachable pre-auth.
- **API10 unsafe consumption.** `partner-api` returns YAML; the client
  `yaml.load`s it and trusts the `role` field it finds. Poison the upstream
  through the SSRF sink and escalate. Cross-service taint end to end, and the
  hardest row in the app.

## Near-misses (safe beside vulnerable)

- `/api/v1/users/{id}/` (`IsOrgMember`) beside `/api/v0/users/{id}/` (zombie).
- `PostViewSet.get_queryset` (org-filtered) beside `PostDetailView.get_object`
  (unfiltered).
- `UserSerializer` (explicit `fields`) beside `UserAdminSerializer` (`__all__`).
- `OrderingFilter` with an `ordering_fields` allowlist beside the `.extra()` path.
- `fetch_partner()` (host allowlist + private-IP block) beside
  `integrations_fetch()`.
- `/api/docs/v2/` (current swagger-ui, `queryConfigEnabled: false`) beside
  `/api/docs/` (pinned 3.x).

## Logic-only bugs (no pattern to grep)

- **Invite race (CWE-362):** 20 concurrent `POST /api/v1/invites/`; the seat
  check and insert are not in one transaction.
- **Seats (CWE-840):** negative/huge `quantity` flips the balance.
- **Version-drift authz (CWE-1059):** `v1` added the org check, `v0` never got
  it - a diff-in-time bug, invisible to any single-endpoint analysis.
- **API6 flow abuse:** `/api/v1/exports/legacy/` has no throttle, so the whole
  post table walks out one page at a time.

## Ground truth & scoring

- `ground-truth/VULNERABILITIES.yaml` - standard schema. The `owasp` field
  carries the **API** Top 10 id (e.g. `"API9:2023-Improper Inventory
  Management"`); the table above keeps the mapping. Optional additive keys for
  this app: `documented: true|false` (was the endpoint in `/api/schema/`) and
  `api_version: v0|v1|none`. Both are ignored by the shared scorer and let you
  report recall split by documented vs. undocumented.
- `ground-truth/verify/*.sh` - pure `curl`. `shadow_001.sh` GETs the excluded
  debug route and greps `SECRET_KEY`; `zombie_001.sh` reads `user2`'s record
  through `v0` as `user1`; `drift_001.sh` PATCHes `role=admin` and re-reads via
  `/api/_verify/user`; `parser_001.sh` sends the same body as `text/plain`;
  `swaggerui_001.sh` asserts `?url=` is honored; `pickle_001.sh` forges a signed
  session with the leaked key; `api10_001.sh` poisons the partner response then
  asserts the escalated role.
- `make verify` → all exploitable on `vuln/`; `make validate` → all fixed on
  `safe/`; `ground-truth/` never enters a build context.

## Patched twin (`safe/`)

Docs + schema behind admin auth (and off by default via env), current
`swagger-ui-dist` with query-config disabled and no `oauth2-redirect`, secrets
scrubbed from examples/extensions, generic `servers:`, shadow debug route
deleted, `/api/v0/` urlconf removed, explicit serializer `fields` with
`read_only` on `role`/`is_staff`, validation applied to every parser, real
`IsAuthenticated`/`IsOrgMember`/`IsAdmin` classes (and a deny-by-default
`DEFAULT_PERMISSION_CLASSES`), `http_method_names` narrowed to what the spec
documents, throttling on auth and list endpoints with a `max_page_size` cap,
`OrderingFilter` allowlist, parameterized cursors, `DEBUG=False`, `SECRET_KEY`
from env, `JSONSerializer` for sessions and cache, admin behind auth with the
seed cred rotated, explicit `ALLOWED_HOSTS` + absolute reset URLs from settings,
CORS allowlist, verified JWT with `exp`/`aud`, SSRF allowlist + metadata block,
`yaml.safe_load` and server-side role resolution for partner data, sanitized
upload names with MIME/size checks, atomic seat reservation, validated
quantities, redacted logs.

**A spec fix is part of the diff.** Regenerating the OpenAPI document so it
matches the implementation is the actual remediation for the API9 rows - in
`safe/`, spec and code agree, and a spec-driven scanner therefore gets complete
coverage. That contrast between the twins is itself a measurement.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-swagger
services:
  app:
    build: ./
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:3000"]
    environment:
      DATABASE_URL: postgres://bench:bench@postgres:5432/bench
      REDIS_URL: redis://redis:6379/0
      SMTP_HOST: mailpit
      PARTNER_URL: http://partner-api:9099          # internal-only SSRF target
      DJANGO_SECRET_KEY: "django-insecure-hardcoded" # planted CWE-798
      DJANGO_DEBUG: "true"                           # planted CWE-489
      EXPOSE_SCHEMA: "true"                          # planted CWE-200
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }
  postgres:
    image: postgres:16.4
    environment: { POSTGRES_USER: bench, POSTGRES_PASSWORD: bench, POSTGRES_DB: bench }
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  redis:
    image: redis:7.4.0
    healthcheck: { test: ["CMD", "redis-cli", "ping"] }
  mailpit:
    image: axllent/mailpit:v1.20
    ports: ["127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13312}:8025", "127.0.0.1:${DYNAST_PORT_MAILPIT_1025:-13313}:1025"]
  partner-api:
    build: ./partner            # NO host port - reachable only via SSRF
    expose: ["9099"]
```

`make solo` collapses this into one image; `internal-sink.mjs` serves both the
fake mailpit on `127.0.0.1:8025` and the partner YAML on `127.0.0.1:9099`, and
the entrypoint aliases `postgres`/`redis`/`mailpit`/`partner-api` to localhost so
config and PoCs are unchanged.

## Build milestones

1. Compose + healthchecks + Makefile; Django project, models, migrations, seed
   (Globex marker draft, weak service cred); `/api/_verify/*` green.
2. `/api/v1/` DRF viewsets + simplejwt auth + drf-spectacular; Swagger UI/ReDoc
   mounted (pinned 3.x) with the `/api/docs/v2/` near-miss.
3. API9 seam - the point of the app: freeze `/api/v0/` before adding
   `IsOrgMember` to `v1`, add the excluded shadow debug route, and introduce the
   spec/code drift (writable fields, extra methods, unenforced `security`).
4. Parameter-level rows: BOLA, BFLA, `__all__` serializers, ordering SQLi,
   second-order report SQLi, pagination/throttle, upload.
5. Config + chain rows: `DEBUG`, `SECRET_KEY` → pickle sessions/cache, admin,
   `ALLOWED_HOSTS` host-header poisoning, CORS, JWT, SSRF → `partner-api` →
   API10 YAML trust.
6. `VULNERABILITIES.yaml` (with `documented`/`api_version`) + every PoC
   exploitable on `vuln/`; copy to `safe/`, fix only the named lines **and
   regenerate the spec**, `make validate` + `make solo` green.
