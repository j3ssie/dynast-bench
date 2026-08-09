# ASP.NET Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **enterprise-Microsoft-monolith** app - ASP.NET Core Razor Pages
in a Web-Forms idiom, SQL Server, ADO.NET with hand-written SQL. Signature bugs
are the .NET classics: **overposting / mass assignment** (model binding sets
`IsAdmin`), **insecure deserialization** (`BinaryFormatter` / Json.NET
`TypeNameHandling.All` / `LosFormatter`-style ViewState), **XXE via
`XmlDocument`**, string-concat `SqlCommand` SQLi, **`Html.Raw` XSS**, and the
**Developer Exception Page left on in production**.

## Services (3 containers) - independent `docker-compose.yml`

| Service   | Image                                       | Host port  | Purpose             |
|-----------|---------------------------------------------|------------|---------------------|
| app       | build ./app (dotnet/aspnet:8.0)             | 3000       | The monolith        |
| sqlserver | mcr.microsoft.com/mssql/server:2022-latest  | 1433       | Data                |
| mailpit   | axllent/mailpit:v1.20                       | 8025 (1025)| Verification emails |

> SQL Server wants ~2 GB RAM; on Apple Silicon add `platform: linux/amd64`.

## Stack choices (bugs live inside these idioms)

- **ASP.NET Core 8 + Razor Pages**, no EF Core:
  - Data: **Microsoft.Data.SqlClient**, hand-written SQL in a `Dal/` folder;
    parameterized in most places, string-concat in the planted SQLi sites
  - Auth: cookie auth + role claims; **BCrypt.Net** hashes; email verification
    via **MailKit** → `mailpit:1025`; a JWT path accepting `alg:none`
  - Binding: page models bind the whole entity (`[BindProperty] public User
    User`) so extra posted fields (`IsAdmin`, `Role`) overpost
  - Deserialization: a "restore" import using `BinaryFormatter` and a settings
    import using Json.NET with `TypeNameHandling.All`
  - Uploads: avatar `IFormFile` → mounted volume (no content check)
- Startup runs `Schema.sql` + `Seed.sql` idempotently (retry loop)

## Domain model

Standard shared domain, cross-tenant `user2` (org Globex) for IDOR PoCs.

## Vulnerability catalog (~29 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| Profile page · binding | **Overposting** sets `IsAdmin`/`Role` | 915 | A01 | H | M | in-file |
| Import · binary | **`BinaryFormatter.Deserialize`** RCE | 502 | A08 | C | H | in-file |
| Import · json | **Json.NET `TypeNameHandling.All`** deser RCE | 502 | A08 | C | H | in-file |
| Import · xml | **XXE** via `XmlDocument`/`XmlReader` DTD on | 611 | A03 | H | M | in-file |
| Search · query | SQLi via string-concat `SqlCommand` | 89 | A03 | H | E | in-file |
| Report · query | **Second-order** SQLi via stored name | 89 | A03 | H | H | cross-file |
| Comments · output | Stored XSS via `@Html.Raw(model.Body)` | 79 | A03 | M | E-M | cross-file |
| Search page · output | Reflected XSS via `@Html.Raw(Request.Query)` | 79 | A03 | M | E | in-file |
| Login `?returnUrl` | Open redirect (unvalidated `Redirect(returnUrl)`) | 601 | A01 | L | E | in-file |
| Fetch page | **SSRF** via `HttpClient.GetAsync(userUrl)` | 918 | A10 | H | M-H | cross-service |
| Export page | Command injection (`Process.Start` shell) | 78 | A03 | C | M | in-file |
| Download page | Path traversal (`Path.Combine` + `..`) | 22 | A01 | H | E-M | in-file |
| Post page · id | IDOR/BOLA - no owner/org check | 639/863 | A01 | H | E | in-file |
| Admin pages | Missing `[Authorize(Roles="Admin")]` | 862 | A01 | M | M | in-file |
| POST handlers | Missing `[ValidateAntiForgeryToken]` (CSRF) | 352 | A01 | M | M | in-file |
| JWT | `alg:none` accepted; lifetime unchecked | 347 | A07 | H | M | in-file |
| Login · rate | No rate limit → brute force | 307 | A07 | M | E | in-file |
| Login · enum | User enumeration + honeypot logic leak | 204 | A07 | L | E-M | in-file |
| Reset · token | Predictable reset token | 640/330 | A07 | M | M | cross-file |
| Cookie · flags | Auth cookie missing `HttpOnly`/`Secure`/`SameSite` | 614/1004 | A05 | M | E | in-file |
| CORS | `AllowAnyOrigin` + `AllowCredentials` (reflect) | 942 | A05 | M | M | in-file |
| Errors | **Developer Exception Page** on in prod | 209/489 | A05 | L | E | in-file |
| Config · secrets | Connection string / secrets in `appsettings.json` | 798 | A05 | M | E | config |
| Crypto · weak | MD5/static IV / ECB | 327 | A02 | M | M | in-file |
| Upload · type | Unrestricted `IFormFile` (no content check) | 434 | A03 | M | M | in-file |
| Profile · role | Priv-esc via posted `Role` field | 269 | A01 | H | M | in-file |
| Billing · seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| Invite · seats | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| Seed data | Default `admin/admin` service creds | 798 | A07 | M | E | config |

## Stack-specific highlights (only make sense in ASP.NET)

- **Overposting** - a Razor Page binds the whole `User` entity, so a form that
  posts `User.IsAdmin=true` (a field never rendered) elevates the account. The
  canonical .NET mass-assignment bug. Near-miss binds a view-model with only
  `DisplayName`/`Bio`.
- **`BinaryFormatter` / Json.NET `TypeNameHandling.All`** - both instantiate
  attacker-chosen types on deserialize (RCE). Near-miss uses
  `System.Text.Json` with a fixed DTO.
- **XXE via `XmlDocument`** - pre-.NET-4.5.2 defaults / explicitly enabled DTD;
  external entity read. Near-miss sets `XmlResolver = null` +
  `DtdProcessing.Prohibit`.
- **`@Html.Raw`** - Razor auto-encodes by default, so `@Html.Raw(userInput)` is
  a deliberate bypass (XSS). Near-miss just renders `@model.Body`.
- **Developer Exception Page in prod** - `app.UseDeveloperExceptionPage()`
  unconditionally (not gated on `IsDevelopment()`); leaks stack traces,
  connection strings, and source snippets. Near-miss gates it on environment.

## Near-misses (safe beside vulnerable)

- `OnPost` binding the entity beside one binding a scoped view-model.
- string-concat `SqlCommand` beside `cmd.Parameters.AddWithValue`.
- `@Html.Raw(model.Body)` beside `@model.Body`.
- `BinaryFormatter` import beside a `System.Text.Json` typed import.

## Logic-only bugs

- **Invite race (CWE-362):** seat check + insert without a transaction/lock;
  parallel PoC beats the limit.
- **Billing (CWE-840):** negative/huge seat value accepted.
- **Honeypot leak (bonus):** the hidden `Website` honeypot's server behavior is
  observable (distinct timing/response), a logic tell.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs (`overpost.sh` posts
  `User.IsAdmin=true`; `binfmt_deser.sh` uploads a serialized payload;
  `typename_deser.sh` posts a `$type` JSON; `xxe.sh`; `race_invite.sh`). PASS on
  `main-vuln`, FAIL on `main-safe`.
- Scorer → P/R/F1 + per-CWE. `ground-truth/` `.dockerignore`d.

## Patched twin (`main-safe`)

Scoped view-models (no overposting), `System.Text.Json` typed imports, XXE-hard
`XmlReader` (`XmlResolver=null`, `DtdProcessing.Prohibit`), parameterized
`SqlCommand`, escaped Razor output, `LocalRedirect`/allowlist, SSRF allowlist +
metadata block, `Process.Start` arg list, containment-checked downloads,
owner/org checks, `[Authorize(Roles="Admin")]`, `[ValidateAntiForgeryToken]` on
all POSTs, verified JWT + strong key, rate limit, generic auth errors, random
reset tokens, `HttpOnly`+`Secure`+`SameSite` cookies, scoped CORS,
environment-gated exception page, secrets via env/user-secrets, AES-GCM crypto,
content-checked uploads, no role self-set, validated billing, locked seat
reservation.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-aspnet
services:
  app:
    build: ./app
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:8080"]
    environment:
      ConnectionStrings__Default: "Server=sqlserver;Database=bench;User Id=sa;Password=Bench12345!;TrustServerCertificate=True"
      ASPNETCORE_ENVIRONMENT: "Production"     # but dev exception page is on anyway (planted)
      SMTP_HOST: mailpit
      JWT_SECRET: "hardcoded-weak-secret"       # planted CWE-798
      APP_URL: http://localhost:13311
    volumes: [uploads:/data/uploads]
    depends_on: { sqlserver: { condition: service_healthy } }
  sqlserver:
    image: mcr.microsoft.com/mssql/server:2022-latest
    environment:
      ACCEPT_EULA: "Y"
      MSSQL_SA_PASSWORD: "Bench12345!"          # planted weak/hardcoded cred
      MSSQL_PID: Developer
    ports: ["127.0.0.1:${DYNAST_PORT_SQLSERVER_1433:-13312}:1433"]
    healthcheck:
      test: ["CMD-SHELL", "/opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -P 'Bench12345!' -Q 'SELECT 1' || exit 1"]
      start_period: 60s
  mailpit:
    image: axllent/mailpit:v1.20
    ports: ["127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13313}:8025", "127.0.0.1:${DYNAST_PORT_MAILPIT_1025:-13314}:1025"]
volumes: { uploads: {} }
```

## Build milestones

1. Compose boots; startup migration/seed loop (cross-tenant + weak creds) makes
   SQL Server ready; Makefile.
2. Signup (CAPTCHA + honeypot) + cookie auth + role claims; plant JWT alg:none,
   rate-limit, enumeration, weak reset token + safe twins; cookie-flag bug.
3. Posts CRUD + IDOR + string-concat SQLi (+ near-miss); `@Html.Raw` XSS.
4. Overposting binding; `BinaryFormatter` + `TypeNameHandling` imports; XXE;
   `HttpClient` SSRF; `Process.Start` export; report second-order SQLi - each +
   safe twin.
5. Billing/invite logic bugs; returnUrl redirect / CORS / dev-exception-page /
   traversal / upload misconfigs.
6. `/api/_verify/*` + `VULNERABILITIES.yaml` + `verify/` PoCs; all PASS on
   `main-vuln`; branch `main-safe`, fix all, all PoCs FAIL; wire scorer.
