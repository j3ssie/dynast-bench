# JSP / Servlet Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **classic-Java-monolith** app - a WAR on Tomcat, JSP + Servlets,
JDBC with hand-written SQL, an auth `Filter`. Signature bugs are the Java-web
classics: **JSP scriptlet XSS** (`<%= request.getParameter(...) %>`),
**arbitrary `.jsp` upload → webshell RCE**, **Java deserialization** of a
cookie/param, **XXE via `DocumentBuilderFactory`**, and an **AuthFilter
path-prefix bypass** that abuses Tomcat's `;`/`..`/case quirks.

## Services (4 containers) - independent `docker-compose.yml`

| Service  | Image                           | Host port  | Purpose             |
|----------|---------------------------------|------------|---------------------|
| app      | build ./app → tomcat:10.1-jre21 | 3000       | The WAR monolith    |
| postgres | postgres:16.4                   | 5432       | Data                |
| mailpit  | axllent/mailpit:v1.20           | 8025 (1025)| Verification emails |

## Structure

```
src/main/webapp/          *.jsp views + WEB-INF/web.xml
src/main/java/bench/
  web/    SignupServlet, LoginServlet, PostServlet, SearchServlet,
          AdminServlet, UploadServlet, DownloadServlet, ImportServlet,
          FetchServlet, ReportServlet, CaptchaServlet, VerifyApiServlet
  filter/ AuthFilter (role checks by path prefix), CharsetFilter
  db/     Db.java (HikariCP), plain JDBC DAOs (hand-written SQL)
```

- **Jakarta** namespace throughout (Tomcat 10); JSTL 3.0
- Auth: **jBCrypt** + `HttpSession`; a JWT path (custom/`jjwt`) accepting
  `alg:none`; `HttpSession` **not** rotated on login (fixation)
- DB: `Statement` string-concat in the planted SQLi sites, `PreparedStatement`
  in the near-misses
- Uploads: `@MultipartConfig` servlet writes into a servable directory (webshell)
- Features: XML import (XXE), object import (`ObjectInputStream`), URL fetch
  (SSRF), report render (EL/expression injection)

## Domain model

Standard shared domain, cross-tenant `user2` (org Globex) for IDOR PoCs.

## Vulnerability catalog (~29 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| *.jsp · output | **Scriptlet XSS** `<%= request.getParameter() %>` | 79 | A03 | M | E | in-file |
| UploadServlet | **`.jsp` webshell upload** → RCE | 434 | A03 | C | M | in-file |
| ImportServlet · obj | **Java deserialization** `ObjectInputStream` on param/cookie | 502 | A08 | C | H | in-file |
| ImportServlet · xml | **XXE** `DocumentBuilderFactory` defaults | 611 | A03 | H | M | in-file |
| AuthFilter | **Path-prefix bypass** (`/admin/..;/`, case, `;jsessionid`) | 288/862 | A01 | H | H | in-file |
| SearchServlet | SQLi via `Statement` string concat | 89 | A03 | H | E | in-file |
| ReportServlet | **Second-order** SQLi via stored title | 89 | A03 | H | H | cross-file |
| ReportServlet · EL | Expression/template injection into JSP EL | 917/1336 | A03 | H | H | cross-file |
| FetchServlet | **SSRF** via `URL.openConnection` → metadata | 918 | A10 | H | M-H | cross-service |
| ExportServlet | Command injection `Runtime.exec` | 78 | A03 | C | M | in-file |
| DownloadServlet | Path traversal (`new File(dir, param)`) | 22 | A01 | H | E-M | in-file |
| PostServlet · id | IDOR/BOLA - no owner/org check | 639/863 | A01 | H | E | in-file |
| AdminServlet | Missing function-level authz | 862 | A01 | M | M | in-file |
| ProfileServlet · role | Mass assignment / priv-esc via `role` param | 915/269 | A01 | H | M | in-file |
| LoginServlet · session | Session fixation (no rotate on login) | 384 | A07 | M | M | in-file |
| JWT filter | `alg:none` accepted; `exp` unchecked | 347 | A07 | H | M | in-file |
| LoginServlet · rate | No rate limit → brute force | 307 | A07 | M | E | in-file |
| LoginServlet · enum | User enumeration (distinct messages) | 204 | A07 | L | E-M | in-file |
| auth · reset token | Predictable reset token (`Random`/timestamp) | 640/330 | A07 | M | M | cross-file |
| comments · output | Stored XSS (unescaped `<c:out escapeXml=false>`) | 79 | A03 | M | E-M | cross-file |
| LoginServlet · `next` | Open redirect (`sendRedirect(param)`) | 601 | A01 | L | E | in-file |
| Db.java · creds | Hardcoded DB creds in source | 798 | A05 | M | E | in-file |
| web.xml · errors | Stack traces / default Tomcat error pages | 209 | A05 | L | E | config |
| Tomcat · manager | `/manager`/`/host-manager` reachable w/ weak creds | 798 | A05 | H | E-M | config |
| CharsetFilter · XFF | Trusts `X-Forwarded-For` for authz/logging | 290 | A07 | M | M | in-file |
| crypto · weak | DES/ECB, static key | 327 | A02 | M | M | in-file |
| billing · seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| invite · seats | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| CaptchaServlet · seed | Predictable CAPTCHA (fixed `Random` seed) | 330 | A07 | L | M | in-file |

## Stack-specific highlights (only make sense in JSP/Tomcat)

- **Scriptlet XSS** - a JSP prints `<%= request.getParameter("q") %>` directly;
  no EL escaping applies to raw scriptlets. Near-miss uses `<c:out value="${q}">`
  (escapes by default).
- **`.jsp` webshell upload** - the upload servlet writes the file under a
  directory Tomcat serves and executes as JSP; uploading `x.jsp` yields RCE.
  Near-miss stores outside the webapp with a random name + content check.
- **`ObjectInputStream`** on a base64 cookie/param - the canonical Java deser
  RCE sink (ysoserial gadgets). Near-miss uses JSON with a typed DTO.
- **XXE via `DocumentBuilderFactory`** with defaults on - external entities +
  DTD load. Near-miss sets `disallow-doctype-decl`.
- **AuthFilter path-prefix bypass** - the filter checks
  `path.startsWith("/admin")`, but Tomcat normalizes `/admin/..;/users`,
  `/Admin`, and `;jsessionid=` path params *after* the filter, so a crafted URL
  slips past the gate. Uniquely a servlet-container quirk. Near-miss canonicalizes
  first and matches on the servlet mapping, not the raw URI.

## Near-misses (safe beside vulnerable)

- `<%= request.getParameter() %>` beside `<c:out value="${param.q}"/>`.
- `Statement` concat beside `PreparedStatement` with `?`.
- `ObjectInputStream` import beside a Jackson typed import.
- `path.startsWith("/admin")` filter beside a canonicalized, mapping-based check.

## Logic-only bugs

- **Invite race (CWE-362):** DAO seat read + insert without a transaction/lock;
  parallel PoC beats the limit.
- **Billing (CWE-840):** negative/huge seat value accepted.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs (`jsp_shell.sh` uploads +
  requests a `.jsp`; `filter_bypass.sh` hits `/admin/..;/users`;
  `java_deser.sh`; `xxe.sh`; `race_invite.sh`). PASS on `main-vuln`, FAIL on
  `main-safe`.
- Scorer → P/R/F1 + per-CWE. `ground-truth/` `.dockerignore`d.

## Patched twin (`main-safe`)

`<c:out>` escaping, upload stored out-of-webapp + content-typed + random name,
JSON import (no `ObjectInputStream`), XXE-hardened parsers, canonicalized
mapping-based auth filter, `PreparedStatement` params, EL injection removed,
SSRF allowlist + metadata block, `ProcessBuilder` arg list, containment-checked
downloads, owner/org checks, role checks, no self-escalation, session rotation
on login, verified JWT + strong secret, rate limit, generic auth errors, random
reset tokens, redirect allowlist, env DB creds, custom error pages, Tomcat
manager removed, XFF ignored for authz, AES-GCM crypto, validated billing,
locked seat reservation, random CAPTCHA seed.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-jsp
services:
  app:
    build: ./app
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:8080"]
    environment:
      DB_URL: jdbc:postgresql://postgres:5432/bench
      SMTP_HOST: mailpit
      CAPTCHA_MODE: image
      CAPTCHA_SEED: "42"          # planted CWE-330
      TOMCAT_MANAGER_ENABLED: "true"   # planted CWE-798 surface
      APP_URL: http://localhost:13311
    volumes: [uploads:/usr/local/tomcat/webapps/ROOT/uploads]  # planted: servable upload dir
    depends_on: { postgres: { condition: service_healthy } }
  postgres:
    image: postgres:16.4
    environment: { POSTGRES_USER: bench, POSTGRES_PASSWORD: bench, POSTGRES_DB: bench }
    volumes: ["./db/init:/docker-entrypoint-initdb.d:ro"]
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  mailpit:
    image: axllent/mailpit:v1.20
    ports: ["127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13312}:8025", "127.0.0.1:${DYNAST_PORT_MAILPIT_1025:-13313}:1025"]
volumes: { uploads: {} }
```

## Build milestones

1. Multi-stage build boots `ROOT.war` on Tomcat; init SQL (cross-tenant + weak
   creds) green; Makefile.
2. Auth servlets + AuthFilter + sessions; plant filter bypass, fixation, JWT
   alg:none, weak reset token + safe twins.
3. Posts CRUD + IDOR + `Statement` SQLi (+ near-miss); JSP scriptlet + `c:out`
   XSS.
4. UploadServlet webshell; ImportServlet deser/XXE; FetchServlet SSRF;
   ExportServlet cmd injection; ReportServlet EL injection - each + safe twin.
5. Billing/invite logic bugs; traversal/redirect/error/manager/XFF misconfigs;
   CAPTCHA seed.
6. VerifyApiServlet + `VULNERABILITIES.yaml` + `verify/` PoCs; all PASS on
   `main-vuln`; branch `main-safe`, fix all, all PoCs FAIL; wire scorer.
