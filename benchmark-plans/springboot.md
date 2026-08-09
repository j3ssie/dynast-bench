# Spring Boot Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **enterprise-Java** app. Signature bugs are the ones that define
Spring CVEs: **SpEL injection**, **exposed Actuator endpoints**
(`/actuator/env`, `/heapdump`, `/mappings`), **Java deserialization**, **XXE**,
JPQL/native SQLi, and **Spring Security matcher misconfiguration**. Jenkins is in
the compose as an extra attack surface (script console / weak creds); Prometheus
scrapes Actuator.

## Services (4 containers) - independent `docker-compose.yml`

| Service    | Image                        | Host port | Purpose                       |
|------------|------------------------------|-----------|-------------------------------|
| app        | build ./app (temurin:21)     | 3000      | Spring Boot + Thymeleaf SSR   |
| postgres   | postgres:16.4                | 5432      | Data                          |
| jenkins    | jenkins/jenkins:2.462.3-lts  | 8080      | CI surface (weak creds)       |
| prometheus | prom/prometheus:v2.54.1      | 9090      | Scrapes Actuator metrics      |

## Stack choices (bugs live inside these idioms)

- **Spring Boot 3.3** + **Spring Security** + **Thymeleaf** + **Spring Data JPA**
  + **Flyway** migrations & seed
- Auth: `BCryptPasswordEncoder`; a **`SecurityFilterChain`** with a deliberately
  wrong matcher ordering (admin routes fall through to `permitAll`); a JWT
  filter (`jjwt`) accepting `alg:none`
- Data: mostly JPA, but the search/report repos use string-concatenated JPQL /
  native `@Query` (SQLi)
- Actuator: `management.endpoints.web.exposure.include=*` and
  `management.endpoint.env.show-values=ALWAYS` (secrets + heapdump exposed)
- Features: a report engine that evaluates a **SpEL** expression from user input
  (`SpelExpressionParser().parseExpression(userStr).getValue()`), an XML import
  (XXE), a "restore" import (`ObjectInputStream` - Java deser), and a
  `RestTemplate` "fetch" (SSRF)
- CSRF: disabled globally (`http.csrf(csrf -> csrf.disable())`)

## Domain model

Standard shared domain, cross-tenant `user2` (org Globex) for IDOR PoCs.

## Vulnerability catalog (~30 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · report engine | **SpEL injection** from user string | 917/94 | A03 | C | H | cross-file |
| app · Actuator | `/actuator/env`,`/heapdump`,`/mappings` exposed | 200/489 | A05 | H | E | config |
| app · Actuator | `env` shows secret values (`show-values=ALWAYS`) | 200/798 | A02 | H | E-M | config |
| app · import (obj) | **Java deserialization** `ObjectInputStream` | 502 | A08 | C | H | in-file |
| app · import (xml) | **XXE** - `DocumentBuilderFactory` defaults | 611 | A03 | H | M | in-file |
| app · SecurityConfig | Matcher misorder → admin routes `permitAll` | 862/285 | A01 | H | M | in-file |
| app · SecurityConfig | CSRF disabled globally | 352 | A01 | M | E | in-file |
| app · JWT filter | `alg:none` accepted; `exp` unchecked | 347 | A07 | H | M | in-file |
| app · login | No rate limit → brute force | 307 | A07 | M | E | in-file |
| app · login | User enumeration (distinct messages) | 204 | A07 | L | E-M | in-file |
| app · reset | Predictable reset token | 640/330 | A07 | M | M | cross-file |
| app · posts/tasks | IDOR/BOLA - no org check | 639/863 | A01 | H | E-M | in-file |
| app · @ModelAttribute | Mass assignment binds `role`/`enabled` | 915 | A01 | M | M | in-file |
| app · /posts/search | SQLi via concatenated JPQL/native `@Query` | 89 | A03 | H | E-M | in-file |
| app · report query | **Second-order** SQLi via stored name | 89 | A03 | H | H | cross-file |
| app · fetch | **SSRF** via `RestTemplate` → internal/metadata | 918 | A10 | H | M-H | cross-service |
| app · export | Command injection (`Runtime.exec`/ProcessBuilder shell) | 78 | A03 | C | M | in-file |
| app · comments | Stored XSS via `th:utext` (unescaped) | 79 | A03 | M | E-M | cross-file |
| app · Thymeleaf | **Template injection** via fragment expr `~{__${..}__}` | 1336 | A03 | H | H | cross-file |
| app · search page | Reflected XSS (`th:utext` on param) | 79 | A03 | M | E | in-file |
| app · login `?next=` | Open redirect | 601 | A01 | L | E | in-file |
| app · CORS | `@CrossOrigin` reflects origin + credentials | 942 | A05 | M | M | in-file |
| app · attachments | Path traversal on download | 22 | A01 | M | M | in-file |
| app · config | Hardcoded secrets in `application.yml` | 798 | A05 | M | E | config |
| app · errors | Whitelabel/`server.error.include-stacktrace=always` | 209 | A05 | L | E | config |
| app · billing/seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| app · invites | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| app · deps | Outdated lib with a known CVE (pinned) | 1035 | A06 | M | E | config |
| jenkins | Weak admin creds / script console reachable | 798/94 | A05 | H | E-M | config |
| seed data | Default `admin/admin` service creds | 798 | A07 | M | E | config |

## Stack-specific highlights (only make sense in Spring/Java)

- **SpEL injection** - the report/rule engine does
  `parser.parseExpression(userInput).getValue(ctx)`. `T(java.lang.Runtime)
  .getRuntime().exec('id')` → RCE. Safe twin evaluates against a fixed,
  non-reflective expression or a whitelist of field names.
- **Actuator exposure** - `include=*` + `show-values=ALWAYS` turns
  `/actuator/env` and `/actuator/heapdump` into a secrets/credential dump; a
  DAST scanner that knows Spring will pull those. Safe twin exposes only
  `health`,`info` and never shows values.
- **`ObjectInputStream`** on an uploaded "session/report restore" blob - the
  canonical Java deser gadget sink. Safe twin uses JSON with a typed DTO.
- **XXE via `DocumentBuilderFactory`** with defaults (external entities on).
  Safe twin sets `disallow-doctype-decl` + disables external entities.
- **Thymeleaf `th:utext` + fragment-expression injection** - unescaped output
  (XSS) and the `~{__${...}__}` preprocessing sink (template injection). Safe
  twin uses `th:text` and never interpolates user data into expressions.
- **Spring Security matcher misorder** - a broad `requestMatchers("/**")
  .permitAll()` placed before the `/admin/**` rule, so admin auth never applies.

## Near-misses (safe beside vulnerable)

- `evalRule(spel)` (SpEL) beside `evalField(name)` (whitelist lookup).
- `searchPosts` (concat JPQL) beside `listPosts` (bound `:param`).
- `th:utext="${comment.body}"` beside `th:text="${post.title}"`.
- `importObject` (`ObjectInputStream`) beside `importJson` (Jackson typed DTO).

## Logic-only bugs

- **Invite race (CWE-362):** seat check + save not transactional / no
  `@Version`; parallel PoC beats the limit.
- **Billing (CWE-840):** negative/huge `seats` accepted.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs (`spel.sh` posts a SpEL payload;
  `actuator_env.sh` GETs `/actuator/env` and greps a secret; `java_deser.sh`
  uploads a serialized object; `xxe.sh`; `race_invite.sh`). PASS on `main-vuln`,
  FAIL on `main-safe`.
- Scorer → P/R/F1 + per-CWE. `ground-truth/` `.dockerignore`d.

## Patched twin (`main-safe`)

Whitelisted expression eval, Actuator locked to `health,info` + values hidden,
JSON import with typed DTO, XXE-hardened parsers, corrected matcher ordering,
CSRF on, verified JWT + strong secret, rate limit, constant-time login, random
reset tokens, org checks, explicit `@InitBinder` allowlist (no role binding),
bound JPQL params, SSRF allowlist + metadata block, `ProcessBuilder` arg list,
`th:text` escaping, redirect allowlist, scoped CORS, containment-checked
downloads, env secrets, stacktraces off, validated billing, `@Version`/locked
seat reservation, patched dep, Jenkins creds rotated + script console disabled.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-springboot
services:
  app:
    build: ./app
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:8080"]
    environment:
      SPRING_DATASOURCE_URL: jdbc:postgresql://postgres:5432/bench
      MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE: "*"        # planted CWE-489
      MANAGEMENT_ENDPOINT_ENV_SHOW_VALUES: "ALWAYS"          # planted CWE-200
      JWT_SECRET: "hardcoded-weak-secret"                     # planted CWE-798
    depends_on: { postgres: { condition: service_healthy } }
  postgres:
    image: postgres:16.4
    environment: { POSTGRES_USER: bench, POSTGRES_PASSWORD: bench, POSTGRES_DB: bench }
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  jenkins:
    image: jenkins/jenkins:2.462.3-lts
    environment: { JENKINS_ADMIN_PASSWORD: Admin123! }       # planted weak cred
    ports: ["127.0.0.1:${DYNAST_PORT_JENKINS_8080:-13312}:8080"]
  prometheus:
    image: prom/prometheus:v2.54.1
    volumes: ["./infra/prometheus.yml:/etc/prometheus/prometheus.yml:ro"]
    ports: ["127.0.0.1:${DYNAST_PORT_PROMETHEUS_9090:-13313}:9090"]
```

## Build milestones

1. Compose + healthchecks + Makefile; Flyway baseline + seed (cross-tenant +
   weak service cred).
2. Security config with the planted matcher-misorder / CSRF-off / JWT bugs +
   safe twins; Actuator exposure config.
3. Posts CRUD + IDOR + JPQL SQLi (+ near-miss); Thymeleaf `th:utext` XSS.
4. Report SpEL injection; second-order SQLi; `ObjectInputStream` import; XXE
   import; `RestTemplate` SSRF; shell export - each with a safe twin.
5. Billing/invite logic bugs; redirect/CORS/traversal/error/dep misconfigs;
   Jenkins surface.
6. `VULNERABILITIES.yaml` + `verify/` PoCs; all PASS on `main-vuln`; branch
   `main-safe`, fix all, all PoCs FAIL; wire scorer.
