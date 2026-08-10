# Spring Boot vulnerable benchmark app

⚠️ **Intentionally vulnerable. Local only. Do not deploy.**

Spring Boot 3.3 / Java 21 benchmark target implementing a representative subset
from `benchmark-plans/springboot.md`: SpEL, Actuator exposure, Java
serialization, XXE, Spring Security matcher/auth mistakes, CSRF, JWT/reset/enum
/rate bugs, IDOR/BFLA/mass assignment, native SQLi and second-order SQLi, SSRF,
command injection, Thymeleaf XSS/template injection, CORS, traversal, secrets,
verbose errors, race/logic bugs, and Jenkins/Prometheus side-surfaces.

**Two research-grade classes.** `PREAUTH-BYPASS-001` (CWE-863): a Spring `@PreAuthorize` admin method reached by *self-invocation* from a public wrapper in the same bean - the AOP proxy never intercepts it, so `/api/reports/admin-export` leaks the admin secret pre-auth. `JACKSON-DESER-001` (CWE-502): Jackson *polymorphic deserialization* (default typing) at `/api/import/typed` lets JSON name the concrete class and instantiate a shipped gadget -> RCE; distinct from the native `ObjectInputStream` deser.

**Spring/Tomcat path-traversal bypasses.** `GET /api/docs/read` and
`/api/docs/list` guard their path with a blacklist that a competent tool defeats
with stack-signature payloads: the matrix-parameter `..;/`, double URL-encoding
`%252e%252e%252f`, and the double-encoded hash `%2523` (which slips past the block
a bare `%23`/`#` trips). The blacklist runs *before* normalisation and a `cleanup()`
step strips `;`-params and decodes a second time, so all three escape `DOCS_BASE` -
reading `/etc/passwd` (`TRAVERSAL-BYPASS-001`, CWE-22) and enumerating arbitrary
directories (`DIRLIST-001`, CWE-548). The `read-safe` sibling resolves identically
then enforces `startsWith(DOCS_BASE)` containment and is the near-miss.

**Agent-only surface (deep hardening).** On top of that catalog it plants an
8-bug surface a request fuzzer cannot reach - only an agent that behaves like a
user: a **four-step signup wizard** at `/signup` (client-driven fetch to
`/api/signup/*`) with four `flow`-tier bugs (clock-derived verification code,
`role`/`org_slug` mass-assignment, complete-without-verify, draft-IDOR leaking
another signup's email + code), two browser-only bugs on the wizard page (**DOM
XSS** via `location.hash`, a **postMessage** sink), and a hidden **config-dump**
endpoint (`CONFIGDUMP`, CWE-200 - returns `System.getenv()` including
`SPRINGBOOT_ACTUATOR_SECRET`) referenced only from the panel the wizard fetches
after an **Advanced** click. Those 8 are tiered `flow`/`interaction`/`js-runtime`;
the pre-existing catalog stays `static-html`, so `recall by discovery tier` shows
how far past the fuzzable surface a tool gets. Browser PoCs drive the shared
`dynast-bench/tools/browser/` image.

All published ports bind to `127.0.0.1`. `ground-truth/` is outside Docker build
contexts.

Seed users: `admin@bench.local/Admin123!`, `editor@bench.local/Editor123!`,
`user1@bench.local/User123!`, `user2@bench.local/User123!`, plus weak service
credential marker `admin/admin`.
