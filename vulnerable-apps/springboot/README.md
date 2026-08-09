# Spring Boot vulnerable benchmark app

⚠️ **Intentionally vulnerable. Local only. Do not deploy.**

Spring Boot 3.3 / Java 21 benchmark target implementing a representative subset
from `benchmark-plans/springboot.md`: SpEL, Actuator exposure, Java
serialization, XXE, Spring Security matcher/auth mistakes, CSRF, JWT/reset/enum
/rate bugs, IDOR/BFLA/mass assignment, native SQLi and second-order SQLi, SSRF,
command injection, Thymeleaf XSS/template injection, CORS, traversal, secrets,
verbose errors, race/logic bugs, and Jenkins/Prometheus side-surfaces.

All published ports bind to `127.0.0.1`. `ground-truth/` is outside Docker build
contexts.

Seed users: `admin@bench.local/Admin123!`, `editor@bench.local/Editor123!`,
`user1@bench.local/User123!`, `user2@bench.local/User123!`, plus weak service
credential marker `admin/admin`.
