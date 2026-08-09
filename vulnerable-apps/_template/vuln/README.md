# `vuln/` - the vulnerable variant

The app **with every planted bug**. This is the default target (`make up`) and
what a scanner or agent points at.

- `docker-compose.yml` - independent compose project; bind host ports to
  `127.0.0.1` only. Its **build context is this folder**, so `../ground-truth/`
  is structurally excluded from any image.
- `app/` - application source. Each planted bug is recorded in
  `../ground-truth/VULNERABILITIES.yaml`, and each has a safe-shaped **near-miss**
  nearby (also recorded) so the benchmark rewards discrimination.
- `db/seed.sql` - seed data including a **cross-tenant user** (for IDOR PoCs) and
  a **weak default credential**.

Keep `safe/` a line-for-line mirror of this folder with **only** the planted
bugs fixed - `diff -ru ../vuln ../safe` is the ground truth.
