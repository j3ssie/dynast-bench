# `safe/` - the patched twin

A **line-for-line mirror of `vuln/`** with every planted bug fixed and **nothing
else changed** (parameterized queries, escaped output, added authz checks, safe
deserializers, SSRF allowlists, …).

- `diff -ru ../vuln ../safe` **is the ground truth** - it must touch only the
  files/lines named in `../ground-truth/VULNERABILITIES.yaml`.
- Scanning this variant (`make safe`) measures a tool's **false-positive rate**:
  every finding here is a false alarm, because the twin is clean by construction.
- Every `../ground-truth/verify/` PoC must **FAIL** against this variant (and
  PASS against `vuln/`).
