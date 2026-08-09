# `expected/` - golden normalized findings

Two hand-maintained `findings/v1` files with the exact scores they must produce.
`dynast-bench/test/fixtures.test.ts` asserts those numbers, so a change in how the
scorer grades fails a test instead of silently moving every tool's results.

| File | What it is | Must score |
|------|------------|------------|
| `perfect.json` | a tool that reports precisely what the answer key says | recall 1.0 · precision 1.0 · discrimination 1.0 |
| `sloppy.json` | one finding per scoring rule, including the traps | 4 tp · 2 duplicates · 3 fp (1 near-miss) · 1 informational |

```bash
dynast-bench score nextjs ground-truth/expected/perfect.json --full
dynast-bench score nextjs ground-truth/expected/sloppy.json --full
```

`sloppy.json` is the more useful one to read: each finding is commented with the
rule it exercises.

| Finding | Rule |
|---------|------|
| `s-01` | a seed marker in `evidence.markers` is proof - matches at tier `proof` |
| `s-02`, `s-03` | more payloads on the same bug are **noise**, not false positives |
| `s-04` | a sibling CWE (`CWE-862` for `CWE-639`) still finds the bug, at half credit |
| `s-05` | a generic CWE (`CWE-20`) still finds it, at quarter credit |
| `s-06` | a source finding inside the bug's own line range matches at tier `source` |
| `s-07` | right route, unrelated CWE - a positive claim that is wrong, so a false positive |
| `s-08` | flagging a **near-miss** (`/api/preview-internal`) is the discrimination penalty |
| `s-09` | an invented route is a plain false positive |
| `s-10` | a port reported **closed** is an observation, not scored either way |

These are `nextjs`-only on purpose: it is the reference app. Other apps are covered
generatively by `dynast-bench/test/apps.test.ts`, which builds a synthetic perfect /
DAST-only / SAST-only tool from each answer key and asserts the invariants, so no
per-app fixture can go stale.

Nothing here is baked into an image - `expected/` sits under `ground-truth/`, outside
both build contexts.
