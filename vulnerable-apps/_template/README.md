# App template

> ⚠️ **Intentionally vulnerable. Local only.** Copy this folder to
> `vulnerable-apps/<stack>/` to start a new app. Fill in `vuln/`, mirror it into `safe/`
> with every planted bug fixed, and record each bug in
> `ground-truth/VULNERABILITIES.yaml`.

## What goes where

| Path | Purpose |
|------|---------|
| `vuln/` | The vulnerable variant. Its `docker-compose.yml` build context is this folder, so the app's `../ground-truth/` can never be baked into the image. |
| `vuln/Dockerfile` | App-only image, used by `docker-compose.yml` (needs the datastore services). |
| `vuln/Dockerfile.standalone` | All-in-one image: embeds the datastores + an internal SSRF sink so the app runs from ONE image with no compose (`make solo`). Aliases the compose service names to `127.0.0.1` so behaviour + PoCs are identical. |
| `safe/` | The patched twin - a copy of `vuln/` with only the planted bugs fixed. `diff -ru vuln safe` must equal the ground truth. |
| `ground-truth/VULNERABILITIES.yaml` | One entry per planted bug (schema below). |
| `ground-truth/verify/` | One runnable PoC per bug - exit `0` against `vuln/`, non-zero against `safe/`. |
| `ground-truth/run.sh` | Runs all PoCs against `$TARGET`; `expect-vuln` (all exploitable) or `expect-safe` (all fixed). |
| `ground-truth/expected/` | Optional golden `findings/v1` files with the exact scores they must produce (see `vulnerable-apps/nextjs/ground-truth/expected/`). |
| `Makefile` | The uniform interface: `up · reset · safe · verify · validate · solo · diff · score · check`. |

## Invariants (enforced in CI)

1. `diff -ru vuln safe` touches **only** files/lines named in
   `VULNERABILITIES.yaml`.
2. Every `verify/` PoC PASSes against `vuln/` and FAILs against `safe/`.
3. `VULNERABILITIES.yaml` validates against `dynast-bench/src/schema`, and every entry
   carries a generated `match:` block - run
   `bun dynast-bench/tools/derive-match.ts <app> --write`, then `dynast-bench check <app>`.
4. Every planted bug has a `near_miss` - safe code of the same shape nearby -
   so the benchmark rewards discrimination, not pattern-matching.
5. The compose file binds host ports to `127.0.0.1` only.

## Workflow

```bash
cp -r vulnerable-apps/_template vulnerable-apps/<stack>       # start
# build vuln/, then copy to safe/ and fix the bugs
make up && make verify                   # all PoCs PASS on vuln/
make safe && make verify                 # all PoCs FAIL on safe/  (twin is clean)
make check                               # the answer key is scoreable
make score FINDINGS=out.json             # grade a scanner against it
```
