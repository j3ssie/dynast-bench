# llmchat - intentionally vulnerable LLM/RAG app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real data,
> and plants LLM/RAG security vulnerabilities for benchmark tooling. Never deploy publicly.

**BenchAssist** is a small FastAPI support chatbot with deterministic `LLM_BACKEND=stub`
behavior by default. It implements a practical subset of the catalog in
`../../benchmark-plans/llmchat.md`: prompt injection channels, unsafe model-output
handling, cross-tenant RAG leaks, prompt-cache leakage, weak shares, quota/model
abuse, Ollama passthrough, pickle config loading, CORS/error/secret exposures, and
other LLM-specific plumbing bugs.

## Layout

```
llmchat/
├── vuln/          # vulnerable variant (Docker build context)
├── safe/          # patched twin - same files, YAML-named fix flags flipped
├── ground-truth/  # VULNERABILITIES.yaml + verify/ PoCs (never baked into images)
└── Makefile       # up · reset · safe · verify · validate · solo · diff
```

## Run

```bash
make up          # build + start vuln/ on http://127.0.0.1:13311
make verify      # run all 30 PoCs; expect ALL exploitable
make safe        # switch to patched twin
make verify-safe # run all 30 PoCs; expect ALL fixed
make diff        # show vuln ↔ safe ground-truth diff
```

The default compose and standalone images use `LLM_BACKEND=stub`; no API key or
network model pull is required. Docker ports are bound to `127.0.0.1` only.

## Status

Created as a representative LLM/RAG benchmark implementation with 30 PoCs. It was
syntax-checked locally; full Docker validation was intentionally not run on the
default port per task instruction.
