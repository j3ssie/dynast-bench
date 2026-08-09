# llmagent - intentionally vulnerable LLM-agent benchmark app

This app is intentionally vulnerable and must only bind to `127.0.0.1`. It models an Ops Copilot with deterministic `LLM_BACKEND=stub` tool calls, MCP-like tool metadata, run transcripts, memory, approvals, and agent-side effects.

Default verification uses the stub backend and does not require real model credentials or public egress.

## Run

```bash
make up APP=llmagent
make verify APP=llmagent
make safe APP=llmagent
make verify-safe APP=llmagent
```

Do not expose this app to a public network. Vulnerabilities are the product; fixes live only in `safe/`.
