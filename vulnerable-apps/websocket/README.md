# websocket - intentionally vulnerable realtime benchmark app

> WARNING: This app intentionally contains exploitable WebSocket, Socket.IO, and HTTP security bugs. Run it only on `127.0.0.1` for DAST/SAST/LLM security-tool benchmarking.

This app implements the WebSocket/realtime catalog from `benchmark-plans/websocket.md` as a compact Node 22 service:

- raw `ws` JSON protocol on `/ws` plus a near-miss `/ws/secure`
- Socket.IO Engine.IO polling/WebSocket path on `/socket.io` with `/rt` and `/admin` namespaces
- tiny HTTP surface for login, health, transcripts, and harness-only verify helpers
- shared seed domain: Acme/Globex tenants, users, weak `admin/admin`, and the Globex draft marker `GLOBEX-CONFIDENTIAL-MARKER-7f3a`

## Local commands

```bash
make up        # vulnerable twin via compose, bound to http://127.0.0.1:13311
make verify    # all ground-truth PoCs must be exploitable
make safe      # patched twin on the same local port
make verify-safe
make solo      # single-image variant, no compose
```

The `ground-truth/` directory is outside both Docker build contexts and is not copied into images.
