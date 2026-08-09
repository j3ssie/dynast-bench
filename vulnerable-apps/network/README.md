# Network range vulnerable app

## Intentionally vulnerable. Local only.

This app is a simulated network-range benchmark for DAST/network scanners. It
creates a lightweight fleet of simulated edge, app, data, and management hosts.
The vulnerable variant intentionally exposes weak TLS/status endpoints,
segmentation breaks, default credentials, no-auth datastores, a rogue port,
telnet, SNMP, insecure headers, and seeded marker leakage.

Do not expose this benchmark to a public network. Every host-published port in
`docker-compose.yml` is bound to `127.0.0.1`; the full scan surface is intended
to be probed from the in-bridge `scanner` / `netmeta` API at
`http://127.0.0.1:13311`.

## Run

```bash
make up          # vulnerable fleet
make verify      # all PoCs should be exploitable
make safe        # hardened twin
make verify-safe # all PoCs should be fixed
make config-check
make solo        # standalone loopback-alias simulation
```

`ground-truth/` is outside the Docker build contexts. The app uses lightweight
Node-based protocol simulators instead of pulling the full upstream fleet, while
preserving meaningful protocol handshakes and network/topology assertions for the
benchmark.
