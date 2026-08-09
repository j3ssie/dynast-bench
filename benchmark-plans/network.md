# Network-Range / Multi-Service Version - Vulnerable Network Plan

> ⚠️ **Intentionally vulnerable. Local only.** This app stands up a *simulated*
> network of many hosts and open ports. The "network" is a **private, non-routed
> Docker bridge** - every host-facing port still binds `127.0.0.1`, and the whole
> range is only reachable from a scanner container placed **inside** the bridge.
> Ships a LOUD banner, carries no real data. **Never attach this bridge to a
> physical NIC, and never expose any of these ports to `0.0.0.0` or a real
> network.** Built to benchmark network scanners (nmap, masscan, Nessus/OpenVAS,
> default-cred and TLS auditors, and LLM recon agents).

**Angle:** the **network-scanning** app. Every other app in the suite is one
service graded by a web/API scanner; this one is a *fleet* - ~18 containers
across four simulated network segments, exposing ~30 ports of real third-party
services (SSH, FTP, SMTP, Redis, Mongo, Elasticsearch, Postgres, MySQL,
Memcached, RabbitMQ, Jenkins, Grafana, phpMyAdmin, MinIO, SNMP), each with a
documented network-level exposure. The point of discrimination is different from
the source-level apps:

- a **host-discovery + port scan** has to enumerate the range and find every
  *open* port (recall) without inventing *filtered/closed* ones (precision),
- **service/version fingerprinting** has to read banners and map old versions to
  CVEs,
- **default-cred / no-auth / anonymous** checks have to actually authenticate,
- **TLS auditing** has to spot expired certs, `TLSv1.0`/`SSLv3`, and weak ciphers,
- and the **segmentation** bugs (a data-tier service reachable from the edge)
  reward a scanner that reasons about *reachability between segments*, not just
  open ports on one host.

Right beside each broken service sits a **hardened twin** on an adjacent
host/port (an authed Redis, a modern-TLS vhost, a key-only SSH) - flagging it is
a false positive, which is what separates a real network scanner from
`nmap -p- | grep open`.

## Simulated topology - four segments on one private bridge

The Docker network is a `/16` split into four `/24` segments. The **scanner**
container is the tool-under-test's vantage point; where it is *placed* changes
what it can reach, and the segmentation bugs live in exactly that gap.

| Segment | Subnet         | Role (simulated)          | Should be reachable from | Contains |
|---------|----------------|---------------------------|--------------------------|----------|
| edge    | 10.89.1.0/24   | Internet-facing DMZ       | scanner (untrusted)      | proxy, bastion, ftp, mail |
| app     | 10.89.2.0/24   | Application tier          | edge only                | web, legacy |
| data    | 10.89.3.0/24   | Datastore tier            | app only (**never edge**)| postgres, redis(+secure), mongo, elastic, memcached |
| mgmt    | 10.89.4.0/24   | Ops / management          | mgmt only (jump host)    | jenkins, grafana, rabbitmq, phpmyadmin, minio, snmp |

The **vuln** variant flattens these ACLs (everything reaches everything - the
segmentation is the headline bug); the **safe** variant enforces them with
per-segment Docker networks + an edge proxy that only forwards allowlisted paths.

## Host & port map (the scan target)

Representative, not exhaustive - the built app's `expected-ports.yaml` is the
authoritative list. Ports below are the **in-bridge** service ports; a curated
subset is also mapped to `127.0.0.1:<port>` for host-run scanners.

| Host (segment)          | Port(s)        | Service (image)                        | Exposure |
|-------------------------|----------------|----------------------------------------|----------|
| edge-proxy (edge)       | 80, 443, 8443  | nginx                                  | expired self-signed + `TLSv1.0`/weak ciphers on 443; `/nginx_status` open; proxies `/internal/*` → data tier |
| edge-bastion (edge)     | 22             | openssh-server                         | password auth on, root login on, weak cred, old banner |
| edge-ftp (edge)         | 21, 30000-30009| pure-ftpd                              | anonymous read/write, cleartext |
| edge-mail (edge)        | 25             | postfix                                | open relay, no STARTTLS |
| app-web (app)           | 8080, **31337**| the suite web app + a rogue bind shell | unexpected high port = planted backdoor |
| app-legacy (app)        | 23, 8000       | busybox telnetd + old httpd            | cleartext telnet admin; banner advertises a CVE'd version |
| data-postgres (data)    | 5432           | postgres:16                            | `trust`/weak auth, `listen_addresses='*'` |
| data-redis (data)       | 6379           | redis:7                                | **no auth** (the classic) |
| data-redis-secure (data)| 6380           | redis:7                                | **hardened near-miss** - `requirepass`, internal-only |
| data-mongo (data)       | 27017          | mongo:7                                | no auth |
| data-elastic (data)     | 9200, 9300     | elasticsearch:8                        | security disabled, no TLS |
| data-memcached (data)   | 11211          | memcached                              | no auth; UDP amplification |
| mgmt-jenkins (mgmt)     | 8080           | jenkins/jenkins:lts                    | anon read, `/script` console reachable |
| mgmt-grafana (mgmt)     | 3000           | grafana:11                             | default `admin/Admin123!`, anon view on |
| mgmt-rabbitmq (mgmt)    | 5672, 15672    | rabbitmq:3-management                  | default `guest/guest`, mgmt UI exposed |
| mgmt-phpmyadmin (mgmt)  | 8081           | phpmyadmin                             | reachable from edge; `AllowNoPassword` |
| mgmt-minio (mgmt)       | 9000, 9001     | minio                                  | default root cred, anonymous bucket policy |
| mgmt-snmp (mgmt)        | 161/udp        | snmpd                                  | `public` community, full walk |
| scanner (all segments)  | -              | nmap/openssl/redis-cli/mongosh/snmp    | the tool-under-test's vantage + PoC runner |

## Stack choices (bugs live inside these idioms)

- **Compose-orchestrated fleet**, one container per host, joined to per-segment
  Docker networks with **static IPs**. No application code of our own except a
  thin `edge-proxy` config and the `app-web` (reuse a slimmed build of one of the
  suite's web apps, or a 50-line static server - the web bugs are *not* the point
  here; the network exposure is).
- Every service is a **real, pinned upstream image** so version banners are
  genuine and CVE mapping is a real test. The vuln↔safe delta is entirely in
  **config** (`*.conf`, `pg_hba.conf`, env, compose `networks:`), never in
  service source.
- The **scanner container** ships the probe toolbox (`nmap`, `openssl`,
  `redis-cli`, `mongosh`, `snmpwalk`, `curl`, `ftp`, `smtp` one-liners) so PoCs
  run identically in compose and solo mode and don't depend on host tooling.
- **Verification API:** a tiny `netmeta` service on the scanner host answers
  `GET /api/_verify/health` (all expected hosts up) and
  `GET /api/_verify/ports?host=` (resolves the expected port set) behind
  `X-Verify-Token: benchsecret`, so PoCs and the compose healthcheck can confirm
  the range booted before scanning.

## Domain model

The shared SaaS domain is thin here - it exists only inside `app-web` and the
seeded datastores (so a scanner that pops open Redis/Mongo/Postgres finds the
`GLOBEX-CONFIDENTIAL-MARKER-7f3a` record, proving the no-auth exposure led to
real data). Seed users, orgs, and the weak `admin/admin` service cred match the
rest of the suite. The network topology, not the data, is the product.

## Vulnerability catalog (~32 planted exposures)

| Host · Service | Planted exposure | CWE | OWASP | Sev | Diff |
|---|---|---|---|---|---|
| edge-proxy · nginx 443 | Expired self-signed cert accepted | 295/298 | A02 | M | E-M |
| edge-proxy · nginx 443 | `TLSv1.0`/`SSLv3` + RC4/3DES ciphers offered | 326/327 | A02 | H | E-M |
| edge-proxy · nginx 80 | Admin/API served cleartext (no HSTS, no redirect) | 319 | A02 | M | E |
| edge-proxy · nginx | `/nginx_status` + `/server-status` exposed | 200 | A05 | L | E |
| **edge-proxy → data** | **Segmentation break** - `/internal/*` proxies edge→data tier | 668/923 | A01 | C | H |
| edge-bastion · ssh 22 | Root login + password auth + weak cred | 1392/307 | A07 | H | E-M |
| edge-bastion · ssh 22 | Outdated OpenSSH banner → known CVEs | 1104 | A06 | M | M |
| edge-ftp · ftp 21 | Anonymous read/write enabled | 306/862 | A05 | H | E |
| edge-ftp · ftp 21 | Cleartext creds + data (no FTPS) | 319 | A02 | M | E |
| edge-mail · smtp 25 | Open relay (unauthenticated relay accepted) | 269/406 | A05 | H | M |
| edge-mail · smtp 25 | No STARTTLS; VRFY user enumeration | 319/204 | A07 | L | E-M |
| app-web · 31337 | **Rogue open port** - unauthenticated bind shell | 1327/912 | A05 | C | M-H |
| app-legacy · telnet 23 | Cleartext admin service listening | 319/306 | A02 | H | E |
| app-legacy · httpd 8000 | Banner advertises a CVE'd server version | 1104/200 | A06 | M | M |
| data-postgres · 5432 | `listen_addresses='*'` + `trust`/weak auth | 306/1392 | A05 | C | E-M |
| data-redis · 6379 | **No auth**, bound to all interfaces | 306 | A05 | C | E |
| data-mongo · 27017 | No auth; databases world-readable | 306 | A05 | C | E |
| data-elastic · 9200 | Security disabled; cluster world-readable, no TLS | 306/319 | A05 | H | E |
| data-memcached · 11211 | No auth; UDP reflection/amplification enabled | 306/406 | A05 | M | M |
| data-* reachable from edge | Datastore tier answers edge-segment probes | 668 | A01 | C | H |
| mgmt-jenkins · 8080 | Anonymous read + `/script` Groovy console reachable | 862/94 | A05 | C | M |
| mgmt-grafana · 3000 | Default `admin/Admin123!` + anonymous view | 1392/798 | A05 | H | E |
| mgmt-rabbitmq · 15672 | Default `guest/guest`, mgmt UI exposed | 1392 | A07 | H | E |
| mgmt-phpmyadmin · 8081 | Reachable + `AllowNoPassword` root login | 862/1392 | A05 | H | E-M |
| mgmt-minio · 9000 | Default root cred + anonymous bucket policy | 1392/732 | A05 | H | M |
| mgmt-snmp · 161/udp | `public` community string, full MIB walk | 1392/200 | A05 | M | M |
| mgmt reachable from app | Management tier answers app-segment probes | 668 | A01 | H | H |
| edge-proxy · headers | Missing security headers / verbose `Server` banner | 693/200 | A05 | L | E |
| range-wide | Datastores hold seeded data → marker leaks via no-auth | 200 | A01 | H | M |
| edge-bastion · ssh | No fail2ban/rate limit → credential stuffing | 307 | A07 | M | E |
| edge-ftp · 30000-30009 | Wide passive-port range open/undocumented | 1327 | A05 | L | M |
| seed data | Default `admin/admin` service cred across services | 798 | A07 | M | E |

Roughly a dozen Easy rows (any port scanner + banner grab finds them), a Medium
core (version→CVE, default-cred auth, SNMP walk, open relay), and ~5 Hard rows
(the two segmentation breaks, the rogue port, the SSH-banner CVE mapping) that
reward reasoning over enumeration.

## Network-scanning highlights (only make sense at the network layer)

- **Segmentation is the headline.** In `vuln/`, `edge-proxy` forwards
  `/internal/redis`, `/internal/pg`, and `/internal/es` straight into the data
  tier, and the compose networks let every segment route to every other. So a
  scanner sitting in `edge` reaches `data-redis` - a host it should never see.
  This is the network analog of SSRF and the single most valuable thing to grade:
  it needs cross-host reachability reasoning, not a per-host port list. The
  `safe/` twin puts each tier on its own Docker network with only the intended
  edges, and the proxy forwards nothing under `/internal/`.
- **Version → CVE, not just "open".** Every image is pinned, so `app-legacy`'s
  Apache banner and `edge-bastion`'s OpenSSH banner map to *real* advisories. A
  scanner that reports "port 22 open" gets partial credit; one that reports "port
  22 open, OpenSSH `<version>`, CVE-XXXX-YYYY" gets full credit. The ground truth
  records the expected version string per port so the scorer can grade
  fingerprint accuracy separately from discovery.
- **TLS auditing surface.** `edge-proxy:443` deliberately offers an expired
  self-signed cert, negotiates `TLSv1.0`, and lists RC4/3DES - three distinct
  findings on one port. The near-miss vhost on `:8443` is `TLSv1.3`-only with a
  current cert and a strong cipher suite; flagging it is a false positive.
- **The rogue port.** `app-web` binds an extra listener on `31337` (a bind
  shell). It is not in any service's normal port set, so it only surfaces from a
  *full* range scan (`-p-`), not a top-1000 scan - a direct test of scan
  thoroughness.
- **UDP is not optional.** `snmp/161` and `memcached/11211` only answer UDP. A
  TCP-only scan misses them entirely, which is exactly the coverage gap worth
  measuring.
- **Auth is required to confirm.** "Redis on 6379" is a guess until the probe
  sends `PING` and gets `PONG` with no `AUTH`. PoCs *complete the handshake* (and
  read the seeded marker) so the finding is proven, not inferred from an open
  port.

## Near-misses (hardened service beside the exposed one)

- `data-redis:6379` (no auth) beside `data-redis-secure:6380` (`requirepass`,
  bound to the data network only).
- `edge-proxy:443` (expired cert, `TLSv1.0`, weak ciphers) beside
  `edge-proxy:8443` (`TLSv1.3`-only, current cert, strong suite).
- `edge-bastion:22` (password + root + weak cred) - the `safe/` twin is the same
  host reconfigured to key-only, `PermitRootLogin no`; in `vuln/` a second
  listener demonstrates the hardened config exists nearby.
- `edge-ftp:21` (anonymous) beside an FTPS-only config path that disables anon.
- A **closed/filtered** port on `edge-proxy` that *looks* like it should be open
  (e.g. `:3306` filtered by the proxy host) - a decoy to catch scanners that
  report by port-number heuristic instead of probing.

## Topology-only bugs (no single-host probe reveals them)

- **Edge→data reachability (CWE-668/923):** PoC runs the probe *from a container
  placed in the edge segment* and asserts it completes a Redis/Postgres handshake
  on the data tier. On `safe/`, the connection times out (segmented).
- **App→mgmt reachability (CWE-668):** same shape, app segment reaching the
  Jenkins script console.
- **Rogue-port detection (CWE-1327):** requires diffing the observed open-port
  set against the expected per-host set - a topology assertion, not a signature.

## Ground truth, PoC tooling & scoring

Two ground-truth artifacts, because two things are being graded:

1. **`ground-truth/expected-ports.yaml`** - the authoritative port map:
   `host, ip, segment, port, proto, state (open|closed|filtered), service,
   version` for every listener (including the decoy's `filtered` state and the
   rogue `31337`). The scorer set-diffs a scanner's discovered ports against this
   → **precision/recall on host+port discovery** and a separate **version-match
   rate** on the `service`/`version` fields.
2. **`ground-truth/VULNERABILITIES.yaml`** - one entry per catalog row, standard
   schema. Field remaps for this app: `route` carries `host:port/proto`
   (e.g. `"data-redis:6379/tcp"`); `variant_paths` point at the differing config
   files (`vuln/edge/nginx.conf` ↔ `safe/edge/nginx.conf`,
   `vuln/compose.networks.yml` ↔ `safe/…`), since the delta is config, not source.
   Additive keys (ignored by the shared scorer): `host`, `segment`, `proto`,
   `from_segment` (where a segmentation PoC must originate), and `expected_open`.

PoCs run **from the scanner container** so they don't depend on host tooling:

- `portscan_baseline.sh` - `nmap -sS -sU -p-` the range, diff against
  `expected-ports.yaml`; exits 0 when the vuln-only ports (incl. `31337`) are open.
- `redis_open.sh` - `redis-cli -h data-redis ping` → `PONG` with no `AUTH`, then
  `KEYS *`/`GET` the seeded marker.
- `mongo_open.sh`, `elastic_open.sh`, `pg_trust.sh`, `memcached_open.sh` - same
  shape per datastore.
- `tls_weak.sh` - `openssl s_client -tls1 -connect edge-proxy:443` succeeds;
  `tls_expired.sh` - cert `notAfter` in the past; both fail against `:8443`.
- `ftp_anon.sh`, `smtp_relay.sh`, `snmp_public.sh`, `telnet_open.sh` - protocol
  one-liners.
- `defaultcred_grafana.sh`, `defaultcred_rabbitmq.sh`,
  `defaultcred_phpmyadmin.sh`, `defaultcred_minio.sh` - complete a login.
- `segbreak_edge_to_data.sh` - launched with `--from edge`, asserts a data-tier
  handshake; the harness runs it from an edge-segment sidecar.

Each exits `0` when the exposure is present (PASS on `vuln/`, FAIL on `safe/`).
`make verify` runs them all; `make validate` proves every one flips on the
hardened twin; `ground-truth/` never enters a build context.

## Patched twin (`safe/`)

Per-segment Docker networks with only the intended edges (edge→app→data, mgmt
isolated behind a jump host); edge proxy forwards no `/internal/*` and drops
`/nginx_status`; `443` reconfigured to `TLSv1.3`-only with a current cert and a
strong cipher suite (or folded into the `:8443` config); SSH key-only,
`PermitRootLogin no`, rate-limited, image bumped; FTP anon off + FTPS; SMTP relay
restrictions + STARTTLS; the `31337` listener removed; telnet removed / replaced
by SSH; `app-legacy` image patched; Postgres `listen_addresses='localhost'` +
`scram-sha-256` + `pg_hba` host rules; Redis `requirepass` + internal bind; Mongo
auth on; Elasticsearch security + TLS on; Memcached bound internal + SASL / no
UDP; Jenkins anon off + script console locked; Grafana cred rotated + anon off;
RabbitMQ `guest` removed; phpMyAdmin behind mgmt-only + `AllowNoPassword` off;
MinIO root rotated + private bucket policy; SNMP community rotated / SNMPv3;
security headers added; seed service cred rotated. Scanning `safe/` measures
false positives - by construction every near-miss and every closed port is clean.

## Compose sketch (independent; private bridge, 127.0.0.1 host bindings only)

```yaml
name: vuln-network
networks:
  edge: { driver: bridge, ipam: { config: [{ subnet: 10.89.1.0/24 }] } }
  app:  { driver: bridge, ipam: { config: [{ subnet: 10.89.2.0/24 }] } }
  data: { driver: bridge, ipam: { config: [{ subnet: 10.89.3.0/24 }] } }
  mgmt: { driver: bridge, ipam: { config: [{ subnet: 10.89.4.0/24 }] } }
services:
  # --- edge segment (simulated DMZ) ---
  edge-proxy:
    image: nginx:1.27
    networks:
      edge: { ipv4_address: 10.89.1.10 }
      data: {}            # planted CWE-668: edge can route to data
    volumes: ["./vuln/edge/nginx.conf:/etc/nginx/nginx.conf:ro", "./vuln/edge/tls:/etc/nginx/tls:ro"]
    ports: ["127.0.0.1:${DYNAST_PORT_EDGE_PROXY_80:-13312}:80", "127.0.0.1:8443r:443"]   # curated host subset only
  edge-bastion:
    image: linuxserver/openssh-server:<pinned>
    environment: { PASSWORD_ACCESS: "true", USER_PASSWORD: "admin", SUDO_ACCESS: "true" }  # weak cred
    networks: { edge: { ipv4_address: 10.89.1.11 } }
  # --- data segment (should be app-only; exposed in vuln) ---
  data-redis:
    image: redis:7.4          # NO requirepass - planted CWE-306
    command: ["redis-server", "--bind", "0.0.0.0", "--protected-mode", "no"]
    networks: { data: { ipv4_address: 10.89.3.11 } }
  data-redis-secure:          # hardened near-miss
    image: redis:7.4
    command: ["redis-server", "--requirepass", "S3cure!", "--bind", "10.89.3.20"]
    networks: { data: { ipv4_address: 10.89.3.20 } }
  data-postgres:
    image: postgres:16.4
    environment: { POSTGRES_HOST_AUTH_METHOD: trust }   # planted CWE-1392
    networks: { data: { ipv4_address: 10.89.3.10 } }
  # --- mgmt segment ---
  mgmt-grafana:
    image: grafana/grafana:11.2.0
    environment: { GF_SECURITY_ADMIN_PASSWORD: Admin123!, GF_AUTH_ANONYMOUS_ENABLED: "true" }
    networks: { mgmt: {}, app: {} }     # planted CWE-668: reachable from app
  # --- the tool's vantage point + PoC runner ---
  scanner:
    build: ./scanner            # nmap, openssl, redis-cli, mongosh, snmp, curl
    networks: [edge, app, data, mgmt]   # vuln: sees everything; safe: edge only
    # netmeta verification API on 127.0.0.1:13311 for healthcheck/port resolution
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:3000"]
  # ... edge-ftp, edge-mail, app-web(+31337), app-legacy, data-mongo,
  #     data-elastic, data-memcached, mgmt-jenkins, mgmt-rabbitmq,
  #     mgmt-phpmyadmin, mgmt-minio, mgmt-snmp
```

*(`8443r` above is shorthand - only a curated subset of ports maps to the host;
the full range is scanned in-bridge from `scanner`.)*

## Standalone single-image (`make solo`)

One container can't run four real Docker subnets, so solo mode **simulates the
hosts on loopback aliases**: the entrypoint brings up `127.0.0.2 … 127.0.0.19`,
starts each service bound to its own alias (supervisord), and the scanner runs
against `127.0.0.0/8` inside the container. The segmentation bugs are simulated
with `iptables` rules between the alias groups (dropped in `vuln/`, enforced in
`safe/`). Config/env/PoCs stay byte-identical because host resolution is aliased
the same way the compose service names are - `/etc/hosts` maps `data-redis`,
`edge-proxy`, etc. to their loopback aliases. Runs as root to manage aliases,
`iptables`, and the service supervisor.

## Build milestones

1. Compose with the four segment networks + static IPs; the `scanner` container
   and `netmeta` verification API; `expected-ports.yaml` scaffold; range boots
   and `/api/_verify/health` reports all hosts up.
2. Stand up the datastore tier open (Redis/Mongo/Elastic/Postgres/Memcached),
   seed the shared domain (marker record), and land the "no-auth" +
   `data-redis-secure` near-miss.
3. Edge segment: nginx TLS misconfig + `:8443` good-TLS twin, `/nginx_status`,
   bastion SSH, FTP anon, SMTP relay.
4. Mgmt segment default-cred services (Grafana/RabbitMQ/phpMyAdmin/MinIO) + SNMP;
   app-web with the rogue `31337` listener and `app-legacy` telnet/old-banner.
5. The two segmentation breaks (edge→data proxy + flattened networks; app→mgmt)
   and their `safe/` per-network isolation.
6. `VULNERABILITIES.yaml` + `expected-ports.yaml` + every `verify/` PoC
   exploitable on `vuln/`; copy to `safe/`, harden **config only** on the named
   lines, `make validate` (all flip) + `make solo` (loopback-alias simulation)
   green.
