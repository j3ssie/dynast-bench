# wordpress - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**BenchPress Tasks** is a lightweight WordPress-compatible PHP app that mirrors
stock WordPress routing and vulnerable-plugin shapes (`wp-login.php`,
`wp-admin/admin-ajax.php`, `wp-admin/admin-post.php`, `/wp-json/...`,
`xmlrpc.php`, `?author=...`, `wp-content/...`). The planted bugs live in the
`bench-tasks` plugin-shaped code and in WordPress-style configuration files.

This app implements a practical representative subset of
`../../benchmark-plans/wordpress.md`: wpdb-style SQL injection, second-order
SQL injection, missing nonce CSRF, missing capability checks,
`wp_ajax_nopriv_`-style privileged action, PHP object injection,
upload/webshell, LFI, SSRF, reflected/stored XSS, IDOR, role escalation,
command injection, open redirect, options/secrets leak, predictable reset token,
REST/author enumeration, XML-RPC pingback SSRF analog, weak salts, debug/backup
exposure, billing/race-style logic bugs, CORS, vulnerable dependency exposure,
and weak default admin credentials.

## Layout

```
wordpress/
├── vuln/          # vulnerable variant (Docker build context)
├── safe/          # patched twin - same app with YAML-named fixes
├── ground-truth/  # VULNERABILITIES.yaml + verify/ PoCs (never baked into images)
└── Makefile       # up · reset · safe · verify · validate · solo · diff
```

## Run

```bash
make up          # build + start vuln/ on http://127.0.0.1:13311
make verify      # run all PoCs; expect ALL exploitable
make safe        # switch to the patched twin on the same local port
make verify-safe # run all PoCs; expect ALL fixed
make validate    # full vuln/safe loop
make solo        # single-image vuln variant on 127.0.0.1:13311
```

Both Docker and standalone modes bind only to `127.0.0.1`. The `ground-truth/`
directory is outside both Docker build contexts and is not copied into images.

## Seed

- Orgs: Acme and Globex.
- Users: `admin@bench.local/Admin123!`, `editor@bench.local/Editor123!`,
  `user1@bench.local/User123!`, `user2@bench.local/User123!`, plus the weak
  WordPress-style default credential `admin/admin` in the vulnerable variant.
- The Globex draft task `globex-internal` contains
  `GLOBEX-CONFIDENTIAL-MARKER-7f3a` and is reachable through SQLi/IDOR only.
- Harness verification API: `/api/_verify/health`, `/api/_verify/user`,
  `/api/_verify/post`, `/api/_verify/task`; protected reads use
  `X-Verify-Token: benchsecret`.

## Notes

This is intentionally a lightweight compatible PHP app rather than a full
WordPress core install so it can be reviewed and syntax-checked quickly while
preserving WordPress URL, plugin, AJAX, REST, XML-RPC, and configuration shapes.
