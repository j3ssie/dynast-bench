// VULN SECRET-001 (CWE-798/321): a hardcoded secret literal committed to source,
// used as the fallback signing key. Because it is a literal, it is also readable
// by anyone with the repo and identical across every deployment.
export const JWT_SECRET = process.env.JWT_SECRET || "dev-super-secret-change-me";

// VULN SECRET-001 (CWE-200): a secret exposed to the browser bundle via the
// NEXT_PUBLIC_ prefix, then rendered into the homepage HTML.
export const PUBLIC_API_KEY = process.env.NEXT_PUBLIC_API_KEY || "leaked-public-key-abc123";

export const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "benchsecret";
export const APP_URL = process.env.APP_URL || "http://localhost:3000";

// Server-side runtime config: internal service coordinates plus the credentials
// the app needs to reach them. Consumed by the mailer. Nothing in here is meant
// to leave the server — see CONFIG-LEAK-001 in src/app/layout.tsx.
export const RUNTIME_CONFIG = {
  appName: "TaskFlow",
  locale: "en-US",
  buildSha: process.env.BUILD_SHA || "0000000",
  internalApiBase: process.env.INTERNAL_API_BASE || "http://mailpit:8025",
  smtp: {
    host: process.env.SMTP_HOST || "mailpit",
    port: Number(process.env.SMTP_PORT || 1025),
    user: process.env.SMTP_USER || "bench-smtp",
    pass: process.env.SMTP_PASS || "SMTP-b3nch-4a91",
  },
  internalAdminToken: process.env.INTERNAL_ADMIN_TOKEN || "int-adm-9c1f2e7b",
};

// NEAR-MISS NM-CONFIG-001: the same config narrowed to an explicit allow-list of
// fields that are safe to publish. Serializing THIS into the page is correct —
// the bug is serializing RUNTIME_CONFIG. Flagging this is a false positive.
export const PUBLIC_RUNTIME_CONFIG = {
  appName: RUNTIME_CONFIG.appName,
  locale: RUNTIME_CONFIG.locale,
  buildSha: RUNTIME_CONFIG.buildSha,
};
