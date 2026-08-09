// FIXED SECRET-001: signing key comes only from the environment — no hardcoded
// literal in source, and no shared cross-deployment default.
export const JWT_SECRET = process.env.JWT_SECRET || "";
if (!JWT_SECRET) console.error("[config] JWT_SECRET is not set");

// FIXED SECRET-001: server-only (no NEXT_PUBLIC_ prefix); never sent to the browser.
export const INTEGRATION_KEY = process.env.INTEGRATION_KEY || "";

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
