// Settings for the "Connected apps" widget.
//
// This module is imported by a CLIENT component (src/app/integrations/page.tsx),
// so every literal below is bundled into a public /_next/static/chunks/*.js file
// and is readable by anyone who loads the page.

// VULN SECRET-002 (CWE-798/CWE-200): a cloud object-store credential pair,
// base64-encoded so it does not read as a secret in review. Base64 is encoding,
// not encryption — this decodes straight back to an access key + secret key.
export const OBJECT_STORE_KEY_B64 =
  "QUtJQUlPU0ZPRE5ON0VYQU1QTEU6d0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ==";

// VULN CREDS-BUNDLE-001 (CWE-522/CWE-798): live service-account credentials
// (the seeded admin/admin) pre-encoded as a Basic auth header and shipped to the
// browser so the widget can call the sync endpoint without a session. Anyone who
// reads the bundle can replay this header — or decode it and log in outright.
export const SYNC_BASIC_AUTH = "Basic YWRtaW46YWRtaW4=";

// The key the embedded widget puts in every postMessage so the page knows the
// message came from "our" widget. It is a constant in a client module, so it is
// in the public bundle exactly like everything else here — which is the whole
// problem with authenticating a message by its contents (see POSTMSG-003).
export const WIDGET_APP_KEY = "wgt_live_7f3a9c21";

// NEAR-MISS NM-B64-001: identical shape to OBJECT_STORE_KEY_B64 — a committed
// base64 literal — but the plaintext is public UI config, not a credential.
// Decodes to {"theme":"dark","density":"compact"}. Flagging it is a false positive.
export const WIDGET_THEME_B64 = "eyJ0aGVtZSI6ImRhcmsiLCJkZW5zaXR5IjoiY29tcGFjdCJ9";

export function decodeWidgetTheme(): { theme: string; density: string } {
  return JSON.parse(atob(WIDGET_THEME_B64));
}

// NEAR-MISS NM-TOKEN-001: reads like a credential (`token`) and is used the same
// way as SYNC_BASIC_AUTH, but it is minted per-request by the server for the
// caller's own session and never committed. Flagging it is a false positive.
export async function fetchSyncToken(): Promise<string> {
  const r = await fetch("/api/integrations/token");
  if (!r.ok) return "";
  return (await r.json()).token as string;
}
