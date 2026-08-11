// Settings for the "Connected apps" widget.
//
// This module is imported by a CLIENT component (src/app/integrations/page.tsx),
// so every literal below is bundled into a public /_next/static/chunks/*.js file
// and is readable by anyone who loads the page. Nothing secret may live here.

// FIXED SECRET-002: the object-store credential is gone from client code. It is
// held server-side (OBJECT_STORE_KEY_ID / OBJECT_STORE_SECRET in the server
// environment) and never encoded into anything the browser downloads — base64
// would not have helped, since it is encoding rather than secrecy.

// FIXED CREDS-BUNDLE-001: no service-account credential is shipped to the
// browser. The widget calls the sync endpoint with the caller's own session
// cookie; the Basic service credential is only ever used server-to-server.

// The key the embedded widget puts in every postMessage so the page knows the
// message came from "our" widget. It is a constant in a client module, so it is
// in the public bundle exactly like everything else here — which is the whole
// problem with authenticating a message by its contents (see POSTMSG-003).
export const WIDGET_APP_KEY = "wgt_live_7f3a9c21";

// NEAR-MISS NM-B64-001: a committed base64 literal, same shape as a leaked
// credential — but the plaintext is public UI config, not a secret. Decodes to
// {"theme":"dark","density":"compact"}. Flagging it is a false positive.
export const WIDGET_THEME_B64 = "eyJ0aGVtZSI6ImRhcmsiLCJkZW5zaXR5IjoiY29tcGFjdCJ9";

export function decodeWidgetTheme(): { theme: string; density: string } {
  return JSON.parse(atob(WIDGET_THEME_B64));
}

// NEAR-MISS NM-TOKEN-001: reads like a credential (`token`), but it is minted
// per-request by the server for the caller's own session and never committed.
// Flagging it is a false positive.
export async function fetchSyncToken(): Promise<string> {
  const r = await fetch("/api/integrations/token");
  if (!r.ok) return "";
  return (await r.json()).token as string;
}
