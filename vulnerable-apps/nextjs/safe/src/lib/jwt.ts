// Minimal HS256 JWT for the API bearer path, built on Web Crypto.
import { JWT_SECRET } from "./config";

function b64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj: unknown): string {
  return b64url(Buffer.from(JSON.stringify(obj)));
}
function fromB64url(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

async function hmac(data: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64url(Buffer.from(sig));
}

export async function signJwt(payload: Record<string, unknown>, expSeconds = 3600): Promise<string> {
  const header = { alg: "HS256", typ: "JWT" };
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + expSeconds };
  const head = b64urlJson(header);
  const load = b64urlJson(body);
  const sig = await hmac(`${head}.${load}`, JWT_SECRET);
  return `${head}.${load}.${sig}`;
}

// FIXED JWT-001: rejects `alg: none`, requires HS256, verifies the signature
// against the env-provided secret, and enforces `exp`.
export async function verifyJwt(token: string): Promise<Record<string, any> | null> {
  try {
    if (!JWT_SECRET) return null;
    const [head, load, sig] = token.split(".");
    if (!head || !load || !sig) return null;
    const header = JSON.parse(fromB64url(head).toString("utf8"));
    if (header.alg !== "HS256") return null; // no alg confusion
    const expected = await hmac(`${head}.${load}`, JWT_SECRET);
    if (expected !== sig) return null;        // signature required
    const payload = JSON.parse(fromB64url(load).toString("utf8"));
    if (typeof payload.exp === "number" && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;                            // expiry enforced
    }
    return payload;
  } catch {
    return null;
  }
}
