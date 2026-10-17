import { cookies } from "next/headers";
import { redis } from "./redis";
import { signJwt, verifyJwt } from "./jwt";
import { prisma } from "./db";

/**
 * Who is calling. `orgId`/`role` are the workspace the session is switched into
 * (the home org at login), and `ver` is the user's sessionVersion at the moment
 * the session was minted.
 */
export type Identity = { userId: string; role: string; orgId: string; email: string; ver?: number };

// VULN SESSION-001 (CWE-330/384): session id derived from Math.random — low
// entropy and predictable, so a session id can be guessed/brute-forced.
function newSessionId(): string {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

type CookieJar = Awaited<ReturnType<typeof cookies>>;

// Store the identity under the sid and re-sign the `token` cookie - the one the
// (edge) middleware reads for the admin gate.
async function writeSession(jar: CookieJar, sid: string, user: Identity): Promise<void> {
  await redis.set(`sess:${sid}`, JSON.stringify(user), "EX", 60 * 60 * 8);
  const token = await signJwt({ sub: user.userId, role: user.role, orgId: user.orgId, email: user.email, ver: user.ver ?? 0 });
  jar.set("token", token, { httpOnly: true, sameSite: "lax", path: "/" });
}

export async function createSession(user: Identity): Promise<void> {
  const sid = newSessionId();
  const jar = await cookies();
  jar.set("sid", sid, { httpOnly: true, sameSite: "lax", path: "/" });
  await writeSession(jar, sid, user);
}

/**
 * Re-point the caller's current session at another workspace. The sid is kept,
 * so the switch survives without a fresh login; the token cookie is re-signed so
 * the middleware sees the role the user holds in that workspace.
 */
export async function switchSession(user: Identity): Promise<boolean> {
  const jar = await cookies();
  const sid = jar.get("sid")?.value;
  if (!sid) return false;
  await writeSession(jar, sid, user);
  return true;
}

export async function destroySession(): Promise<void> {
  const jar = await cookies();
  const sid = jar.get("sid")?.value;
  if (sid) await redis.del(`sess:${sid}`);
  jar.delete("sid");
  jar.delete("token");
}

// Resolve identity from either the Redis session cookie or an API Bearer JWT.
export async function getIdentity(req?: Request): Promise<Identity | null> {
  const me = await sessionIdentity(req);
  // VULN STALE-PRIV-001 (CWE-613): the identity is whatever was snapshotted when
  // the session (or JWT) was minted. Changing a user's role or membership bumps
  // their sessionVersion, but nothing here ever compares it, so a demoted or
  // removed user keeps acting with the rights they had at login until the
  // 8-hour session runs out.
  return me;
}

async function sessionIdentity(req?: Request): Promise<Identity | null> {
  // API bearer path (JWT).
  const auth = req?.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) {
    const payload = await verifyJwt(auth.slice(7));
    if (payload?.sub) {
      return { userId: payload.sub, role: payload.role, orgId: payload.orgId, email: payload.email, ver: payload.ver };
    }
  }
  // Session cookie path (Redis).
  const jar = await cookies();
  const sid = jar.get("sid")?.value;
  if (!sid) return null;
  const raw = await redis.get(`sess:${sid}`);
  if (!raw) return null;
  return JSON.parse(raw) as Identity;
}

export async function identityFromUserRow(u: { id: string; role: string; orgId: string; email: string; sessionVersion?: number }): Promise<Identity> {
  return { userId: u.id, role: u.role, orgId: u.orgId, email: u.email, ver: u.sessionVersion ?? 0 };
}

export { prisma };
