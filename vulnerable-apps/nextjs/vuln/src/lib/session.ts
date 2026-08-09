import { cookies } from "next/headers";
import { redis } from "./redis";
import { signJwt, verifyJwt } from "./jwt";
import { prisma } from "./db";

export type Identity = { userId: string; role: string; orgId: string; email: string };

// VULN SESSION-001 (CWE-330/384): session id derived from Math.random — low
// entropy and predictable, so a session id can be guessed/brute-forced.
function newSessionId(): string {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

export async function createSession(user: Identity): Promise<void> {
  const sid = newSessionId();
  await redis.set(`sess:${sid}`, JSON.stringify(user), "EX", 60 * 60 * 8);
  const token = await signJwt({ sub: user.userId, role: user.role, orgId: user.orgId, email: user.email });
  const jar = await cookies();
  jar.set("sid", sid, { httpOnly: true, sameSite: "lax", path: "/" });
  // The `token` cookie is what the (edge) middleware reads for the admin gate.
  jar.set("token", token, { httpOnly: true, sameSite: "lax", path: "/" });
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
  // API bearer path (JWT).
  const auth = req?.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) {
    const payload = await verifyJwt(auth.slice(7));
    if (payload?.sub) {
      return { userId: payload.sub, role: payload.role, orgId: payload.orgId, email: payload.email };
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

export async function identityFromUserRow(u: { id: string; role: string; orgId: string; email: string }): Promise<Identity> {
  return { userId: u.id, role: u.role, orgId: u.orgId, email: u.email };
}

export { prisma };
