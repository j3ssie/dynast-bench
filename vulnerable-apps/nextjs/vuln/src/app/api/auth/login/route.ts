import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/db";
import { createSession } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN ENUM-001 (CWE-204): distinct responses for "no such user" vs "wrong
// password" let an attacker enumerate valid accounts. (Also: no rate limit —
// RATELIMIT, CWE-307.)
export async function POST(req: Request) {
  const { email, password } = await req.json().catch(() => ({}));
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return NextResponse.json({ error: "no account with that email" }, { status: 404 });
  }
  const ok = bcrypt.compareSync(password || "", user.passwordHash);
  if (!ok) {
    return NextResponse.json({ error: "incorrect password" }, { status: 401 });
  }
  await createSession({ userId: user.id, role: user.role, orgId: user.orgId, email: user.email });
  return NextResponse.json({ ok: true, role: user.role, email: user.email });
}
