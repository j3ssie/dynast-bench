import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/db";
import { createSession } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED ENUM-001: identical generic response for unknown-user and wrong-password,
// with a constant-time-ish compare that runs even when the user doesn't exist.
const DUMMY_HASH = "$2a$08$abcdefghijklmnopqrstuv0123456789012345678901234567890a";

export async function POST(req: Request) {
  const { email, password } = await req.json().catch(() => ({}));
  const user = await prisma.user.findUnique({ where: { email } });
  const hash = user?.passwordHash || DUMMY_HASH;
  const ok = bcrypt.compareSync(password || "", hash);
  if (!user || !ok) {
    return NextResponse.json({ error: "invalid email or password" }, { status: 401 });
  }
  await createSession({ userId: user.id, role: user.role, orgId: user.orgId, email: user.email });
  return NextResponse.json({ ok: true, role: user.role, email: user.email });
}
