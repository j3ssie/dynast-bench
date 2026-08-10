import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { redis } from "@/lib/redis";
import { sendMail } from "@/lib/mailer";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// NEAR-MISS NM-SIGNUP-RESEND-001: the sibling of /api/signup/start — same
// pre-auth surface, same "does this address exist" shape, same mail send. It is
// NOT a bug: the response is constant whatever the answer, and it is rate
// limited per address, so it is neither an enumeration oracle nor a mail cannon.
// Flagging this is a false positive.
export async function POST(req: Request) {
  const { email } = await req.json().catch(() => ({}));
  const constant = NextResponse.json({ ok: true, message: "if that signup exists, a code is on its way" });
  if (!email) return constant;

  const key = `signup:resend:${String(email).toLowerCase()}`;
  const hits = await redis.incr(key);
  if (hits === 1) await redis.expire(key, 300);
  if (hits > 3) return constant;

  const draft = await prisma.signupDraft.findFirst({
    where: { email, completed: false },
    orderBy: { id: "desc" },
  });
  if (draft) await sendMail(draft.email, "Your TaskFlow code", `Your code is ${draft.code}`);
  return constant;
}
