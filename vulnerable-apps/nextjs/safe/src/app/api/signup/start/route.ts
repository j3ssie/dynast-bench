import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { sendMail } from "@/lib/mailer";
import { newVerificationCode } from "@/lib/signup";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED SIGNUP-ENUM-001: step 1 answers the same way whether or not the address
// is already registered — always 200 with a draft id. When the address is
// taken, no user is created and a "you already have an account" notice is mailed
// instead, so the difference is only ever visible in the inbox, not the response.
export async function POST(req: Request) {
  const { email } = await req.json().catch(() => ({}));
  if (!email) return NextResponse.json({ error: "email required" }, { status: 400 });

  const existing = await prisma.user.findUnique({ where: { email } });
  const code = newVerificationCode();
  const draft = await prisma.signupDraft.create({ data: { email, code } });
  if (existing) {
    await sendMail(email, "You already have a TaskFlow account", "Try signing in instead.");
  } else {
    await sendMail(email, "Verify your TaskFlow account", `Your code is ${code}`);
  }
  return NextResponse.json({ draftId: draft.id, step: "verify" });
}
