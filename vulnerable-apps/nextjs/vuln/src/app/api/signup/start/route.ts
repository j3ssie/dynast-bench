import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { sendMail } from "@/lib/mailer";
import { newVerificationCode } from "@/lib/signup";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN SIGNUP-ENUM-001 (CWE-204): step 1 answers differently depending on
// whether the address is already registered — 409 "already registered" versus
// 200 with a draft id. Registration is pre-auth and unthrottled, so this is a
// free oracle for testing an address list against the tenant.
export async function POST(req: Request) {
  const { email } = await req.json().catch(() => ({}));
  if (!email) return NextResponse.json({ error: "email required" }, { status: 400 });

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return NextResponse.json(
      { error: "that email is already registered", registered: true },
      { status: 409 },
    );
  }

  const code = newVerificationCode();
  const draft = await prisma.signupDraft.create({ data: { email, code } });
  await sendMail(email, "Verify your TaskFlow account", `Your code is ${code}`);
  return NextResponse.json({ draftId: draft.id, step: "verify" });
}
