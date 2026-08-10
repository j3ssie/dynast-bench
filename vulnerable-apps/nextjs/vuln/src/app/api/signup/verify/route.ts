import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Step 2: present the code that was emailed. The comparison here is fine; what
// makes this step defeatable is where the code came from — see
// SIGNUP-TOKEN-001 in @/lib/signup.
export async function POST(req: Request) {
  const { draftId, code } = await req.json().catch(() => ({}));
  const draft = await prisma.signupDraft.findUnique({ where: { id: Number(draftId) } });
  if (!draft) return NextResponse.json({ error: "unknown draft" }, { status: 404 });
  if (draft.code !== String(code ?? "")) {
    return NextResponse.json({ error: "incorrect code" }, { status: 400 });
  }
  await prisma.signupDraft.update({ where: { id: draft.id }, data: { verified: true } });
  return NextResponse.json({ ok: true, step: "profile" });
}
