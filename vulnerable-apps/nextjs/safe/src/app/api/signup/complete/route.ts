import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED SIGNUP-STEPSKIP-001: the final step enforces the state the flow depends
// on — a draft that never reached the verified step cannot be completed, so a
// request that jumps straight here for an unverified, unowned mailbox is
// rejected rather than turned into a real account.
export async function POST(req: Request) {
  const { draftId, password } = await req.json().catch(() => ({}));
  const draft = await prisma.signupDraft.findUnique({ where: { id: Number(draftId) } });
  if (!draft) return NextResponse.json({ error: "unknown draft" }, { status: 404 });
  if (!draft.verified) {
    return NextResponse.json({ error: "email not verified" }, { status: 403 });
  }
  if (draft.completed) {
    return NextResponse.json({ error: "already completed" }, { status: 409 });
  }

  const org = await prisma.organization.findUnique({ where: { slug: draft.orgSlug } });
  if (!org) return NextResponse.json({ error: "unknown org" }, { status: 400 });

  const user = await prisma.user.create({
    data: {
      email: draft.email,
      passwordHash: bcrypt.hashSync(String(password || "Changeme123!"), 8),
      displayName: draft.displayName,
      role: draft.role,
      isAdmin: draft.role === "admin",
      verified: draft.verified,
      orgId: org.id,
    },
  });
  await prisma.signupDraft.update({ where: { id: draft.id }, data: { completed: true } });
  return NextResponse.json({ ok: true, id: user.id, email: user.email, role: user.role });
}
