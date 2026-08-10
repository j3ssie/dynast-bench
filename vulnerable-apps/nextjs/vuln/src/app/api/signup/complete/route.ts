import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN SIGNUP-STEPSKIP-001 (CWE-841): the final step never checks that the draft
// reached the verified state. The wizard walks start → verify → profile →
// complete, so in the UI a draft always is verified by the time it gets here —
// but the steps are four independent requests, and posting straight to this one
// with a fresh draft id registers an unverified, unowned mailbox as a real user.
export async function POST(req: Request) {
  const { draftId, password } = await req.json().catch(() => ({}));
  const draft = await prisma.signupDraft.findUnique({ where: { id: Number(draftId) } });
  if (!draft) return NextResponse.json({ error: "unknown draft" }, { status: 404 });
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
