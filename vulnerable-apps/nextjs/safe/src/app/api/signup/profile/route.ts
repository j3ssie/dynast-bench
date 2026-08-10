import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED SIGNUP-MASSASSIGN-001: only the one field this step owns is copied onto
// the draft. `role` and `orgSlug` are never client-writable, so a request that
// names them cannot self-promote or switch tenant.
export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const { draftId, displayName } = body ?? {};
  const draft = await prisma.signupDraft.findUnique({ where: { id: Number(draftId) } });
  if (!draft) return NextResponse.json({ error: "unknown draft" }, { status: 404 });

  const updated = await prisma.signupDraft.update({
    where: { id: draft.id },
    data: { displayName: String(displayName ?? "") },
  });
  return NextResponse.json({ ok: true, step: "complete", displayName: updated.displayName });
}
