import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN SIGNUP-MASSASSIGN-001 (CWE-915): step 3 spreads the request body straight
// into the draft update. The wizard only ever sends displayName, but the draft
// row also carries `role` and `orgSlug` — the two fields step 4 hands to the new
// User — so a request that names them registers an admin, or drops the account
// into another tenant.
export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const { draftId, ...rest } = body ?? {};
  const draft = await prisma.signupDraft.findUnique({ where: { id: Number(draftId) } });
  if (!draft) return NextResponse.json({ error: "unknown draft" }, { status: 404 });

  const updated = await prisma.signupDraft.update({
    where: { id: draft.id },
    data: { ...rest },
  });
  return NextResponse.json({ ok: true, step: "complete", displayName: updated.displayName });
}
