import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// NEAR-MISS NM-BOLA-WRITE-001: the same by-id write one verb over, scoped to the
// caller's own comments in the query itself - a foreign id deletes nothing and
// reads as 404.
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const { count } = await prisma.comment.deleteMany({ where: { id, authorId: me.userId } });
  if (count === 0) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ ok: true });
}

// VULN BOLA-WRITE-001 (CWE-639): editing a comment checks that someone is logged
// in and then updates the row by id alone. Nothing ties the comment to the
// caller - not authorship, not even the org - so any user rewrites any comment
// in any tenant, including the stored-HTML bodies the post page renders.
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const { body } = await req.json().catch(() => ({}));
  if (typeof body !== "string" || !body) return NextResponse.json({ error: "body required" }, { status: 400 });
  const { count } = await prisma.comment.updateMany({ where: { id }, data: { body } });
  if (count === 0) return NextResponse.json({ error: "not found" }, { status: 404 });
  return NextResponse.json({ ok: true, id, body });
}
