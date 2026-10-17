import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";
import { rank, RANKS } from "@/lib/roles";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Publishing is gated on the review: only an approved post goes live. It trusts
// that "approved" still describes the content - which is true only as long as
// every write path drops a post back to draft when its content changes.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const post = await prisma.post.findFirst({ where: { id, orgId: me.orgId } });
  if (!post) return NextResponse.json({ error: "not found" }, { status: 404 });
  if (post.authorId !== me.userId && rank(me.role) < RANKS.editor) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  if (post.status !== "approved") {
    return NextResponse.json({ error: `cannot publish a post in ${post.status}` }, { status: 409 });
  }
  await prisma.post.update({ where: { id }, data: { status: "published" } });
  return NextResponse.json({ ok: true, id, status: "published" });
}
