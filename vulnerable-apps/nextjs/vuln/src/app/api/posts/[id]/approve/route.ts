import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";
import { rank, RANKS } from "@/lib/roles";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// The checker half of maker-checker: an editor of the same workspace, who is
// not the author, signs off on exactly what is in review.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  if (rank(me.role) < RANKS.editor) return NextResponse.json({ error: "editors only" }, { status: 403 });
  const { id } = await params;
  const { count } = await prisma.post.updateMany({
    where: { id, orgId: me.orgId, status: "in_review", authorId: { not: me.userId } },
    data: { status: "approved" },
  });
  if (count === 0) return NextResponse.json({ error: "nothing in review to approve" }, { status: 409 });
  return NextResponse.json({ ok: true, id, status: "approved" });
}
