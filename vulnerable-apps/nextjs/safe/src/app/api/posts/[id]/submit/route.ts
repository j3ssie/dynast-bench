import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// The author sends a draft to review.
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const { count } = await prisma.post.updateMany({
    where: { id, orgId: me.orgId, authorId: me.userId, status: "draft" },
    data: { status: "in_review" },
  });
  if (count === 0) return NextResponse.json({ error: "no draft of yours with that id" }, { status: 409 });
  return NextResponse.json({ ok: true, id, status: "in_review" });
}
