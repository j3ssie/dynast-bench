import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Comment body is stored verbatim (no sanitization). The stored-XSS sink is in
// the post detail page, which renders this body with dangerouslySetInnerHTML.
export async function POST(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { postId, body } = await req.json().catch(() => ({}));
  if (!postId || !body) return NextResponse.json({ error: "postId and body required" }, { status: 400 });
  const c = await prisma.comment.create({ data: { postId, authorId: me.userId, body } });
  return NextResponse.json({ ok: true, id: c.id });
}
