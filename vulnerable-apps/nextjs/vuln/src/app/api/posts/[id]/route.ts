import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";
import { rank, RANKS } from "@/lib/roles";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// NEAR-MISS NM-APPROVAL-001: the API edit path. Org-scoped, author-or-editor,
// and - the part the autosave action forgets - a content change by anyone below
// editor drops the post back to draft, so an approval only ever covers the text
// that was reviewed.
export async function PATCH(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const post = await prisma.post.findFirst({ where: { id, orgId: me.orgId } });
  if (!post) return NextResponse.json({ error: "not found" }, { status: 404 });
  if (post.authorId !== me.userId && rank(me.role) < RANKS.editor) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const { title, body } = await req.json().catch(() => ({}));
  const data: { title?: string; body?: string; status?: string } = {};
  if (typeof title === "string" && title.trim()) data.title = title.trim();
  if (typeof body === "string") data.body = body;
  if ((data.title !== undefined || data.body !== undefined) && rank(me.role) < RANKS.editor && post.status !== "draft") {
    data.status = "draft";
  }
  const updated = await prisma.post.update({ where: { id }, data });
  return NextResponse.json({ ok: true, id, status: updated.status });
}

// Delete a post: its author, or an admin of the workspace.
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { id } = await params;
  const post = await prisma.post.findFirst({ where: { id, orgId: me.orgId } });
  if (!post) return NextResponse.json({ error: "not found" }, { status: 404 });
  if (post.authorId !== me.userId && rank(me.role) < RANKS.admin) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  await prisma.comment.deleteMany({ where: { postId: id } });
  await prisma.post.delete({ where: { id } });
  return NextResponse.json({ ok: true });
}

// VULN IDOR-001 (CWE-639/863): requires a logged-in user but does NOT check that
// the post belongs to the caller's org. Any authenticated user can read any
// post by id, across tenants and across draft/published status.
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const { id } = await params;
  const post = await prisma.post.findUnique({ where: { id } });
  if (!post) return NextResponse.json({ error: "not found" }, { status: 404 });
  // Missing: if (post.orgId !== me.orgId) return 404
  return NextResponse.json(post);
}
