import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

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
