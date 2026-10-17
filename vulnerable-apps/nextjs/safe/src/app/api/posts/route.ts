import { NextResponse } from "next/server";
import { randomBytes } from "node:crypto";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const STATUSES = ["draft", "in_review", "approved", "published"];

// The current workspace's posts, any status - members review each other's
// drafts, so this is meant to show them.
export async function GET(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const status = new URL(req.url).searchParams.get("status");
  const posts = await prisma.post.findMany({
    where: { orgId: me.orgId, ...(status && STATUSES.includes(status) ? { status } : {}) },
    select: { id: true, slug: true, title: true, body: true, status: true, authorId: true, createdAt: true },
    orderBy: { createdAt: "desc" },
  });
  return NextResponse.json({ posts });
}

// Start a new draft in the current workspace.
export async function POST(req: Request) {
  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { title, body } = await req.json().catch(() => ({}));
  if (typeof title !== "string" || !title.trim()) {
    return NextResponse.json({ error: "title required" }, { status: 400 });
  }
  const base = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "post";
  const post = await prisma.post.create({
    data: {
      title: title.trim(),
      body: typeof body === "string" ? body : "",
      slug: `${base}-${randomBytes(4).toString("hex")}`,
      status: "draft",
      authorId: me.userId,
      orgId: me.orgId,
    },
  });
  return NextResponse.json({ ok: true, id: post.id, slug: post.slug, status: post.status }, { status: 201 });
}
