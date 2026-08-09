import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { VERIFY_TOKEN } from "@/lib/config";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(req: Request) {
  if (req.headers.get("x-verify-token") !== VERIFY_TOKEN) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const slug = new URL(req.url).searchParams.get("slug") ?? "";
  const p = await prisma.post.findUnique({ where: { slug }, include: { author: true, org: true, comments: true } });
  if (!p) return NextResponse.json({ exists: false });
  return NextResponse.json({
    exists: true, id: p.id, status: p.status, title: p.title,
    authorEmail: p.author.email, orgSlug: p.org.slug, commentCount: p.comments.length,
  });
}
