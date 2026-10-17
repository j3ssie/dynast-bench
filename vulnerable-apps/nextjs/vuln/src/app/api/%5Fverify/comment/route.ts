import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { VERIFY_TOKEN } from "@/lib/config";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(req: Request) {
  if (req.headers.get("x-verify-token") !== VERIFY_TOKEN) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const id = new URL(req.url).searchParams.get("id") ?? "";
  const c = await prisma.comment.findUnique({ where: { id }, include: { author: true } });
  if (!c) return NextResponse.json({ exists: false });
  return NextResponse.json({ exists: true, id: c.id, body: c.body, authorEmail: c.author.email, postId: c.postId });
}
