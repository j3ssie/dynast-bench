import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { withCors } from "@/lib/cors";
import { Prisma } from "@prisma/client";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? "";

  if (!q) {
    const rows = await prisma.$queryRaw`SELECT id, title, body, status FROM "Post" WHERE status = 'published' ORDER BY "createdAt" DESC`;
    return withCors(NextResponse.json({ results: rows }), req);
  }

  // FIXED SQLI-001: the search term is bound as a parameter (Prisma.sql), never
  // concatenated into the query text.
  const like = `%${q}%`;
  const rows = await prisma.$queryRaw(
    Prisma.sql`SELECT id, title, body, status FROM "Post" WHERE status = 'published' AND title ILIKE ${like} ORDER BY "createdAt" DESC`
  );
  return withCors(NextResponse.json({ results: rows }), req);
}
