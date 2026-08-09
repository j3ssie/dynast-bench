import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { withCors } from "@/lib/cors";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(req: Request) {
  const q = new URL(req.url).searchParams.get("q") ?? "";

  // NM-SQL (near-miss, safe): an empty query takes a correctly PARAMETERIZED
  // path via a tagged-template `$queryRaw`. Present in both variants — must not
  // be flagged as SQLi.
  if (!q) {
    const rows = await prisma.$queryRaw`SELECT id, title, body, status FROM "Post" WHERE status = 'published' ORDER BY "createdAt" DESC`;
    return withCors(NextResponse.json({ results: rows }), req);
  }

  // VULN SQLI-001 (CWE-89): the search term is concatenated directly into the
  // SQL string via $queryRawUnsafe. `q=' OR '1'='1` escapes both the title
  // filter and the status filter, dumping drafts and other tenants' rows.
  const sql =
    `SELECT id, title, body, status FROM "Post" ` +
    `WHERE status = 'published' AND title ILIKE '%${q}%' ORDER BY "createdAt" DESC`;
  try {
    const rows = await prisma.$queryRawUnsafe(sql);
    return withCors(NextResponse.json({ results: rows }), req);
  } catch (e) {
    // Minor: echoes the DB error (verbose error surface).
    return withCors(NextResponse.json({ error: String(e) }, { status: 500 }), req);
  }
}
