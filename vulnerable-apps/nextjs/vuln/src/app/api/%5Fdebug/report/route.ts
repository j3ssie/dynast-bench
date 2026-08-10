import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

/**
 * The report builder's "computed column" backend.
 *
 * Not linked from anywhere, not in the client's route registry, and not in any
 * chunk the app loads up front — the only reference to it lives in the devtools
 * bundle, which is fetched lazily the first time somebody opens the Advanced
 * panel. It is also completely unauthenticated.
 */

// NEAR-MISS NM-AGG-001: the same "let the caller choose the computation" idea,
// resolved through a fixed table instead of evaluated. Callers send a name, not
// code, and an unknown name is rejected. Flagging this is a false positive.
const AGGREGATES: Record<string, (rows: { n: number }[]) => number> = {
  count: (rows) => rows.length,
  sum: (rows) => rows.reduce((a, r) => a + r.n, 0),
  max: (rows) => rows.reduce((a, r) => Math.max(a, r.n), 0),
};

export async function POST(req: Request) {
  const { expr, agg } = await req.json().catch(() => ({}));

  const posts = await prisma.post.findMany({ select: { id: true, title: true, status: true } });
  const rows = posts.map((p, i) => ({ ...p, n: i + 1 }));

  if (agg) {
    const fn = AGGREGATES[String(agg)];
    if (!fn) return NextResponse.json({ error: "unknown aggregate" }, { status: 400 });
    return NextResponse.json({ agg, value: fn(rows) });
  }

  if (!expr) return NextResponse.json({ error: "expr or agg required" }, { status: 400 });

  // VULN CODEINJ-001 (CWE-94): the "computed column" expression is compiled and
  // run on the server. It was meant for things like `row.title.length`, but
  // `new Function` is a whole JavaScript runtime — the body reaches process,
  // require and every secret in the environment.
  const compute = new Function("row", `return (${expr});`);
  const computed = rows.map((row) => {
    try {
      return { id: row.id, value: compute(row) };
    } catch (e) {
      return { id: row.id, error: String(e) };
    }
  });
  return NextResponse.json({ expr, computed });
}
