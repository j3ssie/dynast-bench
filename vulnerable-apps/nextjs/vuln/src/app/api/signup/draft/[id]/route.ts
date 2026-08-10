import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN SIGNUP-IDOR-001 (CWE-639): the wizard reloads its own draft by id after a
// page refresh, and the handler hands back whatever row that id names — with no
// ownership check and no session, over an autoincrement id. Counting down from
// your own draft id walks every registration in progress, and each row carries
// the address AND the verification code that was emailed to it.
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const draft = await prisma.signupDraft.findUnique({ where: { id: Number(id) } });
  if (!draft) return NextResponse.json({ error: "unknown draft" }, { status: 404 });
  return NextResponse.json(draft);
}
