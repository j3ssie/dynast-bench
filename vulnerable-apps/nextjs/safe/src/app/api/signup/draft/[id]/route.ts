import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// FIXED SIGNUP-IDOR-001: reading a draft requires proving ownership of it with
// the code that was emailed to that address, and the code is never echoed back.
// A stranger counting through ids has neither the code to pass the check nor any
// way to harvest one, so the row — and every other in-progress signup — stays
// private.
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const draft = await prisma.signupDraft.findUnique({ where: { id: Number(id) } });
  if (!draft) return NextResponse.json({ error: "unknown draft" }, { status: 404 });

  const presented = req.headers.get("x-draft-code") ?? "";
  if (presented !== draft.code) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const { code: _code, ...safe } = draft;
  return NextResponse.json(safe);
}
