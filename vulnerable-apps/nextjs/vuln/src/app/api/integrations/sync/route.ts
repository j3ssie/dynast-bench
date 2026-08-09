import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// Sync endpoint for the "Connected apps" widget. Two callers: the browser widget
// (session cookie) and server-to-server jobs (service-account Basic credential).
// The endpoint itself is fine — the planted bug is that the vulnerable variant's
// client component ships the Basic credential to the browser (CREDS-BUNDLE-001).
export async function POST(req: Request) {
  const auth = req.headers.get("authorization") || "";

  if (auth.startsWith("Basic ")) {
    const [email, password] = Buffer.from(auth.slice(6), "base64").toString().split(":");
    const svc = email ? await prisma.user.findUnique({ where: { email } }) : null;
    if (!svc || !bcrypt.compareSync(password || "", svc.passwordHash)) {
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    }
    return NextResponse.json({ ok: true, as: svc.role, synced: 3 });
  }

  const me = await getIdentity(req);
  if (!me) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  return NextResponse.json({ ok: true, as: me.role, synced: 3 });
}
