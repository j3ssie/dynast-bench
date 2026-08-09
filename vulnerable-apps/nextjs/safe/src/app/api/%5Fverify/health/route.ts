import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  const out: Record<string, string> = { status: "ok", db: "unknown", redis: "unknown" };
  try { await prisma.$queryRaw`SELECT 1`; out.db = "ok"; } catch { out.db = "down"; out.status = "degraded"; }
  try { const p = await redis.ping(); out.redis = p === "PONG" ? "ok" : "down"; } catch { out.redis = "down"; out.status = "degraded"; }
  return NextResponse.json(out);
}
