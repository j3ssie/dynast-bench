import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// NM-CACHE-001: the SAME widget-cache shape, but the host is part of the cache
// key, so the unkeyed-input poisoning does not apply. Present in both variants —
// flagging it is a false positive.
export async function GET(req: Request) {
  const key = new URL(req.url).searchParams.get("key") ?? "home";
  const host =
    req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? "bench.local";

  const cacheKey = `pagecache_scoped:${key}:${host}`;
  const hit = await redis.get(cacheKey);
  if (hit) {
    return new NextResponse(hit, {
      headers: { "content-type": "text/html", "x-cache": "HIT" },
    });
  }

  const body = `<!doctype html><link rel="canonical" href="https://${host}/w/${key}"><p>widget ${key}</p>`;
  await redis.set(cacheKey, body, "EX", 60);
  return new NextResponse(body, {
    headers: { "content-type": "text/html", "x-cache": "MISS" },
  });
}
