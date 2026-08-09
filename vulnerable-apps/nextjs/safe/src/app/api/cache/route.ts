import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// CACHE-POISON-001 fixed: the host is folded into the cache key, so a request
// with a spoofed X-Forwarded-Host is cached under a key no other visitor shares.
export async function GET(req: Request) {
  const key = new URL(req.url).searchParams.get("key") ?? "home";
  const host =
    req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? "bench.local";

  const cacheKey = `pagecache:${key}:${host}`;
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
