import { NextResponse } from "next/server";
import { redis } from "@/lib/redis";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// CACHE-POISON-001 (CWE-349): a shared Redis cache serves a rendered widget. The
// body embeds the request's X-Forwarded-Host (used to build a canonical link),
// but the cache key is ONLY the `key` param — the host is UNKEYED. So an attacker
// primes the entry with a malicious host and every later visitor is served the
// poisoned response from cache. The safe twin folds the host into the cache key
// (see cache-scoped/route.ts, the properly-keyed near-miss).
export async function GET(req: Request) {
  const key = new URL(req.url).searchParams.get("key") ?? "home";
  const host =
    req.headers.get("x-forwarded-host") ?? req.headers.get("host") ?? "bench.local";

  const cacheKey = `pagecache:${key}`;
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
