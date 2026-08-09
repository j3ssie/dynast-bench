import { NextResponse } from "next/server";
import { deepMerge } from "@/lib/merge";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// VULN PROTO-001 (CWE-1321): the raw JSON body is deep-merged into a config
// object. A body like {"__proto__":{"pollutedFlag":true}} walks onto
// Object.prototype, polluting every object in the process.
//
// The probe/cleanup below is ONLY for benchmark hygiene: it proves the
// pollution happened (a fresh object gained the injected key) and then removes
// any keys the merge added to Object.prototype so the long-lived server process
// isn't left in a broken state for subsequent scans. The vulnerable sink
// (deepMerge recursing through __proto__) is unchanged and is what SAST flags.
export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const before = new Set(Object.getOwnPropertyNames(Object.prototype));

  const cfg: any = {};
  deepMerge(cfg, body);

  const pollutedKeys = Object.getOwnPropertyNames(Object.prototype).filter((k) => !before.has(k));
  for (const k of pollutedKeys) delete (Object.prototype as any)[k]; // hygiene only
  return NextResponse.json({ ok: true, polluted: pollutedKeys.length > 0, pollutedKeys });
}
