import { NextResponse } from "next/server";

// VULN CORS-001 (CWE-942): reflects the request Origin back verbatim AND sets
// Access-Control-Allow-Credentials: true — any site can make credentialed
// cross-origin reads.
export function withCors(res: NextResponse, req: Request): NextResponse {
  const origin = req.headers.get("origin");
  if (origin) {
    res.headers.set("Access-Control-Allow-Origin", origin);
    res.headers.set("Access-Control-Allow-Credentials", "true");
  }
  return res;
}
