import { NextResponse } from "next/server";
import { APP_URL } from "./config";

// FIXED CORS-001: only the application's own origin is allowed; arbitrary
// Origins are never reflected.
export function withCors(res: NextResponse, req: Request): NextResponse {
  const origin = req.headers.get("origin");
  if (origin && origin === APP_URL) {
    res.headers.set("Access-Control-Allow-Origin", origin);
    res.headers.set("Access-Control-Allow-Credentials", "true");
  }
  return res;
}
