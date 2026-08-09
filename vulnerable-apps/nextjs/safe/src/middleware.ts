import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

function roleFromToken(token?: string): string | undefined {
  if (!token) return undefined;
  try {
    const payload = token.split(".")[1];
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    return JSON.parse(json).role;
  } catch {
    return undefined;
  }
}

export function middleware(req: NextRequest) {
  // FIXED MW-BYPASS-001: the internal `x-middleware-subrequest` header is NOT
  // trusted — there is no bypass. (The safe route handlers also re-check
  // authorization themselves, so middleware is defense-in-depth, not the only
  // gate.)
  const role = roleFromToken(req.cookies.get("token")?.value);
  if (role !== "admin" && role !== "service") {
    if (req.nextUrl.pathname.startsWith("/api")) {
      return NextResponse.json({ error: "forbidden" }, { status: 401 });
    }
    return NextResponse.redirect(new URL("/login", req.url));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/admin/:path*", "/api/admin/:path*"],
};
