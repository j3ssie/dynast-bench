import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Coarse admin gate. In the vulnerable design, authorization for /admin and
// /api/admin lives ONLY here in middleware — the route handlers trust that a
// request which reached them was already authorized.
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
  // VULN MW-BYPASS-001 (CWE-285): trusts the internal `x-middleware-subrequest`
  // header and short-circuits the auth check entirely. An external client can
  // spoof this header (the CVE-2025-29927 class) to reach admin routes.
  if (req.headers.get("x-middleware-subrequest")) {
    return NextResponse.next();
  }

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
