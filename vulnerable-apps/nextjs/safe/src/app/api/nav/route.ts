import { NextResponse } from "next/server";
import { getIdentity } from "@/lib/session";

export const dynamic = "force-dynamic";

/**
 * The navigation manifest the client renders its menu from.
 *
 * The app has no server-rendered link list, so this is the only place the route
 * surface is enumerated - and it is scoped to who is asking. A crawler that does
 * not run the page's JS sees a nav with nothing in it; one that does, but is not
 * logged in, still never learns that /integrations or /admin/users exist.
 */
const PUBLIC_ITEMS = [
  { label: "Home", href: "/" },
  { label: "Posts", href: "/posts" },
  { label: "Sign in", href: "/login" },
  { label: "Create account", href: "/signup" },
];

const USER_ITEMS = [
  { label: "Search", href: "/posts/search" },
  { label: "Profile", href: "/profile" },
  { label: "Connected apps", href: "/integrations" },
];

const ADMIN_ITEMS = [{ label: "Admin", href: "/admin/users" }];

export async function GET(req: Request) {
  const me = await getIdentity(req);
  const items = [...PUBLIC_ITEMS];
  if (me) {
    items.push(...USER_ITEMS);
    if (me.role === "admin" || me.role === "service") items.push(...ADMIN_ITEMS);
  }
  return NextResponse.json({ items, authenticated: Boolean(me) });
}
