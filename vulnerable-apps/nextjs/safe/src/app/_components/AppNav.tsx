"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/routes";

type Item = { label: string; href: string };

/**
 * The site navigation, fetched after mount instead of rendered on the server.
 *
 * Nothing here is a vulnerability - it is how the app is shaped. The initial
 * HTML carries no link list at all, so the route surface is only visible to a
 * client that runs the page, and only the part of it that client is entitled to
 * see (see /api/nav).
 */
export default function AppNav() {
  const [items, setItems] = useState<Item[]>([]);

  useEffect(() => {
    let live = true;
    fetch(api("nav"))
      .then((r) => (r.ok ? r.json() : { items: [] }))
      .then((j) => live && setItems(j.items ?? []))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, []);

  return (
    <nav style={{ padding: "12px 24px", borderBottom: "1px solid #223" }} data-nav>
      {items.map((it) => (
        <a key={it.href} href={it.href}>
          {it.label}
        </a>
      ))}
    </nav>
  );
}
