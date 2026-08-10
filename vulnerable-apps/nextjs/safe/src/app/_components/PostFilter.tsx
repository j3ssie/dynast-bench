"use client";
import { useEffect, useRef, useState } from "react";

/**
 * Client-side filtering for the posts list. The active filter is kept in the URL
 * fragment so a filtered view can be linked and restored on reload.
 */
export default function PostFilter({ count }: { count: number }) {
  const [filter, setFilter] = useState("");
  const banner = useRef<HTMLDivElement | null>(null);

  // FIXED DOMXSS-001: the fragment is rendered as text through textContent, so a
  // payload in the URL fragment is shown literally instead of being parsed as
  // HTML and executed.
  useEffect(() => {
    function apply() {
      const raw = decodeURIComponent(window.location.hash.replace(/^#/, ""));
      setFilter(raw);
      if (banner.current) {
        banner.current.textContent = raw ? `Showing posts matching ${raw}` : "";
      }
    }
    apply();
    window.addEventListener("hashchange", apply);
    return () => window.removeEventListener("hashchange", apply);
  }, []);

  return (
    <div className="card">
      <div ref={banner} data-filter-banner />
      <small>
        {count} published post(s){filter ? ` · filter "${filter}"` : ""}
      </small>
    </div>
  );
}
