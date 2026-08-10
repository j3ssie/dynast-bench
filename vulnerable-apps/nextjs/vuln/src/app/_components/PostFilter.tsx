"use client";
import { useEffect, useRef, useState } from "react";

/**
 * Client-side filtering for the posts list. The active filter is kept in the URL
 * fragment so a filtered view can be linked and restored on reload.
 */
export default function PostFilter({ count }: { count: number }) {
  const [filter, setFilter] = useState("");
  const banner = useRef<HTMLDivElement | null>(null);

  // VULN DOMXSS-001 (CWE-79): the fragment is read straight out of
  // location.hash and written into the document with innerHTML. The fragment
  // never reaches the server, so nothing server-side ever sees this payload and
  // no response body ever contains it — it only exists once the page runs.
  useEffect(() => {
    function apply() {
      const raw = decodeURIComponent(window.location.hash.replace(/^#/, ""));
      setFilter(raw);
      if (banner.current) {
        banner.current.innerHTML = raw ? `Showing posts matching <b>${raw}</b>` : "";
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
