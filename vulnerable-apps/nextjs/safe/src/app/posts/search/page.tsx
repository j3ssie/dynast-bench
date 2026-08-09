export const dynamic = "force-dynamic";

// FIXED XSS-REFLECT-002: the query is rendered as escaped text via JSX
// interpolation, not injected as raw HTML.
export default async function SearchPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const sp = await searchParams;
  const q = sp.q ?? "";
  return (
    <main>
      <h1>Search</h1>
      <form method="get">
        <input name="q" defaultValue={q} placeholder="search posts..." />
        <button type="submit">Search</button>
      </form>
      <div className="card">You searched for: {q}</div>
      <p><a href={`/api/posts/search?q=${encodeURIComponent(q)}`}>view JSON results</a></p>
    </main>
  );
}
