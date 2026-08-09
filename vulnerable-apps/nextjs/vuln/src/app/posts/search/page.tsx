export const dynamic = "force-dynamic";

// VULN XSS-REFLECT-002 (CWE-79): the `q` query parameter is reflected into the
// page HTML via dangerouslySetInnerHTML with no escaping.
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
      <div className="card" dangerouslySetInnerHTML={{ __html: `You searched for: ${q}` }} />
      <p><a href={`/api/posts/search?q=${encodeURIComponent(q)}`}>view JSON results</a></p>
    </main>
  );
}
