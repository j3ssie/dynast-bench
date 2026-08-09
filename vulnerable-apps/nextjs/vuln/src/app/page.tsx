import { PUBLIC_API_KEY } from "@/lib/config";

export default function Home() {
  return (
    <main>
      <h1>TaskFlow</h1>
      <p>A tiny multi-tenant task/blog app — deliberately full of security bugs.</p>
      <div className="card">
        <h3>Seed accounts</h3>
        <ul>
          <li>admin@bench.local / Admin123! (admin, org Acme)</li>
          <li>editor@bench.local / Editor123! (editor, org Acme)</li>
          <li>user1@bench.local / User123! (user, org Acme)</li>
          <li>user2@bench.local / User123! (user, org Globex)</li>
        </ul>
      </div>
      {/*
        VULN SECRET-001 (CWE-200): a secret exposed to the browser bundle via the
        NEXT_PUBLIC_ prefix, rendered straight into the page HTML.
      */}
      <div className="card" data-api-key={PUBLIC_API_KEY}>
        <small>build integration key: {PUBLIC_API_KEY}</small>
      </div>
    </main>
  );
}
