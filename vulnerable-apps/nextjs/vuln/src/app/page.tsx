import { PUBLIC_API_KEY } from "@/lib/config";

export default function Home() {
  return (
    <main>
      <h1>TaskFlow</h1>
      <p>A tiny multi-tenant task/blog app — deliberately full of security bugs.</p>
      <div className="card">
        <h3>Getting started</h3>
        <p>
          Sign in with a team account, or <a href="/signup">create one</a> — new
          accounts go through email verification before they are activated.
        </p>
        <p>
          <small>
            Test credentials are no longer listed here. QA builds carry them in
            the sign-in page&apos;s dev helper.
          </small>
        </p>
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
