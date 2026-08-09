"use client";
import { useEffect, useState } from "react";

export default function AdminUsersPage() {
  const [data, setData] = useState<any>(null);
  useEffect(() => {
    fetch("/api/admin/users")
      .then((r) => r.json())
      .then(setData)
      .catch((e) => setData({ error: String(e) }));
  }, []);
  return (
    <main>
      <h1>Admin · Users</h1>
      <pre className="card">{JSON.stringify(data, null, 2)}</pre>
    </main>
  );
}
