import { prisma } from "@/lib/db";
import PostFilter from "../_components/PostFilter";

export const dynamic = "force-dynamic";

export default async function PostsPage() {
  const posts = await prisma.post.findMany({
    where: { status: "published" },
    orderBy: { createdAt: "desc" },
    include: { org: true },
  });
  return (
    <main>
      <h1>Posts</h1>
      <PostFilter count={posts.length} />
      {posts.map((p) => (
        <div key={p.id} className="card">
          <a href={`/posts/${p.id}`}><strong>{p.title}</strong></a>
          <div><small>{p.org.name} · {p.status}</small></div>
        </div>
      ))}
    </main>
  );
}
