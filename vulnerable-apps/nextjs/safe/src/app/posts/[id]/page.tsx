import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export default async function PostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const post = await prisma.post.findUnique({ where: { id }, include: { comments: true } });
  if (!post) return <main><h1>Post not found</h1></main>;

  return (
    <main>
      <h1>{post.title}</h1>
      <p>{post.body}</p>
      <h2>Comments</h2>
      {post.comments.map((c) => (
        // FIXED XSS-STORED-001: comment body rendered as escaped text, not raw HTML.
        <div key={c.id} className="card">{c.body}</div>
      ))}
    </main>
  );
}
