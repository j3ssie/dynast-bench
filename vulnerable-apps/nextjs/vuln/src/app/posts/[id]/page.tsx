import { prisma } from "@/lib/db";

export const dynamic = "force-dynamic";

export default async function PostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const post = await prisma.post.findUnique({ where: { id }, include: { comments: true } });
  if (!post) return <main><h1>Post not found</h1></main>;

  return (
    <main>
      {/* NM-XSS (near-miss, safe): the title is rendered as escaped text via JSX
          interpolation. Present in both variants — must not be flagged. */}
      <h1>{post.title}</h1>
      <p>{post.body}</p>
      <h2>Comments</h2>
      {post.comments.map((c) => (
        // VULN XSS-STORED-001 (CWE-79): comment body rendered as raw HTML.
        <div key={c.id} className="card" dangerouslySetInnerHTML={{ __html: c.body }} />
      ))}
    </main>
  );
}
