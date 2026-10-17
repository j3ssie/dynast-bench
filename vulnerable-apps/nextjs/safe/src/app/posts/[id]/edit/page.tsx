import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";
import Editor from "./Editor";

export const dynamic = "force-dynamic";

export default async function EditPostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const me = await getIdentity();
  if (!me) return <main><h1>Sign in to edit</h1><p><a href="/login">Sign in</a></p></main>;
  const post = await prisma.post.findFirst({ where: { id, orgId: me.orgId } });
  if (!post) return <main><h1>Post not found</h1></main>;
  return (
    <main>
      <h1>Edit post</h1>
      <Editor
        id={post.id}
        title={post.title}
        body={post.body}
        status={post.status}
        mine={post.authorId === me.userId}
      />
    </main>
  );
}
