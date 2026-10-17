"use server";

import { prisma } from "@/lib/db";
import { getIdentity } from "@/lib/session";

/**
 * Autosave for the editor. The page calls this as the author types, so it is a
 * Server Action rather than a route: no URL of its own, just a POST to the page
 * carrying a `Next-Action` id. It is still a public endpoint - anyone holding
 * the id from the client bundle can call it with any arguments.
 */
export async function autosaveDraft(id: string, body: string) {
  const me = await getIdentity();
  if (!me) return { ok: false, error: "unauthorized" };
  const post = await prisma.post.findFirst({ where: { id: String(id), orgId: me.orgId } });
  if (!post || post.authorId !== me.userId) return { ok: false, error: "not found" };

  // FIXED APPROVAL-BYPASS-001: changed content needs a fresh review, so an
  // autosave on a post that is past draft drops it back to draft - the same
  // rule as the API edit path.
  const saved = await prisma.post.update({
    where: { id: post.id },
    data: { body: String(body), ...(post.status !== "draft" ? { status: "draft" } : {}) },
  });
  return { ok: true, status: saved.status, savedAt: Date.now() };
}
