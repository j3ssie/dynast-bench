// Seed: two orgs (tenants), roles per the shared matrix, a cross-tenant user
// (user2 in Globex) for IDOR PoCs, a weak default service credential, and posts
// including a Globex DRAFT carrying a distinctive marker so injection/IDOR PoCs
// can prove cross-tenant / cross-status leakage.
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();
const hash = (pw) => bcrypt.hashSync(pw, 8);
export const GLOBEX_MARKER = "GLOBEX-CONFIDENTIAL-MARKER-7f3a";

async function main() {
  const acme = await prisma.organization.upsert({
    where: { slug: "acme" },
    update: {},
    create: { name: "Acme", slug: "acme", seatsLimit: 5, seatsUsed: 3, premium: false },
  });
  const globex = await prisma.organization.upsert({
    where: { slug: "globex" },
    update: {},
    create: { name: "Globex", slug: "globex", seatsLimit: 5, seatsUsed: 1, premium: true },
  });

  const users = [
    { email: "admin@bench.local",  pw: "Admin123!",  role: "admin",  isAdmin: true,  org: acme.id,   name: "Acme Admin" },
    { email: "editor@bench.local", pw: "Editor123!", role: "editor", isAdmin: false, org: acme.id,   name: "Acme Editor" },
    { email: "user1@bench.local",  pw: "User123!",   role: "user",   isAdmin: false, org: acme.id,   name: "Acme User" },
    { email: "user2@bench.local",  pw: "User123!",   role: "user",   isAdmin: false, org: globex.id, name: "Globex User" },
    // Planted weak default service credential (admin/admin).
    { email: "admin",              pw: "admin",      role: "service",isAdmin: true,  org: acme.id,   name: "Service" },
  ];
  const byEmail = {};
  for (const u of users) {
    byEmail[u.email] = await prisma.user.upsert({
      where: { email: u.email },
      update: {},
      create: {
        email: u.email, passwordHash: hash(u.pw), role: u.role,
        isAdmin: u.isAdmin, verified: true, orgId: u.org, displayName: u.name,
      },
    });
  }

  const posts = [
    { slug: "acme-welcome",   title: "Welcome to Acme",    body: "Public welcome post.",            status: "published", author: "admin@bench.local",  org: acme.id },
    { slug: "acme-roadmap",   title: "Acme Roadmap",       body: "Q3 roadmap details.",             status: "published", author: "editor@bench.local", org: acme.id },
    { slug: "acme-draft",     title: "Acme Draft Notes",   body: "Unpublished acme draft.",         status: "draft",     author: "user1@bench.local",  org: acme.id },
    { slug: "globex-hello",   title: "Globex Hello",       body: "Globex public post.",             status: "published", author: "user2@bench.local",  org: globex.id },
    // Cross-tenant DRAFT with the marker: never returned by a correct,
    // published-only, org-scoped query — only via SQLi or IDOR.
    { slug: "globex-internal",title: "Globex Internal Q3", body: `Secret plans. ${GLOBEX_MARKER}`,  status: "draft",     author: "user2@bench.local",  org: globex.id },
    { slug: "acme-notes",     title: "Acme Notes",         body: "More acme content.",              status: "published", author: "user1@bench.local",  org: acme.id },
  ];
  for (const p of posts) {
    await prisma.post.upsert({
      where: { slug: p.slug },
      update: {},
      create: {
        slug: p.slug, title: p.title, body: p.body, status: p.status,
        authorId: byEmail[p.author].id, orgId: p.org,
      },
    });
  }

  // A benign seeded comment on a public post.
  const welcome = await prisma.post.findUnique({ where: { slug: "acme-welcome" } });
  const existing = await prisma.comment.findFirst({ where: { postId: welcome.id } });
  if (!existing) {
    await prisma.comment.create({
      data: { postId: welcome.id, authorId: byEmail["user1@bench.local"].id, body: "Nice post!" },
    });
  }

  console.log("[seed] done");
}

main().catch((e) => { console.error(e); process.exit(1); }).finally(() => prisma.$disconnect());
