import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';

const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://bench:bench@127.0.0.1:5432/bench' });

async function main() {
  await pool.query(`
    DROP TABLE IF EXISTS reset_tokens, invites, attachments, comments, reports, posts, users, orgs CASCADE;
    CREATE TABLE orgs (id SERIAL PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, seat_limit INT NOT NULL DEFAULT 3, seats_used INT NOT NULL DEFAULT 1);
    CREATE TABLE users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL, is_admin BOOLEAN NOT NULL DEFAULT FALSE, verified BOOLEAN NOT NULL DEFAULT TRUE, org_id INT NOT NULL REFERENCES orgs(id));
    CREATE TABLE posts (id SERIAL PRIMARY KEY, slug TEXT UNIQUE NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, org_id INT NOT NULL REFERENCES orgs(id), author_id INT NOT NULL REFERENCES users(id));
    CREATE TABLE comments (id SERIAL PRIMARY KEY, post_id INT NOT NULL REFERENCES posts(id), body TEXT NOT NULL);
    CREATE TABLE reports (id SERIAL PRIMARY KEY, name TEXT NOT NULL, template TEXT NOT NULL, org_id INT NOT NULL REFERENCES orgs(id), owner_id INT NOT NULL REFERENCES users(id));
    CREATE TABLE attachments (id SERIAL PRIMARY KEY, filename TEXT NOT NULL, path TEXT NOT NULL, org_id INT NOT NULL REFERENCES orgs(id), owner_id INT NOT NULL REFERENCES users(id));
    CREATE TABLE invites (id SERIAL PRIMARY KEY, email TEXT NOT NULL, org_id INT NOT NULL REFERENCES orgs(id));
    CREATE TABLE reset_tokens (id SERIAL PRIMARY KEY, email TEXT NOT NULL, token TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
  `);
  const acme = (await pool.query("INSERT INTO orgs(name, slug, seat_limit, seats_used) VALUES ('Acme','acme',3,1) RETURNING id")).rows[0].id;
  const globex = (await pool.query("INSERT INTO orgs(name, slug, seat_limit, seats_used) VALUES ('Globex','globex',3,1) RETURNING id")).rows[0].id;
  async function user(email: string, password: string, displayName: string, role: string, isAdmin: boolean, orgId: number) {
    const hash = await bcrypt.hash(password, 8);
    return (await pool.query('INSERT INTO users(email,password_hash,display_name,role,is_admin,verified,org_id) VALUES ($1,$2,$3,$4,$5,true,$6) RETURNING id', [email, hash, displayName, role, isAdmin, orgId])).rows[0].id;
  }
  const admin = await user('admin@bench.local', 'Admin123!', 'Acme Admin', 'admin', true, acme);
  const editor = await user('editor@bench.local', 'Editor123!', 'Acme Editor', 'editor', false, acme);
  const user1 = await user('user1@bench.local', 'User123!', 'Acme User', 'user', false, acme);
  const user2 = await user('user2@bench.local', 'User123!', 'Globex User', 'user', false, globex);
  await user('admin', 'admin', 'Default Service', 'service', true, acme);
  await pool.query("INSERT INTO posts(slug,title,body,status,org_id,author_id) VALUES ('welcome-acme','Welcome Acme','Public Acme onboarding post','PUBLISHED',$1,$2)", [acme, editor]);
  await pool.query("INSERT INTO posts(slug,title,body,status,org_id,author_id) VALUES ('globex-public','Globex Public','Globex published note','PUBLISHED',$1,$2)", [globex, user2]);
  await pool.query("INSERT INTO posts(slug,title,body,status,org_id,author_id) VALUES ('globex-internal','Globex Internal Draft','GLOBEX-CONFIDENTIAL-MARKER-7f3a','DRAFT',$1,$2)", [globex, user2]);
  await pool.query("INSERT INTO comments(post_id, body) VALUES (1, 'Welcome comment')");
  await pool.query("INSERT INTO reports(name, template, org_id, owner_id) VALUES ('quarterly', '<p>{{message}}</p>', $1, $2)", [acme, admin]);
  await pool.query("INSERT INTO attachments(filename,path,org_id,owner_id) VALUES ('welcome.txt','/uploads/welcome.txt',$1,$2)", [acme, user1]);
  for (const dir of ['/app/uploads', '/app/attachments']) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync('/app/uploads/welcome.txt', 'Welcome upload from NestJS benchmark\n');
  fs.writeFileSync('/app/attachments/welcome.txt', 'Welcome attachment from NestJS benchmark\n');
  fs.writeFileSync('/app/secret.txt', 'NESTJS-ATTACHMENT-SECRET\n');
  console.log('seeded nestjs benchmark data');
}
main().finally(() => pool.end());
