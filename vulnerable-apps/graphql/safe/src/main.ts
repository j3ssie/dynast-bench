import http, { IncomingMessage, ServerResponse } from 'node:http';
import { URL } from 'node:url';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs/promises';
import { exec, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import { buildSchema, defaultFieldResolver, graphql, GraphQLError } from 'graphql';
import { WebSocketServer } from 'ws';
import { SECURITY } from './security.js';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);
const PORT = Number(process.env.PORT || 3000);
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'benchsecret';
const JWT_SECRET = process.env.JWT_SECRET || 'hardcoded-weak-secret';
const STRICT_JWT_SECRET = process.env.STRICT_JWT_SECRET || 'rotated-safe-secret';
const BILLING_URL = process.env.BILLING_URL || 'http://billing-svc:9099';
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://bench:bench@127.0.0.1:5432/bench';
const { Pool } = pg;
const pool = new Pool({ connectionString: DATABASE_URL });
const apq = new Map<string, string>();
const loginFailures = new Map<string, number>();

type Viewer = { id: number; email: string; role: string; is_admin: boolean; org_id: number; org_slug: string } | null;
type Ctx = { viewer: Viewer; ip: string };
type Flags = typeof SECURITY;

type GqlReq = { query?: string; variables?: any; operationName?: string; extensions?: any };

const schema = buildSchema(`
  scalar JSONObject
  type Organization { id: ID!, slug: String!, name: String!, posts(first: Int): [Post!]! }
  type User { id: ID!, email: String, displayName: String, role: String!, isAdmin: Boolean!, passwordHash: String, resetToken: String, organization: Organization! }
  type Post { id: ID!, slug: String!, title: String!, body: String!, status: String!, author: User!, organization: Organization! }
  type Comment { id: ID!, body: String!, author: User! }
  type Report { id: ID!, name: String!, result: String }
  type AuthPayload { token: String!, user: User! }
  type LinkPreview { url: String!, title: String!, body: String! }
  type MutationResult { ok: Boolean!, message: String }
  input ProfileInput { displayName: String, email: String, role: String, isAdmin: Boolean, orgId: Int, passwordHash: String, resetToken: String }
  type Query {
    me: User
    users: [User!]!
    user(id: ID!): User
    organization(id: ID): Organization
    posts(filter: String, orderBy: String, first: Int): [Post!]!
    searchPosts(where: JSONObject): [Post!]!
    node(id: ID!): JSONObject
    linkPreview(url: String!): LinkPreview!
    reportRun(id: ID!): Report!
    billingBalance(orgId: ID): String!
  }
  type Mutation {
    login(email: String!, password: String!): AuthPayload!
    updateProfile(input: ProfileInput!): User!
    updateEmail(email: String!): User!
    deleteOrganization(id: ID!): MutationResult!
    createReport(name: String!): Report!
    exportReport(format: String!): String!
    addComment(postId: ID!, body: String!): Comment!
    purchaseSeats(quantity: Int!): MutationResult!
    inviteUser(email: String!): MutationResult!
    uploadAvatar(filename: String!, content: String!): String!
    ping(message: String): String!
  }
  type Subscription { postUpdated(orgId: ID!): Post! }
`);

function writeJson(res: ServerResponse, status: number, data: any, origin?: string) {
  const headers: Record<string, string> = { 'content-type': 'application/json; charset=utf-8' };
  applyCors(headers, origin);
  res.writeHead(status, headers);
  res.end(JSON.stringify(data));
}

function applyCors(headers: Record<string, string>, origin?: string) {
  if (SECURITY.LOCK_CORS) {
    headers['access-control-allow-origin'] = 'http://127.0.0.1:3000';
  } else if (origin) {
    headers['access-control-allow-origin'] = origin;
  } else {
    headers['access-control-allow-origin'] = '*';
  }
  headers['access-control-allow-credentials'] = SECURITY.LOCK_CORS ? 'false' : 'true';
  headers['access-control-allow-headers'] = 'content-type, authorization, x-verify-token';
  headers['access-control-allow-methods'] = 'GET,POST,OPTIONS';
}

async function migrateAndSeed() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orgs (id SERIAL PRIMARY KEY, slug TEXT UNIQUE, name TEXT, seat_limit INT DEFAULT 3, seats_used INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, org_id INT REFERENCES orgs(id), email TEXT UNIQUE, password TEXT, display_name TEXT, role TEXT, is_admin BOOLEAN DEFAULT false, password_hash TEXT, reset_token TEXT);
    CREATE TABLE IF NOT EXISTS posts (id SERIAL PRIMARY KEY, org_id INT REFERENCES orgs(id), author_id INT REFERENCES users(id), slug TEXT UNIQUE, title TEXT, body TEXT, status TEXT);
    CREATE TABLE IF NOT EXISTS comments (id SERIAL PRIMARY KEY, post_id INT REFERENCES posts(id), author_id INT REFERENCES users(id), body TEXT);
    CREATE TABLE IF NOT EXISTS reports (id SERIAL PRIMARY KEY, owner_id INT REFERENCES users(id), name TEXT, result TEXT);
    CREATE TABLE IF NOT EXISTS invitations (id SERIAL PRIMARY KEY, org_id INT REFERENCES orgs(id), email TEXT);
  `);
  const count = Number((await pool.query('SELECT count(*) AS n FROM users')).rows[0].n);
  if (count === 0) await seedData();
}

async function seedData() {
  await pool.query('TRUNCATE invitations, reports, comments, posts, users, orgs RESTART IDENTITY CASCADE');
  const acme = (await pool.query("INSERT INTO orgs(slug,name,seat_limit,seats_used) VALUES('acme','Acme',3,2) RETURNING id")).rows[0].id;
  const globex = (await pool.query("INSERT INTO orgs(slug,name,seat_limit,seats_used) VALUES('globex','Globex',3,1) RETURNING id")).rows[0].id;
  const adminPassword = SECURITY.ROTATE_SERVICE_CREDS ? 'ServiceRotated123!' : 'admin';
  const users = [
    [acme, 'admin@bench.local', 'Admin123!', 'Acme Admin', 'admin', true, '$2a$adminhash', 'reset-admin-0e1'],
    [acme, 'editor@bench.local', 'Editor123!', 'Acme Editor', 'editor', false, '$2a$editorhash', 'reset-editor-0e2'],
    [acme, 'user1@bench.local', 'User123!', 'Acme User', 'user', false, '$2a$user1hash', 'reset-user1-0e3'],
    [globex, 'user2@bench.local', 'User123!', 'Globex User', 'user', false, '$2a$user2hash', 'reset-user2-0e4'],
    [acme, 'admin', adminPassword, 'Weak Service Admin', 'service', true, '$2a$servicehash', 'reset-service-0e5']
  ];
  for (const u of users) await pool.query('INSERT INTO users(org_id,email,password,display_name,role,is_admin,password_hash,reset_token) VALUES($1,$2,$3,$4,$5,$6,$7,$8)', u);
  const ids = await pool.query('SELECT email,id,org_id FROM users');
  const byEmail = Object.fromEntries(ids.rows.map((r: any) => [r.email, r]));
  await pool.query('INSERT INTO posts(org_id,author_id,slug,title,body,status) VALUES($1,$2,$3,$4,$5,$6)', [acme, byEmail['editor@bench.local'].id, 'welcome-acme', 'Welcome Acme', 'Public Acme launch notes', 'PUBLISHED']);
  await pool.query('INSERT INTO posts(org_id,author_id,slug,title,body,status) VALUES($1,$2,$3,$4,$5,$6)', [acme, byEmail['user1@bench.local'].id, 'roadmap-acme', 'Acme Roadmap', 'Acme-only published roadmap', 'PUBLISHED']);
  await pool.query('INSERT INTO posts(org_id,author_id,slug,title,body,status) VALUES($1,$2,$3,$4,$5,$6)', [globex, byEmail['user2@bench.local'].id, 'globex-draft', 'Globex Draft', 'GLOBEX-CONFIDENTIAL-MARKER-7f3a draft body', 'DRAFT']);
}

async function resetVerifyState() {
  await pool.query("UPDATE orgs SET seat_limit=3, seats_used=CASE WHEN slug='acme' THEN 2 ELSE 1 END");
  await pool.query("UPDATE users SET role='user', is_admin=false WHERE email='user1@bench.local'");
  await pool.query("UPDATE users SET display_name='Acme User', org_id=(SELECT id FROM orgs WHERE slug='acme') WHERE email='user1@bench.local'");
  await pool.query('DELETE FROM invitations');
  await pool.query('DELETE FROM comments');
  await pool.query('DELETE FROM reports');
}

async function viewerFromAuth(auth?: string): Promise<Viewer> {
  if (!auth || !auth.toLowerCase().startsWith('bearer ')) return null;
  const token = auth.slice(7).trim();
  let payload: any;
  try {
    if (SECURITY.STRICT_JWT) payload = jwt.verify(token, STRICT_JWT_SECRET, { algorithms: ['HS256'] });
    else {
      const decoded: any = jwt.decode(token, { complete: true });
      if (decoded?.header?.alg === 'none') payload = decoded.payload;
      else payload = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true, algorithms: ['HS256'] });
    }
  } catch { return null; }
  if (!payload?.sub) return null;
  return getUser(Number(payload.sub));
}

async function getUser(id: number): Promise<Viewer> {
  const r = await pool.query('SELECT u.*, o.slug AS org_slug FROM users u JOIN orgs o ON o.id=u.org_id WHERE u.id=$1', [id]);
  return r.rows[0] || null;
}

async function getUserByEmail(email: string): Promise<any> {
  const r = await pool.query('SELECT u.*, o.slug AS org_slug FROM users u JOIN orgs o ON o.id=u.org_id WHERE u.email=$1', [email]);
  return r.rows[0] || null;
}

function signUser(user: any) {
  const secret = SECURITY.STRICT_JWT ? STRICT_JWT_SECRET : JWT_SECRET;
  return jwt.sign({ sub: user.id, email: user.email, role: user.role, orgId: user.org_id }, secret, { algorithm: 'HS256', expiresIn: '1h' });
}

function requireViewer(ctx: Ctx): asserts ctx is Ctx & { viewer: NonNullable<Viewer> } {
  if (!ctx.viewer) throw new GraphQLError('Authentication required', { extensions: { code: 'UNAUTHENTICATED' } });
}
function requireAdmin(ctx: Ctx) {
  requireViewer(ctx);
  if (!ctx.viewer.is_admin && ctx.viewer.role !== 'admin') throw new GraphQLError('Admin role required', { extensions: { code: 'FORBIDDEN' } });
}

function rowToPost(r: any) { return { ...r, __typename: 'Post' }; }
function rowToUser(r: any) { return { ...r, __typename: 'User', isAdmin: !!r.is_admin, displayName: r.display_name }; }
function rowToOrg(r: any) { return { ...r, __typename: 'Organization' }; }

async function safeFetch(url: string) {
  const u = new URL(url);
  if (SECURITY.BLOCK_SSRF) {
    const host = u.hostname.toLowerCase();
    if (!['example.com', 'www.example.com'].includes(host)) throw new GraphQLError('URL host not allowed', { extensions: { code: 'BAD_USER_INPUT' } });
  }
  const resp = await fetch(url, { redirect: 'manual' });
  return { url, title: `HTTP ${resp.status}`, body: await resp.text() };
}

const root = {
  async me(_: any, ctx: Ctx) { return ctx.viewer ? rowToUser(ctx.viewer) : null; },
  async users(_: any, ctx: Ctx) { requireAdmin(ctx); const r = await pool.query('SELECT * FROM users ORDER BY id'); return r.rows.map(rowToUser); },
  async user({ id }: any, ctx: Ctx) { requireViewer(ctx); const u = await getUser(Number(id)); if (!u) return null; if (SECURITY.NODE_CHECK_ORG && u.org_id !== ctx.viewer.org_id) return null; return rowToUser(u); },
  async organization({ id }: any, ctx: Ctx) { requireViewer(ctx); const oid = id ? Number(id) : ctx.viewer.org_id; const r = await pool.query('SELECT * FROM orgs WHERE id=$1', [oid]); return r.rows[0] ? rowToOrg(r.rows[0]) : null; },
  async posts({ filter = '', orderBy = 'p.id', first = 20 }: any, ctx: Ctx) {
    requireViewer(ctx);
    const limit = SECURITY.VALIDATE_SEATS ? Math.min(Number(first) || 20, 50) : Number(first) || 20;
    if (SECURITY.USE_SAFE_SQL) {
      const r = await pool.query('SELECT p.* FROM posts p WHERE p.org_id=$1 AND p.status=$2 AND p.title ILIKE $3 ORDER BY p.id LIMIT $4', [ctx.viewer.org_id, 'PUBLISHED', `%${filter}%`, limit]);
      return r.rows.map(rowToPost);
    }
    const sql = `SELECT p.* FROM posts p WHERE p.org_id=${ctx.viewer.org_id} AND p.status='PUBLISHED' AND p.title ILIKE '%${filter}%' ORDER BY ${orderBy} LIMIT ${limit}`;
    const r = await pool.query(sql);
    return r.rows.map(rowToPost);
  },
  async searchPosts({ where }: any, ctx: Ctx) {
    requireViewer(ctx);
    const raw = where?.raw || '';
    if (SECURITY.VALIDATE_JSON_SCALAR && raw) throw new GraphQLError('raw operator is not allowed', { extensions: { code: 'BAD_USER_INPUT' } });
    const sql = SECURITY.USE_SAFE_SQL
      ? 'SELECT * FROM posts WHERE org_id=$1 AND status=$2 ORDER BY id LIMIT 20'
      : `SELECT * FROM posts WHERE org_id=${ctx.viewer.org_id} AND status='PUBLISHED' ${raw} ORDER BY id LIMIT 20`;
    const r = SECURITY.USE_SAFE_SQL ? await pool.query(sql, [ctx.viewer.org_id, 'PUBLISHED']) : await pool.query(sql);
    return r.rows.map(rowToPost);
  },
  async node({ id }: any, ctx: Ctx) {
    requireViewer(ctx);
    const decoded = Buffer.from(String(id), 'base64').toString('utf8');
    const [typ, rawId] = decoded.split(':');
    if (typ === 'Post') {
      const r = await pool.query('SELECT * FROM posts WHERE id=$1', [Number(rawId)]);
      const p = r.rows[0];
      if (!p) return null;
      if (SECURITY.NODE_CHECK_ORG && p.org_id !== ctx.viewer.org_id) return null;
      return rowToPost(p);
    }
    if (typ === 'User') {
      const u = await getUser(Number(rawId));
      if (!u) return null;
      if (SECURITY.NODE_CHECK_ORG && u.org_id !== ctx.viewer.org_id) return null;
      return rowToUser(u);
    }
    return null;
  },
  async linkPreview({ url }: any) { return safeFetch(url); },
  async billingBalance({ orgId }: any, ctx: Ctx) { requireViewer(ctx); const target = `${BILLING_URL}/balance?orgId=${encodeURIComponent(orgId || ctx.viewer.org_id)}`; return (await (await fetch(target)).text()); },
  async reportRun({ id }: any, ctx: Ctx) {
    requireViewer(ctx);
    const report = (await pool.query('SELECT * FROM reports WHERE id=$1', [Number(id)])).rows[0];
    if (!report) throw new GraphQLError('report not found', { extensions: { code: 'NOT_FOUND' } });
    if (SECURITY.USE_SAFE_SQL) {
      const r = await pool.query('SELECT title || chr(10) || body AS result FROM posts WHERE org_id=$1 AND title ILIKE $2 LIMIT 5', [ctx.viewer.org_id, `%${report.name}%`]);
      return { ...report, result: r.rows.map((x: any) => x.result).join('\n') };
    }
    const sql = `SELECT title || chr(10) || body AS result FROM posts WHERE org_id=${ctx.viewer.org_id} AND title ILIKE '%${report.name}%' LIMIT 5`;
    const r = await pool.query(sql);
    return { ...report, result: r.rows.map((x: any) => x.result).join('\n') };
  },
  async login({ email, password }: any, ctx: Ctx) {
    const key = `${ctx.ip}:${email}`;
    if (SECURITY.RATE_LIMIT_LOGIN && (loginFailures.get(key) || 0) > 4) throw new GraphQLError('Too many login attempts', { extensions: { code: 'RATE_LIMITED' } });
    const user = await getUserByEmail(email);
    if (!user) throw new GraphQLError(SECURITY.RATE_LIMIT_LOGIN ? 'Invalid credentials' : `No account exists for ${email}`, { extensions: { code: SECURITY.RATE_LIMIT_LOGIN ? 'BAD_CREDENTIALS' : 'USER_NOT_FOUND' } });
    if (user.password !== password) { loginFailures.set(key, (loginFailures.get(key) || 0) + 1); throw new GraphQLError(SECURITY.RATE_LIMIT_LOGIN ? 'Invalid credentials' : `Bad password for ${email}`, { extensions: { code: 'BAD_CREDENTIALS' } }); }
    loginFailures.delete(key);
    return { token: signUser(user), user: rowToUser(user) };
  },
  async updateProfile({ input }: any, ctx: Ctx) {
    requireViewer(ctx);
    if (SECURITY.MASS_ASSIGN_PROFILE) {
      const fields: string[] = []; const vals: any[] = [];
      const map: any = { displayName: 'display_name', email: 'email', role: 'role', isAdmin: 'is_admin', orgId: 'org_id', passwordHash: 'password_hash', resetToken: 'reset_token' };
      for (const [k, v] of Object.entries(input)) if (v !== undefined && map[k]) { vals.push(v); fields.push(`${map[k]}=$${vals.length}`); }
      vals.push(ctx.viewer.id);
      const r = await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id=$${vals.length} RETURNING *`, vals);
      return rowToUser(r.rows[0]);
    }
    const r = await pool.query('UPDATE users SET display_name=COALESCE($1, display_name) WHERE id=$2 RETURNING *', [input.displayName ?? null, ctx.viewer.id]);
    return rowToUser(r.rows[0]);
  },
  async updateEmail({ email }: any, ctx: Ctx) { requireViewer(ctx); const r = await pool.query('UPDATE users SET email=$1 WHERE id=$2 RETURNING *', [email, ctx.viewer.id]); return rowToUser(r.rows[0]); },
  async deleteOrganization({ id }: any, ctx: Ctx) { if (SECURITY.REQUIRE_ADMIN_DELETE_ORG) requireAdmin(ctx); else requireViewer(ctx); return { ok: true, message: `organization ${id} deletion accepted` }; },
  async createReport({ name }: any, ctx: Ctx) { requireViewer(ctx); const r = await pool.query('INSERT INTO reports(owner_id,name) VALUES($1,$2) RETURNING *', [ctx.viewer.id, name]); return r.rows[0]; },
  async exportReport({ format }: any, ctx: Ctx) {
    requireViewer(ctx);
    if (SECURITY.SAFE_EXPORT_COMMAND) {
      if (!['csv', 'json', 'txt'].includes(format)) throw new GraphQLError('unsupported format', { extensions: { code: 'BAD_USER_INPUT' } });
      const out = await execFileAsync('/bin/echo', [`export-${format}`]);
      return out.stdout.trim();
    }
    const out = await execAsync(`sh -c "echo export-${format}"`);
    return out.stdout.trim();
  },
  async addComment({ postId, body }: any, ctx: Ctx) { requireViewer(ctx); const r = await pool.query('INSERT INTO comments(post_id,author_id,body) VALUES($1,$2,$3) RETURNING *', [Number(postId), ctx.viewer.id, body]); return r.rows[0]; },
  async purchaseSeats({ quantity }: any, ctx: Ctx) {
    requireViewer(ctx);
    if (SECURITY.VALIDATE_SEATS && (!Number.isInteger(quantity) || quantity <= 0 || quantity > 100)) throw new GraphQLError('invalid quantity', { extensions: { code: 'BAD_USER_INPUT' } });
    await pool.query('UPDATE orgs SET seats_used=seats_used+$1 WHERE id=$2', [quantity, ctx.viewer.org_id]);
    return { ok: true, message: `purchased ${quantity}` };
  },
  async inviteUser({ email }: any, ctx: Ctx) {
    requireViewer(ctx);
    if (SECURITY.ATOMIC_INVITES) {
      const r = await pool.query('UPDATE orgs SET seats_used=seats_used+1 WHERE id=$1 AND seats_used < seat_limit RETURNING seats_used', [ctx.viewer.org_id]);
      if (r.rowCount === 0) throw new GraphQLError('seat limit reached', { extensions: { code: 'FORBIDDEN' } });
      await pool.query('INSERT INTO invitations(org_id,email) VALUES($1,$2)', [ctx.viewer.org_id, email]);
      return { ok: true, message: 'invited' };
    }
    const org = (await pool.query('SELECT * FROM orgs WHERE id=$1', [ctx.viewer.org_id])).rows[0];
    if (org.seats_used >= org.seat_limit) throw new GraphQLError('seat limit reached', { extensions: { code: 'FORBIDDEN' } });
    await new Promise(r => setTimeout(r, 80));
    await pool.query('INSERT INTO invitations(org_id,email) VALUES($1,$2)', [ctx.viewer.org_id, email]);
    await pool.query('UPDATE orgs SET seats_used=seats_used+1 WHERE id=$1', [ctx.viewer.org_id]);
    return { ok: true, message: 'invited' };
  },
  async uploadAvatar({ filename, content }: any, ctx: Ctx) {
    requireViewer(ctx);
    const base = '/tmp/graphql-uploads';
    await fs.mkdir(base, { recursive: true });
    const clean = SECURITY.SAFE_UPLOAD ? path.basename(filename).replace(/[^a-zA-Z0-9._-]/g, '_') : filename;
    const target = path.join(base, clean);
    if (SECURITY.SAFE_UPLOAD && !target.startsWith(base + path.sep)) throw new GraphQLError('invalid filename', { extensions: { code: 'BAD_USER_INPUT' } });
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, content);
    return target;
  },
  async ping({ message }: any) { return message || 'pong'; }
};

async function fieldResolver(source: any, args: any, ctx: Ctx, info: any) {
  const p = info.parentType.name; const f = info.fieldName;
  if (typeof source?.[f] === 'function') return source[f](args, ctx, info);
  if (p === 'User') {
    if (f === 'isAdmin') return !!source.is_admin;
    if (f === 'displayName') return source.display_name;
    if (f === 'organization') { const r = await pool.query('SELECT * FROM orgs WHERE id=$1', [source.org_id]); return rowToOrg(r.rows[0]); }
    if (['email', 'passwordHash', 'resetToken'].includes(f)) {
      const col: any = { passwordHash: 'password_hash', resetToken: 'reset_token', email: 'email' };
      if (SECURITY.MASK_USER_SECRETS && (!ctx.viewer || (ctx.viewer.id !== source.id && !ctx.viewer.is_admin))) return null;
      return source[col[f]];
    }
  }
  if (p === 'Organization' && f === 'posts') {
    if (SECURITY.FILTER_ORG_POSTS_FIELD) {
      const r = await pool.query("SELECT * FROM posts WHERE org_id=$1 AND status='PUBLISHED' ORDER BY id LIMIT $2", [source.id, Math.min(args.first || 20, 50)]);
      return r.rows.map(rowToPost);
    }
    const r = await pool.query('SELECT * FROM posts ORDER BY id LIMIT $1', [args.first || 20]);
    return r.rows.map(rowToPost);
  }
  if (p === 'Post') {
    if (f === 'author') { const u = await getUser(source.author_id); return u ? rowToUser(u) : null; }
    if (f === 'organization') { const r = await pool.query('SELECT * FROM orgs WHERE id=$1', [source.org_id]); return rowToOrg(r.rows[0]); }
  }
  if (p === 'Comment' && f === 'author') { const u = await getUser(source.author_id); return u ? rowToUser(u) : null; }
  return defaultFieldResolver(source, args, ctx, info);
}

function queryDepth(query: string) {
  let depth = 0, max = 0;
  for (const ch of query) { if (ch === '{') max = Math.max(max, ++depth); if (ch === '}') depth--; }
  return max;
}
function aliasCount(query: string) { return (query.match(/\b[a-zA-Z_][\w]*\s*:/g) || []).length; }
function formatErrors(errors: readonly any[] | undefined) {
  if (!errors) return undefined;
  return errors.map(e => {
    let msg = e.message || 'GraphQL error';
    if (!SECURITY.SHOW_SUGGESTIONS) msg = msg.replace(/ Did you mean[\s\S]*/m, '');
    if (!SECURITY.VERBOSE_ERRORS) return { message: msg, extensions: { code: e.extensions?.code || 'GRAPHQL_ERROR' } };
    return { message: msg, extensions: { ...e.extensions, stack: e.stack, sql: e.originalError?.query || e.source?.body } };
  });
}

async function executeGraphQL(op: GqlReq, ctx: Ctx, forceSafe = false) {
  const safe = forceSafe;
  let query = op.query;
  const hash = op.extensions?.persistedQuery?.sha256Hash;
  if (hash) {
    if (query) {
      if ((SECURITY.VERIFY_APQ_HASH || safe) && crypto.createHash('sha256').update(query).digest('hex') !== hash) return { errors: [{ message: 'PersistedQuery hash mismatch', extensions: { code: 'BAD_REQUEST' } }] };
      apq.set(hash, query);
    } else query = apq.get(hash);
  }
  if (!query) return { errors: [{ message: 'PersistedQueryNotFound', extensions: { code: 'PERSISTED_QUERY_NOT_FOUND' } }] };
  const limited = safe || SECURITY.ENFORCE_DEPTH_LIMIT || SECURITY.ENFORCE_COST_LIMIT || SECURITY.LIMIT_ALIASES;
  if ((!SECURITY.ALLOW_INTROSPECTION || safe) && /__schema|__type/.test(query)) return { errors: [{ message: 'GraphQL introspection is not allowed', extensions: { code: 'INTROSPECTION_DISABLED' } }] };
  if (limited && queryDepth(query) > 10) return { errors: [{ message: 'Query depth limit exceeded', extensions: { code: 'DEPTH_LIMIT' } }] };
  if (limited && (/first\s*:\s*(\d{2,})/.test(query) && Number(query.match(/first\s*:\s*(\d{2,})/)?.[1]) > 50)) return { errors: [{ message: 'Query cost limit exceeded', extensions: { code: 'COST_LIMIT' } }] };
  if ((safe || SECURITY.LIMIT_ALIASES) && aliasCount(query) > 20) return { errors: [{ message: 'Too many operation aliases', extensions: { code: 'ALIAS_LIMIT' } }] };
  const result = await graphql({ schema, source: query, rootValue: root, contextValue: ctx, variableValues: op.variables, operationName: op.operationName, fieldResolver });
  return { ...result, errors: formatErrors(result.errors) };
}

async function bodyJson(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  const raw = Buffer.concat(chunks).toString('utf8');
  return raw ? JSON.parse(raw) : {};
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse, forceSafe = false) {
  const url = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
  if (req.method === 'OPTIONS') { const h: Record<string, string> = {}; applyCors(h, String(req.headers.origin || '')); res.writeHead(204, h); res.end(); return; }
  let body: any;
  if (req.method === 'GET') {
    const query = url.searchParams.get('query') || '';
    if ((SECURITY.ALLOW_GET_MUTATIONS && !forceSafe) === false && /^\s*mutation\b/.test(query)) { writeJson(res, 405, { errors: [{ message: 'GET mutations are not allowed' }] }, String(req.headers.origin || '')); return; }
    body = { query, variables: url.searchParams.get('variables') ? JSON.parse(url.searchParams.get('variables')!) : undefined };
  } else body = await bodyJson(req);
  const ip = req.socket.remoteAddress || 'local';
  if (Array.isArray(body)) {
    if ((SECURITY.LIMIT_BATCH || forceSafe) && body.length > 1) { writeJson(res, 400, { errors: [{ message: 'GraphQL batching is disabled' }] }, String(req.headers.origin || '')); return; }
    const requestViewer = await viewerFromAuth(String(req.headers.authorization || body[0]?.extensions?.authorization || ''));
    const out = [];
    for (const op of body) {
      const viewer = (SECURITY.PER_OPERATION_CONTEXT || forceSafe) ? await viewerFromAuth(String(op.extensions?.authorization || req.headers.authorization || '')) : requestViewer;
      out.push(await executeGraphQL(op, { viewer, ip }, forceSafe));
    }
    writeJson(res, 200, out, String(req.headers.origin || '')); return;
  }
  const viewer = await viewerFromAuth(String(req.headers.authorization || body?.extensions?.authorization || ''));
  writeJson(res, 200, await executeGraphQL(body, { viewer, ip }, forceSafe), String(req.headers.origin || ''));
}

async function handleVerify(req: IncomingMessage, res: ServerResponse, url: URL) {
  if (url.pathname.endsWith('/health')) {
    try { await pool.query('SELECT 1'); writeJson(res, 200, { status: 'ok', db: 'ok', graphql: true }); } catch (e: any) { writeJson(res, 500, { status: 'bad', db: e.message }); }
    return;
  }
  if (req.headers['x-verify-token'] !== VERIFY_TOKEN) { writeJson(res, 403, { error: 'forbidden' }); return; }
  if (url.pathname.endsWith('/reset')) { await resetVerifyState(); writeJson(res, 200, { ok: true }); return; }
  if (url.pathname.endsWith('/user')) { const u = await getUserByEmail(url.searchParams.get('email') || ''); writeJson(res, 200, u ? { exists: true, id: u.id, role: u.role, isAdmin: !!u.is_admin, verified: true, orgSlug: u.org_slug } : { exists: false }); return; }
  if (url.pathname.endsWith('/post')) {
    const r = await pool.query('SELECT p.*, u.email AS author_email, o.slug AS org_slug FROM posts p JOIN users u ON u.id=p.author_id JOIN orgs o ON o.id=p.org_id WHERE p.slug=$1', [url.searchParams.get('slug') || '']);
    const p = r.rows[0]; writeJson(res, 200, p ? { exists: true, id: p.id, status: p.status, authorEmail: p.author_email, orgSlug: p.org_slug, body: p.body } : { exists: false }); return;
  }
  writeJson(res, 404, { error: 'not found' });
}

function escapeHtml(s: string) { return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' } as any)[c]); }
async function handleHtmlExport(req: IncomingMessage, res: ServerResponse) {
  const r = await pool.query('SELECT body FROM comments ORDER BY id DESC LIMIT 20');
  const body = r.rows.map((x: any) => SECURITY.ESCAPE_HTML_EXPORT ? escapeHtml(x.body) : x.body).join('\n');
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<html><body>${body}</body></html>`);
}

async function handle(req: IncomingMessage, res: ServerResponse) {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
    if (url.pathname.startsWith('/api/_verify/')) return handleVerify(req, res, url);
    if (url.pathname === '/graphql') return handleGraphQL(req, res, false);
    if (url.pathname === '/graphql/public') return handleGraphQL(req, res, true);
    if (url.pathname === '/api/export') return handleHtmlExport(req, res);
    if (url.pathname === '/auth/callback') {
      const next = url.searchParams.get('next') || '/';
      const safeNext = SECURITY.SAFE_REDIRECT && !next.startsWith('/') ? '/' : next;
      res.writeHead(302, { location: safeNext }); res.end(); return;
    }
    if (url.pathname === '/' && SECURITY.EXPOSE_LANDING) { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<h1>Apollo GraphQL landing page</h1><p>Tracing enabled</p>'); return; }
    writeJson(res, 404, { error: 'not found' });
  } catch (e: any) {
    if (SECURITY.VERBOSE_ERRORS) writeJson(res, 500, { error: e.message, stack: e.stack, sql: e.query });
    else writeJson(res, 500, { error: 'internal server error' });
  }
}

function startWs(server: http.Server) {
  const wss = new WebSocketServer({ server, path: '/graphql/ws' });
  wss.on('connection', ws => {
    let viewer: Viewer = null;
    ws.on('message', async raw => {
      const msg = JSON.parse(String(raw));
      if (msg.type === 'connection_init') { viewer = await viewerFromAuth(msg.payload?.Authorization || msg.payload?.authorization || ''); ws.send(JSON.stringify({ type: 'connection_ack' })); return; }
      if (msg.type === 'subscribe') {
        const orgId = Number(msg.payload?.variables?.orgId || 2);
        if (SECURITY.SUBSCRIBE_AUTH_IN_SUBSCRIBE && (!viewer || viewer.org_id !== orgId)) { ws.send(JSON.stringify({ id: msg.id, type: 'error', payload: [{ message: 'forbidden' }] })); return; }
        const r = await pool.query('SELECT * FROM posts WHERE org_id=$1 ORDER BY id DESC LIMIT 1', [orgId]);
        ws.send(JSON.stringify({ id: msg.id, type: 'next', payload: { data: { postUpdated: rowToPost(r.rows[0]) } } }));
        ws.send(JSON.stringify({ id: msg.id, type: 'complete' }));
      }
    });
  });
}

migrateAndSeed().then(() => {
  const server = http.createServer(handle);
  startWs(server);
  server.listen(PORT, '0.0.0.0', () => console.log(`graphql benchmark app listening on ${PORT}`));
}).catch(err => { console.error(err); process.exit(1); });
