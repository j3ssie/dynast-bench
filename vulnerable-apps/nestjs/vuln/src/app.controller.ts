import {
  BadRequestException,
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  Param,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import hbs from 'hbs';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { Request, Response } from 'express';

const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://bench:bench@127.0.0.1:5432/bench' });
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'benchsecret';
const JWT_SECRET = process.env.JWT_SECRET || 'hardcoded-weak-secret';
const ATTACHMENT_ROOT = process.env.ATTACHMENT_ROOT || '/app/attachments';
const UPLOAD_ROOT = process.env.UPLOAD_ROOT || '/app/uploads';

function md5(s: string) {
  return crypto.createHash('md5').update(s).digest('hex');
}
function escapeHtml(s: string) {
  return String(s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] as string));
}
function verifyHeader(headers: any) {
  return headers['x-verify-token'] === VERIFY_TOKEN;
}
function parseNoneJwt(token: string): any {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  if (header.alg === 'none') return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  return jwt.verify(token, JWT_SECRET, { ignoreExpiration: true }) as any;
}
async function currentUser(req: Request): Promise<any | null> {
  const id = (req.session as any)?.userId;
  if (!id) return null;
  const r = await pool.query('SELECT u.*, o.slug AS org_slug FROM users u JOIN orgs o ON o.id = u.org_id WHERE u.id=$1', [id]);
  return r.rows[0] || null;
}
function uploadName(_req: Request, file: Express.Multer.File, cb: (error: Error | null, filename: string) => void) {
  const clean = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, '_');
  cb(null, Date.now() + '-' + clean);
}

@Controller()
export class AppController {
  @Get('/api/_verify/health')
  async health() {
    await pool.query('SELECT 1');
    return { status: 'ok', db: 'ok', redis: 'configured' };
  }

  @Get('/api/_verify/user')
  async verifyUser(@Headers() headers: any, @Query('email') email: string, @Res() res: Response) {
    if (!verifyHeader(headers)) return res.status(403).json({ error: 'forbidden' });
    const r = await pool.query('SELECT u.*, o.slug AS org_slug FROM users u JOIN orgs o ON o.id=u.org_id WHERE email=$1', [email]);
    const u = r.rows[0];
    return res.json({ exists: !!u, id: u?.id || '', role: u?.role || '', isAdmin: !!u?.is_admin, verified: !!u?.verified, orgSlug: u?.org_slug || '' });
  }

  @Get('/api/_verify/post')
  async verifyPost(@Headers() headers: any, @Query('slug') slug: string, @Res() res: Response) {
    if (!verifyHeader(headers)) return res.status(403).json({ error: 'forbidden' });
    const r = await pool.query('SELECT p.*, u.email AS author_email, o.slug AS org_slug FROM posts p JOIN users u ON u.id=p.author_id JOIN orgs o ON o.id=p.org_id WHERE p.slug=$1', [slug]);
    const p = r.rows[0];
    return res.json({ exists: !!p, id: p?.id || '', slug: p?.slug || '', status: p?.status || '', authorEmail: p?.author_email || '', orgSlug: p?.org_slug || '' });
  }

  @Get('/api/_verify/org')
  async verifyOrg(@Headers() headers: any, @Query('slug') slug: string, @Res() res: Response) {
    if (!verifyHeader(headers)) return res.status(403).json({ error: 'forbidden' });
    const r = await pool.query('SELECT *, (SELECT COUNT(*)::int FROM invites WHERE org_id=orgs.id) AS invite_count FROM orgs WHERE slug=$1', [slug]);
    const o = r.rows[0];
    return res.json({ exists: !!o, id: o?.id || '', seatLimit: o?.seat_limit || 0, seatsUsed: o?.seats_used || 0, inviteCount: o?.invite_count || 0 });
  }

  @Get('/api/_verify/invites')
  async verifyInvites(@Headers() headers: any, @Query('prefix') prefix: string, @Res() res: Response) {
    if (!verifyHeader(headers)) return res.status(403).json({ error: 'forbidden' });
    const r = await pool.query('SELECT COUNT(*)::int AS count FROM invites WHERE email LIKE $1', [`${prefix || ''}%`]);
    return res.json({ count: r.rows[0]?.count || 0 });
  }

  @Delete('/api/_verify/invites')
  async cleanupInvites(@Headers() headers: any, @Query('prefix') prefix: string, @Res() res: Response) {
    if (!verifyHeader(headers)) return res.status(403).json({ error: 'forbidden' });
    await pool.query('DELETE FROM invites WHERE email LIKE $1', [`${prefix || 'race'}%`]);
    return res.json({ ok: true });
  }

  @Get('/login')
  loginPage(@Query('next') next: string, @Res() res: Response) {
    if (next) return res.redirect(next);
    return res.type('html').send('<form method="post" action="/api/auth/login">login</form>');
  }

  @Post('/api/auth/login')
  @HttpCode(200)
  async login(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [body.email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'user not found' });
    if (!(await bcrypt.compare(body.password || '', user.password_hash))) return res.status(401).json({ error: 'bad password' });
    (req.session as any).userId = user.id;
    (req.session as any).role = user.role;
    (req.session as any).orgId = user.org_id;
    return res.json({ ok: true, id: user.id, role: user.role });
  }

  @Post('/api/auth/token')
  @HttpCode(200)
  async token(@Body() body: any, @Res() res: Response) {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [body.email]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(body.password || '', user.password_hash))) return res.status(401).json({ error: 'invalid' });
    const token = jwt.sign({ sub: user.id, email: user.email, role: user.role, isAdmin: user.is_admin, orgId: user.org_id }, JWT_SECRET, { noTimestamp: true });
    return res.json({ token });
  }

  @Post('/api/auth/reset')
  @HttpCode(200)
  async reset(@Body() body: any) {
    const token = md5(`${body.email}:${Math.floor(Date.now() / 1000)}`);
    await pool.query('INSERT INTO reset_tokens(email, token) VALUES ($1,$2)', [body.email, token]);
    return { ok: true, token };
  }

  @Get('/api/reports/admin-summary')
  async adminSummary(@Headers('authorization') auth: string, @Res() res: Response) {
    try {
      const token = (auth || '').replace(/^Bearer\s+/i, '');
      const payload = parseNoneJwt(token);
      if (!payload || (payload.role !== 'admin' && !payload.isAdmin)) return res.status(403).json({ error: 'admin only' });
      return res.json({ ok: true, secret: 'ADMIN-SUMMARY-NESTJS' });
    } catch (e: any) {
      return res.status(401).json({ error: e.message, stack: e.stack });
    }
  }

  @Get('/api/posts/search')
  async search(@Query('q') q = '', @Res() res: Response) {
    const sql = `SELECT id, slug, title, body, status FROM posts WHERE status='PUBLISHED' AND (title ILIKE '%${q}%' OR body ILIKE '%${q}%') ORDER BY id`;
    const r = await pool.query(sql);
    return res.json({ rows: r.rows });
  }

  @Get('/search')
  reflectedSearch(@Query('q') q = '', @Res() res: Response) {
    return res.type('html').send(`<html><body><h1>Search</h1><p>You searched for ${q}</p></body></html>`);
  }

  @Get('/api/posts/:id')
  async getPost(@Param('id') id: string, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const r = await pool.query('SELECT * FROM posts WHERE id=$1', [id]);
    const post = r.rows[0];
    if (!post) return res.status(404).json({ error: 'not found' });
    return res.json(post);
  }

  @Patch('/api/users/me')
  async updateMe(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const data: any = { ...body };
    if ('isAdmin' in data) { data.is_admin = data.isAdmin; delete data.isAdmin; }
    const keys = Object.keys(data).filter((k) => ['email', 'display_name', 'role', 'is_admin', 'verified', 'org_id'].includes(k));
    if (!keys.length) return res.json({ ok: true });
    const sets = keys.map((k, i) => `${k}=$${i + 1}`).join(', ');
    await pool.query(`UPDATE users SET ${sets} WHERE id=$${keys.length + 1}`, [...keys.map((k) => data[k]), user.id]);
    return res.json({ ok: true, updated: keys });
  }

  @Patch('/api/users/profile')
  async updateProfileNearMiss(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    await pool.query('UPDATE users SET display_name=$1 WHERE id=$2', [String(body.displayName || '').slice(0, 80), user.id]);
    return res.json({ ok: true });
  }

  @Get('/api/admin/users')
  async adminUsers(@Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const r = await pool.query('SELECT email, role, org_id FROM users ORDER BY id');
    return res.json({ users: r.rows });
  }

  @Get('/api/admin/internal-health')
  async xffAdmin(@Req() req: Request, @Headers('x-forwarded-for') xff: string, @Res() res: Response) {
    const ip = (xff || req.ip || '').split(',')[0].trim();
    if (ip !== '127.0.0.1' && ip !== '::1') return res.status(403).json({ error: 'local only', ip });
    return res.json({ ok: true, secret: 'XFF-ADMIN-BYPASS-NESTJS' });
  }

  @Post('/api/reports/render')
  @HttpCode(200)
  renderReport(@Body() body: any, @Res() res: Response) {
    const tmpl = hbs.compile(String(body.template || ''));
    return res.type('html').send(tmpl({ user: body.user || {}, message: body.message || '', secrets: { flag: 'HBS-SSTI-SECRET' } }));
  }

  @Post('/api/reports/render-safe-preview')
  @HttpCode(200)
  renderSafePreview(@Body() body: any, @Res() res: Response) {
    const tmpl = hbs.compile('<p>{{message}}</p>');
    return res.type('html').send(tmpl({ message: body.message || '' }));
  }

  @Post('/api/posts/:id/comments')
  @HttpCode(200)
  async addComment(@Param('id') id: string, @Body() body: any, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    await pool.query('INSERT INTO comments(post_id, body) VALUES ($1,$2)', [id, String(body.body || '')]);
    return res.json({ ok: true });
  }

  @Get('/posts/:id/html')
  async postHtml(@Param('id') id: string, @Res() res: Response) {
    const post = (await pool.query('SELECT * FROM posts WHERE id=$1', [id])).rows[0];
    const comments = (await pool.query('SELECT body FROM comments WHERE post_id=$1 ORDER BY id', [id])).rows;
    const html = `<html><body><h1>{{title}}</h1>${comments.map((c) => `<div class="comment">{{{body_${crypto.createHash('sha1').update(c.body).digest('hex')}}}}</div>`).join('')}</body></html>`;
    const ctx: any = { title: post?.title || '' };
    for (const c of comments) ctx[`body_${crypto.createHash('sha1').update(c.body).digest('hex')}`] = c.body;
    return res.type('html').send(hbs.compile(html)(ctx));
  }

  @Post('/api/webhooks/test')
  @HttpCode(200)
  async webhook(@Body() body: any, @Res() res: Response) {
    const r = await fetch(String(body.url));
    const text = await r.text();
    return res.json({ status: r.status, body: text.slice(0, 600) });
  }

  @Post('/api/reports/import')
  @HttpCode(200)
  importReport(@Body() body: any) {
    const state = String(body.state || '{}');
    let parsed: any;
    if (state.startsWith('_$$ND_FUNC$$_')) parsed = eval(`(${state.slice('_$$ND_FUNC$$_'.length)})`);
    else parsed = JSON.parse(state);
    return { ok: true, parsed };
  }

  @Post('/api/reports/import-json')
  @HttpCode(200)
  importJsonNearMiss(@Body() body: any) {
    return { ok: true, parsed: JSON.parse(String(body.state || '{}')) };
  }

  @Post('/api/settings/email')
  @HttpCode(200)
  async csrfSettings(@Req() req: Request, @Body() body: any, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    return res.json({ ok: true, changedTo: body.email });
  }

  @Get('/api/attachments/download')
  async download(@Query('name') name: string, @Res() res: Response) {
    const file = path.join(ATTACHMENT_ROOT, name || 'welcome.txt');
    return res.type('text/plain').send(fs.readFileSync(file, 'utf8'));
  }

  @Get('/api/attachments/download-safe-preview')
  async downloadNearMiss(@Query('name') name: string, @Res() res: Response) {
    const file = path.resolve(ATTACHMENT_ROOT, path.basename(name || 'welcome.txt'));
    if (!file.startsWith(path.resolve(ATTACHMENT_ROOT) + path.sep)) throw new BadRequestException('bad path');
    return res.type('text/plain').send(fs.readFileSync(file, 'utf8'));
  }

  @Post('/api/avatar')
  @UseInterceptors(FileInterceptor('file', { storage: diskStorage({ destination: UPLOAD_ROOT, filename: uploadName }) }))
  async uploadAvatar(@UploadedFile() file: Express.Multer.File, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    await pool.query('INSERT INTO attachments(filename, path, org_id, owner_id) VALUES ($1,$2,$3,$4)', [file.filename, `/uploads/${file.filename}`, user.org_id, user.id]);
    return res.json({ ok: true, url: `/uploads/${file.filename}`, mimetype: file.mimetype });
  }

  @Post('/api/billing/seats')
  @HttpCode(200)
  async billing(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const delta = Number(body.delta ?? body.seats ?? 0);
    const r = await pool.query('UPDATE orgs SET seats_used = seats_used + $1 WHERE id=$2 RETURNING seats_used', [delta, user.org_id]);
    return res.json({ ok: true, seatsUsed: r.rows[0].seats_used });
  }

  @Post('/api/invites')
  @HttpCode(200)
  async invite(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const org = (await pool.query('SELECT seat_limit FROM orgs WHERE id=$1', [user.org_id])).rows[0];
    const count = Number((await pool.query('SELECT COUNT(*) AS c FROM invites WHERE org_id=$1', [user.org_id])).rows[0].c);
    if (count >= org.seat_limit) return res.status(409).json({ error: 'seat limit reached' });
    await new Promise((resolve) => setTimeout(resolve, 150));
    await pool.query('INSERT INTO invites(email, org_id) VALUES ($1,$2)', [String(body.email), user.org_id]);
    return res.json({ ok: true });
  }
}
