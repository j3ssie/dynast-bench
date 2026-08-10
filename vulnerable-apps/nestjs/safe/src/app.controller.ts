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
import { execSync } from 'child_process';
import type { Request, Response } from 'express';

// FIXED SSPP-001: the merge refuses prototype-walking keys and merges into a
// null-prototype target, so nothing can reach Object.prototype.
function _ssppMerge(dst: any, src: any): void {
  for (const key of Object.keys(src)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    const v = src[key];
    if (v && typeof v === 'object' && dst[key] && typeof dst[key] === 'object') {
      _ssppMerge(dst[key], v);
    } else {
      dst[key] = v;
    }
  }
}

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
  if (header.alg === 'none') throw new Error('unsigned tokens rejected');
  return jwt.verify(token, JWT_SECRET) as any;
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

// FIXED SIGNUP-TOKEN-001: the verification code is a CSPRNG draw, unrelated to
// when the signup started, so it can only be received in the email.
function signupCode(): string {
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}
function inviteToken(): string {
  return crypto.randomBytes(32).toString('hex');
}
const SIGNUP_RESEND = new Map<string, number>();

// The multi-step signup wizard page (see the vuln twin for the full comment).
const WIZARD_HTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Create account</title></head><body>
<h1>Create your account</h1><p><small data-step>step 1 of 4</small></p>
<div data-ref-banner></div><div data-panel></div><p data-msg></p>
<button type="button" data-advanced>Advanced</button><div data-advanced-panel></div>
<div data-notice></div>
<script>
  // FIXED DOMXSS-001: the fragment is rendered as text via textContent, never HTML.
  (function(){function ap(){var raw=decodeURIComponent((location.hash||'').replace(/^#/,''));
    document.querySelector('[data-ref-banner]').textContent=raw?('Referred by '+raw):'';}
    ap();window.addEventListener('hashchange',ap);})();
  // FIXED POSTMSG-001: the bridge rejects a foreign origin and renders text.
  window.addEventListener('message',function(ev){if(ev.origin!==window.location.origin)return;var d=ev.data||{};
    if(d.type==='taskflow:notice'){document.querySelector('[data-notice]').textContent=String(d.text||'');}});
  var API='';var ROUTES={start:['api','signup','start'],verify:['api','signup','verify'],
    profile:['api','signup','profile'],complete:['api','signup','complete'],
    resend:['api','signup','resend'],report:['api','tools','report']};
  function url(n){return [API].concat(ROUTES[n]).join('/');}
  var draftId=null,email='';var panel=document.querySelector('[data-panel]');
  var msg=document.querySelector('[data-msg]');var stepLabel=document.querySelector('[data-step]');
  function post(n,b){return fetch(url(n),{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify(b)}).then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};});});}
  function render(s){var f={1:'<form data-f="start"><input name="email" placeholder="work email"><button>Continue</button></form>',
    2:'<form data-f="verify"><input name="code" placeholder="6-digit code"><button>Verify</button> <button type="button" data-resend>Resend</button></form>',
    3:'<form data-f="profile"><input name="display_name" placeholder="display name"><button>Continue</button></form>',
    4:'<form data-f="complete"><input name="password" type="password" placeholder="choose a password"><button>Finish</button></form>'};
    stepLabel.textContent='step '+s+' of 4';panel.innerHTML=f[s];}
  panel.addEventListener('submit',function(e){e.preventDefault();var f=e.target.getAttribute('data-f');
    var fd=new FormData(e.target);
    if(f==='start'){email=fd.get('email');post('start',{email:email}).then(function(r){
      if(!r.ok){msg.textContent=r.j.error||'could not start';return;}draftId=r.j.draftId;
      msg.textContent='We emailed you a 6-digit code.';render(2);});}
    else if(f==='verify'){post('verify',{draftId:draftId,code:fd.get('code')}).then(function(r){
      if(!r.ok){msg.textContent=r.j.error||'could not verify';return;}msg.textContent='';render(3);});}
    else if(f==='profile'){post('profile',{draftId:draftId,display_name:fd.get('display_name')}).then(function(r){
      if(!r.ok){msg.textContent=r.j.error||'could not save';return;}msg.textContent='';render(4);});}
    else if(f==='complete'){post('complete',{draftId:draftId,password:fd.get('password')}).then(function(r){
      msg.textContent=r.ok?('Welcome, '+r.j.email+' ('+r.j.role+').'):(r.j.error||'could not finish');});}});
  panel.addEventListener('click',function(e){if(e.target.hasAttribute('data-resend')){
    post('resend',{email:email}).then(function(){msg.textContent='If that signup exists, a code is on its way.';});}});
  document.querySelector('[data-advanced]').addEventListener('click',function(){
    var ap=document.querySelector('[data-advanced-panel]');
    ap.innerHTML='<h3>Report builder</h3><input data-formula value="row.title.length"> <button type="button" data-run>Run</button><pre data-out></pre>';
    ap.querySelector('[data-run]').addEventListener('click',function(){
      fetch(url('report'),{method:'POST',headers:{'content-type':'application/json'},
        body:JSON.stringify({formula:ap.querySelector('[data-formula]').value})}).then(function(r){return r.text();})
        .then(function(t){ap.querySelector('[data-out]').textContent=t;});});});
  render(1);
</script></body></html>`;

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
    if (next && next.startsWith('/')) return res.redirect(next);
    return res.type('html').send('<form method="post" action="/api/auth/login">login</form>');
  }

  @Post('/api/auth/login')
  @HttpCode(200)
  async login(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [body.email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    if (!(await bcrypt.compare(body.password || '', user.password_hash))) return res.status(401).json({ error: 'invalid credentials' });
    return req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'session error' });
      (req.session as any).userId = user.id;
      (req.session as any).role = user.role;
      (req.session as any).orgId = user.org_id;
      return res.json({ ok: true, id: user.id, role: user.role });
    });
  }

  @Post('/api/auth/token')
  @HttpCode(200)
  async token(@Body() body: any, @Res() res: Response) {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [body.email]);
    const user = r.rows[0];
    if (!user || !(await bcrypt.compare(body.password || '', user.password_hash))) return res.status(401).json({ error: 'invalid' });
    const token = jwt.sign({ sub: user.id, email: user.email, role: user.role, isAdmin: user.is_admin, orgId: user.org_id }, JWT_SECRET, { expiresIn: '15m' });
    return res.json({ token });
  }

  @Post('/api/auth/reset')
  @HttpCode(200)
  async reset(@Body() body: any) {
    const token = crypto.randomBytes(24).toString('hex');
    await pool.query('INSERT INTO reset_tokens(email, token) VALUES ($1,$2)', [body.email, token]);
    return { ok: true, delivered: true };
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
    const r = await pool.query("SELECT id, slug, title, body, status FROM posts WHERE status='PUBLISHED' AND (title ILIKE $1 OR body ILIKE $1) ORDER BY id", [`%${q}%`]);
    return res.json({ rows: r.rows });
  }

  @Get('/search')
  reflectedSearch(@Query('q') q = '', @Res() res: Response) {
    return res.type('html').send(`<html><body><h1>Search</h1><p>You searched for ${escapeHtml(q)}</p></body></html>`);
  }

  @Get('/api/posts/:id')
  async getPost(@Param('id') id: string, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const r = await pool.query("SELECT * FROM posts WHERE id=$1 AND org_id=$2 AND status='PUBLISHED'", [id, user.org_id]);
    const post = r.rows[0];
    if (!post) return res.status(404).json({ error: 'not found' });
    return res.json(post);
  }

  @Patch('/api/users/me')
  async updateMe(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const data: any = {};
    if (typeof body.displayName === 'string') data.display_name = body.displayName.slice(0, 80);
    if (typeof body.email === 'string' && body.email.endsWith('@bench.local')) data.email = body.email;
    const keys = Object.keys(data);
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
    if (user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
    const r = await pool.query('SELECT email, role, org_id FROM users ORDER BY id');
    return res.json({ users: r.rows });
  }

  @Get('/api/admin/internal-health')
  async xffAdmin(@Req() req: Request, @Headers('x-forwarded-for') xff: string, @Res() res: Response) {
    const ip = req.socket.remoteAddress || '';
    if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1') return res.status(403).json({ error: 'local only' });
    return res.json({ ok: true, secret: 'XFF-ADMIN-BYPASS-NESTJS' });
  }

  @Post('/api/reports/render')
  @HttpCode(200)
  renderReport(@Body() body: any, @Res() res: Response) {
    const tmpl = hbs.compile('<p>{{message}}</p>');
    return res.type('html').send(tmpl({ message: body.message || '' }));
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
    const html = `<html><body><h1>{{title}}</h1>${comments.map((c) => `<div class="comment">{{body_${crypto.createHash('sha1').update(c.body).digest('hex')}}}</div>`).join('')}</body></html>`;
    const ctx: any = { title: post?.title || '' };
    for (const c of comments) ctx[`body_${crypto.createHash('sha1').update(c.body).digest('hex')}`] = c.body;
    return res.type('html').send(hbs.compile(html)(ctx));
  }

  @Post('/api/webhooks/test')
  @HttpCode(200)
  async webhook(@Body() body: any, @Res() res: Response) {
    const target = new URL(String(body.url));
    if (!['example.com', 'www.example.com'].includes(target.hostname)) throw new BadRequestException('host not allowed');
    const r = await fetch(target.toString());
    const text = await r.text();
    return res.json({ status: r.status, body: text.slice(0, 600) });
  }

  @Post('/api/reports/import')
  @HttpCode(200)
  importReport(@Body() body: any) {
    const state = String(body.state || '{}');
    const parsed = JSON.parse(state);
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
    if (req.header('x-csrf-token') !== 'known-token') return res.status(403).json({ error: 'csrf required' });
    return res.json({ ok: true, changedTo: body.email });
  }

  @Get('/api/attachments/download')
  async download(@Query('name') name: string, @Res() res: Response) {
    const base = path.resolve(ATTACHMENT_ROOT);
    const file = path.resolve(base, name || 'welcome.txt');
    if (!file.startsWith(base + path.sep)) throw new BadRequestException('bad path');
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
    if (!['image/png', 'image/jpeg'].includes(file.mimetype)) { fs.unlinkSync(file.path); return res.status(400).json({ error: 'unsupported type' }); }
    await pool.query('INSERT INTO attachments(filename, path, org_id, owner_id) VALUES ($1,$2,$3,$4)', [file.filename, `/uploads/${file.filename}`, user.org_id, user.id]);
    return res.json({ ok: true, url: `/uploads/${file.filename}`, mimetype: file.mimetype });
  }

  @Post('/api/billing/seats')
  @HttpCode(200)
  async billing(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const delta = Number(body.delta ?? body.seats ?? 0);
    if (!Number.isInteger(delta) || delta < 1 || delta > 3) return res.status(400).json({ error: 'invalid seat delta' });
    const r = await pool.query('UPDATE orgs SET seats_used = LEAST(seat_limit, seats_used + $1) WHERE id=$2 RETURNING seats_used', [delta, user.org_id]);
    return res.json({ ok: true, seatsUsed: r.rows[0].seats_used });
  }

  @Post('/api/invites')
  @HttpCode(200)
  async invite(@Body() body: any, @Req() req: Request, @Res() res: Response) {
    const user = await currentUser(req);
    if (!user) return res.status(401).json({ error: 'login required' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const org = (await client.query('SELECT seat_limit FROM orgs WHERE id=$1 FOR UPDATE', [user.org_id])).rows[0];
      const count = Number((await client.query('SELECT COUNT(*) AS c FROM invites WHERE org_id=$1', [user.org_id])).rows[0].c);
      if (count >= org.seat_limit) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'seat limit reached' }); }
      await client.query('INSERT INTO invites(email, org_id) VALUES ($1,$2)', [String(body.email), user.org_id]);
      await client.query('COMMIT');
      return res.json({ ok: true });
    } finally { client.release(); }
  }

  // ---- multi-step signup wizard (client-driven; endpoints appear in no HTML) ----

  @Get('/signup')
  wizard(@Res() res: Response) {
    return res.type('html').send(WIZARD_HTML);
  }

  // FIXED SIGNUP-ENUM-001: step 1 answers the same way whether or not the address
  // is already registered - always 200 with a draft id.
  @Post('/api/signup/start')
  @HttpCode(200)
  async signupStart(@Body() body: any, @Res() res: Response) {
    const email = String(body.email || '');
    if (!email) return res.status(400).json({ error: 'email required' });
    const r = await pool.query('INSERT INTO signup_drafts(email, code) VALUES ($1,$2) RETURNING id', [email, signupCode()]);
    return res.json({ draftId: r.rows[0].id, step: 'verify' });
  }

  @Post('/api/signup/verify')
  @HttpCode(200)
  async signupVerify(@Body() body: any, @Res() res: Response) {
    const d = (await pool.query('SELECT * FROM signup_drafts WHERE id=$1', [body.draftId])).rows[0];
    if (!d) return res.status(404).json({ error: 'unknown draft' });
    if (d.code !== String(body.code ?? '')) return res.status(400).json({ error: 'incorrect code' });
    await pool.query('UPDATE signup_drafts SET verified=TRUE WHERE id=$1', [d.id]);
    return res.json({ ok: true, step: 'profile' });
  }

  // FIXED SIGNUP-MASSASSIGN-001: only the one field this step owns is written;
  // role and org_slug are never client-writable.
  @Post('/api/signup/profile')
  @HttpCode(200)
  async signupProfile(@Body() body: any, @Res() res: Response) {
    const d = (await pool.query('SELECT * FROM signup_drafts WHERE id=$1', [body.draftId])).rows[0];
    if (!d) return res.status(404).json({ error: 'unknown draft' });
    await pool.query('UPDATE signup_drafts SET display_name=$1 WHERE id=$2', [String(body.display_name ?? ''), d.id]);
    const updated = (await pool.query('SELECT display_name FROM signup_drafts WHERE id=$1', [d.id])).rows[0];
    return res.json({ ok: true, step: 'complete', displayName: updated.display_name });
  }

  // FIXED SIGNUP-STEPSKIP-001: the final step enforces the verified state, so a
  // draft that never verified cannot be completed.
  @Post('/api/signup/complete')
  @HttpCode(200)
  async signupComplete(@Body() body: any, @Res() res: Response) {
    const d = (await pool.query('SELECT * FROM signup_drafts WHERE id=$1', [body.draftId])).rows[0];
    if (!d) return res.status(404).json({ error: 'unknown draft' });
    if (!d.verified) return res.status(403).json({ error: 'email not verified' });
    if (d.completed) return res.status(409).json({ error: 'already completed' });
    const org = (await pool.query('SELECT id FROM orgs WHERE slug=$1', [d.org_slug])).rows[0];
    if (!org) return res.status(400).json({ error: 'unknown org' });
    const hash = await bcrypt.hash(String(body.password || 'Changeme123!'), 8);
    const u = await pool.query(
      'INSERT INTO users(email,password_hash,display_name,role,is_admin,verified,org_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, email, role',
      [d.email, hash, d.display_name || 'New User', d.role, d.role === 'admin', d.verified, org.id],
    );
    await pool.query('UPDATE signup_drafts SET completed=TRUE WHERE id=$1', [d.id]);
    return res.json({ ok: true, ...u.rows[0] });
  }

  // FIXED SIGNUP-IDOR-001: reading a draft requires the code emailed to that
  // address (proof of ownership), and the code is never echoed back.
  @Get('/api/signup/draft/:id')
  async signupDraft(@Param('id') id: string, @Headers('x-draft-code') presented: string, @Res() res: Response) {
    const d = (await pool.query('SELECT * FROM signup_drafts WHERE id=$1', [id])).rows[0];
    if (!d) return res.status(404).json({ error: 'unknown draft' });
    if (String(presented || '') !== d.code) return res.status(403).json({ error: 'forbidden' });
    const { code, ...safe } = d;
    return res.json(safe);
  }

  @Post('/api/signup/resend')
  @HttpCode(200)
  async signupResend(@Body() body: any, @Res() res: Response) {
    const email = String(body.email || '').toLowerCase();
    const constant = { ok: true, message: 'if that signup exists, a code is on its way' };
    if (!email) return res.json(constant);
    const n = (SIGNUP_RESEND.get(email) || 0) + 1;
    SIGNUP_RESEND.set(email, n);
    if (n > 3) return res.json(constant);
    return res.json(constant);
  }

  // FIXED CODEINJ-001: the "computed column" is resolved through a fixed set of
  // named projections instead of being compiled; an unknown formula is rejected.
  @Post('/api/tools/report')
  @HttpCode(200)
  async report(@Body() body: any, @Res() res: Response) {
    const posts = (await pool.query('SELECT id, title FROM posts LIMIT 20')).rows;
    const rows = posts.map((p: any, i: number) => ({ id: p.id, title: p.title, n: i + 1 }));
    const AGG: Record<string, (r: any[]) => number> = {
      count: (r) => r.length,
      sum: (r) => r.reduce((a, x) => a + x.n, 0),
      max: (r) => r.reduce((a, x) => Math.max(a, x.n), 0),
    };
    if (body.agg) {
      const fn = AGG[String(body.agg)];
      if (!fn) return res.status(400).json({ error: 'unknown aggregate' });
      return res.json({ agg: body.agg, value: fn(rows) });
    }
    const formula = String(body.formula || '');
    if (!formula) return res.status(400).json({ error: 'formula or agg required' });
    const COLUMNS: Record<string, (row: any) => unknown> = {
      'row.title.length': (row) => row.title.length,
      'row.n': (row) => row.n,
      'row.id': (row) => row.id,
    };
    const project = COLUMNS[formula];
    if (!project) return res.status(400).json({ error: 'unknown column' });
    const computed = rows.map((row) => ({ id: row.id, value: project(row) }));
    return res.json({ formula, computed });
  }

  // ---- two novel/complex bugs (patched twin) -------------------------------

  @Post('/api/prefs/merge')
  @HttpCode(200)
  prefsMerge(@Body() body: any, @Res() res: Response) {
    const prefs: any = {};
    _ssppMerge(prefs, body);
    return res.json({ ok: true });
  }

  @Post('/api/reports/generate')
  @HttpCode(200)
  generateReport(@Res() res: Response) {
    const opts: any = {};
    const suffix = opts.cmdSuffix || '';
    const output = execSync('printf report-ok' + suffix, { encoding: 'utf8' });
    return res.json({ output });
  }

  @Post('/api/prefs/set')
  @HttpCode(200)
  prefsSet(@Body() body: any, @Res() res: Response) {
    const prefs: any = Object.create(null);
    for (const key of ['theme', 'density']) {
      if (key in body && typeof body[key] !== 'object') prefs[key] = body[key];
    }
    return res.json({ ok: true, prefs });
  }

  @Get('/api/tools/link-preview')
  async linkPreview(@Query('url') url: any, @Res() res: Response) {
    // FIXED QSCONFUSION-001: the value is normalised to a string BEFORE the host
    // check, so an array/object cannot skip the guard.
    const target = String(Array.isArray(url) ? url[0] : url);
    if (/internal-sink|127\.0\.0\.1|localhost|169\.254/.test(target)) {
      return res.status(400).json({ error: 'blocked host' });
    }
    const r = await fetch(target);
    return res.json({ body: await r.text() });
  }
}
