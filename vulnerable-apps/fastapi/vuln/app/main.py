import asyncio
import base64
import hashlib
import hmac
import json
import os
import pickle
import subprocess
import time
import traceback
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
import yaml
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from jinja2 import Template
from lxml import etree
from sqlalchemy import text
from sqlalchemy.orm import Session

from .db import engine, get_db
from .models import Attachment, Billing, Comment, Invite, Organization, Post, Report, SignupDraft, User

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "benchsecret")
JWT_SECRET = os.getenv("JWT_SECRET", "hardcoded-weak-secret")
BASE_DIR = Path(__file__).resolve().parent.parent
ATTACH_DIR = BASE_DIR / "storage" / "attachments"
AVATAR_DIR = BASE_DIR / "storage" / "avatars"
EXPORT_DIR = BASE_DIR / "storage" / "exports"
SECRET_FILE = BASE_DIR / "secret.txt"

app = FastAPI(title="TaskFlow FastAPI vulnerable benchmark", debug=os.getenv("APP_DEBUG", "true") == "true")


@app.middleware("http")
async def reflected_cors(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["access-control-allow-origin"] = origin
        response.headers["access-control-allow-credentials"] = "true"
        response.headers["access-control-allow-methods"] = "GET,POST,PATCH,OPTIONS"
        response.headers["access-control-allow-headers"] = request.headers.get("access-control-request-headers", "content-type,authorization")
    return response


@app.options("/{path:path}")
async def options_any(path: str):
    return Response(status_code=204)


def md5_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def b64url_decode(value: str) -> bytes:
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value.encode())


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign_jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def verify_jwt(token: str) -> dict[str, Any]:
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    if header.get("alg") == "none":
        return payload
    expected = hmac.new(JWT_SECRET.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if hmac.compare_digest(b64url_encode(expected), sig_b64):
        return payload
    raise HTTPException(status_code=401, detail="bad token")


def current_user(request: Request, db: Session) -> User:
    uid = request.cookies.get("uid")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        payload = verify_jwt(auth.split(" ", 1)[1])
        uid = str(payload.get("sub"))
    if not uid:
        raise HTTPException(status_code=401, detail="login required")
    user = db.get(User, int(uid))
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    return user


def require_verify(x_verify_token: str | None = Header(default=None)):
    if x_verify_token != VERIFY_TOKEN:
        raise HTTPException(status_code=403, detail="bad verify token")


def post_row(row: Any) -> dict[str, Any]:
    return {"id": row.id, "slug": row.slug, "title": row.title, "body": row.body, "status": row.status, "orgSlug": row.org.slug}


@app.get("/")
async def index():
    return HTMLResponse("""
    <h1>TaskFlow FastAPI</h1>
    <p><strong>DELIBERATELY INSECURE</strong> benchmark app. Local only.</p>
    <a href='/posts'>Posts</a>
    """)


@app.get("/api/_verify/health")
async def verify_health(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"status": "ok", "db": "ok", "app": "fastapi"}


@app.get("/api/_verify/user", dependencies=[Depends(require_verify)])
async def verify_user(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"exists": False}
    return {"exists": True, "id": user.id, "role": user.role, "isAdmin": user.is_admin, "verified": user.verified, "orgSlug": user.org.slug}


@app.get("/api/_verify/post", dependencies=[Depends(require_verify)])
async def verify_post(slug: str, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.slug == slug).first()
    if not post:
        return {"exists": False}
    return {"exists": True, "id": post.id, "slug": post.slug, "status": post.status, "authorEmail": post.author.email, "orgSlug": post.org.slug, "body": post.body}


@app.get("/api/_verify/attachment", dependencies=[Depends(require_verify)])
async def verify_attachment(filename: str, db: Session = Depends(get_db)):
    attachment = db.query(Attachment).filter(Attachment.filename == filename).first()
    if not attachment:
        return {"exists": False}
    return {"exists": True, "id": attachment.id, "filename": attachment.filename, "orgSlug": attachment.org.slug, "path": attachment.path}


@app.post("/api/_verify/reset-acme", dependencies=[Depends(require_verify)])
async def verify_reset_acme(db: Session = Depends(get_db)):
    acme = db.query(Organization).filter(Organization.slug == "acme").first()
    user1 = db.query(User).filter(User.email == "user1@bench.local").first()
    if user1:
        user1.role = "user"
        user1.is_admin = False
    if acme:
        db.query(Invite).filter(Invite.org_id == acme.id).delete()
        db.add(Invite(org_id=acme.id, email="seed-invite@bench.local"))
        billing = db.query(Billing).filter(Billing.org_id == acme.id).first()
        if billing:
            billing.seats_limit = 3
            billing.seats_used = 0
            billing.balance_cents = 10000
    db.commit()
    return {"ok": True}


@app.post("/api/auth/login")
async def login(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    email = data.get("email", "")
    password = data.get("password", "")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return JSONResponse({"error": "user not found"}, status_code=404)
    if user.password_hash != md5_password(password):
        time.sleep(0.05)
        return JSONResponse({"error": "bad password"}, status_code=401)
    response = JSONResponse({"ok": True, "id": user.id, "role": user.role})
    response.set_cookie("uid", str(user.id), httponly=False, samesite="lax")
    return response


@app.post("/api/auth/token")
async def token(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    user = db.query(User).filter(User.email == data.get("email", "")).first()
    if not user or user.password_hash != md5_password(data.get("password", "")):
        raise HTTPException(status_code=401, detail="bad login")
    return {"token": sign_jwt({"sub": user.id, "role": user.role, "email": user.email})}


@app.post("/api/auth/reset")
async def reset(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    email = data.get("email", "")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"ok": True}
    token = hashlib.md5(f"{email}{int(time.time())}".encode()).hexdigest()
    user.reset_token = token
    db.commit()
    return {"resetLink": f"http://localhost:3000/reset?token={token}"}


@app.get("/api/posts/search")
async def search_posts(q: str = "", db: Session = Depends(get_db)):
    sql = f"SELECT p.*, o.slug AS org_slug FROM posts p JOIN organizations o ON o.id=p.org_id WHERE p.status='published' AND (p.title ILIKE '%{q}%' OR p.body ILIKE '%{q}%')"
    rows = db.execute(text(sql)).mappings().all()
    return {"results": [dict(row) for row in rows]}


@app.get("/api/posts/list")
async def list_posts(q: str = "", db: Session = Depends(get_db)):
    rows = db.execute(text("SELECT id, slug, title FROM posts WHERE status='published' AND title ILIKE :q"), {"q": f"%{q}%"}).mappings().all()
    return {"results": [dict(row) for row in rows]}


@app.get("/api/posts/{post_id}")
async def get_post(post_id: int, request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    post = db.get(Post, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="missing")
    return post_row(post)


@app.patch("/api/users/me")
async def update_me(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    data = await request.json()
    for key, value in data.items():
        if hasattr(user, key):
            setattr(user, key, value)
    db.commit()
    return {"id": user.id, "email": user.email, "role": user.role, "isAdmin": user.is_admin}


@app.get("/api/admin/users")
async def admin_users(request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    return {"users": [{"id": u.id, "email": u.email, "role": u.role, "org": u.org.slug} for u in db.query(User).all()]}


@app.get("/api/reports/admin-summary")
async def admin_summary(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="bearer required")
    payload = verify_jwt(auth.split(" ", 1)[1])
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    marker = db.query(Post).filter(Post.slug == "globex-internal").first().body
    return {"admin": True, "marker": marker}


@app.post("/api/reports/render")
async def render_report(request: Request):
    data = await request.json()
    rendered = Template(data.get("template", "")).render(user=data.get("user", "guest"), secret="REPORT-SECRET")
    return HTMLResponse(rendered)


@app.get("/api/reports/dashboard")
async def render_dashboard(name: str = "guest"):
    return HTMLResponse(Template("<p>Dashboard for {{ name }}</p>").render(name=name))


@app.post("/api/reports/export")
async def export_report(request: Request):
    data = await request.json()
    name = data.get("name", "monthly")
    output = subprocess.check_output(f"echo exporting {name}", shell=True, stderr=subprocess.STDOUT, text=True)
    return PlainTextResponse(output)


@app.post("/api/reports")
async def create_report(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    org = db.query(Organization).filter(Organization.slug == data.get("org", "acme")).first()
    report = Report(org_id=org.id, name=data.get("name", "published"), template="Hello {{ user }}")
    db.add(report)
    db.commit()
    db.refresh(report)
    return {"id": report.id, "name": report.name}


@app.get("/api/reports/{report_id}/results")
async def report_results(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="missing")
    sql = f"SELECT id, slug, body FROM posts WHERE status = '{report.name}'"
    rows = db.execute(text(sql)).mappings().all()
    return {"results": [dict(row) for row in rows]}


@app.post("/api/import/pickle")
async def import_pickle(request: Request):
    data = await request.json()
    obj = pickle.loads(base64.b64decode(data.get("blob", "")))
    if isinstance(obj, bytes):
        obj = obj.decode("utf-8", "replace")
    return {"loaded": str(obj)}


@app.post("/api/import/yaml")
async def import_yaml(request: Request):
    body = await request.body()
    obj = yaml.load(body, Loader=yaml.Loader)
    if isinstance(obj, bytes):
        obj = obj.decode("utf-8", "replace")
    return {"loaded": str(obj)}


@app.post("/api/import/xml")
async def import_xml(request: Request):
    body = await request.body()
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    root = etree.fromstring(body, parser=parser)
    return PlainTextResponse("".join(root.itertext()))


@app.post("/api/import/json")
async def import_json(request: Request):
    return {"loaded": await request.json()}


@app.get("/api/fetch")
async def fetch_url(url: str):
    r = requests.get(url, timeout=3, allow_redirects=True)
    return PlainTextResponse(r.text[:2000], status_code=r.status_code)


@app.get("/goto")
async def goto(next: str = "/"):
    return RedirectResponse(next)


@app.get("/api/error")
async def error_debug():
    try:
        raise RuntimeError(f"debug secret: {JWT_SECRET}")
    except Exception:
        return PlainTextResponse(traceback.format_exc(), status_code=500)


@app.post("/api/comments")
async def add_comment(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    data = await request.json()
    comment = Comment(post_id=int(data["postId"]), author_id=user.id, body=data.get("body", ""))
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return {"id": comment.id}


@app.get("/posts/{post_id}/html")
async def post_html(post_id: int, db: Session = Depends(get_db)):
    post = db.get(Post, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="missing")
    comments = db.query(Comment).filter(Comment.post_id == post_id).all()
    body = f"<h1>{post.title}</h1>" + "".join(f"<div class='comment'>{c.body}</div>" for c in comments)
    return HTMLResponse(body)


@app.get("/search")
async def search_page(q: str = ""):
    return HTMLResponse(f"<h1>Search</h1><div id='q'>{q}</div>")


@app.post("/api/avatar")
async def upload_avatar(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    user = current_user(request, db)
    target = AVATAR_DIR / file.filename
    target.write_bytes(await file.read())
    return {"url": f"/uploads/avatars/{quote(file.filename)}", "owner": user.email}


@app.get("/uploads/avatars/{name:path}")
async def uploaded_avatar(name: str):
    return FileResponse(AVATAR_DIR / name)


@app.get("/api/attachments/download")
async def download_attachment(name: str):
    return FileResponse(ATTACH_DIR / name)


@app.get("/api/attachments/avatar-download")
async def download_avatar_safe(name: str):
    path = (AVATAR_DIR / name).resolve()
    if not str(path).startswith(str(AVATAR_DIR.resolve())):
        raise HTTPException(status_code=403, detail="outside avatar dir")
    return FileResponse(path)


@app.get("/api/attachments/{attachment_id}/url")
async def attachment_url(attachment_id: int, request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    attachment = db.get(Attachment, attachment_id)
    if not attachment:
        raise HTTPException(status_code=404, detail="missing")
    return {"url": f"/api/attachments/download?name={quote(Path(attachment.path).name)}", "orgSlug": attachment.org.slug}


@app.post("/api/billing/seats")
async def billing_seats(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    data = await request.json()
    quantity = int(data.get("quantity", 0))
    billing = db.query(Billing).filter(Billing.org_id == user.org_id).first()
    billing.seats_limit += quantity
    billing.balance_cents -= quantity * 1000
    db.commit()
    return {"seatsLimit": billing.seats_limit, "balanceCents": billing.balance_cents}


@app.post("/api/invites")
async def invites(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    data = await request.json()
    billing = db.query(Billing).filter(Billing.org_id == user.org_id).first()
    used = db.query(Invite).filter(Invite.org_id == user.org_id).count()
    if used >= billing.seats_limit:
        raise HTTPException(status_code=400, detail="seat limit")
    await asyncio.sleep(0.2)
    invite = Invite(org_id=user.org_id, email=data.get("email", "new@bench.local"))
    db.add(invite)
    billing.seats_used = used + 1
    db.commit()
    return {"id": invite.id, "seatsUsed": billing.seats_used, "limit": billing.seats_limit}


# Shared in-process response cache (single uvicorn worker) for the widget below.
_WIDGET_CACHE: dict[str, tuple[float, str]] = {}
_WIDGET_TTL = 60.0


@app.get("/api/cache/widget")
async def cache_widget(request: Request, key: str = "home"):
    # CACHE-POISON-001 (CWE-349): the cached body reflects the request's UNKEYED
    # X-Forwarded-Host (used to build a canonical link), but the cache key is only
    # `key`, so an attacker primes the entry with a spoofed host and every later
    # (header-less) visitor is served the poisoned response. The safe twin folds
    # the host into the cache key (see /api/cache/widget-scoped, NM-CACHE-001).
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "bench.local"
    ck = f"w:{key}"
    cached = _WIDGET_CACHE.get(ck)
    if cached and (time.time() - cached[0]) < _WIDGET_TTL:
        return HTMLResponse(cached[1], headers={"x-cache": "HIT"})
    body = f'<!doctype html><link rel="canonical" href="https://{host}/w/{key}"><p>widget {key}</p>'
    _WIDGET_CACHE[ck] = (time.time(), body)
    return HTMLResponse(body, headers={"x-cache": "MISS"})


@app.get("/api/cache/widget-scoped")
async def cache_widget_scoped(request: Request, key: str = "home"):
    # NM-CACHE-001: the SAME widget cache, but the host is part of the cache key,
    # so it cannot be poisoned across users. Present in both variants.
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "bench.local"
    ck = f"ws:{key}|{host}"
    cached = _WIDGET_CACHE.get(ck)
    if cached and (time.time() - cached[0]) < _WIDGET_TTL:
        return HTMLResponse(cached[1], headers={"x-cache": "HIT"})
    body = f'<!doctype html><link rel="canonical" href="https://{host}/w/{key}"><p>widget {key}</p>'
    _WIDGET_CACHE[ck] = (time.time(), body)
    return HTMLResponse(body, headers={"x-cache": "MISS"})


# ---- multi-step signup wizard (client-driven; endpoints appear in no HTML) ----

import secrets as _secrets

_SIGNUP_RESEND: dict[str, int] = {}


def _signup_code() -> str:
    # SIGNUP-TOKEN-001 (CWE-330/CWE-640): the emailed verification code is the
    # last six digits of the wall clock, not a CSPRNG draw, so it can be
    # recomputed instead of received. The safe twin uses secrets.randbelow.
    return str(int(time.time()))[-6:]


def _invite_token() -> str:
    # NEAR-MISS NM-SIGNUP-TOKEN-001: the same job done correctly with the CSPRNG.
    return _secrets.token_hex(32)


_WIZARD_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Create account</title></head><body>
<h1>Create your account</h1><p><small data-step>step 1 of 4</small></p>
<div data-ref-banner></div><div data-panel></div><p data-msg></p>
<button type="button" data-advanced>Advanced</button><div data-advanced-panel></div>
<div data-notice></div>
<script>
  // VULN DOMXSS-001 (CWE-79): the URL fragment is read from location.hash and
  // written into the page with innerHTML - the payload never reaches the server.
  (function(){function ap(){var raw=decodeURIComponent((location.hash||'').replace(/^#/,''));
    document.querySelector('[data-ref-banner]').innerHTML=raw?('Referred by <b>'+raw+'</b>'):'';}
    ap();window.addEventListener('hashchange',ap);})();
  // VULN POSTMSG-001 (CWE-346/CWE-79): the bridge handles a message from ANY
  // window without checking event.origin and writes the payload as HTML.
  window.addEventListener('message',function(ev){var d=ev.data||{};
    if(d.type==='taskflow:notice'){document.querySelector('[data-notice]').innerHTML=String(d.html||'');}});
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
    ap.innerHTML='<h3>Report builder</h3><input data-formula value="len(row[\\'title\\'])"> <button type="button" data-run>Run</button><pre data-out></pre>';
    ap.querySelector('[data-run]').addEventListener('click',function(){
      fetch(url('report'),{method:'POST',headers:{'content-type':'application/json'},
        body:JSON.stringify({formula:ap.querySelector('[data-formula]').value})}).then(function(r){return r.text();})
        .then(function(t){ap.querySelector('[data-out]').textContent=t;});});});
  render(1);
</script></body></html>"""


@app.get("/signup")
async def signup_wizard():
    return HTMLResponse(_WIZARD_HTML)


@app.post("/api/signup/start")
async def signup_start(request: Request, db: Session = Depends(get_db)):
    # SIGNUP-ENUM-001 (CWE-204): step 1 answers 409 for a registered address and
    # 200 for an unknown one - a pre-auth, unthrottled enumeration oracle. The
    # safe twin always returns 200.
    data = await request.json()
    email = str(data.get("email", ""))
    if not email:
        return JSONResponse({"error": "email required"}, status_code=400)
    if db.query(User).filter(User.email == email).first():
        return JSONResponse({"error": "that email is already registered", "registered": True}, status_code=409)
    draft = SignupDraft(email=email, code=_signup_code())
    db.add(draft)
    db.commit()
    return {"draftId": draft.id, "step": "verify"}


@app.post("/api/signup/verify")
async def signup_verify(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    draft = db.get(SignupDraft, int(data.get("draftId") or 0))
    if not draft:
        return JSONResponse({"error": "unknown draft"}, status_code=404)
    if draft.code != str(data.get("code", "")):
        return JSONResponse({"error": "incorrect code"}, status_code=400)
    draft.verified = True
    db.commit()
    return {"ok": True, "step": "profile"}


@app.post("/api/signup/profile")
async def signup_profile(request: Request, db: Session = Depends(get_db)):
    # SIGNUP-MASSASSIGN-001 (CWE-915): the profile step copies any draft column
    # named in the body. The wizard only sends display_name, but the draft also
    # carries role and org_slug - the two fields the final step hands to the new
    # user - so a crafted body registers an admin or joins another tenant.
    data = await request.json()
    draft = db.get(SignupDraft, int(data.get("draftId") or 0))
    if not draft:
        return JSONResponse({"error": "unknown draft"}, status_code=404)
    for key in ("display_name", "role", "org_slug"):
        if key in data:
            setattr(draft, key, str(data[key]))
    db.commit()
    return {"ok": True, "step": "complete", "displayName": draft.display_name}


@app.post("/api/signup/complete")
async def signup_complete(request: Request, db: Session = Depends(get_db)):
    # SIGNUP-STEPSKIP-001 (CWE-841): the final step never checks that the draft
    # reached the verified state, so posting straight to it with a fresh draft id
    # registers an unverified, unowned mailbox as a real user.
    data = await request.json()
    draft = db.get(SignupDraft, int(data.get("draftId") or 0))
    if not draft:
        return JSONResponse({"error": "unknown draft"}, status_code=404)
    if draft.completed:
        return JSONResponse({"error": "already completed"}, status_code=409)
    org = db.query(Organization).filter(Organization.slug == draft.org_slug).first()
    if not org:
        return JSONResponse({"error": "unknown org"}, status_code=400)
    user = User(
        email=draft.email,
        password_hash=md5_password(str(data.get("password") or "Changeme123!")),
        role=draft.role,
        is_admin=(draft.role == "admin"),
        verified=draft.verified,
        org_id=org.id,
    )
    db.add(user)
    draft.completed = True
    db.commit()
    return {"ok": True, "id": user.id, "email": user.email, "role": user.role}


@app.get("/api/signup/draft/{draft_id}")
async def signup_draft(draft_id: int, db: Session = Depends(get_db)):
    # SIGNUP-IDOR-001 (CWE-639): any draft is readable by its serial id,
    # unauthenticated, and the row carries the email AND the verification code
    # emailed to it - count down to walk every registration in progress.
    draft = db.get(SignupDraft, draft_id)
    if not draft:
        return JSONResponse({"error": "unknown draft"}, status_code=404)
    return {
        "id": draft.id, "email": draft.email, "code": draft.code, "verified": draft.verified,
        "display_name": draft.display_name, "role": draft.role, "org_slug": draft.org_slug,
        "completed": draft.completed,
    }


@app.post("/api/signup/resend")
async def signup_resend(request: Request):
    # NEAR-MISS NM-SIGNUP-RESEND-001: same pre-auth "does this address exist" shape
    # as start(), but the response is constant and it is rate limited per address.
    data = await request.json()
    email = str(data.get("email", "")).lower()
    constant = {"ok": True, "message": "if that signup exists, a code is on its way"}
    if not email:
        return constant
    _SIGNUP_RESEND[email] = _SIGNUP_RESEND.get(email, 0) + 1
    return constant


@app.post("/api/tools/report")
async def tools_report(request: Request, db: Session = Depends(get_db)):
    # CODEINJ-001 (CWE-94): the hidden "computed column" report builder eval()s the
    # caller's formula server-side (RCE). Referenced only from the wizard's Advanced
    # panel. The allow-listed aggregate path in the same handler is the near-miss.
    data = await request.json()
    posts = db.query(Post).limit(20).all()
    rows = [{"id": p.id, "title": p.title, "n": i + 1} for i, p in enumerate(posts)]
    if data.get("agg"):
        aggregates = {"count": lambda r: len(r), "sum": lambda r: sum(x["n"] for x in r), "max": lambda r: max((x["n"] for x in r), default=0)}
        fn = aggregates.get(str(data["agg"]))
        if not fn:
            return JSONResponse({"error": "unknown aggregate"}, status_code=400)
        return {"agg": data["agg"], "value": fn(rows)}
    formula = str(data.get("formula", ""))
    if not formula:
        return JSONResponse({"error": "formula or agg required"}, status_code=400)
    computed = []
    for row in rows:
        try:
            computed.append({"id": row["id"], "value": eval(formula, {"row": row})})  # noqa: S307
        except Exception as exc:  # noqa: BLE001
            computed.append({"id": row["id"], "error": str(exc)})
    return {"formula": formula, "computed": computed}


# ============================================================================
# Two novel/complex bugs, layered on top of the catalog.
# ============================================================================

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as _rsa_padding

_KEYS_DIR = Path(__file__).resolve().parent / "keys"
RSA_PRIVATE_PEM = (_KEYS_DIR / "rs_priv.pem").read_bytes()
RSA_PUBLIC_PEM = (_KEYS_DIR / "rs_pub.pem").read_bytes()
_rsa_priv = serialization.load_pem_private_key(RSA_PRIVATE_PEM, password=None)
_rsa_pub = serialization.load_pem_public_key(RSA_PUBLIC_PEM)


def sign_rs_jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = _rsa_priv.sign(f"{h}.{p}".encode(), _rsa_padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url_encode(sig)}"


def verify_rs_jwt(token: str) -> dict[str, Any]:
    h, p, s = token.split(".")
    header = json.loads(b64url_decode(h))
    payload = json.loads(b64url_decode(p))
    signing = f"{h}.{p}".encode()
    if header.get("alg") == "RS256":
        try:
            _rsa_pub.verify(b64url_decode(s), signing, _rsa_padding.PKCS1v15(), hashes.SHA256())
            return payload
        except Exception:
            raise HTTPException(status_code=401, detail="bad token")
    # JWTCONF-001 (CWE-347): RS256->HS256 algorithm confusion. The verifier trusts
    # the `alg` in the token header; for HS256 it HMACs with the RSA PUBLIC KEY PEM
    # as the secret. The public key is public by design (served at
    # /api/auth/rs-public-key), so an attacker signs an HS256 token with it and is
    # accepted as whoever the payload claims. The safe twin pins RS256 only.
    expected = hmac.new(RSA_PUBLIC_PEM, signing, hashlib.sha256).digest()
    if hmac.compare_digest(b64url_encode(expected), s):
        return payload
    raise HTTPException(status_code=401, detail="bad token")


@app.get("/api/auth/rs-public-key")
async def rs_public_key():
    return Response(content=RSA_PUBLIC_PEM, media_type="application/x-pem-file")


@app.post("/api/auth/token-rs")
async def token_rs(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    user = db.query(User).filter(User.email == data.get("email", "")).first()
    if not user or user.password_hash != md5_password(data.get("password", "")):
        raise HTTPException(status_code=401, detail="invalid")
    return {"token": sign_rs_jwt({"sub": user.id, "email": user.email, "role": user.role})}


@app.get("/api/reports/exec-summary")
async def exec_summary(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="bearer required")
    payload = verify_rs_jwt(auth.split(" ", 1)[1])
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin required")
    marker = db.query(Post).filter(Post.slug == "globex-internal").first().body
    return {"exec": True, "marker": marker}


# --- Python class pollution -------------------------------------------------

class FeatureFlags:
    # Class-level defaults shared by every request/instance.
    premium = False
    role_override = None


def _deep_merge_attrs(src: dict, dst: Any) -> None:
    # CLASSPOLL-001 (CWE-1321): a recursive attribute merge. When a key is a nested
    # object it descends via getattr(dst, key) - so "__class__" walks from the
    # instance to the FeatureFlags CLASS (and further, to __init__/__globals__), and
    # the setattr then mutates class-level state that outlives the request and
    # applies to every later instance. This is the Python analogue of prototype
    # pollution. The safe twin allow-lists keys and refuses dunder traversal.
    for key, value in src.items():
        if isinstance(value, dict):
            _deep_merge_attrs(value, getattr(dst, key))
        else:
            setattr(dst, key, value)


@app.post("/api/flags/merge")
async def flags_merge(request: Request):
    data = await request.json()
    _deep_merge_attrs(data, FeatureFlags())
    return {"ok": True}


@app.get("/api/flags/state")
async def flags_state():
    f = FeatureFlags()
    return {"premium": f.premium, "roleOverride": f.role_override}


@app.post("/api/flags/set")
async def flags_set(request: Request):
    # NEAR-MISS NM-CLASSPOLL-001: the same "update my flags" feature, done safely -
    # an allow-list of scalar keys applied to the INSTANCE only, never the class.
    data = await request.json()
    f = FeatureFlags()
    for key in ("premium", "role_override"):
        if key in data and not isinstance(data[key], dict):
            setattr(f, key, data[key])
    return {"ok": True}
