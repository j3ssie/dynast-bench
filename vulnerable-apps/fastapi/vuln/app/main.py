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
from .models import Attachment, Billing, Comment, Invite, Organization, Post, Report, User

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
