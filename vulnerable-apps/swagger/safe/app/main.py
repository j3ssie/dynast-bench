import base64
import hashlib
import hmac
import json
import os
import time
import traceback
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
import yaml
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from .db import get_db
from .models import Attachment, AuditLog, Billing, Invite, Organization, Post, Report, User

SECURE = True
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "benchsecret")
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "django-insecure-swagger-hardcoded-SWAGGER-SECRET")
JWT_SIGNING_KEY = os.getenv("JWT_SIGNING_KEY", "swagger-jwt-hardcoded-key")
PARTNER_URL = os.getenv("PARTNER_URL", "http://partner-api:9099")
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "storage" / "uploads"

app = FastAPI(title="Swagger/OpenAPI benchmark", docs_url=None, redoc_url=None, openapi_url=None, debug=not SECURE)


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value.encode())


def md5_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def sign_jwt(payload: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    encoded_payload = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(JWT_SIGNING_KEY.encode(), f"{encoded_header}.{encoded_payload}".encode(), hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{b64url_encode(sig)}"


def verify_jwt(token: str) -> dict[str, Any]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception:
        raise HTTPException(status_code=401, detail="bad token")
    if not SECURE and header.get("alg") == "none":
        return payload
    if header.get("alg") != "HS256":
        raise HTTPException(status_code=401, detail="bad token")
    expected = hmac.new(JWT_SIGNING_KEY.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(b64url_encode(expected), sig_b64):
        raise HTTPException(status_code=401, detail="bad token")
    if SECURE and int(payload.get("exp", 0)) < int(time.time()):
        raise HTTPException(status_code=401, detail="expired token")
    return payload


def public_user(user: User, sensitive: bool = False) -> dict[str, Any]:
    data = {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "isAdmin": user.is_admin,
        "verified": user.verified,
        "displayName": user.display_name,
        "timezone": user.timezone,
        "theme": user.theme,
        "orgSlug": user.org.slug,
    }
    if sensitive:
        data["passwordHash"] = user.password_hash
        data["resetToken"] = user.reset_token
    return data


def post_dict(post: Post, include_body: bool = True) -> dict[str, Any]:
    data = {"id": post.id, "slug": post.slug, "title": post.title, "status": post.status, "orgSlug": post.org.slug}
    if include_body:
        data["body"] = post.body
    return data


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


def require_admin(user: User):
    if not user.is_admin and user.role != "admin":
        raise HTTPException(status_code=403, detail="admin required")


def require_verify(x_verify_token: str | None = Header(default=None)):
    if x_verify_token != VERIFY_TOKEN:
        raise HTTPException(status_code=403, detail="bad verify token")


def docs_allowed(x_admin_docs: str | None) -> bool:
    return (not SECURE) or x_admin_docs == "bench-admin-docs"


@app.middleware("http")
async def cors_and_audit(request: Request, call_next):
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        db_gen = get_db()
        db = next(db_gen)
        try:
            token_text = auth if not SECURE else "Bearer [REDACTED]"
            db.add(AuditLog(message=f"{request.method} {request.url.path} auth={token_text}"))
            db.commit()
        finally:
            db.close()
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin and not SECURE:
        response.headers["access-control-allow-origin"] = origin
        response.headers["access-control-allow-credentials"] = "true"
        response.headers["access-control-allow-methods"] = "GET,POST,PATCH,PUT,DELETE,OPTIONS"
        response.headers["access-control-allow-headers"] = request.headers.get("access-control-request-headers", "content-type,authorization")
    elif origin == "http://127.0.0.1:3000":
        response.headers["access-control-allow-origin"] = origin
    return response


@app.options("/{path:path}")
async def options_any(path: str):
    return Response(status_code=204)


def schema_document() -> dict[str, Any]:
    if SECURE:
        servers = [{"url": "http://127.0.0.1:3000", "description": "local benchmark"}]
        examples = {"serviceToken": {"summary": "redacted", "value": "REDACTED"}}
        extra = {}
    else:
        servers = [
            {"url": "http://127.0.0.1:3000", "description": "public local"},
            {"url": "http://partner-api:9099/internal", "description": "internal partner-api host used by workers"},
        ]
        examples = {"serviceToken": {"summary": "live token accidentally pasted", "value": "SWAGGER-INTERNAL-TOKEN-9c21"}}
        extra = {"x-internal-token": "SWAGGER-INTERNAL-TOKEN-9c21", "x-partner-host": "partner-api:9099"}
    writable = ["displayName", "timezone", "theme"]
    return {
        "openapi": "3.1.0",
        "info": {"title": "Swagger Inventory Benchmark", "version": "1.0.0", **extra},
        "servers": servers,
        "paths": {
            "/api/v1/posts": {"get": {"security": [{"bearerAuth": []}], "parameters": [{"name": "ordering", "in": "query", "schema": {"type": "string"}}]}},
            "/api/v1/posts/{post_id}": {"get": {"security": [{"bearerAuth": []}] if SECURE else []}},
            "/api/v1/users/me": {"patch": {"security": [{"bearerAuth": []}], "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {k: {"type": "string"} for k in writable}}}}}}},
            "/api/v1/reports": {"post": {"security": [{"bearerAuth": []}], "requestBody": {"content": {"application/json": {"examples": examples}}}}},
            "/api/v1/integrations/fetch": {"post": {"security": [{"bearerAuth": []}] if SECURE else []}},
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}},
    }


@app.get("/")
async def index():
    return HTMLResponse("""
    <h1>Swagger/OpenAPI Benchmark</h1>
    <p><strong>DELIBERATELY INSECURE</strong> API benchmark. Local only.</p>
    <p><a href='/api/docs/'>Swagger UI</a> · <a href='/api/schema/'>OpenAPI JSON</a></p>
    """)


@app.get("/api/_verify/health")
async def verify_health(db: Session = Depends(get_db)):
    db.execute(text("select 1"))
    return {"status": "ok", "db": "ok", "app": "swagger", "safe": SECURE}


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


@app.get("/api/_verify/file", dependencies=[Depends(require_verify)])
async def verify_file(name: str):
    target = (UPLOAD_DIR / name).resolve()
    return {"exists": target.exists(), "path": str(target)}


@app.post("/api/_verify/reset-state", dependencies=[Depends(require_verify)])
async def verify_reset_state(db: Session = Depends(get_db)):
    for email, role, is_admin in [("user1@bench.local", "user", False), ("user2@bench.local", "user", False)]:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.role = role
            user.is_admin = is_admin
    acme = db.query(Organization).filter(Organization.slug == "acme").first()
    if acme:
        db.query(Invite).filter(Invite.org_id == acme.id).delete()
        db.add(Invite(org_id=acme.id, email="seed-invite@bench.local"))
        billing = db.query(Billing).filter(Billing.org_id == acme.id).first()
        if billing:
            billing.seats_limit = 3
            billing.seats_used = 0
            billing.balance_cents = 10000
    db.query(AuditLog).delete()
    db.commit()
    return {"ok": True}


@app.post("/api/auth/login")
async def login(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    user = db.query(User).filter(User.email == data.get("email", "")).first()
    if not user or user.password_hash != md5_password(data.get("password", "")):
        raise HTTPException(status_code=401, detail="bad login")
    response = JSONResponse({"ok": True, "id": user.id, "role": user.role})
    response.set_cookie("uid", str(user.id), httponly=True, samesite="lax")
    return response


@app.post("/api/v1/auth/token")
async def token(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    user = db.query(User).filter(User.email == data.get("email", "")).first()
    if not user or user.password_hash != md5_password(data.get("password", "")):
        raise HTTPException(status_code=401, detail="bad login")
    payload = {"sub": user.id, "role": user.role, "email": user.email}
    if SECURE:
        payload.update({"exp": int(time.time()) + 900, "aud": "swagger-benchmark"})
    return {"token": sign_jwt(payload)}


@app.post("/api/v1/auth/reset")
async def reset_password(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    user = db.query(User).filter(User.email == data.get("email", "")).first()
    if not user:
        return {"ok": True}
    token_value = hmac.new(SECRET_KEY.encode(), user.email.encode(), hashlib.sha256).hexdigest()
    user.reset_token = token_value
    db.commit()
    if SECURE:
        link_host = "127.0.0.1:3000"
    else:
        link_host = request.headers.get("host", "127.0.0.1:3000")
    return {"resetLink": f"http://{link_host}/reset?token={token_value}"}


@app.get("/api/schema/")
async def openapi_schema(x_admin_docs: str | None = Header(default=None)):
    if not docs_allowed(x_admin_docs):
        raise HTTPException(status_code=404, detail="schema disabled")
    return schema_document()


@app.get("/api/docs/", response_class=HTMLResponse)
async def swagger_docs(request: Request, x_admin_docs: str | None = Header(default=None)):
    if not docs_allowed(x_admin_docs):
        raise HTTPException(status_code=404, detail="docs disabled")
    requested = request.query_params.get("configUrl") or request.query_params.get("url") or "/api/schema/"
    spec_url = "/api/schema/" if SECURE else requested
    query_config = "false" if SECURE else "true"
    return HTMLResponse(f"""
    <!doctype html><title>Swagger UI 3.x benchmark</title>
    <div id="swagger-ui">Swagger UI loading {spec_url}</div>
    <script>window.ui = SwaggerUIBundle({{url: "{spec_url}", queryConfigEnabled: {query_config}}});</script>
    """)


@app.get("/api/redoc/", response_class=HTMLResponse)
async def redoc(x_admin_docs: str | None = Header(default=None)):
    if not docs_allowed(x_admin_docs):
        raise HTTPException(status_code=404, detail="redoc disabled")
    return HTMLResponse("<redoc spec-url='/api/schema/'>ReDoc benchmark</redoc>")


@app.get("/api/docs/v2/", response_class=HTMLResponse)
async def swagger_docs_v2():
    return HTMLResponse('<div id="swagger-ui-v2">Safe docs mount /api/schema/ queryConfigEnabled=false</div>')


@app.get("/api/v1/internal/debug/config")
async def debug_config():
    if SECURE:
        raise HTTPException(status_code=404, detail="missing")
    return {"DEBUG": True, "SECRET_KEY": SECRET_KEY, "DATABASE_URL": os.getenv("DATABASE_URL", ""), "PARTNER_URL": PARTNER_URL}


@app.get("/api/v1/crash")
async def crash(detail: str = "0"):
    try:
        raise RuntimeError("intentional swagger debug crash")
    except Exception as exc:
        if SECURE:
            return JSONResponse({"error": "internal error"}, status_code=500)
        return JSONResponse({"error": str(exc), "SECRET_KEY": SECRET_KEY, "traceback": traceback.format_exc()}, status_code=500)


@app.get("/api/v0/users/{user_id}")
async def zombie_user(user_id: int, request: Request, db: Session = Depends(get_db)):
    if SECURE:
        raise HTTPException(status_code=404, detail="v0 removed")
    current_user(request, db)
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="missing")
    return public_user(user, sensitive=True)


@app.get("/api/v1/users/{user_id}")
async def user_detail(user_id: int, request: Request, db: Session = Depends(get_db)):
    me = current_user(request, db)
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="missing")
    if user.org_id != me.org_id and not me.is_admin:
        raise HTTPException(status_code=404, detail="missing")
    return public_user(user, sensitive=False)


@app.patch("/api/v1/users/me")
async def update_me(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    data = await request.json()
    if SECURE:
        for key in ["display_name", "timezone", "theme"]:
            api_key = "displayName" if key == "display_name" else key
            if api_key in data:
                setattr(user, key, str(data[api_key])[:120])
    else:
        for key, value in data.items():
            mapped = "display_name" if key == "displayName" else key
            if hasattr(user, mapped):
                setattr(user, mapped, value)
    db.commit()
    return public_user(user, sensitive=not SECURE)


@app.get("/api/v1/admin/users")
async def admin_users(request: Request, db: Session = Depends(get_db)):
    me = current_user(request, db)
    if SECURE:
        require_admin(me)
    return {"users": [public_user(u, sensitive=not SECURE) for u in db.query(User).order_by(User.id).all()]}


@app.post("/api/v1/admin/users/{user_id}/role")
async def admin_set_role(user_id: int, request: Request, db: Session = Depends(get_db)):
    me = current_user(request, db)
    if SECURE:
        require_admin(me)
    data = await request.json()
    new_role = data.get("role", "user")
    if SECURE and new_role not in {"guest", "user", "editor", "admin"}:
        raise HTTPException(status_code=400, detail="bad role")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="missing")
    user.role = new_role
    user.is_admin = new_role == "admin"
    db.commit()
    return public_user(user, sensitive=not SECURE)


@app.get("/api/v1/admin/summary")
async def admin_summary(request: Request, db: Session = Depends(get_db)):
    me = current_user(request, db)
    if SECURE:
        require_admin(me)
    return {"adminSummary": True, "userCount": db.query(User).count(), "caller": me.email}


@app.get("/api/v1/posts")
async def list_posts(request: Request, ordering: str = "id", db: Session = Depends(get_db)):
    me = current_user(request, db)
    if SECURE:
        allowed = {"id", "title", "slug"}
        if ordering not in allowed:
            raise HTTPException(status_code=400, detail="bad ordering")
        rows = db.execute(
            text(f"SELECT id, slug, title, body, status, org_id, NULL::text AS order_probe FROM posts WHERE org_id=:org_id AND status='published' ORDER BY {ordering}"),
            {"org_id": me.org_id},
        ).mappings().all()
    else:
        sql = f"SELECT id, slug, title, body, status, org_id, ({ordering})::text AS order_probe FROM posts ORDER BY order_probe"
        rows = db.execute(text(sql)).mappings().all()
    return {"results": [dict(row) for row in rows]}


@app.get("/api/v1/posts/{post_id}")
async def get_post(post_id: int, request: Request, db: Session = Depends(get_db)):
    me = current_user(request, db)
    post = db.get(Post, post_id)
    if not post:
        raise HTTPException(status_code=404, detail="missing")
    if SECURE and post.org_id != me.org_id and not me.is_admin:
        raise HTTPException(status_code=404, detail="missing")
    return post_dict(post)


@app.delete("/api/v1/posts/{post_id}")
async def delete_post(post_id: int, request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    if SECURE:
        raise HTTPException(status_code=405, detail="method not allowed")
    return {"deleted": True, "postId": post_id, "note": "benchmark does not actually delete seed data"}


@app.post("/api/v1/reports")
async def create_report(request: Request, db: Session = Depends(get_db)):
    if SECURE:
        me = current_user(request, db)
        org_id = me.org_id
    else:
        org_id = db.query(Organization).filter(Organization.slug == "acme").first().id
    data = await request.json()
    report = Report(org_id=org_id, name=data.get("name", "anon"), query_filter=data.get("queryFilter", "published"))
    db.add(report)
    db.commit()
    return {"id": report.id, "name": report.name}


@app.get("/api/v1/exports/legacy")
async def legacy_export(request: Request, db: Session = Depends(get_db)):
    if SECURE:
        me = current_user(request, db)
        posts = db.query(Post).filter(Post.org_id == me.org_id, Post.status == "published").all()
    else:
        posts = db.query(Post).order_by(Post.id).all()
    return {"deprecated": True, "posts": [post_dict(p) for p in posts]}


def is_private_or_internal(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in {"partner-api", "localhost", "127.0.0.1"} or host.startswith("169.254.")


@app.post("/api/v1/integrations/fetch")
async def integrations_fetch(request: Request, db: Session = Depends(get_db)):
    current_user(request, db)
    data = await request.json()
    url = data.get("url", "")
    if SECURE and is_private_or_internal(url):
        raise HTTPException(status_code=400, detail="blocked target")
    response = requests.get(url, timeout=2)
    return {"status": response.status_code, "body": response.text[:1000]}


@app.post("/api/v1/integrations/partner/sync")
async def partner_sync(request: Request, role: str = "user", db: Session = Depends(get_db)):
    me = current_user(request, db)
    url = f"{PARTNER_URL}/profile?email={me.email}&role={role}"
    response = requests.get(url, timeout=2)
    if SECURE:
        profile = yaml.safe_load(response.text) or {}
        me.display_name = str(profile.get("name", me.display_name))[:120]
    else:
        profile = yaml.load(response.text, Loader=yaml.Loader) or {}
        if profile.get("role"):
            me.role = profile["role"]
            me.is_admin = profile["role"] == "admin"
    db.commit()
    return public_user(me, sensitive=not SECURE)


@app.post("/api/v1/uploads")
async def upload_file(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    me = current_user(request, db)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    filename = file.filename or "upload.bin"
    safe_name = Path(filename).name
    target = (UPLOAD_DIR / (safe_name if SECURE else filename))
    target.parent.mkdir(parents=True, exist_ok=True)
    data = await file.read()
    if SECURE and len(data) > 1024 * 1024:
        raise HTTPException(status_code=400, detail="too large")
    target.write_bytes(data)
    escaped = not str(target.resolve()).startswith(str(UPLOAD_DIR.resolve()))
    attachment = Attachment(org_id=me.org_id, owner_id=me.id, filename=target.name, path=str(target))
    db.add(attachment)
    db.commit()
    return {"filename": target.name, "path": str(target), "escaped": escaped}


@app.post("/api/v1/invites")
async def create_invite(request: Request, db: Session = Depends(get_db)):
    me = current_user(request, db)
    data = await request.json()
    quantity = int(data.get("quantity", 1))
    billing = db.query(Billing).filter(Billing.org_id == me.org_id).first()
    if not billing:
        raise HTTPException(status_code=404, detail="missing billing")
    if SECURE:
        if quantity < 1 or billing.seats_used + quantity > billing.seats_limit:
            raise HTTPException(status_code=400, detail="invalid quantity")
    else:
        if billing.seats_used + quantity > billing.seats_limit:
            raise HTTPException(status_code=400, detail="seat limit")
    for i in range(max(quantity, 0)):
        db.add(Invite(org_id=me.org_id, email=data.get("email", f"invite{i}@bench.local")))
    billing.seats_used += quantity
    db.commit()
    return {"seatsUsed": billing.seats_used, "seatsLimit": billing.seats_limit}


@app.get("/api/v1/internal/audit")
async def audit_log(request: Request, db: Session = Depends(get_db)):
    if SECURE:
        me = current_user(request, db)
        require_admin(me)
    return {"logs": [row.message for row in db.query(AuditLog).order_by(AuditLog.id.desc()).limit(20).all()]}
