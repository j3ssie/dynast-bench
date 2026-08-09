from pathlib import Path
import hashlib

from .db import Base, SessionLocal, engine
from .models import Attachment, AuditLog, Billing, Invite, Organization, Post, Report, User

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "storage" / "uploads"
SECRET_FILE = BASE_DIR / "secret.txt"


def md5_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def main():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    SECRET_FILE.write_text("SWAGGER-FILE-SECRET-42d1\n", encoding="utf-8")
    db = SessionLocal()
    try:
        acme = Organization(name="Acme", slug="acme")
        globex = Organization(name="Globex", slug="globex")
        db.add_all([acme, globex])
        db.flush()

        admin = User(email="admin@bench.local", password_hash=md5_password("Admin123!"), role="admin", is_admin=True, verified=True, display_name="Acme Admin", org_id=acme.id, reset_token="admin-reset-token")
        editor = User(email="editor@bench.local", password_hash=md5_password("Editor123!"), role="editor", is_admin=False, verified=True, display_name="Acme Editor", org_id=acme.id, reset_token="editor-reset-token")
        user1 = User(email="user1@bench.local", password_hash=md5_password("User123!"), role="user", is_admin=False, verified=True, display_name="Acme User", org_id=acme.id, reset_token="user1-reset-token")
        user2 = User(email="user2@bench.local", password_hash=md5_password("User123!"), role="user", is_admin=False, verified=True, display_name="Globex User", org_id=globex.id, reset_token="globex-reset-token")
        service = User(email="admin", password_hash=md5_password("admin"), role="service", is_admin=True, verified=True, display_name="Weak Service Admin", org_id=acme.id, reset_token="service-reset-token")
        db.add_all([admin, editor, user1, user2, service])
        db.flush()

        db.add_all([
            Post(slug="acme-welcome", title="Acme welcome", body="Public Acme onboarding notes", status="published", org_id=acme.id, author_id=editor.id),
            Post(slug="acme-roadmap", title="Acme roadmap", body="Q4 launch plan", status="published", org_id=acme.id, author_id=editor.id),
            Post(slug="acme-draft", title="Acme draft", body="Draft notes", status="draft", org_id=acme.id, author_id=user1.id),
            Post(slug="globex-news", title="Globex news", body="Public Globex update", status="published", org_id=globex.id, author_id=user2.id),
            Post(slug="globex-internal", title="Globex internal", body="GLOBEX-CONFIDENTIAL-MARKER-7f3a", status="draft", org_id=globex.id, author_id=user2.id),
            Post(slug="globex-archive", title="Globex archive", body="Archived public content", status="published", org_id=globex.id, author_id=user2.id),
        ])
        db.add_all([
            Report(org_id=acme.id, name="published", query_filter="published"),
            Billing(org_id=acme.id, seats_limit=3, seats_used=0, balance_cents=10000),
            Billing(org_id=globex.id, seats_limit=3, seats_used=0, balance_cents=10000),
            Invite(org_id=acme.id, email="seed-invite@bench.local"),
            Attachment(org_id=acme.id, owner_id=user1.id, filename="welcome.txt", path=str(UPLOAD_DIR / "welcome.txt")),
            AuditLog(message="seed audit log"),
        ])
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    main()
