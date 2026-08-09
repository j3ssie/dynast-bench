from pathlib import Path
import hashlib

from .db import Base, SessionLocal, engine
from .models import Attachment, Billing, Comment, Invite, Organization, Post, Report, User

BASE_DIR = Path(__file__).resolve().parent.parent
ATTACH_DIR = BASE_DIR / "storage" / "attachments"
AVATAR_DIR = BASE_DIR / "storage" / "avatars"
EXPORT_DIR = BASE_DIR / "storage" / "exports"
SECRET_FILE = BASE_DIR / "secret.txt"


def md5_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def main():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    ATTACH_DIR.mkdir(parents=True, exist_ok=True)
    AVATAR_DIR.mkdir(parents=True, exist_ok=True)
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    SECRET_FILE.write_text("FASTAPI-LOCAL-SECRET-9b4d\n", encoding="utf-8")
    (ATTACH_DIR / "acme-plan.txt").write_text("Acme launch checklist\n", encoding="utf-8")
    (ATTACH_DIR / "globex-plan.txt").write_text("GLOBEX-CONFIDENTIAL-MARKER-7f3a\n", encoding="utf-8")
    (AVATAR_DIR / "default.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'></svg>\n", encoding="utf-8")

    db = SessionLocal()
    try:
        acme = Organization(name="Acme", slug="acme")
        globex = Organization(name="Globex", slug="globex")
        db.add_all([acme, globex])
        db.flush()

        admin = User(email="admin@bench.local", password_hash=md5_password("Admin123!"), role="admin", is_admin=True, verified=True, org_id=acme.id)
        editor = User(email="editor@bench.local", password_hash=md5_password("Editor123!"), role="editor", is_admin=False, verified=True, org_id=acme.id)
        user1 = User(email="user1@bench.local", password_hash=md5_password("User123!"), role="user", is_admin=False, verified=True, org_id=acme.id)
        user2 = User(email="user2@bench.local", password_hash=md5_password("User123!"), role="user", is_admin=False, verified=True, org_id=globex.id)
        service = User(email="admin", password_hash=md5_password("Service123!"), role="service", is_admin=True, verified=True, org_id=acme.id)
        db.add_all([admin, editor, user1, user2, service])
        db.flush()

        posts = [
            Post(slug="acme-welcome", title="Acme welcome", body="Public Acme onboarding notes", status="published", org_id=acme.id, author_id=editor.id),
            Post(slug="acme-roadmap", title="Acme roadmap", body="Q4 launch plan", status="published", org_id=acme.id, author_id=editor.id),
            Post(slug="acme-draft", title="Acme draft", body="Draft notes", status="draft", org_id=acme.id, author_id=user1.id),
            Post(slug="globex-news", title="Globex news", body="Public Globex update", status="published", org_id=globex.id, author_id=user2.id),
            Post(slug="globex-internal", title="Globex internal", body="GLOBEX-CONFIDENTIAL-MARKER-7f3a", status="draft", org_id=globex.id, author_id=user2.id),
            Post(slug="globex-archive", title="Globex archive", body="Archived public content", status="published", org_id=globex.id, author_id=user2.id),
        ]
        db.add_all(posts)
        db.flush()

        db.add_all([
            Comment(post_id=posts[0].id, author_id=user1.id, body="Looks good"),
            Attachment(org_id=acme.id, owner_id=user1.id, filename="acme-plan.txt", path=str(ATTACH_DIR / "acme-plan.txt")),
            Attachment(org_id=globex.id, owner_id=user2.id, filename="globex-plan.txt", path=str(ATTACH_DIR / "globex-plan.txt")),
            Billing(org_id=acme.id, seats_limit=3, seats_used=0, balance_cents=10000),
            Billing(org_id=globex.id, seats_limit=3, seats_used=0, balance_cents=10000),
            Invite(org_id=acme.id, email="seed-invite@bench.local"),
            Report(org_id=acme.id, name="published", template="Hello {{ user }}", query_filter="published"),
        ])
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    main()
