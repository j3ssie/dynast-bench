from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from .db import Base


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    slug = Column(String(120), unique=True, nullable=False)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(64), nullable=False)
    role = Column(String(32), nullable=False, default="user")
    is_admin = Column(Boolean, nullable=False, default=False)
    verified = Column(Boolean, nullable=False, default=True)
    display_name = Column(String(120), nullable=False, default="")
    timezone = Column(String(64), nullable=False, default="UTC")
    theme = Column(String(32), nullable=False, default="light")
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    reset_token = Column(String(255), nullable=True)
    org = relationship("Organization")


class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True)
    slug = Column(String(160), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="published")
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    org = relationship("Organization")
    author = relationship("User")


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    query_filter = Column(Text, nullable=True)


class Billing(Base):
    __tablename__ = "billing"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True)
    seats_limit = Column(Integer, nullable=False, default=3)
    seats_used = Column(Integer, nullable=False, default=0)
    balance_cents = Column(Integer, nullable=False, default=10000)


class Invite(Base):
    __tablename__ = "invites"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    email = Column(String(255), nullable=False)


class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(Integer, primary_key=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    path = Column(String(500), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    message = Column(Text, nullable=False)
