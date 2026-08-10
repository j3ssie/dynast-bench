package com.bench.springboot;

import jakarta.persistence.*;
import java.io.Serializable;

@Entity @Table(name = "orgs")
class Org {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) Long id;
    String name;
    @Column(unique = true) String slug;
    protected Org() {}
    Org(String name, String slug) { this.name = name; this.slug = slug; }
    public Long getId() { return id; }
    public String getName() { return name; }
    public String getSlug() { return slug; }
}

@Entity @Table(name = "users")
class BenchUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) Long id;
    @Column(unique = true, nullable = false) String email;
    String passwordHash;
    String role;
    boolean isAdmin;
    boolean verified;
    boolean enabled;
    String displayName;
    String resetToken;
    @ManyToOne(fetch = FetchType.LAZY) Org org;
    protected BenchUser() {}
    BenchUser(String email, String passwordHash, String role, boolean isAdmin, boolean verified, Org org, String displayName) {
        this.email = email; this.passwordHash = passwordHash; this.role = role; this.isAdmin = isAdmin;
        this.verified = verified; this.enabled = true; this.org = org; this.displayName = displayName;
    }
    public Long getId() { return id; }
    public String getEmail() { return email; }
    public String getPasswordHash() { return passwordHash; }
    public String getRole() { return role; }
    public boolean isAdmin() { return isAdmin; }
    public boolean isVerified() { return verified; }
    public boolean isEnabled() { return enabled; }
    public String getDisplayName() { return displayName; }
    public String getResetToken() { return resetToken; }
    public Org getOrg() { return org; }
}

@Entity @Table(name = "posts")
class Post {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) Long id;
    @Column(unique = true) String slug;
    String title;
    @Column(length = 4096) String body;
    String status;
    @ManyToOne(fetch = FetchType.LAZY) Org org;
    @ManyToOne(fetch = FetchType.LAZY) BenchUser author;
    protected Post() {}
    Post(String slug, String title, String body, String status, Org org, BenchUser author) {
        this.slug = slug; this.title = title; this.body = body; this.status = status; this.org = org; this.author = author;
    }
    public Long getId() { return id; }
    public String getSlug() { return slug; }
    public String getTitle() { return title; }
    public String getBody() { return body; }
    public String getStatus() { return status; }
    public Org getOrg() { return org; }
    public BenchUser getAuthor() { return author; }
}

@Entity @Table(name = "comments")
class Comment {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) Long id;
    @Column(length = 4096) String body;
    @ManyToOne(fetch = FetchType.LAZY) Post post;
    @ManyToOne(fetch = FetchType.LAZY) BenchUser author;
    protected Comment() {}
    Comment(String body, Post post, BenchUser author) { this.body = body; this.post = post; this.author = author; }
    public Long getId() { return id; }
    public String getBody() { return body; }
    public Post getPost() { return post; }
    public BenchUser getAuthor() { return author; }
}

@Entity @Table(name = "reports")
class ReportDefinition {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) Long id;
    String name;
    @ManyToOne(fetch = FetchType.LAZY) BenchUser owner;
    protected ReportDefinition() {}
    ReportDefinition(String name, BenchUser owner) { this.name = name; this.owner = owner; }
    public Long getId() { return id; }
    public String getName() { return name; }
    public BenchUser getOwner() { return owner; }
}

@Entity @Table(name = "invites")
class Invite {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) Long id;
    String email;
    @ManyToOne(fetch = FetchType.LAZY) Org org;
    protected Invite() {}
    Invite(String email, Org org) { this.email = email; this.org = org; }
    public Long getId() { return id; }
    public String getEmail() { return email; }
    public Org getOrg() { return org; }
}

class RestoreBlob implements Serializable {
    private static final long serialVersionUID = 1L;
    public String marker;
    public RestoreBlob() {}
}

@Entity @Table(name = "signup_drafts")
class SignupDraft {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) Long id;
    String email;
    String code;
    boolean verified;
    String displayName = "";
    String role = "user";
    String orgSlug = "acme";
    boolean completed;
    protected SignupDraft() {}
    SignupDraft(String email, String code) { this.email = email; this.code = code; }
    public Long getId() { return id; }
    public String getEmail() { return email; }
    public String getCode() { return code; }
    public boolean isVerified() { return verified; }
    public void setVerified(boolean v) { this.verified = v; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String d) { this.displayName = d; }
    public String getRole() { return role; }
    public void setRole(String r) { this.role = r; }
    public String getOrgSlug() { return orgSlug; }
    public void setOrgSlug(String s) { this.orgSlug = s; }
    public boolean isCompleted() { return completed; }
    public void setCompleted(boolean c) { this.completed = c; }
}
