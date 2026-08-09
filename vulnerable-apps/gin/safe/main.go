package main

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

const verifyToken = "benchsecret"

// Session HMAC key is generated at boot from crypto/rand (no hardcoded secret).
var sessionKey = randomBytes(32)

var (
	baseDir    = getenv("APP_BASE_DIR", "/app")
	storageDir = filepath.Join(baseDir, "storage")
	beaconMu   sync.Mutex
	beaconHits = map[string]bool{}
)

// chromeBin is the headless browser used to render URLs to PDF.
var chromeBin = getenv("CHROME_BIN", "chromium")

type User struct {
	ID           int
	Email        string
	PasswordHash string
	Role         string
	IsAdmin      bool
	Verified     bool
	OrgID        int
	OrgSlug      string
	DisplayName  string
}

type Post struct {
	ID     int
	Slug   string
	Title  string
	Body   string
	Status string
	OrgID  int
}

func main() {
	dsn := getenv("DATABASE_URL", "postgres://bench:bench@postgres:5432/bench?sslmode=disable")
	var err error
	db, err = sql.Open("pgx", dsn)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for {
		if err := db.PingContext(ctx); err == nil {
			break
		}
		if ctx.Err() != nil {
			log.Fatal("database not ready: ", ctx.Err())
		}
		time.Sleep(1 * time.Second)
	}
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Fatal(err)
	}
	if err := seedDB(context.Background()); err != nil {
		log.Fatal(err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/", index)

	// Harness-only verification API (guarded by X-Verify-Token, except the beacon).
	r.GET("/api/_verify/health", verifyHealth)
	r.GET("/api/_verify/user", verifyUser)
	r.GET("/api/_verify/post", verifyPost)
	r.POST("/api/_verify/reset", verifyReset)
	r.GET("/api/_verify/ssrf-beacon", ssrfBeacon)
	r.GET("/api/_verify/ssrf-check", ssrfCheck)

	// Auth (infrastructure, identical in both variants).
	r.POST("/api/auth/login", login)

	// Feature surface (planted sinks + safe near-miss siblings).
	r.GET("/api/debug/info", debugInfo)                 // [INFO-001] sink
	r.GET("/api/version", versionInfo)                  // near-miss of INFO-001
	r.GET("/api/posts/search", searchPosts)             // near-miss of SQLI-001
	r.GET("/api/posts/:id", getPost)                    // near-miss of IDOR-001
	r.POST("/api/posts/:id/grant", createGrant)         // [IDOR-001] step 1
	r.GET("/api/grants/:token", readGrant)              // [IDOR-001] sink
	r.PATCH("/api/users/me", updateMe)                  // [MASSASSIGN-001] (+ SQLI-001 write path)
	r.GET("/api/reports/timeline", reportTimeline)      // [SQLI-001] sink
	r.POST("/api/images/thumbnail", thumbnail)          // [RCE-001] sink
	r.POST("/api/images/thumbnail-safe", thumbnailSafe) // near-miss of RCE-001
	r.POST("/api/render/pdf", renderPDF)                // [SSRF-001] sink
	r.GET("/api/link/preview", linkPreview)             // near-miss of SSRF-001
	r.POST("/api/import/preview", importPreview)        // [DOS-001] sink
	r.POST("/api/import/text", importText)              // near-miss of DOS-001
	r.GET("/api/admin/users", adminUsers)               // [AUTHZ-001] sink
	r.GET("/goto", gotoNext)                            // [REDIRECT-001] sink
	r.GET("/search", searchPage)                        // [XSS-REFLECT-001] sink

	log.Printf("Gin benchmark app (vuln) listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return b
}

func index(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, `<h1>Snapshot (Gin)</h1><p><strong>DELIBERATELY INSECURE</strong> benchmark app. Local only.</p>`)
}

func seedDB(ctx context.Context) error {
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS grants, posts, users, organizations CASCADE`,
		`CREATE TABLE organizations(id SERIAL PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL)`,
		`CREATE TABLE users(id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, is_admin BOOLEAN NOT NULL, verified BOOLEAN NOT NULL, org_id INTEGER NOT NULL REFERENCES organizations(id), display_name TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE posts(id SERIAL PRIMARY KEY, slug TEXT UNIQUE NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, org_id INTEGER NOT NULL REFERENCES organizations(id), author_id INTEGER NOT NULL REFERENCES users(id))`,
		`CREATE TABLE grants(id SERIAL PRIMARY KEY, post_id INTEGER NOT NULL REFERENCES posts(id), requester_id INTEGER NOT NULL REFERENCES users(id), token TEXT UNIQUE NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}

	var acme, globex int
	if err := db.QueryRowContext(ctx, `INSERT INTO organizations(name,slug) VALUES('Acme','acme') RETURNING id`).Scan(&acme); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, `INSERT INTO organizations(name,slug) VALUES('Globex','globex') RETURNING id`).Scan(&globex); err != nil {
		return err
	}
	insertUser := func(email, pass, role string, admin bool, orgID int) (int, error) {
		hash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
		var id int
		err := db.QueryRowContext(ctx, `INSERT INTO users(email,password_hash,role,is_admin,verified,org_id,display_name) VALUES($1,$2,$3,$4,true,$5,$6) RETURNING id`, email, string(hash), role, admin, orgID, email).Scan(&id)
		return id, err
	}
	if _, err := insertUser("admin@bench.local", "Admin123!", "admin", true, acme); err != nil {
		return err
	}
	editorID, err := insertUser("editor@bench.local", "Editor123!", "editor", false, acme)
	if err != nil {
		return err
	}
	user1ID, err := insertUser("user1@bench.local", "User123!", "user", false, acme)
	if err != nil {
		return err
	}
	user2ID, err := insertUser("user2@bench.local", "User123!", "user", false, globex)
	if err != nil {
		return err
	}
	// Fixed: the service account uses a strong, non-default password.
	if _, err := insertUser("admin", "S3rvice-Acct-9Q7xZ!", "service", true, acme); err != nil {
		return err
	}

	posts := []struct {
		slug, title, body, status string
		orgID, authorID           int
	}{
		{"acme-welcome", "Acme welcome", "Public Acme onboarding notes", "published", acme, editorID},
		{"acme-roadmap", "Acme roadmap", "Q4 launch plan", "published", acme, editorID},
		{"acme-draft", "Acme draft", "Draft notes", "draft", acme, user1ID},
		{"globex-news", "Globex news", "Public Globex update", "published", globex, user2ID},
		{"globex-internal", "Globex internal", "GLOBEX-CONFIDENTIAL-MARKER-7f3a", "draft", globex, user2ID},
		{"globex-archive", "Globex archive", "Archived public content", "published", globex, user2ID},
	}
	for _, p := range posts {
		if _, err := db.ExecContext(ctx, `INSERT INTO posts(slug,title,body,status,org_id,author_id) VALUES($1,$2,$3,$4,$5,$6)`, p.slug, p.title, p.body, p.status, p.orgID, p.authorID); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Verification API (harness-only)
// ---------------------------------------------------------------------------

func requireVerify(c *gin.Context) bool {
	if c.GetHeader("X-Verify-Token") != verifyToken {
		c.JSON(http.StatusForbidden, gin.H{"error": "bad verify token"})
		return false
	}
	return true
}

func verifyHealth(c *gin.Context) {
	if err := db.PingContext(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "bad", "db": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "db": "ok", "app": "gin"})
}

func verifyUser(c *gin.Context) {
	if !requireVerify(c) {
		return
	}
	u := findUserByEmail(c.Request.Context(), c.Query("email"))
	if u.ID == 0 {
		c.JSON(http.StatusOK, gin.H{"exists": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"exists": true, "id": u.ID, "role": u.Role, "isAdmin": u.IsAdmin, "verified": u.Verified, "orgSlug": u.OrgSlug})
}

func verifyPost(c *gin.Context) {
	if !requireVerify(c) {
		return
	}
	var p Post
	var authorEmail, orgSlug string
	_ = db.QueryRowContext(c.Request.Context(), `SELECT p.id,p.slug,p.title,p.body,p.status,p.org_id,u.email,o.slug FROM posts p JOIN users u ON u.id=p.author_id JOIN organizations o ON o.id=p.org_id WHERE p.slug=$1`, c.Query("slug")).Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &p.Status, &p.OrgID, &authorEmail, &orgSlug)
	if p.ID == 0 {
		c.JSON(http.StatusOK, gin.H{"exists": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"exists": true, "id": p.ID, "slug": p.Slug, "status": p.Status, "authorEmail": authorEmail, "orgSlug": orgSlug, "body": p.Body})
}

// verifyReset restores state the mutating PoCs touch, so PoCs stay order-independent.
func verifyReset(c *gin.Context) {
	if !requireVerify(c) {
		return
	}
	ctx := c.Request.Context()
	_, _ = db.ExecContext(ctx, `UPDATE users SET role='user', is_admin=false, display_name='user1@bench.local' WHERE email='user1@bench.local'`)
	_, _ = db.ExecContext(ctx, `DELETE FROM grants`)
	beaconMu.Lock()
	beaconHits = map[string]bool{}
	beaconMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ssrfBeacon is the internal SSRF target. It records that a token was fetched.
// No verify token required so headless chrome (which cannot send one) can reach it.
func ssrfBeacon(c *gin.Context) {
	tok := c.Query("token")
	if tok != "" {
		beaconMu.Lock()
		beaconHits[tok] = true
		beaconMu.Unlock()
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, "<html><body>GIN-INTERNAL-BEACON</body></html>")
}

func ssrfCheck(c *gin.Context) {
	if !requireVerify(c) {
		return
	}
	beaconMu.Lock()
	hit := beaconHits[c.Query("token")]
	beaconMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"hit": hit})
}

// ---------------------------------------------------------------------------
// Auth (infrastructure; not a scored bug - identical in both variants)
// ---------------------------------------------------------------------------

func login(c *gin.Context) {
	var data struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	_ = c.ShouldBindJSON(&data)
	user := findUserByEmail(c.Request.Context(), data.Email)
	if user.ID == 0 || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(data.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	c.SetCookie("session", makeSession(user), 3600, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": user.ID, "role": user.Role})
}

func currentUser(c *gin.Context) (User, bool) {
	ck, err := c.Cookie("session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login required"})
		return User{}, false
	}
	id, err := verifySession(ck)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login required"})
		return User{}, false
	}
	u := findUserByID(c.Request.Context(), id)
	if u.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "login required"})
		return User{}, false
	}
	return u, true
}

func makeSession(u User) string {
	b := b64url([]byte(strconv.Itoa(u.ID)))
	sig := b64url(hmacSHA256(b, sessionKey))
	return b + "." + sig
}

func verifySession(value string) (int, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return 0, errors.New("bad session")
	}
	expected := b64url(hmacSHA256(parts[0], sessionKey))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return 0, errors.New("bad session")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(raw))
}

func hmacSHA256(data string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func b64url(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func findUserByEmail(ctx context.Context, email string) User {
	var u User
	_ = db.QueryRowContext(ctx, `SELECT u.id,u.email,u.password_hash,u.role,u.is_admin,u.verified,u.org_id,o.slug,u.display_name FROM users u JOIN organizations o ON o.id=u.org_id WHERE u.email=$1`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.IsAdmin, &u.Verified, &u.OrgID, &u.OrgSlug, &u.DisplayName)
	return u
}

func findUserByID(ctx context.Context, id int) User {
	var u User
	_ = db.QueryRowContext(ctx, `SELECT u.id,u.email,u.password_hash,u.role,u.is_admin,u.verified,u.org_id,o.slug,u.display_name FROM users u JOIN organizations o ON o.id=u.org_id WHERE u.id=$1`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.IsAdmin, &u.Verified, &u.OrgID, &u.OrgSlug, &u.DisplayName)
	return u
}

// ---------------------------------------------------------------------------
// INFO-001: information disclosure
// ---------------------------------------------------------------------------

func debugInfo(c *gin.Context) {
	// Fixed: report only non-sensitive build info; never dump env/secrets.
	c.JSON(http.StatusOK, gin.H{"app": "gin", "version": "1.0.0", "status": "ok"})
}

// NM-INFO-001: safe sibling - reports only non-sensitive build info.
func versionInfo(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"app": "gin", "version": "1.0.0"})
}

// ---------------------------------------------------------------------------
// IDOR-001: multi-step IDOR (grant workflow)
// ---------------------------------------------------------------------------

func createGrant(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	id, _ := strconv.Atoi(c.Param("id"))
	var exists int
	_ = db.QueryRowContext(c.Request.Context(), `SELECT id FROM posts WHERE id=$1`, id).Scan(&exists)
	if exists == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such post"})
		return
	}
	tok := b64url(randomBytes(12))
	// Step 1: a grant is minted for any post id without checking the caller's org.
	_, err := db.ExecContext(c.Request.Context(), `INSERT INTO grants(post_id,requester_id,token) VALUES($1,$2,$3)`, id, user.ID, tok)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok})
}

func readGrant(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	var post Post
	// Fixed: enforce org ownership on the granted post before returning it.
	_ = db.QueryRowContext(c.Request.Context(), `SELECT p.id,p.slug,p.title,p.body,p.status,p.org_id FROM grants g JOIN posts p ON p.id=g.post_id WHERE g.token=$1`, c.Param("token")).Scan(&post.ID, &post.Slug, &post.Title, &post.Body, &post.Status, &post.OrgID)
	if post.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such grant"})
		return
	}
	if post.OrgID != user.OrgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": post.ID, "slug": post.Slug, "title": post.Title, "body": post.Body, "status": post.Status})
}

// NM-IDOR-001: safe sibling - direct fetch enforces org ownership.
func getPost(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	id, _ := strconv.Atoi(c.Param("id"))
	var post Post
	_ = db.QueryRowContext(c.Request.Context(), `SELECT id,slug,title,body,status,org_id FROM posts WHERE id=$1`, id).Scan(&post.ID, &post.Slug, &post.Title, &post.Body, &post.Status, &post.OrgID)
	if post.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if post.OrgID != user.OrgID && post.Status != "published" {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": post.ID, "slug": post.Slug, "title": post.Title, "body": post.Body, "status": post.Status})
}

// ---------------------------------------------------------------------------
// MASSASSIGN-001 + second-order SQLi write path
// ---------------------------------------------------------------------------

func updateMe(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	var in struct {
		DisplayName *string `json:"displayName"`
		Role        *string `json:"role"`
		IsAdmin     *bool   `json:"isAdmin"`
	}
	_ = c.ShouldBindJSON(&in)
	if in.DisplayName != nil {
		// display_name is stored safely (parameterized) - it is the source read
		// back later by reportTimeline (second-order sink).
		_, _ = db.ExecContext(c.Request.Context(), `UPDATE users SET display_name=$1 WHERE id=$2`, *in.DisplayName, user.ID)
	}
	// Fixed: privileged fields (role, isAdmin) are ignored; only displayName is updatable.
	_ = in.Role
	_ = in.IsAdmin
	c.JSON(http.StatusOK, gin.H{"id": user.ID, "email": user.Email, "role": user.Role, "isAdmin": user.IsAdmin})
}

// ---------------------------------------------------------------------------
// SQLI-001: second-order SQL injection
// ---------------------------------------------------------------------------

func reportTimeline(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	var label string
	_ = db.QueryRowContext(c.Request.Context(), `SELECT display_name FROM users WHERE id=$1`, user.ID).Scan(&label)
	// Fixed: the stored value is passed as a bound parameter, not interpolated.
	pattern := fmt.Sprintf("%%%s%%", label)
	rows, err := db.QueryContext(c.Request.Context(), `SELECT id, slug, body FROM posts WHERE status = 'published' AND body ILIKE $1`, pattern)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id int
		var slug, body string
		_ = rows.Scan(&id, &slug, &body)
		out = append(out, gin.H{"id": id, "slug": slug, "body": body})
	}
	c.JSON(http.StatusOK, gin.H{"results": out})
}

// NM-SQL-001: safe sibling - published-post search built with a placeholder.
func searchPosts(c *gin.Context) {
	q := "%" + c.Query("q") + "%"
	rows, err := db.QueryContext(c.Request.Context(), `SELECT id,slug,title FROM posts WHERE status='published' AND title ILIKE $1`, q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id int
		var slug, title string
		_ = rows.Scan(&id, &slug, &title)
		out = append(out, gin.H{"id": id, "slug": slug, "title": title})
	}
	c.JSON(http.StatusOK, gin.H{"results": out})
}

// ---------------------------------------------------------------------------
// RCE-001: ImageMagick shell-out command injection
// ---------------------------------------------------------------------------

func thumbnail(c *gin.Context) {
	var in struct {
		Size string `json:"size"`
	}
	_ = c.ShouldBindJSON(&in)
	if in.Size == "" {
		in.Size = "64x64"
	}
	out := filepath.Join(storageDir, "thumb.png")
	// Fixed: convert is invoked with an argument slice, so the geometry cannot
	// break out of the command (no shell interpretation).
	res, _ := exec.Command("convert", "rose:", "-resize", in.Size, out).CombinedOutput()
	c.Header("Content-Type", "text/plain")
	c.String(http.StatusOK, string(res))
}

// NM-RCE-001: safe sibling - convert is invoked with an argument slice (no shell).
func thumbnailSafe(c *gin.Context) {
	var in struct {
		Size string `json:"size"`
	}
	_ = c.ShouldBindJSON(&in)
	if in.Size == "" {
		in.Size = "64x64"
	}
	out := filepath.Join(storageDir, "thumb-safe.png")
	res, _ := exec.Command("convert", "rose:", "-resize", in.Size, out).CombinedOutput()
	c.Header("Content-Type", "text/plain")
	c.String(http.StatusOK, string(res)+"done")
}

// ---------------------------------------------------------------------------
// SSRF-001: SSRF via headless-chrome PDF rendering
// ---------------------------------------------------------------------------

func renderPDF(c *gin.Context) {
	var in struct {
		URL string `json:"url"`
	}
	_ = c.ShouldBindJSON(&in)
	if in.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "url required"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
	defer cancel()
	out := filepath.Join(storageDir, "render.pdf")
	// Fixed: reject internal/loopback/link-local destinations before rendering.
	if isPrivateURL(in.URL) {
		c.JSON(http.StatusForbidden, gin.H{"error": "destination not allowed"})
		return
	}
	cmd := exec.CommandContext(ctx, chromeBin,
		"--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
		"--timeout=15000", "--print-to-pdf="+out, in.URL)
	cmd.Env = append(os.Environ(), "HOME=/tmp")
	res, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "render failed", "detail": strings.TrimSpace(string(res))})
		return
	}
	fi, _ := os.Stat(out)
	var size int64
	if fi != nil {
		size = fi.Size()
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "bytes": size})
}

// NM-SSRF-001: safe sibling - a link preview that blocks internal destinations.
func linkPreview(c *gin.Context) {
	raw := c.Query("url")
	if isPrivateURL(raw) {
		c.JSON(http.StatusForbidden, gin.H{"error": "destination not allowed"})
		return
	}
	resp, err := http.Get(raw)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
	c.Header("Content-Type", "text/plain")
	c.String(resp.StatusCode, string(body))
}

func isPrivateURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return true
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return true
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// DOS-001: uncontrolled resource consumption (gzip decompression bomb)
// ---------------------------------------------------------------------------

func importPreview(c *gin.Context) {
	gr, err := gzip.NewReader(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected gzip body"})
		return
	}
	defer gr.Close()
	// Fixed: bound the decompressed size with a LimitReader (decompression bomb guard).
	const maxBytes = 1 << 20
	n, _ := io.Copy(io.Discard, io.LimitReader(gr, maxBytes+1))
	if n > maxBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "decompressed body too large"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"bytes": n})
}

// NM-DOS-001: safe sibling - plain text import bounded by a LimitReader.
func importText(c *gin.Context) {
	const maxBytes = 1 << 20
	lr := io.LimitReader(c.Request.Body, maxBytes+1)
	n, _ := io.Copy(io.Discard, lr)
	if n > maxBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "too large"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"bytes": n})
}

// ---------------------------------------------------------------------------
// AUTHZ-001: broken function-level authorization
// ---------------------------------------------------------------------------

func adminUsers(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	// Fixed: the admin user listing requires the admin role.
	if !user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin required"})
		return
	}
	rows, _ := db.QueryContext(c.Request.Context(), `SELECT u.id,u.email,u.role,o.slug FROM users u JOIN organizations o ON o.id=u.org_id ORDER BY u.id`)
	defer rows.Close()
	users := []gin.H{}
	for rows.Next() {
		var id int
		var email, role, org string
		_ = rows.Scan(&id, &email, &role, &org)
		users = append(users, gin.H{"id": id, "email": email, "role": role, "org": org})
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// ---------------------------------------------------------------------------
// REDIRECT-001: open redirect
// ---------------------------------------------------------------------------

func gotoNext(c *gin.Context) {
	next := c.Query("next")
	// Fixed: only allow same-origin relative paths (no scheme/host, no protocol-relative //).
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	c.Redirect(http.StatusFound, next)
}

// ---------------------------------------------------------------------------
// XSS-REFLECT-001: reflected cross-site scripting
// ---------------------------------------------------------------------------

func searchPage(c *gin.Context) {
	q := html.EscapeString(c.Query("q"))
	c.Header("Content-Type", "text/html; charset=utf-8")
	// Fixed: q is HTML-escaped before being reflected into the page.
	c.String(http.StatusOK, "<h1>Search</h1><div id='q'>"+q+"</div>")
}
