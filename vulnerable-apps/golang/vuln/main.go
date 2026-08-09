package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	html "html"
	htmpl "html/template"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	ttmpl "text/template"
	time "time"

	"github.com/go-chi/chi/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var (
	_ = crand.Reader
	_ = hex.EncodeToString
	_ = html.EscapeString
	_ = mathrand.Int
	_ = pprof.Index
	_ = ttmpl.Must
)

const verifyToken = "benchsecret"

var sessionKey = []byte("hardcoded-32-byte-gorilla-session-key")
var jwtSecret = []byte("hardcoded-go-jwt-secret")

var (
	baseDir      = getenv("APP_BASE_DIR", "/app")
	storageDir   = filepath.Join(baseDir, "storage")
	attachDir    = filepath.Join(storageDir, "attachments")
	avatarDir    = filepath.Join(storageDir, "avatars")
	importDir    = filepath.Join(storageDir, "imports")
	secretFile   = filepath.Join(baseDir, "secret.txt")
	loginMetrics = map[string]int{}
	loginMu      sync.Mutex
	attemptMu    sync.Mutex
	attempts     = map[string]int{}
	inviteMu     sync.Mutex
)

type User struct {
	ID           int
	Email        string
	PasswordHash string
	Role         string
	IsAdmin      bool
	Verified     bool
	OrgID        int
	OrgSlug      string
}

type Post struct {
	ID     int
	Slug   string
	Title  string
	Body   string
	Status string
	OrgID  int
}

type Comment struct {
	Body string
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
	if err := seedDB(context.Background()); err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Use(corsMiddleware)
	r.Get("/", index)
	r.Options("/*", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r.Get("/api/_verify/health", verifyHealth)
	r.Get("/api/_verify/user", verifyUser)
	r.Get("/api/_verify/post", verifyPost)
	r.Post("/api/_verify/reset-acme", verifyResetAcme)
	r.Post("/api/auth/login", login)
	r.Post("/api/auth/token", token)
	r.Post("/api/auth/reset", resetPassword)
	r.Get("/api/posts/search", searchPosts)
	r.Get("/api/posts/list", listPosts)
	r.Get("/api/posts/{id}", getPost)
	r.Patch("/api/users/me", updateMe)
	r.Get("/api/admin/users", adminUsers)
	r.Get("/api/reports/admin-summary", adminSummary)
	r.Post("/api/reports/render", renderReport)
	r.Get("/api/reports/dashboard", renderDashboard)
	r.Post("/api/reports/export", exportReport)
	r.Post("/api/reports", createReport)
	r.Get("/api/reports/{id}/results", reportResults)
	r.Get("/api/fetch", fetchURL)
	r.Get("/goto", gotoNext)
	r.Post("/api/comments", addComment)
	r.Get("/posts/{id}/html", postHTML)
	r.Get("/search", searchPage)
	r.Get("/api/attachments/download", downloadAttachment)
	r.Get("/api/attachments/avatar-download", downloadAvatarSafe)
	r.Post("/api/import/archive", importArchive)
	r.Post("/api/billing/seats", billingSeats)
	r.Get("/api/billing/status", billingStatus)
	r.Post("/api/invites", invites)
	r.Get("/metrics", metrics)
	r.HandleFunc("/debug/pprof/", pprof.Index)
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	r.HandleFunc("/debug/pprof/profile", pprof.Profile)
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	r.HandleFunc("/debug/pprof/trace", pprof.Trace)
	r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))

	log.Printf("Go benchmark app (vuln) listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", r))
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", r.Header.Get("Access-Control-Request-Headers"))
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<h1>TaskFlow Go</h1><p><strong>DELIBERATELY INSECURE</strong> benchmark app. Local only.</p>`))
}

func seedDB(ctx context.Context) error {
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS comments, attachments, invites, billing, reports, posts, users, organizations CASCADE`,
		`CREATE TABLE organizations(id SERIAL PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL)`,
		`CREATE TABLE users(id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, is_admin BOOLEAN NOT NULL, verified BOOLEAN NOT NULL, org_id INTEGER NOT NULL REFERENCES organizations(id), reset_token TEXT, display_name TEXT DEFAULT '')`,
		`CREATE TABLE posts(id SERIAL PRIMARY KEY, slug TEXT UNIQUE NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL, org_id INTEGER NOT NULL REFERENCES organizations(id), author_id INTEGER NOT NULL REFERENCES users(id))`,
		`CREATE TABLE comments(id SERIAL PRIMARY KEY, post_id INTEGER NOT NULL REFERENCES posts(id), author_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL)`,
		`CREATE TABLE attachments(id SERIAL PRIMARY KEY, org_id INTEGER NOT NULL REFERENCES organizations(id), owner_id INTEGER NOT NULL REFERENCES users(id), filename TEXT NOT NULL, path TEXT NOT NULL)`,
		`CREATE TABLE invites(id SERIAL PRIMARY KEY, org_id INTEGER NOT NULL REFERENCES organizations(id), email TEXT NOT NULL)`,
		`CREATE TABLE billing(id SERIAL PRIMARY KEY, org_id INTEGER UNIQUE NOT NULL REFERENCES organizations(id), seats_limit INTEGER NOT NULL DEFAULT 3, seats_used INTEGER NOT NULL DEFAULT 0, balance_cents INTEGER NOT NULL DEFAULT 10000)`,
		`CREATE TABLE reports(id SERIAL PRIMARY KEY, org_id INTEGER NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, template TEXT NOT NULL DEFAULT 'Hello {.User}')`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, dir := range []string{attachDir, avatarDir, importDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	_ = os.WriteFile(secretFile, []byte("GO-LOCAL-SECRET-2f7b\n"), 0644)
	_ = os.WriteFile(filepath.Join(attachDir, "acme-plan.txt"), []byte("Acme launch checklist\n"), 0644)
	_ = os.WriteFile(filepath.Join(attachDir, "globex-plan.txt"), []byte("GLOBEX-CONFIDENTIAL-MARKER-7f3a\n"), 0644)
	_ = os.WriteFile(filepath.Join(avatarDir, "default.svg"), []byte("<svg xmlns='http://www.w3.org/2000/svg'></svg>\n"), 0644)

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
	adminID, err := insertUser("admin@bench.local", "Admin123!", "admin", true, acme)
	if err != nil {
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
	_, err = insertUser("admin", "admin", "service", true, acme)
	if err != nil {
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
	postIDs := map[string]int{}
	for _, p := range posts {
		var id int
		if err := db.QueryRowContext(ctx, `INSERT INTO posts(slug,title,body,status,org_id,author_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`, p.slug, p.title, p.body, p.status, p.orgID, p.authorID).Scan(&id); err != nil {
			return err
		}
		postIDs[p.slug] = id
	}
	_, _ = db.ExecContext(ctx, `INSERT INTO comments(post_id,author_id,body) VALUES($1,$2,'Looks good')`, postIDs["acme-welcome"], user1ID)
	_, _ = db.ExecContext(ctx, `INSERT INTO attachments(org_id,owner_id,filename,path) VALUES($1,$2,'acme-plan.txt',$3)`, acme, user1ID, filepath.Join(attachDir, "acme-plan.txt"))
	_, _ = db.ExecContext(ctx, `INSERT INTO attachments(org_id,owner_id,filename,path) VALUES($1,$2,'globex-plan.txt',$3)`, globex, user2ID, filepath.Join(attachDir, "globex-plan.txt"))
	_, _ = db.ExecContext(ctx, `INSERT INTO billing(org_id,seats_limit,seats_used,balance_cents) VALUES($1,3,0,10000),($2,3,0,10000)`, acme, globex)
	_, _ = db.ExecContext(ctx, `INSERT INTO invites(org_id,email) VALUES($1,'seed-invite@bench.local')`, acme)
	_, _ = db.ExecContext(ctx, `INSERT INTO reports(org_id,name,template) VALUES($1,'published','Hello {.User}')`, acme)
	_ = adminID
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func requireVerify(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Verify-Token") != verifyToken {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "bad verify token"})
		return false
	}
	return true
}

func verifyHealth(w http.ResponseWriter, r *http.Request) {
	if err := db.PingContext(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "bad", "db": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "db": "ok", "app": "golang"})
}

func verifyUser(w http.ResponseWriter, r *http.Request) {
	if !requireVerify(w, r) {
		return
	}
	u := findUserByEmail(r.Context(), r.URL.Query().Get("email"))
	if u.ID == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"exists": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exists": true, "id": u.ID, "role": u.Role, "isAdmin": u.IsAdmin, "verified": u.Verified, "orgSlug": u.OrgSlug})
}

func verifyPost(w http.ResponseWriter, r *http.Request) {
	if !requireVerify(w, r) {
		return
	}
	var p Post
	var authorEmail, orgSlug string
	_ = db.QueryRowContext(r.Context(), `SELECT p.id,p.slug,p.title,p.body,p.status,p.org_id,u.email,o.slug FROM posts p JOIN users u ON u.id=p.author_id JOIN organizations o ON o.id=p.org_id WHERE p.slug=$1`, r.URL.Query().Get("slug")).Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &p.Status, &p.OrgID, &authorEmail, &orgSlug)
	if p.ID == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"exists": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"exists": true, "id": p.ID, "slug": p.Slug, "status": p.Status, "authorEmail": authorEmail, "orgSlug": orgSlug, "body": p.Body})
}

func verifyResetAcme(w http.ResponseWriter, r *http.Request) {
	if !requireVerify(w, r) {
		return
	}
	var acme int
	_ = db.QueryRowContext(r.Context(), `SELECT id FROM organizations WHERE slug='acme'`).Scan(&acme)
	_, _ = db.ExecContext(r.Context(), `UPDATE users SET role='user', is_admin=false WHERE email='user1@bench.local'`)
	_, _ = db.ExecContext(r.Context(), `DELETE FROM invites WHERE org_id=$1`, acme)
	_, _ = db.ExecContext(r.Context(), `UPDATE billing SET seats_limit=1, seats_used=0, balance_cents=10000 WHERE org_id=$1`, acme)
	_, _ = db.ExecContext(r.Context(), `DELETE FROM comments WHERE body LIKE '%GO-XSS-%'`)
	attemptMu.Lock()
	attempts = map[string]int{}
	attemptMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func login(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	_ = json.NewDecoder(r.Body).Decode(&data)
	email, password := data["email"], data["password"]
	user := findUserByEmail(r.Context(), email)
	if user.ID == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		time.Sleep(50 * time.Millisecond)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad password"})
		return
	}
	incrementMetric(email)
	http.SetCookie(w, &http.Cookie{Name: "session", Value: makeSession(user), Path: "/", HttpOnly: false, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": user.ID, "role": user.Role})
}

func token(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	_ = json.NewDecoder(r.Body).Decode(&data)
	user := findUserByEmail(r.Context(), data["email"])
	if user.ID == 0 || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(data["password"])) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad login"})
		return
	}
	payload := map[string]any{"sub": user.ID, "role": user.Role, "email": user.Email, "exp": time.Now().Add(time.Hour).Unix()}
	writeJSON(w, http.StatusOK, map[string]any{"token": signJWT(payload)})
}

func resetPassword(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	_ = json.NewDecoder(r.Body).Decode(&data)
	email := data["email"]
	user := findUserByEmail(r.Context(), email)
	if user.ID == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	tok := newResetToken()
	_, _ = db.ExecContext(r.Context(), `UPDATE users SET reset_token=$1 WHERE id=$2`, tok, user.ID)
	writeJSON(w, http.StatusOK, map[string]any{"resetLink": "http://localhost:3000/reset?token=" + tok})
}

func newResetToken() string {
	mathrand.Seed(424242)
	alphabet := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	out := make([]rune, 24)
	for i := range out {
		out[i] = alphabet[mathrand.Intn(len(alphabet))]
	}
	return string(out)
}

func findUserByEmail(ctx context.Context, email string) User {
	var u User
	_ = db.QueryRowContext(ctx, `SELECT u.id,u.email,u.password_hash,u.role,u.is_admin,u.verified,u.org_id,o.slug FROM users u JOIN organizations o ON o.id=u.org_id WHERE u.email=$1`, email).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.IsAdmin, &u.Verified, &u.OrgID, &u.OrgSlug)
	return u
}

func findUserByID(ctx context.Context, id int) User {
	var u User
	_ = db.QueryRowContext(ctx, `SELECT u.id,u.email,u.password_hash,u.role,u.is_admin,u.verified,u.org_id,o.slug FROM users u JOIN organizations o ON o.id=u.org_id WHERE u.id=$1`, id).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.IsAdmin, &u.Verified, &u.OrgID, &u.OrgSlug)
	return u
}

func currentUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		payload, err := verifyJWT(strings.TrimSpace(auth[7:]))
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "bad token"})
			return User{}, false
		}
		id := intFromAny(payload["sub"])
		user := findUserByID(r.Context(), id)
		if user.ID != 0 {
			return user, true
		}
	}
	c, err := r.Cookie("session")
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login required"})
		return User{}, false
	}
	id, err := verifySession(c.Value)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login required"})
		return User{}, false
	}
	user := findUserByID(r.Context(), id)
	if user.ID == 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login required"})
		return User{}, false
	}
	return user, true
}

func makeSession(u User) string {
	payload := fmt.Sprintf("%d:%s:%s:%t:%d", u.ID, u.Email, u.Role, u.IsAdmin, u.OrgID)
	b := b64url([]byte(payload))
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
	id, _ := strconv.Atoi(strings.Split(string(raw), ":")[0])
	return id, nil
}

func signJWT(payload map[string]any) string {
	header := map[string]any{"alg": "HS256", "typ": "JWT"}
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	hb, pb := b64url(h), b64url(p)
	sig := b64url(hmacSHA256(hb+"."+pb, jwtSecret))
	return hb + "." + pb + "." + sig
}

func verifyJWT(tok string) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("bad jwt")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, err
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, err
	}
	if header["alg"] == "none" {
		return payload, nil
	}
	expected := hmacSHA256(parts[0]+"."+parts[1], jwtSecret)
	if hmac.Equal([]byte(b64url(expected)), []byte(parts[2])) {
		return payload, nil
	}
	return nil, errors.New("bad signature")
}

func hmacSHA256(data string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func b64url(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func intFromAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		i, _ := strconv.Atoi(t)
		return i
	default:
		return 0
	}
}

func searchPosts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	sql := fmt.Sprintf("SELECT p.id,p.slug,p.title,p.body,p.status,o.slug FROM posts p JOIN organizations o ON o.id=p.org_id WHERE p.status='published' AND (p.title ILIKE '%%%s%%' OR p.body ILIKE '%%%s%%')", q, q)
	rows, err := db.QueryContext(r.Context(), sql)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var slug, title, body, status, org string
		_ = rows.Scan(&id, &slug, &title, &body, &status, &org)
		out = append(out, map[string]any{"id": id, "slug": slug, "title": title, "body": body, "status": status, "orgSlug": org})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func listPosts(w http.ResponseWriter, r *http.Request) {
	q := "%" + r.URL.Query().Get("q") + "%"
	rows, err := db.QueryContext(r.Context(), `SELECT id,slug,title FROM posts WHERE status='published' AND title ILIKE $1`, q)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var slug, title string
		_ = rows.Scan(&id, &slug, &title)
		out = append(out, map[string]any{"id": id, "slug": slug, "title": title})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func getPost(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(w, r)
	if !ok {
		return
	}
	_ = user
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	var post Post
	var orgSlug string
	_ = db.QueryRowContext(r.Context(), `SELECT p.id,p.slug,p.title,p.body,p.status,p.org_id,o.slug FROM posts p JOIN organizations o ON o.id=p.org_id WHERE p.id=$1`, id).Scan(&post.ID, &post.Slug, &post.Title, &post.Body, &post.Status, &post.OrgID, &orgSlug)
	if post.ID == 0 {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": post.ID, "slug": post.Slug, "title": post.Title, "body": post.Body, "status": post.Status, "orgSlug": orgSlug})
}

func updateMe(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(w, r)
	if !ok {
		return
	}
	var data map[string]any
	_ = json.NewDecoder(r.Body).Decode(&data)
	if v, ok := data["displayName"].(string); ok {
		_, _ = db.ExecContext(r.Context(), `UPDATE users SET display_name=$1 WHERE id=$2`, v, user.ID)
	}
	if v, ok := data["role"].(string); ok {
		_, _ = db.ExecContext(r.Context(), `UPDATE users SET role=$1 WHERE id=$2`, v, user.ID)
		user.Role = v
	}
	if v, ok := data["isAdmin"].(bool); ok {
		_, _ = db.ExecContext(r.Context(), `UPDATE users SET is_admin=$1 WHERE id=$2`, v, user.ID)
		user.IsAdmin = v
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": user.ID, "email": user.Email, "role": user.Role, "isAdmin": user.IsAdmin})
}

func adminUsers(w http.ResponseWriter, r *http.Request) {
	_, ok := currentUser(w, r)
	if !ok {
		return
	}
	rows, _ := db.QueryContext(r.Context(), `SELECT u.id,u.email,u.role,o.slug FROM users u JOIN organizations o ON o.id=u.org_id ORDER BY u.id`)
	defer rows.Close()
	users := []map[string]any{}
	for rows.Next() {
		var id int
		var email, role, org string
		_ = rows.Scan(&id, &email, &role, &org)
		users = append(users, map[string]any{"id": id, "email": email, "role": role, "org": org})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func adminSummary(w http.ResponseWriter, r *http.Request) {
	payload, err := verifyJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil || payload["role"] != "admin" {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
		return
	}
	var marker string
	_ = db.QueryRowContext(r.Context(), `SELECT body FROM posts WHERE slug='globex-internal'`).Scan(&marker)
	writeJSON(w, http.StatusOK, map[string]any{"admin": true, "marker": marker})
}

func renderReport(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	_ = json.NewDecoder(r.Body).Decode(&data)
	t := ttmpl.Must(ttmpl.New("report").Parse(data["template"]))
	var buf bytes.Buffer
	_ = t.Execute(&buf, map[string]string{"User": data["user"], "Secret": "GO-REPORT-SECRET"})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func renderDashboard(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "guest"
	}
	t := htmpl.Must(htmpl.New("dash").Parse("<p>Dashboard for {.}</p>"))
	_ = t.Execute(w, name)
}

func exportReport(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	_ = json.NewDecoder(r.Body).Decode(&data)
	cmd := exec.Command("sh", "-c", "echo exporting "+data["name"])
	out, err := cmd.CombinedOutput()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write(out)
}

func createReport(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	_ = json.NewDecoder(r.Body).Decode(&data)
	org := data["org"]
	if org == "" {
		org = "acme"
	}
	var orgID int
	_ = db.QueryRowContext(r.Context(), `SELECT id FROM organizations WHERE slug=$1`, org).Scan(&orgID)
	var id int
	_ = db.QueryRowContext(r.Context(), `INSERT INTO reports(org_id,name,template) VALUES($1,$2,'Hello {.User}') RETURNING id`, orgID, data["name"]).Scan(&id)
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "name": data["name"]})
}

func reportResults(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	var reportName string
	_ = db.QueryRowContext(r.Context(), `SELECT name FROM reports WHERE id=$1`, id).Scan(&reportName)
	sql := fmt.Sprintf("SELECT id,slug,body FROM posts WHERE status = '%s'", reportName)
	rows, err := db.QueryContext(r.Context(), sql)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int
		var slug, body string
		_ = rows.Scan(&id, &slug, &body)
		out = append(out, map[string]any{"id": id, "slug": slug, "body": body})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func fetchURL(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	resp, err := http.Get(raw)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func isPrivateURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" {
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

func gotoNext(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func addComment(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(w, r)
	if !ok {
		return
	}
	var data map[string]any
	_ = json.NewDecoder(r.Body).Decode(&data)
	postID := intFromAny(data["postId"])
	body, _ := data["body"].(string)
	var id int
	_ = db.QueryRowContext(r.Context(), `INSERT INTO comments(post_id,author_id,body) VALUES($1,$2,$3) RETURNING id`, postID, user.ID, body).Scan(&id)
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func postHTML(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(chi.URLParam(r, "id"))
	var post Post
	_ = db.QueryRowContext(r.Context(), `SELECT id,title FROM posts WHERE id=$1`, id).Scan(&post.ID, &post.Title)
	rows, _ := db.QueryContext(r.Context(), `SELECT body FROM comments WHERE post_id=$1`, id)
	defer rows.Close()
	comments := []string{}
	for rows.Next() {
		var c string
		_ = rows.Scan(&c)
		comments = append(comments, c)
	}
	body := "<h1>" + post.Title + "</h1>"
	for _, c := range comments {
		body += "<div class='comment'>" + c + "</div>"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(body))
}

func searchPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, "<h1>Search</h1><div id='q'>%s</div>", q)
}

func downloadAttachment(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(attachDir, r.URL.Query().Get("name"))
	http.ServeFile(w, r, path)
}

func downloadAvatarSafe(w http.ResponseWriter, r *http.Request) {
	name := filepath.Clean("/" + r.URL.Query().Get("name"))[1:]
	path := filepath.Join(avatarDir, name)
	if !strings.HasPrefix(path, avatarDir+string(os.PathSeparator)) && path != avatarDir {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "outside avatar dir"})
		return
	}
	http.ServeFile(w, r, path)
}

func importArchive(w http.ResponseWriter, r *http.Request) {
	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "file required"})
		return
	}
	defer file.Close()
	tmp, _ := os.CreateTemp("", "archive-*.zip")
	defer os.Remove(tmp.Name())
	_, _ = io.Copy(tmp, file)
	_ = tmp.Close()
	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad zip"})
		return
	}
	defer zr.Close()
	for _, f := range zr.File {
		target := filepath.Join(importDir, f.Name)
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(target), 0755)
		rc, err := f.Open()
		if err != nil {
			continue
		}
		out, err := os.Create(target)
		if err == nil {
			_, _ = io.Copy(out, rc)
			_ = out.Close()
		}
		_ = rc.Close()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func billingSeats(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(w, r)
	if !ok {
		return
	}
	if !checkCSRF(w, r) {
		return
	}
	var data map[string]any
	_ = json.NewDecoder(r.Body).Decode(&data)
	qty := intFromAny(data["quantity"])
	_, err := db.ExecContext(r.Context(), `UPDATE billing SET seats_limit=seats_limit+$1, balance_cents=balance_cents-($1*1000) WHERE org_id=$2`, qty, user.OrgID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	billingStatus(w, r)
}

func checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	return true
}

func billingStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(w, r)
	if !ok {
		return
	}
	var limit, used, balance, invites int
	_ = db.QueryRowContext(r.Context(), `SELECT seats_limit,seats_used,balance_cents FROM billing WHERE org_id=$1`, user.OrgID).Scan(&limit, &used, &balance)
	_ = db.QueryRowContext(r.Context(), `SELECT count(*) FROM invites WHERE org_id=$1`, user.OrgID).Scan(&invites)
	writeJSON(w, http.StatusOK, map[string]any{"seatsLimit": limit, "seatsUsed": used, "balanceCents": balance, "inviteCount": invites})
}

func invites(w http.ResponseWriter, r *http.Request) {
	user, ok := currentUser(w, r)
	if !ok {
		return
	}
	var data map[string]any
	_ = json.NewDecoder(r.Body).Decode(&data)
	var limit, used int
	_ = db.QueryRowContext(r.Context(), `SELECT seats_limit,seats_used FROM billing WHERE org_id=$1`, user.OrgID).Scan(&limit, &used)
	if used >= limit {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "seat limit"})
		return
	}
	time.Sleep(200 * time.Millisecond)
	email := fmt.Sprintf("invite-%d@bench.local", time.Now().UnixNano())
	if v, ok := data["email"].(string); ok && v != "" {
		email = v
	}
	_, _ = db.ExecContext(r.Context(), `INSERT INTO invites(org_id,email) VALUES($1,$2)`, user.OrgID, email)
	_, _ = db.ExecContext(r.Context(), `UPDATE billing SET seats_used=$1 WHERE org_id=$2`, used+1, user.OrgID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func metrics(w http.ResponseWriter, r *http.Request) {
	loginMu.Lock()
	defer loginMu.Unlock()
	var b strings.Builder
	b.WriteString("# HELP bench_login_total demo login counter\n# TYPE bench_login_total counter\n")
	for email, count := range loginMetrics {
		_, _ = fmt.Fprintf(&b, "bench_login_total{email=%q} %d\n", email, count)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(b.String()))
}

func incrementMetric(email string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	loginMetrics[email]++
}

func tooManyAttempts(email string) bool {
	attemptMu.Lock()
	defer attemptMu.Unlock()
	return attempts[email] >= 5
}

func recordBadAttempt(email string) {
	attemptMu.Lock()
	defer attemptMu.Unlock()
	attempts[email]++
}

func clearAttempts(email string) {
	attemptMu.Lock()
	defer attemptMu.Unlock()
	delete(attempts, email)
}
