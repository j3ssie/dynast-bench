package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Share links: a member hands a post to someone outside the workspace.
//
//   POST   /api/posts/:id/share        mint a link, read-only or editable
//   GET    /api/share/:token           what the link opens (preview)
//   POST   /api/share/:token/redeem    accept it - become a collaborator
//   GET    /api/shared/posts/:id       read a post shared with you
//   PUT    /api/shared/posts/:id       edit it, when your link allowed that
//   DELETE /api/share/:token           revoke (its creator)
// ---------------------------------------------------------------------------

type Share struct {
	ID         int
	PostID     int
	CreatedBy  int
	Token      string
	Permission string
}

func findShare(c *gin.Context) (Share, bool) {
	var s Share
	_ = db.QueryRowContext(c.Request.Context(), `SELECT id,post_id,created_by,token,permission FROM shares WHERE token=$1`, c.Param("token")).Scan(&s.ID, &s.PostID, &s.CreatedBy, &s.Token, &s.Permission)
	return s, s.ID != 0
}

func createShare(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	id, _ := strconv.Atoi(c.Param("id"))
	var orgID, authorID int
	_ = db.QueryRowContext(c.Request.Context(), `SELECT org_id,author_id FROM posts WHERE id=$1`, id).Scan(&orgID, &authorID)
	if orgID == 0 || orgID != user.OrgID {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var in struct {
		Permission string `json:"permission"`
	}
	_ = c.ShouldBindJSON(&in)
	if in.Permission == "" {
		in.Permission = "view"
	}
	if in.Permission != "view" && in.Permission != "edit" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "permission is view or edit"})
		return
	}
	// only someone who may edit the post can hand out an editable link
	if in.Permission == "edit" && authorID != user.ID && user.Role != "editor" && user.Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot share edit access to a post you cannot edit"})
		return
	}
	tok := b64url(randomBytes(12))
	if _, err := db.ExecContext(c.Request.Context(), `INSERT INTO shares(post_id,created_by,token,permission) VALUES($1,$2,$3,$4)`, id, user.ID, tok, in.Permission); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not share"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok, "permission": in.Permission, "link": "/api/share/" + tok})
}

// NM-SHARE-001: the preview reads the link and reports what it grants - the
// stored permission, nothing from the request.
func sharePreview(c *gin.Context) {
	if _, ok := currentUser(c); !ok {
		return
	}
	s, ok := findShare(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such link"})
		return
	}
	var title, org string
	_ = db.QueryRowContext(c.Request.Context(), `SELECT p.title,o.name FROM posts p JOIN organizations o ON o.id=p.org_id WHERE p.id=$1`, s.PostID).Scan(&title, &org)
	c.JSON(http.StatusOK, gin.H{"post": s.PostID, "title": title, "org": org, "permission": s.Permission})
}

func redeemShare(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	s, found := findShare(c)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such link"})
		return
	}
	// The client may ask to open a link read-only ("join as viewer").
	var in struct {
		Permission string `json:"permission"`
	}
	_ = c.ShouldBindJSON(&in)
	perm := s.Permission
	// VULN SHARE-ESCALATE-001 (CWE-915/CWE-639): the requested permission is taken
	// as given instead of only ever narrowing the link's own. A read-only link,
	// redeemed with {"permission":"edit"}, makes the holder an editor of a post
	// in a workspace they do not belong to.
	if in.Permission != "" {
		perm = in.Permission
	}
	_, err := db.ExecContext(c.Request.Context(), `INSERT INTO collaborators(share_id,post_id,user_id,permission) VALUES($1,$2,$3,$4)
		ON CONFLICT (post_id,user_id) DO UPDATE SET share_id=EXCLUDED.share_id, permission=EXCLUDED.permission`, s.ID, s.PostID, user.ID, perm)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not redeem"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"post": s.PostID, "permission": perm})
}

// collaboration is the caller's grant on a shared post, "" when there is none.
func collaboration(c *gin.Context, user User, postID int) string {
	var perm string
	_ = db.QueryRowContext(c.Request.Context(), `SELECT permission FROM collaborators WHERE post_id=$1 AND user_id=$2`, postID, user.ID).Scan(&perm)
	return perm
}

func readShared(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	id, _ := strconv.Atoi(c.Param("id"))
	if collaboration(c, user, id) == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not shared with you"})
		return
	}
	var p Post
	_ = db.QueryRowContext(c.Request.Context(), `SELECT id,slug,title,body,status FROM posts WHERE id=$1`, id).Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &p.Status)
	c.JSON(http.StatusOK, p.json())
}

func editShared(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	id, _ := strconv.Atoi(c.Param("id"))
	if collaboration(c, user, id) != "edit" {
		c.JSON(http.StatusForbidden, gin.H{"error": "read-only"})
		return
	}
	var in struct {
		Title *string `json:"title"`
		Body  *string `json:"body"`
	}
	_ = c.ShouldBindJSON(&in)
	if in.Title != nil {
		_, _ = db.ExecContext(c.Request.Context(), `UPDATE posts SET title=$1 WHERE id=$2`, *in.Title, id)
	}
	if in.Body != nil {
		_, _ = db.ExecContext(c.Request.Context(), `UPDATE posts SET body=$1 WHERE id=$2`, *in.Body, id)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": id})
}

func revokeShare(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	res, err := db.ExecContext(c.Request.Context(), `DELETE FROM shares WHERE token=$1 AND created_by=$2`, c.Param("token"), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not revoke"})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such link of yours"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
