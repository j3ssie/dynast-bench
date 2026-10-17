package main

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Workspace routes: /api/orgs/:org/...
//
// Membership is checked once, by the group's middleware, instead of in every
// handler. That only protects the routes the middleware actually wraps.
// ---------------------------------------------------------------------------

type Org struct {
	ID   int
	Name string
	Slug string
}

func findOrgBySlug(ctx context.Context, slug string) (Org, bool) {
	var o Org
	_ = db.QueryRowContext(ctx, `SELECT id,name,slug FROM organizations WHERE slug=$1`, slug).Scan(&o.ID, &o.Name, &o.Slug)
	return o, o.ID != 0
}

// orgFor is the workspace named in the path - the one requireOrgMember already
// loaded when it ran, otherwise resolved from the slug.
func orgFor(c *gin.Context) (Org, bool) {
	if v, ok := c.Get("org"); ok {
		return v.(Org), true
	}
	return findOrgBySlug(c.Request.Context(), c.Param("org"))
}

// requireOrgMember lets a request through only when the caller belongs to the
// workspace in the path.
func requireOrgMember(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		c.Abort()
		return
	}
	org, found := findOrgBySlug(c.Request.Context(), c.Param("org"))
	if !found {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "no such workspace"})
		return
	}
	if org.ID != user.OrgID {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "not a member of this workspace"})
		return
	}
	c.Set("org", org)
	c.Next()
}

func registerWorkspaceRoutes(r *gin.Engine) {
	orgs := r.Group("/api/orgs/:org")
	// NEAR-MISS NM-GROUP-ORDER-001: registered above the middleware on purpose -
	// the public profile is meant to be readable by anyone, and it only ever
	// returns the name and the count of published posts.
	orgs.GET("/profile", orgProfile)
	orgs.Use(requireOrgMember)
	// FIXED GROUP-ORDER-001: registered after Use(), so the membership check runs.
	orgs.GET("/drafts", orgDrafts)
	orgs.GET("/members", orgMembers) // near-miss of TENANT-SRC-001
	orgs.GET("/posts", orgPosts)     // [TENANT-SRC-001]
}

func orgProfile(c *gin.Context) {
	org, ok := orgFor(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such workspace"})
		return
	}
	var published int
	_ = db.QueryRowContext(c.Request.Context(), `SELECT count(*) FROM posts WHERE org_id=$1 AND status='published'`, org.ID).Scan(&published)
	c.JSON(http.StatusOK, gin.H{"name": org.Name, "slug": org.Slug, "published": published})
}

// orgDrafts is the workspace's review queue: every post that is not live yet.
func orgDrafts(c *gin.Context) {
	org, ok := orgFor(c)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such workspace"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"org": org.Slug, "drafts": postsOf(c.Request.Context(), org.ID, "draft")})
}

// NM-TENANT-SRC-001: the member list takes the workspace from the path, which is
// exactly what the middleware checked - there is no second source to disagree.
func orgMembers(c *gin.Context) {
	org, _ := orgFor(c)
	rows, err := db.QueryContext(c.Request.Context(), `SELECT id,email,role FROM users WHERE org_id=$1 ORDER BY id`, org.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	out := []gin.H{}
	for rows.Next() {
		var id int
		var email, role string
		_ = rows.Scan(&id, &email, &role)
		out = append(out, gin.H{"id": id, "email": email, "role": role})
	}
	c.JSON(http.StatusOK, gin.H{"org": org.Slug, "members": out})
}

// postFilter is the query string of the workspace post listing. OrgID is there
// so the support console can reuse the same listing for any workspace.
type postFilter struct {
	Status string `form:"status"`
	OrgID  int    `form:"org_id"`
}

func orgPosts(c *gin.Context) {
	org, _ := orgFor(c)
	var f postFilter
	_ = c.ShouldBindQuery(&f)
	// FIXED TENANT-SRC-001: the listing runs against the workspace the middleware
	// authorized, whatever ?org_id= says.
	f.OrgID = org.ID
	c.JSON(http.StatusOK, gin.H{"org": org.Slug, "posts": postsOf(c.Request.Context(), f.OrgID, f.Status)})
}

func (p Post) json() gin.H {
	return gin.H{"id": p.ID, "slug": p.Slug, "title": p.Title, "body": p.Body, "status": p.Status}
}

// postsOf lists a workspace's posts, optionally in one status.
func postsOf(ctx context.Context, orgID int, status string) []gin.H {
	rows, err := db.QueryContext(ctx, `SELECT id,slug,title,body,status FROM posts WHERE org_id=$1 AND ($2='' OR status=$2) ORDER BY id`, orgID, status)
	out := []gin.H{}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var p Post
		_ = rows.Scan(&p.ID, &p.Slug, &p.Title, &p.Body, &p.Status)
		out = append(out, p.json())
	}
	return out
}
