package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// ---------------------------------------------------------------------------
// Workspace exports: an async job that bundles every post of the caller's
// workspace, drafts included, into one JSON file.
//
//   POST   /api/exports                 start one (returns its id)
//   GET    /api/exports/:id             poll it
//   GET    /api/exports/:id/download    fetch the file once it is done
//   DELETE /api/exports/:id             discard it
// ---------------------------------------------------------------------------

type Export struct {
	ID          int
	OrgID       int
	RequesterID int
	Status      string
	Payload     string
}

func findExport(c *gin.Context) (Export, bool) {
	id, _ := strconv.Atoi(c.Param("id"))
	var e Export
	_ = db.QueryRowContext(c.Request.Context(), `SELECT id,org_id,requester_id,status,payload FROM exports WHERE id=$1`, id).Scan(&e.ID, &e.OrgID, &e.RequesterID, &e.Status, &e.Payload)
	return e, e.ID != 0
}

// buildExport renders a workspace's posts as the export file.
func buildExport(ctx context.Context, orgID int) string {
	b, _ := json.Marshal(gin.H{"org_id": orgID, "posts": postsOf(ctx, orgID, "")})
	return string(b)
}

func startExport(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	var id int
	if err := db.QueryRowContext(c.Request.Context(), `INSERT INTO exports(org_id,requester_id,status) VALUES($1,$2,'pending') RETURNING id`, user.OrgID, user.ID).Scan(&id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start export"})
		return
	}
	go func(id, orgID int) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		time.Sleep(300 * time.Millisecond) // a real export takes a while
		_, _ = db.ExecContext(ctx, `UPDATE exports SET status='done', payload=$1 WHERE id=$2`, buildExport(ctx, orgID), id)
	}(id, user.OrgID)
	c.JSON(http.StatusAccepted, gin.H{"id": id, "status": "pending"})
}

// NM-EXPORT-001: polling checks the job is yours in every state.
func exportStatus(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	e, found := findExport(c)
	if !found || e.RequesterID != user.ID {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such export"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": e.ID, "status": e.Status})
}

func downloadExport(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	e, found := findExport(c)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such export"})
		return
	}
	// FIXED EXPORT-STATE-001: ownership is checked before the job's state, so it
	// holds whether the export is running or done.
	if e.RequesterID != user.ID {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such export"})
		return
	}
	if e.Status != "done" {
		c.JSON(http.StatusConflict, gin.H{"error": "export still running", "status": e.Status})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=export-"+strconv.Itoa(e.ID)+".json")
	c.Data(http.StatusOK, "application/json", []byte(e.Payload))
}

func deleteExport(c *gin.Context) {
	user, ok := currentUser(c)
	if !ok {
		return
	}
	id, _ := strconv.Atoi(c.Param("id"))
	res, err := db.ExecContext(c.Request.Context(), `DELETE FROM exports WHERE id=$1 AND requester_id=$2`, id, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not delete"})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no such export"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
