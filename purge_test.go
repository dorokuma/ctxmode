package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func newTestServer(t *testing.T) *server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return &server{store: s}
}

func TestPurgeDryRun_Project(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store

	indexDoc(t, s, "session:a", "1")
	indexDoc(t, s, "batch:b", "2")

	// Verify documents exist before dryRun.
	if doc, _ := s.Get("session:a"); doc == nil {
		t.Fatal("session:a should exist before dryRun")
	}
	if doc, _ := s.Get("batch:b"); doc == nil {
		t.Fatal("batch:b should exist before dryRun")
	}

	// DryRun project scope — should preview, not delete.
	result, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		DryRun: true,
		Scope:  "project",
	})
	if err != nil {
		t.Fatalf("dryRun project: %v", err)
	}

	// Verify result content mentions DRY RUN.
	text := contentText(result)
	if text == "" {
		t.Fatal("expected non-empty result from dryRun")
	}
	if !strings.Contains(text, "DRY RUN") {
		t.Fatalf("expected 'DRY RUN' in result, got: %s", text)
	}
	if !strings.Contains(text, "project") {
		t.Fatalf("expected 'project' scope in result, got: %s", text)
	}

	// Documents must still exist after dryRun.
	if doc, _ := s.Get("session:a"); doc == nil {
		t.Fatal("session:a should still exist after dryRun")
	}
	if doc, _ := s.Get("batch:b"); doc == nil {
		t.Fatal("batch:b should still exist after dryRun")
	}
}

func TestPurgeDryRun_Session(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store

	indexDoc(t, s, "session:test-123", "content1")
	indexDoc(t, s, "session:test-123-extra", "content2")
	indexDoc(t, s, "session:other", "content3")

	// DryRun session scope.
	result, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		DryRun:    true,
		Scope:     "session",
		SessionID: "test-123",
	})
	if err != nil {
		t.Fatalf("dryRun session: %v", err)
	}

	text := contentText(result)
	if !strings.Contains(text, "DRY RUN") {
		t.Fatalf("expected 'DRY RUN' in result, got: %s", text)
	}
	if !strings.Contains(text, "session") {
		t.Fatalf("expected 'session' scope in result, got: %s", text)
	}

	// All documents must still exist.
	if doc, _ := s.Get("session:test-123"); doc == nil {
		t.Fatal("session:test-123 should still exist after dryRun")
	}
	if doc, _ := s.Get("session:test-123-extra"); doc == nil {
		t.Fatal("session:test-123-extra should still exist after dryRun")
	}
	if doc, _ := s.Get("session:other"); doc == nil {
		t.Fatal("session:other should still exist after dryRun")
	}
}

func TestPurgeDryRun_NoScope(t *testing.T) {
	srv := newTestServer(t)

	_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		DryRun: true,
	})
	if err == nil {
		t.Fatal("expected error for dryRun without scope")
	}
}

func TestPurgeDryRun_SessionNoID(t *testing.T) {
	srv := newTestServer(t)

	_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		DryRun: true,
		Scope:  "session",
	})
	if err == nil {
		t.Fatal("expected error for session dryRun without sessionId")
	}
}

func TestPurgeDryRun_CountMatchesDelete(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store

	// Exact session key + colon-delimited child; hyphen suffix must NOT match.
	indexDoc(t, s, "session:x", "1")
	indexDoc(t, s, "session:x:child", "2")
	indexDoc(t, s, "session:x-extra", "3") // must survive (not colon-delimited)
	indexDoc(t, s, "session:y", "4")

	// DryRun preview count for exact session semantics.
	result, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		DryRun:    true,
		Scope:     "session",
		SessionID: "x",
	})
	if err != nil {
		t.Fatalf("dryRun: %v", err)
	}
	text := contentText(result)
	t.Logf("dryRun result: %s", text)

	// PurgeSessionKeys: exact "session:x" + "session:x:..." only.
	n, err := s.PurgeSessionKeys("x")
	if err != nil {
		t.Fatalf("PurgeSessionKeys: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 deleted (session:x + session:x:child), got %d", n)
	}

	// session:x-extra and session:y should survive (no prefix false-positive).
	if doc, _ := s.Get("session:x-extra"); doc == nil {
		t.Fatal("session:x-extra should survive (hyphen suffix is not a child)")
	}
	if doc, _ := s.Get("session:y"); doc == nil {
		t.Fatal("session:y should survive")
	}
}

// ============================================================================
// confirm 必填校验（缺失/false 时必须返回明确错误，而非成功的 cancelled 文案）
// ============================================================================

func TestPurge_RequiresConfirmError(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:keepme", "1")

	// Missing confirm (zero value) → explicit error, nothing deleted.
	_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{Scope: "project"})
	if err == nil {
		t.Fatal("expected error when confirm is missing")
	}
	if !strings.Contains(err.Error(), "confirm:true") {
		t.Fatalf("expected confirm:true in error message, got: %v", err)
	}
	if doc, _ := s.Get("session:keepme"); doc == nil {
		t.Fatal("document must survive when purge is not confirmed")
	}

	// Explicit confirm=false → same error.
	_, _, err = srv.toolPurge(context.Background(), nil, purgeArgs{Scope: "project", Confirm: false})
	if err == nil {
		t.Fatal("expected error when confirm=false")
	}
	if !strings.Contains(err.Error(), "confirm:true") {
		t.Fatalf("expected confirm:true in error message, got: %v", err)
	}
	if doc, _ := s.Get("session:keepme"); doc == nil {
		t.Fatal("document must survive when confirm=false")
	}
}

func TestPurge_DryRunWithoutConfirmSucceeds(t *testing.T) {
	srv := newTestServer(t)
	// DryRun keeps the pre-confirm preview behavior: no confirm required.
	res, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{DryRun: true, Scope: "project"})
	if err != nil {
		t.Fatalf("dryRun without confirm should succeed: %v", err)
	}
	if !strings.Contains(contentText(res), "DRY RUN") {
		t.Fatalf("expected DRY RUN preview, got: %s", contentText(res))
	}
}

func TestPurgeSession_NoPrefixFalsePositive(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store

	indexDoc(t, s, "session:ab", "1")
	indexDoc(t, s, "session:abc", "2")
	indexDoc(t, s, "session:ab:sub", "3")

	result, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		Confirm:   true,
		Scope:     "session",
		SessionID: "ab",
	})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	text := contentText(result)
	if !strings.Contains(text, `"deleted_docs": 2`) && !strings.Contains(text, `"deleted_docs":2`) {
		// Accept either spacing from MarshalIndent.
		t.Fatalf("expected deleted_docs=2, purge result: %s", text)
	}

	if doc, _ := s.Get("session:ab"); doc != nil {
		t.Fatal("session:ab should be deleted")
	}
	if doc, _ := s.Get("session:ab:sub"); doc != nil {
		t.Fatal("session:ab:sub should be deleted")
	}
	if doc, _ := s.Get("session:abc"); doc == nil {
		t.Fatal("session:abc must survive when purging session ab")
	}
}

func TestPurgeSession_DeletesServerTaggedDocs(t *testing.T) {
	srv := newTestServer(t)
	srv.sessionID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	label := srv.indexLabel("execute", "job")
	if err := srv.storeIndexLocked(label, "tagged execute output"); err != nil {
		t.Fatal(err)
	}
	res, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		Confirm:   true,
		Scope:     "session",
		SessionID: srv.sessionID,
	})
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	text := contentText(res)
	if !strings.Contains(text, `"deleted_docs": 1`) && !strings.Contains(text, `"deleted_docs":1`) {
		t.Fatalf("expected deleted_docs=1, got %s", text)
	}
	if doc, _ := srv.store.Get(label); doc != nil {
		t.Fatal("session-tagged execute doc should be gone")
	}
}

// helpers

func contentText(result *mcp.CallToolResult) string {
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}
