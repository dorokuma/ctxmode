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

	indexDoc(t, s, "session:x-a", "1")
	indexDoc(t, s, "session:x-b", "2")
	indexDoc(t, s, "session:x-c", "3")
	indexDoc(t, s, "session:y", "4")

	// DryRun to get preview count.
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

	// The prefix "session:x" should match 3 docs (session:x-a, session:x-b, session:x-c).
	n, err := s.PurgeByPrefix("session:x")
	if err != nil {
		t.Fatalf("PurgeByPrefix: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 deleted, got %d", n)
	}

	// session:y should survive.
	if doc, _ := s.Get("session:y"); doc == nil {
		t.Fatal("session:y should survive")
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
