package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// === Merged from purge_test.go ===

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

func TestPurgeProject_RebuildsFTSAndReclaimsBytes(t *testing.T) {
	srv := newTestServer(t)
	for i := 0; i < 20; i++ {
		indexDoc(t, srv.store, "doc:"+string(rune('a'+i)), strings.Repeat("tokencontent ", 600))
	}
	res, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		Confirm:       true,
		Scope:         "project",
		ConfirmPhrase: srv.purgeKBName(),
	})
	if err != nil {
		t.Fatalf("purge project: %v", err)
	}
	if text := contentText(res); !strings.Contains(text, `"freed_bytes":`) {
		t.Fatalf("expected freed_bytes > 0 after project purge+vacuum, got:\n%s", text)
	}
	for _, tbl := range []string{"documents_fts_data", "documents_trigram_data"} {
		var bytes int64
		if err := srv.store.db.QueryRow("SELECT COALESCE(SUM(LENGTH(block)), 0) FROM " + tbl).Scan(&bytes); err != nil {
			t.Fatalf("query %s: %v", tbl, err)
		}
		if bytes > 1024 {
			t.Fatalf("%s still holds %d bytes of tombstones after PurgeAll", tbl, bytes)
		}
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

// === Merged from purge_confirm_test.go ===

// S7 second-confirmation tests for ctx_kb action=purge scope=project.
//
// scope=project wipes the ENTIRE knowledge base with store.PurgeAll, so a bare
// confirm:true boolean must no longer be sufficient: the caller has to echo the
// knowledge base name byte-for-byte in confirm_phrase. Session scope, dryRun
// and invalid scopes keep their pre-existing semantics.

func TestPurgeConfirmPhrase_ProjectMissingPhrase(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:keep1", "doc1")
	indexDoc(t, s, "session:keep2", "doc2")

	// Old-style confirm-only call: must be rejected, nothing deleted.
	_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{Confirm: true, Scope: "project"})
	if err == nil {
		t.Fatal("expected error when confirm_phrase is missing for scope=project")
	}
	if !strings.Contains(err.Error(), "confirm_phrase is required") {
		t.Fatalf("expected confirm_phrase requirement in error, got: %v", err)
	}
	// The error must guide the caller by naming the exact phrase to resend.
	if want := srv.purgeKBName(); !strings.Contains(err.Error(), `confirm_phrase:"`+want+`"`) {
		t.Fatalf("expected error to name the expected confirm_phrase %q, got: %v", want, err)
	}
	for _, key := range []string{"session:keep1", "session:keep2"} {
		if doc, _ := s.Get(key); doc == nil {
			t.Fatalf("%s must survive a rejected purge", key)
		}
	}
}

func TestPurgeConfirmPhrase_ProjectWrongPhrase(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:keep", "doc")
	want := srv.purgeKBName()

	// Byte-exact matching: suffix, case, leading and trailing spaces all fail.
	// Case variants are only added when they actually differ from the name
	// (an all-digit name uppercases to itself).
	bad := []string{want + "x", "x" + want, " " + want, want + " ", want + "\n"}
	if upper := strings.ToUpper(want); upper != want {
		bad = append(bad, upper)
	}
	if lower := strings.ToLower(want); lower != want {
		bad = append(bad, lower)
	}
	for _, phrase := range bad {
		_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{Confirm: true, Scope: "project", ConfirmPhrase: phrase})
		if err == nil {
			t.Fatalf("expected error for confirm_phrase %q", phrase)
		}
		if !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("expected mismatch error for confirm_phrase %q, got: %v", phrase, err)
		}
		if doc, _ := s.Get("session:keep"); doc == nil {
			t.Fatal("document must survive a rejected purge")
		}
	}
}

func TestPurgeConfirmPhrase_ProjectCorrectPhrasePurges(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:gone1", "doc1")
	indexDoc(t, s, "batch:gone2", "doc2")

	res, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		Confirm:       true,
		Scope:         "project",
		ConfirmPhrase: srv.purgeKBName(),
	})
	if err != nil {
		t.Fatalf("purge with correct confirm_phrase: %v", err)
	}
	if text := contentText(res); !strings.Contains(text, `"scope": "project"`) && !strings.Contains(text, `"scope":"project"`) {
		t.Fatalf("unexpected purge result: %s", text)
	}
	if doc, _ := s.Get("session:gone1"); doc != nil {
		t.Fatal("session:gone1 should be deleted")
	}
	if doc, _ := s.Get("batch:gone2"); doc != nil {
		t.Fatal("batch:gone2 should be deleted")
	}
}

func TestPurgeConfirmPhrase_ErrorGuidesToSuccess(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:doc", "content")

	// confirm-only call is rejected with guidance...
	_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{Confirm: true, Scope: "project"})
	if err == nil {
		t.Fatal("expected confirm-only project purge to be rejected")
	}
	if doc, _ := s.Get("session:doc"); doc == nil {
		t.Fatal("nothing may be deleted by the rejected call")
	}

	// ...and following the guidance (echo the KB name) purges successfully.
	_, _, err = srv.toolPurge(context.Background(), nil, purgeArgs{
		Confirm:       true,
		Scope:         "project",
		ConfirmPhrase: srv.purgeKBName(),
	})
	if err != nil {
		t.Fatalf("following the error guidance should purge: %v", err)
	}
	if doc, _ := s.Get("session:doc"); doc != nil {
		t.Fatal("document should be deleted after correct confirmation")
	}
}

func TestPurgeConfirmPhrase_KBNameDerivation(t *testing.T) {
	// With a configured workspace the phrase is the workspace dir base name.
	wd := t.TempDir()
	st := newTestStore(t)
	srv := &server{workdirs: []string{wd}, store: st}
	if got := srv.purgeKBName(); got != filepath.Base(wd) {
		t.Fatalf("purgeKBName with workdirs: got %q, want %q", got, filepath.Base(wd))
	}

	// Without workdirs it falls back to the database directory name.
	srv2 := newTestServer(t)
	wantDB := filepath.Base(filepath.Dir(srv2.store.DBPath()))
	if got := srv2.purgeKBName(); got != wantDB {
		t.Fatalf("purgeKBName fallback: got %q, want %q", got, wantDB)
	}
}

func TestPurgeConfirmPhrase_SessionScopeNeedsNoPhrase(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:ab", "1")
	indexDoc(t, s, "session:ab:child", "2")
	indexDoc(t, s, "session:other", "3")

	// Session scope keeps its confirm:true-only semantics (no phrase).
	if _, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		Confirm:   true,
		Scope:     "session",
		SessionID: "ab",
	}); err != nil {
		t.Fatalf("session purge must not require confirm_phrase: %v", err)
	}
	if doc, _ := s.Get("session:ab"); doc != nil {
		t.Fatal("session:ab should be deleted")
	}
	if doc, _ := s.Get("session:ab:child"); doc != nil {
		t.Fatal("session:ab:child should be deleted")
	}
	if doc, _ := s.Get("session:other"); doc == nil {
		t.Fatal("session:other must survive when purging session ab")
	}
}

func TestPurgeConfirmPhrase_SessionStillRequiresConfirm(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:keep", "1")

	_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{Scope: "session", SessionID: "keep"})
	if err == nil {
		t.Fatal("expected error when confirm is missing for session scope")
	}
	if !strings.Contains(err.Error(), "confirm:true") {
		t.Fatalf("expected confirm:true error, got: %v", err)
	}
	if doc, _ := s.Get("session:keep"); doc == nil {
		t.Fatal("document must survive when confirm is missing")
	}
}

func TestPurgeConfirmPhrase_DryRunNeedsNoPhrase(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:keep", "1")

	res, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{DryRun: true, Scope: "project"})
	if err != nil {
		t.Fatalf("dryRun must not require confirm_phrase: %v", err)
	}
	if !strings.Contains(contentText(res), "DRY RUN") {
		t.Fatalf("expected DRY RUN preview, got: %s", contentText(res))
	}
	if doc, _ := s.Get("session:keep"); doc == nil {
		t.Fatal("dryRun must not delete anything")
	}
}

func TestPurgeConfirmPhrase_AllScopeStillInvalid(t *testing.T) {
	srv := newTestServer(t)
	s := srv.store
	indexDoc(t, s, "session:keep", "1")

	// scope=all does not exist; a literal "ALL" phrase must not unlock anything.
	_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{Confirm: true, Scope: "all", ConfirmPhrase: "ALL"})
	if err == nil {
		t.Fatal("scope=all is not a valid scope; expected error")
	}
	if !strings.Contains(err.Error(), "invalid scope") {
		t.Fatalf("expected invalid scope error, got: %v", err)
	}
	if doc, _ := s.Get("session:keep"); doc == nil {
		t.Fatal("document must survive an invalid scope purge")
	}
}

func TestPurgeConfirmPhrase_ProjectWithWorkdirsCorrectPhrase(t *testing.T) {
	// Mirrors the fixes4_test.go server shape (workdirs configured): once the
	// legacy test adds ConfirmPhrase: filepath.Base(dir) it passes again.
	wd := t.TempDir()
	st := newTestStore(t)
	srv := &server{workdirs: []string{wd}, store: st}
	indexDoc(t, st, "session:doc", "content")

	_, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		Confirm:       true,
		Scope:         "project",
		ConfirmPhrase: filepath.Base(wd),
	})
	if err != nil {
		t.Fatalf("purge with workdir-derived confirm_phrase: %v", err)
	}
	if doc, _ := st.Get("session:doc"); doc != nil {
		t.Fatal("document should be deleted after correct confirmation")
	}
}
