package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

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
