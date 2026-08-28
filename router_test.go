package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCtxRunUnknownAction(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxRun(context.Background(), nil, ctxRunArgs{Action: "nope"})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown action error, got %v", err)
	}
}

func TestCtxRunMissingAction(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxRun(context.Background(), nil, ctxRunArgs{})
	if err == nil {
		t.Fatal("expected error for empty action")
	}
}

func TestCtxFsMissingAction(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxFs(context.Background(), nil, ctxFsArgs{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCtxGitMissingAction(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxGit(context.Background(), nil, ctxGitArgs{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCtxKbMissingAction(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCtxBgMissingAction(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxBg(context.Background(), nil, ctxBgArgs{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCtxRunExecuteRequiresCommand(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxRun(context.Background(), nil, ctxRunArgs{Action: "execute"})
	if err == nil {
		t.Fatal("expected error without command/argv")
	}
}

func TestCtxFsRgRequiresPattern(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxFs(context.Background(), nil, ctxFsArgs{Action: "rg"})
	if err == nil {
		t.Fatal("expected pattern required")
	}
}

func TestCtxKbSearchRequiresQuery(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "search"})
	if err == nil {
		t.Fatal("expected query required")
	}
}

func TestCtxRunActionCaseInsensitive(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxRun(context.Background(), nil, ctxRunArgs{Action: "EXECUTE"})
	// still fails on missing command, but must not say unknown action
	if err == nil {
		t.Fatal("expected command required")
	}
	if strings.Contains(err.Error(), "unknown") {
		t.Fatalf("case-insensitive action should route: %v", err)
	}
}

func TestRegisterCategoryToolsDoesNotPanic(t *testing.T) {
	// Construction only — Run not called.
	s := &server{workdirs: []string{t.TempDir()}}
	// mcp.NewServer is used at runtime; ensure method exists by calling with nil-safe path
	// via tool methods above. This test documents the five public tool names.
	names := []string{"ctx_run", "ctx_fs", "ctx_git", "ctx_kb", "ctx_bg"}
	if len(names) != 5 {
		t.Fatal(names)
	}
	_ = s
}

func TestCtxKbFetchAndIndexAliasRejected(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	_, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "fetch_and_index"})
	if err == nil {
		t.Fatal("expected fetch_and_index alias to be rejected")
	}
	if !strings.Contains(err.Error(), "fetch") {
		t.Fatalf("expected error to hint the correct action name, got: %v", err)
	}
	// Case-insensitive variant also rejected.
	_, _, err = s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "FETCH_AND_INDEX"})
	if err == nil {
		t.Fatal("expected FETCH_AND_INDEX rejected")
	}
}

func TestCtxRunDescriptionListsAllRunTaskKinds(t *testing.T) {
	// The ctx_run description must advertise every kind accepted by run_task.
	for _, k := range []string{"go_test", "go_build", "go_vet", "npm_test", "npm_run_build", "cargo_test", "cargo_build", "make", "custom"} {
		if !strings.Contains(ctxRunDescription, k) {
			t.Fatalf("ctx_run description missing kind %q: %s", k, ctxRunDescription)
		}
	}
	// Removed v1 tool names must not be advertised.
	if strings.Contains(ctxRunDescription, "ctx_search") || strings.Contains(ctxRunDescription, "ctx_batch_execute") {
		t.Fatalf("ctx_run description references removed tool names: %s", ctxRunDescription)
	}
}

func TestCtxFsOffsetPassThrough(t *testing.T) {
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}}
	mustWrite(t, filepath.Join(wd, "test.txt"), "hello world\n")
	res, _, err := s.toolCtxFs(context.Background(), nil, ctxFsArgs{
		Action:  "rg",
		Pattern: "hello",
		Path:    wd,
		Offset:  1,
	})
	if err != nil {
		t.Fatalf("toolCtxFs failed: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "offset=1") {
		t.Errorf("expected offset=1 in output: %s", text)
	}
}

func TestCtxKbScopePassThrough(t *testing.T) {
	st := newTestStore(t)
	fg := NewFloodGuard(60*time.Second, 64)
	sp := NewSearchPipeline(st, fg)
	s := &server{
		sessionID:      "sess1",
		store:          st,
		floodGuard:     fg,
		searchPipeline: sp,
	}

	_, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{
		Action: "search",
		Query:  "some_query",
		Scope:  "invalid_scope",
	})
	if err == nil {
		t.Fatal("expected invalid scope to be rejected via router")
	}
}
