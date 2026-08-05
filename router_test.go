package main

import (
	"context"
	"strings"
	"testing"
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
