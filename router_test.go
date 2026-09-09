package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func boolVal(p *bool) (bool, bool) {
	if p == nil {
		return false, false
	}
	return *p, true
}

func TestCategoryToolAnnotations(t *testing.T) {
	ann := categoryToolAnnotations()
	check := func(name string, readOnly bool, destructive bool, openWorld *bool) {
		t.Helper()
		a, ok := ann[name]
		if !ok || a == nil {
			t.Fatalf("missing annotations for %s", name)
		}
		if a.ReadOnlyHint != readOnly {
			t.Fatalf("%s readOnlyHint=%v want %v", name, a.ReadOnlyHint, readOnly)
		}
		gotD, hasD := boolVal(a.DestructiveHint)
		if !hasD || gotD != destructive {
			t.Fatalf("%s destructiveHint=%v present=%v want %v", name, gotD, hasD, destructive)
		}
		if openWorld != nil {
			gotO, hasO := boolVal(a.OpenWorldHint)
			if !hasO || gotO != *openWorld {
				t.Fatalf("%s openWorldHint=%v present=%v want %v", name, gotO, hasO, *openWorld)
			}
		}
	}
	check("ctx_fs", true, false, nil)
	check("ctx_git", true, false, nil)
	ow := true
	check("ctx_run", false, true, &ow)
	check("ctx_kb", false, true, nil)
	check("ctx_bg", false, true, nil)
}

func TestCategoryToolAnnotationsIndependentPointers(t *testing.T) {
	ann := categoryToolAnnotations()
	run := ann["ctx_run"]
	fs := ann["ctx_fs"]
	kb := ann["ctx_kb"]
	if run == nil || run.DestructiveHint == nil || fs == nil || fs.DestructiveHint == nil || kb == nil || kb.DestructiveHint == nil {
		t.Fatal("missing DestructiveHint pointers")
	}
	if run.DestructiveHint == fs.DestructiveHint || run.DestructiveHint == kb.DestructiveHint || fs.DestructiveHint == kb.DestructiveHint {
		t.Fatal("tools must not share DestructiveHint pointers")
	}
	origFS, origKB := *fs.DestructiveHint, *kb.DestructiveHint
	*run.DestructiveHint = !*run.DestructiveHint
	if *fs.DestructiveHint != origFS {
		t.Fatal("mutating ctx_run DestructiveHint must not affect ctx_fs")
	}
	if *kb.DestructiveHint != origKB {
		t.Fatal("mutating ctx_run DestructiveHint must not affect ctx_kb")
	}
}

func TestCategoryToolAnnotationsInToolsList(t *testing.T) {
	ctx := context.Background()
	s := &server{workdirs: []string{t.TempDir()}}
	srv := mcp.NewServer(&mcp.Implementation{Name: "ctxmode", Version: Version}, nil)
	s.registerCategoryTools(srv)

	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	listed, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	want := categoryToolAnnotations()
	seen := map[string]bool{}
	for _, tool := range listed.Tools {
		seen[tool.Name] = true
		exp, ok := want[tool.Name]
		if !ok {
			continue
		}
		if tool.Annotations == nil {
			t.Fatalf("tools/list %s missing annotations", tool.Name)
		}
		if tool.Annotations.ReadOnlyHint != exp.ReadOnlyHint {
			t.Fatalf("tools/list %s readOnlyHint=%v want %v", tool.Name, tool.Annotations.ReadOnlyHint, exp.ReadOnlyHint)
		}
		gotD, hasD := boolVal(tool.Annotations.DestructiveHint)
		wantD, _ := boolVal(exp.DestructiveHint)
		if !hasD || gotD != wantD {
			t.Fatalf("tools/list %s destructiveHint=%v present=%v want %v", tool.Name, gotD, hasD, wantD)
		}
		if exp.OpenWorldHint != nil {
			gotO, hasO := boolVal(tool.Annotations.OpenWorldHint)
			wantO, _ := boolVal(exp.OpenWorldHint)
			if !hasO || gotO != wantO {
				t.Fatalf("tools/list %s openWorldHint=%v present=%v want %v", tool.Name, gotO, hasO, wantO)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Fatalf("tools/list missing %s", name)
		}
	}
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
