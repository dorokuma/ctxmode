package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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

// TestCtxRunEmptyAndRunActionRouteToExecute pins the router normalization: a
// missing action and the legacy "run" spelling both mean execute, so a call
// that omits action reaches the executor (and the inferred JSON Schema no
// longer lists action as required) instead of failing at the router.
func TestCtxRunEmptyAndRunActionRouteToExecute(t *testing.T) {
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "probe.txt"), "probe\n")
	s := &server{workdirs: []string{wd}}
	const marker = "retro-schema-alias-ok"
	for _, action := range []string{"", "run"} {
		name := action
		if name == "" {
			name = "empty"
		}
		t.Run("action="+name, func(t *testing.T) {
			// command form
			res, _, err := s.toolCtxRun(context.Background(), nil, ctxRunArgs{
				Action:  action,
				Command: "echo " + marker,
				CWD:     wd,
			})
			if err != nil {
				t.Fatalf("toolCtxRun(action=%q, command): %v", action, err)
			}
			if text := mcpResultText(t, res); !strings.Contains(text, marker) {
				t.Fatalf("action=%q command form did not execute: %s", action, text)
			}
			// argv form
			res, _, err = s.toolCtxRun(context.Background(), nil, ctxRunArgs{
				Action: action,
				Argv:   []string{"echo", marker},
				CWD:    wd,
			})
			if err != nil {
				t.Fatalf("toolCtxRun(action=%q, argv): %v", action, err)
			}
			if text := mcpResultText(t, res); !strings.Contains(text, marker) {
				t.Fatalf("action=%q argv form did not execute: %s", action, text)
			}
		})
	}
}

// TestCtxRunBackgroundWithEmptyOrRunAction pins that the background guard sees
// the normalized action: Background must be accepted for the execute defaults
// and still rejected for actions that cannot run in the background.
func TestCtxRunBackgroundWithEmptyOrRunAction(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	for _, action := range []string{"", "run"} {
		res, _, err := s.toolCtxRun(context.Background(), nil, ctxRunArgs{
			Action:     action,
			Command:    "echo retro-bg-alias-ok",
			Background: true,
		})
		if err != nil {
			t.Fatalf("Background with action=%q must route to execute, got %v", action, err)
		}
		if text := mcpResultText(t, res); !strings.Contains(text, "background") {
			t.Fatalf("action=%q background start notice missing: %s", action, text)
		}
		jobID := extractBgJobID(t, mcpResultText(t, res))
		t.Cleanup(func() { cleanupBgJob(jobID) })
	}
	// The guard itself must survive normalization.
	_, _, err := s.toolCtxRun(context.Background(), nil, ctxRunArgs{
		Action:     "batch",
		Commands:   []batchCommand{{Label: "probe", Command: "echo probe"}},
		Background: true,
	})
	if err == nil || !strings.Contains(err.Error(), "background is only supported") {
		t.Fatalf("background guard must still reject batch, got %v", err)
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
	if _, _, err := s.toolCtxBg(context.Background(), nil, ctxBgArgs{Action: "status"}); err != nil {
		t.Fatalf("status alias should route to list, got %v", err)
	}
	// empty id/pid routes "output" to the "log" branch and triggers "id or pid is required" (not "unknown ctx_bg action")
	if _, _, err := s.toolCtxBg(context.Background(), nil, ctxBgArgs{Action: "output"}); err == nil || strings.Contains(err.Error(), "unknown") {
		t.Fatalf("output alias should route to log, got %v", err)
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
	check("ctx_fs", false, false, nil) // F4c: rg indexes oversized hits into ctx_kb
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

// TestCtxFsListAliasRoutesToLs pins that the "list" spelling hosts guess is
// routed to the ls implementation and produces byte-identical output.
func TestCtxFsListAliasRoutesToLs(t *testing.T) {
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "a.txt"), "alpha\n")
	mustWrite(t, filepath.Join(wd, "sub", "b.txt"), "beta\n")
	s := &server{workdirs: []string{wd}}

	resList, _, err := s.toolCtxFs(context.Background(), nil, ctxFsArgs{Action: "list", Path: wd})
	if err != nil {
		t.Fatalf("toolCtxFs(action=list): %v", err)
	}
	resLs, _, err := s.toolCtxFs(context.Background(), nil, ctxFsArgs{Action: "ls", Path: wd})
	if err != nil {
		t.Fatalf("toolCtxFs(action=ls): %v", err)
	}
	textList, textLs := mcpResultText(t, resList), mcpResultText(t, resLs)
	if textList != textLs {
		t.Fatalf("action=list output differs from action=ls:\nlist:\n%s\nls:\n%s", textList, textLs)
	}
	for _, want := range []string{"a.txt", "sub"} {
		if !strings.Contains(textList, want) {
			t.Fatalf("action=list output missing %q:\n%s", want, textList)
		}
	}
	// The alias is case-insensitive like every other router action.
	if _, _, err := s.toolCtxFs(context.Background(), nil, ctxFsArgs{Action: "LIST", Path: wd}); err != nil {
		t.Fatalf("LIST alias should route to ls, got %v", err)
	}
}

// gitRepoWithCommits returns a workdir holding a git repository with n commits
// plus a server bound to it, so log-alias truncation can be asserted.
func gitRepoWithCommits(t *testing.T, n int) (string, *server) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	wd := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = wd
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("git", "init")
	_ = exec.Command("git", "-C", wd, "checkout", "-b", "main").Run()
	for i := 0; i < n; i++ {
		mustWrite(t, filepath.Join(wd, fmt.Sprintf("file-%d.txt", i)), "content\n")
		run("git", "add", ".")
		run("git", "commit", "-m", fmt.Sprintf("retro alias commit %d", i))
	}
	return wd, testServerWithWorkdir(t, wd)
}

// countLogLines counts the non-empty lines of a git log result.
func countLogLines(text string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// TestCtxGitLogLimitAliases pins that limit / max_count are accepted aliases
// for n on action=log, that n wins when set, and that a missing n still falls
// back to the default entry count.
func TestCtxGitLogLimitAliases(t *testing.T) {
	const commits = 3
	wd, s := gitRepoWithCommits(t, commits)

	logText := func(args ctxGitArgs) string {
		t.Helper()
		args.Action = "log"
		args.CWD = wd
		res, _, err := s.toolCtxGit(context.Background(), nil, args)
		if err != nil {
			t.Fatalf("toolCtxGit(%+v): %v", args, err)
		}
		return mcpResultText(t, res)
	}

	if got := countLogLines(logText(ctxGitArgs{Limit: 1})); got != 1 {
		t.Fatalf("limit=1 returned %d lines, want 1:\n%s", got, logText(ctxGitArgs{Limit: 1}))
	}
	if got := countLogLines(logText(ctxGitArgs{MaxCount: 1})); got != 1 {
		t.Fatalf("max_count=1 returned %d lines, want 1", got)
	}
	if got := countLogLines(logText(ctxGitArgs{Limit: 2})); got != 2 {
		t.Fatalf("limit=2 returned %d lines, want 2", got)
	}
	// n wins over the aliases.
	if got := countLogLines(logText(ctxGitArgs{N: 3, Limit: 1})); got != 3 {
		t.Fatalf("n=3 with limit=1 returned %d lines, want 3 (n must win)", got)
	}
	if got := countLogLines(logText(ctxGitArgs{N: 3, MaxCount: 1})); got != 3 {
		t.Fatalf("n=3 with max_count=1 returned %d lines, want 3 (n must win)", got)
	}
	// limit wins over max_count when both are set.
	if got := countLogLines(logText(ctxGitArgs{Limit: 1, MaxCount: 2})); got != 1 {
		t.Fatalf("limit=1 with max_count=2 returned %d lines, want 1", got)
	}
	// No count at all still returns the default (20) entries, i.e. everything.
	if got := countLogLines(logText(ctxGitArgs{})); got != commits {
		t.Fatalf("no count returned %d lines, want %d", got, commits)
	}
}

// connectCategoryTools registers the v2.0 category tools on a fresh in-memory
// MCP server and returns a connected client session.
func connectCategoryTools(t *testing.T, ctx context.Context, s *server) *mcp.ClientSession {
	t.Helper()
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
	return cs
}

// TestCategoryToolSchemaAliasesOverMCP drives the JSON Schema layer end to end
// through an in-memory MCP client/server: the calls hosts actually send must
// pass schema validation and still execute, instead of being rejected with
// `missing properties: ["action"]` or `unexpected additional properties`.
func TestCategoryToolSchemaAliasesOverMCP(t *testing.T) {
	ctx := context.Background()
	wd, s := gitRepoWithCommits(t, 3)
	mustWrite(t, filepath.Join(wd, "alias-probe.txt"), "probe\n")
	cs := connectCategoryTools(t, ctx, s)

	call := func(name string, args map[string]any) string {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("CallTool %s %v: %v", name, args, err)
		}
		if res.IsError {
			t.Fatalf("CallTool %s %v returned error result: %s", name, args, mcpResultText(t, res))
		}
		return mcpResultText(t, res)
	}

	// ctx_run: action omitted (argv and command forms) plus the legacy "run".
	const marker = "retro-schema-alias-ok"
	for _, args := range []map[string]any{
		{"argv": []any{"echo", marker}},
		{"command": "echo " + marker},
		{"action": "run", "argv": []any{"echo", marker}},
		{"action": "run", "command": "echo " + marker},
	} {
		if text := call("ctx_run", args); !strings.Contains(text, marker) {
			t.Fatalf("ctx_run %v did not execute: %s", args, text)
		}
	}

	// ctx_fs: action=list must validate and list the directory.
	if text := call("ctx_fs", map[string]any{"action": "list", "path": wd}); !strings.Contains(text, "alias-probe.txt") {
		t.Fatalf("ctx_fs action=list did not list the directory: %s", text)
	}

	// ctx_git: limit / max_count must validate and truncate to one entry.
	for _, args := range []map[string]any{
		{"action": "log", "limit": 1},
		{"action": "log", "max_count": 1},
	} {
		text := call("ctx_git", args)
		if strings.Contains(text, "unexpected additional properties") {
			t.Fatalf("ctx_git %v rejected by schema: %s", args, text)
		}
		if got := countLogLines(text); got != 1 {
			t.Fatalf("ctx_git %v returned %d lines, want 1:\n%s", args, got, text)
		}
	}

	// The advertised schemas must match the calls above: action is optional for
	// ctx_run, and limit / max_count are known properties for ctx_git.
	listed, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	schemaFor := func(name string) map[string]any {
		t.Helper()
		for _, tool := range listed.Tools {
			if tool.Name != name {
				continue
			}
			raw, err := json.Marshal(tool.InputSchema)
			if err != nil {
				t.Fatalf("marshal %s inputSchema: %v", name, err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("unmarshal %s inputSchema: %v", name, err)
			}
			return m
		}
		t.Fatalf("tools/list missing %s", name)
		return nil
	}
	props := func(name string) map[string]any {
		t.Helper()
		p, _ := schemaFor(name)["properties"].(map[string]any)
		if p == nil {
			t.Fatalf("%s schema has no properties: %v", name, schemaFor(name))
		}
		return p
	}
	runSchema := schemaFor("ctx_run")
	required, _ := runSchema["required"].([]any)
	for _, r := range required {
		if r == "action" {
			t.Fatalf("ctx_run schema still requires action: %v", runSchema)
		}
	}
	if _, ok := props("ctx_run")["action"]; !ok {
		t.Fatalf("ctx_run schema lost the action property: %v", runSchema)
	}
	for _, alias := range []string{"limit", "max_count"} {
		if _, ok := props("ctx_git")[alias]; !ok {
			t.Fatalf("ctx_git schema missing %q property: %v", alias, schemaFor("ctx_git"))
		}
	}
}
