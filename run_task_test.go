package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildRunTaskArgv_GoKinds(t *testing.T) {
	argv, err := buildRunTaskArgv("go_test", "", []string{"-run", "TestFoo", "-count=1"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"go", "test", "./...", "-run", "TestFoo", "-count=1"}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v want %v", argv, want)
	}

	argv, err = buildRunTaskArgv("go_build", "./cmd/foo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "go" || argv[1] != "build" || argv[2] != "./cmd/foo" {
		t.Fatalf("go_build: %v", argv)
	}

	argv, err = buildRunTaskArgv("go_vet", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "go vet ./..." {
		t.Fatalf("go_vet default: %v", argv)
	}
}

func TestBuildRunTaskArgv_NpmInsertsDoubleDash(t *testing.T) {
	argv, err := buildRunTaskArgv("npm_test", "", []string{"--grep", "x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "npm test -- --grep x" {
		t.Fatalf("npm_test: %v", argv)
	}
	argv, err = buildRunTaskArgv("npm_run_build", "", []string{"--mode", "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "npm run build -- --mode prod" {
		t.Fatalf("npm_run_build: %v", argv)
	}
	// No args → no --
	argv, err = buildRunTaskArgv("npm_test", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "npm test" {
		t.Fatalf("npm_test empty: %v", argv)
	}
}

func TestBuildRunTaskArgv_MakeTargetRejectInjection(t *testing.T) {
	_, err := buildRunTaskArgv("make", "all;rm", nil)
	if err == nil {
		t.Fatal("expected make target with ;rm rejected")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid target error, got: %v", err)
	}

	_, err = buildRunTaskArgv("make", "clean && evil", nil)
	if err == nil {
		t.Fatal("expected make target with spaces/&& rejected")
	}

	argv, err := buildRunTaskArgv("make", "test", []string{"-j4"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "make test -j4" {
		t.Fatalf("make: %v", argv)
	}
}

func TestBuildRunTaskArgv_CustomEmptyRejected(t *testing.T) {
	_, err := buildRunTaskArgv("custom", "", nil)
	if err == nil {
		t.Fatal("expected empty custom args rejected")
	}
	_, err = buildRunTaskArgv("custom", "", []string{""})
	if err == nil {
		t.Fatal("expected empty executable rejected")
	}
	argv, err := buildRunTaskArgv("custom", "", []string{"echo", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, " ") != "echo hi" {
		t.Fatalf("custom: %v", argv)
	}
}

func TestBuildRunTaskArgv_UnknownKind(t *testing.T) {
	_, err := buildRunTaskArgv("shell", "", nil)
	if err == nil {
		t.Fatal("expected unknown kind error")
	}
}

func TestToolRunTask_GoTest(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not available")
	}
	// Use this module so `go test` is meaningful.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	s := testServerWithWorkdir(t, wd)

	res, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind:      "go_test",
		Target:    ".",
		Args:      []string{"-run", "TestNonexistentXYZ123", "-count=1"},
		TimeoutMs: 120000,
	})
	if err != nil {
		t.Fatalf("toolRunTask: %v", err)
	}
	text := mcpResultText(t, res)
	// Non-matching -run exits 0 with "no tests to run" OR exit 0 with ok.
	// Either way we must see structured fields.
	if !strings.Contains(text, "exit_code:") {
		t.Fatalf("expected exit_code field:\n%s", text)
	}
	if !strings.Contains(text, "kind: go_test") {
		t.Fatalf("expected kind field:\n%s", text)
	}
	if !strings.Contains(text, "argv: go test") {
		t.Fatalf("expected argv field:\n%s", text)
	}
	// go test with no matching tests typically exit 0
	if !strings.Contains(text, "exit_code: 0") && !strings.Contains(text, "exit_code: 1") {
		t.Fatalf("unexpected exit reporting:\n%s", text)
	}
}

func TestToolRunTask_MakeTargetInjection(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	_, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind:   "make",
		Target: "all;rm -rf /",
	})
	if err == nil {
		t.Fatal("expected make target injection rejected")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid target error, got: %v", err)
	}
}

func TestToolRunTask_CustomEmptyArgs(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	_, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom",
	})
	if err == nil {
		t.Fatal("expected custom empty args rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "args") {
		t.Fatalf("expected args-related error, got: %v", err)
	}
}

func TestToolRunTask_OutsideCwd(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	// Pick a path almost certainly outside the temp workdir.
	outside := filepath.Join(os.TempDir(), "ctxmode-outside-cwd-should-not-exist-parent")
	// Use /tmp which is a real dir but outside the sandboxed temp workdir
	// (unless workdir itself is under /tmp — still must reject sibling paths).
	outside = "/etc"
	_, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom",
		Args: []string{"echo", "x"},
		CWD:  outside,
	})
	if err == nil {
		t.Fatal("expected outside cwd rejected")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "outside") && !strings.Contains(low, "invalid") {
		t.Fatalf("expected outside/invalid cwd error, got: %v", err)
	}
}

func TestToolRunTask_CustomEcho(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom",
		Args: []string{"echo", "run-task-ok"},
	})
	if err != nil {
		t.Fatalf("custom echo: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "exit_code: 0") {
		t.Fatalf("expected exit 0:\n%s", text)
	}
	if !strings.Contains(text, "run-task-ok") {
		t.Fatalf("expected stdout content:\n%s", text)
	}
}

func TestToolRunTask_MissingKind(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	_, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{})
	if err == nil {
		t.Fatal("expected missing kind error")
	}
}

func TestTailUTF8(t *testing.T) {
	s := strings.Repeat("a", 100)
	out := tailUTF8(s, 20)
	if !strings.Contains(out, "truncated head") {
		t.Fatalf("expected truncation marker: %q", out)
	}
	if !strings.HasSuffix(out, strings.Repeat("a", 20)) && !strings.Contains(out, "aaaa") {
		t.Fatalf("expected tail: %q", out)
	}
	if tailUTF8("short", 100) != "short" {
		t.Fatal("short should pass through")
	}
}

// TestFinishRunTaskOutput_HintUsesCtxKb verifies indexed-output messages point
// to the live tool (ctx_kb action=search) and never to the removed ctx_search.
func TestFinishRunTaskOutput_HintUsesCtxKb(t *testing.T) {
	srv := newTestServer(t)

	// Auto-index branch (> 100KB output).
	big := strings.Repeat("x", runTaskAutoIndexBytes+1)
	res, _, err := srv.finishRunTaskOutput(big, 0, "go_test", "")
	if err != nil {
		t.Fatalf("finishRunTaskOutput: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "ctx_kb action=search") {
		t.Fatalf("expected ctx_kb action=search hint, got:\n%s", text)
	}
	if strings.Contains(text, "ctx_search") {
		t.Fatalf("must not reference removed ctx_search tool:\n%s", text)
	}
	if !strings.Contains(text, "Indexed as") {
		t.Fatalf("expected indexed notice:\n%s", text)
	}

	// Intent branch (5KB-100KB with intent).
	med := strings.Repeat("y", runTaskIntentIndexBytes+50)
	res2, _, err := srv.finishRunTaskOutput(med, 0, "go_test", "myintent")
	if err != nil {
		t.Fatalf("finishRunTaskOutput intent: %v", err)
	}
	text2 := mcpResultText(t, res2)
	if !strings.Contains(text2, "ctx_kb action=search") {
		t.Fatalf("expected ctx_kb action=search hint in intent branch:\n%s", text2)
	}
	if strings.Contains(text2, "ctx_search") {
		t.Fatalf("intent branch must not reference ctx_search:\n%s", text2)
	}
	if !strings.Contains(text2, "run_task:myintent") {
		t.Fatalf("expected intent label in message:\n%s", text2)
	}
}
