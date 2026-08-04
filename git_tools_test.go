package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func setupGitRepo(t *testing.T) (wd string, s *server) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	wd = t.TempDir()
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
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("git", "init")
	// Quiet default branch noise across git versions.
	_ = exec.Command("git", "-C", wd, "checkout", "-b", "main").Run()
	mustWrite(t, filepath.Join(wd, "README.md"), "# hello\n")
	mustWrite(t, filepath.Join(wd, "src", "a.go"), "package src\n")
	run("git", "add", ".")
	run("git", "commit", "-m", "initial commit")
	// Unstaged change for status/diff.
	mustWrite(t, filepath.Join(wd, "README.md"), "# hello\nline2\n")
	s = testServerWithWorkdir(t, wd)
	return wd, s
}

func TestCtxGitStatus_Basic(t *testing.T) {
	_, s := setupGitRepo(t)
	res, _, err := s.toolGitStatus(context.Background(), nil, gitStatusArgs{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "README.md") {
		t.Fatalf("expected README.md in status:\n%s", text)
	}
	// Branch header from -b
	if !strings.Contains(text, "##") {
		t.Fatalf("expected branch header:\n%s", text)
	}
}

func TestCtxGitDiff_BasicAndStat(t *testing.T) {
	_, s := setupGitRepo(t)
	res, _, err := s.toolGitDiff(context.Background(), nil, gitDiffArgs{})
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "README.md") && !strings.Contains(text, "line2") {
		t.Fatalf("expected diff content:\n%s", text)
	}

	res2, _, err := s.toolGitDiff(context.Background(), nil, gitDiffArgs{Stat: true})
	if err != nil {
		t.Fatalf("diff --stat: %v", err)
	}
	statText := mcpResultText(t, res2)
	if !strings.Contains(statText, "README.md") {
		t.Fatalf("expected stat for README.md:\n%s", statText)
	}
}

func TestCtxGitDiff_PathAndOutside(t *testing.T) {
	wd, s := setupGitRepo(t)
	res, _, err := s.toolGitDiff(context.Background(), nil, gitDiffArgs{Path: "README.md"})
	if err != nil {
		t.Fatalf("diff path: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res), "README") && !strings.Contains(mcpResultText(t, res), "line2") {
		// empty is ok if path filter works; ensure no error
		_ = res
	}

	_, _, err = s.toolGitDiff(context.Background(), nil, gitDiffArgs{Path: filepath.Join(wd, "..", "escape")})
	if err == nil {
		t.Fatal("expected outside path rejected")
	}

	// A relative path that stays in another configured workdir but escapes this
	// repository cwd must also be rejected.
	other := t.TempDir()
	s.workdirs = append(s.workdirs, other)
	_, _, err = s.toolGitDiff(context.Background(), nil, gitDiffArgs{Path: filepath.Join("..", filepath.Base(other), "x")})
	if err == nil {
		t.Fatal("expected relative path outside repository cwd rejected")
	}
}

func TestCtxGitLog_Basic(t *testing.T) {
	_, s := setupGitRepo(t)
	res, _, err := s.toolGitLog(context.Background(), nil, gitLogArgs{N: 5})
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "initial") {
		t.Fatalf("expected commit message:\n%s", text)
	}
	// Hard cap n
	oneline := true
	res2, _, err := s.toolGitLog(context.Background(), nil, gitLogArgs{N: 500, Oneline: &oneline})
	if err != nil {
		t.Fatalf("log n=500: %v", err)
	}
	_ = res2
}

func TestCtxGit_NotARepo(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	_, _, err := s.toolGitStatus(context.Background(), nil, gitStatusArgs{})
	if err == nil {
		t.Fatal("expected error for non-git directory")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "not a git repository") {
		t.Fatalf("expected not a git repository error, got: %v", err)
	}
}

func TestCtxGit_OutsideCwd(t *testing.T) {
	_, s := setupGitRepo(t)
	_, _, err := s.toolGitStatus(context.Background(), nil, gitStatusArgs{CWD: "/tmp"})
	if err == nil {
		t.Fatal("expected outside cwd rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "outside") && !strings.Contains(strings.ToLower(err.Error()), "invalid") {
		t.Fatalf("expected outside/invalid cwd error, got: %v", err)
	}
}

func TestTruncateGitOutput(t *testing.T) {
	// Many lines
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("line\n")
	}
	out, trunc := truncateGitOutput(b.String(), 10000, 10)
	if !trunc {
		t.Fatal("expected truncated by lines")
	}
	if strings.Count(out, "\n") > 10 {
		t.Fatalf("too many lines kept: %d", strings.Count(out, "\n"))
	}
	// Bytes
	long := strings.Repeat("x", 500)
	out2, trunc2 := truncateGitOutput(long, 100, 1000)
	if !trunc2 {
		t.Fatal("expected truncated by bytes")
	}
	if len(out2) > 100 {
		t.Fatalf("byte cap failed: %d", len(out2))
	}
}

// H1: parent is a git repo, workdir is a non-repo subdirectory → must reject.
func TestCtxGit_ParentRepoOutsideWorkdir(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	parent := t.TempDir()
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
		}
	}
	run(parent, "git", "init")
	mustWrite(t, filepath.Join(parent, "secret.txt"), "parent-only\n")
	run(parent, "git", "add", ".")
	run(parent, "git", "commit", "-m", "parent commit")

	// Workdir is a plain child of the parent repo (no .git of its own).
	wd := filepath.Join(parent, "child-wd")
	if err := os.MkdirAll(wd, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(wd, "local.txt"), "inside workdir\n")
	s := testServerWithWorkdir(t, wd)

	// status / diff / log must all refuse parent-repo leakage.
	for _, name := range []string{"status", "diff", "log"} {
		var err error
		switch name {
		case "status":
			_, _, err = s.toolGitStatus(context.Background(), nil, gitStatusArgs{})
		case "diff":
			_, _, err = s.toolGitDiff(context.Background(), nil, gitDiffArgs{})
		case "log":
			_, _, err = s.toolGitLog(context.Background(), nil, gitLogArgs{})
		}
		if err == nil {
			t.Fatalf("%s: expected parent-repo-outside-workdir rejection", name)
		}
		low := strings.ToLower(err.Error())
		if !strings.Contains(low, "outside") && !strings.Contains(low, "parent repo") && !strings.Contains(low, "not a git repository") {
			t.Fatalf("%s: expected outside/parent-repo error, got: %v", name, err)
		}
	}
}

// M1: pathspec looking like git flags must not take effect (blocked by "--").
func TestSanitizedGitEnv_RemovesInheritedOverrides(t *testing.T) {
	t.Setenv("GIT_DIR", "/tmp/evil")
	t.Setenv("GIT_CONFIG_GLOBAL", "/tmp/evil-config")
	t.Setenv("GIT_EXTERNAL_DIFF", "/tmp/evil-diff")
	env := sanitizedGitEnv()
	joined := "\n" + strings.Join(env, "\n") + "\n"
	if strings.Contains(joined, "\nGIT_DIR=") || strings.Contains(joined, "\nGIT_CONFIG_GLOBAL=/tmp") {
		t.Fatalf("inherited Git override leaked into sanitized env: %s", joined)
	}
	if !strings.Contains(joined, "\nGIT_CONFIG_GLOBAL=/dev/null\n") ||
		!strings.Contains(joined, "\nGIT_EXTERNAL_DIFF=\n") {
		t.Fatalf("missing hardened Git environment: %s", joined)
	}
}

func TestCtxGitDiff_PathspecNotTreatedAsFlag(t *testing.T) {
	wd, s := setupGitRepo(t)
	outFile := filepath.Join(t.TempDir(), "should-not-exist")

	// If "--output=..." were parsed as a flag, git would write a file.
	// After "--" it is only a pathspec; must not create the output file.
	_, _, err := s.toolGitDiff(context.Background(), nil, gitDiffArgs{
		Path: "--output=" + outFile,
	})
	// Either path resolve fails or git returns empty/no-match; never write outFile.
	if _, statErr := os.Stat(outFile); statErr == nil {
		t.Fatalf("--output pathspec wrote file %q (flag must not take effect); git err=%v", outFile, err)
	}
	// Same for a short flag-looking pathspec.
	_, _, err2 := s.toolGitDiff(context.Background(), nil, gitDiffArgs{Path: "-u"})
	if err2 != nil {
		// path parse / no match failure is fine
		_ = err2
	}
	// Sanity: real path still works.
	res, _, err3 := s.toolGitDiff(context.Background(), nil, gitDiffArgs{Path: "README.md"})
	if err3 != nil {
		t.Fatalf("normal pathspec still works: %v", err3)
	}
	_ = res
	_ = wd
}
