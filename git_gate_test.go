package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture secret material is assembled at runtime so secret scanners (and the
// githooks/commit-msg scanner) never see a complete credential literal in the
// source, mirroring fs_security_fixes_test.go / githooks_test.go.
const gitGateSecretValue = "gate-" + "s3cr3t-value-0123456789abcdef"
const gitGateSecretLine = "refresh_" + "token = \"" + gitGateSecretValue + "\""
const gitGateFakeJWT = "e" + "yJhbGciOi" + "." + "cGF5bG9hZE" + "." + "c2lnbmF0dXJl"

// setupGitGateRepo builds a real git repo fixture with one clean commit.
func setupGitGateRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	wd := t.TempDir()
	initTestRepo(t, wd)
	commitFile(t, wd, "README.md", "# hello\n", "initial commit")
	return wd
}

func TestGitSensitiveGate_Unit(t *testing.T) {
	out := "context line\n+" + gitGateSecretLine + "\n"
	gated, hit := gitSensitiveGate("diff", "config.env", out)
	if !hit {
		t.Fatal("expected gate to trip on secret diff output")
	}
	if strings.Contains(gated, gitGateSecretValue) || strings.Contains(gated, "refresh_"+"token") {
		t.Fatalf("withheld notice must not echo secret material:\n%s", gated)
	}
	for _, want := range []string{
		"git diff",
		`pathspec "config.env"`,
		"withheld",
		"sensitive content detected",
		fmt.Sprintf("%d bytes", len(out)),
	} {
		if !strings.Contains(gated, want) {
			t.Fatalf("withheld notice missing %q:\n%s", want, gated)
		}
	}

	kept, hit := gitSensitiveGate("diff", "", "clean diff output\n")
	if hit || kept != "clean diff output\n" {
		t.Fatalf("clean output must pass through unchanged (hit=%v, out=%q)", hit, kept)
	}
}

func TestGitGate_DiffWithSecretWithheld(t *testing.T) {
	wd := setupGitGateRepo(t)
	if err := os.WriteFile(filepath.Join(wd, "README.md"), []byte("# hello\n\n"+gitGateSecretLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := testServerWithWorkdir(t, wd)
	ctx := context.Background()

	// Control: the raw git diff output really does contain the secret.
	raw, err := s.runGit(ctx, wd, "diff", "--no-ext-diff", "--no-textconv")
	if err != nil {
		t.Fatalf("control git diff: %v", err)
	}
	if !strings.Contains(raw, gitGateSecretValue) {
		t.Fatalf("fixture broken: raw diff must contain the secret:\n%s", raw)
	}

	res, _, err := s.toolGitDiff(ctx, nil, gitDiffArgs{})
	if err != nil {
		t.Fatalf("toolGitDiff: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, gitGateSecretValue) || strings.Contains(text, "refresh_"+"token") {
		t.Fatalf("secret leaked through the git diff gate:\n%s", text)
	}
	for _, want := range []string{
		"git diff",
		"withheld",
		"sensitive content detected",
		fmt.Sprintf("%d bytes", len(raw)),
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("withheld notice missing %q:\n%s", want, text)
		}
	}
}

func TestGitGate_DiffCleanPassesThrough(t *testing.T) {
	wd := setupGitGateRepo(t)
	mustWrite(t, filepath.Join(wd, "README.md"), "# hello\nline2\n")

	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolGitDiff(context.Background(), nil, gitDiffArgs{})
	if err != nil {
		t.Fatalf("toolGitDiff: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "line2") {
		t.Fatalf("clean diff must pass through unchanged:\n%s", text)
	}
	if strings.Contains(text, "withheld") {
		t.Fatalf("clean diff must not be gated:\n%s", text)
	}
}

func TestGitGate_StagedDiffWithSecretWithheld(t *testing.T) {
	wd := setupGitGateRepo(t)
	stageFile(t, wd, "config.env", gitGateSecretLine+"\n")

	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolGitDiff(context.Background(), nil, gitDiffArgs{Staged: true, Path: "config.env"})
	if err != nil {
		t.Fatalf("toolGitDiff staged: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, gitGateSecretValue) || strings.Contains(text, "refresh_"+"token") {
		t.Fatalf("secret leaked through the staged diff gate:\n%s", text)
	}
	if !strings.Contains(text, `pathspec "config.env"`) || !strings.Contains(text, "withheld") {
		t.Fatalf("withheld notice must keep command/pathspec metadata:\n%s", text)
	}
}

func TestGitGate_LogWithSecretWithheld(t *testing.T) {
	wd := setupGitGateRepo(t)
	commitFile(t, wd, "app.conf", "k=v\n", "rotate "+gitGateFakeJWT)

	s := testServerWithWorkdir(t, wd)
	ctx := context.Background()

	// Control: the raw git log output really does contain the fake JWT.
	raw, err := s.runGit(ctx, wd, "log", "--oneline", "-n", "5")
	if err != nil {
		t.Fatalf("control git log: %v", err)
	}
	if !strings.Contains(raw, gitGateFakeJWT) {
		t.Fatalf("fixture broken: raw log must contain the fake JWT:\n%s", raw)
	}

	res, _, err := s.toolGitLog(ctx, nil, gitLogArgs{N: 5})
	if err != nil {
		t.Fatalf("toolGitLog: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, gitGateFakeJWT) || strings.Contains(text, "e"+"yJhbGciOi") {
		t.Fatalf("secret leaked through the git log gate:\n%s", text)
	}
	for _, want := range []string{"git log", "withheld", "sensitive content detected"} {
		if !strings.Contains(text, want) {
			t.Fatalf("withheld notice missing %q:\n%s", want, text)
		}
	}
}

func TestGitGate_LogCleanPassesThrough(t *testing.T) {
	wd := setupGitGateRepo(t)
	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolGitLog(context.Background(), nil, gitLogArgs{N: 5})
	if err != nil {
		t.Fatalf("toolGitLog: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "initial commit") {
		t.Fatalf("clean log must pass through unchanged:\n%s", text)
	}
	if strings.Contains(text, "withheld") {
		t.Fatalf("clean log must not be gated:\n%s", text)
	}
}
