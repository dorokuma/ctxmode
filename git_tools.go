package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- git tool limits ----------

const (
	gitTimeout        = 15 * time.Second
	gitDiffMaxBytes   = 200 * 1024 // 200 KB
	gitDiffMaxLines   = 2000
	gitLogDefaultN    = 20
	gitLogHardMaxN    = 100
	gitStatusMaxBytes = 100 * 1024
)

// ---------- ctx_git: status ----------

type gitStatusArgs struct {
	CWD string `json:"cwd,omitempty" jsonschema:"Repository working directory (default: workdir root)"`
}

func (s *server) toolGitStatus(ctx context.Context, _ *mcp.CallToolRequest, args gitStatusArgs) (*mcp.CallToolResult, any, error) {
	cwd, err := s.resolveGitCwd(args.CWD)
	if err != nil {
		return nil, nil, err
	}

	out, err := s.runGit(ctx, cwd, "status", "--porcelain=v1", "-b")
	if err != nil {
		return nil, nil, err
	}
	text, truncated := truncateGitOutput(out, gitStatusMaxBytes, gitDiffMaxLines)
	if truncated {
		text += "\n[truncated]"
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}

// ---------- ctx_git_diff ----------

type gitDiffArgs struct {
	CWD     string `json:"cwd,omitempty" jsonschema:"Repository working directory (default: workdir root)"`
	Path    string `json:"path,omitempty" jsonschema:"Optional pathspec relative to cwd (must stay inside workdir)"`
	Stat    bool   `json:"stat,omitempty" jsonschema:"If true, only show --stat summary"`
	Unified int    `json:"unified,omitempty" jsonschema:"Context lines for unified diff (-U)"`
	Staged  bool   `json:"staged,omitempty" jsonschema:"If true, show staged (--cached) diff"`
}

func (s *server) toolGitDiff(ctx context.Context, _ *mcp.CallToolRequest, args gitDiffArgs) (*mcp.CallToolResult, any, error) {
	cwd, err := s.resolveGitCwd(args.CWD)
	if err != nil {
		return nil, nil, err
	}

	gitArgs := []string{"diff", "--no-ext-diff", "--no-textconv"}
	if args.Staged {
		gitArgs = append(gitArgs, "--cached")
	}
	if args.Stat {
		gitArgs = append(gitArgs, "--stat")
	}
	if args.Unified > 0 {
		gitArgs = append(gitArgs, "-U"+strconv.Itoa(args.Unified))
	}
	if args.Path != "" {
		pathspec, err := s.resolveGitPathspec(cwd, args.Path)
		if err != nil {
			return nil, nil, err
		}
		gitArgs = append(gitArgs, "--", pathspec)
	}

	out, err := s.runGit(ctx, cwd, gitArgs...)
	if err != nil {
		return nil, nil, err
	}

	text, truncated := truncateGitOutput(out, gitDiffMaxBytes, gitDiffMaxLines)
	if truncated {
		text += "\n[truncated: output capped at 200KB / 2000 lines]"
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}

// ---------- ctx_git_log ----------

type gitLogArgs struct {
	CWD     string `json:"cwd,omitempty" jsonschema:"Repository working directory (default: workdir root)"`
	N       int    `json:"n,omitempty" jsonschema:"Number of commits (default: 20, hard max: 100)"`
	Path    string `json:"path,omitempty" jsonschema:"Optional pathspec relative to cwd"`
	Oneline *bool  `json:"oneline,omitempty" jsonschema:"One-line format (default: true)"`
}

func (s *server) toolGitLog(ctx context.Context, _ *mcp.CallToolRequest, args gitLogArgs) (*mcp.CallToolResult, any, error) {
	cwd, err := s.resolveGitCwd(args.CWD)
	if err != nil {
		return nil, nil, err
	}

	n := args.N
	if n <= 0 {
		n = gitLogDefaultN
	}
	if n > gitLogHardMaxN {
		n = gitLogHardMaxN
	}

	oneline := true
	if args.Oneline != nil {
		oneline = *args.Oneline
	}

	gitArgs := []string{"log", "--no-show-signature", "-n", strconv.Itoa(n)}
	if oneline {
		gitArgs = append(gitArgs, "--oneline")
	} else {
		gitArgs = append(gitArgs, "--format=%H %an %ad %s", "--date=short")
	}
	if args.Path != "" {
		pathspec, err := s.resolveGitPathspec(cwd, args.Path)
		if err != nil {
			return nil, nil, err
		}
		gitArgs = append(gitArgs, "--", pathspec)
	}

	out, err := s.runGit(ctx, cwd, gitArgs...)
	if err != nil {
		return nil, nil, err
	}
	text, truncated := truncateGitOutput(out, gitDiffMaxBytes, gitDiffMaxLines)
	if truncated {
		text += "\n[truncated]"
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}

// ---------- helpers ----------

// resolveGitCwd resolves optional cwd to an absolute path inside a workdir.
func (s *server) resolveGitCwd(cwd string) (string, error) {
	if cwd == "" {
		return s.workdirs[0], nil
	}
	resolved, err := s.resolvePath(cwd)
	if err != nil {
		return "", fmt.Errorf("invalid cwd: %w", err)
	}
	return resolved, nil
}

// resolveGitPathspec ensures a pathspec stays inside workspaces.
// Relative pathspecs are returned cleaned; absolute ones are made relative to cwd.
func (s *server) resolveGitPathspec(cwd, p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty pathspec")
	}
	if strings.Contains(p, "\x00") {
		return "", fmt.Errorf("invalid pathspec")
	}

	var target string
	if filepath.IsAbs(p) {
		target = filepath.Clean(p)
	} else {
		target = filepath.Clean(filepath.Join(cwd, p))
	}
	if !s.lexicallyInside(target) {
		return "", fmt.Errorf("path %q is outside all workspaces", p)
	}
	// Symlink fence when the path (or a parent) exists.
	if _, err := s.ensureInsideWorkspaces(target); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}

	rel, err := filepath.Rel(cwd, target)
	if err != nil {
		return "", fmt.Errorf("path %q not under cwd: %w", p, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside repository cwd", p)
	}
	clean := filepath.ToSlash(rel)
	if clean == "" || clean == "." {
		return ".", nil
	}
	return clean, nil
}

// gitCeilingDirectories returns a GIT_CEILING_DIRECTORIES value: the parent of
// each workdir. Git still discovers a repo rooted at the workdir itself, but
// will not walk above the workdir into a parent repository.
func (s *server) gitCeilingDirectories() string {
	seen := make(map[string]bool, len(s.workdirs))
	var parts []string
	for _, wd := range s.workdirs {
		clean := filepath.Clean(wd)
		parent := filepath.Dir(clean)
		if parent == "" || parent == "." || parent == clean {
			continue
		}
		if seen[parent] {
			continue
		}
		seen[parent] = true
		parts = append(parts, parent)
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

// sanitizedGitEnv removes inherited GIT_* overrides that could redirect a
// nominally read-only command to another repository, config, object store, or
// executable. Repository-local config still loads, but command-specific
// hardening below disables fsmonitor hooks and external diff programs.
//
// The env starts from childEnv(nil) so sensitive inherited variables are
// stripped with the same default (and CTXMODE_ENV_PASSTHROUGH semantics) as
// the execute path; then GIT_* keys are dropped; then hardening is applied
// LAST so it cannot be overwritten by anything inherited.
func sanitizedGitEnv() []string {
	env := childEnv(nil)
	for k := range env {
		if strings.HasPrefix(strings.ToUpper(k), "GIT_") {
			delete(env, k)
		}
	}
	flat := flattenEnv(env)
	return append(flat,
		"GIT_PAGER=cat",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_EXTERNAL_DIFF=",
	)
}

func hardenedGitArgs(args ...string) []string {
	prefix := []string{
		"-c", "core.fsmonitor=false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "log.showSignature=false",
		"-c", "gpg.program=/bin/true",
		"-c", "gpg.ssh.program=/bin/true",
	}
	return append(prefix, args...)
}

// isNotGitRepoMessage detects git "not a repository" errors across locales
// (English and common Chinese git UI messages).
func isNotGitRepoMessage(msg string) bool {
	low := strings.ToLower(msg)
	if strings.Contains(low, "not a git repository") {
		return true
	}
	// zh_CN / zh_TW git (e.g. "不是 git 仓库")
	if strings.Contains(msg, "不是 git 仓库") || strings.Contains(msg, "不是 Git 仓库") {
		return true
	}
	return false
}

// ensureGitToplevelInside runs `git rev-parse --show-toplevel` in cwd and
// requires the repository root to lie inside configured workdirs. This blocks
// the case where workdir is a plain subdirectory of a parent git repo.
func (s *server) ensureGitToplevelInside(ctx context.Context, cwd string) error {
	gctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()

	cmd := exec.CommandContext(gctx, "git", hardenedGitArgs("rev-parse", "--show-toplevel")...)
	cmd.Dir = cwd
	// No GIT_CEILING here: we intentionally discover parent repos so we can
	// reject them with a clear error instead of a vague "not a git repository".
	cmd.Env = sanitizedGitEnv()

	var stdout, stderr limitedBuffer
	stdout.limit = 64 * 1024
	stderr.limit = 64 * 1024
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			if gctx.Err() != nil {
				return fmt.Errorf("git timed out after %s", gitTimeout)
			}
			msg = err.Error()
		}
		if isNotGitRepoMessage(msg) {
			return fmt.Errorf("not a git repository (cwd=%s): %s", cwd, msg)
		}
		return fmt.Errorf("git rev-parse --show-toplevel failed: %s", msg)
	}

	toplevel := filepath.Clean(strings.TrimSpace(stdout.String()))
	if toplevel == "" || toplevel == "." {
		return fmt.Errorf("git rev-parse --show-toplevel returned empty")
	}
	if !filepath.IsAbs(toplevel) {
		toplevel = filepath.Clean(filepath.Join(cwd, toplevel))
	}

	if !s.lexicallyInside(toplevel) {
		return fmt.Errorf("git repository root %q is outside workdir (parent repo outside workdir)", toplevel)
	}
	if _, err := s.ensureInsideWorkspaces(toplevel); err != nil {
		return fmt.Errorf("git repository root outside workdir: %w", err)
	}
	return nil
}

// runGit executes a git subcommand in cwd with a short timeout.
// Non-git repositories surface a clear error. The repo toplevel must resolve
// inside configured workdirs (see ensureGitToplevelInside).
func (s *server) runGit(ctx context.Context, cwd string, args ...string) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git executable not found on PATH")
	}

	// H1: refuse when git would operate on a parent repo outside workdirs.
	if err := s.ensureGitToplevelInside(ctx, cwd); err != nil {
		return "", err
	}

	return s.runGitIn(ctx, cwd, args...)
}

func (s *server) runGitIn(ctx context.Context, cwd string, args ...string) (string, error) {
	gctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()

	cmd := exec.CommandContext(gctx, "git", hardenedGitArgs(args...)...)
	cmd.Dir = cwd
	// Avoid paging / prompts and ignore inherited Git redirection variables.
	cmd.Env = sanitizedGitEnv()
	if ceil := s.gitCeilingDirectories(); ceil != "" {
		cmd.Env = append(cmd.Env, "GIT_CEILING_DIRECTORIES="+ceil)
	}

	var stdout, stderr limitedBuffer
	stdout.limit = 2 * gitDiffMaxBytes
	stderr.limit = 64 * 1024
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			if gctx.Err() != nil {
				return "", fmt.Errorf("git timed out after %s", gitTimeout)
			}
			msg = err.Error()
		}
		if isNotGitRepoMessage(msg) {
			return "", fmt.Errorf("not a git repository (cwd=%s): %s", cwd, msg)
		}
		if len(args) > 0 {
			return "", fmt.Errorf("git %s failed: %s", args[0], msg)
		}
		return "", fmt.Errorf("git failed: %s", msg)
	}
	return stdout.String(), nil
}

// truncateGitOutput caps by line count then byte size; returns truncated flag.
func truncateGitOutput(s string, maxBytes, maxLines int) (string, bool) {
	if s == "" {
		return "", false
	}
	truncated := false

	if maxLines > 0 {
		lines := 0
		cut := -1
		for i := 0; i < len(s); i++ {
			if s[i] == '\n' {
				lines++
				if lines >= maxLines {
					cut = i + 1
					break
				}
			}
		}
		// No trailing newline and more content than maxLines: count last line.
		if cut < 0 {
			// fewer than maxLines newlines — check if we still exceed by last partial line
			// lines = number of complete lines ending with \n; total lines = lines or lines+1
			total := lines
			if len(s) > 0 && !strings.HasSuffix(s, "\n") {
				total++
			}
			if total > maxLines {
				// shouldn't happen without enough newlines, but keep safe
				cut = len(s)
			}
		}
		if cut >= 0 && cut < len(s) {
			s = s[:cut]
			truncated = true
		}
	}

	if maxBytes > 0 && len(s) > maxBytes {
		s = truncateUTF8(s, maxBytes)
		truncated = true
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	return s, truncated
}
