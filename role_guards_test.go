package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- rule 1: sub-agent nested-dispatch guard ----------

// TestGuard_SubagentNestedArgv covers the argv path of the nested-dispatch
// guard: bare names, absolute paths, env/KEY=VAL wrappers, and `shell -c`
// unwrap are blocked for a sub-agent caller, while agent-name arguments are
// not command heads and must pass.

// readonlyWantMatch accepts legacy blacklist details and allowlist-prefixed
// details. A non-empty want means "must block"; any allowlist denial matches.
func readonlyWantMatch(got, want string) bool {
	if got == want {
		return true
	}
	const prefix = "not in readonly allowlist: "
	if want != "" && strings.HasPrefix(got, prefix) {
		return true
	}
	return false
}

func TestGuard_SubagentNestedArgv(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string // "" = allowed
	}{
		{name: "bare pig", argv: []string{"pig", "run"}, want: "pig"},
		{name: "absolute path", argv: []string{"/root/.pig/bin/pi"}, want: "pi"},
		{name: "relative path", argv: []string{"./bin/agy"}, want: "agy"},
		{name: "env wrapper", argv: []string{"env", "FOO=1", "pig"}, want: "pig"},
		{name: "exec wrapper", argv: []string{"exec", "dispatch-agent"}, want: "dispatch-agent"},
		{name: "nohup timeout chain", argv: []string{"nohup", "timeout", "5", "grok"}, want: "grok"},
		{name: "busybox wrapper", argv: []string{"busybox", "pi"}, want: "pi"},
		{name: "sh -c nested", argv: []string{"sh", "-c", "pig --version"}, want: "pig"},
		{name: "bash -lc nested", argv: []string{"bash", "-lc", "agy"}, want: "agy"},
		{name: "herdsman on", argv: []string{"herdsman", "on"}, want: "herdsman on"},
		{name: "herdr tab create", argv: []string{"herdr", "tab", "create"}, want: "herdr tab create"},
		{name: "herdr pane send-keys", argv: []string{"herdr", "pane", "send-keys", "p1", "x"}, want: "herdr pane send-keys"},
		{name: "herdr server stop", argv: []string{"herdr", "server", "stop"}, want: "herdr server stop"},
		{name: "herdr workspace focus", argv: []string{"herdr", "workspace", "focus", "w"}, want: "herdr workspace focus"},
		{name: "herdr agent prompt", argv: []string{"herdr", "agent", "prompt", "a"}, want: "herdr agent prompt"},

		// Allowed: agent names as ARGUMENTS, not command heads.
		{name: "echo pig", argv: []string{"echo", "pig"}, want: ""},
		{name: "git grep pig", argv: []string{"git", "log", "--grep=pig"}, want: ""},
		{name: "go build -o agy", argv: []string{"go", "build", "-o", "/tmp/agy"}, want: ""},
		// Allowed: herdr/herdsman read-only queries.
		{name: "herdr session list", argv: []string{"herdr", "session", "list"}, want: ""},
		{name: "herdr pane list", argv: []string{"herdr", "pane", "list"}, want: ""},
		{name: "herdr pane read", argv: []string{"herdr", "pane", "read", "p1"}, want: ""},
		{name: "herdr agent list", argv: []string{"herdr", "agent", "list"}, want: ""},
		{name: "herdr server agent-manifests", argv: []string{"herdr", "server", "agent-manifests"}, want: ""},
		{name: "herdr --help", argv: []string{"herdr", "--help"}, want: ""},
		{name: "herdsman status", argv: []string{"herdsman", "status"}, want: ""},
		{name: "herdsman daemon status", argv: []string{"herdsman", "daemon", "status"}, want: ""},
		{name: "herdsman agent list", argv: []string{"herdsman", "agent", "list"}, want: ""},
		{name: "ordinary command", argv: []string{"ls", "-la"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_SubagentNestedShell covers the shell-text path: each segment's
// command head is screened; subshells, substitutions, pipes, && and env
// wrappers all still surface the blocked head.
func TestGuard_SubagentNestedShell(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		code string
		want string
	}{
		{name: "bare", code: "pig", want: "pig"},
		{name: "after &&", code: "cd /tmp && pig run", want: "pig"},
		{name: "after pipe", code: "cat x | agy", want: "agy"},
		{name: "env + KEY=VAL", code: "FOO=1 env BAR=2 pi", want: "pi"},
		{name: "subshell", code: "(cd x; grok)", want: "grok"},
		{name: "command substitution", code: "echo $(dispatch-agent --check)", want: "dispatch-agent"},
		{name: "backtick substitution", code: "echo `pig`", want: "pig"},
		{name: "semicolon separated", code: "ls; pi", want: "pi"},
		{name: "nested sh -c", code: "sh -c 'env pig'", want: "pig"},
		{name: "herdr in compound", code: "true && herdr tab close t1", want: "herdr tab close"},
		{name: "quoted name not head", code: "echo 'pig' && echo \"agy\"", want: ""},
		{name: "argument not head", code: "echo pig; ls agy", want: ""},
		{name: "herd query", code: "herdr pane current", want: ""},
		{name: "heredoc body is data", code: "cat <<'EOF'\npig is mentioned\nEOF\necho done", want: ""},
		{name: "shell heredoc body is code", code: "sh <<'EOF'\npig\nEOF", want: "pig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardShellSubagent(tc.code)
			if got != tc.want {
				t.Fatalf("guardShellSubagent(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

// ---------- rule 2: strict read-only write guard ----------

// TestGuard_ReadonlyArgvWrite covers write/destructive heads vs read-only
// probes for the strict read-only guard.
func TestGuard_ReadonlyArgvWrite(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "rm", argv: []string{"rm", "-rf", "/tmp/x"}, want: "rm"},
		{name: "mkdir", argv: []string{"mkdir", "/tmp/x"}, want: "mkdir"},
		{name: "mv", argv: []string{"mv", "a", "b"}, want: "mv"},
		{name: "tee", argv: []string{"tee", "/tmp/x"}, want: "tee"},
		{name: "chmod", argv: []string{"chmod", "+x", "f"}, want: "chmod"},
		{name: "kill", argv: []string{"kill", "-9", "1"}, want: "kill"},
		{name: "sed -i", argv: []string{"sed", "-i", "s/a/b/", "f"}, want: "sed -i"},
		{name: "sed -i.bak", argv: []string{"sed", "-i.bak", "s/a/b/", "f"}, want: "sed -i"},
		{name: "sed -ni", argv: []string{"sed", "-ni", "p", "f"}, want: "sed -i"},
		{name: "sed -Ei", argv: []string{"sed", "-Ei", "s/a/b/", "f"}, want: "sed -i"},
		{name: "perl -i", argv: []string{"perl", "-i", "-pe", "s/a/b/", "f"}, want: "perl -i"},
		{name: "gofmt -w", argv: []string{"gofmt", "-w", "x.go"}, want: "gofmt -w"},
		{name: "git commit", argv: []string{"git", "commit", "-m", "x"}, want: "git commit"},
		{name: "git -C clone", argv: []string{"git", "-C", "/tmp", "clone", "u"}, want: "git clone"},
		{name: "git worktree add", argv: []string{"git", "worktree", "add", "/tmp/w"}, want: "git worktree add"},
		{name: "git branch -d", argv: []string{"git", "branch", "-d", "b"}, want: "git branch -d"},
		{name: "git remote add", argv: []string{"git", "remote", "add", "o", "u"}, want: "git remote add"},
		{name: "git tag new", argv: []string{"git", "tag", "v1"}, want: "git tag"},
		{name: "git config write", argv: []string{"git", "config", "k", "v"}, want: "git config"},
		{name: "go build", argv: []string{"go", "build", "./..."}, want: "go build"},
		{name: "go test", argv: []string{"go", "test", "./..."}, want: "go test"},
		{name: "npm install", argv: []string{"npm", "install"}, want: "npm install"},
		{name: "systemctl restart", argv: []string{"systemctl", "restart", "x"}, want: "systemctl restart"},
		{name: "cargo publish", argv: []string{"cargo", "publish"}, want: "cargo publish"},

		// Allowed read-only probes.
		{name: "git status", argv: []string{"git", "status"}, want: ""},
		{name: "git show", argv: []string{"git", "show", "HEAD"}, want: ""},
		{name: "git worktree list", argv: []string{"git", "worktree", "list"}, want: ""},
		{name: "git branch -a", argv: []string{"git", "branch", "-a"}, want: ""},
		{name: "git branch bare", argv: []string{"git", "branch"}, want: ""},
		{name: "git remote -v", argv: []string{"git", "remote", "-v"}, want: ""},
		{name: "git tag -l", argv: []string{"git", "tag", "-l"}, want: ""},
		{name: "git tag bare", argv: []string{"git", "tag"}, want: ""},
		{name: "git config --get", argv: []string{"git", "config", "--get", "k"}, want: ""},
		{name: "git config -l", argv: []string{"git", "config", "-l"}, want: ""},
		{name: "git -c diff", argv: []string{"git", "-c", "a=b", "diff"}, want: "git -c"},
		{name: "sed -n", argv: []string{"sed", "-n", "1,20p", "f"}, want: ""},
		{name: "gofmt -d", argv: []string{"gofmt", "-d", "x.go"}, want: ""},
		{name: "go version", argv: []string{"go", "version"}, want: ""},
		{name: "go env", argv: []string{"go", "env"}, want: ""},
		{name: "ls", argv: []string{"ls", "-la"}, want: ""},
		{name: "cat", argv: []string{"cat", "f"}, want: ""},
		{name: "systemctl status", argv: []string{"systemctl", "status", "x"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_ReadonlyShellWrite covers redirects and compound-command writes.
func TestGuard_ReadonlyShellWrite(t *testing.T) {
	t.Setenv(auditEnvRole, "planner")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		code string
		want string
	}{
		{name: "redirect to file", code: "echo x > /tmp/out", want: "> /tmp/out"},
		{name: "append", code: "echo x >> f.log", want: "> f.log"},
		{name: "redirect in pipe", code: "ls | tee f", want: "tee"},
		{name: "rm after &&", code: "cd /tmp && rm -rf x", want: "rm"},
		{name: "nested sh -c", code: "sh -c 'touch f'", want: "touch"},
		{name: "bash -c rm", code: "bash -c 'rm -rf /tmp/x'", want: "rm"},

		// Redirects that must pass: /dev/null, /dev/stdout, fd duplications.
		{name: "2>/dev/null", code: "true 2>/dev/null", want: ""},
		{name: "2>&1 pipe", code: "true 2>&1 | head", want: ""},
		{name: ">/dev/null", code: "true > /dev/null", want: ""},
		{name: "1>&2", code: "echo x 1>&2", want: ""},
		{name: ">&2", code: "echo x >&2", want: "redirect"},
		{name: ">&-", code: "true >&-", want: "redirect"},
		{name: "input redirect", code: "cat < /etc/hosts", want: "input redirect"},
		{name: "echo pig", code: "echo pig", want: ""},
		{name: "quoted redirect op", code: "echo 'a > b'", want: ""},
		{name: "git status", code: "git status && git log -3", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardShellReadonly(tc.code)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardShellReadonly(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

// ---------- hardening: git dual-mode subcommands ----------

// TestGuard_GitDualMode covers the git read-only whitelist + per-subcommand
// flag precision: query spellings pass, write spellings and unknown
// subcommands block for strict read-only roles.
func TestGuard_GitDualMode(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		// worktree
		{name: "git worktree bare", argv: []string{"git", "worktree"}, want: "deleted"},
		{name: "git worktree list", argv: []string{"git", "worktree", "list"}, want: ""},
		{name: "git worktree -h", argv: []string{"git", "worktree", "-h"}, want: "deleted"},
		{name: "git worktree --help", argv: []string{"git", "worktree", "--help"}, want: "deleted"},
		{name: "git worktree add", argv: []string{"git", "worktree", "add", "/tmp/w"}, want: "git worktree add"},
		{name: "git worktree remove", argv: []string{"git", "worktree", "remove", "w"}, want: "git worktree remove"},
		{name: "git worktree prune", argv: []string{"git", "worktree", "prune"}, want: "git worktree prune"},
		{name: "git worktree repair", argv: []string{"git", "worktree", "repair", "/x"}, want: "git worktree repair"},
		{name: "git worktree lock", argv: []string{"git", "worktree", "lock", "w"}, want: "git worktree lock"},
		// branch
		{name: "git branch --contains", argv: []string{"git", "branch", "--contains", "HEAD"}, want: ""},
		{name: "git branch --no-contains", argv: []string{"git", "branch", "--no-contains", "HEAD"}, want: ""},
		{name: "git branch --merged", argv: []string{"git", "branch", "--merged"}, want: ""},
		{name: "git branch --no-merged", argv: []string{"git", "branch", "--no-merged"}, want: ""},
		{name: "git branch --points-at", argv: []string{"git", "branch", "--points-at", "HEAD"}, want: ""},
		{name: "git branch --sort", argv: []string{"git", "branch", "--sort", "-committerdate"}, want: ""},
		{name: "git branch --format", argv: []string{"git", "branch", "--format", "%(refname)"}, want: ""},
		{name: "git branch -l", argv: []string{"git", "branch", "-l", "fix/*"}, want: ""},
		{name: "git branch --list", argv: []string{"git", "branch", "--list", "fix/*"}, want: ""},
		{name: "git branch new", argv: []string{"git", "branch", "feature-x"}, want: "git branch feature-x"},
		{name: "git branch -d", argv: []string{"git", "branch", "-d", "b"}, want: "git branch -d"},
		{name: "git branch -m", argv: []string{"git", "branch", "-m", "a", "b"}, want: "git branch -m"},
		{name: "git branch --set-upstream-to", argv: []string{"git", "branch", "--set-upstream-to", "o/b"}, want: "git branch --set-upstream-to"},
		{name: "git branch --edit-description", argv: []string{"git", "branch", "--edit-description"}, want: "git branch --edit-description"},
		// tag
		{name: "git tag -d -n bypass", argv: []string{"git", "tag", "-d", "foo", "-n"}, want: "git tag -d"},
		{name: "git tag -l -n", argv: []string{"git", "tag", "-l", "-n"}, want: ""},
		{name: "git tag -n", argv: []string{"git", "tag", "-n"}, want: ""},
		{name: "git tag -n5", argv: []string{"git", "tag", "-n5"}, want: ""},
		{name: "git tag --points-at", argv: []string{"git", "tag", "--points-at", "HEAD"}, want: ""},
		{name: "git tag -v", argv: []string{"git", "tag", "-v", "v1"}, want: ""},
		{name: "git tag create -a", argv: []string{"git", "tag", "-a", "v1", "-m", "x"}, want: "git tag -a"},
		{name: "git tag sign", argv: []string{"git", "tag", "-s", "v1"}, want: "git tag -s"},
		{name: "git tag -m", argv: []string{"git", "tag", "-m", "msg", "v1"}, want: "git tag -m"},
		{name: "git tag new name", argv: []string{"git", "tag", "v2"}, want: "git tag"},
		// config
		{name: "git config --unset", argv: []string{"git", "config", "--unset", "k"}, want: "git config --unset"},
		{name: "git config --add", argv: []string{"git", "config", "--add", "k", "v"}, want: "git config --add"},
		{name: "git config --replace-all", argv: []string{"git", "config", "--replace-all", "k", "v"}, want: "git config --replace-all"},
		{name: "git config -e", argv: []string{"git", "config", "-e"}, want: "git config -e"},
		{name: "git config --get", argv: []string{"git", "config", "--get", "k"}, want: ""},
		{name: "git config --get-regexp", argv: []string{"git", "config", "--get-regexp", "user"}, want: ""},
		{name: "git config -l", argv: []string{"git", "config", "-l"}, want: ""},
		{name: "git config --list", argv: []string{"git", "config", "--list"}, want: ""},
		{name: "git config write pair", argv: []string{"git", "config", "user.name", "x"}, want: "git config"},
		// remote
		{name: "git remote bare", argv: []string{"git", "remote"}, want: ""},
		{name: "git remote -v", argv: []string{"git", "remote", "-v"}, want: ""},
		{name: "git remote show", argv: []string{"git", "remote", "show", "origin"}, want: "deleted"},
		{name: "git remote get-url", argv: []string{"git", "remote", "get-url", "origin"}, want: ""},
		{name: "git remote add", argv: []string{"git", "remote", "add", "o", "u"}, want: "git remote add"},
		{name: "git remote set-url", argv: []string{"git", "remote", "set-url", "o", "u"}, want: "git remote set-url"},
		{name: "git remote remove", argv: []string{"git", "remote", "remove", "o"}, want: "git remote remove"},
		// stash
		{name: "git stash list", argv: []string{"git", "stash", "list"}, want: ""},
		{name: "git stash show", argv: []string{"git", "stash", "show"}, want: ""},
		{name: "git stash bare", argv: []string{"git", "stash"}, want: "git stash"},
		{name: "git stash pop", argv: []string{"git", "stash", "pop"}, want: "git stash pop"},
		{name: "git stash push", argv: []string{"git", "stash", "push", "-m", "x"}, want: "git stash push"},
		// unknown / write subcommands: whitelist blocks them all
		{name: "git notes", argv: []string{"git", "notes", "add", "-m", "x"}, want: "git notes"},
		{name: "git replace", argv: []string{"git", "replace", "a", "b"}, want: "git replace"},
		{name: "git update-ref", argv: []string{"git", "update-ref", "HEAD", "x"}, want: "git update-ref"},
		{name: "git symbolic-ref", argv: []string{"git", "symbolic-ref", "HEAD", "r"}, want: "git symbolic-ref"},
		{name: "git write-tree", argv: []string{"git", "write-tree"}, want: "git write-tree"},
		{name: "git hash-object -w", argv: []string{"git", "hash-object", "-w", "f"}, want: "git hash-object"},
		{name: "git archive", argv: []string{"git", "archive", "HEAD"}, want: "git archive"},
		{name: "git bundle", argv: []string{"git", "bundle", "create", "b", "HEAD"}, want: "git bundle"},
		{name: "git format-patch", argv: []string{"git", "format-patch", "-1"}, want: "git format-patch"},
		{name: "git maintenance", argv: []string{"git", "maintenance", "run"}, want: "git maintenance"},
		{name: "git checkout", argv: []string{"git", "checkout", "b"}, want: "git checkout"},
		{name: "git reflog bare ok", argv: []string{"git", "reflog"}, want: ""},
		// --output writes a file even on read verbs
		{name: "git diff --output", argv: []string{"git", "diff", "--output", "/tmp/d"}, want: "git diff --output"},
		{name: "git log --output=", argv: []string{"git", "log", "--output=/tmp/l"}, want: "git log --output"},
		// whitelist read verbs stay free
		{name: "git blame", argv: []string{"git", "blame", "f.go"}, want: ""},
		{name: "git grep", argv: []string{"git", "grep", "foo"}, want: ""},
		{name: "git ls-files", argv: []string{"git", "ls-files"}, want: ""},
		{name: "git rev-parse", argv: []string{"git", "rev-parse", "HEAD"}, want: ""},
		{name: "git for-each-ref", argv: []string{"git", "for-each-ref"}, want: ""},
		{name: "git fsck", argv: []string{"git", "fsck"}, want: "deleted"},
		{name: "git count-objects", argv: []string{"git", "count-objects", "-v"}, want: ""},
		{name: "git check-ignore", argv: []string{"git", "check-ignore", "f"}, want: ""},
		{name: "git var", argv: []string{"git", "var", "GIT_AUTHOR_IDENT"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// ---------- hardening: wrappers / command -v / env -S / eval / xargs / find ----------

// TestGuard_WrapperPrecision covers command -v, `--` terminators, glued
// sh -c"...", env -S payloads, eval, xargs and find recursion.
func TestGuard_WrapperPrecision(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "command -v pig is read-only query", argv: []string{"command", "-v", "pig"}, want: ""},
		{name: "command -V rm", argv: []string{"command", "-V", "rm"}, want: ""},
		{name: "command pig still blocked", argv: []string{"command", "pig"}, want: "pig"},
		{name: "command -p pig peels", argv: []string{"command", "-p", "pig"}, want: "pig"},
		{name: "env -- pig", argv: []string{"env", "--", "pig"}, want: "pig"},
		{name: "timeout -- 5 pig", argv: []string{"timeout", "--", "5", "pig"}, want: "pig"},
		{name: "nice -- pig", argv: []string{"nice", "--", "pig"}, want: "pig"},
		{name: "nohup -- pig", argv: []string{"nohup", "--", "pig"}, want: "pig"},
		{name: "setsid -- pig", argv: []string{"setsid", "--", "pig"}, want: "pig"},
		{name: "exec -- pig", argv: []string{"exec", "--", "pig"}, want: "pig"},
		{name: "env -uVAR pig", argv: []string{"env", "-uHOME", "pig"}, want: "pig"},
		{name: "env --unset=VAR pig", argv: []string{"env", "--unset=HOME", "pig"}, want: "pig"},
		{name: "env -CDIR pig", argv: []string{"env", "-C/tmp", "pig"}, want: "pig"},
		{name: "env -S pig", argv: []string{"env", "-S", "pig --help"}, want: "env unknown option -S/--split-string"},
		{name: "env --split-string pig", argv: []string{"env", "--split-string", "agy"}, want: "env unknown option -S/--split-string"},
		{name: "env --split-string= pig", argv: []string{"env", "--split-string=pi"}, want: "env unknown option -S/--split-string"},
		{name: "env -S read-only cmd ok", argv: []string{"env", "-S", "git status"}, want: "env unknown option -S/--split-string"},
		{name: "sh -c glued", argv: []string{"sh", "-cpig"}, want: "pig"},
		{name: "bash -lc glued", argv: []string{"bash", "-lcagy"}, want: "agy"},
		{name: "eval pig", argv: []string{"eval", "pig"}, want: "pig"},
		{name: "eval echo ok", argv: []string{"eval", "echo ok"}, want: ""},
		{name: "xargs pig", argv: []string{"xargs", "pig"}, want: "pig"},
		{name: "xargs -I{} pig", argv: []string{"xargs", "-I{}", "pig"}, want: "pig"},
		{name: "xargs -n1 pig", argv: []string{"xargs", "-n", "1", "pig"}, want: "pig"},
		{name: "xargs grep", argv: []string{"xargs", "grep", "foo"}, want: ""},
		{name: "xargs -0 grep", argv: []string{"xargs", "-0", "grep", "-l", "x"}, want: ""},
		{name: "xargs bare echo", argv: []string{"xargs"}, want: ""},
		{name: "find -exec pig", argv: []string{"find", ".", "-exec", "pig", "{}", ";"}, want: "find -exec pig"},
		{name: "find -exec grep ok", argv: []string{"find", ".", "-exec", "grep", "foo", "{}", "+"}, want: ""},
		{name: "find -execdir agy", argv: []string{"find", ".", "-execdir", "agy", ";"}, want: "find -execdir agy"},
		{name: "find -ok pig", argv: []string{"find", ".", "-ok", "pig", ";"}, want: "find -ok pig"},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "command -v rm allowed", argv: []string{"command", "-v", "rm"}, want: "deleted"},
		{name: "env -S rm", argv: []string{"env", "-S", "rm -f /tmp/x"}, want: "rm"},
		{name: "env -- rm", argv: []string{"env", "--", "rm", "f"}, want: "rm"},
		{name: "sh -c glued rm", argv: []string{"sh", "-crm -f x"}, want: "rm"},
		{name: "eval rm", argv: []string{"eval", "rm -f x"}, want: "rm"},
		{name: "eval echo ok", argv: []string{"eval", "echo ok"}, want: "eval"},
		{name: "xargs rm", argv: []string{"xargs", "rm"}, want: "rm"},
		{name: "xargs sed -i", argv: []string{"xargs", "sed", "-i", "s/a/b/"}, want: "sed -i"},
		{name: "xargs wc ok", argv: []string{"xargs", "wc", "-l"}, want: "deleted"},
		{name: "xargs -a file grep", argv: []string{"xargs", "-a", "f.txt", "grep", "x"}, want: "deleted"},
		{name: "find -delete", argv: []string{"find", ".", "-delete"}, want: "find -delete"},
		{name: "find -exec rm", argv: []string{"find", ".", "-exec", "rm", "{}", "+"}, want: "find -exec rm"},
		{name: "find -fls", argv: []string{"find", ".", "-fls", "/tmp/x"}, want: "find -fls"},
		{name: "find -fprint", argv: []string{"find", ".", "-fprint", "/tmp/x"}, want: "find -fprint"},
		{name: "find name ok", argv: []string{"find", ".", "-name", "*.go"}, want: ""},
		{name: "find -exec grep ok", argv: []string{"find", ".", "-exec", "grep", "foo", "{}", "+"}, want: "find -exec"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// ---------- hardening: redirects / comparisons / heredocs ----------

// TestGuard_RedirectAndComparison covers dynamic redirect targets, [[ ]]/
// (( )) comparison operators, and heredoc body handling.
func TestGuard_RedirectAndComparison(t *testing.T) {
	t.Setenv(auditEnvRole, "planner")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		code string
		want string
	}{
		// Dynamic redirect targets must block, not silently pass.
		{name: "redirect to $(...)", code: "echo hi > $(printf /tmp/x)", want: "> <dynamic>"},
		{name: "redirect to backtick", code: "echo hi > `printf /tmp/x`", want: "> <dynamic>"},
		// [[ ]] and (( )) comparisons are not redirections.
		{name: "[[ a > b ]]", code: "[[ $a > $b ]]", want: "[["},
		{name: "[[ a < b ]]", code: "[[ $a < $b ]]", want: "[["},
		{name: "(( a > 0 ))", code: "(( a > 0 ))", want: "parentheses"},
		{name: "echo $((1+1)) ok", code: "echo $((1+1))", want: "$"},
		{name: "standalone $((1+1)) ok", code: "$((1+1))", want: "deleted"},
		{name: "$(( 2 > 1 ))", code: "x=$(( 2 > 1 ))", want: "env assign"},
		// Heredoc body lines are not shell commands.
		{name: "python heredoc rm var ok", code: "python3 - <<'PY'\nimport json\nrm = 1\nprint(rm)\nPY", want: "python interpreter"},
		{name: "cat heredoc rm text ok", code: "cat <<'EOF'\nrm -rf /\nEOF", want: "input redirect"},
		// Shell heredoc body IS code.
		{name: "sh heredoc rm", code: "sh <<'EOF'\nrm -f /tmp/x\nEOF", want: "rm"},
		{name: "bash heredoc rm", code: "bash <<-EOF\n\trm x\n\tEOF", want: "rm"},
		// Interpreter heredoc write is code too.
		{name: "python heredoc write", code: "python3 - <<'PY'\nopen('/tmp/x','w').write('a')\nPY", want: "python open() write mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardShellReadonly(tc.code)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardShellReadonly(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}

	// Substitution inside a dynamic redirect target still scans for agents.
	t.Setenv(auditEnvRole, "worker")
	if got := guardShellSubagent("echo hi > $(pig)"); got == "" {
		t.Fatalf("guardShellSubagent must catch nested dispatch in redirect target")
	}
	// Unquoted heredoc: $(...) inside the body still expands.
	if got := guardShellSubagent("cat <<EOF\n$(pig)\nEOF"); got == "" {
		t.Fatalf("unquoted heredoc substitution must scan for agents")
	}
}

// ---------- hardening: interpreter code guard ----------

// TestGuard_CtxRunCode covers guardCtxRunCode: spawn+agent (subagent), spawn
// primitives and write primitives (strict read-only).
func TestGuard_CtxRunCode(t *testing.T) {
	sub := guardCall{subagent: true}
	strict := guardCall{strictReadonly: true}

	subCases := []struct {
		name string
		lang string
		code string
		want bool // blocked?
	}{
		{name: "subprocess pig", lang: "python", code: "import subprocess\nsubprocess.run(['pig','--help'])", want: true},
		{name: "os.system agy", lang: "python", code: "import os\nos.system('agy')", want: true},
		{name: "child_process grok", lang: "javascript", code: "const cp=require('child_process');cp.execSync('grok')", want: true},
		{name: "execSync dispatch", lang: "javascript", code: "execSync('dispatch-agent --check')", want: true},
		{name: "subprocess go test ok", lang: "python", code: "import subprocess\nsubprocess.run(['go','test','./...'])", want: false},
		{name: "os.system rm no agent ok", lang: "python", code: "import os\nos.system('ls')", want: false},
		{name: "mention pig no spawn", lang: "python", code: "x = 'pig'\nprint(x)", want: false},
		{name: "plain print", lang: "python", code: "import json\nprint(json.dumps({}))", want: false},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			rule, _ := sub.guardCtxRunCode(tc.lang, tc.code)
			if (rule == ruleSubagentNestedAgent) != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule = %q, want blocked=%v", tc.code, rule, tc.want)
			}
		})
	}

	roCases := []struct {
		name string
		lang string
		code string
		want bool
	}{
		{name: "os.system blocked", lang: "python", code: "import os\nos.system('rm -rf x')", want: true},
		{name: "subprocess blocked", lang: "python", code: "import subprocess\nsubprocess.run(['ls'])", want: true},
		{name: "open write", lang: "python", code: "open('/tmp/x','w').write('a')", want: true},
		{name: "open append", lang: "python", code: "open('/tmp/x','a')", want: true},
		{name: "open x mode", lang: "python", code: "open('/tmp/x','x')", want: true},
		{name: "open w+ mode", lang: "python", code: "open('/tmp/x','w+')", want: true},
		{name: "open mode kwarg", lang: "python", code: "open('/tmp/x', mode='w')", want: true},
		{name: "open read ok", lang: "python", code: "open('/tmp/x').read()", want: false},
		{name: "open r ok", lang: "python", code: "open('/tmp/x','r').read()", want: false},
		{name: "open rb ok", lang: "python", code: "open('/tmp/x','rb').read()", want: false},
		{name: "os.remove", lang: "python", code: "import os\nos.remove('/tmp/x')", want: true},
		{name: "os.mkdir", lang: "python", code: "import os\nos.mkdir('/tmp/x')", want: true},
		{name: "shutil.rmtree", lang: "python", code: "import shutil\nshutil.rmtree('/tmp/x')", want: true},
		{name: "pathlib unlink", lang: "python", code: "from pathlib import Path\nPath('/tmp/x').unlink()", want: true},
		{name: "pathlib touch", lang: "python", code: "from pathlib import Path\nPath('/tmp/x').touch()", want: true},
		{name: "tempfile mkstemp", lang: "python", code: "import tempfile\ntempfile.mkstemp()", want: true},
		{name: "python read-only json", lang: "python", code: "import json\nrm = 1\nprint(rm)", want: false},
		{name: "fs.writeFileSync", lang: "javascript", code: "fs.writeFileSync('/tmp/x','a')", want: true},
		{name: "fs.rmSync", lang: "javascript", code: "fs.rmSync('/tmp/x')", want: true},
		{name: "fs.mkdir", lang: "javascript", code: "fs.mkdirSync('/tmp/x')", want: true},
		{name: "fs.openSync w", lang: "javascript", code: "fs.openSync('/tmp/x','w')", want: true},
		// A "foo (bar)" string BEFORE the call breaks byte alignment if the
		// masked view is spacing-normalized — the mode literal must still be
		// recovered from the aligned raw span.
		{name: "fs.openSync w after (bar) string", lang: "javascript", code: "console.log(\"foo (bar)\"); fs.openSync('/tmp/x','w')", want: true},
		{name: "fs.openSync r after (bar) string ok", lang: "javascript", code: "console.log(\"foo (bar)\"); fs.openSync('/tmp/x','r')", want: false},
		{name: "fs.openSync r ok", lang: "javascript", code: "fs.openSync('/tmp/x','r')", want: false},
		{name: "fs.readFileSync ok", lang: "javascript", code: "fs.readFileSync('/tmp/x')", want: false},
		{name: "fs.readFile ok", lang: "javascript", code: "fs.readFile('/tmp/x',cb)", want: false},
		{name: "Deno.write", lang: "javascript", code: "Deno.writeTextFile('/tmp/x','a')", want: true},
		{name: "child_process spawn", lang: "javascript", code: "require('child_process').execSync('ls')", want: true},
		{name: "go language blocked", lang: "go", code: "package main\nfunc main(){}", want: true},
		{name: "rust language blocked", lang: "rust", code: "fn main(){}", want: true},
		{name: "csharp language blocked", lang: "csharp", code: "class A{}", want: true},
		{name: "file_put_contents", lang: "php", code: "file_put_contents('/tmp/x','a');", want: true},
		{name: "FileUtils ruby", lang: "ruby", code: "FileUtils.rm('/tmp/x')", want: true},
		{name: "perl unlink", lang: "perl", code: "unlink('/tmp/x');", want: true},
		{name: "ruby read only", lang: "ruby", code: "puts File.read('/tmp/x')", want: false},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			rule, _ := strict.guardCtxRunCode(tc.lang, tc.code)
			if (rule == ruleReadonlyWrite) != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule = %q, want blocked=%v", tc.code, rule, tc.want)
			}
		})
	}
}

// TestGuard_CodeStaticSpawns covers codeStaticSpawnsDetailed: alias/import
// binding resolution, dynamic-arg unresolution, module-root escapes, and
// shell-text command strings.
func TestGuard_CodeStaticSpawns(t *testing.T) {
	cases := []struct {
		name      string
		lang      string
		code      string
		wantArgvs int
		wantShell int
		wantAll   bool
	}{
		// Pure literal calls resolve and leave no unresolved site.
		{name: "alias run list", lang: "python",
			code:      "import subprocess as sp\nsp.run(['herdsman','status'])",
			wantArgvs: 1, wantAll: true},
		{name: "direct run list", lang: "python",
			code:      "import subprocess\nsubprocess.run(['herdr','pane','list'])",
			wantArgvs: 1, wantAll: true},
		{name: "from import alias", lang: "python",
			code:      "from subprocess import run as r\nr(['echo','ok'])",
			wantArgvs: 1, wantAll: true},
		{name: "from import paren multiline", lang: "python",
			code:      "from subprocess import (\n    run as r,\n    check_output as co,\n)\nr(['git','status'])\nco(['git','log'])",
			wantArgvs: 2, wantAll: true},
		{name: "plain import comma list", lang: "python",
			code:      "import subprocess, os as o\nsubprocess.run(['ls'])\no.system('ls')",
			wantArgvs: 2, wantAll: true},
		{name: "os.system plain words", lang: "python",
			code:      "import os\nos.system('ls -la')",
			wantArgvs: 1, wantAll: true},
		{name: "os.system shell text", lang: "python",
			code:      "import os\nos.system('cat f | grep x')",
			wantShell: 1, wantAll: true},
		{name: "js require member", lang: "javascript",
			code:      "const cp = require('child_process')\ncp.execFileSync('herdsman', ['status'])",
			wantArgvs: 1, wantAll: true},
		{name: "js require direct member", lang: "javascript",
			code:      "require('child_process').execSync('ls')",
			wantArgvs: 1, wantAll: true},
		{name: "js require shell text", lang: "javascript",
			code:      "const cp = require('child_process')\ncp.execSync('cat f | grep x')",
			wantShell: 1, wantAll: true},
		{name: "js destructure alias", lang: "javascript",
			code:      "const {execFileSync: run} = require('child_process')\nrun('git', ['log'])",
			wantArgvs: 1, wantAll: true},
		{name: "js es default import", lang: "javascript",
			code:      "import cp from 'child_process'\ncp.execSync('ls')",
			wantArgvs: 1, wantAll: true},
		{name: "js es named import", lang: "javascript",
			code:      "import {execSync as run} from 'child_process'\nrun('ls')",
			wantArgvs: 1, wantAll: true},
		{name: "js es namespace import", lang: "javascript",
			code:      "import * as cp from 'child_process'\ncp.execSync('ls')",
			wantArgvs: 1, wantAll: true},

		// Any unresolved site flips allResolved false.
		{name: "static then dynamic", lang: "python",
			code:      "import subprocess\nsubprocess.run(['echo','ok'])\nsubprocess.run(cmd)",
			wantArgvs: 1},
		{name: "alias static then dynamic", lang: "python",
			code:      "import subprocess as sp\nsp.run(['echo','ok'])\nsp.run(cmd)",
			wantArgvs: 1},
		{name: "dynamic only", lang: "python",
			code: "import subprocess\nsubprocess.run(f'echo {x}')"},
		{name: "getattr escape", lang: "python",
			code: "import subprocess\nf = getattr(subprocess, 'run')\nf(['echo','ok'])"},
		{name: "function ref escape", lang: "python",
			code: "import subprocess\nf = subprocess.run\nf(['echo','ok'])"},
		{name: "module passed around", lang: "python",
			code: "import subprocess\ng(subprocess)"},
		{name: "star import", lang: "python",
			code: "from subprocess import *\nrun(['ls'])"},
		{name: "js require dynamic", lang: "javascript",
			code: "const m = require(name)\nm.execSync('ls')"},
		{name: "js require expression escape", lang: "javascript",
			code:      "x(require('child_process'))\nexecSync('ls')",
			wantArgvs: 1},
		{name: "js member ref escape", lang: "javascript",
			code: "const cp = require('child_process')\nf = cp.execSync\nf('ls')"},
		{name: "js dynamic member call", lang: "javascript",
			code: "const cp = require('child_process')\ncp[f](['ls'])"},
		{name: "js dynamic import", lang: "javascript",
			code: "const m = await import('child_process')"},
		{name: "js member assign escape", lang: "javascript",
			code: "global.cp = require('child_process')\ncp.execSync('ls')"},
		// Regression (oracle-ctx-r2 C-review): `typeof require('child_process')`
		// and `x == require('child_process')` must NOT bind `typeof`/`x` into
		// names — jsScanRequire (role_guards.go) requires the token left of
		// require to be `=` and the token left of that to be an identifier, so
		// all three shapes fail closed via unresolved.
		{name: "js typeof require unresolved", lang: "javascript",
			code: "typeof require('child_process')"},
		{name: "js const typeof require unresolved", lang: "javascript",
			code: "const x = typeof require('child_process')"},
		{name: "js eq require unresolved", lang: "javascript",
			code: "x === require('child_process')"},
		{name: "unclosed call", lang: "python",
			code: "import subprocess\nsubprocess.run(["},

		// No spawn call resolved at all: allResolved=false — the caller
		// falls back to the co-occurrence screen (which stays silent for
		// these agent-name-free bodies).
		{name: "benign import only", lang: "python",
			code: "import json\nimport subprocess\nprint('hi')"},
		{name: "neutral bare word", lang: "python",
			code: "system = platform.system()\nprint(system)"},
		{name: "name in comment", lang: "python",
			code: "# import subprocess\nprint('hi')"},
		{name: "name in string", lang: "python",
			code: "s = 'unresolved(\"pig\")'\nprint(s)"},
		{name: "other require ok", lang: "javascript",
			code: "const fs = require('fs')\nfs.readFileSync('/etc/hostname')"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argvs, shells, all := codeStaticSpawnsDetailed(tc.lang, tc.code)
			if len(argvs) != tc.wantArgvs || len(shells) != tc.wantShell || all != tc.wantAll {
				t.Fatalf("codeStaticSpawnsDetailed(%q) = argvs=%v shells=%v allResolved=%v, want %d/%d/%v",
					tc.code, argvs, shells, all, tc.wantArgvs, tc.wantShell, tc.wantAll)
			}
		})
	}
}

// TestGuard_CtxRunCodeAliasAndFallback covers the sub-agent code screen's
// three-layer fix: import/require aliases reach the argv screen, a resolved
// call no longer short-circuits the fallback for an adjacent dynamic spawn,
// and the fallback blocks on bare herdr/herdsman presence.
func TestGuard_CtxRunCodeAliasAndFallback(t *testing.T) {
	sub := guardCall{subagent: true}

	cases := []struct {
		name        string
		lang        string
		code        string
		wantBlocked bool
		wantDetail  string // "" = no constraint on the detail text
	}{
		// Alias calls: static argv screening decides.
		{name: "alias daemon start blocked", lang: "python",
			code:        "import subprocess as sp\nsp.run(['herdsman','daemon','start'])",
			wantBlocked: true, wantDetail: "herdsman daemon start"},
		{name: "alias wake blocked", lang: "python",
			code:        "import subprocess as sp\nsp.run(['herdsman','wake'])",
			wantBlocked: true, wantDetail: "herdsman wake"},
		{name: "alias status ok", lang: "python",
			code: "import subprocess as sp\nsp.run(['herdsman','status'])"},
		{name: "alias herdr pane list ok", lang: "python",
			code: "import subprocess as sp\nsp.run(['herdr','pane','list'])"},
		{name: "alias herdr pane close blocked", lang: "python",
			code:        "import subprocess as sp\nsp.run(['herdr','pane','close','w1:p2'])",
			wantBlocked: true, wantDetail: "herdr pane close"},
		{name: "alias pig blocked", lang: "python",
			code:        "import subprocess as sp\nsp.run(['pig'])",
			wantBlocked: true, wantDetail: "pig"},
		{name: "from-import run pig blocked", lang: "python",
			code:        "from subprocess import run as r\nr(['pig'])",
			wantBlocked: true, wantDetail: "pig"},
		{name: "from-import run echo pig ok", lang: "python",
			code: "from subprocess import run as r\nr(['echo','pig'])"},

		// Partial parse must not short-circuit the dynamic fallback.
		{name: "static call + dynamic pig", lang: "python",
			code:        "import subprocess\nsubprocess.run(['echo','ok'])\nsubprocess.run(cmd)  # 'pig' lives in cmd",
			wantBlocked: true},
		{name: "static call + dynamic herdsman", lang: "python",
			code:        "import subprocess\nsubprocess.run(['echo','ok'])\nsubprocess.run('herdsman' + arg)",
			wantBlocked: true},
		{name: "alias static + dynamic pig", lang: "python",
			code:        "import subprocess as sp\nsp.run(['echo','ok'])\nsp.run(cmd)  # 'pig'",
			wantBlocked: true},

		// Reflection / assignment escapes fail closed on co-occurrence.
		{name: "getattr herdsman", lang: "python",
			code:        "import subprocess\nf = getattr(subprocess, 'run')\nf(['herdsman','daemon','start'])",
			wantBlocked: true},
		{name: "getattr herdsman clean stays free", lang: "python",
			code: "import subprocess\nf = getattr(subprocess, 'run')\nf(['echo','ok'])"},

		// JS require binding: alias member calls screen at argv position.
		{name: "js cp daemon start blocked", lang: "javascript",
			code:        "const cp = require('child_process')\ncp.execFileSync('herdsman', ['daemon','start'])",
			wantBlocked: true, wantDetail: "herdsman daemon start"},
		{name: "js cp status ok", lang: "javascript",
			code: "const cp = require('child_process')\ncp.execFileSync('herdsman', ['status'])"},
		{name: "js destructure pig blocked", lang: "javascript",
			code:        "const {execFileSync: run} = require('child_process')\nrun('pig', [])",
			wantBlocked: true, wantDetail: "pig"},
		{name: "js static + dynamic pig", lang: "javascript",
			code:        "const cp = require('child_process')\ncp.execSync('echo ok')\ncp.execSync(cmd) // 'pig'",
			wantBlocked: true},

		// Regression (oracle-ctx-r2): `typeof require('child_process')` /
		// `x === require('child_process')` leave the require site unresolved
		// instead of binding `typeof`/`x` into the spawn-alias map. Paired with
		// a dynamic spawn call the !allResolved co-occurrence fallback decides
		// the verdict: blocked on agent/herdr/herdsman names, free without
		// them. (The bare forms alone carry no spawn-primitive token — the
		// module literal is masked — so spawn detection stays off; their
		// unresolved status is locked in TestGuard_CodeStaticSpawns.)
		{name: "js typeof require + dynamic pig blocked", lang: "javascript",
			code:        "typeof require('child_process')\nrequire('child_process').execSync(cmd) // 'pig'",
			wantBlocked: true},
		{name: "js const typeof require + dynamic herdsman blocked", lang: "javascript",
			code:        "const x = typeof require('child_process')\nrequire('child_process').execSync(cmd) // 'herdsman'",
			wantBlocked: true},
		{name: "js eq require + dynamic herdr blocked", lang: "javascript",
			code:        "x === require('child_process')\nrequire('child_process').execSync(cmd) // herdr",
			wantBlocked: true},
		{name: "js typeof require benign ok", lang: "javascript",
			code: "typeof require('child_process')"},
		{name: "js eq require benign ok", lang: "javascript",
			code: "x === require('child_process')"},

		// Literal shell-form commands screen through the shell guard.
		{name: "os.system piped pig", lang: "python",
			code:        "import os\nos.system('cat f | pig')",
			wantBlocked: true},
		{name: "os.system piped herdsman status ok", lang: "python",
			code: "import os\nos.system('herdsman status')"},
		{name: "execSync piped pig", lang: "javascript",
			code:        "const cp = require('child_process')\ncp.execSync('cat f | pig')",
			wantBlocked: true},
		{name: "getoutput herdsman status ok", lang: "python",
			code: "from subprocess import getoutput\ngetoutput('herdsman status')"},
		{name: "getoutput herdsman daemon blocked", lang: "python",
			code:        "from subprocess import getoutput\ngetoutput('herdsman daemon start')",
			wantBlocked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, detail := sub.guardCtxRunCode(tc.lang, tc.code)
			if (rule == ruleSubagentNestedAgent) != tc.wantBlocked {
				t.Fatalf("guardCtxRunCode(%q) = rule %q detail %q, want blocked=%v",
					tc.code, rule, detail, tc.wantBlocked)
			}
			if tc.wantBlocked && tc.wantDetail != "" && detail != tc.wantDetail {
				t.Fatalf("guardCtxRunCode(%q) detail = %q, want %q", tc.code, detail, tc.wantDetail)
			}
		})
	}
}

// TestGuard_InterpreterInlineArgv covers inline -c/-e argv screening.
func TestGuard_InterpreterInlineArgv(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "python -c subprocess pig", argv: []string{"python3", "-c", "import subprocess; subprocess.run(['pig'])"}, want: "python inline code"},
		{name: "python -c os.system agy", argv: []string{"python3", "-c", "import os; os.system('agy')"}, want: "python inline code"},
		{name: "python -c harmless", argv: []string{"python3", "-c", "import json; print(1)"}, want: ""},
		{name: "python -u -c pig", argv: []string{"python3", "-u", "-c", "import os; os.system('pig')"}, want: "python inline code"},
		{name: "node -e execSync pig", argv: []string{"node", "-e", "require('child_process').execSync('pig')"}, want: "javascript inline code"},
		{name: "node -e harmless", argv: []string{"node", "-e", "console.log(1)"}, want: ""},
		{name: "node --eval pig", argv: []string{"node", "--eval", "execSync('pig')"}, want: "javascript inline code"},
		{name: "perl -e system pig", argv: []string{"perl", "-e", "system('pig')"}, want: "perl inline code"},
		{name: "php -r shell_exec pig", argv: []string{"php", "-r", "shell_exec('pig');"}, want: "php inline code"},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "python -c os.system", argv: []string{"python3", "-c", "import os; os.system('rm -f x')"}, want: "python inline code"},
		{name: "python -c open write", argv: []string{"python3", "-c", "open('/tmp/x','w').write('a')"}, want: "python inline code"},
		{name: "python -c read ok", argv: []string{"python3", "-c", "print(open('/etc/hostname').read())"}, want: "python program text"},
		{name: "python -c harmless", argv: []string{"python3", "-c", "import json; print(1)"}, want: "python program text"},
		{name: "python -m pip", argv: []string{"python3", "-m", "pip", "install", "x"}, want: "python -m pip"},
		{name: "python -m venv", argv: []string{"python3", "-m", "venv", "/tmp/v"}, want: "python -m venv"},
		{name: "python -m json.tool ok", argv: []string{"python3", "-m", "json.tool", "f.json"}, want: "deleted"},
		{name: "node -e writeFile", argv: []string{"node", "-e", "fs.writeFileSync('/tmp/x','a')"}, want: "javascript inline code"},
		{name: "node -e read ok", argv: []string{"node", "-e", "console.log(1)"}, want: "javascript program text"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// ---------- hardening: awk / curl / wget ----------

// TestGuard_AwkCurlWget covers the awk -i inplace, curl -o/-O, wget disk
// download rules.
func TestGuard_AwkCurlWget(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "awk plain", argv: []string{"awk", "{print $1}", "f"}, want: "awk program"},
		{name: "awk -i inplace", argv: []string{"gawk", "-i", "inplace", "{print}", "f"}, want: "awk -i inplace"},
		{name: "awk -i bare", argv: []string{"awk", "-i", "x"}, want: "awk -i"},
		{name: "awk --include inplace", argv: []string{"gawk", "--include", "inplace", "{print}", "f"}, want: "awk -i inplace"},
		{name: "curl -O", argv: []string{"curl", "-O", "https://x/f"}, want: "curl -O"},
		{name: "curl --remote-name", argv: []string{"curl", "--remote-name", "https://x"}, want: "curl --remote-name"},
		{name: "curl -o file", argv: []string{"curl", "-o", "/tmp/f", "https://x"}, want: "curl -o /tmp/f"},
		{name: "curl --output=file", argv: []string{"curl", "--output=/tmp/f", "https://x"}, want: "curl --output=/tmp/f"},
		{name: "curl -o - blocked", argv: []string{"curl", "-o", "-", "https://x"}, want: "curl"},
		{name: "curl -o /dev/null blocked", argv: []string{"curl", "-o", "/dev/null", "https://x"}, want: "curl"},
		{name: "curl plain ok", argv: []string{"curl", "-s", "https://x"}, want: "deleted"},
		{name: "wget default blocks", argv: []string{"wget", "https://x/f"}, want: "wget"},
		{name: "wget -O file", argv: []string{"wget", "-O", "/tmp/f", "https://x"}, want: "wget"},
		{name: "wget -O - ok", argv: []string{"wget", "-O", "-", "https://x"}, want: "unknown command wget"},
		{name: "wget -O /dev/null ok", argv: []string{"wget", "-O", "/dev/null", "https://x"}, want: "unknown command wget"},
		{name: "wget --spider ok", argv: []string{"wget", "--spider", "https://x"}, want: "unknown command wget"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// ---------- hardening: toolExecute / toolExecuteFile wiring ----------

// TestGuard_ToolExecuteCodeBlocked covers the non-shell language guard at the
// toolExecute entry: spawn primitives in python code block for a sub-agent,
// harmless code runs.
func TestGuard_ToolExecuteCodeBlocked(t *testing.T) {
	s, _ := auditTestServer(t)
	t.Setenv(auditEnvRole, "worker")

	_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:  "import subprocess\nsubprocess.run(['pig','--help'])",
		Language: "python",
	})
	if err == nil || !strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("expected nested-agent code block, got %v", err)
	}
}

// TestGuard_ToolExecuteCodeReadonlyBlocked covers strict read-only: a write
// primitive in python code blocks; the same code under a worker role is not
// stopped by the code guard.
func TestGuard_ToolExecuteCodeReadonlyBlocked(t *testing.T) {
	s, _ := auditTestServer(t)
	t.Setenv(auditEnvRole, "scout")

	_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:  "import os\nos.system('rm -rf /tmp/x')",
		Language: "python",
	})
	if err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("expected readonly code block, got %v", err)
	}
}

// TestGuard_ToolExecuteFileCodeGuarded covers execute_file: the guard must
// screen args.Code, NOT injectedCode (which embeds FILE_CONTENT). A target
// file whose contents contain guard-like tokens must not trip the guard.
func TestGuard_ToolExecuteFileCodeGuarded(t *testing.T) {
	wd := t.TempDir()
	target := filepath.Join(wd, "src.py")
	// File content that LOOKS like it spawns pig — it is data, not caller code.
	if err := os.WriteFile(target, []byte("import subprocess\nsubprocess.run(['pig'])\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := testServerWithWorkdir(t, wd)

	// Sub-agent: caller code is benign; FILE_CONTENT's own tokens must not
	// trip the guard (the call may fail later for other reasons, but never
	// with the guard error).
	t.Setenv(auditEnvRole, "worker")
	_, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     target,
		Language: "python",
		Code:     "print(len(FILE_CONTENT))",
	})
	if err != nil && strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("FILE_CONTENT must not trip the guard, got %v", err)
	}

	// Strict read-only: a write primitive in CALLER code must block even
	// though the file itself is innocuous.
	t.Setenv(auditEnvRole, "scout")
	_, _, err = s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     target,
		Language: "python",
		Code:     "open('/tmp/out','w').write(FILE_CONTENT)",
	})
	if err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("caller write code must be blocked, got %v", err)
	}
}

// TestGuard_VerifierKeepsExecButNotDispatch locks the verifier carve-out:
// verifier is read-only (KB writes, readonly_role_call tag) but NOT strict
// read-only — go test / rm -rf /tmp/... / git clone run — while nested agent
// dispatch still blocks it.
func TestGuard_VerifierKeepsExecButNotDispatch(t *testing.T) {
	t.Setenv(auditEnvRole, "verifier")
	t.Setenv(auditEnvReadonly, "")

	g := currentGuardCall()
	if !g.subagent || !g.readonly || g.strictReadonly {
		t.Fatalf("verifier guard = %+v, want subagent+readonly, not strict", g)
	}
	// The verifier exemption lives in classification (strictReadonly=false),
	// not in the write tables: go test / rm -rf / git clone remain BLOCKED by
	// screenReadonlyWrite itself, which is what a strict read-only role hits.
	for _, argv := range [][]string{
		{"go", "test", "./..."},
		{"rm", "-rf", "/tmp/clone"},
		{"git", "clone", "u", "/tmp/x"},
	} {
		if got := screenReadonlyWrite(argv); got == "" {
			t.Fatalf("screenReadonlyWrite(%v) must still flag the write for strict roles", argv)
		}
	}
	// …but the same argv under verifier never reaches it: the guard's own
	// strictReadonly check is what keeps these commands running.
	if got := guardArgvSubagent([]string{"pig"}); got == "" {
		t.Fatalf("verifier must still be blocked from nested dispatch")
	}
}

// TestGuard_StrictReadonlyClassification pins the role → guard mapping.
func TestGuard_StrictReadonlyClassification(t *testing.T) {
	cases := []struct {
		role     string
		readonly string
		subagent bool
		ro       bool
		strict   bool
	}{
		{"", "", false, false, false},
		{"worker", "", true, false, false},
		{"reviewer", "", true, true, true},
		{"verifier", "", true, true, false},
		{"worker", "1", true, true, true},
		{"", "1", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.role+"/"+tc.readonly, func(t *testing.T) {
			t.Setenv(auditEnvRole, tc.role)
			t.Setenv(auditEnvReadonly, tc.readonly)
			g := currentGuardCall()
			if g.subagent != tc.subagent || g.readonly != tc.ro || g.strictReadonly != tc.strict {
				t.Fatalf("guard = %+v, want subagent=%v readonly=%v strict=%v",
					g, tc.subagent, tc.ro, tc.strict)
			}
		})
	}
}

// TestGuard_ToolExecuteArgvBlocked locks the wiring: a sub-agent calling
// ctx_run action=execute argv with a blocked head gets a caller error and the
// audit line records rule + block verdict.
func TestGuard_ToolExecuteArgvBlocked(t *testing.T) {
	s, logPath := auditTestServer(t)
	t.Setenv(auditEnvRole, "worker")

	_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv: []string{"pig", "--help"},
	})
	if err == nil || !strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("expected nested-dispatch block, got %v", err)
	}
	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	if len(recs) != 1 {
		t.Fatalf("expected one audit line, got %d", len(recs))
	}
	rec := recs[0]
	if rec.ScreenVerdict != "block" || rec.ScreenRule != ruleSubagentNestedAgent {
		t.Fatalf("screen = %q/%q, want block/%s", rec.ScreenVerdict, rec.ScreenRule, ruleSubagentNestedAgent)
	}
	if rec.ExitCode != auditExitNotRun || rec.Error == "" {
		t.Fatalf("exit/error = %d/%q, want -1 + error", rec.ExitCode, rec.Error)
	}
}

// TestGuard_ToolExecuteShellBlocked covers the command-string path.
func TestGuard_ToolExecuteShellBlocked(t *testing.T) {
	s, _ := auditTestServer(t)
	t.Setenv(auditEnvRole, "worker")

	_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command: "ls && sh -c 'agy'",
	})
	if err == nil || !strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("expected nested-dispatch block, got %v", err)
	}
}

// TestGuard_BatchPerCommandBlocked covers batch: a blocked command fails its
// own slot (rule recorded per command) without stopping siblings. The sibling
// prints a string built by the SHELL (printf '%s_%s'), not present verbatim in
// the Command field — proving the sibling actually ran. Checked under both
// serial and concurrent execution.
func TestGuard_BatchPerCommandBlocked(t *testing.T) {
	s, logPath := auditTestServer(t)
	t.Setenv(auditEnvRole, "worker")

	for _, conc := range []int{1, 2} {
		res, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
			Concurrency: conc,
			Commands: []batchCommand{
				{Label: "blocked", Command: "pig run"},
				{Label: "ok", Command: "printf '%s_%s\n' BATCH SIBLING"},
			},
		})
		if err != nil {
			t.Fatalf("toolBatchExecute(conc=%d): %v", conc, err)
		}
		text := mcpResultText(t, res)
		if !strings.Contains(text, ruleSubagentNestedAgent) {
			t.Fatalf("batch result must carry the guard error, got %s", text)
		}
		if !strings.Contains(text, `"exit_code": 0`) {
			t.Fatalf("sibling must have run (exit_code 0), got %s", text)
		}
		// "BATCH_SIBLING\n" is 14 bytes of real stdout — proves the sibling
		// actually executed rather than being stubbed to exit 0.
		if !strings.Contains(text, `"size": 14`) {
			t.Fatalf("sibling must have produced 14 bytes of output, got %s", text)
		}
	}
	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	rec := recs[0]
	if rec.ScreenVerdict != "block" || rec.ScreenRule != ruleSubagentNestedAgent {
		t.Fatalf("call screen = %q/%q", rec.ScreenVerdict, rec.ScreenRule)
	}
	if rec.Commands[0].ScreenRule != ruleSubagentNestedAgent || rec.Commands[0].ExitCode != -1 {
		t.Fatalf("commands[0] = %+v", rec.Commands[0])
	}
	if rec.Commands[1].ExitCode != 0 {
		t.Fatalf("commands[1] exit = %d, want 0 (sibling must run)", rec.Commands[1].ExitCode)
	}
}

// TestGuard_ReadonlyShellWriteBlocked covers a strict read-only role being
// refused a write command through ctx_run.
func TestGuard_ReadonlyShellWriteBlocked(t *testing.T) {
	s, _ := auditTestServer(t)
	t.Setenv(auditEnvRole, "scout")

	_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command: "echo x > /tmp/guard-out",
	})
	if err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("expected readonly write block, got %v", err)
	}
}

// TestGuard_RunTaskBlockedStrictReadonly and allowed for verifier.
func TestGuard_RunTaskBlockedStrictReadonly(t *testing.T) {
	s, _ := auditTestServer(t)
	t.Setenv(auditEnvRole, "oracle")
	_, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{Kind: "go_test"})
	if err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("expected run_task block, got %v", err)
	}

	t.Setenv(auditEnvRole, "verifier")
	_, _, err = s.toolRunTask(context.Background(), nil, runTaskArgs{Kind: "custom", Args: []string{"pig"}})
	if err == nil || !strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("verifier run_task custom pig must be nested-blocked, got %v", err)
	}
}

// TestGuard_CtxKbReadonlyBlocked covers ctx_kb index/purge for all read-only
// roles (verifier included), while fetch/search/stats/doctor stay open.
func TestGuard_CtxKbReadonlyBlocked(t *testing.T) {
	s := testServerWithWorkdir(t, t.TempDir())
	t.Setenv(auditEnvReadonly, "")

	for _, role := range []string{"reviewer", "verifier"} {
		t.Setenv(auditEnvRole, role)
		if _, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "index", Path: "x"}); err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
			t.Fatalf("role %s: index must be blocked, got %v", role, err)
		}
		if _, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "purge", Scope: "session", SessionID: "x"}); err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
			t.Fatalf("role %s: purge must be blocked, got %v", role, err)
		}
	}

	// A worker (sub-agent, not read-only) keeps KB writes: the guard must not
	// fire (the call may still fail downstream on a missing store, which is
	// not the guard's error).
	t.Setenv(auditEnvRole, "worker")
	if _, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "purge", Scope: "session", SessionID: "x"}); err != nil && strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("worker must keep ctx_kb purge, got %v", err)
	}
	// fetch is the researcher tool-cache exception: it stays open for the
	// researcher role only; every other read-only role (incl. bare
	// CTXMODE_READONLY=1) is refused because fetch writes into the shared KB.
	t.Setenv(auditEnvRole, "researcher")
	_, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "fetch"})
	if err != nil && strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("researcher ctx_kb fetch must stay open, got %v", err)
	}
	for _, role := range []string{"scout", "planner", "reviewer", "oracle", "verifier"} {
		t.Setenv(auditEnvRole, role)
		if _, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "fetch"}); err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
			t.Fatalf("role %s: ctx_kb fetch must be blocked, got %v", role, err)
		}
	}
	// Bare CTXMODE_READONLY=1 (no named role) is also refused fetch.
	t.Setenv(auditEnvRole, "")
	t.Setenv(auditEnvReadonly, "1")
	if _, _, err := s.toolCtxKb(context.Background(), nil, ctxKbArgs{Action: "fetch"}); err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("anonymous readonly caller: ctx_kb fetch must be blocked, got %v", err)
	}
}

// TestGuard_CtxBgKillBlockedStrictReadonly covers ctx_bg kill.
func TestGuard_CtxBgKillBlockedStrictReadonly(t *testing.T) {
	s := testServerWithWorkdir(t, t.TempDir())
	t.Setenv(auditEnvReadonly, "")
	t.Setenv(auditEnvRole, "researcher")
	if _, _, err := s.toolCtxBg(context.Background(), nil, ctxBgArgs{Action: "kill", ID: "bg-1"}); err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("researcher ctx_bg kill must be blocked, got %v", err)
	}
	t.Setenv(auditEnvRole, "verifier")
	if _, _, err := s.toolCtxBg(context.Background(), nil, ctxBgArgs{Action: "kill", ID: "bg-none"}); err == nil || strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("verifier ctx_bg kill must stay allowed, got %v", err)
	}
}

// ---------- hardening round 2: sessions/escalation execs, keywords, env hooks ----------

// TestGuard_SessionAndEscalationExecs covers the blocked session managers
// (tmux/screen) and privilege/namespace/scheduler/remote wrappers.
func TestGuard_SessionAndEscalationExecs(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "tmux new-session", argv: []string{"tmux", "new-session", "pig"}, want: "tmux"},
		{name: "screen -dm", argv: []string{"screen", "-dmS", "s", "pig"}, want: "screen"},
		{name: "tmux env wrapper", argv: []string{"env", "PATH=/usr/bin", "tmux"}, want: "tmux"},
		{name: "sudo pig", argv: []string{"sudo", "pig"}, want: "sudo"},
		{name: "doas agy", argv: []string{"doas", "agy"}, want: "doas"},
		{name: "su root", argv: []string{"su", "-", "root"}, want: "su"},
		{name: "pkexec", argv: []string{"pkexec", "ls"}, want: "pkexec"},
		{name: "nsenter", argv: []string{"nsenter", "-t", "1", "-m", "pig"}, want: "nsenter"},
		{name: "unshare", argv: []string{"unshare", "-n", "pig"}, want: "unshare"},
		{name: "chroot", argv: []string{"chroot", "/", "pig"}, want: "chroot"},
		{name: "systemd-run", argv: []string{"systemd-run", "pig"}, want: "systemd-run"},
		{name: "crontab -e", argv: []string{"crontab", "-e"}, want: "crontab"},
		{name: "at now", argv: []string{"at", "now"}, want: "at"},
		{name: "ssh remote dispatch", argv: []string{"ssh", "host", "pig"}, want: "pig"},
		{name: "ssh bare host", argv: []string{"ssh", "host"}, want: "ssh"},
		// echo ssh is an argument, not a head
		{name: "echo ssh", argv: []string{"echo", "ssh"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_SSHPeel covers the ssh transparent-peel model: the option run
// is parsed with OpenSSH syntax, dangerous options and -o exec/forwarding
// keys block, a bare interactive `ssh host` blocks, and the remote command
// inherits the caller's own guard — nested dispatch for every sub-agent,
// strict read-only writes for all six read-only roles (verifier's /tmp
// exemption stops at the wire).
func TestGuard_SSHPeel(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	sub := []struct {
		name string
		code string
		want string // "" = allowed, hit names the detail
	}{
		// Bare / interactive and malformed invocations.
		{name: "bare host", code: "ssh dmit", want: "ssh"},
		{name: "flags only", code: "ssh -v", want: "ssh"},
		{name: "missing -p value", code: "ssh -p", want: "ssh"},
		{name: "unknown option", code: "ssh -Z dmit uptime", want: "ssh -Z"},
		// Banned option letters: config file, control socket, forwarding,
		// no-command/local-side-effect modes.
		{name: "-F config", code: "ssh -F /tmp/cfg dmit uptime", want: "ssh -F"},
		{name: "-S socket", code: "ssh -S /tmp/s dmit uptime", want: "ssh -S"},
		{name: "-O check", code: "ssh -O check dmit uptime", want: "ssh -O"},
		{name: "-L forward", code: "ssh -L 8080:localhost:80 dmit uptime", want: "ssh -L"},
		{name: "-R forward", code: "ssh -R 9090:localhost:9 dmit uptime", want: "ssh -R"},
		{name: "-D socks", code: "ssh -D 1080 dmit uptime", want: "ssh -D"},
		{name: "-W tunnel", code: "ssh -W host:22 dmit uptime", want: "ssh -W"},
		{name: "-J jump", code: "ssh -J bastion dmit uptime", want: "ssh -J"},
		{name: "-N no-cmd", code: "ssh -N dmit uptime", want: "ssh -N"},
		{name: "-f bg cluster", code: "ssh -qf dmit uptime", want: "ssh -f"},
		{name: "-G config dump", code: "ssh -G dmit", want: "ssh -G"},
		{name: "-E logfile", code: "ssh -E /tmp/log dmit uptime", want: "ssh -E"},
		{name: "-I pkcs11", code: "ssh -I /tmp/x.so dmit uptime", want: "ssh -I"},
		// -o screening: exec/forward/config keys refuse by name; the
		// connection-hygiene whitelist stays free in every spelling.
		{name: "proxycommand", code: "ssh -o ProxyCommand=/tmp/x dmit uptime", want: "ssh -o proxycommand"},
		{name: "proxyjump", code: "ssh -o ProxyJump=bastion dmit uptime", want: "ssh -o proxyjump"},
		{name: "localcommand", code: "ssh -o 'LocalCommand /tmp/x' dmit uptime", want: "ssh -o localcommand"},
		{name: "remotecommand", code: "ssh -o RemoteCommand=bash dmit uptime", want: "ssh -o remotecommand"},
		{name: "match block", code: "ssh -o 'Match host x exec rm' dmit uptime", want: "ssh -o match"},
		{name: "include file", code: "ssh -o Include=/tmp/cfg dmit uptime", want: "ssh -o include"},
		{name: "controlmaster yes", code: "ssh -o ControlMaster=yes dmit uptime", want: "ssh -o controlmaster"},
		{name: "controlpath sock", code: "ssh -o ControlPath=/tmp/s dmit uptime", want: "ssh -o controlpath"},
		{name: "knownhosts path write", code: "ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/kh dmit uptime", want: "ssh -o userknownhostsfile"},
		{name: "globalknownhosts path", code: "ssh -o GlobalKnownHostsFile=/etc/kh dmit uptime", want: "ssh -o globalknownhostsfile"},
		{name: "knownhosts /dev/null ok", code: "ssh -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=none dmit uptime", want: ""},
		{name: "escape cmdline yes", code: "ssh -o EnableEscapeCommandLine=yes dmit uptime", want: "ssh -o enableescapecommandline"},
		{name: "escape cmdline no ok", code: "ssh -o EnableEscapeCommandLine=no dmit uptime", want: ""},
		{name: "unknown long flag", code: "ssh --unknown-flag dmit uptime", want: "ssh --unknown-flag"},
		{name: "unknown long flag=val", code: "ssh --forward-all=yes dmit uptime", want: "ssh --forward-all=yes"},
		{name: "--help long fails closed", code: "ssh --help dmit uptime", want: "ssh --help"},
		{name: "safe -o separate", code: "ssh -o BatchMode=yes -o ConnectTimeout=5 dmit uptime", want: ""},
		{name: "safe -o glued", code: "ssh -oBatchMode=yes -o 'StrictHostKeyChecking no' dmit uptime", want: ""},
		{name: "controlmaster=no ok", code: "ssh -o ControlMaster=no -o ControlPath=none dmit uptime", want: ""},
		// Post-<destination> options: without `--`, OpenSSH re-enters getopt
		// after <destination>, so trailing options are still ssh's own —
		// screened here — and the remote command starts at the SECOND
		// non-option word. NBSP is not ASCII blank for readconf.c: a
		// `none ` value is a real local filename, never the none sink.
		{name: "post-dest -q remote pig", code: "ssh dmit -q pig", want: "pig"},
		{name: "post-dest -o proxycommand", code: "ssh dmit -o ProxyCommand=/tmp/x uptime", want: "ssh -o proxycommand"},
		{name: "knownhosts nbsp value", code: "ssh -o 'UserKnownHostsFile=none\u00a0' dmit uptime", want: "ssh -o userknownhostsfile"},
		// Option parsing shapes: clusters, glued and separate values, --.
		{name: "cluster -qT", code: "ssh -qT dmit uptime", want: ""},
		{name: "-tt -vvv", code: "ssh -tt -vvv dmit uptime", want: ""},
		{name: "-p separate", code: "ssh -p 2222 dmit uptime", want: ""},
		{name: "-p glued", code: "ssh -p2222 dmit uptime", want: ""},
		{name: "-i glued", code: "ssh -i/root/.ssh/k dmit uptime", want: ""},
		{name: "-l user", code: "ssh -l root dmit uptime", want: ""},
		{name: "dashdash", code: "ssh -- dmit uptime", want: ""},
		{name: "host not option val", code: "ssh -p 2222 -o BatchMode=yes dmit id", want: ""},
		// Remote command inherits the caller guard: nested dispatch still
		// blocks through the wire, multi-statement and nested-ssh forms too.
		{name: "remote pig", code: "ssh dmit pig", want: "pig"},
		{name: "remote pig compound", code: "ssh dmit 'cd /root && pig run'", want: "pig"},
		{name: "remote herdr write", code: "ssh dmit 'cd /root && herdr tab create'", want: "herdr tab create"},
		{name: "remote tmux", code: "ssh dmit 'tmux new-session pig'", want: "tmux"},
		{name: "remote pipe", code: "ssh dmit 'cat f | agy'", want: "agy"},
		{name: "nested ssh", code: "ssh hop 'ssh dmit uptime'", want: ""},
		{name: "nested ssh pig", code: "ssh hop 'ssh dmit pig'", want: "pig"},
		{name: "nested ssh bare", code: "ssh hop 'ssh dmit'", want: "ssh"},
		// Legit remote read/write/deploy commands stay free for worker.
		{name: "deploy pull", code: `ssh -o BatchMode=yes dmit "git -C /root/wechatbridge pull --ff-only && bash deploy/update.sh"`, want: ""},
		{name: "systemctl restart", code: `ssh -o BatchMode=yes dmit systemctl restart wechatbridge@default.service`, want: ""},
		{name: "remote rm ok for worker", code: `ssh dmit "rm -f /tmp/x"`, want: ""},
		// Piped/heredoc stdin reaching a remote program reader: the
		// here-string and heredoc bodies are screened as shell code; a
		// pipe's bytes are not visible here so it fails closed.
		{name: "piped pig", code: "echo pig | ssh dmit sh", want: "piped stdin to ssh"},
		{name: "piped data ok", code: "cat list | ssh dmit 'xargs touch'", want: ""},
		{name: "heredoc pig", code: "ssh dmit sh <<'EOF'\npig\nEOF", want: "pig"},
		{name: "herestring pig", code: "ssh dmit sh <<< 'pig'", want: "pig"},
	}
	for _, tc := range sub {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardShellSubagent(tc.code)
			if got != tc.want {
				t.Fatalf("guardShellSubagent(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}

	// Read-only roles: a remote read probe is fine, any remote write
	// blocks as readonly_write_blocked — verifier included.
	for _, role := range []string{"scout", "reviewer", "oracle", "verifier"} {
		t.Run("ro/"+role, func(t *testing.T) {
			t.Setenv(auditEnvRole, role)
			g := currentGuardCall()
			if rule, _ := g.guardCtxRunShell(`ssh dmit "git -C /root/wechatbridge status && systemctl is-active wechatbridge@default"`); rule != "" {
				t.Fatalf("%s: remote read probe must pass, got %q", role, rule)
			}
			for _, code := range []string{
				`ssh dmit "rm -rf /tmp/x"`,
				`ssh dmit -q rm -rf /tmp/x`, // post-dest option is ssh's; rm is the remote cmd
				`ssh dmit "git -C /root/wechatbridge pull"`,
				`ssh dmit "echo a > /tmp/b"`,
				`ssh dmit "systemctl restart wechatbridge@default"`,
			} {
				if rule, _ := g.guardCtxRunShell(code); rule != ruleReadonlyWrite {
					t.Fatalf("%s: %q rule = %q, want %s", role, code, rule, ruleReadonlyWrite)
				}
			}
			// Remote nested dispatch still reports the sub-agent rule.
			if rule, _ := g.guardCtxRunShell(`ssh dmit pig`); rule != ruleSubagentNestedAgent {
				t.Fatalf("%s: remote pig rule = %q, want %s", role, rule, ruleSubagentNestedAgent)
			}
			// Stdin reaching a remote program reader is unscreenable code
			// for a read-only role and blocks — a remote `sh`/`python3`
			// reading its program from the pipe/heredoc/here-string is the
			// same verdict the local stdin-program model gives.
			for _, code := range []string{
				`echo uptime | ssh dmit sh`,
				"ssh dmit sh <<'EOF'\nls -la /tmp\nEOF",
				"ssh dmit sh <<< 'ls -la /tmp'",
			} {
				if rule, _ := g.guardCtxRunShell(code); rule != ruleReadonlyWrite {
					t.Fatalf("%s: %q rule = %q, want %s", role, code, rule, ruleReadonlyWrite)
				}
			}
			// A read-only command receiving a heredoc as DATA (remote cat)
			// stays free.
			if rule, _ := g.guardCtxRunShell("ssh dmit cat <<'EOF'\nls -la /tmp\nEOF"); rule != "" {
				t.Fatalf("%s: data heredoc must pass, got %q", role, rule)
			}
			// A remote command mixing a write with a nested dispatch reports
			// the dispatch first (sub-agent before strict read-only).
			if rule, _ := g.guardCtxRunShell(`ssh dmit "rm -rf /tmp/x && pig"`); rule != ruleSubagentNestedAgent {
				t.Fatalf("%s: remote write+pig rule = %q, want %s", role, rule, ruleSubagentNestedAgent)
			}
		})
	}

	// ctx_run stdin payloads forwarded through ssh to a remote program
	// reader are remote code: a worker's nested dispatch still blocks, and
	// a verifier's /tmp exemption ends at the wire (strict screen applies
	// to both shell and remote-interpreter payloads).
	t.Setenv(auditEnvRole, "worker")
	g := currentGuardCall()
	if rule, _ := g.guardCtxRunStdin([]string{"ssh", "dmit", "sh"}, "pig"); rule != ruleSubagentNestedAgent {
		t.Fatalf("worker ssh-stdin pig rule = %q, want %s", rule, ruleSubagentNestedAgent)
	}
	if rule, _ := g.guardCtxRunStdinForCommand("ssh dmit sh", "pig"); rule != ruleSubagentNestedAgent {
		t.Fatalf("worker ssh-stdin pig (command) rule = %q, want %s", rule, ruleSubagentNestedAgent)
	}
	if rule, _ := g.guardCtxRunStdin([]string{"ssh", "dmit", "cat"}, "pig"); rule != "" {
		t.Fatalf("ssh-stdin data head must pass, got %q", rule)
	}
	t.Setenv(auditEnvRole, "verifier")
	g = currentGuardCall()
	for _, stdin := range []string{"rm -rf /tmp/x", "pig"} {
		if rule, _ := g.guardCtxRunStdin([]string{"ssh", "dmit", "sh"}, stdin); rule != ruleReadonlyWrite && rule != ruleSubagentNestedAgent {
			t.Fatalf("verifier ssh-stdin %q rule = %q, want a block", stdin, rule)
		}
	}
	if rule, _ := g.guardCtxRunStdin([]string{"ssh", "dmit", "sh"}, "rm -rf /tmp/x"); rule != ruleReadonlyWrite {
		t.Fatalf("verifier ssh-stdin rm rule = %q, want %s", rule, ruleReadonlyWrite)
	}
	if rule, _ := g.guardCtxRunStdinForCommand("ssh dmit sh", "rm -rf /tmp/x"); rule != ruleReadonlyWrite {
		t.Fatalf("verifier ssh-stdin rm (command) rule = %q, want %s", rule, ruleReadonlyWrite)
	}
	if rule, _ := g.guardCtxRunStdin([]string{"ssh", "dmit", "python3", "-"}, "import os; os.remove('/tmp/x')"); rule != ruleReadonlyWrite {
		t.Fatalf("verifier ssh-stdin python rule = %q, want %s", rule, ruleReadonlyWrite)
	}
}

// TestGuard_CompoundKeywords covers shell reserved words and modifier
// keywords being peeled to the real command head.
func TestGuard_CompoundKeywords(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		code string
		want string
	}{
		{name: "if/then/fi", code: "if true; then pig; fi", want: "pig"},
		{name: "brace group", code: "{ pig; }", want: "pig"},
		{name: "negation", code: "! pig", want: "pig"},
		{name: "time", code: "time pig", want: "pig"},
		{name: "time -p", code: "time -p pig", want: "pig"},
		{name: "while loop", code: "while true; do agy; done", want: "agy"},
		{name: "until loop", code: "until false; do pi; done", want: "pi"},
		{name: "elif chain", code: "if a; then b; elif c; then grok; fi", want: "grok"},
		{name: "coproc", code: "coproc pig", want: "pig"},
		{name: "fi done } bare no-op", code: "fi; done; }", want: depthExceededHit},
		{name: "echo safe", code: "if true; then echo pig; fi", want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardShellSubagent(tc.code)
			if got != tc.want {
				t.Fatalf("guardShellSubagent(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		code string
		want string
	}{
		{name: "if rm", code: "if true; then rm -f x; fi", want: "rm"},
		{name: "{ rm }", code: "{ rm foo; }", want: "rm"},
		{name: "! rm", code: "! rm foo", want: "rm"},
		{name: "time -p pig-free", code: "time -p ls", want: "deleted"},
		{name: "while rm", code: "while read x; do rm \"$x\"; done <f", want: "rm"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardShellReadonly(tc.code)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardShellReadonly(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

// TestGuard_ExecHookEnvVars covers KEY=VAL / env -u execution-hook env
// screening for both guard kinds plus the CTXMODE_ROLE/READONLY taint.
// The taint simulation reads the REAL process env (currentCallerIdentity),
// so this test sets the caller role to worker before asserting.
func TestGuard_ExecHookEnvVars(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	sub := guardCall{subagent: true}
	strict := guardCall{strictReadonly: true}

	blocked := []struct {
		name string
		argv []string
	}{
		{"GIT_PAGER shell", []string{"git", "-c", "core.pager=less", "log"}},
	}
	_ = blocked // placeholder; cases below go through the argv guards directly

	subCases := []struct {
		name string
		argv []string
		want string // "" = allowed
	}{
		{name: "GIT_PAGER=less git", argv: []string{"env", "GIT_PAGER=less", "git", "log"}, want: "env GIT_PAGER"},
		{name: "PAGER=less git", argv: []string{"env", "PAGER=less", "git", "log"}, want: "env PAGER"},
		{name: "EDITOR=vi", argv: []string{"env", "EDITOR=vi", "git", "commit"}, want: "env EDITOR"},
		{name: "LD_PRELOAD", argv: []string{"env", "LD_PRELOAD=/tmp/x.so", "ls"}, want: "env LD_PRELOAD"},
		{name: "BASH_ENV", argv: []string{"env", "BASH_ENV=/tmp/x.sh", "bash", "-c", "ls"}, want: "env BASH_ENV"},
		{name: "NODE_OPTIONS", argv: []string{"env", "NODE_OPTIONS=--inspect", "node", "-e", "1"}, want: "env NODE_OPTIONS"},
		{name: "CTXMODE_ROLE clear", argv: []string{"env", "CTXMODE_ROLE=", "pig"}, want: "env CTXMODE_ROLE"},
		{name: "CTXMODE_READONLY clear falls to head", argv: []string{"env", "CTXMODE_READONLY=", "pig"}, want: "pig"},
		{name: "env -u CTXMODE_ROLE", argv: []string{"env", "-u", "CTXMODE_ROLE", "pig"}, want: "env CTXMODE_ROLE"},
		{name: "env --unset=CTXMODE_READONLY falls to head", argv: []string{"env", "--unset=CTXMODE_READONLY", "pig"}, want: "pig"},
		{name: "GIT_SSH_COMMAND", argv: []string{"env", "GIT_SSH_COMMAND=/tmp/x", "git", "fetch"}, want: "env GIT_SSH_COMMAND"},
		{name: "GIT_ASKPASS", argv: []string{"env", "GIT_ASKPASS=/tmp/x", "git", "push"}, want: "env GIT_ASKPASS"},
		{name: "PYTHONSTARTUP", argv: []string{"env", "PYTHONSTARTUP=/tmp/x.py", "python3", "-c", "1"}, want: "env PYTHONSTARTUP"},
		{name: "PERL5OPT", argv: []string{"env", "PERL5OPT=-Mtmp", "perl", "-e", "1"}, want: "env PERL5OPT"},
		{name: "PROMPT_COMMAND", argv: []string{"env", "PROMPT_COMMAND=pig", "bash", "-i"}, want: "env PROMPT_COMMAND"},

		// Pager disabling stays free.
		{name: "GIT_PAGER=cat", argv: []string{"env", "GIT_PAGER=cat", "git", "log"}, want: ""},
		{name: "GIT_PAGER=", argv: []string{"env", "GIT_PAGER=", "git", "log"}, want: ""},
		{name: "PAGER=cat", argv: []string{"env", "PAGER=cat", "man", "ls"}, want: ""},
		// Ordinary dev env vars pass.
		{name: "GOOS=linux", argv: []string{"env", "GOOS=linux", "go", "build"}, want: ""},
		{name: "CGO_ENABLED=0", argv: []string{"env", "CGO_ENABLED=0", "go", "test"}, want: ""},
		{name: "TZ=UTC", argv: []string{"env", "TZ=UTC", "date"}, want: ""},
		{name: "LC_ALL=C", argv: []string{"env", "LC_ALL=C", "grep", "x"}, want: ""},
		{name: "TMPDIR", argv: []string{"env", "TMPDIR=/tmp", "ls"}, want: ""},
		{name: "PATH custom", argv: []string{"env", "PATH=/usr/bin", "ls"}, want: ""},
		// Inline prefix form (no env wrapper) is also screened.
		{name: "inline GIT_PAGER", argv: []string{"GIT_PAGER=less", "git", "log"}, want: "env GIT_PAGER"},
		{name: "inline GOOS ok", argv: []string{"GOOS=linux", "go", "build"}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
	// The same env-hook screen applies under strict read-only (via guardCall
	// methods directly to avoid env side effects on parallel siblings).
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"strict GIT_PAGER", []string{"env", "GIT_PAGER=less", "git", "log"}, "not in readonly allowlist: env"},
		{"strict EDITOR", []string{"env", "EDITOR=vi", "ls"}, "not in readonly allowlist: env"},
		{"strict GOOS ok", []string{"env", "GOOS=linux", "go", "version"}, "not in readonly allowlist: env"},
	} {
		t.Run("strict/"+tc.name, func(t *testing.T) {
			got := func() string {
				if r, d := strict.guardCtxRunArgv(tc.argv); r != "" {
					return d
				}
				return ""
			}()
			if got != tc.want {
				t.Fatalf("strict guardCtxRunArgv(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
	_ = sub
}

// TestGuard_SchedulerWrappers covers ionice/taskset/chrt/watch/flock/script
// wrapper peeling and the flock/script strict-readonly head block.
func TestGuard_SchedulerWrappers(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "ionice pig", argv: []string{"ionice", "-c", "2", "pig"}, want: "pig"},
		{name: "ionice -n glued", argv: []string{"ionice", "-n7", "agy"}, want: "agy"},
		{name: "taskset mask pig", argv: []string{"taskset", "0x1", "pig"}, want: "pig"},
		{name: "taskset -c list", argv: []string{"taskset", "-c", "0-3", "pi"}, want: "pi"},
		{name: "taskset -p pid ok", argv: []string{"taskset", "-p", "1234"}, want: ""},
		{name: "chrt prio pig", argv: []string{"chrt", "-f", "10", "grok"}, want: "grok"},
		{name: "watch pig", argv: []string{"watch", "-n", "5", "pig"}, want: "pig"},
		{name: "watch bare pig", argv: []string{"watch", "pig"}, want: "pig"},
		{name: "flock file pig", argv: []string{"flock", "/tmp/l", "pig"}, want: "pig"},
		{name: "flock -w opts pig", argv: []string{"flock", "-w", "5", "/tmp/l", "agy"}, want: "agy"},
		{name: "script -c pig", argv: []string{"script", "-c", "pig run", "/tmp/t"}, want: "pig"},
		{name: "script -c glued", argv: []string{"script", "-cpig", "/tmp/t"}, want: "pig"},
		{name: "script --command=", argv: []string{"script", "--command=pi", "/tmp/t"}, want: "pi"},
		{name: "ionice ls ok", argv: []string{"ionice", "-c", "3", "ls"}, want: ""},
		{name: "watch ls ok", argv: []string{"watch", "ls"}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "flock blocks outright", argv: []string{"flock", "/tmp/l", "ls"}, want: "flock"},
		{name: "script blocks outright", argv: []string{"script", "/tmp/t"}, want: "script"},
		{name: "script -c blocks outright", argv: []string{"script", "-c", "ls", "/tmp/t"}, want: "script"},
		{name: "ionice ls ok", argv: []string{"ionice", "-c", "3", "ls"}, want: "deleted"},
		{name: "taskset ls ok", argv: []string{"taskset", "0x1", "ls"}, want: "deleted"},
		{name: "watch ls ok", argv: []string{"watch", "ls"}, want: "deleted"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_TrapSourceUnset covers trap action screening, `.`/`source`
// strict block + worker passthrough, and unset of guard taint vars.
func TestGuard_TrapSourceUnset(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		code string
		want string
	}{
		{name: "trap pig EXIT", code: "trap 'pig' EXIT", want: "pig"},
		{name: "trap agy INT", code: "trap 'agy run' INT", want: "agy"},
		{name: "trap -l ok", code: "trap -l", want: ""},
		{name: "trap -p ok", code: "trap -p", want: ""},
		{name: "trap signal-only ok", code: "trap EXIT", want: ""},
		{name: "trap - reset ok", code: "trap - INT", want: ""},
		{name: "unset CTXMODE_ROLE", code: "unset CTXMODE_ROLE", want: "unset CTXMODE_ROLE"},
		{name: "unset CTXMODE_READONLY", code: "unset CTXMODE_READONLY", want: "unset CTXMODE_READONLY"},
		{name: "unset PATH ok", code: "unset PATH", want: ""},
		{name: "source ok for worker", code: ". ./env.sh", want: ""},
		{name: "source word ok for worker", code: "source ./env.sh", want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardShellSubagent(tc.code)
			if got != tc.want {
				t.Fatalf("guardShellSubagent(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		code string
		want string
	}{
		{name: ". script", code: ". ./env.sh", want: "."},
		{name: "source script", code: "source ./env.sh", want: "source"},
		{name: "trap rm", code: "trap 'rm -f x' EXIT", want: "rm"},
		{name: "trap -p ok", code: "trap -p", want: "deleted"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardShellReadonly(tc.code)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardShellReadonly(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

// TestGuard_GitGlobalExecArgs covers `git -c`/`--config-env`/`--exec-path`
// exec-arming config for both sub-agent and strict read-only callers.
func TestGuard_GitGlobalExecArgs(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "-c core.pager=less", argv: []string{"git", "-c", "core.pager=less", "log"}, want: "git -c core.pager"},
		{name: "-c glued", argv: []string{"git", "-ccore.sshCommand=/tmp/x", "fetch"}, want: "git -c core.sshCommand"},
		{name: "-c bang alias", argv: []string{"git", "-c", "alias.x=!pig", "x"}, want: "git -c alias.x"},
		{name: "-c alias.* prefix", argv: []string{"git", "-c", "alias.st=status", "st"}, want: "git -c alias.st"},
		{name: "-c pager.* prefix", argv: []string{"git", "-c", "pager.diff=less", "diff"}, want: "git -c pager.diff"},
		{name: "-c core.editor", argv: []string{"git", "-c", "core.editor=/tmp/x", "commit"}, want: "git -c core.editor"},
		{name: "-c core.hooksPath", argv: []string{"git", "-c", "core.hookspath=/tmp/h", "status"}, want: "git -c core.hookspath"},
		{name: "-c sequence.editor", argv: []string{"git", "-c", "sequence.editor=/tmp/x", "rebase", "-i"}, want: "git -c sequence.editor"},
		{name: "-c credential.helper", argv: []string{"git", "-c", "credential.helper=/tmp/x", "fetch"}, want: "git -c credential.helper"},
		{name: "-c diff.external", argv: []string{"git", "-c", "diff.external=/tmp/x", "diff"}, want: "git -c diff.external"},
		{name: "-c filter.* prefix", argv: []string{"git", "-c", "filter.x.clean=/tmp/x", "status"}, want: "git -c filter.x.clean"},
		{name: "--config-env", argv: []string{"git", "--config-env", "core.sshcommand=GIT_SSH_COMMAND", "fetch"}, want: "git --config-env core.sshcommand"},
		{name: "--config-env=", argv: []string{"git", "--config-env=pager.log=LESS", "log"}, want: "git --config-env pager.log"},
		{name: "--exec-path=dir", argv: []string{"git", "--exec-path=/tmp/x", "status"}, want: "git --exec-path"},
		{name: "--exec-path dir", argv: []string{"git", "--exec-path", "/tmp/x", "status"}, want: "git --exec-path"},
		// Allowed: bare --exec-path query, core.pager=cat/=, ordinary -c.
		{name: "bare --exec-path", argv: []string{"git", "--exec-path"}, want: ""},
		{name: "-c core.pager=cat", argv: []string{"git", "-c", "core.pager=cat", "log"}, want: ""},
		{name: "-c core.pager=", argv: []string{"git", "-c", "core.pager=", "log"}, want: ""},
		{name: "-c user.name", argv: []string{"git", "-c", "user.name=x", "commit"}, want: ""},
		{name: "-c color.ui", argv: []string{"git", "-c", "color.ui=false", "status"}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "-c core.pager=less", argv: []string{"git", "-c", "core.pager=less", "log"}, want: "git -c core.pager"},
		{name: "-c alias.x=!rm", argv: []string{"git", "-c", "alias.x=!rm", "x"}, want: "git -c alias.x"},
		{name: "--exec-path=dir", argv: []string{"git", "--exec-path=/tmp/x", "status"}, want: "git --exec-path"},
		{name: "-c core.pager=cat ok", argv: []string{"git", "-c", "core.pager=cat", "log"}, want: "git -c"},
		{name: "-c safe ok", argv: []string{"git", "-c", "a=b", "diff"}, want: "git -c"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_BareShellAndScriptFile covers strict read-only blocking of bare
// shell/interpreter invocations that would run a script file or read stdin.
func TestGuard_BareShellAndScriptFile(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "sh script.sh", argv: []string{"sh", "script.sh"}, want: "sh"},
		{name: "bash script.sh", argv: []string{"bash", "/tmp/x.sh"}, want: "bash"},
		{name: "sh bare", argv: []string{"sh"}, want: "sh"},
		{name: "sh -n blocked", argv: []string{"sh", "-n", "script.sh"}, want: "shell"},
		{name: "sh --version blocked", argv: []string{"sh", "--version"}, want: "shell"},
		{name: "sh --help blocked", argv: []string{"bash", "--help"}, want: "shell"},
		{name: "python3 script.py", argv: []string{"python3", "app.py"}, want: "python3"},
		{name: "python3 bare", argv: []string{"python3"}, want: "python3"},
		{name: "python3 --version blocked", argv: []string{"python3", "--version"}, want: "python"},
		{name: "python3 -V blocked", argv: []string{"python3", "-V"}, want: "python"},
		{name: "python3 -h blocked", argv: []string{"python3", "-h"}, want: "python"},
		{name: "python3 - dash stdin ok", argv: []string{"python3", "-"}, want: "python interpreter"},
		{name: "python3 -m json.tool ok", argv: []string{"python3", "-m", "json.tool", "f.json"}, want: "deleted"},
		{name: "python3 -m pip blocked", argv: []string{"python3", "-m", "pip", "install", "x"}, want: "python -m pip"},
		{name: "node app.js", argv: []string{"node", "app.js"}, want: "node"},
		{name: "node --version blocked", argv: []string{"node", "--version"}, want: "node"},
		{name: "perl script.pl", argv: []string{"perl", "x.pl"}, want: "perl"},
		{name: "ruby script.rb", argv: []string{"ruby", "x.rb"}, want: "ruby"},
		{name: "php script.php", argv: []string{"php", "x.php"}, want: "php"},
		{name: "python -cCODE glued", argv: []string{"python3", "-cimport json; print(1)"}, want: "python program text"},
		{name: "python -ucCODE glued write", argv: []string{"python3", "-ucopen('/tmp/x','w')"}, want: "python inline code"},
		{name: "python -mMODULE glued write", argv: []string{"python3", "-mpip", "install", "x"}, want: "python -m pip"},
		{name: "python -mMODULE glued ok", argv: []string{"python3", "-mjson.tool", "f.json"}, want: "deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_ArchiveAndCompress covers tar/unzip/gzip read-only vs write
// spellings for strict read-only roles.
func TestGuard_ArchiveAndCompress(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		// tar
		{name: "tar -tf ok", argv: []string{"tar", "-tf", "a.tar"}, want: "deleted"},
		{name: "tar tf bsd ok", argv: []string{"tar", "tf", "a.tar"}, want: "deleted"},
		{name: "tar -tvf ok", argv: []string{"tar", "-tvf", "a.tar"}, want: "deleted"},
		{name: "tar --list ok", argv: []string{"tar", "--list", "-f", "a.tar"}, want: "deleted"},
		{name: "tar --help ok", argv: []string{"tar", "--help"}, want: "deleted"},
		{name: "tar --version ok", argv: []string{"tar", "--version"}, want: "deleted"},
		{name: "tar -cf blocked", argv: []string{"tar", "-cf", "a.tar", "dir"}, want: "tar -c"},
		{name: "tar cf bsd blocked", argv: []string{"tar", "cf", "a.tar", "dir"}, want: "tar -c"},
		{name: "tar czf blocked", argv: []string{"tar", "czf", "a.tar.gz", "dir"}, want: "tar -c"},
		{name: "tar -xf blocked", argv: []string{"tar", "-xf", "a.tar"}, want: "tar -x"},
		{name: "tar xf blocked", argv: []string{"tar", "xf", "a.tar"}, want: "tar -x"},
		{name: "tar -xOf ok", argv: []string{"tar", "-xOf", "a.tar", "f"}, want: "deleted"},
		{name: "tar -x --to-stdout ok", argv: []string{"tar", "-x", "--to-stdout", "-f", "a.tar"}, want: "deleted"},
		{name: "tar -rf blocked", argv: []string{"tar", "-rf", "a.tar", "f"}, want: "tar -r"},
		{name: "tar -u blocked", argv: []string{"tar", "-uf", "a.tar", "f"}, want: "tar -u"},
		{name: "tar --delete blocked", argv: []string{"tar", "--delete", "-f", "a.tar", "f"}, want: "tar --delete"},
		{name: "gtar -cf blocked", argv: []string{"gtar", "-cf", "a.tar", "d"}, want: "gtar -c"},
		// unzip
		{name: "unzip -l ok", argv: []string{"unzip", "-l", "a.zip"}, want: "deleted"},
		{name: "unzip -t ok", argv: []string{"unzip", "-t", "a.zip"}, want: "deleted"},
		{name: "unzip -p ok", argv: []string{"unzip", "-p", "a.zip", "f"}, want: "deleted"},
		{name: "unzip -v ok", argv: []string{"unzip", "-v", "a.zip"}, want: "deleted"},
		{name: "unzip -Z ok", argv: []string{"unzip", "-Z", "a.zip"}, want: "deleted"},
		{name: "unzip default blocked", argv: []string{"unzip", "a.zip"}, want: "unzip"},
		{name: "unzip -d blocked", argv: []string{"unzip", "a.zip", "-d", "/tmp/x"}, want: "unzip"},
		{name: "unzip -o blocked", argv: []string{"unzip", "-o", "a.zip"}, want: "unzip -o"},
		// compressors
		{name: "gzip -dc ok", argv: []string{"gzip", "-dc", "a.gz"}, want: "deleted"},
		{name: "gzip -l ok", argv: []string{"gzip", "-l", "a.gz"}, want: "deleted"},
		{name: "gzip -t ok", argv: []string{"gzip", "-t", "a.gz"}, want: "deleted"},
		{name: "gzip -V ok", argv: []string{"gzip", "-V"}, want: "deleted"},
		{name: "gzip default blocked", argv: []string{"gzip", "a"}, want: "gzip"},
		{name: "gzip -9 blocked", argv: []string{"gzip", "-9", "a"}, want: "gzip"},
		{name: "gunzip blocked", argv: []string{"gunzip", "a.gz"}, want: "gunzip"},
		{name: "gunzip -c ok", argv: []string{"gunzip", "-c", "a.gz"}, want: "deleted"},
		{name: "xz -dc ok", argv: []string{"xz", "-dc", "a.xz"}, want: "deleted"},
		{name: "xz -l ok", argv: []string{"xz", "-l", "a.xz"}, want: "deleted"},
		{name: "xz blocked", argv: []string{"xz", "a"}, want: "xz"},
		{name: "zstd -dc ok", argv: []string{"zstd", "-dc", "a.zst"}, want: "deleted"},
		{name: "zstd blocked", argv: []string{"zstd", "a"}, want: "zstd"},
		{name: "bzip2 blocked", argv: []string{"bzip2", "a"}, want: "bzip2"},
		{name: "bunzip2 -c ok", argv: []string{"bunzip2", "-c", "a.bz2"}, want: "deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_FsWriteHeadsRound2 covers the expanded fsWriteHeads table for
// strict read-only.
func TestGuard_FsWriteHeadsRound2(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	blocked := [][]string{
		{"ed", "f"}, {"ex", "f"}, {"vi", "f"}, {"vim", "f"}, {"nvim", "f"},
		{"nano", "f"}, {"sponge", "f"},
		{"split", "f"}, {"csplit", "f"}, {"fallocate", "-l", "1", "f"},
		{"chattr", "+i", "f"}, {"setfattr", "-n", "k", "f"}, {"setfacl", "-m", "u", "f"},
		{"mount", "/dev/x", "/mnt"}, {"umount", "/mnt"},
		{"mknod", "/tmp/n", "p"}, {"mkfifo", "/tmp/p"},
		{"uudecode", "f"}, {"zip", "a.zip", "f"}, {"7z", "a", "a.7z", "f"},
		{"7za", "a", "a.7z", "f"}, {"rar", "a", "a.rar", "f"}, {"cpio", "-o"},
		{"ar", "r", "a.a", "f"}, {"ranlib", "a.a"}, {"strip", "a"}, {"objcopy", "a"},
		{"gcc", "x.c"}, {"g++", "x.cc"}, {"cc", "x.c"}, {"c++", "x.cc"},
		{"clang", "x.c"}, {"clang++", "x.cc"}, {"rustc", "x.rs"}, {"javac", "X.java"},
		{"make"}, {"gmake"}, {"cmake", "."}, {"ninja"}, {"meson", "build"},
		{"pip", "install", "x"}, {"pip3", "install", "x"}, {"pipx", "install", "x"},
		{"uv", "pip", "install", "x"}, {"poetry", "install"}, {"conda", "install", "x"},
		{"gem", "install", "x"}, {"composer", "install"},
		{"flock", "/tmp/l", "ls"}, {"script", "/tmp/t"},
	}
	for _, argv := range blocked {
		t.Run(argv[0], func(t *testing.T) {
			if got := guardArgvReadonly(argv); got == "" {
				t.Fatalf("guardArgvReadonly(%v) must block", argv)
			}
		})
	}
}

// TestGuard_SedAwkWriteCommands covers sed w/W script commands and awk
// system(|/getline-pipe/print-redirect escapes, plus their read-only
// neighbors.
func TestGuard_SedAwkWriteCommands(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		// sed write commands
		{name: "sed w file", argv: []string{"sed", "w /tmp/x", "f"}, want: "sed w"},
		{name: "sed W file", argv: []string{"sed", "W /tmp/x", "f"}, want: "sed W"},
		{name: "sed s///w flag", argv: []string{"sed", "s/a/b/w /tmp/x", "f"}, want: "sed s///w"},
		{name: "sed -e w", argv: []string{"sed", "-e", "w /tmp/x", "f"}, want: "sed w"},
		{name: "sed 1,3w", argv: []string{"sed", "1,3w /tmp/x", "f"}, want: "sed w"},
		{name: "sed addr w", argv: []string{"sed", "/pat/w /tmp/x", "f"}, want: "sed w"},
		// read-only neighbors must pass
		{name: "sed -n /word/p ok", argv: []string{"sed", "-n", "/word/p", "f"}, want: "deleted"},
		{name: "sed s///g ok", argv: []string{"sed", "s/a/word/g", "f"}, want: "deleted"},
		{name: "sed plain ok", argv: []string{"sed", "s/a/b/", "f"}, want: "deleted"},
		{name: "sed -n p ok", argv: []string{"sed", "-n", "1,20p", "f"}, want: ""},
		{name: "sed d ok", argv: []string{"sed", "1d", "f"}, want: "deleted"},
		{name: "sed y ok", argv: []string{"sed", "y/a/b/", "f"}, want: "blocked"},
		// awk write escapes
		{name: "awk system(", argv: []string{"awk", "{system(\"rm f\")}", "f"}, want: "awk system("},
		{name: "awk print > file", argv: []string{"awk", "{print > \"/tmp/x\"}", "f"}, want: "awk print >"},
		{name: "awk print >> file", argv: []string{"awk", "{printf >> \"/tmp/x\"}", "f"}, want: "awk print >"},
		{name: "awk cmd|getline", argv: []string{"awk", "{\"ls\" | getline x}", "f"}, want: "awk | getline"},
		{name: "awk getline < file ok", argv: []string{"awk", "{getline x < \"f\"}", "f"}, want: "blocked"},
		{name: "awk -f progfile", argv: []string{"awk", "-f", "/tmp/p.awk", "f"}, want: "awk -f"},
		// read-only neighbors
		{name: "awk $1 > 5 compare ok", argv: []string{"awk", "$1 > 5 {print $1}", "f"}, want: "blocked"},
		{name: "awk /a|b/ regex ok", argv: []string{"awk", "/a|b/ {print}", "f"}, want: "blocked"},
		{name: "awk plain ok", argv: []string{"awk", "{print $1}", "f"}, want: "blocked"},
		{name: "awk -F ok", argv: []string{"awk", "-F:", "{print $1}", "f"}, want: "blocked"},
		{name: "awk -v ok", argv: []string{"awk", "-v", "x=1", "{print x}", "f"}, want: "blocked"},
		{name: "awk NR==5 ok", argv: []string{"awk", "NR==5", "f"}, want: "blocked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_CodeSpawnPrimsRound2 covers the new spawn primitives and
// fail-closed open() mode handling in guardCtxRunCode.
func TestGuard_CodeSpawnPrimsRound2(t *testing.T) {
	sub := guardCall{subagent: true}
	strict := guardCall{strictReadonly: true}

	subCases := []struct {
		name string
		lang string
		code string
		want bool
	}{
		{name: "__import__ pig", lang: "python", code: "__import__('subprocess').run(['pig'])", want: true},
		{name: "importlib pig", lang: "python", code: "importlib.import_module('subprocess').run(['pig'])", want: true},
		{name: "ctypes pig", lang: "python", code: "ctypes.CDLL('libc').system('pig')", want: true},
		{name: "eval pig", lang: "python", code: "eval('__import__(\"subprocess\").run([\"pig\"])')", want: true},
		{name: "exec pig", lang: "python", code: "exec('import subprocess; subprocess.run([\"pig\"])')", want: true},
		{name: "Function pig", lang: "javascript", code: "Function('require(\"child_process\").execSync(\"pig\")')()", want: true},
		{name: "process.binding pig", lang: "javascript", code: "process.binding('spawn_sync').spawn({cmd:'pig'})", want: true},
		{name: "tmux agent name", lang: "python", code: "import subprocess; subprocess.run(['tmux','new-session','pig'])", want: true},
		{name: "screen agent name", lang: "python", code: "import subprocess; subprocess.run(['screen','-dm','pig'])", want: true},
		{name: "perl backtick pig", lang: "perl", code: "`pig --help`", want: true},
		{name: "perl qx pig", lang: "perl", code: "qx{pig --help}", want: true},
		{name: "ruby backtick pig", lang: "ruby", code: "`pig --help`", want: true},
		{name: "php backtick pig", lang: "php", code: "`pig --help`;", want: true},
		{name: "System.cmd pig", lang: "elixir", code: "System.cmd(\"pig\", [])", want: true},
		{name: "Port.open pig", lang: "erlang", code: "Port.open({spawn,\"pig\"},[])", want: true},
		{name: "system2 pig", lang: "r", code: "system2('pig')", want: true},
		{name: "mention tmux no spawn", lang: "python", code: "x='tmux'; print(x)", want: false},
		{name: "harmless eval-free", lang: "python", code: "import json; print(1)", want: false},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			rule, _ := sub.guardCtxRunCode(tc.lang, tc.code)
			if (rule == ruleSubagentNestedAgent) != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule = %q, want blocked=%v", tc.code, rule, tc.want)
			}
		})
	}

	roCases := []struct {
		name string
		lang string
		code string
		want bool
	}{
		{name: "__import__ blocked", lang: "python", code: "__import__('os').system('ls')", want: true},
		{name: "importlib blocked", lang: "python", code: "importlib.import_module('os').system('ls')", want: true},
		{name: "eval blocked", lang: "python", code: "eval('1+1')", want: true},
		{name: "exec blocked", lang: "python", code: "exec('print(1)')", want: true},
		{name: "ctypes blocked", lang: "python", code: "ctypes.CDLL('libc')", want: true},
		{name: "perl backtick blocked", lang: "perl", code: "`ls`", want: true},
		{name: "perl qx blocked", lang: "perl", code: "qx(ls)", want: true},
		{name: "perl %x blocked", lang: "perl", code: "%x{ls}", want: true},
		{name: "ruby %x blocked", lang: "ruby", code: "%x(ls)", want: true},
		{name: "Function blocked", lang: "javascript", code: "Function('return 1')()", want: true},
		{name: "process.binding blocked", lang: "javascript", code: "process.binding('spawn_sync')", want: true},
		{name: "open(p) ok", lang: "python", code: "open('/etc/hostname').read()", want: false},
		{name: "open(p,'r') ok", lang: "python", code: "open('/etc/hostname','r').read()", want: false},
		{name: "open(p,'rb') ok", lang: "python", code: "open('/etc/hostname','rb').read()", want: false},
		{name: "open encoding ok", lang: "python", code: "open('/etc/hostname', encoding='utf-8').read()", want: false},
		{name: "Path(p).open('r') ok", lang: "python", code: "Path('/etc/hostname').open('r').read()", want: false},
		{name: "open var mode blocked", lang: "python", code: "open('/tmp/x', m).read()", want: true},
		{name: "open concat mode blocked", lang: "python", code: "open('/tmp/x', 'r'+'w')", want: true},
		{name: "open mode=var blocked", lang: "python", code: "open('/tmp/x', mode=m)", want: true},
		{name: "open mode=concat blocked", lang: "python", code: "open('/tmp/x', mode='r'+'w')", want: true},
		{name: "open 'w' blocked", lang: "python", code: "open('/tmp/x','w')", want: true},
		{name: "open 'a' blocked", lang: "python", code: "open('/tmp/x','a')", want: true},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			rule, _ := strict.guardCtxRunCode(tc.lang, tc.code)
			if (rule == ruleReadonlyWrite) != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule = %q, want blocked=%v", tc.code, rule, tc.want)
			}
		})
	}
}

// TestGuard_StdinPayload covers ctx_run stdin screening: argv/command heads
// that read their program from stdin get the payload screened.
func TestGuard_StdinPayload(t *testing.T) {
	s, _ := auditTestServer(t)

	// argv sh + stdin pig: blocked for a sub-agent.
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")
	_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  []string{"sh"},
		Stdin: "pig --help",
	})
	if err == nil || !strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("argv sh + stdin pig must block, got %v", err)
	}
	// argv python3 + stdin code with a spawn primitive naming an agent.
	_, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  []string{"python3"},
		Stdin: "import subprocess; subprocess.run(['pig'])",
	})
	if err == nil || !strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("argv python3 + stdin agent code must block, got %v", err)
	}
	// argv sh -c + stdin: stdin is DATA, not screened.
	_, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  []string{"sh", "-c", "cat"},
		Stdin: "pig --help",
	})
	if err != nil && strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("sh -c stdin must not be screened as code, got %v", err)
	}

	// command cat file | sh + stdin pig: the peeled sh head screens stdin.
	_, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Command: "cat f | sh",
		Stdin:   "pig",
	})
	if err == nil || !strings.Contains(err.Error(), ruleSubagentNestedAgent) {
		t.Fatalf("pipe to sh + stdin pig must block, got %v", err)
	}

	// strict read-only: stdin write primitive.
	t.Setenv(auditEnvRole, "scout")
	_, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  []string{"python3"},
		Stdin: "open('/tmp/x','w').write('a')",
	})
	if err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
		t.Fatalf("python3 stdin write must block, got %v", err)
	}
}

// TestGuard_HeredocDashEOF covers the <<- heredoc tab-indented terminator.
func TestGuard_HeredocDashEOF(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	// <<-EOF terminator may be indented with tabs: the command after it must
	// still be screened, not swallowed into the body.
	code := "cat <<-EOF\n\tbody\n\tEOF\npig"
	if got := guardShellSubagent(code); got != "pig" {
		t.Fatalf("tab-indented <<- terminator must close, got %q", got)
	}
	code = "sh <<-EOF\n\tpig\n\tEOF"
	if got := guardShellSubagent(code); got != "pig" {
		t.Fatalf("shell heredoc body must be screened, got %q", got)
	}
	// A space-indented terminator under <<EOF (no dash) is NOT a valid
	// terminator: the trailing command stays inside the body (data for cat).
	code = "cat <<EOF\nbody\n EOF\npig"
	if got := guardShellSubagent(code); got == "pig" {
		t.Fatalf("space-indented << terminator must not close, got %q", got)
	}

	t.Setenv(auditEnvRole, "reviewer")
	code = "cat <<-EOF\n\tbody\n\tEOF\nrm -f /tmp/x"
	if got := guardShellReadonly(code); !readonlyWantMatch(got, "rm") {
		t.Fatalf("trailing command after tab-indented EOF must be screened, got %q", got)
	}
}

// TestGuard_DepthFailClosed covers the fail-closed depth caps: nesting past
// shellSplitMaxDepth blocks both guards instead of silently dropping inner
// commands.
func TestGuard_DepthFailClosed(t *testing.T) {
	t.Setenv(auditEnvReadonly, "")

	// Build $( ... ) nesting past the 16-level cap with a benign innermost
	// command: the guard must fail closed on depth, not the head.
	code := "echo ok"
	for d := 0; d < shellSplitMaxDepth+2; d++ {
		code = "x=$(" + code + ")"
	}
	t.Setenv(auditEnvRole, "worker")
	if got := guardShellSubagent(code); got != depthExceededHit {
		t.Fatalf("deep $() nesting must fail closed, got %q", got)
	}
	t.Setenv(auditEnvRole, "reviewer")
	if got := guardShellReadonly(code); got != depthExceededHit && !strings.Contains(got, "$") &&
		!strings.Contains(got, "forbidden") && !strings.Contains(got, "syntax") && !strings.Contains(got, "assign") {
		t.Fatalf("deep $() nesting must fail closed (depth or syntax), got %q", got)
	}
	// Within-cap nesting still parses normally.
	shallow := "echo $(echo $(echo ok))"
	if got := guardShellSubagent(shallow); got != "" {
		t.Fatalf("shallow nesting must pass, got %q", got)
	}
	// eval recursion beyond the chain cap fails closed too.
	deep := "true"
	for d := 0; d < peelChainMaxDepth+2; d++ {
		deep = "eval " + deep
	}
	t.Setenv(auditEnvRole, "worker")
	if got := guardShellSubagent(deep); got != depthExceededHit {
		t.Fatalf("deep eval chain must fail closed, got %q", got)
	}
}

// TestGuard_InlineSubstitutionEscapes locks three scanInlineSubstitutions
// indexing/recursion regressions: an escaped \" inside a double-quoted
// redirect target must not tear the quote pair open, consecutive backtick
// groups inside double quotes must not mis-pair the closers, and a
// substitution hit past the depth cap must fail closed instead of
// recursing into splitShellSegmentsDepth again.
func TestGuard_InlineSubstitutionEscapes(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	// Escaped quote inside a double-quoted redirect target: the \" must be
	// consumed as one escape pair, not treated as a quote boundary —
	// otherwise the trailing `pig` text falls inside a spurious
	// single-quoted span and the substitution is never scanned.
	if got := guardShellSubagent("echo hi > \"\\\"'`pig`'\""); got != "pig" {
		t.Fatalf("escaped-quote redirect target must still scan backticks, got %q", got)
	}

	// Two consecutive backtick groups inside double quotes in an unquoted
	// heredoc body: the first group's closer must not be re-read as an
	// opener — the second `pig` group is real code and must be hit.
	heredoc := "cat <<EOF\n\"a`true`b`pig`c\"\nEOF"
	if got := guardShellSubagent(heredoc); got != "pig" {
		t.Fatalf("adjacent backtick groups in heredoc must scan both, got %q", got)
	}
	// The same input must not emit a spurious segment for the gap text
	// between the two backtick groups (the off-by-one re-pairing).
	segsBT, okBT := parseSubagentShellAST("echo \"a`true`b`pig`c\"", 0, false, false)
	if !okBT {
		t.Fatalf("parse failed for adjacent backticks")
	}
	var heads []string
	for _, s := range segsBT {
		if len(s.argv) > 0 {
			heads = append(heads, s.argv[0])
		}
	}
	want := map[string]bool{"true": true, "pig": true}
	for _, h := range heads {
		delete(want, h)
	}
	if len(want) != 0 {
		t.Fatalf("backtick groups must surface true and pig, heads=%v missing=%v", heads, want)
	}

	// A substitution reached at the depth cap must emit the fail-closed
	// marker rather than recursing one level deeper.
	deep := "echo ok"
	for d := 0; d < shellSplitMaxDepth+2; d++ {
		deep = "$(" + deep + ")"
	}
	if got := guardShellSubagent("echo hi > " + deep); got != depthExceededHit {
		t.Fatalf("redirect target at depth cap must fail closed, got %q", got)
	}
	// Same cap reached through a redirect target nested inside $(...) so
	// scanInlineSubstitutions itself runs at the cap.
	atCap := "echo hi > $(true)"
	for d := 0; d < shellSplitMaxDepth; d++ {
		atCap = "x=$(" + atCap + ")"
	}
	if got := guardShellSubagent(atCap); got != depthExceededHit {
		t.Fatalf("nested redirect target at depth cap must fail closed, got %q", got)
	}
	// At the cap the scan must stop at the marker — no extra recursion
	// segments may follow it.
	segsCap, okCap := parseSubagentShellAST("$(true)", shellSplitMaxDepth, false, false)
	if okCap {
		t.Fatalf("at-cap substitution must fail closed, got %+v", segsCap)
	}
	if len(segsCap) != 1 || !segsCap[0].depthExceeded {
		t.Fatalf("at-cap substitution must emit only the depthExceeded marker, got %+v", segsCap)
	}
}

// ---------- pre-gate convergence: command queries / perl -i / env -i /
// ctxmode index / scripting lexical primitives ----------

// TestGuard_CommandQueryPrecision locks the `command` vs `builtin` split:
// a pure query option run (-v/-V, -p allowed) keeps `command` as head and
// is allowed for every role; argument-reversed forms still peel to the
// wrapped command; `builtin` has no query semantics at all.
func TestGuard_CommandQueryPrecision(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "command -v pig query ok", argv: []string{"command", "-v", "pig"}, want: ""},
		{name: "command -V pig query ok", argv: []string{"command", "-V", "pig"}, want: ""},
		{name: "command -pv pig query ok", argv: []string{"command", "-pv", "pig"}, want: ""},
		{name: "command -Vp pig query ok", argv: []string{"command", "-Vp", "pig"}, want: ""},
		{name: "command -p -v pig query ok", argv: []string{"command", "-p", "-v", "pig"}, want: ""},
		{name: "command pig -v peels", argv: []string{"command", "pig", "-v"}, want: "pig"},
		{name: "command -p pig -v peels", argv: []string{"command", "-p", "pig", "-v"}, want: "pig"},
		{name: "command pig bare peels", argv: []string{"command", "pig"}, want: "pig"},
		{name: "builtin pig peels", argv: []string{"builtin", "pig"}, want: "pig"},
		{name: "builtin -v pig peels", argv: []string{"builtin", "-v", "pig"}, want: "pig"},
		{name: "builtin cd ok", argv: []string{"builtin", "echo", "hi"}, want: ""},
		{name: "command echo ok", argv: []string{"command", "echo", "hi"}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "command -v rm query ok", argv: []string{"command", "-v", "rm"}, want: "deleted"},
		{name: "command -pv rm query ok", argv: []string{"command", "-pv", "rm"}, want: "deleted"},
		{name: "command rm -v peels", argv: []string{"command", "rm", "-v", "/tmp/x"}, want: "rm"},
		{name: "command -p rm -v peels", argv: []string{"command", "-p", "rm", "-v", "/tmp/x"}, want: "rm"},
		{name: "builtin rm peels", argv: []string{"builtin", "rm", "-f", "x"}, want: "rm"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	// worker `command rm -v` is fine (rm is not an agent head for 's').
	t.Setenv(auditEnvRole, "worker")
	if got := guardArgvSubagent([]string{"command", "rm", "-v", "/tmp/x"}); got != "" {
		t.Fatalf("worker command rm -v must pass, got %q", got)
	}
}

// TestGuard_InterpInPlaceArgv locks the perl/ruby -i precision: the in-place
// flag check runs for strict read-only only (workers keep `perl -i -pe`),
// and the scan stops at `--` and skips -e/-E script operands so script
// text can never be mistaken for an -i flag.
func TestGuard_InterpInPlaceArgv(t *testing.T) {
	t.Setenv(auditEnvReadonly, "")

	// Worker: perl/ruby -i -pe inline editing is a normal write task — the
	// sub-agent guard must not misread -i as a nested-dispatch head.
	t.Setenv(auditEnvRole, "worker")
	for _, argv := range [][]string{
		{"perl", "-i", "-pe", "s/a/b/", "file"},
		{"ruby", "-i", "-pe", "s/a/b/", "file"},
		{"perl", "-i.bak", "-pe", "s/a/b/", "file"},
	} {
		if got := guardArgvSubagent(argv); got != "" {
			t.Fatalf("guardArgvSubagent(%v) must pass for worker, got %q", argv, got)
		}
	}

	// Strict read-only: the -i flag still blocks — including via the
	// interpreter-inline path, where the argv ends before the file-run
	// fallthrough.
	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "perl -i -pe", argv: []string{"perl", "-i", "-pe", "s/a/b/", "f"}, want: "perl -i"},
		{name: "perl -ni -pe", argv: []string{"perl", "-ni", "-pe", "s/a/b/", "f"}, want: "perl -i"},
		{name: "perl -i.bak -pe", argv: []string{"perl", "-i.bak", "-pe", "s/a/b/", "f"}, want: "perl -i"},
		{name: "ruby -i -pe", argv: []string{"ruby", "-i", "-pe", "s/a/b/", "f"}, want: "ruby -i"},
		{name: "perl -i no inline", argv: []string{"perl", "-i", "x.pl"}, want: "perl -i"},
		// Read-only neighbors must pass: the -e/-E operand is script text,
		// not an option; `--` ends the option run.
		{name: "perl -e '-i' script", argv: []string{"perl", "-e", "-i"}, want: "perl program text"},
		{name: "perl -ne -- -input.txt", argv: []string{"perl", "-ne", "print", "--", "-input.txt"}, want: "perl program text"},
		{name: "perl -e print", argv: []string{"perl", "-e", "print 1"}, want: "perl program text"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_InlineShortClusters covers the new glued inline-code spellings
// (node -pCODE, perl -ECODE) and the `--` option terminator.
func TestGuard_InlineShortClusters(t *testing.T) {
	t.Setenv(auditEnvReadonly, "")

	// Sub-agent: glued -pCODE/-ECODE carries inline code that spawns an agent.
	t.Setenv(auditEnvRole, "worker")
	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "node -pCODE pig", argv: []string{"node", "-prequire('child_process').execSync('pig')"}, want: "javascript inline code"},
		{name: "perl -ECODE pig", argv: []string{"perl", "-Esystem('pig')"}, want: "perl inline code"},
		{name: "node -eCODE pig", argv: []string{"node", "-eexecSync('pig')"}, want: "javascript inline code"},
		{name: "node -p harmless", argv: []string{"node", "-p", "1+1"}, want: ""},
		{name: "node -- -e.js script ok", argv: []string{"node", "--", "-e.js"}, want: ""},
		{name: "python3 -- -c.py ok", argv: []string{"python3", "--", "-c.py"}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	// Strict read-only: -- after the interpreter means a script file, which
	// blocks via the file-run screen; node -pCODE write primitives block.
	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "node -pCODE write", argv: []string{"node", "-pfs.writeFileSync('/tmp/x','a')"}, want: "javascript inline code"},
		{name: "node -- -e.js file run", argv: []string{"node", "--", "-e.js"}, want: "node"},
		{name: "python3 -- -c.py file run", argv: []string{"python3", "--", "-c.py"}, want: "python3"},
		{name: "perl -ECODE unlink", argv: []string{"perl", "-Eunlink('/tmp/x')"}, want: "perl inline code"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_ScriptingCodePrims covers the paren-less spawn/write lexical
// scan for perl/ruby/php: system/exec/spawn and the write primitives must
// hit on masked code; quoted words and pure reads stay free; backtick
// bodies still count for agent-name detection.
func TestGuard_ScriptingCodePrims(t *testing.T) {
	sub := guardCall{subagent: true}
	strict := guardCall{strictReadonly: true}

	subCases := []struct {
		name string
		lang string
		code string
		want bool
	}{
		{name: "ruby system pig", lang: "ruby", code: "system 'pig'", want: true},
		{name: "perl exec pig", lang: "perl", code: "exec 'pig'", want: true},
		{name: "php shell_exec pig", lang: "php", code: "shell_exec(\"pig\");", want: true},
		{name: "perl backtick pig", lang: "perl", code: "`pig --help`", want: true},
		{name: "ruby %x pig", lang: "ruby", code: "%x{pig}", want: true},
		{name: "ruby system ls ok", lang: "ruby", code: "system 'ls'", want: false},
		{name: "php print ok", lang: "php", code: "echo 'ok';", want: false},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			rule, _ := sub.guardCtxRunCode(tc.lang, tc.code)
			if (rule == ruleSubagentNestedAgent) != tc.want {
				t.Fatalf("guardCtxRunCode(%s,%q) rule = %q, want blocked=%v", tc.lang, tc.code, rule, tc.want)
			}
		})
	}

	roCases := []struct {
		name string
		lang string
		code string
		want bool
	}{
		{name: "perl unlink", lang: "perl", code: "unlink '/tmp/x';", want: true},
		{name: "perl mkdir", lang: "perl", code: "mkdir '/tmp/d';", want: true},
		{name: "perl system", lang: "perl", code: "system('ls');", want: true},
		{name: "perl exec", lang: "perl", code: "exec 'ls';", want: true},
		{name: "perl qx", lang: "perl", code: "my $o = qx(ls);", want: true},
		{name: "perl open write", lang: "perl", code: "open my $fh, '>', '/tmp/x';", want: true},
		{name: "perl open append", lang: "perl", code: "open(FH, '>>', '/tmp/x');", want: true},
		{name: "perl open read ok", lang: "perl", code: "open my $fh, '<', 'f'; print <$fh>;", want: false},
		{name: "perl print ok", lang: "perl", code: "print 'unlink';", want: false},
		{name: "ruby File.write", lang: "ruby", code: "File.write('/tmp/x','a')", want: true},
		{name: "ruby FileUtils.rm", lang: "ruby", code: "FileUtils.rm('/tmp/x')", want: true},
		{name: "ruby Dir.mkdir", lang: "ruby", code: "Dir.mkdir('/tmp/d')", want: true},
		{name: "ruby File.open w", lang: "ruby", code: "File.open('/tmp/x','w')", want: true},
		{name: "ruby File.open var mode", lang: "ruby", code: "File.open('/tmp/x', m)", want: true},
		{name: "ruby File.open r ok", lang: "ruby", code: "File.open('/tmp/x','r')", want: false},
		{name: "ruby File.open 1arg ok", lang: "ruby", code: "File.open('/tmp/x')", want: false},
		{name: "ruby File.read ok", lang: "ruby", code: "puts File.read('a.txt')", want: false},
		{name: "ruby backtick spawn", lang: "ruby", code: "`ls`", want: true},
		{name: "php file_put_contents", lang: "php", code: "file_put_contents('/tmp/x','a');", want: true},
		{name: "php unlink", lang: "php", code: "unlink('/tmp/x');", want: true},
		{name: "php fopen w", lang: "php", code: "fopen('/tmp/x','w');", want: true},
		{name: "php fopen c mode", lang: "php", code: "fopen('/tmp/x','c');", want: true},
		{name: "php fopen var mode", lang: "php", code: "fopen('/tmp/x', $m);", want: true},
		{name: "php fopen r ok", lang: "php", code: "fopen('/tmp/x','r');", want: false},
		{name: "php system spawn", lang: "php", code: "system('ls');", want: true},
		{name: "php shell_exec", lang: "php", code: "shell_exec('ls');", want: true},
		{name: "php json ok", lang: "php", code: "echo json_encode(['ok'=>true]);", want: false},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			rule, _ := strict.guardCtxRunCode(tc.lang, tc.code)
			if (rule == ruleReadonlyWrite) != tc.want {
				t.Fatalf("guardCtxRunCode(%s,%q) rule = %q, want blocked=%v", tc.lang, tc.code, rule, tc.want)
			}
		})
	}
}

// TestGuard_PythonWriteModeRound3 covers the Path.open method-call mode
// handling plus urlretrieve/sqlite3.connect disk writes.
func TestGuard_PythonWriteModeRound3(t *testing.T) {
	strict := guardCall{strictReadonly: true}

	cases := []struct {
		name string
		code string
		want bool
	}{
		{name: "Path.open w", code: "Path('/tmp/x').open('w')", want: true},
		{name: "p.open r+", code: "p.open('r+')", want: true},
		{name: "p.open mode=a", code: "p.open(mode='a')", want: true},
		{name: "p.open var mode", code: "p.open(m)", want: true},
		{name: "p.open() ok", code: "p.open()", want: false},
		{name: "p.open('r') ok", code: "p.open('r')", want: false},
		{name: "p.open('rb') ok", code: "p.open('rb')", want: false},
		{name: "p.open encoding ok", code: "p.open(encoding='utf-8')", want: false},
		{name: "urlretrieve", code: "urllib.request.urlretrieve('http://x','/tmp/f')", want: true},
		{name: "urlretrieve alias", code: "urlretrieve('http://x','/tmp/f')", want: true},
		{name: "sqlite3.connect", code: "sqlite3.connect('/tmp/x.db')", want: true},
		{name: "sqlite3 ro ok", code: "sqlite3.connect('file:/tmp/x.db?mode=ro', uri=True)", want: false},
		{name: "sqlite3 ro kwarg ok", code: "sqlite3.connect(database='file:/tmp/x.db?cache=shared&mode=ro', uri=True)", want: false},
		{name: "sqlite3 file no uri", code: "sqlite3.connect('file:/tmp/x.db?mode=ro')", want: true},
		{name: "sqlite3 ro uri=False", code: "sqlite3.connect('file:/tmp/x.db?mode=ro', uri=False)", want: true},
		{name: "sqlite3 plain ?mode=ro", code: "sqlite3.connect('/tmp/x.db?mode=ro')", want: true},
		{name: "sqlite3 mode=ro in kwarg", code: "sqlite3.connect('/tmp/rw.db', isolation_level='?mode=ro', uri=True)", want: true},
		{name: "sqlite3 concat lit", code: "sqlite3.connect('file:/tmp/x.db?mode=ro' + y, uri=True)", want: true},
		// Byte-aligned mask boundaries: string literals must not trip the
		// write checks, `ident (` spacing must still hit, and a path
		// containing an O_* flag name is not itself a flag.
		{name: "string literal open w ok", code: "print(\"open('/tmp/x', 'w')\")", want: false},
		{name: "string literal urlretrieve ok", code: "print(\"urlretrieve('http://x')\")", want: false},
		{name: "open space-paren w", code: "open ('/tmp/x', 'w')", want: true},
		{name: "os.open space-paren O_WRONLY", code: "os.open ('/tmp/x', os.O_WRONLY)", want: true},
		{name: "sqlite3.connect space-paren", code: "sqlite3.connect ('/tmp/db')", want: true},
		{name: "os.open O_WRONLY path read ok", code: "os.open('/tmp/O_WRONLY_name', os.O_RDONLY)", want: false},
		{name: "plain json ok", code: "import json; print(json.dumps({}))", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, _ := strict.guardCtxRunCode("python", tc.code)
			if (rule == ruleReadonlyWrite) != tc.want {
				t.Fatalf("guardCtxRunCode(python,%q) rule = %q, want blocked=%v", tc.code, rule, tc.want)
			}
		})
	}
}

// TestGuard_EnvIClearsIdentity covers `env -i`/`--ignore-environment`: a
// sub-agent that clears the inherited env without re-passing a non-empty
// CTXMODE_ROLE sheds its guard identity — blocked like `env -u`.
func TestGuard_EnvIClearsIdentity(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "env -i pig", argv: []string{"env", "-i", "pig"}, want: "env CTXMODE_ROLE"},
		{name: "env --ignore-environment", argv: []string{"env", "--ignore-environment", "ls"}, want: "env CTXMODE_ROLE"},
		{name: "env -i0", argv: []string{"env", "-i0", "ls"}, want: "env CTXMODE_ROLE"},
		{name: "env -0i", argv: []string{"env", "-0i", "ls"}, want: "env CTXMODE_ROLE"},
		{name: "env -i re-pass role ok", argv: []string{"env", "-i", "CTXMODE_ROLE=worker", "ls"}, want: ""},
		{name: "env -i empty role still blocks", argv: []string{"env", "-i", "CTXMODE_ROLE=", "ls"}, want: "env CTXMODE_ROLE"},
		{name: "env -i unrelated assign", argv: []string{"env", "-i", "FOO=1", "ls"}, want: "env CTXMODE_ROLE"},
		{name: "env plain ok", argv: []string{"env", "FOO=1", "ls"}, want: ""},
		{name: "env -0 alone ok", argv: []string{"env", "-0", "ls"}, want: ""},
		{name: "env -uCTXMODE_ROLE", argv: []string{"env", "-uCTXMODE_ROLE", "ls"}, want: "env CTXMODE_ROLE"},
		{name: "env --unset=CTXMODE_ROLE", argv: []string{"env", "--unset=CTXMODE_ROLE", "ls"}, want: "env CTXMODE_ROLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	// Shell-text form also blocks.
	if got := guardShellSubagent("env -i pig"); got == "" {
		t.Fatalf("guardShellSubagent(env -i pig) must block")
	}
	// A non-subagent is not identity-bound: env -i is harmless for the
	// strict read-only guard itself (ls is read-only).
	if got := guardArgvReadonly([]string{"env", "-i", "ls"}); got == "" {
		t.Fatalf("guardArgvReadonly(env -i ls) must block (env wrapper removed)")
	}
}

// ---------- hardening round 3: wrapper peeling / heredoc pipes / whitelists ----------

// TestGuard_HardGuardsRound3 covers the C-gate round-3 fixes in one table:
// panic-free unclosed inputs, ordered env identity simulation, wrapper
// peeling (setsid/strace/nice/time/flock/script/sh -ce/multi -e), pipe-fed
// interpreters, heredoc-pipe binding, herdr/herdsman whitelists, awk/sed/
// tar/git exec entries, read-only probe allowance and the write-path
// tightening.
func TestGuard_HardGuardsRound3(t *testing.T) {
	t.Setenv(auditEnvReadonly, "")

	// Sub-agent: identity ordered ops + wrapper peels + whitelist probes.
	t.Setenv(auditEnvRole, "worker")
	subCases := []struct {
		name string
		argv []string
		want string // "" = allowed (still may hit the head screen)
	}{
		// Ordered identity simulation.
		{name: "assign then clear", argv: []string{"CTXMODE_ROLE=worker", "env", "-i", "ls"}, want: "env CTXMODE_ROLE"},
		{name: "clear then re-pass ok", argv: []string{"env", "-i", "CTXMODE_ROLE=worker", "ls"}, want: ""},
		{name: "role downgrade", argv: []string{"env", "CTXMODE_ROLE=worker", "ls"}, want: ""}, // same role ok
		// Wrapper peeling.
		{name: "setsid -f pig", argv: []string{"setsid", "-f", "pig"}, want: "pig"},
		{name: "setsid -w pig", argv: []string{"setsid", "-w", "pig"}, want: "pig"},
		{name: "strace -f pig", argv: []string{"strace", "-f", "pig"}, want: "pig"},
		{name: "strace --seccomp-bpf pig", argv: []string{"strace", "-f", "--seccomp-bpf", "pig"}, want: "pig"},
		{name: "strace -e trace pig", argv: []string{"strace", "-e", "trace=x", "pig"}, want: "pig"},
		{name: "nice -n5 pig", argv: []string{"nice", "-n5", "pig"}, want: "pig"},
		{name: "nice -n 5 pig", argv: []string{"nice", "-n", "5", "pig"}, want: "pig"},
		{name: "nice --adjustment 5 pig", argv: []string{"nice", "--adjustment", "5", "pig"}, want: "pig"},
		{name: "nice --adjustment=5 pig", argv: []string{"nice", "--adjustment=5", "pig"}, want: "pig"},
		{name: "time -v pig", argv: []string{"time", "-v", "pig"}, want: "pig"},
		{name: "flock -c pig", argv: []string{"flock", "/tmp/l", "-c", "pig"}, want: "pig"},
		{name: "flock --command=", argv: []string{"flock", "/tmp/l", "--command=agy"}, want: "agy"},
		{name: "script -qc", argv: []string{"script", "-qc", "pig", "/dev/null"}, want: "pig"},
		{name: "script -c glued", argv: []string{"script", "-c" + "pig"}, want: "pig"},
		{name: "sh -ce script", argv: []string{"sh", "-ce", "pig"}, want: "pig"},
		{name: "bash -lce script", argv: []string{"bash", "-lce", "pig"}, want: "pig"},
		{name: "sh -o errexit -c", argv: []string{"sh", "-o", "errexit", "-c", "pig"}, want: "pig"},
		{name: "perl multi -e", argv: []string{"perl", "-e", "1;", "-e", "system 'pig';"}, want: "perl inline code"},
		{name: "node -e -p", argv: []string{"node", "-e", "1", "-p", "execSync('pig')"}, want: "javascript inline code"},
		// herdr/herdsman whitelist.
		{name: "herdr session list ok", argv: []string{"herdr", "session", "list"}, want: ""},
		{name: "herdr --session opt pane list", argv: []string{"herdr", "--session", "main", "pane", "list"}, want: ""},
		{name: "herdr --session opt pane run", argv: []string{"herdr", "--session", "main", "pane", "run", "x"}, want: "herdr pane run"},
		{name: "herdr pane send-text", argv: []string{"herdr", "pane", "send-text", "p", "x"}, want: "herdr pane send-text"},
		{name: "herdr agent start", argv: []string{"herdr", "agent", "start", "w"}, want: "herdr agent start"},
		{name: "herdr session attach", argv: []string{"herdr", "session", "attach", "s"}, want: "herdr session attach"},
		{name: "herdr server restart", argv: []string{"herdr", "server", "restart"}, want: "herdr server restart"},
		{name: "herdr unknown verb", argv: []string{"herdr", "bogusverb"}, want: "herdr bogusverb"},
		{name: "herdsman daemon status ok", argv: []string{"herdsman", "daemon", "status"}, want: ""},
		{name: "herdsman on", argv: []string{"herdsman", "on"}, want: "herdsman on"},
		{name: "herdsman daemon start", argv: []string{"herdsman", "daemon", "start"}, want: "herdsman daemon start"},
		{name: "herdsman wake", argv: []string{"herdsman", "wake"}, want: "herdsman wake"},
		{name: "crontab -l ok", argv: []string{"crontab", "-l"}, want: ""},
		{name: "crontab -e", argv: []string{"crontab", "-e"}, want: "crontab"},
		// awk exec escapes.
		{name: "awk system pig", argv: []string{"awk", "BEGIN{system(\"pig\")}"}, want: "pig"},
		{name: "awk cmd|getline", argv: []string{"awk", "BEGIN{\"pig\" | getline}"}, want: "pig"},
		{name: "awk print|cmd", argv: []string{"awk", "BEGIN{print \"x\" | \"pig\"}"}, want: "pig"},
		{name: "awk benign ok", argv: []string{"awk", "{print $1}"}, want: ""},
		// sed e command.
		{name: "sed 1e pig", argv: []string{"sed", "1e pig"}, want: "pig"},
		{name: "sed s///e", argv: []string{"sed", "s/.*/agy/e"}, want: "agy"},
		{name: "sed benign ok", argv: []string{"sed", "-n", "1,20p"}, want: ""},
		// tar exec hooks.
		{name: "tar checkpoint exec", argv: []string{"tar", "-tf", "a.tar", "--checkpoint-action=exec=pig"}, want: "pig"},
		{name: "tar to-command", argv: []string{"tar", "-xf", "a.tar", "--to-command", "pig"}, want: "pig"},
		{name: "tar -I cmd", argv: []string{"tar", "-cf", "a.tar", "-I", "pig", "x"}, want: "pig"},
		// git exec args.
		{name: "git grep open-files-in-pager", argv: []string{"git", "grep", "--open-files-in-pager=pig", "x"}, want: "git --open-files-in-pager=pig"},
		{name: "git rebase --exec", argv: []string{"git", "rebase", "--exec", "pig"}, want: "git --exec"},
		{name: "npx pig", argv: []string{"npx", "pig"}, want: "npx pig"},
		{name: "npx eslint ok", argv: []string{"npx", "eslint", "."}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	// Sub-agent shell text: pipe-fed interpreters, heredoc-pipe binding,
	// input-redirect substitutions.
	subShell := []struct {
		name string
		code string
		want string
	}{
		{name: "echo pig | sh", code: "echo pig | sh", want: "piped code to shell"},
		{name: "printf | bash", code: "printf '%s' agy | bash", want: "piped code to shell"},
		{name: "cat x | python3 -", code: "cat x | python3 -", want: "piped code to python"},
		{name: "echo json | python3 -m ok", code: "echo '{\"a\":1}' | python3 -m json.tool", want: ""},
		{name: "echo hi | grep ok", code: "echo hi | grep hi", want: ""},
		{name: "heredoc-pipe binding", code: "sh <<'EOF' | cat\npig\nEOF", want: "pig"},
		{name: "cat <$(pig)", code: "cat <$(pig)", want: "pig"},
		{name: "cat <<< $(pig)", code: "cat <<< \"$(pig)\"", want: depthExceededHit},
	}
	for _, tc := range subShell {
		t.Run("subsh/"+tc.name, func(t *testing.T) {
			got := guardShellSubagent(tc.code)
			if got != tc.want {
				t.Fatalf("guardShellSubagent(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}

	// Strict read-only: probes stay free, writes block (incl. pipe-fed
	// interpreters, new exec entries, tightened compress/sed/git).
	t.Setenv(auditEnvRole, "reviewer")
	roArgv := []struct {
		name string
		argv []string
		want string
	}{
		{name: "mount bare ok", argv: []string{"mount"}, want: ""},
		{name: "mount -l ok", argv: []string{"mount", "-l"}, want: ""},
		{name: "mount -t ok", argv: []string{"mount", "-t", "tmpfs"}, want: ""},
		{name: "mount dev", argv: []string{"mount", "/dev/x", "/mnt"}, want: "mount"},
		{name: "mount -a", argv: []string{"mount", "-a"}, want: "mount"},
		{name: "kill -l ok", argv: []string{"kill", "-l"}, want: ""},
		{name: "kill -9", argv: []string{"kill", "-9", "1"}, want: "kill"},
		{name: "gcc --version ok", argv: []string{"gcc", "--version"}, want: "deleted"},
		{name: "gcc -dumpversion ok", argv: []string{"gcc", "-dumpversion"}, want: "deleted"},
		{name: "make --version ok", argv: []string{"make", "--version"}, want: "deleted"},
		{name: "gcc source", argv: []string{"gcc", "x.c"}, want: "gcc"},
		{name: "unzip -c ok", argv: []string{"unzip", "-c", "a.zip"}, want: "deleted"},
		{name: "gzip -d", argv: []string{"gzip", "-d", "a.gz"}, want: "gzip"},
		{name: "gzip -n", argv: []string{"gzip", "-n", "a"}, want: "gzip"},
		{name: "gzip -dc ok", argv: []string{"gzip", "-dc", "a.gz"}, want: "deleted"},
		{name: "gzip --no-name", argv: []string{"gzip", "--no-name", "a"}, want: "gzip"},
		{name: "curl -sO", argv: []string{"curl", "-sO", "https://x/f"}, want: "curl -sO"},
		{name: "curl -so file", argv: []string{"curl", "-so", "/tmp/x", "https://x"}, want: "curl -o /tmp/x"},
		{name: "curl -so- blocked", argv: []string{"curl", "-so-", "https://x"}, want: "curl"},
		{name: "sed -f", argv: []string{"sed", "-f", "/tmp/s.sed", "f"}, want: "sed -f"},
		{name: "sed e cmd", argv: []string{"sed", "1e pig"}, want: "sed e"},
		{name: "sed s///e", argv: []string{"sed", "s/a/b/e"}, want: "sed e"},
		{name: "awk print (x) > f", argv: []string{"awk", "{print ($1) > \"/tmp/x\"}"}, want: "awk print >"},
		{name: "awk printf() > f", argv: []string{"awk", "{printf(\"%s\", $1) > \"/tmp/x\"}"}, want: "awk print >"},
		{name: "awk print|cmd", argv: []string{"awk", "{print \"x\" | \"cat\"}"}, want: "awk print | cmd"},
		{name: "awk $1 > 5 ok", argv: []string{"awk", "$1 > 5 {print $1}"}, want: "blocked"},
		{name: "tar checkpoint", argv: []string{"tar", "-tf", "a.tar", "--checkpoint-action=exec=x"}, want: "tar --checkpoint-action=exec"},
		{name: "tar to-command", argv: []string{"tar", "-xf", "a.tar", "--to-command=x"}, want: "tar --to-command"},
		{name: "tar -I bad", argv: []string{"tar", "-tf", "a.tar", "-I", "/tmp/x"}, want: "tar -I"},
		{name: "tar -I gzip ok", argv: []string{"tar", "-tf", "a.tar", "-I", "gzip"}, want: "deleted"},
		{name: "git grep -O", argv: []string{"git", "grep", "-Oless", "x"}, want: "git -O"},
		{name: "git remote -v show ok", argv: []string{"git", "remote", "-v", "show", "origin"}, want: "deleted"},
		{name: "git stash -q list ok", argv: []string{"git", "stash", "-q", "list"}, want: ""},
		{name: "git stash -q bare", argv: []string{"git", "stash", "-q"}, want: "git stash"},
		{name: "git branch -q new", argv: []string{"git", "branch", "-q", "newbranch"}, want: "git branch newbranch"},
		{name: "git branch -v ok", argv: []string{"git", "branch", "-v"}, want: ""},
		{name: "git reflog ok", argv: []string{"git", "reflog"}, want: ""},
		{name: "git reflog expire", argv: []string{"git", "reflog", "expire", "--all"}, want: "git reflog expire"},
		{name: "git submodule status ok", argv: []string{"git", "submodule", "status"}, want: ""},
		{name: "git submodule update", argv: []string{"git", "submodule", "update"}, want: "git submodule update"},
		{name: "go env -w", argv: []string{"go", "env", "-w", "GOPRIVATE=x"}, want: "go env -w"},
		{name: "go env -u", argv: []string{"go", "env", "-u", "GOPRIVATE"}, want: "go env -u"},
		{name: "go env ok", argv: []string{"go", "env"}, want: ""},
		{name: "go work", argv: []string{"go", "work", "init"}, want: "go work"},
		{name: "cargo fmt --check ok", argv: []string{"cargo", "fmt", "--check"}, want: "blocked"},
		{name: "cargo fmt", argv: []string{"cargo", "fmt"}, want: "cargo fmt"},
		{name: "cargo fix", argv: []string{"cargo", "fix"}, want: "cargo fix"},
		{name: "npx", argv: []string{"npx", "eslint"}, want: "npx"},
		{name: "bun install", argv: []string{"bun", "install"}, want: "bun install"},
		{name: "npm exec", argv: []string{"npm", "exec", "x"}, want: "npm exec"},
		{name: "python3 app.py --help", argv: []string{"python3", "app.py", "--help"}, want: "python3"},
		{name: "python3 --help blocked", argv: []string{"python3", "--help"}, want: "python"},
		{name: "sh -n blocked", argv: []string{"sh", "-n", "s.sh"}, want: "shell"},
		{name: "node --check blocked", argv: []string{"node", "--check", "app.js"}, want: "node"},
		{name: "node -c blocked", argv: []string{"node", "-c", "app.js"}, want: "node"},
		{name: "perl -c blocked", argv: []string{"perl", "-c", "s.pl"}, want: "perl"},
		{name: "ruby -c blocked", argv: []string{"ruby", "-c", "s.rb"}, want: "ruby"},
		{name: "php -l blocked", argv: []string{"php", "-l", "s.php"}, want: "php"},
		{name: "strace -o FILE", argv: []string{"strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
	}
	for _, tc := range roArgv {
		// The strace -o case is documented separately below; the loop asserts
		// the generic table only when want is set for the head check.
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	roShell := []struct {
		name string
		code string
		want string
	}{
		{name: "echo x | sh", code: "echo x | sh", want: "piped code to shell"},
		{name: "cat x | python3 -", code: "cat x | python3 -", want: "piped code to python"},
		{name: "echo json | python3 -m ok", code: "echo '{\"a\":1}' | python3 -m json.tool", want: "deleted"},
		{name: "echo > backslash-eof no panic", code: "echo > \\", want: "> <dynamic>"},
		{name: "cat <$(rm)", code: "cat <$(rm -f x)", want: "rm"},
		{name: "sh heredoc pipe", code: "sh <<'EOF' | cat\nrm -f /tmp/x\nEOF", want: "rm"},
		{name: "time -o FILE", code: "time -o /tmp/t ls", want: "time -o"},
	}
	for _, tc := range roShell {
		t.Run("rosh/"+tc.name, func(t *testing.T) {
			got := guardShellReadonly(tc.code)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardShellReadonly(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

// while ctx_run argv/shell screening catches `ctxmode [flags] index` for
// the same roles — worker and non-role callers keep both.
func TestGuard_CtxmodeIndexCLI(t *testing.T) {
	// argv-level: verifier is 's' (not strict) but still read-only — the
	// ctxmode index surface must fire for it via guardCtxRunArgv.
	for _, role := range []string{"verifier", "reviewer", "scout", "planner", "oracle"} {
		t.Setenv(auditEnvRole, role)
		t.Setenv(auditEnvReadonly, "")
		g := currentGuardCall()
		if rule, _ := g.guardCtxRunArgv([]string{"ctxmode", "index", "/tmp/x"}); rule != ruleReadonlyWrite {
			t.Fatalf("role %s: ctxmode index argv rule = %q, want %s", role, rule, ruleReadonlyWrite)
		}
		if rule, _ := g.guardCtxRunArgv([]string{"ctxmode", "-workdir", "/tmp", "index", "/tmp/x"}); rule != ruleReadonlyWrite {
			t.Fatalf("role %s: ctxmode -workdir index argv rule = %q, want %s", role, rule, ruleReadonlyWrite)
		}
		if rule, _ := g.guardCtxRunShell("ctxmode index /tmp/x"); rule != ruleReadonlyWrite {
			t.Fatalf("role %s: ctxmode index shell rule = %q, want %s", role, rule, ruleReadonlyWrite)
		}
		// ctxmode search stays open.
		if rule, _ := g.guardCtxRunArgv([]string{"ctxmode", "search", "q"}); rule != "" {
			t.Fatalf("role %s: ctxmode search must pass, got %q", role, rule)
		}
	}
	// Worker keeps ctxmode index through ctx_run (the CLI itself may fail
	// downstream — but never with the guard error).
	t.Setenv(auditEnvRole, "worker")
	g := currentGuardCall()
	if rule, _ := g.guardCtxRunArgv([]string{"ctxmode", "index", "/tmp/x"}); rule != "" {
		t.Fatalf("worker ctxmode index must pass the guard, got %q", rule)
	}

	// CLI entry point: read-only roles refused, worker/non-role pass.
	for _, role := range []string{"verifier", "reviewer"} {
		t.Setenv(auditEnvRole, role)
		s := &server{workdirs: []string{t.TempDir()}}
		var out bytes.Buffer
		if err := runCLI(s, []string{"index", "/tmp/x"}, &out); err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
			t.Fatalf("role %s: runCLI index must be guard-blocked, got %v", role, err)
		}
		// `ctxmode index` alone must hit the guard BEFORE the usage check
		// (parity with ctx_kb action=index).
		if err := runCLI(s, []string{"index"}, &out); err == nil || !strings.Contains(err.Error(), ruleReadonlyWrite) {
			t.Fatalf("role %s: runCLI index (no path) must be guard-blocked, got %v", role, err)
		}
		// search has no guard surface at all: its only early error is usage.
		if err := runCLI(s, []string{"search"}, &out); err == nil || !strings.Contains(err.Error(), "usage: ctxmode search") {
			t.Fatalf("role %s: runCLI search must not hit the guard, got %v", role, err)
		}
	}
	t.Setenv(auditEnvRole, "worker")
	s := &server{workdirs: []string{t.TempDir()}}
	var out bytes.Buffer
	if err := runCLI(s, []string{"index"}, &out); err == nil || !strings.Contains(err.Error(), "usage: ctxmode index") {
		t.Fatalf("worker runCLI index must reach the usage check, got %v", err)
	}

	// Subprocess level: the compiled binary must refuse `index` for
	// read-only roles BEFORE any filesystem side effect — no DB directory
	// created, .git/info/exclude untouched.
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "ctxmode-testbin")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if buildOut, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build test binary: %v\n%s", err, buildOut)
	}
	repo := t.TempDir()
	if gitOut, err := exec.Command("git", "init", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, gitOut)
	}
	docPath := filepath.Join(repo, "doc.md")
	if err := os.WriteFile(docPath, []byte("# doc\n"), 0o644); err != nil {
		t.Fatalf("write doc: %v", err)
	}
	excludePath := filepath.Join(repo, ".git", "info", "exclude")
	excludeBefore, err := os.ReadFile(excludePath)
	if err != nil {
		t.Fatalf("read .git/info/exclude: %v", err)
	}
	dbDir := filepath.Join(t.TempDir(), "nested-db")
	dbPath := filepath.Join(dbDir, "context_mode.db")
	for _, role := range []string{"reviewer", "verifier"} {
		cmd := exec.Command(binPath, "-workdir", repo, "index", docPath)
		cmd.Env = append(os.Environ(), "CTXMODE_ROLE="+role, "CTXMODE_DB="+dbPath)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		if runErr == nil {
			t.Fatalf("role %s: ctxmode index must exit non-zero, stderr=%s", role, stderr.String())
		}
		if !strings.Contains(stderr.String(), "readonly_write_blocked") ||
			!strings.Contains(stderr.String(), "ctxmode index") {
			t.Fatalf("role %s: stderr must carry the guard error, got %s", role, stderr.String())
		}
		if _, statErr := os.Stat(dbDir); !os.IsNotExist(statErr) {
			t.Fatalf("role %s: DB dir %s must not be created, stat err=%v", role, dbDir, statErr)
		}
		excludeAfter, err := os.ReadFile(excludePath)
		if err != nil {
			t.Fatalf("role %s: read .git/info/exclude after run: %v", role, err)
		}
		if !bytes.Equal(excludeBefore, excludeAfter) {
			t.Fatalf("role %s: .git/info/exclude was modified", role)
		}
	}
}

// ---------- r1 review fixes: substitution tearing / option clusters /
// module opens / config-env / wrapper-write chain / watch / xargs -e /
// sed+awk option spellings / spawn prims ----------

// TestGuard_CmdSubArgvIntegrity locks the splitShellSegmentsDepth fix:
// a word-position $(...)/`...` must NOT tear the enclosing command line
// into broken segments — it writes a placeholder word and stages the
// substitution's own commands as sibling segments.
func TestGuard_CmdSubArgvIntegrity(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		code string
		want string
	}{
		// The substitution's inner command is screened as its own segment
		// while the outer argv stays whole (no "" head, no torn "status").
		{name: "git -C $(pwd) ok", code: "git -C $(pwd) status", want: ""},
		{name: "git -C $(pig)", code: "git -C $(pig) status", want: "pig"},
		{name: "assign prefix pig", code: "A=$(true) pig", want: "pig"},
		{name: "assign prefix ls ok", code: "A=$(true) ls", want: ""},
		{name: "env prefix arg subst", code: "GIT_PAGER=sh git log -p $(pig)", want: "pig"},
		{name: "env prefix benign ok", code: "GIT_PAGER=sh git log -p $(echo HEAD)", want: "env GIT_PAGER"},
		{name: "quoted subst arg", code: `cat "$(pig)"`, want: "pig"},
		{name: "backtick arg", code: "cat `pig`", want: "pig"},
		{name: "subst-only segment", code: "$(pig)", want: "pig"},
		// A dynamically generated command head cannot be vetted: fail
		// closed for both guards.
		{name: "dynamic head subst", code: "$(printf pig) --help", want: "dynamic command head"},
		{name: "dynamic head quoted", code: `"$(echo rm)" -f x`, want: "dynamic command head"},
		{name: "dynamic head suffix", code: "$(echo p)ig", want: "dynamic command head"},
		{name: "placeholder arg benign", code: "echo $(true) | wc", want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardShellSubagent(tc.code)
			if got != tc.want {
				t.Fatalf("guardShellSubagent(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		code string
		want string
	}{
		{name: "git -C $(pwd) ok", code: "git -C $(pwd) status", want: "command substitution"},
		{name: "git -C $(rm)", code: "git -C $(rm -f x) status", want: "rm"},
		{name: "dynamic head", code: "$(printf rm) -f /tmp/x", want: "dynamic command head"},
		{name: "assign prefix rm", code: "A=$(true) rm -f x", want: "rm"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardShellReadonly(tc.code)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardShellReadonly(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

// TestGuard_FdRedirectInsideWord locks the digit-lookahead fix: digits
// INSIDE a word (python3) are not an fd prefix; only a bare number word
// before </> is.
func TestGuard_FdRedirectInsideWord(t *testing.T) {
	t.Setenv(auditEnvReadonly, "")

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		code string
		want string
	}{
		{name: "python3>/dev/null -c write", code: `python3>/dev/null -c "import os; os.remove('/tmp/x')"`, want: "python inline code"},
		{name: "python3 harmless ok", code: `python3>/dev/null -c "print(1)"`, want: "python program text"},
		{name: "bare fd redirect ok", code: "true 2>/dev/null", want: ""},
		{name: "fd redirect write", code: "cmd 2>/tmp/err", want: "> /tmp/err"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardShellReadonly(tc.code)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardShellReadonly(%q) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "worker")
	if got := guardShellSubagent(`python3>/dev/null -c "import subprocess; subprocess.run(['pig'])"`); got != "python inline code" {
		t.Fatalf("python3> redirect glued head must screen inline code, got %q", got)
	}
}

// TestGuard_InterpValueOptClusters locks the glued value-option fix:
// letters inside an option VALUE (-Wmodule's 'm', -rtime's 'e',
// -Mstrict's 'e') are not option flags.
func TestGuard_InterpValueOptClusters(t *testing.T) {
	t.Setenv(auditEnvReadonly, "")

	t.Setenv(auditEnvRole, "worker")
	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "python -Wmodule -c pig", argv: []string{"python3", "-Wmodule", "-c", "import subprocess; subprocess.run(['pig'])"}, want: "python inline code"},
		{name: "python -Xutf8 -c pig", argv: []string{"python3", "-Xutf8", "-c", "import os; os.system('pig')"}, want: "python inline code"},
		{name: "python -W ignore -c pig", argv: []string{"python3", "-W", "ignore", "-c", "import os; os.system('pig')"}, want: "python inline code"},
		{name: "ruby -rtime -e pig", argv: []string{"ruby", "-rtime", "-e", "system('pig')"}, want: "ruby inline code"},
		{name: "ruby -r time -e pig", argv: []string{"ruby", "-r", "time", "-e", "system('pig')"}, want: "ruby inline code"},
		{name: "perl -Mstrict -e pig", argv: []string{"perl", "-Mstrict", "-e", "system('pig')"}, want: "perl inline code"},
		{name: "node -rmod -e pig", argv: []string{"node", "-rmod", "-e", "execSync('pig')"}, want: "javascript inline code"},
		{name: "ruby -rtime -e benign ok", argv: []string{"ruby", "-rtime", "-e", "puts 1"}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	// Strict read-only: `ruby -rtime -e 'puts 1'` must not be misread as
	// `ruby -i` (the 'i' inside the -r operand 'time' is not a flag).
	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "ruby -rtime -e ok", argv: []string{"ruby", "-rtime", "-e", "puts 1"}, want: "blocked"},
		{name: "ruby -r time -e ok", argv: []string{"ruby", "-r", "time", "-e", "puts 1"}, want: "blocked"},
		{name: "perl -F: -a -ne ok", argv: []string{"perl", "-F:", "-a", "-ne", "print @F[0]"}, want: "blocked"},
		{name: "ruby -rtime -e system", argv: []string{"ruby", "-rtime", "-e", "system('ls')"}, want: "ruby inline code"},
		{name: "perl -Mstrict -e unlink", argv: []string{"perl", "-Mstrict", "-e", "unlink('/tmp/x')"}, want: "perl inline code"},
		{name: "python -Wmodule -c write", argv: []string{"python3", "-Wmodule", "-c", "open('/tmp/x','w')"}, want: "python inline code"},
		{name: "python -W ignore -c write", argv: []string{"python3", "-W", "ignore", "-c", "open('/tmp/x','w')"}, want: "python inline code"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_PythonModuleOpens locks the stdlib module-level .open() mode
// screening: gzip/bz2/lzma/tarfile/wave/aifc/sunau take the mode at
// positional 2 (default 'r' read); shelve.open defaults to 'c' (write);
// dbm.open is flag-aware ('r' read, w/c/n write, non-literal fails
// closed).
func TestGuard_PythonModuleOpens(t *testing.T) {
	strict := guardCall{strictReadonly: true}

	cases := []struct {
		name string
		code string
		want bool
	}{
		{name: "gzip rb ok", code: "gzip.open('/a/with_w.gz','rb')", want: false},
		{name: "gzip wb", code: "gzip.open('/tmp/x.gz','wb')", want: true},
		{name: "gzip default ok", code: "gzip.open('/tmp/x.gz')", want: false},
		{name: "bz2 rt ok", code: "bz2.open('/tmp/x.bz2','rt')", want: false},
		{name: "bz2 wb", code: "bz2.open('/tmp/x.bz2','wb')", want: true},
		{name: "lzma w", code: "lzma.open('/tmp/x.xz','w')", want: true},
		{name: "tarfile w", code: "tarfile.open('/tmp/a.tar','w')", want: true},
		{name: "tarfile r ok", code: "tarfile.open('/tmp/a.tar','r')", want: false},
		{name: "wave wb", code: "wave.open('/tmp/a.wav','wb')", want: true},
		{name: "aifc r ok", code: "aifc.open('/tmp/a.aifc','r')", want: false},
		{name: "sunau w", code: "sunau.open('/tmp/a.au','w')", want: true},
		{name: "shelve default c", code: "shelve.open('/tmp/s.db')", want: true},
		{name: "dbm r ok", code: "dbm.open('/tmp/d','r')", want: false},
		{name: "dbm default ok", code: "dbm.open('/tmp/d')", want: false},
		{name: "dbm c", code: "dbm.open('/tmp/d','c')", want: true},
		{name: "dbm n", code: "dbm.open('/tmp/d','n')", want: true},
		{name: "dbm w", code: "dbm.open('/tmp/d','w')", want: true},
		{name: "dbm flag=c", code: "dbm.open('/tmp/d', flag='c')", want: true},
		{name: "dbm flag=r ok", code: "dbm.open('/tmp/d', flag='r')", want: false},
		{name: "dbm var flag", code: "dbm.open('/tmp/d', f)", want: true},
		{name: "dbm.gnu r ok", code: "dbm.gnu.open('/tmp/d','r')", want: false},
		{name: "dbm.gnu c", code: "dbm.gnu.open('/tmp/d','c')", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, _ := strict.guardCtxRunCode("python", tc.code)
			if (rule == ruleReadonlyWrite) != tc.want {
				t.Fatalf("guardCtxRunCode(python,%q) rule = %q, want blocked=%v", tc.code, rule, tc.want)
			}
		})
	}
}

// TestGuard_GitConfigEnvPager locks the core.pager --config-env
// tightening: an env-sourced pager value is an exec-arming key like any
// other (pager disabling stays available via --no-pager / -c
// core.pager=cat).
func TestGuard_GitConfigEnvPager(t *testing.T) {
	t.Setenv(auditEnvReadonly, "")

	t.Setenv(auditEnvRole, "worker")
	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "config-env core.pager", argv: []string{"git", "--config-env=core.pager=FOO", "log"}, want: "git --config-env core.pager"},
		{name: "config-env separate", argv: []string{"git", "--config-env", "core.pager=FOO", "log"}, want: "git --config-env core.pager"},
		{name: "no-pager ok", argv: []string{"git", "--no-pager", "log"}, want: ""},
		{name: "-c core.pager=cat ok", argv: []string{"git", "-c", "core.pager=cat", "log"}, want: ""},
		{name: "config-env benign key ok", argv: []string{"git", "--config-env=user.name=FOO", "log"}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	if got := guardArgvReadonly([]string{"git", "--config-env=core.pager=FOO", "log"}); !readonlyWantMatch(got, "git --config-env core.pager") {
		t.Fatalf("strict --config-env core.pager must block, got %q", got)
	}
	if got := guardArgvReadonly([]string{"git", "--no-pager", "log"}); got != "" {
		t.Fatalf("strict --no-pager must pass, got %q", got)
	}
}

// TestGuard_WrapperWriteOpChain locks the wrapper-chain traversal of
// wrapperWriteOpHit: prefixes and non-writing wrappers cannot hide a
// strace -o / time -o from the strict read-only guard.
func TestGuard_WrapperWriteOpChain(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "strace -o direct", argv: []string{"strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "env strace -o", argv: []string{"env", "strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "env FOO strace -o", argv: []string{"env", "FOO=1", "strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "assign prefix strace -o", argv: []string{"FOO=1", "strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "nice time -o", argv: []string{"FOO=1", "nice", "time", "-o", "/tmp/t", "ls"}, want: "time -o"},
		{name: "timeout strace -o", argv: []string{"timeout", "5", "strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "strace -a value -o", argv: []string{"strace", "-a", "40", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "strace --columns -o", argv: []string{"strace", "--columns", "80", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "nohup strace -o", argv: []string{"nohup", "strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "command strace -o", argv: []string{"command", "strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "if strace -o", argv: []string{"if", "strace", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "strace --output-append-mode -o", argv: []string{"strace", "--output-append-mode", "-o", "/tmp/t", "ls"}, want: "strace -o"},
		{name: "strace plain ok", argv: []string{"strace", "-f", "ls"}, want: "deleted"},
		{name: "env ls ok", argv: []string{"env", "FOO=1", "ls"}, want: "deleted"},
		{name: "time plain ok", argv: []string{"nice", "time", "ls"}, want: "deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_WatchAndXargsArity locks the GNU watch shell-exec semantics
// (default `sh -c` join; -x/--exec is a direct exec) and the xargs -e
// arity fix (lowercase -e takes only a glued optional arg).
func TestGuard_WatchAndXargsArity(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "watch quoted pig", argv: []string{"watch", "pig --help"}, want: "pig"},
		{name: "watch single word shell meta", argv: []string{"watch", "pig;id"}, want: "pig"},
		{name: "watch -dn cluster pig", argv: []string{"watch", "-dn", "1", "pig --help"}, want: "pig"},
		{name: "watch -dx cluster pig", argv: []string{"watch", "-dx", "pig"}, want: "pig"},
		{name: "watch -n pig text", argv: []string{"watch", "-n", "1", "pig --help"}, want: "pig"},
		{name: "watch -n1 agy text", argv: []string{"watch", "-n1", "agy run"}, want: "agy"},
		{name: "watch -x pig", argv: []string{"watch", "-x", "pig"}, want: "pig"},
		{name: "watch --exec pig", argv: []string{"watch", "--exec", "pig"}, want: "pig"},
		{name: "watch -- pig text", argv: []string{"watch", "--", "pig --help"}, want: "pig"},
		{name: "watch ls ok", argv: []string{"watch", "ls"}, want: ""},
		{name: "watch -x ls ok", argv: []string{"watch", "-x", "ls"}, want: ""},
		{name: "xargs -e pig", argv: []string{"xargs", "-e", "pig"}, want: "pig"},
		{name: "xargs -en pig", argv: []string{"xargs", "-en", "pig"}, want: "pig"},
		{name: "xargs -n 1 pig", argv: []string{"xargs", "-n", "1", "pig"}, want: "pig"},
		{name: "xargs -eEOF ok", argv: []string{"xargs", "-eEOF", "grep", "x"}, want: ""},
		{name: "xargs -E EOF pig", argv: []string{"xargs", "-E", "EOF", "pig"}, want: "pig"},
		{name: "xargs --eof=E pig", argv: []string{"xargs", "--eof=E", "pig"}, want: "pig"},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "watch rm text", argv: []string{"watch", "-n", "1", "rm -rf /tmp/x"}, want: "rm"},
		{name: "watch single word redirect", argv: []string{"watch", "echo>/tmp/x"}, want: "> /tmp/x"},
		{name: "watch ls ok", argv: []string{"watch", "ls"}, want: "deleted"},
		{name: "watch -x rm", argv: []string{"watch", "-x", "rm", "-f", "x"}, want: "rm"},
		{name: "xargs -e rm", argv: []string{"xargs", "-e", "rm"}, want: "rm"},
		{name: "xargs -en rm", argv: []string{"xargs", "-en", "rm"}, want: "rm"},
		{name: "xargs -eEOF wc ok", argv: []string{"xargs", "-eEOF", "wc", "-l"}, want: "deleted"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_SedAwkOptionClusters locks the combined short-option cluster
// support for sed (-ne/-nf) and awk (-e/--source/--file=, cluster tails)
// plus the lexer-level `system (` detection in awk programs.
func TestGuard_SedAwkOptionClusters(t *testing.T) {
	t.Setenv(auditEnvReadonly, "")

	t.Setenv(auditEnvRole, "worker")
	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "sed -ne e cmd", argv: []string{"sed", "-ne", "1e pig"}, want: "pig"},
		{name: "sed -neSCRIPT glued", argv: []string{"sed", "-ne1e pig", "/etc/hosts"}, want: "pig"},
		{name: "sed multi -ne scripts", argv: []string{"sed", "-ne", "1p", "-ne", "1e pig", "f"}, want: "pig"},
		{name: "sed -- script", argv: []string{"sed", "--", "1e pig", "f"}, want: "pig"},
		{name: "sed -rn e cmd", argv: []string{"sed", "-rn", "e pig"}, want: "pig"},
		{name: "sed -eSCRIPT glued", argv: []string{"sed", "-e1e pig"}, want: "pig"},
		{name: "awk -e system pig", argv: []string{"gawk", "-e", "BEGIN{system(\"pig\")}"}, want: "pig"},
		{name: "awk -ePROG glued", argv: []string{"gawk", "-eBEGIN{system(\"pig\")}"}, want: "pig"},
		{name: "awk --source pig", argv: []string{"gawk", "--source", "BEGIN{system(\"pig\")}"}, want: "pig"},
		{name: "awk --source= pig", argv: []string{"gawk", "--source=BEGIN{system(\"pig\")}"}, want: "pig"},
		{name: "awk two -e frags", argv: []string{"gawk", "-e", "BEGIN{x=1}", "-e", "END{system(\"pig\")}"}, want: "pig"},
		{name: "awk cluster -ne", argv: []string{"gawk", "-ne", "BEGIN{system(\"pig\")}"}, want: "pig"},
		{name: "awk -- program", argv: []string{"awk", "--", "-1 {system(\"pig\")}", "f"}, want: "pig"},
		{name: "awk -f skipped", argv: []string{"gawk", "-f", "/tmp/p.awk"}, want: ""},
		{name: "awk --file= skipped", argv: []string{"gawk", "--file=/tmp/p.awk"}, want: ""},
		{name: "awk -e benign ok", argv: []string{"gawk", "-e", "{print $1}"}, want: ""},
		{name: "sed -ne benign ok", argv: []string{"sed", "-ne", "1,20p"}, want: ""},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "reviewer")
	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "sed -ne w", argv: []string{"sed", "-ne", "s/a/b/w /tmp/x"}, want: "sed s///w"},
		{name: "sed -ne e cmd", argv: []string{"sed", "-ne", "1e pig"}, want: "sed e"},
		{name: "sed -nf file", argv: []string{"sed", "-nf", "/tmp/x.sed"}, want: "sed -f"},
		{name: "sed -rn e cmd", argv: []string{"sed", "-rn", "e rm -f x"}, want: "sed e"},
		{name: "sed -e file named warm.txt ok", argv: []string{"sed", "-e", "1p", "warm.txt"}, want: "deleted"},
		{name: "sed plain -n ok", argv: []string{"sed", "-n", "1,20p", "f"}, want: ""},
		{name: "gawk -e system  (", argv: []string{"gawk", "-e", "BEGIN{system  (\"pig\")}"}, want: "awk system("},
		{name: "awk system tab-paren", argv: []string{"awk", "BEGIN{system\t(\"rm f\")}"}, want: "awk system("},
		{name: "awk -ePROG system", argv: []string{"gawk", "-eBEGIN{system(\"rm f\")}"}, want: "awk system("},
		{name: "awk --file=", argv: []string{"gawk", "--file=/tmp/p.awk"}, want: "awk -f"},
		{name: "awk cluster -nf", argv: []string{"gawk", "-nf", "/tmp/p.awk"}, want: "awk -f"},
		{name: "awk regex /system(/ ok", argv: []string{"awk", "/system\\(/ {print}"}, want: "awk program"},
		{name: "awk plain ok", argv: []string{"awk", "{print $1}", "f"}, want: "awk program"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_SpawnPrimsAndHeredocBun locks the codeSpawnPrims additions
// (execv/execl/spawnl families) and the bun heredoc language mapping.
func TestGuard_SpawnPrimsAndHeredocBun(t *testing.T) {
	strict := guardCall{strictReadonly: true}
	sub := guardCall{subagent: true}

	roCases := []struct {
		name string
		lang string
		code string
		want bool
	}{
		{name: "os.execv", lang: "python", code: "import os; os.execv('/bin/sh',['sh','-c','ls'])", want: true},
		{name: "os.spawnl", lang: "python", code: "import os; os.spawnl(os.P_WAIT,'/bin/ls','ls')", want: true},
		{name: "os.execlp", lang: "python", code: "import os; os.execlp('ls','ls')", want: true},
		{name: "bare execv", lang: "python", code: "from os import execv; execv('/bin/sh',['sh','-c','ls'])", want: true},
		{name: "bare spawnl", lang: "python", code: "from os import spawnl; spawnl(0,'/bin/ls','ls')", want: true},
		{name: "plain json ok", lang: "python", code: "import json; print(json.dumps({}))", want: false},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			rule, _ := strict.guardCtxRunCode(tc.lang, tc.code)
			if (rule == ruleReadonlyWrite) != tc.want {
				t.Fatalf("guardCtxRunCode(%s,%q) rule = %q, want blocked=%v", tc.lang, tc.code, rule, tc.want)
			}
		})
	}

	// Sub-agent: a bare-import exec primitive naming a blocked agent.
	rule, _ := sub.guardCtxRunCode("python", "import os; os.execvp('pig',['pig'])")
	if rule != ruleSubagentNestedAgent {
		t.Fatalf("os.execvp pig must block under subagent, got %q", rule)
	}
	rule, _ = sub.guardCtxRunCode("python", "import os; os.execvp('ls',['ls'])")
	if rule != "" {
		t.Fatalf("os.execvp ls must pass under subagent, got %q", rule)
	}
	// Bare `from os import` spellings hit the same prims.
	rule, _ = sub.guardCtxRunCode("python", "from os import execvp; execvp('pig',['pig'])")
	if rule != ruleSubagentNestedAgent {
		t.Fatalf("from-import execvp pig must block under subagent, got %q", rule)
	}
	wrk := guardCall{} // worker: no spawn restriction at all
	rule, _ = wrk.guardCtxRunCode("python", "from os import execvp; execvp('ls',['ls'])")
	if rule != "" {
		t.Fatalf("from-import execvp ls must pass for worker, got %q", rule)
	}

	// bun heredoc: the body is javascript for the code guard.
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")
	code := "bun <<'JS'\nfs.writeFileSync('/tmp/x','a')\nJS"
	if got := guardShellReadonly(code); got == "" {
		t.Fatalf("bun heredoc write primitive must block")
	}
	t.Setenv(auditEnvRole, "worker")
	code = "bun <<'JS'\nrequire('child_process').execSync('pig')\nJS"
	if got := guardShellSubagent(code); got == "" {
		t.Fatalf("bun heredoc agent spawn must block")
	}
}

// TestGuard_SedTruncatedScriptsNoPanic locks the r3 bounds-hardening of
// sedExecCommands / sedScriptHasWrite: every truncated s///, regex-address
// and backslash-tail input must terminate without a slice-bounds panic and
// without missing a screening decision.
func TestGuard_SedTruncatedScriptsNoPanic(t *testing.T) {
	for _, s := range []string{
		"s", "s/", "s/a", "s/a\\", "s/a/b", "s/a/b\\", "s/a/b/e",
		"/", "/a\\", "\\", "s//", "1e", "1e \\",
	} {
		_ = sedExecCommands(s) // must not panic
		_ = sedScriptHasWrite(s)
	}
	// A well-formed s///e still extracts the replacement command.
	if got := sedExecCommands("s/.*/pig/e"); len(got) != 1 || got[0] != "pig" {
		t.Fatalf("sedExecCommands(s/.*/pig/e) = %v, want [pig]", got)
	}
}
