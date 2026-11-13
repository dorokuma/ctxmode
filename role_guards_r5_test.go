package main

import (
	"testing"
)

// TestGuard_R5_JSTemplateBacktickPrescan covers the jsMask bodyEnd pre-scan
// that stops at the first nested backtick, blanking a later write primitive,
// and jsScanExpr early-close via // / block comments / regex literals.
func TestGuard_R5_JSTemplateBacktickPrescan(t *testing.T) {
	strict := guardCall{strictReadonly: true}
	cases := []struct {
		name string
		code string
		want bool // blocked?
	}{
		{
			name: "nested template before write",
			code: "`${`x` + fs.writeFileSync('/tmp/pwn','1')}`",
			want: true,
		},
		{
			name: "string with backtick before write",
			code: "`${\"`\" + fs.writeFileSync('/tmp/pwn','1')}`",
			want: true,
		},
		{
			name: "line comment closes brace early",
			code: "`${// }\nfs.writeFileSync('/tmp/pwn','1')}`",
			want: true,
		},
		{
			name: "block comment closes brace early",
			code: "`${/*}*/fs.writeFileSync('/tmp/pwn','1')}`",
			want: true,
		},
		{
			name: "regex literal closes brace early",
			code: "`${/}/; fs.writeFileSync('/tmp/pwn','1')}`",
			want: true,
		},
		{
			name: "nested template body mention only ok",
			code: "`${`fs.writeFileSync` + 1}`",
			want: false,
		},
		{
			name: "comment outside expression ok",
			code: "`hello` // fs.writeFileSync('/tmp/x','a')",
			want: false,
		},
		{
			name: "plain read still ok",
			code: "`${fs.readFileSync('/tmp/x')}`",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, detail := strict.guardCtxRunCode("javascript", tc.code)
			blocked := rule == ruleReadonlyWrite
			if blocked != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule=%q detail=%q, want blocked=%v",
					tc.code, rule, detail, tc.want)
			}
		})
	}
}

// TestGuard_R5_ExecShortOptCluster peels bash exec short-option clusters
// whose trailing 'a' consumes the next argv (internal_getopt "cla:").
func TestGuard_R5_ExecShortOptCluster(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "bash -c exec -la benign pig", argv: []string{"bash", "-c", "exec -la benign pig"}, want: "pig"},
		{name: "exec -la benign pig", argv: []string{"exec", "-la", "benign", "pig"}, want: "pig"},
		{name: "exec -ca benign agy", argv: []string{"exec", "-ca", "benign", "agy"}, want: "agy"},
		{name: "exec -cla benign pig", argv: []string{"exec", "-cla", "benign", "pig"}, want: "pig"},
		{name: "exec -abenign pig glued", argv: []string{"exec", "-abenign", "pig"}, want: "pig"},
		{name: "exec -cl -a name agy glued bools", argv: []string{"exec", "-cl", "-a", "x", "agy"}, want: "agy"},
		{name: "exec -la benign ls ok", argv: []string{"exec", "-la", "benign", "ls"}, want: ""},
		{name: "bash -c exec ls ok", argv: []string{"bash", "-c", "exec ls /tmp"}, want: ""},
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
		{name: "exec -la ls rm", argv: []string{"bash", "-c", "exec -la ls rm -rf /tmp/x"}, want: "rm"},
		{name: "exec -la ls ok", argv: []string{"bash", "-c", "exec -la ls ls /tmp"}, want: "exec"},
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

// TestGuard_R5_SqliteURIFragment truncates the #fragment before looking for
// ?mode=ro so a forged fragment cannot fake a read-only URI.
func TestGuard_R5_SqliteURIFragment(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "fragment fake query", uri: "file:/tmp/pwn.db#?mode=ro", want: false},
		{name: "fragment after real query", uri: "file:/tmp/pwn.db?cache=shared#&mode=ro", want: false},
		{name: "fragment after mode=ro ok", uri: "file:/tmp/x.db?mode=ro#frag", want: true},
		{name: "plain query mode=ro ok", uri: "file:/tmp/x.db?mode=ro", want: true},
		{name: "ampersand without query still false", uri: "file:/tmp/new.db&mode=ro", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sqliteURIModeRO(tc.uri)
			if got != tc.want {
				t.Fatalf("sqliteURIModeRO(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}

	strict := guardCall{strictReadonly: true}
	codeCases := []struct {
		name string
		code string
		want bool
	}{
		{name: "fragment uri blocked", code: "sqlite3.connect('file:/tmp/pwn.db#?mode=ro', uri=True)", want: true},
		{name: "real ro ok", code: "sqlite3.connect('file:/tmp/x.db?mode=ro', uri=True)", want: false},
	}
	for _, tc := range codeCases {
		t.Run("code/"+tc.name, func(t *testing.T) {
			rule, _ := strict.guardCtxRunCode("python", tc.code)
			blocked := rule == ruleReadonlyWrite
			if blocked != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule=%q, want blocked=%v", tc.code, rule, tc.want)
			}
		})
	}
}

// TestGuard_R5_WgetOptClusters covers glued short opts, short clusters,
// value-slot flags, extra disk-writing options, and long-option prefixes.
func TestGuard_R5_WgetOptClusters(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "glued -o/tmp", argv: []string{"wget", "-O", "-", "-o/tmp/log", "https://x"}, want: "wget"},
		{name: "glued -a/tmp", argv: []string{"wget", "--spider", "-a/tmp/log", "https://x"}, want: "wget"},
		{name: "cluster -qo log", argv: []string{"wget", "-O", "-", "-qo", "/tmp/log", "https://x"}, want: "wget"},
		{name: "cluster -qo/tmp", argv: []string{"wget", "-O", "-", "-qo/tmp/log", "https://x"}, want: "wget"},
		{name: "cluster -qO payload", argv: []string{"wget", "--spider", "-qO", "/tmp/payload", "https://x"}, want: "wget"},
		{name: "UA eats --spider", argv: []string{"wget", "-U", "--spider", "https://x"}, want: "wget"},
		{name: "--header eats --spider", argv: []string{"wget", "--header", "--spider", "https://x"}, want: "wget"},
		{name: "--rejected-log", argv: []string{"wget", "-O", "-", "--rejected-log=/tmp/rej", "https://x"}, want: "wget"},
		{name: "-b background", argv: []string{"wget", "-b", "-O", "-", "https://x"}, want: "wget"},
		{name: "--save-cookies", argv: []string{"wget", "-O", "-", "--save-cookies=/tmp/c", "https://x"}, want: "wget"},
		{name: "--warc-file", argv: []string{"wget", "-O", "-", "--warc-file=/tmp/w", "https://x"}, want: "wget"},
		{name: "--hsts-file", argv: []string{"wget", "-O", "-", "--hsts-file=/tmp/h", "https://x"}, want: "wget"},
		{name: "-e logfile=", argv: []string{"wget", "-O", "-", "-e", "logfile=/tmp/x", "https://x"}, want: "wget"},
		{name: "long prefix --output-f=", argv: []string{"wget", "-O", "-", "--output-f=/tmp/log", "https://x"}, want: "wget"},
		{name: "long prefix --append-o=", argv: []string{"wget", "--spider", "--append-o=/tmp/log", "https://x"}, want: "wget"},
		// Should Fix #9: allow common stdout spellings and help/version.
		{name: "-qO- ok", argv: []string{"wget", "-qO-", "https://x"}, want: "unknown command wget"},
		{name: "-qO - ok", argv: []string{"wget", "-qO", "-", "https://x"}, want: "unknown command wget"},
		{name: "-O /dev/stdout ok", argv: []string{"wget", "-O", "/dev/stdout", "https://x"}, want: "unknown command wget"},
		{name: "--help ok", argv: []string{"wget", "--help"}, want: "unknown command wget"},
		{name: "--version ok", argv: []string{"wget", "--version"}, want: "unknown command wget"},
		{name: "-O - still ok", argv: []string{"wget", "-O", "-", "https://x"}, want: "unknown command wget"},
		{name: "--spider still ok", argv: []string{"wget", "--spider", "https://x"}, want: "unknown command wget"},
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

// TestGuard_R5_SedAddrModifiers covers I/M after regex addresses and
// delimiters inside character classes that must not end the address.
func TestGuard_R5_SedAddrModifiers(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "custom I w", argv: []string{"sed", `\|root|Iw /tmp/out`}, want: "sed w"},
		{name: "slash M w", argv: []string{"sed", `/root/Mw /tmp/out`}, want: "sed w"},
		{name: "charclass custom delim w", argv: []string{"sed", `\|[|a]|w /tmp/out`}, want: "sed w"},
		{name: "charclass slash delim w", argv: []string{"sed", `/[/a]/w /tmp/out`}, want: "sed w"},
		{name: "I p ok", argv: []string{"sed", `-n`, `\|root|Ip`}, want: "sed cmd I"},
		{name: "charclass p ok", argv: []string{"sed", `-n`, `\|[|a]|p`}, want: "sed"},
	}
	for _, tc := range roCases {
		t.Run("ro/"+tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if !readonlyWantMatch(got, tc.want) {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}

	t.Setenv(auditEnvRole, "worker")
	subCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "custom Ie pig", argv: []string{"sed", `-n`, `\|root|Ie pig`}, want: "pig"},
		{name: "charclass e pig", argv: []string{"sed", `\|[|a]|e pig`}, want: "pig"},
		{name: "custom Ie ls", argv: []string{"sed", `-n`, `\|root|Ie ls`}, want: "sed e"},
	}
	for _, tc := range subCases {
		t.Run("sub/"+tc.name, func(t *testing.T) {
			got := guardArgvSubagent(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvSubagent(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_R5_FsckPrefixAndDashed covers git parse-options unique prefixes
// of --lost-found and direct git-fsck / path invocations.
func TestGuard_R5_FsckPrefixAndDashed(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "--lost", argv: []string{"git", "fsck", "--lost"}, want: "git fsck --lost-found"},
		{name: "--lost-f", argv: []string{"git", "fsck", "--lost-f"}, want: "git fsck --lost-found"},
		{name: "--lo", argv: []string{"git", "fsck", "--lo"}, want: "git fsck --lost-found"},
		{name: "--l", argv: []string{"git", "fsck", "--l"}, want: "git fsck --lost-found"},
		{name: "git-fsck dashed", argv: []string{"git-fsck", "--lost-found"}, want: "git fsck --lost-found"},
		{name: "git-fsck --lost", argv: []string{"git-fsck", "--lost"}, want: "git fsck --lost-found"},
		{name: "path git-fsck", argv: []string{"/usr/lib/git-core/git-fsck", "--lost-found"}, want: "git fsck --lost-found"},
		{name: "plain fsck ok", argv: []string{"git", "fsck"}, want: "fsck"},
		{name: "fsck --unreachable ok", argv: []string{"git", "fsck", "--unreachable"}, want: "fsck"},
		{name: "git-fsck plain ok", argv: []string{"git-fsck"}, want: "fsck"},
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

// TestGuard_R5_CodeAgentAtFalsePositive ensures "at" only trips when it is a
// real command-word spawn context, not comments / .at( / prose.
func TestGuard_R5_CodeAgentAtFalsePositive(t *testing.T) {
	sub := guardCall{subagent: true}
	cases := []struct {
		name string
		code string
		want bool
	}{
		{name: "comment failed at line", code: "import subprocess; subprocess.run(cmd)  # failed at line 3", want: false},
		{name: "js arr.at", code: "const {execFileSync}=require('child_process'); execFileSync(cmd); arr.at(-1)", want: false},
		{name: "prose string at", code: "import os; os.system(x); msg='failed at line 3'", want: false},
		{name: "static at argv still blocked", code: "import subprocess; subprocess.run(['at','now'])", want: true},
		{name: "shell string at cmd", code: "import os; os.system('at now')", want: true},
		{name: "dynamic string at cmd", code: "import subprocess; subprocess.run(cmd); x='at now'", want: true},
		{name: "static ls ok", code: "import subprocess; subprocess.run(['ls'])", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, detail := sub.guardCtxRunCode("python", tc.code)
			if tc.name == "js arr.at" {
				rule, detail = sub.guardCtxRunCode("javascript", tc.code)
			}
			blocked := rule == ruleSubagentNestedAgent
			if blocked != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule=%q detail=%q, want blocked=%v",
					tc.code, rule, detail, tc.want)
			}
		})
	}
}

// TestGuard_R5_JSScanExprStringMask blanks strings inside ${} so a string
// that merely mentions a write primitive is not treated as a call, and keeps
// jsScanExpr indexes within [0,end].
func TestGuard_R5_JSScanExprStringMask(t *testing.T) {
	strict := guardCall{strictReadonly: true}
	cases := []struct {
		name string
		code string
		want bool
	}{
		{name: "string mention in ${} ok", code: "`${\"fs.writeFileSync\"}`", want: false},
		{name: "single-quoted mention ok", code: "`${'fs.writeFileSync'}`", want: false},
		{name: "real call still blocked", code: "`${fs.writeFileSync('/tmp/x','a')}`", want: true},
		{name: "unterminated quote backslash no panic", code: "`${" + "'\\", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %q: %v", tc.code, r)
				}
			}()
			rule, detail := strict.guardCtxRunCode("javascript", tc.code)
			blocked := rule == ruleReadonlyWrite
			if blocked != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule=%q detail=%q, want blocked=%v",
					tc.code, rule, detail, tc.want)
			}
		})
	}

	// Direct index contract: jsScanExpr must never return > end.
	b := []byte(`${'\`)
	end := len(b)
	got := jsScanExpr(b, 2, end, 1)
	if got > end {
		t.Fatalf("jsScanExpr returned %d > end %d", got, end)
	}
}
