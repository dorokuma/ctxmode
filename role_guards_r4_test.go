package main

import (
	"testing"
)

// TestGuard_R4_FsckLostFound blocks git fsck write options such as
// --lost-found while plain fsck stays free.
func TestGuard_R4_FsckLostFound(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "fsck --lost-found", argv: []string{"git", "fsck", "--lost-found"}, want: "git fsck --lost-found"},
		{name: "fsck --lost-found variant order", argv: []string{"git", "fsck", "--unreachable", "--lost-found"}, want: "git fsck --lost-found"},
		{name: "fsck plain ok", argv: []string{"git", "fsck"}, want: "fsck"},
		{name: "fsck --unreachable ok", argv: []string{"git", "fsck", "--unreachable"}, want: "fsck"},
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

// TestGuard_R4_WgetLogFile blocks wget log-to-disk flags (-o/-a/
// --output-file/--append-output) even when -O - / --spider would otherwise
// allow the download itself.
func TestGuard_R4_WgetLogFile(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "wget -O - -o log", argv: []string{"wget", "-O", "-", "-o", "/tmp/log", "https://x"}, want: "wget"},
		{name: "wget --spider --output-file", argv: []string{"wget", "--spider", "--output-file=/tmp/log", "https://x"}, want: "wget"},
		{name: "wget -O - -a log", argv: []string{"wget", "-O", "-", "-a", "/tmp/log", "https://x"}, want: "wget"},
		{name: "wget -O - ok", argv: []string{"wget", "-O", "-", "https://x"}, want: "unknown command wget"},
		{name: "wget --spider ok", argv: []string{"wget", "--spider", "https://x"}, want: "unknown command wget"},
		{name: "wget -O - -o - ok", argv: []string{"wget", "-O", "-", "-o", "-", "https://x"}, want: "unknown command wget"},
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

// TestGuard_R4_SqliteURIModeRO requires mode=ro to live in the URI query
// segment after '?', not as a raw '&mode=ro' glued onto the path.
func TestGuard_R4_SqliteURIModeRO(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "ampersand without query", uri: "file:/tmp/new.db&mode=ro", want: false},
		{name: "ampersand path variant", uri: "file:new.db&mode=ro&cache=shared", want: false},
		{name: "query mode=ro ok", uri: "file:/tmp/x.db?mode=ro", want: true},
		{name: "query with prior params ok", uri: "file:/tmp/x.db?cache=shared&mode=ro", want: true},
		{name: "query mode=rw", uri: "file:/tmp/x.db?mode=rw", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sqliteURIModeRO(tc.uri)
			if got != tc.want {
				t.Fatalf("sqliteURIModeRO(%q) = %v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

// TestGuard_R4_SqliteConnectArgs rejects a second positional argument and
// unknown keyword arguments even when the database URI looks read-only.
func TestGuard_R4_SqliteConnectArgs(t *testing.T) {
	cases := []struct {
		name string
		args string
		want bool // true = treated as readonly (allowed)
	}{
		{name: "extra positional", args: "'file:/tmp/x.db?mode=ro', True, uri=True", want: false},
		{name: "unknown kwarg bogus", args: "database='file:/tmp/x.db?mode=ro', uri=True, bogus=1", want: false},
		{name: "unknown kwarg factory", args: "'file:/tmp/x.db?mode=ro', uri=True, factory=MyFactory", want: false},
		{name: "plain ro ok", args: "'file:/tmp/x.db?mode=ro', uri=True", want: true},
		{name: "kwarg ro ok", args: "database='file:/tmp/x.db?mode=ro', uri=True", want: true},
		{name: "timeout kwarg ok", args: "'file:/tmp/x.db?mode=ro', timeout=5.0, uri=True", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sqliteConnectReadonly(tc.args, tc.args)
			if got != tc.want {
				t.Fatalf("sqliteConnectReadonly(%q) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestGuard_R4_SqliteConnectViaCode wires the URI/args rules through
// guardCtxRunCode for a strict read-only caller.
func TestGuard_R4_SqliteConnectViaCode(t *testing.T) {
	strict := guardCall{strictReadonly: true}
	cases := []struct {
		name string
		code string
		want bool // blocked?
	}{
		{name: "ampersand uri blocked", code: "sqlite3.connect('file:/tmp/new.db&mode=ro', uri=True)", want: true},
		{name: "extra positional blocked", code: "sqlite3.connect('file:/tmp/x.db?mode=ro', True, uri=True)", want: true},
		{name: "query mode=ro ok", code: "sqlite3.connect('file:/tmp/x.db?mode=ro', uri=True)", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, _ := strict.guardCtxRunCode("python", tc.code)
			blocked := rule == ruleReadonlyWrite
			if blocked != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule=%q, want blocked=%v", tc.code, rule, tc.want)
			}
		})
	}
}

// TestGuard_R4_ExecDashA peels bash exec -a/-c/-l so the real command head
// is screened for nested-agent dispatch.
func TestGuard_R4_ExecDashA(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "bash -c exec -a benign pig", argv: []string{"bash", "-c", "exec -a benign pig"}, want: "pig"},
		{name: "exec -a name pig direct", argv: []string{"exec", "-a", "benign", "pig"}, want: "pig"},
		{name: "exec -c -l -a name agy", argv: []string{"exec", "-c", "-l", "-a", "x", "agy"}, want: "agy"},
		{name: "exec -cl -a name agy", argv: []string{"exec", "-cl", "-a", "x", "agy"}, want: "agy"},
		{name: "exec -a name ls ok", argv: []string{"exec", "-a", "benign", "ls"}, want: ""},
		{name: "bash -c exec ls ok", argv: []string{"bash", "-c", "exec ls /tmp"}, want: ""},
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

// TestGuard_R4_XargsEof treats bare --eof as a flag that does not consume
// the next argv (GNU optional value must use --eof=STR).
func TestGuard_R4_XargsEof(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "xargs --eof pig", argv: []string{"xargs", "--eof", "pig"}, want: "pig"},
		{name: "xargs --eof -- pig", argv: []string{"xargs", "--eof", "--", "pig"}, want: "pig"},
		{name: "xargs --eof=STOP pig", argv: []string{"xargs", "--eof=STOP", "pig"}, want: "pig"},
		{name: "xargs -E STOP pig", argv: []string{"xargs", "-E", "STOP", "pig"}, want: "pig"},
		{name: "xargs --eof ls ok", argv: []string{"xargs", "--eof", "ls"}, want: ""},
		{name: "xargs -0 ls ok", argv: []string{"xargs", "-0", "ls"}, want: ""},
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

// TestGuard_R4_SedNegationAndCustomAddr covers sed address negation (!)
// and \c...\c custom-delimiter addresses before w/e commands.
func TestGuard_R4_SedNegationAndCustomAddr(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	roCases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "sed 1!w", argv: []string{"sed", "1!w /tmp/out"}, want: "sed w"},
		{name: "sed /pat/!w", argv: []string{"sed", "/root/!w /tmp/out"}, want: "sed w"},
		{name: "sed custom delim w", argv: []string{"sed", `\|root|w /tmp/out`}, want: "sed w"},
		{name: "sed custom delim W", argv: []string{"sed", `\#root#W /tmp/out`}, want: "sed W"},
		{name: "sed plain w still", argv: []string{"sed", "w /tmp/out"}, want: "sed w"},
		{name: "sed -n p ok", argv: []string{"sed", "-n", "1!p"}, want: "sed"},
		{name: "sed custom delim p ok", argv: []string{"sed", `-n`, `\|root|p`}, want: "sed"},
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
		{name: "sed custom delim e pig", argv: []string{"sed", `\|root|e pig`}, want: "pig"},
		{name: "sed 1!e agy", argv: []string{"sed", "1!e agy"}, want: "agy"},
		{name: "sed custom delim e ls", argv: []string{"sed", `\|root|e ls`}, want: "sed e"},
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

// TestGuard_R4_JSTemplateBraceDepth keeps ${} expressions intact when they
// contain nested object literals, strings, or nested templates so write
// primitives inside the expression are still visible to the screen.
func TestGuard_R4_JSTemplateBraceDepth(t *testing.T) {
	strict := guardCall{strictReadonly: true}
	cases := []struct {
		name string
		code string
		want bool // blocked?
	}{
		{
			name: "object literal in ${}",
			code: "`${({a:1}, fs.writeFileSync('/tmp/x','a'))}`",
			want: true,
		},
		{
			name: "nested braces variant",
			code: "`${({a:{b:2}}, fs.appendFileSync('/tmp/y','b'))}`",
			want: true,
		},
		{
			name: "string with braces in ${}",
			code: "`${(fs.writeFileSync('/tmp/z','{not}'), 1)}`",
			want: true,
		},
		{
			name: "nested template in ${}",
			code: "`${(fs.writeFileSync('/tmp/n',`{x}`), 1)}`",
			want: true,
		},
		{
			name: "template body mention only ok",
			code: "`hello fs.writeFileSync ignored ${1+1}`",
			want: false,
		},
		{
			name: "plain read in ${} ok",
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

// TestGuard_R4_CodeAgentNamesAlign checks codeAgentNames covers every
// argv-side blockedAgentExecutables entry (at least ssh/sudo) and that
// unresolved code spawns naming those targets are blocked.
func TestGuard_R4_CodeAgentNamesAlign(t *testing.T) {
	names := map[string]bool{}
	for _, n := range codeAgentNames {
		names[n] = true
	}
	for n := range blockedAgentExecutables {
		if !names[n] {
			t.Errorf("codeAgentNames missing argv-blocked %q", n)
		}
	}
	for _, need := range []string{"ssh", "sudo"} {
		if !names[need] {
			t.Errorf("codeAgentNames must include %q", need)
		}
	}

	sub := guardCall{subagent: true}
	cases := []struct {
		name string
		code string
		want bool
	}{
		{name: "dynamic spawn ssh", code: "import subprocess; subprocess.run(cmd)  # ssh", want: true},
		{name: "dynamic spawn sudo", code: "import os; os.system(x)  # sudo -u root id", want: true},
		{name: "static ssh argv", code: "import subprocess; subprocess.run(['ssh','host'])", want: true},
		{name: "static sudo argv", code: "import subprocess; subprocess.run(['sudo','id'])", want: true},
		{name: "mention ssh no spawn ok", code: "x = 'ssh'; print(x)", want: false},
		{name: "static ls ok", code: "import subprocess; subprocess.run(['ls'])", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, detail := sub.guardCtxRunCode("python", tc.code)
			blocked := rule == ruleSubagentNestedAgent
			if blocked != tc.want {
				t.Fatalf("guardCtxRunCode(%q) rule=%q detail=%q, want blocked=%v",
					tc.code, rule, detail, tc.want)
			}
		})
	}
}
