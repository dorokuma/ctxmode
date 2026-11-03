package main

import (
	"strings"
	"testing"
)

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
			if !strings.Contains(got, "process substitution") {
				t.Fatalf("expected process substitution in detail, got %q", got)
			}
		})
	}
	t.Run("bash -c argv process subst", func(t *testing.T) {
		got := guardArgvReadonly([]string{"bash", "-c", "cat <(echo hi)"})
		if got == "" {
			t.Fatal("expected block")
		}
		if !strings.Contains(got, "process substitution") {
			t.Fatalf("expected process substitution, got %q", got)
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
		{name: "curl -w", argv: []string{"curl", "-s", "-w", "%{http_code}", "https://example.com"}},
		{name: "curl -X GET", argv: []string{"curl", "-s", "-X", "GET", "https://example.com"}},
		{name: "curl -o dash", argv: []string{"curl", "-s", "-o", "-", "https://example.com"}},
		{name: "curl -o /dev/null", argv: []string{"curl", "-s", "-o", "/dev/null", "https://example.com"}},
		{name: "curl --head", argv: []string{"curl", "--head", "https://example.com"}},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got != "" {
				t.Fatalf("expected allow, got %q", got)
			}
		})
	}

	block := []struct {
		name string
		argv []string
		want string
	}{
		{name: "stderr", argv: []string{"curl", "--stderr", "/tmp/pwn", "https://x"}, want: "stderr"},
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
			if !strings.Contains(got, tc.want) && !strings.Contains(got, "curl") {
				t.Fatalf("expected %q in detail, got %q", tc.want, got)
			}
		})
	}
}

// Must Fix #3: sqlite3 requires -readonly AND SQL positional; no stdin/pipe.
func TestReadonlyAllowlist_SqliteStrict(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	t.Run("allow with sql", func(t *testing.T) {
		got := guardArgvReadonly([]string{"sqlite3", "-readonly", "/tmp/x.db", "SELECT 1"})
		if got != "" {
			t.Fatalf("expected allow, got %q", got)
		}
	})
	block := []struct {
		name string
		argv []string
		code string
		want string
	}{
		{name: "no sql argv", argv: []string{"sqlite3", "-readonly", "/tmp/x.db"}, want: "sql"},
		{name: "piped stdin", code: `echo '.shell id' | sqlite3 -readonly /tmp/x.db`, want: "sql"},
		{name: "heredoc", code: "sqlite3 -readonly /tmp/x.db <<'EOF'\n.shell id\nEOF", want: "sql"},
		{name: "here string", code: `sqlite3 -readonly /tmp/x.db <<< '.shell id'`, want: "sql"},
		{name: "missing readonly", argv: []string{"sqlite3", "/tmp/x.db", "SELECT 1"}, want: "readonly"},
		{name: "dot shell in sql", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", ".shell id"}, want: "dot-command"},
	}
	for _, tc := range block {
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
			if !strings.Contains(strings.ToLower(got), tc.want) &&
				!strings.Contains(got, "sqlite3") {
				t.Fatalf("expected %q in %q", tc.want, got)
			}
		})
	}
}

// Must Fix #4: go fmt must be denied; gofmt -d/-l stay allowed.
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
		{name: "gcc --version", argv: []string{"gcc", "--version"}},
		{name: "mount -l", argv: []string{"mount", "-l"}},
		{name: "tar -tf", argv: []string{"tar", "-tf", "a.tar"}},
		{name: "gzip -l", argv: []string{"gzip", "-l", "file.gz"}},
		{name: "gzip -dc", argv: []string{"gzip", "-dc", "file.gz"}},
		{name: "unzip -l", argv: []string{"unzip", "-l", "a.zip"}},
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
		{name: "sqlite no ro", argv: []string{"sqlite3", "/tmp/x.db", "SELECT 1"}, hint: "-readonly"},
		{name: "go test", argv: []string{"go", "test", "./..."}, hint: "verifier"},
		{name: "process subst", code: `cat <(echo hi)`, hint: "pipe"},
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
	allow := []struct {
		name string
		argv []string
	}{
		{name: "make --version", argv: []string{"make", "--version"}},
		{name: "make -v", argv: []string{"make", "-v"}},
		{name: "make --help", argv: []string{"make", "--help"}},
		{name: "make -h", argv: []string{"make", "-h"}},
		{name: "gmake --version", argv: []string{"gmake", "--version"}},
		{name: "gcc --version", argv: []string{"gcc", "--version"}},
		{name: "gcc -dumpversion", argv: []string{"gcc", "-dumpversion"}},
		{name: "clang --help", argv: []string{"clang", "--help"}},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if got := screenReadonlyAllowlist(tc.argv); got != "" {
				t.Fatalf("screenReadonlyAllowlist(%v) = %q, want allow", tc.argv, got)
			}
			if got := guardArgvReadonly(tc.argv); got != "" {
				t.Fatalf("guardArgvReadonly(%v) = %q, want allow", tc.argv, got)
			}
		})
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
	// Non-@ header values still allowed.
	if got := guardArgvReadonly([]string{"curl", "-s", "-H", "Accept: application/json", "https://x"}); got != "" {
		t.Fatalf("plain -H value must allow, got %q", got)
	}
	if got := guardArgvReadonly([]string{"curl", "-s", "--header=Accept: text/plain", "https://x"}); got != "" {
		t.Fatalf("plain --header= value must allow, got %q", got)
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
		{name: "SELECT", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "SELECT 1"}},
		{name: "select lower", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "select 1"}},
		{name: "WITH", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "WITH c AS (SELECT 1) SELECT * FROM c"}},
		{name: "EXPLAIN", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "EXPLAIN SELECT 1"}},
		{name: "EXPLAIN QUERY PLAN", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "EXPLAIN QUERY PLAN SELECT 1"}},
		{name: "PRAGMA info", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "PRAGMA table_info(t)"}},
		{name: "--version alone", argv: []string{"sqlite3", "--version"}},
		{name: "-version alone", argv: []string{"sqlite3", "-version"}},
		{name: "--help alone", argv: []string{"sqlite3", "--help"}},
		{name: "-help alone", argv: []string{"sqlite3", "-help"}},
	}
	for _, tc := range allow {
		t.Run("allow/"+tc.name, func(t *testing.T) {
			if got := guardArgvReadonly(tc.argv); got != "" {
				t.Fatalf("expected allow for %v, got %q", tc.argv, got)
			}
		})
	}

	block := []struct {
		name string
		argv []string
		want string
	}{
		{name: ".read", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", ".read evil.sql"}, want: "dot"},
		{name: ".READ upper", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", ".READ evil.sql"}, want: "dot"},
		{name: ".load", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", ".load evil.so"}, want: "dot"},
		{name: ".LOAD", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", ".LOAD /tmp/x.so"}, want: "dot"},
		{name: ".shell", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", ".shell id"}, want: "dot"},
		{name: "multi stmt dot", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "SELECT 1; .shell id"}, want: "dot"},
		{name: "newline dot", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "SELECT 1\n.read x"}, want: "dot"},
		{name: "leading ws dot", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "  .read x"}, want: "dot"},
		{name: "INSERT", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "INSERT INTO t VALUES(1)"}, want: "sql"},
		{name: "DELETE", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "DELETE FROM t"}, want: "sql"},
		{name: "ATTACH", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "ATTACH 'x' AS o"}, want: "sql"},
		{name: "PRAGMA assign", argv: []string{"sqlite3", "-readonly", "/tmp/x.db", "PRAGMA soft_heap_limit=1000"}, want: "pragma"},
		{name: "version with db needs ro", argv: []string{"sqlite3", "--version", "/tmp/x.db"}, want: "readonly"},
		{name: "help with db needs ro", argv: []string{"sqlite3", "-help", "/tmp/x.db"}, want: "readonly"},
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
