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
