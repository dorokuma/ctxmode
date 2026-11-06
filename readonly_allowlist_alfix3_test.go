package main

import (
	"strings"
	"testing"
)

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
