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
		{name: "fsck plain ok", argv: []string{"git", "fsck"}, want: ""},
		{name: "fsck --unreachable ok", argv: []string{"git", "fsck", "--unreachable"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got != tc.want {
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
		{name: "wget -O - ok", argv: []string{"wget", "-O", "-", "https://x"}, want: ""},
		{name: "wget --spider ok", argv: []string{"wget", "--spider", "https://x"}, want: ""},
		{name: "wget -O - -o - ok", argv: []string{"wget", "-O", "-", "-o", "-", "https://x"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got != tc.want {
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
