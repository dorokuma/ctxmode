package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// === Merged from cli_test.go ===

func TestCLIUsage_ListsIndexSearchAndHelp(t *testing.T) {
	u := cliUsage()
	for _, want := range []string{"index <path>", "search <query>", "-h", "--help"} {
		if !strings.Contains(u, want) {
			t.Fatalf("cliUsage missing %q:\n%s", want, u)
		}
	}
}

func TestCLI_UnknownAndMissingArgs(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	var out bytes.Buffer
	if err := runCLI(s, []string{"nope"}, &out); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown command: %v", err)
	}
	if err := runCLI(s, []string{"index"}, &out); err == nil || !strings.Contains(err.Error(), "usage: ctxmode index") {
		t.Fatalf("index missing path: %v", err)
	}
	if err := runCLI(s, []string{"search"}, &out); err == nil || !strings.Contains(err.Error(), "usage: ctxmode search") {
		t.Fatalf("search missing query: %v", err)
	}
}

func TestCLI_IndexAndSearchSmoke(t *testing.T) {
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "hello.txt"), "unique-cli-token-abcdef\n")
	st := newTestStore(t)
	fg := NewFloodGuard(60*time.Second, 64)
	s := &server{
		workdirs:       []string{wd},
		store:          st,
		floodGuard:     fg,
		searchPipeline: NewSearchPipeline(st, fg),
		sessionID:      "cli-test",
	}

	var out bytes.Buffer
	if err := runCLI(s, []string{"index", wd}, &out); err != nil {
		t.Fatalf("index: %v", err)
	}
	if !strings.Contains(out.String(), "Indexed") {
		t.Fatalf("index output: %s", out.String())
	}

	out.Reset()
	if err := runCLI(s, []string{"search", "unique-cli-token-abcdef"}, &out); err != nil {
		t.Fatalf("search: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "hello.txt") && !strings.Contains(got, "unique-cli-token-abcdef") {
		t.Fatalf("search output missing hit:\n%s", got)
	}
}

// === Merged from cli_sanitize_test.go ===

// F4d: stripANSI must remove OSC, CSI, and other ESC sequences so KB content
// from untrusted sources cannot inject terminal control codes.
func TestStripANSI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text untouched", "hello world\n", "hello world\n"},
		{"osc bel", "\x1b]0;pwned\x07title gone", "title gone"},
		{"osc st", "\x1b]0;pwned\x1b\\title gone", "title gone"},
		{"osc unterminated drops rest", "keep\x1b]0;pwned", "keep"},
		{"csi sgr", "\x1b[31mred\x1b[0m", "red"},
		{"csi erase", "a\x1b[2Jb", "ab"},
		{"charset designation", "\x1b(Bplain", "plain"},
		{"two byte esc", "a\x1bMb", "ab"},
		{"dangling esc dropped", "tail\x1b", "tail"},
		{"bracket text kept", "[def] not an escape", "[def] not an escape"},
		{"mixed osc links", "\x1b]8;;http://x\x07link\x1b]8;;\x07!", "link!"},
	}
	for _, tc := range cases {
		if got := stripANSI(tc.in); got != tc.want {
			t.Errorf("%s: stripANSI(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// F4d: writeCLIText (the stdout path for both CLI commands) strips escapes
// and keeps the trailing newline behavior.
func TestWriteCLIText_StripsANSIAndKeepsNewline(t *testing.T) {
	var out bytes.Buffer
	if err := writeCLIText(&out, "\x1b]0;pwned\x07\x1b[31mKB content\x1b[0m"); err != nil {
		t.Fatalf("writeCLIText: %v", err)
	}
	if got, want := out.String(), "KB content\n"; got != want {
		t.Fatalf("writeCLIText output = %q, want %q", got, want)
	}
}
