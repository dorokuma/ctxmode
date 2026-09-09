package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
