package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rg_label_test.go covers the summary label layer (fs_rg_summary.go):
// group labels and Read hints must name the real file even when the rg line
// is ambiguous (a path containing ":<digits>:" parses as its first colon
// split), while normal unambiguous output stays byte-identical.

// Control goldens: normal, unambiguous rg output must render byte-identically
// regardless of the label-disambiguation change. These run against real files
// under a temp workdir so rgFileSizeTag resolves (small files -> empty tag).

func TestRgLabel_NormalPathSummaryGolden(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "plain-a.txt"), "alpha hit\nline\nbeta hit\n")
	mustWrite(t, filepath.Join(dir, "sub", "plain-b.md"), "gamma\n")

	groups := []rgFileGroup{
		{file: "plain-a.txt", hits: 2, lines: []string{"plain-a.txt:1:alpha hit", "plain-a.txt:5:beta hit"}},
		{file: "sub/plain-b.md", hits: 1, lines: []string{"sub/plain-b.md:2:gamma"}},
	}
	got := renderRgSummary(groups, 3, 20, "sess:test:rg:golden", "alpha", false, false, false, dir)
	want := strings.Join([]string{
		"→ Read plain-a.txt",
		`3 matches in 2 files (full set indexed, > first-screen limit 20). Retrieve details: ctx_kb action=search query="sess:test:rg:golden" scope=rg or page raw lines: ctx_fs action=rg pattern="alpha" offset=20`,
		"Files (M=modified, A=added, ??=untracked; then by match count):",
		"plain-a.txt 2 matches",
		"  1: alpha hit",
		"  5: beta hit",
		"sub/plain-b.md 1 match",
		"  2: gamma",
	}, "\n")
	if got != want {
		t.Errorf("summary golden mismatch.\nGot:\n%q\nWant:\n%q", got, want)
	}
}

func TestRgLabel_NormalPathReadHintGolden(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "plain-a.txt"), "alpha hit\n")

	groups := []rgFileGroup{
		{file: "plain-a.txt", hits: 2, lines: []string{"plain-a.txt:1:alpha hit", "plain-a.txt:5:beta hit"}},
	}
	body := renderGroups(groups)
	got := prependReadHint(body, groups, dir)
	want := "→ Read plain-a.txt\n" + body
	if got != want {
		t.Errorf("read-hint golden mismatch.\nGot:\n%q\nWant:\n%q", got, want)
	}
}

// TestRgLabel_AmbiguousPathSummaryE2E feeds fake rg output (same technique as
// TestSecurityFixes_AmbiguousPathOutputFence) through toolRg: a non-sensitive
// file under a directory "x:12:y" must be labeled with its real path in the
// summary file list and in the Read hint, not with the mis-split prefix "x",
// on both the indexed summary path and the raw-body path.
func TestRgLabel_AmbiguousPathSummaryE2E(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "x:12:y", "notes.md"), "hit one\nmid\nhit two\n")

	script := "#!/bin/sh\n" +
		"root=\"\"\n" +
		"for a; do root=\"$a\"; done\n" +
		"echo \"${root}/x:12:y/notes.md:1:hit one\"\n" +
		"echo \"${root}/x:12:y/notes.md-2-mid\"\n" +
		"echo \"${root}/x:12:y/notes.md:3:hit two\"\n"
	fake := filepath.Join(dir, "rg")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s := &server{
		workdirs:        []string{dir},
		store:           newTestStore(t),
		sessionID:       "sess-rglabel",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	// Indexed summary path: totalHits > limit.
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "hit", Path: dir, Limit: 1})
	if err != nil {
		t.Fatalf("toolRg summary path: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "x:12:y/notes.md 3 matches") {
		t.Errorf("summary file label must show the real path, got:\n%s", text)
	}
	if !strings.Contains(text, "→ Read x:12:y/notes.md") {
		t.Errorf("Read hint must show the real path, got:\n%s", text)
	}
	if strings.Contains(text, "x 3 matches") || strings.Contains(text, "→ Read x\n") {
		t.Errorf("summary must not label the mis-split prefix \"x\", got:\n%s", text)
	}

	// Raw-body path: totalHits <= limit, hint over raw groups.
	res, _, err = s.toolRg(context.Background(), nil, rgArgs{Pattern: "hit", Path: dir, Limit: 10})
	if err != nil {
		t.Fatalf("toolRg raw path: %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "→ Read x:12:y/notes.md") {
		t.Errorf("raw-path Read hint must show the real path, got:\n%s", text)
	}
	if strings.Contains(text, "→ Read x\n") {
		t.Errorf("raw path must not hint the mis-split prefix \"x\", got:\n%s", text)
	}
	// Raw lines (match and context forms) must survive byte-identically.
	for _, raw := range []string{
		"x:12:y/notes.md:1:hit one",
		"x:12:y/notes.md-2-mid",
		"x:12:y/notes.md:3:hit two",
	} {
		if !strings.Contains(text, raw) {
			t.Errorf("raw line %q must be preserved, got:\n%s", raw, text)
		}
	}
}

// TestRgLabel_AmbiguousPathUnitResolution pins the resolution rule on
// groupRgLines output: the legacy mis-split label "x" is rewritten to the
// stat-verified real path; renderRgSummary and prependReadHint both surface
// it while the caller slice stays untouched.
func TestRgLabel_AmbiguousPathUnitResolution(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "x:12:y", "notes.md")
	mustWrite(t, base, "hit one\nhit two\n")
	legacy := filepath.Join(dir, "x")

	groups := groupRgLines([]string{base + ":1:hit one", base + ":2:hit two"})
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].file != legacy {
		t.Fatalf("pre-resolution parse should be the legacy split %q, got %q", legacy, groups[0].file)
	}

	fixed := make([]rgFileGroup, len(groups))
	copy(fixed, groups)
	disambiguateRgGroupLabels(fixed, dir)
	if fixed[0].file != base {
		t.Fatalf("disambiguated label = %q, want real path %q", fixed[0].file, base)
	}
	if groups[0].file != legacy {
		t.Fatalf("caller slice must not be mutated, got %q", groups[0].file)
	}

	text := renderRgSummary(groups, 2, 20, "sess:test:rg:unit", "hit", false, false, false, dir)
	if !strings.Contains(text, base+" 2 matches") || !strings.Contains(text, "→ Read "+base) {
		t.Errorf("summary must label the real path, got:\n%s", text)
	}
	if strings.Contains(text, "\n"+legacy+" 2 matches") || strings.Contains(text, "→ Read "+legacy+"\n") {
		t.Errorf("summary must not label the mis-split prefix %q, got:\n%s", legacy, text)
	}

	body := renderGroups(groups)
	if got, want := prependReadHint(body, groups, dir), "→ Read "+base+"\n"+body; got != want {
		t.Errorf("read hint mismatch.\nGot:\n%q\nWant:\n%q", got, want)
	}
}

// TestRgLabel_AmbiguousPathFallback: when no candidate stats (file gone or
// fake output without a fixture), the legacy parse is kept so labels for
// vanished files stay byte-identical.
func TestRgLabel_AmbiguousPathFallback(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "x:12:y", "notes.md")
	legacy := filepath.Join(dir, "x")

	groups := groupRgLines([]string{base + ":1:hit one", base + "-2-ctx"})
	if len(groups) != 1 || groups[0].file != legacy {
		t.Fatalf("expected single legacy-parsed group, got %+v", groups)
	}
	fixed := make([]rgFileGroup, len(groups))
	copy(fixed, groups)
	disambiguateRgGroupLabels(fixed, dir)
	if fixed[0].file != legacy {
		t.Fatalf("fallback must keep the legacy parse %q, got %q", legacy, fixed[0].file)
	}
}

// TestRgLabel_ContextAndMatchLabelsConsistent: context lines
// ("path-N-content") and match lines mixed in one block resolve to the same
// label; for normal paths the label is untouched.
func TestRgLabel_ContextAndMatchLabelsConsistent(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "x:12:y", "notes.md")
	mustWrite(t, base, "prev\nhit\nafter\n")
	legacy := filepath.Join(dir, "x")

	// rg -C 1 style block: context, match, context. All lines carry the
	// ":12:" ambiguity and parse to the same legacy prefix.
	lines := []string{base + "-1-prev", base + ":2:hit", base + "-3-after"}
	groups := groupRgLines(lines)
	if len(groups) != 1 || groups[0].file != legacy {
		t.Fatalf("expected 1 group with legacy parse %q, got %+v", legacy, groups)
	}
	if groups[0].hits != 3 {
		t.Fatalf("expected 3 match-counted lines, got %d", groups[0].hits)
	}
	fixed := make([]rgFileGroup, len(groups))
	copy(fixed, groups)
	disambiguateRgGroupLabels(fixed, dir)
	if fixed[0].file != base {
		t.Fatalf("mixed context/match group label = %q, want %q", fixed[0].file, base)
	}

	// Normal-path control: context and match lines already share one exact
	// label, and disambiguation leaves it byte-identical.
	norm := groupRgLines([]string{"sub/f.md-1-ctx", "sub/f.md:2:hit", "sub/f.md-3-after"})
	if len(norm) != 1 || norm[0].file != "sub/f.md" {
		t.Fatalf("expected 1 group labeled sub/f.md, got %+v", norm)
	}
	nfix := make([]rgFileGroup, len(norm))
	copy(nfix, norm)
	disambiguateRgGroupLabels(nfix, dir)
	if nfix[0].file != "sub/f.md" {
		t.Fatalf("normal label must stay byte-identical, got %q", nfix[0].file)
	}
}
