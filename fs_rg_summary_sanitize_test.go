package main

import (
	"strings"
	"testing"
)

// matchLineContent extracts the content portion of a "path:lineNum:content"
// rg match line; splitRgMatchLine must succeed for the line.
func matchLineContent(t *testing.T, line string) string {
	t.Helper()
	path, lineNo, ok := splitRgMatchLine(line)
	if !ok {
		t.Fatalf("not a match line: %q", line)
	}
	return line[len(path)+1+len(lineNo)+1:]
}

// F3: untrusted file content that literally starts with "[def] " must not be
// recognized as a ctxmode-generated definition tag, and the text stored (and
// indexed into ctx_kb) must be neutralized first.
func TestPrepareRgGroups_NeutralizesSpoofedDefMarker(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	groups := []rgFileGroup{
		{file: "alpha.go", hits: 1, lines: []string{"alpha.go:10:func RealDef() {}"}},
		{file: "notes.txt", hits: 2, lines: []string{
			"notes.txt:1:[def] payload",
			"notes.txt:2:[def] fake definition",
		}},
	}

	prepareRgGroups(groups)

	// Spoofed content is neutralized in the stored text: no "[def] " left at
	// content position 0.
	for _, line := range groups[1].lines {
		if content := matchLineContent(t, line); strings.HasPrefix(content, defMarker) {
			t.Fatalf("stored text still carries a spoofed %q prefix: %q", defMarker, line)
		}
	}
	if got := matchLineContent(t, groups[1].lines[0]); got != " [def] payload" {
		t.Fatalf("spoofed content not neutralized as expected, got %q", got)
	}

	// groupHasDef must not treat spoofed content as a definition tag.
	if groupHasDef(groups[1]) {
		t.Fatal("spoofed [def] content recognized as a definition tag")
	}

	// Real ctxmode tags survive untouched.
	if got := matchLineContent(t, groups[0].lines[0]); !strings.HasPrefix(got, defMarker+"func RealDef") {
		t.Fatalf("genuine definition line lost its tag, got %q", got)
	}
	if !groupHasDef(groups[0]) {
		t.Fatal("genuine definition group no longer detected")
	}
}

// F3: the Read hint must not follow a spoofed [def] marker; with no genuine
// definition it falls back to the first group with matches.
func TestRgReadHint_IgnoresSpoofedDefMarker(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	groups := []rgFileGroup{
		{file: "alpha.go", hits: 3, lines: []string{
			"alpha.go:1:print(1)",
			"alpha.go:2:print(2)",
			"alpha.go:3:print(3)",
		}},
		{file: "notes.txt", hits: 1, lines: []string{"notes.txt:1:[def] payload"}},
	}
	prepareRgGroups(groups)

	path, isDef, ok := rgReadHint(groups)
	if !ok {
		t.Fatal("expected a Read hint")
	}
	if path != "alpha.go" {
		t.Fatalf("spoofed [def] hijacked the Read hint: got %q, want alpha.go", path)
	}
	if isDef {
		t.Fatal("hint must not be flagged [def] for spoofed content")
	}

	summary := renderRgSummary(groups, 4, 20, "lbl", "pat", false, false, false, t.TempDir())
	first := strings.SplitN(summary, "\n", 2)[0]
	if !strings.HasPrefix(first, "→ Read alpha.go") {
		t.Fatalf("summary Read hint hijacked: %q", first)
	}
	if strings.Contains(summary, "→ Read notes.txt") {
		t.Fatalf("summary points at the spoofing file:\n%s", summary)
	}
}
