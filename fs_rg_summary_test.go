package main

import (
	"testing"
)

func TestGroupRgLines_ContextAttached(t *testing.T) {
	input := []string{
		"pkg/foo-bar.go:10:func DoWork() {",
		"pkg/foo-bar.go-11-    // context line 1",
		"pkg/foo-bar.go-12-    // context line 2",
		"--",
		"pkg/foo-bar.go:20:func AnotherWork() {",
		"other/baz.go:5:const Pi = 3.14",
	}

	groups := groupRgLines(input)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	if groups[0].file != "pkg/foo-bar.go" {
		t.Errorf("group 0 file expected 'pkg/foo-bar.go', got %q", groups[0].file)
	}
	if groups[0].hits != 2 {
		t.Errorf("group 0 hits expected 2, got %d", groups[0].hits)
	}
	if len(groups[0].lines) != 5 {
		t.Errorf("group 0 lines count expected 5, got %d", len(groups[0].lines))
	}

	if groups[1].file != "other/baz.go" {
		t.Errorf("group 1 file expected 'other/baz.go', got %q", groups[1].file)
	}
	if groups[1].hits != 1 {
		t.Errorf("group 1 hits expected 1, got %d", groups[1].hits)
	}

	rendered := renderGroups(groups)
	expectedRendered := "pkg/foo-bar.go:10:func DoWork() {\npkg/foo-bar.go-11-    // context line 1\npkg/foo-bar.go-12-    // context line 2\n--\npkg/foo-bar.go:20:func AnotherWork() {\nother/baz.go:5:const Pi = 3.14"
	if rendered != expectedRendered {
		t.Errorf("rendered output mismatch.\nGot:\n%s\nWant:\n%s", rendered, expectedRendered)
	}
}
