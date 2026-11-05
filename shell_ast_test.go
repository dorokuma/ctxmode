package main

import (
	"strings"
	"testing"
)

func TestParseReadonlyShellAST_EmptyAndComment(t *testing.T) {
	for _, code := range []string{"", "   ", "\n", "# just a comment\n", "#\n#\n"} {
		argvs, hit := parseReadonlyShellAST(code)
		if hit != "" {
			t.Fatalf("code=%q: unexpected reject %q", code, hit)
		}
		if len(argvs) != 0 {
			t.Fatalf("code=%q: want 0 argvs, got %v", code, argvs)
		}
	}
}

func TestParseReadonlyShellAST_SafeRedirect(t *testing.T) {
	argvs, hit := parseReadonlyShellAST("ls 2>/dev/null")
	if hit != "" {
		t.Fatalf("unexpected reject: %q", hit)
	}
	if len(argvs) != 1 || len(argvs[0]) != 1 || argvs[0][0] != "ls" {
		t.Fatalf("got argvs=%v", argvs)
	}
}

func TestParseReadonlyShellAST_GlobReject(t *testing.T) {
	_, hit := parseReadonlyShellAST("ls *.go")
	if hit == "" {
		t.Fatal("expected reject for glob")
	}
	if !strings.Contains(hit, "glob") && !strings.Contains(hit, "metachar") {
		t.Fatalf("unexpected reason: %q", hit)
	}
}

func TestParseReadonlyShellAST_ControlChar(t *testing.T) {
	_, hit := parseReadonlyShellAST("echo hi\r")
	if hit == "" || !strings.Contains(hit, "control character forbidden") {
		t.Fatalf("want control character forbidden, got %q", hit)
	}
}

func TestParseSubagentShellAST_Pig(t *testing.T) {
	segs, ok := parseSubagentShellAST("pig", 0, false, false)
	if !ok {
		t.Fatal("expected ok")
	}
	if len(segs) != 1 || len(segs[0].argv) < 1 || segs[0].argv[0] != "pig" {
		t.Fatalf("got segs=%v", dumpSegs(segs))
	}
}

func TestParseSubagentShellAST_ParamExpHead(t *testing.T) {
	segs, ok := parseSubagentShellAST("${UNSET:-pig}", 0, false, false)
	if !ok {
		// fail-closed is also acceptable for dynamic head
		if len(segs) == 1 && segs[0].depthExceeded {
			return
		}
		t.Fatalf("rejected without depthExceeded marker: %v", dumpSegs(segs))
	}
	if len(segs) < 1 || len(segs[0].argv) < 1 {
		t.Fatalf("missing argv: %v", dumpSegs(segs))
	}
	if segs[0].argv[0] != cmdSubPlaceholder && !strings.Contains(segs[0].argv[0], cmdSubPlaceholder) {
		t.Fatalf("want cmdSubPlaceholder head, got %q", segs[0].argv[0])
	}
}

func TestParseSubagentShellAST_DoubleParen(t *testing.T) {
	segs, ok := parseSubagentShellAST("((pig))", 0, false, false)
	if !ok {
		t.Fatalf("expected ok, got %v", dumpSegs(segs))
	}
	found := false
	for _, s := range segs {
		if len(s.argv) > 0 && s.argv[0] == "pig" {
			found = true
		}
	}
	if !found {
		t.Fatalf("((pig)) should surface pig, got %v", dumpSegs(segs))
	}
}

func TestParseSubagentShellAST_FuncDecl(t *testing.T) {
	segs, ok := parseSubagentShellAST("f() { pig; }", 0, false, false)
	if !ok {
		t.Fatalf("expected ok, got %v", dumpSegs(segs))
	}
	found := false
	for _, s := range segs {
		if len(s.argv) > 0 && s.argv[0] == "pig" {
			found = true
		}
	}
	if !found {
		t.Fatalf("func body pig not found: %v", dumpSegs(segs))
	}
}

func TestParseSubagentShellAST_D2Reject(t *testing.T) {
	segs, ok := parseSubagentShellAST(`"${x:-'y'}"`, 0, false, false)
	if ok {
		t.Fatalf("D2 should reject, got ok segs=%v", dumpSegs(segs))
	}
	if len(segs) != 1 || (segs[0].parseErr == "" && !segs[0].depthExceeded) {
		t.Fatalf("want parseErr or depthExceeded marker, got %v", dumpSegs(segs))
	}
}

func TestParseSubagentShellAST_ControlChar(t *testing.T) {
	segs, ok := parseSubagentShellAST("echo hi\r", 0, false, false)
	if ok {
		t.Fatal("expected reject for \\r")
	}
	if len(segs) != 1 || (segs[0].parseErr == "" && !segs[0].depthExceeded) {
		t.Fatalf("want parseErr or depthExceeded, got %v", dumpSegs(segs))
	}
}

func TestCheckShellBytes_Both(t *testing.T) {
	if hit := checkShellBytes("ok", false); hit != "" {
		t.Fatalf("clean: %q", hit)
	}
	if hit := checkControlAndUTF8("a\rb"); !strings.Contains(hit, "control character forbidden") {
		t.Fatalf("got %q", hit)
	}
	if hit := checkShellBytes("a\u00a0b", true); hit == "" {
		t.Fatal("strict should reject NBSP")
	}
	if hit := checkShellBytes("a\u00a0b", false); hit != "" {
		t.Fatalf("non-strict should allow NBSP, got %q", hit)
	}
}

func dumpSegs(segs []shellSegment) string {
	var b strings.Builder
	for i, s := range segs {
		if i > 0 {
			b.WriteString(" | ")
		}
		if s.depthExceeded {
			b.WriteString("<depthExceeded>")
			continue
		}
		b.WriteString("[")
		b.WriteString(strings.Join(s.argv, " "))
		b.WriteString("]")
		if s.pipedStdin {
			b.WriteString(" pipe")
		}
		if s.backgrounded {
			b.WriteString(" bg")
		}
		if s.redirectFile != "" {
			b.WriteString(" >")
			b.WriteString(s.redirectFile)
		}
	}
	return b.String()
}
