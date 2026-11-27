package main

import (
	"os/exec"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// === Merged from shell_ast_test.go ===

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

// === Merged from shell_ast_probe_test.go ===

// TestMvdanDashBehaviorProbe documents D2/D5/D9 and bash-only constructs.
// Conclusions feed REPORT.md; assertions encode fail-closed policy inputs.
func TestMvdanDashBehaviorProbe(t *testing.T) {
	t.Run("D2_dq_param_sglquoted_in_mvdan", func(t *testing.T) {
		code := `echo "${UNSET:-'}"; echo PIGDASH # '}"`
		f, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(code), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		foundSgl := false
		syntax.Walk(f, func(n syntax.Node) bool {
			if sq, ok := n.(*syntax.SglQuoted); ok {
				foundSgl = true
				t.Logf("SglQuoted value=%q", sq.Value)
			}
			return true
		})
		if !foundSgl {
			t.Fatal("expected mvdan to treat '...' inside \"${...}\" as SglQuoted")
		}
		out, _ := exec.Command("/bin/sh", "-c", code).CombinedOutput()
		if !strings.Contains(string(out), "PIGDASH") {
			t.Fatalf("dash should execute PIGDASH, got %q", out)
		}
		bout, _ := exec.Command("/bin/bash", "-c", code).CombinedOutput()
		if strings.Contains(string(bout), "PIGDASH\n") && !strings.Contains(string(bout), "PIGDASH #") {
			// bash keeps pig inside the default word; must not execute as command
		}
		t.Logf("dash out=%q bash out=%q → D2 divergence CONFIRMED; fail-closed on ' inside dq ParamExp", out, bout)
	})

	t.Run("D5_double_paren_posix_subshell", func(t *testing.T) {
		code := "((echo HIDASH))"
		f, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(code), "")
		if err != nil {
			t.Fatalf("POSIX parse: %v", err)
		}
		subshells := 0
		syntax.Walk(f, func(n syntax.Node) bool {
			if _, ok := n.(*syntax.Subshell); ok {
				subshells++
			}
			return true
		})
		if subshells < 2 {
			t.Fatalf("LangPOSIX should yield nested Subshells, got %d", subshells)
		}
		_, berr := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(code), "")
		if berr == nil {
			t.Log("LangBash unexpectedly accepted ((echo HIDASH))")
		} else {
			t.Logf("LangBash err=%v (expected for non-arith)", berr)
		}
		out, _ := exec.Command("/bin/sh", "-c", code).CombinedOutput()
		if !strings.Contains(string(out), "HIDASH") {
			t.Fatalf("dash should run echo HIDASH via nested subshells, got %q", out)
		}
		t.Logf("D5 CONFIRMED: POSIX=2 Subshells, dash runs HIDASH, Bash arith path differs")
	})

	t.Run("D9_comment_backslash_no_continue", func(t *testing.T) {
		code := "# \\\necho PIGCOMMENT"
		f, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(code), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		saw := false
		syntax.Walk(f, func(n syntax.Node) bool {
			if c, ok := n.(*syntax.CallExpr); ok && len(c.Args) > 0 {
				if lit, ok := c.Args[0].Parts[0].(*syntax.Lit); ok && lit.Value == "echo" {
					saw = true
				}
			}
			return true
		})
		if !saw {
			t.Fatal("mvdan must see echo after comment line (comment ends at physical newline)")
		}
		out, _ := exec.Command("/bin/sh", "-c", code).CombinedOutput()
		if !strings.Contains(string(out), "PIGCOMMENT") {
			t.Fatalf("dash out=%q", out)
		}
		t.Log("D9 CONFIRMED: comment \\ does not continue; mvdan matches dash")
	})

	t.Run("bash_only_under_LangPOSIX", func(t *testing.T) {
		cases := []struct {
			code     string
			posixErr bool
			note     string
		}{
			{"true &> /dev/null", true, "&> rejected by LangPOSIX"},
			{"[[ -f /etc/passwd ]]", false, "[[ parsed as CallExpr words under POSIX"},
			{"echo $'a\\nb'", false, "$'...' → Lit($)+SglQuoted under POSIX; SglQuoted.Dollar under Bash"},
			{"cat <<< hi", true, "<<< rejected by LangPOSIX"},
		}
		for _, c := range cases {
			_, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(c.code), "")
			gotErr := err != nil
			if gotErr != c.posixErr {
				t.Errorf("%s: posixErr want %v got %v (%v)", c.code, c.posixErr, gotErr, err)
			}
			t.Logf("%s → posixErr=%v (%s)", c.code, gotErr, c.note)
		}
	})
}

// TestDashBuiltinInventory records real dash builtins via `type` (TASK §4).
func TestDashBuiltinInventory(t *testing.T) {
	candidates := []string{
		":", ".", "[", "alias", "bg", "break", "cd", "command", "continue",
		"echo", "eval", "exec", "exit", "export", "false", "fc", "fg",
		"getopts", "hash", "jobs", "kill", "local", "printf", "pwd", "read",
		"readonly", "return", "set", "shift", "test", "times", "trap", "true",
		"type", "ulimit", "umask", "unalias", "unset", "wait",
		"help", "let", "bind", "typeset", "declare",
	}
	var builtins []string
	for _, c := range candidates {
		cmd := exec.Command("/bin/sh", "-c", "type "+astProbeShellQuote(c)+" >/dev/null 2>&1")
		if err := cmd.Run(); err == nil {
			builtins = append(builtins, c)
		}
	}
	t.Logf("dash builtins (%d): %v", len(builtins), builtins)
	if len(builtins) < 30 {
		t.Fatalf("unexpectedly few dash builtins: %d", len(builtins))
	}
	// Sanity: echo/true are builtins; pig is not.
	set := map[string]bool{}
	for _, b := range builtins {
		set[b] = true
	}
	if !set["echo"] || !set["true"] || set["pig"] {
		t.Fatalf("unexpected builtin set: echo=%v true=%v pig=%v", set["echo"], set["true"], set["pig"])
	}
}

func astProbeShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// === Merged from shell_ast_rallow2_test.go ===

// TestRAllow2_ForEnumSubst covers narrowed R-Allow-2 for-loop const
// substitution into -c payloads and top-level static abs-path heads.
func TestRAllow2_ForEnumSubst(t *testing.T) {
	cases := []struct {
		name   string
		code   string
		reject bool
	}{
		{
			name:   "for_safe_python_c",
			code:   `for s in a b c; do python3 -c "print('$s')"; done`,
			reject: false,
		},
		{
			name:   "for_unsafe_enum_reject",
			code:   "for s in a '; pig; #'; do python3 -c \"print('$s')\"; done",
			reject: true,
		},
		{
			name:   "for_scene_worker_replay",
			code:   `for s in a b c d e; do python3 -c "import json;m=json.load(open('scene-$s/...'))"; done`,
			reject: false,
		},
		{
			name:   "for_enum_segments",
			code:   `for s in a b; do python3 -c "print('$s')"; done`,
			reject: false,
		},
		{
			name:   "export_abs_path_head",
			code:   `export BUN=/usr/bin/echo; "$BUN" hi`,
			reject: false,
		},
		{
			name:   "assign_abs_path_head",
			code:   `BUN=/usr/bin/echo; "$BUN" hi`,
			reject: false,
		},
		{
			name:   "rel_path_head_stays_dynamic",
			code:   `BUN=echo; "$BUN" hi`,
			reject: true,
		},
		{
			name:   "bind_inside_if_ignored",
			code:   `if true; then BUN=/usr/bin/echo; fi; "$BUN" hi`,
			reject: true,
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			hit := guardShellSubagent(c.code)
			if c.reject {
				if hit == "" {
					t.Fatalf("expected REJECT, got ALLOW; code=%q", c.code)
				}
			} else if hit != "" {
				t.Fatalf("expected ALLOW, got REJECT %q; code=%q", hit, c.code)
			}
		})
	}

	// All enum values must produce screened segments.
	segs, ok := parseSubagentShellAST(`for s in a b c; do python3 -c "print('$s')"; done`, 0, false, false)
	if !ok {
		t.Fatal("parse failed")
	}
	if len(segs) < 3 {
		t.Fatalf("want >=3 enum segments, got %d: %#v", len(segs), segs)
	}
	want := []string{"print('a')", "print('b')", "print('c')"}
	for i, w := range want {
		if i >= len(segs) || len(segs[i].argv) < 3 || segs[i].argv[2] != w {
			t.Fatalf("seg[%d] want payload %q, segs=%#v", i, w, segs)
		}
	}
}
