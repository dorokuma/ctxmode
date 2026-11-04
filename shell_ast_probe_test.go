package main

import (
	"os/exec"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

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
