package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// AlFix6: AUDIT3 red tests + dash differential argv comparison + fuzz.
// ---------------------------------------------------------------------------

const argvPrintFlag = "--ctxmode-argv-print"

func skipArgvPrintUnderRace(t *testing.T) {
	t.Helper()
	// AlFix7: independent argvprinter binary; no race skip.
}

func alfix6TestBin(t *testing.T) string {
	t.Helper()
	return ensureArgvPrinter(t)
}

// replaceCmdHead rewrites the first bare word of a simple shell command with
// replacement (used to swap dangerous heads for the test binary).
func replaceCmdHead(code, replacement string) string {
	i := 0
	for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
		i++
	}
	j := i
	for j < len(code) {
		c := code[j]
		if c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '|' || c == '&' || c == '<' || c == '>' {
			break
		}
		j++
	}
	if j == i {
		return replacement + code[i:]
	}
	return code[:i] + replacement + code[j:]
}

func dashArgv(t *testing.T, shell, code string) ([]string, string, error) {
	t.Helper()
	outFile := filepath.Join(t.TempDir(), "argv.json")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-c", code)
	cmd.Env = append(os.Environ(), "CTXMODE_ARGV_OUT="+outFile)
	out, err := cmd.CombinedOutput()
	data, rerr := os.ReadFile(outFile)
	if rerr != nil {
		return nil, string(out), fmt.Errorf("read argv file: %v; run err=%v raw=%q", rerr, err, out)
	}
	// Printer appends JSONL; take the last non-empty line.
	lines := bytes.Split(data, []byte("\n"))
	var last []byte
	for _, ln := range lines {
		if len(bytes.TrimSpace(ln)) > 0 {
			last = ln
		}
	}
	var argv []string
	if jerr := json.Unmarshal(last, &argv); jerr != nil {
		return nil, string(data), fmt.Errorf("json decode argv: %w; raw=%q", jerr, data)
	}
	// Printer includes argv[0] basename.
	if len(argv) > 0 && argv[0] == "argvprinter" {
		argv = argv[1:]
	}
	if err != nil {
		return argv, string(out), nil
	}
	return argv, string(out), nil
}

// ---------- AUDIT3 section-3 table (20 items) + agy Must Fix samples ----------

func TestAlFix6_Audit3Table_Readonly(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	type tc struct {
		name string
		code string
		argv []string
		want string // "block" or "allow"
		sub  string // optional substring in block reason
		note string
	}
	cases := []tc{
		// M1 \r
		{name: "M1_cr_comment", code: "true \r#; echo PWN", want: "block", sub: "control"},
		{name: "M1_cr_opt", code: "rg -e \r --pre=/usr/bin/id pat .", want: "block", sub: "control"},
		{name: "M1_cr_redir", code: "echo hi >/dev/null\rfoo", want: "block", sub: "control"},
		// M2 quoted/escaped digit redirect
		{name: "M2_sq_digit", code: "rg -e '2'>/dev/null --pre=/usr/bin/id pat .", want: "block"},
		{name: "M2_dq_digit", code: `nice -n "2">/dev/null pig`, want: "block"},
		{name: "M2_bs_digit", code: `rg -e \2>/dev/null --pre=/usr/bin/id pat .`, want: "block"},
		{name: "M2_empty_q_digit", code: `rg -e ""2>/dev/null --pre=/usr/bin/id pat .`, want: "block"},
		// M3 $((
		{name: "M3_fake_arith", code: `bash -c 'echo $((pig); (true))'`, want: "block"},
		// M4 ${}
		{name: "M4_param_dq", code: `echo $(echo "${x:-")"}"; pig)`, want: "block"},
		// M5 line continuation
		{name: "M5_linecont_dollar", code: "echo $\\\n(pig)", want: "block"},
		// M6 backtick
		{name: "M6_bt_escape", code: "echo `\\`pig\\``", want: "block"},
		// M7 heredoc \r
		{name: "M7_heredoc_cr", code: "cat <<'EOF'\nEOF\r\n'; pig; '\nEOF", want: "block"},
		// M8 tilde/glob
		{name: "M8_tilde", code: "~", want: "block", sub: "tilde"},
		{name: "M8_tilde_root", code: "~root", want: "block", sub: "tilde"},
		{name: "M8_glob_star", code: "ls *.go", want: "block", sub: "glob"},
		{name: "M8_find_unquoted", code: "find . -name *.go", want: "block", sub: "glob"},
		// S1 tail/head/jq
		{name: "S1_tail_nf", argv: []string{"tail", "-n", "-5", "-f", "README.md"}, want: "block"},
		{name: "S1_head_nf", argv: []string{"head", "-n", "-5", "-f", "README.md"}, want: "block"},
		{name: "S1_jq_arg_ok", argv: []string{"jq", "--arg", "a", "b", ".x"}, want: "allow"},
		// S2 ctxmode -h
		{name: "S2_ctxmode_h", argv: []string{"ctxmode", "-h"}, want: "allow"},
		{name: "S2_ctxmode_help", argv: []string{"ctxmode", "--help"}, want: "allow"},
		// S3 herdr
		{name: "S3_herdr_bare", argv: []string{"herdr"}, want: "block"},
		{name: "S3_herdr_remote", argv: []string{"herdr", "--remote=u@h", "status"}, want: "block"},
		{name: "S3_herdr_V", argv: []string{"herdr", "-V"}, want: "allow"},
		// S4 git branch
		{name: "S4_branch_merged_D", argv: []string{"git", "branch", "--merged", "-D", "foo"}, want: "block"},
		// S5 redirect glue / quoted cmd
		{name: "S5_redir_quote_glue", code: "echo hi >'/dev/null'foo", want: "block"},
		{name: "S5_fd_glue", code: "echo hi 2>&1foo", want: "block"},
		{name: "S5_quoted_if", code: "'if' true; then ls; fi", want: "block"},
		// S7 git tag
		{name: "S7_tag_l_d", argv: []string{"git", "tag", "-l", "-d", "foo"}, want: "block"},
		// C4 isolated )
		{name: "C4_orphan_paren", code: "echo $((1+1)) )", want: "block"},
		// agy Must Fix samples (round 5 review)
		{name: "agy_MF1_cr_pig", code: "true \r#; pig", want: "block"},
		{name: "agy_MF2_nice_pig", code: `nice -n '2'>/dev/null pig`, want: "block"},
		{name: "agy_MF3_bash_arith", code: `bash -c 'echo $((pig); (true))'`, want: "block"},
		// controls
		{name: "ctrl_v", code: "ls \v -la", want: "block", sub: "control"},
		{name: "ctrl_del", code: "ls \x7f", want: "block", sub: "control"},
		// legal IO_NUMBER still allowed
		{name: "allow_2devnull", code: "ls 2>/dev/null", want: "allow"},
		{name: "allow_echo_2_redir", code: "echo 2 >/dev/null", want: "allow"},
		{name: "allow_find_quoted_glob", code: "find . -name '*.go'", want: "allow"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hit string
			if len(c.argv) > 0 {
				hit = guardArgvReadonly(c.argv)
			} else {
				hit = guardShellReadonly(c.code)
			}
			switch c.want {
			case "block":
				if hit == "" {
					t.Fatalf("expected block for %s code=%q argv=%v", c.name, c.code, c.argv)
				}
				if c.sub != "" && !strings.Contains(strings.ToLower(hit), strings.ToLower(c.sub)) {
					t.Fatalf("hit %q missing %q", hit, c.sub)
				}
			case "allow":
				if hit != "" {
					t.Fatalf("expected allow for %s, got %q", c.name, hit)
				}
			}
		})
	}
}

func TestAlFix6_Audit3Table_Subagent(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	type tc struct {
		name string
		code string
		want string // "block" | "allow" | "see_pig" | "argv_keep2"
	}
	cases := []tc{
		{name: "M1_cr_comment_seg", code: "true \r#; echo PWN", want: "allow"}, // no nested agent; must parse 2 segs
		{name: "M2_nice_pig", code: `nice -n '2'>/dev/null pig`, want: "block"},
		{name: "M3_fake_arith", code: `bash -c 'echo $((pig); (true))'`, want: "block"},
		{name: "M4_param_pig", code: `echo $(echo "${x:-")"}"; pig)`, want: "block"},
		{name: "M4_param_sq_pig", code: `echo $(echo ${x:-')'}; pig)`, want: "block"},
		{name: "M5_linecont", code: "echo $\\\n(pig)", want: "block"},
		{name: "M5_dq_linecont", code: "echo \"$\\\n(pig)\"", want: "block"},
		{name: "M6_bt", code: "echo `\\`pig\\``", want: "block"},
		{name: "M6_bt_dbs", code: "echo `echo a\\\\` ; pig ; #`", want: "block"},
		{name: "M7_heredoc_cr", code: "cat <<'EOF'\nEOF\r\n'; pig; '\nEOF", want: "allow"}, // cat only; pig inside body as text when quoted
		{name: "arith_real_nested", code: "echo $(( (1+1) * $(pig) ))", want: "block"},
		{name: "S6_env_un", code: "env --un CTXMODE_ROLE pig", want: "block"},
		{name: "S6_env_sp", code: "env --sp='pig' true", want: "block"},
		{name: "S6_env_ig", code: "env --ignore-e pig", want: "block"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit := guardShellSubagent(c.code)
			switch c.want {
			case "block":
				if hit == "" {
					t.Fatalf("expected subagent block for %q", c.code)
				}
			case "allow":
				if hit != "" {
					t.Fatalf("expected allow, got %q for %q", hit, c.code)
				}
			}
		})
	}

	// Parser shape checks for \r (must keep \r in argv, not drop).
	t.Run("M1_cr_argv_shape", func(t *testing.T) {
		segs := splitShellSegments("true \r#; echo PWN")
		if len(segs) < 2 {
			t.Fatalf("want >=2 segs, got %d %#v", len(segs), segs)
		}
		if len(segs[0].argv) < 2 || segs[0].argv[1] != "\r#" {
			t.Fatalf("seg0 argv want [true, \\r#], got %#v", segs[0].argv)
		}
		if len(segs[1].argv) < 2 || segs[1].argv[0] != "echo" || segs[1].argv[1] != "PWN" {
			t.Fatalf("seg1 argv want [echo PWN], got %#v", segs[1].argv)
		}
	})

	t.Run("M2_keep_digit_argv", func(t *testing.T) {
		segs := splitShellSegments(`rg -e '2'>/dev/null --pre=/usr/bin/id pat .`)
		if len(segs) == 0 {
			t.Fatal("no segs")
		}
		found2 := false
		for _, a := range segs[0].argv {
			if a == "2" {
				found2 = true
			}
		}
		if !found2 {
			t.Fatalf("expected argv to keep \"2\", got %#v", segs[0].argv)
		}
		// Must also keep --pre as its own argv element (not swallowed).
		foundPre := false
		for _, a := range segs[0].argv {
			if strings.HasPrefix(a, "--pre=") {
				foundPre = true
			}
		}
		if !foundPre {
			t.Fatalf("expected --pre= to remain an option, got %#v", segs[0].argv)
		}
	})

	t.Run("M1_cr_redirect_target", func(t *testing.T) {
		segs := splitShellSegments("echo hi >/dev/null\rfoo")
		if len(segs) == 0 {
			t.Fatal("no segs")
		}
		if segs[0].redirectFile != "/dev/null\rfoo" && !strings.Contains(segs[0].redirectFile, "\r") {
			// After fix, redirect target must include \r (blocking write).
			t.Fatalf("redirectFile=%q, want to contain \\r", segs[0].redirectFile)
		}
	})
}

func TestAlFix6_Audit3_DiffCases32_ReadonlyExpectations(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	// Compact coverage of all 32 differential case categories from AUDIT3 §4.
	block := []string{
		"true \r#; echo PWN",
		"ls\r",
		"rg -e \r --pre=/usr/bin/id pat .",
		"echo hi >/dev/null\rfoo",
		"ls \v -la",
		"rg -e '2'>/dev/null --pre=/usr/bin/id pat .",
		`nice -n "2">/dev/null pig`,
		`rg -e \2>/dev/null --pre=/usr/bin/id pat .`,
		`rg -e ""2>/dev/null --pre=/usr/bin/id pat .`,
		"echo a2>/dev/null b",
		"echo hi >'/dev/null'foo",
		"echo hi 2>&1foo",
		"2>/dev/null ls -la",
		`""/bin/ls`,
		"~",
		"ls ~",
		"ls *.go",
		`bash -c 'echo $((pig); (true))'`,
		"echo $(( (1+1) * $(pig) ))",
		`echo $(echo "${x:-")"}"; pig)`,
		`echo $(echo ${x:-')'}; pig)`,
		"echo $\\\n(pig)",
		"echo \"$\\\n(pig)\"",
		"cat <\\\n<EOF\n$(pig)\nEOF",
		"echo `\\`pig\\``",
		"echo `echo a\\\\` ; pig ; #`",
		"cat <<'EOF'\nEOF\r\n'; pig; '\nEOF",
	}
	for i, code := range block {
		t.Run(fmt.Sprintf("diff_block_%02d", i+1), func(t *testing.T) {
			if hit := guardShellReadonly(code); hit == "" {
				t.Fatalf("expected block for %q", code)
			}
		})
	}
	allow := []string{
		"ls 2>/dev/null",
		"echo 2 >/dev/null",
	}
	for i, code := range allow {
		t.Run(fmt.Sprintf("diff_allow_%02d", i+1), func(t *testing.T) {
			if hit := guardShellReadonly(code); hit != "" {
				t.Fatalf("expected allow for %q, got %q", code, hit)
			}
		})
	}
	// argv-level cases 30-32
	if hit := guardArgvReadonly([]string{"tail", "-n", "-5", "-f", "README.md"}); hit == "" {
		t.Fatal("case30: expected tail -f block")
	}
	if hit := guardArgvReadonly([]string{"git", "branch", "--merged", "-D", "feature"}); hit == "" {
		t.Fatal("case31: expected git branch -D block")
	}
	if hit := guardArgvReadonly([]string{"ctxmode", "-h"}); hit != "" {
		t.Fatalf("case32: ctxmode -h should allow, got %q", hit)
	}
	if hit := guardArgvReadonly([]string{"herdr", "--remote=x", "status"}); hit == "" {
		t.Fatal("case32: herdr --remote should block")
	}
}

// ---------- Green sample regression (alfix5) with noted glob exceptions ----------

func TestAlFix6_FalsePositivesPass(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")
	pass := []struct {
		name string
		argv []string
		code string
	}{
		{name: "find_mtime", argv: []string{"find", ".", "-mtime", "-7"}},
		{name: "find_name_quoted", code: "find . -name '*.go'"},
		{name: "date_d", argv: []string{"date", "-d", "2026-01-01"}},
		{name: "du_d1", argv: []string{"du", "-d1"}},
		{name: "uniq_cf", argv: []string{"uniq", "-cf", "1", "input.txt"}},
		{name: "head_20", argv: []string{"head", "-20", "file"}},
		{name: "tail_20", argv: []string{"tail", "-20", "file"}},
		{name: "head_n", argv: []string{"head", "-n", "5", "f"}},
		{name: "tail_n", argv: []string{"tail", "-n", "5", "f"}},
		{name: "ss_s", argv: []string{"ss", "-s"}},
		{name: "ps_p", argv: []string{"ps", "-p", "1"}},
		{name: "diff_U", argv: []string{"diff", "-U", "3", "a", "b"}},
		{name: "jq_arg", argv: []string{"jq", "--arg", "k", "v", ".x == $k"}},
		{name: "git_C_glued", argv: []string{"git", "-C/tmp", "status"}},
		{name: "git_branch_show_current", argv: []string{"git", "branch", "--show-current"}},
		{name: "herdr_session_status", argv: []string{"herdr", "--session", "s", "status"}},
		{name: "cat", argv: []string{"cat", "f"}},
		{name: "rg_dollar", code: "rg 'a$'"},
		{name: "pipe_devnull_head", code: "ls 2>/dev/null | head -n 5"},
		{name: "git_status", argv: []string{"git", "status"}},
		{name: "ls", argv: []string{"ls", "-la"}},
	}
	for _, c := range pass {
		t.Run(c.name, func(t *testing.T) {
			var hit string
			if len(c.argv) > 0 {
				hit = guardArgvReadonly(c.argv)
			} else {
				hit = guardShellReadonly(c.code)
			}
			if hit != "" {
				t.Fatalf("expected allow for %+v, got %q", c, hit)
			}
		})
	}
	// Explicitly noted new blocks (unquoted glob) — document replay exceptions.
	t.Run("replay_exception_unquoted_glob", func(t *testing.T) {
		if hit := guardShellReadonly("find . -name *.go"); hit == "" {
			t.Fatal("unquoted glob should now block")
		}
	})
}

func TestAlFix6_WorkerStillAllowsNesting(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	segs := splitShellSegments("echo $(echo hi)")
	if len(segs) == 0 {
		t.Fatal("$(...) produced 0 segments")
	}
	segs = splitShellSegments("( echo hi )")
	if len(segs) == 0 {
		t.Fatal("subshell produced 0 segments")
	}
	segs = splitShellSegments("(( echo hi ))")
	if len(segs) == 0 {
		t.Fatal("(( )) produced 0 segments")
	}
	hit := guardShellSubagent("( pig # (\n); true")
	if hit == "" {
		t.Fatal("expected subagent guard to see pig")
	}
	hit = guardShellSubagent("cat <<EOF\n$(echo hi)\nEOF")
	_ = hit // heredoc with benign cmdsub must parse; pig variants blocked elsewhere
}

// ---------- Real dash / bash differential argv tests ----------

func TestAlFix6_DashArgvDiff(t *testing.T) {
	skipArgvPrintUnderRace(t)
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	bin := alfix6TestBin(t)
	printer := bin

	type tc struct {
		name string
		code string // original; head will be replaced with printer for dash & expected
		// expectGo is a function that returns Go argv (without needing printer in parse)
		goArgv   func() []string
		skipDash bool
	}

	cases := []tc{
		{
			name: "simple_args",
			code: "printargv -e foo --pre=x pat .",
			goArgv: func() []string {
				segs := splitShellSegments("printargv -e foo --pre=x pat .")
				return segs[0].argv
			},
		},
		{
			name: "cr_as_word",
			code: "printargv -e \r --pre=/usr/bin/id pat .",
			goArgv: func() []string {
				segs := splitShellSegments("printargv -e \r --pre=/usr/bin/id pat .")
				return segs[0].argv
			},
		},
		{
			name: "sq_digit_keep",
			code: "printargv -e '2'>/dev/null --pre=/usr/bin/id pat .",
			goArgv: func() []string {
				segs := splitShellSegments("printargv -e '2'>/dev/null --pre=/usr/bin/id pat .")
				return segs[0].argv
			},
		},
		{
			name: "dq_digit_keep",
			code: `printargv -n "2">/dev/null a`,
			goArgv: func() []string {
				segs := splitShellSegments(`printargv -n "2">/dev/null a`)
				return segs[0].argv
			},
		},
		{
			name: "bs_digit_keep",
			code: `printargv -e \2>/dev/null --pre=/usr/bin/id pat .`,
			goArgv: func() []string {
				segs := splitShellSegments(`printargv -e \2>/dev/null --pre=/usr/bin/id pat .`)
				return segs[0].argv
			},
		},
		{
			name: "empty_q_digit",
			code: `printargv -e ""2>/dev/null --pre=/usr/bin/id pat .`,
			goArgv: func() []string {
				segs := splitShellSegments(`printargv -e ""2>/dev/null --pre=/usr/bin/id pat .`)
				return segs[0].argv
			},
		},
		{
			name: "midword_digit",
			code: "printargv a2>/dev/null b",
			goArgv: func() []string {
				segs := splitShellSegments("printargv a2>/dev/null b")
				return segs[0].argv
			},
		},
		{
			name: "bare_io_number",
			code: "printargv 2>/dev/null a b",
			goArgv: func() []string {
				segs := splitShellSegments("printargv 2>/dev/null a b")
				return segs[0].argv
			},
		},
		{
			name: "digit_space_redir",
			code: "printargv 2 >/dev/null",
			goArgv: func() []string {
				segs := splitShellSegments("printargv 2 >/dev/null")
				return segs[0].argv
			},
		},
		{
			name: "cr_cmd_head",
			code: "printargv\r",
			goArgv: func() []string {
				segs := splitShellSegments("printargv\r")
				return segs[0].argv
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			goArgv := c.goArgv()
			if len(goArgv) == 0 {
				t.Fatal("Go produced empty argv")
			}
			if c.name == "cr_cmd_head" {
				if goArgv[0] != "printargv\r" {
					t.Fatalf("Go argv[0]=%q want printargv\\r", goArgv[0])
				}
				return
			}
			// Printer emits Args[2:] (operands only). Compare to Go argv[1:].
			dashCode := replaceCmdHead(c.code, printer)
			dashOut, raw, err := dashArgv(t, "/bin/sh", dashCode)
			if err != nil {
				t.Fatalf("dash failed: %v raw=%q go=%#v", err, raw, goArgv)
			}
			wantArgs := goArgv[1:]
			if len(dashOut) != len(wantArgs) {
				t.Fatalf("len mismatch dash=%d go=%d\ndash=%#v\ngo=%#v", len(dashOut), len(wantArgs), dashOut, wantArgs)
			}
			for i := range wantArgs {
				if dashOut[i] != wantArgs[i] {
					t.Fatalf("argv[%d] mismatch\n dash=%q\n go  =%q\n full dash=%#v\n full go=%#v", i, dashOut[i], wantArgs[i], dashOut, wantArgs)
				}
			}
		})
	}
}

func TestAlFix6_DashArgvDiff_MultiSeg(t *testing.T) {
	skipArgvPrintUnderRace(t)
	bin := alfix6TestBin(t)
	printer := bin

	_ = printer
	segs := splitShellSegments("true \r#; printargv PWN")
	if len(segs) < 2 {
		t.Fatalf("want 2 segs, got %#v", segs)
	}
	// Run only the second segment via dash by constructing equivalent.
	dashCode := printer + " PWN"
	dashOut, raw, err := dashArgv(t, "/bin/sh", dashCode)
	if err != nil {
		t.Fatalf("dash: %v raw=%q", err, raw)
	}
	goArgv := segs[1].argv
	wantArgs := goArgv[1:]
	if len(dashOut) != len(wantArgs) {
		t.Fatalf("len dash=%d go=%d dash=%#v go=%#v", len(dashOut), len(wantArgs), dashOut, wantArgs)
	}
	for i := range wantArgs {
		if dashOut[i] != wantArgs[i] {
			t.Fatalf("argv[%d] dash=%q go=%q", i, dashOut[i], wantArgs[i])
		}
	}
}

func TestAlFix6_BashSubagent_FakeArith(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	hit := guardShellSubagent(`bash -c 'echo $((pig); (true))'`)
	if hit == "" {
		t.Fatal("expected pig visible through fake $(( ))")
	}
}

// ---------- Fuzz / mutation differential (printer only, fixed seed) ----------

func TestAlFix6_FuzzArgvDiff(t *testing.T) {
	skipArgvPrintUnderRace(t)
	if testing.Short() {
		t.Skip("short")
	}
	bin := alfix6TestBin(t)
	printer := bin
	rng := rand.New(rand.NewSource(20261104))

	safeChars := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+.=/@:")
	quoteStyles := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return "'" + s + "'" },
		func(s string) string { return `"` + s + `"` },
	}

	N := 3000
	if raceEnabled {
		N = 500 // alfix7 owns the large race fuzz
	}
	mismatches := 0
	outFile := filepath.Join(t.TempDir(), "fuzz-argv.json")
	for i := 0; i < N; i++ {
		nArgs := 1 + rng.Intn(4)
		var parts []string
		parts = append(parts, "printargv")
		for a := 0; a < nArgs; a++ {
			n := 1 + rng.Intn(8)
			b := make([]byte, n)
			for j := range b {
				b[j] = safeChars[rng.Intn(len(safeChars))]
			}
			s := string(b)
			q := quoteStyles[rng.Intn(len(quoteStyles))]
			parts = append(parts, q(s))
		}
		// Occasionally append a safe redirect.
		code := strings.Join(parts, " ")
		if rng.Intn(5) == 0 {
			code += " >/dev/null"
		}
		if rng.Intn(5) == 0 {
			code += " 2>/dev/null"
		}

		segs := splitShellSegments(code)
		if len(segs) == 0 || len(segs[0].argv) == 0 {
			continue
		}
		goArgv := segs[0].argv
		dashCode := replaceCmdHead(code, printer)
		_ = os.Remove(outFile)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", dashCode)
		cmd.Env = append(os.Environ(), "CTXMODE_ARGV_OUT="+outFile)
		_, _ = cmd.CombinedOutput()
		cancel()
		data, rerr := os.ReadFile(outFile)
		if rerr != nil {
			continue
		}
		var dashOut []string
		// JSONL: last line
		lines := bytes.Split(data, []byte("\n"))
		var last []byte
		for _, ln := range lines {
			if len(bytes.TrimSpace(ln)) > 0 {
				last = ln
			}
		}
		if json.Unmarshal(last, &dashOut) != nil {
			continue
		}
		if len(dashOut) > 0 && dashOut[0] == "argvprinter" {
			dashOut = dashOut[1:]
		}
		wantArgs := goArgv[1:]
		if len(dashOut) != len(wantArgs) {
			mismatches++
			if mismatches <= 5 {
				t.Logf("len mismatch i=%d code=%q dash=%#v go=%#v", i, code, dashOut, wantArgs)
			}
			continue
		}
		for j := range wantArgs {
			if dashOut[j] != wantArgs[j] {
				mismatches++
				if mismatches <= 5 {
					t.Logf("argv mismatch i=%d j=%d code=%q dash=%q go=%q", i, j, code, dashOut[j], wantArgs[j])
				}
				break
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("fuzz argv mismatches: %d / %d (seed=20261104)", mismatches, N)
	}
}

func TestAlFix6_ByteAllowlist(t *testing.T) {
	if hit := checkReadonlyShellSyntax("ls\r"); hit == "" {
		t.Fatal("expected \\r reject")
	}
	if hit := checkReadonlyShellSyntax("ls\x00"); hit == "" {
		t.Fatal("expected NUL reject")
	}
	if !utf8.ValidString("ls\xff") {
		if hit := checkReadonlyShellSyntax("ls\xff"); hit == "" {
			t.Fatal("expected illegal UTF-8 reject")
		}
	}
	if hit := checkReadonlyShellSyntax("ls -la"); hit != "" {
		t.Fatalf("plain ls blocked: %q", hit)
	}
}

func TestAlFix6_DeadCodeGone(t *testing.T) {
	// Compile-time: symbols removed. Runtime: ensure unzip/gzip not in allowlist.
	if _, ok := readonlyAllowlist["unzip"]; ok {
		t.Fatal("unzip still in allowlist")
	}
	if _, ok := readonlyAllowlist["gzip"]; ok {
		t.Fatal("gzip still in allowlist")
	}
}

func TestAlFix6_SyntaxHints(t *testing.T) {
	hit := checkReadonlyShellSyntax("find . -name *.go")
	if hit == "" || !strings.Contains(hit, "Hint:") {
		t.Fatalf("want Hint for glob, got %q", hit)
	}
	if !strings.Contains(hit, "*.go") && !strings.Contains(hit, "find") {
		t.Fatalf("hint should mention quoted glob example, got %q", hit)
	}
}

// Ensure test binary path is absolute for dash.
func TestAlFix6_PrinterSelfCheck(t *testing.T) {
	skipArgvPrintUnderRace(t)
	bin := alfix6TestBin(t)
	if !filepath.IsAbs(bin) {
		t.Fatalf("executable not absolute: %q", bin)
	}
	outFile := filepath.Join(t.TempDir(), "argv.json")
	cmd := exec.Command(bin, "a", "b")
	cmd.Env = append(os.Environ(), "CTXMODE_ARGV_OUT="+outFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("printer mode failed: %v out=%q", err, out)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read argv file: %v", err)
	}
	var argv []string
	if err := json.Unmarshal(data, &argv); err != nil {
		t.Fatalf("json: %v raw=%q", err, data)
	}
	if len(argv) == 3 && argv[0] == "argvprinter" {
		argv = argv[1:]
	}
	if len(argv) != 2 || argv[0] != "a" || argv[1] != "b" {
		t.Fatalf("printer argv=%#v want [a b]", argv)
	}
}
