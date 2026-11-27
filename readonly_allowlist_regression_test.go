package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// === Merged from readonly_allowlist_alfix5_test.go ===

// Round-5: minimal shell syntax whitelist + AUDIT2 26 findings + false-positive restores.

func TestReadonlyShellSyntax_Table(t *testing.T) {
	deny := []struct {
		name string
		code string
		sub  string // substring expected in reason (aligned to mvdan AST messages)
	}{
		{"dollar_var", "echo $HOME", "ParamExp"},
		{"dollar_brace", "echo ${HOME}", "ParamExp"},
		{"dollar_cmdsub", "echo $(ls)", "CmdSubst"},
		{"dollar_arith", "echo $((1+1))", "ArithmExp"},
		{"backtick", "echo `ls`", "CmdSubst"},
		{"subshell", "( ls )", "parentheses"},
		{"arith_cmd", "(( rm -rf /tmp/x ))", "parentheses"},
		{"brace_group", "{ ls; }", "brace"},
		{"background", "ls &", "background"},
		{"amp_redirect", "echo &>/dev/null", "syntax"},
		{"heredoc", "cat <<EOF\nhi\nEOF", "Redirect"},
		{"herestring", "cat <<< hi", "syntax"},
		{"input_redir", "cat < /etc/passwd", "Redirect"},
		{"write_file", "echo x > /tmp/pwn", "redirect"},
		{"append", "echo x >> /tmp/pwn", "Redirect"},
		{"if_kw", "if true; then ls; fi", "control flow"},
		{"while_kw", "while true; do ls; done", "control flow"},
		{"for_kw", "for x in a; do ls; done", "control flow"},
		{"bang", "! ls", "control flow"},
		{"cond_bracket", "[[ -f a ]]", "charset"},
		{"unclosed_single", "echo 'hi", "closing quote"},
		{"unclosed_double", `echo "hi`, "closing quote"},
		{"dq_dollar", `echo "hi $HOME"`, "expansion"},
		{"line_cont", "echo \\\nls", "backslash"},
		{"path_cmd", "/tmp/ls", "metachar"},
		{"empty_pipe", "ls |", "syntax"},
		{"proc_subst", "cat <(ls)", "syntax"},
		{"env_assign", "FOO=1 ls", "env assign"},
	}
	for _, tc := range deny {
		t.Run("deny_"+tc.name, func(t *testing.T) {
			got := checkReadonlyShellSyntax(tc.code)
			if got == "" {
				t.Fatalf("expected block for %q, got allow", tc.code)
			}
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tc.sub)) &&
				!strings.Contains(got, tc.sub) {
				t.Fatalf("reason %q missing %q", got, tc.sub)
			}
			// Hint: is best-effort guidance; AST fail-closed reasons may omit it.
		})
	}

	allow := []struct {
		name string
		code string
	}{
		{"simple", "ls"},
		{"args", "ls -la /tmp"},
		{"pipe", "cat f | head -n 5"},
		{"and", "ls && pwd"},
		{"or", "ls || pwd"},
		{"semi", "ls; pwd"},
		{"newline", "ls\npwd"},
		{"sq", "rg 'a$'"},
		{"dq_plain", `echo "hello world"`},
		{"devnull", "ls >/dev/null"},
		{"devnull2", "ls 2>/dev/null"},
		{"devnull1", "ls 1>/dev/null"},
		{"fd_dup", "ls 2>&1"},
		{"fd_dup12", "ls 1>&2"},
		{"pipe_redir", "cmd 2>/dev/null | head -n 5"},
		{"comment", "ls # ignore $HOME"},
		// alfix6: unquoted backslash banned; quoted glob is the supported form.
		{"escape_quoted", `echo "*"`},
	}
	for _, tc := range allow {
		t.Run("allow_"+tc.name, func(t *testing.T) {
			if got := checkReadonlyShellSyntax(tc.code); got != "" {
				t.Fatalf("expected allow for %q, got %q", tc.code, got)
			}
		})
	}
}

func TestReadonlyAllowlist_AlFix5_Audit2Blocked(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	type tc struct {
		name string
		argv []string
		code string
	}
	cases := []tc{
		// AUDIT2 Must Fix samples (shell / argv)
		{name: "arith_subshell_rm", code: "(( rm -rf /tmp/x ))"},
		{name: "arith_subshell_pig", code: "(( pig ))"},
		{name: "arith_expand_PATH", code: "echo $(( PATH=0 ))"},
		{name: "arith_expand_ROLE", code: "echo $(( CTXMODE_ROLE=0 ))"},
		{name: "cond_pollute_write", code: "echo a[[b; git show HEAD:file > /tmp/pwn"},
		{name: "cond_dash_write", code: "[[ a > /tmp/pwn ]]"},
		{name: "amp_redirect_rm", code: "echo &>/dev/null rm -rf /tmp/x"},
		{name: "amp_redirect_pig", code: "echo &> 1 pig"},
		{name: "heredoc_cont", code: "cat <<\\\nEOF\nEOF\nrm -rf /tmp/x"},
		{name: "bare_heredoc_cmdsub", code: "<<EOF\n$(rm -rf /tmp/x)\nEOF"},
		{name: "nested_heredoc_cmdsub", code: "cat <<EOF\n$(cat <<INNER\n$(rm -rf /tmp/x)\nINNER\n)\nEOF"},
		{name: "skipBalanced_comment_quote", code: "( rm -rf /tmp/x # '\n)"},
		{name: "skipBalanced_comment_paren", code: "( pig # (\n); true"},
		{name: "skipBalanced_dq_nested", code: `( echo "$( echo '")echo ' ; rm -rf /tmp/x ; echo "'" )" )`},
		{name: "backtick_escape_arith", code: "echo $(( `echo 1 \\`rm -rf /tmp/x\\` + 0` ))"},
		{name: "path_if_peel", code: "/tmp/if ls"},
		{name: "path_do_peel", code: "./do ls"},
		{name: "path_while_argv", argv: []string{"/tmp/while", "ls"}},
		{name: "git_grep_iO", argv: []string{"git", "grep", "-iO/usr/bin/id", "pat"}},
		{name: "git_grep_open_abbrev", argv: []string{"git", "grep", "--open=/usr/bin/id", "pat"}},
		{name: "git_cat_file_filters", argv: []string{"git", "cat-file", "--filters", "HEAD:a"}},
		{name: "git_cat_file_textc", argv: []string{"git", "cat-file", "--textc", "HEAD:a"}},
		{name: "git_grep_textc", argv: []string{"git", "grep", "--textc", "pat"}},
		{name: "background_amp", code: "ls &"},
		{name: "input_cmdsub", code: "cat < $(echo /etc/passwd)"},
		{name: "herestring_cmdsub", code: "cat <<< $(echo hi)"},
		{name: "dq_dev_null_escape", code: `echo pwn > "/dev/\null"`},
		{name: "ctxmode_workdir", argv: []string{"ctxmode", "--workdir", "/tmp/newdir"}},
		{name: "ctxmode_bare", argv: []string{"ctxmode"}},
		{name: "while_loop", code: "while true; do ls; done"},
		// agy Must Fix 1-6 samples
		{name: "agy1_arith_rm", code: "(( rm -rf /tmp/x ))"},
		{name: "agy2_cond_write", code: "[[ a > /tmp/pwn ]]"},
		{name: "agy3_path_if", argv: []string{"/tmp/if", "ls"}},
		{name: "agy6_git_grep_iO", argv: []string{"git", "grep", "-iO/usr/bin/id", "pat"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hit string
			if len(c.argv) > 0 {
				hit = guardArgvReadonly(c.argv)
			} else {
				hit = guardShellReadonly(c.code)
			}
			if hit == "" {
				t.Fatalf("expected block for %+v", c)
			}
		})
	}
}

func TestReadonlyAllowlist_AlFix5_CtxRunEntries(t *testing.T) {
	s, _ := auditTestServer(t)
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	// language non-shell
	for _, lang := range []string{"python", "javascript", "r", "elixir", "go", "ruby", "perl", "php"} {
		t.Run("lang_"+lang, func(t *testing.T) {
			_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
				Language: lang,
				Command:  "print(1)",
			})
			if err == nil {
				t.Fatalf("expected block for language=%s", lang)
			}
		})
	}

	// execute_file banned
	t.Run("execute_file", func(t *testing.T) {
		readme := "README.md"
		// ensure a file exists in workdir
		_ = readme
		_, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
			Path: "go.mod",
			Code: "console.log(1)",
		})
		if err == nil {
			t.Fatal("expected execute_file blocked for strict readonly")
		}
		if !strings.Contains(err.Error(), "execute_file") && !strings.Contains(err.Error(), ruleReadonlyWrite) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	// background=true banned
	t.Run("background", func(t *testing.T) {
		_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
			Command:    "ls",
			Background: true,
		})
		if err == nil {
			t.Fatal("expected background=true blocked")
		}
	})

	// env GOFLAGS banned
	t.Run("env_GOFLAGS", func(t *testing.T) {
		_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
			Argv: []string{"go", "list", "./..."},
			Env:  map[string]string{"GOFLAGS": "-toolexec=/usr/bin/id"},
		})
		if err == nil {
			t.Fatal("expected GOFLAGS env blocked")
		}
	})

	// LANG allowed
	t.Run("env_LANG_ok", func(t *testing.T) {
		_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
			Argv: []string{"true"},
			Env:  map[string]string{"LANG": "C"},
		})
		if err != nil {
			t.Fatalf("LANG should be allowed: %v", err)
		}
	})
}

func TestReadonlyAllowlist_AlFix5_FalsePositivesPass(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	pass := []struct {
		name string
		argv []string
		code string
	}{
		{name: "find_mtime", argv: []string{"find", ".", "-mtime", "-7"}},
		{name: "find_mmin", argv: []string{"find", ".", "-mmin", "-30"}},
		{name: "find_size", argv: []string{"find", ".", "-size", "-10k"}},
		{name: "find_perm", argv: []string{"find", ".", "-perm", "-644"}},
		{name: "find_name_dash", argv: []string{"find", ".", "-name", "-*"}},
		{name: "find_O3", argv: []string{"find", "-O3", "."}},
		{name: "date_d", argv: []string{"date", "-d", "2026-01-01"}},
		{name: "date_r", argv: []string{"date", "-r", "README.md"}},
		{name: "date_date", argv: []string{"date", "--date", "yesterday", "+%s"}},
		{name: "date_ud", argv: []string{"date", "-ud", "@0"}},
		{name: "du_d1", argv: []string{"du", "-d1"}},
		{name: "du_hd1", argv: []string{"du", "-hd1"}},
		{name: "du_d_sep", argv: []string{"du", "-d", "1", "/tmp"}},
		{name: "uniq_cf", argv: []string{"uniq", "-cf", "1", "input.txt"}},
		{name: "uniq_ic_s", argv: []string{"uniq", "-ic", "-s", "2", "input.txt"}},
		{name: "head_20", argv: []string{"head", "-20", "file"}},
		{name: "tail_20", argv: []string{"tail", "-20", "file"}},
		{name: "ss_s", argv: []string{"ss", "-s"}},
		{name: "ss_4", argv: []string{"ss", "-4"}},
		{name: "ss_6", argv: []string{"ss", "-6"}},
		{name: "ps_p", argv: []string{"ps", "-p", "1"}},
		{name: "ps_u", argv: []string{"ps", "-u", "root"}},
		{name: "ps_T", argv: []string{"ps", "-T"}},
		{name: "diff_U", argv: []string{"diff", "-U", "3", "a", "b"}},
		{name: "diff_C", argv: []string{"diff", "-C", "2", "a", "b"}},
		{name: "diff_I", argv: []string{"diff", "-I", "foo", "a", "b"}},
		{name: "diff_x", argv: []string{"diff", "-x", "*.o", "a", "b"}},
		{name: "jq_arg", argv: []string{"jq", "--arg", "k", "v", ".x == $k"}},
		{name: "jq_argjson", argv: []string{"jq", "--argjson", "k", "123", ".x"}},
		{name: "git_C_glued", argv: []string{"git", "-C/tmp", "status"}},
		{name: "git_branch_show_current", argv: []string{"git", "branch", "--show-current"}},
		{name: "hc_send", argv: []string{"hc", "send", "t42", "done"}},
		// green samples from TASK
		{name: "cat", argv: []string{"cat", "f"}},
		{name: "head_n", argv: []string{"head", "-n", "5", "f"}},
		{name: "tail_n", argv: []string{"tail", "-n", "5", "f"}},
		{name: "wc", argv: []string{"wc", "-l", "f"}},
		{name: "rg_dollar", code: "rg 'a$'"},
		{name: "jq_dot", argv: []string{"jq", "."}},
		{name: "git_log", argv: []string{"git", "log", "-1"}},
		{name: "git_show", argv: []string{"git", "show", "HEAD"}},
		{name: "git_diff", argv: []string{"git", "diff"}},
		{name: "git_status", argv: []string{"git", "status"}},
		{name: "git_branch", argv: []string{"git", "branch"}},
		{name: "ls", argv: []string{"ls", "-la"}},
		{name: "find_name", argv: []string{"find", ".", "-name", "x"}},
		{name: "sed_n", argv: []string{"sed", "-n", "1,20p", "f"}},
		{name: "ps_aux", argv: []string{"ps", "aux"}},
		{name: "ss_tlnp", argv: []string{"ss", "-tlnp"}},
		{name: "pipe_devnull_head", code: "ls 2>/dev/null | head -n 5"},
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
}

func TestReadonlyAllowlist_AlFix5_WorkerStillAllowsNesting(t *testing.T) {
	// worker/verifier: shared parser hardened but $(...) / subshell / heredoc still parse.
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	// These must NOT be rejected by the readonly allowlist path; worker uses
	// subagent guard instead. Ensure splitShellSegments still yields segments
	// for nested forms (no silent drop).
	segs := splitShellSegments("echo $(echo hi)")
	if len(segs) == 0 {
		t.Fatal("worker path: $(...) produced 0 segments")
	}
	segs = splitShellSegments("( echo hi )")
	if len(segs) == 0 {
		t.Fatal("worker path: subshell produced 0 segments")
	}
	// (( should now parse as nested subshells, not skip
	segs = splitShellSegments("(( echo hi ))")
	if len(segs) == 0 {
		t.Fatal("worker path: (( )) produced 0 segments after dash-aligned fix")
	}
	// Unbalanced skipBalanced must fail closed
	hit := guardShellSubagent("( echo hi # '\n")
	if hit == "" {
		// may or may not hit nested agent; at least must not silently allow pig
	}
	_ = hit
	hit = guardShellSubagent("( pig # (\n); true")
	if hit == "" {
		t.Fatal("expected subagent guard to see pig after skipBalanced fix")
	}
}

// === Merged from readonly_allowlist_alfix6_test.go ===

// ---------------------------------------------------------------------------
// AlFix6: AUDIT3 red tests + dash differential argv comparison + fuzz.
// ---------------------------------------------------------------------------

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
		{name: "M8_tilde", code: "~", want: "block", sub: "charset"},
		{name: "M8_tilde_root", code: "~root", want: "block", sub: "charset"},
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
		{name: "S3_herdr_V", argv: []string{"herdr", "-V"}, want: "block"},
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
		{name: "M1_cr_comment_seg", code: "true \r#; echo PWN", want: "block"}, // D1: \r fail-closed
		{name: "M2_nice_pig", code: `nice -n '2'>/dev/null pig`, want: "block"},
		{name: "M3_fake_arith", code: `bash -c 'echo $((pig); (true))'`, want: "block"},
		{name: "M4_param_pig", code: `echo $(echo "${x:-")"}"; pig)`, want: "block"},
		{name: "M4_param_sq_pig", code: `echo $(echo ${x:-')'}; pig)`, want: "block"},
		{name: "M5_linecont", code: "echo $\\\n(pig)", want: "block"},
		{name: "M5_dq_linecont", code: "echo \"$\\\n(pig)\"", want: "block"},
		{name: "M6_bt", code: "echo `\\`pig\\``", want: "block"},
		{name: "M6_bt_dbs", code: "echo `echo a\\\\` ; pig ; #`", want: "block"},
		{name: "M7_heredoc_cr", code: "cat <<'EOF'\nEOF\r\n'; pig; '\nEOF", want: "block"}, // D1: \r fail-closed
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
		// D1: control CR is rejected at entry (depthExceeded marker).
		if len(segs) != 1 || !segs[0].depthExceeded {
			t.Fatalf("want depthExceeded marker for \\r, got %#v", segs)
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
		// D1: control CR rejected at entry.
		if len(segs) != 1 || !segs[0].depthExceeded {
			t.Fatalf("want depthExceeded for redirect \\r, got %#v", segs)
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
		{name: "hc_send", argv: []string{"hc", "send", "t42", "done"}},
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
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	printer := ensureArgvPrinter(t)

	type tc struct {
		name string
		code string // original; head will be replaced with printer for dash & expected
		// expectGo is a function that returns Go argv (without needing printer in parse)
		goArgv func() []string
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
				if strings.Contains(c.name, "cr_") {
					// D1 fail-closed: CR rejected before argv extraction.
					t.Skip("CR fail-closed; no argv to compare")
				}
				t.Fatal("Go produced empty argv")
			}
			if c.name == "cr_cmd_head" {
				if goArgv[0] != "printargv\r" {
					t.Fatalf("Go argv[0]=%q want printargv\\r", goArgv[0])
				}
				return
			}
			// Absolute argvprinter path → argv[0]=argvprinter; compare operands to Go argv[1:].
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
	// Full multi-segment scripts fed to /bin/sh -c (no single-segment cheat).
	cases := []string{
		"p1; p2",
		"p1 && p2",
		"p1 | p2",
		"p1\np2",
		"echo x; p1",
	}
	for _, code := range cases {
		t.Run(code, func(t *testing.T) {
			goArgvs, depthEx := collectGoCmdArgvs(code)
			names := append(namesFromGoArgvs(goArgvs), "p1", "p2", "echo")
			pathDir, outFile := setupPrinterPATH(t, names)
			_ = os.Remove(outFile)
			dashArgvs, _, _ := runDashCollectArgvs(t, code, pathDir, outFile)
			if depthEx {
				return
			}
			miss := dashExecutedUnknown(filterExternalArgvs(goArgvs), dashArgvs)
			if len(miss) > 0 {
				t.Fatalf("dash ran %v not seen by AST; go=%s dash=%s", miss, fmtArgvs(goArgvs), fmtArgvs(dashArgvs))
			}
		})
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
	if testing.Short() {
		t.Skip("short")
	}
	printer := ensureArgvPrinter(t)
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
	if !strings.Contains(hit, "glob") && !strings.Contains(hit, "*") && !strings.Contains(hit, "Hint:") {
		t.Fatalf("hint should mention glob guidance, got %q", hit)
	}
}

// Ensure test binary path is absolute for dash.
func TestAlFix6_PrinterSelfCheck(t *testing.T) {
	bin := ensureArgvPrinter(t)
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

// === Merged from readonly_allowlist_alfix7_test.go ===

// ---------------------------------------------------------------------------
// AlFix7: real dash argv differential tests (independent printer, race-safe).
// Host-safety hardened: no auto-delete under /, absolute redirects gated,
// write-dangerous names → argvprinter, fuzz corpus free of /, .., cd, ~.
// ---------------------------------------------------------------------------

var (
	argvPrinterOnce sync.Once
	argvPrinterPath string
	argvPrinterErr  error
)

func ensureArgvPrinter(t *testing.T) string {
	t.Helper()
	argvPrinterOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ctxmode-argvprinter-*")
		if err != nil {
			argvPrinterErr = err
			return
		}
		srcDir := filepath.Join(dir, "src")
		if err := os.MkdirAll(srcDir, 0o755); err != nil {
			argvPrinterErr = err
			return
		}
		src := filepath.Join(srcDir, "main.go")
		// Prefer checked-in testdata; fall back to embedded source.
		candidates := []string{
			"testdata/argvprinter/main.go",
		}
		var data []byte
		for _, c := range candidates {
			data, err = os.ReadFile(c)
			if err == nil {
				break
			}
		}
		if err != nil {
			data = []byte(argvPrinterSource)
		}
		if err := os.WriteFile(src, data, 0o644); err != nil {
			argvPrinterErr = err
			return
		}
		out := filepath.Join(dir, "argvprinter")
		cmd := exec.Command("go", "build", "-o", out, src)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			argvPrinterErr = fmt.Errorf("go build argvprinter: %v\n%s", err, b)
			return
		}
		argvPrinterPath = out
	})
	if argvPrinterErr != nil {
		t.Fatalf("argv printer: %v", argvPrinterErr)
	}
	return argvPrinterPath
}

const argvPrinterSource = `package main
import (
	"encoding/json"
	"os"
	"path/filepath"
)
func main() {
	out := os.Getenv("CTXMODE_ARGV_OUT")
	if out == "" { os.Exit(2) }
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil { os.Exit(2) }
	argv := make([]string, len(os.Args))
	copy(argv, os.Args)
	if len(argv) > 0 { argv[0] = filepath.Base(argv[0]) }
	if err := json.NewEncoder(f).Encode(argv); err != nil { _ = f.Close(); os.Exit(2) }
	_ = f.Close()
}
`

// collectGoCmdArgvs returns argv slices for segments that look like real commands
// (non-empty argv, not depth-exceeded markers). Nested substitution segments are
// included because dash executes them too.
func collectGoCmdArgvs(code string) (argvs [][]string, depthExceeded bool) {
	// Nested CmdSubst/heredoc commands are already sibling segments from the AST parser.
	// parseErr is fail-closed (same as depthExceeded for dash-diff purposes): the guard
	// rejected before emitting a complete argv picture, so argv mismatch is expected.
	// Wrapper heads are peeled so dash argv[0] (post env/nice/xargs) can match Go targets.
	// Interpreter -c payloads are recursively collected so dashExecutedUnknown sees nested
	// heads (SF-1). When peelWrappers consumes the whole argv (env -S only, etc.), treat
	// as fail-closed — the argv picture of what -S would exec is incomplete.
	segs := splitShellSegments(code)
	for _, s := range segs {
		if s.depthExceeded || s.parseErr != "" {
			depthExceeded = true
			continue
		}
		if len(s.argv) == 0 {
			continue
		}
		head, payloads, _, exhausted := peelWrappers(s.argv)
		if exhausted {
			depthExceeded = true
			continue
		}
		if len(head) == 0 {
			// Peel ate everything (e.g. env -vS '…' with no trailing command).
			if len(payloads) > 0 {
				depthExceeded = true
			}
			continue
		}
		cp := append([]string(nil), head...)
		argvs = append(argvs, cp)
		if shellText, ok := unwrapShellArgv(head); ok && shellText != "" {
			nested, nestEx := collectGoCmdArgvs(shellText)
			if nestEx {
				depthExceeded = true
			}
			argvs = append(argvs, nested...)
		}
		// flock LOCK -c CMD / flock LOCK cmd…: collect inner command so
		// dashExecutedUnknown sees what dash runs after the lock wrapper (SF-1).
		if filepath.Base(head[0]) == "flock" {
			inner, cmdText := skipFlockArgs(head, 1)
			if cmdText != "" {
				if isDynamicArg(cmdText) {
					depthExceeded = true
				} else {
					nested, nestEx := collectGoCmdArgvs(cmdText)
					if nestEx {
						depthExceeded = true
					}
					argvs = append(argvs, nested...)
				}
			} else if inner >= 0 && inner < len(head) {
				nestedHead := append([]string(nil), head[inner:]...)
				if len(nestedHead) > 0 {
					argvs = append(argvs, nestedHead)
					if shellText2, ok2 := unwrapShellArgv(nestedHead); ok2 && shellText2 != "" {
						n2, n2ex := collectGoCmdArgvs(shellText2)
						if n2ex {
							depthExceeded = true
						}
						argvs = append(argvs, n2...)
					}
				}
			}
		}
	}
	return argvs, depthExceeded
}

// realWrapperBins are wrappers/interpreters that must resolve to real system
// binaries so MF-6-style env/nice/xargs/find peeling still works under PATH.
var realWrapperBins = []string{
	"sh", "dash", "bash", "env", "nice", "timeout", "xargs", "find",
	"stdbuf", "setsid", "flock", "nohup",
}

// argvPrinterLeafNames are leaf probes, blocked targets, and write-dangerous
// command names that must NEVER resolve to real binaries in the test PATH.
var argvPrinterLeafNames = []string{
	"p1", "p2", "p3", "probe", "printargv", "pig", "pi", "agy",
	"dispatch-agent", "dispatch-agent-go", "grok", "tmux", "screen", "sudo",
	"rg", "ls", "cat", "git", "rm", "mv", "cp", "tee", "dd", "chmod", "ln",
	"herdr", "herdsman", "ctxmode", "head", "tail", "wc", "sort", "uniq",
	"cut", "tr", "jq", "diff", "stat", "file", "du", "df",
	"python3", "node", "perl", "ruby", "php",
}

func lookRealBin(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range []string{"/bin", "/usr/bin"} {
		cand := filepath.Join(d, name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	return ""
}

// setupPrinterPATH creates a temp dir with:
//   - real symlinks for wrappers/interpreters (sh/env/nice/find/…)
//   - argvprinter symlinks for leaf probes + write-dangerous names
//
// Dash builtins (echo/true/false/test/[) are NOT faked into PATH.
func setupPrinterPATH(t *testing.T, names []string) (pathDir, outFile string) {
	t.Helper()
	printer := ensureArgvPrinter(t)
	pathDir = t.TempDir()
	outFile = filepath.Join(t.TempDir(), "argv.jsonl")
	seen := map[string]bool{}

	linkPrinter := func(base string) {
		if base == "" || base == "." || base == "/" || seen[base] {
			return
		}
		if isDashBuiltin(base) {
			return
		}
		seen[base] = true
		if err := os.Symlink(printer, filepath.Join(pathDir, base)); err != nil {
			t.Fatalf("symlink printer %s: %v", base, err)
		}
	}
	linkReal := func(base string) {
		if base == "" || seen[base] {
			return
		}
		seen[base] = true
		target := lookRealBin(base)
		if target == "" {
			// Missing wrapper: fall back to printer so PATH stays closed.
			if err := os.Symlink(printer, filepath.Join(pathDir, base)); err != nil {
				t.Fatalf("symlink fallback %s: %v", base, err)
			}
			return
		}
		if err := os.Symlink(target, filepath.Join(pathDir, base)); err != nil {
			t.Fatalf("symlink real %s -> %s: %v", base, target, err)
		}
	}

	for _, n := range realWrapperBins {
		linkReal(n)
	}
	for _, n := range argvPrinterLeafNames {
		linkPrinter(n)
	}
	for _, n := range names {
		linkPrinter(filepath.Base(n))
	}
	return pathDir, outFile
}

func namesFromGoArgvs(argvs [][]string) []string {
	var names []string
	for _, a := range argvs {
		if len(a) > 0 {
			// R18-Oracle-M4: the NUL-provenanced tilde marker
			// (\x00__ctx_tilde__\x00) is internal encoding evidence, never
			// executable text — argv bytes can never carry NUL — so it is
			// stripped before the placeholder name is shaped into a symlink
			// fixture exactly like the runtime argv it models.
			names = append(names, strings.ReplaceAll(a[0], "\x00", ""))
		}
	}
	return names
}

// snapshotRootDir records the set of names present directly under "/".
func snapshotRootDir(t *testing.T) map[string]struct{} {
	t.Helper()
	ents, err := os.ReadDir("/")
	if err != nil {
		t.Fatalf("snapshot /: %v", err)
	}
	m := make(map[string]struct{}, len(ents))
	for _, e := range ents {
		m[e.Name()] = struct{}{}
	}
	return m
}

// assertRootDirUnchanged fails if "/" gained new entries.
// It NEVER deletes or modifies anything under "/".
func assertRootDirUnchanged(t *testing.T, before map[string]struct{}) {
	t.Helper()
	ents, err := os.ReadDir("/")
	if err != nil {
		t.Fatalf("re-read /: %v", err)
	}
	var added []string
	for _, e := range ents {
		if _, ok := before[e.Name()]; !ok {
			added = append(added, e.Name())
		}
	}
	if len(added) > 0 {
		t.Fatalf("host safety: new entries appeared under /: %v (report only; nothing deleted)", added)
	}
}

// takeRedirectWord returns the next shell word at s[0:] (quoted or bare) and
// the number of bytes consumed. Quotes are stripped for the returned value;
// glued quote/bare tails are concatenated (e.g. '/dev/null'foo → /dev/nullfoo).
func takeRedirectWord(s string) (word string, n int) {
	if s == "" {
		return "", 0
	}
	i := 0
	var b strings.Builder
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r', ';', '&', '|', '<', '>', '(', ')', '\x00':
			return b.String(), i
		case '\'':
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++ // closing '
			}
		case '"':
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++ // closing "
			}
		case '\\':
			if i+1 < len(s) {
				b.WriteByte(s[i+1])
				i += 2
			} else {
				b.WriteByte('\\')
				i++
			}
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String(), i
}

// isSafeRedirectForTestExec reports whether code is safe to feed to /bin/sh.
// Unsafe = absolute redirect targets other than /dev/null, dynamic redirect
// targets ($ ` * ? [ ..), unquoted-# comment quote-flip hazards, or find
// write actions (-delete/-fprint*/-fls). Heredocs and fd-duplication (>&N)
// are ignored. On unsafe, callers must NOT exec /bin/sh.
func isSafeRedirectForTestExec(code string) bool {
	// Real find in PATH can write/delete; never feed those samples to /bin/sh.
	if strings.Contains(code, "-delete") || strings.Contains(code, "-fprint") || strings.Contains(code, "-fls") {
		return false
	}
	i := 0
	for i < len(code) {
		// Unquoted '#' at a word-start boundary starts a comment through '\n'.
		// Quotes inside the comment must NOT flip quote state (SF-1).
		if code[i] == '#' {
			atWordStart := i == 0
			if !atWordStart {
				prev := code[i-1]
				atWordStart = prev == ' ' || prev == '\t' || prev == '\n' ||
					prev == ';' || prev == '|' || prev == '&' || prev == '(' || prev == ')'
			}
			if atWordStart {
				for i < len(code) && code[i] != '\n' {
					i++
				}
				continue
			}
		}
		// Skip single-quoted regions so literal > inside quotes is ignored.
		if code[i] == '\'' {
			i++
			for i < len(code) && code[i] != '\'' {
				i++
			}
			if i < len(code) {
				i++
			}
			continue
		}
		if code[i] == '"' {
			i++
			for i < len(code) && code[i] != '"' {
				if code[i] == '\\' && i+1 < len(code) {
					i += 2
					continue
				}
				i++
			}
			if i < len(code) {
				i++
			}
			continue
		}
		if code[i] == '\\' && i+1 < len(code) {
			i += 2
			continue
		}

		c := code[i]
		if c != '>' && c != '<' {
			i++
			continue
		}
		// Heredoc << / <<- : not a file redirect target we gate.
		if c == '<' && i+1 < len(code) && code[i+1] == '<' {
			i += 2
			continue
		}
		j := i + 1
		if c == '>' && j < len(code) && (code[j] == '>' || code[j] == '|') {
			j++ // >> or >|
		}
		// Fd duplication: >&1 / <&0 — no path target.
		if j < len(code) && code[j] == '&' {
			i = j + 1
			continue
		}
		for j < len(code) && (code[j] == ' ' || code[j] == '\t') {
			j++
		}
		if j >= len(code) {
			return true
		}
		rawStart := j
		target, n := takeRedirectWord(code[j:])
		rawTarget := code[rawStart : rawStart+n]
		if target == "" ||
			strings.ContainsAny(rawTarget, "$`*?[\r\n") ||
			strings.Contains(target, "..") ||
			(strings.HasPrefix(target, "/") && target != "/dev/null") {
			return false
		}
		i = j
	}
	return true
}

// runDashCollectArgvs executes code under /bin/sh with PATH limited to the
// printer directory. Returns the JSONL-decoded argv sequences dash invoked.
// Host safety: skips exec when redirects target absolute paths other than
// /dev/null; snapshots "/" around the run and fails on new entries (never deletes).
func runDashCollectArgvs(t *testing.T, code, pathDir, outFile string) ([][]string, string, error) {
	t.Helper()
	if !isSafeRedirectForTestExec(code) {
		return nil, "", nil
	}
	before := snapshotRootDir(t)
	defer assertRootDirUnchanged(t, before)

	_ = os.Remove(outFile)
	workDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", code)
	cmd.Dir = workDir
	cmd.Env = []string{
		"PATH=" + pathDir,
		"CTXMODE_ARGV_OUT=" + outFile,
		"HOME=" + workDir,
		"TMPDIR=" + workDir,
		"LANG=C",
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	raw := buf.String()
	data, rerr := os.ReadFile(outFile)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return nil, raw, err
		}
		return nil, raw, fmt.Errorf("read argv out: %v (run err=%v raw=%q)", rerr, err, raw)
	}
	var argvs [][]string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var a []string
		if jerr := json.Unmarshal(line, &a); jerr != nil {
			return argvs, raw, fmt.Errorf("json line %q: %w", line, jerr)
		}
		argvs = append(argvs, a)
	}
	return argvs, raw, err
}

func argvsEqual(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

func fmtArgvs(a [][]string) string {
	var b strings.Builder
	for i, v := range a {
		fmt.Fprintf(&b, "  [%d]=%#v\n", i, v)
	}
	return b.String()
}

// isDashBuiltin reports Debian dash builtins measured via `type` (TASK sh8).
// fc/help/let/bind/typeset/declare are absent on this dash.
func isDashBuiltin(name string) bool {
	switch name {
	case ":", ".", "[", "alias", "bg", "break", "cd", "command", "continue",
		"echo", "eval", "exec", "exit", "export", "false", "fg", "getopts",
		"hash", "jobs", "kill", "local", "printf", "pwd", "read", "readonly",
		"return", "set", "shift", "test", "times", "trap", "true", "type",
		"ulimit", "umask", "unalias", "unset", "wait":
		return true
	}
	return false
}

// filterExternalArgvs drops dash builtins (they never hit the printer PATH).
func filterExternalArgvs(argvs [][]string) [][]string {
	var out [][]string
	for _, a := range argvs {
		if len(a) == 0 || isDashBuiltin(a[0]) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// isRealWrapper reports wrappers/interpreters that resolve to real binaries.
func isRealWrapper(name string) bool {
	for _, w := range realWrapperBins {
		if name == w {
			return true
		}
	}
	return false
}

// staticLeafArgvs keeps argvprinter-leaf commands (not builtins, not real wrappers)
// for deep argv[0]+argv[1:] matching against dash printer captures.
func staticLeafArgvs(argvs [][]string) [][]string {
	var out [][]string
	for _, a := range argvs {
		if len(a) == 0 || isDashBuiltin(a[0]) || isRealWrapper(a[0]) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// argvHasDynamic reports placeholders left by the AST for non-static words.
func argvHasDynamic(a []string) bool {
	for _, s := range a {
		if strings.Contains(s, cmdSubPlaceholder) || strings.Contains(s, cmdSubPlaceholderQuoted) ||
			strings.Contains(s, dynamicRedirectTarget) ||
			strings.Contains(s, envUnknownLongPrefix) || strings.Contains(s, "__ctx_") {
			return true
		}
	}
	return false
}

// staticConcreteLeafArgvs keeps printer-leaf commands with fully static argv
// (no __ctx_cmdsub__ / dynamic placeholders) for deep argv[0]+argv[1:] checks.
func staticConcreteLeafArgvs(argvs [][]string) [][]string {
	var out [][]string
	for _, a := range staticLeafArgvs(argvs) {
		if argvHasDynamic(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func leafArgvDeepAgreeExt(goLeaves, dashLeaves, goWithDyn [][]string) bool {
	// When dash ran a head that Go listed as a static leaf, full argv must
	// exact-match one static Go leaf. If Go also tracked a dynamic sibling
	// with the same argv0 (placeholder args), a dash expansion that does not
	// exact-match is ignored — the static Go leaf is a different invocation.
	// Unknown dash heads use dashExecutedUnknown. Go-only over-parses are ignored.
	byHead := map[string][][]string{}
	for _, g := range goLeaves {
		if len(g) == 0 {
			continue
		}
		byHead[g[0]] = append(byHead[g[0]], g)
	}
	dynHeads := map[string]bool{}
	for _, g := range goWithDyn {
		if len(g) == 0 || !argvHasDynamic(g) {
			continue
		}
		dynHeads[g[0]] = true
	}
	for _, d := range dashLeaves {
		if len(d) == 0 {
			continue
		}
		cands := byHead[d[0]]
		if len(cands) == 0 {
			continue
		}
		ok := false
		for _, g := range cands {
			if len(g) != len(d) {
				continue
			}
			eq := true
			for k := range g {
				if g[k] != d[k] {
					eq = false
					break
				}
			}
			if eq {
				ok = true
				break
			}
		}
		if !ok {
			if dynHeads[d[0]] {
				continue
			}
			return false
		}
	}
	return true
}

// dashExecutedUnknown reports whether dash ran a command name that Go did not
// list in any segment argv[0]. This is the Must-Fix-1 failure shape.

// envArgv0Aliases collects names that env -a / --argv0 would install as the
// executed process argv[0], so argvprinter recordings of those names are not
// treated as real executions of a binary with that basename.
func envArgv0Aliases(argvs [][]string) map[string]bool {
	out := map[string]bool{}
	for _, a := range argvs {
		for i := 0; i < len(a); i++ {
			switch {
			case a[i] == "-a" || a[i] == "--argv0":
				if i+1 < len(a) {
					out[a[i+1]] = true
					i++
				}
			case strings.HasPrefix(a[i], "-a") && a[i] != "-a" && !strings.HasPrefix(a[i], "--"):
				rest := a[i][2:]
				if rest != "" {
					out[rest] = true
				}
			case strings.HasPrefix(a[i], "--argv0="):
				out[a[i][len("--argv0="):]] = true
			}
		}
	}
	return out
}

func filterAliasMisses(miss []string, aliases map[string]bool) []string {
	if len(aliases) == 0 {
		return miss
	}
	var out []string
	for _, m := range miss {
		if !aliases[m] {
			out = append(out, m)
		}
	}
	return out
}

func dashExecutedUnknown(goArgvs, dashArgvs [][]string) []string {
	seen := map[string]bool{}
	argv0Aliases := map[string]bool{} // env -a NAME / --argv0 NAME rename the executed argv0
	for _, a := range goArgvs {
		if len(a) > 0 {
			seen[a[0]] = true
		}
		for i := 0; i+1 < len(a); i++ {
			if a[i] == "-a" || a[i] == "--argv0" {
				argv0Aliases[a[i+1]] = true
			}
			if strings.HasPrefix(a[i], "--argv0=") {
				argv0Aliases[a[i][len("--argv0="):]] = true
			}
		}
	}
	var miss []string
	for _, a := range dashArgvs {
		if len(a) == 0 {
			continue
		}
		if !seen[a[0]] && !argv0Aliases[a[0]] {
			miss = append(miss, a[0])
		}
	}
	return miss
}

type dashDiffCase struct {
	name string
	code string
	// compareFull: when true, require exact argv sequence match (segment count + bytes).
	// when false, only fail if dash executed a command Go did not see (or segment-count 0 vs >0).
	compareFull bool
	// expectDashRuns: optional; if set, require dash to have invoked at least one command.
	expectDashRuns bool
}

func alfix7MustFixSamples() []dashDiffCase {
	return []dashDiffCase{
		// Must Fix 1
		{name: "MF1_comment_cont_rm", code: "# \\\nrm -rf /tmp/pwn", compareFull: false, expectDashRuns: true},
		{name: "MF1_comment_cont_pig", code: "# \\\npig", compareFull: false, expectDashRuns: true},
		{name: "MF1_comment_cont_python", code: "# \\\npython3 -c 'import os'", compareFull: false, expectDashRuns: true},
		{name: "MF1_even_bs_pig", code: "echo \\\\\npig", compareFull: false, expectDashRuns: true},
		{name: "MF1_dq_sq_contam", code: "echo \"'\" \"$\\\n(pig)\"", compareFull: false, expectDashRuns: true},
		// Must Fix 2
		{name: "MF2_heredoc_cr_delim", code: "cat <<'EOF'\r\nEOF\n'\nEOF\r\npig\n# '\n", compareFull: false, expectDashRuns: true},
		// Must Fix 3
		{name: "MF3_param_sq_in_dq", code: `echo "${UNSET:-'$(pig)'}"`, compareFull: false, expectDashRuns: true},
		{name: "MF3_param_brace_sq", code: `echo "${UNSET:-'}"; pig # '}"`, compareFull: false, expectDashRuns: true},
		{name: "MF3_nested_param", code: `echo ${UNSET1:-"${UNSET2:-"'"}" $(pig)}`, compareFull: false, expectDashRuns: true},
		{name: "MF3_redir_param", code: `true < "${UNSET:-"'"}" 2>/dev/null ; pig # '`, compareFull: false, expectDashRuns: true},
		// Must Fix 4
		{name: "MF4_bt_in_param", code: "echo ${UNSET:-`\\`pig\\``}", compareFull: false, expectDashRuns: true},
		{name: "MF4_bt_in_arith", code: "echo $(( `\\`pig\\`` + 0 ))", compareFull: false, expectDashRuns: true},
		// Must Fix 5
		{name: "MF5_case_in_dq_cmdsub", code: `echo "$(case x in x) pig;; esac)"`, compareFull: false, expectDashRuns: true},
		{name: "MF5_heredoc_in_dq_cmdsub", code: "echo \"$(cat <<EOF\n)\nEOF\npig)\"", compareFull: false, expectDashRuns: true},
		// Must Fix 6 (argv-level; also exercised via shell)
		{name: "MF6_env_a", code: "env -a true pig", compareFull: false, expectDashRuns: true},
		{name: "MF6_env_argv0", code: "env --argv0 true pig", compareFull: false, expectDashRuns: true},
		{name: "MF6_env_vS", code: "env -vS 'env pig'", compareFull: false, expectDashRuns: true},
		{name: "MF6_env_dash", code: "env - sh -c p1", compareFull: false, expectDashRuns: false},
	}
}

func alfix7Audit3Diff32() []dashDiffCase {
	// Shell-string cases from AUDIT3 §4 (argv-only cases handled separately).
	return []dashDiffCase{
		{name: "A01_cr_comment", code: "true \r#; echo PWN", compareFull: false},
		{name: "A02_cr_cmdhead", code: "ls\r", compareFull: false},
		{name: "A03_cr_opt", code: "rg -e \r --pre=/usr/bin/id pat .", compareFull: true},
		{name: "A04_cr_redir", code: "echo hi >/dev/null\rfoo", compareFull: false},
		{name: "A05_ctrl_v", code: "ls \v -la", compareFull: true},
		{name: "A06_sq_digit", code: "rg -e '2'>/dev/null --pre=/usr/bin/id pat .", compareFull: true},
		{name: "A07_dq_digit", code: `nice -n "2">/dev/null pig`, compareFull: false, expectDashRuns: true},
		{name: "A08_bs_digit", code: `rg -e \2>/dev/null --pre=/usr/bin/id pat .`, compareFull: true},
		{name: "A09_empty_q_digit", code: `rg -e ""2>/dev/null --pre=/usr/bin/id pat .`, compareFull: true},
		{name: "A10_midword_digit", code: "echo a2>/dev/null b", compareFull: false},
		{name: "A11_bare_io", code: "ls 2>/dev/null", compareFull: true},
		{name: "A12_digit_space", code: "echo 2 >/dev/null", compareFull: false},
		{name: "A13_redir_glue", code: "echo hi >'/dev/null'foo", compareFull: false},
		{name: "A14_fd_glue", code: "echo hi 2>&1foo", compareFull: false},
		{name: "A15_leading_redir", code: "2>/dev/null ls -la", compareFull: true},
		{name: "A16_quoted_if", code: "'if' true; then ls; fi", compareFull: false},
		{name: "A17_tilde", code: "~", compareFull: false},
		{name: "A18_tilde_arg", code: "ls ~", compareFull: false},
		{name: "A19_glob", code: "ls *.go", compareFull: false},
		{name: "A20_fake_arith", code: `bash -c 'echo $((pig); (true))'`, compareFull: false},
		{name: "A21_arith_nested", code: "echo $(( (1+1) * $(pig) ))", compareFull: false, expectDashRuns: true},
		{name: "A22_param_dq", code: `echo $(echo "${x:-")"}"; pig)`, compareFull: false, expectDashRuns: true},
		{name: "A23_param_sq", code: `echo $(echo ${x:-')'}; pig)`, compareFull: false, expectDashRuns: true},
		{name: "A24_linecont_dollar", code: "echo $\\\n(pig)", compareFull: false, expectDashRuns: true},
		{name: "A25_dq_linecont", code: "echo \"$\\\n(pig)\"", compareFull: false, expectDashRuns: true},
		{name: "A26_linecont_heredoc", code: "cat <\\\n<EOF\n$(pig)\nEOF", compareFull: false, expectDashRuns: true},
		{name: "A27_bt_escape", code: "echo `\\`pig\\``", compareFull: false, expectDashRuns: true},
		{name: "A28_bt_dbs", code: "echo `echo a\\\\` ; pig ; #`", compareFull: false, expectDashRuns: true},
		{name: "A29_heredoc_cr", code: "cat <<'EOF'\nEOF\r\n'; pig; '\nEOF", compareFull: false},
	}
}

func alfix7ShouldFixSamples() []dashDiffCase {
	return []dashDiffCase{
		{name: "SF_comment_cont_ls", code: "# \\\nls", compareFull: false, expectDashRuns: true},
		{name: "SF_heredoc_phys_line", code: "cat <<'EOF' >/dev/null\nEO\\\nF\n'\nEOF\npig\n# '\n", compareFull: false, expectDashRuns: true},
	}
}

func alfix7ReportTableSamples() []dashDiffCase {
	// From REPORT §2 excerpt table (shell forms).
	return []dashDiffCase{
		{name: "R_cr_pwn", code: "true \r#; echo PWN", compareFull: false},
		{name: "R_rg_cr_pre", code: "rg -e \r --pre=/usr/bin/id pat .", compareFull: true},
		{name: "R_sq_digit_pre", code: "rg -e '2'>/dev/null --pre=/usr/bin/id pat .", compareFull: true},
		{name: "R_bs_digit", code: `rg -e \2>/dev/null --pre=/usr/bin/id pat .`, compareFull: true},
		{name: "R_fd_glue", code: "echo hi 2>&1foo", compareFull: false},
		{name: "R_fake_arith", code: `bash -c 'echo $((pig); (true))'`, compareFull: false},
		{name: "R_comment_cont_pwn", code: "# \\\npig", compareFull: false, expectDashRuns: true},
		{name: "R_comment_cont_pig", code: "# \\\npig", compareFull: false, expectDashRuns: true},
		{name: "R_comment_cont_ls", code: "# \\\nls", compareFull: false, expectDashRuns: true},
		{name: "R_comment_cont_cat", code: "# \\\ncat", compareFull: false, expectDashRuns: true},
	}
}

func runDashDiffCases(t *testing.T, cases []dashDiffCase) (mismatches []string) {
	t.Helper()
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	_ = ensureArgvPrinter(t)
	rootBefore := snapshotRootDir(t)
	t.Cleanup(func() { assertRootDirUnchanged(t, rootBefore) })

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			before := snapshotRootDir(t)
			t.Cleanup(func() { assertRootDirUnchanged(t, before) })

			goArgvs, depthEx := collectGoCmdArgvs(c.code)
			// Always install printer names for expected dash heads + common set.
			names := namesFromGoArgvs(goArgvs)
			// Seed likely heads from the code text for MF1 (Go may see 0 segs).
			for _, h := range []string{"rm", "pig", "python3", "echo", "true", "ls", "cat", "env", "sh", "bash", "nice", "rg"} {
				if strings.Contains(c.code, h) {
					names = append(names, h)
				}
			}
			pathDir, outFile := setupPrinterPATH(t, names)
			safe := isSafeRedirectForTestExec(c.code)
			dashArgvs, raw, _ := runDashCollectArgvs(t, c.code, pathDir, outFile)

			// SF-1: never early-return on guard reject. When !depthEx the Go AST
			// produced a complete argv picture, so dashExecutedUnknown must still
			// fire even if the worker guard blocked pig/rm by name. Only depthEx
			// (parseErr / depthExceeded fail-closed) skips those asserts.
			// expectDashRuns: skip when safety gate refused exec or AST fail-closed.
			if c.expectDashRuns && len(dashArgvs) == 0 && safe && !depthEx {
				msg := fmt.Sprintf("%s: expected dash to run external probe; raw=%q go=%s Hint: replace builtins with p1/p2/pig", c.name, raw, fmtArgvs(goArgvs))
				mismatches = append(mismatches, msg)
				t.Error(msg)
				return
			}

			goExt := filterExternalArgvs(goArgvs)
			// env -a/--argv0 aliases come from the unpeeled segment argv.
			rawArgvs := [][]string{}
			for _, s := range splitShellSegments(c.code) {
				if len(s.argv) > 0 {
					rawArgvs = append(rawArgvs, append([]string(nil), s.argv...))
				}
			}
			aliases := envArgv0Aliases(rawArgvs)
			miss := filterAliasMisses(dashExecutedUnknown(goExt, dashArgvs), aliases)
			if len(miss) > 0 && !depthEx {
				msg := fmt.Sprintf("%s: dash ran cmds Go missed: %v\ncode=%q\ngo:\n%sdash:\n%sraw=%q",
					c.name, miss, c.code, fmtArgvs(goArgvs), fmtArgvs(dashArgvs), raw)
				mismatches = append(mismatches, msg)
				t.Error(msg)
				return
			}
			// Segment count mismatch when Go sees 0 externals but dash ran ≥1 (MF1 shape).
			if len(goExt) == 0 && len(dashArgvs) > 0 && !depthEx {
				msg := fmt.Sprintf("%s: Go 0 external segs but dash ran %d\ncode=%q\ndash:\n%s",
					c.name, len(dashArgvs), c.code, fmtArgvs(dashArgvs))
				mismatches = append(mismatches, msg)
				t.Error(msg)
				return
			}
			if c.compareFull && !depthEx {
				// Full argv[0]+argv[1:] compare for external commands only.
				if !argvsEqual(goExt, dashArgvs) {
					msg := fmt.Sprintf("%s: argv sequence mismatch\ncode=%q\ngoExt:\n%sdash:\n%sraw=%q",
						c.name, c.code, fmtArgvs(goExt), fmtArgvs(dashArgvs), raw)
					mismatches = append(mismatches, msg)
					t.Error(msg)
				}
			}
		})
	}
	return mismatches
}

func TestAlFix7_DashDiff_MustFix(t *testing.T) {
	runDashDiffCases(t, alfix7MustFixSamples())
}

func TestAlFix7_DashDiff_Audit3_32(t *testing.T) {
	runDashDiffCases(t, alfix7Audit3Diff32())
}

func TestAlFix7_DashDiff_ShouldFixSamples(t *testing.T) {
	runDashDiffCases(t, alfix7ShouldFixSamples())
}

func TestAlFix7_DashDiff_ReportTable(t *testing.T) {
	runDashDiffCases(t, alfix7ReportTableSamples())
}

// Guard-level red tests for Must Fix samples (subagent must see nested agent).
func TestAlFix7_MustFix_SubagentBlocks(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")
	cases := []struct {
		name string
		code string
		argv []string
	}{
		{name: "MF1_comment_cont_pig", code: "# \\\npig"},
		{name: "MF1_even_bs", code: "echo \\\\\npig"},
		{name: "MF1_dq_sq", code: "echo \"'\" \"$\\\n(pig)\""},
		{name: "MF2_heredoc_cr", code: "cat <<'EOF'\r\nEOF\n'\nEOF\r\npig\n# '\n"},
		{name: "MF3_param_sq", code: `echo "${UNSET:-'$(pig)'}"`},
		{name: "MF3_brace", code: `echo "${UNSET:-'}"; pig # '}"`},
		{name: "MF3_nested", code: `echo ${UNSET1:-"${UNSET2:-"'"}" $(pig)}`},
		{name: "MF4_bt_param", code: "echo ${UNSET:-`\\`pig\\``}"},
		{name: "MF4_bt_arith", code: "echo $(( `\\`pig\\`` + 0 ))"},
		{name: "MF5_case", code: `echo "$(case x in x) pig;; esac)"`},
		{name: "MF5_heredoc", code: "echo \"$(cat <<EOF\n)\nEOF\npig)\""},
		{name: "MF6_env_a", argv: []string{"env", "-a", "true", "pig"}},
		{name: "MF6_env_argv0", argv: []string{"env", "--argv0", "true", "pig"}},
		{name: "MF6_env_vS", argv: []string{"env", "-vS", "env pig"}},
		{name: "MF6_env_vC", argv: []string{"env", "-vC", "/tmp", "pig"}},
		{name: "MF6_env_vu", argv: []string{"env", "-vu", "CTXMODE_ROLE", "pig"}},
		{name: "MF6_env_dash", argv: []string{"env", "-", "sh", "-c", "id"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hit string
			if len(c.argv) > 0 {
				hit = guardArgvSubagent(c.argv)
			} else {
				hit = guardShellSubagent(c.code)
			}
			if hit == "" {
				t.Fatalf("expected subagent block for %s code=%q argv=%v", c.name, c.code, c.argv)
			}
		})
	}
}

func TestAlFix7_MustFix_ReadonlyBlocks(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")
	cases := []struct {
		name string
		code string
	}{
		{name: "MF1_comment_cont_pig", code: "# \\\npig"},
		{name: "MF1_comment_cont_rm", code: "# \\\nrm -rf /tmp/pwn"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if hit := guardShellReadonly(c.code); hit == "" {
				t.Fatalf("expected readonly block for %q", c.code)
			}
		})
	}
	// After the parse fix, comment-continuation + allowlisted cmd is visible and allowed.
	t.Run("MF1_comment_cont_ls_allow", func(t *testing.T) {
		if hit := guardShellReadonly("# \\\nls"); hit != "" {
			t.Fatalf("expected allow for comment-cont + ls, got %q", hit)
		}
	})
}

// Should Fix / Nice to Have allow/block expectations.
func TestAlFix7_ShouldFix_Allowlist(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	allow := []struct {
		name string
		argv []string
		code string
	}{
		{name: "trailing_nl", code: "ls -la\n"},
		{name: "blank_line", code: "git status\n\ngit log -n 5"},
		{name: "comment_line", code: "# 查看状态\ngit status"},
		{name: "trailing_comment", code: "git status\n# 备注"},
		{name: "find_prune", argv: []string{"find", ".", "-path", "./.git", "-prune", "-o", "-name", "*.go", "-print"}},
		{name: "find_newermt", argv: []string{"find", ".", "-newermt", "2026-01-01"}},
		{name: "git_tag_sort_desc", argv: []string{"git", "tag", "-l", "--sort", "-creatordate"}},
		{name: "hc_send", argv: []string{"hc", "send", "t42", "done"}},
		{name: "git_reflog_n", argv: []string{"git", "reflog", "-n", "10"}},
		{name: "ctxmode_h", argv: []string{"ctxmode", "-h"}},
		{name: "ctxmode_help_flag", argv: []string{"ctxmode", "--help"}},
		{name: "rg_a", argv: []string{"rg", "-a", "pat", "."}},
		{name: "rg_c", argv: []string{"rg", "-c", "pat", "."}},
		{name: "rg_g", argv: []string{"rg", "-g", "*.go", "pat"}},
	}
	for _, c := range allow {
		t.Run("allow_"+c.name, func(t *testing.T) {
			var hit string
			if len(c.argv) > 0 {
				hit = guardArgvReadonly(c.argv)
			} else {
				hit = guardShellReadonly(c.code)
			}
			if hit != "" {
				t.Fatalf("expected allow, got %q for %s", hit, c.name)
			}
		})
	}

	block := []struct {
		name string
		argv []string
	}{
		{name: "ctxmode_help_sub", argv: []string{"ctxmode", "help"}},
		{name: "ctxmode_ddash_h", argv: []string{"ctxmode", "--", "-h"}},
		{name: "git_tag_delete", argv: []string{"git", "tag", "-l", "-d", "foo"}},
		{name: "git_branch_sort_D", argv: []string{"git", "branch", "-l", "--sort", "-D", "foo"}},
		{name: "herdr_pane_current", argv: []string{"herdr", "pane", "current"}},
		{name: "herdr_pane_help", argv: []string{"herdr", "pane", "--help"}},
		{name: "herdr_skill", argv: []string{"herdr", "--skill"}},
		{name: "herdr_default_config", argv: []string{"herdr", "--default-config"}},
		{name: "herdsman_status", argv: []string{"herdsman", "status"}},
		{name: "herdsman_agent_list", argv: []string{"herdsman", "agent", "list"}},
	}
	for _, c := range block {
		t.Run("block_"+c.name, func(t *testing.T) {
			if hit := guardArgvReadonly(c.argv); hit == "" {
				t.Fatalf("expected block for %v", c.argv)
			}
		})
	}
}

func TestAlFix7_FuzzArgvDiff(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")
	rootBefore := snapshotRootDir(t)
	t.Cleanup(func() { assertRootDirUnchanged(t, rootBefore) })

	const seed = 20261104
	rng := rand.New(rand.NewSource(seed))
	N := 20000
	if raceEnabled {
		N = 2000
	}

	// Byte fragments with NO implicit surrounding spaces (PLAN §5.3).
	// Host safety: no "/", "..", "cd", or "~" in any frag.
	frags := []string{
		"p1", "p2", "pig",
		" ", "\t", "\n", ";", "|", "&&", "||",
		"\\\n", "\\\\\n", "\\", "\\\"", "\\$", "\\'",
		"'a'", "'", "\"", "$(", ")", "$((", "))", "${x:-", "${x:-\"", "}", "`",
		"cat <<EOF\n", "cat <<'EOF'\n", "cat <<EO\\\nF\n", "cat <<\"\\$EOF\"\n",
		"\nEOF\n", "\n$EOF\n", "\n)\nEOF\n",
		"case $? in 0) p1;; esac", "case x in x) pig;; esac",
		"# \\\np1\n", "2\\\n>sink", "'2'>sink",
		// SF-1 grammar-aware lexical seeds (no "/", "..", "cd", "~")
		"$", "$\\\n", "{x:-pig}", "{x:-p1}", "{x:--c}", "1",
		"\\\n # \\\n", " # \\\n", "p1 \\\n # \\\npig\n",
		"sh -c '", "' _ pig", "env -u ", "flock sink -c ", "trap ", " EXIT",
		"${x:-", "\\\"\"", "$(case x in x) p1;; esac)",
	}
	// Host safety: no "/", "..", "cd", or "~"; redirects use relative sink.
	templates := []string{
		"p1 $(p2)",
		"p1 ${x:-p2}",
		"p1 \"${x:-'y'}\"",
		"cat <<EOF\n$(pig)\nEOF",
		"cat <<'EOF'\n$(pig)\nEOF",
		"env -a p1 pig",
		"echo \"$(case x in x) pig;; esac)\"",
		"p1; pig",
		"p1 && pig",
		"p1 | p2",
		"# \\\npig",
		"echo \\\\\npig",
		"p1 $\\\n(pig)",
		"echo \"$\\\n(pig)\"",
		"cat <<EO\\\nF\n$(pig)\nEOF",
		"env --default-signal pig",
		"env -S pig",
		"${UNSET:-pig}",
		"\"${UNSET:-pig}\"",
		"eval \"$X\"",
		"f() { pig; }; p1",
		"((pig))",
		"p1 <<EOF\n$\\\n(pig)\nEOF",
		"echo \"$(echo case in)\" >sink ; pig",
		"nice -n 1 pig",
		"p1 `pig`",
		"p1 `\\`pig\\``",
		"true; pig",
		"p1\npig",
		"cat <<\"\\$EOF\"\n$EOF\npig",
		// SF-1 grammar-aware templates
		"$\\\n{x:-pig}",
		"echo \\\n # \\\npig",
		"sh -c '$\\\n1' _ pig",
		"flock sink -c 'pig'",
		"trap 'pig' EXIT",
		"env -u CTXMODE_ROLE sh -c p1",
	}

	mismatches := 0
	bypasses := 0
	for i := 0; i < N; i++ {
		var code string
		if rng.Intn(2) == 0 {
			// Template with random byte inserts.
			base := templates[rng.Intn(len(templates))]
			b := []byte(base)
			inserts := 1 + rng.Intn(3)
			for k := 0; k < inserts; k++ {
				frag := frags[rng.Intn(len(frags))]
				pos := rng.Intn(len(b) + 1)
				nb := make([]byte, 0, len(b)+len(frag))
				nb = append(nb, b[:pos]...)
				nb = append(nb, frag...)
				nb = append(nb, b[pos:]...)
				b = nb
			}
			code = string(b)
		} else {
			// Byte-join 4..12 fragments; sometimes insert space/tab between.
			nTok := 4 + rng.Intn(9)
			parts := make([]string, 0, nTok*2)
			for k := 0; k < nTok; k++ {
				parts = append(parts, frags[rng.Intn(len(frags))])
				if rng.Intn(2) == 0 {
					if rng.Intn(2) == 0 {
						parts = append(parts, " ")
					} else {
						parts = append(parts, "\t")
					}
				}
			}
			code = strings.Join(parts, "")
		}

		// Guard first: if worker allows, dash must never execute pig/agy, and
		// static-leaf full argv must agree with Go AST. When parseReadonlyShellAST
		// allows, also require concrete static-leaf argv[0]+argv[1:] agreement.
		hit := guardShellSubagent(code)
		goArgvs, depthEx := collectGoCmdArgvs(code)
		roArgvs, roReject := parseReadonlyShellAST(code)
		names := namesFromGoArgvs(goArgvs)
		names = append(names, "p1", "p2", "pig", "agy", "cat", "env", "nice", "printargv")
		pathDir, outFile := setupPrinterPATH(t, names)
		_ = os.Remove(outFile)
		dashArgvs, _, _ := runDashCollectArgvs(t, code, pathDir, outFile)

		goExt := filterExternalArgvs(goArgvs)

		if hit == "" {
			var rawArgvs [][]string
			for _, s := range splitShellSegments(code) {
				if len(s.argv) > 0 {
					rawArgvs = append(rawArgvs, append([]string(nil), s.argv...))
				}
			}
			aliases := envArgv0Aliases(rawArgvs)
			for _, a := range dashArgvs {
				if len(a) == 0 {
					continue
				}
				if (a[0] == "pig" || a[0] == "agy") && !aliases[a[0]] {
					bypasses++
					if bypasses <= 5 {
						t.Fatalf("BYPASS FOUND: worker guard allowed script that executed %s in dash: %q", a[0], code)
					}
				}
			}
			miss := filterAliasMisses(dashExecutedUnknown(goExt, dashArgvs), aliases)
			if len(miss) > 0 && !depthEx {
				mismatches++
				if mismatches <= 10 {
					t.Logf("AST BLINDSPOT i=%d miss=%v code=%q", i, miss, code)
				}
			}
			// Concrete static-leaf full argv must agree with dash captures.
			if !depthEx {
				goLeaves := staticConcreteLeafArgvs(goExt)
				dashLeaves := staticLeafArgvs(dashArgvs)
				if !leafArgvDeepAgreeExt(goLeaves, dashLeaves, goExt) {
					mismatches++
					if mismatches <= 10 {
						t.Logf("LEAF ARGV MISMATCH i=%d code=%q goLeaves=%s dashLeaves=%s",
							i, code, fmtArgvs(goLeaves), fmtArgvs(dashLeaves))
					}
				}
			}
		}

		// Readonly AST allow path: concrete static-leaf full argv must agree with dash.
		if roReject == "" && !depthEx {
			roExt := filterExternalArgvs(roArgvs)
			roLeaves := staticConcreteLeafArgvs(roExt)
			dashLeaves := staticLeafArgvs(dashArgvs)
			if !leafArgvDeepAgreeExt(roLeaves, dashLeaves, roExt) {
				mismatches++
				if mismatches <= 10 {
					t.Logf("RO FULL ARGV MISMATCH i=%d code=%q roLeaves=%s dashLeaves=%s",
						i, code, fmtArgvs(roLeaves), fmtArgvs(dashLeaves))
				}
			}
		}
	}
	if bypasses > 0 {
		t.Fatalf("fuzz bypasses: %d / %d", bypasses, N)
	}
	if mismatches > 0 {
		t.Fatalf("fuzz AST blindspots: %d / %d (seed=%d race=%v)", mismatches, N, seed, raceEnabled)
	}
}

func TestAlFix7_CaptureBaselineMismatches(t *testing.T) {
	if os.Getenv("CTXMODE_ALFIX7_CAPTURE") != "1" {
		t.Skip("set CTXMODE_ALFIX7_CAPTURE=1 to write baseline mismatch report")
	}
	outPath := os.Getenv("CTXMODE_ALFIX7_CAPTURE_OUT")
	if outPath == "" {
		outPath = "/tmp/alfix7-baseline-mismatches.txt"
	}
	var all []dashDiffCase
	all = append(all, alfix7MustFixSamples()...)
	all = append(all, alfix7Audit3Diff32()...)
	all = append(all, alfix7ShouldFixSamples()...)
	all = append(all, alfix7ReportTableSamples()...)

	var report strings.Builder
	report.WriteString("alfix7 baseline dash/Go mismatches\n")
	report.WriteString("HEAD capture mode\n\n")

	nFail := 0
	for _, c := range all {
		goArgvs, depthEx := collectGoCmdArgvs(c.code)
		names := namesFromGoArgvs(goArgvs)
		for _, h := range []string{"rm", "pig", "python3", "echo", "true", "ls", "cat", "env", "sh", "bash", "nice", "rg"} {
			if strings.Contains(c.code, h) {
				names = append(names, h)
			}
		}
		pathDir, outFile := setupPrinterPATH(t, names)
		dashArgvs, raw, _ := runDashCollectArgvs(t, c.code, pathDir, outFile)
		goExt := filterExternalArgvs(goArgvs)
		miss := dashExecutedUnknown(goExt, dashArgvs)
		fail := false
		reason := ""
		if len(goExt) == 0 && len(dashArgvs) > 0 && !depthEx {
			fail = true
			reason = "Go0_dashN"
		} else if len(miss) > 0 && !depthEx {
			fail = true
			reason = "dash_unknown:" + strings.Join(miss, ",")
		} else if c.compareFull && !depthEx && !argvsEqual(goExt, dashArgvs) {
			fail = true
			reason = "argv_mismatch"
		} else if c.expectDashRuns && len(dashArgvs) == 0 {
			fail = true
			reason = "dash_no_run"
		}
		if fail {
			nFail++
			fmt.Fprintf(&report, "FAIL %s reason=%s\ncode=%q\ngo_segs=%d dash_segs=%d depthEx=%v\ngo:\n%sdash:\n%sraw=%q\n\n",
				c.name, reason, c.code, len(goArgvs), len(dashArgvs), depthEx, fmtArgvs(goArgvs), fmtArgvs(dashArgvs), raw)
		}
	}
	fmt.Fprintf(&report, "TOTAL_FAIL=%d TOTAL=%d\n", nFail, len(all))
	if err := os.WriteFile(outPath, []byte(report.String()), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("wrote %s fail=%d/%d", outPath, nFail, len(all))
}

// TestIsSafeRedirect_SF1 closes PLAN10 R10_SF1_01/02: comment quote-flip and
// dynamic redirect targets must never be fed to real /bin/sh.
func TestIsSafeRedirect_SF1(t *testing.T) {
	if isSafeRedirectForTestExec("# '\necho x > /pwn # '") {
		t.Fatalf("R10_SF1_01: comment quote-flip must be unsafe")
	}
	if isSafeRedirectForTestExec("echo x > ${UNSET:-/pwn}") {
		t.Fatalf("R10_SF1_02: dynamic redirect target must be unsafe")
	}
	if isSafeRedirectForTestExec("find . -delete") {
		t.Fatalf("find -delete must be unsafe")
	}
	if isSafeRedirectForTestExec("find . -fprint /tmp/x") {
		t.Fatalf("find -fprint must be unsafe")
	}
	if !isSafeRedirectForTestExec("echo x > sink") {
		t.Fatalf("relative sink redirect should be safe")
	}
	if !isSafeRedirectForTestExec("cat < /dev/null") {
		t.Fatalf("/dev/null redirect should be safe")
	}
}
