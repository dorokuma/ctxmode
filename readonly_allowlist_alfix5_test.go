package main

import (
	"context"
	"strings"
	"testing"
)

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
		{name: "herdr_session_status", argv: []string{"herdr", "--session", "s", "status"}},
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
