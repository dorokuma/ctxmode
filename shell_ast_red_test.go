package main

import (
	"testing"
)

// astRedCase is one row of the PLAN §5.1 must-red table (66 + 4 extras).
type astRedCase struct {
	id     string
	code   string
	role   string // "ro" or "worker"
	reject bool   // true = must reject; false = must allow
	reason string
}

func astMustRedCases() []astRedCase {
	return []astRedCase{
		{"A01_cr_comment_smuggle_ro", "true \r#; rm -rf /tmp/x", "ro", true, "AUDIT3 #1"},
		{"A02_cr_comment_smuggle_sub", "true \r#; pig", "worker", true, "AUDIT3 #1"},
		{"A03_cr_cmd_head", "ls\r", "ro", true, "AUDIT3 #2"},
		{"A04_cr_opt_swallow_rg", "rg -e \r --pre=/usr/bin/id pat .", "ro", true, "AUDIT3 #3"},
		{"A05_cr_redir_trunc", "echo hi >/dev/null\rfoo", "ro", true, "AUDIT3 #4"},
		{"A06_ctrl_vt_del", "ls \v -la", "ro", true, "AUDIT3 #5"},
		{"A07_sq_digit_redir_rg", "rg -e '2'>/dev/null --pre=/usr/bin/id pat .", "ro", true, "AUDIT3 #6"},
		{"A08_dq_digit_redir_nice", "nice -n \"2\">/dev/null pig", "worker", true, "AUDIT3 #7"},
		{"A09_bs_digit_redir_rg", "rg -e \\2>/dev/null --pre=/usr/bin/id pat .", "ro", true, "AUDIT3 #8"},
		{"A10_empty_dq_digit_redir", "rg -e \"\"2>/dev/null --pre=/usr/bin/id pat .", "ro", true, "AUDIT3 #9"},
		{"A11_midword_digit_redir", "echo a2>/dev/null b", "ro", true, "AUDIT3 #10"},
		{"A12_valid_io_number_2null", "ls 2>/dev/null", "ro", false, "AUDIT3 #11"},
		{"A13_digit_arg_before_redir", "echo 2 >/dev/null", "ro", false, "AUDIT3 #12"},
		{"A14_redir_quoted_target_tail", "echo hi >'/dev/null'foo", "ro", true, "AUDIT3 #13"},
		{"A15_redir_fd_dup_tail", "echo hi 2>&1foo", "ro", true, "AUDIT3 #14"},
		{"A16_leading_redir_before_cmd", "2>/dev/null ls -la", "ro", true, "AUDIT3 #15"},
		{"A17_empty_quote_cmd_head", "\"\"/bin/ls", "ro", true, "AUDIT3 #16"},
		{"A18_quoted_if_cmd_head", "'if' true; then ls; fi", "ro", true, "AUDIT3 #16"},
		{"A19_tilde_cmd_head", "~", "ro", true, "AUDIT3 #17"},
		{"A20_tilde_arg_unquoted", "rg pat ~/src", "ro", true, "AUDIT3 #18"},
		{"A21_glob_unquoted_star", "ls *.go", "ro", true, "AUDIT3 #19"},
		{"A22_fake_arith_subshell_bash", "bash -c 'echo $((pig); (true))'", "worker", true, "AUDIT3 #20"},
		{"A23_real_arith_with_cmdsub", "echo $(( (1+1) * $(pig) ))", "worker", true, "AUDIT3 #21"},
		{"A24_param_dq_nested_rparen", "echo $(echo \"${x:-\")\"}\"; pig)", "worker", true, "AUDIT3 #22"},
		{"A25_param_sq_rparen", "echo $(echo ${x:-')'}; pig)", "worker", true, "AUDIT3 #23"},
		{"A26_line_cont_split_cmdsub", "echo $\\\n(pig)", "worker", true, "AUDIT3 #24"},
		{"A27_dq_line_cont_split_cmdsub", "echo \"$\\\n(pig)\"", "worker", true, "AUDIT3 #25"},
		{"A28_line_cont_split_heredoc_op", "cat <\\\n<EOF\n$(pig)\nEOF", "worker", true, "AUDIT3 #26"},
		{"A29_backtick_escaped_backtick", "echo `\\`pig\\``", "worker", true, "AUDIT3 #27"},
		{"A30_backtick_double_bs_close", "echo `echo a\\\\` ; pig ; #`", "worker", true, "AUDIT3 #28"},
		{"A31_heredoc_delim_cr_line", "cat <<'EOF'\nEOF\r\n'; pig; '\nEOF", "worker", true, "AUDIT3 #29"},
		{"A32_tail_legacy_num_swallow_f", "tail -n -5 -f README.md", "ro", true, "AUDIT3 #30"},
		{"A33_git_branch_merged_dash_D", "git branch --merged -D feature", "ro", true, "AUDIT3 #31"},
		{"A34_ctxmode_dash_h_allow", "ctxmode -h", "ro", false, "AUDIT3 #32"},
		{"A35_herdr_remote_block", "herdr --remote=x status", "ro", true, "AUDIT3 #32"},
		{"G6_MF1_comment_bs_rm_ro", "# \\\nrm -rf /tmp/pwn", "ro", true, "AGY6 MF1"},
		{"G6_MF1_comment_bs_pig_sub", "# \\\npig", "worker", true, "AGY6 MF1"},
		{"G6_MF1_even_bs_newline_pig", "echo \\\\\npig", "worker", true, "AGY6 MF1"},
		{"G6_MF1_dq_sq_contam_cmdsub", "echo \"'\" \"$\\\n(pig)\"", "worker", true, "AGY6 MF1"},
		{"G6_MF1_heredoc_body_cont_delim", "cat <<'EOF' >/dev/null\nEO\\\nF\n'\nEOF\npig\n# '", "worker", true, "AGY6 MF1"},
		{"G6_MF2_heredoc_cr_delim", "cat <<'EOF'\r\nEOF\n'\nEOF\r\npig\n# '\n", "worker", true, "AGY6 MF2"},
		{"G6_MF3_dq_param_sq_cmdsub", "echo \"${UNSET:-'$(pig)'}\"", "worker", true, "AGY6 MF3"},
		{"G6_MF3_dq_param_sq_rbrace_dash", "echo \"${UNSET:-'}\"; pig # '}\"", "worker", true, "AGY6 MF3"},
		{"G6_MF3_nested_param_dq_sq", "echo ${UNSET1:-\"${UNSET2:-\"'\"}\" $(pig)}", "worker", true, "AGY6 MF3"},
		{"G6_MF3_redir_target_param_sq", "true < \"${UNSET:-\"'\"}\" 2>/dev/null ; pig # '", "worker", true, "AGY6 MF3"},
		{"G6_MF4_param_backtick_unescape", "echo ${UNSET:-`\\`pig\\``}", "worker", true, "AGY6 MF4"},
		{"G6_MF4_arith_backtick_unescape", "echo $(( `\\`pig\\`` + 0 ))", "worker", true, "AGY6 MF4"},
		{"G6_MF5_dq_cmdsub_case_arm", "echo \"$(case x in x) pig;; esac)\"", "worker", true, "AGY6 MF5"},
		{"G6_MF5_dq_cmdsub_heredoc_rparen", "echo \"$(cat <<EOF\n)\nEOF\npig)\"", "worker", true, "AGY6 MF5"},
		{"G6_MF6_env_dash_a_cluster_bare", "env -a true pig", "worker", true, "AGY6 MF6"},
		{"G6_MF6_env_short_cluster_vu", "env -vu CTXMODE_ROLE true", "worker", true, "AGY6 MF6"},
		{"G6_SF3_ctxmode_help_subcmd_block", "ctxmode help", "ro", true, "AGY6 SF3"},
		{"G7_MF1_heredoc_unquoted_cont_sub", "cat <<EOF\n$\\\n(pig)\nEOF", "worker", true, "AGY7 MF1-1"},
		{"G7_MF1_io_num_line_cont_env", "env -a 2\\\n>/dev/null fake0 pig", "worker", true, "AGY7 MF1-2"},
		{"G7_MF1_dq_cmdsub_case_kw_cont", "echo \"$(ca\\\nse x in x) pig;; esac)\"", "worker", true, "AGY7 MF1-3"},
		{"G7_MF2_heredoc_delim_line_cont", "cat <<EO\\\nF\n$(pig)\nEOF", "worker", true, "AGY7 MF2-1"},
		{"G7_MF2_heredoc_dq_dollar_delim", "cat <<\"\\$EOF\" >/dev/null\n$EOF\npig", "worker", true, "AGY7 MF2-2"},
		{"G7_MF3_bash_c_dq_param_sq_mirror", "bash -c 'echo \"${UNSET:-'\\''}\"; echo '\\''}\" $(pig) # '\\'''", "worker", true, "AGY7 MF3-1"},
		{"G7_MF3_dynamic_cmd_head_param", "${UNSET:-pig}", "worker", true, "AGY7 MF3-2"},
		{"G7_MF3_dynamic_cmd_head_dq_param", "\"${UNSET:-pig}\"", "worker", true, "AGY7 MF3-2"},
		{"G7_MF4_fake_case_in_echo_args", "echo \"$(echo case in)\" >/dev/null ; pig", "worker", true, "AGY7 MF4-B"},
		{"G7_MF4_case_subject_dollar_q", "echo \"$(case $? in 0) pig;; esac)\"", "worker", true, "AGY7 MF4-C"},
		{"G7_MF4_cmdsub_heredoc_same_line", "echo \"$(true <<EOF)\" >/dev/null ; pig ; echo \"\nEOF\n)\" >/dev/null", "worker", true, "AGY7 MF4-D"},
		{"G7_MF5_env_default_signal_no_eq", "env --default-signal pig", "worker", true, "AGY7 MF5-1"},
		{"G7_MF5_env_split_string_dash_S", "env -S -a fake0 pig", "worker", true, "AGY7 MF5-2"},
		{"G7_SF1_git_branch_color_never", "git branch --color=never", "ro", false, "AGY7 SF1"},
		// Extra morphs from PLAN §5.1 note
		{"X01_double_paren_subshell", "((pig))", "worker", true, "((pig)) nested subshell"},
		{"X02_eval_dynamic", "eval \"$X\"", "worker", true, "eval dynamic payload"},
		{"X03_glob_cmd_head", "/*/pig", "worker", true, "glob command head"},
		{"X04_func_decl_body", "f() { pig; }", "worker", true, "function body"},
	}
}

func setAstRole(t *testing.T, role string) {
	t.Helper()
	switch role {
	case "ro":
		t.Setenv(auditEnvRole, "scout")
		t.Setenv(auditEnvReadonly, "1")
	default:
		t.Setenv(auditEnvRole, "worker")
		t.Setenv(auditEnvReadonly, "")
	}
}

func runAstGuard(role, code string) string {
	switch role {
	case "ro":
		return guardShellReadonly(code)
	default:
		return guardShellSubagent(code)
	}
}

// TestAST_MustRed66 is the PLAN §5.1 table. On baseline 897a43e many worker
// cases are expected RED (guard allows); after mvdan rewrite all must be green.
func TestAST_MustRed66(t *testing.T) {
	cases := astMustRedCases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			setAstRole(t, c.role)
			hit := runAstGuard(c.role, c.code)
			allowed := hit == ""
			if c.reject {
				if allowed {
					t.Fatalf("expected REJECT (%s) but guard allowed; code=%q", c.reason, c.code)
				}
			} else {
				if !allowed {
					t.Fatalf("expected ALLOW (%s) but guard rejected: %s; code=%q", c.reason, hit, c.code)
				}
			}
		})
	}
	t.Logf("must-red summary: cases=%d", len(cases))
}

// TestAST_BaselineSnapshot logs which must-red rows currently pass/fail so
// REPORT.md can compare 897a43e vs HEAD. It never fails.
func TestAST_BaselineSnapshot(t *testing.T) {
	var pass, fail []string
	for _, c := range astMustRedCases() {
		setAstRole(t, c.role)
		hit := runAstGuard(c.role, c.code)
		allowed := hit == ""
		ok := (c.reject && !allowed) || (!c.reject && allowed)
		line := c.id + " role=" + c.role + " reject=" + boolStr(c.reject)
		if ok {
			pass = append(pass, line+" PASS hit="+truncate(hit, 60))
		} else {
			fail = append(fail, line+" FAIL hit="+truncate(hit, 60))
		}
	}
	t.Logf("PASS %d / FAIL %d (of %d)", len(pass), len(fail), len(pass)+len(fail))
	for _, l := range fail {
		t.Log("FAIL:", l)
	}
	for _, l := range pass {
		t.Log("PASS:", l)
	}
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
