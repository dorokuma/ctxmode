package main

import (
	"os/exec"
	"strings"
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

// astRedWantCase extends a table row with `want`: when the case rejects,
// the hit detail must contain this substring (R13 — a bare allow/deny
// boolean can hide a wrong-reason hit).
type astRedWantCase struct {
	astRedCase
	want string
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
			runAstRedCase(t, c)
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

// astMustRedRound9Cases is the PLAN9 must-red table (TASK correction for R9_SF2_01).
// MF2_01 / MF3_03 restore backtick escapes that markdown stripped from PLAN9.
func astMustRedRound9Cases() []astRedCase {
	return []astRedCase{
		{"R9_MF1_01", "case x in x) echo 'a'#; pig\n;; esac", "worker", true, "MF-1 case arm quote-adjacent #"},
		{"R9_MF1_02", "(echo $(echo 'a'#) ; pig ; (true\n))", "worker", true, "MF-1 cmdsubst quote-adjacent #"},
		{"R9_MF1_03", "case x in x) echo 'a'\\\n#; pig\n;; esac", "worker", true, "MF-1 quote then \\\n then #"},
		{"R9_MF1_04", "echo \\ #; rm -rf /tmp/x", "ro", true, "MF-1 escaped-space before #"},
		{"R9_MF2_01", "sh -c \"\\`pig\\`\"", "worker", true, "MF-2 dq backtick unescape into sh -c"},
		{"R9_MF2_02", "sh -c \"echo \\\"\\$(pig)\\\"\"", "worker", true, "MF-2 dq \\$ unescape into sh -c"},
		{"R9_MF2_03", "eval \"echo \\\"\\$(pig)\\\"\"", "worker", true, "MF-2 dq \\$ unescape into eval"},
		{"R9_MF2_04", "rg \"\\$foo\" README.md", "ro", false, "MF-2 readonly rg \\$foo argv exact"},
		{"R9_MF3_01", "sh <<EOF\necho \"\\\\\\\"; pig #\"\nEOF", "worker", true, "MF-3 unquoted heredoc \\\" unescape"},
		{"R9_MF3_02", "sh <<EOF\ntrue ${UNSET:-; pig}\nEOF", "worker", true, "MF-3 unquoted heredoc param expand"},
		{"R9_MF3_03", "sh <<EOF\n\\`pig\\`\nEOF", "worker", true, "MF-3 unquoted heredoc backtick unescape"},
		{"R9_MF3_04", "sh <<EOF\np\\\\\nig\nEOF", "worker", true, "MF-3 unquoted heredoc line-cont splice"},
		{"R9_MF4_01", "sh \"${UNSET:--c}\" pig", "worker", true, "MF-4 dynamic sh option word"},
		{"R9_MF4_02", "python3 -c\"${UNSET:-__import__('os').system('pig')}\"", "worker", true, "MF-4 -c glued dynamic payload"},
		{"R9_MF4_03", "find . \"${UNSET:--exec}\" pig \\;", "worker", true, "MF-4 find predicate dynamic"},
		{"R9_MF4_04", "git -c\"${UNSET:-core.pager=pig}\" log", "worker", true, "MF-4 git -c glued dynamic"},
		{"R9_MF4_05", "sh \"${UNSET:--s}\" <<'EOF'\npig\nEOF", "worker", true, "MF-4 dynamic sh -s still screens heredoc"},
		{"R9_MF4_06", "env \"${UNSET:--a}\" true pig", "worker", true, "MF-4 env option-zone dynamic"},
		{"R9_MF5_01", "# \\\nls", "ro", false, "MF-5 standalone comment \\ does not continue"},
		{"R9_MF5_02", "ls # \\\nrm -rf /tmp/pwn", "ro", true, "MF-5 trailing comment ends with \\"},
		{"R9_MF5_03", "echo a# \\\nls", "ro", true, "MF-5 word-internal a# then real \\\n"},
		{"R9_MF6_01", "env -a p1 pig", "worker", true, "MF-6 env -a argv0 rewrite"},
		{"R9_MF6_02", "nice -n 1 sh -c 'pig'", "worker", true, "MF-6 nice+sh nested wrapper"},
		{"R9_SF1_01", "if [ -d /tmp ]; then echo ok; fi", "worker", false, "SF-1 standalone [ test allow"},
		{"R9_SF1_02", "for d in /root /tmp; do [ -d \"$d\" ] && echo \"$d\"; done", "worker", false, "SF-1 loop [ test allow"},
		{"R9_SF1_03", "/usr/bin/[p]ig", "worker", true, "SF-1 char-class glob cmd head"},
		{"R9_SF2_01", "bash -c 'go version | head -1; echo \"rc=${PIPESTATUS[0]}\"'", "worker", false, "SF-2 TASK fix PIPESTATUS allow"},
		{"R9_SF2_02", "bash -c '[[ -d /tmp ]] && pig'", "worker", true, "SF-2 bash [[ still catches pig"},
		{"R9_SF3_01", "echo \"### build ###\" \\\n && echo done", "worker", false, "SF-3 dq # with line cont allow"},
		{"R9_SF3_02", "sed 's/#foo/bar/' \\\n /tmp/test.txt", "worker", false, "SF-3 sq # with line cont allow"},
		{"R9_SF4_01", "ls\r", "ro", true, "SF-4 CR byte reject"},
		{"R9_SF4_02", "rg 'a\n\\\nb' README.md", "ro", false, "SF-4 sq embedded \\\n not cont"},
		{"R9_AU1_01", "cat <<EOF\n$(true)\n${UNSET:-'$(pig)'}\nEOF", "worker", true, "Audit-1 heredoc param sq cmdsub"},
		{"R9_AU1_02", "echo $(( ${UNSET:-'$(pig)'} + 0 ))", "worker", true, "Audit-1 arith param sq cmdsub"},
		{"R9_AU2_01", "bash -O extglob -c 'pig'", "worker", true, "Audit-2 bash -O then -c"},
		{"R9_AU2_02", "sh -s arg1 <<'EOF'\npig\nEOF", "worker", true, "Audit-2 sh -s reads stdin"},
		{"R9_AU3_01", "export GIT_PAGER=pig; git log", "worker", true, "Audit-3 export GIT_PAGER"},
		{"R9_AU3_02", ": $(( CTXMODE_READONLY = 0 ))", "worker", true, "Audit-3 arith assign role var"},
		{"R9_AU4_01", "bash -c 'eval -- pig'", "worker", true, "Audit-4 eval -- peel"},
		{"R9_SSH_01", "ssh dmit echo \"${UNSET:-; pig}\"", "worker", true, "SSH dynamic remote payload"},
	}
}

// TestAST_MustRed_Round9 is the PLAN9 §must-red table (40 cases; PLAN said 36).
func TestAST_MustRed_Round9(t *testing.T) {
	cases := astMustRedRound9Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstRedCase(t, c)
		})
	}
	t.Logf("must-red round9 summary: cases=%d", len(cases))
}

// TestAST_Round9_BaselineSnapshot logs which Round9 must-red rows currently
// pass/fail so REPORT can compare ce557f1 vs HEAD. It never fails.
func TestAST_Round9_BaselineSnapshot(t *testing.T) {
	var pass, fail []string
	for _, c := range astMustRedRound9Cases() {
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

// astMustRedRound10Cases is PLAN10 §must-red + TASK.md split-safe corrections.
func astMustRedRound10Cases() []astRedCase {
	return []astRedCase{
		// MF-1 lexical
		{"R10_MF1_01", "$\\\n{UNSET:-pig}", "worker", true, "MF-1 $ then \\\n brace param"},
		{"R10_MF1_02", "/bin/sh -c '$\\\n1' _ pig", "worker", true, "MF-1 $ then \\\n positional"},
		{"R10_MF1_03", "/bin/sh \"$\\\n{UNSET:--c}\" pig", "worker", true, "MF-1 dq $ then \\\n expands -c"},
		{"R10_MF1_04", "/bin/sh <<EOF\ntrue $\\\n{UNSET:-; pig}\nEOF", "worker", true, "MF-1 unquoted hdoc $ \\\n"},
		{"R10_MF1_05", "echo \\\n # \\\npig", "worker", true, "MF-1 cont then indented comment \\\n swallows pig"},
		// MF-2 dynamic payload slots
		{"R10_MF2_01", "flock /tmp/lk -c \"true ${UNSET:-; pig}\"", "worker", true, "MF-2 flock -c dynamic"},
		{"R10_MF2_02", "script -qc \"true ${UNSET:-; pig}\" /dev/null", "worker", true, "MF-2 script -c dynamic"},
		{"R10_MF2_03", "trap \"true ${UNSET:-; pig}\" EXIT", "worker", true, "MF-2 trap dynamic"},
		{"R10_MF2_04", "awk \"${UNSET:-BEGIN{system(\\\"pig\\\")}}\"", "worker", true, "MF-2 awk program dynamic"},
		{"R10_MF2_05", "awk \"BEGIN{system(\\\"true ${UNSET:-; pig}\\\")}\"", "worker", true, "MF-2 awk system dynamic"},
		{"R10_MF2_06", "echo x | sed \"${UNSET:-e pig}\"", "worker", true, "MF-2 sed script dynamic"},
		{"R10_MF2_07", "tar -cf /dev/null /dev/null \"${UNSET:---checkpoint=1}\" \"${UNSET:---checkpoint-action=exec=pig}\"", "worker", true, "MF-2 tar checkpoint dynamic"},
		{"R10_MF2_08", "node -e \"1\" \"${UNSET:--e}\" \"require('child_process').execSync('pig')\"", "worker", true, "MF-2 node multi -e dynamic"},
		{"R10_MF2_09", "perl -e 1 \"${UNSET:--e}\" 'system(\"pig\")'", "worker", true, "MF-2 perl multi -e dynamic"},
		{"R10_MF2_10", "env -u \"${UNSET:-CTXMODE_ROLE}\" sh -c 'echo ok'", "worker", true, "MF-2 env -u dynamic key"},
		{"R10_MF2_11", "git --config-env \"${UNSET:-core.pager=pig}\" log", "worker", true, "MF-2 git --config-env dynamic"},
		{"R10_MF2_12", "git grep \"${UNSET:--Opig}\" main", "worker", true, "MF-2 git grep dynamic option"},
		// MF-3 staticVars invariant
		{"R10_MF3_01", "BUN=/bin/true /usr/bin/env; : \"${BUN:=pig}\"; \"$BUN\"", "worker", true, "MF-3 prefix assign not persistent"},
		{"R10_MF3_02", "BUN=/bin/true; if true; then BUN=pig; fi; \"$BUN\"", "worker", true, "MF-3 branch reassign"},
		{"R10_MF3_03", "BUN=/bin/true; unset BUN; : \"${BUN:=pig}\"; \"$BUN\"", "worker", true, "MF-3 unset then default assign"},
		{"R10_MF3_04", "for x in true; do x=pig; sh -c \"$x\"; done", "worker", true, "MF-3 for body reassign"},
		// MF-4 readonly ssh local bypass
		{"R10_MF4_01", "> /tmp/pwn_host; ssh -o BatchMode=yes dmit uptime", "ro", true, "MF-4 bare redirect then ssh"},
		{"R10_MF4_02", "ssh -o BatchMode=yes dmit uptime > /tmp/pwn_host", "ro", true, "MF-4 ssh with local redir"},
		{"R10_MF4_03", "strace -o /tmp/pwn_host ssh -o BatchMode=yes dmit uptime", "ro", true, "MF-4 strace -o wrap ssh"},
		{"R10_MF4_04", "ssh -o BatchMode=yes dmit sh <<'EOF'\nls -la\nEOF", "ro", false, "MF-4 ssh sq heredoc readonly remote"},
		{"R10_MF4_05", "ssh -o BatchMode=yes dmit sh <<'EOF'\nrm -rf /tmp/x\nEOF", "ro", true, "MF-4 ssh sq heredoc remote write"},
		// MF-5 stdin inherit
		{"R10_MF5_01", "echo pig | sh -c 'sh'", "worker", true, "MF-5 sh -c sh inherits pipe"},
		{"R10_MF5_02", "sh -c 'sh' <<'EOF'\npig\nEOF", "worker", true, "MF-5 sh -c sh inherits heredoc"},
		{"R10_MF5_03", "echo pig | ssh dmit 'sh -c sh'", "worker", true, "MF-5 ssh tunnel stdin inherit"},
		// SF-2 remote interp lang
		{"R10_SF2_01", "ssh -o BatchMode=yes dmit python3 - <<'PY'\ndef f():\n print(123)\nf()\nPY", "worker", false, "SF-2 ssh python3 heredoc lang"},
		// SF-3 static spawn stdin
		{"R10_SF3_01", "python3 -c \"import subprocess; subprocess.run(['ssh', 'dmit', 'sh'], input=b'pig')\"", "worker", true, "SF-3 python spawn stdin code"},
		// W-Fix allow
		{"R10_WF_01", "for p in '/tmp/' '整条不画'; do printf '%s\\n' \"$(grep -c -- \"$p\" report2.md)\"; done", "worker", false, "W-Fix-1 for enum chinese fallback"},
		{"R10_WF_02", "d=/tmp/repo; git -C \"$d\" rev-parse --git-dir", "worker", false, "W-Fix-5 git -C quoted dyn path"},
		{"R10_WF_03", "for d in /tmp/a /tmp/b; do find \"$d\" -maxdepth 2 -newermt '-40 minutes' -type f; done", "worker", false, "W-Fix-4 find quoted start path"},
		// TASK.md correction 1: unquoted dynamic split must reject
		{"R10_SPLIT_01", "git -C /tmp/w-$d status", "worker", true, "TASK split: unquoted git -C dyn"},
		{"R10_SPLIT_02", "find $d/s -name x", "worker", true, "TASK split: unquoted find start path"},
		{"R10_SPLIT_03", "node $X.js", "worker", true, "TASK split: unquoted node script"},
		{"R10_SPLIT_04", "d=/tmp/repo; git -C \"$d\" rev-parse --git-dir", "worker", false, "TASK split: quoted git -C allow"},
		{"R10_SPLIT_05", "python3 $X", "worker", true, "TASK split: unquoted python script"},
	}
}

// TestAST_MustRed_Round10 is the PLAN10 + TASK split must-red table.
func TestAST_MustRed_Round10(t *testing.T) {
	cases := astMustRedRound10Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstRedCase(t, c)
		})
	}
	t.Logf("must-red round10 summary: cases=%d", len(cases))
}

// TestAST_Round10_BaselineSnapshot logs Round10 pass/fail; never fails.
func TestAST_Round10_BaselineSnapshot(t *testing.T) {
	var pass, fail []string
	for _, c := range astMustRedRound10Cases() {
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

// TestAST_Round11_Lexical checks quote scope and delimiter escaping in both
// the guard and real dash. All executed commands are fixed, harmless builtins
// or cat; their working directory is isolated in t.TempDir().
func TestAST_Round11_Lexical(t *testing.T) {
	cases := []struct {
		name, code, output string
		reject             bool
	}{
		{"dq-text", "printf '%s' \"line1 \\\n# text\"", "line1 # text", false},
		{"dq-nested-command", "printf '%s' \"$(pri\\\nntf '%s' ok)\"", "ok", true},
		{"dq-inner-quote", "printf '%s' \"$(printf '%s' \"a\\\nb\")\"", "ab", false},
		{"hdoc-escape-first", "cat <<\\EOF\nliteral $HOME\nEOF\n", "literal $HOME\n", false},
		{"hdoc-escape-middle", "cat <<E\\OF\nliteral $HOME\nEOF\n", "literal $HOME\n", false},
		{"param-nested-dq", "printf '%s' \"${UNSET:-\"default\"}\"", "default", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setAstRole(t, "worker")
			hit := runAstGuard("worker", tc.code)
			if (hit != "") != tc.reject {
				t.Errorf("guard reject=%v want=%v: %s", hit != "", tc.reject, hit)
			}
			cmd := exec.Command("/usr/bin/dash", "-c", tc.code)
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + cmd.Dir, "LANG=C"}
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != tc.output {
				t.Fatalf("dash err=%v output=%q want=%q", err, out, tc.output)
			}
		})
	}
}

// astMustRedRound11Cases is PLAN11 §5.1: 40 cases (39 rejects and one
// allow control, R11_MF2_07). Counts describe table entries, not passing tests.
func astMustRedRound11Cases() []astRedCase {
	return []astRedCase{
		// --- MF-1: ssh remote readonly bypass + local eval/flock/script stdin ---
		{"R11_MF1_01", "ssh -o BatchMode=yes -n dmit 'rm -rf /tmp/target; sh'", "ro", true, "MF-1.1 ro ssh multi-seg with trailing sh no heredoc"},
		{"R11_MF1_02", "ssh -o BatchMode=yes dmit 'rm -rf /tmp/target; sh' <<'EOF'\nls -la\nEOF", "ro", true, "MF-1.1 ro ssh multi-seg piggyback write with benign heredoc"},
		{"R11_MF1_03", "ssh -o BatchMode=yes dmit 'sh > /tmp/pwn_remote' <<'EOF'\nls -la\nEOF", "ro", true, "MF-1.1 ro ssh vehicle with remote write redirect"},
		{"R11_MF1_04", "ssh -o BatchMode=yes dmit 'strace -o /tmp/pwn sh' <<'EOF'\nls -la\nEOF", "ro", true, "MF-1.1 ro ssh vehicle with remote strace -o"},
		{"R11_MF1_05", "ssh -o BatchMode=yes -n dmit sh", "ro", true, "MF-1.1 ro bare remote sh without heredoc"},
		{"R11_MF1_06", "echo pig | eval sh", "worker", true, "MF-1.2 piped code through eval sh"},
		{"R11_MF1_07", "eval sh <<'EOF'\npig\nEOF", "worker", true, "MF-1.2 heredoc code through eval sh"},
		{"R11_MF1_08", "echo pig | flock /tmp/lk sh", "worker", true, "MF-1.2 piped code through flock sh"},
		{"R11_MF1_09", "flock /tmp/lk sh <<'EOF'\npig\nEOF", "worker", true, "MF-1.2 heredoc code through flock sh"},
		{"R11_MF1_10", "echo pig | script -qc sh /dev/null", "worker", true, "MF-1.2 piped code through script -c sh"},

		// --- MF-2: interpreter / git -c / find split-safety ---
		{"R11_MF2_01", "python3 $X.py", "worker", true, "MF-2.1 unquoted python3 $X.py word-split option injection"},
		{"R11_MF2_02", "python3 /tmp/w-$X", "worker", true, "MF-2.1 unquoted python3 /tmp/w-$X word-split option injection"},
		{"R11_MF2_03", "node /tmp/w-$X.js", "worker", true, "MF-2.1 unquoted node /tmp/w-$X.js word-split"},
		{"R11_MF2_04", "git -c user.name=$X log", "worker", true, "MF-2.2 unquoted git -c value word-split"},
		{"R11_MF2_05", "X=-exec\nY=';'\nfind \"$X\" pig \"$Y\"", "worker", true, "MF-2.3 find dual dynamic words masquerading as start paths"},
		{"R11_MF2_06", "X=-exec\nY=+\nfind . \"$X\" pig {} \"$Y\"", "worker", true, "MF-2.3 find dynamic predicate with dynamic + terminator"},
		{"R11_MF2_07", "d=/tmp/dir; node \"$d/app.js\" --help", "worker", false, "MF-2.1 double-quoted script path must allow"},

		// --- MF-3 & SF-3: G1 operator-adjacent line continuation ---
		{"R11_MF3_01", ": $(\\\n(CTXMODE_READONLY = 0))", "worker", true, "MF-3 $( + \\\n + ( arithmetic split mutating CTXMODE_READONLY"},
		{"R11_MF3_02", "x=/bin/true\n: $(\\\n(x = 0))\n\"$x\"", "worker", true, "MF-3 $( + \\\n + ( arithmetic split mutating staticVars"},
		{"R11_MF3_03", "bash -c '(\\\n(CTXMODE_READONLY = 0))'", "worker", true, "MF-3 bash ( + \\\n + ( ArithmCmd split"},
		{"R11_MF3_04", "false |\\\n| pig", "worker", true, "SF-3 | + \\\n + | operator split"},
		{"R11_MF3_05", "true &\\\n& pig", "worker", true, "SF-3 & + \\\n + & operator split"},

		// --- MF-4: G3 short-circuit / getopts / command wrapper ---
		{"R11_MF4_01", "env BUN=pig /bin/sh -c 'false && BUN=/bin/true; \"$BUN\"'", "worker", true, "MF-4.1 AndStmt short-circuit false bind"},
		{"R11_MF4_02", "env BUN=pig /bin/sh -c 'true || BUN=/bin/true; \"$BUN\"'", "worker", true, "MF-4.1 OrStmt short-circuit false bind"},
		{"R11_MF4_03", "OPTARG=/bin/true\nset -- -apig\ngetopts a: dummy\n\"$OPTARG\"", "worker", true, "MF-4.2 getopts implicit OPTARG mutation"},
		{"R11_MF4_04", "x=/bin/true\nset -- -a\ngetopts a x\n\"$x\"", "worker", true, "MF-4.2 getopts target var mutation"},
		{"R11_MF4_05", "printf 'pig\\n' | {\n  for x in /bin/true; do\n    command read x\n    \"$x\"\n  done\n}", "worker", true, "MF-4.3 command read wrapper escaping preScanVarMutations"},
		{"R11_MF4_06", "BUN=/bin/true; builtin unset BUN; : \"${BUN:=pig}\"; \"$BUN\"", "worker", true, "MF-4.3 builtin unset wrapper escaping preScanVarMutations"},

		// --- MF-5: PATH empty/non-first/sq-literal + hook vars ---
		{"R11_MF5_01", "PATH=\":/usr/bin\" git status", "worker", true, "MF-5.1a leading empty PATH segment (current dir .)"},
		{"R11_MF5_02", "PATH=\"/usr/bin:\" git status", "worker", true, "MF-5.1a trailing empty PATH segment"},
		{"R11_MF5_03", "PATH=\"/usr/sbin:/tmp/evil:/usr/bin\" git status", "worker", true, "MF-5.1b non-first segment /tmp/evil before /usr/bin"},
		{"R11_MF5_04", "env PATH='$PATH:/tmp/evil' git status", "worker", true, "MF-5.1c single-quoted literal $PATH relative segment"},
		{"R11_MF5_05", "GIT_CONFIG_PARAMETERS=\"'core.pager=pig'\" git log -p", "worker", true, "MF-5.2 GIT_CONFIG_PARAMETERS hook injection"},
		{"R11_MF5_06", "GIT_CONFIG_GLOBAL=/tmp/evil_gitconfig git status", "worker", true, "MF-5.2 GIT_CONFIG_GLOBAL hook injection"},
		{"R11_MF5_07", "LD_PROFILE=/bin/sh LD_PROFILE_OUTPUT=/tmp/pwn ls", "worker", true, "MF-5.2 LD_* prefix hook injection"},
		{"R11_MF5_08", "NODE_PATH=/tmp/evil_modules node -e 'console.log(1)'", "worker", true, "MF-5.2 NODE_PATH module hijack"},

		// --- MF-6: export -n / declare+typeset +x identity strip ---
		{"R11_MF6_01", "bash -c 'export -n CTXMODE_ROLE; /usr/bin/python3 -V'", "worker", true, "MF-6 export -n strips CTXMODE_ROLE"},
		{"R11_MF6_02", "bash -c 'declare +x CTXMODE_ROLE; /usr/bin/python3 -V'", "worker", true, "MF-6 declare +x strips CTXMODE_ROLE"},
		{"R11_MF6_03", "bash -c 'typeset +rx CTXMODE_READONLY; ls'", "worker", true, "MF-6 typeset +rx strips CTXMODE_READONLY"},
		{"R11_MF6_04", "unset GIT_PAGER", "worker", true, "MF-6 unset hook var blocked"},
	}
}

// TestAST_MustRed_Round11 is the PLAN11 §5.1 must-red table.
func TestAST_MustRed_Round11(t *testing.T) {
	cases := astMustRedRound11Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstRedCase(t, c)
		})
	}
	t.Logf("must-red round11 summary: cases=%d", len(cases))
}

// astMustAllowRound11Cases is PLAN11 §5.2 must-allow (65 cases).
func astMustAllowRound11Cases() []astRedCase {
	return []astRedCase{
		// === 1. PATH toolchain prepend + IFS idioms (15) ===
		{"R11_ALW_01", "PATH=\"$HOME/.local/share/mise/shims:$PATH\" pnpm check", "worker", false, "mise shims prepend"},
		{"R11_ALW_02", "PATH=$HOME/.local/share/mise/installs/node/26.7.0/bin:$HOME/.local/share/mise/installs/pnpm/11.9.0:$PATH pnpm exec tsc --noEmit", "worker", false, "mise node+pnpm unquoted PATH prefix"},
		{"R11_ALW_03", "PATH=$HOME/.local/share/mise/installs/node/26.7.0/bin:$HOME/.local/share/mise/installs/pnpm/11.9.0:$PATH pnpm install --frozen-lockfile --ignore-scripts", "worker", false, "mise pnpm install"},
		{"R11_ALW_04", "PATH=\"$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:$PATH\" go version", "worker", false, "local/bin + go/bin + cargo/bin prepend"},
		{"R11_ALW_05", "PATH=\"$HOME/.cargo/bin:$HOME/.local/bin:$PATH\" cargo test --no-run", "worker", false, "$HOME/.cargo/bin prepend"},
		{"R11_ALW_06", "PATH=\"$HOME/.nvm/versions/node/v22.0.0/bin:$PATH\" npm test", "worker", false, "nvm node bin prepend"},
		{"R11_ALW_07", "PATH=\"$HOME/.pyenv/shims:$HOME/.pyenv/bin:$PATH\" pytest -q", "worker", false, "pyenv shims prepend"},
		{"R11_ALW_08", "PATH=\"$HOME/.bun/bin:$HOME/.deno/bin:$PATH\" bun --version", "worker", false, "bun + deno bin prepend"},
		{"R11_ALW_09", "PATH=\"/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin\" go env GOVERSION", "worker", false, "static system + /usr/local/go/bin PATH"},
		{"R11_ALW_10", "PATH=\"$PATH:$HOME/go/bin\" go list ./...", "worker", false, "PATH append after $PATH"},
		{"R11_ALW_11", "PATH=\"node_modules/.bin:$PATH\" tsc --noEmit", "worker", false, "node_modules/.bin relative tool prepend"},
		{"R11_ALW_12", "PATH=\".venv/bin:$PATH\" python3 -c 'import sys; print(sys.version)'", "worker", false, ".venv/bin prepend"},
		{"R11_ALW_13", "d=/usr/bin; PATH=\"$d:/bin\" ls -la", "worker", false, "NTH-2 staticVars expanded in prefix assignment"},
		{"R11_ALW_14", "find . -maxdepth 1 | while IFS= read -r p; do echo \"$p\"; done", "worker", false, "IFS= read -r standard idiom"},
		{"R11_ALW_15", "printf 'a:b:c\\n' | while IFS=: read -r f1 f2 f3; do echo \"$f1-$f2-$f3\"; done", "worker", false, "IFS=: read -r field split"},

		// === 2. Heredoc script generation (10) ===
		{"R11_ALW_16", "mkdir -p /tmp/verif/logs && cat > /tmp/verif/run.sh <<'EOF'\n#!/bin/sh\nlabel=\"$1\"; log=\"$2\"; shift 2\nstart=$(date +%s%N)\n\"$@\" >\"$log\" 2>&1\nrc=$?\necho \"${label}_exit=$rc\"\nEOF", "worker", false, "single-quoted heredoc writing wrapper script with $1/$@/$(...)"},
		{"R11_ALW_17", "cat > /tmp/verif/snapshot_check.sh <<'EOF'\n#!/bin/bash\nWT=/root/workspace\necho \"=== WT path ===\"; ls -ld \"$WT\"\ngit -C \"$WT\" rev-parse HEAD\nEOF", "worker", false, "single-quoted heredoc writing bash script with $WT"},
		{"R11_ALW_18", "cat > /tmp/verif/r4.sh <<'EOF'\n#!/bin/bash\nD=/tmp/realext-r4\nsha256sum \"$D\"/*.patch \"$D\"/*.bin 2>/dev/null\ncat \"$D/backup-r3.sha256\"\nEOF", "worker", false, "single-quoted heredoc with globs and $D"},
		{"R11_ALW_19", "cat > /tmp/verif/pipx_wrap.sh <<EOF\n#!/bin/sh\nexec /usr/bin/python3 -m pipx \"\\$@\" \\$(echo ok)\nEOF", "worker", false, "unquoted heredoc with escaped \\$@ and \\$(...)"},
		{"R11_ALW_20", "cat > /tmp/verif/doc.txt <<\\EOF\nliteral $HOME and $(id) not expanded\nEOF", "worker", false, "backslash-escaped heredoc delimiter <<\\EOF"},
		{"R11_ALW_21", "cat > /tmp/verif/doc2.txt <<'EOF-1'\nsection $1 content\nEOF-1", "worker", false, "heredoc delimiter containing hyphen <<'EOF-1'"},
		{"R11_ALW_22", "python3 - <<'PY'\nimport sys, json\ndata = {'k': '$1', 'v': '${UNSET}'}\nprint(json.dumps(data))\nPY", "worker", false, "python3 heredoc containing $ strings"},
		{"R11_ALW_23", "python3 - \"$H\" \"$S\" <<'PY'\nimport sys\nprint(sys.argv[1:])\nPY", "worker", false, "python3 - with dynamic argv operands and sq heredoc"},
		{"R11_ALW_24", "ssh -o BatchMode=yes dmit sh <<'EOF'\nls -la\ngit status --short\nEOF", "ro", false, "readonly ssh single-quoted heredoc with readonly body"},
		{"R11_ALW_25", "ssh -o BatchMode=yes dmit python3 - <<'PY'\ndef check():\n    return 42\nprint(check())\nPY", "worker", false, "worker ssh python3 - heredoc"},

		// === 3. awk/sed/tar dynamic file paths (10) ===
		{"R11_ALW_26", "git archive HEAD | tar -x -C /tmp/r4-base", "worker", false, "tar -x -C static dir"},
		{"R11_ALW_27", "d=/tmp/r4-base; tar -xf \"$d/pkg.tar.gz\" -C \"$d\"", "worker", false, "tar -xf and -C with double-quoted dynamic paths"},
		{"R11_ALW_28", "out=$(mktemp -d); tar -czf \"$out/archive.tgz\" -C /tmp/src .", "worker", false, "tar -czf with dynamic archive path"},
		{"R11_ALW_29", "f=/tmp/test.txt; sed -n '1,40p' \"$f\"", "worker", false, "sed -n with double-quoted dynamic file operand"},
		{"R11_ALW_30", "for f in /tmp/a.txt /tmp/b.txt; do sed -i 's/foo/bar/g' \"$f\"; done", "worker", false, "sed -i in loop with dynamic file"},
		{"R11_ALW_31", "p=foo; sed \"s/$p/bar/g\" /tmp/test.txt", "worker", false, "sed s///g without e flag and safe dq var"},
		{"R11_ALW_32", "f=/tmp/data.log; awk '{print $1, $2}' \"$f\"", "worker", false, "awk with double-quoted dynamic file operand"},
		{"R11_ALW_33", "val=$(date +%s); awk -v ts=\"$val\" 'BEGIN{print ts}'", "worker", false, "awk -v var=dyn assignment"},
		{"R11_ALW_34", "git diff --cached | awk 'BEGIN { state = 0 } /^@@ / { state = 1 } END { print state }'", "worker", false, "multiline awk script in pipeline"},
		{"R11_ALW_35", "bash -c 'WT=/tmp/wt; git -C \"$WT\" diff > /tmp/d.patch; echo \"n=$(rg -c \"^diff\" /tmp/d.patch)\"'", "worker", false, "bash -c with nested $(rg ...) inside double quotes"},

		// === 4. interpreter dynamic script paths + globs (8) ===
		{"R11_ALW_36", "H=/root/workspace/herdsman; node \"$H/dist/src/cli/herdsman.js\" help", "worker", false, "node with staticVar path prefix"},
		{"R11_ALW_37", "d=$(pwd); node \"$d/dist/index.js\" --version", "worker", false, "node with double-quoted cmdsub script path"},
		{"R11_ALW_38", "node --experimental-strip-types --test integrations/pi/*.test.ts", "worker", false, "node --test with path glob *.test.ts"},
		{"R11_ALW_39", "d=$(pwd); python3 \"$d/scripts/verify.py\" --fast", "worker", false, "python3 with double-quoted dynamic script path"},
		{"R11_ALW_40", "python3 -m unittest discover -s tests -p 'test_*.py'", "worker", false, "python3 -m unittest"},
		{"R11_ALW_41", "tsx \"$PWD/tools/check.ts\" --json", "worker", false, "tsx with double-quoted script path"},
		{"R11_ALW_42", "bun test tests/*.test.ts", "worker", false, "bun test with glob"},
		{"R11_ALW_43", "perl -ne 'print if /PASS/' /tmp/*.log", "worker", false, "perl -ne with file glob after script"},

		// === 5. git -C/-c/--git-dir + nested enum (8) ===
		{"R11_ALW_44", "git diff HEAD~1 HEAD | git -C /tmp/verifier-compact-ui-$$ apply", "worker", false, "git -C with $$ PID suffix"},
		{"R11_ALW_45", "set -u\nR=/root/workspace/herdsman\ngit -C $R status --short || { echo FAIL; exit 1; }", "worker", false, "git -C $R with top-level staticVars"},
		{"R11_ALW_46", "for d in repo-a repo-b; do echo \"HEAD=$(git -C /root/workspace/$d rev-parse HEAD)\"; done", "worker", false, "git -C with for-enum var inside $(...)"},
		{"R11_ALW_47", "p=$(pwd); git -C \"$p\" rev-parse --git-dir", "worker", false, "git -C double-quoted dynamic path"},
		{"R11_ALW_48", "git -c user.name=\"$(git config user.name)\" -c user.email=\"$(git config user.email)\" commit --allow-empty -m test", "worker", false, "git -c safe metadata keys with dq dynamic values"},
		{"R11_ALW_49", "d=$(pwd); git -c safe.directory=\"$d\" status", "worker", false, "git -c safe.directory dynamic"},
		{"R11_ALW_50", "d=$(pwd); git --git-dir=\"$d/.git\" --work-tree=\"$d\" status -s", "worker", false, "git --git-dir and --work-tree dq dynamic"},
		{"R11_ALW_51", "GIT_DIR=\"$PWD/.git\" GIT_WORK_TREE=\"$PWD\" git status", "worker", false, "GIT_DIR and GIT_WORK_TREE dq dynamic for worker"},

		// === 6. find start paths / globs / @ paths (7) ===
		{"R11_ALW_52", "for d in compact-on compact-off; do s=$(find $d/sessions -name '*.jsonl' | head -1); echo \"$s\"; done", "worker", false, "find $d/sessions inside $(...) inheriting for-enum"},
		{"R11_ALW_53", "find /tmp/tmp.* -newermt '5 minutes ago' 2>/dev/null | wc -l", "worker", false, "find /tmp/tmp.* unquoted glob start path"},
		{"R11_ALW_54", "D=/root/.pi/agent/npm/node_modules/@juicesharp/rpiv-config; find \"$D\" -name '*.ts' -type f -exec wc -l {} +", "worker", false, "find with @ in staticVars path and -exec +"},
		{"R11_ALW_55", "d=$(mktemp -d); find \"$d\" -maxdepth 2 -newermt '-40 minutes' -type f", "worker", false, "find pure dq var start path with static predicates"},
		{"R11_ALW_56", "d=$(pwd); find \"$d/src\" -type f -name '*.go' -exec gofmt -l {} +", "worker", false, "find \"$d/src\" with slash prefix and -exec +"},
		{"R11_ALW_57", "find /tmp -maxdepth 1 -regextype posix-extended -iregex '.*\\.(log|txt)' -fstype ext4", "worker", false, "find -regextype and -fstype value predicates"},
		{"R11_ALW_58", "find . -maxdepth 2 -name '*.go' -type f", "ro", false, "readonly find basic query"},

		// === 7. for enum / mktemp / line cont (7) ===
		{"R11_ALW_59", "for s in \"gofmt -l .\" \"go build ./...\" \"go vet ./...\" \"go test -count=1 ./...\"; do $s >/tmp/chk.log 2>&1; done", "worker", false, "for enum static multi-word commands"},
		{"R11_ALW_60", "for f in /root/.local/bin/termosh /usr/local/bin/termosh; do \"$f\" --version; done", "worker", false, "for enum abs-path command heads"},
		{"R11_ALW_61", "for p in '/tmp/' '整条不画' 'a:b' ''; do printf '%s\\n' \"$(grep -c -- \"$p\" report.md)\"; done", "worker", false, "for enum non-ident items graceful fallback"},
		{"R11_ALW_62", "td=$(mktemp -d) && go build -o \"$td/sbx\" ./cmd/sbx && \"$td/sbx\" --help", "worker", false, "mktemp -d var used in built binary head"},
		{"R11_ALW_63", "echo \"=== header ===\" \\\n  && git status --short \\\n  | head -n 20", "worker", false, "normal whitespace-preceded line continuations"},
		{"R11_ALW_64", "echo \"line 1 \\\n# still inside double quotes\"", "worker", false, "NTH-1 line continuation before # inside double quotes"},
		{"R11_ALW_65", "git log -n 5 --oneline 2>/dev/null | head -n 5", "ro", false, "readonly git log pipeline with 2>/dev/null"},
	}
}

// TestAST_MustAllow_Round11 is the PLAN11 §5.2 must-allow hard gate.
func TestAST_MustAllow_Round11(t *testing.T) {
	cases := astMustAllowRound11Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			setAstRole(t, c.role)
			hit := runAstGuard(c.role, c.code)
			if hit != "" {
				t.Fatalf("expected ALLOW (%s) but guard rejected: %s; code=%q", c.reason, hit, c.code)
			}
		})
	}
	t.Logf("must-allow round11 summary: cases=%d", len(cases))
}

// astMustRedRound12Cases is the review round-1 fix table: every R1-R9 / M1-M5
// finding gets a probe, plus the S1-S4 should-fix rows and their allow
// controls. Comment tags name the review item.
func astMustRedRound12Cases() []astRedCase {
	return []astRedCase{
		// R1/M5: missing env operands fail closed (no panic, no silent skip)
		{"FR1_01", "env --unset", "worker", true, "R1/M5 bare --unset"},
		{"FR1_02", "env -u", "worker", true, "R1/M5 bare -u"},
		{"FR1_03", "env --chdir", "worker", true, "R1 bare --chdir"},
		{"FR1_04", "env --argv0", "worker", true, "R1 bare --argv0"},
		{"FR1_05", "env -a", "worker", true, "R1 bare -a"},
		// R2/M2: GNU env -S escapes
		{"FR2_01", "env -S 'pig\\_x'", "worker", true, "R2/M2 \\_ word separator exposes pig head"},
		{"FR2_02", "env -S 'id\\_x'", "worker", false, "R2/M2 \\_ separator, benign id argv"},
		{"FR2_03", "env -S 'x\\qy'", "worker", true, "R2/M2 unknown escape fails closed"},
		{"FR2_04", "env -S 'x\\ y'", "worker", true, "R2/M2 backslash-space invalid per GNU"},
		{"FR2_05", "env -S 'true\\c pig'", "worker", false, "R2/M2 \\c truncates payload to true"},
		{"FR2_06", "env -S 'pig #x'", "worker", true, "R2/M2 word-start # comment leaves pig head"},
		{"FR2_07", "env -S 'true pig'", "worker", false, "R2/M2 plain words: exec true with arg pig"},
		// R3/M1: word-start dq placeholder + '/' can run as -c/-e
		{"FR3_01", "find \"$X/y\" -name n", "worker", true, "R3/M1 dq+/ start path"},
		{"FR3_02", "node \"$X/app.js\"", "worker", true, "R3/M1 dq+/ script operand"},
		{"FR3_03", "find \"$PWD/x\" -maxdepth 1", "worker", false, "R3/M1 abs-dq+/ stays safe"},
		// R4: dynamic sed script may inject `e` via a delimiter byte
		{"FR4_01", "sed \"s/$p/bar/g\" /tmp/test.txt", "worker", true, "R4 unbound dynamic s/// script"},
		{"FR4_02", "p='x/g;e pig'; sed \"s/$p/bar/g\" /tmp/test.txt", "worker", true, "R4 lit bind carrying e command"},
		{"FR4_03", "p=foo; sed \"s/$p/bar/g\" /tmp/test.txt", "worker", false, "R4 restricted literal bind stays free (ALW31)"},
		{"FR4_04", "sed 's/a/b/e' /tmp/f", "worker", true, "R4 static s///e already screened"},
		// R5: xargs -I token inside a code slot is fed, not only as a whole word
		{"FR5_01", "echo pig | xargs -I{} sh -c 'echo {}'", "worker", true, "R5 -I{} token word after -c"},
		{"FR5_02", "echo pig | xargs -I{} sh -c 'x{}y'", "worker", true, "R5 token embedded in code word"},
		{"FR5_03", "echo pig | xargs -I{} sh -c\"{}\"", "worker", true, "R5 glued -c code slot"},
		{"FR5_04", "echo pig | xargs sh -c", "worker", true, "R5 bare trailing -c fed by stream"},
		// R6: a Background subtree never binds in the parent
		{"FR6_01", "x=/tmp && true & find \"$x\" -maxdepth 1", "worker", true, "R6 BinaryCmd background left-bind"},
		{"FR6_02", "{ x=/tmp; } & find \"$x\" -maxdepth 1", "worker", true, "R6 Block background bind"},
		{"FR6_03", "(x=/tmp) & find \"$x\" -maxdepth 1", "worker", true, "R6 Subshell background bind"},
		// R7: env context reaches heredoc / here-string / -c payloads
		{"FR7_01", "env -u PWD sh <<'EOF'\nfind \"$PWD\" -maxdepth 1\nEOF", "worker", true, "R7 env -u PWD into heredoc"},
		{"FR7_02", "env -i sh <<'EOF'\nfind \"$PWD\" -maxdepth 1\nEOF", "worker", true, "R7 env -i clears heredoc grants"},
		{"FR7_03", "env -u PWD sh -c 'find \"$PWD\" -maxdepth 1'", "worker", true, "R7 env -u PWD into -c"},
		{"FR7_04", "env HOME=/x sh <<'EOF'\ncd \"$HOME\"; pig\nEOF", "worker", true, "R7 HOME override taints heredoc"},
		{"FR7_05", "sh <<'EOF'\nfind \"$PWD\" -maxdepth 1\nEOF", "worker", false, "R7 untouched PWD grant still passes"},
		// R8: enum sub-words must not re-glob
		{"FR8_01", "for s in \"git *\" \"echo ok\"; do $s; done", "worker", true, "R8 glob char in enum cmd word"},
		{"FR8_02", "for s in \"ls -l\" \"echo ok\"; do $s; done", "worker", false, "R8 plain enum words still bind"},
		// R9: ctx_run env API uses the unified hook table
		// (probe lives in role_guards_test.go — needs guardCtxRunEnv)
		// M3: last fd0 redirect decides what feeds the program
		{"FM3_01", "sh < /tmp/x <<'EOF'\npig\nEOF", "worker", true, "M3 file-redir before heredoc still screens body"},
		{"FM3_02", "sh <<'EOF' < /tmp/x\nls\nEOF", "worker", false, "M3 file-redir last: body is data, sh runs /tmp/x"},
		// M4: pipeIn reaches compound bodies
		{"FM4_01", "echo pig | (sh)", "worker", true, "M4 subshell pipe penetration"},
		{"FM4_02", "echo pig | (cat; sh)", "worker", true, "M4 second stmt in subshell"},
		{"FM4_03", "echo pig | { sh; }", "worker", true, "M4 brace group"},
		{"FM4_04", "echo pig | if true; then sh; fi", "worker", true, "M4 if body"},
		{"FM4_05", "echo pig | while read x; do sh; done", "worker", true, "M4 while body"},
		{"FM4_06", "echo pig | cat $(sh)", "worker", true, "M4 cmdsubst inherits pipe stdin"},
		{"FM4_07", "bash -c 'ls > >(sh)'", "worker", true, "M4 output procsubst fed by stdout"},
		// S1: the "*" give-up taint poisons every bind
		{"FS1_01", "command $(true) PWD; find \"$PWD\" -maxdepth 1", "worker", true, "S1 * taint blocks PWD grant"},
		// S2: PS4/SHELLOPTS/BASHOPTS are hook vars
		{"FS2_01", "PS4='x' bash -x -c 'id'", "worker", true, "S2 PS4 prompt-expansion hook"},
		{"FS2_02", "BASHOPTS=xpg_echo bash -c 'id'", "worker", true, "S2 BASHOPTS startup options"},
		// S3: -f - / -f <(...) read an unvetted script
		{"FS3_01", "awk -f -", "worker", true, "S3 awk program from stdin"},
		{"FS3_02", "sed -f -", "worker", true, "S3 sed script from stdin"},
		{"FS3_03", "sed --file=-", "worker", true, "S3 sed --file=- stdin"},
		{"FS3_04", "bash -c 'awk -f <(echo x)'", "worker", true, "S3 awk -f process subst"},
		{"FS3_05", "bash -c 'sed -f <(echo x)'", "worker", true, "S3 sed -f process subst"},
		// S4: journalctl -n is a legal short option
		{"FS4_01", "journalctl -n 5", "ro", false, "S4 -n boolean + operand"},
		{"FS4_02", "journalctl -n", "ro", false, "S4 bare -n"},
		// M3 follow-up: local file redirect feeding an ssh stdin-program head
		{"FSH_01", "ssh dmit sh < /tmp/x", "worker", true, "M3 local file as remote program"},
	}
}

// TestAST_MustRed_Round12 is the review round-1 regression gate.
func TestAST_MustRed_Round12(t *testing.T) {
	cases := astMustRedRound12Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstRedCase(t, c)
		})
	}
	t.Logf("must-red round12 summary: cases=%d", len(cases))
}

// astMustRedRound13Cases is the review round-3 fix table: five must-fix
// probes with `want` asserting the hit REASON (the why), not only the
// allow/deny boolean. Rows whose attack lives in the ctx_run stdin API
// (env-taint, read -s) sit in role_guards_test.go instead.
func astMustRedRound13Cases() []astRedWantCase {
	return []astRedWantCase{
		// M1: only an fd0 redirect binds stdin — `sh 3</dev/null` still
		// reads the piped bytes as its program.
		{astRedCase{"R13_M1_01", "echo pig | sh 3</dev/null", "worker", true, "M1 non-fd0 redir still piped"}, "piped code to shell"},
		{astRedCase{"R13_M1_02", "echo pig | sh 3<<EOF\nls\nEOF", "worker", true, "M1 non-fd0 heredoc still piped"}, "piped code to shell"},
		// M2: the right side of && / || shares the operator's stdin —
		// inside a compound fed by a pipe, `grep p && sh` runs the piped
		// bytes as sh's program (the operator itself is piped).
		{astRedCase{"R13_M2_01", "echo pig | (grep p && sh)", "worker", true, "M2 &&-right inherits pipe"}, "piped code to shell"},
		{astRedCase{"R13_M2_02", "echo pig | { grep q || sh; }", "worker", true, "M2 ||-right inherits pipe"}, "piped code to shell"},
		// M3: every executable sub-statement inside $(...) shares the
		// substitution's stdin, not only the first one.
		{astRedCase{"R13_M3_01", "echo pig | cat $(true; sh)", "worker", true, "M3 second cmdsubst stmt inherits pipe"}, "piped code to shell"},
		// M4: xargs fed words reaching a code slot in ANY interpreter
		// spelling — clusters (-lc), glued values and wrapper heads.
		{astRedCase{"R13_M4_01", "echo pig | xargs -I{} sh -lc '{}'", "worker", true, "M4 sh -lc cluster code slot"}, "piped code to shell"},
		{astRedCase{"R13_M4_02", "echo pig | xargs -i sh -c '{}'", "worker", true, "M4 deprecated -i default token"}, "piped code to shell"},
		{astRedCase{"R13_M4_03", "echo pig | xargs -I{} env sh -c '{}'", "worker", true, "M4 inner wrapper head peel"}, "piped code to shell"},
		{astRedCase{"R13_M4_04", "echo pig | xargs -I{} python3 -uc '{}'", "worker", true, "M4 python cluster code slot"}, "piped code to python"},
		{astRedCase{"R13_M4_05", "echo pig | xargs -I{} node -pe '{}'", "worker", true, "M4 node cluster code slot"}, "piped code to javascript"},
		// M6: sed --file=VALUE is a script-file slot: proc subst and
		// unvettable dynamic values must hit the -f operand screen.
		{astRedCase{"R13_M6_01", "bash -c 'sed --file=<(echo x)'", "worker", true, "M6 --file= proc subst script file"}, "dynamic code payload"},
		{astRedCase{"R13_M6_02", "sed --file=$X /tmp/f", "worker", true, "M6 --file= unquoted dynamic"}, "dynamic code payload"},
		// Allow controls: fd0 file redir still exempts the program, and a
		// proc subst in a DATA slot stays free.
		{astRedCase{"R13_ALW_01", "echo pig | sh < /dev/null 3</dev/null", "worker", false, "M1 fd0 file redir wins"}, ""},
		{astRedCase{"R13_ALW_02", "bash -c 'ls <(echo x)'", "worker", false, "M6 proc subst in data slot"}, ""},
	}
}

// TestAST_MustRed_Round13 is the review round-3 regression gate.
func TestAST_MustRed_Round13(t *testing.T) {
	cases := astMustRedRound13Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstWantCase(t, c)
		})
	}
	t.Logf("must-red round13 summary: cases=%d", len(cases))
}

// astMustRedRound14Cases is the review round-4 fix table: fd-duplication
// stdin origins, the flag-model interpreter cluster fix (-ce / -pe / -co),
// xargs cluster + GNU --replace replace-token handling, recursive API-stdin
// env propagation (probes in TestGuard_CtxRunStdinEnv), sed dynamic cluster
// values and the narrowed relative-PATH exception.
func astMustRedRound14Cases() []astRedWantCase {
	return []astRedWantCase{
		// MF-1a: n<&m copies the SOURCE fd's stdin origin — `0<&0` keeps the
		// pipe open (no file binding happened) and `9<&0 0<&9` still routes
		// the piped fd0 into the program slot through fd 9.
		{astRedCase{"R14_M1_01", "echo pig | sh 0<&0", "worker", true, "M1 fd0 self-dup keeps pipe"}, "piped code to shell"},
		{astRedCase{"R14_M1_02", "echo pig | sh 9<&0 0<&9", "worker", true, "M1 fd0 dup via fd9 keeps pipe"}, "piped code to shell"},
		{astRedCase{"R14_M1_03", "echo pig | sh 0<&-", "worker", false, "M1 fd0 close binds stdin"}, ""},
		{astRedCase{"R14_M1_04", "echo pig | sh 9<f 0<&9", "worker", false, "M1 fd0 dup of file-bound fd"}, ""},
		// MF-1b: a compound statement's fd0 redirect feeds its body —
		// `(sh) <<'EOF'` hands the heredoc payload to the inner sh and
		// `(sh) < f` marks its stdin file-bound.
		{astRedCase{"R14_M1_05", "(sh) <<'EOF'\npig\nEOF", "worker", true, "M1 compound heredoc feeds inner sh"}, "pig"},
		{astRedCase{"R14_M1_06", "echo pig | (sh) <<'EOF'\nls\nEOF", "worker", false, "M1 compound heredoc overrides pipe"}, ""},
		{astRedCase{"R14_M1_07", "{ sh; } <<'EOF'\npig\nEOF", "worker", true, "M1 brace-group heredoc feeds sh"}, "pig"},
		{astRedCase{"R14_M1_08", "echo pig | (sh) < /dev/null", "worker", false, "M1 compound file redir binds stdin"}, ""},

		// MF-2: flag-model interpreter clusters — letters after a code flag
		// are flags, not code tails (sh -ce, node -pe), and a trailing -o
		// inside the tail consumes the next argv as its option name.
		{astRedCase{"R14_M2_01", "echo pig | xargs -I{} sh -ce '{}'", "worker", true, "M2 sh -ce flag tail fed"}, "piped code to shell"},
		{astRedCase{"R14_M2_02", "sh -ce 'pig'", "worker", true, "M2 sh -ce code is next argv"}, "pig"},
		{astRedCase{"R14_M2_03", "bash -co vi 'pig'", "worker", true, "M2 bash -co: vi is -o operand, pig is code"}, "pig"},
		{astRedCase{"R14_M2_04", "node -pe 'require(\"child_process\").execSync(\"pig\")'", "worker", true, "M2 node -pe code is next argv"}, "javascript inline code"},
		{astRedCase{"R14_M2_05", "echo pig | xargs -I{} node -pe '{}'", "worker", true, "M2 node -pe code slot fed"}, "piped code to javascript"},
		{astRedCase{"R14_M2_06", "echo pig | xargs -rI{} sh -c '{}'", "worker", true, "M2 -rI{} cluster repl token"}, "piped code to shell"},
		{astRedCase{"R14_M2_07", "echo pig | xargs --replace sh -c '{}'", "worker", true, "M2 bare --replace defaults to {}"}, "piped code to shell"},
		{astRedCase{"R14_M2_08", "xargs --replace true <<'EOF'\npig\nEOF", "worker", false, "M2 --replace does not eat the command"}, ""},

		// MF-4: a dynamic sed cluster value is located by the static prefix —
		// -nf<V> names a script FILE and must get the -f operand screen; an
		// unvettable dynamic option zone fails closed.
		{astRedCase{"R14_M4_01", "bash -c 'sed -nf<(echo \"e pig\")'", "worker", true, "M4 -nf proc-subst script file"}, "dynamic code payload"},
		{astRedCase{"R14_M4_02", "sed -nf$X /tmp/f", "worker", true, "M4 -nf unquoted dynamic"}, "dynamic code payload"},
		{astRedCase{"R14_M4_03", "sed -$X /tmp/f", "worker", true, "M4 unvettable dynamic option word"}, "dynamic code payload"},
		{astRedCase{"R14_M4_04", "sed -nf\"$PWD/x.sed\" /tmp/f", "worker", false, "M4 -nf abs-dq file stays free"}, ""},

		// MF-5: only the four authorized relative PATH segments survive —
		// venv/bin and ./venv/bin (no leading dot) must reject again.
		{astRedCase{"R14_M5_01", "PATH=\"venv/bin:$PATH\" python3 -V", "worker", true, "M5 venv/bin no longer allowed"}, "env PATH"},
		{astRedCase{"R14_M5_02", "PATH=\"./venv/bin:$PATH\" python3 -V", "worker", true, "M5 ./venv/bin no longer allowed"}, "env PATH"},

		// Evidence: `read -s x` binds x — the pre-scan must taint the name so
		// a later head/$ expansion does not inherit a stale trust. R15: x is
		// bound to a LEGAL head first; without the read taint the "$x" head
		// would resolve statically and pass — a bare `read -s x; "$x"` was a
		// false-green probe because an unbound $x is dynamic either way.
		{astRedCase{"R14_EV_01", "x=/bin/echo; read -s x; \"$x\"", "worker", true, "EV read -s x taints x"}, "dynamic command head"},
	}
}

// astMustRedRound15Cases is the review round-5 fix table: operator-scoped
// default fd descriptors, inherited compound fd origins, perl/ruby
// optional-glued cluster letters (-i not swallowing -e), recursive env
// propagation through wrapper/fed-code/stdin branches, and sed's dynamic
// -f argv advance.
func astMustRedRound15Cases() []astRedWantCase {
	return []astRedWantCase{
		// MF-1: an output op without N binds fd1, not fd0 — `sh >/dev/null`
		// inside a pipeline still reads its program from the pipe.
		{astRedCase{"R15_M1_01", "echo pig | sh >/dev/null", "worker", true, "M1 > binds fd1 not fd0"}, "piped code to shell"},
		{astRedCase{"R15_M1_02", "echo pig | sh >>/dev/null", "worker", true, "M1 >> binds fd1 not fd0"}, "piped code to shell"},

		// MF-2: a compound statement's own non-fd0 dups ride the inherited
		// descriptor table into the body — `{ sh 0<&9; } 9<&0` smuggles the
		// pipe through fd9 exactly like the flat `9<&0 0<&9` spelling.
		{astRedCase{"R15_M2_01", "echo pig | { sh 0<&9; } 9<&0", "worker", true, "M2 compound fd9 dup carries pipe"}, "piped code to shell"},
		{astRedCase{"R15_M2_02", "echo pig | (sh 0<&9) 9<&0", "worker", true, "M2 subshell fd9 dup carries pipe"}, "piped code to shell"},
		{astRedCase{"R15_M2_03", "echo pig | { sh 0<&9; } 9<f", "worker", false, "M2 fd9 file-bound inside group"}, ""},

		// MF-3: perl/ruby -i is an optional-GLUED flag — a bare -i consumes
		// no argv word, so a separate -e still carries the code operand.
		{astRedCase{"R15_M3_01", "perl -i -e 'system(\"pig\")'", "worker", true, "M3 perl -i -e code slot"}, "perl inline code"},
		{astRedCase{"R15_M3_02", "ruby -i -e 'system(\"pig\")'", "worker", true, "M3 ruby -i -e code slot"}, "ruby inline code"},
		{astRedCase{"R15_M3_03", "echo x | xargs -I{} perl -i -e '{}'", "worker", true, "M3 xargs-fed perl -e after -i"}, "piped code to perl"},

		// MF-4: env ops peeled inside flock/watch/xargs recursion reach the
		// env the stdin-program text runs under — a heredoc / here-string
		// payload screens `find "$HOME"` as a dynamic predicate once the
		// inner HOME=-exec op merges into envAs (the xargs fed-code inner
		// env is covered in TestGuard_CtxRunStdinEnv).
		{astRedCase{"R15_M4_01", "flock /tmp/l env HOME=-exec sh <<'EOF'\nfind \"$HOME\" -maxdepth 1\nEOF", "worker", true, "M4 flock inner env reaches heredoc"}, "find dynamic predicate"},
		{astRedCase{"R15_M4_02", "watch -x env HOME=-exec sh <<'EOF'\nfind \"$HOME\" -maxdepth 1\nEOF", "worker", true, "M4 watch -x inner env reaches heredoc"}, "find dynamic predicate"},
		{astRedCase{"R15_M4_03", "xargs -r env HOME=-exec sh <<'EOF'\nfind \"$HOME\" -maxdepth 1\nEOF", "worker", true, "M4 xargs inner env reaches heredoc"}, "find dynamic predicate"},
		// <<< needs the bash grammar — the payload rides a bash -c wrapper;
		// the escaped \$ keeps $HOME literal inside the here-string so the
		// env-merge (not collect-time substitution) decides the verdict.
		{astRedCase{"R15_M4_04", "bash -c 'flock /tmp/l env HOME=-exec sh <<< \"find \\$HOME -maxdepth 1\"'", "worker", true, "M4 flock inner env reaches here-string"}, "find dynamic predicate"},
		{astRedCase{"R15_M4_05", "bash -c 'watch -x env HOME=-exec sh <<< \"find \\$HOME -maxdepth 1\"'", "worker", true, "M4 watch inner env reaches here-string"}, "find dynamic predicate"},

		// MF-5: a dynamic -f tail is the GLUED script-file operand — argv
		// advance uses the real word length, so a following -e still arms
		// the exec screen while the dynamic path operand stays free.
		{astRedCase{"R15_M5_01", "sed -nf\"$PWD/x.sed\" -e 'e pig' /tmp/f", "worker", true, "M5 dynamic -f tail: -e still seen"}, "pig"},
		{astRedCase{"R15_M5_02", "sed -nf\"$PWD/x.sed\" 'e pig' /tmp/f", "worker", false, "M5 dynamic -f tail: positional is data"}, ""},
	}
}

// TestAST_MustRed_Round15 is the review round-5 regression gate.
func TestAST_MustRed_Round15(t *testing.T) {
	cases := astMustRedRound15Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstWantCase(t, c)
		})
	}
	t.Logf("must-red round15 summary: cases=%d", len(cases))
}

// astMustRedRound16Cases is the review round-6 fix table: output-side fd
// duplication copies the source descriptor's stdin origin (0>&0 is a
// no-op, not a file bind), the right side of &&/|| and a pipeline keeps
// the inherited descriptor table (0<&9 still resolves fd9), and perl/ruby
// restricted numeric optional flags resume cluster scanning after their
// legal tail (-0e is -0 -e).
func astMustRedRound16Cases() []astRedWantCase {
	return []astRedWantCase{
		// MF-1: n>&m duplicates the descriptor — dash runs the same dup2
		// for >& and <&, so 0>&0 leaves fd0's origin untouched and the
		// pipe still reaches the program.
		{astRedCase{"R16_M1_01", "echo pig | sh 0>&0", "worker", true, "M1 output-side fd0 self-dup keeps pipe"}, "piped code to shell"},
		{astRedCase{"R16_M1_02", "echo pig | sh 9>&0 0<&9", "worker", true, "M1 fd9 dup of fd0 via >&"}, "piped code to shell"},
		{astRedCase{"R16_M1_03", "echo pig | sh 0>&1", "worker", false, "M1 fd0 dup of unseen fd1 is a write target"}, ""},
		{astRedCase{"R16_M1_04", "echo pig | sh 0>&-", "worker", false, "M1 fd0 close binds stdin"}, ""},

		// MF-2: a && / || / | right branch shares the whole descriptor
		// table — only fd0's stream differs (pipe) or is identical
		// (conditional), so an inherited fd9 dup still smuggles the pipe.
		// R16_M2_03 narrowed (R17): the { cat; sh; } row exercises
		// stmtFeed's group-redirect replay into walkStmtsAll's shared feed,
		// NOT walkStmts' i>0 sequential fds branch — that branch's
		// feed.fds is nil at every call site (see R17_M3_01).
		{astRedCase{"R16_M2_01", "echo pig | { true && sh 0<&9; } 9<&0", "worker", true, "M2 &&-right inherits fd table"}, "piped code to shell"},
		{astRedCase{"R16_M2_02", "echo pig | { cat | sh 0<&9; } 9<&0", "worker", true, "M2 pipe-right keeps fd9"}, "piped code to shell"},
		{astRedCase{"R16_M2_03", "echo pig | { cat; sh 0<&9; } 9<&0", "worker", true, "M2 brace-group fd table into later stmts (walkStmtsAll)"}, "piped code to shell"},
		{astRedCase{"R16_M2_04", "echo pig | { true && sh 0<&9; } 9<f", "worker", false, "M2 fd9 file-bound inside group"}, ""},

		// MF-3: perl/ruby restricted numeric optional tails (-0/-l) end at
		// their legal bytes — a glued flag letter after the value is a
		// FLAG, not part of the value, so -0e/-le still carry -e's code.
		{astRedCase{"R16_M3_01", "perl -0e 'system(\"pig\")'", "worker", true, "M3 perl -0e code slot"}, "perl inline code"},
		{astRedCase{"R16_M3_02", "perl -le 'system(\"pig\")'", "worker", true, "M3 perl -le code slot"}, "perl inline code"},
		{astRedCase{"R16_M3_03", "perl -0777e 'system(\"pig\")'", "worker", true, "M3 perl -0 digit tail then e"}, "perl inline code"},
		{astRedCase{"R16_M3_04", "ruby -0e 'system(\"pig\")'", "worker", true, "M3 ruby -0e code slot"}, "ruby inline code"},
		{astRedCase{"R16_M3_05", "echo x | xargs -I{} perl -0e '{}'", "worker", true, "M3 xargs-fed perl -e after -0"}, "piped code to perl"},
	}
}

// TestAST_MustRed_Round16 is the review round-6 regression gate.
func TestAST_MustRed_Round16(t *testing.T) {
	cases := astMustRedRound16Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstWantCase(t, c)
		})
	}
	t.Logf("must-red round16 summary: cases=%d", len(cases))
}

// astMustRedRound17Cases is the review round-7 fix table: a dynamic
// n<&m / n>&m target no longer earns a file exemption (an unparseable dup
// word keeps fd n's origin tainted, never file-bound), and a function body
// inherits the declaration's PROVABLE descriptor table while every other
// dup inside the body fails closed — the call-site fd set is unknown.
func astMustRedRound17Cases() []astRedWantCase {
	return []astRedWantCase{
		// MF-1: 0<&$(...) cannot prove the dup target, so fd0 keeps a
		// tainted (possibly-pipe) origin — the real shell dup2s whatever the
		// expansion yields and fd0 may still be the pipe.
		{astRedCase{"R17_M1_01", "echo pig | sh 0<&$(printf 0)", "worker", true, "M1 dynamic dup target keeps fd0 taint"}, "piped code to shell"},
		{astRedCase{"R17_M1_02", "echo pig | sh 0<&`printf 0`", "worker", true, "M1 backtick dup target keeps fd0 taint"}, "piped code to shell"},
		{astRedCase{"R17_M1_03", "echo pig | sh 9<&$(printf 0) 0<&9", "worker", true, "M1 dynamic fd9 stays tainted"}, "piped code to shell"},
		{astRedCase{"R17_M1_04", "echo pig | sh 9<&$(printf 1) 0>&9", "worker", true, "M1 output-side dynamic dup stays tainted"}, "piped code to shell"},
		// Without a pipe the same construct still fails closed: an
		// unprovable dup target never buys back the file exemption, and the
		// tainted origin reads as a possibly-piped stdin for a program head.
		{astRedCase{"R17_M1_05", "sh 0<&$(printf 0)", "worker", true, "M1 dynamic dup fails closed without pipe too"}, "piped code to shell"},
		{astRedCase{"R17_M1_06", "echo pig | sh 0<&0", "worker", true, "M1 static self-dup still resolves"}, "piped code to shell"},

		// MF-2: a function body sees the CALL's stdin, modelled as fed —
		// its fd table therefore inherits only the declaration-site
		// redirects that provably ride the call (`{ f(){...}; f; } 9<&0` and
		// `f(){...} 9<&0`), and every dup of an unproven fd fails closed
		// instead of inheriting the old file exemption.
		{astRedCase{"R17_M2_01", "echo pig | { f() { sh 0<&9; }; f; } 9<&0", "worker", true, "M2 function body inherits group fd9"}, "piped code to shell"},
		{astRedCase{"R17_M2_02", "f() { sh 0<&9; }; f", "worker", true, "M2 unprovable call-site fd9 fails closed"}, "piped code to shell"},
		{astRedCase{"R17_M2_03", "echo pig | f() { sh 0<&9; } 9<&0", "worker", true, "M2 decl-site 9<&0 rides the call"}, "piped code to shell"},
		{astRedCase{"R17_M2_04", "f() { cat; sh 0<&9; }; f", "worker", true, "M2 unprovable fd9 in sequential body"}, "piped code to shell"},
		{astRedCase{"R17_M2_05", "f() { sh 0<&9; } 9<f; f", "worker", false, "M2 provable file fd9 stays file"}, ""},

		// MF-3 coverage honesty: R16_M2_03's sequential claim actually
		// exercises stmtFeed's group-redirect replay into walkStmtsAll's
		// shared feed — walkStmts' i>0 fds field is dead (every list-level
		// feed carries fds=nil, propagated only defensively). This row pins
		// the standalone spelling of the same brace redirect so the real
		// covered path is what the reason names.
		{astRedCase{"R17_M3_01", "{ cat; sh 0<&9; } 9<&0", "worker", false, "M3 standalone brace group fd9 resolves fd0"}, ""},
	}
}

// TestAST_MustRed_Round17 is the review round-7 regression gate.
func TestAST_MustRed_Round17(t *testing.T) {
	cases := astMustRedRound17Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstWantCase(t, c)
		})
	}
	t.Logf("must-red round17 summary: cases=%d", len(cases))
}

// astMustRedRound18Cases is the review round-8 fix table: a function
// declaration no longer captures the DECLARATION-site environment (the
// body's file/body exemptions and fd table now model the unknown call
// environment — only the decl's own redirects replay at call time), dup
// source descriptors normalize leading zeros (00 is fd0), and the bash
// n<&m- move syntax copies the source origin then closes the source.
func astMustRedRound18Cases() []astRedWantCase {
	return []astRedWantCase{
		// MF-1: the declaration environment is not a closure — a file
		// bound at decl site (compound redirect or decl-env fd9) does not
		// carry into the body, so a call-time pipe still feeds sh.
		{astRedCase{"R18_M1_01", "{ f() { sh; }; } </dev/null; echo pig | f", "worker", true, "M1 decl-env </dev/null not captured by body"}, "piped code to shell"},
		{astRedCase{"R18_M1_02", "{ f() { sh 0<&9; }; } 9</dev/null; echo pig | f", "worker", true, "M1 decl-env file fd9 not captured by body"}, "piped code to shell"},
		{astRedCase{"R18_M1_03", "f() { sh; }; echo pig | f", "worker", true, "M1 bare call pipe still feeds body"}, "piped code to shell"},
		// Release controls: the function's OWN redirects replay at call
		// time — `</dev/null` on the decl binds call-site stdin to a file,
		// `9<f` keeps the provable file fd9 exemption, and `9<&-` closes.
		{astRedCase{"R18_M1_04", "f() { sh; } </dev/null; echo pig | f", "worker", false, "M1 decl-self </dev/null binds call stdin"}, ""},
		{astRedCase{"R18_M1_05", "f() { sh 0<&9; } 9</dev/null; f", "worker", false, "M1 decl-self 9<f stays provable file"}, ""},
		{astRedCase{"R18_M1_06", "f() { sh 0<&9; } 9<&-; f", "worker", false, "M1 decl-self fd9 close stays file"}, ""},

		// MF-2: the dup source descriptor normalizes leading zeros —
		// bash reads `0<&00` as dup2(0,0), so the "00" word must hit the
		// "0" slot and keep the pipe origin instead of a file.
		{astRedCase{"R18_M2_01", "echo pig | sh 0<&00", "worker", true, "M2 leading-zero source fd resolves fd0"}, "piped code to shell"},
		{astRedCase{"R18_M2_02", "echo pig | sh 09<&0 0<&9", "worker", true, "M2 leading-zero dest fd9 still carries pipe"}, "piped code to shell"},

		// MF-3: `n<&m-` is the bash move syntax — dup m into n then close
		// m — never a file target. fd0 inherits fd9's piped origin, and a
		// later dup of the moved-away fd reads the CLOSED descriptor.
		{astRedCase{"R18_M3_01", "echo pig | sh 9<&0 0<&9-", "worker", true, "M3 move copies piped fd9 into fd0"}, "piped code to shell"},
		{astRedCase{"R18_M3_02", "echo pig | sh 0>&9- 0<&9", "worker", false, "M3 moved-away fd9 reads closed"}, ""},
		{astRedCase{"R18_M3_03", "echo pig | sh 9>&/tmp/out", "worker", true, "M3 non-digit >&word is no fd bind (fd0 keeps pipe)"}, "piped code to shell"},
	}
}

// TestAST_MustRed_Round18 is the review round-8 regression gate.
func TestAST_MustRed_Round18(t *testing.T) {
	cases := astMustRedRound18Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstWantCase(t, c)
		})
	}
	t.Logf("must-red round18 summary: cases=%d", len(cases))
}

// TestAST_MustRed_Round14 is the review round-4 regression gate.
func TestAST_MustRed_Round14(t *testing.T) {
	cases := astMustRedRound14Cases()
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			runAstWantCase(t, c)
		})
	}
	t.Logf("must-red round14 summary: cases=%d", len(cases))
}

// runAstWantCase executes one want-case row: an expected reject must hit,
// and when want is set the hit detail must contain it (the WHY).
func runAstWantCase(t *testing.T, c astRedWantCase) {
	t.Helper()
	setAstRole(t, c.role)
	hit := runAstGuard(c.role, c.code)
	allowed := hit == ""
	if c.reject {
		if allowed {
			t.Fatalf("expected REJECT (%s) but guard allowed; code=%q", c.reason, c.code)
		}
		if c.want != "" && !strings.Contains(hit, c.want) {
			t.Fatalf("expected hit containing %q (%s) but got %q; code=%q", c.want, c.reason, hit, c.code)
		}
	} else {
		if !allowed {
			t.Fatalf("expected ALLOW (%s) but guard rejected: %s; code=%q", c.reason, hit, c.code)
		}
	}
}

// runAstRedCase executes one table row: an expected reject must hit.
func runAstRedCase(t *testing.T, c astRedCase) {
	t.Helper()
	runAstWantCase(t, astRedWantCase{astRedCase: c})
}
