package main

// Regression tests for the rt1111 red-team fix batch (A-1..A-11, W-5).
// Guard entry mirrors main.go toolExecute: guardCtxRunShell +
// guardCtxRunStdinForCommand for shell commands, guardCtxRunArgv +
// guardCtxRunStdin for argv form, guardCtxRunCode for language snippets.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rtCmdRule returns the guard outcome for a shell command + stdin pair.
// "" means the call passed every guard layer.
func rtCmdRule(role, ro, cmd, stdin string) (rule, detail string) {
	os.Setenv("CTXMODE_ROLE", role)
	os.Setenv("CTXMODE_READONLY", ro)
	defer os.Unsetenv("CTXMODE_ROLE")
	defer os.Unsetenv("CTXMODE_READONLY")
	g := currentGuardCall()
	if v, _ := screenShellCommand(cmd); v == shellBlock {
		return "screenBlock", ""
	}
	if rule, detail := g.guardCtxRunShell(cmd); rule != "" {
		return rule, detail
	}
	return g.guardCtxRunStdinForCommand(cmd, stdin)
}

func rtArgvRule(role, ro string, argv []string, stdin string) (rule, detail string) {
	os.Setenv("CTXMODE_ROLE", role)
	os.Setenv("CTXMODE_READONLY", ro)
	defer os.Unsetenv("CTXMODE_ROLE")
	defer os.Unsetenv("CTXMODE_READONLY")
	g := currentGuardCall()
	if rule, detail := g.guardCtxRunArgv(argv); rule != "" {
		return rule, detail
	}
	return g.guardCtxRunStdin(argv, stdin)
}

func rtCodeRule(role, ro, lang, code string) (rule, detail string) {
	os.Setenv("CTXMODE_ROLE", role)
	os.Setenv("CTXMODE_READONLY", ro)
	defer os.Unsetenv("CTXMODE_ROLE")
	defer os.Unsetenv("CTXMODE_READONLY")
	g := currentGuardCall()
	return g.guardCtxRunCode(lang, code)
}

// A-6: stdin screening must inspect every segment, skipping segments
// whose stdin is already claimed by a pipe/redirect/heredoc/here-string.
func TestRT_A6_StdinPerSegment(t *testing.T) {
	block := []struct{ name, role, ro, cmd, stdin string }{
		{"py-devnull-then-sh-worker", "worker", "", "python3 - </dev/null; sh", "pig"},
		{"py-devnull-then-sh-verifier", "verifier", "", "python3 - </dev/null; sh", "pig"},
		{"py-then-sh-worker", "worker", "", "python3 -; sh", "pig"},
		{"sh-herestring-then-sh", "worker", "", "sh <<< 'echo hi'; sh", "pig"},
		{"sh-heredoc-then-sh", "worker", "", "sh <<'EOF'\necho hi\nEOF\nsh", "pig"},
		{"pipe-then-sh", "worker", "", "echo hi | sh; sh", "pig"},
	}
	for _, c := range block {
		rule, detail := rtCmdRule(c.role, c.ro, c.cmd, c.stdin)
		if rule != ruleSubagentNestedAgent {
			t.Errorf("%s: got (%q,%q), want %s", c.name, rule, detail, ruleSubagentNestedAgent)
		}
	}
	allow := []struct{ name, role, ro, cmd, stdin string }{
		{"py-stdin-then-ls", "worker", "", "python3 -; ls", "print(1)"},
		{"py-heredoc", "worker", "", "python3 - <<'EOF'\nprint(1)\nEOF", ""},
		{"py-devnull-then-ls", "worker", "", "python3 - </dev/null; ls", "pig"},
	}
	for _, c := range allow {
		rule, detail := rtCmdRule(c.role, c.ro, c.cmd, c.stdin)
		if rule != "" {
			t.Errorf("%s: got BLOCK %s: %s, want ALLOW", c.name, rule, detail)
		}
	}
}

// A-5: /dev/stdin, /dev/fd/0, /proc/self/fd/0, /proc/thread-self/fd/0 must
// count as stdin program sources for shells, interpreters, awk and sed.
func TestRT_A5_StdinDevicePath(t *testing.T) {
	if !isStdinDevicePath("/dev/stdin") || !isStdinDevicePath("/dev/fd/0") ||
		!isStdinDevicePath("/proc/self/fd/0") || !isStdinDevicePath("/proc/thread-self/fd/0") {
		t.Fatal("isStdinDevicePath misses a device path")
	}
	for _, p := range []string{"", "/dev/stdout", "/dev/fd/1", "/etc/passwd", "x"} {
		if isStdinDevicePath(p) {
			t.Errorf("isStdinDevicePath(%q)=true", p)
		}
	}
	blockCmd := []struct{ name, role, cmd, stdin string }{
		{"pipe-sh-devstdin", "verifier", "echo 'pig' | sh /dev/stdin", ""},
		{"cmd-sh-devfd0", "worker", "sh /dev/fd/0", "pig"},
		{"cmd-sh-dd-devstdin", "worker", "sh -- /dev/stdin", "pig"},
		{"cmd-py-procfd0", "worker", "python3 /proc/self/fd/0", "import os\nos.system('pig')"},
		{"cmd-py-dd-procfd0", "worker", "python3 -- /proc/self/fd/0", "import os\nos.system('pig')"},
		{"pipe-awk-f-devstdin", "worker", "echo 'BEGIN{system(\"pig\")}' | awk -f /dev/stdin", ""},
		{"pipe-awk-file-devstdin", "worker", "echo 'BEGIN{system(\"pig\")}' | awk --file /dev/stdin", ""},
		{"pipe-awk-fileeq-devstdin", "worker", "echo 'BEGIN{system(\"pig\")}' | awk --file=/dev/stdin", ""},
		{"pipe-sed-f-devstdin", "worker", "echo '1e pig' | sed -n -f /dev/stdin /etc/hosts", ""},
		{"pipe-sed-fileeq-devstdin", "worker", "echo '1e pig' | sed --file=/dev/stdin /etc/hosts", ""},
	}
	for _, c := range blockCmd {
		rule, detail := rtCmdRule(c.role, "", c.cmd, c.stdin)
		if rule == "" {
			t.Errorf("%s: got ALLOW, want block", c.name)
		} else {
			t.Logf("%s: BLOCK %s: %s", c.name, rule, detail)
		}
	}
	argvCases := []struct {
		name, role string
		argv       []string
		stdin      string
	}{
		{"argv-sh-devstdin", "verifier", []string{"sh", "/dev/stdin"}, "pig"},
		{"argv-sh-dd-devfd0", "worker", []string{"sh", "--", "/dev/fd/0"}, "pig"},
		{"argv-py-procfd0", "worker", []string{"python3", "/proc/self/fd/0"}, "import os\nos.system('pig')"},
	}
	for _, c := range argvCases {
		rule, detail := rtArgvRule(c.role, "", c.argv, c.stdin)
		if rule == "" {
			t.Errorf("%s: got ALLOW, want block", c.name)
		} else {
			t.Logf("%s: BLOCK %s: %s", c.name, rule, detail)
		}
	}
	allow := []struct{ name, role, cmd, stdin string }{
		{"pipe-sh-file", "verifier", "echo hi | sh ./scripts/x.sh", ""},
		{"awk-f-file", "worker", "awk -f script.awk input.txt", ""},
		{"sed-f-file", "worker", "sed -n -f rules.sed input.txt", ""},
	}
	for _, c := range allow {
		rule, detail := rtCmdRule(c.role, "", c.cmd, c.stdin)
		if rule != "" {
			t.Errorf("%s: got BLOCK %s: %s, want ALLOW", c.name, rule, detail)
		}
	}
}

// A-2: bare `journalctl --lines` (no =) must not pass the read-only
// allowlist; only --lines=N / -n N / -nN do.
func TestRT_A2_JournalctlLinesEqOnly(t *testing.T) {
	for _, cmd := range []string{
		"journalctl --lines --vacuum-size=1",
		"journalctl --lines --rotate",
		"journalctl --lines 50",
	} {
		rule, detail := rtCmdRule("scout", "", cmd, "")
		if rule == "" {
			t.Errorf("%q: got ALLOW, want block", cmd)
		} else {
			t.Logf("%q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	for _, cmd := range []string{
		"journalctl -n 50",
		"journalctl -n50",
		"journalctl --lines=50",
		"journalctl -u x -n 30 --no-pager",
	} {
		rule, detail := rtCmdRule("scout", "", cmd, "")
		if rule != "" {
			t.Errorf("%q: got BLOCK %s: %s, want ALLOW", cmd, rule, detail)
		}
	}
}

// A-3: --sort/--format alone must not mark git tag/branch as list/query:
// with a name operand it is a create; without an operand it stays free.
func TestRT_A3_GitTagSort(t *testing.T) {
	block := []string{
		"git tag --sort refname pwned-tag",
		"git tag --format x pwned-tag",
		"git branch --sort refname newbr",
	}
	for _, cmd := range block {
		rule, detail := rtCmdRule("scout", "", cmd, "")
		if rule == "" {
			t.Errorf("%q: got ALLOW, want block", cmd)
		} else {
			t.Logf("%q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	allow := []string{
		"git tag",
		"git tag -l --sort=refname",
		"git tag --sort=-refname",
		"git tag -n",
		"git tag --contains HEAD",
		"git branch -a --sort=-committerdate",
		"git tag --sort refname",
	}
	for _, cmd := range allow {
		rule, detail := rtCmdRule("scout", "", cmd, "")
		if rule != "" {
			t.Errorf("%q: got BLOCK %s: %s, want ALLOW", cmd, rule, detail)
		}
	}
}

// A-10: sub-agents must not arm the CTXMODE_* identity/audit env hooks.
func TestRT_A10_EnvHookCtxmodeKeys(t *testing.T) {
	block := []struct{ name, role, cmd string }{
		{"db-verifier", "verifier", "CTXMODE_DB=/tmp/x.db ctxmode search q"},
		{"audit-env-worker", "worker", "env CTXMODE_AUDIT_LOG=/dev/null echo ok"},
		{"sbx-env-passthrough", "worker", "sbx --env CTXMODE_ENV_PASSTHROUGH=1 -- echo ok"},
		{"config-worker", "worker", "env CTXMODE_CONFIG=/tmp/c.yaml echo ok"},
	}
	for _, c := range block {
		rule, detail := rtCmdRule(c.role, "", c.cmd, "")
		if rule == "" {
			t.Errorf("%s: got ALLOW, want block", c.name)
		} else {
			t.Logf("%s: BLOCK %s: %s", c.name, rule, detail)
		}
	}
	// Main agent (no role env) stays free.
	os.Unsetenv("CTXMODE_ROLE")
	os.Unsetenv("CTXMODE_READONLY")
	g := currentGuardCall()
	if rule, detail := g.guardCtxRunShell("CTXMODE_DB=/tmp/x.db ctxmode search q"); rule != "" {
		t.Errorf("main agent CTXMODE_DB: got BLOCK %s: %s, want ALLOW", rule, detail)
	}
	// Worker non-hook sbx env stays free.
	rule, detail := rtCmdRule("worker", "", "sbx --env A=1,B=2 -- echo ok", "")
	if rule != "" {
		t.Errorf("sbx --env A=1,B=2: got BLOCK %s: %s, want ALLOW", rule, detail)
	}
}

// A-9 (front half): npx/bunx/pnpx must be screened for -c, -p pkg and a
// blocked executable as the package spec.
func TestRT_A9_NodeRunner(t *testing.T) {
	block := []string{
		"npx -c 'unset CTXMODE_ROLE; pig'",
		"npx -p typescript pig",
		"npx pig@1.0.0",
		"npx pig@latest",
		"bunx hc kill t1",
		"pnpx pig",
	}
	for _, cmd := range block {
		rule, detail := rtCmdRule("worker", "", cmd, "")
		if rule == "" {
			t.Errorf("%q: got ALLOW, want block", cmd)
		} else {
			t.Logf("%q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	allow := []string{
		"npx tsc --noEmit",
		"npx -y -p typescript tsc --noEmit",
		"bunx vitest run",
	}
	for _, cmd := range allow {
		rule, detail := rtCmdRule("worker", "", cmd, "")
		if rule != "" {
			t.Errorf("%q: got BLOCK %s: %s, want ALLOW", cmd, rule, detail)
		}
	}
}

// A-7: dynamic expansions inside wrapper option/argument slots fail
// closed instead of being skipped silently.
func TestRT_A7_WrapperDynamicSlots(t *testing.T) {
	block := []string{
		"timeout $(printf '10 pig') echo ok",
		"d='10 pig'; timeout $d echo ok",
		"nice -n $(printf '5 pig') echo ok",
		"x='p pig'; command -$x echo ok",
		"watch -x -n $(printf '1 pig') echo ok",
		"timeout \"$T\" go test ./...",
	}
	for _, cmd := range block {
		rule, detail := rtCmdRule("worker", "", cmd, "")
		if rule == "" {
			t.Errorf("%q: got ALLOW, want block", cmd)
		} else {
			t.Logf("%q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	allow := []string{
		"timeout 10 go test ./...",
		"nice -n 5 go test",
		"stdbuf -oL grep foo bar",
		"taskset -c 0 go test",
		"env FOO=1 go test",
	}
	for _, cmd := range allow {
		rule, detail := rtCmdRule("worker", "", cmd, "")
		if rule != "" {
			t.Errorf("%q: got BLOCK %s: %s, want ALLOW", cmd, rule, detail)
		}
	}
}

// A-4: hc send blocks dangerous control chars in the text operand and
// dynamic (unquoted or double-quoted) expansions in both operand slots.
func TestRT_A4_HcSendCtrlAndDynamic(t *testing.T) {
	if !hasHcControlChars("\x03x") || !hasHcControlChars("\x1b[A") ||
		!hasHcControlChars("a\rb") || !hasHcControlChars("a\x7f") ||
		!hasHcControlChars("a\x00b") {
		t.Fatal("hasHcControlChars misses a control char")
	}
	for _, s := range []string{"line1\nline2", "a\tb", "中文报告", "done: report ready"} {
		if hasHcControlChars(s) {
			t.Errorf("hasHcControlChars(%q)=true", s)
		}
	}
	blockArgv := [][]string{
		{"hc", "send", "t1", "\x03touch /tmp/x\r"},
		{"hc", "send", "t1", "\x1b[Ahello"},
	}
	for _, argv := range blockArgv {
		rule, detail := rtArgvRule("scout", "", argv, "")
		if rule == "" {
			t.Errorf("%v: got ALLOW, want block", argv)
		} else {
			t.Logf("%v: BLOCK %s: %s", argv, rule, detail)
		}
	}
	blockCmd := []struct{ role, cmd string }{
		{"worker", "x='ok --force'; hc send t42 $x"},
		{"worker", "x='-flag'; hc send t42 \"$x\""},
		{"worker", "hc send t42 \"pre: $x\""},
		{"worker", "hc send t1 \"$(printf hi)\""},
	}
	for _, c := range blockCmd {
		rule, detail := rtCmdRule(c.role, "", c.cmd, "")
		if rule == "" {
			t.Errorf("%q: got ALLOW, want block", c.cmd)
		} else {
			t.Logf("%q: BLOCK %s: %s", c.cmd, rule, detail)
		}
	}
	allow := []struct{ role, cmd string }{
		{"scout", "hc send t1 'line1\nline2'"},
		{"scout", "hc send t42 \"done: report ready\""},
		{"scout", "hc send test hello"},
		{"scout", "hc send t42 ok"},
	}
	for _, c := range allow {
		rule, detail := rtCmdRule(c.role, "", c.cmd, "")
		if rule != "" {
			t.Errorf("%q: got BLOCK %s: %s, want ALLOW", c.cmd, rule, detail)
		}
	}
	argv := []string{"hc", "send", "t1", "line1\nline2\t中文"}
	if rule, detail := rtArgvRule("scout", "", argv, ""); rule != "" {
		t.Errorf("argv multiline: got BLOCK %s: %s, want ALLOW", rule, detail)
	}
}

// R4-C1: C1 control runes (U+0080-U+009F, incl. 0x9B CSI) must also block
// hc send text — decided on the decoded rune so legal multi-byte UTF-8
// (whose continuation bytes land in 0x80-0x9F) keeps passing.
func TestRT_A4_HcSendC1Rune(t *testing.T) {
	if !hasHcControlChars("a\u009bb") { // 0x9B = ANSI CSI
		t.Error("hasHcControlChars misses U+009B (CSI)")
	}
	if !hasHcControlChars("x\u0085y") { // NEL
		t.Error("hasHcControlChars misses U+0085 (NEL)")
	}
	// Multi-byte UTF-8 continuation bytes are >= 0x80 — a byte-level check
	// would reject all of these; the rune-level check must not.
	for _, s := range []string{
		"中文报告", "caf\u00e9", "emoji \U0001f600 ok",
		"nbsp\u00a0here",  // C2 A0 — second byte is 0xA0
		"\u00a1 inverted", // C2 A1
		"line1\nline2\t中文",
	} {
		if hasHcControlChars(s) {
			t.Errorf("hasHcControlChars(%q)=true (rune-level must not misfire)", s)
		}
	}
	argv := []string{"hc", "send", "t5", "a\u009bb"}
	rule, detail := rtArgvRule("scout", "", argv, "")
	if rule == "" {
		t.Errorf("%v: got ALLOW, want block (CSI in send text)", argv)
	} else {
		t.Logf("%v: BLOCK %s: %s", argv, rule, detail)
	}
	// Sanity: a clean multiline send still passes.
	argv = []string{"hc", "send", "t5", "done\n多行 ok"}
	if rule, detail := rtArgvRule("scout", "", argv, ""); rule != "" {
		t.Errorf("%v: got BLOCK %s: %s, want ALLOW", argv, rule, detail)
	}
}

// R4-fd00: zero-padded fd spellings (fd/00, fd/000) reach fd 0 through
// Linux open() — isStdinDevicePath must compare the trailing fd number
// numerically after filepath.Clean, while fd/1 and non-numeric tails
// stay free.
func TestRT_A5_StdinDevicePathPadded(t *testing.T) {
	for _, p := range []string{
		"/proc/self/fd/00", "/proc/self/fd/000",
		"/dev/fd/00", "/dev/fd/0000",
		"/proc/thread-self/fd/000",
		"/dev/fd/./00", "/proc/self/fd/./0",
	} {
		if !isStdinDevicePath(p) {
			t.Errorf("isStdinDevicePath(%q)=false, want true", p)
		}
	}
	for _, p := range []string{
		"/dev/fd/1", "/proc/self/fd/1", "/dev/fd/x",
		"/proc/self/fd/0/extra", "/dev/fd0", "/dev/fd",
	} {
		if isStdinDevicePath(p) {
			t.Errorf("isStdinDevicePath(%q)=true, want false", p)
		}
	}
	// End-to-end argv: padded spellings must hit the same stdin block.
	argvBlock := [][]string{
		{"python3", "/proc/self/fd/00"},
		{"sh", "/dev/fd/00"},
		{"python3", "/proc/thread-self/fd/000"},
	}
	for _, argv := range argvBlock {
		rule, detail := rtArgvRule("worker", "", argv, "import os\nos.system('pig')")
		if rule == "" {
			t.Errorf("%v: got ALLOW, want block (fd 0 via padded spelling)", argv)
		} else {
			t.Logf("%v: BLOCK %s: %s", argv, rule, detail)
		}
	}
	// fd/1 is not stdin: a python3 script arg of /proc/self/fd/1 must not
	// be treated as a stdin program source (it may still block for other
	// reasons — the unit check above is the precise assertion).
}

// R4-npm-prefix: npm/pnpm/yarn `exec`/`dlx` reach the same unvetted-code
// surface as npx/bunx/pnpx — the sub-agent layer must re-dispatch the
// exec operand through screenNestedDispatch. A value-taking option before
// the verb (`npm --prefix /tmp exec pig`) must not hide it behind the
// option's operand word; npmFamilyExecArgs skips option VALUES.
func TestRT_A9_NpmExecBehindValueFlag(t *testing.T) {
	block := []string{
		"npm --prefix /tmp exec pig",
		"npm --prefix=/tmp exec pig",
		"pnpm --dir /tmp dlx pig",
		"pnpm -C /tmp exec pig",
		"yarn --cwd /tmp dlx pig",
		"npm -y exec pig",
		"npm --workspace pkg exec pig",
		"npm --registry https://x exec pig",
		"npm exec pig", "pnpm dlx pig", "npm exec -- pig",
	}
	for _, cmd := range block {
		rule, detail := rtCmdRule("worker", "", cmd, "")
		if rule != ruleSubagentNestedAgent {
			t.Errorf("%q: got (%q,%q), want %s", cmd, rule, detail, ruleSubagentNestedAgent)
		} else {
			t.Logf("%q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	// Ordinary npm use for a worker sub-agent stays free — npm install/run
	// are write commands inside the worker's mandate, and a non-blocked
	// exec spec (tsc/vitest) is no different from `npx tsc`.
	allow := []string{
		"npm install", "npm run build", "pnpm -C /tmp install",
		"npm --version", "npm view typescript",
		"npm --prefix /tmp view typescript", "pnpm --dir /tmp list",
		"npm exec tsc", "pnpm dlx vitest", "npm --prefix /tmp exec tsc",
	}
	for _, cmd := range allow {
		if rule, detail := rtCmdRule("worker", "", cmd, ""); rule != "" {
			t.Errorf("%q: got BLOCK %s: %s, want ALLOW", cmd, rule, detail)
		}
	}
	// The readonly write-table twin path also stops hiding exec/dlx
	// behind a value flag (defence in depth; npm already fails the
	// readonly allowlist, so this is the subagent layer that mattered).
}

// R5-npm-call: `npm exec -c CMD`/`--call CMD`/`--call=CMD` run a raw
// command string through a shell — the same unvettable payload
// `npx -c`/`--call` already fails closed on. The glued `--call=pig`
// spelling previously landed in the `--flag=value` drop rule and let
// `npm exec --call=pig` sail past the exec-head screen entirely. And the
// exec/dlx verb must be the FIRST non-flag operand (the real npm
// subcommand): `npm view exec pig`'s `exec` is a `view` field name, not
// the exec verb — scanning every operand misread it and blocked a legal
// metadata query.
func TestRT_A9_NpmExecCallAndViewField(t *testing.T) {
	block := []string{
		"npm exec --call=pig",
		"npm exec -c pig",
		"npm exec --call=pig tsc",
		"npm exec --call pig",
		"npm exec -cpig",
		"pnpm dlx --call=pig",
		"yarn dlx -c pig",
		"npm --prefix /tmp exec --call=pig",
	}
	for _, cmd := range block {
		rule, detail := rtCmdRule("worker", "", cmd, "")
		if rule != ruleSubagentNestedAgent {
			t.Errorf("%q: got (%q,%q), want %s", cmd, rule, detail, ruleSubagentNestedAgent)
		} else {
			t.Logf("%q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	allow := []string{
		"npm exec tsc",
		"npm exec -- tsc",
		"npm view exec pig",         // `exec` is a `view` field name
		"npm view exec bin.version", // field lookups stay free
	}
	for _, cmd := range allow {
		if rule, detail := rtCmdRule("worker", "", cmd, ""); rule != "" {
			t.Errorf("%q: got BLOCK %s: %s, want ALLOW", cmd, rule, detail)
		}
	}
}

// A-1: ssh remote stdin vehicle is narrowed to pure shells; read-only
// callers lose piped ssh exfiltration and StrictHostKeyChecking without
// UserKnownHostsFile=/dev/null.
func TestRT_A1_SSHTightening(t *testing.T) {
	block := []struct{ name, role, cmd string }{
		{"scout-node-heredoc", "scout", "ssh dmit 'node -' <<'EOF'\nconst cp = require('child_process');\ncp['exec' + 'Sync']('rm -rf /tmp/x && pig');\nEOF"},
		{"scout-py-heredoc-open-rebind", "scout", "ssh dmit 'python3 -' <<'EOF'\nf = open\nf('/tmp/x', 'w').write('pwn')\nEOF"},
		{"scout-pipe-ssh", "scout", "cat /tmp/f | ssh u@h true"},
		{"scout-accept-new-noukh", "scout", "ssh -o StrictHostKeyChecking=accept-new u@h true"},
		{"scout-shkc-no-noukh", "scout", "ssh -o 'StrictHostKeyChecking no' u@h uptime"},
		{"scout-shkc-space-noukh", "scout", "ssh -o 'StrictHostKeyChecking no' u@h uptime"},
	}
	for _, c := range block {
		rule, detail := rtCmdRule(c.role, "", c.cmd, "")
		if rule == "" {
			t.Errorf("%s: got ALLOW, want block", c.name)
		} else {
			t.Logf("%s: BLOCK %s: %s", c.name, rule, detail)
		}
	}
	// StrictHostKeyChecking=accept-new with UKH=/dev/null still blocks
	// for verifier — the baseline already refused remote commands for
	// read-only roles on the remote-write screen, so the sink spelling
	// stays on that baseline (the new wall only adds the no-sink hit).
	if rule, detail := rtCmdRule("verifier", "", "ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null u@h uptime", ""); rule == "" {
		t.Error("verifier ssh UKH-sink: got ALLOW, want baseline remote-write block")
	} else {
		t.Logf("verifier ssh UKH-sink: BLOCK %s: %s", rule, detail)
	}
	// strictReadonly caller (worker + CTXMODE_READONLY=1): same ssh walls
	// as the read-only roles.
	for _, cmd := range []string{
		"cat /tmp/f | ssh u@h true",
		"ssh -o StrictHostKeyChecking=accept-new u@h uptime",
	} {
		rule, detail := rtCmdRule("worker", "1", cmd, "")
		if rule == "" {
			t.Errorf("strict ro %q: got ALLOW, want block", cmd)
		} else {
			t.Logf("strict ro %q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	// Worker guardCtxRunCode: computed member access child_process spawn.
	rule, detail := rtCodeRule("worker", "", "javascript",
		"const cp = require('child_process');\ncp['exec' + 'Sync']('pig');")
	if rule == "" {
		t.Error("worker js cp['exec'+'Sync']: got ALLOW, want block")
	} else {
		t.Logf("worker js spawn: BLOCK %s: %s", rule, detail)
	}
	// Worker ssh is unaffected by the read-only tightening. (Read-only
	// roles incl. verifier already lose remote commands to the baseline
	// remote-write screen — assert that baseline below, not here.)
	allow := []struct{ name, role, cmd string }{
		{"worker-ssh-shkc", "worker", "ssh -oBatchMode=yes -o 'StrictHostKeyChecking no' dmit uptime"},
		{"worker-ssh-sh-heredoc", "worker", "ssh dmit sh <<'EOF'\nuptime\nEOF"},
		{"worker-ssh-uptime", "worker", "ssh dmit uptime"},
	}
	for _, c := range allow {
		rule, detail := rtCmdRule(c.role, "", c.cmd, "")
		if rule != "" {
			t.Errorf("%s: got BLOCK %s: %s, want ALLOW", c.name, rule, detail)
		}
	}
	// Baseline behaviour unchanged: scout remote commands still hit the
	// remote-write screen (ssh remote write); a UKH=/dev/null pairing
	// must not make it worse — it still blocks on the remote command,
	// not on the known_hosts check itself.
	for _, cmd := range []string{
		"ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null u@h uptime",
		"ssh dmit uptime",
	} {
		rule, detail := rtCmdRule("scout", "", cmd, "")
		if rule == "" {
			t.Errorf("scout %q: got ALLOW, want baseline remote-write block", cmd)
		} else {
			t.Logf("scout %q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	// Verifier: piped stdin and SHKC-without-sink block; a benign remote
	// command stays allowed.
	for _, cmd := range []string{
		"cat /tmp/f | ssh u@h true",
		"ssh -o StrictHostKeyChecking=accept-new u@h uptime",
		"ssh -o 'StrictHostKeyChecking no' u@h uptime",
	} {
		rule, detail := rtCmdRule("verifier", "", cmd, "")
		if rule == "" {
			t.Errorf("verifier %q: got ALLOW, want block", cmd)
		} else {
			t.Logf("verifier %q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
}

// A-11: retired herdr/herdsman heads are fully blocked for sub-agents.
func TestRT_A11_HerdrHerdsmanRetired(t *testing.T) {
	blockArgv := [][]string{
		{"herdr", "pane", "read", "t1"},
		{"herdsman"},
		{"herdsman", "agent", "list"},
		{"herdr", "pane", "list"},
		{"herdr", "-V", "--remote=u@h", "pane", "run", "pig"},
	}
	for _, argv := range blockArgv {
		rule, detail := rtArgvRule("worker", "", argv, "")
		if rule != ruleSubagentNestedAgent {
			t.Errorf("%v: got (%q,%q), want %s", argv, rule, detail, ruleSubagentNestedAgent)
		}
	}
	allowArgv := [][]string{
		{"hc", "send", "t42", "ok"},
		{"hc", "--help"},
		{"hc", "send", "--help"},
		{"herdr-core", "send", "t42", "ok"},
	}
	for _, argv := range allowArgv {
		rule, detail := rtArgvRule("worker", "", argv, "")
		if rule != "" {
			t.Errorf("%v: got BLOCK %s: %s, want ALLOW", argv, rule, detail)
		}
	}
}

// A-8: wrapper-named symlinks get re-peeled (myenv -> env), cross-family
// structural aliases block (python3 -> dash), and GNU 'g' prefixed real
// binaries (genv/gfind) still screen as their canonical tool.
func TestRT_A8_AliasFamilyAndGnuPrefix(t *testing.T) {
	home := withTestTrustedHome(t)
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	link := func(name, target string) {
		os.Remove(filepath.Join(bin, name))
		if err := os.Symlink(target, filepath.Join(bin, name)); err != nil {
			t.Skipf("symlink %s -> %s: %v", name, target, err)
		}
	}
	prepend := `PATH="$HOME/.local/bin:$PATH" `

	block := []struct {
		name, cmd string
		prep      func()
	}{
		{"myenv", prepend + "myenv -u CTXMODE_ROLE pig", func() { link("myenv", "/usr/bin/env") }},
		{"mytimeout", prepend + "mytimeout 5 pig", func() { link("mytimeout", "/usr/bin/timeout") }},
		{"python3-to-dash", prepend + "python3 -c 'pig'", func() { link("python3", "/bin/dash") }},
	}
	for _, c := range block {
		c.prep()
		rule, detail := rtCmdRule("worker", "", c.cmd, "")
		if rule == "" {
			t.Errorf("%s: got ALLOW, want block", c.name)
		} else {
			t.Logf("%s: BLOCK %s: %s", c.name, rule, detail)
		}
	}
	// Same-family aliases keep their typed base: sh -> dash, python3 ->
	// python3.x are legal and must not trip the conflict check.
	link("sh", "/bin/dash")
	rule, detail := rtCmdRule("worker", "", "sh -c 'echo hi'", "")
	_ = detail
	if rule == "subagent_nested_agent" && strings.Contains(detail, "conflicting structural alias") {
		t.Errorf("sh->dash same-family alias blocked: %s: %s", rule, detail)
	}
	// genv / gfind as real files are recognised as the GNU tool.
	if data, err := os.ReadFile("/usr/bin/env"); err == nil {
		p := filepath.Join(bin, "genv")
		if err := os.WriteFile(p, data, 0755); err == nil {
			rule, detail := rtCmdRule("worker", "", prepend+"genv -u CTXMODE_ROLE pig", "")
			if rule == "" {
				t.Error("genv -u CTXMODE_ROLE pig: got ALLOW, want block")
			} else {
				t.Logf("genv: BLOCK %s: %s", rule, detail)
			}
		}
	}
	if data, err := os.ReadFile("/usr/bin/find"); err == nil {
		p := filepath.Join(bin, "gfind")
		if err := os.WriteFile(p, data, 0755); err == nil {
			rule, detail := rtCmdRule("worker", "", prepend+"gfind . -exec pig ';'", "")
			if rule == "" {
				t.Error("gfind . -exec pig: got ALLOW, want block")
			} else {
				t.Logf("gfind: BLOCK %s: %s", rule, detail)
			}
		}
	}
	// scout: gps/ghc are unknown commands, not g-stripped ps/hc.
	for _, cmd := range []string{"gps 198.51.100.1:2947", "ghc send t1 hi"} {
		rule, detail := rtCmdRule("scout", "", cmd, "")
		if rule == "" {
			t.Errorf("%q: got ALLOW, want block", cmd)
		} else {
			t.Logf("%q: BLOCK %s: %s", cmd, rule, detail)
		}
	}
	// Must-allow: sh and python3 used normally under Debian-style aliases.
	for _, c := range []struct{ name, role, cmd string }{
		{"worker-sh-heredoc", "worker", "sh <<'EOF'\necho hi\nEOF"},
		{"worker-python-heredoc", "worker", "python3 - <<'EOF'\nprint(1)\nEOF"},
		{"worker-ssh-sh-heredoc", "worker", "ssh dmit sh <<'EOF'\nuptime\nEOF"},
		{"worker-py-stdin", "worker", "python3 -"},
	} {
		rule, detail := rtCmdRule(c.role, "", c.cmd, "print(1)")
		if rule != "" {
			t.Errorf("%s: got BLOCK %s: %s, want ALLOW", c.name, rule, detail)
		}
	}
}
