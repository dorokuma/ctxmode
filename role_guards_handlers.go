package main

// role_guards_handlers.go — guardCall MCP/CLI handler entry points and stdin target extractors.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ---------- entry points used by the handlers ----------

// guardCall is the per-role view computed once per tool call.
type guardCall struct {
	subagent       bool
	readonly       bool
	strictReadonly bool
	// cwd is the resolved ctx_run cwd of the call under screening, pinned
	// by the entry point before any guard runs. "" reproduces the former
	// screenCwd=="" semantics: resolution falls back to the process
	// working directory (unit tests and unguarded call sites).
	cwd string
}

func currentGuardCall() guardCall {
	ro := auditCallerIsReadonly()
	return guardCall{
		subagent:       auditCallerIsSubagent(),
		readonly:       ro,
		strictReadonly: auditCallerIsStrictReadonly(),
	}
}

// guardCtxRunArgv screens one argv for both guards (sub-agent first, then
// strict read-only). rule is the audit screen_rule; detail names the matched
// head for the caller-facing error.
func (g guardCall) guardCtxRunArgv(argv []string) (rule, detail string) {
	if !g.subagent && !g.strictReadonly {
		return "", "" // main agent: no role guard runs at all
	}
	caller := g.callerIdentity()
	if g.subagent {
		if hit := peelResolvedDepth(argv, 's', 0, caller); hit != "" {
			if hit == "ctxmode index" || hit == roSSHWriteHit {
				return ruleReadonlyWrite, hit
			}
			return ruleSubagentNestedAgent, hit
		}
	}
	if g.strictReadonly {
		if hit := g.guardArgvReadonly(argv); hit != "" {
			return ruleReadonlyWrite, hit
		}
	}
	return "", ""
}

// guardCtxRunShell screens one shell command string for both guards.
func (g guardCall) guardCtxRunShell(code string) (rule, detail string) {
	return g.guardCtxRunShellEnv(code, envAssignments{})
}

// guardCtxRunShellEnv is guardCtxRunShell under the env ops peeled off the
// calling argv (R13): `argv=["env","HOME=-exec","sh"]`+stdin must screen
// the stdin program text with HOME already tainted — a `$HOME` inside the
// payload is then a dynamic placeholder, never the trusted abs-dir grant.
func (g guardCall) guardCtxRunShellEnv(code string, envAs envAssignments) (rule, detail string) {
	if !g.subagent && !g.strictReadonly {
		return "", "" // main agent: never enters the sub-agent parser
	}
	caller := g.callerIdentity().seededWith(envAs)
	if g.subagent {
		if hit := guardShellSubagentDepth(code, 0, caller); hit != "" {
			if hit == "ctxmode index" || hit == roSSHWriteHit {
				return ruleReadonlyWrite, hit
			}
			return ruleSubagentNestedAgent, hit
		}
	}
	if g.strictReadonly {
		if hit := guardShellReadonlyDepth(code, 0, caller); hit != "" {
			return ruleReadonlyWrite, hit
		}
	}
	return "", ""
}

// stdinProgramHead reports whether a peeled argv head reads its program
// from stdin: a shell with no -c payload (unwrapShellArgv already checked)
// or a scripting interpreter with no inline-code flag. Returns (lang, true)
// where lang is "" for a shell head or the guardCtxRunCode language.
// An ssh head resolves through its option run (parseSSHInvocation) to the
// remote command, whose own heads inherit the verdict: `argv=["ssh","dmit",
// "sh"]` forwards the caller's stdin to a remote shell reading its PROGRAM
// from that stream, so the stdin payload is remote code, not data.

// hasDynamicInterpOption reports a dynamic word in the shell/interpreter
// option zone (before -- or the first static script operand).
func hasDynamicInterpOption(head []string, base string) bool {
	if len(head) < 2 {
		return false
	}
	shell := shellHeads[base]
	_, interp := heredocInterpLang(base)
	if !shell && !interp {
		return false
	}
	valueExact := map[string]bool{
		"-o": true, "+o": true, "-O": true, "+O": true,
		"-W": true, "-X": true, "-r": true, "--require": true,
		"--loader": true, "--import": true, "--experimental-loader": true,
		"--conditions": true, "-I": true, "-M": true, "-m": true,
		"-d": true, "-z": true, "--rcfile": true, "--init-file": true,
		// Code-carrying flags: still consume the next argv so a following
		// dynamic -e is not mistaken for the script file (MF-2 multi -e).
		"-c": true, "+c": true, "-e": true, "-E": true, "-p": true,
		"--eval": true, "--print": true,
	}
	codeFlags := map[string]bool{
		"-c": true, "+c": true, "-e": true, "-E": true, "-p": true,
		"--eval": true, "--print": true, "-r": true,
	}
	for i := 1; i < len(head); i++ {
		a := head[i]
		if a == "--" {
			return false
		}
		// "-" means stdin script source; remaining args are script argv (W-Fix-6).
		if a == "-" {
			return false
		}
		if isDynamicArg(a) {
			// Shell option zone: any dynamic word may expand to -c/-s etc.
			if shell {
				return true
			}
			// Interpreters: a split-safe word that is path-shaped (absolute,
			// glob-with-safe-start containing '/', abs-dq placeholder) ends
			// the option zone as the script-file operand (MF-2/Q1-C). A
			// word-start __ctx_dq_sub__ may begin with '-' at runtime and is
			// NOT a safe script operand.
			if isSafeDynamicDataOperand(a) &&
				(strings.Contains(a, "/") || strings.HasPrefix(a, "/") ||
					strings.HasPrefix(a, cmdSubPlaceholderAbsDq) || hasInterpScriptExt(a)) {
				return false
			}
			return true
		}
		if valueExact[a] {
			if i+1 < len(head) && isDynamicArg(head[i+1]) && !codeFlags[a] {
				return true
			}
			i++ // consume value / code slot
			continue
		}
		if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
			continue
		}
		// first static non-option operand = script file → option zone ends
		return false
	}
	return false
}

func hasInterpScriptExt(a string) bool {
	lower := strings.ToLower(a)
	for _, ext := range []string{".js", ".ts", ".mjs", ".cjs", ".py", ".pl", ".rb", ".php"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// stdinProgramHeadCwd is stdinProgramHead with the screening call's
// resolution base pinned: callers that already hold a callerIdentity pass
// its cwd so relative heads inside the argv resolve against the call's
// directory, not the process cwd the zero caller would fall back to.
func stdinProgramHeadCwd(argv []string, cwd string) (lang string, isInterp bool) {
	lang, isProg, _ := stdinProgramHeadWithEnv(argv, 0, envAssignments{}, os.Getenv("PATH"), callerIdentity{cwd: cwd})
	return lang, isProg
}

// stdinProgramHeadWithEnv is stdinProgramHeadDepth carrying the env ops
// accumulated above this recursion level: a peeled `PATH=...` prefix (or an
// `env PATH=...` op) rewires name resolution for every wrapper the
// command nests into, so `echo pig | PATH=dir foo -- sh` (dir/foo -> sh)
// resolves the alias under the peeled PATH instead of the process PATH.
// The ssh remote-command branch drops it — remote heads resolve under the
// remote login env, so only the remote ops feed their PATH replay.
// basePath seeds the PATH the accumulated env ops replay over (the
// caller's effective PATH — its own process PATH at depth 0): a peeled
// `PATH=$PATH:<dir>` prefix then expands $PATH like the runtime instead
// of collapsing to `:<dir>`.
func stdinProgramHeadWithEnv(argv []string, depth int, inherited envAssignments, basePath string, caller callerIdentity) (lang string, isInterp bool, envAs envAssignments) {
	targets := stdinProgramTargetsWithEnv(argv, depth, inherited, basePath, caller)
	if len(targets) == 0 {
		return "", false, inherited
	}
	return targets[0].lang, true, targets[0].envAs
}

// peelToSSHHead peels both standard wrappers and statement-level stdin
// wrappers (flock, watch -x, xargs) to reach an underlying ssh argv.
// pathEnv is the effective PATH the peeled head resolves against: the
// env ops peeled at each layer replay over it so PATH-injected aliases
// (ssx -> ssh) resolve like the runtime would.
func peelToSSHHead(argv []string, pathEnv string, caller callerIdentity) []string {
	cur := argv
	effPath := pathEnv
	for depth := 0; depth < peelWrapperMaxSteps && len(cur) > 0; depth++ {
		head, _, ea, exhausted := peelWrappers(cur)
		effPath = ea.effectivePATHFrom(effPath)
		caller = caller.seededCwdWith(ea)
		if exhausted || len(head) == 0 {
			return nil
		}
		base := filepath.Base(head[0])
		// A PATH alias resolving to a wrapper (myenv -> env, mytimeout ->
		// timeout) skipped the option peel because peelWrappers saw only
		// the typed name — rewrite the head to the resolved wrapper and
		// loop so its own options are peeled like a directly typed
		// invocation.
		if rb := canonicalResolvedBase(resolveHeadBase(head[0], effPath, caller.screenCwd())); rb != "" && rb != base && isPeeledWrapperBase(rb) {
			cur = append([]string{rb}, head[1:]...)
			continue
		}
		if base == "ssh" || resolveHeadBase(head[0], effPath, caller.screenCwd()) == "ssh" {
			return head
		}
		switch base {
		case "flock":
			inner, cmdText := skipFlockArgs(head, 1)
			if cmdText != "" || inner >= len(head) {
				return nil
			}
			cur = head[inner:]
		case "watch":
			k, execMode, fc := skipWatchArgs(head, 1)
			if fc || !execMode || k >= len(head) {
				return nil
			}
			cur = head[k:]
		case "xargs":
			k := xargsTargetIndex(head)
			if k < 0 || k >= len(head) {
				return nil
			}
			cur = head[k:]
		default:
			return nil
		}
	}
	return nil
}
func sshTunnelsStdinProgram(argv []string, pathEnv string, caller callerIdentity) bool {
	head := peelToSSHHead(argv, pathEnv, caller)
	if len(head) == 0 {
		return false
	}
	remoteCmd, hit := parseSSHInvocation(head)
	if hit != "" {
		return false
	}
	return remoteReadsProgramFromStdinCwd(remoteCmd, caller.screenCwd())
}

// guardCtxRunStdin screens a ctx_run stdin payload when the argv's resolved
// head is a shell or interpreter that reads its program from stdin
// (`argv=["sh"]`, `argv=["python3","-"]`, etc.). Inline-code spellings
// (`sh -c`, `python3 -c`, `node -e`, `perl -e`, `php -r`, `python -m`) mean
// stdin is data, not the program, and are not screened here. An ssh head
// whose REMOTE command reads its program from stdin
// (`argv=["ssh","dmit","sh"]`) counts too — ssh forwards the stream — and
// additionally upgrades a read-only-but-not-strict caller to the strict
// screen since the bytes leave this host.
func (g guardCall) guardCtxRunStdin(argv []string, stdin string) (rule, detail string) {
	if stdin == "" || (!g.subagent && !g.strictReadonly) {
		return "", ""
	}
	caller := g.callerIdentity()
	targets := stdinProgramTargetsWithEnv(argv, 0, envAssignments{}, os.Getenv("PATH"), caller)
	if len(targets) == 0 {
		return "", ""
	}
	for _, t := range targets {
		gSeg := g
		if gSeg.readonly && !gSeg.strictReadonly &&
			(t.remote || sshTunnelsStdinProgram(argv, os.Getenv("PATH"), caller)) {
			// The stream leaves this host (ssh forwards it): a
			// read-only-but-not-strict caller faces the strict screen.
			gSeg.strictReadonly = true
		}
		if t.lang == "" {
			if r, d := gSeg.guardCtxRunShellEnv(stdin, t.envAs); r != "" {
				return r, d
			}
			continue
		}
		if r, d := gSeg.guardCtxRunCode(t.lang, stdin); r != "" {
			return r, d
		}
	}
	return "", ""
}

// guardCtxRunStdinForCommand is the command-string variant of
// guardCtxRunStdin: it splits the command into segments and checks each
// peeled head for a shell/interpreter reading stdin — including a head
// reached through an ssh remote command.
func (g guardCall) guardCtxRunStdinForCommand(command, stdin string) (rule, detail string) {
	if stdin == "" || (!g.subagent && !g.strictReadonly) {
		return "", ""
	}
	caller := g.callerIdentity()
	for _, seg := range splitShellSegmentsCaller(command, caller.envTaint, caller) {
		if seg.depthExceeded || seg.parseErr != "" {
			detail := seg.parseErr
			if seg.depthExceeded {
				detail = depthExceededHit
			}
			if g.strictReadonly {
				return ruleReadonlyWrite, detail
			}
			if g.subagent {
				return ruleSubagentNestedAgent, detail
			}
			return "", ""
		}
		if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
			continue
		}
		targets := stdinProgramTargetsWithEnv(seg.argv, 0, envAssignments{}, os.Getenv("PATH"), caller)
		if len(targets) == 0 {
			continue
		}
		for _, t := range targets {
			gSeg := g
			if gSeg.readonly && !gSeg.strictReadonly &&
				(t.remote || sshTunnelsStdinProgram(seg.argv, os.Getenv("PATH"), caller)) {
				gSeg.strictReadonly = true
			}
			if t.lang == "" {
				if r, d := gSeg.guardCtxRunShellEnv(stdin, t.envAs); r != "" {
					return r, d
				}
				continue
			}
			if r, d := gSeg.guardCtxRunCode(t.lang, stdin); r != "" {
				return r, d
			}
		}
	}
	return "", ""
}

// guardCtxRunEnv screens caller-supplied env overrides (ctx_run env args):
// a sub-agent or strict read-only caller may not arm an execution-hook
// variable (GIT_PAGER=/tmp/x, NODE_OPTIONS=--inspect, PYTHONSTARTUP=...)
// through args.Env either — the variable reaches the child process
// exactly like an env KEY=VAL prefix would. Values are never reported.
func (g guardCall) guardCtxRunEnv(env map[string]string) (rule, detail string) {
	if !g.subagent && !g.strictReadonly {
		return "", ""
	}
	if g.strictReadonly {
		for k := range env {
			switch k {
			case "LANG", "LC_ALL", "TZ":
				continue
			default:
				return ruleReadonlyWrite, "env " + k
			}
		}
		return "", ""
	}
	for k, v := range env {
		if !isEnvHookVar(k) {
			continue
		}
		if pagerSafeVars[k] && (v == "" || v == "cat") {
			continue
		}
		if g.subagent {
			return ruleSubagentNestedAgent, "env " + k
		}
		return ruleReadonlyWrite, "env " + k
	}
	return "", ""
}

// guardBlockedError renders the caller-facing error for a blocked call. The
// wording names the rule and the matched head so an operator can pair the
// error with the audit record's screen_rule mechanically.
func guardBlockedError(rule, detail string) error {
	if rule == ruleReadonlyWrite {
		detail = readonlyBlockWithHint(detail)
	}
	return fmt.Errorf("blocked by role guard (%s): %s", rule, detail)
}

// reportDeliveryHintText is the self-heal guidance appended when a role
// guard blocks a dispatch-report invocation.
const reportDeliveryHintText = "Report delivery hint: call the ctx_report MCP tool (content=\"<report>\"); dispatch-report is not callable via ctx_run"

// blockedReportError returns err unchanged unless it is a role-guard block
// AND the screened invocation names dispatch-report as a command head — in
// which case the report-delivery hint is appended so a dispatched role
// recovers with the right spelling instead of retrying the forbidden form.
//
// argv invocations match on filepath.Base(argv[0]) — a bare name or any
// path spelling (which the guards block as "path command"). Shell command
// strings match only when dispatch-report is the FIRST WORD of a `;`, `&&`,
// `||`, `|` or newline separated segment (or of the whole string), so a
// mid-token mention — `rg dispatch-report .`, `echo dispatch-report x`,
// `python3 -c 'import dispatch_report'` — can never mis-hint a blocked call
// into a report retry. A non-shell `code` spawn (`subprocess.run([...
// "dispatch-report" ...])`) is unreachable by that shell lexer, so the
// rendered guard error's ruleSubagentNestedAgent detail is consulted
// instead: an exact `dispatch-report` detail, or any detail whose final
// word is `dispatch-report` (`code spawns dispatch-report`,
// `code statement head invokes dispatch-report`, `npm exec dispatch-report`,
// `npx dispatch-report`, `awk dynamic cmd dispatch-report`-style hits), earns the hint —
// while the `untrusted path binary <head>`/`planted shadow binary`
// prefixes keep their own diagnosis and never append it (a crafted
// `foo: dispatch-report` basename is a path-trust verdict, not a report
// delivery attempt).
func blockedReportError(err error, argv []string, command string) error {
	if err == nil || !strings.Contains(err.Error(), "blocked by role guard") {
		return err
	}
	if strings.Contains(err.Error(), reportDeliveryHintText) {
		return err
	}
	if len(argv) > 0 && filepath.Base(argv[0]) == "dispatch-report" {
		return fmt.Errorf("%w %s", err, reportDeliveryHintText)
	}
	if command != "" && shellCommandHeadIsReport(command) {
		return fmt.Errorf("%w %s", err, reportDeliveryHintText)
	}
	const nestedPrefix = "blocked by role guard (" + ruleSubagentNestedAgent + "): "
	if msg := err.Error(); strings.HasPrefix(msg, nestedPrefix) {
		detail := strings.TrimPrefix(msg, nestedPrefix)
		if isReportGuardDetail(detail) {
			return fmt.Errorf("%w %s", err, reportDeliveryHintText)
		}
	}
	return err
}

// isReportGuardDetail reports whether a ruleSubagentNestedAgent detail
// names dispatch-report as the intercepted command: an exact
// `dispatch-report` detail or a ` dispatch-report` final word (`code
// spawns dispatch-report`, `code statement head invokes dispatch-report`,
// `npm exec dispatch-report`, `npx dispatch-report`, `awk dynamic cmd
// dispatch-report`). The `untrusted path binary <head>`/`planted shadow
// binary` prefixes keep their own path-trust diagnosis — a crafted
// `foo: dispatch-report` basename is not a report delivery attempt.
func isReportGuardDetail(detail string) bool {
	return detail == "dispatch-report" ||
		(!strings.HasPrefix(detail, "untrusted path binary ") &&
			!strings.HasPrefix(detail, "planted shadow binary ") &&
			strings.HasSuffix(detail, " dispatch-report"))
}

// shellCommandHeadIsReport reports whether any parsed command segment of
// code starts with a dispatch-report word (bare or path spelling). The
// sub-agent AST splitter (splitShellSegments) owns every `;`/`&&`/`||`/`|`
// /newline boundary plus quoting and heredoc handling, so a mention inside
// an argument (`rg dispatch-report .`), a quoted string or an env
// assignment value can never be mistaken for the command head.
func shellCommandHeadIsReport(code string) bool {
	for _, seg := range splitShellSegments(code) {
		if len(seg.argv) == 0 {
			continue
		}
		if filepath.Base(seg.argv[0]) == "dispatch-report" {
			return true
		}
	}
	return false
}

// minInt is a tiny local helper (avoid pulling in math for two ints).
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func optNumValueOK(s string) bool {
	if s == "all" {
		return true
	}
	return allDigits(strings.TrimPrefix(s, "+"))
}

// isTrustedRelToolchainTarget allows a symlink from a relative toolchain PATH
// segment (node_modules/.bin, .venv/bin) to resolve into an ancestor monorepo's
// hoisted node_modules/.venv/venv tree (e.g. packages/app -> ../../node_modules/...)
// or a sibling worktree under trustedHomeDirs(), while rejecting all scratch
// roots (/tmp, /var/tmp, /dev/shm, /run) and foreign-owned binaries.
func isTrustedRelToolchainTarget(resolved, realCwd string, euid int) bool {
	if isTmpOrScratchPath(resolved) {
		return false
	}
	st, err := os.Stat(resolved)
	if err != nil || st.IsDir() {
		return false
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if sys.Uid != 0 && int(sys.Uid) != euid {
			return false
		}
	}
	if realCwd != "" && !isTmpOrScratchPath(realCwd) {
		for anc := filepath.Dir(realCwd); anc != "/" && anc != "."; {
			if isTmpOrScratchPath(anc) || anc == "/home" || anc == "/Users" {
				break
			}
			for _, sub := range []string{"/node_modules/", "/.venv/", "/venv/"} {
				if strings.HasPrefix(resolved, anc+sub) {
					return true
				}
			}
			next := filepath.Dir(anc)
			if next == anc {
				break
			}
			anc = next
		}
	}
	resDir := filepath.Clean(filepath.Dir(resolved))
	if tail, ok := stripTrustedHomePrefix(resDir); ok {
		for _, sub := range []string{"/node_modules/", "/.venv/", "/venv/"} {
			if strings.Contains(tail+"/", sub) && isTrustedExecutableOnDiskCwd(resolved, euid, realCwd) {
				return true
			}
		}
	}
	return false
}

func pythonHasBareOpenIdent(masked string) bool {
	for off := 0; ; {
		pos := indexIdent(masked, "open", off)
		if pos < 0 {
			return false
		}
		off = pos + len("open")
		if openParenAfter(masked, off) >= 0 {
			continue
		}
		// Exempt keyword-argument label `fn(..., open=...)`; keep bare `open`
		// and `.open` (e.g. `f = io.open`) blocked against rebind escapes.
		prev := pos - 1
		for prev >= 0 && (masked[prev] == ' ' || masked[prev] == '\t' || masked[prev] == '\n') {
			prev--
		}
		next := off
		for next < len(masked) && (masked[next] == ' ' || masked[next] == '\t') {
			next++
		}
		if prev >= 0 && (masked[prev] == '(' || masked[prev] == ',') &&
			next < len(masked) && masked[next] == '=' &&
			(next+1 >= len(masked) || masked[next+1] != '=') {
			continue
		}
		return true
	}
}

type stdinTarget struct {
	lang  string
	envAs envAssignments
	// remote marks a target whose stdin program runs on a REMOTE host: it
	// is minted only by the ssh branch below (an ssh remote command that
	// itself reads a program from stdin) and rides collectSegs up through
	// any `bash -c 'ssh host sh'` unwrap that peelToSSHHead cannot reach.
	// Remote bytes must NEVER be rewritten into a local
	// `<selfExe> --hc-gate` call, and a read-only-but-not-strict caller
	// screening them escalates to the strict rules.
	remote bool
}

func stdinProgramTargetsWithEnv(argv []string, depth int, inherited envAssignments, basePath string, caller callerIdentity) []stdinTarget {
	if len(argv) == 0 || depth >= shellSplitMaxDepth {
		return nil
	}
	head, _, ea, exhausted := peelWrappers(argv)
	envAs := inherited.merged(ea)
	if exhausted {
		return []stdinTarget{{lang: "", envAs: envAs}}
	}
	if len(head) == 0 {
		return nil
	}
	// Seed only THIS level's freshly-peeled ops BEFORE any early-return
	// recursion: `inherited` already rode in on `caller` (the recursion
	// seeds each layer as it descends), so seeding the merged envAs again
	// would re-apply an outer `env -C` relative dir onto the already-
	// chdir'd cwd — a doubled join (R4 MF-1). envAs itself is still
	// recorded whole on the returned stdinTarget so every peeled op stays
	// visible to the caller. seeding also covers envTaint/pathEnv — a
	// canon-rewritten recursion (`env -C sub genv ./mysh`) must keep the
	// -C re-anchor and the `u`/`a` taints it peeled (R5 MF-4).
	caller = caller.seededWith(ea)
	base := filepath.Base(head[0])
	if canon := canonicalResolvedBase(base); canon != base {
		if isPeeledWrapperBase(canon) {
			return stdinProgramTargetsWithEnv(append([]string{canon}, head[1:]...), depth+1, envAs, basePath, caller)
		}
		head = append([]string{canon}, head[1:]...)
		base = canon
	}
	effPath := envAs.effectivePATHFrom(basePath)
	if rb := canonicalResolvedBase(resolveHeadBase(head[0], effPath, caller.screenCwd())); rb != "" && rb != base {
		if isPeeledWrapperBase(rb) {
			return stdinProgramTargetsWithEnv(append([]string{rb}, head[1:]...), depth+1, envAs, basePath, caller)
		}
		if !isStructuralGuardHead(base) {
			head = append([]string{rb}, head[1:]...)
			base = rb
		}
	}
	collectSegs := func(segs []shellSegment, subEnv envAssignments, subPath string, mergeOuter bool, subCaller callerIdentity) []stdinTarget {
		var out []stdinTarget
		for _, seg := range segs {
			if seg.depthExceeded || seg.parseErr != "" {
				out = append(out, stdinTarget{lang: "", envAs: envAs})
				continue
			}
			if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
				continue
			}
			for _, t := range stdinProgramTargetsWithEnv(seg.argv, depth+1, subEnv, subPath, subCaller) {
				if mergeOuter {
					t.envAs = envAs.merged(t.envAs)
				}
				out = append(out, t)
			}
		}
		return out
	}
	if base == "ssh" {
		remoteCmd, hit := parseSSHInvocation(head)
		if hit != "" {
			return nil
		}
		// Remote commands resolve under the remote login env — only the
		// remote ops feed their PATH replay — but relative heads inside
		// them still resolve under the screen cwd like the old shared
		// screenCwd did (the remote ops themselves stay untainted).
		remoteCaller := callerIdentity{cwd: caller.cwd}
		targets := collectSegs(splitShellSegmentsCaller(remoteCmd, nil, remoteCaller), envAssignments{}, os.Getenv("PATH"), true, remoteCaller)
		// Every target of an ssh remote command runs OFF this host: the
		// stream is forwarded verbatim, so mark it remote even when the
		// remote program is a local-shell-shaped head (ssh host sh).
		for i := range targets {
			targets[i].remote = true
		}
		return targets
	}
	if innerText, has := unwrapShellArgv(head); has {
		if isDynamicArg(innerText) {
			return []stdinTarget{{lang: "", envAs: envAs}}
		}
		// A nested -c script must additionally carry envAs's sentinel
		// taints (`env -u PWD sh -c 'echo $PWD'`): the caller was seeded
		// with only this level's `ea` above, so merge the accumulated
		// envAs taints for the sub-parse (R5 MF-4).
		subCaller := caller
		subCaller.envTaint = mergeEnvTaint(subCaller.envTaint, envAs.taintedSentinelNames())
		var segs []shellSegment
		switch base {
		case "bash", "zsh", "ksh", "mksh":
			segs = splitShellSegmentsBashCaller(innerText, subCaller.envTaint, subCaller)
		default:
			segs = splitShellSegmentsCaller(innerText, subCaller.envTaint, subCaller)
		}
		return collectSegs(segs, envAs, basePath, false, subCaller)
	}
	if _, _, has := unwrapInterpreterInline(head); has {
		return nil
	}
	switch base {
	case "eval":
		if len(head) < 2 {
			return nil
		}
		inner := strings.Join(head[1:], " ")
		if isDynamicArg(inner) {
			return []stdinTarget{{lang: "", envAs: envAs}}
		}
		return collectSegs(splitShellSegmentsCaller(inner, caller.envTaint, caller), envAs, basePath, false, caller)
	case "flock":
		inner, cmdText := skipFlockArgs(head, 1)
		if cmdText != "" {
			if isDynamicArg(cmdText) {
				return []stdinTarget{{lang: "", envAs: envAs}}
			}
			return collectSegs(splitShellSegmentsCaller(cmdText, caller.envTaint, caller), envAs, basePath, false, caller)
		}
		if inner < len(head) {
			return stdinProgramTargetsWithEnv(head[inner:], depth+1, envAs, basePath, caller)
		}
		return nil
	case "script":
		if payload := scriptCommandArg(head); payload != "" {
			if isDynamicArg(payload) {
				return []stdinTarget{{lang: "", envAs: envAs}}
			}
			return collectSegs(splitShellSegmentsCaller(payload, caller.envTaint, caller), envAs, basePath, false, caller)
		}
		return []stdinTarget{{lang: "", envAs: envAs}}
	case "watch":
		if len(head) < 2 {
			return nil
		}
		k, execMode, fc := skipWatchArgs(head, 1)
		if fc {
			return []stdinTarget{{lang: "", envAs: envAs}}
		}
		if k >= len(head) {
			return nil
		}
		if execMode {
			return stdinProgramTargetsWithEnv(head[k:], depth+1, envAs, basePath, caller)
		}
		text := strings.Join(head[k:], " ")
		if isDynamicArg(text) {
			return []stdinTarget{{lang: "", envAs: envAs}}
		}
		return collectSegs(splitShellSegmentsCaller(text, caller.envTaint, caller), envAs, basePath, false, caller)
	case "xargs":
		k := xargsTargetIndex(head)
		if k >= len(head) {
			return nil
		}
		if xargsFeedsCodeFlag(head[k:], head, effPath, caller) {
			innerHead, innerEnv, innerEffPath, innerExhausted := peelWrappersAndWrapperAliases(head[k:], effPath, caller)
			envAs = envAs.merged(innerEnv)
			if !innerExhausted && len(innerHead) > 0 {
				// Resolve the xargs target under its own peeled env (the
				// `env -C sub` re-anchor inside the xargs operand): a
				// symlink alias like ./myruby -> <real ruby> must yield
				// its language, not fall through to the POSIX-shell
				// re-review lang:"" (R6 MF-1).
				innerCaller := caller.seededWith(innerEnv)
				ib := filepath.Base(innerHead[0])
				if rb := canonicalResolvedBase(resolveHeadBase(innerHead[0], innerEffPath, innerCaller.screenCwd())); rb != "" {
					ib = rb
				}
				if l, ok := heredocInterpLang(ib); ok {
					return []stdinTarget{{lang: l, envAs: envAs}}
				}
			}
			return []stdinTarget{{lang: "", envAs: envAs}}
		}
		return stdinProgramTargetsWithEnv(head[k:], depth+1, envAs, basePath, caller)
	}
	if shellHeads[base] {
		sawDashDash := false
		forceStdin := false
		for i := 1; i < len(head); {
			a := head[i]
			if isDynamicArg(a) {
				return []stdinTarget{{lang: "", envAs: envAs}}
			}
			if a == "--" {
				sawDashDash = true
				i++
				continue
			}
			if sawDashDash {
				if a == "-" || isStdinDevicePath(a) || forceStdin {
					return []stdinTarget{{lang: "", envAs: envAs}}
				}
				return nil
			}
			if a == "-" || isStdinDevicePath(a) {
				return []stdinTarget{{lang: "", envAs: envAs}}
			}
			if a == "-o" || a == "+o" || a == "-O" || a == "+O" {
				i += 2
				continue
			}
			if (strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+")) && len(a) > 1 && !strings.HasPrefix(a, "--") {
				plus := a[0] == '+'
				for j := 1; j < len(a); j++ {
					ch := a[j]
					if ch == 's' && !plus {
						forceStdin = true
					}
					if ch == 'c' && !plus {
						return nil
					}
					if ch == 'o' || ch == 'O' {
						if j+1 >= len(a) {
							i++
						}
						break
					}
				}
				i++
				continue
			}
			if strings.HasPrefix(a, "--") {
				i++
				continue
			}
			if forceStdin {
				return []stdinTarget{{lang: "", envAs: envAs}}
			}
			return nil
		}
		return []stdinTarget{{lang: "", envAs: envAs}}
	}
	if lang, ok := heredocInterpLang(base); ok {
		sawDashDash := false
		valueOpts := map[string]bool{
			"-W": true, "-X": true, "-r": true, "--require": true,
			"--loader": true, "--import": true, "--experimental-loader": true,
			"--conditions": true, "-C": true, "-I": true, "-M": true, "-m": true,
			"-c": true, "-d": true, "-z": true, "-F": true, "-K": true,
			"--input-type": true, "--check-hash-based-pycs": true, "--title": true,
			"--env-file": true, "--env-file-if-exists": true, "--redirect-warnings": true,
			"--diagnostic-dir": true, "--watch-path": true,
		}
		for i := 1; i < len(head); {
			a := head[i]
			if isDynamicArg(a) {
				return []stdinTarget{{lang: lang, envAs: envAs}}
			}
			if a == "-" || isStdinDevicePath(a) {
				return []stdinTarget{{lang: lang, envAs: envAs}}
			}
			if a == "--" {
				sawDashDash = true
				i++
				continue
			}
			if sawDashDash || !strings.HasPrefix(a, "-") {
				return nil
			}
			if valueOpts[a] {
				i += 2
				continue
			}
			i++
		}
		return []stdinTarget{{lang: lang, envAs: envAs}}
	}
	return nil
}

func isLongOptAbbrev(name, full string, minPrefixLen int) bool {
	return name == full || (len(name) >= minPrefixLen && strings.HasPrefix(full, name))
}

// resolveNodeRunnerPathOpt normalizes a path-valued option operand (--prefix /
// --userconfig) of npx/bunx/pnpx and reports the resolved path plus whether it
// is safe: single-word, only `~` or `~/...` for tilde (`~user` fails closed),
// no '..' traversal on dynamic prefixes, relative paths joined against cwd
// (the screened call's working directory), and neither lexical nor
// symlink-resolved path inside /tmp|/var/tmp|/dev/shm|/run.
func resolveNodeRunnerPathOpt(val string, cwd string) (string, bool) {
	if val == "" || !isSingleWordOptionValue(val) {
		return "", false
	}
	var cand string
	switch {
	case strings.HasPrefix(val, "~"):
		raw := strings.Replace(val, cmdSubPlaceholderGlob, "", 1)
		if isDynamicArg(raw) || strings.ContainsAny(raw, "*?[") {
			return "", false
		}
		if raw != "~" && !strings.HasPrefix(raw, "~/") {
			return "", false // ~otheruser: untrusted home directory
		}
		home := filepath.Clean(safeHomeDir())
		if home == "" || home == "." || !filepath.IsAbs(home) {
			return "", false
		}
		cand = filepath.Clean(home + raw[1:])
	case isDynamicArg(val):
		for _, seg := range strings.Split(filepath.ToSlash(val), "/") {
			if seg == ".." {
				return "", false
			}
		}
		cand = filepath.Clean(val)
	case filepath.IsAbs(val):
		cand = filepath.Clean(val)
	default:
		if cwd == "" {
			return "", false
		}
		if ec, err := filepath.EvalSymlinks(cwd); err == nil {
			cwd = ec
		}
		cand = filepath.Clean(filepath.Join(cwd, val))
	}
	if isTmpOrScratchPath(cand) {
		return "", false
	}
	if resolved, err := filepath.EvalSymlinks(cand); err == nil {
		if isTmpOrScratchPath(filepath.Clean(resolved)) {
			return "", false
		}
	}
	return cand, true
}

func trimByteAligned(raw, mask string) (string, string) {
	n := minInt(len(raw), len(mask))
	s, e := 0, n
	for s < e && (raw[s] == ' ' || raw[s] == '\t' || raw[s] == '\n' || raw[s] == '\r') {
		s++
	}
	for e > s && (raw[e-1] == ' ' || raw[e-1] == '\t' || raw[e-1] == '\n' || raw[e-1] == '\r') {
		e--
	}
	return raw[s:e], mask[s:e]
}

func staticArgvListAllowEmpty(s string) ([]string, bool) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && ((s[0] == '[' && strings.TrimSpace(s[1:]) == "]") ||
		(s[0] == '(' && strings.TrimSpace(s[1:]) == ")")) {
		return []string{}, true
	}
	return staticArgvList(s)
}

// inspectJSSpawnOptions parses a JS/TS child_process options object literal
// (`{ cwd: '/tmp', shell: ..., execPath: ... }`) and extracts any shell mode
// or custom executable path. Dynamic values on shell/execPath, spread `...`,
// computed keys `[k]: v`, or shorthand `{ shell }`/`{ execPath }` return ok=false.
func inspectJSSpawnOptions(rawObj, maskObj string) (shellMode bool, execPath string, ok bool) {
	if len(maskObj) < 2 || maskObj[0] != '{' {
		return false, "", false
	}
	end := matchingBracket(maskObj, '{', '}')
	if end < 0 || strings.TrimSpace(maskObj[end+1:]) != "" {
		return false, "", false
	}
	innerMask := maskObj[1:end]
	innerRaw := rawObj[1:minInt(end, len(rawObj))]
	for _, sp := range splitCallArgsOffsets(innerMask) {
		lo := minInt(sp[0], len(innerRaw))
		hi := minInt(sp[1], len(innerRaw))
		mlo := minInt(sp[0], len(innerMask))
		mhi := minInt(sp[1], len(innerMask))
		if hi <= lo || mhi <= mlo {
			continue
		}
		eRaw, eMask := trimByteAligned(innerRaw[lo:hi], innerMask[mlo:mhi])
		if eRaw == "" {
			continue
		}
		if strings.HasPrefix(eMask, "...") || strings.HasPrefix(eMask, "[") {
			return false, "", false
		}
		colon := strings.IndexByte(eMask, ':')
		if colon < 0 {
			if eMask == "shell" || eMask == "execPath" {
				return false, "", false
			}
			continue
		}
		kRaw := strings.TrimSpace(eRaw[:colon])
		kMask := strings.TrimSpace(eMask[:colon])
		key := kMask
		if !isIdentName(key) {
			var rest string
			var litOK bool
			key, rest, litOK = leadingStringLiteral(kRaw)
			if !litOK || strings.TrimSpace(rest) != "" {
				return false, "", false
			}
		}
		vRaw := strings.TrimSpace(eRaw[colon+1:])
		switch key {
		case "execPath":
			if vRaw == "undefined" || vRaw == "null" {
				continue
			}
			lit, rest, litOK := leadingStringLiteral(vRaw)
			if !litOK || strings.TrimSpace(rest) != "" {
				return false, "", false
			}
			execPath = lit
		case "shell":
			switch vRaw {
			case "false", "undefined", "null":
				continue
			case "true":
				shellMode = true
			default:
				lit, rest, litOK := leadingStringLiteral(vRaw)
				if !litOK || strings.TrimSpace(rest) != "" {
					return false, "", false
				}
				shellMode = true
				execPath = lit
			}
		}
	}
	return shellMode, execPath, true
}

func staticSpawnCalls(language, raw, masked string) (argvs [][]string, shellCmds []string, ok bool) {
	isJS := language == "javascript" || language == "typescript"
	type callArg struct{ raw, mask string }
	var allArgs []callArg
	for _, sp := range splitCallArgsOffsets(masked) {
		lo := minInt(sp[0], len(raw))
		hi := minInt(sp[1], len(raw))
		mlo := minInt(sp[0], len(masked))
		mhi := minInt(sp[1], len(masked))
		if hi <= lo || mhi <= mlo {
			continue
		}
		rOp, mOp := trimByteAligned(raw[lo:hi], masked[mlo:mhi])
		if rOp != "" {
			allArgs = append(allArgs, callArg{raw: rOp, mask: mOp})
		}
	}
	if len(allArgs) == 0 {
		return nil, nil, false
	}

	var posArgs []callArg
	shellMode := false
	var extraExecs []string
	for _, op := range allArgs {
		if strings.HasPrefix(op.mask, "*") || strings.HasPrefix(op.mask, "...") {
			return nil, nil, false
		}
		if language == "python" {
			if eq := strings.IndexByte(op.mask, '='); eq > 0 &&
				(eq+1 >= len(op.mask) || op.mask[eq+1] != '=') &&
				op.mask[eq-1] != '!' && op.mask[eq-1] != '<' && op.mask[eq-1] != '>' &&
				isIdentName(strings.TrimSpace(op.mask[:eq])) {
				k := strings.TrimSpace(op.mask[:eq])
				vRaw := strings.TrimSpace(op.raw[eq+1:])
				switch k {
				case "args", "cmd", "command":
					rSub, mSub := trimByteAligned(op.raw[eq+1:], op.mask[eq+1:])
					posArgs = append([]callArg{{raw: rSub, mask: mSub}}, posArgs...)
				case "shell":
					switch vRaw {
					case "True", "true", "1":
						shellMode = true
					case "False", "false", "0", "None":
					default:
						return nil, nil, false
					}
				case "executable":
					if vRaw == "None" {
						continue
					}
					lit, rest, litOK := leadingStringLiteral(vRaw)
					if !litOK || strings.TrimSpace(rest) != "" {
						return nil, nil, false
					}
					extraExecs = append(extraExecs, lit)
				}
				continue
			}
		}
		posArgs = append(posArgs, op)
	}
	if len(posArgs) == 0 {
		return nil, nil, false
	}

	var jsArgsList []string
	hasJSArgsList := false
	if isJS {
		for idx := 1; idx < len(posArgs); idx++ {
			op := posArgs[idx]
			switch {
			case op.mask == "undefined" || op.mask == "null":
				continue
			case strings.HasPrefix(op.mask, "function") || strings.Contains(op.mask, "=>"):
				continue
			case idx == 1 && len(op.mask) > 0 && op.mask[0] == '[':
				l, listOK := staticArgvListAllowEmpty(op.raw)
				if !listOK {
					return nil, nil, false
				}
				jsArgsList = l
				hasJSArgsList = true
			case len(op.mask) > 0 && op.mask[0] == '{':
				shMode, execLit, optOK := inspectJSSpawnOptions(op.raw, op.mask)
				if !optOK {
					return nil, nil, false
				}
				if shMode {
					shellMode = true
				}
				if execLit != "" {
					extraExecs = append(extraExecs, execLit)
				}
			default:
				return nil, nil, false // dynamic args/options variable
			}
		}
	}

	appendExtras := func(mainArgv []string) {
		for _, ex := range extraExecs {
			argvs = append(argvs, []string{ex})
			if !shellMode && len(mainArgv) > 1 {
				argvs = append(argvs, append([]string{ex}, mainArgv[1:]...))
			} else if isJS && !shellMode && len(mainArgv) == 1 {
				// fork('/tmp/pig', [], {execPath: ...}) or fork('/tmp/x.js', [], {execPath: P})
				argvs = append(argvs, []string{ex, mainArgv[0]})
			}
		}
	}

	if isJS {
		firstOp := posArgs[0].raw
		if listArgv, listOK := staticArgvList(firstOp); listOK {
			if shellMode || (len(listArgv) == 1 && strings.ContainsAny(listArgv[0], " \t'\"\\$`*|;&")) {
				shellCmds = append(shellCmds, strings.Join(listArgv, " "))
			} else {
				argvs = append(argvs, listArgv)
			}
			appendExtras(listArgv)
			return argvs, shellCmds, len(argvs)+len(shellCmds) > 0
		}
		lit, rest, litOK := leadingStringLiteral(firstOp)
		if !litOK || strings.TrimSpace(rest) != "" {
			return nil, nil, false
		}
		if hasJSArgsList {
			combined := append([]string{lit}, jsArgsList...)
			if shellMode {
				shellCmds = append(shellCmds, strings.Join(combined, " "))
			} else {
				argvs = append(argvs, combined)
			}
			appendExtras(combined)
			return argvs, shellCmds, len(argvs)+len(shellCmds) > 0
		}
		if shellMode || strings.ContainsAny(lit, "'\"\\$`*|;&") {
			shellCmds = append(shellCmds, lit)
		} else if f := strings.Fields(lit); len(f) > 0 {
			argvs = append(argvs, f)
		}
		appendExtras([]string{lit})
		return argvs, shellCmds, len(argvs)+len(shellCmds) > 0
	}

	// Python positional extraction: delegate base argv/shell parsing to
	// staticSpawnArgv and additionally vet positional Popen executable (arg 3).
	if len(posArgs) >= 3 {
		if _, isList0 := staticArgvListAllowEmpty(posArgs[0].raw); isList0 {
			pExec := posArgs[2].raw
			if pExec != "None" {
				lit, rest, litOK := leadingStringLiteral(pExec)
				if !litOK || strings.TrimSpace(rest) != "" {
					return nil, nil, false
				}
				extraExecs = append(extraExecs, lit)
			}
		}
	}
	baseArgv, baseShell, baseOK := staticSpawnArgv(raw, masked)
	if !baseOK {
		return nil, nil, false
	}
	if len(baseArgv) > 0 {
		if shellMode {
			shellCmds = append(shellCmds, strings.Join(baseArgv, " "))
		} else {
			argvs = append(argvs, baseArgv)
			base := canonicalResolvedBase(filepath.Base(baseArgv[0]))
			if len(baseArgv) >= 3 && (shellHeads[base] || isPeeledWrapperBase(base)) && strings.HasPrefix(baseArgv[2], "-") {
				// Cover Python execv/posix_spawn(shell, ['fake_argv0', '-c', 'pig']).
				argvs = append(argvs, append([]string{baseArgv[0]}, baseArgv[2:]...))
			}
		}
	}
	if baseShell != "" {
		shellCmds = append(shellCmds, baseShell)
	}
	appendExtras(baseArgv)
	return argvs, shellCmds, len(argvs)+len(shellCmds) > 0
}

// isPythonImportStmtAt reports whether byte offset pos in pythonMask-processed
// code s lies inside a syntactically valid Python `import ...` or
// `from ... import ...` statement (rather than a runtime call, attribute load,
// or symbol rebind). Bare newlines terminate statements unless enclosed within
// `from <module> import ( ... )` or escaped by a trailing `\` line continuation.
func isPythonImportStmtAt(s string, pos int) bool {
	isIdent := func(b byte) bool {
		return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
	}
	if pos < 0 || pos >= len(s) || !isIdent(s[pos]) {
		return false
	}
	if pos > 0 && isIdent(s[pos-1]) {
		return false
	}
	end := pos
	for end < len(s) && isIdent(s[end]) {
		end++
	}

	// prevContinuedNL reports whether s[nlIdx] == '\n' is escaped by a single
	// line-continuation backslash (`\\\n` or `\\\r\n`), returning the byte index
	// immediately preceding that backslash.
	prevContinuedNL := func(nlIdx int) (int, bool) {
		k := nlIdx - 1
		if k >= 0 && s[k] == '\r' {
			k--
		}
		if k >= 0 && s[k] == '\\' && (k == 0 || s[k-1] != '\\') {
			return k - 1, true
		}
		return 0, false
	}

	skipForwardWS := func(i int) int {
		for i < len(s) {
			if s[i] == ' ' || s[i] == '\t' || s[i] == '\r' {
				i++
				continue
			}
			if s[i] == '\\' && (i == 0 || s[i-1] != '\\') {
				if i+1 < len(s) && s[i+1] == '\n' {
					i += 2
					continue
				}
				if i+2 < len(s) && s[i+1] == '\r' && s[i+2] == '\n' {
					i += 3
					continue
				}
			}
			break
		}
		return i
	}

	skipBackwardWS := func(i int) int {
		for i >= 0 {
			if s[i] == ' ' || s[i] == '\t' || s[i] == '\r' {
				i--
				continue
			}
			if s[i] == '\n' {
				if prev, ok := prevContinuedNL(i); ok {
					i = prev
					continue
				}
			}
			break
		}
		return i
	}

	isStmtBoundaryBefore := func(idx int) bool {
		k := skipBackwardWS(idx - 1)
		if k < 0 || s[k] == '\n' || s[k] == ';' {
			return true
		}
		if s[k] == ':' && (k == 0 || s[k-1] != ':') {
			return true
		}
		return false
	}

	matchWordAt := func(idx int, kw string) bool {
		if idx < 0 || idx+len(kw) > len(s) || s[idx:idx+len(kw)] != kw {
			return false
		}
		if idx > 0 && isIdent(s[idx-1]) {
			return false
		}
		if idx+len(kw) < len(s) && isIdent(s[idx+len(kw)]) {
			return false
		}
		return true
	}

	// hasFromImportPrefix validates `from <module> import` starting at kwStart up
	// to limit (openParen for parenthesized imports, stmtEnd for plain imports).
	hasFromImportPrefix := func(kwStart, limit int, requireTargetAfterImport bool) bool {
		if !isStmtBoundaryBefore(kwStart) || !matchWordAt(kwStart, "from") {
			return false
		}
		q := skipForwardWS(kwStart + len("from"))
		hasMod := false
		for q < limit {
			if matchWordAt(q, "import") {
				if !hasMod {
					return false
				}
				afterImp := skipForwardWS(q + len("import"))
				if requireTargetAfterImport {
					return afterImp < limit
				}
				return afterImp == limit
			}
			if isIdent(s[q]) {
				hasMod = true
				for q < limit && isIdent(s[q]) {
					q++
				}
				q = skipForwardWS(q)
				continue
			}
			if s[q] == '.' {
				hasMod = true
				q++
				q = skipForwardWS(q)
				continue
			}
			return false
		}
		return false
	}

	// Case 1: Parenthesized multiline `from <module> import ( ... )`.
	// Bare newlines are permitted ONLY strictly between `(` and matching `)`.
	{
		i := pos - 1
		openParen := -1
		for i >= 0 {
			c := s[i]
			if isIdent(c) || c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
				i--
				continue
			}
			if c == '\\' && (i == 0 || s[i-1] != '\\') &&
				((i+1 < len(s) && s[i+1] == '\n') || (i+2 < len(s) && s[i+1] == '\r' && s[i+2] == '\n')) {
				i--
				continue
			}
			if c == '(' {
				openParen = i
			}
			break
		}
		if openParen >= 0 {
			j := end
			closeParen := -1
			for j < len(s) {
				c := s[j]
				if isIdent(c) || c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
					j++
					continue
				}
				if c == '\\' && (j == 0 || s[j-1] != '\\') &&
					((j+1 < len(s) && s[j+1] == '\n') || (j+2 < len(s) && s[j+1] == '\r' && s[j+2] == '\n')) {
					j++
					continue
				}
				if c == ')' {
					closeParen = j
				}
				break
			}
			if closeParen >= 0 {
				afterClose := skipForwardWS(closeParen + 1)
				if afterClose == len(s) || s[afterClose] == '\n' || s[afterClose] == ';' {
					m := openParen - 1
					for m >= 0 {
						if isIdent(s[m]) || s[m] == '.' {
							m--
							continue
						}
						nextM := skipBackwardWS(m)
						if nextM != m {
							m = nextM
							continue
						}
						break
					}
					kwStart := skipForwardWS(m + 1)
					if hasFromImportPrefix(kwStart, openParen, false) {
						return true
					}
				}
			}
		}
	}

	// Case 2: Unparenthesized `import ...` or `from ... import ...` on a single
	// logical line (only `\`-escaped newlines may join physical lines).
	m := pos - 1
	for m >= 0 {
		if isIdent(s[m]) || s[m] == '.' || s[m] == ',' {
			m--
			continue
		}
		nextM := skipBackwardWS(m)
		if nextM != m {
			m = nextM
			continue
		}
		break
	}
	kwStart := skipForwardWS(m + 1)
	if kwStart > pos || !isStmtBoundaryBefore(kwStart) {
		return false
	}

	stmtEnd := kwStart
	for stmtEnd < len(s) {
		if isIdent(s[stmtEnd]) || s[stmtEnd] == '.' || s[stmtEnd] == ',' {
			stmtEnd++
			continue
		}
		nextE := skipForwardWS(stmtEnd)
		if nextE != stmtEnd {
			stmtEnd = nextE
			continue
		}
		break
	}
	if end > stmtEnd {
		return false
	}
	if stmtEnd < len(s) && s[stmtEnd] != '\n' && s[stmtEnd] != ';' {
		return false
	}

	if matchWordAt(kwStart, "import") {
		afterImp := skipForwardWS(kwStart + len("import"))
		return afterImp <= pos && afterImp < stmtEnd
	}
	return hasFromImportPrefix(kwStart, stmtEnd, true)
}
