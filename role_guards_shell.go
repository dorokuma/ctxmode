package main

// role_guards_shell.go — role classification, shell command segmentation, and argv wrapper peeling.

// role_guards.go — hard guards for sub-agent and read-only role callers of the
// ctx_* tools (pure standard library).
//
// The audit trail records CTXMODE_ROLE / CTXMODE_READONLY (audit.go); those two
// inputs were annotation-only. This file turns them into enforcement inputs for
// the dispatch layer that already sets them on every spawned role:
//
//   - The sub-agent guard (audit rule "subagent_nested_agent") applies to every
//     sub-agent caller — a call arriving with CTXMODE_ROLE set or
//     CTXMODE_READONLY=1. It blocks nested dispatch of agent executables (pig,
//     pi, agy, dispatch-agent, dispatch-agent-go, grok) and orchestration
//     mutations through herdr/herdsman from every ctx_run branch, while
//     leaving herdr/herdsman read-only queries alone. The hc terminal-control
//     CLI is whitelisted to `hc send <t-addr> <text>` (the report channel)
//     plus --help/--version/<sub> --help queries; every other hc verb
//     blocks.
//   - The read-only guard (audit rule "readonly_write_blocked") applies to
//     read-only roles: CTXMODE_READONLY=1 or CTXMODE_ROLE ∈
//     scout|planner|researcher|reviewer|oracle|verifier. For all of them it
//     blocks KB writes (ctx_kb index/purge). For the strict set — every
//     read-only role except verifier, which keeps /tmp scratch capability for
//     isolated verification clones — it additionally blocks ctx_bg kill,
//     ctx_run action=run_task, write/destructive/build command heads,
//     in-place editors, git write subcommands, and output redirects to real
//     files inside shell command text. When CTXMODE_ROLE=worker (not a
//     read-only role name) and CTXMODE_READONLY=1 appear together, the
//     explicit read-only flag wins: auditCallerIsStrictReadonly treats the
//     caller as strict read-only, matching the table-driven tests.
//
// Both guards run after startAudit + defer emit in each ctx_run handler, so a
// blocked call is still audited (exit_code -1, screen_verdict "block",
// screen_rule set, error non-empty). They are a hardening layer inside the
// documented trust model, not a sandbox: nothing here constrains a caller that
// spawns processes outside ctxmode.

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Guard rule names, shared by the guards, the router, and the audit record.
const (
	ruleSubagentNestedAgent = "subagent_nested_agent"
	ruleReadonlyWrite       = "readonly_write_blocked"
)

// ---------- role classification ----------

// auditCallerIsSubagent reports whether the call carries a sub-agent identity:
// an explicit role name (any role, including worker) or the read-only caller
// flag. Both come from the env the dispatch layer sets for spawned roles.
func auditCallerIsSubagent() bool {
	return strings.TrimSpace(os.Getenv(auditEnvRole)) != "" || auditReadonlyEnv()
}

// auditCallerIsReadonly reports whether the caller is a read-only role:
// CTXMODE_READONLY=1 or one of the read-only role names.
func auditCallerIsReadonly() bool {
	return auditReadonlyEnv() || auditRoleIsReadonly(os.Getenv(auditEnvRole))
}

// auditCallerIsStrictReadonly is the read-only set minus verifier. A verifier
// keeps the ability to run isolated checks in /tmp (git clone, rm -rf, go test)
// but remains a sub-agent for nested-dispatch purposes and still cannot write
// to the shared KB.
func auditCallerIsStrictReadonly() bool {
	if !auditCallerIsReadonly() {
		return false
	}
	return strings.ToLower(strings.TrimSpace(os.Getenv(auditEnvRole))) != "verifier"
}

// callerIsRoleGuarded reports whether the call carries a role identity that
// either guard enforces. Callers with no role at all (the main agent) are
// outside both models, so the surfaces that only exist to protect the guards
// from a guarded caller — overriding the guard's own view of who is calling
// through a CTXMODE_* env key — must stay open for them.
func callerIsRoleGuarded() bool {
	return auditCallerIsSubagent() || auditCallerIsStrictReadonly()
}

// ---------- shell command segmentation ----------

// heredocBody is one consumed heredoc body attached to the segment owning the
// `<<` redirect; quoted=false bodies also get $(...)/`...` substitution
// scanning because the shell still expands them.
type heredocBody struct {
	text    string
	quoted  bool
	dynamic bool // unquoted body had ParamExp/CmdSubst/ArithmExp — not static text
}

// shellSegment is one simple command parsed out of a shell command string:
// its words (quotes/escapes already folded), the first output-redirection
// target that is not /dev/null|stdout|stderr or an fd duplication, which a
// read-only caller must not write to, and any heredoc bodies this command
// consumed. A segment with no words is dropped.
type shellSegment struct {
	argv         []string
	argWords     []*syntax.Word // parallel to argv; nil for assigns / enum-expanded heads
	redirectFile string         // "" when every redirection was safe (or none existed)
	heredocText  []heredocBody  // bodies queued by <<DELIM on this command line
	// pipedStdin marks a segment whose stdin comes from a pipeline upstream
	// (it follows a bare `|`). A shell/interpreter head with pipedStdin reads
	// its PROGRAM from the pipe — the upstream bytes are code, not data.
	pipedStdin bool
	// backgrounded marks a segment terminated by a bare `&` (background job).
	// Strict read-only allowlist policy rejects background execution.
	backgrounded bool
	// hereString is the `<<< word` payload this command consumed: the bytes
	// it reads on stdin. Like heredoc bodies it is screened as code when the
	// head is a shell/interpreter reading its program from stdin, and its
	// $(...)/`...` substitutions are scanned because the shell expands them
	// unless the word was single-quoted.
	hereString string
	// processSubst marks that this segment used bash process substitution
	// `<(...)` or `>(...)`. Strict read-only allowlist rejects these: the
	// lexer previously mistook them for plain redirects and skipped the
	// inner command, letting bash execute it unguarded.
	processSubst bool
	// depthExceeded marks a synthetic segment emitted when $(...)/`...`/(...)
	// nesting exceeds shellSplitMaxDepth: the inner commands could not be
	// parsed, so the guards must fail closed instead of silently dropping
	// them. It is never a real command.
	depthExceeded bool
	// stdinRedir marks a segment whose stdin was explicitly redirected from
	// a file/fd (<, N<, <&N, <>): piped bytes and heredoc bodies do NOT
	// reach it as a program stream, and a remote stdin vehicle must not
	// have one (SH11 F7).
	stdinRedir bool
	// parseErr is a fail-closed parse/validation reason that is NOT a nesting-depth
	// overflow (e.g. bash-only syntax under /bin/sh). Prefer this over stuffing
	// every parse failure into depthExceeded.
	parseErr string
	// srcCode is the exact buffer this segment's words were parsed from. It is
	// the buffer identity half of the structured provenance match — a span index
	// means nothing without it.
	srcCode string
	// gateProvenanced marks a segment whose `<selfExe> --hc-gate …` shape was
	// minted by prepare* and matched against its span-bound hcGateProvenance.
	// It is a copy of a VERIFIED result, never evidence on its own: every read
	// site also requires isPreparedHcGateArgv + the provenance spans.
	gateProvenanced bool
	// secondaryDialect marks a segment that ONLY the non-primary dialect tree
	// produced (posix primary + bash secondary, or the reverse under `bash -c`).
	// Rewrite decisions are taken from the primary tree only; a dynamic hc send
	// visible solely here fails closed instead of being silently dropped.
	secondaryDialect bool
}

// shellSplitMaxDepth bounds recursion into $(...)/`...`/subshell text so a
// deeply nested command cannot blow the stack; nesting beyond it emits a
// depthExceeded marker segment that both guards block outright.
const shellSplitMaxDepth = 16

// peelChainMaxDepth bounds guard recursion through eval / xargs / find -exec /
// flock -c / script -c / sh -c style indirections; exceeding it fails closed.
const peelChainMaxDepth = 24

// peelWrapperMaxSteps bounds wrapper peeling in peelWrappers; a longer chain
// of wrappers fails closed. Bare KEY=VAL prefixes do not consume steps.
const peelWrapperMaxSteps = 32

// depthExceededHit is the guard hit returned for depthExceeded marker
// segments and over-deep guard recursion.
const depthExceededHit = "exceeded max shell nesting depth"

// dynamicRedirectTarget is the placeholder recorded as redirectFile when an
// output redirection's target is a command substitution or otherwise
// unreadable statically. It is never a real path, and any non-empty
// redirectFile blocks a read-only caller, so `echo hi > $(printf /tmp/x)`
// cannot slip through.
const dynamicRedirectTarget = "<dynamic>"

// cmdSubPlaceholder is the word-level stand-in written for a word-position
// command substitution ($(...) / `...`): the substitution's own commands are
// parsed into sibling segments while the placeholder keeps the enclosing
// command line's argv shape intact — `git -C $(pwd) status` stays
// [git -C __ctx_cmdsub__ status] instead of being torn into three broken
// segments, and `A=$(true) pig` keeps the KEY=VAL assignment attached to the
// pig segment. peelResolvedDepth fails closed when the placeholder appears
// in the resolved command HEAD word (a dynamically generated command name
// cannot be vetted); placeholders in argument positions are inert.
const cmdSubPlaceholder = "__ctx_cmdsub__"

// cmdSubPlaceholderQuoted marks dynamic content that lived entirely inside
// double quotes (no field-split / glob). Unquoted dynamics keep cmdSubPlaceholder.
const cmdSubPlaceholderQuoted = "__ctx_dq_sub__"

// cmdSubPlaceholderGlob marks an UNQUOTED glob/tilde literal (* ? [...] ~):
// pathname expansion happens after field splitting and each match is one
// argv word, so the word can never inject extra options — but it IS dynamic.
const cmdSubPlaceholderGlob = "__ctx_glob__"

// cmdSubPlaceholderAbsDq marks a double-quoted dynamic whose expansion is
// GUARANTEED to begin with '/': $PWD/$OLDPWD/${PWD}/${OLDPWD}, $(pwd) and a
// bare $(mktemp -d) with untainted TMPDIR. Word-start it is split-safe AND
// cannot become an option flag (Q1-C: absolute-path placeholder class).
const cmdSubPlaceholderAbsDq = "__ctx_abspath_dq__"

// envPathSelfPlaceholder stands for a literal $PATH / ${PATH} expansion
// inside a PATH= value. The embedded NUL bytes make it impossible to
// produce from shell text or argv (exec rejects NUL) — so only a real
// expansion site can mint it (SH11 F1/Q3: provenance is structural, not a
// forgeable string literal).
const envPathSelfPlaceholder = "\x00ctx-env-path\x00"

// mktempDirPlaceholder is the fake absolute path bound for a bare
// $(mktemp -d) assignment (F8: only with untainted TMPDIR).
const mktempDirPlaceholder = "/tmp/__ctx_mktemp_dir__"

// sentinelTrustVars are variables whose value the placeholder grants depend
// on: writing them even once (any site counted by preScanVarMutations)
// taints their expansion semantics in the collector.
var sentinelTrustVars = map[string]bool{
	"HOME": true, "PWD": true, "OLDPWD": true, "TMPDIR": true,
	"IFS": true, "CTXMODE_ROLE": true, "CTXMODE_READONLY": true,
}

// isDynamicArg reports a word that still carries a dynamic placeholder
// (static prefix may precede it, e.g. -c__ctx_cmdsub__). The PATH self
// sentinel deliberately does NOT count: inside PATH= values it is the
// legal "keep my current PATH" marker, and everywhere else its NUL bytes
// make the word unexecutable anyway.
func isDynamicArg(a string) bool {
	return strings.Contains(a, cmdSubPlaceholder) || strings.Contains(a, cmdSubPlaceholderQuoted) ||
		strings.Contains(a, cmdSubPlaceholderGlob) || strings.Contains(a, cmdSubPlaceholderAbsDq)
}

// isSplitSafeDynamicWord reports a dynamic argv word whose dynamic parts
// are guaranteed to stay a single argv word at runtime: fully double-quoted
// expansions, unquoted glob/tilde literals (pathname expansion never
// field-splits) and the $$ PID. Plain unquoted $VAR/$(...)/`...` parts can
// field-split and are NOT split-safe (TASK.md correction 1). Static words
// return false; callers must check isDynamicArg first when distinguishing
// allow vs deny.
func isSplitSafeDynamicWord(a string) bool {
	// Unquoted expansions are never split-safe.
	if strings.Contains(a, cmdSubPlaceholder) {
		return false
	}
	if strings.Contains(a, cmdSubPlaceholderGlob) && !globWordIsSplitSafe(a) {
		return false
	}
	return strings.Contains(a, cmdSubPlaceholderQuoted) ||
		strings.Contains(a, cmdSubPlaceholderGlob) ||
		strings.Contains(a, cmdSubPlaceholderAbsDq)
}

// globWordIsSplitSafe reports whether a word carrying cmdSubPlaceholderGlob
// cannot expand to an option-looking argv word: the FIRST byte must be a
// literal, non '-'/'+'/'~' character (a word starting with * ? [ ~ can
// expand to a filename that begins with '-').
func globWordIsSplitSafe(a string) bool {
	if a == "" {
		return false
	}
	switch a[0] {
	case '-', '+', '~', '*', '?', '[':
		return false
	}
	return true
}

// isSafeDynamicDataOperand reports whether a dynamic word is safe in a
// plain file/data operand slot (script path, file operand, option value
// consumed verbatim): it must be split-safe, must not be able to become an
// option flag (no '-'/'+' word start — including the RUNTIME start, which
// is why a word-start __ctx_dq_sub__ fails but __ctx_abspath_dq__ passes),
// and it must name a path (start with '/' or contain '/' after a safe
// static literal start — R3/M1: a word that BEGINS with a dynamic
// placeholder can expand to `-c`/`-e`, so only __ctx_abspath_dq__ or a
// literal non-'-'/'+'/'~' start may precede the '/').
func isSafeDynamicDataOperand(a string) bool {
	if !isSplitSafeDynamicWord(a) {
		return false
	}
	if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
		return false
	}
	if strings.HasPrefix(a, "/") || strings.HasPrefix(a, cmdSubPlaceholderAbsDq) {
		return true
	}
	// Word-start dynamic placeholders other than abs-dq are unvettable:
	// their runtime text may start with '-' (option injection).
	if strings.HasPrefix(a, cmdSubPlaceholder) || strings.HasPrefix(a, cmdSubPlaceholderQuoted) ||
		strings.HasPrefix(a, cmdSubPlaceholderGlob) {
		return false
	}
	// First byte is a static literal now (placeholders checked above);
	// it must not be '-', '+' or '~' for the same option-injection reason.
	switch a[0] {
	case '-', '+', '~':
		return false
	}
	return strings.Contains(a, "/")
}

// splitShellSegments parses shell text via mvdan.cc/sh (LangPOSIX + Bash cross-check).
func splitShellSegments(code string) []shellSegment {
	return splitShellSegmentsEnv(code, nil)
}

// splitShellSegmentsEnv parses shell text with environment-override taint
// from an outer envAs (HOME=/x sh -c 'PATH=$HOME/x:$PATH git').
func splitShellSegmentsEnv(code string, envTaint map[string]bool) []shellSegment {
	return splitShellSegmentsCaller(code, envTaint, callerIdentity{})
}

// splitShellSegmentsCaller is splitShellSegmentsEnv with an explicit caller
// so the inner $(pwd) base matches the screened call's cwd.
func splitShellSegmentsCaller(code string, envTaint map[string]bool, caller callerIdentity) []shellSegment {
	segs, ok := parseSubagentShellASTEnv(code, 0, false, false, envTaint, caller)
	if !ok {
		if len(segs) > 0 {
			return segs
		}
		return []shellSegment{{depthExceeded: true}}
	}
	return segs
}

// splitShellSegmentsBashCaller parses bash/zsh/ksh/mksh -c payloads with
// LangBash fail-closed, with an explicit caller so the inner $(pwd) base
// matches the screened call's cwd (the former caller-less
// splitShellSegmentsBash/BashEnv wrappers were dropped once every call
// site threaded its caller — R3 MF-3).
func splitShellSegmentsBashCaller(code string, envTaint map[string]bool, caller callerIdentity) []shellSegment {
	segs, ok := parseSubagentShellASTEnv(code, 0, false, true, envTaint, caller)
	if !ok {
		if len(segs) > 0 {
			return segs
		}
		return []shellSegment{{depthExceeded: true}}
	}
	return segs
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ---------- argv command-head resolution ----------

// shellNoopWords are compound-statement fragments that carry no command of
// their own; a segment whose head resolves to one of them is a no-op for the
// guards (the real commands inside were already split into own segments).
var shellNoopWords = map[string]bool{
	"fi": true, "done": true, "}": true, "esac": true, "{": true,
}

// envOp is one ordered env manipulation peeled by peelWrappers /
// skipEnvOperands: a KEY=VAL assignment, an `env -u` unset, or an
// `env -i`/`--ignore-environment` inheritance clear. Replaying the ops in
// order simulates the child process's final role identity so a
// CTXMODE_ROLE=worker env -i pig (clear AFTER the re-assign) is caught
// exactly like env -u CTXMODE_ROLE.
type envOp struct {
	kind  byte   // 'a' assign, 'u' unset, 'c' clearInherit, 'd' chdir (env -C/--chdir)
	key   string // variable name (assign/unset only)
	value string // assigned value (assign only); chdir target dir (chdir only)
}

// envAssignments records the ordered env operations stripped by
// peelWrappers / skipEnvOperands so the guards can screen execution-hook
// environment variables and role-identity shedding (LD_PRELOAD=...,
// EDITOR=..., env -u CTXMODE_ROLE, env -i).
type envAssignments struct {
	ops []envOp // ordered: prefix assignments, then env's own operands
}

// addAssign appends one KEY=VAL op when word actually looks like an
// assignment (KEY must be a bare identifier).
func (e *envAssignments) addAssign(word string) {
	if k := strings.IndexByte(word, '='); k > 0 && !strings.HasPrefix(word, "-") {
		e.ops = append(e.ops, envOp{kind: 'a', key: word[:k], value: word[k+1:]})
	}
}

// merged returns the env op list of e followed by o's ops, preserving
// order so a nested invocation's env ops replay after the outer ones.
func (e envAssignments) merged(o envAssignments) envAssignments {
	if len(e.ops) == 0 {
		return o
	}
	if len(o.ops) == 0 {
		return e
	}
	out := envAssignments{ops: make([]envOp, 0, len(e.ops)+len(o.ops))}
	out.ops = append(out.ops, e.ops...)
	out.ops = append(out.ops, o.ops...)
	return out
}

// envHookVars are execution-hook environment variable names: assigning one a
// non-trivial value hands a command string (or a preload path) to git, the
// pager stack, a shell, or the dynamic loader, so a sub-agent or strict
// read-only role must not set them through KEY=VAL prefixes or `env`.
var envHookVars = map[string]bool{
	"GIT_PAGER": true, "PAGER": true, "MANPAGER": true,
	"LESSOPEN": true, "LESSCLOSE": true,
	"GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_ASKPASS": true,
	"SSH_ASKPASS": true, "GIT_EXTERNAL_DIFF": true,
	"GIT_EDITOR": true, "EDITOR": true, "VISUAL": true,
	"SEQUENCE_EDITOR": true, "BASH_ENV": true, "ENV": true,
	"PROMPT_COMMAND": true, "LD_PRELOAD": true, "LD_AUDIT": true,
	"LD_LIBRARY_PATH": true, "DYLD_INSERT_LIBRARIES": true,
	"PATH": true, "IFS": true,
	"NODE_OPTIONS": true, "PYTHONSTARTUP": true, "PYTHONINSPECT": true,
	"PYTHONPATH": true,
	"PERL5OPT":   true, "PERL5DB": true, "RUBYOPT": true,
	"JAVA_TOOL_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "_JAVA_OPTIONS": true,
	// S2: bash -x prompt expansion and startup option vars can re-arm
	// execution (PS4='$(pig)' bash -x -c, SHELLOPTS=braceexpand,
	// BASHOPTS=xpg_echo) the same way BASH_ENV does.
	"PS4": true, "SHELLOPTS": true, "BASHOPTS": true,
	// Broad GIT_* execution hooks beyond the explicit names above.
	"GIT_PROXY_COMMAND": true, "GIT_DIFF_OPTS": true,
	"GIT_CONFIG_COUNT": true, "GIT_CONFIG_KEY_0": true, "GIT_CONFIG_VALUE_0": true,
	"GIT_TRACE2_PARENT_SID": true, "GIT_EXEC_PATH": true,
	// Dispatch report channel and terminal-control sockets: a sub-agent
	// re-pointing DISPATCH_REPORT_PATH hands its report to a fake collector
	// and a rewritten DISPATCH_REPORT_PARENT retargets the notify address
	// the report lands on; HC_TERMINAL_ID/HC_SOCKET re-target hc send to
	// another terminal or a forged control socket, bypassing the
	// whitelist'd report address; and CTXMODE_EXTRA_WORKDIRS widens the
	// ctxmode workspace set at spawn, letting a role read files outside
	// its authorized roots.
	"DISPATCH_REPORT_PATH": true, "DISPATCH_REPORT_PARENT": true,
	"HC_TERMINAL_ID": true, "HC_SOCKET": true,
	"CTXMODE_EXTRA_WORKDIRS": true,
}

// pagerSafeVars may be set to "" or "cat" — disabling the pager is the
// canonical read-only spelling (`GIT_PAGER=cat git log`).
var pagerSafeVars = map[string]bool{
	"PAGER": true, "GIT_PAGER": true, "MANPAGER": true,
}

// isEnvHookVar reports whether assigning the variable hands an executable
// command/path/module resolution to a later child: the static table plus
// the LD_*/DYLD_*/GIT_CONFIG* prefixes and the GIT_DIR-family, NODE_PATH,
// PERL5LIB/PERLLIB and RUBYLIB module-hijack variables (SH11 MF-5.2).
func isEnvHookVar(key string) bool {
	if envHookVars[key] {
		return true
	}
	if strings.HasPrefix(key, "LD_") || strings.HasPrefix(key, "DYLD_") ||
		strings.HasPrefix(key, "GIT_CONFIG") {
		return true
	}
	switch key {
	case "GIT_DIR", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE",
		"GIT_TEMPLATE_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"NODE_PATH", "PERL5LIB", "PERLLIB", "RUBYLIB",
		// The CTXMODE_* identity/audit keys a role-carrying caller must not
		// rewrite — kept in sync with executor.go roleIdentityEnvKeys so an
		// env prefix / export hits the same wall as args.Env.
		"CTXMODE_AUDIT_LOG", "CTXMODE_ENV_PASSTHROUGH", "CTXMODE_DB", "CTXMODE_CONFIG":
		return true
	}
	return false
}

// gitDirEnvVars are the GIT_* path variables a non-readonly worker may
// redirect to a (split-safe) dynamic path, matching the already-allowed
// git --git-dir="$d" spellings. Strict read-only roles must never set them.
var gitDirEnvVars = map[string]bool{
	"GIT_DIR": true, "GIT_WORK_TREE": true, "GIT_COMMON_DIR": true,
	"GIT_INDEX_FILE": true, "GIT_OBJECT_DIRECTORY": true,
	"GIT_ALTERNATE_OBJECT_DIRECTORIES": true, "GIT_TEMPLATE_DIR": true,
}

// guardTaintVars are the variables carrying the caller's role identity; a
// sub-agent must not clear or unset them to shed its guard.
var guardTaintVars = map[string]bool{
	"CTXMODE_ROLE": true, "CTXMODE_READONLY": true,
}

// peelWrappers strips leading command wrappers, compound-statement keywords
// and KEY=VAL prefixes from argv and returns the index of the real command
// name. env -S/--split-string payloads (which are themselves shell-ish
// command lines) are returned for the caller to screen rather than skipped
// blindly, and stripped KEY=VAL / env -u operands are collected for the
// execution-hook env screen.
//
// Wrappers handled by peelWrappers itself: env (with its options and
// NAME=val assignments), command (-v/-V stay as a read-only builtin
// query), exec, nohup, timeout (with duration and option args), nice,
// setsid, stdbuf, busybox, ionice, taskset, chrt, time, strace/ltrace,
// builtin, shell reserved/modifier words (`if`/`then`/`elif`/`else`/
// `while`/`until`/`do`/`coproc`/`time`/`!`), and `--` terminators.
// watch, flock, script and sudo/doas are NOT peeled here — they need
// stdin-context and privilege semantics, so the downstream
// peelResolvedSegDepth / stdinProgramHeadDepth helpers unwrap them.
// Recursion is bounded by peelWrapperMaxSteps (bare KEY=VAL prefixes
// do not consume steps); a chain that never resolves returns an index
// past the end.

// skipExecArgs advances past bash `exec` options matching internal_getopt
// optstring "cla:": -c/-l are boolean; -a takes a name (separate argv,
// glued -aNAME, or trailing letter in a short cluster like -la/-ca/-cla).
// i is the index just after the "exec" word. Returns the index of the
// command head (or len(argv) when exhausted) and whether the option zone
// must fail closed (a dynamic word in a flag or value slot).
func skipExecArgs(argv []string, i int) (int, bool) {
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return i, true
		}
		if a == "--" {
			return i + 1, false
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			return i, false
		}
		if strings.HasPrefix(a, "--") {
			// bash exec has no long options; treat as the command head.
			return i, false
		}
		if a == "-a" {
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return i, true
			}
			i += 2 // -a name
			continue
		}
		if a == "-c" || a == "-l" {
			i++
			continue
		}
		// Short cluster: -cl, -la, -ca, -cla, -abenign, ...
		cluster := a[1:]
		i++ // consume the cluster argv slot
		for ci := 0; ci < len(cluster); ci++ {
			switch cluster[ci] {
			case 'c', 'l':
				// boolean
			case 'a':
				if cluster[ci+1:] == "" {
					if i < len(argv) && isDynamicArg(argv[i]) {
						return i, true
					}
					i++ // name is the next argv
				}
				// else name is the glued remainder; either way cluster is done
				ci = len(cluster)
			default:
				ci = len(cluster)
			}
		}
	}
	return i, false
}

func peelWrappers(argv []string) (headArgv []string, splitPayloads []string, envAs envAssignments, exhausted bool) {
	i := 0
	depth := 0
	for ; depth < peelWrapperMaxSteps && i < len(argv); depth++ {
		a := argv[i]
		if isAssignWord(a) {
			envAs.addAssign(a)
			i++
			depth--
			continue
		}
		if shellNoopWords[a] {
			if i+1 >= len(argv) {
				return argv[len(argv):], splitPayloads, envAs, false
			}
			i++
			depth--
			continue
		}
		switch a {
		case "if", "then", "elif", "else", "while", "until", "do", "!", "coproc":
			i++
			continue
		case "--":
			i++
			continue
		}
		if isDynamicArg(a) {
			return argv[i:], splitPayloads, envAs, false
		}
		switch filepath.Base(a) {
		case "time":
			i++
			for i < len(argv) {
				a := argv[i]
				if a == "--" {
					i++
					break
				}
				if isDynamicArg(a) {
					return argv[i:], splitPayloads, envAs, true
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-o" || a == "--output" || a == "-f" || a == "--format" {
					if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
						return argv[i:], splitPayloads, envAs, true
					}
					i += 2
					continue
				}
				i++
			}
		case "env":
			i++
			rest, payloads, ea := skipEnvOperands(argv, i, envAs)
			envAs = ea
			splitPayloads = append(splitPayloads, payloads...)
			argv = rest
			i = 0
		case "command":
			start := i
			i++
			if isCommandQuery(argv[i:]) {
				return argv[start:], splitPayloads, envAs, false
			}
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				if isDynamicArg(argv[i]) {
					return argv[i:], splitPayloads, envAs, true
				}
				i++
			}
			i = skipDashDash(argv, i)
		case "builtin":
			i++
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				if isDynamicArg(argv[i]) {
					return argv[i:], splitPayloads, envAs, true
				}
				i++
			}
			i = skipDashDash(argv, i)
		case "exec":
			// bash exec [-cl] [-a name] [--] command (internal_getopt "cla:").
			var fc bool
			i, fc = skipExecArgs(argv, i+1)
			if fc {
				return argv[i:], splitPayloads, envAs, true
			}
		case "nohup":
			i++
			i = skipDashDash(argv, i)
		case "setsid":
			i++
			for i < len(argv) {
				a := argv[i]
				if a == "--" {
					i++
					break
				}
				if isDynamicArg(a) {
					return argv[i:], splitPayloads, envAs, true
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				i++
			}
		case "nice":
			i++
			for i < len(argv) {
				a := argv[i]
				if a == "--" {
					i++
					break
				}
				if isDynamicArg(a) {
					return argv[i:], splitPayloads, envAs, true
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-n" || a == "--adjustment" {
					if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
						return argv[i:], splitPayloads, envAs, true
					}
					i += 2 // separate value
					continue
				}
				i++
			}
		case "timeout":
			i++
			var fc bool
			i, fc = skipTimeoutArgs(argv, i)
			if fc {
				return argv[i:], splitPayloads, envAs, true
			}
		case "stdbuf":
			i++
			var fc bool
			i, fc = skipStdbufArgs(argv, i)
			if fc {
				return argv[i:], splitPayloads, envAs, true
			}
		case "busybox":
			i++
		case "ionice":
			i++
			var fc bool
			i, fc = skipIoniceArgs(argv, i)
			if fc {
				return argv[i:], splitPayloads, envAs, true
			}
		case "taskset":
			i++
			var fc bool
			i, fc = skipTasksetArgs(argv, i)
			if fc {
				return argv[i:], splitPayloads, envAs, true
			}
		case "chrt":
			i++
			var fc bool
			i, fc = skipChrtArgs(argv, i)
			if fc {
				return argv[i:], splitPayloads, envAs, true
			}
		case "strace", "ltrace":
			i++
			var fc bool
			i, fc = skipStraceArgs(argv, i)
			if fc {
				return argv[i:], splitPayloads, envAs, true
			}
		default:
			if i > len(argv) {
				i = len(argv)
			}
			return argv[i:], splitPayloads, envAs, false
		}
	}
	if i > len(argv) {
		i = len(argv)
		return argv[i:], splitPayloads, envAs, true
	}
	return argv[i:], splitPayloads, envAs, depth >= peelWrapperMaxSteps
}

// peelWrappersAndWrapperAliases is peelWrappers plus a bounded,
// repeated PATH-alias rewrite: every peeled head resolving to a wrapper
// binary (myenv -> env, mytimeout -> timeout, ...) is rewritten to the
// resolved wrapper name and peeled again (each alias level consumes one
// peelWrapperMaxSteps-bounded step), so a nested
// `foo --opt -- foo --opt -- CMD` cannot hide CMD behind a second alias
// the caller only unwrapped once (M-REV-2). env ops accumulate across
// all levels and the returned effPath replays them over pathEnv — each
// alias resolves under the PATH its own level's env ops install.
// Exhausted peels and alias chains hitting the bound return exhausted
// (fail-closed) like peelWrappers.
func peelWrappersAndWrapperAliases(argv []string, pathEnv string, caller callerIdentity) (head []string, envAs envAssignments, effPath string, exhausted bool) {
	cur := argv
	effPath = pathEnv
	for steps := 0; steps < peelWrapperMaxSteps; steps++ {
		h, _, ea, ex := peelWrappers(cur)
		envAs = envAs.merged(ea)
		effPath = ea.effectivePATHFrom(effPath)
		caller = caller.seededWith(ea)
		if ex || len(h) == 0 {
			return h, envAs, effPath, ex
		}
		hb := filepath.Base(h[0])
		// A PATH alias whose typed name is not a wrapper but resolves to
		// one (myenv -> env, mytimeout -> timeout) needs its options peeled
		// too: rewrite the head to the resolved wrapper and loop.
		if rb := canonicalResolvedBase(resolveHeadBase(h[0], effPath, caller.screenCwd())); rb != "" && rb != hb && isPeeledWrapperBase(rb) {
			cur = append([]string{rb}, h[1:]...)
			continue
		}
		return h, envAs, effPath, false
	}
	return cur, envAs, effPath, true
}

// skipTimeoutArgs consumes timeout's option arguments and its duration.
// failclosed reports a dynamic word in the option zone or the duration
// slot (timeout $(…) / timeout "$T"): the duration is mandatory, so a
// runtime split there shifts the whole command out of its slot.
func skipTimeoutArgs(argv []string, i int) (int, bool) {
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return i, true
		}
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
		if a == "-k" || a == "--kill-after" || a == "-s" || a == "--signal" {
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return i, true
			}
			i += 2
		} else {
			i++
		}
	}
	if i < len(argv) {
		if isDynamicArg(argv[i]) {
			return i, true // duration slot
		}
		i++ // duration
	}
	return skipDashDash(argv, i), false
}

// skipStdbufArgs consumes stdbuf's buffering options.
func skipStdbufArgs(argv []string, i int) (int, bool) {
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return i, true
		}
		if a == "--" {
			return i + 1, false
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
		if a == "-i" || a == "-o" || a == "-e" {
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return i, true
			}
			i += 2
		} else {
			i++
		}
	}
	return i, false
}

// skipIoniceArgs consumes ionice's -c N / -n N / -p PID / -t options.
func skipIoniceArgs(argv []string, i int) (int, bool) {
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return i, true
		}
		switch {
		case a == "--":
			return i + 1, false
		case a == "-c" || a == "-n" || a == "-p":
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return i, true
			}
			i += 2
		case a == "-t":
			i++
		case strings.HasPrefix(a, "-c") || strings.HasPrefix(a, "-n") || strings.HasPrefix(a, "-p"):
			i++ // -cN / -nN / -pPID glued
		case strings.HasPrefix(a, "-"):
			i++
		default:
			return i, false
		}
	}
	return i, false
}

// skipTasksetArgs consumes taskset's options and its CPU mask operand.
func skipTasksetArgs(argv []string, i int) (int, bool) {
	sawList := false // -c/--cpu-list seen: the mask is inside an option operand
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return i, true
		}
		switch {
		case a == "--":
			i++
			if sawList {
				return i, false
			}
			if i < len(argv) {
				if isDynamicArg(argv[i]) {
					return i, true
				}
				return i + 1, false
			}
			return i, false
		case a == "-c" || a == "--cpu-list":
			sawList = true
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return i, true
			}
			i += 2 // -c LIST operand
		case a == "-p" || a == "--pid":
			return len(argv), false // pid operand, no inner command
		case strings.HasPrefix(a, "--cpu-list="):
			sawList = true
			i++
		case strings.HasPrefix(a, "-"):
			i++
		default:
			if sawList {
				return i, false // mask already consumed; this is the command
			}
			return i + 1, false // the CPU mask operand consumed; next is the command
		}
	}
	return i, false
}

// skipChrtArgs consumes chrt's policy flags and its priority operand.
func skipChrtArgs(argv []string, i int) (int, bool) {
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return i, true
		}
		switch {
		case a == "--":
			i++
			if i < len(argv) {
				if isDynamicArg(argv[i]) {
					return i, true
				}
				return i + 1, false
			}
			return i, false
		case a == "-p" || a == "--pid":
			return len(argv), false // pid operand, no inner command
		case strings.HasPrefix(a, "-"):
			i++
		default:
			return i + 1, false // priority operand consumed; next is the command
		}
	}
	return i, false
}

// skipWatchArgs consumes watch's options and returns (idx, execMode,
// failclosed): idx is the first operand (the watched command words),
// execMode reports whether -x/--exec appeared — under it the operands
// are a direct exec argv, otherwise GNU watch joins them and runs
// `sh -c`. failclosed reports a dynamic word in the option zone (a
// runtime split can shift the watched command out of its slot).
func skipWatchArgs(argv []string, i int) (int, bool, bool) {
	execMode := false
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return i, execMode, true
		}
		if a == "--" {
			return i + 1, execMode, false
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		switch a {
		case "-x", "--exec":
			execMode = true
			i++
		case "-n", "--interval", "-q", "--equexit":
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return i, execMode, true
			}
			i += 2 // separate value operand
		default:
			if strings.HasPrefix(a, "--") {
				i++ // other long options (--differences, --chgexit, ...)
				break
			}
			// Short-option cluster: 'x' sets exec mode; 'n'/'q' carry a
			// value — the cluster tail or the next argv — and end the
			// cluster (-dn 1, -dx, -n1, -q5).
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'x':
					execMode = true
				case 'n', 'q':
					if j+1 >= len(a) {
						if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
							return i, execMode, true
						}
						i++ // value operand is the next argv
					}
					j = len(a)
				}
			}
			i++
		}
	}
	return i, execMode, false
}

// skipFlockArgs consumes flock's options plus its lock file/fd operand and
// returns (cmdIdx, cmdText): when the operand is followed by -c/--command
// (or --command=...), cmdText is that shell string and cmdIdx is len(argv)
// (there is no argv head to recurse into — the caller screens the text);
// otherwise cmdIdx points at the command argv after the lock operand.
func skipFlockArgs(argv []string, i int) (int, string) {
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return len(argv), cmdSubPlaceholder
		}
		switch {
		case a == "--":
			i++
			if i < len(argv) {
				if isDynamicArg(argv[i]) {
					return len(argv), cmdSubPlaceholder
				}
				i++
			}
			return i, ""
		case a == "-c" || a == "--command":
			if i+1 < len(argv) {
				return len(argv), argv[i+1]
			}
			return len(argv), ""
		case strings.HasPrefix(a, "--command="):
			return len(argv), a[len("--command="):]
		case a == "-w" || a == "--timeout" || a == "-E" || a == "--conflict-exit-code" ||
			a == "-F" || a == "--fcntl" || a == "-d" || a == "--fd":
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) && !isSplitSafeDynamicWord(argv[i+1]) {
				return len(argv), cmdSubPlaceholder
			}
			i += 2
		case a == "-o" || a == "--close" || a == "-s" || a == "--shared" ||
			a == "-x" || a == "--exclusive" || a == "-u" || a == "--unlock" ||
			a == "-n" || a == "--nonblock" || a == "-v" || a == "--verbose":
			i++
		case strings.HasPrefix(a, "-"):
			i++
		default:
			i++
			if i < len(argv) && (argv[i] == "-c" || argv[i] == "--command") {
				if i+1 < len(argv) {
					return len(argv), argv[i+1]
				}
				return len(argv), ""
			}
			if i < len(argv) && strings.HasPrefix(argv[i], "--command=") {
				return len(argv), argv[i][len("--command="):]
			}
			return i, ""
		}
	}
	return i, ""
}

// skipStraceArgs consumes strace/ltrace options; the remainder is the traced
// command. Boolean options (fork-following, counting, timestamps, quiet,
// syscall-info) consume ONE slot — treating -f as value-carrying would eat
// the traced command itself (`strace -f pig` must peel to `pig`). Only
// options that genuinely take a separate value consume two slots, and only
// when they stand alone (glued -eexpr/-ofile/-p123 carry the value inside).
func skipStraceArgs(argv []string, i int) (int, bool) {
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) {
			return i, true
		}
		if a == "--" {
			return i + 1, false
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
		switch a {
		case "-e", "-o", "-p", "-s", "-u", "-E", "-a", "-b", "-O", "-S", "-I", "-P",
			"-X", "-U",
			"--trace", "--output", "--attach", "--string-limit", "--user",
			"--env", "--columns", "--const-print-style", "--summary-columns",
			"--trace-path", "--signal":
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return i, true
			}
			i += 2 // separate value operand
		default:
			i++ // boolean (-f/-ff/-c/-C/-t/-tt/-ttt/-T/-r/-v/-q/-y) or glued value
		}
	}
	return i, false
}

// isAssignWord reports whether word is a bare KEY=VAL assignment prefix.
func isAssignWord(word string) bool {
	k := strings.IndexByte(word, '=')
	if k <= 0 || strings.HasPrefix(word, "-") {
		return false
	}
	for j := 0; j < k; j++ {
		c := word[j]
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || j > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// isCommandQuery reports whether the args after `command` are a pure
// resolution query: an option run (up to `--` or the first non-option
// operand) made only of p/v/V letters that contains at least one v/V.
// `command -v pig`, `command -V rm`, `command -pv pig`, `command -Vp pig`,
// `command -p -v pig` all query resolution without executing; `command pig`,
// `command -p pig` and `command pig -v` wrap a real command head.
func isCommandQuery(args []string) bool {
	sawV := false
	for _, a := range args {
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			break // option terminator or first operand ends the option run
		}
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 'v', 'V':
				sawV = true
			case 'p':
			default:
				return false
			}
		}
	}
	return sawV
}

// skipDashDash consumes a single "--" option terminator when present.
func skipDashDash(argv []string, i int) int {
	if i < len(argv) && argv[i] == "--" {
		return i + 1
	}
	return i
}

const envUnknownLongPrefix = "__ctx_env_unknown__:"

func envSplitLong(a string) (name, val string, hasVal bool) {
	s := strings.TrimPrefix(a, "--")
	if eq := strings.IndexByte(s, '='); eq >= 0 {
		return s[:eq], s[eq+1:], true
	}
	return s, "", false
}

// envMatchLong returns the canonical GNU env long option name for a unique
// prefix of name, or "" when unknown/ambiguous.
func envMatchLong(name string) string {
	candidates := []string{
		"ignore-environment", "null", "unset", "chdir", "split-string",
		"argv0", "block-signal", "default-signal", "ignore-signal",
		"list-signal-handling", "debug", "help", "version",
	}
	var hits []string
	for _, c := range candidates {
		if c == name || strings.HasPrefix(c, name) {
			hits = append(hits, c)
		}
	}
	if len(hits) == 1 {
		return hits[0]
	}
	return ""
}

// envSEscape decodes one GNU env -S backslash escape at s[i] ('\\' + c).
// Measured against coreutils 9.7: \_ is a WORD SEPARATOR, \t \n \r \v \f
// are literal bytes inside the current word, \c truncates the rest of the
// payload (and is an error inside double quotes), \" \' \\ \$ \# produce
// the literal byte, and every other escape is invalid (fail closed).
// Returns (emit byte, action) — action 'w' write byte, 's' word separator,
// 'c' truncate rest of payload, 'e' invalid escape.
func envSEscape(c byte, inDQ bool) (byte, byte) {
	switch c {
	case '_':
		if inDQ {
			return ' ', 'w' // inside dq \_ is a literal space
		}
		return 0, 's'
	case 't':
		return '\t', 'w'
	case 'n':
		return '\n', 'w'
	case 'r':
		return '\r', 'w'
	case 'v':
		return '\v', 'w'
	case 'f':
		return '\f', 'w'
	case 'c':
		if inDQ {
			return 0, 'e' // GNU rejects "\c" inside double quotes
		}
		return 0, 'c'
	case '"', '\'', '\\', '$', '#':
		return c, 'w'
	}
	return 0, 'e'
}

// splitEnvSPayload splits an env -S/--split-string payload into the argv
// GNU env would re-parse: whitespace and \_ split words, '#' outside a
// word starts a comment, single/double quotes group, GNU backslash escapes
// decode per envSEscape (unknown escapes fail closed like GNU does), and
// every $/${}/$(..)/`..` sequence inside or outside double quotes emits a
// placeholder word (unquoted dynamics stay splittable markers; a whole-$
// word emits cmdSubPlaceholder so head/option checks see it as dynamic).
// Quote/escape errors return (nil, true) so callers fail closed.
func splitEnvSPayload(s string) ([]string, bool) {
	var words []string
	var b strings.Builder
	inWord := false
	emit := func() {
		if inWord {
			words = append(words, b.String())
			b.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch c {
		case ' ', '\t', '\n':
			emit()
			i++
		case '#':
			if inWord {
				b.WriteByte(c)
				i++
				continue
			}
			return words, false // GNU: '#' at a word start comments out the rest
		case '\\':
			if i+1 >= len(s) {
				return nil, true
			}
			b_, act := envSEscape(s[i+1], false)
			switch act {
			case 'e':
				return nil, true
			case 'c':
				emit()
				return words, false // \c truncates the rest of the payload
			case 's':
				emit()
				i += 2
				continue
			}
			inWord = true
			b.WriteByte(b_)
			i += 2
		case '\'':
			inWord = true
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i >= len(s) {
				return nil, true // unterminated quote
			}
			i++
		case '"':
			inWord = true
			i++
			for i < len(s) && s[i] != '"' {
				ch := s[i]
				if ch == '\\' && i+1 < len(s) {
					b_, act := envSEscape(s[i+1], true)
					switch act {
					case 'e':
						return nil, true
					case 'c', 's':
						// unreachable: inDQ maps those to 'e'/'w'
						return nil, true
					}
					b.WriteByte(b_)
					i += 2
					continue
				}
				if ch == '$' || ch == '`' {
					// "$@" / "${arr[@]}" / "${!prefix@}" / "${x:-$@}" expand to
					// one argv word per element even inside double quotes, so they
					// are NOT split-safe — emit the splittable cmdSubPlaceholder,
					// not cmdSubPlaceholderQuoted ("$*"/"$$" stay single-word).
					ph := cmdSubPlaceholderQuoted
					switch {
					case ch == '$' && i+1 < len(s) && s[i+1] == '@':
						ph = cmdSubPlaceholder
					case ch == '$' && i+1 < len(s) && s[i+1] == '{':
						if body, ok := envSDollarBraceBody(s, i); ok {
							if envSBraceBodySplits(body) {
								ph = cmdSubPlaceholder
							}
						}
					}
					b.WriteString(ph)
					i += splitEnvSubLen(s, i)
					continue
				}
				b.WriteByte(ch)
				i++
			}
			if i >= len(s) {
				return nil, true
			}
			i++
		case '$', '`':
			inWord = true
			b.WriteString(cmdSubPlaceholder)
			i += splitEnvSubLen(s, i)
		default:
			inWord = true
			b.WriteByte(c)
			i++
		}
	}
	emit()
	return words, false
}

// splitEnvSubLen returns the byte length of a $/${}/$(..)/`..` expansion
// starting at s[i] (at least 1), scanning nested quotes/parens loosely so
// the expansion is consumed whole rather than split mid-way.
func splitEnvSubLen(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	if s[i] == '`' {
		for j := i + 1; j < len(s); j++ {
			if s[j] == '`' {
				return j + 1 - i
			}
			if s[j] == '\\' {
				j++
			}
		}
		return len(s) - i
	}
	// s[i] == '$'
	if i+1 >= len(s) {
		return 1
	}
	switch s[i+1] {
	case '(', '{':
		close_ := byte(')')
		if s[i+1] == '{' {
			close_ = '}'
		}
		depth := 0
		for j := i + 1; j < len(s); j++ {
			ch := s[j]
			if ch == '\\' {
				j++
				continue
			}
			if ch == '\'' {
				for j+1 < len(s) && s[j+1] != '\'' {
					j++
				}
				j++
				continue
			}
			if ch == '"' {
				for j+1 < len(s) && s[j+1] != '"' {
					j++
				}
				j++
				continue
			}
			if ch == s[i+1] {
				depth++
			} else if ch == close_ {
				depth--
				if depth == 0 {
					return j + 1 - i
				}
			}
		}
		return len(s) - i
	default:
		// $VAR: consume the identifier.
		j := i + 1
		for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' ||
			s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
			j++
		}
		return j - i
	}
}

// envSDollarBraceBody returns the inner body of a `${...}` expansion
// starting at s[i] (s[i]=='$', s[i+1]=='{'), or ("", false) when the braces
// never close. The body is what envSBraceBodySplits inspects.
func envSDollarBraceBody(s string, i int) (string, bool) {
	n := splitEnvSubLen(s, i)
	// splitEnvSubLen consumed `$` + `{` + body + `}` => n-3 inner bytes.
	if n < 3 || i+n > len(s) || s[i+n-1] != '}' {
		return "", false
	}
	return s[i+2 : i+n-1], true
}

// envSBraceBodySplits reports whether a `${body}` expansion (inside double
// quotes) can field-split into multiple argv words — the @-split forms.
// "${#...}" (length, prefix '#') is always a single integer word and is
// excluded. Matches the AST-side paramExpSplitsInDblQuotes.
func envSBraceBodySplits(body string) bool {
	if body == "" || strings.HasPrefix(body, "#") {
		return false // ${#x} length is one word
	}
	// ${@...}    — $@ family: ${@}, ${@:1}, ${@/#a/b}, ${@@Q}
	if strings.HasPrefix(body, "@") {
		return true
	}
	// ${arr[@]} / ${!arr[@]} — element-wise subscript split.
	if strings.Contains(body, "[@]") {
		return true
	}
	// ${!prefix@} — variable-name list, one word per name.
	if strings.HasPrefix(body, "!") && strings.HasSuffix(body, "@") && len(body) > 2 {
		return true
	}
	// ${x:-$@} / ${x:-${@}} / ${x:-"$@"} — nested @-split in the default:
	// any literal "$@" or "${@" inside the body carries the split up.
	if strings.Contains(body, "$@") || strings.Contains(body, "${@") {
		return true
	}
	return false
}

// skipEnvOperands consumes env's own arguments (options and NAME=val
// assignments) starting at i and returns the index of the command env would
// exec plus any -S/--split-string payloads for the caller to screen (the
// text is itself a shell-ish command line). NAME=val assignments and
// -u/--unset operands are recorded into envAs for the execution-hook env
// screen. Short clusters are scanned character-by-character; bare "-" is
// treated as -i; unknown shorts/longs fail closed via envUnknownLongPrefix.
func skipEnvOperands(argv []string, i int, envAs envAssignments) ([]string, []string, envAssignments) {
	var payloads []string
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) && !isAssignWord(a) {
			payloads = append(payloads, envUnknownLongPrefix+"dynamic option")
			return argv[i:], payloads, envAs
		}
		switch {
		case a == "--":
			return argv[i+1:], payloads, envAs
		case a == "-":
			envAs.ops = append(envAs.ops, envOp{kind: 'c'})
			i++
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := envSplitLong(a)
			switch envMatchLong(name) {
			case "ignore-environment":
				envAs.ops = append(envAs.ops, envOp{kind: 'c'})
				i++
			case "null", "list-signal-handling", "debug", "help", "version":
				i++
			case "unset":
				if hasVal {
					envAs.ops = append(envAs.ops, envOp{kind: 'u', key: val})
					i++
				} else if i+1 < len(argv) {
					envAs.ops = append(envAs.ops, envOp{kind: 'u', key: argv[i+1]})
					i += 2
				} else {
					payloads = append(payloads, envUnknownLongPrefix+"missing operand "+a)
					i++
				}
			case "chdir":
				if hasVal {
					envAs.ops = append(envAs.ops, envOp{kind: 'd', value: val})
					i++
				} else if i+1 < len(argv) {
					if isDynamicArg(argv[i+1]) && !isSplitSafeDynamicWord(argv[i+1]) {
						payloads = append(payloads, envUnknownLongPrefix+"dynamic option")
						return argv[i+1:], payloads, envAs
					}
					envAs.ops = append(envAs.ops, envOp{kind: 'd', value: argv[i+1]})
					i += 2
				} else {
					payloads = append(payloads, envUnknownLongPrefix+"missing operand "+a)
					i++
				}
			case "argv0":
				if hasVal {
					i++
				} else if i+1 < len(argv) {
					if isDynamicArg(argv[i+1]) && !isSplitSafeDynamicWord(argv[i+1]) {
						payloads = append(payloads, envUnknownLongPrefix+"dynamic option")
						return argv[i+1:], payloads, envAs
					}
					i += 2
				} else {
					payloads = append(payloads, envUnknownLongPrefix+"missing operand "+a)
					i++
				}
			case "split-string":
				var payload string
				havePayload := false
				if hasVal {
					payload, havePayload = val, true
					i++
				} else if i+1 < len(argv) {
					payload, havePayload = argv[i+1], true
					i += 2
				} else {
					i++
				}
				if !havePayload {
					payloads = append(payloads, envUnknownLongPrefix+"-S/--split-string")
					continue
				}
				if isDynamicArg(payload) {
					payloads = append(payloads, envUnknownLongPrefix+"dynamic option")
					continue
				}
				words, bad := splitEnvSPayload(payload)
				if bad {
					payloads = append(payloads, envUnknownLongPrefix+"-S/--split-string")
					continue
				}
				rest := append(append([]string{}, words...), argv[i:]...)
				rem, moreP, envAs := skipEnvOperands(rest, 0, envAs)
				payloads = append(payloads, moreP...)
				return rem, payloads, envAs
			case "block-signal", "default-signal", "ignore-signal":
				i++
			default:
				payloads = append(payloads, envUnknownLongPrefix+a)
				i++
			}
		case strings.HasPrefix(a, "-"):
			consumedNext := false
			unknown := false
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'i':
					envAs.ops = append(envAs.ops, envOp{kind: 'c'})
				case '0', 'v':
				case 'u', 'C', 'S', 'a':
					opt := a[j]
					var optVal string
					hasOptVal := false
					if j+1 < len(a) {
						optVal = a[j+1:]
						hasOptVal = true
						j = len(a)
					} else if i+1 < len(argv) {
						optVal = argv[i+1]
						hasOptVal = true
						consumedNext = true
					}
					if !hasOptVal {
						payloads = append(payloads, envUnknownLongPrefix+"missing operand "+a)
						unknown = true
						j = len(a)
						break
					}
					switch opt {
					case 'u':
						envAs.ops = append(envAs.ops, envOp{kind: 'u', key: optVal})
					case 'C':
						if consumedNext && isDynamicArg(optVal) && !isSplitSafeDynamicWord(optVal) {
							payloads = append(payloads, envUnknownLongPrefix+"dynamic option")
							unknown = true
							j = len(a)
							break
						}
						envAs.ops = append(envAs.ops, envOp{kind: 'd', value: optVal})
					case 'a':
						if consumedNext && isDynamicArg(optVal) && !isSplitSafeDynamicWord(optVal) {
							payloads = append(payloads, envUnknownLongPrefix+"dynamic option")
							unknown = true
							j = len(a)
						}
					case 'S':
						start := i
						if consumedNext {
							start = i + 1
						}
						words, bad := splitEnvSPayload(optVal)
						if bad || isDynamicArg(optVal) {
							payloads = append(payloads, envUnknownLongPrefix+"-S/--split-string")
							j = len(a)
							break
						}
						rest := append(append([]string{}, words...), argv[start+1:]...)
						rem, moreP, envAs := skipEnvOperands(rest, 0, envAs)
						payloads = append(payloads, moreP...)
						return rem, payloads, envAs
					}
				default:
					payloads = append(payloads, envUnknownLongPrefix+a)
					unknown = true
					j = len(a)
				}
			}
			if consumedNext {
				i += 2
			} else {
				i++
			}
			if unknown {
				return argv[i:], payloads, envAs
			}
		case isAssignWord(a):
			envAs.addAssign(a)
			i++
		default:
			return argv[i:], payloads, envAs
		}
	}
	return argv[i:], payloads, envAs
}

// unwrapShellArgv reports whether argv (starting at a resolved command head)
// is a `shell -c`/`shell -lc` shape: argv[0] a POSIX-ish shell and an option
// bundle containing 'c' before the first non-flag argument. The code is
// argv[i+1] when a next argument exists — for a cluster like -ce the 'c'
// consumes the NEXT argv as the script, leaving the tail ("e") as flags; a
// non-letter tail after 'c' (`-c"pig"` glued spelling) is prepended to that
// script as an extra line. Only when no next argv exists does a non-empty
// tail stand alone as the script (`["sh","-c\"pig\""]`). -o/+o option
// values are skipped so `sh -o errexit -c 'pig'` unwraps.
func unwrapShellArgv(argv []string) (shellText string, has bool) {
	if len(argv) < 2 {
		return "", false
	}
	switch filepath.Base(argv[0]) {
	case "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash":
	default:
		return "", false
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if isDynamicArg(a) {
			return "", false // let hasDynamicInterpOption / peel catch it
		}
		if a == "--" {
			return "", false
		}
		if strings.HasPrefix(a, "--") {
			name, val, hasVal := a[2:], "", false
			if k := strings.IndexByte(name, '='); k >= 0 {
				name, val, hasVal = name[:k], name[k+1:], true
			}
			switch name {
			case "rcfile", "init-file":
				if !hasVal {
					if i+1 >= len(argv) {
						return "", false
					}
					i++
					val = argv[i]
				}
				if val != "/dev/null" {
					return "", false // external rc is unreviewed code
				}
				continue
			default:
				continue
			}
		}
		if a == "-o" || a == "+o" || a == "-O" || a == "+O" {
			i++ // consumes the option NAME
			continue
		}
		if (strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+")) && len(a) > 1 {
			plus := a[0] == '+'
			for j := 1; j < len(a); j++ {
				ch := a[j]
				if ch == 'c' && !plus {
					tail := a[j+1:]
					if isLetterOnly(tail) {
						// Flag model (R14): letters after c are flags, not
						// code — `sh -ce 'x'` is -c -e 'x'. A trailing -o/-O
						// inside the tail still consumes the next argv as
						// its option name (`sh -co vi 'x'`: vi feeds -o and
						// 'x' is the program). The letter tail is ambiguous
						// (ksh/zsh read -cWORD as glued code) so it is
						// prepended to the screened text, never dropped.
						for k := j + 1; k < len(a); k++ {
							if a[k] == 'o' || a[k] == 'O' {
								if k+1 >= len(a) && i+1 < len(argv) {
									i++
								}
								break
							}
						}
						if i+1 < len(argv) {
							return tail + "\n" + argv[i+1], true
						}
						return tail, true // bare -cWORD: ambiguous glued operand — screen it
					}
					// A non-letter tail is an ambiguous glued spelling
					// (zsh-style -c= or -c"x"); screen it as a prepended
					// line along with the real operand — fail closed.
					if i+1 < len(argv) {
						if tail != "" {
							return tail + "\n" + argv[i+1], true
						}
						return argv[i+1], true
					}
					if tail != "" {
						return tail, true
					}
					return "", false
				}
				if ch == 'o' || ch == 'O' {
					// valued at end of cluster
					if j+1 >= len(a) {
						i++ // next argv is the option name
					}
					break
				}
			}
			continue
		}
		return "", false
	}
	return "", false
}

// isLetterOnly reports whether s is a non-empty run of ASCII letters (a pure
// short-flag bundle like "e" or "xe"). Anything else — quotes, spaces,
// metacharacters — is script text.
func isLetterOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// unwrapInterpreterInline extracts inline code handed to a non-shell
// interpreter: python[3[.x]] -c (after its option flags; -m pip|venv|
// ensurepip|compileall reported as "python-module"), node/nodejs -e /
// --eval / -p / --print, ts-node/tsx/bun -e/--eval, perl -e/-E, ruby -e,
// php -r. Returns (language, code, true) when a spelling was found.
func unwrapInterpreterInline(argv []string) (lang, code string, ok bool) {
	if len(argv) == 0 {
		return "", "", false
	}
	base := filepath.Base(argv[0])
	if base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3") {
		for i := 1; i < len(argv); i++ {
			a := argv[i]
			if a == "--" {
				return "", "", false // -- terminates options; the next operand is a script file
			}
			if a == "-c" {
				if i+1 < len(argv) {
					return "python", argv[i+1], true
				}
				return "", "", false
			}
			if a == "-m" {
				if i+1 < len(argv) {
					return "python-module", argv[i+1], true
				}
				return "", "", false
			}
			if a == "-W" || a == "-X" {
				i++
				continue
			}
			if strings.HasPrefix(a, "-") && len(a) > 1 {
				// Bundled short options may carry inline code or the module
				// name: -cCODE, -ucCODE, -mMODULE, -umMODULE.
				for j := 1; j < len(a); j++ {
					switch a[j] {
					case 'c':
						if tail := a[j+1:]; tail != "" {
							return "python", tail, true
						}
						if i+1 < len(argv) {
							return "python", argv[i+1], true
						}
						return "", "", false
					case 'm':
						if tail := a[j+1:]; tail != "" {
							return "python-module", tail, true
						}
						if i+1 < len(argv) {
							return "python-module", argv[i+1], true
						}
						return "", "", false
					case 'W', 'X':
						// -W arg / -X arg take a value — glued (-Wmodule, -Xutf8)
						// or the next argv. Either way the cluster scan must END
						// here: continuing would misread letters inside the option
						// value (-Wmodule's 'm' looking like -m odule) and miss a
						// later -c.
						if j+1 >= len(a) {
							i++
						}
						j = len(a)
					}
				}
				continue
			}
			return "", "", false
		}
		return "", "", false
	}
	// The remaining interpreters share interpCodeSlots' option model so the
	// xargs feed analysis and the inline unwrap cannot disagree: clusters
	// (`node -pe`, `perl -eA -eB`, `ruby -e`), glued code tails, --eval /
	// --require-style longs and dynamic operand words all behave identically.
	switch base {
	case "node", "nodejs", "ts-node", "tsx", "bun", "perl", "ruby", "php":
		var frags []string
		for _, s := range interpCodeSlots(argv) {
			if s.flagOnly || s.text == "" {
				continue
			}
			frags = append(frags, s.text)
		}
		if len(frags) == 0 {
			return "", "", false
		}
		lang := map[string]string{
			"node": "javascript", "nodejs": "javascript",
			"ts-node": "javascript", "tsx": "javascript", "bun": "javascript",
			"perl": "perl", "ruby": "ruby", "php": "php",
		}[base]
		return lang, strings.Join(frags, "\n"), true
	}
	return "", "", false
}
