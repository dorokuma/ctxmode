package main

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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
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
	redirectFile string        // "" when every redirection was safe (or none existed)
	heredocText  []heredocBody // bodies queued by <<DELIM on this command line
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
	segs, ok := parseSubagentShellASTEnv(code, 0, false, false, envTaint)
	if !ok {
		if len(segs) > 0 {
			return segs
		}
		return []shellSegment{{depthExceeded: true}}
	}
	return segs
}

// splitShellSegmentsBash parses bash/zsh/ksh/mksh -c payloads with LangBash fail-closed.
func splitShellSegmentsBash(code string) []shellSegment {
	return splitShellSegmentsBashEnv(code, nil)
}

// splitShellSegmentsBashEnv is splitShellSegmentsBash with env taint.
func splitShellSegmentsBashEnv(code string, envTaint map[string]bool) []shellSegment {
	segs, ok := parseSubagentShellASTEnv(code, 0, false, true, envTaint)
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
	kind  byte   // 'a' assign, 'u' unset, 'c' clearInherit
	key   string // variable name (assign/unset only)
	value string // assigned value (assign only)
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
	// sbx internal child-process spec: a forged value makes sbx execute the
	// injected JSON spec instead of the CLI args (S-NEW-2).
	"PI_SANDBOX_INTERNAL_CHILD_SPEC": true,
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
	// PI_SANDBOX_* carries sbx internal child-process state
	// (PI_SANDBOX_INTERNAL_CHILD_SPEC); a sub-agent must never forge it.
	if strings.HasPrefix(key, "PI_SANDBOX_") {
		return true
	}
	switch key {
	case "GIT_DIR", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE",
		"GIT_TEMPLATE_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
		"NODE_PATH", "PERL5LIB", "PERLLIB", "RUBYLIB",
		// The CTXMODE_* identity/audit keys a role-carrying caller must not
		// rewrite — kept in sync with executor.go roleIdentityEnvKeys so an
		// env prefix / export / sbx --env hits the same wall as args.Env.
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
// builtin, sbx (flag-style options, --env screened like env operands),
// shell reserved/modifier words (`if`/`then`/`elif`/`else`/`while`/
// `until`/`do`/`coproc`/`time`/`!`), and `--` terminators. watch, flock,
// script and sudo/doas are NOT peeled here — they need stdin-context and
// privilege semantics, so the downstream peelResolvedSegDepth /
// stdinProgramHeadDepth helpers unwrap them. Recursion is bounded by
// peelWrapperMaxSteps (bare KEY=VAL prefixes do not consume steps); a
// chain that never resolves returns an index past the end.

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

// screenSbxEnvValue screens one `sbx --env`/`--env=` operand and records
// it into envAs. The real sbx stringSlice.Set splits each value on `,` and
// trims every segment, so a single argv slot can inject several KEY=VAL
// assignments — screening the whole word as one assignment would let
// `A=1,PATH=/x` smuggle a PATH (or sentinel) write past the env screens.
// Returns false when any segment must fail closed: an empty segment (the
// real sbx silently drops it, but rejecting is simpler and safer), a
// dynamic word, a non-KEY=VAL word, or a sentinelTrustVars key (HOME/PWD/
// TMPDIR/IFS re-base the trusted path anchors the env screen relies on).
func screenSbxEnvValue(val string, envAs *envAssignments) bool {
	if val == "" {
		return false
	}
	for _, rawPart := range strings.Split(val, ",") {
		part := strings.TrimSpace(rawPart)
		if part == "" || isDynamicArg(part) || !isAssignWord(part) {
			return false
		}
		if sentinelTrustVars[part[:strings.IndexByte(part, '=')]] {
			return false
		}
		envAs.addAssign(part)
	}
	return true
}

func peelWrappers(argv []string) (headArgv []string, splitPayloads []string, envAs envAssignments, exhausted bool) {
	i := 0
	depth := 0
	for ; depth < peelWrapperMaxSteps && i < len(argv); depth++ {
		a := argv[i]
		if isAssignWord(a) {
			envAs.addAssign(a)
			i++
			depth-- // bare KEY=VAL prefixes do not consume a wrapper step
			continue
		}
		if shellNoopWords[a] {
			if i+1 >= len(argv) {
				return argv[len(argv):], splitPayloads, envAs, false // trailing `}`/`fi`/`done`
			}
			i++ // leading `{` / `(` group opener: peel to the inner head
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
			// Dynamic word in head position: stop peeling so peelResolvedSegDepth
			// can return "dynamic command head". Wrapper option loops have their
			// own isDynamicArg->exhausted checks.
			return argv[i:], splitPayloads, envAs, false
		}
		switch filepath.Base(a) {
		case "time":
			// Bash reserved word AND /usr/bin/time: peel its options
			// (-p/-v/--verbose/--portability/-a boolean; -o FILE/--output
			// FILE/-f FMT/--format FMT two-slot; --output=*/--format=*
			// single-slot) so `time -v pig` peels to `pig`.
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
					i += 2 // separate value
					continue
				}
				i++ // -p/-v/-a/--verbose/--portability/--output=*/--format=*
			}
		case "env":
			i++
			rest, payloads, ea := skipEnvOperands(argv, i, envAs)
			envAs = ea
			splitPayloads = append(splitPayloads, payloads...)
			// -S re-parses payload words INTO argv: continue peeling on the
			// residual argv (may be a new slice when -S injected words).
			argv = rest
			i = 0
		case "command":
			start := i
			i++
			// `command` followed by a pure query option run (-v/-V, with
			// optional -p) reports the command path/type without executing
			// it: keep `command` as the resolved head so peelResolvedDepth
			// can allow it outright. Anything else peels to the real head.
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
			// builtin has no -v/-V query semantics: it always wraps a real
			// builtin name, so peel its option run to the command head.
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
			// setsid [-c|-f|-w|--ctty|--fork|--wait] [--] cmd: its short
			// options are all boolean single-slot flags; peel until `--` or
			// the first non-option operand (the command).
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
			// nice [-n N|--adjustment N|-N|--adjustment=N] [--] cmd: loop
			// through every leading option, not just the first.
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
				i++ // -nN / -n-N / --adjustment=N / -N glued level / boolean
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
		case "sbx":
			// sbx is a Go flag.FlagSet tool: single- AND double-dash option
			// spellings work (-preset/--preset, -env/--env, --flag=val /
			// -flag=val and the two-slot --flag val forms), and a bare `--`
			// ends option parsing so the NEXT word is the inner command head.
			// The flag table mirrors the real sbx parseArgs
			// (pi-extensions/go/sandbox/cmd/sbx): value options
			// preset/workdir/ro/rw/exec/reviewer/report-to/env, booleans
			// deny-net/best-effort (+check/-version as pure queries below).
			// Every other `-` word fails closed rather than guessing its
			// arity — an unknown flag could consume the slot meant for the
			// inner command and smuggle it past the head screens
			// ([pattern:sbx-wrapper-unwrap-asymmetry]).
			start := i
			i++
			if len(argv[start:]) == 2 &&
				(isPureQueryInvocation(argv[start:]) || argv[start+1] == "-check" ||
					argv[start+1] == "--check" || argv[start+1] == "-version") {
				// `sbx -h`/`sbx --version`/`sbx --check`: prints and exits,
				// nothing unwraps — keep `sbx` as the head like `command -v`.
				return argv[start:], splitPayloads, envAs, false
			}
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
					break // first operand: the inner command head
				}
				// Strip one or two leading dashes; Go's flag package accepts
				// both, but three or more is not a flag spelling it recognises.
				name := a
				name = strings.TrimPrefix(name, "-")
				name = strings.TrimPrefix(name, "-")
				if strings.HasPrefix(name, "-") {
					return argv[i:], splitPayloads, envAs, true
				}
				if strings.HasPrefix(name, "env=") {
					// --env=KEY=VAL[,KEY=VAL...] glued form: screen each
					// comma-split assignment like an env operand.
					if !screenSbxEnvValue(name[len("env="):], &envAs) {
						return argv[i:], splitPayloads, envAs, true
					}
					i++
					continue
				}
				switch name {
				case "env":
					if i+1 >= len(argv) {
						return argv[i:], splitPayloads, envAs, true
					}
					if !screenSbxEnvValue(argv[i+1], &envAs) {
						return argv[i:], splitPayloads, envAs, true
					}
					i += 2
				case "preset", "workdir", "ro", "rw", "exec", "reviewer", "report-to":
					// The value slot itself must be screened: a dynamic word
					// consumed unchecked can split at runtime and shift the inner
					// command out of its slot (M-REV-1).
					if i+1 >= len(argv) || isDynamicArg(argv[i+1]) {
						return argv[i:], splitPayloads, envAs, true
					}
					i += 2
				case "deny-net", "best-effort":
					i++
				default:
					// Known =glued value options consume one slot; Go bool flags
					// also accept the =glued spelling (--deny-net=false).
					switch {
					case strings.HasPrefix(name, "preset="), strings.HasPrefix(name, "workdir="),
						strings.HasPrefix(name, "ro="), strings.HasPrefix(name, "rw="),
						strings.HasPrefix(name, "exec="), strings.HasPrefix(name, "reviewer="),
						strings.HasPrefix(name, "report-to="),
						strings.HasPrefix(name, "deny-net="), strings.HasPrefix(name, "best-effort="):
						i++
					default:
						return argv[i:], splitPayloads, envAs, true // unknown flag: fail closed
					}
				}
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

// peelWrappersAndSbxAliases is peelWrappers plus a bounded, repeated
// `foo -> sbx` PATH-alias rewrite: every peeled head resolving to sbx is
// rewritten to `sbx` and peeled again (each alias level consumes one
// peelWrapperMaxSteps-bounded step), so a nested
// `foo --deny-net -- foo --deny-net -- CMD` cannot hide CMD behind a
// second alias the caller only unwrapped once (M-REV-2). env ops
// accumulate across all levels and the returned effPath replays them
// over pathEnv — each alias resolves under the PATH its own level's
// env ops install. Exhausted peels and alias chains hitting the bound
// return exhausted (fail-closed) like peelWrappers.
func peelWrappersAndSbxAliases(argv []string, pathEnv string) (head []string, envAs envAssignments, effPath string, exhausted bool) {
	cur := argv
	effPath = pathEnv
	for steps := 0; steps < peelWrapperMaxSteps; steps++ {
		h, _, ea, ex := peelWrappers(cur)
		envAs = envAs.merged(ea)
		effPath = ea.effectivePATHFrom(effPath)
		if ex || len(h) == 0 {
			return h, envAs, effPath, ex
		}
		hb := filepath.Base(h[0])
		// A PATH alias whose typed name is not a wrapper but resolves to
		// one (foo -> sbx, myenv -> env) needs its options peeled too:
		// rewrite the head to the resolved wrapper and loop.
		if rb := canonicalResolvedBase(resolveHeadBase(h[0], effPath)); rb != "" && rb != hb && isPeeledWrapperBase(rb) {
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
			return i + 1, false
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
			return i + 1, false
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
			// Dynamic option/lock/command in flock zone → treat as code payload.
			return len(argv), cmdSubPlaceholder
		}
		switch {
		case a == "--":
			return i + 1, ""
		case a == "-c" || a == "--command":
			if i+1 < len(argv) {
				return len(argv), argv[i+1]
			}
			return len(argv), ""
		case strings.HasPrefix(a, "--command="):
			return len(argv), a[len("--command="):]
		case a == "-w" || a == "--timeout" || a == "-E" || a == "--conflict-exit-code":
			i += 2
		case a == "-o" || a == "--close" || a == "-s" || a == "--shared" ||
			a == "-x" || a == "--exclusive" || a == "-u" || a == "--unlock" ||
			a == "-n" || a == "--nonblock" || a == "-v" || a == "--verbose":
			i++
		case strings.HasPrefix(a, "-"):
			i++
		default:
			i++ // lock operand (file or fd) consumed
			if i < len(argv) && (argv[i] == "-c" || argv[i] == "--command") {
				if i+1 < len(argv) {
					return len(argv), argv[i+1]
				}
				return len(argv), ""
			}
			if i < len(argv) && strings.HasPrefix(argv[i], "--command=") {
				return len(argv), argv[i][len("--command="):]
			}
			return i, "" // argv-form command follows the lock operand
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
					b.WriteString(cmdSubPlaceholderQuoted)
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
			// GNU: a mere "-" implies -i (clear inherited environment).
			envAs.ops = append(envAs.ops, envOp{kind: 'c'})
			i++
		case strings.HasPrefix(a, "--"):
			// GNU unique-prefix long options. Ambiguous/unknown => fail-closed
			// via envUnknownLong so subagent/readonly guards can reject.
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
					// R1/M5: missing operand — GNU errors; fail closed and do
					// NOT advance past the end (i+=2 would slice out of bounds).
					payloads = append(payloads, envUnknownLongPrefix+"missing operand "+a)
					i++
				}
			case "chdir", "argv0":
				if hasVal {
					i++
				} else if i+1 < len(argv) {
					i += 2
				} else {
					payloads = append(payloads, envUnknownLongPrefix+"missing operand "+a)
					i++
				}
			case "split-string":
				// GNU env -S/--split-string: the payload is re-parsed by env
				// itself as its own argv — split it and feed the words back
				// through the operand scanner so options, assignments and the
				// real command head all resolve exactly like env (SH11 F5).
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
				// The -S argv restarts env's operand parse (options first),
				// then the remaining real argv continues after it.
				rest := append(append([]string{}, words...), argv[i:]...)
				rem, moreP, envAs := skipEnvOperands(rest, 0, envAs)
				payloads = append(payloads, moreP...)
				return rem, payloads, envAs
			case "block-signal", "default-signal", "ignore-signal":
				// GNU optional_argument: only consume a value with '='.
				i++
			default:
				// Unknown or ambiguous long option: record and consume one argv
				// so the command head is not mistaken; guards see the marker.
				payloads = append(payloads, envUnknownLongPrefix+a)
				i++
			}
		case strings.HasPrefix(a, "-"):
			// Character-by-character short-option cluster scan (GNU env).
			// Boolean: i/0/v; value: u/C/S/a (rest of cluster or next argv).
			consumedNext := false
			unknown := false
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'i':
					envAs.ops = append(envAs.ops, envOp{kind: 'c'})
				case '0', 'v':
					// boolean
				case 'u', 'C', 'S', 'a':
					opt := a[j]
					var optVal string
					hasOptVal := false
					if j+1 < len(a) {
						optVal = a[j+1:]
						hasOptVal = true
						j = len(a) // consume rest of cluster as value
					} else if i+1 < len(argv) {
						optVal = argv[i+1]
						hasOptVal = true
						consumedNext = true
					}
					if !hasOptVal {
						// R1/M5: trailing value-option without an operand — GNU
						// errors; fail closed instead of slicing past the end.
						payloads = append(payloads, envUnknownLongPrefix+"missing operand "+a)
						unknown = true
						j = len(a)
						break
					}
					switch opt {
					case 'u':
						envAs.ops = append(envAs.ops, envOp{kind: 'u', key: optVal})
					case 'S':
						// See the --split-string branch: the payload restarts
						// env's operand parse.
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
					// 'C' (chdir) and 'a' (argv0): value consumed only
				default:
					// Unknown short letter: fail-closed; do not silently skip.
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

// ---------- rule 1: sub-agent nested-dispatch guard ----------

// blockedAgentExecutableList is the canonical list of executables a
// sub-agent must never spawn. blockedAgentExecutables (argv heads) and
// codeAgentNames (in-code identifier scan) are both derived from it so the
// two screens cannot drift.
var blockedAgentExecutableList = []string{
	"pig", "pi", "agy", "dispatch-agent", "dispatch-agent-go", "grok",
	// herdr/herdsman are retired as a sub-agent terminal-control surface:
	// hc is the only sanctioned channel, so even their read-only verbs
	// block outright now.
	"herdr", "herdsman",
	// Detached session managers let a sub-agent spawn an agent outside the
	// audited ctx_run surface.
	"tmux", "screen",
	// Privilege / namespace / scheduler / remote wrappers whose inner command
	// escapes the caller's role context or scheduling control.
	"sudo", "doas", "su", "pkexec", "nsenter", "unshare", "chroot",
	"systemd-run", "at",
}

// blockedAgentExecutables are the agent executables a sub-agent must never
// spawn from ctx_run. Matching is on filepath.Base of each command head, so a
// bare name, an absolute path, or a worktree-relative path are all caught
// while `echo pig` (pig is an argument, not a head) is not.
var blockedAgentExecutables = func() map[string]bool {
	m := make(map[string]bool, len(blockedAgentExecutableList))
	for _, n := range blockedAgentExecutableList {
		m[n] = true
	}
	return m
}()

// hcSendAddrOK reports whether s is an hc terminal address a sub-agent may
// send to: `^t[0-9a-z]+$` — the numeric/lettered tN ids only. Named
// terminals and machine-qualified `machine/t7` spellings are not admitted.
func hcSendAddrOK(s string) bool {
	if len(s) < 2 || s[0] != 't' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

// screenHcSubagent applies the hc whitelist: `hc send <addr> <text>` with
// exactly two operand words (so --force/--if/--wait/--timeout and extra
// operands block), plus the pure query spellings `hc --help`,
// `hc --version` and `hc <sub> --help`. Every other verb — run/attach/read/
// ls/get/wait/keys/exec/file/kill/rm/label/server/machine/connect/update
// and unknown verbs — blocks; hc is a terminal-control surface like herdr,
// and send is the only channel a sub-agent is granted (the report path).
// hasHcControlChars reports code points that inject terminal control into a
// pasted `hc send` text: C0 controls other than \n/\t (\x00-\x08,
// \x0b-\x1f including \r, \x03 ETX and \x1b ESC), DEL and the C1 set
// (U+0080-U+009F — 0x9B is the ANSI CSI, a second escape-sequence lead-in).
// C1 must be rejected on the decoded RUNE, not on the byte value: every
// UTF-8 continuation byte is >= 0x80, so a byte-level 0x80-0x9F check would
// also reject the second byte of legal multi-byte encodings (U+00A0 is
// `C2 A0`) and break ordinary multilingual text.
func hasHcControlChars(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f ||
			(r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

func screenHcSubagent(headArgv []string) string {
	args := headArgv[1:]
	if isPureQueryInvocation(headArgv) {
		return "" // hc --help / hc -h / hc --version / hc -V
	}
	if len(args) == 0 {
		return "hc bare"
	}
	sub := args[0]
	rest := args[1:]
	if strings.HasPrefix(sub, "-") {
		return "hc " + sub
	}
	// hc <sub> --help / -h: a one-flag query on any spelled subcommand.
	if len(rest) == 1 && (rest[0] == "--help" || rest[0] == "-h") {
		return ""
	}
	if sub == "send" {
		// The addr and the text must both be static and option-free:
		// an unquoted $x splits into extra operands at runtime, and a
		// double-quoted "$(…)" placeholder could expand to a leading
		// dash or fresh control bytes, so any dynamic word fails closed.
		if len(rest) == 2 && !strings.HasPrefix(rest[0], "-") && !strings.HasPrefix(rest[1], "-") &&
			hcSendAddrOK(rest[0]) && !isDynamicArg(rest[0]) && !isDynamicArg(rest[1]) &&
			!hasHcControlChars(rest[1]) {
			return ""
		}
		return "hc send"
	}
	return "hc " + sub
}

// queryOnlyFlagArgs are the pure query flags of the agent-launcher heads:
// they print and exit without dispatching anything. `--dry-run` and
// `--print` are deliberately absent — dispatch-agent writes its combined
// prompt files under /tmp for those, which is a write and (for a
// sub-agent) an orchestration side effect.
var queryOnlyFlagArgs = map[string]bool{
	"--version": true, "-V": true, "--help": true, "-h": true,
}

// isPureQueryInvocation reports whether argv is the program alone plus a
// single version/help flag (`prog -h`, `prog --version`). Exactly two words:
// `prog --version extra` may do more than print.
func isPureQueryInvocation(argv []string) bool {
	return len(argv) == 2 && queryOnlyFlagArgs[argv[1]]
}

// pureQueryOnlyHeads are agent-launcher heads whose ONLY job is dispatch, so
// a version/help query is their one safe spelling. `pig`/`pi`/`agy`/`grok`
// keep blocking outright: for them --version/--help is an ordinary argument
// to the agent run, not a separate query mode.
var pureQueryOnlyHeads = map[string]bool{
	"dispatch-agent":    true,
	"dispatch-agent-go": true,
}

// currentScreenCwd returns the directory relative command spellings resolve
// against: the ctx_run cwd of the call being screened when a guard set it,
// else the process working directory (where a bare name would exec anyway).
func currentScreenCwd() string {
	if screenCwd != "" {
		return screenCwd
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return ""
}

// screenCwd is the ctx_run cwd of the call under screening (see
// withScreenCwd). Empty during unit screening, which makes currentScreenCwd
// fall back to the process working directory.
var screenCwd string

// testTrustedHomeRoot is set only by isolated unit tests (via
// withTestTrustedHome) so tests can build a fake $HOME inside t.TempDir()
// without weakening the production /tmp ban.
var testTrustedHomeRoot string

// withScreenCwd records the ctx_run cwd of the call under screening and
// returns the restore func, for `defer withScreenCwd(cwd)()` at each guarded
// entry point (execute, execute_file, batch, run_task).
func withScreenCwd(cwd string) func() {
	prev := screenCwd
	if cwd != "" {
		screenCwd = cwd
	}
	runtime.LockOSThread()
	return func() {
		screenCwd = prev
		runtime.UnlockOSThread()
	}
}

// transparentShimBins are toolchain version-manager shim multiplexers whose
// runtime dispatch is keyed on argv[0] (the shim link name) rather than the
// multiplexer binary's own basename. When ~/.local/share/mise/shims/node or
// ~/.local/share/mise/shims/rg resolves to /usr/bin/mise, the command being
// executed is still "node" or "rg", never "mise".
var transparentShimBins = map[string]bool{
	"mise": true, "asdf": true, "rustup": true, "pyenv": true,
	"rbenv": true, "nodenv": true, "volta": true, "fnm": true,
	"corepack": true,
}

// isPeeledWrapperBase reports whether base is one of the wrapper heads
// peelWrappers / peelWrappersAndSbxAliases strip. A PATH symlink whose
// typed name is not itself a wrapper but resolves to one (myenv -> env,
// mytimeout -> timeout) must be re-peeled: the option peel ran on the
// typed name before alias resolution rewrote head[0].
func isPeeledWrapperBase(b string) bool {
	switch b {
	case "sbx", "env", "command", "builtin", "exec", "nohup", "setsid",
		"nice", "timeout", "stdbuf", "busybox", "ionice", "taskset", "chrt",
		"strace", "ltrace", "time":
		return true
	}
	return false
}

// sameStructuralFamily reports whether a typed structural head and its
// resolved symlink target basename are aliases for the SAME tool — the
// normal distro/toolchain layout (Debian /bin/sh -> dash, python3 ->
// python3.13, awk -> mawk, gtar -> tar, hc -> herdr-core|sbx). Aliases
// inside a family keep the typed base; a resolved name that crosses to a
// different family is a conflicting alias.
func sameStructuralFamily(a, b string) bool {
	if a == b {
		return true
	}
	if shellHeads[a] && shellHeads[b] {
		return true
	}
	la, oka := heredocInterpLang(a)
	lb, okb := heredocInterpLang(b)
	if oka && okb && la == lb {
		return true
	}
	if (a == "awk" || a == "gawk" || a == "mawk" || a == "nawk") &&
		(b == "awk" || b == "gawk" || b == "mawk" || b == "nawk") {
		return true
	}
	if (a == "sed" || a == "gsed") && (b == "sed" || b == "gsed") {
		return true
	}
	if (a == "tar" || a == "gtar" || a == "bsdtar") &&
		(b == "tar" || b == "gtar" || b == "bsdtar") {
		return true
	}
	if (a == "npx" || a == "npx-cli.js") && (b == "npx" || b == "npx-cli.js") {
		return true
	}
	if (a == "npm" || a == "npm-cli.js") && (b == "npm" || b == "npm-cli.js") {
		return true
	}
	if a == "hc" && (b == "herdr-core" || b == "sbx") {
		return true
	}
	return false
}

// isStructuralGuardHead reports whether base is a command name with
// dedicated structural/code-unwrapping logic in peelResolvedSegDepth. A
// symlink target must never overwrite a structural head name into an
// unrecognized name (which would skip -c/-e unwrapping).
func isStructuralGuardHead(base string) bool {
	if shellHeads[base] {
		return true
	}
	if _, ok := heredocInterpLang(base); ok {
		return true
	}
	switch base {
	case "ssh", "xargs", "find", "eval", "watch", "flock", "script",
		"trap", "unset", "export", "readonly", "declare", "typeset", "local",
		"read", "getopts", "printf", "command", "ctxmode", "sbx",
		"awk", "gawk", "mawk", "nawk", "sed", "gsed", "tar", "gtar", "bsdtar",
		"npx", "bunx", "pnpx", "git", "hc", "herdr-core":
		return true
	}
	return false
}

// userDirForbiddenShadowHeads are core OS / POSIX utilities and guard-critical
// binaries that legitimately reside in root-owned system directories
// (/bin, /usr/bin, /sbin, /usr/sbin, /usr/local/bin, /nix/store, /opt, or
// /home/linuxbrew/.linuxbrew/bin for git), never in user-home writable bin
// directories (~/.local/bin, ~/.cargo/bin, ~/go/bin, ~/.local/share/mise/shims,
// node_modules/.bin, .venv/bin). A same-name binary planted in a user-writable
// directory to shadow one of these heads is blocked by screenPathHeadTrust.
var userDirForbiddenShadowHeads = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true,
	"env": true, "command": true, "exec": true, "nohup": true, "timeout": true, "nice": true,
	"setsid": true, "stdbuf": true, "ionice": true, "taskset": true, "chrt": true,
	"strace": true, "ltrace": true, "flock": true, "script": true, "watch": true,
	"ls": true, "cat": true, "head": true, "tail": true, "wc": true, "stat": true,
	"file": true, "du": true, "df": true, "pwd": true, "echo": true, "printf": true,
	"true": true, "false": true, "which": true, "date": true, "sort": true, "uniq": true,
	"cut": true, "tr": true, "diff": true, "cmp": true, "realpath": true, "basename": true,
	"dirname": true, "readlink": true, "md5sum": true, "sha256sum": true, "sha1sum": true,
	"sha512sum": true, "strings": true, "objdump": true, "readelf": true,
	"ps": true, "pgrep": true, "ss": true, "journalctl": true, "systemctl": true,
	"find": true, "xargs": true, "sed": true, "gsed": true, "grep": true, "egrep": true, "fgrep": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true,
	"tar": true, "gtar": true, "bsdtar": true, "gzip": true, "gunzip": true,
	"bzip2": true, "bunzip2": true, "xz": true, "unxz": true, "zstd": true, "unzstd": true, "lz4": true,
	"unzip": true, "mount": true, "umount": true, "kill": true, "pkill": true, "killall": true,
	"rm": true, "unlink": true, "rmdir": true, "mv": true, "cp": true, "ln": true,
	"chmod": true, "chown": true, "chgrp": true, "mkdir": true, "mktemp": true, "touch": true,
	"dd": true, "tee": true, "crontab": true, "at": true,
	"ssh": true, "scp": true, "sftp": true, "rsync": true,
	"sudo": true, "doas": true, "su": true, "pkexec": true, "nsenter": true, "unshare": true,
	"chroot": true, "systemd-run": true, "git": true,
}

// isSystemPathDir reports whether a cleaned absolute directory path is a
// system-level (non-user-home) executable directory.
func isSystemPathDir(norm string) bool {
	norm = filepath.Clean(norm)
	if isTmpOrScratchPath(norm) {
		return false
	}
	switch norm {
	case "/usr/bin", "/bin", "/usr/sbin", "/sbin",
		"/usr/local/bin", "/usr/local/sbin",
		"/usr/games", "/usr/local/games", "/snap/bin":
		return true
	}
	for _, sysPref := range []string{
		"/usr/local/", "/usr/lib/", "/usr/libexec/", "/opt/",
		"/nix/store/", "/snap/",
	} {
		if strings.HasPrefix(norm, sysPref) {
			return true
		}
	}
	return false
}

// isLinuxbrewPathDir reports whether norm is under /home/linuxbrew/.linuxbrew.
func isLinuxbrewPathDir(norm string) bool {
	norm = filepath.Clean(norm)
	const brewRoot = "/home/linuxbrew/.linuxbrew"
	return norm == brewRoot || strings.HasPrefix(norm, brewRoot+"/")
}

// resolveHeadBase returns the basename of the executable program a command
// head actually runs: the same name when head[0] is not a symlink (or cannot
// be located), the target's basename when it is. Transparent version-manager
// shims (mise, asdf, rustup, pyenv, volta, fnm, corepack) preserve the typed
// tool basename so shim-wrapped interpreters and allowlisted tools keep their
// real identity.
func resolveHeadBase(name, pathEnv string) string {
	if name == "" || isDynamicArg(name) {
		return ""
	}
	target := name
	if !filepath.IsAbs(target) {
		if !looksLikePath(target) {
			p, dot, err := lookPathIn(target, pathEnv)
			if err != nil || (dot && !hasExplicitRelativeSegment(pathEnv)) {
				return ""
			}
			target = p
		} else if cwd := currentScreenCwd(); cwd != "" {
			target = filepath.Join(cwd, target)
		}
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return ""
	}
	rb := filepath.Base(resolved)
	typedBase := filepath.Base(name)
	if rb != typedBase && transparentShimBins[rb] {
		return typedBase
	}
	return rb
}

// hasExplicitRelativeSegment reports whether pathEnv carries a relative
// segment the guard explicitly admitted (the toolchain-relative list) —
// only then is a "." lookup result reachable at runtime.
func hasExplicitRelativeSegment(pathEnv string) bool {
	for _, p := range strings.Split(pathEnv, ":") {
		if p != "" && !strings.HasPrefix(p, "/") {
			return true
		}
	}
	return false
}

// lookPathIn emulates execvp name resolution over an explicit PATH value:
// bare names scan each segment (relative segments resolve against the
// screen cwd, empty segments mean "."); returns (path, foundInDot, err).
func lookPathIn(name, pathEnv string) (string, bool, error) {
	if pathEnv == "" {
		pathEnv = os.Getenv("PATH")
	}
	cwd := currentScreenCwd()
	for _, dir := range strings.Split(pathEnv, ":") {
		dot := false
		switch {
		case dir == "":
			dot = true
			dir = "."
		case !filepath.IsAbs(dir):
			dot = true // relative segment resolves against the call cwd
		}
		if !filepath.IsAbs(dir) {
			if cwd == "" {
				continue
			}
			dir = filepath.Join(cwd, dir)
		}
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return p, dot, nil
		}
	}
	return "", false, exec.ErrNotFound
}

// canonicalResolvedBase maps a symlink-resolved executable basename to the
// canonical program name the name-keyed screens know.
func canonicalResolvedBase(b string) string {
	switch b {
	case "npx-cli.js":
		return "npx"
	case "npm-cli.js":
		return "npm"
	}
	for _, stem := range []string{"php", "ruby", "perl"} {
		if rest, ok := strings.CutPrefix(b, stem); ok && isVersionSuffix(rest) {
			return stem
		}
	}
	// GNU packages installed by Homebrew (coreutils, findutils, grep, sed,
	// tar, ...) place the real binary under a "g"/"gnu" prefix (gdf,
	// gnutrue, gls) and symlink the unprefixed name to it, so a resolved
	// basename can carry the prefix. Map it back to the canonical program,
	// but ONLY for names Homebrew actually ships g-prefixed — stripping
	// 'g' off an unrelated real tool (gps -> ps, ghc -> hc, gcrontab)
	// would re-identity it as a different program.
	for _, pref := range []string{"gnu", "g"} {
		if rest, ok := strings.CutPrefix(b, pref); ok && gnuCanonicalSet[rest] {
			return rest
		}
	}
	return b
}

// gnuCanonicalSet is the closed list of program names that have a real
// Homebrew/Linuxbrew g-prefixed binary (coreutils, findutils, gnu-sed,
// gnu-tar, grep, gawk, diffutils, ed, getopt, gzip, make, parallel,
// gnu-time, which, gnu-getopt, gnu-indent, gnu-units) plus the wrapper
// names a g-prefixed coreutils install also provides (genv, gtimeout,
// gnice, gnohup, gstdbuf). Real tools like gps, ghc, gcrontab are NOT
// in the set: stripping their 'g' would alias them to ps/hc/crontab.
var gnuCanonicalSet = map[string]bool{
	// coreutils
	"env": true, "timeout": true, "nice": true, "nohup": true, "stdbuf": true,
	"printenv": true, "true": true, "false": true, "ls": true, "dir": true,
	"vdir": true, "cat": true, "head": true, "tail": true, "wc": true,
	"stat": true, "du": true, "df": true, "pwd": true, "echo": true,
	"printf": true, "yes": true, "date": true, "sort": true, "uniq": true,
	"cut": true, "tr": true, "fold": true, "fmt": true, "join": true,
	"paste": true, "split": true, "csplit": true, "nl": true, "pr": true,
	"expand": true, "unexpand": true, "comm": true, "tsort": true,
	"factor": true, "shuf": true, "tee": true, "mktemp": true, "install": true,
	"mkdir": true, "rmdir": true, "mkfifo": true, "mknod": true,
	"mv": true, "cp": true, "ln": true, "link": true, "unlink": true,
	"rm": true, "chmod": true, "chown": true, "chgrp": true, "touch": true,
	"dd": true, "sync": true, "truncate": true, "shred": true,
	"basename": true, "dirname": true, "readlink": true, "realpath": true,
	"pathchk": true, "md5sum": true, "sha1sum": true, "sha256sum": true,
	"sha384sum": true, "sha512sum": true, "b2sum": true, "cksum": true,
	"sum": true, "base32": true, "base64": true, "basenc": true,
	"tty": true, "uname": true, "hostname": true, "arch": true,
	"id": true, "whoami": true, "who": true, "users": true, "groups": true,
	"logname": true, "nproc": true, "uptime": true, "sleep": true,
	"kill": true, "test": true, "[": true, "expr": true,
	"numfmt": true, "seq": true, "stty": true, "chroot": true,
	"chcon": true, "runcon": true, "hostid": true, "pinky": true,
	"dircolors": true,
	// findutils
	"find": true, "xargs": true, "locate": true, "updatedb": true,
	// grep / sed / awk / tar / diffutils / ed / getopt / make / which / time
	"grep": true, "egrep": true, "fgrep": true, "sed": true,
	"awk": true, "tar": true, "diff": true, "cmp": true, "diff3": true,
	"sdiff": true, "patch": true, "ed": true, "getopt": true, "make": true,
	"which": true, "time": true, "indent": true, "units": true,
	// compression tools that also get brew g-prefixes on some formulas
	"gzip": true, "gunzip": true, "zcat": true,
}

// isVersionSuffix reports whether s is a version tail: a digit followed by
// digits and dots only ("8.3", "3.2", "5.38.2").
func isVersionSuffix(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// headBaseAliasHits returns every name a command head can resolve to: its
// own basename plus, when the file behind head[0] is a symlink, the basename
// of the resolved target.
func headBaseAliasHits(headArgv []string, pathEnv string) []string {
	if len(headArgv) == 0 {
		return nil
	}
	out := []string{filepath.Base(headArgv[0])}
	if b := resolveHeadBase(headArgv[0], pathEnv); b != "" && b != out[0] {
		out = append(out, b)
	}
	return out
}

// screenPathHeadTrust verifies that a bare command head resolved through
// pathEnv is not backed by an untrusted/world-writable binary, a symlink
// escaping into /tmp, or a user-directory binary planted to shadow a core
// system command (C10: [pattern:path-trust-user-writable]).
func screenPathHeadTrust(head0, pathEnv string) string {
	if head0 == "" || isDynamicArg(head0) || looksLikePath(head0) || filepath.IsAbs(head0) {
		return ""
	}
	p, dot, err := lookPathIn(head0, pathEnv)
	if err != nil {
		return ""
	}
	euid := os.Geteuid()
	if dot {
		// A relative PATH segment skips every on-disk check above, so a
		// whitelisted toolchain dir (.venv/bin, node_modules/.bin) could
		// smuggle a symlink escaping the workspace (.venv/bin/pytest ->
		// /tmp/pytest, or -> /home/otheruser/.local/bin/pytest). Resolve
		// the link and require the target to stay inside the current
		// workspace, or to land in a trusted system/linuxbrew/user
		// toolchain dir that also passes the executable trust check
		// (regular venv .venv/bin/python3 -> /usr/bin/python3.x).
		if !hasExplicitRelativeSegment(pathEnv) {
			return ""
		}
		resolved, rerr := filepath.EvalSymlinks(p)
		if rerr != nil {
			return "untrusted path binary " + head0
		}
		resolved = filepath.Clean(resolved)
		realCwd := filepath.Clean(currentScreenCwd())
		if ec, e := filepath.EvalSymlinks(realCwd); e == nil {
			realCwd = filepath.Clean(ec)
		}
		if realCwd != "" && realCwd != "." && realCwd != string(filepath.Separator) &&
			(resolved == realCwd || strings.HasPrefix(resolved, realCwd+string(filepath.Separator))) {
			return "" // resolved target stays inside the workspace
		}
		resDir := filepath.Clean(filepath.Dir(resolved))
		if (isSystemPathDir(resDir) || isLinuxbrewPathDir(resDir) || isUserToolchainPathDir(resDir)) &&
			isTrustedExecutableOnDisk(resolved, euid) {
			return ""
		}
		return "untrusted path binary " + head0
	}
	dir := filepath.Clean(filepath.Dir(p))
	// Only enforce planted-binary / shadowing checks when the winning PATH
	// segment is a user-home or linuxbrew toolchain directory (as opposed to
	// an explicit test-injected temp PATH segment that is not a home dir).
	inToolchainDir := isUserToolchainPathDir(dir) || isLinuxbrewPathDir(dir)
	if !isSystemPathDir(dir) && !inToolchainDir {
		return ""
	}
	if !isTrustedExecutableOnDisk(p, euid) {
		return "untrusted path binary " + head0
	}
	if inToolchainDir && userDirForbiddenShadowHeads[head0] {
		// git may legitimately reside in /home/linuxbrew/.linuxbrew/bin,
		// provided the directory and binary pass the trust check above.
		if head0 == "git" && isLinuxbrewPathDir(dir) {
			return ""
		}
		// Same-basename or distro-alias symlink into a system directory
		// (e.g. ~/.local/bin/find -> /usr/bin/find, ~/.local/bin/awk ->
		// /usr/bin/mawk via alternatives) is a PATH convenience, not a planted
		// binary. A real file or a symlink to an unrelated program still blocks.
		// The linuxbrew prefix has the same shape internally: its unprefixed
		// bin links (ls, cat, df, true, ...) point at gnu-prefixed Cellar
		// binaries, so a link resolving within the prefix under the canonical
		// name (via isAllowedSystemReadonlyAlias) is brew's own layout, not a
		// plant. A real file sitting in the brew bin dir still blocks: the
		// prefix escape requires the resolved path to differ from the link.
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			resolved = filepath.Clean(resolved)
			rb := filepath.Base(resolved)
			rdir := filepath.Dir(resolved)
			if (isSystemPathDir(rdir) || (isLinuxbrewPathDir(rdir) && resolved != filepath.Clean(p))) && (rb == head0 || isAllowedSystemReadonlyAlias(head0, rb, head0, pathEnv)) {
				return ""
			}
		}
		return "planted shadow binary in user path: " + head0
	}
	return ""
}

// isTrustedExecutableOnDisk checks that an executable resolved from a
// toolchain/system PATH directory (and its EvalSymlinks target) is owned by
// root or euid — at system locations the owner check is exempt (ADAPT2) and
// write bits are not judged there (see the note in isTrustedPathDirOnDisk) —
// and that it does not resolve into /tmp|/var/tmp|/dev/shm|/run.
func isTrustedExecutableOnDisk(binPath string, euid int) bool {
	dir := filepath.Clean(filepath.Dir(binPath))
	if !isTrustedPathDirOnDisk(dir, euid) {
		return false
	}
	// ADAPT2: a binary in a lexical system PATH dir skips the owner-uid
	// check, mirroring isTrustedPathDirOnDisk — system dirs are
	// admin-managed, so a third-party image owner (e.g. uid 65534 on a
	// container image's /opt) is normal there. The fixed linuxbrew prefix
	// gets the same treatment (see isTrustedPathDirOnDisk). Write bits are
	// not judged at system locations either (same note); a target that
	// escapes into a user dir keeps the owner check below, and user
	// toolchain dirs keep the full owner check here.
	sysBin := isSystemPathDir(dir) || isLinuxbrewPathDir(dir)
	if lst, err := os.Lstat(binPath); err == nil && !sysBin {
		if !statUIDAndPermOK(lst, euid, true) {
			return false
		}
	}
	resolved, err := filepath.EvalSymlinks(binPath)
	if err != nil {
		return false
	}
	resolved = filepath.Clean(resolved)
	if isTmpOrScratchPath(resolved) {
		return false
	}
	st, err := os.Stat(resolved)
	if err != nil || st.IsDir() {
		return false
	}
	resDir := filepath.Clean(filepath.Dir(resolved))
	// The resolved target is judged by where it lives: a target inside a
	// system dir (or the linuxbrew prefix) gets the same ADAPT2 exemption;
	// a target that escapes into a user dir keeps the owner check.
	if !isSystemPathDir(resDir) && !isLinuxbrewPathDir(resDir) {
		if !statUIDAndPermOK(st, euid, false) {
			return false
		}
	}
	return isTrustedPathDirOnDisk(resDir, euid)
}

// isAllowedSystemReadonlyAlias reports whether a symlink from typedBase to
// resolvedBase is a standard OS/distro alias for an allowlisted command.
func isAllowedSystemReadonlyAlias(typedBase, resolvedBase, head0, pathEnv string) bool {
	if typedBase == resolvedBase || transparentShimBins[resolvedBase] {
		return true
	}
	if canonicalResolvedBase(resolvedBase) == typedBase {
		return true
	}
	switch typedBase {
	case "awk", "gawk", "mawk", "nawk":
		if resolvedBase == "awk" || resolvedBase == "gawk" || resolvedBase == "mawk" || resolvedBase == "nawk" {
			return true
		}
	case "grep", "egrep", "fgrep":
		if resolvedBase == "grep" || resolvedBase == "egrep" || resolvedBase == "fgrep" {
			return true
		}
	case "sed", "gsed":
		if resolvedBase == "sed" || resolvedBase == "gsed" {
			return true
		}
	case "systemctl", "journalctl":
		if resolvedBase == "systemd" || resolvedBase == "systemctl" || resolvedBase == "journalctl" {
			return true
		}
	case "hc":
		// Live layouts: /root/.local/bin/hc -> herdr-core on the host, and
		// hc -> sbx inside the `sbx --preset reviewer-agent` sandbox. Only
		// the typed `hc` head earns the pass — herdr-core/sbx themselves are
		// NOT readonly-allowlisted, and argv still goes through the strict
		// screenHcSubagent whitelist keyed on the typed name.
		if resolvedBase == "herdr-core" || resolvedBase == "sbx" {
			return true
		}
	case "which":
		if strings.Contains(resolvedBase, "which") || resolvedBase == "debianutils" {
			return true
		}
	case "strings", "objdump", "readelf":
		if strings.HasSuffix(resolvedBase, "-"+typedBase) || strings.Contains(resolvedBase, typedBase) {
			return true
		}
	}
	if resolvedBase == "coreutils" || resolvedBase == "busybox" {
		if p, _, err := lookPathIn(head0, pathEnv); err == nil && isSystemPathDir(filepath.Dir(p)) {
			return true
		}
	}
	return false
}

// screenReadonlyAliasTarget ensures that when a bare command in strict
// readonly mode resolves through a symlink to a different binary name, the
// target binary name is also permitted by the readonly allowlist (closing the
// C10 symlink-to-unlisted-binary bypass).
func screenReadonlyAliasTarget(typedHead []string, pathEnv string) string {
	if len(typedHead) == 0 {
		return ""
	}
	typedBase := canonicalResolvedBase(filepath.Base(typedHead[0]))
	rb := resolveHeadBase(typedHead[0], pathEnv)
	if rb == "" {
		return ""
	}
	rbCanon := canonicalResolvedBase(rb)
	if isAllowedSystemReadonlyAlias(typedBase, rbCanon, typedHead[0], pathEnv) {
		return ""
	}
	aliasArgv := append([]string{rbCanon}, typedHead[1:]...)
	return screenReadonlyAllowlist(aliasArgv)
}

// screenNestedDispatch returns the guard hit for ONE resolved command head
// (already wrapper-peeled), or "" when allowed. headArgv starts at the head.
// depth carries the enclosing peel budget (peelChainMaxDepth) so a nested
// recursion — `npm exec -- npm exec -- …`, `npm exec -- npx …` — consumes
// the SAME budget instead of restarting it; caller is the env-seeded
// identity the inner command inherits.
// `git` heads also get the global exec-config screen: a sub-agent must not
// arm a pager/ssh/hook command through `git -c`/`--config-env`/`--exec-path`.
func screenNestedDispatch(headArgv []string, pathEnv string, depth int, caller callerIdentity) string {
	if len(headArgv) == 0 {
		return ""
	}
	for _, base := range headBaseAliasHits(headArgv, pathEnv) {
		if isPureQueryInvocation(headArgv) && pureQueryOnlyHeads[base] {
			continue // `dispatch-agent --version`: nothing is dispatched
		}
		if blockedAgentExecutables[base] {
			return base
		}
		switch base {
		// `herdr-core` is the host-side symlink target of `hc`; naming the
		// target directly must route through the same hc whitelist so
		// `herdr-core run ...` cannot bypass the `hc` interception.
		case "hc", "herdr-core":
			if hit := screenHcSubagent(headArgv); hit != "" {
				return hit
			}
		case "crontab":
			// `crontab -l` alone is a read-only listing; every other spelling
			// (-e, -r, file, -, extra args) mutates or schedules.
			if len(headArgv) != 2 || headArgv[1] != "-l" {
				return "crontab"
			}
		case "git":
			if _, hit := screenGitGlobalArgs(headArgv[1:]); hit != "" {
				return hit
			}
			if hit := screenGitSubagentExecArgs(headArgv[1:]); hit != "" {
				return hit
			}
		// npm/pnpm/yarn `exec`/`dlx` fetch-and-run a package binary — the
		// same unvetted-code surface as npx/bunx/pnpx. The argv is parsed
		// once by parseNpmFamilyArgv's finite accept grammar: the verb is
		// the FIRST positional (`npm view exec pig`'s `exec` is a `view`
		// field name), `-c`/`--call` and every unlisted option Reject, and
		// the WHOLE child argv recurses through peelResolvedSegDepth at
		// depth+1 so `npm exec -- npm exec pig` and `npm exec -- npx pig`
		// are screened under the shared budget.
		case "npm", "pnpm", "yarn":
			r := parseNpmFamilyArgv(base, headArgv[1:])
			switch r.state {
			case npmArgvExec:
				// A -p/--package spec naming a blocked executable is a hit
				// whatever the child command is: `tsc` cannot launder
				// `--package=pig`.
				for _, spec := range r.packages {
					if blockedAgentExecutables[filepath.Base(nodePkgSpecBase(spec))] {
						return base + " " + r.verb + " " + spec
					}
				}
				// The child's FIRST positional is the package spec the runner
				// fetch-and-runs: normalize it like the -p/--package specs
				// above (`pig@latest` -> `pig`, `@scope/pig@1.2` -> `pig`) or
				// the version tag hides the blocked name from the PATH lookup
				// and the agent blacklist. A non-scoped spec containing `/`
				// is a path, not a registry name, and stays verbatim (the
				// recursion's own filepath.Base still sees `pig`). The tail
				// always stays verbatim so a nested
				// `npm exec -- npm exec pig` still recurses.
				child := r.child
				if head0 := child[0]; strings.HasPrefix(head0, "@") || !strings.Contains(head0, "/") {
					child = append([]string{filepath.Base(nodePkgSpecBase(head0))}, child[1:]...)
				}
				if hit := peelResolvedSegDepth(child, shellSegment{}, 's', depth+1, caller); hit != "" {
					return base + " " + r.verb + " " + hit
				}
			case npmArgvReject:
				return r.rejectHit(base)
			}
		}
	}
	return ""
}

// npmArgvState is the verdict of parseNpmFamilyArgv.
type npmArgvState int

const (
	npmArgvNoVerb npmArgvState = iota // flag-only argv: no subcommand
	npmArgvOther                      // a non-exec/dlx verb
	npmArgvExec                       // verb is exec/dlx: child/packages filled
	npmArgvReject                     // argv does not fit the accepted grammar
)

// npmArgvParse is the result of parseNpmFamilyArgv: the locked verb (and
// its argv index), the exec/dlx child command plus -p/--package specs, or
// the rejection reason.
type npmArgvParse struct {
	state    npmArgvState
	verbIx   int      // argv index of the subcommand word (-1 when none)
	verb     string   // the subcommand word
	child    []string // exec/dlx: the fetched command argv to re-screen
	packages []string // exec/dlx: package specs named by -p/--package
	reason   string   // Reject detail
}

// rejectHit formats the guard hit for a rejected parse.
func (r npmArgvParse) rejectHit(base string) string {
	if r.verb != "" {
		return base + " " + r.verb + " " + r.reason
	}
	return base + " " + r.reason
}

// npmOptKind classifies an accepted npm-family option spelling.
type npmOptKind byte

const (
	npmOptBool    npmOptKind = 'B' // boolean: no operand
	npmOptValue   npmOptKind = 'V' // consumes one operand value
	npmOptPackage npmOptKind = 'S' // consumes a package spec operand
)

// npmFamilyOptTable is the FINITE accepted set of npm/pnpm/yarn option
// spellings keyed by manager: a boolean, a value-taker or (in exec mode)
// a package-spec taker. Anything not listed — long or short — is a
// Reject, never a guessed pass: the guard deliberately does not emulate
// the full CLI surface.
var npmFamilyOptTable = map[string]map[string]npmOptKind{
	"npm": {
		"help": npmOptBool, "h": npmOptBool,
		"version": npmOptBool, "v": npmOptBool,
		"yes": npmOptBool, "y": npmOptBool,
		"global": npmOptBool, "g": npmOptBool,
		"parseable": npmOptBool, "p": npmOptBool,
		"prefix": npmOptValue, "workspace": npmOptValue, "w": npmOptValue,
		"userconfig": npmOptValue, "globalconfig": npmOptValue,
		"cache": npmOptValue, "registry": npmOptValue,
		"loglevel": npmOptValue, "tag": npmOptValue,
	},
	"pnpm": {
		"help": npmOptBool, "h": npmOptBool,
		"version": npmOptBool, "v": npmOptBool,
		"workspace-root": npmOptBool, "w": npmOptBool,
		"recursive": npmOptBool, "r": npmOptBool,
		"dir": npmOptValue, "C": npmOptValue,
		"filter": npmOptValue, "F": npmOptValue,
	},
	"yarn": {
		"help": npmOptBool, "h": npmOptBool,
		"version": npmOptBool, "v": npmOptBool,
		"cwd": npmOptValue,
	},
}

// npmFamilyExecOptTable lists the extra options exec/dlx accept on top of
// the common set: -p/--package name a fetched package spec. npm's own `-p`
// stays boolean (parseable): unlike pnpm's/yarn's it is NOT a --package
// alias, so `npm exec -p pig` cannot smuggle a spec — and only yarn gets
// `-p` as a spec taker here.
var npmFamilyExecOptTable = map[string]map[string]npmOptKind{
	"npm":  {"package": npmOptPackage},
	"pnpm": {"package": npmOptPackage},
	"yarn": {"package": npmOptPackage, "p": npmOptPackage},
}

// parseNpmFamilyArgv parses an npm/pnpm/yarn argv under the guard's
// finite accept grammar. The first positional locks the subcommand verb —
// only exec/dlx enter the exec state (every other verb is Other, so
// `npm view exec pig`'s `exec` stays field data, and no trailing scan can
// resurrect it). exec/dlx then collect the child command the manager
// would fetch-and-run: manager options are consumed up front (npm's own
// `--`, like pnpm/yarn's first child word, ends the option zone), and
// the child's first positional is version/tag-stripped like a
// -p/--package spec so `pig@latest` still hits the blacklist. Once the
// child locks, `--` and every later word are child data passed through
// verbatim — `pnpm exec npm exec -- tsc --noEmit` and
// `npm -- exec tsc --noEmit` keep `--noEmit` as tsc's own option.
// `-c`/`--call` in the option zone, every unlisted option spelling, a
// dynamic operand and a malformed value slot all Reject — the grammar
// fails closed everywhere instead of guessing.
func parseNpmFamilyArgv(base string, args []string) npmArgvParse {
	r := npmArgvParse{verbIx: -1}
	reject := func(reason string) npmArgvParse {
		return npmArgvParse{state: npmArgvReject, verbIx: r.verbIx, verb: r.verb, reason: reason}
	}
	common := npmFamilyOptTable[base]
	execOpts := npmFamilyExecOptTable[base]

	// takeValue consumes an inline or separate option value; it returns
	// the value and the index of the next unconsumed word, or a Reject.
	takeValue := func(i int, inline string, hasInline bool) (string, int, npmArgvParse) {
		if hasInline {
			v := strings.TrimPrefix(inline, "=") // short cluster may glue -C=dir
			if v == "" {
				return "", 0, reject("empty option value")
			}
			if isDynamicArg(v) {
				return "", 0, reject("dynamic option value")
			}
			return v, i + 1, npmArgvParse{}
		}
		if i+1 >= len(args) || args[i+1] == "--" {
			return "", 0, reject("missing option value")
		}
		v := args[i+1]
		if strings.HasPrefix(v, "-") || isDynamicArg(v) {
			return "", 0, reject("missing option value")
		}
		return v, i + 2, npmArgvParse{}
	}

	inExec := false
	childLocked := false // option consumption ends at the first child word
	for i := 0; i < len(args); {
		a := args[i]
		if a == "--" {
			if childLocked {
				// The child command is already locked: this `--` belongs to
				// the child, not to the manager. Pass it — and every word
				// after it — through verbatim so `pnpm exec npm exec -- tsc
				// --noEmit` keeps `--noEmit` as tsc's own data instead of
				// reopening manager option parsing on it.
				r.child = append(r.child, args[i:]...)
				break
			}
			if !inExec {
				// `--` closes manager option parsing; the NEXT word is the
				// verb (a dynamic verb cannot be judged — fail closed).
				i++
				if i >= len(args) {
					r.state = npmArgvNoVerb
					return r
				}
				if isDynamicArg(args[i]) {
					return reject("dynamic operand")
				}
				r.verbIx, r.verb = i, args[i]
				if r.verb == "exec" || r.verb == "dlx" {
					inExec, r.state = true, npmArgvExec
					i++
					continue
				}
				r.state = npmArgvOther
				return r
			}
			// exec: `--` removes itself; everything after joins the child.
			r.child = append(r.child, args[i+1:]...)
			break
		}
		treatAsOpt := strings.HasPrefix(a, "-") && a != "-"
		switch {
		case !inExec:
			// GLOBAL: option-looking words are manager options.
		case childLocked:
			// Every manager: once the first child word locks the fetched
			// command, the tail is the child's own argv — an option-looking
			// word there is the CHILD's option (`tsc --noEmit`), never a
			// manager option. The same rule governs `--` above.
			treatAsOpt = false
		}
		if treatAsOpt {
			endBool := false // last consumed kind was a bare boolean
			if strings.HasPrefix(a, "--") {
				name, val, hasEq := strings.Cut(a[2:], "=")
				switch {
				case name == "c" || name == "call":
					return reject("option --" + name)
				}
				kind, ok := common[name]
				if !ok && inExec {
					kind, ok = execOpts[name]
				}
				if !ok {
					return reject("option --" + name)
				}
				switch kind {
				case npmOptBool:
					if hasEq {
						if val != "true" && val != "false" {
							return reject("option --" + name + " value")
						}
					} else {
						endBool = true
					}
					i++
				case npmOptValue:
					_, ni, rr := takeValue(i, val, hasEq)
					if rr.state == npmArgvReject {
						return rr
					}
					i = ni
				case npmOptPackage:
					v, ni, rr := takeValue(i, val, hasEq)
					if rr.state == npmArgvReject {
						return rr
					}
					r.packages = append(r.packages, v)
					i = ni
				}
			} else {
				// Short option or cluster: B letters continue; a V/S letter
				// eats the cluster tail (an optional leading `=` is dropped)
				// or the next word, then the word is done. `c` and unknown
				// letters Reject.
				valueEnd := false
				for j := 1; j < len(a); j++ {
					ch := a[j : j+1]
					if ch == "c" {
						return reject("option -c")
					}
					kind, ok := common[ch]
					if !ok && inExec {
						kind, ok = execOpts[ch]
					}
					if !ok {
						return reject("option -" + ch)
					}
					if kind == npmOptBool {
						endBool = true
						continue
					}
					v, ni, rr := takeValue(i, a[j+1:], j+1 < len(a))
					if rr.state == npmArgvReject {
						return rr
					}
					if kind == npmOptPackage {
						r.packages = append(r.packages, v)
					}
					i = ni
					valueEnd = true
					break
				}
				if !valueEnd {
					i++
				}
			}
			if endBool && i < len(args) && (args[i] == "true" || args[i] == "false") {
				// An optional boolean value must be glued; a separated
				// true/false word would misparse as the verb or a child
				// word — fail closed rather than guess the arity.
				return reject("separated boolean value")
			}
			continue
		}
		// Positional word.
		if isDynamicArg(a) {
			return reject("dynamic operand")
		}
		if !inExec {
			r.verbIx, r.verb = i, a
			if a == "exec" || a == "dlx" {
				inExec, r.state = true, npmArgvExec
				i++
				continue
			}
			r.state = npmArgvOther
			return r
		}
		r.child = append(r.child, a)
		childLocked = true
		i++
	}
	if r.state == npmArgvExec && len(r.child) == 0 {
		// `npm exec` with no command: do not guess a manifest default bin
		// or an interactive shell — fail closed.
		return reject("missing command")
	}
	return r
}

// nodePkgSpecBase strips the version/tag suffix from an npm package
// spec: `pig@latest` → `pig`, `@scope/pkg@1.2` → `@scope/pkg`, a bare
// `pig` or `@scope/pkg` unchanged. The executable the runner dispatches
// is what matters to the guard, not the registry version pin.
func nodePkgSpecBase(spec string) string {
	if i := strings.LastIndexByte(spec, '@'); i > 0 {
		return spec[:i]
	}
	return spec
}

// screenNodeRunnerSubagent vets an npx/bunx/pnpx invocation for a
// sub-agent caller: -c/--call hands a raw command string to a shell
// (unvettable), -p/--package installs-and-runs the named package (its
// spec is checked against blockedAgentExecutables after version
// stripping), unknown flags fail closed, and the first positional
// package spec is re-dispatched through screenNestedDispatch so
// `npx pig@latest` and `bunx hc kill t1` cannot dodge the agent/terminal
// whitelists.
func screenNodeRunnerSubagent(base string, args []string, effPath string, depth int, caller callerIdentity) string {
	const boolShort = "ynq"
	const valueShort = "pw"
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if isDynamicArg(a) {
			return "dynamic code payload"
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break // first positional: package spec / command
		}
		if strings.HasPrefix(a, "--") {
			name := a[2:]
			val := ""
			glued := false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				val = name[eq+1:]
				name = name[:eq]
				glued = true
			}
			switch name {
			case "call":
				return base + " -c"
			case "package":
				if !glued && i+1 < len(args) {
					i++
					val = args[i]
				}
				if isDynamicArg(val) {
					return "dynamic code payload"
				}
				if spec := filepath.Base(nodePkgSpecBase(val)); blockedAgentExecutables[spec] {
					return base + " " + spec
				}
			case "prefix", "cache", "userconfig", "registry", "workspace":
				if !glued {
					i++ // consume the value operand
				}
			case "yes", "no", "no-install", "quiet", "offline",
				"prefer-offline", "workspaces", "include-workspace-root",
				"help", "version":
				// boolean / query flags: no operand consumed
			default:
				return base + " " + a // fail closed on unknown long flags
			}
			continue
		}
		// Short-option cluster: c is -c (arbitrary command); p/w carry a
		// value (cluster tail or next argv); y/n/q are boolean.
		for j := 1; j < len(a); j++ {
			ch := a[j]
			switch {
			case ch == 'c':
				return base + " -c"
			case strings.IndexByte(valueShort, ch) >= 0:
				val := a[j+1:]
				if val == "" && i+1 < len(args) {
					i++
					val = args[i]
				}
				if isDynamicArg(val) {
					return "dynamic code payload"
				}
				if ch == 'p' {
					if spec := filepath.Base(nodePkgSpecBase(val)); blockedAgentExecutables[spec] {
						return base + " " + spec
					}
				}
				j = len(a) // value ends the cluster
			case strings.IndexByte(boolShort, ch) >= 0:
				// keep scanning the cluster
			default:
				return base + " " + a // fail closed on unknown short flags
			}
		}
	}
	if i >= len(args) {
		return "" // bare npx / flag-only invocation
	}
	spec := filepath.Base(nodePkgSpecBase(args[i]))
	inner := append([]string{spec}, args[i+1:]...)
	// The fetched command argv re-enters the shared peel at depth+1: the
	// inner head may itself be a manager/runner (`npx npx pig`,
	// `npm exec -- npx pig`) or a shell (`npx sh -c pig`), and every such
	// hop consumes the SAME peel budget.
	if hit := peelResolvedSegDepth(inner, shellSegment{}, 's', depth+1, caller); hit != "" {
		return base + " " + hit
	}
	return ""
}

// callerIdentity is the role identity a spawned child would inherit: the
// caller's own CTXMODE_ROLE / CTXMODE_READONLY process-env values. The env
// op replay in screenEnvAssignments starts from it so `env -i`/`env -u`
// shedding is judged against who the caller really is, not against a
// static allowlist.
type callerIdentity struct {
	role     string // CTXMODE_ROLE as-is (trimmed)
	readonly string // CTXMODE_READONLY raw value
	// envTaint marks variables an outer envAs overrode (HOME=/x sh -c,
	// env -i, env -u PWD). Nested shell payloads parsed under this
	// caller degrade the PATH/HOME/abs-dir placeholder grants for these
	// names (SH11 F3/Q5).
	envTaint map[string]bool
	// pathEnv is the EFFECTIVE PATH the nested child resolves against:
	// the process PATH replayed through every envAs op seen so far. ""
	// means "use the process PATH" — the same fallback lookPathIn
	// already applies to an empty pathEnv argument (R7).
	pathEnv string
}

// currentCallerIdentity reads the caller's role identity from the process
// environment once per top-level guard entry.
func currentCallerIdentity() callerIdentity {
	return callerIdentity{
		role:     strings.TrimSpace(os.Getenv(auditEnvRole)),
		readonly: os.Getenv(auditEnvReadonly),
		pathEnv:  os.Getenv("PATH"),
	}
}

// seededWith returns a copy of the identity whose envTaint additionally
// covers every name envAs overrode or cleared. Recursion into nested shell
// payloads (-c scripts, eval text, env -S, flock -c, script -c, watch
// operands, heredoc bodies, here-strings) uses it so inner placeholder
// grants match the real env. The effective PATH is replayed too (R7): a
// PATH=/x prefix must drive alias resolution inside the nested payload.
func (c callerIdentity) seededWith(envAs envAssignments) callerIdentity {
	c.pathEnv = envAs.effectivePATHFrom(c.pathEnv)
	extra := envAs.taintedSentinelNames()
	if len(extra) == 0 {
		return c
	}
	merged := make(map[string]bool, len(c.envTaint)+len(extra))
	for k, v := range c.envTaint {
		merged[k] = v
	}
	for k := range extra {
		merged[k] = true
	}
	c.envTaint = merged
	return c
}

// callerIdentity returns a callerIdentity consistent with g's role flags so
// direct unit-test guardCall structs (e.g. guardCall{subagent: true} run
// under `CTXMODE_ROLE=verifier go test`) never inherit a conflicting role
// from the outer test runner's process environment.
func (g guardCall) callerIdentity() callerIdentity {
	c := currentCallerIdentity()
	if !g.readonly && !g.strictReadonly {
		c.readonly = ""
		if auditRoleIsReadonly(c.role) {
			c.role = "worker"
		} else if c.role == "" && g.subagent {
			c.role = "worker"
		}
	} else {
		if !callerReadonlyRole(c) {
			c.readonly = "1"
		}
	}
	return c
}

// wrapperWriteOpHit scans the leading wrapper chain of argv for options
// that WRITE: strace/ltrace -o FILE / --output=FILE, /usr/bin/time -o FILE
// / --output=FILE, flock -o / --close. Peeling must not discard them — a
// strict read-only caller running `strace -o /tmp/t ls` still writes
// /tmp/t. Non-writing wrappers and KEY=VAL prefixes are stepped through
// the same way peelWrappers walks them, so `env strace -o /tmp/t ls` and
// `FOO=1 nice time -o /tmp/t ls` cannot hide the write behind a prefix.
// The scan stops at the first operand that is not part of a wrapper; it
// returns the offending `head -o` detail or "".
func wrapperWriteOpHit(argv []string) string {
	var envAs envAssignments
	for i := 0; i < len(argv); {
		a := argv[i]
		if isAssignWord(a) {
			envAs.addAssign(a)
			i++
			continue
		}
		if shellNoopWords[a] {
			i++
			continue
		}
		base := filepath.Base(a)
		switch base {
		case "strace", "ltrace":
			j := i + 1
			for j < len(argv) {
				a := argv[j]
				if a == "--" {
					j++
					break
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-o" || a == "--output" {
					return base + " -o"
				}
				if strings.HasPrefix(a, "-o") && len(a) > 2 || strings.HasPrefix(a, "--output=") {
					return base + " -o"
				}
				if straceArgHasValue(a) {
					j += 2
					continue
				}
				j++
			}
			i = j
		case "time":
			j := i + 1
			for j < len(argv) {
				a := argv[j]
				if a == "--" {
					j++
					break
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-o" || a == "--output" || strings.HasPrefix(a, "--output=") ||
					(strings.HasPrefix(a, "-o") && len(a) > 2) ||
					a == "-a" || a == "--append" {
					return base + " -o"
				}
				if a == "-f" || a == "--format" {
					j += 2
					continue
				}
				j++
			}
			i = j
		case "flock":
			j := i + 1
			for j < len(argv) {
				a := argv[j]
				if a == "--" {
					j++
					break
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-o" || a == "--close" {
					return base + " " + a
				}
				if flockArgHasValue(a) {
					j += 2
					continue
				}
				j++
			}
			i = j
		// Non-writing wrappers: step through exactly like peelWrappers does
		// so the scan keeps looking at the next head.
		case "if", "then", "elif", "else", "while", "until", "do", "!", "coproc":
			i++
		case "env":
			var payloads []string
			var rest []string
			rest, payloads, envAs = skipEnvOperands(argv, i+1, envAs)
			argv = rest
			i = 0
			_ = payloads // env -S payloads are screened by the caller chain
		case "command":
			if isCommandQuery(argv[i+1:]) {
				return "" // pure query: nothing after it executes
			}
			i++
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				i++
			}
			i = skipDashDash(argv, i)
		case "builtin":
			i++
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				i++
			}
			i = skipDashDash(argv, i)
		case "exec":
			// bash exec [-cl] [-a name] [--] command (internal_getopt "cla:").
			i, _ = skipExecArgs(argv, i+1)
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
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-n" || a == "--adjustment" {
					i += 2 // separate value
					continue
				}
				i++ // -nN / -n-N / --adjustment=N / -N glued level / boolean
			}
		case "timeout":
			i, _ = skipTimeoutArgs(argv, i+1)
		case "stdbuf":
			i, _ = skipStdbufArgs(argv, i+1)
		case "busybox":
			i++
		case "ionice":
			i, _ = skipIoniceArgs(argv, i+1)
		case "taskset":
			i, _ = skipTasksetArgs(argv, i+1)
		case "chrt":
			i, _ = skipChrtArgs(argv, i+1)
		case "--":
			i++
		default:
			return ""
		}
	}
	return ""
}

// straceArgHasValue reports whether an strace/ltrace option consumes a
// separate value slot (so the next argv word is its argument, not the
// traced command). The list MUST match skipStraceArgs' two-slot set — an
// option missing here lets its value masquerade as the traced command
// and can hide a later -o FILE from wrapperWriteOpHit.
func straceArgHasValue(a string) bool {
	switch a {
	case "-e", "-o", "-p", "-s", "-u", "-E", "-a", "-b", "-O", "-S", "-I", "-P",
		"-X", "-U",
		"--trace", "--output", "--attach", "--string-limit", "--user",
		"--env", "--columns", "--const-print-style", "--summary-columns",
		"--trace-path", "--signal":
		return true
	}
	return false
}

// flockArgHasValue reports whether a flock option consumes a separate
// value slot: -w/--timeout SEC, -E/--conflict-exit-code CODE,
// -F/--fcntl, -d/--fd FD.
func flockArgHasValue(a string) bool {
	switch a {
	case "-w", "--timeout", "-E", "--conflict-exit-code", "-F", "--fcntl",
		"-d", "--fd":
		return true
	}
	return false
}

// peelResolved strips wrappers from argv then applies the shared recursive
// checks (env -S payload, execution-hook env screen, shell -c unwrap,
// interpreter inline code, eval / xargs / find tail recursion, watch/flock
// inner commands, trap actions, unset targets) for the given guard kind.
// kind is 's' (subagent) or 'r' (strict read-only); depth bounds recursion
// and fails closed at peelChainMaxDepth. It returns the guard hit or "".
func peelResolvedDepth(argv []string, kind byte, depth int, caller callerIdentity) string {
	return peelResolvedSegDepth(argv, shellSegment{}, kind, depth, caller)
}
func peelResolvedSegDepth(argv []string, seg shellSegment, kind byte, depth int, caller callerIdentity) string {
	if len(argv) == 0 || depth >= peelChainMaxDepth {
		if depth >= peelChainMaxDepth {
			return depthExceededHit
		}
		return ""
	}
	if kind == 'r' {
		if hit := wrapperWriteOpHit(argv); hit != "" {
			return hit
		}
		// Reject exec/eval/source before peelWrappers strips them.
		if hit := readonlyPrePeelHit(argv); hit != "" {
			return allowlistDetail(hit)
		}
	}
	head, splitPayloads, envAs, exhausted := peelWrappers(argv)
	if exhausted {
		return depthExceededHit // fail closed: wrapper chain never resolved
	}
	screenPayloads := func() string {
		for _, payload := range splitPayloads {
			if strings.HasPrefix(payload, envUnknownLongPrefix) {
				return "env unknown option " + strings.TrimPrefix(payload, envUnknownLongPrefix)
			}
			if kind == 's' {
				seeded := caller.seededWith(envAs)
				if hit := guardShellSubagentDepthEnv(payload, depth+1, seeded, seeded.envTaint); hit != "" {
					return hit
				}
			} else {
				if hit := guardShellReadonlyDepth(payload, depth+1, caller); hit != "" {
					return hit
				}
			}
		}
		return ""
	}
	if len(head) == 0 {
		if hit := screenEnvAssignments(envAs, kind, caller.role, caller.readonly, ""); hit != "" {
			return hit
		}
		return screenPayloads()
	}
	if isDynamicArg(head[0]) {
		return "dynamic command head"
	}
	base := filepath.Base(head[0])
	typedHead := head
	// A typed GNU-prefixed name (genv, gfind, gtimeout — the on-disk
	// Homebrew/Linuxbrew spelling) is the same program as its canonical
	// name: normalize head[0] so the name-keyed screens see the real
	// tool even when nothing in PATH needs resolving.
	if canon := canonicalResolvedBase(base); canon != base {
		head = append([]string{canon}, head[1:]...)
		base = canon
	}
	effPath := envAs.effectivePATHFrom(caller.pathEnv)
	// C10: verify that the winning PATH binary is not an untrusted file or a
	// planted binary in a user-writable toolchain dir shadowing a system command.
	if hit := screenPathHeadTrust(typedHead[0], effPath); hit != "" {
		return hit
	}
	if rb := resolveHeadBase(head[0], effPath); rb != "" && rb != base {
		// Only promote the symlink target into head[0]/base when the typed
		// head is NOT already a structural guard/interpreter head (so
		// `python3 -> custom_runner` never loses `python3 -c` unwrapping).
		if rb = canonicalResolvedBase(rb); rb != base {
			if isStructuralGuardHead(base) {
				// A structural head resolving into a DIFFERENT structural
				// family or a wrapper binary (python3 -> dash, sed -> env)
				// is a conflicting alias — the typed name's unwrapping
				// rules no longer match what will actually run. Same-family
				// aliases (/bin/sh -> dash, python3 -> python3.13) keep the
				// typed base.
				if (isStructuralGuardHead(rb) || isPeeledWrapperBase(rb)) && !sameStructuralFamily(base, rb) {
					return "conflicting structural alias " + filepath.Base(typedHead[0]) + " -> " + rb
				}
			} else {
				head = append([]string{rb}, head[1:]...)
				base = rb
			}
		}
	}
	if hit := screenEnvAssignments(envAs, kind, caller.role, caller.readonly, base); hit != "" {
		return hit
	}
	caller = caller.seededWith(envAs)
	if hit := screenPayloads(); hit != "" {
		return hit
	}
	if base == "command" && isCommandQuery(head[1:]) {
		if kind == 's' {
			if hit := screenNestedDispatch(typedHead, effPath, depth, caller); hit != "" {
				return hit
			}
		}
		return ""
	}
	if base == "ctxmode" && callerReadonlyRole(caller) && ctxmodeCLIAction(head[1:]) == "index" {
		return "ctxmode index"
	}
	// C10: screen typedHead for nested-agent dispatch BEFORE any early-return
	// unwrap branch (ssh, sh -c, python -c, xargs, find, etc.) so a symlink
	// `pig -> sh` or `pig -> ssh` cannot bypass the blocked-head check.
	if kind == 's' && filepath.Base(typedHead[0]) != base {
		if hit := screenNestedDispatch(typedHead, effPath, depth, caller); hit != "" {
			return hit
		}
	}
	// ssh: peel OpenSSH options and screen remote command.
	if base == "ssh" {
		if kind == 'r' && filepath.Base(typedHead[0]) != "ssh" {
			if hit := screenReadonlyAllowlist(typedHead); hit != "" {
				return allowlistDetail(hit)
			}
		}
		return screenSSHHead(head, seg, kind, depth, caller)
	}
	// A symlink target promoted to a WRAPPER (PATH entry foo -> sbx/env/
	// timeout/...) was not peeled — peelWrappers ran on the TYPED name
	// before the alias resolution rewrote head[0]. Re-screen the promoted
	// argv so the wrapper's own options (sbx --env/-S, env -u/-S, timeout's
	// duration slot) and inner command head get the same treatment a
	// directly typed invocation receives. A real wrapper head
	// (typedHead[0] already names it) already peeled above and must not
	// re-enter. `caller` is already envAs-seeded.
	if isPeeledWrapperBase(base) && filepath.Base(typedHead[0]) != base {
		return peelResolvedSegDepth(head, seg, kind, depth+1, caller)
	}
	// Strict readonly: allowlist before shell/interpreter unwrap, plus
	// C10 alias target allowlist verification.
	if kind == 'r' {
		if hit := screenReadonlyAllowlist(typedHead); hit != "" {
			return allowlistDetail(hit)
		}
		if hit := screenReadonlyAliasTarget(typedHead, effPath); hit != "" {
			return allowlistDetail(hit)
		}
	}
	if hasDynamicInterpOption(head, base) {
		return "dynamic code payload"
	}
	switch base {
	case "export", "readonly", "declare", "typeset", "local":
		if kind == 's' {
			dropsExport, nameref := declFlagOps(base, head[1:])
			if nameref {
				return "env " + base + " -n"
			}
			var envAs2 envAssignments
			for _, a := range head[1:] {
				if isDynamicArg(a) && !isAssignWord(a) {
					return "env dynamic export"
				}
				if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
					continue
				}
				key := a
				if eq := strings.IndexByte(a, '='); eq >= 0 {
					key = a[:eq]
				}
				if dropsExport {
					if guardTaintVars[key] || isEnvHookVar(key) {
						return "env " + key
					}
					envAs2.ops = append(envAs2.ops, envOp{kind: 'u', key: key})
					continue
				}
				if isAssignWord(a) || strings.Contains(a, "=") {
					envAs2.addAssign(a)
				}
			}
			if hit := screenEnvAssignments(envAs2, kind, caller.role, caller.readonly, base); hit != "" {
				return hit
			}
		}
	}
	if kind == 's' {
		if hit := screenEnvWriteTargets(head, base); hit != "" {
			return hit
		}
	}
	if text, has := unwrapShellArgv(head); has {
		if isDynamicArg(text) {
			return "dynamic code payload"
		}
		if kind == 's' {
			inner := caller.seededWith(envAs)
			// The -c payload parses under the RESOLVED shell dialect: a
			// same-family alias (sh -> bash) keeps its typed base, but the
			// running interpreter is bash, so bash-only syntax must be
			// judged as bash, not POSIX sh.
			shellDialect := base
			if shellHeads[base] {
				if rb := canonicalResolvedBase(resolveHeadBase(typedHead[0], effPath)); shellHeads[rb] {
					shellDialect = rb
				}
			}
			switch shellDialect {
			case "bash", "zsh", "ksh", "mksh":
				return guardShellSubagentDepthBash(text, depth+1, inner)
			}
			return guardShellSubagentDepth(text, depth+1, inner)
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	if lang, code, has := unwrapInterpreterInline(head); has {
		if isDynamicArg(code) {
			return "dynamic code payload"
		}
		if lang == "python-module" {
			if kind == 'r' {
				return allowlistDetail("python interpreter")
			}
			if modArgv := pythonModuleArgvFrom(head); len(modArgv) > 0 {
				if hit := peelResolvedDepth(modArgv, 's', depth+1, caller.seededWith(envAs)); hit != "" {
					return hit
				}
			}
			return ""
		}
		if kind == 'r' {
			return allowlistDetail(lang + " program text")
		}
		g := guardCall{}
		if kind == 's' {
			g.subagent = true
			g.readonly = callerReadonlyRole(caller)
		} else {
			g.strictReadonly = true
			g.readonly = true
		}
		if rule, detail := g.guardCtxRunCode(lang, code); rule != "" {
			if detail == roSSHWriteHit || detail == "ctxmode index" {
				return detail
			}
			return lang + " inline code"
		}
		if kind == 'r' && (base == "perl" || base == "ruby") {
			if hasInterpInPlaceFlag(head) {
				return base + " -i"
			}
		}
		return ""
	}
	// eval: join remaining args and screen as shell text.
	if base == "eval" && len(head) > 1 {
		if kind == 'r' {
			return allowlistDetail("eval")
		}
		text := strings.Join(head[1:], " ")
		if isDynamicArg(text) {
			return "dynamic code payload"
		}
		if kind == 's' {
			return guardShellSubagentDepth(text, depth+1, caller.seededWith(envAs))
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	// xargs: peel xargs options, model derived stdin/fed-code context (2.c),
	// then screen the target command argv.
	if base == "xargs" {
		if k := xargsTargetIndex(head); k >= 0 && k < len(head) {
			if xargsFeedsCodeFlag(head[k:], head, caller.pathEnv) {
				return "dynamic code payload"
			}
			if repl := xargsReplToken(head); repl != "" && replTokenInExecSlot(head[k:], repl, caller.pathEnv) {
				return "dynamic code payload"
			}
			innerSeg := xargsDerivedSeg(head[:k], head[k:], seg, caller.pathEnv)
			return peelResolvedSegDepth(head[k:], innerSeg, kind, depth+1, caller.seededWith(envAs))
		}
		return "" // `xargs` with no command runs echo: read-only
	}
	// find: scan for -exec/-execdir/-ok/-okdir (inner command recursion, with
	// explicit stdin context modelling for -ok vs -exec) and -delete/-fprint*.
	if base == "find" {
		if kind == 'r' {
			if hit := screenReadonlyAllowlist(typedHead); hit != "" {
				return allowlistDetail(hit)
			}
			return screenFindArgsSeg(head[1:], seg, kind, depth+1, caller)
		}
		return screenFindArgsSeg(head[1:], seg, kind, depth+1, caller.seededWith(envAs))
	}
	// trap: a non-print action argument is shell text to screen.
	if base == "trap" {
		return screenTrapArgs(head[1:], kind, depth+1, caller)
	}
	// unset: clearing CTXMODE_ROLE/CTXMODE_READONLY sheds the guard.
	if base == "unset" {
		return screenUnsetArgs(head[1:], kind)
	}
	// watch: GNU watch runs its operands through `sh -c` by default; only
	// -x/--exec makes them a direct exec argv (which inherits fd 0).
	if base == "watch" && len(head) > 1 {
		k, execMode, fc := skipWatchArgs(head, 1)
		if fc {
			return "dynamic code payload"
		}
		if k >= len(head) {
			return ""
		}
		if execMode {
			return peelResolvedSegDepth(head[k:], seg, kind, depth+1, caller.seededWith(envAs))
		}
		text := strings.Join(head[k:], " ")
		if isDynamicArg(text) {
			return "dynamic code payload"
		}
		if kind == 's' {
			return guardShellSubagentDepth(text, depth+1, caller.seededWith(envAs))
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	// flock: peel its own options + lock operand, then screen the inner
	// command while preserving the enclosing segment's stdin context (2.c).
	if base == "flock" {
		if kind == 'r' {
			return "flock"
		}
		inner, cmdText := skipFlockArgs(head, 1)
		if cmdText != "" {
			if isDynamicArg(cmdText) {
				return "dynamic code payload"
			}
			return guardShellSubagentDepth(cmdText, depth+1, caller.seededWith(envAs))
		}
		if inner < len(head) {
			return peelResolvedSegDepth(head[inner:], seg, kind, depth+1, caller.seededWith(envAs))
		}
		return ""
	}
	// script: `-c cmd` runs cmd through a shell inside a pty.
	if base == "script" {
		if kind == 'r' {
			return "script"
		}
		if payload := scriptCommandArg(head); payload != "" {
			if isDynamicArg(payload) {
				return "dynamic code payload"
			}
			return guardShellSubagentDepth(payload, depth+1, caller.seededWith(envAs))
		}
		return ""
	}
	if kind == 's' && (base == "awk" || base == "gawk" || base == "mawk" || base == "nawk") {
		if hit := screenAwkSubagent(head[1:], depth, caller); hit != "" {
			return hit
		}
	}
	if kind == 's' && (base == "sed" || base == "gsed") {
		if hit := screenSedSubagent(head[1:], depth, caller); hit != "" {
			return hit
		}
	}
	if kind == 's' && (base == "tar" || base == "gtar" || base == "bsdtar") {
		if hit := screenTarSubagent(head[1:], depth, caller); hit != "" {
			return hit
		}
	}
	if kind == 's' && (base == "npx" || base == "bunx" || base == "pnpx") {
		if hit := screenNodeRunnerSubagent(base, head[1:], effPath, depth, caller); hit != "" {
			return hit
		}
	}
	if kind == 's' {
		return screenNestedDispatch(typedHead, effPath, depth, caller)
	}
	if hit := screenReadonlyAllowlist(typedHead); hit != "" {
		return allowlistDetail(hit)
	}
	return screenReadonlyWritePath(typedHead, effPath)
}

// xargsHasArgFile reports whether the xargs option zone (before the target
// command) specifies -a FILE or --arg-file[=FILE]. When present, xargs reads
// items from the file and leaves the child process's fd 0 inherited from the
// enclosing shellSegment.
func xargsHasArgFile(xargsOpts []string) bool {
	for i := 1; i < len(xargsOpts); i++ {
		a := xargsOpts[i]
		if a == "--" {
			return false
		}
		if a == "--arg-file" || strings.HasPrefix(a, "--arg-file=") {
			return true
		}
		if strings.HasPrefix(a, "--") {
			if !strings.Contains(a, "=") && xargsLongWithValue[a] {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			for j := 1; j < len(a); j++ {
				ch := a[j]
				if ch == 'a' {
					return true
				}
				if ch == 'e' || ch == 'i' {
					break
				}
				if xargsShortWithValue[ch] {
					if j+1 >= len(a) {
						i++
					}
					break
				}
			}
		}
	}
	return false
}

// xargsDerivedSeg models the shellSegment seen by the target command of
// xargs: with -a/--arg-file, the child inherits outerSeg's stdin stream;
// without -a, xargs consumes outerSeg's stdin to build trailing argv tokens
// and redirects child fd 0 to /dev/null — EXCEPT when the target command is
// an ssh invocation whose remote command reads a program from stdin
// (`echo code | xargs ssh dmit sh`), where OpenSSH joins xargs-appended
// words into the remote login shell command string.
func xargsDerivedSeg(xargsOpts, targetArgv []string, outerSeg shellSegment, pathEnv string) shellSegment {
	if xargsHasArgFile(xargsOpts) {
		return outerSeg
	}
	hasOuterInput := outerSeg.pipedStdin || outerSeg.stdinRedir ||
		outerSeg.hereString != "" || len(outerSeg.heredocText) > 0
	if hasOuterInput && sshTunnelsStdinProgram(targetArgv, pathEnv) {
		return shellSegment{pipedStdin: true}
	}
	return shellSegment{}
}

// replTokenInExecSlot reports whether a placeholder token (xargs -I token or
// find -exec "{}") sits in a command-execution slot of innerArgv: the peeled
// command head itself, an inline shell/interpreter code slot (-c/-e), or the
// remote command head / code slot inside an ssh invocation. Data operand
// positions (`grep foo {}`, `git -C {} status`, `sh -c 'echo "$1"' _ {}`)
// return false.
func replTokenInExecSlot(innerArgv []string, token, pathEnv string) bool {
	if token == "" || len(innerArgv) == 0 {
		return false
	}
	head, _, effPath, exhausted := peelWrappersAndSbxAliases(innerArgv, pathEnv)
	if exhausted || len(head) == 0 {
		return true
	}
	if strings.Contains(head[0], token) {
		return true
	}
	if text, has := unwrapShellArgv(head); has {
		return strings.Contains(text, token)
	}
	if _, code, has := unwrapInterpreterInline(head); has {
		return strings.Contains(code, token)
	}
	for _, slot := range interpCodeSlots(head) {
		if slot.flagOnly || strings.Contains(slot.text, token) {
			return true
		}
	}
	base := filepath.Base(head[0])
	if base == "ssh" || resolveHeadBase(head[0], effPath) == "ssh" {
		remoteCmd, hit := parseSSHInvocation(head)
		if hit != "" {
			return true
		}
		for _, rseg := range splitShellSegments(remoteCmd) {
			if len(rseg.argv) == 0 {
				continue
			}
			// In POSIX sh, a lone "{}" is parsed into shellNoopWords or a
			// command head containing the token.
			if replTokenInExecSlot(rseg.argv, token, os.Getenv("PATH")) {
				return true
			}
		}
		if strings.TrimSpace(remoteCmd) == token {
			return true
		}
	}
	return false
}

const roSSHWriteHit = "ssh remote write"

func screenSSHHead(head []string, seg shellSegment, kind byte, depth int, caller callerIdentity) string {
	remoteCmd, hit := parseSSHInvocation(head)
	if hit != "" {
		return hit
	}
	if kind == 'r' || callerReadonlyRole(caller) {
		// A read-only caller must not use ssh as a write/exfil channel:
		// piped bytes reach the remote shell unaudited (local file
		// exfiltration), and StrictHostKeyChecking=no|accept-new without
		// UserKnownHostsFile=/dev/null|none makes ssh WRITE the local
		// ~/.ssh/known_hosts. Worker (kind 's' non-readonly) is unaffected.
		if seg.pipedStdin {
			return roSSHWriteHit
		}
		if h := sshKnownHostsHit(head); h != "" {
			return h
		}
	}
	langs, stdinIsProg := remoteStdinProgramLangs(remoteCmd)
	if seg.pipedStdin && stdinIsProg {
		if kind == 'r' || callerReadonlyRole(caller) {
			return roSSHWriteHit
		}
		return "piped stdin to ssh"
	}
	if stdinIsProg && seg.stdinRedir {
		if kind == 'r' || callerReadonlyRole(caller) {
			return roSSHWriteHit
		}
		return "file stdin to ssh stdin-program"
	}
	if stdinIsProg {
		if len(langs) > 1 && (seg.hereString != "" || len(seg.heredocText) > 0) {
			return "ssh multi-stage stdin program"
		}
		screenBody := func(body string) string {
			if isDynamicArg(body) {
				return "dynamic code payload"
			}
			if body == "" {
				return ""
			}
			if len(langs) == 0 {
				langs = []string{""}
			}
			bodyKind := kind
			if kind == 's' && callerReadonlyRole(caller) {
				bodyKind = 'r'
			}
			for _, lang := range langs {
				if h := screenStdinProgram(body, lang, bodyKind, depth, caller); h != "" {
					if kind == 'r' || callerReadonlyRole(caller) {
						return roSSHWriteHit
					}
					return h
				}
			}
			return ""
		}
		if seg.hereString != "" {
			if h := screenBody(seg.hereString); h != "" {
				return h
			}
		}
		for _, hb := range seg.heredocText {
			if hb.dynamic {
				return "dynamic code payload"
			}
			if h := screenBody(hb.text); h != "" {
				return h
			}
		}
	}
	// Exemption from remote readonly screening applies ONLY when a local
	// static stdin payload (already screened above) feeds a single pure
	// remote stdin-program vehicle (`sh`, `python3 -`). Both kind == 'r' and
	// read-only callers under kind == 's' (verifier / CTXMODE_READONLY=1)
	// share this exact gate so `ssh dmit "rm -rf /tmp/x; sh"` or bare
	// `find . -exec ssh dmit sh \;` can never slip past readonly screening.
	vehicleOnly := stdinIsProg &&
		(seg.hereString != "" || len(seg.heredocText) > 0) &&
		isPureRemoteStdinVehicle(remoteCmd)

	remoteCaller := caller
	remoteCaller.envTaint = nil
	remoteCaller.pathEnv = ""
	if kind == 's' {
		if h := guardShellSubagentDepthEnv(remoteCmd, depth+1, remoteCaller, nil); h != "" {
			return h
		}
		if callerReadonlyRole(caller) && !vehicleOnly {
			if h := guardShellReadonlyDepth(remoteCmd, depth+1, remoteCaller); h != "" {
				return roSSHWriteHit
			}
		}
		return ""
	}
	if !vehicleOnly {
		if h := guardShellReadonlyDepth(remoteCmd, depth+1, remoteCaller); h != "" {
			return roSSHWriteHit
		}
	}
	return ""
}

// isPureRemoteStdinVehicle reports whether remoteCmd parses (under the
// strict readonly grammar) into EXACTLY ONE command whose head reads its
// program from stdin (a bare `sh`, `python3 -`, `node -`…): no other
// segments, no output redirect, no write-capable wrapper ops, no env
// prefixes — anything else can carry an unaudited side effect and is not
// pure. Input redirections and background/& are rejected by the readonly
// grammar itself (SH11 MF-1/F7).
func isPureRemoteStdinVehicle(remoteCmd string) bool {
	roSegs, hit := parseReadonlyShellSegments(remoteCmd)
	if hit != "" || len(roSegs) != 1 {
		return false
	}
	s := roSegs[0]
	if s.pipedStdin || s.redirectFile != "" || len(s.heredocText) > 0 || len(s.argv) == 0 {
		return false
	}
	if wrapperWriteOpHit(s.argv) != "" {
		return false
	}
	// Any env op (KEY=VAL prefix or env -i/-u/assign) mutates the remote
	// vehicle's environment — not pure. `env FOO=1 sh` would otherwise
	// smuggle an unscreened override through the exemption (R7).
	if _, _, envAs, _ := peelWrappers(s.argv); len(envAs.ops) > 0 {
		return false
	}
	// The head must be EXACTLY a bare stdin-program SHELL: `node -`,
	// `python3 -` and friends hand the already-screened body to an
	// interpreter whose OWN code primitives (open/write/exec) are far
	// wider than the shell grammar the body was screened under, so only
	// a lang == "" head qualifies for the exemption (A-1).
	lang, isProg := stdinProgramHead(s.argv)
	return isProg && lang == ""
}

// remoteReadsProgramFromStdin reports whether the remote command string
// contains a head that reads its program from stdin (a bare remote
// `sh`/`python3 -` with no inline code). Only then are piped bytes
// unaudited remote CODE rather than data for the remote command.
func remoteReadsProgramFromStdin(remoteCmd string) bool {
	_, reads := remoteStdinProgramLangs(remoteCmd)
	return reads
}

// remoteStdinProgramLangs returns the interpreter langs of remote heads that
// read program text from stdin (SF-2).
func remoteStdinProgramLangs(remoteCmd string) (langs []string, readsProg bool) {
	for _, seg := range splitShellSegments(remoteCmd) {
		if seg.depthExceeded || seg.parseErr != "" {
			return []string{""}, true
		}
		if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || seg.backgrounded ||
			len(seg.heredocText) > 0 || seg.hereString != "" {
			continue
		}
		if lang, isProg := stdinProgramHead(seg.argv); isProg {
			langs = append(langs, lang)
		}
	}
	return langs, len(langs) > 0
}

// sshNoArgShorts are OpenSSH short options that take no operand.
const sshNoArgShorts = "46AaCfGgKkMNnqsTtVvXxYy"

// sshArgShortsSet are OpenSSH short options that consume an operand,
// either glued (-p2222) or as the next argv (-p 2222): -B -b -c -D -E -e
// -F -I -i -J -L -l -m -O -o -p -Q -R -S -W -w.
const sshArgShortsSet = "BbcDEeFIiJLlmOopQRSWw"

// sshShortTakesValue reports whether short option letter c consumes an
// operand.
func sshShortTakesValue(c byte) bool {
	return strings.IndexByte(sshArgShortsSet, c) >= 0
}

// sshBannedShorts are short options (or letters inside a cluster) that must
// never reach a role-guarded ssh: they arm a config file, a jump host
// (same reach as -o ProxyJump), a control socket, a forwarding channel or
// a local side effect the guards cannot see.
const sshBannedShorts = "FSMOLRDWwNfGQsEJI"

// sshBannedLongs are long-option names rejected outright (value or not).
var sshBannedLongs = map[string]bool{
	"localforward": true, "remoteforward": true, "dynamicforward": true,
	"permitlocalcommand": true, "controlpersist": true, "configfile": true,
}

// sshSafeOKeys are the only -o option names (lowercased) a role-guarded ssh
// may set: pure connection hygiene with no exec, forwarding or config-file
// reach. controlmaster/controlpath pass only with a hard "no"/"none"
// value — screened separately so `ssh -o ControlPath=/tmp/x` never
// re-opens the control-socket hole the -S/-M ban closed.
var sshSafeOKeys = map[string]bool{
	"batchmode": true, "connecttimeout": true, "stricthostkeychecking": true,
	"userknownhostsfile": true, "globalknownhostsfile": true,
	"identitiesonly": true, "identityfile": true, "certificatefile": true,
	"port": true, "user": true, "hostname": true,
	"serveraliveinterval": true, "serveralivecountmax": true,
	"loglevel": true, "connectionattempts": true, "addressfamily": true,
	"requesttty": true, "compression": true, "ciphers": true, "macs": true,
	"kexalgorithms": true, "hostkeyalgorithms": true,
	"pubkeyacceptedalgorithms": true, "pubkeyacceptedkeytypes": true,
	"pubkeyauthentication": true, "passwordauthentication": true,
	"kbdinteractiveauthentication": true, "numberofpasswordprompts": true,
	"forwardagent": true, "ipqos": true, "escapechar": true,
	"tcpkeepalive": true, "canonicalizehostname": true,
	"checkhostip": true, "enableescapecommandline": true,
	// controlmaster/controlpath pass the KEY whitelist but are value-gated
	// by sshOValueOK: only "no"/"none" is allowed, so the control-socket
	// hole the -S/-M/-O ban closed cannot re-open through -o.
	"controlmaster": true, "controlpath": true,
}

// sshOValueOK reports whether a whitelisted -o key may carry this value.
// The value-sensitive keys are the control-socket pair, the known-hosts
// files (an arbitrary path plus accept-new gives a read-only caller a
// local file-write side effect) and the interactive ~C escape-command
// line: everything else accepts its value unchecked (the key whitelist
// is what vetted it).
func sshOValueOK(key, val string) bool {
	switch key {
	case "controlmaster":
		return strings.EqualFold(val, "no")
	case "controlpath":
		return strings.EqualFold(val, "none")
	case "userknownhostsfile", "globalknownhostsfile":
		// Only sink/keep spellings stay: an arbitrary path pairs with
		// StrictHostKeyChecking=accept-new to write host keys locally.
		return val == "/dev/null" || strings.EqualFold(val, "none")
	case "enableescapecommandline":
		// The interactive ~C command line runs local commands; only the
		// explicit disable value is allowed through.
		return strings.EqualFold(val, "no")
	}
	return true
}

// sshKnownHostsHit screens the -o option words of an ssh argv for
// StrictHostKeyChecking=no|accept-new without a matching
// UserKnownHostsFile=/dev/null|none: a read-only caller must not let ssh
// write the local ~/.ssh/known_hosts. Replays parseSSHInvocation's -o
// operand consumption (glued tail or next argv); any other option shape
// is ignored here because parseSSHInvocation already vetted it.
func sshKnownHostsHit(head []string) string {
	shkc := ""
	ukhSink := false
	endOpts := false
	for i := 1; i < len(head); i++ {
		a := head[i]
		if isDynamicArg(a) {
			continue // placeholder words already gated by parseSSHInvocation
		}
		if !endOpts && a == "--" {
			endOpts = true
			continue
		}
		if endOpts || len(a) < 2 || a[0] != '-' {
			continue // destination or remote command words
		}
		if strings.HasPrefix(a, "--") {
			continue
		}
		for j := 1; j < len(a); j++ {
			c := a[j]
			if c == 'o' {
				var v string
				if j+1 < len(a) {
					v = a[j+1:]
				} else if i+1 < len(head) {
					i++
					v = head[i]
				} else {
					j = len(a)
					continue
				}
				key, val := v, ""
				if k := strings.IndexAny(v, "= \t"); k >= 0 {
					key, val = v[:k], strings.Trim(v[k+1:], " \t\r\n")
				}
				switch strings.ToLower(strings.Trim(key, " \t\r\n")) {
				case "stricthostkeychecking":
					shkc = strings.ToLower(val)
				case "userknownhostsfile":
					if val == "/dev/null" || strings.EqualFold(val, "none") {
						ukhSink = true
					}
				}
				j = len(a)
				continue
			}
			if sshShortTakesValue(c) {
				if j+1 >= len(a) && i+1 < len(head) {
					i++ // separate operand
				}
				j = len(a)
			}
		}
	}
	if (shkc == "no" || shkc == "accept-new") && !ukhSink {
		return roSSHWriteHit
	}
	return ""
}

// screenSSHOpt screens one -o option TEXT (the operand after -o or the
// glued tail): OpenSSH accepts both `-o key=val` and `-o "key val"`.
// The key (lowercased for the lookup) must appear in sshSafeOKeys and pass
// the value-sensitive check; every other key is refused by name so
// proxycommand/proxyjump/localcommand/remotecommand/match/include and
// friends can never reach the client config. Trimming is ASCII-blank only
// (" \t\r\n") — matching OpenSSH readconf.c, which treats a non-ASCII
// blank like U+00A0 as part of the word rather than whitespace, so
// `UserKnownHostsFile=none ` stays a literal path instead of being
// trimmed into a `none` that the sink-value gate would admit.
func screenSSHOpt(optText string) string {
	key, val := optText, ""
	if k := strings.IndexAny(optText, "= \t"); k >= 0 {
		key, val = optText[:k], strings.Trim(optText[k+1:], " \t\r\n")
	}
	key = strings.ToLower(strings.Trim(key, " \t\r\n"))
	if key == "" {
		return "-o" // empty option text: unvetted, fail closed
	}
	if !sshSafeOKeys[key] {
		return "-o " + key
	}
	if !sshOValueOK(key, val) {
		return "-o " + key
	}
	return ""
}

// parseSSHInvocation walks an ssh argv after head[0] and returns the
// remote command text OpenSSH would run (strings.Join of every word after
// <destination>), or a guard hit naming the offending option. It
// understands single-dash short clusters (no-arg letters may pack, a
// value-taking letter ends its cluster and may carry a glued tail or the
// next argv) and double-dash long options; a value-taking option whose
// operand never arrives is malformed and fails closed. The first
// non-option operand is <destination>; WITHOUT a `--` terminator OpenSSH
// (ssh.c `optind = optreset = 1; goto again`) keeps parsing options after
// it until the SECOND non-option word — so `ssh dmit -q pig` names the
// remote command `pig`, not `-q pig` — while after `--` the word
// following <destination> already starts the remote command. An empty
// destination or a missing remote command both block (bare `ssh host`
// drops the caller into an unaudited interactive login shell).
func parseSSHInvocation(head []string) (remoteCmd, hit string) {
	i := 1
	endOpts := false
	sawDest := false
	for i < len(head) {
		a := head[i]
		if isDynamicArg(a) {
			// SH11 MF-2/Q1-C: a dynamic word may pass only where it cannot
			// become an option or inject extra words: no unquoted
			// placeholder (it field-splits), no word-start dq/abs-dq
			// placeholder only when options are still live (it may begin
			// with '-'). Words that survive here are joined into the remote
			// command text and screened remotely — an unsafe one still
			// fails there. Absolute paths and literal-tail dq words pass.
			if strings.Contains(a, cmdSubPlaceholder) || strings.Contains(a, cmdSubPlaceholderGlob) {
				return "", "dynamic code payload"
			}
			optionCapable := strings.HasPrefix(a, cmdSubPlaceholderQuoted)
			if !endOpts && !sawDest {
				// Option zone / destination slot: a word that may start
				// with '-' changes the local parse — refuse it; other
				// split-safe words serve as <destination>.
				if optionCapable {
					return "", "dynamic code payload"
				}
				sawDest = true
				i++
				continue
			}
			if !endOpts && optionCapable {
				// After <destination> without `--`, OpenSSH keeps parsing
				// options until the second non-option word — a possible '-'
				// word stays an option locally.
				return "", "dynamic code payload"
			}
			i++
			continue
		}
		if !endOpts && a == "--" {
			endOpts = true
			i++
			continue
		}
		if !endOpts && strings.HasPrefix(a, "--") {
			// OpenSSH ssh has no double-dash long options at all (even
			// --help/--version are 4.2BSD spellings that never run a
			// remote command): every `--name` is unvetted, so any
			// non-banned long option fails closed by its literal text.
			name := a[2:]
			if k := strings.IndexByte(name, '='); k >= 0 {
				name = name[:k]
			}
			if sshBannedLongs[strings.ToLower(name)] {
				return "", "--" + strings.ToLower(name)
			}
			return "", "ssh " + a
		}
		if !endOpts && len(a) > 1 && a[0] == '-' && a != "-" {
			// Short cluster: walk the letters; a no-arg letter continues the
			// cluster, a value-taking letter ends it (glued tail or next argv
			// is the operand), a banned letter blocks outright.
			for j := 1; j < len(a); j++ {
				c := a[j]
				switch {
				case strings.IndexByte(sshBannedShorts, c) >= 0:
					return "", "ssh -" + string(c)
				case c == 'o':
					// -o is value-taking AND its value is screened.
					var v string
					if j+1 < len(a) {
						v = a[j+1:]
					} else if i+1 < len(head) {
						i++
						v = head[i]
					} else {
						return "", "ssh"
					}
					if h := screenSSHOpt(v); h != "" {
						return "", "ssh " + h
					}
					j = len(a) // option operand ends the cluster
				case sshShortTakesValue(c):
					if j+1 < len(a) {
						// Glued operand: cluster ends here.
					} else if i+1 < len(head) {
						i++ // separate operand
					} else {
						return "", "ssh"
					}
					j = len(a)
				case strings.IndexByte(sshNoArgShorts, c) >= 0:
					continue
				default:
					// Unknown short letter: unvetted, fail closed.
					return "", "ssh -" + string(c)
				}
			}
			i++
			continue
		}
		if a == "" {
			return "", "ssh" // empty <destination> word
		}
		if !sawDest {
			// First non-option operand: <destination>. When `--` has not
			// ended options, OpenSSH re-enters getopt after it, so any
			// `-x`/`--x` words that follow are still ssh's own options and
			// continue through the screening above until the SECOND
			// non-option word — the real remote command head.
			sawDest = true
			i++
			continue
		}
		// Second non-option operand: everything from here is the remote
		// command OpenSSH joins and hands to the login shell.
		remote := strings.Join(head[i:], " ")
		if strings.Contains(remote, cmdSubPlaceholder) || strings.Contains(remote, cmdSubPlaceholderQuoted) ||
			strings.Contains(remote, cmdSubPlaceholderGlob) || strings.Contains(remote, cmdSubPlaceholderAbsDq) {
			return "", "dynamic code payload"
		}
		if strings.Trim(remote, " \t\r\n") == "" {
			return "", "ssh"
		}
		return remote, ""
	}
	return "", "ssh" // no <destination> at all
}

// scriptCommandArg returns the `-c cmd` payload of a `script` argv, or "".
// Short clusters count (`script -qc 'pig'`, `script -c"pig"`), as do
// --command/--command= forms.
func scriptCommandArg(head []string) string {
	for i := 1; i < len(head); i++ {
		a := head[i]
		if a != "--" && isDynamicArg(a) {
			return cmdSubPlaceholder
		}
		switch {
		case a == "-c" || a == "--command":
			if i+1 < len(head) {
				return head[i+1]
			}
			return ""
		case strings.HasPrefix(a, "--command="):
			return a[len("--command="):]
		case a == "--":
			return ""
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 2:
			// Short-option cluster: a 'c' letter carries the command text
			// (rest of the cluster, or the next argv when 'c' ends it).
			for j := 1; j < len(a); j++ {
				if a[j] == 'c' {
					if tail := a[j+1:]; tail != "" {
						return tail
					}
					if i+1 < len(head) {
						return head[i+1]
					}
					return ""
				}
			}
		case a == "-O" || a == "-I" || a == "-B" || a == "-T" ||
			a == "--log-out" || a == "--log-in" || a == "--log-timing" || a == "--timing":
			i++
		}
	}
	return ""
}

// toolchainRelPathHeads are the resolved command heads for which a RELATIVE
// PATH segment (node_modules/.bin, .venv/bin, venv/bin) is tolerated: they
// are toolchain executables living inside such directories. Controlled
// commands (git, sh, find, tar, awk, env, the guards' own tables) keep the
// absolute-only PATH rule so a repo's node_modules/.bin/git cannot shadow
// the screened binary (SH11 Q4).
var toolchainRelPathHeads = map[string]bool{
	"tsc": true, "tsx": true, "ts-node": true, "eslint": true,
	"jest": true, "vitest": true, "mocha": true, "ava": true,
	"babel": true, "webpack": true, "vite": true, "rollup": true,
	"esbuild": true, "turbo": true, "nx": true, "lerna": true,
	"node": true, "nodejs": true, "npx": true, "npm": true,
	"pnpm": true, "yarn": true, "bun": true, "bunx": true,
	"deno": true, "corepack": true,
	"python": true, "python2": true, "python3": true, "pip": true,
	"pip3": true, "pipx": true, "pytest": true, "uv": true, "poetry": true,
	"rye": true, "virtualenv": true, "mypy": true, "ruff": true,
	"black": true, "flake8": true, "pylint": true, "prettier": true,
}

// pathIsUnsafeForSubagent reports whether a PATH= value may inject a
// hostile executable ahead of (or instead of) the real one. Every segment
// is checked (no early exit): empty segments mean ".", relative segments
// are only the vetted toolchain directories and only when the command head
// is itself a toolchain executable, and every absolute segment must be a
// known system or toolchain directory. A $PATH/${PATH} expansion appears
// as the unforgeable envPathSelfPlaceholder; every other dynamic or
// literal-$ segment rejects (SH11 MF-5.1, Q4).
func pathIsUnsafeForSubagent(val, headBase string) bool {
	if val == "" {
		return true // empty PATH ≡ "."
	}
	relOK := toolchainRelPathHeads[headBase] || isToolchainVersionVariant(headBase)
	for _, p := range strings.Split(val, ":") {
		if p == "" {
			return true // leading/trailing/inner empty segment is "."
		}
		if p == envPathSelfPlaceholder {
			continue // genuine $PATH reference (unforgeable sentinel)
		}
		// Anything else carrying a placeholder or a literal '$' is an
		// unvetted expansion: a single-quoted '$PATH' segment would search
		// the relative directory ./$PATH.
		if isDynamicArg(p) || strings.Contains(p, "$") || strings.ContainsRune(p, '\x00') {
			return true
		}
		if !strings.HasPrefix(p, "/") {
			if relOK {
				switch p {
				case "node_modules/.bin", "./node_modules/.bin",
					".venv/bin", "./.venv/bin":
					continue
				}
			}
			return true
		}
		norm := filepath.Clean(p)
		if !isSafePathDirEntry(norm) {
			return true
		}
	}
	return false
}

// isToolchainVersionVariant reports whether headBase is a VERSIONED spelling
// of a toolchain interpreter (python3.12, python3, python2.7, node20, pypy3):
// the PATH relative-segment rule keys on the canonical name, so a resolved
// /usr/bin/python3 -> python3.12 alias must not lose its toolchain status.
func isToolchainVersionVariant(b string) bool {
	for _, stem := range []string{"python", "node", "pypy", "ruby", "perl", "php"} {
		if rest, ok := strings.CutPrefix(b, stem); ok && rest != "" && isVersionSuffix(rest) {
			return true
		}
	}
	return false
}

// isTmpOrScratchPath reports whether norm is under a world-writable scratch
// root (/tmp, /var/tmp, /dev/shm, /run), respecting testTrustedHomeRoot when
// an isolated unit test mounts a fake home inside t.TempDir().
func isTmpOrScratchPath(norm string) bool {
	if testTrustedHomeRoot != "" {
		th := filepath.Clean(testTrustedHomeRoot)
		if norm == th || strings.HasPrefix(norm, th+"/") {
			return false
		}
	}
	for _, bad := range []string{"/tmp", "/var/tmp", "/dev/shm", "/run"} {
		if norm == bad || strings.HasPrefix(norm, bad+"/") {
			return true
		}
	}
	return false
}

// trustedHomeDirs returns the canonical home directory prefixes that user
// toolchain PATH entries may sit under.
func trustedHomeDirs() []string {
	var homes []string
	if testTrustedHomeRoot != "" {
		homes = append(homes, filepath.Clean(testTrustedHomeRoot))
	}
	h := filepath.Clean(safeHomeDir())
	if h != "" && h != "/" {
		homes = append(homes, h)
	}
	if os.Geteuid() == 0 && h != "/root" {
		homes = append(homes, "/root")
	}
	// Do NOT append a /home/* wildcard when HOME is unset or /root.
	// Production root sessions (HOME=/root) must reject cross-user home
	// PATH segments such as /home/otheruser/.local/bin; trusting every
	// /home/<user> prefix would reopen the C10 foreign-home bypass.
	return homes
}

// stripTrustedHomePrefix removes a trusted home prefix from norm and returns
// the remainder starting with "/" (e.g. "/.local/bin"), or ("", false).
func stripTrustedHomePrefix(norm string) (string, bool) {
	for _, h := range trustedHomeDirs() {
		if strings.HasPrefix(norm, h+"/") {
			return norm[len(h):], true
		}
	}
	return "", false
}

// isUserToolchainPathDir reports whether norm is a recognized user-home or
// project-local development toolchain directory (anchored under a trusted
// home directory or the active screenCwd).
func isUserToolchainPathDir(norm string) bool {
	if tail, ok := stripTrustedHomePrefix(norm); ok {
		for _, toolPref := range []string{
			"/.local/share/mise/", "/.local/share/fnm/", "/.local/share/nvim/",
			"/.local/share/uv/", "/.mise/", "/.asdf/", "/.nvm/", "/.fnm/",
			"/.volta/", "/.rustup/", "/.pyenv/", "/.sdkman/",
		} {
			trimmed := strings.TrimSuffix(toolPref, "/")
			if tail == trimmed || strings.HasPrefix(tail, toolPref) {
				return true
			}
		}
		for _, toolSub := range []string{
			"/.local/share/mise/shims", "/.local/share/pnpm",
			"/.local/bin", "/.cargo/bin", "/go/bin", "/.go/bin",
			"/.pyenv/shims", "/.pyenv/bin", "/.poetry/bin", "/.rye/shims",
			"/.bun/bin", "/.deno/bin", "/.npm-global/bin", "/.yarn/bin",
			"/node_modules/.bin", "/.venv/bin", "/venv/bin",
		} {
			if tail == toolSub || strings.HasPrefix(tail, toolSub+"/") ||
				((toolSub == "/node_modules/.bin" || toolSub == "/.venv/bin" || toolSub == "/venv/bin") &&
					(strings.HasSuffix(tail, toolSub) || strings.Contains(tail, toolSub+"/"))) {
				return true
			}
		}
	}
	// Project-local venv / node_modules/.bin under currentScreenCwd().
	if cwd := currentScreenCwd(); cwd != "" {
		cleanCwd := filepath.Clean(cwd)
		if !isTmpOrScratchPath(cleanCwd) && strings.HasPrefix(norm, cleanCwd+"/") {
			rel := norm[len(cleanCwd):]
			for _, sub := range []string{"/node_modules/.bin", "/.venv/bin", "/venv/bin"} {
				if rel == sub || strings.HasPrefix(rel, sub+"/") || strings.HasSuffix(rel, sub) {
					return true
				}
			}
		}
	}
	return false
}

// statUIDAndPermOK checks that fi is owned by root (0) or euid, and when it
// is not a symlink (isLstatSymlink), that group/other write bits (0022) are
// clear.
func statUIDAndPermOK(fi os.FileInfo, euid int, allowSymlinkMode bool) bool {
	if fi == nil {
		return false
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if st.Uid != 0 && int(st.Uid) != euid {
			return false
		}
	}
	if allowSymlinkMode && fi.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return fi.Mode().Perm()&0022 == 0
}

// isTrustedPathDirOnDisk verifies filesystem ownership and permission bits
// for a PATH directory — user toolchain dirs must be root/euid-owned with
// no group/world write bit; at system locations ownership and write bits
// are not judged (ADAPT2; see the note below) — plus symlink target safety.
// Non-existent directories pass if their nearest existing ancestor is not a
// scratch path or world-writable, preserving dry-run and cross-machine
// replay compatibility.
func isTrustedPathDirOnDisk(norm string, euid int) bool {
	if isTmpOrScratchPath(norm) {
		return false
	}
	// The fixed linuxbrew prefix is judged like a system dir for ownership
	// (see the ADAPT2 note below): it is a package-manager prefix whose
	// owner is whoever installed brew — on GitHub runners a dedicated
	// linuxbrew user, neither root nor the caller's euid.
	sysDir := isSystemPathDir(norm) || isLinuxbrewPathDir(norm)
	lst, err := os.Lstat(norm)
	if err != nil {
		if !os.IsNotExist(err) {
			return false
		}
		// Walk up to the nearest existing ancestor to catch symlinked parent
		// directories pointing into /tmp.
		cur := filepath.Dir(norm)
		for cur != "/" && cur != "." {
			if isTmpOrScratchPath(cur) {
				return false
			}
			if _, aerr := os.Lstat(cur); aerr == nil {
				resolved, rerr := filepath.EvalSymlinks(cur)
				if rerr != nil || isTmpOrScratchPath(filepath.Clean(resolved)) {
					return false
				}
				ast, serr := os.Stat(resolved)
				if serr != nil || !ast.IsDir() || ast.Mode().Perm()&0002 != 0 {
					return false
				}
				return true
			}
			next := filepath.Dir(cur)
			if next == cur {
				break
			}
			cur = next
		}
		return true
	}
	// ADAPT2: lexical system PATH dirs (including /usr/local/bin) skip the
	// owner-uid check. On this host /usr/local/bin is owned by uid 1001
	// (package/admin user), not root or the caller euid; requiring uid==0
	// or uid==euid would reject the entire system PATH segment and break
	// normal tooling. The linuxbrew prefix rides along via sysDir (see the
	// note at the top of this function). Write bits are not judged at
	// system locations either: the GitHub ubuntu-26.04 runner image ships
	// /opt (the whole hosted toolcache) and /usr/local/bin recursive-0777
	// by design — its build runs `chmod -R 777` on both — because those
	// ephemeral single-user VMs let the unprivileged job user install into
	// them; a write-bit rule rejects every pre-baked tool on that platform.
	// Trust at a system location is by location: the planted-binary
	// defenses live in the user-writable layers, which keep their full
	// checks (toolchain dirs via statUIDAndPermOK, $HOME shadow screening),
	// and symlinks into /tmp|/var/tmp|/dev/shm|/run are still rejected.
	if !sysDir {
		if !statUIDAndPermOK(lst, euid, true) {
			return false
		}
	}
	resolved, err := filepath.EvalSymlinks(norm)
	if err != nil {
		return false
	}
	resolved = filepath.Clean(resolved)
	if isTmpOrScratchPath(resolved) {
		return false
	}
	if resolved != norm && !isSystemPathDir(resolved) && !isLinuxbrewPathDir(resolved) && !isUserToolchainPathDir(resolved) {
		return false
	}
	st, err := os.Stat(resolved)
	if err != nil || !st.IsDir() {
		return false
	}
	if isSystemPathDir(resolved) || isLinuxbrewPathDir(resolved) || sysDir {
		return true
	}
	return statUIDAndPermOK(st, euid, false)
}

// isSafePathDirEntry reports whether a canonicalised absolute PATH segment
// is a trusted system or development-toolchain directory (C10 hardened).
func isSafePathDirEntry(norm string) bool {
	if !filepath.IsAbs(norm) {
		return false
	}
	norm = filepath.Clean(norm)
	if isTmpOrScratchPath(norm) {
		return false
	}
	if !isSystemPathDir(norm) && !isLinuxbrewPathDir(norm) && !isUserToolchainPathDir(norm) {
		return false
	}
	return isTrustedPathDirOnDisk(norm, os.Geteuid())
}

// isSafeIFSValue reports whether an IFS= value is a benign field-split
// alphabet: empty (the `IFS= read -r` idiom) or runs of whitespace plus
// ':' ','  — the separators of the PATH/CSV world. Anything that could
// resplit command tokens (letters, digits, '/', '-', '.', '_', ';', '|',
// '=') is unsafe (SH11 MF-5/S2).
func isSafeIFSValue(val string) bool {
	for i := 0; i < len(val); i++ {
		switch val[i] {
		case ' ', '\t', '\n', '\r', ':', ',':
			continue
		}
		return false
	}
	return true
}

// effectivePATHFrom replays the env ops over base PATH and returns the
// PATH a spawned command would resolve against: 'c' (env -i) drops to "",
// 'u' unsets, 'a' re-assigns. A $PATH self-reference inside an assigned
// value expands to the PATH in force BEFORE that op (the accumulator),
// matching runtime scoping — nested replays therefore accumulate instead
// of re-reading the process PATH (R7). An unset/empty result is returned
// verbatim so lookup treats it as ".".
func (e envAssignments) effectivePATHFrom(base string) string {
	path := base
	for _, op := range e.ops {
		switch op.kind {
		case 'c':
			path = ""
		case 'u':
			if op.key == "PATH" {
				path = ""
			}
		case 'a':
			if op.key == "PATH" {
				path = expandPathSelfRefs(op.value, path)
			}
		}
	}
	return path
}

// expandPathSelfRefs substitutes the unforgeable $PATH sentinel with base
// (the PATH in force at assignment time) so alias resolution sees the same
// search list the runtime would (a sentinel value never reaches here
// unexpanded: it only exists in PATH= values the guard already admitted).
func expandPathSelfRefs(val, base string) string {
	return strings.ReplaceAll(val, envPathSelfPlaceholder, base)
}

// taintedSentinelNames returns the names whose expansion semantics this
// env op list invalidated: every sentinelTrustVars name touched by an
// assign/unset/clear op (Q5/F3: HOME= overrides and env -i/-u degrade
// $HOME/$PWD/... placeholder grants inside nested payloads).
func (e envAssignments) taintedSentinelNames() map[string]bool {
	var out map[string]bool
	for _, op := range e.ops {
		switch op.kind {
		case 'c':
			if out == nil {
				out = map[string]bool{}
			}
			for name := range sentinelTrustVars {
				out[name] = true
			}
		case 'u', 'a':
			if sentinelTrustVars[op.key] {
				if out == nil {
					out = map[string]bool{}
				}
				out[op.key] = true
			}
		}
	}
	return out
}

// declFlagOps classifies the option words of an
// export/readonly/declare/typeset/local argv: dropsExport reports an
// `export -n` short-cluster (or a `declare`/`typeset`/`local` +x
// cluster) — both remove the export attribute so the child loses the
// variable; nameref reports a -n cluster on declare/typeset/local (bash
// nameref: writes through the ref reach the target).
func declFlagOps(base string, args []string) (dropsExport, nameref bool) {
	for _, a := range args {
		if a == "--" {
			break
		}
		if len(a) < 2 || (a[0] != '-' && a[0] != '+') || strings.HasPrefix(a, "--") {
			continue
		}
		for _, ch := range a[1:] {
			switch {
			case base == "export" && a[0] == '-' && ch == 'n':
				dropsExport = true
			case (base == "declare" || base == "typeset" || base == "local") && a[0] == '+' && ch == 'x':
				dropsExport = true
			case (base == "declare" || base == "typeset" || base == "local") && a[0] == '-' && ch == 'n':
				nameref = true
			}
		}
	}
	return dropsExport, nameref
}

// screenEnvWriteTargets rejects read/getopts/printf -v invocations whose
// WRITE TARGETS name a role-identity or execution-hook variable, and any
// dynamic (unvettable) target name (SH11 MF-4 tail). getopts implicitly
// writes OPTARG/OPTIND — hook names are impossible there, so only an
// explicit dynamic target matters; printf -v takes the name as its operand.
func screenEnvWriteTargets(head []string, base string) string {
	tainted := func(name string) string {
		if isDynamicArg(name) {
			return "env dynamic " + base
		}
		if guardTaintVars[name] || isEnvHookVar(name) {
			return "env " + name
		}
		return ""
	}
	switch base {
	case "read":
		sawDashDash := false
		j := 1
		for j < len(head) {
			a := head[j]
			if a == "--" && !sawDashDash {
				sawDashDash = true
				j++
				continue
			}
			if !sawDashDash && strings.HasPrefix(a, "-") && len(a) > 1 {
				// Option cluster: value letters d n N p t u a consume a
				// value (the cluster tail, or the next argv when last); every
				// other letter (r s e i) is a boolean. R13: -s is silent echo,
				// NOT a value option — `read -s x` still writes x.
				for k := 1; k < len(a); k++ {
					switch a[k] {
					case 'a':
						// -a ARRAY is itself a write target.
						var arr string
						if k+1 < len(a) {
							arr = a[k+1:]
						} else if j+1 < len(head) {
							arr = head[j+1]
							j++
						}
						if hit := tainted(arr); hit != "" {
							return hit
						}
						k = len(a)
					case 'd', 'n', 'N', 'p', 't', 'u':
						if k+1 >= len(a) && j+1 < len(head) {
							j++ // separate value operand
						}
						k = len(a)
					}
				}
				j++
				continue
			}
			if a == "" {
				j++
				continue
			}
			if hit := tainted(a); hit != "" {
				return hit
			}
			j++
		}
	case "getopts":
		// getopts OPTSTRING NAME [args...]: the second operand is the target
		// (the optstring itself may begin with ':' or '-').
		opIdx := 0
		if len(head) > 1 {
			if head[1] == "--" {
				if len(head) > 2 {
					opIdx = 2
				}
			} else {
				opIdx = 1
			}
		}
		if opIdx > 0 && opIdx+1 < len(head) {
			if hit := tainted(head[opIdx+1]); hit != "" {
				return hit
			}
		}
	case "printf":
		for j := 1; j+1 < len(head); j++ {
			if head[j] == "-v" {
				return tainted(head[j+1])
			}
			if !strings.HasPrefix(head[j], "-") {
				break
			}
		}
	}
	return ""
}

// envTruthy reports whether a CTXMODE_READONLY value counts as set.
func envTruthy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true"
}

// screenEnvAssignments replays the ordered env ops and screens each
// assignment for execution-hook variables. For the sub-agent guard it
// additionally simulates the spawned child's ROLE IDENTITY: starting from
// the caller's own identity (callerRole/callerReadonly — the process env
// values, which is what the child would inherit), each `env -i` clears,
// each `env -u` unsets and each KEY=VAL re-assigns. At the end the child's
// effective identity must still equal the caller's: a role must not drop
// to anonymous (effRole "") and must not downgrade to a weaker role
// (reviewer -> worker), and a read-only caller must stay read-only. The
// check fires even when the command argv itself is benign, because the
// child process would otherwise run unguarded.
//
// headBase is the resolved command head basename: relative PATH segments
// are tolerated only for toolchain heads (Q4).
//
// Detail strings name only the variable (never the value): env values can
// carry secrets and the detail goes into the audit record verbatim.
func screenEnvAssignments(envAs envAssignments, kind byte, callerRole, callerReadonly, headBase string) string {
	effRole := callerRole
	effReadonly := callerReadonly
	callerSub := callerRole != "" || envTruthy(callerReadonly)
	for _, op := range envAs.ops {
		switch op.kind {
		case 'c':
			effRole = ""
			effReadonly = ""
		case 'u':
			if isDynamicArg(op.key) {
				return "env unset dynamic"
			}
			switch op.key {
			case auditEnvRole:
				effRole = ""
			case auditEnvReadonly:
				effReadonly = ""
			}
			// Execution-hook vars may not be unset. Role-identity taint vars
			// (CTXMODE_ROLE / CTXMODE_READONLY) only update eff* above; the
			// final identity check decides (allows readonly-clear → fall to
			// command head, blocks role clear/downgrade).
			if isEnvHookVar(op.key) {
				return "env " + op.key
			}
		case 'a':
			if isDynamicArg(op.key) {
				return "env dynamic key"
			}
			switch op.key {
			case auditEnvRole:
				effRole = op.value
			case auditEnvReadonly:
				effReadonly = op.value
			}
			if pagerSafeVars[op.key] && (op.value == "" || op.value == "cat") {
				continue
			}
			// PATH: per-segment trust check — system/toolchain dirs and a
			// genuine $PATH self-reference pass; empty, relative, tmp, and
			// unvetted dynamic segments reject (MF-5.1).
			if op.key == "PATH" {
				if pathIsUnsafeForSubagent(op.value, headBase) {
					return "env PATH"
				}
				continue
			}
			// IFS: the split alphabet must stay benign — the `IFS= read -r`
			// and `IFS=:` idioms pass, letters/slashes/=/; reject (S2).
			if op.key == "IFS" {
				if isDynamicArg(op.value) || !isSafeIFSValue(op.value) {
					return "env IFS"
				}
				continue
			}
			// GIT_DIR-family: read-only roles may never redirect the repo;
			// workers may point it at a static or split-safe path, matching
			// the git --git-dir="$d" model.
			if gitDirEnvVars[op.key] {
				if kind == 'r' || callerReadonlyRole(callerIdentity{role: callerRole, readonly: callerReadonly}) {
					return "env " + op.key
				}
				if isDynamicArg(op.value) && !isSplitSafeDynamicWord(op.value) {
					return "env " + op.key
				}
				continue
			}
			if isEnvHookVar(op.key) {
				// Remaining hook vars: any dynamic value is rejected outright.
				if isDynamicArg(op.value) {
					return "env " + op.key
				}
				return "env " + op.key
			}
			// Taint vars: identity simulation only (no early return).
		}
	}
	if !callerSub || kind != 's' {
		return ""
	}
	if callerRole != "" && effRole != callerRole {
		return "env " + auditEnvRole
	}
	if envTruthy(callerReadonly) && !envTruthy(effReadonly) {
		return "env " + auditEnvReadonly
	}
	return ""
}

// callerReadonlyRole reports whether the caller identity counts as a
// read-only role (CTXMODE_READONLY set, or a read-only role name).
func callerReadonlyRole(c callerIdentity) bool {
	return envTruthy(c.readonly) || auditRoleIsReadonly(c.role)
}

// screenTrapArgs screens trap's action argument as shell text. Print modes
// (-p, -l) and signal-name operands are allowed; the first non-option,
// non-"-" operand is the action.
func screenTrapArgs(args []string, kind byte, depth int, caller callerIdentity) string {
	for _, a := range args {
		if isDynamicArg(a) {
			return "dynamic code payload"
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			continue // -p / -l / --help stay read-only
		}
		if a == "-" || a == "" {
			continue
		}
		// First real operand: is it a signal name or the action? A pure
		// uppercase signal (EXIT, INT, SIGTERM, ...) or number is the signal
		// operand; anything containing shell metacharacters or lowercase is
		// the action. When in doubt screen it as shell text — an action-less
		// signal list screens clean anyway.
		if isLikelyTrapSignal(a) {
			continue
		}
		if kind == 's' {
			return guardShellSubagentDepth(a, depth, caller)
		}
		return guardShellReadonlyDepth(a, depth, caller)
	}
	return ""
}

// isLikelyTrapSignal reports whether s looks like a bare signal operand
// (uppercase word, optional SIG prefix, or digits).
func isLikelyTrapSignal(s string) bool {
	if allDigits(s) {
		return true
	}
	t := strings.TrimPrefix(s, "SIG")
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(c >= 'A' && c <= 'Z' || c == '_') {
			return false
		}
	}
	return true
}

// screenUnsetArgs blocks `unset CTXMODE_ROLE`/`CTXMODE_READONLY` for
// sub-agent callers, and any unset of an execution-hook or sentinel-trust
// variable (unset GIT_PAGER, unset HOME would both re-arm a later child or
// invalidate placeholder semantics). Strict read-only leaves other unsets
// free.
func screenUnsetArgs(args []string, kind byte) string {
	if kind != 's' {
		return ""
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue // -v/-f flags
		}
		if isDynamicArg(a) {
			return "unset dynamic"
		}
		if guardTaintVars[a] || isEnvHookVar(a) || sentinelTrustVars[a] {
			return "unset " + a
		}
	}
	return ""
}

// xargsLongWithValue are GNU xargs long options that consume a SEPARATE
// value operand. GNU --eof and --replace take an optional value only via
// =glue: bare --eof/--replace must NOT consume the next argv (that word is
// the command or an operand).
var xargsLongWithValue = map[string]bool{
	"--arg-file": true, "--delimiter": true,
	"--max-args": true, "--max-lines": true, "--max-procs": true,
	"--max-chars": true, "--process-slot-var": true,
}

// xargsShortWithValue are short-option letters that consume a value (the
// cluster tail, or the next argv when they end the cluster). Lowercase -e
// and -i take only a GLUED optional operand (-eE / -iSTR), never a
// separate argv, so like -e they are absent here and handled as
// cluster-ending letters by the caller's scan. Uppercase -E keeps the
// separate-operand form.
var xargsShortWithValue = map[byte]bool{
	'I': true, 'L': true, 'n': true, 'P': true, 's': true,
	'd': true, 'a': true, 'E': true, 'J': true,
}

// xargsTargetIndex returns the index in argv of the command xargs would run,
// or len(argv) when xargs would run its default (echo). Option arities follow
// GNU findutils; `--` terminates xargs options.
func xargsTargetIndex(argv []string) int {
	i := 1
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if strings.HasPrefix(a, "--") {
			if j := strings.IndexByte(a, '='); j > 0 {
				i++ // --opt=value
			} else if xargsLongWithValue[a] {
				i += 2 // --opt value
			} else {
				i++ // boolean long option
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			// Short-option cluster: value-carrying letters take the rest of
			// the cluster or the next arg; bare clusters (-0, -r, -t, -p, -x)
			// consume one slot. R13: -i is the deprecated -I spelling — it
			// takes only a GLUED optional repl-str (-iSTR), never a separate
			// argv, so like -e it ends the cluster and consumes nothing.
			consumedNext := false
			for j := 1; j < len(a); j++ {
				if a[j] == 'e' || a[j] == 'i' {
					break // -e/-i take only a glued optional operand: the rest of
					// the cluster is its operand, never the next argv slot.
				}
				if xargsShortWithValue[a[j]] {
					consumedNext = j+1 >= len(a)
					break
				}
			}
			i++
			if consumedNext {
				i++
			}
			continue
		}
		return i
	}
	return i
}

// xargsReplToken returns the LAST -I/-i/--replace replacement token the
// xargs option zone names, or "" when none appeared. The scan shares
// xargs' option-arity model with xargsTargetIndex: clusters like -rI{}
// expose the I operand, -iSTR's tail is the token while a bare -i defaults
// to "{}", and GNU bare --replace also defaults to "{}" without consuming
// the next argv (only --replace=STR names a token).
func xargsReplToken(argv []string) string {
	repl := ""
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "--") {
			if j := strings.IndexByte(a, '='); j > 0 {
				if a[:j] == "--replace" {
					repl = a[j+1:]
				}
				continue
			}
			if a == "--replace" {
				repl = "{}" // GNU: bare --replace == -I{}
			} else if xargsLongWithValue[a] {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			consumedNext := false
			for j := 1; j < len(a); j++ {
				ch := a[j]
				if ch == 'e' {
					break // -e's tail is its optional operand
				}
				if ch == 'i' {
					// Deprecated -I: bare -i defaults to "{}"; -iSTR glued.
					if tail := a[j+1:]; tail != "" {
						repl = tail
					} else {
						repl = "{}"
					}
					break
				}
				if ch == 'I' {
					if tail := a[j+1:]; tail != "" {
						repl = tail
					} else if i+1 < len(argv) {
						repl = argv[i+1]
						consumedNext = true
					}
					break
				}
				if xargsShortWithValue[ch] {
					consumedNext = j+1 >= len(a)
					break
				}
			}
			if consumedNext {
				i++
			}
			continue
		}
		break // first non-option operand is the command
	}
	return repl
}

// screenFindArgsSeg scans find's operand list with explicit stdin context
// modelling (2.c): -exec/-execdir redirect child stdin to /dev/null
// (empty shellSegment), whereas -ok/-okdir share find's own stdin stream
// (outerSeg). Placeholders "{}" in command-head or inline-code slots fail
// closed while data-operand "{}" (`grep foo {}`, `sh -c 'echo "$1"' _ {}`)
// stay open.
func screenFindArgsSeg(args []string, outerSeg shellSegment, kind byte, depth int, caller callerIdentity) string {
	expectValue := false
	pathDone := false
	valueOpts := map[string]bool{
		"-name": true, "-iname": true, "-path": true, "-ipath": true,
		"-wholename": true, "-iwholename": true, "-regex": true, "-iregex": true,
		"-type": true, "-xtype": true, "-maxdepth": true, "-mindepth": true,
		"-newermt": true, "-newer": true, "-size": true, "-perm": true,
		"-mtime": true, "-mmin": true, "-uid": true, "-gid": true,
		"-user": true, "-group": true, "-printf": true, "-fprintf": true,
		"-lname": true, "-ilname": true, "-samefile": true, "-inum": true,
		"-links": true, "-used": true, "-fstype": true, "-anewer": true,
		"-cnewer": true, "-newerat": true, "-newerct": true, "-regextype": true,
		"-D": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if expectValue {
			expectValue = false
			continue
		}
		if kind == 'r' && (a == "-delete" || a == "-fprint" || a == "-fprint0" || a == "-fprintf" || a == "-fls") {
			return "find " + a
		}
		if isDynamicArg(a) {
			if !pathDone {
				if isSafeDynamicDataOperand(a) {
					continue
				}
			}
			return "find dynamic predicate"
		}
		if a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
			j := i + 1
			for j < len(args) && args[j] != ";" && args[j] != "+" {
				j++
			}
			if j > i+1 {
				inner := args[i+1 : j]
				if replTokenInExecSlot(inner, "{}", caller.pathEnv) {
					return "find " + a + " dynamic code payload"
				}
				innerSeg := shellSegment{}
				if a == "-ok" || a == "-okdir" {
					innerSeg = outerSeg
				}
				if hit := peelResolvedSegDepth(inner, innerSeg, kind, depth, caller); hit != "" {
					if hit == roSSHWriteHit {
						return roSSHWriteHit
					}
					return "find " + a + " " + hit
				}
			}
			i = j
			pathDone = true
			continue
		}
		if valueOpts[a] {
			pathDone = true
			expectValue = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			pathDone = true
		}
		if kind == 'r' && (a == "-delete" || a == "-fprint" || a == "-fprint0" || a == "-fprintf" || a == "-fls") {
			return "find " + a
		}
	}
	return ""
}

// guardArgvSubagent screens one argv (execute argv mode, run_task argv) for
// nested agent dispatch. A `shell -c` argv is redirected to the shell-text
// screener so `sh -c 'pig'` cannot route around it. The read-only-inclusive
// surfaces (ctxmode index) are only reachable through the guardCall entry
// points, which pass the caller's read-only classification explicitly.
func guardArgvSubagent(argv []string) string {
	return peelResolvedDepth(argv, 's', 0, currentCallerIdentity())
}

// screenStdinProgram screens text that reaches a head as its PROGRAM on
// stdin: shell text when lang is "" (a bare sh/bash/… reading stdin),
// interpreter code otherwise (python3 -, node -, a heredoc or a `<<<`
// here-string into python3). The heredoc body, the here-string and the
// ctx_run stdin payload all come through here so the same bytes always get
// the same verdict.
func screenStdinProgram(text, lang string, kind byte, depth int, caller callerIdentity) string {
	if lang == "" {
		if kind == 's' {
			return guardShellSubagentDepth(text, depth+1, caller)
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	g := guardCall{}
	if kind == 's' {
		g.subagent = true
	} else {
		g.strictReadonly = true
	}
	if rule, detail := g.guardCtxRunCode(lang, text); rule != "" {
		return detail
	}
	return ""
}

// screenOneSegmentDepth applies the head/tail checks to one parsed segment.
func screenOneSegmentDepth(seg shellSegment, kind byte, depth int, caller callerIdentity) string {
	if seg.parseErr != "" {
		return seg.parseErr
	}
	if seg.depthExceeded {
		return depthExceededHit
	}
	if kind == 'r' && seg.redirectFile != "" {
		return "redirect to " + seg.redirectFile + " forbidden"
	}
	if len(seg.argv) == 0 {
		return ""
	}
	// A bare shell/interpreter reading its PROGRAM off a pipe is fed by the
	// upstream bytes: for a strict read-only role that is an unreviewable
	// code stream (block outright); for a sub-agent it is a covert channel
	// around head screening (same verdict — the upstream text is not part
	// of this segment and cannot be screened here). An ssh head whose
	// REMOTE command reads its program from stdin is left for the ssh
	// model (screenSSHHead) — it returns the remote-aware roSSHWriteHit /
	// "piped stdin to ssh" verdict.
	if seg.pipedStdin && !seg.stdinRedir && !sshTunnelsStdinProgram(seg.argv, caller.pathEnv) {
		if lang, isProg, _ := stdinProgramHeadWithEnv(seg.argv, 0, envAssignments{}, caller.pathEnv); isProg {
			if lang == "" {
				return "piped code to shell"
			}
			return "piped code to " + lang
		}
	}
	// A `<<<` here-string is this command's stdin: when the head reads its
	// PROGRAM from stdin (`bash <<< 'pig'`, `python3 <<< 'import …'`) the
	// payload is program text and gets the code screen — under the same
	// env context the peeled argv carries (R7); for any other head
	// (`cat <<< 'pig'`) it is plain data. A later fd0 file redirect
	// (stdinRedir) means the here-string never reaches the program.
	if seg.hereString != "" && !seg.stdinRedir {
		// R15: the program head may itself hide inside wrappers
		// (flock/watch/xargs/env) — env ops found at ANY recursion
		// level are the env the here-string text runs under.
		if lang, isProg, envAs := stdinProgramHeadWithEnv(seg.argv, 0, envAssignments{}, caller.pathEnv); isProg {
			if hit := screenStdinProgram(seg.hereString, lang, kind, depth, caller.seededWith(envAs)); hit != "" {
				return hit
			}
		}
	}
	return peelResolvedSegDepth(seg.argv, seg, kind, depth, caller)
}
func screenSegmentHeredocsDepth(seg shellSegment, kind byte, depth int, caller callerIdentity) string {
	if len(seg.heredocText) == 0 {
		return ""
	}
	// The tunnel probe runs on the UNPEELED argv against the caller's PATH
	// BEFORE seeding: peelToSSHHead replays the argv's own env ops per
	// layer, so neither the caller's seeded envAs nor remote PATH ops may
	// feed its base (R4: a remote `PATH=` op leaking into the base drops
	// the ssx -> ssh resolution; a `PATH=$PATH:` prefix replayed twice
	// collapses to `:<dir>`).
	sshTunnel := sshTunnelsStdinProgram(seg.argv, caller.pathEnv)
	if seg.stdinRedir {
		return ""
	}
	lang, isProg, envAs := stdinProgramHeadWithEnv(seg.argv, 0, envAssignments{}, caller.pathEnv)
	if !isProg {
		return ""
	}
	caller = caller.seededWith(envAs)
	// When the heredoc tunnels through ssh (directly or behind wrappers like
	// flock) to a remote stdin-program head, a read-only caller (verifier /
	// CTXMODE_READONLY=1) loses its local /tmp write exemption at the wire.
	bodyKind := kind
	if kind == 's' && callerReadonlyRole(caller) && sshTunnel {
		bodyKind = 'r'
	}
	for _, hb := range seg.heredocText {
		if hb.dynamic || isDynamicArg(hb.text) {
			return "dynamic code payload"
		}
		if hit := screenStdinProgram(hb.text, lang, bodyKind, depth, caller); hit != "" {
			if sshTunnel && (kind == 'r' || callerReadonlyRole(caller)) && bodyKind == 'r' {
				return roSSHWriteHit
			}
			return hit
		}
	}
	return ""
}

// shellHeads are the shell executables whose heredoc stdin is shell code.
var shellHeads = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"mksh": true, "ash": true,
}

// heredocInterpLang maps a heredoc-receiving interpreter head to the code
// language used for guardCtxRunCode.
func heredocInterpLang(base string) (string, bool) {
	if base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3") {
		return "python", true
	}
	switch base {
	case "node", "nodejs", "ts-node", "tsx", "bun":
		return "javascript", true
	case "perl":
		return "perl", true
	case "ruby":
		return "ruby", true
	case "php":
		return "php", true
	}
	return "", false
}

// guardShellSubagent screens shell command text for nested agent dispatch:
// every segment's head is wrapper-peeled and checked; nested `shell -c`
// segments recurse; heredoc bodies for shell/interpreter heads are screened.
func guardShellSubagent(code string) string {
	return guardShellSubagentDepth(code, 0, currentCallerIdentity())
}
func guardShellSubagentDepth(code string, depth int, caller callerIdentity) string {
	return guardShellSubagentDepthEnv(code, depth, caller, caller.envTaint)
}

// guardShellSubagentDepthEnv parses with an explicit envTaint map (the
// caller identity's own taint may already carry it; passing it separately
// keeps remote-command parses untainted — the far side sees its own env).
func guardShellSubagentDepthEnv(code string, depth int, caller callerIdentity, envTaint map[string]bool) string {
	return guardShellSubagentDepthSegs(splitShellSegmentsEnv(code, envTaint), depth, caller)
}

func guardShellSubagentDepthBash(code string, depth int, caller callerIdentity) string {
	return guardShellSubagentDepthSegs(splitShellSegmentsBashEnv(code, caller.envTaint), depth, caller)
}

func guardShellSubagentDepthSegs(segs []shellSegment, depth int, caller callerIdentity) string {
	if depth >= peelChainMaxDepth {
		return depthExceededHit
	}
	for _, seg := range segs {
		if seg.parseErr != "" {
			return seg.parseErr
		}
		if seg.depthExceeded {
			return depthExceededHit
		}
		if hit := screenSegmentHeredocsDepth(seg, 's', depth, caller); hit != "" {
			return hit
		}
		if hit := screenOneSegmentDepth(seg, 's', depth, caller); hit != "" {
			return hit
		}
	}
	return ""
}

// ---------- rule 2: read-only write guard ----------

// fsWriteHeads are command heads that unconditionally write, remove, create or
// move filesystem objects (or, for the lock/pty/shell runners at the end,
// always escape the read-only write fence).
var fsWriteHeads = map[string]bool{
	"rm": true, "unlink": true, "rmdir": true, "mv": true, "cp": true,
	"install": true, "mkdir": true, "mktemp": true, "touch": true,
	"truncate": true, "dd": true, "tee": true, "chmod": true, "chown": true,
	"chgrp": true, "ln": true, "patch": true, "rsync": true, "scp": true,
	"sftp": true,
	// Interactive / in-place editors and stream copiers.
	"ed": true, "ex": true, "vi": true, "vim": true, "nvim": true,
	"nano": true, "sponge": true,
	// File split/allocation/attribute writes.
	"split": true, "csplit": true, "fallocate": true, "chattr": true,
	"setfattr": true, "setfacl": true,
	"shred": true, "rename": true, "prename": true, "file-rename": true,
	"wipefs": true,
	// Mount and special-file creation (mount is handled by a dual-mode
	// screen: bare/`mount -l`/`mount -t T` listings stay free).
	"umount": true, "mknod": true, "mkfifo": true,
	// Archive writers / binary tools.
	"uudecode": true, "zip": true, "7z": true, "7za": true, "7zr": true,
	"rar": true, "cpio": true, "ar": true, "ranlib": true,
	"strip": true, "objcopy": true,
	// Compilers and build drivers are handled by a dual-mode screen
	// (compilerQueryOnly): pure --version/--help/-dumpversion probes stay
	// free; anything else writes.
	// Package managers mutate environments/caches.
	"pip": true, "pip3": true, "pipx": true, "uv": true, "poetry": true,
	"conda": true, "gem": true, "composer": true,
	// flock takes a write lock; script writes a pty transcript / spawns a shell.
	"flock": true, "script": true,
	// `.`/`source` execute unreviewed script files in the current shell.
	".": true, "source": true,
}

// procKillHeads terminate processes; blocked for strict read-only roles.
// kill is handled by a dual-mode screen (`kill -l`/`kill -L` lists signal
// names and stays free).
var procKillHeads = map[string]bool{
	"pkill": true, "killall": true,
}

// mountQueryOnly reports whether a mount argv is a pure listing: no
// positional device/dir operand, no -a, no -o/--options, no --bind/--move.
// `mount`, `mount -l`, `mount -t ext4`, `mount -l -t tmpfs` list the table.
func mountQueryOnly(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t" || a == "--types" || a == "-O" || a == "--test-opts":
			i++ // -t TYPE / -O LIST consume a value but stay a listing
		case a == "-a" || a == "--all" || a == "-o" || a == "--options" ||
			a == "--bind" || a == "--move" || a == "-B" || a == "-M" || a == "-R" ||
			a == "--remount" || a == "--rbind" || a == "--make-shared" ||
			strings.HasPrefix(a, "--make-") || strings.HasPrefix(a, "--options="):
			return false
		case strings.HasPrefix(a, "-"):
			continue // -l / -v / -s / -f-free listing flags
		default:
			return false // device or mountpoint operand => a real mount
		}
	}
	return true
}

// compilerQueryOnly reports whether a compiler/build-driver argv is a pure
// version/help probe: only --version/-version/-V/--help/-h (and gcc-style
// -dumpversion/-dumpmachine), no source file or build target operand.
func compilerQueryOnly(args []string, base string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		switch a {
		case "--version", "-version", "-V", "--help", "-h", "-v":
			continue
		}
		if (base == "gcc" || base == "g++" || base == "cc" || base == "c++" ||
			base == "clang" || base == "clang++") &&
			(a == "-dumpversion" || a == "-dumpmachine" || strings.HasPrefix(a, "-print-")) {
			continue
		}
		return false
	}
	return true
}

// npmFamilyWriteSubs are the mutating subcommands shared by npm/pnpm/yarn/bun.
var npmFamilyWriteSubs = map[string]bool{
	"install": true, "i": true, "add": true, "a": true, "remove": true,
	"rm": true, "uninstall": true, "ci": true,
	"publish": true, "link": true, "unlink": true, "update": true,
	"run": true, "test": true, "build": true,
	"init": true, "create": true, "patch": true, "pm": true,
}

// goWriteSubs are the go-tool subcommands that build, run, generate or mutate
// (version/env/list/doc stay free; env -w/-u and work are screened inside
// screenGoWrite).
var goWriteSubs = map[string]bool{
	"build": true, "test": true, "install": true, "run": true, "generate": true,
	"get": true, "mod": true, "clean": true, "fix": true, "fmt": true,
}

// cargoWriteSubs likewise for cargo.
var cargoWriteSubs = map[string]bool{
	"build": true, "test": true, "run": true, "install": true, "clean": true,
	"publish": true, "add": true, "remove": true,
	"fix": true, "update": true, "init": true, "new": true,
	"vendor": true, "generate-lockfile": true,
}

// systemctlWriteSubs are systemctl verbs that change state.
var systemctlWriteSubs = map[string]bool{
	"start": true, "stop": true, "restart": true, "reload": true,
	"enable": true, "disable": true, "mask": true, "unmask": true,
	"daemon-reload": true,
}

// screenGoWrite applies the go-tool write model for strict read-only:
// goWriteSubs verbs mutate; `go env -w`/`-u` (including glued
// -wKEY=VAL/-uKEY) writes go env config; `go work` (init/use/sync/edit)
// mutates the workspace file.
func screenGoWrite(args []string) string {
	sub := firstNonFlagArg(args)
	if sub == "" {
		return ""
	}
	if goWriteSubs[sub] {
		return "go " + sub
	}
	if sub == "work" {
		return "go work"
	}
	if sub == "env" {
		// Scan only the operands after `env`: -w/-u (and the glued
		// -wKEY=VAL/-uKEY forms) write go env configuration.
		seenEnv := false
		for _, a := range args {
			if a == "env" && !seenEnv {
				seenEnv = true
				continue
			}
			if !seenEnv {
				continue
			}
			if a == "-w" || a == "-u" || a == "--w" || a == "--u" ||
				strings.HasPrefix(a, "-w") || strings.HasPrefix(a, "-u") ||
				strings.HasPrefix(a, "--w=") || strings.HasPrefix(a, "--u=") {
				return "go env " + a
			}
		}
	}
	return ""
}

// screenCargoWrite applies the cargo write model; `cargo fmt` is dual-mode
// (--check stays read-only).
func screenCargoWrite(args []string) string {
	sub := firstNonFlagArg(args)
	if sub == "" {
		return ""
	}
	if sub == "fmt" {
		for _, a := range args {
			if a == "--check" {
				return ""
			}
		}
		return "cargo fmt"
	}
	if cargoWriteSubs[sub] {
		return "cargo " + sub
	}
	return ""
}

// gitReadonlySubs is the explicit whitelist of read-only git subcommands.
// Anything not here and not handled by the dual-mode branches
// (worktree/branch/tag/config/remote/stash) is a write for the strict guard.
var gitReadonlySubs = map[string]bool{
	"status": true, "diff": true, "log": true, "show": true,
	"rev-parse": true, "ls-files": true, "ls-tree": true, "ls-remote": true,
	"cat-file": true, "blame": true, "annotate": true, "grep": true,
	"describe": true, "merge-base": true, "rev-list": true,
	"for-each-ref": true, "shortlog": true, "name-rev": true,
	"check-ignore": true, "check-attr": true, "check-ref-format": true,
	"var": true, "version": true, "help": true,
	"diff-tree": true, "diff-files": true, "diff-index": true,
	"verify-commit": true, "verify-tag": true, "whatchanged": true,
	"cherry": true, "count-objects": true,
	// fsck is dual-mode: plain checks are free, --lost-found writes.
	// Dual-mode subcommands are handled in screenGitWrite and deliberately
	// absent here: worktree, branch, tag, config, remote, stash.
}

// gitStashReadonlySubs are the stash verbs that only inspect.
var gitStashReadonlySubs = map[string]bool{
	"list": true, "show": true,
}

// screenReadonlyWrite returns the guard hit for ONE resolved command head and
// its argv (starting at the head), or "" when allowed. The head is screened
// under its own basename AND the basename of the file it resolves through
// (headBaseAliasHits), so an alias like `ln -s /usr/bin/rm /tmp/remove`
// cannot walk past the write table.
func screenReadonlyWrite(headArgv []string) string {
	return screenReadonlyWritePath(headArgv, "")
}

// screenReadonlyWritePath is screenReadonlyWrite with an explicit effective
// PATH for alias resolution (Q4 symlink penetration under envAs overrides).
func screenReadonlyWritePath(headArgv []string, pathEnv string) string {
	if len(headArgv) == 0 {
		return ""
	}
	args := headArgv[1:]
	for _, base := range headBaseAliasHits(headArgv, pathEnv) {
		// `python -m <mod>` runs an arbitrary module: screen it as the command
		// it actually executes instead of as an interpreter head. Runs before
		// the alias walk so /usr/bin/python3 and python3 behave identically.
		if lang, ok := heredocInterpLang(base); ok && lang == "python" {
			if hit, isModuleRun := pythonModuleHit(args); isModuleRun {
				if hit != "" {
					return hit
				}
				continue // vetted module run: the interpreter head is done here
			}
		}
		if isPureQueryInvocation(headArgv) && pureQueryOnlyHeads[base] {
			continue // `dispatch-agent --version` is a query, not a spawn
		}
		if hit := screenReadonlyWriteAlias(headArgv, base, args); hit != "" {
			return hit
		}
	}
	return ""
}

// screenReadonlyWriteAlias applies the whole strict read-only head model to
// ONE candidate name for the command head: base is the spelling under test
// (the name as typed, or the basename of the symlink behind it) and args are
// the words after the head.
func screenReadonlyWriteAlias(headArgv []string, base string, args []string) string {
	if fsWriteHeads[base] || procKillHeads[base] {
		return base
	}
	// Dual-mode heads: a pure query spelling stays free, everything else
	// writes.
	switch base {
	case "crontab":
		if len(args) == 1 && args[0] == "-l" {
			return ""
		}
		return "crontab"
	case "mount":
		if mountQueryOnly(args) {
			return ""
		}
		return "mount"
	case "kill":
		if len(args) == 1 && (args[0] == "-l" || args[0] == "-L" || args[0] == "--list") {
			return ""
		}
		return "kill"
	case "gcc", "g++", "cc", "c++", "clang", "clang++", "rustc", "javac",
		"make", "gmake", "cmake", "ninja", "meson":
		if compilerQueryOnly(args, base) {
			return ""
		}
		return base
	case "flock", "script":
		return base
	}
	switch base {
	case "sed", "gsed":
		if hasInPlaceFlag(args) {
			return base + " -i"
		}
		if hit := screenSedScriptWrite(args); hit != "" {
			return hit
		}
	case "perl", "ruby":
		if hasInterpInPlaceFlag(headArgv) {
			return base + " -i"
		}
		// Reaching here means unwrapInterpreterInline found no -e/-r inline
		// code: a script file or stdin must block; -n (syntax check) and
		// version/help flags stay free.
		return screenInterpFileRun(args, base)
	case "awk", "gawk", "mawk", "nawk":
		if hit := screenAwkInplace(args); hit != "" {
			return hit
		}
		if hit := screenAwkProgram(args); hit != "" {
			return hit
		}
	case "gofmt", "goimports":
		for _, a := range args {
			if a == "-w" || strings.HasPrefix(a, "-w=") {
				return base + " -w"
			}
		}
	case "git":
		if _, hit := screenGitGlobalArgs(args); hit != "" {
			return hit
		}
		return screenGitWrite(args)
	case "git-fsck":
		// Dashed form /usr/lib/git-core/git-fsck → symlink to git with implicit
		// "fsck" subcommand; screen as git fsck <args>.
		return screenGitWrite(append([]string{"fsck"}, args...))
	case "tar", "bsdtar", "gtar":
		return screenTarWrite(args, base)
	case "unzip":
		return screenUnzipWrite(args)
	case "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "zstd", "unzstd", "lz4":
		return screenCompressWrite(args, base)
	case "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash":
		// Reaching here means unwrapShellArgv found no `-c` inline code, so
		// the invocation runs a script file or reads stdin — both must block
		// for strict read-only. `-n` syntax checks and version/help stay free.
		return screenShellFileRun(args, base)
	case "node", "nodejs", "ts-node", "tsx", "php":
		// Reaching here means unwrapInterpreterInline found no -e/-r inline
		// code: a script file or stdin must block; version/help stay free.
		return screenInterpFileRun(args, base)
	case "bun":
		// bun doubles as a package manager: its npm-family verbs
		// (install/add/remove/update/link/publish/init/create/build/pm)
		// mutate before any script-run logic applies.
		if sub := firstNonFlagArg(args); sub != "" && npmFamilyWriteSubs[sub] {
			return "bun " + sub
		}
		return screenInterpFileRun(args, base)
	case "ctxmode":
		// `ctxmode index` writes the shared KB — same surface as
		// ctx_kb action=index (router.go): every read-only role,
		// verifier included, is refused. `ctxmode search` / `-h` /
		// `--help` stay free; global -workdir/-config flags are skipped.
		if sub := ctxmodeCLIAction(args); sub == "index" {
			return "ctxmode index"
		}
	case "curl":
		return screenCurlWrite(args)
	case "wget":
		return screenWgetWrite(args)
	case "systemctl":
		if sub := firstNonFlagArg(args); sub != "" && systemctlWriteSubs[sub] {
			return "systemctl " + sub
		}
	case "go":
		if hit := screenGoWrite(args); hit != "" {
			return hit
		}
	case "cargo":
		if hit := screenCargoWrite(args); hit != "" {
			return hit
		}
	case "npm", "pnpm", "yarn":
		// npm/pnpm/yarn run under the same finite accept grammar as the
		// sub-agent screen (parseNpmFamilyArgv): an argv that does not fit
		// the grammar Rejects here too (fail closed — the value slot of an
		// unlisted option could masquerade as a read-only verb), the
		// exec/dlx verbs fetch-and-run unvetted code, and the remaining
		// verbs hit the write table. A flag-only or other-verb argv falls
		// through unchanged.
		switch r := parseNpmFamilyArgv(base, args); r.state {
		case npmArgvReject:
			return base + " " + r.reason
		case npmArgvExec:
			return base + " " + r.verb
		default:
			if r.verb != "" && npmFamilyWriteSubs[r.verb] {
				return base + " " + r.verb
			}
		}
	case "npx", "bunx", "pnpx":
		return base // package-runner: always executes a fetched binary
	default:
		if base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3") {
			// Reaching here means unwrapInterpreterInline found no -c inline
			// code and pythonModuleHit found no -m: a script file or stdin
			// must block while --version/-V/-VV/--help/-h stay free.
			return screenInterpFileRun(args, base)
		}
	}
	return ""
}

// awkProgramFrags collects awk's program text for a SUB-AGENT caller:
// every -e PROG / -ePROG / --source PROG / --source=PROG fragment plus
// the first positional operand when no -e/--source appeared, joined with
// "\n" for screening. -f FILE / --file=FILE names an unvetted program
// file — reported via the file flag so the caller can decide (sub-agent:
// skip; strict read-only: block). hit names the offending dynamic operand
// in a code/exec position; a plain data-position dynamic word (input file,
// -v/-F value, -f path) is not a hit (SH11 W11-2).
// isStdinDevicePath reports a literal path spelling of the process stdin
// device: reading it is equivalent to reading fd 0, so `sh /dev/stdin`,
// `python3 /proc/self/fd/0`, `awk -f /dev/stdin` and `sed -f /dev/fd/0`
// all consume the piped/redirected stream as PROGRAM text. Dynamic words
// are handled by the callers' own placeholder checks.
func isStdinDevicePath(p string) bool {
	if p == "" || isDynamicArg(p) {
		return false
	}
	p = filepath.Clean(p) // /dev/fd/./0 -> /dev/fd/0
	if p == "/dev/stdin" {
		return true
	}
	// Compare the trailing fd number numerically: Linux open() accepts
	// padded spellings (fd/00, fd/000) that filepath.Clean does NOT fold,
	// while non-numeric tails (fd/x) and other fds (fd/1) stay free.
	for _, prefix := range []string{"/dev/fd", "/proc/self/fd", "/proc/thread-self/fd"} {
		if tail, ok := strings.CutPrefix(p, prefix+"/"); ok && tail != "" && !strings.Contains(tail, "/") {
			if n, err := strconv.Atoi(tail); err == nil {
				return n == 0
			}
		}
	}
	return false
}

func awkProgramFrags(args []string) (string, bool, string) {
	var frags []string
	var positional string
	sawFile := false
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if isDynamicArg(a) {
			if !endOpts && strings.HasPrefix(a, "-") {
				return "", sawFile, "dynamic code payload"
			}
			// Data-position dynamic word: only a split-safe path/data value
			// may pass — a word-start __ctx_dq_sub__ could be -f/-e at
			// runtime.
			if !isSafeDynamicDataOperand(a) {
				return "", sawFile, "dynamic code payload"
			}
			if !endOpts && positional == "" && len(frags) == 0 {
				// Dynamic program slot is unvettable.
				return "", sawFile, "dynamic code payload"
			}
			if positional == "" {
				positional = a // kept so a later non-option stays a file too
			}
			continue
		}
		switch {
		case a == "--" && !endOpts:
			// Option terminator: everything after is a positional operand —
			// the first one is still the program text
			// (`awk -- '-1 {system("pig")}' f`).
			endOpts = true
		case a == "-f" || a == "--file":
			sawFile = true
			if i+1 < len(args) {
				v := args[i+1]
				// S3: `awk -f -` (and the /dev/stdin family) reads the
				// PROGRAM from stdin — unvetted.
				if v == "-" || isStdinDevicePath(v) {
					return "", sawFile, "awk script from stdin"
				}
				if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
					return "", sawFile, "dynamic code payload"
				}
			}
			i++ // consume the file operand
		case strings.HasPrefix(a, "--file="):
			sawFile = true
			v := a[len("--file="):]
			if v == "-" || isStdinDevicePath(v) {
				return "", sawFile, "awk script from stdin"
			}
			if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
				return "", sawFile, "dynamic code payload"
			}
		case a == "-e" || a == "--source":
			if i+1 < len(args) {
				frags = append(frags, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--source="):
			frags = append(frags, a[len("--source="):])
		case a == "-F" || a == "-v" || a == "--assign" || a == "--field-separator" ||
			a == "-i" || a == "--include":
			i++ // consume the value operand
		case !endOpts && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1:
			// Short-option cluster: f/e/F/v/i carry an operand — the cluster
			// tail or the next argv — and end the cluster.
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'e':
					if tail := a[j+1:]; tail != "" {
						frags = append(frags, tail)
					} else if i+1 < len(args) {
						frags = append(frags, args[i+1])
						i++
					}
					j = len(a)
				case 'f':
					sawFile = true
					if j+1 < len(a) {
						v := a[j+1:]
						if v == "-" || isStdinDevicePath(v) {
							return "", sawFile, "awk script from stdin"
						}
						if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
							return "", sawFile, "dynamic code payload"
						}
					} else {
						if i+1 < len(args) {
							v := args[i+1]
							if v == "-" || isStdinDevicePath(v) {
								return "", sawFile, "awk script from stdin"
							}
							if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
								return "", sawFile, "dynamic code payload"
							}
						}
						i++ // file operand is the next argv
					}
					j = len(a)
				case 'F', 'v', 'i':
					if j+1 >= len(a) {
						i++ // value operand is the next argv
					}
					j = len(a)
				}
			}
		case !endOpts && strings.HasPrefix(a, "-"):
			continue // other long options (--posix, --lint, ...)
		default:
			if positional == "" && len(frags) == 0 {
				positional = a
			}
		}
	}
	if len(frags) == 0 && positional != "" && !isDynamicArg(positional) {
		frags = append(frags, positional)
	}
	return strings.Join(frags, "\n"), sawFile, ""
}

// screenAwkSubagent extracts awk's program text for a SUB-AGENT caller and
// screens the command strings inside its exec escapes (system("cmd"),
// "cmd" | getline, print x | "cmd") as shell text. A dynamic command
// (system(var), concatenation) cannot be screened statically — the program
// is blocked outright when it mentions a blocked agent/orchestrator name.
// A -f program FILE is skipped here (unvetted text is worse than skipped
// text: the strict guard blocks it; the sub-agent guard has no write
// fence to protect inside awk).
func screenAwkSubagent(args []string, depth int, caller callerIdentity) string {
	program, _, hit := awkProgramFrags(args)
	if hit != "" {
		return hit
	}
	if program == "" {
		return ""
	}
	if isDynamicArg(program) {
		return "dynamic code payload"
	}
	// Screen each STRING LITERAL that reaches a command sink as shell text;
	// a non-literal command is only allowed when it names no blocked head.
	for _, lit := range awkCommandLiterals(program) {
		if isDynamicArg(lit.text) {
			return "dynamic code payload"
		}
		if lit.dynamic {
			// Dynamic command text: only fails when the program itself names
			// a blocked agent/orchestrator identifier.
			if programNamesBlockedAgent(program) {
				return "awk dynamic cmd"
			}
			continue
		}
		if hit := guardShellSubagentDepth(lit.text, depth+1, caller); hit != "" {
			return hit
		}
	}
	return ""
}

// awkCmdLit is one command-text literal extracted from an awk program, or a
// dynamic marker when the command is not a static string.
type awkCmdLit struct {
	text    string
	dynamic bool
}

// awkCommandLiterals walks the program and returns the string literals
// (decoded, quotes stripped) that feed command sinks: system(...),
// `"cmd" | getline`, `print x | "cmd"`. A sink fed by a non-literal
// expression yields a dynamic entry instead.
func awkCommandLiterals(prog string) []awkCmdLit {
	var out []awkCmdLit
	n := len(prog)
	i := 0
	inStr := byte(0)
	strStart := -1
	var lastLit string
	lastWasLit := false
	inPrint := false
	paren := 0
	for i < n {
		c := prog[i]
		switch {
		case inStr != 0:
			if c == '\\' {
				i++
			} else if c == inStr {
				inStr = 0
				lit, _, ok := leadingStringLiteral(prog[strStart : i+1])
				lastWasLit = ok
				lastLit = lit
			}
		case c == '"' || c == '\'':
			inStr = c
			strStart = i
			lastWasLit = false
		case c == '(' || c == '[':
			paren++
		case c == ')' || c == ']':
			if paren > 0 {
				paren--
			}
		case c == ' ' || c == '\t':
			// Whitespace does not disturb the last-literal tracking (a literal
			// may precede `| getline` with a space: "cmd" | getline).
		case c == ';' || c == '\n' || c == '{' || c == '}':
			if paren == 0 {
				inPrint = false
			}
			lastWasLit = false
		case c == '|':
			rest := strings.TrimLeft(prog[i+1:], " \t")
			if strings.HasPrefix(rest, "getline") {
				if lastWasLit {
					out = append(out, awkCmdLit{text: lastLit})
				} else {
					out = append(out, awkCmdLit{dynamic: true})
				}
			} else if inPrint {
				// print x | "cmd": screen the literal after the pipe.
				j := i + 1
				for j < n && (prog[j] == ' ' || prog[j] == '\t') {
					j++
				}
				if j < n && (prog[j] == '"' || prog[j] == '\'') {
					if lit, _, ok := leadingStringLiteral(prog[j:]); ok {
						out = append(out, awkCmdLit{text: lit})
					}
				} else {
					out = append(out, awkCmdLit{dynamic: true})
				}
			}
			lastWasLit = false
		default:
			if isIdentByte(c) {
				j := i
				for j < n && isIdentByte(prog[j]) {
					j++
				}
				w := prog[i:j]
				if w == "print" || w == "printf" {
					inPrint = true
				}
				if w == "system" {
					// system( LIT ) / system LIT: take the literal operand.
					k := j
					for k < n && (prog[k] == ' ' || prog[k] == '\t' || prog[k] == '(') {
						k++
					}
					if k < n && (prog[k] == '"' || prog[k] == '\'') {
						if lit, _, ok := leadingStringLiteral(prog[k:]); ok {
							out = append(out, awkCmdLit{text: lit})
						}
					} else if k < n {
						out = append(out, awkCmdLit{dynamic: true})
					}
				}
				lastWasLit = false
				i = j
				continue
			}
			lastWasLit = false
		}
		i++
	}
	return out
}

// programNamesBlockedAgent reports whether program text names a blocked
// agent executable or orchestrator identifier (used to fail closed on
// dynamic awk command construction).
func programNamesBlockedAgent(prog string) bool {
	toks := codeTokens(prog)
	for _, name := range codeAgentNames {
		if toks.hasIdent(name) {
			return true
		}
	}
	return toks.hasIdent("herdr") || toks.hasIdent("herdsman") || toks.hasIdent("hc")
}

// sedDynamicScriptSafe is gone (R4): a dynamic s/// fragment can inject
// sed `e` commands when the expanded value contains the delimiter
// (`p='x/g;e pig'` → s/x/g;e pig/bar/g = EXECUTION). Restricted literal
// binds (litVars) resolve to static text BEFORE this point, so any
// placeholder still present is unvettable and the script slot rejects it.

// screenSedSubagent collects sed script text (inline -e payloads and the
// first positional operand) for a SUB-AGENT caller and screens any GNU sed
// `e` exec commands: `1e pig`, `sed -e 'e agy'`, `s/.*/pig/e`. The command
// text after `e` is screened as shell text.
func screenSedSubagent(args []string, depth int, caller callerIdentity) string {
	// SH11 W11-2: dynamic words are only refused in the SCRIPT slot — a
	// script operand decides what sed executes and may arm `e`; input
	// file operands (every positional after the script) are plain data
	// paths and pass when split-safe. sedScripts already extracts the
	// script fragments; re-scan the operand zone to locate and validate
	// dynamic positionals.
	scripts, _ := sedScripts(args)
	for _, s := range scripts {
		if isDynamicArg(s) {
			// R4: only restricted literal binds reach static text; a
			// placeholder still present means the script text is unvettable.
			return "dynamic code payload"
		}
		cmds := sedExecCommands(s)
		for _, cmd := range cmds {
			if hit := guardShellSubagentDepth(cmd, depth+1, caller); hit != "" {
				return hit
			}
		}
		if len(cmds) > 0 {
			// An e command arms text the guard cannot vet (the screened
			// hits above are the vettable sub-set — e.g. `e pig`); the
			// rest fail closed as a sed write/exec surface.
			return "sed e"
		}
	}
	// Dynamic operands outside the script slots must be split-safe data
	// paths: walk the operand zone with sed's own consumption model so
	// -e/-f/-l value slots and the first positional (the script — already
	// screened above) are not misread as data, and input FILE operands
	// only need to be option-incapable (SH11 W11-2).
	sawExplicit := false
	sawScript := false
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" && !endOpts {
			endOpts = true
			continue
		}
		dynOptVal, dynOptKind := sedDynamicOptValue(a)
		if !endOpts && strings.HasPrefix(a, "-") && a != "-" && (!isDynamicArg(a) || dynOptKind != 0 || strings.HasPrefix(a, "--file=") || strings.HasPrefix(a, "--expression=")) {
			// Option word: replicate the value consumption (e/f script or
			// file, l wrap length — cluster tail or next argv). R13/R14: a
			// -f/--file=/-nfV word whose VALUE is dynamic still belongs to
			// the option zone (the flag slot is recognisable from its
			// static prefix) and its value gets the same independent /
			// glued / long-option validation; any OTHER dynamic option word
			// is unvettable and fails closed instead of being skipped as a
			// checked positional.
			if isDynamicArg(a) && dynOptKind == 0 {
				return "dynamic code payload"
			}
			if dynOptKind != 0 {
				// Dynamic cluster value: dynOptVal is the dynamic tail
				// (the glued operand). '-' feeds the script from stdin;
				// a safe data path is the only other allowed value.
				switch {
				case dynOptVal == "-" || isStdinDevicePath(dynOptVal):
					return "sed script from stdin"
				case !isSafeDynamicDataOperand(dynOptVal):
					return "dynamic code payload"
				}
				sawExplicit = true
				continue
			}
			switch {
			case a == "-f" || a == "--file":
				sawExplicit = true
				// S3: `sed -f -` (and the /dev/stdin family) reads the SCRIPT
				// from stdin — unvetted program text; reject it like a
				// dynamic payload. A process-substitution target arrives as
				// a placeholder and must still name a safe data path.
				if i+1 < len(args) {
					v := args[i+1]
					if v == "-" || isStdinDevicePath(v) {
						return "sed script from stdin"
					}
					if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
						return "dynamic code payload"
					}
				}
				i++
			case a == "-e" || a == "--expression" || a == "--line-length":
				sawExplicit = sawExplicit || a != "--line-length"
				i++
			case strings.HasPrefix(a, "--expression=") || strings.HasPrefix(a, "--file="):
				sawExplicit = true
				// R13: the =value still names the script FILE — validate it
				// like a separate -f operand so a dynamic/proc-subst path
				// (--file=<(…) / --file=$X) or a stdin device path cannot
				// smuggle unvetted program text past the first-positional
				// check.
				if strings.HasPrefix(a, "--file=") {
					v := a[len("--file="):]
					if v == "-" || isStdinDevicePath(v) {
						return "sed script from stdin"
					}
					if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
						return "dynamic code payload"
					}
				}
			case strings.HasPrefix(a, "--"):
				// other long options: no value operand consumed
			default:
				for j := 1; j < len(a); j++ {
					switch a[j] {
					case 'e', 'f':
						sawExplicit = true
						if j+1 >= len(a) {
							if a[j] == 'f' && i+1 < len(args) {
								v := args[i+1]
								if v == "-" || isStdinDevicePath(v) {
									return "sed script from stdin"
								}
								if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
									return "dynamic code payload"
								}
							}
							i++
						} else {
							// Glued file/script operand (cluster tail): an `f`
							// tail names the script FILE — '-' or a stdin device
							// path reads stdin and a dynamic tail must still be a
							// safe data path.
							if a[j] == 'f' {
								v := a[j+1:]
								if v == "-" || isStdinDevicePath(v) {
									return "sed script from stdin"
								}
								if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
									return "dynamic code payload"
								}
							}
						}
						j = len(a)
					case 'l':
						if j+1 >= len(a) {
							i++
						}
						j = len(a)
					}
				}
			}
			continue
		}
		// Positional operand (after --, or non-option shape, or bare "-").
		if isDynamicArg(a) {
			if !sawScript && !sawExplicit && a != "-" {
				// This word IS the script slot — screened above.
				sawScript = true
				continue
			}
			if !isSafeDynamicDataOperand(a) {
				return "dynamic code payload"
			}
			continue
		}
		if !sawScript && !sawExplicit && a != "-" {
			sawScript = true // first static positional is the script
		}
	}
	return ""
}

// sedDynamicOptValue locates the value slot of a DYNAMIC short-option
// cluster (-nf<V>, -e<V>, -l<V>): it scans the static prefix before the
// first dynamic byte for sed's value-carrying letters (e script, f file,
// l length — each ends the cluster). kind is 'e', 'f' or 'l' and val the
// dynamic tail (the glued operand); kind 0 means no recognisable value
// slot — either the word is not dynamic/option-shaped or the option zone
// itself is unvettable.
func sedDynamicOptValue(a string) (val string, kind byte) {
	if len(a) < 3 || a[0] != '-' || a[1] == '-' || !isDynamicArg(a) {
		return "", 0
	}
	// lim: the static prefix length — the cluster scan never crosses a
	// placeholder boundary.
	lim := len(a)
	for _, ph := range []string{cmdSubPlaceholder, cmdSubPlaceholderQuoted,
		cmdSubPlaceholderGlob, cmdSubPlaceholderAbsDq} {
		if k := strings.Index(a, ph); k >= 0 && k < lim {
			lim = k
		}
	}
	for j := 1; j < lim; j++ {
		switch a[j] {
		case 'e', 'f', 'l':
			if lim < len(a) {
				// The glued operand is everything after the letter — it
				// may carry static bytes before the dynamic part.
				return a[j+1:], a[j]
			}
			return "", 0 // value letter inside a fully static cluster
		}
	}
	return "", 0
}

// sedScripts extracts the script text fragments a sed invocation actually
// executes: every -e/--expression payload (separate, =glued, or a
// short-option-cluster tail) plus the FIRST positional operand when no -e/-f
// appeared — GNU sed treats only that first operand as the script; later
// positionals are always input file names. sawFile reports -f/--file
// (unvetted script file): the strict read-only guard fails closed on it,
// the sub-agent caller just keeps the inline fragments.
func sedScripts(args []string) (scripts []string, sawFile bool) {
	sawExplicit := false
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" && !endOpts {
			endOpts = true
			continue
		}
		if !endOpts {
			switch {
			case a == "-e" || a == "--expression":
				sawExplicit = true
				if i+1 < len(args) {
					scripts = append(scripts, args[i+1])
					i++
				}
			case strings.HasPrefix(a, "--expression="):
				sawExplicit = true
				scripts = append(scripts, a[len("--expression="):])
			case a == "-f" || a == "--file":
				sawExplicit = true
				sawFile = true
				i++ // consume the script-file operand
			case strings.HasPrefix(a, "--file="):
				sawExplicit = true
				sawFile = true
			case a == "--line-length":
				i++ // consume the length operand
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1:
				// Short-option cluster: 'e' carries the script (cluster tail
				// or next argv), 'f' names a script file, 'l' (GNU -l N
				// wrap length) carries a value — all three end the cluster.
				// R14: the scan stops at the first placeholder byte so a
				// dynamic tail lands on the value letter's slot (-nf<V>
				// marks sawFile, -ne<V> feeds the script); an option word
				// whose OPTION ZONE is dynamic is unvettable and is fed to
				// the caller's script screen as a dynamic payload.
				lim := len(a)
				for _, ph := range []string{cmdSubPlaceholder, cmdSubPlaceholderQuoted,
					cmdSubPlaceholderGlob, cmdSubPlaceholderAbsDq} {
					if k := strings.Index(a, ph); k >= 0 && k < lim {
						lim = k
					}
				}
				sawValLetter := false
				for j := 1; j < lim; j++ {
					switch a[j] {
					case 'e':
						sawExplicit = true
						sawValLetter = true
						if tail := a[j+1:]; tail != "" {
							scripts = append(scripts, tail)
						} else if i+1 < len(args) {
							scripts = append(scripts, args[i+1])
							i++
						}
						j = lim
					case 'f':
						sawExplicit = true
						sawFile = true
						sawValLetter = true
						// R15: a dynamic TAIL is the glued file operand —
						// argv advance is decided by the real word length,
						// not the placeholder boundary (lim). Skipping the
						// next argv here would let a following -e land in
						// the positional slot where sawExplicit ignores it.
						if j+1 >= len(a) {
							i++ // file operand is the next argv
						}
						j = lim
					case 'l':
						sawValLetter = true
						if j+1 >= len(a) {
							i++ // length operand is the next argv
						}
						j = lim
					}
				}
				if isDynamicArg(a) && !sawValLetter {
					// -$X / -n$X: the dynamic part could expand into option
					// letters (nf script file, e script) or a script — feed
					// it to the caller's dynamic rejection instead of
					// silently skipping it as "first script already seen".
					scripts = append(scripts, a)
				}
			case strings.HasPrefix(a, "-"):
				continue // other long options (--posix, --regexp-extended, ...)
			}
		}
		// Positional operand (after --, or not option-shaped, or bare "-"):
		// only the very first positional is a script, and only when no
		// -e/-f ever appeared; everything else is an input file name.
		if endOpts || !strings.HasPrefix(a, "-") || a == "-" {
			if !sawExplicit && len(scripts) == 0 && a != "-" {
				scripts = append(scripts, a)
			}
		}
	}
	return scripts, sawFile
}

// sedExecCommands extracts the command text of GNU sed `e` executions:
// a bare `e cmd` command (executes cmd, output into pattern space) and
// `s///e` whose substituted text is executed. Returns nil when no e is
// present (sed -n '1,20p', s/a/b/g, /err/p stay free).
func sedExecCommands(s string) []string {
	var out []string
	i := 0
	n := len(s)
	atCmdStart := true // after ; { } or start-of-script an `e` is a command
	for i < n {
		c := s[i]
		switch {
		case c == '#':
			for i < n && s[i] != '\n' && s[i] != ';' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == ';' || c == '{' || c == '}':
			atCmdStart = true
			i++
		case c == '/':
			// Regex address: skip to the unquoted closing /, tracking [...].
			i++
			for i < n {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if s[i] == '[' {
					// Character class: delimiters inside [...] are literal.
					i++
					if i < n && s[i] == '^' {
						i++
					}
					if i < n && s[i] == ']' { // ] as first (data) char is literal
						i++
					}
					for i < n && s[i] != ']' {
						if s[i] == '\\' {
							if i+1 < n {
								i += 2
							} else {
								i = n
							}
							continue
						}
						i++
					}
					if i < n {
						i++ // closing ]
					}
					continue
				}
				if s[i] == '/' {
					i++
					// GNU sed allows I/M (and i/m) regex flags after the close.
					for i < n && (s[i] == 'I' || s[i] == 'M' || s[i] == 'i' || s[i] == 'm') {
						i++
					}
					break
				}
				i++
			}
			atCmdStart = true // an address precedes a command
		case c == 's' && atCmdStart:
			// s<delim><pat><delim><repl><delim><flags>: an `e` flag executes
			// the REPLACEMENT text as a command — extract it for screening.
			atCmdStart = false
			i++
			if i >= n {
				break
			}
			delim := s[i]
			i++
			// Skip the pattern part.
			for i < n && s[i] != delim {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				i++
			}
			if i >= n {
				break // truncated: no middle delimiter, no e flag possible
			}
			i++
			// The replacement part is the command text for s///e.
			replStart := i
			for i < n && s[i] != delim {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				i++
			}
			repl := s[replStart:i]
			if i >= n {
				break // truncated: no closing delimiter, no e flag possible
			}
			i++
			for i < n {
				fc := s[i]
				if fc == 'e' {
					if strings.TrimSpace(repl) != "" {
						out = append(out, repl)
					} else {
						out = append(out, s) // dynamic: pattern space content
					}
					break
				}
				if fc == ' ' || fc == '\t' || fc == ';' || fc == '\n' {
					break
				}
				if fc >= 'a' && fc <= 'z' || fc >= 'A' && fc <= 'Z' || fc >= '0' && fc <= '9' {
					i++
					continue
				}
				break
			}
		case c == 'e' && atCmdStart:
			// Bare `e cmd` command: everything after it on the command is the
			// shell text (up to ; or newline).
			atCmdStart = false
			i++
			j := i
			for j < n && s[j] != ';' && s[j] != '\n' {
				j++
			}
			out = append(out, strings.TrimSpace(s[i:j]))
			i = j
		case c >= '0' && c <= '9' || c == '$' || c == ',' || c == '~' || c == '+' || c == '!':
			// Address components / negation: keep atCmdStart so the following
			// letter is still read as a command (1!e cmd).
			i++
		case c == '\\':
			// Custom-delimiter regex address \c...c (e.g. \|root|e pig).
			if i+1 >= n {
				i = n
				break
			}
			delim := s[i+1]
			i += 2
			for i < n {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if s[i] == '[' {
					// Character class: delimiters inside [...] are literal.
					i++
					if i < n && s[i] == '^' {
						i++
					}
					if i < n && s[i] == ']' { // ] as first (data) char is literal
						i++
					}
					for i < n && s[i] != ']' {
						if s[i] == '\\' {
							if i+1 < n {
								i += 2
							} else {
								i = n
							}
							continue
						}
						i++
					}
					if i < n {
						i++ // closing ]
					}
					continue
				}
				if s[i] == delim {
					i++
					// GNU sed allows I/M (and i/m) regex flags after the close.
					for i < n && (s[i] == 'I' || s[i] == 'M' || s[i] == 'i' || s[i] == 'm') {
						i++
					}
					break
				}
				i++
			}
			atCmdStart = true // an address precedes a command
		default:
			// Any other command letter consumes the rest of its command.
			atCmdStart = false
			i++
			for i < n && s[i] != ';' && s[i] != '\n' {
				i++
			}
		}
	}
	return out
}

// screenTarSubagent screens tar exec-hook options for a SUB-AGENT caller:
// --checkpoint-action=exec=CMD, --to-command CMD and --use-compress-program
// CMD / -I CMD carry shell text screened as a command. Dynamic words are
// refused only when they can sit in an OPTION or hook position — value
// operands of -f/-C/-T/-X and split-safe member paths are data (W11-2).
func screenTarSubagent(args []string, depth int, caller callerIdentity) string {
	screenCmd := func(cmd string) string {
		if isDynamicArg(cmd) {
			return "dynamic code payload"
		}
		if hit := guardShellSubagentDepth(cmd, depth+1, caller); hit != "" {
			return hit
		}
		return "tar exec hook" // any non-blocked hook command still executes
	}
	bsdAction := false // first operand without '-' is the BSD action word
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if isDynamicArg(a) {
			// Value slots of -f/-C/-T/-X and member paths: split-safe path
			// operands only — a word-start __ctx_dq_sub__ may expand to an
			// option and is refused (Q1-C).
			if isSafeDynamicDataOperand(a) {
				continue
			}
			return "dynamic code payload"
		}
		var cmd string
		switch {
		case strings.HasPrefix(a, "--checkpoint-action="):
			v := a[len("--checkpoint-action="):]
			if strings.HasPrefix(v, "exec=") {
				cmd = v[len("exec="):]
			} else if v == "exec" {
				cmd = "true" // bare exec still arms the hook
			}
		case a == "--checkpoint-action":
			if i+1 < len(args) {
				v := args[i+1]
				if strings.HasPrefix(v, "exec=") {
					cmd = v[len("exec="):]
				}
				i++
			}
		case a == "--to-command" || a == "--use-compress-program" || a == "-I":
			if i+1 < len(args) {
				cmd = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--to-command="):
			cmd = a[len("--to-command="):]
		case strings.HasPrefix(a, "--use-compress-program="):
			cmd = a[len("--use-compress-program="):]
		case strings.HasPrefix(a, "-I") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			cmd = a[2:]
		case a == "-f" || a == "--file" || a == "-C" || a == "--directory" ||
			a == "-T" || a == "--files-from" || a == "-X" || a == "--exclude-from" ||
			a == "--exclude" || a == "--owner" || a == "--group" || a == "--mode" ||
			a == "--mtime" || a == "--strip-components" || a == "--transform" ||
			a == "--format" || a == "--index-file" || a == "--occurrence":
			// Data value slot: the next argv is a filename/dir/pattern, not
			// an option — a dynamic value is already screened above.
			i++
		case strings.HasPrefix(a, "--"):
			// Other long options (--numeric-owner, --exclude=pat, ...).
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// Short-option cluster: f/C/T/X take a value operand — the
			// cluster tail or the next argv — and end the cluster.
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'f', 'C', 'T', 'X', 'b', 'L', 'H', 'h':
					if j+1 >= len(a) {
						i++ // value operand is the next argv
					}
					j = len(a)
				}
			}
		default:
			// BSD first-operand action word (tar cf / tar xf / tar tzf):
			// when it contains 'f' the NEXT operand is the archive value.
			if !bsdAction {
				bsdAction = true
				if strings.Contains(a, "f") {
					i++
				}
			}
		}
		if cmd == "" {
			continue
		}
		if hit := screenCmd(cmd); hit != "" {
			return hit
		}
		return "tar exec hook" // any non-blocked hook command still executes
	}
	return ""
}

// -i inplace / -iINCL / --include inplace. Ordinary `awk '{print $1}'` passes.
func screenAwkInplace(args []string) string {
	for i, a := range args {
		switch {
		case a == "-i" || a == "--include":
			if i+1 < len(args) && (args[i+1] == "inplace" || strings.HasPrefix(args[i+1], "inplace")) {
				return "awk -i inplace"
			}
			if a == "-i" {
				return "awk -i"
			}
		case strings.HasPrefix(a, "-i") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			if strings.Contains(a[2:], "inplace") || a[2] != '-' {
				return "awk " + a
			}
		}
	}
	return ""
}

// screenCurlWrite blocks download-to-disk spellings for strict read-only:
// -O/--remote-name/--remote-name-all and -o/--output whose target is a real
// file (-o -, -o /dev/null, /dev/stdout, /dev/stderr stay free). Short
// OPTION CLUSTERS count too: -sO, -fsSLO, -so /tmp/x, -so/tmp/x.
func screenCurlWrite(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" || a == "--remote-name" || a == "--remote-name-all":
			return "curl " + a
		case a == "-o" || a == "--output":
			if i+1 < len(args) {
				switch args[i+1] {
				case "-", "/dev/null", "/dev/stdout", "/dev/stderr":
					i++
				default:
					return "curl " + a + " " + args[i+1]
				}
			}
		case strings.HasPrefix(a, "--output="):
			if !curlSafeOutput(a[len("--output="):]) {
				return "curl " + a
			}
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1:
			// Short cluster: walk letters; 'O' anywhere writes to disk, 'o'
			// carries the output target (rest of cluster, else next argv).
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'O':
					return "curl " + a
				case 'o':
					if tail := a[j+1:]; tail != "" {
						if !curlSafeOutput(tail) {
							return "curl " + a
						}
					} else if i+1 < len(args) {
						if !curlSafeOutput(args[i+1]) {
							return "curl -o " + args[i+1]
						}
						i++
					}
					j = len(a)
				}
			}
		}
	}
	return ""
}

func curlSafeOutput(t string) bool {
	switch t {
	case "-", "/dev/null", "/dev/stdout", "/dev/stderr":
		return true
	}
	return false
}

// ctxmodeCLIAction returns the CLI action word of a `ctxmode` argv
// (skipping its boolean -workdir/-config flag spellings), or "" when the
// argv is a bare server invocation. `-workdir DIR` / `-config FILE` /
// `--workdir=DIR` / `-h` / `--help` do not count as actions.
func ctxmodeCLIAction(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-workdir" || a == "-config" || a == "--workdir" || a == "--config":
			i++ // consumes a value operand
		case strings.HasPrefix(a, "-"):
			// boolean flags incl. -h/--help and --workdir=/path
		default:
			return a
		}
	}
	return ""
}

// screenWgetWrite allows only explicit no-disk spellings (-O -, -O /dev/null,
// --spider); every other wget invocation downloads to disk by default.

// wgetSafeOutput reports destinations that do not create a payload file.
func wgetSafeOutput(t string) bool {
	switch t {
	case "-", "/dev/null", "/dev/stdout", "/dev/stderr":
		return true
	}
	return false
}

// wgetLongPrefix reports whether arg (without leading --) uniquely matches
// one of the candidate long option names (GNU getopt_long unique-prefix).
// Returns the matched full name or "".
func wgetLongPrefix(arg string, candidates []string) string {
	name, _, _ := strings.Cut(arg, "=")
	var hit string
	for _, c := range candidates {
		if name == c || (len(name) >= 1 && strings.HasPrefix(c, name)) {
			if hit != "" {
				return "" // ambiguous
			}
			hit = c
		}
	}
	return hit
}

func screenWgetWrite(args []string) string {
	// Model GNU wget getopt_long: short clusters, glued values, value slots,
	// unique long-option prefixes, and disk-writing side channels
	// (logs/cookies/warc/hsts/background/execute logfile=).
	okDownload := false
	onlyQuery := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			continue
		}
		if a == "--help" || a == "--version" || a == "-h" || a == "-V" {
			onlyQuery = true
			continue
		}
		if a == "--spider" {
			okDownload = true
			continue
		}

		// Long options (exact or unique prefix), with optional =value.
		if strings.HasPrefix(a, "--") {
			body := strings.TrimPrefix(a, "--")
			name, val, hasEq := strings.Cut(body, "=")

			// Disk-writing long options.
			diskLong := []string{
				"output-file", "append-output", "rejected-log",
				"save-cookies", "warc-file", "hsts-file",
				"output-document",
			}
			if hit := wgetLongPrefix(name, diskLong); hit != "" {
				dest := val
				if !hasEq {
					if i+1 >= len(args) {
						return "wget"
					}
					i++
					dest = args[i]
				}
				if hit == "output-document" {
					if wgetSafeOutput(dest) {
						okDownload = true
						continue
					}
					return "wget"
				}
				if !wgetSafeOutput(dest) {
					return "wget"
				}
				continue
			}
			if hit := wgetLongPrefix(name, []string{"background"}); hit != "" {
				return "wget" // -b/--background writes wget-log
			}
			if hit := wgetLongPrefix(name, []string{"execute"}); hit != "" {
				cmd := val
				if !hasEq {
					if i+1 >= len(args) {
						return "wget"
					}
					i++
					cmd = args[i]
				}
				if wgetExecuteWrites(cmd) {
					return "wget"
				}
				continue
			}
			// Value-taking long options that must consume the next argv so a
			// following --spider is not mistaken for a flag.
			valueLong := []string{
				"user-agent", "header", "referer", "proxy-user", "proxy-password",
				"user", "password", "base", "directory-prefix", "input-file",
				"bind-address", "tries", "timeout", "dns-timeout", "connect-timeout",
				"read-timeout", "wait", "waitretry", "limit-rate", "quota",
				"level", "load-cookies", "certificate", "ca-certificate",
				"private-key", "random-file", "egd-file", "secure-protocol",
				"post-data", "post-file", "method", "body-data", "body-file",
				"regex-type", "accept", "reject", "include-directories",
				"exclude-directories", "domains", "exclude-domains",
			}
			if hit := wgetLongPrefix(name, valueLong); hit != "" {
				if !hasEq {
					i++ // consume value slot
				}
				continue
			}
			continue // other long boolean flags
		}

		// Short options / clusters.
		if strings.HasPrefix(a, "-") && a != "-" && !strings.HasPrefix(a, "--") {
			cluster := a[1:]
			for j := 0; j < len(cluster); j++ {
				switch cluster[j] {
				case 'O':
					rest := cluster[j+1:]
					var dest string
					if rest != "" {
						dest = rest
						j = len(cluster)
					} else if i+1 < len(args) {
						i++
						dest = args[i]
						j = len(cluster)
					} else {
						return "wget"
					}
					if wgetSafeOutput(dest) {
						okDownload = true
					} else {
						return "wget"
					}
				case 'o', 'a':
					rest := cluster[j+1:]
					var dest string
					if rest != "" {
						dest = rest
						j = len(cluster)
					} else if i+1 < len(args) {
						i++
						dest = args[i]
						j = len(cluster)
					} else {
						return "wget"
					}
					if !wgetSafeOutput(dest) {
						return "wget"
					}
				case 'b':
					return "wget" // background → wget-log
				case 'e':
					rest := cluster[j+1:]
					var cmd string
					if rest != "" {
						cmd = rest
						j = len(cluster)
					} else if i+1 < len(args) {
						i++
						cmd = args[i]
						j = len(cluster)
					} else {
						return "wget"
					}
					if wgetExecuteWrites(cmd) {
						return "wget"
					}
				case 'U', 'P', 'i', 'B', 't', 'T', 'w', 'Q', 'l':
					// Value-taking shorts that shift subsequent argv slots.
					rest := cluster[j+1:]
					if rest != "" {
						j = len(cluster)
					} else {
						i++ // consume next argv as value
						j = len(cluster)
					}
				case 'h', 'V':
					onlyQuery = true
				default:
					// boolean short (q, n, c, ...)
				}
			}
			continue
		}
	}
	if okDownload || onlyQuery {
		return ""
	}
	return "wget"
}

// wgetExecuteWrites reports whether an -e/--execute COMMAND writes a logfile
// (wgetrc `logfile=PATH`).
func wgetExecuteWrites(cmd string) bool {
	for _, part := range strings.Split(cmd, ",") {
		part = strings.TrimSpace(part)
		key, val, hasEq := strings.Cut(part, "=")
		if !hasEq {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "logfile") {
			if !wgetSafeOutput(strings.TrimSpace(val)) {
				return true
			}
		}
	}
	return false
}

// firstNonFlagArg returns the first argument that is not a -flag.
func firstNonFlagArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// hasInPlaceFlag reports whether args contain an in-place spelling for
// sed/perl/ruby: -i, -i.SUFFIX, a bundled cluster containing i (-ni, -Ei,
// -ri), or --in-place[=SUFFIX]. `sed -n '1,20p' f` has none and passes.
func hasInPlaceFlag(args []string) bool {
	for _, a := range args {
		switch {
		case a == "--in-place" || strings.HasPrefix(a, "--in-place="):
			return true
		case a == "-i" || strings.HasPrefix(a, "-i."):
			return true
		case strings.HasPrefix(a, "-") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			for j := 1; j < len(a); j++ {
				if a[j] == 'i' {
					return true
				}
			}
		}
	}
	return false
}

// hasInterpInPlaceFlag reports whether a perl/ruby argv (starting at the
// interpreter head) carries an in-place -i flag. Unlike hasInPlaceFlag it
// stops scanning at `--` (what follows is the script filename/args, not
// options) and skips the operand of -e/-E so the script text itself can
// never be mistaken for an option cluster: `perl -e '-i'` and
// `perl -ne 'print' -- -input.txt` stay free.
func hasInterpInPlaceFlag(argv []string) bool {
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return false
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return false // first non-option operand ends the option run
		}
		if strings.HasPrefix(a, "--") {
			if a == "--in-place" || strings.HasPrefix(a, "--in-place=") {
				return true
			}
			continue
		}
		// Short cluster: -e/-E take an inline-script operand — when glued
		// (-eCODE) the cluster ends there and holds no i; when bare
		// (-e CODE) the next arg is the script text and must be skipped.
		// -M/-m/-I/-r/-x/-F also take a separate operand when bare (-r lib
		// for ruby, -x[dir]/-F pattern for perl): without them a library
		// name like 'time' would be misread for an 'i' letter.
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 'i':
				return true
			case 'e', 'E', 'M', 'm', 'I', 'r', 'x', 'F':
				if j+1 >= len(a) {
					i++ // operand is the next argv
				}
				j = len(a)
			}
		}
	}
	return false
}

// gitBranchWriteFlags are the branch flags that mutate.
var gitBranchWriteFlags = map[string]bool{
	"-d": true, "-D": true, "-m": true, "-M": true, "-c": true, "-C": true,
	"--delete": true, "--move": true, "--copy": true,
	"-f": true, "--force": true, "-u": true, "--unset-upstream": true,
	"--edit-description": true,
}

// gitBranchQueryFlags make `git branch` a listing/query even with operands.
// -q/--quiet are deliberately ABSENT: `git branch -q newbranch` creates a
// branch quietly — the flag must not turn a creation into a "query".
var gitBranchQueryFlags = map[string]bool{
	"--contains": true, "--no-contains": true, "--merged": true,
	"--no-merged": true, "--points-at": true,
	"-l": true, "--list": true,
	"--show-current": true, "-a": true, "--all": true, "-r": true,
	"--remotes": true, "-v": true, "--verbose": true,
}

// gitTagWriteFlags are tag flags that mutate (delete/create/sign/force).
var gitTagWriteFlags = map[string]bool{
	"-d": true, "--delete": true, "-a": true, "-s": true, "-u": true,
	"-f": true, "--force": true, "-m": true, "-F": true,
	"--annotate": true, "--sign": true, "--local-user": true,
}

// gitTagReadFlags are tag flags that keep the invocation a listing/verify.
var gitTagReadFlags = map[string]bool{
	"-l": true, "--list": true, "-v": true, "--verify": true,
	"--points-at": true, "--contains": true, "--no-contains": true,
	"--merged": true, "--no-merged": true,
	"-h": true, "--help": true,
}

// gitConfigWriteFlags are config operations that write.
var gitConfigWriteFlags = map[string]bool{
	"--unset": true, "--unset-all": true, "--replace-all": true,
	"--add": true, "--remove-section": true, "--rename-section": true,
	"-e": true, "--edit": true,
}

// gitConfigReadFlags make config a pure query.
var gitConfigReadFlags = map[string]bool{
	"--get": true, "--get-all": true, "--get-regexp": true,
	"--get-urlmatch": true, "--list": true, "-l": true,
	"--show-origin": true, "--show-scope": true, "-h": true, "--help": true,
}

// screenGitWrite applies the git subcommand model: global options are skipped
// first, then the subcommand decides. Read-only subcommands must not carry a
// file-writing --output; worktree/branch/tag/config/remote/stash get
// dual-mode flag checks; every other subcommand is a write for strict roles.

// gitFsckLostFoundOpt reports whether a is a unique prefix of --lost-found
// (Git parse-options accepts unambiguous abbreviations; fsck has no other
// --l* option, so --l / --lo / --lost / --lost-f all mean --lost-found).
func gitFsckLostFoundOpt(a string) bool {
	const full = "--lost-found"
	if a == full {
		return true
	}
	if !strings.HasPrefix(a, "--") || len(a) < 3 || strings.Contains(a, "=") {
		return false
	}
	return strings.HasPrefix(full, a)
}

func screenGitWrite(args []string) string {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree" || a == "--namespace" || a == "--exec-path":
			i += 2
		case strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") ||
			strings.HasPrefix(a, "--namespace=") || strings.HasPrefix(a, "--exec-path="):
			i++
		case strings.HasPrefix(a, "-c") && len(a) > 2 && strings.ContainsRune(a[2:], '='):
			i++ // -ckey=value bundle
		case strings.HasPrefix(a, "-"):
			i++ // boolean global flags (--no-pager, --bare, -P, ...)
		default:
			goto subFound
		}
	}
	return ""
subFound:
	if i >= len(args) {
		return ""
	}
	sub := args[i]
	rest := args[i+1:]

	// A file-writing --output on any subcommand is a write.
	for _, a := range rest {
		if a == "--output" || strings.HasPrefix(a, "--output=") {
			return "git " + sub + " --output"
		}
	}
	// A pager/exec helper armed inside a read-only verb still executes a
	// command inside git's plumbing — block it for strict roles too.
	if hit := gitExecArgHit(rest); hit != "" {
		return hit
	}

	switch sub {
	case "worktree":
		// Bare `git worktree`, `list`, and -h/--help are read-only; every
		// other verb (add/remove/prune/move/lock/unlock/repair/...) writes.
		if len(rest) == 0 {
			return ""
		}
		first := rest[0]
		if first == "-h" || first == "--help" {
			return ""
		}
		if strings.HasPrefix(first, "-") {
			return "" // bare `git worktree -v`-style flags stay a listing
		}
		if first == "list" {
			return ""
		}
		return "git worktree " + first
	case "branch":
		writeFlag := ""
		query := false
		hasOperand := false
		for k := 0; k < len(rest); k++ {
			a := rest[k]
			if gitBranchWriteFlags[a] || strings.HasPrefix(a, "--set-upstream-to") {
				writeFlag = a
				break
			}
			if gitBranchQueryFlags[a] {
				// -v/-vv (verbose listing) alone does not make an operand a
				// query: `git branch -v newbranch` shows it, `git branch
				// newbranch` creates it — the verb decides on operands.
				if a != "-v" && a != "--verbose" && a != "-vv" {
					query = true
				}
				// --points-at/--contains/--no-contains/--merged/--no-merged
				// take a separate value; skip it.
				switch a {
				case "--points-at", "--contains",
					"--no-contains", "--merged", "--no-merged":
					if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
						k++
					}
				}
				continue
			}
			// --sort/--format only pick a display order/layout — they are
			// NOT listing triggers. Consume their value so the operand is
			// not misread as a branch name, but never set query.
			if a == "--sort" || a == "--format" {
				if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
					k++
				}
				continue
			}
			if strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--format=") {
				continue
			}
			if strings.HasPrefix(a, "--points-at=") || strings.HasPrefix(a, "--contains=") ||
				strings.HasPrefix(a, "--no-contains=") || strings.HasPrefix(a, "--merged=") ||
				strings.HasPrefix(a, "--no-merged=") {
				query = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue // other flags (-q, --quiet, -f handled above)
			}
			hasOperand = true
		}
		if writeFlag != "" {
			return "git branch " + writeFlag
		}
		if query {
			return "" // `git branch --contains HEAD` / `-l pat` etc.
		}
		if hasOperand {
			for _, a := range rest {
				if !strings.HasPrefix(a, "-") {
					return "git branch " + a
				}
			}
		}
		return "" // bare `git branch` / flag-only listing (-v, -q)
	case "tag":
		for _, a := range rest {
			if gitTagWriteFlags[a] {
				return "git tag " + a
			}
		}
		// Any explicit list/verify flag keeps it read-only; bare `git tag`
		// lists; a bare name operand without read flags creates a tag.
		hasReadFlag := false
		hasOperand := false
		for k := 0; k < len(rest); k++ {
			a := rest[k]
			// --sort/--format only choose a display order/layout — they are
			// NOT read flags. Consume their value so it is not misread as a
			// tag name, but never set hasReadFlag.
			if a == "--sort" || a == "--format" {
				if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
					k++
				}
				continue
			}
			if strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--format=") {
				continue
			}
			if gitTagReadFlags[a] || strings.HasPrefix(a, "-n") ||
				strings.HasPrefix(a, "--contains=") || strings.HasPrefix(a, "--no-contains=") ||
				strings.HasPrefix(a, "--merged=") || strings.HasPrefix(a, "--no-merged=") {
				hasReadFlag = true
				// Separate-value forms consume the next arg.
				switch a {
				case "-n", "--points-at", "--contains",
					"--no-contains", "--merged", "--no-merged":
					if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
						k++
					}
				case "-l", "--list", "-v", "--verify":
					// list/verify take an optional pattern; never swallow a flag.
					if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
						k++
					}
				}
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			hasOperand = true
		}
		if hasReadFlag {
			return ""
		}
		if hasOperand {
			return "git tag"
		}
		return "" // bare `git tag` or flag-only invocation lists
	case "config":
		for _, a := range rest {
			if gitConfigWriteFlags[a] {
				return "git config " + a
			}
		}
		hasRead := false
		positional := 0
		for _, a := range rest {
			if gitConfigReadFlags[a] {
				hasRead = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue // --global/--file scope flags: neither proves read nor write
			}
			positional++
		}
		if hasRead {
			return "" // --get/-l style query (value operands are the pattern)
		}
		switch {
		case positional >= 2:
			return "git config" // `git config name value` writes
		case positional == 1:
			return "" // `git config name` reads a key
		default:
			return "git config" // flag-only / bare: fail closed for strict
		}
	case "remote":
		if len(rest) == 0 {
			return ""
		}
		// Peel a leading -v/--verbose BEFORE the subcommand: `git remote -v`
		// alone is the listing, `git remote -v show origin` still reaches
		// the read-only `show` verb.
		k := 0
		for k < len(rest) && (rest[k] == "-v" || rest[k] == "--verbose") {
			k++
		}
		if k >= len(rest) {
			return ""
		}
		sub2 := rest[k]
		if sub2 == "-h" || sub2 == "--help" {
			return ""
		}
		if sub2 == "show" || sub2 == "get-url" {
			return ""
		}
		if strings.HasPrefix(sub2, "-") {
			return "" // bare flag-only remote (-v -h) stays a listing
		}
		return "git remote " + sub2
	case "stash":
		if len(rest) == 0 {
			return "git stash" // bare stash pushes
		}
		// Peel a leading -q/--quiet BEFORE the verb: `git stash -q list` is
		// still the read-only list; bare `git stash -q` pushes.
		k := 0
		for k < len(rest) && (rest[k] == "-q" || rest[k] == "--quiet") {
			k++
		}
		if k >= len(rest) {
			return "git stash" // flag-only: still pushes quietly
		}
		sub2 := rest[k]
		if sub2 == "-h" || sub2 == "--help" {
			return ""
		}
		if gitStashReadonlySubs[sub2] {
			return ""
		}
		return "git stash " + sub2
	case "reflog":
		// `git reflog`, `reflog show`, --help / -n listing inspect; expire/delete write.
		j := 0
		for j < len(rest) {
			a := rest[j]
			if a == "--" {
				j++
				break
			}
			if !strings.HasPrefix(a, "-") || a == "-" {
				break
			}
			if a == "-n" || a == "--max-count" || strings.HasPrefix(a, "--max-count=") {
				if !strings.Contains(a, "=") {
					j += 2
					continue
				}
				j++
				continue
			}
			if strings.HasPrefix(a, "-n") && a != "-n" && !strings.HasPrefix(a, "--") {
				j++
				continue
			}
			if a == "-h" || a == "--help" {
				return ""
			}
			j++
		}
		if j >= len(rest) {
			return ""
		}
		sub2 := rest[j]
		if sub2 == "show" || sub2 == "-h" || sub2 == "--help" {
			return ""
		}
		return "git reflog " + sub2
	case "fsck":
		// Plain fsck / connectivity checks are read-only; --lost-found
		// (and unique prefixes --l/--lo/--lost/...) write into .git/lost-found/.
		for _, a := range rest {
			if gitFsckLostFoundOpt(a) {
				return "git fsck --lost-found"
			}
		}
		return ""
	case "submodule":
		// Bare `git submodule`, `status`, `summary`, --help inspect; init/
		// update/add/deinit/sync/set-url/set-branch/foreach/absorbgitdirs
		// mutate the tree — and a leading option run (--quiet, -q,
		// --recursive, --branch NAME) must be peeled BEFORE the verb is read,
		// or `git submodule --quiet foreach 'touch /tmp/x'` slips through on
		// the flag.
		verb, isVerb := gitSubmoduleVerb(rest)
		if !isVerb {
			return "" // bare / flag-only `git submodule --quiet` lists
		}
		switch verb {
		case "status", "summary":
			return ""
		}
		return "git submodule " + verb
	default:
		if gitReadonlySubs[sub] {
			return ""
		}
		return "git " + sub
	}
}

// gitSubmoduleVerb returns the verb of `git submodule [flags] VERB`: the
// leading option run is peeled first (GNU --quiet/-q/--progress/--no-progress
// are boolean; --branch/-b/--configuration carry a separate value; `--`
// terminates options). isVerb is false when no verb word follows — a bare or
// flag-only `git submodule` is the listing.
func gitSubmoduleVerb(args []string) (verb string, isVerb bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case a == "--branch" || a == "-b" || a == "--configuration":
			i++ // verb-taking option: its value is not the verb
		case strings.HasPrefix(a, "--branch=") || strings.HasPrefix(a, "--configuration="):
			// glued value, nothing to skip
		case strings.HasPrefix(a, "-"):
			// boolean global flag (--quiet/-q/--recursive/--progress/…)
		default:
			return a, true
		}
	}
	return "", false
}

// ---------- additional head screens ----------

// screenGitGlobalArgs scans the global options before a git subcommand for
// execution-arming configuration: `-c` / `--config-env` entries that hand a
// command string to a hook key (or a `!`-prefixed shell alias), and
// `--exec-path=<dir>` that redirects git to an unvetted helper directory.
// Returns (index of the subcommand, guard hit or ""). Bare `git --exec-path`
// (no value) is the path query and stays free.

func gitKeyIsExecCapable(key string) bool {
	if gitExecConfigKeys[key] {
		return true
	}
	for _, p := range gitExecConfigPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	lk := strings.ToLower(key)
	for _, needle := range []string{"hook", "command", "exec", "driver", "helper", "askpass", "editor", "pager", "ssh", "proxy"} {
		if strings.Contains(lk, needle) {
			return true
		}
	}
	return false
}

func screenGitGlobalArgs(args []string) (int, string) {
	i := 0
	for i < len(args) {
		a := args[i]
		if isDynamicArg(a) {
			return i, "git dynamic global option"
		}
		switch {
		case a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace":
			if i+1 >= len(args) {
				return i, "git " + a
			}
			if isDynamicArg(args[i+1]) && !isSplitSafeDynamicWord(args[i+1]) {
				return i, "git dynamic global option"
			}
			i += 2
		case a == "-c":
			if i+1 >= len(args) {
				return i, "git -c"
			}
			pair := args[i+1]
			if isDynamicArg(pair) {
				// SH11 MF-2.2: the whole KEY=VAL word must be split-safe — an
				// unquoted $X value can field-split a second `-c` option in.
				if !isSplitSafeDynamicWord(pair) {
					return i, "git dynamic global option"
				}
				// Key must be static; value may be split-safe dynamic for non-hook keys.
				eq := strings.IndexByte(pair, '=')
				if eq < 0 || isDynamicArg(pair[:eq]) {
					return i, "git dynamic global option"
				}
				key, val := pair[:eq], pair[eq+1:]
				if gitKeyIsExecCapable(key) || strings.HasPrefix(val, "!") {
					return i, "git dynamic global option"
				}
			} else if hit := screenGitConfigPair(pair); hit != "" {
				return i, hit
			}
			i += 2
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			if isDynamicArg(a) {
				return i, "git dynamic global option"
			}
			if hit := screenGitConfigPair(a[2:]); hit != "" {
				return i, hit
			}
			i++
		case a == "--config-env":
			if i+1 >= len(args) || isDynamicArg(args[i+1]) {
				return i, "git dynamic global option"
			}
			if hit := screenGitConfigEnvPair(args[i+1]); hit != "" {
				return i, hit
			}
			i += 2
		case strings.HasPrefix(a, "--config-env="):
			if isDynamicArg(a) {
				return i, "git dynamic global option"
			}
			if hit := screenGitConfigEnvPair(a[len("--config-env="):]); hit != "" {
				return i, hit
			}
			i++
		case a == "--exec-path":
			// Bare `git --exec-path` prints the path (read-only); a following
			// operand binds a directory that must block.
			if i+1 < len(args) {
				return i, "git --exec-path"
			}
			i++
		case strings.HasPrefix(a, "--exec-path="):
			return i, "git --exec-path"
		case strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") ||
			strings.HasPrefix(a, "--namespace="):
			if isDynamicArg(a) && !isSplitSafeDynamicWord(a) {
				return i, "git dynamic global option"
			}
			i++
		case strings.HasPrefix(a, "-"):
			i++ // boolean global flags (--no-pager, --bare, -P, ...)
		default:
			return i, ""
		}
	}
	return i, ""
}

// screenGitSubagentExecArgs scans the args AFTER the global options for
// execution-arming subcommand flags a sub-agent must not use:
// `git grep --open-files-in-pager=cmd` / `-Ocmd`, and `git rebase --exec cmd`
// (also git fetch --recurse-submodules=<cmd>-style run helpers are not
// covered — those go through the command whitelist). A non-empty, non-cat
// pager/exec value is screened as shell text.
func screenGitSubagentExecArgs(args []string) string {
	// Skip the global options (same walk as screenGitGlobalArgs) to reach
	// the subcommand operands.
	i, hit := screenGitGlobalArgs(args)
	if hit != "" {
		return hit
	}
	sub := ""
	if i < len(args) {
		sub = args[i]
		i++
	}
	endOpts := false
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			endOpts = true
			continue
		}
		if !endOpts && isDynamicArg(a) && (sub == "grep" || sub == "rebase") {
			return "git " + sub + " dynamic option"
		}
		var val string
		switch {
		case a == "--open-files-in-pager" || a == "-O":
			if i+1 < len(args) {
				val = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--open-files-in-pager="):
			val = a[len("--open-files-in-pager="):]
		case strings.HasPrefix(a, "-O") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			val = a[2:]
		case a == "--exec":
			if i+1 < len(args) {
				val = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--exec="):
			val = a[len("--exec="):]
		default:
			continue
		}
		if val == "" || val == "cat" {
			continue
		}
		if hit := guardShellSubagentDepth(val, 1, currentCallerIdentity()); hit != "" {
			return "git " + a
		}
		// Non-blocked but non-trivial command text still arms a hook — a
		// sub-agent must not run ANY pager/exec helper; only cat/"" disable.
		return "git " + a
	}
	return ""
}

// gitExecArgHit scans subcommand args for --open-files-in-pager/-O/--exec
// spellings carrying a non-empty, non-cat command: for strict read-only the
// command runs unscreened inside git's plumbing, so it must block outright.
func gitExecArgHit(rest []string) string {
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--open-files-in-pager" || a == "-O" || a == "--exec":
			if i+1 < len(rest) && rest[i+1] != "" && rest[i+1] != "cat" {
				return "git " + a
			}
			i++
		case strings.HasPrefix(a, "--open-files-in-pager="):
			if v := a[len("--open-files-in-pager="):]; v != "" && v != "cat" {
				return "git --open-files-in-pager"
			}
		case strings.HasPrefix(a, "-O") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			if v := a[2:]; v != "" && v != "cat" {
				return "git -O"
			}
		case strings.HasPrefix(a, "--exec="):
			if v := a[len("--exec="):]; v != "" && v != "cat" {
				return "git --exec"
			}
		}
	}
	return ""
}

// gitExecConfigKeys are the lower-cased config keys whose value git execs:
// pager/ssh/editor/hook paths, credential and diff helpers.
var gitExecConfigKeys = map[string]bool{
	"core.pager": true, "core.sshcommand": true, "core.fsmonitor": true,
	"core.editor": true, "sequence.editor": true, "core.hookspath": true,
	"core.askpass": true, "diff.external": true, "credential.helper": true,
}

// gitExecConfigPrefixes are lower-cased key prefixes whose values git execs.
var gitExecConfigPrefixes = []string{
	"pager.", "alias.", "filter.", "difftool.", "mergetool.",
}

// screenGitConfigPair screens one `key=value` from `git -c`. A `!`-prefixed
// value is a shell alias; a blocked key hands a command path to git.
// `core.pager=cat` / `core.pager=` stay free (pager disabling is read-only).
func screenGitConfigPair(pair string) string {
	eq := strings.IndexByte(pair, '=')
	if eq < 0 {
		return ""
	}
	key := strings.ToLower(pair[:eq])
	val := pair[eq+1:]
	if strings.HasPrefix(val, "!") {
		return "git -c " + pair[:eq] // key only: the !cmd value may carry secrets
	}
	if key == "core.pager" && (val == "" || val == "cat") {
		return ""
	}
	if gitExecConfigKeys[key] {
		return "git -c " + pair[:eq]
	}
	for _, p := range gitExecConfigPrefixes {
		if strings.HasPrefix(key, p) {
			return "git -c " + pair[:eq]
		}
	}
	return ""
}

// screenGitConfigEnvPair screens one `key=ENVNAME` from `git --config-env`:
// the value comes from an environment variable, so only the key side can be
// screened for exec-arming configuration — and unlike `git -c`, the env
// value cannot carry the literal `cat` exemption, so exec keys block
// unconditionally (disabling a pager stays available via `--no-pager` or
// `-c core.pager=cat`).
func screenGitConfigEnvPair(pair string) string {
	eq := strings.IndexByte(pair, '=')
	if eq < 0 {
		return ""
	}
	key := strings.ToLower(pair[:eq])
	if gitExecConfigKeys[key] {
		return "git --config-env " + pair[:eq]
	}
	for _, p := range gitExecConfigPrefixes {
		if strings.HasPrefix(key, p) {
			return "git --config-env " + pair[:eq]
		}
	}
	return ""
}

// screenTarWrite allows only read-only tar spellings for strict roles:
// -t/--list (and --diff/--compare), --help, --version, or extraction to
// stdout via -O/--to-stdout. Creation (-c), append (-r), update (-u),
// --delete, disk extraction (-x without -O), and BSD flag-less `cf`/`xf`/
// `czf` bundles all block. Exec hooks (--checkpoint-action=exec*,
// --to-command) run shell text inside tar and block outright;
// --use-compress-program/-I may only name a plain compressor binary
// (gzip/bzip2/xz/zstd/lz4). A bare `tar` with no verb fails closed.
func screenTarWrite(args []string, base string) string {
	verb := byte(0) // t / x / c / r / u / d (delete) / 0 none
	sawStdout := false
	sawHelp := false
	firstOperand := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" || a == "--to-stdout":
			sawStdout = true
		case a == "--help" || a == "--version" || a == "--usage":
			sawHelp = true
		case a == "--list" || a == "--diff" || a == "--compare" || a == "--show":
			if verb == 0 {
				verb = 't'
			}
		case a == "--extract" || a == "--get":
			if verb == 0 {
				verb = 'x'
			}
		case a == "--create":
			verb = 'c'
		case a == "--append":
			verb = 'r'
		case a == "--update":
			verb = 'u'
		case a == "--delete":
			return base + " --delete"
		case a == "--concatenate" || a == "--catenate":
			verb = 'c'
		case a == "--checkpoint-action":
			if i+1 < len(args) {
				v := args[i+1]
				if strings.HasPrefix(v, "exec") {
					return base + " --checkpoint-action=exec"
				}
				i++
			}
		case strings.HasPrefix(a, "--checkpoint-action="):
			if strings.HasPrefix(a[len("--checkpoint-action="):], "exec") {
				return base + " --checkpoint-action=exec"
			}
		case a == "--to-command":
			return base + " --to-command"
		case strings.HasPrefix(a, "--to-command="):
			return base + " --to-command"
		case a == "--use-compress-program" || a == "-I":
			if i+1 < len(args) {
				if !tarCompressorSafe(args[i+1]) {
					return base + " " + a
				}
				i++
			}
		case strings.HasPrefix(a, "--use-compress-program="):
			if !tarCompressorSafe(a[len("--use-compress-program="):]) {
				return base + " --use-compress-program"
			}
		case strings.HasPrefix(a, "-I") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			if !tarCompressorSafe(a[2:]) {
				return base + " -I"
			}
		case strings.HasPrefix(a, "--"):
			// Other long options: skip a separate value operand when the
			// option takes one.
			if !strings.ContainsRune(a, '=') && tarLongTakesValue(a) && i+1 < len(args) {
				i++
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// Short-option cluster: letters with operands consume the rest of
			// the cluster or the next argv.
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 't':
					if verb == 0 {
						verb = 't'
					}
				case 'x':
					if verb == 0 {
						verb = 'x'
					}
				case 'c':
					verb = 'c'
				case 'r':
					verb = 'r'
				case 'u':
					verb = 'u'
				case 'O':
					sawStdout = true
				case 'f', 'C', 'T', 'X', 'b', 'k', 'K', 'N', 'W', 'g', 'F', 'L', 'P', 'S', 'U', 'V':
					// Operand-bearing letters (approximate GNU set): consume the
					// rest of the cluster or the next argv.
					if j+1 >= len(a) && i+1 < len(args) {
						i++
					}
					j = len(a)
				}
			}
		default:
			if firstOperand == "" {
				firstOperand = a // BSD flag-less bundle (cf / xf / czf ...)
			}
		}
	}
	if firstOperand != "" && verb == 0 {
		for k := 0; k < len(firstOperand); k++ {
			switch firstOperand[k] {
			case 't':
				verb = 't'
			case 'x':
				verb = 'x'
			case 'c':
				verb = 'c'
			case 'r':
				verb = 'r'
			case 'u':
				verb = 'u'
			case 'O':
				sawStdout = true
			}
		}
	}
	switch {
	case sawHelp:
		return ""
	case verb == 't':
		return ""
	case verb == 'x':
		if sawStdout {
			return ""
		}
		return base + " -x"
	case verb == 'c':
		return base + " -c"
	case verb == 'r':
		return base + " -r"
	case verb == 'u':
		return base + " -u"
	default:
		return base // bare tar / no verb: fail closed
	}
}

// tarCompressorSafe reports whether a --use-compress-program / -I value
// names a plain compressor binary (and nothing else): a bare name on PATH
// or an absolute/relative path whose base is a known compressor, with no
// extra arguments.
func tarCompressorSafe(v string) bool {
	switch filepath.Base(strings.TrimSpace(v)) {
	case "gzip", "bzip2", "xz", "zstd", "lz4":
		return !strings.ContainsAny(v, " \t")
	}
	return false
}

// tarLongTakesValue reports whether a GNU tar long option consumes a separate
// operand (used to skip its value when scanning).
func tarLongTakesValue(a string) bool {
	switch a {
	case "--file", "--directory", "--files-from", "--exclude", "--include",
		"--transform", "--format", "--checkpoint-action", "--newer",
		"--after-date", "--occurrence", "--index-file", "--use-compress-program",
		"--owner", "--group", "--mode", "--mtime", "--sort", "--quoting-style":
		return true
	}
	return false
}

// screenUnzipWrite allows only query spellings of unzip for strict roles:
// -l/-t/-p/-v/-Z/-h/--help/--version. Extraction (default, -d, -o, -f, -u)
// writes. A `w` in a bundled flag cluster is zipinfo's verbose mode and is
// not a query on its own.
func screenUnzipWrite(args []string) string {
	sawQuery := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-d" || a == "--dir" {
			i++ // -d exdir: consume the dir operand
			continue
		}
		if !strings.HasPrefix(a, "-") {
			continue // zipfile / member operands
		}
		if strings.HasPrefix(a, "--") {
			if a == "--help" || a == "--version" {
				sawQuery = true
			}
			continue
		}
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 'l', 't', 'p', 'v', 'Z', 'h', 'c':
				sawQuery = true // -c pipes the member to stdout: read-only
			case 'o', 'f', 'u', 'n':
				// overwrite-policy flags: extraction still writes
				return "unzip " + a
			}
		}
	}
	if sawQuery {
		return ""
	}
	// No explicit read verb: unzip's default action extracts to disk.
	return "unzip"
}

// screenCompressWrite allows only stream/query spellings of compressors
// for strict roles: --stdout/--to-stdout/-c (stdout), --list/-l, --test/-t,
// --version/-V, --license/-L, --help/-h. Every other spelling REWRITES the
// operand file in place — including -d (decompress in place) and
// -n/--no-name (compress without name metadata): both block.
func screenCompressWrite(args []string, base string) string {
	sawSafe := false
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--stdout", "--to-stdout", "--list", "--test", "--version",
				"--help", "--license":
				sawSafe = true
			}
			continue
		}
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 'c', 'l', 't', 'V', 'L', 'h':
				sawSafe = true
			}
		}
	}
	if sawSafe {
		return ""
	}
	return base
}

// screenSedScriptWrite scans sed's script arguments (inline -e payloads and
// the first positional operand) for `w`/`W` write-file commands and GNU
// `e` exec commands: `s///w file` flags, address-followed `w file`/`W file`
// commands, bare `e cmd`, and `s///e`. `-f`/`--file` hands sed an unvetted
// script FILE and blocks outright for strict read-only. Comparison text
// (`/word/p`, `s/a/word/`) must not trip the screen.
func screenSedScriptWrite(args []string) string {
	scripts, sawFile := sedScripts(args)
	if sawFile {
		return "sed -f" // unvetted script file
	}
	for _, s := range scripts {
		if hit := sedScriptHasWrite(s); hit != "" {
			return hit
		}
		if len(sedExecCommands(s)) > 0 {
			return "sed e"
		}
	}
	return ""
}

// sedScriptHasWrite parses sed command text for w/W write commands. It is a
// shallow scanner: comments (#...), addresses (/re/, $, N, N,M, \$), s///
// with its w flag, and the bare w/W commands are recognized; text inside
// pattern space (a/c/i commands, regex bodies) is skipped.
func sedScriptHasWrite(s string) string {
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		switch {
		case c == '#':
			for i < n && s[i] != '\n' && s[i] != ';' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\n' || c == ';':
			i++
		case c == '/':
			// Regex address: skip to the unquoted closing /, tracking [...].
			i++
			for i < n {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if s[i] == '[' {
					// Character class: delimiters inside [...] are literal.
					i++
					if i < n && s[i] == '^' {
						i++
					}
					if i < n && s[i] == ']' { // ] as first (data) char is literal
						i++
					}
					for i < n && s[i] != ']' {
						if s[i] == '\\' {
							if i+1 < n {
								i += 2
							} else {
								i = n
							}
							continue
						}
						i++
					}
					if i < n {
						i++ // closing ]
					}
					continue
				}
				if s[i] == '/' {
					i++
					// GNU sed allows I/M (and i/m) regex flags after the close.
					for i < n && (s[i] == 'I' || s[i] == 'M' || s[i] == 'i' || s[i] == 'm') {
						i++
					}
					break
				}
				i++
			}
		case c == '$' || c >= '0' && c <= '9' || c == '~' || c == '+' || c == ',':
			i++ // address components
		case c == '!':
			i++ // address negation: 1!w / /pat/!w
		case c == '\\':
			// Custom-delimiter regex address \c...c (e.g. \|root|w).
			if i+1 >= n {
				i = n
				break
			}
			delim := s[i+1]
			i += 2
			for i < n {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if s[i] == '[' {
					// Character class: delimiters inside [...] are literal.
					i++
					if i < n && s[i] == '^' {
						i++
					}
					if i < n && s[i] == ']' { // ] as first (data) char is literal
						i++
					}
					for i < n && s[i] != ']' {
						if s[i] == '\\' {
							if i+1 < n {
								i += 2
							} else {
								i = n
							}
							continue
						}
						i++
					}
					if i < n {
						i++ // closing ]
					}
					continue
				}
				if s[i] == delim {
					i++
					// GNU sed allows I/M (and i/m) regex flags after the close.
					for i < n && (s[i] == 'I' || s[i] == 'M' || s[i] == 'i' || s[i] == 'm') {
						i++
					}
					break
				}
				i++
			}
		case c == 's':
			// s<delim><pat><delim><repl><delim><flags>
			i++
			if i >= n {
				break
			}
			delim := s[i]
			i++
			for part := 0; part < 2 && i < n; part++ {
				for i < n && s[i] != delim {
					if s[i] == '\\' {
						if i+1 < n {
							i += 2
						} else {
							i = n
						}
						continue
					}
					i++
				}
				if i >= n {
					break // truncated: no closing delimiter
				}
				i++ // consume the delim
			}
			// Flags: n N g p w. A `w` or `W` flag followed by a filename writes.
			for i < n {
				fc := s[i]
				if fc == 'w' || fc == 'W' {
					return "sed s///w"
				}
				if fc == ' ' || fc == '\t' || fc == ';' || fc == '\n' {
					break
				}
				if fc >= 'a' && fc <= 'z' || fc >= 'A' && fc <= 'Z' || fc >= '0' && fc <= '9' {
					i++
					continue
				}
				break
			}
		case c == 'w' || c == 'W':
			// Bare w/W command: `w file` / `W file`.
			return "sed " + string(c)
		case c == 'r' || c == 'R':
			// r/R read a file (input, not a write) — still not a write; skip the
			// filename operand.
			i++
			for i < n && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			for i < n && s[i] != ';' && s[i] != '\n' {
				i++
			}
		case c == '{':
			i++ // command group: keep scanning the contents
		case c == '}':
			i++
		default:
			// Any other command letter: skip the rest of the command to the
			// next ;/newline — some (a/i/c) carry free text that must not be
			// re-scanned for w.
			i++
			for i < n && s[i] != ';' && s[i] != '\n' {
				i++
			}
		}
	}
	return ""
}

// screenAwkProgram extracts awk's program text (every -e/--source
// fragment joined, or the first positional operand) and blocks constructs
// that write: `system(`, cmd pipes via `getline`, and print/printf output
// redirection `>` `>>` inside the program. `-f`/`--file` in any spelling
// (separate, =glued, or cluster tail) is an unvetted script file and
// blocks.
func screenAwkProgram(args []string) string {
	program, sawFile, _ := awkProgramFrags(args)
	if sawFile {
		return "awk -f" // unvetted program file
	}
	if program == "" {
		return ""
	}
	return awkProgramWrite(program)
}

// awkProgramWrite scans awk program text for write escapes: `system(`, a
// command piped into `getline` ("cmd" | getline, getline < "cmd"), and
// print/printf output redirections `>` / `>>`. Comparisons like `$1 > 5`
// and regexes like /a|b/ must not trip it. The inPrintStmt flag is
// statement-scoped: `)` inside `print (x) > f` no longer cancels the
// statement, while a top-level `;`, `{` or `}` does.
func awkProgramWrite(prog string) string {
	// Scan for `system (` calls, `>`/`>>` after print/printf, and
	// `| getline` / `getline <`. The system check runs on the lexer path
	// (identifier boundary + openParenAfter) so `system  (` and
	// `system\t(` hit while a regex literal like /system\(/ cannot trip it.
	i := 0
	n := len(prog)
	inStr := byte(0)
	inRegex := false
	inPrintStmt := false    // inside a print/printf statement (resets at ; \n { })
	prevWasOperand := false // last token was $/literal/)/number (division vs regex)
	parenDepth := 0
	for i < n {
		c := prog[i]
		switch {
		case inStr != 0:
			if c == '\\' {
				i++
			} else if c == inStr {
				inStr = 0
			}
		case inRegex:
			if c == '\\' {
				i++
			} else if c == '/' {
				inRegex = false
			}
		case c == '"' || c == '\'':
			inStr = c
			prevWasOperand = true
		case c == '/':
			// '/' after an operand is division; after an operator/open it is
			// a regex literal (whose body may contain `|`/`>`).
			if !prevWasOperand {
				inRegex = true
			} else {
				prevWasOperand = false
			}
		case c == '|':
			prevWasOperand = false
			// `cmd | getline` — a command feeding getline is a spawn+read.
			rest := strings.TrimLeft(prog[i+1:], " \t")
			if strings.HasPrefix(rest, "getline") {
				return "awk | getline"
			}
			// `print x | "cmd"` writes to a command pipe — also an escape.
			if inPrintStmt {
				return "awk print | cmd"
			}
		case c == '>':
			if inPrintStmt {
				return "awk print >"
			}
			prevWasOperand = false
		case c == '<':
			prevWasOperand = false
		case c == '(' || c == '[':
			parenDepth++
			prevWasOperand = false
		case c == ')' || c == ']':
			if parenDepth > 0 {
				parenDepth--
			}
			prevWasOperand = true // a closed group is a value (print (x))
		case c == '{':
			if parenDepth == 0 {
				inPrintStmt = false
			}
			prevWasOperand = false
		case c == '}':
			if parenDepth == 0 {
				inPrintStmt = false
			}
			prevWasOperand = false
		case c == ';' || c == '\n':
			if parenDepth == 0 {
				inPrintStmt = false
			}
			prevWasOperand = false
		case c == ' ' || c == '\t':
			// keep both flags across whitespace
		case c == '$' || c >= '0' && c <= '9':
			prevWasOperand = true
		default:
			// Track whether the current word is print/printf.
			j := i
			for j < n && isIdentByte(prog[j]) {
				j++
			}
			if j == i {
				prevWasOperand = false
				i++
				continue
			}
			w := prog[i:j]
			if w == "print" || w == "printf" {
				inPrintStmt = true
			}
			if w == "system" && openParenAfter(prog, j) >= 0 {
				return "awk system("
			}
			// Any word counts as an operand for the division-vs-regex heuristic.
			prevWasOperand = true
			i = j
			continue
		}
		i++
	}
	return ""
}

// pythonModuleArgvFrom returns the program argv `python … -m MOD [args…]`
// actually executes ([MOD, args…]) or nil when the argv has no -m operand.
// The glued `-mMOD` spelling is expanded back into its own word.
func pythonModuleArgvFrom(argv []string) []string {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-m":
			if i+1 < len(argv) {
				return argv[i+1:]
			}
			return nil
		case strings.HasPrefix(a, "-m") && len(a) > 2:
			return append([]string{a[2:]}, argv[i+1:]...)
		case a == "-W" || a == "-X":
			i++ // value-bearing option
		case !strings.HasPrefix(a, "-") || a == "-":
			return nil // script-file operand ends the option run
		}
	}
	return nil
}

// pythonModuleHit screens `python[3] [flags] -m <mod> [args]` for a strict
// read-only caller: the module name resolves through sys.path, so `-m`
// default-allowing an arbitrary module (http.server, compileall, venv, a
// local evil_mod) means default-allowing arbitrary code and writes. Only a
// pure `--help`/`-h` query and the side-effect-free text filters of
// pythonSafeModules with no output file stay free; anything else — and any
// module the caller cannot name statically — blocks. hasModule is false when
// the argv carries no `-m`, leaving the caller to the interpreter-head model.
func pythonModuleHit(args []string) (hit string, hasModule bool) {
	mod, rest := "", []string(nil)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-m":
			if i+1 >= len(args) {
				return "python -m <missing>", true
			}
			mod, rest = args[i+1], args[i+2:]
			i = len(args)
		case strings.HasPrefix(a, "-m") && len(a) > 2:
			mod, rest = a[2:], args[i+1:]
			i = len(args)
		case a == "-W" || a == "-X":
			i++ // value-bearing options
		case strings.HasPrefix(a, "-W") || strings.HasPrefix(a, "-X"):
			// glued value (-Wmodule, -Xutf8): no extra operand
		case strings.HasPrefix(a, "-") && a != "-":
			// other interpreter flags (-q, -O, -B, -u, …)
		default:
			return "", false // a script-file operand before -m ends the option run
		}
	}
	if mod == "" {
		return "", false // no -m on this invocation
	}
	hasModule = true
	if isDynamicArg(mod) {
		return "python -m <dynamic>", true // module name generated at run time
	}
	// `--` ends options; positionals after it still count (outfile path).
	switch {
	case allQueryArgs(rest):
		return "", true // `python -m x --help`
	case pythonSafeModules[mod] && !moduleWritesOutput(rest):
		return "", true // pure stdin→stdout text filter
	}
	// Everything else RUNS the module — with no operands at all in the
	// common case (`python -m venv`, `python -m http.server`, a local
	// `python -m evil_mod`), which is exactly when default-allowing would be
	// wrong.
	return "python -m " + mod, true
}

// allQueryArgs reports whether a module/tool option run is nothing but the
// help query (`--help`, `-h`, in any repetition): the program prints its
// usage and exits without touching the filesystem.
func allQueryArgs(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		if a != "--help" && a != "-h" {
			return false
		}
	}
	return true
}

// pythonSafeModules are `python -m` modules that read stdin/an input file
// and write ONLY stdout: no side effects a strict read-only role must not
// take. Any spelling that names an output file (-o/--out/--inplace) blocks.
var pythonSafeModules = map[string]bool{
	"json.tool": true,
}

// moduleWritesOutput reports whether a `python -m` module run carries an
// output-file flag OR a second positional output path. json.tool takes
// `[infile [outfile]]` — two positionals overwrite outfile. After `--`,
// every operand is positional (`python -m json.tool -- -o` is infile "-o").
func moduleWritesOutput(args []string) bool {
	pos := 0
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if endOpts {
			pos++
			if pos > 1 {
				return true
			}
			continue
		}
		switch {
		case a == "--":
			endOpts = true
		case a == "-o" || a == "--out" || a == "--output" || a == "--outfile" || a == "-O" || a == "--inplace" || a == "--in-place":
			return true
		case strings.HasPrefix(a, "--out="), strings.HasPrefix(a, "--output="), strings.HasPrefix(a, "--outfile="):
			return true
		case strings.HasPrefix(a, "-o") && len(a) > 2 && a != "-o":
			return true
		case a == "--indent":
			if i+1 < len(args) {
				i++
			}
		case strings.HasPrefix(a, "--indent="):
			// glued
		case strings.HasPrefix(a, "-") && a != "-":
			// other module flags
		default:
			pos++
			if pos > 1 {
				return true
			}
		}
	}
	return false
}

// screenShellFileRun decides a bare shell invocation (no -c payload): -n
// (syntax check, no execution) and version/help spellings stay free — but
// ONLY before the first non-option script operand (`bash script.sh -n`
// runs the script). Anything else runs a script file or reads stdin and
// blocks.
func screenShellFileRun(args []string, base string) string {
	for _, a := range args {
		if a == "-n" || a == "--version" || a == "--help" || a == "-V" {
			return ""
		}
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			break // script-file operand reached: trailing flags are its args
		}
	}
	return base
}

// interpSyntaxCheckFlags are the per-interpreter "parse, do not execute"
// option spellings that stay free for strict read-only roles: node
// --check/-c, perl -c, ruby -c, php -l (php -l consumes no value here —
// screenInterpFileRun only reaches this table when unwrapInterpreterInline
// already ruled out inline code, so a bare php -c is php's -l-free ini
// option and still blocks through the default path).
var interpSyntaxCheckFlags = map[string][]string{
	"sh": {"-n"}, "bash": {"-n"}, "dash": {"-n"}, "zsh": {"-n"},
	"ksh": {"-n"}, "mksh": {"-n"}, "ash": {"-n"},
	"node": {"--check", "-c"}, "nodejs": {"--check", "-c"},
	"perl": {"-c"}, "ruby": {"-c"}, "php": {"-l"},
}

// screenInterpFileRun decides a bare interpreter invocation with no inline
// code: --version/-V/--help/-h spellings and the `-` stdin marker (whose
// program stream is screened via the heredoc/stdin payload paths) stay
// free, but ONLY while still in the option run — a flag after the first
// non-option script operand is an argument to the script
// (`python3 app.py --help` RUNS app.py and must block). Pure syntax-check
// spellings (node --check, perl -c, php -l) stay free too. Anything else
// runs a script file and blocks for strict read-only.
func screenInterpFileRun(args []string, base string) string {
	syntaxFlags := interpSyntaxCheckFlags[base]
	for _, a := range args {
		switch a {
		case "-", "--version", "-V", "-VV", "--help", "-h":
			return ""
		}
		for _, f := range syntaxFlags {
			if a == f {
				return ""
			}
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			break // script operand reached: later flags belong to the script
		}
	}
	return base
}

// ---------- end additional head screens ----------

// guardArgvReadonly screens one argv for the strict read-only write guard.
// A `shell -c` argv is redirected to the shell-text screener.
func guardArgvReadonly(argv []string) string {
	return peelResolvedDepth(argv, 'r', 0, currentCallerIdentity())
}

// guardShellReadonly screens shell command text for the strict read-only
// write guard: every segment's head goes through screenReadonlyWrite, and a
// file-writing redirection blocks the segment.
func guardShellReadonly(code string) string {
	return guardShellReadonlyDepth(code, 0, currentCallerIdentity())
}
func guardShellReadonlyDepth(code string, depth int, caller callerIdentity) string {
	if depth >= peelChainMaxDepth {
		return depthExceededHit
	}
	roSegs, hit := parseReadonlyShellSegments(code)
	if hit != "" {
		return readonlyBlockWithHint(allowlistDetail(hit))
	}
	for _, ro := range roSegs {
		seg := shellSegment{
			argv:         ro.argv,
			pipedStdin:   ro.pipedStdin,
			heredocText:  ro.heredocText,
			redirectFile: ro.redirectFile,
		}
		if h := screenOneSegmentDepth(seg, 'r', depth, caller); h != "" {
			return h
		}
	}
	return ""
}

// skipBalancedParens matches nested parentheses ignoring string/shell quoting.
// Used only by non-shell code scanners (Python/JS callInnerBounds).
func skipBalancedParens(s string, open int) int {
	if open < 0 || open >= len(s) || s[open] != '(' {
		return open
	}
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

// callInnerBounds returns the [lo,hi) byte span of the parenthesized
// argument list whose '(' sits at openIdx in s (s[openIdx] must be '(').
// It validates openIdx and returns closed=false when no matching ')' exists
// so callers can fail closed instead of slicing out of bounds.
func callInnerBounds(s string, openIdx int) (lo, hi int, closed bool) {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != '(' {
		return len(s), len(s), false
	}
	end := skipBalancedParens(s, openIdx)
	if end > len(s) || end == 0 || s[end-1] != ')' {
		return openIdx + 1, len(s), false
	}
	return openIdx + 1, end - 1, true
}

// pythonMask produces a Python lexical mask: '#' comments and the bodies of
// '...'/"..."/”'...”'/"""...""" literals are blanked to spaces, EXCEPT
// the {...} expression slices inside f-strings (which are real code) —
// those keep their bytes. Quotes and prefixes stay readable so identifier
// scans see structure without being fooled by string text.
func pythonMask(code string) string {
	b := []byte(code)
	n := len(b)
	i := 0
	blank := func(lo, hi int) {
		for k := lo; k < hi && k < n; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	for i < n {
		c := b[i]
		switch {
		case c == '#':
			for i < n && b[i] != '\n' {
				b[i] = ' '
				i++
			}
		case c == '\'' || c == '"':
			// Detect the literal kind: triple or single, and whether an
			// f-prefix immediately precedes it.
			triple := i+2 < n && b[i+1] == c && b[i+2] == c
			fstr := i > 0 && (b[i-1] == 'f' || b[i-1] == 'F')
			if i > 1 && (b[i-1] == 'f' || b[i-1] == 'F') && (b[i-2] == 'r' || b[i-2] == 'R' || b[i-2] == 'b' || b[i-2] == 'B') {
				fstr = true // rf"" / bf"" / fr""
			}
			if i > 1 && (b[i-1] == 'r' || b[i-1] == 'R') && (b[i-2] == 'f' || b[i-2] == 'F') {
				fstr = true
			}
			bodyStart := i + 1
			var bodyEnd int
			if triple {
				bodyStart = i + 3
				j := bodyStart
				for j+2 < n && !(b[j] == c && b[j+1] == c && b[j+2] == c) {
					if b[j] == '\\' {
						j++
					}
					j++
				}
				// An unterminated literal (or one whose closer sits at the very
				// end, or a trailing lone backslash) walks j to/over the end.
				// bodyEnd is a BLANK bound indexed by the f-string slice loop
				// below (b[k] for k < bodyEnd), so it must stay inside the
				// buffer.
				bodyEnd = minInt(j, n)
				i = minInt(j+3, n)
			} else {
				j := bodyStart
				for j < n && b[j] != c && b[j] != '\n' {
					if b[j] == '\\' {
						j++ // skip the escaped byte — may step past the end
					}
					j++
				}
				bodyEnd = minInt(j, n)
				i = minInt(j+1, n)
			}
			if fstr {
				// Blank the string body EXCEPT {...} expression slices: those
				// are evaluated code (f"{open('/tmp/x','w')}" must still hit).
				k := bodyStart
				segStart := k
				depth := 0
				for k < bodyEnd {
					switch b[k] {
					case '{':
						if depth == 0 {
							blank(segStart, k)
						}
						depth++
					case '}':
						if depth > 0 {
							depth--
						}
						if depth == 0 {
							segStart = k + 1
						}
					}
					k++
				}
				blank(segStart, bodyEnd)
			} else {
				blank(bodyStart, bodyEnd)
			}
		default:
			i++
		}
	}
	return string(b)
}

// jsMask produces a JS/TS lexical mask: // and /* */ comments and the
// bodies of '...'/"..." literals are blanked; template literals `...`
// blank except ${...} expression slices (real code kept).
// jsScanExpr advances i through a JS expression until braceDepth reaches 0,
// counting nested { }, skipping string/template contents so braces inside
// them do not affect depth. i starts just after `${` with braceDepth 1;
// the return value is the index just past the closing `}`.
func jsScanExpr(b []byte, i, end, braceDepth int) int {
	blank := func(lo, hi int) {
		if hi > end {
			hi = end
		}
		if hi > len(b) {
			hi = len(b)
		}
		for k := lo; k < hi; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	prevOperand := false
	for i < end && braceDepth > 0 {
		switch b[i] {
		case '\\':
			i++
			if i < end {
				i++
			}
			prevOperand = true
		case '/':
			if i+1 < end && b[i+1] == '/' {
				// Line comment: blank through newline; '}' here must not close.
				lo := i
				for i < end && b[i] != '\n' {
					i++
				}
				blank(lo, i)
				prevOperand = false
				continue
			}
			if i+1 < end && b[i+1] == '*' {
				lo := i
				i += 2
				for i+1 < end && !(b[i] == '*' && b[i+1] == '/') {
					i++
				}
				if i+1 < end {
					i += 2
				} else {
					i = end
				}
				blank(lo, i)
				prevOperand = false
				continue
			}
			if !prevOperand {
				// Regex literal: skip body so /}/ does not close the expression.
				i++
				for i < end {
					if b[i] == '\\' {
						i++
						if i < end {
							i++
						}
						continue
					}
					if b[i] == '/' {
						i++
						break
					}
					if b[i] == '\n' {
						break
					}
					i++
				}
				// optional regex flags
				for i < end && ((b[i] >= 'a' && b[i] <= 'z') || (b[i] >= 'A' && b[i] <= 'Z')) {
					i++
				}
				prevOperand = true
				continue
			}
			// Division operator.
			i++
			prevOperand = false
		case '\'', '"':
			q := b[i]
			lo := i
			i++
			for i < end && b[i] != q {
				if b[i] == '\n' {
					break
				}
				if b[i] == '\\' {
					i++
					if i >= end {
						break
					}
				}
				i++
			}
			if i < end && b[i] == q {
				i++
			}
			blank(lo, i)
			prevOperand = true
		case '`':
			// Nested template: blank static text; recurse into ${...}.
			i++
			seg := i
			for i < end {
				if b[i] == '\\' {
					i++
					if i < end {
						i++
					}
					continue
				}
				if b[i] == '`' {
					blank(seg, i)
					i++
					break
				}
				if b[i] == '$' && i+1 < end && b[i+1] == '{' {
					blank(seg, i)
					i = jsScanExpr(b, i+2, end, 1)
					seg = i
					continue
				}
				i++
			}
			prevOperand = true
		case '{':
			braceDepth++
			i++
			prevOperand = false
		case '}':
			braceDepth--
			i++
			prevOperand = true
		case ' ', '\t', '\n', '\r':
			i++
			// whitespace does not change prevOperand
		case ')', ']', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			prevOperand = true
			i++
		default:
			if (b[i] >= 'a' && b[i] <= 'z') || (b[i] >= 'A' && b[i] <= 'Z') || b[i] == '_' || b[i] == '$' {
				for i < end && (isIdentByte(b[i]) || b[i] == '$') {
					i++
				}
				prevOperand = true
				continue
			}
			prevOperand = false
			i++
		}
	}
	if i > end {
		i = end
	}
	return i
}

func jsMask(code string) string {
	b := []byte(code)
	n := len(b)
	i := 0
	blank := func(lo, hi int) {
		for k := lo; k < hi && k < n; k++ {
			if b[k] != '\n' {
				b[k] = ' '
			}
		}
	}
	for i < n {
		c := b[i]
		switch {
		case c == '/' && i+1 < n && b[i+1] == '/':
			for i < n && b[i] != '\n' {
				b[i] = ' '
				i++
			}
		case c == '/' && i+1 < n && b[i+1] == '*':
			b[i] = ' '
			b[i+1] = ' '
			i += 2
			for i+1 < n && !(b[i] == '*' && b[i+1] == '/') {
				if b[i] != '\n' {
					b[i] = ' '
				}
				i++
			}
			if i+1 < n {
				b[i] = ' '
				b[i+1] = ' '
				i += 2
			}
		case c == '\'' || c == '"':
			j := i + 1
			for j < n && b[j] != c && b[j] != '\n' {
				if b[j] == '\\' {
					j++
				}
				j++
			}
			blank(i+1, j)
			i = j + 1
			if i > n {
				i = n
			}
		case c == '`':
			// Template literal: walk character-by-character (no pre-scan to
			// the next backtick — nested templates and backtick-bearing
			// strings live inside ${...} and must not truncate the body).
			i++
			segStart := i
			for i < n {
				if b[i] == '\\' {
					i++
					if i < n {
						i++
					}
					continue
				}
				if b[i] == '`' {
					blank(segStart, i)
					i++
					break
				}
				if b[i] == '$' && i+1 < n && b[i+1] == '{' {
					blank(segStart, i)
					i = jsScanExpr(b, i+2, n, 1)
					segStart = i
					continue
				}
				i++
			}
			if i >= n {
				blank(segStart, n)
			}
		default:
			i++
		}
	}
	return string(b)
}

// normCallSpace returns a copy of s where whitespace between an
// identifier-end and a following '(' is collapsed to nothing
// (`open ('x')` -> `open('x')`, `system ('pig')` -> `system('pig')`) so
// spacing cannot smuggle a call past the primitive tables. Iterating a
// byte copy keeps indexes aligned with the original text.
func normCallSpace(s string) string {
	b := []byte(s)
	w := 0
	for i := 0; i < len(b); i++ {
		c := b[i]
		if (c == ' ' || c == '\t') && w > 0 && isIdentByte(b[w-1]) {
			// Look ahead: does a '(' follow the whitespace run?
			j := i
			for j < len(b) && (b[j] == ' ' || b[j] == '\t') {
				j++
			}
			if j < len(b) && b[j] == '(' {
				i = j - 1 // drop the whitespace run
				continue
			}
		}
		b[w] = c
		w++
	}
	return string(b[:w])
}

// codeSpawnPrims are tokens indicating a subprocess-spawning primitive in any
// supported language. For the sub-agent guard they must co-occur with a
// blocked agent name or a herdr/herdsman mutation verb; for strict read-only
// their presence alone blocks (a read-only role has no need to fork external
// commands from inside an interpreter).
var codeSpawnPrims = []string{
	"subprocess", "os.system", "os.popen", "os.exec", "os.spawn",
	"pty.spawn", "child_process", "execSync", "spawnSync", "execFile",
	"spawnFile",
	"Deno.Command", "Bun.spawn", "os/exec", "exec.Command",
	"syscall.Exec", "syscall.ForkExec", "std::process::Command",
	"shell_exec", "proc_open", "passthru", "Kernel.system", "Open3",
	"Process.spawn", "popen(", "Runtime.exec", "ProcessBuilder",
	"system(", "backticks", "IO.popen", "spawn(", "pcntl_exec",
	// Bare exec-family / spawn-lv spawn entry points (os.execv*,
	// os.spawnl*/os.spawnv* reached through dynamic attribute access).
	"execv(", "execve(", "execl(", "execle(", "execlp(", "execvp(",
	"execvpe(", "spawnl", "spawnv",
	// Dynamic import / native-code / eval escape hatches: each one can
	// re-enter a process or execute arbitrary code.
	"__import__", "importlib", "ctypes", "cffi",
	"eval(", "exec(", "Function(",
	"process.binding", "process.dlopen",
	"System.cmd", "Port.open", "system2(",
}

// codeAgentNames are the blocked nested-agent identifiers inside code.
// Derived from the same list as blockedAgentExecutables so argv and code
// screens stay aligned.
// ssh stays in codeAgentNames so Python/JS dynamic subprocess.run("ssh ...")
// remains fail-closed even though shell/argv ssh is peeled via screenSSHHead.
var codeAgentNames = append(append([]string(nil), blockedAgentExecutableList...), "ssh")

// codeWritePrims are file write/delete/mutate primitives for strict
// read-only, matched with identifier-boundary edges. Call sites that take a
// mode argument (open/os.open) are handled separately to keep plain reads
// free.
var codeWritePrims = []string{
	// Python (open()/os.open() modes are handled in pythonWriteModeHit)
	".write_text(", ".write_bytes(",
	"os.remove(", "os.unlink(", "os.rmdir(", "os.removedirs(",
	"os.rename(", "os.replace(", "os.mkdir(", "os.makedirs(",
	"os.chmod(", "os.chown(", "os.symlink(", "os.link(", "os.truncate(",
	"shutil.rmtree(", "shutil.move(", "shutil.copy", "shutil.copytree(",
	".unlink(", ".rmdir(", ".mkdir(", ".rename(", ".touch(",
	".symlink_to(", ".hardlink_to(",
	"tempfile.NamedTemporaryFile", "tempfile.mkstemp", "tempfile.mkdtemp",
	// JS/TS (fs.readFile*/readdir stay free by absence)
	"writeFile", "appendFile", "unlinkSync", "rmSync", "rmdirSync",
	"mkdirSync", "mkdtemp", "renameSync", "copyFile", "cpSync",
	"truncateSync", "createWriteStream", "Deno.write", "Bun.write",
	".unlink(", ".rm(", ".rmdir(", ".mkdir(", ".rename(", ".copyFile(",
	// Go / Rust / PHP / Ruby
	"os.WriteFile", "os.Create", "os.OpenFile", "os.Remove", "os.RemoveAll",
	"os.Mkdir", "os.MkdirAll", "os.Chmod", "os.Rename", "os.Symlink",
	"std::fs::write", "std::fs::remove", "std::fs::create_dir",
	"File::create", "file_put_contents", "FileUtils.",
	"File.delete", "File.binwrite", "IO.binwrite", "Dir.rmdir",
	"unlink(", "rename(", "mkdir(", "rmdir(",
	// shelve.open defaults to flag='c' — read-write, creating the shelf.
	"shelve.open",
}

// codeCompileToDiskLangs are runtime languages whose invocation always writes
// build artifacts; strict read-only roles may not run them at all.
var codeCompileToDiskLangs = map[string]bool{
	"go": true, "rust": true, "csharp": true,
}

// guardCtxRunCode screens non-shell interpreter code. For the sub-agent guard
// it blocks code that both spawns processes AND names a blocked agent or a
// herdr/herdsman mutation. For strict read-only it blocks spawn primitives,
// file-write primitives, and compile-to-disk languages outright.

// codeHasAgentCmdWord reports whether name appears as a shell-style command
// word inside a string literal of code (start of string or after a shell
// metacharacter/whitespace, with a non-identifier boundary after it). Used
// for short false-positive-prone names like "at"/"su" that must not match
// comments, prose ("failed at line 3"), or property calls (arr.at(-1)).
func codeHasAgentCmdWord(code, name string) bool {
	n := len(code)
	i := 0
	for i < n {
		c := code[i]
		switch {
		case c == '#' && (i == 0 || code[i-1] == '\n' || code[i-1] == ' ' || code[i-1] == '\t' || code[i-1] == ';'):
			// Python/shell line comment — skip (JS // handled below).
			for i < n && code[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && code[i+1] == '/':
			i += 2
			for i < n && code[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && code[i+1] == '*':
			i += 2
			for i+1 < n && !(code[i] == '*' && code[i+1] == '/') {
				i++
			}
			if i+1 < n {
				i += 2
			}
		case c == '\'' || c == '"' || c == '`':
			q := c
			i++
			start := i
			for i < n && code[i] != q {
				if code[i] == '\\' {
					i++
				}
				if i < n {
					i++
				}
			}
			lit := code[start:i]
			if stringHasCmdWord(lit, name) {
				return true
			}
			if i < n {
				i++ // closing quote
			}
		default:
			i++
		}
	}
	return false
}

// stringHasCmdWord reports whether name is the first token of a shell
// command segment inside s (start of string or after ;|&\\n(), not mid-prose
// like "failed at line 3" and not a ".at" property access).
func stringHasCmdWord(s, name string) bool {
	atCmd := true
	i := 0
	n := len(s)
	for i < n {
		for i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') {
			i++
		}
		if i >= n {
			break
		}
		if atCmd {
			if strings.HasPrefix(s[i:], name) {
				end := i + len(name)
				if end >= n || !isIdentByte(s[end]) {
					return true
				}
			}
			atCmd = false
		}
		c := s[i]
		switch c {
		case ';', '|', '&', '\n', '(', ')':
			atCmd = true
			i++
		default:
			// Skip the rest of this token.
			for i < n && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' &&
				s[i] != ';' && s[i] != '|' && s[i] != '&' && s[i] != '(' && s[i] != ')' {
				i++
			}
			for i < n && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
		}
	}
	return false
}
func (g guardCall) guardCtxRunCode(language, code string) (rule, detail string) {
	if !g.subagent && !g.strictReadonly {
		return "", "" // main agent: no role guard runs at all
	}
	masked := code
	switch language {
	case "python":
		masked = pythonMask(code)
	case "javascript", "typescript":
		masked = jsMask(code)
	}
	toks := codeTokens(normCallSpace(masked))
	caller := g.callerIdentity()

	// Sub-agent nested-dispatch screening runs BEFORE the blanket strict
	// read-only spawn block on static spawns so `subprocess.run(['ssh','dmit','pig'])`
	// and `subprocess.run(['pig'])` report ruleSubagentNestedAgent first,
	// matching guardCtxRunArgv and guardCtxRunShell.
	if g.subagent {
		rawToks := codeTokens(code)
		spawn := false
		for _, prim := range codeSpawnPrims {
			if toks.hasTokenLike(prim) {
				spawn = true
				break
			}
		}
		if !spawn && langHasBacktickSpawn(language) && codeHasBacktickOrQx(code) {
			spawn = true
		}
		if !spawn && (language == "perl" || language == "ruby" || language == "php") {
			spawn = scriptingLexicalSpawnHit(language, code) != ""
		}
		// Computed member access (`cp['exec'+'Sync'](…)`) defeats the
		// masked-token scan — the brackets hide `execSync` — so the raw
		// (unmasked) presence of the child_process module identifier
		// counts as a spawn site too.
		if !spawn && (language == "javascript" || language == "typescript") &&
			rawToks.hasIdent("child_process") {
			spawn = true
		}
		if spawn {
			argvs, shellCmds, allResolved := codeStaticSpawnsDetailed(language, code)
			for _, argv := range argvs {
				// peelResolvedDepth routes ssh (and wrapped ssh like
				// ['env','ssh','dmit','pig']) through screenSSHHead /
				// parseSSHInvocation so remote commands inherit caller guards.
				if hit := peelResolvedDepth(argv, 's', 0, caller); hit != "" {
					if hit == "ctxmode index" || hit == roSSHWriteHit {
						return ruleReadonlyWrite, hit
					}
					return ruleSubagentNestedAgent, hit
				}
				if _, isProg, _ := stdinProgramHeadWithEnv(argv, 0, envAssignments{}, caller.pathEnv); isProg {
					if g.readonly && !g.strictReadonly && sshTunnelsStdinProgram(argv, caller.pathEnv) {
						return ruleReadonlyWrite, roSSHWriteHit
					}
					allResolved = false
				}
			}
			if len(shellCmds) > 0 {
				for _, cmd := range shellCmds {
					if hit := guardShellSubagentDepth(cmd, 0, caller); hit != "" {
						if hit == "ctxmode index" || hit == roSSHWriteHit {
							return ruleReadonlyWrite, hit
						}
						return ruleSubagentNestedAgent, hit
					}
				}
			}
			if !allResolved {
				for _, name := range codeAgentNames {
					if name == "at" || name == "su" {
						if codeHasAgentCmdWord(code, name) {
							return ruleSubagentNestedAgent, "code spawns " + name
						}
						continue
					}
					if rawToks.hasIdent(name) {
						return ruleSubagentNestedAgent, "code spawns " + name
					}
				}
				// A dynamic spawn site cannot prove a herdr/herdsman/hc argv is
				// on the read-only whitelist, so the mere presence of the
				// orchestrator name fails closed — the same rule
				// programNamesBlockedAgent applies to dynamic awk commands.
				if rawToks.hasIdent("herdr") {
					return ruleSubagentNestedAgent, "code drives herdr mutation"
				}
				if rawToks.hasIdent("herdsman") {
					return ruleSubagentNestedAgent, "code drives herdsman mutation"
				}
				if rawToks.hasIdent("hc") {
					return ruleSubagentNestedAgent, "code drives hc mutation"
				}
			}
		}
	}

	if g.strictReadonly {
		if codeCompileToDiskLangs[language] {
			return ruleReadonlyWrite, language + " compiles to disk"
		}
		for _, argv := range codeStaticSpawns(language, code) {
			if len(argv) == 0 {
				continue
			}
			if hit := screenReadonlyWrite(argv); hit != "" {
				return ruleReadonlyWrite, hit
			}
			return ruleReadonlyWrite, "spawn primitive " + filepath.Base(argv[0])
		}
		for _, prim := range codeSpawnPrims {
			if toks.hasTokenLike(prim) {
				return ruleReadonlyWrite, "spawn primitive " + prim
			}
		}
		if langHasBacktickSpawn(language) && codeHasBacktickOrQx(code) {
			return ruleReadonlyWrite, "backtick/qx spawn"
		}
		if language == "perl" || language == "ruby" || language == "php" {
			if hit := scriptingLexicalSpawnHit(language, code); hit != "" {
				return ruleReadonlyWrite, "spawn primitive " + hit
			}
			if hit := scriptingWritePrimHit(language, code); hit != "" {
				return ruleReadonlyWrite, hit
			}
		}
		if language == "python" {
			if hit := pythonWriteModeHit(code); hit != "" {
				return ruleReadonlyWrite, hit
			}
			// `f = open` rebinds the builtin so the call-site scan never
			// sees `open(`: an `open` IDENTIFIER in the masked code without
			// any `open(` call fails closed (string literals are masked, so
			// `print("open('/tmp/x','w')")` stays free).
			if toks.hasIdent("open") && !toks.hasTokenLike("open(") {
				return ruleReadonlyWrite, "write primitive open"
			}
		}
		if (language == "javascript" || language == "typescript") &&
			codeTokens(code).hasIdent("child_process") {
			return ruleReadonlyWrite, "spawn primitive child_process"
		}
		if language == "javascript" || language == "typescript" {
			if hit := jsFsOpenWriteHit(code); hit != "" {
				return ruleReadonlyWrite, hit
			}
		}
		for _, prim := range codeWritePrims {
			if toks.hasTokenLike(prim) {
				return ruleReadonlyWrite, "write primitive " + prim
			}
		}
		if language == "python" || language == "javascript" || language == "typescript" {
			if singleArgDotReplace(normCallSpace(masked)) {
				return ruleReadonlyWrite, "write primitive .replace("
			}
		}
	}
	return "", ""
}

// codeSpawnKeywords are the primitive spellings whose call arguments carry
// the command to run. The lookup walks the rest of the dotted attribute path
// (callOpenAfter), so `subprocess` reaches `subprocess.run/.Popen`,
// `child_process` reaches `require('child_process').execFileSync`, and
// `os.exec` reaches `os.execvp`. `subprocess` and `child_process` are also
// MODULE roots: import/require alias bindings (`import subprocess as sp`,
// `const cp = require('child_process')`) add the bound name to the scan, and
// any non-call use of a module root (`getattr(subprocess, 'run')`,
// `f = subprocess.run`) is an unresolved spawn-capability escape.
//
// What the operand MEANS decides the screen: a literal list is an argv and is
// screened at the command position; a string operand is a command line the
// interpreter hands to a shell (os.system, subprocess.run("a | b"),
// execSync) and is screened as shell text.
var codeSpawnKeywords = map[string][]string{
	"python": {
		"subprocess", // subprocess.run / .Popen / .call / .check_output
		"os.system", "os.popen", "os.exec", "os.spawn", "pty.spawn",
		"system", "popen",
		"execv", "execve", "execl", "execle", "execlp", "execvp", "execvpe",
		"spawnl", "spawnv",
	},
	"javascript": {
		"child_process", // require('child_process').execFileSync / .execSync
		"execSync", "spawnSync", "execFileSync", "spawnFileSync", "execFile",
		"spawn", "Bun.spawn", "Bun.spawnSync", "Deno.Command",
	},
}

// codeSpawnNonCallNeutral are the loose bare-word keywords whose non-call
// occurrences stay INERT: they exist to catch `from os import system`-style
// calls, and a plain mention (`system = platform.system()`) is too common a
// word to count as a spawn-capability escape. Module roots (subprocess,
// child_process) and every import/require bound name are NOT neutral — a
// non-call use of those fails closed.
var codeSpawnNonCallNeutral = map[string]bool{
	"system": true, "popen": true,
	"execv": true, "execve": true, "execl": true, "execle": true,
	"execlp": true, "execvp": true, "execvpe": true,
	"spawnl": true, "spawnv": true,
}

// codeSpawnBindings is what the import/require scan learned about a code
// body: which names alias a spawn module or function, which token spans are
// inert binding declarations, and whether a spawn-bearing binding resisted
// parsing (`from subprocess import *`, `require(<dynamic>)`).
type codeSpawnBindings struct {
	names      map[string]string // bound name → "subprocess"|"os"|"pty"|"child_process"|"fn"
	accounted  map[int]int       // token start → end for inert declaration occurrences
	unresolved bool              // a spawn-bearing binding resisted static parsing
}

// staticSpawnArgv reads the command of a spawn call's argument text (raw +
// byte-aligned mask): either a literal list/tuple of string literals, an
// execFile/execv (file, argv) pair, an execl/spawnl variadic literal list,
// or a plain string command.

// isAccounted reports whether the keyword occurrence spanning [start,end)
// is one of the parsed binding declarations rather than a live use.
func (b codeSpawnBindings) isAccounted(start, end int) bool {
	e, ok := b.accounted[start]
	return ok && e == end
}

// isFromImportAccounted reports whether the occurrence [start,end) sits at
// the tail of an accounted dotted module path — `x.run` in
// `from x.run import y` accounts [from-start, run-end), so the `run` token
// at start is a declaration byte, not a live spawn name.
func isFromImportAccounted(start, end int, accounted map[int]int) bool {
	for a, b := range accounted {
		if a < start && b == end {
			return true
		}
	}
	return false
}

// identEndAt returns the index just past the identifier starting at i.
func identEndAt(s string, i int) int {
	for i < len(s) && isIdentByte(s[i]) {
		i++
	}
	return i
}

// pythonSpawnSym reports whether a name imported FROM subprocess/os/pty is a
// spawn-capable function (run, Popen, call, check_*, getoutput,
// getstatusoutput, system, popen, exec*, spawn*).
func pythonSpawnSym(name string) bool {
	switch name {
	case "run", "Popen", "call", "check_call", "check_output",
		"getoutput", "getstatusoutput", "system", "popen":
		return true
	}
	return strings.HasPrefix(name, "exec") || strings.HasPrefix(name, "spawn")
}

// jsSpawnFunc reports whether a child_process member name is spawn-capable.
func jsSpawnFunc(name string) bool {
	switch name {
	case "exec", "execSync", "execFile", "execFileSync", "spawn",
		"spawnSync", "spawnFileSync", "fork", "execv", "execvSync":
		return true
	}
	return false
}

// pythonSpawnBindings parses `import ...` / `from ... import ...` statements
// in python code for bindings of the spawn modules subprocess/os/pty and
// their spawn functions. Input is the byte-aligned lexical mask (strings and
// comments already blank), so only real code is seen. `from subprocess
// import *` or a starred name marks the code unresolved: the scanner cannot
// enumerate the names it bound.
func pythonSpawnBindings(masked string) codeSpawnBindings {
	out := codeSpawnBindings{names: map[string]string{}, accounted: map[int]int{}}
	for off := 0; ; {
		p := indexIdent(masked, "import", off)
		if p < 0 {
			break
		}
		off = p + len("import")
		// Skip the `import` that belongs to a `from X import` statement: it
		// is always preceded by the module path (an ident byte or '.').
		j := p - 1
		for j >= 0 && (masked[j] == ' ' || masked[j] == '\t') {
			j--
		}
		if j >= 0 && (isIdentByte(masked[j]) || masked[j] == '.') {
			continue
		}
		pythonParseImportList(masked, p+len("import"), &out)
	}
	for off := 0; ; {
		p := indexIdent(masked, "from", off)
		if p < 0 {
			break
		}
		off = p + len("from")
		pythonParseFromImport(masked, p+len("from"), &out)
	}
	return out
}

// pythonParseImportList parses the name list after a plain `import`:
// `import a.b [as x], c [as y]`, possibly line-continued. For tracked first
// segments (subprocess/os/pty) the bound alias becomes a module binding; the
// declaration tokens are marked accounted either way.
func pythonParseImportList(masked string, pos int, out *codeSpawnBindings) {
	n := len(masked)
	i := pos
	depth := 0
	for i < n {
		for i < n && (masked[i] == ' ' || masked[i] == '\t' || (depth > 0 && masked[i] == '\n')) {
			i++
		}
		if i >= n {
			return
		}
		c := masked[i]
		switch {
		case c == '\n' || c == ';':
			return
		case c == '\\':
			i += 2 // line continuation
			continue
		case c == '(' || c == '[':
			depth++
			i++
			continue
		case isIdentByte(c):
			j := i
			for j < n && (isIdentByte(masked[j]) || masked[j] == '.') {
				j++
			}
			name := masked[i:j]
			seg := name
			if k := strings.IndexByte(name, '.'); k >= 0 {
				seg = name[:k]
			}
			out.accounted[i] = j
			i = j
			for i < n && (masked[i] == ' ' || masked[i] == '\t') {
				i++
			}
			k := identEndAt(masked, i)
			if masked[i:k] == "as" {
				i = k
				for i < n && (masked[i] == ' ' || masked[i] == '\t') {
					i++
				}
				a := i
				i = identEndAt(masked, i)
				out.accounted[a] = i
				if seg == "subprocess" || seg == "os" || seg == "pty" {
					out.names[masked[a:i]] = seg
				}
			}
			for i < n && (masked[i] == ' ' || masked[i] == '\t' || (depth > 0 && masked[i] == '\n')) {
				i++
			}
			if i < n && masked[i] == ',' {
				i++
				continue
			}
			return
		default:
			return
		}
	}
}

// pythonParseFromImport parses `from <module> import <names>`: the imported
// name list (comma-separated, optionally parenthesized across lines) is
// walked element by element. Only tracked modules (subprocess/os/pty) bind
// spawn names; `*` or an unparseable element of a tracked module marks the
// code unresolved.
func pythonParseFromImport(masked string, pos int, out *codeSpawnBindings) {
	n := len(masked)
	i := pos
	for i < n && (masked[i] == ' ' || masked[i] == '\t') {
		i++
	}
	ms := i
	for i < n && (isIdentByte(masked[i]) || masked[i] == '.') {
		i++
	}
	me := i
	mod := masked[ms:me]
	seg := mod
	if k := strings.LastIndex(mod, "."); k >= 0 {
		seg = mod[k+1:]
	}
	tracked := seg == "subprocess" || seg == "os" || seg == "pty"
	for i < n && (masked[i] == ' ' || masked[i] == '\t') {
		i++
	}
	j := identEndAt(masked, i)
	if masked[i:j] != "import" {
		return // not an import statement (e.g. `yield from x`)
	}
	i = j
	if !tracked {
		return
	}
	out.accounted[ms] = me
	depth := 0
	for i < n {
		for i < n && (masked[i] == ' ' || masked[i] == '\t' || (depth > 0 && masked[i] == '\n')) {
			i++
		}
		if i >= n {
			return
		}
		c := masked[i]
		switch {
		case c == '\n' || c == ';':
			return
		case c == '\\':
			i += 2
			continue
		case c == '(':
			depth++
			i++
			continue
		case c == ')':
			if depth > 0 {
				depth--
			}
			i++
			continue
		case c == '*':
			out.unresolved = true // `from subprocess import *`
			i++
			continue
		case isIdentByte(c):
			j := identEndAt(masked, i)
			name := masked[i:j]
			out.accounted[i] = j
			i = j
			for i < n && (masked[i] == ' ' || masked[i] == '\t') {
				i++
			}
			k := identEndAt(masked, i)
			if masked[i:k] == "as" {
				i = k
				for i < n && (masked[i] == ' ' || masked[i] == '\t') {
					i++
				}
				a := i
				i = identEndAt(masked, i)
				out.accounted[a] = i
				if pythonSpawnSym(name) {
					out.names[masked[a:i]] = "fn"
				}
			} else if pythonSpawnSym(name) {
				out.names[name] = "fn"
			}
			for i < n && (masked[i] == ' ' || masked[i] == '\t' || (depth > 0 && masked[i] == '\n')) {
				i++
			}
			if i < n && masked[i] == ',' {
				i++
				continue
			}
			return
		default:
			return
		}
	}
}

// jsSpawnBindings parses JS/TS child_process bindings: `require(
// 'child_process')` / `require('node:child_process')` assigned to a name or
// destructured, and ES `import ... from 'child_process'` clauses. Input is
// the byte-aligned mask; literals are read back from the raw code.
func jsSpawnBindings(code, masked string) codeSpawnBindings {
	out := codeSpawnBindings{names: map[string]string{}, accounted: map[int]int{}}
	for off := 0; ; {
		p := indexIdent(masked, "require", off)
		if p < 0 {
			break
		}
		off = p + len("require")
		jsScanRequire(code, masked, p, &out)
	}
	for off := 0; ; {
		p := indexIdent(masked, "import", off)
		if p < 0 {
			break
		}
		off = p + len("import")
		jsScanImport(code, masked, p, &out)
	}
	return out
}

// jsScanRequire inspects one `require(...)` call site at pos. A literal
// child_process argument either leads to a dotted member call (the member
// name is then screened by the normal keyword pass), or must be bound on
// the same statement (`const cp = require(...)`, `const {execSync: x} =
// require(...)`); a module object that escapes into an arbitrary expression
// is unresolved.
func jsScanRequire(code, masked string, pos int, out *codeSpawnBindings) {
	open := openParenAfter(masked, pos+len("require"))
	if open < 0 {
		return
	}
	lo, hi, closed := callInnerBounds(masked, open)
	if !closed {
		return
	}
	argStart := lo
	for argStart < hi && (masked[argStart] == ' ' || masked[argStart] == '\t' || masked[argStart] == '\n') {
		argStart++
	}
	lit, rest, ok := leadingStringLiteral(code[argStart:hi])
	if !ok || strings.TrimSpace(rest) != "" {
		out.unresolved = true // require(<dynamic>) may load child_process
		return
	}
	if lit != "child_process" && lit != "node:child_process" {
		return // a different module entirely
	}
	// `require('child_process').execSync(...)`: the member call is screened
	// by the normal keyword pass, including the uncalled-member escape
	// (`f = require('child_process').execSync` fails closed there).
	if _, chained := kwChainEnd(masked, hi+1); chained {
		return
	}
	// Otherwise the module object must be bound by `<target> = require(...)`.
	j := pos - 1
	for j >= 0 && (masked[j] == ' ' || masked[j] == '\t' || masked[j] == '\n') {
		j--
	}
	if j < 0 || masked[j] != '=' {
		out.unresolved = true // module object escapes into an expression
		return
	}
	k := j - 1
	for k >= 0 && (masked[k] == ' ' || masked[k] == '\t' || masked[k] == '\n') {
		k--
	}
	if k < 0 {
		return
	}
	if masked[k] == '}' {
		bopen := matchBackward(masked, k, '{', '}')
		if bopen < 0 {
			out.unresolved = true
			return
		}
		jsBindDestructure(masked, bopen+1, k, out)
		return
	}
	if !isIdentByte(masked[k]) {
		out.unresolved = true
		return
	}
	ke := k + 1
	for k >= 0 && isIdentByte(masked[k]) {
		k--
	}
	nameStart := k + 1
	// A member target (`global.cp = require(...)`) escapes the binding model.
	p := nameStart - 1
	for p >= 0 && (masked[p] == ' ' || masked[p] == '\t') {
		p--
	}
	if p >= 0 && masked[p] == '.' {
		out.unresolved = true
		return
	}
	out.accounted[nameStart] = ke
	out.names[masked[nameStart:ke]] = "child_process"
}

// kwChainEnd walks a keyword continuation tail (`.member`/`.member(...)`,
// `[...]`, `(...)`) starting at pos, skipping whitespace, and returns the
// offset just past the tail plus whether any non-whitespace chain step was
// consumed. It exists for jsScanRequire: `require('x').m(...)`,
// `require('x')['m']`, and `require('x')(...)` all keep the require inside
// a member/call chain, so no module-object binding is required.
func kwChainEnd(s string, pos int) (end int, chained bool) {
	for pos < len(s) {
		switch s[pos] {
		case ' ', '\t', '\n':
			pos++
		case '.', '[':
			chained = true
			i := pos + 1
			for i < len(s) && s[i] != '.' && s[i] != '(' && s[i] != '[' && s[i] != ')' && s[i] != ';' && s[i] != '\n' {
				i++
			}
			if i < len(s) && s[i] == '(' {
				_, hi, closed := callInnerBounds(s, i)
				if !closed {
					return len(s), chained
				}
				pos = hi + 1
			} else {
				pos = i
			}
		case '(':
			chained = true
			_, hi, closed := callInnerBounds(s, pos)
			if !closed {
				return len(s), chained
			}
			pos = hi + 1
		default:
			return pos, chained
		}
	}
	return pos, chained
}

// jsScanImport inspects one `import` site: a dynamic `import(
// 'child_process')` hands the module to a promise (unresolved), a bare
// `import 'x'` binds nothing, and `import <clause> from 'child_process'`
// binds the clause names.
func jsScanImport(code, masked string, pos int, out *codeSpawnBindings) {
	n := len(masked)
	i := pos + len("import")
	for i < n && (masked[i] == ' ' || masked[i] == '\t') {
		i++
	}
	if i >= n {
		return
	}
	c := masked[i]
	if c == '(' {
		lo, hi, closed := callInnerBounds(masked, i)
		if !closed {
			return
		}
		argStart := lo
		for argStart < hi && (masked[argStart] == ' ' || masked[argStart] == '\t' || masked[argStart] == '\n') {
			argStart++
		}
		lit, rest, ok := leadingStringLiteral(code[argStart:hi])
		if ok && strings.TrimSpace(rest) == "" &&
			(lit == "child_process" || lit == "node:child_process") {
			out.unresolved = true
		}
		return
	}
	if c == '\'' || c == '"' {
		return // bare `import 'x'`: nothing is bound
	}
	clauseStart := i
	fromPos := -1
	for j := i; j < n; {
		if masked[j] == ';' {
			break
		}
		if isIdentByte(masked[j]) {
			je := identEndAt(masked, j)
			if masked[j:je] == "from" {
				fromPos = j
				break
			}
			j = je
			continue
		}
		j++
	}
	if fromPos < 0 {
		return
	}
	i = fromPos + len("from")
	for i < n && (masked[i] == ' ' || masked[i] == '\t') {
		i++
	}
	if i >= n || (masked[i] != '\'' && masked[i] != '"') {
		return
	}
	lit, _, ok := leadingStringLiteral(code[i:])
	if !ok || (lit != "child_process" && lit != "node:child_process") {
		return
	}
	jsBindImportClause(masked, clauseStart, fromPos, out)
}

// jsBindImportClause binds the names of an ES import clause: a default name
// or `* as name` binds the module root, `{...}` destructures spawn function
// names. An unparseable element marks the code unresolved.
func jsBindImportClause(masked string, lo, hi int, out *codeSpawnBindings) {
	i := lo
	for i < hi {
		for i < hi && (masked[i] == ' ' || masked[i] == '\t' || masked[i] == '\n' || masked[i] == ',') {
			i++
		}
		if i >= hi {
			return
		}
		c := masked[i]
		switch {
		case c == '{':
			end := matchingBracket(masked[i:hi], '{', '}')
			if end < 0 {
				out.unresolved = true
				return
			}
			jsBindDestructure(masked, i+1, i+end, out)
			i += end + 1
		case c == '*':
			i++
			for i < hi && (masked[i] == ' ' || masked[i] == '\t') {
				i++
			}
			j := identEndAt(masked, i)
			if masked[i:j] != "as" {
				out.unresolved = true
				return
			}
			i = j
			for i < hi && (masked[i] == ' ' || masked[i] == '\t') {
				i++
			}
			a := i
			i = identEndAt(masked, i)
			out.accounted[a] = i
			out.names[masked[a:i]] = "child_process"
		case isIdentByte(c):
			j := identEndAt(masked, i)
			out.accounted[i] = j
			out.names[masked[i:j]] = "child_process" // default import: module root
			i = j
		default:
			out.unresolved = true
			return
		}
	}
}

// jsBindDestructure binds the entries of a `{a, b: c}` destructure of
// child_process (require or ES import): `name` / `name: alias` bind the
// alias (or the name itself) to a spawn function when the member is
// spawn-capable; `...rest` or unparseable elements mark the code unresolved.
func jsBindDestructure(masked string, lo, hi int, out *codeSpawnBindings) {
	i := lo
	for i < hi {
		for i < hi && (masked[i] == ' ' || masked[i] == '\t' || masked[i] == '\n' || masked[i] == ',') {
			i++
		}
		if i >= hi {
			return
		}
		if masked[i] == '.' || !isIdentByte(masked[i]) {
			out.unresolved = true // `...rest` or a computed key
			return
		}
		j := identEndAt(masked, i)
		sym := masked[i:j]
		out.accounted[i] = j
		i = j
		for i < hi && (masked[i] == ' ' || masked[i] == '\t') {
			i++
		}
		alias := ""
		if i < hi && masked[i] == ':' {
			i++
			for i < hi && (masked[i] == ' ' || masked[i] == '\t') {
				i++
			}
			a := i
			i = identEndAt(masked, i)
			alias = masked[a:i]
			out.accounted[a] = i
		} else if k := identEndAt(masked, i); masked[i:k] == "as" {
			// ES import clause spelling: `{execSync as run}`.
			i = k
			for i < hi && (masked[i] == ' ' || masked[i] == '\t') {
				i++
			}
			a := i
			i = identEndAt(masked, i)
			alias = masked[a:i]
			out.accounted[a] = i
		}
		for i < hi && masked[i] != ',' { // skip an optional `= default`
			i++
		}
		bind := alias
		if bind == "" {
			bind = sym
		}
		if jsSpawnFunc(sym) {
			out.names[bind] = "fn"
		}
	}
}

// matchBackward finds the index of the bracket opening the one at closeIdx
// (s[closeIdx] == close), honouring nested brackets and string literals, or
// -1 when unbalanced. String bodies in a lexical mask are already blank, so
// a lone quote byte toggles symmetrically in either direction.
func matchBackward(s string, closeIdx int, open, close byte) int {
	depth := 0
	inStr := byte(0)
	for i := closeIdx; i >= 0; i-- {
		c := s[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case close:
			depth++
		case open:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// callOpenAfter finds the '(' of the call a primitive identifier takes part
// in, walking the REST of the dotted identifier run: `subprocess.run`,
// `child_process.execFileSync` and `os.execvp` all lead to one. It stops at
// the first byte that cannot continue a call expression, so a primitive that
// is merely named (never called) cannot reach across the statement into
// someone else's parentheses.
func callOpenAfter(s string, from int) int {
	for i := from; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '(':
			return i
		case isIdentByte(c), c == '.', c == ' ', c == '\t':
			// still inside the dotted attribute path
		default:
			return -1
		}
	}
	return -1
}

// codeStaticSpawns extracts the command argv of every statically readable
// spawn call. It is the argv-only view of codeStaticSpawnsDetailed for the
// strict read-only path, which blocks on the extracted command head.
func codeStaticSpawns(language, code string) [][]string {
	argvs, _, _ := codeStaticSpawnsDetailed(language, code)
	return argvs
}

// codeStaticSpawnsDetailed extracts the command argv (or shell command text)
// of every spawn call whose command words are statically readable in python
// / JS code — including import/require alias bindings:
//
//	subprocess.run(['herdsman', 'daemon', 'start'])          → [herdsman daemon start]
//	import subprocess as sp; sp.run(['herdr', 'pane', 'list']) → [herdr pane list]
//	from subprocess import run as r; r(['echo', 'ok'])       → [echo ok]
//	const cp = require('child_process'); cp.execSync('ls')   → [ls]
//	child_process.execFileSync('git', ['log', '-1'])         → [git log -1]
//	os.system("ls")                                          → [ls]
//	os.system("cat f | grep x")                              → shell text
//
// A call is extracted only when its RECEIVER is spawn-bearing: the dotted
// path left of the function name must be a spawn module (subprocess,
// os/pty member chains, require('child_process')) or a bound module alias
// — otherwise a bound fn name is checked as a bare call only. This keeps
// `platform.system()`, `os.path.join('system', 'x')`, and
// `m.execSync('ls')` on an arbitrary receiver out of the spawn set.
//
// allResolved reports whether EVERY spawn-capable site in the code was
// statically accounted for: it is true only when at least one call was
// resolved AND no spawn site resisted static reading. A site counts as
// unresolved when
//   - a primitive/alias is called with a non-literal command (a variable, an
//     f-string, a template literal, a concatenation — `subprocess.run(cmd)`),
//   - a call opener never closes (`subprocess.run(` at EOF),
//   - `from subprocess|os|pty import *`, a dynamic `require(...)`/
//     `import(...)`, or a child_process module object escapes into an
//     expression the binding model cannot follow, or
//   - a module root or bound spawn name is used WITHOUT being its parsed
//     declaration or a call site (`getattr(subprocess, 'run')`,
//     `f = subprocess.run`, `x = cp.execSync`).
//
// The caller uses allResolved to decide whether the conservative
// co-occurrence fallback still applies: one resolved argv must NOT let an
// adjacent dynamic spawn slip through.
func codeStaticSpawnsDetailed(language, code string) (argvs [][]string, shellCmds []string, allResolved bool) {
	var keywords []string
	var masked string
	var binds codeSpawnBindings
	switch language {
	case "python":
		keywords = codeSpawnKeywords["python"]
		masked = pythonMask(code)
		binds = pythonSpawnBindings(masked)
	case "javascript", "typescript":
		keywords = codeSpawnKeywords["javascript"]
		masked = jsMask(code)
		binds = jsSpawnBindings(code, masked)
	default:
		return nil, nil, false
	}
	keywords = append([]string{}, keywords...)
	moduleRoots := map[string]bool{"subprocess": true, "child_process": true}
	for name, kind := range binds.names {
		switch kind {
		case "subprocess", "child_process":
			keywords = append(keywords, name)
			moduleRoots[name] = true
		case "os":
			keywords = append(keywords,
				name+".system", name+".popen", name+".exec", name+".spawn")
		case "pty":
			keywords = append(keywords, name+".spawn")
		default: // "fn": a bound spawn function name
			keywords = append(keywords, name)
		}
	}
	unresolved := binds.unresolved
	// One spawn CALL is reached by several keyword spellings at once
	// (`subprocess` and `run`, `o.system` and `system`, `cp.execSync` and
	// `execSync`): dedupe on the call-open offset so each site is resolved
	// exactly once.
	seenCalls := map[int]bool{}
	for _, kw := range keywords {
		bare := true
		if d := strings.IndexByte(kw, '.'); d >= 0 {
			bare = false
			if !strings.Contains(kw[d+1:], ".") {
				// `o.system`-shaped alias members: the receiver is the
				// module name before the dot — the bare `system` keyword
				// would double-count the call.
				continue
			}
		}
		for off := 0; ; {
			i := indexIdent(masked, kw, off)
			if i < 0 {
				break
			}
			off = i + len(kw)
			end := i + len(kw)
			if binds.isAccounted(i, end) || isFromImportAccounted(i, end, binds.accounted) {
				// A declaration token (`import subprocess`, the module path
				// of a from-import) never calls: `from subprocess import (`
				// must not be read as a subprocess( call.
				continue
			}
			open := callOpenAfter(masked, end)
			if open < 0 {
				// Named, not called: inert at its binding declaration,
				// or in a receiver position (`platform.system()`) —
				// every other use of a spawn-capable name is an
				// escape the argv model cannot follow.
				p := i - 1
				for p >= 0 && (masked[p] == ' ' || masked[p] == '\t') {
					p--
				}
				if p >= 0 && masked[p] == '.' {
					continue
				}
				_, bound := binds.names[kw]
				if bound || moduleRoots[kw] || !codeSpawnNonCallNeutral[kw] {
					unresolved = true
				}
				continue
			}
			if seenCalls[open] {
				continue
			}
			if bare {
				// A bare member name (`system`, `run`, `execSync`, a bound
				// fn alias) is a spawn call only when its receiver — the
				// dotted path left of it — is spawn-bearing. Receivers
				// that are already spawn keywords (subprocess, os/pty
				// member chains, require('child_process')) or bound
				// module names are already audited by their own keyword
				// pass; any other receiver means this is someone else's
				// method and the bare keyword is not a spawn site.
				p := i - 1
				for p >= 0 && (masked[p] == ' ' || masked[p] == '\t') {
					p--
				}
				if p >= 0 && masked[p] == '.' {
					// Ident-start tail (`.execSync` vs `[x].execSync`):
					// only a receiver IDENT can be a spawn module.
					q := p - 1
					for q >= 0 && (masked[q] == ' ' || masked[q] == '\t') {
						q--
					}
					if q >= 0 && isIdentByte(masked[q]) {
						re := q + 1
						for q >= 0 && (isIdentByte(masked[q]) || masked[q] == '.') {
							q--
						}
						rs := q + 1
						if !callReceiverIsSpawn(masked[rs:re], binds.names, keywords) {
							continue
						}
					}
				}
			}
			seenCalls[open] = true
			lo, hi, closed := callInnerBounds(masked, open)
			if !closed {
				unresolved = true
				continue
			}
			argv, shell, ok := staticSpawnArgv(code[lo:hi], masked[lo:hi])
			switch {
			case len(argv) > 0:
				argvs = append(argvs, argv)
			case shell != "":
				shellCmds = append(shellCmds, shell)
			case !ok:
				unresolved = true
			}
		}
	}
	return argvs, shellCmds, len(argvs)+len(shellCmds) > 0 && !unresolved
}

// callReceiverIsSpawn reports whether the dotted receiver path left of a
// bare member name is itself spawn-bearing: either a name the keyword scan
// already audits (spawn modules and their member chains like `os.exec`,
// `pty.spawn`, `Bun.spawn`, `Deno.Command`, bound module aliases) or the
// `require('child_process')` call-chain form. A receiver not in that set
// (`platform`, `os.path`, an arbitrary `m`) means the member call is
// someone else's method, not a spawn site the bare keyword must claim.
func callReceiverIsSpawn(receiver string, names map[string]string, keywords []string) bool {
	if receiver == "" {
		return false
	}
	seg := receiver
	if k := strings.LastIndexByte(seg, '.'); k >= 0 {
		seg = seg[k+1:]
	}
	// The receiver ident (or its last dotted segment) is spawn-bearing when
	// it IS one of the scan keywords (`subprocess`, `os.system` chains,
	// `Bun`, `Deno`, bound aliases) or prefixes one (`os`, `pty`, `Bun`,
	// `Deno` reach `os.exec`/`pty.spawn`/`Bun.spawn`/`Deno.Command`).
	for _, kw := range keywords {
		if seg == kw || strings.HasPrefix(kw, seg+".") {
			return true
		}
	}
	if _, bound := names[seg]; bound {
		return true
	}
	// `require('child_process')`-family receivers end in `require`.
	if seg == "require" {
		return true
	}
	return false
}
func staticSpawnArgv(raw, masked string) (argv []string, shell string, ok bool) {
	spans := splitCallArgsOffsets(masked)
	operands := make([]string, 0, len(spans))
	shellMode := false
	for _, sp := range spans {
		lo := minInt(sp[0], len(raw))
		hi := minInt(sp[1], len(raw))
		if hi <= lo {
			continue
		}
		if w := strings.TrimSpace(raw[lo:hi]); w != "" {
			if eq := strings.IndexByte(w, '='); eq > 0 && isIdentName(strings.TrimSpace(w[:eq])) {
				k := strings.TrimSpace(w[:eq])
				v := strings.TrimSpace(w[eq+1:])
				if k == "shell" && (v == "True" || v == "true" || v == "1") {
					shellMode = true
				}
			}
			operands = append(operands, w)
		}
	}
	if len(operands) == 0 {
		return nil, "", false
	}
	firstOp := operands[0]
	if eq := strings.IndexByte(firstOp, '='); eq > 0 {
		k := strings.TrimSpace(firstOp[:eq])
		if k == "args" || k == "cmd" || k == "command" {
			firstOp = strings.TrimSpace(firstOp[eq+1:])
		}
	}
	// os.spawnl*(mode, file, arg0, arg1, ...) / os.spawnv*(mode, file, argv):
	// skip a leading os.P_* mode constant when followed by a literal/list.
	startIdx := 0
	if len(operands) >= 2 && (strings.HasPrefix(firstOp, "os.P_") || firstOp == "0" || firstOp == "1") {
		startIdx = 1
		firstOp = operands[1]
	}
	// Literal argv list/tuple: `['herdsman', 'daemon', 'start']`.
	if listArgv, ok := staticArgvList(firstOp); ok {
		if shellMode || (len(listArgv) == 1 && strings.ContainsAny(listArgv[0], " \t'\"\\$`*|;&")) {
			return nil, strings.Join(listArgv, " "), true
		}
		return listArgv, "", true
	}
	lit, rest, ok := leadingStringLiteral(firstOp)
	if !ok || strings.TrimSpace(rest) != "" {
		return nil, "", false
	}
	if len(operands) > startIdx+1 {
		secondOp := operands[startIdx+1]
		if listArgv, ok := staticArgvList(secondOp); ok {
			// In Python os.execv*(file, argv) / os.spawnv*(mode, file, argv),
			// listArgv[0] is argv[0] (the program name itself, e.g. 'ssh'),
			// whereas in JS execFileSync('ssh', ['dmit', 'pig']) listArgv[0]
			// is the first argument after argv[0]. Deduplicate when listArgv[0]
			// repeats the executable name and has remaining arguments.
			if len(listArgv) >= 1 && filepath.Base(lit) == filepath.Base(listArgv[0]) {
				return append([]string{lit}, listArgv[1:]...), "", true
			}
			return append([]string{lit}, listArgv...), "", true
		}
		// Variadic literal string form: os.execl(path, arg0, arg1, ...) /
		// os.execlp(file, arg0, arg1, ...). Collect when every remaining
		// positional operand (except a trailing env dict) is a string literal.
		var varArgs []string
		allLit := true
		for idx := startIdx + 1; idx < len(operands); idx++ {
			op := operands[idx]
			if strings.Contains(op, "=") && !strings.HasPrefix(op, "'") && !strings.HasPrefix(op, "\"") {
				break
			}
			s, srest, sok := leadingStringLiteral(op)
			if !sok || strings.TrimSpace(srest) != "" {
				allLit = false
				break
			}
			varArgs = append(varArgs, s)
		}
		if allLit && len(varArgs) > 0 {
			if filepath.Base(lit) == filepath.Base(varArgs[0]) {
				return append([]string{lit}, varArgs[1:]...), "", true
			}
			return append([]string{lit}, varArgs...), "", true
		}
	}
	if strings.ContainsAny(lit, "'\"\\$`*|;&") {
		return nil, lit, true
	}
	return strings.Fields(lit), "", true
}

// staticArgvList parses a literal command list — `['echo', 'pig']` (python),
// `("echo", "pig")` (python tuple), `['echo', 'pig']` (JS array, including
// the `child_process.execFileSync` form where the array is argv and the
// program is the preceding string literal). It requires EVERY element to be
// a plain string literal: an f-string, a template literal, a nested
// substitution or a variable element makes the argv dynamic.
func staticArgvList(s string) ([]string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	open, close := byte(0), byte(0)
	switch s[0] {
	case '[':
		open, close = '[', ']'
	case '(':
		open, close = '(', ')'
	default:
		return nil, false
	}
	end := matchingBracket(s, open, close)
	if end < 0 {
		return nil, false
	}
	if strings.TrimSpace(s[end+1:]) != "" {
		return nil, false // trailing text: concatenation or call, not a plain list
	}
	var out []string
	for _, part := range splitTopLevelItems(s[1:end], open, close) {
		lit, rest, ok := leadingStringLiteral(strings.TrimSpace(part))
		if !ok || strings.TrimSpace(rest) != "" {
			return nil, false
		}
		out = append(out, lit)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// matchingBracket returns the index of the bracket closing the one at s[0],
// honouring nested brackets and string literals, or -1 when unbalanced.
func matchingBracket(s string, open, close byte) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if j := strings.IndexByte(s[i+1:], '\''); j >= 0 {
				i += j + 1
			}
		case '"':
			if j := strings.IndexByte(s[i+1:], '"'); j >= 0 {
				i += j + 1
			}
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// splitTopLevelItems splits the inside of a bracketed list on commas that
// sit at depth 0, skipping string literals.
func splitTopLevelItems(s string, open, close byte) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if j := strings.IndexByte(s[i+1:], '\''); j >= 0 {
				i += j + 1
			}
		case '"':
			if j := strings.IndexByte(s[i+1:], '"'); j >= 0 {
				i += j + 1
			}
		case open:
			depth++
		case close:
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	if strings.TrimSpace(s[start:]) != "" {
		out = append(out, s[start:])
	}
	return out
}

// interpCodeSlots walks argv's option zone with the interpreter's real
// option model and returns every inline-code operand slot. Two cluster
// models exist:
//
//   - GLUED model (python -c/-m, perl -eE, ruby -e, php -r): the option
//     letter's cluster tail IS the code/value (-eCODE, -cCODE).
//   - FLAG model (sh/bash/dash/... -c, node -e/-p): a cluster tail is never
//     code — `sh -ce code` is `-c -e`, `node -pe code` is `-p -e`. A
//     flag-model code letter sets a PENDING slot whose operand is the next
//     argv word AFTER the whole cluster's option scan finishes (a trailing
//     -o/-O in the tail may still consume a word first, e.g.
//     `bash -co vi 'code'`).
//
// A non-empty cluster tail after a flag-model code letter is ambiguous
// (ksh/zsh/node spell the glued operand there) so it is screened as code
// in addition to the pending argv operand — never silently ignored. A "--" or the first static non-option operand ends the
// zone; a bare "-" is the stdin-script operand, not a cluster.
type codeSlot struct {
	flag     int
	text     string
	flagOnly bool
}

func interpCodeSlots(argv []string) []codeSlot {
	if len(argv) < 2 {
		return nil
	}
	base := filepath.Base(argv[0])
	gluedCodes := ""               // cluster letters whose TAIL (or next argv) is code
	flagCodes := ""                // code flags: operand is the next argv AFTER the cluster scan
	valShort := ""                 // letters REQUIRING a value: glued tail, else the next argv
	optShort := ""                 // letters with an OPTIONAL glued value of ARBITRARY bytes: glued tail ends the cluster, a bare letter is a flag and consumes nothing
	optNumShort := ""              // letters with an OPTIONAL restricted NUMERIC glued value: after its legal tail the cluster keeps scanning — perl -0e is -0 -e, not -0 with value 'e'
	longCode := map[string]bool{}  // --name / --name=code
	longValue := map[string]bool{} // --name consumes a separate value
	dynScriptOperand := false      // a dynamic first operand is inline code (xargs feed / $X eval)
	switch {
	case base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3"):
		gluedCodes, valShort = "cm", "WX"
		dynScriptOperand = true
	case base == "node" || base == "nodejs":
		// node clusters are flag-parsed: -pe is -p -e and the code operand
		// is the next argv; -e/-p never glue their operand. -r takes a
		// module operand (tail or next argv).
		flagCodes, valShort = "ep", "r"
		longCode = map[string]bool{"--eval": true, "--print": true}
		longValue = map[string]bool{"--require": true, "--loader": true, "--import": true, "--experimental-loader": true, "--conditions": true}
		dynScriptOperand = true
	case base == "ts-node" || base == "tsx" || base == "bun":
		gluedCodes = "e"
		longCode = map[string]bool{"--eval": true}
		longValue = map[string]bool{"--require": true, "--loader": true, "--import": true}
		dynScriptOperand = true
	case base == "perl":
		// -M/-m/-I REQUIRE a module/dir operand (glued or next argv). The
		// optional-glued letters split in two: -i/-F/-x take an ARBITRARY
		// tail (backup extension, autosplit pattern, extract dir) that ends
		// the cluster, while -0/-l take a restricted NUMERIC tail — after
		// the digits (or -0's xHH hex) the cluster resumes, so `perl -0e
		// CODE` and `perl -le CODE` still see the -e (R15 handled the
		// bare-letter form; R16 covers the glued tail). -7 is not a real
		// perl option but stays optional-glued so a glued tail is consumed
		// conservatively.
		gluedCodes, valShort, optShort, optNumShort = "eE", "MmI", "iF7x", "l0"
		dynScriptOperand = true
	case base == "ruby":
		// Same split for ruby: -F/-K/-C/-X/-r/-I require operands (K eats
		// its single coding char); -i/-x take arbitrary optional-glued
		// tails while -0 is the restricted numeric kind (`ruby -0e CODE`
		// still reaches -e).
		gluedCodes, valShort, optShort, optNumShort = "e", "FKCXrI", "ix", "0"
		dynScriptOperand = true
	case base == "php":
		gluedCodes, valShort = "r", "cdz"
		dynScriptOperand = true
	case shellHeads[base]:
		// dash/bash/zsh/ksh flag-model -c; -o/-O consume an option-name
		// operand (cluster tail or next argv).
		flagCodes, valShort = "c", "oO"
	default:
		return nil
	}
	var out []codeSlot
	pendingCode := false // flag-model code letter seen; operand resolves after the cluster
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			break // option terminator
		}
		if strings.HasPrefix(a, "--") {
			if pendingCode {
				break // an option still cannot be -c's operand
			}
			name, val, hasVal := a[2:], "", false
			if k := strings.IndexByte(name, '='); k >= 0 {
				name, val, hasVal = name[:k], name[k+1:], true
			}
			if longCode["--"+name] {
				if hasVal {
					out = append(out, codeSlot{flag: i, text: val})
				} else if i+1 < len(argv) {
					out = append(out, codeSlot{flag: i, text: argv[i+1]})
					i++
				} else {
					out = append(out, codeSlot{flag: i, flagOnly: true})
				}
				continue
			}
			if longValue["--"+name] {
				if !hasVal {
					i++ // consumes the separate value operand
				}
			}
			continue // boolean or unknown long option
		}
		// A bare "-" is the stdin-script operand, not an option cluster.
		if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") || a == "-" || a == "+" {
			if pendingCode {
				// The pending flag-model code operand IS this word
				// (`sh -c code`, `node -pe code`): argv0/positional-name
				// words that follow are already covered — a second
				// non-option operand ends the zone.
				out = append(out, codeSlot{flag: i, text: a})
				pendingCode = false
				continue
			}
			if dynScriptOperand && isDynamicArg(a) {
				// SH11 MF-2: a split-safe path-shaped word is the script-file
				// operand, not inline code — end the option scan (Q1-C). Any
				// other dynamic word in operand position may BE the code text
				// (xargs replace-token / $X eval) — screen it.
				if isSafeDynamicDataOperand(a) &&
					(strings.Contains(a, "/") || strings.HasPrefix(a, "/") ||
						strings.HasPrefix(a, cmdSubPlaceholderAbsDq) || hasInterpScriptExt(a)) {
					break
				}
				out = append(out, codeSlot{flag: i, text: a})
				break
			}
			break // first non-option operand: the script file
		}
		plus := a[0] == '+'
		for j := 1; j < len(a); j++ {
			ch := a[j]
			if !plus && strings.IndexByte(gluedCodes, ch) >= 0 {
				if tail := a[j+1:]; tail != "" {
					out = append(out, codeSlot{flag: i, text: tail})
				} else if i+1 < len(argv) {
					out = append(out, codeSlot{flag: i, text: argv[i+1]})
					i++
				} else {
					out = append(out, codeSlot{flag: i, flagOnly: true})
				}
				break
			}
			if !plus && strings.IndexByte(flagCodes, ch) >= 0 {
				// Flag-model code letter: the operand is the next argv word
				// after the cluster scan. A non-empty tail is an ambiguous
				// glued spelling (ksh/zsh may read it as the operand —
				// `-cpig`) so it is ALSO screened as code while its letters
				// keep being parsed as flags (`-ce` needs the next argv too).
				pendingCode = true
				if tail := a[j+1:]; tail != "" {
					out = append(out, codeSlot{flag: i, text: tail})
					if !isLetterOnly(tail) {
						break // ambiguous glued operand — not flag letters
					}
				}
				continue
			}
			if strings.IndexByte(valShort, ch) >= 0 {
				if j+1 >= len(a) {
					i++ // value is the next argv
				}
				break // value letters end the cluster either way
			}
			if strings.IndexByte(optNumShort, ch) >= 0 {
				// Restricted numeric tail: consume its legal bytes, then RESUME
				// the cluster — `perl -0e` is -0 -e, so the e must not be eaten
				// as a value.
				j += consumeNumOptTail(a, j, ch)
				continue
			}
			if strings.IndexByte(optShort, ch) >= 0 {
				if j+1 >= len(a) {
					continue // bare optional-value flag — consumes no argv
				}
				break // glued value ends the cluster
			}
		}
	}
	if pendingCode {
		// A trailing flag-model code letter with no operand word: the fed
		// text lands here (xargs model) — mark the open slot.
		out = append(out, codeSlot{flag: len(argv) - 1, flagOnly: true})
	}
	return out
}

// consumeNumOptTail returns how many bytes after a[j] form the legal
// glued value of a restricted numeric optional flag (perl -0/-l, ruby
// -0): decimal digits, or an x/X marker plus hexadecimal digits for -0's
// hex spelling (-0x1be). The caller then resumes scanning the cluster,
// so flag letters glued after the value still resolve.
func consumeNumOptTail(a string, j int, ch byte) int {
	i := j + 1
	if ch == '0' && i < len(a) && (a[i] == 'x' || a[i] == 'X') {
		k := i + 1
		for k < len(a) && isHexDigit(a[k]) {
			k++
		}
		if k > i+1 {
			return k - i // 'x' marker plus its hex digits
		}
	}
	k := i
	for k < len(a) && a[k] >= '0' && a[k] <= '9' {
		k++
	}
	return k - i // decimal digits only — the flag letter itself is not counted
}

func isHexDigit(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}
func xargsFeedsCodeFlag(inner, full []string, pathEnv string) bool {
	if len(inner) == 0 {
		return false
	}
	head, _, effPath, exhausted := peelWrappersAndSbxAliases(inner, pathEnv)
	if exhausted || len(head) == 0 {
		return false
	}
	repl := xargsReplToken(full)
	if repl != "" && strings.Contains(head[0], repl) {
		return true
	}
	// If the inner target is ssh, inspect the remote command for an open
	// code flag (`xargs ssh dmit sh -c`) or a replace-token in the remote
	// command head / code slot (`xargs -I{} ssh dmit {}`).
	base := filepath.Base(head[0])
	if base == "ssh" || resolveHeadBase(head[0], effPath) == "ssh" {
		remoteCmd, hit := parseSSHInvocation(head)
		if hit != "" {
			return false
		}
		if repl != "" && strings.TrimSpace(remoteCmd) == repl {
			return true
		}
		for _, rseg := range splitShellSegments(remoteCmd) {
			if len(rseg.argv) == 0 {
				continue
			}
			if xargsFeedsCodeFlag(rseg.argv, full, os.Getenv("PATH")) {
				return true
			}
		}
		return false
	}
	if len(head) < 2 {
		return false
	}
	slots := interpCodeSlots(head)
	if len(slots) == 0 {
		return false
	}
	for _, s := range slots {
		if s.flagOnly {
			return true
		}
		if repl != "" && strings.Contains(s.text, repl) {
			return true
		}
	}
	return false
}

// langHasBacktickSpawn reports whether the language's code can spawn a
// process through a backtick / qx / %x spelling (perl, ruby, php).
func langHasBacktickSpawn(language string) bool {
	switch language {
	case "perl", "ruby", "php":
		return true
	}
	return false
}

// codeHasBacktickOrQx detects a backtick spawn literal, a qx operator, or a
// %x delimited command in perl/ruby/php code.
func codeHasBacktickOrQx(code string) bool {
	if strings.ContainsRune(code, '`') {
		return true
	}
	// qx{...} / qx(...) / qx/.../ and %x{...}.
	toks := codeTokens(code)
	if toks.hasTokenLike("qx{") || toks.hasTokenLike("qx(") || toks.hasTokenLike("qx[") ||
		toks.hasTokenLike("qx/") || toks.hasTokenLike("qx!") || toks.hasTokenLike("qx|") {
		return true
	}
	if toks.hasTokenLike("%x{") || toks.hasTokenLike("%x(") || toks.hasTokenLike("%x[") ||
		toks.hasTokenLike("%x/") || toks.hasTokenLike("%x!") || toks.hasTokenLike("%x|") {
		return true
	}
	return false
}

// openParenAfter skips spaces and tabs from afterIdx in s and returns the
// byte index of a following '(', or -1 when the next non-blank byte is not
// '('. The input must be a view byte-aligned with the original code (a
// mask — never a spacing-normalized copy, which shifts offsets).
func openParenAfter(s string, afterIdx int) int {
	for afterIdx < len(s) && (s[afterIdx] == ' ' || s[afterIdx] == '\t') {
		afterIdx++
	}
	if afterIdx < len(s) && s[afterIdx] == '(' {
		return afterIdx
	}
	return -1
}

// pythonWriteModeHit checks Python open()/io.open()/os.open() call sites for
// write modes; plain `open(p)` / `open(p,'r')` / `open(p,'rb')` stay free.
// A method call `.open(` on io/codecs/builtins/_io is the module function
// (mode in the SECOND positional arg); any other `.open(` (Path.open, file
// objects) takes the mode as its FIRST positional arg or the mode= kwarg.
// urllib.request.urlretrieve downloads to disk and sqlite3.connect opens
// the database for writing unless mode=ro — both block. An unclosed call
// (`open(` at EOF) fails closed rather than slicing out of bounds.
//
// Matching runs on `masked` — the byte-aligned lexical mask produced by
// pythonMask (len(masked) == len(code)) — so string/comment bodies cannot
// trip or hide a call (`print("open('/tmp/x','w')")` stays free, and a
// filename containing "O_WRONLY" is blanked before the flag scan). Mode
// literals are recovered from the same byte span in the original code; no
// normCallSpace is applied to `masked` before slicing (it would shift
// offsets), so `openParenAfter` covers the `open ('x')` spelling instead.
func pythonWriteModeHit(code string) string {
	masked := pythonMask(code)
	// Single pass over `open` occurrences (builtin and io.open/module
	// spellings): the identifier on the LEFT decides whether this is a
	// builtin open, a module open (io.open/codecs.open — mode at arg 2),
	// or a real method call (Path(p).open/p.open — mode at arg 1).
	ioModuleOpens := map[string]bool{
		// Mode in the SECOND positional arg (or mode= kwarg), default 'r'.
		"io": true, "codecs": true, "builtins": true, "_io": true,
		"gzip": true, "bz2": true, "lzma": true, "tarfile": true,
		"wave": true, "aifc": true, "sunau": true,
	}
	idx := 0
	for {
		j := indexIdent(masked, "open", idx)
		if j < 0 {
			break
		}
		pos := j
		openParen := openParenAfter(masked, pos+len("open"))
		if openParen < 0 {
			idx = pos + len("open")
			continue
		}
		// Resolve the receiver: `.open(` is a method/module call; a bare
		// `open(` is the builtin. `os.open` is skipped here — its flags are
		// vetted by the dedicated os.open scan below (treating the path as
		// the mode operand would misfire on filenames containing w/a/x/+).
		methodCall := false
		skip := false
		if pos > 0 && masked[pos-1] == '.' {
			// Walk back over the receiver: identifiers AND dots so a
			// package path (dbm.gnu.open, self.io.open) is captured whole.
			k := pos - 1
			for k > 0 && (isIdentByte(masked[k-1]) || masked[k-1] == '.') {
				k--
			}
			recv := masked[k : pos-1]
			// The module table matches the LAST package segment
			// (x.io.open -> io); the dedicated scans match a leading or
			// trailing name (os.open / dbm.gnu.open).
			lastSeg := recv
			if dot := strings.LastIndexByte(recv, '.'); dot >= 0 {
				lastSeg = recv[dot+1:]
			}
			switch {
			case lastSeg == "os":
				skip = true
			case recv == "dbm" || strings.HasPrefix(recv, "dbm."):
				// dbm.open(file[, flag]): flag 'r' (default) reads; 'w'/'c'/'n'
				// write. Handled by a dedicated scan below — a generic mode
				// check cannot express the flag set.
				if dbmOpenWrites(masked, code, openParen) {
					return "dbm.open write flag"
				}
				skip = true
			default:
				methodCall = !ioModuleOpens[lastSeg]
			}
		}
		if skip {
			idx = openParen + 1
			continue
		}
		lo, hi, closed := callInnerBounds(masked, openParen)
		if !closed {
			// Unclosed `open(` — cannot vet the call: fail closed.
			return "python open() unclosed"
		}
		if openArgsWriteMode(masked[lo:hi], code[lo:hi], methodCall) {
			return "python open() write mode"
		}
		idx = openParen + 1
	}
	// os.open(path, flags) with a write flag. The scan runs on the masked
	// argument text, so a path literal containing "O_WRONLY" cannot trip it
	// while `os.open ('/tmp/x', os.O_WRONLY)` still blocks.
	idx = 0
	for {
		j := strings.Index(masked[idx:], "os.open")
		if j < 0 {
			break
		}
		pos := idx + j
		leftOK := pos == 0 || !isIdentByte(masked[pos-1])
		if !leftOK {
			idx = pos + len("os.open")
			continue
		}
		openParen := openParenAfter(masked, pos+len("os.open"))
		if openParen < 0 {
			idx = pos + len("os.open")
			continue
		}
		lo, hi, closed := callInnerBounds(masked, openParen)
		if !closed {
			return "os.open unclosed"
		}
		inner := masked[lo:hi]
		for _, flag := range []string{"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"} {
			if strings.Contains(inner, flag) {
				return "os.open " + flag
			}
		}
		idx = openParen + 1
	}
	// urllib.request.urlretrieve(url, filename) downloads to disk — a file
	// write no matter where the call site appears. The token view is built
	// from the spacing-normalized MASKED text so `urlretrieve (` hits while
	// a mention inside a string literal (blanked by the mask) stays free.
	toks := codeTokens(normCallSpace(masked))
	if toks.hasTokenLike("urlretrieve(") || toks.hasTokenLike("urllib.request.urlretrieve") {
		return "urlretrieve downloads to disk"
	}
	// sqlite3.connect(path) opens the database read-write unless the URI
	// carries mode=ro; plain connects are writes (journal, wal, schema).
	idx = 0
	for {
		j := strings.Index(masked[idx:], "sqlite3.connect")
		if j < 0 {
			break
		}
		pos := idx + j
		openParen := openParenAfter(masked, pos+len("sqlite3.connect"))
		if openParen < 0 {
			idx = pos + len("sqlite3.connect")
			continue
		}
		lo, hi, closed := callInnerBounds(masked, openParen)
		if !closed {
			return "sqlite3.connect unclosed"
		}
		if !sqliteConnectReadonly(masked[lo:hi], code[lo:hi]) {
			return "sqlite3.connect write"
		}
		idx = openParen + 1
	}
	return ""
}

// singleArgDotReplace reports whether masked code calls `.replace(` with a
// single positional operand — the filesystem RENAME signature (Python
// Path.replace(target), JS fsp.rename-style single-target call).
// str.replace(old, new[, count]) and JS str.replace(pat, repl) take at
// least two operands and stay free.
func singleArgDotReplace(masked string) bool {
	idx := 0
	for {
		j := strings.Index(masked[idx:], ".replace(")
		if j < 0 {
			return false
		}
		pos := idx + j
		openParen := pos + len(".replace")
		lo, hi, closed := callInnerBounds(masked, openParen)
		if !closed {
			return true // unclosed .replace( — fail closed
		}
		argc := 0
		for _, p := range splitCallArgs(masked[lo:hi]) {
			if strings.TrimSpace(p) != "" {
				argc++
			}
		}
		if argc <= 1 {
			return true
		}
		idx = openParen + 1
	}
}

// jsFsOpenWriteHit checks JS/TS fs.openSync/fs.open/fsPromises.open call
// sites: a SECOND argument containing 'w'/'a'/'x'/'+' or an O_WRONLY /
// O_RDWR / O_CREAT / O_TRUNC / O_APPEND constant — or a non-literal mode
// expression — opens for writing. 'r' / O_RDONLY stay free.
//
// Matching runs on `masked` — the byte-aligned lexical mask produced by
// jsMask (len(masked) == len(code)) — so string literals and comments
// cannot fake or hide a call (`console.log("fs.openSync('/x','w')")`
// stays free). The mode literal is recovered from the SAME byte span in
// the original code: no normCallSpace is applied to `masked` before
// slicing (it would shift offsets whenever a string like "foo (bar)"
// precedes the call), so `openParenAfter` covers `fs.openSync ('x','w')`.
func jsFsOpenWriteHit(code string) string {
	masked := jsMask(code)
	for _, fname := range []string{"fs.openSync", "fs.open", "openSync",
		"fsPromises.open", "fs.promises.open"} {
		idx := 0
		for {
			j := strings.Index(masked[idx:], fname)
			if j < 0 {
				break
			}
			pos := idx + j
			if pos > 0 && isIdentByte(masked[pos-1]) {
				// myopenSync / myfs.open — not the fs builtin.
				idx = pos + len(fname)
				continue
			}
			openParen := openParenAfter(masked, pos+len(fname))
			if openParen < 0 {
				idx = pos + len(fname)
				continue
			}
			lo, hi, closed := callInnerBounds(masked, openParen)
			if !closed {
				return "fs.open unclosed"
			}
			maskedInner := masked[lo:hi]
			rawInner := code[lo:hi] // byte-aligned with masked
			pos2 := 0
			for _, sp := range splitCallArgsOffsets(maskedInner) {
				p := strings.TrimSpace(maskedInner[sp[0]:sp[1]])
				if p == "" {
					continue
				}
				pos2++
				if pos2 != 2 {
					continue
				}
				// The mode literal is blanked in maskedInner; recover it
				// from the byte-aligned raw span.
				rp := strings.TrimSpace(rawInner[sp[0]:minInt(sp[1], len(rawInner))])
				if lit, rest, ok := leadingStringLiteral(rp); ok && strings.TrimSpace(rest) == "" {
					if strings.ContainsAny(lit, "wax+") {
						return "fs.open write flag"
					}
				} else if strings.Contains(rp, "O_WRONLY") || strings.Contains(rp, "O_RDWR") ||
					strings.Contains(rp, "O_CREAT") || strings.Contains(rp, "O_TRUNC") ||
					strings.Contains(rp, "O_APPEND") {
					return "fs.open O_ write flag"
				} else if rp != "" {
					return "fs.open non-literal flag"
				}
			}
			idx = openParen + 1
		}
	}
	return ""
}

// sqliteConnectReadonly reports whether a sqlite3.connect( call is
// read-only. Python's sqlite3.connect(database, ..., uri=False) defaults to
// uri=False: without an explicit uri=True the database text is a plain
// filename, so 'file:/tmp/x.db?mode=ro' or even '/tmp/x.db?mode=ro' would
// CREATE a new database file named with the literal '?' bytes. The
// read-only exemption therefore requires ALL of: a static string literal
// database argument (first positional or database= kwarg, exactly one) that
// decodes to a "file:" URI carrying an explicit mode=ro query pair, AND an
// explicit uri=True keyword in the same call. Dynamic *args/**kwargs,
// concatenations ('file:x?mode=ro' + suffix) and any other shape fail
// closed. maskedInner carries the blanked view used to split top-level
// arguments (string bodies cannot fake a comma); the URI literal itself is
// decoded from the byte-aligned rawInner.
func sqliteConnectReadonly(maskedInner, rawInner string) bool {
	sawURI := false
	dbLit := ""
	sawDB := false
	positional := 0
	for _, sp := range splitCallArgsOffsets(maskedInner) {
		p := strings.TrimSpace(rawInner[sp[0]:minInt(sp[1], len(rawInner))])
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*") {
			return false // *args / **kwargs unpacking: fail closed
		}
		if eq := strings.Index(p, "="); eq > 0 && isIdentName(p[:eq]) {
			key, val := p[:eq], strings.TrimSpace(p[eq+1:])
			switch key {
			case "uri":
				if val == "True" {
					sawURI = true
				}
			case "database":
				if sawDB {
					return false // duplicate database operand
				}
				sawDB = true
				if lit, rest, ok := leadingStringLiteral(val); !ok || strings.TrimSpace(rest) != "" {
					return false // non-literal or concatenated database
				} else {
					dbLit = lit
				}
			case "timeout", "detect_types", "isolation_level", "check_same_thread", "cached_statements":
				// Known sqlite3.connect kwargs that do not grant write access.
			default:
				return false // unknown keyword: fail closed
			}
			continue // keyword arg
		}
		positional++
		if positional > 1 {
			return false // second+ positional args are not vetted
		}
		if positional == 1 {
			if sawDB {
				return false // database given twice
			}
			sawDB = true
			if lit, rest, ok := leadingStringLiteral(p); !ok || strings.TrimSpace(rest) != "" {
				return false // non-literal or concatenated database
			} else {
				dbLit = lit
			}
		}
	}
	return sawDB && sawURI && strings.HasPrefix(dbLit, "file:") && sqliteURIModeRO(dbLit)
}

// sqliteURIModeRO reports whether a sqlite URI string carries an explicit
// mode=ro query pair (file:...?mode=ro / &mode=ro, with optional further
// params after it).
func sqliteURIModeRO(uri string) bool {
	// RFC 3986 / sqlite3ParseUri: '#' terminates path and query; fragment
	// content is ignored. Truncate before looking for '?' so a forged
	// fragment like file:x.db#?mode=ro cannot fake read-only mode.
	if hash := strings.IndexByte(uri, '#'); hash >= 0 {
		uri = uri[:hash]
	}
	// mode=ro is only meaningful in the URI query segment after '?'.
	// A bare 'file:/tmp/x.db&mode=ro' (no '?') keeps &mode=ro as path text.
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return false
	}
	query := uri[q:] // includes leading '?'
	for _, sep := range []string{"?mode=ro", "&mode=ro"} {
		if k := strings.Index(query, sep); k >= 0 {
			rest := query[k+len(sep):]
			if rest == "" || rest[0] == '&' || rest[0] == '#' {
				return true
			}
		}
	}
	return false
}

// openArgsWriteMode inspects the argument text of open( for a write mode.
// For the builtin open(path, mode) the mode is the SECOND positional
// argument or the mode= kwarg; for a method call `.open(` (Path.open, file
// objects) it is the FIRST positional argument or mode=. A static read-only
// string literal ('r', 'rb', 'rt') stays free; a non-literal mode
// (variable, call, concatenation like 'r'+'w') fails closed.
// `open(p)`, `open(p,'r')`, `open(p, encoding='utf-8')`,
// `Path(p).open('r')`, `p.open(encoding='utf-8')` stay free.
//
// maskedInner carries the blanked view used to split top-level arguments
// (a comma inside a string literal cannot fake an argument boundary);
// mode literals are decoded from the byte-aligned rawInner.
func openArgsWriteMode(maskedInner, rawInner string, methodCall bool) bool {
	modeKwarg := ""
	hasModeKwarg := false
	modePos := ""
	modePosIdx := 2
	if methodCall {
		modePosIdx = 1
	}
	positional := 0
	for _, sp := range splitCallArgsOffsets(maskedInner) {
		p := strings.TrimSpace(rawInner[sp[0]:minInt(sp[1], len(rawInner))])
		if p == "" {
			continue
		}
		if eq := strings.Index(p, "="); eq > 0 && isIdentName(p[:eq]) {
			if p[:eq] == "mode" {
				hasModeKwarg = true
				modeKwarg = p[eq+1:]
			}
			continue // keyword arg
		}
		positional++
		if positional == modePosIdx {
			modePos = p
		}
	}
	if hasModeKwarg {
		m, rest, ok := leadingStringLiteral(strings.TrimSpace(modeKwarg))
		if !ok || strings.TrimSpace(rest) != "" {
			return true // non-static mode=: fail closed
		}
		return modeIsWrite(m)
	}
	if positional >= modePosIdx {
		m, rest, ok := leadingStringLiteral(strings.TrimSpace(modePos))
		if !ok || strings.TrimSpace(rest) != "" {
			return true // non-static mode positional: fail closed
		}
		return modeIsWrite(m)
	}
	return false
}

// dbmOpenWrites reports whether a `dbm.open(` call site (openParen is the
// byte index of its '(') writes: the second positional arg or flag= kwarg
// is 'w'/'c'/'n' or a non-literal. `dbm.open(p)` and `dbm.open(p, 'r')`
// are pure reads and stay free.
func dbmOpenWrites(masked, code string, openParen int) bool {
	lo, hi, closed := callInnerBounds(masked, openParen)
	if !closed {
		return true // unclosed dbm.open( — fail closed
	}
	maskedInner := masked[lo:hi]
	rawInner := code[lo:hi]
	positional := 0
	flagPos := ""
	hasFlagKwarg := false
	flagKwarg := ""
	for _, sp := range splitCallArgsOffsets(maskedInner) {
		p := strings.TrimSpace(rawInner[sp[0]:minInt(sp[1], len(rawInner))])
		if p == "" {
			continue
		}
		if eq := strings.Index(p, "="); eq > 0 && isIdentName(p[:eq]) {
			if p[:eq] == "flag" {
				hasFlagKwarg = true
				flagKwarg = p[eq+1:]
			}
			continue // keyword arg
		}
		positional++
		if positional == 2 {
			flagPos = p
		}
	}
	if hasFlagKwarg {
		lit, rest, ok := leadingStringLiteral(strings.TrimSpace(flagKwarg))
		if !ok || strings.TrimSpace(rest) != "" {
			return true // non-static flag=: fail closed
		}
		return dbmFlagWrites(lit)
	}
	if flagPos == "" {
		return false // dbm.open(file): default flag 'r' is a read
	}
	lit, rest, ok := leadingStringLiteral(strings.TrimSpace(flagPos))
	if !ok || strings.TrimSpace(rest) != "" {
		return true // non-literal flag operand: fail closed
	}
	return dbmFlagWrites(lit)
}

// dbmFlagWrites reports whether a dbm.open flag string opens for writing:
// 'r' reads, 'w'/'c'/'n' write (w = existing rw, c = create rw, n = new
// empty). Anything else is not a valid dbm flag — fail closed.
func dbmFlagWrites(f string) bool {
	switch f {
	case "r":
		return false
	case "w", "c", "n":
		return true
	}
	return true
}

// isIdentName reports whether s (already trimmed) is a bare identifier.
func isIdentName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// splitCallArgs splits a call's argument text on top-level commas, honouring
// quotes and bracket nesting.
func splitCallArgs(args string) []string {
	var out []string
	depth := 0
	inStr := byte(0)
	start := 0
	for i := 0; i < len(args); i++ {
		c := args[i]
		if inStr != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, args[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, args[start:])
	return out
}

// leadingStringLiteral extracts a quoted string literal's contents and
// returns (contents, remainderAfterClosingQuote, ok). The remainder lets the
// caller reject concatenations like 'r'+'w'. Escape sequences are DECODED
// (decodeStringEscapes), because the guard's decision is about the value the
// interpreter sees, not the bytes the source spells.
func leadingStringLiteral(s string) (string, string, bool) {
	if len(s) == 0 {
		return "", "", false
	}
	q := s[0]
	if q != '\'' && q != '"' {
		return "", "", false
	}
	var b strings.Builder
	for i := 1; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			n := i // decodeStringEscapes consumes the backslash at s[n]
			if !decodeStringEscapes(s, &n, &b) || n <= i {
				// Truncated or unknown escape: the character behind it is not
				// statically known, which the mode checks read as a write.
				var marker [4]byte
				nn := utf8.EncodeRune(marker[:], runeEscMarker)
				b.Write(marker[:nn])
				i += 2
				continue
			}
			i = n
			continue
		}
		if s[i] == q {
			return b.String(), s[i+1:], true
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), "", true
}

// runeEscMarker is what decodeStringEscapes emits in place of an escape
// sequence it cannot resolve statically (\N{…}, a truncated \u). A mode
// string carrying it can hide any character, so the write checks treat it as
// a write instead of guessing.
const runeEscMarker = rune(0xFFFD)

// decodeStringEscapes decodes string-literal escape sequences of s starting
// at s[off] == '\\', appending the decoded text to out and leaving off just
// past the last consumed byte. It returns false when the sequence is
// truncated (a lone trailing backslash). Both Python and JavaScript escape
// shapes are handled — `\n \t \r \0 \a \b \f \v \\ \' \"`, the octeral
// `\OOO` (Python) and decimal `\N` (JS), `\xHH`, `\uHHHH`, `\u{H...}`, and
// the 32-bit `\UHHHHHHHH`/`\u{1F600}` forms — encoded as UTF-8 so the result
// is byte-comparable with a literal typed directly.
//
// This exists because `open('/tmp/x', '\u0077')` opens for WRITING: a decoder
// that merely dropped the backslash turned it into "u0077" and every write
// check called it a read mode.
func decodeStringEscapes(s string, off *int, out *strings.Builder) bool {
	i := *off + 1 // s[*off] == '\\'
	if i >= len(s) {
		return false
	}
	hexVal := func(c byte) (int, bool) {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0'), true
		case c >= 'a' && c <= 'f':
			return int(c-'a') + 10, true
		case c >= 'A' && c <= 'F':
			return int(c-'A') + 10, true
		}
		return 0, false
	}
	emit := func(r rune) {
		var buf [4]byte
		n := utf8.EncodeRune(buf[:], r)
		out.Write(buf[:n])
	}
	readHex := func(nbytes int) (int, bool) {
		v := 0
		for k := 0; k < nbytes; k++ {
			if i >= len(s) {
				return 0, false
			}
			d, ok := hexVal(s[i])
			if !ok {
				return 0, false
			}
			v = v*16 + d
			i++
		}
		return v, true
	}
	switch s[i] {
	case 'x':
		i++
		v, ok := readHex(2) // JS allows \x{HH…}; Python is exactly two digits
		if !ok {
			return false
		}
		emit(rune(v))
	case 'u':
		i++
		if i < len(s) && s[i] == '{' { // JS \u{1F600}
			i++
			v := 0
			digits := 0
			for i < len(s) && s[i] != '}' {
				d, ok := hexVal(s[i])
				if !ok {
					return false
				}
				v = v*16 + d
				digits++
				i++
			}
			if digits == 0 || i >= len(s) {
				return false
			}
			i++ // '}'
			emit(rune(v))
			break
		}
		v, ok := readHex(4)
		if !ok {
			return false
		}
		emit(rune(v))
	case 'U':
		i++
		v, ok := readHex(8)
		if !ok {
			return false
		}
		emit(rune(v))
	case 'N': // JS \N{…} named sequence: the character is not statically known
		i++
		if i < len(s) && s[i] == '{' {
			for i < len(s) && s[i] != '}' {
				i++
			}
			if i >= len(s) {
				return false // unterminated \N{
			}
			i++ // '}'
		}
		emit(runeEscMarker)
	case '0', '1', '2', '3', '4', '5', '6', '7':
		v := 0
		for k := 0; k < 3 && i < len(s) && s[i] >= '0' && s[i] <= '7'; k++ {
			v = v*8 + int(s[i]-'0')
			i++
		}
		emit(rune(v))
	case 'n':
		out.WriteByte('\n')
		i++
	case 't':
		out.WriteByte('\t')
		i++
	case 'r':
		out.WriteByte('\r')
		i++
	case 'a':
		out.WriteByte(7)
		i++
	case 'b':
		out.WriteByte(8)
		i++
	case 'f':
		out.WriteByte(12)
		i++
	case 'v':
		out.WriteByte(11)
		i++
	case 'e':
		out.WriteByte(27)
		i++
	default:
		out.WriteByte(s[i]) // \x5c \' \" \\ and anything unknown
		i++
	}
	*off = i
	return true
}

// modeIsWrite reports whether an open() mode string opens for writing. An
// escape sequence the decoder could not resolve is a WRITE: the check runs on
// the decoded literal, and "u0077" is a mis-decoded 'w' — not a read mode.
// Fail-closed means an undecodable mode is treated as a write.
func modeIsWrite(m string) bool {
	if strings.ContainsRune(m, runeEscMarker) {
		return true
	}
	for i := 0; i < len(m); i++ {
		switch m[i] {
		case 'w', 'a', 'x', '+':
			return true
		}
	}
	return false
}

// ---------- perl/ruby/php lexical spawn & write screens ----------

// codeCommentText returns code with quoted-string and comment bytes
// replaced by spaces, EXCEPT backtick literals — a “ `cmd` “ body is a
// spawned command string and must keep its text for the spawn checks and
// the codeAgentNames scan (agent names inside string arguments are
// detected from the raw tokenSet, not this view). Identifier/word matches
// on this view cannot be fooled by string content
// (`perl -e "print 'unlink'"` stays free).
func codeCommentText(code string) string {
	b := []byte(code)
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '#' && i+1 < len(b) && b[i+1] != '{' && b[i+1] != '!' && !(i > 0 && b[i-1] == '$'):
			// perl $#ARGV: the '#' after '$' is the last-index sigil, not a
			// comment opener — the guard above already excluded it.
			for i < len(b) && b[i] != '\n' {
				b[i] = ' '
				i++
			}
			if i < len(b) {
				i-- // leave the newline in place
			}
		case c == '/' && i+1 < len(b) && (b[i+1] == '/' || b[i+1] == '*'):
			if b[i+1] == '/' {
				for i < len(b) && b[i] != '\n' {
					b[i] = ' '
					i++
				}
				if i < len(b) {
					i--
				}
			} else {
				b[i] = ' '
				b[i+1] = ' '
				i += 2
				for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
					if b[i] != '\n' {
						b[i] = ' '
					}
					i++
				}
				if i+1 < len(b) {
					b[i] = ' '
					b[i+1] = ' '
					i++
				}
			}
		case c == '=' && strings.HasPrefix(string(b[i:]), "=cut"):
			// perl POD: blank everything until a line starting with =
			for i < len(b) && b[i] != '\n' {
				b[i] = ' '
				i++
			}
		case c == '\'' || c == '"':
			b[i] = ' '
			i++
			for i < len(b) {
				if b[i] == '\\' && i+1 < len(b) {
					b[i] = ' '
					b[i+1] = ' '
					i += 2
					continue
				}
				if b[i] == c {
					b[i] = ' '
					break
				}
				if b[i] != '\n' {
					b[i] = ' '
				}
				i++
			}
		case c == '`':
			// Keep the backtick body: it is a spawned command string.
			i++
			for i < len(b) && b[i] != '`' {
				i++
			}
		}
	}
	return string(b)
}

// scriptingLexicalSpawnHit scans the comment/string-masked code for the
// spawn constructs a paren-less call can still reach in perl/ruby/php.
// Returns the matched construct or "". Backtick literals were kept by
// codeCommentText but are already covered by codeHasBacktickOrQx, so this
// pass looks only at identifiers, qx/%x operators, and perl pipe opens.
func scriptingLexicalSpawnHit(language, code string) string {
	m := codeCommentText(code)
	toks := codeTokens(m)
	switch language {
	case "perl":
		for _, name := range []string{"system", "exec", "qx"} {
			if toks.hasIdent(name) {
				return name
			}
		}
		if perlPipeOpen(code, m) {
			return "open |"
		}
	case "ruby":
		for _, name := range []string{"system", "exec", "spawn", "popen"} {
			if toks.hasIdent(name) {
				return name
			}
		}
		for _, prim := range []string{"Kernel.system", "Kernel.exec", "Kernel.spawn",
			"Process.spawn", "IO.popen", "Open3"} {
			if toks.hasTokenLike(prim) {
				return prim
			}
		}
		if toks.hasTokenLike("%x") {
			return "%x"
		}
	case "php":
		for _, name := range []string{"system", "exec", "passthru", "shell_exec",
			"proc_open", "popen", "pcntl_exec", "pcntl_fork"} {
			if toks.hasIdent(name) {
				return name
			}
		}
	}
	return ""
}

// indexIdent finds the next occurrence of name with identifier boundaries
// at or after off in s, or -1.
func indexIdent(s, name string, off int) int {
	idx := off
	for {
		j := strings.Index(s[idx:], name)
		if j < 0 {
			return -1
		}
		pos := idx + j
		leftOK := pos == 0 || !isIdentByte(s[pos-1])
		right := pos + len(name)
		rightOK := right >= len(s) || !isIdentByte(s[right])
		if leftOK && rightOK {
			return pos
		}
		idx = pos + len(name)
	}
}

// scriptingWritePrimHit scans code for the file-write/delete primitives a
// strict read-only role must not reach in perl/ruby/php, including
// paren-less call forms (perl `unlink '/tmp/x'`) and mode-aware opens
// (perl `open my $fh, '>', 'f'`, ruby `File.open('f','w')`, php
// `fopen('f','w')`; their read spellings stay free). Identifier matching
// runs on the string/comment-masked view so quoted words cannot trip it.
func scriptingWritePrimHit(language, code string) string {
	m := codeCommentText(code)
	toks := codeTokens(m)
	switch language {
	case "perl":
		for _, name := range []string{"unlink", "mkdir", "rmdir", "rename",
			"chmod", "chown", "truncate", "symlink", "link", "sysopen"} {
			if toks.hasIdent(name) {
				return "perl " + name
			}
		}
		if perlOpenWriteMode(code, m) {
			return "perl open write mode"
		}
	case "ruby":
		for _, prim := range []string{
			"FileUtils.", "File.write", "File.binwrite", "IO.write",
			"IO.binwrite", "File.delete", "File.unlink", "File.rename",
			"File.chmod", "File.chown", "File.truncate", "File.symlink",
			"File.link", "Dir.mkdir", "Dir.rmdir", "Dir.unlink",
		} {
			if toks.hasTokenLike(prim) {
				return prim
			}
		}
		for _, name := range []string{"unlink", "mkdir", "rmdir", "rename",
			"chmod", "chown", "truncate", "symlink"} {
			if toks.hasIdent(name) {
				return "ruby " + name
			}
		}
		if rubyFileOpenWrite(code, m) {
			return "File.open write mode"
		}
	case "php":
		for _, name := range []string{"file_put_contents", "unlink", "mkdir",
			"rmdir", "rename", "chmod", "chown", "touch", "copy",
			"symlink", "link"} {
			if toks.hasIdent(name) {
				return "php " + name
			}
		}
		if phpFopenWrite(code, m) {
			return "fopen write mode"
		}
	}
	return ""
}

// perlPipeOpen reports whether perl code contains an `open` whose mode
// operand opens a pipe: open FH, "cmd|" / "|cmd" / "|-" / "-|" / the
// three-arg open FH, "|", "cmd". Read/write modes are handled by
// perlOpenWriteMode; pure reads stay free.
func perlPipeOpen(raw, masked string) bool {
	if !codeTokens(masked).hasIdent("open") {
		return false
	}
	idx := 0
	for {
		j := indexIdent(masked, "open", idx)
		if j < 0 {
			return false
		}
		ops := perlOpenOperands(raw, masked, j)
		if len(ops) > 1 {
			for _, op := range ops[1:] { // skip the filehandle
				if lit, _, ok := leadingStringLiteral(strings.TrimSpace(op)); ok {
					if modeIsPipe(lit) {
						return true
					}
				}
			}
		}
		idx = j + len("open")
	}
}

// perlOpenWriteMode reports whether perl code contains an `open` whose mode
// operand writes: ">", ">>", "+<", "+">", "+>>" spellings in the
// mode+file operand or the three-arg MODE operand. Pure reads
// (open FH, '<', 'f' / open FH, 'file' / open(FH,$path)) stay free; a
// non-literal three-arg MODE fails closed.
func perlOpenWriteMode(raw, masked string) bool {
	idx := 0
	for {
		j := indexIdent(masked, "open", idx)
		if j < 0 {
			return false
		}
		ops := perlOpenOperands(raw, masked, j)
		switch {
		case ops == nil && perlOpenUnclosed(masked, j):
			return true // unclosed open( — fail closed
		case len(ops) >= 3:
			// open(FH, MODE, FILE): the MODE operand decides. A literal
			// starting with > or + writes; a non-literal mode is unknown —
			// fail closed.
			mode := strings.TrimSpace(ops[1])
			if lit, rest, ok := leadingStringLiteral(mode); ok && strings.TrimSpace(rest) == "" {
				if modeIsPerlWrite(lit) {
					return true
				}
			} else {
				return true
			}
		case len(ops) == 2:
			// open(FH, modefile): a literal starting with > or + writes;
			// a non-literal defaults to read mode and stays free.
			mode := strings.TrimSpace(ops[1])
			if lit, rest, ok := leadingStringLiteral(mode); ok && strings.TrimSpace(rest) == "" {
				if modeIsPerlWrite(lit) {
					return true
				}
			}
		}
		idx = j + len("open")
	}
}

// perlOpenUnclosed reports whether the `open` keyword at pos in masked is
// followed by an unclosed `(` call form (the parenthesized operand list
// never terminates — a signature the guard cannot vet).
func perlOpenUnclosed(masked string, pos int) bool {
	rest := masked[pos+len("open"):]
	k := strings.IndexAny(rest, "(\n")
	if k < 0 || rest[k] != '(' {
		return false
	}
	_, _, closed := callInnerBounds(masked, pos+len("open")+k)
	return !closed
}

// perlOpenOperands returns the raw-code operand slices after the `open`
// keyword at pos in masked (raw and masked are byte-aligned). Handles the
// parenthesized open(...) form and the paren-less open FH, MODE, FILE
// statement (terminated by ';' or newline).
func perlOpenOperands(raw, masked string, pos int) []string {
	rest := masked[pos+len("open"):]
	var maskedInner, rawInner string
	k := strings.IndexAny(rest, "(\n")
	if k >= 0 && rest[k] == '(' {
		openIdx := pos + len("open") + k
		mlo, mhi, mclosed := callInnerBounds(masked, openIdx)
		rlo, rhi, rclosed := callInnerBounds(raw, openIdx)
		if !mclosed || !rclosed {
			return nil // unclosed open( — nothing safe to inspect
		}
		maskedInner = masked[mlo:mhi]
		rawInner = raw[rlo:rhi]
	} else {
		seg := rest
		if e := strings.IndexAny(seg, ";\n"); e >= 0 {
			seg = seg[:e]
		}
		off := pos + len("open")
		maskedInner = seg
		rawInner = raw[off : off+len(seg)]
	}
	var ops []string
	for _, sp := range splitCallArgsOffsets(maskedInner) {
		if sp[0] < len(rawInner) {
			hi := minInt(sp[1], len(rawInner))
			ops = append(ops, rawInner[sp[0]:hi])
		}
	}
	return ops
}

// splitCallArgsOffsets is splitCallArgs but returns [lo,hi) byte spans of
// each operand inside args, so a byte-aligned view (raw vs masked code)
// can recover the literal text.
func splitCallArgsOffsets(args string) [][2]int {
	var out [][2]int
	depth := 0
	inStr := byte(0)
	start := 0
	for i := 0; i < len(args); i++ {
		c := args[i]
		if inStr != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, [2]int{start, i})
				start = i + 1
			}
		}
	}
	out = append(out, [2]int{start, len(args)})
	return out
}

// modeIsPerlWrite reports whether a perl open mode string opens for
// writing: modes starting with '>' or '+' (>, >>, +<, +>, +>>) write;
// '<', bare names and pipes (handled separately) do not.
func modeIsPerlWrite(m string) bool {
	if strings.ContainsRune(m, runeEscMarker) {
		return true // undecodable mode: fail closed
	}
	return strings.HasPrefix(m, ">") || strings.HasPrefix(m, "+")
}

// modeIsPipe reports whether an open mode string opens a pipe: trailing
// or leading '|', and perl's "- |" / "|-" / "-|" duplex spellings.
func modeIsPipe(m string) bool {
	m = strings.TrimSpace(m)
	return strings.HasPrefix(m, "|") || strings.HasSuffix(m, "|") ||
		m == "-|" || m == "|-" || strings.HasPrefix(m, "-|") || strings.HasPrefix(m, "|-")
}

// rubyFileOpenWrite reports whether code calls File.open with a write
// mode as its second positional arg (a literal containing w/a/x/+ or any
// non-literal mode operand); File.open('f') / ('f','r') stay free.
// Positions come from the masked view; the mode literal is decoded from
// the raw code.
func rubyFileOpenWrite(raw, masked string) bool {
	idx := 0
	for {
		j := strings.Index(masked[idx:], "File.open(")
		if j < 0 {
			return false
		}
		openParen := idx + j + len("File.open")
		mlo, mhi, mclosed := callInnerBounds(masked, openParen)
		rlo, rhi, rclosed := callInnerBounds(raw, openParen)
		if !mclosed || !rclosed {
			return true // unclosed File.open( — fail closed
		}
		maskedInner := masked[mlo:mhi]
		rawInner := raw[rlo:rhi]
		if secondOperandWriteMode(maskedInner, rawInner, modeIsWrite) {
			return true
		}
		idx = openParen + 1
	}
}

// phpFopenWrite reports whether code calls fopen with a write mode as its
// second positional arg (a literal containing w/a/x/c/+ or any
// non-literal operand); fopen('f','r') stays free.
func phpFopenWrite(raw, masked string) bool {
	idx := 0
	for {
		j := indexIdent(masked, "fopen", idx)
		if j < 0 {
			return false
		}
		rest := masked[j+len("fopen"):]
		k := strings.IndexAny(rest, "(\n")
		if k < 0 || rest[k] != '(' {
			idx = j + len("fopen")
			continue
		}
		openIdx := j + len("fopen") + k
		mlo, mhi, mclosed := callInnerBounds(masked, openIdx)
		rlo, rhi, rclosed := callInnerBounds(raw, openIdx)
		if !mclosed || !rclosed {
			return true // unclosed fopen( — fail closed
		}
		maskedInner := masked[mlo:mhi]
		rawInner := raw[rlo:rhi]
		if secondOperandWriteMode(maskedInner, rawInner, modeIsFopenWrite) {
			return true
		}
		idx = openIdx + 1
	}
}

// secondOperandWriteMode reports whether a call's SECOND operand is a write
// mode: a string literal decoded from rawInner for which modeFn(content)
// is true, or a non-literal operand (variable/expression — fail closed).
// Fewer than two operands is a read (mode defaults to 'r').
func secondOperandWriteMode(maskedInner, rawInner string, modeFn func(string) bool) bool {
	spans := splitCallArgsOffsets(maskedInner)
	count := 0
	for _, sp := range spans {
		if sp[0] >= len(rawInner) {
			continue
		}
		raw := strings.TrimSpace(rawInner[sp[0]:minInt(sp[1], len(rawInner))])
		if raw == "" {
			continue
		}
		count++
		if count < 2 {
			continue
		}
		lit, rest, ok := leadingStringLiteral(raw)
		if !ok || strings.TrimSpace(rest) != "" {
			return true // non-literal mode operand: fail closed
		}
		return modeFn(lit)
	}
	return false
}

// modeIsFopenWrite reports whether a php fopen mode opens for writing:
// any of w a x c + (c creates the file when missing) marks a write.
func modeIsFopenWrite(m string) bool {
	if strings.ContainsRune(m, runeEscMarker) {
		return true // undecodable mode: fail closed
	}
	return strings.ContainsAny(m, "waxc+")
}

// ---------- code tokenization ----------

// tokenSet is a cheap lexical view of interpreter code. Matchers apply
// identifier-boundary checks at match time so `mysubprocess` or `reopen` do
// not fire, while string-literal content stays searchable for agent names
// (spawn primitives take the command as a string argument).
type tokenSet struct {
	code string
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func codeTokens(code string) tokenSet {
	return tokenSet{code: code}
}

// hasTokenLike reports whether prim occurs with a non-identifier byte on
// its left edge (so `mysubprocess` does not match `subprocess`). Primitives
// leading with '.' (method calls like `.unlink(`) skip the left check — the
// receiver is always an identifier — and primitives ending in '(' or '.'
// carry their own open right edge. Other word-like primitives match as a
// prefix so `writeFile` covers `writeFileSync`.
func (t tokenSet) hasTokenLike(prim string) bool {
	idx := 0
	for {
		j := strings.Index(t.code[idx:], prim)
		if j < 0 {
			return false
		}
		pos := idx + j
		leftOK := strings.HasPrefix(prim, ".") || pos == 0 || !isIdentByte(t.code[pos-1])
		if leftOK {
			return true
		}
		idx = pos + len(prim)
	}
}

// hasIdent reports whether name occurs as a standalone token (identifier
// boundaries on both sides; string-literal content counts because agent
// names are arguments to spawn calls).
func (t tokenSet) hasIdent(name string) bool {
	idx := 0
	for {
		j := strings.Index(t.code[idx:], name)
		if j < 0 {
			return false
		}
		pos := idx + j
		leftOK := pos == 0 || !isIdentByte(t.code[pos-1])
		right := pos + len(name)
		rightOK := right >= len(t.code) || !isIdentByte(t.code[right])
		if leftOK && rightOK {
			return true
		}
		idx = pos + len(name)
	}
}

// ---------- entry points used by the handlers ----------

// guardCall is the per-role view computed once per tool call.
type guardCall struct {
	subagent       bool
	readonly       bool
	strictReadonly bool
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
	if g.subagent {
		if hit := peelResolvedDepth(argv, 's', 0, currentCallerIdentity()); hit != "" {
			if hit == "ctxmode index" || hit == roSSHWriteHit {
				return ruleReadonlyWrite, hit
			}
			return ruleSubagentNestedAgent, hit
		}
	}
	if g.strictReadonly {
		if hit := guardArgvReadonly(argv); hit != "" {
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
	caller := currentCallerIdentity().seededWith(envAs)
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

func stdinProgramHead(argv []string) (lang string, isInterp bool) {
	lang, isProg, _ := stdinProgramHeadEnv(argv)
	return lang, isProg
}

// stdinProgramHeadEnv is stdinProgramHead plus the environment the resolved
// stdin-program head runs under: the merged env ops peeled at every
// recursion level (prefix KEY=VAL, env -i/-u/-S operands, ops inside -c
// payloads and ssh remote commands). ctx_run stdin payloads and remote
// heredoc screens must replay them — `sh -c 'env HOME=-exec sh'` runs the
// stdin text with HOME overridden, so $HOME's placeholder grant is gone.
func stdinProgramHeadEnv(argv []string) (lang string, isInterp bool, envAs envAssignments) {
	return stdinProgramHeadDepth(argv, 0)
}

func stdinProgramHeadDepth(argv []string, depth int) (lang string, isInterp bool, envAs envAssignments) {
	return stdinProgramHeadWithEnv(argv, depth, envAssignments{}, os.Getenv("PATH"))
}

// stdinProgramHeadWithEnv is stdinProgramHeadDepth carrying the env ops
// accumulated above this recursion level: a peeled `PATH=...` prefix (or an
// `sbx --env PATH=...` op) rewires name resolution for every wrapper the
// command nests into, so `echo pig | PATH=dir foo -- sh` (dir/foo -> sbx)
// resolves the alias under the peeled PATH instead of the process PATH.
// The ssh remote-command branch drops it — remote heads resolve under the
// remote login env, so only the remote ops feed their PATH replay.
// basePath seeds the PATH the accumulated env ops replay over (the
// caller's effective PATH — its own process PATH at depth 0): a peeled
// `PATH=$PATH:<dir>` prefix then expands $PATH like the runtime instead
// of collapsing to `:<dir>` ([pattern:sbx-wrapper-unwrap-asymmetry]).
func stdinProgramHeadWithEnv(argv []string, depth int, inherited envAssignments, basePath string) (lang string, isInterp bool, envAs envAssignments) {
	if len(argv) == 0 || depth >= shellSplitMaxDepth {
		return "", false, inherited
	}
	head, _, ea, exhausted := peelWrappers(argv)
	if exhausted {
		// An unresolvable wrapper chain (dynamic word in an option/value
		// slot) could hide a stdin-reading head — fail closed like the
		// dynamic-placeholder paths below.
		return "", true, inherited
	}
	// R14: the env ops peeled at every recursion level are the environment
	// the stdin program text actually runs under — `sh -c 'env HOME=-exec
	// sh'` hands stdin a head whose HOME is overridden. Accumulate them so
	// the caller screens the payload under the consumed position's env.
	envAs = inherited.merged(ea)
	if len(head) == 0 {
		return "", false, envAs
	}
	base := filepath.Base(head[0])
	// Alias resolution runs against the PATH the peeled env ops install
	// over the caller's base PATH, not the process PATH alone — the
	// runtime resolves the head the same way.
	effPath := envAs.effectivePATHFrom(basePath)
	// A PATH alias resolving to sbx (foo -> sbx) skipped the sbx option
	// peel because peelWrappers saw only the typed name — rewrite the
	// head to `sbx` and recurse once so the inner command (after its
	// own -- separator) is classified as the stdin program instead of
	// the unpeeled wrapper ([pattern:sbx-wrapper-unwrap-asymmetry]).
	if rb := canonicalResolvedBase(resolveHeadBase(head[0], effPath)); rb != "" && rb != base && isPeeledWrapperBase(rb) {
		l, isProg, inner := stdinProgramHeadWithEnv(append([]string{rb}, head[1:]...), depth+1, envAs, basePath)
		return l, isProg, inner
	}
	// An ssh head forwards stdin to the remote command's stdin: resolve the
	// remote invocation and ask whether any remote head reads its program
	// from that stream. Malformed invocations keep their argv/shell hits;
	// here only the bare-host/missing-remote shape returns a parse hit, and
	// with no remote command stdin is pure data for the login shell anyway.
	if base == "ssh" || resolveHeadBase(head[0], effPath) == "ssh" {
		remoteCmd, hit := parseSSHInvocation(head)
		if hit != "" {
			return "", false, envAs
		}
		for _, seg := range splitShellSegments(remoteCmd) {
			if seg.depthExceeded || seg.parseErr != "" {
				return "", true, envAs
			}
			if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
				continue
			}
			if l, isProg, inner := stdinProgramHeadWithEnv(seg.argv, depth+1, envAssignments{}, os.Getenv("PATH")); isProg {
				return l, true, envAs.merged(inner)
			}
		}
		return "", false, envAs
	}
	// A `shell -c 'code'` argv carries outer program inline, but the INNER
	// script may still start a stdin-reading head (MF-5: sh -c 'sh').
	if innerText, has := unwrapShellArgv(head); has {
		if isDynamicArg(innerText) {
			return "", true, envAs
		}
		var segs []shellSegment
		switch base {
		case "bash", "zsh", "ksh", "mksh":
			segs = splitShellSegmentsBash(innerText)
		default:
			segs = splitShellSegments(innerText)
		}
		for _, seg := range segs {
			if seg.depthExceeded || seg.parseErr != "" {
				return "", true, envAs
			}
			if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
				continue
			}
			if l, isProg, inner := stdinProgramHeadWithEnv(seg.argv, depth+1, envAs, basePath); isProg {
				return l, true, inner
			}
		}
		return "", false, envAs
	}
	// An interpreter with -c/-e/-r/-m/-p inline code likewise.
	if _, _, has := unwrapInterpreterInline(head); has {
		return "", false, envAs
	}
	// SH11 MF-1.2: statement-level wrappers whose inner command shares this
	// stdin. eval joins its operands as shell text; flock/script/watch and
	// xargs resolve to an inner command argv (or -c text) which may itself
	// be a stdin program head.
	switch base {
	case "eval":
		if len(head) < 2 {
			return "", false, envAs
		}
		inner := strings.Join(head[1:], " ")
		if isDynamicArg(inner) {
			return "", true, envAs
		}
		for _, seg := range splitShellSegments(inner) {
			if seg.depthExceeded || seg.parseErr != "" {
				return "", true, envAs
			}
			if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
				continue
			}
			if l, isProg, inner := stdinProgramHeadWithEnv(seg.argv, depth+1, envAs, basePath); isProg {
				return l, true, inner
			}
		}
		return "", false, envAs
	case "flock":
		inner, cmdText := skipFlockArgs(head, 1)
		if cmdText != "" {
			if isDynamicArg(cmdText) {
				return "", true, envAs
			}
			for _, seg := range splitShellSegments(cmdText) {
				if seg.depthExceeded || seg.parseErr != "" {
					return "", true, envAs
				}
				if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
					continue
				}
				if l, isProg, inner := stdinProgramHeadWithEnv(seg.argv, depth+1, envAs, basePath); isProg {
					return l, true, inner
				}
			}
			return "", false, envAs
		}
		if inner < len(head) {
			// The inner command still inherits this level's peeled env.
			l, isProg, inner := stdinProgramHeadWithEnv(head[inner:], depth+1, envAs, basePath)
			return l, isProg, inner
		}
		return "", false, envAs
	case "script":
		if payload := scriptCommandArg(head); payload != "" {
			if isDynamicArg(payload) {
				return "", true, envAs
			}
			for _, seg := range splitShellSegments(payload) {
				if seg.depthExceeded || seg.parseErr != "" {
					return "", true, envAs
				}
				if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
					continue
				}
				if l, isProg, inner := stdinProgramHeadWithEnv(seg.argv, depth+1, envAs, basePath); isProg {
					return l, true, inner
				}
			}
			return "", false, envAs
		}
		// script without -c spawns a login shell on the pty — it reads the
		// forwarded stdin as commands.
		return "", true, envAs
	case "watch":
		if len(head) < 2 {
			return "", false, envAs
		}
		k, execMode, fc := skipWatchArgs(head, 1)
		if fc {
			return "", true, envAs
		}
		if k >= len(head) {
			return "", false, envAs
		}
		if execMode {
			l, isProg, inner := stdinProgramHeadWithEnv(head[k:], depth+1, envAs, basePath)
			return l, isProg, inner
		}
		text := strings.Join(head[k:], " ")
		if isDynamicArg(text) {
			return "", true, envAs
		}
		for _, seg := range splitShellSegments(text) {
			if seg.depthExceeded || seg.parseErr != "" {
				return "", true, envAs
			}
			if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
				continue
			}
			if l, isProg, inner := stdinProgramHeadWithEnv(seg.argv, depth+1, envAs, basePath); isProg {
				return l, true, inner
			}
		}
		return "", false, envAs
	case "xargs":
		k := xargsTargetIndex(head)
		if k >= len(head) {
			return "", false, envAs // xargs with no command runs echo
		}
		// xargs feeds the piped words as ARGV, not stdin: an inner bare
		// `sh` is not a stdin-program (S3). But an inner `sh -c`/`python -c`
		// whose code operand slot is FILLED from the fed words (code flag
		// last, or the -I/-i replace-token right after it) IS fed code —
		// the language follows the fed interpreter head so the payload is
		// screened under the right code rules.
		if xargsFeedsCodeFlag(head[k:], head, effPath) {
			innerHead, innerEnv, _, innerExhausted := peelWrappersAndSbxAliases(head[k:], effPath)
			envAs = envAs.merged(innerEnv) // fed code runs under the inner wrapper env too
			if !innerExhausted && len(innerHead) > 0 {
				if l, ok := heredocInterpLang(filepath.Base(innerHead[0])); ok {
					return l, true, envAs
				}
			}
			return "", true, envAs
		}
		l, isProg, inner := stdinProgramHeadWithEnv(head[k:], depth+1, envAs, basePath)
		return l, isProg, inner
	}
	if shellHeads[base] {
		// sh/bash/... without -c: commands come from a script file or
		// stdin. -s forces stdin even with positional args; -o/+o/-O/+O
		// and short clusters containing o/O consume a value slot.
		sawDashDash := false
		forceStdin := false
		i := 1
		for i < len(head) {
			a := head[i]
			if isDynamicArg(a) {
				return "", true, envAs // dynamic option/script → treat as stdin-program so heredoc screens
			}
			if a == "--" {
				sawDashDash = true
				i++
				continue
			}
			if sawDashDash {
				if isStdinDevicePath(a) {
					return "", true, envAs // sh -- /dev/stdin reads the program from stdin
				}
				if forceStdin {
					return "", true, envAs
				}
				return "", false, envAs
			}
			if a == "-" || isStdinDevicePath(a) {
				return "", true, envAs
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
						return "", false, envAs // -c means inline, not stdin
					}
					if ch == 'o' || ch == 'O' {
						if j+1 >= len(a) {
							i++ // consume option name argv
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
			// non-option operand
			if forceStdin {
				return "", true, envAs // -s arg1 still reads stdin
			}
			return "", false, envAs // script file
		}
		return "", true, envAs // bare shell / only flags
	}
	if lang, ok := heredocInterpLang(base); ok {
		sawDashDash := false
		valueOpts := map[string]bool{
			"-W": true, "-X": true, "-r": true, "--require": true,
			"--loader": true, "--import": true, "--experimental-loader": true,
			"--conditions": true, "-I": true, "-M": true, "-m": true,
			"-c": true, "-d": true, "-z": true,
		}
		i := 1
		for i < len(head) {
			a := head[i]
			if isDynamicArg(a) {
				return lang, true, envAs
			}
			// A stdin device path reads the PROGRAM from stdin — checked
			// before the sawDashDash script-file early return so
			// `python3 -- /dev/stdin` blocks too.
			if a == "-" || isStdinDevicePath(a) {
				return lang, true, envAs
			}
			if a == "--" {
				sawDashDash = true
				i++
				continue
			}
			if sawDashDash || !strings.HasPrefix(a, "-") {
				return "", false, envAs
			}
			if valueOpts[a] {
				i += 2
				continue
			}
			if strings.HasPrefix(a, "--") && strings.Contains(a, "=") {
				i++
				continue
			}
			// bundled short opts: -Wignore / -Xutf8 etc. already single argv
			i++
		}
		return lang, true, envAs
	}
	return "", false, envAs
}

// peelToSSHHead peels both standard wrappers and statement-level stdin
// wrappers (flock, watch -x, xargs) to reach an underlying ssh argv.
// pathEnv is the effective PATH the peeled head resolves against: the
// env ops peeled at each layer replay over it so PATH-injected aliases
// (foo -> sbx, ssx -> ssh) resolve like the runtime would.
func peelToSSHHead(argv []string, pathEnv string) []string {
	cur := argv
	effPath := pathEnv
	for depth := 0; depth < peelWrapperMaxSteps && len(cur) > 0; depth++ {
		head, _, ea, exhausted := peelWrappers(cur)
		effPath = ea.effectivePATHFrom(effPath)
		if exhausted || len(head) == 0 {
			return nil
		}
		base := filepath.Base(head[0])
		// A PATH alias resolving to a wrapper (foo -> sbx, myenv -> env)
		// skipped the option peel because peelWrappers saw only the typed
		// name — rewrite the head to the resolved wrapper and loop so its
		// own options are peeled like a directly typed invocation.
		if rb := canonicalResolvedBase(resolveHeadBase(head[0], effPath)); rb != "" && rb != base && isPeeledWrapperBase(rb) {
			cur = append([]string{rb}, head[1:]...)
			continue
		}
		if base == "ssh" || resolveHeadBase(head[0], effPath) == "ssh" {
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
func sshTunnelsStdinProgram(argv []string, pathEnv string) bool {
	head := peelToSSHHead(argv, pathEnv)
	if len(head) == 0 {
		return false
	}
	remoteCmd, hit := parseSSHInvocation(head)
	if hit != "" {
		return false
	}
	return remoteReadsProgramFromStdin(remoteCmd)
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
	// The env ops peeled at EVERY recursion level (including inside -c
	// payloads and remote commands) are the env the stdin program text is
	// parsed against: env HOME=-exec sh +stdin, and `sh -c 'env HOME=-exec
	// sh'`+stdin alike (R14).
	lang, isProg, envAs := stdinProgramHeadEnv(argv)
	if !isProg {
		return "", ""
	}
	if g.readonly && !g.strictReadonly && sshTunnelsStdinProgram(argv, os.Getenv("PATH")) {
		g.strictReadonly = true
	}
	if lang == "" {
		// Shell head: stdin is shell code, screened under envAs' taint.
		return g.guardCtxRunShellEnv(stdin, envAs)
	}
	return g.guardCtxRunCode(lang, stdin)
}

// guardCtxRunStdinForCommand is the command-string variant of
// guardCtxRunStdin: it splits the command into segments and checks each
// peeled head for a shell/interpreter reading stdin — including a head
// reached through an ssh remote command.
func (g guardCall) guardCtxRunStdinForCommand(command, stdin string) (rule, detail string) {
	if stdin == "" || (!g.subagent && !g.strictReadonly) {
		return "", ""
	}
	for _, seg := range splitShellSegments(command) {
		if seg.depthExceeded {
			if g.strictReadonly {
				return ruleReadonlyWrite, depthExceededHit
			}
			if g.subagent {
				return ruleSubagentNestedAgent, depthExceededHit
			}
			return "", ""
		}
		// Skip segments that cannot read the ctx_run stdin: they either
		// carry no argv, consume the pipe themselves (their stdin is the
		// upstream bytes, not the stdin payload — those are screened as
		// piped code separately), or already take their input from a file
		// redirect / heredoc / here-string (stdin never reaches them).
		if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
			continue
		}
		if lang, isProg, envAs := stdinProgramHeadEnv(seg.argv); isProg {
			// A clean segment result does not end the scan: a LATER
			// segment may still read stdin (e.g. `python3 -; sh` +stdin).
			// Only a rule hit blocks; "" falls through to the next segment.
			gSeg := g
			if gSeg.readonly && !gSeg.strictReadonly && sshTunnelsStdinProgram(seg.argv, os.Getenv("PATH")) {
				gSeg.strictReadonly = true
			}
			if lang == "" {
				if r, d := gSeg.guardCtxRunShellEnv(stdin, envAs); r != "" {
					return r, d
				}
				continue
			}
			if r, d := gSeg.guardCtxRunCode(lang, stdin); r != "" {
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

// minInt is a tiny local helper (avoid pulling in math for two ints).
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
