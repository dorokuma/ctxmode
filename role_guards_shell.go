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
	// declClause marks a segment emitted from a bash DeclClause (export/readonly
	// FOO=1 with UNQUOTED keyword spelling — the parser itself proves the
	// keyword was a bare literal token). POSIX parses `export FOO=1` as a
	// CallExpr, so all other paths rely on peelPreludeHasNonAssign's word-shape
	// verification instead (v6.2.2 Oracle R11 R11-MF-2).
	declClause bool
	// bashDialect marks a segment whose enclosing script was parsed under a
	// bash-family interpreter dialect (v6.2.2 Oracle R16 M2). A same-process
	// re-parse — eval operand or trap action — runs in the SAME interpreter,
	// so the recursive guard must re-enter under this dialect instead of
	// falling back to the dash POSIX default (a dash-only static literal
	// like printf tag{red,blue} brace-expands into multiple argv words when
	// bash re-parses it).
	bashDialect bool
	// childScope marks a segment whose command runs in a CHILD execution
	// scope — inside a `( ... )` subshell, any pipeline component, a
	// backgrounded (`&`) subtree or a command/process substitution — so its
	// pure assignments can NEVER re-bind variables of the running parent
	// shell (R20-Oracle-M3). Conditional-but-same-shell shapes (`&&`/`||`
	// right sides, if/while/for bodies, brace groups) deliberately do NOT
	// carry this marker: their assignments stay in the parent's scope, and
	// the conservative direction for the stdin environment accumulation is
	// to fold them in rather than to pretend they never happened.
	// Retained as the boolean summary of scopePath != "" for legacy
	// readers; scope-aware accumulation keys on scopePath itself.
	childScope bool
	// scopePath identifies the execution scope the segment runs in
	// (R21-Oracle-M3/R21-Reviewer-1): "" is the parent shell's own scope
	// and each child execution scope carries a unique dotted suffix whose
	// PREFIX chain is the lexical nesting of the scopes that forked it.
	// A pure assignment at scope path P is visible exactly to consumers
	// whose scope path has P as a prefix — never to the parent scope
	// (P != "") and never to a sibling scope.
	scopePath string
	// condAssign marks a segment minted inside a conditional region (the
	// right side of `&&`/`||`, an if/case branch, a loop body or a
	// possibly-uncalled function body): its assignment writes may or may
	// not execute, so the control-flow merge treats every variable they
	// touch as UNCERTAIN — never an exact environment override for later
	// consumers (R21-Oracle-M3).
	condAssign bool
	// pureAssign marks a segment whose AST CallExpr is PROVABLY a bare
	// assignment sequence of the shell itself (len(Args)==0 &&
	// len(Assigns)>0 — R22-Oracle-M3 / R22-Reviewer-#2): the environment
	// accumulation may fold exactly these segments. A plain command word
	// that merely SPELLS KEY=VAL after quote stripping (a dynamic head
	// resolving to `A=1` at runtime, or the operand of an echo-shaped
	// command) is a command invocation, never an assignment of the
	// running shell, so the argv shape alone must never mint this flag.
	pureAssign bool
	// assignFlags is parallel to argv and carries the assignment
	// OPERATOR provenance the serialization into KEY=VAL text destroys
	// (R23-Reviewer-#2 / R23-Oracle-M3): bit 1 marks a `+=` append write
	// (the result concatenates onto the unknowable old value), bit 2 an
	// array-subscript write (`name[i]=v` never overwrites the whole
	// scalar). Only genuinely independent plain `=` scalar writes may
	// clear a conditional-write uncertainty in the tracker — the fold
	// consults exactly these bits.
	assignFlags []byte
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
// It is a PRINTABLE string by design (the glob part of a word is public
// knowledge) — R18-Oracle-M4: never key provenance on it alone, because a
// single-quoted literal can carry the same bytes verbatim.
const cmdSubPlaceholderGlob = "__ctx_glob__"

// cmdSubPlaceholderTilde marks a REAL unquoted word-start tilde whose
// expansion HOME is known to the encoding collector (R18-Oracle-M4). The
// embedded NUL bytes make it impossible to produce from shell text or argv
// (exec rejects NUL) — exactly like envPathSelfPlaceholder — so only the
// word encoder itself can mint it, and a single-quoted literal spelling of
// the printable glob marker can never forge the HOME restoration. When the
// collector's HOME is tainted the marker is simply absent: the concrete
// path grant is lost, while the word-count proof survives independently
// (R18-Oracle-S5 — bash tilde expansion never field-splits).
const cmdSubPlaceholderTilde = "\x00__ctx_tilde__\x00"

// cmdSubPlaceholderAbsDq marks a double-quoted dynamic whose expansion is
// GUARANTEED to begin with '/': $PWD/${PWD}, $(pwd) and a bare
// $(mktemp -d) with untainted TMPDIR — but NOT $OLDPWD (R14-Oracle-M2:
// the shell only populates OLDPWD after the first cd, so an unbound
// expansion can collapse to the empty string). Word-start it is
// split-safe AND cannot become an option flag (Q1-C: absolute-path
// placeholder class).
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

// isSingleWordSplitSafe reports a dynamic word guaranteed to stay ONE argv
// word at runtime: split-safe AND free of unquoted pathname-expansion globs
// (cmdSubPlaceholderGlob can expand into N >= 2 argv words, spilling
// match[1..] out of a single-operand option value slot into the program
// or command-head position — v6.2.2 Oracle R9 R9-MF-2 `awk -F B*` /
// `gawk --assign a=1*` / `env -a p*` / `xargs -a p*` / `flock -w 0*` /
// `git -C g*` / `npx --cache p*`). Multi-file operand slots keep the
// wider isSplitSafeDynamicWord (glob expansion is valid input data there).
func isSingleWordSplitSafe(a string) bool {
	return isSplitSafeDynamicWord(a) && !strings.Contains(a, cmdSubPlaceholderGlob)
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
	// R15-Oracle-M1: a brace-expansion word (the glob placeholder plus
	// surviving '{' list text, e.g. `{docs/a,-blue}`) encodes SEVERAL
	// expansion results in one string — the leading '{' byte is NOT a
	// path property of any result and a '/' carried by ONE branch
	// (docs/a) says nothing about the sibling branches (-blue, which
	// expands to an OPTION spelling). Neither the per-result option
	// review nor the per-result data review can be discharged from this
	// merged encoding, so brace words can never be proven safe data
	// operands here (ordinary pathname globs like docs/*.txt carry no
	// '{' byte and are unaffected).
	// R16-Oracle-S1: a REAL brace expansion encodes at least two glob
	// placeholders (writeBraceExpansionMarkers), so the refusal keys on the
	// two-marker brace shape instead of the mere co-occurrence of one glob
	// marker and a literal '{'. A QUOTED literal brace inside an ordinary
	// pathname glob — docs/'{v1}'/*.txt — carries exactly ONE marker and
	// stays a safe data operand: every match shares the fixed docs/ prefix
	// and {v1} is a literal directory, never an expansion branch.
	// R17-Oracle-S1: the brace shape is the CONSECUTIVE ADJACENT pair of
	// glob markers writeBraceExpansionMarkers guarantees at the word tail —
	// ordinary pathname globs never produce one even when several unquoted
	// '*'/tilde parts of the same word each emitted their own marker
	// (docs/*/'{v1}'/*.txt carries two SEPARATED markers and must stay a
	// safe data operand: every match keeps the fixed docs/ prefix and {v1}
	// is a literal directory).
	if strings.Contains(a, "{") && strings.Contains(a, cmdSubPlaceholderGlob+cmdSubPlaceholderGlob) {
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

// addAssign appends one KEY=VAL op when word carries an '=' anywhere.
// GNU env(1) consumes ANY operand containing '=' as an assignment —
// POSIX-key or not (a.b=1, BASH_FUNC_echo%%=..., -x=1 after `--`, even
// `=foo` with an empty key) — so the env operand peel must record them
// all for screening instead of dropping the non-POSIX shapes (v6.2.2
// Oracle R9 R9-MF-3/R9-MF-4). Keys are never executed; every consumer
// matches exact names or prefixes, so an empty/odd key is inert data.
func (e *envAssignments) addAssign(word string) {
	if k := strings.IndexByte(word, '='); k >= 0 {
		e.ops = append(e.ops, envOp{kind: 'a', key: word[:k], value: word[k+1:]})
	}
}

// merged returns the env op list of e followed by o's ops, preserving
// order so a nested invocation's env ops replay after the outer ones.
// The result's backing array is always EXACTLY sized (R20-Oracle
// observation): target snapshots handed out by the stdin scans must stay
// immutable while the running accumulator keeps appending pure-assignment
// ops — with len == cap every later append reallocates instead of
// clobbering a handed-out slice's backing memory, and consecutive pure
// assignments can append in place without the quadratic copy cost a fresh
// full copy per merge would impose.
func (e envAssignments) merged(o envAssignments) envAssignments {
	if len(e.ops) == 0 {
		o.ops = o.ops[:len(o.ops):len(o.ops)]
		return o
	}
	if len(o.ops) == 0 {
		e.ops = e.ops[:len(e.ops):len(e.ops)]
		return e
	}
	out := envAssignments{ops: make([]envOp, 0, len(e.ops)+len(o.ops))}
	out.ops = append(out.ops, e.ops...)
	out.ops = append(out.ops, o.ops...)
	out.ops = out.ops[:len(out.ops):len(out.ops)]
	return out
}

// scopeEnvState is one execution scope's accumulated environment state
// (R21-Oracle-M3/R21-Reviewer-1): the pure-assignment ops performed
// UNCONDITIONALLY inside the scope itself (in statement order — NOT
// including the inherited parent prefix) plus the variables whose
// post-merge value is UNCERTAIN because a conditional region
// (`&&`/`||` right side, if/case branch, loop body, possibly-uncalled
// function body) wrote them. Only PATH and the sentinel trust variables
// are tracked — every other variable is invisible to the environment
// model anyway.
//
// R22-Reviewer-#7 / R22-Oracle-SF2: the fork-time parent environment is
// shared by POINTER, never eagerly copied — parent links the scope state
// it forked from and baseLen freezes the length of the parent's own op
// list at fork time, so a later parent-side append can never leak into
// this scope's inherited view (the parent's ops are append-only, so the
// frozen prefix is immutable for the tracker's whole lifetime). The
// full environment a consumer runs with is materialized only when a
// real stdin consumer needs it (scopeEnvTracker.view) — a run of pure
// assignments with no consumer pays exactly zero snapshot copies.
type scopeEnvState struct {
	ops     []envOp
	taint   map[string]bool
	parent  *scopeEnvState
	baseLen int
}

// scopeEnvTracker is the control-flow-aware environment accumulator of
// one segment list (R21-Oracle-M3/R21-Reviewer-1): a flat running env
// cannot answer WHICH scope a consumer belongs to, so states are keyed
// by the segment's scope path — a child scope forks a clone of its
// longest-prefix ancestor state, writes bind within the child only, and
// the parent scope's consumers keep their own exact view. Conditional
// writes never mint exact overrides: they taint the variable, and only
// a later UNCONDITIONAL assignment in the same scope re-establishes an
// exact value.
type scopeEnvTracker struct {
	states map[string]*scopeEnvState
}

// envTrackTaintedVar reports whether a variable name matters to the
// environment model: PATH (head resolution) or a sentinel trust variable
// (placeholder grant premises). Other conditional writes need no taint
// tracking — the model never reads their values.
func envTrackTaintedVar(name string) bool {
	return name == "PATH" || sentinelTrustVars[name]
}

// stateFor returns the accumulated state of one scope path, materializing
// it as a parent-linked fork of the longest-prefix ancestor when the scope
// has not been touched yet (R22-Reviewer-#7: the fork-time environment of
// a child scope is exactly its parent's state at fork time — emission
// order guarantees the ancestor rows already hold every op visible then,
// and the append-only op lists make the frozen prefix immutable without
// any copy).
func (t *scopeEnvTracker) stateFor(path string) *scopeEnvState {
	if t.states == nil {
		t.states = map[string]*scopeEnvState{}
	}
	if st, ok := t.states[path]; ok {
		return st
	}
	if path == "" {
		st := &scopeEnvState{}
		t.states[path] = st
		return st
	}
	// R23-Reviewer-#7 / R23-Oracle-SF2: the scope path's construction is
	// STRICTLY hierarchical — enterChildScope mints each id as
	// parentPath + "/" + id — so the longest-prefix ancestor is exactly
	// the direct parent, reachable in ONE table lookup by trimming the
	// trailing id element. The pre-R23 scan walked the entire states map
	// on every new scope: n sibling scopes under one root paid quadratic
	// discovery cost even at constant depth. A detached path (no
	// registered parent at all) forks off the root state exactly like
	// the former best-prefix fallback resolved to "".
	parentPath := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		parentPath = path[:i]
	} else {
		parentPath = ""
	}
	base := t.stateFor(parentPath)
	fork := &scopeEnvState{parent: base, baseLen: len(base.ops)}
	if len(base.taint) > 0 {
		// The uncertainty map is mutable on both sides (new conditional
		// writes may land in either scope later), so the fork-time
		// snapshot must be a real copy — it is small (PATH plus a handful
		// of sentinel names) and only paid once per scope, never per
		// segment.
		fork.taint = map[string]bool{}
		for k, v := range base.taint {
			fork.taint[k] = v
		}
	}
	t.states[path] = fork
	return fork
}

// foldSegment folds one segment's pure-assignment writes into its own
// scope's state (R21-Oracle-M3): conditional segments never mint exact
// ops — they taint every tracked variable they touch — while
// unconditional assignments append their ops and clear the variable's
// uncertainty (a definite re-write re-establishes the exact value).
// Segments that are not pure parent/child-shell assignments (a real
// command head, an env-spawned subprocess shape) fold nothing.
func (t *scopeEnvTracker) foldSegment(seg shellSegment, caller callerIdentity) {
	if len(seg.argv) == 0 {
		return
	}
	// R22-Oracle-M3 / R22-Reviewer-#2: the fold license is the AST's own
	// assignment verdict, never the argv word shape — a plain command
	// word that merely SPELLS KEY=VAL after quote stripping is a command
	// invocation (its runtime resolution may be a program or a builtin
	// that performs no assignment at all), so the pre-R22 shape test
	// folded writes the shell never performs.
	if !seg.pureAssign {
		return
	}
	if peeledHead, _, _, _, _ := peelWrappersWithIndex(seg.argv, caller); len(peeledHead) != 0 {
		return
	}
	if !argvIsPlainAssignRun(seg.argv) {
		return
	}
	st := t.stateFor(seg.scopePath)
	for i, a := range seg.argv {
		t.foldAssignWord(st, a, seg.condAssign, assignFlagAt(seg.assignFlags, i))
	}
}

// assignFlagAt reads the assignment operator provenance parallel to one
// argv index, tolerating segments assembled outside the AST collector
// that carry no parallel slice at all (R23 complexity budget extraction).
func assignFlagAt(flags []byte, i int) byte {
	if i < len(flags) {
		return flags[i]
	}
	return 0
}

// foldAssignWord folds one assignment word into the scope state
// (extracted from foldSegment so the taint-survival policy carries no
// extra nesting): a conditional write taints every tracked variable it
// touches, while an unconditional write appends its op and clears the
// variable's uncertainty — UNLESS the new value depends on the
// unknowable old one, and NEVER for a non-scalar write operator
// (R23-Reviewer-#2 / R23-Oracle-M3): flags carries the AST assignment
// operator provenance (bit 1 `+=` append, bit 2 array subscript) the
// KEY=VAL serialization cannot express.
func (t *scopeEnvTracker) foldAssignWord(st *scopeEnvState, a string, cond bool, flags byte) {
	if !isAssignWord(a) {
		return
	}
	k := strings.IndexByte(a, '=')
	if k <= 0 {
		return
	}
	name := a[:k]
	if cond {
		taintTrackedVar(st, name)
		return
	}
	value := a[k+1:]
	if flags&2 != 0 {
		// R23-Oracle-M3: an array-subscript write `name[i]=v` touches ONE
		// element of the array — every other element keeps its inherited
		// value, so the scalar is never overwritten: no exact op stands,
		// and a tracked variable turns uncertain outright.
		taintTrackedVar(st, name)
		return
	}
	if flags&1 != 0 {
		foldAppendWrite(st, name, value)
		return
	}
	st.ops = append(st.ops, envOp{kind: 'a', key: name, value: value})
	if !st.taint[name] {
		return
	}
	if strings.Contains(value, envPathSelfPlaceholder) || isDynamicArg(value) {
		// R22-Oracle-M3 / R22-Reviewer-#2: the unconditional write
		// DEPENDS on the old value of the very uncertainty it would
		// clear — a self-reference (`PATH=$PATH:/suffix` expands the
		// unknowable old value) or any other dynamic content. Because
		// the old value is unknown the new value is unknown too, so
		// the taint MUST survive the overwrite; only a completely
		// independent constant re-establishes an exact value.
		return
	}
	delete(st.taint, name)
}

// taintTrackedVar marks one variable uncertain in the scope state when
// the environment model tracks it at all (extracted from foldAssignWord
// so the conditional/subscript write shapes carry no extra nesting —
// the R23 complexity budget).
func taintTrackedVar(st *scopeEnvState, name string) {
	if !envTrackTaintedVar(name) {
		return
	}
	if st.taint == nil {
		st.taint = map[string]bool{}
	}
	st.taint[name] = true
}

// foldAppendWrite folds one bash `+=` append assignment (R23-Oracle-M3 /
// R23-Reviewer-#2): the operator concatenates the suffix onto the OLD
// value, so the result is never the independent constant the serialized
// KEY=VAL word spells. PATH keeps its exact self-reference form when the
// old value is certain (the expansion machinery replays it honestly);
// once the old value is uncertain the concatenation depends on it and
// the uncertainty MUST survive — clearing it here would launder the
// conditional write into an exact constant exactly like the
// plain-overwrite self-reference the R22 model already refuses. Every
// other tracked variable has no self-expansion model at all, so the
// append is uncertainty outright.
func foldAppendWrite(st *scopeEnvState, name, value string) {
	if name == "PATH" && !st.taint[name] {
		st.ops = append(st.ops, envOp{kind: 'a', key: name, value: envPathSelfPlaceholder + value})
		return
	}
	taintTrackedVar(st, name)
}

// view returns the environment op view one consumer scope runs with:
// the scope's fork-time inherited chain plus its own exact unconditional
// ops, followed by one uncertainty marker op per tainted tracked variable
// (R21-Oracle-M3). The taint ops ride at the tail because they shadow
// every earlier exact op of the same name — a conditional write anywhere
// in the scope's history makes the merged value unknowable unless a
// later unconditional write cleared it.
//
// R22-Reviewer-#7 / R22-Oracle-SF2: callers materialize this view ONLY
// for segments that really consume stdin (heredoc/here-string/program
// projection) — consecutive pure-assignment segments pay nothing beyond
// the op append itself. The result is freshly allocated exactly once per
// call and capacity-frozen, so the handed-out snapshot stays immutable
// while the running accumulator keeps appending (the R20 observation's
// contract, preserved).
func (t *scopeEnvTracker) view(path string) envAssignments {
	st := t.stateFor(path)
	// Walk the parent chain leaf-to-root, then emit root-to-leaf. Each
	// ancestor's contribution is truncated to the length its child froze
	// at fork time — a parent-side op appended AFTER the fork is invisible
	// to the child exactly like the fork-time process environment.
	var chain []*scopeEnvState
	for cur := st; cur != nil; cur = cur.parent {
		chain = append(chain, cur)
	}
	return st.chainView(chain)
}

// chainView emits the root-to-leaf op view of one resolved chain
// (extracted from view so the fork-chain walk carries no extra
// nesting): each ancestor contributes the ops visible at fork time,
// then the leaf's uncertainty markers ride at the tail, and the result
// is freshly allocated exactly once and capacity-frozen.
func (st *scopeEnvState) chainView(chain []*scopeEnvState) envAssignments {
	total := len(st.taint)
	for i := range chain {
		total += scopeVisibleLen(chain, i)
	}
	ops := make([]envOp, 0, total)
	for i := len(chain) - 1; i >= 0; i-- {
		ops = append(ops, chain[i].ops[:scopeVisibleLen(chain, i)]...)
	}
	for name := range st.taint {
		ops = append(ops, envOp{kind: 't', key: name})
	}
	out := envAssignments{ops: ops}
	out.ops = out.ops[:len(out.ops):len(out.ops)]
	return out
}

// scopeVisibleLen is the number of ops chain position i contributes to
// a view: everything the state itself holds, truncated to the length
// its direct child froze at fork time for every non-root position.
func scopeVisibleLen(chain []*scopeEnvState, i int) int {
	n := len(chain[i].ops)
	if i == 0 {
		return n
	}
	if lim := chain[i-1].baseLen; lim < n {
		return lim
	}
	return n
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
	// mawk(1) MAWK_LONG_OPTIONS rewrites how mawk treats GNU --long
	// options at runtime (ignore/warn/allow), desynchronizing the guard's
	// gawk-shaped long-option parse from what the interpreter actually
	// consumes — the positional program escapes review (v6.2.2 Oracle R8
	// R8-MF-3).
	"MAWK_LONG_OPTIONS": true,
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
	// GNU tar prepends $TAR_OPTIONS to its own argv before parsing the
	// command line: --use-compress-program / --checkpoint-action=exec /
	// --to-command / -I all hand a command string to tar outside every
	// argv-level tar screening (v6.2.2 Oracle R9 R9-MF-4).
	"TAR_OPTIONS": true,
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
		strings.HasPrefix(key, "GIT_CONFIG") ||
		// bash auto-imports BASH_FUNC_<name>%%=() { ... } as a shell
		// function, hijacking builtins and external commands alike
		// (v6.2.2 Oracle R9 R9-MF-4).
		strings.HasPrefix(key, "BASH_FUNC_") {
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
			if i+1 < len(argv) && !isDynamicArg(argv[i+1]) {
				i += 2 // -a name
				continue
			}
			// R26-Oracle-M4 / R26-Reviewer-#2: a trailing -a whose name
			// operand never arrived fails closed exactly at the slice bound
			// (merged with the dynamic-operand verdict).
			return len(argv), true
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
					if i < len(argv) && !isDynamicArg(argv[i]) {
						i++ // name is the next argv
						break
					}
					// R26-Oracle-M4: a bare cluster-trailing -a never received
					// its name operand — fail closed exactly at the slice
					// bound (merged with the dynamic verdict).
					return len(argv), true
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

// wrapperPathTracker is the O(1)-per-op incremental untrusted-PATH
// tracker of the single-pass checked wrapper peel (R26-Oracle-M2 /
// R26-Reviewer-#1/#3): it mirrors effectivePATHFrom + pathUntrusted
// exactly — the control-flow uncertainty marker op ('t') is sticky
// across every later op, while the unresolvable placeholder an
// over-budget self-reference expansion or a placeholder-carrying value
// installs can be cleared by a later env -i/-u PATH or overwritten by
// a constant assignment — but applies each op ONCE as it is appended
// instead of rescanning the whole accumulated op list at every layer
// (the pre-R26 scan re-ran pathUntrusted per bare wrapper layer,
// scaling quadratically on deep env chains).
type wrapperPathTracker struct {
	cur     string // running effective PATH value (never materializes expansions twice)
	stickyT bool   // a 't' op on PATH was seen — pathUntrusted's first loop arm
	caller  bool   // caller.pathUntrusted() captured at construction
}

// newWrapperPathTracker seeds the tracker with the inherited op list
// replayed over basePath plus the caller identity's own sticky verdict.
func newWrapperPathTracker(basePath string, inherited envAssignments, caller callerIdentity) *wrapperPathTracker {
	tk := &wrapperPathTracker{cur: basePath, caller: caller.pathUntrusted()}
	tk.applyOps(inherited.ops)
	return tk
}

// untrusted reports the tracker's current verdict (identical to
// envAssignments.pathUntrusted(basePath) || caller.pathUntrusted() of
// the ops applied so far).
func (tk *wrapperPathTracker) untrusted() bool {
	return tk.stickyT || strings.Contains(tk.cur, cmdSubPlaceholder) || tk.caller
}

// applyOps folds one batch of newly appended env ops into the running
// state exactly like the effectivePATHFrom replay loop.
func (tk *wrapperPathTracker) applyOps(ops []envOp) {
	for _, op := range ops {
		switch op.kind {
		case 'c':
			tk.cur = ""
		case 'u':
			if op.key == "PATH" {
				tk.cur = ""
			}
		case 't':
			if op.key == "PATH" {
				tk.stickyT = true
				tk.cur = cmdSubPlaceholder
			}
		case 'a':
			if op.key == "PATH" {
				expanded, ok := expandPathSelfRefs(op.value, tk.cur)
				if !ok {
					tk.cur = cmdSubPlaceholder
					continue
				}
				tk.cur = expanded
			}
		}
	}
}

// peelFlagZone consumes one wrapper option zone shared by the time/nice/
// setsid flag families and the command/builtin builtin families
// (extracted for the R26 single-pass peel refactor): the scan consumes
// dashed option words until `--` or the first operand. dynOperandFC
// selects the two per-family orderings — the external-wrapper families
// treat a dynamic non-dash word as a fail-closed split (the word may
// re-split into further options at runtime), while the builtin families
// end the zone at the first non-dash word BEFORE any dynamic check.
// breakBareDash selects whether a bare `-` ends the zone (external
// families) or is consumed as an option word (command/builtin). valued
// reports a separate-value option (-n/--adjustment for nice,
// -o/--output/-f/--format for time). A trailing valued option missing
// its operand fails closed at exactly len(argv) (R26-Oracle-M4 — never
// past the slice bound). Returns (ni, fc): ni is the index the command
// head continues at and never exceeds len(argv).
func peelFlagZone(argv []string, i int, dynOperandFC, breakBareDash bool, valued func(string) bool) (int, bool) {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1, false
		}
		if dynOperandFC && isDynamicArg(a) {
			return i, true
		}
		if !strings.HasPrefix(a, "-") || breakBareDash && a == "-" {
			return i, false
		}
		if !dynOperandFC && isDynamicArg(a) {
			return i, true
		}
		if valued != nil && valued(a) {
			if i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return i, true
			}
			if i+1 >= len(argv) {
				return len(argv), true
			}
			i += 2
			continue
		}
		i++
	}
	return i, false
}

func timeValuedOpt(a string) bool {
	return a == "-o" || a == "--output" || a == "-f" || a == "--format"
}

func niceValuedOpt(a string) bool {
	return a == "-n" || a == "--adjustment"
}

func peelWrappers(argv []string) (headArgv []string, splitPayloads []string, envAs envAssignments, exhausted bool) {
	return peelWrappersCore(argv, nil)
}

// peelLayerOutcome carries one consumed wrapper layer back into
// peelWrappersCore (extracted for the R26 complexity budget): rest is
// the argv tail replacing everything from the layer head onward (env
// rewrites the operand stream wholesale), i is the index into rest the
// walk continues from, env carries the accumulated env ops after an
// env layer, split carries any -S payloads, stop reports the
// command-query early end, and fc reports the fail-closed dynamic or
// missing-operand verdict.
type peelLayerOutcome struct {
	rest  []string
	i     int
	env   envAssignments
	split []string
	stop  bool
	fc    bool
}

// peelWrapperLayer consumes exactly one wrapper layer of argv whose
// head sits at index i (resolving to base) exactly like the pre-R26
// per-base cases of peelWrappers (extracted so the core walk carries
// no per-base option-zone branching): every zone consumer shares the
// same skipper helpers the validation scan uses, so the two cannot
// drift apart. Indices are ABSOLUTE positions in argv; the env case
// returns rest as the spliced replacement operand stream (the walk
// restarts it at index 0 exactly like the pre-R26 splice).
func peelWrapperLayer(argv []string, i int, base string, envAs envAssignments) peelLayerOutcome {
	switch base {
	case "time":
		ni, fc := peelFlagZone(argv, i+1, true, true, timeValuedOpt)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "env":
		rest, payloads, ea := skipEnvOperands(argv, i+1, envAs)
		return peelLayerOutcome{rest: rest, i: 0, env: ea, split: payloads}
	case "command":
		if isCommandQuery(argv[i+1:]) {
			return peelLayerOutcome{rest: argv, i: i, stop: true}
		}
		ni, fc := peelFlagZone(argv, i+1, false, false, nil)
		return peelLayerOutcome{rest: argv, i: skipDashDash(argv, ni), fc: fc}
	case "builtin":
		ni, fc := peelFlagZone(argv, i+1, false, false, nil)
		return peelLayerOutcome{rest: argv, i: skipDashDash(argv, ni), fc: fc}
	case "exec":
		ni, fc := skipExecArgs(argv, i+1)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "nohup":
		return peelLayerOutcome{rest: argv, i: skipDashDash(argv, i+1)}
	case "setsid":
		ni, fc := peelFlagZone(argv, i+1, true, true, nil)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "nice":
		ni, fc := peelFlagZone(argv, i+1, true, true, niceValuedOpt)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "timeout":
		ni, fc := skipTimeoutArgs(argv, i+1)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "stdbuf":
		ni, fc := skipStdbufArgs(argv, i+1)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "busybox":
		return peelLayerOutcome{rest: argv, i: i + 1}
	case "ionice":
		ni, fc := skipIoniceArgs(argv, i+1)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "taskset":
		ni, fc := skipTasksetArgs(argv, i+1)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "chrt":
		ni, fc := skipChrtArgs(argv, i+1)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	case "strace", "ltrace":
		ni, fc := skipStraceArgs(argv, i+1)
		return peelLayerOutcome{rest: argv, i: ni, fc: fc}
	}
	return peelLayerOutcome{rest: argv, i: len(argv) + 1}
}

// peelWrappersCore is the single shared wrapper-peel walk behind
// peelWrappers and the R26 checked peel (R26-Oracle-M2/M4 /
// R26-Reviewer-#1/#2/#3): a nil tracker reproduces the pre-R26 peel
// byte-for-byte, while a non-nil tracker validates EVERY bare
// slash-free external wrapper identity BEFORE that layer's options or
// env operands are consumed — the wrapper's own resolution owes itself
// to the environment in force when the kernel looked it up, never to
// the operands only the next layer inherits. Pure KEY=VAL assignments
// and shellNoopWords keep the peel's depth-- step exemption exactly;
// the tracker folds every op as it is appended (O(1) per op), so the
// validation never rescans the accumulated environment. A validation
// failure IS the exhaustion verdict: the consumer identity is
// unknowable, never a confirmed shell.
func peelWrappersCore(argv []string, tk *wrapperPathTracker) (headArgv []string, splitPayloads []string, envAs envAssignments, exhausted bool) {
	i := 0
	depth := 0
	for ; depth < peelWrapperMaxSteps && i < len(argv); depth++ {
		a := argv[i]
		if isAssignWord(a) {
			before := len(envAs.ops)
			envAs.addAssign(a)
			if tk != nil {
				tk.applyOps(envAs.ops[before:])
			}
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
		base := filepath.Base(a)
		if !isPeeledWrapperBase(base) {
			return argv[i:], splitPayloads, envAs, false
		}
		if tk != nil && wrapperNeedsPathValidation(base, a) && tk.untrusted() {
			// R26-Oracle-M2 / R26-Reviewer-#1: the bare external wrapper's
			// own resolution depended on an untrusted PATH — validated
			// against the environment in force BEFORE this layer's
			// operands can rewrite it.
			return argv[i:], splitPayloads, envAs, true
		}
		before := len(envAs.ops)
		out := peelWrapperLayer(argv, i, base, envAs)
		switch {
		case out.stop:
			return argv[out.i:], splitPayloads, envAs, false
		case out.fc:
			if out.i > len(argv) {
				out.i = len(argv)
			}
			return argv[out.i:], splitPayloads, envAs, true
		case base == "env":
			envAs = out.env
			if tk != nil {
				tk.applyOps(envAs.ops[before:])
			}
			splitPayloads = append(splitPayloads, out.split...)
			// env rewrites the operand stream wholesale: rest replaces the
			// argv exactly like the pre-R26 splice — reassignment only,
			// never a copy or write-through of the caller's backing array
			// (skipEnvOperands either re-slices the input or builds its own
			// backing for -S payloads).
			argv = out.rest
			i = 0
		default:
			i = out.i
		}
	}
	if i > len(argv) {
		i = len(argv)
		return argv[i:], splitPayloads, envAs, true
	}
	return argv[i:], splitPayloads, envAs, depth >= peelWrapperMaxSteps
}

// wrapperNeedsPathValidation reports whether one adopted wrapper layer
// owes its own resolution to PATH (R26-Oracle-M2 / R26-Reviewer-#1):
// every EXTERNAL wrapper (env/nice/nohup/timeout/stdbuf/setsid/busybox/
// ionice/taskset/chrt/strace/ltrace/time) spelled without a slash. Shell
// builtins (command/builtin/exec) resolve inside the shell process
// itself — never through PATH — and slash-carrying spellings carry
// their own resolution, so both are exempt.
func wrapperNeedsPathValidation(base, word string) bool {
	if strings.ContainsRune(word, '/') {
		return false
	}
	switch base {
	case "command", "builtin", "exec":
		return false
	}
	return true
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
	return peelWrappersAndWrapperAliasesChecked(argv, pathEnv, caller, nil)
}

// peelWrappersAndWrapperAliasesChecked is peelWrappersAndWrapperAliases
// plus the R26 untrusted-PATH adoption validation (R26-Oracle-M2 /
// R26-Reviewer-#1, wired for the xargs inner open-code-slot target): a
// non-nil tracker validates every bare external wrapper layer BEFORE
// its operands are consumed AND the final peeled head when that head
// is itself a bare slash-free name. The alias loop additionally keeps
// the original spelling's slash identity across the rewrite
// (R26-Oracle-M3 / R26-Reviewer-#4): a fixed-path wrapper alias
// (./myenv -> /usr/bin/env) must never degrade into a bare name the
// next layer would re-resolve through PATH.
func peelWrappersAndWrapperAliasesChecked(argv []string, pathEnv string, caller callerIdentity, tk *wrapperPathTracker) (head []string, envAs envAssignments, effPath string, exhausted bool) {
	cur := argv
	effPath = pathEnv
	for steps := 0; steps < peelWrapperMaxSteps; steps++ {
		before := len(envAs.ops)
		h, _, ea, ex := peelWrappersCore(cur, tk)
		envAs = envAs.merged(ea)
		effPath = ea.effectivePATHFrom(effPath)
		caller = caller.seededWith(ea)
		if tk != nil {
			tk.applyOps(envAs.ops[before:])
		}
		if ex || len(h) == 0 {
			return h, envAs, effPath, ex
		}
		hb := filepath.Base(h[0])
		// A PATH alias whose typed name is not a wrapper but resolves to
		// one (myenv -> env, mytimeout -> timeout) needs its options peeled
		// too: rewrite the head to the resolved wrapper and loop.
		if rb := canonicalResolvedBase(resolveHeadBase(h[0], effPath, caller.screenCwd())); rb != "" && rb != hb && isPeeledWrapperBase(rb) {
			cur = append([]string{rewriteKeepSlashIdentity(h[0], rb)}, h[1:]...)
			continue
		}
		// R26-Oracle-M2 / R26-Reviewer-#1: the FINAL peeled head owes its
		// identity to the same untrusted PATH when it carries no slash —
		// the xargs inner open-code-slot target must never re-read it as
		// a confirmed consumer.
		if tk != nil && !strings.ContainsRune(h[0], '/') && tk.untrusted() {
			return h, envAs, effPath, true
		}
		return h, envAs, effPath, false
	}
	return cur, envAs, effPath, true
}

// rewriteKeepSlashIdentity preserves the fixed-path identity of an
// original head spelling across a canonical/resolved rewrite
// (R26-Oracle-M3 / R26-Reviewer-#4): a slash-free original spelling
// resolves through PATH either way, so the canonical name applies
// verbatim; a slash-carrying spelling joins its directory onto the
// canonical name, and when filepath.Join cleans the slash away (the
// directory is "." or cancels out like "sub/..") the explicit "./"
// prefix is restored so the rewritten head NEVER degrades into a bare
// PATH-dependent name the original spelling never was.
func rewriteKeepSlashIdentity(origHead, canon string) string {
	if !strings.ContainsRune(origHead, '/') {
		return canon
	}
	joined := filepath.Join(filepath.Dir(origHead), canon)
	if !strings.ContainsRune(joined, '/') {
		return "./" + joined
	}
	return joined
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
			// R26-Oracle-M4 / R26-Reviewer-#2: the trailing valued option
			// missing its operand fails closed exactly at the slice bound
			// (the pre-R26 unclamped i+=2 overflowed it). The fail-closed
			// index is irrelevant to every consumer, so the trailing and
			// dynamic verdicts merge into one return.
			if i+1 >= len(argv) || isDynamicArg(argv[i+1]) {
				return len(argv), true
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
			// R26-Oracle-M4 / R26-Reviewer-#2: trailing valued option missing
			// its operand fails closed at the bound (merged return).
			if i+1 >= len(argv) || isDynamicArg(argv[i+1]) {
				return len(argv), true
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
			// R26-Oracle-M4 / R26-Reviewer-#2: trailing valued option missing
			// its operand fails closed at the bound (merged return).
			if i+1 >= len(argv) || isDynamicArg(argv[i+1]) {
				return len(argv), true
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
			// R26-Oracle-M4 / R26-Reviewer-#2: trailing valued option missing
			// its operand fails closed at the bound (merged return).
			if i+1 >= len(argv) || isDynamicArg(argv[i+1]) {
				return len(argv), true
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
			return flockAfterLock(argv, i)
		case strings.HasPrefix(a, "--") || a == "-c":
			if txt, hit := flockCommandWordHit(a, argv, i); hit {
				return len(argv), txt
			}
			i = skipFlockLong(argv, i)
			if i < 0 {
				return len(argv), cmdSubPlaceholder
			}
		case strings.HasPrefix(a, "-") && len(a) > 2:
			// Short cluster: walk the letters (v6.2.2 MF-9) — valued letters
			// w/E/d end the cluster, 'c' is the command flag whose glued tail
			// or next argv is the shell string.
			idx, txt, done := flockClusterScan(argv, i)
			if done {
				return idx, txt
			}
			i = idx
		case strings.HasPrefix(a, "-"):
			if i+1 < len(argv) && flockShortTakesValue(a) {
				if isDynamicArg(argv[i+1]) && !isSingleWordSplitSafe(argv[i+1]) {
					return len(argv), cmdSubPlaceholder
				}
				i += 2
			} else {
				i++
			}
		default:
			i++
			return flockAfterLock(argv, i)
		}
	}
	return i, ""
}

// flockShortTakesValue reports whether a bare two-letter flock short option
// consumes a separate operand (-w/-E take values; -d takes an fd).
func flockShortTakesValue(a string) bool {
	return a == "-w" || a == "-E" || a == "-d"
}

// flockMatchLong resolves one long-option name (no leading dashes, no
// =value) against util-linux flock's real getopt_long table with GNU
// unique-prefix abbreviation (v6.2.2 R3 R2-MF-4): --com abbreviates
// --command, --time abbreviates --timeout, --con abbreviates
// --conflict-exit-code. The second return value is false when the name
// matches no option or is ambiguous (getopt_long rejects ambiguities
// with an error, so the caller treats them conservatively).
func flockMatchLong(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	// util-linux flock's REAL getopt_long table (checked against util-linux
	// flock.c and the bash-completion data): the phantom fd/lock-file/debug
	// spellings and the dash-less nofork/nonblocking forms never existed —
	// the real boolean aliases are --no-fork/--nb (v6.2.2 R3 R3-MF-3).
	candidates := []string{
		"command", "conflict-exit-code", "close", "exclusive", "fcntl",
		"help", "nb", "no-fork", "nonblock", "shared", "timeout",
		"unlock", "verbose", "version", "wait",
	}
	match := ""
	hits := 0
	for _, c := range candidates {
		if c == name {
			return c, true
		}
		if strings.HasPrefix(c, name) {
			hits++
			match = c
		}
	}
	if hits == 1 {
		return match, true
	}
	return "", false
}

// flockLongTakesValue reports whether a resolved flock long option consumes
// a separate value operand when spelled without =glue.
func flockLongTakesValue(full string) bool {
	return full == "timeout" || full == "conflict-exit-code" || full == "wait"
}

// flockCommandWordHit screens one `--` word of flock's option zone for the
// --command flag under GNU unique-prefix abbreviation: the glued or
// separate command text is returned with hit=true. This is shared by
// skipFlockArgs' option zone and flockAfterLock's post-lock zone so the
// two positions cannot drift (v6.2.2 R3 R2-MF-4).
func flockCommandWordHit(a string, argv []string, i int) (cmdText string, hit bool) {
	if a == "-c" {
		if i+1 < len(argv) {
			return argv[i+1], true
		}
		return "", true
	}
	if !strings.HasPrefix(a, "--") {
		return "", false
	}
	name, val, hasVal := a[2:], "", false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, val, hasVal = name[:k], name[k+1:], true
	}
	full, ok := flockMatchLong(name)
	if !ok || full != "command" {
		return "", false
	}
	if hasVal {
		return val, true
	}
	if i+1 < len(argv) {
		return argv[i+1], true
	}
	return "", true
}

// skipFlockLong consumes one `--` long-option word of flock's option zone
// and returns the index to continue from, or -1 when a dynamic operand
// fails closed. -F/--fcntl are BOOLEAN flags in util-linux flock (never
// valued — v6.2.2 MF-9), so they consume only their own word; GNU
// unique-prefix abbreviations resolve through flockMatchLong (v6.2.2 R3).
func skipFlockLong(argv []string, i int) int {
	a := argv[i]
	name := a[2:]
	if k := strings.IndexByte(name, '='); k >= 0 {
		// Glued values consume only their own word whatever the arity.
		return i + 1
	}
	full, ok := flockMatchLong(name)
	if ok && flockLongTakesValue(full) {
		if i+1 < len(argv) && isDynamicArg(argv[i+1]) && !isSingleWordSplitSafe(argv[i+1]) {
			return -1
		}
		return i + 2
	}
	if !ok {
		// An unknown/ambiguous long option's arity is statically unknowable:
		// fail CLOSED instead of guessing a width — swallowing the next word
		// here let `--no-fork`/`--nb` eat the lock file and slide the real
		// command head out of review (v6.2.2 R3 R3-MF-3 regression).
		return -1
	}
	return i + 1 // boolean or glued-value long option
}

// flockClusterScan walks one short-option cluster of flock's option zone.
// done reports the scan produced a final answer: idx/txt are the return
// values of skipFlockArgs. Otherwise idx is the index to continue from.
func flockClusterScan(argv []string, i int) (idx int, txt string, done bool) {
	a := argv[i]
	consumedNext := false
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'c':
			if tail := a[j+1:]; tail != "" {
				return len(argv), tail, true
			}
			if i+1 < len(argv) {
				return len(argv), argv[i+1], true
			}
			return len(argv), "", true
		case 'w', 'E', 'd':
			if j+1 >= len(a) {
				consumedNext = true
			}
			j = len(a) // valued letter ends the cluster (glued tail or next argv)
		}
	}
	if consumedNext {
		if i+1 < len(argv) && isDynamicArg(argv[i+1]) && !isSingleWordSplitSafe(argv[i+1]) {
			return len(argv), cmdSubPlaceholder, true
		}
		return i + 2, "", false
	}
	return i + 1, "", false
}

// flockAfterLock checks what follows flock's lock file/fd operand: a
// -c/--command flag (glued, separate or GNU-abbreviated) yields the shell
// string, anything else is the command argv start.
func flockAfterLock(argv []string, i int) (int, string) {
	if i < len(argv) {
		if txt, hit := flockCommandWordHit(argv[i], argv, i); hit {
			return len(argv), txt
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
			if i+1 < len(argv) && !isDynamicArg(argv[i+1]) {
				i += 2 // separate value operand
				continue
			}
			// R26-Oracle-M4 / R26-Reviewer-#2: the trailing valued option
			// missing its operand fails closed exactly at the slice bound
			// (merged with the dynamic-operand verdict — the fail-closed
			// index is irrelevant to every consumer).
			return len(argv), true
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
	rest, payloads, outEnv, _ := skipEnvOperandsToken(argv, i, envAs, "", 0)
	return rest, payloads, outEnv
}

// skipEnvOperandsToken is skipEnvOperands' implementation carrying the
// xargs/find replacement token and the recursion depth (v6.2.2 Oracle R5
// R5-MF-2): when an -S/--split-string payload itself CONTAINS the token,
// splitTokHit propagates up through every nested split recursion, so an
// outer `env -S` whose split re-spells an INNER `-S` option word
// (`env -S "-S" "find . -name {}"` / `env "-S-S" ...`) cannot digest the
// inner payload inside the same call and hide it from
// wrapperChainEnvSplitHasToken. Depth beyond peelWrapperMaxSteps fails
// closed through the envUnknownLongPrefix payload channel.
func skipEnvOperandsToken(argv []string, i int, envAs envAssignments, token string, depth int) (rest, payloads []string, outEnv envAssignments, splitTokHit bool) {
	if depth > peelWrapperMaxSteps {
		return argv[i:], []string{envUnknownLongPrefix + "split depth"}, envAs, false
	}
	// v6.2.2 Oracle R9 R9-MF-3: GNU coreutils env(1) consumes ANY operand
	// containing '=' as an environment assignment — POSIX-key or not
	// (a.b=1, a-b=1, BASH_FUNC_echo%%=...) and even after the `--`
	// terminator (-x=1). endOpts latches after `--` so the assignment peel
	// continues while option parsing stops; a dynamic word is exempted
	// from the fail-closed verdict ONLY when it is a single-word-safe
	// KEY=VALUE shape (unquoted `env FOO=$X` field-splits `FOO=1 pig` into
	// a command head at runtime — unlike a shell prefix assignment, here
	// the word is env's argv).
	endOpts := false
	for i < len(argv) {
		a := argv[i]
		if isDynamicArg(a) && !(strings.IndexByte(a, '=') > 0 && isSingleWordSplitSafe(a)) {
			payloads = append(payloads, envUnknownLongPrefix+"dynamic option")
			return argv[i:], payloads, envAs, splitTokHit
		}
		switch {
		case !endOpts && a == "--":
			endOpts = true
			i++
		case !endOpts && a == "-":
			envAs.ops = append(envAs.ops, envOp{kind: 'c'})
			i++
		case !endOpts && strings.HasPrefix(a, "--"):
			ls := skipEnvLongToken(argv, i, envAs, token, depth, a, splitTokHit)
			if ls.done {
				return ls.rest, append(payloads, ls.payloads...), ls.envAs, ls.hit
			}
			payloads = append(payloads, ls.payloads...)
			envAs, splitTokHit = ls.envAs, ls.hit
			if ls.early {
				return argv[ls.ni:], payloads, envAs, splitTokHit
			}
			i = ls.ni
		case !endOpts && strings.HasPrefix(a, "-"):
			cl := skipEnvClusterToken(argv, i, envAs, token, depth, a, splitTokHit)
			if cl.done {
				return cl.rest, append(payloads, cl.payloads...), cl.envAs, cl.hit
			}
			payloads = append(payloads, cl.payloads...)
			envAs, splitTokHit = cl.envAs, cl.hit
			if cl.early {
				return argv[cl.ni:], payloads, envAs, splitTokHit
			}
			i = cl.ni
		case strings.IndexByte(a, '=') >= 0:
			envAs.addAssign(a)
			i++
		default:
			return argv[i:], payloads, envAs, splitTokHit
		}
	}
	return argv[i:], payloads, envAs, splitTokHit
}

// envTokenStep carries one option word's outcome back to
// skipEnvOperandsToken's operand loop (v6.2.2 Oracle R5 R5-MF-2 — extracted
// so the walk stays under the complexity budget): ni is the loop index to
// continue from, done reports a nested -S recursion whose rest/payloads/
// envAs/hit ARE the whole scan's result, early reports the walk ends at ni
// (unknown option or dynamic operand fail-closed).
type envTokenStep struct {
	ni       int
	rest     []string
	payloads []string
	envAs    envAssignments
	hit      bool
	done     bool
	early    bool
}

// skipEnvLongToken handles one `--` long option word of
// skipEnvOperandsToken: envMatchLong-resolved arities consume their
// operands into envAs, --split-string rewrites the operand stream through
// the same nested recursion as the short -S form, and unknown or
// operand-less spellings fail closed through the payload channel.
func skipEnvLongToken(argv []string, i int, envAs envAssignments, token string, depth int, a string, splitTokHit bool) envTokenStep {
	st := envTokenStep{envAs: envAs, hit: splitTokHit}
	name, val, hasVal := envSplitLong(a)
	payloadMissing := func() {
		st.payloads = append(st.payloads, envUnknownLongPrefix+"missing operand "+a)
		st.ni = i + 1
	}
	switch envMatchLong(name) {
	case "ignore-environment":
		st.envAs.ops = append(st.envAs.ops, envOp{kind: 'c'})
		st.ni = i + 1
	case "null", "list-signal-handling", "debug", "help", "version":
		st.ni = i + 1
	case "unset":
		if hasVal {
			st.envAs.ops = append(st.envAs.ops, envOp{kind: 'u', key: val})
			st.ni = i + 1
		} else if i+1 < len(argv) {
			st.envAs.ops = append(st.envAs.ops, envOp{kind: 'u', key: argv[i+1]})
			st.ni = i + 2
		} else {
			payloadMissing()
		}
	case "chdir", "argv0":
		isChdir := envMatchLong(name) == "chdir"
		switch {
		case hasVal:
			if isChdir {
				st.envAs.ops = append(st.envAs.ops, envOp{kind: 'd', value: val})
			}
			st.ni = i + 1
		case i+1 < len(argv):
			if isDynamicArg(argv[i+1]) && !isSingleWordSplitSafe(argv[i+1]) {
				st.payloads = append(st.payloads, envUnknownLongPrefix+"dynamic option")
				// v6.2.2 Oracle R9 R9-MF-2: end the scan PAST the unsafe value
				// (ni falls through to i+2 below, same as the short-cluster
				// path in envValuedLetterOp) — ni=i+1 left the glob word in
				// the rest stream, where peelWrappers surfaced it as a bare
				// "dynamic command head" instead of the precise env verdict.
				st.ni, st.early = i+2, true
				return st
			}
			if isChdir {
				st.envAs.ops = append(st.envAs.ops, envOp{kind: 'd', value: argv[i+1]})
			}
			st.ni = i + 2
		default:
			payloadMissing()
		}
	case "split-string":
		return envSplitStringToken(argv, i, st, token, depth, val, hasVal)
	case "block-signal", "default-signal", "ignore-signal":
		st.ni = i + 1
	default:
		st.payloads = append(st.payloads, envUnknownLongPrefix+a)
		st.ni = i + 1
	}
	return st
}

// envSplitStringToken handles one --split-string/-S payload of
// skipEnvOperandsToken: the payload words are re-parsed as env's own argv
// through the depth+1 recursion, with the token-presence bit propagated
// upward (v6.2.2 Oracle R5 R5-MF-2).
func envSplitStringToken(argv []string, i int, st envTokenStep, token string, depth int, val string, hasVal bool) envTokenStep {
	var payload string
	havePayload := false
	if hasVal {
		payload, havePayload, st.ni = val, true, i+1
	} else if i+1 < len(argv) {
		payload, havePayload, st.ni = argv[i+1], true, i+2
	} else {
		st.ni = i + 1
	}
	if !havePayload {
		st.payloads = append(st.payloads, envUnknownLongPrefix+"-S/--split-string")
		return st
	}
	if isDynamicArg(payload) {
		st.payloads = append(st.payloads, envUnknownLongPrefix+"dynamic option")
		return st
	}
	if token != "" && strings.Contains(payload, token) {
		st.hit = true
	}
	words, bad := splitEnvSPayload(payload)
	if bad {
		st.payloads = append(st.payloads, envUnknownLongPrefix+"-S/--split-string")
		return st
	}
	rest := append(append([]string{}, words...), argv[st.ni:]...)
	rem, moreP, outEnv, innerHit := skipEnvOperandsToken(rest, 0, st.envAs, token, depth+1)
	st.rest, st.payloads, st.envAs, st.hit, st.done = rem, append(st.payloads, moreP...), outEnv, st.hit || innerHit, true
	return st
}

// skipEnvClusterToken handles one short-option cluster word of
// skipEnvOperandsToken: valued letters consume their glued tail or the
// next argv, -S rewrites the operand stream through envClusterSplitS,
// and unknown letters fail closed.
func skipEnvClusterToken(argv []string, i int, envAs envAssignments, token string, depth int, a string, splitTokHit bool) envTokenStep {
	st := envTokenStep{envAs: envAs, hit: splitTokHit}
	consumedNext := false
	unknown := false
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'i':
			st.envAs.ops = append(st.envAs.ops, envOp{kind: 'c'})
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
				st.payloads = append(st.payloads, envUnknownLongPrefix+"missing operand "+a)
				unknown = true
				j = len(a)
				break
			}
			if opt == 'S' {
				if done, ok := envClusterSplitS(argv, i, &st, optVal, consumedNext, token, depth); ok {
					return done
				}
				j = len(a)
				break
			}
			if envValuedLetterOp(&st, opt, optVal, consumedNext) {
				unknown = true
				j = len(a)
			}
		default:
			st.payloads = append(st.payloads, envUnknownLongPrefix+a)
			unknown = true
			j = len(a)
		}
	}
	if consumedNext {
		st.ni = i + 2
	} else {
		st.ni = i + 1
	}
	if unknown {
		st.early = true
	}
	return st
}

// envValuedLetterOp applies env's non--S valued short letters (u/C/a) to
// the operand state, reporting whether the letter failed closed on a
// dynamic separate operand (v6.2.2 Oracle R5 R5-MF-2 extraction).
func envValuedLetterOp(st *envTokenStep, opt byte, optVal string, consumedNext bool) bool {
	switch opt {
	case 'u':
		st.envAs.ops = append(st.envAs.ops, envOp{kind: 'u', key: optVal})
	case 'C':
		if consumedNext && isDynamicArg(optVal) && !isSingleWordSplitSafe(optVal) {
			st.payloads = append(st.payloads, envUnknownLongPrefix+"dynamic option")
			return true
		}
		st.envAs.ops = append(st.envAs.ops, envOp{kind: 'd', value: optVal})
	case 'a':
		if consumedNext && isDynamicArg(optVal) && !isSingleWordSplitSafe(optVal) {
			st.payloads = append(st.payloads, envUnknownLongPrefix+"dynamic option")
			return true
		}
	}
	return false
}

// envClusterSplitS handles the -S letter of one env short cluster: the
// payload words are re-parsed as env's own argv through the depth+1
// recursion with the token-presence bit propagated upward (v6.2.2 Oracle
// R5 R5-MF-2). ok reports the payload was parseable — st is then the scan's
// final state (done); a malformed or dynamic payload falls back to the
// caller's payload channel with ok false.
func envClusterSplitS(argv []string, i int, st *envTokenStep, optVal string, consumedNext bool, token string, depth int) (envTokenStep, bool) {
	words, bad := splitEnvSPayload(optVal)
	if bad || isDynamicArg(optVal) {
		st.payloads = append(st.payloads, envUnknownLongPrefix+"-S/--split-string")
		return *st, false
	}
	if token != "" && strings.Contains(optVal, token) {
		st.hit = true
	}
	start := i
	if consumedNext {
		start = i + 1
	}
	rest := append(append([]string{}, words...), argv[start+1:]...)
	rem, moreP, outEnv, innerHit := skipEnvOperandsToken(rest, 0, st.envAs, token, depth+1)
	st.rest, st.envAs, st.hit, st.done = rem, outEnv, st.hit || innerHit, true
	st.payloads = append(st.payloads, moreP...)
	return *st, true
}

// unwrapShellArgv reports whether argv (starting at a resolved command head)
// is a `shell -c` shape: argv[0] a POSIX-ish shell and an option bundle
// containing 'c' before the first non-flag argument. POSIX shells parse -c
// as a BOOLEAN flag and keep scanning options AFTER it — the command string
// is the FIRST NON-OPTION WORD (or the word right after `--`), not the word
// immediately following the -c cluster (v6.2.2 Oracle R6 R6-MF-1: the
// immediate-return model let `sh -co errexit -o pipefail 'pig'` and
// `sh -co errexit -- 'pig'` slide a real code word past the unwrap). A
// cluster tail after 'c' (`-c"pig"` glued spelling) is prepended to that
// script as an extra line — never dropped — and letters after a bare 'c'
// keep parsing as flags. -o/+o/-O/+O/--rcfile operands are skipped on both
// sides of the -c letter.
func unwrapShellArgv(argv []string) (shellText string, has bool) {
	if len(argv) < 2 {
		return "", false
	}
	switch filepath.Base(argv[0]) {
	case "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash":
	default:
		return "", false
	}
	sawC := false
	tail := ""
	for i := 1; i < len(argv); i++ {
		text, has, ni, done, isCluster := unwrapShellWordStep(argv, i, sawC, tail)
		if done {
			return text, has
		}
		if !isCluster {
			// A NON-cluster word (long option, option-name pair, terminator)
			// is settled here — it must NEVER fall through to the short-cluster
			// scanner, whose byte-wise walk would misread single-word long
			// options as flag letters (`bash --restricted` colliding with 'c'
			// — v6.2.2 Oracle R7 R7-MF-2).
			i = ni
			continue
		}
		// A cluster word the step could not settle: it may still mint the
		// -c state, so re-run the cluster handler here.
		skipped, newC, newTail, dyn := unwrapShellClusterWord(argv, i, sawC)
		if dyn != "" {
			return dyn, true
		}
		if newC && !sawC {
			sawC, tail = true, newTail
		}
		i += skipped
	}
	if sawC {
		// No command-string word at all: a recorded ambiguous tail stands
		// alone as the screened text (`["sh","-c\"pig\""]`).
		return tail, tail != ""
	}
	return "", false
}

// unwrapShellWordStep settles the non-cluster words of unwrapShellArgv's
// scan (extracted — v6.2.2 Oracle R6 R6-MF-1): dynamic words, the `--`/`-`
// terminators, `--` long options, the bare -o/+o/-O/+O option-name pair and
// the first non-option positional. done reports the scan ends here with
// text/has; ni is the index the caller continues from; isCluster reports
// the word is an unresolved SHORT-option cluster the caller must scan —
// everything else (including every single-word `--` long option) is fully
// settled here and must never reach the byte-wise cluster walk (v6.2.2
// Oracle R7 R7-MF-2 `bash --restricted`).
func unwrapShellWordStep(argv []string, i int, sawC bool, tail string) (text string, has bool, ni int, done, isCluster bool) {
	a := argv[i]
	if isDynamicArg(a) {
		if sawC {
			// The command string slot itself is dynamic — hand it to the
			// downstream dynamic-payload verdict (a peel/`$0` argv word is
			// screened as data only when the STATIC command string passes
			// its own screen).
			return unwrapShellJoinTail(tail, a), true, i, true, false
		}
		return "", false, i, true, false // let hasDynamicInterpOption / peel catch it
	}
	if a == "--" || a == "-" || (sawC && a == "+") {
		// POSIX: an argument of `-` is equivalent to `--` (and dash treats a
		// bare `+` the same way) — option parsing ENDS here and the word
		// right after the terminator is the -c command string when one is
		// pending (v6.2.2 Oracle R7 R7-MF-3 path B `sh -c - 'pig'`).
		if !sawC {
			return "", false, i, true, false
		}
		if i+1 < len(argv) {
			return unwrapShellJoinTail(tail, argv[i+1]), true, i, true, false
		}
		return tail, tail != "", i, true, false
	}
	if strings.HasPrefix(a, "--") {
		if ni2, bail := unwrapShellLongWord(argv, i); bail {
			return "", false, i, true, false
		} else {
			return "", false, ni2, false, false
		}
	}
	if a == "-o" || a == "+o" || a == "-O" || a == "+O" {
		// The option-NAME operand of a bare -o/+o/-O/+O: after a pending -c
		// an UNQUOTED dynamic name word-splits at runtime and the fragments
		// re-parse as further options — it must surface as screened text
		// instead of being silently skipped (v6.2.2 Oracle R7 R7-MF-3 path
		// A `sh -c -o errexit -o $X 'echo hi'`). A plain static name or a
		// split-safe expansion stays data.
		if sawC && i+1 < len(argv) && isDynamicArg(argv[i+1]) {
			return unwrapShellJoinTail(tail, argv[i+1]), true, i, true, false
		}
		return "", false, i + 1, false, false // consumes the option NAME
	}
	if len(a) > 1 && (a[0] == '-' || a[0] == '+') && !strings.HasPrefix(a, "--") {
		return "", false, i, false, true // cluster word — the caller scans it
	}
	// First non-option word: with a pending -c it IS the command string;
	// without -c the shell runs a script FILE — nothing to unwrap, and the
	// positional ends the option zone either way.
	if sawC {
		return unwrapShellJoinTail(tail, a), true, i, true, false
	}
	return "", false, i, true, false
}

// unwrapShellJoinTail prepends the recorded cluster tail to the command
// string (the tail is an ambiguous glued spelling, screened rather than
// dropped — v6.2.2 Oracle R6 R6-MF-1).
func unwrapShellJoinTail(tail, script string) string {
	if tail == "" {
		return script
	}
	if script == "" {
		return tail
	}
	return tail + "\n" + script
}

// unwrapShellLongWord skips one `--` long-option word of the shell scan
// (extracted from unwrapShellArgv — v6.2.2 Oracle R6 R6-MF-1): --rcfile/
// --init-file consume a file operand that must name /dev/null to stay
// reviewable; every other long word is a boolean flag. ni is the loop
// index the scan continues from, bail reports the unwrap must give up.
func unwrapShellLongWord(argv []string, i int) (ni int, bail bool) {
	a := argv[i]
	name, val, hasVal := a[2:], "", false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, val, hasVal = name[:k], name[k+1:], true
	}
	if name != "rcfile" && name != "init-file" {
		return i, false
	}
	if !hasVal {
		if i+1 >= len(argv) {
			return i, true
		}
		return i + 1, argv[i+1] != "/dev/null"
	}
	return i, val != "/dev/null"
}

// unwrapShellClusterWord advances unwrapShellArgv past one short-option
// cluster word (extracted — v6.2.2 Oracle R6 R6-MF-1): skipped counts EXTRA
// argv operands the cluster's trailing bare -o/-O eats, newC/newTail report
// a freshly-seen -c letter and its ambiguous tail, dyn is the dynamic
// option-name fail-closed surface of shellClusterOName. The scan matches
// scanShortCluster's shell grammar: letters after 'c' keep parsing as flags
// (the recorded tail is prepended to the command text, never dropped), a
// non-letter byte in the tail ends the flag letters, and a bare -o/-O at
// the cluster end consumes the NEXT argv as its option name.
func unwrapShellClusterWord(argv []string, i int, sawC bool) (skipped int, newC bool, newTail, dyn string) {
	a := argv[i]
	plus := a[0] == '+'
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if ch == 'c' && !plus && !sawC {
			newC, newTail = true, a[j+1:]
			// Flag model (R14): letters after c are flags, not code —
			// `sh -ce 'x'` is -c -e 'x'. A trailing bare -o/-O inside the
			// tail still consumes the next argv as its option name (`sh -co
			// vi 'x'`: vi feeds -o and 'x' is the program).
			if isLetterOnly(newTail) {
				dyn, skipped = shellClusterOName(argv, a, j, i)
				return skipped, true, newTail, dyn
			}
			// A non-letter byte in the tail is an ambiguous glued spelling
			// (zsh-style -c= or -c"x"): it is NOT part of the flag letters,
			// so the cluster scan ends here — the whole tail is prepended
			// to the screened text fail-closed.
			return 0, true, newTail, ""
		}
		if ch == 'o' || ch == 'O' {
			// valued at end of cluster
			if j+1 >= len(a) {
				if i+1 < len(argv) {
					if isDynamicArg(argv[i+1]) && sawC {
						// The option name slot is dynamic AFTER a pending -c:
						// the split re-parses it as further options (R5-MF-1).
						return 0, newC, newTail, argv[i+1]
					}
					return 1, newC, newTail, ""
				}
			}
			return skipped, newC, newTail, ""
		}
	}
	return skipped, newC, newTail, ""
}

// shellClusterOName scans the letter tail after a cluster's 'c' for a
// trailing -o/-O that consumes the NEXT argv as its option name (extracted
// from unwrapShellArgv — v6.2.2 Oracle R5 R5-MF-1). skipped counts the
// extra argv operands eaten (0 or 1). Depth-defense: a dynamic option-NAME
// operand (`sh -co $X`) splits into further option letters at runtime — it
// is never a static name, so the cluster cannot be statically unwrapped;
// the placeholder surfaces as screened text instead of being silently
// skipped.
func shellClusterOName(argv []string, a string, j, i int) (dyn string, skipped int) {
	for k := j + 1; k < len(a); k++ {
		if a[k] == 'o' || a[k] == 'O' {
			if k+1 >= len(a) && i+1 < len(argv) {
				if isDynamicArg(argv[i+1]) {
					return argv[i+1], 1
				}
				return "", 1
			}
			return "", 0
		}
	}
	return "", 0
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

// isPythonInterpBase reports whether base names a Python CLI head
// (python, python2*, python3*).
func isPythonInterpBase(base string) bool {
	return base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3")
}

// isValidPycsMode reports whether s is a valid --check-hash-based-pycs mode.
func isValidPycsMode(s string) bool {
	return s == "default" || s == "always" || s == "never"
}

// inlineSlotInterpLang maps non-Python interpreter heads to their
// guardCtxRunCode language.
func inlineSlotInterpLang(base string) (string, bool) {
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

// pyShortClusterEnd reports how CPython's own option scan treats one
// short-option cluster word: a cluster ending in 'c'/'m' (or gluing the
// operand right after those letters) reaches CPython's first code/module
// slot — its own option parsing STOPS there and every later word is script
// argv, so consumesNext marks the operand's position (glued inside the
// word, the next argv, or still missing). A cluster ending in the valued
// letters 'W'/'X' consumes the next argv as their operand (or glues it).
// Shared by hasDynamicInterpOption, screenInterpFileRun and
// stdinProgramTargetsWithEnv so the four Python option scans cannot drift
// (v6.2.2 MF-2): `-uW ignore` eats `ignore`, `-uc`/`-um` glue the slot.
func pyShortClusterEnd(a string) (isCodeOrMod, consumesNext bool) {
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'c', 'm':
			return true, j+1 >= len(a)
		case 'W', 'X':
			return false, j+1 >= len(a)
		}
	}
	return false, false
}

// unwrapPythonSlots converts interpCodeSlots output on a Python head into
// the unwrapInterpreterInline return triple. Dynamic script-path slots stay
// in hasDynamicInterpOption / stdinProgramTargetsWithEnv rather than posing
// as -c.
func unwrapPythonSlots(slots []codeSlot) (string, string, bool) {
	for _, s := range slots {
		if s.flagOnly {
			// An open -c/-m flag (operand never supplied — the xargs/-uW
			// shuffle model): the fed text lands in the code slot, so the
			// inline-code screen must treat it as present rather than
			// skipping it into a vacuum (v6.2.2 MF-2).
			return "python", cmdSubPlaceholder, true
		}
		if s.dynOperand {
			continue
		}
		if s.module {
			return "python-module", s.text, true
		}
		return "python", s.text, true
	}
	return "", "", false
}

// unwrapInterpreterInline extracts inline code handed to a non-shell
// interpreter: python[2|3[.x]] -c/-m, node/nodejs/ts-node/tsx/bun
// -e/--eval/-p/--print, perl -e/-E, ruby -e, php -r. Every interpreter shares
// interpCodeSlots' option grammar so direct execution, find -exec and xargs
// screens cannot drift.
func unwrapInterpreterInline(argv []string) (lang, code string, ok bool) {
	if len(argv) == 0 {
		return "", "", false
	}
	base := filepath.Base(argv[0])
	if isPythonInterpBase(base) {
		return unwrapPythonSlots(interpCodeSlots(argv))
	}
	lang, ok = inlineSlotInterpLang(base)
	if !ok {
		return "", "", false
	}
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
	return lang, strings.Join(frags, "\n"), true
}

// ---------- rule 1: sub-agent nested-dispatch guard ----------

// blockedAgentExecutableList is the canonical list of executables a
// sub-agent must never spawn. blockedAgentExecutables (argv heads) and
// codeAgentNames (in-code identifier scan) are both derived from it so the
// two screens cannot drift.
