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
// R23-Reviewer-#1 / R23-Oracle-M5: the xargs memo/budget table is
// PRE-INITIALIZED on the struct (currentGuardCall mints it once per
// request), so the one guardCall of a request shares ONE table across
// all 12 callerIdentity call sites (head screening, prepare projection,
// stdin fallback) instead of minting a fresh 512-node budget per stage —
// the budget denominator is exactly one tool request. Copies of the
// struct share the minted pointer, so a copy can never restart the
// budget either.
type guardCall struct {
	subagent       bool
	readonly       bool
	strictReadonly bool
	// cwd is the resolved ctx_run cwd of the call under screening, pinned
	// by the entry point before any guard runs. "" reproduces the former
	// screenCwd=="" semantics: resolution falls back to the process
	// working directory (unit tests and unguarded call sites).
	cwd string
	// xw is the request-scoped xargs memo/budget table this call's
	// identities share — pre-initialized by currentGuardCall; a zero-value
	// hand-assembled struct (unit screening only) keeps the per-identity
	// fallback table.
	xw *xargsWorkState
}

func currentGuardCall() guardCall {
	ro := auditCallerIsReadonly()
	return guardCall{
		subagent:       auditCallerIsSubagent(),
		readonly:       ro,
		strictReadonly: auditCallerIsStrictReadonly(),
		// R23-Reviewer-#1 / R23-Oracle-M5: the xargs memo/budget table is
		// PRE-INITIALIZED once per request object — every callerIdentity
		// of this guardCall inherits the same pointer, so all twelve
		// identity lookups of one tool request share the single 512-node
		// budget while two concurrent requests naturally never share it.
		xw: &xargsWorkState{},
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
	return g.guardCtxRunShellEnvDialect(code, envAs, false)
}

// guardCtxRunShellEnvDialect is guardCtxRunShellEnv under an explicit shell
// dialect (v6.2.2 Oracle R16 M2): a bash-family shell reading its program
// from stdin re-parses brace expansion exactly like `bash -c` — the stdin
// entry can no longer judge the same program text as dash POSIX.
func (g guardCall) guardCtxRunShellEnvDialect(code string, envAs envAssignments, bash bool) (rule, detail string) {
	if !g.subagent && !g.strictReadonly {
		return "", "" // main agent: never enters the sub-agent parser
	}
	caller := g.callerIdentity().seededWith(envAs)
	if g.subagent {
		if hit := guardShellSubagentDepthDialect(code, 0, caller, bash); hit != "" {
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

// checkPythonLongInterpOpt screens one `--` word in a Python head's option
// zone: the zero-arg query spellings pass, --check-hash-based-pycs must
// carry a statically valid mode (glued or the next argv), and every other
// long option — its operand arity unknowable — is bad (fail closed).
func checkPythonLongInterpOpt(head []string, i int) (nextIdx int, bad bool) {
	a := head[i]
	name, val, hasVal := a[2:], "", false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, val, hasVal = name[:k], name[k+1:], true
	}
	switch name {
	case "help", "help-env", "help-xoptions", "help-all", "version":
		if hasVal {
			return i, true
		}
		return i, false
	case "check-hash-based-pycs":
		if hasVal {
			return i, !isValidPycsMode(val)
		}
		if i+1 >= len(head) || isDynamicArg(head[i+1]) || !isValidPycsMode(head[i+1]) {
			return i, true
		}
		return i + 1, false // consumes the separate mode operand
	}
	return i, true // unknown Python long option
}

// isSafeDynamicScriptPath reports whether a dynamic word in the interpreter
// option zone ends the zone as the script-file operand: split-safe, never
// option-shaped at runtime, and path-shaped (absolute, glob containing '/',
// abs-dq placeholder, or a known interpreter script extension).
func isSafeDynamicScriptPath(a string) bool {
	if !isSafeDynamicDataOperand(a) {
		return false
	}
	return strings.Contains(a, "/") || strings.HasPrefix(a, "/") ||
		strings.HasPrefix(a, cmdSubPlaceholderAbsDq) || hasInterpScriptExt(a)
}

// interpDynValueOpts derives the plain-value (and code-value) option table
// hasDynamicInterpOption consumes operands with, from the interpreter's own
// spec: every exact short value letter, every longValue entry, plus the
// inline-code spellings (whose operands unwrapInterpreterInline screens —
// they still consume the next argv so a following dynamic -e is not
// mistaken for the script file, MF-2 multi -e). Deriving it per-interpreter
// keeps bun's `-c` a bunfig VALUE (dynamic operand must fail closed,
// v6.2.2 MF-3) instead of the generic shell -c code flag.
func interpDynValueOpts(spec interpOptSpec) (valueExact, codeFlags map[string]bool) {
	valueExact = map[string]bool{}
	codeFlags = map[string]bool{}
	for j := 0; j < len(spec.valShort); j++ {
		valueExact["-"+string(spec.valShort[j])] = true
	}
	for j := 0; j < len(spec.gluedCodes); j++ {
		w := "-" + string(spec.gluedCodes[j])
		valueExact[w], codeFlags[w] = true, true
	}
	for j := 0; j < len(spec.flagCodes); j++ {
		w := "-" + string(spec.flagCodes[j])
		valueExact[w], codeFlags[w] = true, true
	}
	for k := range spec.longValue {
		valueExact[k] = true
	}
	for k := range spec.longCode {
		valueExact[k], codeFlags[k] = true, true
	}
	if shellOptSpecHasPlus(spec) {
		valueExact["+o"], valueExact["+O"], valueExact["+c"] = true, true, true
		codeFlags["+c"] = true
	}
	return valueExact, codeFlags
}

// shellOptSpecHasPlus reports whether the spec belongs to a POSIX shell
// (the only heads whose option zone also spells +o/+O/+c).
func shellOptSpecHasPlus(spec interpOptSpec) bool {
	return spec.flagCodes == "c" && strings.Contains(spec.valShort, "o")
}

// interpDynLongStep handles one `--` word in hasDynamicInterpOption's scan
// (extracted so the main scan loop stays reviewable — v6.2.2 R3): end/dyn
// carry the final verdict when the word decides the outcome, next is the
// loop index to continue from. Python's strict long arity table owns the
// Python verdict; non-Python long VALUE options consume their operand
// through the spec-derived valueExact table and a dynamic operand fails
// closed unless the slot is itself inline code (v6.2.2 R3 R2-MF-1).
func interpDynLongStep(head []string, i int, spec interpOptSpec, valueExact, codeFlags map[string]bool, pyHead, shell bool) (next int, end, dyn bool) {
	if pyHead {
		n, bad := checkPythonLongInterpOpt(head, i)
		if bad {
			return i, true, true
		}
		return n, false, false
	}
	a := head[i]
	name := a[2:]
	hasEq := false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, hasEq = name[:k], true
	}
	if shell && (name == "rcfile" || name == "init-file") && shellRcfileDynamicHit(head, i) {
		return i, true, true
	}
	if !valueExact["--"+name] {
		return i, false, false // unknown or boolean long option consumes only its own word
	}
	if hasEq {
		return i, false, false // glued value consumes only its own word
	}
	// A separate value operand follows: dynamic operands fail closed unless
	// the slot itself is inline code (its own screen judges those downstream).
	if i+1 < len(head) && isDynamicArg(head[i+1]) && !codeFlags["--"+name] {
		return i, true, true
	}
	if i+1 < len(head) {
		return i + 1, false, false // consume the separate value operand
	}
	return i, false, false
}

// hasDynamicInterpOption reports a dynamic word in the shell/interpreter
// option zone (before -- or the first static script operand). For Python
// heads the scan ENDS at the first -c/-m (CPython's own option parsing
// stops there — module/script arguments like `python3 -m pytest --cov=x`
// are no longer interpreter options, v6.2.2 MF-1).
func hasDynamicInterpOption(head []string, base string) bool {
	if len(head) < 2 {
		return false
	}
	shell := shellHeads[base]
	_, interp := heredocInterpLang(base)
	if !shell && !interp {
		return false
	}
	spec, hasSpec := lookupInterpOptSpec(base)
	if !hasSpec {
		return false
	}
	valueExact, codeFlags := interpDynValueOpts(spec)
	pyHead := isPythonInterpBase(base)
	for i := 1; i < len(head); i++ {
		ni, end, dyn := interpDynWordStep(head, i, spec, valueExact, codeFlags, pyHead, shell)
		if end {
			return dyn
		}
		i = ni
	}
	return false
}

// interpDynWordStep advances hasDynamicInterpOption's scan past the word at
// index i (extracted so the scan loop stays reviewable — v6.2.2 R3): next
// is the loop index to continue from, end/dyn carry the final verdict when
// the word decides the outcome (including the zone-ending first static
// script operand, reported as end=true, dyn=false).
func interpDynWordStep(head []string, i int, spec interpOptSpec, valueExact, codeFlags map[string]bool, pyHead, shell bool) (next int, end, dyn bool) {
	a := head[i]
	if a == "--" || a == "-" || (shell && a == "+") {
		// "--" ends the option zone; "-" means stdin script source and
		// the remaining args are script argv (W-Fix-6); POSIX/dash treat a
		// bare "+" as the same terminator once the zone is a shell's
		// (v6.2.2 Oracle R7 R7-MF-3 path B).
		return i, true, false
	}
	if shell && (a == "-c" || a == "+c") {
		// POSIX shells model -c/+c as a BOOLEAN letter — the word consumes
		// NO operand of its own (the command string is the first non-option
		// word). Treating the bare spelling through valueExact would swallow
		// the NEXT option word (`sh -c -o errexit -o $X 'echo hi'` lost the
		// first -o and the dynamic word rode the second — v6.2.2 Oracle R7
		// R7-MF-3 path A).
		return i, false, false
	}
	if isDynamicArg(a) {
		return i, true, dynInterpWordHit(a, shell)
	}
	if strings.HasPrefix(a, "--") {
		return interpDynLongStep(head, i, spec, valueExact, codeFlags, pyHead, shell)
	}
	if pyHead {
		if pyEnd, pyDyn := pyInterpScanStep(head, i); pyEnd {
			return i, true, pyDyn
		}
	}
	if valueExact[a] {
		if i+1 < len(head) && isDynamicArg(head[i+1]) && !codeFlags[a] {
			return i, true, true
		}
		return i + 1, false, false // consume value / code slot
	}
	if strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+") {
		return interpDynClusterStep(head, i, spec, shell, a)
	}
	// first static non-option operand = script file → option zone ends
	return i, true, false
}

// interpDynClusterStep handles one short-option cluster word of
// hasDynamicInterpOption's scan (extracted so interpDynWordStep stays
// under the complexity budget — v6.2.2 R3 R3-MF-5). Spec-derived cluster
// value consumption (R2-MF-2): a cluster ending in a bare value letter
// consumes the NEXT argv — the operand is checked for dynamic words
// BEFORE it is skipped, so python3 -uW $X / sh -o errexit "$OPT" /
// perl -wI /tmp -I $X can no longer launder a dynamic word through the
// value slot. A trailing bare CODE letter of a multi-code interpreter
// consumes its code operand and the scan CONTINUES inside the option
// zone so a following -I/-r/-c value slot still sees the dynamic word.
func interpDynClusterStep(head []string, i int, spec interpOptSpec, shell bool, a string) (next int, end, dyn bool) {
	if len(a) == 2 {
		ch := a[1]
		if strings.IndexByte(spec.valShort, ch) >= 0 {
			if i+1 < len(head) && isDynamicArg(head[i+1]) {
				return i, true, true
			}
			return i + 1, false, false
		}
		return i, false, false
	}
	consumesVal, hasPendingCode := clusterConsumesOperand(spec, a)
	next = i
	if consumesVal {
		// The value letter's operand is the NEXT argv — checked for dynamic
		// words BEFORE it is skipped, even when a pending flag-code letter
		// shares the cluster (`sh -co $X` / `node -pr $X` / `bun -pc $X`):
		// scanShortCluster feeds the operand to the value letter, so the
		// expansion rides a plain VALUE slot (v6.2.2 Oracle R5 R5-MF-1 —
		// the R6 mis-label dropped this check and regressed the R3 BLOCK).
		if i+1 < len(head) && isDynamicArg(head[i+1]) {
			return i, true, true
		}
		next = i + 1
	}
	if hasPendingCode {
		// A flag-model code letter (node -p / sh -c) still awaits its own
		// operand after the value slot. CPython stops at the first code
		// slot, matching its own parser (v6.2.2 R3 R3-MF-5); multi-code
		// interpreters consume one more slot so a later -r/-I operand
		// cannot pose as the code (v6.2.2 Oracle R5 R5-MF-1 `node -pC
		// default '1' -r $X`). POSIX shells are NEITHER: -c is a boolean
		// flag there and the shell keeps parsing further -/+ options after
		// it, so the scan must CONTINUE through the option zone (the
		// command string is the first non-option word — v6.2.2 Oracle R6
		// R6-MF-1 `sh -co errexit -o $X 'echo hi'` regressed to ALLOW when
		// the R5-MF-1 repair let shells share CPython's stop).
		if spec.stopOnFirstCode {
			return next, true, false
		}
		if shell {
			return next, false, false
		}
		return next + 1, false, false
	}
	return next, false, false
}

// clusterConsumesOperand is the spec-derived single source for short-cluster
// operand consumption shared by hasDynamicInterpOption and
// stdinInterpTargetsScan (v6.2.2 R3 R2-MF-2; consumesVal/hasPendingCode pair
// for Oracle R5 R5-MF-1): consumesVal reports the cluster's trailing letter
// takes the NEXT argv as a plain VALUE operand, hasPendingCode reports a
// pending flag-model code letter whose own operand follows it (a bare glued
// code letter exposes only the code slot — reported through hasPendingCode
// with consumesVal false). A `flagCodes`+`valShort` cluster (`sh -co`,
// `node -pr`, `bun -pc`) reports BOTH: scanShortCluster feeds the next argv
// to the VALUE letter, so the value slot must stay dynamic-checked while
// the pending code letter consumes the operand after it (v6.2.2 Oracle R5
// R5-MF-1 — the R4-SF-1-era (true,true) collapse dropped the value check
// AND the second slot, regressing `sh -co $X` / `node -pr $X` / `bun -pc $X`
// to ALLOW). Cluster parsing mirrors interpOptSpec.scanShortCluster: glued
// code letters end the cluster, glued or flag value letters end at the
// value letter, optional-glued letters absorb their tails.
func clusterConsumesOperand(spec interpOptSpec, a string) (consumesVal, hasPendingCode bool) {
	if strings.HasPrefix(a, "--") || len(a) < 2 {
		return false, false
	}
	plus := a[0] == '+'
	hasFlagCode := false
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if !plus && strings.IndexByte(spec.gluedCodes, ch) >= 0 {
			if j+1 >= len(a) {
				return false, true // bare glued-code letter: the next argv is CODE
			}
			return false, false // glued tail IS the code text — the cluster ends
		}
		if !plus && strings.IndexByte(spec.flagCodes, ch) >= 0 {
			// Flag-model code letter (node -pe / sh -c): its operand is the
			// next argv and it is CODE. Letters after a letter-only tail keep
			// parsing as flags — remember the pending code letter through
			// hasFlagCode even when the scan continues, so a later NON-flag
			// letter settling the cluster cannot drop it (v6.2.2 Oracle R4
			// R4-SF-1: scanShortCluster keeps `pending` across exactly the
			// same continuation).
			hasFlagCode = true
			if tail := a[j+1:]; tail != "" && !isLetterOnly(tail) {
				// scanShortCluster sets pending BEFORE breaking on a non-letter
				// tail (the tail is an ambiguous glued spelling, not flag
				// letters): keep hasFlagCode through the early return so the
				// pending code operand is not dropped (v6.2.2 Oracle R6
				// R6-SF-2 `node -pCfoo-bar '1' -r $X`).
				return false, hasFlagCode
			}
			if j+1 >= len(a) {
				return false, true
			}
			continue
		}
		if strings.IndexByte(spec.valShort, ch) >= 0 {
			if j+1 >= len(a) {
				// A bare value letter consumes the next argv as a VALUE slot;
				// a pending flag-code letter keeps its own operand after it
				// (v6.2.2 Oracle R5 R5-MF-1 `node -pC default '1' -r $X` consumes
				// TWO slots — the value `default` and the code `1`).
				return true, hasFlagCode
			}
			// A glued tail IS the value — the value slot needs no next argv,
			// but a pending flag-code letter survives the cluster end
			// (`node -pCdefault '1' -r $X` still owes its code operand).
			return false, hasFlagCode
		}
		if strings.IndexByte(spec.optNumShort, ch) >= 0 {
			j += consumeNumOptTail(a, j, ch)
			continue
		}
		if strings.IndexByte(spec.optShort, ch) >= 0 {
			return false, false // optional-glued tail absorbs the rest
		}
	}
	if hasFlagCode {
		// The cluster ended on non-settling flag letters after a flag-code
		// letter (`node -pi` where 'i' is not in any table): the next argv
		// is still the pending CODE operand (v6.2.2 Oracle R4 R4-SF-1).
		return false, true
	}
	return false, false
}

// clusterConsumesNext is the value-only projection of
// clusterConsumesOperand kept for stdinInterpTargetsScan: a trailing CODE
// operand must NOT consume the next argv there, because stdin-program
// detection owns the code slot itself (v6.2.2 R3 R3-MF-5).
func clusterConsumesNext(spec interpOptSpec, a string) bool {
	consumesVal, hasPendingCode := clusterConsumesOperand(spec, a)
	return consumesVal && !hasPendingCode
}

// dynInterpWordHit decides a dynamic word inside the shell/interpreter
// option zone: shell zones fail closed on ANY dynamic word; interpreter
// zones pass only a split-safe path-shaped script-file operand (which ends
// the zone — MF-2/Q1-C) and fail closed on everything else.
func dynInterpWordHit(a string, shell bool) bool {
	if shell {
		return true // may expand to -c/-s etc.
	}
	if isSafeDynamicScriptPath(a) {
		return false // script-file operand ends the option zone
	}
	return true
}

// pyInterpScanStep applies CPython's stop-at-first-code-slot rule to argv
// position i: end reports the interpreter's own option zone terminates AT
// this word (every later word is script argv — module arguments like
// `python3 -m pytest --cov=x` are not Python options, v6.2.2 MF-1), and
// dyn reports the slot's operand is dynamic module code that must fail
// closed. A -c operand faces unwrapInterpreterInline's own dynamic-code
// verdict downstream, so only -m's dynamic operand reports dyn=true.
func pyInterpScanStep(head []string, i int) (end, dyn bool) {
	a := head[i]
	if strings.HasPrefix(a, "--") || len(a) < 2 ||
		(!strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+")) {
		return false, false
	}
	isModule := false
	if len(a) == 2 {
		isModule = a == "-m"
		if a != "-c" && a != "-m" {
			return false, false
		}
	} else {
		var isCode, consumesNext bool
		isCode, consumesNext = pyShortClusterEnd(a)
		if !isCode {
			return false, false
		}
		if !consumesNext {
			// The module/code text is glued INSIDE the cluster (-mjson.tool):
			// the next argv is a script/module argument, never the module
			// name — the scan ends here with no dynamic verdict (v6.2.2 R3
			// R2-MF-2 restores python3 -mjson.tool "$HOME/a.json").
			return true, false
		}
		isModule = clusterEndsInM(a)
	}
	if i+1 < len(head) && isDynamicArg(head[i+1]) && isModule {
		return true, true
	}
	return true, false
}

// clusterEndsInM reports whether a Python short cluster's first c/m letter
// is 'm' (the module variant whose dynamic operand is unreviewed code).
func clusterEndsInM(a string) bool {
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'c':
			return false
		case 'm':
			return true
		case 'W', 'X':
			return false
		}
	}
	return false
}

// shellRcfileDynamicHit reports whether a shell head's --rcfile/--init-file
// word carries a non-/dev/null or dynamic operand: bash ignores rcfiles in
// non-interactive -c mode, so the option must never shadow the -c unwrapping
// or launder an unreviewed startup file (v6.2.2 MF-4b).
func shellRcfileDynamicHit(head []string, i int) bool {
	a := head[i]
	name, val, hasVal := a[2:], "", false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, val, hasVal = name[:k], name[k+1:], true
	}
	if name != "rcfile" && name != "init-file" {
		return false
	}
	if !hasVal {
		if i+1 >= len(head) {
			return true
		}
		val = head[i+1]
	}
	return val != "/dev/null"
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

// The former stdinProgramHeadCwd projection wrapper is gone
// (R23-Reviewer-#5 / R23-Oracle-M5): its last consumer was the
// first-non-data-target lookup inside the remote language projection,
// which the multi-target rewrite replaced with the full-list iteration
// — a partial lookup can never certify or reject correctly when one
// segment projects several targets.

// stdinEntryCaller mints the caller identity of one headless stdin
// projection entry (R23-Reviewer-#1 / R23-Oracle-M5): with no enclosing
// request identity to inherit, the entry itself pre-installs the xargs
// memo/budget table so the ENTIRE projection chain below shares the one
// 512-node budget — xargsEnsureWork's write-back then has nothing to
// repair at intermediate layers.
func stdinEntryCaller(cwd string) callerIdentity {
	return callerIdentity{cwd: cwd, xw: &xargsWorkState{}}
}

// The former narrow stdinProgramHeadCwdExh projection is gone
// (R23-Reviewer-#5 / R23-Oracle-M5): the remote pure-shell exemption is
// a CERTIFICATION path, and a first-non-data-target lookup can launder
// an exhausted sibling target behind a positively identified shell —
// certification must iterate the projection's entire non-data list
// (isPureRemoteStdinVehicleCwd does exactly that), so the two-value
// narrow helper has no legitimate consumer left. Rejection paths keep
// the plain projection: an exhausted consumer is never cleaner than a
// shell there, so treating it as a program-shaped target is the
// conservative direction already.

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
// R17-Oracle-M2: the bash dialect of the consuming shell is projected out
// of the target instead of being dropped — a local bash reading its
// program from a heredoc / here-string / pipe brace-expands exactly like
// `bash -c`, so the screen must re-parse under the bash dialect.
func stdinProgramHeadWithEnv(argv []string, depth int, inherited envAssignments, basePath string, caller callerIdentity) (lang string, isInterp bool, envAs envAssignments, bash bool) {
	targets := stdinProgramTargetsWithEnv(argv, depth, inherited, basePath, caller)
	// R17-Oracle-M6: nested data consumers ride the target list now — they
	// are not programs, so the projection skips them and surfaces the first
	// real program target (or none).
	t, has := firstProgramTarget(targets)
	if !has {
		return "", false, inherited, false
	}
	return t.lang, true, t.envAs, t.bash
}

// firstProgramTarget returns the first non-data stdin target (extracted
// for the v6.2.2 R17 complexity budget): data consumers are byte sinks,
// never programs.
func firstProgramTarget(targets []stdinTarget) (stdinTarget, bool) {
	for _, t := range targets {
		if t.data {
			continue
		}
		return t, true
	}
	return stdinTarget{}, false
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
	return g.screenStdinTargets(targets, argv, stdin, caller)
}

// screenStdinTargets screens one stdin payload against every program
// target of an argv (extracted for the v6.2.2 R17 complexity budget):
// remote targets upgrade the strictness, data consumers are byte sinks and
// never programs, shell targets re-parse under their own dialect and
// interpreter targets face their own language screen.
func (g guardCall) screenStdinTargets(targets []stdinTarget, argv []string, stdin string, caller callerIdentity) (rule, detail string) {
	for _, t := range targets {
		if t.data {
			continue // a data consumer is not a program target (R17-Oracle-M6)
		}
		// R21-Oracle-M5/R21-Reviewer-4: depth exhaustion is the exact
		// opposite of a confirmed POSIX shell — the analysis could not
		// descend deep enough to know WHO interprets the stream, so the
		// zero-value lang=""/bash=false must never be re-read as a known
		// shell verdict. Every final consumption point blocks explicitly.
		if t.exhausted {
			if g.strictReadonly {
				return ruleReadonlyWrite, depthExceededHit
			}
			if g.subagent {
				return ruleSubagentNestedAgent, depthExceededHit
			}
			return "", ""
		}
		// The per-target copy preserves the original value semantics (the
		// strict-escalation must never mutate the caller's own guardCall);
		// xw is a shared pointer either way, so the request budget carries
		// into the copy exactly like the direct identity.
		gSeg := g
		if gSeg.readonly && !gSeg.strictReadonly &&
			(t.remote || sshTunnelsStdinProgram(argv, os.Getenv("PATH"), caller)) {
			// The stream leaves this host (ssh forwards it): a
			// read-only-but-not-strict caller faces the strict screen.
			gSeg.strictReadonly = true
		}
		if t.lang == "" {
			if r, d := gSeg.guardCtxRunShellEnvDialect(stdin, t.envAs, t.bash); r != "" {
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
	// R20-Oracle-M4: the fallback path must carry the SAME accumulated
	// pure-assignment environment the flat prepare scan builds — a
	// mixed-dialect or data-target refusal reroutes the exact same bytes
	// here, and screening each segment under a fresh empty environment
	// would judge them against a shell state the consumers do not have
	// (an exported HOME reassigned by an independent statement is what
	// every later child inherits, exactly like the env-prefix spelling).
	// R21-Oracle-M3: the accumulation is scope-aware — each segment's
	// inherited env is the view of ITS OWN scope path.
	tracker := &scopeEnvTracker{}
	for _, seg := range splitShellSegmentsCaller(command, caller.envTaint, caller) {
		tracker.foldSegment(seg, caller)
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
		if rule, detail := g.stdinCommandSegRule(tracker, seg, stdin, caller); rule != "" {
			return rule, detail
		}
	}
	return "", ""
}

// stdinCommandSegRule screens one split segment of the stdin-fallback
// command (extracted from guardCtxRunStdinForCommand so the pure-
// assignment skip carries no extra nesting there): the stream-skip
// shapes (empty argv, pipe/redirection-fed, heredoc/here-string
// consumers) and — R22-Reviewer-#7 / R22-Oracle-SF2 — the AST's own
// pure-assignment verdict carry the skip for free, so the environment
// view materializes ONLY when the segment can actually consume the
// shared stream and consecutive assignment runs pay zero snapshot
// copies (and zero wrapper peels).
func (g guardCall) stdinCommandSegRule(tracker *scopeEnvTracker, seg shellSegment, stdin string, caller callerIdentity) (rule, detail string) {
	if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
		return "", ""
	}
	if seg.pureAssign {
		return "", ""
	}
	runEnv := tracker.view(seg.scopePath)
	targets := stdinProgramTargetsWithEnv(seg.argv, 0, runEnv, os.Getenv("PATH"), caller)
	if len(targets) == 0 {
		return "", ""
	}
	return g.screenStdinTargets(targets, seg.argv, stdin, caller)
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
	// bash marks a shell target whose interpreter is a bash-family shell
	// (v6.2.2 Oracle R16 M2): the stdin program text must be re-parsed
	// under the bash dialect (brace expansion) instead of the dash POSIX
	// default — the consuming process is never a top-level /bin/sh.
	bash bool
	// remote marks a target whose stdin program runs on a REMOTE host: it
	// is minted only by the ssh branch below (an ssh remote command that
	// itself reads a program from stdin) and rides collectSegs up through
	// any `bash -c 'ssh host sh'` unwrap that peelToSSHHead cannot reach.
	// Remote bytes must NEVER be rewritten into a local
	// `<selfExe> --hc-gate` call, and a read-only-but-not-strict caller
	// screening them escalates to the strict rules.
	remote bool
	// data marks a segment that CONSUMES the shared stdin stream without
	// being a program-reading shell/interpreter (R17-Oracle-M6): a plain
	// data consumer (cat, jq ., git apply) found while unwrapping a nested
	// shell -c script. Such a consumer must never vanish from the summary
	// — a mixed `cat; bash` stream can never be honestly rewritten as a
	// pure shell program, so scriptAllowsLocalShellStdinPrepareDialect
	// must refuse it exactly like the flat spelling.
	data bool
	// exhausted marks a projection that hit the recursion budget
	// (R20-Oracle-M5): the stream MIGHT be a program — the analysis
	// simply could not descend deep enough to find out. It is the exact
	// opposite of data=true: never a rewrite candidate, never an
	// exemption from the dynamic heredoc payload screen, and never
	// filterable into a data-only summary.
	exhausted bool
}

func stdinProgramTargetsWithEnv(argv []string, depth int, inherited envAssignments, basePath string, caller callerIdentity) []stdinTarget {
	return stdinProgramTargetsDialect(argv, depth, inherited, basePath, caller, false)
}

// stdinProgramTargetsDialect is stdinProgramTargetsWithEnv plus the dialect
// of the SHELL that produced argv (bash=true for segments of a bash payload).
// Same-process re-parses — the eval indirection joining operands back into
// shell text — must re-enter the parser under that dialect (v6.2.2 Oracle
// R16 M2); heads that spawn a FRESH shell (flock -c / script -c / watch /
// `sh -c` unwrapping) pick their own dialect below and never inherit it.
func stdinProgramTargetsDialect(argv []string, depth int, inherited envAssignments, basePath string, caller callerIdentity, bash bool) []stdinTarget {
	head, envAs, caller, prologue := stdinTargetsPeelPrologue(argv, depth, inherited, caller)
	if prologue != nil {
		return prologue
	}
	if len(head) == 0 {
		return nil
	}
	base := filepath.Base(head[0])
	if canon := canonicalResolvedBase(base); canon != base {
		if isPeeledWrapperBase(canon) {
			return stdinProgramTargetsDialect(append([]string{canon}, head[1:]...), depth+1, envAs, basePath, caller, bash)
		}
		head = append([]string{canon}, head[1:]...)
		base = canon
	}
	effPath := envAs.effectivePATHFrom(basePath)
	// R23-Reviewer-#6 / R23-Oracle-#6: a bare (slash-free) command head
	// owes its ENTIRE identity to PATH resolution — including a name the
	// static head tables recognize (sh/dash/ash/bash/cat/…). When the
	// effective PATH is untrusted the lookup answer is unknowable BEFORE
	// any static spelling or symlink resolution may be adopted.
	if bareHeadUntrustedPATH(head[0], envAs, basePath, caller) {
		return []stdinTarget{{lang: "", envAs: envAs, exhausted: true}}
	}
	if rb := canonicalResolvedBase(resolveHeadBase(head[0], effPath, caller.screenCwd())); rb != "" && rb != base {
		if isPeeledWrapperBase(rb) {
			return stdinProgramTargetsDialect(append([]string{rb}, head[1:]...), depth+1, envAs, basePath, caller, bash)
		}
		if !isStructuralGuardHead(base) {
			head = append([]string{rb}, head[1:]...)
			base = rb
		}
	}
	collectSegs := func(segs []shellSegment, subEnv envAssignments, subPath string, mergeOuter bool, subCaller callerIdentity) []stdinTarget {
		var out []stdinTarget
		// R19-Oracle-M4: a pure-assignment segment consumes no stdin but
		// DOES rewrite the running shell's environment — for a variable
		// already exported (HOME, PATH, ...) the assignment keeps its
		// export attribute and every LATER segment's child inherits the
		// new value. Its env ops therefore accumulate into runEnv exactly
		// like the flat prepare scan; neutral assignments (X=1) never
		// touch a sentinel name and change nothing downstream.
		// R21-Oracle-M3/R21-Reviewer-1: the accumulation is SCOPE-AWARE —
		// the flat runEnv answered only "not a parent write", never
		// "which scope does this consumer belong to". Each consumer's
		// inherited env is the view of ITS OWN scope path: assignments
		// inside a subshell bind for that same subshell's consumers and
		// die with it, while conditional writes surface as uncertainty
		// markers instead of exact overrides.
		tracker := &scopeEnvTracker{}
		for _, seg := range segs {
			out = append(out, collectOneStdinSeg(tracker, seg, depth, subEnv, envAs, subPath, mergeOuter, subCaller)...)
		}
		return out
	}
	if base == "ssh" {
		return stdinSSHTargets(head, depth, envAs, caller, collectSegs)
	}
	if innerText, has := unwrapShellArgv(head); has {
		return stdinShellCTargets(innerText, base, depth, envAs, basePath, caller, collectSegs)
	}
	if _, _, has := unwrapInterpreterInline(head); has {
		return nil
	}
	if base == "xargs" {
		return stdinXargsTargets(head, depth, envAs, basePath, effPath, caller)
	}
	if targets, handled := stdinIndirectionTargets(head, base, depth, envAs, basePath, caller, collectSegs, bash); handled {
		return targets
	}
	if shellHeads[base] {
		// R16-Oracle-M2: a bash-family shell reading its program from stdin
		// marks the target bash — the stream re-parses under brace-expansion
		// rules. The resolution mirrors the explicit -c path: both the typed
		// name and the PATH/symlink-resolved name decide.
		return stdinShellTargetsScan(head, envAs, hcShellDialectBash(head[0], effPath, caller))
	}
	if lang, ok := heredocInterpLang(base); ok {
		return stdinInterpTargetsScan(head, base, lang, envAs)
	}
	return stdinUnknownHeadTargets(head[0], envAs, basePath, caller)
}

// stdinTargetsPeelPrologue is the entry prologue of
// stdinProgramTargetsDialect (extracted for the R23 complexity budget):
// the recursion-depth cutoff (R20-Oracle-M5) and the wrapper-peel budget
// (R22-Oracle-M5 / R22-Reviewer-#5) are both EXPLICIT exhaustion
// verdicts, never nil — nil would ride the data-consumer fallback into
// a confirmed data-only summary and a zero-value lang:"" target would
// re-read as a KNOWN POSIX shell downstream, certifying bytes nobody
// identified. A non-nil prologue result IS the final verdict; otherwise
// the caller proceeds with the peeled head, the merged env ops and the
// level-seeded caller. Seeding covers only THIS level's freshly-peeled
// ops BEFORE any early-return recursion: `inherited` already rode in on
// `caller` (the recursion seeds each layer as it descends), so seeding
// the merged envAs again would re-apply an outer `env -C` relative dir
// onto the already-chdir'd cwd — a doubled join (R4 MF-1). envAs itself
// is still recorded whole on the returned stdinTarget so every peeled
// op stays visible to the caller; seeding also covers envTaint/pathEnv
// — a canon-rewritten recursion (`env -C sub genv ./mysh`) must keep
// the -C re-anchor and the `u`/`a` taints it peeled (R5 MF-4).
func stdinTargetsPeelPrologue(argv []string, depth int, inherited envAssignments, caller callerIdentity) ([]string, envAssignments, callerIdentity, []stdinTarget) {
	if len(argv) == 0 || depth >= shellSplitMaxDepth {
		if len(argv) == 0 {
			return nil, inherited, caller, nil
		}
		return nil, inherited, caller, []stdinTarget{{lang: "", envAs: inherited, exhausted: true}}
	}
	head, _, ea, exhausted := peelWrappers(argv)
	envAs := inherited.merged(ea)
	if exhausted {
		return nil, envAs, caller, []stdinTarget{{lang: "", envAs: envAs, exhausted: true}}
	}
	return head, envAs, caller.seededWith(ea), nil
}

// stdinUnknownHeadTargets is the tail verdict of
// stdinProgramTargetsDialect for an unrecognized head (R22-Oracle-#6 /
// R22-Reviewer-#6): an unrecognized BARE name carries no static
// builtin-language classification, so its identity depends entirely on
// PATH resolution. When the effective PATH is untrusted (a conditional
// write marker or an expansion that exceeded the byte budget degenerated
// it to the placeholder), the consumer is UNKNOWABLE — returning nil
// would ride the data-consumer fallback (`stdinTargetsWithDataFallback`)
// and let the caller skip the stream as if a plain data consumer were
// proven. The verdict is the explicit exhaustion target instead: never
// a rewrite candidate, never a data exemption. A name carrying '/' never
// depends on PATH, and a fixed absolute spelling keeps its own
// resolution path, so both stay on the nil/data fallback exactly like
// before.
func stdinUnknownHeadTargets(head string, envAs envAssignments, basePath string, caller callerIdentity) []stdinTarget {
	if strings.ContainsRune(head, '/') {
		return nil
	}
	// The caller's own replayed PATH counts exactly like the peeled
	// env ops (R22-Oracle-#6): once any layer degenerated it to the
	// unresolvable placeholder the verdict is sticky, and a bare name
	// resolving through it is unknowable either way.
	if envAs.pathUntrusted(basePath) || caller.pathUntrusted() {
		return []stdinTarget{{lang: "", envAs: envAs, exhausted: true}}
	}
	return nil
}

// bareHeadUntrustedPATH reports whether a command head is a bare
// (slash-free) name whose resolution depends on an untrusted PATH
// (R23-Reviewer-#6 / R23-Oracle-#6, extracted so the interception inside
// stdinProgramTargetsDialect carries no extra nesting): the same bare
// `sh` can be dash, bash, or an attacker-placed program once the search
// list is unknowable, so neither a static spelling nor a later
// PATH-segment hit may be adopted — the consumer is UNIDENTIFIED. Fixed
// absolute spellings (/bin/sh, ./x) carry their own resolution and stay
// unaffected exactly like stdinUnknownHeadTargets.
func bareHeadUntrustedPATH(head string, envAs envAssignments, basePath string, caller callerIdentity) bool {
	if strings.ContainsRune(head, '/') {
		return false
	}
	return envAs.pathUntrusted(basePath) || caller.pathUntrusted()
}

// collectOneStdinSeg projects one nested segment inside the collectSegs
// loop (extracted so the closure carries no per-segment branching — the
// R22 complexity budget): an unparsed or depth-exhausted segment is an
// UNIDENTIFIED consumer whose exhaustion verdict rides the target just
// like the recursion cutoff (R22-Oracle-M5), never a zero-value
// pseudo-POSIX-shell target; a pure-assignment segment consumes no stdin
// but DOES rewrite the running shell's environment regardless of its own
// redirects (R19-Oracle-M4), so its ops fold BEFORE any consumption
// skip; and the AST's own pure-assignment verdict carries the view skip
// for free (R22-Reviewer-#7) — the environment view materializes only
// for segments that can consume the stream, never per folded assignment.
func collectOneStdinSeg(tracker *scopeEnvTracker, seg shellSegment, depth int, subEnv, envAs envAssignments, subPath string, mergeOuter bool, subCaller callerIdentity) []stdinTarget {
	if seg.depthExceeded || seg.parseErr != "" {
		return []stdinTarget{{lang: "", envAs: envAs, exhausted: true}}
	}
	tracker.foldSegment(seg, subCaller)
	if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
		return nil
	}
	// R23-Reviewer-#7 / R23-Oracle-SF2: a pure-assignment segment consumes
	// NO stdin — its ops already folded into the tracker above — so it
	// must skip BEFORE any view materialization exactly like the flat
	// prepare scan. The pre-R23 condition guarded only the empty-head
	// peel, letting every real assignment reach tracker.view: n
	// consecutive nested assignments copied 1+2+…+n ops of quota the
	// parent tree never paid, and the projection could even mint phantom
	// depth exhaustion for a segment that never reads the stream.
	if seg.pureAssign {
		return nil
	}
	if peeledHead, _, _, _, _ := peelWrappersWithIndex(seg.argv, subCaller); len(peeledHead) == 0 {
		return nil
	}
	runEnv := subEnv.merged(tracker.view(seg.scopePath))
	return collectStdinSegTargets(seg, depth, runEnv, envAs, subPath, mergeOuter, subCaller)
}

// collectStdinSegTargets is the per-segment projection of the
// collectSegs loop (extracted for the v6.2.2 R19 complexity budget):
// recursion plus the R17-Oracle-M6 data-consumer fallback and the
// mergeOuter env overlay. runEnv already carries every earlier
// pure-assignment segment's ops in statement order (R19-Oracle-M4).
func collectStdinSegTargets(seg shellSegment, depth int, runEnv, envAs envAssignments, subPath string, mergeOuter bool, subCaller callerIdentity) []stdinTarget {
	var out []stdinTarget
	sub := stdinProgramTargetsDialect(seg.argv, depth+1, runEnv, subPath, subCaller, seg.bashDialect)
	// R17-Oracle-M6: a segment that can read the shared stream but
	// resolves to NO program target is a plain data consumer (cat,
	// jq .) — it must surface as such instead of silently dropping
	// out of the nested summary, or `bash -c "cat; bash"` would
	// earn a rewrite the flat `cat; bash` never gets.
	// R18-Oracle-S2: EXCEPT when nothing consumes the stream at all —
	// a pure-assignment segment (`X=1`) peels to an empty head exactly
	// like the flat scan in scriptAllowsLocalShellStdinPrepare skips
	// it, so `bash -c 'X=1; bash'` keeps the same verdict as the flat
	// spelling instead of inventing a data consumer.
	sub = stdinTargetsWithDataFallback(sub, seg, envAs, subCaller)
	for _, t := range sub {
		if mergeOuter {
			t.envAs = envAs.merged(t.envAs)
		}
		out = append(out, t)
	}
	return out
}

// argvIsPlainAssignRun reports whether every word of argv is a literal
// KEY=VAL assignment or an inert compound-statement fragment (the
// shellNoopWords the wrapper peel skips) — the only shape whose words
// PROVABLY execute as assignments of the running shell itself. Anything
// else (env/nohup/command wrapper heads, options, plain operands) either
// spawns its own process or is not an assignment at all, so it must
// never contribute to the parent-state accumulation (R20-Oracle-M3).
func argvIsPlainAssignRun(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	for _, a := range argv {
		if isAssignWord(a) || shellNoopWords[a] {
			continue
		}
		return false
	}
	return true
}

// evalJoinOperands drops the leading `--` option terminator bash's
// builtin eval consumes itself (R19-Oracle-M1) from an eval operand
// argv: joining it into the re-parse text would demote the real command
// to an argument of a `--` command head. Everything else passes through
// unchanged.
func evalJoinOperands(args []string) []string {
	if len(args) > 0 && args[0] == "--" {
		return args[1:]
	}
	return args
}

// stdinIndirectionTargets covers the eval/flock/script/watch branches of
// stdinProgramTargetsWithEnv (extracted for the v6.2.2 complexity budget):
// each shape either joins operands into shell text the segments screen,
// recurses into a positional inner argv, or reports the stream is data,
// not program. handled reports the base matched one of the four heads.
func stdinIndirectionTargets(head []string, base string, depth int, envAs envAssignments, basePath string, caller callerIdentity, collectSegs stdinSegCollectFunc, bash bool) (targets []stdinTarget, handled bool) {
	switch base {
	case "eval":
		if len(head) < 2 {
			return nil, true
		}
		inner := strings.Join(evalJoinOperands(head[1:]), " ")
		if isDynamicArg(inner) {
			return []stdinTarget{{lang: "", envAs: envAs}}, true
		}
		// R16-Oracle-M2: eval re-parses in the SAME shell — the enclosing
		// script's dialect rides in on the bash parameter.
		if bash {
			return collectSegs(splitShellSegmentsBashCaller(inner, caller.envTaint, caller), envAs, basePath, false, caller), true
		}
		return collectSegs(splitShellSegmentsCaller(inner, caller.envTaint, caller), envAs, basePath, false, caller), true
	case "flock":
		inner, cmdText := skipFlockArgs(head, 1)
		if cmdText != "" {
			if isDynamicArg(cmdText) {
				return []stdinTarget{{lang: "", envAs: envAs}}, true
			}
			return collectSegs(splitShellSegmentsCaller(cmdText, caller.envTaint, caller), envAs, basePath, false, caller), true
		}
		if inner < len(head) {
			return stdinProgramTargetsWithEnv(head[inner:], depth+1, envAs, basePath, caller), true
		}
		return nil, true
	case "script":
		if payload := scriptCommandArg(head); payload != "" {
			if isDynamicArg(payload) {
				return []stdinTarget{{lang: "", envAs: envAs}}, true
			}
			return collectSegs(splitShellSegmentsCaller(payload, caller.envTaint, caller), envAs, basePath, false, caller), true
		}
		return []stdinTarget{{lang: "", envAs: envAs}}, true
	case "watch":
		return stdinWatchTargets(head, depth, envAs, basePath, caller, collectSegs), true
	}
	return nil, false
}

// stdinWatchTargets is the watch branch: -x/--exec operands form a direct
// exec argv the recursion descends into; the default mode joins operands
// into a `sh -c` string the segments screen.
func stdinWatchTargets(head []string, depth int, envAs envAssignments, basePath string, caller callerIdentity, collectSegs stdinSegCollectFunc) []stdinTarget {
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
}

// stdinTargetsWithDataFallback appends the R17-Oracle-M6 data-consumer
// marker to a target-less recursion result ONLY when the segment really
// consumes the shared stream (extracted for the v6.2.2 R18 complexity
// budget — R18-Oracle-S2): a pure-assignment / no-op segment peels to an
// EMPTY command head, reads nothing and vanishes from the summary exactly
// like the flat prepare scan already skips it. Any segment with a real
// non-program head (cat, echo, jq .) stays a data consumer.
func stdinTargetsWithDataFallback(sub []stdinTarget, seg shellSegment, envAs envAssignments, subCaller callerIdentity) []stdinTarget {
	if len(sub) != 0 {
		return sub
	}
	if peeledHead, _, _, _, _ := peelWrappersWithIndex(seg.argv, subCaller); len(peeledHead) == 0 {
		return sub
	}
	return append(sub, stdinTarget{data: true, envAs: envAs})
}

// stdinSegCollectFunc is the collectSegs closure shape shared by the
// extracted stdinProgramTargetsWithEnv branch helpers.
type stdinSegCollectFunc func(segs []shellSegment, subEnv envAssignments, subPath string, mergeOuter bool, subCaller callerIdentity) []stdinTarget

// stdinSSHTargets is the ssh branch of stdinProgramTargetsWithEnv: remote
// commands resolve under the remote login env — only the remote ops feed
// their PATH replay — but relative heads inside them still resolve under
// the screen cwd like the old shared screenCwd did (the remote ops
// themselves stay untainted). Extracted for the v6.2.2 complexity budget.
func stdinSSHTargets(head []string, depth int, envAs envAssignments, caller callerIdentity, collectSegs stdinSegCollectFunc) []stdinTarget {
	remoteCmd, hit := parseSSHInvocation(head)
	if hit != "" {
		return nil
	}
	remoteCaller := callerIdentity{cwd: caller.cwd, xw: caller.xw}
	targets := collectSegs(splitShellSegmentsCaller(remoteCmd, nil, remoteCaller), envAssignments{}, os.Getenv("PATH"), true, remoteCaller)
	// Every target of an ssh remote command runs OFF this host: the
	// stream is forwarded verbatim, so mark it remote even when the
	// remote program is a local-shell-shaped head (ssh host sh).
	for i := range targets {
		targets[i].remote = true
	}
	return targets
}

// stdinShellCTargets is the shell `-c` unwrap branch of
// stdinProgramTargetsWithEnv: a nested -c script must additionally carry
// envAs's sentinel taints (`env -u PWD sh -c 'echo $PWD'`) — the caller
// was seeded with only this level's freshly peeled ops, so the
// accumulated envAs taints merge for the sub-parse (R5 MF-4). Extracted
// for the v6.2.2 complexity budget.
func stdinShellCTargets(innerText, base string, depth int, envAs envAssignments, basePath string, caller callerIdentity, collectSegs stdinSegCollectFunc) []stdinTarget {
	if isDynamicArg(innerText) {
		return []stdinTarget{{lang: "", envAs: envAs}}
	}
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

// stdinXargsTargets is the xargs branch of stdinProgramTargetsWithEnv: an
// xargs target whose open code slot the stdin words feed resolves under
// its own peeled env (the `env -C sub` re-anchor inside the xargs
// operand), so a symlink alias like ./myruby -> <real ruby> yields its
// language, never the POSIX-shell re-review lang:"" (R6 MF-1).
// Extracted for the v6.2.2 complexity budget.
func stdinXargsTargets(head []string, depth int, envAs envAssignments, basePath, effPath string, caller callerIdentity) []stdinTarget {
	k := xargsTargetIndex(head)
	if k >= len(head) {
		return nil
	}
	// R23-Reviewer-#5 / R23-Oracle-M5: the xargs analysis's bool conflates
	// "the stdin words provably feed an open code slot" with "the shared
	// single-request work budget gave up" — both fail closed inside the
	// analysis, but the TARGET projection must distinguish them: a budget
	// cutoff means the consumer identity is UNKNOWABLE (an exhaustion
	// verdict), never the zero-value POSIX shell an ordinary cat inner
	// target would project. The budget is sticky per request, so the
	// caller's table carries the exhausted state across the analysis call.
	caller, ws := xargsEnsureWork(caller)
	feedsCode := xargsFeedsCodeFlag(head[k:], head, effPath, caller)
	if xargsBudgetSpent(ws) {
		return []stdinTarget{{lang: "", envAs: envAs, exhausted: true}}
	}
	if !feedsCode {
		return stdinProgramTargetsWithEnv(head[k:], depth+1, envAs, basePath, caller)
	}
	return stdinXargsInnerTarget(head[k:], depth+1, envAs, effPath, caller)
}

// stdinXargsInnerTarget projects the inner target of an xargs invocation
// whose stdin words provably feed its open code slot (extracted for the
// R23 complexity budget): the target resolves under its own peeled env
// (the `env -C sub` re-anchor inside the xargs operand), so a symlink
// alias like ./myruby -> <real ruby> yields its language, never the
// POSIX-shell re-review lang:"" (R6 MF-1). The inner target's own
// wrapper-peel budget is an exhaustion verdict exactly like the
// recursion cutoff (R22-Oracle-M5 / R22-Reviewer-#5) — the consumer
// identity is UNKNOWABLE, never a known POSIX shell.
func stdinXargsInnerTarget(argv []string, depth int, envAs envAssignments, effPath string, caller callerIdentity) []stdinTarget {
	innerHead, innerEnv, innerEffPath, innerExhausted := peelWrappersAndWrapperAliases(argv, effPath, caller)
	envAs = envAs.merged(innerEnv)
	if innerExhausted {
		return []stdinTarget{{lang: "", envAs: envAs, exhausted: true}}
	}
	if lang, hit := stdinInnerHeadLang(innerHead, innerEffPath, caller.seededWith(innerEnv)); hit {
		return []stdinTarget{{lang: lang, envAs: envAs}}
	}
	return []stdinTarget{{lang: "", envAs: envAs}}
}

// stdinInnerHeadLang classifies one peeled inner target head by its
// resolved basename (extracted for the R23 complexity budget): the typed
// name and the PATH/symlink-resolved name both decide the interpreter
// language exactly like the flat projection. The second return is false
// for an empty head or a non-interpreter resolution.
func stdinInnerHeadLang(head []string, effPath string, caller callerIdentity) (string, bool) {
	if len(head) == 0 {
		return "", false
	}
	ib := filepath.Base(head[0])
	if rb := canonicalResolvedBase(resolveHeadBase(head[0], effPath, caller.screenCwd())); rb != "" {
		ib = rb
	}
	return heredocInterpLang(ib)
}

// stdinShellTargetsScan is the shell-head tail of
// stdinProgramTargetsWithEnv, extracted so the caller stays reviewable
// (v6.2.2 Oracle R1). It walks the shell option zone: -c means the stream
// is data not program (nil), -s forces the stdin-program verdict, and
// bash's --rcfile/--init-file consume a file operand that must never pose
// as the first script word (v6.2.2 MF-4b). Verdict encoding: -1 keep
// scanning, 0 not-a-stdin-program (nil), 1 stdin-program target.
func stdinShellTargetsScan(head []string, envAs envAssignments, bash bool) []stdinTarget {
	sawDashDash := false
	forceStdin := false
	for i := 1; i < len(head); {
		v, ni, nf := stdinShellWordVerdict(head, i, sawDashDash, forceStdin)
		if v >= 0 {
			if v == 1 {
				return []stdinTarget{{lang: "", envAs: envAs, bash: bash}}
			}
			return nil
		}
		sawDashDash, forceStdin = sawDashDash || head[i] == "--", nf
		i = ni
	}
	return []stdinTarget{{lang: "", envAs: envAs, bash: bash}}
}

// stdinShellWordVerdict decides one word of the shell option zone for
// stdinShellTargetsScan: verdict -1 keeps scanning (next is the index to
// continue from, force carries the -s state forward), 0 stops with
// not-a-stdin-program, 1 stops with the stdin-program verdict.
func stdinShellWordVerdict(head []string, i int, sawDashDash, forceStdin bool) (verdict, next int, force bool) {
	a := head[i]
	force = forceStdin
	if isDynamicArg(a) || a == "-" || isStdinDevicePath(a) {
		return 1, i, force
	}
	if a == "--" {
		return -1, i + 1, force
	}
	if sawDashDash {
		if forceStdin {
			return 1, i, force
		}
		return 0, i, force
	}
	if a == "-o" || a == "+o" || a == "-O" || a == "+O" {
		return -1, i + 2, force
	}
	if (strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+")) && len(a) > 1 && !strings.HasPrefix(a, "--") {
		v, n, f := stdinShellClusterVerdict(a, i)
		return v, n, f || force
	}
	if strings.HasPrefix(a, "--") {
		if a == "--rcfile" || a == "--init-file" {
			return -1, i + 2, force // bash rcfile consumes a file operand (v6.2.2 MF-4b)
		}
		return -1, i + 1, force
	}
	if forceStdin {
		return 1, i, force
	}
	return 0, i, force
}

// stdinShellClusterVerdict scans one short-option cluster word of the
// shell option zone: 's' forces the stdin-program state, 'c' ends the scan
// with not-a-stdin-program, valued o/O letters may consume the next argv.
func stdinShellClusterVerdict(a string, i int) (verdict, next int, force bool) {
	plus := a[0] == '+'
	extra := 0
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if ch == 's' && !plus {
			force = true
		}
		if ch == 'c' && !plus {
			return 0, i, force
		}
		if ch == 'o' || ch == 'O' {
			if j+1 >= len(a) {
				extra = 1
			}
			break
		}
	}
	return -1, i + 1 + extra, force
}

// stdinInterpTargetsScan is the interpreter-head tail of
// stdinProgramTargetsWithEnv, extracted so the caller stays reviewable
// (v6.2.2 Oracle R1). Value options consume their operands; the value table
// derives from the interpreter's own spec so bun/tsx/node/shell/perl/ruby
// value options can never drift apart from hasDynamicInterpOption (v6.2.2
// R3 R2-MF-2/R2-SF-4), and a spec-driven cluster trailing a bare value
// letter consumes the NEXT argv instead of letting it pose as the script
// file.
func stdinInterpTargetsScan(head []string, base, lang string, envAs envAssignments) []stdinTarget {
	sawDashDash := false
	spec, hasSpec := lookupInterpOptSpec(base)
	var valueExact map[string]bool
	if hasSpec {
		valueExact, _ = interpDynValueOpts(spec)
	} else {
		valueExact = map[string]bool{}
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
		if strings.HasPrefix(a, "--") {
			name := a[2:]
			hasEq := strings.IndexByte(name, '=') >= 0
			if k := strings.IndexByte(name, '='); k >= 0 {
				name = name[:k]
			}
			if valueExact["--"+name] && !hasEq {
				i += 2 // consume the separate value operand
				continue
			}
			i++
			continue
		}
		if hasSpec && clusterConsumesNext(spec, a) {
			i += 2 // cluster word plus the separate plain-VALUE operand it consumes
			continue
		}
		if valueExact[a] {
			i += 2
			continue
		}
		i++
	}
	return []stdinTarget{{lang: lang, envAs: envAs}}
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
	// R18-Oracle-M4: any glob-placeholder byte WITHOUT the unforgeable
	// tilde provenance fails closed outright — the value is either an
	// ordinary pathname glob (matches unenumerable) or a tilde whose HOME
	// is tainted / a verbatim literal that only SPELLS the printable
	// marker. Neither may reach the dynamic-path or tilde restoration
	// branches below.
	if globTildePathUnproven(val) {
		return "", false
	}
	var cand string
	switch {
	case tildeExpansionSpelling(val):
		restored, rok := restoreTildePathOpt(val)
		if !rok {
			return "", false
		}
		cand = restored
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

// restoreTildePathOpt is the tilde branch of resolveNodeRunnerPathOpt
// (extracted for the v6.2.2 R18 complexity budget): the word carries the
// unforgeable tilde provenance (tildeExpansionSpelling already fired), so
// stripping BOTH markers yields the raw ~/... spelling the consuming shell
// expands. Inside this branch the sole glob marker IS the unquoted
// word-start tilde's: isSingleWordOptionValue already forced exactly one
// marker and ruled out every other glob/tilde source byte.
func restoreTildePathOpt(val string) (string, bool) {
	raw := strings.Replace(val, cmdSubPlaceholderGlob, "", 1)
	raw = strings.ReplaceAll(raw, cmdSubPlaceholderTilde, "")
	if isDynamicArg(raw) || strings.ContainsAny(raw, "*?[") {
		return "", false
	}
	if raw != "~" && !strings.HasPrefix(raw, "~/") {
		return "", false // ~otheruser: untrusted home directory
	}
	// R16-Oracle-M4: restoring the shell's `~/...` expansion must use
	// the shell-visible inherited HOME (inheritedHomeDir), never the
	// config-search fallback of safeHomeDir — a relative or empty
	// inherited HOME must not fabricate "/root/notes" the running
	// shell never expands to. Failing closed is the sound outcome when
	// the inherited value cannot anchor an absolute path.
	h, ok := inheritedHomeDir()
	if !ok {
		return "", false
	}
	home := filepath.Clean(h)
	if home == "" || home == "." || !filepath.IsAbs(home) {
		return "", false
	}
	return filepath.Clean(home + raw[1:]), true
}

// tildeExpansionSpelling reports whether a value carries the shell's
// real tilde-expansion PROVENANCE at a leading `~` (extracted for the
// v6.2.2 R17 complexity budget — R17-Oracle-M4 criterion A, hardened in
// R18-Oracle-M4): provenance is now the NUL-carrying cmdSubPlaceholderTilde
// only the collector's word encoder can mint — the printable glob marker
// is no longer evidence, because a single-quoted literal can carry the
// same bytes verbatim (`'~__ctx_glob__/notes'`). A bare leading `~`
// without the unforgeable marker is a VERBATIM relative-path byte (direct
// argv, single-quoted word, or a tilde whose HOME is tainted), never an
// expansion the service HOME may stand in for.
func tildeExpansionSpelling(val string) bool {
	return strings.HasPrefix(val, "~") && strings.Contains(val, cmdSubPlaceholderTilde)
}

// globTildePathUnproven reports a value carrying the glob placeholder whose
// concrete path can never be proven (R18-Oracle-M4/R18-Oracle-S5 split):
// either a genuine tilde whose HOME is tainted (no tilde marker — the
// service process HOME must never stand in for the consuming shell's) or
// an ordinary pathname glob (`docs/*.txt`) whose matches the npx/bunx path
// option model cannot enumerate. Both shapes must fail closed as path
// operands while INDEPENDENTLY keeping their word-count proofs elsewhere.
func globTildePathUnproven(val string) bool {
	return !tildeExpansionSpelling(val) && strings.Contains(val, cmdSubPlaceholderGlob)
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
