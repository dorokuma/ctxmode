package main

// role_guards_peel.go — recursive argv/shell peeling and env/ssh/xargs/find/trap/unset/heredoc screens.

import (
	"os"
	"path/filepath"
	"strings"
)

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
	// The provenance of THIS buffer is consumed locally. Exactly one
	// cross-buffer jump (the rewritten `sh -c` script word) may carry it into
	// the child; every other recursion below starts with nil because the
	// caller copy is cleared here.
	entryProv := caller.hcProv
	caller.hcProv = nil
	gateLeaf := kind == 'r' && seg.gateProvenanced && isPreparedHcGateArgv(argv)
	if kind == 'r' {
		if hit := wrapperWriteOpHit(argv); hit != "" {
			return hit
		}
		if hit := readonlyPrePeelHitExempt(argv, gateLeaf); hit != "" {
			return allowlistDetail(hit)
		}
	}
	head, splitPayloads, envAs, exhausted := peelWrappers(argv)
	if exhausted {
		return depthExceededHit
	}
	// An `env -C`/`--chdir` whose directory operand is empty or dynamic can
	// never be reasoned about: the inner head would resolve under an
	// unknowable cwd, so the whole peeled head fails closed (R2-4).
	for _, op := range envAs.ops {
		if op.kind == 'd' && (op.value == "" || isDynamicArg(op.value)) {
			return "env -C"
		}
	}
	effCaller := caller.seededWith(envAs)
	outerCaller := caller
	caller = effCaller
	screenPayloads := func() string {
		for _, payload := range splitPayloads {
			if strings.HasPrefix(payload, envUnknownLongPrefix) {
				return "env unknown option " + strings.TrimPrefix(payload, envUnknownLongPrefix)
			}
			if kind == 's' {
				if hit := guardShellSubagentDepthEnv(payload, depth+1, effCaller, effCaller.envTaint); hit != "" {
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
		if hit := screenEnvAssignments(envAs, kind, caller.role, caller.readonly, "", caller); hit != "" {
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
	effPath := caller.effectivePATH()
	// A ctxmode/selfExe head is a direct --hc-gate attempt unless the exact
	// prepare*-minted provenance of this buffer backs it (P-3 / 裁决 5): a
	// worker's `echo --hc-gate` is untouched, while a raw
	// `./postinstall --hc-gate …`, `ctxmode --hc-gate …` or a dynamic option
	// word in the ctxmode option zone fails closed. The gate slot walk
	// re-derives under the OUTER caller — an env -C re-anchor must not move
	// the prepared -c slot (R3 MF-2) — while every other screen below runs
	// under the env -C-switched effCaller.
	if headIsCtxmodeOrSelfExe(typedHead[0], effPath, caller.screenCwd()) {
		if hit := screenCtxmodeGateHead(typedHead, seg, entryProv, outerCaller); hit != "" {
			return hit
		}
	}
	// C10: verify that the winning PATH binary is not an untrusted file or a
	// planted binary in a user-writable toolchain dir shadowing a system command.
	if hit := screenPathHeadTrust(typedHead[0], effPath, caller); hit != "" {
		return hit
	}
	if rb := resolveHeadBase(head[0], effPath, caller.screenCwd()); rb != "" && rb != base {
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
				if (isStructuralGuardHead(rb) || isPeeledWrapperBase(rb) || isBlockedAgentHead(rb)) && !sameStructuralFamily(base, rb) {
					return "conflicting structural alias " + filepath.Base(typedHead[0]) + " -> " + rb
				}
			} else {
				head = append([]string{rb}, head[1:]...)
				base = rb
			}
		}
	}
	if hit := screenEnvAssignments(envAs, kind, caller.role, caller.readonly, base, caller); hit != "" {
		return hit
	}
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
	if base == "ssh" {
		if kind == 'r' && filepath.Base(typedHead[0]) != "ssh" {
			if hit := screenReadonlyAllowlist(typedHead); hit != "" {
				return allowlistDetail(hit)
			}
		}
		return screenSSHHead(head, seg, kind, depth, caller)
	}
	// A symlink target promoted to a WRAPPER (PATH entry foo -> env/
	// timeout/...) was not peeled — peelWrappers ran on the TYPED name
	// before the alias resolution rewrote head[0]. Re-screen the promoted
	// argv so the wrapper's own options (env -u/-S, timeout's duration
	// slot) and inner command head get the same treatment a directly
	// typed invocation receives. A real wrapper head (typedHead[0]
	// already names it) already peeled above and must not re-enter.
	// `caller` is already envAs-seeded.
	if isPeeledWrapperBase(base) && filepath.Base(typedHead[0]) != base {
		return peelResolvedSegDepth(head, seg, kind, depth+1, caller)
	}
	// Strict readonly: allowlist before shell/interpreter unwrap, plus
	// C10 alias target allowlist verification.
	if kind == 'r' {
		if hit := screenReadonlyAllowlistSeg(typedHead, seg.gateProvenanced); hit != "" {
			return allowlistDetail(hit)
		}
		if !gateLeaf {
			if hit := screenReadonlyAliasTarget(typedHead, effPath, caller); hit != "" {
				return allowlistDetail(hit)
			}
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
			// R10-MF-4: when a NON-ASSIGNMENT wrapper word (command/builtin/
			// env/timeout/...) was peeled in front of the declaration builtin,
			// the shell runs export/readonly/declare as an ORDINARY command —
			// the declaration-utility exemption from field splitting no longer
			// applies, so `command export FOO=$X` word-splits $X and exports
			// the smuggled KEY=VAL words. The lenient isAssignWord-only rule
			// is correct only for the bare declaration form, whose operands
			// never field-split. (A prefix-assignment-only prelude keeps the
			// declaration status in dash/bash, so only a non-assignment peeled
			// word flips this check strict.)
			strict := peelPreludeHasNonAssign(argv, head, seg)
			for _, a := range head[1:] {
				if isDynamicArg(a) && (!isAssignWord(a) || (strict && !isSingleWordSplitSafe(a))) {
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
			if hit := screenEnvAssignments(envAs2, kind, caller.role, caller.readonly, base, caller); hit != "" {
				return hit
			}
		}
	}
	if kind == 's' {
		// R13-SF-3: only the shell BUILTIN printf writes shell variables —
		// an explicit-path spelling (/usr/bin/printf, ./printf, ...) execs
		// the external binary in a child process that can never mutate the
		// parent's environment, so the write-target scan does not apply.
		if !(base == "printf" && strings.Contains(typedHead[0], "/")) {
			if hit := screenEnvWriteTargets(head, base); hit != "" {
				return hit
			}
		}
	}
	if text, has := unwrapShellArgv(head); has {
		if isDynamicArg(text) {
			return "dynamic code payload"
		}
		if kind == 's' {
			inner := caller
			// Provenance crosses a `sh -c` boundary ONLY when the script word is
			// the exact rewritten Type-B slot of this buffer (same buffer, exact
			// span, exact decoded text). The slot is re-located with the SAME
			// peel + -c walk prepare* used to mint it, so no other word — even
			// one carrying identical decoded text — can inherit provenance.
			if entryProv != nil {
				// Re-locate the slot under the OUTER caller (matching L3959's
				// gate-head walk): `caller` here is already envAs-seeded, and an
				// env -C re-anchor must not move the prepared -c slot (R4 SF-1).
				if _, headIdx, _, _, exhausted := peelWrappersWithIndex(seg.argv, outerCaller); !exhausted && headIdx >= 0 {
					if scriptRel, _, glued, slotOK := locateShellCSlot(seg.argv[headIdx:]); slotOK && !glued && scriptRel >= 0 {
						if absIdx := headIdx + scriptRel; absIdx >= 0 && absIdx < len(seg.argWords) {
							inner.hcProv = entryProv.innerProvAt(seg.srcCode, seg.argWords[absIdx], text)
						}
					}
				}
			}
			// The -c payload parses under the RESOLVED shell dialect: a
			// same-family alias (sh -> bash) keeps its typed base, but the
			// running interpreter is bash, so bash-only syntax must be
			// judged as bash, not POSIX sh.
			shellDialect := base
			if shellHeads[base] {
				if rb := canonicalResolvedBase(resolveHeadBase(typedHead[0], effPath, caller.screenCwd())); shellHeads[rb] {
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
				if hit := peelResolvedDepth(modArgv, 's', depth+1, caller); hit != "" {
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
		// The inner code screen resolves under the same call cwd as the
		// enclosing head — the guardCall must inherit it or the
		// process-cwd fallback would resolve differently.
		// R24-Reviewer-#1 / R24-Oracle-M1: it also inherits the request's
		// xargs memo/budget table — an inner code screen is the same
		// analysis request, never a fresh 512-step allowance.
		g.cwd = caller.cwd
		g.xw = caller.xw
		if rule, detail := g.guardCtxRunCode(lang, code); rule != "" {
			if detail == roSSHWriteHit || detail == "ctxmode index" || isReportGuardDetail(detail) {
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
	if base == "eval" && len(head) > 1 {
		if kind == 'r' {
			return allowlistDetail("eval")
		}
		// R19-Oracle-M1: bash's builtin eval consumes its own leading `--`
		// option terminator — the re-parse must not re-join it or the real
		// command text degrades into an argument of a `--` command head.
		text := strings.Join(evalJoinOperands(head[1:]), " ")
		if isDynamicArg(text) {
			return "dynamic code payload"
		}
		if kind == 's' {
			// R16-Oracle-M2: eval re-parses in the SAME shell — a segment of a
			// bash payload must face the bash dialect (brace expansion), not
			// the dash POSIX default.
			return guardShellSubagentDepthDialect(text, depth+1, caller, seg.bashDialect)
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	if base == "xargs" {
		if k := xargsTargetIndex(head); k >= 0 && k < len(head) {
			if xargsFeedsCodeFlag(head[k:], head, caller.pathEnv, caller) {
				return "dynamic code payload"
			}
			if repl := xargsReplToken(head); repl != "" && replTokenInExecSlot(head[k:], repl, caller.pathEnv, caller) {
				return "dynamic code payload"
			}
			// Nested hc/herdr-core via xargs can receive injected argv at runtime
			// ( -I replacement / trailing stdin words ). Block unconditionally —
			// including help/query — because no -I `xargs hc --help` still appends
			// stdin words and breaks the two-word pure-query shape.
			target := head[k:]
			th, tea, teffP, tex := peelWrappersAndWrapperAliases(target, caller.pathEnv, caller)
			if tex {
				return "xargs " + depthExceededHit
			}
			// An env -C inside the xargs target re-anchors the target's own
			// resolution: `xargs env -C <evil> ./myctxmode` resolves against
			// <evil>, not the outer cwd — the peeled ops must seed the caller
			// used by both screens (R4 MF-2).
			tCaller := caller.seededWith(tea)
			for _, b := range headBaseAliasHits(th, teffP, tCaller) {
				if b == "hc" || b == "herdr-core" {
					return "xargs " + b
				}
			}
			// `printf '--hc-gate\nsend\nt42\nhi\n' | xargs ctxmode` never spells
			// --hc-gate on the xargs line, yet the runtime argv becomes
			// os.Args[1] == "--hc-gate": an unprovenanced ctxmode/selfExe target
			// through xargs is blocked unconditionally.
			if len(th) > 0 && headIsCtxmodeOrSelfExe(th[0], teffP, tCaller.screenCwd()) {
				return "xargs ctxmode --hc-gate"
			}
			innerSeg := xargsDerivedSeg(head[:k], head[k:], seg, caller.pathEnv, caller)
			return peelResolvedSegDepth(head[k:], innerSeg, kind, depth+1, caller)
		}
		return ""
	}
	if base == "find" {
		if kind == 'r' {
			if hit := screenReadonlyAllowlist(typedHead); hit != "" {
				return allowlistDetail(hit)
			}
			return screenFindArgsSeg(head[1:], seg, kind, depth+1, caller)
		}
		return screenFindArgsSeg(head[1:], seg, kind, depth+1, caller)
	}
	if base == "trap" {
		return screenTrapArgs(head[1:], kind, depth+1, caller, seg)
	}
	if base == "unset" {
		return screenUnsetArgs(head[1:], kind)
	}
	if base == "watch" && len(head) > 1 {
		k, execMode, fc := skipWatchArgs(head, 1)
		if fc {
			return "dynamic code payload"
		}
		if k >= len(head) {
			return ""
		}
		if execMode {
			// watch -x spawns the operand as a process whose fd 0 is the
			// outer stdin stream: pass the stdin projection only.
			return peelResolvedSegDepth(head[k:], stdinOnlySeg(seg), kind, depth+1, caller)
		}
		text := strings.Join(head[k:], " ")
		if isDynamicArg(text) {
			return "dynamic code payload"
		}
		if kind == 's' {
			return guardShellSubagentDepth(text, depth+1, caller)
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	if base == "flock" {
		if kind == 'r' {
			return "flock"
		}
		inner, cmdText := skipFlockArgs(head, 1)
		if cmdText != "" {
			if isDynamicArg(cmdText) {
				return "dynamic code payload"
			}
			return guardShellSubagentDepth(cmdText, depth+1, caller)
		}
		if inner < len(head) {
			// flock fd N command: fd 0 is inherited from the outer stream.
			return peelResolvedSegDepth(head[inner:], stdinOnlySeg(seg), kind, depth+1, caller)
		}
		return ""
	}
	if base == "script" {
		if kind == 'r' {
			return "script"
		}
		if payload := scriptCommandArg(head); payload != "" {
			if isDynamicArg(payload) {
				return "dynamic code payload"
			}
			return guardShellSubagentDepth(payload, depth+1, caller)
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
	if hit := screenReadonlyAllowlistSeg(typedHead, seg.gateProvenanced); hit != "" {
		return allowlistDetail(hit)
	}
	return screenReadonlyWritePath(typedHead, effPath, caller)
}

// xargsHasArgFile reports whether the xargs option zone (before the target
// command) specifies -a FILE or --arg-file[=FILE]. When present, xargs reads
// items from the file and leaves the child process's fd 0 inherited from the
// enclosing shellSegment. GNU unique-prefix abbreviations resolve through
// xargsMatchValueLong/xargsLongConsumesNext so `--arg-f` cannot drift apart
// from the full spelling (v6.2.2 R3 R3-MF-6).
func xargsHasArgFile(xargsOpts []string) bool {
	for i := 1; i < len(xargsOpts); i++ {
		a := xargsOpts[i]
		if a == "--" {
			return false
		}
		if strings.HasPrefix(a, "--") {
			isArgFile, consumedNext := xargsLongIsArgFile(a)
			if isArgFile {
				return true
			}
			if consumedNext {
				i++
			}
			continue
		}
		if xargsClusterHasArgFile(a) {
			return true
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 && xargsClusterConsumesNext(a) {
			i++
		}
	}
	return false
}

// xargsLongIsArgFile screens one `--` word of the xargs option zone:
// isArgFile reports it resolves (exactly or by GNU unique-prefix
// abbreviation) to --arg-file; consumedNext reports it consumes the NEXT
// argv as a plain value operand.
func xargsLongIsArgFile(a string) (isArgFile, consumedNext bool) {
	name := a[2:]
	hasEq := strings.IndexByte(name, '=') >= 0
	if k := strings.IndexByte(name, '='); k >= 0 {
		name = name[:k]
	}
	if xargsMatchValueLong(name) == "arg-file" {
		return true, false
	}
	return false, !hasEq && xargsLongConsumesNext(a)
}

// xargsClusterHasArgFile reports whether one short-option cluster word of
// the xargs option zone carries the -a FILE letter. The scan ends at the
// first value-bearing letter (its tail IS the value) and at the
// optional-glued -e/-i letters.
func xargsClusterHasArgFile(a string) bool {
	if !strings.HasPrefix(a, "-") || len(a) <= 1 || strings.HasPrefix(a, "--") {
		return false
	}
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if ch == 'a' {
			return true
		}
		if ch == 'e' || ch == 'i' {
			return false
		}
		if xargsShortWithValue[ch] {
			return false // value letter ends the cluster
		}
	}
	return false
}

// stdinOnlySeg projects a shellSegment onto ONLY its true stdin-source
// fields: the parts of the enclosing command line that decide where the
// nested command's fd 0 comes from. argv/argWords/srcCode/gateProvenanced
// are all zeroed — a derived segment must never inherit the outer
// command's words (a rewritten `<selfExe> --hc-gate` leaf would otherwise
// leak its provenance into the child's screen), and redirectFile is an
// OUTPUT field that says nothing about the child's stdin.
func stdinOnlySeg(s shellSegment) shellSegment {
	return shellSegment{
		pipedStdin:  s.pipedStdin,
		stdinRedir:  s.stdinRedir,
		heredocText: s.heredocText,
		hereString:  s.hereString,
	}
}

// xargsDerivedSeg models the shellSegment seen by the target command of
// xargs: with -a/--arg-file, the child inherits outerSeg's stdin stream;
// without -a, xargs consumes outerSeg's stdin to build trailing argv tokens
// and redirects child fd 0 to /dev/null — EXCEPT when the target command is
// an ssh invocation whose remote command reads a program from stdin
// (`echo code | xargs ssh dmit sh`), where OpenSSH joins xargs-appended
// words into the remote login shell command string.
func xargsDerivedSeg(xargsOpts, targetArgv []string, outerSeg shellSegment, pathEnv string, caller callerIdentity) shellSegment {
	if xargsHasArgFile(xargsOpts) {
		// The child inherits the outer stdin stream — but only the stdin
		// facts, never the outer words or their provenance. A benign
		// here-string/heredoc must NOT suppress the -a append risk: only a
		// real pipe or file redirection feeds the target's stdin directly,
		// while xargs still appends the -a FILE's words after the ssh
		// invocation exactly like a pipe feed (v6.2.2 R3 R3-MF-6
		// `xargs -a <payload> ssh dmit sh <<< 'echo hi'`).
		if !(outerSeg.pipedStdin || outerSeg.stdinRedir) && sshTunnelsStdinProgram(targetArgv, pathEnv, caller) {
			return shellSegment{pipedStdin: true}
		}
		return stdinOnlySeg(outerSeg)
	}
	if sshTunnelsStdinProgram(targetArgv, pathEnv, caller) {
		// Without -I the appended words ALWAYS come from xargs' stdin —
		// piped, redirected, or the ctx_run stdin parameter (argv mode,
		// where outerSeg carries no facts at all). A remote stdin-program
		// target (ssh dmit sh) reads them as program text (v6.2.2 R3
		// R2-MF-5); the precise downstream verdict names the transport.
		return shellSegment{pipedStdin: true}
	}
	return shellSegment{}
}

// peeledExecHead carries the wrapper-peeled head of an exec-slot argv plus
// the screens' alias variants and the fail-closed facts collected while
// peeling (exhausted peel, dangling wrapper head, unknown env options, an
// env -S split payload naming the token).
type peeledExecHead struct {
	head        []string
	variants    [][]string
	envAs       envAssignments
	effPath     string
	caller      callerIdentity
	hasSplitTok bool
	failClosed  bool
}

// findExecSlotValueOpts are find's value-carrying predicates, mirrored from
// screenFindArgsSeg's own table so both screens agree on which words consume
// a value slot. A token in such a value (find . -name {}) stays a data
// operand.
var findExecSlotValueOpts = map[string]bool{
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
	// One-operand file-output predicates (v6.2.2 MF-7): leaving them out
	// shifts the operand walk so a following -exec misaligns.
	"-fprint": true, "-fprint0": true, "-fls": true, "-files0-from": true,
}

// isFindValueOpt reports whether a find operand word is a value-carrying
// predicate whose operand must be skipped as DATA: the explicit
// findExecSlotValueOpts table plus GNU find's time predicates
// (-amin/-atime/-cmin/-ctime/-context) and the -newerXY family
// (-newermm etc — 8 chars, XY in aBcmt) (v6.2.2 R3 R2-SF-2).
func isFindValueOpt(a string) bool {
	if findExecSlotValueOpts[a] {
		return true
	}
	switch a {
	case "-amin", "-atime", "-cmin", "-ctime", "-context":
		return true
	}
	if len(a) == 8 && strings.HasPrefix(a, "-newer") {
		x, y := a[6], a[7]
		okX := x == 'a' || x == 'B' || x == 'c' || x == 'm' || x == 't'
		okY := y == 'a' || y == 'B' || y == 'c' || y == 'm' || y == 't'
		return okX && okY
	}
	return false
}

// envHeadSplitHasToken reports whether the raw -S/--split-string payload of
// an `env` argv head names the placeholder token. xargs -I{} env -S 'perl {}'
// splits AFTER the substitution, so a token inside the payload can become an
// option word (perl -e) at runtime. The head name normalizes through
// canonicalResolvedBase so a genv brew spelling scans the same (v6.2.2 MF-5).
func envHeadSplitHasToken(argv []string, token string) bool {
	if canonicalResolvedBase(filepath.Base(argv[0])) != "env" {
		return false
	}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			return false // end of env's option zone
		}
		if a == "-" {
			continue // GNU env: a bare "-" is exactly -i, the scan continues
		}
		if !strings.HasPrefix(a, "-") {
			return false // first operand/command word ends env's option zone
		}
		if strings.HasPrefix(a, "--") {
			consume, hit := envLongSplitHasToken(argv, i, token)
			if hit {
				return true
			}
			i += consume
			continue
		}
		consume, hit := envClusterSplitHasToken(argv, i, token)
		if hit {
			return true
		}
		i += consume
	}
	return false
}

// envLongSplitHasToken screens one long-option word of env's option zone;
// consume is how many EXTRA argv operands the option's value takes. GNU
// unique-prefix abbreviations resolve through envMatchLong like
// skipEnvOperands, so `--split`/`--s=`/`--ch` cannot drift (v6.2.2 MF-5).
func envLongSplitHasToken(argv []string, i int, token string) (consume int, hit bool) {
	name, val, hasVal := argv[i][2:], "", false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, val, hasVal = name[:k], name[k+1:], true
	}
	switch envMatchLong(name) {
	case "split-string":
		if hasVal {
			return 0, strings.Contains(val, token)
		}
		if i+1 < len(argv) {
			return 1, strings.Contains(argv[i+1], token)
		}
	case "unset", "chdir", "argv0":
		if !hasVal && i+1 < len(argv) {
			return 1, false
		}
	}
	return 0, false
}

// envClusterSplitHasToken scans one short-option cluster of env's option
// zone for a token-carrying -S payload; consume is how many EXTRA argv
// operands the cluster's trailing value letter takes.
func envClusterSplitHasToken(argv []string, i int, token string) (consume int, hit bool) {
	a := argv[i]
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'u', 'C', 'a':
			if j+1 >= len(a) {
				return 1, false // separate value operand
			}
			return 0, false
		case 'S':
			if tail := a[j+1:]; tail != "" {
				return 0, strings.Contains(tail, token)
			}
			if i+1 < len(argv) {
				return 1, strings.Contains(argv[i+1], token)
			}
			return 0, false
		}
	}
	return 0, false
}

// peelWrappersWithPayloads is peelWrappersAndWrapperAliases for exec-slot
// screens: unlike the shared peel it does not drop env -S payloads or treat
// a dangling wrapper head as safe. Exhausted peels, an empty residual head
// (xargs env with nothing after it) and any env unknown-option/split payload
// all fail closed, and hasSplitTok marks an env -S payload carrying the
// token.
func peelWrappersWithPayloads(argv []string, pathEnv string, caller callerIdentity, token string) peeledExecHead {
	var out peeledExecHead
	out.effPath = pathEnv
	cur := argv
	for steps := 0; steps < peelWrapperMaxSteps; steps++ {
		// Scan the CURRENT chain's wrapper positions for an env head whose
		// raw -S payload carries the token — BEFORE peeling rewrites or
		// drops the payload (v6.2.2 R3 R2-MF-7). The scan is constrained
		// to wrapper positions only: a non-wrapper command head (rg, echo)
		// ends the walk, so `rg env -S {}` never false-hits on the
		// smart-case flag, while alias-rewritten chains re-scan after each
		// rewrite so ./myenv -> env still exposes its -S payload.
		if !out.hasSplitTok && wrapperChainEnvSplitHasToken(cur, out.effPath, caller, token) {
			out.hasSplitTok = true
		}
		h, sp, ea, ex := peelWrappers(cur)
		out.envAs = out.envAs.merged(ea)
		out.effPath = ea.effectivePATHFrom(out.effPath)
		caller = caller.seededWith(ea)
		if ex || len(sp) > 0 || len(h) == 0 {
			out.failClosed = true
			out.head, out.caller = h, caller
			return out
		}
		if rb := canonicalResolvedBase(resolveHeadBase(h[0], out.effPath, caller.screenCwd())); rb != "" && rb != filepath.Base(h[0]) && isPeeledWrapperBase(rb) {
			cur = append([]string{rb}, h[1:]...)
			continue
		}
		out.head, out.caller = h, caller
		return out
	}
	out.failClosed = true
	out.head, out.caller = cur, caller
	return out
}

// wrapperChainEnvSplitHasToken walks the leading wrapper chain of argv and
// reports whether any ENV head inside that chain carries a -S/--split-string
// payload naming the token. The walk is constrained to wrapper positions:
// assignment words and shell no-op prefixes step free; a wrapper head
// (resolved through PATH aliases so ./myenv -> env counts) hands its OWN
// argv to envHeadSplitHasToken when it is env, then the walk steps past
// the wrapper with peelWrappers' exact operand arities. The FIRST
// non-wrapper command head ends the zone — operand positions of real
// commands (rg env -S {}) are never scanned (v6.2.2 R3 R2-MF-7).
func wrapperChainEnvSplitHasToken(argv []string, pathEnv string, caller callerIdentity, token string) bool {
	cur := argv
	for depth := 0; depth < peelWrapperMaxSteps; depth++ {
		if len(cur) == 0 {
			return false
		}
		a := cur[0]
		if isAssignWord(a) || shellNoopWords[a] {
			cur = cur[1:]
			depth-- // assignments/no-ops are free prefixes, not wrappers
			continue
		}
		if isDynamicArg(a) {
			return false
		}
		base := filepath.Base(a)
		if rb := canonicalResolvedBase(resolveHeadBase(a, pathEnv, caller.screenCwd())); rb != "" {
			base = rb
		} else if cb := canonicalResolvedBase(base); cb != "" {
			base = cb
		}
		if base == "env" {
			// An env position: scan its own option zone for the -S token
			// under the CANONICAL env head spelling (an alias ./myenv still
			// parses env options — v6.2.2 R3 R3-MF-2). When the scan does
			// not hit, step past THIS ONE env layer with skipEnvOperands'
			// own arities and keep walking the chain: nested forms like
			// `env -- env -S ...` / `env -i env -S ...` must still expose
			// the inner env's payload instead of ending the walk here.
			canon := append([]string{"env"}, cur[1:]...)
			if envHeadSplitHasToken(canon, token) {
				return true
			}
			// The token-aware operand walk (v6.2.2 Oracle R5 R5-MF-2): an
			// -S/--split-string payload carrying the token anywhere INSIDE
			// the nested split recursion counts as a hit — an outer `env -S`
			// whose split re-spells an inner `-S`/`--split-string` option word
			// (`env -S "-S" "find . -name {}"` / `env "-S-S" ...` /
			// `env -S "-i -S" ...`) can no longer digest the inner payload
			// in the same call and hide it from envHeadSplitHasToken's scan.
			rest, payloads, ea, splitHit := skipEnvOperandsToken(cur, 1, envAssignments{}, token, 0)
			if splitHit {
				return true
			}
			if len(payloads) > 0 || len(rest) == 0 {
				return false // unknown/dangling env options fail closed, not open
			}
			// No length-shrink requirement: an outer env -S's split can RE-SPELL
			// env heads and keep len(rest) == len(cur) or longer (`env "-Senv -S"
			// "find . -name {}"` -> `env -S "find . -name {}"`), which must NOT
			// end the walk — the outer depth budget already bounds it, and a
			// non-converging chain fails CLOSED below (v6.2.2 Oracle R4 R4-MF-3).
			pathEnv = ea.effectivePATHFrom(pathEnv)
			caller = caller.seededWith(ea)
			cur = rest
			continue
		}
		if !isPeeledWrapperBase(base) && base != "command" && base != "builtin" && base != "exec" && base != "nohup" && base != "setsid" && base != "busybox" {
			return false // first real command head ends the wrapper zone
		}
		// Step past THIS wrapper layer ONLY (never the whole chain — a
		// full-chain peel would leapfrog an intermediate env -S position,
		// the R3 regression that re-opened nice env -S "find . -name {}").
		// peelSingleWrapperArgs is called with the RESOLVED base directly so
		// a PATH-alias wrapper (./mynice) still peels under its canonical
		// arity (v6.2.2 Oracle R4 R4-MF-3).
		wi, ok := peelSingleWrapperArgs(cur, base)
		if !ok || wi > len(cur) {
			return false
		}
		rest := cur[wi:]
		if len(rest) == 0 || len(rest) >= len(cur) {
			return false
		}
		cur = rest
	}
	// Depth exhausted without reaching a real command head: the chain's
	// shape is unprovable — fail CLOSED (peelWrappers' exhausted parity,
	// v6.2.2 Oracle R4 R4-MF-3).
	return true
}

// peelSingleWrapperArgs consumes the option words of ONE wrapper head and
// returns the index its command operand starts at; ok is false when the
// base is not a peelable wrapper or a dynamic word in the option zone
// makes the arity unprovable (fail closed, like peelWrappers).
func peelSingleWrapperArgs(argv []string, base string) (int, bool) {
	switch base {
	case "nice":
		return skipNiceSingleArgs(argv, 1)
	case "timeout":
		i, fc := skipTimeoutArgs(argv, 1)
		return i, !fc
	case "stdbuf":
		i, fc := skipStdbufArgs(argv, 1)
		return i, !fc
	case "ionice":
		i, fc := skipIoniceArgs(argv, 1)
		return i, !fc
	case "taskset":
		i, fc := skipTasksetArgs(argv, 1)
		return i, !fc
	case "chrt":
		i, fc := skipChrtArgs(argv, 1)
		return i, !fc
	case "strace", "ltrace":
		i, fc := skipStraceArgs(argv, 1)
		return i, !fc
	case "nohup", "busybox":
		return skipDashDash(argv, 1), true
	case "setsid":
		return skipPlainFlagZone(argv, 1), true
	case "command", "builtin":
		if isCommandQuery(argv[1:]) {
			return 0, false
		}
		i := 1
		for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
			i++
		}
		return skipDashDash(argv, i), true
	case "exec":
		i, fc := skipExecArgs(argv, 1)
		return i, !fc
	case "time":
		return skipTimeSingleArgs(argv, 1)
	}
	return 0, false
}

// skipNiceSingleArgs consumes nice's option words: -n/--adjustment carry a
// separate value operand, everything else is boolean. The second return
// reports the fail-closed arity verdict (dynamic zone word or a trailing
// valued option missing its operand, stopping at exactly len(argv) —
// R26-Oracle-M4: the pre-R26 i+=2 overflowed the slice bound). The scan
// shares peelWrappers' option-zone consumer exactly so the single-pass
// peel and the one-layer walk can never drift apart.
func skipNiceSingleArgs(argv []string, i int) (int, bool) {
	ni, fc := peelFlagZone(argv, i, true, true, niceValuedOpt)
	return ni, !fc
}

// skipPlainFlagZone consumes a boolean-only wrapper option zone (setsid):
// every dashed word up to `--` or the first operand.
func skipPlainFlagZone(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return i
		}
		i++
	}
	return i
}

// skipTimeSingleArgs consumes time's option words: -o/--output/-f/--format
// carry a separate value operand, everything else is boolean. The second
// return reports the fail-closed arity verdict exactly like
// skipNiceSingleArgs (R26-Oracle-M4).
func skipTimeSingleArgs(argv []string, i int) (int, bool) {
	ni, fc := peelFlagZone(argv, i, true, true, timeValuedOpt)
	return ni, !fc
}

// peelExecSlotHead peels wrappers off an exec-slot argv and produces the
// literal head plus its alias-resolution variants. A cross-family structural
// re-identity (xargs -> /bin/sh, bun -> node) fails closed; a same-family
// link only adds the canonical spelling as a second variant.
func peelExecSlotHead(argv []string, pathEnv string, caller callerIdentity, token string) peeledExecHead {
	p := peelWrappersWithPayloads(argv, pathEnv, caller, token)
	if p.failClosed || len(p.head) == 0 {
		p.failClosed = true
		return p
	}
	typed := filepath.Base(p.head[0])
	tb := canonicalResolvedBase(typed) // normalize g-prefixed/npm-cli spellings first (v6.2.2 SF-2)
	p.variants = [][]string{p.head}
	if tb != "" && tb != typed {
		// Write the canonical spelling back as a variant (v6.2.2 R3 R2-SF-1):
		// gfind/gxargs/genv spellings must face the SAME find/xargs/env
		// screens as their canonical bases even when nothing resolves on
		// disk (peelResolvedSegDepth L4010-style normalization).
		p.variants = append(p.variants, append([]string{tb}, p.head[1:]...))
	}
	if isDynamicArg(p.head[0]) {
		return p
	}
	rb := canonicalResolvedBase(resolveHeadBase(p.head[0], p.effPath, p.caller.screenCwd()))
	if rb == "" || rb == tb {
		return p
	}
	typedStructural := isStructuralGuardHead(tb) || isPeeledWrapperBase(tb) || isBlockedAgentHead(tb)
	resolvedStructural := isStructuralGuardHead(rb) || isPeeledWrapperBase(rb) || isBlockedAgentHead(rb)
	if rb != typed && typedStructural && resolvedStructural && !sameStructuralFamily(tb, rb) {
		p.failClosed = true
		return p
	}
	p.variants = append(p.variants, append([]string{rb}, p.head[1:]...))
	return p
}

// replTokenInPeeledEnv reports whether a peeled env operation list plants
// the token into an execution-relevant variable or working directory.
func replTokenInPeeledEnv(envAs envAssignments, token string) bool {
	for _, op := range envAs.ops {
		if strings.Contains(op.key, token) {
			return true
		}
		if op.kind == 'd' || op.key == "PATH" || isEnvHookVar(op.key) ||
			guardTaintVars[op.key] || sentinelTrustVars[op.key] {
			if strings.Contains(op.value, token) {
				return true
			}
		}
	}
	return false
}

// replTokenInExecSlot reports whether a placeholder token (xargs -I token or
// find -exec "{}") sits in a command-execution slot of innerArgv: the peeled
// command head itself, an inline shell/interpreter code slot (-c/-e), or the
// remote command head / code slot inside an ssh invocation. Data operand
// positions (`grep foo {}`, `git -C {} status`, `sh -c 'echo "$1"' _ {}`)
// return false. Command indirection layers (xargs / flock / watch / find
// -exec / ssh) are descended with a bounded depth.
func replTokenInExecSlot(innerArgv []string, token, pathEnv string, caller callerIdentity) bool {
	return replTokenInExecSlotDepth(innerArgv, token, pathEnv, caller, 0, false)
}

// replTokenInExecSlotFind is replTokenInExecSlot for find's OWN -exec/-ok
// family: find expands "{}" onto its scan-root file paths, which never
// start with '-', so a bare find "{}" is provably option-inert — unlike
// the xargs replacement token, which expands onto arbitrary stdin bytes
// (v6.2.2 Oracle R4 R4-MF-2).
func replTokenInExecSlotFind(innerArgv []string, token, pathEnv string, caller callerIdentity) bool {
	return replTokenInExecSlotDepth(innerArgv, token, pathEnv, caller, 0, true)
}

// replTokenInExecSlotDepth is the bounded-depth worker of
// replTokenInExecSlot. Reaching peelChainMaxDepth fails closed.
// findPathToken is true only when token is find's OWN "{}" placeholder
// (the screenFindExecInner entry): xargs replace tokens and every further
// descent pass false (v6.2.2 Oracle R4 R4-MF-2).
func replTokenInExecSlotDepth(innerArgv []string, token, pathEnv string, caller callerIdentity, depth int, findPathToken bool) bool {
	if token == "" || len(innerArgv) == 0 {
		return false
	}
	if depth >= peelChainMaxDepth {
		// R25-Oracle-MF4 / R25-Reviewer-#2: the replacement-slot recursion's
		// own depth cutoff is an ANALYSIS cutoff exactly like the enclosing
		// xargs scan's — returning the hit verdict without recording the
		// sticky exhaustion bit let the outer projection mint a confirmed
		// empty-language target for a consumer nobody identified. When the
		// caller carries a shared request table the cutoff is recorded on
		// it exactly like the xargsFeedsCodeFlagDepth boundary.
		xargsMarkSharedWorkExhausted(caller)
		return true
	}
	p := peelExecSlotHead(innerArgv, pathEnv, caller, token)
	if p.failClosed || len(p.head) == 0 {
		return true
	}
	if p.hasSplitTok || replTokenInPeeledEnv(p.envAs, token) || strings.Contains(p.head[0], token) {
		return true
	}
	for _, h := range p.variants {
		if replTokenInVariant(h, token, p.effPath, p.caller, caller, depth, findPathToken) {
			return true
		}
	}
	return false
}

// replTokenInVariant screens one spelling of the peeled exec-slot head:
// inline code slots first, then the command-indirection heads that need a
// depth+1 descent.
func replTokenInVariant(h []string, token, effPath string, tCaller, outerCaller callerIdentity, depth int, findPathToken bool) bool {
	if text, has := unwrapShellArgv(h); has && strings.Contains(text, token) {
		return true
	}
	if _, code, has := unwrapInterpreterInline(h); has && strings.Contains(code, token) {
		return true
	}
	for _, slot := range interpCodeSlots(h) {
		if slot.flagOnly || strings.Contains(slot.text, token) {
			return true
		}
	}
	b := filepath.Base(h[0])
	if depth >= 1 && (b == "hc" || b == "herdr-core" || headIsCtxmodeOrSelfExe(h[0], effPath, tCaller.screenCwd())) {
		// A nested report-channel/gate head inside a descended layer
		// (flock ... hc, watch -x ctxmode) fails closed on the spot; at
		// depth 0 the top-level xargs/find screens name the nested head
		// themselves, so the exec-slot analysis stays silent there.
		return true
	}
	// A token in a shell/interpreter's OWN option zone (`sh % 'pig'`,
	// `python3 % 'import ...'`) expands before the shell/interpreter parses
	// its options: at runtime `%` becomes -c/-m/-e and the following static
	// word runs as code. Words AFTER the first code slot or static script
	// operand are script argv and stay free (v6.2.2 MF-8).
	if shellHeads[b] || isPythonInterpBase(b) || inlineSlotInterpBase(b) {
		if interpOptionZoneHasToken(h, token, b, findPathToken) {
			return true
		}
	}
	if replTokenInToolExecSlots(h, token, b, findPathToken) {
		return true
	}
	switch b {
	case "ssh":
		return replTokenInSSH(h, token, outerCaller, depth)
	case "eval":
		return len(h) > 1 && strings.Contains(strings.Join(h[1:], " "), token)
	case "xargs":
		k := xargsTargetIndex(h)
		if k < 0 {
			return true
		}
		// A token in the INNER xargs' own option zone (`xargs -a /tmp/p -% sh
		// -c '{}'`) expands before the inner xargs parses it: at runtime it
		// can become -I/replace bindings that re-route the feed (v6.2.2 MF-8).
		zx := k
		if zx > len(h) {
			zx = len(h)
		}
		for i := 1; i < zx; i++ {
			if strings.Contains(h[i], token) {
				return true
			}
		}
		if k < len(h) {
			// Recursion descends under the env -C-re-anchored caller: an
			// outer `env -C sub` moves the resolution base into sub, and
			// dropping it here would lose the ./mysh -> /bin/sh re-anchor
			// (v6.2.2 MF-6). findPathToken does NOT propagate: even when the
			// outer scan was find's own {}, an xargs descent re-exposes the
			// token to arbitrary stdin bytes (v6.2.2 Oracle R4 R4-MF-2).
			return replTokenInExecSlotDepth(h[k:], token, effPath, tCaller, depth+1, false)
		}
		return false
	case "flock":
		return replTokenInFlock(h, token, effPath, tCaller, depth)
	case "watch":
		return replTokenInWatch(h, token, effPath, tCaller, depth)
	case "script":
		payload := scriptCommandArg(h)
		if payload != "" && (isDynamicArg(payload) || strings.Contains(payload, token)) {
			return true
		}
		// A token in script's own option zone (`script % 'pig' /dev/null`)
		// expands before util-linux script permutes and parses its options:
		// at runtime % can become -c and arm the following word as the
		// command (v6.2.2 R3 R2-MF-6). Words AFTER the first static
		// typescript operand with no -c anywhere stay inert data.
		return scriptOptZoneHasToken(h, token)
	case "find":
		return replTokenInFind(h[1:], token, effPath, tCaller, depth)
	}
	return false
}

// replTokenInSSH descends into the ssh remote command: a parse failure, a
// bare-token remote command, or a token in an execution slot of any remote
// segment all count as an exec-slot hit.
func replTokenInSSH(h []string, token string, outerCaller callerIdentity, depth int) bool {
	// A token in ssh's own option zone or the <destination> word is a
	// local-injection slot: at runtime it can expand into a local option
	// (-oProxyCommand=...) or a different destination (v6.2.2 MF-8).
	if sshLocalZoneHasToken(h, token) {
		return true
	}
	remoteCmd, hit := parseSSHInvocation(h)
	if hit != "" {
		return true
	}
	// OpenSSH joins every remote-command word with spaces and hands the
	// result to the remote $SHELL -c: a token ANYWHERE inside the joined
	// text expands before the remote shell parses it (v6.2.2 MF-8), exactly
	// like the non-x watch join.
	if strings.Contains(remoteCmd, token) {
		return true
	}
	for _, rseg := range splitShellSegments(remoteCmd) {
		if rseg.parseErr != "" || rseg.depthExceeded {
			return true
		}
		if len(rseg.argv) == 0 {
			continue
		}
		if replTokenInExecSlotDepth(rseg.argv, token, os.Getenv("PATH"), callerIdentity{cwd: outerCaller.cwd, xw: outerCaller.xw}, depth+1, false) {
			return true
		}
	}
	return false
}

// inlineSlotInterpBase reports whether base names a non-Python inline-code
// interpreter head (node/bun/tsx/ts-node/perl/ruby/php).
func inlineSlotInterpBase(b string) bool {
	_, ok := inlineSlotInterpLang(b)
	return ok
}

// interpOptionZoneHasToken reports whether the token sits in the option
// zone (or first operand slot) of a shell/interpreter argv. The scan is
// driven by the head's own interpOptSpec (v6.2.2 R3 R2-MF-6): value options
// consume their operands (the operand word itself is still token-checked),
// code slots consume their operands too but do NOT end the scan unless the
// spec stops on first code (CPython) or the head is a POSIX shell — shells
// positional $0/$1 after -c are data slots (`sh -c 'echo "$1"' _ {}`),
// while multi-code interpreters (perl/ruby/node/bun/tsx/php) may carry a
// SECOND -e/-r after the first whose slot the runtime expansion can still
// arm. The zone ends at -- or the first static non-option script operand.
func interpOptionZoneHasToken(h []string, token, base string, findPathToken bool) bool {
	spec, hasSpec := lookupInterpOptSpec(base)
	end := len(h)
	codeDone := 0
	for i := 1; i < len(h); i++ {
		a := h[i]
		if a == "--" || (shellHeads[base] && codeDone > 0 && (a == "-" || a == "+")) {
			if shellHeads[base] && codeDone > 0 {
				// A pending shell -c survives the option terminator: the word
				// right after it IS the command string and stays inside the
				// zone (`xargs -a <p> -I% sh -co errexit -- %` — v6.2.2 Oracle
				// R6 R6-MF-1). POSIX's bare "-"/"+" spellings settle exactly
				// like "--" here (v6.2.2 Oracle R7 R7-MF-3 path B
				// `xargs -a <p> -I{} sh -c - {}`).
				end = i + 2
				break
			}
			end = i + 1 // the word right after -- is the script operand
			break
		}
		ni, stopZone, stopExcl, zoneEnd, consumedCode := interpZoneWordStep(spec, hasSpec, base, h, i, codeDone, token, findPathToken)
		if consumedCode {
			codeDone++
		}
		if zoneEnd {
			end = i + 1 // first static script operand — include it, stop after
			break
		}
		i = ni
		if stopZone {
			if stopExcl {
				end = i // post-code input-data positional: outside the zone
			} else {
				end = i + 1
			}
			break
		}
	}
	if end > len(h) {
		end = len(h)
	}
	for i := 1; i < end; i++ {
		if strings.Contains(h[i], token) {
			return true
		}
	}
	return false
}

// interpZoneWordStep advances interpOptionZoneHasToken's scan past the
// word at index i (extracted so the scan loop stays reviewable — v6.2.2
// R3). next is the index the loop continues from; stopZone reports the
// zone ends AFTER this word (first code slot of a stop-on-first-code
// interpreter or a shell); zoneEnd reports the first static non-option
// script operand was reached. codeDone counts the code slots already
// consumed: for multi-code interpreters (perl/ruby/node/bun/tsx/php) a
// non-option word AFTER a code slot is input-DATA (the script file or
// stdin data — v6.2.2 R3 R3-MF-5/Reviewer R2-6 `find -exec perl -pe
// 's/a/b/' {}`), so it ends the zone for REAL instead of posing as the
// script operand. token is the replacement token xargs/find expands and
// findPathToken is true ONLY for find's own "{}" (whose expansion onto
// scan-root file paths never starts with '-'): a token-carrying post-code
// positional stays data only when it is provably option-inert — the token
// is absent, a non-empty static prefix precedes it (`./{}`/`dir/{}` — the
// expansion can never begin with '-'), or it is find's own bare "{}"
// (v6.2.2 Oracle R4 R4-MF-2: the R5 last-word exemption let a single
// xargs-fed word arm a GLUED second code option — `-esystem("pig")` —
// with no trailing operand at all).
func interpZoneWordStep(spec interpOptSpec, hasSpec bool, base string, h []string, i, codeDone int, token string, findPathToken bool) (next int, stopZone, stopExcl, zoneEnd, consumedCode bool) {
	a := h[i]
	next = i
	if !hasSpec {
		if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") {
			return i, false, false, true, false
		}
		return i, false, false, false, false
	}
	switch {
	case strings.HasPrefix(a, "--"):
		return interpZoneLongWordStep(spec, base, h, i)
	case len(a) >= 2 && (a[0] == '-' || a[0] == '+'):
		var consumed int
		var codeHit bool
		if shellHeads[base] {
			consumed, codeHit = shellClusterZoneConsume(a, h, i)
		} else {
			consumed, codeHit = interpClusterZoneStep(spec, a, h, i)
		}
		if codeHit {
			// POSIX shells keep parsing options after a pending -c — the
			// command string is the first NON-OPTION word — so the zone
			// scan must continue through the remaining -/+ words instead of
			// stopping at the -c cluster (v6.2.2 Oracle R6 R6-MF-1
			// `sh -co errexit -o % 'echo hi'`).
			return i + consumed, spec.stopOnFirstCode, false, false, true
		}
		return i + consumed, false, false, false, false
	case !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+"):
		if codeDone > 0 && interpMultiCodeBase(base) {
			// A post-code positional of a multi-code interpreter is input
			// DATA in the common case (the script file or stream data) —
			// its bytes are never re-parsed as options. Two shapes keep
			// the conservative in-zone treatment instead: a DYNAMIC word
			// (cmdsub expansion can spell an option) and a bare token
			// OTHER than find's `{}` — find expands `{}` onto the scan
			// root's file paths (never option-shaped), while an xargs
			// replace token expands onto arbitrary stdin words that CAN
			// re-arm an option (`perl -e '1' % 'system("pig")'`).
			// Everything else ends the zone EXCLUDED — a static data file
			// never counts as a zone hit (v6.2.2 R3 R3-MF-5 / Reviewer
			// R2-6 `find -exec perl -pe 's/a/b/' {}` stays allowed).
			if !isDynamicArg(a) && (!strings.Contains(a, token) || strings.Index(a, token) > 0 || (findPathToken && a == "{}")) {
				return i, true, true, false, false
			}
		}
		return i, false, false, true, false
	}
	return i, false, false, false, false
}

// interpZoneLongWordStep advances interpZoneWordStep past one `--` long
// option word (extracted so interpZoneWordStep stays under the complexity
// budget — v6.2.2 Oracle R6 R6-MF-1): long code slots consume their
// operand and stop the zone for stopOnFirstCode interpreters and POSIX
// shells (long forms have no boolean -c continuation), long value options
// consume a separate value operand.
func interpZoneLongWordStep(spec interpOptSpec, base string, h []string, i int) (next int, stopZone, stopExcl, zoneEnd, consumedCode bool) {
	a := h[i]
	name := a[2:]
	if k := strings.IndexByte(name, '='); k >= 0 {
		name = name[:k]
	}
	opt := "--" + name
	next = i
	if spec.longCode[opt] {
		// A long code slot: consume its operand and either stop
		// (shell/python) or keep scanning (multi-code interps).
		if strings.IndexByte(a, '=') < 0 && i+1 < len(h) {
			next = i + 1
		}
		return next, spec.stopOnFirstCode || shellHeads[base], false, false, true
	}
	if spec.longValue[opt] && strings.IndexByte(a, '=') < 0 && i+1 < len(h) {
		next = i + 1 // plain value operand
	}
	return next, false, false, false, false
}

// interpMultiCodeBase reports whether base names a multi-code-slot
// interpreter (perl/ruby/node/bun/tsx/ts-node/php) whose option zone may
// carry further options after the first code operand.
func interpMultiCodeBase(base string) bool {
	switch base {
	case "perl", "ruby", "node", "nodejs", "bun", "tsx", "ts-node", "php":
		return true
	}
	return false
}

// interpClusterZoneStep walks one short-option cluster in
// interpOptionZoneHasToken's spec-driven scan: consumed counts EXTRA argv
// operands the cluster's trailing value/code letter eats, and codeHit
// reports the cluster names a code slot letter (glued or flag model).
func interpClusterZoneStep(spec interpOptSpec, a string, h []string, i int) (consumed int, codeHit bool) {
	if strings.HasPrefix(a, "--") {
		return 0, false
	}
	plus := a[0] == '+'
	hasFlagCode := false
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if !plus && strings.IndexByte(spec.gluedCodes, ch) >= 0 {
			if j+1 >= len(a) && i+1+consumed < len(h) {
				consumed++ // separate code operand
			}
			return consumed, true
		}
		if !plus && strings.IndexByte(spec.flagCodes, ch) >= 0 {
			hasFlagCode = true
			if j+1 >= len(a) {
				return interpZoneConsumeNext(consumed, i, h), true
			}
			// A letter-only tail keeps parsing as cluster flags — the
			// pending flag-code letter only settles its operand when the
			// scan reaches the end of the word (v6.2.2 R3 R3-MF-5: `node
			// -pe 1 {}` must expose exactly ONE code operand, not two).
			// hasFlagCode carries it across the continuation so a later
			// non-flag letter cannot drop it (v6.2.2 Oracle R4 R4-SF-1).
			continue
		}
		if strings.IndexByte(spec.valShort, ch) >= 0 {
			if j+1 >= len(a) {
				// A bare value letter consumes the NEXT argv as its value
				// slot; a pending flag-code letter then consumes the operand
				// AFTER it as its own code slot (v6.2.2 Oracle R5 R5-MF-1
				// `xargs -a <p> -I% node -pC default '1' %` — scanShortCluster
				// pending parity, the R6 single-slot consumption let the
				// fed word pose as the first script operand and end the zone).
				consumed = interpZoneConsumeNext(consumed, i, h)
				if hasFlagCode {
					consumed = interpZoneConsumeNext(consumed, i, h)
				}
				return consumed, hasFlagCode
			}
			// A glued tail IS the value: no value operand consumed, but the
			// pending flag-code letter still owes its own code slot
			// (`node -pCdefault '1' %`).
			if hasFlagCode {
				consumed = interpZoneConsumeNext(consumed, i, h)
			}
			return consumed, hasFlagCode
		}
		if strings.IndexByte(spec.optNumShort, ch) >= 0 {
			j += consumeNumOptTail(a, j, ch)
			continue
		}
		if strings.IndexByte(spec.optShort, ch) >= 0 {
			return consumed, false
		}
	}
	if hasFlagCode {
		// The cluster ended on non-settling letters after a flag-code
		// letter (`node -pi`): the next argv is the pending CODE operand
		// (v6.2.2 Oracle R4 R4-SF-1, scanShortCluster pending parity).
		return interpZoneConsumeNext(consumed, i, h), true
	}
	return consumed, false
}

// shellClusterZoneConsume walks one short-option cluster of a POSIX shell
// under POSIX's boolean -c model (extracted for interpZoneWordStep —
// v6.2.2 Oracle R6 R6-MF-1): unlike the generic interpClusterZoneStep the
// pending -c letter consumes NO operand of its own (the command string is
// the first non-option word), while a trailing bare -o/-O still eats the
// NEXT argv as its option name. consumed counts those EXTRA argv operands
// and codeHit reports a bare-mode -c letter was seen.
func shellClusterZoneConsume(a string, h []string, i int) (consumed int, codeHit bool) {
	plus := a[0] == '+'
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if ch == 'c' && !plus {
			codeHit = true
			continue
		}
		if ch == 'o' || ch == 'O' {
			if j+1 >= len(a) && i+1+consumed < len(h) {
				consumed++ // bare valued letter: the next argv is its operand
			}
			return consumed, codeHit
		}
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') {
			// A non-letter byte ends the flag letters (ambiguous glued
			// spelling) — no further letters parse.
			return consumed, codeHit
		}
	}
	return consumed, codeHit
}

// interpZoneConsumeNext adds one to consumed when the cluster's trailing
// value/code letter can still reach a next argv operand (v6.2.2 R4-SF-1).
func interpZoneConsumeNext(consumed, i int, h []string) int {
	if i+1+consumed < len(h) {
		return consumed + 1
	}
	return consumed
}

// replTokenInToolExecSlots covers the awk/sed/tar/git execution slots a
// token can land in (v6.2.2 SF-4): awk's program-text operand, sed's -e/-f
// script operands and bare script word, tar's --checkpoint-action=exec*
// and --to-command/--use-compress-program values, and git -c config keys
// that run external commands (core.pager and friends).
func replTokenInToolExecSlots(h []string, token, b string, findPathToken bool) bool {
	switch b {
	case "awk", "gawk", "mawk", "nawk":
		return awkProgramTokenHit(h, token, findPathToken)
	case "sed", "gsed":
		return sedScriptTokenHit(h, token)
	case "tar", "gtar", "bsdtar":
		return tarExecOptTokenHit(h, token)
	case "git":
		return gitConfigExecTokenHit(h, token)
	}
	return false
}

// awkProgramTokenHit reports the token inside awk's program-text operands.
// It reuses awkProgramFrags' full option grammar (v6.2.2 R3 R2-MF-3): a -f
// program FILE leaves the input operands as DATA (no false hit on
// `awk -f parse.awk {}`), while GNU gawk's -e/--source texts, cluster-glued
// -e and the bare program word are all matched against the token. The awk
// OPTION ZONE itself is scanned too — a token inside an option word or a
// value operand expands before awk parses it.
func awkProgramTokenHit(h []string, token string, findPathToken bool) bool {
	program, _, hit := awkProgramFrags(h[1:])
	if hit != "" {
		// awkProgramFrags already flags dynamic/unsafe program sources
		// conservatively; a token anywhere in such a shape counts as a hit.
		for _, a := range h[1:] {
			if strings.Contains(a, token) {
				return true
			}
		}
	}
	if strings.Contains(program, token) {
		// The program text is what awk executes, and a token inside it is
		// awk code (system() reaches a shell). -f input filenames no
		// longer fold into `program` (awkProgramFrags' positional fallback
		// is !sawFile-gated — v6.2.2 R3 R3-MF-6), so a REAL -e fragment
		// cannot hide behind -f either (`gawk -f /dev/null /dev/null -e
		// '{}'` blocks while `awk -f parse.awk {}` stays allowed).
		return true
	}
	// The option zone is scanned unconditionally (v6.2.2 Oracle R6 R6-MF-3
	// path B): an EMPTY program (`gawk -e ''` / `gawk -l '{}'` / `gawk -e ''
	// -i '{}'`) no longer skips the zone scan — the xargs-fed word after
	// the empty fragment can still re-arm an option spelling
	// (`-eBEGIN{system("pig")}`) under gawk's permutation. With no program
	// source the positional input filenames are awk's own data words,
	// which awkOptZoneHasToken already treats as inert unless they carry
	// the bare replace token.
	return awkOptZoneHasToken(h[1:], token, findPathToken)
}

// awkOptZoneHasToken scans awk's option words for the token (cluster tails,
// -f/-v/-F/--assign/--include values): expansion there re-shapes the parse
// before awk reads its operands (v6.2.2 R3 R2-MF-3 --assign/'{}' rows).
func awkOptZoneHasToken(args []string, token string, findPathToken bool) bool {
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" && !endOpts {
			endOpts = true
			continue
		}
		if endOpts {
			return false // words after -- / gawk -E are awk's argv data
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			// Positional program/input-file operands do NOT end the scan:
			// GNU gawk's getopt_long permutes options after operands, so a
			// trailing -f/--file/-i/-W still parses (v6.2.2 Oracle R4
			// R4-MF-4 `gawk -e '1' /dev/null -f '{}'`). A positional that
			// itself IS the bare replace token is NOT inert data either:
			// an xargs-fed word can expand into an option spelling
			// (`-eBEGIN{system("pig")}` / `-f/dev/stdin`) that gawk's
			// permutation picks up (v6.2.2 Oracle R5 R5-MF-3 — interpZoneWordStep
			// parity). find's own bare "{}" stays exempt: its expansion onto
			// scan-root file paths never starts with '-'.
			if strings.Contains(a, token) && !(strings.Index(a, token) > 0 || (findPathToken && a == "{}")) {
				return true
			}
			continue
		}
		if awkGluedDataAssign(a) {
			// Glued pure-data assignments (-vf={} / -F{} / --assign=f={} /
			// --field-separator={}) carry their value inside the word: the
			// token there is DATA awk never executes as program text, in
			// parity with the separate-operand spelling (v6.2.2 Oracle R4
			// R4-SF-3 `awk -v f={}` stays allowed).
			continue
		}
		if strings.Contains(a, token) {
			return true
		}
		consume, hit, endHit := awkOptWordTokenStep(args, i, token)
		if hit {
			return true
		}
		if endHit {
			// gawk -E/--exec/-W exec ends awk's own option parsing: words
			// after its operand are the program's argv data (v6.2.2 Oracle
			// R5 R5-SF-1 — the comment claimed this but endOpts was never
			// set, so a post-exec data word could still false-hit).
			endOpts = true
		}
		i += consume
	}
	return false
}

// awkGluedDataAssign reports whether a is a GLUED pure-data awk assignment
// word (-v<kv> / -F<fs> / --assign=<kv> / --field-separator=<fs>): the
// value lives inside the word itself, so the separate-operand data
// exemption applies to the whole word (v6.2.2 Oracle R4 R4-SF-3). Only
// cluster shapes whose FIRST letter is the value letter count — in
// `-ev{}` the tail is program text, not an assignment.
func awkGluedDataAssign(a string) bool {
	if strings.HasPrefix(a, "--assign=") || strings.HasPrefix(a, "--field-separator=") {
		return true
	}
	if strings.HasPrefix(a, "--") || len(a) < 3 {
		return false
	}
	return a[0] == '-' && (a[1] == 'v' || a[1] == 'F')
}

// awkOptWordTokenStep advances awkOptZoneHasToken past the option word at
// index i: consume counts EXTRA argv operands the word's trailing value
// letter eats, hit reports the token inside a PROGRAM-bearing value
// operand. Pure-data assignment operands (-v/-F/--assign/
// --field-separator) are consumed so they cannot pose as the program,
// but a token inside them is data awk never executes as code — the
// dynamic system() surface is screenAwkSubagent's own scope (v6.2.2 R3
// R3-Obs-1 `awk -v fname={} 'END{print fname}' {}` stays allowed).
func awkOptWordTokenStep(args []string, i int, token string) (consume int, hit bool, endHit bool) {
	a := args[i]
	if strings.HasPrefix(a, "--") {
		name := a[2:]
		hasEq := strings.IndexByte(name, '=') >= 0
		if k := strings.IndexByte(name, '='); k >= 0 {
			name = name[:k]
		}
		endHit = isLongOptAbbrev(name, "exec", 1)
		if !hasEq && awkLongTakesValue(name) && i+1 < len(args) {
			if awkLongValueIsProgram(name) && strings.Contains(args[i+1], token) {
				return 1, true, endHit
			}
			return 1, false, endHit
		}
		return 0, false, endHit
	}
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'e', 'f', 'i', 'l', 'E':
			// Program-bearing options: the operand IS awk source (or names
			// the source file/library — gawk -l/--load included, v6.2.2
			// Oracle R5 R5-MF-4), so a token inside it is a hit. -E
			// additionally ends awk's own option parsing (gawk --exec).
			isE := a[j] == 'E'
			if j+1 >= len(a) && i+1 < len(args) {
				if strings.Contains(args[i+1], token) {
					return 1, true, isE
				}
				return 1, false, isE
			}
			return 0, false, isE // glued tail IS the value — the cluster ends
		case 'F', 'v':
			// Pure-data assignments (field separator / var=value): consumed
			// but never a hit on the VALUE itself (v6.2.2 R3 R3-Obs-1).
			if j+1 >= len(a) && i+1 < len(args) {
				return 1, false, false
			}
			return 0, false, false
		case 'W':
			wc, wh := awkWOperandTokenStep(args, i, j, a, token)
			wv, _ := awkWClusterValue(args, i, j, a)
			// v6.2.2 Oracle R8 R8-SF-1: the item name is the LAST comma
			// item's name — `-W interactive,exec` ends awk's option parse
			// exactly like `-W exec`.
			wName := awkWLastItemName(wv)
			return wc, wh, isLongOptAbbrev(wName, "exec", 1)
		case 'd', 'D', 'L', 'o', 'p':
			// gawk optional_argument short options (getopt_long d::/D::/L::/
			// o::/p::): a glued tail IS the option's argument and ends the
			// cluster immediately without consuming the next argv — the
			// tail's letters must never reach the 'e'/'f'/'v' cases
			// (v6.2.2 Oracle R6 R6-MF-4 `gawk -Lfatal`/`gawk -p/dev/null`/
			// `xargs -a <p> -I{} gawk -d/tmp/v {}`).
			if j+1 < len(a) {
				return 0, false, false
			}
		}
	}
	return 0, false, false
}

// (awkWValueIsProgram is superseded by awkLongProgramName's GNU-prefix
// resolution — v6.2.2 Oracle R4 R4-MF-4.)

// awkWOperandTokenStep handles one gawk -W compatibility letter inside a
// short cluster under GNU getopt_long's "W;" translation (`-W x=y` ==
// `--x=y`, `-W x` == `--x`, `-W x y` == `--x y` — v6.2.2 Oracle R4
// R4-MF-4): the bare-word spellings consume the operand word AND the
// value word after it, and the token check lands on the real VALUE slot
// (`-W exec '{}'` hits on args[i+2], not on the bare word `exec`).
func awkWOperandTokenStep(args []string, i, j int, a, token string) (consume int, hit bool) {
	v := ""
	consume = 0
	if j+1 < len(a) {
		v = a[j+1:]
	} else if i+1 < len(args) {
		v, consume = args[i+1], 1
	} else {
		return 0, false
	}
	if strings.Contains(v, ",") {
		// mawk chains several -W operands with commas — the composite is
		// never ONE option name, so the token check must split it exactly
		// like awkWCommaProgram splits the program grammar (v6.2.2 Oracle
		// R7 R7-MF-4 `-W interactive,exec` / `-W i,e`).
		return awkWCommaTokenHit(v, args, i, consume, token)
	}
	// Inline x=y spelling: the value is inside v itself.
	name, eqVal, hasEq := strings.Cut(v, "=")
	isProg, _ := awkLongProgramName(name)
	if !isProg {
		// The OPTION NAME itself is attacker-controlled in the `-W {}` /
		// `-W "$X"` spellings: the runtime expansion can spell a
		// program-source option (`exec` / `source=BEGIN{system("pig")}`)
		// that the static scan never sees (v6.2.2 Oracle R6 R6-MF-3
		// `xargs -a <p> -I{} awk -W '{}' /dev/stdin` — mawk AND gawk).
		// Pure-data assignments (-W assign=x={} / -W assign '{}') keep
		// their exemption: their value is data awk never executes.
		if strings.Contains(name, token) {
			return consume, true
		}
		// Non-program value-bearing options (assign / field-separator and
		// their GNU unique prefixes) consume their separate value operand
		// too — otherwise the value word poses as the program and hides
		// the REAL program text behind it (v6.2.2 Oracle R5 R5-MF-4
		// `xargs -a <p> -I{} gawk -W assign 'x=1' '{}'`).
		if awkLongIsDataAssign(name) {
			if !hasEq && i+consume+1 < len(args) {
				return consume + 1, false
			}
			return consume, false
		}
		if strings.Contains(v, token) {
			return consume, true
		}
		return consume, false
	}
	if hasEq {
		return consume, strings.Contains(eqVal, token)
	}
	// Bare -W word spelling: the value is the NEXT argv after the operand
	// word — that slot is what carries the token (`-W exec '{}'`). Both
	// file-valued (exec/file) and inline-text (source) operands hit on it:
	// either way the word names awk program material.
	if i+consume+1 < len(args) {
		if strings.Contains(args[i+consume+1], token) {
			return consume + 1, true
		}
		return consume + 1, false
	}
	return consume, false
}

// awkWCommaTokenHit checks one comma-chained mawk -W operand for the
// replacement token (v6.2.2 Oracle R7 R7-MF-4): each comma item re-runs
// the single-item name/value checks, only the LAST item may consume the
// next argv as its value, and a bare program/value-bearing item in
// NON-final position fails closed as a hit — no awk can statically settle
// where such an item's operand lives (mirrors awkWCommaProgram's
// fail-closed shape).
func awkWCommaTokenHit(v string, args []string, i, consume int, token string) (consumeOut int, hit bool) {
	parts := strings.Split(v, ",")
	consumeOut = consume
	for k, part := range parts {
		name, eqVal, hasEq := strings.Cut(part, "=")
		if strings.Contains(name, token) || (hasEq && strings.Contains(eqVal, token)) {
			hit = true
		}
		isProg, _ := awkLongProgramName(name)
		if hasEq || (!isProg && !awkLongIsDataAssign(name)) {
			continue // inline-valued or zero-operand item: nothing to consume
		}
		if k < len(parts)-1 {
			// The `-Wi`/`-W in` collision names chain in mawk as the
			// zero-operand interactive boolean (v6.2.2 Oracle R7 R7-MF-4):
			// they never reach for the next argv. Every OTHER bare
			// value-bearing item in non-final position has no statically
			// knowable operand — fail closed as a hit.
			if name == "i" || name == "in" {
				continue
			}
			return consumeOut, true
		}
		if !isProg {
			// trailing pure-data item: consume its value word like the
			// single-item grammar so it cannot pose as the program.
			if i+consumeOut+1 < len(args) {
				consumeOut++
			}
			continue
		}
		// Trailing program item: its value lives in the NEXT argv — the
		// token check lands there exactly like `-W exec '{}'`.
		if i+consumeOut+1 < len(args) {
			consumeOut++
			if strings.Contains(args[i+consumeOut], token) {
				hit = true
			}
		}
	}
	return consumeOut, hit
}

// awkWClusterValue extracts the -W operand of one awk short cluster:
// the glued tail when present, otherwise the NEXT argv (consumedNext).
// awkWLastItemName extracts the option NAME of the LAST comma item of
// a (possibly comma-chained) mawk -W operand — `-W interactive,exec`
// reports `exec`, `-W i,e` reports `e`, and a comma-free operand simply
// reports its own name cut at `=` (v6.2.2 Oracle R8 R8-SF-1): mawk
// parses the chain item by item, so the trailing item alone decides
// whether the positional program word is retired (file/exec) and
// whether awk's own option parsing ends (exec).
func awkWLastItemName(wv string) string {
	if idx := strings.LastIndexByte(wv, ','); idx >= 0 {
		wv = wv[idx+1:]
	}
	name, _, _ := strings.Cut(wv, "=")
	return name
}

func awkWClusterValue(args []string, i, j int, a string) (v string, consumedNext bool) {
	if j+1 < len(a) {
		return a[j+1:], false
	}
	if i+1 < len(args) {
		return args[i+1], true
	}
	return "", false
}

// awkProgramFileHit applies the `-f` program-FILE source validation to one
// operand value v: `-`/stdin devices read the PROGRAM from stdin (unvetted),
// an unsafe dynamic path fails closed.
func awkProgramFileHit(v string) string {
	if v == "-" || isStdinDevicePath(v) {
		return "awk script from stdin"
	}
	if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
		return "dynamic code payload"
	}
	return ""
}

// awkLongProgramName reports whether name GNU-prefix-resolves to one of
// gawk's program-source long options (file/source/include/load/exec).
// source/include are the inline-text/library pair, file/exec/load name
// files. isLongOptAbbrev's minPrefixLen is 1 for the unambiguous pair and
// 3/2 for the ambiguous ones, matching GNU's unique-prefix rule
// (v6.2.2 Oracle R4 R4-MF-4 `-W 'so=...'`).
func awkLongProgramName(name string) (isProgram bool, isFile bool) {
	// GNU gawk's optab[] unique prefixes (v6.2.2 Oracle R5 R5-MF-4): `e*` is
	// --exec alone (minPrefix 1), `i*` is --include alone (1), --load needs
	// `lo` (2, against --lint/--lint-old), --source needs `so` (2, against
	// --sandbox), --file needs `fil` (3, against --field-separator).
	switch {
	case isLongOptAbbrev(name, "source", 2):
		return true, false
	case isLongOptAbbrev(name, "file", 3):
		return true, true
	case isLongOptAbbrev(name, "exec", 1):
		return true, true
	case isLongOptAbbrev(name, "include", 1):
		return true, true
	case isLongOptAbbrev(name, "load", 2):
		return true, true
	}
	return false, false
}

// awkWOperandProgram parses one gawk `-W` compatibility operand value under
// GNU getopt_long's "W;" translation (`-W x=y` == `--x=y`, `-W x` == `--x`,
// `-W x y` == `--x y` — v6.2.2 Oracle R4 R4-MF-4): frags/appended program
// text is reported through frag (empty when not a source operand), isFile
// marks a program-FILE source and fileVal carries its value (which for the
// bare-word `-W exec FILE` / `-W file FILE` spellings lives in the NEXT
// argv — the caller consumes it). consumedNext reports the operand needed
// one additional argv beyond the -W word itself (bare `-W` + operand word
// already counts one). Non-program value-bearing options (assign /
// field-separator and their GNU unique prefixes) consume their value
// operand WITHOUT posing as the program (v6.2.2 Oracle R5 R5-MF-4:
// `gawk -W assign 'x=1' 'BEGIN{...}'` — the x=1 value can no longer usurp
// the positional program slot and hide the real program text behind it).
func awkWOperandProgram(v string, args []string, nextIdx int, aux *[]string) (frag string, isFile bool, fileVal string, hit string, extraConsumed int) {
	if strings.Contains(v, ",") {
		// mawk chains several -W operands with commas (`-W interactive,exec
		// FILE` / `-W i,e FILE`) where gawk would reject the composite as a
		// single unknown option — fail-closed must track the MAWK parse, so
		// each comma item is re-validated by the leaf grammar (v6.2.2 Oracle
		// R7 R7-MF-4 path B).
		return awkWCommaProgram(v, args, nextIdx, aux)
	}
	return awkWOperandProgramLeaf(v, args, nextIdx, aux)
}

// awkWCommaProgram validates one comma-chained mawk -W operand (v6.2.2
// Oracle R7 R7-MF-4): each item re-runs the single-item leaf grammar;
// only the LAST item may consume the next argv operand, inline fragments
// merge, and a terminal file/exec item still ends awk's option parse
// through the leaf's isFile channel. awk never executes a concatenated
// composite as ONE option name, so the whole-word dynamic/ambiguous
// fallback of the leaf cannot model it.
func awkWCommaProgram(v string, args []string, nextIdx int, aux *[]string) (frag string, isFile bool, fileVal string, hit string, extraConsumed int) {
	parts := strings.Split(v, ",")
	var frags []string
	for k, part := range parts {
		// A leading comma item that still names a value-bearing operand
		// carries its value INSIDE the item (x=y) or is a zero-operand
		// mawk boolean — only the trailing item can reach the next argv
		// (mawk's -W exec FILE shape).
		itemNext := len(args)
		if k == len(parts)-1 {
			itemNext = nextIdx
		}
		if strings.IndexByte(part, '=') < 0 && k < len(parts)-1 {
			// A bare value-bearing/program operand in NON-final position
			// would silently drop its value under every awk — fail closed
			// rather than guess. mawk zero-operand BOOLEANS never reach this
			// branch: they are not program-source names, and the `-Wi`/`-W
			// in` collision names are excluded too (`-W i,e` chains the
			// interactive boolean with exec — v6.2.2 Oracle R7 R7-MF-4).
			if n := part; n != "i" && n != "in" {
				if isProg, _ := awkLongProgramName(n); isProg || awkLongIsDataAssign(n) {
					return "", false, "", "dynamic code payload", extraConsumed
				}
			}
		}
		f, fFile, fv, h, extra := awkWOperandProgramLeaf(part, args, itemNext, aux)
		if h != "" {
			return "", isFile || fFile, "", h, extraConsumed
		}
		if extra > 0 {
			extraConsumed += extra
		}
		if f != "" {
			frags = append(frags, f)
		}
		if fFile {
			isFile, fileVal = true, fv
		}
	}
	return strings.Join(frags, "\n"), isFile, fileVal, "", extraConsumed
}

// awkWOperandProgramLeaf validates one comma-free -W operand item (the
// pre-R7 grammar plus the -Wi/-W in collision handling of Oracle R7
// R7-MF-4 and the unquoted-split data-value verdict of R7-SF-1). aux
// (when non-nil) carries the -Wi/-W in collision operand value OUT of
// band so it never enters the caller's ordinary fragment list (v6.2.2
// Oracle R8 R8-MF-1).
func awkWOperandProgramLeaf(v string, args []string, nextIdx int, aux *[]string) (frag string, isFile bool, fileVal string, hit string, extraConsumed int) {
	name, val, hasEq := strings.Cut(v, "=")
	isProg, isF := awkLongProgramName(name)
	if !isProg {
		// The option NAME slot fails closed when it is dynamic or too
		// short to resolve: at runtime the expansion can spell a
		// program-source option (`exec` / `source=BEGIN{system("pig")}`)
		// that the static scan never sees (v6.2.2 Oracle R6 R6-MF-3
		// `X='exec'; awk -W "$X" /dev/stdin` — mawk AND gawk). Pure-data
		// assignments (-W assign=x="$VAR" / -W assign "$VAR") stay
		// exempt: their value is data awk never executes.
		if isDynamicArg(name) || awkAmbiguousShortPrefix(name) {
			return "", false, "", "dynamic code payload", 0
		}
		if awkLongIsDataAssign(name) {
			return awkWDataAssignLeaf(v, args, nextIdx, hasEq)
		}
		if isDynamicArg(v) {
			return "", false, "", "dynamic code payload", 0
		}
		return "", false, "", "", 0
	}
	if !hasEq {
		// Bare -W word spelling (`-W source PROG` / `-W exec FILE`): the value
		// is the NEXT argv after the operand word.
		if nextIdx < len(args) {
			val, extraConsumed = args[nextIdx], 1
		} else {
			val = ""
		}
		if extraConsumed == 1 && (name == "i" || name == "in") && val != "" {
			return awkWIncludeCollisionLeaf(val, extraConsumed, aux)
		}
	}
	if !isF {
		return val, false, "", "", extraConsumed
	}
	return "", true, val, awkProgramFileHit(val), extraConsumed
}

// awkWDataAssignLeaf validates one pure-data assignment -W operand
// (extracted so awkWOperandProgramLeaf stays under the complexity budget
// — v6.2.2 Oracle R7 R7-SF-1): an UNQUOTED dynamic assignment value
// word-splits at runtime and the fragments re-arm awk's own option parse
// — the check applies to the whole OPERAND word for the inline spelling
// too (`gawk -W assign=x=$VAR '1'` splits inside `assign=x=<expansion>`
// and spills `-e BEGIN{...}` out of the assignment). Quoted spellings
// stay split-safe.
func awkWDataAssignLeaf(v string, args []string, nextIdx int, hasEq bool) (frag string, isFile bool, fileVal string, hit string, extraConsumed int) {
	if hasEq {
		return "", false, "", awkDataValSplitHit(v), 0
	}
	if nextIdx < len(args) {
		if sh := awkDataValSplitHit(args[nextIdx]); sh != "" {
			return "", false, "", sh, 0
		}
		return "", false, "", "", 1
	}
	return "", false, "", "", 0
}

// awkWIncludeCollisionLeaf reports the `-Wi` / `-W i` / `-W in` collision
// operand (extracted — v6.2.2 Oracle R7 R7-MF-4): gawk resolves them to
// the --include library FILE (consuming the next argv) while mawk spells
// the zero-operand BOOLEAN -W interactive, leaving the same word as awk's
// positional PROGRAM. The file validation still runs on val (gawk
// semantics) and extraConsumed stays 1 (gawk consumption), but val is
// ALSO merged into the final program as a fragment — under mawk the same
// bytes ARE the main program text, so `awk -Wi 'BEGIN{system("pig")}'`
// can no longer pass unreviewed while `awk -Wi 'BEGIN{print 1}'` stays
// inert. Crucially include never marks sawFile downstream, so the
// positional program word still extracts on the gawk interpretation too
// (`gawk -W i /dev/null 'BEGIN{system("pig")}'` blocks through BOTH
// channels).
//
// v6.2.2 Oracle R8 R8-MF-1: the collision value must NOT enter the
// ordinary frag return — a non-empty frags list suppresses
// awkProgramFrags' positional-program extraction (`len(frags) == 0`
// gates), which regressed `gawk -W i /dev/null 'BEGIN{system("pig")}'`
// (and the `--`/xargs twins) from BLOCK to ALLOW. It travels out of
// band through aux instead: awkProgramFrags appends it AFTER the
// positional settlement so a library file name carrying an unclosed
// quote (`gawk -W i "a'b" ...`) can never poison the REAL program text
// that precedes it in the joined program.
func awkWIncludeCollisionLeaf(val string, extraConsumed int, aux *[]string) (frag string, isFile bool, fileVal string, hit string, extraConsumedOut int) {
	if fh := awkProgramFileHit(val); fh != "" {
		return "", true, val, fh, extraConsumed
	}
	// v6.2.2 Oracle R9 R9-MF-1: a collision value starting with '-' is a
	// mawk OPTION word (-v/-F/-f/-W) that gawk would consume as the
	// --include library file. The two parses are irreconcilable — under
	// mawk the word re-arms awk's own option parse (its x=1 value usurps
	// the positional program slot, or -f /dev/stdin escapes review) while
	// dropping extraConsumed would let `gawk -W i -foo` be mis-clustered
	// as -f oo — so fail closed. awkProgramFileHit runs first so the
	// bare '-' spelling keeps its precise stdin verdict.
	if strings.HasPrefix(val, "-") {
		return "", true, val, "dynamic code payload", extraConsumed
	}
	if aux != nil {
		*aux = append(*aux, val)
	}
	return "", true, val, "", extraConsumed
}

// awkDataValSplitHit reports a pure-data assignment VALUE (-v/-F/--assign/
// --field-separator/-W assign) whose unquoted word split re-arms awk's
// option parse at runtime: the placeholder expands inside a NON-split-safe
// word (`awk -v x=$VAR` splits onto `-f /dev/stdin` / `-e BEGIN{...}` —
// v6.2.2 Oracle R7 R7-SF-1). Quoted spellings (-v ts="$val" / "$VAR") stay
// exempt: their expansion never leaves the word (isSplitSafeDynamicWord).
func awkDataValSplitHit(val string) string {
	if isDynamicArg(val) && !isSingleWordSplitSafe(val) {
		return "dynamic code payload"
	}
	return ""
}

// awkLongIsDataAssign reports whether name GNU-prefix-resolves to one of
// gawk's pure-data assignment long options (--assign / --field-separator):
// --assign is the only `a*` long option (unique prefix 1) and
// --field-separator needs `fie` (3, against --file) in GNU gawk's optab[]
// (v6.2.2 Oracle R5 R5-MF-4).
func awkLongIsDataAssign(name string) bool {
	return isLongOptAbbrev(name, "assign", 1) || isLongOptAbbrev(name, "field-separator", 3)
}

// awkClusterFragsEnd scans one short-option cluster of awk's argv
// (extracted from awkProgramFrags so the main walk stays under the
// complexity budget — v6.2.2 R3 R3-MF-6): 'e' collects program fragments,
// 'f'/'E' name a program FILE (stdin devices and unsafe dynamic paths fail
// closed, 'E' additionally ends the option scan like gawk's own --exec),
// the data letters 'F'/'v'/'i' consume their operands, and the gawk
// compatibility letter 'W' re-plays source=/file=/exec program shapes
// under GNU getopt_long "W;" semantics. consumedNext counts how many
// EXTRA argv operands the cluster eats; endOut (when non-nil) is set true
// after gawk's -E/--exec shape terminates awk's own option parsing
// (v6.2.2 Oracle R4 R4-MF-4).
func awkClusterFragsEnd(args []string, i int, a string, endOut *bool, aux *[]string) (frags []string, sawFile bool, consumedNext int, hit string) {
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'e':
			if tail := a[j+1:]; tail != "" {
				frags = append(frags, tail)
			} else if i+1+consumedNext < len(args) {
				frags = append(frags, args[i+1+consumedNext])
				consumedNext++
			}
			return frags, sawFile, consumedNext, ""
		case 'f', 'E':
			sawFile = true
			_, extra, fh := awkClusterFileOperand(args, i, j, a, consumedNext, a[j] == 'E', endOut)
			consumedNext += extra
			if fh != "" {
				return nil, sawFile, consumedNext, fh
			}
			return frags, sawFile, consumedNext, ""
		case 'F', 'v':
			// Pure-data assignment letters consume their operand — but an
			// UNQUOTED dynamic operand word-splits at runtime and the
			// fragments re-arm awk's own option parse (v6.2.2 Oracle R7
			// R7-SF-1 `awk -v x=$VAR -f /dev/null`). A glued tail inside the
			// cluster is a single word, which never splits.
			dExtra, dHit := awkClusterDataAssignEnd(args, i, j, a, consumedNext)
			consumedNext += dExtra
			if dHit != "" {
				return nil, sawFile, consumedNext, dHit
			}
			return frags, sawFile, consumedNext, ""
		case 'i', 'l':
			// gawk -i/--include and -l/--load consume a library operand
			// that is awk program material — a stdin device smuggles
			// unvetted text (v6.2.2 Oracle R5 R5-MF-4 `gawk -i /dev/stdin`).
			// Like -f's file operand, the value is validated; unlike -f
			// they do not mark sawFile (they add libraries, not the
			// program file itself).
			v := a[j+1:]
			if v == "" && i+1+consumedNext < len(args) {
				v = args[i+1+consumedNext]
				consumedNext++
			}
			if fh := awkProgramFileHit(v); fh != "" {
				return nil, sawFile, consumedNext, fh
			}
			return frags, sawFile, consumedNext, ""
		case 'W':
			wFrag, wSawFile, wExtra, wh := awkClusterWOperand(args, i, j, a, consumedNext, endOut, aux)
			consumedNext += wExtra
			if wFrag != "" {
				frags = append(frags, wFrag)
			}
			sawFile = sawFile || wSawFile
			if wh != "" {
				return nil, sawFile, consumedNext, wh
			}
			return frags, sawFile, consumedNext, ""
		case 'd', 'D', 'L', 'o', 'p':
			// gawk optional_argument short options (getopt_long d::/D::/L::/
			// o::/p::): a glued tail IS the option's argument and ends the
			// cluster immediately without consuming the next argv — the
			// tail's letters must never reach the 'e'/'f'/'v' cases
			// (v6.2.2 Oracle R6 R6-MF-4 `gawk -Lfatal` / `gawk -p/dev/null`).
			if j+1 < len(a) {
				return frags, sawFile, consumedNext, ""
			}
		}
	}
	return frags, sawFile, consumedNext, ""
}

// awkClusterDataAssignEnd resolves the operand of one -F/-v pure-data
// assignment letter (extracted so awkClusterFragsEnd stays under the
// complexity budget — v6.2.2 Oracle R7 R7-SF-1): the separate operand
// counts one EXTRA argv and both spellings run the unquoted word-split
// validation — the separate operand splits on its own, and a glued tail
// still splits the WHOLE cluster word when it carries a non-split-safe
// expansion (`awk -v x=$VAR` / `-vx=$VAR` — v6.2.2 Oracle R7 R7-SF-1).
func awkClusterDataAssignEnd(args []string, i, j int, a string, consumedNext int) (extra int, hit string) {
	if j+1 < len(a) {
		return 0, awkDataValSplitHit(a[j+1:])
	}
	if i+1+consumedNext < len(args) {
		return 1, awkDataValSplitHit(args[i+1+consumedNext])
	}
	return 1, ""
}

// awkClusterFileOperand resolves the program-file operand of one -f/-E
// cluster letter (glued tail or next argv), reporting the EXTRA argv count
// and any stdin/dynamic hit; -E additionally marks endOpts through endOut
// (v6.2.2 Oracle R4 R4-MF-4).
func awkClusterFileOperand(args []string, i, j int, a string, consumedNext int, isE bool, endOut *bool) (v string, extra int, hit string) {
	if isE && endOut != nil {
		// gawk -E/--exec terminates option parsing: words after its
		// operand are the program's argv data.
		*endOut = true
	}
	v = a[j+1:]
	if v == "" && i+1+consumedNext < len(args) {
		v, extra = args[i+1+consumedNext], 1
	}
	return v, extra, awkProgramFileHit(v)
}

// awkClusterWOperand resolves one gawk -W compatibility letter inside a
// short cluster (glued tail or operand word), reporting the program
// fragment / file-source / extra argv count / hit under GNU getopt_long's
// "W;" translation (v6.2.2 Oracle R4 R4-MF-4).
func awkClusterWOperand(args []string, i, j int, a string, consumedNext int, endOut *bool, aux *[]string) (frag string, sawFile bool, extra int, hit string) {
	wv, wConsumed := awkWClusterValue(args, i+consumedNext, j, a)
	if wConsumed {
		extra++
	}
	frag, isFile, _, wh, wc := awkWOperandProgram(wv, args, i+consumedNext+extra+1, aux)
	extra += wc
	// v6.2.2 Oracle R8 R8-SF-1: the item name is the LAST comma item's
	// name — `-W interactive,exec` / `-W i,e` retire the positional
	// program exactly like `-W exec`.
	wName := awkWLastItemName(wv)
	if isFile && (isLongOptAbbrev(wName, "file", 3) || isLongOptAbbrev(wName, "exec", 1)) {
		// Only the PROGRAM-FILE sources (-W file/-W exec) retire the
		// positional program word; -W include/-W load (and their GNU
		// unique prefixes -W i/-W lo) are LIBRARY loads — the positional
		// word is still awk's main program text and must stay extractable
		// (v6.2.2 Oracle R6 R6-MF-2 `gawk -W include=/dev/null
		// 'BEGIN{system("pig")}'`).
		sawFile = true
	}
	if isFile && isLongOptAbbrev(wName, "exec", 1) && endOut != nil {
		*endOut = true // -W exec == --exec: ends awk's option parsing
	}
	return frag, sawFile, extra, wh
}

// awkLongValueIsProgram reports whether a gawk long option's value operand
// carries program text (or names the program file/library) rather than
// pure assignment data.
func awkLongValueIsProgram(name string) bool {
	for _, full := range []string{"file", "source", "include", "load", "exec"} {
		if isLongOptAbbrev(name, full, 1) {
			return true
		}
	}
	return false
}

// awkLongTakesValue reports whether a GNU awk long option consumes a
// separate value operand (the value-bearing subset of gawk's longopts).
func awkLongTakesValue(name string) bool {
	for _, full := range []string{"file", "source", "assign", "field-separator", "include", "load", "exec"} {
		if isLongOptAbbrev(name, full, 1) {
			return true
		}
	}
	return false
}

// sedScriptTokenHit reports the token inside sed's script operands. It
// reuses sedScripts' full option grammar (v6.2.2 R3 R2-MF-3): once any
// -e/-f/--expression/--file script source appeared, remaining positional
// words are INPUT FILES — data, never scripts (restores
// `find -exec sed -e 's/foo/bar/' {} \;`), while the -e/-f values
// themselves, cluster-glued -ne'{}' tails, --expr GNU abbreviations and
// option-zone words are all matched against the token.
func sedScriptTokenHit(h []string, token string) bool {
	scripts, _ := sedScripts(h[1:])
	for _, s := range scripts {
		if strings.Contains(s, token) {
			return true
		}
	}
	if len(scripts) > 0 {
		return sedOptZoneHasToken(h[1:], token)
	}
	// No explicit script at all: sedScripts treats the first bare positional
	// as the script, so scripts is non-empty whenever a candidate existed.
	// Reaching here means operands were dynamic or absent — scan the raw
	// words conservatively.
	return sedOptZoneHasToken(h[1:], token)
}

// sedOptZoneHasToken scans sed's option zone for the token: option words,
// cluster tails and value operands all expand before sed parses them
// (v6.2.2 R3 R2-MF-3 --expr='{}' rows). Positional input files never count.
func sedOptZoneHasToken(args []string, token string) bool {
	endOpts := false
	sawScript := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" && !endOpts {
			endOpts = true
			continue
		}
		if endOpts || !strings.HasPrefix(a, "-") || a == "-" {
			if sawScript {
				return false // input files are data
			}
			// first positional IS the script when nothing explicit appeared
			if strings.Contains(a, token) {
				return true
			}
			sawScript = true
			continue
		}
		isDanglingBareE := a == "-e" && i+1 >= len(args)
		if strings.Contains(a, token) && !isDanglingBareE {
			return true
		}
		consume, hit, scripted := sedOptWordTokenStep(args, i, token)
		if hit {
			return true
		}
		if scripted {
			sawScript = true
		}
		i += consume
	}
	return false
}

// sedOptWordTokenStep advances sedOptZoneHasToken past the option word at
// index i (extracted so the scan loop stays reviewable — v6.2.2 R3):
// consume counts EXTRA argv operands the word's value eats, hit reports
// the token inside a value operand, scripted reports the word carries an
// explicit script source (-e/-f/--expression/--file or their clusters).
func sedOptWordTokenStep(args []string, i int, token string) (consume int, hit, scripted bool) {
	a := args[i]
	if strings.HasPrefix(a, "--") {
		return sedLongOptTokenStep(args, i, token)
	}
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'e', 'f', 'l':
			if a[j] != 'l' {
				scripted = true
			}
			if j+1 >= len(a) && i+1 < len(args) {
				if strings.Contains(args[i+1], token) {
					return 1, true, scripted
				}
				return 1, false, scripted
			}
			return 0, false, scripted // glued tail IS the value
		}
	}
	return 0, false, false
}

// sedLongOptTokenStep handles one `--` word of sedOptZoneHasToken's scan.
func sedLongOptTokenStep(args []string, i int, token string) (consume int, hit, scripted bool) {
	name := args[i][2:]
	hasEq := strings.IndexByte(name, '=') >= 0
	if k := strings.IndexByte(name, '='); k >= 0 {
		name = name[:k]
	}
	isExpr := isLongOptAbbrev(name, "expression", 1)
	isFile := !isExpr && isLongOptAbbrev(name, "file", 2)
	isLineLen := !isExpr && !isFile && isLongOptAbbrev(name, "line-length", 1)
	if !isExpr && !isFile && !isLineLen {
		return 0, false, false
	}
	scripted = isExpr || isFile
	if !hasEq && i+1 < len(args) {
		if strings.Contains(args[i+1], token) {
			return 1, true, scripted
		}
		return 1, false, scripted
	}
	return 0, false, scripted
}

// tarExecOptTokenHit reports the token inside tar's command-exec option
// values: --checkpoint-action=exec*/-exec/… glued or separate, --to-command,
// --use-compress-program and the -I short form (glued or separate). GNU
// tar resolves unique-prefix abbreviations of its long options, so the
// scan matches prefixes (--checkpoint-act=, --use-compress=) against the
// real long names (v6.2.2 R3 R2-SF-3).
func tarExecOptTokenHit(h []string, token string) bool {
	for i := 1; i < len(h); i++ {
		consume, hit := tarExecWordTokenStep(h, i, token)
		if hit {
			return true
		}
		i += consume
	}
	return false
}

// tarExecWordTokenStep advances tarExecOptTokenHit past the word at index
// i (extracted so the scan loop stays reviewable — v6.2.2 R3): consume
// counts EXTRA argv operands consumed, hit reports a token inside an
// exec-arming value.
func tarExecWordTokenStep(h []string, i int, token string) (consume int, hit bool) {
	a := h[i]
	if strings.HasPrefix(a, "--") {
		return tarLongExecTokenStep(h, i, token)
	}
	if !strings.HasPrefix(a, "-") || len(a) <= 1 || a == "-" {
		return 0, false
	}
	// Short cluster: 'I' is --use-compress-program's short form — its
	// operand is the glued tail or the next argv (v6.2.2 R3 R2-SF-3).
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'I':
			if tail := a[j+1:]; tail != "" {
				return 0, strings.Contains(tail, token)
			}
			if i+1 < len(h) {
				return 1, strings.Contains(h[i+1], token)
			}
			return 0, false
		case 'f', 'C', 'T', 'X', 'b', 'L', 'H':
			if j+1 >= len(a) && i+1 < len(h) {
				return 1, false // plain value operand — data, but consumed
			}
			return 0, false
		}
	}
	return 0, false
}

// tarLongExecTokenStep handles one `--` word of tarExecOptTokenHit's scan.
func tarLongExecTokenStep(h []string, i int, token string) (consume int, hit bool) {
	name, val, hasEq := h[i][2:], "", false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, val, hasEq = name[:k], name[k+1:], true
	}
	if !tarExecLongMatch(name, "checkpoint-action") && !tarExecLongMatch(name, "to-command") &&
		!tarExecLongMatch(name, "use-compress-program") {
		return 0, false
	}
	if hasEq {
		return 0, strings.Contains(val, token)
	}
	if i+1 < len(h) {
		return 1, strings.Contains(h[i+1], token)
	}
	return 0, false
}

// tarExecLongMatch reports whether name is a unique-prefix abbreviation of
// the full long option among tar's own exec-relevant and common value long
// options. Ambiguity against the other tar longs resolves conservatively
// to NO match (getopt_long would reject it at runtime).
func tarExecLongMatch(name, full string) bool {
	if name == "" {
		return false
	}
	if name == full {
		return true
	}
	if !strings.HasPrefix(full, name) {
		return false
	}
	// Candidate competitor long options sharing the prefix space; an equal
	// or longer common prefix on a competitor makes the abbreviation
	// ambiguous at runtime, so it does not resolve.
	competitors := []string{
		"checkpoint", "checkpoint-action", "to-command", "use-compress-program",
		"file", "directory", "files-from", "exclude", "include", "transform",
		"format", "newer", "after-date", "occurrence", "index-file", "owner",
		"group", "mode", "mtime", "sort", "quoting-style", "totals",
	}
	for _, c := range competitors {
		if c == full {
			continue
		}
		if strings.HasPrefix(c, name) {
			return false // ambiguous prefix — getopt_long rejects at runtime
		}
	}
	return true
}

// gitConfigExecTokenHit reports the token inside `git -c key=val` config
// overrides whose keys run external commands, or anywhere in git's GLOBAL
// OPTION ZONE itself: an option word carrying the token expands before git
// parses it (v6.2.2 R3 R2-MF-3 `git % 'core.pager=pig' log`), so it can
// become a `-c` arming an exec-capable key. Global value options
// (-C/--git-dir/--work-tree/--namespace/--exec-path/--config-env) consume
// their operands before the -c scan (their operand word is still checked).
func gitConfigExecTokenHit(h []string, token string) bool {
	for i := 1; i < len(h); i++ {
		a := h[i]
		if !strings.HasPrefix(a, "-") || len(a) <= 1 {
			if strings.Contains(a, token) {
				// A non-option word carrying the token sits where git expects
				// the SUBCOMMAND: at runtime the expansion can spell `-c` and
				// arm the following static key=val word (v6.2.2 R3 R2-MF-3
				// `git % 'core.pager=pig' log`).
				return true
			}
			return false // the -c zone ended at the subcommand
		}
		consume, hit, cont := gitGlobalOptTokenStep(h, i, token)
		if hit {
			return true
		}
		i += consume
		if !cont {
			return false
		}
	}
	return false
}

// gitGlobalOptTokenStep advances gitConfigExecTokenHit past the global
// option word at index i (extracted so the scan loop stays reviewable —
// v6.2.2 R3): consume counts EXTRA argv operands consumed, hit reports a
// token in an exec-arming position, cont reports the scan continues.
func gitGlobalOptTokenStep(h []string, i int, token string) (consume int, hit, cont bool) {
	a := h[i]
	isBareDashC := a == "-c"
	// Pure-data glued long forms are exempted from the blanket token hit
	// below: their value is a path the git binary consumes itself, never a
	// shell-bound string (v6.2.2 R3 R3-MF-6 / Reviewer R2-6 parity with
	// the separate-operand spelling). --exec-path is NOT here: it redirects
	// git's subprogram lookup directory, which screenGitGlobalArgs blocks
	// unconditionally, so a token there must hit (v6.2.2 Oracle R4 R4-SF-2).
	gluedData := strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") ||
		strings.HasPrefix(a, "--namespace=")
	// Key=value-bearing shapes are screened BEFORE the blanket token hit
	// (v6.2.2 Oracle R4 R4-SF-2 — the blanket hit used to precede them,
	// making this code unreachable and false-hitting `git -cuser.name={}`
	// while the separate `-c user.name={}` spelling stayed allowed).
	if len(a) > 2 && strings.HasPrefix(a, "-c") && !strings.HasPrefix(a, "--") {
		if gitExecConfigValueHasToken(a[2:], token) {
			return 0, true, false
		}
		return 0, false, true
	}
	if strings.HasPrefix(a, "--config-env=") {
		if gitExecConfigValueHasToken(a[len("--config-env="):], token) {
			return 0, true, false
		}
		return 0, false, true
	}
	if len(a) > 2 && strings.HasPrefix(a, "-C") && !strings.HasPrefix(a, "--") {
		// Glued -C<dir>: a plain path value exactly like the separate
		// operand — never a hit on its own (v6.2.2 Oracle R4 R4-SF-2
		// `find . -exec git -C{} status \;` parity).
		return 0, false, true
	}
	if strings.Contains(a, token) && !isBareDashC && !gluedData {
		return 0, true, false
	}
	if isBareDashC {
		if i+1 < len(h) {
			if gitExecConfigValueHasToken(h[i+1], token) {
				return 1, true, false
			}
			return 1, false, true
		}
		return 0, false, true
	}
	if a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace" {
		// Plain path value operand — pure DATA (git -C {} status): the word
		// is consumed so it cannot pose as the subcommand, but a token
		// inside it never reaches a shell (v6.2.2 R3).
		if i+1 < len(h) {
			return 1, false, true
		}
		return 0, false, true
	}
	if a == "--exec-path" || strings.HasPrefix(a, "--exec-path=") {
		// --exec-path redirects git's subprogram lookup directory — NOT pure
		// data (screenGitGlobalArgs blocks it unconditionally). A token in
		// the value already hit above; the plain form still consumes its
		// operand so it cannot pose as the subcommand (v6.2.2 R4-SF-2).
		if a == "--exec-path" && i+1 < len(h) {
			return 1, strings.Contains(h[i+1], token), true
		}
		return 0, false, true
	}
	if gluedData {
		// Glued forms of the pure-data path options: the value is DATA
		// exactly like the separate operand (v6.2.2 R3 R3-MF-6 / Reviewer
		// R2-6 `git --git-dir={} log -1` parity).
		return 0, false, true
	}
	if a == "--config-env" {
		// --config-env takes a key=var pair exactly like -c takes key=val:
		// screen it with the SAME exec-capability predicate instead of
		// treating it as pure data (v6.2.2 R3 R3-MF-6).
		if i+1 < len(h) {
			if gitExecConfigValueHasToken(h[i+1], token) {
				return 1, true, false
			}
			return 1, false, true
		}
		return 0, false, true
	}
	return 0, false, true
}

// gitExecConfigValueHasToken reports whether one `git -c` key=val word both
// names a command-exec config key and carries the token in its value. A
// bare token word with NO '=' at all counts as a hit: at runtime the word
// IS the placeholder expansion, and a config value positioned after the
// expansion cannot be shape-proven (v6.2.2 R3 R2-MF-3 `git -c '{}'`). Key
// capability flows through gitKeyIsExecCapable — the same predicate
// screenGitGlobalArgs uses — so merge.foo.driver / diff.foo.command /
// credential.<url>.helper cannot drift (v6.2.2 R3 R2-MF-3).
func gitExecConfigValueHasToken(kv, token string) bool {
	eq := strings.IndexByte(kv, '=')
	if eq < 0 {
		return strings.Contains(kv, token)
	}
	if strings.Contains(kv[:eq], token) {
		// A token on the KEY side expands into key text at runtime — the
		// resulting key capability is unprovable (v6.2.2 R3 R3-MF-6
		// `git -c '{}=pig' log` → core.pager=pig).
		return true
	}
	if !strings.Contains(kv[eq+1:], token) {
		return false
	}
	key := strings.ToLower(kv[:eq])
	return gitKeyIsExecCapable(key) || strings.HasPrefix(kv[eq+1:], "!")
}

// sshLocalZoneHasToken reports whether the token sits in ssh's LOCAL parse
// zone — the option words and the <destination> operand: those bytes are
// consumed by the local ssh client, so a runtime expansion there injects
// local options (ProxyCommand) or retargets the connection. Words after
// the second non-option operand are remote-command text and are judged by
// the remote screens, not here.
func sshLocalZoneHasToken(h []string, token string) bool {
	sawDest := false
	endOpts := false
	for i := 1; i < len(h); i++ {
		a := h[i]
		if !endOpts && a == "--" {
			endOpts = true
			continue
		}
		if !endOpts && strings.HasPrefix(a, "-") && a != "-" {
			if strings.Contains(a, token) {
				return true
			}
			// Skip the operands of value-taking letters so they are not
			// mistaken for <destination>: a value letter at the cluster
			// tail consumes the NEXT argv word (v6.2.2 R3 R2-MF-5).
			for j := 1; j < len(a); j++ {
				if sshShortTakesValue(a[j]) {
					if j+1 >= len(a) && i+1 < len(h) {
						if strings.Contains(h[i+1], token) {
							return true
						}
						i++
					}
					break // a glued tail IS the value — the cluster ends
				}
			}
			continue
		}
		if !sawDest {
			if strings.Contains(a, token) {
				return true // <destination> carries the token
			}
			sawDest = true
			continue
		}
		return false // second non-option word begins the remote command
	}
	return false
}

// replTokenInFlock descends past flock's options: a -c/--command shell
// string carrying the token is an exec-slot hit, as is the token in the
// positional command argv.
func replTokenInFlock(h []string, token, effPath string, outerCaller callerIdentity, depth int) bool {
	innerIdx, cmdText := skipFlockArgs(h, 1)
	if cmdText != "" {
		return isDynamicArg(cmdText) || strings.Contains(cmdText, token)
	}
	// A token inside flock's own option/lock-file zone (`flock % 'sh -c pig'
	// /dev/null`) expands before flock parses it — at runtime it can become
	// -c or shift the command argv into a different shape (v6.2.2 MF-8).
	end := innerIdx
	if end > len(h) {
		end = len(h)
	}
	for i := 1; i < end; i++ {
		if strings.Contains(h[i], token) {
			return true
		}
	}
	if innerIdx < len(h) {
		return replTokenInExecSlotDepth(h[innerIdx:], token, effPath, outerCaller, depth+1, false)
	}
	return false
}

// replTokenInWatch descends past watch's options: -x/--exec operands form a
// direct exec argv, while the default mode joins operands into a `sh -c`
// string — a token there is shell text.
func replTokenInWatch(h []string, token, effPath string, outerCaller callerIdentity, depth int) bool {
	k, execMode, fc := skipWatchArgs(h, 1)
	if fc {
		return true
	}
	if k >= len(h) {
		return false
	}
	if execMode {
		return replTokenInExecSlotDepth(h[k:], token, effPath, outerCaller, depth+1, false)
	}
	return strings.Contains(strings.Join(h[k:], " "), token)
}

// replTokenInFind scans find's operand list: -exec/-execdir/-ok/-okdir argv
// descend at depth+1, value predicates skip their operand (find . -name {}
// stays data), and a token that lands where find would parse it as a
// predicate or path — with execution operators after it — fails closed.
func replTokenInFind(args []string, token, effPath string, outerCaller callerIdentity, depth int) bool {
	pathDone := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
			end, hit := findExecTerminatorHit(args, i, token, effPath, outerCaller, depth)
			if hit {
				return true
			}
			i = end
			pathDone = true
			continue
		}
		if isFindValueOpt(a) {
			pathDone = true
			i++ // skip the predicate's value operand
			if a == "-fprintf" {
				i++ // -fprintf consumes FILE FORMAT — two operands (v6.2.2 MF-7)
			}
			continue
		}
		if a == "-H" || a == "-L" || a == "-P" {
			// find's symlink-dereference OPTIONS precede the path list: they
			// never end it (v6.2.2 Obs-1), so `find -L {} -name x` keeps the
			// token in harmless path position.
			continue
		}
		if strings.HasPrefix(a, "-") {
			pathDone = true
			if strings.Contains(a, token) {
				return true // option-shaped word carrying the token
			}
			continue
		}
		if strings.Contains(a, token) && replTokenInFindPathWord(args, i, token, pathDone) {
			return true
		}
	}
	return false
}

// findExecTerminatorHit locates the ';'/'+' terminator of one -exec/-ok
// family operator and descends into its command argv. A missing terminator
// fails closed (xargs would append stdin words into the open command slot).
func findExecTerminatorHit(args []string, i int, token, effPath string, outerCaller callerIdentity, depth int) (end int, hit bool) {
	j := i + 1
	for j < len(args) && args[j] != ";" && args[j] != "+" {
		j++
	}
	if j >= len(args) {
		return len(args) - 1, true
	}
	// A NESTED find descent passes false: even when the outermost scan was
	// find's own {}, this inner command is reached through an xargs/flock/
	// ssh layer where the token already re-exposes to arbitrary bytes
	// (v6.2.2 Oracle R4 R4-MF-2).
	if j > i+1 && replTokenInExecSlotDepth(args[i+1:j], token, effPath, outerCaller, depth+1, false) {
		return j, true
	}
	return j, false
}

// replTokenInFindPathWord reports whether a token-carrying non-option word
// in find's operand list is dangerous: after pathDone the word is parsed as
// an expression (fails closed unconditionally); in path position it is
// dangerous only when execution operators follow before the next plain
// operand (xargs -I% find . % -exec pig \;).
func replTokenInFindPathWord(args []string, i int, token string, pathDone bool) bool {
	if pathDone {
		return true
	}
	// Scan the WHOLE remaining operand list: a token in path position is
	// dangerous whenever execution material follows it anywhere — a bare
	// ";"/"+" closes an exec the runtime substitution itself supplies
	// (`xargs -I% find . % pig ';'` substitutes %=-exec), as does any real
	// -exec/-execdir/-ok/-okdir operator. Plain operands never end this
	// scan (v6.2.2 MF-7): find parses ALL leading non-option words as the
	// path list, so only the presence of exec material decides.
	for k := i + 1; k < len(args); k++ {
		switch args[k] {
		case "-exec", "-execdir", "-ok", "-okdir", ";", "+":
			return true
		}
	}
	return false
}

const roSSHWriteHit = "ssh remote write"
