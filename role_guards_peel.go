package main

// role_guards_peel.go — recursive argv/shell peeling and env/ssh/xargs/find/trap/unset/heredoc screens.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
			if hit := screenEnvAssignments(envAs2, kind, caller.role, caller.readonly, base, caller); hit != "" {
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
		g.cwd = caller.cwd
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
		text := strings.Join(head[1:], " ")
		if isDynamicArg(text) {
			return "dynamic code payload"
		}
		if kind == 's' {
			return guardShellSubagentDepth(text, depth+1, caller)
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
		return screenTrapArgs(head[1:], kind, depth+1, caller)
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
		// facts, never the outer words or their provenance.
		return stdinOnlySeg(outerSeg)
	}
	hasOuterInput := outerSeg.pipedStdin || outerSeg.stdinRedir ||
		outerSeg.hereString != "" || len(outerSeg.heredocText) > 0
	if hasOuterInput && sshTunnelsStdinProgram(targetArgv, pathEnv, caller) {
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
func replTokenInExecSlot(innerArgv []string, token, pathEnv string, caller callerIdentity) bool {
	if token == "" || len(innerArgv) == 0 {
		return false
	}
	head, tea, effPath, exhausted := peelWrappersAndWrapperAliases(innerArgv, pathEnv, caller)
	if exhausted || len(head) == 0 {
		return true
	}
	// The peeled env ops re-anchor resolution (env -C inside the peeled
	// head moves its own cwd): resolve the ssh head under the seeded
	// caller (R5 MF-3). The remote recursion below still crosses the ssh
	// boundary with a bare callerIdentity (only the local cwd field) —
	// local pathEnv/envTaint never reach remote segments.
	tCaller := caller.seededWith(tea)
	if strings.Contains(head[0], token) {
		return true
	}
	// A non-ssh alias head (mysh -> /bin/sh under env -C, or a PATH alias
	// to ssh) must face the SAME code-slot and ssh screens as the typed
	// name: resolve the peeled head under the seeded caller and screen
	// the canonical spelling alongside the literal one (R6 MF-1). A
	// CROSS-FAMILY structural re-identity (one guard head resolving to a
	// DIFFERENT structural family, `xargs -> /bin/sh`) is a conflict —
	// fail closed; a same-family link (`hc -> herdr-core`, `sed -> gsed`)
	// is the ordinary install spelling and only adds the variant.
	headVariants := [][]string{head}
	if rb := canonicalResolvedBase(resolveHeadBase(head[0], effPath, tCaller.screenCwd())); rb != "" && rb != filepath.Base(head[0]) {
		if tb := filepath.Base(head[0]); rb != head[0] && isStructuralGuardHead(tb) && isStructuralGuardHead(rb) && !sameStructuralFamily(tb, rb) {
			return true
		}
		headVariants = append(headVariants, append([]string{rb}, head[1:]...))
	}
	isSSH := false
	for _, h := range headVariants {
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
		if b == "ssh" || resolveHeadBase(h[0], effPath, tCaller.screenCwd()) == "ssh" {
			isSSH = true
		}
	}
	if isSSH {
		remoteCmd, hit := parseSSHInvocation(head)
		if hit != "" {
			return true
		}
		for _, rseg := range splitShellSegments(remoteCmd) {
			if len(rseg.argv) == 0 {
				continue
			}
			// In POSIX sh, a lone "{}" is parsed into shellNoopWords or a
			// command head containing the token. The remote recursion keeps
			// ONLY the resolution base of this call (the old shared screenCwd
			// reached remote segments too): the remote PATH base stays
			// os.Getenv("PATH") and the remote identity/env taint stay
			// cleared — nothing else of the local caller crosses.
			if replTokenInExecSlot(rseg.argv, token, os.Getenv("PATH"), callerIdentity{cwd: caller.cwd}) {
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
		// Block piped stdin and local file input redirection (< file) to
		// prevent local file exfiltration; inline heredoc/here-string data
		// (`ssh dmit cat <<'EOF'`) has no local file-read reach and stays
		// allowed (program heredocs are screened via screenBody below).
		if seg.pipedStdin || seg.stdinRedir {
			return roSSHWriteHit
		}
		if h := sshKnownHostsHit(head); h != "" {
			return h
		}
	}
	langs, stdinIsProg := remoteStdinProgramLangsCwd(remoteCmd, caller.screenCwd())
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
	vehicleOnly := stdinIsProg &&
		(seg.hereString != "" || len(seg.heredocText) > 0) &&
		isPureRemoteStdinVehicleCwd(remoteCmd, caller.screenCwd())

	remoteCaller := caller
	remoteCaller.envTaint = nil
	remoteCaller.pathEnv = ""
	// Remote commands resolve under the remote login env — the remote
	// PATH base above — but the old shared screenCwd was still the
	// resolution base for relative heads inside remote segments
	// (`ssh host ./bin/mytool`, find/xargs replace-tokens landing in an
	// exec slot, bare-interp stdin detection). Dropping it here would
	// silently fall back to the process cwd and change every such
	// verdict, so the call cwd rides along (it is a resolution base,
	// not identity: role/envTaint/pathEnv stay remote, cleared above).
	remoteCaller.cwd = caller.cwd
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
// grammar itself (SH11 MF-1/F7). The no-cwd wrapper keeps the legacy
// unit-screening semantics: resolution falls back to the process working
// directory, the same base the empty screenCwd had.
func isPureRemoteStdinVehicleCwd(remoteCmd, cwd string) bool {
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
	// A lang == "" verdict resolves the remote vehicle head under the
	// same screen cwd the outer caller used (process-cwd fallback when
	// unset): the old shared screenCwd reached this recursion too.
	lang, isProg := stdinProgramHeadCwd(s.argv, cwd)
	return isProg && lang == ""
}

// remoteReadsProgramFromStdin reports whether the remote command string
// contains a head that reads its program from stdin (a bare remote
// `sh`/`python3 -` with no inline code). Only then are piped bytes
// unaudited remote CODE rather than data for the remote command.
func remoteReadsProgramFromStdinCwd(remoteCmd, cwd string) bool {
	_, reads := remoteStdinProgramLangsCwd(remoteCmd, cwd)
	return reads
}

// remoteStdinProgramLangs returns the interpreter langs of remote heads that
// read program text from stdin (SF-2). The no-cwd wrapper resolves heads
// against the process working directory — the base the old empty screenCwd
// had; the Cwd variant carries the screening call's own cwd so relative
// remote heads resolve like the outer caller just resolved them.
func remoteStdinProgramLangsCwd(remoteCmd, cwd string) (langs []string, readsProg bool) {
	for _, seg := range splitShellSegments(remoteCmd) {
		if seg.depthExceeded || seg.parseErr != "" {
			return []string{""}, true
		}
		if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || seg.backgrounded ||
			len(seg.heredocText) > 0 || seg.hereString != "" {
			continue
		}
		if lang, isProg := stdinProgramHeadCwd(seg.argv, cwd); isProg {
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
	seenSHKC := false
	ukhSink := false
	seenUKH := false
	endOpts := false
	sawDest := false
	for i := 1; i < len(head); i++ {
		a := head[i]
		if isDynamicArg(a) {
			if !endOpts && !sawDest {
				sawDest = true
				continue
			}
			if sawDest {
				break
			}
			continue
		}
		if !endOpts && a == "--" {
			endOpts = true
			continue
		}
		if !endOpts && strings.HasPrefix(a, "--") {
			continue
		}
		if !endOpts && len(a) >= 2 && a[0] == '-' {
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
					v = strings.Trim(v, " \t\r\n")
					if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
						v = v[1 : len(v)-1]
					}
					key, val := v, ""
					if k := strings.IndexAny(v, "= \t"); k >= 0 {
						key = v[:k]
						val = strings.Trim(v[k+1:], " \t\r\n\"")
					}
					switch strings.ToLower(strings.Trim(key, " \t\r\n\"")) {
					case "stricthostkeychecking":
						if !seenSHKC {
							seenSHKC = true
							shkc = strings.ToLower(val)
						}
					case "userknownhostsfile":
						if !seenUKH {
							seenUKH = true
							if val == "/dev/null" || strings.EqualFold(val, "none") {
								ukhSink = true
							}
						}
					}
					j = len(a)
					continue
				}
				if sshShortTakesValue(c) {
					if j+1 >= len(a) && i+1 < len(head) {
						i++
					}
					j = len(a)
				}
			}
			continue
		}
		if !sawDest {
			sawDest = true
			continue
		}
		break // remote command starts here
	}
	if (shkc == "no" || shkc == "off" || shkc == "accept-new") && !ukhSink {
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
			if i+1 < len(head) && isDynamicArg(head[i+1]) && !isSplitSafeDynamicWord(head[i+1]) {
				return cmdSubPlaceholder
			}
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
func pathIsUnsafeForSubagent(val, headBase string, caller callerIdentity) bool {
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
		if !isSafePathDirEntryCwd(norm, caller.screenCwd()) {
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
// home directory or the caller identity's screen cwd).
func (c callerIdentity) isUserToolchainPathDir(norm string) bool {
	return isUserToolchainPathDirCwd(norm, c.screenCwd())
}
func isUserToolchainPathDir(norm string) bool {
	return isUserToolchainPathDirCwd(norm, callerIdentity{}.screenCwd())
}
func isUserToolchainPathDirCwd(norm, cwd string) bool {
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
	// Project-local venv / node_modules/.bin under the screen cwd.
	if cwd != "" {
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
func isTrustedPathDirOnDiskCwd(norm string, euid int, cwd string) bool {
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
	if resolved != norm && !isSystemPathDir(resolved) && !isLinuxbrewPathDir(resolved) && !isUserToolchainPathDirCwd(resolved, cwd) {
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
	return isSafePathDirEntryCwd(norm, "")
}
func isSafePathDirEntryCwd(norm, cwd string) bool {
	if !filepath.IsAbs(norm) {
		return false
	}
	norm = filepath.Clean(norm)
	if isTmpOrScratchPath(norm) {
		return false
	}
	if !isSystemPathDir(norm) && !isLinuxbrewPathDir(norm) && !isUserToolchainPathDirCwd(norm, cwd) {
		return false
	}
	return isTrustedPathDirOnDiskCwd(norm, os.Geteuid(), cwd)
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
func screenEnvAssignments(envAs envAssignments, kind byte, callerRole, callerReadonly, headBase string, caller callerIdentity) string {
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
				if pathIsUnsafeForSubagent(op.value, headBase, caller) {
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
		if isDynamicArg(a) && strings.HasPrefix(a, "-") {
			return i
		}
		if strings.HasPrefix(a, "--") {
			if j := strings.IndexByte(a, '='); j > 0 {
				i++
			} else if xargsLongWithValue[a] {
				if i+1 < len(argv) && isDynamicArg(argv[i+1]) && !isSplitSafeDynamicWord(argv[i+1]) {
					return i + 1
				}
				i += 2
			} else {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			consumedNext := false
			for j := 1; j < len(a); j++ {
				if a[j] == 'e' || a[j] == 'i' {
					break
				}
				if xargsShortWithValue[a[j]] {
					consumedNext = j+1 >= len(a)
					break
				}
			}
			if consumedNext && i+1 < len(argv) && isDynamicArg(argv[i+1]) && !isSplitSafeDynamicWord(argv[i+1]) {
				return i + 1
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
				if replTokenInExecSlot(inner, "{}", caller.pathEnv, caller) {
					return "find " + a + " dynamic code payload"
				}
				// Nested hc/herdr-core via find -exec* / -ok* receives path args
				// at runtime ({} replacement / + batching). Block unconditionally.
				th, tea, teffP, tex := peelWrappersAndWrapperAliases(inner, caller.pathEnv, caller)
				if tex {
					return "find " + a + " " + depthExceededHit
				}
				// Same env -C re-anchor as the xargs branch: the peeled ops
				// seed the caller before alias/self-exe resolution (R4 MF-2).
				tCaller := caller.seededWith(tea)
				for _, b := range headBaseAliasHits(th, teffP, tCaller) {
					if b == "hc" || b == "herdr-core" {
						return "find " + a + " " + b
					}
				}
				if len(th) > 0 && headIsCtxmodeOrSelfExe(th[0], teffP, tCaller.screenCwd()) {
					return "find " + a + " ctxmode --hc-gate"
				}
				innerSeg := shellSegment{}
				if a == "-ok" || a == "-okdir" {
					// -ok/-okdir share find's own stdin stream: inherit ONLY
					// the outer stdin facts, never the outer words.
					innerSeg = stdinOnlySeg(outerSeg)
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
// (Defined beside guardArgvReadonly below so the method+wrapper pair stays
// together.)

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
	// The inner code screen resolves under the same call cwd as the
	// enclosing segment — the guardCall must inherit it or the process-cwd
	// fallback would resolve differently than the head just screened.
	g.cwd = caller.cwd
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
	if seg.pipedStdin && !seg.stdinRedir && !sshTunnelsStdinProgram(seg.argv, caller.pathEnv, caller) {
		if lang, isProg, _ := stdinProgramHeadWithEnv(seg.argv, 0, envAssignments{}, caller.pathEnv, caller); isProg {
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
		if lang, isProg, envAs := stdinProgramHeadWithEnv(seg.argv, 0, envAssignments{}, caller.pathEnv, caller); isProg {
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
	sshTunnel := sshTunnelsStdinProgram(seg.argv, caller.pathEnv, caller)
	if seg.stdinRedir {
		return ""
	}
	lang, isProg, envAs := stdinProgramHeadWithEnv(seg.argv, 0, envAssignments{}, caller.pathEnv, caller)
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
	return guardShellSubagentDepthSegs(splitShellSegmentsCaller(code, envTaint, caller), depth, caller)
}

func guardShellSubagentDepthBash(code string, depth int, caller callerIdentity) string {
	return guardShellSubagentDepthSegs(splitShellSegmentsBashCaller(code, caller.envTaint, caller), depth, caller)
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
