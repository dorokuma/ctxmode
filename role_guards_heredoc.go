package main

// role_guards_heredoc.go — ssh/remote-stdin vehicle screens and heredoc/here-string stdin target analysis.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

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
				if h := screenStdinProgram(body, lang, bodyKind, depth, caller, false); h != "" {
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
	// R22-Oracle-M5 / R22-Reviewer-#5: the exemption CERTIFIES a known
	// pure shell, so an exhausted projection (the analysis gave up before
	// identifying the consumer) must never qualify — lang == "" on an
	// exhausted target is the zero value of unknowable, not POSIX sh.
	lang, isProg, exhausted := stdinProgramHeadCwdExh(s.argv, cwd)
	return isProg && !exhausted && lang == ""
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
						// R10-MF-3: the separate operand must stay one argv
						// word — an unquoted $VAR field-splits into extra
						// option words (-o ProxyCommand=pig, executed locally
						// before connect) and a multi-match glob overflows
						// the slot, shifting the remote command boundary.
						if isDynamicArg(head[i+1]) && !isSingleWordSplitSafe(head[i+1]) {
							return "", "dynamic code payload"
						}
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

// scriptOptScan is the small state machine both script screens share
// (v6.2.2 MF-9): it walks util-linux script's option zone with the REAL
// operand arity — the valued letters O/I/B/T/t/o/m/l end their cluster
// (a glued tail IS the value, so letters inside it — like the 'c' of
// `-T/tmp/xc` — are filename bytes, never flags) and consume the next
// argv only when bare, while 'c' anywhere in a cluster is the command
// flag and GNU unique prefixes of --command abbreviate it.
type scriptOptScan struct {
	cmdText    string // the -c/--command operand (or glued tail)
	cmdFlagIdx int    // argv index of the word carrying the command flag, -1 none
	cmdOpen    bool   // the command flag's operand never arrived
}

// scanScriptOpts walks head[1:] once and fills the scan result. Dynamic
// words surface as cmdSubPlaceholder payloads like the legacy screens did.
func scanScriptOpts(head []string) scriptOptScan {
	var sc scriptOptScan
	sc.cmdFlagIdx = -1
	for i := 1; i < len(head); i++ {
		a := head[i]
		if a == "--" {
			return sc
		}
		if isDynamicArg(a) {
			sc.cmdText, sc.cmdFlagIdx = cmdSubPlaceholder, i
			return sc
		}
		if strings.HasPrefix(a, "--") {
			i = scanScriptLong(head, i, &sc)
			if sc.cmdFlagIdx >= 0 {
				return sc
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			i = scanScriptCluster(head, i, &sc)
			if sc.cmdFlagIdx >= 0 {
				return sc
			}
			continue
		}
		// Positional typescript file: util-linux script's getopt_long has NO
		// leading '+' — options are PERMUTED after positional operands, so a
		// -c following the file still arms the command. Skip the operand and
		// keep scanning (v6.2.2 R3 R2-MF-4 / Reviewer MF-3).
		continue
	}
	return sc
}

// scanScriptLong handles one `--` word of script's option zone and returns
// the loop index to continue from. GNU getopt_long unique abbreviations of
// --command count; the valued long options consume their operands. util-linux
// script's --timing is an OPTIONAL argument (t:: / --timing[=FILE]) — only
// the glued =FILE form carries a value, a bare --timing NEVER consumes the
// next argv (v6.2.2 R3 R2-MF-4).
func scanScriptLong(head []string, i int, sc *scriptOptScan) int {
	a := head[i]
	name, val, hasVal := a[2:], "", false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, val, hasVal = name[:k], name[k+1:], true
	}
	if strings.HasPrefix("command", name) && name != "" {
		sc.cmdFlagIdx = i
		switch {
		case hasVal:
			sc.cmdText = val
		case i+1 < len(head):
			sc.cmdText = head[i+1]
		default:
			sc.cmdOpen = true
		}
		return i
	}
	if name == "timing" || strings.HasPrefix("timing", name) && len(name) >= 2 {
		// optional_argument: only the =glued form carries a value.
		return i
	}
	// util-linux script value long options: log-in/log-out/log-timing
	// (-I/-O/-T), log-io (-B), output-limit (-o), logging-format (-m) and
	// echo (-E, v6.2.2 R3 R3-MF-4).
	for _, full := range []string{"log-out", "log-in", "log-timing", "log-io", "output-limit", "logging-format", "echo"} {
		if strings.HasPrefix(full, name) && name != "" {
			if !hasVal && i+1 < len(head) {
				if isDynamicArg(head[i+1]) && !isSingleWordSplitSafe(head[i+1]) {
					sc.cmdText, sc.cmdFlagIdx = cmdSubPlaceholder, i
					return i
				}
				return i + 1
			}
			return i
		}
	}
	return i
}

// scanScriptCluster handles one short-option cluster word of script's
// option zone: valued letters end the cluster (their tail IS the value —
// never flag bytes), 'c' is the command flag.
func scanScriptCluster(head []string, i int, sc *scriptOptScan) int {
	a := head[i]
	for j := 1; j < len(a); j++ {
		ch := a[j]
		switch ch {
		case 'c':
			sc.cmdFlagIdx = i
			switch {
			case j+1 < len(a):
				sc.cmdText = a[j+1:]
			case i+1 < len(head):
				sc.cmdText = head[i+1]
			default:
				sc.cmdOpen = true
			}
			return i
		case 'O', 'I', 'B', 'T', 'o', 'm', 'E':
			if j+1 >= len(a) && i+1 < len(head) {
				if isDynamicArg(head[i+1]) && !isSingleWordSplitSafe(head[i+1]) {
					sc.cmdText, sc.cmdFlagIdx = cmdSubPlaceholder, i
					return i
				}
				return i + 1 // bare valued letter: the next argv is its operand
			}
			return i // glued value ends the cluster
		case 't':
			// optional_argument (t::): only a glued tail is the timing file —
			// a bare -t NEVER consumes the next argv, so the cluster scan
			// simply ends here (v6.2.2 R3 R2-MF-4).
			return i
		}
	}
	return i
}

// scriptOptZoneHasToken reports whether the token sits anywhere in
// script's option zone — every word BEFORE the -- terminator, positional
// operands included: util-linux script's getopt_long has no leading '+',
// so options are PERMUTED and ANY pre-`--` word can expand into
// -c/--command at runtime regardless of position (v6.2.2 R3 R3-MF-4 —
// the earlier positional-early-return let `script % 'pig' /dev/null` and
// `script /dev/null % 'pig'` slip past in the xargs -a / find -exec /
// argv+stdin spellings). Words after `--` remain inert data.
func scriptOptZoneHasToken(h []string, token string) bool {
	for i := 1; i < len(h); i++ {
		a := h[i]
		if a == "--" {
			return false
		}
		if strings.Contains(a, token) {
			return true
		}
		consume, hit := scriptOptWordTokenStep(h, i, token)
		if hit {
			return true
		}
		i += consume
	}
	return false
}

// scriptOptWordTokenStep advances scriptOptZoneHasToken past the option
// word at index i (extracted so the scan loop stays reviewable — v6.2.2
// R3): consume counts EXTRA argv operands consumed, hit reports the token
// inside a value operand.
func scriptOptWordTokenStep(h []string, i int, token string) (consume int, hit bool) {
	a := h[i]
	if !strings.HasPrefix(a, "-") || len(a) <= 1 {
		// Positional operands are not option words — treating them as short
		// clusters would let a filename ending in c/O/I/... swallow the
		// following `--` terminator (v6.2.2 Oracle R4 R4-SF-3
		// `script /tmp/out.o -- %`).
		return 0, false
	}
	if strings.HasPrefix(a, "--") {
		name := a[2:]
		hasEq := strings.IndexByte(name, '=') >= 0
		if k := strings.IndexByte(name, '='); k >= 0 {
			name = name[:k]
		}
		for _, full := range []string{"log-out", "log-in", "log-timing", "log-io", "output-limit", "logging-format", "echo", "command"} {
			if strings.HasPrefix(full, name) && name != "" && !hasEq && i+1 < len(h) {
				return 1, strings.Contains(h[i+1], token)
			}
		}
		return 0, false
	}
	// Short cluster: O/I/B/T/o/m/E take values, c takes the command.
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if ch == 'c' || ch == 'O' || ch == 'I' || ch == 'B' || ch == 'T' || ch == 'o' || ch == 'm' || ch == 'E' {
			if j+1 >= len(a) && i+1 < len(h) {
				return 1, strings.Contains(h[i+1], token)
			}
			return 0, false
		}
		if ch == 't' {
			return 0, false // optional-glued only
		}
	}
	return 0, false
}

// scriptHasOpenCommandFlag reports whether a `script` argv ends with a
// dangling -c/--command flag whose shell-command operand has not been
// supplied yet (so an enclosing xargs would append stdin words into -c's
// slot).
func scriptHasOpenCommandFlag(head []string) bool {
	sc := scanScriptOpts(head)
	if sc.cmdFlagIdx < 0 {
		return false
	}
	if sc.cmdOpen {
		return true
	}
	return false
}

// scriptCommandArg returns the `-c cmd` payload of a `script` argv, or "".
// Short clusters count (`script -qc 'pig'`, `script -c"pig"`), as do
// --command/--command= forms and their GNU unique abbreviations.
func scriptCommandArg(head []string) string {
	sc := scanScriptOpts(head)
	if sc.cmdFlagIdx < 0 {
		return ""
	}
	return sc.cmdText
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
// R21-Reviewer-6: two untrusted-input shapes NEVER yield a resolvable
// PATH — the expansion-budget overflow (a self-referencing chain whose
// replayed size crosses maxShellCommandBytes: expanding it would either
// allocate an attacker-sized string or truncate into a DIFFERENT valid
// short PATH) and the control-flow uncertainty marker 't' (a conditional
// write makes the merged value unknowable). Both return a
// placeholder-carrying non-path string: no directory resolution can ever
// succeed against it, and callers that gate rewrites detect the marker
// through effectivePATHUntrusted.
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
		case 't':
			if op.key == "PATH" {
				path = cmdSubPlaceholder
			}
		case 'a':
			if op.key == "PATH" {
				expanded, ok := expandPathSelfRefs(op.value, path)
				if !ok {
					path = cmdSubPlaceholder
					continue
				}
				path = expanded
			}
		}
	}
	return path
}

// pathUntrusted reports whether the effective PATH these env ops produce
// over base can never resolve a command head honestly (R22-Oracle-#6 /
// R22-Reviewer-#6): a control-flow uncertainty marker op ('t' — a
// conditional write makes the merged value unknowable), or a
// self-reference expansion the byte budget refused (the replay
// degenerates to the unresolvable placeholder rather than materializing
// an attacker-sized string or a truncated DIFFERENT short PATH). Either
// shape means a bare command name resolved against it is UNKNOWABLE —
// never a proven data consumer and never a rewrite candidate.
func (e envAssignments) pathUntrusted(base string) bool {
	for _, op := range e.ops {
		if op.kind == 't' && op.key == "PATH" {
			return true
		}
	}
	return strings.Contains(e.effectivePATHFrom(base), cmdSubPlaceholder)
}

// pathUntrusted reports whether this caller identity's effective PATH is
// already degenerated to the unresolvable placeholder (R22-Oracle-#6):
// the untrusted verdict is sticky across every seeding replay, so once
// any env layer failed the budget the identity carries it forward.
func (c callerIdentity) pathUntrusted() bool {
	return strings.Contains(c.pathEnv, cmdSubPlaceholder)
}

// expandPathSelfRefs substitutes the unforgeable $PATH sentinel with base
// (the PATH in force at assignment time) so alias resolution sees the same
// search list the runtime would (a sentinel value never reaches here
// unexpanded: it only exists in PATH= values the guard already admitted).
// R21-Reviewer-6: the substitution is budget-checked BEFORE any allocation
// — a cross-statement self-reference chain (PATH=$PATH$x PATH=$PATH$x …)
// materializes the previous expansion repeatedly, so the output size is
// estimated first; once it crosses maxShellCommandBytes the assignment
// verdict is UNTRUSTED (ok=false) instead of a giant allocation or a
// truncated short PATH the shell never computes.
func expandPathSelfRefs(val, base string) (string, bool) {
	if strings.Contains(base, cmdSubPlaceholder) {
		// The accumulator already degenerated to the untrusted marker:
		// expanding further ops against it could materialize a
		// VALID-looking short PATH (placeholder-shaped segments are not
		// real directories, but a later op may drop the sentinel entirely
		// and re-install an exact value the chain never computed).
		// Untrusted is sticky across the rest of the replay.
		return "", false
	}
	n := strings.Count(val, envPathSelfPlaceholder)
	if n == 0 {
		return val, len(val) <= maxShellCommandBytes
	}
	est := len(val) - n*len(envPathSelfPlaceholder) + n*len(base)
	if est > maxShellCommandBytes {
		return "", false
	}
	out := strings.ReplaceAll(val, envPathSelfPlaceholder, base)
	if len(out) > maxShellCommandBytes {
		return "", false
	}
	return out, true
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
		case 't':
			// R21-Oracle-M3: a control-flow uncertainty marker invalidates
			// the variable's expansion semantics exactly like an overwrite —
			// the merged value is unknowable, so the placeholder grants must
			// not trust it.
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
// The per-command scanners are extracted so each stays small enough to
// audit (v6.2.2 Oracle R11 R11-MF-3).
func screenEnvWriteTargets(head []string, base string) string {
	switch base {
	case "read":
		return screenReadEnvWrite(head)
	case "getopts":
		return screenGetoptsEnvWrite(head)
	case "printf":
		return screenPrintfEnvWrite(head)
	}
	return ""
}

// writeTargetBase parses one bash write-target NAME slot: a plain variable
// name or a scalar array-element spelling BASE[SUBSCRIPT]. The subscript
// must be a non-empty run of decimal digits — bash evaluates [...] as
// arithmetic, so any arithmetic/dynamic shape (x[1+1], x[$i], nested or
// unbalanced brackets, whitespace, a bare closing ']') is unvettable and
// reported ok=false. The returned name is the BASE for lookup: assigning
// arr[0] is an assignment to the array arr itself.
func writeTargetBase(raw string) (name string, ok bool) {
	lb := strings.IndexByte(raw, '[')
	if lb < 0 {
		if strings.IndexByte(raw, ']') >= 0 {
			return raw, false // dangling ']': never a valid write target
		}
		return raw, true
	}
	if !strings.HasSuffix(raw, "]") || lb == 0 {
		return raw, false
	}
	base := raw[:lb]
	if !isShellIdentStart(base) {
		return base, false
	}
	if !allDigits(raw[lb+1 : len(raw)-1]) {
		return base, false // arithmetic/dynamic subscript: unvettable
	}
	return base, true
}

// isShellIdentStart reports whether s matches bash's identifier grammar
// [A-Za-z_][A-Za-z0-9_]* — the only spellings printf -v / read / getopts
// accept as a write-target variable name.
func isShellIdentStart(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlpha := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if isAlpha || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// envWriteTainted vets one write-target NAME slot: dynamic (unvettable)
// names, malformed/arithmetic array subscripts and role-identity /
// execution-hook variables are refused. Array-element spellings are vetted
// through writeTargetBase (R4-MF-4): a legal arr[0] reduces to the array
// base for the hook lookup.
func envWriteTainted(name, base string) string {
	if isDynamicArg(name) {
		return "env dynamic " + base
	}
	target, ok := writeTargetBase(name)
	if !ok {
		return "env dynamic " + base
	}
	if guardTaintVars[target] || isEnvHookVar(target) {
		return "env " + target
	}
	return ""
}

// dynWordCanSpellDashDash reports whether a dynamic word's expansion can
// be EXACTLY "--": stripping every placeholder marker must leave only '-'
// bytes (or nothing — an empty expansion still lands as one operand, never
// shifting into head[3]'s slot in a way the static layout misses). Any
// surviving ':'/letter/digit makes "--" unreachable at runtime (R4-SF-2).
// R13-SF-2 exactness: an absolute-path placeholder ($PWD/$(pwd)/$(mktemp
// -d)) or the PATH self-sentinel ALWAYS yields '/'-leading or colon-joined
// path text — never a bare "--". And since expansion can only GROW or
// shrink the dynamic part, a static remainder of three or more dashes
// (`---$X`) can never shrink back to exactly two, so len(rest) must stay
// within the two-byte terminator. A bare dynamic word (no static bytes)
// still qualifies: X="--" is a legal runtime expansion.
func dynWordCanSpellDashDash(a string) bool {
	if strings.Contains(a, cmdSubPlaceholderAbsDq) || strings.Contains(a, envPathSelfPlaceholder) {
		return false
	}
	rest := a
	for _, ph := range []string{cmdSubPlaceholderAbsDq, cmdSubPlaceholderQuoted, cmdSubPlaceholderGlob, cmdSubPlaceholder} {
		rest = strings.ReplaceAll(rest, ph, "")
	}
	if len(rest) > 2 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] != '-' {
			return false
		}
	}
	return true
}

// envDynSlotHit vets a single-value OPTION OPERAND slot (read's -p/-t/-d/...
// argument, getopts' OPTSTRING): a word that field-splits or pathname-
// expands at runtime overflows its slot, so the positional layout the
// scanner validated no longer matches what the builtin consumes (R11-MF-3).
func envDynSlotHit(v, base string) string {
	if isDynamicArg(v) && !isSingleWordSplitSafe(v) {
		return "env dynamic " + base
	}
	return ""
}

// readClusterStep scans ONE static `read` option-cluster word (the '-'
// already vetted by the caller): value letters d n N p t u a consume a
// value — the cluster tail, or the next argv when last; every other
// letter (r s e i) is a boolean. R13: -s is silent echo, NOT a value
// option — `read -s x` still writes x. extra reports how many ADDITIONAL
// argv words (separate value operands) were consumed. Every separate
// value slot is vetted BEFORE being skipped: a word-splitting $X
// prompt/nchars/delim overflows into a forged write-target name slot at
// runtime (R11-MF-3).
func readClusterStep(head []string, j int) (hit string, extra int) {
	a := head[j]
	for k := 1; k < len(a); k++ {
		switch a[k] {
		case 'a':
			// -a ARRAY is itself a write target.
			if k+1 < len(a) {
				return envWriteTainted(a[k+1:], "read"), extra
			}
			if j+1+extra < len(head) {
				arr := head[j+1+extra]
				if hit := envDynSlotHit(arr, "read"); hit != "" {
					return hit, extra
				}
				extra++
				return envWriteTainted(arr, "read"), extra
			}
			return "", extra
		case 'd', 'n', 'N', 'p', 't', 'u', 'i':
			if k+1 < len(a) {
				return "", extra // glued value tail ends the cluster
			}
			if j+1+extra < len(head) {
				if hit := envDynSlotHit(head[j+1+extra], "read"); hit != "" {
					return hit, extra
				}
				extra++ // separate value operand
			}
			return "", extra
		}
	}
	return "", extra
}

// readDynClusterHit vets ONE dynamic `read` option-zone word
// (R11 closure / R4-SF-1): a placeholder inside the option-LETTER zone is
// unvettable — `read "-$OPT"` picks its cluster letters at runtime even
// though the quoted expansion stays one argv word. A value letter
// (d n N p t u i) reached BEFORE the dynamic part ends the cluster — the
// tail is a glued prompt/initial value, not option letters — so split-safe
// spellings (`read -p"$PROMPT" x`, `read -p"Prompt: $P" x`) stay ALLOW. A
// glued dynamic -a ARRAY tail is a write TARGET, not a value: the
// variable name is unvettable either way.
func readDynClusterHit(a string) string {
	for k := 1; k < len(a); k++ {
		c := a[k]
		if c == '_' {
			break // every placeholder spelling starts with '_'
		}
		if strings.IndexByte("dnNptui", c) >= 0 {
			// R13-MF-4: split-safety alone is not enough — the glued value
			// tail must be PROVABLY NON-EMPTY at runtime. `read -p"$PROMPT"`
			// with PROMPT='' collapses to `read -p`, and bash then consumes
			// the NEXT argv word as the prompt text, silently shifting the
			// positional write-target layout the scan validated. A tail with
			// at least one static literal byte (`-p"Prompt: $P"`) or a
			// guaranteed non-empty placeholder class can never collapse.
			if isSingleWordSplitSafe(a) && dynGluedTailNonEmpty(a[k+1:]) {
				return "" // glued dynamic value tail: data, not letters
			}
			return "env dynamic read"
		}
		if c == 'a' {
			return "env dynamic read" // dynamic array-name tail: unvettable
		}
		// R14 closure: only the known BOOLEAN letters may precede the dynamic
		// part (parity with shell_ast.go's 'r', 's', 'e' case arm) — any other
		// static byte is an unknown option letter whose runtime consumption
		// shape is unvettable, so fail closed instead of silently stepping over
		// it.
		if strings.IndexByte("rse", c) < 0 {
			return "env dynamic read"
		}
	}
	return "env dynamic read"
}

// dynGluedTailNonEmpty reports whether a glued read-option value tail is
// PROVABLY non-empty at runtime (R13-MF-4): after stripping every
// placeholder spelling at least one static literal byte must survive, or
// the tail must carry the absolute-path placeholder class (an expansion
// guaranteed to start with '/'). Ordinary quoted placeholders
// (cmdSubPlaceholderQuoted — including the '$$' PID digits, which are
// never empty), unquoted splittable expansions and globs can all collapse
// to the empty string, so a tail built from nothing else is unvettable.
func dynGluedTailNonEmpty(tail string) bool {
	if strings.Contains(tail, cmdSubPlaceholderAbsDq) {
		return true
	}
	rest := tail
	for _, ph := range []string{cmdSubPlaceholder, cmdSubPlaceholderQuoted, cmdSubPlaceholderGlob, cmdSubPlaceholderAbsDq, envPathSelfPlaceholder} {
		rest = strings.ReplaceAll(rest, ph, "")
	}
	return rest != ""
}

// screenReadEnvWrite scans bash's `read` builtin: option letters are
// consumed cluster-wise, every separate value slot is vetted against
// runtime word-splitting, and the positional names are write targets
// (R11-MF-3).
func screenReadEnvWrite(head []string) string {
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
			if isDynamicArg(a) {
				if hit := readDynClusterHit(a); hit != "" {
					return hit
				}
				j++
				continue
			}
			hit, extra := readClusterStep(head, j)
			if hit != "" {
				return hit
			}
			j += 1 + extra
			continue
		}
		if a == "" {
			j++
			continue
		}
		if hit := envWriteTainted(a, "read"); hit != "" {
			return hit
		}
		j++
	}
	return ""
}

// screenGetoptsEnvWrite scans `getopts OPTSTRING NAME [args...]`: the
// OPTSTRING operand itself may be a static word starting with ':' or '-'
// (bash getopts treats the first operand as the optstring regardless),
// but a dynamic word in the pre-`--` zone or in the OPTSTRING slot can
// word-split at runtime, shifting NAME into an attacker-chosen slot
// (R11-MF-3: `getopts $X -1` with X='1 GIT_CONFIG_COUNT').
func screenGetoptsEnvWrite(head []string) string {
	opIdx := 0
	if len(head) > 1 {
		if head[1] == "--" {
			if len(head) > 2 {
				opIdx = 2
			}
		} else {
			if hit := envDynSlotHit(head[1], "getopts"); hit != "" {
				return hit
			}
			// R11 closure / R4-SF-2: a dynamic first operand may expand to
			// exactly "--" at runtime ONLY when its static remainder is dash-
			// shaped — `H="--"; getopts "$H" opt TAR_OPTIONS` shifts the
			// positional layout so head[3] becomes the write-target NAME, but
			// `getopts ":$OPTS" opt TAR_OPTIONS` can never spell "--" (the
			// literal ':'/`o` survive every expansion) and keeps the static
			// layout. Vet the standby slot only for the dash-shaped form.
			if isDynamicArg(head[1]) && len(head) > 3 && dynWordCanSpellDashDash(head[1]) {
				if hit := envWriteTainted(head[3], "getopts"); hit != "" {
					return hit
				}
			}
			opIdx = 1
		}
	}
	if opIdx > 0 {
		if hit := envDynSlotHit(head[opIdx], "getopts"); hit != "" {
			return hit
		}
		if opIdx+1 < len(head) {
			if hit := envWriteTainted(head[opIdx+1], "getopts"); hit != "" {
				return hit
			}
		}
	}
	return ""
}

// printfFmtConv parses ONE printf conversion starting just after '%':
// flags, width ('*' consumes an argument), precision ('.*' likewise), an
// optional length modifier and the conversion letter. It reports the number
// of argument slots consumed AHEAD of the conversion plus whether the
// conversion is 'n', the index of the first byte AFTER the conversion, and
// whether a positional 'm$' designator appeared (unvettable slot
// attribution). ok=false means the conversion is malformed — bash errors
// out before writing anything.
//
// R14 closure: bash printf HONOURS the length modifiers hh/h/l/ll/j/z/t/L
// on EVERY conversion including 'n' (`printf "%ln" TAR_OPTIONS` writes 3
// into TAR_OPTIONS outright), so the modifiers are skipped BEFORE the
// conversion letter is judged. `%(...)T` (strftime) consumes one argument
// even with flags/width/precision in front (`%10(%Y)T`), and a digits+'$'
// sequence directly AFTER a '*' or '.*' (`%*2$n`) is a positional width
// designator — unvettable slot attribution, fail closed. 'q' is
// deliberately absent from the length modifiers: bash printf '%q' is the
// shell-quoting CONVERSION specifier, not a length modifier (R13-MF-2).
func printfFmtConv(fmtStr string, i int) (preArgs int, isN bool, next int, positional bool, ok bool) {
	// Positional 'm$' designator: unvettable slot attribution.
	if printfStarPositional(fmtStr, i) {
		return 0, false, i, true, false
	}
	for i < len(fmtStr) && strings.IndexByte("-+' #0,", fmtStr[i]) >= 0 {
		i++ // flag characters
	}
	width, wpos, wnext := printfFmtMeasure(fmtStr, i)
	if wpos {
		return 0, false, i, true, false
	}
	preArgs += width
	i = wnext
	if i < len(fmtStr) && fmtStr[i] == '.' {
		prec, ppos, pnext := printfFmtMeasure(fmtStr, i+1)
		if ppos {
			return 0, false, i, true, false
		}
		preArgs += prec
		i = pnext
	}
	// Optional length modifier: hh/ll or single h/l/j/z/t/L. Bash applies
	// them to every conversion INCLUDING 'n', so skipping them is what makes
	// `%ln`/`%hhn`/`%lln` visible as write conversions at all.
	if i < len(fmtStr) {
		switch fmtStr[i] {
		case 'h', 'l':
			i++
			if i < len(fmtStr) && fmtStr[i] == fmtStr[i-1] {
				i++ // doubled hh / ll
			}
		// R13-MF-2: bash printf's length modifiers are h/hh/l/ll/j/z/t/L only
		// (LENMODS = "hjlLtz") — 'q' is NOT among them. '%q'/'%Q' are
		// CONVERSION specifiers emitting shell-quoted text, so `%q%n` is a
		// quoting conversion followed by a '%n' write conversion and `%qn`
		// is a quoting conversion followed by a literal 'n'.
		case 'j', 'z', 't', 'L':
			i++
		}
	}
	if i >= len(fmtStr) {
		return preArgs, false, i, false, false // missing conversion letter
	}
	if fmtStr[i] == '(' {
		// '%(...)T' strftime conversion: exactly ONE argument slot (never a
		// write), the parenthesized text is strftime layout where '%n' is a
		// newline. Without the closing ')' or the trailing 'T' bash errors
		// out before writing anything.
		close := strings.IndexByte(fmtStr[i:], ')')
		if close < 0 {
			return preArgs, false, len(fmtStr), false, false
		}
		i += close + 1
		if i < len(fmtStr) && fmtStr[i] == 'T' {
			return preArgs, false, i + 1, false, true
		}
		return preArgs, false, i, false, false
	}
	return preArgs, fmtStr[i] == 'n', i + 1, false, true
}

// printfFmtMeasure parses ONE width/precision measure starting at i: a
// '*' consumes one argument slot (and a digits+'$' directly after it is a
// positional width designator, reported as positional=true), a digit run
// is a numeric measure consuming nothing. The same shape serves both the
// width position and the post-'.' precision position.
func printfFmtMeasure(fmtStr string, i int) (preArgs int, positional bool, next int) {
	if i < len(fmtStr) && fmtStr[i] == '*' {
		return 1, printfStarPositional(fmtStr, i+1), i + 1
	}
	for i < len(fmtStr) && fmtStr[i] >= '0' && fmtStr[i] <= '9' {
		i++ // numeric measure
	}
	return 0, false, i
}

// printfStarPositional reports whether the bytes directly AFTER a '*' width
// or '.*' precision spell digits+'$' — a positional width designator
// (`%*2$n`) whose slot attribution is unvettable statically.
func printfStarPositional(fmtStr string, i int) bool {
	dig := i
	for dig < len(fmtStr) && fmtStr[dig] >= '0' && fmtStr[dig] <= '9' {
		dig++
	}
	return dig > i && dig < len(fmtStr) && fmtStr[dig] == '$'
}

// printfWriteHit is one write-target event from printfOptionScan: kind 'v'
// carries a -v variable name, kind 'n' a '%n' slot target argument.
type printfWriteHit struct {
	kind byte
	name string
}

// printfOptionScan walks bash printf's internal_getopt(list, "v:") option
// zone over the ALREADY-STRING argv words in order: glued -vVAR, clustered
// '-v' and repeated '-v x' spellings each emit a write hit, '--' or the
// first non-option word settles fmtIdx (the format-string position), and
// the format string plus arguments are scanned for '%n' write targets
// (printfFmtWriteHit applies — the per-target vetting is left to the
// caller so the argv guard can report a verdict while the AST pre-scan
// counts writes). dyn=true means a dynamic word in the option-letter zone
// or an unvettable format/target shape was seen: fail closed.
func printfOptionScan(words []string) (hits []printfWriteHit, fmtIdx int, dyn bool) {
	fmtIdx = -1
	j := 0
	for ; j < len(words); j++ {
		a := words[j]
		if a == "--" {
			fmtIdx = j + 1
			break
		}
		if strings.HasPrefix(a, cmdSubPlaceholder) || strings.HasPrefix(a, cmdSubPlaceholderQuoted) ||
			strings.HasPrefix(a, cmdSubPlaceholderGlob) {
			return hits, fmtIdx, true
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			if printfGlobFormatHit(a) {
				return hits, fmtIdx, true
			}
			fmtIdx = j
			break
		}
		if isDynamicArg(a) {
			return hits, fmtIdx, true
		}
		// Walk the short cluster; only 'v' is a real printf option letter.
		for k := 1; k < len(a); k++ {
			if a[k] != 'v' {
				continue // unknown letters end in bash's usage error — inert
			}
			if k+1 < len(a) {
				hits = append(hits, printfWriteHit{kind: 'v', name: a[k+1:]})
				break // glued -vVAR ends the cluster
			}
			if j+1 >= len(words) {
				return hits, fmtIdx, false // dangling -v: bash errors, inert
			}
			j++
			hits = append(hits, printfWriteHit{kind: 'v', name: words[j]})
			break
		}
	}
	if fmtIdx < 0 || fmtIdx >= len(words) {
		return hits, fmtIdx, dyn
	}
	nHits, nDyn := printfFmtWriteSlots(words[fmtIdx], words[fmtIdx+1:])
	return append(hits, nHits...), fmtIdx, dyn || nDyn
}

// printfFmtWriteSlots scans printf's format string for '%n' write targets
// (R4-MF-3): a dynamic variable/command-substitution format text is
// unvettable (dyn=true), positional 'm$' conversions fail closed, and a
// static format carrying a real '%n' first requires EVERY argument to stay
// a single argv word (an unquoted $X field-split shifts the positional
// alignment), then replays Bash's format-reuse cycle so the argument
// landing in each '%n' slot becomes a write hit. A dynamic format word
// (R14 closure — INCLUDING a glob-only one) with ANY trailing argument is
// unvettable: pathname expansion can legitimately spell '%n' inside a
// filename (`lit%n`), so `printf lit* TAR_OPTIONS` writes the byte count
// into TAR_OPTIONS outright. Only the no-argument spelling stays safe —
// with no arguments nothing can be written regardless of the format text.
func printfFmtWriteSlots(fmtStr string, fmtArgs []string) (hits []printfWriteHit, dyn bool) {
	if len(fmtArgs) == 0 {
		// R13-MF-1: zero argv arguments only means "nothing can be written"
		// when the format word itself is guaranteed to arrive as ONE runtime
		// argv word. An unquoted glob (`printf lit*` expanding to
		// `lit%n litTARGET`) or a word-splitting unquoted expansion can
		// produce MULTIPLE argv words at runtime — match[0]/word[0] becomes
		// the real format string (whose '%n' conversions bash then honours)
		// and match[1]/word[1] the first write-target argument. Only a
		// split-safe, glob-free spelling (e.g. `printf x"$FMT"`) stays
		// exactly one word, so with no arguments nothing is ever written.
		// R14-Oracle-S2: reuse isSingleWordOptionValue — it is exactly this
		// same single-runtime-word predicate PLUS the proven pure-tilde
		// exemption: `printf ~/banner` expands to ONE path word under any
		// normal absolute HOME (no glob metacharacters, no brace bytes), so
		// it must not be refused as `env dynamic printf`, while a globbing
		// or brace-expanding spelling (`printf ~/banner*`,
		// `printf tag{red,blue}`) keeps failing closed.
		if !isSingleWordOptionValue(fmtStr) {
			return nil, true
		}
		return nil, false
	}
	if isDynamicArg(fmtStr) {
		return nil, true
	}
	if !strings.Contains(fmtStr, "%") {
		return nil, false
	}
	slots, positional := printfFmtSlots(fmtStr)
	if positional {
		return nil, true
	}
	hasN := false
	for _, w := range slots {
		if w {
			hasN = true
			break
		}
	}
	if !hasN || len(slots) == 0 {
		return nil, false
	}
	for _, arg := range fmtArgs {
		if isDynamicArg(arg) && !isSingleWordSplitSafe(arg) {
			return nil, true // word-splitting shifts %n alignment
		}
	}
	for i, arg := range fmtArgs {
		if slots[i%len(slots)] {
			hits = append(hits, printfWriteHit{kind: 'n', name: arg})
		}
	}
	return hits, false
}

// printfFmtSlots scans ONE linear pass of a static printf FORMAT string,
// emitting the argv-consumption shape of a single cycle: '%%' is literal,
// '%(...)T' consumes one argument (its parentheses are strftime text, not
// format conversions — printfFmtConv settles flags/width/precision in
// front of it), '*' width and '.*' precision each consume one argument
// ahead of the conversion's own, length modifiers (hh/h/l/ll/j/z/t/L/q)
// are skipped before the conversion letter, and conversion 'n' marks its
// slot as a WRITE TARGET (bash printf %n stores the byte count into the
// named variable). Positional conversions ('m$' — including the `%*2$n`
// star-positional shape) cannot be attributed to argv slots statically —
// the second return reports them so the caller can fail closed. Scanning
// stops at a malformed conversion exactly the way bash errors out before
// writing.
func printfFmtSlots(fmtStr string) (slots []bool, hasPositional bool) {
	for i := 0; i < len(fmtStr); i++ {
		if fmtStr[i] != '%' {
			continue
		}
		i++
		if i >= len(fmtStr) {
			break // trailing '%': bash errors, inert
		}
		if fmtStr[i] == '%' {
			continue // literal '%%'
		}
		preArgs, isN, next, positional, ok := printfFmtConv(fmtStr, i)
		if positional {
			return slots, true
		}
		if !ok {
			break
		}
		for ; preArgs > 0; preArgs-- {
			slots = append(slots, false)
		}
		slots = append(slots, isN)
		i = next - 1
	}
	return slots, hasPositional
}

// printfGlobFormatHit reports whether a word carrying an unquoted
// pathname-expansion glob may expand into a printf OPTION spelling at
// runtime: with a glob-starting first byte ('*', '?', '[') or an extglob
// prefix ('@(', '+(' or '!(') the expansion can produce `-vNAME`,
// desynchronizing the statically scanned option zone (R4-MF-2). A word
// with a definite non-'-' literal first byte can only expand into more
// data words and stays a format string.
func printfGlobFormatHit(a string) bool {
	if !strings.Contains(a, cmdSubPlaceholderGlob) {
		return false
	}
	if strings.HasPrefix(a, "@(") || strings.HasPrefix(a, "+(") || strings.HasPrefix(a, "!(") {
		return true
	}
	if a == "" {
		return false
	}
	switch a[0] {
	case '*', '?', '[':
		return true
	}
	return false
}

// screenPrintfEnvWrite scans bash's `printf` builtin the way
// internal_getopt(list, "v:") actually consumes it: -v takes its variable
// name glued (-vVAR) or as the next argv, short clusters end at the 'v'
// letter, `--` terminates the option zone (bash then errors on the
// dangling -- itself, so `printf -- -v TAR_OPTIONS` is inert data), and
// EVERY -v name slot is vetted in sequence — a leading innocuous
// `-v x` no longer hides a later `-v TAR_OPTIONS` (R11-MF-3). Once the
// format word settles (post-`--` or the first non-option word) the format
// string and its arguments are vetted for '%n' write targets through
// printfFmtWriteHit (R4-MF-3).
func screenPrintfEnvWrite(head []string) string {
	// R11 closure: a word STARTING with a dynamic placeholder — even the
	// quoted-safe spelling — can expand to `-v...` at runtime, so it must
	// never vet as a static format string (`OPT="-vTAR_OPTIONS";
	// printf "$OPT" "%s" "--use-compress-program=pig"`). R4-MF-2/-MF-3:
	// printfOptionScan additionally refuses glob-expansion option spells
	// and scans the format string's '%n' write slots.
	hits, _, dyn := printfOptionScan(head[1:])
	if dyn {
		return "env dynamic printf"
	}
	for _, h := range hits {
		if hit := envWriteTainted(h.name, "printf"); hit != "" {
			return hit
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
// non-"-" operand is the action. R16-Oracle-M2: the action re-parses in the
// SAME interpreter as the enclosing script, so seg carries the enclosing
// dialect — a bash payload's trap action faces the bash brace-expansion
// rules, never the dash POSIX default.
func screenTrapArgs(args []string, kind byte, depth int, caller callerIdentity, seg shellSegment) string {
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
			return guardShellSubagentDepthDialect(a, depth, caller, seg.bashDialect)
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

// xargsValueLongs are GNU xargs long options that consume a value operand
// (separate argv, or glued with =). The table feeds GNU unique-prefix
// resolution in xargsMatchValueLong (v6.2.2 R3 R2-SF-3): findutils xargs
// longopts are arg-file(-a), delimiter(-d), eof, replace(-i/-I), verbose,
// interactive, no-run-if-empty, max-lines(-L/-l), max-args(-n), max-chars(-s),
// max-procs(-P), process-slot-var, show-limits, exit, null, open-tty,
// version, help. --eof and --replace take OPTIONAL glued-only values and
// never consume a separate argv, so they stay OUT of this table.
var xargsValueLongs = []string{
	"arg-file", "delimiter", "max-args", "max-lines", "max-procs",
	"max-chars", "process-slot-var",
}

// xargsMatchValueLong resolves one long-option name against xargs'
// separate-value long options with GNU unique-prefix abbreviation
// (--max-a -> max-args, --arg-f -> arg-file). The empty string means no
// value option matched (boolean, optional-value or ambiguous prefix).
func xargsMatchValueLong(name string) string {
	if name == "" {
		return ""
	}
	match := ""
	hits := 0
	for _, c := range xargsValueLongs {
		if c == name {
			return c
		}
		if strings.HasPrefix(c, name) {
			hits++
			match = c
		}
	}
	if hits == 1 {
		return match
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

// xargsLongConsumesNext reports whether one `--` word of xargs' option zone
// consumes the NEXT argv as its value: exact or GNU-abbreviated value long
// options without a glued =value (v6.2.2 R3 R2-SF-3).
func xargsLongConsumesNext(a string) bool {
	if !strings.HasPrefix(a, "--") {
		return false
	}
	name := a[2:]
	if strings.IndexByte(name, '=') >= 0 {
		return false // glued value never consumes the next argv
	}
	if xargsLongWithValue[a] {
		return true
	}
	return xargsMatchValueLong(name) != ""
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
			ni, at := xargsLongTargetStep(argv, i)
			if at >= 0 {
				return at
			}
			i = ni
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			consumedNext := xargsClusterConsumesNext(a)
			if consumedNext && i+1 < len(argv) && isDynamicArg(argv[i+1]) && !isSingleWordSplitSafe(argv[i+1]) {
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

// xargsLongTargetStep advances xargsTargetIndex past one `--` word: next is
// the index to continue from, at is the command-index answer when a dynamic
// value operand decides it (-1 while the scan continues).
func xargsLongTargetStep(argv []string, i int) (next, at int) {
	a := argv[i]
	if strings.IndexByte(a, '=') > 0 {
		return i + 1, -1
	}
	if xargsLongConsumesNext(a) {
		if i+1 < len(argv) && isDynamicArg(argv[i+1]) && !isSingleWordSplitSafe(argv[i+1]) {
			return i, i + 1
		}
		return i + 2, -1
	}
	return i + 1, -1
}

// xargsClusterConsumesNext reports whether xargs' short cluster word a
// ends in a value letter whose operand is the NEXT argv word.
func xargsClusterConsumesNext(a string) bool {
	for j := 1; j < len(a); j++ {
		if a[j] == 'e' || a[j] == 'i' {
			return false
		}
		if xargsShortWithValue[a[j]] {
			return j+1 >= len(a)
		}
	}
	return false
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
			tok, hasTok, consumed := xargsReplLongToken(a)
			if hasTok {
				repl = tok
			}
			i += consumed
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			if tok, consumed := xargsReplClusterToken(argv, i); tok != "" || consumed {
				if tok != "" {
					repl = tok
				}
				if consumed {
					i++
				}
				continue
			}
			continue
		}
		break // first non-option operand is the command
	}
	return repl
}

// xargsReplLongToken handles one `--` word in xargsReplToken's scan
// (extracted so the scan loop stays reviewable — v6.2.2 R3): tok/hasTok
// carry a replacement token the word names, consumed counts EXTRA argv
// operands the word eats as a value option. GNU `--replace=` with an
// empty value still defaults to "{}" (v6.2.2 R3 R2-SF-3), bare
// --replace abbreviations default to "{}" without consuming the next
// argv, and GNU-abbreviated value long options consume one operand.
func xargsReplLongToken(a string) (tok string, hasTok bool, consumed int) {
	if j := strings.IndexByte(a, '='); j > 0 {
		if xargsIsReplaceLong(a[:j]) {
			if a[j+1:] == "" {
				return "{}", true, 0 // GNU --replace= (empty) still defaults to {}
			}
			return a[j+1:], true, 0
		}
		return "", false, 0
	}
	if xargsIsReplaceLong(a) {
		return "{}", true, 0 // GNU: bare --replace == -I{}
	}
	if xargsLongConsumesNext(a) {
		return "", false, 1
	}
	return "", false, 0
}

// xargsReplClusterToken scans one short-option cluster word of xargs'
// option zone for the replace-token letters i/I. tok is "" when the
// cluster named no token (or -i/-I defaulted, reported as "{}" by the
// caller contract — see below); consumed reports the cluster ate the next
// argv as a value operand. A bare -i defaults to "{}" directly in tok.
func xargsReplClusterToken(argv []string, i int) (tok string, consumed bool) {
	a := argv[i]
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if ch == 'e' {
			break // -e's tail is its optional operand
		}
		if ch == 'i' {
			// Deprecated -I: bare -i defaults to "{}"; -iSTR glued.
			if tail := a[j+1:]; tail != "" {
				return tail, false
			}
			return "{}", false
		}
		if ch == 'I' {
			if tail := a[j+1:]; tail != "" {
				return tail, false
			}
			if i+1 < len(argv) {
				return argv[i+1], true
			}
			return "", false
		}
		if xargsShortWithValue[ch] {
			return "", j+1 >= len(a)
		}
	}
	return "", false
}

// xargsSSHAppendFeedsRemoteShell reports whether xargs-appended words
// landing after an ssh invocation's argv reach a remote shell-text join
// position: OpenSSH concatenates every remote-command word into the
// `$SHELL -c` string, so a remote command like `echo hi` receives the
// appended words as shell text (`echo hi ; pig`). When the remote command
// is itself a stdin-program consumer (`xargs ssh dmit sh`), the precise
// sshTunnelsStdinProgram modelling downstream owns the verdict and this
// screen stays silent so the exact rule is not preempted (v6.2.2 MF-8).
func xargsSSHAppendFeedsRemoteShell(h []string) bool {
	remoteCmd, hit := parseSSHInvocation(h)
	if hit != "" {
		return true
	}
	if strings.TrimSpace(remoteCmd) == "" {
		return true // empty remote command was already fail-closed upstream
	}
	if sshTunnelsStdinProgram(h, os.Getenv("PATH"), callerIdentity{}) {
		return false
	}
	return true
}

// xargsIsReplaceLong reports whether a long-option word names xargs'
// --replace: GNU findutils xargs has no other `--r*` long option, so every
// unambiguous prefix abbreviation (--repl/--rep/--re/--r) is the same
// binding (v6.2.2 SF-3).
func xargsIsReplaceLong(a string) bool {
	if !strings.HasPrefix(a, "--r") {
		return false
	}
	return strings.HasPrefix("--replace", a)
}

// screenFindArgsSeg scans find's operand list with explicit stdin context
// modelling (2.c): -exec/-execdir redirect child stdin to /dev/null
// (empty shellSegment), whereas -ok/-okdir share find's own stdin stream
// (outerSeg). Placeholders "{}" in command-head or inline-code slots fail
// closed while data-operand "{}" (`grep foo {}`, `sh -c 'echo "$1"' _ {}`)
// stay open.
func screenFindArgsSeg(args []string, outerSeg shellSegment, kind byte, depth int, caller callerIdentity) string {
	expectValue := false
	skipNextAlso := false // -fprintf consumed TWO operands: this slot is its FORMAT
	pathDone := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if skipNextAlso {
			skipNextAlso = false
			if hit := findValueSlotHit(a); hit != "" {
				return hit
			}
			continue
		}
		if expectValue {
			expectValue = false
			if hit := findValueSlotHit(a); hit != "" {
				return hit
			}
			continue
		}
		if kind == 'r' && (a == "-delete" || a == "-fprint" || a == "-fprint0" || a == "-fprintf" || a == "-fls") {
			return "find " + a
		}
		if isDynamicArg(a) {
			if !pathDone && isSafeDynamicDataOperand(a) {
				continue
			}
			return "find dynamic predicate"
		}
		if a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
			j := findExecEnd(args, i)

			if hit := screenFindExecInner(args, i, j, a, outerSeg, kind, depth, caller); hit != "" {
				return hit
			}
			i = j
			pathDone = true
			continue
		}
		if isFindValueOpt(a) {
			pathDone = true
			expectValue = true
			if a == "-fprintf" {
				skipNextAlso = true // FILE FORMAT — two operands (v6.2.2 MF-7)
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			pathDone = true
		}
	}
	return ""
}

// findValueSlotHit vets one operand CONSUMED by a find value predicate
// (-name/-path/-fprintf FILE+FORMAT/...): an unquoted $VAR field-splits at
// runtime and can inject extra predicates (-exec pig) past the statically
// expected operand count, and a multi-match glob both overflows its slot
// and shifts the allocation of every later operand (the -fprintf FILE+
// FORMAT pair swallowing a static -exec word — v6.2.2 Oracle R10 R10-MF-2).
func findValueSlotHit(a string) string {
	if isDynamicArg(a) && !isSingleWordSplitSafe(a) {
		return "find dynamic predicate"
	}
	return ""
}

// findExecEnd returns the index of the ';'/'+' terminator closing the
// -exec-family operator opened at args[i] (len(args) when unterminated).
func findExecEnd(args []string, i int) int {
	j := i + 1
	for j < len(args) && args[j] != ";" && args[j] != "+" {
		j++
	}
	return j
}

// screenFindExecInner screens the command argv of one find -exec/-execdir/
// -ok/-okdir operator: the replace-token exec-slot scan, the nested
// hc/herdr-core and ctxmode-self heads, and the full segment peel of the
// inner argv (extracted from screenFindArgsSeg so the predicate walk stays
// reviewable — v6.2.2 Oracle R1). Returns "" when the inner argv is clean
// or empty.
func screenFindExecInner(args []string, i, j int, op string, outerSeg shellSegment, kind byte, depth int, caller callerIdentity) string {
	if j <= i+1 {
		return ""
	}
	inner := args[i+1 : j]
	if replTokenInExecSlotFind(inner, "{}", caller.pathEnv, caller) {
		return "find " + op + " dynamic code payload"
	}
	// Nested hc/herdr-core via find -exec* / -ok* receives path args
	// at runtime ({} replacement / + batching). Block unconditionally.
	th, tea, teffP, tex := peelWrappersAndWrapperAliases(inner, caller.pathEnv, caller)
	if tex {
		return "find " + op + " " + depthExceededHit
	}
	// Same env -C re-anchor as the xargs branch: the peeled ops
	// seed the caller before alias/self-exe resolution (R4 MF-2).
	tCaller := caller.seededWith(tea)
	for _, b := range headBaseAliasHits(th, teffP, tCaller) {
		if b == "hc" || b == "herdr-core" {
			return "find " + op + " " + b
		}
	}
	if len(th) > 0 && headIsCtxmodeOrSelfExe(th[0], teffP, tCaller.screenCwd()) {
		return "find " + op + " ctxmode --hc-gate"
	}
	innerSeg := shellSegment{}
	if op == "-ok" || op == "-okdir" {
		// -ok/-okdir share find's own stdin stream: inherit ONLY
		// the outer stdin facts, never the outer words.
		innerSeg = stdinOnlySeg(outerSeg)
	}
	if hit := peelResolvedSegDepth(inner, innerSeg, kind, depth, caller); hit != "" {
		if hit == roSSHWriteHit {
			return roSSHWriteHit
		}
		return "find " + op + " " + hit
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
// the same verdict. bash (variadic, default false) is the consuming shell's
// dialect (R17-Oracle-M2): a local bash reading its program from stdin
// brace-expands exactly like `bash -c`, so the dash default re-parse must
// not stand in for it.
func screenStdinProgram(text, lang string, kind byte, depth int, caller callerIdentity, bash bool) string {
	if lang == "" {
		if kind == 's' {
			return guardShellSubagentDepthDialect(text, depth+1, caller, bash)
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
// runEnv (variadic, default empty) carries the accumulated pure-assignment
// environment of the segments preceding this one in the same command list
// (R20-Oracle-M4): the stdin/here-string program projection must resolve
// under the shell state the consumer actually inherits.
func screenOneSegmentDepth(seg shellSegment, kind byte, depth int, caller callerIdentity, runEnvOpt ...envAssignments) string {
	runEnv := envAssignments{}
	if len(runEnvOpt) > 0 {
		runEnv = runEnvOpt[0]
	}
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
		if lang, isProg, _, _ := stdinProgramHeadWithEnv(seg.argv, 0, runEnv, caller.pathEnv, caller); isProg {
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
		// R17-Oracle-M2: the bash dialect of the consuming shell rides
		// the projection into the screen — the dash default must not
		// re-parse a bash-consumed program.
		// R18-Oracle-M2: EVERY program target is screened — a mutual-
		// exclusion branch pair (`if …; then dash; else bash; fi`) may
		// consume the same stream through either of two shells, so
		// projecting only the first target both missed the bash dialect
		// and made the verdict depend on the branch ORDER; any single
		// target's rejection rejects the payload, matching the per-target
		// API stdin screen exactly.
		targets := stdinProgramTargetsWithEnv(seg.argv, 0, runEnv, caller.pathEnv, caller)
		if hit := screenHereStringTargetsDepth(seg.hereString, targets, kind, depth, caller); hit != "" {
			return hit
		}
	}
	return peelResolvedSegDepth(seg.argv, seg, kind, depth, caller)
}

// screenHereStringTargetsDepth screens one here-string payload against
// EVERY program target of the consuming argv (extracted for the v6.2.2
// R18 complexity budget — R18-Oracle-M2): data consumers are byte sinks
// and never programs, and each real consumer is judged under its own env
// ops and dialect. The first rejection wins, which — because rejection
// never depends on position — makes `[dash, bash]` and `[bash, dash]`
// agree exactly.
func screenHereStringTargetsDepth(text string, targets []stdinTarget, kind byte, depth int, caller callerIdentity) string {
	for _, t := range targets {
		if t.data {
			continue
		}
		// R21-Oracle-M5/R21-Reviewer-4: an exhausted target is not a
		// known POSIX shell — the projection gave up before identifying
		// the consumer, so the payload faces an explicit depth block
		// instead of a dash-shaped re-parse of bytes that may belong to
		// an entirely different interpreter.
		if t.exhausted {
			return depthExceededHit
		}
		if hit := screenStdinProgram(text, t.lang, kind, depth, caller.seededWith(t.envAs), t.bash); hit != "" {
			return hit
		}
	}
	return ""
}

// screenSegmentHeredocsDepth screens the heredoc bodies of one segment.
// runEnv (variadic, default empty) carries the accumulated pure-assignment
// environment of the preceding segments in the same command list
// (R20-Oracle-M4), exactly like screenOneSegmentDepth.
func screenSegmentHeredocsDepth(seg shellSegment, kind byte, depth int, caller callerIdentity, runEnvOpt ...envAssignments) string {
	if len(seg.heredocText) == 0 {
		return ""
	}
	runEnv := envAssignments{}
	if len(runEnvOpt) > 0 {
		runEnv = runEnvOpt[0]
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
	// When the heredoc tunnels through ssh (directly or behind wrappers like
	// flock) to a remote stdin-program head, a read-only caller (verifier /
	// CTXMODE_READONLY=1) loses its local /tmp write exemption at the wire.
	bodyKind := kind
	if kind == 's' && callerReadonlyRole(caller) && sshTunnel {
		bodyKind = 'r'
	}
	// R18-Oracle-M2: EVERY program target is screened per body — projecting
	// only the first one missed a second possible consuming shell (and its
	// bash dialect) and made the verdict depend on the branch order of a
	// mutually exclusive `if …; then dash; else bash; fi` pair. Any single
	// target's rejection rejects the payload, matching the per-target API
	// stdin screen exactly. Data consumers are byte sinks, never programs.
	targets := stdinProgramTargetsWithEnv(seg.argv, 0, runEnv, caller.pathEnv, caller)
	// R19-Oracle-S1: the code-payload screens apply ONLY when at least one
	// non-data PROGRAM consumer exists — a heredoc feeding a pure data
	// consumer (cat, jq .) is ordinary input whose parameter expansions
	// ($HOME inside the body text) are just bytes; the parent behaviour
	// returned before judging payload dynamics in exactly this case, and
	// any substitutions inside the body are already emitted as nested
	// segments by the collector itself.
	progTargets := stdinProgramNonDataTargets(targets)
	if len(progTargets) == 0 {
		return ""
	}
	for _, hb := range seg.heredocText {
		if hb.dynamic || isDynamicArg(hb.text) {
			return "dynamic code payload"
		}
		if hit := screenHeredocBodyTargetsDepth(hb.text, progTargets, bodyKind, depth, caller); hit != "" {
			return sshHeredocVerdict(hit, sshTunnel, kind, bodyKind, caller)
		}
	}
	return ""
}

// stdinProgramNonDataTargets filters a stdin target list down to the real
// PROGRAM consumers (extracted for the v6.2.2 R19 complexity budget —
// R19-Oracle-S1): data consumers are byte sinks, never programs, and an
// all-data list carries no code payload to screen at all.
func stdinProgramNonDataTargets(targets []stdinTarget) []stdinTarget {
	var out []stdinTarget
	for _, t := range targets {
		if !t.data {
			out = append(out, t)
		}
	}
	return out
}

// sshHeredocVerdict maps a heredoc body screening hit onto the ssh-tunnel
// read-only verdict exactly like the former inline mapping (extracted for
// the v6.2.2 R19 complexity budget — R19-Oracle-S1).
func sshHeredocVerdict(hit string, sshTunnel bool, kind, bodyKind byte, caller callerIdentity) string {
	if sshTunnel && (kind == 'r' || callerReadonlyRole(caller)) && bodyKind == 'r' {
		return roSSHWriteHit
	}
	return hit
}

// screenHeredocBodyTargetsDepth screens one heredoc body against EVERY
// program target of the consuming argv (extracted for the v6.2.2 R18
// complexity budget — R18-Oracle-M2): each real consumer is judged under
// its own env ops and dialect, and the first rejection wins — because
// rejection never depends on position, `[dash, bash]` and `[bash, dash]`
// agree exactly, and the verdict aligns with the per-target API stdin
// screen (R17-Oracle-M6 data consumers are byte sinks, never programs).
func screenHeredocBodyTargetsDepth(text string, targets []stdinTarget, bodyKind byte, depth int, caller callerIdentity) string {
	for _, t := range targets {
		if t.data {
			continue
		}
		// R21-Oracle-M5/R21-Reviewer-4: an exhausted target is an
		// UNIDENTIFIED consumer, never a confirmed POSIX shell — the
		// heredoc body faces an explicit depth block rather than a
		// dash-default re-parse.
		if t.exhausted {
			return depthExceededHit
		}
		// R17-Oracle-M2: the heredoc re-parse inherits the consuming
		// shell's dialect — a local bash heredoc brace-expands exactly
		// like `bash -c`.
		if hit := screenStdinProgram(text, t.lang, bodyKind, depth, caller.seededWith(t.envAs), t.bash); hit != "" {
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

// guardShellSubagentDepthDialect is the dialect-selected re-entry used by
// same-process re-parses (eval operand, trap action): bash=true picks the
// bash-family parser exactly like guardShellSubagentDepthBash, false keeps
// the dash POSIX default (v6.2.2 Oracle R16 M2).
func guardShellSubagentDepthDialect(code string, depth int, caller callerIdentity, bash bool) string {
	if bash {
		return guardShellSubagentDepthBash(code, depth, caller)
	}
	return guardShellSubagentDepth(code, depth, caller)
}

func guardShellSubagentDepthSegs(segs []shellSegment, depth int, caller callerIdentity) string {
	if depth >= peelChainMaxDepth {
		return depthExceededHit
	}
	// R20-Oracle-M4: the local heredoc/here-string/pipe stdin screens
	// must face the SAME environment accumulation the flat prepare scan
	// builds — a pure-assignment segment re-binds the exported variables
	// every later child inherits, so a heredoc payload parsed under a
	// per-segment empty environment would be judged against a shell
	// state the consumer does not run with.
	// R21-Oracle-M3: the accumulation is scope-aware — each segment's
	// heredoc/here-string/pipe projection resolves under the view of ITS
	// OWN scope path, and conditional writes surface as uncertainty
	// markers (pollution) instead of exact overrides.
	tracker := &scopeEnvTracker{}
	for _, seg := range segs {
		tracker.foldSegment(seg, caller)
		if seg.parseErr != "" {
			return seg.parseErr
		}
		if seg.depthExceeded {
			return depthExceededHit
		}
		runEnv := consumerViewEnv(tracker, seg)
		if hit := screenSegmentHeredocsDepth(seg, 's', depth, caller, runEnv); hit != "" {
			return hit
		}
		if hit := screenOneSegmentDepth(seg, 's', depth, caller, runEnv); hit != "" {
			return hit
		}
	}
	return ""
}

// consumerViewEnv materializes the scope environment view ONLY for a
// segment that can consume stdin (R22-Reviewer-#7 / R22-Oracle-SF2): a
// heredoc/here-string/pipe-fed consumer or a command head the stream
// may reach. A run of consecutive pure assignments folds its ops and
// copies NOTHING — the pre-R22 loops paid a full prefix copy per
// segment whether or not any consumer existed — while the head
// screening itself NEVER skips (the screens vet every command
// regardless of stdin), and the AST's own assignment verdict decides
// the view need without any per-segment wrapper peel.
func consumerViewEnv(tracker *scopeEnvTracker, seg shellSegment) envAssignments {
	if len(seg.heredocText) > 0 || seg.hereString != "" || seg.pipedStdin || !seg.pureAssign {
		return tracker.view(seg.scopePath)
	}
	return envAssignments{}
}

// ---------- rule 2: read-only write guard ----------

// fsWriteHeads are command heads that unconditionally write, remove, create or
// move filesystem objects (or, for the lock/pty/shell runners at the end,
// always escape the read-only write fence).
