package main

// shell_screen.go — graded, advisory pre-execution screen for ctx_run input
// (shell command strings and argv mode). Pure standard library.
//
// Two verdict classes:
//   - Block (shellBlock): NUL byte, or a command longer than 64 KiB. These abort
//     execution. The empty string is NOT blocked here — main.go's existing
//     "command is required" error already covers it. For argv mode only the NUL
//     rule can block (see screenArgv): an over-length argv is warn-only.
//   - Warn (shellWarn): a small set of heuristic patterns (encoded/downloaded
//     payload piped into a shell, or a redirect into /etc//dev/sd*), plus the
//     over-length argv shape. These are logged at the caller sites and the
//     command runs anyway. The screen is defense-in-depth logging, never a
//     policy or a security boundary.

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

// shellVerdict is the outcome of screenShellCommand / screenArgv.
type shellVerdict int

const (
	shellOK shellVerdict = iota
	shellWarn
	shellBlock
)

// String renders the verdict for the audit record (screen_verdict).
func (v shellVerdict) String() string {
	switch v {
	case shellOK:
		return "ok"
	case shellWarn:
		return "warn"
	case shellBlock:
		return "block"
	default:
		return "unknown"
	}
}

// maxShellCommandBytes caps the length of a command-form shell string. The
// block threshold is strictly greater than this value, so a command of exactly
// this length is allowed.
const maxShellCommandBytes = 64 * 1024

// Rule names, shared by the screen, the callers and the audit record so the
// strings in logs and audit lines cannot drift from the matchers.
const (
	shellRuleNulByte   = "nul_byte"
	shellRuleOversized = "oversized"
)

// shellWarnPattern is a single advisory rule: a compiled matcher plus a stable
// name used in the log line (the command text itself is never logged in full).
type shellWarnPattern struct {
	name string
	re   *regexp.Regexp
}

// shellWarnPatterns holds every heuristic matcher. Package-level
// *regexp.MustCompile; keep the count small (current: 3). Each pattern must have
// a matching "must-pass" negation test in shell_screen_test.go.
var shellWarnPatterns = []shellWarnPattern{
	// base64 -d / --decode whose output is piped into a shell within a short
	// window (obfuscation-then-execute). Only the immediate pipe-to-shell is
	// flagged; a plain `base64 file` or `base64 -d f > out` is fine.
	{
		name: "base64_pipe_to_shell",
		re:   regexp.MustCompile(`(?i)base64\s+(?:-d|--decode)[^|\n]{0,120}\|\s*(?:sh|bash|dash|zsh|ksh)\b`),
	},
	// curl / wget whose downloaded body is piped into a shell within a short
	// window (remote-command-execution idiom).
	{
		name: "download_pipe_to_shell",
		re:   regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|\n]{0,120}\|\s*(?:sh|bash|dash)\b`),
	},
	// Redirect (truncating or appending) into /etc/ or a raw block device
	// /dev/sd[a-z].
	{
		name: "redirect_into_sensitive_path",
		re:   regexp.MustCompile(`(?:>>?)\s*(?:/etc/|/dev/sd[a-z]\b)`),
	},
}

// screenShellBlock performs the block-level checks only: NUL byte or a command
// longer than maxShellCommandBytes. It is called on its own from runShellOpts so
// the length/NUL block covers BOTH execute and execute_file without applying the
// warn-level pattern scan to whole-file FILE_CONTENT scripts.
func screenShellBlock(code string) (shellVerdict, string) {
	if strings.ContainsRune(code, 0) {
		return shellBlock, shellRuleNulByte
	}
	if len(code) > maxShellCommandBytes {
		return shellBlock, shellRuleOversized
	}
	return shellOK, ""
}

// screenShellCommand grades a command-form shell string. It applies the
// block-level checks first (NUL / oversize), then the warn-level heuristic
// patterns, and returns shellOK when neither fires. The returned string is the
// matched rule name ("" for shellOK); the command text is never part of it.
func screenShellCommand(code string) (shellVerdict, string) {
	if verdict, rule := screenShellBlock(code); verdict == shellBlock {
		return shellBlock, rule
	}
	for _, p := range shellWarnPatterns {
		if p.re.MatchString(code) {
			return shellWarn, p.name
		}
	}
	return shellOK, ""
}

// screenArgv grades an argv-mode command (ctx_run action=execute argv). argv is
// never handed to a shell, so the shell-length rule cannot apply as-is; the
// rules are restricted to what is unconditionally broken or worth logging:
//
//   - a NUL byte in any argument is a hard block. execve(2) rejects an argument
//     containing a NUL byte with EINVAL, so the spawn can never succeed; the
//     caller gets "argv command blocked (nul_byte)" instead of a confusing
//     start failure.
//   - joined argument bytes longer than maxShellCommandBytes byte is a WARN
//     only, never a block: argv is not a shell string, large build/codegen
//     arguments are legitimate, and processes accept them up to
//     MAX_ARG_STRLEN (128 KiB per single argument). Blocking here would kill
//     real builds, which is exactly what the argv escape hatch exists to avoid.
//   - the shellWarnPatterns heuristics are matched against the space-joined
//     argv string so shapes like `sh -c 'curl ... | sh'` are still logged for
//     the audit trail. A warn hit is logged and passed to the audit record; it
//     never changes the exit status of the call.
//
// The returned rule name is "" for shellOK. Like screenShellCommand this is
// defense-in-depth logging, never a policy or a security boundary.
func screenArgv(argv []string) (shellVerdict, string) {
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return shellBlock, shellRuleNulByte
		}
	}
	joined := strings.Join(argv, " ")
	if len(joined) > maxShellCommandBytes {
		return shellWarn, shellRuleOversized
	}
	for _, p := range shellWarnPatterns {
		if p.re.MatchString(joined) {
			return shellWarn, p.name
		}
	}
	return shellOK, ""
}

// applyArgvScreen grades argv, logs a warn hit, and turns the hard block into a
// caller-facing error. Both argv entry points (ctx_run action=execute and
// run_task) go through it so their behaviour cannot drift apart: an argv NUL
// byte is refused with the same message in both.
func applyArgvScreen(argv []string, rawCmd string) (verdict shellVerdict, rule string, err error) {
	verdict, rule = screenArgv(argv)
	switch verdict {
	case shellBlock:
		return verdict, rule, fmt.Errorf("argv command blocked (%s)", rule)
	case shellWarn:
		if rule == shellRuleOversized {
			// The "command" here is a legitimate large argument list; copying its
			// head into the system log is noise, not evidence.
			logShellScreenNoHead(rule, rawCmd)
		} else {
			logShellScreen(rule, rawCmd)
		}
	}
	return verdict, rule, nil
}

// logShellScreen emits a warn-line for a shellWarn hit. It logs ONLY the rule
// name, the full command length, and the first 80 bytes of the command (quoted);
// the full command text is never logged.
func logShellScreen(rule, code string) {
	const head = 80
	snippet := code
	if len(snippet) > head {
		snippet = snippet[:head]
	}
	log.Printf("ctxmode: shell screen warning rule=%s len=%d head=%q", rule, len(code), snippet)
}

// logShellScreenNoHead emits the same warn-line without any of the command text.
// It is used for the argv oversize rule, where the text is a large but
// legitimate argument list whose first bytes carry no signal.
func logShellScreenNoHead(rule, code string) {
	log.Printf("ctxmode: shell screen warning rule=%s len=%d", rule, len(code))
}
