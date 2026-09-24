package main

// shell_screen.go — graded, advisory pre-execution screen for command-form
// shell input (ctx_run execute/batch command strings). Pure standard library.
//
// Two verdict classes:
//   - Block (shellBlock): NUL byte or command longer than 64 KiB. These abort
//     execution. The empty string is NOT blocked here — main.go's existing
//     "command is required" error already covers it.
//   - Warn (shellWarn): a small set of heuristic patterns (encoded/downloaded
//     payload piped into a shell, or a redirect into /etc//dev/sd*). These are
//     logged at the two caller sites and the command runs anyway. The screen is
//     defense-in-depth logging, never a policy or a security boundary.

import (
	"log"
	"regexp"
	"strings"
)

// shellVerdict is the outcome of screenShellCommand.
type shellVerdict int

const (
	shellOK shellVerdict = iota
	shellWarn
	shellBlock
)

// maxShellCommandBytes caps the length of a command-form shell string. The
// block threshold is strictly greater than this value, so a command of exactly
// this length is allowed.
const maxShellCommandBytes = 64 * 1024

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
		return shellBlock, "nul_byte"
	}
	if len(code) > maxShellCommandBytes {
		return shellBlock, "oversized"
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
