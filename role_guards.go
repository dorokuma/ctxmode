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
//     leaving herdr/herdsman read-only queries alone.
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
	"strings"
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
	text   string
	quoted bool
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
	// hereString is the `<<< word` payload this command consumed: the bytes
	// it reads on stdin. Like heredoc bodies it is screened as code when the
	// head is a shell/interpreter reading its program from stdin, and its
	// $(...)/`...` substitutions are scanned because the shell expands them
	// unless the word was single-quoted.
	hereString string
	// depthExceeded marks a synthetic segment emitted when $(...)/`...`/(...)
	// nesting exceeds shellSplitMaxDepth: the inner commands could not be
	// parsed, so the guards must fail closed instead of silently dropping
	// them. It is never a real command.
	depthExceeded bool
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
// unreadable statically. It is never a real path, and redirectBlocksWrite
// treats it as blocking so `echo hi > $(printf /tmp/x)` cannot slip through.
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

// heredocSpec is a queued `<<DELIM` (or `<<-DELIM`) awaiting body consumption
// at the next newline. quoted reports whether the terminator word carried
// quotes (<<'EOF'), which suppresses expansion inside the body. stripTabs
// records the `<<-` form: the terminator line may be indented with tabs.
// ownerIdx/pending tie the body to the segment that DECLARED the `<<`: in
// `sh <<EOF | cat` the body belongs to the sh segment even though the cat
// segment is the last one flushed before the newline.
type heredocSpec struct {
	delim     string
	quoted    bool
	stripTabs bool
	ownerIdx  int  // index into segs once the declaring segment was flushed
	pending   bool // owner not yet known (declaring segment not flushed yet)
}

// shellWordBreakBytes are the bytes after which a `#` starts a comment: POSIX
// treats `#` as a comment only at the start of a word, i.e. at the beginning
// of input or after whitespace or a metacharacter. `echo foo#bar` keeps the
// `#` inside the word.
const shellWordBreakBytes = " \t\r\n;|&()<>"

func isShellWordBreak(c byte) bool {
	return strings.IndexByte(shellWordBreakBytes, c) >= 0
}

// skipToLineEnd returns the index of the '\n' at or after i (len(code) when
// the last line has no newline): where a `#` comment stops.
func skipToLineEnd(code string, i int) int {
	for i < len(code) && code[i] != '\n' {
		i++
	}
	return i
}

// sliceTo clamps [lo,hi) to s so a scanner that stopped past the end of the
// input on an unterminated quote/backtick can never panic the caller.
func sliceTo(s string, lo, hi int) string {
	if lo < 0 {
		lo = 0
	}
	if lo > len(s) {
		return ""
	}
	if hi > len(s) {
		hi = len(s)
	}
	if hi < lo {
		hi = lo
	}
	return s[lo:hi]
}

// splitShellSegments splits shell command text into simple commands at every
// unquoted separator: ; | && || & newline, subshells (...), and command
// substitutions $(...) / `...`. Quotes and backslash escapes are folded away
// inside words; single-quoted text is literal, double-quoted text folds \$ \"
// \\ \` and keeps embedded $(...) literal-but-scanned.
//
// Special handling beyond separators:
//   - `[[ ... ]]`: between `[[` and the matching `]]`, unquoted < and > are
//     string-comparison operators, not redirections, and are not recorded.
//   - `(( ... ))` / `$(( ... ))`: comparison operators inside balanced
//     arithmetic parens are skipped likewise.
//   - `<<` / `<<-` heredocs: the body lines after the next newline are
//     consumed up to a lone terminator line so `rm = 1` inside a heredoc is
//     never mistaken for a command, and are attached to the owning segment so
//     the guards can screen them as shell/interpreter code.
//
// Design note (why not a regex): the guard must only see command heads. A
// `pig` inside 'pig', "pig", $(pig) output text, a heredoc body, or a
// redirection target is not a command name, and a ; inside quotes is not a
// separator — all of which a substring/regex matcher gets wrong in at least
// one direction. This parser trades completeness on pathological inputs for
// exactness on the separations that matter; anything it cannot decompose is
// screened as one opaque segment.
func splitShellSegments(code string) []shellSegment {
	segs, _ := splitShellSegmentsDepth(code, 0, false)
	return segs
}

// splitShellSegmentsDepth is the recursive worker; depth counts nesting into
// $(...)/`...`/(...). pipeIn reports whether the outer context feeds this
// text's first command through a pipeline (a subshell or substitution inside
// a pipe-fed command inherits the pipe). The bool result reports whether
// parsing stayed balanced (kept for future callers; the current guards
// ignore it and screen what was parsed, which is the conservative
// direction).
func splitShellSegmentsDepth(code string, depth int, pipeIn bool) ([]shellSegment, bool) {
	var segs []shellSegment
	var cur shellSegment
	// curExtra stages substitution segments parsed inside the CURRENT word
	// context (word-position $(...)/`...` and the small-slice scans for
	// arithmetic groups, redirect targets and heredoc bodies). Flushing them
	// straight into segs would tear the segment under construction apart
	// mid-word; instead they ride along and flush with cur in flushSeg.
	var curExtra []shellSegment
	var word strings.Builder
	wordStarted := false
	var heredocs []heredocSpec // pending terminators, consumed on the next '\n'
	condDepth := 0             // inside [[ ... ]] nesting (bash conditionals)
	segPipeIn := pipeIn        // the next segment receives its stdin from a pipe

	// assignPendingOwners binds still-pending heredoc specs to the segment
	// just appended to segs (the one that declared them).
	assignPendingOwners := func() {
		if len(segs) == 0 {
			return
		}
		for k := range heredocs {
			if heredocs[k].pending {
				heredocs[k].ownerIdx = len(segs) - 1
				heredocs[k].pending = false
			}
		}
	}

	flushWord := func() {
		if wordStarted {
			cur.argv = append(cur.argv, word.String())
			word.Reset()
			wordStarted = false
		}
	}
	flushSeg := func() {
		flushWord()
		// Staged substitution segments always flush BEFORE cur so the
		// $(...)'s inner commands land ahead of the command that expands
		// them — and they flush even when cur itself is empty (a segment
		// consisting of only `$(rm -f x)` still screens the substitution).
		if len(curExtra) > 0 {
			segs = append(segs, curExtra...)
			curExtra = nil
		}
		if len(cur.argv) > 0 || cur.redirectFile != "" {
			cur.pipedStdin = segPipeIn
			segs = append(segs, cur)
			assignPendingOwners()
		}
		cur = shellSegment{}
	}
	// scanInner parses a word-position command substitution ($(...)/`...`):
	// the inner commands are parsed recursively into curExtra and a
	// placeholder is written into the current word so the outer argv stays
	// whole. At the depth cap a fail-closed marker is staged instead of
	// silently dropping the inner commands.
	scanInner := func(inner string) {
		if depth >= shellSplitMaxDepth {
			curExtra = append(curExtra, shellSegment{depthExceeded: true})
		} else {
			sub, _ := splitShellSegmentsDepth(inner, depth+1, segPipeIn)
			curExtra = append(curExtra, sub...)
		}
		word.WriteString(cmdSubPlaceholder)
		wordStarted = true
	}
	// scanSubs scans a small slice (arithmetic group, redirect target word,
	// heredoc body) for $(...)/`...` substitutions and recursively screens
	// them. It only touches curExtra — never cur/word/wordStarted — so the
	// enclosing word is not torn apart.
	scanSubs := func(text string) {
		scanInlineSubstitutions(text, depth, &curExtra)
	}

	// skipWord consumes one word starting at i (quoting rules identical to the
	// main loop) and returns the index just after it. It is used for
	// redirection targets, which are never command names. The trailing
	// fd-redirect marker: digits immediately before the operator are part of
	// the operator, not the target, so 2>/dev/null still lands here with '>'.
	skipWord := func(i int) int {
		n := len(code)
		// A `#` at the START of this word opens a comment: the rest of the
		// line — including any unbalanced quote or backtick inside it — is
		// not part of the word.
		if i < n && code[i] == '#' {
			return skipToLineEnd(code, i)
		}
		for i < n && code[i] != ' ' && code[i] != '\t' && code[i] != '\n' && code[i] != '\r' {
			switch code[i] {
			case '\'':
				i++
				for i < len(code) && code[i] != '\'' {
					i++
				}
				if i < len(code) {
					i++
				}
			case '"':
				i++
				for i < len(code) && code[i] != '"' {
					if code[i] == '\\' && i+1 < len(code) {
						i++
					}
					i++
				}
				if i < len(code) {
					i++
				}
			case '\\':
				// A backslash escapes the next byte; a trailing one at end of
				// input has no operand and must stop here (echo > \ at EOF).
				if i+1 >= n {
					return n
				}
				i += 2
			case '$':
				if i+1 < len(code) && code[i+1] == '(' {
					i = skipBalanced(code, i+1, '(', ')')
				} else {
					i++
				}
			case '`':
				j := i + 1
				for j < len(code) && code[j] != '`' {
					j++
				}
				if j >= len(code) {
					// Unterminated backtick: the word runs to the end of the
					// input. Clamping to n is what keeps every caller's
					// code[i:next] slice in range (j+1 would be len+1).
					return n
				}
				i = j + 1
			case '(', ')', ';', '|', '&', '<', '>':
				return i
			default:
				i++
			}
		}
		return i
	}

	// readRedirectTarget reads the target word after a redirect operator at
	// index i and returns (target, indexAfterTarget). It uses the flattened
	// readShellWord so '>' "/tmp/x" yields /tmp/x.
	readRedirectTarget := func(i int) (string, int) {
		for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
			i++
		}
		if i >= len(code) {
			return "", i
		}
		return readShellWord(code, i), skipWord(i)
	}
	// readOutputRedirectTarget is readRedirectTarget for writing operators:
	// a dynamic target (command substitution or empty-after-scan) must block,
	// and inner $(...)/`...` text is scanned for nested commands.
	readOutputRedirectTarget := func(i int) (string, int) {
		for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
			i++
		}
		if i >= len(code) {
			return "", i
		}
		target := readShellWord(code, i)
		next := skipWord(i)
		scanSubs(sliceTo(code, i, next))
		if target == "" {
			return dynamicRedirectTarget, next
		}
		return target, next
	}

	i := 0
	for i < len(code) {
		c := code[i]
		// A `#` at the start of a word opens a comment that runs to the end of
		// the line. Skipping it here keeps an unbalanced quote/backtick or a
		// stray `<<` inside commentary from swallowing (or fabricating) real
		// commands on the following lines. `$#`, `foo#bar` and quoted `'#'`
		// never reach this branch: the `#` is then mid-word.
		if c == '#' && !wordStarted && (i == 0 || isShellWordBreak(code[i-1])) {
			i = skipToLineEnd(code, i)
			continue
		}
		switch c {
		case ' ', '\t', '\r':
			flushWord()
			i++
		case '\n':
			flushWord()
			flushSeg()
			segPipeIn = false
			i++
			// Consume each queued heredoc body; attach it to the segment that
			// DECLARED the redirection (ownerIdx), which is not necessarily
			// the last segment flushed before the newline — `sh <<EOF | cat`
			// binds its body to the sh segment, not to cat.
			for _, spec := range heredocs {
				bodyText, after := heredocBodyText(code, i, spec)
				owner := len(segs) - 1
				if !spec.pending {
					owner = spec.ownerIdx
				}
				if owner >= 0 && owner < len(segs) && bodyText != "" {
					segs[owner].heredocText = append(segs[owner].heredocText,
						heredocBody{text: bodyText, quoted: spec.quoted})
				}
				i = after
			}
			heredocs = nil
		case ';':
			flushWord()
			flushSeg()
			segPipeIn = false
			i++
		case '&':
			if i+1 < len(code) && code[i+1] == '>' {
				// &> or &>> redirect: consume, then read the target.
				j := i + 2
				if j < len(code) && code[j] == '>' {
					j++
				}
				flushWord()
				target, next := readOutputRedirectTarget(j)
				if cur.redirectFile == "" && redirectBlocksWrite("&>", target) {
					cur.redirectFile = target
				}
				i = next
				continue
			}
			flushWord()
			flushSeg()
			if i+1 < len(code) && code[i+1] == '&' {
				segPipeIn = false // &&: no pipe relationship
				i += 2
			} else {
				segPipeIn = false // & backgrounds: no pipe relationship
				i++
			}
		case '|':
			flushWord()
			flushSeg()
			if i+1 < len(code) && code[i+1] == '|' {
				segPipeIn = false // ||: no pipe relationship
				i += 2
			} else {
				segPipeIn = true // the next segment reads this one's stdout
				i++
			}
		case '\'':
			j := i + 1
			for j < len(code) && code[j] != '\'' {
				j++
			}
			word.WriteString(code[i+1 : j])
			wordStarted = true
			i = j
			if i < len(code) {
				i++
			}
		case '"':
			j := i + 1
			for j < len(code) && code[j] != '"' {
				if code[j] == '\\' && j+1 < len(code) {
					switch code[j+1] {
					case '"', '\\', '$', '`':
						word.WriteByte(code[j+1])
						j += 2
						continue
					case '\n':
						j += 2
						continue
					}
				}
				if code[j] == '$' && j+1 < len(code) && code[j+1] == '(' {
					if inner, ok := innerBalanced(code, j+1, '(', ')'); ok {
						scanInner(inner)
					}
					j = skipBalanced(code, j+1, '(', ')')
					continue
				}
				if code[j] == '`' {
					if k := strings.IndexByte(code[j+1:], '`'); k >= 0 {
						scanInner(code[j+1 : j+1+k])
						j += k + 2
						continue
					}
				}
				word.WriteByte(code[j])
				j++
			}
			wordStarted = true
			i = j
			if i < len(code) {
				i++
			}
		case '\\':
			if i+1 < len(code) {
				if code[i+1] != '\n' {
					word.WriteByte(code[i+1])
					wordStarted = true
				}
				i += 2
			} else {
				i++
			}
		case '$':
			if i+1 < len(code) && code[i+1] == '(' {
				if i+2 < len(code) && code[i+2] == '(' {
					// $(( ... )) arithmetic: comparisons inside are not
					// redirections; still scan nested substitutions. A '0'
					// placeholder keeps the standalone form a non-empty word
					// (filepath.Base("") would misread as ".").
					end := skipBalanced(code, i+1, '(', ')')
					scanSubs(sliceTo(code, i+3, end))
					word.WriteByte('0')
					wordStarted = true
					i = end
					continue
				}
				if inner, ok := innerBalanced(code, i+1, '(', ')'); ok {
					scanInner(inner)
				}
				wordStarted = true
				i = skipBalanced(code, i+1, '(', ')')
			} else {
				word.WriteByte(c)
				wordStarted = true
				i++
			}
		case '`':
			if j := strings.IndexByte(code[i+1:], '`'); j >= 0 {
				scanInner(code[i+1 : i+1+j])
				wordStarted = true
				i += j + 2
			} else {
				// Unterminated backtick: it is literal text, and the scan must
				// stop at the end of input (i+2 would overshoot len by one).
				word.WriteByte(c)
				wordStarted = true
				i = len(code)
			}
		case '(':
			if i+1 < len(code) && code[i+1] == '(' {
				// (( ... )) arithmetic command: skip comparisons inside,
				// still scan nested command substitutions.
				end := skipBalanced(code, i+1, '(', ')')
				scanSubs(sliceTo(code, i+2, end))
				i = end
				continue
			}
			// A pure ( ... ) subshell group is a full command context, not a
			// word: the enclosing segment ends here and the group's commands
			// parse into their own segments appended directly to segs.
			flushSeg()
			if depth < shellSplitMaxDepth {
				if inner, ok := innerBalanced(code, i, '(', ')'); ok {
					sub, _ := splitShellSegmentsDepth(inner, depth+1, segPipeIn)
					segs = append(segs, sub...)
				}
			} else {
				segs = append(segs, shellSegment{depthExceeded: true})
			}
			segPipeIn = false
			i = skipBalanced(code, i, '(', ')')
		case ')':
			flushWord()
			flushSeg()
			segPipeIn = false
			i++
		case '<':
			if condDepth > 0 {
				// Inside [[ ... ]]: a comparison operator, not a redirect.
				i++
				continue
			}
			// Input/here-doc redirect: the target word is skipped (never a
			// command head, never a write). `<<EOF`/`<<-EOF` queue the
			// terminator for body consumption at the next newline; `<<<` is a
			// here-string whose single-word payload is skipped like any
			// other input redirect.
			j := i
			for j < len(code) && code[j] == '<' {
				j++
			}
			nlt := j - i
			if j < len(code) && code[j] == '&' {
				j++
			}
			if nlt == 1 && j < len(code) && code[j] == '>' {
				j++ // <> read-write open: treat as a write for the guard.
				flushWord()
				target, next := readOutputRedirectTarget(j)
				if cur.redirectFile == "" && redirectBlocksWrite(">", target) {
					cur.redirectFile = target
				}
				i = next
				continue
			}
			if nlt == 3 {
				// <<< here-string: its one word is this command's stdin. A
				// $(...)/`...` inside still expands (scanInlineSubstitutions
				// skips single-quoted spans, matching the shell) and the
				// flattened payload rides on the segment so a shell or
				// interpreter head reading stdin (`bash <<< 'pig'`) has it
				// screened as code; a data head (`cat <<< x`) ignores it.
				k := j
				for k < len(code) && (code[k] == ' ' || code[k] == '\t') {
					k++
				}
				next := skipWord(k)
				word := sliceTo(code, k, next)
				scanSubs(word)
				if payload := readShellWord(code, k); payload != "" {
					cur.hereString = payload
				} else if word != "" {
					// Dynamic payload ($(...) in the word): keep the raw
					// word so an interpreter head still fails closed on it.
					cur.hereString = word
				}
				i = next
				continue
			}
			if nlt == 2 {
				// << / <<- heredoc: read the terminator word and queue the body
				// against the CURRENT segment (owner resolved at next flush).
				k := j
				stripTabs := false
				if k < len(code) && code[k] == '-' {
					stripTabs = true
					k++
				}
				delim, quoted, next := readHeredocDelim(code, k)
				if delim != "" {
					heredocs = append(heredocs, heredocSpec{delim: delim, quoted: quoted, stripTabs: stripTabs, pending: true})
				}
				scanSubs(sliceTo(code, k, next)) // $(...) inside the delimiter word expands
				i = next
				continue
			}
			// `<`, `<<&`, `<&` input redirections: the target word is skipped
			// (never a command head, never a write) but any $(...)/`...`
			// inside it still runs — scan it like an output target does.
			_, next := readRedirectTarget(j)
			scanSubs(sliceTo(code, j, next))
			i = next
		case '>':
			if condDepth > 0 {
				i++
				continue
			}
			// Output redirect. The digits that may precede it (2>) were already
			// consumed into the word — fold the op text for the fd-dup check and
			// drop the accumulated fd number so "2" is not mistaken for argv.
			op := ">"
			j := i + 1
			if j < len(code) && code[j] == '>' {
				op = ">>"
				j++
			}
			if j < len(code) && code[j] == '|' {
				op += "|"
				j++
			}
			if j < len(code) && code[j] == '&' {
				op += "&"
				j++
			}
			// Strip a pending fd number from the word under construction so
			// "cmd 2>f" parses argv [cmd] not [cmd 2].
			if wordStarted {
				if w := word.String(); allDigits(w) {
					word.Reset()
					wordStarted = false
				}
			}
			flushWord()
			target, next := readOutputRedirectTarget(j)
			if cur.redirectFile == "" && redirectBlocksWrite(op, target) {
				cur.redirectFile = target
			}
			i = next
		case '[':
			// [[ ... ]] conditional: < and > inside are comparison operators,
			// not redirections.
			if i+1 < len(code) && code[i+1] == '[' {
				condDepth++
				word.WriteString("[[")
				wordStarted = true
				i += 2
				continue
			}
			word.WriteByte(c)
			wordStarted = true
			i++
		case ']':
			if i+1 < len(code) && code[i+1] == ']' && condDepth > 0 {
				condDepth--
				word.WriteString("]]")
				i += 2
				continue
			}
			word.WriteByte(c)
			wordStarted = true
			i++
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			// A bare number followed directly by < or > is an fd prefix on a
			// redirect, not a word: "cmd 2>f" must not leave "2" in argv and
			// "2>&1" must be read as one operator target pair. The lookahead
			// only applies when NO word is under construction — digits INSIDE a
			// word (python3>/dev/null) are ordinary bytes. When no operator
			// follows, fall back to word mode.
			if !wordStarted {
				j := i
				for j < len(code) && code[j] >= '0' && code[j] <= '9' {
					j++
				}
				if j < len(code) && (code[j] == '<' || code[j] == '>') && condDepth == 0 {
					i = j // let the '<'/'>' case handle the operator
					continue
				}
			}
			word.WriteByte(c)
			wordStarted = true
			i++
		default:
			word.WriteByte(c)
			wordStarted = true
			i++
		}
	}
	flushWord()
	flushSeg()
	return segs, true
}

// heredocBodyText extracts the body of a heredoc starting at bodyStart (the
// first line after the `<<` line) up to a lone terminator line equal to
// spec.delim. For the `<<-` form (spec.stripTabs) leading tab characters on
// the terminator line are stripped before comparison, matching shell
// semantics so an indented closing line is not swallowed into the body.
// It returns (bodyText, indexAfterTerminatorLine). When no terminator
// appears, the whole remainder is body (the shell would error at runtime;
// screening it costs nothing).
func heredocBodyText(code string, bodyStart int, spec heredocSpec) (string, int) {
	i := bodyStart
	lineStart := i
	for i < len(code) {
		if code[i] == '\n' {
			line := code[lineStart:i]
			candidate := strings.TrimRight(line, "\r")
			if spec.stripTabs {
				candidate = strings.TrimLeft(candidate, "\t")
			}
			if candidate == spec.delim {
				return code[bodyStart:lineStart], i + 1
			}
			i++
			lineStart = i
			continue
		}
		i++
	}
	return code[bodyStart:], i
}

// readHeredocDelim reads the terminator word after `<<`/`<<-`: it may be
// quoted ('EOF' / "EOF" / \E\O\F), in which case the body is literal. Returns
// (delim, quoted, indexAfterWord). An empty delim means the word could not be
// read and no body is queued.
func readHeredocDelim(code string, i int) (string, bool, int) {
	for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
		i++
	}
	if i >= len(code) {
		return "", false, i
	}
	var b strings.Builder
	quoted := false
	for i < len(code) {
		c := code[i]
		switch c {
		case ' ', '\t', '\r', '\n', ';', '|', '&', '<', '>':
			return b.String(), quoted, i
		case '\'':
			quoted = true
			i++
			for i < len(code) && code[i] != '\'' {
				b.WriteByte(code[i])
				i++
			}
			if i < len(code) {
				i++
			}
		case '"':
			quoted = true
			i++
			for i < len(code) && code[i] != '"' {
				b.WriteByte(code[i])
				i++
			}
			if i < len(code) {
				i++
			}
		case '\\':
			quoted = true // \E counts as quoting in POSIX heredoc delimiters
			if i+1 < len(code) {
				b.WriteByte(code[i+1])
				i += 2
			} else {
				i++
			}
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String(), quoted, i
}

// scanInlineSubstitutions scans a small slice (an arithmetic group, a
// redirect target word, or an unquoted heredoc body) for $(...) and `...`
// substitutions and recursively screens their inner text, appending the
// parsed segments to extra in order. It NEVER touches the enclosing
// segment under construction — substitution segments are staged and flush
// together with the segment that owns them. At the depth cap it appends a
// fail-closed marker segment instead of recursing any further.
func scanInlineSubstitutions(text string, depth int, extra *[]shellSegment) {
	// The depth cap only fires when a substitution is actually present — a
	// plain word (e.g. a redirect target like >/dev/null) at max depth
	// must not trip the fail-closed marker.
	overDepth := depth >= shellSplitMaxDepth
	failClosed := func() {
		if overDepth {
			*extra = append(*extra, shellSegment{depthExceeded: true})
		}
	}
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\'':
			i++
			for i < len(text) && text[i] != '\'' {
				i++
			}
		case '"':
			i++
			for i < len(text) && text[i] != '"' {
				if text[i] == '\\' && i+1 < len(text) {
					i += 2
					continue
				}
				if text[i] == '$' && i+1 < len(text) && text[i+1] == '(' {
					failClosed()
					if !overDepth {
						if inner, ok := innerBalanced(text, i+1, '(', ')'); ok {
							sub, _ := splitShellSegmentsDepth(inner, depth+1, false)
							*extra = append(*extra, sub...)
						}
					}
					i = skipBalanced(text, i+1, '(', ')') - 1
				}
				if text[i] == '`' {
					if j := strings.IndexByte(text[i+1:], '`'); j >= 0 {
						failClosed()
						if !overDepth {
							sub, _ := splitShellSegmentsDepth(text[i+1:i+1+j], depth+1, false)
							*extra = append(*extra, sub...)
						}
						i += j + 1
					}
				}
				i++
			}
		case '\\':
			i++
		case '$':
			if i+1 < len(text) && text[i+1] == '(' {
				failClosed()
				if !overDepth {
					if inner, ok := innerBalanced(text, i+1, '(', ')'); ok {
						sub, _ := splitShellSegmentsDepth(inner, depth+1, false)
						*extra = append(*extra, sub...)
					}
				}
				i = skipBalanced(text, i+1, '(', ')') - 1
			}
		case '`':
			if j := strings.IndexByte(text[i+1:], '`'); j >= 0 {
				failClosed()
				if !overDepth {
					sub, _ := splitShellSegmentsDepth(text[i+1:i+1+j], depth+1, false)
					*extra = append(*extra, sub...)
				}
				i += j + 1
			}
		}
	}
}

// scanHeredocSubstitutions is scanInlineSubstitutions for the body of an
// UNQUOTED heredoc (`<<EOF` / `<<-EOF`). The shell performs expansion on
// those lines line-by-line, where single and double quotes carry no
// syntactic meaning — `echo '$(rm -f x)' <<EOF` still runs `rm`. So the
// scanner anchors on `$(` and a backtick anywhere in the text and only
// honours a backslash escape (`\$(` / “ \` “ stay literal); `$(...)` groups
// are walked with the shared balanced scanner, which handles nested quotes
// and substitutions.
func scanHeredocSubstitutions(text string, depth int, extra *[]shellSegment) {
	if depth >= shellSplitMaxDepth {
		if strings.Contains(text, "$(") || strings.IndexByte(text, '`') >= 0 {
			*extra = append(*extra, shellSegment{depthExceeded: true})
		}
		return
	}
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\\':
			i++ // the escaped byte is literal: \$( and \` do not expand
		case '$':
			if i+1 < len(text) && text[i+1] == '(' {
				if inner, ok := innerBalanced(text, i+1, '(', ')'); ok {
					sub, _ := splitShellSegmentsDepth(inner, depth+1, false)
					*extra = append(*extra, sub...)
				}
				i = skipBalanced(text, i+1, '(', ')') - 1
			}
		case '`':
			if j := strings.IndexByte(text[i+1:], '`'); j >= 0 {
				sub, _ := splitShellSegmentsDepth(text[i+1:i+1+j], depth+1, false)
				*extra = append(*extra, sub...)
				i += j + 1
			}
		}
	}
}

// readShellWord extracts one unquoted-flattened word starting at i, stopping
// at whitespace or a shell metacharacter. Returns "" when the word is empty,
// begins with a separator, or contains a command substitution ($(...) or
// `...`); the caller substitutes the blocking placeholder for output
// redirects.
func readShellWord(code string, i int) string {
	var b strings.Builder
	// A `#` at the very start of the word is a comment, not word text: the
	// word is empty (the caller decides what a missing target means).
	if i < len(code) && code[i] == '#' && (i == 0 || isShellWordBreak(code[i-1])) {
		return ""
	}
	for i < len(code) {
		c := code[i]
		switch c {
		case ' ', '\t', '\r', '\n', ';', '|', '&', '(', ')', '<', '>':
			return b.String()
		case '\'':
			j := i + 1
			for j < len(code) && code[j] != '\'' {
				j++
			}
			b.WriteString(code[i+1 : j])
			i = j + 1
		case '"':
			j := i + 1
			for j < len(code) && code[j] != '"' {
				if code[j] == '\\' && j+1 < len(code) {
					j++
				}
				b.WriteByte(code[j])
				j++
			}
			i = j + 1
		case '\\':
			if i+1 < len(code) {
				b.WriteByte(code[i+1])
				i += 2
			} else {
				i++
			}
		case '$':
			if i+1 < len(code) && code[i+1] == '(' {
				return ""
			}
			b.WriteByte(c)
			i++
		case '`':
			return "" // dynamic, same class as $(...)
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// redirectBlocksWrite reports whether a write-like redirection whose flattened
// target word is target must block for a read-only caller. The target is
// blocked unless it is /dev/null, /dev/stdout, /dev/stderr, or an fd
// duplication/close (>&N, >&-, N>&M). An empty target never blocks (a bare `>`
// with no target is a shell syntax error anyway); a dynamic placeholder does.
func redirectBlocksWrite(op, target string) bool {
	if target == "" {
		return false
	}
	if strings.HasSuffix(op, "&") || op == ">&" || op == "&>" {
		// >&N / >&- fd duplications are never file writes. `&> file` (bash's
		// stdout+stderr redirect) IS a write and reaches here with op "&>" and
		// a non-numeric target, which the digit check correctly lets through to
		// the path comparison below.
		if target == "-" || allDigits(target) {
			return false
		}
	}
	switch target {
	case "/dev/null", "/dev/stdout", "/dev/stderr":
		return false
	}
	return true
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

// skipBalanced returns the index just past the balanced group opened at
// code[open] (code[open] must be the opening rune). Quotes and escapes inside
// are honoured so ')' inside quotes doesn't end the group. On an unbalanced
// group it returns len(code).
func skipBalanced(code string, open int, openCh, closeCh byte) int {
	depth := 0
	i := open
	for i < len(code) {
		c := code[i]
		switch c {
		case '\'':
			i++
			for i < len(code) && code[i] != '\'' {
				i++
			}
			if i < len(code) {
				i++
			}
		case '"':
			i++
			for i < len(code) && code[i] != '"' {
				if code[i] == '\\' && i+1 < len(code) {
					i++
				}
				i++
			}
			if i < len(code) {
				i++
			}
		case '\\':
			i += 2
		case openCh:
			depth++
			i++
		case closeCh:
			depth--
			i++
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return len(code)
}

// innerBalanced returns the text inside the balanced group opened at
// code[open], or ok=false when unbalanced.
func innerBalanced(code string, open int, openCh, closeCh byte) (string, bool) {
	end := skipBalanced(code, open, openCh, closeCh)
	if end > len(code) || end == 0 || code[end-1] != closeCh {
		return "", false
	}
	return code[open+1 : end-1], true
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
	"DYLD_INSERT_LIBRARIES": true,
	"NODE_OPTIONS":          true, "PYTHONSTARTUP": true, "PYTHONINSPECT": true,
	"PERL5OPT": true, "PERL5DB": true, "RUBYOPT": true,
	"JAVA_TOOL_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "_JAVA_OPTIONS": true,
}

// pagerSafeVars may be set to "" or "cat" — disabling the pager is the
// canonical read-only spelling (`GIT_PAGER=cat git log`).
var pagerSafeVars = map[string]bool{
	"PAGER": true, "GIT_PAGER": true, "MANPAGER": true,
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
// Wrappers handled: env (with its options and NAME=val assignments), command
// (-v/-V stay as a read-only builtin query), exec, nohup, timeout (with
// duration and option args), nice, setsid, stdbuf, busybox, ionice, taskset,
// chrt, watch, flock (options + lock file), script (without -c), sudo/doas
// (with option args), strace/ltrace, builtin, shell reserved/modifier words
// (`if`/`then`/`elif`/`else`/`while`/`until`/`do`/`coproc`/`time`/`!`), and
// `--` terminators. Recursion is bounded by peelWrapperMaxSteps (bare KEY=VAL
// prefixes do not consume steps); a chain that never resolves returns an
// index past the end.
func peelWrappers(argv []string) (idx int, splitPayloads []string, envAs envAssignments, exhausted bool) {
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
				return len(argv), splitPayloads, envAs, false // trailing `}`/`fi`/`done`
			}
			i++ // leading `{` / `(` group opener: peel to the inner head
			depth--
			continue
		}
		switch filepath.Base(a) {
		case "if", "then", "elif", "else", "while", "until", "do", "!", "coproc":
			i++
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
			var payloads []string
			i, payloads, envAs = skipEnvOperands(argv, i, envAs)
			splitPayloads = append(splitPayloads, payloads...)
		case "command":
			start := i
			i++
			// `command` followed by a pure query option run (-v/-V, with
			// optional -p) reports the command path/type without executing
			// it: keep `command` as the resolved head so peelResolvedDepth
			// can allow it outright. Anything else peels to the real head.
			if isCommandQuery(argv[i:]) {
				return start, splitPayloads, envAs, false
			}
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				i++
			}
			i = skipDashDash(argv, i)
		case "builtin":
			// builtin has no -v/-V query semantics: it always wraps a real
			// builtin name, so peel its option run to the command head.
			i++
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				i++
			}
			i = skipDashDash(argv, i)
		case "exec":
			// bash exec [-cl] [-a name] [--] command: skip option run so
			// `exec -a benign pig` peels to `pig`.
			i++
			for i < len(argv) {
				a := argv[i]
				if a == "--" {
					i++
					break
				}
				if a == "-a" {
					i += 2 // -a name
					continue
				}
				if a == "-c" || a == "-l" {
					i++
					continue
				}
				// Glued clusters like -cl: all boolean; -aNAME is not used by bash.
				if strings.HasPrefix(a, "-") && a != "-" && !strings.HasPrefix(a, "--") {
					i++
					continue
				}
				break
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
			i++
			i = skipTimeoutArgs(argv, i)
		case "stdbuf":
			i++
			i = skipStdbufArgs(argv, i)
		case "busybox":
			i++
		case "ionice":
			i++
			i = skipIoniceArgs(argv, i)
		case "taskset":
			i++
			i = skipTasksetArgs(argv, i)
		case "chrt":
			i++
			i = skipChrtArgs(argv, i)
		case "strace", "ltrace":
			i++
			i = skipStraceArgs(argv, i)
		default:
			return i, splitPayloads, envAs, false
		}
	}
	return i, splitPayloads, envAs, depth >= peelWrapperMaxSteps
}

// skipTimeoutArgs consumes timeout's option arguments and its duration.
func skipTimeoutArgs(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
		if a == "-k" || a == "--kill-after" || a == "-s" || a == "--signal" {
			i += 2
		} else {
			i++
		}
	}
	if i < len(argv) {
		i++ // duration
	}
	return skipDashDash(argv, i)
}

// skipStdbufArgs consumes stdbuf's buffering options.
func skipStdbufArgs(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if !strings.HasPrefix(a, "-") {
			break
		}
		if a == "-i" || a == "-o" || a == "-e" {
			i += 2
		} else {
			i++
		}
	}
	return i
}

// skipIoniceArgs consumes ionice's -c N / -n N / -p PID / -t options.
func skipIoniceArgs(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			return i + 1
		case a == "-c" || a == "-n" || a == "-p":
			i += 2
		case a == "-t":
			i++
		case strings.HasPrefix(a, "-c") || strings.HasPrefix(a, "-n") || strings.HasPrefix(a, "-p"):
			i++ // -cN / -nN / -pPID glued
		case strings.HasPrefix(a, "-"):
			i++
		default:
			return i
		}
	}
	return i
}

// skipTasksetArgs consumes taskset's options and its CPU mask operand.
func skipTasksetArgs(argv []string, i int) int {
	sawList := false // -c/--cpu-list seen: the mask is inside an option operand
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			return i + 1
		case a == "-c" || a == "--cpu-list":
			sawList = true
			i += 2 // -c LIST operand
		case a == "-p" || a == "--pid":
			return len(argv) // pid operand, no inner command
		case strings.HasPrefix(a, "--cpu-list="):
			sawList = true
			i++
		case strings.HasPrefix(a, "-"):
			i++
		default:
			if sawList {
				return i // mask already consumed; this is the command
			}
			return i + 1 // the CPU mask operand consumed; next is the command
		}
	}
	return i
}

// skipChrtArgs consumes chrt's policy flags and its priority operand.
func skipChrtArgs(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			return i + 1
		case a == "-p" || a == "--pid":
			return len(argv) // pid operand, no inner command
		case strings.HasPrefix(a, "-"):
			i++
		default:
			return i + 1 // priority operand consumed; next is the command
		}
	}
	return i
}

// skipWatchArgs consumes watch's options and returns (idx, execMode):
// idx is the first operand (the watched command words), execMode reports
// whether -x/--exec appeared — under it the operands are a direct exec
// argv, otherwise GNU watch joins them and runs `sh -c`.
func skipWatchArgs(argv []string, i int) (int, bool) {
	execMode := false
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1, execMode
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		switch a {
		case "-x", "--exec":
			execMode = true
			i++
		case "-n", "--interval", "-q", "--equexit":
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
						i++ // value operand is the next argv
					}
					j = len(a)
				}
			}
			i++
		}
	}
	return i, execMode
}

// skipFlockArgs consumes flock's options plus its lock file/fd operand and
// returns (cmdIdx, cmdText): when the operand is followed by -c/--command
// (or --command=...), cmdText is that shell string and cmdIdx is len(argv)
// (there is no argv head to recurse into — the caller screens the text);
// otherwise cmdIdx points at the command argv after the lock operand.
func skipFlockArgs(argv []string, i int) (int, string) {
	for i < len(argv) {
		a := argv[i]
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
func skipStraceArgs(argv []string, i int) int {
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
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
			i += 2 // separate value operand
		default:
			i++ // boolean (-f/-ff/-c/-C/-t/-tt/-ttt/-T/-r/-v/-q/-y) or glued value
		}
	}
	return i
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

// skipEnvOperands consumes env's own arguments (options and NAME=val
// assignments) starting at i and returns the index of the command env would
// exec plus any -S/--split-string payloads for the caller to screen (the
// text is itself a shell-ish command line). NAME=val assignments and
// -u/--unset operands are recorded into envAs for the execution-hook env
// screen. `-uVAR`/`-CVAR`/`--unset=*`/`--chdir=*` bundles and `--` are
// handled.
func skipEnvOperands(argv []string, i int, envAs envAssignments) (int, []string, envAssignments) {
	var payloads []string
	for i < len(argv) {
		a := argv[i]
		switch {
		case a == "--":
			return i + 1, payloads, envAs
		case a == "-i" || a == "-0" || a == "--ignore-environment" || a == "--null":
			if a == "-i" || a == "--ignore-environment" {
				envAs.ops = append(envAs.ops, envOp{kind: 'c'})
			}
			i++
		case a == "-u" || a == "--unset":
			if i+1 < len(argv) {
				envAs.ops = append(envAs.ops, envOp{kind: 'u', key: argv[i+1]})
			}
			i += 2
		case a == "-C" || a == "--chdir":
			i += 2
		case a == "-S" || a == "--split-string":
			if i+1 < len(argv) {
				payloads = append(payloads, argv[i+1])
			}
			i += 2
		case strings.HasPrefix(a, "-S") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			payloads = append(payloads, a[2:])
			i++
		case strings.HasPrefix(a, "--split-string="):
			payloads = append(payloads, a[len("--split-string="):])
			i++
		case strings.HasPrefix(a, "-u") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			envAs.ops = append(envAs.ops, envOp{kind: 'u', key: a[2:]}) // -uVAR bundle
			i++
		case strings.HasPrefix(a, "-C") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			i++ // -CDIR bundle
		case strings.HasPrefix(a, "--unset="):
			envAs.ops = append(envAs.ops, envOp{kind: 'u', key: a[len("--unset="):]})
			i++
		case strings.HasPrefix(a, "--chdir="):
			i++
		case strings.HasPrefix(a, "-"):
			// Generic short cluster: -uVAR/-CDIR/-SSTR glued forms were
			// handled above; any 'i' letter here is the short form of
			// --ignore-environment and clears the inherited environment.
			if !strings.HasPrefix(a, "--") && strings.IndexByte(a[1:], 'i') >= 0 {
				envAs.ops = append(envAs.ops, envOp{kind: 'c'})
			}
			i++
		case isAssignWord(a):
			envAs.addAssign(a)
			i++
		default:
			return i, payloads, envAs
		}
	}
	return i, payloads, envAs
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
		if a == "--" {
			return "", false
		}
		if strings.HasPrefix(a, "--") {
			continue
		}
		if a == "-o" || a == "+o" {
			i++ // -o/+o consumes the option NAME as its operand
			continue
		}
		if (strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+")) && len(a) > 1 {
			plus := a[0] == '+'
			for j := 1; j < len(a); j++ {
				if a[j] == 'c' && !plus {
					tail := a[j+1:]
					if i+1 < len(argv) {
						// The script is the NEXT argv. A tail that is not a
						// pure-letter flag bundle is glued script text — merge
						// both so nothing escapes review.
						if tail != "" && !isLetterOnly(tail) {
							return tail + "\n" + argv[i+1], true
						}
						return argv[i+1], true
					}
					if tail != "" {
						return tail, true // -c"pig" glued, no next argv
					}
					return "", false
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
	// inlineArgs collects EVERY inline-code operand of this interpreter run
	// (perl -e A -e B, node -e A -p B). opts lists the option spellings that
	// carry code; shortCodes the short-option letters whose cluster tail or
	// next argv is code; valueOpts lists non-code options that consume the
	// next argv (-I dir, -M mod, -r lib, --require mod, -c ini, -d k=v,
	// -z ext). The collected fragments are joined with "\n" and screened
	// together so code split across several -e flags cannot hide.
	inlineArgs := func(opts map[string]bool, shortCodes string, valueOpts map[string]bool) (string, bool) {
		var frags []string
		for i := 1; i < len(argv); i++ {
			a := argv[i]
			if a == "--" {
				break // -- terminates options; what follows is a script file
			}
			if opts[a] {
				if i+1 < len(argv) {
					frags = append(frags, argv[i+1])
					i++
				}
				continue
			}
			if valueOpts[a] {
				i++ // non-code option consumes its value operand
				continue
			}
			if strings.HasPrefix(a, "--") {
				if j := strings.IndexByte(a, '='); j > 0 && opts[a[:j]] {
					frags = append(frags, a[j+1:])
				}
				continue
			}
			if strings.HasPrefix(a, "-") && len(a) > 1 {
				// Bundled short option carrying inline code: -eCODE / -peCODE,
				// -pCODE for node, -ECODE for perl. A value-option letter at
				// the cluster end consumes the next argv instead; either way
				// the cluster scan stops — letters inside the option VALUE
				// (-rtime's 'e', -Mstrict's 'e') are not code flags.
				for j := 1; j < len(a); j++ {
					if strings.IndexByte(shortCodes, a[j]) >= 0 {
						if tail := a[j+1:]; tail != "" {
							frags = append(frags, tail)
						} else if i+1 < len(argv) {
							frags = append(frags, argv[i+1])
							i++
						}
						break
					}
					if valueOpts["-"+string(a[j])] {
						if j+1 >= len(a) {
							i++ // -I / -M / -r / -d at cluster end: next argv is the value
						}
						break
					}
				}
				continue
			}
			break // first non-option operand is the script file
		}
		if len(frags) == 0 {
			return "", false
		}
		return strings.Join(frags, "\n"), true
	}
	switch base {
	case "node", "nodejs":
		if c, has := inlineArgs(map[string]bool{
			"-e": true, "--eval": true, "-p": true, "--print": true,
		}, "ep", map[string]bool{
			"-r": true, "--require": true, "--loader": true, "--import": true,
			"--experimental-loader": true, "--conditions": true,
		}); has {
			return "javascript", c, true
		}
	case "ts-node", "tsx", "bun":
		if c, has := inlineArgs(map[string]bool{"-e": true, "--eval": true}, "e",
			map[string]bool{"-r": true, "--require": true, "--loader": true, "--import": true}); has {
			return "javascript", c, true
		}
	case "perl":
		if c, has := inlineArgs(map[string]bool{"-e": true, "-E": true}, "eE",
			map[string]bool{"-I": true, "-M": true, "-m": true}); has {
			return "perl", c, true
		}
	case "ruby":
		if c, has := inlineArgs(map[string]bool{"-e": true}, "e",
			map[string]bool{"-I": true, "-r": true}); has {
			return "ruby", c, true
		}
	case "php":
		if c, has := inlineArgs(map[string]bool{"-r": true}, "r",
			map[string]bool{"-c": true, "-d": true, "-z": true}); has {
			return "php", c, true
		}
	}
	return "", "", false
}

// ---------- rule 1: sub-agent nested-dispatch guard ----------

// blockedAgentExecutables are the agent executables a sub-agent must never
// spawn from ctx_run. Matching is on filepath.Base of each command head, so a
// bare name, an absolute path, or a worktree-relative path are all caught
// while `echo pig` (pig is an argument, not a head) is not.
var blockedAgentExecutables = map[string]bool{
	"pig":               true,
	"pi":                true,
	"agy":               true,
	"dispatch-agent":    true,
	"dispatch-agent-go": true,
	"grok":              true,
	// Detached session managers let a sub-agent spawn an agent outside the
	// audited ctx_run surface.
	"tmux":   true,
	"screen": true,
	// Privilege / namespace / scheduler / remote wrappers whose inner command
	// escapes the caller's role context or scheduling control.
	"sudo":        true,
	"doas":        true,
	"su":          true,
	"pkexec":      true,
	"nsenter":     true,
	"unshare":     true,
	"chroot":      true,
	"systemd-run": true,
	"at":          true,
	"ssh":         true,
}

// herdrReadonlySubs is the explicit whitelist of read-only herdr
// invocations for a sub-agent: every entry is the exact subcommand WORD
// SEQUENCE (no operands counted). Anything not listed — every pane run /
// split / send-keys / input / resize, tab create/close/rename/move/focus,
// agent start/prompt/send-keys/attach/stop/kill/wait, session create/close
// /kill/attach, server stop/restart/reload-agent-manifests, and any
// unknown verb — blocks outright.
var herdrReadonlySubs = map[string]bool{
	"status": true, "help": true,
	"session list":   true,
	"workspace list": true, "workspace get": true, "workspace current": true,
	"tab list": true, "tab get": true, "tab current": true,
	"pane list": true, "pane get": true, "pane current": true,
	"pane read": true, "pane layout": true,
	"agent list": true, "agent get": true, "agent read": true,
	"agent explain": true,
	"server status": true, "server agent-manifests": true,
}

// herdsmanReadonlySubs is the herdsman read-only whitelist.
var herdsmanReadonlySubs = map[string]bool{
	"status": true, "help": true,
	"daemon status": true,
	"agent list":    true, "agent get": true, "agent read": true,
}

// skipToolGlobalFlags consumes the global option run that precedes a
// herdr/herdsman subcommand: --session/--socket/--workspace/--config with
// a separate or =glued value, plus boolean --json/--no-color/-h-style
// flags. It returns the index of the first non-option operand and whether
// a pure query flag (--help/-h/--version/-V) appeared in the option run —
// such a flag makes the whole invocation a help/version query.
func skipToolGlobalFlags(args []string) (idx int, query bool) {
	for idx < len(args) {
		a := args[idx]
		switch {
		case a == "--help" || a == "-h" || a == "--version" || a == "-V":
			return idx, true
		case a == "--session" || a == "--socket" || a == "--workspace" || a == "--config":
			idx += 2
		case strings.HasPrefix(a, "--session=") || strings.HasPrefix(a, "--socket=") ||
			strings.HasPrefix(a, "--workspace=") || strings.HasPrefix(a, "--config="):
			idx++
		case a == "--":
			idx++
		case strings.HasPrefix(a, "-"):
			idx++ // --json / --no-color / other boolean globals
		default:
			return idx, false
		}
	}
	return idx, false
}

// toolSubKey returns the subcommand key of a tool argv: when the first
// word is a category with second-level verbs (session/workspace/tab/pane/
// agent/server for herdr; daemon/agent for herdsman) the key joins the
// first TWO words (`pane list`); otherwise it is the first word alone
// (`status`). `herdr tab create` => "tab create"; `herdr status` =>
// "status".
func toolSubKey(args []string, secondLevel map[string]bool) string {
	if len(args) == 0 {
		return ""
	}
	if len(args) > 1 && secondLevel[args[0]] {
		return args[0] + " " + args[1]
	}
	return args[0]
}

// herdrSecondLevel are the first words that take a second-level verb.
var herdrSecondLevel = map[string]bool{
	"session": true, "workspace": true, "tab": true, "pane": true,
	"agent": true, "server": true,
}

// herdsmanSecondLevel likewise for herdsman.
var herdsmanSecondLevel = map[string]bool{
	"daemon": true, "agent": true,
}

// screenHerdrSubagent applies the read-only subcommand whitelist: global
// flags are peeled first (a leading --session cannot smuggle a write verb
// past the check), then the subcommand pair must appear in the whitelist
// verbatim. A --help/-h after the whitelisted subcommand stays a query.
func screenHerdrSubagent(headArgv []string) string {
	args := headArgv[1:]
	idx, query := skipToolGlobalFlags(args)
	if idx >= len(args) {
		return "" // bare herdr / pure query flag run
	}
	if query {
		return "" // `herdr --help sub` stays a help query
	}
	key := toolSubKey(args[idx:], herdrSecondLevel)
	if !herdrReadonlySubs[key] {
		return "herdr " + key
	}
	// Whitelisted subcommand: a trailing --help/-h is still a query; any
	// other trailing word is data for that read-only verb and stays free.
	return ""
}

// screenHerdsmanSubagent likewise for herdsman.
func screenHerdsmanSubagent(headArgv []string) string {
	args := headArgv[1:]
	idx, query := skipToolGlobalFlags(args)
	if idx >= len(args) {
		return ""
	}
	if query {
		return ""
	}
	key := toolSubKey(args[idx:], herdsmanSecondLevel)
	if !herdsmanReadonlySubs[key] {
		return "herdsman " + key
	}
	return ""
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

// withScreenCwd records the ctx_run cwd of the call under screening and
// returns the restore func, for `defer withScreenCwd(cwd)()` at each guarded
// entry point (execute, execute_file, batch, run_task). Relative command
// heads (`./bin/piglet`) must resolve against the SAME directory the child
// process gets, and symlink aliases must be found there. ctxmode's own
// environment never carries it: a child exec'd by ctx_run inherits the
// CTXMODE_* identity vars but not the per-call cwd. The MCP server
// serializes requests (jsonrpc2.HandlerSerializer), so exactly one call is
// ever being screened; LockOSThread pins this goroutine to one OS thread for
// the window as belt-and-braces against a torn read from another goroutine.
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

// resolveHeadBase returns the basename of the executable program a command
// head actually runs: the same name when head[0] is not a symlink (or cannot
// be located), the target's basename when it is. Resolution honours the
// caller's ctx_run cwd for relative spellings and exec.LookPath for bare
// names; every lookup failure yields "" (screen the typed name only), which
// is exactly the pre-alias behaviour.
func resolveHeadBase(name string) string {
	if name == "" || strings.Contains(name, cmdSubPlaceholder) {
		return ""
	}
	target := name
	if !filepath.IsAbs(target) {
		if !looksLikePath(target) {
			p, err := exec.LookPath(target)
			if err != nil {
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
	return filepath.Base(resolved)
}

// canonicalResolvedBase maps a symlink-resolved executable basename to the
// canonical program name the name-keyed screens know. Distro and toolchain
// layouts resolve canonical names to versioned or script-shim targets —
// php -> php8.3 (Debian alternatives), ruby -> ruby3.2, perl -> perl5.38.2,
// npx -> npm's npx-cli.js — and keying a screen on the resolved spelling
// silently skips every branch written for the canonical name (the
// interpreter inline-code table, the npx package-runner branch), but only
// on machines where the tool is actually installed that way: where the
// lookup fails the typed name survives and the screen fires. Names that
// are not a known variant pass through unchanged, so a disguised alias
// still surfaces under its real target name.
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
	return b
}

// isVersionSuffix reports whether s is a version tail: a digit followed by
// digits and dots only ("8.3", "3.2", "5.38.2"). The empty string and
// letter-led tails ("-cgi", "stan") are not versions.
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
// of the resolved target. `ln -s $(command -v pig) /tmp/piglet &&
// /tmp/piglet run` names no blocked agent in its own text, and
// `/usr/bin/python3` is a real symlink — so screening only the spelling the
// caller typed is a bypass.
//
// Both names go through the SAME screens: a legitimate system alias keeps
// working because the target is allowed too (`sh -> dash` is a shell under
// either name, `python3 -> python3.12` hits the python prefix match either
// way), while an alias chosen to dodge a rule is caught on the target name.
func headBaseAliasHits(headArgv []string) []string {
	if len(headArgv) == 0 {
		return nil
	}
	out := []string{filepath.Base(headArgv[0])}
	if b := resolveHeadBase(headArgv[0]); b != "" && b != out[0] {
		out = append(out, b)
	}
	return out
}

// screenNestedDispatch returns the guard hit for ONE resolved command head
// (already wrapper-peeled), or "" when allowed. headArgv starts at the head.
// `git` heads also get the global exec-config screen: a sub-agent must not
// arm a pager/ssh/hook command through `git -c`/`--config-env`/`--exec-path`.
func screenNestedDispatch(headArgv []string) string {
	if len(headArgv) == 0 {
		return ""
	}
	for _, base := range headBaseAliasHits(headArgv) {
		if isPureQueryInvocation(headArgv) && pureQueryOnlyHeads[base] {
			continue // `dispatch-agent --version`: nothing is dispatched
		}
		if blockedAgentExecutables[base] {
			return base
		}
		switch base {
		case "herdr":
			if hit := screenHerdrSubagent(headArgv); hit != "" {
				return hit
			}
		case "herdsman":
			if hit := screenHerdsmanSubagent(headArgv); hit != "" {
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
		}
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
}

// currentCallerIdentity reads the caller's role identity from the process
// environment once per top-level guard entry.
func currentCallerIdentity() callerIdentity {
	return callerIdentity{
		role:     strings.TrimSpace(os.Getenv(auditEnvRole)),
		readonly: os.Getenv(auditEnvReadonly),
	}
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
			i, payloads, envAs = skipEnvOperands(argv, i+1, envAs)
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
			// bash exec [-cl] [-a name] [--] command: skip option run so
			// `exec -a benign pig` peels to `pig`.
			i++
			for i < len(argv) {
				a := argv[i]
				if a == "--" {
					i++
					break
				}
				if a == "-a" {
					i += 2 // -a name
					continue
				}
				if a == "-c" || a == "-l" {
					i++
					continue
				}
				// Glued clusters like -cl: all boolean; -aNAME is not used by bash.
				if strings.HasPrefix(a, "-") && a != "-" && !strings.HasPrefix(a, "--") {
					i++
					continue
				}
				break
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
			i = skipTimeoutArgs(argv, i+1)
		case "stdbuf":
			i = skipStdbufArgs(argv, i+1)
		case "busybox":
			i++
		case "ionice":
			i = skipIoniceArgs(argv, i+1)
		case "taskset":
			i = skipTasksetArgs(argv, i+1)
		case "chrt":
			i = skipChrtArgs(argv, i+1)
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
	}
	i, splitPayloads, envAs, exhausted := peelWrappers(argv)
	if exhausted {
		return depthExceededHit // fail closed: wrapper chain never resolved
	}
	if hit := screenEnvAssignments(envAs, kind, caller.role, caller.readonly); hit != "" {
		return hit
	}
	// env -S and script -c payloads were captured during peeling; screen
	// each as shell text.
	for _, payload := range splitPayloads {
		if kind == 's' {
			if hit := guardShellSubagentDepth(payload, depth+1, caller); hit != "" {
				return hit
			}
		} else {
			if hit := guardShellReadonlyDepth(payload, depth+1, caller); hit != "" {
				return hit
			}
		}
	}
	if i >= len(argv) {
		return ""
	}
	head := argv[i:]
	// A command head generated by a command substitution ($(...) / `...`)
	// cannot be vetted statically: the placeholder the shell parser left in
	// the head word means the executable name is dynamic — fail closed for
	// both guards. Placeholders in ARGUMENT positions are inert (the
	// substitution's own commands were already screened as segments).
	if strings.Contains(head[0], cmdSubPlaceholder) {
		return "dynamic command head"
	}
	base := filepath.Base(head[0])
	// typedHead keeps the spelling the caller wrote: the head model at the
	// bottom screens BOTH it and the resolved target (headBaseAliasHits).
	typedHead := head
	// An alias must be recognised as the program it really runs wherever a
	// screen is keyed on the NAME: `mysh -c '…'` with mysh -> dash carries
	// inline code exactly like `dash -c '…'`, and reading it as a bare
	// script-file run would block a benign query (same for py3 -> python3.13).
	if rb := resolveHeadBase(head[0]); rb != "" && rb != base {
		// The resolved spelling is canonicalised first: a versioned or
		// shim target (php8.3, npx-cli.js) must key the screens exactly
		// like the canonical program name, or every branch written for
		// that name is skipped on machines laid out that way.
		if rb = canonicalResolvedBase(rb); rb != base {
			head = append([]string{rb}, head[1:]...)
			base = rb
		}
	}
	// `command` followed by a pure query option run (-v/-V, -p allowed)
	// is a read-only builtin query — peelWrappers kept `command` as the
	// head exactly for this check. Allowed outright.
	if base == "command" && isCommandQuery(head[1:]) {
		return ""
	}
	// `ctxmode index` writes the shared KB (same rule as ctx_kb
	// action=index, which refuses every read-only role, verifier
	// included). screenReadonlyWrite only sees strict read-only
	// callers, so verifier needs this branch before it.
	if base == "ctxmode" && callerReadonlyRole(caller) && ctxmodeCLIAction(head[1:]) == "index" {
		return "ctxmode index"
	}
	if text, has := unwrapShellArgv(head); has {
		if kind == 's' {
			return guardShellSubagentDepth(text, depth+1, caller)
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	if lang, code, has := unwrapInterpreterInline(head); has {
		if lang == "python-module" {
			// `python -m MOD` runs MOD, not the interpreter's own code path:
			// a strict read-only caller gets the default-deny module model
			// (http.server, compileall, venv, a local evil_mod and every other
			// unvetted module block; only a pure --help and the side-effect-free
			// text filters stay free), a sub-agent gets the nested-dispatch
			// screen on MOD and its operands (`python -m pip install pig`).
			if kind == 'r' {
				return screenReadonlyWrite(head)
			}
			if modArgv := pythonModuleArgvFrom(head); len(modArgv) > 0 {
				if hit := screenNestedDispatch(modArgv); hit != "" {
					return hit
				}
			}
			return ""
		}
		g := guardCall{}
		if kind == 's' {
			g.subagent = true
		} else {
			g.strictReadonly = true
		}
		if rule, _ := g.guardCtxRunCode(lang, code); rule != "" {
			return lang + " inline code"
		}
		// Inline code screened clean; perl/ruby still get the in-place
		// flag check (-i) that screenReadonlyWrite performs — but only
		// for strict read-only roles: a worker may legitimately run
		// `perl -i -pe 's/a/b/' file` to edit a file. Then the argv is
		// done — no file-run fallthrough.
		if kind == 'r' && (base == "perl" || base == "ruby") {
			if hasInterpInPlaceFlag(head) {
				return base + " -i"
			}
		}
		return ""
	}
	// eval: join remaining args and screen as shell text.
	if base == "eval" && len(head) > 1 {
		text := strings.Join(head[1:], " ")
		if kind == 's' {
			return guardShellSubagentDepth(text, depth+1, caller)
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	// xargs: peel xargs options, then screen the target command argv.
	if base == "xargs" {
		if k := xargsTargetIndex(head); k >= 0 && k < len(head) {
			return peelResolvedDepth(head[k:], kind, depth+1, caller)
		}
		return "" // `xargs` with no command runs echo: read-only
	}
	// find: scan for -exec/-execdir/-ok/-okdir (inner command recursion, all
	// callers) and -delete/-fprint* (strict read-only only).
	if base == "find" {
		return screenFindArgs(head[1:], kind, depth+1, caller)
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
	// -x/--exec makes them a direct exec argv. peelWrappers deliberately
	// keeps watch as the head so the correct execution model applies.
	if base == "watch" && len(head) > 1 {
		k, execMode := skipWatchArgs(head, 1)
		if k >= len(head) {
			return "" // `watch` with no command does nothing
		}
		if execMode {
			return peelResolvedDepth(head[k:], kind, depth+1, caller)
		}
		text := strings.Join(head[k:], " ")
		if kind == 's' {
			return guardShellSubagentDepth(text, depth+1, caller)
		}
		return guardShellReadonlyDepth(text, depth+1, caller)
	}
	// flock: peel its own options + lock operand, then screen the inner
	// command; `flock LOCK -c CMD` carries the command as shell text. For
	// strict read-only the head itself blocks (it writes a lock file).
	if base == "flock" {
		if kind == 'r' {
			return "flock"
		}
		inner, cmdText := skipFlockArgs(head, 1)
		if cmdText != "" {
			return guardShellSubagentDepth(cmdText, depth+1, caller)
		}
		if inner < len(head) {
			return peelResolvedDepth(head[inner:], kind, depth+1, caller)
		}
		return ""
	}
	// script: `-c cmd` runs cmd through a shell inside a pty — screen the
	// payload as shell text; for strict read-only the head itself blocks
	// (it writes a transcript / spawns a shell).
	if base == "script" {
		if kind == 'r' {
			return "script"
		}
		if payload := scriptCommandArg(head); payload != "" {
			return guardShellSubagentDepth(payload, depth+1, caller)
		}
		return ""
	}
	// awk/gawk/mawk/nawk: the program text can spawn commands
	// (system("cmd"), "cmd" | getline, print | "cmd") — for a sub-agent
	// the command strings inside are screened like shell text.
	if kind == 's' && (base == "awk" || base == "gawk" || base == "mawk" || base == "nawk") {
		if hit := screenAwkSubagent(head[1:], depth, caller); hit != "" {
			return hit
		}
	}
	// sed: GNU sed's `e` command / `s///e` flag execute shell text from the
	// script — screen it like any other embedded command.
	if kind == 's' && (base == "sed" || base == "gsed") {
		if hit := screenSedSubagent(head[1:], depth, caller); hit != "" {
			return hit
		}
	}
	// tar: --checkpoint-action=exec=CMD / --to-command CMD /
	// --use-compress-program CMD run external commands; the command text
	// goes through the sub-agent screen.
	if kind == 's' && (base == "tar" || base == "gtar" || base == "bsdtar") {
		if hit := screenTarSubagent(head[1:], depth, caller); hit != "" {
			return hit
		}
	}
	// npx/bunx/pnpx fetch and run a package binary: when the TARGET command
	// itself names a blocked agent executable the sub-agent guard fires.
	if kind == 's' && (base == "npx" || base == "bunx" || base == "pnpx") {
		if sub := firstNonFlagArg(head[1:]); sub != "" && blockedAgentExecutables[filepath.Base(sub)] {
			return base + " " + sub
		}
	}
	// The plain head check, under the typed spelling and the resolved target
	// alike (headBaseAliasHits walks both inside each screen).
	if kind == 's' {
		return screenNestedDispatch(typedHead)
	}
	return screenReadonlyWrite(typedHead)
}

// scriptCommandArg returns the `-c cmd` payload of a `script` argv, or "".
// Short clusters count (`script -qc 'pig'`, `script -c"pig"`), as do
// --command/--command= forms.
func scriptCommandArg(head []string) string {
	for i := 1; i < len(head); i++ {
		a := head[i]
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
// Detail strings name only the variable (never the value): env values can
// carry secrets and the detail goes into the audit record verbatim.
func screenEnvAssignments(envAs envAssignments, kind byte, callerRole, callerReadonly string) string {
	effRole := callerRole
	effReadonly := callerReadonly
	callerSub := callerRole != "" || envTruthy(callerReadonly)
	for _, op := range envAs.ops {
		switch op.kind {
		case 'c':
			effRole = ""
			effReadonly = ""
		case 'u':
			switch op.key {
			case auditEnvRole:
				effRole = ""
			case auditEnvReadonly:
				effReadonly = ""
			}
		case 'a':
			switch op.key {
			case auditEnvRole:
				effRole = op.value
			case auditEnvReadonly:
				effReadonly = op.value
			}
			if envHookVars[op.key] {
				if pagerSafeVars[op.key] && (op.value == "" || op.value == "cat") {
					continue
				}
				return "env " + op.key
			}
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

// envTruthy reports whether a CTXMODE_READONLY value counts as set.
func envTruthy(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true"
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
// sub-agent callers; strict read-only leaves other unsets free.
func screenUnsetArgs(args []string, kind byte) string {
	if kind != 's' {
		return ""
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue // -v/-f flags
		}
		if guardTaintVars[a] {
			return "unset " + a
		}
	}
	return ""
}

// xargsTargetIndex returns the index in argv of the command xargs would run,
// or len(argv) when xargs would run its default (echo). Option arities follow
// GNU findutils; `--` terminates xargs options.
func xargsTargetIndex(argv []string) int {
	i := 1
	longWithValue := map[string]bool{
		"--arg-file": true, "--delimiter": true,
		// GNU --eof takes an optional value only via --eof=STR; bare --eof
		// must NOT consume the next argv (unlike -E which requires a value).
		"--max-args": true, "--max-lines": true, "--max-procs": true,
		"--max-chars": true, "--process-slot-var": true,
	}
	shortWithValue := map[byte]bool{
		// GNU xargs option arity: lowercase -e takes only a GLUED optional
		// eof-str (-eE / -e=E), never a separate argv — it is absent here so
		// `xargs -e pig` resolves to `pig`. Uppercase -E keeps the
		// separate-operand form.
		'I': true, 'L': true, 'n': true, 'P': true, 's': true,
		'd': true, 'a': true, 'E': true, 'J': true,
	}
	for i < len(argv) {
		a := argv[i]
		if a == "--" {
			return i + 1
		}
		if strings.HasPrefix(a, "--") {
			if j := strings.IndexByte(a, '='); j > 0 {
				i++ // --opt=value
			} else if longWithValue[a] {
				i += 2 // --opt value
			} else {
				i++ // boolean long option
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			// Short-option cluster: value-carrying letters take the rest of
			// the cluster or the next arg; bare clusters (-0, -r, -t, -p, -x)
			// consume one slot.
			consumedNext := false
			for j := 1; j < len(a); j++ {
				if a[j] == 'e' {
					break // -e takes only a glued optional eof-str: the rest of
					// the cluster is its operand, never the next argv slot.
				}
				if shortWithValue[a[j]] {
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

// screenFindArgs scans find's operand list: -exec/-execdir/-ok/-okdir inner
// commands recurse into the argv guards; -delete/-fprint/-fprint0/-fprintf/
// -fls block under strict read-only.
func screenFindArgs(args []string, kind byte, depth int, caller callerIdentity) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir" {
			j := i + 1
			for j < len(args) && args[j] != ";" && args[j] != "+" {
				j++
			}
			if j > i+1 {
				inner := args[i+1 : j]
				// Keep {} placeholders so arity stays right for parsing.
				if hit := peelResolvedDepth(inner, kind, depth, caller); hit != "" {
					return "find " + a + " " + hit
				}
			}
			i = j
			continue
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
	if seg.depthExceeded {
		return depthExceededHit
	}
	if len(seg.argv) == 0 {
		return ""
	}
	// A bare shell/interpreter reading its PROGRAM off a pipe is fed by the
	// upstream bytes: for a strict read-only role that is an unreviewable
	// code stream (block outright); for a sub-agent it is a covert channel
	// around head screening (same verdict — the upstream text is not part
	// of this segment and cannot be screened here).
	if seg.pipedStdin {
		if lang, isProg := stdinProgramHead(seg.argv); isProg {
			if lang == "" {
				return "piped code to shell"
			}
			return "piped code to " + lang
		}
	}
	// A `<<<` here-string is this command's stdin: when the head reads its
	// PROGRAM from stdin (`bash <<< 'pig'`, `python3 <<< 'import …'`) the
	// payload is program text and gets the code screen; for any other head
	// (`cat <<< 'pig'`) it is plain data.
	if seg.hereString != "" && headReadsStdinProgram(seg.argv) {
		lang, _ := stdinProgramHead(seg.argv)
		if hit := screenStdinProgram(seg.hereString, lang, kind, depth, caller); hit != "" {
			return hit
		}
	}
	return peelResolvedDepth(seg.argv, kind, depth, caller)
}

// screenSegmentHeredocsDepth screens a segment's consumed heredoc bodies:
// every UNQUOTED body first gets the real heredoc expansion scan (`$(...)`
// and backticks expand inside a `<<EOF` body even when the body wraps them
// in single quotes); a body that reaches a head reading its PROGRAM from
// stdin (a bare shell or a bare interpreter) is additionally screened as
// that interpreter's code. A head with inline code (`sh -c cat <<EOF`) or a
// script-file operand consumes the body as DATA, so only the substitution
// scan applies to it.
func screenSegmentHeredocsDepth(seg shellSegment, kind byte, depth int, caller callerIdentity) string {
	if len(seg.heredocText) == 0 {
		return ""
	}
	lang, isProg := "", false
	{
		i, _, _, _ := peelWrappers(seg.argv)
		if i < len(seg.argv) {
			lang, isProg = stdinProgramHead(seg.argv[i:])
		}
	}
	for _, hb := range seg.heredocText {
		if !hb.quoted {
			// Unquoted terminator: the shell expands $(...)/`...` inside the
			// body no matter what quoting the body text itself uses.
			var extra []shellSegment
			scanHeredocSubstitutions(hb.text, 0, &extra)
			for _, s2 := range extra {
				if s2.depthExceeded {
					return depthExceededHit
				}
				if kind == 'r' && s2.redirectFile != "" {
					return "> " + s2.redirectFile
				}
				if hit := screenOneSegmentDepth(s2, kind, depth+1, caller); hit != "" {
					return hit
				}
			}
		}
		if !isProg {
			continue // the body is data for this head (cat <<EOF, sh -c cat <<EOF)
		}
		if hit := screenStdinProgram(hb.text, lang, kind, depth, caller); hit != "" {
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
	if depth >= peelChainMaxDepth {
		return depthExceededHit
	}
	for _, seg := range splitShellSegments(code) {
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
			if a == "-w" || a == "-u" || strings.HasPrefix(a, "-w") || strings.HasPrefix(a, "-u") {
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
	if len(headArgv) == 0 {
		return ""
	}
	args := headArgv[1:]
	for _, base := range headBaseAliasHits(headArgv) {
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
		if sub := firstNonFlagArg(args); sub != "" && npmFamilyWriteSubs[sub] {
			return base + " " + sub
		}
		// `npm exec`/`pnpm dlx`/`pnpm exec`/`yarn dlx` run a downloaded
		// package binary: an unvetted code path, block for strict roles.
		if sub := firstNonFlagArg(args); sub == "exec" || sub == "dlx" {
			return base + " " + sub
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
// skip; strict read-only: block). Returns (program, sawFile).
func awkProgramFrags(args []string) (string, bool) {
	var frags []string
	var positional string
	sawFile := false
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--" && !endOpts:
			// Option terminator: everything after is a positional operand —
			// the first one is still the program text
			// (`awk -- '-1 {system("pig")}' f`).
			endOpts = true
		case a == "-f" || a == "--file":
			sawFile = true
			i++ // consume the file operand
		case strings.HasPrefix(a, "--file="):
			sawFile = true
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
					if j+1 >= len(a) {
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
	if len(frags) == 0 && positional != "" {
		frags = append(frags, positional)
	}
	return strings.Join(frags, "\n"), sawFile
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
	program, _ := awkProgramFrags(args)
	if program == "" {
		return ""
	}
	// Screen each STRING LITERAL that reaches a command sink as shell text;
	// a non-literal command is only allowed when it names no blocked head.
	for _, lit := range awkCommandLiterals(program) {
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
	return toks.hasIdent("herdr") || toks.hasIdent("herdsman")
}

// screenSedSubagent collects sed script text (inline -e payloads and the
// first positional operand) for a SUB-AGENT caller and screens any GNU sed
// `e` exec commands: `1e pig`, `sed -e 'e agy'`, `s/.*/pig/e`. The command
// text after `e` is screened as shell text.
func screenSedSubagent(args []string, depth int, caller callerIdentity) string {
	// sawFile is ignored: a script FILE is unvetted text, and unlike the
	// strict guard the sub-agent caller keeps screening the inline/positional
	// fragments collected alongside (the strict guard fails closed on -f).
	scripts, _ := sedScripts(args)
	for _, s := range scripts {
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
	return ""
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
				for j := 1; j < len(a); j++ {
					switch a[j] {
					case 'e':
						sawExplicit = true
						if tail := a[j+1:]; tail != "" {
							scripts = append(scripts, tail)
						} else if i+1 < len(args) {
							scripts = append(scripts, args[i+1])
							i++
						}
						j = len(a)
					case 'f':
						sawExplicit = true
						sawFile = true
						if j+1 >= len(a) {
							i++ // file operand is the next argv
						}
						j = len(a)
					case 'l':
						if j+1 >= len(a) {
							i++ // length operand is the next argv
						}
						j = len(a)
					}
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
			// Regex address: skip to the unquoted closing /.
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
				if s[i] == '/' {
					i++
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
				if s[i] == delim {
					i++
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
// CMD / -I CMD carry shell text screened as a command.
func screenTarSubagent(args []string, depth int, caller callerIdentity) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
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
		}
		if cmd == "" {
			continue
		}
		if hit := guardShellSubagentDepth(cmd, depth+1, caller); hit != "" {
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
func screenWgetWrite(args []string) string {
	// Default wget writes the payload to a local file. --spider and
	// -O - / -O /dev/null avoid that, but log-to-disk flags (-o/-a/
	// --output-file/--append-output) are independent and still write.
	okDownload := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--spider" {
			okDownload = true
			continue
		}
		if a == "-O" || a == "--output-document" {
			if i+1 < len(args) {
				dest := args[i+1]
				i++
				if dest == "-" || dest == "/dev/null" {
					okDownload = true
				} else {
					return "wget"
				}
			}
			continue
		}
		if strings.HasPrefix(a, "-O") && len(a) > 2 {
			dest := a[2:]
			if dest == "-" || dest == "/dev/null" {
				okDownload = true
			} else {
				return "wget"
			}
			continue
		}
		if strings.HasPrefix(a, "--output-document=") {
			dest := a[len("--output-document="):]
			if dest == "-" || dest == "/dev/null" {
				okDownload = true
			} else {
				return "wget"
			}
			continue
		}
		// Log file destinations: stdout /dev/null stay free.
		if a == "-o" || a == "-a" || a == "--output-file" || a == "--append-output" {
			if i+1 < len(args) {
				dest := args[i+1]
				i++
				if dest != "-" && dest != "/dev/null" {
					return "wget"
				}
			}
			continue
		}
		if strings.HasPrefix(a, "--output-file=") {
			if dest := a[len("--output-file="):]; dest != "-" && dest != "/dev/null" {
				return "wget"
			}
			continue
		}
		if strings.HasPrefix(a, "--append-output=") {
			if dest := a[len("--append-output="):]; dest != "-" && dest != "/dev/null" {
				return "wget"
			}
			continue
		}
	}
	if okDownload {
		return ""
	}
	return "wget"
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
	"--no-merged": true, "--points-at": true, "--sort": true,
	"--format": true, "-l": true, "--list": true,
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
	"--merged": true, "--no-merged": true, "--sort": true,
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
				// --sort/--format/--points-at/--contains/--no-contains/
				// --merged/--no-merged take a separate value; skip it.
				switch a {
				case "--sort", "--format", "--points-at", "--contains",
					"--no-contains", "--merged", "--no-merged":
					k++
				}
				continue
			}
			if strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--format=") ||
				strings.HasPrefix(a, "--points-at=") || strings.HasPrefix(a, "--contains=") ||
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
			if gitTagReadFlags[a] || strings.HasPrefix(a, "-n") ||
				strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--points-at=") ||
				strings.HasPrefix(a, "--contains=") || strings.HasPrefix(a, "--no-contains=") ||
				strings.HasPrefix(a, "--merged=") || strings.HasPrefix(a, "--no-merged=") {
				hasReadFlag = true
				// Separate-value forms consume the next arg.
				switch a {
				case "-n", "--sort", "--points-at", "--contains",
					"--no-contains", "--merged", "--no-merged", "-l", "--list", "-v", "--verify":
					k++
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
		// `git reflog`, `reflog show`, --help inspect; expire/delete write.
		if len(rest) == 0 {
			return ""
		}
		if rest[0] == "show" || rest[0] == "-h" || rest[0] == "--help" {
			return ""
		}
		return "git reflog " + rest[0]
	case "fsck":
		// Plain fsck / connectivity checks are read-only; --lost-found
		// writes dangling objects into .git/lost-found/.
		for _, a := range rest {
			if a == "--lost-found" {
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
func screenGitGlobalArgs(args []string) (int, string) {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace":
			i += 2
		case a == "-c":
			if i+1 < len(args) {
				if hit := screenGitConfigPair(args[i+1]); hit != "" {
					return i, hit
				}
			}
			i += 2
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			if hit := screenGitConfigPair(a[2:]); hit != "" {
				return i, hit
			}
			i++
		case a == "--config-env":
			if i+1 < len(args) {
				if hit := screenGitConfigEnvPair(args[i+1]); hit != "" {
					return i, hit
				}
			}
			i += 2
		case strings.HasPrefix(a, "--config-env="):
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
	i, _ := screenGitGlobalArgs(args)
	for ; i < len(args); i++ {
		a := args[i]
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
			// Regex address: skip to the unquoted closing /.
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
				if s[i] == '/' {
					i++
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
				if s[i] == delim {
					i++
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
	program, sawFile := awkProgramFrags(args)
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
	if strings.Contains(mod, cmdSubPlaceholder) {
		return "python -m <dynamic>", true // module name generated at run time
	}
	// `--` ends the module's option run: after it everything is positional
	// data, so `python -m json.tool -- -o` cannot carry an output flag.
	for j, a := range rest {
		if a == "--" {
			rest = rest[:j]
			break
		}
	}
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
	"pprint":    true,
}

// moduleWritesOutput reports whether a `python -m` module run carries an
// output-file flag: `-o FILE`/`--out FILE` (json.tool), the glued
// `--out=FILE`/`-oFILE` forms, or an in-place flag. `--outdir`-style options
// that merely START with a flag name are not matches.
func moduleWritesOutput(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" || a == "--out" || a == "--output" || a == "--outfile" || a == "-O" || a == "--inplace" || a == "--in-place":
			return true
		case strings.HasPrefix(a, "--out="), strings.HasPrefix(a, "--output="), strings.HasPrefix(a, "--outfile="):
			return true
		case strings.HasPrefix(a, "-o") && len(a) > 2:
			return true
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
	for _, seg := range splitShellSegments(code) {
		if seg.depthExceeded {
			return depthExceededHit
		}
		if seg.redirectFile != "" {
			return "> " + seg.redirectFile
		}
		if hit := screenSegmentHeredocsDepth(seg, 'r', depth, caller); hit != "" {
			return hit
		}
		if hit := screenOneSegmentDepth(seg, 'r', depth, caller); hit != "" {
			return hit
		}
	}
	return ""
}

// callInnerBounds returns the [lo,hi) byte span of the parenthesized
// argument list whose '(' sits at openIdx in s (s[openIdx] must be '(').
// It validates openIdx and returns closed=false when no matching ')' exists
// so callers can fail closed instead of slicing out of bounds.
func callInnerBounds(s string, openIdx int) (lo, hi int, closed bool) {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != '(' {
		return len(s), len(s), false
	}
	end := skipBalanced(s, openIdx, '(', ')')
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
			// Template literal: blank body but keep ${...} expressions.
			bodyStart := i + 1
			j := bodyStart
			for j < n && b[j] != '`' {
				if b[j] == '\\' {
					j++
				}
				j++
			}
			// A trailing lone backslash (`x = \`abc\`) walks j to n+1; the
			// expression-slice loop below indexes b[k] for k < bodyEnd, so both
			// bounds have to be clamped to the buffer.
			bodyEnd := minInt(j, n)
			i = minInt(j+1, n)
			k := bodyStart
			segStart := k
			depth := 0
			for k < bodyEnd {
				if b[k] == '$' && k+1 < bodyEnd && b[k+1] == '{' {
					if depth == 0 {
						blank(segStart, k)
					}
					depth++
					k += 2
					continue
				}
				if b[k] == '}' && depth > 0 {
					depth--
					if depth == 0 {
						segStart = k + 1
					}
				}
				k++
			}
			blank(segStart, bodyEnd)
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
var codeAgentNames = []string{
	"pig", "pi", "agy", "dispatch-agent", "dispatch-agent-go", "grok",
	"tmux", "screen",
}

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
func (g guardCall) guardCtxRunCode(language, code string) (rule, detail string) {
	if !g.subagent && !g.strictReadonly {
		return "", "" // main agent: no role guard runs at all
	}
	// Lexically mask string/comment bodies for python/javascript so quoted
	// text cannot trip or hide a primitive, and normalize `ident (` call
	// spacing so `open ('/tmp/x','w')` cannot slip through. Agent-name
	// detection still runs on the ORIGINAL code below (spawn arguments are
	// string literals the mask erases).
	masked := code
	switch language {
	case "python":
		masked = pythonMask(code)
	case "javascript", "typescript":
		masked = jsMask(code)
	}
	toks := codeTokens(normCallSpace(masked))
	if g.strictReadonly {
		if codeCompileToDiskLangs[language] {
			return ruleReadonlyWrite, language + " compiles to disk"
		}
		// A command the scanner can read statically is screened at the real
		// command position, so the audit detail names the head the code
		// actually runs (`subprocess.run(['rm','-rf','/tmp/x'])` → `rm`). Any
		// spawn still blocks a strict read-only role: the fallback is the
		// spawn-primitive scan below.
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
		// `.replace(` is dual-meaning: Python str.replace(old,new) and JS
		// str.replace(pat,repl) are pure text transforms, while
		// Path.replace(target)/fs-style rename takes ONE target operand.
		// Single-operand .replace( is a rename — block it. The call runs on
		// the spacing-normalized masked view so `Path(p).replace ('/tmp/y')`
		// is caught, and only for python/javascript/typescript — other
		// languages' masked view is the raw code, where a string literal
		// like `s = ".replace('x')"` could masquerade as a call.
		if language == "python" || language == "javascript" || language == "typescript" {
			if singleArgDotReplace(normCallSpace(masked)) {
				return ruleReadonlyWrite, "write primitive .replace("
			}
		}
	}
	if g.subagent {
		rawToks := codeTokens(code) // string literals stay searchable
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
		if spawn {
			// A command list the scanner can read statically
			// (`subprocess.run(['echo', 'pig'])`,
			// `child_process.execFileSync('git', ['log'])`, plus import/
			// require aliases like `import subprocess as sp; sp.run(...)`)
			// is screened at the REAL command position with the same argv
			// model a shell command gets: `['echo', 'pig']` stays free
			// because pig is an argument, while
			// `['herdsman', 'daemon', 'start']` blocks on its verb instead of
			// on bare text co-occurrence. allResolved means EVERY spawn site
			// was statically resolved — one resolved call must NOT let an
			// adjacent unresolved spawn site skip the fallback (a harmless
			// literal call above `subprocess.run(cmd)` would otherwise
			// short-circuit the whole screen).
			argvs, shellCmds, allResolved := codeStaticSpawnsDetailed(language, code)
			for _, argv := range argvs {
				if hit := screenNestedDispatch(argv); hit != "" {
					return ruleSubagentNestedAgent, hit
				}
			}
			// String-form commands (`os.system("cat f | pig")`,
			// `sp.getoutput("...")`, `execSync('a | b')`) are literal shell
			// text, not an argv: screen them with the shell guard so a
			// blocked agent name anywhere in the pipeline is caught.
			if len(shellCmds) > 0 {
				caller := currentCallerIdentity()
				for _, cmd := range shellCmds {
					if hit := guardShellSubagentDepth(cmd, 0, caller); hit != "" {
						return ruleSubagentNestedAgent, hit
					}
				}
			}
			if !allResolved {
				for _, name := range codeAgentNames {
					if rawToks.hasIdent(name) {
						return ruleSubagentNestedAgent, "code spawns " + name
					}
				}
				// A dynamic spawn site cannot prove a herdr/herdsman argv is
				// on the read-only whitelist, so the mere presence of the
				// orchestrator name fails closed — the same rule
				// programNamesBlockedAgent applies to dynamic awk commands.
				if rawToks.hasIdent("herdr") {
					return ruleSubagentNestedAgent, "code drives herdr mutation"
				}
				if rawToks.hasIdent("herdsman") {
					return ruleSubagentNestedAgent, "code drives herdsman mutation"
				}
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
		"system", "popen", "execv", "execl", "spawnl", "spawnv",
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
	"system": true, "popen": true, "execv": true, "execl": true,
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

// staticSpawnArgv reads the command of a spawn call's argument text (raw +
// byte-aligned mask): either a literal list/tuple of string literals or an
// array-literal first argument, or a plain string command. It returns
//   - argv when the command is a clean argv or a literal command line made
//     of plain words (screened at the command position),
//   - shell when the command is a literal string carrying shell syntax
//     (screened as shell text by the caller),
//   - ok=false when the command is not statically readable at all, which
//     sends the caller to the conservative fallback.
func staticSpawnArgv(raw, masked string) (argv []string, shell string, ok bool) {
	spans := splitCallArgsOffsets(masked)
	operands := make([]string, 0, len(spans))
	for _, sp := range spans {
		lo := minInt(sp[0], len(raw))
		hi := minInt(sp[1], len(raw))
		if hi <= lo {
			continue
		}
		if w := strings.TrimSpace(raw[lo:hi]); w != "" {
			operands = append(operands, w)
		}
	}
	if len(operands) == 0 {
		return nil, "", false
	}
	// Literal argv: `['herdsman', 'daemon', 'start']`.
	if argv, ok := staticArgvList(operands[0]); ok {
		return argv, "", true
	}
	lit, rest, ok := leadingStringLiteral(operands[0])
	if !ok || strings.TrimSpace(rest) != "" {
		return nil, "", false // a variable, an f-string, a template literal, a call …
	}
	// exec-file form: `execFileSync('herdsman', ['daemon', 'start'])`.
	if len(operands) > 1 {
		if argv, ok := staticArgvList(operands[1]); ok {
			return append([]string{lit}, argv...), "", true
		}
	}
	// A literal command line carrying shell syntax is statically readable
	// but is shell text, not an argv — the caller screens it with the shell
	// guard so `os.system("cat f | pig")` blocks on the pipeline head.
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

// headReadsStdinProgram reports whether the peeled command head list takes
// its PROGRAM text from stdin (a bare sh/bash/… with no -c, a bare
// python3/node/perl with no -c/-e). Callers that screen a command stream
// which is not part of the argv text — a ctx_run stdin payload, a heredoc or
// a `<<<` here-string — ask this before treating those bytes as data.
func headReadsStdinProgram(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	i, _, _, _ := peelWrappers(argv)
	if i >= len(argv) {
		return false
	}
	_, isProg := stdinProgramHead(argv[i:])
	return isProg
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
			if hit == "ctxmode index" {
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
	if !g.subagent && !g.strictReadonly {
		return "", "" // main agent: never enters the sub-agent parser
	}
	if g.subagent {
		if hit := guardShellSubagentDepth(code, 0, currentCallerIdentity()); hit != "" {
			if hit == "ctxmode index" {
				return ruleReadonlyWrite, hit
			}
			return ruleSubagentNestedAgent, hit
		}
	}
	if g.strictReadonly {
		if hit := guardShellReadonly(code); hit != "" {
			return ruleReadonlyWrite, hit
		}
	}
	return "", ""
}

// stdinProgramHead reports whether a peeled argv head reads its program
// from stdin: a shell with no -c payload (unwrapShellArgv already checked)
// or a scripting interpreter with no inline-code flag. Returns (lang, true)
// where lang is "" for a shell head or the guardCtxRunCode language.
func stdinProgramHead(argv []string) (lang string, isInterp bool) {
	if len(argv) == 0 {
		return "", false
	}
	i, _, _, _ := peelWrappers(argv)
	if i >= len(argv) {
		return "", false
	}
	head := argv[i:]
	base := filepath.Base(head[0])
	// A `shell -c 'code'` argv carries its program inline — stdin is data.
	if _, has := unwrapShellArgv(head); has {
		return "", false
	}
	// An interpreter with -c/-e/-r/-m/-p inline code likewise.
	if _, _, has := unwrapInterpreterInline(head); has {
		return "", false
	}
	if shellHeads[base] {
		// sh/bash/... without -c: commands come from a script file or
		// stdin. A non-option operand names the script file (stdin is then
		// data); `--` ends options and a following operand is likewise the
		// script. Bare flags (`sh -i`, `sh -s`, `sh -`) mean stdin is the
		// program.
		sawDashDash := false
		for _, a := range head[1:] {
			if a == "--" {
				sawDashDash = true
				continue
			}
			if !strings.HasPrefix(a, "-") || (sawDashDash && a == "-") {
				return "", false // script file operand
			}
			if a == "-" {
				return "", true // `sh -` reads commands from stdin
			}
		}
		return "", true // bare shell: stdin is the program
	}
	if lang, ok := heredocInterpLang(base); ok {
		// python3 - / node - / bare interpreter with only flags: stdin is
		// the program. A non-option operand is a script file — its stdin is
		// just data (and the file itself blocks for strict read-only via
		// screenInterpFileRun).
		sawDashDash := false
		for _, a := range head[1:] {
			if a == "--" {
				sawDashDash = true
				continue
			}
			if a == "-" {
				return lang, true
			}
			if !strings.HasPrefix(a, "-") || sawDashDash {
				return "", false // script file operand
			}
		}
		return lang, true // bare interpreter with only flags
	}
	return "", false
}

// guardCtxRunStdin screens a ctx_run stdin payload when the argv's resolved
// head is a shell or interpreter that reads its program from stdin
// (`argv=["sh"]`, `argv=["python3","-"]`, etc.). Inline-code spellings
// (`sh -c`, `python3 -c`, `node -e`, `perl -e`, `php -r`, `python -m`) mean
// stdin is data, not the program, and are not screened here.
func (g guardCall) guardCtxRunStdin(argv []string, stdin string) (rule, detail string) {
	if stdin == "" || (!g.subagent && !g.strictReadonly) {
		return "", ""
	}
	lang, isProg := stdinProgramHead(argv)
	if !isProg {
		return "", ""
	}
	if lang == "" {
		// Shell head: stdin is shell code.
		return g.guardCtxRunShell(stdin)
	}
	return g.guardCtxRunCode(lang, stdin)
}

// guardCtxRunStdinForCommand is the command-string variant of
// guardCtxRunStdin: it splits the command into segments and checks each
// peeled head for a shell/interpreter reading stdin.
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
		if len(seg.argv) == 0 {
			continue
		}
		if lang, isProg := stdinProgramHead(seg.argv); isProg {
			if lang == "" {
				return g.guardCtxRunShell(stdin)
			}
			return g.guardCtxRunCode(lang, stdin)
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
	for k, v := range env {
		if !envHookVars[k] {
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
	return fmt.Errorf("blocked by role guard (%s): %s", rule, detail)
}

// minInt is a tiny local helper (avoid pulling in math for two ints).
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
