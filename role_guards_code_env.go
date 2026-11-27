package main

// role_guards_code_env.go — guard entry wrappers, code masking, env override screens, and static spawn analysis.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ---------- end additional head screens ----------

// guardArgvReadonly screens one argv for the strict read-only write guard.
// A `shell -c` argv is redirected to the shell-text screener. The legacy
// package wrapper keeps the pre-refactor semantics exactly: it screens
// under currentCallerIdentity() (a readonly verifier/reviewer caller stays
// readonly, never re-classified by guardCall{}.callerIdentity's role
// coercion) and resolves against the process working directory — the base
// the old empty screenCwd had.
func guardArgvReadonly(argv []string) string {
	return peelResolvedDepth(argv, 'r', 0, currentCallerIdentity())
}

// guardArgvSubagent is the matching legacy sub-agent wrapper (same
// currentCallerIdentity + process-cwd semantics). The guardCall methods
// are the pinned-cwd production path: they carry THIS call's cwd and keep
// g.callerIdentity's readonly/role reconciliation intact.
func guardArgvSubagent(argv []string) string {
	return peelResolvedDepth(argv, 's', 0, currentCallerIdentity())
}
func (g guardCall) guardArgvReadonly(argv []string) string {
	return peelResolvedDepth(argv, 'r', 0, g.callerIdentity())
}

// guardShellSubagent screens shell command text for nested agent dispatch:

// guardShellReadonly screens shell command text for the strict read-only
// write guard: every segment's head goes through screenReadonlyWrite, and a
// file-writing redirection blocks the segment.
func guardShellReadonly(code string) string {
	return guardShellReadonlyDepth(code, 0, currentCallerIdentity())
}
func guardShellReadonlyDepth(code string, depth int, caller callerIdentity) string {
	return guardShellReadonlyDepthMode(code, depth, caller, false)
}

func guardShellReadonlyDepthPrepare(code string, depth int, caller callerIdentity) string {
	return guardShellReadonlyDepthMode(code, depth, caller, true)
}

func guardShellReadonlyDepthMode(code string, depth int, caller callerIdentity, prepare bool) string {
	if depth >= peelChainMaxDepth {
		return depthExceededHit
	}
	var roSegs []roSegment
	var hit string
	if prepare {
		roSegs, hit = parseReadonlyShellSegmentsPrepare(code, caller.hcProv)
	} else {
		roSegs, hit = parseReadonlyShellSegments(code)
	}
	if hit != "" {
		return readonlyBlockWithHint(allowlistDetail(hit))
	}
	for _, ro := range roSegs {
		seg := shellSegment{
			argv:            ro.argv,
			argWords:        ro.argWords,
			pipedStdin:      ro.pipedStdin,
			heredocText:     ro.heredocText,
			redirectFile:    ro.redirectFile,
			srcCode:         ro.srcCode,
			gateProvenanced: ro.gateProvenanced,
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
	"posix_spawn", "pty.spawn", "child_process", "execSync", "spawnSync",
	"execFile", "spawnFile",
	"Deno.Command", "Bun.spawn", "os/exec", "exec.Command",
	"syscall.Exec", "syscall.ForkExec", "std::process::Command",
	"shell_exec", "proc_open", "passthru", "Kernel.system", "Open3",
	"Process.spawn", "popen(", "Runtime.exec", "ProcessBuilder",
	"system(", "backticks", "IO.popen", "spawn(", "pcntl_exec",
	"execv(", "execve(", "execl(", "execle(", "execlp(", "execvp(",
	"execvpe(", "spawnl", "spawnv",
	"__import__", "importlib", "ctypes", "cffi",
	"eval(", "exec(", "Function(",
	"process.binding", "process.dlopen",
	"System.cmd", "Port.open", "system2(",
	"Process.Start", "ProcessStartInfo", ".StartInfo",
	"os.StartProcess", "syscall.StartProcess",
	"process::Command", "os.cmd",
}

// codeAgentNames are the blocked nested-agent identifiers inside code.
// Derived from the same list as blockedAgentExecutables so argv and code
// screens stay aligned.
// ssh stays in codeAgentNames so Python/JS dynamic subprocess.run("ssh ...")
// remains fail-closed even though shell/argv ssh is peeled via screenSSHHead.
var codeAgentNames = append(append([]string(nil), blockedAgentExecutableList...), "ssh")

// codeEnvOverrideHit reports the env-override write inside Python or
// JavaScript code that a sub-agent must not reach: os.environ['K']=v,
// os.environ.setdefault/update, os.putenv, process.env.K=v /
// process.env['K']=v, Object.assign(process.env, …). String bodies are
// blanked in masked, so bracket keys are re-read from raw code; a key that
// cannot be statically resolved fails closed (same contract as a dynamic
// KEY=VAL prefix). Plain reads (os.environ['K'], environ.get, process.env.X
// on the right of `=`) stay free.
func codeEnvOverrideHit(language, code, masked string) string {
	if language == "python" {
		return pyEnvOverrideHit(code, masked)
	}
	if language == "javascript" || language == "typescript" {
		return jsEnvOverrideHit(code, masked)
	}
	return ""
}

// envOverrideKeyVerdict judges a statically extracted env key (already
// unquoted). "" allows the write; a non-empty string is the block detail.
func envOverrideKeyVerdict(key string) string {
	if key == "" {
		return "env override dynamic"
	}
	if guardTaintVars[key] || isEnvHookVar(key) || sentinelTrustVars[key] {
		return "env " + key
	}
	return ""
}

// unquoteCodeKey strips a simple quoted literal key (no escapes). A
// backtick template containing `${` is interpolated at runtime — never a
// static key — and fails closed so the caller reports
// `env override dynamic`. Python non-interpolated string/bytes literal
// prefixes are peeled too, but ONLY before a `'`/`"` quote (`b`/`B`,
// `r`/`R`, `u`/`U` and the two-letter `br`/`bR`/`Br`/`BR`/`rb`/`rB`/`Rb`/`RB`
// combinations): `os.environb[b'K']=v` extracts `K` like `os.environ['K']`.
// Interpolating `f`/`F`/`fr`/`rf` prefixes are never peeled (an f-string key
// is dynamic and fails closed), and a backtick never takes a prefix —
// `tag` + backtick is a JS tagged template, not a static key.
func unquoteCodeKey(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		q := s[0]
		if q != '\'' && q != '"' && q != '`' {
			// Try a Python string/bytes literal prefix (1-2 bytes).
			for pl := 1; pl <= 2 && pl < len(s)-1; pl++ {
				pq := s[pl]
				if pq != '\'' && pq != '"' {
					continue
				}
				switch s[:pl] {
				case "b", "B", "r", "R", "u", "U",
					"br", "bR", "Br", "BR", "rb", "rB", "Rb", "RB":
					s = s[pl:]
					q = pq
				default:
					return "", false
				}
				break
			}
		}
		if (q == '\'' || q == '"' || q == '`') && s[len(s)-1] == q {
			inner := s[1 : len(s)-1]
			if q == '`' && strings.Contains(inner, "${") {
				return "", false
			}
			if !strings.ContainsAny(inner, "\\"+string(q)) {
				return inner, true
			}
			return "", false
		}
	}
	return "", false
}

// skipMaskSpace advances i over masked whitespace — ' ', '\t', '\r',
// '\n', '\v', '\f' — and over Python-style backslash line continuations
// ('\' followed by optional ' '/'\t'/'\r'/'\v'/'\f' then '\n').
// String/comment bodies are already blanked in the mask, so a '\\' inside
// a literal cannot reach here; a '\' not followed by a newline stops the
// scan (it is not a continuation).
func skipMaskSpace(s string, i int) int {
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			i++
		case '\\':
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\v' || s[j] == '\f') {
				j++
			}
			if j < len(s) && s[j] == '\n' {
				i = j + 1
				continue
			}
			return i
		default:
			return i
		}
	}
	return i
}

// maskAssignAfterBracket reports whether masked[i] opens a `[…]` subscript
// whose closing bracket is immediately followed by an assignment — a plain
// `=` (not `==` or `=>`) or a compound assignment operator (`+=`, `-=`, `*=`,
// `/=`, `//=`, `%=`, `**=`, `<<=`, `>>=`, `>>>=`, `&=`, `|=`, `^=`, `@=`,
// `&&=`, `||=`, `??=`). Both forms MUTATE the subscripted slot — an
// `os.environ['K'] += 'x'` / `process.env['K'] <<= 1` is an env override —
// so a post-bracket comparison (`['K'] == v`), arrow callback or
// null-comparison (`['K'] ??= v` is a write, `??` alone is not) stays a read.
// Returns (keyLo, keyHi, true) when so; the raw key text is code[keyLo:keyHi].
func maskAssignAfterBracket(masked string, i int) (int, int, bool) {
	if i >= len(masked) || masked[i] != '[' {
		return 0, 0, false
	}
	depth := 0
	for j := i; j < len(masked); j++ {
		switch masked[j] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				// Whitespace-wrapped `)` groups between `]` and the write
				// op — `(os.environ['K'])\n = v` — bind the subscript to
				// the assignment exactly like an unwrapped target, while
				// comparison openers (`==`/`!=`/`<=`/`>=`/`=>`) still fail
				// maskAssignOpAt below.
				k := skipMaskSpace(masked, j+1)
				for k < len(masked) && masked[k] == ')' {
					k = skipMaskSpace(masked, k+1)
				}
				if maskAssignOpAt(masked, k) {
					return i + 1, j, true
				}
				return 0, 0, false
			}
		}
	}
	return 0, 0, false
}

// isMaskSpaceByte reports whether c is a mask-whitespace byte — the set
// skipMaskSpace crosses (' ', '\t', '\r', '\n', '\v', '\f'). A '\' is
// NOT whitespace here (a backslash continuation is a skipMaskSpace-level
// forward concept); for the backward byte checks below a lone '\' simply
// counts as a non-space byte.
func isMaskSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

// maskDestructAssignTarget reports whether the receiver expression spanning
// masked[exprLo:exprHi] (an `os.environ`/`process.env` occurrence whose own
// key/member did NOT take a direct write op) is one ELEMENT of a
// destructuring assignment target — `[a, env['K']] = […]`,
// `({p: env.K} = {…})` — so the env slot is written even though no `=`
// follows the key itself.
//
// Wrapped shape: scan backwards from exprLo tracking bracket depth for an
// unmatched `(`, `[` or `{` enclosing the expression. Each opener must sit
// in operand position — openIsCallOrSubscript rejects call-argument and
// subscript positions (`f(…`, `d[…`, `a[i](…`, `fn()[…`), statement-head
// keywords (`if (1) [K]=v`, `else [K]=v`), ASI/Python statement starts
// (`let x\n[K]=v`) and `{` literals, where the env expr is either READ or
// genuinely assigned. The matching closer is then found by depth, a plain
// `=` right after it (next byte not `=`/`>`) proves the write, otherwise
// enclosing groups are peeled under the same premise. `==`/`=>` still read
// as comparisons/arrows.
//
// Bare-tuple shape (Python only): when the outermost peel leaves the group
// followed by `,` rather than `=` — `[env['K']], a = ['/x'], 1` — or when
// no bracket encloses the expression at all — `env['K'], a = '/x', 1` —
// pyBareTupleAssignAfter looks for a plain `=` at bracket depth 0 in the
// same statement after the comma. JavaScript must not use this shape: a
// comma there is a sequence expression or a multi-declarator (`const a =
// process.env.K, b = 1` READS env), never a destructuring target.
func maskDestructAssignTarget(masked string, exprLo, exprHi int, py bool) bool {
	// Find the nearest unmatched opener enclosing the expression.
	depth := 0
	openIdx := -1
	for j := exprLo - 1; j >= 0; j-- {
		switch masked[j] {
		case ')', ']', '}':
			depth++
		case '(', '[', '{':
			if depth == 0 {
				openIdx = j
			} else {
				depth--
			}
		}
		if openIdx >= 0 {
			break
		}
	}
	if openIdx < 0 {
		// Bare tuple unpack: `os.environ['K'], a = '/x', 1` (Python only).
		return py && pyBareTupleAssignAfter(masked, exprHi)
	}
	// Peel enclosing groups until the outermost literal wrapper; each level
	// must sit in operand position (openIsCallOrSubscript rejects call /
	// subscript openers — the env expr is a read there).
	for {
		if openIsCallOrSubscript(masked, openIdx, py) {
			return false
		}
		d := 0
		closeIdx := -1
		for j := openIdx + 1; j < len(masked); j++ {
			switch masked[j] {
			case '(', '[', '{':
				d++
			case ')', ']', '}':
				if d == 0 {
					closeIdx = j
				} else {
					d--
				}
			}
			if closeIdx >= 0 {
				break
			}
		}
		if closeIdx < 0 {
			return false
		}
		// `group = …` at THIS level is the destructuring write — the
		// `=` of `({p:X}={p:Y})` sits between the inner `}` and the
		// outer `)`, so it must be checked before peeling outward.
		k := skipMaskSpace(masked, closeIdx+1)
		if k < len(masked) && masked[k] == '=' &&
			(k+1 >= len(masked) || (masked[k+1] != '=' && masked[k+1] != '>')) {
			return true
		}
		nested := 0
		nextOpen := -1
		for j := openIdx - 1; j >= 0; j-- {
			switch masked[j] {
			case ')', ']', '}':
				nested++
			case '(', '[', '{':
				if nested == 0 {
					nextOpen = j
				} else {
					nested--
				}
			}
			if nextOpen >= 0 {
				break
			}
		}
		if nextOpen < 0 {
			// Outermost wrapper peeled: the group can still be ONE bare-tuple
			// element — `[env['K']], a = ['/x'], 1` writes env even though
			// the outer `]` is followed by `,`, not `=` (Python only).
			return py && pyBareTupleAssignAfter(masked, closeIdx+1)
		}
		openIdx = nextOpen
	}
}

// pyBareTupleAssignAfter reports whether masked[pos] — an env expression or
// a peeled wrapper group sitting at Python statement level — continues into
// a bare-tuple unpack WRITE: a `,` right after pos (mask whitespace
// allowed), then at bracket depth 0 within the same statement (`;` or a
// non-continuation `\n` ends it) a plain `=` — previous byte not in
// `!<>=`, next byte not `=`/`>`. Only the `=` AFTER the comma writes;
// `x = [env['K']], 1` keeps its `=` before the comma and returns false —
// the env expr is a read.
func pyBareTupleAssignAfter(masked string, pos int) bool {
	k := skipMaskSpace(masked, pos)
	if k >= len(masked) || masked[k] != ',' {
		return false
	}
	d := 0
	for j := k + 1; j < len(masked); j++ {
		switch masked[j] {
		case '(', '[', '{':
			d++
		case ')', ']', '}':
			if d > 0 {
				d--
			}
		case ';':
			if d == 0 {
				return false
			}
		case '\n':
			if d == 0 && !pyLineContBefore(masked, j) {
				return false
			}
		case '=':
			if d == 0 &&
				(j == 0 || strings.IndexByte("!<>=", masked[j-1]) < 0) &&
				(j+1 >= len(masked) || (masked[j+1] != '=' && masked[j+1] != '>')) {
				return true
			}
		}
	}
	return false
}

// maskStmtHeadKeyword reports whether w is a statement-head keyword whose
// parenthesised condition — `if (…)`, `while (…)`, `for (…)`, `with (…)`,
// `switch (…)`, `catch (…)` — is NOT a call. A `[…]` following such a `)`
// opens the statement body (a destructuring target), it does not subscript
// the `)` group.
func maskStmtHeadKeyword(w string) bool {
	switch w {
	case "if", "while", "for", "with", "switch", "catch":
		return true
	}
	return false
}

// maskPrefixKeyword reports whether w is a keyword after which a `[`/`(`
// group opens a NEW operand/statement rather than a subscript or call — JS
// statement/prefix words (`else`, `do`, `return`, `throw`, `yield`,
// `await`, `case`, `of`, `in`, `void`, `typeof`, `delete`, `if`, `while`,
// `for`, `with`, `switch`, `catch`) and Python ones (`elif`, `except`,
// `raise`, `assert`, `del`, `not`, `and`, `or`, `is`, `from`, `import`,
// plus the shared condition heads). `else [K]=v`, `return [K]` and
// `del [K]` all put the group at statement/operand head, never in
// subscript position.
func maskPrefixKeyword(w string) bool {
	switch w {
	case "else", "do", "return", "throw", "yield", "await", "case",
		"of", "in", "void", "typeof", "delete", "if", "while", "for",
		"with", "switch", "catch", "elif", "except", "raise", "assert",
		"del", "not", "and", "or", "is", "from", "import":
		return true
	}
	return false
}

// maskIdentBefore returns the identifier word whose LAST byte is masked[p]
// — the maximal run of identifier bytes ending at p (caller guarantees
// isIdentByte(masked[p])).
func maskIdentBefore(masked string, p int) string {
	lo := p
	for lo-1 >= 0 && isIdentByte(masked[lo-1]) {
		lo--
	}
	return masked[lo : p+1]
}

// openIsCallOrSubscript reports whether the group opener masked[openIdx]
// sits in call-argument or subscript position — `fn(…`, `d[…`, `a[0][…`,
// `fn()[…` — where an env expression inside is READ, versus a
// statement/operand head where `[…]`/`(…)`/`{…}` may be a destructuring
// target literal. Checks, in order:
//   - `{` never opens a call or subscript — it is an object/block literal.
//   - `(` whose own match takes a plain `=` is a tuple-group target
//     `(…) = rhs`, never a call read (`f(…)` cannot be assigned).
//   - skipping mask whitespace backwards: a non-continuation `\n` ends the
//     statement in Python; in JS a `\n` before a `[` is an ASI statement
//     break (`let x\n[K]=v` destructures), while `(`/`{` simply continue
//     a call/operand across lines.
//   - `]` before the opener is a chained subscript `a[0][…` — read.
//   - `)` before the opener: its matching `(` preceded by a statement-head
//     keyword (`if (1) [K]=v` body) makes the group a fresh operand; any
//     other or missing word (`fn()[K]=v`) is a subscripted call result —
//     read.
//   - an identifier: a keyword (else/do/return/…/del/not/and/or/is/
//     import) puts the group at statement head; any other word makes it a
//     subscript or call — `d[K]=v` reads K.
func openIsCallOrSubscript(masked string, openIdx int, py bool) bool {
	if masked[openIdx] == '{' {
		return false
	}
	if masked[openIdx] == '(' {
		// `(…) = rhs` is a destructuring target group, not a call read —
		// a plain `=` after this opener's own match decides before the
		// backward scan (`=>`/`==` still excluded).
		d := 0
		closed := -1
		for j := openIdx + 1; j < len(masked); j++ {
			switch masked[j] {
			case '(', '[', '{':
				d++
			case ')', ']', '}':
				if d == 0 {
					closed = j
				} else {
					d--
				}
			}
			if closed >= 0 {
				break
			}
		}
		if closed < 0 {
			return false
		}
		if k := skipMaskSpace(masked, closed+1); k < len(masked) &&
			masked[k] == '=' &&
			(k+1 >= len(masked) || (masked[k+1] != '=' && masked[k+1] != '>')) {
			return false
		}
	}
	p := openIdx - 1
	for p >= 0 && isMaskSpaceByte(masked[p]) {
		if masked[p] == '\n' {
			if py {
				if !pyLineContBefore(masked, p) {
					return false
				}
			} else if masked[openIdx] == '[' {
				// JS ASI: `x\n[K]` does NOT subscript x — the `[` opens a
				// new expression statement (array destructuring target).
				return false
			}
		}
		p--
	}
	if p < 0 {
		return false
	}
	switch {
	case masked[p] == ']':
		// Chained subscript/call — `a[0][…`.
		return true
	case masked[p] == ')':
		// The opener follows a `)` group: find its `(` and read the word
		// (if any) right before it.
		d := 0
		open := -1
		for j := p - 1; j >= 0; j-- {
			switch masked[j] {
			case ')':
				d++
			case '(':
				if d == 0 {
					open = j
				} else {
					d--
				}
			}
			if open >= 0 {
				break
			}
		}
		if open < 0 {
			return true
		}
		q := open - 1
		for q >= 0 && isMaskSpaceByte(masked[q]) {
			q--
		}
		if q < 0 || !isIdentByte(masked[q]) {
			return true
		}
		return !maskStmtHeadKeyword(maskIdentBefore(masked, q))
	case isIdentByte(masked[p]):
		return !maskPrefixKeyword(maskIdentBefore(masked, p))
	}
	return false
}

// maskAssignOpAt reports whether masked[i] begins an assignment operator:
// `=` alone (next byte not `=` or `>`), or a compound write op whose final
// byte is `=` and whose operator prefix is one the masked-code scanners
// recognise (`+ - * / % < > & | ^ @ ! ?` — `<<=`, `>>=`, `>>>=`, `//=`,
// `**=`, `&&=`, `||=`, `??=`, `!=` is excluded below as a comparison).
// The caller only invokes this immediately after a closing `]` (or, for the
// JS dot-member form, after a property identifier), so a compound op found
// here is unambiguously an assignment — there is no `a == b` parse where a
// leading `+`/`*`/`/`/`%`/`&`/`|`/`^`/`@`/`?` could precede `=` in operand
// position. `!=` and `??=` differ in kind but are cheap to separate:
// `!=`/`==`/`===` are comparisons, every other `X=` after the name is a
// write.
func maskAssignOpAt(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	if s[i] == '=' {
		// `=` is a write only when the next byte cannot make it `==`/`=>`.
		return i+1 >= len(s) || (s[i+1] != '=' && s[i+1] != '>')
	}
	if strings.IndexByte("+-*/%<>&|^@?", s[i]) < 0 {
		return false
	}
	// Scan the operator run: every byte must be an operator char and the
	// run must end in `=`. `!=` (and `!` alone) never reaches here — `!`
	// is not in the prefix set, so `!==`/`!=` are comparisons; a lone
	// `<=`/`>=` is a comparison too and is excluded inside the run.
	j := i + 1
	for j < len(s) && strings.IndexByte("+-*/%<>&|^@?=", s[j]) >= 0 {
		if s[j] == '=' {
			// `<x=`/`>x=` are shift-assigns only when a second op char
			// precedes the `=`: a single `<=`/`>=` is a comparison
			// (same class as `==`/`=>`/`!=`), while `<<=`/`>>=`/`>>>=`
			// genuinely mutate.
			if j == i+1 && (s[i] == '<' || s[i] == '>') {
				return false
			}
			// The `=` may not itself be followed by `=` or `>` (`>>==`,
			// `>>>` alone are not assignments, but `>>=`/`>>>=` are —
			// the run ends exactly at that `=`).
			return j+1 >= len(s) || (s[j+1] != '=' && s[j+1] != '>')
		}
		j++
	}
	return false
}

// pyEnvOverrideHit scans masked Python for os.environ/os.environb
// mutation spellings.
func pyEnvOverrideHit(code, masked string) string {
	toks := codeTokens(masked)
	// environ.update / environ.setdefault / os.putenv mutate env without a
	// visible `=` on the environ name: they always fail closed — a
	// sub-agent code body has no legitimate need to write process env, and
	// a dynamic payload could re-target the report/socket hooks. The
	// `environb.` spellings cover os.environb — Python's byte-keyed
	// environ view — which mutates the same environment.
	for _, prim := range []string{"environ.update", "environ.setdefault", "environ.__setitem__", "environ.__delitem__", "environb.update", "environb.setdefault", "environb.__setitem__", "environb.__delitem__", "putenv", "unsetenv"} {
		if toks.hasTokenLike(prim) || toks.hasIdent(prim) {
			return "env override " + prim
		}
	}
	hasDel := toks.hasIdent("del")
	// os.environ['K']=v / environ['K']=v / os.environb[b'K']=v —
	// mask-blanked key re-read raw. `environb` is tried first (longer
	// prefix): an `environ` left-anchored match on `environb` would treat
	// the `b` as a stray identifier byte and skip the receiver.
	for i := 0; i+7 < len(masked); i++ {
		envLen := 0
		if strings.HasPrefix(masked[i:], "environb") {
			envLen = len("environb")
		} else if strings.HasPrefix(masked[i:], "environ") {
			envLen = len("environ")
		}
		if envLen == 0 {
			continue
		}
		if i > 0 && isIdentByte(masked[i-1]) {
			continue
		}
		// `environment`/`environX` are different names, not the receiver.
		if i+envLen < len(masked) && isIdentByte(masked[i+envLen]) {
			continue
		}
		// environ\n.update({...}) / environ.pop('K') spellings: a
		// mutating method after mask whitespace + '.' + whitespace.
		if m := pyEnvironWriteMethodAfter(masked, i+envLen); m != "" {
			return "env override environ." + m
		}
		j := skipMaskSpace(masked, i+envLen)
		lo, hi, ok := maskAssignAfterBracket(masked, j)
		if !ok {
			// No `=` after the bracket — a read, a `del environ['K']`
			// operand (screened below), or a destructuring element:
			// `[a, os.environ['K']] = …` / `os.environ['K'], a = …`
			// writes the env slot through the tuple/list target.
			if j < len(masked) && masked[j] == '[' {
				depth := 0
				for e := j; e < len(masked); e++ {
					if masked[e] == '[' {
						depth++
					}
					if masked[e] == ']' {
						depth--
						if depth == 0 {
							// exprLo walks back from `environ` over the
							// optional `os` + mask space + `.` + mask space
							// qualifier so the enclosing-bracket scan sees
							// the whole receiver expression.
							exprLo := i
							b := i - 1
							for b >= 0 && isMaskSpaceByte(masked[b]) {
								b--
							}
							if b >= 0 && masked[b] == '.' {
								b--
								for b >= 0 && isMaskSpaceByte(masked[b]) {
									b--
								}
								if b >= 1 && masked[b-1] == 'o' && masked[b] == 's' &&
									(b-1 == 0 || !isIdentByte(masked[b-2])) {
									exprLo = b - 1
								}
							}
							if maskDestructAssignTarget(masked, exprLo, e+1, true) {
								key, okKey := unquoteCodeKey(code[j+1 : e])
								if !okKey {
									return "env override dynamic"
								}
								if hit := envOverrideKeyVerdict(key); hit != "" {
									return hit
								}
							}
							break
						}
					}
				}
			}
			if hasDel {
				if hit := pyDelEnvironKeyHit(code, masked, i, envLen); hit != "" {
					return hit
				}
			}
			continue
		}
		key, okKey := unquoteCodeKey(code[lo:hi])
		if !okKey {
			// Dynamic key (variable/expression) — cannot prove the target.
			return "env override dynamic"
		}
		if hit := envOverrideKeyVerdict(key); hit != "" {
			return hit
		}
		i = hi
	}
	return ""
}

// pyEnvironWriteMethodAfter reports whether masked[i] — positioned just
// after an `environ` occurrence — is followed (through mask whitespace)
// by `.` and a mutating method identifier (`update`, `setdefault`,
// `__setitem__`, `pop`, `popitem`, `clear` — `get`/`keys`/iterators are
// reads and stay free). Returns the method name, or "".
func pyEnvironWriteMethodAfter(masked string, i int) string {
	j := skipMaskSpace(masked, i)
	if j >= len(masked) || masked[j] != '.' {
		return ""
	}
	k := skipMaskSpace(masked, j+1)
	start := k
	for k < len(masked) && isIdentByte(masked[k]) {
		k++
	}
	switch masked[start:k] {
	case "update", "setdefault", "__setitem__", "__delitem__", "pop", "popitem", "clear":
		return masked[start:k]
	}
	return ""
}

// pyDelEnvironKeyHit reports whether masked[envIdx] starts `environ` or
// `environb` (envLen = the matched receiver length) used as the operand of
// a `del` statement (`del os.environ['K']`, `del environb[b'K']`) — the
// in-code equivalent of `unset K`. The key is judged by
// envOverrideKeyVerdict; reads (`x in os.environ`, `os.environ.get`) are not
// reached here because the caller only runs this when a `del` ident exists
// somewhere in the masked code AND the subscript is not followed by `=`.
func pyDelEnvironKeyHit(code, masked string, envIdx, envLen int) string {
	// Locate the statement containing envIdx: a `;` or a `\n` at bracket
	// depth 0 ends a statement, while `\n` inside an open `(…`/`[…`/`{…`
	// group or directly behind a `\\` continuation stays inside it — so
	// `del (\nos.environ['K']\n)` and `del \\\nos.environ['K']` still land in
	// their `del` statement. Any earlier `del` ident inside the same
	// statement counts (conservative, same rule as before).
	stmtStart := 0
	depth := 0
	for p := 0; p < envIdx; p++ {
		switch masked[p] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				stmtStart = p + 1
			}
		case '\n':
			if depth == 0 && !pyLineContBefore(masked, p) {
				stmtStart = p + 1
			}
		}
	}
	if !strings.HasPrefix(strings.TrimLeft(masked[stmtStart:], " \t"), "del") &&
		!toksLineHasDel(masked[stmtStart:envIdx]) {
		return ""
	}
	k := skipMaskSpace(masked, envIdx+envLen)
	if k >= len(masked) || masked[k] != '[' {
		return ""
	}
	depth = 0
	for e := k; e < len(masked); e++ {
		if masked[e] == '[' {
			depth++
		}
		if masked[e] == ']' {
			depth--
			if depth == 0 {
				key, okKey := unquoteCodeKey(code[k+1 : e])
				if !okKey {
					return "env override dynamic"
				}
				return envOverrideKeyVerdict(key)
			}
		}
	}
	return ""
}

// pyLineContBefore reports whether masked[nl] (a '\n') is a backslash line
// continuation — a `\\` followed only by ' '/'\t'/'\r'/'\v'/'\f' up to the
// newline.
func pyLineContBefore(masked string, nl int) bool {
	b := nl - 1
	for b >= 0 && (masked[b] == ' ' || masked[b] == '\t' || masked[b] == '\r' || masked[b] == '\v' || masked[b] == '\f') {
		b--
	}
	return b >= 0 && masked[b] == '\\'
}

// toksLineHasDel reports whether the masked segment s contains a `del`
// identifier token.
func toksLineHasDel(s string) bool {
	return codeTokens(s).hasIdent("del")
}

// jsEnvOverrideHit scans masked JavaScript for process.env mutation
// spellings: `process.env.K=v`, `process.env['K']=v`,
// `Object.assign(process.env, …)` / `Object.defineProperty(process.env, …)` /
// `Object.defineProperties(process.env, …)` / `Reflect.set(process.env, …)` /
// `Reflect.defineProperty(process.env, …)` (the qualified names match
// across mask whitespace around the dot — `Object\n.assign`,
// `Object\f.assign`).
func jsEnvOverrideHit(code, masked string) string {
	toks := codeTokens(masked)
	if hasMaskQualCall(masked, "Object", "assign") ||
		hasMaskQualCall(masked, "Object", "defineProperty") ||
		hasMaskQualCall(masked, "Object", "defineProperties") ||
		hasMaskQualCall(masked, "Reflect", "set") ||
		hasMaskQualCall(masked, "Reflect", "defineProperty") ||
		hasMaskQualCall(masked, "Reflect", "deleteProperty") || toks.hasIdent("putenv") {
		if toks.hasIdent("env") || jsProcessEnvAtAny(masked) {
			return "env override"
		}
	}
	// `delete process.env.K` / `delete process.env['K']` — an env CLEAR,
	// the in-code equivalent of `unset K`/`env -u K`.
	if toks.hasIdent("delete") {
		if hit := jsDeleteEnvHit(code, masked); hit != "" {
			return hit
		}
	}
	for i := 0; i+7 < len(masked); i++ {
		j := jsProcessEnvAt(masked, i)
		if j < 0 {
			continue
		}
		if i > 0 && isIdentByte(masked[i-1]) {
			continue
		}
		j = skipMaskSpace(masked, j)
		if j >= len(masked) {
			break
		}
		if masked[j] == '[' {
			lo, hi, ok := maskAssignAfterBracket(masked, j)
			if !ok {
				// No direct write op — still a destructuring element when
				// an enclosing literal group takes the `=`:
				// `[a, process.env['K']] = …` writes the env slot. The
				// py flag stays off: a JS comma makes a sequence
				// expression or a multi-declarator, never a bare tuple
				// destructuring target, and `x\n[y]` still subscripts.
				depth := 0
				for e := j; e < len(masked); e++ {
					if masked[e] == '[' {
						depth++
					}
					if masked[e] == ']' {
						depth--
						if depth == 0 {
							if maskDestructAssignTarget(masked, i, e+1, false) {
								key, okKey := unquoteCodeKey(code[j+1 : e])
								if !okKey {
									return "env override dynamic"
								}
								if hit := envOverrideKeyVerdict(key); hit != "" {
									return hit
								}
							}
							break
						}
					}
				}
				i = j
				continue
			}
			key, okKey := unquoteCodeKey(code[lo:hi])
			if !okKey {
				return "env override dynamic"
			}
			if hit := envOverrideKeyVerdict(key); hit != "" {
				return hit
			}
			i = hi
			continue
		}
		if masked[j] != '.' {
			i = j
			continue
		}
		k := skipMaskSpace(masked, j+1)
		start := k
		for k < len(masked) && isIdentByte(masked[k]) {
			k++
		}
		name := masked[start:k]
		if name == "" {
			i = k
			continue
		}
		// process.env.NAME <op>= v — plain `=` or a compound write op
		// (shared maskAssignOpAt; `NAME == v`/`NAME ?? v` stay reads).
		// Whitespace-wrapped closing `)`s are transparent too:
		// `(process.env.K)\n = v` writes the member all the same.
		k = skipMaskSpace(masked, k)
		for k < len(masked) && masked[k] == ')' {
			k = skipMaskSpace(masked, k+1)
		}
		if maskAssignOpAt(masked, k) {
			if hit := envOverrideKeyVerdict(name); hit != "" {
				return hit
			}
		} else if maskDestructAssignTarget(masked, i, k, false) {
			// `({p: process.env.K} = …)` writes the member through the
			// enclosing destructuring literal.
			if hit := envOverrideKeyVerdict(name); hit != "" {
				return hit
			}
		}
		i = k
	}
	return ""
}

// jsProcessEnvAt reports whether masked[i] begins the `process.env`
// receiver, tolerating mask whitespace around the dot
// (`process\n.env.K`). Returns the index just past `env`, or -1.
func jsProcessEnvAt(masked string, i int) int {
	if !strings.HasPrefix(masked[i:], "process") {
		return -1
	}
	j := skipMaskSpace(masked, i+len("process"))
	if j >= len(masked) || masked[j] != '.' {
		return -1
	}
	j = skipMaskSpace(masked, j+1)
	if !strings.HasPrefix(masked[j:], "env") {
		return -1
	}
	// `environment`/`envX` are a different property, not the receiver.
	if j+len("env") < len(masked) && isIdentByte(masked[j+len("env")]) {
		return -1
	}
	return j + len("env")
}

// hasMaskQualCall reports whether masked contains `recv.method` as a
// qualified call spelling with mask whitespace tolerated around the dot
// (`Object\n.assign`, `Object\f.assign`). Both edges are identifier
// boundaries: a `myObject.assign` or `Object.assignX` does not count.
func hasMaskQualCall(masked, recv, method string) bool {
	idx := 0
	for {
		k := strings.Index(masked[idx:], recv)
		if k < 0 {
			return false
		}
		pos := idx + k
		if pos > 0 && isIdentByte(masked[pos-1]) {
			idx = pos + len(recv)
			continue
		}
		j := skipMaskSpace(masked, pos+len(recv))
		if j >= len(masked) || masked[j] != '.' {
			idx = pos + len(recv)
			continue
		}
		m := skipMaskSpace(masked, j+1)
		if strings.HasPrefix(masked[m:], method) &&
			(m+len(method) >= len(masked) || !isIdentByte(masked[m+len(method)])) {
			return true
		}
		idx = pos + len(recv)
	}
}

// jsProcessEnvAtAny reports whether the `process.env` receiver occurs
// anywhere in masked (whitespace around the dots tolerated, identifier
// boundaries respected — unlike a bare substring scan).
func jsProcessEnvAtAny(masked string) bool {
	for i := 0; i+7 < len(masked); i++ {
		if i > 0 && isIdentByte(masked[i-1]) {
			continue
		}
		if jsProcessEnvAt(masked, i) >= 0 {
			return true
		}
	}
	return false
}

// jsDeleteEnvHit screens `delete process.env.<key>` spellings: the key is
// judged by envOverrideKeyVerdict — hook/taint/sentinel names and
// unverifiable dynamic keys block, benign names pass (an env delete the
// spawn never needed).
func jsDeleteEnvHit(code, masked string) string {
	for i := 0; i+6 < len(masked); i++ {
		if !strings.HasPrefix(masked[i:], "delete") {
			continue
		}
		if i > 0 && isIdentByte(masked[i-1]) {
			continue
		}
		// A `.` immediately before the `delete` ident is member access —
		// `x.delete` is an ordinary property/method name, not the unary
		// operator — while member access does NOT continue across mask
		// whitespace, so a real unary `delete` on the next statement still
		// screens. Checking only the adjacent byte keeps
		// `api.delete\nconsole.log(process.env.K)` free and blocks
		// `let q=1.\ndelete process.env.K` (the `.` glues to `1.`).
		if i > 0 && masked[i-1] == '.' {
			continue
		}
		j := skipMaskSpace(masked, i+len("delete"))
		k := jsProcessEnvAt(masked, j)
		if k < 0 {
			continue
		}
		k = skipMaskSpace(masked, k)
		if k >= len(masked) {
			break
		}
		if masked[k] == '[' {
			depth := 0
			for e := k; e < len(masked); e++ {
				if masked[e] == '[' {
					depth++
				}
				if masked[e] == ']' {
					depth--
					if depth == 0 {
						key, okKey := unquoteCodeKey(code[k+1 : e])
						if !okKey {
							return "env override dynamic"
						}
						if hit := envOverrideKeyVerdict(key); hit != "" {
							return hit
						}
						break
					}
				}
			}
			i = k
			continue
		}
		if masked[k] != '.' {
			i = k
			continue
		}
		start := skipMaskSpace(masked, k+1)
		e := start
		for e < len(masked) && isIdentByte(masked[e]) {
			e++
		}
		if hit := envOverrideKeyVerdict(masked[start:e]); hit != "" {
			return hit
		}
		i = e
	}
	return ""
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

// stripLeadingCodeComments removes leading whitespace and the run of top
// comments (`#...`, `//...`, `/*...*/`) at the very start of a foreign-
// language code buffer, so the first REAL statement head can be read.
// Only the top of the buffer is stripped — a later comment, string literal
// or docstring is never touched (a Python ”'docstring”' mid-file is data).
func stripLeadingCodeComments(code string) string {
	for {
		// Drop leading whitespace (incl. newlines) first.
		code = strings.TrimLeft(code, " \t\r\n")
		switch {
		case strings.HasPrefix(code, "//"):
			if k := strings.IndexByte(code, '\n'); k >= 0 {
				code = code[k+1:]
			} else {
				return ""
			}
		case strings.HasPrefix(code, "#"):
			if k := strings.IndexByte(code, '\n'); k >= 0 {
				code = code[k+1:]
			} else {
				return ""
			}
		case strings.HasPrefix(code, "/*"):
			if k := strings.Index(code, "*/"); k >= 0 {
				code = code[k+2:]
			} else {
				return ""
			}
		default:
			return code
		}
	}
}

// headWord matches [A-Za-z0-9_-]+ — a whole command word including the '-'
// inside "herdr-core" (so it is never split on the dash).
func headWord(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' {
			i++
			continue
		}
		break
	}
	return s[:i]
}

// infixWord reports whether w is a language infix/modifier keyword that may
// legitimately follow an identifier in a first statement head (so
// `hc and x`, `hc in xs`, `hc if cond` are not agent invocations).
var infixWord = map[string]bool{
	"and": true, "or": true, "is": true, "in": true, "not": true,
	"if": true, "else": true, "unless": true, "until": true, "while": true,
	"for": true, "as": true, "instanceof": true,
}

// codeHeadIsAgentInvocation reports whether the first statement head of a
// foreign-language code buffer is an agent command invocation: a first word
// that is exactly hc / herdr-core / herdr / herdsman / dispatch-report
// followed by horizontal
// whitespace and an option/quote/non-keyword argument. This catches a bare
// `hc send t42 ...` fed to `python3 -`/`ruby -`/`perl -` stdin or `-c`, where
// the foreign runtime never spawns a recognisable primitive — a defence-in-
// depth fail-closed check independent of the spawn-primitive scan (the
// program is not rewritten to --hc-gate because 1114E keeps foreign stdin
// verbatim data).
func codeHeadIsAgentInvocation(code string) (string, bool) {
	head := stripLeadingCodeComments(code)
	w := headWord(head)
	switch w {
	case "hc", "herdr-core", "herdr", "herdsman", "dispatch-report":
	default:
		return "", false
	}
	rest := head[len(w):]
	// Require 1+ horizontal whitespace chars after the name (`hc  send`
	// must hit, `hc=5`/`hc(x)` must not).
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return "", false
	}
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return "", false
	}
	c := rest[0]
	switch {
	case c == '"' || c == '\'':
		return w, true // hc "send", hc 'send'
	case strings.HasPrefix(rest, "--"):
		return w, true // hc -- send, hc --x
	case c == '-' && len(rest) > 1 && rest[1] >= 'a' && rest[1] <= 'z':
		return w, true // hc -h (but not `hc - 1` / `hc -1`)
	case c == '-' && len(rest) > 1 && rest[1] >= 'A' && rest[1] <= 'Z':
		return w, true
	}
	// An identifier argument (send, kill, t42-free word) that is not a
	// language infix keyword means the name was used as a command.
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
		arg := headWord(rest)
		if !infixWord[arg] {
			return w, true
		}
	}
	return "", false
}

func (g guardCall) guardCtxRunCode(language, code string) (rule, detail string) {
	if !g.subagent && !g.strictReadonly {
		return "", ""
	}
	masked := code
	var jsBinds codeSpawnBindings
	switch language {
	case "python":
		masked = pythonMask(code)
	case "javascript", "typescript":
		masked = jsMask(code)
		jsBinds = jsSpawnBindings(code, masked)
	}
	toks := codeTokens(normCallSpace(masked))
	caller := g.callerIdentity()

	if g.subagent {
		// Statement-head check: a bare `hc send …` / `herdr-core …` as the
		// first statement of foreign-language code never reaches a spawn
		// primitive (it is a SyntaxError at runtime), so the spawn-gated
		// hasIdent block below cannot see it. Fail closed here — the check
		// only fires on a real command head, so `hc = 5`, `--hc-gate`
		// literals and `fix/hc-feedback-gate` strings stay free.
		if name, ok := codeHeadIsAgentInvocation(code); ok {
			return ruleSubagentNestedAgent, "code statement head invokes " + name
		}
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
		if !spawn && (language == "javascript" || language == "typescript") &&
			(rawToks.hasIdent("child_process") || len(jsBinds.names) > 0 || jsBinds.unresolved) {
			spawn = true
		}
		if spawn {
			argvs, shellCmds, allResolved := codeStaticSpawnsDetailed(language, code)
			for _, argv := range argvs {
				if hit := peelResolvedDepth(argv, 's', 0, caller); hit != "" {
					if hit == "ctxmode index" || hit == roSSHWriteHit {
						return ruleReadonlyWrite, hit
					}
					return ruleSubagentNestedAgent, hit
				}
				if _, isProg, _, _ := stdinProgramHeadWithEnv(argv, 0, envAssignments{}, caller.pathEnv, caller); isProg {
					if g.readonly && !g.strictReadonly && sshTunnelsStdinProgram(argv, caller.pathEnv, caller) {
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
			// An env-override write inside code (os.environ['X']=…,
			// process.env.X=…, environ.update/putenv/Object.assign) reaches
			// the spawned child's environment exactly like an `export`
			// prefix: hook/taint names must block, and an unverifiable
			// (dynamic) target fails closed.
			if hit := codeEnvOverrideHit(language, code, masked); hit != "" {
				return ruleSubagentNestedAgent, hit
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
			if hit := screenReadonlyWritePath(argv, "", caller); hit != "" {
				return ruleReadonlyWrite, hit
			}
			return ruleReadonlyWrite, "spawn primitive " + filepath.Base(argv[0])
		}
		for _, prim := range codeSpawnPrims {
			if (language == "javascript" || language == "typescript") && prim == "exec(" {
				continue
			}
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
			if pythonHasBareOpenIdent(masked) {
				return ruleReadonlyWrite, "write primitive open"
			}
		}
		if (language == "javascript" || language == "typescript") &&
			(len(jsBinds.names) > 0 || jsBinds.unresolved || toks.hasTokenLike("child_process")) {
			return ruleReadonlyWrite, "spawn primitive child_process"
		}
		if language == "javascript" || language == "typescript" {
			if hit := jsUnicodeIdentEscapeHit(code); hit != "" {
				return ruleReadonlyWrite, hit
			}
			if hit := jsFsOpenWriteHit(code); hit != "" {
				return ruleReadonlyWrite, hit
			}
		}
		for _, prim := range codeWritePrims {
			if toks.hasTokenLike(prim) {
				return ruleReadonlyWrite, "write primitive " + prim
			}
		}
		if hit := strictReadonlyCodeAllowlistHit(language, code); hit != "" {
			return ruleReadonlyWrite, hit
		}
	}
	return "", ""
}

var codeSpawnKeywords = map[string][]string{
	"python": {
		"subprocess", // subprocess.run / .Popen / .call / .check_output
		"os.system", "os.popen", "os.exec", "os.spawn",
		"os.posix_spawn", "os.posix_spawnp", "pty.spawn",
		"system", "popen", "posix_spawn", "posix_spawnp",
		"execv", "execve", "execl", "execle", "execlp", "execvp", "execvpe",
		"spawnl", "spawnle", "spawnlp", "spawnlpe",
		"spawnv", "spawnve", "spawnvp", "spawnvpe", "spawn",
	},
	"javascript": {
		"child_process", // require('child_process').execFileSync / .execSync / .fork
		"exec", "execSync", "spawnSync", "execFileSync", "spawnFileSync",
		"execFile", "spawn", "fork", "Bun.spawn", "Bun.spawnSync", "Deno.Command",
	},
}

var codeSpawnNonCallNeutral = map[string]bool{
	"system": true, "popen": true, "posix_spawn": true, "posix_spawnp": true,
	"execv": true, "execve": true, "execl": true, "execle": true,
	"execlp": true, "execvp": true, "execvpe": true,
	"spawnl": true, "spawnle": true, "spawnlp": true, "spawnlpe": true,
	"spawnv": true, "spawnve": true, "spawnvp": true, "spawnvpe": true,
	"spawn": true, "exec": true, "fork": true,
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
// getstatusoutput, system, popen, exec*, spawn*, posix_spawn*).
func pythonSpawnSym(name string) bool {
	switch name {
	case "run", "Popen", "call", "check_call", "check_output",
		"getoutput", "getstatusoutput", "system", "popen":
		return true
	}
	return strings.HasPrefix(name, "exec") || strings.HasPrefix(name, "spawn") ||
		strings.HasPrefix(name, "posix_spawn")
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
				name+".system", name+".popen", name+".exec", name+".spawn",
				name+".posix_spawn", name+".posix_spawnp")
		case "pty":
			keywords = append(keywords, name+".spawn")
		default: // "fn": a bound spawn function name
			keywords = append(keywords, name)
		}
	}
	unresolved := binds.unresolved
	seenCalls := map[int]bool{}
	for _, kw := range keywords {
		bare := true
		if d := strings.IndexByte(kw, '.'); d >= 0 {
			bare = false
			if !strings.Contains(kw[d+1:], ".") {
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
				continue
			}
			open := callOpenAfter(masked, end)
			if open < 0 {
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
				p := i - 1
				for p >= 0 && (masked[p] == ' ' || masked[p] == '\t') {
					p--
				}
				if p >= 0 && masked[p] == '.' {
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
					} else if q < 0 || (masked[q] != ')' && masked[q] != ']') {
						// Skip non-call/non-index receivers like regex `/pat/.exec(s)`.
						continue
					}
				}
			}
			seenCalls[open] = true
			lo, hi, closed := callInnerBounds(masked, open)
			if !closed {
				unresolved = true
				continue
			}
			cArgvs, cShells, ok := staticSpawnCalls(language, code[lo:hi], masked[lo:hi])
			if !ok {
				unresolved = true
				continue
			}
			argvs = append(argvs, cArgvs...)
			shellCmds = append(shellCmds, cShells...)
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
				if k != "args" && k != "cmd" && k != "command" {
					continue
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
	startIdx := 0
	if len(operands) >= 2 && (strings.HasPrefix(firstOp, "os.P_") || firstOp == "0" || firstOp == "1") {
		startIdx = 1
		firstOp = operands[1]
	}
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
		if listArgv, ok := staticArgvListAllowEmpty(secondOp); ok {
			if len(listArgv) >= 1 && filepath.Base(lit) == filepath.Base(listArgv[0]) {
				return append([]string{lit}, listArgv[1:]...), "", true
			}
			return append([]string{lit}, listArgv...), "", true
		}
		var varArgs []string
		allLit := true
		for idx := startIdx + 1; idx < len(operands); idx++ {
			op := operands[idx]
			if strings.Contains(op, "=") && !strings.HasPrefix(op, "'") && !strings.HasPrefix(op, "\"") {
				break
			}
			if strings.HasPrefix(op, "{") && strings.HasSuffix(op, "}") {
				// Trailing env dict in os.posix_spawn(path, argv, {}) or os.execle(..., {}).
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
	if shellMode || strings.ContainsAny(lit, "'\"\\$`*|;&") {
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
	flag       int
	text       string
	flagOnly   bool
	module     bool // the slot is a python -m module operand, not inline code
	dynOperand bool // the slot text is a dynamic script-operand word, not literal code
	restIdx    int  // argv index where the operands AFTER this slot begin
}

// interpOptSpec is one interpreter's CLI option grammar.
type interpOptSpec struct {
	gluedCodes       string
	flagCodes        string
	valShort         string
	optShort         string
	optNumShort      string
	longCode         map[string]bool
	longBool         map[string]bool
	longValue        map[string]bool
	dynScriptOperand bool
	stopOnFirstCode  bool
	strictLong       bool
}

// lookupInterpOptSpec returns the CLI option grammar for an interpreter or
// shell head, or false when the head has no inline-code surface.
func lookupInterpOptSpec(base string) (interpOptSpec, bool) {
	spec := interpOptSpec{}
	switch {
	case isPythonInterpBase(base):
		// CPython: glued -c/-m, valued -W/-X; the legal long options are the
		// zero-arg queries plus --check-hash-based-pycs (PEP 552). Every other
		// `--` word fails closed — its arity is unknowable statically. CPython
		// stops parsing its own options at the first -c/-m.
		spec.gluedCodes, spec.valShort = "cm", "WX"
		spec.longBool = map[string]bool{"--help": true, "--help-env": true, "--help-xoptions": true, "--help-all": true, "--version": true}
		spec.longValue = map[string]bool{"--check-hash-based-pycs": true}
		spec.dynScriptOperand, spec.stopOnFirstCode, spec.strictLong = true, true, true
	case base == "node" || base == "nodejs":
		// node clusters are flag-parsed: -pe is -p -e and the code operand
		// is the next argv; -e/-p never glue their operand. -r takes a
		// module operand (tail or next argv), -C is --conditions' short
		// alias. The readonly-plumbing long values (--title/--env-file/
		// ...) live HERE in the single spec source so the four scanner
		// families cannot drift apart (v6.2.2 R3 R3-SF-1).
		spec.flagCodes, spec.valShort = "ep", "rC"
		spec.longCode = map[string]bool{"--eval": true, "--print": true}
		spec.longValue = map[string]bool{"--require": true, "--loader": true, "--import": true, "--experimental-loader": true, "--conditions": true, "--input-type": true,
			"--title": true, "--env-file": true, "--env-file-if-exists": true, "--redirect-warnings": true, "--diagnostic-dir": true, "--watch-path": true}
		spec.dynScriptOperand = true
	case base == "bun":
		// bun -e/--eval/-p/--print carry inline code; -r preloads a module and
		// -c names a bunfig file, so neither is a shell-style code flag.
		spec.flagCodes, spec.valShort = "ep", "rc"
		spec.longCode = map[string]bool{"--eval": true, "--print": true}
		spec.longValue = map[string]bool{"--require": true, "--preload": true, "--import": true, "--loader": true, "--cwd": true, "--config": true, "--env-file": true, "--conditions": true, "--define": true, "--target": true, "--tsconfig-override": true}
		spec.dynScriptOperand = true
	case base == "ts-node" || base == "tsx":
		// ts-node/tsx support node's -e/-p inline-code spellings; -r/-P/-O
		// consume module/project/compilerOptions operands.
		spec.flagCodes, spec.valShort = "ep", "rPO"
		spec.longCode = map[string]bool{"--eval": true, "--print": true}
		spec.longValue = map[string]bool{"--require": true, "--loader": true, "--import": true, "--project": true, "--compiler-options": true, "--tsconfig": true}
		spec.dynScriptOperand = true
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
		spec.gluedCodes, spec.valShort, spec.optShort, spec.optNumShort = "eE", "MmI", "iF7x", "l0"
		spec.dynScriptOperand = true
	case base == "ruby":
		// Same split for ruby: -F/-K/-C/-X/-r/-I require operands (K eats
		// its single coding char); -i/-x take arbitrary optional-glued
		// tails while -0 is the restricted numeric kind (`ruby -0e CODE`
		// still reaches -e).
		spec.gluedCodes, spec.valShort, spec.optShort, spec.optNumShort = "e", "FKCXrI", "ix", "0"
		spec.dynScriptOperand = true
	case base == "php":
		spec.gluedCodes, spec.valShort = "r", "cdz"
		spec.dynScriptOperand = true
	case shellHeads[base]:
		// dash/bash/zsh/ksh flag-model -c; -o/-O consume an option-name
		// operand (cluster tail or next argv); bash's --rcfile/--init-file
		// consume a file operand that must not pose as the first script
		// word (v6.2.2 MF-4b).
		spec.flagCodes, spec.valShort = "c", "oO"
		spec.longValue = map[string]bool{"--rcfile": true, "--init-file": true}
	default:
		return spec, false
	}
	if spec.longCode == nil {
		spec.longCode = map[string]bool{}
	}
	if spec.longValue == nil {
		spec.longValue = map[string]bool{}
	}
	if spec.longBool == nil {
		spec.longBool = map[string]bool{}
	}
	return spec, true
}

// scanLongOpt screens one `--` word of the option zone and returns the
// index of the LAST argv word the option consumes (the loop advances past
// it). stop reports that the option scan must end here: either because a
// strict-arity long option failed validation (an open code slot is emitted
// fail-closed) or because a pending flag-model code letter cannot take an
// option word as its operand.
func (spec interpOptSpec) scanLongOpt(argv []string, i int, pendingCode bool) (slot codeSlot, hasSlot bool, nextIdx int, stop bool) {
	if pendingCode {
		return codeSlot{}, false, i, true // an option still cannot be -c's operand
	}
	a := argv[i]
	name, val, hasVal := a[2:], "", false
	if k := strings.IndexByte(name, '='); k >= 0 {
		name, val, hasVal = name[:k], name[k+1:], true
	}
	opt := "--" + name
	if spec.longCode[opt] {
		slot.flag = i
		switch {
		case hasVal:
			slot.text, slot.restIdx = val, i+1
		case i+1 < len(argv):
			slot.text, slot.restIdx, nextIdx = argv[i+1], i+2, i+1
		default:
			slot.flagOnly, slot.restIdx = true, i+1
		}
		return slot, true, nextIdx, false
	}
	if spec.longValue[opt] {
		if opt == "--check-hash-based-pycs" {
			valid := false
			if hasVal {
				valid = isValidPycsMode(val)
			} else if i+1 < len(argv) && !isDynamicArg(argv[i+1]) && isValidPycsMode(argv[i+1]) {
				nextIdx = i + 1
				valid = true
			}
			if !valid {
				// A missing/dynamic/illegal mode means the scanner cannot tell
				// how many operands the option consumes — fail closed with an
				// open code slot and end the scan.
				return codeSlot{flag: i, flagOnly: true}, true, i, true
			}
			return codeSlot{}, false, nextIdx, false
		}
		if !hasVal && i+1 < len(argv) {
			nextIdx = i + 1 // consumes the separate value operand
		}
		return codeSlot{}, false, nextIdx, false
	}
	if spec.strictLong {
		if spec.longBool[opt] && !hasVal {
			return codeSlot{}, false, i, false
		}
		// Unknown long option (or a glued value on a zero-arg query): its
		// operand arity is unknowable — fail closed, end the scan.
		return codeSlot{flag: i, flagOnly: true}, true, i, true
	}
	return codeSlot{}, false, i, false // boolean or unknown long option
}

// scanShortCluster scans one short-option cluster word and returns the code
// slots it exposes. pending reports a flag-model code letter whose operand
// is the next argv word after the whole cluster scan finishes.
func (spec interpOptSpec) scanShortCluster(argv []string, i int) (slots []codeSlot, nextIdx int, pending bool) {
	a := argv[i]
	nextIdx = i
	plus := a[0] == '+'
	isPy := isPythonInterpBase(filepath.Base(argv[0]))
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if !plus && strings.IndexByte(spec.gluedCodes, ch) >= 0 {
			slot := codeSlot{flag: i, module: isPy && ch == 'm'}
			if tail := a[j+1:]; tail != "" {
				slot.text, slot.restIdx = tail, i+1
			} else if i+1 < len(argv) {
				slot.text, slot.restIdx, nextIdx = argv[i+1], i+2, i+1
			} else {
				slot.flagOnly, slot.restIdx = true, i+1
			}
			slots = append(slots, slot)
			break
		}
		if !plus && strings.IndexByte(spec.flagCodes, ch) >= 0 {
			// Flag-model code letter: the operand is the next argv word
			// after the cluster scan. A non-empty tail is an ambiguous
			// glued spelling (ksh/zsh may read it as the operand —
			// `-cpig`) so it is ALSO screened as code while its letters
			// keep being parsed as flags (`-ce` needs the next argv too).
			pending = true
			if tail := a[j+1:]; tail != "" {
				slots = append(slots, codeSlot{flag: i, text: tail, restIdx: i + 1})
				if !isLetterOnly(tail) {
					break // ambiguous glued operand — not flag letters
				}
			}
			continue
		}
		if strings.IndexByte(spec.valShort, ch) >= 0 {
			if j+1 >= len(a) {
				nextIdx = i + 1 // value is the next argv
			}
			break // value letters end the cluster either way
		}
		if strings.IndexByte(spec.optNumShort, ch) >= 0 {
			// Restricted numeric tail: consume its legal bytes, then RESUME
			// the cluster — `perl -0e` is -0 -e, so the e must not be eaten
			// as a value.
			j += consumeNumOptTail(a, j, ch)
			continue
		}
		if strings.IndexByte(spec.optShort, ch) >= 0 {
			if j+1 >= len(a) {
				continue // bare optional-value flag — consumes no argv
			}
			break // glued value ends the cluster
		}
	}
	return slots, nextIdx, pending
}

// isDynScriptCodeOperand reports whether a dynamic word in first-operand
// position is inline code (true) or a split-safe path-shaped script-file
// operand (false — the option scan ends there, Q1-C).
func isDynScriptCodeOperand(a string) bool {
	if isSafeDynamicDataOperand(a) &&
		(strings.Contains(a, "/") || strings.HasPrefix(a, "/") ||
			strings.HasPrefix(a, cmdSubPlaceholderAbsDq) || hasInterpScriptExt(a)) {
		return false
	}
	return true
}

func interpCodeSlots(argv []string) []codeSlot {
	if len(argv) < 2 {
		return nil
	}
	spec, ok := lookupInterpOptSpec(filepath.Base(argv[0]))
	if !ok {
		return nil
	}
	st := interpScanState{spec: spec}
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "--") {
			if st.scanLongWord(argv, i, &i) {
				return st.out
			}
			continue
		}
		if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") || a == "-" || a == "+" {
			if st.scanOperandWord(argv, i) {
				return st.out
			}
			continue
		}
		if st.scanClusterWord(argv, i, &i) {
			return st.out
		}
	}
	if st.pendingCode {
		// A trailing flag-model code letter with no operand word: the fed
		// text lands here (xargs model) — mark the open slot.
		st.out = append(st.out, codeSlot{flag: len(argv) - 1, flagOnly: true, restIdx: len(argv)})
	}
	return st.out
}

// interpScanState carries interpCodeSlots' scan registers so the per-word
// handlers stay small enough to review independently.
type interpScanState struct {
	spec        interpOptSpec
	out         []codeSlot
	pendingCode bool
}

// scanLongWord handles one `--` word (and the `--` terminator); done reports
// the scan must end — either the option terminator, an early stopOnFirstCode
// return, or a strict-long validation failure. Words that are not long
// options leave the loop index untouched.
func (st *interpScanState) scanLongWord(argv []string, i int, idx *int) bool {
	a := argv[i]
	if a == "--" {
		if st.pendingCode {
			// A pending flag-model code letter of a POSIX shell survives the
			// `--` terminator: -c is boolean there, so the word right after
			// `--` IS the command string (`sh -co errexit -- 'pig'` —
			// v6.2.2 Oracle R6 R6-MF-1). No word at all means the fed text
			// lands in the open slot (xargs `-a` append mode
			// `xargs -a <p> sh -c --`).
			if i+1 < len(argv) {
				st.out = append(st.out, codeSlot{flag: i + 1, text: argv[i+1], restIdx: i + 2})
			} else {
				st.out = append(st.out, codeSlot{flag: i, flagOnly: true, restIdx: i + 1})
			}
		}
		return true // option terminator
	}
	if !strings.HasPrefix(a, "--") {
		return false
	}
	slot, hasSlot, nextIdx, stop := st.spec.scanLongOpt(argv, i, st.pendingCode)
	if hasSlot {
		st.out = append(st.out, slot)
	}
	if nextIdx > i {
		*idx = nextIdx // consumed a separate value operand
	}
	// stopOnFirstCode must not drop a LATER -c/-m still inside argv — a
	// strict-long validation failure is not CPython's own -c/-m either.
	// The only stopOnFirstCode interpreter (CPython) has no longCode table,
	// so a long-option word can never produce a code slot here: reaching
	// this line with stop==false means the scan simply continues.
	return stop
}

// scanOperandWord handles a non-option operand word (including a bare "-"
// stdin marker); done reports the scan must end — operands always terminate
// the option zone except for the pending flag-model code operand itself.
func (st *interpScanState) scanOperandWord(argv []string, i int) bool {
	a := argv[i]
	if strings.HasPrefix(a, "-") && a != "-" || strings.HasPrefix(a, "+") && a != "+" {
		return false
	}
	if st.pendingCode && shellOptSpecHasPlus(st.spec) && (a == "-" || a == "+") {
		// POSIX: a bare "-"/"+" argument terminates option parsing exactly
		// like "--" — with a pending shell -c it is NOT the command string
		// but the terminator, and the word right AFTER it carries the code
		// (v6.2.2 Oracle R7 R7-MF-3 path B `sh -c - 'pig'` / xargs `-a`
		// append mode `xargs -a <p> sh -c -`). Settling it as the operand
		// itself emitted an inert "-" slot and dropped the real payload.
		if i+1 < len(argv) {
			st.out = append(st.out, codeSlot{flag: i + 1, text: argv[i+1], restIdx: i + 2})
		} else {
			st.out = append(st.out, codeSlot{flag: i, flagOnly: true, restIdx: i + 1})
		}
		return true
	}
	if st.pendingCode {
		// The pending flag-model code operand IS this word
		// (`sh -c code`, `node -pe code`): argv0/positional-name
		// words that follow are already covered — a second
		// non-option operand ends the zone.
		st.out = append(st.out, codeSlot{flag: i, text: a, restIdx: i + 1})
		if st.spec.stopOnFirstCode {
			return true
		}
		st.pendingCode = false
		return false
	}
	if st.spec.dynScriptOperand && isDynamicArg(a) {
		// SH11 MF-2: a split-safe path-shaped word is the script-file
		// operand, not inline code — end the option scan (Q1-C). Any
		// other dynamic word in operand position may BE the code text
		// (xargs replace-token / $X eval) — screen it.
		if isDynScriptCodeOperand(a) {
			st.out = append(st.out, codeSlot{flag: i, text: a, dynOperand: true, restIdx: i + 1})
		}
	}
	return true // first non-option operand: the script file ends the zone
}

// scanClusterWord handles one short-option cluster word; done reports an
// early stopOnFirstCode return.
func (st *interpScanState) scanClusterWord(argv []string, i int, idx *int) bool {
	a := argv[i]
	if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") || a == "-" || a == "+" {
		return false
	}
	if strings.HasPrefix(a, "--") {
		return false
	}
	slots, nextIdx, pending := st.spec.scanShortCluster(argv, i)
	*idx = nextIdx
	if len(slots) > 0 {
		st.out = append(st.out, slots...)
		if st.spec.stopOnFirstCode {
			return true
		}
	}
	if pending {
		st.pendingCode = true
	}
	return false
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

// xargsFeedsCodeFlag reports whether the stdin words an xargs invocation
// feeds its target command can land in an open inline-code slot (-c/-e
// whose operand has not been supplied yet) or in a replace-token exec slot.
// Command indirection layers (xargs / flock / watch -x / ssh / find -exec)
// are descended with a bounded depth; exceeding it fails closed.
func xargsFeedsCodeFlag(inner, full []string, pathEnv string, caller callerIdentity) bool {
	return xargsFeedsCodeFlagDepth(inner, full, pathEnv, caller, 0)
}

// xargsFeedsCodeFlagDepth is the bounded-depth worker of
// xargsFeedsCodeFlag. The repl-token screen is shared with
// replTokenInExecSlotDepth so the two feeds cannot drift, and a dangling
// wrapper or wrapper-only target (xargs env) fails closed — the stdin words
// would become the command head itself.
// R21-Reviewer-5: every entry recomputes NOTHING — a normalized state
// cache keys (depth, inner argv, replacement-token context) so a repeated
// descent returns the memoized verdict instead of redoing the same
// peel/LookPath cascade, and a single-request step budget caps the total
// number of distinct nodes evaluated (fail-closed once exceeded): the
// append-mode merge in xargsNestedFeedsCodeSlot already removes the
// per-level doubling, but replacement-token branch shapes can still fan
// out, so the budget is the hard ceiling the depth cap alone never was.
//
// R22-Reviewer-#1 / R22-Oracle-M5: the cache and counter belong to ONE
// analysis REQUEST, never to the process — the pre-R22 package-level
// table let a concurrent second request reset the table underneath a
// first request's in-flight computation, so the first request then
// published verdicts into the second request's memo (and the key did
// not even carry the resolution context). The state is minted once per
// top-level guard entry and threaded through callerIdentity, so two
// parallel requests are naturally isolated WITHOUT any cross-request
// lock ordering; the mutex only defends the table against shared-caller
// misuse. Every xargs descent of the same request shares the one
// 512-node budget, exactly the single-request ceiling the audit asked
// for.
type xargsWorkState struct {
	mu    sync.Mutex
	memo  map[string]bool
	steps int
}

// xargsWork returns the request-scoped memo/budget state of one caller
// identity, allocating it lazily. A zero caller (direct unit screening
// that never went through a guard entry) mints a FRESH state per call —
// correct if occasionally under-shared, never cross-request.
func xargsWork(c callerIdentity) *xargsWorkState {
	if c.xw != nil {
		return c.xw
	}
	return &xargsWorkState{}
}

// xargsWorkMemoKey normalizes one recursion state. R22-Reviewer-#1: the
// key MUST disambiguate every input the verdict depends on — the depth,
// the inner argv, the replacement token the outer invocation carries
// (the ONLY input outerXargs contributes), PLUS the resolution context
// the peel/LookPath cascade reads: the effective PATH of this layer and
// the caller's cwd. Two descents that agree on argv but resolve under
// different directories or search paths are different questions and must
// never share a memo entry.
func xargsWorkMemoKey(depth int, inner, outerXargs []string, pathEnv, cwd string) string {
	return strconv.Itoa(depth) + "\x00" + strings.Join(inner, "\x01") +
		"\x00" + xargsReplToken(outerXargs) + "\x00" + pathEnv + "\x00" + cwd
}

const xargsWorkBudget = 512

func xargsFeedsCodeFlagDepth(inner, outerXargs []string, pathEnv string, caller callerIdentity, depth int) bool {
	if len(inner) == 0 {
		return false
	}
	if depth >= peelChainMaxDepth {
		return true
	}
	ws := xargsWork(caller)
	key := xargsWorkMemoKey(depth, inner, outerXargs, pathEnv, caller.cwd)
	ws.mu.Lock()
	if ws.memo == nil {
		ws.memo = map[string]bool{}
	}
	if v, ok := ws.memo[key]; ok {
		ws.mu.Unlock()
		return v
	}
	if ws.steps >= xargsWorkBudget {
		// Single-request budget ceiling: fail closed rather than pay an
		// attacker-shaped re-peel cascade.
		ws.mu.Unlock()
		return true
	}
	ws.steps++
	ws.mu.Unlock()
	verdict := xargsFeedsCodeFlagWork(inner, outerXargs, pathEnv, caller, depth)
	ws.mu.Lock()
	ws.memo[key] = verdict
	ws.mu.Unlock()
	return verdict
}

func xargsFeedsCodeFlagWork(inner, outerXargs []string, pathEnv string, caller callerIdentity, depth int) bool {
	if len(inner) == 0 {
		return false
	}
	repl := xargsReplToken(outerXargs)
	if repl != "" && replTokenInExecSlotDepth(inner, repl, pathEnv, caller, depth, false) {
		return true
	}
	p := peelExecSlotHead(inner, pathEnv, caller, repl)
	if p.failClosed || len(p.head) == 0 {
		return true
	}
	for _, h := range p.variants {
		if xargsVariantFeedsCodeSlot(h, repl, outerXargs, p.effPath, caller, p.caller, depth) {
			return true
		}
	}
	return false
}

// xargsVariantFeedsCodeSlot screens one spelling of the xargs target head:
// interpreter inline-code slots first, then the command indirection heads.
func xargsVariantFeedsCodeSlot(h []string, repl string, outerXargs []string, effPath string, outerCaller, tCaller callerIdentity, depth int) bool {
	b := filepath.Base(h[0])
	if len(h) >= 2 {
		for _, s := range interpCodeSlots(h) {
			if s.flagOnly {
				return true
			}
		}
	}
	if depth >= 1 && (b == "hc" || b == "herdr-core" || headIsCtxmodeOrSelfExe(h[0], effPath, tCaller.screenCwd())) {
		return true
	}
	switch b {
	case "ssh":
		return xargsSSHFeedsCodeSlot(h, repl, outerXargs, outerCaller, depth)
	case "xargs":
		return xargsNestedFeedsCodeSlot(h, outerXargs, effPath, tCaller, depth)
	case "flock":
		return xargsFlockFeedsCodeSlot(h, outerXargs, effPath, tCaller, depth)
	case "watch":
		return xargsWatchFeedsCodeSlot(h, outerXargs, effPath, tCaller, depth)
	case "script":
		if scriptHasOpenCommandFlag(h) {
			return true
		}
		if isDynamicArg(scriptCommandArg(h)) {
			return true
		}
		// Append mode: util-linux script never batch-consumes multiple
		// typescript files, so fed stdin words land where getopt can
		// permute them into -c/--command (v6.2.2 Oracle R4 R4-Obs-1
		// `xargs -a <payload> script /dev/null`).
		return repl == ""
	case "eval":
		return repl == ""
	case "find":
		return xargsFindFeedsCodeSlot(h[1:], repl)
	}
	return false
}

// xargsSSHFeedsCodeSlot screens the remote command an ssh target runs: a
// parse failure or a missing remote command fails closed, and every remote
// segment is descended as an xargs target in its own right.
func xargsSSHFeedsCodeSlot(h []string, repl string, outerXargs []string, outerCaller callerIdentity, depth int) bool {
	if repl == "" {
		// Append mode: the stdin words join the remote command text only
		// when the remote command itself does not already consume stdin as
		// a program — the sshTunnelsStdinProgram/xargsDerivedSeg modelling
		// screens that vehicle path with the precise verdict, so the open
		// feed only matters for remote shell-text joins (v6.2.2 MF-8).
		return xargsSSHAppendFeedsRemoteShell(h)
	}
	remoteCmd, hit := parseSSHInvocation(h)
	if hit != "" {
		return true
	}
	if strings.Contains(remoteCmd, repl) {
		return true
	}
	for _, rseg := range splitShellSegments(remoteCmd) {
		if rseg.parseErr != "" || rseg.depthExceeded {
			return true
		}
		if len(rseg.argv) == 0 {
			continue
		}
		if xargsFeedsCodeFlagDepth(rseg.argv, outerXargs, os.Getenv("PATH"), callerIdentity{cwd: outerCaller.cwd, xw: outerCaller.xw}, depth+1) {
			return true
		}
	}
	return false
}

// xargsNestedFeedsCodeSlot descends into a nested xargs target: the inner
// xargs consumes its OWN stdin words, and the outer feed reaches its target
// only when the outer xargs appends operands (no -I token).
// R21-Reviewer-5: the two continuation recursions are merged whenever they
// are provably EQUIVALENT. The outer-xargs context contributes exactly one
// input to the recursion — the -I replacement token of outerXargs — so when
// both invocations run in append mode (repl == "" and the INNER xargs
// itself carries no replacement token), xargsReplToken(h) and
// xargsReplToken(outerXargs) are both empty and the two calls pass
// byte-identical state: the second call is a pure duplicate of the first.
// Merging them removes the per-level doubling of the no-hit walk — the
// former shape paid 2^depth LookPath resolutions (each redoing the same
// executable lookups) for a linear chain of nested xargs. When the inner
// xargs DOES carry its own -I token the two continuations genuinely
// diverge (the replace-token analysis depends on which invocation's token
// applies), so both branches are kept — exactly the necessary split the
// equivalence argument does not cover.
func xargsNestedFeedsCodeSlot(h, outerXargs []string, effPath string, outerCaller callerIdentity, depth int) bool {
	repl := xargsReplToken(outerXargs)
	k := xargsTargetIndex(h)
	if k < 0 {
		return true
	}
	if k >= len(h) {
		// No inner target at all (xargs xargs): the inner xargs runs its
		// default echo — outer appended words only matter without -I.
		return repl == ""
	}
	if xargsFeedsCodeFlagDepth(h[k:], h, effPath, outerCaller, depth+1) {
		return true
	}
	if repl == "" {
		if xargsReplToken(h) == "" {
			// Both continuations are append-mode with an empty replacement
			// token: the recursion state is identical, so the outer-context
			// replay is a pure duplicate of the inner one above — running it
			// again would only double the same work (R21-Reviewer-5).
			return false
		}
		return xargsFeedsCodeFlagDepth(h[k:], outerXargs, effPath, outerCaller, depth+1)
	}
	return false
}

// xargsFlockFeedsCodeSlot descends past flock's options: a -c/--command
// shell string fed by xargs is shell text the outer stream lands in; a
// positional command argv feeds the same way the direct target does.
func xargsFlockFeedsCodeSlot(h, outerXargs []string, effPath string, outerCaller callerIdentity, depth int) bool {
	repl := xargsReplToken(outerXargs)
	innerIdx, cmdText := skipFlockArgs(h, 1)
	if cmdText != "" {
		return isDynamicArg(cmdText)
	}
	if innerIdx >= len(h) {
		// Dangling flock (xargs flock -x / xargs flock /tmp/lk): the fed
		// words become the command flock runs — open only without -I.
		return repl == ""
	}
	return xargsFeedsCodeFlagDepth(h[innerIdx:], outerXargs, effPath, outerCaller, depth+1)
}

// xargsWatchFeedsCodeSlot descends past watch's options: -x/--exec operands
// form a direct exec argv fed like the direct target; the default mode
// joins operands into a `sh -c` string, so fed words land in shell text
// only when the outer xargs appends them (no -I).
func xargsWatchFeedsCodeSlot(h, outerXargs []string, effPath string, outerCaller callerIdentity, depth int) bool {
	repl := xargsReplToken(outerXargs)
	if len(h) < 2 {
		return repl == ""
	}
	k, execMode, fc := skipWatchArgs(h, 1)
	if fc {
		return true
	}
	if k >= len(h) {
		return repl == ""
	}
	if !execMode {
		return repl == ""
	}
	return xargsFeedsCodeFlagDepth(h[k:], outerXargs, effPath, outerCaller, depth+1)
}

// xargsFindFeedsCodeSlot reports whether fed words can land inside a
// find target's -exec/-execdir/-ok/-okdir command argv. With a replace
// token the scan can never prove it (replTokenInFind owns the token
// analysis — the loop that used to walk the operand list here returned
// false on every path, dead code since v6.2.2 R3 — v6.2.2 Oracle R4
// R4-SF-4); in append mode the stdin words always land in find's
// expression tail (`xargs find .` feeding `-exec pig ;`).
func xargsFindFeedsCodeSlot(args []string, repl string) bool {
	return repl == ""
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

// pythonWriteModeHit checks Python open()/io.open()/os.open()/ZipFile()/
// PyZipFile()/FileIO()/logging.*FileHandler() call sites for write modes;
// plain read-only `open(p)`, `ZipFile(p)`, `ZipFile(p,'r')`, `FileIO(p,'r')`
// stay free while write modes ('w','a','x','+'), non-literal modes, rebinds,
// urlretrieve, non-ro sqlite3.connect, and logging FileHandlers block.
