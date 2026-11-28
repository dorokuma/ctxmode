package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"mvdan.cc/sh/v3/syntax"
)

// checkControlAndUTF8 rejects illegal UTF-8 and C0 controls (except \t/\n) plus DEL.
func checkControlAndUTF8(code string) string {
	if !utf8.ValidString(code) {
		return "illegal UTF-8"
	}
	for i := 0; i < len(code); i++ {
		b := code[i]
		if b == '\t' || b == '\n' {
			continue
		}
		if b <= 0x08 || b == 0x0b || b == 0x0c || b == 0x0d ||
			(b >= 0x0e && b <= 0x1f) || b == 0x7f {
			return "control character forbidden"
		}
	}
	return ""
}

// checkShellBytes runs shared control/UTF-8 checks; strictReadonly also rejects
// Unicode controls / non-ASCII spaces and attaches Chinese Hint: text.
func checkShellBytes(code string, strictReadonly bool) string {
	if !utf8.ValidString(code) {
		if strictReadonly {
			return "illegal UTF-8 Hint: 命令必须是合法 UTF-8"
		}
		return "illegal UTF-8"
	}
	for i := 0; i < len(code); i++ {
		b := code[i]
		if b == '\t' || b == '\n' {
			continue
		}
		if b <= 0x08 || b == 0x0b || b == 0x0c || b == 0x0d ||
			(b >= 0x0e && b <= 0x1f) || b == 0x7f {
			if !strictReadonly {
				return "control character forbidden"
			}
			if b == 0x7f {
				return "control character forbidden Hint: 禁止 DEL (0x7f)"
			}
			return "control character forbidden Hint: 禁止控制字符（含 \\r \\v \\f）；匹配回车请写 rg '\\r'"
		}
	}
	if !strictReadonly {
		return ""
	}
	for i := 0; i < len(code); {
		b := code[i]
		if b < 0x80 {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(code[i:])
		if r == utf8.RuneError && size == 1 {
			return "illegal UTF-8 Hint: 命令必须是合法 UTF-8"
		}
		if unicode.IsControl(r) || (unicode.Is(unicode.Z, r) && r != ' ') {
			return "unicode control/space forbidden Hint: 禁止 Unicode 控制/特殊空白码点"
		}
		switch r {
		case '\u0085', '\u00a0', '\u1680', '\u180e',
			'\u2000', '\u2001', '\u2002', '\u2003', '\u2004', '\u2005',
			'\u2006', '\u2007', '\u2008', '\u2009', '\u200a',
			'\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
			'\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff':
			return "unicode control/space forbidden Hint: 禁止 Unicode 控制/特殊空白码点"
		}
		i += size
	}
	return ""
}

// hasOddTrailingBackslash reports whether s ends with an odd number of
// backslashes (so a following newline would be a line continuation).
func hasOddTrailingBackslash(s string) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// litHasResidualExpand reports an unescaped $ in a Lit that dash would
// treat as the start of a parameter/command expansion (G1-3).

// litHasUnescapedCmdExpand reports unescaped $( or ` in a raw literal
// (used for unquoted-heredoc outer-expand checks).
func litHasUnescapedCmdExpand(raw string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' {
			i++
			continue
		}
		if raw[i] == '`' {
			return true
		}
		if raw[i] == '$' && i+1 < len(raw) && raw[i+1] == '(' {
			return true
		}
	}
	return false
}

func litHasResidualExpand(raw string) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' {
			i++ // skip escaped byte
			continue
		}
		if raw[i] != '$' {
			continue
		}
		if i+1 >= len(raw) {
			continue
		}
		n := raw[i+1]
		if n == '{' || n == '(' || n == '\\' ||
			(n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') || n == '_' ||
			(n >= '0' && n <= '9') ||
			n == '@' || n == '*' || n == '#' || n == '?' || n == '!' || n == '-' || n == '$' {
			return true
		}
	}
	return false
}

// checkCommentsAndContinuations validates KeepComments AST comment starts
// (MF-1 / Audit-5) and G1 lexical gates (token-internal \\\n, comment-tail \,
// $ then \\\n, quoted-heredoc exemption).
func checkCommentsAndContinuations(code string, f *syntax.File, strictReadonly bool) string {
	if f == nil {
		return ""
	}
	type span struct{ lo, hi int }
	var comments []span
	var exempt []span // sgl-quoted + quoted-heredoc bodies
	var dblQuoted []span
	var substitutions []span
	var ambig string
	syntax.Walk(f, func(n syntax.Node) bool {
		if n == nil || ambig != "" {
			return false
		}
		switch x := n.(type) {
		case *syntax.Comment:
			off := int(x.Hash.Offset())
			if off < 0 || off >= len(code) || code[off] != '#' {
				ambig = "ambiguous comment start"
				return false
			}
			if off > 0 {
				prev := code[off-1]
				switch prev {
				case ' ', '\t', '\n', ';', '|', '&', '(', ')':
					if off >= 2 && hasOddTrailingBackslash(code[:off-1]) {
						ambig = "ambiguous comment start"
						return false
					}
				default:
					ambig = "ambiguous comment start"
					return false
				}
			}
			end := int(x.End().Offset())
			if end < off {
				end = off + 1
			}
			if end > len(code) {
				end = len(code)
			}
			comments = append(comments, span{off, end})
			// G1-2: comment text ending with \ is dangerous (dash ends the
			// command; mvdan may swallow the next line).
			trimmed := strings.TrimRight(x.Text, " \t\r\n")
			if strings.HasSuffix(trimmed, `\`) {
				lineStart := 0
				if i := strings.LastIndex(code[:off], "\n"); i >= 0 {
					lineStart = i + 1
				}
				prefix := code[lineStart:off]
				hasNonWS := false
				for j := 0; j < len(prefix); j++ {
					if prefix[j] != ' ' && prefix[j] != '\t' {
						hasNonWS = true
						break
					}
				}
				prevCont := lineStart >= 2 && hasOddTrailingBackslash(code[:lineStart-1])
				if !strictReadonly {
					// worker: any comment ending with \ is forbidden
					ambig = "comment line continuation forbidden"
					return false
				}
				// readonly: file-leading # \ only (R9_MF5_01). A trailing
				// newline in Comment.Text is normal; swallowed NEXT-line
				// content shows as an interior newline after TrimRight.
				body := strings.TrimRight(x.Text, "\r\n")
				if off != 0 || strings.Contains(body, "\n") || hasNonWS || prevCont {
					ambig = "comment line continuation forbidden"
					return false
				}
			}
		case *syntax.SglQuoted:
			lo, hi := int(x.Pos().Offset()), int(x.End().Offset())
			if lo >= 0 && hi >= lo && hi <= len(code) {
				exempt = append(exempt, span{lo, hi})
			}
		case *syntax.DblQuoted:
			lo, hi := int(x.Pos().Offset()), int(x.End().Offset())
			if lo >= 0 && hi >= lo && hi <= len(code) {
				dblQuoted = append(dblQuoted, span{lo, hi})
			}
		case *syntax.CmdSubst:
			substitutions = append(substitutions, span{int(x.Pos().Offset()), int(x.End().Offset())})
		case *syntax.ProcSubst:
			substitutions = append(substitutions, span{int(x.Pos().Offset()), int(x.End().Offset())})
		case *syntax.Redirect:
			// W-Fix-3: quoted heredoc bodies are pure literals at top-level dash.
			if (x.Op == syntax.Hdoc || x.Op == syntax.DashHdoc) &&
				isQuotedHeredocDelim(x.Word) && x.Hdoc != nil {
				lo, hi := int(x.Hdoc.Pos().Offset()), int(x.Hdoc.End().Offset())
				if lo >= 0 && hi >= lo && hi <= len(code) {
					exempt = append(exempt, span{lo, hi})
				}
			}
		}
		return true
	})
	if ambig != "" {
		return ambig
	}
	inSpan := func(spans []span, i int) bool {
		for _, s := range spans {
			if i >= s.lo && i < s.hi {
				return true
			}
		}
		return false
	}
	isSepPrev := func(i int) bool {
		if i <= 0 {
			return true
		}
		switch code[i-1] {
		case ' ', '\t', '\n':
			return true
		}
		return false
	}
	// G1-1 + existing redirect-after-cont + $ then \\\n
	for i := 0; i+1 < len(code); i++ {
		if code[i] != '\\' || code[i+1] != '\n' {
			continue
		}
		// only odd-parity backslash starts a real continuation
		if i > 0 && code[i-1] == '\\' {
			// count run
			k := i
			for k > 0 && code[k-1] == '\\' {
				k--
			}
			if (i-k)%2 == 1 {
				continue // even total → escaped backslash, not cont
			}
		}
		if inSpan(comments, i) || inSpan(exempt, i) {
			continue
		}
		// $(...) starts a new shell quoting context: an enclosing double
		// quote must not exempt its unquoted tokens. Only a double quote
		// opened inside the innermost substitution applies there.
		innerSub := -1
		for _, sp := range substitutions {
			if i >= sp.lo && i < sp.hi && sp.lo > innerSub {
				innerSub = sp.lo
			}
		}
		inDQ := false
		for _, sp := range dblQuoted {
			if i >= sp.lo && i < sp.hi && sp.lo > innerSub {
				inDQ = true
			}
		}
		// Reject operator-adjacent continuations (incl. inside dq for $ ` ( ) ; | & < >).
		if i > 0 {
			switch code[i-1] {
			case '$', '`', '(', ')', ';', '|', '&', '<', '>':
				if i < 2 || !hasOddTrailingBackslash(code[:i-1]) {
					if code[i-1] == '$' {
						return "ambiguous line continuation after $"
					}
					return "ambiguous line continuation after operator"
				}
			}
		}
		if inDQ {
			// NTH-1: ordinary text continuation inside double quotes is fine;
			// skip # / </> false positives that only matter outside quotes.
			continue
		}
		// Forward boundary: must follow whitespace (token-external).
		if !isSepPrev(i) {
			return "ambiguous line continuation inside token"
		}
		j := i + 2
		for j < len(code) && (code[j] == ' ' || code[j] == '\t') {
			j++
		}
		if j < len(code) && (code[j] == '<' || code[j] == '>') {
			return "ambiguous line continuation before redirect"
		}
		if j < len(code) && code[j] == '#' {
			return "ambiguous line continuation before comment"
		}
	}
	if !strictReadonly {
		return ""
	}
	for i := 0; i+1 < len(code); i++ {
		if code[i] != '\\' || code[i+1] != '\n' {
			continue
		}
		if inSpan(comments, i) || inSpan(exempt, i) {
			continue
		}
		return "backslash line continuation forbidden"
	}
	return ""
}

// parseReadonlyShellAST fail-closed-parses code under LangPOSIX and returns
// every CallExpr argv, or a reject reason.
// roSegment is one readonly-parsed command segment with stdin metadata.
type roSegment struct {
	argv         []string
	argWords     []*syntax.Word // parallel to argv (nil when unavailable)
	pipedStdin   bool
	heredocText  []heredocBody
	redirectFile string
	// srcCode is the exact buffer this segment was parsed from, and
	// gateProvenanced marks a segment minted by roWalkPreparedHcSend from a
	// prepare*-verified provenance. Both are copied verbatim into the
	// shellSegment handed to peelResolvedSegDepth — never inferred from argv
	// shape.
	srcCode         string
	gateProvenanced bool
}

func parseReadonlyShellAST(code string) (argvs [][]string, rejectReason string) {
	segs, hit := parseReadonlyShellSegments(code)
	if hit != "" {
		return nil, hit
	}
	out := make([][]string, 0, len(segs))
	for _, s := range segs {
		out = append(out, s.argv)
	}
	return out, ""
}

func parseReadonlyShellSegments(code string) (segs []roSegment, rejectReason string) {
	return parseReadonlyShellSegmentsMode(code, false, nil)
}

func parseReadonlyShellSegmentsPrepare(code string, prov *hcGateProvenance) (segs []roSegment, rejectReason string) {
	return parseReadonlyShellSegmentsMode(code, true, prov)
}

func parseReadonlyShellSegmentsMode(code string, prepare bool, prov *hcGateProvenance) (segs []roSegment, rejectReason string) {
	if hit := checkShellBytes(code, true); hit != "" {
		return nil, hit
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangPOSIX), syntax.KeepComments(true))
	file, err := parser.Parse(strings.NewReader(code), "")
	if err != nil {
		return nil, "shell syntax error: " + err.Error()
	}
	if hit := checkCommentsAndContinuations(code, file, true); hit != "" {
		return nil, hit
	}
	var out []roSegment
	if hit := roWalkFileMode(code, file, &out, false, prepare, prov); hit != "" {
		return nil, hit
	}
	return out, ""
}

func roWalkFile(code string, f *syntax.File, out *[]roSegment, pipeIn bool) string {
	return roWalkFileMode(code, f, out, pipeIn, false, nil)
}

func roWalkFileMode(code string, f *syntax.File, out *[]roSegment, pipeIn bool, prepare bool, prov *hcGateProvenance) string {
	for i, st := range f.Stmts {
		if hit := roWalkStmtMode(code, st, out, pipeIn && i == 0, prepare, prov); hit != "" {
			return hit
		}
	}
	return ""
}

func roWalkStmtMode(code string, st *syntax.Stmt, out *[]roSegment, pipeIn bool, prepare bool, prov *hcGateProvenance) string {
	if st.Negated {
		return "control flow '!' forbidden"
	}
	if st.Background {
		return "background & forbidden"
	}
	if st.Coprocess {
		return "coproc forbidden"
	}
	if st.Cmd == nil {
		return "empty command"
	}
	switch cmd := st.Cmd.(type) {
	case *syntax.CallExpr:
		return roWalkCallMode(code, st, cmd, out, pipeIn, prepare, prov)
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.Pipe, syntax.PipeAll:
			if hit := roWalkStmtMode(code, cmd.X, out, pipeIn, prepare, prov); hit != "" {
				return hit
			}
			return roWalkStmtMode(code, cmd.Y, out, true, prepare, prov)
		case syntax.AndStmt, syntax.OrStmt:
			if hit := roWalkStmtMode(code, cmd.X, out, pipeIn, prepare, prov); hit != "" {
				return hit
			}
			return roWalkStmtMode(code, cmd.Y, out, false, prepare, prov)
		default:
			return fmt.Sprintf("unsupported syntax node %T op=%v", cmd, cmd.Op)
		}
	case *syntax.Subshell:
		return "parentheses forbidden"
	case *syntax.Block:
		return "brace group forbidden"
	case *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
		return "control flow forbidden"
	case *syntax.FuncDecl:
		return "function definition forbidden"
	case *syntax.ArithmCmd, *syntax.TestClause, *syntax.DeclClause,
		*syntax.LetClause, *syntax.TimeClause, *syntax.CoprocClause:
		return fmt.Sprintf("unsupported syntax node %T", cmd)
	default:
		return fmt.Sprintf("unsupported syntax node %T", cmd)
	}
}

func roWalkCallMode(code string, st *syntax.Stmt, call *syntax.CallExpr, out *[]roSegment, pipeIn bool, prepare bool, prov *hcGateProvenance) string {
	if len(call.Assigns) > 0 {
		return "env assign forbidden Hint: 禁止 VAR=val 前缀；需要环境变量时只用 LANG/LC_ALL/TZ 经 ctx_run env"
	}
	if len(call.Args) < 1 {
		return "empty command"
	}
	// Prepare-mode: allow ONLY a prov-verified rewritten
	// `<selfExe> --hc-gate send addr text` call; recurse into CmdSubst for
	// readonly screening. A user-typed raw --hc-gate carries no provenance and
	// falls through to the ordinary (blocking) roWord path.
	if prepare {
		if hit := roWalkPreparedHcSend(code, st, call, out, pipeIn, prov); hit != "not-hc" {
			return hit
		}
	}
	argv := make([]string, 0, len(call.Args))
	for i, w := range call.Args {
		s, hit := roWord(code, w, i == 0)
		if hit != "" {
			return hit
		}
		argv = append(argv, s)
	}
	seg := roSegment{argv: argv, argWords: call.Args, pipedStdin: pipeIn, srcCode: code}
	for _, r := range st.Redirs {
		hb, redirFile, hit := roCheckRedirect(code, call, r)
		if hit != "" {
			return hit
		}
		if hb != nil {
			seg.heredocText = append(seg.heredocText, *hb)
		}
		if redirFile != "" {
			seg.redirectFile = redirFile
		}
	}
	*out = append(*out, seg)
	return ""
}

// roWalkPreparedHcSend handles the prepare*-minted gate form ONLY. It returns
// "not-hc" for every other call. The four-word `hc send <addr> <text>`
// disguise is gone: a static hc send is already covered by the ordinary
// roWord + readonlyAllowlist["hc"] path, and pretending the head was "hc"
// laundered /tmp/hc and herdr-core into an allowed call.
func roWalkPreparedHcSend(code string, st *syntax.Stmt, call *syntax.CallExpr, out *[]roSegment, pipeIn bool, prov *hcGateProvenance) string {
	args := call.Args
	if len(args) != 5 || prov == nil {
		return "not-hc"
	}
	head, ok0 := wordToArg(args[0])
	flag, ok1 := wordToArg(args[1])
	send, ok2 := wordToArg(args[2])
	addr, ok3 := wordToArg(args[3])
	if !ok0 || !ok1 || !ok2 || !ok3 {
		return "not-hc"
	}
	// Accept any absolute selfExe (test binaries are not named "ctxmode").
	if !strings.Contains(head, "/") || flag != "--hc-gate" || send != "send" ||
		!hcSendAddrOK(addr) || strings.HasPrefix(addr, "-") {
		return "not-hc"
	}
	// The span-bound proof: head/flag must be EXACTLY the words the rewriter
	// minted in THIS buffer. A raw user-typed --hc-gate can never satisfy it.
	if !prov.hasGateCall(code, args[0], args[1]) {
		return "not-hc"
	}
	if !isPreparedHcGateArgv([]string{head, flag, send, addr, "ok"}) {
		return "not-hc"
	}
	textWord := args[4]
	if !isGuaranteedSingleArgWord(textWord, false) {
		return "not-hc"
	}
	if strings.HasPrefix(staticWordPrefix(textWord), "-") {
		return "not-hc"
	}
	if hit := roWalkHcTextCmdSubsts(code, textWord, out); hit != "" {
		return hit
	}
	// Keep the REAL head and mark the segment as provenance-backed; the
	// strict-readonly screens bridge on gateProvenanced to skip the first-word
	// path rejection (陷阱 A) without ever trusting argv shape.
	argv := []string{head, "--hc-gate", "send", addr, "ok"} // static stand-in; the gate validates real text
	seg := roSegment{argv: argv, argWords: args, pipedStdin: pipeIn, srcCode: code, gateProvenanced: true}
	for _, r := range st.Redirs {
		hb, redirFile, hit := roCheckRedirect(code, call, r)
		if hit != "" {
			return hit
		}
		if hb != nil {
			seg.heredocText = append(seg.heredocText, *hb)
		}
		if redirFile != "" {
			seg.redirectFile = redirFile
		}
	}
	*out = append(*out, seg)
	return ""
}

func roWalkHcTextCmdSubsts(code string, textWord *syntax.Word, out *[]roSegment) string {
	if textWord == nil {
		return "empty command"
	}
	for _, part := range textWord.Parts {
		switch p := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
			continue
		case *syntax.DblQuoted:
			if p.Dollar {
				return `$"..." quoting forbidden`
			}
			for _, ip := range p.Parts {
				switch ipp := ip.(type) {
				case *syntax.Lit:
					continue
				case *syntax.CmdSubst:
					if hit := roWalkFile(code, &syntax.File{Stmts: ipp.Stmts}, out, false); hit != "" {
						return hit
					}
				default:
					return "shell expansion inside double quotes forbidden"
				}
			}
		default:
			return "not-hc"
		}
	}
	return ""
}

func roWord(code string, w *syntax.Word, isHead bool) (string, string) {
	if w == nil || len(w.Parts) == 0 {
		return "", "empty command"
	}
	if isHead {
		if len(w.Parts) != 1 {
			return "", "command head must be a plain literal"
		}
		lit, ok := w.Parts[0].(*syntax.Lit)
		if !ok {
			return "", "command head must be a plain literal"
		}
		if strings.ContainsAny(lit.Value, "\\'\"/$") {
			return "", "command head metachar forbidden"
		}
		if hit := roShellCheckCmdHead(lit.Value); hit != "" {
			return "", hit
		}
		return lit.Value, ""
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if strings.Contains(p.Value, `$`) {
				return "", "shell expansion $ forbidden Hint: $ 只能放在单引号里"
			}
			if strings.Contains(p.Value, `\`) {
				return "", "unquoted backslash forbidden Hint: 特殊字符请放进引号"
			}
			if strings.ContainsAny(p.Value, "~*?[") {
				return "", "glob/tilde metachar forbidden Hint: 引号外禁止 ~ * ? [；请加单引号或双引号"
			}
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", "$'...' quoting forbidden"
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return "", "$\"...\" quoting forbidden"
			}
			for _, ip := range p.Parts {
				lit, ok := ip.(*syntax.Lit)
				if !ok {
					return "", "shell expansion inside double quotes forbidden"
				}
				b.WriteString(decodeDblQuotedLit(lit.Value))
			}
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp,
			*syntax.ProcSubst, *syntax.ExtGlob, *syntax.BraceExp:
			return "", fmt.Sprintf("unsupported syntax node %T", p)
		default:
			return "", fmt.Sprintf("unsupported syntax node %T", p)
		}
	}
	return b.String(), ""
}

func decodeDblQuotedLit(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '"', '\\', '$', '`':
				b.WriteByte(s[i+1])
				i++
				continue
			case '\n':
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// decodeUnquotedHeredocLit applies POSIX §2.7.4 unquoted-heredoc unescape:
// \$ → $, \` → `, \\ → \, \\\n folds away; <<- strips leading tabs per line.
func decodeUnquotedHeredocLit(s string, dashHdoc bool) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	lineStart := true
	for i < len(s) {
		if dashHdoc && lineStart {
			for i < len(s) && s[i] == '\t' {
				i++
			}
			lineStart = false
			if i >= len(s) {
				break
			}
		}
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '$', '`', '\\':
				b.WriteByte(s[i+1])
				i += 2
				lineStart = false
				continue
			case '\n':
				i += 2
				lineStart = true
				continue
			}
		}
		if s[i] == '\n' {
			lineStart = true
		} else {
			lineStart = false
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func stripDashHdocTabs(s string) string {
	if s == "" || !strings.Contains(s, "\t") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	lineStart := true
	for i := 0; i < len(s); i++ {
		if lineStart {
			if s[i] == '\t' {
				continue
			}
			lineStart = false
		}
		if s[i] == '\n' {
			lineStart = true
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
func roCheckRedirect(code string, call *syntax.CallExpr, r *syntax.Redirect) (hb *heredocBody, redirectFile string, hit string) {
	if len(call.Args) == 0 {
		return nil, "", "empty command"
	}
	// Redirects must follow the command head (no prefix redirs like 2>/dev/null ls).
	if !r.Pos().After(call.Args[0].End()) {
		return nil, "", "prefix redirect forbidden"
	}
	off := int(r.Pos().Offset())
	if off == 0 || off > len(code) {
		return nil, "", "prefix redirect forbidden"
	}
	prev := code[off-1]
	if prev != ' ' && prev != '\t' {
		return nil, "", "redirect must be preceded by space/tab"
	}
	if r.Word == nil {
		return nil, "", "redirect target required"
	}
	endPos := int(r.Word.End().Offset())
	if endPos < len(code) {
		c := code[endPos]
		switch c {
		case ' ', '\t', '\n', ';', '|', '&':
		default:
			return nil, "", "redirect not word-bounded"
		}
	}
	switch r.Op {
	case syntax.RdrOut:
		if r.N != nil && r.N.Value != "1" && r.N.Value != "2" {
			return nil, "", "redirect fd forbidden"
		}
		if len(r.Word.Parts) != 1 {
			return nil, "", "redirect target must be plain literal"
		}
		lit, ok := r.Word.Parts[0].(*syntax.Lit)
		if !ok || strings.ContainsAny(lit.Value, "\\'\"") {
			return nil, "", "redirect target must be plain literal"
		}
		if lit.Value != "/dev/null" {
			return nil, lit.Value, "redirect target forbidden"
		}
		return nil, "", ""
	case syntax.DplOut:
		raw, ok := rawSlice(code, r.Pos(), r.End())
		if !ok || (raw != "2>&1" && raw != "1>&2") {
			return nil, "", "redirect duplex forbidden"
		}
		return nil, "", ""
	case syntax.Hdoc, syntax.DashHdoc:
		// MF-4: only static single-quoted heredoc on a literal ssh head.
		head, hhit := roWord(code, call.Args[0], true)
		if hhit != "" || head != "ssh" {
			return nil, "", fmt.Sprintf("unsupported syntax node %T op=%v", r, r.Op)
		}
		if r.N != nil {
			return nil, "", "ssh heredoc fd forbidden"
		}
		if len(r.Word.Parts) != 1 {
			return nil, "", "ssh heredoc delim must be single-quoted"
		}
		sgl, ok := r.Word.Parts[0].(*syntax.SglQuoted)
		if !ok || sgl.Dollar || !isHeredocDelimName(sgl.Value) {
			return nil, "", "ssh heredoc delim must be single-quoted"
		}
		opLen := len(r.Op.String())
		lo := int(r.OpPos.Offset()) + opLen
		hi := int(r.Word.End().Offset())
		if lo < 0 || hi > len(code) || lo > hi {
			return nil, "", "ssh heredoc delim span"
		}
		if strings.ContainsAny(code[lo:hi], "\\\n") {
			return nil, "", "ssh heredoc delim span"
		}
		text := ""
		if r.Hdoc != nil {
			// Prefer Lit() so the closing delimiter is not part of the body.
			if lit := r.Hdoc.Lit(); lit != "" {
				text = lit
			} else if raw, ok := rawSlice(code, r.Hdoc.Pos(), r.Hdoc.End()); ok {
				text = raw
			} else {
				return nil, "", "ssh heredoc body"
			}
			if r.Op == syntax.DashHdoc {
				text = stripDashHdocTabs(text)
			}
		}
		body := heredocBody{text: text, quoted: true, dynamic: false}
		return &body, "", ""
	default:
		return nil, "", fmt.Sprintf("unsupported syntax node %T op=%v", r, r.Op)
	}
}

func rawSlice(code string, pos, end syntax.Pos) (string, bool) {
	if !pos.IsValid() || !end.IsValid() {
		return "", false
	}
	lo, hi := int(pos.Offset()), int(end.Offset())
	if lo < 0 || hi < lo || hi > len(code) {
		return "", false
	}
	return code[lo:hi], true
}

// rawHasLineContAfterDollar reports an unescaped $ followed by \\\n.
// dash folds the continuation before parsing the expansion; mvdan may not.
func rawHasLineContAfterDollar(raw string) bool {
	for i := 0; i+1 < len(raw); i++ {
		if raw[i] == '\\' {
			i++ // skip escaped byte
			continue
		}
		if raw[i] != '$' {
			continue
		}
		if i+2 < len(raw) && raw[i+1] == '\\' && raw[i+2] == '\n' {
			return true
		}
	}
	return false
}

// preScanVarMutations counts variable write/bind sites across the whole AST
// (G3 SSA-like invariant). Names with writeCount > 1 are tainted before walk.
// posixNoBraces (variadic, default false) marks the POSIX/dash dialect of
// the file being scanned (v6.2.2 Oracle R16 S2): dash performs NO brace
// expansion, so a literal format word like printf tag{red,blue} is static
// text there — encoding it with the bash brace-expansion rules would blind
// the whole-script write scan on perfectly ordinary dash scripts.
func preScanVarMutations(f *syntax.File, posixNoBracesOpt ...bool) (writeCount map[string]int, allTainted bool) {
	posixNoBraces := len(posixNoBracesOpt) > 0 && posixNoBracesOpt[0]
	return preScanVarMutationsDepth(f, posixNoBraces, 0)
}

// preScanVarMutationsDepth is preScanVarMutations with the eval recursion
// depth threaded through (R19-Oracle-S2): scanShellBuiltinWritesDepth
// consumes one peelChainMaxDepth step per nested static eval re-parse and
// hands the incremented budget back here, so a self-nesting eval text can
// never outparse the budget the outer guard peels under. The body is a
// verbatim move of the historical preScanVarMutations scan — only the
// scanShellBuiltinWrites call carries the depth.
func preScanVarMutationsDepth(f *syntax.File, posixNoBraces bool, depth int) (writeCount map[string]int, allTainted bool) {
	writeCount = map[string]int{}
	if f == nil {
		return writeCount, false
	}
	// scanWord is the dialect-aware word conversion of this scan: the
	// context-free wordToArg always assumes bash brace expansion, which is
	// correct for the bash primary/secondary trees but wrong for a dash
	// script — under posixNoBraces the brace scan is skipped entirely.
	scanWord := wordToArg
	if posixNoBraces {
		scanWord = wordToArgPosix
	}
	inc := func(name string) {
		if name != "" {
			writeCount[name]++
		}
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		if n == nil || allTainted {
			return false
		}
		switch x := n.(type) {
		case *syntax.Assign:
			if x.Name != nil {
				inc(x.Name.Value)
			}
		case *syntax.ForClause:
			if wi, ok := x.Loop.(*syntax.WordIter); ok && wi.Name != nil {
				inc(wi.Name.Value)
			}
		case *syntax.ParamExp:
			if x.Param != nil && x.Exp != nil &&
				(x.Exp.Op == syntax.AssignUnset || x.Exp.Op == syntax.AssignUnsetOrNull) {
				inc(x.Param.Value)
			}
		case *syntax.BinaryArithm:
			if isArithAssignOp(x.Op) {
				inc(arithmTargetName(x.X))
			}
		case *syntax.UnaryArithm:
			if x.Op == syntax.Inc || x.Op == syntax.Dec {
				inc(arithmTargetName(x.X))
			}
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				return true
			}
			// SH11 MF-4.3: strip leading `command`/`builtin` wrappers so
			// `command read x` / `builtin unset BUN` cannot hide mutations
			// from the write count. A `command -v`/`command -V` pure query
			// wraps nothing; a dynamic word in the wrapper zone cannot be
			// reasoned about → taint everything.
			args := x.Args
			sawWrapper := false
			for len(args) > 0 {
				h, ok := scanWord(args[0])
				if !ok || isDynamicArg(h) {
					// A dynamic word is not literally command/builtin. When it
					// appears AFTER a real command/builtin it could still be
					// `read`/any mutator the wrapper is hiding → taint all.
					// As the FIRST word it is still a command head we cannot
					// vet (`$X "cd /tmp"`, `$(eval) "cd /tmp"`): conservatively
					// taint PWD/OLDPWD so a later $(pwd) stays dynamic (R5 MF-2).
					inc("PWD")
					inc("OLDPWD")
					if sawWrapper {
						allTainted = true
						return false
					}
					args = nil
					break
				}
				base0 := h
				if k := strings.LastIndexByte(base0, '/'); k >= 0 {
					base0 = base0[k+1:]
				}
				if base0 != "command" && base0 != "builtin" {
					break
				}
				sawWrapper = true
				args = args[1:]
				// Peel the wrapper's own option run (command -v/-V/-p; any
				// unknown option is conservatively consumed the same way).
				optStrs := make([]string, 0, len(args))
				for _, w := range args {
					os_, ook := scanWord(w)
					if !ook {
						os_ = cmdSubPlaceholder
					}
					optStrs = append(optStrs, os_)
				}
				if isCommandQuery(optStrs) {
					args = nil // pure -v/-V query: wraps no command
					break
				}
				for len(args) > 0 {
					a, aok := scanWord(args[0])
					if !aok || isDynamicArg(a) {
						allTainted = true
						return false
					}
					if a == "--" {
						args = args[1:]
						break
					}
					if strings.HasPrefix(a, "-") && a != "-" {
						args = args[1:]
						continue
					}
					break
				}
			}
			if len(args) == 0 {
				return true
			}
			head, _ := scanWord(args[0])
			base := head
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			scanShellBuiltinWritesDepth(base, args, scanWord, inc, posixNoBraces, depth)
			switch base {
			case "cd", "chdir", "pushd", "popd", "eval", "source", ".":
				// Every directory-switch builtin (cd/chdir/pushd/popd) rewrites
				// PWD/OLDPWD in the running shell, and eval/source/. can hide
				// one inside its argument text — any sighting taints the $(pwd)
				// static bind (R3 MF-3).
				inc("PWD")
				inc("OLDPWD")
			case "getopts":
				// getopts always mutates OPTIND and may write OPTARG.
				inc("OPTIND")
				inc("OPTARG")
				// getopts OPTSTRING NAME [args...]: the first operand is the
				// optstring (may begin with ':' or '-'), the second is the
				// target variable name.
				// R13-SF-1: aligned with the argv-layer screenGetoptsEnvWrite —
				// a DYNAMIC first operand keeps its static layout whenever it
				// cannot word-split its slot open (envDynSlotHit) and can never
				// expand to exactly "--" (dynWordCanSpellDashDash — including
				// the '$$' PID digits encoding, R13-SF-2), so `getopts ":$OPTS"
				// opt` no longer blinds the whole-script write scan. Only the
				// dash-shaped runtime-terminator spelling vets the standby NAME
				// slot at args[3] as a write target.
				opIdx := 0
				if len(args) > 1 {
					s1, ok1 := scanWord(args[1])
					if !ok1 && s1 == "" {
						allTainted = true
						return false
					}
					if envDynSlotHit(s1, "getopts") != "" {
						allTainted = true
						return false
					}
					if s1 == "--" {
						if len(args) > 2 {
							opIdx = 2
						}
					} else {
						opIdx = 1
						if isDynamicArg(s1) && len(args) > 3 && dynWordCanSpellDashDash(s1) {
							s3, ok3 := scanWord(args[3])
							if !ok3 || isDynamicArg(s3) {
								allTainted = true
								return false
							}
							if bn, bok := writeTargetBase(s3); bok {
								inc(bn)
							} else {
								allTainted = true
								return false
							}
						}
					}
				}
				if opIdx > 0 && opIdx+1 < len(args) {
					s, ok := scanWord(args[opIdx+1])
					if !ok || isDynamicArg(s) {
						allTainted = true
						return false
					}
					inc(s)
				}
			case "read":
				// Bare read writes REPLY; -a ARRAY writes the array.
				inc("REPLY")
				// read option letters: boolean r s e; value-carrying d n N p t u i a
				// (a separate argv when last in its cluster). -a ARRAY is itself
				// a write target. R13: -s is a BOOLEAN (silent echo) — treating
				// it as value-carrying hides the real write target (`read -s x`).
				// R4-SF-1: -e is boolean and -i carries the initial-value text.
				sawDashDash := false
				j := 1
				for j < len(args) {
					s, ok := scanWord(args[j])
					if !ok || isDynamicArg(s) {
						// R13-SF-1/R13-MF-4: delegate to the SAME readDynClusterHit
						// the argv layer uses — a dynamic word whose static letters
						// end at a value letter carries a glued prompt/initial value
						// (`read -p"Prompt: $PROMPT" x`) and writes nothing itself,
						// but only while the glued tail is provably non-empty so an
						// empty expansion cannot swallow the next argv word. (The
						// old inline walk was dead code: context-free wordToArg
						// always reports ok=false for dynamic words.)
						if !ok && s == "" {
							allTainted = true
							return false
						}
						if !sawDashDash && strings.HasPrefix(s, "-") && len(s) > 1 && readDynClusterHit(s) == "" {
							j++
							continue
						}
						allTainted = true
						return false
					}
					if s == "--" && !sawDashDash {
						sawDashDash = true
						j++
						continue
					}
					if !sawDashDash && strings.HasPrefix(s, "-") && len(s) > 1 {
						// R13-MF-3: a value-carrying letter consumes the NEXT argv
						// word only when it sits at the END of its cluster — the
						// decision is positional (k == len(s)-1 at the hit), never
						// a comparison of the cluster's last byte against the value
						// letter itself. `read -eii sample` glues the -i initial
						// value text 'i' AFTER the option letter, so the cluster's
						// trailing byte matching 'i' by coincidence must not make
						// the scan swallow `sample` as a consumed value operand.
						consumesNext := false
						for k := 1; k < len(s); k++ {
							switch s[k] {
							case 'r', 's', 'e':
								continue
							case 'a':
								// -a ARRAY: the array name is a write target.
								arrName := ""
								if k+1 < len(s) {
									arrName = s[k+1:]
								} else if j+1 < len(args) {
									an, aok := scanWord(args[j+1])
									if !aok || isDynamicArg(an) {
										allTainted = true
										return false
									}
									arrName = an
									j++
								}
								if arrName != "" {
									if bn, bok := writeTargetBase(arrName); bok {
										inc(bn)
									} else {
										allTainted = true
										return false
									}
								}
								k = len(s)
							case 'd', 'n', 'N', 'p', 't', 'u', 'i':
								consumesNext = k == len(s)-1
								k = len(s)
							default:
								// Unknown option letter: be conservative.
								allTainted = true
								return false
							}
						}
						if consumesNext && j+1 < len(args) {
							// R14 closure: the consumed value operand is vetted BEFORE
							// it is skipped — an unquoted expansion (`read -p $X` with
							// X="p cmd") word-splits at runtime, shifting the positional
							// layout so the REAL write-target variable lands one slot
							// later than the static scan assumed. A QUOTED expansion
							// (`read -p "$PROMPT" x`) stays exactly one argv word at
							// runtime (bash consumes it even when empty — measured),
							// so the downstream positional layout can never shift and
							// the slot is skipped like static text. wordToArg grades
							// every dynamic word with ok=false plus a placeholder
							// encoding, so the ok flag cannot separate quoted from
							// unquoted here — isDynamicArg && !isSingleWordSplitSafe
							// is the discriminating condition, matching the argv
							// layer's envDynSlotHit exactly.
							vn, _ := scanWord(args[j+1])
							if isDynamicArg(vn) && !isSingleWordSplitSafe(vn) {
								allTainted = true
								return false
							}
							j++ // value operand consumed
						}
						j++
						continue
					}
					if s != "" {
						if bn, bok := writeTargetBase(s); bok {
							inc(bn)
						} else {
							allTainted = true
							return false
						}
					}
					j++
				}
			case "unset", "export", "readonly", "declare", "typeset", "local":
				for _, w := range args[1:] {
					s, ok := scanWord(w)
					if !ok {
						allTainted = true
						return false
					}
					name := s
					if eq := strings.IndexByte(s, '='); eq >= 0 {
						name = s[:eq]
					}
					if name != "" && !strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "+") {
						inc(name)
					}
				}
			case "printf":
				// R14-Oracle-S1: an explicit-PATH printf (/usr/bin/printf,
				// ./printf) execs the EXTERNAL binary in a child process —
				// its -v/%n machinery can never write the parent shell's
				// variables — so the builtin write scan does not apply at all.
				// Mirroring the argv layer's screenPrintfEnvWrite path
				// exemption, skip it before any word decoding.
				if strings.Contains(head, "/") {
					return true
				}
				// printf -v VAR writes VAR (glued -vVAR and clustered spellings
				// included — R4-MF-1), and every '%n' conversion in the format
				// string writes its aligned argument as a variable name
				// (R4-MF-3). The option zone, glob gate and format-reuse cycle are
				// the shared printfOptionScan used by screenPrintfEnvWrite; a
				// dynamic/unvettable shape taints everything.
				// R13-SF-1: wordToArg emits (encoded, false) for DYNAMIC words —
				// the encoding still carries the exact option/format letters, so
				// the word is COLLECTED whenever it has any content and
				// printfOptionScan decides vettable-vs-dynamic itself. Only a
				// conversion failure (empty encoding, never produced for real
				// dynamic words) taints everything. A data-only dynamic
				// argument like `printf '%s' "$DATA"` no longer blinds the
				// whole-script write scan.
				words := make([]string, 0, len(args)-1)
				for _, w := range args[1:] {
					s, ok := scanWord(w)
					if !ok && s == "" {
						allTainted = true
						return false
					}
					words = append(words, s)
				}
				hits, _, pdyn := printfOptionScan(words)
				if pdyn {
					allTainted = true
					return false
				}
				for _, h := range hits {
					if isDynamicArg(h.name) {
						allTainted = true
						return false
					}
					if bn, bok := writeTargetBase(h.name); bok {
						inc(bn)
					} else {
						allTainted = true
						return false
					}
				}
			}
		}
		return true
	})
	return writeCount, allTainted
}

// scanShellBuiltinWritesDepth replays the variable writes of a STATIC
// eval operand into the outer write scan (R18-Oracle-M3): eval re-parses
// its arguments in the SAME shell process, so `eval 'IFS=:'` mutates the
// very collector state the enclosing script's later words are graded
// under — yet the R3 model only conservatively tainted the directory
// variables and dropped every other write on the floor. Static operands
// are joined with spaces exactly like eval does (minus the `--` option
// terminator bash's builtin consumes itself, R19-Oracle-M1), re-parsed
// under the script's own dialect and fed through preScanVarMutations
// itself (recursing into nested static evals); every inner write count
// ADDS onto the outer count so a write split between the script and its
// eval text is still seen as multi-assignment. A dynamic operand, an
// unparseable operand or an all-tainted inner scan leaves the state
// unknowable: every sentinel name the collector's placeholder grants
// depend on is conservatively counted as written. Everything else
// (cd/read/printf/getopts heads) is untouched.
// evalStaticOperandParts decodes the STATIC operand text a bash builtin
// eval would re-parse (extracted for the v6.2.2 R19 complexity budget —
// R19-Oracle-M1). Bash's builtin eval consumes a leading `--` option
// terminator itself, so feeding `args[1:]` verbatim would hand the inner
// parser a `--`-led command whose assignment spelling degrades to an
// ordinary argument of a `--` command head — never a *syntax.Assign. The
// terminator is stripped BEFORE the operands are joined. (parts, true)
// means every operand decoded as static non-dynamic text; any dynamic or
// unparseable word makes the eval unknowable (false).
func evalStaticOperandParts(args []*syntax.Word, scanWord func(*syntax.Word) (string, bool)) ([]string, bool) {
	operands := args[1:]
	if len(operands) > 0 {
		if s, ok := scanWord(operands[0]); ok && s == "--" {
			operands = operands[1:]
		}
	}
	parts := make([]string, 0, len(operands))
	for _, w := range operands {
		s, ok := scanWord(w)
		if !ok || isDynamicArg(s) {
			return nil, false
		}
		parts = append(parts, s)
	}
	return parts, true
}

// scanShellBuiltinWritesDepth is the depth-metered body of
// scanShellBuiltinWrites (R19-Oracle-S2): the recursion into nested static
// evals must share the SAME budget the guard peels under
// (peelChainMaxDepth) — once it is exhausted the inner state is
// unknowable, so every sentinel name is conservatively counted as written
// and the leaf never gets parsed.
func scanShellBuiltinWritesDepth(base string, args []*syntax.Word, scanWord func(*syntax.Word) (string, bool), inc func(string), posixNoBraces bool, depth int) {
	if base != "eval" || len(args) < 2 {
		return
	}
	incSentinels := func() {
		for name := range sentinelTrustVars {
			inc(name)
		}
	}
	parts, static := evalStaticOperandParts(args, scanWord)
	if !static {
		incSentinels()
		return
	}
	if depth+1 >= peelChainMaxDepth {
		incSentinels()
		return
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangPOSIX), syntax.KeepComments(true))
	if !posixNoBraces {
		parser = syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true))
	}
	inner, err := parser.Parse(strings.NewReader(strings.Join(parts, " ")), "")
	if err != nil {
		incSentinels()
		return
	}
	innerWrites, innerAll := preScanVarMutationsDepth(inner, posixNoBraces, depth+1)
	if innerAll {
		incSentinels()
		return
	}
	for name, n := range innerWrites {
		for i := 0; i < n; i++ {
			inc(name)
		}
	}
}

// evalChainVerdict classifies one call's wrapper chain ending (or not) in
// a same-process eval builtin (R21-Oracle-M1 / R21-Reviewer-2).
type evalChainVerdict int

const (
	// evalChainNone: the surviving head is not eval at all (or the chain
	// runs dry — a bare `command`/`builtin` never reaches a command).
	evalChainNone evalChainVerdict = iota
	// evalChainQuery: a provable pure `command -v/-V` resolution query —
	// nothing executes, so the operand text can never write.
	evalChainQuery
	// evalChainBind: EVERY layer of the chain is a provably-executed real
	// builtin of the script's own dialect carrying only legal non-query
	// options, and the final head is the bare word `eval`.
	evalChainBind
	// evalChainTaint: eval-shaped, but the same-process successful-execution
	// premises fail somewhere along the chain — a slash-carrying wrapper or
	// eval head (an external program can never write shell state), a
	// dialect-foreign builtin (dash has no `builtin`), an unknown or
	// malformed option, or a dynamic/unvettable word in the wrapper zone.
	evalChainTaint
)

// peelEvalBuiltinChain validates the COMPLETE wrapper chain of one call
// targeting eval (R21-Oracle-M1 / R21-Reviewer-2): the binding replication
// licenses only an invocation PROVABLY executing the same-process builtin
// exactly once —
//
//   - no word in the chain may carry a `/` path component (`/dev/null/command`
//     execs an external program even when its basename spells a builtin);
//   - `command` may carry only POSIX's non-query `-p` clusters: `-v`/`-V`
//     shapes are pure resolution queries (nothing executes), and any other
//     `-…` option is an error under the real builtin contract — neither
//     may license a trust peel;
//   - `builtin` is a bash-only builtin taking NO options: under the dash
//     dialect the word is not a builtin at all, and any option spelling
//     fails the invocation;
//   - the final surviving head must be the bare word `eval` exactly.
//
// Dynamic/unparseable words in the wrapper zone make the chain unknowable:
// the conservative verdict is evalChainTaint because preScanVarMutations
// already accounts the operand writes — pretending the invocation cannot
// reach eval would lose them. The returned rest slice (bind/taint verdicts
// only) still CARRIES the eval head word itself, matching the operand
// decoder's expectations (rest[0] == eval, operands at rest[1:]).
func peelEvalBuiltinChain(args []*syntax.Word, posixNoBraces bool) (evalChainVerdict, []*syntax.Word) {
	cur := args
	for len(cur) > 0 {
		h, wok := wordToArg(cur[0])
		if !wok || isDynamicArg(h) {
			return evalChainTaintedRest(cur)
		}
		if h == "eval" {
			return evalChainBind, cur
		}
		if h != "command" && h != "builtin" {
			return evalChainPathVerdict(h, cur)
		}
		cur = cur[1:]
		if h == "builtin" {
			v, rest, ok := peelBuiltinLayer(cur, posixNoBraces)
			if !ok {
				return evalChainLayerVerdict(v, cur)
			}
			cur = rest
			continue
		}
		v, rest, _ := peelCommandLayer(cur)
		if v != evalChainBind {
			return evalChainLayerVerdict(v, cur)
		}
		cur = rest
	}
	return evalChainNone, nil
}

// evalChainTaintedRest is the taint verdict for a chain whose operand
// boundary is no longer statically confirmable (R22-Oracle-M2): the
// best-effort rest slice still exposes any visible bare eval word, so
// the replication can taint exactly the operand writes it can decode.
func evalChainTaintedRest(cur []*syntax.Word) (evalChainVerdict, []*syntax.Word) {
	return evalChainTaint, evalChainBestEffortRest(cur)
}

// evalChainLayerVerdict maps a failed wrapper layer's verdict onto the
// chain-level result: the taint verdict keeps the best-effort operand
// rest, every other verdict has no operand boundary at all.
func evalChainLayerVerdict(v evalChainVerdict, cur []*syntax.Word) (evalChainVerdict, []*syntax.Word) {
	if v == evalChainTaint {
		return v, evalChainBestEffortRest(cur)
	}
	return v, nil
}

// evalChainPathVerdict is the verdict of a non-chain first word: a path
// spelling of eval/command/builtin never invokes the shell builtin —
// yet the pre-scan counts the operand writes, so the sound verdict is
// pollution, never a silent skip.
func evalChainPathVerdict(h string, cur []*syntax.Word) (evalChainVerdict, []*syntax.Word) {
	if strings.ContainsRune(h, '/') {
		b := h[strings.LastIndexByte(h, '/')+1:]
		if b == "eval" || b == "command" || b == "builtin" {
			return evalChainTaint, evalChainBestEffortRest(cur)
		}
	}
	return evalChainNone, nil
}

// evalChainBestEffortRest locates the eval operand boundary of a tainted
// chain on a best-effort basis (R22-Oracle-M2 / R22-Reviewer-#4): the
// first statically decodable bare `eval` word of the remaining argv
// starts the re-parse operands exactly like the confirmed chain's rest
// (rest[0] == eval, operands at rest[1:]). When no bare eval word is
// statically visible — a dynamic wrapper-zone word may itself expand to
// `eval`, so no operand boundary can be confirmed at all — the result is
// nil and the caller must apply the maximal pollution verdict (every
// enumerable write of the whole call plus sentinelTrustVars and PATH)
// instead of dropping the counted writes on the floor.
func evalChainBestEffortRest(words []*syntax.Word) []*syntax.Word {
	for i, w := range words {
		h, ok := wordToArg(w)
		if !ok || isDynamicArg(h) {
			continue
		}
		if h == "eval" {
			return words[i:]
		}
	}
	return nil
}

// evalChainShaped reports whether a call's first word shapes the
// invocation toward the eval builtin chain (R22-Oracle-M2): a bare or
// path-carrying eval/command/builtin spelling. A dynamic first word is
// NOT eval-shaped — the pre-scan counts no eval operand writes for an
// unvettable head, so nothing needs the maximal pollution backstop.
func evalChainShaped(args []*syntax.Word) bool {
	if len(args) == 0 {
		return false
	}
	h, ok := wordToArg(args[0])
	if !ok || isDynamicArg(h) {
		return false
	}
	if k := strings.LastIndexByte(h, '/'); k >= 0 {
		h = h[k+1:]
	}
	return h == "eval" || h == "command" || h == "builtin"
}

// peelEvalBuiltinChainShadowed is peelEvalBuiltinChain plus the
// shell-function shadowing premise (R22-Oracle-M1 / R22-Reviewer-#3):
// name resolution in the shell tries a same-named FUNCTION before any
// builtin, so when eval/command/builtin itself is shadowed by a shell
// function definition the invocation executes user code, never the
// builtin — no exact operand binding may be minted. Only the FIRST word
// of the chain is shadow-sensitive: a surviving unshadowed `command` or
// `builtin` wrapper bypasses the function lookup for every word after it
// (the inner eval then really is the builtin). The operand words the
// function receives may or may not be re-evaluated inside its body, so
// the sound verdict is pollution, never a bind and never a silent skip.
func peelEvalBuiltinChainShadowed(args []*syntax.Word, posixNoBraces bool, funcNames map[string]bool) (evalChainVerdict, []*syntax.Word) {
	if len(args) > 0 && len(funcNames) > 0 {
		if h, ok := wordToArg(args[0]); ok && !isDynamicArg(h) && !strings.ContainsRune(h, '/') {
			if (h == "eval" || h == "command" || h == "builtin") && funcNames[h] {
				return evalChainTaint, evalChainBestEffortRest(args)
			}
		}
	}
	return peelEvalBuiltinChain(args, posixNoBraces)
}

// peelBuiltinLayer validates the remainder of a bash `builtin` invocation
// (R21-Oracle-M1): bash builtin accepts NO options of its own, and under
// the dash dialect the word is not a builtin at all. A dash-dialect
// invocation fails before eval can ever execute — the operand writes
// never bind, so the sound verdict is evalChainNone, NOT taint. An
// option spelling (or an undecodable word) errors at runtime too, but
// the dash judgment cannot be repeated for bash: POSIX offers no stable
// contract for `builtin -x` — it may fail or strip one dash layer — so
// the sound verdict there is taint. ok=false means the caller must
// return v verbatim; ok=true means rest continues the chain.
func peelBuiltinLayer(cur []*syntax.Word, posixNoBraces bool) (evalChainVerdict, []*syntax.Word, bool) {
	if posixNoBraces {
		return evalChainNone, nil, false
	}
	if len(cur) == 0 {
		return evalChainNone, nil, false
	}
	a, aok := wordToArg(cur[0])
	if !aok || isDynamicArg(a) {
		return evalChainTaint, nil, false
	}
	if strings.HasPrefix(a, "-") && a != "-" {
		return evalChainTaint, nil, false
	}
	return evalChainBind, cur, true
}

// peelCommandLayer validates the remainder of a `command` invocation
// (R21-Oracle-M1): -v/-V shapes are pure resolution queries that execute
// nothing (evalChainQuery), and only POSIX's legal execution options —
// `-p` clusters and the `--` terminator — may precede the utility word.
// Any unknown `-…` option is an invocation error: `command -x eval`
// never runs eval, yet the pre-scan counts the operand writes, so the
// sound verdict is pollution, never a silent skip. ok=true means the
// remaining words continue the chain walk.
func peelCommandLayer(cur []*syntax.Word) (evalChainVerdict, []*syntax.Word, bool) {
	optStrs := make([]string, 0, len(cur))
	for _, w := range cur {
		os_, ook := wordToArg(w)
		if !ook {
			os_ = cmdSubPlaceholder
		}
		optStrs = append(optStrs, os_)
	}
	if isCommandQuery(optStrs) {
		return evalChainQuery, nil, false
	}
	for len(cur) > 0 {
		a, aok := wordToArg(cur[0])
		if !aok || isDynamicArg(a) {
			return evalChainTaint, nil, false
		}
		if a == "--" {
			cur = cur[1:]
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			for j := 1; j < len(a); j++ {
				if a[j] != 'p' {
					return evalChainTaint, nil, false
				}
			}
			cur = cur[1:]
			continue
		}
		break
	}
	return evalChainBind, cur, true
}

// writeNamesInStmtFuncs lists the variable names a single statement
// writes according to EXACTLY the pre-scan definition (R21-Oracle-M2 /
// R21-Reviewer-3) plus the shell-function shadowing set of the enclosing
// collector (R22-Oracle-M1 / R22-Reviewer-#3): the two collectors can no
// longer fork — replaying a statement feeds a one-statement pseudo-file
// through preScanVarMutations itself, so plain assigns, for-loop
// variables, ${x:=...} default assigns, arithmetic mutations, nested
// static eval operand writes AND the Bash builtin named-write targets
// (`printf -v`/`%n`, `read`/`REPLY`, `getopts` OPTIND/OPTARG/NAME,
// `unset`/`export`/`declare` families, cd-PDPWD chain) all surface in one
// shared set. allUnvettable reports the pre-scan's give-up signal: the
// collector then taints its wildcard entry exactly like the parse-level
// allTainted seeding does. The writes of a proven root eval binding are
// EXCLUDED from the name set because the replication owns them. A bare
// eval/command/builtin head shadowed by a same-named shell function
// resolves to the FUNCTION, never the builtin, so the chain can never
// license the exact binding.
func writeNamesInStmtFuncs(st *syntax.Stmt, posixNoBraces bool, funcNames map[string]bool) (names []string, allUnvettable bool) {
	if st == nil {
		return nil, false
	}
	// The eval replication owns the writes of a ROOT static eval call —
	// but ONLY for the evalChainBind verdict, where bindEvalCallWrites
	// really replays the operand writes into exact bindings / precise
	// pollution (R22-Oracle-M2 / R22-Reviewer-#4). A TAINTED chain keeps
	// the FULL write scan: the replication cannot confirm the operand
	// boundary there, so truncating the root call to its head word would
	// drop every counted write between the two owners — the exact hole
	// the unified write definition forbids. Nested evals inside compound
	// subtrees (or behind non-eval heads) stay inside the shared scan —
	// their writes surface in the name set.
	rootEval := false
	if call, isCall := st.Cmd.(*syntax.CallExpr); isCall {
		v, _ := peelEvalBuiltinChainShadowed(call.Args, posixNoBraces, funcNames)
		if v == evalChainBind {
			rootEval = true
		}
	}
	var counts map[string]int
	var at bool
	if rootEval {
		// Rescan a clone with the root eval call's arguments truncated to
		// the bare head word: the builtin write scan only descends operand
		// texts when len(args) >= 2, so this truncated scan counts every
		// write EXCEPT the root eval's operand replication — exactly the
		// set this function must return (the eval replication owns the
		// operand writes). The eval head's own conservative PWD/OLDPWD
		// sighting noise is identical on both shapes, so it survives.
		cp := *st
		if call, isCall := st.Cmd.(*syntax.CallExpr); isCall && len(call.Args) > 0 {
			cpCall := *call
			cpCall.Args = cpCall.Args[:1]
			cp.Cmd = &cpCall
		}
		counts, at = preScanVarMutationsDepth(&syntax.File{Stmts: []*syntax.Stmt{&cp}}, posixNoBraces, 0)
	} else {
		counts, at = preScanVarMutationsDepth(&syntax.File{Stmts: []*syntax.Stmt{st}}, posixNoBraces, 0)
	}
	seen := map[string]bool{}
	for name, n := range counts {
		if n > 0 && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names, at
}

// taintOperandParamAssigns taints every variable a word list's
// parameter-expansion ASSIGNMENT operators write (R23-Reviewer-#4 /
// R23-Oracle-M2): `${X=v}` and `${X:=v}` inside an eval OPERAND word
// expand when the shell evaluates the operand — BEFORE eval re-parses
// anything — so the write is neither part of the re-parse text (the
// replication's subject) nor visible in the truncated root-call scan
// writeNamesInStmtFuncs performs for a bind verdict. The pre-scan counts
// exactly these AST nodes, so the replication must own them explicitly:
// pollution (never a silent skip) is the sound verdict for a write the
// operand evaluation performs unconditionally — a default-assign
// expansion is conditional at runtime on X being unset, which is
// precisely the uncertainty direction.
func (c *subCollector) taintOperandParamAssigns(words []*syntax.Word) {
	for _, w := range words {
		if w == nil {
			continue
		}
		// R25: the walk callback is a single-line delegation so the
		// operand-write scan carries its branching inside one named method
		// (complexity budget).
		syntax.Walk(w, func(node syntax.Node) bool { return c.taintOperandWalkNode(node) })
	}
}

// taintOperandWalkNode is the per-node scan of taintOperandParamAssigns
// (extracted for the R25 complexity budget): parameter-expansion
// assignment operators (`${X=v}`, `${X:=v}`) and arithmetic assignment
// or increment/decrement writes both land as pollution, because the
// counted write may never vanish between the truncated root scan and
// the operand replication.
func (c *subCollector) taintOperandWalkNode(node syntax.Node) bool {
	if node == nil {
		return false
	}
	if pe, isPe := node.(*syntax.ParamExp); isPe && pe.Param != nil && pe.Exp != nil &&
		(pe.Exp.Op == syntax.AssignUnset || pe.Exp.Op == syntax.AssignUnsetOrNull) {
		c.taintVar(pe.Param.Value)
	}
	// R24-Reviewer-#4 / R24-Oracle-M4: the pre-scan counts arithmetic
	// writes inside the operand words too — a `$((X=1))` BinaryArithm
	// assignment or a `$((X++))` UnaryArithm increment expands when
	// the shell evaluates the operand, before eval re-parses
	// anything. The truncated root-call scan drops exactly these
	// nodes for a bind verdict, so the replication owns them here
	// under the same pollution verdict as the parameter-expansion
	// assignments: the counted write may never vanish between the
	// two owners.
	switch x := node.(type) {
	case *syntax.BinaryArithm:
		if isArithAssignOp(x.Op) {
			c.taintVar(arithmTargetName(x.X))
		}
	case *syntax.UnaryArithm:
		if x.Op == syntax.Inc || x.Op == syntax.Dec {
			c.taintVar(arithmTargetName(x.X))
		}
	}
	return true
}

// bindEvalCallWrites replicates the variable BINDINGS of a static eval
// invocation into this collector (R19-Oracle-M2): eval re-parses its
// operand text in the SAME shell process, so `eval 'PATH=/custom/dir'`
// rewires the effective PATH the substitution success proofs resolve
// against exactly like the direct `PATH=/custom/dir` spelling — yet the
// R18 model only counted the write in preScanVarMutations (a single write
// count is the SSA candidate bookkeeping, not a bind), so
// canResolveMktempInPath fell back to the caller's ORIGINAL PATH. Only
// fully static operands replicate (anything dynamic is already handled by
// the conservative write scan); the replication itself mirrors the
// collector's own assignment machinery so a static-eval write and a direct
// write end in the same staticVars/taintedVars state.
//
// R20-Oracle-M1: the replication is licensed ONLY for an invocation that
// is PROVABLY the same-process builtin executing exactly once — the
// command head must be a bare `eval` (no path component: `/dev/null/eval`
// is an external program that can never write shell state) and the call
// must carry NO redirections (a redirection that fails — `<
// /dev/null/missing` — aborts the command BEFORE the builtin runs, so the
// write never happens). When either premise fails the operand writes are
// conservatively TAINTED instead of silently skipped: the pre-scan counts
// them, so pretending they cannot happen would leave the collector
// trusting values the runtime may have rewritten (pollution is always the
// fail-closed direction).
func (c *subCollector) bindEvalCallWrites(st *syntax.Stmt, call *syntax.CallExpr) {
	if len(call.Args) == 0 {
		return
	}
	// R25-Oracle-MF3 / R25-Reviewer-#4: a backgrounded or coprocess eval
	// statement runs in its OWN child process — the replicated re-parse
	// no longer carries the statement's process bits, so the replay must
	// never mint parent bindings, and every function/readonly registration
	// it produces dies with the child. The frame also covers the nested
	// hidden-eval replays the taint scan re-enters, because the same
	// boundary verdict spans the whole child process.
	if st != nil && (st.Background || st.Coprocess) {
		defer c.snapshotProcessRegs()()
		c.bindEvalCallChain(st, call, true)
		return
	}
	c.bindEvalCallChain(st, call, len(st.Redirs) > 0)
}

// bindEvalCallChain is the chain-analysis body of bindEvalCallWrites
// (extracted for the R25 complexity budget — the process-boundary wrap
// must carry no chain-verdict branching): mustTaint forces the
// conservative pollution replay for an invocation whose execution is
// not provably-exactly-once-in-this-process (failing redirections or a
// child-process execution shape).
func (c *subCollector) bindEvalCallChain(st *syntax.Stmt, call *syntax.CallExpr, mustTaint bool) {
	if len(call.Args) == 0 {
		return
	}
	// R23-Reviewer-#4 / R23-Oracle-M2: the parameter-expansion writes of
	// the OPERAND WORDS belong to the operand's own evaluation, never to
	// the re-parse — and the root-call truncation the statement write
	// scan performs for a bind verdict drops exactly these AST nodes, so
	// the replication must own them explicitly for every chain verdict.
	// Skip them only when the chain provably never executes anything
	// (non-eval head / pure resolution query): the pre-scan counts no
	// eval operand writes in exactly those cases either.
	verdict, rest := peelEvalBuiltinChainShadowed(call.Args, c.posixNoBraces, c.funcNames)
	if verdict == evalChainNone || verdict == evalChainQuery {
		// Not eval at all, or a provable pure resolution query that
		// executes nothing — the pre-scan does not count such writes
		// either, so the replication can skip them precisely.
		return
	}
	c.taintOperandParamAssigns(call.Args)
	if rest == nil {
		// R22-Oracle-M2 / R22-Reviewer-#4: a TAINTED chain without a
		// confirmable operand boundary (no statically visible bare eval
		// word — the dynamic wrapper-zone word may itself expand to it)
		// faces the maximal pollution verdict in taintEvalBoundary.
		c.taintEvalBoundary(verdict, call.Args)
		return
	}
	if len(rest) < 2 {
		// R23-Reviewer-#4 / R23-Oracle-M2: a TAINTED chain whose visible
		// operand text is absent still carries the unconfirmable boundary
		// — the uniform maximal pollution verdict applies exactly like
		// the rest==nil shape; a proven bind chain with no operands
		// genuinely re-parses nothing.
		c.taintShortRestBoundary(verdict, call.Args)
		return
	}
	c.replayEvalOperandTail(verdict, rest, mustTaint)
}

// replayEvalOperandTail is the static-operand decode and replay
// dispatch shared by bindEvalCallWrites (extracted for the R23
// complexity budget): a dynamic operand makes the re-parse unknowable,
// and the pre-scan conservatively counts every sentinel variable as
// written in exactly this case, so the replay must match the definition
// (R21-Oracle-M2 — counted writes may never vanish).
func (c *subCollector) replayEvalOperandTail(verdict evalChainVerdict, rest []*syntax.Word, hasRedirs bool) {
	scanWord := wordToArg
	if c.posixNoBraces {
		scanWord = wordToArgPosix
	}
	parts, static := evalStaticOperandParts(rest, scanWord)
	if !static {
		c.taintSentinelVars()
		return
	}
	c.replayEvalTextWrites(verdict, strings.Join(parts, " "), hasRedirs)
}

// replayEvalTextWrites dispatches the replication of one statically
// decoded eval operand text (extracted from bindEvalCallWrites): a
// provably-successful same-process builtin invocation replicates exact
// bindings, while every other shape is pollution — never a silent skip
// (R20-Oracle-M1).
func (c *subCollector) replayEvalTextWrites(verdict evalChainVerdict, text string, hasRedirs bool) {
	if verdict != evalChainBind || hasRedirs {
		c.taintEvalTextWrites(text, 0)
		return
	}
	c.bindEvalTextWrites(text, 0)
}

// bindEvalTextWrites parses one static eval operand text under the
// collector's own dialect and replays its top-level statement writes. The
// recursion shares the peelChainMaxDepth budget with the write pre-scan
// (R19-Oracle-S2). R20-Oracle-M2: the budget boundary is NOT a silent
// skip — the scan side already counts those writes, so an unparsable or
// budget-exhausted text conservatively taints the sentinel variables the
// collector's placeholder proofs depend on (exactly like the scan's own
// fallback) instead of dropping every write on the floor.
func (c *subCollector) bindEvalTextWrites(text string, depth int) {
	if text == "" {
		return
	}
	if depth+1 >= peelChainMaxDepth {
		c.taintSentinelVars()
		return
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangPOSIX), syntax.KeepComments(true))
	if !c.posixNoBraces {
		parser = syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true))
	}
	inner, err := parser.Parse(strings.NewReader(text), "")
	if err != nil {
		c.taintSentinelVars()
		return
	}
	c.bindEvalStmtWrites(inner.Stmts, depth)
}

// taintSentinelVars marks every sentinelTrustVars name tainted — the
// conservative verdict for an eval operand text the replication cannot
// parse or must not descend into (R20-Oracle-M2): the pre-scan already
// counts writes in exactly these cases, so dropping them would let the
// collector keep proofs (mktemp PATH resolution, safe-HOME tilde grants)
// the runtime may have invalidated.
func (c *subCollector) taintSentinelVars() {
	for name := range sentinelTrustVars {
		c.taintVar(name)
	}
}

// taintEvalTextWrites conservatively taints every writable name of one
// static eval operand text WITHOUT minting any binding (R20-Oracle-M1):
// the write may or may not happen (a non-builtin eval, a failing
// redirection), so pollution — never a silent skip — is the sound
// verdict. Shares the replication's depth budget and dialect.
func (c *subCollector) taintEvalTextWrites(text string, depth int) {
	if text == "" {
		return
	}
	if depth+1 >= peelChainMaxDepth {
		c.taintSentinelVars()
		return
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangPOSIX), syntax.KeepComments(true))
	if !c.posixNoBraces {
		parser = syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true))
	}
	inner, err := parser.Parse(strings.NewReader(text), "")
	if err != nil {
		c.taintSentinelVars()
		return
	}
	for _, st := range inner.Stmts {
		if st == nil {
			continue
		}
		// R23-Reviewer-#3 / R23-Oracle-M1: the taint replay shares the
		// shadowing registration with the bind replay — a definition
		// inside the tainted text MAY still execute at runtime (the
		// taint verdict means uncertainty, never impossibility), and
		// the fail-closed direction for the positional tracks is to
		// register it exactly like the certain replication does.
		// R24-Reviewer-#3: readonly declarations share the same positional
		// registration exactly — the attribute may still take effect.
		c.noteEvalStmtFuncDefs(st)
		c.noteEvalStmtReadonlyDecls(st)
		c.taintStmtSharedWrites(st)
		c.taintEvalOneStmt(st, depth)
	}
}

// taintEvalOneStmt replays the hidden-eval writes of ONE statement of
// a tainted eval operand text inside the statement's own process
// boundary (extracted for the R26 fix — R26-Oracle-M1 /
// R26-Reviewer-#5): the re-parsed text no longer carries the
// background/coprocess bits of the statements it spells, so a
// child-process statement replays inside a snapshotProcessRegs frame
// whose restore rolls back every function/readonly registration the
// nested replay mints — exactly like bindEvalOneStmt's frame — while
// the conservative variable TAINT of the same writes deliberately
// survives: pollution belongs to the possibility, never the process
// ownership.
func (c *subCollector) taintEvalOneStmt(st *syntax.Stmt, depth int) {
	if st.Background || st.Coprocess {
		defer c.snapshotProcessRegs()()
		c.taintHiddenEvalWrites(st, depth)
		return
	}
	c.taintHiddenEvalWrites(st, depth)
}

// noteEvalStmtFuncDefs registers the same-process function definitions
// of one eval-text statement (extracted for the R23 complexity budget):
// a top-level FuncDecl registers directly, every other statement shape
// is scanned for definitions inside its same-process compound blocks.
func (c *subCollector) noteEvalStmtFuncDefs(st *syntax.Stmt) {
	// R24-Reviewer-#3 / R24-Oracle-M3: the statement's own process
	// boundary precedes even the fast top-level path — a backgrounded
	// FuncDecl (`eval() { :; } &`) executes in a child shell and can
	// never shadow the parent's later name resolution. Extracted into
	// childProcStmtBoundary so all three positional scans share one
	// boundary verdict (R24 complexity budget).
	if childProcStmtBoundary(st) {
		return
	}
	// No fast path for a top-level FuncDecl: the noteSameProcessFuncDefs
	// walk visits st.Cmd itself as the ROOT node of the traversal, so a
	// plain same-process FuncDecl registers through exactly the same
	// FuncDecl case — one single scan owner, zero duplication.
	c.noteSameProcessFuncDefs(st)
}

// childProcStmtBoundary reports whether one statement is unusable for
// the same-process positional scans (extracted for the R24 complexity
// budget): a nil/headless statement carries nothing to scan, and a
// backgrounded or coprocess statement runs in its own child process so
// every definition/declaration inside it dies with the child.
func childProcStmtBoundary(st *syntax.Stmt) bool {
	return st == nil || st.Cmd == nil || st.Background || st.Coprocess
}

// noteEvalStmtReadonlyDecls records the readonly attributes one
// eval-text statement installs in the SAME shell process
// (R24-Reviewer-#3 / R24-Oracle-M3): the main traversal registers them
// through emitDecl/emitCall, but the static eval replication re-parses
// the operand text without those emission paths — a bare
// `eval 'readonly X'` otherwise left the positional track unchanged,
// so a later assignment replication minted a bind the frozen runtime
// variable can never receive. The scan shares the function-definition
// process boundary exactly: backgrounded/coprocess subtrees, pipeline
// components, substitutions and subshells die with their child.
func (c *subCollector) noteEvalStmtReadonlyDecls(st *syntax.Stmt) {
	if childProcStmtBoundary(st) {
		return
	}
	if d, isDecl := st.Cmd.(*syntax.DeclClause); isDecl {
		c.noteReadonlyDecls(c.declClauseArgv(d))
	}
	if call, isCall := st.Cmd.(*syntax.CallExpr); isCall {
		// R25-Oracle-MF2: the POSIX dialect parses `readonly NAME` as a
		// CallExpr, not a DeclClause — the main traversal registers it
		// through emitCall, and the replication must share exactly the
		// same process state.
		c.noteReadonlyDecls(c.callArgsArgv(call))
	}
	syntax.Walk(st.Cmd, func(node syntax.Node) bool {
		if node == nil {
			return false
		}
		switch x := node.(type) {
		case *syntax.Stmt:
			if x.Background || x.Coprocess {
				return false
			}
			return true
		case *syntax.DeclClause:
			c.noteReadonlyDecls(c.declClauseArgv(x))
			return true
		case *syntax.CallExpr:
			// R25-Oracle-MF2: POSIX parses `readonly NAME` as a call — the
			// attribute it installs is a positional fact exactly like the
			// DeclClause shape.
			c.noteReadonlyDecls(c.callArgsArgv(x))
			return true
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				return false
			}
			return true
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.Subshell, *syntax.CoprocClause:
			return false
		}
		return true
	})
}

// callArgsArgv serializes the static positional operands of one CallExpr
// into the argv shape noteReadonlyDecls/noteDeclCallBinds consume
// (extracted for the R25 readonly-replay fix): the POSIX dialect parses
// `readonly NAME` as a plain command invocation, so the replication must
// decode its words exactly like emitCall does — dynamic words encode
// through the collector's own wordToArg, assignment prefixes never
// appear here because the declare family is a DeclClause in the bash
// dialect and readonly-export POSIX words carry no prefix assigns.
func (c *subCollector) callArgsArgv(call *syntax.CallExpr) []string {
	if call == nil {
		return nil
	}
	argv := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		s, _ := c.wordToArg(w)
		argv = append(argv, s)
	}
	return argv
}

// declClauseArgv serializes the positional operands of one declare/
// readonly/typeset/local clause into the argv shape noteReadonlyDecls
// consumes (extracted so noteEvalStmtReadonlyDecls carries no operand
// conversion branching): the variant word leads, naked names ride as
// bare operands, and assignments serialize exactly like the emitDecl
// path — the declaration's own inline bind is irrelevant here, only
// the attribute the word installs matters.
func (c *subCollector) declClauseArgv(d *syntax.DeclClause) []string {
	if d == nil {
		return nil
	}
	argv := make([]string, 0, 1+len(d.Args))
	if d.Variant != nil {
		argv = append(argv, d.Variant.Value)
	}
	for _, a := range d.Args {
		if a.Naked && a.Name == nil && a.Value != nil {
			// R25-Oracle-MF2 / R25-Reviewer-#3: a bash declaration flag word
			// (`declare -r`, `-xr`, `--`) is Naked=true with NO name —
			// assignToPrefix serializes that shape to the empty string and
			// the readonly scan never sees the -r cluster. Serialize the
			// flag word itself exactly like emitDecl does.
			s, _ := c.wordToArg(a.Value)
			argv = append(argv, s)
			continue
		}
		argv = append(argv, c.assignToPrefix(a))
	}
	return argv
}

// taintStmtSharedWrites taints every name of one statement according to
// the SHARED pre-scan write definition (R21-Oracle-M2/R21-Reviewer-3):
// the Bash named-write builtins (`printf -v PATH`, `read`, `getopts`,
// `unset`, the declare family) surface exactly like syntax assignments,
// and an unvettable statement shape taints the wildcard entry so no
// sentinel grant survives. eval-bindable root writes are excluded — the
// replication's own chain analysis owns them.
func (c *subCollector) taintStmtSharedWrites(st *syntax.Stmt) {
	names, allUnv := writeNamesInStmtFuncs(st, c.posixNoBraces, c.funcNames)
	if allUnv {
		c.taintedVars["*"] = true
	}
	for _, name := range names {
		c.taintVar(name)
	}
}

// taintHiddenEvalWrites taints the writes of nested static evals hidden
// inside a statement the replication does NOT descend into (R20-Oracle-M2):
// preScanVarMutations counts every nested-eval write of the whole inner
// text, so a compound like `: && eval "PATH=/x"` inside a static eval
// provably CAN write the sentinel variable in the same shell — skipping
// the statement silently would leave the parent's original PATH standing
// in the substitution success proofs. Walked nested eval texts recurse
// through the same budgeted scan-and-taint path; every other write shape
// inside the compound is already covered by writtenNamesInNode.
// R25-Oracle-MF3 / R25-Reviewer-#4: the scan is process-BOUNDARY aware —
// eval texts re-parsed inside a child-process subtree (a backgrounded
// statement, a pipeline component, a command/process substitution, a
// subshell or a coprocess) install their positional facts inside a
// registry frame the subtree exit rolls back, because the re-parsed
// text no longer carries the bits of the process it runs in.
// R26-Oracle-M1 / R26-Reviewer-#5: the statement ITSELF is dispatched
// through scanHiddenEvalStmt — the boundary-aware root owner — instead
// of replaying the root call unframed here: the pre-R26 shape checked
// st.Background/st.Coprocess only AFTER the root eval call had already
// re-entered the text replay, leaking the child process's positional
// registrations into the parent collector.
func (c *subCollector) taintHiddenEvalWrites(st *syntax.Stmt, depth int) {
	scanWord := wordToArg
	if c.posixNoBraces {
		scanWord = wordToArgPosix
	}
	c.scanHiddenEvalStmt(st, scanWord, depth)
}

// scanHiddenEvalDispatch routes one AST node of the hidden-eval scan
// either into a framed child-process subtree scan or into the plain
// same-process descent (extracted for the R25 complexity budget):
// pipeline components, substitutions, subshells and coprocesses run in
// their own child processes, so every positional registration inside
// them belongs to a registry frame that closes when the subtree scan
// completes. The conservative variable taint the replays produce is
// unaffected — pollution belongs to the possibility, never the process.
func (c *subCollector) scanHiddenEvalDispatch(node syntax.Node, scanWord func(*syntax.Word) (string, bool), depth int) {
	if node == nil {
		return
	}
	if c.scanHiddenEvalChildFrame(node, scanWord, depth) {
		return
	}
	c.scanHiddenEvalNode(node, scanWord, depth)
}

// scanHiddenEvalChildFrame handles the child-process shapes of
// scanHiddenEvalDispatch (extracted for the R26 complexity budget):
// substitutions, subshells and coprocesses scan inside one registry
// frame, pipeline components scan in independent sibling frames
// through scanHiddenEvalPipeSiblings. Returns true when the node was
// a child-process shape and the scan completed here.
func (c *subCollector) scanHiddenEvalChildFrame(node syntax.Node, scanWord func(*syntax.Word) (string, bool), depth int) bool {
	switch x := node.(type) {
	case *syntax.CmdSubst:
		c.scanHiddenEvalSubstFrame(x.Stmts, scanWord, depth)
		return true
	case *syntax.ProcSubst:
		c.scanHiddenEvalSubstFrame(x.Stmts, scanWord, depth)
		return true
	case *syntax.Subshell:
		c.scanHiddenEvalSubstFrame(x.Stmts, scanWord, depth)
		return true
	case *syntax.CoprocClause:
		c.scanHiddenEvalCoprocFrame(x, scanWord, depth)
		return true
	case *syntax.BinaryCmd:
		if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
			c.scanHiddenEvalPipeSiblings(x, scanWord, depth)
			return true
		}
	}
	return false
}

// scanHiddenEvalSubstFrame scans one substitution/proc-substitution/
// subshell statement list inside its own registry frame (extracted for
// the R27 complexity budget — R27-Oracle-M1 / R27-Reviewer-#1):
// scanning the statement list through scanHiddenEvalFramedStmt covers
// the WHOLE subtree (every statement's root call, command subtree and
// redirections), so the pre-R27 scanHiddenEvalNode descent would
// double-scan it — and the per-statement registration makes the
// same-process definitions visible to the list's later statements
// before the frame restores.
func (c *subCollector) scanHiddenEvalSubstFrame(stmts []*syntax.Stmt, scanWord func(*syntax.Word) (string, bool), depth int) {
	defer c.snapshotProcessRegs()()
	c.scanHiddenEvalStmtList(stmts, scanWord, depth)
}

// scanHiddenEvalCoprocFrame scans the coprocess body inside its own
// registry frame (extracted for the R27 complexity budget): the body's
// same-process registrations are visible to the body's own later
// statements exactly like the substitution shapes.
func (c *subCollector) scanHiddenEvalCoprocFrame(x *syntax.CoprocClause, scanWord func(*syntax.Word) (string, bool), depth int) {
	if x.Stmt == nil {
		return
	}
	defer c.snapshotProcessRegs()()
	c.scanHiddenEvalFramedStmt(x.Stmt, scanWord, depth)
}

// scanHiddenEvalFramedStmt scans one same-process statement inside its
// OWN child-process frame (extracted for the R27 fix — R27-Oracle-M1 /
// R27-Reviewer-#1): the statement's same-process function definitions
// and readonly declarations register BEFORE the scan so they are
// visible to the eval replay the frame scans, while the enclosing
// frame's restore rolls them back when the child process exits. The
// registration is deliberately statement-order-blind inside one
// statement's subtree (definitions hoist over the statement's own
// earlier commands) — over-registration taints extra writes, never the
// reverse, and matches the pre-existing batch registration discipline
// of the eval replication loop.
func (c *subCollector) scanHiddenEvalFramedStmt(st *syntax.Stmt, scanWord func(*syntax.Word) (string, bool), depth int) {
	c.noteEvalStmtFuncDefs(st)
	c.noteEvalStmtReadonlyDecls(st)
	c.scanHiddenEvalStmt(st, scanWord, depth)
}

// scanHiddenEvalStmtList registers and scans a statement list of one
// child-process subtree (substitution, proc substitution or subshell —
// R27-Oracle-M1 / R27-Reviewer-#1): same-process definitions and
// declarations of earlier statements are visible to the LATER
// statements of the same list exactly like the real child shell's own
// sequential execution, so each statement registers before it scans
// inside the single frame the caller already opened.
func (c *subCollector) scanHiddenEvalStmtList(stmts []*syntax.Stmt, scanWord func(*syntax.Word) (string, bool), depth int) {
	for _, st := range stmts {
		if st == nil {
			continue
		}
		c.scanHiddenEvalFramedStmt(st, scanWord, depth)
	}
}

// scanHiddenEvalPipeSiblings scans the two components of one pipeline
// in independent sibling frames (extracted for the R26 complexity
// budget — R26-Oracle-M1 / R26-Reviewer-#5): EVERY pipeline component
// is its own child process exactly like walkStmt's pipe case — each
// side derives its registry boundary from the SAME parent state
// independently: the left component's nested-eval registrations
// (eval 'eval() { :; }') restore BEFORE the right component starts,
// never shadowing its name resolution, and neither side leaks into
// the parent. Same-process statements inside ONE component still see
// each other's registrations because the frame spans the component's
// whole subtree scan.
func (c *subCollector) scanHiddenEvalPipeSiblings(x *syntax.BinaryCmd, scanWord func(*syntax.Word) (string, bool), depth int) {
	// R27-Oracle-M1 / R27-Reviewer-#1: x.X and x.Y are *syntax.Stmt, so
	// the pre-R27 scanHiddenEvalDispatch routed them into
	// scanHiddenEvalNode — whose walk returns true at the root node and
	// whose CallExpr children never pass scanHiddenEvalStmtBody, silently
	// skipping the component's own root eval call (`eval 'eval() { :; }'
	// | command -x eval`) and every redirection scan of the root. Each
	// sibling now enters through scanHiddenEvalFramedStmt: the root call
	// check plus redirection descent of scanHiddenEvalStmt apply, AND
	// the component's directly-written same-process function definitions
	// / readonly declarations (the AST FuncDecl of
	// `{ eval() { :; }; eval; } | cat`, not an eval-text re-parse)
	// register inside the sibling's own frame — visible to the eval
	// replay the frame scans, rolled back when the child process exits.
	restoreX := c.snapshotProcessRegs()
	c.scanHiddenEvalFramedStmt(x.X, scanWord, depth)
	restoreX()
	restoreY := c.snapshotProcessRegs()
	c.scanHiddenEvalFramedStmt(x.Y, scanWord, depth)
	restoreY()
}

// scanHiddenEvalNode walks one AST node for nested eval invocations: a
// statement node is dispatched through the boundary-aware check (a
// backgrounded or coprocess statement is a child process exactly like
// the outer spelling), and every other node recurses into its immediate
// children so the scan visits the whole subtree exactly once —
// syntax.Walk lacks an exit hook, so the process-boundary frames are
// driven by explicit recursion instead.
func (c *subCollector) scanHiddenEvalNode(node syntax.Node, scanWord func(*syntax.Word) (string, bool), depth int) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(n syntax.Node) bool {
		if n == node {
			return true // descend into the children; the root itself was already dispatched
		}
		c.scanHiddenEvalChild(n, scanWord, depth)
		return false
	})
}

// scanHiddenEvalChild is the per-child dispatch of scanHiddenEvalNode
// (extracted so the recursion closure carries no branching): statement
// nodes check the hidden eval call or enter their own boundary frame,
// everything else descends through the boundary dispatcher.
func (c *subCollector) scanHiddenEvalChild(n syntax.Node, scanWord func(*syntax.Word) (string, bool), depth int) {
	if ist, isStmt := n.(*syntax.Stmt); isStmt {
		c.scanHiddenEvalStmt(ist, scanWord, depth)
		return
	}
	c.scanHiddenEvalDispatch(n, scanWord, depth)
}

// scanHiddenEvalStmt checks one statement node of the hidden-eval scan
// (R26-Reviewer-#6): a backgrounded or coprocess statement scans its
// subtree inside a registry frame (its eval replays install
// child-process-only facts), while a same-process statement's root
// call is checked directly. The scan covers the WHOLE statement —
// ist.Cmd AND every redirection word/heredoc of ist.Redirs: the
// pre-R26 walk returned early on a nil command and never descended
// into the redirection subtree at all, so a command substitution
// hiding a nested eval inside `: >/dev/null/$(command -x eval)`
// escaped the replay the pre-scan counts.
func (c *subCollector) scanHiddenEvalStmt(ist *syntax.Stmt, scanWord func(*syntax.Word) (string, bool), depth int) {
	if ist == nil {
		return
	}
	if ist.Background || ist.Coprocess {
		defer c.snapshotProcessRegs()()
		c.scanHiddenEvalStmtBody(ist, scanWord, depth)
		return
	}
	c.scanHiddenEvalStmtBody(ist, scanWord, depth)
}

// scanHiddenEvalStmtBody is the root-check plus subtree descent of
// scanHiddenEvalStmt (extracted for the R26 complexity budget — the
// process-boundary frame carries no node branching): the statement's
// own root eval call is checked exactly once, and the descent covers
// both the command subtree and every redirection word/heredoc of the
// statement's Redirs list.
func (c *subCollector) scanHiddenEvalStmtBody(ist *syntax.Stmt, scanWord func(*syntax.Word) (string, bool), depth int) {
	if call, isCall := ist.Cmd.(*syntax.CallExpr); isCall {
		c.taintOneEvalCallWrites(call, scanWord, depth+1)
	}
	if ist.Cmd != nil {
		c.scanHiddenEvalDispatch(ist.Cmd, scanWord, depth)
	}
	for _, r := range ist.Redirs {
		if r == nil {
			continue
		}
		if r.Word != nil {
			c.scanHiddenEvalDispatch(r.Word, scanWord, depth)
		}
		if r.Hdoc != nil {
			c.scanHiddenEvalDispatch(r.Hdoc, scanWord, depth)
		}
	}
}

// taintEvalBoundary applies the maximal pollution verdict for an
// eval chain whose operand boundary is unconfirmable (R22-Oracle-M2 /
// R22-Reviewer-#4): the statement-level write scan (writeNamesInStmtFuncs,
// untruncated for taint verdicts) already covers every enumerable write,
// so the replication adds exactly the sentinelTrustVars/PATH share the
// scan cannot know are at risk — the single-write PATH pollution
// exemption never extends to an unconfirmable eval boundary. The verdict
// applies ONLY to chains that actually shaped toward eval: a plain
// dynamic command head (`$s`, `$(cmd)`) is not eval-shaped at all — the
// pre-scan counts no operand writes for it (its unvettable-head
// bookkeeping taints PWD/OLDPWD at the parse level independently), so
// polluting here would revoke grants the scan never endangered.
func (c *subCollector) taintEvalBoundary(verdict evalChainVerdict, args []*syntax.Word) {
	if verdict != evalChainTaint || !evalChainShaped(args) {
		return
	}
	c.taintSentinelVars()
	c.taintVar("PATH")
}

// taintOneEvalCallWrites taints the writes of ONE eval-shaped invocation
// (extracted for the v6.2.2 R21 complexity budget): a bindable chain's
// static operand text taints recursively through the shared budget path,
// a failing chain premises keeps the same conservative verdict (the
// pre-scan counts the write either way), and a dynamic operand taints
// the sentinel set exactly like the pre-scan's own fallback. Pure
// resolution queries and non-eval heads are skipped precisely.
func (c *subCollector) taintOneEvalCallWrites(call *syntax.CallExpr, scanWord func(*syntax.Word) (string, bool), depth int) {
	verdict, rest := peelEvalBuiltinChainShadowed(call.Args, c.posixNoBraces, c.funcNames)
	if evalChainSkippable(verdict) {
		return
	}
	// R23-Reviewer-#4 / R23-Oracle-M2: operand-expansion writes and the
	// uniform taint boundary apply to the nested walk exactly like the
	// root replication — a short or absent rest of a TAINTED chain is
	// pollution, never a silent skip.
	c.taintOperandParamAssigns(call.Args)
	if len(rest) < 2 {
		c.taintShortRestBoundary(verdict, call.Args)
		return
	}
	parts, static := evalStaticOperandParts(rest, scanWord)
	if !static {
		c.taintSentinelVars()
		return
	}
	c.taintEvalTextWrites(strings.Join(parts, " "), depth)
}

// evalChainSkippable reports whether one eval chain verdict carries no
// replication subject at all (extracted for the R23 complexity budget):
// a non-eval head or a provable pure resolution query executes nothing
// the pre-scan counts, so the replication can skip it precisely.
func evalChainSkippable(verdict evalChainVerdict) bool {
	return verdict == evalChainNone || verdict == evalChainQuery
}

// taintShortRestBoundary applies the uniform maximal pollution verdict
// for a chain whose rest is too short to carry operand text (extracted
// for the R23 complexity budget — R23-Reviewer-#4): only a TAINTED
// chain carries the unconfirmable boundary; a proven bind chain with no
// operands genuinely re-parses nothing.
func (c *subCollector) taintShortRestBoundary(verdict evalChainVerdict, args []*syntax.Word) {
	if verdict == evalChainTaint {
		c.taintEvalBoundary(verdict, args)
	}
}

// bindEvalStmtWrites replays the writes of one static eval's statement
// list: a pure top-level assignment binds through the collector's own
// staticAssignVal/noteStaticAssign pair (exactly the path a direct
// assignment statement takes — allowBind, SSA blocking and taint reuse
// included), a nested static eval recurses, and every OTHER statement's
// written names are conservatively tainted because their execution is
// conditional on that statement's own commands (mirroring how an if/for/
// loop body write never earns a bind in the outer script either).
func (c *subCollector) bindEvalStmtWrites(stmts []*syntax.Stmt, depth int) {
	for _, st := range stmts {
		if st == nil {
			continue
		}
		c.bindEvalOneStmt(st, depth)
	}
}

// bindEvalOneStmt replays the writes of one statement inside a static
// eval text (extracted from bindEvalStmtWrites so the shadowing
// registration carries no extra nesting — R22 complexity budget).
func (c *subCollector) bindEvalOneStmt(st *syntax.Stmt, depth int) {
	// R25-Oracle-MF3 / R25-Reviewer-#4: a backgrounded or coprocess
	// statement inside the eval text runs in its own child process —
	// every positional registration the nested replay produces inside
	// it (including static eval texts re-parsed deeper down) dies with
	// the child, so the whole statement replays inside one registry
	// frame. The conservative variable TAINT of the same writes is
	// deliberately unaffected: pollution belongs to the possibility,
	// never the process ownership.
	if st.Background || st.Coprocess {
		defer c.snapshotProcessRegs()()
		c.bindEvalOneStmtBody(st, depth)
		return
	}
	c.bindEvalOneStmtBody(st, depth)
}

// bindEvalOneStmtBody is the replay body of bindEvalOneStmt (extracted
// for the R25 complexity budget — the process-boundary frame carries no
// statement-shape branching): the nesting below is exactly the pre-R25
// replay, now guaranteed to run under the boundary frame the child
// process requires.
func (c *subCollector) bindEvalOneStmtBody(st *syntax.Stmt, depth int) {
	// R22-Oracle-M1 / R22-Reviewer-#3: the nested replay shares the
	// shadowing premise with the outer walk — a shell function
	// definition inside the eval text takes effect for every LATER
	// same-process re-parse exactly like one written directly, so it
	// registers before the statement's own write accounting.
	// R23-Reviewer-#3 / R23-Oracle-M1: same-process COMPOUND blocks
	// ({ ...; }, if/while/for/case bodies) register their definitions
	// exactly like a top-level FuncDecl — name resolution in the real
	// shell does not distinguish where inside the same process the
	// definition executed.
	// R24-Reviewer-#3 / R24-Oracle-M3: the readonly attribute replay is
	// part of the same positional registration — a declaration inside the
	// eval text freezes the variable for every LATER write exactly like
	// the direct spelling registered through emitDecl/emitCall.
	c.noteEvalStmtFuncDefs(st)
	c.noteEvalStmtReadonlyDecls(st)
	call, isCall := st.Cmd.(*syntax.CallExpr)
	if isCall && !st.Background && !st.Negated && !st.Coprocess && len(st.Redirs) == 0 && len(call.Args) == 0 {
		// R20-Oracle-M1: the statement must be a PROVABLY-executed bare
		// assignment sequence — no redirections (a failing one aborts
		// before the assignment) — and every assignment a plain
		// unsubscripted scalar `=`: bash's `+=` concatenates onto the
		// inherited value, so the result is never the literal suffix
		// the word carries, and an array-subscript write `a[1]=/x`
		// leaves every other element of the array intact, so the
		// scalar is never the exact bind either (R21-Reviewer-2).
		// The conservative verdict for both is pollution, never a bind.
		for _, a := range call.Assigns {
			if a.Name == nil || a.Naked {
				continue
			}
			if a.Append || a.Index != nil {
				c.taintVar(a.Name.Value)
				continue
			}
			val, stOk := c.staticAssignVal(a.Value)
			// R22-Oracle-M1: the replication replays pure assignment
			// writes — a readonly-declared variable can never receive
			// them at runtime, so the declaration-aware gate applies
			// exactly like the direct spelling.
			c.noteShellAssign(a.Name.Value, val, stOk)
		}
		return
	}
	c.taintStmtSharedWrites(st)
	if !isCall {
		// R20-Oracle-M2: a compound statement (AndStmt/OrStmt/if/brace
		// group/subshell/pipeline/loop) can hide nested static evals
		// whose writes the replication loop here never reaches — the
		// pre-scan counts them, so they must surface as pollution.
		c.taintHiddenEvalWrites(st, depth)
		return
	}
	verdict, rest := peelEvalBuiltinChainShadowed(call.Args, c.posixNoBraces, c.funcNames)
	if verdict == evalChainNone || verdict == evalChainQuery {
		c.taintHiddenEvalWrites(st, depth)
		return
	}
	// R23-Reviewer-#4 / R23-Oracle-M2: the operand-expansion writes belong
	// to the nested operand evaluation exactly like the root call's — the
	// replication owns them for every surviving chain verdict.
	c.taintOperandParamAssigns(call.Args)
	if len(rest) < 2 {
		// R23-Reviewer-#4: a TAINTED chain without a confirmable operand
		// boundary (including a rest too short to carry operand text)
		// faces the uniform maximal pollution verdict — the nested replay
		// must not silently drop what the root call already refuses.
		c.taintShortRestBoundary(verdict, call.Args)
		c.taintHiddenEvalWrites(st, depth)
		return
	}
	scanWord := wordToArg
	if c.posixNoBraces {
		scanWord = wordToArgPosix
	}
	parts, static := evalStaticOperandParts(rest, scanWord)
	if !static {
		c.taintSentinelVars()
		return
	}
	text := strings.Join(parts, " ")
	if c.nestedEvalMustTaint(verdict, st) {
		// R20-Oracle-M1 premises apply to nested evals exactly like the
		// outer one: an external path head, a possibly-failing redirect
		// or a child-process/conditional execution never mints a bind,
		// and the write is pollution instead of a silent skip.
		c.taintEvalTextWrites(text, depth+1)
		return
	}
	c.bindEvalTextWrites(text, depth+1)
}

// nestedEvalMustTaint reports whether one nested eval statement fails
// the exact-binding premises (extracted for the R23 complexity budget —
// the R20-Oracle-M1 premises apply to nested evals exactly like the
// outer one): a non-bind chain verdict, a possibly-failing redirection
// or a child-process/conditional execution never mints a bind.
func (c *subCollector) nestedEvalMustTaint(verdict evalChainVerdict, st *syntax.Stmt) bool {
	return verdict != evalChainBind || len(st.Redirs) > 0 || st.Background || st.Negated || st.Coprocess
}

// parseSubagentShellAST parses code into shellSegments for subagent guards.
// ok=false means fail-closed (caller treats as depthExceeded). envTaint
// carries environment-override knowledge from an outer envAs (HOME=/x sh -c,
// env -i sh -c, env -u PWD ...): every named variable's expansion is treated
// as untrusted inside this script, degrading the PATH/HOME/absolute-dir
// placeholder grants to plain dynamic placeholders.
func parseSubagentShellAST(code string, depth int, pipeIn bool, useBashVariant bool) ([]shellSegment, bool) {
	return parseSubagentShellASTEnv(code, depth, pipeIn, useBashVariant, nil, callerIdentity{})
}

// parseSubagentShellASTEnv is parseSubagentShellAST plus an envTaint set
// for the env/ssh AST descent (SH11 F3/Q5). caller carries the screened
// call's cwd so a bare $(pwd) can bind the directory the inner shell will
// actually start in — and so any cd/chdir/pushd/popd in the script can
// invalidate that static bind (task R2-3).
func parseSubagentShellASTEnv(code string, depth int, pipeIn bool, useBashVariant bool, envTaint map[string]bool, caller callerIdentity) ([]shellSegment, bool) {
	if hit := checkShellBytes(code, false); hit != "" {
		return []shellSegment{{depthExceeded: true}}, false
	}
	if depth >= shellSplitMaxDepth {
		return []shellSegment{{depthExceeded: true}}, false
	}

	posixParser := syntax.NewParser(syntax.Variant(syntax.LangPOSIX), syntax.KeepComments(true))
	bashParser := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(true))
	posixFile, perr := posixParser.Parse(strings.NewReader(code), "")
	var bashFile *syntax.File
	var berr error
	if bf, e := bashParser.Parse(strings.NewReader(code), ""); e == nil {
		bashFile = bf
	} else {
		berr = e
	}
	if useBashVariant {
		if berr != nil {
			return []shellSegment{{parseErr: "shell syntax error: " + berr.Error()}}, false
		}
		if perr != nil {
			posixFile = nil
		}
	} else {
		// Top-level ctx_run is /bin/sh (dash): no LangBash fallback.
		if perr != nil {
			if berr == nil {
				return []shellSegment{{parseErr: "bash-only syntax under /bin/sh Hint: /bin/sh 是 dash，不支持这种写法，请改用 bash -c '...'"}}, false
			}
			return []shellSegment{{parseErr: "shell syntax error: " + perr.Error()}}, false
		}
		if berr != nil {
			bashFile = nil
		}
	}

	col := &subCollector{code: code, depth: depth, staticVars: map[string]string{}, enumVars: map[string]string{}, taintedVars: map[string]bool{}, enumCmdWords: map[string][]string{}, allowBind: true, caller: caller, posixNoBraces: !useBashVariant}
	// R21-Oracle-M3: mint the shared scope-id counter EAGERLY — substitution
	// sub-collectors copy the pointer through newSub, and a lazily-created
	// per-sub counter would collide sibling scope ids.
	zeroScopeCounter := 0
	col.scopeCounter = &zeroScopeCounter
	for name := range envTaint {
		col.taintedVars[name] = true
	}
	primary := posixFile
	if useBashVariant {
		primary = bashFile
	}
	if primary == nil {
		return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
	}
	if hit := validateParsedShellFile(col, code, primary); hit != "" {
		return []shellSegment{{parseErr: hit}}, false
	}
	if !useBashVariant && bashFile != nil {
		if hit := validateParsedShellFile(col, code, bashFile); hit != "" {
			return []shellSegment{{parseErr: hit}}, false
		}
	}
	if useBashVariant && posixFile != nil {
		if hit := validateParsedShellFile(col, code, posixFile); hit != "" {
			return []shellSegment{{parseErr: hit}}, false
		}
	}

	col.ssaBlocked = map[string]bool{}
	writes, allTainted := preScanVarMutations(primary, !useBashVariant)
	if allTainted {
		for name := range writes {
			col.taintedVars[name] = true
			col.ssaBlocked[name] = true
		}
		col.taintedVars["*"] = true
		// S1: the "*" sentinel means every variable may be unreadable — no
		// bind collected so far can still be trusted.
		col.staticVars = map[string]string{}
		col.litVars = map[string]string{}
		col.enumVars = map[string]string{}
		col.enumCmdWords = map[string][]string{}
	} else {
		for name, n := range writes {
			if n > 1 {
				col.taintedVars[name] = true
				col.ssaBlocked[name] = true
			}
		}
	}
	// SH11 F2/F3/F6: variables whose value the sentinel/placeholder grant
	// model depends on (HOME safe-dir, PWD/OLDPWD absolute-dir, TMPDIR for
	// mktemp, IFS for enum word-splitting) must be treated as unknown the
	// moment the script writes them even once — a single write is already
	// enough to invalidate "the expansion is the inherited/safe value".
	for name := range writes {
		if name == "PATH" {
			continue // every PATH= value is screened by envAs ops instead
		}
		if sentinelTrustVars[name] {
			col.taintedVars[name] = true
			col.ssaBlocked[name] = true
		}
	}
	col.walkStmts(primary.Stmts, stdinFeed{piped: pipeIn})
	if col.rejected {
		return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
	}
	secondary := posixFile
	if !useBashVariant {
		secondary = bashFile
	}
	if !col.walkSecondaryShellFile(secondary, pipeIn) {
		return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
	}
	// R16-Oracle-M2: every segment this parse produced was encoded under
	// ONE interpreter dialect — the same collector's posixNoBraces applies
	// to the secondary-tree walk too, so the whole result shares the
	// dialect. Mark it so a same-process re-parse (eval / trap action)
	// re-enters the guard under the interpreter that will actually
	// consume the text instead of falling back to the dash default.
	for i := range col.segs {
		col.segs[i].bashDialect = useBashVariant
	}
	return col.segs, true
}

// validateParsedShellFile runs the comment/continuation scan and the
// fail-closed walk for one already-parsed file (extracted for the v6.2.2
// R17 complexity budget): "" means valid, anything else is the parseErr
// detail the caller surfaces.
func validateParsedShellFile(col *subCollector, code string, f *syntax.File) string {
	if f == nil {
		return ""
	}
	if hit := checkCommentsAndContinuations(code, f, false); hit != "" {
		return hit
	}
	if !col.failClosedFile(f) {
		return "shell AST fail-closed"
	}
	return ""
}

// walkSecondaryShellFile walks the non-primary dialect tree of one parse
// (extracted for the v6.2.2 R17 complexity budget), dedupes the appended
// tail against the primary segments and marks it secondary-dialect. A nil
// file (the cross-parse failed) is a no-op success.
func (col *subCollector) walkSecondaryShellFile(f *syntax.File, pipeIn bool) bool {
	if f == nil {
		return true
	}
	pre := len(col.segs)
	// R22-Oracle-M1: the ORDER-sensitive shadowing/readonly tracks are
	// per-walk source-order replays — the primary tree's final position
	// (every function defined, every readonly attribute installed) must
	// not contaminate the secondary tree's first statements, or an
	// eval that runs BEFORE its shadowing definition in source order
	// loses its binding in the cross-dialect walk. The write-scan
	// taints stay cumulative across both trees exactly like before
	// (the union is the conservative direction); only the positional
	// tracks restart. Substitution sub-collectors minted inside this
	// walk copy the restarted state, matching the source position they
	// really sit at.
	savedFuncs, savedReadonly := col.funcNames, col.readonlyVars
	col.funcNames, col.readonlyVars = nil, nil
	col.walkStmts(f.Stmts, stdinFeed{piped: pipeIn})
	col.funcNames, col.readonlyVars = savedFuncs, savedReadonly
	if col.rejected {
		return false
	}
	col.segs = dedupeSegTail(col.segs, pre)
	markSecondaryDialect(col.segs, pre)
	return true
}

// markSecondaryDialect flags the segments appended by the non-primary dialect
// walk. The primary block [0,pre) is left untouched by dedupeSegTail, so the
// boundary is exact.
func markSecondaryDialect(segs []shellSegment, pre int) {
	if pre <= 0 {
		return
	}
	for i := pre; i < len(segs); i++ {
		segs[i].secondaryDialect = true
	}
}

func dedupeSegTail(segs []shellSegment, pre int) []shellSegment {
	if pre <= 0 || pre >= len(segs) {
		return segs
	}
	head, tail := segs[:pre], segs[pre:]
	out := head
	for _, s := range tail {
		dup := false
		for _, h := range head {
			if segEqual(h, s) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

func segEqual(a, b shellSegment) bool {
	if a.depthExceeded != b.depthExceeded || a.pipedStdin != b.pipedStdin ||
		a.backgrounded != b.backgrounded || a.processSubst != b.processSubst ||
		a.stdinRedir != b.stdinRedir ||
		a.redirectFile != b.redirectFile || a.hereString != b.hereString ||
		a.parseErr != b.parseErr ||
		len(a.argv) != len(b.argv) || len(a.heredocText) != len(b.heredocText) {
		return false
	}
	for i := range a.argv {
		if a.argv[i] != b.argv[i] {
			return false
		}
	}
	for i := range a.heredocText {
		if a.heredocText[i] != b.heredocText[i] {
			return false
		}
	}
	return true
}

type subCollector struct {
	code         string
	depth        int
	segs         []shellSegment
	rejected     bool
	staticVars   map[string]string   // head-eligible safe-value binds (R-Allow-2)
	litVars      map[string]string   // safe-literal binds: in-word subst only, never heads (ALW31)
	enumVars     map[string]string   // for-loop enum temporary binds (payload subst only)
	enumCmdWords map[string][]string // for-loop enum multi-word command binds (W11-5)
	taintedVars  map[string]bool
	ssaBlocked   map[string]bool // G3: writeCount>1 from preScan
	allowBind    bool            // top-level sequential stmts only (R-Allow-2)
	fdUnvetted   bool            // inside a function body: unproven dups fail closed (R17 MF-2)
	// caller is the screened call identity: its cwd is the base a bare
	// $(pwd) expansion must resolve against, and any cd/chdir/pushd/popd
	// in the script (or a pre-scan that sees a directory-switch builtin)
	// taints the static cwd bind — a later $(pwd) then stays a dynamic
	// placeholder instead of a literal the guard trusts.
	caller callerIdentity
	hasCd  bool // any directory-switch builtin seen anywhere in the script
	// posixNoBraces marks the POSIX/dash TOP-LEVEL dialect (R15-Oracle-S1):
	// /bin/sh is dash on the deployment topology, which performs NO brace
	// expansion, so the primary-dialect encoding must not treat literal
	// '{a,b}' text as a word-multiplying bash expansion. Explicit
	// `bash -c` payloads keep posixNoBraces=false — bash really does
	// expand — and the blank-collector zero value keeps the conservative
	// bash detection for pure parser probes.
	posixNoBraces bool
	// childScope marks statements executing in a CHILD execution scope
	// (R20-Oracle-M3): pipeline components, `( ... )` subshells and
	// backgrounded subtrees run in their own processes — their pure
	// assignments die with the child and must never be accumulated into
	// the parent shell's stdin-scan environment. Command/process
	// substitutions inherit it through newSub (the zero value propagates
	// false only at the real parent level).
	childScope bool
	// scopePath identifies the execution scope the current subtree runs
	// in (R21-Oracle-M3 / R21-Reviewer-1): "" is the parent shell's own
	// scope, and every child execution scope (subshell body, each
	// pipeline component, backgrounded subtree, command/process
	// substitution) receives a UNIQUE dotted suffix. Pure assignments
	// inside a child scope bind within that same child environment —
	// visible to the SAME child's later consumers, dead the moment the
	// scope pops — instead of being dropped wholesale (the R20 flat
	// boolean) or smuggled into the parent (the pre-R20 behavior).
	scopePath string
	// scopeCounter is the per-parse unique scope id source shared by the
	// root collector and every substitution sub-collector so no two
	// child scopes ever collide (sibling scopes MUST diverge: two
	// subshells each fork their own environment).
	scopeCounter *int
	// condDepth counts enclosing conditional regions (the right side of
	// `&&`/`||`, if/case branches, loop bodies, uncalled function bodies):
	// assignments minted while condDepth > 0 may or may not execute, so
	// the control-flow JOIN must treat every variable they touch as
	// uncertain (R21-Oracle-M3) — never an exact override of the outer
	// shell's environment.
	condDepth int
	// readonlyVars records variable names the script declared READONLY
	// (`readonly X`, `declare -r X`, `typeset -r X`) before the current
	// walk position (R22-Oracle-M1 / R22-Reviewer-#3): a later assignment
	// to such a name fails at runtime, so it can never establish the new
	// value the word carries — the replication must refuse the exact
	// binding and treat the write as pollution instead. The declaration
	// with an inline value (`readonly X=/x`) still mints its own bind
	// first (that assignment itself succeeds); only writes AFTER the
	// readonly attribute took effect are excluded.
	readonlyVars map[string]bool
	// funcNames records the names of shell functions defined so far
	// (R22-Oracle-M1 / R22-Reviewer-#3): shell name resolution tries a
	// same-named FUNCTION before any builtin, so once `eval`/`command`/
	// `builtin` is shadowed by a function definition the bare word no
	// longer invokes the builtin and the eval chain replication must
	// refuse the exact binding. Only definitions reached before the
	// invocation in statement order count — the walk is single-pass, so
	// a later definition cannot shadow an earlier call either at
	// runtime or in this model.
	funcNames map[string]bool
	// funcNamesShared / readonlyVarsShared mark a map newSub handed to a
	// substitution collector WITHOUT cloning (R24-Oracle-S2): the first
	// positional-track write inside the child clones lazily, so a
	// substitution that never defines a function or declares a readonly
	// variable pays no copy at all. Only the two mutation owners
	// (noteFuncDef, noteReadonlyDecls) consult the bits; every read of
	// the shared map is exactly as correct as a read of the clone.
	funcNamesShared    bool
	readonlyVarsShared bool
	// regUndo is the incremental undo log of open child-process
	// boundaries (R24-Reviewer-#3 / R24-Oracle-S2): entering a subshell,
	// pipeline component, backgrounded subtree or coprocess pushes one
	// frame, and the mutation owners append only the keys they newly
	// insert while that frame is innermost. Restoring deletes exactly
	// those keys — the parent maps never move — so a child process that
	// writes nothing pays O(1) instead of one full-table clone per map.
	regUndo []*processRegFrame
	// regCopyElements counts positional-registry map elements copied by
	// copy-on-write for THIS collector (test observability for
	// R24-Oracle-S2): the child-process boundary itself must never copy
	// anything, so an empty child shell keeps the count at zero no matter
	// how many names the parent registered before entering it.
	regCopyElements int
}

// processRegFrame is one open child-process registry boundary of
// subCollector.regUndo: the names added to funcNames/readonlyVars while
// the frame is innermost. Keys are recorded only on first insertion —
// redefining an already-registered name leaves the parent's truth value
// unchanged, so nothing needs undoing.
type processRegFrame struct {
	funcs    map[string]bool
	readonly map[string]bool
	// restored latches the frame closed exactly once (R25): a double
	// restore of the same frame must never delete keys a LATER child
	// legitimately re-registered.
	restored bool
}

// shellNonBindableVars are the Bash/POSIX special variables whose value
// an assignment can NEVER establish at runtime (R22-Oracle-M1 /
// R22-Reviewer-#3): some are truly readonly (UID/EUID/PPID), some are
// dynamic (RANDOM/SRANDOM re-seed a fresh value on every expansion,
// SECONDS/EPOCHSECONDS count time, LINENO tracks the line), and the rest
// are shell-maintained state (GROUPS/FUNCNAME/BASHPID/BASHOPTS/
// SHELLOPTS/HISTCMD/BASH_SUBSHELL/BASH_VERSINFO). A static `X=v`
// spelling of any of these either errors (readonly) or silently drops
// the value on the very next expansion, so minting an exact binding
// would hand the substitution proofs a value the shell never yields.
// Both dialects share the conservative superset: dash lacks most of
// these names, but an unprovable assignment there is no more bindable
// than in bash.
var shellNonBindableVars = map[string]bool{
	"UID": true, "EUID": true, "PPID": true, "BASHPID": true,
	"SHELLOPTS": true, "BASHOPTS": true, "GROUPS": true, "FUNCNAME": true,
	"LINENO": true, "RANDOM": true, "SECONDS": true, "SRANDOM": true,
	"EPOCHSECONDS": true, "EPOCHREALTIME": true, "HISTCMD": true,
	"BASH_SUBSHELL": true, "BASH_VERSINFO": true,
	// R23-Reviewer-#3 / R23-Oracle-M1: PIPESTATUS is re-written by bash
	// after EVERY foreground pipeline — even a successful write to
	// PIPESTATUS[0] is discarded by the very next simple command — and
	// `_` is re-bound at every command start, so neither can ever hold
	// the value an assignment word spells across the next expansion.
	"PIPESTATUS": true, "_": true,
}

// enterChildScope switches the collector into a freshly minted child
// execution scope, returning the restore closure (R21-Oracle-M3): every
// scope id is unique within the parse via the shared counter, so two
// sibling subshells or pipeline components never alias each other.
func (c *subCollector) enterChildScope() func() {
	if c.scopeCounter == nil {
		n := 0
		c.scopeCounter = &n
	}
	*c.scopeCounter = *c.scopeCounter + 1
	prevPath, prevScope := c.scopePath, c.childScope
	id := *c.scopeCounter
	c.scopePath = c.scopePath + "/" + strconv.Itoa(id)
	c.childScope = true
	return func() { c.scopePath, c.childScope = prevPath, prevScope }
}

// enterConditional switches the collector into one conditional region
// (R21-Oracle-M3): assignments minted inside may or may not execute, so
// the accumulation treats them as control-flow-merge taint instead of
// exact environment overrides.
func (c *subCollector) enterConditional() func() {
	c.condDepth++
	return func() { c.condDepth-- }
}

// snapshotProcessRegs opens one incremental child-process boundary on
// the positional process-state tracks (funcNames/readonlyVars —
// R23-Reviewer-#3 / R24-Oracle-S2) and returns the restore closure.
// R24-Reviewer-#3 / R24-Oracle-S2: the pre-R24 implementation cloned
// BOTH maps on entry, so registering n functions and then walking n
// child processes copied n(n+1)/2 entries even when no child wrote a
// single name. The boundary is copy-on-WRITE instead: the frame records
// only the keys actually inserted while it is innermost, and restoring
// deletes exactly those additions. The maps themselves never move, the
// parent's entries are immutable at runtime (registrations only ever
// write true), and a child that defines or declares nothing pays O(1).
// R25: the closure is a single-line delegation so the undo bookkeeping
// carries its complexity budget inside one named method.
func (c *subCollector) snapshotProcessRegs() func() {
	frame := &processRegFrame{}
	c.regUndo = append(c.regUndo, frame)
	return func() { c.restoreProcessRegFrame(frame) }
}

// restoreProcessRegFrame is the single-owner undo of one
// snapshotProcessRegs frame (extracted for the R25 complexity budget —
// the closure must carry no scan branching): restoring once deletes
// exactly the additions the frame recorded while it was innermost, and
// a stale or already-restored frame is a no-op.
func (c *subCollector) restoreProcessRegFrame(frame *processRegFrame) {
	if frame.restored {
		return
	}
	frame.restored = true
	idx := -1
	for i := len(c.regUndo) - 1; i >= 0; i-- {
		if c.regUndo[i] == frame {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	c.regUndo = append(c.regUndo[:idx], c.regUndo[idx+1:]...)
	for name := range frame.funcs {
		delete(c.funcNames, name)
	}
	for name := range frame.readonly {
		delete(c.readonlyVars, name)
	}
}

// noteProcessRegAdd records one first insertion into the innermost open
// child-process registry frame (extracted so both mutation owners carry
// no frame-walk nesting): the addition belongs to the boundary it was
// minted under, and restoring that boundary deletes it exactly like the
// runtime discarding the child process's name table.
func (c *subCollector) noteProcessRegAdd(name string, readonly bool) {
	if len(c.regUndo) == 0 {
		return
	}
	frame := c.regUndo[len(c.regUndo)-1]
	if readonly {
		if frame.readonly == nil {
			frame.readonly = map[string]bool{}
		}
		frame.readonly[name] = true
		return
	}
	if frame.funcs == nil {
		frame.funcs = map[string]bool{}
	}
	frame.funcs[name] = true
}

// noteSameProcessFuncDefs registers every shell function definition
// statement of one eval-text statement that runs in the SAME shell
// process (R23-Reviewer-#3 / R23-Oracle-M1): the eval replication and
// the taint replay both re-parse operand text top-level only, but a
// definition inside a same-process compound block ({ ...; }, if/while/
// for/case bodies) is exactly as visible to the shell's later name
// resolution as a top-level one — the pre-R23 replay never registered
// it, so a following bare eval in the enclosing script minted the
// builtin binding a shadowed runtime can never perform. Definitions
// inside child-process shapes (pipes, command substitutions, process
// substitutions, subshells) die with the child and are skipped; the
// background bit of the statement itself is the caller's boundary,
// already handled at the outer scope level.
func (c *subCollector) noteSameProcessFuncDefs(st *syntax.Stmt) {
	// R24-Reviewer-#3 / R24-Oracle-M3: the statement's own process
	// boundary is the FIRST check — a backgrounded or coprocess subtree
	// runs in its own child process, so every definition inside it dies
	// with the child no matter how shallowly it nests. The pre-R24 scan
	// walked straight into st.Cmd and registered `{ eval() { :; }; } &`
	// into the parent table.
	if childProcStmtBoundary(st) {
		return
	}
	// R25: the walk callback is a single-line delegation so the
	// function-definition scan carries its boundary branching inside one
	// named method (complexity budget).
	syntax.Walk(st.Cmd, func(node syntax.Node) bool { return c.visitSameProcessFuncDefNode(node) })
}

// visitSameProcessFuncDefNode is the per-node scan of
// noteSameProcessFuncDefs (extracted for the R25 complexity budget):
// nested statements carry their own process bits (a backgrounded brace
// group is a child process exactly like the outer spelling), same-process
// compound blocks register their definitions, and definitions inside
// child-process shapes die with the child.
func (c *subCollector) visitSameProcessFuncDefNode(node syntax.Node) bool {
	if node == nil {
		return false
	}
	switch x := node.(type) {
	case *syntax.Stmt:
		// Nested statements carry their own process bits: a pipeline
		// component or brace group followed by `&` inside the eval text
		// is a child process exactly like the outer spelling.
		if x.Background || x.Coprocess {
			return false
		}
		return true
	case *syntax.FuncDecl:
		c.noteFuncDef(x)
		return true
	case *syntax.BinaryCmd:
		if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
			return false // pipeline components are child processes
		}
		return true
	case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.Subshell, *syntax.CoprocClause:
		return false // child processes: definitions die with them
	}
	return true
}

// noteFuncDef records a shell function definition (R22-Oracle-M1 /
// R22-Reviewer-#3): the definition TAKES EFFECT at this statement —
// every later bare invocation of the same name resolves to the function,
// never to a same-named builtin — so the name is registered BEFORE the
// body is walked and the shadowing premise is visible to the eval chain
// analysis of everything after it.
func (c *subCollector) noteFuncDef(fd *syntax.FuncDecl) {
	if fd == nil || fd.Name == nil {
		return
	}
	// R24-Oracle-S2: the insertion path clones the shared substitution
	// map lazily on its first positional write — reads never needed the
	// copy. Extracted so the registration owner carries no registry
	// bookkeeping nesting (R24 complexity budget).
	c.regInsertFuncNames(fd.Name.Value)
}

// regInsertFuncNames installs one name into the positional function
// registry (extracted from noteFuncDef / noteReadonlyDecls for the R24
// complexity budget): the copy-on-write clone, the nil-table mint, the
// incremental undo bookkeeping and the insertion itself are the SAME
// single-owner registry operation every positional write shares.
func (c *subCollector) regInsertFuncNames(name string) {
	if c.funcNamesShared {
		// R24-Oracle-S2: the shared substitution map clones lazily on its
		// first positional write — reads never needed the copy.
		c.regCopyElements += len(c.funcNames)
		c.funcNames = cloneBoolMap(c.funcNames)
		c.funcNamesShared = false
	}
	if c.funcNames == nil {
		c.funcNames = map[string]bool{}
	}
	if !c.funcNames[name] {
		c.noteProcessRegAdd(name, false)
	}
	c.funcNames[name] = true
}

// regInsertReadonlyVar installs one name into the positional readonly
// registry — the same single-owner registry operation as
// regInsertFuncNames, keyed on the readonly table.
func (c *subCollector) regInsertReadonlyVar(name string) {
	if c.readonlyVarsShared {
		c.regCopyElements += len(c.readonlyVars)
		c.readonlyVars = cloneBoolMap(c.readonlyVars)
		c.readonlyVarsShared = false
	}
	if c.readonlyVars == nil {
		c.readonlyVars = map[string]bool{}
	}
	if !c.readonlyVars[name] {
		c.noteProcessRegAdd(name, true)
	}
	c.readonlyVars[name] = true
}

// visitIf walks one if/elif/else statement (extracted from walkStmt so
// the conditionality bookkeeping carries no extra nesting there). Only
// the FIRST `if` condition is guaranteed to execute (R22-Oracle-M3 /
// R22-Reviewer-#2): an `elif` condition runs solely when every preceding
// branch missed — its writes are conditional across the control-flow
// merge exactly like the Then bodies — so the walk enters the
// conditional region BEFORE replaying them. A plain `else` carries no
// Cond at all, so the chain walk end is unaffected.
func (c *subCollector) visitIf(st *syntax.Stmt, cmd *syntax.IfClause, feed stdinFeed) {
	prevBind := c.allowBind
	c.allowBind = false
	innerFeed := c.stmtFeed(st, feed)
	first := true
	for ic := cmd; ic != nil; ic = ic.Else {
		if first {
			c.walkStmtsAll(ic.Cond, innerFeed)
			first = false
		} else {
			restoreCondC := c.enterConditional()
			c.walkStmtsAll(ic.Cond, innerFeed)
			restoreCondC()
		}
		restoreCond := c.enterConditional()
		c.walkStmtsAll(ic.Then, innerFeed)
		restoreCond()
	}
	c.allowBind = prevBind
}

func (c *subCollector) reject() {
	c.rejected = true
}

func (c *subCollector) failClosedFile(f *syntax.File) bool {
	ok := true
	quotedHdocLits := map[syntax.Node]bool{}
	syntax.Walk(f, func(n syntax.Node) bool {
		if n == nil {
			return false
		}
		if r, is := n.(*syntax.Redirect); is && (r.Op == syntax.Hdoc || r.Op == syntax.DashHdoc) &&
			isQuotedHeredocDelim(r.Word) && r.Hdoc != nil {
			quotedHdocLits[r.Hdoc] = true
			syntax.Walk(r.Hdoc, func(hn syntax.Node) bool {
				if lit, okLit := hn.(*syntax.Lit); okLit {
					quotedHdocLits[lit] = true
				}
				return true
			})
		}
		return true
	})
	syntax.Walk(f, func(n syntax.Node) bool {
		if n == nil || !ok || c.rejected {
			return false
		}
		switch x := n.(type) {
		case *syntax.DblQuoted:
			if raw, okRaw := rawSlice(c.code, x.Pos(), x.End()); okRaw && rawHasLineContAfterDollar(raw) {
				ok = false
				return false
			}
			for _, p := range x.Parts {
				if pe, is := p.(*syntax.ParamExp); is && paramExpD2Ambiguous(c.code, pe) {
					ok = false
					return false
				}
				if lit, is := p.(*syntax.Lit); is && litHasResidualExpand(lit.Value) {
					ok = false
					return false
				}
			}
		case *syntax.Lit:
			// G1-3: mvdan left an expand residue inside a Lit.
			// Quoted heredoc bodies are pure literals at top-level (W11-1).
			if quotedHdocLits[x] {
				return true
			}
			if litHasResidualExpand(x.Value) {
				ok = false
				return false
			}
		case *syntax.CmdSubst:
			if x.Backquotes {
				lo := int(x.Pos().Offset()) + 1
				hi := int(x.End().Offset()) - 1
				if lo >= 0 && hi <= len(c.code) && lo <= hi {
					if strings.Contains(c.code[lo:hi], `\`) {
						ok = false
						return false
					}
				}
			}
		case *syntax.Redirect:
			if x.Op == syntax.Hdoc || x.Op == syntax.DashHdoc {
				if !c.heredocDelimOK(x) {
					ok = false
					return false
				}
				if x.Hdoc != nil && !isQuotedHeredocDelim(x.Word) {
					if !c.failClosedUnquotedHdoc(x.Hdoc) {
						ok = false
						return false
					}
				}
			}
		case *syntax.ArithmExp:
			raw, okRaw := rawSlice(c.code, x.Pos(), x.End())
			if okRaw && (strings.Contains(raw, ";") || strings.Contains(raw, "\n")) {
				ok = false
				return false
			}
			if !c.failClosedArithmCtx(x.X) {
				ok = false
				return false
			}
		case *syntax.ArithmCmd:
			if !c.failClosedArithmCtx(x.X) {
				ok = false
				return false
			}
		case *syntax.ExtGlob:
			if x.Pattern != nil && strings.ContainsAny(x.Pattern.Value, "$`\n\\;") {
				ok = false
				return false
			}
		case *syntax.ParamExp:
			if peAssignsHookOrTaint(x) {
				ok = false
				return false
			}
		case *syntax.BinaryArithm:
			if isArithAssignOp(x.Op) && arithmTargetIsHookOrTaint(x.X) {
				ok = false
				return false
			}
		case *syntax.UnaryArithm:
			if (x.Op == syntax.Inc || x.Op == syntax.Dec) && arithmTargetIsHookOrTaint(x.X) {
				ok = false
				return false
			}
		case *syntax.ForClause:
			if wi, is := x.Loop.(*syntax.WordIter); is && wi.Name != nil {
				if isEnvHookVar(wi.Name.Value) || guardTaintVars[wi.Name.Value] {
					ok = false
					return false
				}
			}
		}
		return true
	})
	return ok && !c.rejected
}

func paramExpD2Ambiguous(code string, pe *syntax.ParamExp) bool {
	if pe == nil {
		return false
	}
	ambig := false
	var csSpans [][2]int
	syntax.Walk(pe, func(n syntax.Node) bool {
		if n == nil || ambig {
			return false
		}
		switch x := n.(type) {
		case *syntax.CmdSubst:
			lo, hi := int(x.Pos().Offset()), int(x.End().Offset())
			if lo >= 0 && hi >= lo && hi <= len(code) {
				csSpans = append(csSpans, [2]int{lo, hi})
			}
			return false
		case *syntax.SglQuoted:
			// Inner single quotes diverge between mvdan and dash (G6_MF3).
			ambig = true
			return false
		case *syntax.DblQuoted:
			// Nested double quotes themselves are fine; raw scan below.
			return true
		}
		return true
	})
	if ambig {
		return true
	}
	raw, okRaw := rawSlice(code, pe.Pos(), pe.End())
	if !okRaw {
		return false
	}
	lo := int(pe.Pos().Offset())
	inCS := func(abs int) bool {
		for _, sp := range csSpans {
			if abs >= sp[0] && abs < sp[1] {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(raw); i++ {
		abs := lo + i
		if inCS(abs) {
			continue
		}
		switch raw[i] {
		case '\'':
			return true
		case '\n':
			return true
		case '\\':
			if i+1 >= len(raw) {
				return true
			}
			nxt := raw[i+1]
			switch nxt {
			case '"', '$', '`', '\\', '\n', '\'':
				return true
			}
			// escaped slash etc. (e.g. ${p//\//_}) is fine
			i++
		}
	}
	return false
}

func peAssignsHookOrTaint(pe *syntax.ParamExp) bool {
	if pe == nil || pe.Exp == nil || pe.Param == nil {
		return false
	}
	switch pe.Exp.Op {
	case syntax.AssignUnset, syntax.AssignUnsetOrNull:
		name := pe.Param.Value
		return isEnvHookVar(name) || guardTaintVars[name]
	}
	return false
}

func isArithAssignOp(op syntax.BinAritOperator) bool {
	switch op {
	case syntax.Assgn, syntax.AddAssgn, syntax.SubAssgn, syntax.MulAssgn,
		syntax.QuoAssgn, syntax.RemAssgn, syntax.ShlAssgn, syntax.ShrAssgn,
		syntax.AndAssgn, syntax.XorAssgn, syntax.OrAssgn:
		return true
	}
	return false
}

func arithmTargetIsHookOrTaint(x syntax.ArithmExpr) bool {
	name := arithmTargetName(x)
	if name == "" {
		return false
	}
	return isEnvHookVar(name) || guardTaintVars[name]
}

func arithmTargetName(x syntax.ArithmExpr) string {
	switch t := x.(type) {
	case *syntax.Word:
		if len(t.Parts) == 1 {
			if lit, ok := t.Parts[0].(*syntax.Lit); ok {
				return lit.Value
			}
			if pe, ok := t.Parts[0].(*syntax.ParamExp); ok && pe.Param != nil && pe.Short && pe.Exp == nil && pe.Index == nil {
				return pe.Param.Value
			}
		}
	case *syntax.UnaryArithm:
		return arithmTargetName(t.X)
	}
	return ""
}

func (c *subCollector) failClosedArithmCtx(x syntax.ArithmExpr) bool {
	if x == nil {
		return true
	}
	ok := true
	syntax.Walk(x, func(n syntax.Node) bool {
		if n == nil || !ok {
			return false
		}
		switch t := n.(type) {
		case *syntax.CmdSubst:
			return false
		case *syntax.ParamExp:
			if paramExpD2Ambiguous(c.code, t) || peAssignsHookOrTaint(t) {
				ok = false
				return false
			}
		case *syntax.BinaryArithm:
			if isArithAssignOp(t.Op) && arithmTargetIsHookOrTaint(t.X) {
				ok = false
				return false
			}
		case *syntax.UnaryArithm:
			if (t.Op == syntax.Inc || t.Op == syntax.Dec) && arithmTargetIsHookOrTaint(t.X) {
				ok = false
				return false
			}
		}
		return true
	})
	return ok
}

func (c *subCollector) failClosedUnquotedHdoc(hdoc *syntax.Word) bool {
	if hdoc == nil {
		return true
	}
	ok := true
	syntax.Walk(hdoc, func(n syntax.Node) bool {
		if n == nil || !ok {
			return false
		}
		switch t := n.(type) {
		case *syntax.CmdSubst:
			return false
		case *syntax.SglQuoted:
			ok = false
			return false
		case *syntax.ParamExp:
			if paramExpD2Ambiguous(c.code, t) || peAssignsHookOrTaint(t) {
				ok = false
				return false
			}
		case *syntax.Lit:
			// W-Fix-2: check ORIGINAL lit for unescaped $( / backtick / dollar-linecont.
			if litHasUnescapedCmdExpand(t.Value) || rawHasLineContAfterDollar(t.Value) {
				ok = false
				return false
			}
		}
		return true
	})
	return ok
}

func (c *subCollector) heredocDelimOK(r *syntax.Redirect) bool {
	if r.Word == nil {
		return false
	}
	opLen := len(r.Op.String())
	lo := int(r.OpPos.Offset()) + opLen
	hi := int(r.Word.End().Offset())
	if lo < 0 || hi > len(c.code) || lo > hi {
		return false
	}
	src := c.code[lo:hi]
	// Allow leading/in-word backslash escapes (<<\EOF) but reject cross-line cont.
	if strings.Contains(src, "\n") || hasOddTrailingBackslash(src) {
		return false
	}
	if len(r.Word.Parts) != 1 {
		return false
	}
	switch p := r.Word.Parts[0].(type) {
	case *syntax.Lit:
		return isHeredocDelimName(posixUnescapeLit(p.Value))
	case *syntax.SglQuoted:
		return !p.Dollar && isHeredocDelimName(p.Value)
	case *syntax.DblQuoted:
		if p.Dollar || len(p.Parts) != 1 {
			return false
		}
		lit, ok := p.Parts[0].(*syntax.Lit)
		if !ok || strings.ContainsAny(lit.Value, `\/$`+"`") {
			return false
		}
		return isHeredocDelimName(lit.Value)
	default:
		return false
	}
}

func isHeredocDelimName(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.'
		if !ok {
			return false
		}
	}
	return true
}

func (c *subCollector) walkStmts(stmts []*syntax.Stmt, feed stdinFeed) {
	for i, st := range stmts {
		if c.rejected {
			return
		}
		if i > 0 {
			// Sequential list: only the FIRST statement consumes the piped
			// stream. Heredoc/here-string/file feeds are pre-bound input,
			// so every statement in the list shares them. R17: feed.fds is
			// nil at every call site (all three list-level feeds are
			// {piped: pipeIn}) — sequential statements inside compounds
			// run through walkStmtsAll instead, so the fds field below is
			// propagated only defensively and carries no coverage.
			c.walkStmt(st, stdinFeed{piped: false, bodies: feed.bodies, hasHere: feed.hasHere, hereStr: feed.hereStr, file: feed.file, fds: feed.fds})
			continue
		}
		c.walkStmt(st, feed)
	}
}

// walkStmtsAll walks every stmt of a COMPOUND body with the same feed:
// inside ( ... )/{ ...; }/if/while/for/case the whole body shares the
// compound's stdin, so the first-executed-statement rule cannot pick a
// single inner stmt (M4: `echo pig | (sh)` marks sh's pipedStdin).
func (c *subCollector) walkStmtsAll(stmts []*syntax.Stmt, feed stdinFeed) {
	for _, st := range stmts {
		if c.rejected {
			return
		}
		c.walkStmt(st, feed)
	}
}

// isTainted reports the effective taint of a variable name: the wildcard
// "*" entry (set when the pre-scan gave up) counts as EVERY name tainted
// (S1), so authorization paths cannot consult stale binds.
func (c *subCollector) isTainted(name string) bool {
	return c.taintedVars[name] || c.taintedVars["*"]
}

func (c *subCollector) walkStmt(st *syntax.Stmt, feed stdinFeed) {
	if st == nil || c.rejected {
		return
	}
	// R6: a `cmd &` subtree runs in a subshell — nothing inside it binds in
	// the parent. Closing bind on the whole Background subtree (not only on
	// the leaf CallExpr) keeps `x=v && true &` from arming "$x".
	// R21-Oracle-M3: the whole backgrounded subtree runs in its OWN child
	// execution scope — including compound shapes like `{ x=v; sh; } &`
	// whose inner statements otherwise carry the parent's scope — so the
	// scope marker must propagate DOWNWARD through the subtree, not just
	// ride the leaf segment's background bit.
	prevBind := c.allowBind
	restoreScope := func() {}
	restoreRegs := func() {}
	if st.Background {
		c.allowBind = false
		restoreScope = c.enterChildScope()
		// R23-Reviewer-#3 / R23-Oracle-M1: the whole backgrounded subtree
		// runs in a CHILD PROCESS — function definitions and readonly
		// declarations inside it die with the child exactly like its
		// assignments, so the parent's positional tracks restore when
		// the subtree finishes: a `(eval(){ :; }) &` must never shadow
		// the parent's later bare eval.
		restoreRegs = c.snapshotProcessRegs()
	}
	defer func() { restoreRegs(); restoreScope(); c.allowBind = prevBind }()
	if st.Cmd == nil {
		// bare redirects — still record if they write; unquoted heredoc bodies
		// can contain $(...) that dash expands (must emit nested CallExprs).
		for _, r := range st.Redirs {
			if r.Word != nil {
				c.emitNestedFromWord(r.Word, feed)
			}
			if r.Hdoc != nil && !isQuotedHeredocDelim(r.Word) {
				c.emitNestedFromWord(r.Hdoc, feed)
			}
		}
		seg := shellSegment{pipedStdin: feed.piped, backgrounded: st.Background, childScope: st.Background || c.childScope, scopePath: c.scopePath, condAssign: c.condDepth > 0}
		c.applyRedirs(&seg, st.Redirs, feed)
		if len(seg.argv) > 0 || seg.redirectFile != "" || len(seg.heredocText) > 0 || seg.hereString != "" || seg.depthExceeded {
			c.segs = append(c.segs, seg)
		}
		return
	}
	switch cmd := st.Cmd.(type) {
	case *syntax.CallExpr:
		// A `PWD=` / `OLDPWD=` assignment anywhere in the script invalidates
		// the static $(pwd) bind: a later `cd` or prefix assignment can
		// re-anchor the expansion. preScanVarMutations already taints
		// PWD/OLDPWD for ANY write (single write counts), which
		// pwdSwitchTainted() below consults. This check runs BEFORE
		// emitCall so a `PWD=$(pwd)` sighting cannot self-bind (R3 MF-3).
		for _, a := range cmd.Assigns {
			if a.Name != nil && (a.Name.Value == "PWD" || a.Name.Value == "OLDPWD") {
				c.hasCd = true
			}
		}
		// A directory-switch builtin anywhere in the script invalidates every
		// later static $(pwd) bind: the collector walks statements in source
		// order, but a sequential `cd /tmp/evil` earlier in the same stmt list
		// (or a preScanVarMutations sighting) makes the real cwd at a later
		// $(pwd) unknowable — the bind must stay dynamic. Leading
		// `builtin`/`command` wrappers are stripped first so
		// `builtin pushd /tmp/evil` cannot hide the switch (R3 MF-3).
		if !c.hasCd && len(cmd.Args) > 0 {
			args := cmd.Args
			for len(args) > 0 {
				h, ok := wordToArg(args[0])
				if !ok || isDynamicArg(h) {
					break
				}
				base := h
				if k := strings.LastIndexByte(base, '/'); k >= 0 {
					base = base[k+1:]
				}
				if base != "builtin" && base != "command" {
					break
				}
				args = args[1:]
				for len(args) > 0 {
					a, aok := wordToArg(args[0])
					if !aok || isDynamicArg(a) || a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
						break
					}
					args = args[1:]
				}
				if len(args) > 0 {
					if a, aok := wordToArg(args[0]); aok && a == "--" {
						args = args[1:]
					}
				}
			}
			if len(args) > 0 {
				if h, ok := wordToArg(args[0]); ok {
					base := h
					if k := strings.LastIndexByte(base, '/'); k >= 0 {
						base = base[k+1:]
					}
					switch base {
					case "cd", "chdir", "pushd", "popd", "eval", "source", ".":
						c.hasCd = true
					}
				}
			}
		}
		// R19-Oracle-M2: the eval builtin re-parses its static operands in
		// the SAME shell — the assignment bindings inside `eval 'PATH=/x'`
		// must land in this collector's staticVars/taintedVars exactly like
		// the direct `PATH=/x` spelling, or canResolveMktempInPath falls
		// back to the caller's original PATH and grades the substitution
		// under a PATH the running shell no longer has. One plain hook call
		// keeps this case's complexity untouched; the decode itself lives
		// in bindEvalCallWrites (R20-Oracle-M1: the statement carries the
		// redirections whose failure would prevent the builtin from ever
		// running, so the replication needs it, not just the call).
		c.bindEvalCallWrites(st, cmd)
		// R21-Oracle-M2/R21-Reviewer-3: the Bash named-write builtins
		// (`printf -v`, `read`, `getopts`, `unset`, the declare family)
		// write shell variables the pre-scan already counts — the replay
		// must surface those writes as taint under the SHARED write
		// definition, or a single counted write falls back to the parent
		// shell's environment in the substitution success proofs. eval
		// root writes are excluded inside writeNamesInStmtFuncs — the chain
		// replication above owns them.
		c.noteBuiltinWrites(st, cmd)
		c.emitCall(st, cmd, feed)
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.Pipe, syntax.PipeAll:
			prevBind := c.allowBind
			c.allowBind = false // no static head-bind across/inside pipelines
			// R24-Reviewer-#3 / R24-Oracle-M3: EVERY pipeline component is
			// its own child process, so each side derives its positional
			// registry boundary from the SAME parent state independently —
			// a function defined in the left component can never be visible
			// while the right component is walked, and neither side leaks
			// into the parent. The pre-R24 single snapshot covered both
			// walks: it kept definitions out of the parent, but the left
			// side's additions were still live when the right side ran.
			// R20-Oracle-M3/R21-Oracle-M3: the two sides fork sibling scopes
			// (two distinct ids off the same parent prefix): an assignment
			// inside either component binds within THAT component's
			// environment only, never the sibling's and never the parent's.
			restoreRegsX := c.snapshotProcessRegs()
			restoreX := c.enterChildScope()
			c.walkStmt(cmd.X, feed)
			restoreX()
			restoreRegsX()
			// Pipe right: fd0 becomes the upstream stream, but the rest of
			// the descriptor table is inherited — { cat | sh 0<&9; } 9<&0
			// still resolves fd9 to the pipe.
			restoreRegsY := c.snapshotProcessRegs()
			restoreY := c.enterChildScope()
			c.walkStmt(cmd.Y, stdinFeed{piped: true, fds: feed.fds})
			restoreY()
			restoreRegsY()
			c.allowBind = prevBind
		case syntax.AndStmt, syntax.OrStmt:
			c.walkStmt(cmd.X, feed)
			// SH11 MF-4.1: the right side is a conditional short-circuit
			// branch — its assignments are NOT guaranteed to run, so they
			// must never become staticVars binds. Its stdin is the SAME
			// feed the left side saw — `true && sh` fed by a pipe runs the
			// piped bytes as sh's program (R13), and { true && sh 0<&9; }
			// 9<&0 resolves fd9 through the inherited descriptor table.
			// R21-Oracle-M3: the conditional region is tracked — the
			// control-flow merge after the branch treats every variable
			// the right side writes as uncertain, never an exact override.
			prevBind := c.allowBind
			c.allowBind = false
			restoreCond := c.enterConditional()
			c.walkStmt(cmd.Y, feed)
			restoreCond()
			c.allowBind = prevBind
		default:
			c.reject()
		}
	case *syntax.Subshell:
		prevBind := c.allowBind
		c.allowBind = false
		// R20-Oracle-M3/R21-Oracle-M3: a subshell is a child process by
		// definition — assignments inside it bind within its OWN freshly
		// cloned scope environment (visible to the same subshell's later
		// consumers) and never reach the parent shell.
		// R23-Reviewer-#3 / R23-Oracle-M1: function definitions and
		// readonly declarations inside the subshell die with it exactly
		// like its assignments — the parent's positional tracks restore
		// at the boundary, so `(eval(){ :; }); eval 'X=1'` keeps the
		// builtin binding premise a leaking definition would revoke.
		restoreRegs := c.snapshotProcessRegs()
		restoreScope := c.enterChildScope()
		innerFeed := c.stmtFeed(st, feed)
		c.walkStmtsAll(cmd.Stmts, innerFeed)
		restoreScope()
		restoreRegs()
		c.allowBind = prevBind
	case *syntax.Block:
		prevBind := c.allowBind
		c.allowBind = false
		innerFeed := c.stmtFeed(st, feed)
		c.walkStmtsAll(cmd.Stmts, innerFeed)
		c.allowBind = prevBind
	case *syntax.IfClause:
		// R22-Oracle-M3: the elif-condition conditionality walk lives in
		// visitIf so walkStmt carries no extra nesting (cccc discipline).
		c.visitIf(st, cmd, feed)
	case *syntax.WhileClause:
		prevBind := c.allowBind
		c.allowBind = false
		innerFeed := c.stmtFeed(st, feed)
		c.walkStmtsAll(cmd.Cond, innerFeed)
		// R21-Oracle-M3: the loop body may run zero times — its writes
		// are conditional across the merge.
		restoreCond := c.enterConditional()
		c.walkStmtsAll(cmd.Do, innerFeed)
		restoreCond()
		c.allowBind = prevBind
	case *syntax.ForClause:
		prevBind := c.allowBind
		c.allowBind = false
		innerFeed := c.stmtFeed(st, feed)
		enumDone := false
		if wi, ok := cmd.Loop.(*syntax.WordIter); ok {
			loopName := ""
			if wi.Name != nil {
				loopName = wi.Name.Value
				c.taintVar(loopName) // loop var never eligible as static command head
			}
			for _, w := range wi.Items {
				c.emitNestedFromWord(w, innerFeed)
			}
			if loopName != "" {
				restoreCond := c.enterConditional()
				enumDone = c.forEnumSubst(loopName, wi.Items, cmd.Do, innerFeed)
				restoreCond()
			}
		}
		if !enumDone {
			restoreCond := c.enterConditional()
			c.walkStmtsAll(cmd.Do, innerFeed)
			restoreCond()
		}
		c.allowBind = prevBind
	case *syntax.CaseClause:
		prevBind := c.allowBind
		c.allowBind = false
		innerFeed := c.stmtFeed(st, feed)
		c.emitNestedFromWord(cmd.Word, innerFeed)
		for _, item := range cmd.Items {
			for _, pat := range item.Patterns {
				c.emitNestedFromWord(pat, innerFeed)
			}
			// R21-Oracle-M3: each case arm is a conditional branch.
			restoreCond := c.enterConditional()
			c.walkStmtsAll(item.Stmts, innerFeed)
			restoreCond()
		}
		c.allowBind = prevBind
	case *syntax.FuncDecl:
		// R22-Oracle-M1 / R22-Reviewer-#3: the definition TAKES EFFECT at
		// this statement — every later bare invocation of the same name
		// resolves to the function, never to a same-named builtin. Record
		// the name BEFORE walking the body so the shadowing premise is
		// visible to the eval chain analysis of everything after it.
		c.noteFuncDef(cmd)
		prevBind := c.allowBind
		c.allowBind = false
		prevUnvetted := c.fdUnvetted
		c.fdUnvetted = true
		if cmd.Body != nil {
			// The body runs with the CALL's stdin and descriptor table —
			// both unknown at declaration, so the entry feed is an
			// unknown-call-environment base: stdin conservatively fed and
			// an EMPTY table (fdUnvetted makes every unproven dup fail
			// closed). The declaration-site environment is never captured:
			// `{ f() { sh; }; } </dev/null` leaves the body's file/body
			// exemptions out, and a decl-env fd9 cannot be duped back as a
			// file (R18 MF-1). Only st.Redirs replay over the fresh base —
			// `f() { sh; } </dev/null` (or 9<f / 9<&-) still applies at
			// call time exactly like the enclosing stmt's redirects do.
			// R21-Oracle-M3: the body runs in the caller's SAME shell (no
			// child scope) but possibly zero times — every write inside is
			// conditional across the control-flow merge.
			restoreCond := c.enterConditional()
			inner := c.stmtFeed(st, stdinFeed{piped: true})
			c.walkStmt(cmd.Body, inner)
			restoreCond()
		}
		c.fdUnvetted = prevUnvetted
		c.allowBind = prevBind
	case *syntax.TimeClause:
		prevBind := c.allowBind
		c.allowBind = false
		if cmd.Stmt != nil {
			c.walkStmt(cmd.Stmt, c.stmtFeed(st, feed))
		}
		c.allowBind = prevBind
	case *syntax.CoprocClause:
		prevBind := c.allowBind
		c.allowBind = false
		// A coprocess runs in its own child process — assignments inside
		// never reach the parent shell (R21-Oracle-M3).
		restoreRegs := c.snapshotProcessRegs()
		restoreScope := c.enterChildScope()
		if cmd.Stmt != nil {
			c.walkStmt(cmd.Stmt, stdinFeed{})
		}
		restoreScope()
		restoreRegs()
		c.allowBind = prevBind
	case *syntax.DeclClause:
		c.emitDecl(st, cmd, feed)
	case *syntax.ArithmCmd:
		// Bash arithmetic command: still scan for nested CmdSubst via Walk.
		c.emitNestedFromNode(cmd, feed)
	case *syntax.TestClause:
		c.emitNestedFromNode(cmd, feed)
	case *syntax.LetClause:
		c.emitNestedFromNode(cmd, feed)
	default:
		c.reject()
	}
}

// noteDeclInlineAssign replays the inline bind of one declaration
// assignment word (extracted for the R25 complexity budget —
// R25-Oracle-MF1 / R25-Reviewer-#2-alignment): the declaration entry
// mirrors the pure-assignment path at emitCall — bash's `+=`
// concatenates onto the unknowable inherited value and an
// array-subscript write leaves every other element intact, so neither
// operator can mint the literal RHS as the scalar binding; the
// conservative verdict is pollution, never the exact value.
func (c *subCollector) noteDeclInlineAssign(a *syntax.Assign) {
	if a.Append || a.Index != nil {
		c.noteShellAssign(a.Name.Value, "", false)
		return
	}
	val, stOk := c.staticAssignVal(a.Value)
	c.noteShellAssign(a.Name.Value, val, stOk)
}

func (c *subCollector) emitDecl(st *syntax.Stmt, d *syntax.DeclClause, feed stdinFeed) {
	c.emitNestedFromNode(d, feed)
	argv := make([]string, 0, 1+len(d.Args))
	if d.Variant != nil {
		argv = append(argv, d.Variant.Value)
	}
	// SH11 F9: a backgrounded statement runs in a subshell — its assigns
	// never bind in the parent shell (walkStmt already closed allowBind on
	// the whole subtree).
	for _, a := range d.Args {
		if a.Name != nil && !a.Naked {
			argv = append(argv, c.assignToPrefix(a))
			c.noteDeclInlineAssign(a)
			continue
		}
		if a.Name != nil && a.Naked {
			argv = append(argv, a.Name.Value)
			continue
		}
		if a.Value != nil {
			s, _ := c.wordToArg(a.Value)
			argv = append(argv, s)
		}
	}
	// R22-Oracle-M1: same readonly-attribute recording as the CallExpr
	// path — the declaration's own binds mint first, later assignments
	// to the declared names can never establish a new value.
	c.noteReadonlyDecls(argv)
	seg := shellSegment{argv: argv, pipedStdin: feed.piped, backgrounded: st.Background, declClause: true, childScope: st.Background || c.childScope, scopePath: c.scopePath, condAssign: c.condDepth > 0}
	c.applyRedirs(&seg, st.Redirs, feed)
	c.segs = append(c.segs, seg)
}

func (c *subCollector) emitCall(st *syntax.Stmt, call *syntax.CallExpr, feed stdinFeed) {
	// Nested substitutions flush BEFORE the enclosing call.
	for _, a := range call.Assigns {
		if a.Value != nil {
			c.emitNestedFromWord(a.Value, feed)
		}
		if a.Array != nil {
			c.emitNestedFromNode(a.Array, feed)
		}
	}
	for _, w := range call.Args {
		c.emitNestedFromWord(w, feed)
	}
	for _, r := range st.Redirs {
		if r.Word != nil {
			c.emitNestedFromWord(r.Word, feed)
		}
		if r.Hdoc != nil && !isQuotedHeredocDelim(r.Word) {
			c.emitNestedFromWord(r.Hdoc, feed)
		}
	}

	argv := make([]string, 0, len(call.Assigns)+len(call.Args))
	argWords := make([]*syntax.Word, 0, len(call.Assigns)+len(call.Args))
	// R23-Reviewer-#2 / R23-Oracle-M3: parallel to argv — the assignment
	// OPERATOR provenance (`+=` append, array subscript) the KEY=VAL
	// serialization destroys. The tracker folds pure-assignment segments
	// through these bits; every non-assignment word carries zero.
	assignFlags := make([]byte, 0, len(call.Assigns)+len(call.Args))
	// SH11 F9: a backgrounded statement runs in a subshell — its assigns
	// never bind in the parent shell (walkStmt already closed allowBind on
	// the whole subtree).
	for _, a := range call.Assigns {
		argv = append(argv, c.assignToPrefix(a))
		argWords = append(argWords, nil) // prefix assigns have no command Word
		assignFlags = append(assignFlags, assignOpFlag(a))
		if a.Name != nil && !a.Naked {
			if len(call.Args) == 0 {
				// Pure assignment statement — eligible for staticVars.
				// R22-Oracle-M1: a readonly-declared variable can never
				// receive the write at runtime, so the declaration-aware
				// gate applies exactly like the eval replication.
				// R24-Reviewer-#2 / R24-Oracle-M2: the assignment OPERATOR
				// decides whether a scalar bind can exist at all — exactly
				// like the eval replication at bindEvalOneStmt: bash's `+=`
				// concatenates onto the unknowable inherited value, and an
				// array-subscript write `name[i]=v` leaves every other
				// element intact, so neither can ever mint the literal RHS
				// as the scalar binding. The conservative verdict for both
				// is pollution, never the exact value.
				if a.Append || a.Index != nil {
					c.noteShellAssign(a.Name.Value, "", false)
					continue
				}
				val, stOk := c.staticAssignVal(a.Value)
				c.noteShellAssign(a.Name.Value, val, stOk)
			} else {
				// Prefix env (FOO=bar cmd) does not bind in the current shell.
				c.taintVar(a.Name.Value)
			}
		}
	}
	enumHeadExpanded := false
	for i, w := range call.Args {
		// Command head: for-loop enum binds may expand the head (W-Fix-6
		// abs-path single words; W11-5 static multi-word command strings).
		if i == 0 {
			if !c.isTainted("IFS") {
				if name, single := singleSimpleParamExp(w); single {
					if words, ok := c.enumCmdWords[name]; ok && len(words) > 0 {
						argv = append(argv, words...)
						for range words {
							argWords = append(argWords, nil) // expanded; no 1:1 Word
							assignFlags = append(assignFlags, 0)
						}
						enumHeadExpanded = true
						continue
					}
				}
			}
			if len(c.enumVars) > 0 {
				// Try with enumVars; if resolved value is not a safe abs path,
				// fall back.
				s, ok := c.wordToArg(w)
				if ok && isSafeAbsPathVal(s) {
					argv = append(argv, s)
					argWords = append(argWords, w)
					assignFlags = append(assignFlags, 0)
					continue
				}
				saved := c.enumVars
				c.enumVars = nil
				s, _ = c.wordToArg(w)
				c.enumVars = saved
				argv = append(argv, s)
				argWords = append(argWords, w)
				assignFlags = append(assignFlags, 0)
				continue
			}
		}
		s, _ := c.wordToArg(w)
		argv = append(argv, s)
		argWords = append(argWords, w)
		assignFlags = append(assignFlags, 0)
	}
	// POSIX parses `export NAME=VAL` as CallExpr (bash uses DeclClause).
	c.noteDeclCallBinds(argv)
	// R22-Oracle-M1: the readonly attribute takes effect with this
	// declaration — later assignments to the same names can never
	// establish a new value. Recorded AFTER the declaration's own binds
	// so `readonly X=/x` still mints the value it successfully sets.
	c.noteReadonlyDecls(argv)

	// A for-loop enum command head ($X) that expanded to a directory-
	// switch or code-eval builtin invalidates every later static $(pwd)
	// bind exactly like a literal `cd` sighting — `for X in cd; do $X
	// <evil>; done; D=$(pwd)` must stay dynamic (R4 MF-2). Extracted so
	// the assignment-operator ownership carries no enum chain-scan
	// nesting (R24 complexity budget).
	if enumHeadExpanded {
		c.noteEnumHeadBuiltin(argv)
	}

	seg := shellSegment{
		argv:         argv,
		argWords:     argWords,
		pureAssign:   isPureAssignCall(call),
		pipedStdin:   feed.piped,
		backgrounded: st.Background,
		processSubst: callHasProcSubst(call),
		srcCode:      c.code,
		childScope:   st.Background || c.childScope,
		scopePath:    c.scopePath,
		condAssign:   c.condDepth > 0,
		assignFlags:  assignFlags,
	}
	c.applyRedirs(&seg, st.Redirs, feed)
	if len(seg.argv) > 0 || seg.redirectFile != "" || len(seg.heredocText) > 0 ||
		seg.hereString != "" || seg.processSubst || seg.depthExceeded {
		c.segs = append(c.segs, seg)
	}
}

// noteEnumHeadBuiltin marks the collector's directory-switch sighting
// when one expanded enum command head resolves to cd/eval/source (R4
// MF-2 — extracted from emitCall for the R24 complexity budget, verbatim
// behavior): prefix env assigns (FOO=1 $X "cd ...") sit ahead of the
// expanded head word — skip them before the builtin/command strip or the
// first word reads as the assignment, not the builtin (R5 MF-2). The
// strip itself is the same one the CallExpr sighting uses.
func (c *subCollector) noteEnumHeadBuiltin(argv []string) {
	if c.hasCd {
		return
	}
	args := argv
	for len(args) > 0 && isAssignWord(args[0]) {
		args = args[1:]
	}
	for len(args) > 0 {
		base := args[0]
		if k := strings.LastIndexByte(base, '/'); k >= 0 {
			base = base[k+1:]
		}
		if base != "builtin" && base != "command" {
			break
		}
		args = args[1:]
		for len(args) > 0 {
			a := args[0]
			if a == "--" || isDynamicArg(a) || !strings.HasPrefix(a, "-") || a == "-" {
				break
			}
			args = args[1:]
		}
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
	}
	if len(args) > 0 {
		base := args[0]
		if k := strings.LastIndexByte(base, '/'); k >= 0 {
			base = base[k+1:]
		}
		switch base {
		case "cd", "chdir", "pushd", "popd", "eval", "source", ".":
			c.hasCd = true
		}
	}
}

// assignOpFlag encodes the assignment-operator provenance of one syntax
// Assign for shellSegment.assignFlags (R23-Reviewer-#2 / R23-Oracle-M3):
// bit 1 (`+=`) means the write concatenates onto the unknowable inherited
// value, bit 2 (array subscript) means the write touches one element and
// never overwrites the whole scalar. Only a zero flag is a genuinely
// independent plain scalar overwrite.
func assignOpFlag(a *syntax.Assign) byte {
	if a == nil {
		return 0
	}
	var f byte
	if a.Append {
		f |= 1
	}
	if a.Index != nil {
		f |= 2
	}
	return f
}

// isPureAssignCall reports whether a call expression is a genuine
// bare-assignment statement in the shell grammar (R22-Oracle-M3): no
// command arguments at all and at least one assignment word. A command
// word that merely SPELLS KEY=VAL after quote stripping is a command
// invocation — its runtime resolution may be a program or a builtin
// that performs no assignment — so the argv shape is never consulted.
func isPureAssignCall(call *syntax.CallExpr) bool {
	return len(call.Args) == 0 && len(call.Assigns) > 0
}

// noteBuiltinWrites taints the shell variables a NON-eval command call
// writes through the Bash named-write builtins (R21-Oracle-M2 /
// R21-Reviewer-3 — the replay side of the unified write definition):
// `printf -v PATH ...`, `read PATH`, `getopts x PATH`, `unset PATH`,
// `declare PATH=...` in the POSIX-parsed CallExpr shape and every other
// write shape the pre-scan counts. Pure-assignment statements
// (len(call.Args) == 0) bind through noteStaticAssign instead, and prefix
// assignments die with the child exactly like emitCall already models.
// Writes hidden inside nested conditional subtrees of the same statement
// taint conservatively — their execution is uncertain, which is precisely
// the pollution direction.
func (c *subCollector) noteBuiltinWrites(st *syntax.Stmt, cmd *syntax.CallExpr) {
	if len(cmd.Args) == 0 {
		return
	}
	names, allUnv := writeNamesInStmtFuncs(st, c.posixNoBraces, c.funcNames)
	if allUnv {
		c.taintedVars["*"] = true
	}
	bound := map[string]bool{}
	for _, a := range cmd.Assigns {
		if a.Name != nil {
			bound[a.Name.Value] = true
		}
	}
	// The export/readonly/declare/typeset/local family is the SHARED scan's
	// KEY=VAL write shape, but the collector binds exactly those writes
	// through noteDeclCallBinds/emitDecl — tainting them here would revoke
	// the binds before they are even minted. A bare `export X` (no value)
	// changes nothing the runtime state did not already carry, so the
	// whole family's operand writes stay out of the taint pass; unset,
	// read, getopts and printf keep theirs.
	exportFamily := false
	if len(cmd.Args) > 0 {
		scanWord := wordToArg
		if c.posixNoBraces {
			scanWord = wordToArgPosix
		}
		if h, ok := scanWord(cmd.Args[0]); ok {
			switch h {
			case "export", "readonly", "declare", "typeset", "local":
				exportFamily = true
			}
		}
	}
	for _, name := range names {
		if bound[name] || exportFamily {
			continue // emitCall/noteDeclCallBinds already model these writes
		}
		c.taintVar(name)
	}
}

// stdinFeed describes where a statement's fd0 comes from when it has no
// redirect of its own (or when a dup re-binds fd0 to the same source):
// piped for a pipeline upstream stream, bodies/hereStr for an enclosing
// compound's heredoc / here-string (only an fd0 redirect queues them), and
// file for a real file/dup binding. A file-bound stdin never reaches the
// program as piped bytes, so feeds carrying file set seg.stdinRedir.
// fds carries the full fd->origin snapshot an enclosing compound left
// behind: `{ sh 0<&9; } 9<&0` needs fd9's piped origin inside the braces
// even though only fd0 feeds the group itself. Entries carry no nested
// fds; a fds[0] entry holds the enclosing fd0 origin and feedThrough
// always overrides origins[0] with the statement's own feed.
type stdinFeed struct {
	piped   bool
	bodies  []heredocBody
	hereStr string
	hasHere bool
	file    bool
	fds     map[string]stdinFeed
}

// applyRedirs folds st.Redirs into seg: output redirects feed redirectFile /
// processSubst, input redirects decide the segment's effective stdin by
// tracking every fd's ORIGIN — a bare stmt starts from feed, n<f binds fd n
// to a file, n<<EOF/n<<<w queue their payload on fd n, and n<&m copies m's
// origin instead of pretending a file (`sh 0<&0` keeps the pipe open, while
// `sh 9<&0 0<&9` still copies the piped fd0 origin). Only the FINAL fd0
// origin sets stdinRedir; non-fd0 heredocs never reach stdin, so their
// bodies are not collected.
func (c *subCollector) applyRedirs(seg *shellSegment, redirs []*syntax.Redirect, feed stdinFeed) {
	origin := c.feedThrough(redirs, feed)["0"]
	seg.stdinRedir = origin.file
	// The FINAL fd0 origin decides the piped-stdin mark too: an explicit
	// rebind (0< f, 0>f, 0<&9 with fd9 file-bound) means no pipe bytes
	// reach the program even though the segment sits inside a pipeline.
	seg.pipedStdin = origin.piped
	seg.heredocText = append(seg.heredocText, origin.bodies...)
	if origin.hasHere {
		seg.hereString = origin.hereStr
	}
	for _, r := range redirs {
		// Only an fd0 redirect decides where the command's stdin comes from;
		// 3< f or 2<<E leave stdin untouched.
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob:
			c.setWriteRedirect(seg, r)
		case syntax.DplOut:
			// fd duplication: blocking only when target is not a bare fd —
			// `>&9-` is the bash move syntax (a descriptor dup, never a
			// write target; R18 MF-2).
			if r.Word != nil {
				s, ok := wordToArg(r.Word)
				if !ok {
					seg.redirectFile = dynamicRedirectTarget
				} else if !isFdDupWord(s) {
					if seg.redirectFile == "" {
						seg.redirectFile = s
					}
				}
			}
		case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc,
			syntax.RdrIn, syntax.DplIn, syntax.RdrInOut:
			// stdin-side ops already folded via feedThrough; a redirect WORD
			// still hides nested substitutions to emit.
			if r.Word != nil {
				c.emitNestedFromWord(r.Word, feed)
			}
		}
	}
}

// fdDupSource splits a dup word into the source descriptor and the bash
// move flag: a trailing `-` on a digit word is the n<&m- / n>&m- move
// syntax (dup then close the source), not part of the descriptor.
func fdDupSource(s string) (src string, move bool) {
	src, move = s, false
	if strings.HasSuffix(src, "-") {
		maybe := src[:len(src)-1]
		if allDigits(maybe) {
			src, move = maybe, true
		}
	}
	return src, move
}

// fdNormalize canonicalizes a numeric descriptor for the origins table:
// bash treats `00` as fd0, so every lookup and table key strips leading
// zeros. Non-numeric words return unchanged.
func fdNormalize(s string) string {
	if !allDigits(s) {
		return s
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// isFdDupWord reports whether a dup word names a descriptor rather than a
// write target: "-" (close), digits (dup), or digits with a trailing "-"
// (the bash n>&m- move syntax).
func isFdDupWord(s string) bool {
	if s == "-" {
		return true
	}
	src, _ := fdDupSource(s)
	return allDigits(src)
}

// heredocBodyOf decodes one heredoc redirect's body exactly the way the
// collector consumes it: quoted delimiters carry literal text, nil bodies a
// payload-less entry, and unquoted bodies are POSIX-unescaped with a
// dynamic marker when they contain substitutions.
func (c *subCollector) heredocBodyOf(r *syntax.Redirect) heredocBody {
	quoted := isQuotedHeredocDelim(r.Word)
	dash := r.Op == syntax.DashHdoc
	if quoted {
		text := ""
		if r.Hdoc != nil {
			if lit := r.Hdoc.Lit(); lit != "" {
				text = lit
			} else if raw, ok := rawSlice(c.code, r.Hdoc.Pos(), r.Hdoc.End()); ok {
				text = raw
			}
		}
		if dash {
			text = stripDashHdocTabs(text)
		}
		return heredocBody{text: text, quoted: true, dynamic: false}
	}
	if r.Hdoc == nil {
		return heredocBody{quoted: false, dynamic: false}
	}
	var b strings.Builder
	for _, p := range r.Hdoc.Parts {
		lit, isLit := p.(*syntax.Lit)
		if !isLit {
			return heredocBody{text: cmdSubPlaceholder, quoted: false, dynamic: true}
		}
		b.WriteString(decodeUnquotedHeredocLit(lit.Value, dash))
	}
	return heredocBody{text: b.String(), quoted: false, dynamic: false}
}

// feedThrough replays a redirect list over base and returns the resulting
// per-descriptor origin table; callers read ["0"] for the fd0 origin. Fd
// origins are tracked per descriptor: an input op on fd n re-binds that fd
// (file / heredoc payload / here-string / closed / dup of another fd's
// origin), an output op on fd0 binds it to the write target, and anything
// else leaves the fd alone. An fd never touched by the list keeps a file
// origin (an inherited foreign fd cannot be the pipe) — except fd0, which
// starts at base, and the descriptors base.fds carries down from an
// enclosing compound's own redirect list. The default descriptor when the
// redirect word omits N is the operator's own: fd0 for stdin-side ops,
// fd1 for output-side ops — `sh >/dev/null` rebinds stdout, never stdin.
// No nested commands are emitted here; callers emit them so compound
// statements can reuse the replay without double scanning.
func (c *subCollector) feedThrough(redirs []*syntax.Redirect, base stdinFeed) map[string]stdinFeed {
	origins := make(map[string]stdinFeed, len(base.fds)+1)
	for fd, o := range base.fds {
		origins[fd] = o
	}
	origins["0"] = base
	for _, r := range redirs {
		// n: the descriptor the op actually binds when the word omits N —
		// fd0 for stdin-side ops, fd1 for output-side ops.
		n := "0"
		switch r.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll,
			syntax.RdrClob, syntax.DplOut:
			n = "1"
		}
		if r.N != nil {
			n = fdNormalize(r.N.Value)
		}
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			o := origins[n]
			o.piped, o.file = false, false
			o.bodies = append(o.bodies, c.heredocBodyOf(r))
			o.hasHere, o.hereStr = false, ""
			origins[n] = o
		case syntax.WordHdoc:
			s := ""
			if r.Word != nil {
				w, ok := wordToArg(r.Word)
				if !ok {
					s = cmdSubPlaceholder
				} else {
					s = w
				}
			}
			o := origins[n]
			o.piped, o.file = false, false
			o.bodies = nil
			o.hasHere, o.hereStr = true, s
			origins[n] = o
		case syntax.RdrIn, syntax.RdrInOut:
			origins[n] = stdinFeed{file: true}
		case syntax.DplIn, syntax.DplOut:
			// n<&m / n>&m copies m's CURRENT origin — dash runs the same
			// dup2 for both operators, so 0>&0 keeps base (it never rebinds
			// the input side) and 9>&0 then 0<&9 still smuggles the pipe
			// through fd9. n>&- / n<&- closes the fd. A target that fails
			// to parse keeps a TAINTED (possibly-pipe) origin: `0<&$(…)`
			// dup2s whatever the expansion yields — fd0 may still be the
			// pipe, so the file exemption must not apply (R17 MF-1). A
			// non-digit >&word is a write target (applyRedirs records it
			// as redirectFile) which is file for origin purposes. The
			// SOURCE descriptor normalizes leading zeros before the table
			// lookup — bash reads `0<&00` as dup2(0,0), so "00" must hit
			// the "0" slot — and a trailing `-` is the bash move syntax
			// n<&m-: it copies m's origin into n and then CLOSES m, never
			// a file target (R18 MF-2).
			if r.Word == nil {
				origins[n] = stdinFeed{file: true}
				break
			}
			s, ok := wordToArg(r.Word)
			switch {
			case !ok:
				// Unparseable dup target: fd n binds to an unvetted,
				// possibly-piped stream — never a file exemption.
				origins[n] = stdinFeed{piped: true}
			case s == "-":
				origins[n] = stdinFeed{file: true}
			default:
				src, move := fdDupSource(s)
				if !allDigits(src) {
					// Non-descriptor word: >&word write target — file.
					origins[n] = stdinFeed{file: true}
					break
				}
				src = fdNormalize(src)
				if o, seen := origins[src]; seen {
					origins[n] = o
				} else if c.fdUnvetted {
					// Inside a function body the call-site descriptor set
					// is unknown: an unproven fd fails closed as tainted.
					origins[n] = stdinFeed{piped: true}
				} else {
					origins[n] = stdinFeed{file: true}
				}
				if move {
					// n<&m- closes m after the copy: a later 0<&m reads a
					// closed descriptor (file), not m's pre-move pipe.
					origins[src] = stdinFeed{file: true}
				}
			}
		default:
			// Output-side ops on fd0 (0>f) re-bind it to the write target
			// — no program bytes stream through it. (0>&m is DplOut,
			// handled by the dup case above.)
			if n == "0" {
				origins[n] = stdinFeed{file: true}
			}
		}
	}
	return origins
}

// stmtFeed computes the stdin feed a COMPOUND statement's body sees:
// its own redirect list is replayed over the enclosing feed so
// `(sh) <<'EOF'` hands the heredoc payload to inner commands (they are
// screened as program text) and `(sh) < f` marks their stdin file-bound.
// The body also inherits the whole descriptor table: `{ sh 0<&9; } 9<&0`
// resolves fd9 through feed.fds to the pipe the group's redirect copied.
// Redirect words and unquoted heredoc bodies still emit their nested
// substitutions exactly like a CallExpr's redirects do.
func (c *subCollector) stmtFeed(st *syntax.Stmt, feed stdinFeed) stdinFeed {
	for _, r := range st.Redirs {
		if r.Word != nil {
			c.emitNestedFromWord(r.Word, feed)
		}
		if r.Hdoc != nil && !isQuotedHeredocDelim(r.Word) {
			c.emitNestedFromWord(r.Hdoc, feed)
		}
	}
	origins := c.feedThrough(st.Redirs, feed)
	inner := origins["0"]
	inner.fds = origins
	return inner
}

func (c *subCollector) setWriteRedirect(seg *shellSegment, r *syntax.Redirect) {
	if r.Word == nil {
		if seg.redirectFile == "" {
			seg.redirectFile = dynamicRedirectTarget
		}
		return
	}
	// ProcSubst as redirect target is handled via word parts.
	for _, p := range r.Word.Parts {
		if _, ok := p.(*syntax.ProcSubst); ok {
			seg.processSubst = true
		}
	}
	s, ok := wordToArg(r.Word)
	if !ok || s == "" {
		if seg.redirectFile == "" {
			seg.redirectFile = dynamicRedirectTarget
		}
		return
	}
	if s == "/dev/null" || s == "/dev/stdout" || s == "/dev/stderr" {
		return
	}
	if seg.redirectFile == "" {
		seg.redirectFile = s
	}
}

func (c *subCollector) emitNestedFromWord(w *syntax.Word, feed stdinFeed) {
	if w == nil {
		return
	}
	if raw, ok := rawSlice(c.code, w.Pos(), w.End()); ok && rawHasLineContAfterDollar(raw) {
		c.reject()
		return
	}
	c.emitNestedFromNode(w, feed)
}

// feed flows into substitutions: a $(...) inherits the enclosing command's
// stdin, so `echo pig | cat $(sh)` feeds the pipe to sh. A <(...) proc subst
// inherits that same stdin; a >(...) subst is fed by the enclosing command's
// stdout — also an unvetted byte stream, so its inner stmts get feed too.
func (c *subCollector) emitNestedFromNode(n syntax.Node, feed stdinFeed) {
	if n == nil || c.rejected {
		return
	}
	syntax.Walk(n, func(node syntax.Node) bool {
		if node == nil || c.rejected {
			return false
		}
		switch x := node.(type) {
		case *syntax.CmdSubst:
			if c.depth+1 >= shellSplitMaxDepth {
				c.segs = append(c.segs, shellSegment{depthExceeded: true})
				return false
			}
			sub := c.newSub()
			// R13: every executable sub-statement shares the substitution's
			// stdin — `cat $(true; sh)` feeds the pipe to sh, not only to
			// the first statement.
			sub.walkStmtsAll(x.Stmts, feed)
			if sub.rejected {
				c.reject()
				return false
			}
			c.segs = append(c.segs, sub.segs...)
			return false
		case *syntax.ProcSubst:
			if c.depth+1 >= shellSplitMaxDepth {
				c.segs = append(c.segs, shellSegment{depthExceeded: true})
				return false
			}
			sub := c.newSub()
			if x.Op == syntax.CmdOut {
				// >(...) : the inner command is fed by the enclosing command's
				// stdout — an unvetted byte stream, treat as piped input.
				sub.walkStmtsAll(x.Stmts, stdinFeed{piped: true})
			} else {
				sub.walkStmtsAll(x.Stmts, feed)
			}
			if sub.rejected {
				c.reject()
				return false
			}
			c.segs = append(c.segs, sub.segs...)
			return false
		}
		return true
	})
}

// newSub creates a nested $(...)/<(...) sub-collector inheriting READ-ONLY
// snapshots of the outer static/enum/taint binds (W11-4): `$(find $d/...)`
// sees the enclosing for-loop's enum value and the outer top-level
// staticVars, while the child's own writes never leak back (allowBind=false).
// R21-Oracle-M3: the substitution is its own child execution scope — a
// freshly minted unique id off the current scope path — so assignments
// inside bind within this substitution's environment only.
func (c *subCollector) newSub() *subCollector {
	sub := &subCollector{
		code:         c.code,
		depth:        c.depth + 1,
		staticVars:   cloneStringMap(c.staticVars),
		litVars:      cloneStringMap(c.litVars),
		enumVars:     cloneStringMap(c.enumVars),
		enumCmdWords: cloneStringsMap(c.enumCmdWords),
		taintedVars:  cloneBoolMap(c.taintedVars),
		ssaBlocked:   cloneBoolMap(c.ssaBlocked),
		// R24-Oracle-S2: the positional tracks move to copy-on-write —
		// a substitution that defines no function and declares no readonly
		// variable never pays a table copy. The first write inside the
		// substitution clones lazily in noteFuncDef/noteReadonlyDecls;
		// the parent's map can never mutate underneath because the walk
		// is single-threaded and the substitution collector is discarded
		// before the walk resumes.
		readonlyVars: c.readonlyVars,
		funcNames:    c.funcNames,
		// R25-Oracle-MF3 / R25-Reviewer-#5: the sharing verdict keys on the
		// map REFERENCE itself, never its element count — an incremental
		// undo restore that deleted the last key leaves a non-nil empty
		// map, and a substitution writing into that aliased reference
		// would mutate the parent's table in place. nil means the child
		// may mint its own table; any non-nil reference is shared state
		// whose first write must clone.
		readonlyVarsShared: c.readonlyVars != nil,
		funcNamesShared:    c.funcNames != nil,
		allowBind:          false,
		childScope:         true,           // $(...) / <(...) run in their own child process (R20-Oracle-M3)
		scopeCounter:       c.scopeCounter, // R21-Oracle-M3: share the unique scope id space
		fdUnvetted:         c.fdUnvetted,
		caller:             c.caller,        // $(pwd) binds the same screened cwd inside $(...)
		hasCd:              c.hasCd,         // an outer cd already sighted stays sighted
		posixNoBraces:      c.posixNoBraces, // R18-Oracle-S4: the $(...) re-parse runs in the SAME shell — dash never brace-expands there either, so the dialect must ride into the substitution collector or echo $(printf tag{red,blue}) under dash encodes a brace word the runtime never produces
	}
	// Mint this substitution's own child scope id once: the sub-collector
	// is single-use, so the scope never pops (the restore closure is
	// deliberately discarded).
	if c.scopePath != "" || c.childScope {
		sub.scopePath = c.scopePath
	}
	sub.enterChildScope()
	return sub
}

func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneStringsMap(m map[string][]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func cloneBoolMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// posixUnescapeLit applies POSIX unquoted backslash rules to a Lit.Value:
// each "\X" becomes "X" (line-cont \n is already folded by the parser).
func posixUnescapeLit(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// wordToArg returns the static string form of w, or (cmdSubPlaceholder, false)
// when the word has dynamic/glob/tilde content.

func isSafeAbsPathVal(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") {
		return false
	}
	return isSafeIdentOrRelPath(s)
}

func isSafeIdentOrRelPath(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '/' ||
			ch == '-' || ch == '@' || ch == ':' || ch == '+'
		if !ok {
			return false
		}
	}
	return true
}

func (c *subCollector) taintVar(name string) {
	if name == "" {
		return
	}
	if c.taintedVars == nil {
		c.taintedVars = map[string]bool{}
	}
	c.taintedVars[name] = true
	delete(c.staticVars, name)
	delete(c.litVars, name)
}

// noteReadonlyDecls records the readonly attribute a
// readonly/declare/typeset/local declaration installs on its operand
// names (R22-Oracle-M1 / R22-Reviewer-#3): `readonly X` and
// `readonly X=v` both freeze X, and the declare family freezes the
// operands of its `-r` cluster (`declare -r X`, `declare -rx X=v`).
// Called AFTER the declaration's own binds are minted, so the inline
// value of `readonly X=/x` still binds — only writes AFTER this point
// hit the readonly wall. A `+r` spelling REMOVES nothing conservatively
// (declare +r unsets the attribute in bash): keeping the name frozen is
// the fail-closed direction because an unfreeze is never provable here.
func (c *subCollector) noteReadonlyDecls(argv []string) {
	if len(argv) < 2 {
		return
	}
	frozen := false
	switch argv[0] {
	case "readonly":
		frozen = true // readonly freezes ALL its name operands
	case "declare", "typeset", "local":
	default:
		return
	}
	for _, a := range argv[1:] {
		if len(a) > 1 && a[0] == '-' {
			if strings.ContainsRune(a[1:], 'r') {
				frozen = true
			}
			continue
		}
		if !frozen {
			continue
		}
		name := a
		if k := strings.IndexByte(name, '='); k >= 0 {
			name = name[:k]
		}
		if name == "" || strings.ContainsAny(name, "\x00") || isDynamicArg(name) {
			continue
		}
		c.regInsertReadonlyVar(name)
	}
}

// noteDeclCallBinds records abs-path binds from POSIX-style
// `export`/`readonly`/`declare`/`typeset`/`local` CallExpr KEY=VAL args.
func (c *subCollector) noteDeclCallBinds(argv []string) {
	if len(argv) < 2 || !c.allowBind {
		return
	}
	switch argv[0] {
	case "export", "readonly", "declare", "typeset", "local":
	default:
		return
	}
	for _, a := range argv[1:] {
		if !isAssignWord(a) {
			continue
		}
		k := strings.IndexByte(a, '=')
		if k <= 0 {
			continue
		}
		name, val := a[:k], a[k+1:]
		static := !isDynamicArg(val)
		c.noteStaticAssign(name, val, static)
	}
}

// noteShellAssign is noteStaticAssign for a PURE assignment write of
// the script (a bare `X=v` statement or a static eval's replication —
// never a declaration's own inline value): after `readonly X` /
// `declare -r X` the runtime write fails outright, so it can never
// establish the new value the word carries and the sound verdict is
// pollution, not the exact binding (R22-Oracle-M1 / R22-Reviewer-#3).
func (c *subCollector) noteShellAssign(name, val string, static bool) {
	if c.readonlyVars[name] {
		c.taintVar(name)
		return
	}
	c.noteStaticAssign(name, val, static)
}

func (c *subCollector) noteStaticAssign(name, val string, static bool) {
	if c.staticVars == nil {
		c.staticVars = map[string]string{}
	}
	if c.litVars == nil {
		c.litVars = map[string]string{}
	}
	if c.taintedVars == nil {
		c.taintedVars = map[string]bool{}
	}
	if name == "" {
		return
	}
	if c.bindImpossible(name, val, static) {
		return
	}
	// Safe-literal values (no field-split / glob / tilde chars) bind into
	// litVars for in-word substitution; absolute-path values ALSO bind into
	// staticVars (command-head eligible). A stale or differing earlier bind
	// taints the name — writes must be single-assignment to stay known.
	if prev, ok := c.staticVars[name]; ok && prev != val {
		c.taintVar(name)
		return
	}
	if prev, ok := c.litVars[name]; ok && prev != val {
		c.taintVar(name)
		return
	}
	c.litVars[name] = val
	if isSafeAbsPathVal(val) {
		c.staticVars[name] = val
	}
}

// bindImpossible applies the pre-bind verdicts of noteStaticAssign
// (extracted so the readonly/dynamic special-variable gate carries no
// extra nesting): a name the runtime can never re-bind (readonly or
// dynamic specials — R22-Oracle-M1 / R22-Reviewer-#3: the write errors
// or is silently dropped, so the exact binding the word spells is
// certainly wrong; this precedes even allowBind because no execution
// context can repair an impossible write, and even a declaration
// `declare UID=5` errors in bash — script-declared readonly variables
// are handled by the pure-assignment paths instead because the
// declaration's own inline write `readonly X=/x` succeeds), a write
// outside a binding scope, an already-tainted name and a non-static or
// unsafe value all resolve to pollution or a no-op before any binding
// is minted. Returns true when the caller must stop here.
func (c *subCollector) bindImpossible(name, val string, static bool) bool {
	if shellNonBindableVars[name] {
		c.taintVar(name)
		return true
	}
	if !c.allowBind {
		c.taintVar(name)
		return true
	}
	if c.isTainted(name) {
		return true
	}
	if !static || !isSafeIdentOrRelPath(val) {
		c.taintVar(name)
		return true
	}
	return false
}

func (c *subCollector) resolveStaticParam(pe *syntax.ParamExp) (string, bool) {
	if pe == nil || pe.Param == nil || c.staticVars == nil {
		return "", false
	}
	if pe.Exp != nil || pe.Slice != nil || pe.Repl != nil || pe.Index != nil || pe.Length || pe.Excl || pe.Names != 0 {
		return "", false
	}
	name := pe.Param.Value
	if c.isTainted(name) {
		return "", false // S1: the "*" give-up taint never resolves binds
	}
	v, ok := c.staticVars[name]
	if !ok {
		return "", false
	}
	// Guard vars may NEVER become a static command head: an attacker who
	// managed to bind CTXMODE_ROLE must not get a screened-free head.
	if guardTaintVars[name] {
		return "", false
	}
	if !isSafeIdentOrRelPath(v) {
		return "", false
	}
	return v, true
}

// resolveParamForSubst resolves a simple $VAR / ${VAR} from enumVars (for-loop
// payload subst — consulted FIRST: the loop var is deliberately tainted so it
// can never become a static head, yet the enum walk binds it per-iteration),
// staticVars (abs-path binds) or litVars (safe-literal binds — only when
// litOK, i.e. never for a bare whole-word "$VAR", so `BUN=echo; "$BUN"`
// stays a dynamic head). The "*" give-up taint blocks static/lit binds (S1).
func (c *subCollector) resolveParamForSubst(pe *syntax.ParamExp, litOK bool) (string, bool) {
	if pe == nil || pe.Param == nil {
		return "", false
	}
	if pe.Exp != nil || pe.Slice != nil || pe.Repl != nil || pe.Index != nil || pe.Length || pe.Excl || pe.Names != 0 {
		return "", false
	}
	name := pe.Param.Value
	if c.enumVars != nil {
		if v, ok := c.enumVars[name]; ok {
			if !isSafeIdentOrRelPath(v) {
				return "", false
			}
			return v, true
		}
	}
	if c.isTainted(name) {
		return "", false // S1: "*" taint blocks every persistent bind
	}
	if c.staticVars != nil {
		if v, ok := c.staticVars[name]; ok {
			if !isSafeIdentOrRelPath(v) {
				return "", false
			}
			return v, true
		}
	}
	if litOK && c.litVars != nil {
		if v, ok := c.litVars[name]; ok {
			return v, true
		}
	}
	return "", false
}

// staticAssignVal computes the (value, static) pair for an assignment whose
// RHS is w. A bare $(pwd) binds the process cwd; a bare $(mktemp -d) binds
// the marker /tmp/__ctx_mktemp_dir__ (F8: only when TMPDIR is not tainted —
// every other spelling keeps the value dynamic).
func (c *subCollector) staticAssignVal(w *syntax.Word) (string, bool) {
	if w != nil && len(w.Parts) == 1 {
		if cs, ok := w.Parts[0].(*syntax.CmdSubst); ok && !cs.Backquotes {
			if isPwdCallStmts(cs.Stmts) {
				// A bare $(pwd) binds the caller's screened cwd only while no
				// directory-switch builtin (cd/chdir/pushd/popd) can run first;
				// once c.hasCd is set — or the preScanVarMutations pass saw one —
				// the value is unknowable and the bind must stay dynamic.
				if !c.hasCd && !c.pwdSwitchTainted() {
					if wd := c.caller.screenCwd(); wd != "" {
						return wd, true
					}
				}
				return "", false
			}
			// R16-Oracle-M1: the assignment-binding grant must carry the SAME
			// inheritedTmpdirValid() proof as the direct double-quoted
			// substitution path (dqSubstPlaceholder) — a TMPDIR=/dev/null or
			// TMPDIR=/proc makes mktemp fail with EMPTY stdout, so a variable
			// bound here must not pose as the non-empty absolute mktemp
			// directory either. R17-Oracle-M1: a writable TMPDIR still does
			// not prove the child RUNS at all — the effective PATH must also
			// resolve an executable mktemp (canResolveMktempInPath).
			if c.mktempGrantOK() && isMktempDashDCallStmts(cs.Stmts) {
				return mktempDirPlaceholder, true
			}
		}
	}
	if w == nil {
		return "", false
	}
	return c.wordToArg(w)
}

// mktempGrantOK reports whether a bare `$(mktemp -d)` substitution is
// guaranteed to SUCCEED: TMPDIR untainted and inherited-valid (so the child
// can create the directory) AND the collector's effective PATH resolves an
// executable mktemp binary (R17-Oracle-M1). A PATH carrying only directories
// without mktemp (e.g. a minimal /usr/local/sbin sandbox PATH) makes the
// shell report "command not found", the substitution collapses to the empty
// string and no absolute-dir / non-empty proof may stand — not even the
// assignment-binding mktempDirPlaceholder grant. When the script wrote PATH
// in any unreadable shape (tainted) no proof exists either.
func (c *subCollector) mktempGrantOK() bool {
	if c.isTainted("TMPDIR") || !inheritedTmpdirValid() {
		return false
	}
	return c.canResolveMktempInPath()
}

// canResolveMktempInPath reports whether the EFFECTIVE PATH the shell child
// would resolve against contains an executable `mktemp` in one of its
// directories. A tainted PATH is unvettable; an unreadable script bind falls
// through to the caller's effective PATH (replay of the process PATH through
// every env op seen so far), finally os.Getenv("PATH"). Every candidate
// directory must itself be absolute (a relative PATH segment resolves
// against the child's cwd — unknowable here — and never proves the lookup)
// and yield a non-directory entry with any execute bit set.
func (c *subCollector) canResolveMktempInPath() bool {
	if c.isTainted("PATH") || c.ssaBlocked["PATH"] {
		return false
	}
	pathEnv := ""
	if c.staticVars != nil {
		pathEnv = c.staticVars["PATH"]
	}
	if pathEnv == "" {
		pathEnv = c.caller.effectivePATH()
	}
	for _, d := range strings.Split(pathEnv, ":") {
		if pathHasExecutable(d, "mktemp") {
			return true
		}
	}
	return false
}

// pathHasExecutable reports whether dir (an absolute directory of a PATH
// value) contains a non-directory entry `name` with any execute bit. Empty
// (the PATH "current directory" entry) and relative segments can never
// prove a lookup — the resolution base is the child's cwd, not ours.
// R18-Oracle-M1: the lookup must reproduce the KERNEL's per-component
// resolution exactly — filepath.Join would lexically clean a `..` segment
// away before Stat, turning `/usr/bin/true/..` (which the kernel rejects
// with ENOTDIR because /usr/bin/true is a regular file) into `/usr/bin`.
// The candidate path is therefore concatenated WITHOUT any cleaning and
// dir itself must stat as a real directory first.
func pathHasExecutable(dir, name string) bool {
	if dir == "" || !filepath.IsAbs(dir) || !pathIsRealDirectory(dir) {
		return false
	}
	return statExecutableFile(strings.TrimRight(dir, "/") + "/" + name)
}

// pathIsRealDirectory reports whether dir stats as a real directory
// (extracted for the v6.2.2 R18 complexity budget). Because the path is
// stat'd VERBATIM, a `/usr/bin/true/..` spelling fails here with ENOTDIR
// exactly like the kernel's per-component lookup rejects it — no lexical
// `..` cleanup may ever launder it into a usable PATH directory.
func pathIsRealDirectory(dir string) bool {
	dfi, err := os.Stat(dir)
	return err == nil && dfi.IsDir()
}

// statExecutableFile reports whether p stats as a non-directory entry
// with any execute bit (extracted for the v6.2.2 R18 complexity budget).
// The path is concatenated WITHOUT cleaning by the caller and passed to
// Stat verbatim, so the kernel performs its own per-component resolution.
func statExecutableFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Mode()&0111 != 0
}

// pwdSwitchTainted reports whether the whole-script mutation pre-scan saw a
// directory-switch builtin (cd/chdir/pushd/popd) — those inc PWD/OLDPWD, and
// preScanVarMutations marks both tainted before the walk starts, so a bare
// $(pwd) bind in a script containing any of them can never be static.
func (c *subCollector) pwdSwitchTainted() bool {
	return c.isTainted("PWD") || c.isTainted("OLDPWD")
}

// isPwdCallStmts reports whether stmts is exactly `pwd` (no operands).
func isPwdCallStmts(stmts []*syntax.Stmt) bool {
	return bareCallArgvIs(stmts, []string{"pwd"})
}

// isMktempDashDCallStmts reports whether stmts is exactly `mktemp -d`.
func isMktempDashDCallStmts(stmts []*syntax.Stmt) bool {
	return bareCallArgvIs(stmts, []string{"mktemp", "-d"})
}

// bareCallArgvIs reports whether stmts is a single plain call whose static
// argv equals want.
func bareCallArgvIs(stmts []*syntax.Stmt, want []string) bool {
	if len(stmts) != 1 || stmts[0] == nil || stmts[0].Background ||
		stmts[0].Negated || stmts[0].Coprocess || len(stmts[0].Redirs) > 0 {
		return false
	}
	call, ok := stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) != len(want) {
		return false
	}
	for i, w := range call.Args {
		s, ok := wordToArg(w)
		if !ok || s != want[i] {
			return false
		}
	}
	return true
}

// forEnumSubst substitutes each static for-list value into the Do body.
// Returns true when the Do body was handled (either enum-walked or rejected).
// Dynamic items leave the caller to walk Do once without binding.
//
// W11-5/F6: items that are static multi-word command strings bind into
// enumCmdWords (expanding a bare $name head word into several argv words,
// each individually screened); this requires an untainted IFS since the
// runtime split uses the live IFS while the model uses ASCII whitespace.
// Items that fail even that check make the whole loop fall back to the
// dynamic path.
func (c *subCollector) forEnumSubst(loopName string, items []*syntax.Word, do []*syntax.Stmt, feed stdinFeed) bool {
	if len(items) == 0 {
		return false
	}
	if c.ssaBlocked != nil && c.ssaBlocked[loopName] {
		return false // G3: multi-write elsewhere → no static enum
	}
	type item struct {
		single string
		words  []string
	}
	vals := make([]item, 0, len(items))
	for _, w := range items {
		s, ok := c.wordToArg(w)
		if !ok || isDynamicArg(s) {
			return false // dynamic item → stay dynamic
		}
		if isSafeIdentOrRelPath(s) {
			vals = append(vals, item{single: s, words: []string{s}})
			continue
		}
		// W11-5: multi-word static command string. Every sub-word must be a
		// safe token; the head sub-word additionally forbids '=' (an
		// IFS='=' split would otherwise smuggle a KEY=VAL env prefix). The
		// whole construct is disabled when IFS is tainted.
		if c.isTainted("IFS") {
			return false
		}
		ws := strings.Fields(s)
		if len(ws) < 2 {
			return false
		}
		safe := true
		for i, sw := range ws {
			if !isSafeEnumCmdWord(sw, i == 0) {
				safe = false
				break
			}
		}
		if !safe {
			return false
		}
		vals = append(vals, item{words: ws})
	}
	if c.enumVars == nil {
		c.enumVars = map[string]string{}
	}
	if c.enumCmdWords == nil {
		c.enumCmdWords = map[string][]string{}
	}
	prev, hadPrev := c.enumVars[loopName]
	prevW, hadPrevW := c.enumCmdWords[loopName]
	for _, it := range vals {
		if it.single != "" {
			c.enumVars[loopName] = it.single
		} else {
			delete(c.enumVars, loopName)
		}
		c.enumCmdWords[loopName] = it.words
		c.walkStmtsAll(do, feed)
		if c.rejected {
			break
		}
	}
	if hadPrev {
		c.enumVars[loopName] = prev
	} else {
		delete(c.enumVars, loopName)
	}
	if hadPrevW {
		c.enumCmdWords[loopName] = prevW
	} else {
		delete(c.enumCmdWords, loopName)
	}
	return true
}

// isSafeEnumCmdWord reports whether one whitespace-split token of a static
// multi-word enum item is safe to splice into argv: no characters that a
// plausible IFS could re-split (':' '+' ',' ';' '|'), no glob/regex bytes
// that could re-expand at runtime (R8: '*', '?', '[', ']') and no grouping
// parens (extglob operators) — for the HEAD sub-word no '=' either
// (KEY=VAL env prefix via IFS='=').
func isSafeEnumCmdWord(s string, head bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ':', '+', ',', ';', '|', '*', '?', '[', ']', '(', ')':
			return false
		case '=':
			if head {
				return false
			}
		}
	}
	return true
}

// singleSimpleParamExp reports whether w is exactly one unquoted simple
// parameter expansion ($name or ${name}) and returns the name.
func singleSimpleParamExp(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	pe, ok := w.Parts[0].(*syntax.ParamExp)
	if !ok || pe.Param == nil {
		return "", false
	}
	if pe.Exp != nil || pe.Slice != nil || pe.Repl != nil || pe.Index != nil ||
		pe.Length || pe.Excl || pe.Names != 0 {
		return "", false
	}
	return pe.Param.Value, true
}

// tilde expansion shapes for a word-start tilde literal (R19-Oracle-M3):
// bash expands `~` into $HOME ONLY when the whole tilde prefix — the bytes
// up to the first unquoted `/` — contains no quoted character AND the
// prefix is empty (or resolves as a login name). A literal like `~\/notes`
// (the slash backslash-escaped) or `~'notes'` (the tilde literal followed
// by another word part) is NEVER expanded: the shell passes `~/notes` as a
// verbatim cwd-relative path word. tildeShapeLiteral therefore carries no
// glob/tilde marker at all, tildeShapeHome is the $HOME expansion the
// provenance marker may attach to, and tildeShapeDynamic covers everything
// else expansible (login names, ~+/~-) without the HOME provenance.
const (
	tildeShapeNone = iota
	tildeShapeLiteral
	tildeShapeHome
	tildeShapeDynamic
)

// tildeLitShape classifies one word-leading literal's tilde prefix exactly
// like bash: scan the bytes after `~` up to the first unquoted `/` — a
// backslash-escaped byte anywhere inside the prefix is a QUOTED character
// and disqualifies the expansion outright (verbatim literal). soloPart is
// whether the literal is the word's ONLY part: a lone `~` expands only as
// a whole word, while a multi-part word whose first literal is exactly `~`
// can never expand (the next part is never an unquoted slash — adjacent
// unquoted literals merge into one Lit in the parser).
func tildeLitShape(rawLit string, soloPart bool) int {
	if !strings.HasPrefix(rawLit, "~") {
		return tildeShapeNone
	}
	prefix := rawLit[1:]
	endsAtSlash := false
	quoted := false
	for i := 0; i < len(prefix); i++ {
		if prefix[i] == '\\' {
			quoted = true
			i++
			continue
		}
		if prefix[i] == '/' {
			prefix = prefix[:i]
			endsAtSlash = true
			break
		}
	}
	if quoted {
		return tildeShapeLiteral
	}
	if prefix == "" {
		if endsAtSlash || soloPart {
			return tildeShapeHome
		}
		return tildeShapeLiteral
	}
	if endsAtSlash {
		// The unquoted prefix ENDS at a real unquoted slash inside this
		// very literal — no quoting can hide inside the prefix, so the
		// login-name expansion genuinely applies (~user/notes).
		return tildeShapeDynamic
	}
	// No unquoted slash inside the leading literal: the rest of the tilde
	// prefix continues in the LATER word parts — the caller supplies
	// whether any of them is quoted (R20-Oracle-S1).
	if soloPart {
		return tildeShapeDynamic
	}
	return tildeShapeDynamic // refined by tildeWordShape — see below
}

// tildeWordShape refines tildeLitShape with the word-level view bash's
// tilde expansion actually uses (R20-Oracle-S1): the tilde PREFIX spans
// every byte up to the first UNQUOTED slash (or the word end) ACROSS word
// parts, and the expansion fires only when no byte of that prefix is
// quoted. A login-name literal like ~ro"ot"/notes carries quoted bytes
// inside its prefix, so bash passes the de-quoted text VERBATIM — a
// cwd-relative literal path, never a dynamic login lookup: the shape is
// tildeShapeLiteral (plain static text, no glob or tilde marker). The
// genuinely unquoted ~root/notes keeps tildeShapeDynamic and its original
// dynamic treatment.
func tildeWordShape(w *syntax.Word, litIdx int) int {
	if litIdx >= len(w.Parts) {
		return tildeShapeNone
	}
	lit, ok := w.Parts[litIdx].(*syntax.Lit)
	if !ok {
		return tildeShapeNone
	}
	solo := len(w.Parts) == 1
	shape := tildeLitShape(lit.Value, solo)
	if shape != tildeShapeDynamic {
		return shape
	}
	// Dynamic candidate: check whether an unquoted slash ended the prefix
	// inside the leading literal itself. If not, scan the following parts:
	// any quoted part (or any part at all) before the first unquoted slash
	// poisons the expansion — quoted bytes inside the prefix make the
	// whole word a verbatim literal.
	prefix := lit.Value[1:]
	unquotedSlashInLit := false
	for i := 0; i < len(prefix); i++ {
		if prefix[i] == '\\' {
			i++
			continue
		}
		if prefix[i] == '/' {
			unquotedSlashInLit = true
			break
		}
	}
	if unquotedSlashInLit || solo {
		return tildeShapeDynamic
	}
	// The prefix continues beyond the first literal. Adjacent unquoted
	// literals merge inside the parser, so any further Lit/quoted/dynamic
	// part either carries quoted bytes or is not literal text — either
	// way the expansion cannot fire and the word is a verbatim literal.
	// (A dynamic part already forces the dynamic encoding through its own
	// placeholder regardless of this classification.)
	if litIdx+1 < len(w.Parts) {
		switch w.Parts[litIdx+1].(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted, *syntax.Lit:
			return tildeShapeLiteral
		default:
			return tildeShapeDynamic
		}
	}
	return tildeShapeDynamic
}

// unquotedTildeTrigger reports whether a word-start tilde literal mints a
// glob/tilde marker: only EXPANSIBLE shapes do (R19-Oracle-M3) — a
// verbatim literal tilde (`~\/notes`, `~` followed by more word parts,
// or a login-name prefix carrying quoted bytes, R20-Oracle-S1) produces
// plain static text.
func unquotedTildeTrigger(rawLit string, isWordStart, soloPart bool) bool {
	if !isWordStart {
		return false
	}
	shape := tildeLitShape(rawLit, soloPart)
	return shape == tildeShapeHome || shape == tildeShapeDynamic
}

// unquotedTildeTriggerWord is unquotedTildeTrigger refined by the
// word-level tilde-prefix analysis (R20-Oracle-S1): the expansion shape
// depends on parts AFTER the leading literal, so the per-part scan needs
// the whole word and the literal's index. quoted-follows shapes are
// verbatim literals — no expansion of any kind happens.
func unquotedTildeTriggerWord(w *syntax.Word, litIdx int, isWordStart bool) bool {
	if !isWordStart {
		return false
	}
	shape := tildeWordShape(w, litIdx)
	return shape == tildeShapeHome || shape == tildeShapeDynamic
}

func litHasUnquotedGlobOrTilde(rawLit string, isWordStart bool, openBracket *bool) bool {
	return litHasUnquotedGlobOrTildePart(rawLit, isWordStart, true, openBracket)
}

// litHasUnquotedGlobOrTildePart is litHasUnquotedGlobOrTilde with the
// literal's only-part status threaded through for the tilde classifier
// (R19-Oracle-M3). The verbatim move keeps the byte-scan body unchanged;
// only the tilde arm consults unquotedTildeTrigger.
func litHasUnquotedGlobOrTildePart(rawLit string, isWordStart, soloPart bool, openBracket *bool) bool {
	for i := 0; i < len(rawLit); i++ {
		ch := rawLit[i]
		if ch == '\\' {
			i++ // escaped byte is literal
			continue
		}
		if isWordStart && i == 0 && ch == '~' {
			if unquotedTildeTrigger(rawLit, isWordStart, soloPart) {
				return true
			}
			continue
		}
		switch ch {
		case '*', '?':
			return true
		case '[':
			*openBracket = true
		case ']':
			if *openBracket {
				return true
			}
		}
	}
	return false
}

// litHasUnquotedGlobOrTildeWord is litHasUnquotedGlobOrTildePart with the
// whole word and the literal's part index (R20-Oracle-S1): the tilde arm
// consults the word-level prefix scan so a login-name prefix carrying
// quoted bytes stays the verbatim literal bash passes. The glob byte scan
// is unchanged.
func litHasUnquotedGlobOrTildeWord(w *syntax.Word, litIdx int, rawLit string, isWordStart bool, openBracket *bool) bool {
	for i := 0; i < len(rawLit); i++ {
		ch := rawLit[i]
		if ch == '\\' {
			i++ // escaped byte is literal
			continue
		}
		if isWordStart && i == 0 && ch == '~' {
			if unquotedTildeTriggerWord(w, litIdx, isWordStart) {
				return true
			}
			continue
		}
		switch ch {
		case '*', '?':
			return true
		case '[':
			*openBracket = true
		case ']':
			if *openBracket {
				return true
			}
		}
	}
	return false
}

// wordBraceExpHit reports whether w carries an unquoted BRACE EXPANSION
// (R14-Oracle-M1). The locked parser (mvdan.cc/sh v3.14.1) keeps brace
// expansions inside *syntax.Lit — the *syntax.BraceExp node only ever
// materializes through syntax.SplitBraces, so the conversion must replay
// that split on a throwaway copy of the word. Brace text can also SPAN
// quoting boundaries ({'%n',TAR_OPTIONS} — bash still expands it), so the
// scan walks EVERY Lit part of the word instead of trusting a per-part
// literal scan. Bash performs brace expansion before field splitting: one
// static word becomes MULTIPLE argv words, so any hit forces the dynamic
// encoding even when no glob/tilde byte is present.
func wordBraceExpHit(w *syntax.Word) bool {
	// R15-Oracle-S3: single-pass work-budget scan BEFORE any SplitBraces
	// replay. A VALID brace expansion must carry a closing '}' AND a
	// separator (',' or '..'); nested pure-literal braces without a
	// separator ({{{{a}}}}) never materialize a BraceExp node — but the
	// former recursive replay copied the already-restored inner Parts at
	// every nesting level (1+3+5+... items: QUADRATIC in depth, 16 copied
	// items at depth 4, 64 at depth 8, for a word bash leaves as ONE
	// literal). Skipping those words entirely costs one O(N) literal scan
	// with ZERO WordPart copies. The scan is conservative in both
	// directions: quoted/concatenated '{' bytes it cannot see keep the
	// SplitBraces replay, and pathologically deep nesting WITH a
	// separator (openCount > 8) conservatively reports a hit without
	// replaying anything — failing closed with a bounded budget.
	openCount := 0
	hasClose := false
	hasSep := false
	for _, part := range w.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			continue
		}
		for i := 0; i < len(lit.Value); i++ {
			switch lit.Value[i] {
			case '{':
				openCount++
			case '}':
				hasClose = true
			case ',':
				hasSep = true
			case '.':
				if i+1 < len(lit.Value) && lit.Value[i+1] == '.' {
					hasSep = true
				}
			}
		}
	}
	if openCount == 0 || !hasClose || !hasSep {
		return false
	}
	if openCount > 8 {
		return true // deep nesting with separators: conservatively dynamic
	}
	cp := *w
	cp.Parts = append([]syntax.WordPart(nil), w.Parts...)
	syntax.SplitBraces(&cp)
	for _, part := range cp.Parts {
		if _, ok := part.(*syntax.BraceExp); ok {
			return true
		}
	}
	return false
}

// wordToArg returns the static string form of w, or (prefix+placeholder, false)
// when the word has dynamic/glob/tilde content. Static prefixes such as -c are
// preserved so option scanners can still see the option letter.
//
// Placeholder grading (SH11 G2): unquoted glob/tilde lits emit
// cmdSubPlaceholderGlob (split-safe by POSIX definition: pathname expansion
// never field-splits), unquoted $$ emits cmdSubPlaceholderQuoted (a PID is
// digits — cannot field-split). Variable/command substitutions in a
// context-free conversion keep the conservative cmdSubPlaceholder; the
// collector method c.wordToArg is taint-aware and upgrades $HOME / $PATH /
// $PWD / $$ / $(pwd) / $(mktemp -d).
func wordToArg(w *syntax.Word) (string, bool) {
	return wordToArgDialect(w, false)
}

// wordToArgPosix is wordToArg under the POSIX/dash dialect (v6.2.2 Oracle
// R16 S2): dash performs NO brace expansion, so the brace scan is skipped
// and printf tag{red,blue} stays the static literal dash really passes.
func wordToArgPosix(w *syntax.Word) (string, bool) {
	return wordToArgDialect(w, true)
}

// wordBraceExpHitDialect is wordBraceExpHit gated on the dialect
// (v6.2.2 Oracle R16 S2): dash performs NO brace expansion at all, so the
// scan is skipped outright under posixNoBraces instead of paying the
// budget scan for a multiplication the runtime never performs.
func wordBraceExpHitDialect(w *syntax.Word, posixNoBraces bool) bool {
	if posixNoBraces {
		return false
	}
	return wordBraceExpHit(w)
}

func wordToArgDialect(w *syntax.Word, posixNoBraces bool) (string, bool) {
	if w == nil || len(w.Parts) == 0 {
		return "", false
	}
	var b strings.Builder
	static := true
	openBracket := false
	// R14-Oracle-M1: brace expansion turns ONE static word into MANY argv
	// words under bash — the encoding can never stay static.
	// R15-Oracle-S1: the brace hit UNCONDITIONALLY appends its own glob
	// placeholder — a leading '~' that already emitted one therefore yields
	// TWO markers, which is exactly what denies `~/{red,blue}` (but not the
	// single-glob `~/x` or the quoted-literal `~/'{red,blue}'`) the
	// pure-tilde single-path exemption in isSingleWordOptionValue.
	braceSeen := wordBraceExpHitDialect(w, posixNoBraces)
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if litHasUnquotedGlobOrTildeWord(w, i, p.Value, i == 0 && b.Len() == 0, &openBracket) {
				static = false
				b.WriteString(posixUnescapeLit(p.Value))
				b.WriteString(cmdSubPlaceholderGlob)
				continue
			}
			b.WriteString(posixUnescapeLit(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				static = false
				b.WriteString(cmdSubPlaceholder)
			} else {
				b.WriteString(p.Value)
			}
		case *syntax.DblQuoted:
			if p.Dollar {
				static = false
				b.WriteString(cmdSubPlaceholderQuoted)
				break
			}
			if !writeCtxFreeDqParts(&b, p) {
				static = false
			}
		case *syntax.ParamExp:
			// Context-free: only $$ (a decimal PID) is known split-safe.
			// R13-SF-2: the encoding carries a leading digit — a PID can never
			// expand to "--" (or any dash spelling) and never starts with '-',
			// so dynWordCanSpellDashDash must not vacuously strip the whole
			// word. The digit prefix is a marker, not a value claim.
			// R14-Oracle-M3: simpleParamName excludes Slice/Repl/Index/Length/
			// Excl/Names — ${$:0:0} can expand EMPTY and spell "--".
			static = false
			if name, ok := simpleParamName(p); ok && name == "$" {
				b.WriteString("0" + cmdSubPlaceholderQuoted)
			} else {
				b.WriteString(cmdSubPlaceholder)
			}
		case *syntax.CmdSubst, *syntax.ArithmExp,
			*syntax.ProcSubst, *syntax.ExtGlob, *syntax.BraceExp:
			static = false
			b.WriteString(cmdSubPlaceholder)
		default:
			static = false
			b.WriteString(cmdSubPlaceholder)
		}
	}
	if braceSeen {
		static = false
		writeBraceExpansionMarkers(&b)
	}
	if !static {
		if b.Len() == 0 {
			return cmdSubPlaceholder, false
		}
		return b.String(), false
	}
	return b.String(), true
}

// writeCtxFreeDqParts encodes the parts of one non-dollar double-quoted
// segment for the context-free wordToArgDialect (extracted for the v6.2.2
// R16 complexity budget). Returns false when any part is dynamic.
func writeCtxFreeDqParts(b *strings.Builder, p *syntax.DblQuoted) bool {
	static := true
	for _, ip := range p.Parts {
		switch ipp := ip.(type) {
		case *syntax.Lit:
			b.WriteString(decodeDblQuotedLit(ipp.Value))
		case *syntax.ParamExp:
			// "$@"/"${arr[@]}"/"${!prefix@}"/"${x:-$@}" still
			// field-split inside double quotes -> NOT split-safe.
			static = false
			if paramExpSplitsInDblQuotes(ipp) {
				b.WriteString(cmdSubPlaceholder)
			} else if name, ok := simpleParamName(ipp); ok && name == "$" {
				// R13-SF-2: decimal PID — the digit prefix keeps
				// dynWordCanSpellDashDash from a vacuous all-dash match.
				// R14-Oracle-M3: simpleParamName, never a bare
				// Param.Value=="$" check — derived operators
				// (${$:0:0} zero-length slice CAN be empty) must not
				// inherit the never-dash PID grant.
				b.WriteString("0" + cmdSubPlaceholderQuoted)
			} else {
				b.WriteString(cmdSubPlaceholderQuoted)
			}
		default:
			static = false
			b.WriteString(cmdSubPlaceholderQuoted)
		}
	}
	return static
}

// writeBraceExpansionMarkers emits the glob markers a real brace expansion
// word carries (R16-Oracle-S1, R17-Oracle-S1): the encoding must end with
// TWO CONSECUTIVE ADJACENT glob placeholders so the consumer can
// distinguish a true brace expansion (the word multiplied into several
// argv words) from a plain pathname glob that merely passes through a
// QUOTED literal '{' — docs/*/'{v1}'/*.txt legitimately carries TWO
// markers already (one per unquoted '*' Lit), but they are separated by
// the static infix "/{v1}/*.txt" and never adjacent, so it stays a safe
// data operand while {docs/a,-blue} and ~/{red,blue} both end in the
// adjacent __ctx_glob____ctx_glob__ pair the consumers key on.
func writeBraceExpansionMarkers(b *strings.Builder) {
	// R18-Oracle-M4: the NUL-provenanced tilde marker is provenance, not
	// a glob byte — it sits between the tilde literal's own glob marker
	// and this tail, so the suffix check must see through it or a tilde
	// brace word (~/{red,blue}) would mint a phantom third glob marker
	// instead of the required adjacent pair.
	if !strings.HasSuffix(strings.ReplaceAll(b.String(), cmdSubPlaceholderTilde, ""), cmdSubPlaceholderGlob) {
		b.WriteString(cmdSubPlaceholderGlob)
	}
	b.WriteString(cmdSubPlaceholderGlob)
}

func (c *subCollector) wordToArg(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) == 0 {
		return "", false
	}
	// Fast path: full-word simple ParamExp resolve for command heads
	// (staticVars / abs-path binds only — enumVars never become heads).
	if len(w.Parts) == 1 {
		if pe, ok := w.Parts[0].(*syntax.ParamExp); ok {
			if v, ok := c.resolveStaticParam(pe); ok {
				return v, true
			}
		}
		if dq, ok := w.Parts[0].(*syntax.DblQuoted); ok && !dq.Dollar && len(dq.Parts) == 1 {
			if pe, ok := dq.Parts[0].(*syntax.ParamExp); ok {
				if v, ok := c.resolveStaticParam(pe); ok {
					return v, true
				}
			}
		}
	}
	// Always route through the taint-aware converter: the PATH/HOME/PWD
	// placeholder grants depend on envTaint + script writes even when no
	// staticVars/enumVars binds exist.
	return c.wordToArgWithSubst(w)
}

// wordToArgWithSubst is wordToArg plus R-Allow-2 ParamExp substitution from
// enumVars/staticVars/litVars (in-word / -c payload expansion) and the SH11
// taint-aware placeholder grading. A bare "$VAR" word never resolves
// litVars (litOK=false): a plain literal head like BUN=echo must stay
// dynamic — `x=v && "$x"` patterns are only honoured for abs-path binds.
func (c *subCollector) wordToArgWithSubst(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) == 0 {
		return "", false
	}
	litOK := true
	if len(w.Parts) == 1 {
		if _, ok := w.Parts[0].(*syntax.ParamExp); ok {
			litOK = false
		}
		if dq, ok := w.Parts[0].(*syntax.DblQuoted); ok && len(dq.Parts) == 1 {
			if _, ok := dq.Parts[0].(*syntax.ParamExp); ok {
				litOK = false
			}
		}
	}
	var b strings.Builder
	static := true
	openBracket := false
	// R14-Oracle-M1: same brace-expansion encoding as the context-free
	// wordToArg — one word becomes MANY argv words under bash, so a brace
	// hit can never stay static.
	// R15-Oracle-S1: under the POSIX/dash top-level dialect brace
	// expansion does not exist at all (posixNoBraces), so the scan is
	// skipped for the primary-dialect encoding; when it IS applied (bash
	// payloads and the blank collector default) the hit UNCONDITIONALLY
	// appends its own glob placeholder — a leading '~' that already
	// emitted one therefore yields TWO markers, which is exactly what
	// denies `~/{red,blue}` (but not the quoted-literal `~/'{red,blue}'`)
	// the pure-tilde single-path exemption in isSingleWordOptionValue.
	braceSeen := false
	if !c.posixNoBraces {
		braceSeen = wordBraceExpHit(w)
	}
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if c.writeUnquotedGlobTildeLit(&b, w, i, p.Value, i == 0 && b.Len() == 0, &openBracket) {
				static = false
				continue
			}
			b.WriteString(posixUnescapeLit(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				static = false
				b.WriteString(cmdSubPlaceholder)
			} else {
				b.WriteString(p.Value)
			}
		case *syntax.DblQuoted:
			if p.Dollar {
				static = false
				b.WriteString(cmdSubPlaceholderQuoted)
				break
			}
			for _, ip := range p.Parts {
				switch ipp := ip.(type) {
				case *syntax.Lit:
					b.WriteString(decodeDblQuotedLit(ipp.Value))
				case *syntax.ParamExp:
					if v, ok := c.resolveParamForSubst(ipp, litOK); ok {
						b.WriteString(v)
					} else {
						s, ok2 := c.dqParamPlaceholder(ipp)
						if !ok2 {
							static = false
						}
						b.WriteString(s)
					}
				case *syntax.CmdSubst:
					static = false
					b.WriteString(c.dqSubstPlaceholder(ipp))
				default:
					static = false
					b.WriteString(cmdSubPlaceholderQuoted)
				}
			}
		case *syntax.ParamExp:
			if v, ok := c.resolveParamForSubst(p, litOK); ok {
				if openBracket {
					// SF-4: [prefix$v] can form a glob after expansion.
					static = false
				}
				b.WriteString(v)
			} else {
				static = false
				b.WriteString(c.unquotedParamPlaceholder(p))
			}
		case *syntax.CmdSubst:
			static = false
			b.WriteString(c.unquotedSubstPlaceholder(p))
		case *syntax.ArithmExp,
			*syntax.ProcSubst, *syntax.ExtGlob, *syntax.BraceExp:
			static = false
			b.WriteString(cmdSubPlaceholder)
		default:
			static = false
			b.WriteString(cmdSubPlaceholder)
		}
	}
	if braceSeen {
		static = false
		writeBraceExpansionMarkers(&b)
	}
	if !static {
		if b.Len() == 0 {
			return cmdSubPlaceholder, false
		}
		return b.String(), false
	}
	return b.String(), true
}

// simpleParamName returns the variable name of a simple $VAR / ${VAR}
// expansion (no operators, indexes or lengths), or "".
func simpleParamName(pe *syntax.ParamExp) (string, bool) {
	if pe == nil || pe.Param == nil {
		return "", false
	}
	if pe.Exp != nil || pe.Slice != nil || pe.Repl != nil || pe.Index != nil ||
		pe.Length || pe.Excl || pe.Names != 0 {
		return "", false
	}
	return pe.Param.Value, true
}

// unquotedParamPlaceholder classifies an unresolved unquoted $VAR word part.
// $HOME expands to a known absolute path (no field-split risk from OUR
// value) only when HOME was never written/overridden; $PATH keeps its
// self-reference sentinel; $$ is a decimal PID (split-safe); everything
// else is a plain splittable dynamic placeholder.
func (c *subCollector) unquotedParamPlaceholder(pe *syntax.ParamExp) string {
	name, simple := simpleParamName(pe)
	if !simple {
		return cmdSubPlaceholder
	}
	switch name {
	case "PATH":
		// The "*" give-up taint does NOT gate PATH: its grant channel is the
		// env-op screen (envAs), not a placeholder class — sentinelTrustVars
		// deliberately excludes it.
		if !c.taintedVars["PATH"] && !c.ssaBlocked["PATH"] {
			return envPathSelfPlaceholder
		}
		return cmdSubPlaceholder
	case "HOME":
		// R15-Oracle-M2: only an ACTUALLY inherited absolute HOME may
		// expand as static absolute path text — an empty/unset/relative
		// inherited value (childEnv copies existing keys verbatim; nothing
		// re-populates HOME) makes "$HOME" expand EMPTY, so the word must
		// fall back to the plain splittable placeholder instead of
		// fabricating a "/root" the shell never received.
		// R16-Oracle-M3: a legal absolute HOME is still not safe as UNQUOTED
		// static text when it carries whitespace or glob bytes — unquoted
		// expansion field-splits on whitespace and glob-expands on *?[ at
		// runtime, so the word is NEVER a single static operand then. The
		// static-literal grant is restricted to whitespace/glob-free values;
		// everything else degrades to an absolute-path-prefixed DYNAMIC
		// multi-word encoding (the dq-sub placeholder carries the
		// never-dash, never-'-'-start properties of the leading '/', the
		// plain cmdsub marks it non-split-safe, and the glob marker models
		// the potential pathname expansion), so isSingleWordOptionValue and
		// the zero-argument printf review can no longer treat HOME="/home/
		// Team Blue" as one operand slot.
		return c.unquotedHomePlaceholder()
	case "$":
		// R13-SF-2: digit-prefixed encoding — a decimal PID can never spell
		// "--" nor start with '-', so dynWordCanSpellDashDash must not
		// strip the word to a vacuous all-dash match.
		return "0" + cmdSubPlaceholderQuoted
	}
	return cmdSubPlaceholder
}

// unquotedHomePlaceholder is the HOME case of unquotedParamPlaceholder
// (extracted for the v6.2.2 R17 complexity budget). A whitespace/glob-free
// absolute inherited HOME encodes as literal path text only while BOTH the
// name is untainted and the IFS model is clean; whitespace/glob bytes — or
// R17-Oracle-M3: a polluted IFS — degrade it to the multi-word encoding
// (the abs-dq prefix is what a DOUBLE-quoted expansion could keep, the
// plain cmdsub marks the word splittable, and the glob marker blocks the
// single-word option-value exemption outright). Everything else is the
// conservative splittable placeholder.
func (c *subCollector) unquotedHomePlaceholder() string {
	if c.isTainted("HOME") {
		return cmdSubPlaceholder
	}
	h, ok := inheritedHomeDir()
	if !ok {
		return cmdSubPlaceholder
	}
	if strings.ContainsAny(h, " \t\n\r*?[") || !c.ifsClean() {
		// A whitespace/glob HOME splits or glob-expands regardless of IFS;
		// a polluted IFS (':'/',' are legal separators here) re-splits even
		// a clean value — e.g. HOME=/home/red:blue with IFS=: yields TWO
		// argv words, never one.
		return cmdSubPlaceholderAbsDq + cmdSubPlaceholder + cmdSubPlaceholderGlob
	}
	return h
}

// tmpdirPseudoRoot reports whether td names a pseudo filesystem root or a
// device tree mktemp can never create a subdirectory in (extracted for the
// v6.2.2 R17 complexity budget). /dev/shm — a real 1777 tmpfs the
// repository itself lists as an allowed scratch root — is the sole /dev
// exception (R17-Oracle-S2). R18-Oracle-S3: the comparison is strictly by
// path COMPONENT — /development/cache shares the /dev prefix but is an
// ordinary directory, so a blind HasPrefix must never match it.
func tmpdirPseudoRoot(td string) bool {
	return tmpdirPseudoCleanedRoot(filepath.Clean(td))
}

// tmpdirPseudoCleanedRoot is the component-exact pseudo-root predicate of
// tmpdirPseudoRoot applied to an already-cleaned path: /proc and /sys are
// pseudo roots outright, while under /dev only /dev/shm (and its children)
// escape — /dev/mqueue is a POSIX message queue filesystem, never a tmpfs.
func tmpdirPseudoCleanedRoot(clean string) bool {
	for _, pseudo := range []string{"/proc", "/sys"} {
		if clean == pseudo || strings.HasPrefix(clean, pseudo+"/") {
			return true
		}
	}
	if clean != "/dev" && !strings.HasPrefix(clean, "/dev/") {
		return false
	}
	return clean != "/dev/shm" && !strings.HasPrefix(clean, "/dev/shm/")
}

// writeUnquotedGlobTildeLit encodes one unquoted literal that carries a
// glob or tilde metacharacter (extracted for the v6.2.2 R17 complexity
// budget): the text plus its glob marker — and, for a word-leading tilde
// whose expansion HOME is KNOWN, the NUL-provenanced tilde marker.
// R18-Oracle-S5: the tilde word-count proof no longer collapses under a
// tainted HOME — bash's tilde expansion never field-splits, so the word
// stays exactly ONE argv word either way; only the concrete-path grant is
// what a tainted HOME loses, and that grant now lives exclusively in the
// unforgeable cmdSubPlaceholderTilde (R18-Oracle-M4). Returns false when
// the literal carries no glob/tilde byte at all. w/litIdx carry the whole
// word context for the R20-Oracle-S1 login-name prefix analysis.
func (c *subCollector) writeUnquotedGlobTildeLit(b *strings.Builder, w *syntax.Word, litIdx int, rawLit string, wordStart bool, openBracket *bool) bool {
	if !litHasUnquotedGlobOrTildeWord(w, litIdx, rawLit, wordStart, openBracket) {
		return false
	}
	b.WriteString(posixUnescapeLit(rawLit))
	// R19-Oracle-O1: the NUL tilde provenance marker precedes the glob
	// marker so the word tail of a HOME-proven tilde literal is a glob
	// byte group — writeBraceExpansionMarkers then mints the adjacent
	// glob+glob pair in the RAW byte stream, not only after stripping.
	if tildeHomeProvenWord(w, litIdx, rawLit, wordStart, c) {
		b.WriteString(cmdSubPlaceholderTilde)
	}
	b.WriteString(cmdSubPlaceholderGlob)
	return true
}

// tildeHomeProvenWord is tildeHomeProven with the word-level tilde shape
// (R20-Oracle-S1): the HOME provenance may attach only to a real word-start
// $HOME tilde expansion — tildeWordShape covers the lone `~` whole word
// and the unquoted `~/` prefix exactly like before, while login-name
// shapes and quoted-prefix verbatim literals never reach it.
func tildeHomeProvenWord(w *syntax.Word, litIdx int, rawLit string, wordStart bool, c *subCollector) bool {
	return wordStart && tildeWordShape(w, litIdx) == tildeShapeHome && !c.isTainted("HOME")
}

// ifsClean reports whether the unquoted expansion model may assume POSIX
// field splitting on the DEFAULT whitespace set (R17-Oracle-M3). The grant
// is false the moment the script wrote IFS (tainted — the value is
// unreadable), the process itself inherited a non-default exported IFS, or
// a static bind carrying separators other than the default " \t\n" (or the
// POSIX no-split empty string) is visible.
func (c *subCollector) ifsClean() bool {
	if c.isTainted("IFS") {
		return false
	}
	if c.staticVars != nil {
		if ifs, ok := c.staticVars["IFS"]; ok && ifs != " \t\n" && ifs != "" {
			return false
		}
	}
	if ifs, ok := os.LookupEnv("IFS"); ok && ifs != " \t\n" && ifs != "" {
		return false
	}
	return true
}

// dqParamPlaceholder classifies an unresolved $VAR inside double quotes.
// (text, true) means the part emitted literal text that stays static;
// (placeholder, false) marks the word dynamic.
func (c *subCollector) dqParamPlaceholder(pe *syntax.ParamExp) (string, bool) {
	// A @-splitting expansion must NOT keep the split-safe dq placeholder:
	// "$@"/"${arr[@]}"/"${!prefix@}"/"${x:-$@}" all expand to one argv word
	// per element even inside double quotes, so emit the conservative
	// cmdSubPlaceholder instead (isSplitSafeDynamicWord -> false).
	if paramExpSplitsInDblQuotes(pe) {
		return cmdSubPlaceholder, false
	}
	name, simple := simpleParamName(pe)
	if !simple {
		return cmdSubPlaceholderQuoted, false
	}
	switch name {
	case "PATH":
		if !c.taintedVars["PATH"] && !c.ssaBlocked["PATH"] {
			return envPathSelfPlaceholder, false
		}
	case "HOME":
		// R15-Oracle-M2: same inherited-HOME gate as the unquoted encoder —
		// HOME="" in the parent environment expands EMPTY inside double
		// quotes too, so it must NOT keep the ("/root", true) static grant
		// (a glued tail can collapse and "--"+"$HOME" can spell the
		// terminator). The plain quoted placeholder is split-safe but
		// empty-able, which is exactly what the consumer predicates model.
		if !c.isTainted("HOME") {
			if h, ok := inheritedHomeDir(); ok {
				return h, true // static absolute path text
			}
		}
	case "PWD":
		// PWD is a bash-special variable the shell itself maintains: a
		// running bash ALWAYS re-populates it to a non-empty absolute path
		// (cd/pushd rewrite it, and bash re-creates it when unset), so the
		// absolute-dir placeholder is sound as long as the script never
		// wrote it. OLDPWD is deliberately NOT granted here (R14-Oracle-M2):
		// the child environment only copies existing keys — when the parent
		// process never exported a non-empty OLDPWD (no prior cd), the
		// expansion is the EMPTY string, so a glued tail can collapse and
		// "--"+"$OLDPWD" can spell the terminator. A script-level static
		// bind (OLDPWD=/abs) already resolved upstream in
		// resolveParamForSubst, and any script write taints the name anyway.
		if !c.isTainted(name) {
			return cmdSubPlaceholderAbsDq, false // guaranteed to start with /
		}
	case "$":
		// R13-SF-2: digit-prefixed encoding — a decimal PID can never spell
		// "--" nor start with '-' (see unquotedParamPlaceholder).
		return "0" + cmdSubPlaceholderQuoted, false
	}
	return cmdSubPlaceholderQuoted, false
}

// dqSubstPlaceholder classifies a $(...) inside double quotes: `$(pwd)` and
// a bare `$(mktemp -d)` (with untainted TMPDIR) are guaranteed to produce a
// path starting with /, so they carry the absolute-dir dq placeholder — but
// only while the script cannot have changed directory first (c.hasCd /
// preScanVarMutations PWD/OLDPWD taint keep $(pwd) fully dynamic then).
func (c *subCollector) dqSubstPlaceholder(cs *syntax.CmdSubst) string {
	if cs != nil {
		// Both backquote and $(...) forms of `pwd` / `mktemp -d` produce an
		// absolute path (backquotes cannot smuggle a second word in dq).
		if isPwdCallStmts(cs.Stmts) {
			if !c.hasCd && !c.pwdSwitchTainted() {
				return cmdSubPlaceholderAbsDq
			}
			return cmdSubPlaceholderQuoted
		}
		// R15-Oracle-M2: a spelling match plus untainted TMPDIR does NOT
		// prove the mktemp child succeeded — when the inherited TMPDIR
		// points at a non-directory (or is a relative/NUL-carrying path),
		// GNU mktemp fails, writes its diagnostic to stderr and stdout is
		// the EMPTY string inside the double quotes. The absolute-dir grant
		// therefore additionally requires the inherited TMPDIR to be a
		// validated absolute existing directory; every failure shape falls
		// back to the ordinary quoted placeholder.
		if c.mktempGrantOK() && isMktempDashDCallStmts(cs.Stmts) {
			return cmdSubPlaceholderAbsDq
		}
	}
	return cmdSubPlaceholderQuoted
}

// unquotedSubstPlaceholder keeps unquoted $(...) fully dynamic — its output
// field-splits on IFS at runtime, so even a bare $(pwd) can never be
// trusted as a single static directory operand (R3 MF-1): only the
// double-quoted `"$(pwd)"` dqSubstPlaceholder and the assignment-binding
// staticAssignVal grant the safe cwd bind.
func (c *subCollector) unquotedSubstPlaceholder(cs *syntax.CmdSubst) string {
	return cmdSubPlaceholder
}

// safeHomeDir returns the process home as a static absolute path for
// NON-shell-variable consumers (configuration search paths, default
// config locations). Falls back to "/root" when HOME is unset/relative
// — matching the deployment user. R15-Oracle-M2: shell "$HOME"
// EXPANSION encoding must use inheritedHomeDir instead — a config
// fallback directory is not the value the shell actually received.
func safeHomeDir() string {
	if h := os.Getenv("HOME"); h != "" && strings.HasPrefix(h, "/") && !strings.Contains(h, "\x00") {
		return h
	}
	return "/root"
}

// inheritedHomeDir reports the shell "$HOME" expansion value exactly as
// the child process inherits it: an empty/unset/relative/NUL-carrying
// HOME means the expansion is empty or unsafe, so ("", false) is
// returned instead of fabricating a fallback home the shell never
// received (R15-Oracle-M2). Only a non-empty absolute NUL-free inherited
// value is granted the static-path encoding.
func inheritedHomeDir() (string, bool) {
	if h := os.Getenv("HOME"); h != "" && strings.HasPrefix(h, "/") && !strings.Contains(h, "\x00") {
		return h, true
	}
	return "", false
}

// inheritedTmpdirValid reports whether the TMPDIR the mktemp child would
// inherit names an existing absolute directory — the only shape under
// which `$(mktemp -d)` is guaranteed to SUCCEED and therefore print a
// non-empty absolute path (R15-Oracle-M2). An unset/empty TMPDIR makes
// mktemp use its built-in "/tmp" default, which is valid; a relative,
// NUL-carrying, missing or non-directory value (TMPDIR=/dev/null) makes
// mktemp fail with EMPTY stdout, so the grant must not apply.
func inheritedTmpdirValid() bool {
	td := os.Getenv("TMPDIR")
	if td == "" {
		return true // mktemp falls back to /tmp
	}
	if !strings.HasPrefix(td, "/") || strings.Contains(td, "\x00") {
		return false
	}
	// R16-Oracle-M1: a directory entry is not enough — pseudo filesystems
	// like /proc are real directories (mode 0555) on which mktemp can never
	// create a subdirectory, so TMPDIR=/proc must fail closed exactly like
	// the non-directory TMPDIR=/dev/null. The perm-bit check plus a real
	// write/search access probe together approximate "a subdirectory could
	// be created here"; both must pass.
	// R17-Oracle-S2: /dev is NOT uniformly a pseudo root — /dev/shm is a
	// real tmpfs (mode 1777) the repository itself lists as an allowed
	// scratch root, so TMPDIR=/dev/shm[/...] keeps the validity proof
	// while /dev/null (a device NODE, not even a directory — already
	// rejected by the Stat walk below) and /dev/foo stay out.
	if tmpdirPseudoRoot(td) {
		return false
	}
	// R18-Oracle-M5: the lexical check above judges the SPELLING, but the
	// Stat/Access probes below act on the RESOLVED object — `/dev/shm/..`
	// spells the tmpfs exception yet resolves to /dev, and
	// `/dev/shm/../mqueue` resolves to the mqueue pseudo filesystem (never
	// a tmpfs a mktemp child could create a directory in). The symlink
	// resolution must pass AND its result must pass the same component-exact
	// pseudo-root review before any metadata proof can stand.
	resolved, err := filepath.EvalSymlinks(td)
	if err != nil || tmpdirPseudoRoot(resolved) {
		return false
	}
	return tmpdirChildCreatable(td)
}

// tmpdirChildCreatable is the Stat/perm/access tail of
// inheritedTmpdirValid (extracted for the v6.2.2 R18 complexity budget):
// the directory entry must exist as a directory, carry a write permission
// bit and survive a real write/search access probe — together approximating
// "a subdirectory could be created here".
func tmpdirChildCreatable(td string) bool {
	fi, err := os.Stat(td)
	if err != nil || !fi.IsDir() {
		return false
	}
	if fi.Mode().Perm()&0222 == 0 {
		return false
	}
	return unix.Access(td, unix.W_OK|unix.X_OK) == nil
}

func callHasProcSubst(call *syntax.CallExpr) bool {
	found := false
	syntax.Walk(call, func(n syntax.Node) bool {
		if n == nil || found {
			return false
		}
		if _, ok := n.(*syntax.ProcSubst); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// isQuotedHeredocDelim reports whether the heredoc delimiter suppresses expansion.
func isQuotedHeredocDelim(w *syntax.Word) bool {
	if w == nil || len(w.Parts) != 1 {
		return false
	}
	switch p := w.Parts[0].(type) {
	case *syntax.SglQuoted, *syntax.DblQuoted:
		return true
	case *syntax.Lit:
		// Any escaped delimiter byte suppresses expansion, including
		// <<\EOF and <<E\OF. heredocDelimOK rejects escaped newlines.
		return strings.Contains(p.Value, "\\")
	default:
		return false
	}
}

// withLhsUntainted evaluates fn with `name` temporarily removed from the
// taint sets: the RHS of `PATH=$PATH:x` must still read the OLD PATH
// value (POSIX expands the RHS before the assignment), so a whole-file
// mutation pre-scan that already counts this assignment must not
// contaminate the word conversion.
func (c *subCollector) withLhsUntainted(name string, fn func()) {
	saveT, saveS := c.taintedVars[name], c.ssaBlocked[name]
	delete(c.taintedVars, name)
	delete(c.ssaBlocked, name)
	fn()
	c.taintedVars[name], c.ssaBlocked[name] = saveT, saveS
}

// assignToPrefix formats an Assign as NAME=value (or NAME=__ctx_cmdsub__),
// using the collector's taint-aware word conversion so $PATH/$HOME sentinels
// and staticVars binds apply to prefix assignments exactly like env args.
func (c *subCollector) assignToPrefix(a *syntax.Assign) string {
	name := ""
	if a.Name != nil {
		name = a.Name.Value
	}
	if a.Naked {
		return name
	}
	if a.Value == nil {
		if a.Array != nil {
			return name + "=" + cmdSubPlaceholder
		}
		return name + "="
	}
	var s string
	var ok bool
	c.withLhsUntainted(name, func() { s, ok = c.wordToArg(a.Value) })
	if !ok && !strings.Contains(s, envPathSelfPlaceholder) && !strings.HasPrefix(s, cmdSubPlaceholderAbsDq) {
		return name + "=" + cmdSubPlaceholder
	}
	return name + "=" + s
}
