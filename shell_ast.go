package main

import (
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

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
	pipedStdin   bool
	heredocText  []heredocBody
	redirectFile string
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
	if hit := roWalkFile(code, file, &out, false); hit != "" {
		return nil, hit
	}
	return out, ""
}

func roWalkFile(code string, f *syntax.File, out *[]roSegment, pipeIn bool) string {
	for i, st := range f.Stmts {
		if hit := roWalkStmt(code, st, out, pipeIn && i == 0); hit != "" {
			return hit
		}
	}
	return ""
}

func roWalkStmt(code string, st *syntax.Stmt, out *[]roSegment, pipeIn bool) string {
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
		return roWalkCall(code, st, cmd, out, pipeIn)
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.Pipe, syntax.PipeAll:
			if hit := roWalkStmt(code, cmd.X, out, pipeIn); hit != "" {
				return hit
			}
			return roWalkStmt(code, cmd.Y, out, true)
		case syntax.AndStmt, syntax.OrStmt:
			if hit := roWalkStmt(code, cmd.X, out, pipeIn); hit != "" {
				return hit
			}
			return roWalkStmt(code, cmd.Y, out, false)
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

func roWalkCall(code string, st *syntax.Stmt, call *syntax.CallExpr, out *[]roSegment, pipeIn bool) string {
	if len(call.Assigns) > 0 {
		return "env assign forbidden Hint: 禁止 VAR=val 前缀；需要环境变量时只用 LANG/LC_ALL/TZ 经 ctx_run env"
	}
	if len(call.Args) < 1 {
		return "empty command"
	}
	argv := make([]string, 0, len(call.Args))
	for i, w := range call.Args {
		s, hit := roWord(code, w, i == 0)
		if hit != "" {
			return hit
		}
		argv = append(argv, s)
	}
	seg := roSegment{argv: argv, pipedStdin: pipeIn}
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
func preScanVarMutations(f *syntax.File) (writeCount map[string]int, allTainted bool) {
	writeCount = map[string]int{}
	if f == nil {
		return writeCount, false
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
				h, ok := wordToArg(args[0])
				if !ok || isDynamicArg(h) {
					// A dynamic word is not literally command/builtin. When it
					// appears AFTER a real command/builtin it could still be
					// `read`/any mutator the wrapper is hiding → taint all;
					// as the first word it is just a dynamic head, peel done.
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
					os_, ook := wordToArg(w)
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
					a, aok := wordToArg(args[0])
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
			head, _ := wordToArg(args[0])
			base := head
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			switch base {
			case "cd", "chdir":
				// cd implicitly rewrites PWD/OLDPWD in the running shell.
				inc("PWD")
				inc("OLDPWD")
			case "getopts":
				// getopts always mutates OPTIND and may write OPTARG.
				inc("OPTIND")
				inc("OPTARG")
				// getopts OPTSTRING NAME [args...]: the first operand is the
				// optstring (may begin with ':' or '-'), the second is the
				// target variable name.
				opIdx := 0
				for j := 1; j < len(args); j++ {
					s, ok := wordToArg(args[j])
					if !ok || isDynamicArg(s) {
						allTainted = true
						return false
					}
					if s == "--" {
						if j+1 < len(args) {
							opIdx = j + 1
						}
						break
					}
					opIdx = j
					break
				}
				if opIdx > 0 && opIdx+1 < len(args) {
					s, ok := wordToArg(args[opIdx+1])
					if !ok || isDynamicArg(s) {
						allTainted = true
						return false
					}
					inc(s)
				}
			case "read":
				// Bare read writes REPLY; -a ARRAY writes the array.
				inc("REPLY")
				// read option letters: boolean r s; value-carrying d n N p t u a
				// (a separate argv when last in its cluster). -a ARRAY is itself
				// a write target. R13: -s is a BOOLEAN (silent echo) — treating
				// it as value-carrying hides the real write target (`read -s x`).
				sawDashDash := false
				j := 1
				for j < len(args) {
					s, ok := wordToArg(args[j])
					if !ok || isDynamicArg(s) {
						allTainted = true
						return false
					}
					if s == "--" && !sawDashDash {
						sawDashDash = true
						j++
						continue
					}
					if !sawDashDash && strings.HasPrefix(s, "-") && len(s) > 1 {
						endLetter := byte(0)
						for k := 1; k < len(s); k++ {
							switch s[k] {
							case 'r', 's':
								continue
							case 'a':
								// -a ARRAY: the array name is a write target.
								if k+1 < len(s) {
									inc(s[k+1:])
								} else if j+1 < len(args) {
									an, aok := wordToArg(args[j+1])
									if !aok || isDynamicArg(an) {
										allTainted = true
										return false
									}
									inc(an)
									j++
								}
								endLetter = 'a'
								k = len(s)
							case 'd', 'n', 'N', 'p', 't', 'u':
								endLetter = s[k]
								k = len(s)
							default:
								// Unknown option letter: be conservative.
								allTainted = true
								return false
							}
						}
						if endLetter != 0 && len(s) > 1 && s[len(s)-1] == endLetter &&
							strings.IndexByte("dnNptu", endLetter) >= 0 && j+1 < len(args) {
							j++ // value operand consumed
						}
						j++
						continue
					}
					if s != "" {
						inc(s)
					}
					j++
				}
			case "unset", "export", "readonly", "declare", "typeset", "local":
				for _, w := range args[1:] {
					s, ok := wordToArg(w)
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
				// printf -v VAR ...
				for i := 1; i+1 < len(args); i++ {
					s, ok := wordToArg(args[i])
					if !ok {
						continue
					}
					if s == "-v" {
						vn, vok := wordToArg(args[i+1])
						if !vok {
							allTainted = true
							return false
						}
						inc(vn)
						i++
					}
				}
			}
		}
		return true
	})
	return writeCount, allTainted
}

// parseSubagentShellAST parses code into shellSegments for subagent guards.
// ok=false means fail-closed (caller treats as depthExceeded). envTaint
// carries environment-override knowledge from an outer envAs (HOME=/x sh -c,
// env -i sh -c, env -u PWD ...): every named variable's expansion is treated
// as untrusted inside this script, degrading the PATH/HOME/absolute-dir
// placeholder grants to plain dynamic placeholders.
func parseSubagentShellAST(code string, depth int, pipeIn bool, useBashVariant bool) ([]shellSegment, bool) {
	return parseSubagentShellASTEnv(code, depth, pipeIn, useBashVariant, nil)
}

// parseSubagentShellASTEnv is parseSubagentShellAST plus an envTaint set
// for the env/ssh AST descent (SH11 F3/Q5).
func parseSubagentShellASTEnv(code string, depth int, pipeIn bool, useBashVariant bool, envTaint map[string]bool) ([]shellSegment, bool) {
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

	col := &subCollector{code: code, depth: depth, staticVars: map[string]string{}, enumVars: map[string]string{}, taintedVars: map[string]bool{}, enumCmdWords: map[string][]string{}, allowBind: true}
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
	if hit := checkCommentsAndContinuations(code, primary, false); hit != "" {
		return []shellSegment{{parseErr: hit}}, false
	}
	if !col.failClosedFile(primary) {
		return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
	}
	if !useBashVariant && bashFile != nil {
		if hit := checkCommentsAndContinuations(code, bashFile, false); hit != "" {
			return []shellSegment{{parseErr: hit}}, false
		}
		if !col.failClosedFile(bashFile) {
			return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
		}
	}
	if useBashVariant && posixFile != nil {
		if hit := checkCommentsAndContinuations(code, posixFile, false); hit != "" {
			return []shellSegment{{parseErr: hit}}, false
		}
		if !col.failClosedFile(posixFile) {
			return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
		}
	}

	col.ssaBlocked = map[string]bool{}
	writes, allTainted := preScanVarMutations(primary)
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
	if useBashVariant && posixFile != nil {
		pre := len(col.segs)
		col.walkStmts(posixFile.Stmts, stdinFeed{piped: pipeIn})
		if col.rejected {
			return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
		}
		col.segs = dedupeSegTail(col.segs, pre)
	} else if !useBashVariant && bashFile != nil {
		pre := len(col.segs)
		col.walkStmts(bashFile.Stmts, stdinFeed{piped: pipeIn})
		if col.rejected {
			return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
		}
		col.segs = dedupeSegTail(col.segs, pre)
	}
	return col.segs, true
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
				if envHookVars[wi.Name.Value] || guardTaintVars[wi.Name.Value] {
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
		return envHookVars[name] || guardTaintVars[name]
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
	return envHookVars[name] || guardTaintVars[name]
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
	prevBind := c.allowBind
	if st.Background {
		c.allowBind = false
	}
	defer func() { c.allowBind = prevBind }()
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
		seg := shellSegment{pipedStdin: feed.piped, backgrounded: st.Background}
		c.applyRedirs(&seg, st.Redirs, feed)
		if len(seg.argv) > 0 || seg.redirectFile != "" || len(seg.heredocText) > 0 || seg.hereString != "" || seg.depthExceeded {
			c.segs = append(c.segs, seg)
		}
		return
	}
	switch cmd := st.Cmd.(type) {
	case *syntax.CallExpr:
		c.emitCall(st, cmd, feed)
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.Pipe, syntax.PipeAll:
			prevBind := c.allowBind
			c.allowBind = false // no static head-bind across/inside pipelines
			c.walkStmt(cmd.X, feed)
			// Pipe right: fd0 becomes the upstream stream, but the rest of
			// the descriptor table is inherited — { cat | sh 0<&9; } 9<&0
			// still resolves fd9 to the pipe.
			c.walkStmt(cmd.Y, stdinFeed{piped: true, fds: feed.fds})
			c.allowBind = prevBind
		case syntax.AndStmt, syntax.OrStmt:
			c.walkStmt(cmd.X, feed)
			// SH11 MF-4.1: the right side is a conditional short-circuit
			// branch — its assignments are NOT guaranteed to run, so they
			// must never become staticVars binds. Its stdin is the SAME
			// feed the left side saw — `true && sh` fed by a pipe runs the
			// piped bytes as sh's program (R13), and { true && sh 0<&9; }
			// 9<&0 resolves fd9 through the inherited descriptor table.
			prevBind := c.allowBind
			c.allowBind = false
			c.walkStmt(cmd.Y, feed)
			c.allowBind = prevBind
		default:
			c.reject()
		}
	case *syntax.Subshell:
		prevBind := c.allowBind
		c.allowBind = false
		innerFeed := c.stmtFeed(st, feed)
		c.walkStmtsAll(cmd.Stmts, innerFeed)
		c.allowBind = prevBind
	case *syntax.Block:
		prevBind := c.allowBind
		c.allowBind = false
		innerFeed := c.stmtFeed(st, feed)
		c.walkStmtsAll(cmd.Stmts, innerFeed)
		c.allowBind = prevBind
	case *syntax.IfClause:
		prevBind := c.allowBind
		c.allowBind = false
		innerFeed := c.stmtFeed(st, feed)
		for ic := cmd; ic != nil; ic = ic.Else {
			c.walkStmtsAll(ic.Cond, innerFeed)
			c.walkStmtsAll(ic.Then, innerFeed)
		}
		c.allowBind = prevBind
	case *syntax.WhileClause:
		prevBind := c.allowBind
		c.allowBind = false
		innerFeed := c.stmtFeed(st, feed)
		c.walkStmtsAll(cmd.Cond, innerFeed)
		c.walkStmtsAll(cmd.Do, innerFeed)
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
				enumDone = c.forEnumSubst(loopName, wi.Items, cmd.Do, innerFeed)
			}
		}
		if !enumDone {
			c.walkStmtsAll(cmd.Do, innerFeed)
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
			c.walkStmtsAll(item.Stmts, innerFeed)
		}
		c.allowBind = prevBind
	case *syntax.FuncDecl:
		prevBind := c.allowBind
		c.allowBind = false
		prevUnvetted := c.fdUnvetted
		c.fdUnvetted = true
		if cmd.Body != nil {
			// The body's stdin is the stdin of whatever invocation runs
			// it — unknown at definition, so conservatively fed. The fd
			// table is inherited from the CALL, which is likewise
			// unprovable, so every descriptor the declaration itself does
			// not bind (st.Redirs replayed at call time, plus the table an
			// enclosing compound left behind) fails closed: a bare
			// `f() { sh 0<&9; }; f` dup gets no file exemption (R17 MF-2).
			inner := c.stmtFeed(st, feed)
			inner.piped = true
			if fd0, seen := inner.fds["0"]; seen && !fd0.piped {
				fd0.piped = true
				inner.fds["0"] = fd0
			}
			c.walkStmt(cmd.Body, inner)
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
		if cmd.Stmt != nil {
			c.walkStmt(cmd.Stmt, stdinFeed{})
		}
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
			val, stOk := c.staticAssignVal(a.Value)
			c.noteStaticAssign(a.Name.Value, val, stOk)
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
	seg := shellSegment{argv: argv, pipedStdin: feed.piped, backgrounded: st.Background}
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
	// SH11 F9: a backgrounded statement runs in a subshell — its assigns
	// never bind in the parent shell (walkStmt already closed allowBind on
	// the whole subtree).
	for _, a := range call.Assigns {
		argv = append(argv, c.assignToPrefix(a))
		if a.Name != nil && !a.Naked {
			if len(call.Args) == 0 {
				// Pure assignment statement — eligible for staticVars.
				val, stOk := c.staticAssignVal(a.Value)
				c.noteStaticAssign(a.Name.Value, val, stOk)
			} else {
				// Prefix env (FOO=bar cmd) does not bind in the current shell.
				c.taintVar(a.Name.Value)
			}
		}
	}
	for i, w := range call.Args {
		// Command head: for-loop enum binds may expand the head (W-Fix-6
		// abs-path single words; W11-5 static multi-word command strings).
		if i == 0 {
			if !c.isTainted("IFS") {
				if name, single := singleSimpleParamExp(w); single {
					if words, ok := c.enumCmdWords[name]; ok && len(words) > 0 {
						argv = append(argv, words...)
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
					continue
				}
				saved := c.enumVars
				c.enumVars = nil
				s, _ = c.wordToArg(w)
				c.enumVars = saved
				argv = append(argv, s)
				continue
			}
		}
		s, _ := c.wordToArg(w)
		argv = append(argv, s)
	}
	// POSIX parses `export NAME=VAL` as CallExpr (bash uses DeclClause).
	c.noteDeclCallBinds(argv)

	seg := shellSegment{
		argv:         argv,
		pipedStdin:   feed.piped,
		backgrounded: st.Background,
		processSubst: callHasProcSubst(call),
	}
	c.applyRedirs(&seg, st.Redirs, feed)
	if len(seg.argv) > 0 || seg.redirectFile != "" || len(seg.heredocText) > 0 ||
		seg.hereString != "" || seg.processSubst || seg.depthExceeded {
		c.segs = append(c.segs, seg)
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
			// fd duplication: blocking only when target is not a bare fd
			if r.Word != nil {
				s, ok := wordToArg(r.Word)
				if !ok {
					seg.redirectFile = dynamicRedirectTarget
				} else if s != "-" && !allDigits(s) {
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
			n = r.N.Value
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
			// as redirectFile) which is file for origin purposes.
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
			case allDigits(s):
				if o, seen := origins[s]; seen {
					origins[n] = o
				} else if c.fdUnvetted {
					// Inside a function body the call-site descriptor set
					// is unknown: an unproven fd fails closed as tainted.
					origins[n] = stdinFeed{piped: true}
				} else {
					origins[n] = stdinFeed{file: true}
				}
			default:
				origins[n] = stdinFeed{file: true}
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
func (c *subCollector) newSub() *subCollector {
	return &subCollector{
		code:         c.code,
		depth:        c.depth + 1,
		staticVars:   cloneStringMap(c.staticVars),
		litVars:      cloneStringMap(c.litVars),
		enumVars:     cloneStringMap(c.enumVars),
		enumCmdWords: cloneStringsMap(c.enumCmdWords),
		taintedVars:  cloneBoolMap(c.taintedVars),
		ssaBlocked:   cloneBoolMap(c.ssaBlocked),
		allowBind:    false,
		fdUnvetted:   c.fdUnvetted,
	}
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
	if !c.allowBind {
		c.taintVar(name)
		return
	}
	if c.isTainted(name) {
		return
	}
	if !static || !isSafeIdentOrRelPath(val) {
		c.taintVar(name)
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
				if wd, err := os.Getwd(); err == nil {
					return wd, true
				}
			}
			if !c.isTainted("TMPDIR") && isMktempDashDCallStmts(cs.Stmts) {
				return mktempDirPlaceholder, true
			}
		}
	}
	if w == nil {
		return "", false
	}
	return c.wordToArg(w)
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

func litHasUnquotedGlobOrTilde(rawLit string, isWordStart bool, openBracket *bool) bool {
	for i := 0; i < len(rawLit); i++ {
		ch := rawLit[i]
		if ch == '\\' {
			i++ // escaped byte is literal
			continue
		}
		if isWordStart && i == 0 && ch == '~' {
			return true
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
	if w == nil || len(w.Parts) == 0 {
		return "", false
	}
	var b strings.Builder
	static := true
	openBracket := false
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if litHasUnquotedGlobOrTilde(p.Value, i == 0 && b.Len() == 0, &openBracket) {
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
			for _, ip := range p.Parts {
				lit, ok := ip.(*syntax.Lit)
				if !ok {
					static = false
					b.WriteString(cmdSubPlaceholderQuoted)
					continue
				}
				b.WriteString(decodeDblQuotedLit(lit.Value))
			}
		case *syntax.ParamExp:
			// Context-free: only $$ (a decimal PID) is known split-safe.
			static = false
			if p.Param != nil && p.Param.Value == "$" && p.Exp == nil {
				b.WriteString(cmdSubPlaceholderQuoted)
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
	if !static {
		if b.Len() == 0 {
			return cmdSubPlaceholder, false
		}
		return b.String(), false
	}
	return b.String(), true
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
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if litHasUnquotedGlobOrTilde(p.Value, i == 0 && b.Len() == 0, &openBracket) {
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
		if !c.isTainted("HOME") {
			return safeHomeDir()
		}
		return cmdSubPlaceholder
	case "$":
		return cmdSubPlaceholderQuoted // PID: digits, no field-split
	}
	return cmdSubPlaceholder
}

// dqParamPlaceholder classifies an unresolved $VAR inside double quotes.
// (text, true) means the part emitted literal text that stays static;
// (placeholder, false) marks the word dynamic.
func (c *subCollector) dqParamPlaceholder(pe *syntax.ParamExp) (string, bool) {
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
		if !c.isTainted("HOME") {
			return safeHomeDir(), true // static absolute path text
		}
	case "PWD", "OLDPWD":
		if !c.isTainted(name) {
			return cmdSubPlaceholderAbsDq, false // guaranteed to start with /
		}
	case "$":
		return cmdSubPlaceholderQuoted, false
	}
	return cmdSubPlaceholderQuoted, false
}

// dqSubstPlaceholder classifies a $(...) inside double quotes: `$(pwd)` and
// a bare `$(mktemp -d)` (with untainted TMPDIR) are guaranteed to produce a
// path starting with /, so they carry the absolute-dir dq placeholder.
func (c *subCollector) dqSubstPlaceholder(cs *syntax.CmdSubst) string {
	if cs != nil {
		// Both backquote and $(...) forms of `pwd` / `mktemp -d` produce an
		// absolute path (backquotes cannot smuggle a second word in dq).
		if isPwdCallStmts(cs.Stmts) {
			return cmdSubPlaceholderAbsDq
		}
		if !c.isTainted("TMPDIR") && isMktempDashDCallStmts(cs.Stmts) {
			return cmdSubPlaceholderAbsDq
		}
	}
	return cmdSubPlaceholderQuoted
}

// unquotedSubstPlaceholder keeps unquoted $(...) fully dynamic — its output
// field-splits on IFS. A bare $(pwd) emits the dq-abs placeholder only when
// IFS is untainted AND the result cannot begin with '-': pwd's output
// begins with / by definition, but word-splitting could still break it, so
// unquoted $(pwd) stays plain dynamic (conservative).
func (c *subCollector) unquotedSubstPlaceholder(cs *syntax.CmdSubst) string {
	return cmdSubPlaceholder
}

// safeHomeDir returns the process home as a static absolute path used for
// $HOME expansion when the script never reassigned it. Falls back to "/root"
// when HOME is unset/relative — matching the deployment user.
func safeHomeDir() string {
	if h := os.Getenv("HOME"); h != "" && strings.HasPrefix(h, "/") && !strings.Contains(h, "\x00") {
		return h
	}
	return "/root"
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
