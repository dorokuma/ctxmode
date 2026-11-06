package main

import (
	"fmt"
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
		case ' ', '\t', '\n', ';', '|', '&', '(':
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
		// $ then \\\n (G1 / MF-1)
		if i > 0 && code[i-1] == '$' {
			// ensure $ itself is unescaped
			if i < 2 || !hasOddTrailingBackslash(code[:i-1]) {
				return "ambiguous line continuation after $"
			}
		}
		// Forward boundary: must follow whitespace/separator (token-external).
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
			head, _ := wordToArg(x.Args[0])
			base := head
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			switch base {
			case "unset", "read", "export", "readonly", "declare", "typeset", "local", "getopts":
				for _, w := range x.Args[1:] {
					s, ok := wordToArg(w)
					if !ok {
						allTainted = true
						return false
					}
					if base == "unset" || base == "read" || base == "getopts" {
						// bare names / optstring+name
						if base == "getopts" {
							continue // handled loosely: taint following name words
						}
						name := s
						if eq := strings.IndexByte(s, '='); eq > 0 && (base == "export" || base == "readonly" || base == "declare" || base == "typeset" || base == "local") {
							name = s[:eq]
						}
						if name != "" && !strings.HasPrefix(name, "-") {
							inc(name)
						}
					} else {
						// export/readonly/declare/typeset/local NAME[=VAL]
						name := s
						if eq := strings.IndexByte(s, '='); eq >= 0 {
							name = s[:eq]
						}
						if name != "" && !strings.HasPrefix(name, "-") {
							inc(name)
						}
					}
				}
			case "printf":
				// printf -v VAR ...
				for i := 1; i+1 < len(x.Args); i++ {
					s, ok := wordToArg(x.Args[i])
					if !ok {
						continue
					}
					if s == "-v" {
						vn, vok := wordToArg(x.Args[i+1])
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
// ok=false means fail-closed (caller treats as depthExceeded).
func parseSubagentShellAST(code string, depth int, pipeIn bool, useBashVariant bool) ([]shellSegment, bool) {
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

	col := &subCollector{code: code, depth: depth, staticVars: map[string]string{}, enumVars: map[string]string{}, taintedVars: map[string]bool{}, allowBind: depth == 0}
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
	} else {
		for name, n := range writes {
			if n > 1 {
				col.taintedVars[name] = true
				col.ssaBlocked[name] = true
			}
		}
	}
	col.walkStmts(primary.Stmts, pipeIn)
	if col.rejected {
		return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
	}
	if useBashVariant && posixFile != nil {
		pre := len(col.segs)
		col.walkStmts(posixFile.Stmts, pipeIn)
		if col.rejected {
			return []shellSegment{{parseErr: "shell AST fail-closed"}}, false
		}
		col.segs = dedupeSegTail(col.segs, pre)
	} else if !useBashVariant && bashFile != nil {
		pre := len(col.segs)
		col.walkStmts(bashFile.Stmts, pipeIn)
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
	code        string
	depth       int
	segs        []shellSegment
	rejected    bool
	staticVars  map[string]string // head-eligible abs-path binds (R-Allow-2)
	enumVars    map[string]string // for-loop enum temporary binds (payload subst only)
	taintedVars map[string]bool
	ssaBlocked  map[string]bool // G3: writeCount>1 from preScan
	allowBind   bool            // top-level sequential stmts only (R-Allow-2)
}

func (c *subCollector) reject() {
	c.rejected = true
}

func (c *subCollector) failClosedFile(f *syntax.File) bool {
	ok := true
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
			// G1-3: mvdan left an expand residue inside a Lit
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
		case *syntax.SglQuoted, *syntax.DblQuoted:
			ambig = true
			return false
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
	for i := 0; i < len(raw); i++ {
		abs := lo + i
		inCS := false
		for _, sp := range csSpans {
			if abs >= sp[0] && abs < sp[1] {
				inCS = true
				break
			}
		}
		if inCS {
			continue
		}
		switch raw[i] {
		case '\'', '"', '\\':
			return true
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
	if strings.ContainsAny(src, "\\\n") {
		return false
	}
	if len(r.Word.Parts) != 1 {
		return false
	}
	switch p := r.Word.Parts[0].(type) {
	case *syntax.Lit:
		return isHeredocDelimName(p.Value)
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
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_'
		if !ok {
			return false
		}
	}
	return true
}

func (c *subCollector) walkStmts(stmts []*syntax.Stmt, pipeIn bool) {
	for i, st := range stmts {
		if c.rejected {
			return
		}
		c.walkStmt(st, pipeIn && i == 0)
	}
}

func (c *subCollector) walkStmt(st *syntax.Stmt, pipeIn bool) {
	if st == nil || c.rejected {
		return
	}
	if st.Cmd == nil {
		// bare redirects — still record if they write; unquoted heredoc bodies
		// can contain $(...) that dash expands (must emit nested CallExprs).
		for _, r := range st.Redirs {
			if r.Word != nil {
				c.emitNestedFromWord(r.Word)
			}
			if r.Hdoc != nil && !isQuotedHeredocDelim(r.Word) {
				c.emitNestedFromWord(r.Hdoc)
			}
		}
		seg := shellSegment{pipedStdin: pipeIn, backgrounded: st.Background}
		c.applyRedirs(&seg, st.Redirs)
		if len(seg.argv) > 0 || seg.redirectFile != "" || len(seg.heredocText) > 0 || seg.hereString != "" || seg.depthExceeded {
			c.segs = append(c.segs, seg)
		}
		return
	}
	switch cmd := st.Cmd.(type) {
	case *syntax.CallExpr:
		c.emitCall(st, cmd, pipeIn)
	case *syntax.BinaryCmd:
		switch cmd.Op {
		case syntax.Pipe, syntax.PipeAll:
			prevBind := c.allowBind
			c.allowBind = false // no static head-bind across/inside pipelines
			c.walkStmt(cmd.X, pipeIn)
			c.walkStmt(cmd.Y, true)
			c.allowBind = prevBind
		case syntax.AndStmt, syntax.OrStmt:
			c.walkStmt(cmd.X, pipeIn)
			c.walkStmt(cmd.Y, false)
		default:
			c.reject()
		}
	case *syntax.Subshell:
		prevBind := c.allowBind
		c.allowBind = false
		c.walkStmts(cmd.Stmts, false)
		c.allowBind = prevBind
	case *syntax.Block:
		prevBind := c.allowBind
		c.allowBind = false
		c.walkStmts(cmd.Stmts, false)
		c.allowBind = prevBind
	case *syntax.IfClause:
		prevBind := c.allowBind
		c.allowBind = false
		for ic := cmd; ic != nil; ic = ic.Else {
			c.walkStmts(ic.Cond, false)
			c.walkStmts(ic.Then, false)
		}
		c.allowBind = prevBind
	case *syntax.WhileClause:
		prevBind := c.allowBind
		c.allowBind = false
		c.walkStmts(cmd.Cond, false)
		c.walkStmts(cmd.Do, false)
		c.allowBind = prevBind
	case *syntax.ForClause:
		prevBind := c.allowBind
		c.allowBind = false
		enumDone := false
		if wi, ok := cmd.Loop.(*syntax.WordIter); ok {
			loopName := ""
			if wi.Name != nil {
				loopName = wi.Name.Value
				c.taintVar(loopName) // loop var never eligible as static command head
			}
			for _, w := range wi.Items {
				c.emitNestedFromWord(w)
			}
			if loopName != "" {
				enumDone = c.forEnumSubst(loopName, wi.Items, cmd.Do)
			}
		}
		if !enumDone {
			c.walkStmts(cmd.Do, false)
		}
		c.allowBind = prevBind
	case *syntax.CaseClause:
		prevBind := c.allowBind
		c.allowBind = false
		c.emitNestedFromWord(cmd.Word)
		for _, item := range cmd.Items {
			for _, pat := range item.Patterns {
				c.emitNestedFromWord(pat)
			}
			c.walkStmts(item.Stmts, false)
		}
		c.allowBind = prevBind
	case *syntax.FuncDecl:
		prevBind := c.allowBind
		c.allowBind = false
		if cmd.Body != nil {
			c.walkStmt(cmd.Body, false)
		}
		c.allowBind = prevBind
	case *syntax.TimeClause:
		prevBind := c.allowBind
		c.allowBind = false
		if cmd.Stmt != nil {
			c.walkStmt(cmd.Stmt, pipeIn)
		}
		c.allowBind = prevBind
	case *syntax.CoprocClause:
		prevBind := c.allowBind
		c.allowBind = false
		if cmd.Stmt != nil {
			c.walkStmt(cmd.Stmt, false)
		}
		c.allowBind = prevBind
	case *syntax.DeclClause:
		c.emitDecl(st, cmd, pipeIn)
	case *syntax.ArithmCmd:
		// Bash arithmetic command: still scan for nested CmdSubst via Walk.
		c.emitNestedFromNode(cmd)
	case *syntax.TestClause:
		c.emitNestedFromNode(cmd)
	case *syntax.LetClause:
		c.emitNestedFromNode(cmd)
	default:
		c.reject()
	}
}

func (c *subCollector) emitDecl(st *syntax.Stmt, d *syntax.DeclClause, pipeIn bool) {
	c.emitNestedFromNode(d)
	argv := make([]string, 0, 1+len(d.Args))
	if d.Variant != nil {
		argv = append(argv, d.Variant.Value)
	}
	for _, a := range d.Args {
		if a.Name != nil && !a.Naked {
			argv = append(argv, assignToPrefix(a))
			val, stOk := "", false
			if a.Value != nil {
				val, stOk = c.wordToArg(a.Value)
			}
			c.noteStaticAssign(a.Name.Value, val, stOk)
			continue
		}
		if a.Name != nil && a.Naked {
			argv = append(argv, a.Name.Value)
			continue
		}
		if a.Value != nil {
			s, _ := wordToArg(a.Value)
			argv = append(argv, s)
		}
	}
	seg := shellSegment{argv: argv, pipedStdin: pipeIn, backgrounded: st.Background}
	c.applyRedirs(&seg, st.Redirs)
	c.segs = append(c.segs, seg)
}

func (c *subCollector) emitCall(st *syntax.Stmt, call *syntax.CallExpr, pipeIn bool) {
	// Nested substitutions flush BEFORE the enclosing call.
	for _, a := range call.Assigns {
		if a.Value != nil {
			c.emitNestedFromWord(a.Value)
		}
		if a.Array != nil {
			c.emitNestedFromNode(a.Array)
		}
	}
	for _, w := range call.Args {
		c.emitNestedFromWord(w)
	}
	for _, r := range st.Redirs {
		if r.Word != nil {
			c.emitNestedFromWord(r.Word)
		}
		if r.Hdoc != nil && !isQuotedHeredocDelim(r.Word) {
			c.emitNestedFromWord(r.Hdoc)
		}
	}

	argv := make([]string, 0, len(call.Assigns)+len(call.Args))
	for _, a := range call.Assigns {
		argv = append(argv, assignToPrefix(a))
		if a.Name != nil && !a.Naked {
			if len(call.Args) == 0 {
				// Pure assignment statement — eligible for staticVars.
				val, st := "", false
				if a.Value != nil {
					val, st = c.wordToArg(a.Value)
				}
				c.noteStaticAssign(a.Name.Value, val, st)
			} else {
				// Prefix env (FOO=bar cmd) does not bind in the current shell.
				c.taintVar(a.Name.Value)
			}
		}
	}
	for i, w := range call.Args {
		// Command head: allow enumVars only for abs-path for-loop values (W-Fix-6).
		if i == 0 && len(c.enumVars) > 0 {
			// Try with enumVars; if resolved value is not a safe abs path, fall back.
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
		s, _ := c.wordToArg(w)
		argv = append(argv, s)
	}
	// POSIX parses `export NAME=VAL` as CallExpr (bash uses DeclClause).
	c.noteDeclCallBinds(argv)

	seg := shellSegment{
		argv:         argv,
		pipedStdin:   pipeIn,
		backgrounded: st.Background,
		processSubst: callHasProcSubst(call),
	}
	c.applyRedirs(&seg, st.Redirs)
	if len(seg.argv) > 0 || seg.redirectFile != "" || len(seg.heredocText) > 0 ||
		seg.hereString != "" || seg.processSubst || seg.depthExceeded {
		c.segs = append(c.segs, seg)
	}
}

func (c *subCollector) applyRedirs(seg *shellSegment, redirs []*syntax.Redirect) {
	for _, r := range redirs {
		switch r.Op {
		case syntax.Hdoc, syntax.DashHdoc:
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
				seg.heredocText = append(seg.heredocText, heredocBody{text: text, quoted: true, dynamic: false})
			} else if r.Hdoc == nil {
				seg.heredocText = append(seg.heredocText, heredocBody{quoted: false, dynamic: false})
			} else {
				dynamic := false
				var b strings.Builder
				for _, p := range r.Hdoc.Parts {
					lit, isLit := p.(*syntax.Lit)
					if !isLit {
						dynamic = true
						break
					}
					b.WriteString(decodeUnquotedHeredocLit(lit.Value, dash))
				}
				if dynamic {
					seg.heredocText = append(seg.heredocText, heredocBody{text: cmdSubPlaceholder, quoted: false, dynamic: true})
				} else {
					seg.heredocText = append(seg.heredocText, heredocBody{text: b.String(), quoted: false, dynamic: false})
				}
			}
		case syntax.WordHdoc:
			if r.Word != nil {
				s, ok := wordToArg(r.Word)
				if !ok {
					s = cmdSubPlaceholder
				}
				seg.hereString = s
			}
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
		case syntax.RdrIn, syntax.DplIn, syntax.RdrInOut:
			if r.Word != nil {
				c.emitNestedFromWord(r.Word)
			}
		}
	}
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

func (c *subCollector) emitNestedFromWord(w *syntax.Word) {
	if w == nil {
		return
	}
	if raw, ok := rawSlice(c.code, w.Pos(), w.End()); ok && rawHasLineContAfterDollar(raw) {
		c.reject()
		return
	}
	c.emitNestedFromNode(w)
}

func (c *subCollector) emitNestedFromNode(n syntax.Node) {
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
			sub := &subCollector{code: c.code, depth: c.depth + 1, staticVars: map[string]string{}, enumVars: map[string]string{}, taintedVars: map[string]bool{}, allowBind: false}
			sub.walkStmts(x.Stmts, false)
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
			sub := &subCollector{code: c.code, depth: c.depth + 1, staticVars: map[string]string{}, enumVars: map[string]string{}, taintedVars: map[string]bool{}, allowBind: false}
			sub.walkStmts(x.Stmts, false)
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
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '/' || ch == '-'
		if !ok {
			return false
		}
	}
	return true
}

func isSafeIdentOrRelPath(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '/' || ch == '-'
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
	if c.taintedVars[name] {
		return
	}
	if !static || !isSafeAbsPathVal(val) {
		c.taintedVars[name] = true
		delete(c.staticVars, name)
		return
	}
	if prev, ok := c.staticVars[name]; ok && prev != val {
		c.taintedVars[name] = true
		delete(c.staticVars, name)
		return
	}
	c.staticVars[name] = val
}

func (c *subCollector) resolveStaticParam(pe *syntax.ParamExp) (string, bool) {
	if pe == nil || pe.Param == nil || c.staticVars == nil {
		return "", false
	}
	if pe.Exp != nil || pe.Slice != nil || pe.Repl != nil || pe.Index != nil || pe.Length || pe.Excl || pe.Names != 0 {
		return "", false
	}
	v, ok := c.staticVars[pe.Param.Value]
	if !ok || !isSafeIdentOrRelPath(v) {
		return "", false
	}
	return v, true
}

// resolveParamForSubst resolves a simple $VAR / ${VAR} from enumVars (for-loop
// payload subst) or staticVars (abs-path binds). Used for in-word expansion;
// command-head resolution stays on resolveStaticParam (staticVars only).
func (c *subCollector) resolveParamForSubst(pe *syntax.ParamExp) (string, bool) {
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
	if c.staticVars != nil {
		if v, ok := c.staticVars[name]; ok {
			if !isSafeIdentOrRelPath(v) {
				return "", false
			}
			return v, true
		}
	}
	return "", false
}

// forEnumSubst substitutes each static for-list value into the Do body.
// Returns true when the Do body was handled (either enum-walked or rejected).
// Dynamic items leave the caller to walk Do once without binding.
func (c *subCollector) forEnumSubst(loopName string, items []*syntax.Word, do []*syntax.Stmt) bool {
	if len(items) == 0 {
		return false
	}
	if c.ssaBlocked != nil && c.ssaBlocked[loopName] {
		return false // G3: multi-write elsewhere → no static enum
	}
	vals := make([]string, 0, len(items))
	for _, w := range items {
		s, ok := wordToArg(w)
		if !ok {
			return false // dynamic item → stay dynamic
		}
		// W-Fix-1: non-simple enum items → graceful fallback (not reject).
		if !isSafeIdentOrRelPath(s) {
			return false
		}
		vals = append(vals, s)
	}
	if c.enumVars == nil {
		c.enumVars = map[string]string{}
	}
	prev, hadPrev := c.enumVars[loopName]
	for _, v := range vals {
		c.enumVars[loopName] = v
		c.walkStmts(do, false)
		if c.rejected {
			break
		}
	}
	if hadPrev {
		c.enumVars[loopName] = prev
	} else {
		delete(c.enumVars, loopName)
	}
	return true
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
				b.WriteString(cmdSubPlaceholder)
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
			// R-Allow-2 narrow: simple $VAR / ${VAR} may resolve from staticVars
			// when the collector context provides one; wordToArg itself stays
			// context-free and treats ParamExp as dynamic (prefix-preserving).
			static = false
			b.WriteString(cmdSubPlaceholder)
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
	hasSubst := (c.enumVars != nil && len(c.enumVars) > 0) || (c.staticVars != nil && len(c.staticVars) > 0)
	if !hasSubst {
		return wordToArg(w)
	}
	return c.wordToArgWithSubst(w)
}

// wordToArgWithSubst is wordToArg plus R-Allow-2 ParamExp substitution from
// enumVars/staticVars (in-word / -c payload expansion).
func (c *subCollector) wordToArgWithSubst(w *syntax.Word) (string, bool) {
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
				b.WriteString(cmdSubPlaceholder)
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
					if v, ok := c.resolveParamForSubst(ipp); ok {
						b.WriteString(v)
					} else {
						static = false
						b.WriteString(cmdSubPlaceholderQuoted)
					}
				default:
					static = false
					b.WriteString(cmdSubPlaceholderQuoted)
				}
			}
		case *syntax.ParamExp:
			if v, ok := c.resolveParamForSubst(p); ok {
				if openBracket {
					// SF-4: [prefix$v] can form a glob after expansion.
					static = false
				}
				b.WriteString(v)
			} else {
				static = false
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
	switch w.Parts[0].(type) {
	case *syntax.SglQuoted, *syntax.DblQuoted:
		return true
	default:
		return false
	}
}

// assignToPrefix formats an Assign as NAME=value (or NAME=__ctx_cmdsub__).
func assignToPrefix(a *syntax.Assign) string {
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
	s, ok := wordToArg(a.Value)
	if !ok {
		return name + "=" + cmdSubPlaceholder
	}
	return name + "=" + s
}
