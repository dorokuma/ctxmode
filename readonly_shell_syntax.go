package main

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// checkReadonlyShellSyntax is the fail-closed minimal shell syntax gate for
// strict read-only roles (scout/planner/researcher/reviewer/oracle). It runs
// BEFORE splitShellSegments. Design: byte allowlist precheck + two-state
// lexer aligned with dash token recognition (POSIX blanks = space/tab only).
//
// Allowed: bare simple commands, | && || ; newline, single-quoted literals,
// double-quoted literals without $ or `, and only the five safe redirects
// >/dev/null 1>/dev/null 2>/dev/null 2>&1 1>&2 (exact, word-bounded).
//
// Rejected: control chars (except \t \n), unquoted $ ` ( ) { } < ~ * ? [,
// lone &, unquoted backslash, quotes/backslash in command head, redirect
// before command name, glued redirects inside a word.
func checkReadonlyShellSyntax(code string) string {
	if code == "" {
		return ""
	}
	if hit := roByteAllowlist(code); hit != "" {
		return hit
	}
	p := &roShellSyn{code: code}
	if err := p.parse(); err != "" {
		return err
	}
	return ""
}

// roByteAllowlist rejects illegal UTF-8, C0 controls (except \t \n), DEL,
// and Unicode control / special-space code points.
func roByteAllowlist(code string) string {
	if !utf8.ValidString(code) {
		return "illegal UTF-8 Hint: 命令必须是合法 UTF-8"
	}
	for i := 0; i < len(code); {
		b := code[i]
		if b < 0x20 {
			if b == '\t' || b == '\n' {
				i++
				continue
			}
			return "control character forbidden Hint: 禁止控制字符（含 \\r \\v \\f）；匹配回车请写 rg '\\r'"
		}
		if b == 0x7f {
			return "control character forbidden Hint: 禁止 DEL (0x7f)"
		}
		if b < 0x80 {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(code[i:])
		if r == utf8.RuneError && size == 1 {
			return "illegal UTF-8 Hint: 命令必须是合法 UTF-8"
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Z, r) && r != ' ' {
			// Reject Unicode controls and non-ASCII spaces (U+00A0, U+2000.., U+2028/9, …).
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

type roShellSyn struct {
	code string
	i    int
}

func (p *roShellSyn) parse() string {
	segStarted := false
	needCmd := true
	sawSep := false
	inWord := false

	for p.i < len(p.code) {
		c := p.code[p.i]

		// Comment only at word start (not inside a word).
		if c == '#' && !inWord {
			p.i = skipToLineEnd(p.code, p.i)
			continue
		}

		switch c {
		case ' ', '\t':
			inWord = false
			p.i++
		case '\n':
			if needCmd && sawSep && !segStarted {
				return "empty command around separator Hint: 多步请拆成多次 ctx_run；分隔符两侧都必须有命令"
			}
			if segStarted {
				sawSep = true
				needCmd = true
				segStarted = false
			}
			inWord = false
			p.i++
		case ';':
			if !segStarted {
				return "empty command around ; Hint: 多步请拆成多次 ctx_run；分隔符两侧都必须有命令"
			}
			segStarted = false
			needCmd = true
			sawSep = true
			inWord = false
			p.i++
		case '|':
			if !segStarted {
				return "empty command around | Hint: 管道两侧都必须有命令"
			}
			if p.i+1 < len(p.code) && p.code[p.i+1] == '|' {
				p.i += 2
			} else {
				p.i++
			}
			segStarted = false
			needCmd = true
			sawSep = true
			inWord = false
		case '&':
			if p.i+1 < len(p.code) && p.code[p.i+1] == '&' {
				if !segStarted {
					return "empty command around && Hint: 多步请拆成多次 ctx_run；分隔符两侧都必须有命令"
				}
				p.i += 2
				segStarted = false
				needCmd = true
				sawSep = true
				inWord = false
				continue
			}
			if p.i+1 < len(p.code) && p.code[p.i+1] == '>' {
				return "redirect &> forbidden Hint: 用 >/dev/null 或 2>/dev/null；禁止后台 & 与 &> 合并重定向"
			}
			return "background & forbidden Hint: 严格只读角色禁止后台；多步请拆成多次 ctx_run"
		case '<':
			return "input redirect forbidden Hint: 禁止 < << <<- <<<；用 cat/rg 读文件，或把数据放 stdin"
		case '>':
			if inWord {
				return "glued redirect forbidden Hint: 重定向符 > 前必须留空格，如 cmd >/dev/null 或 cmd 2>/dev/null"
			}
			if needCmd {
				return "leading redirect forbidden Hint: 重定向只能写在命令名之后，禁止 2>/dev/null ls"
			}
			if hit := p.consumeSafeRedirect(""); hit != "" {
				return hit
			}
			inWord = false
		case '\'', '"':
			if needCmd {
				return "quoted command name forbidden Hint: 命令名禁止带引号或转义；写裸命令名如 ls/rg/git"
			}
			if c == '\'' {
				if hit := p.consumeSingleQuote(); hit != "" {
					return hit
				}
			} else {
				if hit := p.consumeDoubleQuote(); hit != "" {
					return hit
				}
			}
			segStarted = true
			needCmd = false
			inWord = true
		case '\\':
			// Unquoted backslash is banned entirely for strict readonly.
			return "unquoted backslash forbidden Hint: 特殊字符请放进引号（例如 find . -name '*.go'）；禁止引号外反斜杠"
		case '$':
			return "shell expansion $ forbidden Hint: $ 只能放在单引号里（例如 rg 'a$'）；禁止 $VAR ${} $() $(())"
		case '`':
			return "backtick substitution forbidden Hint: 禁止反引号命令替换；把步骤拆成多次 ctx_run"
		case '(', ')':
			return "parentheses forbidden Hint: 禁止子 shell / $() / (())；把步骤拆成多次 ctx_run"
		case '{', '}':
			return "brace group forbidden Hint: 禁止 { ...; }；把步骤拆成多次 ctx_run"
		case '~':
			return "tilde expansion forbidden Hint: 引号外禁止 ~；请写显式路径或给 ~ 加引号"
		case '*', '?':
			return "glob metachar forbidden Hint: 引号外禁止 * ? [；通配请加引号，例如 find . -name '*.go'"
		case '[':
			// Bare `[` as the test builtin command name is allowed only as a
			// complete word that we still reject via control-flow / allowlist
			// later; unquoted `[` anywhere is a glob char — ban it here and
			// tell agents to quote or use test.
			return "glob metachar forbidden Hint: 引号外禁止 * ? [；通配请加引号，或改用 test"
		default:
			// Bare IO_NUMBER redirect only at word start: 1>/dev/null, 2>&1.
			if !inWord && c >= '0' && c <= '9' {
				j := p.i
				for j < len(p.code) && p.code[j] >= '0' && p.code[j] <= '9' {
					j++
				}
				if j < len(p.code) && p.code[j] == '>' {
					if needCmd {
						return "leading redirect forbidden Hint: 重定向只能写在命令名之后，禁止 2>/dev/null ls"
					}
					fd := p.code[p.i:j]
					p.i = j
					if hit := p.consumeSafeRedirect(fd); hit != "" {
						return hit
					}
					inWord = false
					continue
				}
			}
			word, hit := p.consumeBareWord()
			if hit != "" {
				return hit
			}
			if word == "" {
				if p.i < len(p.code) {
					p.i++
				}
				continue
			}
			if needCmd || !segStarted {
				if err := roShellCheckCmdHead(word); err != "" {
					return err
				}
			}
			segStarted = true
			needCmd = false
			inWord = true
		}
	}
	if needCmd && sawSep && !segStarted {
		return "empty command around separator Hint: 多步请拆成多次 ctx_run；分隔符两侧都必须有命令"
	}
	return ""
}

// consumeSafeRedirect accepts only the five exact forms:
// >/dev/null, 1>/dev/null, 2>/dev/null, 2>&1, 1>&2.
// Target must be unquoted/unescaped; after the token a word boundary is required.
func (p *roShellSyn) consumeSafeRedirect(fd string) string {
	if p.i >= len(p.code) || p.code[p.i] != '>' {
		return "redirect forbidden Hint: 只允许 >/dev/null、2>/dev/null、1>/dev/null、2>&1、1>&2"
	}
	p.i++ // '>'
	if p.i < len(p.code) && p.code[p.i] == '>' {
		return "redirect >> forbidden Hint: 禁止写文件；只允许 >/dev/null 或 2>&1"
	}
	if p.i < len(p.code) && p.code[p.i] == '|' {
		return "redirect >| forbidden Hint: 禁止写文件"
	}
	if p.i < len(p.code) && p.code[p.i] == '&' {
		// 2>&1 / 1>&2 must be fully glued — no spaces.
		p.i++
		if p.i >= len(p.code) || p.code[p.i] < '0' || p.code[p.i] > '9' {
			return "redirect fd dup forbidden Hint: 只允许紧贴的 2>&1 或 1>&2"
		}
		tStart := p.i
		for p.i < len(p.code) && p.code[p.i] >= '0' && p.code[p.i] <= '9' {
			p.i++
		}
		target := p.code[tStart:p.i]
		if !((fd == "2" && target == "1") || (fd == "1" && target == "2")) {
			return "redirect " + fd + ">&" + target + " forbidden Hint: 只允许 2>&1 或 1>&2"
		}
		if !p.atWordBoundary() {
			return "redirect missing word boundary Hint: 2>&1 / 1>&2 后必须是词边界（空格/分隔符/结尾）"
		}
		return ""
	}
	// >/dev/null — spaces/tabs allowed between > and /dev/null; target bare.
	for p.i < len(p.code) && (p.code[p.i] == ' ' || p.code[p.i] == '\t') {
		p.i++
	}
	if p.i < len(p.code) && (p.code[p.i] == '\'' || p.code[p.i] == '"' || p.code[p.i] == '\\') {
		return "redirect target quote/escape forbidden Hint: 只允许裸 >/dev/null，禁止引号或转义目标"
	}
	const want = "/dev/null"
	if p.i+len(want) > len(p.code) || p.code[p.i:p.i+len(want)] != want {
		tStart := p.i
		for p.i < len(p.code) && !roIsWordBreak(p.code[p.i]) {
			p.i++
		}
		target := p.code[tStart:p.i]
		if target == "" {
			return "redirect missing target Hint: 只允许 >/dev/null、2>/dev/null、1>/dev/null、2>&1、1>&2"
		}
		return "redirect to " + target + " forbidden Hint: 只允许 >/dev/null、2>/dev/null、1>/dev/null；禁止写任何文件"
	}
	p.i += len(want)
	if fd != "" && fd != "1" && fd != "2" {
		return "redirect " + fd + ">/dev/null forbidden Hint: 只允许 >/dev/null、1>/dev/null、2>/dev/null"
	}
	if !p.atWordBoundary() {
		return "redirect missing word boundary Hint: >/dev/null 后必须是词边界；禁止 >'/dev/null'foo 等粘连"
	}
	return ""
}

func (p *roShellSyn) atWordBoundary() bool {
	if p.i >= len(p.code) {
		return true
	}
	return roIsWordBreak(p.code[p.i])
}

// roIsWordBreak is the readonly lexer word-break set: blank, newline, and
// list/pipe operators. '&' alone is a break for boundary checks after a
// finished redirect token (actual lone & is rejected elsewhere).
func roIsWordBreak(c byte) bool {
	switch c {
	case ' ', '\t', '\n', ';', '|', '&':
		return true
	}
	return false
}

func (p *roShellSyn) consumeSingleQuote() string {
	p.i++
	for p.i < len(p.code) && p.code[p.i] != '\'' {
		p.i++
	}
	if p.i >= len(p.code) {
		return "unclosed single quote Hint: 单引号必须闭合"
	}
	p.i++
	return ""
}

func (p *roShellSyn) consumeDoubleQuote() string {
	p.i++
	for p.i < len(p.code) {
		c := p.code[p.i]
		if c == '"' {
			p.i++
			return ""
		}
		if c == '$' || c == '`' {
			return "shell expansion inside double quotes forbidden Hint: $ 和反引号只能放在单引号里（例如 rg 'a$'）"
		}
		if c == '\\' {
			if p.i+1 >= len(p.code) {
				return "trailing backslash Hint: 双引号内禁止续行"
			}
			if p.code[p.i+1] == '\n' {
				return "backslash line continuation forbidden Hint: 双引号内禁止 \\+换行续行"
			}
			p.i += 2
			continue
		}
		p.i++
	}
	return "unclosed double quote Hint: 双引号必须闭合"
}

// consumeBareWord reads an unquoted word. Metacharacters that must be
// quoted are rejected; backslash is rejected (must use quotes instead).
func (p *roShellSyn) consumeBareWord() (string, string) {
	start := p.i
	for p.i < len(p.code) {
		c := p.code[p.i]
		switch c {
		case ' ', '\t', '\n', ';', '|', '&', '<', '>', '(', ')', '{', '}', '\'', '"':
			return p.code[start:p.i], ""
		case '#':
			// Mid-word '#' is literal.
			p.i++
		case '$':
			return "", "shell expansion $ forbidden Hint: $ 只能放在单引号里（例如 rg 'a$'）；禁止 $VAR ${} $() $(())"
		case '`':
			return "", "backtick substitution forbidden Hint: 禁止反引号命令替换；把步骤拆成多次 ctx_run"
		case '\\':
			return "", "unquoted backslash forbidden Hint: 特殊字符请放进引号（例如 find . -name '*.go'）；禁止引号外反斜杠"
		case '~':
			return "", "tilde expansion forbidden Hint: 引号外禁止 ~；请写显式路径或给 ~ 加引号"
		case '*', '?', '[':
			return "", "glob metachar forbidden Hint: 引号外禁止 * ? [；通配请加引号，例如 find . -name '*.go'"
		default:
			p.i++
		}
	}
	return p.code[start:p.i], ""
}

func roShellCheckCmdHead(word string) string {
	if word == "" {
		return "empty command Hint: 分隔符两侧都必须有命令"
	}
	if strings.Contains(word, "/") {
		return "path command Hint: 禁止带 / 的命令头；用白名单裸命令名（ls/cat/rg/git）"
	}
	if strings.Contains(word, "$") {
		return "shell expansion $ forbidden Hint: $ 只能放在单引号里"
	}
	// Command head must be plain [A-Za-z0-9_.-] or the test builtin "[".
	for i := 0; i < len(word); i++ {
		ch := word[i]
		ok := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '.' || ch == '-' ||
			(ch == '[' && word == "[") || (ch == ']' && word == "]")
		if !ok {
			return "command name charset Hint: 命令名只能含字母数字 _ . -"
		}
	}
	switch word {
	case "if", "then", "elif", "else", "fi",
		"for", "in", "while", "until", "do", "done",
		"case", "esac", "function", "select", "time", "coproc",
		"!", "[[", "]]", "{", "}":
		return "control flow '" + word + "' forbidden Hint: 禁止 if/for/while/[[ 等控制流；多步请拆成多次 ctx_run"
	}
	if eq := strings.IndexByte(word, '='); eq > 0 {
		name := word[:eq]
		ok := true
		for i := 0; i < len(name); i++ {
			ch := name[i]
			if i == 0 && !unicode.IsLetter(rune(ch)) && ch != '_' {
				ok = false
				break
			}
			if i > 0 && !unicode.IsLetter(rune(ch)) && !unicode.IsDigit(rune(ch)) && ch != '_' {
				ok = false
				break
			}
		}
		if ok {
			return "env assign forbidden Hint: 禁止 VAR=val 前缀；需要环境变量时只用 LANG/LC_ALL/TZ 经 ctx_run env"
		}
	}
	return ""
}
