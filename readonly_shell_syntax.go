package main

import (
	"strings"
	"unicode"
)

// checkReadonlyShellSyntax is the fail-closed minimal shell syntax gate for
// strict read-only roles (scout/planner/researcher/reviewer/oracle). It runs
// BEFORE splitShellSegments. Anything outside the subset is rejected with a
// concrete Hint telling the agent how to rewrite.
//
// Allowed: bare simple commands (argv[0] has no '/' and no '$'), list/pipe
// operators | && || ; newline (both sides non-empty), single-quoted literals,
// double-quoted literals without $ or `, ordinary \c escapes (no line
// continuation), and only >/dev/null 2>/dev/null 1>/dev/null 2>&1 1>&2.
//
// Rejected: any $, backticks, parentheses/braces, process substitution,
// background &, heredoc/here-string/input redirect, all control-flow
// reserved words, unclosed quotes, and any other redirection.
func checkReadonlyShellSyntax(code string) string {
	if code == "" {
		return ""
	}
	p := &roShellSyn{code: code}
	if err := p.parse(); err != "" {
		return err
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

	for p.i < len(p.code) {
		c := p.code[p.i]
		if c == '#' && (p.i == 0 || isShellWordBreak(p.code[p.i-1])) {
			p.i = skipToLineEnd(p.code, p.i)
			continue
		}
		switch c {
		case ' ', '\t', '\r':
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
			p.i++
		case ';':
			if !segStarted {
				return "empty command around ; Hint: 多步请拆成多次 ctx_run；分隔符两侧都必须有命令"
			}
			segStarted = false
			needCmd = true
			sawSep = true
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
		case '&':
			if p.i+1 < len(p.code) && p.code[p.i+1] == '&' {
				if !segStarted {
					return "empty command around && Hint: 多步请拆成多次 ctx_run；分隔符两侧都必须有命令"
				}
				p.i += 2
				segStarted = false
				needCmd = true
				sawSep = true
				continue
			}
			if p.i+1 < len(p.code) && p.code[p.i+1] == '>' {
				return "redirect &> forbidden Hint: 用 >/dev/null 或 2>/dev/null；禁止后台 & 与 &> 合并重定向"
			}
			return "background & forbidden Hint: 严格只读角色禁止后台；多步请拆成多次 ctx_run"
		case '<':
			return "input redirect forbidden Hint: 禁止 < << <<- <<<；用 cat/rg 读文件，或把数据放 stdin"
		case '>':
			if hit := p.consumeSafeRedirect(""); hit != "" {
				return hit
			}
		case '\'':
			if hit := p.consumeSingleQuote(); hit != "" {
				return hit
			}
			segStarted = true
			needCmd = false
		case '"':
			if hit := p.consumeDoubleQuote(); hit != "" {
				return hit
			}
			segStarted = true
			needCmd = false
		case '\\':
			if p.i+1 >= len(p.code) {
				return "trailing backslash Hint: 反斜杠只能转义普通字符，禁止续行"
			}
			if p.code[p.i+1] == '\n' {
				return "backslash line continuation forbidden Hint: 禁止 \\+换行续行；写成一行或拆成多次 ctx_run"
			}
			p.i += 2
			segStarted = true
			needCmd = false
		case '$':
			return "shell expansion $ forbidden Hint: $ 只能放在单引号里（例如 rg 'a$'）；禁止 $VAR ${} $() $(())"
		case '`':
			return "backtick substitution forbidden Hint: 禁止反引号命令替换；把步骤拆成多次 ctx_run"
		case '(', ')':
			return "parentheses forbidden Hint: 禁止子 shell / $() / (())；把步骤拆成多次 ctx_run"
		case '{', '}':
			return "brace group forbidden Hint: 禁止 { ...; }；把步骤拆成多次 ctx_run"
		default:
			// Glued fd redirect: 2>/dev/null or 2>&1
			if c >= '0' && c <= '9' {
				j := p.i
				for j < len(p.code) && p.code[j] >= '0' && p.code[j] <= '9' {
					j++
				}
				if j < len(p.code) && p.code[j] == '>' {
					fd := p.code[p.i:j]
					p.i = j
					if hit := p.consumeSafeRedirect(fd); hit != "" {
						return hit
					}
					continue
				}
			}
			word, hit := p.consumeWord()
			if hit != "" {
				return hit
			}
			if word == "" {
				// Should not spin: advance one byte defensively.
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
		}
	}
	if needCmd && sawSep && !segStarted {
		return "empty command around separator Hint: 多步请拆成多次 ctx_run；分隔符两侧都必须有命令"
	}
	return ""
}

// consumeSafeRedirect accepts only >/dev/null, 1>/dev/null, 2>/dev/null,
// 2>&1, 1>&2. fd is the optional leading descriptor already scanned ("2").
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
		p.i++
		for p.i < len(p.code) && (p.code[p.i] == ' ' || p.code[p.i] == '\t') {
			p.i++
		}
		tStart := p.i
		if p.i < len(p.code) && p.code[p.i] == '-' {
			return "redirect >&- forbidden Hint: 只允许 2>&1 或 1>&2"
		}
		for p.i < len(p.code) && p.code[p.i] >= '0' && p.code[p.i] <= '9' {
			p.i++
		}
		target := p.code[tStart:p.i]
		if (fd == "2" && target == "1") || (fd == "1" && target == "2") {
			return ""
		}
		return "redirect " + fd + ">&" + target + " forbidden Hint: 只允许 2>&1 或 1>&2"
	}
	for p.i < len(p.code) && (p.code[p.i] == ' ' || p.code[p.i] == '\t') {
		p.i++
	}
	tStart := p.i
	if p.i < len(p.code) && (p.code[p.i] == '\'' || p.code[p.i] == '"') {
		quote := p.code[p.i]
		p.i++
		body := p.i
		for p.i < len(p.code) && p.code[p.i] != quote {
			if quote == '"' && (p.code[p.i] == '$' || p.code[p.i] == '`') {
				return "redirect target expansion forbidden Hint: 只允许 >/dev/null"
			}
			if p.code[p.i] == '\\' && p.i+1 < len(p.code) {
				p.i += 2
				continue
			}
			p.i++
		}
		if p.i >= len(p.code) {
			return "unclosed quote in redirect Hint: 引号必须闭合"
		}
		target := p.code[body:p.i]
		p.i++
		if target != "/dev/null" {
			return "redirect to " + target + " forbidden Hint: 只允许 >/dev/null、2>/dev/null、1>/dev/null"
		}
		if fd != "" && fd != "1" && fd != "2" {
			return "redirect " + fd + ">/dev/null forbidden Hint: 只允许 >/dev/null、1>/dev/null、2>/dev/null"
		}
		_ = tStart
		return ""
	}
	for p.i < len(p.code) && !isShellWordBreak(p.code[p.i]) &&
		p.code[p.i] != ' ' && p.code[p.i] != '\t' {
		if p.code[p.i] == '$' || p.code[p.i] == '`' {
			return "redirect target expansion forbidden Hint: 只允许 >/dev/null"
		}
		p.i++
	}
	target := p.code[tStart:p.i]
	if target != "/dev/null" {
		if target == "" {
			return "redirect missing target Hint: 只允许 >/dev/null、2>/dev/null、1>/dev/null、2>&1、1>&2"
		}
		return "redirect to " + target + " forbidden Hint: 只允许 >/dev/null、2>/dev/null、1>/dev/null；禁止写任何文件"
	}
	if fd != "" && fd != "1" && fd != "2" {
		return "redirect " + fd + ">/dev/null forbidden Hint: 只允许 >/dev/null、1>/dev/null、2>/dev/null"
	}
	return ""
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
				return "trailing backslash Hint: 反斜杠只能转义普通字符，禁止续行"
			}
			if p.code[p.i+1] == '\n' {
				return "backslash line continuation forbidden Hint: 禁止 \\+换行续行"
			}
			p.i += 2
			continue
		}
		p.i++
	}
	return "unclosed double quote Hint: 双引号必须闭合"
}

func (p *roShellSyn) consumeWord() (string, string) {
	start := p.i
	for p.i < len(p.code) {
		c := p.code[p.i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
			c == ';' || c == '|' || c == '&' || c == '<' || c == '>' ||
			c == '(' || c == ')' || c == '{' || c == '}' ||
			c == '\'' || c == '"' {
			break
		}
		if c == '#' && p.i == start {
			break
		}
		if c == '$' {
			return "", "shell expansion $ forbidden Hint: $ 只能放在单引号里（例如 rg 'a$'）；禁止 $VAR ${} $() $(())"
		}
		if c == '`' {
			return "", "backtick substitution forbidden Hint: 禁止反引号命令替换；把步骤拆成多次 ctx_run"
		}
		if c == '\\' {
			if p.i+1 >= len(p.code) {
				return "", "trailing backslash Hint: 反斜杠只能转义普通字符，禁止续行"
			}
			if p.code[p.i+1] == '\n' {
				return "", "backslash line continuation forbidden Hint: 禁止 \\+换行续行；写成一行或拆成多次 ctx_run"
			}
			p.i += 2
			continue
		}
		p.i++
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
