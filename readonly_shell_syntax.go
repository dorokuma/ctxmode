package main

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// checkReadonlyShellSyntax is the fail-closed minimal shell syntax gate for
// strict read-only roles. It delegates to parseReadonlyShellAST (mvdan LangPOSIX).
func checkReadonlyShellSyntax(code string) string {
	if code == "" {
		return ""
	}
	_, hit := parseReadonlyShellAST(code)
	return hit
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
