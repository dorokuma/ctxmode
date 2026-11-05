package main

import (
	"strings"
	"unicode"
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
