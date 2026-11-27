package main

// role_guards_js_allowlist.go — strict-readonly JavaScript allowlist lexer, evaluator, and unicode identifier guards.

import (
	"strings"
)

type sroJSTokKind uint8

const (
	sroJSId sroJSTokKind = iota
	sroJSNum
	sroJSStr
	sroJSRe
	sroJSTokOp
)

type sroJSTok struct {
	kind          sroJSTokKind
	val           string
	hasEscape     bool
	isTemplate    bool
	isSynthTmplFn bool
}

func (t sroJSTok) isOp(op string) bool {
	return t.kind == sroJSTokOp && t.val == op
}

func (t sroJSTok) isId(v string) bool {
	return t.kind == sroJSId && t.val == v
}

func sroIsJSIdentStart(b byte) bool {
	return sroIsASCIIAlpha(b) || b == '_' || b == '$'
}

func sroIsJSIdentCont(b byte) bool {
	return sroIsASCIIAlpha(b) || sroIsASCIIDigit(b) || b == '_' || b == '$'
}

func sroIsValidJSIdentStr(s string) bool {
	if len(s) == 0 || !sroIsJSIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !sroIsJSIdentCont(s[i]) {
			return false
		}
	}
	return true
}

func sroIsDigitsOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !sroIsASCIIDigit(s[i]) {
			return false
		}
	}
	return true
}

var sroJSRegexKw = sroWordSet("return throw case delete void typeof await yield in of instanceof new else do")

var sroJSNonExprKw = sroWordSet("return throw case delete void typeof await yield in of instanceof new const let var else do try finally function class if while for switch catch")

var sroJSBadIdents = sroWordSet(`
	eval Function AsyncFunction GeneratorFunction AsyncGeneratorFunction
	Proxy Reflect globalThis global self window module exports arguments
	WebAssembly SharedArrayBuffer Atomics FinalizationRegistry WeakRef Worker
	fetch XMLHttpRequest WebSocket importScripts
	setImmediate setInterval setTimeout
`)

var sroJSBadProps = sroWordSet(`
	constructor __proto__ prototype mainModule
	__defineGetter__ __defineSetter__ __lookupGetter__ __lookupSetter__
	getBuiltinModule binding dlopen _load _compile
	umask chdir kill initgroups setuid setgid seteuid setegid setgroups openStdin
`)

var sroJSBuiltinNS = sroWordSet(`
	Object Array String Number Boolean Math JSON Date RegExp Promise
	Map Set WeakMap WeakSet Symbol BigInt Buffer URL URLSearchParams
	Error TypeError RangeError SyntaxError ReferenceError URIError EvalError
	Int8Array Uint8Array Uint8ClampedArray Int16Array Uint16Array
	Int32Array Uint32Array Float32Array Float64Array BigInt64Array BigUint64Array
	ArrayBuffer DataView Intl TextEncoder TextDecoder console require
`)

type sroJSExportKind uint8

const (
	sroJSExpConst sroJSExportKind = iota
	sroJSExpCall
	sroJSExpSubns
)

func sroJSExports(calls, consts, subns string) map[string]sroJSExportKind {
	m := make(map[string]sroJSExportKind)
	for _, w := range strings.Fields(calls) {
		m[w] = sroJSExpCall
	}
	for _, w := range strings.Fields(consts) {
		m[w] = sroJSExpConst
	}
	for _, w := range strings.Fields(subns) {
		m[w] = sroJSExpSubns
	}
	return m
}

var sroJSModExports = map[string]map[string]sroJSExportKind{
	"assert":      sroJSExports("ok strictEqual deepStrictEqual notStrictEqual", "", ""),
	"buffer":      sroJSExports("", "Buffer", ""),
	"crypto":      sroJSExports("createHash createHmac randomBytes randomUUID randomInt timingSafeEqual", "", ""),
	"fs":          sroJSExports("readFileSync readdirSync statSync lstatSync existsSync realpathSync accessSync readFile readdir stat lstat realpath access", "constants", "promises"),
	"fs/promises": sroJSExports("readFile readdir stat lstat realpath access", "", ""),
	"os":          sroJSExports("arch cpus endianness freemem homedir hostname loadavg machine networkInterfaces platform release tmpdir totalmem type uptime userInfo version", "EOL", ""),
	"path":        sroJSExports("basename dirname extname format isAbsolute join normalize parse relative resolve", "sep delimiter", "posix win32"),
	"querystring": sroJSExports("parse stringify escape unescape", "", ""),
	"url":         sroJSExports("URL URLSearchParams parse format fileURLToPath pathToFileURL", "", ""),
	"util":        sroJSExports("format inspect", "types", ""),
}

var sroJSProcMembers = sroJSExports("cwd exit hrtime memoryUsage uptime nextTick", "env argv platform arch version versions pid ppid stdout stderr", "")

var sroJSMeths = sroWordSet(`
	charAt charCodeAt codePointAt concat endsWith includes indexOf lastIndexOf
	localeCompare match matchAll normalize padEnd padStart repeat replace
	replaceAll search slice split startsWith substring toLocaleLowerCase
	toLocaleUpperCase toLowerCase toUpperCase trim trimEnd trimStart
	at every fill filter find findIndex findLast findLastIndex flat flatMap
	forEach join keys map pop push reduce reduceRight reverse shift some sort
	splice unshift values entries with toReversed toSorted toSpliced
	has get set add delete clear
	exec test
	toFixed toExponential toPrecision toString valueOf
	getTime getFullYear getUTCFullYear getMonth getUTCMonth getDate getUTCDate
	getDay getUTCDay getHours getUTCHours getMinutes getUTCMinutes
	getSeconds getUTCSeconds getMilliseconds getUTCMilliseconds
	getTimezoneOffset toISOString toJSON toDateString toTimeString toUTCString
	then catch finally resolve reject all allSettled any race
	isArray from of
	isFinite isInteger isNaN isSafeInteger parseFloat parseInt
	abs acos acosh asin asinh atan atan2 atanh cbrt ceil clz32 cos cosh exp
	expm1 floor fround hypot imul log log1p log10 log2 max min pow random
	round sign sin sinh sqrt tan tanh trunc
	parse stringify
	fromEntries hasOwn is
	alloc allocUnsafe byteLength compare isBuffer subarray readUInt8 readUInt16LE
	readUInt16BE readUInt32LE readUInt32BE readInt32LE readInt32BE
	update digest
	log info warn error debug dir table time timeEnd
	encode decode
	append getAll sort toString
`)

var sroJSDynSubMeths = sroWordSet("trim trimStart trimEnd toLowerCase toUpperCase startsWith endsWith includes indexOf lastIndexOf charCodeAt codePointAt")

func sroJSCanStartRegex(toks []sroJSTok) bool {
	if len(toks) == 0 {
		return true
	}
	prev := toks[len(toks)-1]
	if prev.kind == sroJSId {
		return sroJSRegexKw[prev.val]
	}
	if prev.kind == sroJSTokOp {
		switch prev.val {
		case ")", "]", "++", "--":
			return false
		default:
			return true
		}
	}
	return false
}

func sroJSLex(code string) ([]sroJSTok, string) {
	if strings.Contains(code, "\xe2\x80\xa8") || strings.Contains(code, "\xe2\x80\xa9") {
		code = "\x01"
	}
	norm := sroNormNL(code)
	var toks []sroJSTok
	var deferredTmplExprs [][]sroJSTok
	n := len(norm)
	i := 0
	delimStack := make([]byte, 0, 16)
	delimBad := false

	for i < n {
		b := norm[i]
		if b == ' ' || b == '\t' || b == '\n' {
			i++
			continue
		}
		if b < 0x20 || b == 0x7f {
			return nil, "allowlist: [js-ctrl-char] blocked"
		}
		if b >= 0x80 {
			return nil, "allowlist: [js-non-ascii] blocked"
		}

		if b == '/' && i+1 < n && norm[i+1] == '/' {
			i += 2
			for i < n && norm[i] != '\n' {
				i++
			}
			continue
		}
		if b == '/' && i+1 < n && norm[i+1] == '*' {
			end := strings.Index(norm[i+2:], "*/")
			if end < 0 {
				return nil, "allowlist: [js-unclosed-comment] blocked"
			}
			i += 2 + end + 2
			continue
		}

		if b == '\\' {
			if i+1 < n && (norm[i+1] == 'u' || norm[i+1] == 'x') {
				return nil, "allowlist: [js-unicode-esc] blocked"
			}
			return nil, "allowlist: [js-stray-bs] blocked"
		}

		if b == '\'' || b == '"' {
			q := b
			i++
			start := i
			hasEsc := false
			closed := false
			for i < n {
				c := norm[i]
				if c == '\\' {
					hasEsc = true
					if i+1 >= n {
						break
					}
					i += 2
					continue
				}
				if c == '\n' {
					break
				}
				if c == q {
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, "allowlist: [js-unclosed-string] blocked"
			}
			toks = append(toks, sroJSTok{kind: sroJSStr, val: norm[start:i], hasEscape: hasEsc})
			i++
			continue
		}

		if b == '`' {
			if len(toks) > 0 {
				prev := toks[len(toks)-1]
				if (prev.kind == sroJSId && !sroJSNonExprKw[prev.val]) ||
					prev.isOp(")") || prev.isOp("]") || prev.isTemplate {
					return nil, "allowlist: [js-tagged-template] blocked"
				}
			}
			subExprs, nextIdx, okTmpl, innerHit := sroJSScanTemplate(norm, i+1)
			if innerHit != "" {
				return nil, innerHit
			}
			if !okTmpl {
				return nil, "allowlist: [js-unclosed-template] blocked"
			}
			toks = append(toks, sroJSTok{kind: sroJSStr, val: "", hasEscape: true, isTemplate: true})
			deferredTmplExprs = append(deferredTmplExprs, subExprs...)
			i = nextIdx
			continue
		}

		if b == '/' && sroJSCanStartRegex(toks) {
			k := i + 1
			inCharClass := false
			closed := false
			for k < n {
				c := norm[k]
				if c == '\n' {
					break
				}
				if c == '\\' {
					if k+1 >= n || norm[k+1] == '\n' {
						break
					}
					k += 2
					continue
				}
				if c == '[' {
					inCharClass = true
				} else if c == ']' {
					inCharClass = false
				} else if c == '/' && !inCharClass {
					closed = true
					break
				}
				k++
			}
			if !closed {
				return nil, "allowlist: [js-unclosed-regex] blocked"
			}
			k++
			for k < n && sroIsASCIIAlpha(norm[k]) {
				k++
			}
			toks = append(toks, sroJSTok{kind: sroJSRe, val: norm[i:k]})
			i = k
			continue
		}

		if sroIsJSIdentStart(b) {
			start := i
			i++
			for i < n && sroIsJSIdentCont(norm[i]) {
				i++
			}
			toks = append(toks, sroJSTok{kind: sroJSId, val: norm[start:i]})
			continue
		}

		if sroIsASCIIDigit(b) || (b == '.' && i+1 < n && sroIsASCIIDigit(norm[i+1])) {
			start := i
			if b == '.' {
				i += 2
			} else {
				i++
			}
			for i < n {
				c := norm[i]
				if sroIsASCIIDigit(c) || sroIsASCIIAlpha(c) || c == '_' || c == '.' {
					if (c == 'e' || c == 'E') && i+1 < n && (norm[i+1] == '+' || norm[i+1] == '-') {
						i += 2
						continue
					}
					i++
				} else {
					break
				}
			}
			toks = append(toks, sroJSTok{kind: sroJSNum, val: norm[start:i]})
			continue
		}

		if b == '(' || b == '[' || b == '{' {
			delimStack = append(delimStack, b)
			toks = append(toks, sroJSTok{kind: sroJSTokOp, val: string(b)})
			i++
			continue
		}
		if b == ')' || b == ']' || b == '}' {
			if len(delimStack) == 0 || delimStack[len(delimStack)-1] != sroPyMatchingOpen(b) {
				delimBad = true
				break
			}
			delimStack = delimStack[:len(delimStack)-1]
			toks = append(toks, sroJSTok{kind: sroJSTokOp, val: string(b)})
			i++
			continue
		}

		op, step := sroJSScanOp(norm, i)
		if step == 0 {
			return nil, "allowlist: [js-unknown-char] blocked"
		}
		toks = append(toks, sroJSTok{kind: sroJSTokOp, val: op})
		i += step
	}

	if delimBad || len(delimStack) > 0 {
		return nil, "allowlist: [js-delim-mismatch] blocked"
	}

	for _, sub := range deferredTmplExprs {
		toks = append(toks,
			sroJSTok{kind: sroJSTokOp, val: ";"},
			sroJSTok{kind: sroJSId, val: "String", isSynthTmplFn: true},
			sroJSTok{kind: sroJSTokOp, val: "("},
		)
		toks = append(toks, sub...)
		toks = append(toks,
			sroJSTok{kind: sroJSTokOp, val: ")"},
			sroJSTok{kind: sroJSTokOp, val: ";"},
		)
	}
	return toks, ""
}

func sroJSScanTemplate(s string, start int) ([][]sroJSTok, int, bool, string) {
	n := len(s)
	i := start
	var exprs [][]sroJSTok
	for i < n {
		c := s[i]
		if c == '\\' {
			if i+1 >= n {
				return nil, 0, false, ""
			}
			i += 2
			continue
		}
		if c == '`' {
			return exprs, i + 1, true, ""
		}
		if c == '$' && i+1 < n && s[i+1] == '{' {
			k := i + 2
			depth := 1
			for k < n && depth > 0 {
				ch := s[k]
				if ch == '/' && k+1 < n && s[k+1] == '/' {
					for k < n && s[k] != '\n' {
						k++
					}
					continue
				}
				if ch == '/' && k+1 < n && s[k+1] == '*' {
					end := strings.Index(s[k+2:], "*/")
					if end < 0 {
						return nil, 0, false, ""
					}
					k += 2 + end + 2
					continue
				}
				if ch == '\'' || ch == '"' {
					q := ch
					k++
					for k < n {
						if s[k] == '\\' {
							k += 2
							continue
						}
						if s[k] == q || s[k] == '\n' {
							break
						}
						k++
					}
					if k >= n || s[k] != q {
						return nil, 0, false, ""
					}
					k++
					continue
				}
				if ch == '`' {
					nested, nextK, okN, hitN := sroJSScanTemplate(s, k+1)
					if hitN != "" {
						return nil, 0, false, hitN
					}
					if !okN {
						return nil, 0, false, ""
					}
					exprs = append(exprs, nested...)
					k = nextK
					continue
				}
				if ch == '{' {
					depth++
				} else if ch == '}' {
					depth--
					if depth == 0 {
						break
					}
				}
				k++
			}
			if depth != 0 {
				return nil, 0, false, ""
			}
			rawInner := strings.TrimSpace(s[i+2 : k])
			if rawInner == "" {
				return nil, 0, false, ""
			}
			subToks, hitSub := sroJSLex(rawInner)
			if hitSub != "" {
				return nil, 0, false, hitSub
			}
			if len(subToks) == 0 {
				return nil, 0, false, ""
			}
			exprs = append(exprs, subToks)
			i = k + 1
			continue
		}
		i++
	}
	return nil, 0, false, ""
}

var (
	sroJSOps3 = sroWordSet("=== !== >>> <<= >>= **= &&= ||= ??= ...")
	sroJSOps2 = sroWordSet("== != <= >= && || ?? ++ -- => ?. += -= *= /= %= &= |= ^= << >> **")
)

func sroJSScanOp(s string, i int) (string, int) {
	if i+4 <= len(s) && s[i:i+4] == ">>>=" {
		return ">>>=", 4
	}
	if i+3 <= len(s) && sroJSOps3[s[i:i+3]] {
		return s[i : i+3], 3
	}
	if i+2 <= len(s) && sroJSOps2[s[i:i+2]] {
		return s[i : i+2], 2
	}
	if strings.IndexByte("+-*/%&|^~!<>?=?:.,;", s[i]) >= 0 {
		return s[i : i+1], 1
	}
	return "", 0
}

func sroJSMatchDelim(toks []sroJSTok, openIdx int, openOp, closeOp string) int {
	if openIdx < 0 || openIdx >= len(toks) || !toks[openIdx].isOp(openOp) {
		return -1
	}
	depth := 0
	for i := openIdx; i < len(toks); i++ {
		if toks[i].isOp(openOp) {
			depth++
		} else if toks[i].isOp(closeOp) {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func sroJSIsAssign(t sroJSTok) bool {
	if t.kind != sroJSTokOp {
		return false
	}
	switch t.val {
	case "=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??=", "++", "--":
		return true
	default:
		return false
	}
}

func sroJSIsPrimBinOp(t sroJSTok) bool {
	if t.kind == sroJSId {
		return t.val == "in" || t.val == "instanceof"
	}
	if t.kind != sroJSTokOp {
		return false
	}
	switch t.val {
	case "+", "-", "*", "/", "%", "**", "<<", ">>", ">>>", "&", "^", "|",
		"===", "!==", "==", "!=", "<", "<=", ">", ">=":
		return true
	default:
		return false
	}
}

func sroJSIsSafePostPrimBoundary(toks []sroJSTok, idx int) bool {
	if idx >= len(toks) {
		return true
	}
	t := toks[idx]
	if t.kind != sroJSTokOp {
		return false
	}
	switch t.val {
	case ";", ",", ")", ":", "?", "&&", "||":
		return true
	default:
		return sroJSIsPrimBinOp(t)
	}
}

func sroJSSafeSinkArg(toks []sroJSTok, openParenIdx, argStart, argEnd int, confinedMods map[string]string) bool {
	if openParenIdx <= 0 || !toks[openParenIdx].isOp("(") {
		return false
	}
	if argStart <= openParenIdx || (argStart != openParenIdx+1 && !toks[argStart-1].isOp(",")) {
		return false
	}
	cp := sroJSMatchDelim(toks, openParenIdx, "(", ")")
	if cp < 0 || argEnd > cp || (argEnd != cp && !toks[argEnd].isOp(",")) {
		return false
	}

	fnTok := toks[openParenIdx-1]
	if fnTok.kind == sroJSId && fnTok.isSynthTmplFn {
		return argStart == openParenIdx+1 && argEnd == cp
	}

	if fnTok.kind == sroJSId && (openParenIdx < 2 || (!toks[openParenIdx-2].isOp(".") && !toks[openParenIdx-2].isOp("?."))) {
		if confinedMods[fnTok.val] != "" {
			return false
		}
		if openParenIdx >= 2 && toks[openParenIdx-2].isId("new") {
			return false
		}
		switch fnTok.val {
		case "String", "Number", "Boolean", "parseFloat", "isNaN", "isFinite":
			return argStart == openParenIdx+1 && argEnd == cp
		case "parseInt":
			return argStart == openParenIdx+1
		}
		return false
	}

	if openParenIdx >= 3 && toks[openParenIdx-2].isOp(".") && toks[openParenIdx-3].kind == sroJSId && fnTok.kind == sroJSId {
		if openParenIdx >= 4 && (toks[openParenIdx-4].isOp(".") || (toks[openParenIdx-4].isId("new"))) {
			return false
		}
		obj := toks[openParenIdx-3].val
		meth := fnTok.val
		if confinedMods[obj] != "" {
			return false
		}
		switch obj {
		case "console":
			return meth == "log" || meth == "info" || meth == "warn" || meth == "error"
		case "Math":
			return sroJSMeths[meth]
		case "Array":
			return meth == "isArray" && argStart == openParenIdx+1 && argEnd == cp
		case "Number":
			switch meth {
			case "isFinite", "isInteger", "isNaN", "isSafeInteger", "parseFloat":
				return argStart == openParenIdx+1 && argEnd == cp
			case "parseInt":
				return argStart == openParenIdx+1
			}
		case "JSON":
			return meth == "stringify" && argStart == openParenIdx+1 && argEnd == cp
		}
	}
	return false
}

func sroJSDynSubReadSink(toks []sroJSTok, baseIdx, endIdx int, confinedMods map[string]string) bool {
	if endIdx+2 < len(toks) && toks[endIdx+1].isOp(".") && toks[endIdx+2].kind == sroJSId {
		prop := toks[endIdx+2].val
		if prop == "length" {
			afterProp := endIdx + 3
			if afterProp < len(toks) && (toks[afterProp].isOp("(") || toks[afterProp].isOp("[") || toks[afterProp].isOp("?.") || sroJSIsAssign(toks[afterProp])) {
				return false
			}
			return true
		}
		if sroJSDynSubMeths[prop] && endIdx+3 < len(toks) && toks[endIdx+3].isOp("(") {
			return true
		}
		return false
	}

	if baseIdx >= 2 && toks[baseIdx-1].isOp("(") && endIdx+1 < len(toks) && toks[endIdx+1].isOp(")") &&
		toks[baseIdx-2].kind == sroJSId && (toks[baseIdx-2].val == "if" || toks[baseIdx-2].val == "while") {
		return true
	}

	if baseIdx > 0 && (toks[baseIdx-1].isOp("(") || toks[baseIdx-1].isOp(",")) {
		d := 0
		for k := baseIdx - 1; k >= 0; k-- {
			if toks[k].isOp(")") || toks[k].isOp("]") || toks[k].isOp("}") {
				d++
			} else if toks[k].isOp("(") || toks[k].isOp("[") || toks[k].isOp("{") {
				if d == 0 {
					if toks[k].isOp("(") && sroJSSafeSinkArg(toks, k, baseIdx, endIdx+1, confinedMods) {
						return true
					}
					break
				}
				d--
			}
		}
	}

	if baseIdx > 0 && toks[baseIdx-1].isOp("(") && endIdx+4 < len(toks) &&
		(toks[endIdx+1].isOp("||") || toks[endIdx+1].isOp("??")) &&
		(toks[endIdx+2].kind == sroJSNum || (toks[endIdx+2].kind == sroJSStr && !toks[endIdx+2].isTemplate)) &&
		toks[endIdx+3].isOp(")") && sroJSIsPrimBinOp(toks[endIdx+4]) {
		return true
	}

	if baseIdx > 0 {
		prev := toks[baseIdx-1]
		isUnaryPrim := prev.isOp("!") || prev.isOp("~") || prev.isId("typeof")
		isAugRHS := prev.isOp("+=") || prev.isOp("-=") || prev.isOp("*=") || prev.isOp("/=") || prev.isOp("%=")
		if (isUnaryPrim || isAugRHS || sroJSIsPrimBinOp(prev)) && sroJSIsSafePostPrimBoundary(toks, endIdx+1) {
			return true
		}
	}

	if endIdx+1 < len(toks) && sroJSIsPrimBinOp(toks[endIdx+1]) {
		if baseIdx == 0 {
			return true
		}
		prev := toks[baseIdx-1]
		if prev.isOp("(") || prev.isOp(",") || prev.isOp(";") || prev.isOp("{") || prev.isOp("?") || prev.isOp(":") ||
			prev.isOp("&&") || prev.isOp("||") || prev.isOp("=") || prev.isOp("+=") || prev.isOp("-=") ||
			sroJSIsPrimBinOp(prev) || prev.isId("return") {
			return true
		}
	}

	return false
}

func sroJSDynSubSafe(toks []sroJSTok, baseIdx, closeBracketIdx int, ctrlCloses map[int]bool, confinedMods map[string]string) bool {
	endIdx := closeBracketIdx
	for endIdx+1 < len(toks) && toks[endIdx+1].isOp("[") {
		nb := sroJSMatchDelim(toks, endIdx+1, "[", "]")
		if nb < 0 {
			return false
		}
		endIdx = nb
	}

	if endIdx+1 < len(toks) && sroJSIsAssign(toks[endIdx+1]) {
		atStmtBoundary := baseIdx == 0 || toks[baseIdx-1].isOp(";") || toks[baseIdx-1].isOp("{") ||
			toks[baseIdx-1].isOp("}") || ctrlCloses[baseIdx-1] ||
			toks[baseIdx-1].isId("else")
		return atStmtBoundary
	}

	return sroJSDynSubReadSink(toks, baseIdx, endIdx, confinedMods)
}

func sroJSDynSubConstOK(
	toks []sroJSTok,
	rootBaseIdx, closeBracketIdx int,
	ctrlCloses map[int]bool,
	confinedMods map[string]string,
	fnVars map[string]bool,
) (string, bool) {
	endIdx := closeBracketIdx
	for endIdx+1 < len(toks) && toks[endIdx+1].isOp("[") {
		nb := sroJSMatchDelim(toks, endIdx+1, "[", "]")
		if nb < 0 {
			return "", false
		}
		endIdx = nb
	}
	if rootBaseIdx < 3 {
		return "", false
	}
	endOK := endIdx+1 == len(toks) || toks[endIdx+1].isOp(";") || toks[endIdx+1].isOp("}") ||
		(toks[endIdx+1].kind == sroJSId && toks[endIdx+1].val != "in" && toks[endIdx+1].val != "instanceof")
	if !endOK {
		return "", false
	}
	constIdx := rootBaseIdx - 3
	declIdx := rootBaseIdx - 2
	if !toks[constIdx].isId("const") || toks[declIdx].kind != sroJSId || !toks[rootBaseIdx-1].isOp("=") {
		return "", false
	}
	if constIdx > 0 && toks[constIdx-1].isOp("(") {
		return "", false
	}
	vName := toks[declIdx].val
	if vName == "this" || vName == "process" || sroJSBadIdents[vName] || sroJSBuiltinNS[vName] ||
		confinedMods[vName] != "" || fnVars[vName] {
		return "", false
	}
	for u := 0; u < len(toks); u++ {
		if toks[u].kind != sroJSId || toks[u].val != vName || u == declIdx {
			continue
		}
		if u > 0 && (toks[u-1].isOp(".") || toks[u-1].isOp("?.")) {
			continue
		}
		if u > 0 && (toks[u-1].isOp("{") || toks[u-1].isOp(",")) && u+1 < len(toks) && toks[u+1].isOp(":") {
			continue
		}
		if u > 0 && toks[u-1].kind == sroJSId &&
			(toks[u-1].val == "const" || toks[u-1].val == "let" || toks[u-1].val == "var" ||
				toks[u-1].val == "function" || toks[u-1].val == "class" || toks[u-1].val == "catch") {
			return "", false
		}
		if u+1 < len(toks) && (toks[u+1].isOp("=>") || sroJSIsAssign(toks[u+1])) {
			return "", false
		}
		spanEnd := u
		for spanEnd+2 < len(toks) && toks[spanEnd+1].isOp(".") && toks[spanEnd+2].kind == sroJSId {
			prop := toks[spanEnd+2].val
			if sroJSBadProps[prop] || prop == "toString" || prop == "valueOf" {
				return "", false
			}
			afterProp := spanEnd + 3
			if prop == "length" && (afterProp >= len(toks) || !toks[afterProp].isOp(".")) {
				break
			}
			if afterProp < len(toks) && toks[afterProp].isOp("(") {
				break
			}
			spanEnd += 2
		}
		if spanEnd+1 < len(toks) && (toks[spanEnd+1].isOp("(") || toks[spanEnd+1].isOp("[") ||
			toks[spanEnd+1].isOp("?.") || sroJSIsAssign(toks[spanEnd+1])) {
			return "", false
		}
		if !sroJSDynSubReadSink(toks, u, spanEnd, confinedMods) {
			return "", false
		}
	}
	return vName, true
}

func sroJSAllowlistHit(code string, jsNodePerm bool) string {
	toks, lexHit := sroJSLex(code)
	if lexHit != "" {
		return lexHit
	}
	if len(toks) == 0 {
		return ""
	}

	inClassBody := make(map[int]bool)
	ctrlCloses := make(map[int]bool)
	fnVars := make(map[string]bool)
	localVars := make(map[string]bool)
	userClassMethods := make(map[string]bool)

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind == sroJSId {
			switch t.val {
			case "if", "while", "for", "switch", "catch":
				if i+1 < len(toks) && toks[i+1].isOp("(") {
					cp := sroJSMatchDelim(toks, i+1, "(", ")")
					if cp > i+1 {
						ctrlCloses[cp] = true
					}
				}
			case "class":
				k := i + 1
				if k < len(toks) && toks[k].kind == sroJSId {
					fnVars[toks[k].val] = true
					localVars[toks[k].val] = true
					k++
				}
				if k < len(toks) && toks[k].isId("extends") {
					k += 2
				}
				if k < len(toks) && toks[k].isOp("{") {
					cb := sroJSMatchDelim(toks, k, "{", "}")
					if cb > k {
						for p := k + 1; p < cb; p++ {
							inClassBody[p] = true
						}
						d := 0
						for p := k + 1; p < cb; p++ {
							if toks[p].isOp("{") || toks[p].isOp("(") || toks[p].isOp("[") {
								d++
							} else if toks[p].isOp("}") || toks[p].isOp(")") || toks[p].isOp("]") {
								d--
							} else if d == 0 && toks[p].kind == sroJSId && p+1 < cb && toks[p+1].isOp("(") {
								mn := toks[p].val
								if mn != "constructor" && !sroJSBadProps[mn] && !sroJSWriteMeths[mn] {
									userClassMethods[mn] = true
								}
							}
						}
					}
				}
			case "function":
				if i+1 < len(toks) && toks[i+1].kind == sroJSId {
					fnVars[toks[i+1].val] = true
					localVars[toks[i+1].val] = true
				}
			case "const", "let", "var":
				if i+1 < len(toks) && toks[i+1].kind == sroJSId {
					vName := toks[i+1].val
					localVars[vName] = true
					if i+3 < len(toks) && toks[i+2].isOp("=") {
						rhs := toks[i+3]
						if (rhs.kind == sroJSId && (rhs.val == "function" || rhs.val == "async")) ||
							(i+4 < len(toks) && rhs.kind == sroJSId && toks[i+4].isOp("=>")) {
							fnVars[vName] = true
						} else if rhs.isOp("(") {
							cp := sroJSMatchDelim(toks, i+3, "(", ")")
							if cp > 0 && cp+1 < len(toks) && toks[cp+1].isOp("=>") {
								fnVars[vName] = true
							}
						}
					}
				}
			}
		}
	}

	confinedMods := make(map[string]string)
	confinedModFns := make(map[string]string)
	validRequireTok := make(map[int]bool)
	modDeclBindTok := make(map[int]bool)
	destrBindTok := make(map[int]bool)

	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.kind != sroJSId || t.val != "require" {
			continue
		}
		if i > 0 && (toks[i-1].isOp(".") || toks[i-1].isOp("?.")) {
			continue
		}
		if i+3 >= len(toks) || !toks[i+1].isOp("(") || toks[i+2].kind != sroJSStr ||
			toks[i+2].hasEscape || toks[i+2].isTemplate || !toks[i+3].isOp(")") {
			return "allowlist: [js-require-syntax] blocked"
		}
		rawMod := strings.TrimPrefix(toks[i+2].val, "node:")
		exports, okMod := sroJSModExports[rawMod]
		if !okMod {
			return "allowlist: [js-require-mod] module " + rawMod + " not allowed"
		}
		closeReq := i + 3

		if closeReq+1 < len(toks) && toks[closeReq+1].isOp(".") {
			validRequireTok[i] = true
			continue
		}

		if i >= 3 && toks[i-1].isOp("=") && toks[i-2].kind == sroJSId &&
			toks[i-3].kind == sroJSId && (toks[i-3].val == "const" || toks[i-3].val == "let" || toks[i-3].val == "var") {
			alias := toks[i-2].val
			confinedMods[alias] = rawMod
			modDeclBindTok[i-2] = true
			validRequireTok[i] = true
			continue
		}

		if i >= 4 && toks[i-1].isOp("=") && toks[i-2].isOp("}") {
			openBrace := -1
			d := 0
			for k := i - 2; k >= 0; k-- {
				if toks[k].isOp("}") {
					d++
				} else if toks[k].isOp("{") {
					d--
					if d == 0 {
						openBrace = k
						break
					}
				}
			}
			if openBrace >= 1 && toks[openBrace-1].kind == sroJSId &&
				(toks[openBrace-1].val == "const" || toks[openBrace-1].val == "let" || toks[openBrace-1].val == "var") {
				propHit, badShape := sroJSDestructReq(toks, openBrace, i-2, rawMod, exports, confinedModFns, destrBindTok)
				if badShape {
					return "allowlist: [js-destruct-require-unconfined] blocked"
				}
				if propHit != "" {
					return propHit
				}
				validRequireTok[i] = true
				continue
			}
		}

		return "allowlist: [js-require-unconfined] blocked"
	}

	for modName := range sroJSModExports {
		if strings.IndexByte(modName, '/') >= 0 {
			continue
		}
		if confinedMods[modName] == "" && !localVars[modName] {
			confinedMods[modName] = modName
		}
	}

	dynSubTaintedVars := make(map[string]bool)
	dynSubConstVars := make(map[string]bool)
	if jsNodePerm {
		for i := 0; i+4 < len(toks); i++ {
			if toks[i].kind == sroJSId && toks[i+1].isOp("=") {
				for k := i + 2; k < len(toks) && !toks[k].isOp(";"); k++ {
					if toks[k].isOp("[") && k > i+2 && toks[k-1].kind == sroJSId {
						dynSubTaintedVars[toks[i].val] = true
						break
					}
				}
			}
		}
	}

	skipUntil := -1
	for i := 0; i < len(toks); i++ {
		if i <= skipUntil {
			continue
		}
		t := toks[i]

		if t.isOp("?.") {
			if i+1 < len(toks) && (toks[i+1].isOp("[") || toks[i+1].isOp("(")) {
				return "allowlist: [js-optchain-sub-call] blocked"
			}
		}
		if (t.isOp(".") || t.isOp("?.")) && (i == 0 || i+1 >= len(toks) || toks[i+1].kind != sroJSId) {
			return "allowlist: [js-dot-syntax] blocked"
		}
		if t.isOp(".") || t.isOp("?.") {
			continue
		}

		isAfterDot := i > 0 && (toks[i-1].isOp(".") || toks[i-1].isOp("?."))

		if t.kind == sroJSId && !isAfterDot {
			switch t.val {
			case "import":
				if i+1 < len(toks) && toks[i+1].isOp("(") {
					return "allowlist: [js-dynamic-import] blocked"
				}
				return "allowlist: [js-esm-import] blocked"
			case "with":
				return "allowlist: [js-with-stmt] blocked"
			case "this":
				if !inClassBody[i] {
					return "allowlist: [js-this-outside-class] blocked"
				}
				if i+2 >= len(toks) || !toks[i+1].isOp(".") || toks[i+2].kind != sroJSId {
					return "allowlist: [js-this-non-dot] blocked"
				}
				continue
			}

			if sroJSBadIdents[t.val] {
				return "allowlist: [js-forbidden-ident] identifier " + t.val + " not allowed"
			}

			if i > 0 && (toks[i-1].isOp("{") || toks[i-1].isOp(",")) &&
				i+1 < len(toks) && (toks[i+1].isOp(":") || toks[i+1].isOp("}") || toks[i+1].isOp(",") || toks[i+1].isOp("=")) {
				if sroJSBadProps[t.val] || t.val == "toString" || t.val == "valueOf" {
					return "allowlist: [js-destruct-forbidden-prop] destructuring or defining ." + t.val + " not allowed"
				}
			}

			if t.val == "require" && validRequireTok[i] {
				if i+4 < len(toks) && toks[i+4].isOp(".") {
					rawMod := strings.TrimPrefix(toks[i+2].val, "node:")
					if hit, nextIdx := sroJSModChain(toks, i+3, rawMod); hit != "" {
						return hit
					} else {
						skipUntil = nextIdx
					}
				}
				continue
			}

			if canonMod := confinedMods[t.val]; canonMod != "" {
				if modDeclBindTok[i] {
					continue
				}
				if i+1 < len(toks) && sroJSIsAssign(toks[i+1]) {
					return "allowlist: [js-mod-rebind] reassigning confined module " + t.val + " not allowed"
				}
				if i+1 >= len(toks) || !toks[i+1].isOp(".") {
					return "allowlist: [js-mod-bare] confined module " + t.val + " must be accessed via .member"
				}
				if hit, nextIdx := sroJSModChain(toks, i, canonMod); hit != "" {
					return hit
				} else {
					skipUntil = nextIdx
				}
				continue
			}

			if canonFn := confinedModFns[t.val]; canonFn != "" {
				if destrBindTok[i] {
					continue
				}
				parts := strings.SplitN(canonFn, ".", 2)
				expKind := sroJSModExports[parts[0]][parts[1]]
				if expKind == sroJSExpCall && (i+1 >= len(toks) || !toks[i+1].isOp("(")) {
					return "allowlist: [js-destruct-callable] destructured module function " + t.val + " must be called directly"
				}
				continue
			}

			if t.val == "process" {
				if hit, nextIdx := sroJSCheckProcessUse(toks, i); hit != "" {
					return hit
				} else {
					skipUntil = nextIdx
				}
				continue
			}

			if jsNodePerm && dynSubTaintedVars[t.val] && i+1 < len(toks) && toks[i+1].isOp("(") {
				return "allowlist: [js-dynsub-taint-call] blocked"
			}
		}

		if t.kind == sroJSId && isAfterDot {
			prop := t.val
			isCall := i+1 < len(toks) && toks[i+1].isOp("(")
			if sroJSBadProps[prop] || (!isCall && (prop == "toString" || prop == "valueOf")) {
				return "allowlist: [js-forbidden-prop] property ." + prop + " not allowed"
			}
			if isCall && !sroJSMeths[prop] && !userClassMethods[prop] {
				return "allowlist: [js-method-call] method ." + prop + "() not allowed"
			}
			continue
		}

		if t.isOp("[") && sroJSIsBracketSubscript(toks, i, ctrlCloses) {
			cb := sroJSMatchDelim(toks, i, "[", "]")
			if cb <= i+1 {
				return "allowlist: [js-sub-empty] blocked"
			}
			idxSlice := toks[i+1 : cb]

			if len(idxSlice) == 1 && idxSlice[0].kind == sroJSNum && sroIsDigitsOnly(idxSlice[0].val) {
				continue
			}

			if len(idxSlice) == 1 && idxSlice[0].kind == sroJSStr && !idxSlice[0].isTemplate {
				if idxSlice[0].hasEscape {
					return "allowlist: [js-sub-escaped-key] blocked"
				}
				key := idxSlice[0].val
				isCall := cb+1 < len(toks) && toks[cb+1].isOp("(")
				if !sroIsValidJSIdentStr(key) || sroJSBadProps[key] || (!isCall && (key == "toString" || key == "valueOf")) {
					return "allowlist: [js-sub-static-prop] subscript ['" + key + "'] not allowed"
				}
				if isCall && !sroJSMeths[key] && !userClassMethods[key] {
					return "allowlist: [js-sub-static-call] subscript method ['" + key + "']() not allowed"
				}
				continue
			}

			if cb+1 < len(toks) && (toks[cb+1].isOp("(") || toks[cb+1].isOp("?.")) {
				return "allowlist: [js-dynsub-call] blocked"
			}
			if i >= 3 && (toks[i-2].isOp(".") || toks[i-2].isOp("?.")) && toks[i-1].kind == sroJSId {
				propBefore := toks[i-1].val
				if sroJSMeths[propBefore] {
					return "allowlist: [js-dynsub-method-prop] dynamic subscript on method property ." + propBefore + " not allowed"
				}
			}
			rootBaseIdx := i - 1
			for rootBaseIdx >= 2 && toks[rootBaseIdx].isOp("]") {
				d := 0
				for k := rootBaseIdx; k >= 0; k-- {
					if toks[k].isOp("]") {
						d++
					} else if toks[k].isOp("[") {
						d--
						if d == 0 {
							rootBaseIdx = k - 1
							break
						}
					}
				}
			}
			badBase := rootBaseIdx < 0 || toks[rootBaseIdx].kind != sroJSId ||
				(rootBaseIdx > 0 && (toks[rootBaseIdx-1].isOp(".") || toks[rootBaseIdx-1].isOp("?.")))
			if !badBase {
				baseName := toks[rootBaseIdx].val
				badBase = baseName == "this" || baseName == "process" || confinedMods[baseName] != "" ||
					sroJSBuiltinNS[baseName] || fnVars[baseName] || dynSubConstVars[baseName]
			}
			if badBase {
				return "allowlist: [js-dynsub-base] blocked"
			}

			if !jsNodePerm && !sroJSDynSubSafe(toks, rootBaseIdx, cb, ctrlCloses, confinedMods) {
				vName, okHold := sroJSDynSubConstOK(toks, rootBaseIdx, cb, ctrlCloses, confinedMods, fnVars)
				if !okHold {
					return "allowlist: [js-dynsub-escape] blocked"
				}
				dynSubConstVars[vName] = true
			}
		}
	}

	return ""
}

var sroJSWriteMeths = sroWordSet("write writeFile writeFileSync appendFile appendFileSync mkdir mkdirSync mkdtemp mkdtempSync rmdir rmdirSync rm rmSync unlink unlinkSync rename renameSync copyFile copyFileSync cp cpSync chmod chmodSync lchmod fchmod chown chownSync lchown fchown utimes utimesSync lutimes lutimesSync futimes symlink symlinkSync link linkSync truncate truncateSync ftruncate open openSync createWriteStream")

func sroJSIsBracketSubscript(toks []sroJSTok, openBracketIdx int, ctrlCloses map[int]bool) bool {
	if openBracketIdx <= 0 {
		return false
	}
	prev := toks[openBracketIdx-1]
	if prev.kind == sroJSId {
		return !sroJSNonExprKw[prev.val]
	}
	if prev.kind == sroJSStr || prev.kind == sroJSNum || prev.kind == sroJSRe {
		return true
	}
	if prev.isOp(")") {
		return !ctrlCloses[openBracketIdx-1]
	}
	if prev.isOp("]") {
		return true
	}
	return false
}

func sroJSDestructReq(
	toks []sroJSTok,
	openBrace, closeBrace int,
	rawMod string,
	exports map[string]sroJSExportKind,
	confinedModFns map[string]string,
	destrBindTok map[int]bool,
) (string, bool) {
	if closeBrace <= openBrace+1 {
		return "", true
	}
	k := openBrace + 1
	for k < closeBrace {
		if toks[k].isOp("...") || toks[k].isOp("[") || toks[k].isOp("{") || toks[k].kind != sroJSId {
			return "", true
		}
		prop := toks[k].val
		local := prop
		localIdx := k
		k++
		if k < closeBrace && toks[k].isOp(":") {
			if k+1 >= closeBrace || toks[k+1].kind != sroJSId {
				return "", true
			}
			local = toks[k+1].val
			localIdx = k + 1
			k += 2
		}
		if k < closeBrace && !toks[k].isOp(",") {
			return "", true
		}
		if k < closeBrace && toks[k].isOp(",") {
			k++
		}
		if _, ok := exports[prop]; !ok {
			return "allowlist: [js-destruct-require-prop] destructured require member " + rawMod + "." + prop + " not allowed", false
		}
		confinedModFns[local] = rawMod + "." + prop
		destrBindTok[localIdx] = true
	}
	return "", false
}

func sroJSModChain(toks []sroJSTok, baseEndIdx int, canonMod string) (string, int) {
	if baseEndIdx+2 >= len(toks) || toks[baseEndIdx+2].kind != sroJSId {
		return "", baseEndIdx
	}
	member := toks[baseEndIdx+2].val
	memberIdx := baseEndIdx + 2
	exports := sroJSModExports[canonMod]
	expKind, okExp := exports[member]
	if !okExp {
		return "allowlist: [js-mod-member] module member " + canonMod + "." + member + " not allowed", memberIdx
	}
	if expKind == sroJSExpSubns {
		if canonMod == "fs" && member == "promises" {
			okFSP := memberIdx+3 < len(toks) && toks[memberIdx+1].isOp(".") && toks[memberIdx+2].kind == sroJSId && toks[memberIdx+3].isOp("(")
			if okFSP {
				_, okFSP = sroJSModExports["fs/promises"][toks[memberIdx+2].val]
			}
			if !okFSP {
				return "allowlist: [js-fs-promises-member] blocked", memberIdx
			}
			return "", memberIdx + 2
		}
		return sroJSModChain(toks, memberIdx, "path")
	}
	if expKind == sroJSExpCall {
		if memberIdx+1 >= len(toks) || !toks[memberIdx+1].isOp("(") {
			return "allowlist: [js-mod-callable] " + canonMod + "." + member + " must be called directly", memberIdx
		}
	}
	return "", memberIdx
}

func sroJSValidProcessEnvRead(toks []sroJSTok, idx, memIdx int) (bool, int) {
	if idx > 0 && toks[idx-1].isId("delete") {
		return false, memIdx
	}
	if memIdx+2 < len(toks) && toks[memIdx+1].isOp(".") && toks[memIdx+2].kind == sroJSId {
		keyIdx := memIdx + 2
		if keyIdx+1 < len(toks) && sroJSIsAssign(toks[keyIdx+1]) {
			return false, keyIdx
		}
		return true, keyIdx
	}
	if memIdx+1 < len(toks) && toks[memIdx+1].isOp("[") {
		cb := sroJSMatchDelim(toks, memIdx+1, "[", "]")
		if cb != memIdx+3 || toks[memIdx+2].kind != sroJSStr || toks[memIdx+2].hasEscape ||
			toks[memIdx+2].isTemplate || !sroIsValidJSIdentStr(toks[memIdx+2].val) {
			return false, memIdx
		}
		if cb+1 < len(toks) && sroJSIsAssign(toks[cb+1]) {
			return false, cb
		}
		return true, cb
	}
	return false, -1
}

func sroJSCheckProcessUse(toks []sroJSTok, idx int) (string, int) {
	hasDotMem := idx+2 < len(toks) && toks[idx+1].isOp(".") && toks[idx+2].kind == sroJSId
	var expKind sroJSExportKind
	okMem := false
	mem := ""
	memIdx := idx
	if hasDotMem {
		mem = toks[idx+2].val
		memIdx = idx + 2
		expKind, okMem = sroJSProcMembers[mem]
		if okMem && memIdx+1 < len(toks) && sroJSIsAssign(toks[memIdx+1]) {
			okMem = false
		}
	}
	if !hasDotMem || !okMem {
		return "allowlist: [js-process-member] blocked", memIdx
	}
	if mem == "stdout" || mem == "stderr" {
		if memIdx+3 >= len(toks) || !toks[memIdx+1].isOp(".") || toks[memIdx+2].kind != sroJSId ||
			toks[memIdx+2].val != "write" || !toks[memIdx+3].isOp("(") {
			return "allowlist: [js-process-stdio] process." + mem + " only allows .write(...)", memIdx
		}
		return "", memIdx + 2
	}
	if mem == "env" {
		okRead, endIdx := sroJSValidProcessEnvRead(toks, idx, memIdx)
		if okRead {
			return "", endIdx
		}
		if endIdx >= 0 {
			return "allowlist: [js-process-env-mutate] blocked", endIdx
		}
		if idx >= 4 && toks[idx-1].isOp("(") && memIdx+1 < len(toks) && toks[memIdx+1].isOp(")") &&
			toks[idx-3].isOp(".") && toks[idx-4].kind == sroJSId && toks[idx-2].kind == sroJSId {
			oName := toks[idx-4].val
			mName := toks[idx-2].val
			if (oName == "Object" && (mName == "keys" || mName == "values" || mName == "entries")) ||
				(oName == "JSON" && mName == "stringify") ||
				(oName == "console" && mName == "log") {
				return "", memIdx
			}
		}
		return "allowlist: [js-process-env-alias] blocked", memIdx
	}
	if expKind == sroJSExpCall {
		if memIdx+1 >= len(toks) || !toks[memIdx+1].isOp("(") {
			return "allowlist: [js-process-callable] process." + mem + " must be called directly", memIdx
		}
	}
	return "", memIdx
}

// Legacy helper entrypoints retained for guardCtxRunCode, pythonStdlibWriteTailHit, and unit tests.
func jsUnicodeIdentEscapeHit(code string) string {
	if !strings.Contains(code, `\u`) {
		return ""
	}
	if _, why := sroJSLex(code); strings.HasPrefix(why, "allowlist: [js-unicode-esc]") {
		return "js unicode identifier escape"
	}
	return ""
}

func pyMaskedNonASCIIIdentHit(codeOrMasked string) string {
	if _, why := sroPyLex(sroNormNL(codeOrMasked)); strings.HasPrefix(why, "allowlist: [py-non-ascii]") {
		return "python non-ASCII identifier"
	}
	return ""
}
