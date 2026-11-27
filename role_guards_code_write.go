package main

// role_guards_code_write.go — language-specific write and lexical spawn screens (python/js/sqlite/dbm/perl/ruby/php).

import (
	"strings"
	"unicode/utf8"
)

func pythonWriteModeHit(code string) string {
	masked := pythonMask(code)
	ioModuleOpens := map[string]bool{
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
		methodCall := false
		skip := false
		if pos > 0 && masked[pos-1] == '.' {
			k := pos - 1
			for k > 0 && (isIdentByte(masked[k-1]) || masked[k-1] == '.') {
				k--
			}
			recv := masked[k : pos-1]
			lastSeg := recv
			if dot := strings.LastIndexByte(recv, '.'); dot >= 0 {
				lastSeg = recv[dot+1:]
			}
			switch {
			case lastSeg == "os":
				skip = true
			case recv == "dbm" || strings.HasPrefix(recv, "dbm."):
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
			return "python open() unclosed"
		}
		if openArgsWriteMode(masked[lo:hi], code[lo:hi], methodCall) {
			return "python open() write mode"
		}
		idx = openParen + 1
	}
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
	toks := codeTokens(normCallSpace(masked))
	if toks.hasTokenLike("urlretrieve(") || toks.hasTokenLike("urllib.request.urlretrieve") {
		return "urlretrieve downloads to disk"
	}
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
	return pythonStdlibWriteTailHit(code, masked)
}

var pySensitiveReflectNames = map[string]bool{
	"open":                     true,
	"FileIO":                   true,
	"ZipFile":                  true,
	"PyZipFile":                true,
	"BaseRotatingHandler":      true,
	"FileHandler":              true,
	"RotatingFileHandler":      true,
	"TimedRotatingFileHandler": true,
	"WatchedFileHandler":       true,
	"basicConfig":              true,
	"dictConfig":               true,
	"DictConfigurator":         true,
	"dictConfigClass":          true,
	"BaseConfigurator":         true,
	"fileConfig":               true,
	"resolve_name":             true,
	"write_text":               true,
	"write_bytes":              true,
	"unlink":                   true,
	"rmdir":                    true,
	"rmtree":                   true,
	"mkdir":                    true,
	"makedirs":                 true,
	"symlink":                  true,
	"symlink_to":               true,
	"hardlink_to":              true,
	"chmod":                    true,
	"lchmod":                   true,
	"chown":                    true,
	"ftruncate":                true,
	"copyfile":                 true,
	"copy2":                    true,
	"copytree":                 true,
	"make_archive":             true,
	"NamedTemporaryFile":       true,
	"TemporaryFile":            true,
	"mkstemp":                  true,
	"mkdtemp":                  true,
	"popen":                    true,
	"Popen":                    true,
	"posix_spawn":              true,
	"posix_spawnp":             true,
}

func pyIsIdentByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func pyNextIdent(s string, from int, name string) int {
	if name == "" || from < 0 {
		return -1
	}
	for off := from; off+len(name) <= len(s); {
		rel := strings.Index(s[off:], name)
		if rel < 0 {
			return -1
		}
		idx := off + rel
		prevOK := idx == 0 || !pyIsIdentByte(s[idx-1])
		nextOK := idx+len(name) == len(s) || !pyIsIdentByte(s[idx+len(name)])
		if prevOK && nextOK {
			return idx
		}
		off = idx + 1
	}
	return -1
}

func pySkipHorizAndCont(s string, i int, allowBareNL bool) int {
	for i < len(s) {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || (allowBareNL && c == '\n') {
			i++
			continue
		}
		if c == '\\' && (i == 0 || s[i-1] != '\\') {
			if i+1 < len(s) && s[i+1] == '\n' {
				i += 2
				continue
			}
			if i+2 < len(s) && s[i+1] == '\r' && s[i+2] == '\n' {
				i += 3
				continue
			}
		}
		break
	}
	return i
}

// pyImportStmtHeaderStart returns the start offset of the enclosing import /
// from-import statement for an identifier at idx where isPythonImportStmtAt(s, idx) is true.
func pyImportStmtHeaderStart(s string, idx int) (stmtStart int, inParen bool) {
	i := idx - 1
	openParen := -1
	for i >= 0 {
		c := s[i]
		if pyIsIdentByte(c) || c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\\' {
			i--
			continue
		}
		if c == '(' {
			openParen = i
		}
		break
	}
	scanFrom := idx - 1
	if openParen >= 0 {
		inParen = true
		scanFrom = openParen - 1
	}
	m := scanFrom
	for m >= 0 {
		c := s[m]
		if pyIsIdentByte(c) || c == '.' || c == ',' || c == ' ' || c == '\t' || c == '\r' {
			m--
			continue
		}
		if c == '\n' {
			k := m - 1
			if k >= 0 && s[k] == '\r' {
				k--
			}
			if k >= 0 && s[k] == '\\' && (k == 0 || s[k-1] != '\\') {
				m = k - 1
				continue
			}
		}
		break
	}
	return pySkipHorizAndCont(s, m+1, false), inParen
}

// pyImportAliasAfter extracts `Y` from `<name> as Y` when name at [idx, idx+nameLen)
// lies inside a valid Python import statement.
func pyImportAliasAfter(masked string, idx, nameLen int) string {
	_, inParen := pyImportStmtHeaderStart(masked, idx)
	j := pySkipHorizAndCont(masked, idx+nameLen, inParen)
	if j+2 > len(masked) || masked[j:j+2] != "as" {
		return ""
	}
	if j > 0 && pyIsIdentByte(masked[j-1]) {
		return ""
	}
	if j+2 < len(masked) && pyIsIdentByte(masked[j+2]) {
		return ""
	}
	k := pySkipHorizAndCont(masked, j+2, inParen)
	if k >= len(masked) || !pyIsIdentByte(masked[k]) || (masked[k] >= '0' && masked[k] <= '9') {
		return ""
	}
	end := k
	for end < len(masked) && pyIsIdentByte(masked[end]) {
		end++
	}
	return masked[k:end]
}

func pyMatchMatchingDelim(masked string, openIdx int, openCh, closeCh byte) int {
	if openIdx < 0 || openIdx >= len(masked) || masked[openIdx] != openCh {
		return -1
	}
	var stack [64]byte
	sp := 0
	for i := openIdx; i < len(masked); i++ {
		switch masked[i] {
		case '(', '[', '{':
			if sp >= len(stack) {
				return -1
			}
			stack[sp] = masked[i]
			sp++
		case ')', ']', '}':
			if sp == 0 {
				return -1
			}
			top := stack[sp-1]
			if (top == '(' && masked[i] != ')') ||
				(top == '[' && masked[i] != ']') ||
				(top == '{' && masked[i] != '}') {
				return -1
			}
			sp--
			if sp == 0 {
				if masked[i] == closeCh {
					return i
				}
				return -1
			}
		}
	}
	return -1
}

func pyTrimContinuationSpan(s string) string {
	start := 0
	for start < len(s) {
		c := s[start]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			start++
			continue
		}
		if c == '\\' && start+1 < len(s) &&
			(s[start+1] == '\n' || (s[start+1] == '\r' && start+2 < len(s) && s[start+2] == '\n')) {
			start++
			continue
		}
		break
	}
	end := len(s)
	for end > start {
		c := s[end-1]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\\' {
			end--
			continue
		}
		break
	}
	return s[start:end]
}

func pyTrimSpanBounds(s string, a, b int) (int, int) {
	for a < b {
		c := s[a]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			a++
			continue
		}
		if c == '\\' && a+1 < b &&
			(s[a+1] == '\n' || (s[a+1] == '\r' && a+2 < b && s[a+2] == '\n')) {
			a++
			continue
		}
		break
	}
	for b > a {
		c := s[b-1]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\\' {
			b--
			continue
		}
		break
	}
	return a, b
}

func pySplitTopLevelArgs(masked string, openParen, closeParen int) [][2]int {
	var out [][2]int
	depth := 0
	segStart := openParen + 1
	for i := openParen + 1; i <= closeParen; i++ {
		if i == closeParen || (depth == 0 && masked[i] == ',') {
			a, b := pyTrimSpanBounds(masked, segStart, i)
			if a < b {
				out = append(out, [2]int{a, b})
			}
			segStart = i + 1
			continue
		}
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return out
}

func pyTopLevelKeywordEq(masked string, aStart, aEnd int) (string, int, bool) {
	depth := 0
	for i := aStart; i < aEnd; i++ {
		switch masked[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case '=':
			if depth != 0 {
				continue
			}
			if i > aStart {
				prev := masked[i-1]
				if prev == '=' || prev == '!' || prev == '<' || prev == '>' || prev == ':' {
					continue
				}
			}
			if i+1 < aEnd && masked[i+1] == '=' {
				continue
			}
			kw := pyTrimContinuationSpan(masked[aStart:i])
			if kw == "" || (kw[0] >= '0' && kw[0] <= '9') {
				return "", -1, false
			}
			for j := 0; j < len(kw); j++ {
				if !pyIsIdentByte(kw[j]) {
					return "", -1, false
				}
			}
			return kw, i, true
		}
	}
	return "", -1, false
}

func pyHexVal(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func pyUnquoteStringLiteral(raw string) (string, string, bool) {
	s := pyTrimContinuationSpan(raw)
	if len(s) < 2 {
		return "", "", false
	}
	pEnd := 0
	for pEnd < len(s) && pEnd < 2 &&
		((s[pEnd] >= 'a' && s[pEnd] <= 'z') || (s[pEnd] >= 'A' && s[pEnd] <= 'Z')) {
		pEnd++
	}
	if pEnd >= len(s) || (s[pEnd] != '\'' && s[pEnd] != '"') {
		return "", "", false
	}
	prefix := s[:pEnd]
	for i := 0; i < len(prefix); i++ {
		switch prefix[i] {
		case 'r', 'R', 'u', 'U', 'b', 'B', 'f', 'F':
		default:
			return "", "", false
		}
	}
	isRaw := strings.ContainsAny(prefix, "rR")
	q := s[pEnd]
	delimLen := 1
	if len(s) >= pEnd+6 && s[pEnd+1] == q && s[pEnd+2] == q {
		delimLen = 3
	}
	var buf strings.Builder
	i := pEnd + delimLen
	closedAt := -1
	for i < len(s) {
		if delimLen == 3 {
			if i+3 <= len(s) && s[i] == q && s[i+1] == q && s[i+2] == q {
				closedAt = i + 3
				break
			}
		} else if s[i] == q {
			closedAt = i + 1
			break
		}
		if s[i] == '\\' {
			if i+1 >= len(s) {
				return "", "", false
			}
			if isRaw {
				buf.WriteByte('\\')
				buf.WriteByte(s[i+1])
				i += 2
				continue
			}
			next := s[i+1]
			switch next {
			case '\n':
				i += 2
			case '\r':
				if i+2 < len(s) && s[i+2] == '\n' {
					i += 3
				} else {
					i += 2
				}
			case '\\', '\'', '"':
				buf.WriteByte(next)
				i += 2
			case 'n':
				buf.WriteByte('\n')
				i += 2
			case 'r':
				buf.WriteByte('\r')
				i += 2
			case 't':
				buf.WriteByte('\t')
				i += 2
			case 'x':
				if i+4 > len(s) {
					return "", "", false
				}
				hi, ok1 := pyHexVal(s[i+2])
				lo, ok2 := pyHexVal(s[i+3])
				if !ok1 || !ok2 {
					return "", "", false
				}
				buf.WriteByte((hi << 4) | lo)
				i += 4
			case 'u':
				if i+6 > len(s) {
					return "", "", false
				}
				var cp uint32
				for k := 0; k < 4; k++ {
					hv, okH := pyHexVal(s[i+2+k])
					if !okH {
						return "", "", false
					}
					cp = (cp << 4) | uint32(hv)
				}
				buf.WriteRune(rune(cp))
				i += 6
			case 'U':
				if i+10 > len(s) {
					return "", "", false
				}
				var cp uint32
				for k := 0; k < 8; k++ {
					hv, okH := pyHexVal(s[i+2+k])
					if !okH {
						return "", "", false
					}
					cp = (cp << 4) | uint32(hv)
				}
				if cp > 0x10FFFF {
					return "", "", false
				}
				buf.WriteRune(rune(cp))
				i += 10
			default:
				if next >= '0' && next <= '7' {
					oct := uint32(next - '0')
					step := 2
					for step < 4 && i+step < len(s) && s[i+step] >= '0' && s[i+step] <= '7' {
						oct = (oct << 3) | uint32(s[i+step]-'0')
						step++
					}
					buf.WriteByte(byte(oct & 0xff))
					i += step
				} else {
					buf.WriteByte('\\')
					buf.WriteByte(next)
					i += 2
				}
			}
			continue
		}
		buf.WriteByte(s[i])
		i++
	}
	if closedAt != len(s) {
		return "", "", false
	}
	return buf.String(), prefix, true
}

func pyIsReadonlyModeLiteral(raw string) bool {
	val, prefix, ok := pyUnquoteStringLiteral(raw)
	if !ok || val == "" || strings.ContainsAny(prefix, "fF") {
		return false
	}
	for i := 0; i < len(val); i++ {
		switch val[i] {
		case 'r', 'b', 't', 'U':
		default:
			return false
		}
	}
	return true
}

func pyCtorCallIsWrite(code, masked string, openParen int, canonName string) bool {
	closeParen := pyMatchMatchingDelim(masked, openParen, '(', ')')
	if closeParen < 0 {
		return true
	}
	args := pySplitTopLevelArgs(masked, openParen, closeParen)
	posIdx := 0
	for _, sp := range args {
		aStart, aEnd := sp[0], sp[1]
		if masked[aStart] == '*' {
			return true
		}
		if kw, eqIdx, ok := pyTopLevelKeywordEq(masked, aStart, aEnd); ok {
			if kw == "mode" && !pyIsReadonlyModeLiteral(code[eqIdx+1:aEnd]) {
				return true
			}
			if canonName == "FileIO" && kw == "opener" &&
				pyTrimContinuationSpan(masked[eqIdx+1:aEnd]) != "None" {
				return true
			}
			continue
		}
		if posIdx == 1 && !pyIsReadonlyModeLiteral(code[aStart:aEnd]) {
			return true
		}
		if canonName == "FileIO" && posIdx == 3 &&
			pyTrimContinuationSpan(masked[aStart:aEnd]) != "None" {
			return true
		}
		posIdx++
	}
	return false
}

func pyCheckDictSubscriptOrGet(code, masked string, afterExpr int, label string) string {
	k := pySkipHorizAndCont(masked, afterExpr, true)
	if k >= len(masked) {
		return ""
	}
	if masked[k] == '[' {
		closeBr := pyMatchMatchingDelim(masked, k, '[', ']')
		if closeBr > k+1 {
			if val, prefix, ok := pyUnquoteStringLiteral(code[k+1 : closeBr]); ok &&
				!strings.ContainsAny(prefix, "fF") && pySensitiveReflectNames[val] {
				return "python " + label + " " + val
			}
		}
		return ""
	}
	if masked[k] == '.' {
		m := pySkipHorizAndCont(masked, k+1, true)
		if m+3 <= len(masked) && masked[m:m+3] == "get" &&
			(m+3 == len(masked) || !pyIsIdentByte(masked[m+3])) {
			p := pySkipHorizAndCont(masked, m+3, true)
			if p < len(masked) && masked[p] == '(' {
				closeP := pyMatchMatchingDelim(masked, p, '(', ')')
				if closeP > p+1 {
					args := pySplitTopLevelArgs(masked, p, closeP)
					if len(args) >= 1 {
						if val, prefix, ok := pyUnquoteStringLiteral(code[args[0][0]:args[0][1]]); ok &&
							!strings.ContainsAny(prefix, "fF") && pySensitiveReflectNames[val] {
							return "python " + label + ".get " + val
						}
					}
				}
			}
		}
	}
	return ""
}

type pySymTarget struct {
	sym   string
	canon string
}

// pyExtractFromImportItems parses all `from <wantModule> import ...` statements
// in masked, returning imported local bindings paired with their canonical names
// in wantModule, plus hasStar when `from <wantModule> import *` is present.
func pyExtractFromImportItems(masked, wantModule string) ([]pySymTarget, bool) {
	var out []pySymTarget
	hasStar := false

	prevContNL := func(nlIdx int) (int, bool) {
		k := nlIdx - 1
		if k >= 0 && masked[k] == '\r' {
			k--
		}
		if k >= 0 && masked[k] == '\\' && (k == 0 || masked[k-1] != '\\') {
			return k - 1, true
		}
		return 0, false
	}

	isBoundaryBefore := func(idx int) bool {
		k := idx - 1
		for k >= 0 {
			if masked[k] == ' ' || masked[k] == '\t' || masked[k] == '\r' {
				k--
				continue
			}
			if masked[k] == '\n' {
				if prev, ok := prevContNL(k); ok {
					k = prev
					continue
				}
			}
			break
		}
		if k < 0 || masked[k] == '\n' || masked[k] == ';' {
			return true
		}
		return masked[k] == ':' && (k == 0 || masked[k-1] != ':')
	}

	parseTargets := func(seg string, allowNL bool) {
		i := 0
		for i < len(seg) {
			i = pySkipHorizAndCont(seg, i, allowNL)
			if i >= len(seg) {
				break
			}
			if seg[i] == ',' {
				i++
				continue
			}
			if !pyIsIdentByte(seg[i]) || (seg[i] >= '0' && seg[i] <= '9') {
				break
			}
			nEnd := i
			for nEnd < len(seg) && pyIsIdentByte(seg[nEnd]) {
				nEnd++
			}
			orig := seg[i:nEnd]
			bound := orig
			j := pySkipHorizAndCont(seg, nEnd, allowNL)
			if j+2 <= len(seg) && seg[j:j+2] == "as" && (j+2 == len(seg) || !pyIsIdentByte(seg[j+2])) {
				k := pySkipHorizAndCont(seg, j+2, allowNL)
				if k < len(seg) && pyIsIdentByte(seg[k]) && !(seg[k] >= '0' && seg[k] <= '9') {
					aEnd := k
					for aEnd < len(seg) && pyIsIdentByte(seg[aEnd]) {
						aEnd++
					}
					bound = seg[k:aEnd]
					j = pySkipHorizAndCont(seg, aEnd, allowNL)
				}
			}
			out = append(out, pySymTarget{sym: bound, canon: orig})
			i = j
			if i < len(seg) && seg[i] == ',' {
				i++
			}
		}
	}

	for fromIdx := pyNextIdent(masked, 0, "from"); fromIdx >= 0; fromIdx = pyNextIdent(masked, fromIdx+len("from"), "from") {
		if !isBoundaryBefore(fromIdx) {
			continue
		}
		q := pySkipHorizAndCont(masked, fromIdx+len("from"), false)
		var modBuf strings.Builder
		impIdx := -1
		for q < len(masked) {
			if q+len("import") <= len(masked) && masked[q:q+len("import")] == "import" &&
				(q == 0 || !pyIsIdentByte(masked[q-1])) &&
				(q+len("import") == len(masked) || !pyIsIdentByte(masked[q+len("import")])) {
				impIdx = q
				break
			}
			if pyIsIdentByte(masked[q]) {
				s0 := q
				for q < len(masked) && pyIsIdentByte(masked[q]) {
					q++
				}
				modBuf.WriteString(masked[s0:q])
				q = pySkipHorizAndCont(masked, q, false)
				continue
			}
			if masked[q] == '.' {
				modBuf.WriteByte('.')
				q = pySkipHorizAndCont(masked, q+1, false)
				continue
			}
			break
		}
		if impIdx < 0 || modBuf.String() != wantModule {
			continue
		}
		p := pySkipHorizAndCont(masked, impIdx+len("import"), false)
		if p >= len(masked) {
			continue
		}
		if masked[p] == '*' {
			hasStar = true
			continue
		}
		if masked[p] == '(' {
			closeP := pyMatchMatchingDelim(masked, p, '(', ')')
			if closeP < 0 {
				hasStar = true
				continue
			}
			parseTargets(masked[p+1:closeP], true)
			continue
		}
		end := p
		for end < len(masked) {
			if masked[end] == '\n' || masked[end] == ';' {
				break
			}
			nextE := pySkipHorizAndCont(masked, end, false)
			if nextE != end {
				end = nextE
				continue
			}
			end++
		}
		parseTargets(masked[p:end], false)
	}
	return out, hasStar
}

// pyCollectDirectImportModAliases collects local aliases bound by plain
// `import <topMod> as X` (`topAliases`, seeded with topMod itself) and optional
// `import <topMod>.<subMod> as Y` (`subAliases`) statements in masked.
func pyCollectDirectImportModAliases(masked, topMod, subMod string) (topAliases []string, subAliases []string) {
	topAliases = []string{topMod}
	addUniq := func(list []string, s string) []string {
		if s == "" {
			return list
		}
		for _, v := range list {
			if v == s {
				return list
			}
		}
		return append(list, s)
	}
	for idx := pyNextIdent(masked, 0, topMod); idx >= 0; idx = pyNextIdent(masked, idx+len(topMod), topMod) {
		if !isPythonImportStmtAt(masked, idx) {
			continue
		}
		stmtStart, _ := pyImportStmtHeaderStart(masked, idx)
		if !strings.HasPrefix(masked[stmtStart:], "import") || pyNextIdent(masked[stmtStart:idx], 0, "from") >= 0 {
			continue
		}
		prev := idx - 1
		for prev >= stmtStart && (masked[prev] == ' ' || masked[prev] == '\t' || masked[prev] == '\r') {
			prev--
		}
		if prev >= stmtStart && masked[prev] == '.' {
			continue
		}
		d := pySkipHorizAndCont(masked, idx+len(topMod), false)
		if d < len(masked) && masked[d] == '.' {
			if subMod != "" {
				cIdx := pySkipHorizAndCont(masked, d+1, false)
				if cIdx+len(subMod) <= len(masked) && masked[cIdx:cIdx+len(subMod)] == subMod &&
					(cIdx+len(subMod) == len(masked) || !pyIsIdentByte(masked[cIdx+len(subMod)])) {
					if alias := pyImportAliasAfter(masked, cIdx, len(subMod)); alias != "" {
						subAliases = addUniq(subAliases, alias)
					}
				}
			}
			continue
		}
		if alias := pyImportAliasAfter(masked, idx, len(topMod)); alias != "" {
			topAliases = addUniq(topAliases, alias)
		}
	}
	return topAliases, subAliases
}

// pythonStdlibWriteTailHit checks non-ASCII NFKC identifiers, ZipFile/PyZipFile/FileIO
// (including `as` aliases and rebinds), logging file handlers (including BaseRotatingHandler),
// whole-module logging.config usage, logging.basicConfig(filename=/**kw),
// pkgutil.resolve_name & pydoc.{locate,safeimport}, and literal-string reflection
// via getattr/__getattribute__/__dict__/vars/globals/locals on strict-readonly Python code.
func pythonStdlibWriteTailHit(code, masked string) string {
	// 0. Reject non-ASCII bytes in masked code to defeat PEP 3131 NFKC identifier aliases.
	if hit := pyMaskedNonASCIIIdentHit(masked); hit != "" {
		return hit
	}

	addTarget := func(list []pySymTarget, sym, canon string) []pySymTarget {
		if sym == "" {
			return list
		}
		for _, it := range list {
			if it.sym == sym && it.canon == canon {
				return list
			}
		}
		return append(list, pySymTarget{sym: sym, canon: canon})
	}

	// 1. ZipFile / PyZipFile / FileIO + `from ... import X as Y` aliases.
	ctorCanons := []string{"ZipFile", "PyZipFile", "FileIO"}
	ctors := make([]pySymTarget, 0, 6)
	for _, c := range ctorCanons {
		ctors = addTarget(ctors, c, c)
		for idx := pyNextIdent(masked, 0, c); idx >= 0; idx = pyNextIdent(masked, idx+len(c), c) {
			if isPythonImportStmtAt(masked, idx) {
				if alias := pyImportAliasAfter(masked, idx, len(c)); alias != "" {
					ctors = addTarget(ctors, alias, c)
				}
			}
		}
	}
	for _, t := range ctors {
		for idx := pyNextIdent(masked, 0, t.sym); idx >= 0; idx = pyNextIdent(masked, idx+len(t.sym), t.sym) {
			if isPythonImportStmtAt(masked, idx) {
				continue
			}
			k := pySkipHorizAndCont(masked, idx+len(t.sym), false)
			if k >= len(masked) || masked[k] != '(' {
				return "python " + t.canon + " rebind"
			}
			if pyCtorCallIsWrite(code, masked, k, t.canon) {
				return "python " + t.canon + " write"
			}
		}
	}

	// 2. Logging file handlers (all 5 FileHandler classes) + dictConfig/fileConfig + aliases.
	handlerCanons := []string{
		"BaseRotatingHandler",
		"FileHandler",
		"RotatingFileHandler",
		"TimedRotatingFileHandler",
		"WatchedFileHandler",
		"dictConfig",
		"fileConfig",
	}
	handlers := make([]pySymTarget, 0, 12)
	for _, h := range handlerCanons {
		handlers = addTarget(handlers, h, h)
		for idx := pyNextIdent(masked, 0, h); idx >= 0; idx = pyNextIdent(masked, idx+len(h), h) {
			if isPythonImportStmtAt(masked, idx) {
				if alias := pyImportAliasAfter(masked, idx, len(h)); alias != "" {
					handlers = addTarget(handlers, alias, h)
				}
			}
		}
	}
	for _, t := range handlers {
		for idx := pyNextIdent(masked, 0, t.sym); idx >= 0; idx = pyNextIdent(masked, idx+len(t.sym), t.sym) {
			if !isPythonImportStmtAt(masked, idx) {
				return "python logging." + t.canon
			}
		}
	}

	// 3. Whole-module `logging.config` runtime closure:
	// - `from logging.config import *`
	// - any runtime usage of symbols imported via `from logging.config import X [as Y]`
	// - any runtime `<loggingMod>.config[.<attr>]` (where loggingMod is `logging` or `import logging as L`)
	// - any runtime `<lc>[.<attr>]` (where lc comes from `import logging.config as lc` or `from logging import config [as lc]`)
	lcItems, lcStar := pyExtractFromImportItems(masked, "logging.config")
	if lcStar {
		return "python logging.config wildcard import"
	}
	for _, it := range lcItems {
		for idx := pyNextIdent(masked, 0, it.sym); idx >= 0; idx = pyNextIdent(masked, idx+len(it.sym), it.sym) {
			if !isPythonImportStmtAt(masked, idx) {
				return "python logging.config." + it.canon
			}
		}
	}
	loggingMods, lcModSyms := pyCollectDirectImportModAliases(masked, "logging", "config")
	fromLoggingItems, _ := pyExtractFromImportItems(masked, "logging")
	for _, it := range fromLoggingItems {
		if it.canon == "config" {
			lcModSyms = append(lcModSyms, it.sym)
		}
	}
	readTrailingAttr := func(afterObj int) string {
		d := pySkipHorizAndCont(masked, afterObj, false)
		if d < len(masked) && masked[d] == '.' {
			m := pySkipHorizAndCont(masked, d+1, false)
			if m < len(masked) && pyIsIdentByte(masked[m]) && !(masked[m] >= '0' && masked[m] <= '9') {
				e := m
				for e < len(masked) && pyIsIdentByte(masked[e]) {
					e++
				}
				return masked[m:e]
			}
		}
		return ""
	}
	for _, lm := range loggingMods {
		for idx := pyNextIdent(masked, 0, lm); idx >= 0; idx = pyNextIdent(masked, idx+len(lm), lm) {
			if isPythonImportStmtAt(masked, idx) {
				continue
			}
			d := pySkipHorizAndCont(masked, idx+len(lm), false)
			if d < len(masked) && masked[d] == '.' {
				cIdx := pySkipHorizAndCont(masked, d+1, false)
				if cIdx+len("config") <= len(masked) && masked[cIdx:cIdx+len("config")] == "config" &&
					(cIdx+len("config") == len(masked) || !pyIsIdentByte(masked[cIdx+len("config")])) {
					if attr := readTrailingAttr(cIdx + len("config")); attr != "" {
						return "python logging.config." + attr
					}
					return "python logging.config"
				}
			}
		}
	}
	for _, lc := range lcModSyms {
		for idx := pyNextIdent(masked, 0, lc); idx >= 0; idx = pyNextIdent(masked, idx+len(lc), lc) {
			if isPythonImportStmtAt(masked, idx) {
				continue
			}
			if attr := readTrailingAttr(idx + len(lc)); attr != "" {
				return "python logging.config." + attr
			}
			return "python logging.config"
		}
	}

	// 4. `logging.basicConfig(filename=...)` / `basicConfig(**kw)` / rebinds / aliases.
	bcSyms := []string{"basicConfig"}
	for idx := pyNextIdent(masked, 0, "basicConfig"); idx >= 0; idx = pyNextIdent(masked, idx+len("basicConfig"), "basicConfig") {
		if isPythonImportStmtAt(masked, idx) {
			if alias := pyImportAliasAfter(masked, idx, len("basicConfig")); alias != "" {
				bcSyms = append(bcSyms, alias)
			}
		}
	}
	for _, sym := range bcSyms {
		for idx := pyNextIdent(masked, 0, sym); idx >= 0; idx = pyNextIdent(masked, idx+len(sym), sym) {
			if isPythonImportStmtAt(masked, idx) {
				continue
			}
			k := pySkipHorizAndCont(masked, idx+len(sym), false)
			if k >= len(masked) || masked[k] != '(' {
				return "python logging.basicConfig rebind"
			}
			closeP := pyMatchMatchingDelim(masked, k, '(', ')')
			if closeP < 0 {
				return "python logging.basicConfig"
			}
			for _, sp := range pySplitTopLevelArgs(masked, k, closeP) {
				if masked[sp[0]] == '*' {
					return "python logging.basicConfig unpack"
				}
				if kw, _, ok := pyTopLevelKeywordEq(masked, sp[0], sp[1]); ok && kw == "filename" {
					return "python logging.basicConfig filename"
				}
			}
		}
	}

	// 5. Dynamic string-import resolvers: `pkgutil.resolve_name` & `pydoc.{locate,safeimport}`.
	rnSyms := []string{"resolve_name"}
	for idx := pyNextIdent(masked, 0, "resolve_name"); idx >= 0; idx = pyNextIdent(masked, idx+len("resolve_name"), "resolve_name") {
		if isPythonImportStmtAt(masked, idx) {
			if alias := pyImportAliasAfter(masked, idx, len("resolve_name")); alias != "" {
				rnSyms = append(rnSyms, alias)
			}
		}
	}
	for _, sym := range rnSyms {
		for idx := pyNextIdent(masked, 0, sym); idx >= 0; idx = pyNextIdent(masked, idx+len(sym), sym) {
			if !isPythonImportStmtAt(masked, idx) {
				return "python pkgutil.resolve_name"
			}
		}
	}
	pydocMods, _ := pyCollectDirectImportModAliases(masked, "pydoc", "")
	for _, pm := range pydocMods {
		for idx := pyNextIdent(masked, 0, pm); idx >= 0; idx = pyNextIdent(masked, idx+len(pm), pm) {
			if isPythonImportStmtAt(masked, idx) {
				continue
			}
			if attr := readTrailingAttr(idx + len(pm)); attr == "locate" || attr == "safeimport" {
				return "python pydoc." + attr
			}
		}
	}
	pydocItems, pydocStar := pyExtractFromImportItems(masked, "pydoc")
	var pydocTargets []pySymTarget
	if pydocStar {
		pydocTargets = append(pydocTargets,
			pySymTarget{sym: "locate", canon: "locate"},
			pySymTarget{sym: "safeimport", canon: "safeimport"},
		)
	}
	for _, it := range pydocItems {
		if it.canon == "locate" || it.canon == "safeimport" {
			pydocTargets = addTarget(pydocTargets, it.sym, it.canon)
		}
	}
	for _, t := range pydocTargets {
		for idx := pyNextIdent(masked, 0, t.sym); idx >= 0; idx = pyNextIdent(masked, idx+len(t.sym), t.sym) {
			if !isPythonImportStmtAt(masked, idx) {
				return "python pydoc." + t.canon
			}
		}
	}

	// 6. Narrow fail-closed reflection on sensitive target string literals:
	// `getattr`, `__getattribute__`, `.__dict__`, `vars`, `globals`, `locals`.
	osMods, _ := pyCollectDirectImportModAliases(masked, "os", "")
	isOSMod := func(expr string) bool {
		for _, m := range osMods {
			if expr == m {
				return true
			}
		}
		return false
	}
	getattrSyms := []string{"getattr"}
	for idx := pyNextIdent(masked, 0, "getattr"); idx >= 0; idx = pyNextIdent(masked, idx+len("getattr"), "getattr") {
		if isPythonImportStmtAt(masked, idx) {
			if alias := pyImportAliasAfter(masked, idx, len("getattr")); alias != "" {
				getattrSyms = append(getattrSyms, alias)
			}
		}
	}
	for _, sym := range getattrSyms {
		for idx := pyNextIdent(masked, 0, sym); idx >= 0; idx = pyNextIdent(masked, idx+len(sym), sym) {
			if isPythonImportStmtAt(masked, idx) {
				continue
			}
			k := pySkipHorizAndCont(masked, idx+len(sym), false)
			if k < len(masked) && masked[k] == '(' {
				closeP := pyMatchMatchingDelim(masked, k, '(', ')')
				if closeP > k+1 {
					args := pySplitTopLevelArgs(masked, k, closeP)
					if len(args) >= 2 {
						if val, prefix, ok := pyUnquoteStringLiteral(code[args[1][0]:args[1][1]]); ok && !strings.ContainsAny(prefix, "fF") {
							if pySensitiveReflectNames[val] {
								return "python getattr " + val
							}
							if val == "system" && isOSMod(pyTrimContinuationSpan(masked[args[0][0]:args[0][1]])) {
								return "python getattr system"
							}
						}
					}
				}
			}
		}
	}
	for idx := pyNextIdent(masked, 0, "__getattribute__"); idx >= 0; idx = pyNextIdent(masked, idx+len("__getattribute__"), "__getattribute__") {
		k := pySkipHorizAndCont(masked, idx+len("__getattribute__"), false)
		if k < len(masked) && masked[k] == '(' {
			closeP := pyMatchMatchingDelim(masked, k, '(', ')')
			if closeP > k+1 {
				args := pySplitTopLevelArgs(masked, k, closeP)
				checkSlots := []int{0}
				if len(args) >= 2 {
					checkSlots = []int{0, 1}
				}
				for _, sl := range checkSlots {
					if sl < len(args) {
						if val, prefix, ok := pyUnquoteStringLiteral(code[args[sl][0]:args[sl][1]]); ok &&
							!strings.ContainsAny(prefix, "fF") && pySensitiveReflectNames[val] {
							return "python __getattribute__ " + val
						}
					}
				}
			}
		}
	}
	for idx := pyNextIdent(masked, 0, "__dict__"); idx >= 0; idx = pyNextIdent(masked, idx+len("__dict__"), "__dict__") {
		if hit := pyCheckDictSubscriptOrGet(code, masked, idx+len("__dict__"), "__dict__"); hit != "" {
			return hit
		}
	}
	for _, fn := range []string{"vars", "globals", "locals"} {
		for idx := pyNextIdent(masked, 0, fn); idx >= 0; idx = pyNextIdent(masked, idx+len(fn), fn) {
			k := pySkipHorizAndCont(masked, idx+len(fn), false)
			if k < len(masked) && masked[k] == '(' {
				closeP := pyMatchMatchingDelim(masked, k, '(', ')')
				if closeP >= 0 {
					if hit := pyCheckDictSubscriptOrGet(code, masked, closeP+1, fn); hit != "" {
						return hit
					}
				}
			}
		}
	}

	return ""
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
	// RFC 3986 / sqlite3ParseUri: '#' terminates path and query; fragment
	// content is ignored. Truncate before looking for '?' so a forged
	// fragment like file:x.db#?mode=ro cannot fake read-only mode.
	if hash := strings.IndexByte(uri, '#'); hash >= 0 {
		uri = uri[:hash]
	}
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
