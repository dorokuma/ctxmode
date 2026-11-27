package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

// preparedShell is the unique prepared artifact for shell-text execution.
// Downstream runners consume only execCode; audit/batchResult keep rawCode.
type preparedShell struct {
	rawCode   string
	execCode  string // empty when blocked
	execStdin string // prepared stdin payload ("" = run the caller's stdin)
	rule      string
	detail    string
}

// preparedArgv is the unique prepared artifact for argv (+ optional stdin) execution.
type preparedArgv struct {
	rawArgv   []string
	execArgv  []string // nil when blocked
	execStdin string
	rule      string
	detail    string
}

// hcEditKind tags which synthetic node one buffer edit mints: a rewritten
// `headWord -> '<selfExe>' --hc-gate` leaf (Type-A) or a rewritten
// `sh -c '…'` script word (Type-B). Only prepare* may mint these kinds.
type hcEditKind uint8

const (
	hcEditLeafGate hcEditKind = iota + 1 // Type-A: headWord -> '<selfExe>' --hc-gate
	hcEditInnerSh                        // Type-B: scriptWord -> '<innerRewritten>'
)

type byteEdit struct {
	lo, hi    int
	repl      string
	kind      hcEditKind
	quotedLen int               // Type-A: len(shellSingleQuote(selfExe))
	innerText string            // Type-B: innerRewritten (unquoted decoded script)
	innerProv *hcGateProvenance // Type-B: provenance of the inner buffer
}

// gateCallSpan records the exact [Pos, End) spans of one prepare*-minted
// `'<selfExe>' --hc-gate` call inside the REWRITTEN buffer. The span is the
// only structural evidence that a --hc-gate invocation came from the
// rewriter — never argv shape, SameFile, or a diagnostic string.
type gateCallSpan struct {
	headLo, headHi int // rewritten-buffer span of the '<selfExe>' word
	flagLo, flagHi int // rewritten-buffer span of the --hc-gate word
}

// innerScriptProv records the span + expected decoded text of a Type-B
// script word inside the rewritten buffer, plus the child buffer's
// provenance: only a cross-buffer match on ALL of (buffer identity, span,
// decoded text) transfers hcProv into the nested -c payload.
type innerScriptProv struct {
	scriptLo, scriptHi int
	innerText          string
	prov               *hcGateProvenance
}

// hcGateProvenance binds one rewritten buffer to the synthetic gate calls
// and inner scripts the rewriter minted inside it. A pure-check caller
// always carries hcProv == nil; a raw user-typed `--hc-gate` can therefore
// never be mistaken for a prepare*-minted call.
type hcGateProvenance struct {
	code       string
	gateSpans  []gateCallSpan
	innerProvs []innerScriptProv
}

// hasGateCall reports whether head/flag are the exact rewritten-buffer WORD
// spans of a minted `'<selfExe>' --hc-gate` pair.
func (p *hcGateProvenance) hasGateCall(code string, headWord, flagWord *syntax.Word) bool {
	if p == nil || p.code != code || headWord == nil || flagWord == nil {
		return false
	}
	hLo, hHi := int(headWord.Pos().Offset()), int(headWord.End().Offset())
	fLo, fHi := int(flagWord.Pos().Offset()), int(flagWord.End().Offset())
	for _, s := range p.gateSpans {
		if s.headLo == hLo && s.headHi == hHi && s.flagLo == fLo && s.flagHi == fHi {
			return true
		}
	}
	return false
}

// innerProvAt returns the child provenance for a Type-B script word only
// when the word's span AND its decoded text exactly match the recorded
// Type-B slot of this buffer. Any other cross-buffer jump (eval, env -S,
// ssh, heredoc, watch, flock -c, script -c, interpreter code, …) carries
// nil provenance by construction — callers simply do not ask.
func (p *hcGateProvenance) innerProvAt(code string, scriptWord *syntax.Word, decodedText string) *hcGateProvenance {
	if p == nil || p.code != code || scriptWord == nil {
		return nil
	}
	lo, hi := int(scriptWord.Pos().Offset()), int(scriptWord.End().Offset())
	for _, ip := range p.innerProvs {
		if ip.scriptLo == lo && ip.scriptHi == hi && ip.innerText == decodedText {
			return ip.prov
		}
	}
	return nil
}

// shellSingleQuote wraps s in POSIX single quotes suitable for /bin/sh.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// applyHcGateEdits applies non-overlapping edits low-to-high and mints the
// hcGateProvenance of the rewritten buffer in the same pass: every Type-A
// edit records the exact new-buffer span of its '<selfExe>' + --hc-gate
// words, every Type-B edit records the new-buffer span of the rewritten
// script word plus the child buffer's provenance. A zero-width or
// out-of-range edit is a hard error — there is no fallback to raw code.
func applyHcGateEdits(buf string, edits []byteEdit) (string, *hcGateProvenance, error) {
	prov := &hcGateProvenance{code: buf}
	if len(edits) == 0 {
		return buf, prov, nil
	}
	sorted := append([]byteEdit(nil), edits...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].lo != sorted[j].lo {
			return sorted[i].lo < sorted[j].lo
		}
		return sorted[i].hi < sorted[j].hi
	})
	// Dedup identical intervals with identical replacement (kind included:
	// two different provenance kinds on one span can never be deduped).
	dedup := sorted[:0]
	for i, e := range sorted {
		if i > 0 && e.lo == sorted[i-1].lo && e.hi == sorted[i-1].hi &&
			e.repl == sorted[i-1].repl && e.kind == sorted[i-1].kind {
			continue
		}
		dedup = append(dedup, e)
	}
	sorted = dedup
	for i, e := range sorted {
		if e.lo < 0 || e.hi <= e.lo || e.hi > len(buf) {
			return "", nil, fmt.Errorf("edit out of range")
		}
		if i > 0 && sorted[i-1].hi > e.lo {
			return "", nil, fmt.Errorf("overlapping edits")
		}
	}
	var b strings.Builder
	b.Grow(len(buf) + 64)
	cursor := 0
	for _, e := range sorted {
		b.WriteString(buf[cursor:e.lo])
		newLo := b.Len()
		b.WriteString(e.repl)
		newHi := b.Len()
		switch e.kind {
		case hcEditLeafGate:
			// repl = '<selfExe>' --hc-gate ; quotedLen covers '<selfExe>'.
			prov.gateSpans = append(prov.gateSpans, gateCallSpan{
				headLo: newLo,
				headHi: newLo + e.quotedLen,
				flagLo: newLo + e.quotedLen + 1,
				flagHi: newHi,
			})
		case hcEditInnerSh:
			prov.innerProvs = append(prov.innerProvs, innerScriptProv{
				scriptLo:  newLo,
				scriptHi:  newHi,
				innerText: e.innerText,
				prov:      e.innerProv,
			})
		}
		cursor = e.hi
	}
	b.WriteString(buf[cursor:])
	out := b.String()
	prov.code = out
	return out, prov, nil
}

// isGuaranteedSingleArgWord reports an AST word that expands to exactly one
// argv word. See C3 §3.2. bashANSI allows $'...' (bash dialect only).
func isGuaranteedSingleArgWord(w *syntax.Word, bashANSI bool) bool {
	if w == nil || len(w.Parts) == 0 {
		return false
	}
	openBracket := false
	wordStart := true
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if litHasUnquotedGlobOrTilde(p.Value, wordStart, &openBracket) {
				return false
			}
			if litHasResidualExpand(p.Value) {
				return false
			}
			if p.Value != "" {
				wordStart = false
			}
		case *syntax.SglQuoted:
			if p.Dollar {
				if !bashANSI {
					return false
				}
				// $'...' is always a single word; gate catches controls.
			}
			wordStart = false
		case *syntax.DblQuoted:
			if p.Dollar {
				return false // $"..."
			}
			if !dblQuotedIsSingleArg(p) {
				return false
			}
			wordStart = false
		default:
			// Unquoted ParamExp / CmdSubst / ArithmExp / ProcSubst / ExtGlob / BraceExp
			return false
		}
	}
	return true
}

func dblQuotedIsSingleArg(p *syntax.DblQuoted) bool {
	for _, ip := range p.Parts {
		switch pe := ip.(type) {
		case *syntax.Lit:
			continue
		case *syntax.CmdSubst, *syntax.ArithmExp:
			continue
		case *syntax.ParamExp:
			if pe.Param != nil && pe.Param.Value == "@" {
				return false
			}
			if paramExpHasAtIndex(pe) {
				return false
			}
			if pe.Exp != nil && pe.Exp.Word != nil && wordHasAtSplitExpansion(pe.Exp.Word) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func paramExpHasAtIndex(pe *syntax.ParamExp) bool {
	if pe == nil || pe.Index == nil {
		return false
	}
	// ${a[@]} is an ArithmExpr Word whose lit is "@"; ${a[*]} stays single-arg.
	if w, ok := pe.Index.(*syntax.Word); ok {
		if len(w.Parts) == 1 {
			if lit, ok := w.Parts[0].(*syntax.Lit); ok {
				return lit.Value == "@"
			}
		}
		return wordHasAtSplitExpansion(w)
	}
	return false
}

// wordHasAtSplitExpansion reports whether an EXPANSION word (the Exp side
// of ${x:-…} etc.) can field-split into multiple argv words at runtime.
// It checks only REAL expansions — a plain literal "@" inside an expansion
// default (`${x:-@}`) is data, NOT the `$@` array expansion, so *syntax.Lit
// is never a split on its own (fixes the `${x:-@}` false kill). Nested
// ParamExp / DblQuoted recursion covers `${x:-${y:-$@}}` and `${x:-"$@"}`.
func wordHasAtSplitExpansion(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.ParamExp:
			if paramExpSplitsInDblQuotes(p) {
				return true
			}
		case *syntax.DblQuoted:
			for _, ip := range p.Parts {
				switch ipp := ip.(type) {
				case *syntax.ParamExp:
					if paramExpSplitsInDblQuotes(ipp) {
						return true
					}
				case *syntax.CmdSubst, *syntax.ArithmExp:
					// Dynamic content inside the expansion default: treated
					// conservatively by the caller's own dynamic-word rules,
					// not an @-split.
				}
			}
		}
	}
	return false
}

// paramExpSplitsInDblQuotes reports whether a double-quoted ${...}/$@
// parameter expansion can field-split into multiple argv words at runtime
// (and therefore must NOT be emitted as a split-safe cmdSubPlaceholderQuoted).
// Unlike "$PWD" (single value), "$@" / "${arr[@]}" / "${!prefix@}" /
// "${x:-$@}" expand to one word PER element even inside double quotes.
// Returns true when pe != nil && !pe.Length (a ${#...} length is always one
// integer word) and any of:
//   - pe.Param.Value == "@"         — $@, ${@}, ${@:1}, ${@/#a/b}, ${@@Q}
//   - pe.Names == NamesPrefixWords  — "${!prefix@}" (names list, splits)
//   - paramExpHasAtIndex(pe)          — "${arr[@]}" and "${!arr[@]}"
//   - pe.Exp.Word carries an @-split — "${x:-$@}", "${x:+$@}",
//     "${x:-\"${arr[@]}\"}" ("${x:-@}" literal stays false via
//     wordHasAtSplitExpansion)
func paramExpSplitsInDblQuotes(pe *syntax.ParamExp) bool {
	if pe == nil || pe.Length {
		return false
	}
	if pe.Param != nil && pe.Param.Value == "@" {
		return true
	}
	if pe.Names == syntax.NamesPrefixWords {
		return true
	}
	if paramExpHasAtIndex(pe) {
		return true
	}
	if pe.Exp != nil && pe.Exp.Word != nil && wordHasAtSplitExpansion(pe.Exp.Word) {
		return true
	}
	return false
}

// wordIsStaticLiteral reports a word with no dynamic AST nodes (safe command head).
// A non-$ double-quoted word whose parts are ALL residue-free literals
// counts too (`bash -c "hc send t42 static"`), while any CmdSubst/ParamExp
// inside the quotes keeps the word dynamic.
func wordIsStaticLiteral(w *syntax.Word) bool {
	if w == nil || len(w.Parts) == 0 {
		return false
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if litHasResidualExpand(p.Value) {
				return false
			}
		case *syntax.SglQuoted:
			if p.Dollar {
				return false
			}
		case *syntax.DblQuoted:
			if p.Dollar {
				return false
			}
			for _, ip := range p.Parts {
				lit, ok := ip.(*syntax.Lit)
				if !ok || litHasResidualExpand(lit.Value) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

var hcGateSafeWrappers = map[string]bool{
	"time": true, "env": true, "command": true, "nohup": true, "setsid": true,
	"nice": true, "timeout": true, "stdbuf": true, "ionice": true,
	"taskset": true, "chrt": true,
}

// hcGateUnsafePeelBases are wrapper bases that ALWAYS surrender word-index
// provenance: they re-arrange or re-exec the child argv in ways the
// word-level rewrite cannot bound, so any hc send behind them must stay
// unrewritten and face the ordinary guard (fail-closed).
func hcGateUnsafePeelBase(b string) bool {
	switch b {
	case "exec", "builtin", "busybox", "strace", "ltrace":
		return true
	}
	return false
}

// peelWrappersWithIndex consumes argv FORWARD from index 0, tracking the
// exact head position so a Type-A rewrite always lands on a real word.
// Provenance is surrendered (headIdx=-1) the moment the walk meets:
// `env -S`/`--split-string` in ANY spelling (long, short cluster, glued
// value), `env -i`/clear ops, a non-whitelisted or unsafe wrapper (exec,
// builtin, busybox, strace, ltrace), a PATH-alias whose resolved name
// IS a wrapper, a dynamic word inside a wrapper's option zone, or peel
// exhaustion. The old suffix-match shortcut ("find the peeled head back in
// argv") is gone — `env -S "exec --" hc …` can no longer satisfy it.
func peelWrappersWithIndex(argv []string, caller callerIdentity) (headArgv []string, headIdx int, wrappers []string, envAs envAssignments, exhausted bool) {
	basePath := caller.effectivePATH()
	effPath := envAs.effectivePATHFrom(basePath)
	effCwd := caller.screenCwd()
	i := 0
	steps := 0
	for ; steps < peelWrapperMaxSteps && i < len(argv); steps++ {
		a := argv[i]
		if isAssignWord(a) {
			envAs.addAssign(a)
			effPath = envAs.effectivePATHFrom(basePath)
			i++
			steps--
			continue
		}
		if shellNoopWords[a] {
			i++
			steps--
			continue
		}
		switch a {
		case "if", "then", "elif", "else", "while", "until", "do", "!", "coproc", "--":
			i++
			continue
		}
		if isDynamicArg(a) {
			return argv[i:], i, wrappers, envAs, false
		}
		base := filepath.Base(a)
		rb := canonicalResolvedBase(resolveHeadBase(a, effPath, effCwd))
		if hcGateUnsafePeelBase(rb) {
			return argv[i:], -1, nil, envAs, false
		}
		// A typed name resolving to a DIFFERENT wrapper (myenv -> env)
		// is an alias-wrapped head: provenance is void either way.
		if rb != "" && rb != base && isPeeledWrapperBase(rb) {
			return argv[i:], -1, nil, envAs, false
		}
		if hcGateUnsafePeelBase(base) {
			return argv[i:], -1, nil, envAs, false
		}
		switch base {
		case "env":
			// Forward env scan honouring ONLY the env grammar; -S in any
			// spelling, env -i and unknown/dynamic options lose provenance.
			i++
			wrappers = append(wrappers, "env")
			for i < len(argv) {
				w := argv[i]
				if w == "--" {
					i++
					break
				}
				if isDynamicArg(w) {
					return argv[i:], -1, nil, envAs, false
				}
				if strings.HasPrefix(w, "--") {
					name := strings.TrimPrefix(w, "--")
					if strings.HasPrefix(name, "split-string") {
						return argv[i:], -1, nil, envAs, false
					}
					switch {
					case name == "ignore-environment":
						envAs.ops = append(envAs.ops, envOp{kind: 'c'})
						i++
						continue
					case name == "unset":
						if i+1 >= len(argv) {
							return argv[i:], -1, nil, envAs, false
						}
						envAs.ops = append(envAs.ops, envOp{kind: 'u', key: argv[i+1]})
						i += 2
						continue
					case strings.HasPrefix(name, "unset="):
						envAs.ops = append(envAs.ops, envOp{kind: 'u', key: name[len("unset="):]})
						i++
						continue
					case name == "chdir":
						if i+1 >= len(argv) {
							return argv[i:], -1, nil, envAs, false
						}
						envAs.ops = append(envAs.ops, envOp{kind: 'd', value: argv[i+1]})
						i += 2
						continue
					case name == "argv0":
						if i+1 >= len(argv) {
							return argv[i:], -1, nil, envAs, false
						}
						i += 2
						continue
					case strings.HasPrefix(name, "chdir="):
						envAs.ops = append(envAs.ops, envOp{kind: 'd', value: name[len("chdir="):]})
						i++
						continue
					case strings.HasPrefix(name, "argv0="):
						i++
						continue
					case name == "null" || name == "version" || name == "help":
						i++
						continue
					case name == "block-signal" || name == "default-signal" || name == "ignore-signal":
						i++
						continue
					default:
						return argv[i:], -1, nil, envAs, false
					}
				}
				if strings.HasPrefix(w, "-") && w != "-" {
					// short option cluster
					consumed := false
					bad := false
					for j := 1; j < len(w); j++ {
						switch w[j] {
						case '0', 'v':
							continue
						case 'i':
							envAs.ops = append(envAs.ops, envOp{kind: 'c'})
							continue
						case 'S':
							return argv[i:], -1, nil, envAs, false
						case 'u', 'C', 'a':
							if j+1 < len(w) {
								// glued value
								if w[j] == 'u' {
									envAs.ops = append(envAs.ops, envOp{kind: 'u', key: w[j+1:]})
								}
								if w[j] == 'C' {
									envAs.ops = append(envAs.ops, envOp{kind: 'd', value: w[j+1:]})
								}
								j = len(w)
								continue
							}
							if i+1 >= len(argv) {
								bad = true
								j = len(w)
								break
							}
							if w[j] == 'u' {
								envAs.ops = append(envAs.ops, envOp{kind: 'u', key: argv[i+1]})
							}
							if w[j] == 'C' {
								envAs.ops = append(envAs.ops, envOp{kind: 'd', value: argv[i+1]})
							}
							consumed = true
							j = len(w)
						default:
							bad = true
							j = len(w)
						}
					}
					if bad {
						return argv[i:], -1, nil, envAs, false
					}
					if consumed {
						i += 2
					} else {
						i++
					}
					continue
				}
				if isAssignWord(w) {
					envAs.addAssign(w)
					i++
					continue
				}
				// first operand → env's program; loop continues at it
				goto envDone
			}
		envDone:
			effPath = envAs.effectivePATHFrom(basePath)
			effCwd = caller.seededCwdWith(envAs).screenCwd()
			// A `d` op with an empty or dynamic target can never re-anchor the
			// slot walk to a knowable directory — surrender provenance like an
			// env -i (R3 MF-2), matching peelResolvedSegDepth's fail-closed hit.
			for _, op := range envAs.ops {
				if op.kind == 'd' && (op.value == "" || isDynamicArg(op.value)) {
					return argv[i:], -1, nil, envAs, false
				}
			}
		case "time":
			i++
			wrappers = append(wrappers, "time")
			for i < len(argv) {
				w := argv[i]
				if w == "--" {
					i++
					break
				}
				if isDynamicArg(w) {
					return argv[i:], -1, nil, envAs, false
				}
				if !strings.HasPrefix(w, "-") || w == "-" {
					break
				}
				if w == "-o" || w == "--output" || w == "-f" || w == "--format" {
					i += 2
					continue
				}
				i++
			}
		case "command":
			i++
			wrappers = append(wrappers, "command")
			if isCommandQuery(argv[i:]) {
				return argv[i-1:], i - 1, wrappers[:len(wrappers)-1], envAs, false
			}
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				if isDynamicArg(argv[i]) {
					return argv[i:], -1, nil, envAs, false
				}
				i++
			}
			i = skipDashDash(argv, i)
		case "nohup":
			i++
			wrappers = append(wrappers, "nohup")
			i = skipDashDash(argv, i)
		case "setsid":
			i++
			wrappers = append(wrappers, "setsid")
			for i < len(argv) {
				w := argv[i]
				if w == "--" {
					i++
					break
				}
				if isDynamicArg(w) {
					return argv[i:], -1, nil, envAs, false
				}
				if !strings.HasPrefix(w, "-") || w == "-" {
					break
				}
				i++
			}
		case "nice":
			i++
			wrappers = append(wrappers, "nice")
			for i < len(argv) {
				w := argv[i]
				if w == "--" {
					i++
					break
				}
				if isDynamicArg(w) {
					return argv[i:], -1, nil, envAs, false
				}
				if !strings.HasPrefix(w, "-") || w == "-" {
					break
				}
				if w == "-n" || w == "--adjustment" {
					i += 2
					continue
				}
				i++
			}
		case "timeout":
			i++
			wrappers = append(wrappers, "timeout")
			var fc bool
			i, fc = skipTimeoutArgs(argv, i)
			if fc {
				return argv[i:], -1, nil, envAs, false
			}
		case "stdbuf":
			i++
			wrappers = append(wrappers, "stdbuf")
			var fc bool
			i, fc = skipStdbufArgs(argv, i)
			if fc {
				return argv[i:], -1, nil, envAs, false
			}
		case "ionice":
			i++
			wrappers = append(wrappers, "ionice")
			var fc bool
			i, fc = skipIoniceArgs(argv, i)
			if fc {
				return argv[i:], -1, nil, envAs, false
			}
		case "taskset":
			i++
			wrappers = append(wrappers, "taskset")
			var fc bool
			i, fc = skipTasksetArgs(argv, i)
			if fc {
				return argv[i:], -1, nil, envAs, false
			}
		case "chrt":
			i++
			wrappers = append(wrappers, "chrt")
			var fc bool
			i, fc = skipChrtArgs(argv, i)
			if fc {
				return argv[i:], -1, nil, envAs, false
			}
		default:
			return argv[i:], i, wrappers, envAs, false
		}
	}
	if i >= len(argv) {
		return argv[len(argv):], -1, nil, envAs, steps >= peelWrapperMaxSteps
	}
	return argv[i:], -1, nil, envAs, true
}

// locateShellCSlot finds the argv index of the `shell -c` script operand,
// mirroring unwrapShellArgv's option-zone walk word for word: the bare
// terminators `--` / `-` (and the dash-only `+` after a pending -c) end
// option parsing and the word right AFTER them is the command string, so
// `bash -c -- 'echo ok'` locates slot 4 exactly like the unwrap decodes it
// (R17-Oracle-M5 — the former implementation read `--` itself as the
// script word and production prepare rewrote a slot the guard never
// screened). When the 'c' carries a glued/ambiguous tail (-cCODE, -ce,
// -co errexit) the slot is NOT a clean script word: glued reports true
// with the decoded unwrapped text so callers can fail closed on dynamic
// hc and otherwise leave the argv alone for the ordinary guard.
func locateShellCSlot(argv []string) (scriptIdx int, rawScript string, glued bool, ok bool) {
	text, has := unwrapShellArgv(argv)
	if !has {
		return -1, "", false, false
	}
	if len(argv) < 2 {
		return -1, "", false, false
	}
	sawC := false
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if isDynamicArg(a) {
			return -1, "", false, false
		}
		if a == "--" || a == "-" || (sawC && a == "+") {
			// POSIX option terminator: after a pending -c the NEXT word is
			// the command string (mirroring unwrapShellWordStep); before it
			// the positional zone ends any -c semantics at all.
			if !sawC || i+1 >= len(argv) {
				return -1, "", false, false
			}
			if isDynamicArg(argv[i+1]) {
				return -1, "", false, false
			}
			return i + 1, argv[i+1], false, true
		}
		if strings.HasPrefix(a, "--") {
			name, val, hasVal := a[2:], "", false
			if k := strings.IndexByte(name, '='); k >= 0 {
				name, val, hasVal = name[:k], name[k+1:], true
			}
			switch name {
			case "rcfile", "init-file":
				if !hasVal {
					if i+1 >= len(argv) {
						return -1, "", false, false
					}
					i++
					val = argv[i]
				}
				if val != "/dev/null" {
					return -1, "", false, false
				}
			}
			continue
		}
		if a == "-o" || a == "+o" || a == "-O" || a == "+O" {
			// The option-NAME operand: after a pending -c a dynamic name
			// re-parses as further options at runtime — the slot can never
			// be statically located then (mirrors unwrapShellWordStep).
			if sawC && i+1 < len(argv) && isDynamicArg(argv[i+1]) {
				return -1, "", false, false
			}
			i++
			continue
		}
		if len(a) > 1 && (a[0] == '-' || a[0] == '+') && !strings.HasPrefix(a, "--") {
			var ni int
			var dynName bool
			sawC, ni, dynName, glued = scanShellCClusterWord(argv, i, sawC)
			if dynName {
				return -1, "", false, false
			}
			if glued {
				return -1, text, true, true
			}
			i = ni
			continue
		}
		// First non-option word: with a pending -c it IS the command
		// string; without one the shell runs a script FILE and nothing
		// can be located.
		if sawC {
			return i, a, false, true
		}
		return -1, "", false, false
	}
	return -1, "", false, false
}

// scanShellCClusterWord advances locateShellCSlot past one short-option
// cluster word (extracted for the v6.2.2 R17 complexity budget): the 'c'
// letter arms the pending state, a second 'c' after a pending -c stays a
// plain flag (mirroring unwrapShellClusterWord), a trailing bare -o/-O
// consumes the next argv as its option name, and a non-empty tail after
// 'c' marks the slot glued. ni is the argv index the caller continues
// from, dynName reports a dynamic option-name operand after a pending -c.
func scanShellCClusterWord(argv []string, i int, sawC bool) (newSawC bool, ni int, dynName, glued bool) {
	// R18-Oracle-S1: the pending -c state must survive a cluster that does
	// not itself carry a 'c' — `bash -c -e 'echo ok'` keeps sawC armed
	// across the -e word exactly like unwrapShellArgv's caller-side
	// tracking, so the positional command string is still located.
	newSawC = sawC
	a := argv[i]
	plus := a[0] == '+'
	for j := 1; j < len(a); j++ {
		ch := a[j]
		if ch == 'c' && !plus {
			if sawC {
				continue // a second c is a flag letter, not a new slot
			}
			if a[j+1:] != "" {
				return sawC, i, false, true // glued tail — no clean script word
			}
			newSawC = true
			continue
		}
		if ch == 'o' || ch == 'O' {
			if j+1 >= len(a) {
				if i+1 < len(argv) && sawC && isDynamicArg(argv[i+1]) {
					return newSawC, i, true, false
				}
				return newSawC, i + 1, false, false // consumes the option NAME
			}
			return newSawC, i, false, false
		}
	}
	return newSawC, i, false, false
}

// mergeEnvTaint returns base ∪ extra without mutating either map.
func mergeEnvTaint(base, extra map[string]bool) map[string]bool {
	if len(extra) == 0 {
		return base
	}
	out := make(map[string]bool, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k := range extra {
		out[k] = true
	}
	return out
}

// hcShellDialectBash reports whether head0 runs a bash-family shell, judging
// BOTH the typed name and the PATH/symlink-resolved name so `sh -> bash`
// payloads are parsed as bash while `sh -> dash` stays POSIX.
func hcShellDialectBash(head0, effPath string, caller callerIdentity) bool {
	bashFamily := func(b string) bool {
		switch b {
		case "bash", "zsh", "ksh", "mksh":
			return true
		}
		return false
	}
	if bashFamily(canonicalResolvedBase(filepath.Base(head0))) {
		return true
	}
	if rb := canonicalResolvedBase(resolveHeadBase(head0, effPath, caller.screenCwd())); rb != "" && bashFamily(rb) {
		return true
	}
	return false
}

// collectHcGateEdits walks one source buffer and returns Type-A/Type-B edits.
// bashANSI enables $'...' in isGuaranteedSingleArgWord (bash -c payloads only).
// strictReadonly selects the read-only admission rules: only a bare literal
// `hc` at head index 0 may be rewritten (no wrappers, no assigns, no
// /tmp/hc, no herdr-core), and Type-B (sh -c) is never rewritten at all.
func collectHcGateEdits(code, selfExe string, envTaint map[string]bool, bashANSI, strictReadonly bool, caller callerIdentity) (edits []byteEdit, rule, detail string) {
	segs, ok := parseSubagentShellASTEnv(code, 0, false, bashANSI, envTaint, caller)
	if !ok {
		// Preserve fail-closed: if parse produced a parseErr/depth segment, let
		// the later guard surface it; no edits.
		return nil, "", ""
	}
	for _, seg := range segs {
		if seg.depthExceeded || seg.parseErr != "" {
			continue
		}
		if len(seg.argv) == 0 {
			continue
		}
		// 主副方言交叉校验: the primary dialect tree is the ONLY source of
		// rewrite decisions. A segment that only the secondary tree produced
		// must never be edited (its word boundaries belong to a command shape
		// the primary tree did not see) — and a dynamic hc send hiding there is
		// not silently dropped, it fails closed.
		if seg.secondaryDialect {
			if hit := secondaryDialectHcHit(seg); hit != "" {
				return nil, ruleSubagentNestedAgent, hit
			}
			continue
		}
		// Type-B: static sh/bash -c script word — recurse then replace whole word.
		if e, r, d := collectInnerShellScriptEdit(seg, selfExe, envTaint, strictReadonly, caller); r != "" {
			return nil, r, d
		} else if e != nil {
			edits = append(edits, *e)
			continue
		}
		e, r, d := collectLeafHcEdit(seg, selfExe, bashANSI, strictReadonly, caller)
		if r != "" {
			return nil, r, d
		}
		if e != nil {
			edits = append(edits, *e)
		}
	}
	return edits, "", ""
}

// secondaryDialectHcHit reports a dynamic hc send that only the secondary
// dialect tree sees. Such a segment is never rewritten (the primary tree did
// not confirm the command shape), so the payload would otherwise reach the
// shell untouched — fail closed instead.
func secondaryDialectHcHit(seg shellSegment) string {
	if len(seg.argv) == 0 {
		return ""
	}
	dynamic := false
	for _, a := range seg.argv {
		if isDynamicArg(a) {
			dynamic = true
			break
		}
	}
	if !dynamic {
		return ""
	}
	words := seg.argWords
	if len(words) != len(seg.argv) {
		words = nil
	}
	for i, a := range seg.argv {
		pref := a
		if words != nil && words[i] != nil {
			pref = staticWordPrefix(words[i])
		}
		if pref == "" || isDynamicArg(pref) {
			continue
		}
		switch canonicalResolvedBase(filepath.Base(pref)) {
		case "hc", "herdr-core":
			return "hc send (secondary dialect)"
		}
	}
	return ""
}

func collectInnerShellScriptEdit(seg shellSegment, selfExe string, envTaint map[string]bool, strictReadonly bool, caller callerIdentity) (*byteEdit, string, string) {
	// Read-only roles never run shells: no Type-B rewrite exists for them.
	// The ordinary strict screen rejects the shell head itself, so returning
	// no edit keeps the fail-closed verdict intact.
	if strictReadonly {
		return nil, "", ""
	}
	head, headIdx, _, envAs, exhausted := peelWrappersWithIndex(seg.argv, caller)
	if exhausted || headIdx < 0 || len(head) < 2 {
		return nil, "", ""
	}
	base := filepath.Base(head[0])
	if !shellHeads[base] {
		return nil, "", ""
	}
	text, has := unwrapShellArgv(head)
	if !has || isDynamicArg(text) {
		return nil, "", ""
	}
	// Locate the script Word with the SAME option walk unwrapShellArgv uses
	// (--rcfile/--init-file/-o/+o/-O/+O), so review and synthesis never pick
	// different -c slots. A glued slot (-cCODE / -ce / -co errexit) or a
	// non-literal script word is never rewritten as a substring: the argv
	// stays untouched and the ordinary guard (guardCtxRunArgv via
	// unwrapShellArgv / guardPreparedShell) judges the decoded text under
	// the full rules — no partial pre-scan can stand in for that screen.
	scriptRel, _, glued, slotOK := locateShellCSlot(head)
	if glued || !slotOK || scriptRel < 0 {
		return nil, "", ""
	}
	absIdx := headIdx + scriptRel
	if absIdx < 0 || absIdx >= len(seg.argWords) || seg.argWords[absIdx] == nil {
		return nil, "", ""
	}
	scriptWord := seg.argWords[absIdx]
	if !wordIsStaticLiteral(scriptWord) {
		return nil, "", ""
	}
	// The dialect and every downstream check resolve under the caller
	// seeded with the peeled env ops — a PATH=<cargoBin> prefix must
	// drive alias resolution here, never the bare process PATH (R4 SF-1).
	innerCaller := caller.seededWith(envAs)
	bashANSI := hcShellDialectBash(head[0], innerCaller.effectivePATH(), innerCaller)
	// The peeled env overrides (HOME=/x sh -c ..., env -C dir ...) taint
	// and re-anchor the inner payload exactly like a caller-level env
	// prefix; losing them lets an inner `$HOME` keep an abs-dir grant it
	// must not have, and an inner relative head would resolve under the
	// OUTER cwd instead of the chdir'd one (R3 MF-2).
	innerTaint := mergeEnvTaint(envTaint, envAs.taintedSentinelNames())
	innerEdits, rule, detail := collectHcGateEdits(text, selfExe, innerTaint, bashANSI, strictReadonly, innerCaller)
	if rule != "" {
		return nil, rule, detail
	}
	if len(innerEdits) == 0 {
		return nil, "", ""
	}
	innerRewritten, innerProv, err := applyHcGateEdits(text, innerEdits)
	if err != nil {
		return nil, ruleSubagentNestedAgent, "hc rewrite"
	}
	lo := int(scriptWord.Pos().Offset())
	hi := int(scriptWord.End().Offset())
	return &byteEdit{
		lo: lo, hi: hi,
		kind:      hcEditInnerSh,
		repl:      shellSingleQuote(innerRewritten),
		innerText: innerRewritten,
		innerProv: innerProv,
	}, "", ""
}

// hcRewritableHcHead reports whether a NON-strict (worker/verifier) caller's
// typed hc head may be rewritten into `<selfExe> --hc-gate`. A path form must
// be a trusted on-disk executable in a safe directory (keeps
// /root/.local/bin/hc, rejects /tmp/hc); a bare name must resolve through the
// effective PATH to hc/herdr-core. Nothing here grants anything to read-only
// roles — they never reach this helper.
func hcRewritableHcHead(head0, effPath string, caller callerIdentity) bool {
	if looksLikePath(head0) || filepath.IsAbs(head0) {
		abs := head0
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(caller.screenCwd(), abs)
		}
		// A path-form hc head may rewrite ONLY at a real install slot —
		// /usr/local/bin or <trustedHome>/.local/bin — so a planted
		// .venv/bin/hc, node_modules/.bin/hc or ~/.cargo/bin/hc is never
		// laundered into a --hc-gate call (R3 SF-2).
		return admittedReadonlyCanonicalHead(filepath.Clean(abs), os.Geteuid()) != ""
	}
	// A bare-name head must resolve through the effective PATH without
	// tripping the planted-shadow screen: a PATH carrying .venv/bin or
	// ~/.cargo/bin whose hc is NOT a trusted install slot fails closed
	// and leaves the block to the guard's screenPathHeadTrust.
	if hit := screenPathHeadTrust(head0, effPath, caller); hit != "" {
		return false
	}
	for _, b := range headBaseAliasHits([]string{head0}, effPath, caller) {
		if b == "hc" || b == "herdr-core" {
			return true
		}
	}
	return false
}

func collectLeafHcEdit(seg shellSegment, selfExe string, bashANSI, strictReadonly bool, caller callerIdentity) (*byteEdit, string, string) {
	if len(seg.argv) == 0 || len(seg.argWords) != len(seg.argv) {
		// Provenance lost (enum expand etc.) — cannot rewrite; leave to guard.
		return nil, "", ""
	}
	head, headIdx, wrappers, envAs, exhausted := peelWrappersWithIndex(seg.argv, caller)
	if exhausted || headIdx < 0 {
		return nil, "", ""
	}
	// Disallow env -i / clear and env -C / --chdir: a cwd-changing wrapper
	// surrenders provenance exactly like a clear (R3 SF-1, matching
	// screenCtxmodeGateHead's 'c'||'d' contract).
	for _, op := range envAs.ops {
		if op.kind == 'c' || op.kind == 'd' {
			return nil, "", ""
		}
	}
	for _, w := range wrappers {
		if !hcGateSafeWrappers[w] {
			return nil, "", ""
		}
	}
	if len(head) != 4 || head[1] != "send" {
		return nil, "", ""
	}
	// Both branches resolve under the caller seeded with the peeled env
	// ops: a PATH=<cargoBin>:$PATH prefix must drive the bare-name hc
	// resolution and the path-trust screen alike, so a shadow hc can
	// never be laundered into --hc-gate (R4 MF-3).
	innerCaller := caller.seededWith(envAs)
	effPath := innerCaller.effectivePATH()
	if strictReadonly {
		// The read-only admission rule: `headIdx == 0` with no wrapper and no
		// assignment prefix, and head[0] the bare literal "hc". /tmp/hc,
		// herdr-core and `FOO=1 timeout 5 hc …` are NEVER laundered into an
		// allowed prepared gate call.
		if headIdx != 0 || len(wrappers) != 0 || head[0] != "hc" {
			return nil, "", ""
		}
		if !wordIsStaticLiteral(seg.argWords[0]) {
			return nil, "", ""
		}
		// Even the strict bare-"hc" admission must not rewrite when the
		// effective PATH planted a shadow hc ahead of the trusted slot
		// (R3 SF-2): the guard would block the call anyway, and the
		// rewrite must never bless a head the path-trust screen rejects.
		if hit := screenPathHeadTrust(head[0], innerCaller.effectivePATH(), innerCaller); hit != "" {
			return nil, "", ""
		}
	} else if !hcRewritableHcHead(head[0], effPath, innerCaller) {
		return nil, "", ""
	}
	addr, text := head[2], head[3]
	if isDynamicArg(addr) || !hcSendAddrOK(addr) || strings.HasPrefix(addr, "-") {
		return nil, "", ""
	}
	if !isDynamicArg(text) {
		return nil, "", "" // static send — no rewrite needed
	}
	if strings.HasPrefix(text, "-") {
		// Static leading-dash marker in placeholder form shouldn't happen;
		// leave to guard.
		return nil, "", ""
	}
	if headIdx+3 >= len(seg.argWords) {
		return nil, ruleSubagentNestedAgent, "hc send"
	}
	headWord := seg.argWords[headIdx]
	textWord := seg.argWords[headIdx+3]
	if headWord == nil || textWord == nil {
		return nil, ruleSubagentNestedAgent, "hc send"
	}
	if !wordIsStaticLiteral(headWord) {
		return nil, ruleSubagentNestedAgent, "hc send"
	}
	if !isGuaranteedSingleArgWord(textWord, bashANSI) {
		return nil, ruleSubagentNestedAgent, "hc send"
	}
	// Static text prefix must not look like an option (gate also checks runtime).
	if staticText := staticWordPrefix(textWord); strings.HasPrefix(staticText, "-") {
		return nil, ruleSubagentNestedAgent, "hc send"
	}
	if selfExe == "" {
		return nil, ruleSubagentNestedAgent, "hc send (self exe unresolved)"
	}
	lo := int(headWord.Pos().Offset())
	hi := int(headWord.End().Offset())
	quoted := shellSingleQuote(selfExe)
	repl := quoted + " --hc-gate"
	return &byteEdit{lo: lo, hi: hi, kind: hcEditLeafGate, repl: repl, quotedLen: len(quoted)}, "", ""
}

func staticWordPrefix(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			if !p.Dollar {
				b.WriteString(p.Value)
			} else {
				return b.String()
			}
		case *syntax.DblQuoted:
			for _, ip := range p.Parts {
				lit, ok := ip.(*syntax.Lit)
				if !ok {
					return b.String()
				}
				b.WriteString(decodeDblQuotedLit(lit.Value))
			}
		default:
			return b.String()
		}
	}
	return b.String()
}

func (g guardCall) prepareCtxRunShell(code string) preparedShell {
	return g.prepareCtxRunShellWithTaint(code, nil)
}

func (g guardCall) prepareCtxRunShellWithTaint(code string, envTaint map[string]bool) preparedShell {
	caller := g.callerIdentity()
	out := preparedShell{rawCode: code, execStdin: ""}
	if !g.subagent && !g.strictReadonly {
		out.execCode = code
		return out
	}
	selfExe, _, selfErr := resolvedSelfExe()
	edits, rule, detail := collectHcGateEdits(code, selfExe, envTaint, false, g.strictReadonly, caller)
	if rule != "" {
		out.rule, out.detail = rule, detail
		return out
	}
	if len(edits) > 0 && (selfErr != nil || selfExe == "") {
		out.rule = ruleSubagentNestedAgent
		out.detail = "hc send (self exe unresolved)"
		return out
	}
	execCode := code
	var prov *hcGateProvenance
	if len(edits) > 0 {
		var err error
		execCode, prov, err = applyHcGateEdits(code, edits)
		if err != nil {
			out.rule = ruleSubagentNestedAgent
			out.detail = "hc rewrite"
			return out
		}
	}
	// Screen the prepared text with the provenance the rewriter just minted: a
	// raw user-typed --hc-gate carries none and stays blocked.
	if rule, detail := g.guardPreparedShell(execCode, envTaint, prov); rule != "" {
		out.rule, out.detail = rule, detail
		return out
	}
	out.execCode = execCode
	return out
}

// prepareCtxRunShellTargets prepares one stdin shell payload under the env
// overrides of EVERY local-shell stdin target (a single-target call passes
// a one-element slice — the former prepareCtxRunShellEnv): the payload's
// env taint is the union of every target's ops, and each target's envAs is
// screened separately so a later target's PATH= can never mask an earlier
// target's PATH view (a merged replay would let `PATH=/dirA sh ;
// PATH=/usr/bin sh` resolve the first target's heads under /usr/bin only —
// the /dirA alias would escape audit). The rewrite still happens ONCE and
// the single prepared buffer carries one provenance that each per-target
// guardPreparedShellEnv pass reuses, so caller.pathEnv / envTaint reflect
// the exact env the rewritten payload runs under (a peeled PATH= must
// drive alias resolution inside the payload too).
// prepareCtxRunShellTargets prepares a stdin program payload that feeds
// local shell targets. bash (variadic, default false) is the shared dialect
// of the consuming shells (v6.2.2 Oracle R16 M2): a bash-family shell reading
// its program from stdin brace-expands exactly like `bash -c`, so the edit
// walk AND the prov-aware guard pass must face the same dialect or the
// `printf tag{red,blue}`-shaped format words the -c path blocks would pass
// as dash static literals.
func (g guardCall) prepareCtxRunShellTargets(code string, targetEnvs []envAssignments, bashOpt ...bool) preparedShell {
	bash := len(bashOpt) > 0 && bashOpt[0]
	caller := g.callerIdentity()
	out := preparedShell{rawCode: code, execStdin: ""}
	if !g.subagent && !g.strictReadonly {
		out.execCode = code
		return out
	}
	selfExe, _, selfErr := resolvedSelfExe()
	envTaint := envAssignments{}.taintedSentinelNames()
	for _, ea := range targetEnvs {
		for name := range ea.taintedSentinelNames() {
			if envTaint == nil {
				envTaint = map[string]bool{}
			}
			envTaint[name] = true
		}
	}
	// The edit walk must face the SAME env each target's own PATH view
	// presents: a PATH=<cargoBin>:$PATH prefix on the stdin-target peel
	// otherwise lets a shadow hc earn the --hc-gate rewrite the guard
	// then blesses (R4 MF-1). Every target env whose seeded edit walk
	// yields a rule rejects the whole prepare.
	for _, te := range targetEnvs {
		if _, erule, edetail := collectHcGateEdits(code, selfExe, envTaint, bash, g.strictReadonly, caller.seededWith(te)); erule != "" {
			out.rule, out.detail = erule, edetail
			return out
		}
	}
	var edits []byteEdit
	if len(targetEnvs) > 0 {
		edits, _, _ = collectHcGateEdits(code, selfExe, envTaint, bash, g.strictReadonly, caller.seededWith(targetEnvs[0]))
	} else {
		edits, _, _ = collectHcGateEdits(code, selfExe, envTaint, bash, g.strictReadonly, caller)
	}
	// Order-independent fail-closed (R6 SF-1): when the stdin stream feeds
	// MORE THAN ONE local shell target, the rewrite decision must not
	// depend on which target's env rode in first — `sh ;
	// PATH=<cargoBin>:$PATH sh` and `PATH=<cargoBin>:$PATH sh ; sh` are
	// the same runtime command, yet the first order seeds targetEnvs[0]
	// with the clean PATH (a rewrite the second target's guard may judge
	// against the shadow hc it did not collect). If the per-target edit
	// walks disagree on the edit count, drop the rewrite and let the
	// per-target guardPreparedShellEnv passes screen the code as-is.
	if len(edits) > 0 && len(targetEnvs) > 1 {
		want := len(edits)
		for i := 1; i < len(targetEnvs); i++ {
			teEdits, _, _ := collectHcGateEdits(code, selfExe, envTaint, bash, g.strictReadonly, caller.seededWith(targetEnvs[i]))
			if len(teEdits) != want {
				edits = nil
				break
			}
		}
	}
	if len(edits) > 0 && (selfErr != nil || selfExe == "") {
		out.rule = ruleSubagentNestedAgent
		out.detail = "hc send (self exe unresolved)"
		return out
	}
	execCode := code
	var prov *hcGateProvenance
	if len(edits) > 0 {
		var err error
		execCode, prov, err = applyHcGateEdits(code, edits)
		if err != nil {
			out.rule = ruleSubagentNestedAgent
			out.detail = "hc rewrite"
			return out
		}
	}
	if len(targetEnvs) == 0 {
		// Defensive: every real caller passes >= 1 target env; an empty slice
		// still gets a single prov-aware screen under the empty env so the
		// rewritten buffer can never leave unscreened.
		targetEnvs = []envAssignments{{}}
	}
	for _, ea := range targetEnvs {
		// Screen the prepared text once per target env, under the seeded
		// env AND the minted provenance. Screening the rewritten buffer
		// through a pure-check entry (guardCtxRunStdin*) would re-enter
		// screenCtxmodeGateHead with hcProv == nil and self-block every
		// legal prepared `<selfExe> --hc-gate` call (the stdin rewrite
		// self-lock).
		if rule, detail := g.guardPreparedShellEnvDialect(execCode, ea, nil, prov, bash); rule != "" {
			out.rule, out.detail = rule, detail
			return out
		}
	}
	out.execCode = execCode
	return out
}

// stdinSingleShellTarget reports whether every stdin-reading target of the
// command is a LOCAL shell (lang == "", remote == false) and the command is
// not an SSH tunnel, returning each target's own env ops in order. Only then
// may the stdin payload be prepared as shell text: jq/cat/git apply read
// DATA, python3 -/node - read their own language, and ssh forwards the
// stream to a REMOTE program — rewriting any of those into a local
// `<selfExe> --hc-gate` call would turn data into a host-local send. A
// remote target arriving through a `bash -c 'ssh host sh'` unwrap carries
// remote: true and must likewise stay data. The per-target envAs slices are
// kept separate (never merged): a later target's PATH= must not rewrite the
// PATH view an earlier target's heads are audited under.
// stdinSingleShellTargetDialect additionally returns the shared
// consuming-shell dialect (v6.2.2 Oracle R16 M2). Every target must agree
// on the dialect: a MIXED bash/dash consumer set can never be rewritten
// under one parser honestly, so the rewrite is refused (ok=false) and the
// caller falls back to the verbatim per-target stdin screen.
// R17-Oracle-M6: a data consumer riding the target list (a nested
// `bash -c "cat; bash"` unwrap that surfaced the plain cat) refuses the
// rewrite exactly like the flat `cat; bash` — the shared stream is partly
// DATA and must never be rewritten into a shell program.
func stdinSingleShellTargetDialect(targets []stdinTarget, sshTunnel bool) (envs []envAssignments, ok bool, bash bool) {
	if sshTunnel || len(targets) == 0 {
		return nil, false, false
	}
	envs = make([]envAssignments, 0, len(targets))
	// R18-Oracle-S2/v6.2.2 complexity budget: the data check inside the
	// loop already refuses every target list with a leading data consumer,
	// so targets[0] IS the first program target whenever the loop can
	// succeed — the separate firstProgramTarget projection was redundant.
	bash = targets[0].bash
	for _, t := range targets {
		if !stdinShellTargetRewriteable(t, bash) {
			return nil, false, false
		}
		envs = append(envs, t.envAs)
	}
	return envs, true, bash
}

// stdinShellTargetRewriteable reports whether one stdin target may take
// part in the local shell-program rewrite (extracted for the v6.2.2 R18
// complexity budget): it must consume the stream as PROGRAM (never data),
// run on THIS host, be a shell rather than a foreign-language interpreter
// and share the consuming shells' single dialect — a mixed bash/dash
// consumer set can never be rewritten under one parser honestly.
func stdinShellTargetRewriteable(t stdinTarget, bash bool) bool {
	return !t.data && !t.exhausted && t.lang == "" && !t.remote && t.bash == bash
}

// scriptAllowsLocalShellStdinPrepare reports whether a shell command string
// permits stdin to be prepared as shell text, returning the per-target env
// ops of every local stdin-reading shell target (one slice per target, in
// order — the caller screens the prepared payload under EACH slice
// separately). Every segment that could touch the shared stdin stream must
// resolve to local shell heads; a data consumer (jq ., cat), a
// foreign-language interpreter, an ssh tunnel (including one nested inside
// `bash -c 'ssh host sh'`), a glued -c script or an unparsed segment all
// refuse the rewrite — the stream then stays data and the caller screens it
// with guardCtxRunStdin / guardCtxRunStdinForCommand. Segments that never
// see the stream (pipe-fed, redirect-fed, heredoc / here-string fed, empty
// or pure-assignment commands) are skipped.
// scriptAllowsLocalShellStdinPrepareDialect additionally returns the shared
// consuming-shell dialect (v6.2.2 Oracle R16 M2): the caller must parse the
// prepared stdin payload under the bash dialect when a bash-family shell
// consumes it.
func scriptAllowsLocalShellStdinPrepare(code string, bash bool, outerEnv envAssignments, basePath string, caller callerIdentity) ([]envAssignments, bool) {
	envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect(code, bash, outerEnv, basePath, caller)
	return envs, ok
}

func scriptAllowsLocalShellStdinPrepareDialect(code string, bash bool, outerEnv envAssignments, basePath string, caller callerIdentity) ([]envAssignments, bool, bool) {
	// Seed the outer env ONCE here: every segment, wrapper peel and stdin
	// target below resolves under the env ops the prepared -c argv installs
	// (an outer `env -C sub` re-anchors inner heads exactly once — never a
	// doubled join, and never dropped from the resolution base, R4 MF-1).
	caller = caller.seededWith(outerEnv)
	var segs []shellSegment
	if bash {
		segs = splitShellSegmentsBashCaller(code, caller.envTaint, caller)
	} else {
		segs = splitShellSegmentsCaller(code, caller.envTaint, caller)
	}
	sawTarget := false
	segBash := false
	var out []envAssignments
	// R19-Oracle-M4: a pure-assignment segment (`HOME=/home/x`) consumes
	// no stdin but re-binds the exported variables EVERY LATER segment's
	// children inherit — its ops accumulate into runEnv in statement
	// order, so `HOME=/home/x; bash` marks the bash target's HOME tainted
	// exactly like the env-prefix spelling `HOME=/home/x bash`.
	runEnv := outerEnv
	for _, seg := range segs {
		if seg.depthExceeded || seg.parseErr != "" {
			return nil, false, false
		}
		// R19-Oracle-M4: the pure-assignment binding happens regardless of
		// the segment's own redirects, so accumulation precedes every
		// stdin-consumption skip — a `HOME=/x <<EOF` segment still rebinds
		// the exported variables the NEXT consumers inherit.
		// accumulatePureAssignEnv folds ops only for segments whose peeled
		// head is EMPTY: prefix ops ahead of a real command die with that
		// child and never re-bind the running shell.
		// R20-Oracle-M3: child-scope segments (subshells, pipelines,
		// backgrounded trees, substitutions) never re-bind the parent —
		// their local environments die with the child process.
		runEnv = accumulatePureAssignEnv(runEnv, seg.argv, caller, seg.childScope)
		if len(seg.argv) == 0 || seg.pipedStdin || seg.stdinRedir || len(seg.heredocText) > 0 || seg.hereString != "" {
			continue
		}
		// Pure-assignment / no-op segments consume no stdin; a segment whose
		// head does not survive the wrapper peel is left to the caller's
		// guard pass (which fails closed on the same condition). Its
		// assignment ops already accumulated into runEnv above (R19-M4).
		if peeledHead, _, _, _, _ := peelWrappersWithIndex(seg.argv, caller); len(peeledHead) == 0 {
			continue
		}
		// A nested shell -c whose slot walk cannot pin a clean script word
		// (glued -cCODE / -ce / -co, or an unlocatable slot) has an ambiguous
		// script/option boundary: refuse the rewrite and let the caller's
		// guard pass judge the argv verbatim.
		if _, hasC := unwrapShellArgv(seg.argv); hasC {
			if _, _, glued, slotOK := locateShellCSlot(seg.argv); glued || !slotOK {
				return nil, false, false
			}
		}
		// R16-Oracle-M2: the segments carry their own dialect — an eval
		// indirection inside the scan re-parses under seg.bashDialect.
		// R19-Oracle-M4: the inherited env is runEnv (outer ops plus every
		// earlier pure-assignment segment in statement order), not bare
		// outerEnv — the consumer runs with the assignments in force.
		targets := stdinProgramTargetsDialect(seg.argv, 0, runEnv, basePath, caller, seg.bashDialect)
		if len(targets) == 0 {
			// A plain data consumer (jq ., cat, git apply) reads the stream as
			// DATA: rewriting it into `<selfExe> --hc-gate` would turn payload
			// bytes into a host-local send.
			return nil, false, false
		}
		sawTarget = true
		// The ssh baseline is the OUTER env, never the cross-segment
		// accumulator: `out` would drop outerEnv's PATH= on the first
		// segment and smuggle an earlier segment's local PATH= into a later
		// one.
		envs, ok, tBash := stdinSingleShellTargetDialect(targets, sshTunnelsStdinProgram(seg.argv, outerEnv.effectivePATHFrom(basePath), caller))
		if !ok {
			return nil, false, false
		}
		// R16-Oracle-M2: the consuming shells of different segments must
		// agree on one dialect — a `sh ; bash` mixture reading the same
		// stream can never be prepared under a single parser honestly.
		if len(out) > 0 && tBash != segBash {
			return nil, false, false
		}
		segBash = tBash
		out = append(out, envs...)
	}
	if !sawTarget {
		return nil, false, false
	}
	return out, true, segBash
}

func (g guardCall) prepareCtxRunShellAndStdin(command, stdin string) preparedShell {
	prep := g.prepareCtxRunShell(command)
	// execStdin always carries the bytes main must feed: the caller's stdin
	// unchanged unless a rewrite below replaces it. No "stdin:" string magic in
	// the diagnostic field can therefore be mistaken for a payload.
	prep.execStdin = stdin
	if prep.rule != "" || stdin == "" {
		return prep
	}
	// stdin is only prepared when EVERY stdin-touching segment of the
	// prepared command resolves to a local shell reading its PROGRAM from
	// this stream. Otherwise the payload stays data and is screened by the
	// real language / remote rules.
	targetEnvs, ok, stdinBash := scriptAllowsLocalShellStdinPrepareDialect(prep.execCode, false, envAssignments{}, os.Getenv("PATH"), g.callerIdentity())
	if !ok {
		if rule, detail := g.guardCtxRunStdinForCommand(prep.execCode, stdin); rule != "" {
			prep.rule, prep.detail = rule, detail
			prep.execCode = ""
		}
		return prep
	}
	// The rewrite and its per-target prov-aware guard passes happen inside
	// prepareCtxRunShellTargets; re-screening the rewritten bytes through a
	// pure-check stdin guard would self-lock on hcProv == nil.
	sp := g.prepareCtxRunShellTargets(stdin, targetEnvs, stdinBash)
	if sp.rule != "" {
		prep.rule, prep.detail = sp.rule, sp.detail
		prep.execCode = ""
		return prep
	}
	// No "stdin:" string magic: the prepared bytes travel in execStdin.
	prep.execStdin = sp.execCode
	return prep
}

func (g guardCall) prepareCtxRunArgv(argv []string, stdin string) preparedArgv {
	out := preparedArgv{rawArgv: append([]string(nil), argv...), execStdin: stdin}
	if !g.subagent && !g.strictReadonly {
		out.execArgv = append([]string(nil), argv...)
		return out
	}
	if len(argv) == 0 {
		out.execArgv = append([]string(nil), argv...)
		return out
	}
	// Shell head with a CLEAN -c script word (never glued): rewrite ONLY
	// that word, and only after the OUTER argv passed the ordinary guard
	// with the script slot replaced by a static ":" (so no script text is
	// screened twice and no diagnostic string can ever stand in for
	// authorization). A glued -c (-cCODE / -ce / -co errexit) or a missing
	// slot is NOT a clean rewritable word: it sets noStdinRewrite and falls
	// through to the plain branch, which screens argv + stdin and never
	// rewrites stdin.
	noStdinRewrite := false
	if _, has := unwrapShellArgv(argv); has {
		scriptIdx, rawScript, glued, slotOK := locateShellCSlot(argv)
		if !glued && slotOK && scriptIdx >= 0 && scriptIdx < len(argv) {
			outerCheck := append([]string(nil), argv...)
			outerCheck[scriptIdx] = ":"
			if rule, detail := g.guardCtxRunArgv(outerCheck); rule != "" {
				out.rule, out.detail = rule, detail
				return out
			}
			// The outer env prefix taints the payload, and the resolved dialect
			// (sh -> bash) decides $'...' acceptance.
			caller := g.callerIdentity()
			_, _, _, envAs, exhausted := peelWrappersWithIndex(argv, caller)
			if exhausted {
				out.rule, out.detail = ruleSubagentNestedAgent, "dynamic code payload"
				return out
			}
			innerCaller := caller.seededWith(envAs)
			innerTaint := envAs.taintedSentinelNames()
			effPath := envAs.effectivePATHFrom(os.Getenv("PATH"))
			selfExe, _, selfErr := resolvedSelfExe()
			isBash := hcShellDialectBash(argv[0], effPath, innerCaller)
			edits, rule, detail := collectHcGateEdits(rawScript, selfExe, innerTaint, isBash, g.strictReadonly, innerCaller)
			if rule != "" {
				out.rule, out.detail = rule, detail
				return out
			}
			execText := rawScript
			var prov *hcGateProvenance
			if len(edits) > 0 {
				if selfErr != nil || selfExe == "" {
					out.rule = ruleSubagentNestedAgent
					out.detail = "hc send (self exe unresolved)"
					return out
				}
				var err error
				execText, prov, err = applyHcGateEdits(rawScript, edits)
				if err != nil {
					out.rule = ruleSubagentNestedAgent
					out.detail = "hc rewrite"
					return out
				}
			}
			// A bash -c payload must face the BASH dialect on the second
			// review: $'...', [[ ... ]] and arithmetic are legal bash but
			// POSIX-syntax errors under LangPOSIX — screening them with the
			// POSIX parser would reject a prepare*-legal rewrite (R2-7).
			var gRule, gDetail string
			if isBash {
				gRule, gDetail = g.guardPreparedShellEnvBash(execText, envAs, nil, prov)
			} else {
				gRule, gDetail = g.guardPreparedShellEnv(execText, envAs, nil, prov)
			}
			if gRule != "" {
				out.rule, out.detail = gRule, gDetail
				return out
			}
			execArgv := append([]string(nil), argv...)
			execArgv[scriptIdx] = execText
			if stdin != "" {
				// stdin may be rewritten into a prepared shell program ONLY
				// when every segment of the script that could touch the
				// stream resolves to a local shell head — the outerCheck
				// argv (script slot = ":") has no stdin-program target, so
				// the real script text must be segmented under its own
				// dialect. A data consumer (jq . ; sh), a glued -c or an
				// ssh tunnel (`bash -c 'ssh host sh'`) leaves the stream as
				// data and screens it through guardCtxRunStdin on the REAL
				// execArgv (never the ":"-stubbed outerCheck), which also
				// escalates strictReadonly for remote targets.
				// The outer caller is passed, not the already-seeded innerCaller:
				// scriptAllowsLocalShellStdinPrepare seeds effCaller itself
				// (caller.seededWith(outerEnv)), and stdinProgramTargetsWithEnv
				// applies each level's OWN peeled ops — a double seed here would
				// replay the outer env -C twice (R4 MF-1).
				if targetEnvs, ok, stdinBash := scriptAllowsLocalShellStdinPrepareDialect(execText, isBash, envAs, os.Getenv("PATH"), caller); ok {
					sp := g.prepareCtxRunShellTargets(stdin, targetEnvs, stdinBash)
					if sp.rule != "" {
						out.rule, out.detail = sp.rule, sp.detail
						return out
					}
					out.execStdin = sp.execCode
				} else if rule, detail := g.guardCtxRunStdin(execArgv, stdin); rule != "" {
					out.rule, out.detail = rule, detail
					return out
				}
			}
			out.execArgv = execArgv
			return out
		}
		// Glued -c / missing slot: fall through to the plain branch with
		// noStdinRewrite set — the decoded "e\nx" text has an ambiguous
		// script/option boundary, so stdin is only ever screened verbatim.
		noStdinRewrite = true
	}

	// Plain argv (no clean -c script word) plus optional stdin program. A
	// glued -c argv lands here too: its stdin is only ever SCREENED, never
	// rewritten — unwrapShellArgv decodes `sh -ce 'x'` into "e\nx" whose
	// script/option boundary is ambiguous, so the bytes must stay data and
	// face guardCtxRunStdin verbatim.
	if rule, detail := g.guardCtxRunArgv(argv); rule != "" {
		out.rule, out.detail = rule, detail
		return out
	}
	if stdin != "" {
		if noStdinRewrite {
			// Glued -c / unlocatable slot: screen only — rewriting these
			// bytes into `<selfExe> --hc-gate` would hand a forged program
			// to the ambiguous inner shell invocation.
			if rule, detail := g.guardCtxRunStdin(argv, stdin); rule != "" {
				out.rule, out.detail = rule, detail
				return out
			}
			out.execStdin = stdin
		} else {
			caller := g.callerIdentity()
			targets := stdinProgramTargetsWithEnv(argv, 0, envAssignments{}, os.Getenv("PATH"), caller)
			if len(targets) > 0 {
				if targetEnvs, ok, stdinBash := stdinSingleShellTargetDialect(targets, sshTunnelsStdinProgram(argv, os.Getenv("PATH"), caller)); ok {
					sp := g.prepareCtxRunShellTargets(stdin, targetEnvs, stdinBash)
					if sp.rule != "" {
						out.rule, out.detail = sp.rule, sp.detail
						return out
					}
					out.execStdin = sp.execCode
				} else {
					// Data / foreign-language / remote stream: keep the bytes and let
					// the ordinary language-aware stdin screen judge them.
					if rule, detail := g.guardCtxRunStdin(argv, stdin); rule != "" {
						out.rule, out.detail = rule, detail
						return out
					}
					out.execStdin = stdin
				}
			}
		}
	}
	out.execArgv = append([]string(nil), argv...)
	return out
}

// guardPreparedShell screens prepared shell text. For strictReadonly it uses
// prepare-mode readonly parsing so hc-gate + dq CmdSubst text slots work.
// prov is the structured provenance of THIS buffer: it is the only evidence
// that an `<selfExe> --hc-gate` call was minted by prepare*, never argv shape,
// SameFile or a diagnostic string. Pure-check callers pass nil.
func (g guardCall) guardPreparedShell(code string, envTaint map[string]bool, prov *hcGateProvenance) (rule, detail string) {
	return g.guardPreparedShellEnv(code, envAssignments{}, envTaint, prov)
}

// guardPreparedShellEnv is guardPreparedShell under the env ops peeled off
// the calling argv: the caller identity is seededWith(envAs) so pathEnv and
// envTaint match the environment the payload will really run under, then
// extraTaint merges any additional tainted names (execute_file's
// FILE_CONTENT). This is the ONLY guard that may see hcProv: a pure-check
// caller has prov == nil and can never mint an allowed `<selfExe> --hc-gate`.
func (g guardCall) guardPreparedShellEnv(code string, envAs envAssignments, extraTaint map[string]bool, prov *hcGateProvenance) (rule, detail string) {
	return g.guardPreparedShellEnvDialect(code, envAs, extraTaint, prov, false)
}

// guardPreparedShellEnvBash is guardPreparedShellEnv under the bash dialect:
// a `bash -c` payload's $'...', [[ ... ]] and arithmetic stay legal where
// the POSIX parser would reject them (R2-7).
func (g guardCall) guardPreparedShellEnvBash(code string, envAs envAssignments, extraTaint map[string]bool, prov *hcGateProvenance) (rule, detail string) {
	return g.guardPreparedShellEnvDialect(code, envAs, extraTaint, prov, true)
}

func (g guardCall) guardPreparedShellEnvDialect(code string, envAs envAssignments, extraTaint map[string]bool, prov *hcGateProvenance, bash bool) (rule, detail string) {
	caller := g.callerIdentity().seededWith(envAs)
	caller.hcProv = prov
	caller.envTaint = mergeEnvTaint(caller.envTaint, extraTaint)
	if g.subagent {
		var hit string
		if bash {
			hit = guardShellSubagentDepthBash(code, 0, caller)
		} else {
			hit = guardShellSubagentDepthEnv(code, 0, caller, caller.envTaint)
		}
		if hit != "" {
			if hit == "ctxmode index" || hit == roSSHWriteHit {
				return ruleReadonlyWrite, hit
			}
			return ruleSubagentNestedAgent, hit
		}
	}
	if g.strictReadonly {
		if hit := guardShellReadonlyDepthPrepare(code, 0, caller); hit != "" {
			return ruleReadonlyWrite, hit
		}
	}
	return "", ""
}

// ensure prepared types satisfy utf8 usage (gate also checks).
var _ = utf8.ValidString
