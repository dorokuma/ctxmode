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
	rawCode  string
	execCode string // empty when blocked
	rule     string
	detail   string
}

// preparedArgv is the unique prepared artifact for argv (+ optional stdin) execution.
type preparedArgv struct {
	rawArgv   []string
	execArgv  []string // nil when blocked
	execStdin string
	rule      string
	detail    string
}

type byteEdit struct {
	lo, hi int
	repl   string
}

// shellSingleQuote wraps s in POSIX single quotes suitable for /bin/sh.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// applyByteEdits applies non-overlapping edits in reverse offset order.
func applyByteEdits(buf string, edits []byteEdit) (string, error) {
	if len(edits) == 0 {
		return buf, nil
	}
	sorted := append([]byteEdit(nil), edits...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].lo != sorted[j].lo {
			return sorted[i].lo < sorted[j].lo
		}
		return sorted[i].hi < sorted[j].hi
	})
	// Dedup identical intervals with identical replacement.
	dedup := sorted[:0]
	for i, e := range sorted {
		if i > 0 && e.lo == sorted[i-1].lo && e.hi == sorted[i-1].hi && e.repl == sorted[i-1].repl {
			continue
		}
		dedup = append(dedup, e)
	}
	sorted = dedup
	for i, e := range sorted {
		if e.lo < 0 || e.hi < e.lo || e.hi > len(buf) {
			return "", fmt.Errorf("edit out of range")
		}
		if i > 0 && sorted[i-1].hi > e.lo {
			return "", fmt.Errorf("overlapping edits")
		}
	}
	var b strings.Builder
	b.Grow(len(buf) + 64)
	cursor := 0
	// Apply low-to-high while building (equivalent to reverse splice).
	for _, e := range sorted {
		b.WriteString(buf[cursor:e.lo])
		b.WriteString(e.repl)
		cursor = e.hi
	}
	b.WriteString(buf[cursor:])
	return b.String(), nil
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
			if pe.Exp != nil && pe.Exp.Word != nil && wordContainsAtSplit(pe.Exp.Word) {
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
		return wordContainsAtSplit(w)
	}
	return false
}

func wordContainsAtSplit(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if p.Value == "@" {
				return true
			}
		case *syntax.ParamExp:
			if p.Param != nil && p.Param.Value == "@" {
				return true
			}
			if paramExpHasAtIndex(p) {
				return true
			}
		}
	}
	return false
}

// wordIsStaticLiteral reports a word with no dynamic AST nodes (safe command head).
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

// peelWrappersWithIndex returns the peeled head and its absolute index in argv.
// headIdx is -1 when provenance is lost (env -S, exhausted peel, or head is
// not a contiguous suffix of the original argv).
func peelWrappersWithIndex(argv []string) (headArgv []string, headIdx int, wrappers []string, envAs envAssignments, exhausted bool) {
	var payloads []string
	headArgv, payloads, envAs, exhausted = peelWrappers(argv)
	for _, p := range payloads {
		if strings.Contains(p, "split-string") || strings.Contains(p, "-S/--split-string") {
			return headArgv, -1, nil, envAs, exhausted
		}
	}
	if exhausted || len(headArgv) == 0 {
		return headArgv, -1, nil, envAs, exhausted
	}
	for i := 0; i <= len(argv)-len(headArgv); i++ {
		match := true
		for j := range headArgv {
			if argv[i+j] != headArgv[j] {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		for _, a := range argv[:i] {
			if isAssignWord(a) || shellNoopWords[a] {
				continue
			}
			b := filepath.Base(a)
			if b == "builtin" || b == "exec" || b == "busybox" || b == "sbx" || b == "strace" || b == "ltrace" {
				return headArgv, -1, wrappers, envAs, false
			}
			if hcGateSafeWrappers[b] {
				wrappers = append(wrappers, b)
			}
		}
		return headArgv, i, wrappers, envAs, false
	}
	return headArgv, -1, nil, envAs, false
}

// collectHcGateEdits walks one source buffer and returns Type-A/Type-B edits.
// bashANSI enables $'...' in isGuaranteedSingleArgWord (bash -c payloads only).
func collectHcGateEdits(code, selfExe string, envTaint map[string]bool, bashANSI bool) (edits []byteEdit, rule, detail string) {
	segs, ok := parseSubagentShellASTEnv(code, 0, false, bashANSI, envTaint)
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
		// Type-B: static sh/bash -c script word — recurse then replace whole word.
		if e, r, d := collectInnerShellScriptEdit(seg, selfExe, envTaint); r != "" {
			return nil, r, d
		} else if e != nil {
			edits = append(edits, *e)
			continue
		}
		e, r, d := collectLeafHcEdit(seg, selfExe, bashANSI)
		if r != "" {
			return nil, r, d
		}
		if e != nil {
			edits = append(edits, *e)
		}
	}
	// Dialect cross-check: if bash/posix secondary tree introduces a dynamic
	// hc that primary missed, fail closed (parseSubagentShellASTEnv already
	// merges segs; re-scan merged list for unrewritable dynamic hc).
	return edits, "", ""
}

func collectInnerShellScriptEdit(seg shellSegment, selfExe string, envTaint map[string]bool) (*byteEdit, string, string) {
	head, headIdx, _, _, exhausted := peelWrappersWithIndex(seg.argv)
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
	// Locate the script Word: relative index of -c's operand within head,
	// mapped back through headIdx.
	scriptRel, glued := shellCScriptRelIndex(head)
	if scriptRel < 0 || glued {
		// Glued -c"..." with dynamic hc must fail closed if present.
		if shellTextHasDynamicHc(text) {
			return nil, ruleSubagentNestedAgent, "hc send"
		}
		return nil, "", ""
	}
	absIdx := headIdx + scriptRel
	if absIdx < 0 || absIdx >= len(seg.argWords) || seg.argWords[absIdx] == nil {
		if shellTextHasDynamicHc(text) {
			return nil, ruleSubagentNestedAgent, "hc send"
		}
		return nil, "", ""
	}
	scriptWord := seg.argWords[absIdx]
	if !wordIsStaticLiteral(scriptWord) {
		if shellTextHasDynamicHc(text) {
			return nil, ruleSubagentNestedAgent, "hc send"
		}
		return nil, "", ""
	}
	bashANSI := base == "bash" || base == "zsh" || base == "ksh" || base == "mksh"
	innerEdits, rule, detail := collectHcGateEdits(text, selfExe, envTaint, bashANSI)
	if rule != "" {
		return nil, rule, detail
	}
	if len(innerEdits) == 0 {
		return nil, "", ""
	}
	innerRewritten, err := applyByteEdits(text, innerEdits)
	if err != nil {
		return nil, ruleSubagentNestedAgent, "hc rewrite"
	}
	lo := int(scriptWord.Pos().Offset())
	hi := int(scriptWord.End().Offset())
	return &byteEdit{lo: lo, hi: hi, repl: shellSingleQuote(innerRewritten)}, "", ""
}

func shellCScriptRelIndex(head []string) (rel int, glued bool) {
	// Mirror unwrapShellArgv's -c discovery enough to find the script argv index
	// relative to head[0].
	for i := 1; i < len(head); i++ {
		a := head[i]
		if a == "--" {
			return -1, false
		}
		if isDynamicArg(a) {
			return -1, false
		}
		if a == "-c" || a == "+c" {
			if i+1 >= len(head) {
				return -1, false
			}
			return i + 1, false
		}
		if strings.HasPrefix(a, "-") && a != "-" && !strings.HasPrefix(a, "--") {
			// Short cluster may contain c with glued tail: -ceCODE or -cCODE
			cluster := a[1:]
			for j := 0; j < len(cluster); j++ {
				if cluster[j] == 'c' {
					tail := cluster[j+1:]
					// letter-only tails are more flags (sh -ce 'x'); else glued.
					allLetters := true
					for k := 0; k < len(tail); k++ {
						c := tail[k]
						if c < 'a' || c > 'z' {
							if c < 'A' || c > 'Z' {
								allLetters = false
								break
							}
						}
					}
					if tail != "" && !allLetters {
						return i, true // glued script in same argv word
					}
					if i+1 >= len(head) {
						return -1, false
					}
					return i + 1, false
				}
			}
		}
	}
	return -1, false
}

func shellTextHasDynamicHc(code string) bool {
	segs, ok := parseSubagentShellASTEnv(code, 0, false, false, nil)
	if !ok {
		segs, _ = parseSubagentShellASTEnv(code, 0, false, true, nil)
	}
	for _, seg := range segs {
		head, _, _, _ := peelWrappers(seg.argv)
		for _, b := range headBaseAliasHits(head, os.Getenv("PATH")) {
			if (b == "hc" || b == "herdr-core") && len(head) >= 4 && head[1] == "send" && isDynamicArg(head[len(head)-1]) {
				return true
			}
		}
	}
	return false
}

func collectLeafHcEdit(seg shellSegment, selfExe string, bashANSI bool) (*byteEdit, string, string) {
	if len(seg.argv) == 0 || len(seg.argWords) != len(seg.argv) {
		// Provenance lost (enum expand etc.) — cannot rewrite; leave to guard.
		return nil, "", ""
	}
	head, headIdx, wrappers, envAs, exhausted := peelWrappersWithIndex(seg.argv)
	if exhausted || headIdx < 0 {
		return nil, "", ""
	}
	// Disallow env -i / clear.
	for _, op := range envAs.ops {
		if op.kind == 'c' {
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
	baseHit := false
	for _, b := range headBaseAliasHits(head, os.Getenv("PATH")) {
		if b == "hc" || b == "herdr-core" {
			baseHit = true
			break
		}
	}
	if !baseHit {
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
	repl := shellSingleQuote(selfExe) + " --hc-gate"
	return &byteEdit{lo: lo, hi: hi, repl: repl}, "", ""
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
	out := preparedShell{rawCode: code}
	if !g.subagent && !g.strictReadonly {
		out.execCode = code
		return out
	}
	selfExe, _, selfErr := resolvedSelfExe()
	edits, rule, detail := collectHcGateEdits(code, selfExe, envTaint, false)
	if rule != "" {
		out.rule, out.detail = rule, detail
		return out
	}
	if selfErr != nil && len(edits) > 0 {
		out.rule = ruleSubagentNestedAgent
		out.detail = "hc send (self exe unresolved)"
		return out
	}
	execCode := code
	if len(edits) > 0 {
		var err error
		execCode, err = applyByteEdits(code, edits)
		if err != nil {
			out.rule = ruleSubagentNestedAgent
			out.detail = "hc rewrite"
			return out
		}
	}
	// Screen the prepared text. Absolute selfExe --hc-gate is recognized by
	// allowlist helpers; remaining dq CmdSubst in the text slot is accepted
	// under prepare-mode readonly walk.
	if rule, detail := g.guardPreparedShell(execCode, envTaint); rule != "" {
		out.rule, out.detail = rule, detail
		return out
	}
	out.execCode = execCode
	return out
}

func (g guardCall) prepareCtxRunShellAndStdin(command, stdin string) preparedShell {
	prep := g.prepareCtxRunShell(command)
	if prep.rule != "" {
		return prep
	}
	if stdin == "" {
		return prep
	}
	// Stdin program screening + rewrite when the command head reads stdin as code.
	if rule, _ := g.guardCtxRunStdinForCommand(prep.execCode, stdin); rule != "" {
		// Try preparing stdin as its own shell buffer when it looks like a program.
		stdinPrep := g.prepareCtxRunShell(stdin)
		if stdinPrep.rule != "" {
			prep.rule, prep.detail = stdinPrep.rule, stdinPrep.detail
			prep.execCode = ""
			return prep
		}
		// Re-check with prepared stdin against original command head intent.
		if rule2, detail2 := g.guardCtxRunStdinForCommand(prep.execCode, stdinPrep.execCode); rule2 != "" {
			prep.rule, prep.detail = rule2, detail2
			prep.execCode = ""
			return prep
		}
		// Stash prepared stdin via detail prefix; prepareStdinExec unwraps it.
		prep.detail = "stdin:" + stdinPrep.execCode
		return prep
	}
	return prep
}

// prepareStdinExec extracts a prepared stdin payload encoded by
// prepareCtxRunShellAndStdin, or returns the original stdin.
func prepareStdinExec(prep preparedShell, origStdin string) string {
	if strings.HasPrefix(prep.detail, "stdin:") {
		return strings.TrimPrefix(prep.detail, "stdin:")
	}
	return origStdin
}

func (g guardCall) prepareCtxRunArgv(argv []string, stdin string) preparedArgv {
	out := preparedArgv{rawArgv: append([]string(nil), argv...), execStdin: stdin}
	if !g.subagent && !g.strictReadonly {
		out.execArgv = append([]string(nil), argv...)
		return out
	}
	// Pure argv without shell head: literal data — never treat as shell.
	if text, has := unwrapShellArgv(argv); has {
		bashANSI := false
		if len(argv) > 0 {
			b := filepath.Base(argv[0])
			bashANSI = b == "bash" || b == "zsh" || b == "ksh" || b == "mksh"
		}
		selfExe, _, selfErr := resolvedSelfExe()
		edits, rule, detail := collectHcGateEdits(text, selfExe, nil, bashANSI)
		if rule != "" {
			out.rule, out.detail = rule, detail
			return out
		}
		execText := text
		if len(edits) > 0 {
			if selfErr != nil {
				out.rule = ruleSubagentNestedAgent
				out.detail = "hc send (self exe unresolved)"
				return out
			}
			var err error
			execText, err = applyByteEdits(text, edits)
			if err != nil {
				out.rule = ruleSubagentNestedAgent
				out.detail = "hc rewrite"
				return out
			}
		}
		execArgv := append([]string(nil), argv...)
		// Replace the -c script argv element with rewritten text (unquoted form
		// is fine for argv mode — no shell re-parse of the outer argv).
		if rel, glued := shellCScriptRelIndex(argv); rel >= 0 && !glued && rel < len(execArgv) {
			execArgv[rel] = execText
		} else if glued {
			out.rule = ruleSubagentNestedAgent
			out.detail = "hc send"
			return out
		}
		if rule, detail := g.guardPreparedShell(execText, nil); rule != "" {
			out.rule, out.detail = rule, detail
			return out
		}
		// Also run argv-level screens on the outer argv (non-script parts).
		if rule, detail := g.guardCtxRunArgv(execArgv); rule != "" {
			// guardCtxRunArgv will re-enter shell screen for -c; use prepared text path only.
			// If it still blocks for non-hc reasons, surface it.
			if !(strings.Contains(detail, "hc send") && len(edits) > 0) {
				out.rule, out.detail = rule, detail
				return out
			}
		}
		out.execArgv = execArgv
		if stdin != "" {
			if rule, _ := g.guardCtxRunStdin(execArgv, stdin); rule != "" {
				sp := g.prepareCtxRunShell(stdin)
				if sp.rule != "" {
					out.rule, out.detail = sp.rule, sp.detail
					out.execArgv = nil
					return out
				}
				if rule2, detail2 := g.guardCtxRunStdin(execArgv, sp.execCode); rule2 != "" {
					out.rule, out.detail = rule2, detail2
					out.execArgv = nil
					return out
				}
				out.execStdin = sp.execCode
			}
		}
		return out
	}

	// argv is a shell reading stdin as program.
	if stdin != "" {
		if rule, detail := g.guardCtxRunArgv(argv); rule != "" {
			out.rule, out.detail = rule, detail
			return out
		}
		sp := g.prepareCtxRunShell(stdin)
		if sp.rule != "" {
			out.rule, out.detail = sp.rule, sp.detail
			return out
		}
		if rule, detail := g.guardCtxRunStdin(argv, sp.execCode); rule != "" {
			out.rule, out.detail = rule, detail
			return out
		}
		out.execArgv = append([]string(nil), argv...)
		out.execStdin = sp.execCode
		return out
	}

	// Plain argv (including literal ["hc","send",...,"$(cat ...)"] ): static screen only.
	if rule, detail := g.guardCtxRunArgv(argv); rule != "" {
		out.rule, out.detail = rule, detail
		return out
	}
	out.execArgv = append([]string(nil), argv...)
	return out
}

// guardPreparedShell screens prepared shell text. For strictReadonly it uses
// prepare-mode readonly parsing so hc-gate + dq CmdSubst text slots work.
func (g guardCall) guardPreparedShell(code string, envTaint map[string]bool) (rule, detail string) {
	caller := currentCallerIdentity()
	if envTaint != nil {
		// Seed taint into caller env map for depth screens that honor it.
		_ = envTaint
	}
	if g.subagent {
		if hit := guardShellSubagentDepthEnv(code, 0, caller, envTaint); hit != "" {
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
