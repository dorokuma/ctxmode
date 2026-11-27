package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// role_guards_v622_eval_test.go — v6.2.2 regression tests: eval binding, tilde shapes, depth budgets,
// and Oracle R14–R19 probes. Migrated losslessly from zz_r2fix_test.go.

// TestGuard_V622_OracleR14Probes pins the Oracle R14 audit closure:
// unquoted brace expansion never encodes as a static single word
// (R14-M1), the unbound "$OLDPWD" placeholder is no longer granted the
// never-empty absolute-dir class (R14-M2), the two wordToArg PID
// encoders exclude Slice/Repl-style derived expansions through
// simpleParamName (R14-M3), explicit-path printf skips the builtin write
// scan in the AST pre-scan (R14-S1), printf's zero-argument exemption
// keeps pure-tilde format words while real globs/braces still fail
// closed (R14-S2) and awk's --source= empty program fragment survives
// collection (R14-S3). Pure-function pins reference only existing
// production symbols plus parse helpers, so the file can be copied onto
// the pre-fix tree 27eaccb to reproduce FAIL directly.
func TestGuard_V622_OracleR14Probes(t *testing.T) {
	// ---- R14-M1: brace expansion parser/encoding pins ----
	t.Run("R14-M1 parser SplitBraces yields BraceExp", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `echo tag{red,blue}`, 1)
		cp := *w
		cp.Parts = append([]syntax.WordPart(nil), w.Parts...)
		syntax.SplitBraces(&cp)
		found := false
		for _, part := range cp.Parts {
			if _, ok := part.(*syntax.BraceExp); ok {
				found = true
			}
		}
		if !found {
			t.Fatal("SplitBraces(tag{red,blue}): no *syntax.BraceExp in copy — dependency contract broken")
		}
	})
	t.Run("R14-M1 wordToArg brace word is dynamic", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `echo tag{red,blue}`, 1)
		s, static := wordToArg(w)
		if static {
			t.Fatalf("wordToArg(tag{red,blue}) = (%q, true), want static=false (brace expansion multiplies the word)", s)
		}
		if !strings.Contains(s, cmdSubPlaceholderGlob) {
			t.Fatalf("wordToArg(tag{red,blue}) = %q, want the glob placeholder encoding", s)
		}
		if _, dyn := printfFmtWriteSlots(s, nil); !dyn {
			t.Fatalf("printfFmtWriteSlots(%q, nil): dyn = false, want true (brace expansion multiplies the zero-argument format word)", s)
		}
	})
	t.Run("R14-M1 collector wordToArg brace word is dynamic", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `echo tag{red,blue}`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("subCollector.wordToArg(tag{red,blue}) = (%q, true), want static=false", s)
		}
		if _, dyn := printfFmtWriteSlots(s, nil); !dyn {
			t.Fatalf("printfFmtWriteSlots(%q, nil): dyn = false, want true", s)
		}
	})
	t.Run("R14-M1-pos single-quoted brace stays static", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `echo 'tag{red,blue}'`, 1)
		s, static := wordToArg(w)
		if !static || s != "tag{red,blue}" {
			t.Fatalf("wordToArg('tag{red,blue}') = (%q, %v), want (tag{red,blue}, true) — quoting suppresses brace expansion", s, static)
		}
		if _, dyn := printfFmtWriteSlots(s, nil); dyn {
			t.Fatalf("printfFmtWriteSlots(%q, nil): dyn = true, want false", s)
		}
		s2, static2 := blankSubCollector().wordToArg(w)
		if !static2 || s2 != "tag{red,blue}" {
			t.Fatalf("subCollector.wordToArg('tag{red,blue}') = (%q, %v), want (tag{red,blue}, true)", s2, static2)
		}
	})
	t.Run("R14-M1 brace word spanning quotes is dynamic", func(t *testing.T) {
		// Bash expands {'%n',TAR_OPTIONS} — the brace text spans a quoting
		// boundary — into TWO words, so the per-literal scan alone can
		// never suffice: the word-level copy walk must catch it.
		w := parseBashSingleCmdWord(t, `printf {'%n',TAR_OPTIONS}`, 1)
		s, static := wordToArg(w)
		if static {
			t.Fatalf("wordToArg({'%%n',TAR_OPTIONS}) = (%q, true), want static=false", s)
		}
	})

	// ---- R14-M2: unbound "$OLDPWD" never granted the abs-dq class ----
	t.Run("R14-M2 unbound OLDPWD placeholder can collapse empty", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `printf "%s" "$OLDPWD"`, 2)
		dq, ok := w.Parts[0].(*syntax.DblQuoted)
		if !ok || len(dq.Parts) != 1 {
			t.Fatalf("parse: word shape %T/%d parts, want one DblQuoted/one part", w.Parts[0], len(w.Parts))
		}
		pe, ok := dq.Parts[0].(*syntax.ParamExp)
		if !ok {
			t.Fatalf("parse: dq part is %T, want *syntax.ParamExp", dq.Parts[0])
		}
		s, staticText := blankSubCollector().dqParamPlaceholder(pe)
		if staticText {
			t.Fatalf("dqParamPlaceholder($OLDPWD) = (%q, true), want ok=false (unbound OLDPWD is dynamic)", s)
		}
		if dynGluedTailNonEmpty(s) {
			t.Fatalf("dynGluedTailNonEmpty(%q) = true, want false (OLDPWD can be empty when never inherited)", s)
		}
		if !dynWordCanSpellDashDash("--" + s) {
			t.Fatalf("dynWordCanSpellDashDash(--%q) = false, want true (an empty OLDPWD spells exactly '--')", s)
		}
	})
	t.Run("R14-M2-pos PWD keeps the abs-dq class", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `printf "%s" "$PWD"`, 2)
		dq := w.Parts[0].(*syntax.DblQuoted)
		pe := dq.Parts[0].(*syntax.ParamExp)
		s, _ := blankSubCollector().dqParamPlaceholder(pe)
		if s != cmdSubPlaceholderAbsDq {
			t.Fatalf("dqParamPlaceholder($PWD) = %q, want the abs-dq placeholder (bash always populates PWD)", s)
		}
	})

	// ---- R14-M3: derived $$ operators are not raw PID digits ----
	t.Run("R14-M3 sliced PID can spell dashdash in both encoders", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `printf "%s" "--${$:0:0}"`, 2)
		s1, st1 := wordToArg(w)
		if st1 {
			t.Fatalf("wordToArg(\"--${$:0:0}\") is static, want dynamic")
		}
		if !dynWordCanSpellDashDash(s1) {
			t.Fatalf("dynWordCanSpellDashDash(wordToArg) = false for %q, want true (a zero-length slice expands EMPTY)", s1)
		}
		s2, st2 := blankSubCollector().wordToArg(w)
		if st2 {
			t.Fatalf("subCollector.wordToArg(\"--${$:0:0}\") is static, want dynamic")
		}
		if !dynWordCanSpellDashDash(s2) {
			t.Fatalf("dynWordCanSpellDashDash(subCollector.wordToArg) = false for %q, want true", s2)
		}
	})
	t.Run("R14-M3-pos bare PID never spells dashdash", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `printf "%s" "$$"`, 2)
		s1, _ := wordToArg(w)
		if dynWordCanSpellDashDash(s1) {
			t.Fatalf("dynWordCanSpellDashDash(wordToArg bare $$) = true for %q, want false (PID digits)", s1)
		}
		s2, _ := blankSubCollector().wordToArg(w)
		if dynWordCanSpellDashDash(s2) {
			t.Fatalf("dynWordCanSpellDashDash(subCollector bare $$) = true for %q, want false", s2)
		}
	})
	t.Run("R14-M3 preScanVarMutations counts getopts standby slot", func(t *testing.T) {
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(`getopts "--${$:0:0}" first second`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		writes, allTainted := preScanVarMutations(f)
		if allTainted {
			t.Fatal("preScanVarMutations(getopts sliced-PID optstring): allTainted = true, want false")
		}
		if writes["second"] < 1 {
			t.Fatalf("preScanVarMutations: writes[second] = %d, want >= 1 (the sliced PID can expand to exactly '--', vetting the standby NAME slot)", writes["second"])
		}
	})

	// ---- R14-S1: explicit-path printf exempt in the AST pre-scan ----
	t.Run("R14-S1 preScanVarMutations usr bin printf no taint", func(t *testing.T) {
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(`/usr/bin/printf "label=$LABEL %s" value`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		_, allTainted := preScanVarMutations(f)
		if allTainted {
			t.Fatal("preScanVarMutations(/usr/bin/printf ...): allTainted = true, want false (an external child process cannot write shell variables)")
		}
	})

	// ---- R14-S2: zero-argument printf pure-tilde exemption ----
	t.Run("R14-S2 printfFmtWriteSlots pure tilde fmt is safe", func(t *testing.T) {
		if _, dyn := printfFmtWriteSlots("~/banner"+cmdSubPlaceholderGlob, nil); dyn {
			t.Fatal("printfFmtWriteSlots(~/banner+glob, nil): dyn = true, want false (tilde expansion yields exactly ONE path word)")
		}
	})
	t.Run("R14-S2 glob and brace fmt stay dyn", func(t *testing.T) {
		if _, dyn := printfFmtWriteSlots("~/banner*"+cmdSubPlaceholderGlob, nil); !dyn {
			t.Fatal("printfFmtWriteSlots(~/banner*+glob, nil): dyn = false, want true (real glob metacharacter)")
		}
		if _, dyn := printfFmtWriteSlots("lit*"+cmdSubPlaceholderGlob, nil); !dyn {
			t.Fatal("printfFmtWriteSlots(lit*+glob, nil): dyn = false, want true")
		}
		w := parseBashSingleCmdWord(t, `printf tag{red,blue}`, 1)
		s, _ := wordToArg(w)
		if _, dyn := printfFmtWriteSlots(s, nil); !dyn {
			t.Fatalf("printfFmtWriteSlots(%q, nil): dyn = false, want true (brace expansion multiplies the word)", s)
		}
	})

	// ---- R14-S3: awk --source= explicit empty program ----
	t.Run("R14-S3 awkProgramFrags empty source parity", func(t *testing.T) {
		F := cmdSubPlaceholderQuoted
		prog1, sf1, hit1 := awkProgramFrags([]string{"--source=", "--", F})
		prog2, sf2, hit2 := awkProgramFrags([]string{"-e", "", "--", F})
		if hit1 != "" || hit2 != "" {
			t.Fatalf("awkProgramFrags hits = (%q, %q), want both empty (the post-`--` word is input data once a program source exists)", hit1, hit2)
		}
		if prog1 != prog2 || sf1 != sf2 {
			t.Fatalf("awkProgramFrags(--source=) = (%q,%v) vs (-e '') = (%q,%v), want identical", prog1, sf1, prog2, sf2)
		}
	})

	// ---- End-to-end guard verdicts ----
	blockCases := []struct {
		name, cmd string
	}{
		// R14-M1: a brace-expanded printf format word becomes MULTIPLE argv
		// words inside bash — match[0] is the real format string, match[1]
		// the first write-target argument. The zero-argument exemption must
		// not apply.
		{"P-R14-M1-a printf brace fmt script", `bash -c 'printf tag{red,blue}'`},
		{"P-R14-M1-b printf brace fmt script args", `bash -c 'printf a{b,c} x'`},
		// R14-M2: an UNBOUND "$OLDPWD" can expand EMPTY at runtime, so the
		// glued read prompt tail can collapse and swallow the next argv
		// word — the pre-scan must fail closed instead of trusting the
		// absolute-dir placeholder class.
		{"P-R14-M2-a read empty-able OLDPWD prompt in script", `bash -c 'cmd=/bin/true; read -p"$OLDPWD" answer <<< ok; "$cmd"'`},
		// R14-M3: a zero-length ${$:0:0} slice can expand EMPTY, spelling
		// the getopts terminator and shifting the standby write target onto
		// `second` — the pre-scan must count that write.
		{"P-R14-M3-a getopts sliced PID in script", `bash -c 'second=/usr/bin/env; getopts "--${$:0:0}" first second; "$second"'`},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
		})
	}
	allowCases := []struct {
		name, cmd string
	}{
		// R16-Oracle-S3: the row duplicating R13's external-printf
		// combination script verbatim (`bash -c 'cmd=/bin/true;
		// /usr/bin/printf "label=$LABEL %s" value; "$cmd"'` — the exact cmd
		// of R13's R13-SF3-script row) is REMOVED, not duplicated: two
		// byte-identical rows can never count as two independent behavior
		// evidences. The table is now exactly 6 rows with a zero cmd
		// intersection against R13's allowCases.
		// R14-S2: pure-tilde zero-argument printf format words expand to
		// exactly one path word — nothing can be written without arguments.
		{"R14-S2-pos printf tilde fmt", `printf ~/banner`},
		{"R14-S2-pos printf tilde fmt script", `bash -c 'printf ~/banner'`},
		// R14-S3: an explicitly empty awk program with input data after the
		// terminator is inert.
		{"R14-S3-pos gawk empty source data file", `gawk --source= -- "$F"`},
		// R14-M1-pos: quoting suppresses brace expansion entirely.
		{"R14-M1-pos printf quoted brace fmt", `bash -c 'printf '\''a{b,c}'\'''`},
		// R14-M2-pos: a SEPARATE double-quoted prompt operand stays exactly
		// one argv word even when empty — no glued-tail collapse is
		// possible — so the unbound-OLDPWD tightening must not refuse it.
		{"R14-M2-pos read separate OLDPWD prompt in script", `bash -c 'cmd=/bin/true; read -p "$OLDPWD" answer <<< ok; "$cmd"'`},
		// R14-S2-pos combo-script variant (R15-Oracle-S4: replaces the row
		// that duplicated R13's `bash -c` external-printf combination
		// script verbatim — two identical rows cannot count as two
		// independent behavior evidences). This is the combination-script
		// counterpart of the pure-tilde printf exemption: the tilde format
		// word inside `bash -c` must not all-taint the write pre-scan, so
		// `cmd` keeps its static bind.
		{"R14-S2-pos printf tilde fmt combo script", `bash -c 'cmd=/bin/true; printf ~/banner; "$cmd"'`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// TestGuard_V622_OracleR15Probes pins the Oracle R15 audit closure:
// brace-expansion words never pass the merged path-prefix/slash review
// of isSafeDynamicDataOperand (R15-M1), the non-empty absolute-path
// grants of `"$(mktemp -d)"` and `"$HOME"` require an actually inherited
// valid TMPDIR/HOME (R15-M2), quoted literal braces keep the pure-tilde
// single-path exemption while the POSIX/dash top-level dialect performs
// no brace expansion (R15-S1), awk distinguishes an explicitly empty
// positional program from a not-yet-provided one (R15-S2) and nested
// separator-less literal braces are rejected by the single-pass budget
// scan without any SplitBraces replay (R15-S3). Pure-function pins
// reference only production symbols that exist verbatim on the pre-fix
// tree c02027c (the consumer predicates and parsers), so the
// discriminating rows reproduce FAIL directly there; rows whose verdict
// is unchanged by the bounded-cost rewrite are marked as invariant
// controls.
func TestGuard_V622_OracleR15Probes(t *testing.T) {
	// ---- R15-M1: brace words never pass isSafeDynamicDataOperand ----
	t.Run("R15-M1 context-free encoding brace word unsafe operand", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `echo {docs/a,-blue}`, 1)
		s, static := wordToArg(w)
		if static {
			t.Fatalf("wordToArg({docs/a,-blue}) = (%q, true), want static=false", s)
		}
		if !strings.Contains(s, cmdSubPlaceholderGlob) || !strings.Contains(s, "{") {
			t.Fatalf("wordToArg({docs/a,-blue}) = %q, want the brace-list glob encoding", s)
		}
		if isSafeDynamicDataOperand(s) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = true, want false — the '/' of docs/a says nothing about the sibling '-blue' branch expanding to an option spelling", s)
		}
	})
	t.Run("R15-M1 collector encoding brace word unsafe operand", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `echo {docs/a,-blue}`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("subCollector.wordToArg({docs/a,-blue}) = (%q, true), want static=false", s)
		}
		if isSafeDynamicDataOperand(s) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = true, want false (collector encoding)", s)
		}
	})
	t.Run("R15-M1-pos ordinary path glob stays a safe operand", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `cat docs/*.txt`, 1)
		s, static := wordToArg(w)
		if static {
			t.Fatalf("wordToArg(docs/*.txt) = (%q, true), want dynamic", s)
		}
		if !isSafeDynamicDataOperand(s) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = false, want true — a plain pathname glob carries no '{' brace byte and keeps its data-operand grant", s)
		}
	})

	// ---- R15-M2: failing $(mktemp -d) and empty $HOME lose the grant ----
	t.Run("R15-M2 mktemp invalid TMPDIR encoding can collapse empty", func(t *testing.T) {
		// TMPDIR pointing at a regular file makes GNU mktemp fail: the
		// diagnostic goes to stderr and stdout inside the double quotes is
		// EMPTY, so the substitution must never carry the absolute-dir
		// class here (pure parse probe — no child process runs).
		t.Setenv("TMPDIR", "/dev/null")
		w := parseBashSingleCmdWord(t, `echo "$(mktemp -d)"`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("subCollector.wordToArg(\"$(mktemp -d)\") under TMPDIR=/dev/null is static, want dynamic")
		}
		if strings.Contains(s, cmdSubPlaceholderAbsDq) {
			t.Fatalf("encoding %q carries the abs-dq class, want the ordinary quoted placeholder (mktemp can fail empty under TMPDIR=/dev/null)", s)
		}
		if dynGluedTailNonEmpty(s) {
			t.Fatalf("dynGluedTailNonEmpty(%q) = true, want false", s)
		}
		if !dynWordCanSpellDashDash("--" + s) {
			t.Fatalf("dynWordCanSpellDashDash(--%q) = false, want true (an empty substitution spells exactly '--')", s)
		}
	})
	t.Run("R15-M2-pos mktemp valid TMPDIR keeps the abs-dq class", func(t *testing.T) {
		// An unset TMPDIR makes mktemp use its /tmp default — the success
		// grant must survive (control row for the tightened gate).
		t.Setenv("TMPDIR", "")
		w := parseBashSingleCmdWord(t, `echo "$(mktemp -d)"`, 1)
		s, _ := blankSubCollector().wordToArg(w)
		if !strings.Contains(s, cmdSubPlaceholderAbsDq) {
			t.Fatalf("encoding %q lost the abs-dq class under a valid inherited TMPDIR, want it kept", s)
		}
		if dynWordCanSpellDashDash("--" + s) {
			t.Fatalf("dynWordCanSpellDashDash(--%q) = true, want false (a successful mktemp -d is a non-empty absolute path)", s)
		}
	})
	t.Run("R15-M2 empty inherited HOME is not a static /root", func(t *testing.T) {
		t.Setenv("HOME", "")
		w := parseBashSingleCmdWord(t, `echo "$HOME"`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("subCollector.wordToArg(\"$HOME\") under HOME=\"\" = (%q, true), want dynamic — childEnv copies keys verbatim and never re-populates HOME, so the expansion is EMPTY", s)
		}
		if strings.Contains(s, "/root") {
			t.Fatalf("encoding %q contains the fabricated /root fallback, want the plain quoted placeholder", s)
		}
		if dynGluedTailNonEmpty(s) {
			t.Fatalf("dynGluedTailNonEmpty(%q) = true, want false", s)
		}
		if !dynWordCanSpellDashDash("--" + s) {
			t.Fatalf("dynWordCanSpellDashDash(--%q) = false, want true (an empty HOME spells exactly '--')", s)
		}
	})
	t.Run("R15-M2-pos valid inherited HOME keeps the static abs path", func(t *testing.T) {
		t.Setenv("HOME", "/root")
		w := parseBashSingleCmdWord(t, `echo "$HOME"`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if !static || s != "/root" {
			t.Fatalf("subCollector.wordToArg(\"$HOME\") under HOME=/root = (%q, %v), want (/root, true)", s, static)
		}
	})

	// ---- R15-S1: quoted literal braces and the dash dialect ----
	t.Run("R15-S1 quoted tilde brace literal is single-word safe", func(t *testing.T) {
		// `~/'{red,blue}'`: the braces are SINGLE-QUOTED literal text —
		// bash expands only the tilde, so the runtime result is exactly
		// ONE path word. wordBraceExpHit must not fire on the quoted
		// braces, and the encoding carries exactly one glob placeholder
		// (from the tilde) with '{' only AFTER the placeholder marker, so
		// the pure-tilde exemption applies again.
		w := parseBashSingleCmdWord(t, `echo ~/'{red,blue}'`, 1)
		if wordBraceExpHit(w) {
			t.Fatal("wordBraceExpHit(~/'{red,blue}') = true, want false (quoted braces never expand)")
		}
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("subCollector.wordToArg(~/'{red,blue}') = (%q, true), want dynamic (the tilde is expansion)", s)
		}
		if _, dyn := printfFmtWriteSlots(s, nil); dyn {
			t.Fatalf("printfFmtWriteSlots(%q, nil): dyn = true, want false — tilde expansion yields exactly ONE path word even with quoted literal brace bytes", s)
		}
	})
	t.Run("R15-S1-pos unquoted tilde brace still multiplies words", func(t *testing.T) {
		// `~/{red,blue}` DOES brace-expand into multiple path words: the
		// tilde glob placeholder plus the brace hit's own marker make TWO
		// glob placeholders, denying the single-word exemption.
		w := parseBashSingleCmdWord(t, `echo ~/{red,blue}`, 1)
		if !wordBraceExpHit(w) {
			t.Fatal("wordBraceExpHit(~/{red,blue}) = false, want true")
		}
		s, _ := blankSubCollector().wordToArg(w)
		// R18-Oracle-M4: the NUL-provenanced tilde marker is pure
		// provenance evidence, not a glob byte — the exactly-two-glob
		// brace expansion shape is judged after stripping it.
		// R19-Oracle-S3: the NUL-provenanced tilde marker is referenced as
		// its LITERAL bytes so this test file compiles verbatim on the
		// pre-fix parent trees (which do not yet define the constant).
		stripped := strings.ReplaceAll(s, "\x00__ctx_tilde__\x00", "")
		if strings.Count(stripped, cmdSubPlaceholderGlob) != 2 {
			t.Fatalf("subCollector.wordToArg(~/{red,blue}) = %q, want exactly 2 glob placeholders (tilde + brace, after stripping the NUL tilde marker)", s)
		}
		if _, dyn := printfFmtWriteSlots(s, nil); !dyn {
			t.Fatalf("printfFmtWriteSlots(%q, nil): dyn = false, want true", s)
		}
	})

	// ---- R15-S2: awk empty positional program vs absent program ----
	t.Run("R15-S2 awk empty positional program parity", func(t *testing.T) {
		F := cmdSubPlaceholderQuoted
		prog1, sf1, hit1 := awkProgramFrags([]string{"--", "", F})
		prog2, sf2, hit2 := awkProgramFrags([]string{"-e", "", "--", F})
		if hit1 != "" || hit2 != "" {
			t.Fatalf("awkProgramFrags hits = (%q, %q), want both empty — an explicitly EMPTY positional program already supplies awk's program text, so the post-`--` word is input data exactly like after `-e ''`", hit1, hit2)
		}
		if prog1 != "" || prog2 != "" || sf1 || sf2 {
			t.Fatalf("awkProgramFrags = (%q,%v) / (%q,%v), want (\"\",false) for both", prog1, sf1, prog2, sf2)
		}
	})

	// ---- R15-S3: nested separator-less braces rejected in one pass ----
	t.Run("R15-S3 nested literal braces never reach SplitBraces", func(t *testing.T) {
		// INVARIANT-CONTROL rows: the verdict was false on the pre-fix
		// tree too — the change is the COST model (the former recursive
		// replay copied already-restored inner Parts at every level,
		// quadratic in depth; the single-pass budget scan performs zero
		// WordPart copies for separator-less shapes). These rows pin the
		// verdict so the bounded-cost rewrite cannot regress correctness.
		for _, depth := range []int{4, 8} {
			word := strings.Repeat("{", depth) + "a" + strings.Repeat("}", depth)
			w := parseBashSingleCmdWord(t, `echo `+word, 1)
			if wordBraceExpHit(w) {
				t.Fatalf("wordBraceExpHit(%s) = true, want false (no ',' or '..' separator — bash never expands it)", word)
			}
			s, static := wordToArg(w)
			if !static || s != word {
				t.Fatalf("wordToArg(%s) = (%q, %v), want the static literal", word, s, static)
			}
			s2, static2 := blankSubCollector().wordToArg(w)
			if !static2 || s2 != word {
				t.Fatalf("subCollector.wordToArg(%s) = (%q, %v), want the static literal", word, s2, static2)
			}
		}
	})

	// ---- End-to-end guard verdicts ----
	blockCases := []struct {
		name, cmd, want string
	}{
		// R15-S1 control: bash really performs brace expansion, so the
		// explicit `bash -c` spelling keeps blocking exactly like R14.
		{"P-R15-S1-b bash printf brace fmt", `bash -c 'printf tag{red,blue}'`, "env dynamic printf"},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want verdict substring %q", tc.cmd, got, tc.want)
			}
		})
	}
	allowCases := []struct {
		name, cmd string
	}{
		// R15-S1-b: /bin/sh is dash on this topology — dash performs NO
		// brace expansion, so `printf tag{red,blue}` arrives as exactly
		// ONE literal format word with no '%' conversions and no arguments.
		{"P-R15-S1-b-pos dash printf literal brace fmt", `printf tag{red,blue}`},
		// R15-S1-a: the single-quoted tilde-brace word is exactly one path
		// word after tilde expansion — the pure-tilde exemption restored.
		{"P-R15-S1-a-pos printf quoted tilde brace fmt", `printf ~/'{red,blue}'`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// TestGuard_V622_OracleR16Probes pins the Oracle R16 audit closure:
// the mktemp directory proof covers pseudo filesystems AND the
// variable-assignment binding path (R16-M1), a bash-family interpreter's
// eval/trap/stdin re-parses keep the bash dialect instead of falling back
// to dash (R16-M2), unquoted $HOME with whitespace or glob bytes is never
// a single static operand (R16-M3), ~/... path restoration uses the
// shell-visible inherited HOME rather than the config-search fallback
// (R16-M4), a quoted literal brace inside an ordinary pathname glob stays
// a safe data operand (R16-S1), the AST write pre-scan is dialect-aware
// for dash (R16-S2) and the R14 allow table is mechanically deduplicated
// to 6 rows with a zero cmd intersection against R13 (R16-S3).
// Pure-function pins reference only production symbols that exist verbatim
// on the pre-fix tree d3efa30 (the consumer predicates, parsers and the
// unchanged preScanVarMutations one-argument call shape), so the
// discriminating rows reproduce FAIL directly there; rows marked
// post-fix-only exercise the new dialect plumbing that cannot exist on
// the pre-fix tree.
func TestGuard_V622_OracleR16Probes(t *testing.T) {
	// ---- R16-M1: mktemp TMPDIR validity proof ----
	t.Run("R16-M1-a TMPDIR proc loses the abs-dq grant", func(t *testing.T) {
		// /proc is a real directory (mode 0555) but a pseudo filesystem on
		// which mktemp can never create a subdirectory — the encoding must
		// never carry the non-empty absolute-dir class here.
		t.Setenv("TMPDIR", "/proc")
		w := parseBashSingleCmdWord(t, `echo "$(mktemp -d)"`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("subCollector.wordToArg(\"$(mktemp -d)\") under TMPDIR=/proc is static, want dynamic")
		}
		if strings.Contains(s, cmdSubPlaceholderAbsDq) {
			t.Fatalf("encoding %q carries the abs-dq class, want the ordinary quoted placeholder (mktemp can fail empty under TMPDIR=/proc)", s)
		}
		if dynGluedTailNonEmpty(s) {
			t.Fatalf("dynGluedTailNonEmpty(%q) = true, want false", s)
		}
		if !dynWordCanSpellDashDash("--" + s) {
			t.Fatalf("dynWordCanSpellDashDash(--%q) = false, want true (an empty substitution spells exactly '--')", s)
		}
	})
	t.Run("R16-M1-a-pos TMPDIR unset keeps the abs-dq grant", func(t *testing.T) {
		t.Setenv("TMPDIR", "")
		w := parseBashSingleCmdWord(t, `echo "$(mktemp -d)"`, 1)
		s, _ := blankSubCollector().wordToArg(w)
		if !strings.Contains(s, cmdSubPlaceholderAbsDq) {
			t.Fatalf("encoding %q lost the abs-dq class under an unset TMPDIR, want it kept", s)
		}
	})
	t.Run("R16-M1-b assignment binding requires a valid TMPDIR", func(t *testing.T) {
		// staticAssignVal is the variable-binding producer feeding the SAME
		// downstream positional-layout proofs: TMPDIR=/dev/null must not
		// mint the non-empty mktemp directory bind there either.
		for _, td := range []string{"/dev/null", "/proc"} {
			t.Run(strings.ReplaceAll(td, "/", "_"), func(t *testing.T) {
				t.Setenv("TMPDIR", td)
				p := syntax.NewParser(syntax.Variant(syntax.LangBash))
				f, err := p.Parse(strings.NewReader(`d=$(mktemp -d)`), "")
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
				if !ok || len(call.Assigns) != 1 || call.Assigns[0].Value == nil {
					t.Fatalf("parse shape %T, want one Assign with a value", f.Stmts[0].Cmd)
				}
				v, ok := blankSubCollector().staticAssignVal(call.Assigns[0].Value)
				if ok && v == mktempDirPlaceholder {
					t.Fatalf("staticAssignVal($(mktemp -d)) under TMPDIR=%s = (%q, true), want the mktemp-dir grant withheld — mktemp fails empty there", td, v)
				}
			})
		}
	})
	t.Run("R16-M1-b-pos assignment binding keeps the grant when TMPDIR is unset", func(t *testing.T) {
		t.Setenv("TMPDIR", "")
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(`d=$(mktemp -d)`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		call := f.Stmts[0].Cmd.(*syntax.CallExpr)
		v, ok := blankSubCollector().staticAssignVal(call.Assigns[0].Value)
		if !ok || v != mktempDirPlaceholder {
			t.Fatalf("staticAssignVal($(mktemp -d)) under an unset TMPDIR = (%q, %v), want (%q, true)", v, ok, mktempDirPlaceholder)
		}
	})

	// ---- R16-M2: bash stdin / eval / trap keep the bash dialect ----
	t.Run("R16-M2-c bash -c blocks the brace format (control)", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R16-M2-c", role: "worker", cmd: `bash -c 'printf tag{red,blue}'`}, "")
		if !strings.Contains(got, "env dynamic printf") {
			t.Fatalf("bash -c path = %q, want substring %q", got, "env dynamic printf")
		}
	})
	t.Run("R16-M2-s bash stdin faces the same bash dialect", func(t *testing.T) {
		// The SAME interpreter reading the SAME program text — only the
		// input channel differs. A dash re-parse judges the brace word a
		// static literal (zero-argument exemption, ALLOW); bash really
		// multiplies it, so the stdin path must agree with the -c path.
		got := rtGuardCwd(t, rtCase{id: "R16-M2-s", role: "worker", argv: []string{"bash"}, stdin: "printf tag{red,blue}\n"}, "")
		if !strings.Contains(got, "env dynamic printf") {
			t.Fatalf("bash stdin path = %q, want substring %q — same interpreter, same program, same verdict as bash -c", got, "env dynamic printf")
		}
	})
	t.Run("R16-M2-s2 bash stdin prepare faces the bash dialect", func(t *testing.T) {
		prep := guardCall{subagent: true}.prepareCtxRunArgv([]string{"bash"}, "printf tag{red,blue}\n")
		if prep.rule == "" {
			t.Fatalf("prepareCtxRunArgv(bash + brace stdin) passed, want the bash-dialect guard block")
		}
	})
	t.Run("R16-M2-s-pos dash stdin keeps the POSIX literal", func(t *testing.T) {
		// /bin/sh is dash on this topology: dash performs NO brace
		// expansion, so the zero-argument literal format word stays ALLOW —
		// the compatibility half of the dialect split.
		got := rtGuardCwd(t, rtCase{id: "R16-M2-s-pos", role: "worker", argv: []string{"sh"}, stdin: "printf tag{red,blue}\n"}, "")
		if got != "ALLOW" {
			t.Fatalf("dash stdin path = %q, want ALLOW", got)
		}
	})
	t.Run("R16-M2-eval re-parse inherits the bash dialect", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R16-M2-eval", role: "worker", cmd: `bash -c 'eval "printf tag{red,blue}"'`}, "")
		if !strings.Contains(got, "env dynamic printf") {
			t.Fatalf("bash eval path = %q, want substring %q", got, "env dynamic printf")
		}
	})
	t.Run("R16-M2-eval-pos dash eval keeps the POSIX literal", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R16-M2-eval-pos", role: "worker", cmd: `eval "printf tag{red,blue}"`}, "")
		if got != "ALLOW" {
			t.Fatalf("dash eval path = %q, want ALLOW", got)
		}
	})
	t.Run("R16-M2-trap action inherits the bash dialect", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R16-M2-trap", role: "worker", cmd: `bash -c 'trap "printf tag{red,blue}" EXIT'`}, "")
		if !strings.Contains(got, "env dynamic printf") {
			t.Fatalf("bash trap path = %q, want substring %q", got, "env dynamic printf")
		}
	})
	t.Run("R16-M2-trap-pos dash trap keeps the POSIX literal", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R16-M2-trap-pos", role: "worker", cmd: `trap "printf tag{red,blue}" EXIT`}, "")
		if got != "ALLOW" {
			t.Fatalf("dash trap path = %q, want ALLOW", got)
		}
	})

	// ---- R16-M3: unquoted $HOME with whitespace/globs is never one word ----
	t.Run("R16-M3 unquoted HOME with whitespace is not a single operand", func(t *testing.T) {
		t.Setenv("HOME", "/home/Team Blue")
		w := parseBashSingleCmdWord(t, `echo $HOME`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("subCollector.wordToArg($HOME) under HOME=/home/Team Blue = (%q, true), want dynamic — the expansion field-splits at runtime", s)
		}
		if isSingleWordOptionValue(s) {
			t.Fatalf("isSingleWordOptionValue(%q) = true, want false — HOME=\"/home/Team Blue\" splits into two fields unquoted", s)
		}
	})
	t.Run("R16-M3-pos quoted HOME stays one operand slot", func(t *testing.T) {
		t.Setenv("HOME", "/home/Team Blue")
		w := parseBashSingleCmdWord(t, `echo "$HOME"`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if !static {
			t.Fatalf("subCollector.wordToArg(\"$HOME\") = (%q, false), want the static literal — double quotes suppress field splitting entirely", s)
		}
		if !isSingleWordOptionValue(s) {
			t.Fatalf("isSingleWordOptionValue(%q) = false, want true (a double-quoted expansion is exactly one argv word)", s)
		}
	})
	t.Run("R16-M3 unquoted HOME with glob bytes is not a single operand", func(t *testing.T) {
		t.Setenv("HOME", "/home/te*am")
		w := parseBashSingleCmdWord(t, `echo $HOME`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("subCollector.wordToArg($HOME) under HOME=/home/te*am = (%q, true), want dynamic — pathname expansion can multiply the word", s)
		}
		if isSingleWordOptionValue(s) {
			t.Fatalf("isSingleWordOptionValue(%q) = true, want false", s)
		}
	})
	t.Run("R16-M3-pos clean unquoted HOME keeps the literal grant", func(t *testing.T) {
		// INVARIANT-CONTROL row: an unquoted $HOME never encodes as a static
		// word on either tree (the collector always marks unquoted expansions
		// dynamic) — but a whitespace/glob-free absolute HOME keeps the
		// literal path TEXT, which is single-word-safe as an option value.
		t.Setenv("HOME", "/root")
		w := parseBashSingleCmdWord(t, `echo $HOME`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static || s != "/root" {
			t.Fatalf("subCollector.wordToArg($HOME) under HOME=/root = (%q, %v), want (/root, false)", s, static)
		}
		if !isSingleWordOptionValue(s) {
			t.Fatalf("isSingleWordOptionValue(%q) = false, want true — a whitespace/glob-free absolute HOME expands to exactly one field", s)
		}
	})

	// ---- R16-M4: ~/... path restoration never fabricates /root ----
	t.Run("R16-M4 relative HOME never resolves to /root", func(t *testing.T) {
		t.Setenv("HOME", "relative-home")
		w := parseBashSingleCmdWord(t, `echo ~/notes`, 1)
		s, _ := blankSubCollector().wordToArg(w)
		cand, ok := resolveNodeRunnerPathOpt(s, "/opt/example")
		if ok && cand == "/root/notes" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true) — a relative inherited HOME must never fabricate /root/notes; bash would expand ~ against the caller cwd instead", s, cand)
		}
		if ok {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true), want ok=false — a relative inherited HOME cannot anchor an absolute path", s, cand)
		}
	})
	t.Run("R16-M4-pos absolute HOME keeps the restoration", func(t *testing.T) {
		// An isolated fake home inside t.TempDir() (isTmpOrScratchPath
		// honours testTrustedHomeRoot) keeps the grant end-to-end.
		t.Setenv("HOME", "/home/user")
		w := parseBashSingleCmdWord(t, `echo ~/notes`, 1)
		s, _ := blankSubCollector().wordToArg(w)
		cand, ok := resolveNodeRunnerPathOpt(s, "/opt/example")
		if !ok || cand != "/home/user/notes" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, %v), want (/home/user/notes, true)", s, cand, ok)
		}
	})

	// ---- R16-S1: quoted literal braces in ordinary globs stay safe ----
	t.Run("R16-S1 quoted literal brace glob is a safe data operand", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `cat docs/'{v1}'/*.txt`, 1)
		if wordBraceExpHit(w) {
			t.Fatal("wordBraceExpHit(docs/'{v1}'/*.txt) = true, want false — the braces are single-quoted literal text, never an expansion")
		}
		s1, static1 := wordToArg(w)
		if static1 {
			t.Fatalf("wordToArg(docs/'{v1}'/*.txt) = (%q, true), want dynamic (the *.txt glob)", s1)
		}
		if !isSafeDynamicDataOperand(s1) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = false, want true — every match keeps the fixed docs/ prefix and {v1} is a literal directory", s1)
		}
		s2, static2 := blankSubCollector().wordToArg(w)
		if static2 {
			t.Fatalf("subCollector.wordToArg(docs/'{v1}'/*.txt) = (%q, true), want dynamic", s2)
		}
		if !isSafeDynamicDataOperand(s2) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = false, want true (collector encoding)", s2)
		}
	})
	t.Run("R16-S1-pos real brace words keep the refusal", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `echo {docs/a,-blue}`, 1)
		s, _ := wordToArg(w)
		if isSafeDynamicDataOperand(s) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = true, want false — a real brace expansion's sibling branches can spell options", s)
		}
		s2, _ := blankSubCollector().wordToArg(w)
		if isSafeDynamicDataOperand(s2) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = true, want false (collector encoding)", s2)
		}
	})

	// ---- R16-S2: dash write pre-scan skips the bash brace scan ----
	t.Run("R16-S2 dash printf combination script stays bound", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R16-S2", role: "worker", cmd: `cmd=/bin/true; printf tag{red,blue}; "$cmd"`}, "")
		if got != "ALLOW" {
			t.Fatalf("rtGuardCwd(dash combination script) = %q, want ALLOW — dash treats the brace word as a zero-argument literal format, so nothing can be written", got)
		}
	})

	// ---- R16-S3: mechanical AST/verification of the case tables ----
	t.Run("R16-S3 R14 allow table is exactly 6 rows disjoint from R13", func(t *testing.T) {
		// The allow rows are (name, cmd) struct literals: the cmd is the
		// second back-quoted string of each row — the walk extracts them
		// positionally (every row here carries exactly two strings).
		// The probes were migrated losslessly from zz_r2fix_test.go into the
		// v622 split files: R14 lives in the eval file, R13 in the shell file.
		extractRows := func(fileName, funcName string) (block int, allow int, cmds []string) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, fileName, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", fileName, err)
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != funcName {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					assign, ok := n.(*ast.AssignStmt)
					if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
						return true
					}
					ident, ok := assign.Lhs[0].(*ast.Ident)
					if !ok {
						return true
					}
					comp, ok := assign.Rhs[0].(*ast.CompositeLit)
					if !ok {
						return true
					}
					rowCmds := func() []string {
						var cmdsOut []string
						for _, el := range comp.Elts {
							row, ok := el.(*ast.CompositeLit)
							if !ok {
								continue
							}
							var lits []string
							for _, v := range row.Elts {
								if bl, ok := v.(*ast.BasicLit); ok && bl.Kind == token.STRING {
									if unq, err := strconv.Unquote(bl.Value); err == nil {
										lits = append(lits, unq)
									}
								}
							}
							if len(lits) >= 2 {
								cmdsOut = append(cmdsOut, lits[1])
							}
						}
						return cmdsOut
					}
					switch ident.Name {
					case "blockCases":
						block = len(comp.Elts)
					case "allowCases":
						allow = len(comp.Elts)
						cmds = rowCmds()
					}
					return true
				})
			}
			return block, allow, cmds
		}
		block14, allow14, cmds14 := extractRows("role_guards_v622_eval_test.go", "TestGuard_V622_OracleR14Probes")
		_, _, cmds13 := extractRows("role_guards_v622_shell_test.go", "TestGuard_V622_OracleR13Probes")
		if block14 != 4 || allow14 != 6 {
			t.Fatalf("R14 tables = (%d block, %d allow), want (4, 6)", block14, allow14)
		}
		if len(cmds14) != 6 || len(cmds13) != 10 {
			t.Fatalf("extracted cmd counts = (%d R14, %d R13), want (6, 10)", len(cmds14), len(cmds13))
		}
		set13 := map[string]bool{}
		for _, c := range cmds13 {
			set13[c] = true
		}
		for _, c := range cmds14 {
			if set13[c] {
				t.Fatalf("R14 allow cmd %q duplicates an R13 allow row — two byte-identical rows cannot count as two independent evidences", c)
			}
		}
	})
}

// TestGuard_V622_OracleR17Probes pins the Oracle R17 audit closure:
// the mktemp grants additionally require the effective PATH to resolve an
// executable mktemp (R17-M1), local bash heredoc / here-string stdin
// re-parses keep the bash dialect instead of falling back to dash
// (R17-M2), the unquoted-$HOME single-word proof collapses the moment IFS
// is polluted (R17-M3), ~/... restoration demands both the real tilde
// marker and an untainted expansion environment (R17-M4), locateShellCSlot
// skips the `--` terminator after a pending -c exactly like
// unwrapShellArgv (R17-M5), nested -c stdin classification no longer
// drops plain data consumers (R17-M6), a multi-glob path with quoted
// literal braces is never a brace expansion (R17-S1) and /dev/shm is a
// valid tmpfs TMPDIR (R17-S2). Pure-function pins reference only
// production symbols that exist verbatim on the pre-fix tree 841473c
// (the consumer predicates, the collectors, unwrapShellArgv,
// locateShellCSlot, scriptAllowsLocalShellStdinPrepareDialect and
// stdinProgramTargetsWithEnv), so the discriminating rows reproduce FAIL
// directly there.
func TestGuard_V622_OracleR17Probes(t *testing.T) {
	// ---- R17-M1: a missing mktemp on the effective PATH revokes the grants ----
	t.Run("R17-M1-a dq grant requires PATH resolvable mktemp", func(t *testing.T) {
		// /usr/local/sbin is verified root-owned without mktemp on this
		// host (Oracle R17 read-only metadata check); TMPDIR=/tmp is
		// valid, so only the missing lookup can revoke the grant.
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/local/sbin")
		w := parseBashSingleCmdWord(t, `echo "$(mktemp -d)"`, 1)
		s, static := blankSubCollector().wordToArg(w)
		if static {
			t.Fatalf("wordToArg(\"$(mktemp -d)\") static under mktemp-less PATH")
		}
		if strings.Contains(s, cmdSubPlaceholderAbsDq) {
			t.Fatalf("encoding %q carries the abs-dq class under PATH=/usr/local/sbin, want the ordinary quoted placeholder (mktemp is not runnable there)", s)
		}
		if dynGluedTailNonEmpty(s) {
			t.Fatalf("dynGluedTailNonEmpty(%q) = true, want false — a failing substitution is empty", s)
		}
	})
	t.Run("R17-M1-b assignment binding requires PATH resolvable mktemp", func(t *testing.T) {
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/local/sbin")
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(`d=$(mktemp -d)`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 1 || call.Assigns[0].Value == nil {
			t.Fatalf("parse shape %T, want one Assign with a value", f.Stmts[0].Cmd)
		}
		v, ok := blankSubCollector().staticAssignVal(call.Assigns[0].Value)
		if ok && v == mktempDirPlaceholder {
			t.Fatalf("staticAssignVal($(mktemp -d)) under PATH=/usr/local/sbin = (%q, true), want the mktemp-dir grant withheld — the child cannot even be exec'd there", v)
		}
	})
	t.Run("R17-M1-pos normal PATH keeps the grants", func(t *testing.T) {
		t.Setenv("TMPDIR", "")
		t.Setenv("PATH", "/usr/bin:/bin")
		w := parseBashSingleCmdWord(t, `echo "$(mktemp -d)"`, 1)
		s, _ := blankSubCollector().wordToArg(w)
		if !strings.Contains(s, cmdSubPlaceholderAbsDq) {
			t.Fatalf("encoding %q lost the abs-dq class under PATH=/usr/bin:/bin, want it kept (/usr/bin/mktemp is executable)", s)
		}
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(`d=$(mktemp -d)`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		call := f.Stmts[0].Cmd.(*syntax.CallExpr)
		v, ok := blankSubCollector().staticAssignVal(call.Assigns[0].Value)
		if !ok || v != mktempDirPlaceholder {
			t.Fatalf("staticAssignVal($(mktemp -d)) under PATH=/usr/bin:/bin = (%q, %v), want (%q, true)", v, ok, mktempDirPlaceholder)
		}
	})

	// ---- R17-M2: bash heredoc / here-string keep the bash dialect ----
	t.Run("R17-M2-api bash API stdin keeps the bash dialect (control)", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R17-M2-api", role: "worker", argv: []string{"bash"}, stdin: "printf tag{red,blue}\n"}, "")
		if !strings.Contains(got, "env dynamic printf") {
			t.Fatalf("bash API stdin path = %q, want substring %q", got, "env dynamic printf")
		}
	})
	t.Run("R17-M2-hd bash heredoc keeps the bash dialect", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R17-M2-hd", role: "worker", cmd: "bash -c 'bash <<\"EOF\"\nprintf tag{red,blue}\nEOF'"}, "")
		if !strings.Contains(got, "env dynamic printf") {
			t.Fatalf("bash heredoc path = %q, want substring %q — a bash reading its program from a heredoc brace-expands exactly like bash -c", got, "env dynamic printf")
		}
	})
	t.Run("R17-M2-hs bash here-string keeps the bash dialect", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R17-M2-hs", role: "worker", cmd: "bash -c 'bash <<< \"printf tag{red,blue}\"'"}, "")
		if !strings.Contains(got, "env dynamic printf") {
			t.Fatalf("bash here-string path = %q, want substring %q", got, "env dynamic printf")
		}
	})
	t.Run("R17-M2-pos dash heredoc / here-string keep the POSIX literal", func(t *testing.T) {
		for _, cmd := range []string{
			"bash -c 'sh <<\"EOF\"\nprintf tag{red,blue}\nEOF'",
			"bash -c 'sh <<< \"printf tag{red,blue}\"'",
		} {
			got := rtGuardCwd(t, rtCase{id: "R17-M2-pos", role: "worker", cmd: cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("dash stdin path %q = %q, want ALLOW — dash performs no brace expansion", cmd, got)
			}
		}
	})

	// ---- R17-M3: a polluted IFS revokes the unquoted-$HOME single-word proof ----
	ifsFixture := func(t *testing.T, script string, argIdx int) string {
		t.Helper()
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
		}
		last := segs[len(segs)-1]
		if argIdx >= len(last.argv) {
			t.Fatalf("parse %q: last seg argv=%v, want index %d", script, last.argv, argIdx)
		}
		return last.argv[argIdx]
	}
	t.Run("R17-M3 IFS=':' degrades unquoted HOME but keeps the quoted word", func(t *testing.T) {
		t.Setenv("HOME", "/home/red:blue")
		unq := ifsFixture(t, "IFS=:; echo $HOME", 1)
		quo := ifsFixture(t, "IFS=:; echo \"$HOME\"", 1)
		if isSingleWordOptionValue(unq) {
			t.Fatalf("isSingleWordOptionValue(%q) = true, want false — unquoted $HOME field-splits on ':' at runtime", unq)
		}
		if !isSingleWordOptionValue(quo) {
			t.Fatalf("isSingleWordOptionValue(%q) = false, want true — a double-quoted expansion is exactly one argv word regardless of IFS", quo)
		}
	})
	t.Run("R17-M3-pos untainted IFS keeps the unquoted literal text", func(t *testing.T) {
		t.Setenv("HOME", "/home/red:blue")
		unq := ifsFixture(t, "echo $HOME", 1)
		if !isSingleWordOptionValue(unq) {
			t.Fatalf("isSingleWordOptionValue(%q) = false, want true — a whitespace/glob-free HOME expands to one field under the default IFS", unq)
		}
	})

	// ---- R17-M4: tilde restoration needs the marker AND the environment ----
	t.Run("R17-M4-a unmarked literal ~/notes never resolves to the service HOME", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		cand, ok := resolveNodeRunnerPathOpt("~/notes", "/opt/example")
		if ok && cand == "/home/parent/notes" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true) — a direct argv or single-quoted word reaches the consumer VERBATIM and must never be home-restored", "~/notes", cand)
		}
		if ok && cand != "/opt/example/~/notes" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true), want ok=false or the cwd-relative %q", "~/notes", cand, "/opt/example/~/notes")
		}
	})
	t.Run("R17-M4-b tainted HOME revokes the tilde restoration", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		w := parseBashSingleCmdWord(t, `echo ~/notes`, 1)
		col := blankSubCollector()
		col.taintedVars["HOME"] = true
		s, _ := col.wordToArg(w)
		cand, ok := resolveNodeRunnerPathOpt(s, "/opt/example")
		if ok && cand == "/home/parent/notes" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true) — the service HOME must never stand in for the consuming shell's tainted HOME", s, cand)
		}
		if ok {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true), want ok=false under a tainted HOME", s, cand)
		}
	})
	t.Run("R17-M4-pos untainted tilde expansion keeps the restoration", func(t *testing.T) {
		t.Setenv("HOME", "/home/user")
		w := parseBashSingleCmdWord(t, `echo ~/notes`, 1)
		s, _ := blankSubCollector().wordToArg(w)
		cand, ok := resolveNodeRunnerPathOpt(s, "/opt/example")
		if !ok || cand != "/home/user/notes" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, %v), want (/home/user/notes, true)", s, cand, ok)
		}
	})

	// ---- R17-M5: locateShellCSlot skips the terminator after a pending -c ----
	t.Run("R17-M5 located slot equals the unwrapped script text", func(t *testing.T) {
		argv := []string{"bash", "-c", "--", "echo ok"}
		idx, rawScript, glued, ok := locateShellCSlot(argv)
		text, has := unwrapShellArgv(argv)
		if !has || text != "echo ok" {
			t.Fatalf("unwrapShellArgv(%v) = (%q, %v), want (echo ok, true)", argv, text, has)
		}
		if !ok || glued {
			t.Fatalf("locateShellCSlot(%v) = (%d, %q, glued=%v, ok=%v), want a clean unglued slot", argv, idx, rawScript, glued, ok)
		}
		if idx != 3 || rawScript != "echo ok" || argv[idx] != rawScript {
			t.Fatalf("locateShellCSlot(%v) = (%d, %q), want (3, echo ok) with argv[idx] == rawScript == unwrap text", argv, idx, rawScript)
		}
	})
	t.Run("R17-M5-pos dash terminator spellings locate the same word", func(t *testing.T) {
		for _, argv := range [][]string{
			{"sh", "-c", "echo ok"},
			{"bash", "-c", "-", "echo ok"},
			{"bash", "--rcfile", "/dev/null", "-c", "--", "echo ok"},
		} {
			idx, rawScript, glued, ok := locateShellCSlot(argv)
			text, has := unwrapShellArgv(argv)
			if !ok || glued || !has || rawScript != text || argv[idx] != rawScript {
				t.Fatalf("locateShellCSlot(%v) = (%d, %q, glued=%v, ok=%v) vs unwrap=(%q,%v), want the same clean script word", argv, idx, rawScript, glued, ok, text, has)
			}
		}
	})
	t.Run("R17-M5-neg glued cluster tails stay unrewritable", func(t *testing.T) {
		for _, argv := range [][]string{
			{"sh", "-ce", "echo ok"},
			{"sh", "-co", "vi", "echo ok"},
		} {
			_, _, glued, ok := locateShellCSlot(argv)
			if !glued || !ok {
				t.Fatalf("locateShellCSlot(%v) glued=%v ok=%v, want a glued-but-decoded verdict", argv, glued, ok)
			}
		}
	})

	// ---- R17-M6: nested stdin classification keeps data consumers ----
	t.Run("R17-M6 flat and nested cat+bash both refuse the rewrite", func(t *testing.T) {
		_, flatOK, _ := scriptAllowsLocalShellStdinPrepareDialect("cat; bash", false, envAssignments{}, "", callerIdentity{})
		if flatOK {
			t.Fatal("flat 'cat; bash' permits a stdin program rewrite, want ok=false (the stream is partly data)")
		}
		targets := stdinProgramTargetsWithEnv([]string{"bash", "-c", "cat; bash"}, 0, envAssignments{}, "", callerIdentity{})
		_, nestedOK, nestedBash := stdinSingleShellTargetDialect(targets, false)
		if nestedOK {
			t.Fatalf("nested 'bash -c \"cat; bash\"' targets permit a stdin program rewrite (bash=%v), want ok=false — the inner cat must not vanish from the summary", nestedBash)
		}
	})
	t.Run("R17-M6-pos pure nested shell targets keep the rewrite", func(t *testing.T) {
		targets := stdinProgramTargetsWithEnv([]string{"bash", "-c", "sh; bash"}, 0, envAssignments{}, "", callerIdentity{})
		if _, mixedOK, _ := stdinSingleShellTargetDialect(targets, false); mixedOK {
			t.Fatal("mixed sh+bash consumers permit a stdin rewrite, want ok=false (R16 dialect agreement)")
		}
		pure := stdinProgramTargetsWithEnv([]string{"bash", "-c", "bash; bash"}, 0, envAssignments{}, "", callerIdentity{})
		envs, ok, bash := stdinSingleShellTargetDialect(pure, false)
		if !ok || len(envs) == 0 || !bash {
			t.Fatalf("pure nested bash targets = (envs=%d, ok=%v, bash=%v), want (>=1, true, true)", len(envs), ok, bash)
		}
	})

	// ---- R17-S1: two ordinary glob fragments are not a brace expansion ----
	t.Run("R17-S1 multi-glob quoted-brace path stays a safe data operand", func(t *testing.T) {
		w := parseBashSingleCmdWord(t, `cat docs/*/'{v1}'/*.txt`, 1)
		if wordBraceExpHit(w) {
			t.Fatal("wordBraceExpHit(docs/*/'{v1}'/*.txt) = true, want false — the braces are single-quoted literal text")
		}
		s1, _ := wordToArg(w)
		if strings.Contains(s1, cmdSubPlaceholderGlob+cmdSubPlaceholderGlob) {
			t.Fatalf("wordToArg encoding %q carries adjacent glob markers, want the two glob fragments SEPARATED by the static infix", s1)
		}
		if !isSafeDynamicDataOperand(s1) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = false, want true — every match keeps the fixed docs/ prefix and {v1} is a literal directory", s1)
		}
		s2, _ := blankSubCollector().wordToArg(w)
		if !isSafeDynamicDataOperand(s2) {
			t.Fatalf("isSafeDynamicDataOperand(%q) = false, want true (collector encoding)", s2)
		}
	})
	t.Run("R17-S1-neg real brace expansions keep the refusal", func(t *testing.T) {
		for _, src := range []string{`echo {docs/a,-blue}`, `echo ~/{red,blue}`} {
			w := parseBashSingleCmdWord(t, src, 1)
			s1, _ := wordToArg(w)
			if !strings.Contains(s1, cmdSubPlaceholderGlob+cmdSubPlaceholderGlob) {
				t.Fatalf("wordToArg(%q) = %q, want the adjacent glob-pair encoding of a real brace expansion", src, s1)
			}
			if isSafeDynamicDataOperand(s1) {
				t.Fatalf("isSafeDynamicDataOperand(%q) = true, want false — a real brace expansion's sibling branches can spell options", s1)
			}
			s2, _ := blankSubCollector().wordToArg(w)
			if isSafeDynamicDataOperand(s2) {
				t.Fatalf("isSafeDynamicDataOperand(%q) = true, want false (collector encoding)", s2)
			}
		}
	})

	// ---- R17-S2: /dev/shm is a valid tmpfs TMPDIR ----
	t.Run("R17-S2 TMPDIR=/dev/shm keeps the success proof", func(t *testing.T) {
		st, err := os.Stat("/dev/shm")
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0o777 || st.Mode()&os.ModeSticky == 0 {
			t.Skipf("/dev/shm not a 1777 tmpfs directory on this host: %v", err)
		}
		t.Setenv("TMPDIR", "/dev/shm")
		if !inheritedTmpdirValid() {
			t.Fatal("inheritedTmpdirValid() = false under TMPDIR=/dev/shm, want true — /dev/shm is a real 1777 tmpfs scratch root")
		}
		got := rtGuardCwd(t, rtCase{id: "R17-S2", role: "worker", cmd: `out=$(mktemp -d); tar -czf "$out/archive.tgz" -C /tmp/src .`}, "")
		if got != "ALLOW" {
			t.Fatalf("rtGuardCwd(mktemp success path under TMPDIR=/dev/shm) = %q, want ALLOW", got)
		}
	})
	t.Run("R17-S2-neg /proc /dev/null /dev/pts stay rejected", func(t *testing.T) {
		for _, td := range []string{"/proc", "/sys", "/dev/null", "/dev/pts"} {
			t.Setenv("TMPDIR", td)
			if inheritedTmpdirValid() {
				t.Fatalf("inheritedTmpdirValid() = true under TMPDIR=%s, want false", td)
			}
		}
	})
}

// TestGuard_V622_OracleR18Probes pins the Oracle R18 audit closure:
// PATH lookups must reproduce the kernel's per-component resolution
// instead of lexically cleaning `..` away (R18-M1), local heredoc and
// here-string payloads are screened against EVERY program target in an
// order-independent way (R18-M2), a static eval's variable writes ride
// back into the enclosing collector's write scan (R18-M3), the tilde
// restoration requires the unforgeable NUL-provenanced marker while the
// word-count proof survives a tainted HOME independently (R18-M4/S5),
// the TMPDIR pseudo-root review is component-exact plus symlink-resolved
// (R18-M5/S3), the -c slot scanner keeps a pending -c across a later
// independent cluster (R18-S1), nested pure-assignment segments consume
// no stdin and never mint a data consumer (R18-S2), and the dash dialect
// rides into command-substitution collectors (R18-S4). Pure-function pins
// reference only production symbols that exist verbatim on the pre-fix
// tree 8c9447a (pathHasExecutable, the screen*Depth helpers,
// parseSubagentShellASTEnv, isSingleWordOptionValue,
// resolveNodeRunnerPathOpt, printfFmtWriteSlots, inheritedTmpdirValid,
// tmpdirPseudoRoot, locateShellCSlot, stdinProgramTargetsWithEnv and
// stdinSingleShellTargetDialect), so the discriminating rows reproduce
// FAIL directly there.
func TestGuard_V622_OracleR18Probes(t *testing.T) {
	// ---- R18-M1: the PATH lookup must not lexically clean `..` ----
	t.Run("R18-M1 /usr/bin/true/.. can never yield mktemp", func(t *testing.T) {
		// Host preconditions from the Oracle R18 read-only metadata check:
		// /usr/bin/true is a regular file and /usr/bin/mktemp is an
		// executable regular file, so /usr/bin/true/../mktemp CANNOT be
		// traversed by the kernel (ENOTDIR at the true component) even
		// though the lexically cleaned /usr/bin/mktemp exists.
		if st, err := os.Stat("/usr/bin/true"); err != nil || st.IsDir() {
			t.Skipf("/usr/bin/true not a regular file: %v", err)
		}
		if st, err := os.Stat("/usr/bin/mktemp"); err != nil || st.IsDir() || st.Mode()&0111 == 0 {
			t.Skipf("/usr/bin/mktemp not executable: %v", err)
		}
		if pathHasExecutable("/usr/bin/true/..", "mktemp") {
			t.Fatal("pathHasExecutable(/usr/bin/true/.., mktemp) = true, want false — the kernel resolves true as a regular file and rejects the traversal with ENOTDIR; a lexical filepath.Join must never launder it into /usr/bin")
		}
	})
	t.Run("R18-M1-pos genuine PATH directories keep resolving executables", func(t *testing.T) {
		if !pathHasExecutable("/usr/bin", "mktemp") {
			t.Fatal("pathHasExecutable(/usr/bin, mktemp) = false, want true")
		}
		if !pathHasExecutable("/usr/bin/", "mktemp") {
			t.Fatal("pathHasExecutable(/usr/bin/, mktemp) = false, want true — a trailing slash is the same directory")
		}
	})

	// ---- R18-M2: every program target of a heredoc / here-string is screened ----
	t.Run("R18-M2 here-string verdict is branch-order independent", func(t *testing.T) {
		// Both shells share the same here-string; either of them may consume
		// it (mutually exclusive branches), so the bash target must face the
		// bash dialect screen regardless of which target sorts first.
		for _, inner := range []string{"dash; bash", "bash; dash"} {
			seg := shellSegment{
				argv:       []string{"sh", "-c", inner},
				hereString: "printf tag{red,blue}",
			}
			hit := screenOneSegmentDepth(seg, 's', 0, callerIdentity{})
			if !strings.Contains(hit, "env dynamic printf") {
				t.Fatalf("screenOneSegmentDepth(sh -c %q <<< printf tag{red,blue}) = %q, want substring %q — either shell may consume the stream and bash brace-expands it", inner, hit, "env dynamic printf")
			}
		}
	})
	t.Run("R18-M2-pos pure dash here-string consumers keep the POSIX literal", func(t *testing.T) {
		seg := shellSegment{
			argv:       []string{"sh", "-c", "dash; dash"},
			hereString: "printf tag{red,blue}",
		}
		if hit := screenOneSegmentDepth(seg, 's', 0, callerIdentity{}); hit != "" {
			t.Fatalf("screenOneSegmentDepth(sh -c 'dash; dash' <<< printf tag{red,blue}) = %q, want no hit — dash performs no brace expansion", hit)
		}
	})
	t.Run("R18-M2-hd heredoc verdict is branch-order independent", func(t *testing.T) {
		for _, inner := range []string{"dash; bash", "bash; dash"} {
			seg := shellSegment{
				argv: []string{"sh", "-c", inner},
				heredocText: []heredocBody{
					{text: "printf tag{red,blue}", quoted: true},
				},
			}
			hit := screenSegmentHeredocsDepth(seg, 's', 0, callerIdentity{})
			if !strings.Contains(hit, "env dynamic printf") {
				t.Fatalf("screenSegmentHeredocsDepth(sh -c %q <<EOF printf tag{red,blue}) = %q, want substring %q", inner, hit, "env dynamic printf")
			}
		}
	})
	t.Run("R18-M2-hd-pos pure dash heredoc consumers keep the POSIX literal", func(t *testing.T) {
		seg := shellSegment{
			argv: []string{"sh", "-c", "dash; dash"},
			heredocText: []heredocBody{
				{text: "printf tag{red,blue}", quoted: true},
			},
		}
		if hit := screenSegmentHeredocsDepth(seg, 's', 0, callerIdentity{}); hit != "" {
			t.Fatalf("screenSegmentHeredocsDepth(sh -c 'dash; dash' <<EOF printf tag{red,blue}) = %q, want no hit", hit)
		}
	})

	// ---- R18-M3: a static eval's IFS write rides back into the collector ----
	ifsFixture := func(t *testing.T, script string, argIdx int) string {
		t.Helper()
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
		}
		last := segs[len(segs)-1]
		if argIdx >= len(last.argv) {
			t.Fatalf("parse %q: last seg argv=%v, want index %d", script, last.argv, argIdx)
		}
		return last.argv[argIdx]
	}
	t.Run("R18-M3 eval IFS write degrades the unquoted HOME exactly like the direct assignment", func(t *testing.T) {
		t.Setenv("HOME", "/home/red:blue")
		direct := ifsFixture(t, "IFS=:; echo $HOME", 1)
		viaEval := ifsFixture(t, "eval 'IFS=:'; echo $HOME", 1)
		if isSingleWordOptionValue(direct) {
			t.Fatalf("control broken: direct IFS=: unquoted $HOME %q is single-word, want false", direct)
		}
		if isSingleWordOptionValue(viaEval) != isSingleWordOptionValue(direct) {
			t.Fatalf("isSingleWordOptionValue(eval spelling %q) = %v vs direct spelling %q = %v — eval re-parses in the SAME shell, so its IFS write must reach the outer collector", viaEval, isSingleWordOptionValue(viaEval), direct, isSingleWordOptionValue(direct))
		}
		if isSingleWordOptionValue(viaEval) {
			t.Fatalf("isSingleWordOptionValue(%q) = true after eval 'IFS=:', want false — unquoted $HOME field-splits on ':' at runtime", viaEval)
		}
	})
	t.Run("R18-M3-pos double-quoted HOME is unaffected by the eval IFS write", func(t *testing.T) {
		t.Setenv("HOME", "/home/red:blue")
		quo := ifsFixture(t, "eval 'IFS=:'; echo \"$HOME\"", 1)
		if !isSingleWordOptionValue(quo) {
			t.Fatalf("isSingleWordOptionValue(%q) = false, want true — double quotes suppress field splitting entirely regardless of IFS", quo)
		}
	})
	t.Run("R18-M3-dyn dynamic eval operands conservatively pollute IFS", func(t *testing.T) {
		t.Setenv("HOME", "/home/red:blue")
		unq := ifsFixture(t, "eval \"$X\"; echo $HOME", 1)
		if isSingleWordOptionValue(unq) {
			t.Fatalf("isSingleWordOptionValue(%q) = true after a dynamic eval, want false — the re-parsed text is unknowable, so IFS may be polluted", unq)
		}
	})

	// ---- R18-M4: the tilde restoration demands unforgeable provenance ----
	t.Run("R18-M4 a literal spelling of the printable marker never resolves to the service HOME", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		w := parseBashSingleCmdWord(t, "echo '~__ctx_glob__/notes'", 1)
		s, _ := blankSubCollector().wordToArg(w)
		cand, ok := resolveNodeRunnerPathOpt(s, "/opt/example")
		if ok && cand == "/home/parent/notes" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true) — the bytes arrived as a single-quoted LITERAL, not a tilde expansion, so the service HOME must never be restored into them", s, cand)
		}
		if ok {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true), want ok=false — the printable glob marker is forgeable evidence, never provenance", s, cand)
		}
	})
	t.Run("R18-M4-pos a real untainted tilde expansion keeps the restoration", func(t *testing.T) {
		t.Setenv("HOME", "/home/user")
		w := parseBashSingleCmdWord(t, `echo ~/notes`, 1)
		s, _ := blankSubCollector().wordToArg(w)
		cand, ok := resolveNodeRunnerPathOpt(s, "/opt/example")
		if !ok || cand != "/home/user/notes" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, %v), want (/home/user/notes, true) — a genuine word-start tilde under a known HOME mints the unforgeable marker", s, cand, ok)
		}
	})
	t.Run("R18-M4-b tainted-HOME tilde keeps failing path restoration closed", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		w := parseBashSingleCmdWord(t, `echo ~/notes`, 1)
		col := blankSubCollector()
		col.taintedVars["HOME"] = true
		s, _ := col.wordToArg(w)
		cand, ok := resolveNodeRunnerPathOpt(s, "/opt/example")
		if ok {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, true), want ok=false under a tainted HOME (R17-M4-b is preserved)", s, cand)
		}
	})

	// ---- R18-M5: the TMPDIR exception is judged on the resolved object ----
	t.Run("R18-M5 the /dev/shm spellings of /dev and /dev/mqueue are rejected", func(t *testing.T) {
		st, err := os.Stat("/dev/mqueue")
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0o777 {
			t.Skipf("/dev/mqueue not a 1777 directory on this host: %v", err)
		}
		for _, td := range []string{"/dev/mqueue", "/dev/shm/..", "/dev/shm/../mqueue"} {
			t.Setenv("TMPDIR", td)
			if inheritedTmpdirValid() {
				t.Fatalf("inheritedTmpdirValid() = true under TMPDIR=%s, want false — %s resolves to a non-tmpfs pseudo filesystem regardless of how it is spelled", td, td)
			}
		}
	})
	t.Run("R18-M5-pos TMPDIR=/dev/shm itself keeps the tmpfs validity", func(t *testing.T) {
		st, err := os.Stat("/dev/shm")
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0o777 || st.Mode()&os.ModeSticky == 0 {
			t.Skipf("/dev/shm not a 1777 tmpfs directory on this host: %v", err)
		}
		t.Setenv("TMPDIR", "/dev/shm")
		if !inheritedTmpdirValid() {
			t.Fatal("inheritedTmpdirValid() = false under TMPDIR=/dev/shm, want true (R17-S2 preserved)")
		}
	})

	// ---- R18-S1: a pending -c survives an independent later cluster ----
	t.Run("R18-S1 locateShellCSlot keeps the pending -c across -e", func(t *testing.T) {
		argv := []string{"bash", "-c", "-e", "echo ok"}
		idx, rawScript, glued, ok := locateShellCSlot(argv)
		text, has := unwrapShellArgv(argv)
		if !has || text != "echo ok" {
			t.Fatalf("unwrapShellArgv(%v) = (%q, %v), want (echo ok, true)", argv, text, has)
		}
		if !ok || glued || idx != 3 || rawScript != "echo ok" {
			t.Fatalf("locateShellCSlot(%v) = (%d, %q, glued=%v, ok=%v), want (3, echo ok, false, true) — the -e cluster must not drop the pending -c state", argv, idx, rawScript, glued, ok)
		}
	})
	t.Run("R18-S1-pos plain spellings keep locating the same word", func(t *testing.T) {
		for _, argv := range [][]string{
			{"sh", "-c", "echo ok"},
			{"bash", "-c", "--", "echo ok"},
		} {
			idx, rawScript, glued, ok := locateShellCSlot(argv)
			text, has := unwrapShellArgv(argv)
			if !ok || glued || !has || rawScript != text || argv[idx] != rawScript {
				t.Fatalf("locateShellCSlot(%v) = (%d, %q, glued=%v, ok=%v) vs unwrap=(%q,%v), want the same clean script word", argv, idx, rawScript, glued, ok, text, has)
			}
		}
	})

	// ---- R18-S2: nested pure-assignment segments consume no stdin ----
	t.Run("R18-S2 nested and flat X=1; bash agree on the pure shell rewrite", func(t *testing.T) {
		targets := stdinProgramTargetsWithEnv([]string{"bash", "-c", "X=1; bash"}, 0, envAssignments{}, "", callerIdentity{})
		_, nestedOK, nestedBash := stdinSingleShellTargetDialect(targets, false)
		if !nestedOK {
			t.Fatalf("nested 'bash -c \"X=1; bash\"' refuses the stdin rewrite, want ok=true — a pure assignment consumes no stdin exactly like the flat spelling")
		}
		flatEnvs, flatOK, flatBash := scriptAllowsLocalShellStdinPrepareDialect("X=1; bash", false, envAssignments{}, "", callerIdentity{})
		if !flatOK || len(flatEnvs) == 0 {
			t.Fatalf("flat 'X=1; bash' control broken: (envs=%d, ok=%v)", len(flatEnvs), flatOK)
		}
		if nestedBash != flatBash {
			t.Fatalf("nested bash=%v vs flat bash=%v — the two spellings must agree", nestedBash, flatBash)
		}
	})
	t.Run("R18-S2-neg nested real data consumers still refuse the rewrite", func(t *testing.T) {
		targets := stdinProgramTargetsWithEnv([]string{"bash", "-c", "cat; bash"}, 0, envAssignments{}, "", callerIdentity{})
		if _, nestedOK, _ := stdinSingleShellTargetDialect(targets, false); nestedOK {
			t.Fatal("nested 'bash -c \"cat; bash\"' permits a stdin rewrite, want ok=false — the inner cat consumes the stream as data (R17-M6 preserved)")
		}
	})

	// ---- R18-S3: /dev-adjacent ordinary directories are not pseudo roots ----
	t.Run("R18-S3 /development/cache is not a pseudo filesystem root", func(t *testing.T) {
		if tmpdirPseudoRoot("/development/cache") {
			t.Fatal("tmpdirPseudoRoot(/development/cache) = true, want false — sharing the /dev prefix does not make an ordinary development directory a device tree")
		}
		for _, td := range []string{"/dev", "/dev/mqueue", "/proc", "/proc/x", "/sys", "/dev/null"} {
			if !tmpdirPseudoRoot(td) {
				t.Fatalf("control broken: tmpdirPseudoRoot(%s) = false, want true", td)
			}
		}
		if tmpdirPseudoRoot("/dev/shm") || tmpdirPseudoRoot("/dev/shm/x") {
			t.Fatal("control broken: /dev/shm[/x] must stay out of the pseudo roots (R17-S2)")
		}
	})

	// ---- R18-S4: dash dialect rides into command substitutions ----
	t.Run("R18-S4 dash command substitution keeps the printf format word static", func(t *testing.T) {
		segs, ok := parseSubagentShellASTEnv("echo $(printf tag{red,blue})", 0, false, false, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse failed: ok=%v segs=%v", ok, segs)
		}
		found := false
		for _, seg := range segs {
			if len(seg.argv) == 2 && seg.argv[0] == "printf" {
				found = true
				if isDynamicArg(seg.argv[1]) {
					t.Fatalf("dash substitution printf format %q is dynamic, want the static literal tag{red,blue} — dash performs no brace expansion inside $(...) either", seg.argv[1])
				}
				if _, dyn := printfFmtWriteSlots(seg.argv[1], nil); dyn {
					t.Fatalf("printfFmtWriteSlots(%q, nil) dyn=true, want false (dash literal)", seg.argv[1])
				}
			}
		}
		if !found {
			t.Fatalf("no printf segment in %v — the substitution was not walked", segs)
		}
	})
	t.Run("R18-S4-neg bash command substitution keeps the brace encoding", func(t *testing.T) {
		segs, ok := parseSubagentShellASTEnv("echo $(printf tag{red,blue})", 0, false, true, nil, callerIdentity{})
		if !ok {
			t.Fatal("bash parse failed")
		}
		found := false
		for _, seg := range segs {
			if len(seg.argv) == 2 && seg.argv[0] == "printf" {
				found = true
				if _, dyn := printfFmtWriteSlots(seg.argv[1], nil); !dyn {
					t.Fatalf("printfFmtWriteSlots(%q, nil) dyn=false under bash, want true — bash really brace-expands inside $(...)", seg.argv[1])
				}
			}
		}
		if !found {
			t.Fatal("no printf segment under bash parse")
		}
	})

	// ---- R18-S5: the tainted-HOME tilde keeps its single-word proof ----
	t.Run("R18-S5 printf ~/banner under a rewritten HOME stays dyn=false", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		segs, ok := parseSubagentShellASTEnv("HOME=/custom/home; printf ~/banner", 0, false, true, nil, callerIdentity{})
		if !ok {
			t.Fatal("parse failed")
		}
		last := segs[len(segs)-1]
		if len(last.argv) != 2 || last.argv[0] != "printf" {
			t.Fatalf("last seg argv=%v, want [printf <tilde-word>]", last.argv)
		}
		if !isSingleWordOptionValue(last.argv[1]) {
			t.Fatalf("isSingleWordOptionValue(%q) = false, want true — bash tilde expansion never field-splits, so the word stays exactly one argv word even when its concrete path is unknowable", last.argv[1])
		}
		if _, dyn := printfFmtWriteSlots(last.argv[1], nil); dyn {
			t.Fatalf("printfFmtWriteSlots(%q, nil) dyn=true, want false — losing the concrete-path proof must not revoke the word-count proof", last.argv[1])
		}
		if _, ok := resolveNodeRunnerPathOpt(last.argv[1], "/opt/example"); ok {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) ok=true, want false — the service HOME must never stand in for the consuming shell's tainted HOME (R17-M4-b preserved)", last.argv[1])
		}
	})
	t.Run("R18-S5-pos untainted printf ~/banner keeps both proofs", func(t *testing.T) {
		t.Setenv("HOME", "/home/user")
		segs, ok := parseSubagentShellASTEnv("printf ~/banner", 0, false, true, nil, callerIdentity{})
		if !ok {
			t.Fatal("parse failed")
		}
		last := segs[len(segs)-1]
		if len(last.argv) != 2 {
			t.Fatalf("last seg argv=%v, want [printf <tilde-word>]", last.argv)
		}
		if _, dyn := printfFmtWriteSlots(last.argv[1], nil); dyn {
			t.Fatalf("printfFmtWriteSlots(%q, nil) dyn=true, want false (R14-S2 positive preserved)", last.argv[1])
		}
		cand, rok := resolveNodeRunnerPathOpt(last.argv[1], "/opt/example")
		if !rok || cand != "/home/user/banner" {
			t.Fatalf("resolveNodeRunnerPathOpt(%q) = (%q, %v), want (/home/user/banner, true)", last.argv[1], cand, rok)
		}
	})
}

// TestGuard_V622_OracleR19Probes pins the Oracle R19 audit closure
// (v6.2.2): the eval `--` option terminator, the static-eval PATH binding
// replication, the tilde expansion shapes, the pure-assignment environment
// propagation, the data-only heredoc payload exemption, the eval recursion
// depth budget and the raw byte-level adjacent double-glob contract. Every
// new-symbol reference uses LITERAL marker bytes so this file compiles
// verbatim on the pre-fix parent trees (R19-Oracle-S3).
func TestGuard_V622_OracleR19Probes(t *testing.T) {
	ifsFixture := func(t *testing.T, script string) (string, bool) {
		t.Helper()
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
		}
		last := segs[len(segs)-1]
		if len(last.argv) < 2 {
			t.Fatalf("parse %q: last seg argv=%v, want at least 2 words", script, last.argv)
		}
		return last.argv[1], isSingleWordOptionValue(last.argv[1])
	}

	// ---- R19-M1: the eval builtin consumes its own `--` terminator ----
	t.Run("R19-M1 eval -- 'IFS=:' counts the IFS write exactly like the plain spelling", func(t *testing.T) {
		t.Setenv("HOME", "/home/red:blue")
		direct := "IFS=:; echo $HOME"
		plain := "eval 'IFS=:'; echo $HOME"
		dashdash := "eval -- 'IFS=:'; echo $HOME"
		dEnc, dOne := ifsFixture(t, direct)
		pEnc, pOne := ifsFixture(t, plain)
		ddEnc, ddOne := ifsFixture(t, dashdash)
		if dOne {
			t.Fatalf("control broken: direct IFS=: unquoted $HOME %q is single-word, want false", dEnc)
		}
		if ddEnc != pEnc || ddOne != pOne {
			t.Fatalf("eval -- 'IFS=:' encodes %q (single=%v) vs eval 'IFS=:' %q (single=%v) — bash consumes the -- terminator itself, so both spellings re-parse the SAME inner text and must agree exactly", ddEnc, ddOne, pEnc, pOne)
		}
		if ddOne {
			t.Fatalf("isSingleWordOptionValue(%q) = true after eval -- 'IFS=:', want false — the IFS write must reach the collector through the terminator", ddEnc)
		}
	})

	// ---- R19-M2: a static eval PATH write reproduces the direct binding ----
	mkFixture := func(t *testing.T, script string) string {
		t.Helper()
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/bin:/bin")
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v", script, ok)
		}
		last := segs[len(segs)-1]
		if len(last.argv) < 2 {
			t.Fatalf("parse %q: last seg argv=%v", script, last.argv)
		}
		return last.argv[1]
	}
	t.Run("R19-M2 eval 'PATH=<no-mktemp>' revokes the abs-dq grant exactly like the direct write", func(t *testing.T) {
		direct := mkFixture(t, `PATH=/usr/local/sbin; echo "$(mktemp -d)"`)
		viaEval := mkFixture(t, `eval 'PATH=/usr/local/sbin'; echo "$(mktemp -d)"`)
		viaEvalDD := mkFixture(t, `eval -- 'PATH=/usr/local/sbin'; echo "$(mktemp -d)"`)
		if strings.Contains(direct, "__ctx_abspath_dq__") {
			t.Fatalf("control broken: direct PATH=/usr/local/sbin write %q keeps the abs-dq class — /usr/local/sbin is verified mktemp-less on this host", direct)
		}
		if viaEval != direct {
			t.Fatalf("eval spelling %q vs direct spelling %q — eval re-parses in the SAME shell, so its single static PATH write must bind exactly like the direct assignment (the effective PATH the substitution success proof resolves against)", viaEval, direct)
		}
		if strings.Contains(viaEval, "__ctx_abspath_dq__") {
			t.Fatalf("eval 'PATH=/usr/local/sbin' encoding %q carries the abs-dq class — the mktemp child cannot even exec under the eval-written PATH", viaEval)
		}
		if strings.Contains(viaEvalDD, "__ctx_abspath_dq__") || viaEvalDD != viaEval {
			t.Fatalf("eval -- 'PATH=...' encoding %q disagrees with %q — the -- terminator must not change the inner binding replication", viaEvalDD, viaEval)
		}
	})
	t.Run("R19-M2-pos eval 'PATH=<with-mktemp>' keeps the grant exactly like the direct write", func(t *testing.T) {
		direct := mkFixture(t, `PATH=/usr/bin:/bin; echo "$(mktemp -d)"`)
		viaEval := mkFixture(t, `eval 'PATH=/usr/bin:/bin'; echo "$(mktemp -d)"`)
		if !strings.Contains(direct, "__ctx_abspath_dq__") {
			t.Fatalf("control broken: direct PATH=/usr/bin:/bin %q lost the abs-dq class (/usr/bin/mktemp is executable)", direct)
		}
		if viaEval != direct {
			t.Fatalf("eval spelling %q vs direct spelling %q — a PATH carrying mktemp keeps the grant under both spellings", viaEval, direct)
		}
	})

	// ---- R19-M3: only real tilde expansions mint the tilde marker ----
	tildeFixture := func(t *testing.T, word string) (string, bool, string, bool) {
		t.Helper()
		w := parseBashSingleCmdWord(t, word, 1)
		s, static := blankSubCollector().wordToArg(w)
		cand, ok := resolveNodeRunnerPathOpt(s, "/opt/r19")
		return s, static, cand, ok
	}
	t.Run("R19-M3 quoted-slash tilde is a verbatim relative path, never a HOME expansion", func(t *testing.T) {
		t.Setenv("HOME", "/home/r19")
		expEnc, _, expCand, expOk := tildeFixture(t, `echo ~/"notes"`)
		if !expOk || expCand != "/home/r19/notes" {
			t.Fatalf("control broken: ~/\"notes\" resolves (%q, %v), want (/home/r19/notes, true) — the slash is UNQUOTED inside the first Lit, so bash really expands the tilde", expCand, expOk)
		}
		if !strings.Contains(expEnc, "\x00__ctx_tilde__\x00") {
			t.Fatalf("control broken: ~/\"notes\" encoding %q lost the tilde provenance marker", expEnc)
		}
		qEnc, qStatic, qCand, qOk := tildeFixture(t, `echo ~\/notes`)
		if strings.Contains(qEnc, "\x00__ctx_tilde__\x00") {
			t.Fatalf("~\\/notes encoding %q mints the tilde provenance — the slash is backslash-QUOTED, so bash never expands this tilde: the word is a verbatim cwd-relative path", qEnc)
		}
		if strings.Contains(qEnc, "__ctx_glob__") {
			t.Fatalf("~\\/notes encoding %q carries a glob marker — a verbatim literal tilde is plain static text (no expansion of any kind happens)", qEnc)
		}
		if !qStatic || qEnc != "~/notes" {
			t.Fatalf("~\\/notes encodes (%q, static=%v), want the static literal ~/notes exactly like the shell passes it", qEnc, qStatic)
		}
		if !qOk || qCand != "/opt/r19/~/notes" {
			t.Fatalf("~\\/notes resolves (%q, %v), want (/opt/r19/~/notes, true) — the verbatim word is a relative path under the caller cwd, never the service HOME", qCand, qOk)
		}
	})
	t.Run("R19-M3-pos login-name tilde stays dynamic without HOME provenance", func(t *testing.T) {
		t.Setenv("HOME", "/home/r19")
		uEnc, uStatic, uCand, uOk := tildeFixture(t, `echo ~root/notes`)
		if uStatic {
			t.Fatalf("~root/notes encodes static — the login lookup is dynamic, never static text")
		}
		if strings.Contains(uEnc, "\x00__ctx_tilde__\x00") {
			t.Fatalf("~root/notes encoding %q mints HOME provenance — ~user expands against the LOGIN DATABASE, never $HOME", uEnc)
		}
		if uOk {
			t.Fatalf("~root/notes resolves (%q, true), want ok=false — an unproven home directory can never be restored", uCand)
		}
	})

	// ---- R19-M4: pure-assignment segments propagate their environment ----
	t.Run("R19-M4 HOME=/home/r19; bash taints the consumer HOME exactly like the env prefix", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		stmtEnvs, stmtOK, _ := scriptAllowsLocalShellStdinPrepareDialect("HOME=/home/r19; bash", false, envAssignments{}, "", callerIdentity{})
		prefixEnvs, prefixOK, _ := scriptAllowsLocalShellStdinPrepareDialect("HOME=/home/r19 bash", false, envAssignments{}, "", callerIdentity{})
		if !prefixOK || len(prefixEnvs) == 0 {
			t.Fatalf("control broken: env-prefix spelling refuses the rewrite (ok=%v envs=%d)", prefixOK, len(prefixEnvs))
		}
		if !stmtOK || len(stmtEnvs) == 0 {
			t.Fatalf("statement spelling refuses the rewrite (ok=%v envs=%d), want ok=true like X=1 — the pure assignment consumes no stdin", stmtOK, len(stmtEnvs))
		}
		prefixTainted := prefixEnvs[0].taintedSentinelNames()["HOME"]
		stmtTainted := stmtEnvs[0].taintedSentinelNames()["HOME"]
		if stmtTainted != prefixTainted {
			t.Fatalf("HOME=/home/r19; bash env HOME-taint=%v vs HOME=/home/r19 bash %v — an exported HOME reassigned in the running shell is inherited by the consumer exactly like the env-prefix spelling", stmtTainted, prefixTainted)
		}
		if !stmtTainted {
			t.Fatal("HOME=/home/r19; bash target env does not taint HOME — the rewritten payload would be graded under the OLD HOME the consumer no longer sees")
		}
	})
	t.Run("R19-M4-n nested bash -c 'HOME=/home/r19; bash' propagates the assignment environment", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		targets := stdinProgramTargetsWithEnv([]string{"bash", "-c", "HOME=/home/r19; bash"}, 0, envAssignments{}, "", callerIdentity{})
		ctrl := stdinProgramTargetsWithEnv([]string{"bash", "-c", "HOME=/home/r19 bash"}, 0, envAssignments{}, "", callerIdentity{})
		if len(targets) == 0 || len(ctrl) == 0 {
			t.Fatalf("target projection broken: nested=%d ctrl=%d", len(targets), len(ctrl))
		}
		got := targets[len(targets)-1].envAs.taintedSentinelNames()["HOME"]
		want := ctrl[len(ctrl)-1].envAs.taintedSentinelNames()["HOME"]
		if got != want {
			t.Fatalf("nested statement spelling HOME-taint=%v vs nested env-prefix %v — the collectSegs skip must not drop the environment mutation", got, want)
		}
		if !got {
			t.Fatal("nested HOME=/home/r19; bash does not taint HOME on the consumer target")
		}
	})
	t.Run("R19-M4-pos neutral X=1; bash stays untainted and rewritable", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect("X=1; bash", false, envAssignments{}, "", callerIdentity{})
		if !ok || len(envs) == 0 {
			t.Fatalf("X=1; bash refuses the rewrite (ok=%v), want true — neutral assignments never touch sentinel state (R18-S2 preserved)", ok)
		}
		if envs[0].taintedSentinelNames()["HOME"] || envs[0].taintedSentinelNames()["X"] {
			t.Fatalf("X=1 taints sentinel state %v, want empty — X is not a sentinel variable", envs[0].taintedSentinelNames())
		}
	})

	// ---- R19-S1: a pure-data heredoc consumer never faces the payload screen ----
	t.Run("R19-S1 cat heredoc with a plain $HOME expansion is not a dynamic code payload", func(t *testing.T) {
		seg := shellSegment{argv: []string{"cat"}, heredocText: []heredocBody{{text: "$HOME", dynamic: true}}}
		if hit := screenSegmentHeredocsDepth(seg, 's', 0, callerIdentity{}); hit != "" {
			t.Fatalf("screenSegmentHeredocsDepth(cat <<EOF $HOME) = %q, want empty — a pure data consumer reads the body as BYTES; no program target exists, so the dynamic code payload screen must not fire", hit)
		}
		segQ := shellSegment{argv: []string{"cat"}, heredocText: []heredocBody{{text: "just data", quoted: true}}}
		if hit := screenSegmentHeredocsDepth(segQ, 's', 0, callerIdentity{}); hit != "" {
			t.Fatalf("control broken: quoted data heredoc hits %q", hit)
		}
	})
	t.Run("R19-S1-neg program consumers keep the dynamic payload refusal", func(t *testing.T) {
		seg := shellSegment{argv: []string{"bash"}, heredocText: []heredocBody{{text: "$HOME", dynamic: true}}}
		if hit := screenSegmentHeredocsDepth(seg, 's', 0, callerIdentity{}); !strings.Contains(hit, "dynamic code payload") {
			t.Fatalf("screenSegmentHeredocsDepth(bash <<EOF $HOME) = %q, want substring %q — a shell reading its program from the stream faces the payload screen", hit, "dynamic code payload")
		}
	})

	// ---- R19-S2: the eval recursion shares the peel depth budget ----
	t.Run("R19-S2 eval nesting beyond peelChainMaxDepth stops parsing the leaf write", func(t *testing.T) {
		// Quoting a text one eval level deeper doubles the backslashes first
		// and then the quotes — inside double quotes \ is special before
		// \ " $ ` only, so this reproduces exactly the nesting bash itself
		// verifies (eval "eval \"zzleaf=1\"" really assigns zzleaf).
		nestEval := func(leaf string, levels int) string {
			inner := leaf
			for i := 0; i < levels; i++ {
				esc := strings.ReplaceAll(inner, `\`, `\\`)
				esc = strings.ReplaceAll(esc, `"`, `\"`)
				inner = `eval "` + esc + `"`
			}
			return inner
		}
		scanLeaf := func(t *testing.T, levels int) int {
			t.Helper()
			p := syntax.NewParser(syntax.Variant(syntax.LangBash))
			f, err := p.Parse(strings.NewReader(nestEval("zzleaf=1", levels)), "")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			writes, _ := preScanVarMutations(f, false)
			return writes["zzleaf"]
		}
		shallow := scanLeaf(t, 3)
		if shallow != 1 {
			t.Fatalf("control broken: 3-level nested static eval leaf write count = %d, want 1 — shallow nesting stays inside the budget and replays exactly", shallow)
		}
		deep := scanLeaf(t, peelChainMaxDepth+1)
		if deep != 0 {
			t.Fatalf("peelChainMaxDepth+1-level nested eval leaf write count = %d, want 0 — beyond the depth budget the leaf is never parsed and only the conservative sentinel accounting applies", deep)
		}
	})

	// ---- R19-O1: the raw encoding carries the adjacent glob pair ----
	t.Run("R19-O1 a HOME-proven tilde brace word ends in the RAW adjacent glob pair", func(t *testing.T) {
		t.Setenv("HOME", "/home/user")
		w := parseBashSingleCmdWord(t, `echo ~/{red,blue}`, 1)
		s, _ := blankSubCollector().wordToArg(w)
		pair := "__ctx_glob____ctx_glob__"
		if !strings.Contains(s, pair) {
			t.Fatalf("subCollector.wordToArg(~/{red,blue}) = %q — the RAW encoding must carry the consecutive adjacent glob pair writeBraceExpansionMarkers guarantees, not only the tilde-stripped normalized form", s)
		}
		if !strings.HasSuffix(s, pair) {
			t.Fatalf("subCollector.wordToArg(~/{red,blue}) = %q — the adjacent pair must sit at the word tail (tilde provenance precedes the glob markers)", s)
		}
	})
}
