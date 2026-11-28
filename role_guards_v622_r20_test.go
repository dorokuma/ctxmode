package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// role_guards_v622_r20_test.go — Oracle R20/R21/R22 audit regression tests.
// R22 merge note: role_guards_v622_r21_test.go is folded into this file
// (the suites share the probe fixtures and helper imports; the R20/R21
// overlap the R21 header documented is de-duplicated inside the R21 func).
//
// Coverage contract (one discriminating test per Must-Fix / Should-Fix,
// mirroring the R20 report's acceptance criteria):
//
//	R20-M1: a static eval's assignment replication requires a real builtin
//	  invocation — no path component in the eval command head, NO redirection
//	  on the call, and no `+=` append assignment.
//	R20-M2: writes hidden inside a compound statement of a static eval text
//	  (behind `&&`/`||`/if/braces — where the replication loop never descends)
//	  can never vanish: PATH (and every sentinelTrustVars name) is tainted
//	  when the replay cannot produce an exact binding.
//	R20-M3: only assignments the PARENT shell really performs propagate into
//	  later stdin consumers — never a subshell/pipeline component's local
//	  scope and never a childless `/usr/bin/env KEY=VAL` process.
//	R20-M4: the mixed-dialect stdin fallback (guardCtxRunStdinForCommand)
//	  carries the accumulated pure-assignment environment forward exactly
//	  like the flat prepare scan.
//	R20-M5: stdin target recursion at the depth boundary yields an explicit
//	  exhaustion / program target, never a confirmed data-only verdict.
//	R20-S1: a login-name tilde prefix carrying quoted bytes is a verbatim
//	  cwd-relative literal path (never dynamic glob text).
//	R20-S2: the linear length/budget discrimination of the eval depth
//	  fixture — the authoritative copy lives in
//	  role_guards_v622_eval_test.go (R19-S2); R21 deduplicated the
//	  repeated clone that used to sit here.
//	Observation: merged target snapshots capacity-freeze their backing
//	  array on EVERY branch (including the empty-side passthroughs), and
//	  consecutive pure assignments append in place instead of paying the
//	  quadratic copy cascade.
//
// R21 coverage lives in TestGuard_V622_OracleR21Probes (merged from the
//   former role_guards_v622_r21_test.go).
//
// R22 adds: special/declared-readonly variables never mint the static
//   binding and shell function shadowing of eval/command/builtin refuses
//   the exact eval replication (M1); eval operand writes outside the
//   replication's shape taint the exact variables, and an unknown-option
//   or shadowed chain revokes the single-write PATH pollution exemption
//   (M2); elif-condition writes never land as exact overrides,
//   self-referencing overwrites preserve conditional uncertainty and a
//   quoted KEY=VAL command word is never folded as an assignment (M3);
//   stdin program-target exhaustion propagates end to end — wrapper-peel
//   budget cutoff, nested parse failure, xargs inner exhaustion and the
//   remote exemption's zero-value re-read (M5); a bare unknown name under
//   an untrusted PATH is an explicit unknown target (M6); concurrent
//   xargs analyses stay isolated per request (L1); and pure-assignment
//   runs pay zero environment snapshot copies in the production
//   traversal (SF2).
//
// Every discriminating row is FAIL-first on the pre-fix merge tree: the
// probes reference only symbols that already exist there (the collectors,
// the stdin projection helpers, tildeLitShape's callers and the depth
// constants), so the file compiles verbatim on the Commit-1 tree and the
// failures reproduce the audit findings directly.

func TestGuard_V622_OracleR20Probes(t *testing.T) {
	// ---- R20-M1: eval replication requires the real-builtin premises ----
	r20vFixture := func(t *testing.T, script string) string {
		t.Helper()
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
		}
		last := segs[len(segs)-1]
		if len(last.argv) < 2 {
			t.Fatalf("parse %q: last seg argv=%v, want at least 2 words", script, last.argv)
		}
		return last.argv[1]
	}
	t.Run("R20-M1 path-headed eval and failing-redirect eval never mint the static binding", func(t *testing.T) {
		// /dev/null is a character device on this host: /dev/null/eval can
		// never exec (ENOTDIR) and /dev/null/missing can never open, so
		// neither invocation performs the assignment — while the plain
		// builtin spelling really re-parses in the same shell. The fixtures
		// hold exactly ONE write of R20_V (the eval operand) so the single-
		// write replication criterion applies, and no fixture depends on
		// any temporary file existing.
		plain := r20vFixture(t, `eval 'R20_V=/after'; echo "$R20_V"`)
		if plain != "/after" {
			t.Fatalf("control broken: builtin eval binding query = %q, want /after — the eval replication itself regressed", plain)
		}
		viaPath := r20vFixture(t, `/dev/null/eval 'R20_V=/after'; echo "$R20_V"`)
		if viaPath == "/after" {
			t.Fatalf("/dev/null/eval binding query = %q — an EXTERNAL process can never write the shell's variables; the path-headed eval must not replicate a static /after bind", viaPath)
		}
		viaRedir := r20vFixture(t, `eval 'R20_V=/after' < /dev/null/missing; echo "$R20_V"`)
		if viaRedir == "/after" {
			t.Fatalf("eval < /dev/null/missing binding query = %q — a redirection that fails BEFORE the builtin runs means the write never happens; no static /after bind may stand", viaRedir)
		}
	})
	t.Run("R20-M1 append assignment inside a static eval never mints the suffix-only binding", func(t *testing.T) {
		// bash's += concatenates onto whatever value the variable already
		// holds at runtime — with exactly one write in the script the
		// replication cannot know the inherited value, so a conservative
		// taint/unknown verdict is REQUIRED: the wrong outcome is the
		// suffix-only EXACT bind the replication currently mints.
		got := r20vFixture(t, `eval 'R20_V+=/suffix'; echo "$R20_V"`)
		if got == "/suffix" {
			t.Fatalf("eval 'R20_V+=/suffix' binding query = %q — bash's append operator concatenates onto the inherited value, so the runtime result is never the bare suffix; the replication must treat the assignment as pollution/unknown instead of minting the exact bind", got)
		}
	})

	// ---- R20-M2: writes inside compound statements of the eval text ----
	t.Run("R20-M2 nested eval behind && inside a static eval revokes the parent PATH proof", func(t *testing.T) {
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/bin:/bin")
		mk := func(script string) string {
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
		script := `eval ': && eval "PATH=/usr/local/sbin"'; echo "$(mktemp -d)"`
		// Pre-scan MUST count the write (the scan descends into nested
		// static evals of the whole inner text — the replication loop is
		// the side that cannot reach them).
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(script), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		writes, _ := preScanVarMutations(f, false)
		if writes["PATH"] != 1 {
			t.Fatalf("pre-scan PATH write count = %d, want 1 — the scanner sees the nested eval write exactly like the direct spelling (this assertion pins the scanner half of the invariant)", writes["PATH"])
		}
		enc := mk(script)
		if strings.Contains(enc, "__ctx_abspath_dq__") {
			t.Fatalf("eval ': && eval \"PATH=/usr/local/sbin\"' substitution encoding %q carries the abs-dq class — the nested eval CAN write PATH in the same shell, and the replication never reaches it, so no proof may resolve mktemp under the parent's ORIGINAL PATH", enc)
		}
	})

	// ---- R20-M3: subprocess/subshell environments never rebind the parent ----
	t.Run("R20-M3 env-PATH=B / (PATH=B) consumers keep the parent PATH view", func(t *testing.T) {
		const pathA = "/usr/bin:/bin"
		const pathB = "/usr/local/sbin"
		probe := func(script string) (string, bool) {
			envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect(script, false, envAssignments{}, pathA, callerIdentity{})
			if !ok || len(envs) == 0 {
				return "", false
			}
			return envs[len(envs)-1].effectivePATHFrom(pathA), true
		}
		parent, ok := probe("PATH=" + pathB + "; /bin/bash")
		if !ok {
			t.Fatalf("control broken: parent-shell PATH assignment refuses the rewrite")
		}
		if parent != pathB {
			t.Fatalf("PATH=B; /bin/bash consumer effective PATH = %q, want %q — the running shell's reassignment is inherited by every later child", parent, pathB)
		}
		viaEnv, envOK := probe("/usr/bin/env PATH=" + pathB + "; /bin/bash")
		if envOK && viaEnv == pathB {
			t.Fatalf("/usr/bin/env PATH=B; /bin/bash consumer effective PATH = %q — env spawns its own process: without a child command it merely PRINTS its environment and can never modify the calling shell, so the consumer must not see PATH=B", viaEnv)
		}
		viaSubshell, subOK := probe("(PATH=" + pathB + "); /bin/bash")
		if subOK && viaSubshell == pathB {
			t.Fatalf("(PATH=B); /bin/bash consumer effective PATH = %q — a subshell's local assignment dies with the subshell; the parent's consumer must keep PATH=A (or the rewrite may be refused, but never granted under B)", viaSubshell)
		}
	})

	// ---- R20-M4: the mixed-dialect stdin fallback keeps the accumulated env ----
	t.Run("R20-M4 guardCtxRunStdinForCommand carries the pure-assignment HOME forward", func(t *testing.T) {
		t.Setenv("HOME", "/home/parent")
		// The HOME-tainted command-head verdict is the discriminating
		// observable: with the assignment propagated, "$HOME/bin/hc"
		// encodes DYNAMIC (the tainted HOME revokes the static path text)
		// exactly like the env-prefix spelling, while the HEAD fallback —
		// which rebuilds an empty environment per segment — keeps the
		// inherited static resolution and reports the wrong rule entirely.
		g := guardCall{subagent: true}
		stmtRule, stmtDetail := g.guardCtxRunStdinForCommand("HOME=/home/r20mix; dash; bash", "$HOME/bin/hc")
		prefixRule, prefixDetail := g.guardCtxRunStdinForCommand("HOME=/home/r20mix dash; HOME=/home/r20mix bash", "$HOME/bin/hc")
		if stmtRule != prefixRule || stmtDetail != prefixDetail {
			t.Fatalf("independent-assignment stdin fallback verdict (%q, %q) vs env-prefix control (%q, %q) — the rewritten-away prepare path is no excuse for screening the SAME bytes under a HOME the consumer no longer has", stmtRule, stmtDetail, prefixRule, prefixDetail)
		}
		if stmtRule == "" {
			t.Fatalf("stdin fallback ALLOWS $HOME/bin/hc — a path-shaped command head must always face a verdict in this fixture")
		}
	})

	// ---- R20-M5: depth exhaustion never mints a data-only verdict ----
	t.Run("R20-M5 depth-exhausted stdin projection is not a confirmed data consumer", func(t *testing.T) {
		segs, ok := parseSubagentShellASTEnv("bash", 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) != 1 {
			t.Fatalf("parse of plain bash segment failed: ok=%v segs=%v", ok, segs)
		}
		targets := collectStdinSegTargets(segs[0], shellSplitMaxDepth-1, envAssignments{}, envAssignments{}, "", false, callerIdentity{})
		nonData := stdinProgramNonDataTargets(targets)
		if len(nonData) == 0 {
			t.Fatalf("collectStdinSegTargets at depth=shellSplitMaxDepth-1 yields %v targets with NO non-data entry — depth exhaustion must surface as an explicit exhaustion/program marker, never degrade into a data-only verdict that exempts dynamic heredoc payloads", targets)
		}
		ctrl := collectStdinSegTargets(segs[0], shellSplitMaxDepth-2, envAssignments{}, envAssignments{}, "", false, callerIdentity{})
		ctrlNonData := stdinProgramNonDataTargets(ctrl)
		if len(ctrlNonData) == 0 {
			t.Fatalf("control broken: one depth level earlier the plain bash segment yields no program target either (%v) — the projection itself regressed", ctrl)
		}
		// R21 reviewer #7: the boundary shape alone does not discriminate —
		// a projection minting ordinary dash verdicts on BOTH sides passes
		// it. The consumer verdict is the real contract: the exhausted
		// target must face an explicit rejection at the final consumption
		// point, distinguishable from the one-level-shallower KNOWN bash
		// consumer's ordinary per-language screen.
		hitExh := screenHereStringTargetsDepth("printf tag{red,blue}", targets, 's', 0, callerIdentity{})
		if hitExh != depthExceededHit {
			t.Fatalf("screenHereStringTargetsDepth(exhausted boundary target) = %q, want %q — exhaustion at the final consumer is an explicit depth rejection, never the zero-value POSIX-shell screen", hitExh, depthExceededHit)
		}
		hitCtrl := screenHereStringTargetsDepth("printf tag{red,blue}", ctrl, 's', 0, callerIdentity{})
		if hitCtrl == "" || hitCtrl == depthExceededHit {
			t.Fatalf("control broken: the KNOWN bash consumer one level shallower screens the brace payload with %q — the per-language dialect verdict must stay distinguishable from the exhaustion rejection", hitCtrl)
		}
	})

	// ---- R20-S1: quoted login-name tilde prefix is a verbatim literal ----
	t.Run("R20-S1 quoted-bytes login tilde resolves as a static cwd-relative path", func(t *testing.T) {
		t.Setenv("HOME", "/home/r19")
		fixture := func(word string) (string, bool, string, bool) {
			w := parseBashSingleCmdWord(t, word, 1)
			s, static := blankSubCollector().wordToArg(w)
			cand, ok := resolveNodeRunnerPathOpt(s, "/opt/r19")
			return s, static, cand, ok
		}
		enc, static, cand, ok := fixture(`echo ~ro"ot"/notes`)
		if !static {
			t.Fatalf("~ro\"ot\"/notes encodes dynamic (%q) — bash's tilde expansion requires every byte of the login-name prefix UNQUOTED, so the quoted \"ot\" makes the whole word a verbatim literal, never a glob/dynamic shape", enc)
		}
		if strings.Contains(enc, "__ctx_glob__") || strings.Contains(enc, "\x00__ctx_tilde__\x00") {
			t.Fatalf("~ro\"ot\"/notes encoding %q carries glob/tilde markers — nothing expands in this word, it is plain static text", enc)
		}
		if enc != "~root/notes" {
			t.Fatalf("~ro\"ot\"/notes encodes %q, want the de-quoted literal ~root/notes exactly like the shell passes it", enc)
		}
		if !ok || cand != "/opt/r19/~root/notes" {
			t.Fatalf("~ro\"ot\"/notes resolves (%q, %v), want (/opt/r19/~root/notes, true) — a verbatim relative path under the caller cwd, no account-database lookup involved", cand, ok)
		}
		// Negative control: the FULLY unquoted login-name spelling keeps
		// its original refusal (the login lookup is genuinely dynamic).
		uEnc, uStatic, uCand, uOk := fixture(`echo ~root/notes`)
		if uStatic || uOk {
			t.Fatalf("control broken: unquoted ~root/notes encodes (%q, static=%v) resolves (%q, %v) — the genuine login-name tilde must stay dynamic and unresolvable", uEnc, uStatic, uCand, uOk)
		}
	})

	// ---- Observation: merged snapshots are capacity-frozen on every branch ----
	t.Run("R20-OBS merged empty-side passthrough freezes capacity so appends cannot clobber shared backing", func(t *testing.T) {
		// R21 reviewer #7: the proof must exercise the EMPTY-SIDE direct
		// return branch — merging two non-empty slices allocates a fresh
		// exactly-sized array on ANY implementation (even the pre-fix one),
		// so it can never discriminate. Build a backing array with SPARE
		// capacity directly, hand it to merged as the non-empty side with
		// the other side empty, and verify appending onto the RETURNED
		// snapshot cannot overwrite the spare slots of the original
		// backing array — a passthrough without the three-index freeze
		// shares the backing store with cap > len and the append lands in
		// the caller's own memory.
		backing := make([]envOp, 1, 4)
		backing[0] = envOp{kind: 'a', key: "A", value: "1"}
		source := envAssignments{ops: backing}
		snap := envAssignments{}.merged(source)
		if len(snap.ops) != cap(snap.ops) {
			t.Fatalf("empty-side merged snapshot len %d != cap %d — the passthrough must capacity-freeze the handed-out slice or a later append writes shared memory", len(snap.ops), cap(snap.ops))
		}
		grown := append(snap.ops, envOp{kind: 'a', key: "B", value: "2"})
		if len(grown) != 2 {
			t.Fatalf("append shape broken: %d ops, want 2", len(grown))
		}
		// The ORIGINAL backing array's spare slot must still read zero —
		// the append onto the returned snapshot must have reallocated
		// instead of writing into backing[1] (read through a reslice —
		// the backing array physically owns the memory even though the
		// original slice length stops at 1).
		spare := backing[:cap(backing)][1]
		if spare.kind != 0 || spare.key != "" {
			t.Fatalf("append onto the merged snapshot clobbered the shared backing array slot: spare=%v — the empty-side passthrough shares memory without the capacity freeze", spare)
		}
		// Mirror branch: non-empty LEFT side with an empty right side.
		backing2 := make([]envOp, 1, 4)
		backing2[0] = envOp{kind: 'a', key: "C", value: "3"}
		snap2 := (envAssignments{ops: backing2}).merged(envAssignments{})
		if len(snap2.ops) != cap(snap2.ops) {
			t.Fatalf("left-side merged snapshot len %d != cap %d — the mirror passthrough must freeze capacity too", len(snap2.ops), cap(snap2.ops))
		}
		grown2 := append(snap2.ops, envOp{kind: 'a', key: "D", value: "4"})
		if len(grown2) != 2 {
			t.Fatalf("mirror append shape broken: %d ops, want 2", len(grown2))
		}
		spare2 := backing2[:cap(backing2)][1]
		if spare2.kind != 0 || spare2.key != "" {
			t.Fatalf("mirror append clobbered the shared backing array slot: spare2=%v", spare2)
		}
	})
}

func TestGuard_V622_OracleR21Probes(t *testing.T) {
	// lastOperand encodes the last segment's second argv word of a script —
	// the substitution/query result the replication state decides.
	lastOperand := func(t *testing.T, script string) string {
		t.Helper()
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
		}
		last := segs[len(segs)-1]
		if len(last.argv) < 2 {
			t.Fatalf("parse %q: last seg argv=%v, want at least 2 words", script, last.argv)
		}
		return last.argv[1]
	}

	// ---- R21-M1: the complete wrapper chain must validate ----

	t.Run("R21-M1 slash-carrying wrapper and unknown command option never mint the static binding", func(t *testing.T) {
		plain := lastOperand(t, `eval 'R21_V=/after'; echo "$R21_V"`)
		if plain != "/after" {
			t.Fatalf("control broken: builtin eval binding query = %q, want /after — the eval replication itself regressed", plain)
		}
		viaSlashWrapper := lastOperand(t, `/dev/null/command eval 'R21_V=/after'; echo "$R21_V"`)
		if viaSlashWrapper == "/after" {
			t.Fatalf("/dev/null/command eval binding query = %q — the wrapper word carries a path component, so it execs an EXTERNAL program that can never invoke the shell builtin; no exact /after bind may stand", viaSlashWrapper)
		}
		viaUnknownOpt := lastOperand(t, `command -x eval 'R21_V=/after'; echo "$R21_V"`)
		if viaUnknownOpt == "/after" {
			t.Fatalf("command -x eval binding query = %q — an unknown non-query option is outside the real builtin's contract (the invocation errors before eval can run), so the operand write must never replicate as an exact bind", viaUnknownOpt)
		}
		// Positive control for the legal non-query option: `command -p` is
		// POSIX's documented execution option, so the replication premise
		// holds exactly like the bare builtin spelling.
		viaDashP := lastOperand(t, `command -p eval 'R21_V=/after'; echo "$R21_V"`)
		if viaDashP != "/after" {
			t.Fatalf("control broken: command -p eval binding query = %q, want /after — -p is the legal non-query execution option of the real builtin", viaDashP)
		}
	})

	t.Run("R21-M1 array-subscript write inside a static eval never mints the scalar binding", func(t *testing.T) {
		// `arr[1]=/after` writes ONE element of the array arr — every other
		// element keeps its inherited value, so the scalar expansion "$arr"
		// (element 0) is never the literal /after the replication would
		// record: the write must surface as pollution, never a bind.
		got := lastOperand(t, `eval 'R21_V[1]=/after'; echo "$R21_V"`)
		if got == "/after" {
			t.Fatalf("eval 'R21_V[1]=/after' binding query = %q — the array-subscript write leaves element 0 untouched, so the scalar expansion is never the written suffix; the replication must treat it as pollution/unknown", got)
		}
	})

	// ---- R21-M2: the unified write definition covers builtin writes ----

	t.Run("R21-M2 printf -v write inside a static eval revokes the parent PATH proof", func(t *testing.T) {
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/bin:/bin")
		script := `eval 'printf -v PATH %s /usr/local/sbin'; echo "$(mktemp -d)"`
		// Pre-scan MUST count the write — printf -v VAR is the pre-scan's
		// named-write builtin shape, exactly like a syntax assignment.
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(script), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		writes, _ := preScanVarMutations(f, false)
		if writes["PATH"] != 1 {
			t.Fatalf("pre-scan PATH write count = %d, want 1 — the scanner sees the printf -v write exactly like the direct spelling (this assertion pins the scanner half of the invariant)", writes["PATH"])
		}
		enc := lastOperand(t, script)
		if strings.Contains(enc, "__ctx_abspath_dq__") {
			t.Fatalf("eval 'printf -v PATH ...' substitution encoding %q carries the abs-dq class — the printf builtin provably CAN write PATH in the same shell, and a write the pre-scan counts must never fall back to the parent's ORIGINAL PATH in the mktemp success proof", enc)
		}
	})

	t.Run("R21-M2 root-level static eval inside a tainted eval text is never skipped", func(t *testing.T) {
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/bin:/bin")
		// The outer eval carries a failing redirect, so its operand text is
		// TAINTED rather than bound; inside that text the ROOT statement is
		// itself a static eval whose write the pre-scan counts. Walking
		// only st.Cmd's descendants matches no *syntax.Stmt root — the write
		// must surface as pollution regardless.
		script := `eval 'eval "PATH=/usr/local/sbin"' < /dev/null/missing; echo "$(mktemp -d)"`
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(script), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		writes, _ := preScanVarMutations(f, false)
		if writes["PATH"] != 1 {
			t.Fatalf("pre-scan PATH write count = %d, want 1 — the scanner descends the nested static eval of the inner text", writes["PATH"])
		}
		enc := lastOperand(t, script)
		if strings.Contains(enc, "__ctx_abspath_dq__") {
			t.Fatalf("tainted eval text with a root-level static eval encoding %q carries the abs-dq class — the counted PATH write must land as pollution even when the nested eval IS the root statement of its operand text", enc)
		}
	})

	t.Run("R21-M2 direct printf -v PATH write outside eval revokes the proof", func(t *testing.T) {
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/bin:/bin")
		// The same unified write definition applies to direct statements:
		// a counted printf -v write must never leave the parent's original
		// PATH standing in the substitution success proof.
		enc := lastOperand(t, `printf -v PATH %s /usr/local/sbin; echo "$(mktemp -d)"`)
		if strings.Contains(enc, "__ctx_abspath_dq__") {
			t.Fatalf("printf -v PATH substitution encoding %q carries the abs-dq class — the direct builtin write must replay as pollution exactly like the eval-hidden spelling", enc)
		}
	})

	// ---- R21-M3: scope-aware environment accumulation ----

	t.Run("R21-M3 subshell consumers see the exact snapshot sequence", func(t *testing.T) {
		const pathA = "/usr/bin:/bin"
		const pathB = "/usr/local/sbin"
		envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect("(PATH="+pathB+"; /bin/bash); /bin/bash", false, envAssignments{}, pathA, callerIdentity{})
		if ok {
			if len(envs) != 2 {
				t.Fatalf("rewrite granted with %d target envs, want 2 — one per same-dialect shell consumer", len(envs))
			}
			inner := envs[0].effectivePATHFrom(pathA)
			outer := envs[1].effectivePATHFrom(pathA)
			if inner != pathB || outer != pathA {
				t.Fatalf("subshell snapshot sequence = [%q, %q], want [%q, %q] — the subshell assignment binds within the SAME subshell's consumers and dies with it; [A,A] drops the inner visibility, [B,B] leaks it to the parent", inner, outer, pathB, pathA)
			}
		}
		// Refusing the rewrite is the other licensed outcome (the
		// conservative direction), so an !ok verdict is accepted — the
		// discrimination is only against a WRONG exact sequence.
	})

	t.Run("R21-M3 conditional writes never override outer consumers exactly", func(t *testing.T) {
		const pathA = "/usr/bin:/bin"
		const pathB = "/usr/local/sbin"
		probe := func(script string) (string, bool) {
			envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect(script, false, envAssignments{}, pathA, callerIdentity{})
			if !ok || len(envs) == 0 {
				return "", false
			}
			return envs[len(envs)-1].effectivePATHFrom(pathA), true
		}
		// Unconditional control: the exact override is the correct answer.
		uncond, uncondOK := probe("PATH=" + pathB + "; /bin/bash")
		if !uncondOK || uncond != pathB {
			t.Fatalf("control broken: unconditional PATH=B; /bin/bash = (%q, %v), want (%q, true)", uncond, uncondOK, pathB)
		}
		for _, tc := range []struct {
			name   string
			script string
		}{
			{"if branch", "if x=1; then PATH=" + pathB + "; fi; /bin/bash"},
			{"loop body", "for i in 1; do PATH=" + pathB + "; done; /bin/bash"},
			{"case arm", "case x in x) PATH=" + pathB + ";; esac; /bin/bash"},
			{"uncalled function body", "f() { PATH=" + pathB + "; }; /bin/bash"},
		} {
			got, ok := probe(tc.script)
			if ok && got == pathB {
				t.Fatalf("%s: consumer effective PATH = %q under a GRANTED rewrite — the conditional write may never execute, so an exact B override is unsound in BOTH directions; the rewrite must be refused or the consumer must keep an uncertain view", tc.name, got)
			}
		}
	})

	t.Run("R21-M3 background compound subtree keeps the parent scope", func(t *testing.T) {
		const pathA = "/usr/bin:/bin"
		const pathB = "/usr/local/sbin"
		envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect("{ PATH="+pathB+"; } & /bin/bash", false, envAssignments{}, pathA, callerIdentity{})
		if ok && len(envs) > 0 {
			got := envs[len(envs)-1].effectivePATHFrom(pathA)
			if got == pathB {
				t.Fatalf("{ PATH=B; } & /bin/bash consumer effective PATH = %q — the backgrounded compound runs in its own child process: the assignment dies with it and the child-scope marker must propagate DOWNWARD through the whole subtree, not just ride the leaf statement's background bit", got)
			}
		}
	})

	// ---- R21-M5: depth exhaustion blocks at the final consumption point ----

	// ---- R21-xargs: append-mode nested recursion keeps its verdict ----

	t.Run("R21-xargs append-mode nested recursion verdict is stable", func(t *testing.T) {
		// Behavior pin for the recursion merge: a chain of append-mode
		// nested xargs feeding an inline-code target still reports the
		// open feed (the merge must not drop the single necessary
		// recursion), while a replace-token outer invocation closes it.
		deep := []string{"sh", "-c"}
		for i := 0; i < 6; i++ {
			deep = append([]string{"xargs"}, deep...)
		}
		if !xargsFeedsCodeFlag(deep[1:], deep, "/usr/bin:/bin", callerIdentity{}) {
			t.Fatalf("xargsFeedsCodeFlag(6-level append-mode chain feeding sh -c) = false — the merged recursion lost the single necessary descent: appended stdin words still reach the open -c slot of the innermost target")
		}
		replTarget := []string{"watch", "-x", "sh", "-c", "{}"}
		repl := []string{"xargs", "-I", "{}"}
		if !xargsFeedsCodeFlag(replTarget, repl, "/usr/bin:/bin", callerIdentity{}) {
			t.Fatalf("xargsFeedsCodeFlag(replace-token chain landing in sh -c) = false — the replace-token branch shape must keep its independent descent")
		}
		// Append-mode negative control: a plain cat target has no open
		// inline-code slot at all, so even a fully appended chain reports
		// the feed CLOSED — the merged recursion must not manufacture a
		// false positive by collapsing distinct recursion states.
		catChain := []string{"cat"}
		for i := 0; i < 6; i++ {
			catChain = append([]string{"xargs"}, catChain...)
		}
		if xargsFeedsCodeFlag(catChain[1:], catChain, "/usr/bin:/bin", callerIdentity{}) {
			t.Fatalf("xargsFeedsCodeFlag(6-level append-mode chain feeding plain cat) = true — cat carries no open inline-code slot; the memo/merge must not alias the sh -c descent")
		}
	})

	// ---- R21-PATH-budget: chained self-reference expansion is bounded ----

	t.Run("R21-PATH-budget chained self-reference expansion yields the untrusted verdict", func(t *testing.T) {
		// One single small self-reference keeps its exact expansion (the
		// order semantics of PATH=$PATH:/x must survive).
		var small envAssignments
		small.addAssign("PATH=" + envPathSelfPlaceholder + "/x")
		smallPath := small.effectivePATHFrom("/usr/bin:/bin")
		if smallPath != "/usr/bin:/bin/x" {
			t.Fatalf("control broken: single self-reference expansion = %q, want /usr/bin:/bin/x — the budget gate must not disturb the ordinary single expansion", smallPath)
		}
		// A cross-statement doubling chain materializes the previous
		// expansion repeatedly: 14 rounds of PATH=$PATH:$PATH replay to
		// ~229 KB — beyond maxShellCommandBytes. The verdict must be the
		// untrusted placeholder (no giant allocation, and NEVER a
		// truncation that spells a different valid short PATH).
		var chain envAssignments
		for i := 0; i < 14; i++ {
			chain.addAssign("PATH=" + envPathSelfPlaceholder + ":" + envPathSelfPlaceholder)
		}
		p := chain.effectivePATHFrom("/usr/bin:/bin")
		if p != cmdSubPlaceholder {
			t.Fatalf("chained self-reference expansion len=%d — want the untrusted placeholder verdict exactly: expanding further either allocates an attacker-sized string or truncates into a DIFFERENT valid short PATH the shell never computes", len(p))
		}
	})
}

func TestGuard_V622_OracleR22Probes(t *testing.T) {
	// lastOperand encodes the last segment's second argv word of a script —
	// the substitution/binding result the replication state decides.
	lastOperand := func(t *testing.T, script string) string {
		t.Helper()
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
		}
		last := segs[len(segs)-1]
		if len(last.argv) < 2 {
			t.Fatalf("parse %q: last seg argv=%v, want at least 2 words", script, last.argv)
		}
		return last.argv[1]
	}

	// ---- R22-M1a: readonly/special variables never mint the exact binding ----
	t.Run("R22-M1 readonly special and declared-readonly variables never mint the static binding", func(t *testing.T) {
		plain := lastOperand(t, `eval 'R22_V=/after'; echo "$R22_V"`)
		if plain != "/after" {
			t.Fatalf("control broken: builtin eval binding query = %q, want /after — the eval replication itself regressed", plain)
		}
		for _, tc := range []struct {
			name   string
			script string
		}{
			// Bash/POSIX readonly or dynamic special variables: the write
			// can NEVER establish the spelled value at runtime.
			{"UID special", `eval 'UID=/after'; echo "$UID"`},
			{"RANDOM dynamic special", `eval 'RANDOM=/after'; echo "$RANDOM"`},
			{"EPOCHSECONDS dynamic special", `eval 'EPOCHSECONDS=/after'; echo "$EPOCHSECONDS"`},
			// Script-declared readonly: the write fails outright at runtime.
			{"readonly bare then assign", `readonly R22_RO; eval 'R22_RO=/after'; echo "$R22_RO"`},
			{"declare -r then assign", `declare -r R22_RO=1; eval 'R22_RO=/after'; echo "$R22_RO"`},
		} {
			got := lastOperand(t, tc.script)
			if got == "/after" {
				t.Fatalf("%s: binding query = %q — the runtime can never establish this value (readonly/special variable), so no exact /after bind may stand; the replication must treat the write as pollution/unknown", tc.name, got)
			}
		}
		// Positive control: the declaration's OWN inline write succeeds at
		// runtime, so it keeps its exact bind — the exclusion applies only
		// to writes AFTER the attribute took effect.
		kept := lastOperand(t, `readonly R22_RO=/kept; echo "$R22_RO"`)
		if kept != "/kept" {
			t.Fatalf("control broken: readonly R22_RO=/kept binding query = %q, want /kept — the declaration's own inline write succeeds exactly like a plain assignment", kept)
		}
	})

	// ---- R22-M1b: a same-named shell function shadows the eval builtin ----
	t.Run("R22-M1 shell function shadowing refuses the exact eval binding", func(t *testing.T) {
		shadowed := lastOperand(t, `eval() { :; }; eval 'R22_V=/after'; echo "$R22_V"`)
		if shadowed == "/after" {
			t.Fatalf("eval() { :; }; eval binding query = %q — shell name resolution picks the FUNCTION before the builtin, so eval never re-parses the operand in the same shell and no exact /after bind may stand", shadowed)
		}
		shadowedWrapper := lastOperand(t, `command() { :; }; command eval 'R22_V=/after'; echo "$R22_V"`)
		if shadowedWrapper == "/after" {
			t.Fatalf("command() { :; }; command eval binding query = %q — the shadowed first word IS the function, so the chain never reaches any builtin", shadowedWrapper)
		}
		// Positive controls: an unshadowed `command` prefix bypasses the
		// function lookup for eval, and a definition AFTER the call cannot
		// shadow a call that already ran.
		viaCommand := lastOperand(t, `eval() { :; }; command eval 'R22_V=/after'; echo "$R22_V"`)
		if viaCommand != "/after" {
			t.Fatalf("control broken: command eval under an eval-shadowing function = %q, want /after — the real command builtin bypasses function lookup exactly like POSIX specifies", viaCommand)
		}
		definedLater := lastOperand(t, `eval 'R22_V=/after'; eval() { :; }; echo "$R22_V"`)
		if definedLater != "/after" {
			t.Fatalf("control broken: eval before its shadowing definition = %q, want /after — the invocation ran when no function existed, so the builtin binding is sound", definedLater)
		}
	})

	// ---- R22-M2: tainted eval chains never lose the counted writes ----
	t.Run("R22-M2 an unknown-option eval chain revokes the single-write PATH proof", func(t *testing.T) {
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/bin:/bin")
		script := `command -x eval 'PATH=/usr/local/sbin'; echo "$(mktemp -d)"`
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(script), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		writes, _ := preScanVarMutations(f, false)
		if writes["PATH"] != 1 {
			t.Fatalf("pre-scan PATH write count = %d, want 1 — the scanner counts the operand write of the tainted chain exactly like any static eval (this assertion pins the scanner half of the invariant)", writes["PATH"])
		}
		enc := lastOperand(t, script)
		if strings.Contains(enc, "__ctx_abspath_dq__") {
			t.Fatalf("command -x eval 'PATH=...' substitution encoding %q carries the abs-dq class — the counted write must land as pollution (tainting PATH), never vanish between the eval replication and the statement write scan", enc)
		}
	})
	t.Run("R22-M2 a function-shadowed eval revokes the single-write PATH proof", func(t *testing.T) {
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/bin:/bin")
		// PATH=/usr/bin is the discriminator: a wrongly-minted exact bind
		// resolves mktemp (it exists there), so the abs-dq grant appears
		// iff the replication ignored the shadowing; the correct taint
		// verdict revokes the proof either way.
		script := `eval() { :; }; eval 'PATH=/usr/bin'; echo "$(mktemp -d)"`
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(script), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		writes, _ := preScanVarMutations(f, false)
		if writes["PATH"] != 1 {
			t.Fatalf("pre-scan PATH write count = %d, want 1 — the scanner counts the shadowed invocation's operand writes", writes["PATH"])
		}
		enc := lastOperand(t, script)
		if strings.Contains(enc, "__ctx_abspath_dq__") {
			t.Fatalf("shadowed eval 'PATH=...' substitution encoding %q carries the abs-dq class — the counted write must land as pollution, never silently skipped because no binding was minted", enc)
		}
	})

	// ---- R22-M3: elif conditions are conditional; self-referencing
	// overwrites preserve uncertainty; AST real assignments only ----
	t.Run("R22-M3 an elif condition write never lands as an exact override", func(t *testing.T) {
		const pathA = "/usr/bin:/bin"
		const pathB = "/usr/local/sbin"
		probe := func(script string) (string, bool) {
			envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect(script, false, envAssignments{}, pathA, callerIdentity{})
			if !ok || len(envs) == 0 {
				return "", false
			}
			return envs[len(envs)-1].effectivePATHFrom(pathA), true
		}
		uncond, uncondOK := probe("PATH=" + pathB + "; /bin/bash")
		if !uncondOK || uncond != pathB {
			t.Fatalf("control broken: unconditional PATH=B; /bin/bash = (%q, %v), want (%q, true)", uncond, uncondOK, pathB)
		}
		// `x=1` always succeeds, so the elif condition NEVER executes at
		// runtime — its PATH=B write is conditional across the merge.
		// Refusing the rewrite is the licensed conservative outcome; an
		// exact B is unsound in both directions. (The branch bodies are
		// pure assignments as well — a real command head in the branch
		// would be a data consumer and refuse the rewrite for an
		// unrelated reason, vacating the discrimination.)
		got, ok := probe("if x=1; then y=1; elif PATH=" + pathB + "; then z=1; fi; /bin/bash")
		if ok && got == pathB {
			t.Fatalf("elif-condition consumer effective PATH = %q under a GRANTED rewrite — the elif condition runs only when the first branch missed, so its write is conditional: never an exact override", got)
		}
	})
	t.Run("R22-M3 a self-referencing overwrite preserves the conditional uncertainty", func(t *testing.T) {
		const pathA = "/usr/bin:/bin"
		const pathB = "/usr/local/sbin"
		probe := func(script string) (string, bool) {
			envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect(script, false, envAssignments{}, pathA, callerIdentity{})
			if !ok || len(envs) == 0 {
				return "", false
			}
			return envs[len(envs)-1].effectivePATHFrom(pathA), true
		}
		// The conditional write may not execute; the UNCONDITIONAL
		// self-referencing overwrite depends on the old value, so the
		// merged PATH stays unknowable — the rewrite must be refused (or
		// the consumer keep an uncertain view), never exact. (`x=1` is
		// the always-true guard assignment: a real command head there
		// would be a data consumer and refuse the rewrite for an
		// unrelated reason.)
		got, ok := probe("x=1 && PATH=" + pathB + "; PATH=$PATH:/suffix; /bin/bash")
		if ok {
			if got == pathB+"/suffix" || got == pathB || got == pathA+"/suffix" {
				t.Fatalf("self-referencing overwrite consumer PATH = %q under a GRANTED rewrite — the new value depends on the unknowable old value, so every exact spelling is unsound; the uncertainty must survive", got)
			}
			if !strings.Contains(got, "__ctx_cmdsub__") {
				t.Fatalf("self-referencing overwrite consumer PATH = %q — the untrusted placeholder verdict is the only licensed exact answer here; a derivation from either candidate value is unsound", got)
			}
		}
		// Positive control: a completely INDEPENDENT constant overwrite
		// re-establishes the exact value — the taint clears.
		// R23-Reviewer-#2 / R23-Oracle-M3: the control must assert the
		// SUCCESS and the EXACT value, not merely tolerate a vacuous pass
		// — a probe that never grants the rewrite proves nothing about
		// the overwrite's independence.
		indep, indepOK := probe("x=1 && PATH=" + pathB + "; PATH=/usr/bin:/bin; /bin/bash")
		if !indepOK {
			t.Fatalf("control broken: independent constant overwrite rewrite REFUSED — a constant overwrite does not depend on the old value and must re-establish the exact PATH")
		}
		if indep != "/usr/bin:/bin" {
			t.Fatalf("control broken: independent constant overwrite PATH = %q, want exactly /usr/bin:/bin — a constant overwrite does not depend on the old value", indep)
		}
	})
	t.Run("R22-M3 a quoted command word spelling KEY=VAL is never folded as an assignment", func(t *testing.T) {
		// AST real-assignment verdict: `"X22Q=1"` is a COMMAND word (an
		// unknown/bogus head the shell resolves as a program invocation),
		// not an assignment of the running shell — folding it into the
		// scope environment model hands later consumers a variable the
		// shell never installs. The discrimination rides the production
		// fold/view pair directly so the file compiles on both trees.
		segs, ok := parseSubagentShellASTEnv(`"X22Q=1"`, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) != 1 {
			t.Fatalf("parse failed: ok=%v segs=%v", ok, segs)
		}
		tracker := &scopeEnvTracker{}
		tracker.foldSegment(segs[0], callerIdentity{})
		for _, op := range tracker.view("").ops {
			if op.key == "X22Q" {
				t.Fatalf("quoted KEY=VAL command word folded op %v into the environment model — the AST assignment verdict must distinguish a bare assignment statement from a command word that merely SPELLS KEY=VAL after quote stripping", op)
			}
		}
		// Positive control: the genuine bare assignment statement folds
		// exactly like before.
		segs2, ok2 := parseSubagentShellASTEnv(`X22Q=1`, 0, false, true, nil, callerIdentity{})
		if !ok2 || len(segs2) != 1 {
			t.Fatalf("parse failed: ok=%v segs=%v", ok2, segs2)
		}
		tracker2 := &scopeEnvTracker{}
		tracker2.foldSegment(segs2[0], callerIdentity{})
		found := false
		for _, op := range tracker2.view("").ops {
			if op.key == "X22Q" && op.value == "1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("control broken: bare X22Q=1 assignment did not fold into the environment model — the real-assignment propagation regressed")
		}
	})

	// ---- R22-M5: every unprojectable exit propagates the exhaustion state ----
	t.Run("R22-M5 wrapper-peel exhaustion marks the target exhausted end to end", func(t *testing.T) {
		// peelWrapperMaxSteps+ nested env wrappers exhaust the wrapper-peel
		// budget: the consumer is UNIDENTIFIED, so the target must carry
		// the exhaustion verdict exactly like the recursion-depth cutoff.
		argv := []string{"cat"}
		for i := 0; i < peelWrapperMaxSteps+4; i++ {
			argv = append([]string{"env"}, argv...)
		}
		targets := stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		hasExhausted := false
		for _, tg := range targets {
			if tg.exhausted {
				hasExhausted = true
			}
		}
		if !hasExhausted {
			t.Fatalf("stdinProgramTargetsDialect(peel-exhausted argv) = %v targets with NO exhaustion marker — a wrapper-peel budget cutoff must propagate exactly like the recursion-depth exhaustion, never pose as a zero-value POSIX shell", targets)
		}
		// The exhaustion verdict must block at the final consumption point:
		// the narrow rewrite projection refuses it exactly like the
		// recursion-depth boundary.
		if envs, ok, _ := stdinSingleShellTargetDialect(targets, false); ok || len(envs) > 0 {
			t.Fatalf("stdinSingleShellTargetDialect(peel-exhausted target) = (envs=%d, ok=%v) — an unidentified consumer can never be rewritten as a known local shell", len(envs), ok)
		}
	})
	t.Run("R22-M5 a nested parse failure marks the target exhausted", func(t *testing.T) {
		targets := stdinProgramTargetsDialect([]string{"bash", "-c", "if x; then"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		hasExhausted := false
		for _, tg := range targets {
			if tg.exhausted {
				hasExhausted = true
			}
		}
		if !hasExhausted {
			t.Fatalf("stdinProgramTargetsDialect(bash -c parse-err script) = %v targets with NO exhaustion marker — an unparsable nested script's consumer is unidentified, never a confirmed POSIX shell", targets)
		}
	})
	t.Run("R22-M5 the xargs inner wrapper exhaustion marks the target exhausted", func(t *testing.T) {
		inner := []string{"sh", "-c"}
		for i := 0; i < peelWrapperMaxSteps+4; i++ {
			inner = append([]string{"env"}, inner...)
		}
		argv := append([]string{"xargs"}, inner...)
		targets := stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		hasExhausted := false
		for _, tg := range targets {
			if tg.exhausted {
				hasExhausted = true
			}
		}
		if !hasExhausted {
			t.Fatalf("stdinProgramTargetsDialect(xargs peel-exhausted inner target) = %v targets with NO exhaustion marker — the xargs inner peel budget is an exhaustion verdict exactly like the recursion cutoff", targets)
		}
	})
	t.Run("R22-M5 the remote pure-shell exemption never certifies an exhausted vehicle", func(t *testing.T) {
		// An exhaustion-carrying vehicle must stay INELIGIBLE for the
		// exemption (lang == "" on an exhausted target is the zero value
		// of unknowable, not POSIX sh), while the plain `sh` vehicle
		// control keeps its eligibility exactly like before.
		if isPureRemoteStdinVehicleCwd("sh", "/tmp") != true {
			t.Fatalf("control broken: isPureRemoteStdinVehicleCwd(sh) = false — the plain remote shell vehicle keeps its exemption eligibility")
		}
		long := "cat"
		for i := 0; i < peelWrapperMaxSteps+4; i++ {
			long = "env " + long
		}
		if isPureRemoteStdinVehicleCwd(long, "/tmp") {
			t.Fatalf("isPureRemoteStdinVehicleCwd(wrapper-exhausted vehicle) = true — the narrow projection re-read the exhausted zero-value lang as a confirmed POSIX shell and certified an UNIDENTIFIED remote consumer")
		}
	})

	// ---- R22-M6: untrusted PATH blocks identity-dependent resolution ----
	t.Run("R22-M6 a bare unknown name under an untrusted PATH is an explicit unknown target", func(t *testing.T) {
		var runEnv envAssignments
		runEnv.ops = append(runEnv.ops, envOp{kind: 't', key: "PATH"})
		targets := stdinProgramTargetsDialect([]string{"qzxunknownr22probe"}, 0, runEnv, "/usr/bin:/bin", callerIdentity{}, false)
		if len(targets) == 0 {
			t.Fatalf("stdinProgramTargetsDialect(bare name, untrusted PATH) = nil — the empty list rides the data-consumer fallback and lets the caller skip the stream as if a proven data consumer existed; an unknowable consumer must surface as an explicit unknown/exhausted target")
		}
		hasExhausted := false
		for _, tg := range targets {
			if tg.exhausted {
				hasExhausted = true
			}
		}
		if !hasExhausted {
			t.Fatalf("untrusted-PATH bare name targets = %v with NO exhaustion marker — the consumer identity depends on PATH resolution the untrusted PATH cannot answer", targets)
		}
		// Controls: the same bare name under a TRUSTED PATH keeps the
		// data-consumer nil fallback, and a path-spelled name never
		// depends on PATH at all.
		trusted := stdinProgramTargetsDialect([]string{"qzxunknownr22probe"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		if len(trusted) != 0 {
			t.Fatalf("control broken: trusted-PATH bare unknown name = %v targets, want nil data fallback — the untrusted interception must not fire on a resolvable PATH", trusted)
		}
		pathNamed := stdinProgramTargetsDialect([]string{"./qzxunknownr22probe"}, 0, runEnv, "/usr/bin:/bin", callerIdentity{}, false)
		if len(pathNamed) != 0 {
			t.Fatalf("control broken: path-spelled name under untrusted PATH = %v targets, want nil data fallback — a '/'-carrying head never depends on PATH resolution", pathNamed)
		}
	})

	// ---- R22-1: the xargs memo/budget is per-request, keyed by context ----
	t.Run("R22-1 parallel xargs analyses stay isolated and match their serial verdicts", func(t *testing.T) {
		// Two resolution contexts over the SAME argv shape: with tmpA on
		// PATH, myhc resolves to a symlink whose target basename is hc —
		// the xargs analysis fails closed (true); without it the bare
		// name resolves nothing and the append-mode analysis reports the
		// feed closed (false). The serial verdicts are computed first and
		// the parallel runs must match them exactly — a shared process
		// memo cross-contaminates the two contexts whenever the
		// computations overlap, and a shared budget lets one request's
		// entries rewrite the other request's table.
		tmpA := t.TempDir()
		realDir := t.TempDir()
		hcBin := realDir + string(os.PathSeparator) + "hc"
		if err := os.WriteFile(hcBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write hc stub: %v", err)
		}
		if err := os.Symlink(hcBin, tmpA+string(os.PathSeparator)+"myhc"); err != nil {
			t.Fatalf("symlink myhc: %v", err)
		}
		// inner is the xargs TARGET argv exactly like the production call
		// (xargsFeedsCodeFlag(head[k:], head, …)): one nested xargs layer
		// so the hc resolution verdict lands at depth 1, where a resolved
		// nested hc/herdr-core head fails closed.
		inner := []string{"xargs", "myhc"}
		// A long chain of nonexistent directories slows the per-context
		// resolution so overlapping computations interleave instead of
		// serializing — the contamination window the audit describes is
		// inside the computation, not at the lock.
		filler := strings.Repeat("/nonexistent-r22-x1:/nonexistent-r22-x2:/nonexistent-r22-x3:", 40)
		pathTrue := tmpA + ":" + filler + "/usr/bin:/bin"
		pathFalse := filler + "/usr/bin:/bin"
		serialTrue := xargsFeedsCodeFlag(inner, []string{"xargs"}, pathTrue, callerIdentity{})
		serialFalse := xargsFeedsCodeFlag(inner, []string{"xargs"}, pathFalse, callerIdentity{})
		if !serialTrue {
			t.Fatalf("control broken: serial verdict under tmpA PATH = false, want true — the hc-resolving xargs target analysis itself regressed (check depth/budget setup)")
		}
		if serialFalse {
			t.Fatalf("control broken: serial verdict without tmpA on PATH = true, want false — the unresolvable bare name must not report an open code feed")
		}
		const iterations = 300
		for round := 0; round < iterations; round++ {
			start := make(chan struct{})
			type res struct{ v bool }
			chA, chB := make(chan res, 1), make(chan res, 1)
			go func() {
				<-start
				chA <- res{xargsFeedsCodeFlag(inner, []string{"xargs"}, pathTrue, callerIdentity{})}
			}()
			go func() {
				<-start
				chB <- res{xargsFeedsCodeFlag(inner, []string{"xargs"}, pathFalse, callerIdentity{})}
			}()
			close(start)
			ra, rb := <-chA, <-chB
			if ra.v != serialTrue || rb.v != serialFalse {
				t.Fatalf("round %d: parallel verdicts (%v, %v) != serial (%v, %v) — the two requests contaminated each other's memo or budget: a concurrent depth-0 entry reset the shared table underneath an in-flight computation, and the context-free memo key then served the WRONG resolution context's verdict", round, ra.v, rb.v, serialTrue, serialFalse)
			}
		}
	})

	// ---- R22-SF2: pure-assignment runs materialize no environment snapshots ----
	t.Run("R22-SF2 the production subagent traversal copies zero snapshots for pure-assignment runs", func(t *testing.T) {
		// Measure the production loop itself (guardShellSubagentDepthSegs):
		// n consecutive pure-assignment segments fold their ops and copy
		// NOTHING — the pre-R22 loop materialized a full prefix copy per
		// segment (1+..+n ops) whether or not any stdin consumer existed.
		// The byte thresholds sit between the two implementations'
		// measured allocations (quadratic vs constant); doubling the
		// assignment count must not multiply the view materialization
		// cost either.
		mkSegs := func(n int) []shellSegment {
			var sb strings.Builder
			for i := 0; i < n; i++ {
				sb.WriteString("R22X")
				sb.WriteByte(byte('a' + i%26))
				sb.WriteByte(byte('a' + i/26))
				sb.WriteString("=1; ")
			}
			return splitShellSegments(sb.String())
		}
		// The discriminating invariant is the marginal BYTE cost of a
		// fixed-width window of pure-assignment segments as the prefix
		// grows: a per-segment view materialization copies the accumulated
		// prefix, so segments 57-64 copy a 56-op prefix and cost strictly
		// more bytes than segments 1-8 copying up to 7 ops (measured on
		// the pre-fix tree: 6672 vs 25424 bytes, ratio ≈ 3.8), while a
		// zero-copy fold pays only the amortized-constant ops append and
		// both windows stay flat (measured: 5216 vs 4320, ratio ≈ 0.83).
		// Allocation COUNT cannot discriminate — the copy is one backing
		// array per segment regardless of its size; slice-growth noise is
		// why small windows are avoided.
		measure := func(n int) uint64 {
			segs := mkSegs(n)
			if len(segs) != n {
				t.Fatalf("fixture broken: %d segments for %d assignments", len(segs), n)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			if hit := guardShellSubagentDepthSegs(segs, 0, callerIdentity{}); hit != "" {
				t.Fatalf("control broken: pure-assignment run hit %q — inert assignments must screen clean", hit)
			}
			runtime.ReadMemStats(&after)
			return after.TotalAlloc - before.TotalAlloc
		}
		b8, b56, b64 := measure(8), measure(56), measure(64)
		early := b8       // segments 1-8
		late := b64 - b56 // segments 57-64
		if early == 0 {
			t.Fatalf("fixture broken: zero marginal bytes for segments 1-8 (b8=%d)", b8)
		}
		if late > early*3/2 {
			t.Fatalf("marginal allocation of a fixed-width pure-assignment window GROWS with the prefix length: %d bytes for segments 1-8 vs %d for segments 57-64 (ratio %.2f, want ≤ 1.5) — the production traversal still materializes one prefix-snapshot copy per segment even with no stdin consumer (quadratic copy cascade), instead of folding ops only", early, late, float64(late)/float64(early))
		}
	})
}

// TestGuard_V622_OracleR23Probes pins the Oracle R23 / Reviewer R23
// closure — one discriminating subtest per intersecting finding:
//
//	R23-1: one guardCall shares ONE xargs memo/budget table across every
//	  callerIdentity lookup of the request, while a second guardCall owns
//	  an independent full budget (Reviewer #1 / Oracle M5-xargs).
//	R23-2: the assignment operator provenance survives serialization — a
//	  `+=` append or array-subscript overwrite of a conditionally tainted
//	  tracked variable never launders the uncertainty into the serialized
//	  KEY=VAL constant, and the independent plain `=` overwrite still
//	  re-establishes the exact value (Reviewer #2 / Oracle M3).
//	R23-3: function definitions inside same-process compound blocks of a
//	  static eval text register into the process shadowing track, child-
//	  process definitions never leak into the parent, and PIPESTATUS/`_`
//	  can never hold an assigned value across the next command
//	  (Reviewer #3 / Oracle M1).
//	R23-4: the bind root-eval truncation drops no operand-evaluation AST
//	  write — `${X=v}` inside an eval operand word taints exactly the
//	  counted write — and a nested tainted chain without a confirmable
//	  operand boundary faces the uniform maximal pollution verdict
//	  (Reviewer #4 / Oracle M2).
//	R23-5: the remote pure-shell exemption consults EVERY non-data
//	  projection target, and the xargs work-budget cutoff is an explicit
//	  exhaustion verdict distinct from a confirmed code-slot hit
//	  (Reviewer #5 / Oracle M5).
//	R23-6: a bare PATH-dependent command head — including the dialect-
//	  ambiguous bare `sh` — is unknowable under an untrusted PATH before
//	  any static spelling or lookup result is adopted, and both prepare
//	  entries share the stdinRewriteableTarget refusal (Reviewer #6 /
//	  Oracle #6).
//	R23-7: the nested collectOneStdinSeg loop skips pure-assignment
//	  segments BEFORE any view materialization exactly like the flat
//	  scan (Reviewer #7 / Oracle SF2).
//
// Every discriminating row is FAIL-first on the pre-fix tree b9d481e:
// the probes reference only symbols that already exist there (the
// collectors, the projection helpers, xargsWorkState/xargsWorkBudget)
// so the file compiles verbatim on the parent tree and the failures
// reproduce the audit findings directly.
func TestGuard_V622_OracleR23Probes(t *testing.T) {
	// lastOperand encodes the last segment's second argv word of a script —
	// the substitution/binding result the replication state decides.
	lastOperand := func(t *testing.T, script string) string {
		t.Helper()
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
		}
		last := segs[len(segs)-1]
		if len(last.argv) < 2 {
			t.Fatalf("parse %q: last seg argv=%v, want at least 2 words", script, last.argv)
		}
		return last.argv[1]
	}

	// ---- R23-1: one request, one xargs budget table ----
	t.Run("R23-1 a single guardCall shares one xargs budget across every stage identity", func(t *testing.T) {
		// The production request mints its guardCall once per tool call;
		// the head screening, prepare projection and fallback stages all
		// derive their callerIdentity from it. Exhausting the first
		// stage's table must be visible in the second stage's identity —
		// the 512-node ceiling denominates the REQUEST, not one stage.
		g := currentGuardCall()
		c1 := g.callerIdentity()
		c2 := g.callerIdentity()
		if c1.xw == nil || c2.xw == nil {
			t.Fatalf("guardCall identities carry no xargs work state (c1.xw nil=%v, c2.xw nil=%v) — the per-request table must ride every stage identity", c1.xw == nil, c2.xw == nil)
		}
		if c1.xw != c2.xw {
			t.Fatalf("two callerIdentity lookups of the SAME guardCall carry distinct xargs tables (%p vs %p) — the budget denominator is a stage, not the request", c1.xw, c2.xw)
		}
		c1.xw.mu.Lock()
		c1.xw.steps = xargsWorkBudget
		c1.xw.mu.Unlock()
		c2.xw.mu.Lock()
		steps2 := c2.xw.steps
		c2.xw.mu.Unlock()
		if steps2 != xargsWorkBudget {
			t.Fatalf("exhausted first-stage budget invisible in second-stage identity (steps=%d, want %d) — the request ceiling is per stage", steps2, xargsWorkBudget)
		}
		// A second request owns an independent full budget.
		g2 := currentGuardCall()
		c3 := g2.callerIdentity()
		if c3.xw == c1.xw {
			t.Fatalf("two distinct guardCalls share one xargs table — cross-request isolation regressed")
		}
		c3.xw.mu.Lock()
		steps3 := c3.xw.steps
		c3.xw.mu.Unlock()
		if steps3 != 0 {
			t.Fatalf("independent request's budget starts at %d, want 0 — the other request's exhaustion must never cross the boundary", steps3)
		}
	})

	// foldViewOps parses one bash script, folds its segments into a fresh
	// tracker in statement order and returns the root scope view — the
	// direct fold/view pair of the environment model (the prepare-level
	// probe cannot discriminate these rows: the POSIX secondary tree
	// parses `PATH+=x`/`PATH[1]=x` as plain command words and refuses the
	// rewrite for an unrelated reason on BOTH trees).
	foldViewOps := func(t *testing.T, scripts ...string) []envOp {
		t.Helper()
		tracker := &scopeEnvTracker{}
		for _, script := range scripts {
			segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
			if !ok || len(segs) == 0 {
				t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
			}
			for _, seg := range segs {
				tracker.foldSegment(seg, callerIdentity{})
			}
		}
		return tracker.view("").ops
	}

	// ---- R23-2: append/subscript writes never launder conditional uncertainty ----
	t.Run("R23-2 a += append overwrite of a tainted PATH never mints the suffix-only exact value", func(t *testing.T) {
		// The conditional write may or may not execute, so PATH is
		// uncertain; bash's append operator concatenates onto that
		// unknowable OLD value — the serialized KEY=VAL suffix must never
		// clear the uncertainty marker.
		ops := foldViewOps(t, "x=1 && PATH=/usr/local/sbin", "PATH+=/suffix")
		hasTaint, hasSuffixOverride := false, false
		for _, op := range ops {
			if op.kind == 't' && op.key == "PATH" {
				hasTaint = true
			}
			if op.kind == 'a' && op.key == "PATH" && op.value == "/suffix" {
				hasSuffixOverride = true
			}
		}
		if hasSuffixOverride && !hasTaint {
			t.Fatalf("conditional-write then PATH+=/suffix view = %v — the append concatenates onto the unknowable old value, so the serialized suffix-only constant cannot stand without the uncertainty marker", ops)
		}
		if !hasTaint {
			t.Fatalf("conditional-write then PATH+=/suffix view = %v carries NO PATH uncertainty — the conditional write's taint must survive the append", ops)
		}
		// Positive control: a plain `=` INDEPENDENT constant overwrite
		// clears the uncertainty and re-establishes the exact value —
		// the operator distinction must not degrade the plain spelling.
		indep := foldViewOps(t, "x=1 && PATH=/usr/local/sbin", "PATH=/usr/bin:/bin")
		exact, tainted := false, false
		for _, op := range indep {
			if op.kind == 't' && op.key == "PATH" {
				tainted = true
			}
			if op.kind == 'a' && op.key == "PATH" && op.value == "/usr/bin:/bin" {
				exact = true
			}
		}
		if !exact || tainted {
			t.Fatalf("control broken: independent plain constant overwrite view = %v — want the exact /usr/bin:/bin op with NO surviving taint", indep)
		}
	})
	t.Run("R23-2 an array-subscript overwrite never mints the scalar exact value", func(t *testing.T) {
		// PATH[1]=/x writes ONE array element — element 0 (the scalar
		// expansion) keeps its inherited value, so the write can never
		// clear the conditional uncertainty with the serialized constant.
		ops := foldViewOps(t, "x=1 && PATH=/usr/local/sbin", "PATH[1]=/x")
		hasTaint, hasExactX := false, false
		for _, op := range ops {
			if op.kind == 't' && op.key == "PATH" {
				hasTaint = true
			}
			if op.kind == 'a' && op.key == "PATH" && op.value == "/x" {
				hasExactX = true
			}
		}
		if hasExactX && !hasTaint {
			t.Fatalf("conditional-write then PATH[1]=/x view = %v — the subscript write never overwrites the scalar, so the serialized /x constant cannot stand without the uncertainty marker", ops)
		}
		if hasExactX && hasTaint {
			t.Fatalf("conditional-write then PATH[1]=/x view = %v — even shadowed by the taint, minting the exact /x op pretends a scalar overwrite that never happens; the subscript write must not serialize as a plain override at all", ops)
		}
	})

	// ---- R23-3: scope-aware shadowing registration + volatile variables ----
	t.Run("R23-3 a function definition inside a brace block of a static eval shadows later eval", func(t *testing.T) {
		// Top-level control: the direct definition shadows exactly like
		// the R22 premise.
		top := lastOperand(t, `eval() { :; }; eval 'R23_V=/after'; echo "$R23_V"`)
		if top == "/after" {
			t.Fatalf("control broken: top-level shadowed eval binding query = %q — the direct shadowing registration itself regressed", top)
		}
		// The same definition inside a brace block of the eval TEXT is a
		// same-process definition: eval re-parses `{ eval() { :; }; }` in
		// the running shell, so the second eval resolves to the function
		// and the exact binding is impossible.
		brace := lastOperand(t, `eval '{ eval() { :; }; }'; eval 'R23_V=/after'; echo "$R23_V"`)
		if brace == "/after" {
			t.Fatalf("brace-block eval-shadowing binding query = %q — the definition inside the same-process compound block never registered, so the replication minted a builtin binding the shadowed runtime can never perform", brace)
		}
		// Positive control: without the inner definition the replication
		// binds exactly like before.
		plain := lastOperand(t, `eval '{ :; }'; eval 'R23_V=/after'; echo "$R23_V"`)
		if plain != "/after" {
			t.Fatalf("control broken: unshadowed brace-block eval binding query = %q, want /after", plain)
		}
	})
	t.Run("R23-3 a subshell function definition never shadows the parent shell", func(t *testing.T) {
		// ( eval() { :; } ) dies with the subshell — the parent's later
		// bare eval still resolves to the real builtin, so the exact
		// binding is sound. A leaking child-process registration would
		// taint it instead.
		got := lastOperand(t, `( eval() { :; } ); eval 'R23_V=/after'; echo "$R23_V"`)
		if got != "/after" {
			t.Fatalf("subshell-scoped shadowing binding query = %q, want /after — the child process's definition must die with it; the parent's positional track must restore at the boundary", got)
		}
		// A backgrounded definition dies with its child process exactly
		// like the subshell spelling. (A bare `eval() { :; } | cat` is no
		// fixture: bash parses the pipeline as the function's BODY, so the
		// definition itself genuinely takes effect in the parent shell.)
		bg := lastOperand(t, `{ eval() { :; }; } & eval 'R23_V=/after'; echo "$R23_V"`)
		if bg != "/after" {
			t.Fatalf("background-scoped shadowing binding query = %q, want /after — the backgrounded subtree is a child process exactly like the subshell", bg)
		}
	})
	t.Run("R23-3 PIPESTATUS never holds an assigned value across the next command", func(t *testing.T) {
		// bash rewrites PIPESTATUS after EVERY foreground pipeline — the
		// assigned /after is discarded by the intervening `:` long before
		// the echo expands the variable, so the exact bind is impossible.
		got := lastOperand(t, `eval "PIPESTATUS=/after"; :; echo "$PIPESTATUS"`)
		if got == "/after" {
			t.Fatalf("PIPESTATUS binding query = %q — the shell-maintained pipeline status array can never hold an assigned value across the next simple command", got)
		}
		underscore := lastOperand(t, `eval "_=/after"; :; echo "$_"`)
		if underscore == "/after" {
			t.Fatalf("underscore binding query = %q — the shell re-binds _ at every command start", underscore)
		}
	})

	// ---- R23-4: operand-evaluation writes survive the bind truncation ----
	t.Run("R23-4 an eval operand parameter-assignment expansion lands as pollution", func(t *testing.T) {
		// eval ${AUDIT_MARK=/val}: the outer script carries exactly ONE
		// AST write of the marker (the operand word's := expansion), the
		// pre-scan counts it, and the bind-truncated statement scan drops
		// the whole operand list — the replication must own the
		// operand-evaluation write explicitly.
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(`eval ${AUDIT_MARK=/val}`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(f.Stmts) != 1 {
			t.Fatalf("fixture broken: %d statements", len(f.Stmts))
		}
		writes, _ := preScanVarMutations(f, false)
		if writes["AUDIT_MARK"] != 1 {
			t.Fatalf("pre-scan AUDIT_MARK write count = %d, want 1 — the operand expansion write is exactly the counted shape (this assertion pins the scanner half of the invariant)", writes["AUDIT_MARK"])
		}
		call, isCall := f.Stmts[0].Cmd.(*syntax.CallExpr)
		if !isCall {
			t.Fatalf("fixture broken: root cmd is %T, want CallExpr", f.Stmts[0].Cmd)
		}
		c := blankSubCollector()
		c.allowBind = true
		c.bindEvalCallWrites(f.Stmts[0], call)
		if !c.taintedVars["AUDIT_MARK"] {
			t.Fatalf("bindEvalCallWrites left AUDIT_MARK untouched (taintedVars=%v staticVars=%v) — the counted write vanished between the truncated scan and the replication: neither bound nor polluted", c.taintedVars, c.staticVars)
		}
		if c.staticVars["AUDIT_MARK"] == "/val" {
			t.Fatalf("AUDIT_MARK minted the exact /val bind — a default-assign expansion is conditional at runtime, so pollution is the only sound verdict")
		}
	})

	// ---- R23-5: full-list remote certification + xargs budget distinction ----
	t.Run("R23-5 the remote exemption consults every non-data projection target", func(t *testing.T) {
		if !isPureRemoteStdinVehicleCwd("sh", "/tmp") {
			t.Fatalf("control broken: isPureRemoteStdinVehicleCwd(sh) = false — the plain remote shell vehicle keeps its exemption eligibility")
		}
		longSeg := "cat"
		for i := 0; i < peelWrapperMaxSteps+4; i++ {
			longSeg = "env " + longSeg
		}
		// One outer vehicle segment projects TWO non-data targets: the
		// positively identified inner shell AND the wrapper-exhausted
		// sibling. Certification keyed on the first target alone launder
		// the exhausted one — both orders must refuse.
		first := "bash -c 'sh; " + longSeg + "'"
		if isPureRemoteStdinVehicleCwd(first, "/tmp") {
			t.Fatalf("isPureRemoteStdinVehicleCwd(shell-first multi-target vehicle) = true — the first non-data target is a positively identified shell, but the exhausted sibling certifies nothing; the exemption must consult the ENTIRE projection")
		}
		second := "bash -c '" + longSeg + "; sh'"
		if isPureRemoteStdinVehicleCwd(second, "/tmp") {
			t.Fatalf("isPureRemoteStdinVehicleCwd(exhausted-first multi-target vehicle) = true — even the favourable order must never certify an unidentified consumer")
		}
	})
	t.Run("R23-5 an xargs budget cutoff is exhaustion, never a confirmed shell target", func(t *testing.T) {
		// Pre-install a fully spent budget on the caller: the analysis
		// fails closed (true) inside xargsFeedsCodeFlag, but a plain cat
		// inner target has no open code slot — the budget cutoff must
		// surface as an EXPLICIT exhaustion verdict, never the zero-value
		// lang:"" pseudo-POSIX-shell target the control produces.
		// R24-Reviewer-#5: the exhaustion verdict is explicit state, never a
		// post-hoc reading of the step counter — the fixture forces it
		// through the public denied-step path rather than naming state
		// fields, so setting only the step count models "the 512th step
		// completed normally", not an analysis cutoff.
		spent := &xargsWorkState{steps: xargsWorkBudget}
		_ = xargsFeedsCodeFlagDepth([]string{"cat"}, []string{"xargs"}, "/usr/bin:/bin", callerIdentity{xw: spent}, 0)
		caller := callerIdentity{xw: spent}
		targets := stdinProgramTargetsDialect([]string{"xargs", "cat"}, 0, envAssignments{}, "/usr/bin:/bin", caller, false)
		hasExhausted := false
		for _, tg := range targets {
			if tg.exhausted {
				hasExhausted = true
			}
		}
		if !hasExhausted {
			t.Fatalf("stdinProgramTargetsDialect(budget-exhausted xargs cat) = %v targets with NO exhaustion marker — the budget cutoff means the consumer identity is unknowable, never a confirmed data or shell verdict", targets)
		}
		// Control: a fresh budget over the same argv keeps the ordinary
		// non-exhausted projection — the budget state itself is the
		// discriminator.
		fresh := stdinProgramTargetsDialect([]string{"xargs", "cat"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{xw: &xargsWorkState{}}, false)
		for _, tg := range fresh {
			if tg.exhausted {
				t.Fatalf("control broken: fresh-budget xargs cat = %v carries an exhaustion marker — the ordinary data projection regressed", fresh)
			}
		}
	})

	// ---- R23-6: bare heads are unknowable under an untrusted PATH ----
	t.Run("R23-6 a bare sh under an untrusted PATH never certifies one dialect", func(t *testing.T) {
		var runEnv envAssignments
		runEnv.ops = append(runEnv.ops, envOp{kind: 't', key: "PATH"})
		targets := stdinProgramTargetsDialect([]string{"sh"}, 0, runEnv, "/usr/bin:/bin", callerIdentity{}, false)
		hasExhausted := false
		for _, tg := range targets {
			if tg.exhausted {
				hasExhausted = true
			}
			if !tg.exhausted && tg.lang == "" && !tg.bash {
				t.Fatalf("bare sh under untrusted PATH = %+v — the zero-value confirmed-POSIX verdict certifies a dialect nobody resolved: the same bare name can be dash, bash or an attacker-placed program", tg)
			}
		}
		if !hasExhausted {
			t.Fatalf("bare sh under untrusted PATH = %v targets with NO exhaustion marker — a PATH-dependent identity under an unanswerable PATH is unknowable", targets)
		}
		// Positive controls: the same bare head under a TRUSTED PATH
		// keeps its ordinary projection, and a fixed absolute spelling
		// never depends on PATH at all.
		trusted := stdinProgramTargetsDialect([]string{"sh"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		trustedProg := false
		for _, tg := range trusted {
			if !tg.data && !tg.exhausted {
				trustedProg = true
			}
			if tg.exhausted {
				t.Fatalf("control broken: trusted-PATH bare sh = %v carries exhaustion — the interception must not fire on a resolvable PATH", trusted)
			}
		}
		if !trustedProg {
			t.Fatalf("control broken: trusted-PATH bare sh yields no program target (%v) — the shell projection itself regressed", trusted)
		}
		abs := stdinProgramTargetsDialect([]string{"/bin/sh"}, 0, runEnv, "/usr/bin:/bin", callerIdentity{}, false)
		for _, tg := range abs {
			if tg.exhausted {
				t.Fatalf("control broken: absolute /bin/sh under untrusted PATH = %v carries exhaustion — a fixed absolute spelling never depends on PATH resolution", abs)
			}
		}
		// The joint rewrite refusal is the shared helper itself: an
		// env slice carrying the uncertainty marker is never rewrite-
		// eligible, while the same target list without it is.
		var badEnv, goodEnv envAssignments
		badEnv.ops = append(badEnv.ops, envOp{kind: 't', key: "PATH"})
		badTargets := []stdinTarget{{lang: "", envAs: badEnv}}
		if _, ok, _ := stdinRewriteableTarget(badTargets, false, "/usr/bin:/bin"); ok {
			t.Fatalf("stdinRewriteableTarget(uncertainty-marker target env) = ok — the joint refusal both prepare entries share regressed")
		}
		goodTargets := []stdinTarget{{lang: "", envAs: goodEnv}}
		if _, ok, _ := stdinRewriteableTarget(goodTargets, false, "/usr/bin:/bin"); !ok {
			t.Fatalf("control broken: stdinRewriteableTarget(clean target env) = refused — the ordinary rewrite eligibility regressed")
		}
	})

	// ---- R23-7: the nested loop skips pure assignments before any view ----
	t.Run("R23-7 the nested collectOneStdinSeg loop pays zero view copies for pure assignments", func(t *testing.T) {
		// Mirror of the R22-SF2 byte-window discrimination, but for the
		// NESTED collectSegs loop: the pre-fix condition guarded only the
		// empty-head peel, so every real nested assignment reached
		// tracker.view and copied the accumulated prefix (1+..+n ops).
		mkSegs := func(n int) []shellSegment {
			var sb strings.Builder
			for i := 0; i < n; i++ {
				sb.WriteString("R23X")
				sb.WriteByte(byte('a' + i%26))
				sb.WriteByte(byte('a' + i/26))
				sb.WriteString("=1; ")
			}
			return splitShellSegments(sb.String())
		}
		measure := func(n int) uint64 {
			segs := mkSegs(n)
			if len(segs) != n {
				t.Fatalf("fixture broken: %d segments for %d assignments", len(segs), n)
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			tracker := &scopeEnvTracker{}
			for _, seg := range segs {
				collectOneStdinSeg(tracker, seg, 0, envAssignments{}, envAssignments{}, "/usr/bin:/bin", false, callerIdentity{})
			}
			runtime.ReadMemStats(&after)
			return after.TotalAlloc - before.TotalAlloc
		}
		b8, b56, b64 := measure(8), measure(56), measure(64)
		early := b8       // segments 1-8
		late := b64 - b56 // segments 57-64
		if early == 0 {
			t.Fatalf("fixture broken: zero marginal bytes for segments 1-8 (b8=%d)", b8)
		}
		if late > early*3/2 {
			t.Fatalf("nested collectOneStdinSeg marginal allocation GROWS with the prefix length: %d bytes for segments 1-8 vs %d for segments 57-64 (ratio %.2f, want ≤ 1.5) — the nested loop still materializes one view copy per pure-assignment segment instead of skipping before the view", early, late, float64(late)/float64(early))
		}
	})
}

// TestGuard_V622_OracleR24Probes pins the Oracle R24 / Reviewer R24
// closure — one discriminating subtest per intersecting finding:
//
//	R24-1: the SSH remote projection threads the SAME request xargs
//	  memo/budget table end to end — an already-exhausted caller reports
//	  the remote xargs data consumer as program-shaped (fail closed),
//	  a fresh caller reports it as data, and the fresh projection's steps
//	  accumulate on the caller's own table (Reviewer #1 / Oracle M1).
//	R24-2: the main AST collector never mints a scalar static binding for
//	  an array-subscript or `+=` assignment, while a plain independent `=`
//	  keeps its exact binding (Reviewer #2 / Oracle M2).
//	R24-3: static eval replay shares the main traversal's process
//	  boundaries — background definitions die with the child, readonly
//	  declarations replay, pipeline components are mutually isolated —
//	  and child-process registry isolation is incremental instead of
//	  cloning the whole registry at every boundary (Reviewer #3 /
//	  Oracle M3 + S2).
//	R24-4: arithmetic writes inside eval operand expansion words are
//	  owned by the replication exactly like parameter-expansion default
//	  assignments, and a nested tainted chain with a short rest still
//	  reaches the maximal pollution boundary (Reviewer #4 / Oracle M4).
//	R24-5: xargs recursion-depth cutoff is explicit exhaustion distinct
//	  from both a confirmed hit and a normally completed 512th step; the
//	  remote projection folds environment writes across segments and
//	  keeps the consuming shell's dialect (Reviewer #5 / Oracle M5).
//	R24-6: bare external wrapper identities are validated before the
//	  peel adopts them, and a canon-normalized absolute interpreter
//	  keeps the original spelling's fixed-path identity (Reviewer #6 /
//	  Oracle M6).
//
// Every discriminating row is FAIL-first on the pre-fix tree f8cd003:
// the probes reference only symbols that already exist there (the
// collectors, remote projections, peel helpers and xargsWorkState), so
// the file compiles verbatim on the parent tree and the failures
// reproduce the audit findings directly. The only exception is the
// process-registry copy probe: f8cd003 has no incremental undo log to
// observe, so that row uses the same allocation-window discrimination
// style as R23-7 and compares marginal copy cost across registry sizes
// without naming any post-fix implementation detail.
func TestGuard_V622_OracleR24Probes(t *testing.T) {
	// lastOperand encodes the last segment's second argv word of a bash
	// script — the substitution/binding result the replication state
	// decides. It mirrors the R23 fixture exactly.
	lastOperand := func(t *testing.T, script string) string {
		t.Helper()
		segs, ok := parseSubagentShellASTEnv(script, 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) == 0 {
			t.Fatalf("parse %q failed: ok=%v segs=%v", script, ok, segs)
		}
		last := segs[len(segs)-1]
		if len(last.argv) < 2 {
			t.Fatalf("parse %q: last seg argv=%v, want at least 2 words", script, last.argv)
		}
		return last.argv[1]
	}

	// ---- R24-1: one xargs budget spans the SSH remote projection ----
	t.Run("R24-1 the SSH remote projection shares the caller's request xargs table", func(t *testing.T) {
		argv := []string{"ssh", "host", "xargs cat"}
		exhaustedState := &xargsWorkState{steps: xargsWorkBudget}
		// Force the sticky analysis-cutoff state through the public analysis
		// path rather than naming implementation fields: on f8cd003 the step
		// count itself is the cutoff state; after the explicit-verdict fix
		// this denied 513th-step request is what records exhaustion.
		_ = xargsFeedsCodeFlagDepth([]string{"cat"}, []string{"xargs"}, "/usr/bin:/bin", callerIdentity{xw: exhaustedState}, 0)
		if !sshTunnelsStdinProgram(argv, "/usr/bin:/bin", callerIdentity{xw: exhaustedState}) {
			t.Fatalf("sshTunnelsStdinProgram(ssh host xargs cat, exhausted caller) = false — the budget cutoff means the remote consumer identity is unknowable, so the projection must fail closed as program-shaped")
		}
		freshState := &xargsWorkState{}
		if sshTunnelsStdinProgram(argv, "/usr/bin:/bin", callerIdentity{xw: freshState}) {
			t.Fatalf("sshTunnelsStdinProgram(ssh host xargs cat, fresh caller) = true — a plain remote xargs cat is a data consumer, not a stdin program")
		}
		freshState.mu.Lock()
		steps := freshState.steps
		freshState.mu.Unlock()
		if steps == 0 {
			t.Fatalf("fresh SSH remote projection consumed ZERO xargs steps on the caller's table — the remote statements each minted a private budget through stdinEntryCaller instead of sharing the request's xargsWorkState")
		}
	})

	// ---- R24-2: no scalar bind for append/subscript assignment writes ----
	t.Run("R24-2 array-subscript and append assignments never mint scalar static bindings", func(t *testing.T) {
		// Feed one pure-assignment statement directly to the main collector's
		// emitCall: the discriminating state is staticVars itself, the same
		// table later scalar expansion reads. (The array-subscript spelling
		// intentionally never reaches the segment parser as a plain command
		// word — a full-script echo probe would test glob encoding instead.)
		emitAssign := func(src string) *subCollector {
			t.Helper()
			p := syntax.NewParser(syntax.Variant(syntax.LangBash))
			f, err := p.Parse(strings.NewReader(src), "")
			if err != nil || len(f.Stmts) != 1 {
				t.Fatalf("parse %q: err=%v stmts=%d", src, err, len(f.Stmts))
			}
			call, isCall := f.Stmts[0].Cmd.(*syntax.CallExpr)
			if !isCall {
				t.Fatalf("fixture broken: %q root cmd is %T, want CallExpr", src, f.Stmts[0].Cmd)
			}
			c := blankSubCollector()
			c.allowBind = true
			c.emitCall(f.Stmts[0], call, stdinFeed{})
			return c
		}
		if got := emitAssign(`ARR[1]=/marker`).staticVars["ARR"]; got == "/marker" {
			t.Fatalf("ARR[1]=/marker minted staticVars[ARR]=%q — a subscript write touches one array element and can never establish the scalar value later expansion reads", got)
		}
		if got := emitAssign(`VAR+=/marker`).staticVars["VAR"]; got == "/marker" {
			t.Fatalf("VAR+=/marker minted staticVars[VAR]=%q — bash concatenates the suffix onto the inherited value, so the literal suffix is never the exact scalar binding", got)
		}
		if got := emitAssign(`VAR=/marker`).staticVars["VAR"]; got != "/marker" {
			t.Fatalf("control broken: plain VAR=/marker staticVars[VAR]=%q, want /marker — the independent plain assignment must keep its exact binding", got)
		}
	})

	// ---- R24-3: shared process boundaries in eval replay and traversal ----
	t.Run("R24-3 backgrounded eval-text definitions never shadow the parent but foreground ones do", func(t *testing.T) {
		bg := lastOperand(t, `eval '{ eval() { :; }; } &'; eval 'R24_BG=/after'; echo "$R24_BG"`)
		if bg != "/after" {
			t.Fatalf("backgrounded eval-text shadowing binding query = %q, want /after — the backgrounded brace block runs in a child shell, so its definition must die with the child", bg)
		}
		fg := lastOperand(t, `eval '{ eval() { :; }; }'; eval 'R24_FG=/after'; echo "$R24_FG"`)
		if fg == "/after" {
			t.Fatalf("control broken: foreground eval-text shadowing binding query = %q — the same-process foreground definition must shadow the later bare eval", fg)
		}
	})
	t.Run("R24-3 eval replay records readonly declarations", func(t *testing.T) {
		c := blankSubCollector()
		c.allowBind = true
		c.bindEvalTextWrites("readonly R24_RO", 0)
		if !c.readonlyVars["R24_RO"] {
			t.Fatalf("static eval replay of readonly R24_RO left readonlyVars=%v — the main traversal records the attribute through emitDecl/emitCall, and the replication must share that process state", c.readonlyVars)
		}
		got := lastOperand(t, `eval 'readonly R24_ROV'; eval 'R24_ROV=/after'; echo "$R24_ROV"`)
		if got == "/after" {
			t.Fatalf("readonly eval binding query = %q — the frozen runtime variable can never receive the replicated write, so the exact bind is impossible", got)
		}
	})
	t.Run("R24-3 pipeline components derive independent registry boundaries", func(t *testing.T) {
		// The left pipe component defines eval in its own child process; the
		// right component then invokes a bare eval with no operand. Isolated
		// correctly, that right-side eval is the real builtin with an empty
		// re-parse — no pollution. If the left component's definition is
		// still visible while the right side is walked, the invocation is
		// function-shadowed, its operand boundary is unconfirmable, and the
		// maximal eval boundary taints PATH for every later proof.
		t.Setenv("TMPDIR", "/tmp")
		t.Setenv("PATH", "/usr/bin:/bin")
		script := `{ eval() { :; }; } | { eval; }; echo "$(mktemp -d)"`
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(script), "")
		if err != nil {
			t.Fatalf("parse pipeline fixture: %v", err)
		}
		c := blankSubCollector()
		c.allowBind = true
		zero := 0
		c.scopeCounter = &zero
		c.walkStmts(f.Stmts, stdinFeed{})
		if c.funcNames["eval"] {
			t.Fatalf("pipeline function definition leaked into the parent registry (funcNames=%v) — both components are child processes", c.funcNames)
		}
		if c.taintedVars["PATH"] {
			t.Fatalf("right-side bare eval was shadowed by the LEFT pipeline component's definition (tainted PATH=true) — the two components must derive independent registry boundaries from the same parent state")
		}
		if len(c.segs) == 0 || !strings.Contains(c.segs[len(c.segs)-1].argv[len(c.segs[len(c.segs)-1].argv)-1], "__ctx_abspath_dq__") {
			t.Fatalf("mktemp substitution after isolated pipeline encoded as %v — left-to-right registry leakage polluted PATH and revoked the resolution proof", c.segs)
		}
	})
	t.Run("R24-3 child-process registry isolation does not copy the whole registry", func(t *testing.T) {
		// Register n empty functions OUTSIDE the allocation window, then
		// measure one writeless child shell `(:)`. The pre-R24 snapshot
		// cloned both positional maps on entry, so the marginal cost grew
		// with the parent's registered population; the incremental undo
		// boundary pays constant cost when the child writes nothing.
		measure := func(n int) uint64 {
			p := syntax.NewParser(syntax.Variant(syntax.LangBash))
			f, err := p.Parse(strings.NewReader(`(:)`), "")
			if err != nil {
				t.Fatalf("parse subshell fixture: %v", err)
			}
			c := blankSubCollector()
			zero := 0
			c.scopeCounter = &zero
			for i := 0; i < n; i++ {
				c.noteFuncDef(&syntax.FuncDecl{Name: &syntax.Lit{Value: fmt.Sprintf("r24f%03d", i)}})
			}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			c.walkStmts(f.Stmts, stdinFeed{})
			runtime.ReadMemStats(&after)
			return after.TotalAlloc - before.TotalAlloc
		}
		small, large := measure(4), measure(64)
		if small == 0 {
			t.Fatalf("fixture broken: zero marginal allocation for the n=4 child shell")
		}
		if large > small*3/2 {
			t.Fatalf("writeless child-process boundary marginal allocation grows with the parent registry: %d bytes at n=4 vs %d at n=64 (ratio %.2f, want ≤ 1.5) — snapshotProcessRegs still copies the whole funcNames table on entry (f8cd003 copied n elements per child: 10 total for n=4 with four children, 36 for n=8)", small, large, float64(large)/float64(small))
		}
	})

	// ---- R24-4: eval operand arithmetic writes have an owner ----
	t.Run("R24-4 arithmetic writes inside an eval operand land as pollution", func(t *testing.T) {
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(`eval "$((AUDIT_MARK=1))"`), "")
		if err != nil {
			t.Fatalf("parse arithmetic operand fixture: %v", err)
		}
		writes, _ := preScanVarMutations(f, false)
		if writes["AUDIT_MARK"] != 1 {
			t.Fatalf("pre-scan AUDIT_MARK arithmetic write count = %d, want 1 — the operand arithmetic expansion is exactly the counted shape", writes["AUDIT_MARK"])
		}
		call, isCall := f.Stmts[0].Cmd.(*syntax.CallExpr)
		if !isCall {
			t.Fatalf("fixture broken: root cmd is %T, want CallExpr", f.Stmts[0].Cmd)
		}
		c := blankSubCollector()
		c.allowBind = true
		c.bindEvalCallWrites(f.Stmts[0], call)
		if !c.taintedVars["AUDIT_MARK"] {
			t.Fatalf("bindEvalCallWrites left AUDIT_MARK untouched (taintedVars=%v staticVars=%v) — the counted arithmetic write vanished between the truncated root scan and the operand replication", c.taintedVars, c.staticVars)
		}
		c.noteBuiltinWrites(f.Stmts[0], call)
		if !c.taintedVars["AUDIT_MARK"] {
			t.Fatalf("noteBuiltinWrites removed or never preserved AUDIT_MARK pollution (taintedVars=%v) — the counted write must survive the full bind/builtin replay", c.taintedVars)
		}
	})
	t.Run("R24-4 a nested tainted short-rest eval chain reaches the maximal pollution boundary", func(t *testing.T) {
		// `command -x eval` is an invocation error before eval can run:
		// the chain verdict is tainted, the visible operand boundary is
		// too short to carry text, and the replication must apply the
		// uniform sentinel/PATH pollution instead of silently dropping
		// the unconfirmable boundary.
		c := blankSubCollector()
		c.allowBind = true
		c.bindEvalTextWrites("command -x eval", 0)
		if !c.taintedVars["PATH"] {
			t.Fatalf("nested tainted short-rest chain left PATH untainted (taintedVars=%v) — taintShortRestBoundary must reach taintEvalBoundary for an unconfirmable eval operand boundary", c.taintedVars)
		}
		for _, name := range []string{"HOME", "PWD", "OLDPWD"} {
			if !c.taintedVars[name] {
				t.Fatalf("nested tainted short-rest chain left sentinel %s untainted (taintedVars=%v) — the maximal pollution boundary is incomplete", name, c.taintedVars)
			}
		}
	})

	// ---- R24-5: explicit cutoff kinds, remote env folding and dialect ----
	t.Run("R24-5 recursion-depth cutoff is exhaustion but a normal 512th step is not", func(t *testing.T) {
		argv := []string{"cat"}
		for i := 0; i < peelChainMaxDepth+2; i++ {
			argv = append([]string{"xargs"}, argv...)
		}
		fresh := &xargsWorkState{}
		targets := stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{xw: fresh}, false)
		hasExhausted := false
		for _, tg := range targets {
			if tg.exhausted {
				hasExhausted = true
			}
		}
		if !hasExhausted {
			t.Fatalf("deeply nested xargs projection = %v targets with NO exhaustion marker — the recursion-depth cutoff is an analysis cutoff exactly like the step ceiling, never a confirmed empty-language target", targets)
		}
		if !xargsBudgetSpent(fresh) {
			t.Fatalf("deeply nested xargs projection did not mark the caller's request table exhausted — the cutoff state must be sticky for every later stage of the same request")
		}
		first, _ := firstProgramTarget(targets)
		if stdinShellTargetRewriteable(first, false) {
			t.Fatalf("depth-cutoff xargs projection remained rewrite-eligible (%+v) — an unidentified consumer can never be rewritten as a certified shell program", first)
		}
		// Control: completing exactly the 512th permitted step is a normal
		// analysis result, not an analysis cutoff.
		ws := &xargsWorkState{steps: xargsWorkBudget - 1}
		stepTargets := stdinProgramTargetsDialect([]string{"xargs", "cat"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{xw: ws}, false)
		if ws.steps != xargsWorkBudget {
			t.Fatalf("fixture broken: xargs cat consumed %d steps from a %d-step table, want exactly %d", ws.steps, xargsWorkBudget-1, xargsWorkBudget)
		}
		if xargsBudgetSpent(ws) {
			t.Fatalf("the normally completed 512th xargs step marked the request table exhausted — step count is not the analysis-cutoff verdict")
		}
		for _, tg := range stepTargets {
			if tg.exhausted {
				t.Fatalf("the normally completed 512th xargs step produced an exhausted target (%+v) — a definite answer computed on the final permitted step must stand", tg)
			}
		}
	})
	t.Run("R24-5 the remote projection folds environment writes across segments", func(t *testing.T) {
		// The first remote segment conditionally writes PATH; the second
		// segment is a bare sh whose identity depends entirely on PATH
		// resolution. A per-segment empty-env projection misses the write;
		// the folded remote shell environment makes the consumer unknowable.
		// The legacy language-only API is deliberately the probe surface:
		// it exists on both trees, so this row compiles verbatim on
		// f8cd003 while the production screen consumes the richer target
		// projection underneath it.
		_, reads, exhausted := remoteStdinProgramLangsCwd("if x; then PATH=/evil; fi; sh", "/tmp")
		if !reads {
			t.Fatalf("remote conditional-PATH bare sh projection reads=false — the unknowable consumer must still fail closed as program-shaped")
		}
		if !exhausted {
			t.Fatalf("remote conditional-PATH bare sh projection exhausted=false — the first segment's conditional PATH write never reached the second segment's bare-shell resolution")
		}
	})
	t.Run("R24-5 the remote projection preserves the consuming shell dialect", func(t *testing.T) {
		// Both dialects project the same language ("") through the legacy
		// narrow view by design — it carries no dialect bits. The
		// discriminating surface is the consuming screen: a brace-word
		// heredoc body is a parse error under dash but valid bash text
		// under bash, so the remote bash body must face the bash dialect
		// rather than collapsing to the same POSIX re-review as sh.
		// The pre-R24 screenStdinProgram invocation hard-coded false and
		// made the two consumers indistinguishable.
		bashSeg := shellSegment{argv: []string{"ssh", "host", "bash"}, heredocText: []heredocBody{{text: "printf tag{red,blue}"}}}
		shSeg := shellSegment{argv: []string{"ssh", "host", "sh"}, heredocText: []heredocBody{{text: "printf tag{red,blue}"}}}
		bashHit := screenSSHHead([]string{"ssh", "host", "bash"}, bashSeg, 's', 0, callerIdentity{})
		shHit := screenSSHHead([]string{"ssh", "host", "sh"}, shSeg, 's', 0, callerIdentity{})
		if bashHit == shHit {
			t.Fatalf("remote bash and sh heredoc bodies received the same screening verdict %q — the projection collapsed both consuming shells to the dash POSIX default instead of preserving the bash dialect", bashHit)
		}
	})

	// ---- R24-6: validate wrapper identity before adoption; keep fixed paths fixed ----
	t.Run("R24-6 bare external wrappers are validated before the peel adopts them", func(t *testing.T) {
		var untrusted envAssignments
		untrusted.ops = append(untrusted.ops, envOp{kind: 't', key: "PATH"})
		assertExhaustion := func(argv []string, want bool) {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
			got := false
			for _, tg := range targets {
				if tg.exhausted {
					got = true
				}
			}
			if got != want {
				t.Fatalf("stdinProgramTargetsDialect(%v) exhaustion = %v, want %v (targets=%v) — a bare external wrapper owes its own resolution to the untrusted PATH even when the peeled inner command is absolute", argv, got, want, targets)
			}
		}
		assertExhaustion([]string{"env", "/bin/sh"}, true)
		assertExhaustion([]string{"nice", "/bin/sh"}, true)
		assertExhaustion([]string{"/usr/bin/env", "/bin/sh"}, false)
		assertExhaustion([]string{"exec", "/bin/sh"}, false)
	})
	t.Run("R24-6 a canon-normalized absolute interpreter keeps its fixed-path identity", func(t *testing.T) {
		var untrusted envAssignments
		untrusted.ops = append(untrusted.ops, envOp{kind: 't', key: "PATH"})
		// Acceptance spelling: even when the versioned interpreter is absent
		// on this host, its static basename classification is python — and a
		// host where it resolves to python3 must never let the canonical
		// rewrite erase the original fixed-path identity.
		targets := stdinProgramTargetsDialect([]string{"/usr/bin/python3.11"}, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
		prog, has := firstProgramTarget(targets)
		if !has {
			t.Fatalf("absolute versioned python projection produced no program target (%v) — the fixed absolute spelling must keep its interpreter identity", targets)
		}
		if prog.exhausted {
			t.Fatalf("absolute versioned python under untrusted PATH became exhausted (%+v) — the canonical rewrite to a slash-free interpreter name must not erase the original spelling's fixed-path identity", prog)
		}
		if prog.lang != "python" {
			t.Fatalf("absolute versioned python projection lang=%q, want python — the recognized interpreter type must survive the fixed-path PATH check", prog.lang)
		}
		// Discriminating rows: ruby/perl version suffixes are exactly the
		// canonical-resolved-base rewrite the R24 audit named. They need no
		// host executable because the typed basename itself carries the
		// static interpreter classification.
		for _, tc := range []struct{ exe, lang string }{
			{"/usr/bin/ruby3.2", "ruby"},
			{"/usr/bin/perl5.38", "perl"},
		} {
			rows := stdinProgramTargetsDialect([]string{tc.exe}, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
			row, rowHas := firstProgramTarget(rows)
			if !rowHas {
				t.Fatalf("absolute %s projection produced no program target (%v) — the fixed absolute spelling must keep its interpreter identity", tc.exe, rows)
			}
			if row.exhausted {
				t.Fatalf("absolute %s under untrusted PATH became exhausted (%+v) — canonical normalization rewrote the fixed absolute spelling into a slash-free name and then misread it as PATH-dependent", tc.exe, row)
			}
			if row.lang != tc.lang {
				t.Fatalf("absolute %s projection lang=%q, want %q — the recognized interpreter type must survive the fixed-path PATH check", tc.exe, row.lang, tc.lang)
			}
		}
	})
}

// TestGuard_V622_OracleR25Probes pins the Oracle R25 / Reviewer R25
// closure — one discriminating subtest per intersecting finding:
//
//	R25-1: the declare-family emission path never mints a scalar static
//	  binding for an array-subscript or `+=` assignment either (the
//	  R24 fix covered only emitCall), while a plain declare bind stays
//	  exact (Oracle MF1).
//	R25-2: the static eval readonly replay covers the POSIX CallExpr
//	  shape and bash's `declare -r` flag word, not only the bash bare
//	  readonly DeclClause (Oracle MF2 / Reviewer #3).
//	R25-3: a non-nil but EMPTY registry map still counts as shared for
//	  the substitution collector's copy-on-write, and positional facts
//	  replayed inside child-process eval shapes roll back with the
//	  child while the foreground equivalents register (Oracle MF3 /
//	  Reviewer #4/#5).
//	R25-4: the xargs replacement-mode recursion-depth cutoff records
//	  the sticky exhaustion bit exactly like the append-mode cutoff
//	  (Oracle MF4 / Reviewer #2).
//	R25-5: the SSH stdin-program body review consumes the target's
//	  folded remote environment exactly like the heredoc entry, the
//	  xargs inner shell target carries the consuming shell's dialect,
//	  and the legacy pure-vehicle spelling delegates to the production
//	  entry (Oracle MF5 + SF2 / Reviewer #6/#10).
//	R25-6: bare external wrapper adoption is validated at EVERY peel
//	  layer with the layer-folded environment, while fixed-path GNU
//	  aliases keep their slash identity (Oracle MF6 / Reviewer #1).
//
// Every discriminating row is FAIL-first on the pre-fix tree 028ac50:
// the probes reference only symbols that already exist there (the
// collectors, the stdin projection helpers, the xargs budget table and
// the ssh screen entries), so the file compiles verbatim on the parent
// tree and the failures reproduce the audit findings directly.
func TestGuard_V622_OracleR25Probes(t *testing.T) {
	// ---- R25-1: the declare-family path shares the operator verdict ----
	t.Run("R25-1 declare-family append and subscript assignments never mint scalar static bindings", func(t *testing.T) {
		emitDeclAssign := func(src string) *subCollector {
			t.Helper()
			p := syntax.NewParser(syntax.Variant(syntax.LangBash))
			f, err := p.Parse(strings.NewReader(src), "")
			if err != nil || len(f.Stmts) != 1 {
				t.Fatalf("parse %q: err=%v stmts=%d", src, err, len(f.Stmts))
			}
			decl, isDecl := f.Stmts[0].Cmd.(*syntax.DeclClause)
			if !isDecl {
				t.Fatalf("fixture broken: %q root cmd is %T, want DeclClause", src, f.Stmts[0].Cmd)
			}
			c := blankSubCollector()
			c.allowBind = true
			c.emitDecl(f.Stmts[0], decl, stdinFeed{})
			return c
		}
		if got := emitDeclAssign(`declare ARR[1]=/marker`).staticVars["ARR"]; got == "/marker" {
			t.Fatalf("declare ARR[1]=/marker minted staticVars[ARR]=%q — a subscript write touches one array element and can never establish the scalar value later expansion reads; the declare path must share emitCall's operator verdict", got)
		}
		if got := emitDeclAssign(`declare VAR+=/marker`).staticVars["VAR"]; got == "/marker" {
			t.Fatalf("declare VAR+=/marker minted staticVars[VAR]=%q — bash concatenates the suffix onto the inherited value, so the literal suffix is never the exact scalar binding; the declare path must share emitCall's operator verdict", got)
		}
		if got := emitDeclAssign(`declare VAR=/marker`).staticVars["VAR"]; got != "/marker" {
			t.Fatalf("control broken: plain declare VAR=/marker staticVars[VAR]=%q, want /marker — the independent plain declaration assignment must keep its exact binding", got)
		}
	})

	// ---- R25-2: readonly replay covers POSIX calls and declare -r ----
	t.Run("R25-2 eval readonly replay covers the POSIX CallExpr and the declare -r flag word", func(t *testing.T) {
		replay := func(posix bool, text string) *subCollector {
			t.Helper()
			c := blankSubCollector()
			c.allowBind = true
			c.posixNoBraces = posix
			c.bindEvalTextWrites(text, 0)
			return c
		}
		if !replay(true, "readonly AUDIT_MARK").readonlyVars["AUDIT_MARK"] {
			t.Fatalf("POSIX-mode eval replay of 'readonly AUDIT_MARK' left readonlyVars empty — POSIX parses readonly as a CallExpr, and the replication must record the attribute exactly like the main traversal's emitCall")
		}
		if !replay(false, "declare -r AUDIT_MARK").readonlyVars["AUDIT_MARK"] {
			t.Fatalf("bash-mode eval replay of 'declare -r AUDIT_MARK' left readonlyVars empty — the declaration's -r flag word is Naked=true with no name, and serializing it as an empty string loses the readonly cluster")
		}
		if !replay(false, "readonly AUDIT_MARK").readonlyVars["AUDIT_MARK"] {
			t.Fatalf("control broken: bash-mode eval replay of bare 'readonly AUDIT_MARK' left readonlyVars empty — the R24 DeclClause replay itself regressed")
		}
	})

	// ---- R25-3: empty-but-aliased registries stay copy-on-write ----
	t.Run("R25-3 an emptied parent registry map never aliases substitution writes", func(t *testing.T) {
		parent := blankSubCollector()
		// Open a child-process frame, register one throwaway function and
		// restore it: the undo deletes the key but the map OBJECT stays
		// non-nil — exactly the state a finished child shell leaves behind.
		restore := parent.snapshotProcessRegs()
		parent.noteFuncDef(&syntax.FuncDecl{Name: &syntax.Lit{Value: "r25tmpfn"}})
		restore()
		if parent.funcNames == nil || len(parent.funcNames) != 0 {
			t.Fatalf("fixture broken: after the insert/restore cycle funcNames=%v (nil=%v) — the audit's premise is a non-nil empty map", parent.funcNames, parent.funcNames == nil)
		}
		sub := parent.newSub()
		sub.noteFuncDef(&syntax.FuncDecl{Name: &syntax.Lit{Value: "r25subfn"}})
		if parent.funcNames["r25subfn"] {
			t.Fatalf("substitution function write leaked into the parent registry — a non-nil empty map is still a shared reference whose first write must clone, never an element-count verdict")
		}
		restoreRO := parent.snapshotProcessRegs()
		parent.noteReadonlyDecls([]string{"readonly", "R25TMPRO"})
		restoreRO()
		if parent.readonlyVars == nil || len(parent.readonlyVars) != 0 {
			t.Fatalf("fixture broken: after the readonly insert/restore cycle readonlyVars=%v — the audit's premise is a non-nil empty map", parent.readonlyVars)
		}
		sub2 := parent.newSub()
		sub2.noteReadonlyDecls([]string{"readonly", "R25SUBRO"})
		if parent.readonlyVars["R25SUBRO"] {
			t.Fatalf("substitution readonly write leaked into the parent registry — the empty aliased map was mutated in place")
		}
	})
	t.Run("R25-3 child-process eval replay registrations die with the child", func(t *testing.T) {
		probe := func(script string) *subCollector {
			t.Helper()
			p := syntax.NewParser(syntax.Variant(syntax.LangBash))
			f, err := p.Parse(strings.NewReader(script), "")
			if err != nil || len(f.Stmts) != 1 {
				t.Fatalf("parse %q: err=%v stmts=%d", script, err, len(f.Stmts))
			}
			call, isCall := f.Stmts[0].Cmd.(*syntax.CallExpr)
			if !isCall {
				t.Fatalf("fixture broken: %q root cmd is %T, want CallExpr", script, f.Stmts[0].Cmd)
			}
			c := blankSubCollector()
			c.allowBind = true
			c.bindEvalCallWrites(f.Stmts[0], call)
			return c
		}
		bg := probe(`eval 'readonly AUDIT_CHILD; r25child() { :; }' &`)
		if bg.readonlyVars["AUDIT_CHILD"] || bg.funcNames["r25child"] {
			t.Fatalf("backgrounded static eval replay registered child-process facts into the parent (readonly=%v funcs=%v) — the re-parse text carries no process bits, so the replay must frame the whole child-process statement", bg.readonlyVars, bg.funcNames)
		}
		nestedBg := probe(`eval "eval 'readonly AUDIT_NESTED; r25nested() { :; }' &"`)
		if nestedBg.readonlyVars["AUDIT_NESTED"] || nestedBg.funcNames["r25nested"] {
			t.Fatalf("nested backgrounded eval replay registered child-process facts into the parent (readonly=%v funcs=%v) — the inner eval statement's background bit must survive the re-parse through the boundary frame", nestedBg.readonlyVars, nestedBg.funcNames)
		}
		fg := probe(`eval 'readonly AUDIT_FG; r25fg() { :; }'`)
		if !fg.readonlyVars["AUDIT_FG"] || !fg.funcNames["r25fg"] {
			t.Fatalf("control broken: foreground static eval replay lost its positional facts (readonly=%v funcs=%v) — a same-process eval re-parse registers exactly like the direct spelling", fg.readonlyVars, fg.funcNames)
		}
		nestedFg := probe(`eval "eval 'readonly AUDIT_NFG'"`)
		if !nestedFg.readonlyVars["AUDIT_NFG"] {
			t.Fatalf("control broken: foreground nested eval replay lost its readonly registration — the frame must roll back ONLY the child-process shapes")
		}
	})

	// ---- R25-4: replacement-mode depth cutoff records exhaustion ----
	t.Run("R25-4 replacement-mode recursion-depth cutoff is sticky exhaustion", func(t *testing.T) {
		argv := []string{"cat"}
		for i := 0; i < peelChainMaxDepth+2; i++ {
			argv = append([]string{"xargs"}, argv...)
		}
		// Switch the OUTERMOST xargs to replacement mode with one token the
		// tree never carries: the replacement-slot scan descends the same
		// chain independently of the append analysis, and its own depth
		// cutoff must record the same exhaustion verdict.
		argv = append([]string{"xargs", "-I{}"}, argv...)
		fresh := &xargsWorkState{}
		targets := stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{xw: fresh}, false)
		if !xargsBudgetSpent(fresh) {
			t.Fatalf("replacement-mode deeply nested xargs projection did not mark the caller's request table exhausted — the replacement-slot scan's depth cutoff returned a bare hit verdict and the projection re-read it as a confirmed consumer")
		}
		hasExhausted := false
		for _, tg := range targets {
			if tg.exhausted {
				hasExhausted = true
			}
		}
		if !hasExhausted {
			t.Fatalf("replacement-mode deeply nested xargs projection = %v targets with NO exhaustion marker — an analysis cutoff can never pose as a confirmed empty-language target", targets)
		}
		first, okFirst := firstProgramTarget(targets)
		if okFirst && stdinShellTargetRewriteable(first, false) {
			t.Fatalf("replacement-mode depth-cutoff projection remained rewrite-eligible (%+v) — an unidentified consumer is never a certified shell program", first)
		}
	})

	// ---- R25-5: SSH body environment, xargs inner dialect, vehicle delegation ----
	t.Run("R25-5 the SSH stdin body review consumes the target's folded remote environment", func(t *testing.T) {
		t.Setenv("HOME", "/home/r25parent")
		// A conditional remote HOME write marks the variable uncertain in
		// the target's folded envAs: the body's $HOME expansion must face
		// the taint exactly like the heredoc entry, never re-read the
		// parent process HOME.
		var folded envAssignments
		folded.ops = append(folded.ops, envOp{kind: 't', key: "HOME"})
		targets := []stdinTarget{{lang: "", envAs: folded}}
		seg := shellSegment{heredocText: []heredocBody{{text: "\"$HOME/bin/hc\""}}}
		sshHit := sshStdinProgramBodiesHit(targets, seg, 's', 0, true, callerIdentity{})
		hdHit := screenHeredocBodyTargetsDepth("\"$HOME/bin/hc\"", targets, 's', 0, callerIdentity{})
		if hdHit == "" {
			t.Fatalf("control broken: the heredoc body entry screens the HOME-tainted $HOME/bin/hc body clean — the tainted-HOME verdict fixture itself regressed")
		}
		if sshHit != hdHit {
			t.Fatalf("SSH stdin body review verdict %q vs heredoc entry %q — the SSH path re-uses the local caller instead of seeding the remote identity with the target's folded environment, so the same body faces two different environments", sshHit, hdHit)
		}
	})
	t.Run("R25-5 the xargs inner shell target carries the consuming shell dialect", func(t *testing.T) {
		probe := func(shell string) stdinTarget {
			t.Helper()
			xw := &xargsWorkState{}
			targets := stdinProgramTargetsDialect([]string{"xargs", "-I{}", shell, "-c", "{}"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{xw: xw}, false)
			first, okFirst := firstProgramTarget(targets)
			if !okFirst {
				t.Fatalf("xargs -I{} %s -c {} projected no program target (%v)", shell, targets)
			}
			if first.exhausted {
				t.Fatalf("xargs -I{} %s -c {} projected an exhausted target (%+v) — the confirmed open code slot is a definite consumer", shell, first)
			}
			return first
		}
		if got := probe("bash"); !got.bash {
			t.Fatalf("xargs bash -c inner target bash=%v — a remote bash reading stdin brace-expands exactly like a local one, and the open-code-slot projection never wrote the dialect bit", got.bash)
		}
		if got := probe("dash"); got.bash {
			t.Fatalf("control broken: xargs dash -c inner target bash=%v — dash is never the brace-expanding dialect", got.bash)
		}
	})
	// R26-Reviewer-#9: the tautological legacy pure-vehicle delegation
	// comparison row is REMOVED — both spellings called the same production
	// entry with equivalent arguments, so it passed on BOTH trees even if
	// the certification degenerated to a constant; the five independent
	// behavioral assertions at the shared tail (lines 827/834/1254/1266/
	// 1270 of this file's R20-R24 rows) already pin the delegation's
	// behavior, and cognitive-complexity-0 pure delegation earns no new
	// behavioral case. TestGuard_V622_OracleR25Probes therefore holds 10
	// discriminating subtests after this removal.

	// ---- R25-6: per-layer wrapper validation; fixed-path GNU aliases ----
	t.Run("R25-6 bare external wrappers are validated at every peel layer", func(t *testing.T) {
		var untrusted envAssignments
		untrusted.ops = append(untrusted.ops, envOp{kind: 't', key: "PATH"})
		assertExhaustion := func(argv []string, want bool) {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
			got := false
			for _, tg := range targets {
				if tg.exhausted {
					got = true
				}
			}
			if got != want {
				t.Fatalf("stdinProgramTargetsDialect(%v) exhaustion = %v, want %v (targets=%v) — every bare external wrapper layer owes its own resolution to the untrusted PATH, no matter how many transparent or fixed-path layers precede it", argv, got, want, targets)
			}
		}
		// The R24 single-layer rows must survive unchanged.
		assertExhaustion([]string{"env", "/bin/sh"}, true)
		assertExhaustion([]string{"nice", "/bin/sh"}, true)
		assertExhaustion([]string{"/usr/bin/env", "/bin/sh"}, false)
		assertExhaustion([]string{"exec", "/bin/sh"}, false)
		// The discriminating rows: a transparent shell builtin or a
		// fixed-path env layer in front of the bare external wrapper must
		// not shield it — the peel adopts the inner identity in the same
		// invocation, so the validation must follow layer by layer.
		assertExhaustion([]string{"command", "env", "/bin/sh"}, true)
		assertExhaustion([]string{"/usr/bin/env", "nice", "/bin/sh"}, true)
	})
	t.Run("R25-6 a polluting PATH assignment folds before the bare wrapper validation", func(t *testing.T) {
		// No inherited taint: the prefix assignment itself carries the
		// unresolvable placeholder, so only a validator that FOLDS the
		// assignment words can see the untrusted PATH the bare env layer
		// resolves under.
		polluted := []string{"PATH=" + cmdSubPlaceholder + ":/evil", "env", "/bin/sh"}
		targets := stdinProgramTargetsDialect(polluted, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		got := false
		for _, tg := range targets {
			if tg.exhausted {
				got = true
			}
		}
		if !got {
			t.Fatalf("stdinProgramTargetsDialect(%v) exhaustion = false (targets=%v) — the bare env wrapper resolves under the PATH the prefix assignment itself polluted; skipping the assignment word without folding it validates the wrong environment", polluted, targets)
		}
	})
	t.Run("R25-6 a fixed-path GNU wrapper alias keeps its slash identity across the canon rewrite", func(t *testing.T) {
		var untrusted envAssignments
		untrusted.ops = append(untrusted.ops, envOp{kind: 't', key: "PATH"})
		targets := stdinProgramTargetsDialect([]string{"/usr/bin/genv", "/bin/sh"}, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
		first, okFirst := firstProgramTarget(targets)
		if !okFirst {
			t.Fatalf("/usr/bin/genv /bin/sh projected no program target (%v) — the fixed-path alias strips to /bin/sh exactly like the directly spelled env", targets)
		}
		if first.exhausted {
			t.Fatalf("/usr/bin/genv /bin/sh under untrusted PATH became exhausted (%+v) — the canonical rewrite dropped the directory prefix and the bare canon word was misread as PATH-dependent even though the original spelling carries its own resolution", first)
		}
		if first.lang != "" || first.data {
			t.Fatalf("control broken: /usr/bin/genv /bin/sh projected (%+v) — the peeled fixed-path shell target itself regressed", first)
		}
	})
}

// TestGuard_V622_OracleR26Probes pins the Oracle R26 / Reviewer R26
// discriminating rows: the taint-entry background-root eval process
// boundary, the hidden-eval pipeline sibling isolation, the nested
// statement redirection subtree scan, the wrapper entry-environment
// validation order, the xargs inner-target untrusted-PATH validation,
// the trailing missing-operand wrapper zones, the bounded single-pass
// wrapper budget, and the explicit relative-path slash identity. Every
// subtest references ONLY symbols already present on the pre-fix tree
// (the production entries are validated through their public internal
// surface), so the complete file compiles there verbatim.
func TestGuard_V622_OracleR26Probes(t *testing.T) {

	// ---- R26-1: taint-entry background root eval isolation ----
	t.Run("R26-1 the taint-entry background root eval replays inside its own process frame", func(t *testing.T) {
		probe := func(text string) *subCollector {
			t.Helper()
			c := blankSubCollector()
			c.allowBind = true
			c.taintEvalTextWrites(text, 0)
			return c
		}
		bg := probe(`eval "readonly AUDIT_CHILD; r26fn() { :; }" &`)
		if bg.readonlyVars["AUDIT_CHILD"] || bg.funcNames["r26fn"] {
			t.Fatalf("taint-entry backgrounded nested eval registered child-process facts into the parent (readonly=%v funcs=%v) — the root statement's background bit must frame the whole hidden-eval replay exactly like the bind entry", bg.readonlyVars, bg.funcNames)
		}
		fg := probe(`eval "readonly AUDIT_FG26; r26fg() { :; }"`)
		if !fg.readonlyVars["AUDIT_FG26"] || !fg.funcNames["r26fg"] {
			t.Fatalf("control broken: foreground taint-entry nested eval lost its positional facts (readonly=%v funcs=%v) — a same-process re-parse registers exactly like the certain replication", fg.readonlyVars, fg.funcNames)
		}
		vt := probe(`AUDIT_V26=/x &`)
		if !vt.taintedVars["AUDIT_V26"] {
			t.Fatalf("control broken: the child-process frame rolled back the conservative variable TAINT of the same writes (taintedVars=%v) — pollution belongs to the possibility, never the process ownership", vt.taintedVars)
		}
		// The redirected eval spelling reaches the taint replay through
		// bindEvalCallWrites (a possibly-failing redirection never mints a
		// bind): the nested background root inside the tainted text must
		// face the same process frame.
		p := syntax.NewParser(syntax.Variant(syntax.LangBash))
		f, err := p.Parse(strings.NewReader(`eval 'eval "readonly AUDIT_R26R; r26rf() { :; }" &' </dev/null`), "")
		if err != nil || len(f.Stmts) != 1 {
			t.Fatalf("parse redirected eval fixture: err=%v stmts=%d", err, len(f.Stmts))
		}
		call, isCall := f.Stmts[0].Cmd.(*syntax.CallExpr)
		if !isCall {
			t.Fatalf("fixture broken: redirected eval root cmd is %T, want CallExpr", f.Stmts[0].Cmd)
		}
		c := blankSubCollector()
		c.allowBind = true
		c.bindEvalCallWrites(f.Stmts[0], call)
		if c.readonlyVars["AUDIT_R26R"] || c.funcNames["r26rf"] {
			t.Fatalf("redirected eval's nested background root registered child-process facts into the parent (readonly=%v funcs=%v) — the taint replay of the redirected eval must frame the backgrounded statement it re-parses", c.readonlyVars, c.funcNames)
		}
	})

	// ---- R26-2: hidden-eval pipeline sibling isolation ----
	t.Run("R26-2 hidden-eval pipeline components scan in independent sibling frames", func(t *testing.T) {
		probe := func(text string) *subCollector {
			t.Helper()
			c := blankSubCollector()
			c.allowBind = true
			c.taintEvalTextWrites(text, 0)
			return c
		}
		sib := probe(`eval 'eval() { :; }' | eval`)
		if sib.taintedVars["PATH"] {
			t.Fatalf("right-side bare eval was shadowed by the LEFT pipeline component's nested definition (taintedVars=%v) — the two components must scan in independent registry frames derived from the same parent state", sib.taintedVars)
		}
		if sib.funcNames["eval"] {
			t.Fatalf("pipeline nested function definition leaked into the parent registry (funcNames=%v) — both components are child processes whose registrations die with them", sib.funcNames)
		}
		ctrl := probe(`{ eval 'eval() { :; }'; eval; } | cat`)
		if !ctrl.taintedVars["PATH"] {
			t.Fatalf("control broken: same-component nested eval shadowing left PATH untainted (taintedVars=%v) — registrations inside ONE pipeline component must stay visible to that component's own later statements before the frame rolls back", ctrl.taintedVars)
		}
	})

	// ---- R26-3: nested statement redirection subtrees ----
	t.Run("R26-3 the hidden-eval scan walks nested statement redirection subtrees", func(t *testing.T) {
		probe := func(text string) *subCollector {
			t.Helper()
			c := blankSubCollector()
			c.allowBind = true
			c.taintEvalTextWrites(text, 0)
			return c
		}
		ifHit := probe(`if true; then : >/dev/null/$(command -x eval); fi`)
		if !ifHit.taintedVars["PATH"] {
			t.Fatalf("nested if-body redirection substitution `$(command -x eval)` left PATH untainted (taintedVars=%v) — the hidden-eval scan never descended into the statement's redirection subtree, silently dropping the tainted short-rest chain the pre-scan counts", ifHit.taintedVars)
		}
		blockHit := probe(`{ >/dev/null/$(command -x eval); }`)
		if !blockHit.taintedVars["PATH"] {
			t.Fatalf("empty-command redirection substitution `$(command -x eval)` left PATH untainted (taintedVars=%v) — a nil command must never skip the statement's own redirection words", blockHit.taintedVars)
		}
		ctrl := probe(`>/dev/null/$(eval 'readonly AUDIT_NR26; r26nrfn() { :; }')`)
		if ctrl.readonlyVars["AUDIT_NR26"] || ctrl.funcNames["r26nrfn"] {
			t.Fatalf("control broken: redirection command substitution registered substitution-local facts into the parent (readonly=%v funcs=%v) — the substitution frame must roll back exactly like before", ctrl.readonlyVars, ctrl.funcNames)
		}
	})

	// ---- R26-4: wrapper entry-environment validation order ----
	t.Run("R26-4 bare wrapper validation uses the entry environment, not the post-layer one", func(t *testing.T) {
		probe := func(inherited envAssignments, argv []string) bool {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, inherited, "/usr/bin:/bin", callerIdentity{}, false)
			for _, tg := range targets {
				if tg.exhausted {
					return true
				}
			}
			return false
		}
		assertExh := func(inherited envAssignments, argv []string, want bool) {
			t.Helper()
			if got := probe(inherited, argv); got != want {
				t.Fatalf("stdinProgramTargetsDialect(%v) exhaustion = %v, want %v — a wrapper's own resolution must face the environment in force when the kernel looked it up, never the operands only the next layer inherits", argv, got, want)
			}
		}
		var trusted envAssignments
		// R27-Reviewer-#7: the positive rows must pin the CONFIRMED shell
		// target itself — a nil/data/exhausted projection or a wrong
		// language must never satisfy them. The env operand is a STATIC
		// clean PATH assignment (a bare cmdSubPlaceholder word is not
		// single-word-safe and skipEnvOperandsToken rightly stops the env
		// scan on it as a dynamic option, so it can never serve as the
		// fold fixture), and the target's envAs must PROVE the fold by
		// carrying the exact 'a' op the peel recorded.
		assertShell := func(inherited envAssignments, argv []string, wantPathOp string) {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, inherited, "/usr/bin:/bin", callerIdentity{}, false)
			first, ok := firstProgramTarget(targets)
			if !ok {
				t.Fatalf("stdinProgramTargetsDialect(%v) projected NO program target (%v) — the confirmed shell consumer itself regressed, not just its exhaustion bit", argv, targets)
			}
			if first.exhausted || first.data || first.lang != "" {
				t.Fatalf("stdinProgramTargetsDialect(%v) first target = %+v — want a non-exhausted, non-data, empty-language confirmed POSIX shell target", argv, first)
			}
			if wantPathOp != "" {
				found := false
				for _, op := range first.envAs.ops {
					if op.kind == 'a' && op.key == "PATH" && op.value == wantPathOp {
						found = true
					}
				}
				if !found {
					t.Fatalf("stdinProgramTargetsDialect(%v) target envAs.ops = %v — the env operand PATH assignment never folded into the target environment, so the entry/post-layer ordering verdict is unproven", argv, first.envAs.ops)
				}
			}
		}
		// A bare env validated under the trusted ENTRY environment stays a
		// confirmed consumer even though its own operands poison the NEXT
		// layer's PATH: the pre-fix scan judged env against the post-layer
		// environment and falsely exhausted it. The fold is pinned both
		// for a static clean PATH value and for a single-word-safe quoted
		// dynamic value (the quoted placeholder folds exactly like a static
		// operand because it can never field-split).
		assertShell(trusted, []string{"env", "PATH=/usr/bin:/bin", "/bin/sh"}, "/usr/bin:/bin")
		assertShell(trusted, []string{"env", "PATH=" + cmdSubPlaceholderQuoted, "/bin/sh"}, cmdSubPlaceholderQuoted)
		// R28-Oracle-S1 / Reviewer R28: the quoted dynamic fold must ALSO
		// read as an untrusted effective PATH — the word boundary is known
		// but the content never is, so the env op replay's trust verdict
		// keys on every dynamic placeholder class (R28-Oracle-M5), never
		// on the bare cmdSubPlaceholder spelling alone. On the pre-R28
		// verdict this row reads trusted — the exact misjudgment the
		// strengthened propagation row below exposes end to end.
		qTargets := stdinProgramTargetsDialect([]string{"env", "PATH=" + cmdSubPlaceholderQuoted, "/bin/sh"}, 0, trusted, "/usr/bin:/bin", callerIdentity{}, false)
		qFirst, qOk := firstProgramTarget(qTargets)
		if !qOk || !qFirst.envAs.pathUntrusted("/usr/bin:/bin") {
			t.Fatalf("stdinProgramTargetsDialect([env PATH=<quoted> /bin/sh]) target envAs pathUntrusted = %v (first=%+v ok=%v) — a fully double-quoted dynamic PATH value is an unknowable search list exactly like the unquoted form", qOk && qFirst.envAs.pathUntrusted("/usr/bin:/bin"), qFirst, qOk)
		}
		assertExh(trusted, []string{"env", "PATH=/usr/bin:/bin", "/bin/sh"}, false)
		// Non-sticky placeholder entry environments: env -i / -u PATH clear
		// PATH only AFTER the bare env itself already resolved through the
		// untrusted entry search list — the pre-fix scan validated against
		// the cleared post-layer environment and missed both.
		var phInherited envAssignments
		phInherited.ops = append(phInherited.ops, envOp{kind: 'a', key: "PATH", value: cmdSubPlaceholder})
		assertExh(phInherited, []string{"env", "-i", "/bin/sh"}, true)
		assertExh(phInherited, []string{"env", "-u", "PATH", "/bin/sh"}, true)
		// A bare env with NO operand zone under a TRUSTED entry environment
		// resolves fine and keeps the confirmed fixed-path shell target
		// itself (R28-Oracle-S1 — the upgraded positive control pins the
		// target, never merely the absence of an exhaustion bit).
		assertShell(trusted, []string{"env", "/bin/sh"}, "")
		// The untrusted verdict propagates layer by layer: once env's
		// operands poison the PATH, the NEXT bare external wrapper faces
		// it. R28-Oracle-S1 / Reviewer R28: the fold fixture is the
		// single-word-safe QUOTED dynamic value — a BARE cmdSubPlaceholder
		// stops the env operand scan itself as a dynamic option
		// (R27-Reviewer-#7), so env exhausts before the poisoned PATH ever
		// reaches nice and the row could never discriminate propagation.
		// The quoted fold survives the operand scan and the exhaustion
		// verdict can only arise when the NEXT layer's bare nice faces
		// the poisoned PATH (R28-Oracle-M5).
		assertExh(trusted, []string{"env", "PATH=" + cmdSubPlaceholderQuoted, "nice", "/bin/sh"}, true)
	})

	// ---- R26-5: xargs inner-target untrusted-PATH validation ----
	t.Run("R26-5 the xargs open-code-slot inner target validates bare wrappers and bare heads", func(t *testing.T) {
		var untrusted envAssignments
		untrusted.ops = append(untrusted.ops, envOp{kind: 't', key: "PATH"})
		probe := func(argv []string) (stdinTarget, bool) {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{xw: &xargsWorkState{}}, false)
			return firstProgramTarget(targets)
		}
		assertExhausted := func(argv []string, want bool) {
			t.Helper()
			first, ok := probe(argv)
			got := ok && first.exhausted
			if got != want {
				t.Fatalf("stdinProgramTargetsDialect(%v) inner-target exhaustion = %v, want %v (first=%+v ok=%v) — the open-code-slot inner target owes its resolution to the same untrusted PATH", argv, got, want, first, ok)
			}
		}
		assertExhausted([]string{"/usr/bin/xargs", "-I{}", "env", "/bin/sh", "-c", "{}"}, true)
		assertExhausted([]string{"/usr/bin/xargs", "-I{}", "sh", "-c", "{}"}, true)
		first, ok := probe([]string{"/usr/bin/xargs", "-I{}", "/usr/bin/env", "/bin/bash", "-c", "{}"})
		if !ok || first.exhausted {
			t.Fatalf("control broken: /usr/bin/xargs -I{} /usr/bin/env /bin/bash -c {} under untrusted PATH became exhausted (first=%+v ok=%v) — slash-carrying wrapper and shell spellings carry their own resolution", first, ok)
		}
		if !first.bash {
			t.Fatalf("control broken: /usr/bin/xargs -I{} /usr/bin/env /bin/bash -c {} inner target bash=%v — the fixed-path bash keeps its dialect exactly like the direct spelling", first.bash)
		}
	})

	// ---- R26-6: trailing missing-operand wrapper zones ----
	t.Run("R26-6 trailing missing-operand wrapper options clamp at the slice bound", func(t *testing.T) {
		for _, tc := range []struct {
			argv []string
			base string
		}{
			{[]string{"nice", "-n"}, "nice"},
			{[]string{"nice", "--adjustment"}, "nice"},
			{[]string{"timeout", "-k"}, "timeout"},
			{[]string{"timeout", "-s"}, "timeout"},
			{[]string{"stdbuf", "-o"}, "stdbuf"},
			{[]string{"ionice", "-c"}, "ionice"},
			{[]string{"taskset", "-c"}, "taskset"},
			{[]string{"strace", "-e"}, "strace"},
			{[]string{"time", "-o"}, "time"},
			{[]string{"exec", "-a"}, "exec"},
		} {
			next, ok := peelSingleWrapperArgs(tc.argv, tc.base)
			if next < 0 || next > len(tc.argv) {
				t.Fatalf("peelSingleWrapperArgs(%v, %q) = (%d, %v) — the returned index escapes the slice bound and argv[ni:] panics in every consumer", tc.argv, tc.base, next, ok)
			}
			if next != len(tc.argv) || ok {
				t.Fatalf("peelSingleWrapperArgs(%v, %q) = (%d, %v), want (%d, false) — a trailing valued option missing its operand fails closed exactly at the slice bound", tc.argv, tc.base, next, ok, len(tc.argv))
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("stdinProgramTargetsDialect(%v) panicked: %v — an incomplete trailing wrapper option must yield the exhaustion verdict, never a slice-bounds panic", tc.argv, r)
					}
				}()
				targets := stdinProgramTargetsDialect(tc.argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
				hasExh := false
				for _, tg := range targets {
					if tg.exhausted {
						hasExh = true
					}
				}
				if !hasExh {
					t.Fatalf("stdinProgramTargetsDialect(%v) = %v targets with NO exhaustion marker — the incomplete trailing option zone is an unprovable arity, never a confirmed empty command", tc.argv, targets)
				}
			}()
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("remoteStdinProgramTargets projection of %v panicked: %v — screenSSHHead hands incomplete remote segments to the same peel path", tc.argv, r)
					}
				}()
				_, _, ex := remoteStdinProgramTargets(strings.Join(tc.argv, " "), stdinEntryCaller("/tmp"))
				if !ex {
					t.Fatalf("remoteStdinProgramTargets projection of %v exhausted=false — the incomplete trailing option zone must surface the exhaustion verdict end to end", tc.argv)
				}
			}()
		}
	})

	// ---- R26-7: bounded single-pass wrapper budget ----
	t.Run("R26-7 the wrapper validation shares the bounded 32-step peel budget", func(t *testing.T) {
		build := func(layers int) []string {
			argv := []string{}
			for i := 0; i < layers; i++ {
				argv = append(argv, "env", "K=1")
			}
			return append(argv, "/bin/sh")
		}
		measure := func(argv []string) uint64 {
			t.Helper()
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for n := 0; n < 4; n++ {
				stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
			}
			runtime.ReadMemStats(&after)
			return after.TotalAlloc - before.TotalAlloc
		}
		small := measure(build(64))
		large := measure(build(512))
		if small == 0 {
			t.Fatalf("fixture broken: zero allocation for the 64-layer chain measurement")
		}
		if large > small*3/2 {
			t.Fatalf("wrapper-chain validation allocation scales with the chain length: %d bytes at L=64 vs %d at L=512 (ratio %.2f, want <= 1.5) — the validation must share peelWrapperMaxSteps' bounded single pass instead of pre-scanning every layer outside the budget", small, large, float64(large)/float64(small))
		}
		// Control: pure KEY=VAL assignments never consume wrapper steps —
		// a 40-assignment prefix ahead of a fixed-path env resolves the
		// confirmed fixed-path consumer without any exhaustion verdict.
		ctrl := []string{}
		for i := 0; i < 40; i++ {
			ctrl = append(ctrl, fmt.Sprintf("A%d=1", i))
		}
		ctrl = append(ctrl, "/usr/bin/env", "/bin/sh")
		targets := stdinProgramTargetsDialect(ctrl, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		first, okFirst := firstProgramTarget(targets)
		// R27-Reviewer-#7: the positive control pins the confirmed shell
		// target itself, never merely the absence of an exhaustion bit.
		if !okFirst || first.exhausted || first.data || first.lang != "" {
			t.Fatalf("control broken: 40 pure assignments ahead of /usr/bin/env /bin/sh projected first=%+v ok=%v (targets=%v) — want a non-exhausted, non-data, empty-language confirmed POSIX shell target; pure assignments are step-exempt exactly like the pre-fix peel", first, okFirst, targets)
		}
	})

	// ---- R26-8: explicit relative-path slash identity ----
	t.Run("R26-8 explicit relative-path wrapper aliases never degrade into bare names", func(t *testing.T) {
		var untrusted envAssignments
		untrusted.ops = append(untrusted.ops, envOp{kind: 't', key: "PATH"})
		probe := func(argv []string) bool {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
			for _, tg := range targets {
				if tg.exhausted {
					return true
				}
			}
			return false
		}
		// R27-Reviewer-#7: the positive rows pin the CONFIRMED shell target
		// itself — degenerating every slash target into no target at all
		// must never satisfy them.
		assertConfirmedShell := func(argv []string, desc string) {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
			first, ok := firstProgramTarget(targets)
			if !ok || first.exhausted || first.data || first.lang != "" {
				t.Fatalf("%s under untrusted PATH projected first=%+v ok=%v (targets=%v) — want a non-exhausted, non-data, empty-language confirmed POSIX shell target: an explicit relative spelling carries its own resolution and must never degrade into a PATH-dependent bare name", desc, first, ok, targets)
			}
		}
		// Explicit relative spellings keep their fixed-path identity across
		// the canonical GNU-alias rewrite even when filepath.Join would
		// clean the slash away — the pre-fix rewrite degraded both into the
		// bare canon word and re-validated them through the untrusted PATH.
		assertConfirmedShell([]string{"./genv", "/bin/sh"}, "./genv /bin/sh")
		assertConfirmedShell([]string{"sub/../genv", "/bin/sh"}, "sub/../genv /bin/sh")
		if !probe([]string{"genv", "/bin/sh"}) {
			t.Fatalf("control broken: bare genv /bin/sh under untrusted PATH did NOT exhaust — a genuinely slash-free GNU alias owes its resolution to PATH exactly like the canonical env")
		}
		// A symlinked fixed-path wrapper alias preserves its slash identity
		// through the resolved-wrapper recursion as well.
		dir := t.TempDir()
		if err := os.Symlink("/usr/bin/env", filepath.Join(dir, "myenv")); err != nil {
			t.Fatalf("fixture symlink: %v", err)
		}
		t.Chdir(dir)
		assertConfirmedShell([]string{"./myenv", "/bin/sh"}, "./myenv (-> /usr/bin/env) /bin/sh")
		if !probe([]string{"myenv", "/bin/sh"}) {
			t.Fatalf("control broken: bare myenv /bin/sh under untrusted PATH did NOT exhaust — a genuinely slash-free wrapper alias owes its resolution to PATH")
		}
	})
}

// TestGuard_V622_OracleR27Probes pins the Oracle R27 / Reviewer R27
// discriminating rows: the pipeline component root-call scan plus the
// same-component direct AST registrations, the dynamic-vs-missing
// operand residue indices, the xargs checked-peel single application
// of the env ops, the execution-context-sensitive builtin exemption
// with the bare-name-before-alias ordering, the cross-alias shared
// 32-step budget with the single `--` consumption, and the env/
// taskset/chrt missing-operand fail-closed verdicts. Every subtest
// references ONLY symbols already present on the pre-fix tree
// 0d907a8 (the collectors, peel helpers, the tracker constructor is
// intentionally NOT referenced — the checked path is exercised through
// stdinProgramTargetsDialect end to end), so the complete file compiles
// there verbatim.
func TestGuard_V622_OracleR27Probes(t *testing.T) {

	// ---- R27-1: pipeline component root calls scan through the
	// statement entry, and same-component direct AST registrations are
	// visible inside the component's own frame ----
	t.Run("R27-1 pipeline component root eval chains scan exactly like their block-wrapped twins", func(t *testing.T) {
		probe := func(text string) *subCollector {
			t.Helper()
			c := blankSubCollector()
			c.allowBind = true
			c.taintEvalTextWrites(text, 0)
			return c
		}
		// The direct pipe component root `command -x eval` is a tainted
		// short-rest eval chain — exactly the R26-3 fixture shape. Wrapped
		// in a single-statement Block the nested Stmt already reached
		// scanHiddenEvalStmt; unwrapped, the pre-R27 scan dispatched the
		// root statement into scanHiddenEvalNode whose walk returns true
		// at the root and never runs the root call check.
		if direct := probe(`command -x eval | cat`); !direct.taintedVars["PATH"] {
			t.Fatalf("direct pipe component root `command -x eval | cat` left PATH untainted (taintedVars=%v) — the component root statement entered through scanHiddenEvalDispatch/scanHiddenEvalNode skips scanHiddenEvalStmtBody's root call check entirely", direct.taintedVars)
		}
		if wrapped := probe(`{ command -x eval; } | cat`); !wrapped.taintedVars["PATH"] {
			t.Fatalf("control broken: block-wrapped `{ command -x eval; } | cat` left PATH untainted (taintedVars=%v) — the nested Stmt reference case must stay on the same verdict", wrapped.taintedVars)
		}
		// Root redirection descent: the substitution hiding a nested eval
		// inside the pipe component's own redirection word must reach the
		// scan exactly like the block-wrapped spelling.
		if directRedir := probe(`: >/dev/null/$(command -x eval) | cat`); !directRedir.taintedVars["PATH"] {
			t.Fatalf("direct pipe component root redirection substitution `: >/dev/null/$(command -x eval) | cat` left PATH untainted (taintedVars=%v) — the component root statement's Redirs list never scanned", directRedir.taintedVars)
		}
		// Negative control: a non-eval-shaped direct root keeps the stream
		// clean — the scan must stay precise, never blanket-tainted.
		if neg := probe(`command cat | cat`); neg.taintedVars["PATH"] {
			t.Fatalf("control broken: non-eval-shaped direct root `command cat | cat` polluted PATH (taintedVars=%v) — the root call check must stay verdict-precise", neg.taintedVars)
		}
	})

	t.Run("R27-1 same-component direct AST function definitions register inside the component frame", func(t *testing.T) {
		probe := func(text string) *subCollector {
			t.Helper()
			c := blankSubCollector()
			c.allowBind = true
			c.taintEvalTextWrites(text, 0)
			return c
		}
		// The directly-written AST FuncDecl (NOT an eval-text re-parse)
		// shadows the later bare eval inside the SAME pipeline component:
		// the shadowed invocation is eval-shaped but never the builtin, so
		// its short rest carries the uniform maximal pollution verdict.
		shadowed := probe(`{ eval() { :; }; eval; } | cat`)
		if !shadowed.taintedVars["PATH"] {
			t.Fatalf("`{ eval() { :; }; eval; } | cat` left PATH untainted (taintedVars=%v) — the direct AST FuncDecl inside the pipe component never registered, so the shadowed bare eval was misread as a no-op builtin invocation", shadowed.taintedVars)
		}
		if shadowed.funcNames["eval"] {
			t.Fatalf("pipe component function definition leaked into the parent registry (funcNames=%v) — the component is a child process whose registrations die with it when the frame restores", shadowed.funcNames)
		}
		// Negative control: without the definition the bare eval is the
		// no-operand builtin — genuinely re-parsing nothing.
		if plain := probe(`{ eval; } | cat`); plain.taintedVars["PATH"] {
			t.Fatalf("control broken: `{ eval; } | cat` polluted PATH (taintedVars=%v) — a no-operand unshadowed eval chain re-parses nothing", plain.taintedVars)
		}
		// Sibling isolation: the definition inside the LEFT component must
		// never shadow the right component's name resolution.
		if sib := probe(`{ eval() { :; }; } | cat`); sib.taintedVars["PATH"] {
			t.Fatalf("control broken: `{ eval() { :; }; } | cat` polluted PATH (taintedVars=%v) — a definition without any shadowed invocation must stay inert", sib.taintedVars)
		}
	})

	// ---- R27-2: dynamic option values keep the pre-R26 residue index ----
	t.Run("R27-2 dynamic option values keep the pre-R26 non-empty residue", func(t *testing.T) {
		// peelWrappers([timeout,-k,cmdSubPlaceholder]) — pre-R26 abe543b
		// returned the non-empty residue argv[1:] (the dynamic -k value
		// stops the scan AT the option) with the fail-closed bit; merging
		// the dynamic-value and missing-operand verdicts into len(argv)
		// empties the residue and the downstream prepare/nested-collect
		// empty-head skips drop the unknowable consumer from the summary.
		head, _, _, exhausted := peelWrappers([]string{"timeout", "-k", cmdSubPlaceholder})
		if len(head) != 2 {
			t.Fatalf("peelWrappers([timeout -k %q]) residue length = %d (head=%v exhausted=%v), want 2 — the dynamic -k value EXISTS, so the residue starts at the option exactly like pre-R26, never at len(argv)", cmdSubPlaceholder, len(head), head, exhausted)
		}
		if !exhausted {
			t.Fatalf("peelWrappers([timeout -k %q]) exhausted = false — the fail-closed verdict itself must survive exactly like the merged form", cmdSubPlaceholder)
		}
		// peelWrappersWithIndex must not collapse the dynamic-valued zone
		// into an empty head either — the nested collect / flat prepare
		// empty-head skip fires only for a truly consumed argv.
		if peeledHead, _, _, _, _ := peelWrappersWithIndex([]string{"timeout", "-k", cmdSubPlaceholder}, callerIdentity{}); len(peeledHead) == 0 {
			t.Fatalf("peelWrappersWithIndex([timeout -k %q]) returned an EMPTY head — the dynamic option value is residue, not absence", cmdSubPlaceholder)
		}
		// Regression pin: the truly-missing trailing operand still clamps
		// at the slice bound with the fail-closed verdict (R26-6).
		missing, _, _, missExhausted := peelWrappers([]string{"timeout", "-k"})
		if len(missing) != 0 || !missExhausted {
			t.Fatalf("control broken: peelWrappers([timeout -k]) residue length = %d exhausted = %v — the missing-operand clamp regressed", len(missing), missExhausted)
		}
	})

	// ---- R27-3: the xargs checked peel applies every env op exactly once ----
	t.Run("R27-3 the xargs checked peel applies a self-referencing PATH op exactly once", func(t *testing.T) {
		// A PATH assignment carrying the unforgeable self-reference
		// sentinel is NOT idempotent: applying it once against /base yields
		// /base/x, applying the SAME op again yields /base/x/x. The core
		// already folds every op batch in place as it peels — the checked
		// alias loop must never re-apply the merged batch.
		target := []string{"env", "PATH=" + envPathSelfPlaceholder + "/x", "/bin/sh"}
		caller := callerIdentity{}
		// The tracker literal carries only the pre-R27 shared fields, so
		// the file compiles verbatim on the parent tree 0d907a8.
		tk := &wrapperPathTracker{cur: "/base"}
		_, _, _, exhausted := peelWrappersAndWrapperAliasesChecked(target, "/base", caller, tk)
		if exhausted {
			t.Fatalf("xargs inner checked peel of %v exhausted — a single legal PATH expansion must stay trusted", target)
		}
		if tk.cur != "/base/x" {
			t.Fatalf("xargs inner checked peel tracker cur = %q, want %q — the merged env op batch was applied TWICE (the pre-R27 double application materialized /base/x/x)", tk.cur, "/base/x")
		}
		// Byte budget discrimination (R28-Oracle-S1 / Reviewer R28 — the
		// pre-R28 arithmetic was off by two: base len max-4 expanded once
		// to max-2 and twice to exactly max, so BOTH applications stayed
		// legal and the second half discriminated nothing): the base is
		// sized so ONE expansion of <self>/x lands EXACTLY at
		// maxShellCommandBytes — legal — while a double application
		// reaches maxShellCommandBytes+2 and must degenerate. The exact
		// post-expansion tracker value and its trusted verdict are
		// pinned, never merely the absence of the placeholder.
		pad := strings.Repeat("a", maxShellCommandBytes-2) // +len("/x") == exactly the ceiling after one expansion
		tk2 := &wrapperPathTracker{cur: pad}
		_, _, _, exhausted2 := peelWrappersAndWrapperAliasesChecked(target, pad, callerIdentity{}, tk2)
		if exhausted2 {
			t.Fatalf("xargs inner checked peel at the exact byte ceiling exhausted — the double application pushed the single legal expansion past maxShellCommandBytes")
		}
		if tk2.cur != pad+"/x" || tk2.untrusted() {
			t.Fatalf("xargs inner checked peel tracker cur len = %d untrusted = %v at the exact byte ceiling, want len %d trusted — a legal single expansion landing exactly on maxShellCommandBytes materializes verbatim; only the double application overflows the budget", len(tk2.cur), tk2.untrusted(), maxShellCommandBytes)
		}
	})

	// ---- R27-4: execution-context-sensitive builtin exemption ----
	t.Run("R27-4 bare command/builtin/exec behind external execve contexts owe their identity to PATH", func(t *testing.T) {
		var untrusted envAssignments
		untrusted.ops = append(untrusted.ops, envOp{kind: 't', key: "PATH"})
		xargsProbe := func(argv []string) (stdinTarget, bool) {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{xw: &xargsWorkState{}}, false)
			return firstProgramTarget(targets)
		}
		// xargs starts its open-code-slot target through its own execvp —
		// bare command/exec spellings there are PATH lookups of external
		// executables, NEVER the shell builtins, so under the untrusted
		// PATH the consumer identity is unknowable.
		for _, argv := range [][]string{
			{"/usr/bin/xargs", "-I{}", "command", "/bin/sh", "-c", "{}"},
			{"/usr/bin/xargs", "-I{}", "exec", "/bin/sh", "-c", "{}"},
			{"/usr/bin/xargs", "-I{}", "builtin", "/bin/sh", "-c", "{}"},
		} {
			first, ok := xargsProbe(argv)
			if !ok || !first.exhausted {
				t.Fatalf("stdinProgramTargetsDialect(%v) inner target exhaustion = %v (first=%+v ok=%v) — xargs execvps its target directly, so a bare %q spelling is a PATH lookup of an external executable and never the shell builtin", argv, ok && first.exhausted, first, ok, argv[2])
			}
		}
		// The same direct-execution context arises INSIDE one shell-
		// dispatched chain the moment an external wrapper peeled: env
		// starts command through execvp, so the bare command behind it is
		// no longer the shell builtin. R28-Oracle-S1 / Reviewer R28: the
		// outer wrapper is the FIXED-PATH /usr/bin/env — the pre-R28 bare
		// `env` already exhausted as an unidentified bare head under the
		// untrusted PATH before the inner layer was ever judged, so both
		// the pre- and post-flip implementations passed the row without
		// the directExec bit mattering at all.
		targets := stdinProgramTargetsDialect([]string{"/usr/bin/env", "command", "/bin/sh"}, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
		exh := false
		for _, tg := range targets {
			if tg.exhausted {
				exh = true
			}
		}
		if !exh {
			t.Fatalf("stdinProgramTargetsDialect([env command /bin/sh]) under untrusted PATH not exhausted (targets=%v) — the bare command behind env resolves through execvp PATH lookup, never the shell builtin dispatch", targets)
		}
		// Positive controls: the TOP-LEVEL shell dispatch keeps the
		// builtin exemption exactly — command/exec are shell builtins
		// there and /bin/sh carries its own resolution.
		for _, argv := range [][]string{
			{"command", "/bin/sh"},
			{"exec", "/bin/sh"},
		} {
			pos := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
			first, ok := firstProgramTarget(pos)
			if !ok || first.exhausted || first.data || first.lang != "" {
				t.Fatalf("positive control broken: stdinProgramTargetsDialect(%v) under untrusted PATH first=%+v ok=%v — the shell-dispatched %q builtin exemption must survive exactly", argv, first, ok, argv[0])
			}
		}
		// Ordering pin (R28-Oracle-S1 / Reviewer R28 — the pre-R28 row used
		// the bare `env` head the CORE wrapper validation already refuses
		// before the alias loop, so the verdict never depended on the
		// loop's ordering at all): a symlinked bare name `myenv` — not a
		// statically recognized wrapper spelling — resolves through the
		// (trusted) pathEnv onto /usr/bin/env, so the checked peel CAN
		// adopt the alias only when the bare-head untrusted verdict does
		// NOT precede resolveHeadBase. The tracker carries the untrusted
		// PATH while the alias lookup itself rides the real temp-dir
		// search list.
		ordDir := t.TempDir()
		if err := os.Symlink("/usr/bin/env", filepath.Join(ordDir, "myenv")); err != nil {
			t.Fatalf("fixture symlink: %v", err)
		}
		ordTk := &wrapperPathTracker{cur: cmdSubPlaceholder}
		if ordHead, _, _, ordExhausted := peelWrappersAndWrapperAliasesChecked([]string{"myenv", "/bin/sh"}, ordDir, callerIdentity{}, ordTk); !ordExhausted {
			t.Fatalf("checked peel of [myenv /bin/sh] (symlink -> /usr/bin/env) under an untrusted tracker PATH exhausted = false (head=%v) — the bare head verdict must precede the alias rewrite adoption, or the PATH-segment hit launders the bare name into a slash-carrying wrapper the untrusted lookup never proved", ordHead)
		}
	})

	// ---- R27-5: cross-alias shared 32-step budget; single `--` ----
	t.Run("R27-5 wrapper aliases share the projection-wide 32-step budget", func(t *testing.T) {
		chain := func(layers int, final string) []string {
			argv := []string{}
			for i := 0; i < layers; i++ {
				argv = append(argv, "/usr/bin/env")
			}
			return append(argv, final)
		}
		exhaustedOf := func(argv []string) bool {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
			for _, tg := range targets {
				if tg.exhausted {
					return true
				}
			}
			return false
		}
		// 33 canonical /usr/bin/env layers ahead of /bin/sh exhaust the
		// 32-step budget.
		canon := append(chain(32, "/usr/bin/env"), "/bin/sh")
		if !exhaustedOf(canon) {
			t.Fatalf("control broken: 33 canonical /usr/bin/env wrapper layers before /bin/sh did NOT exhaust the 32-step budget")
		}
		// The SAME total layer count with a fixed-path GNU alias at layer
		// 32 must face the identical verdict — the canonical rewrite
		// recursion continues spending the pre-rewrite steps instead of
		// restarting the budget.
		alias := append(chain(31, "./genv"), "/usr/bin/env")
		alias = append(alias, "/bin/sh")
		if !exhaustedOf(alias) {
			t.Fatalf("31 /usr/bin/env layers + ./genv + /usr/bin/env + /bin/sh did NOT exhaust (same 33 total layers) — the canonical rewrite recursion restarted the step budget and laundered the chain into two under-budget halves")
		}
		// A symlinked fixed-path wrapper alias exercises the resolved-
		// wrapper recursion with the same shared budget.
		dir := t.TempDir()
		if err := os.Symlink("/usr/bin/env", filepath.Join(dir, "myenv")); err != nil {
			t.Fatalf("fixture symlink: %v", err)
		}
		t.Chdir(dir)
		res := append(chain(31, "./myenv"), "/usr/bin/env")
		res = append(res, "/bin/sh")
		if !exhaustedOf(res) {
			t.Fatalf("31 /usr/bin/env layers + ./myenv + /usr/bin/env + /bin/sh did NOT exhaust — the resolved-wrapper recursion restarted the step budget")
		}
		// Positive control: 29 + alias + 1 = 31 total layers stays INSIDE
		// the budget (the head must be discovered before the 32nd step
		// boundary) and confirms the fixed-path shell target.
		inside := append(chain(29, "./myenv"), "/usr/bin/env")
		inside = append(inside, "/bin/sh")
		if exhaustedOf(inside) {
			t.Fatalf("positive control broken: 29 /usr/bin/env + ./myenv + /usr/bin/env + /bin/sh (31 total layers) exhausted — the shared budget must still admit a chain the canonical spelling of the same length confirms")
		}
		// R28-Oracle-S1 / Reviewer R28: the in-budget positive control
		// must pin the confirmed shell target itself — a projection that
		// accidentally degenerated to nil/data would satisfy the bare
		// absence of an exhaustion bit without proving anything.
		within := stdinProgramTargetsDialect(inside, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		if len(within) != 1 || within[0].data || within[0].lang != "" {
			t.Fatalf("positive control broken: 31-layer in-budget chain projected %v — want exactly one non-data empty-language confirmed POSIX shell target", within)
		}
	})

	t.Run("R27-5 command consumes exactly one `--` option terminator", func(t *testing.T) {
		// `command -- -- /bin/sh`: the FIRST `--` is command's own option
		// terminator; the second `--` is a core-level reserved word that
		// costs one more wrapper step. The pre-R27 double consumption let
		// command swallow both for free. The discrimination rides the step
		// budget: command + `--` + 30 /usr/bin/env layers totals 32 steps
		// (exhausted) while the double-consumed shape fits 31.
		argv := []string{"command", "--", "--"}
		for i := 0; i < 30; i++ {
			argv = append(argv, "/usr/bin/env")
		}
		argv = append(argv, "/bin/sh")
		targets := stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		exh := false
		for _, tg := range targets {
			if tg.exhausted {
				exh = true
			}
		}
		if !exh {
			t.Fatalf("`command -- --` + 30 /usr/bin/env layers + /bin/sh did NOT exhaust — command swallowed BOTH `--` words, so only 31 of the 32 budgeted steps were ever spent")
		}
		// Positive control: a single `--` ahead of the same 30-layer chain
		// keeps one spare step and confirms the shell target.
		one := []string{"command", "--"}
		for i := 0; i < 30; i++ {
			one = append(one, "/usr/bin/env")
		}
		one = append(one, "/bin/sh")
		pos := stdinProgramTargetsDialect(one, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		first, ok := firstProgramTarget(pos)
		if !ok || first.exhausted || first.data || first.lang != "" {
			t.Fatalf("positive control broken: `command --` + 30 /usr/bin/env layers + /bin/sh first=%+v ok=%v — 31 peeled layers stay inside the budget", first, ok)
		}
	})

	// ---- R27-6: missing env/taskset/chrt operands fail closed ----
	t.Run("R27-6 trailing -p PID queries distinguish present/missing operands", func(t *testing.T) {
		// peelSingleWrapperArgs indexes are one past the option word in
		// every case — the arities mirror real taskset/chrt exactly.
		if next, ok := peelSingleWrapperArgs([]string{"chrt", "-p"}, "chrt"); next != 2 || ok {
			t.Fatalf("peelSingleWrapperArgs([chrt -p], chrt) = (%d, %v), want (2, false) — a trailing -p missing its PID operand is an unprovable arity, never the legitimate PID query", next, ok)
		}
		if next, ok := peelSingleWrapperArgs([]string{"taskset", "-p"}, "taskset"); next != 2 || ok {
			t.Fatalf("peelSingleWrapperArgs([taskset -p], taskset) = (%d, %v), want (2, false) — same missing-PID fail-closed verdict", next, ok)
		}
		if next, ok := peelSingleWrapperArgs([]string{"chrt", "-p", "1"}, "chrt"); next != 3 || !ok {
			t.Fatalf("control broken: peelSingleWrapperArgs([chrt -p 1], chrt) = (%d, %v), want (3, true) — the legitimate static-PID query keeps its exact no-inner-command shape", next, ok)
		}
		if next, ok := peelSingleWrapperArgs([]string{"taskset", "-p", "1"}, "taskset"); next != 3 || !ok {
			t.Fatalf("control broken: peelSingleWrapperArgs([taskset -p 1], taskset) = (%d, %v), want (3, true)", next, ok)
		}
		exhaustedOf := func(argv []string) bool {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
			for _, tg := range targets {
				if tg.exhausted {
					return true
				}
			}
			return false
		}
		for _, argv := range [][]string{
			{"chrt", "-p"},
			{"taskset", "-p"},
		} {
			if !exhaustedOf(argv) {
				t.Fatalf("stdinProgramTargetsDialect(%v) projected NO exhaustion verdict — the missing PID operand is an unprovable arity, never a nil data consumer", argv)
			}
		}
		// Positive control: the static-PID query remains a clean
		// no-inner-command projection (nil targets, no exhaustion).
		if exhaustedOf([]string{"chrt", "-p", "1"}) {
			t.Fatalf("control broken: stdinProgramTargetsDialect([chrt -p 1]) exhausted — the legitimate PID query must survive exactly")
		}
		if targets := stdinProgramTargetsDialect([]string{"chrt", "-p", "1"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false); len(targets) != 0 {
			t.Fatalf("control broken: stdinProgramTargetsDialect([chrt -p 1]) targets = %v — a PID query consumes no stream and projects no program target", targets)
		}
	})

	t.Run("R27-6 env missing operands and unknown options exhaust the checked projection", func(t *testing.T) {
		exhaustedOf := func(argv []string) bool {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
			for _, tg := range targets {
				if tg.exhausted {
					return true
				}
			}
			return false
		}
		for _, argv := range [][]string{
			{"/usr/bin/env", "--unset"},
			{"/usr/bin/env", "-u"},
			{"/usr/bin/env", "-C"},
			{"/usr/bin/env", "--bogus"},
			{"env", "--bogus"},
		} {
			if !exhaustedOf(argv) {
				t.Fatalf("stdinProgramTargetsDialect(%v) projected NO exhaustion verdict — env's missing-operand/unknown-option diagnostics ride the payload channel the pre-R27 checked projection discarded", argv)
			}
		}
		// The xargs inner target is the second checked entry: the same
		// truncated env must exhaust instead of falling into the default
		// empty-language shell fallback.
		xargsTargets := stdinProgramTargetsDialect([]string{"/usr/bin/xargs", "-I{}", "env", "--unset"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{xw: &xargsWorkState{}}, false)
		xExh := false
		for _, tg := range xargsTargets {
			if tg.exhausted {
				xExh = true
			}
		}
		if !xExh {
			t.Fatalf("stdinProgramTargetsDialect([/usr/bin/xargs -I{} env --unset]) inner targets = %v — the truncated env must never fall into the default empty-language shell fallback", xargsTargets)
		}
		// Positive control: a COMPLETE env --unset operand keeps the
		// confirmed fixed-path shell target.
		pos := stdinProgramTargetsDialect([]string{"env", "--unset", "HOME", "/bin/sh"}, 0, envAssignments{}, "/usr/bin:/bin", callerIdentity{}, false)
		first, ok := firstProgramTarget(pos)
		if !ok || first.exhausted || first.data || first.lang != "" {
			t.Fatalf("positive control broken: stdinProgramTargetsDialect([env --unset HOME /bin/sh]) first=%+v ok=%v — a complete env operand zone must keep the confirmed consumer", first, ok)
		}
		// Regression guard: the peelResolvedSegDepth error message for the
		// unknown option must survive — the nil-tracker peel keeps the
		// payload channel instead of preempting it with the exhaustion bit.
		if hit := peelResolvedDepth([]string{"env", "--bogus", "pig"}, 's', 0, callerIdentity{}); !strings.Contains(hit, "env unknown option") {
			t.Fatalf("control broken: peelResolvedDepth([env --bogus pig]) hit = %q — the precise env unknown-option diagnostic regressed", hit)
		}
	})
}

// TestGuard_V622_OracleR28Probes pins the Oracle R28 / Reviewer R28
// discriminating rows: the coprocess Name word scan, the lexical
// in-place registration of the hidden-eval scan, the direct-execution
// context across every external launch edge (xargs positional, flock
// argv form, watch -x operands, and the peeled shell `exec` builtin),
// the guard-side cross-check of the empty-head proof, and the
// isDynamicArg-keyed PATH trust verdicts. Every subtest references
// ONLY symbols already present on the pre-fix tree 1aa4752 (the
// collector replay, the peel entries, the tracker literal and the env
// op replay), so the complete file compiles there verbatim.
func TestGuard_V622_OracleR28Probes(t *testing.T) {

	// ---- R28-1: the coprocess Name word scans inside the frame ----
	t.Run("R28-1 coproc Name substitutions reach the hidden-eval scan", func(t *testing.T) {
		probe := func(text string) *subCollector {
			t.Helper()
			c := blankSubCollector()
			c.allowBind = true
			c.taintEvalTextWrites(text, 0)
			return c
		}
		// The pinned mvdan.cc/sh parser fills CoprocClause.Name whenever a
		// compound command follows a coproc word, and bash expands that
		// word — a substitution hiding a nested eval chain there is real
		// evaluation the replication's pre-scan counts. The pre-R28 frame
		// scanned ONLY x.Stmt, silently dropping the Name subtree the
		// pre-R27 whole-node walk visited.
		if name := probe(`coproc $(command -x eval) { :; }`); !name.taintedVars["PATH"] {
			t.Fatalf("`coproc $(command -x eval) { :; }` left PATH untainted (taintedVars=%v) — the CoprocClause.Name word never scanned, dropping an AST subtree the pre-R27 whole-node walk covered", name.taintedVars)
		}
		// Regression control: the body statement's redirection substitution
		// keeps scanning exactly like before.
		if body := probe(`coproc x { : >/dev/null/$(command -x eval); }`); !body.taintedVars["PATH"] {
			t.Fatalf("control broken: `coproc x { : >/dev/null/$(command -x eval); }` left PATH untainted (taintedVars=%v) — the coproc BODY scan regressed", body.taintedVars)
		}
		// Negative control: a static coproc name is inert.
		if plain := probe(`coproc x { :; }`); plain.taintedVars["PATH"] {
			t.Fatalf("control broken: `coproc x { :; }` polluted PATH (taintedVars=%v) — a static coproc carries no eval evaluation", plain.taintedVars)
		}
	})

	// ---- R28-2: lexical in-place registration inside the child frame ----
	t.Run("R28-2 hidden-eval registrations follow statement order inside the process frame", func(t *testing.T) {
		probe := func(text string) *subCollector {
			t.Helper()
			c := blankSubCollector()
			c.allowBind = true
			c.taintEvalTextWrites(text, 0)
			return c
		}
		// The backgrounded block's inner definition registers in the
		// CHILD frame the scan opens — the pre-R28 batch registration
		// stopped at the process bit and the inner statements never
		// re-entered a registration path, so the shadowed bare eval
		// inside the same child process was misread as the no-operand
		// builtin and re-parsed nothing.
		bg := probe(`$( { eval() { :; }; eval; } & )`)
		if !bg.taintedVars["PATH"] {
			t.Fatalf("`$( { eval() { :; }; eval; } & )` left PATH untainted (taintedVars=%v) — the definition inside a backgrounded compound block never registered in the child frame, so the shadowed eval was misread as the no-op builtin", bg.taintedVars)
		}
		if bg.funcNames["eval"] {
			t.Fatalf("backgrounded block's function definition leaked into the parent registry (funcNames=%v) — the child frame must roll its registrations back on exit", bg.funcNames)
		}
		// The FOREGROUND block with the pair reversed — call first,
		// definition second — re-parses NOTHING at the leading eval: the
		// definition has not executed yet when the call runs, exactly
		// like the R27-1 no-definition control. The pre-R28 pre-hoist
		// batch-registered the trailing definition BEFORE the scan and
		// shadowed the earlier call retroactively.
		if fwd := probe(`{ eval; eval() { :; }; }`); fwd.taintedVars["PATH"] {
			t.Fatalf("`{ eval; eval() { :; }; }` polluted PATH (taintedVars=%v) — the trailing definition hoisted over the block's own earlier eval call, retroactively shadowing a builtin invocation that ran unshadowed", fwd.taintedVars)
		}
		// Positive control: definition first, call second taints exactly
		// like the R27-1 pipe-component row.
		if bwd := probe(`{ eval() { :; }; eval; }`); !bwd.taintedVars["PATH"] {
			t.Fatalf("control broken: `{ eval() { :; }; eval; }` left PATH untainted (taintedVars=%v) — the definition-first shape must keep the shadowed maximal-pollution verdict", bwd.taintedVars)
		}
	})

	// ---- R28-3: direct-execution context covers every external launch edge ----
	t.Run("R28-3 external direct-exec edges validate bare builtin spellings against PATH", func(t *testing.T) {
		var untrusted envAssignments
		untrusted.ops = append(untrusted.ops, envOp{kind: 't', key: "PATH"})
		exhaustedOf := func(argv []string) bool {
			t.Helper()
			targets := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{xw: &xargsWorkState{}}, false)
			for _, tg := range targets {
				if tg.exhausted {
					return true
				}
			}
			return false
		}
		// Every one of these inner argvs is started by an external
		// program's execvp — the xargs positional target, flock's argv
		// form, and watch's -x operands — so the bare `command` spelling
		// is a PATH lookup of an external executable, NEVER the shell
		// builtin. The pre-R28 recursion re-entered with the default
		// shell-dispatch context and exempted it under the untrusted PATH.
		// The OUTER heads are fixed-path spellings so the verdict can
		// never arise from the bare-head PATH interception — only from
		// the inner layer's own validation context.
		for _, argv := range [][]string{
			{"/usr/bin/xargs", "command", "/bin/sh"},
			{"/usr/bin/flock", "/tmp/lk", "command", "/bin/sh"},
			{"/usr/bin/watch", "-x", "command", "/bin/sh"},
		} {
			// Errorf rather than Fatalf: every direct-exec edge owes its own
			// FAIL-first evidence on the parent tree, never just the first.
			if !exhaustedOf(argv) {
				t.Errorf("stdinProgramTargetsDialect(%v) under untrusted PATH projected NO exhaustion verdict — the outer program execvps this target directly, so the bare command spelling owes its identity to the unknowable PATH and enjoys no shell builtin exemption", argv)
			}
		}
		// The peeled shell `exec` builtin itself flips the context: it
		// launches its target through the OS PATH lookup rather than the
		// shell's builtin dispatch, so `exec command /bin/sh` faces the
		// same verdict even at the TOP-level shell dispatch.
		if !exhaustedOf([]string{"exec", "command", "/bin/sh"}) {
			t.Fatalf("stdinProgramTargetsDialect([exec command /bin/sh]) under untrusted PATH projected NO exhaustion verdict — the shell exec builtin never dispatches builtins, so the bare command behind it is an external PATH lookup")
		}
		// Positive controls: the shell-dispatched bare command keeps its
		// builtin exemption exactly, and the direct `exec /bin/sh` target
		// (no bare builtin spelling involved) stays a confirmed consumer.
		for _, argv := range [][]string{
			{"command", "/bin/sh"},
			{"exec", "/bin/sh"},
		} {
			targets := stdinProgramTargetsDialect(argv, 0, untrusted, "/usr/bin:/bin", callerIdentity{}, false)
			first, ok := firstProgramTarget(targets)
			if !ok || first.exhausted || first.data || first.lang != "" {
				t.Fatalf("positive control broken: stdinProgramTargetsDialect(%v) under untrusted PATH first=%+v ok=%v — the shell-dispatched shape keeps its exact verdict", argv, first, ok)
			}
		}
	})

	// ---- R28-4: the empty-head proof requires the checked peel's agreement ----
	t.Run("R28-4 peelProvesEmptyHead cross-checks the guard-side verified peel", func(t *testing.T) {
		// The index peel surrenders provenance (headIdx -1, exhausted =
		// false) exactly at the shapes the checked peel rejects, so the
		// pre-R28 helper read the missing-operand residue as a proven
		// absence and let the unknowable consumer vanish from the nested
		// summary. Every row here must answer FALSE — the consumer
		// identity is unknowable, never absent.
		for _, argv := range [][]string{
			{"taskset", "-p"},
			{"chrt", "-p"},
			{"timeout", "-k"},
			{"env", "--unset"},
		} {
			if peelProvesEmptyHead(argv, callerIdentity{}) {
				t.Fatalf("peelProvesEmptyHead(%v) = true — a trailing missing operand is an unprovable arity the checked peel rejects, never a proven empty command head", argv)
			}
		}
		// Positive controls: the static-PID query and the pure-assignment
		// prefix genuinely consume nothing — both peels complete empty
		// and non-exhausted exactly like before.
		for _, argv := range [][]string{
			{"taskset", "-p", "1"},
			{"chrt", "-p", "1"},
			{"FOO=1"},
			{"env", "FOO=1"},
		} {
			if !peelProvesEmptyHead(argv, callerIdentity{}) {
				t.Fatalf("positive control broken: peelProvesEmptyHead(%v) = false — the legitimate no-consumer shape must survive exactly", argv)
			}
		}
		// The dynamic option value keeps its non-empty residue either
		// way — residue, not absence (R27-2).
		if peelProvesEmptyHead([]string{"timeout", "-k", cmdSubPlaceholder}, callerIdentity{}) {
			t.Fatalf("control broken: peelProvesEmptyHead([timeout -k <dynamic>]) = true — the dynamic value is residue exactly like R27-2 pins")
		}
	})

	// ---- R28-5: the PATH trust verdict keys on every dynamic placeholder ----
	t.Run("R28-5 fully quoted dynamic PATH values are untrusted search lists", func(t *testing.T) {
		// The fully double-quoted dynamic placeholder cmdSubPlaceholderQuoted
		// proves the word BOUNDARY but never the CONTENT — a PATH carrying
		// it is an unknowable search list exactly like the unquoted form.
		// The pre-R28 verdicts keyed on the bare cmdSubPlaceholder
		// spelling alone and read the quoted fold as trusted.
		var ea envAssignments
		ea.ops = append(ea.ops, envOp{kind: 'a', key: "PATH", value: cmdSubPlaceholderQuoted})
		if !ea.pathUntrusted("/base") {
			t.Fatalf("envAssignments([a PATH=<quoted>]).pathUntrusted(/base) = false — a fully double-quoted dynamic PATH value is unknowable content exactly like the unquoted form")
		}
		tk := &wrapperPathTracker{cur: cmdSubPlaceholderQuoted}
		if !tk.untrusted() {
			t.Fatalf("wrapperPathTracker{cur: <quoted>}.untrusted() = false — the tracker verdict must key on every dynamic placeholder class")
		}
		if ci := (callerIdentity{pathEnv: cmdSubPlaceholderQuoted}); !ci.pathUntrusted() {
			t.Fatalf("callerIdentity{pathEnv: <quoted>}.pathUntrusted() = false — the identity-level sticky verdict must key on every dynamic placeholder class")
		}
		if expanded, ok := expandPathSelfRefs(cmdSubPlaceholderQuoted+"sub", cmdSubPlaceholderQuoted); ok {
			t.Fatalf("expandPathSelfRefs against a quoted-placeholder base expanded to %q — a degenerated base of ANY placeholder class must refuse further expansion (untrusted is sticky)", expanded)
		}
		if !pathSegUnvettable(cmdSubPlaceholderQuoted) {
			t.Fatalf("pathSegUnvettable(<quoted>) = false — a PATH segment carrying dynamic content of any class can never be a real lookup directory")
		}
		// Positive controls: the unquoted placeholder was ALWAYS
		// untrusted, and a static PATH stays trusted.
		if st := (&wrapperPathTracker{cur: cmdSubPlaceholder}); !st.untrusted() {
			t.Fatalf("control broken: wrapperPathTracker{cur: <unquoted>}.untrusted() = false")
		}
		if st := (&wrapperPathTracker{cur: "/usr/bin:/bin"}); st.untrusted() {
			t.Fatalf("control broken: wrapperPathTracker{cur: /usr/bin:/bin}.untrusted() = true — a static search list must stay trusted")
		}
		var static envAssignments
		static.ops = append(static.ops, envOp{kind: 'a', key: "PATH", value: "/usr/bin:/bin"})
		if static.pathUntrusted("/base") {
			t.Fatalf("control broken: static PATH assignment reads untrusted")
		}
	})
}
