package main

import (
	"fmt"
	"os"
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
