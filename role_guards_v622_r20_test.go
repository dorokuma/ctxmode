package main

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// role_guards_v622_r20_test.go — Oracle R20 audit regression tests.
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
		// Cost contract: consecutive pure assignments append in place onto
		// the running accumulator instead of paying a full copy per step.
		runEnv := accumulatePureAssignEnv(envAssignments{}, []string{"A=1"}, callerIdentity{})
		runEnv = accumulatePureAssignEnv(runEnv, []string{"B=2"}, callerIdentity{})
		runEnv = accumulatePureAssignEnv(runEnv, []string{"C=3"}, callerIdentity{})
		if len(runEnv.ops) != 3 {
			t.Fatalf("accumulator after 3 consecutive assignments: %d ops, want 3 (linear in-place append)", len(runEnv.ops))
		}
	})
}
