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
//	R20-S2: the eval depth-budget fixture is LINEAR in length and stays
//	  within maxShellCommandBytes.
//	Observation: consecutive pure assignments no longer pay quadratic copy
//	  cost — target snapshots cap their backing array so later appends
//	  cannot mutate a handed-out ops slice.
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

	// ---- R20-S2: the depth-budget fixture is linear and budget-sized ----
	t.Run("R20-S2 linear-length eval nesting reproduces the shallow/deep boundary within maxShellCommandBytes", func(t *testing.T) {
		// Bare-word nesting keeps growth strictly LINEAR: eval joins its
		// operands with single spaces before re-parsing, so
		// `eval eval eval zzleaf=1` peels one `eval` per level — each level
		// costs exactly 5 bytes and the leaf write still sits N re-parses
		// deep, reproducing the same shallow-exact/deep-cutoff boundary the
		// exponential backslash fixture proved without ever approaching
		// maxShellCommandBytes (25 levels = ~130 bytes vs 65536).
		nestLinear := func(leaf string, levels int) string {
			inner := leaf
			for i := 0; i < levels; i++ {
				inner = "eval " + inner
			}
			return inner
		}
		scanLeaf := func(levels int) (int, int) {
			src := nestLinear("zzleaf=1", levels)
			p := syntax.NewParser(syntax.Variant(syntax.LangBash))
			f, err := p.Parse(strings.NewReader(src), "")
			if err != nil {
				t.Fatalf("parse %d levels: %v", levels, err)
			}
			writes, _ := preScanVarMutations(f, false)
			return writes["zzleaf"], len(src)
		}
		shallow, shallowLen := scanLeaf(3)
		if shallowLen > maxShellCommandBytes {
			t.Fatalf("shallow fixture length = %d > maxShellCommandBytes %d — the budget fixture must stay a legal command text", shallowLen, maxShellCommandBytes)
		}
		if shallow != 1 {
			t.Fatalf("control broken: 3-level linear nested eval leaf write count = %d, want 1 — shallow nesting replays exactly", shallow)
		}
		deep, deepLen := scanLeaf(peelChainMaxDepth + 1)
		if deepLen > maxShellCommandBytes {
			t.Fatalf("deep fixture length = %d > maxShellCommandBytes %d — the depth-budget proof must not require input sizes the command-shape gate rejects outright", deepLen, maxShellCommandBytes)
		}
		if deep != 0 {
			t.Fatalf("peelChainMaxDepth+1-level nested eval leaf write count = %d, want 0 — beyond the depth budget the leaf is never parsed", deep)
		}
	})

	// ---- Observation: consecutive pure assignments stay linear, snapshots stay immutable ----
	t.Run("R20-OBS merged env ops cap their backing array; later appends cannot mutate snapshots", func(t *testing.T) {
		// Production-shaped proof: accumulate consecutive pure assignments
		// the way the stdin scans do, take the target snapshot in the
		// middle, then keep appending — the handed-out snapshot must be
		// capacity-frozen so no later append can mutate it, and its ops
		// must still read exactly what it captured.
		one := envAssignments{}
		one.addAssign("A=1")
		runEnv := accumulatePureAssignEnv(envAssignments{}, []string{"A=1"}, callerIdentity{})
		if len(runEnv.ops) != 1 {
			t.Fatalf("accumulator after 1 assignment: %d ops, want 1", len(runEnv.ops))
		}
		snap := runEnv.merged(one) // the shape a target receives
		if len(snap.ops) != cap(snap.ops) {
			t.Fatalf("merged snapshot len %d != cap %d — a handed-out target env must be capacity-frozen so later appends reallocate instead of clobbering it", len(snap.ops), cap(snap.ops))
		}
		runEnv = accumulatePureAssignEnv(runEnv, []string{"B=2"}, callerIdentity{})
		runEnv = accumulatePureAssignEnv(runEnv, []string{"C=3"}, callerIdentity{})
		if len(runEnv.ops) != 3 {
			t.Fatalf("accumulator after 3 assignments: %d ops, want 3 (linear in-place append)", len(runEnv.ops))
		}
		if len(snap.ops) != 2 || snap.ops[0].key != "A" || snap.ops[1].key != "A" {
			t.Fatalf("snapshot mutated by later accumulation: ops=%v", snap.ops)
		}
		// A subprocess-shaped argv must never join the accumulation at all
		// (R20-Oracle-M3 rides the same helper).
		before := len(runEnv.ops)
		runEnv = accumulatePureAssignEnv(runEnv, []string{"/usr/bin/env", "D=4"}, callerIdentity{})
		if len(runEnv.ops) != before {
			t.Fatalf("/usr/bin/env D=4 joined the parent accumulation — env spawns its own process and cannot re-bind the calling shell")
		}
	})
}
