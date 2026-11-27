package main

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// role_guards_v622_r21_test.go — Oracle R21 + Reviewer R21 audit regression
// tests.
//
// Coverage contract (one discriminating row per root cause):
//
//	R21-M1: a static eval's binding replication validates the COMPLETE
//	  wrapper chain — no slash-carrying wrapper or eval head, only legal
//	  non-query options on real dialect builtins, and no array-subscript
//	  write posing as a plain scalar.
//	R21-M2: the write definition is unified — Bash named-write builtins
//	  (printf -v/read/getopts/unset) replay as taint exactly like the
//	  pre-scan counts them, and a root-level static eval inside an
//	  eval-operand statement is never skipped.
//	R21-M3: scope-aware environment accumulation — subshell assignments
//	  bind within the same subshell and die with it, background compound
//	  subtrees propagate the child scope downward, and conditional writes
//	  never override outer consumers exactly.
//	R21-M5: depth-exhausted stdin targets block explicitly at every final
//	  consumption point — never a zero-value "known POSIX shell" verdict.
//	R21-xargs: nested xargs append-mode recursion stays correct (and the
//	  work budget caps fan-out) — behavior pin for the recursion merge.
//	R21-PATH-budget: chained $PATH self-reference expansion never
//	  materializes beyond maxShellCommandBytes — the replay yields the
//	  untrusted placeholder instead of a giant allocation or a truncated
//	  short PATH.
//
// Every discriminating row is FAIL-first on the pre-fix tree ce35f40: the
// probes reference only symbols that exist there verbatim (the collectors,
// the stdin projection helpers, the depth constants and the placeholder
// sentinels), so the file compiles unchanged on that tree (`go vet` rc=0)
// and the failures reproduce the audit findings directly.

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
	t.Run("R21-M3 childless env process never rewrites the parent view", func(t *testing.T) {
		const pathA = "/usr/bin:/bin"
		const pathB = "/usr/local/sbin"
		envs, ok, _ := scriptAllowsLocalShellStdinPrepareDialect("/usr/bin/env PATH="+pathB+"; /bin/bash", false, envAssignments{}, pathA, callerIdentity{})
		if ok && len(envs) > 0 {
			got := envs[len(envs)-1].effectivePATHFrom(pathA)
			if got == pathB {
				t.Fatalf("/usr/bin/env PATH=B; /bin/bash consumer effective PATH = %q — env spawns its own process and can never modify the calling shell", got)
			}
		}
	})

	// ---- R21-M5: depth exhaustion blocks at the final consumption point ----
	t.Run("R21-M5 here-string screening blocks an exhausted target explicitly", func(t *testing.T) {
		segs, ok := parseSubagentShellASTEnv("bash", 0, false, true, nil, callerIdentity{})
		if !ok || len(segs) != 1 {
			t.Fatalf("parse of plain bash segment failed: ok=%v segs=%v", ok, segs)
		}
		exh := collectStdinSegTargets(segs[0], shellSplitMaxDepth-1, envAssignments{}, envAssignments{}, "", false, callerIdentity{})
		hasExhausted := false
		for _, tg := range exh {
			if tg.exhausted {
				hasExhausted = true
			}
		}
		if !hasExhausted {
			t.Fatalf("collectStdinSegTargets at depth=shellSplitMaxDepth-1 yields %v targets with NO exhaustion marker — the R20 boundary shape itself regressed", exh)
		}
		hitExh := screenHereStringTargetsDepth("printf tag{red,blue}", exh, 's', 0, callerIdentity{})
		if hitExh != depthExceededHit {
			t.Fatalf("screenHereStringTargetsDepth(exhausted target) = %q, want %q — an unidentified consumer is never a known POSIX shell: the payload must face an explicit depth block instead of the dash-default re-parse", hitExh, depthExceededHit)
		}
		ctrl := collectStdinSegTargets(segs[0], shellSplitMaxDepth-2, envAssignments{}, envAssignments{}, "", false, callerIdentity{})
		hitCtrl := screenHereStringTargetsDepth("printf tag{red,blue}", ctrl, 's', 0, callerIdentity{})
		if hitCtrl == depthExceededHit {
			t.Fatalf("control broken: one depth level earlier the KNOWN bash consumer verdict is %q — the exhausted branch must be distinguishable from the ordinary per-language screen", hitCtrl)
		}
		if hitCtrl == "" {
			t.Fatalf("control broken: the brace-fixture payload into a known bash consumer screens clean — the bash dialect continuation regressed")
		}
	})

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
