package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// === Merged from zz_r2fix_test.go ===

// ---------------------------------------------------------------------------
// R2-3: $(pwd) static bind — foreign cwd and cd-switch invalidation
// ---------------------------------------------------------------------------

// A bare $(pwd) assignment must bind the caller's SCREENED cwd so a later
// "$D/mytool" resolves to <caller-cwd>/mytool (never a planted pig in a
// foreign directory), and ANY cd/chdir/pushd/popd in the same script keeps
// $(pwd) a dynamic placeholder so the runtime value cannot be laundered.
func TestGuard_R2_PwdCwdBind(t *testing.T) {
	foreign := t.TempDir()
	// A non-/tmp trusted cwd whose .venv/bin really exists: only a
	// CORRECT $(pwd) static bind can resolve PATH="$D/.venv/bin:$PATH"
	// onto it (R6 SF-3 positive row).
	positiveCwd := filepath.Join(withTestTrustedHome(t), "proj")
	if err := os.MkdirAll(filepath.Join(positiveCwd, ".venv", "bin"), 0755); err != nil {
		t.Fatalf("mkdir positiveCwd venv: %v", err)
	}
	// A planted "pig" under the foreign dir: if $(pwd) binds the process cwd
	// instead of caller.cwd, "D=$(pwd); $D/pig" passes the guard on the wrong
	// directory and runs the planted binary. The R4 spelling uses a symlink
	// alias (mytool -> pig) so the typed name is not itself a blocked head:
	// only a CORRECT $(pwd) bind resolves to the planted target.
	writeTestExecutable(t, filepath.Join(foreign, "pig"), 0755)
	if err := os.Symlink(filepath.Join(foreign, "pig"), filepath.Join(foreign, "mytool")); err != nil {
		t.Fatalf("symlink mytool -> pig: %v", err)
	}

	cases := []struct {
		name string
		cmd  string
		cwd  string
		want string
	}{
		// Positive bind (R6 SF-3): a non-/tmp trusted cwd + a constant
		// command head keeps D=$(pwd) bound to caller.screenCwd(), so
		// PATH="$D/.venv/bin:$PATH" resolves a REAL venv pig under the
		// trusted dir and the segment passes the env-PATH audit cleanly
		// (ALLOW — not a silent false-positive: without the bind the
		// PATH= value stays dynamic and fails closed).
		{"pathA positive bind", `D=$(pwd); PATH="$D/.venv/bin:$PATH" ls`, positiveCwd, "ALLOW"},
		// Path A: guard cwd differs from process cwd — $(pwd) must still bind
		// the CALL's directory so the head resolves against it.
		// R5 MF-2: a non-constant command head anywhere in the script
		// conservatively taints PWD/OLDPWD, so the $(pwd) bind is dropped
		// and the dynamic head fails closed — the same block, earlier.
		// (The PATH row below still pins the positive foreign-cwd bind.)
		{"pathA foreign cwd pig", `D=$(pwd); "$D/mytool"`, foreign, "dynamic command head"},
		{"pathA foreign cwd PATH", `D=$(pwd); PATH="$D/.venv/bin:$PATH" pig`, foreign, "env PATH"},
		// Path B: a cd inside the script re-bases the expansion — the bind is
		// unknowable, so $(pwd) must stay dynamic and fail closed. A for-loop
		// enum head smuggling the switch (`for X in cd; do $X <evil>`) must
		// invalidate the bind the same way (R4 MF-2).
		{"pathB cd pig", `cd /tmp/evil; D=$(pwd); "$D/pig"`, "", "dynamic command head"},
		{"pathB cd PATH", `cd /tmp/evil; D=$(pwd); PATH="$D/.venv/bin:$PATH" pig`, "", "env PATH"},
		{"pathB for-enum cd", `for X in cd; do $X ` + foreign + `; done; D=$(pwd); "$D/mytool"`, "", "dynamic command head"},
		{"pathB for-enum eval", `for X in eval; do $X "cd ` + foreign + `"; done; D=$(pwd); "$D/mytool"`, "", "dynamic command head"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, tc.cwd)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q, cwd=%q) = %q, want substring %q", tc.cmd, tc.cwd, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// R2-4: env -C / --chdir — inner head + relative PATH resolve under chdir'd cwd
// ---------------------------------------------------------------------------

// `env -C DIR` must re-anchor the inner command's resolution: a relative head
// like ./mytool joins onto DIR (not the outer cwd), and a relative PATH
// segment env itself carries (.venv/bin) resolves under DIR — in EITHER
// option order. An empty or dynamic DIR fails closed rather than falling
// back to the outer directory.
func TestGuard_R2_EnvChdirCwd(t *testing.T) {
	evil := t.TempDir()
	writeTestExecutable(t, filepath.Join(evil, "mytool"), 0755)
	venvBin := filepath.Join(evil, ".venv", "bin")
	if err := os.MkdirAll(venvBin, 0755); err != nil {
		t.Fatalf("mkdir venvBin: %v", err)
	}
	writeTestExecutable(t, filepath.Join(venvBin, "pig"), 0755)

	argvCases := []struct {
		name string
		argv []string
		want string
	}{
		{"env -C abs ./mytool", []string{"env", "-C", evil, "./mytool"}, ""},
		{"env --chdir=abs ./mytool", []string{"env", "--chdir=" + evil, "./mytool"}, ""},
		{"env -C abs PATH=.venv/bin pig", []string{"env", "-C", evil, "PATH=.venv/bin:/usr/bin", "pig"}, "env PATH"},
		{"PATH=.venv/bin env -C abs pig", []string{"env", "PATH=.venv/bin:/usr/bin", "-C", evil, "pig"}, "env PATH"},
		// A dynamic or empty chdir target fails closed: the inner relative head
		// must NOT fall back to the outer cwd.
		{"env -C empty ./mytool", []string{"env", "-C", "", "./mytool"}, "env -C"},
	}
	for _, tc := range argvCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", argv: tc.argv}, "")
			if tc.want == "" {
				if got != "ALLOW" {
					t.Fatalf("rtGuardCwd(%v) = %q, want ALLOW", tc.argv, got)
				}
			} else if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%v) = %q, want substring %q", tc.argv, got, tc.want)
			}
		})
	}

	// Shell-text spellings through the segment peel carry the same rule.
	shellCases := []struct {
		name string
		cmd  string
		want string
	}{
		{"shell env -C ./mytool", `env -C ` + evil + ` ./mytool`, ""},
		{"shell env -C PATH pig", `env -C ` + evil + ` PATH=".venv/bin:$PATH" pig`, "env PATH"},
		{"shell PATH env -C pig", `env PATH=".venv/bin:$PATH" -C ` + evil + ` pig`, "env PATH"},
		// $(pwd) is a dynamic placeholder operand — env -C must fail closed.
		{"shell env -C $(pwd) ./mytool", `env -C "$(pwd)" ./mytool`, "env"},
	}
	for _, tc := range shellCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if tc.want == "" {
				if got != "ALLOW" {
					t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
				}
			} else if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want substring %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// R2-5: dot-prefixed relative head — `.foo` is a path, not a PATH lookup
// ---------------------------------------------------------------------------

// A head like `.foo` names a file in the caller's cwd (looksLikePath), never a
// PATH entry — a planted `<cwd>/.foo -> /tmp/hc` must hit the same untrusted
// path verdict as `/tmp/hc`, not silently exec the symlink target.
func TestGuard_R2_DotHeadIsPath(t *testing.T) {
	cwd := t.TempDir()
	// `.foo` is a dot-prefixed path spelling (looksLikePath) whose symlink
	// target is a planted hc — the path-form head must fail the trusted
	// canonical-slot admission, exactly like `/tmp/hc`.
	decoyTarget := filepath.Join(cwd, "hc")
	writeTestExecutable(t, decoyTarget, 0755)
	if err := os.Symlink(decoyTarget, filepath.Join(cwd, ".foo")); err != nil {
		t.Fatalf("symlink .foo -> hc: %v", err)
	}
	got := rtGuardCwd(t, rtCase{id: "dothead", role: "worker", argv: []string{".foo", "send", "t42", "ok"}}, cwd)
	if !strings.Contains(got, "untrusted path binary") {
		t.Fatalf(".foo -> hc head = %q, want untrusted path binary", got)
	}
}

// ---------------------------------------------------------------------------
// R2-6: toolchain hc/herdr-core shadow heads — block .venv/bin, keep .local/bin
// ---------------------------------------------------------------------------

// A planted hc/herdr-core in a user-writable toolchain dir shadows the real
// report-channel binary: .venv/bin/hc, node_modules/.bin/hc and
// ~/.cargo/bin/hc all fail closed, while the legitimate
// <trustedHome>/.local/bin/hc symlink to herdr-core stays free.
func TestGuard_R2_ToolchainHcShadow(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	// The workspace and stub must live under fakeHome: a /tmp workspace or
	// /tmp stub trips the /tmp-scratch block before the planted-shadow rule
	// the test exists to pin (R4).
	cwd := filepath.Join(fakeHome, "proj")
	if err := os.MkdirAll(cwd, 0755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	venvBin := filepath.Join(cwd, ".venv", "bin")
	nmBin := filepath.Join(cwd, "node_modules", ".bin")
	cargoBin := filepath.Join(fakeHome, ".cargo", "bin")
	localBin := filepath.Join(fakeHome, ".local", "bin")
	for _, d := range []string{venvBin, nmBin, cargoBin, localBin} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	stubDir := filepath.Join(fakeHome, "stubdir")
	if err := os.MkdirAll(stubDir, 0755); err != nil {
		t.Fatalf("mkdir stubDir: %v", err)
	}
	stub := filepath.Join(stubDir, "herdr-core-stub")
	writeTestExecutable(t, stub, 0755)
	for _, dir := range []string{venvBin, nmBin, cargoBin} {
		for _, name := range []string{"hc", "herdr-core"} {
			p := filepath.Join(dir, name)
			if err := os.Symlink(stub, p); err != nil {
				t.Fatalf("symlink %s -> %s: %v", p, stub, err)
			}
		}
	}
	// A symlink alias whose TARGET basename is the forbidden head must hit
	// the same planted-shadow verdict as the literal name (R4 MF-4 / R5
	// SF-6): <cargoBin>/myhc -> <cargoBin>/hc and myenv -> <cargoBin>/env
	// both smuggle the shadow past a typed-name-only check. The targets
	// are REAL files inside the toolchain dir (the planted-shadow rule
	// judges the resolved target's own directory) — the generic hc
	// symlink the loop above planted under cargoBin is removed first.
	if err := os.Remove(filepath.Join(cargoBin, "hc")); err != nil {
		t.Fatalf("remove symlink cargoBin/hc: %v", err)
	}
	for _, name := range []string{"hc", "env"} {
		writeTestExecutable(t, filepath.Join(cargoBin, name), 0755)
	}
	if err := os.Symlink(filepath.Join(cargoBin, "hc"), filepath.Join(cargoBin, "myhc")); err != nil {
		t.Fatalf("symlink myhc -> hc: %v", err)
	}
	if err := os.Symlink(filepath.Join(cargoBin, "env"), filepath.Join(cargoBin, "myenv")); err != nil {
		t.Fatalf("symlink myenv -> env: %v", err)
	}
	// The legitimate install slot <trustedHome>/.local/bin/hc resolves to a
	// real herdr-core inside the SAME trusted dir — the canonical admission
	// accepts it exactly like the production /root/.local/bin layout.
	realHc := filepath.Join(localBin, "herdr-core")
	writeTestExecutable(t, realHc, 0755)
	if err := os.Symlink(realHc, filepath.Join(localBin, "hc")); err != nil {
		t.Fatalf("symlink .local/bin/hc -> herdr-core: %v", err)
	}

	// Block: relative PATH segments that resolve inside the project tree.
	for _, seg := range []string{".venv/bin", "node_modules/.bin"} {
		pathEnv := seg + ":" + os.Getenv("PATH")
		t.Setenv("PATH", pathEnv)
		got := rtGuardCwd(t, rtCase{id: "relpath-" + seg, role: "worker", argv: []string{"hc", "send", "t42", "ok"}}, cwd)
		if !strings.Contains(got, "shadow binary") && !strings.Contains(got, "untrusted path binary") {
			t.Fatalf("relative PATH %q hc head = %q, want shadow/untrusted binary block", seg, got)
		}
	}
	// Block: absolute user toolchain dir (~/.cargo/bin).
	t.Setenv("PATH", cargoBin+":"+os.Getenv("PATH"))
	if got := rtGuardCwd(t, rtCase{id: "cargobin-hc", role: "worker", argv: []string{"hc", "send", "t42", "ok"}}, cwd); !strings.Contains(got, "shadow binary") && !strings.Contains(got, "untrusted path binary") {
		t.Fatalf("~/.cargo/bin hc head = %q, want shadow/untrusted binary block", got)
	}
	// Allow: the real <trustedHome>/.local/bin/hc install slot.
	t.Setenv("PATH", localBin+":"+os.Getenv("PATH"))
	if got := rtGuardCwd(t, rtCase{id: "localbin-hc", role: "worker", argv: []string{"hc", "send", "t42", "ok"}}, cwd); got != "ALLOW" {
		t.Fatalf("trusted .local/bin hc head = %q, want ALLOW", got)
	}
	// Block: the symlink-alias smuggle — myhc -> <cargoBin>/hc under the
	// cargo toolchain dir is a planted shadow whose resolved target lives
	// INSIDE the user toolchain dir (R5 SF-6 exact assertion).
	t.Setenv("PATH", cargoBin+":"+os.Getenv("PATH"))
	if got := rtGuardCwd(t, rtCase{id: "cargobin-myhc", role: "worker", argv: []string{"myhc", "send", "t42", "ok"}}, cwd); !strings.Contains(got, "planted shadow binary") {
		t.Fatalf("~/.cargo/bin myhc -> hc head = %q, want planted shadow binary block", got)
	}
	// Block: myenv -> <cargoBin>/env — the resolved env target lives in
	// the same user toolchain dir, so even a no-op operand run is a
	// planted shadow (R5 SF-6: the resolved-target rule fires before the
	// env re-peel can launder the name).
	if got := rtGuardCwd(t, rtCase{id: "cargobin-myenv", role: "worker", argv: []string{"myenv", "echo", "ok"}}, cwd); !strings.Contains(got, "planted shadow binary") {
		t.Fatalf("~/.cargo/bin myenv -> env head = %q, want planted shadow binary block", got)
	}
	// Block: an xargs target re-anchored by env -C into a foreign dir must
	// not smuggle a planted ctxmode — the peeled env ops seed the target's
	// own resolution caller (R4 MF-2). The file is named myctxmode (a
	// symlink to the screened binary's own basename) so the hit lands on
	// the resolved-target rule, never the typed name.
	evil := filepath.Join(fakeHome, "evil")
	if err := os.MkdirAll(evil, 0755); err != nil {
		t.Fatalf("mkdir evil: %v", err)
	}
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if err := os.Symlink(selfExe, filepath.Join(evil, "myctxmode")); err != nil {
		t.Fatalf("symlink myctxmode -> selfExe: %v", err)
	}
	if got := rtGuardCwd(t, rtCase{
		id: "xargs-env-C-myctxmode", role: "worker",
		cmd: `printf '--hc-gate\nsend\nt42\nhi\n' | xargs env -C ` + evil + ` ./myctxmode`,
	}, cwd); !strings.Contains(got, "xargs ctxmode --hc-gate") {
		t.Fatalf("xargs env -C <evil> ./myctxmode = %q, want xargs ctxmode --hc-gate block", got)
	}
	// The find -exec twin: {} feeds a path operand, the env -C re-anchor
	// still moves the target's resolution into <evil>.
	if got := rtGuardCwd(t, rtCase{
		id: "find-exec-env-C-myctxmode", role: "worker",
		cmd: `find . -exec env -C ` + evil + ` ./myctxmode {} \;`,
	}, cwd); !strings.Contains(got, "find -exec ctxmode --hc-gate") {
		t.Fatalf("find -exec env -C <evil> ./myctxmode = %q, want find -exec ctxmode --hc-gate block", got)
	}
	// R2 SF-1: `env -C <dir> hc send t42 "$x"` never rewrites — a cwd-
	// changing wrapper surrenders provenance exactly like an env -i.
	g := guardCall{subagent: true}
	prep := g.prepareCtxRunArgv([]string{"env", "-C", cwd, "hc", "send", "t42", "$x"}, "")
	if prep.rule == "" && strings.Contains(strings.Join(prep.execArgv, " "), "--hc-gate") {
		t.Fatalf("env -C hc send rewritten to --hc-gate: %v", prep.execArgv)
	}
}

// ---------------------------------------------------------------------------
// R2-7: bash -c re-review under the bash dialect
// ---------------------------------------------------------------------------

// A `bash -c` payload may carry bash-only syntax ($'...', [[ ... ]], (( )))
// that a POSIX re-review would reject — the second pass must use
// guardShellSubagentDepthBash so a legal rewrite is not killed and a nested
// `hc send` inside the bash script still reaches the gate.
func TestGuard_R2_BashDialectReReview(t *testing.T) {
	g := guardCall{subagent: true}
	// A benign bash-only script must pass both prepare and re-review.
	prep := g.prepareCtxRunArgv([]string{"bash", "-c", `x=$'a\nb'; [[ $x == *b* ]] && echo ok`}, "")
	if prep.rule != "" {
		t.Fatalf("bash-only script re-review = %q: %q, want pass", prep.rule, prep.detail)
	}
	// A dynamic hc send hidden inside bash syntax must still rewrite and
	// screen under the bash dialect (the rewritten --hc-gate argv then faces
	// the same prepare→guard round the POSIX path uses).
	prep = g.prepareCtxRunArgv([]string{"bash", "-c", `hc send t42 "$x"`}, "")
	if prep.rule != "" {
		t.Fatalf("bash -c dynamic hc send = %q: %q, want prepared", prep.rule, prep.detail)
	}
	// R3 SF-3: the rewritten execArgv must carry the --hc-gate leaf the
	// provenance admits (never a raw hc head left for the runtime).
	joined := strings.Join(prep.execArgv, " ")
	if !strings.Contains(joined, "--hc-gate") {
		t.Fatalf("bash -c rewrite missing --hc-gate: %v", prep.execArgv)
	}
	// The combined bash-only + dynamic-send spelling stays rewritable too:
	// $'...' and [[ ... ]] are legal under the bash dialect while "$x"
	// still lands in the --hc-gate text slot.
	prep = g.prepareCtxRunArgv([]string{"bash", "-c", `x=$'a\nb'; [[ $x == *b* ]] && hc send t42 "$x"`}, "")
	if prep.rule != "" {
		t.Fatalf("bash -c combined dynamic hc send = %q: %q, want prepared", prep.rule, prep.detail)
	}
	if !strings.Contains(strings.Join(prep.execArgv, " "), "--hc-gate") {
		t.Fatalf("combined rewrite missing --hc-gate: %v", prep.execArgv)
	}
}

// ---------------------------------------------------------------------------
// R3-MF-2a: env -C <evil> ./mysh -c pig — inner shell head resolves under the
// chdir'd directory, so a planted mysh -> /bin/sh in <evil> can never pose as
// the peeled -c interpreter (alias-promoted wrappers keep the -c payload
// screened; a planted pig argv head still blocks).
// ---------------------------------------------------------------------------

func TestGuard_R3_EnvChdirInnerShellAlias(t *testing.T) {
	evil := t.TempDir()
	// mysh -> /bin/sh inside the foreign dir: `env -C <evil> ./mysh -c pig`
	// must NOT let the chdir'd shell head smuggle the pig payload past the
	// inner -c screen.
	if err := os.Symlink("/bin/sh", filepath.Join(evil, "mysh")); err != nil {
		t.Fatalf("symlink mysh -> /bin/sh: %v", err)
	}
	got := rtGuardCwd(t, rtCase{id: "env-C-mysh-c", role: "worker", argv: []string{"env", "-C", evil, "./mysh", "-c", "pig"}}, "")
	if !strings.Contains(got, "pig") {
		t.Fatalf("env -C <evil> ./mysh -c pig = %q, want pig block", got)
	}
}

// ---------------------------------------------------------------------------
// R3-MF-2b: relative `env -C sub` must not double-join onto itself (sub/sub)
// — the inner ./mytool resolves under <cwd>/sub exactly once.
// ---------------------------------------------------------------------------

func TestGuard_R3_EnvChdirRelativeNoDoubleJoin(t *testing.T) {
	cwd := t.TempDir()
	sub := filepath.Join(cwd, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	writeTestExecutable(t, filepath.Join(sub, "mytool"), 0755)
	// A benign tool under the chdir'd sub: `env -C sub ./mytool` must pass
	// (the cwd re-anchors to <cwd>/sub, NOT <cwd>/sub/sub).
	got := rtGuardCwd(t, rtCase{id: "env-C-sub-mytool", role: "worker", argv: []string{"env", "-C", "sub", "./mytool"}}, cwd)
	if got != "ALLOW" {
		t.Fatalf("env -C sub ./mytool = %q, want ALLOW", got)
	}
	// A planted pig under the same sub still blocks through the relative -C.
	writeTestExecutable(t, filepath.Join(sub, "pig"), 0755)
	got = rtGuardCwd(t, rtCase{id: "env-C-sub-pig", role: "worker", argv: []string{"env", "-C", "sub", "./pig"}}, cwd)
	if !strings.Contains(got, "pig") {
		t.Fatalf("env -C sub ./pig = %q, want pig block", got)
	}
}

// ---------------------------------------------------------------------------
// R3-MF-2c: env -C <evil> ./mysh + stdin "pig" — the stdin payload screen
// sees the chdir'd shell head, so the streamed program still blocks.
// ---------------------------------------------------------------------------

func TestGuard_R3_EnvChdirStdinTarget(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	// The workspace, sub dir and stub stay under fakeHome — a /tmp
	// workspace or /tmp symlink target trips the /tmp block before the
	// env -C re-anchor the test pins (R4).
	cwd := filepath.Join(fakeHome, "proj")
	sub := filepath.Join(cwd, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.Symlink("/bin/sh", filepath.Join(sub, "mysh")); err != nil {
		t.Fatalf("symlink mysh -> /bin/sh: %v", err)
	}
	// A relative `env -C sub` re-anchors the inner ./mysh onto <cwd>/sub
	// exactly once (no doubled join); the streamed pig program still
	// blocks (R4 MF-1, R2 SF-1).
	got := rtGuardCwd(t, rtCase{
		id: "env-C-sub-mysh-stdin", role: "worker",
		argv:  []string{"env", "-C", "sub", "./mysh"},
		stdin: "pig",
	}, cwd)
	if !strings.Contains(got, "pig") {
		t.Fatalf("env -C sub ./mysh stdin=pig = %q, want pig block", got)
	}
}

// ---------------------------------------------------------------------------
// R3-MF-3: builtin/command-prefixed pushd and eval-cd invalidate $(pwd)
// static binds — D=$(pwd) can never bind a static cwd after a hidden
// directory switch.
// ---------------------------------------------------------------------------

func TestGuard_R3_PwdBindHiddenSwitch(t *testing.T) {
	evil := t.TempDir()
	writeTestExecutable(t, filepath.Join(evil, "pig"), 0755)
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{"builtin pushd", `builtin pushd ` + evil + `; D=$(pwd); "$D/pig"`, "dynamic command head"},
		{"command pushd", `command pushd ` + evil + `; D=$(pwd); "$D/pig"`, "dynamic command head"},
		{"eval cd", `eval "cd ` + evil + `"; D=$(pwd); "$D/pig"`, "dynamic command head"},
		{"source dot", `. /dev/null; cd ` + evil + `; D=$(pwd); "$D/pig"`, "dynamic command head"},
		{"popd", `pushd /tmp >/dev/null; popd >/dev/null; D=$(pwd); "$D/pig"`, "dynamic command head"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want substring %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// R3-SF-2: PATH-planted shadow hc never earns a --hc-gate rewrite — the
// dynamic hc send under a .venv/bin / ~/.cargo/bin PATH stays blocked.
// ---------------------------------------------------------------------------

func TestGuard_R3_ShadowHcNoRewrite(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	// cwd and stub under fakeHome (never /tmp): the planted-shadow verdict
	// must be reached, not the generic /tmp-scratch block (R4).
	cwd := filepath.Join(fakeHome, "proj")
	if err := os.MkdirAll(cwd, 0755); err != nil {
		t.Fatalf("mkdir cwd: %v", err)
	}
	venvBin := filepath.Join(cwd, ".venv", "bin")
	cargoBin := filepath.Join(fakeHome, ".cargo", "bin")
	for _, d := range []string{venvBin, cargoBin} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	stubDir := filepath.Join(fakeHome, "stubdir")
	if err := os.MkdirAll(stubDir, 0755); err != nil {
		t.Fatalf("mkdir stubDir: %v", err)
	}
	stub := filepath.Join(stubDir, "herdr-core-stub")
	writeTestExecutable(t, stub, 0755)
	for _, dir := range []string{venvBin, cargoBin} {
		if err := os.Symlink(stub, filepath.Join(dir, "hc")); err != nil {
			t.Fatalf("symlink %s/hc: %v", dir, err)
		}
	}
	for _, tc := range []struct {
		name string
		path string
	}{
		{"venv shadow", venvBin + ":" + os.Getenv("PATH")},
		{"cargo shadow", cargoBin + ":" + os.Getenv("PATH")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", tc.path)
			g := guardCall{subagent: true}
			prep := g.prepareCtxRunArgv([]string{"hc", "send", "t42", "$x"}, "")
			// The shadow hc must NOT be rewritten into --hc-gate; either the
			// prepare blocks or the argv keeps the bare hc head for the guard.
			if prep.rule == "" && strings.Contains(strings.Join(prep.execArgv, " "), "--hc-gate") {
				t.Fatalf("shadow hc rewritten to --hc-gate: %v", prep.execArgv)
			}
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", argv: []string{"hc", "send", "t42", "ok"}}, cwd)
			// A relative-PATH shadow blocks either at the path-trust screen
			// (shadow/untrusted binary) or at the structural-alias screen
			// (the symlink target is itself a blocked agent head); the
			// planted cargo-bin absolute dir hits the first verdict.
			blocked := strings.Contains(got, "shadow binary") ||
				strings.Contains(got, "untrusted path binary") ||
				strings.Contains(got, "conflicting structural alias")
			if !blocked {
				t.Fatalf("%s hc head = %q, want a guard block", tc.name, got)
			}
		})
	}
	// R4 MF-3 / R5 MF-1: a PATH= assign prefix inside the -c script must
	// drive the leaf rewrite's effective PATH — `PATH=<cargoBin>:$PATH sh
	// -c 'hc send t42 "$x"'` peels the prefix, feeds it to
	// collectLeafHcEdit, and can no longer launder the shadow hc into
	// --hc-gate. prepareCtxRunShell is the entry that actually reaches
	// the leaf rewriter (the argv spelling never unwraps into it).
	t.Run("PATH prefix sh -c", func(t *testing.T) {
		g := guardCall{subagent: true}
		prep := g.prepareCtxRunShell(`PATH=` + cargoBin + `:$PATH sh -c 'hc send t42 "$x"'`)
		if prep.rule == "" && strings.Contains(prep.execCode, "--hc-gate") {
			t.Fatalf("PATH-prefix shadow hc rewritten to --hc-gate: %q", prep.execCode)
		}
		// R6 SF-2: STATIC send spelling — the planted-shadow verdict is
		// asserted exactly (a dynamic "$x" slot could have blocked on the
		// generic payload rule before ever reaching the shadow check).
		got := rtGuardCwd(t, rtCase{
			id: "path-prefix-hc", role: "worker",
			cmd: `PATH=` + cargoBin + `:$PATH sh -c 'hc send t42 ok'`,
		}, cwd)
		if !strings.Contains(got, "planted shadow binary") {
			t.Fatalf("PATH=<cargoBin> sh -c hc send = %q, want planted shadow binary", got)
		}
	})

	// R5 closeout probes (each pins one of the six R5 fix sites):
	//
	// 1. peelWrappersWithIndex replays PATH= ops over
	//    caller.effectivePATH(): an outer caller.pathEnv carrying a
	//    `nice -> exec` alias makes the SAFE-LOOKING typed `nice` head
	//    resolve to an UNSAFE peel base — headIdx must surrender
	//    (return -1). Before the fix the replay used os.Getenv("PATH")
	//    and the alias was invisible to the slot walk.
	t.Run("R5 MF-1 nice->exec headIdx", func(t *testing.T) {
		aliasDir := filepath.Join(fakeHome, "aliasbin")
		if err := os.MkdirAll(aliasDir, 0755); err != nil {
			t.Fatalf("mkdir aliasDir: %v", err)
		}
		// The symlink TARGET must exist or EvalSymlinks leaves the typed
		// name unresolved (rb stays "", no unsafe-base hit).
		writeTestExecutable(t, filepath.Join(aliasDir, "exec"), 0755)
		if err := os.Symlink(filepath.Join(aliasDir, "exec"), filepath.Join(aliasDir, "nice")); err != nil {
			t.Fatalf("symlink nice -> exec: %v", err)
		}
		caller := callerIdentity{pathEnv: aliasDir}
		_, headIdx, _, _, _ := peelWrappersWithIndex([]string{"nice", "-n", "5", "hc", "send", "t42", "$x"}, caller)
		if headIdx != -1 {
			t.Fatalf("nice -> exec alias: headIdx = %d, want -1 (provenance surrendered)", headIdx)
		}
	})
	//
	// 2. preScanVarMutations / emitCall: a prefix env assign ahead of a
	//    for-loop enum head expansion no longer hides the directory
	//    switch — `for X in eval; do FOO=1 $X "cd <evil>"; done` must
	//    still invalidate the $(pwd) static bind (R5 MF-2).
	t.Run("R5 MF-2 for-enum eval FOO=1", func(t *testing.T) {
		evil := t.TempDir()
		writeTestExecutable(t, filepath.Join(evil, "pig"), 0755)
		if err := os.Symlink(filepath.Join(evil, "pig"), filepath.Join(evil, "mytool")); err != nil {
			t.Fatalf("symlink mytool -> pig: %v", err)
		}
		got := rtGuardCwd(t, rtCase{
			id: "for-enum-eval-FOO", role: "worker",
			cmd: `for X in eval; do FOO=1 $X "cd ` + evil + `"; done; D=$(pwd); "$D/mytool"`,
		}, "")
		if !strings.Contains(got, "dynamic command head") {
			t.Fatalf("for-enum FOO=1 eval cd = %q, want dynamic command head", got)
		}
	})
	//
	// 3. stdinProgramTargetsWithEnv seeds `ea` before the canon
	//    early-return: `env -C sub genv ./mysh` peels -C, sees `genv`
	//    canonicalise to `env`, recurses with the seeded caller — the
	//    inner ./mysh must resolve under <cwd>/sub (R5 MF-4a).
	t.Run("R5 MF-4 env -C genv stdin", func(t *testing.T) {
		sub := filepath.Join(cwd, "sub")
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatalf("mkdir sub: %v", err)
		}
		if err := os.Symlink("/bin/sh", filepath.Join(sub, "mysh")); err != nil {
			t.Fatalf("symlink mysh -> /bin/sh: %v", err)
		}
		got := rtGuardCwd(t, rtCase{
			id: "env-C-sub-genv-mysh-stdin", role: "worker",
			argv:  []string{"env", "-C", "sub", "genv", "./mysh"},
			stdin: "pig",
		}, cwd)
		if !strings.Contains(got, "pig") {
			t.Fatalf("env -C sub genv ./mysh stdin=pig = %q, want pig block", got)
		}
	})
	//
	// 4. scriptAllowsLocalShellStdinPrepare seeds the OUTER env on the
	//    caller itself: outerEnv carrying `env -C sub` must make the
	//    inner ./mysh resolve under <cwd>/sub — the planted non-shell
	//    (mycat -> selfExe) there is a DATA consumer, not a shell, so
	//    the rewrite refuses (false). Without the -C re-anchor the same
	//    head would land on a system shell and return true (R5 MF-4b).
	t.Run("R5 MF-4 outerEnv env -C sub", func(t *testing.T) {
		sub := filepath.Join(cwd, "sub")
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatalf("mkdir sub: %v", err)
		}
		selfExe4, err := os.Executable()
		if err != nil {
			t.Fatalf("os.Executable: %v", err)
		}
		if err := os.Symlink(selfExe4, filepath.Join(sub, "mycat")); err != nil {
			t.Fatalf("symlink mycat -> selfExe: %v", err)
		}
		// R6 MF-1 pairing: a same-name SHELL alias lives at cwd, so the
		// IDENTICAL "./mycat" head resolves to a local shell (true) without
		// -C and to the non-shell selfExe (false) with `env -C sub` — the
		// boolean flip can no longer pass vacuously on an unresolvable head.
		if err := os.Symlink("/bin/sh", filepath.Join(cwd, "mycat")); err != nil {
			t.Fatalf("symlink cwd mycat -> /bin/sh: %v", err)
		}
		g := guardCall{subagent: true, cwd: cwd}
		caller := g.callerIdentity()
		var outerEnv envAssignments
		outerEnv.ops = append(outerEnv.ops, envOp{kind: 'd', value: "sub"})
		if _, ok := scriptAllowsLocalShellStdinPrepare("./mycat", false, outerEnv, os.Getenv("PATH"), caller); ok {
			t.Fatalf("env -C sub + ./mycat (non-shell) must refuse the stdin shell rewrite")
		}
		// Control: the same "./mycat" without the -C re-anchor resolves to
		// cwd/mycat -> /bin/sh — the stream is a local shell program and the
		// rewrite is allowed (true). The boolean flip proves the env -C
		// seed actually steered resolution (no vacuous false).
		var noEnv envAssignments
		if _, ok := scriptAllowsLocalShellStdinPrepare("./mycat", false, noEnv, os.Getenv("PATH"), caller); !ok {
			t.Fatalf("./mycat -> /bin/sh at cwd must allow the stdin shell rewrite")
		}
		// Bare sh stays a local shell target without any outer env.
		if _, ok := scriptAllowsLocalShellStdinPrepare("sh", false, noEnv, os.Getenv("PATH"), caller); !ok {
			t.Fatalf("bare sh without outerEnv must still allow the stdin shell rewrite")
		}
	})
}

// ---------------------------------------------------------------------------
// R6 MF-1: non-ssh alias heads under xargs/find -exec — the peeled target's
// resolved basename must face the SAME code-slot and ssh screens as the
// typed name (`env -C sub ./mysh -c` where mysh -> /bin/sh feeds xargs /
// find placeholders into a hidden shell -c slot), and the stdin-target
// language lookup must resolve through the alias too.
// ---------------------------------------------------------------------------

func TestGuard_R6_XargsFindAliasCodeSlot(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	cwd := filepath.Join(fakeHome, "proj")
	sub := filepath.Join(cwd, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.Symlink("/bin/sh", filepath.Join(sub, "mysh")); err != nil {
		t.Fatalf("symlink mysh -> /bin/sh: %v", err)
	}
	for _, tc := range []struct {
		name  string
		cmd   string
		argv  []string
		stdin string
	}{
		// The -C re-anchor moves ./mysh resolution into sub where the alias
		// resolves to a shell: the trailing -c slot is an open code flag the
		// piped word feeds — xargsFeedsCodeFlag must see the RESOLVED head.
		{"xargs env -C sub ./mysh -c", `echo pig | xargs env -C sub ./mysh -c`, nil, ""},
		// -I{}: the replace token sits in the -c code slot of the alias —
		// replTokenInExecSlot must see it through the resolved head.
		{"xargs -I{} env -C sub ./mysh -c {}", `echo pig | xargs -I{} env -C sub ./mysh -c '{}'`, nil, ""},
		// find -exec twin: {} in the alias's -c slot.
		{"find -exec env -C sub ./mysh -c {}", `find . -exec env -C sub ./mysh -c {} \;`, nil, ""},
		// argv + stdin: the xargs target resolves to a shell whose -c slot
		// is flag-open — the streamed "pig" must block, never slip into a
		// data / unscreened target path.
		{"argv xargs env -C sub ./mysh -c stdin", ``, []string{"xargs", "env", "-C", "sub", "./mysh", "-c"}, "pig"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{
				id: tc.name, role: "worker",
				cmd: tc.cmd, argv: tc.argv, stdin: tc.stdin,
			}, cwd)
			if got == "ALLOW" {
				t.Fatalf("%s = ALLOW, want a guard block", tc.name)
			}
		})
	}

	// Non-shell interpreter alias via xargs: stdinProgramTargetsWithEnv must
	// resolve the target basename to "ruby" instead of falling back to "".
	t.Run("xargs env -C sub ./myruby -e keeps ruby lang", func(t *testing.T) {
		rubyStub := filepath.Join(sub, "ruby")
		writeTestExecutable(t, rubyStub, 0755)
		if err := os.Symlink(rubyStub, filepath.Join(sub, "myruby")); err != nil {
			t.Fatalf("symlink myruby -> ruby: %v", err)
		}
		caller := callerIdentity{cwd: cwd}
		targets := stdinProgramTargetsWithEnv([]string{"xargs", "env", "-C", "sub", "./myruby", "-e"}, 0, envAssignments{}, os.Getenv("PATH"), caller)
		if len(targets) != 1 || targets[0].lang != "ruby" {
			t.Fatalf("targets = %+v, want 1 target with lang=ruby", targets)
		}
	})

	// Cross-family structural conflict (sh -> python3) must fail closed in
	// replTokenInExecSlot and xargsFeedsCodeFlag.
	t.Run("cross-family conflict sh -> python3 fails closed", func(t *testing.T) {
		pyStub := filepath.Join(sub, "python3")
		writeTestExecutable(t, pyStub, 0755)
		if err := os.Symlink(pyStub, filepath.Join(sub, "sh")); err != nil {
			t.Fatalf("symlink sh -> python3: %v", err)
		}
		caller := callerIdentity{cwd: cwd}
		if !replTokenInExecSlot([]string{"env", "-C", "sub", "./sh", "{}"}, "{}", os.Getenv("PATH"), caller) {
			t.Fatalf("replTokenInExecSlot must fail closed on cross-family sh -> python3")
		}
		if !xargsFeedsCodeFlag([]string{"env", "-C", "sub", "./sh"}, nil, os.Getenv("PATH"), caller) {
			t.Fatalf("xargsFeedsCodeFlag must fail closed on cross-family sh -> python3")
		}
	})
}

// ---------------------------------------------------------------------------
// R6 SF-1: prepareCtxRunShellTargets multi-target order independence — the
// same payload under reversed target-env order must yield the SAME verdict
// (one rewrite decision never rides on targetEnvs[0] alone).
// ---------------------------------------------------------------------------

func TestGuard_R6_MultiTargetOrderIndependent(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	cargoBin := filepath.Join(fakeHome, ".cargo", "bin")
	if err := os.MkdirAll(cargoBin, 0755); err != nil {
		t.Fatalf("mkdir cargoBin: %v", err)
	}
	stubDir := filepath.Join(fakeHome, "stubdir")
	if err := os.MkdirAll(stubDir, 0755); err != nil {
		t.Fatalf("mkdir stubDir: %v", err)
	}
	stub := filepath.Join(stubDir, "herdr-core-stub")
	writeTestExecutable(t, stub, 0755)
	if err := os.Symlink(stub, filepath.Join(cargoBin, "hc")); err != nil {
		t.Fatalf("symlink cargoBin/hc: %v", err)
	}
	// The shadow hc is only visible under the PATH=<cargoBin> env; the clean
	// target sees the REAL hc. Whatever the target order, the per-target
	// guard under the cargo env must block on the planted shadow — the
	// order-independence fix guarantees the first-env rewrite never leaks
	// past the second env's screen.
	g := guardCall{subagent: true}
	// Same scenario through the REAL entry point: `sh ; PATH=<cargoBin>
	// sh` and `PATH=<cargoBin> sh ; sh` feed the stream to TWO local
	// shell targets — the first target's env is the clean outer PATH,
	// the second's carries the shadow dir. Whatever the order, the
	// cargo-env guard must block the planted-shadow `hc send` stdin
	// payload; the SF-1 fix additionally guarantees the rewrite itself
	// never rides on targetEnvs[0] alone (a clean-first order would
	// otherwise mint an --hc-gate edit the shadow order never saw).
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"clean first", []string{"sh", "-c", `sh ; PATH=` + cargoBin + `:$PATH sh`}},
		{"shadow first", []string{"sh", "-c", `PATH=` + cargoBin + `:$PATH sh ; sh`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prep := g.prepareCtxRunArgv(tc.argv, "hc send t42 ok")
			if prep.rule == "" && strings.Contains(prep.execStdin, "--hc-gate") {
				t.Fatalf("%s: shadow hc stdin rewritten to --hc-gate: %q", tc.name, prep.execStdin)
			}
			if prep.rule == "" {
				t.Fatalf("%s: prepareCtxRunArgv passed, want planted shadow block", tc.name)
			}
		})
	}
	// Direct envAssignments probe: the same two target-env slices in
	// either order must produce the SAME verdict.
	var cleanEnv, cargoEnv envAssignments
	cleanEnv.ops = append(cleanEnv.ops, envOp{kind: 'a', key: "PATH", value: "/usr/bin:/bin"})
	cargoEnv.ops = append(cargoEnv.ops, envOp{kind: 'a', key: "PATH", value: cargoBin + ":/usr/bin:/bin"})
	for _, tc := range []struct {
		name string
		envs []envAssignments
	}{
		{"clean first direct", []envAssignments{cleanEnv, cargoEnv}},
		{"shadow first direct", []envAssignments{cargoEnv, cleanEnv}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := g.prepareCtxRunShellTargets(`hc send t42 "$x"`, tc.envs)
			if sp.rule == "" {
				t.Fatalf("%s: prepareCtxRunShellTargets passed, want planted shadow block", tc.name)
			}
		})
	}

	// Symmetric two-segment payload: under the CLEAN env both `hc send`
	// candidates rewrite (bare `hc` resolves through trustedBin to the
	// install slot, the absolute `<trustedBin>/hc` spelling is a path
	// admitted by admittedReadonlyCanonicalHead) — 2 edits. Under the
	// CARGO env the bare `hc` resolves to the planted shadow (never
	// rewritable) while the absolute spelling still admits — 1 edit.
	// The counts disagree, so the order-independent guard drops the
	// whole rewrite and the cargo-env guard pass blocks the shadow
	// `hc send` head.
	trustedBin := filepath.Join(fakeHome, ".local", "bin")
	if err := os.MkdirAll(trustedBin, 0755); err != nil {
		t.Fatalf("mkdir trustedBin: %v", err)
	}
	realHc := filepath.Join(trustedBin, "herdr-core")
	writeTestExecutable(t, realHc, 0755)
	if err := os.Symlink(realHc, filepath.Join(trustedBin, "hc")); err != nil {
		t.Fatalf("symlink hc -> herdr-core: %v", err)
	}
	var cleanEnv2 envAssignments
	cleanEnv2.ops = append(cleanEnv2.ops, envOp{kind: 'a', key: "PATH", value: trustedBin + ":/usr/bin:/bin"})
	code2 := `hc send t42 "$x" ; ` + trustedBin + `/hc send t42 "$y"`
	for _, tc := range []struct {
		name string
		envs []envAssignments
	}{
		{"clean first symmetric", []envAssignments{cleanEnv2, cargoEnv}},
		{"shadow first symmetric", []envAssignments{cargoEnv, cleanEnv2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := g.prepareCtxRunShellTargets(code2, tc.envs)
			if sp.rule == "" {
				t.Fatalf("%s: prepareCtxRunShellTargets passed, want planted shadow block", tc.name)
			}
		})
	}
}

// === Merged from zz_r3path_test.go ===

func writePwnTool(t *testing.T, path, tag string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\necho PWNED-" + tag + "\n"
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func writeBenign(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho BENIGN\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

// tmpScratchDir explicitly allocates a small directory under /tmp regardless
// of TMPDIR so C10 isTmpOrScratchPath tests behave identically when TMPDIR
// points to a disk directory.
func tmpScratchDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ctxmode-w5-")
	if err != nil {
		return t.TempDir()
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// nonTmpWS creates a temporary workspace outside /tmp|/var/tmp|/dev/shm|/run
// without requiring root or /opt write access (uses ~/.cache or parent of cwd).
func nonTmpWS(t *testing.T) string {
	t.Helper()
	var candidates []string
	if h, err := os.UserHomeDir(); err == nil && h != "" && !isTmpOrScratchPath(h) {
		candidates = append(candidates, filepath.Join(h, ".cache", "ctxmode-r3-repro"))
	}
	if wd, err := os.Getwd(); err == nil && wd != "" && !isTmpOrScratchPath(wd) {
		candidates = append(candidates, filepath.Join(filepath.Dir(wd), ".ctxmode-r3-repro"))
	}
	for _, root := range candidates {
		if err := os.MkdirAll(root, 0755); err != nil {
			continue
		}
		ws, err := os.MkdirTemp(root, "ws-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(ws) })
		return ws
	}
	t.Skip("no writable non-/tmp workspace directory available for current user")
	return ""
}

func relVenvLink(t *testing.T, ws, linkName, target string) {
	t.Helper()
	bin := filepath.Join(ws, ".venv", "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(bin, 0755)
	link := filepath.Join(bin, linkName)
	_ = os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func guardWorker(t *testing.T, cwd, cmd string) string {
	t.Helper()
	return rtGuardCwd(t, rtCase{id: t.Name(), role: "worker", cmd: cmd}, cwd)
}

func TestR3_RelativePATH_SymlinkToTmp(t *testing.T) {
	scratch := tmpScratchDir(t)
	samePytest := filepath.Join(scratch, "pytest")
	writePwnTool(t, samePytest, "pytest-same")
	tmpRuff := filepath.Join(scratch, "ruff")
	writePwnTool(t, tmpRuff, "ruff-cross")
	evil := filepath.Join(scratch, "evil")
	writePwnTool(t, evil, "evil")
	samePy := filepath.Join(scratch, "python3")
	writePwnTool(t, samePy, "python3-same")
	usrPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("lookpath python3: %v", err)
	}
	usrSu, _ := exec.LookPath("su")

	type tc struct {
		id, wsKind, linkName, target, cmd string
		wantAllow                         bool
		note                              string
	}
	cases := []tc{
		{id: "W5-same-pytest-nontmp", wsKind: "nontmp", linkName: "pytest", target: samePytest,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "same-name .venv/bin/pytest -> /tmp/pytest, non-/tmp cwd"},
		{id: "W5-same-pytest-intmp", wsKind: "intmp", linkName: "pytest", target: samePytest,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "same-name, workspace itself under /tmp"},
		{id: "W5-cross-pytest-to-tmpruff-nontmp", wsKind: "nontmp", linkName: "pytest", target: tmpRuff,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "cross-name .venv/bin/pytest -> /tmp/ruff (ruff in toolchainRelPathHeads)"},
		{id: "W5-pytest-to-evil-nontmp", wsKind: "nontmp", linkName: "pytest", target: evil,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "pytest -> /tmp/evil"},
		{id: "W5-python3-to-evil-nontmp", wsKind: "nontmp", linkName: "python3", target: evil,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'print(1)'`, wantAllow: false,
			note: "structural head python3 -> /tmp/evil"},
		{id: "W5-python3-to-tmppython-nontmp", wsKind: "nontmp", linkName: "python3", target: samePy,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'print(1)'`, wantAllow: false,
			note: "structural head python3 -> /tmp/python3"},
		{id: "W5-abs-same-pytest-nontmp", wsKind: "nontmp", linkName: "pytest", target: samePytest,
			cmd: `PATH="$PWD/.venv/bin:$PATH" pytest`, wantAllow: false,
			note: "dynamic $PWD in PATH"},
		{id: "W5-abs-literal-same-pytest-nontmp", wsKind: "nontmp-litabs", linkName: "pytest", target: samePytest,
			cmd: "PLACEHOLDER", wantAllow: false,
			note: "literal abs PATH .venv/bin -> /tmp/pytest"},
		{id: "W5-bin-rel-pytest-nontmp", wsKind: "nontmp-bin", linkName: "pytest", target: samePytest,
			cmd: `PATH="bin:$PATH" pytest`, wantAllow: false,
			note: "PATH=bin:$PATH rejected by pathIsUnsafeForSubagent"},
		{id: "M-rel-venv-pytest-file-nontmp", wsKind: "nontmp-file", linkName: "pytest", target: "",
			cmd: `PATH=".venv/bin:$PATH" pytest -q`, wantAllow: true,
			note: "regular file .venv/bin/pytest"},
		{id: "M-rel-nodemod-tsc-nontmp", wsKind: "nontmp-nm", linkName: "tsc", target: "",
			cmd: `PATH="node_modules/.bin:$PATH" tsc --noEmit`, wantAllow: true,
			note: "regular file node_modules/.bin/tsc"},
		{id: "M-rel-monorepo-hoisted-tsc", wsKind: "monorepo-hoisted", linkName: "tsc", target: "",
			cmd: `PATH="node_modules/.bin:$PATH" tsc --noEmit`, wantAllow: true,
			note: "monorepo subpackage node_modules/.bin/tsc -> ../../node_modules/typescript/bin/tsc"},
		{id: "M-rel-monorepo-pnpm-tsc", wsKind: "monorepo-pnpm", linkName: "tsc", target: "",
			cmd: `PATH="node_modules/.bin:$PATH" tsc --noEmit`, wantAllow: true,
			note: "pnpm workspace subpackage node_modules/.bin/tsc -> ../../node_modules/.pnpm/.../tsc"},
		{id: "M-rel-venv-python3-sys-nontmp", wsKind: "nontmp", linkName: "python3", target: usrPython,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'import sys; print(sys.version)'`, wantAllow: true,
			note: "normal venv: .venv/bin/python3 -> system python3"},
		{id: "M-rel-venv-python3-sys-intmp", wsKind: "intmp", linkName: "python3", target: usrPython,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'import sys; print(sys.version)'`, wantAllow: true,
			note: "normal venv under /tmp workspace"},
	}
	if usrSu != "" {
		cases = append(cases, tc{
			id: "A8-python3-to-su-nontmp", wsKind: "nontmp", linkName: "python3", target: usrSu,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'unset CTXMODE_ROLE; pig'`, wantAllow: false,
			note: ".venv/bin/python3 -> /bin/su must block before unwrapInterpreterInline",
		})
	}

	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			var ws string
			switch c.wsKind {
			case "nontmp", "nontmp-bin", "nontmp-file", "nontmp-nm", "nontmp-litabs",
				"monorepo-hoisted", "monorepo-pnpm":
				ws = nonTmpWS(t)
			default:
				ws = tmpScratchDir(t)
			}
			cwd := ws
			switch c.wsKind {
			case "nontmp-bin":
				bin := filepath.Join(ws, "bin")
				if err := os.MkdirAll(bin, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(c.target, filepath.Join(bin, c.linkName)); err != nil {
					t.Fatal(err)
				}
			case "nontmp-file":
				writeBenign(t, filepath.Join(ws, ".venv", "bin", c.linkName))
			case "nontmp-nm":
				writeBenign(t, filepath.Join(ws, "node_modules", ".bin", c.linkName))
			case "monorepo-hoisted":
				realBin := filepath.Join(ws, "node_modules", "typescript", "bin", "tsc")
				writeBenign(t, realBin)
				subPkg := filepath.Join(ws, "packages", "app")
				nmBin := filepath.Join(subPkg, "node_modules", ".bin")
				if err := os.MkdirAll(nmBin, 0775); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(realBin, filepath.Join(nmBin, "tsc")); err != nil {
					t.Fatal(err)
				}
				cwd = subPkg
			case "monorepo-pnpm":
				realBin := filepath.Join(ws, "node_modules", ".pnpm", "typescript@5.6.3", "node_modules", "typescript", "bin", "tsc")
				writeBenign(t, realBin)
				subPkg := filepath.Join(ws, "packages", "app")
				nmBin := filepath.Join(subPkg, "node_modules", ".bin")
				if err := os.MkdirAll(nmBin, 0775); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(realBin, filepath.Join(nmBin, "tsc")); err != nil {
					t.Fatal(err)
				}
				cwd = subPkg
			default:
				relVenvLink(t, ws, c.linkName, c.target)
			}
			cmd := c.cmd
			if c.wsKind == "nontmp-litabs" {
				cmd = "PATH=\"" + filepath.Join(ws, ".venv", "bin") + ":$PATH\" pytest"
			}
			got := guardWorker(t, cwd, cmd)
			allow := strings.HasPrefix(got, "ALLOW")
			if allow != c.wantAllow {
				t.Errorf("%s: got %s, wantAllow=%v (%s)", c.id, got, c.wantAllow, c.note)
			}
		})
	}
}

func TestR3_hcSendAddrAndCtrl(t *testing.T) {
	for _, s := range []string{"t1", "t42", "t0", "test", "tmux", "tab"} {
		if !hcSendAddrOK(s) {
			t.Errorf("hcSendAddrOK(%q)=false, want true", s)
		}
	}
	for _, s := range []string{"main", "editor", "machine/t7", "T1", "t-1", "1t", ""} {
		if hcSendAddrOK(s) {
			t.Errorf("hcSendAddrOK(%q)=true, want false", s)
		}
	}
	cases := []rtCase{
		{id: "A4-ctrl-x03-argv", role: "scout", argv: []string{"hc", "send", "t1", "\x03touch /tmp/x\r"}, wantAllow: false},
		{id: "A4-ctrl-esc-argv", role: "scout", argv: []string{"hc", "send", "t1", "\x1b[Ahello"}, wantAllow: false},
		{id: "A4-ansic-ctrl-shell", role: "scout", cmd: "hc send t1 $'\\x03touch /tmp/x\\r'", wantAllow: false},
		{id: "A4-ansic-ctrl-bash", role: "worker", cmd: "bash -c \"hc send t1 $'\\x03touch /tmp/x\\r'\"", wantAllow: false},
		// shell_ast.go encodes ANSI-C $'...' as dynamic placeholder __ctx_dq_sub__, so it fails closed;
		// ordinary single-quoted and double-quoted multiline literals stay allowed.
		{id: "A4-ansic-placeholder-bash", role: "worker", cmd: "bash -c \"hc send t1 $'line1\\nline2'\"", wantAllow: false},
		{id: "A4-newline-shell", role: "scout", cmd: "hc send t1 'line1\nline2'", wantAllow: true},
		{id: "A4-newline-dq-shell", role: "scout", cmd: "hc send t1 \"line1\nline2\"", wantAllow: true},
		{id: "A4-named-test", role: "scout", cmd: "hc send test hello", wantAllow: true},
		{id: "A4-named-tmux", role: "scout", cmd: "hc send tmux hello", wantAllow: true},
		{id: "A4-plain-t1", role: "scout", cmd: "hc send t1 'done: report ready'", wantAllow: true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			got := rtGuard(t, c)
			allow := strings.HasPrefix(got, "ALLOW")
			if allow != c.wantAllow {
				t.Errorf("%s: got %s, wantAllow=%v", c.id, got, c.wantAllow)
			}
		})
	}
}

// === Merged from zz_r5_pyimport_test.go ===

func TestR5_PythonImportStmtBoundary(t *testing.T) {
	// Override TMPDIR with a cwd-local directory and exercise non-/tmp relative
	// filenames ('audit.log', 'bundle.zip', 'raw.bin', 'log.ini') alongside '/tmp'
	// fixtures so every assertion is completely independent of TMPDIR or /tmp rules.
	altTmp, err := os.MkdirTemp(".", ".r7-tmpdir-")
	if err == nil {
		t.Cleanup(func() { _ = os.RemoveAll(altTmp) })
		t.Setenv("TMPDIR", altTmp)
	}

	cases := []struct {
		name      string
		code      string
		wantBlock bool
		wantSub   string
	}{
		// --- Pure import statements: must ALLOW ---
		{
			name:      "allow-pure-import-logging",
			code:      "import logging\n",
			wantBlock: false,
		},
		{
			name:      "allow-pure-from-rotatinghandler",
			code:      "from logging.handlers import RotatingFileHandler\n",
			wantBlock: false,
		},
		{
			name: "allow-pure-multiline-paren-handlers",
			code: "from logging.handlers import (\n" +
				"    RotatingFileHandler,\n" +
				"    WatchedFileHandler,\n" +
				")\n",
			wantBlock: false,
		},
		{
			name: "allow-pure-multiline-paren-with-comments-and-alias",
			code: "from logging.handlers import (  # handlers\n" +
				"    RotatingFileHandler as RFH,  # keep\n" +
				"    TimedRotatingFileHandler,\n" +
				")\n",
			wantBlock: false,
		},
		{
			name: "allow-pure-backslash-continued-import",
			code: "from logging.handlers \\\n" +
				"    import \\\n" +
				"    RotatingFileHandler\n",
			wantBlock: false,
		},
		{
			name: "allow-indented-from-import-zipfile",
			code: "if True:\n" +
				"    from zipfile import ZipFile\n",
			wantBlock: false,
		},
		{
			name:      "allow-pure-relative-from-import",
			code:      "from .handlers import WatchedFileHandler\n",
			wantBlock: false,
		},
		{
			name:      "allow-pure-import-zipfile",
			code:      "import zipfile\n",
			wantBlock: false,
		},
		{
			name:      "allow-import-zipfile-as-zf-alone",
			code:      "import zipfile as zf\n",
			wantBlock: false,
		},
		{
			name:      "allow-import-logging-handlers-as-lh-alone",
			code:      "import logging.handlers as lh\n",
			wantBlock: false,
		},
		{
			name:      "allow-from-logging-import-star-alone",
			code:      "from logging import *\n",
			wantBlock: false,
		},
		{
			name:      "allow-import-logging-config-alone",
			code:      "import logging.config\n",
			wantBlock: false,
		},

		// --- Runtime logging handler calls across newline / `;` / parens: must BLOCK ---
		{
			name:      "block-import-newline-logging-filehandler-relpath",
			code:      "import logging\nlogging.FileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-import-newline-logging-filehandler-tmppath",
			code:      "import logging\nlogging.FileHandler('/tmp/x.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name: "block-from-import-newline-rotatinghandler",
			code: "from logging.handlers import RotatingFileHandler\n" +
				"RotatingFileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "RotatingFileHandler",
		},
		{
			name: "block-multiline-import-then-runtime-watchedhandler",
			code: "from logging.handlers import (\n" +
				"    RotatingFileHandler,\n" +
				"    WatchedFileHandler,\n" +
				")\n" +
				"WatchedFileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "WatchedFileHandler",
		},
		{
			name:      "block-semicolon-import-logging-filehandler",
			code:      "import logging ; logging.FileHandler('audit.log')",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-import-then-multiline-paren-expr-filehandler",
			code:      "import logging\n(\n    logging.FileHandler('audit.log')\n)\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-yield-from-filehandler",
			code:      "import logging\ndef g():\n    yield from logging.FileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-from-logging-star-then-filehandler",
			code:      "from logging import *\nFileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},

		// --- R6 §4 Mutation M2 killers: non-import parenthesized references must BLOCK ---
		{
			name:      "block-m2-call-multiline-paren-filehandler-arg",
			code:      "foo(\n    FileHandler,\n)\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-m2-tuple-filehandler-index-call",
			code:      "x = (FileHandler,)\nx[0]('audit.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-m2-call-multiline-paren-zipfile-arg",
			code:      "f(\n    ZipFile,\n)\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},

		// --- R6 §1: `from ... import X as Alias` across all 7 classes ---
		{
			name:      "block-alias-filehandler",
			code:      "from logging import FileHandler as F\nF('/tmp/x.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name: "block-alias-multiline-rotatinghandler",
			code: "from logging.handlers import (\n" +
				"  RotatingFileHandler as R,\n" +
				")\n" +
				"R('audit.log')\n",
			wantBlock: true,
			wantSub:   "RotatingFileHandler",
		},
		{
			name:      "block-alias-timed-and-watched-handlers",
			code:      "from logging.handlers import TimedRotatingFileHandler as T, WatchedFileHandler as W\nT('audit.log')\n",
			wantBlock: true,
			wantSub:   "TimedRotatingFileHandler",
		},
		{
			name:      "block-alias-watchedhandler-call",
			code:      "from logging.handlers import WatchedFileHandler as W\nW('audit.log')\n",
			wantBlock: true,
			wantSub:   "WatchedFileHandler",
		},
		{
			name:      "block-alias-zipfile-write",
			code:      "from zipfile import ZipFile as Z\nZ('bundle.zip', 'w').writestr('a', 'b')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-alias-fileio-write",
			code:      "from io import FileIO as F\nF('raw.bin', 'w').write(b'x')\n",
			wantBlock: true,
			wantSub:   "FileIO",
		},
		{
			name:      "block-alias-pyzipfile-write",
			code:      "from zipfile import PyZipFile as P\nP('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "PyZipFile",
		},
		{
			name:      "block-alias-zipfile-chained-rebind",
			code:      "from zipfile import ZipFile as Z\ng = Z\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-module-alias-zf-zipfile-write",
			code:      "import zipfile as zf\nzf.ZipFile('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name: "allow-alias-zipfile-readonly-with",
			code: "from zipfile import ZipFile as Z\n" +
				"with Z('bundle.zip') as z:\n" +
				"    print(z.namelist())\n",
			wantBlock: false,
		},

		// --- R6 §2: logging.basicConfig / dictConfig / fileConfig / config.listen ---
		{
			name:      "block-logging-basicconfig-filename",
			code:      "import logging\nlogging.basicConfig(filename='audit.log')\nlogging.warning('x')\n",
			wantBlock: true,
			wantSub:   "basicConfig",
		},
		{
			name:      "block-logging-basicconfig-kwargs-unpack",
			code:      "import logging\nlogging.basicConfig(**{'filename': 'audit.log'})\n",
			wantBlock: true,
			wantSub:   "basicConfig",
		},
		{
			name:      "block-logging-basicconfig-alias-filename",
			code:      "from logging import basicConfig as bc\nbc(level=20, filename='audit.log')\n",
			wantBlock: true,
			wantSub:   "basicConfig",
		},
		{
			name: "block-logging-dictconfig",
			code: "import logging.config\n" +
				"logging.config.dictConfig({'version': 1, 'handlers': {'f': {'class': 'logging.FileHandler', 'filename': 'audit.log'}}, 'root': {'handlers': ['f']}})\n",
			wantBlock: true,
			wantSub:   "dictConfig",
		},
		{
			name:      "block-logging-fileconfig",
			code:      "import logging.config\nlogging.config.fileConfig('log.ini')\n",
			wantBlock: true,
			wantSub:   "fileConfig",
		},
		{
			name:      "block-logging-config-listen-qualified",
			code:      "import logging.config\nlogging.config.listen(9999)\n",
			wantBlock: true,
			wantSub:   "config.listen",
		},
		{
			name:      "block-logging-config-listen-aliased",
			code:      "from logging.config import listen as L\nL(9999)\n",
			wantBlock: true,
			wantSub:   "config.listen",
		},
		{
			name:      "allow-logging-basicconfig-level-only",
			code:      "import logging\nlogging.basicConfig(level=logging.INFO)\n",
			wantBlock: false,
		},
		{
			name:      "allow-unrelated-socket-listen",
			code:      "import socket\ns = socket.socket()\ns.listen(5)\n",
			wantBlock: false,
		},

		// --- R6 §3: Reflection via getattr / __dict__ / vars / globals ---
		{
			name:      "block-getattr-logging-filehandler",
			code:      "import logging\ngetattr(logging, 'FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "getattr FileHandler",
		},
		{
			name:      "block-dict-subscript-filehandler",
			code:      "import logging.handlers\nlogging.handlers.__dict__['FileHandler']('audit.log')\n",
			wantBlock: true,
			wantSub:   "__dict__ FileHandler",
		},
		{
			name:      "block-getattr-builtins-open",
			code:      "import builtins\ngetattr(builtins, 'open')('audit.log', 'w')\n",
			wantBlock: true,
			wantSub:   "getattr open",
		},
		{
			name:      "block-getattr-builtins-hex-escaped-open",
			code:      "import builtins\ngetattr(builtins, '\\x6fpen')('audit.log', 'w')\n",
			wantBlock: true,
			wantSub:   "getattr open",
		},
		{
			name:      "block-vars-logging-filehandler",
			code:      "import logging\nvars(logging)['FileHandler']('audit.log')\n",
			wantBlock: true,
			wantSub:   "vars FileHandler",
		},
		{
			name:      "allow-benign-getattr-and-vars",
			code:      "import sys\nprint(getattr(sys, 'version', ''), vars(sys).get('platform'))\n",
			wantBlock: false,
		},

		// --- ZipFile / PyZipFile / FileIO regressions & bare/rebind checks ---
		{
			name:      "block-zipfile-assign-rebind",
			code:      "import zipfile\nf = zipfile.ZipFile\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-zipfile-bare-expr-after-import",
			code:      "import zipfile\nzipfile.ZipFile\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-from-zipfile-bare-expr-second-line",
			code:      "from zipfile import ZipFile\nZipFile\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-zipfile-paren-wrapped-ctor-write",
			code:      "import zipfile\n(zipfile.ZipFile)('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "allow-zipfile-readonly-var-arg",
			code:      "from zipfile import ZipFile\np = 'bundle.zip'\nz = ZipFile(p)\n",
			wantBlock: false,
		},
		{
			name:      "allow-zipfile-readonly-default",
			code:      "from zipfile import ZipFile\nwith ZipFile('bundle.zip') as z:\n    print(z.namelist())\n",
			wantBlock: false,
		},
		{
			name:      "allow-zipfile-readonly-explicit-r",
			code:      "import zipfile\nzipfile.ZipFile('bundle.zip', 'r')\n",
			wantBlock: false,
		},
		{
			name:      "allow-fileio-readonly-explicit-r",
			code:      "import io\nio.FileIO('raw.bin', 'r')\n",
			wantBlock: false,
		},
		{
			name:      "block-zipfile-positional-w",
			code:      "import zipfile\nzipfile.ZipFile('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-zipfile-kwarg-mode-a",
			code:      "from zipfile import ZipFile\nZipFile('bundle.zip', mode='a')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-fileio-positional-w",
			code:      "import io\nio.FileIO('raw.bin', 'w')\n",
			wantBlock: true,
			wantSub:   "FileIO",
		},

		// --- R7 §1: Python NFKC non-ASCII identifiers vs UTF-8 strings/comments/f-strings ---
		{
			name:      "allow-utf8-strings-and-comments-ete-cafe",
			code:      "print('été')\n# café\n",
			wantBlock: false,
		},
		{
			name:      "allow-utf8-fstring-literal-segment",
			code:      "x = 42\nprint(f'结果 café: {x}')\n",
			wantBlock: false,
		},
		{
			name:      "block-nfkc-fullwidth-open",
			code:      "\uff4fpen('audit.txt', 'w').write('x')\n",
			wantBlock: true,
			wantSub:   "non-ASCII identifier",
		},
		{
			name:      "block-nfkc-fullwidth-zipfile",
			code:      "import zipfile\nzipfile.\uff3aipFile('bundle.zip', 'w').writestr('a', 'b')\n",
			wantBlock: true,
			wantSub:   "non-ASCII identifier",
		},
		{
			name:      "block-nfkc-fullwidth-filehandler",
			code:      "import logging\nlogging.\uff26ileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "non-ASCII identifier",
		},
		{
			name:      "block-nfkc-inside-fstring-expr",
			code:      "f\"{\uff4fpen('audit.txt', 'w')}\"\n",
			wantBlock: true,
			wantSub:   "non-ASCII identifier",
		},

		// --- R7 §2: BaseRotatingHandler & whole-module logging.config closure ---
		{
			name:      "block-logging-handlers-baserotatinghandler",
			code:      "import logging.handlers\nlogging.handlers.BaseRotatingHandler('audit.log', 'a')\n",
			wantBlock: true,
			wantSub:   "BaseRotatingHandler",
		},
		{
			name:      "block-alias-baserotatinghandler",
			code:      "from logging.handlers import BaseRotatingHandler as B\nB('audit.log', 'a')\n",
			wantBlock: true,
			wantSub:   "BaseRotatingHandler",
		},
		{
			name: "block-logging-config-dictconfigurator",
			code: "import logging.config\n" +
				"logging.config.DictConfigurator({'version': 1, 'handlers': {'f': {'class': 'logging.FileHandler', 'filename': 'audit.log'}}, 'root': {'handlers': ['f']}}).configure()\n",
			wantBlock: true,
			wantSub:   "logging.config.DictConfigurator",
		},
		{
			name:      "block-logging-config-dictconfigclass",
			code:      "import logging.config\nlogging.config.dictConfigClass({'version': 1}).configure()\n",
			wantBlock: true,
			wantSub:   "logging.config.dictConfigClass",
		},
		{
			name: "block-logging-config-install-handlers",
			code: "import logging.config, configparser\n" +
				"cp = configparser.ConfigParser()\n" +
				"cp.read_string(\"[handlers]\\nkeys=f\\n[handler_f]\\nclass=FileHandler\\nargs=('audit.log',)\\n\")\n" +
				"logging.config._install_handlers(cp, {})\n",
			wantBlock: true,
			wantSub:   "logging.config._install_handlers",
		},
		{
			name:      "block-logging-config-private-resolve",
			code:      "import logging.config\nlogging.config._resolve('logging.FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "logging.config._resolve",
		},
		{
			name:      "block-logging-config-baseconfigurator-resolve",
			code:      "import logging.config\nlogging.config.BaseConfigurator({}).resolve('logging.FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "logging.config.BaseConfigurator",
		},
		{
			name:      "block-from-logging-config-import-resolve-alias",
			code:      "from logging.config import _resolve as r\nr('logging.FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "logging.config._resolve",
		},
		{
			name:      "block-from-logging-config-import-star",
			code:      "from logging.config import *\n",
			wantBlock: true,
			wantSub:   "logging.config",
		},
		{
			name:      "block-logging-config-module-rebind",
			code:      "import logging.config\nc = logging.config\n",
			wantBlock: true,
			wantSub:   "logging.config",
		},

		// --- R7 §3: pkgutil.resolve_name & pydoc.{locate,safeimport} ---
		{
			name:      "block-pkgutil-resolve-name",
			code:      "import pkgutil\npkgutil.resolve_name('logging:FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "resolve_name",
		},
		{
			name:      "block-pkgutil-resolve-name-alias",
			code:      "from pkgutil import resolve_name as rn\nrn('logging:FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "resolve_name",
		},
		{
			name:      "block-pydoc-locate",
			code:      "import pydoc\npydoc.locate('logging.FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "pydoc.locate",
		},
		{
			name:      "block-pydoc-safeimport-alias",
			code:      "from pydoc import safeimport as si\nsi('logging.handlers')\n",
			wantBlock: true,
			wantSub:   "pydoc.safeimport",
		},
		{
			name:      "allow-import-pkgutil-and-pydoc-alone",
			code:      "import pkgutil, pydoc\n",
			wantBlock: false,
		},

		// --- R7 §4.1: locals() & __getattribute__ reflection ---
		{
			name:      "block-locals-subscript-filehandler",
			code:      "from logging import *\nlocals()['FileHandler']('audit.log')\n",
			wantBlock: true,
			wantSub:   "locals FileHandler",
		},
		{
			name:      "block-builtins-dunder-getattribute-open",
			code:      "import builtins\nbuiltins.__getattribute__('open')('audit.txt', 'w')\n",
			wantBlock: true,
			wantSub:   "__getattribute__ open",
		},
		{
			name:      "block-object-dunder-getattribute-builtins-open",
			code:      "import builtins\nobject.__getattribute__(builtins, 'open')('audit.txt', 'w')\n",
			wantBlock: true,
			wantSub:   "__getattribute__ open",
		},

		// --- R7 §4.2: False-positive regressions (argparse config.listen & getattr system) ---
		{
			name:      "allow-argparse-namespace-config-listen",
			code:      "import argparse\nconfig = argparse.Namespace(listen=1)\nprint(config.listen)\n",
			wantBlock: false,
		},
		{
			name:      "allow-argparse-config-listen-with-import-logging",
			code:      "import argparse, logging\nconfig = argparse.Namespace(listen=1)\nprint(config.listen)\n",
			wantBlock: false,
		},
		{
			name:      "allow-getattr-args-system-none",
			code:      "print(getattr(args, 'system', None))\n",
			wantBlock: false,
		},
		{
			name:      "block-getattr-os-system",
			code:      "import os\ngetattr(os, 'system')('id')\n",
			wantBlock: true,
			wantSub:   "getattr system",
		},

		// --- R7 §4.3: 5 surviving mutation-gap killers ---
		{
			name: "block-mut-paren-import-newline-before-as",
			code: "from zipfile import (\n" +
				"    ZipFile\n" +
				"    as Z,\n" +
				")\n" +
				"Z('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name: "block-mut-paren-import-comment-before-as",
			code: "from zipfile import (\n" +
				"    ZipFile  # c\n" +
				"    as Z,\n" +
				")\n" +
				"Z('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name: "block-mut-paren-import-newline-after-as",
			code: "from zipfile import (\n" +
				"    ZipFile as\n" +
				"    Z,\n" +
				")\n" +
				"Z('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-mut-zipfile-star-args-unpack",
			code:      "from zipfile import ZipFile as Z\na = ('bundle.zip', 'w')\nZ(*a)\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-mut-zipfile-kw-star-unpack",
			code:      "from zipfile import ZipFile as Z\nkw = {'mode': 'w'}\nZ('bundle.zip', **kw)\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-mut-fileio-positional-opener",
			code:      "import io\nio.FileIO('raw.bin', 'r', True, lambda p, f: 3)\n",
			wantBlock: true,
			wantSub:   "FileIO",
		},
		{
			name:      "block-mut-fileio-keyword-opener",
			code:      "import io\nio.FileIO('raw.bin', opener=o)\n",
			wantBlock: true,
			wantSub:   "FileIO",
		},
		{
			name:      "allow-fileio-explicit-none-opener",
			code:      "import io\nio.FileIO('raw.bin', 'r', True, None)\nio.FileIO('raw.bin', 'r', opener=None)\n",
			wantBlock: false,
		},
		{
			name:      "block-mut-from-logging-import-config-as-c-listen",
			code:      "from logging import config as c\nc.listen(9999)\n",
			wantBlock: true,
			wantSub:   "logging.config.listen",
		},
		{
			name:      "block-mut-import-logging-config-as-lc",
			code:      "import logging.config as lc\nlc.DictConfigurator({})\n",
			wantBlock: true,
			wantSub:   "logging.config.DictConfigurator",
		},
		{
			name:      "block-mut-basicconfig-rebind",
			code:      "import logging\nb = logging.basicConfig\nb(filename='audit.log')\n",
			wantBlock: true,
			wantSub:   "basicConfig rebind",
		},
		{
			name:      "allow-alias-zipfile-readonly-positional",
			code:      "from zipfile import ZipFile as Z\nz = Z('bundle.zip')\n",
			wantBlock: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit := pythonWriteModeHit(tc.code)
			gotBlock := hit != ""
			if gotBlock != tc.wantBlock {
				t.Fatalf("pythonWriteModeHit(%q) = %q (block=%v), want block=%v", tc.code, hit, gotBlock, tc.wantBlock)
			}
			if tc.wantBlock && tc.wantSub != "" && !strings.Contains(hit, tc.wantSub) {
				t.Errorf("pythonWriteModeHit(%q) = %q, want substring %q", tc.code, hit, tc.wantSub)
			}
		})
	}
}

func TestR5_IsPythonImportStmtAtUnit(t *testing.T) {
	// 1. Multiline parenthesized `from ... import (...)` vs runtime call after `)`.
	src := "from logging.handlers import (\n    RotatingFileHandler,\n)\nRotatingFileHandler('audit.log')\n"
	first := strings.Index(src, "RotatingFileHandler")
	second := strings.LastIndex(src, "RotatingFileHandler")
	if first < 0 || second <= first {
		t.Fatalf("unexpected fixture indices: first=%d second=%d", first, second)
	}
	if !isPythonImportStmtAt(src, first) {
		t.Errorf("first RotatingFileHandler at %d inside multiline import (...) got false, want true", first)
	}
	if isPythonImportStmtAt(src, second) {
		t.Errorf("second RotatingFileHandler at %d on runtime call line got true, want false", second)
	}

	// 2. Direct R4-regression assertions (R4 returned true on all three due to `\n` skip).
	r4CrossLine := "import logging\nlogging.FileHandler"
	fhIdx := strings.Index(r4CrossLine, "FileHandler")
	if isPythonImportStmtAt(r4CrossLine, fhIdx) {
		t.Errorf("R4 regression: FileHandler at %d after bare newline got true, want false", fhIdx)
	}

	r4FromCrossLine := "from logging.handlers import RotatingFileHandler\nRotatingFileHandler"
	rfhSecond := strings.LastIndex(r4FromCrossLine, "RotatingFileHandler")
	if isPythonImportStmtAt(r4FromCrossLine, rfhSecond) {
		t.Errorf("R4 regression: second RotatingFileHandler at %d got true, want false", rfhSecond)
	}

	r4BareZip := "import zipfile\nzipfile.ZipFile\n"
	zfIdx := strings.Index(r4BareZip, "ZipFile")
	if isPythonImportStmtAt(r4BareZip, zfIdx) {
		t.Errorf("R4 regression: bare zipfile.ZipFile at %d got true, want false", zfIdx)
	}

	// 3. Direct M2-killer assertion: non-import parenthesized multiline call argument.
	m2Call := "foo(\n    FileHandler,\n)\n"
	m2Idx := strings.Index(m2Call, "FileHandler")
	if isPythonImportStmtAt(m2Call, m2Idx) {
		t.Errorf("M2 regression: FileHandler inside foo(...) at %d got true, want false", m2Idx)
	}

	// 4. CRLF backslash continuation vs bare CRLF newline.
	crlf := "from logging.handlers \\\r\n    import RotatingFileHandler\r\nRotatingFileHandler('audit.log')\r\n"
	cFirst := strings.Index(crlf, "RotatingFileHandler")
	cSecond := strings.LastIndex(crlf, "RotatingFileHandler")
	if !isPythonImportStmtAt(crlf, cFirst) {
		t.Errorf("CRLF continued import RotatingFileHandler at %d got false, want true", cFirst)
	}
	if isPythonImportStmtAt(crlf, cSecond) {
		t.Errorf("CRLF runtime RotatingFileHandler at %d got true, want false", cSecond)
	}
}

func TestR7_JSUnicodeIdentEscapeHit(t *testing.T) {
	jsCases := []struct {
		name      string
		code      string
		wantBlock bool
	}{
		{
			name:      "block-js-hex4-writefilesync",
			code:      "require('fs').\\u0077riteFileSync('js.txt', 'x')\n",
			wantBlock: true,
		},
		{
			name:      "block-js-codepoint-brace-writefilesync",
			code:      "require('fs').\\u{77}riteFileSync('js.txt', 'x')\n",
			wantBlock: true,
		},
		{
			name:      "block-js-hex4-execsync",
			code:      "const cp = require('child_process'); cp.\\u0065xecSync('id')\n",
			wantBlock: true,
		},
		{
			name:      "allow-js-unicode-escape-in-strings-and-comments",
			code:      "console.log('\\u00e9té'); // \\u0077riteFileSync café\nconst s = \"\\u{1F600}\";\n",
			wantBlock: false,
		},
		{
			name:      "allow-js-unicode-escape-in-template-literal",
			code:      "const n = 1;\nconsole.log(`café \\u00e9 ${n}`);\n",
			wantBlock: false,
		},
	}
	for _, tc := range jsCases {
		t.Run(tc.name, func(t *testing.T) {
			hit := jsUnicodeIdentEscapeHit(tc.code)
			gotBlock := hit != ""
			if gotBlock != tc.wantBlock {
				t.Fatalf("jsUnicodeIdentEscapeHit(%q) = %q (block=%v), want block=%v", tc.code, hit, gotBlock, tc.wantBlock)
			}
		})
	}
}

// === Merged from zz_r5adv_test.go ===

type r5adv struct {
	id   string
	want string // "A" or "B"
	code string
}

var r5advCases = []r5adv{
	// ---- pure imports: must ALLOW ----
	{"P-paren-alias-comment", "A", "from logging.handlers import (\n  RotatingFileHandler as RFH,  # c\n)\n"},
	{"P-paren-alias-comment-crlf", "A", "from logging.handlers import (\r\n  RotatingFileHandler as RFH,  # c\r\n)\r\n"},
	{"P-def-indented-from", "A", "def f():\n    from logging.handlers import RotatingFileHandler\n    return 1\n"},
	{"P-try-indented-from", "A", "try:\n    from logging.handlers import RotatingFileHandler\nexcept ImportError:\n    pass\n"},
	{"P-if-inline-colon", "A", "if True: from logging import FileHandler\n"},
	{"P-class-body", "A", "class A:\n    from logging import FileHandler\n"},
	{"P-multi-names", "A", "from logging import FileHandler, StreamHandler\n"},
	{"P-paren-single-line", "A", "from logging import (FileHandler)\n"},
	{"P-paren-trailing-comment", "A", "from logging.handlers import (\n    RotatingFileHandler\n)  # trailing\n"},
	{"P-paren-first-line-names", "A", "from logging.handlers import (RotatingFileHandler,\n    WatchedFileHandler)\n"},
	{"P-from-dot", "A", "from . import FileHandler\n"},
	{"P-from-dotdot", "A", "from .. import FileHandler\n"},
	{"P-from-dot-mod", "A", "from .handlers import WatchedFileHandler\n"},
	{"P-crlf", "A", "from logging import FileHandler\r\n"},
	{"P-semi-after-other", "A", "import os; from logging import FileHandler\n"},
	{"P-semi-before-other", "A", "from logging import FileHandler; import os\n"},
	{"P-comment-import-word", "A", "from logging import FileHandler  # import x\n"},
	{"P-tabs", "A", "from\tlogging.handlers\timport\tRotatingFileHandler\n"},
	{"P-backslash-names", "A", "from logging.handlers import RotatingFileHandler,\\\n    WatchedFileHandler\n"},
	{"P-import-mod-as", "A", "import logging.handlers as lh\n"},
	{"P-import-a-b", "A", "import os, logging\n"},
	{"P-zip-alias", "A", "from zipfile import ZipFile as Z\n"},
	{"P-zip-indented-try", "A", "try:\n    from zipfile import ZipFile\nexcept Exception:\n    ZipFile = None\n"},
	{"P-paren-trailing-comma-crlf", "A", "from logging.handlers import (\r\n    RotatingFileHandler,\r\n    WatchedFileHandler,\r\n)\r\n"},
	{"P-paren-empty-line", "A", "from logging.handlers import (\n\n    RotatingFileHandler,\n\n)\n"},
	{"P-string-has-call", "A", "from logging import FileHandler\nprint('FileHandler(\"/tmp/x\")')\n"},
	// ---- runtime uses: must BLOCK ----
	{"B-def-import-call", "B", "def f():\n    import logging\n    logging.FileHandler('a.log')\n"},
	{"B-try-import-call", "B", "try:\n    import logging\n    logging.FileHandler('a.log')\nexcept Exception:\n    pass\n"},
	{"B-if-semi", "B", "if True:\n    import logging; logging.FileHandler('a.log')\n"},
	{"B-semi", "B", "import logging; logging.FileHandler('a.log')"},
	{"B-semi-nospace", "B", "from logging import FileHandler;FileHandler('a.log')"},
	{"B-bs-semi", "B", "from logging import FileHandler \\\n;FileHandler('a.log')\n"},
	{"B-paren1-newline-call", "B", "from logging.handlers import (RotatingFileHandler)\nRotatingFileHandler('a.log')\n"},
	{"B-paren1-semi-call", "B", "from logging.handlers import (RotatingFileHandler); RotatingFileHandler('a.log')\n"},
	{"B-parenML-semi-call", "B", "from logging.handlers import (\n    RotatingFileHandler,\n); RotatingFileHandler('a.log')\n"},
	{"B-paren1-crlf-call", "B", "from logging.handlers import (RotatingFileHandler)\r\nRotatingFileHandler('a.log')\r\n"},
	{"B-import-crlf-call", "B", "import logging\r\nlogging.FileHandler('a.log')\r\n"},
	{"B-comment-import-then-call", "B", "# import logging\nlogging.FileHandler('a.log')\n"},
	{"B-string-import-then-call", "B", "x = 'import'\nlogging.FileHandler('a.log')\n"},
	{"B-import-a-b-call", "B", "import os, logging\nlogging.FileHandler('a.log')\n"},
	{"B-mod-alias-call", "B", "import logging as L\nL.FileHandler('a.log')\n"},
	{"B-paren-wrapped-attr", "B", "import logging\nh = (logging\n  .FileHandler('a.log'))\n"},
	{"B-bs-attr", "B", "import logging\nlogging.\\\nFileHandler('a.log')\n"},
	{"B-bs-before-call-line", "B", "import logging \\\n\nlogging.FileHandler('a.log')\n"},
	{"B-ref-print", "B", "import logging\nprint(logging.FileHandler)\n"},
	{"B-list", "B", "import logging\n[logging.FileHandler('a.log')]\n"},
	{"B-call-arg-ml", "B", "from logging import FileHandler\nfoo(\n    FileHandler,\n)\n"},
	{"B-paren-ref-ml", "B", "from logging import FileHandler\n(\n    FileHandler\n)('a.log')\n"},
	{"B-paren-ref-1", "B", "from logging import FileHandler\n(FileHandler)('a.log')\n"},
	{"B-tuple-ref", "B", "from logging import FileHandler\nx = (FileHandler,)\nx[0]('a.log')\n"},
	{"B-lambda", "B", "from logging import FileHandler\nf = lambda: FileHandler('a.log')\n"},
	{"B-yield-from-bare", "B", "def g():\n    yield from FileHandler\n"},
	{"B-raise-from", "B", "raise X from FileHandler('a.log')\n"},
	{"B-ifinline-call", "B", "if True: FileHandler('a.log')\n"},
	{"B-else-inline-call", "B", "if 0: pass\nelse: FileHandler('a.log')\n"},
	{"B-from-imp-then-indented-call", "B", "from logging import FileHandler\nif True:\n    FileHandler('a.log')\n"},
	{"B-zip-bare-indented", "B", "import zipfile\nif True:\n    zipfile.ZipFile\n"},
	{"B-zip-paren-ctor", "B", "import zipfile\n(zipfile.ZipFile)('b.zip', 'w')\n"},
	{"B-zip-paren-ml-ctor", "B", "from zipfile import ZipFile\n(\n  ZipFile\n)('b.zip', 'w')\n"},
	{"B-zip-ref-in-call-ml", "B", "from zipfile import ZipFile\nf(\n  ZipFile,\n)\n"},
	{"B-fileio-bare", "B", "import io\nio.FileIO\n"},
	{"B-zip-semi-bare", "B", "import zipfile; zipfile.ZipFile\n"},
	{"B-watched-bs-call", "B", "from logging.handlers import WatchedFileHandler\nWatchedFileHandler \\\n('a.log')\n"},
	{"B-handler-import-then-from-call-same", "B", "from logging import FileHandler as F, FileHandler\nFileHandler('a.log')\n"},
	{"B-timed-call", "B", "import logging.handlers\nlogging.handlers.TimedRotatingFileHandler('a.log')\n"},
	{"B-walrus", "B", "import logging\n(h := logging.FileHandler('a.log'))\n"},
	{"B-decorator", "B", "import logging\n@logging.FileHandler\ndef f(): pass\n"},
	{"B-fstring", "B", "import logging\nf\"{logging.FileHandler('a.log')}\"\n"},
	// ---- semantic aliasing / other routes (design questions; expected BLOCK for fail-closed) ----
	{"S-from-alias-call", "B", "from logging import FileHandler as F\nF('/tmp/x.log')\n"},
	{"S-paren-alias-call", "B", "from logging.handlers import (\n  RotatingFileHandler as R,\n)\nR('/tmp/x.log')\n"},
	{"S-zip-alias-write", "B", "from zipfile import ZipFile as Z\nZ('/tmp/x.zip', 'w').writestr('a', 'b')\n"},
	{"S-fileio-alias-write", "B", "from io import FileIO as F\nF('/tmp/x', 'w').write(b'x')\n"},
	{"S-pyzip-alias-write", "B", "from zipfile import PyZipFile as P\nP('/tmp/x.zip', 'w')\n"},
	{"S-basicconfig-filename", "B", "import logging\nlogging.basicConfig(filename='/tmp/x.log')\nlogging.warning('x')\n"},
	{"S-getattr-handler", "B", "import logging\ngetattr(logging, 'FileHandler')('/tmp/x.log')\n"},
}

func TestAUProbeR5(t *testing.T) {
	for _, c := range r5advCases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			got := auGuard(t, auCase{id: c.id, role: "scout", lang: "python", cmd: c.code})
			auPrint("R5ADV-scout-"+c.want+"-"+c.id, "scout", got)
			got2 := auGuard(t, auCase{id: c.id, role: "worker", ro: "1", argv: []string{"python3", "-"}, stdin: c.code})
			auPrint("R5ADV-roworker-"+c.want+"-"+c.id, "worker", got2)
		})
	}
}

// === Merged from zz_r5direct_test.go ===

func TestR5Direct(t *testing.T) {
	for _, c := range r5advCases {
		m := pythonMask(c.code)
		if len(m) != len(c.code) {
			fmt.Printf("MASKLEN\t%s\t%d!=%d\n", c.id, len(m), len(c.code))
		}
		hit := pythonWriteModeHit(c.code)
		v := "A"
		if hit != "" {
			v = "B"
		}
		mark := "ok"
		if v != c.want {
			mark = "MISMATCH"
		}
		fmt.Printf("DIRECT\t%s\twant=%s\tgot=%s\t%s\t%q\n", c.id, c.want, v, mark, hit)
	}
}

// === Merged from zz_r6adv_test.go ===

type r6adv struct {
	id   string
	want string
	code string
}

var r6advCases = []r6adv{
	// ---- alias forms: must BLOCK ----
	{"AL-from-F", "B", "from logging import FileHandler as F\nF('/tmp/x.log')\n"},
	{"AL-paren-R", "B", "from logging.handlers import (\n  RotatingFileHandler as R,\n)\nR('/tmp/x.log')\n"},
	{"AL-zip-Z", "B", "from zipfile import ZipFile as Z\nZ('/tmp/x.zip', 'w').writestr('a', 'b')\n"},
	{"AL-fileio", "B", "from io import FileIO as F\nF('/tmp/x', 'w').write(b'x')\n"},
	{"AL-pyzip", "B", "from zipfile import PyZipFile as P\nP('/tmp/x.zip', 'w')\n"},
	{"AL-multi-second", "B", "from logging.handlers import RotatingFileHandler as R, WatchedFileHandler as W\nW('a.log')\n"},
	{"AL-double-as", "B", "from zipfile import ZipFile as Z, ZipFile as Y\nY('a.zip', 'w')\n"},
	{"AL-chain-assign", "B", "from zipfile import ZipFile as Z\nZ2 = Z\nZ2('a.zip', 'w')\n"},
	{"AL-semi", "B", "from zipfile import ZipFile as Z; Z('a.zip', 'w')\n"},
	{"AL-bs-before-as", "B", "from zipfile import ZipFile \\\n    as Z\nZ('a.zip', 'w')\n"},
	{"AL-bs-after-as", "B", "from zipfile import ZipFile as \\\n    Z\nZ('a.zip', 'w')\n"},
	{"AL-paren-nl-before-as", "B", "from zipfile import (\n    ZipFile\n    as Z,\n)\nZ('a.zip', 'w')\n"},
	{"AL-paren-comment-before-as", "B", "from zipfile import (ZipFile  # c\n    as Z)\nZ('a.zip', 'w')\n"},
	{"AL-paren-nl-after-as", "B", "from zipfile import (ZipFile as\n    Z)\nZ('a.zip', 'w')\n"},
	{"AL-crlf", "B", "from zipfile import ZipFile as Z\r\nZ('a.zip', 'w')\r\n"},
	{"AL-tabs", "B", "from zipfile import ZipFile\tas\tZ\nZ('a.zip', 'w')\n"},
	{"AL-nested-def", "B", "def f():\n    from zipfile import ZipFile as Z\n    return Z('a.zip', 'w')\nf()\n"},
	{"AL-use-before-import", "B", "def p():\n    return Z('a.zip', 'w')\nfrom zipfile import ZipFile as Z\np()\n"},
	{"AL-class-attr", "B", "class C:\n    from zipfile import ZipFile as Z\nC.Z('a.zip', 'w')\n"},
	{"AL-kw-mode", "B", "from zipfile import ZipFile as Z\nZ('a.zip', mode='a')\n"},
	{"AL-var-mode", "B", "from zipfile import ZipFile as Z\nm = 'w'\nZ('a.zip', m)\n"},
	{"AL-star-args", "B", "from zipfile import ZipFile as Z\na = ('a.zip', 'w')\nZ(*a)\n"},
	{"AL-fileio-opener", "B", "from io import FileIO as F\nF('a', 'r', True, lambda p, f: 3)\n"},
	{"AL-fileio-rplus", "B", "from io import FileIO as F\nF('a', 'r+')\n"},
	{"AL-concat-mode", "B", "from io import FileIO as F\nF('a', 'r' '+')\n"},
	{"AL-handler-ref", "B", "from logging import FileHandler as F\nprint(F)\n"},
	{"AL-handler-dict", "B", "from logging import FileHandler as F\nd = {'h': F}\n"},
	{"AL-unicode-alias", "B", "from zipfile import ZipFile as \u00e9Z\n\u00e9Z('a.zip', 'w')\n"},
	{"AL-unicode-alias-handler", "B", "from logging import FileHandler as \u00e9F\n\u00e9F('a.log')\n"},
	{"NFKC-fullwidth-zipfile", "B", "import zipfile\nzipfile.\uff3aipFile('a.zip', 'w')\n"},
	{"NFKC-fullwidth-handler", "B", "import logging\nlogging.\uff26ileHandler('a.log')\n"},
	{"NFKC-fullwidth-open", "B", "\uff4fpen('a.txt', 'w').write('x')\n"},
	{"AL-star", "B", "from zipfile import *\nZipFile('a.zip', 'w')\n"},
	{"AL-dunder-import", "B", "__import__('zipfile').ZipFile('a.zip', 'w')\n"},
	{"AL-sysmodules", "B", "import sys, zipfile\nsys.modules['zipfile'].ZipFile('a.zip', 'w')\n"},
	{"AL-open-io-alias", "B", "from io import open as o\no('a.txt', 'w').write('x')\n"},
	{"AL-open-builtins-alias", "B", "from builtins import open as o\no('a.txt', 'w').write('x')\n"},
	{"AL-open-gzip-alias", "B", "from gzip import open as go\ngo('a.gz', 'wb').write(b'x')\n"},
	{"AL-open-assign", "B", "o = open\no('a.txt', 'w').write('x')\n"},
	{"AL-io-module-alias-open", "B", "import io as I\nI.open('a.txt', 'w').write('x')\n"},
	{"AL-os-open-alias", "B", "from os import open as oo, O_WRONLY, O_CREAT\noo('a.txt', O_WRONLY | O_CREAT)\n"},
	// ---- logging config entries: must BLOCK ----
	{"LG-bc-filename", "B", "import logging\nlogging.basicConfig(filename='a.log')\n"},
	{"LG-bc-ml", "B", "import logging\nlogging.basicConfig(\n    level=10,\n    filename='a.log',\n)\n"},
	{"LG-bc-alias", "B", "from logging import basicConfig as bc\nbc(filename='a.log')\n"},
	{"LG-bc-rebind", "B", "import logging\nb = logging.basicConfig\nb(filename='a.log')\n"},
	{"LG-bc-kw", "B", "import logging\nkw = {'filename': 'a.log'}\nlogging.basicConfig(**kw)\n"},
	{"LG-bc-handlers", "B", "import logging\nlogging.basicConfig(handlers=[logging.FileHandler('a.log')])\n"},
	{"LG-bc-stream-open", "B", "import logging\nlogging.basicConfig(stream=open('a.log', 'w'))\n"},
	{"LG-dict-alias", "B", "from logging.config import dictConfig as dc\ndc({'version': 1})\n"},
	{"LG-dict-modalias", "B", "import logging.config as lc\nlc.dictConfig({'version': 1})\n"},
	{"LG-DictConfigurator", "B", "import logging.config\nlogging.config.DictConfigurator({'version': 1, 'handlers': {'f': {'class': 'logging.FileHandler', 'filename': 'a.log'}}, 'root': {'handlers': ['f']}}).configure()\n"},
	{"LG-dictConfigClass", "B", "import logging.config\nlogging.config.dictConfigClass({'version': 1, 'handlers': {'f': {'class': 'logging.FileHandler', 'filename': 'a.log'}}, 'root': {'handlers': ['f']}}).configure()\n"},
	{"LG-BaseRotatingHandler", "B", "import logging.handlers\nlogging.handlers.BaseRotatingHandler('a.log', 'a')\n"},
	{"LG-install-handlers", "B", "import logging.config, configparser\ncp = configparser.ConfigParser()\ncp.read_string('[handlers]\\nkeys=f\\n[handler_f]\\nclass=FileHandler\\nargs=(\\'a.log\\',)\\n')\nlogging.config._install_handlers(cp, {})\n"},
	{"LG-fileconfig-alias", "B", "from logging.config import fileConfig as fc\nfc('a.ini')\n"},
	{"LG-listen-modalias", "B", "from logging import config as c\nc.listen(9999)\n"},
	{"LG-listen-from", "B", "from logging.config import listen\nlisten(9999).start()\n"},
	// ---- reflection: must BLOCK (her §3 claims) ----
	{"RF-getattr", "B", "import logging\ngetattr(logging, 'FileHandler')('a.log')\n"},
	{"RF-dict", "B", "import logging.handlers\nlogging.handlers.__dict__['FileHandler']('a.log')\n"},
	{"RF-vars", "B", "import logging\nvars(logging)['FileHandler']('a.log')\n"},
	{"RF-globals", "B", "from logging import *\nglobals()['FileHandler']('a.log')\n"},
	{"RF-locals", "B", "from logging import *\nlocals()['FileHandler']('a.log')\n"},
	{"RF-dict-get", "B", "import builtins\nbuiltins.__dict__.get('open')('a.txt', 'w')\n"},
	{"RF-getattribute", "B", "import builtins\nbuiltins.__getattribute__('open')('a.txt', 'w')\n"},
	// ---- must ALLOW ----
	{"OK-alias-zip-read", "A", "from zipfile import ZipFile as Z\nwith Z('a.zip') as z:\n    print(z.namelist())\n"},
	{"OK-alias-zip-read-r", "A", "from zipfile import ZipFile as Z\nwith Z('a.zip', 'r') as z:\n    print(z.namelist())\n"},
	{"OK-alias-zip-str-mention", "A", "from zipfile import ZipFile as Z\nwith Z('a.zip') as z:\n    print(\"Z(1,'w')\")\n"},
	{"OK-zip-ml-r", "A", "import zipfile\nwith zipfile.ZipFile(\n    'a.zip',\n    'r',\n) as z:\n    print(z.namelist())\n"},
	{"OK-zip-kw-r", "A", "import zipfile\nz = zipfile.ZipFile('a.zip', mode = \"r\", allowZip64=True)\n"},
	{"OK-zip-bytesio", "A", "import io, zipfile\nz = zipfile.ZipFile(io.BytesIO(b''))\n"},
	{"OK-zip-r-compress", "A", "import zipfile\nz = zipfile.ZipFile('a.zip', 'r', zipfile.ZIP_DEFLATED)\n"},
	{"OK-fileio-rb", "A", "import io\nio.FileIO('a', 'rb').read()\n"},
	{"OK-fileio-fd", "A", "import io\nio.FileIO(0).read(1)\n"},
	{"OK-alias-handler-unused-paren", "A", "from logging.handlers import (\n  RotatingFileHandler as RFH,  # c\n)\n"},
	{"OK-bc-none", "A", "import logging\nlogging.basicConfig()\n"},
	{"OK-bc-level-fmt", "A", "import logging\nlogging.basicConfig(level=logging.INFO, format='%(message)s filename=x')\n"},
	{"OK-socket-listen", "A", "import socket\ns = socket.socket()\ns.listen(5)\n"},
	{"OK-config-dict", "A", "config = {'listen': 1}\nprint(config.get('listen'))\n"},
	{"OK-config-attr-listen", "A", "import argparse\nconfig = argparse.Namespace(listen=1)\nprint(config.listen)\n"},
	{"OK-getattr-benign", "A", "import sys\nprint(getattr(sys, 'version', ''), vars(sys).get('platform'))\n"},
	{"OK-getattr-lineno", "A", "import ast\nfor n in ast.walk(ast.parse('x')):\n    print(getattr(n, 'lineno', None))\n"},
	{"OK-hasattr-open", "A", "import io\nprint(hasattr(io, 'open'))\n"},
	{"OK-getattr-args-system", "A", "import argparse\nargs = argparse.Namespace(system='x')\nprint(getattr(args, 'system', None))\n"},
	{"OK-plain-read", "A", "print(open('a.txt').read())\n"},
	{"OK-logging-getlogger", "A", "import logging\nlog = logging.getLogger(__name__)\nlog.info('x')\n"},
	{"OK-logging-streamhandler", "A", "import logging, sys\nlogging.getLogger().addHandler(logging.StreamHandler(sys.stderr))\n"},
	{"OK-from-io-stringio-as", "A", "from io import StringIO as S\nprint(S('x').read())\n"},
	{"OK-json-config", "A", "import json\nconfig = json.load(open('c.json'))\nprint(config['x'])\n"},
}

func TestAUProbeR6(t *testing.T) {
	for _, c := range r6advCases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			got := auGuard(t, auCase{id: c.id, role: "scout", lang: "python", cmd: c.code})
			auPrint("R6ADV-scout-"+c.want+"-"+c.id, "scout", got)
		})
	}
}

func TestR6Direct(t *testing.T) {
	for _, c := range r6advCases {
		if m := pythonMask(c.code); len(m) != len(c.code) {
			fmt.Printf("MASKLEN\t%s\n", c.id)
		}
		hit := pythonWriteModeHit(c.code)
		v := "A"
		if hit != "" {
			v = "B"
		}
		mark := "ok"
		if v != c.want {
			mark = "MISMATCH"
		}
		fmt.Printf("DIRECT\t%s\twant=%s\tgot=%s\t%s\t%q\n", c.id, c.want, v, mark, hit)
	}
}

// === Merged from zz_r6adv2_test.go ===

func TestR6Adv2(t *testing.T) {
	py := []string{
		"import logging.config\nlogging.config._resolve('logging.FileHandler')('a.log')\n",
		"import logging.config\nlogging.config.BaseConfigurator({}).resolve('logging.FileHandler')('a.log')\n",
		"import pkgutil\npkgutil.resolve_name('logging:FileHandler')('a.log')\n",
		"import pydoc\npydoc.locate('logging.FileHandler')('a.log')\n",
		"from logging.handlers import BaseRotatingHandler as B\nB('a.log', 'a')\n",
		"import logging\n\uff4cogging.FileHandler('a.log')\n",
		"print('\u00e9t\u00e9')\n# caf\u00e9\n",
	}
	for _, c := range py {
		got := auGuard(t, auCase{role: "scout", lang: "python", cmd: c})
		fmt.Printf("ADV2PY\t%q\t%s\n", c, got)
	}
	js := []string{
		"require('fs').\\u0077riteFileSync('js.txt', 'x')\n",
		"require('fs').writeFileSync('js.txt', 'x')\n",
	}
	for _, lang := range []string{"javascript", "node", "js"} {
		for _, c := range js {
			got := auGuard(t, auCase{role: "scout", lang: lang, cmd: c})
			fmt.Printf("ADV2JS\t%s\t%q\t%s\n", lang, c, got)
		}
	}
}

// === Merged from zz_r7adv_test.go ===

func r7load(t *testing.T, p string) [][2]string {
	b, err := os.ReadFile(p)
	if err != nil {
		// Local audit fixtures live under /root on the dev host only;
		// skip (do not fail) when they are not available, e.g. on CI.
		t.Skip(err)
	}
	var out [][2]string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		f := strings.SplitN(l, "\t", 2)
		out = append(out, [2]string{f[0], strings.ReplaceAll(f[1], `\n`, "\n")})
	}
	return out
}

func TestR7Adv(t *testing.T) {
	for _, c := range r7load(t, "/root/r7in/adv/cases_py.tsv") {
		got := auGuard(t, auCase{id: c[0], role: "scout", lang: "python", cmd: c[1]})
		fmt.Printf("R7ADV\tpython\t%s\t%s\n", c[0], got)
	}
	for _, c := range r7load(t, "/root/r7in/adv/cases_js.tsv") {
		for _, lang := range []string{"javascript", "node", "js"} {
			got := auGuard(t, auCase{id: c[0], role: "scout", lang: lang, cmd: c[1]})
			fmt.Printf("R7ADV\t%s\t%s\t%s\n", lang, c[0], got)
		}
	}
}

// === Merged from zz_r7reg_test.go ===

func TestR7Reg(t *testing.T) {
	for _, c := range r7load(t, "/root/r7in/adv/cases_reg.tsv") {
		got := auGuard(t, auCase{id: c[0], role: "scout", lang: "python", cmd: c[1]})
		fmt.Printf("R7REG\tpython\t%s\t%s\n", c[0], got)
	}
}
