package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

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

// ---------------------------------------------------------------------------
// v6.2.2 待办 1: Python `--` 长选项解析统一收敛 —
// --check-hash-based-pycs 两种形态（=val / 空格分隔）在任何守卫入口都不再
// 逃逸，未知 Python `--` 长选项保守 fail-closed，合法查询长选项保持放行。
// ---------------------------------------------------------------------------

func TestGuard_V622_PythonLongOpts(t *testing.T) {
	blockCases := []struct {
		name, role, ro, cmd string
		want                string
	}{
		// 粘连值形态：基线误把 heck-hash-based-pycs=default 当 -c 载荷放行。
		{"v622-1a glued -c", "worker", "", `python3 --check-hash-based-pycs=default -c 'import os; os.system("pig")'`, "python"},
		// worker+ro=1（strict readonly verifier 模型）：基线漏审 python 写文件载荷。
		{"v622-1b verifier write", "worker", "1", `python3 --check-hash-based-pycs default -c "open('out.txt', 'w')"`, "python"},
		// worker 嵌套代理守卫：-c 载荷含 pig，基线借长选项逃逸。
		{"v622-1b2 worker subagent write", "worker", "", `python3 --check-hash-based-pycs default -c "open('out.txt', 'w'); import os; os.system('pig')"`, "python"},
		// 空格分隔形态："default" 不得提前终止选项区扫描。
		{"v622-1c xargs -c feed", "worker", "", `echo 'import os; os.system("pig")' | xargs python3 --check-hash-based-pycs default -c`, "BLOCK"},
		{"v622-1d find -exec -c", "worker", "", `find . -exec python3 --check-hash-based-pycs default -c '{}' \;`, "BLOCK"},
		{"v622-1e1 -m after long", "worker", "", `python3 --check-hash-based-pycs default -m pig`, "pig"},
		{"v622-1e2 -um glued", "worker", "", `python3 -um pig`, "pig"},
		// 未知 Python 长选项（--jit off）：操作数 arity 不可知，fail-closed。
		{"v622-1f unknown long", "worker", "", `python3 --jit off -c 'import os; os.system("pig")'`, "BLOCK"},
		{"v622-1f2 missing mode", "worker", "", `python3 --check-hash-based-pycs -c 'print(1)'`, "BLOCK"},
		{"v622-1f3 bad mode", "worker", "", `python3 --check-hash-based-pycs=bogus -c 'print(1)'`, "BLOCK"},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: tc.role, ro: tc.ro, cmd: tc.cmd}, "")
			if tc.want == "BLOCK" {
				if got == "ALLOW" {
					t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want substring %q", tc.cmd, got, tc.want)
			}
		})
	}
	allowCases := []struct {
		name, role, ro, cmd string
	}{
		{"worker python3 --version", "worker", "", `python3 --version`},
		{"verifier python3 --version", "verifier", "", `python3 --version`},
		{"worker python3 --help-all", "worker", "", `python3 --help-all`},
		{"worker pycs then --version", "worker", "", `python3 --check-hash-based-pycs=default --version`},
		{"worker pycs benign -c", "worker", "", `python3 --check-hash-based-pycs default -c 'print(1)' "$HOME"`},
		{"worker script custom flag", "worker", "", `python3 app.py --custom-flag val`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: tc.role, ro: tc.ro, cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// v6.2.2 待办 2: JavaScript 族拆族 — bun/ts-node/tsx 不再与 node/nodejs
// 共享结构族；跨名软链（bun -> node）conflicting structural alias fail-
// closed，真实 bun/tsx 自身的 -p/--print 内联代码也被拦截；node <-> nodejs
// 同族合法软链保持放行。
// ---------------------------------------------------------------------------

func TestGuard_V622_JSFamilySplit(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	binDir := filepath.Join(fakeHome, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("mkdir binDir: %v", err)
	}
	writeTestExecutable(t, filepath.Join(binDir, "node"), 0755)
	for _, name := range []string{"bun", "tsx"} {
		if err := os.Symlink(filepath.Join(binDir, "node"), filepath.Join(binDir, name)); err != nil {
			t.Fatalf("symlink %s -> node: %v", name, err)
		}
	}
	pathEnv := binDir + ":" + os.Getenv("PATH")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", pathEnv)
	for _, tc := range []struct {
		name, cmd string
	}{
		{"v622-2a bun symlink", `bun -p 'require("child_process").execSync("pig")'`},
		{"v622-2b tsx symlink", `tsx -p 'require("child_process").execSync("pig")'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want conflicting structural alias block", tc.cmd)
			}
		})
	}
	// Direct bun -p with no symlink at all: -p is inline code and must hit
	// the nested-agent scan even when resolution finds nothing. The PATH
	// restore must re-bind the ORIGINAL PATH — re-reading os.Getenv after
	// t.Setenv would hand back the already-modified value and keep the
	// bun -> node symlink visible (v6.2.2 Oracle R1 Obs-2).
	t.Setenv("PATH", origPath)
	t.Run("v622-2c direct bun -p", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "v622-2c", role: "worker", cmd: `bun -p 'require("child_process").execSync("pig")'`}, "")
		if !strings.Contains(got, "javascript inline code") {
			t.Fatalf("direct bun -p = %q, want javascript inline code block", got)
		}
	})
	// node -> nodejs is the same distro family: the inline code is
	// screened under the shared node grammar, never a conflicting alias.
	writeTestExecutable(t, filepath.Join(binDir, "nodejs"), 0755)
	if err := os.Remove(filepath.Join(binDir, "node")); err != nil {
		t.Fatalf("remove node stub: %v", err)
	}
	if err := os.Symlink(filepath.Join(binDir, "nodejs"), filepath.Join(binDir, "node")); err != nil {
		t.Fatalf("symlink node -> nodejs: %v", err)
	}
	t.Setenv("PATH", pathEnv)
	t.Run("node->nodejs same family no conflict", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "v622-node-nodejs", role: "worker", argv: []string{"node", "-p", "1+1"}}, "")
		if strings.Contains(got, "conflicting structural alias") {
			t.Fatalf("node -> nodejs = %q, want no conflicting structural alias", got)
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 待办 3: replTokenInExecSlot / xargsFeedsCodeFlag 受限递归穿透 —
// 二层 xargs / flock -c / watch -x / script -qc / find -okdir / 悬空 env
// 包装器与 peelChainMaxDepth 深度上限全部 fail-closed；数据位 {} 保持放行。
// ---------------------------------------------------------------------------

func TestGuard_V622_MultiLayerExecSlots(t *testing.T) {
	blockCases := []struct {
		name, cmd string
	}{
		{"v622-3a xargs flock -c", `echo pig | xargs -I{} flock -x /dev/null -c '{}'`},
		{"v622-3b find xargs sh -c", `find . -exec xargs sh -c {} \;`},
		{"v622-3c1 xargs watch -x repl", `echo pig | xargs -I{} watch -x sh -c '{}'`},
		{"v622-3c2 xargs watch -x open", `echo pig | xargs watch -x sh -c`},
		{"v622-3d1 find -okdir flock cmd", `xargs -I% find . -okdir flock /tmp/lk --command='%' \;`},
		{"v622-3d2 script -qc token", `xargs -I{} script -qc '{}' /dev/null`},
		{"v622-3d3 dangling env", `echo pig | xargs env`},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want dynamic code payload block", tc.cmd)
			}
		})
	}
	allowCases := []struct {
		name, cmd string
	}{
		{"flock data operand", `find . -exec flock /tmp/lk grep foo {} \;`},
		{"watch -x data operand", `echo foo | xargs -I{} watch -x grep foo {}`},
		{"find path-position token", `echo x | xargs -I{} find {} -maxdepth 1 -name '*.go'`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
	// v622-3e: 25 层 watch -x 嵌套直达 peelChainMaxDepth (24) — 两处直接
	// 单测入口都必须 fail-closed。
	t.Run("v622-3e depth cap", func(t *testing.T) {
		deep := []string{"echo", "safe"}
		for n := 0; n < 25; n++ {
			deep = append([]string{"watch", "-x"}, deep...)
		}
		caller := callerIdentity{}
		if !replTokenInExecSlot(deep, "{}", os.Getenv("PATH"), caller) {
			t.Fatalf("replTokenInExecSlot 25-layer watch -x = false, want depth-cap fail-closed")
		}
		if !xargsFeedsCodeFlag(deep, nil, os.Getenv("PATH"), caller) {
			t.Fatalf("xargsFeedsCodeFlag 25-layer watch -x = false, want depth-cap fail-closed")
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R1: MF-1〜MF-9 / SF-1〜SF-5 / Obs-1〜Obs-2 探针回归 —
// Python -c/-m 后选项区终止与 -uW/-uX 短簇四处同构、bun -c/node -r/php -c
// 值槽动态拦截、npm 族结构头与 shell --rcfile、env -S 包装链扫描、递归
// caller 重锚、find 谓词/尾部追加/-fprintf 二元 arity、占位符非首词注入、
// script/flock 选项状态机、xargs --r* 缩写、awk/sed/tar/git -c 执行槽、
// find -H/-L/-P 前置标志豁免。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR1Probes(t *testing.T) {
	blockCases := []struct {
		name, cmd string
	}{
		// MF-2: -uW/-uX 短簇消费下一 argv 后，$OPT 动态词与非法长选项均 fail-closed。
		{"P-MF2-a -uW dynOPT", `OPT=-c; python3 -uW ignore "$OPT" 'import os; os.system("pig")'`},
		{"P-MF2-b -uW unknown long", `python3 -uW ignore --jit off -c 'import os; os.system("pig")'`},
		{"P-MF2-c -uW bad pycs", `python3 -uW ignore --check-hash-based-pycs=bogus -c 'import os; os.system("pig")'`},
		{"P-MF2-f xargs -0 feed", `printf '%s\0' -c 'import os; os.system("pig")' | xargs -0 python3 -uW ignore`},
		// MF-3: bun -c 是 bunfig 值槽而非代码标志——动态操作数 fail-closed。
		{"P-MF3-a bun -c $X", `X='a.toml -e require("child_process").execSync("pig")'; bun -c $X`},
		// MF-4b: shell --rcfile/--init-file 值槽消费与非 /dev/null fail-closed。
		{"P-MF4b-1 bash rcfile -c", `bash --rcfile /etc/profile -c 'pig'`},
		{"P-MF4b-2 xargs rcfile open -c", `echo pig | xargs bash --rcfile /dev/null -c`},
		{"P-MF4b-3 find rcfile -c", `find . -exec bash --rcfile /etc/profile -c '{}' \;`},
		{"P-MF4b-4 pipe rcfile stdin", `echo pig | bash --rcfile /dev/null`},
		// MF-5: env -S 分词注入——前导包装器/赋值/裸 '-'/GNU 缩写全线拦截。
		{"P-MF5-a nice env -S", `echo "-e system('pig')" | xargs -I{} nice env -S 'perl {}'`},
		{"P-MF5-b FOO=1 env -S", `echo "-e system('pig')" | xargs -I{} FOO=1 env -S 'perl {}'`},
		{"P-MF5-c env - -S", `echo "-e system('pig')" | xargs -I{} env - -S 'perl {}'`},
		{"P-MF5-d env --split abbrev", `echo "-e system('pig')" | xargs -I{} env --split 'perl {}'`},
		// MF-7: find 路径位占位符全后缀扫描、尾部追加、-fprintf 二元 arity。
		{"P-MF7-a pathword exec suffix", `echo -exec | xargs -I% find . % pig ';'`},
		{"P-MF7-b append mode", `printf -- '-exec\npig\n;\n' | xargs find .`},
		{"P-MF7-c fprintf shift", `echo pig | xargs -I{} find . -fprintf /dev/null -exec -exec sh -c '{}' ';'`},
		// MF-8: shell/解释器选项区占位符、内层 xargs 选项位、flock 锁文件位、ssh 本地与远端注入。
		{"P-MF8-a sh opt zone", `echo -c | xargs -I% sh % 'pig'`},
		{"P-MF8-b python opt zone", `echo -c | xargs -I% python3 % 'import os; os.system("pig")'`},
		{"P-MF8-c inner xargs zone", `echo pig > /tmp/p && echo 'I{}' | xargs -I% xargs -a /tmp/p -% sh -c '{}'`},
		{"P-MF8-d flock lockfile zone", `echo -c | xargs -I% flock % 'sh -c pig' /dev/null`},
		{"P-MF8-e ssh dest zone", `echo '-oProxyCommand=pig' | xargs -I{} ssh {} dmit ls`},
		{"P-MF8-f1 ssh remote repl", `echo '; pig' | xargs -I{} ssh dmit 'echo {}'`},
		{"P-MF8-f2 ssh remote append", `echo '; pig' | xargs ssh dmit echo hi`},
		// MF-9: script -T 文件名字母 c 不再误判、flock 短簇/--/--fcntl 修正。
		{"P-MF9-a script -T open -c", `echo pig | xargs script -T/tmp/xc -c`},
		{"P-MF9-b script -T token -c", `echo pig | xargs -I{} script -T/tmp/c.log -c '{}' /dev/null`},
		{"P-MF9-c flock -xc cluster", `echo pig | xargs -I{} flock -xc '{}' /dev/null`},
		{"P-MF9-d flock -- then -c", `echo pig | xargs -I{} flock -- /dev/null -c '{}'`},
		{"P-MF9-e flock --fcntl boolean", `echo pig | xargs -I{} flock --fcntl /dev/null sh -c '{}'`},
		// SF-3: GNU xargs --r* 唯一前缀缩写。
		{"SF3 xargs --repl", `echo pig | xargs --repl sh -c '{}'`},
		// SF-4: awk/sed/tar/git -c 执行槽。
		{"SF4 awk program", `echo 'BEGIN{system("pig")}' | xargs -I{} awk '{}' /dev/null`},
		{"SF4 sed script", `echo '1e pig' | xargs -I{} sed '{}' /dev/null`},
		{"SF4 tar checkpoint-action", `echo 'pig' | xargs -I{} tar --checkpoint=1 --checkpoint-action=exec='{}' -cf /dev/null /dev/null`},
		{"SF4 git -c pager", `echo 'pig' | xargs -I{} git -c core.pager='{}' log`},
		// SF-5: node --input-type 入 longValue 后动态/静态错位不再逃逸。
		{"SF5 node --input-type", `node --input-type commonjs -e 'require("child_process").execSync("pig")'`},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
		})
	}
	// MF-1 功能回归与 Obs-1 假阳性豁免：以下合法调用必须放行。
	allowCases := []struct {
		name, cmd string
	}{
		{"P-MF1-a pytest module", `python3 -m pytest --cov=x`},
		{"P-MF1-b json.tool module", `python3 -m json.tool --sort-keys`},
		{"P-MF1-c -c then script args", `python3 -c 'import sys; print(sys.argv)' --foo`},
		{"P-OBS1 find -L path token", `echo src | xargs -I{} find -L {} -name '*.go'`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
	// P-MF2-d: screenReadonlyWrite 对 -uX 携带值与粘连 -c 的只读文件运行拦截。
	t.Run("P-MF2-d readonly -uX", func(t *testing.T) {
		if got := screenReadonlyWrite([]string{"python3", "-uX", "--version", "evil.py"}); got == "" {
			t.Fatalf("screenReadonlyWrite python3 -uX --version evil.py = empty, want python3 block")
		}
	})
	t.Run("P-MF2-d2 readonly glued -c", func(t *testing.T) {
		if got := screenReadonlyWrite([]string{"python3", "-c__import__('os').system('touch /tmp/pwn')", "--version"}); got == "" {
			t.Fatalf("screenReadonlyWrite glued -c --version = empty, want python3 block")
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R2 (R3 闭环): R2-MF-1..7 / R2-SF-1..4 / R2-Obs-1..2 探针回归 —
// 长值选项 valueExact 统一消费与动态校验、pyInterpScanStep consumesNext 恢复
// 粘连 -m、sed/awk/git 复用仓内单源解析器、script -t optional_argument 与
// 位置参数置换、flock/xargs/tar GNU 唯一前缀缩写、ssh 短簇值操作数、xargs -a
// 与 argv+stdin 闭合、peelExecSlotHead canonical 变体写回、find 谓词表补齐、
// env -S 包装链约束扫描。每条 block 探针在修复前均为 ALLOW（或回归BLOCK），
// 每条 allow 探针钉住不得误伤的合法调用。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR2Probes(t *testing.T) {
	blockCases := []struct {
		name, cmd string
	}{
		// R2-MF-1: 非 Python 长值选项经 valueExact 统一消费并校验动态操作数。
		{"P-R2-MF1-a bash rcfile /dev/null $OPT", `OPT=-c; bash --rcfile /dev/null "$OPT" 'pig'`},
		{"P-R2-MF1-b bash double rcfile", `bash --rcfile /dev/null --rcfile /etc/profile -c 'pig'`},
		{"P-R2-MF1-c node --conditions --import", `X='a.js -e require("child_process").execSync("pig")'; node --conditions default --import $X`},
		{"P-R2-MF1-d bun --cwd -c", `X='a.toml -e require("child_process").execSync("pig")'; bun --cwd . -c $X`},
		{"P-R2-MF1-e node --input-type -r", `X='a.js -e require("child_process").execSync("pig")'; node --input-type commonjs -r $X`},
		{"P-R2-MF1-f node --require no reverse polarity", `X='a.js -e require("child_process").execSync("pig")'; node --require $X`},
		// R2-MF-2: spec 驱动短簇带值消费先查动态词再 i++。
		{"P-R2-MF2-c python3 -uW dyn", `X='ignore -c __import__("os").system("pig")'; python3 -uW $X`},
		{"P-R2-MF2-d bash -xo cluster", `bash -xo errexit --rcfile /etc/profile -c 'pig'`},
		{"P-R2-MF2-e sh -xo dynOPT", `OPT=-c; sh -xo errexit "$OPT" 'pig'`},
		{"P-R2-MF2-f perl -wI dyn", `X='/tmp -e system("pig")'; perl -wI /tmp -I $X`},
		{"P-R2-MF2-g perl -wI heredoc", "perl -wI /tmp <<'EOF'\nsystem(\"pig\")\nEOF"},
		// R2-MF-3: sed/awk/git 复用单源解析器后的绕过面。
		{"P-R2-MF3-d sed -ne glued", `echo '1e pig' | xargs -I{} sed -ne'{}' /etc/hosts`},
		{"P-R2-MF3-e sed --expr abbrev", `echo '1e pig' | xargs -I{} sed --expr='{}' /etc/hosts`},
		{"P-R2-MF3-f gawk -e glued", `echo 'BEGIN{system("pig")}' | xargs -I{} gawk -e'{}' /dev/null`},
		{"P-R2-MF3-g gawk --assign then token", `echo 'BEGIN{system("pig")}' | xargs -I{} gawk --assign x=1 '{}' /dev/null`},
		{"P-R2-MF3-h git -c bare token", `echo 'core.pager=pig' | xargs -I{} git -c '{}' log`},
		{"P-R2-MF3-i git optzone token", `echo '-c' | xargs -I% git % 'core.pager=pig' log`},
		{"P-R2-MF3-j git merge driver key", `echo 'pig' | xargs -I{} git -c 'merge.foo.driver={}' merge`},
		// R2-MF-4: script -t optional_argument / 长选项补全 / 位置参数置换;
		// flock GNU 唯一前缀缩写。
		{"P-R2-MF4-a script -t bare", `script -t -c 'pig' /dev/null`},
		{"P-R2-MF4-b xargs script -t", `echo pig | xargs -I{} script -t -c '{}' /dev/null`},
		{"P-R2-MF4-c script --timing bare", `script --timing -c 'pig' /dev/null`},
		{"P-R2-MF4-d script --log-io", `script --log-io /dev/null -c 'pig'`},
		{"P-R2-MF4-e script positional then -c", `script /dev/null -c 'pig'`},
		{"P-R2-MF4-f flock --com glued", `flock --com='pig' /dev/null`},
		{"P-R2-MF4-g flock --time separate", `flock --time 5 /dev/null -c 'pig'`},
		// R2-MF-5: ssh 短簇带值操作数不再冒充 destination。
		{"P-R2-MF5-a ssh -p operand", `echo '-oProxyCommand=pig' | xargs -I{} ssh -p 22 {} dmit ls`},
		// R2-MF-6: interpOptionZoneHasToken spec 驱动跳值、多 -e 继续扫描。
		{"P-R2-MF6-a python3 -W operand", `echo -c | xargs -I% python3 -W ignore % 'import os; os.system("pig")'`},
		{"P-R2-MF6-b sh -o operand", `echo -c | xargs -I% sh -o errexit % 'pig'`},
		{"P-R2-MF6-c bun -c value then token", `echo -e | xargs -I% bun -c a.toml % 'require("child_process").execSync("pig")'`},
		{"P-R2-MF6-d perl multi -e", `echo -e | xargs -I% perl -e '1' % 'system("pig")'`},
		{"P-R2-MF6-e php -r then token", `echo -r | xargs -I% php -r '1;' % 'system("pig");'`},
		{"P-R2-MF6-f script optzone token", `echo -c | xargs -I% script % 'pig' /dev/null`},
		// R2-SF-1..4: canonical 变体、find 谓词、xargs/tar GNU 缩写、stdin spec 派生。
		{"P-R2-SF1-a gfind canonical", `echo pig | xargs -I% gfind . -exec sh -c '%' ';'`},
		{"P-R2-SF2-a find -newermm shift", `find . -newermm -exec -exec pig ';'`},
		{"P-R2-SF3-a xargs --replace= empty", `echo pig | xargs --replace= sh -c '{}'`},
		{"P-R2-SF3-b xargs --max-a abbrev", `echo pig | xargs --max-a 1 -I{} sh -c '{}'`},
		{"P-R2-SF3-c tar -cI cluster", `echo 'pig' | xargs -I{} tar -cI '{}' -f /dev/null /dev/null`},
		{"P-R2-SF4-a bun --cwd stdin", `echo 'require("child_process").execSync("pig")' | bun --cwd . -`},
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
		// R2-MF-2 功能回归恢复:粘连 -m 后动态/通配参数是模块参数而非模块名。
		{"P-R2-MF2-a python3 -mjson.tool", `python3 -mjson.tool "$HOME/a.json"`},
		{"P-R2-MF2-b python3 -mpytest glob", `python3 -mpytest tests/*.py`},
		// R2-MF-3 功能回归恢复:-e/-f 之后输入文件名是数据。
		{"P-R2-MF3-a find sed -e", `find . -name '*.txt' -exec sed -e 's/foo/bar/' {} \;`},
		{"P-R2-MF3-b xargs sed -e", `echo foo.txt | xargs -I{} sed -e 's/foo/bar/' {}`},
		{"P-R2-MF3-c find awk -f", `find . -name '*.log' -exec awk -f parse.awk {} \;`},
		{"P-R2-MF3-a2 find sed -n -e", `find . -name '*.txt' -exec sed -n -e '1,5p' {} \;`},
		{"P-R2-MF3-a3 find sed -f", `find . -name '*.txt' -exec sed -f rules.sed {} \;`},
		// R2-MF-7 功能回归恢复:rg 参数位的 env -S 不触发包装链扫描。
		{"P-R2-MF7-b rg env -S operand", `find . -name '*.go' -exec rg env -S {} \;`},
		{"P-R2-MF7-b2 echo env -S operand", `echo foo | xargs -I{} echo env -S {}`},
		// R2-SF-2 假阳性恢复:-ctime 等时间谓词的值是数据。
		{"P-R2-SF2-b find -ctime value", `echo 5 | xargs -I{} find . -ctime {}`},
		// flock 正例:-xw 粘连簇与分离 -x -w 都正确解析到命令头 true。
		{"flock -xw 0 positive", `flock -xw 0 /dev/null true`},
		{"flock -x -w 30 positive", `flock -x -w 30 /dev/null true`},
		// script/typescript 合法调用不受选项区扫描误伤。
		{"script benign -c no token", `script -c 'echo hi' /tmp/out`},
		// R12 数据位保持:sh -c positional $1 与 git -C 路径值。
		{"R12 sh positional", `find . -exec sh -c 'echo "$1"' _ {} +`},
		{"R12 git -C data", `echo /tmp/repo | xargs -I{} git -C {} status`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// P-R2-MF5-b/c: xargs -a 文件喂词与 argv+stdin 两路闭合。文件用
	// t.TempDir() 预建——`printf ... > /tmp/p` 前置重定向会独立命中写拦截
	// 掩盖目标路径 (Reviewer should-fix),且断言精确 verdict 子串。
	t.Run("P-R2-MF5-b xargs -a file feed", func(t *testing.T) {
		payload := filepath.Join(t.TempDir(), "payload")
		if err := os.WriteFile(payload, []byte("-c\npig\n"), 0644); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		got := rtGuardCwd(t, rtCase{id: "P-R2-MF5-b", role: "worker", cmd: `xargs -a ` + payload + ` ssh dmit sh`}, "")
		if !strings.Contains(got, "ssh") {
			t.Fatalf("xargs -a payload ssh dmit sh = %q, want an ssh verdict block", got)
		}
	})
	t.Run("P-R2-MF5-c argv+stdin feed", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{
			id: "P-R2-MF5-c", role: "worker",
			argv:  []string{"xargs", "ssh", "dmit", "sh"},
			stdin: "-c pig",
		}, "")
		if !strings.Contains(got, "ssh") {
			t.Fatalf("argv xargs ssh dmit sh + stdin '-c pig' = %q, want an ssh verdict block", got)
		}
	})
	// R12 精确 verdict 不破坏:pipe 与 file-redir 两种传输必须各归其名。
	t.Run("R12 piped verdict exact", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R12-a", role: "worker", cmd: `echo code | xargs ssh dmit sh`}, "")
		if !strings.Contains(got, "piped stdin to ssh") {
			t.Fatalf("echo code | xargs ssh dmit sh = %q, want piped stdin to ssh", got)
		}
	})
	t.Run("R12 file-redir verdict exact", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R12-b", role: "worker", cmd: `xargs -a /tmp/items ssh dmit sh < /tmp/script.sh`}, "")
		if !strings.Contains(got, "file stdin to ssh stdin-program") {
			t.Fatalf("xargs -a file ssh dmit sh < redir = %q, want file stdin to ssh stdin-program", got)
		}
	})
}

// TestGuard_V622_OracleR2EnvCwd 覆盖 R2-MF-7 软链别名 env -S 注入
// (依赖文件系统软链布置,单独成组)。
func TestGuard_V622_OracleR2EnvCwd(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Symlink("/usr/bin/env", filepath.Join(cwd, "myenv")); err != nil {
		t.Fatalf("symlink myenv -> /usr/bin/env: %v", err)
	}
	t.Run("P-R2-MF7-a symlink alias env -S", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{
			id: "P-R2-MF7-a", role: "worker",
			cmd: `echo "-e system('pig')" | xargs -I{} ./myenv -S "perl -e '1' {}"`,
		}, cwd)
		if got == "ALLOW" {
			t.Fatalf("./myenv -S split injection = ALLOW, want a guard block")
		}
	})
	// P-MF2-e 补齐 (R2-Obs-1):-uW 后 heredoc 代码流同样拦截。
	t.Run("P-MF2-e python3 -uW heredoc", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{
			id: "P-MF2-e", role: "worker",
			cmd: "python3 -uW ignore <<'EOF'\nimport os; os.system(\"pig\")\nEOF",
		}, "")
		if got == "ALLOW" {
			t.Fatalf("python3 -uW ignore heredoc = ALLOW, want a guard block")
		}
	})
	// R2-Obs-1: 独立两字符 -c 后查询标志不得放行脚本文件运行。
	t.Run("P-R2-Obs1 readonly bare -c then --version", func(t *testing.T) {
		if got := screenReadonlyWrite([]string{"python3", "-c", "-1; open('/var/a','w').write('x')", "--version"}); got == "" {
			t.Fatalf("screenReadonlyWrite python3 -c <code> --version = empty, want python3 block")
		}
	})
}

// TestGuard_V622_OracleR1EnvCwd 覆盖 MF-4a 结构别名与 MF-6 env -C 重锚
// 递归 caller 修复(依赖文件系统软链布置,单独成组)。
func TestGuard_V622_OracleR1EnvCwd(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	binDir := filepath.Join(fakeHome, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("mkdir binDir: %v", err)
	}
	writeTestExecutable(t, filepath.Join(binDir, "npm-cli.js"), 0755)
	if err := os.Symlink(filepath.Join(binDir, "npm-cli.js"), filepath.Join(binDir, "bun")); err != nil {
		t.Fatalf("symlink bun -> npm-cli.js: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Run("P-MF4a bun->npm-cli.js conflict", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-MF4a", role: "worker", cmd: `bun exec -- pig`}, "")
		if !strings.Contains(got, "conflicting structural alias") {
			t.Fatalf("bun exec -- pig = %q, want conflicting structural alias", got)
		}
	})

	cwd := filepath.Join(fakeHome, "proj")
	sub := filepath.Join(cwd, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.Symlink("/bin/sh", filepath.Join(sub, "mysh")); err != nil {
		t.Fatalf("symlink mysh -> /bin/sh: %v", err)
	}
	mf6 := []struct {
		name, cmd string
	}{
		{"P-MF6-a env -C watch -x", `echo pig | xargs -I{} env -C sub watch -x ./mysh -c '{}'`},
		{"P-MF6-b env -C watch open", `echo pig | xargs env -C sub watch -x ./mysh -c`},
		{"P-MF6-c env -C flock", `echo pig | xargs -I{} env -C sub flock /dev/null ./mysh -c '{}'`},
		{"P-MF6-d env -C find -exec", `echo pig | xargs -I{} env -C sub find . -exec ./mysh -c '{}' ';'`},
		{"P-MF6-e env -C flock open", `echo pig | xargs env -C sub flock /dev/null ./mysh -c`},
	}
	for _, tc := range mf6 {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, cwd)
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R3 (R4 闭环): R3-MF-1..6 / R3-SF-1..2 / R3-Obs-1 探针回归 —
// tar 长数据选项与 BSD 首词、wrapperChainEnvSplitHasToken 单步剥离、flock
// 真实长选项表 fail-closed、script 置换扫描与 -E/--echo、多代码槽短簇操作数
// 消费与合法数据文件名恢复、git/awk/xargs -a ssh 三路残余绕过、node spec
// 单源收口。BLOCK 探针均断言目标 verdict 子串(不被上游管道/重定向规则掩盖),
// ALLOW 探针钉住 Reviewer R2-6 的合法数据语义。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR3Probes(t *testing.T) {
	// xargs -a / heredoc 用例的预建 payload(t.TempDir 避免前导重定向命中写
	// 拦截掩盖目标 verdict —— R3-Obs-2 测试隔离纪律)。
	payloadC := filepath.Join(t.TempDir(), "payload-c")
	if err := os.WriteFile(payloadC, []byte("-c\n"), 0644); err != nil {
		t.Fatalf("write payload-c: %v", err)
	}
	payloadCPig := filepath.Join(t.TempDir(), "payload-cpig")
	if err := os.WriteFile(payloadCPig, []byte("-c\npig\n"), 0644); err != nil {
		t.Fatalf("write payload-cpig: %v", err)
	}
	// R3/R5 探针的 xargs -a 无管道 payload(Oracle R4 精确 verdict 纪律:
	// 管道 echo 会被上游 piped code 规则掩盖目标 verdict,改用 -a 文件喂入)。
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadFooExec := mkPayload("payload-fooexec", "foo -exec pig ;\n")
	payloadCkpt := mkPayload("payload-ckpt", "a --checkpoint=1 --checkpoint-action=exec=pig\n")
	payloadDashE := mkPayload("payload-dashe", "-e\n")
	payloadBegin := mkPayload("payload-begin", "BEGIN{system(\"pig\")}\n")
	payloadCorePager := mkPayload("payload-cp", "core.pager\n")
	payloadPig := mkPayload("payload-pig", "pig\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R3-MF-1: tar 长数据选项消费操作数 + BSD 首词严格限定 argv[0]。
		{"P-R3-MF1-a tar --file swallow", `tar -c --file foo.tar --use-compress-program=pig /dev/null`, "pig"},
		{"P-R3-MF1-b tar --directory ckpt", `tar --directory /tmp/f --checkpoint=1 --checkpoint-action=exec=pig -cf /dev/null /dev/null`, "pig"},
		{"P-R3-MF1-c tar fstab nonfirst", `tar -cf /dev/null /etc/fstab --use-compress-program=pig`, "pig"},
		{"P-R3-MF1-d tar BSD cIf", `tar cIf pig /dev/null /dev/null`, "pig"},
		// R3-MF-2: 单步剥离包装链,nice/timeout/嵌套 env 不再跃过 env -S。
		{"P-R3-MF2-a nice env -S find", `xargs -a ` + payloadFooExec + ` -I{} nice env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R3-MF2-b timeout env -S", `xargs -a ` + payloadFooExec + ` -I{} timeout 10 env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R3-MF2-c env -- env -S", `xargs -a ` + payloadFooExec + ` -I{} env -- env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R3-MF2-d env -i env -S", `xargs -a ` + payloadFooExec + ` -I{} env -i env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R3-MF2-e nice env -S tar", `xargs -a ` + payloadCkpt + ` -I{} nice env -S "tar -cf /dev/null {}"`, "dynamic code payload"},
		// R3-MF-3: flock 真实长选项表 + 未知长选项 fail-closed。
		{"P-R3-MF3-a flock --no-fork", `flock --no-fork /dev/null pig`, "pig"},
		{"P-R3-MF3-c flock --f fcntl", `flock --f /dev/null pig`, "pig"},
		{"P-R3-MF3-d flock --nb", `flock --nb /dev/null pig`, "pig"},
		// R3-MF-5: 多代码槽短簇操作数消费后继续扫选项区。
		{"P-R3-MF5-a perl -we -I", `X='/tmp -e system("pig")'; perl -we '1' -I $X`, "dynamic code payload"},
		{"P-R3-MF5-b ruby -we -I", `X='/tmp -e system("pig")'; ruby -we '1' -I $X`, "dynamic code payload"},
		{"P-R3-MF5-c php -nr -c", `X='a.ini -r system("pig");'; php -nr '1;' -c $X`, "dynamic code payload"},
		{"P-R3-MF5-d node -pe -r", `X='a.js -e require("child_process").execSync("pig")'; node -pe '1' -r $X`, "dynamic code payload"},
		{"P-R3-MF5-e bun -pe -c", `X='a.toml -e require("child_process").execSync("pig")'; bun -pe '1' -c $X`, "dynamic code payload"},
		// R3-MF-5 攻击面补充: 代码槽后选项位占位符仍拦截。
		{"P-R3-MF5-f perl -e xargs %", `xargs -a ` + payloadDashE + ` -I% perl -e '1' % 'system("pig")'`, "dynamic code payload"},
		{"P-R3-MF5-g perl -e dash-%", `xargs -a ` + payloadDashE + ` -I% perl -e '1' -%`, "dynamic code payload"},
		// v6.2.2 R5 加固: 自定义/默认替换 token 位于非末尾位置时,其后方参数
		// 仍可被扩展武装成 -e/-r 代码操作数,不再依赖硬编码拼写名单。
		{"P-R5-a xargs -I{} perl trailing", `xargs -a ` + payloadDashE + ` -I{} perl -e '1' {} 'system("pig")'`, "dynamic code payload"},
		{"P-R5-b xargs -IFOO custom token", `xargs -a ` + payloadDashE + ` -IFOO perl -e '1' FOO 'system("pig")'`, "dynamic code payload"},
		// R3-MF-6: git/awk/xargs 三路残余绕过。
		{"P-R3-MF6-a git -c key-side", `xargs -a ` + payloadCorePager + ` -I{} git -c '{}=pig' log`, "dynamic code payload"},
		{"P-R3-MF6-a2 git --config-env", `xargs -a ` + payloadPig + ` -I{} git --config-env 'core.pager={}' log`, "dynamic code payload"},
		{"P-R3-MF6-b gawk -f masks -e", `xargs -a ` + payloadBegin + ` -I{} gawk -f /dev/null /dev/null -e '{}'`, "dynamic code payload"},
		{"P-R3-MF6-c gawk -W source", `xargs -a ` + payloadBegin + ` -I{} gawk -e '1' -W 'source={}' /dev/null`, "dynamic code payload"},
		// R3-SF-1: node spec 单源收口(-C / 长值选项)。
		{"P-R3-SF1-a node --title", `node --title x -e 'require("child_process").execSync("pig")'`, "javascript inline code"},
		{"P-R3-SF1-b node --env-file", `node --env-file /dev/null -e 'require("child_process").execSync("pig")'`, "javascript inline code"},
		{"P-R3-SF1-c node -C", `node -C default -e 'require("child_process").execSync("pig")'`, "javascript inline code"},
		{"P-R3-SF1-d node -C stdin", `echo 'require("child_process").execSync("pig")' | node -C default -`, "piped code to javascript"},
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

	// R3-MF-4: script 置换扫描(xargs -a 无管道入口,断言 dynamic code payload
	// 精确 verdict —— 修复前仅靠 echo 管道误触 piped code to shell 掩盖)。
	for _, tc := range []struct{ name, cmd string }{
		{"P-R3-MF4-a script xargs -a pre", `xargs -a ` + payloadC + ` -I% script % 'pig' /dev/null`},
		{"P-R3-MF4-b script xargs -a post", `xargs -a ` + payloadC + ` -I% script /dev/null % 'pig'`},
		{"P-R3-MF4-d find -exec script", `find . -name '-c' -exec script {} 'pig' /dev/null \;`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if !strings.Contains(got, "dynamic code payload") {
				t.Fatalf("rtGuardCwd(%q) = %q, want dynamic code payload", tc.cmd, got)
			}
		})
	}
	t.Run("P-R3-MF4-c script argv+stdin", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{
			id: "P-R3-MF4-c", role: "worker",
			argv:  []string{"xargs", "-I%", "script", "%", "pig", "/dev/null"},
			stdin: "-c",
		}, "")
		if !strings.Contains(got, "dynamic code payload") {
			t.Fatalf("argv script %% pig + stdin '-c' = %q, want dynamic code payload", got)
		}
	})

	// R3-MF-3-b: flock --no-fork 后 python3 不再被错当锁文件。
	t.Run("P-R3-MF3-b flock --no-fork python3", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R3-MF3-b", role: "worker", cmd: `flock --no-fork /dev/null python3 -c 'import os; os.system("pig")'`}, "")
		if !strings.Contains(got, "python inline code") {
			t.Fatalf("flock --no-fork python3 -c = %q, want python inline code", got)
		}
	})

	// R3-MF-6-d/e: xargs -a 配良性 here-string/heredoc 不再绕过 ssh stdin
	// 追加审查;f: GNU --arg-f 缩写接入 xargsMatchValueLong(verifier 外泄)。
	t.Run("P-R3-MF6-d xargs -a argv+stdin", func(t *testing.T) {
		// <<< here-string 是 bash-only 语法(/bin/sh dash 拒收),stdin 流通道
		// 经 argv+stdin 入口钉精确 verdict;heredoc 的 POSIX 拼写见 MF6-e。
		got := rtGuardCwd(t, rtCase{
			id: "P-R3-MF6-d", role: "worker",
			argv:  []string{"xargs", "-a", payloadCPig, "ssh", "dmit", "sh"},
			stdin: "echo hi",
		}, "")
		if !strings.Contains(got, "piped stdin to ssh") {
			t.Fatalf("xargs -a payload ssh dmit sh + stdin = %q, want piped stdin to ssh", got)
		}
	})
	t.Run("P-R3-MF6-e xargs -a heredoc", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R3-MF6-e", role: "worker", cmd: "xargs -a " + payloadCPig + " ssh dmit sh <<'EOF'\necho hi\nEOF"}, "")
		if !strings.Contains(got, "piped stdin to ssh") {
			t.Fatalf("xargs -a payload ssh dmit sh heredoc = %q, want piped stdin to ssh", got)
		}
	})
	t.Run("P-R3-MF6-f xargs --arg-f verifier", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R3-MF6-f", role: "verifier", cmd: `xargs --arg-f=/tmp/items -I{} ssh dmit cat < /etc/passwd`}, "")
		if !strings.Contains(got, "ssh remote write") {
			t.Fatalf("xargs --arg-f ssh cat exfil = %q, want ssh remote write", got)
		}
	})

	// Reviewer R2-6 合法数据 ALLOW 行: 解释器输入文件名 / awk -v 纯数据赋
	// 值 / git 纯数据路径值(glued 与分离双形态)。
	allowCases := []struct {
		name, cmd string
	}{
		{"R2-6-a find perl -pe data", `find . -exec perl -pe 's/a/b/' {} \;`},
		{"R2-6-b find awk -v data", `find . -exec awk -v f={} 'END {print f}' {} \;`},
		{"R2-6-c find awk -f -v data", `find . -exec awk -f parse.awk -v fname={} {} \;`},
		{"R2-6-d find git --git-dir glued", `find . -name .git -exec git --git-dir={} log -1 \;`},
		{"R2-6-e xargs awk -v", `echo x | xargs -I{} awk -v k={} 'BEGIN{print k}' /dev/null`},
		{"R2-6-f git --git-dir separate", `echo /tmp/repo | xargs -I{} git --git-dir {} log -1`},
		{"R2-6-g perl -we legit -I", `perl -we 'print qq(ok)' -I /tmp`},
		{"R5-a xargs -I{} perl -pe data", `echo a.txt | xargs -I{} perl -pe 's/a/b/' -- {}`},
		{"R5-b xargs -I{} perl -pe dot-slash", `echo a.txt | xargs -I{} perl -pe 's/a/b/' ./{}`},
		{"R5-c find perl -pe trailing", `find . -exec perl -pe 's/a/b/' {} other.txt \;`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// R12 精确 verdict 不受 xargsDerivedSeg 收紧影响: 真管道与文件重定向
	// 各归其名。
	t.Run("R12 piped verdict unchanged", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R12-a-r3", role: "worker", cmd: `echo code | xargs ssh dmit sh`}, "")
		if !strings.Contains(got, "piped stdin to ssh") {
			t.Fatalf("echo code | xargs ssh dmit sh = %q, want piped stdin to ssh", got)
		}
	})
	t.Run("R12 file-redir verdict unchanged", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R12-b-r3", role: "worker", cmd: `xargs -a /tmp/items ssh dmit sh < /tmp/script.sh`}, "")
		if !strings.Contains(got, "file stdin to ssh stdin-program") {
			t.Fatalf("xargs -a file ssh dmit sh < redir = %q, want file stdin to ssh stdin-program", got)
		}
	})

	// 目标层直断断言(R3-Obs-2 防掩盖纪律): wrapperChainEnvSplitHasToken /
	// scriptOptZoneHasToken / gitExecConfigValueHasToken / flockMatchLong 的
	// 单元 verdict 不依赖上层管道或外围规则兜出 BLOCK。
	t.Run("R3-unit env-split chain direct", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
			want bool
		}{
			{"nice env -S find", []string{"nice", "env", "-S", "find . -name {}"}, true},
			{"timeout env -S find", []string{"timeout", "10", "env", "-S", "find . -name {}"}, true},
			{"env -- env -S find", []string{"env", "--", "env", "-S", "find . -name {}"}, true},
			{"env -i env -S find", []string{"env", "-i", "env", "-S", "find . -name {}"}, true},
			{"nice env -S tar", []string{"nice", "env", "-S", "tar -cf /dev/null {}"}, true},
			{"rg env -S operand", []string{"rg", "env", "-S", "{}"}, false},
			{"echo env -S operand", []string{"echo", "env", "-S", "{}"}, false},
		} {
			if got := wrapperChainEnvSplitHasToken(tc.argv, os.Getenv("PATH"), callerIdentity{}, "{}"); got != tc.want {
				t.Errorf("wrapperChainEnvSplitHasToken(%v) = %v, want %v", tc.argv, got, tc.want)
			}
		}
	})
	t.Run("R3-unit script zone direct", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			h    []string
			want bool
		}{
			{"script % pig", []string{"script", "%", "pig", "/dev/null"}, true},
			{"script positional then %", []string{"script", "/dev/null", "%", "pig"}, true},
			{"script -q % pig", []string{"script", "-q", "%", "pig", "/dev/null"}, true},
			{"script -c benign", []string{"script", "-c", "echo hi", "/tmp/out"}, false},
			{"script -- terminator", []string{"script", "--", "%"}, false},
		} {
			if got := scriptOptZoneHasToken(tc.h, "%"); got != tc.want {
				t.Errorf("scriptOptZoneHasToken(%v) = %v, want %v", tc.h, got, tc.want)
			}
		}
	})
	t.Run("R3-unit git -c key-side direct", func(t *testing.T) {
		if !gitExecConfigValueHasToken("{}=pig", "{}") {
			t.Errorf("gitExecConfigValueHasToken({}=pig) = false, want true")
		}
		if !gitExecConfigValueHasToken("core.pager={}", "{}") {
			t.Errorf("gitExecConfigValueHasToken(core.pager={}) = false, want true")
		}
		if gitExecConfigValueHasToken("user.name={}", "{}") {
			t.Errorf("gitExecConfigValueHasToken(user.name={}) = true, want false for a non-exec key")
		}
	})
	t.Run("R3-unit flock long table direct", func(t *testing.T) {
		for _, tc := range []struct {
			in, want string
			ok       bool
		}{
			{"no-fork", "no-fork", true},
			{"nb", "nb", true},
			{"f", "fcntl", true},
			{"fd", "", false},
			{"nofork", "", false},
			{"com", "command", true},
			{"c", "", false},
		} {
			if full, ok := flockMatchLong(tc.in); full != tc.want || ok != tc.ok {
				t.Errorf("flockMatchLong(%q) = %q,%v want %q,%v", tc.in, full, ok, tc.want, tc.ok)
			}
		}
		if got := skipFlockLong([]string{"flock", "--no-fork-x", "/dev/null", "pig"}, 1); got != -1 {
			t.Errorf("skipFlockLong unknown long = %d, want -1 fail-closed", got)
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R4 (R6 闭环): R4-MF-1..4 / R4-SF-1..4 / R4-Obs-1 探针回归 —
// tar 布尔 -h 不再吞并后续 exec 选项;xargs 替换 token 的单词粘连/=` 代码
// 选项 RCE(-esystem pig / --eval=...)在末词也不豁免;env -S 嵌套重拆链
// 不再被 len(rest)>=len(cur) 截断;gawk -W 按 GNU getopt_long "W;" 解析
// 且 -E/--exec 接通 stdin/动态校验,awk 位置参数不再终止选项区扫描。
// 管道 echo 形态受上游 piped code 规则掩盖(verdict 为 piped code to shell/
// perl/javascript),精确 dynamic code payload 断言一律走 xargs -a 无管道
// 入口(R3-Obs-2 隔离纪律);stdin 程序源断言走 echo 管道与 argv+stdin 双通道。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR4Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadEsys := mkPayload("r4-esys", "-esystem(\"pig\")\n")
	payloadEval := mkPayload("r4-eval", "--eval=require(\"child_process\").execSync(\"pig\")\n")
	payloadDash := mkPayload("r4-dash", "-\n")
	payloadFooExec := mkPayload("r4-fooexec", "foo -exec pig ;\n")
	payloadCkpt := mkPayload("r4-ckpt", "a --checkpoint=1 --checkpoint-action=exec=pig\n")
	payloadBegin := mkPayload("r4-begin", "BEGIN{system(\"pig\")}\n")
	payloadEvilAwk := mkPayload("r4-evilawk", "/tmp/evil.awk\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R4-MF-1: tar 布尔 -h(--dereference)不再当带值字母吞并后续 exec 选项。
		{"P-R4-MF1-a tar -h use-compress", `tar -h --use-compress-program=pig -cf /dev/null /dev/null`, "pig"},
		{"P-R4-MF1-b tar -ch use-compress", `tar -ch --use-compress-program=pig -cf /dev/null /dev/null`, "pig"},
		{"P-R4-MF1-c tar -xh to-command", `tar -xh --to-command=pig -f /dev/null`, "pig"},
		{"P-R4-MF1-d tar -chI pig", `tar -chI pig -cf /dev/null /dev/null`, "pig"},
		{"P-R4-MF1-e tar -h ckpt-exec", `tar -h --checkpoint-action=exec=pig --checkpoint=1 -cf /dev/null /dev/null`, "pig"},
		// R4-MF-2: 单词粘连/=` 代码选项 RCE —— 末词也不豁免(xargs -a 无管道
		// 入口断言 dynamic code payload;stdin 管道形态的上游 verdict 另行验证)。
		{"P-R4-MF2-a perl glued -e", `xargs -a ` + payloadEsys + ` -I{} perl -e '1' {}`, "dynamic code payload"},
		{"P-R4-MF2-b perl -pe glued", `xargs -a ` + payloadEsys + ` -I{} perl -pe 's/a/b/' {}`, "dynamic code payload"},
		{"P-R4-MF2-c custom token FOO", `xargs -a ` + payloadEsys + ` -IFOO perl -e '1' FOO`, "dynamic code payload"},
		{"P-R4-MF2-d ruby glued -e", `xargs -a ` + payloadEsys + ` -I{} ruby -e '1' {}`, "dynamic code payload"},
		{"P-R4-MF2-e node --eval=", `xargs -a ` + payloadEval + ` -I{} node -e '1' {}`, "dynamic code payload"},
		{"P-R4-MF2-f bun --eval=", `xargs -a ` + payloadEval + ` -I{} bun -e '1' {}`, "dynamic code payload"},
		{"P-R4-MF2-g php glued -r", `xargs -a ` + mkPayload("r4-phpr", "-rsystem(\"pig\");\n") + ` -I{} php -r '1;' {}`, "dynamic code payload"},
		{"P-R4-MF2-h tsx --eval=", `xargs -a ` + payloadEval + ` -I{} tsx -e '1' {}`, "dynamic code payload"},
		// R4-MF-3: env -S 拆词重拼嵌套链不再被 len(rest)>=len(cur) 截断。
		{"P-R4-MF3-a env -Senv -S find", `xargs -a ` + payloadFooExec + ` -I{} env "-Senv -S" "find . -name {}"`, "dynamic code payload"},
		{"P-R4-MF3-b env -S nice chain", `xargs -a ` + payloadFooExec + ` -I{} env -S "nice nice nice" env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R4-MF3-c env -S nested env", `xargs -a ` + payloadFooExec + ` -I{} env -S "nice nice env -S" "find . -name {}"`, "dynamic code payload"},
		{"P-R4-MF3-d env -Senv -S tar", `xargs -a ` + payloadCkpt + ` -I{} env "-Senv -S" "tar -cf /dev/null {}"`, "dynamic code payload"},
		// R4-MF-4: gawk -W GNU "W;" 语义 / -E/--exec / 位置参数后置选项。
		{"P-R4-MF4-c -W source PROG", `gawk -e '1' -W source 'BEGIN{system("pig")}' /dev/null`, "pig"},
		{"P-R4-MF4-d -W source xargs", `xargs -a ` + payloadBegin + ` -I{} gawk -e '1' -W source '{}' /dev/null`, "dynamic code payload"},
		{"P-R4-MF4-e -W so= prefix", `gawk -e '1' -W 'so=BEGIN{system("pig")}' /dev/null`, "pig"},
		{"P-R4-MF4-f -W exec xargs", `xargs -a ` + payloadBegin + ` -I{} gawk -e '1' -W exec '{}' /dev/null`, "dynamic code payload"},
		{"P-R4-MF4-g positional -f", `xargs -a ` + payloadDash + ` -I{} gawk -e '1' /dev/null -f '{}'`, "dynamic code payload"},
		{"P-R4-MF4-x1 --file= positional", `xargs -a ` + payloadEvilAwk + ` -I{} gawk -e '1' /dev/null --file='{}'`, "dynamic code payload"},
		{"P-R4-MF4-x2 -f mask -f", `xargs -a ` + payloadEvilAwk + ` -I{} gawk -f /dev/null /dev/null -f '{}'`, "dynamic code payload"},
		{"P-R4-MF4-x3 positional -i", `xargs -a ` + payloadEvilAwk + ` -I{} gawk -e '1' /dev/null -i '{}'`, "dynamic code payload"},
		{"P-R4-MF4-x4 -W file= token", `xargs -a ` + payloadEvilAwk + ` -I{} gawk -e '1' /dev/null -W 'file={}'`, "dynamic code payload"},
		// R4-SF-1: flagCodes 后接非代码字母不再丢失 hasFlagCode。
		{"P-R4-SF1 node -pi pending", `xargs -a ` + payloadDash + ` -I% node -pi '1' %`, "dynamic code payload"},
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

	// R4-MF-2 管道路径:stdin 是任意字节的 xargs 馈入,整块管线必 BLOCK
	// (上游 piped code verdict 与精确 exec-slot verdict 任一都算闭合)。
	for _, tc := range []struct{ name, cmd string }{
		{"P-R4-MF2-a-pipe perl glued", `echo '-esystem("pig")' | xargs -I{} perl -e '1' {}`},
		{"P-R4-MF2-b-pipe perl -pe glued", `echo '-eBEGIN{system("pig")}' | xargs -I{} perl -pe 's/a/b/' {}`},
		{"P-R4-MF2-c-pipe custom FOO", `echo '-esystem("pig")' | xargs -IFOO perl -e '1' FOO`},
		{"P-R4-MF2-d-pipe ruby glued", `echo '-esystem("pig")' | xargs -I{} ruby -e '1' {}`},
		{"P-R4-MF2-e-pipe node --eval=", `echo '--eval=require("child_process").execSync("pig")' | xargs -I{} node -e '1' {}`},
		{"P-R4-MF2-f-pipe bun --eval=", `echo '--eval=require("child_process").execSync("pig")' | xargs -I{} bun -e '1' {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
		})
	}

	// R4-MF-4 awk stdin 程序源:echo 管道 + guardCtxRunArgv argv+stdin 双通道
	// 均须拦截(Reviewer R3 #3 argv+stdin 独立性)。
	for _, tc := range []struct {
		name, cmd, want string
	}{
		{"P-R4-MF4-a -W file=-", `echo 'BEGIN{system("pig")}' | gawk -W file=-`, "awk script from stdin"},
		{"P-R4-MF4-b -W file=/dev/stdin", `echo 'BEGIN{system("pig")}' | gawk -W file=/dev/stdin`, "awk script from stdin"},
		{"P-R4-MF4-h gawk -E stdin", `echo 'BEGIN{system("pig")}' | gawk -E /dev/stdin`, "awk script from stdin"},
		{"P-R4-MF4-i --exec=stdin", `echo 'BEGIN{system("pig")}' | gawk --exec=/dev/stdin`, "awk script from stdin"},
		{"P-R4-MF4-j --exec stdin sep", `echo 'BEGIN{system("pig")}' | gawk --exec /dev/stdin`, "awk script from stdin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want verdict substring %q", tc.cmd, got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"P-R4-MF4-a-argvstdin", []string{"gawk", "-W", "file=-"}, "awk script from stdin"},
		{"P-R4-MF4-b-argvstdin", []string{"gawk", "-W", "file=/dev/stdin"}, "awk script from stdin"},
		{"P-R4-MF4-h-argvstdin", []string{"gawk", "-E", "/dev/stdin"}, "awk script from stdin"},
		{"P-R4-MF4-i-argvstdin", []string{"gawk", "--exec=/dev/stdin"}, "awk script from stdin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{
				id: tc.name, role: "worker",
				argv:  tc.argv,
				stdin: "BEGIN{system(\"pig\")}",
			}, "")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("guardCtxRunArgv %v + stdin = %q, want verdict substring %q", tc.argv, got, tc.want)
			}
		})
	}
	t.Run("P-R4-MF4-k -W file heredoc", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R4-MF4-k", role: "worker", cmd: "gawk -W file=- <<'EOF'\nBEGIN{system(\"pig\")}\nEOF"}, "")
		if !strings.Contains(got, "awk script from stdin") {
			t.Fatalf("gawk -W file=- heredoc = %q, want awk script from stdin", got)
		}
	})

	// 放行守卫正例(R4 零假阳纪律):find 自身 {}、xargs -- 分隔/./{} 前缀、
	// awk/git 合法数据、script 以值字母结尾的位置文件名不再吞 --。
	allowCases := []struct {
		name, cmd string
	}{
		{"R4-pos find perl -pe", `find . -exec perl -pe 's/a/b/' {} \;`},
		{"R4-pos find perl trailing", `find . -exec perl -pe 's/a/b/' {} other.txt \;`},
		{"R4-pos xargs perl -- token", `echo a.txt | xargs -I{} perl -pe 's/a/b/' -- {}`},
		{"R4-pos xargs perl dot-slash", `echo a.txt | xargs -I{} perl -pe 's/a/b/' ./{}`},
		{"R4-pos find awk -f -v", `find . -exec awk -f parse.awk -v fname={} {} \;`},
		{"R4-pos find git --git-dir", `find . -name .git -exec git --git-dir={} log -1 \;`},
		{"R4-pos find rg env -S", `find . -name '*.go' -exec rg env -S {} \;`},
		{"R4-pos git -c user.name", `xargs -a ` + payloadEvilAwk + ` -I{} git -cuser.name={} log`},
		{"R4-pos git -C glued", `find . -exec git -C{} status \;`},
		{"R4-pos awk glued -vf", `xargs -a ` + payloadEvilAwk + ` -I{} awk -vf={} 'END{print f}' /dev/null`},
		{"R4-pos awk glued -F", `xargs -a ` + payloadEvilAwk + ` -I{} awk -F{} 'END{print f}' /dev/null`},
		{"R4-pos awk --assign glued", `xargs -a ` + payloadEvilAwk + ` -I{} awk --assign=f={} 'END{print f}' /dev/null`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// R4-SF-3: script 以值字母结尾的位置文件名不再吞掉 --(xargs -a 无管道
	// 入口,避免上游 piped code verdict 掩盖)。
	t.Run("R4-pos script positional .o", func(t *testing.T) {
		payloadX := mkPayload("r4-x", "x\n")
		got := rtGuardCwd(t, rtCase{id: "R4-pos-script-o", role: "worker", cmd: `xargs -a ` + payloadX + ` -I% script /tmp/out.o -- %`}, "")
		if got != "ALLOW" {
			t.Fatalf("xargs script /tmp/out.o -- %% = %q, want ALLOW", got)
		}
	})

	// 目标层直断断言:R4 修复点的单元 verdict 不依赖外层规则兜出 BLOCK。
	t.Run("R4-unit env-split re-split chain", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
			want bool
		}{
			{"env -Senv -S", []string{"env", "-Senv -S", "find . -name {}"}, true},
			{"env -S nice nice env -S", []string{"env", "-S", "nice nice env -S", "find . -name {}"}, true},
			{"env -S nice nice nice env -S", []string{"env", "-S", "nice nice nice", "env", "-S", "find . -name {}"}, true},
		} {
			if got := wrapperChainEnvSplitHasToken(tc.argv, os.Getenv("PATH"), callerIdentity{}, "{}"); got != tc.want {
				t.Errorf("wrapperChainEnvSplitHasToken(%v) = %v, want %v", tc.argv, got, tc.want)
			}
		}
	})
	t.Run("R4-unit awk -W shapes direct", func(t *testing.T) {
		if _, _, hit := awkProgramFrags([]string{"-W", "file=-"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-W file=-) hit = %q, want awk script from stdin", hit)
		}
		if _, _, hit := awkProgramFrags([]string{"-W", "file=/dev/stdin"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-W file=/dev/stdin) hit = %q, want awk script from stdin", hit)
		}
		if _, _, hit := awkProgramFrags([]string{"-Wfile=-"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-Wfile=-) hit = %q, want awk script from stdin", hit)
		}
		if _, _, hit := awkProgramFrags([]string{"-E", "/dev/stdin"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-E /dev/stdin) hit = %q, want awk script from stdin", hit)
		}
		if _, _, hit := awkProgramFrags([]string{"--exec=/dev/stdin"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(--exec=/dev/stdin) hit = %q, want awk script from stdin", hit)
		}
		prog, _, hit := awkProgramFrags([]string{"-e", "1", "-W", "source", "BEGIN{1}", "/dev/null"})
		if hit != "" || !strings.Contains(prog, "BEGIN{1}") {
			t.Errorf("awkProgramFrags(-W source PROG) = %q hit %q, want program containing BEGIN{1}", prog, hit)
		}
		prog2, _, hit2 := awkProgramFrags([]string{"-e", "1", "-W", "so=BEGIN{2}", "/dev/null"})
		if hit2 != "" || !strings.Contains(prog2, "BEGIN{2}") {
			t.Errorf("awkProgramFrags(-W so=PROG) = %q hit %q, want program containing BEGIN{2}", prog2, hit2)
		}
	})
	t.Run("R4-unit awkOptZone positional scan", func(t *testing.T) {
		if !awkOptZoneHasToken([]string{"-e", "1", "/dev/null", "-f", "{}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken(positional then -f {}) = false, want true")
		}
		if !awkOptZoneHasToken([]string{"-e", "1", "/dev/null", "--file={}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken(positional then --file={}) = false, want true")
		}
		if awkOptZoneHasToken([]string{"-vf={}", "/dev/null"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken(-vf={}) = true, want false (glued data assignment)")
		}
	})
	t.Run("R4-unit scriptOptWord positional", func(t *testing.T) {
		if consume, hit := scriptOptWordTokenStep([]string{"script", "/tmp/out.o", "--", "%"}, 1, "%"); consume != 0 || hit {
			t.Errorf("scriptOptWordTokenStep(positional /tmp/out.o) = %d,%v want 0,false", consume, hit)
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R5 (R7 闭环): R5-MF-1..4 / R5-SF-1..3 探针回归 —
// flagCodes+valShort 双槽消费恢复 sh -co/bash -co/node -pr/bun -pc 的 BLOCK;
// env -S 同层递归拆出内层 -S 载荷沿 token 传播闭合;awk 选项区裸 token
// 按 findPathToken 语义命中;gawk GNU 唯一前缀与 -W assign/--as 操作数消费
// 闭合。所有 dynamic code payload 精确断言走 xargs -a 无管道入口,stdin
// 程序源断言走 echo 管道与 argv+stdin 双通道(R3-Obs-2 隔离纪律)。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR5Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadEval := mkPayload("r5-eval", "--eval=require(\"child_process\").execSync(\"pig\")\n")
	payloadFooExec := mkPayload("r5-fooexec", "foo -exec pig ;\n")
	payloadCkpt := mkPayload("r5-ckpt", "a --checkpoint=1 --checkpoint-action=exec=pig\n")
	payloadEBegin := mkPayload("r5-ebegin", "-eBEGIN{system(\"pig\")}\n")
	payloadFstdin := mkPayload("r5-fstdin", "-f/dev/stdin\n")
	payloadEvilSo := mkPayload("r5-evilso", "/tmp/evil.so\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R5-MF-1: R6 回归修复 — flagCodes+valShort 集群的值槽先查动态词,
		// 待定代码槽再消费一个操作数(sh/bash/node/bun 全部恢复 BLOCK)。
		{"P-R5-MF1-a sh -co", `X='errexit pig'; sh -co $X 'echo hi'`, "dynamic code payload"},
		{"P-R5-MF1-b bash -co", `X='errexit pig'; bash -co $X 'echo hi'`, "dynamic code payload"},
		{"P-R5-MF1-c node -pr", `X='a.js -e require("child_process").execSync("pig")'; node -pr $X '1'`, "dynamic code payload"},
		{"P-R5-MF1-d bun -pc", `X='a.toml -e require("child_process").execSync("pig")'; bun -pc $X '1'`, "dynamic code payload"},
		{"P-R5-MF1-e node -pC separate", `X='a.js -e require("child_process").execSync("pig")'; node -pC default '1' -r $X`, "dynamic code payload"},
		{"P-R5-MF1-f node -pC glued", `X='a.js -e require("child_process").execSync("pig")'; node -pCdefault '1' -r $X`, "dynamic code payload"},
		{"P-R5-MF1-g xargs node -pC", `xargs -a ` + payloadEval + ` -I% node -pC default '1' %`, "dynamic code payload"},
		{"P-R5-MF1-h xargs node -pC glued", `xargs -a ` + payloadEval + ` -I% node -pCdefault '1' %`, "dynamic code payload"},
		// R5-MF-2: env -S 同层递归拆出内层 -S 载荷沿 token 传播。
		{"P-R5-MF2-a env -S -S find", `xargs -a ` + payloadFooExec + ` -I{} env -S "-S" "find . -name {}"`, "dynamic code payload"},
		{"P-R5-MF2-b env -S-S find", `xargs -a ` + payloadFooExec + ` -I{} env "-S-S" "find . -name {}"`, "dynamic code payload"},
		{"P-R5-MF2-c env -S split-string", `xargs -a ` + payloadFooExec + ` -I{} env -S "--split-string" "find . -name {}"`, "dynamic code payload"},
		{"P-R5-MF2-d env -S -i -S tar", `xargs -a ` + payloadCkpt + ` -I{} env -S "-i -S" "tar -cf /dev/null {}"`, "dynamic code payload"},
		// R5-MF-3: awk 选项区裸 token 按 findPathToken 语义命中(单词粘连
		// 选项注入 — mawk/gawk 均可触发)。
		{"P-R5-MF3-a gawk -e glued", `xargs -a ` + payloadEBegin + ` -I{} gawk -e '1' {}`, "dynamic code payload"},
		{"P-R5-MF3-b gawk -e /dev/null", `xargs -a ` + payloadEBegin + ` -I{} gawk -e '1' /dev/null {}`, "dynamic code payload"},
		{"P-R5-MF3-c awk -f devstdin", `xargs -a ` + payloadFstdin + ` -I{} awk -f /dev/null {}`, "dynamic code payload"},
		// R5-MF-4: gawk GNU 唯一前缀 / -i 库验证 / -W assign 操作数消费。
		{"P-R5-MF4-f -W assign program", `gawk -W assign 'x=1' 'BEGIN{system("pig")}'`, "pig"},
		{"P-R5-MF4-f2 -W field-separator", `gawk -W field-separator : 'BEGIN{system("pig")}'`, "pig"},
		{"P-R5-MF4-g --as program", `gawk --as 'x=1' 'BEGIN{system("pig")}'`, "pig"},
		{"P-R5-MF4-g2 --fie program", `gawk --fie : 'BEGIN{system("pig")}'`, "pig"},
		{"P-R5-MF4-h -l load xargs", `xargs -a ` + payloadEvilSo + ` -I{} gawk -e '1' -l '{}'`, "dynamic code payload"},
		{"P-R5-MF4-h2 -W lo xargs", `xargs -a ` + payloadEvilSo + ` -I{} gawk -e '1' -W lo '{}'`, "dynamic code payload"},
		{"P-R5-MF4-h3 -W e xargs", `xargs -a ` + payloadEvilSo + ` -I{} gawk -e '1' -W e '{}'`, "dynamic code payload"},
		{"P-R5-MF4-x1 --as xargs", `xargs -a ` + mkPayload("r5-begin2", "BEGIN{system(\"pig\")}\n") + ` -I{} gawk --as 'x=1' '{}'`, "dynamic code payload"},
		// R4-Obs-1: script 追加模式回归用例(补 R4 缺口)。
		{"P-R4-Obs1 script append", `xargs -a ` + mkPayload("r5-cflag", "-c pig\n") + ` script /dev/null`, "dynamic code payload"},
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

	// R5-MF-4 stdin 程序源管道:--include/-i/--e/-W e 各形态均须命中
	// awk script from stdin(echo 管道 + argv+stdin 双通道)。
	for _, tc := range []struct {
		name, cmd, want string
	}{
		{"P-R5-MF4-a --include=stdin pipe", `echo 'BEGIN{system("pig")}' | gawk --include=/dev/stdin '1'`, "awk script from stdin"},
		{"P-R5-MF4-a2 --include sep pipe", `echo 'BEGIN{system("pig")}' | gawk --include /dev/stdin '1'`, "awk script from stdin"},
		{"P-R5-MF4-b -i stdin pipe", `echo 'BEGIN{system("pig")}' | gawk -i /dev/stdin '1'`, "awk script from stdin"},
		{"P-R5-MF4-b2 -i glued pipe", `echo 'BEGIN{system("pig")}' | gawk -i/dev/stdin '1'`, "awk script from stdin"},
		{"P-R5-MF4-d --e=stdin pipe", `echo 'BEGIN{system("pig")}' | gawk --e=/dev/stdin`, "awk script from stdin"},
		{"P-R5-MF4-d2 --e sep pipe", `echo 'BEGIN{system("pig")}' | gawk --e /dev/stdin`, "awk script from stdin"},
		{"P-R5-MF4-e -W e=stdin pipe", `echo 'BEGIN{system("pig")}' | gawk -W e=/dev/stdin`, "awk script from stdin"},
		{"P-R5-MF4-e2 -W e sep pipe", `echo 'BEGIN{system("pig")}' | gawk -W e /dev/stdin`, "awk script from stdin"},
		{"P-R5-MF4-e3 -W in=stdin pipe", `echo 'BEGIN{system("pig")}' | gawk -W in=/dev/stdin '1'`, "awk script from stdin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want verdict substring %q", tc.cmd, got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"P-R5-MF4-c argvstdin --include=", []string{"gawk", "--include=/dev/stdin", "1"}, "awk script from stdin"},
		{"P-R5-MF4-c2 argvstdin -i sep", []string{"gawk", "-i", "/dev/stdin", "1"}, "awk script from stdin"},
		{"P-R5-MF4-c3 argvstdin --e=", []string{"gawk", "--e=/dev/stdin"}, "awk script from stdin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{
				id: tc.name, role: "worker",
				argv:  tc.argv,
				stdin: "BEGIN{system(\"pig\")}",
			}, "")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("guardCtxRunArgv %v + stdin = %q, want verdict substring %q", tc.argv, got, tc.want)
			}
		})
	}

	// 放行守卫正例(R5 零假阳纪律):find 自身 {}、xargs --/./{} 拼写、
	// awk -v 纯数据、静态 sh -co、-- 后的 awk argv 数据。
	allowCases := []struct {
		name, cmd string
	}{
		{"R5-pos find perl -pe", `find . -exec perl -pe 's/a/b/' {} \;`},
		{"R5-pos find perl trailing", `find . -exec perl -pe 's/a/b/' {} other.txt \;`},
		{"R5-pos xargs perl -- token", `echo a.txt | xargs -I{} perl -pe 's/a/b/' -- {}`},
		{"R5-pos xargs perl dot-slash", `echo a.txt | xargs -I{} perl -pe 's/a/b/' ./{}`},
		{"R5-pos find awk -f -v", `find . -exec awk -f parse.awk -v fname={} {} \;`},
		{"R5-pos find awk -v data", `find . -exec awk -v f={} 'END {print f}' {} \;`},
		{"R5-pos xargs awk -vf glued", `echo x | xargs -I{} awk -vf={} 'END{print f}' /dev/null`},
		{"R5-pos xargs awk -- token", `echo x | xargs -I{} awk -f parse.awk -- {}`},
		{"R5-pos xargs awk dot-slash", `echo x | xargs -I{} awk -f parse.awk ./{}`},
		{"R5-pos sh -co static", `sh -co errexit 'echo hi'`},
		{"R5-pos gawk -- data", `gawk 'BEGIN{print ARGV[1]}' -- -f -`},
		{"R5-pos find rg env -S", `find . -name '*.go' -exec rg env -S {} \;`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// 目标层直断断言(R5-Obs 防掩盖纪律):skipEnvOperandsToken /
	// awkOptZoneHasToken findPathToken / awkWOperandProgram 的单元 verdict
	// 不依赖外层管道或外围规则兜出 BLOCK。
	t.Run("R5-unit env re-split token propagation", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
			want bool
		}{
			{"env -S -S", []string{"env", "-S", "-S", "find . -name {}"}, true},
			{"env -S-S", []string{"env", "-S-S", "find . -name {}"}, true},
			{"env -S -i -S", []string{"env", "-S", "-i -S", "find . -name {}"}, true},
			{"env -S benign", []string{"env", "-S", "echo hi"}, false},
			{"rg env -S operand", []string{"rg", "env", "-S", "{}"}, false},
		} {
			if got := wrapperChainEnvSplitHasToken(tc.argv, os.Getenv("PATH"), callerIdentity{}, "{}"); got != tc.want {
				t.Errorf("wrapperChainEnvSplitHasToken(%v) = %v, want %v", tc.argv, got, tc.want)
			}
		}
	})
	t.Run("R5-unit awkOptZone bare token find-vs-xargs", func(t *testing.T) {
		if !awkOptZoneHasToken([]string{"-e", "1", "{}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken xargs bare token = false, want true")
		}
		if awkOptZoneHasToken([]string{"-e", "1", "{}"}, "{}", true) {
			t.Errorf("awkOptZoneHasToken find own {} = true, want false")
		}
		if awkOptZoneHasToken([]string{"-e", "1", "./{}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken ./{} = true, want false")
		}
		if awkOptZoneHasToken([]string{"-e", "1", "--", "{}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken -- {} = true, want false (post-terminator data)")
		}
	})
	t.Run("R5-unit awk -W assign consumption", func(t *testing.T) {
		prog, _, hit := awkProgramFrags([]string{"-W", "assign", "x=1", "BEGIN{1}"})
		if hit != "" || !strings.Contains(prog, "BEGIN{1}") {
			t.Errorf("awkProgramFrags(-W assign x=1 PROG) = %q hit %q, want program BEGIN{1}", prog, hit)
		}
		prog2, _, hit2 := awkProgramFrags([]string{"--as", "x=1", "BEGIN{2}"})
		if hit2 != "" || !strings.Contains(prog2, "BEGIN{2}") {
			t.Errorf("awkProgramFrags(--as x=1 PROG) = %q hit %q, want program BEGIN{2}", prog2, hit2)
		}
		if _, _, hit3 := awkProgramFrags([]string{"--include=/dev/stdin", "1"}); hit3 != "awk script from stdin" {
			t.Errorf("awkProgramFrags(--include=/dev/stdin) hit = %q, want awk script from stdin", hit3)
		}
		if _, _, hit4 := awkProgramFrags([]string{"-i", "/dev/stdin", "1"}); hit4 != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-i /dev/stdin) hit = %q, want awk script from stdin", hit4)
		}
		if _, _, hit5 := awkProgramFrags([]string{"--e=/dev/stdin"}); hit5 != "awk script from stdin" {
			t.Errorf("awkProgramFrags(--e=/dev/stdin) hit = %q, want awk script from stdin", hit5)
		}
		if _, _, hit6 := awkProgramFrags([]string{"-l", "/dev/stdin"}); hit6 != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-l /dev/stdin) hit = %q, want awk script from stdin", hit6)
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R6 (R8 终局收口): R6-MF-1..4 / R6-SF-1..2 探针回归 —
// POSIX shell pending -c 全链路对齐(sh -co errexit -o $X / sh -co errexit --
// /xargs -a sh -c -- 回归与逃逸闭合);awkClusterWOperand -W include/-W load
// 不再错置 sawFile;awkWOperandTokenStep/awkWOperandProgram 覆盖 -W '{}' /
// -W "$X" 选项名盲区与 awkProgramTokenHit 空程序门控;gawk 可选参数短选项
// d/D/L/o/p 粘连尾串立即结束集群;awk -- "$VAR" 与 clusterConsumesOperand
// 非纯字母尾 hasFlagCode 锁步对齐。所有 dynamic code payload 精确断言走
// xargs -a 无管道入口(R3-Obs-2 隔离纪律)。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR6Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadPig := mkPayload("r6-pig", "pig\n")
	payloadExec := mkPayload("r6-exec", "exec\n")
	payloadSource := mkPayload("r6-source", "source=BEGIN{system(\"pig\")}\n")
	payloadEBegin := mkPayload("r6-ebegin", "-eBEGIN{system(\"pig\")}\n")
	payloadEvilSo := mkPayload("r6-evilso", "/tmp/evil.so\n")
	payloadDevStdin := mkPayload("r6-devstdin", "/dev/stdin\n")
	payloadX := mkPayload("r6-x", "x\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R6-MF-1: POSIX shell pending -c 全链路对齐 — R7 回归(sh/bash -co
		// errexit -o $X 从 3ddc0a7 BLOCK 退化)与 -o/-- 逃逸全部恢复 BLOCK。
		{"P-R6-MF1-a sh -co -o X", `X='errexit pig'; sh -co errexit -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R6-MF1-b bash -co -o X", `X='errexit pig'; bash -co errexit -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R6-MF1-c bash -co -o pipefail", `bash -co errexit -o pipefail 'pig'`, "pig"},
		{"P-R6-MF1-d sh -co -- pig", `sh -co errexit -- 'pig'`, "pig"},
		{"P-R6-MF1-e sh -ce -o X", `X='errexit pig'; sh -ce -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R6-MF1-f xargs -I% sh -co -- %", `xargs -a ` + payloadPig + ` -I% sh -co errexit -- %`, "dynamic code payload"},
		{"P-R6-MF1-g xargs sh -c --", `xargs -a ` + payloadPig + ` sh -c --`, "dynamic code payload"},
		// R6-MF-2: -W include/-W load 不再错置 sawFile,位置主程序正常提取。
		{"P-R6-MF2-a -W include=", `gawk -W include=/dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF2-b -W include sep", `gawk -W include /dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF2-c -W i=", `gawk -W i=/dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF2-d -W load=time", `gawk -W load=time 'BEGIN{system("pig")}'`, "pig"},
		// R6-MF-3: -W '{}' / -W "$X" 选项名盲区与 awkProgramTokenHit 空程序
		// 门控跳过全部闭合。
		{"P-R6-MF3-a xargs awk -W '{}' /dev/stdin", `xargs -a ` + payloadExec + ` -I{} awk -W '{}' /dev/stdin`, "dynamic code payload"},
		{"P-R6-MF3-b xargs gawk -W '{}' '1'", `xargs -a ` + payloadSource + ` -I{} gawk -W '{}' '1'`, "dynamic code payload"},
		{"P-R6-MF3-c awk -W X /dev/stdin", `X='exec'; echo 'BEGIN{system("pig")}' | awk -W "$X" /dev/stdin`, "dynamic code payload"},
		{"P-R6-MF3-d gawk -W X 1", `X='source=BEGIN{system("pig")}'; gawk -W "$X" '1'`, "dynamic code payload"},
		{"P-R6-MF3-e gawk -e '' {}", `xargs -a ` + payloadEBegin + ` -I{} gawk -e '' {}`, "dynamic code payload"},
		{"P-R6-MF3-f gawk -e '' -l '{}'", `xargs -a ` + payloadEvilSo + ` -I{} gawk -e '' -l '{}'`, "dynamic code payload"},
		{"P-R6-MF3-g gawk -e '' -i '{}'", `xargs -a ` + payloadDevStdin + ` -I{} gawk -e '' -i '{}'`, "dynamic code payload"},
		// R6-MF-4: gawk 可选参数短选项 d/D/L/o/p 粘连尾串立即结束集群。
		{"P-R6-MF4-a -Lfatal", `gawk -Lfatal 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF4-b -Lno-ext", `gawk -Lno-ext 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF4-c -p/dev/null", `gawk -p/dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF4-d -d/tmp/v xargs", `xargs -a ` + payloadEBegin + ` -I{} gawk -d/tmp/v {} '1'`, "dynamic code payload"},
		// R6-SF-1: awk -- "$VAR" 在本机 mawk/gawk 直通 — !endOpts 改 !sawFile。
		{"P-R6-SF1-a awk -- VAR", `VAR='BEGIN{system("pig")}'; awk -- "$VAR"`, "dynamic code payload"},
		// R6-SF-2: clusterConsumesOperand 非纯字母尾保留 hasFlagCode。
		{"P-R6-SF2-a node -pCfoo-bar", `X='a.js -e require("child_process").execSync("pig")'; node -pCfoo-bar '1' -r $X`, "dynamic code payload"},
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

	// 放行守卫正例(R6 零假阳纪律):合法 $0/$1 数据槽、-W assign 纯数据、
	// awk -- 后文件名、gawk -Lfatal 合法 lint 值。
	allowCases := []struct {
		name, cmd string
	}{
		{"R6-pos sh -co errexit echo", `sh -co errexit 'echo hi'`},
		{"R6-pos sh -co errexit $1", `sh -co errexit 'echo "$1"' _ "$ARG"`},
		{"R6-pos xargs sh -c $1", `xargs -a ` + payloadX + ` -I{} sh -c 'echo "$1"' _ {}`},
		{"R6-pos gawk -W assign", `gawk -W assign 'x=1' 'BEGIN{print x}'`},
		{"R6-pos xargs -W assign {}", `xargs -a ` + payloadX + ` -I{} gawk -W assign '{}' '1' /dev/null`},
		{"R6-pos xargs -W assign=x={}", `xargs -a ` + payloadX + ` -I{} gawk -W 'assign=x={}' '1' /dev/null`},
		{"R6-pos awk -f -- $FILE", `awk -f parse.awk -- "$FILE"`},
		{"R6-pos awk '1' -- $FILE", `awk '1' -- "$FILE"`},
		{"R6-pos gawk -Lfatal lint", `gawk -Lfatal 'BEGIN{print 1}'`},
		{"R6-pos gawk -- data", `gawk 'BEGIN{print ARGV[1]}' -- -f -`},
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

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R7 (R9 终局收口): R7-MF-1..4 / R7-SF-1 探针回归 —
// awkProgramFrags 恢复 !endOpts 动态词门控(awk -f /dev/null "$X" / gawk '1'
// "$X" 系列 R8 安全回归);unwrapShellWordStep 的 isCluster 通道杜绝单字
// --long-opt 落入短选项集群(bash --restricted 四路 stdin 回归);裸 -c 布
// 尔语义与 POSIX 单横杠 "-"/"+" 终止符结算(sh -c -o ... -o $X / sh -c -
// 'pig' / xargs -a sh -c -);mawk -W 语法冲突(-Wi/-W i/-W in 布尔吞程序
// 与逗号串联 -W interactive,exec);awk 纯数据赋值槽无引号词拆分拦截
// (-v/-F/--assign/-W assign)。所有探针仅依赖基线共有入口 rtGuardCwd
// 与 guardCtxRunStdin(argv 通道)。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR7Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadPig := mkPayload("r7-pig", "pig\n")
	payloadX := mkPayload("r7-x", "x\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R7-MF-1: awkProgramFrags -- 前动态选项注入 R8 回归恢复 BLOCK。
		{"P-R7-MF1-a awk -f null X", `X='-f/dev/stdin'; echo 'BEGIN{system("pig")}' | awk -f /dev/null "$X"`, "dynamic code payload"},
		{"P-R7-MF1-b awk -f null split X", `X='-f /dev/stdin'; echo 'BEGIN{system("pig")}' | awk -f /dev/null $X`, "dynamic code payload"},
		{"P-R7-MF1-c gawk 1 X", `X='-eBEGIN{system("pig")}'; gawk '1' "$X"`, "dynamic code payload"},
		{"P-R7-MF1-d gawk -e 1 X", `X='-eBEGIN{system("pig")}'; gawk -e '1' "$X"`, "dynamic code payload"},
		{"P-R7-MF1-e gawk 1 ./X", `X='x -e BEGIN{system("pig")}'; gawk '1' ./$X`, "dynamic code payload"},
		// R7-MF-2: 单字 --long-opt 不再落入短选项集群(bash --restricted
		// 管道/here-string/heredoc/stdin 四路 R8 回归)。
		{"P-R7-MF2-a pipe bash --restricted", `echo 'pig' | bash --restricted`, "piped code to shell"},
		// 注: <<< 是 bash-only 语法,外层 dash 语法门在 stdin 筛查前先 BLOCK —
		// 该探针的裁决串不含 pig(与 Oracle R7 预期串的偏差,判别性证据由
		// 探针 a/c/d 承担,此处断言其恒定 BLOCK 不回归为 ALLOW)。
		{"P-R7-MF2-b bash --restricted herestring", `bash --restricted <<< 'pig'`, "bash-only syntax"},
		{"P-R7-MF2-c bash --restricted heredoc", `bash --restricted <<'EOF'
pig
EOF`, "pig"},
		// R7-MF-3 路径 A: 裸 -c 布尔语义 + 裸 -o/+o/-O/+O 动态词校验。
		{"P-R7-MF3-a sh -c -o -o X", `X='errexit pig'; sh -c -o errexit -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R7-MF3-b bash -c -o -o X", `X='errexit pig'; bash -c -o errexit -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R7-MF3-c sh -c +o +o X", `X='errexit pig'; sh -c +o errexit +o $X 'echo hi'`, "dynamic code payload"},
		{"P-R7-MF3-d bash -c -O -O X", `X='extglob pig'; bash -c -O extglob -O $X 'echo hi'`, "dynamic code payload"},
		// R7-MF-3 路径 B: POSIX 单横杠 "-" 终止符结算。
		{"P-R7-MF3-e sh -c - pig", `sh -c - 'pig'`, "pig"},
		{"P-R7-MF3-f bash -c - pig", `bash -c - 'pig'`, "pig"},
		{"P-R7-MF3-g sh -co errexit - pig", `sh -co errexit - 'pig'`, "pig"},
		{"P-R7-MF3-h sh -c - X", `X='pig'; sh -c - "$X"`, "dynamic code payload"},
		{"P-R7-MF3-i xargs sh -c -", `xargs -a ` + payloadPig + ` sh -c -`, "dynamic code payload"},
		// R7-MF-4: mawk -W 语法冲突(布尔吞程序与逗号串联)。
		{"P-R7-MF4-a awk -Wi", `awk -Wi 'BEGIN{system("pig")}'`, "pig"},
		{"P-R7-MF4-b awk -W i", `awk -W i 'BEGIN{system("pig")}'`, "pig"},
		{"P-R7-MF4-c awk -W in", `awk -W in 'BEGIN{system("pig")}'`, "pig"},
		{"P-R7-MF4-d awk -W interactive,exec", `echo 'BEGIN{system("pig")}' | awk -W interactive,exec /dev/stdin`, "awk script from stdin"},
		// R7-SF-1: awk 纯数据赋值槽无引号词拆分选项注入。
		{"P-R7-SF1-a awk -v x=VAR", `VAR='1 -f /dev/stdin'; echo 'BEGIN{system("pig")}' | awk -v x=$VAR -f /dev/null`, "dynamic code payload"},
		{"P-R7-SF1-b gawk -W assign=x=VAR", `VAR='1 -e BEGIN{system("pig")}'; gawk -W assign=x=$VAR '1'`, "dynamic code payload"},
		{"P-R7-SF1-c gawk -W assign VAR", `VAR='x=1 -e BEGIN{system("pig")}'; gawk -W assign $VAR '1'`, "dynamic code payload"},
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

	// R7-MF-2-d: guardCtxRunStdin argv+stdin 通道(argv 不走 shell 字符串)。
	t.Run("P-R7-MF2-d argv bash --restricted stdin", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R7-MF2-d", role: "worker", argv: []string{"bash", "--restricted"}, stdin: "pig\n"}, "")
		if got == "ALLOW" {
			t.Fatalf("rtGuardCwd(argv bash --restricted stdin pig) = ALLOW, want a guard block")
		}
		if !strings.Contains(got, "pig") {
			t.Fatalf("rtGuardCwd(argv bash --restricted) = %q, want verdict substring %q", got, "pig")
		}
	})

	// 放行守卫正例(R7 零假阳纪律,含 R6 既有放行契约的核心行)。
	allowCases := []struct {
		name, cmd string
	}{
		{"R7-pos awk -f -- $FILE", `awk -f parse.awk -- "$FILE"`},
		{"R7-pos awk '1' -- $FILE", `awk '1' -- "$FILE"`},
		{"R7-pos awk 1 $PWD data", `awk '1' "$PWD/data.txt"`},
		{"R7-pos awk glob log", `awk '{print $1}' /tmp/*.log`},
		{"R7-pos awk f static", `f=/tmp/data.log; awk '{print $1, $2}' "$f"`},
		{"R7-pos awk -v ts quoted", `val=$(date +%s); awk -v ts="$val" 'BEGIN{print ts}'`},
		{"R7-pos gawk -W assign=x=quoted", `gawk -W assign=x="$VAR" '1'`},
		{"R7-pos gawk -W assign quoted", `gawk -W assign "$VAR" '1'`},
		{"R7-pos awk -Wi benign", `awk -Wi 'BEGIN{print 1}'`},
		{"R7-pos gawk -W i devnull benign", `gawk -W i /dev/null 'BEGIN{print 1}'`},
		{"R7-pos bash --restricted scriptfile", `bash --restricted "a'b.sh"`},
		{"R7-pos sh -c $1", `sh -c 'echo "$1"' _ "$ARG"`},
		{"R7-pos sh -c -o errexit $1", `sh -c -o errexit 'echo "$1"' _ "$ARG"`},
		{"R7-pos sh -c - $1", `sh -c - 'echo "$1"' _ "$ARG"`},
		{"R7-pos xargs sh -c - $1", `xargs -a ` + payloadX + ` -I{} sh -c - 'echo "$1"' _ {}`},
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

func TestGuard_V622_OracleR8Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadPigProg := mkPayload("r8-prog", "BEGIN{system(\"pig\")}\n")
	payloadPig := mkPayload("r8-pig", "pig\n")
	payloadX := mkPayload("r8-x", "x\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R8-MF-1: -Wi/-W in 碰撞值经独立 aux 通道,不再压死位置主程序
		// 与 -- 后动态程序提取(R9 引入的 gawk 直通回归)。
		{"P-R8-MF1-a gawk -W i devnull pig", `gawk -W i /dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R8-MF1-b gawk -Wi devnull pig", `gawk -Wi /dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R8-MF1-c gawk -W in devnull pig", `gawk -W in /dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R8-MF1-d gawk -W i devnull -- VAR", `VAR='BEGIN{system("pig")}'; gawk -W i /dev/null -- "$VAR"`, "dynamic code payload"},
		{"P-R8-MF1-e xargs gawk -W i devnull -- tok", `xargs -a ` + payloadPigProg + ` -I{} gawk -W i /dev/null -- '{}'`, "dynamic code payload"},
		{"P-R8-MF1-f xargs gawk -W i devnull tok prog", `xargs -a ` + payloadPig + ` -I{} gawk -W i /dev/null 'BEGIN{system("{}")}'`, "dynamic code payload"},
		// R8-MF-2: awkProgramLongStep 接入 --assign/--field-separator
		// 分离值的 awkDataValSplitHit(无引号词拆分重新武装选项解析)。
		{"P-R8-MF2-a gawk --as VAR", `VAR='x=1 -e BEGIN{system("pig")}'; gawk --as $VAR '1'`, "dynamic code payload"},
		{"P-R8-MF2-b gawk --assign VAR", `VAR='x=1 -e BEGIN{system("pig")}'; gawk --assign $VAR '1'`, "dynamic code payload"},
		{"P-R8-MF2-c gawk --field-separator VAR", `VAR=', -e BEGIN{system("pig")}'; gawk --field-separator $VAR '1'`, "dynamic code payload"},
		{"P-R8-MF2-d gawk --fie VAR", `VAR=', -e BEGIN{system("pig")}'; gawk --fie $VAR '1'`, "dynamic code payload"},
		// R8-MF-3: MAWK_LONG_OPTIONS 纳入 envHookVars(KEY=VAL 前缀/export/env 通路)。
		{"P-R8-MF3-a MAWK ignore --file", `MAWK_LONG_OPTIONS=ignore awk --file=/dev/null 'BEGIN{system("pig")}'`, "MAWK_LONG_OPTIONS"},
		{"P-R8-MF3-b MAWK ignore --assign", `MAWK_LONG_OPTIONS=ignore awk --assign 'BEGIN{system("pig")}'`, "MAWK_LONG_OPTIONS"},
		{"P-R8-MF3-c MAWK warn --file", `MAWK_LONG_OPTIONS=warn awk --file=/dev/null 'BEGIN{system("pig")}'`, "MAWK_LONG_OPTIONS"},
		{"P-R8-MF3-d MAWK allow --i", `MAWK_LONG_OPTIONS=allow awk --i 'BEGIN{system("pig")}'`, "MAWK_LONG_OPTIONS"},
		// 附加反例守卫:引号毒化 / 末项非 exec 的逗号链 / R8-Obs-1 穿透 here-string。
		{"R8-neg gawk -W i quote poison", `gawk -W i "a'b" 'BEGIN{system("pig")}'`, "pig"},
		{"R8-neg awk -W i,interactive pig", `awk -W i,interactive 'BEGIN{system("pig")}'`, "pig"},
		{"R8-neg bash -c nested restricted herestring", `bash -c "bash --restricted <<< 'pig'"`, "pig"},
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

	// P-R8-MF3-e: ctx_run env 通道的 MAWK_LONG_OPTIONS 覆盖拦截。
	t.Run("P-R8-MF3-e guardCtxRunEnv MAWK", func(t *testing.T) {
		rule, detail := guardCall{subagent: true}.guardCtxRunEnv(map[string]string{"MAWK_LONG_OPTIONS": "ignore"})
		if rule != "subagent_nested_agent" || detail != "env MAWK_LONG_OPTIONS" {
			t.Fatalf("guardCtxRunEnv(MAWK_LONG_OPTIONS=ignore) = (%q, %q), want (%q, %q)", rule, detail, "subagent_nested_agent", "env MAWK_LONG_OPTIONS")
		}
	})

	// P-R8-SF1-c: 逗号末项名契约 — -W interactive,exec FILE 标记 sawFile。
	t.Run("P-R8-SF1-c awkProgramFrags sawFile contract", func(t *testing.T) {
		_, sawFile, hit := awkProgramFrags([]string{"-W", "interactive,exec", "/tmp/evil.awk"})
		if hit != "" {
			t.Fatalf("awkProgramFrags hit = %q, want empty", hit)
		}
		if !sawFile {
			t.Fatalf("awkProgramFrags(-W interactive,exec FILE) sawFile = false, want true")
		}
	})

	// 放行守卫正例(R8 零假阳纪律)。
	allowCases := []struct {
		name, cmd string
	}{
		{"P-R8-SF1-a awk -W interactive,exec parse", `awk -W interactive,exec parse.awk "$FILE"`},
		{"P-R8-SF1-b xargs awk -W interactive,exec parse", `xargs -a ` + payloadX + ` -I{} awk -W interactive,exec parse.awk {}`},
		{"R8-pos awk -Winteractive,exec parse", `awk -Winteractive,exec parse.awk "$FILE"`},
		{"R8-pos gawk --assign quoted", `VAR='x=1'; gawk --assign "$VAR" '1'`},
		{"R8-pos gawk --as quoted", `VAR='x=1'; gawk --as "$VAR" '1'`},
		{"R8-pos gawk --field-separator quoted", `SEP=','; gawk --field-separator "$SEP" '1'`},
		{"R8-pos awk -Wi benign", `awk -Wi 'BEGIN{print 1}'`},
		{"R8-pos gawk -W i devnull benign", `gawk -W i /dev/null 'BEGIN{print 1}'`},
		{"R8-pos gawk -W i devnull benign -- FILE", `gawk -W i /dev/null 'BEGIN{print 1}' -- "$FILE"`},
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

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R9 (R9 终局收口): R9-MF-1..4 探针回归 —
// R9-MF-1: -Wi/-W i/-W in 碰撞值以 '-' 开头(gawk --include 库文件语义
// 与 mawk 布尔冲突不可调和)一律 fail-closed,不再把 -v/-F/-f/-W 选项词
// 吞入 aux 丢弃真实主程序或放行 -f /dev/stdin;
// R9-MF-2: isSingleWordSplitSafe 收紧全部单值选项槽 — 无引号通配符
// (cmdSubPlaceholderGlob)路径展开产出 N>=2 个 argv 词,match[1..] 溢出
// 至主程序/命令头/子命令槽(awk -F B* / env -a p* / xargs -a p* /
// flock -w 0* / git -C g* / npx --cache p*);
// R9-MF-3: skipEnvOperandsToken 三重缺陷 — GNU env 消费任何含 '=' 的
// 操作数(POSIX 键与否、`--` 之后均为赋值),且 `env FOO=$X` 无引号词
// 拆分(env 的 argv 不是 shell 前缀赋值);
// R9-MF-4: TAR_OPTIONS 与 BASH_FUNC_* 纳入 envHookVars/isEnvHookVar。
// 全部探针仅依赖基线共有入口 rtGuardCwd 与 guardCall.guardCtxRunEnv。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR9Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadProg := mkPayload("r9-prog", "BEGIN{system(\"pig\")}\n")
	payloadX := mkPayload("r9-x", "x\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R9-MF-1: -Wi/-W i/-W in 碰撞值以 '-' 开头一律 fail-closed。
		{"P-R9-MF1-a awk -Wi -v x=1 pig", `awk -Wi -v x=1 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-b awk -W i -v x=1 pig", `awk -W i -v x=1 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-c awk -W in -F : pig", `awk -W in -F : 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-d awk -Wi -f devstdin", `echo 'BEGIN{system("pig")}' | awk -Wi -f /dev/stdin`, "dynamic code payload"},
		{"P-R9-MF1-e awk -Wi -W exec devstdin", `echo 'BEGIN{system("pig")}' | awk -Wi -W exec /dev/stdin`, "dynamic code payload"},
		{"P-R9-MF1-f awk -Wi -W i pig", `awk -Wi -W i 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-g awk -W interactive,i -v pig", `awk -W interactive,i -v x=1 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-h awk -Wi -v x=1 -- VAR", `VAR='BEGIN{system("pig")}'; awk -Wi -v x=1 -- "$VAR"`, "dynamic code payload"},
		{"P-R9-MF1-i xargs awk -Wi -v x=1 -- tok", `xargs -a ` + payloadProg + ` -I{} awk -Wi -v x=1 -- '{}'`, "dynamic code payload"},
		// R9-MF-2: 单值选项槽无引号 glob 多词溢出。
		{"P-R9-MF2-a awk -F glob", `awk -F B*`, "dynamic code payload"},
		{"P-R9-MF2-b awk -v a=1 glob", `awk -v a=1*`, "dynamic code payload"},
		{"P-R9-MF2-c gawk --assign glob", `gawk --assign a=1*`, "dynamic code payload"},
		{"P-R9-MF2-d gawk -W assign glob", `gawk -W assign a=1*`, "dynamic code payload"},
		{"P-R9-MF2-e env -a glob", `env -a p*`, "dynamic option"},
		{"P-R9-MF2-f xargs -a glob", `xargs -a p*`, "dynamic command head"},
		{"P-R9-MF2-g flock -w glob", `flock -w 0* pig`, "dynamic code payload"},
		{"P-R9-MF2-h git -C glob", `git -C g* -Opig foo`, "git dynamic global option"},
		{"P-R9-MF2-i npx --cache glob", `npx --cache p*`, "dynamic code payload"},
		// R9-MF-3: skipEnvOperandsToken 三重缺陷。
		{"P-R9-MF3-a env a.b=1 pig", `env 'a.b=1' pig`, "pig"},
		{"P-R9-MF3-b env a-b=1 hc", `env 'a-b=1' hc list`, "hc"},
		{"P-R9-MF3-c env -- -x=1 pig", `env -- -x=1 pig`, "pig"},
		{"P-R9-MF3-d env -- a.b=1 pig", `env -- 'a.b=1' pig`, "pig"},
		{"P-R9-MF3-e env FOO=X unquoted", `X='1 pig'; env FOO=$X`, "dynamic option"},
		{"P-R9-MF3-f xargs env a.b=1 env -S", `xargs -a ` + payloadX + ` -I{} env 'a.b=1' env -S "find . -name {}"`, "dynamic code payload"},
		// R9-MF-4: TAR_OPTIONS / BASH_FUNC_* 钩子变量。
		{"P-R9-MF4-a TAR_OPTIONS use-compress-program", `TAR_OPTIONS='--use-compress-program=pig' tar -cf /dev/null /dev/null`, "TAR_OPTIONS"},
		{"P-R9-MF4-b TAR_OPTIONS checkpoint-action", `TAR_OPTIONS='--checkpoint=1 --checkpoint-action=exec=pig' tar -cf /dev/null /dev/null`, "TAR_OPTIONS"},
		{"P-R9-MF4-e env BASH_FUNC bash", `env 'BASH_FUNC_echo%%=() { pig; }' bash -c 'echo hi'`, "BASH_FUNC_echo%%"},
		// 附加回归(Oracle R9 底部):-Wi - 保精准 stdin 裁决;-W i -foo
		// 与 glob/`--` 变体全 BLOCK。
		{"R9-reg awk -Wi dash stdin", `awk -Wi -`, "awk script from stdin"},
		{"R9-reg gawk -W i -foo pig", `gawk -W i -foo 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"R9-reg env -- FOO=X unquoted", `X='1 pig'; env -- FOO=$X`, "dynamic option"},
		{"R9-reg gawk --field-separator glob", `gawk --field-separator B*`, "dynamic code payload"},
		{"R9-reg gawk -W assign=a=1 glob", `gawk -W assign=a=1*`, "dynamic code payload"},
		{"R9-reg env --argv0 glob", `env --argv0 p*`, "dynamic option"},
		{"R9-reg env -C glob", `env -C p*`, "dynamic option"},
		{"R9-reg xargs --arg-file glob", `xargs --arg-file p*`, "dynamic command head"},
		{"R9-reg flock --timeout glob", `flock --timeout 0* pig`, "dynamic code payload"},
		{"R9-reg flock -xw glob", `flock -xw 0* pig`, "dynamic code payload"},
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

	// P-R9-MF4-c: ctx_run env 通道的 TAR_OPTIONS 覆盖拦截。
	t.Run("P-R9-MF4-c guardCtxRunEnv TAR_OPTIONS", func(t *testing.T) {
		rule, detail := guardCall{subagent: true}.guardCtxRunEnv(map[string]string{"TAR_OPTIONS": "--use-compress-program=pig"})
		if rule != "subagent_nested_agent" || detail != "env TAR_OPTIONS" {
			t.Fatalf("guardCtxRunEnv(TAR_OPTIONS) = (%q, %q), want (%q, %q)", rule, detail, "subagent_nested_agent", "env TAR_OPTIONS")
		}
	})

	// P-R9-MF4-d: ctx_run env 通道的 BASH_FUNC_* 覆盖拦截。
	t.Run("P-R9-MF4-d guardCtxRunEnv BASH_FUNC", func(t *testing.T) {
		rule, detail := guardCall{subagent: true}.guardCtxRunEnv(map[string]string{"BASH_FUNC_echo%%": "() { pig; }"})
		if rule != "subagent_nested_agent" || detail != "env BASH_FUNC_echo%%" {
			t.Fatalf("guardCtxRunEnv(BASH_FUNC_echo%%) = (%q, %q), want (%q, %q)", rule, detail, "subagent_nested_agent", "env BASH_FUNC_echo%%")
		}
	})

	// 放行守卫正例(R9 零假阳纪律):带引号动态值、单字 glob 多文件操作数、
	// 纯波浪线路径与非 POSIX 键 env 赋值全部保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R9-pos awk -W interactive -v benign", `awk -W interactive -v x=1 'BEGIN{print 1}'`},
		{"R9-pos awk -v x=1 -Wi benign", `awk -v x=1 -Wi 'BEGIN{print 1}'`},
		{"R9-pos awk -Wi benign", `awk -Wi 'BEGIN{print 1}'`},
		{"R9-pos gawk -W i devnull benign", `gawk -W i /dev/null 'BEGIN{print 1}'`},
		{"R9-pos gawk -W i devnull benign -- FILE", `gawk -W i /dev/null 'BEGIN{print 1}' -- "$FILE"`},
		{"R9-pos awk glob log", `awk '{print $1}' /tmp/*.log`},
		{"R9-pos awk -v ts quoted", `awk -v ts="$val" 'BEGIN{print ts}'`},
		{"R9-pos env a.b=1 ls", `env 'a.b=1' ls`},
		{"R9-pos env FOO=X quoted", `env FOO="$X" ls`},
		{"R9-pos env -- FOO=X quoted VAR", `env -- FOO="$X" ls "$VAR"`},
		{"R9-pos env -- ls VAR", `env -- ls "$VAR"`},
		// 注: Oracle R9 正例列表中的 `env -C "$PWD" ls` 未纳入 — R2-4 既有契约
		// (zz_r2fix_test.go:130)对动态 chdir 目录一律 fail-closed,属 Oracle 与
		// 基线固定契约的冲突,不改核心策略,报告中列明偏差。
		{"R9-pos xargs -a FILE grep", `xargs -a "$FILE" grep foo`},
		{"R9-pos flock -w T lk true", `flock -w "$T" /tmp/lk true`},
		{"R9-pos git -C DIR status", `git -C "$DIR" status`},
		{"R9-pos npx --userconfig tilde", `npx --userconfig ~/.npmrc tsc --noEmit`},
		{"R9-pos FOO=X shell prefix true", `FOO=$X true`},
		{"R9-pos python glob pytest", `python3 -m pytest tests/*.py`},
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

// TestGuard_V622_OracleR10Probes covers the Oracle R10 must-fix matrix:
// tar/find/sed/ssh separated single-value operand slots must require
// isSingleWordSplitSafe on dynamic words (R10-MF-1/2/3), the separated
// --checkpoint-action operand must refuse every dynamic word, and a
// declaration builtin demoted by a non-assignment wrapper (command/
// builtin) must reject non-split-safe dynamic export operands
// (R10-MF-4) — plus the shell_ast.go isEnvHookVar closure for
// GIT_CONFIG_PARAMETERS-style hook variables. Zero new production symbols
// are referenced here: every probe goes through rtGuardCwd.
func TestGuard_V622_OracleR10Probes(t *testing.T) {
	blockCases := []struct {
		name, cmd, want string
	}{
		// R10-MF-1: tar 分离值槽词拆分/glob 溢出与动态 --checkpoint-action。
		{"P-R10-MF1-a tar checkpoint-action quoted VAR", `VAR='exec=pig'; tar --checkpoint=1 --checkpoint-action "$VAR" -cf /dev/null /dev/null`, "dynamic code payload"},
		{"P-R10-MF1-b tar -cf unquoted VAR", `VAR='/dev/null -Ipig'; tar -cf $VAR /dev/null`, "dynamic code payload"},
		{"P-R10-MF1-c tar -f unquoted VAR", `VAR='/dev/null --use-compress-program=pig'; tar -f $VAR -c /dev/null`, "dynamic code payload"},
		{"P-R10-MF1-d tar --file unquoted VAR", `VAR='/dev/null --use-compress-program=pig'; tar --file $VAR -c /dev/null`, "dynamic code payload"},
		{"P-R10-MF1-e tar cfI glob", `tar cfI p*`, "dynamic code payload"},
		{"P-R10-MF1-e2 tar cfI unquoted VAR", `X='/dev/null pig /dev/null'; tar cfI $X`, "dynamic code payload"},
		// R10-MF-2: find -name/-fprintf 值槽词拆分与 glob 吞噬 -exec。
		{"P-R10-MF2-a find -name unquoted VAR", `VAR='null -exec pig ;'; find /dev/null -name $VAR`, "find dynamic predicate"},
		{"P-R10-MF2-b find -fprintf glob", `find /dev/null -fprintf p* -exec pig \;`, "find dynamic predicate"},
		{"P-R10-MF2-c find -fprintf unquoted VAR", `VAR='/dev/null fmt'; find /dev/null -fprintf $VAR -exec pig \;`, "find dynamic predicate"},
		// R10-MF-3: sed -l/--line-length 与 ssh 值选项分离值槽。
		{"P-R10-MF3-a sed -l unquoted VAR", `VAR='80 -e 1epig'; sed -e '1p' -l $VAR CHANGELOG.md`, "dynamic code payload"},
		{"P-R10-MF3-a2 sed --line-length unquoted VAR", `VAR='80 -e 1epig'; sed -e '1p' --line-length $VAR CHANGELOG.md`, "dynamic code payload"},
		{"P-R10-MF3-b sed -l glob", `sed -l 1* CHANGELOG.md`, "dynamic code payload"},
		{"P-R10-MF3-b2 sed --line-length glob", `sed --line-length 1* CHANGELOG.md`, "dynamic code payload"},
		{"P-R10-MF3-c ssh -p unquoted VAR", `VAR='22 -o ProxyCommand=pig'; ssh -p $VAR dmit ls`, "dynamic code payload"},
		{"P-R10-MF3-d ssh -l glob", `ssh -l p* a true`, "dynamic code payload"},
		// R10-MF-4: command/builtin export 词拆分导出与 GIT_CONFIG_* 钩子变量。
		{"P-R10-MF4-a command export TAR_OPTIONS", `X='1 TAR_OPTIONS=--use-compress-program=pig'; command export FOO=$X; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R10-MF4-b builtin export BASH_FUNC", `bash -c 'X="1 BASH_FUNC_echo%%=() { pig; }"; builtin export FOO=$X; bash -c "echo hi"'`, "env dynamic export"},
		{"P-R10-MF4-c command export glob", `command export FOO=T*`, "env dynamic export"},
		// R11-MF-3: the UNQUOTED spelling is the discriminating probe — the
		// quoted variant hits paramExpD2Ambiguous before reaching
		// peAssignsHookOrTaint, so it could never reproduce RED on b13a82b.
		{"P-R10-MF4-d GIT_CONFIG_PARAMETERS paramexp", `set -a; printf '' ${GIT_CONFIG_PARAMETERS:='alias.x=!pig'}; git x`, ""},
		{"P-R10-MF4-d2 GIT_CONFIG_PARAMETERS quoted", `set -a; printf '' "${GIT_CONFIG_PARAMETERS:='alias.x=!pig'}"; git x`, ""},
		{"P-R10-MF4-e GIT_CONFIG_PARAMETERS for-loop", `set -a; for GIT_CONFIG_PARAMETERS in "'alias.x=!pig'"; do git x; done`, ""},
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

	// 放行守卫正例(R10 零假阳纪律):带引号单值槽、BSD 消耗槽带引号值、
	// xargs 静态 {} 替换、裸/包装声明内建的带引号与无包装动态赋值全部
	// 保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R10-pos tar -cf quoted OUT", `tar -cf "$OUT" /tmp/*.log`},
		{"R10-pos tar -C xf quoted", `tar -C "$DIR" -xf "$ARCHIVE"`},
		{"R10-pos find -name quoted PAT", `find . -name "$PAT"`},
		{"R10-pos find PWD maxdepth", `find "$PWD" -maxdepth 1`},
		{"R10-pos xargs find -ctime token", `echo 5 | xargs -I{} find . -ctime {}`},
		{"R10-pos find -exec rg", `find . -name '*.go' -exec rg foo {} \;`},
		{"R10-pos sed -l quoted N", `sed -l "$N" '1p' CHANGELOG.md`},
		{"R10-pos ssh -p quoted PORT", `ssh -p "$PORT" dmit ls`},
		{"R10-pos ssh -i quoted KEY", `ssh -i "$KEY" dmit ls`},
		{"R10-pos command export quoted", `command export FOO="$X"`},
		{"R10-pos bash -c export quoted", `bash -c 'export FOO="$X"'`},
		{"R10-pos bare export unquoted", `export FOO=$X`},
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

// TestGuard_V622_OracleR11Probes covers the Oracle R11 must-fix matrix:
// trailing dangling tar value options must never panic the guard
// (R11-MF-1), quoted/escaped/enum-expanded/env -S-rewritten declaration
// builtins lose their field-splitting exemption (R11-MF-2), and
// printf -v/read/getopts write-target slots must vet glued and repeated
// spellings plus dynamic single-value operands (R11-MF-3). Zero new
// production symbols are referenced here: every probe goes through
// rtGuardCwd so an independent verifier can copy this file onto the
// pre-fix tree fd8f417 and reproduce FAIL/panic directly.
func TestGuard_V622_OracleR11Probes(t *testing.T) {
	// R11-MF-1: trailing dangling value options must not panic. On the
	// pre-fix tree ANY of these crashes the test binary with
	// `panic: index out of range`; the rows assert nothing about the
	// verdict itself — reaching the comparison IS the assertion.
	noPanicShell := []struct {
		name, cmd string
	}{
		{"P-R11-MF1-a tar -f dangling", `tar -f`},
		{"P-R11-MF1-b tar --file dangling", `tar --file`},
		{"P-R11-MF1-b2 tar -cf then -C dangling", `tar -cf /dev/null -C`},
		{"P-R11-MF1-b3 tar -C dangling", `tar -C`},
		{"P-R11-MF1-b4 tar --directory dangling", `tar --directory`},
	}
	for _, tc := range noPanicShell {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "" {
				t.Fatalf("rtGuardCwd(%q) returned empty verdict", tc.cmd)
			}
		})
	}
	noPanicArgv := []struct {
		name string
		argv []string
	}{
		{"P-R11-MF1-c argv tar -f dangling", []string{"tar", "-f"}},
		{"P-R11-MF1-d argv tar --file dangling", []string{"tar", "--file"}},
		{"P-R11-MF1-e argv tar -cf then -C dangling", []string{"tar", "-cf", "/dev/null", "-C"}},
	}
	for _, tc := range noPanicArgv {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", argv: tc.argv}, "")
			if got == "" {
				t.Fatalf("rtGuardCwd(%v) returned empty verdict", tc.argv)
			}
		})
	}

	blockCases := []struct {
		name, cmd, want string
	}{
		// R11-MF-2: quoted/escaped/enum-expanded/env -S declaration heads.
		{"P-R11-MF2-a dq export demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; "export" FOO=$X; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R11-MF2-b backslash export demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; \export FOO=$X; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R11-MF2-b2 sq export demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; 'export' FOO=$X; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R11-MF2-c enum export demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; for E in export; do $E FOO=$X; done; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R11-MF2-d env -S rewrite demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; env -S 'command export a=1 b=2' FOO=$X`, "env dynamic export"},
		// R11-MF-3: printf -v glued/repeated, read/getopts dynamic slots.
		{"P-R11-MF3-a printf -vTAR_OPTIONS glued", `bash -c 'set -a; printf -vTAR_OPTIONS "%s" "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env TAR_OPTIONS"},
		{"P-R11-MF3-b printf repeated -v", `bash -c 'set -a; printf -v x -v TAR_OPTIONS "%s" "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env TAR_OPTIONS"},
		{"P-R11-MF3-c read -p dynamic split", `bash -c 'set -a; X="x TAR_OPTIONS"; read -p $X <<< "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env dynamic read"},
		{"P-R11-MF3-d getopts dynamic optstring", `set -a; X='1 GIT_CONFIG_COUNT'; getopts $X -1`, "env dynamic getopts"},
		{"P-R11-MF3-e getopts glob optstring", `set -a; getopts p* -1`, "env dynamic getopts"},
		// R11 closure: quoted dynamic OPTION-ZONE words pick their option
		// letters (or terminator status) at runtime even though the expansion
		// itself never field-splits.
		{"P-R11-MF3-f printf dq dynamic format", `bash -c 'set -a; OPT="-vTAR_OPTIONS"; printf "$OPT" "%s" "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env dynamic printf"},
		// NOTE: the value must NOT be a static-literal single assignment —
		// the collector in-lines safe literals, so `OPT="vTAR_OPTIONS"` would
		// statically resolve `-$OPT` to `-vTAR_OPTIONS` and hit the (correct)
		// static `env TAR_OPTIONS` verdict instead of exercising the dynamic
		// branch. Concatenating an undefined expansion keeps the word dynamic.
		{"P-R11-MF3-g printf dq dash-prefixed", `bash -c 'set -a; OPT="vTAR_OPTIONS$NOPE"; printf "-$OPT" "%s" "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env dynamic printf"},
		{"P-R11-MF3-h read dq dash-prefixed cluster", `bash -c 'set -a; OPT="aTAR_OPTIONS"; read "-$OPT" <<< "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env dynamic read"},
		{"P-R11-MF3-i getopts dq terminator shift", `set -a; H="--"; getopts "$H" opt TAR_OPTIONS`, "env TAR_OPTIONS"},
		{"P-R11-MF3-j getopts dq terminator dyn name", `set -a; H="--"; V='GIT_CONFIG_COUNT'; getopts "$H" opt "$V"`, "env dynamic getopts"},
		// R11 closure: quoted/escaped declaration heads inside the BASH-dialect
		// parse (bash -c) lose field-splitting exemption exactly like the
		// POSIX-level probes a/b above.
		{"P-R11-MF2-e bash -c dq export demotion", `bash -c 'X="1 TAR_OPTIONS=--use-compress-program=pig"; "export" FOO=$X; tar -cf /dev/null /dev/null'`, "env dynamic export"},
		{"P-R11-MF2-f bash -c backslash export demotion", `bash -c 'X="1 TAR_OPTIONS=--use-compress-program=pig"; \export FOO=$X; tar -cf /dev/null /dev/null'`, "env dynamic export"},
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

	// 放行守卫正例(R11 零假阳纪律):无包装声明内建、带引号包装导出、
	// printf 格式串/-- 终止、带引号 read 提示符、静态/带引号 getopts
	// 与正常 tar 带值选项全部保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R11-pos tar -cf quoted OUT", `tar -cf "$OUT" /dev/null`},
		{"R11-pos tar -C xf normal", `tar -C /tmp -xf "$ARCHIVE"`},
		{"R11-pos bare export unquoted", `export FOO=$X`},
		{"R11-pos prefix-assign export", `A=1 export FOO=$X`},
		{"R11-pos bash -c export quoted", `bash -c 'export FOO="$X"'`},
		{"R11-pos command export quoted", `command export FOO="$X"`},
		{"R11-pos printf format quoted", `printf '%s\n' "$X"`},
		{"R11-pos printf dq static format", `printf "val=$X\n"`},
		{"R11-pos printf -- terminator", `printf -- -v TAR_OPTIONS`},
		{"R11-pos printf -v benign", `printf -v myvar '%s' "$X"`},
		{"R11-pos printf -vmyvar glued benign", `printf -vmyvar '%s' "$X"`},
		{"R11-pos read -p quoted prompt", `bash -c 'read -p "$PROMPT" x <<< y'`},
		{"R11-pos read -r plain", `read -r line`},
		{"R11-pos getopts static optstring", `getopts ":ab:" opt`},
		{"R11-pos getopts quoted optstring", `getopts "$OPTS" opt`},
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

// TestGuard_V622_ReviewerR4Probes covers the Reviewer R4 / Oracle R12 audit
// matrix: printf write-target closure (glued/clustered -v, static %n slots
// with Bash format reuse, dynamic format strings and array-subscripted write
// targets — R4-MF-1/MF-3/MF-4), printf first-word glob expansion into the
// option zone (R4-MF-2), GNU tar --occurrence as an OPTIONAL-argument option
// (R4-MF-5), read's -i value letter and glued dynamic value tails (R4-SF-1),
// and the getopts dynamic first operand standby slot narrowed to a real "--"
// expansion shape (R4-SF-2). Zero new production symbols are referenced here:
// every probe goes through rtGuardCwd so an independent verifier can copy
// this file onto the pre-fix tree 9139e0e and reproduce FAIL directly.
func TestGuard_V622_ReviewerR4Probes(t *testing.T) {
	blockCases := []struct {
		name, cmd, want string
	}{
		// R4-MF-1: preScanVarMutations never counted glued/clustered -v or
		// %n writes, so a second write into `cmd` stayed static-bindable.
		{"P-R4-MF1-a printf glued -v double write", `bash -c 'cmd=/bin/true; printf -vcmd %s pig; "$cmd"'`, ""},
		{"P-R4-MF1-b printf clustered -v double write", `bash -c 'cmd=/bin/true; printf -v cmd %s pig; "$cmd"'`, ""},
		// R4-MF-3: static format-string %n write targets were never scanned.
		{"P-R4-MF3-a printf %n TAR_OPTIONS", `bash -c 'printf "%n" TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R4-MF3-b printf %n aligned arg", `bash -c 'printf "%s %n" x TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R4-MF3-c printf -- %n", `bash -c 'printf -- "%n" TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R4-MF3-d printf width-star %n alignment", `bash -c 'printf "%*s %n" 1 x TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R4-MF3-e printf dynamic fmt args", `bash -c 'printf x"$FMT" "%s" x'`, "env dynamic printf"},
		{"P-R4-MF3-f printf %n unquoted arg splitting", `bash -c 'printf "%s %n" $X TAR_OPTIONS'`, "env dynamic printf"},
		{"P-R4-MF3-g printf %n dynamic target", `bash -c 'printf "%n" "$X"'`, "env dynamic printf"},
		{"P-R4-MF3-h printf %n array subscript hook", `bash -c 'printf "%n" '\''TAR_OPTIONS[0]'\'''`, "env TAR_OPTIONS"},
		{"P-R4-MF3-i printf %n dynamic subscript", `bash -c 'printf "%n" "x[$(echo 0)]"'`, "env dynamic printf"},
		// R13-SF-4: inside bash double quotes '$' starts a parameter expansion,
		// so the positional designator must be backslash-escaped to reach
		// printf as literal '%2$s%n' (unescaped '$s' expanded empty and the
		// probe tested the wrong string).
		{"P-R4-MF3-j printf %n positional slot", `bash -c 'printf "%2\$s%n" x TAR_OPTIONS'`, "env dynamic printf"},
		// R14 closure: bash printf honours length modifiers on '%n', the
		// '%*2$n' star-positional width is unvettable, and a glob-expanded
		// filename can legitimately spell '%n' (`lit%n`) so a glob-only
		// format word WITH arguments is no longer trusted.
		{"P-R14-1 printf glob-only fmt with args", `printf lit* TAR_OPTIONS`, "env dynamic printf"},
		// R13-MF-1: even with NO trailing argument an unquoted glob format
		// word can expand to MULTIPLE words at runtime — match[0] becomes the
		// real format string and match[1] the first argument, so `lit%n`
		// content would write into whatever match[1] names. Only a split-safe
		// (quoted) zero-argument spelling stays safe.
		{"P-R13-MF1 printf glob fmt no args", `printf lit*`, "env dynamic printf"},
		{"P-R14-2 printf %ln length modifier", `bash -c 'printf "%ln" TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R14-3 printf %hhn length modifier", `bash -c 'printf "%hhn" TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R14-4 printf star-positional %n", `bash -c 'printf "%*2\$n" 1 TAR_OPTIONS'`, "env dynamic printf"},
		// R14 closure: read's separate value operand word-splits at runtime
		// when unquoted (`read -p $X` with X="p cmd"), shifting the positional
		// layout. The argv layer already refused this shape at 9139e0e
		// (readClusterStep vets the consumed operand), so the discriminating
		// regression pin is the direct preScanVarMutations unit row below the
		// positive table.
		{"P-R14-5-shell read -p unquoted value blocks", `bash -c 'cmd=/bin/true; X="p cmd"; read -p $X <<< pig; "$cmd"'`, ""},
		// R4-MF-4: write-target subscripts must validate their base name and
		// reject arithmetic/dynamic subscripts fail-closed. NOTE: an UNQUOTED
		// arr[0] is itself a glob character class (litHasUnquotedGlobOrTilde),
		// so the static-subscript spellings are single-quoted here.
		{"P-R4-MF4-a printf -v array hook", `bash -c 'printf -v '\''TAR_OPTIONS[0]'\'' "%s" x'`, "env TAR_OPTIONS"},
		{"P-R4-MF4-b printf -v glued array hook", `bash -c 'printf "-vTAR_OPTIONS[0]" "%s" x'`, "env TAR_OPTIONS"},
		{"P-R4-MF4-c printf -v arithmetic subscript", `bash -c 'printf -v x[1+1] "%s" y'`, "env dynamic printf"},
		{"P-R4-MF4-d printf -v dangling subscript", `bash -c 'printf -v x[0 "%s" y'`, "env dynamic printf"},
		// R4-MF-2: a glob word first in the format position may expand into
		// -vNAME at runtime, desynchronizing the option zone.
		{"P-R4-MF2-a printf glob star format", `printf * '%s' x`, "env dynamic printf"},
		{"P-R4-MF2-b printf glob qmark format", `printf ? '%s' x`, "env dynamic printf"},
		// R4-MF-5: GNU tar --occurrence[=N] is optional-argument — the bare
		// spelling consumes NO operand, so the following exec hook must be
		// scanned instead of swallowed as the "occurrence value".
		{"P-R4-MF5-a tar occurrence swallow glued hook", `tar --occurrence --use-compress-program=pig -cf /dev/null /dev/null`, ""},
		{"P-R4-MF5-b tar occurrence swallow split hook", `tar --occurrence --use-compress-program pig -cf /dev/null /dev/null`, ""},
		// R4-SF-1: a dynamic placeholder inside read's option-letter zone is
		// unvettable, including a glued -p tail that word-splits at runtime.
		{"P-R4-SF1-a read glued -p unquoted dyn", `bash -c 'read -p$P x <<< y'`, "env dynamic read"},
		// R13-MF-4: a glued dynamic prompt tail that can expand EMPTY at
		// runtime (`read -p"$PROMPT"` with PROMPT='') turns into `read -p`
		// which consumes the NEXT argv word as the prompt — the positional
		// write-target layout diverges from the static scan.
		{"P-R13-MF4 read glued empty-able dq prompt", `bash -c 'read -p"$PROMPT" answer <<< y'`, "env dynamic read"},
		// R4-SF-2: a dynamic getopts first operand may expand to exactly "--",
		// shifting NAME out of its static slot.
		{"P-R4-SF2-a getopts dyn terminator hook", `set -a; H="--"; getopts "$H" opt TAR_OPTIONS`, "env TAR_OPTIONS"},
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

	// 放行守卫正例(R4 零假阳纪律):普通/复用格式串参数、带引号动态格式串
	// 无参、静态下标合法数组写、安全字面前缀 glob、tar 正常带参、read -p/-i
	// 带引号提示与初始值、getopts 带冒号/字母的动态 OPTSTRING 全部保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R4-pos printf static fmt benign", `bash -c 'printf "%s %s" "$A" "$B"'`},
		{"R4-pos printf fmt reuse benign", `bash -c 'printf "%s" "$A" "$B"'`},
		{"R4-pos printf dq fmt no args", `bash -c 'printf x"$FMT"'`},
		{"R4-pos printf unquoted arg no %n", `printf '%s\n' $UNQUOTED`},
		{"R4-pos printf %n benign var", `bash -c 'printf "%n" myvar'`},
		{"R4-pos printf %n benign array", `bash -c 'printf "%n" '\''arr[0]'\'''`},
		{"R4-pos printf -v benign array", `bash -c 'printf -v '\''arr[0]'\'' "%s" x'`},
		// R14 closure: the glob-only literal-prefix positive keeps ONLY the
		// zero-argument spelling — with no arguments nothing can be written
		// regardless of what the expansion spells; ANY trailing argument
		// makes the dynamically shaped format unvettable (blocked above).
		{"R4-pos printf glob literal prefix quoted no args", `printf 'lit*'`},
		{"R14-pos printf strftime width conv", `bash -c 'printf "%10(%Y)T\n" -1'`},
		{"R4-pos printf quoted star format", `printf '*' '%s' x`},
		{"R4-pos tar occurrence value benign", `tar --occurrence 2 -tf /dev/null`},
		{"R4-pos tar occurrence glued benign", `tar --occurrence=2 -tf /dev/null`},
		{"R4-pos read -p glued dq prompt", `bash -c 'read -p"Prompt: $PROMPT" line <<< y'`},
		{"R4-pos read -ei separate value", `bash -c 'read -ei "$DEFAULT" answer <<< y'`},
		{"R4-pos getopts colon dyn optstring", `getopts ":$OPTS" opt TAR_OPTIONS`},
		{"R4-pos getopts colon dyn optstring arg", `getopts ":$OPTS" opt "$arg"`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// P-R14-5 direct unit pin: rtGuardCwd cannot discriminate this fix
	// because screenReadEnvWrite's readClusterStep already refuses a
	// word-splitting separate value operand at the argv layer — the
	// preScanVarMutations taint is DEPTH defense for the shell-string
	// static-bind analysis inside bash -c. The regression is pinned at
	// the function itself: an unquoted expansion in read's consumed value
	// slot (`read -p $X` — X="p cmd" word-splits at runtime, shifting the
	// positional layout so the REAL write targets diverge from the static
	// operand scan) must taint every static bind, while the split-safe
	// quoted spelling keeps the scan clean.
	t.Run("P-R14-5 preScanVarMutations read unquoted value slot", func(t *testing.T) {
		p := syntax.NewParser()
		f, err := p.Parse(strings.NewReader(`X="p cmd"; read -p $X <<< pig; echo ok`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		_, tainted := preScanVarMutations(f)
		if !tainted {
			t.Fatal("preScanVarMutations(read -p $X): allTainted = false, want true (unquoted value slot word-splits at runtime)")
		}
	})
	t.Run("P-R14-5-pos preScanVarMutations read quoted value slot", func(t *testing.T) {
		p := syntax.NewParser()
		f, err := p.Parse(strings.NewReader(`read -p "$PROMPT" x <<< pig; echo ok`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		_, tainted := preScanVarMutations(f)
		if tainted {
			t.Fatal("preScanVarMutations(read -p \"$PROMPT\" x): allTainted = true, want false (quoted value stays one argv word)")
		}
	})
}

// TestGuard_V622_OracleR13Probes pins the Oracle R13 audit closure:
// printf zero-argument dynamic/glob format write slots (R13-MF-1), the
// '%q' conversion letter mis-parsed as a length modifier (R13-MF-2),
// read's static-cluster end-letter misjudgment `-eii` (R13-MF-3), a glued
// dynamic read prompt tail that can expand empty and swallow the next
// argv word (R13-MF-4), the printf/read/getopts AST pre-scan alignment
// (R13-SF-1), dynWordCanSpellDashDash exactness and the '$$' PID
// recognition (R13-SF-2) and external-path /usr/bin/printf exemption
// (R13-SF-3). Pure-function pins reference only existing production
// symbols plus parse helpers, so the file can be copied onto the pre-fix
// tree 056cb3e5 to reproduce FAIL directly.
func TestGuard_V622_OracleR13Probes(t *testing.T) {
	// ---- Pure-function pins (R13-SF-4) ----
	t.Run("R13-MF1 printfFmtWriteSlots zero-arg glob fmt is dyn", func(t *testing.T) {
		if _, dyn := printfFmtWriteSlots("sample*"+cmdSubPlaceholderGlob, nil); !dyn {
			t.Fatal("printfFmtWriteSlots(glob-only fmt, no args): dyn = false, want true (glob expands to many words — match[0] becomes the format, match[1] a '%n' write target)")
		}
	})
	t.Run("R13-MF1-pos printfFmtWriteSlots zero-arg split-safe fmt stays safe", func(t *testing.T) {
		if _, dyn := printfFmtWriteSlots("sample"+cmdSubPlaceholderQuoted, nil); dyn {
			t.Fatal("printfFmtWriteSlots(quoted dyn fmt, no args): dyn = true, want false (no arguments — nothing can be written)")
		}
	})
	t.Run("R13-MF2 printfFmtSlots %q%n is conv+write pair", func(t *testing.T) {
		slots, pos := printfFmtSlots("%q%n")
		if pos || len(slots) != 2 || slots[0] || !slots[1] {
			t.Fatalf("printfFmtSlots(%%q%%n) = %v positional=%v, want [false true] positional=false ('q' is a conversion letter, not a length modifier)", slots, pos)
		}
	})
	t.Run("R13-MF2-pos printfFmtSlots %qn is single non-write slot", func(t *testing.T) {
		slots, pos := printfFmtSlots("%qn")
		if pos || len(slots) != 1 || slots[0] {
			t.Fatalf("printfFmtSlots(%%qn) = %v positional=%v, want [false] positional=false (the trailing 'n' is literal text after the %%q conversion)", slots, pos)
		}
	})
	t.Run("R13-MF3 preScanVarMutations read -eii counts sample", func(t *testing.T) {
		p := syntax.NewParser()
		f, err := p.Parse(strings.NewReader(`read -eii sample <<< ok`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		writes, tainted := preScanVarMutations(f)
		if tainted {
			t.Fatal("preScanVarMutations(read -eii sample): allTainted = true, want false")
		}
		if writes["sample"] != 1 {
			t.Fatalf("preScanVarMutations(read -eii sample): writes[sample] = %d, want 1 (the glued -i VALUE ends the cluster — trailing 'i' text never consumes the next word)", writes["sample"])
		}
	})
	t.Run("R13-MF4 readDynClusterHit empty-able glued prompt tail blocks", func(t *testing.T) {
		if hit := readDynClusterHit("-p" + cmdSubPlaceholderQuoted); hit == "" {
			t.Fatal("readDynClusterHit(-p\"$PROMPT\") = \"\", want non-empty (an empty PROMPT collapses the glued tail so -p swallows the next argv word)")
		}
	})
	t.Run("R13-MF4-pos readDynClusterHit static-prefix prompt tail allows", func(t *testing.T) {
		if hit := readDynClusterHit("-pPrompt: " + cmdSubPlaceholderQuoted); hit != "" {
			t.Fatalf("readDynClusterHit(-p\"Prompt: $PROMPT\") = %q, want empty (static non-empty prefix keeps the glued tail non-empty at runtime)", hit)
		}
	})
	t.Run("R13-SF2 dynWordCanSpellDashDash precision", func(t *testing.T) {
		if dynWordCanSpellDashDash("---" + cmdSubPlaceholderQuoted) {
			t.Fatal("dynWordCanSpellDashDash(---$X) = true, want false (three static dashes can never shrink to exactly '--')")
		}
		if dynWordCanSpellDashDash(cmdSubPlaceholderAbsDq) {
			t.Fatal("dynWordCanSpellDashDash(abs-dq) = true, want false (absolute-path expansions always start with '/')")
		}
		if dynWordCanSpellDashDash("0" + cmdSubPlaceholderQuoted) {
			t.Fatal("dynWordCanSpellDashDash(PID encoding) = true, want false ('$$' is decimal digits, never '--')")
		}
		if !dynWordCanSpellDashDash("--" + cmdSubPlaceholderQuoted) {
			t.Fatal("dynWordCanSpellDashDash(--$X) = false, want true (an empty expansion spells exactly '--')")
		}
	})

	// ---- End-to-end guard verdicts ----
	blockCases := []struct {
		name, cmd, want string
	}{
		// R13-MF-2 argv layer: '%q' was skipped as a length modifier, so
		// printf "%q%n" hid its write conversion and printf "%qn" invented
		// a false '%n' write.
		{"P-R13-MF2-a printf %q%n write", `bash -c 'printf "%q%n" x TAR_OPTIONS'`, "env TAR_OPTIONS"},
		// R13-MF-3: `read -eii sample` — the trailing 'i' is the glued -i
		// initial value text, so `sample` remains the write target; the
		// pre-scan must count it so a double write into `sample` blocks the
		// static bind.
		{"P-R13-MF3 read -eii sample rewrite", `bash -c 'sample=/bin/true; read -eii sample <<< pig; "$sample"'`, ""},
		// R13-MF-4 shell layer: an empty-expanding glued prompt swallows the
		// positional layout inside a bash -c script.
		{"P-R13-MF4-shell read empty-able prompt in script", `bash -c 'cmd=/bin/true; read -p"$PROMPT" answer <<< ok; "$cmd"'`, ""},
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

	// 放行守卫正例(R13 零假阳纪律):'%q' 引号转换、分离写法 read 提示符、
	// 静态非空前缀粘连提示符、printf/read/getopts 带安全动态参数的组合脚
	// 本、'$$' PID OPTSTRING 与显式路径 /usr/bin/printf 全部保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R13-pos printf %qn conversion benign", `bash -c 'printf "%qn" "$X"'`},
		{"R13-pos read -p separate dq prompt", `bash -c 'read -p "$PROMPT" answer <<< y'`},
		{"R13-pos read -p glued static-prefix prompt", `bash -c 'read -p"Prompt: $PROMPT" line <<< y'`},
		// R13-SF-1: combination scripts with dynamic but safe printf/read/
		// getopts arguments must not all-taint the pre-scan — `cmd` keeps
		// its static bind and the script stays ALLOW.
		{"R13-SF1 printf dyn args in script", `bash -c 'cmd=/bin/true; printf "%s" "$DATA"; "$cmd"'`},
		{"R13-SF1 read static-prefix prompt in script", `bash -c 'cmd=/bin/true; read -p"Prompt: $PROMPT" answer <<< ok; "$cmd"'`},
		{"R13-SF1 getopts colon dyn optstring in script", `bash -c 'cmd=/bin/true; getopts ":$OPTS" opt; "$cmd"'`},
		// R13-SF-2: '$$' expands to decimal PID digits — it can never spell
		// the "--" terminator, so the standby NAME slot is not vetted.
		{"R13-SF2 getopts PID optstring", `bash -c 'getopts "$$" opt "$arg"'`},
		// R13-SF-3: an explicit-path printf invokes /usr/bin/printf — a
		// child process can never write shell variables, so neither the
		// dynamic format text nor '%n'-looking content is vetted as a
		// shell write.
		{"R13-SF3 usr bin printf dyn format", `/usr/bin/printf "label=$LABEL %s" value`},
		{"R13-SF3 usr bin printf static format", `/usr/bin/printf 'label=%s' value`},
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
