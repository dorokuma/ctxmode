package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	// the nested-agent scan even when resolution finds nothing.
	t.Setenv("PATH", os.Getenv("PATH"))
	t.Run("v622-2c direct bun -p", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "v622-2c", role: "worker", cmd: `bun -p 'require("child_process").execSync("pig")'`}, "")
		if got == "ALLOW" {
			t.Fatalf("direct bun -p = ALLOW, want javascript inline code block")
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
