package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTestTrustedHome binds testTrustedHomeRoot and HOME to a directory
// inside t.TempDir() so C10 PATH trust and planted-binary tests are 100%
// isolated in t.TempDir() without writing to /, .., ~, or the repo root.
func withTestTrustedHome(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	fakeHome := filepath.Join(root, "home", "tester")
	if err := os.MkdirAll(fakeHome, 0755); err != nil {
		t.Fatalf("mkdir fakeHome: %v", err)
	}
	prev := testTrustedHomeRoot
	testTrustedHomeRoot = fakeHome
	t.Setenv("HOME", fakeHome)
	t.Cleanup(func() {
		testTrustedHomeRoot = prev
	})
	return fakeHome
}

func writeTestExecutable(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir parent for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), mode); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
	// Explicit Chmod so the proses's umask does not mask 0777/0775 in tests.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
}

// TestGuard_R12_PathTrustUserWritable covers item 2.a
// ([pattern:path-trust-user-writable], C10):
//   - unanchored non-home .local/bin / .cargo/bin / foreign home / bad linuxbrew
//     prefixes are rejected;
//   - world-writable (0777) and group-writable (0775) toolchain dirs and
//     symlinks pointing into /tmp are rejected;
//   - planted same-name system binaries (ls, git, sh) and symlinks to
//     unlisted binaries in ~/.local/bin are rejected;
//   - normal toolchain PATH prepends (mise shims, ~/.local/bin, ~/.cargo/bin,
//     /home/linuxbrew/.linuxbrew/bin) and transparent mise shims pass with
//     zero false blocks.
func TestGuard_R12_PathTrustUserWritable(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	localBin := filepath.Join(fakeHome, ".local", "bin")
	miseShims := filepath.Join(fakeHome, ".local", "share", "mise", "shims")
	cargoBin := filepath.Join(fakeHome, ".cargo", "bin")
	for _, d := range []string{localBin, miseShims, cargoBin} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	// 1. Must-allow: normal export PATH prepends with clean 0755 dirs.
	allowShell := []string{
		// NOTE: `export PATH="$HOME/..."` is a pre-existing AST limitation
		// (export CallExpr leaves $HOME as __ctx_dq_sub__); use PATH= assignment.
		`PATH="$HOME/.local/share/mise/shims:$HOME/.local/bin:$HOME/.cargo/bin:$PATH" git status`,
		`PATH="$HOME/.local/share/mise/shims:$PATH" ls -la`,
		`PATH="/home/linuxbrew/.linuxbrew/bin:$PATH" git status`,
	}
	for _, cmd := range allowShell {
		if got := guardShellSubagent(cmd); got != "" {
			t.Fatalf("expected clean toolchain PATH to pass for %q, got %q", cmd, got)
		}
	}

	// 2. Must-red: unanchored / foreign-home / non-.linuxbrew PATH entries.
	redPaths := []string{
		`PATH="/var/spool/.local/bin:$PATH" git status`,
		`PATH="/srv/scratch/.cargo/bin:$PATH" ls`,
		`PATH="/home/otheruser/.local/bin:$PATH" git status`,
		`PATH="/home/linuxbrew/evil/bin:$PATH" ls`,
	}
	for _, cmd := range redPaths {
		if got := guardShellSubagent(cmd); got != "env PATH" {
			t.Fatalf("expected env PATH block for %q, got %q", cmd, got)
		}
	}

	// 3. Must-red: world-writable (0777) and group-writable (0775) ~/.local/bin.
	for _, perm := range []os.FileMode{0777, 0775} {
		if err := os.Chmod(localBin, perm); err != nil {
			t.Fatalf("chmod localBin %o: %v", perm, err)
		}
		if got := guardShellSubagent(`PATH="$HOME/.local/bin:$PATH" git status`); got != "env PATH" {
			t.Fatalf("perm %o on ~/.local/bin must block env PATH, got %q", perm, got)
		}
	}
	if err := os.Chmod(localBin, 0755); err != nil {
		t.Fatalf("restore localBin 0755: %v", err)
	}

	// 4. Must-red: ~/.local/bin symlinked to an untrusted /tmp directory.
	scratchTmp := t.TempDir()
	symlinkBin := filepath.Join(fakeHome, ".bun", "bin")
	if err := os.MkdirAll(filepath.Dir(symlinkBin), 0755); err != nil {
		t.Fatalf("mkdir .bun: %v", err)
	}
	if err := os.Symlink(scratchTmp, symlinkBin); err != nil {
		t.Fatalf("symlink .bun/bin -> scratchTmp: %v", err)
	}
	if got := guardShellSubagent(`PATH="$HOME/.bun/bin:$PATH" git status`); got != "env PATH" {
		t.Fatalf("symlinked ~/.bun/bin -> /tmp must block env PATH, got %q", got)
	}

	// 5. Transparent mise shims: node -> mise and rg -> mise.
	fakeMise := filepath.Join(localBin, "mise")
	writeTestExecutable(t, fakeMise, 0755)
	nodeShim := filepath.Join(miseShims, "node")
	rgShim := filepath.Join(miseShims, "rg")
	if err := os.Symlink(fakeMise, nodeShim); err != nil {
		t.Fatalf("symlink node -> mise: %v", err)
	}
	if err := os.Symlink(fakeMise, rgShim); err != nil {
		t.Fatalf("symlink rg -> mise: %v", err)
	}
	t.Setenv("PATH", miseShims+":"+localBin+":"+os.Getenv("PATH"))

	// Must-allow: benign `node -e` and readonly `rg` through mise shims.
	if got := guardShellSubagent(`node -e "console.log(1)"`); got != "" {
		t.Fatalf("mise shim node -e benign must pass, got %q", got)
	}
	// Must-red: malicious `node -e` spawning pig through mise shim (must NOT
	// lose node -e unwrapping just because node resolves to mise).
	if got := guardShellSubagent(`node -e "require('child_process').execSync('pig')"`); got == "" {
		t.Fatalf("mise shim node -e spawning pig must block, got empty")
	}

	// Readonly caller running rg through mise shim: must pass.
	t.Setenv(auditEnvRole, "reviewer")
	if got := guardShellReadonly(`rg foo README.md`); got != "" {
		t.Fatalf("mise shim rg under reviewer must pass, got %q", got)
	}

	// 6. Must-red: planted same-name system binary (ls, git) in ~/.local/bin.
	plantedLs := filepath.Join(localBin, "ls")
	writeTestExecutable(t, plantedLs, 0755)
	if got := guardShellReadonly(`ls -la`); !strings.Contains(got, "planted shadow binary") {
		t.Fatalf("planted ~/.local/bin/ls under reviewer must block, got %q", got)
	}
	t.Setenv(auditEnvRole, "worker")
	if got := guardShellSubagent(`ls -la`); !strings.Contains(got, "planted shadow binary") {
		t.Fatalf("planted ~/.local/bin/ls under worker must block, got %q", got)
	}
	_ = os.Remove(plantedLs)

	plantedGit := filepath.Join(localBin, "git")
	writeTestExecutable(t, plantedGit, 0755)
	if got := guardShellSubagent(`git status`); !strings.Contains(got, "planted shadow binary") {
		t.Fatalf("planted ~/.local/bin/git under worker must block, got %q", got)
	}
	_ = os.Remove(plantedGit)

	// 7. Must-red: symlink in ~/.local/bin from blocked `pig` to `/bin/sh`
	// must NOT bypass screenNestedDispatch via unwrapShellArgv early return.
	pigLink := filepath.Join(localBin, "pig")
	if err := os.Symlink("/bin/sh", pigLink); err == nil {
		if got := guardShellSubagent(`pig -c "echo ok"`); got != "pig" {
			t.Fatalf("symlink pig -> /bin/sh must still block as pig, got %q", got)
		}
		_ = os.Remove(pigLink)
	}

	// 8. Must-red: symlink in ~/.local/bin from allowlisted `tree` to an
	// unlisted binary `custom_writer` must fail readonly allowlist.
	customWriter := filepath.Join(localBin, "custom_writer")
	writeTestExecutable(t, customWriter, 0755)
	treeLink := filepath.Join(localBin, "tree")
	if err := os.Symlink(customWriter, treeLink); err != nil {
		t.Fatalf("symlink tree -> custom_writer: %v", err)
	}
	t.Setenv(auditEnvRole, "reviewer")
	if got := guardShellReadonly(`tree`); !strings.Contains(got, "not in readonly allowlist") {
		t.Fatalf("symlink tree -> custom_writer must block in readonly, got %q", got)
	}
	_ = os.Remove(treeLink)
	_ = os.Remove(customWriter)
}

// TestGuard_R12_CodeStaticSpawnSSHPeel covers item 2.b
// ([pattern:code-static-spawn-single-layer]):
//   - static array/tuple/execFile/execvp/execlp spawns of ssh in Python & JS
//     peel ssh options and screen remote commands with caller guard inheritance;
//   - legitimate remote readonly/worker commands (`['ssh','dmit','git','status']`)
//     pass without triggering the dynamic `codeAgentNames` ssh fallback;
//   - verifier blocks remote writes via code spawns with ruleReadonlyWrite.
func TestGuard_R12_CodeStaticSpawnSSHPeel(t *testing.T) {
	sub := guardCall{subagent: true}
	verifier := guardCall{subagent: true, readonly: true}
	reviewer := guardCall{subagent: true, readonly: true, strictReadonly: true}

	cases := []struct {
		name       string
		caller     guardCall
		lang       string
		code       string
		wantRule   string
		wantDetail string
	}{
		// Must-red: remote nested agent dispatch via static array / tuple / alias / JS.
		{
			name:       "py subprocess.run ssh pig",
			caller:     sub,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(['ssh', 'dmit', 'pig'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "pig",
		},
		{
			name:       "reviewer subprocess.run ssh pig reports subagent rule first",
			caller:     reviewer,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(['ssh', 'dmit', 'pig'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "pig",
		},
		{
			name:       "py subprocess.run ssh post-dest -q pig",
			caller:     sub,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(['ssh', 'dmit', '-q', 'pig'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "pig",
		},
		{
			name:       "py subprocess.run ssh proxycommand blocked",
			caller:     sub,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(['ssh', '-o', 'ProxyCommand=/tmp/x', 'dmit', 'uptime'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "ssh -o proxycommand",
		},
		{
			name:       "py subprocess.run ssh bare host blocked",
			caller:     sub,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(['ssh', 'dmit'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "ssh",
		},
		{
			name:       "py subprocess.run ssh remote herdr write",
			caller:     sub,
			lang:       "python",
			code:       "import subprocess as sp\nsp.run(['ssh', 'dmit', 'cd /root && herdr tab create'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "herdr",
		},
		{
			name:       "py wrapped env timeout ssh agy",
			caller:     sub,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(['env', 'timeout', '5', 'ssh', 'dmit', 'agy'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "agy",
		},
		{
			name:       "py os.execvp ssh pig (argv0 deduped)",
			caller:     sub,
			lang:       "python",
			code:       "import os\nos.execvp('ssh', ['ssh', 'dmit', 'pig'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "pig",
		},
		{
			name:       "py os.execlp ssh pig (variadic literals)",
			caller:     sub,
			lang:       "python",
			code:       "import os\nos.execlp('ssh', 'ssh', 'dmit', 'pig')",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "pig",
		},
		{
			name:       "py subprocess.run shell=True list ssh pig",
			caller:     sub,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(['ssh dmit pig'], shell=True)",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "pig",
		},
		{
			name:       "py subprocess.run args= keyword ssh pig",
			caller:     sub,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(args=['ssh', 'dmit', 'pig'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "pig",
		},
		{
			name:       "js execFileSync ssh pig",
			caller:     sub,
			lang:       "javascript",
			code:       "const cp = require('child_process'); cp.execFileSync('ssh', ['dmit', 'pig'])",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "pig",
		},
		{
			name:       "verifier subprocess.run ssh remote rm blocked as readonly write",
			caller:     verifier,
			lang:       "python",
			code:       "import subprocess\nsubprocess.run(['ssh', 'dmit', 'rm', '-rf', '/tmp/x'])",
			wantRule:   ruleReadonlyWrite,
			wantDetail: roSSHWriteHit,
		},

		// Must-allow: legitimate remote read-only & worker operations.
		{
			name:     "worker subprocess.run ssh git status ok",
			caller:   sub,
			lang:     "python",
			code:     "import subprocess\nsubprocess.run(['ssh', 'dmit', 'git', 'status'])",
			wantRule: "",
		},
		{
			name:     "verifier subprocess.run ssh git status ok",
			caller:   verifier,
			lang:     "python",
			code:     "import subprocess\nsubprocess.run(['ssh', '-o', 'BatchMode=yes', '-p', '2222', 'dmit', 'git', 'status'])",
			wantRule: "",
		},
		{
			name:     "worker subprocess.run ssh remote rm ok",
			caller:   sub,
			lang:     "python",
			code:     "import subprocess\nsubprocess.run(['ssh', 'dmit', 'rm', '-f', '/tmp/x'])",
			wantRule: "",
		},
		{
			name:     "worker os.execvp ssh git status ok",
			caller:   sub,
			lang:     "python",
			code:     "import os\nos.execvp('ssh', ['ssh', 'dmit', 'git', 'status'])",
			wantRule: "",
		},
		{
			name:     "worker os.execlp ssh git status ok",
			caller:   sub,
			lang:     "python",
			code:     "import os\nos.execlp('ssh', 'ssh', 'dmit', 'git', 'status')",
			wantRule: "",
		},
		{
			name:     "worker js execFileSync ssh git status ok",
			caller:   sub,
			lang:     "javascript",
			code:     "const {execFileSync} = require('child_process'); execFileSync('ssh', ['dmit', 'git', 'status'])",
			wantRule: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, detail := tc.caller.guardCtxRunCode(tc.lang, tc.code)
			if rule != tc.wantRule {
				t.Fatalf("guardCtxRunCode(%q) rule = %q (detail=%q), want rule %q",
					tc.code, rule, detail, tc.wantRule)
			}
			if tc.wantDetail != "" && detail != tc.wantDetail {
				t.Fatalf("guardCtxRunCode(%q) detail = %q, want %q",
					tc.code, detail, tc.wantDetail)
			}
		})
	}
}

// TestGuard_R12_IndirectWrapperSegStdin covers item 2.c
// ([pattern:indirect-wrapper-seg-stdin]):
//   - xargs / find -exec / find -ok / flock / watch -x indirect ssh and
//     interpreter derivations preserve accurate stdin / argument-injection
//     semantics;
//   - verifier remote write piggybacks (`ssh dmit "rm -rf /tmp/x; sh"`) and
//     bare `find . -exec ssh dmit sh \;` block with readonly_write_blocked.
func TestGuard_R12_IndirectWrapperSegStdin(t *testing.T) {
	// 1. Worker cases.
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")
	workerG := currentGuardCall()

	workerCases := []struct {
		name       string
		code       string
		wantRule   string
		wantDetail string
	}{
		// Must-red under worker.
		{
			name:       "pipe into xargs ssh dmit sh",
			code:       "echo code | xargs ssh dmit sh",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "piped stdin to ssh",
		},
		{
			name:       "pipe into xargs ssh dmit sh -c",
			code:       "echo pig | xargs ssh dmit sh -c",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "piped code to shell", // screenOneSegmentDepth fires before xargs peel
		},
		{
			name:       "pipe into xargs -I{} ssh dmit {}",
			code:       "echo pig | xargs -I{} ssh dmit {}",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "piped code to shell", // screenOneSegmentDepth fires before xargs peel
		},
		{
			name:       "pipe into xargs -I{} ssh dmit sh -c {}",
			code:       "echo pig | xargs -I{} ssh dmit sh -c {}",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "piped code to shell", // screenOneSegmentDepth fires before xargs peel
		},
		{
			name:       "xargs -a file forwards file-redirected stdin to ssh sh",
			code:       "xargs -a /tmp/items ssh dmit sh < /tmp/script.sh",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "file stdin to ssh stdin-program",
		},
		{
			name:       "xargs -a file into open sh -c",
			code:       "xargs -a /tmp/items sh -c",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "dynamic code payload",
		},
		{
			name:       "flock preserves stdinRedir on ssh sh",
			code:       "flock /tmp/lk ssh dmit sh < /tmp/script.sh",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "file stdin to ssh stdin-program",
		},
		{
			name:       "watch -x preserves stdinRedir on ssh sh",
			code:       "watch -x ssh dmit sh < /tmp/script.sh",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "file stdin to ssh stdin-program",
		},
		{
			name:       "pipe into find -ok ssh dmit sh",
			code:       "echo pig | find . -ok ssh dmit sh \\;",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "find -ok piped stdin to ssh",
		},
		{
			name:       "find -exec sh -c {} placeholder in code slot",
			code:       "find . -exec sh -c {} \\;",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "find -exec dynamic code payload",
		},
		{
			name:       "find -exec ssh dmit {} placeholder in remote head",
			code:       "find . -exec ssh dmit {} \\;",
			wantRule:   ruleSubagentNestedAgent,
			wantDetail: "find -exec dynamic code payload",
		},

		// Must-allow under worker.
		{
			name:     "find -exec ssh dmit git status",
			code:     "find . -exec ssh dmit git status \\;",
			wantRule: "",
		},
		{
			name:     "find -exec grep foo {} +",
			code:     "find . -exec grep foo {} +",
			wantRule: "",
		},
		{
			name:     "find -exec sh -c with {} as positional arg $1",
			code:     `find . -exec sh -c 'echo "$1"' _ {} +`,
			wantRule: "",
		},
		{
			name:     "xargs -I{} git -C {} status",
			code:     "echo /tmp/repo | xargs -I{} git -C {} status",
			wantRule: "",
		},
		{
			name:     "flock ssh dmit sh with benign heredoc",
			code:     "flock /tmp/lk ssh dmit sh <<'EOF'\nls -la /tmp\nEOF",
			wantRule: "",
		},
	}

	for _, tc := range workerCases {
		t.Run("worker/"+tc.name, func(t *testing.T) {
			rule, detail := workerG.guardCtxRunShell(tc.code)
			if rule != tc.wantRule {
				t.Fatalf("guardCtxRunShell(%q) = (%q, %q), want rule %q",
					tc.code, rule, detail, tc.wantRule)
			}
			if tc.wantDetail != "" && detail != tc.wantDetail {
				t.Fatalf("guardCtxRunShell(%q) detail = %q, want %q",
					tc.code, detail, tc.wantDetail)
			}
		})
	}

	// 2. Verifier cases: remote writes (direct, piggybacked on `; sh`, via
	// find -exec, via xargs, via flock heredoc, or via python3 -c) must all
	// block with ruleReadonlyWrite.
	t.Setenv(auditEnvRole, "verifier")
	t.Setenv(auditEnvReadonly, "")
	verifierG := currentGuardCall()

	verifierBlock := []string{
		`echo code | xargs ssh dmit sh`,
		`find . -exec ssh dmit sh \;`,
		`find . -exec ssh dmit "rm -rf /tmp/x; sh" \;`,
		`ssh dmit "rm -rf /tmp/x; sh"`,
		"flock /tmp/lk ssh dmit sh <<'EOF'\nrm -rf /tmp/x\nEOF",
		`python3 -c "import subprocess; subprocess.run(['ssh', 'dmit', 'rm', '-rf', '/tmp/x'])"`,
	}
	for _, code := range verifierBlock {
		rule, detail := verifierG.guardCtxRunShell(code)
		if rule != ruleReadonlyWrite {
			t.Fatalf("verifier: %q got (%q, %q), want rule %s",
				code, rule, detail, ruleReadonlyWrite)
		}
	}

	verifierAllow := []string{
		`find . -exec ssh dmit "git status" \;`,
		"flock /tmp/lk ssh dmit sh <<'EOF'\nls -la /tmp\nEOF",
		`python3 -c "import subprocess; subprocess.run(['ssh', 'dmit', 'git', 'status'])"`,
	}
	for _, code := range verifierAllow {
		if rule, detail := verifierG.guardCtxRunShell(code); rule != "" {
			t.Fatalf("verifier: expected %q to pass, got (%q, %q)", code, rule, detail)
		}
	}
}

// TestGuard_R12_RootHomeRejectsForeignHomePath covers the production residual
// where HOME=/root must NOT append a /home/* trust wildcard. Cross-user home
// PATH segments (/home/otheruser/.local/bin) must be rejected. This test does
// NOT use withTestTrustedHome — that helper binds testTrustedHomeRoot and would
// bypass the production HOME=/root path under test.
func TestGuard_R12_RootHomeRejectsForeignHomePath(t *testing.T) {
	prev := testTrustedHomeRoot
	testTrustedHomeRoot = ""
	t.Cleanup(func() { testTrustedHomeRoot = prev })
	t.Setenv("HOME", "/root")
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	foreign := "/home/otheruser/.local/bin"
	if isSafePathDirEntry(foreign) {
		t.Fatalf("HOME=/root must reject isSafePathDirEntry(%q), got true", foreign)
	}

	cmd := `PATH="/home/otheruser/.local/bin:$PATH" git status`
	if got := guardShellSubagent(cmd); got != "env PATH" {
		t.Fatalf("HOME=/root: expected env PATH block for %q, got %q", cmd, got)
	}

	// Own home under /root remains a valid trust prefix for lexical matching
	// of known toolchain suffixes (disk checks still apply when the dir exists).
	own := "/root/.local/bin"
	if !isUserToolchainPathDir(own) {
		t.Fatalf("HOME=/root must still treat %q as a user toolchain path lexically", own)
	}
}
