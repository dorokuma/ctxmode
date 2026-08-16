package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for the git hooks (githooks/pre-push, githooks/commit-msg)
// and the installer (scripts/install-hooks.sh). Each test builds a throwaway
// git repo under t.TempDir() and runs the real hook scripts through bash.
// Only fake test strings are used — never real credentials.

const (
	realPrePush      = "githooks/pre-push"
	realCommitMsg    = "githooks/commit-msg"
	realInstallHooks = "scripts/install-hooks.sh"
)

var zeroSHA = strings.Repeat("0", 40)

// fakeToken is ghp_ + 36 alphanumerics, matching the ghp_ secret pattern.
// Built at runtime so the complete literal never appears in the source or in
// the staged diff scanned by githooks/commit-msg; the runtime value still
// matches the hook's ghp_ pattern exactly.
var fakeToken = "ghp_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"[:26] + "ABCDEFGHIJ"

// fakeSkKey is sk- + 40 alphanumerics, matching the sk- secret pattern.
// Built at runtime so the complete literal never appears in the source or in
// the staged diff scanned by githooks/commit-msg; the runtime value still
// matches the hook's sk- pattern exactly.
var fakeSkKey = "sk-" + "abcdefghijklmnopqrstuvwxyz1234567890ABCD"[:26] + "1234567890ABCD"

// fakePemHeader builds a PEM private-key header line. Assembled at runtime so
// the complete literal never appears in the source or staged diff.
func fakePemHeader(kind string) string {
	return "-----BEGIN " + kind + " " + "PRIVATE KEY-----"
}

func hookEnv() []string {
	return append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", // isolate from any dev-machine git config
		"GIT_CONFIG_NOSYSTEM=1",
	)
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = hookEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func initTestRepo(t *testing.T, dir string) {
	t.Helper()
	runGit(t, dir, "init", "-b", "main", ".")
	runGit(t, dir, "config", "user.email", "hook-test@example.com")
	runGit(t, dir, "config", "user.name", "Hook Test")
}

func gitRevParse(t *testing.T, dir, ref string) string {
	t.Helper()
	return runGit(t, dir, "rev-parse", ref)
}

func commitFile(t *testing.T, dir, name, content, msg string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", name)
	runGit(t, dir, "commit", "-q", "-m", msg)
	return gitRevParse(t, dir, "HEAD")
}

func stageFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", name)
}

func writeMsgFile(t *testing.T, msg string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "msg-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(msg + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// runHook executes `bash <script> [args...]` with cwd=dir, feeds stdin,
// and returns combined output plus the process exit code.
func runHook(t *testing.T, dir, script, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = dir
	cmd.Env = hookEnv()
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run %s: %v", script, err)
		}
	}
	return string(out), code
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

// ============================================================================
// githooks/pre-push
// ============================================================================

func TestPrePushHook(t *testing.T) {
	script, err := filepath.Abs(realPrePush)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("clean commits pass on new branch", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "a.txt", "hello\n", "feat: add a")
		head = commitFile(t, repo, "b.txt", "world\n", "feat: add b")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code != 0 {
			t.Fatalf("expected pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("new branch scans all commits and rejects fake token", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: add a")
		head := commitFile(t, repo, "secret.txt",
			"token = "+fakeToken+"\n", "feat: add config")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected rejection for fake token, got pass:\n%s", out)
		}
	})

	t.Run("new ref on fully remote-owned history passes", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: add a")
		head := commitFile(t, repo, "b.txt", "world\n", "修复加载器")
		// Simulate the remote already owning all of head's history.
		runGit(t, repo, "update-ref", "refs/remotes/origin/main", head)
		// New tag (zero remote sha) pointing at fully owned history: the
		// pre-existing non-ASCII message must not be rescanned.
		out, code := runHook(t, repo, script,
			"refs/tags/v1.0.0 "+head+" refs/tags/v1.0.0 "+zeroSHA+"\n")
		if code != 0 {
			t.Fatalf("expected pass (remote already owns history), got exit %d:\n%s", code, out)
		}
	})

	t.Run("new ref with commit unseen by remote is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		base := commitFile(t, repo, "a.txt", "hello\n", "feat: add a")
		runGit(t, repo, "update-ref", "refs/remotes/origin/main", base)
		head := commitFile(t, repo, "secret.txt",
			"token = "+fakeToken+"\n", "feat: add config")
		// New branch (zero remote sha) with a commit the remote lacks:
		// the outgoing secret must still be caught.
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected rejection for unseen secret commit, got pass:\n%s", out)
		}
	})

	t.Run("existing remote only scans outgoing commits", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		a := commitFile(t, repo, "a.txt", "hello\n", "feat: add a")
		b := commitFile(t, repo, "secret.txt",
			"token = "+fakeToken+"\n", "feat: add config")
		c := commitFile(t, repo, "c.txt", "clean\n", "feat: add c")
		// Push c with remote at b: b's secret is not outgoing → must pass.
		out, code := runHook(t, repo, script,
			"refs/heads/main "+c+" refs/heads/main "+b+"\n")
		if code != 0 {
			t.Fatalf("expected pass (outgoing only), got exit %d:\n%s", code, out)
		}
		// Push b with remote at a: b is outgoing → must reject.
		out, code = runHook(t, repo, script,
			"refs/heads/main "+b+" refs/heads/main "+a+"\n")
		if code == 0 {
			t.Fatalf("expected rejection for outgoing secret, got pass:\n%s", out)
		}
	})

	t.Run("deletion is skipped", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		a := commitFile(t, repo, "secret.txt",
			"token = "+fakeToken+"\n", "feat: add config")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+zeroSHA+" refs/heads/main "+a+"\n")
		if code != 0 {
			t.Fatalf("expected deletion to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("malformed input is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "a.txt", "hello\n", "feat: add a")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+"\n") // missing remote ref + remote sha
		if code == 0 {
			t.Fatalf("expected malformed input to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("private key header is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "key.pem",
			fakePemHeader("RSA")+"\nMIIEowIBAAKCAQEA\n", "feat: add key")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected private key header to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("non-ASCII message is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "a.txt", "hello\n", "修复加载器")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected non-ASCII message to be rejected, got pass:\n%s", out)
		}
	})
}

// ============================================================================
// githooks/commit-msg
// ============================================================================

func TestCommitMsgHook(t *testing.T) {
	script, err := filepath.Abs(realCommitMsg)
	if err != nil {
		t.Fatal(err)
	}

	// setup returns a repo with a seeded commit and a staged clean change,
	// so the staged-diff secret scan also runs.
	setup := func(t *testing.T) string {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "b.txt", "package main\n")
		return repo
	}

	run := func(t *testing.T, repo, msg string) (string, int) {
		t.Helper()
		return runHook(t, repo, script, "", writeMsgFile(t, msg))
	}

	t.Run("normal bugfix message passes", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "bugfix: correct upload retry after timeout")
		if code != 0 {
			t.Fatalf("expected bugfix message to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("fixed-the-bug message passes", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "fixed the bug in the loader")
		if code != 0 {
			t.Fatalf("expected 'fixed the bug' message to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("clean message passes", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "feat: add widget loader")
		if code != 0 {
			t.Fatalf("expected clean message to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("audit noise is still rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "fix audit findings in executor")
		if code == 0 {
			t.Fatalf("expected audit noise to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("fake token in message is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "rotate "+fakeToken+" now")
		if code == 0 {
			t.Fatalf("expected fake token to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("private key header in message is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "backup "+fakePemHeader("OPENSSH")+" material")
		if code == 0 {
			t.Fatalf("expected private key header to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("fake key in staged diff is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "config.txt", "api_key"+" = "+fakeSkKey+"\n")
		out, code := run(t, repo, "feat: add config sample")
		if code == 0 {
			t.Fatalf("expected staged-diff fake key to be rejected, got pass:\n%s", out)
		}
	})
}

// ============================================================================
// scripts/install-hooks.sh
// ============================================================================

func TestInstallHooks(t *testing.T) {
	prePushData, err := os.ReadFile(realPrePush)
	if err != nil {
		t.Fatal(err)
	}
	commitMsgData, err := os.ReadFile(realCommitMsg)
	if err != nil {
		t.Fatal(err)
	}

	// setup replicates the repo layout: <root>/githooks/*, <root>/scripts/,
	// with <root> itself a git work tree.
	setup := func(t *testing.T) string {
		root := t.TempDir()
		copyFile(t, realPrePush, filepath.Join(root, "githooks", "pre-push"))
		copyFile(t, realCommitMsg, filepath.Join(root, "githooks", "commit-msg"))
		copyFile(t, realInstallHooks, filepath.Join(root, "scripts", "install-hooks.sh"))
		runGit(t, root, "init", "-b", "main", ".")
		return root
	}

	// Run the copied installer inside the throwaway repo layout so that the
	// real repo (and its configured core.hooksPath) is never touched.
	run := func(t *testing.T, root string) (string, int) {
		t.Helper()
		return runHook(t, root, filepath.Join(root, "scripts", "install-hooks.sh"), "")
	}

	assertInstalled := func(t *testing.T, hooksDir string) {
		t.Helper()
		pre := filepath.Join(hooksDir, "pre-push")
		data, err := os.ReadFile(pre)
		if err != nil {
			t.Fatalf("expected hook installed at %s: %v", pre, err)
		}
		if !bytes.Equal(data, prePushData) {
			t.Fatalf("hook at %s does not match githooks/pre-push", pre)
		}
		info, err := os.Stat(pre)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("hook at %s is not executable", pre)
		}
		cm := filepath.Join(hooksDir, "commit-msg")
		data, err = os.ReadFile(cm)
		if err != nil {
			t.Fatalf("expected hook installed at %s: %v", cm, err)
		}
		if !bytes.Equal(data, commitMsgData) {
			t.Fatalf("hook at %s does not match githooks/commit-msg", cm)
		}
	}

	assertNotInstalled := func(t *testing.T, hooksDir string) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(hooksDir, "pre-push")); !os.IsNotExist(err) {
			t.Fatalf("hook must not be installed into %s", hooksDir)
		}
	}

	t.Run("default installs into .git/hooks", func(t *testing.T) {
		root := setup(t)
		out, code := run(t, root)
		if code != 0 {
			t.Fatalf("expected install to pass, got exit %d:\n%s", code, out)
		}
		assertInstalled(t, filepath.Join(root, ".git", "hooks"))
	})

	t.Run("absolute core.hooksPath is used", func(t *testing.T) {
		root := setup(t)
		custom := filepath.Join(root, "custom-hooks")
		if err := os.MkdirAll(custom, 0o755); err != nil {
			t.Fatal(err)
		}
		runGit(t, root, "config", "core.hooksPath", custom)
		out, code := run(t, root)
		if code != 0 {
			t.Fatalf("expected install to pass, got exit %d:\n%s", code, out)
		}
		assertInstalled(t, custom)
		assertNotInstalled(t, filepath.Join(root, ".git", "hooks"))
	})

	t.Run("relative core.hooksPath resolves against repo root", func(t *testing.T) {
		root := setup(t)
		if err := os.MkdirAll(filepath.Join(root, "rel-hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		runGit(t, root, "config", "core.hooksPath", "rel-hooks")
		out, code := run(t, root)
		if code != 0 {
			t.Fatalf("expected install to pass, got exit %d:\n%s", code, out)
		}
		assertInstalled(t, filepath.Join(root, "rel-hooks"))
		assertNotInstalled(t, filepath.Join(root, ".git", "hooks"))
	})

	t.Run("invalid core.hooksPath fails fast", func(t *testing.T) {
		root := setup(t)
		missing := filepath.Join(root, "no-such-dir")
		runGit(t, root, "config", "core.hooksPath", missing)
		out, code := run(t, root)
		if code == 0 {
			t.Fatalf("expected failure for missing hooks dir, got pass:\n%s", out)
		}
		assertNotInstalled(t, filepath.Join(root, ".git", "hooks"))
	})

	t.Run("not a git work tree fails fast", func(t *testing.T) {
		root := t.TempDir()
		copyFile(t, realPrePush, filepath.Join(root, "githooks", "pre-push"))
		copyFile(t, realCommitMsg, filepath.Join(root, "githooks", "commit-msg"))
		copyFile(t, realInstallHooks, filepath.Join(root, "scripts", "install-hooks.sh"))
		out, code := run(t, root)
		if code == 0 {
			t.Fatalf("expected failure outside a git work tree, got pass:\n%s", out)
		}
	})
}
