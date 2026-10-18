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

// fakeGitHubPat is a fine-grained PAT (github_pat_ + body), assembled at
// runtime so the complete literal never appears in the source or staged diff.
var fakeGitHubPat = "github_pat_" + "ABCDEFGHIJabcdefghijAB" + "_" +
	"ABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHIJABCDEFGHI"

// fakeSkProjKey / fakeSkAntKey are hyphenated example keys (skProjPlaceholder,
// skAntPlaceholder). Assembled at runtime for the same reason as fakeSkKey.
var fakeSkProjKey = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz1234567890ABCD"
var fakeSkAntKey = "sk-" + "ant-api03-" + "abcdefghijklmnopqrstuvwxyz1234567890ABCD"

// fakePemHeader builds a PEM private-key header line. Assembled at runtime so
// the complete literal never appears in the source or staged diff.
func fakePemHeader(kind string) string {
	return "-----BEGIN " + kind + " " + "PRIVATE KEY-----"
}

// hookUsesGrepP reports a real grep -P invocation. Comment lines that mention
// the flag (for example explaining why it is banned) do not count.
func hookUsesGrepP(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		trim := bytes.TrimSpace(line)
		if len(trim) == 0 || trim[0] == '#' {
			continue
		}
		if bytes.Contains(trim, []byte("grep -P")) {
			return true
		}
	}
	return false
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
		commitFile(t, repo, "a.txt", "hello\n", "feat: add a")
		head := commitFile(t, repo, "b.txt", "world\n", "feat: add b")
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

	t.Run("outgoing commit with invalid message format is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "a.txt", "hello\n", "fixed the loader")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected rejection for invalid message format, got pass:\n%s", out)
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

	t.Run("github_pat in file is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "secret.txt",
			"token = "+fakeGitHubPat+"\n", "feat: add config")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected github_pat rejection, got pass:\n%s", out)
		}
	})

	t.Run("hyphenated skProj key in file is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "secret.txt",
			"key = "+fakeSkProjKey+"\n", "feat: add config")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected skProj rejection, got pass:\n%s", out)
		}
	})

	t.Run("hyphenated sk-ant key in file is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "secret.txt",
			"key = "+fakeSkAntKey+"\n", "feat: add config")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected sk-ant rejection, got pass:\n%s", out)
		}
	})

	t.Run("hardcoded password assignment in commit is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "config.py", "pass"+"word = \"hunter2\"\n", "feat: add config")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected password assignment rejection, got pass:\n%s", out)
		}
	})

	t.Run("hardcoded api_key and secret assignment in commit is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "config.go", "api_"+"key := \"mysecretkey123\"\n", "feat: add api key")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 {
			t.Fatalf("expected api_key assignment rejection, got pass:\n%s", out)
		}
	})

	t.Run("explanatory password assignments in commit pass", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		content := "pass" + "word: none\npass" + "word: optional\npass" + "word: removed\npass" + "word: unchanged\npass" + "word: empty\nvar pass" + "word = \"\"\napi_" + "key: optional\nsec" + "ret: removed\n"
		head := commitFile(t, repo, "config.yaml", content, "feat: update config docs")
		out, code := runHook(t, repo, script,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code != 0 {
			t.Fatalf("expected explanatory password assignments to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("script scans new token shapes and does not use grep -P", func(t *testing.T) {
		data, err := os.ReadFile(script)
		if err != nil {
			t.Fatal(err)
		}
		if hookUsesGrepP(data) {
			t.Fatal("pre-push must not use grep -P; missing PCRE used to skip non-ASCII checks")
		}
		if !bytes.Contains(data, []byte("github_pat_")) {
			t.Fatal("pre-push must scan github_pat_ tokens")
		}
		if !bytes.Contains(data, []byte(`sk-[a-zA-Z0-9._-]{8,}`)) {
			t.Fatal("pre-push sk- pattern must allow hyphens, dots, underscores")
		}
	})

	// Message format, noise words and in-message secrets are enforced by the
	// sibling commit-msg hook. When that hook is not next to pre-push, the
	// check must fail closed instead of being skipped. The fallback path is
	// pointed at an empty directory so a machine-global commit-msg cannot
	// satisfy the check for this test; a sibling that exists but is not
	// executable is covered by the same failure (the hook must not fall
	// through to a global copy either).
	t.Run("missing sibling commit-msg fails the message check", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "a.txt", "hello\n", "fixed the loader")
		hooksDir := filepath.Join(repo, ".git", "hooks")
		if err := os.MkdirAll(hooksDir, 0o755); err != nil {
			t.Fatal(err)
		}
		local := filepath.Join(hooksDir, "pre-push")
		copyFile(t, script, local)
		t.Setenv("CTXMODE_COMMIT_MSG_FALLBACK", filepath.Join(t.TempDir(), "commit-msg"))
		out, code := runHook(t, repo, local,
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 || !strings.Contains(out, "commit-msg is missing or not executable") {
			t.Fatalf("expected an explicit missing-commit-msg failure, got exit %d:\n%s", code, out)
		}
	})

	// A sibling that exists but is not executable must fail the same way. It
	// must not be skipped, and it must not fall through to another commit-msg.
	t.Run("non-executable sibling commit-msg fails the message check", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		head := commitFile(t, repo, "a.txt", "hello\n", "fixed the loader")
		hooksDir := filepath.Join(repo, ".git", "hooks")
		if err := os.MkdirAll(hooksDir, 0o755); err != nil {
			t.Fatal(err)
		}
		copyFile(t, script, filepath.Join(hooksDir, "pre-push"))
		cm := filepath.Join(hooksDir, "commit-msg")
		copyFile(t, realCommitMsg, cm)
		if err := os.Chmod(cm, 0o644); err != nil {
			t.Fatal(err)
		}
		out, code := runHook(t, repo, filepath.Join(hooksDir, "pre-push"),
			"refs/heads/main "+head+" refs/heads/main "+zeroSHA+"\n")
		if code == 0 || !strings.Contains(out, "commit-msg is missing or not executable") {
			t.Fatalf("expected an explicit non-executable commit-msg failure, got exit %d:\n%s", code, out)
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

	t.Run("normal fix message passes", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "fix: correct upload retry after timeout")
		if code != 0 {
			t.Fatalf("expected fix message to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("invalid type bugfix is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "bugfix: correct upload retry after timeout")
		if code == 0 {
			t.Fatalf("expected invalid type bugfix to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("message without type prefix is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "fixed the bug in the loader")
		if code == 0 {
			t.Fatalf("expected message without type to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("conventional commit with scope passes", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "fix(loader): fix the bug in the loader")
		if code != 0 {
			t.Fatalf("expected scoped message to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("chinese subject in conventional commit passes", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "fix(db): 修复缓存 TTL")
		if code != 0 {
			t.Fatalf("expected chinese subject in conventional commit to pass, got exit %d:\n%s", code, out)
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

	t.Run("non-ASCII message is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "修复加载器")
		if code == 0 {
			t.Fatalf("expected non-ASCII message to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("github_pat in message is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "rotate "+fakeGitHubPat+" now")
		if code == 0 {
			t.Fatalf("expected github_pat rejection, got pass:\n%s", out)
		}
	})

	t.Run("hyphenated skProj key in message is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "rotate "+fakeSkProjKey+" now")
		if code == 0 {
			t.Fatalf("expected skProj rejection, got pass:\n%s", out)
		}
	})

	t.Run("hyphenated sk-ant key in staged diff is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "config.txt", "api_key"+" = "+fakeSkAntKey+"\n")
		out, code := run(t, repo, "feat: add config sample")
		if code == 0 {
			t.Fatalf("expected staged-diff sk-ant rejection, got pass:\n%s", out)
		}
	})

	t.Run("review round noise is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "fix: address code review round 2 comments")
		if code == 0 {
			t.Fatalf("expected review round noise to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("staged diff with variable assignment passes", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "auth.go", "package auth\n\nvar pass"+"word = \"\"\nvar api_"+"key = \"\"\nvar sec"+"ret = \"\"\n")
		out, code := run(t, repo, "feat: add auth placeholders")
		if code != 0 {
			t.Fatalf("expected low-confidence code assignment to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("hardcoded password assignment in staged diff is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "config.py", "pass"+"word = \"hunter2\"\n")
		out, code := run(t, repo, "feat: add config")
		if code == 0 {
			t.Fatalf("expected pass"+"word=hunter2 in staged diff to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("hardcoded api_key and secret in staged diff are rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "config.go", "api_"+"key := \"supersecretkey123\"\n")
		out, code := run(t, repo, "feat: add api key")
		if code == 0 {
			t.Fatalf("expected api_key in staged diff to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("hardcoded password assignment in commit message is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "feat: set pass"+"word=hunter2 for testing")
		if code == 0 {
			t.Fatalf("expected pass"+"word=hunter2 in commit msg to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("hardcoded secret assignment in commit message is rejected", func(t *testing.T) {
		repo := setup(t)
		out, code := run(t, repo, "feat: set SEC"+"RET=mysecrettoken123 for testing")
		if code == 0 {
			t.Fatalf("expected SECRET in commit msg to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("explanatory password assignments in commit message and staged diff pass", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "config.yaml", "pass"+"word: none\npass"+"word: optional\npass"+"word: removed\npass"+"word: unchanged\npass"+"word: empty\napi_"+"key: none\nsec"+"ret: optional\n")
		out, code := run(t, repo, "feat: mark pass"+"word: optional and pass"+"word: empty in docs")
		if code != 0 {
			t.Fatalf("expected explanatory password assignments to pass, got exit %d:\n%s", code, out)
		}
	})

	t.Run("script scans new token shapes and does not use grep -P", func(t *testing.T) {
		data, err := os.ReadFile(script)
		if err != nil {
			t.Fatal(err)
		}
		if hookUsesGrepP(data) {
			t.Fatal("commit-msg must not use grep -P; missing PCRE used to skip non-ASCII checks")
		}
		if !bytes.Contains(data, []byte("github_pat_")) {
			t.Fatal("commit-msg must scan github_pat_ tokens")
		}
		if !bytes.Contains(data, []byte(`sk-[a-zA-Z0-9._-]{32,}`)) {
			t.Fatal("commit-msg sk- pattern must allow hyphens, dots, underscores")
		}
	})

	t.Run("staged diff with plusplus added content containing secret is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "notes.txt", "++ "+fakeToken+"\n")
		out, code := run(t, repo, "feat: add notes")
		if code == 0 {
			t.Fatalf("expected added line starting with ++ containing secret to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("staged diff with arrow password assignment is rejected", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "config.rb", "pass"+"word => \"hunter2\"\n")
		out, code := run(t, repo, "feat: add ruby config")
		if code == 0 {
			t.Fatalf("expected arrow password assignment to be rejected, got pass:\n%s", out)
		}
	})

	t.Run("staged diff with env-var constant structural exemption passes", func(t *testing.T) {
		repo := t.TempDir()
		initTestRepo(t, repo)
		commitFile(t, repo, "a.txt", "hello\n", "feat: seed")
		stageFile(t, repo, "consts.go", "const API_"+"KEY_ENV = \"OPENAI_API_KEY\"\n")
		out, code := run(t, repo, "feat: add env var constants")
		if code != 0 {
			t.Fatalf("expected env-var name constant exemption to pass, got exit %d:\n%s", code, out)
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

	t.Run("external core.hooksPath is rejected", func(t *testing.T) {
		root := setup(t)
		custom := filepath.Join(root, "custom-hooks")
		if err := os.MkdirAll(custom, 0o755); err != nil {
			t.Fatal(err)
		}
		runGit(t, root, "config", "core.hooksPath", custom)
		out, code := run(t, root)
		if code == 0 {
			t.Fatalf("expected install to fail for external hooksPath, got pass:\n%s", out)
		}
		assertNotInstalled(t, custom)
		assertNotInstalled(t, filepath.Join(root, ".git", "hooks"))
	})

	t.Run("relative core.hooksPath outside .git/hooks is rejected", func(t *testing.T) {
		root := setup(t)
		if err := os.MkdirAll(filepath.Join(root, "rel-hooks"), 0o755); err != nil {
			t.Fatal(err)
		}
		runGit(t, root, "config", "core.hooksPath", "rel-hooks")
		out, code := run(t, root)
		if code == 0 {
			t.Fatalf("expected install to fail for relative external hooksPath, got pass:\n%s", out)
		}
		assertNotInstalled(t, filepath.Join(root, "rel-hooks"))
		assertNotInstalled(t, filepath.Join(root, ".git", "hooks"))
	})

	t.Run("symlink target in hooks dir is replaced without following it", func(t *testing.T) {
		root := setup(t)
		hooksDir := filepath.Join(root, ".git", "hooks")
		if err := os.MkdirAll(hooksDir, 0o755); err != nil {
			t.Fatal(err)
		}
		externalDir := t.TempDir()
		externalHook := filepath.Join(externalDir, "commit-msg")
		originalContent := []byte("#!/bin/sh\n# Original external hook\nexit 0\n")
		if err := os.WriteFile(externalHook, originalContent, 0o755); err != nil {
			t.Fatal(err)
		}
		symlinkTarget := filepath.Join(hooksDir, "commit-msg")
		if err := os.Symlink(externalHook, symlinkTarget); err != nil {
			t.Fatal(err)
		}

		out, code := run(t, root)
		if code != 0 {
			t.Fatalf("expected installer to replace the symlink target, got exit %d:\n%s", code, out)
		}
		data, err := os.ReadFile(externalHook)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, originalContent) {
			t.Fatalf("external hook was overwritten through the symlink: got %s", data)
		}
		if _, err := os.Readlink(symlinkTarget); err == nil {
			t.Fatalf("installed hook %s is still a symlink", symlinkTarget)
		}
		got, err := os.ReadFile(symlinkTarget)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, commitMsgData) {
			t.Fatalf("installed commit-msg does not match githooks/commit-msg")
		}
	})

	t.Run("symlinked hooks directory is rejected", func(t *testing.T) {
		root := setup(t)
		externalDir := t.TempDir()
		hooksDir := filepath.Join(root, ".git", "hooks")
		if err := os.RemoveAll(hooksDir); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(externalDir, hooksDir); err != nil {
			t.Fatal(err)
		}

		out, code := run(t, root)
		if code == 0 {
			t.Fatalf("expected installer to reject symlinked hooks directory, but it passed:\n%s", out)
		}
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

	// Trailing "/", "/." and "//" must not hide that .git/hooks itself is a
	// symlink to a directory outside the repository. The installer used to
	// canonicalize with pwd -P (which follows the link) and then test [ -L ]
	// on the decorated path, so those spellings compared equal and were not
	// reported as a symlink, and cp wrote the hooks outside the repo.
	for _, spelling := range []string{".git/hooks/", ".git/hooks/.", ".git/hooks//"} {
		spelling := spelling
		t.Run("symlinked .git/hooks via "+spelling+" is rejected", func(t *testing.T) {
			root := setup(t)
			externalDir := t.TempDir()
			marker := filepath.Join(externalDir, "marker")
			if err := os.WriteFile(marker, []byte("untouched\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			hooksDir := filepath.Join(root, ".git", "hooks")
			if err := os.RemoveAll(hooksDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(externalDir, hooksDir); err != nil {
				t.Fatal(err)
			}
			runGit(t, root, "config", "core.hooksPath", spelling)

			out, code := run(t, root)
			if code == 0 {
				t.Fatalf("expected installer to reject hooksPath %q when .git/hooks is a symlink, got pass:\n%s", spelling, out)
			}
			if _, err := os.Stat(filepath.Join(externalDir, "pre-push")); !os.IsNotExist(err) {
				t.Fatalf("installer wrote pre-push into the external directory via %q", spelling)
			}
			data, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "untouched\n" {
				t.Fatalf("external directory was modified via %q", spelling)
			}
		})
	}

	// cp -P does not follow a *source* symlink, but it still follows a symlink
	// at the destination and overwrites the file it points at. A hook name that
	// is a symlink must be removed (the link itself) before the copy.
	t.Run("destination symlink is not followed by the copy", func(t *testing.T) {
		root := setup(t)
		hooksDir := filepath.Join(root, ".git", "hooks")
		if err := os.MkdirAll(hooksDir, 0o755); err != nil {
			t.Fatal(err)
		}
		externalDir := t.TempDir()
		externalHook := filepath.Join(externalDir, "real-commit-msg")
		originalContent := []byte("#!/bin/sh\n# original external hook\nexit 0\n")
		if err := os.WriteFile(externalHook, originalContent, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(externalHook, filepath.Join(hooksDir, "commit-msg")); err != nil {
			t.Fatal(err)
		}

		out, code := run(t, root)
		if code != 0 {
			t.Fatalf("expected install to pass after replacing the destination symlink, got exit %d:\n%s", code, out)
		}
		data, err := os.ReadFile(externalHook)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, originalContent) {
			t.Fatalf("external file behind the destination symlink was overwritten: %q", data)
		}
		installed := filepath.Join(hooksDir, "commit-msg")
		if _, err := os.Lstat(installed); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Readlink(installed); err == nil {
			t.Fatalf("installed hook %s is still a symlink", installed)
		}
		got, err := os.ReadFile(installed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, commitMsgData) {
			t.Fatalf("installed commit-msg does not match githooks/commit-msg")
		}
	})
}
