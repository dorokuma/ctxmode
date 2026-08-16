package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	deployScript  = "deploy.sh"
	fragmentStart = "# ===== atomic deploy fragment: start =====\n"
	fragmentEnd   = "# ===== atomic deploy fragment: end =====\n"
)

// ---------- helpers ----------

func readDeployScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(deployScript)
	if err != nil {
		t.Fatalf("read %s: %v", deployScript, err)
	}
	return string(data)
}

// extractDeployFragment pulls the atomic-deploy section out of deploy.sh so
// tests can exercise it in temp copies without running the real script or
// touching real deployment paths.
func extractDeployFragment(t *testing.T, src string) string {
	t.Helper()
	start := strings.Index(src, fragmentStart)
	end := strings.Index(src, fragmentEnd)
	if start < 0 || end < 0 || end <= start+len(fragmentStart) {
		t.Fatalf("atomic deploy fragment markers not found in %s", deployScript)
	}
	return src[start+len(fragmentStart) : end]
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runFragment writes the extracted fragment into a temp copy with BUILD_OUT /
// BINARY injected, runs it with bash, and returns combined output + error.
func runFragment(t *testing.T, buildOut, binary string) (string, error) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "deploy-fragment.sh")
	header := "#!/bin/bash\nset -euo pipefail\nBUILD_OUT=" + shellQuote(buildOut) +
		"\nBINARY=" + shellQuote(binary) + "\n"
	content := header + extractDeployFragment(t, readDeployScript(t))
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write fragment copy: %v", err)
	}
	cmd := exec.Command("bash", script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func listTempFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".ctxmode.*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	return matches
}

// writeStubBinary writes an executable that consumes stdin, prints stdout/stderr,
// and exits with the given code. Used so the deploy fragment can run initialize
// against a fake binary without touching the real ctxmode.
func writeStubBinary(t *testing.T, path, stdout, stderr string, exitCode int) {
	t.Helper()
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("cat >/dev/null\n")
	if stderr != "" {
		b.WriteString("printf '%s\\n' " + shellQuote(stderr) + " >&2\n")
	}
	if stdout != "" {
		b.WriteString("printf '%s\\n' " + shellQuote(stdout) + "\n")
	}
	b.WriteString("exit " + strconv.Itoa(exitCode) + "\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o755); err != nil {
		t.Fatalf("write stub binary: %v", err)
	}
}

const stubInitializeJSON = `{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"ctxmode","version":"9.9.9"}}}`

// ---------- static constraints ----------

func TestDeployScript_StaticConstraints(t *testing.T) {
	src := readDeployScript(t)
	frag := extractDeployFragment(t, src)

	// temp file must be created inside the target directory (same fs as target).
	if !strings.Contains(frag, `mktemp "$TARGET_DIR/`) {
		t.Error(`fragment must mktemp inside target dir: mktemp "$TARGET_DIR/...`)
	}
	// replacement must be an atomic rename (mv) onto the target.
	if !strings.Contains(frag, `mv -f -- "$TMP_FILE" "$BINARY"`) {
		t.Error(`fragment must atomically rename temp file over target: mv -f -- "$TMP_FILE" "$BINARY"`)
	}
	// failure cleanup trap and success release must both be present.
	if !strings.Contains(frag, "trap cleanup_tmp ERR") {
		t.Error("fragment must install ERR trap for temp cleanup")
	}
	if !strings.Contains(frag, "trap - ERR") {
		t.Error("fragment must release ERR trap after successful rename")
	}
	// no direct install onto the target (the old non-atomic overwrite).
	if strings.Contains(frag, `"$BUILD_OUT" "$BINARY"`) {
		t.Error("fragment must not install directly onto the target path")
	}
	// initialize the staged file before replacing the live target.
	initAt := strings.Index(frag, "initialize")
	mvAt := strings.Index(frag, `mv -f -- "$TMP_FILE" "$BINARY"`)
	if initAt < 0 || mvAt < 0 || initAt > mvAt {
		t.Error("fragment must run initialize on the staged binary before mv")
	}
	if strings.Contains(frag, `timeout 5 "$BINARY"`) {
		t.Error("fragment must not initialize the live target; verify the staged file first")
	}
	if !strings.Contains(frag, `timeout 5 "$TMP_FILE"`) && !strings.Contains(frag, `timeout 5 "$BUILD_OUT"`) {
		t.Error("fragment must initialize $TMP_FILE or $BUILD_OUT before replace")
	}
	if strings.Contains(frag, "部署成功") {
		t.Error("fragment must not print 部署成功 (verify-failure path must never claim success)")
	}
	// verify failure must be a hard exit, not a swallowed no-op.
	if !strings.Contains(frag, "exit 1") {
		t.Error("fragment must exit 1 when initialize verification fails")
	}
	// do not hide initialize stderr on the failure path.
	if strings.Contains(frag, `"$TMP_FILE" 2>/dev/null`) || strings.Contains(frag, `"$BUILD_OUT" 2>/dev/null`) {
		t.Error("fragment must not swallow initialize stderr with 2>/dev/null")
	}
	// every variable use must be double-quoted (BINARY may contain spaces).
	for _, v := range []string{"$BINARY", "$BUILD_OUT", "$TMP_FILE", "$TARGET_DIR"} {
		for i := 0; ; {
			j := strings.Index(frag[i:], v)
			if j < 0 {
				break
			}
			pos := i + j
			if pos == 0 || frag[pos-1] != '"' {
				t.Errorf("variable %s must be double-quoted (use at offset %d)", v, pos)
			}
			i = pos + len(v)
		}
	}
	// the real script must at least parse cleanly (never executed here).
	if out, err := exec.Command("bash", "-n", deployScript).CombinedOutput(); err != nil {
		t.Errorf("bash -n %s failed: %v\n%s", deployScript, err, out)
	}
}

// ---------- behavior: success path ----------

func TestDeployFragment_SuccessReplacesTargetAtomically(t *testing.T) {
	// target directory and binary name both contain spaces.
	dir := filepath.Join(t.TempDir(), "my tools")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "ctx mode.bin")
	if err := os.WriteFile(binary, []byte("OLDV1"), 0o644); err != nil {
		t.Fatal(err)
	}

	buildOut := filepath.Join(t.TempDir(), "ctxmode-build")
	writeStubBinary(t, buildOut, stubInitializeJSON, "", 0)
	newBin, err := os.ReadFile(buildOut)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runFragment(t, buildOut, binary)
	if err != nil {
		t.Fatalf("fragment failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("read deployed binary: %v", err)
	}
	if string(got) != string(newBin) {
		t.Errorf("deployed content = %q, want %q", got, newBin)
	}
	info, err := os.Stat(binary)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("deployed mode = %v, want 0755", info.Mode().Perm())
	}
	if tmp := listTempFiles(t, dir); len(tmp) != 0 {
		t.Errorf("temp files left behind after success: %v", tmp)
	}
}

// ---------- behavior: failure before replacement ----------

func TestDeployFragment_FailureKeepsOldTargetAndCleansTemp(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "ctxmode")
	old := []byte("OLDV1")
	if err := os.WriteFile(binary, old, 0o755); err != nil {
		t.Fatal(err)
	}

	// missing build output => install fails before any replacement happens.
	buildOut := filepath.Join(t.TempDir(), "does-not-exist")

	out, err := runFragment(t, buildOut, binary)
	if err == nil {
		t.Fatalf("expected fragment to fail, got success\n%s", out)
	}

	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("old target lost after failure: %v", err)
	}
	if string(got) != string(old) {
		t.Errorf("old target content = %q, want %q", got, old)
	}
	if tmp := listTempFiles(t, dir); len(tmp) != 0 {
		t.Errorf("temp files not cleaned after failure: %v", tmp)
	}
}

func TestDeployFragment_MkdirFailureLeavesNothing(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("plain file"), 0o644); err != nil {
		t.Fatal(err)
	}
	// a parent component of BINARY is a regular file => mkdir -p fails early.
	binary := filepath.Join(blocker, "ctxmode")

	out, err := runFragment(t, filepath.Join(t.TempDir(), "unused"), binary)
	if err == nil {
		t.Fatalf("expected fragment to fail, got success\n%s", out)
	}
	if tmp := listTempFiles(t, dir); len(tmp) != 0 {
		t.Errorf("temp files left after mkdir failure: %v", tmp)
	}
}

// ---------- behavior: initialize fails, old target stays ----------

func TestDeployFragment_VerifyFailureKeepsOldTarget(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "ctxmode")
	old := []byte("OLDV1")
	if err := os.WriteFile(binary, old, 0o755); err != nil {
		t.Fatal(err)
	}

	buildOut := filepath.Join(t.TempDir(), "ctxmode-build")
	writeStubBinary(t, buildOut, "not-a-json-rpc-response", "initialize boom from stub", 1)

	out, err := runFragment(t, buildOut, binary)
	if err == nil {
		t.Fatalf("expected verify failure, got success\n%s", out)
	}
	if strings.Contains(out, "部署成功") {
		t.Errorf("verify failure must not print 部署成功\n%s", out)
	}
	if !strings.Contains(out, "initialize boom from stub") {
		t.Errorf("verify failure must surface initialize stderr, got:\n%s", out)
	}

	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("old target lost after verify failure: %v", err)
	}
	if string(got) != string(old) {
		t.Errorf("old target content = %q, want %q", got, old)
	}
	if tmp := listTempFiles(t, dir); len(tmp) != 0 {
		t.Errorf("temp files not cleaned after verify failure: %v", tmp)
	}
}

func TestDeployFragment_VerifyExitZeroWithoutVersionKeepsOldTarget(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "ctxmode")
	old := []byte("OLDV1")
	if err := os.WriteFile(binary, old, 0o755); err != nil {
		t.Fatal(err)
	}

	buildOut := filepath.Join(t.TempDir(), "ctxmode-build")
	// Exit 0 but no "version" field: the old script still printed 部署成功.
	writeStubBinary(t, buildOut, `{"jsonrpc":"2.0","id":1,"result":{}}`, "", 0)

	out, err := runFragment(t, buildOut, binary)
	if err == nil {
		t.Fatalf("expected verify failure for missing version, got success\n%s", out)
	}
	if strings.Contains(out, "部署成功") {
		t.Errorf("missing version must not print 部署成功\n%s", out)
	}

	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("old target lost after verify failure: %v", err)
	}
	if string(got) != string(old) {
		t.Errorf("old target content = %q, want %q", got, old)
	}
	if tmp := listTempFiles(t, dir); len(tmp) != 0 {
		t.Errorf("temp files not cleaned after verify failure: %v", tmp)
	}
}

func TestDeployScript_SuccessMessageRequiresVersion(t *testing.T) {
	src := readDeployScript(t)
	if strings.Contains(src, `${VERSION:-?}`) {
		t.Error("must not print 部署成功 with a placeholder version")
	}
	successAt := strings.Index(src, "部署成功")
	initAt := strings.Index(src, "initialize")
	if successAt < 0 || initAt < 0 {
		t.Fatal("expected both initialize and 部署成功 in deploy.sh")
	}
	if initAt > successAt {
		t.Error("initialize must run before printing 部署成功")
	}
}
