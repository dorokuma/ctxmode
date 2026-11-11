package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
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

// verifyTimeoutRe matches the verify pipeline's `timeout <N> "$VAR"`
// invocation. N must be a bare integer argument (rejects `timeout 15s`,
// `timeout -k 1 15`, `command -v timeout`, and comment prose like
// "timeout 15 必须…" because the "15" there is followed by a space, not
// a quoted variable).
var verifyTimeoutRe = regexp.MustCompile(`\btimeout[ \t]+([0-9]+)[ \t]+"`)

// verifyTimeoutFloor is the minimum acceptable verify timeout in
// deploy.sh. It must strictly exceed stdioDrainMaxWait (the drain cap,
// read from the source constant rather than redeclared here): when the
// stdio drain holds EOF for the full cap, a verify `timeout` of the same
// value would kill the process at the same instant (rc=124) and the
// bounded retries would reject a working binary.
const verifyTimeoutFloor = 15 * time.Second

// assertVerifyTimeoutAboveDrainCap extracts the verify `timeout` argument
// from a shell fragment and asserts it is a numeric value >=
// verifyTimeoutFloor (which itself must exceed stdioDrainMaxWait).
// Parsing is anchored on the verify invocation shape `timeout <N> "$VAR"`,
// so non-numeric uses like `command -v timeout` and prose inside comments
// cannot satisfy it; finding no such invocation is a hard failure, never
// a skip.
func assertVerifyTimeoutAboveDrainCap(t *testing.T, frag, scope string) {
	t.Helper()
	if err := verifyTimeoutErr(frag, scope); err != nil {
		t.Error(err)
	}
}

// verifyTimeoutErr is the pure-check core of
// assertVerifyTimeoutAboveDrainCap so the false-green regression test can
// drive it with constructed fragments without a real *testing.T failure.
func verifyTimeoutErr(frag, scope string) error {
	if verifyTimeoutFloor <= stdioDrainMaxWait {
		return fmt.Errorf("%s: test floor bug: verifyTimeoutFloor=%v must exceed stdioDrainMaxWait=%v",
			scope, verifyTimeoutFloor, stdioDrainMaxWait)
	}
	var vals []int
	for _, m := range verifyTimeoutRe.FindAllStringSubmatch(frag, -1) {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return fmt.Errorf("%s: cannot parse verify timeout value %q: %v", scope, m[1], err)
		}
		vals = append(vals, n)
	}
	if len(vals) == 0 {
		return fmt.Errorf("%s: 未能从 fragment 解析出 verify timeout 值 (want `timeout <N> \"$VAR\"`)", scope)
	}
	for _, n := range vals {
		if time.Duration(n)*time.Second < verifyTimeoutFloor {
			return fmt.Errorf("%s: verify timeout %ds must be >= %ds (> stdioDrainMaxWait=%v)",
				scope, n, int(verifyTimeoutFloor/time.Second), stdioDrainMaxWait)
		}
	}
	return nil
}

// runFragment writes the extracted fragment into a temp copy with BUILD_OUT /
// BINARY injected, runs it with bash, and returns combined output + error.
// CTXMODE_SKIP_IMMUTABLE_LOCK=1 is injected by default: these tests run as
// root on ext4 under t.TempDir(), where a real `chattr +i` would survive the
// test and make the temp-dir cleanup fail with "operation not permitted".
// The lock logic itself is covered by TestDeployScript_StaticConstraints.
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
	cmd.Env = append(os.Environ(), "CTXMODE_SKIP_IMMUTABLE_LOCK=1")
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
	// WriteFile's perm is masked by the process umask: under a strict
	// umask (0007/0027) the stub lands 0750 and the unprivileged
	// re-deploy in TestDeployFragment_SecondDeployOverReadonlyPrevSucceeds
	// cannot read it. Pin the mode the write intended.
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatalf("chmod stub binary: %v", err)
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
	if strings.Contains(frag, `timeout 15 "$BINARY"`) {
		t.Error("fragment must not initialize the live target; verify the staged file first")
	}
	if !strings.Contains(frag, `timeout 15 "$TMP_FILE"`) && !strings.Contains(frag, `timeout 15 "$BUILD_OUT"`) {
		t.Error("fragment must initialize $TMP_FILE or $BUILD_OUT before replace")
	}
	// The verify timeout must exceed the drain cap: when the stdio drain
	// holds EOF for the full stdioDrainMaxWait (5s), a verify `timeout` of
	// the same value would kill the process at the same instant (rc=124)
	// and reject a working binary after the bounded retries.
	assertVerifyTimeoutAboveDrainCap(t, frag, "deploy fragment")
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
	// The staged file is read+execute only: a deployed binary must not be
	// writable through the ordinary DAC path.
	if !strings.Contains(frag, `install -m 0555 "$BUILD_OUT" "$TMP_FILE"`) {
		t.Error(`fragment must stage the binary read+execute only: install -m 0555 "$BUILD_OUT" "$TMP_FILE"`)
	}
	// Immutable-lock protection: unlock the live target before the rename,
	// re-lock it after, with an explicit opt-out for tests.
	if !strings.Contains(frag, "CTXMODE_SKIP_IMMUTABLE_LOCK") {
		t.Error("fragment must honour CTXMODE_SKIP_IMMUTABLE_LOCK so tests can skip chattr")
	}
	if !strings.Contains(frag, `chattr -i "$1"`) || !strings.Contains(frag, `chattr +i "$1"`) {
		t.Error(`fragment must guard the target with chattr -i / chattr +i`)
	}
	unlockAt := strings.Index(frag, `unlock_immutable "$BINARY"`)
	mvAt = strings.Index(frag, `mv -f -- "$TMP_FILE" "$BINARY"`)
	if unlockAt < 0 || mvAt < 0 || unlockAt > mvAt {
		t.Error("fragment must chattr -i the target before mv")
	}
	// (searched after the rename so the `unlock_immutable` spelling, which
	// contains this substring, cannot satisfy it by accident)
	if mvAt < 0 || !strings.Contains(frag[mvAt:], `lock_immutable "$BINARY"`) {
		t.Error("fragment must chattr +i the target after a successful mv")
	}
	if prevAt := strings.Index(frag, `unlock_immutable "${BINARY}.prev"`); prevAt < 0 || prevAt > strings.Index(frag, `cp -- "$BINARY" "${BINARY}.prev"`) {
		t.Error("fragment must clear an existing +i on ${BINARY}.prev before backing up")
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

// ---------- behavior: second deploy over a read-only .prev ----------

func TestDeployFragment_SecondDeployOverReadonlyPrevSucceeds(t *testing.T) {
	// The work dir must sit directly under /tmp: when run as root the second
	// deploy is re-executed as an unprivileged uid, and t.TempDir() parents
	// are 0700 root-owned — a non-root child could not even traverse into
	// the directory. /tmp is world-traversable on every supported host.
	dir, err := os.MkdirTemp("/tmp", "ctxmode-deploy-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		// The unprivileged deploy may leave files root must remove; the dir
		// itself is already writable by the test user.
		if err := os.RemoveAll(dir); err != nil {
			t.Logf("cleanup %s: %v", dir, err)
		}
	}()
	binary := filepath.Join(dir, "ctxmode")
	prev := binary + ".prev"

	// First deploy stages the old binary into .prev.
	buildOut := filepath.Join(t.TempDir(), "ctxmode-build")
	writeStubBinary(t, buildOut, stubInitializeJSON, "", 0)
	if err := os.WriteFile(binary, []byte("OLDV1"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := runFragment(t, buildOut, binary)
	if err != nil {
		t.Fatalf("first deploy failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(prev); err != nil {
		t.Fatalf("first deploy must leave a .prev backup: %v", err)
	}
	// Second deploy: make .prev read-only — a leftover 0444/0555 backup must
	// not break the next deploy's backup step. Run as an unprivileged user
	// when possible: as root cp over a 0444 file succeeds anyway, so only a
	// non-root run actually exercises the rm -f fix.
	if err := os.Chmod(prev, 0o444); err != nil {
		t.Fatal(err)
	}
	// The second stub also lives under dir so the unprivileged child can
	// read it (a t.TempDir() parent would again be 0700 root-owned).
	buildOut2 := filepath.Join(dir, "ctxmode-build2")
	writeStubBinary(t, buildOut2, stubInitializeJSON, "", 0)
	stub2, err := os.ReadFile(buildOut2)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		// Hand the directory to an unprivileged user and re-run the
		// fragment as them: without rm -f the cp over the read-only
		// .prev is a real Permission denied.
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Skipf("cannot chown temp dir for unprivileged re-deploy: %v", err)
		}
		if err := os.Chown(binary, 65534, 65534); err != nil {
			t.Skipf("cannot chown binary for unprivileged re-deploy: %v", err)
		}
		if err := os.Chown(prev, 65534, 65534); err != nil {
			t.Skipf("cannot chown .prev for unprivileged re-deploy: %v", err)
		}
		// dir lives under /tmp (world-traversable) so the unprivileged child
		// can reach and write into it once it owns it.
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Skipf("cannot chmod temp dir for unprivileged re-deploy: %v", err)
		}
		if _, err := exec.LookPath("setpriv"); err != nil {
			t.Skip("setpriv not available for unprivileged re-deploy")
		}
		// Feed the fragment through bash's stdin so the unprivileged uid
		// never needs execute/search permission on a script file or its
		// root-owned parent dirs.
		header := "set -euo pipefail\nBUILD_OUT=" + shellQuote(buildOut2) +
			"\nBINARY=" + shellQuote(binary) + "\n"
		content := header + extractDeployFragment(t, readDeployScript(t))
		cmd := exec.Command("setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "bash", "-s")
		cmd.Stdin = strings.NewReader(content)
		// The child needs a cwd it can still chdir back into after setpriv
		// drops privileges (bash probes it at startup), and TMPDIR must be
		// dropped so bash/mktemp fall back to world-writable /tmp instead
		// of the inherited root-owned test dir.
		env := []string{"CTXMODE_SKIP_IMMUTABLE_LOCK=1"}
		for _, e := range os.Environ() {
			if !strings.HasPrefix(e, "TMPDIR=") && !strings.HasPrefix(e, "CTXMODE_SKIP_IMMUTABLE_LOCK=") {
				env = append(env, e)
			}
		}
		cmd.Env = env
		cmd.Dir = dir
		var outBytes []byte
		outBytes, err = cmd.CombinedOutput()
		out = string(outBytes)
	} else {
		out, err = runFragment(t, buildOut2, binary)
	}
	if err != nil {
		t.Fatalf("second deploy over read-only .prev failed: %v\n%s", err, out)
	}
	prevData, err := os.ReadFile(prev)
	if err != nil {
		t.Fatalf("second deploy must refresh .prev: %v\n%s", err, out)
	}
	if !strings.Contains(string(prevData), "9.9.9") {
		t.Errorf(".prev must hold the previous (stub) binary, got %q", prevData)
	}
	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(stub2) {
		t.Errorf("deployed content = %q, want second stub", got)
	}
	if tmp := listTempFiles(t, dir); len(tmp) != 0 {
		t.Errorf("temp files left behind after second deploy: %v", tmp)
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
	if info.Mode().Perm() != 0o555 {
		t.Errorf("deployed mode = %v, want 0555 (read+execute only)", info.Mode().Perm())
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

// ---------- rollback: static constraints ----------

const (
	rollbackFragmentStart = "# ===== rollback fragment: start =====\n"
	rollbackFragmentEnd   = "# ===== rollback fragment: end =====\n"
)

func extractRollbackFragment(t *testing.T, src string) string {
	t.Helper()
	start := strings.Index(src, rollbackFragmentStart)
	end := strings.Index(src, rollbackFragmentEnd)
	if start < 0 || end < 0 || end <= start+len(rollbackFragmentStart) {
		t.Fatalf("rollback fragment markers not found in %s", deployScript)
	}
	return src[start+len(rollbackFragmentStart) : end]
}

// runRollbackFragment runs the rollback section in a temp copy with BINARY
// injected and argv[1]=rollback (rollback never compiles, no BUILD_OUT).
// CTXMODE_SKIP_IMMUTABLE_LOCK=1 mirrors runFragment: a real chattr +i under
// t.TempDir() would break the temp-dir cleanup when the tests run as root.
func runRollbackFragment(t *testing.T, binary string) (string, error) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "deploy-rollback.sh")
	header := "#!/bin/bash\nset -euo pipefail\nBINARY=" + shellQuote(binary) + "\n"
	content := header + extractRollbackFragment(t, readDeployScript(t))
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatalf("write rollback copy: %v", err)
	}
	cmd := exec.Command("bash", script, "rollback")
	cmd.Env = append(os.Environ(), "CTXMODE_SKIP_IMMUTABLE_LOCK=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestDeployScript_RollbackStaticConstraints(t *testing.T) {
	src := readDeployScript(t)
	frag := extractRollbackFragment(t, src)

	// missing backup / failed verification must be hard errors.
	if !strings.Contains(frag, "exit 1") {
		t.Error("rollback must exit 1 when the .prev backup is missing or fails verification")
	}
	// restore must be an atomic rename within the target directory.
	if !strings.Contains(frag, `mv -f -- "$PREV" "$BINARY"`) {
		t.Error(`rollback must atomically rename the backup over the target: mv -f -- "$PREV" "$BINARY"`)
	}
	// the backup must be verified with initialize before it replaces the target.
	initAt := strings.Index(frag, "initialize")
	mvAt := strings.Index(frag, `mv -f -- "$PREV" "$BINARY"`)
	if initAt < 0 || mvAt < 0 || initAt > mvAt {
		t.Error("rollback must run initialize on the backup before mv")
	}
	if strings.Contains(frag, `timeout 15 "$BINARY"`) {
		t.Error("rollback must not initialize the live target; verify the backup instead")
	}
	if !strings.Contains(frag, `timeout 15 "$PREV"`) {
		t.Error("rollback must initialize the staged backup with timeout")
	}
	assertVerifyTimeoutAboveDrainCap(t, frag, "rollback fragment")
	// The restored binary stays under the same protection as a deployed one:
	// read+execute mode and the immutable lock (after unlocking the target,
	// which a rename over an immutable file could not otherwise replace).
	if !strings.Contains(frag, `chmod 0555 "$PREV"`) {
		t.Error(`rollback must restore the read+execute mode: chmod 0555 "$PREV"`)
	}
	if !strings.Contains(frag, "CTXMODE_SKIP_IMMUTABLE_LOCK") || !strings.Contains(frag, "chattr +i") {
		t.Error("rollback must re-apply the immutable lock (honouring CTXMODE_SKIP_IMMUTABLE_LOCK)")
	}
	if unlockAt := strings.Index(frag, `unlock_immutable "$BINARY"`); unlockAt < 0 || unlockAt > strings.Index(frag, `mv -f -- "$PREV" "$BINARY"`) {
		t.Error("rollback must clear the target's +i lock before the rename")
	}
	if mvAt := strings.Index(frag, `mv -f -- "$PREV" "$BINARY"`); mvAt < 0 || !strings.Contains(frag[mvAt:], `lock_immutable "$BINARY"`) {
		t.Error("rollback must re-lock the restored binary after the rename")
	}
	if !strings.Contains(src, "rollback") || !strings.Contains(src, "用法") {
		t.Error("deploy.sh must document rollback usage")
	}
	// every variable use must be double-quoted (BINARY may contain spaces).
	for _, v := range []string{"$BINARY", "$PREV", "$TARGET_DIR", "$ROLL_ERR"} {
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
}

// ---------- rollback: behavior ----------

func TestDeployRollback_RestoresPrevAndReportsVersion(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "ctx mode.bin")
	if err := os.WriteFile(binary, []byte("CURRENT"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := binary + ".prev"
	writeStubBinary(t, prev, stubInitializeJSON, "", 0)
	want, err := os.ReadFile(prev)
	if err != nil {
		t.Fatal(err)
	}

	out, err := runRollbackFragment(t, binary)
	if err != nil {
		t.Fatalf("rollback failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "9.9.9") || !strings.Contains(out, "回滚成功") {
		t.Errorf("rollback must report restored version, got:\n%s", out)
	}
	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("rolled-back content = %q, want %q", got, want)
	}
	if _, err := os.Stat(prev); !os.IsNotExist(err) {
		t.Errorf(".prev should be consumed by a successful rollback (stat err=%v)", err)
	}
	if files := listTempFiles(t, dir); len(files) != 0 {
		t.Errorf("rollback temp files left behind: %v", files)
	}
}

func TestDeployRollback_MissingPrevFailsWithoutTouchingTarget(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "ctxmode")
	if err := os.WriteFile(binary, []byte("CURRENT"), 0o755); err != nil {
		t.Fatal(err)
	}

	out, err := runRollbackFragment(t, binary)
	if err == nil {
		t.Fatalf("expected rollback to fail without .prev\n%s", out)
	}
	if !strings.Contains(out, "备份不存在") {
		t.Errorf("must report the missing backup, got:\n%s", out)
	}
	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "CURRENT" {
		t.Errorf("target must stay untouched, got %q", got)
	}
}

func TestDeployRollback_VerifyFailureKeepsTargetAndPrev(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "ctxmode")
	if err := os.WriteFile(binary, []byte("CURRENT"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := binary + ".prev"
	writeStubBinary(t, prev, "not-a-json-rpc-response", "initialize boom from stub", 1)

	out, err := runRollbackFragment(t, binary)
	if err == nil {
		t.Fatalf("expected verify failure, got success\n%s", out)
	}
	if !strings.Contains(out, "initialize boom from stub") {
		t.Errorf("verify failure must surface initialize stderr, got:\n%s", out)
	}
	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "CURRENT" {
		t.Errorf("target must stay untouched after verify failure, got %q", got)
	}
	if _, err := os.Stat(prev); err != nil {
		t.Errorf(".prev must survive a failed rollback: %v", err)
	}
	if files := listTempFiles(t, dir); len(files) != 0 {
		t.Errorf("rollback temp files left behind: %v", files)
	}
}

func TestDeployFragment_CreatesPrevBackupBeforeReplace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "my tools")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "ctxmode")
	if err := os.WriteFile(binary, []byte("OLDV1"), 0o755); err != nil {
		t.Fatal(err)
	}
	buildOut := filepath.Join(t.TempDir(), "ctxmode-build")
	writeStubBinary(t, buildOut, stubInitializeJSON, "", 0)

	out, err := runFragment(t, buildOut, binary)
	if err != nil {
		t.Fatalf("fragment failed: %v\n%s", err, out)
	}
	prevData, err := os.ReadFile(binary + ".prev")
	if err != nil {
		t.Fatalf("deploy must back up the current binary to .prev: %v\n%s", err, out)
	}
	if string(prevData) != "OLDV1" {
		t.Errorf(".prev content = %q, want OLDV1", prevData)
	}
	got, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "9.9.9") {
		t.Errorf("deployed content should be the new stub, got %q", got)
	}
}

// ---------- pi extension install guard (native Go extension coexistence) ----------

// TestPiInstallScript_NativeGoExtensionGuard covers the zero-node host
// regression: on hosts where ~/.pig/agent/extensions/ctxmode is a symlink to
// a native Go extension directory (containing go.mod), install.sh must NOT
// write ctxmode.ts — pig scans *.ts extensions at startup and would try to
// spawn a nonexistent node (>= 22.13), crashing before any session starts.
// The guard only applies to the default destination; an explicit
// PI_CTXMODE_EXT still installs. All fixtures live under t.TempDir(); the
// real /root/.pig is never touched.
func TestPiInstallScript_NativeGoExtensionGuard(t *testing.T) {
	installScript, err := filepath.Abs(filepath.Join("integrations", "pi", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}

	// runInstall executes the real install.sh with a minimal env: PATH (for
	// md5sum/install), an optional fake HOME, and an optional explicit
	// PI_CTXMODE_EXT. stdout/stderr are returned separately.
	runInstall := func(t *testing.T, home, explicitDest string) (string, string, error) {
		t.Helper()
		cmd := exec.Command("bash", installScript)
		env := []string{"PATH=" + os.Getenv("PATH")}
		if home != "" {
			env = append(env, "HOME="+home)
		}
		if explicitDest != "" {
			env = append(env, "PI_CTXMODE_EXT="+explicitDest)
		}
		cmd.Env = env
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		runErr := cmd.Run()
		return stdout.String(), stderr.String(), runErr
	}

	// newNativeFixture builds fakeHome/.pig/agent/extensions/ctxmode as a
	// symlink to a temp dir containing go.mod — the zero-node host layout.
	newNativeFixture := func(t *testing.T) (fakeHome, extDir, nativeDir, tsDest string) {
		t.Helper()
		fakeHome = t.TempDir()
		extDir = filepath.Join(fakeHome, ".pig", "agent", "extensions")
		if err := os.MkdirAll(extDir, 0o755); err != nil {
			t.Fatal(err)
		}
		nativeDir = t.TempDir()
		if err := os.WriteFile(filepath.Join(nativeDir, "go.mod"), []byte("module example.com/native\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(nativeDir, filepath.Join(extDir, "ctxmode")); err != nil {
			t.Fatal(err)
		}
		tsDest = filepath.Join(extDir, "ctxmode.ts")
		return fakeHome, extDir, nativeDir, tsDest
	}

	t.Run("default dest skipped when native Go extension is active", func(t *testing.T) {
		fakeHome, extDir, nativeDir, tsDest := newNativeFixture(t)
		if err := os.WriteFile(tsDest, []byte("STALE"), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := runInstall(t, fakeHome, "")
		if err != nil {
			t.Fatalf("install.sh must exit 0 when skipping for a native Go ext: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
		}
		if !strings.Contains(stdout, "skipped: native Go extension active") {
			t.Errorf("expected skip notice on stdout, got:\n%s", stdout)
		}
		if _, err := os.Lstat(tsDest); !os.IsNotExist(err) {
			t.Errorf("stale ctxmode.ts must be removed (self-heal), Lstat err=%v", err)
		}
		target, err := os.Readlink(filepath.Join(extDir, "ctxmode"))
		if err != nil || target != nativeDir {
			t.Errorf("native ext symlink must survive, target=%q err=%v", target, err)
		}
		if _, err := os.Stat(filepath.Join(nativeDir, "go.mod")); err != nil {
			t.Errorf("native ext go.mod must survive: %v", err)
		}
	})

	t.Run("default dest removes dangling symlink ctxmode.ts", func(t *testing.T) {
		fakeHome, _, _, tsDest := newNativeFixture(t)
		// A dangling symlink: [ -e "$DEST" ] is false but [ -L "$DEST" ] is
		// true — the guard must still self-heal it before skipping.
		if err := os.Symlink(filepath.Join(t.TempDir(), "nonexistent.ts"), tsDest); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, err := runInstall(t, fakeHome, "")
		if err != nil {
			t.Fatalf("install.sh must exit 0 when skipping for a native Go ext: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
		}
		if !strings.Contains(stdout, "skipped: native Go extension active") {
			t.Errorf("expected skip notice on stdout, got:\n%s", stdout)
		}
		if _, err := os.Lstat(tsDest); !os.IsNotExist(err) {
			t.Errorf("dangling ctxmode.ts symlink must be removed (self-heal), Lstat err=%v", err)
		}
	})

	t.Run("explicit PI_CTXMODE_EXT still installs alongside native ext", func(t *testing.T) {
		fakeHome, _, _, tsDest := newNativeFixture(t)
		stdout, stderr, err := runInstall(t, fakeHome, tsDest)
		if err != nil {
			t.Fatalf("explicit PI_CTXMODE_EXT must bypass the native-ext guard: %v\nstderr:\n%s", err, stderr)
		}
		if !strings.Contains(stdout, "changed: installed") {
			t.Errorf("expected install, got:\n%s", stdout)
		}
		got, err := os.ReadFile(tsDest)
		if err != nil {
			t.Fatalf("dest must be written: %v", err)
		}
		want, err := os.ReadFile(filepath.Join("integrations", "pi", "ctxmode.ts"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Error("installed ctxmode.ts must match the repo source")
		}
	})

	t.Run("no native ext installs then reports unchanged", func(t *testing.T) {
		fakeHome := t.TempDir()
		stdout, _, err := runInstall(t, fakeHome, "")
		if err != nil {
			t.Fatalf("first install must succeed: %v", err)
		}
		if !strings.Contains(stdout, "changed: installed") {
			t.Errorf("first run must install, got:\n%s", stdout)
		}
		stdout, _, err = runInstall(t, fakeHome, "")
		if err != nil {
			t.Fatalf("second install must succeed: %v", err)
		}
		if !strings.Contains(stdout, "unchanged:") {
			t.Errorf("second run must hit the md5 idempotent branch, got:\n%s", stdout)
		}
	})

	t.Run("trailing slash destination fails explicitly", func(t *testing.T) {
		_, stderr, err := runInstall(t, "", filepath.Join(t.TempDir(), "foo")+"/")
		if err == nil {
			t.Fatal("a PI_CTXMODE_EXT ending in '/' must fail")
		}
		if !strings.Contains(stderr, "install.sh FAILED:") {
			t.Errorf("failure must be explicit on stderr, got:\n%s", stderr)
		}
	})
}
