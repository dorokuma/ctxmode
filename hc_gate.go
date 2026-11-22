package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"
)

// Cached EvalSymlinks(os.Executable()) result for --hc-gate and prepare*.
var (
	selfExeOnce sync.Once
	selfExePath string
	selfExeInfo os.FileInfo
	selfExeErr  error
)

// inTestBinary is set true ONLY by TestMain in *_test.go builds: it arms the
// compile-time hc-gate pin so a test binary can never fall through to the
// host herdr-core on PATH. Production source never reads CTXMODE_TEST_*
// here — the pin itself is activated from test code.
var inTestBinary bool

// hcGateTestPin binds the test-binary hc-gate to ONE pre-verified stub
// herdr-core inside a single trusted home. The pin is installed by
// mustActivateChildHcGatePin (audit_test.go) in the --hc-gate child and by
// the test helpers for in-process runHcGate calls.
type hcGateTestPin struct {
	trustedHome string      // canonical trusted-home root (under os.TempDir())
	stubBin     string      // canonical stub path inside trustedHome, basename "herdr-core"
	stubInfo    os.FileInfo // os.Stat(stubBin) captured at pin time
}

// testHcGatePin is the process-wide pin; nil means "no pin" (fail-closed
// under inTestBinary, unused in production).
var testHcGatePin *hcGateTestPin

// hcTestEnvTrustedHome / hcTestEnvStub / hcTestEnvStubLog are the env names
// the pin contract passes from a test parent to a --hc-gate child of the
// test binary. They are declared here only so the contract documentation
// travels with the implementation — PRODUCTION code must never read them
// (mustActivateChildHcGatePin in *_test.go is the sole reader).
const (
	hcTestEnvTrustedHome = "CTXMODE_TEST_TRUSTED_HOME"
	hcTestEnvStub        = "CTXMODE_TEST_HC_STUB"
	hcTestEnvStubLog     = "HC_STUB_LOG"
)

// resolvedSelfExe returns the symlink-resolved path of the running
// executable and its Stat info. The result is computed once per process.
func resolvedSelfExe() (string, os.FileInfo, error) {
	selfExeOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil {
			selfExeErr = err
			return
		}
		resolved, err := filepath.EvalSymlinks(exe)
		if err != nil {
			selfExeErr = err
			return
		}
		info, err := os.Stat(resolved)
		if err != nil {
			selfExeErr = err
			return
		}
		selfExePath = resolved
		selfExeInfo = info
	})
	return selfExePath, selfExeInfo, selfExeErr
}

// isPreparedHcGateArgv reports whether argv is a prepare*-emitted
// `[selfExe, "--hc-gate", ...]` invocation whose argv[0] matches the
// cached self executable (EvalSymlinks path or SameFile).
func isPreparedHcGateArgv(argv []string) bool {
	if len(argv) < 2 || argv[1] != "--hc-gate" {
		return false
	}
	self, selfInfo, err := resolvedSelfExe()
	if err != nil || self == "" || selfInfo == nil {
		return false
	}
	head := argv[0]
	if head == self || filepath.Clean(head) == self {
		return true
	}
	if resolved, err := filepath.EvalSymlinks(head); err == nil {
		if resolved == self {
			return true
		}
		if st, err := os.Stat(resolved); err == nil && os.SameFile(st, selfInfo) {
			return true
		}
	}
	if st, err := os.Stat(head); err == nil && os.SameFile(st, selfInfo) {
		return true
	}
	return false
}

// runHcGate implements `ctxmode --hc-gate …`: validate the hc argv, resolve
// a trusted herdr-core via safe PATH dirs only, and exec it by fd
// (/proc/self/fd/3 + ExtraFiles) with no PATH fallback.
func runHcGate(args []string) int {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "hc-gate: unsupported on "+runtime.GOOS+" (linux fd-exec only)")
		return 126
	}
	if os.Getenv("CTXMODE_IN_HC_GATE") == "1" {
		fmt.Fprintln(os.Stderr, "hc-gate: recursive invocation blocked")
		return 126
	}

	if reason := validateHcGateArgs(args); reason != "" {
		fmt.Fprintln(os.Stderr, guardBlockedError(ruleSubagentNestedAgent, "hc send ("+reason+")"))
		return 1
	}

	selfExe, selfStat, err := resolvedSelfExe()
	if err != nil || selfExe == "" || selfStat == nil {
		fmt.Fprintln(os.Stderr, "hc-gate: cannot resolve self executable")
		return 126
	}

	resolved, err := findTrustedHcExecutable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hc-gate:", err)
		return 126
	}

	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hc-gate: open failed:", err)
		return 126
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		fmt.Fprintln(os.Stderr, "hc-gate: stat failed:", err)
		return 126
	}
	if !st.Mode().IsRegular() || st.Mode()&0111 == 0 {
		fmt.Fprintln(os.Stderr, "hc-gate: target is not an executable regular file")
		return 126
	}
	if os.SameFile(st, selfStat) {
		fmt.Fprintln(os.Stderr, "hc-gate: refusing to exec self (recursive)")
		return 126
	}
	resDir := filepath.Clean(filepath.Dir(resolved))
	if !isSystemPathDir(resDir) {
		if !statUIDAndPermOK(st, os.Geteuid(), false) {
			fmt.Fprintln(os.Stderr, "hc-gate: target ownership/permissions not trusted")
			return 126
		}
	}
	var hdr [4]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil || string(hdr[:]) != "\x7fELF" {
		fmt.Fprintln(os.Stderr, "hc-gate: target is not an ELF binary")
		return 126
	}
	// Test binaries: the opened target must be the PINNED stub itself — the
	// selection-stage pin already guarantees this, but the fd-exec stage
	// re-verifies so a pin bypass (or a swapped file) can never reach exec.
	if inTestBinary && (testHcGatePin == nil || !os.SameFile(st, testHcGatePin.stubInfo)) {
		fmt.Fprintln(os.Stderr, "hc-gate: test binary refuses non-pinned hc target")
		return 126
	}

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hc-gate: open /dev/null failed:", err)
		return 126
	}
	defer devNull.Close()

	cmd := exec.Command("/proc/self/fd/3", args...)
	cmd.Args[0] = "hc"
	cmd.ExtraFiles = []*os.File{f}
	cmd.Stdin = devNull
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "CTXMODE_IN_HC_GATE=1")

	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "hc-gate: exec failed:", err)
		return 126
	}
	if cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	return 0
}

// validateHcGateArgs applies the same static hc-send rules at runtime.
// On failure it returns a short reason that MUST NOT include the text body.
func validateHcGateArgs(args []string) string {
	if isPureQueryInvocation(append([]string{"hc"}, args...)) {
		return ""
	}
	if len(args) == 2 && !strings.HasPrefix(args[0], "-") &&
		(args[1] == "--help" || args[1] == "-h") {
		return ""
	}
	if len(args) != 3 || args[0] != "send" {
		return "invalid argv"
	}
	addr, text := args[1], args[2]
	if strings.HasPrefix(addr, "-") || !hcSendAddrOK(addr) {
		return "bad address"
	}
	if strings.HasPrefix(text, "-") {
		return "leading '-' / option-injection"
	}
	if !utf8.ValidString(text) || hasHcControlChars(text) {
		if strings.Contains(text, "\r") {
			return "CR control character"
		}
		if !utf8.ValidString(text) {
			return "invalid UTF-8"
		}
		return "control characters"
	}
	if err := checkSensitiveContent(text); err != nil {
		return "sensitive content (redacted)"
	}
	return ""
}

// findTrustedHcExecutable walks PATH like lookPathIn but only admits
// directories that pass isSafePathDirEntry, requires on-disk trust, and
// insists the EvalSymlinks basename canonicalises to herdr-core.
func findTrustedHcExecutable() (string, error) {
	euid := os.Geteuid()
	pathEnv := os.Getenv("PATH")
	if inTestBinary && testHcGatePin == nil {
		return "", fmt.Errorf("test binary without hc pin refuses to search PATH")
	}
	pinHome := ""
	if testHcGatePin != nil {
		pinHome = filepath.Clean(testHcGatePin.trustedHome) + "/"
	}
	for _, dir := range strings.Split(pathEnv, ":") {
		switch {
		case dir == "":
			continue // lookPathIn would use "."; not an absolute safe dir
		case !filepath.IsAbs(dir):
			continue
		}
		dir = filepath.Clean(dir)
		cand := filepath.Join(dir, "hc")
		if testHcGatePin != nil {
			// Pinned mode: a PATH directory with NO hc entry is skipped
			// normally (mise/pnpm shim dirs stay compatible), but once a
			// directory DOES carry an "hc" entry it must be the pinned
			// stub — anything else is an immediate failure, never a
			// fall-through to the next PATH dir (e.g. /root/.local/bin).
			if _, err := os.Lstat(cand); err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return "", fmt.Errorf("test hc pin: lstat %s: %v", cand, err)
			}
			if !strings.HasPrefix(dir+"/", pinHome) {
				return "", fmt.Errorf("test hc pin: %s outside pinned trusted home", cand)
			}
			if !isSafePathDirEntry(dir) {
				return "", fmt.Errorf("test hc pin: %s dir not a safe PATH entry", dir)
			}
			st, err := os.Stat(cand)
			if err != nil || st.IsDir() || st.Mode()&0111 == 0 {
				return "", fmt.Errorf("test hc pin: %s not an executable regular file", cand)
			}
			if !isTrustedExecutableOnDisk(cand, euid) {
				return "", fmt.Errorf("test hc pin: %s untrusted on disk", cand)
			}
			resolved, err := filepath.EvalSymlinks(cand)
			if err != nil {
				return "", fmt.Errorf("test hc pin: %s resolve: %v", cand, err)
			}
			pst, err := os.Stat(resolved)
			if err != nil || !os.SameFile(pst, testHcGatePin.stubInfo) {
				return "", fmt.Errorf("test hc pin: %s is not the pinned stub", cand)
			}
			return resolved, nil
		}
		if !isSafePathDirEntry(dir) {
			continue
		}
		// Production refuses every non-install-slot PATH entry: a safe
		// toolchain dir is not enough — the gate must never exec a
		// ~/.cargo/bin, .venv/bin or node_modules/.bin shadow (R3 SF-2).
		// Only /usr/local/bin or <trustedHome>/.local/bin qualify.
		if dir != "/usr/local/bin" {
			tail, ok := stripTrustedHomePrefix(dir)
			if !ok || tail != "/.local/bin" {
				continue
			}
		}
		st, err := os.Stat(cand)
		if err != nil || st.IsDir() || st.Mode()&0111 == 0 {
			continue
		}
		if !isTrustedExecutableOnDisk(cand, euid) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(cand)
		if err != nil {
			continue
		}
		base := canonicalResolvedBase(filepath.Base(resolved))
		if base != "herdr-core" {
			continue
		}
		return resolved, nil
	}
	return "", fmt.Errorf("trusted hc not found in safe PATH")
}
