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
// a trusted herdr-core/sbx via safe PATH dirs only, and exec it by fd
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
// insists the EvalSymlinks basename canonicalises to herdr-core or sbx.
func findTrustedHcExecutable() (string, error) {
	euid := os.Geteuid()
	pathEnv := os.Getenv("PATH")
	for _, dir := range strings.Split(pathEnv, ":") {
		switch {
		case dir == "":
			continue // lookPathIn would use "."; not an absolute safe dir
		case !filepath.IsAbs(dir):
			continue
		}
		dir = filepath.Clean(dir)
		if !isSafePathDirEntry(dir) {
			continue
		}
		cand := filepath.Join(dir, "hc")
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
		if base != "herdr-core" && base != "sbx" {
			continue
		}
		return resolved, nil
	}
	return "", fmt.Errorf("trusted hc not found in safe PATH")
}
