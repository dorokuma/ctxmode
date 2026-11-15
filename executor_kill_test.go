package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newTestSleeper returns a unique per-test path to the system sleep binary:
// a symlink inside t.TempDir(). Tests launch their sleepers through this
// path so cleanup and waitForNoProc match only THIS test run's own
// processes by their /proc/<pid>/cmdline — a foreign "sleep" (or another
// concurrent session's test run) can never be matched or killed.
func newTestSleeper(t *testing.T) string {
	t.Helper()
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep binary not found: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ctxmode-test-sleeper")
	if err := os.Symlink(sleepBin, path); err != nil {
		t.Fatalf("symlink sleeper: %v", err)
	}
	return path
}

// killTestSleepers SIGKILLs every leftover process whose cmdline contains
// this test's unique sleeperPath, then polls until they are gone. Matching
// is by the unique path only — never a global name or argument pattern —
// so it cannot hit unrelated processes.
func killTestSleepers(t *testing.T, sleeperPath string) {
	t.Helper()
	for _, pidStr := range findProcCmdline(sleeperPath) {
		if pid, err := strconv.Atoi(pidStr); err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(findProcCmdline(sleeperPath)) > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
}

// findProcCmdline returns the pids of live processes whose cmdline contains
// marker (NUL separators in /proc/<pid>/cmdline are normalized to spaces).
func findProcCmdline(marker string) []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []string
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		data, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil {
			continue // process vanished mid-scan
		}
		if strings.Contains(strings.ReplaceAll(string(data), "\x00", " "), marker) {
			pids = append(pids, e.Name())
		}
	}
	return pids
}

// waitForNoProc polls up to 3s until no live process matches marker.
func waitForNoProc(t *testing.T, marker string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for len(findProcCmdline(marker)) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("processes with cmdline %q still alive after 3s: pids %v", marker, findProcCmdline(marker))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestKill_SetsidDescendantReapedOnTimeout (t-setsid): a `setsid
// <sleeper> 37 &` grandchild lives in a new session/process group and
// escapes the pgid-wide kill. The timeout path must sweep the /proc
// descendant tree before killing and SIGKILL survivors afterwards, so no
// sleeper outlives the timed-out tool call. Control: a normal completion
// leaves no sleeper behind. Sleepers run through a unique per-test
// symlink (newTestSleeper) so process matching is isolated to this run.
func TestKill_SetsidDescendantReapedOnTimeout(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	sleeper := newTestSleeper(t)
	// Best-effort sweep of this run's own leftovers only: matching is by
	// the unique sleeperPath, so foreign sleepers are never killed.
	t.Cleanup(func() { killTestSleepers(t, sleeper) })

	// Control: same shape, but the job completes normally — the setsid
	// sleeper exits on its own and nothing is left behind.
	if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:   "setsid '" + sleeper + "' 0.4 & '" + sleeper + "' 0.4",
		TimeoutMs: 30000,
	}); err != nil {
		t.Fatalf("control execute: %v", err)
	}
	waitForNoProc(t, sleeper)

	// Timed-out run: timeout 1s while the foreground 37s sleeper still
	// runs; the setsid twin must be reaped by the escapee sweep, not
	// orphaned.
	start := time.Now()
	if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:   "setsid '" + sleeper + "' 37 & '" + sleeper + "' 37",
		TimeoutMs: 1000,
	}); err != nil {
		t.Fatalf("timed-out execute: %v", err)
	}
	// A leaked escapee keeps the stdout/stderr pipe open, so cmd.Wait (and
	// this call) would block until the sleeper exits by itself (~37s). The
	// timeout path must return in seconds: 1s timeout + 3s grace + margin.
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("timed-out execute returned after %v; setsid escapee was not killed and kept the output pipe open", elapsed)
	}
	waitForNoProc(t, sleeper)
}

// TestFindProcCmdline_IgnoresForeignSleeper verifies per-test isolation: a
// sleep started from the system binary (not this test's unique symlink)
// must never be matched by the test marker, so the cleanup helpers can
// never kill or wait on a foreign sleeper.
func TestFindProcCmdline_IgnoresForeignSleeper(t *testing.T) {
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep binary not found: %v", err)
	}
	sleeper := newTestSleeper(t)

	foreign := exec.Command(sleepBin, "30")
	if err := foreign.Start(); err != nil {
		t.Fatalf("start foreign sleeper: %v", err)
	}
	foreignPID := strconv.Itoa(foreign.Process.Pid)
	t.Cleanup(func() {
		_ = foreign.Process.Kill()
		_, _ = foreign.Process.Wait()
	})

	for _, pid := range findProcCmdline(sleeper) {
		if pid == foreignPID {
			t.Fatalf("foreign sleeper pid %s matched test marker %q", foreignPID, sleeper)
		}
	}
}

// waitForBgDone polls until the background entry id is marked Done and
// returns its maxAgeTimer handle as observed under bgMu.
func waitForBgDone(t *testing.T, id string) *time.Timer {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		bgMu.Lock()
		e, ok := bgProcs[id]
		var timer *time.Timer
		terminal := false
		if ok && e.Done {
			terminal = true
			timer = e.maxAgeTimer
		}
		bgMu.Unlock()
		if terminal {
			return timer
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("background entry %s never reached Done within 5s", id)
	return nil
}

// TestBackgroundKill_MaxAgeTimerStoppedOnEarlyFinish (t-timer): a background
// job that finishes (or is killed) before maxAge must not leave its
// AfterFunc kill timer armed until maxAge.
func TestBackgroundKill_MaxAgeTimerStoppedOnEarlyFinish(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)

	// finishBackground path: job completes immediately on its own.
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:    "echo TIMER_STOP_EARLY_FINISH",
		Background: true,
	})
	if err != nil {
		t.Fatalf("background execute: %v", err)
	}
	id := parseBgID(t, mcpResultText(t, res))
	if timer := waitForBgDone(t, id); timer != nil {
		t.Fatalf("max-age timer still armed after entry %s reached Done via finishBackground (would fire a redundant kill at maxAge)", id)
	}

	// markBackgroundKilled path: job killed explicitly before maxAge.
	res, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Command:    "sleep 5",
		Background: true,
	})
	if err != nil {
		t.Fatalf("background execute: %v", err)
	}
	id = parseBgID(t, mcpResultText(t, res))

	// While running, the handle must be stored and armed (guards against a
	// vacuous nil assertion).
	bgMu.Lock()
	e, ok := bgProcs[id]
	armed := ok && !e.Done && e.maxAgeTimer != nil
	bgMu.Unlock()
	if !armed {
		t.Fatalf("live background entry %s does not hold an armed max-age timer", id)
	}

	if _, err := killBackground(id); err != nil {
		t.Fatalf("killBackground(%s): %v", id, err)
	}
	if timer := waitForBgDone(t, id); timer != nil {
		t.Fatalf("max-age timer still armed after entry %s was killed via markBackgroundKilled", id)
	}
}
