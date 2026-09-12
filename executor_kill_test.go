package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

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

// TestKill_SetsidDescendantReapedOnTimeout (t-setsid): a `setsid sleep 37 &`
// grandchild lives in a new session/process group and escapes the pgid-wide
// kill. The timeout path must sweep the /proc descendant tree before killing
// and SIGKILL survivors afterwards, so no sleeper outlives the timed-out tool
// call. Control: a normal completion leaves no sleeper behind.
func TestKill_SetsidDescendantReapedOnTimeout(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	cleanup := func() {
		// Best-effort sweep so neither this run nor a failed run leaks sleepers.
		_ = exec.Command("pkill", "-f", "sleep 37").Run()
	}
	cleanup()
	defer cleanup()

	// Control: same shape, but the job completes normally — the setsid
	// sleeper exits on its own and nothing is left behind.
	if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:   "setsid sleep 0.4 & sleep 0.4",
		TimeoutMs: 30000,
	}); err != nil {
		t.Fatalf("control execute: %v", err)
	}
	waitForNoProc(t, "sleep 0.4")

	// Timed-out run: timeout 1s while the foreground sleep 37 still runs; the
	// setsid sleep 37 twin must be reaped by the escapee sweep, not orphaned.
	start := time.Now()
	if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:   "setsid sleep 37 & sleep 37",
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
	waitForNoProc(t, "sleep 37")
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
