// Tests for reap hardening of the kill paths: the setsid escapee sweep on the
// ctx-cancel kill paths (runCmd + batch executeCommand) and the conservative
// killBackground fallback for entries with starttime==0.

package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// reapSleeperCleanup kills any leftover "sleep 120" escapees from earlier or
// failed runs. The [p] character class keeps the pattern from matching this
// pkill's own command line (a literal "sleep 120" pattern would self-match
// pkill's own argv under -f).
func reapSleeperCleanup() {
	_ = exec.Command("pkill", "-f", "slee[p] 120").Run()
}

// waitBackgroundDone polls until the background entry id is marked Done.
func waitBackgroundDone(t *testing.T, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		bgMu.Lock()
		e, ok := bgProcs[id]
		done := ok && e.Done
		bgMu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("background entry %s never reached Done within 5s", id)
}

// TestReap_BatchSetsidEscapeeKilledOnCtxTimeout (t-reap-batch): red-team
// repro. A batch command `setsid sleep 120 & sleep 120` with timeout_ms=2000
// hits the ctx.Done kill path in executeCommand. The setsid escapee lives in
// a new session and escapes the process-group kill; without the escapee sweep
// it keeps the output pipe open, cmd.Wait never returns, and the batch call
// hangs until the sleeper exits by itself (observed: 45s+). The call must
// return promptly and leave no sleeper behind.
func TestReap_BatchSetsidEscapeeKilledOnCtxTimeout(t *testing.T) {
	srv := newTestServer(t)
	srv.workdirs = []string{t.TempDir()}
	reapSleeperCleanup()
	t.Cleanup(reapSleeperCleanup)

	start := time.Now()
	res, _, err := srv.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands:  []batchCommand{{Label: "setsid", Command: "setsid sleep 120 & sleep 120"}},
		TimeoutMs: 2000,
	})
	if err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	var resp batchResponse
	if err := json.Unmarshal([]byte(contentText(res)), &resp); err != nil {
		t.Fatalf("unmarshal batch response: %v", err)
	}
	if len(resp.Commands) != 1 || resp.Commands[0].Success {
		t.Fatalf("expected one cancelled (failed) command result, got %+v", resp.Commands)
	}
	// 2s timeout + 3s SIGTERM grace + drain margin. A leaked escapee holds
	// the output pipe, so cmd.Wait — and this call — blocks until sleep 120
	// exits by itself.
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("batch call returned after %v; setsid escapee kept the output pipe open", elapsed)
	}
	waitForNoProc(t, "sleep 120")
}

// TestReap_ExecuteSetsidEscapeeKilledOnCtxCancel (t-reap-execute): the
// ctx.Done kill path in runCmd must run the same escapee sweep as the timeout
// path, so a `setsid sleep 120 & sleep 120` job cancelled mid-flight leaves
// no escapee behind and returns promptly instead of hanging on the pipe.
func TestReap_ExecuteSetsidEscapeeKilledOnCtxCancel(t *testing.T) {
	s := testServerWithWorkdir(t, t.TempDir())
	reapSleeperCleanup()
	t.Cleanup(reapSleeperCleanup)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel once the shell has forked the setsid escapee (it forks within a
	// few ms of start; 300ms makes that deterministic without slowing the run).
	_ = time.AfterFunc(300*time.Millisecond, cancel)
	defer cancel()

	start := time.Now()
	if _, _, err := s.toolExecute(ctx, nil, executeArgs{
		Command:   "setsid sleep 120 & sleep 120",
		TimeoutMs: 60000,
	}); err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("cancelled execute returned after %v; setsid escapee kept the output pipe open", elapsed)
	}
	waitForNoProc(t, "sleep 120")
}

// TestReap_KillBackgroundStarttimeZeroFallback (t-reap-bg): an entry whose
// proc starttime could not be captured (starttime==0) must still be killable.
// killBackground falls back to a conservative process-group SIGKILL (only
// when /proc/<pid> still owns its own process group) and marks the entry
// Done, so the maxAge timer and the 30s reaper can retire the slot instead of
// pinning one of the 16 background slots forever.
func TestReap_KillBackgroundStarttimeZeroFallback(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 120 & sleep 120")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pgid := cmd.Process.Pid
	t.Cleanup(func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	entry, err := registerBackground(cmd, "", "killBackground starttime=0 fallback test", nil, "", nil, nil)
	if err != nil {
		t.Fatalf("registerBackground: %v", err)
	}
	// Simulate the failure mode: registration could not read proc starttime.
	bgMu.Lock()
	entry.starttime = 0
	bgMu.Unlock()

	msg, err := killBackground(entry.ID)
	if err != nil {
		t.Fatalf("killBackground with starttime==0: unexpected error: %v (msg %q)", err, msg)
	}
	if !strings.Contains(msg, "starttime unknown") {
		t.Fatalf("expected conservative fallback group-kill message, got %q", msg)
	}
	// The entry must be marked Done so maxAge/reaper paths can retire it.
	waitBackgroundDone(t, entry.ID)

	// The group SIGKILL must have taken down the whole group: cmd.Wait
	// (blocked on the direct child and the output pipes) must return.
	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("process group %d survived the fallback group kill", pgid)
	}
	waitForNoProc(t, "sleep 120")
}

// TestReap_LimitedBufferConcurrentReadWrite (t-reap-buf): after a reap path
// gives up on cmd.Wait (reapWaitBound), the os/exec pipe-copy goroutine may
// still Write into the limitedBuffer while the main flow reads String() and
// the truncation flag. Without the internal mutex that is a concurrent
// bytes.Buffer read/write data race — run with -race to surface it. Without
// -race the test still asserts the keep-newest policy holds under
// concurrency.
func TestReap_LimitedBufferConcurrentReadWrite(t *testing.T) {
	var lb limitedBuffer
	lb.limit = 64
	payload := []byte(strings.Repeat("ab", 32)) // exactly the limit

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := lb.Write(payload); err != nil {
				t.Errorf("limitedBuffer.Write: %v", err)
				return
			}
		}
	}()

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if out := lb.String(); len(out) > lb.limit {
			t.Fatalf("String() returned %d bytes, limit is %d", len(out), lb.limit)
		}
		_ = lb.truncatedFlag()
	}
	close(stop)
	wg.Wait()

	// Every write is exactly limit-sized: the newest payload must survive
	// intact and the buffer must report truncation (older bytes dropped).
	if got := lb.String(); got != string(payload) {
		t.Fatalf("keep-newest policy broken: got %d bytes, want %d identical", len(got), len(payload))
	}
	if !lb.truncatedFlag() {
		t.Fatal("expected truncated=true after overflow writes")
	}
}
