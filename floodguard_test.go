package main

import (
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Ring buffer tests
// ---------------------------------------------------------------------------

// TestFloodGuard_RingBuffer_CountWithinWindow verifies that WindowCount
// correctly reports the number of entries within the sliding window after
// a series of rapid Allow() calls.
func TestFloodGuard_RingBuffer_CountWithinWindow(t *testing.T) {
	fg := NewFloodGuard(10*time.Second, 64)

	// First 4 requests (count 0→1→2→3) are OK and appended.
	for i := 0; i < 4; i++ {
		fg.Allow()
	}

	if n := fg.WindowCount(); n != 4 {
		t.Fatalf("WindowCount: expected 4, got %d", n)
	}
}

// TestFloodGuard_RingBuffer_Expiration verifies that entries are pruned
// after the window duration elapses and new requests are OK again.
func TestFloodGuard_RingBuffer_Expiration(t *testing.T) {
	fg := NewFloodGuard(50*time.Millisecond, 64)

	// Fill window with 4 OK requests.
	for i := 0; i < 4; i++ {
		fg.Allow()
	}
	if n := fg.WindowCount(); n != 4 {
		t.Fatalf("before expire: expected 4, got %d", n)
	}

	// Wait for entries to age out.
	time.Sleep(100 * time.Millisecond)

	// Window should be empty after expiration.
	if n := fg.WindowCount(); n != 0 {
		t.Fatalf("after expire: expected 0, got %d", n)
	}

	// New requests should be OK again.
	for i := 0; i < 4; i++ {
		if s := fg.Allow(); s != StatusOK {
			t.Fatalf("after expire request %d: expected OK, got %v", i+1, s)
		}
	}
}

// TestFloodGuard_RingBuffer_CapacityCap verifies that the ring buffer
// correctly handles wrap-around when capacity is reached.  With the
// dual-counter design, all attempts (including blocked) are appended to
// attemptsBuf, so wrap-around is exercised by sending more requests than
// the capacity (64).  The test also verifies that all three statuses
// (OK, Throttled, Blocked) are reachable.
func TestFloodGuard_RingBuffer_CapacityCap(t *testing.T) {
	capacity := 64
	fg := NewFloodGuard(1*time.Hour, capacity)

	// Send enough requests to wrap the attemptsBuf ring buffer (capacity=64).
	// First 4 are OK, next 5 are Throttled, rest are Blocked.
	// All 70 go into attemptsBuf, wrapping at 64.
	var sawOK, sawThrottled, sawBlocked bool
	for i := 0; i < 70; i++ {
		s := fg.Allow()
		switch s {
		case StatusOK:
			sawOK = true
		case StatusThrottled:
			sawThrottled = true
		case StatusBlocked:
			sawBlocked = true
		}
	}

	if !sawOK {
		t.Fatal("never saw StatusOK")
	}
	if !sawThrottled {
		t.Fatal("never saw StatusThrottled")
	}
	if !sawBlocked {
		t.Fatal("never saw StatusBlocked — dual-counter block should be reachable")
	}

	// okBuf should have at most 4 entries.
	if n := fg.WindowCount(); n > 4 {
		t.Fatalf("WindowCount: expected ≤ 4, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// Rate-limit threshold tests
// ---------------------------------------------------------------------------

// TestFloodGuard_Thresholds_OK verifies that the first 4 requests within
// a fresh window receive StatusOK.  With count-before-append, the
// sequence is:
//
//	call 1: count=0 → OK, append → size=1
//	call 2: count=1 → OK, append → size=2
//	call 3: count=2 → OK, append → size=3
//	call 4: count=3 → OK, append → size=4
//
// The 5th call sees count=4 → Throttled.
func TestFloodGuard_Thresholds_OK(t *testing.T) {
	fg := NewFloodGuard(10*time.Second, 64)

	for i := 0; i < 4; i++ {
		if s := fg.Allow(); s != StatusOK {
			t.Fatalf("request %d: expected OK, got %v", i+1, s)
		}
	}
}

// TestFloodGuard_Thresholds_Throttled verifies that after 4 OK requests,
// subsequent requests are throttled — until the hard-block threshold (total≥9)
// is reached.
func TestFloodGuard_Thresholds_Throttled(t *testing.T) {
	fg := NewFloodGuard(10*time.Second, 64)

	// Fill to 4 OK (total=4, okCount=4).
	for i := 0; i < 4; i++ {
		fg.Allow()
	}

	// Requests 5-9 should be Throttled (okCount=4 triggers throttle,
	// total=5..9 stays below block threshold).
	for i := 0; i < 5; i++ {
		if s := fg.Allow(); s != StatusThrottled {
			t.Fatalf("after OK request %d: expected Throttled, got %v", i+5, s)
		}
	}

	// Request 10 triggers Blocked (total reaches 9).
	if s := fg.Allow(); s != StatusBlocked {
		t.Fatalf("request 10: expected Blocked (total≥9), got %v", s)
	}

	// Window count must not have grown beyond 4.
	if n := fg.WindowCount(); n != 4 {
		t.Fatalf("WindowCount: expected 4, got %d", n)
	}
}

// TestFloodGuard_Thresholds_Blocked verifies that the Blocked threshold
// (total attempts ≥ 9) is reachable with the dual-counter design.
// Sustained rapid requests accumulate in attemptsBuf and eventually
// trigger a hard block after the 9th attempt.
func TestFloodGuard_Thresholds_Blocked(t *testing.T) {
	fg := NewFloodGuard(10*time.Second, 64)

	// The first 4 requests are OK.
	for i := 0; i < 4; i++ {
		if s := fg.Allow(); s != StatusOK {
			t.Fatalf("request %d: expected OK, got %v", i+1, s)
		}
	}

	// Requests 5-9 are Throttled (okCount=4 ≥ 4, total=5..9 < 9).
	for i := 0; i < 5; i++ {
		if s := fg.Allow(); s != StatusThrottled {
			t.Fatalf("request %d: expected Throttled, got %v", i+5, s)
		}
	}

	// Request 10: total=9 → StatusBlocked (hard block triggered).
	if s := fg.Allow(); s != StatusBlocked {
		t.Fatalf("request 10: expected Blocked (total≥9), got %v", s)
	}

	// Further requests stay Blocked as total continues to grow.
	for i := 0; i < 5; i++ {
		if s := fg.Allow(); s != StatusBlocked {
			t.Fatalf("request %d: expected Blocked, got %v", i+11, s)
		}
	}

	// OK window count must still be 4 (blocked/throttled don't add to okBuf).
	if n := fg.WindowCount(); n != 4 {
		t.Fatalf("WindowCount: expected 4, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// S12 behaviour: rejected requests do not consume window slots
// ---------------------------------------------------------------------------

// TestFloodGuard_S12_RejectedNotCounted is the core S12 test.
// Throttled/Blocked requests must NOT increase the OK window count (okBuf).
// With dual counters, rejected attempts go into attemptsBuf (for block
// detection) but never into okBuf, so WindowCount stays capped at 4.
func TestFloodGuard_S12_RejectedNotCounted(t *testing.T) {
	fg := NewFloodGuard(10*time.Second, 64)

	// 4 OK requests fill okBuf to count=4.
	for i := 0; i < 4; i++ {
		fg.Allow()
	}
	if n := fg.WindowCount(); n != 4 {
		t.Fatalf("after 4 OK: expected 4, got %d", n)
	}

	// Send 50 requests.  With dual counters requests 5-9 are Throttled,
	// request 10 onward are Blocked.  The key invariant: WindowCount
	// (okBuf size) must never exceed 4.
	var sawBlocked bool
	for i := 0; i < 50; i++ {
		s := fg.Allow()
		if s == StatusBlocked {
			sawBlocked = true
		}
	}
	if !sawBlocked {
		t.Fatal("expected to see StatusBlocked after sustained abuse, never saw it")
	}
	if n := fg.WindowCount(); n != 4 {
		t.Fatalf("after 50 requests: window grew to %d (expected 4)", n)
	}
}

// TestFloodGuard_S12_RecoveryAfterExpiry verifies that legitimate
// requests can pass after the window expires, even if the previous
// window was saturated with throttled requests.
func TestFloodGuard_S12_RecoveryAfterExpiry(t *testing.T) {
	fg := NewFloodGuard(50*time.Millisecond, 64)

	// Saturate the window.
	for i := 0; i < 4; i++ {
		fg.Allow()
	}

	// Verify we're throttled.
	if s := fg.Allow(); s != StatusThrottled {
		t.Fatalf("expected Throttled, got %v", s)
	}

	// Wait for window to expire.
	time.Sleep(100 * time.Millisecond)

	// New requests should be OK again (window is empty).
	if s := fg.Allow(); s != StatusOK {
		t.Fatalf("after expiry: expected OK, got %v", s)
	}
}

// TestFloodGuard_S12_ThrottledDoesNotBlockRecovery verifies that a burst
// of throttled requests does not extend the window.  The window only
// grows when OK requests are recorded.
// TestFloodGuard_S12_ThrottledDoesNotBlockRecovery verifies that a burst
// of throttled requests does not extend the window.  The window only
// grows when OK requests are recorded.
func TestFloodGuard_S12_ThrottledDoesNotBlockRecovery(t *testing.T) {
	fg := NewFloodGuard(10*time.Second, 64)

	// Fill window with 4 OK requests to hit the throttle threshold.
	for i := 0; i < 4; i++ {
		fg.Allow()
	}
	if n := fg.WindowCount(); n != 4 {
		t.Fatalf("after 4 OK: expected 4, got %d", n)
	}

	// Requests 5-9 should be Throttled (okCount=4 triggers throttle).
	for i := 0; i < 5; i++ {
		s := fg.Allow()
		if s != StatusThrottled {
			t.Fatalf("request %d: expected Throttled, got %v", i+5, s)
		}
	}

	// Window count must still be 4 — throttled requests don't consume OK slots.
	if n := fg.WindowCount(); n != 4 {
		t.Fatalf("after throttled bursts: expected 4, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// Recovery after Blocked expiry
// ---------------------------------------------------------------------------

// TestFloodGuard_S12_BlockRecoveryAfterExpiry verifies that a caller
// blocked after sustained abuse can recover once the window expires.
// Blocked requests are recorded in attemptsBuf (for block detection) but
// not in okBuf, so when the window rolls over both buffers drain.
func TestFloodGuard_S12_BlockRecoveryAfterExpiry(t *testing.T) {
	fg := NewFloodGuard(50*time.Millisecond, 64)

	// Send 15 requests to trigger StatusBlocked (total reaches 9 at request 10).
	for i := 0; i < 15; i++ {
		fg.Allow()
	}

	// Verify we're blocked.
	if s := fg.Allow(); s != StatusBlocked {
		t.Fatalf("expected Blocked after 15 requests, got %v", s)
	}

	// Sleep for window duration + buffer to let entries age out.
	time.Sleep(100 * time.Millisecond)

	// After expiry, requests should be OK again (both buffers are drained).
	if s := fg.Allow(); s != StatusOK {
		t.Fatalf("after expiry: expected OK, got %v", s)
	}
}

// ---------------------------------------------------------------------------
// Concurrency safety
// ---------------------------------------------------------------------------

// TestFloodGuard_Concurrency runs Allow() from many goroutines
// concurrently and checks for data races with -race.
func TestFloodGuard_Concurrency(t *testing.T) {
	fg := NewFloodGuard(10*time.Second, 64)
	var wg sync.WaitGroup

	n := 100
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fg.Allow()
		}()
	}
	wg.Wait()

	// With dual counters, at most 4 OK entries can be recorded (okCount 0→1→2→3).
	// The mutex serializes access, so exactly 4 goroutines see okCount<4
	// and get OK; the rest get Throttled or Blocked.
	if wc := fg.WindowCount(); wc > 4 {
		t.Fatalf("WindowCount: expected ≤ 4, got %d", wc)
	}
}

// TestFloodGuard_ConcurrentWindowCount verifies WindowCount is safe
// to call concurrently with Allow.
func TestFloodGuard_ConcurrentWindowCount(t *testing.T) {
	fg := NewFloodGuard(10*time.Second, 64)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fg.Allow()
		}()
	}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fg.WindowCount()
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Initial state / boundary
// ---------------------------------------------------------------------------

func TestFloodGuard_InitialWindowCount(t *testing.T) {
	fg := NewFloodGuard(1*time.Second, 64)
	if n := fg.WindowCount(); n != 0 {
		t.Fatalf("initial WindowCount: expected 0, got %d", n)
	}
}

func TestFloodGuard_MinCapacity(t *testing.T) {
	fg := NewFloodGuard(1*time.Second, 10) // below min 64
	if fg.capacity != 64 {
		t.Fatalf("expected capacity 64, got %d", fg.capacity)
	}
}
