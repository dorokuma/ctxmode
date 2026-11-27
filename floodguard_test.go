package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// === Merged from floodguard_test.go ===

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

// === Merged from flood_scope_test.go ===

// ---------------------------------------------------------------------------
// rg-scope bucket: thresholds, throttle copy, block copy
// ---------------------------------------------------------------------------

// TestSearchRgScoped_FloodGuardThresholds verifies the dedicated rg-scope
// bucket: the first rgFloodOKLimit calls are OK, calls up to
// rgFloodBlockLimit are throttled (but still succeed), and the call that
// pushes total attempts past rgFloodBlockLimit is hard-blocked with the
// FloodGuard-aligned error copy.
func TestSearchRgScoped_FloodGuardThresholds(t *testing.T) {
	store := newTestStore(t)
	indexDoc(t, store, "session:s1:rg:doc1", "needle token alpha")
	sp := NewSearchPipeline(store, NewFloodGuard(time.Hour, 64))
	prefix := "session:s1:rg:"

	for i := 1; i <= rgFloodOKLimit; i++ {
		res, meta, err := sp.SearchRgScoped("needle", prefix, 20)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if meta == nil || meta.FloodStatus != "ok" {
			t.Fatalf("call %d: expected FloodStatus ok, got %+v", i, meta)
		}
		if len(res) == 0 {
			t.Fatalf("call %d: expected results within threshold", i)
		}
	}

	// Throttle window: attempts rgFloodOKLimit+1 .. rgFloodBlockLimit still
	// succeed but carry the throttle message.
	for i := rgFloodOKLimit + 1; i <= rgFloodBlockLimit; i++ {
		_, meta, err := sp.SearchRgScoped("needle", prefix, 20)
		if err != nil {
			t.Fatalf("call %d: throttled search should still succeed: %v", i, err)
		}
		if meta == nil || meta.FloodStatus != "throttled" || meta.ThrottleMsg == "" {
			t.Fatalf("call %d: expected throttle metadata, got %+v", i, meta)
		}
	}

	// Next attempt crosses the block threshold.
	_, meta, err := sp.SearchRgScoped("needle", prefix, 20)
	if err == nil {
		t.Fatal("expected rg-scoped search to be blocked after sustained abuse")
	}
	if meta == nil || meta.FloodStatus != "blocked" {
		t.Fatalf("expected FloodStatus blocked, got %+v", meta)
	}
	if !strings.Contains(err.Error(), "too many requests in a short time. Wait a moment and retry") {
		t.Fatalf("blocked copy must align with the FloodGuard wording, got: %s", err.Error())
	}
}

// TestSearchRgScopeBucket_IndependentFromGlobalBucket verifies that
// exhausting the rg bucket does not touch the global search bucket (separate
// keys/ring buffers), and vice versa.
func TestSearchRgScopeBucket_IndependentFromGlobalBucket(t *testing.T) {
	store := newTestStore(t)
	indexDoc(t, store, "session:s1:rg:doc1", "needle token alpha")
	sp := NewSearchPipeline(store, NewFloodGuard(time.Hour, 64))
	prefix := "session:s1:rg:"

	// Exhaust the rg bucket (ok + throttle + block).
	for i := 0; i < rgFloodBlockLimit+1; i++ {
		sp.SearchRgScoped("needle", prefix, 20)
	}

	// Global search must still be allowed with full status.
	_, meta, err := sp.Search("needle", 20)
	if err != nil {
		t.Fatalf("global search after rg-bucket exhaustion: %v", err)
	}
	if meta.FloodStatus != "ok" {
		t.Fatalf("global search must not share the rg bucket, got %+v", meta)
	}

	// The rg bucket stays blocked while the global bucket is fresh.
	_, meta, err = sp.SearchRgScoped("needle", prefix, 20)
	if err == nil || meta == nil || meta.FloodStatus != "blocked" {
		t.Fatalf("rg bucket should remain blocked, got err=%v meta=%+v", err, meta)
	}
}

// TestSearchBatchScoped_StillBypassesFloodGuard pins the historical bypass:
// batch-scoped searches (ctx_run action=batch query_scope=batch) consume no
// quota and keep working even with both search buckets exhausted.
func TestSearchBatchScoped_StillBypassesFloodGuard(t *testing.T) {
	store := newTestStore(t)
	indexDoc(t, store, "batch:run1/doc", "zzbatchrun output body")
	indexDoc(t, store, "session:s1:rg:doc1", "needle token alpha")
	sp := NewSearchPipeline(store, NewFloodGuard(time.Hour, 64))
	prefix := "session:s1:rg:"

	// Exhaust the global bucket directly (block triggers at total >= 9).
	for i := 0; i < 12; i++ {
		sp.Search("needle", 5)
	}
	// Exhaust the rg bucket.
	for i := 0; i < rgFloodBlockLimit+1; i++ {
		sp.SearchRgScoped("needle", prefix, 20)
	}

	res, meta, err := sp.SearchBatchScoped("zzbatchrun", 5)
	if err != nil {
		t.Fatalf("batch-scoped search must bypass flood guards: %v", err)
	}
	if meta.FloodStatus != "ok" {
		t.Fatalf("batch-scoped search must report ok, got %+v", meta)
	}
	if len(res) == 0 {
		t.Fatal("batch-scoped search should still find its documents")
	}
}

// TestGlobalSearchThresholds_Unchanged pins the pre-existing global-bucket
// semantics: 4 OK calls, then throttling, then a hard block whose copy keeps
// the ctx_run action=batch hint.
func TestGlobalSearchThresholds_Unchanged(t *testing.T) {
	store := newTestStore(t)
	indexDoc(t, store, "doc1", "needle token alpha")
	sp := NewSearchPipeline(store, NewFloodGuard(time.Hour, 64))

	for i := 1; i <= 4; i++ {
		_, meta, err := sp.Search("needle", 20)
		if err != nil || meta.FloodStatus != "ok" {
			t.Fatalf("call %d: expected ok, got err=%v meta=%+v", i, err, meta)
		}
	}
	_, meta, err := sp.Search("needle", 20)
	if err != nil || meta.FloodStatus != "throttled" || meta.ThrottleMsg == "" {
		t.Fatalf("call 5: expected throttled, got err=%v meta=%+v", err, meta)
	}
	for i := 6; i <= 9; i++ {
		if _, _, err := sp.Search("needle", 20); err != nil {
			t.Fatalf("call %d: throttled search should still succeed: %v", i, err)
		}
	}
	_, meta, err = sp.Search("needle", 20)
	if err == nil || meta == nil || meta.FloodStatus != "blocked" {
		t.Fatalf("call 10: expected blocked, got err=%v meta=%+v", err, meta)
	}
	if !strings.Contains(err.Error(), "ctx_run action=batch") {
		t.Fatalf("global blocked copy must keep the batch hint, got: %s", err.Error())
	}
}

// TestSearchRgScoped_NilRgGuardBehavesAsBefore verifies the disabled path: a
// zero-value pipeline (rgFloodGuard unset) never rate-limits rg-scoped
// searches — matching pre-guard behavior even far beyond the block threshold.
func TestSearchRgScoped_NilRgGuardBehavesAsBefore(t *testing.T) {
	store := newTestStore(t)
	indexDoc(t, store, "session:s1:rg:doc1", "needle token alpha")
	sp := &SearchPipeline{store: store} // zero value: rg guard disabled

	for i := 0; i < rgFloodBlockLimit+5; i++ {
		_, meta, err := sp.SearchRgScoped("needle", "session:s1:rg:", 20)
		if err != nil {
			t.Fatalf("call %d: nil rg guard must not limit: %v", i, err)
		}
		if meta.FloodStatus != "ok" {
			t.Fatalf("call %d: expected ok, got %+v", i, meta)
		}
	}
}

// ---------------------------------------------------------------------------
// fetch bucket
// ---------------------------------------------------------------------------

// TestToolFetchAndIndex_FloodGuardThresholds drives toolFetchAndIndex against
// a local fake-transport server (public-looking IP host so validateURL passes
// without DNS — same pattern as fetch_test.go) and verifies:
// fetchFloodOKLimit full-speed calls, then throttled-but-successful calls
// with the volume warning, then a hard block with the FloodGuard-aligned copy.
func TestToolFetchAndIndex_FloodGuardThresholds(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("fetch flood guard body"))
	})
	s := newFetchTestServer(t, handler)

	call := func(i int) (*mcp.CallToolResult, error) {
		ttl0 := 0 // skip cache: every call is a real fetch
		res, _, err := s.toolFetchAndIndex(context.Background(), nil, fetchArgs{
			URL:    fmt.Sprintf("http://1.1.1.1/flood-%d", i),
			Source: "flood",
			TTLMs:  &ttl0,
		})
		return res, err
	}

	for i := 1; i <= fetchFloodOKLimit; i++ {
		res, err := call(i)
		if err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
		if text := contentText(res); strings.Contains(text, "Fetch volume is high") {
			t.Fatalf("call %d: unexpected throttle warning: %s", i, text)
		}
	}

	// Throttled window: calls still succeed but carry the warning.
	for i := fetchFloodOKLimit + 1; i <= fetchFloodBlockLimit; i++ {
		res, err := call(i)
		if err != nil {
			t.Fatalf("call %d: throttled fetch should still succeed: %v", i, err)
		}
		if text := contentText(res); !strings.Contains(text, "Fetch volume is high") {
			t.Fatalf("call %d: expected throttle warning, got: %s", i, text)
		}
	}

	// Next attempt crosses the block threshold.
	_, err := call(fetchFloodBlockLimit + 1)
	if err == nil {
		t.Fatal("expected fetch to be blocked after sustained abuse")
	}
	if !strings.Contains(err.Error(), "too many requests in a short time. Wait a moment and retry") {
		t.Fatalf("blocked copy must align with the FloodGuard wording, got: %s", err.Error())
	}
}

// TestToolFetchAndIndex_FetchGuardDisabled verifies the switch: with
// fetchFloodGuardEnabled=false the guard is fully bypassed, matching
// pre-guard behavior even beyond the block threshold.
func TestToolFetchAndIndex_FetchGuardDisabled(t *testing.T) {
	fetchFloodGuardEnabled = false
	t.Cleanup(func() { fetchFloodGuardEnabled = true })

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("fetch flood guard body"))
	})
	s := newFetchTestServer(t, handler)

	for i := 1; i <= fetchFloodBlockLimit+3; i++ {
		ttl0 := 0
		res, _, err := s.toolFetchAndIndex(context.Background(), nil, fetchArgs{
			URL:    fmt.Sprintf("http://1.1.1.1/disabled-%d", i),
			Source: "flood",
			TTLMs:  &ttl0,
		})
		if err != nil {
			t.Fatalf("call %d: disabled guard must not limit: %v", i, err)
		}
		if text := contentText(res); strings.Contains(text, "Fetch volume is high") {
			t.Fatalf("call %d: unexpected throttle warning: %s", i, text)
		}
	}
}

// TestFetchBucket_IndependentFromSearchBucket verifies that the fetch bucket
// is keyed separately: exhausting fetch quota does not consume search quota.
func TestFetchBucket_IndependentFromSearchBucket(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("fetch flood guard body"))
	})
	s := newFetchTestServer(t, handler)
	s.searchPipeline = NewSearchPipeline(s.store, NewFloodGuard(time.Hour, 64))

	for i := 1; i <= fetchFloodBlockLimit+1; i++ {
		ttl0 := 0
		_, _, err := s.toolFetchAndIndex(context.Background(), nil, fetchArgs{
			URL:    fmt.Sprintf("http://1.1.1.1/indep-%d", i),
			Source: "flood",
			TTLMs:  &ttl0,
		})
		if err != nil && i <= fetchFloodBlockLimit {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}

	_, meta, err := s.searchPipeline.Search("anything", 5)
	if err != nil || meta.FloodStatus != "ok" {
		t.Fatalf("search must not share the fetch bucket: err=%v meta=%+v", err, meta)
	}
}
