package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
