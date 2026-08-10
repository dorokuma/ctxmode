package main

import (
	"strings"
	"testing"
	"time"
)

// ============================================================================
// search 提示文案：必须指向现存工具 ctx_run action=batch，而非已下线的 ctx_batch_execute
// ============================================================================

func TestSearchBlockedMessage_UsesCtxRunBatch(t *testing.T) {
	store := newTestStore(t)
	fg := NewFloodGuard(time.Hour, 64)
	// 9 attempts in window → the 10th Allow() returns StatusBlocked.
	for i := 0; i < 9; i++ {
		fg.Allow()
	}
	sp := NewSearchPipeline(store, fg)

	_, _, err := sp.Search("anything", 5)
	if err == nil {
		t.Fatal("expected blocked error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ctx_run action=batch") {
		t.Fatalf("expected ctx_run action=batch hint, got: %s", msg)
	}
	if strings.Contains(msg, "ctx_batch_execute") {
		t.Fatalf("must not reference removed ctx_batch_execute tool: %s", msg)
	}
}

func TestSearchThrottleMessage_UsesCtxRunBatch(t *testing.T) {
	store := newTestStore(t)
	indexDoc(t, store, "session:a", "hello world")
	fg := NewFloodGuard(time.Hour, 64)
	// 4 OK calls → the 5th Allow() returns StatusThrottled (search still proceeds).
	for i := 0; i < 4; i++ {
		fg.Allow()
	}
	sp := NewSearchPipeline(store, fg)

	_, meta, err := sp.Search("zzz_no_match_12345", 5)
	if err != nil {
		t.Fatalf("throttled search should still succeed: %v", err)
	}
	if meta == nil || meta.ThrottleMsg == "" {
		t.Fatal("expected throttle message")
	}
	if !strings.Contains(meta.ThrottleMsg, "ctx_run action=batch") {
		t.Fatalf("expected ctx_run action=batch hint, got: %s", meta.ThrottleMsg)
	}
	if strings.Contains(meta.ThrottleMsg, "ctx_batch_execute") {
		t.Fatalf("must not reference removed ctx_batch_execute tool: %s", meta.ThrottleMsg)
	}
}
