package main

import (
	"math"
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

func TestSearch_OneSideErrorNotReportedAsNoHits(t *testing.T) {
	store := newTestStore(t)
	indexDoc(t, store, "p", "hello world unique-token-xyz")
	if _, err := store.db.Exec(`DROP TABLE documents_fts`); err != nil {
		t.Fatalf("drop porter: %v", err)
	}
	_, err := store.Search("no-such-token-zzzz-absent", 5)
	if err == nil {
		t.Fatal("expected error when porter is down and trigram has no hits")
	}
}

// ---------- Proximity reranking ----------

// TestProximityBoostRerank table-covers the <b>-density boost and the rerank
// pass: higher marker density moves results up, but only enough to overtake a
// better original rank when the density gap is large (base score = inverse
// original rank).
func TestProximityBoostRerank(t *testing.T) {
	t.Run("boost", func(t *testing.T) {
		tests := []struct {
			name    string
			snippet string
			want    float64
		}{
			{name: "empty", snippet: "", want: 0},
			{name: "no markers", snippet: "plain text", want: 0},
			{name: "single marker density", snippet: "<b>x</b>", want: 12.5}, // 1*100/8 runes
			// 2 markers over 17 runes = 200/17
			{name: "two markers density", snippet: "<b>a</b> <b>b</b>", want: 200.0 / 17.0},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := proximityBoost(tt.snippet)
				if math.Abs(got-tt.want) > 1e-9 {
					t.Errorf("proximityBoost(%q) = %v, want %v", tt.snippet, got, tt.want)
				}
			})
		}
	})

	t.Run("rerank", func(t *testing.T) {
		tests := []struct {
			name  string
			input []SearchResult
			want  []string
		}{
			{
				name:  "empty input",
				input: nil,
				want:  nil,
			},
			{
				name: "single result is returned unchanged",
				input: []SearchResult{
					{Path: "a", Snippet: "no markers"},
				},
				want: []string{"a"},
			},
			{
				name: "higher density overtakes better original rank",
				input: []SearchResult{
					{Path: "top-rank-sparse", Snippet: "x x x x x x x x x x <b>"}, // 1 marker / 21 runes
					{Path: "second-rank-dense", Snippet: "<b>a"},                  // 1 marker / 4 runes
				},
				want: []string{"second-rank-dense", "top-rank-sparse"},
			},
			{
				name: "modest density does not overturn original rank",
				input: []SearchResult{
					{Path: "top-rank", Snippet: "<b>a</b>"},                  // 12.5
					{Path: "second-rank", Snippet: "<b>a</b> <b>b</b> tail"}, // 2*100/21 < 12.5
				},
				want: []string{"top-rank", "second-rank"},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := proximityRerank(tt.input)
				paths := make([]string, len(got))
				for i, r := range got {
					paths[i] = r.Path
				}
				if len(paths) != len(tt.want) {
					t.Fatalf("got %v, want %v", paths, tt.want)
				}
				for i := range tt.want {
					if paths[i] != tt.want[i] {
						t.Fatalf("order = %v, want %v", paths, tt.want)
					}
				}
			})
		}
	})
}
