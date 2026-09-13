package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------- RRF (Reciprocal Rank Fusion) ----------

// rrfMerge merges two ranked result lists using RRF.
// k is set to 60 as recommended in the literature.
func rrfMerge(porter, trigram []SearchResult, limit int) []SearchResult {
	type rrfEntry struct {
		path    string
		snippet string
		score   float64
	}

	const k = 60.0
	entries := make(map[string]*rrfEntry)

	for i, r := range porter {
		rank := i + 1
		entries[r.Path] = &rrfEntry{
			path:    r.Path,
			snippet: r.Snippet,
			score:   1.0 / (k + float64(rank)),
		}
	}

	for i, r := range trigram {
		rank := i + 1
		rr := 1.0 / (k + float64(rank))
		if entry, ok := entries[r.Path]; ok {
			entry.score += rr
			// Keep the porter snippet (prefer porter for readability).
		} else {
			entries[r.Path] = &rrfEntry{
				path:    r.Path,
				snippet: r.Snippet,
				score:   rr,
			}
		}
	}

	if len(entries) == 0 {
		return nil
	}

	// Convert to slice and sort descending by score.
	entryList := make([]*rrfEntry, 0, len(entries))
	for _, e := range entries {
		entryList = append(entryList, e)
	}

	sort.Slice(entryList, func(i, j int) bool {
		return entryList[i].score > entryList[j].score
	})

	if len(entryList) > limit {
		entryList = entryList[:limit]
	}

	results := make([]SearchResult, len(entryList))
	for i, e := range entryList {
		results[i] = SearchResult{Path: e.path, Snippet: e.snippet}
	}
	return results
}

// ---------- Proximity reranking ----------

// proximityBoost scores a snippet by the density of <b> tags, which serves
// as a proxy for term proximity—more concentrated match markers means the
// query terms appear close together.
func proximityBoost(snippet string) float64 {
	bCount := strings.Count(snippet, "<b>")
	if bCount == 0 {
		return 0
	}
	// Density: <b> count per 100 chars of snippet text.
	textLen := utf8.RuneCountInString(snippet)
	if textLen == 0 {
		return 0
	}
	return float64(bCount*100) / float64(textLen)
}

// proximityRerank reorders results so that results with closer term
// matches (higher <b> density) are ranked higher. It is only applied
// for multi-word queries where proximity makes sense.
func proximityRerank(results []SearchResult) []SearchResult {
	if len(results) <= 1 {
		return results
	}

	type scored struct {
		result SearchResult
		score  float64
	}

	scoredList := make([]scored, len(results))
	for i, r := range results {
		boost := proximityBoost(r.Snippet)
		// Base score = inverse of original rank + proximity boost
		base := float64(len(results) - i) // higher = better original rank
		scoredList[i] = scored{r, base + boost}
	}

	sort.Slice(scoredList, func(i, j int) bool {
		return scoredList[i].score > scoredList[j].score
	})

	sorted := make([]SearchResult, len(results))
	for i, s := range scoredList {
		sorted[i] = s.result
	}
	return sorted
}

// ---------- SearchMeta ----------

// SearchMeta contains metadata about a search operation, including
// flood status, correction info, and timing.
type SearchMeta struct {
	FloodStatus string `json:"flood_status,omitempty"`
	ThrottleMsg string `json:"throttle_msg,omitempty"`
	Corrected   bool   `json:"corrected,omitempty"`
	TimeMs      int64  `json:"time_ms"`
	TotalHits   int    `json:"total_hits"`
}

// ---------- SearchPipeline ----------

// Flood-guard modes for the shared search implementation. Each externally
// reachable path uses its own bucket so that a compromised agent spamming
// one path cannot exhaust another path's quota:
//
//	floodNone   — internal/batch-scoped queries: no guard. Batch queries are
//	              not agent-spammable and keep their historical bypass.
//	floodGlobal — unscoped ctx_kb action=search: the original global bucket.
//	floodRg     — ctx_kb action=search scope=rg: dedicated rg bucket, more
//	              generous than global because legitimate rg-summary reuse
//	              (searching back output indexed by ctx_fs rg) can produce
//	              several lookups per rg run during iterative agent work.
type floodMode int

const (
	floodNone floodMode = iota
	floodGlobal
	floodRg
)

// rg-scope bucket thresholds (same 60s sliding window as the global bucket):
// 20 full-result searches per minute before throttling, hard block at 40
// total attempts — 5x the global search quota (4/9). rg-scoped searches only
// hit this session's rg index, and the legitimate reuse path (ctx_fs rg
// indexes oversized output, then the agent searches it back with scope=rg)
// is not throttled at normal interactive rates, while sustained abuse still
// trips the hard block and caps the double-FTS query rate.
const (
	rgFloodOKLimit    = 20
	rgFloodBlockLimit = 40
)

// SearchPipeline orchestrates the complete search pipeline:
// flood guard → dual-table search → RRF merge → fuzzy fallback → proximity rerank.
type SearchPipeline struct {
	store        *Store
	floodGuard   *FloodGuard // global bucket for unscoped search (unchanged semantics)
	rgFloodGuard *FloodGuard // dedicated bucket for scope=rg (nil = disabled, no limiting)
}

// NewSearchPipeline creates a new search pipeline.
func NewSearchPipeline(store *Store, floodGuard *FloodGuard) *SearchPipeline {
	return &SearchPipeline{
		store:        store,
		floodGuard:   floodGuard,
		rgFloodGuard: NewFloodGuardWithThresholds(60*time.Second, 64, rgFloodOKLimit, rgFloodBlockLimit),
	}
}

// Search runs the complete enhanced search pipeline (with flood guard).
func (sp *SearchPipeline) Search(query string, limit int) ([]SearchResult, *SearchMeta, error) {
	return sp.search(query, "", limit, floodGlobal)
}

// SearchBatchScoped searches only documents under the batch: path prefix and
// does NOT consume flood-guard quota (batch queries are internal, not agent spam).
func (sp *SearchPipeline) SearchBatchScoped(query string, limit int) ([]SearchResult, *SearchMeta, error) {
	return sp.SearchPrefixScoped(query, "batch:", limit)
}

// SearchRgScoped searches only documents under rgSessionPrefix. It consumes
// the dedicated rg-scope flood bucket — independent from the global search
// bucket and more generous — so rg-scoped searches no longer bypass rate
// limiting entirely while legitimate rg-summary reuse keeps ample headroom.
func (sp *SearchPipeline) SearchRgScoped(query, rgSessionPrefix string, limit int) ([]SearchResult, *SearchMeta, error) {
	return sp.search(query, rgSessionPrefix, limit, floodRg)
}

// SearchPrefixScoped searches documents under pathPrefix and skips the flood
// guard (used by ctx_run action=batch query_scope=batch, which is internal
// and must keep its historical bypass).
func (sp *SearchPipeline) SearchPrefixScoped(query, pathPrefix string, limit int) ([]SearchResult, *SearchMeta, error) {
	return sp.search(query, pathPrefix, limit, floodNone)
}

// search is the shared implementation.
// pathPrefix filters at the store layer; mode selects the flood-guard bucket
// (floodNone skips the guard, floodGlobal uses the original global bucket
// unchanged, floodRg uses the dedicated rg-scope bucket).
func (sp *SearchPipeline) search(query, pathPrefix string, limit int, mode floodMode) ([]SearchResult, *SearchMeta, error) {
	if limit < 0 {
		limit = 0
	}
	start := time.Now()
	meta := &SearchMeta{}

	// 1. Flood guard check: floodNone skips it entirely (batch-scoped
	// queries), floodGlobal keeps the original semantics unchanged, floodRg
	// uses the dedicated rg-scope bucket. A nil bucket means the guard is
	// disabled and everything behaves exactly as before.
	switch mode {
	case floodGlobal:
		status := sp.floodGuard.Allow()
		switch status {
		case StatusBlocked:
			meta.FloodStatus = "blocked"
			meta.TimeMs = time.Since(start).Milliseconds()
			return nil, meta, fmt.Errorf("search blocked: too many requests in a short time. Wait a moment and retry. ctx_run action=batch with query_scope=batch only searches that batch run's indexed output and bypasses this guard")
		case StatusThrottled:
			meta.FloodStatus = "throttled"
			meta.ThrottleMsg = "Search volume is high: showing limited results. Wait before retrying global search. ctx_run action=batch with query_scope=batch only searches that batch run's documents."
			if limit > 1 {
				limit = max(1, limit/2)
			}
		default:
			meta.FloodStatus = "ok"
		}
	case floodRg:
		if sp.rgFloodGuard != nil {
			status := sp.rgFloodGuard.Allow()
			switch status {
			case StatusBlocked:
				meta.FloodStatus = "blocked"
				meta.TimeMs = time.Since(start).Milliseconds()
				return nil, meta, fmt.Errorf("rg-scoped search blocked: too many requests in a short time. Wait a moment and retry")
			case StatusThrottled:
				meta.FloodStatus = "throttled"
				meta.ThrottleMsg = "Search volume is high: showing limited results. Wait before retrying rg-scoped search."
				if limit > 1 {
					limit = max(1, limit/2)
				}
			default:
				meta.FloodStatus = "ok"
			}
		} else {
			meta.FloodStatus = "ok"
		}
	default:
		meta.FloodStatus = "ok"
	}

	// 2. Search both indices (optionally path-scoped).
	// Request extra results from each index for better RRF merging.
	extraLimit := limit * 3
	if extraLimit < 30 {
		extraLimit = 30
	}

	porterResults, porterErr := sp.store.searchPorter(query, pathPrefix, extraLimit)
	trigramResults, trigramErr := sp.store.searchTrigram(query, pathPrefix, extraLimit)

	// If both failed, return the error. One side failing with an empty
	// other side is also an error — do not report it as "no matches".
	if porterErr != nil && trigramErr != nil {
		meta.TimeMs = time.Since(start).Milliseconds()
		return nil, meta, fmt.Errorf("porter: %v / trigram: %v", porterErr, trigramErr)
	}
	if porterErr != nil && len(trigramResults) == 0 {
		meta.TimeMs = time.Since(start).Milliseconds()
		return nil, meta, porterErr
	}
	if trigramErr != nil && len(porterResults) == 0 {
		meta.TimeMs = time.Since(start).Milliseconds()
		return nil, meta, trigramErr
	}

	// 3. RRF merge.
	results := rrfMerge(porterResults, trigramResults, limit)

	// 4. Fuzzy correction fallback.
	// If Porter returned very few results (< 2) and trigram returned more,
	// the query likely has a typo—trigram is naturally tolerant to
	// spelling errors via substring matching.
	if len(results) < 2 && len(trigramResults) > len(porterResults) {
		// Use trigram results as fuzzy fallback.
		results = trigramResults
		if len(results) > limit {
			results = results[:limit]
		}
		meta.Corrected = true
	}

	// 5. Proximity reranking for multi-word queries.
	if len(results) > 1 && len(strings.Fields(query)) > 1 {
		results = proximityRerank(results)
	}

	meta.TotalHits = len(results)
	meta.TimeMs = time.Since(start).Milliseconds()

	return results, meta, nil
}
