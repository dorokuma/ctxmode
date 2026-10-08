package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatRecordCallAndKeptOut(t *testing.T) {
	s := testServerWithWorkdir(t, t.TempDir())
	s.statRecordCall("ctx_run", 100)
	s.statRecordCall("ctx_run", 50)
	s.statRecordKeptOut("store", 1000)
	s.statMu.Lock()
	st := s.statTools["ctx_run"]
	s.statMu.Unlock()
	if st == nil || st.calls != 2 || st.returned != 150 {
		t.Fatalf("call counters wrong: %+v", st)
	}
	s.statMu.Lock()
	st = s.statTools["store"]
	s.statMu.Unlock()
	if st == nil || st.keptOut != 1000 {
		t.Fatalf("kept-out counter wrong: %+v", st)
	}
	// Non-positive kept-out bytes are ignored.
	s.statRecordKeptOut("store", 0)
	s.statMu.Lock()
	if s.statTools["store"].keptOut != 1000 {
		t.Fatal("zero kept-out must not double count")
	}
	s.statMu.Unlock()
}

func TestCountedWrapperRecordsResultLength(t *testing.T) {
	s := testServerWithWorkdir(t, t.TempDir())
	// counted() is exercised against the real tool signatures via the
	// resolver: run one resolve call through a counted-wrapped handler.
	wrapped := counted(s, "ctx_fs", s.toolResolve)
	mustWrite(t, filepath.Join(s.workdirs[0], "a.txt"), "x\n")
	if _, _, err := wrapped(context.Background(), nil, resolveArgs{Path: "a.txt"}); err != nil {
		t.Fatalf("wrapped call: %v", err)
	}
	s.statMu.Lock()
	st := s.statTools["ctx_fs"]
	s.statMu.Unlock()
	if st == nil || st.calls != 1 || st.returned == 0 {
		t.Fatalf("wrapper did not record returned bytes: %+v", st)
	}
}

func TestAggregateAuditLogSessionFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	lines := []string{
		`{"timestamp":"2026-10-07T00:00:00Z","session_id":"s1","action":"execute","output_len":100,"truncated":false,"indexed":false,"commands":[]}`,
		`{"timestamp":"2026-10-07T00:00:01Z","session_id":"s1","action":"batch","output_len":200,"truncated":true,"indexed":true,"commands":[]}`,
		`{"timestamp":"2026-10-07T00:00:02Z","session_id":"s2","action":"execute","output_len":999,"truncated":false,"indexed":false,"commands":[]}`,
		`not json`,
		``,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var agg auditAgg
	if err := aggregateAuditLog(path, "s1", &agg); err != nil {
		t.Fatalf("aggregateAuditLog: %v", err)
	}
	if agg.calls != 2 || agg.output != 300 || agg.indexed != 1 || agg.truncated != 1 {
		t.Fatalf("aggregation wrong: %+v", agg)
	}
	var all auditAgg
	if err := aggregateAuditLog(path, "", &all); err != nil {
		t.Fatalf("aggregateAuditLog all: %v", err)
	}
	if all.calls != 3 {
		t.Fatalf("unfiltered aggregation wrong: %+v", all)
	}
	if err := aggregateAuditLog(filepath.Join(dir, "missing.jsonl"), "s1", &agg); err == nil {
		t.Fatal("missing audit file should error")
	}
}

func TestToolCtxStatsTextAndJSON(t *testing.T) {
	s := testServerWithWorkdir(t, t.TempDir())
	s.statRecordCall("ctx_run", 4096)
	s.statRecordKeptOut("store", 8192)
	res, _, err := s.toolCtxStats(context.Background(), nil, ctxStatsArgs{})
	if err != nil {
		t.Fatalf("toolCtxStats: %v", err)
	}
	text := mcpResultText(t, res)
	for _, want := range []string{"ctx_run", "store", "4.0KB", "1.0K", "8.0KB", "2.0K", "savings"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stats text missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "NaN") {
		t.Fatalf("stats text has NaN:\n%s", text)
	}
	res, _, err = s.toolCtxStats(context.Background(), nil, ctxStatsArgs{JSON: true})
	if err != nil {
		t.Fatalf("toolCtxStats json: %v", err)
	}
	if text := mcpResultText(t, res); !strings.Contains(text, `"total_kept_out"`) {
		t.Fatalf("json output wrong:\n%s", text)
	}
}

func TestStoreLayerKeptOutCoversBatchDirectIndex(t *testing.T) {
	// Regression: the batch auto-index path writes with a direct
	// Store.Index call, so the kept-out accounting used to miss it. The sink
	// now lives in the Store itself, so this path is counted too.
	s := &server{workdirs: []string{t.TempDir()}}
	s.attachStore(newTestStore(t))

	out := strings.Repeat("x", maxOutputSize+1)
	r := &batchResult{Label: "big", ExitCode: 0}
	s.completeBatchResult(r, "run-1", out, "")
	if !r.Indexed {
		t.Fatalf("batch output was not indexed: %q", r.IndexError)
	}
	s.statMu.Lock()
	st := s.statTools["store"]
	s.statMu.Unlock()
	if st == nil || st.keptOut != int64(len(out)) {
		t.Fatalf("batch direct store must be counted as kept-out: %+v (want %d)", st, len(out))
	}
}

func TestStoreLayerKeptOutCoversFetchChunks(t *testing.T) {
	// Regression: ctx_kb fetch writes through indexContentLocked →
	// Store.ReplaceExactAndChunks, which bypassed the old storeIndexLocked
	// accounting point. The Store-layer sink counts the chunk bytes.
	s := &server{}
	s.attachStore(newTestStore(t))

	content := strings.Repeat("fetch chunk body text\n\n", 300)
	if _, err := s.indexContentLocked("session:x:src:md:http://example.com/probe", content); err != nil {
		t.Fatalf("indexContentLocked: %v", err)
	}
	var want int64
	for _, c := range chunkContent(content) {
		want += int64(len(c))
	}
	s.statMu.Lock()
	st := s.statTools["store"]
	s.statMu.Unlock()
	if st == nil || st.keptOut != want {
		t.Fatalf("fetch chunked write must be counted as kept-out: %+v (want %d)", st, want)
	}
}

func TestToolStatsKeptOutBytesIsKeptOutTotal(t *testing.T) {
	// ctx_kb action=stats must report kept_out_bytes (the kept-out total),
	// not totalOutput-totalInput — a short output returned verbatim saves
	// nothing even though it makes the old subtraction look large.
	s := &server{store: newTestStore(t), floodGuard: NewFloodGuard(60*time.Second, 64)}
	s.totalOutput = 100000
	s.totalInput = 1000
	s.statRecordKeptOut("store", 4096)

	res, _, err := s.toolStats(context.Background(), nil, statsArgs{})
	if err != nil {
		t.Fatalf("toolStats: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, `"kept_out_bytes": 4096`) {
		t.Fatalf("kept_out_bytes must be the kept-out total:\n%s", text)
	}
	if strings.Contains(text, "saved_estimate_bytes") {
		t.Fatalf("saved_estimate_bytes must be gone:\n%s", text)
	}
	if !strings.Contains(text, `"total_output_bytes": 100000`) {
		t.Fatalf("raw byte counters must be kept:\n%s", text)
	}
}

func TestHumanBytesTokensUptime(t *testing.T) {
	cases := map[int64]string{0: "0B", 512: "512B", 2048: "2.0KB", 3 << 20: "3.0MB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Fatalf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := humanTokens(2500); got != "2.5K" {
		t.Fatalf("humanTokens(2500) = %q", got)
	}
	if got := formatUptime(90 * 1e9); got != "1m30s" {
		t.Fatalf("formatUptime = %q", got)
	}
	if got := formatUptime(90 * 60 * 1e9); got != "1h30m0s" {
		t.Fatalf("formatUptime h = %q", got)
	}
}
