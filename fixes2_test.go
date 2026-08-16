package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// 审计修复 1：目录索引必须基于符号链接解析后的真实目标做检查
// ============================================================================

// TestToolIndex_SymlinkToSensitiveRejected: a harmless-looking link name
// (notes.txt) pointing at a sensitive real file (.env) must be rejected by the
// directory walk. Before the fix the sensitive/size/binary checks ran on the
// link name and link stat, so the secret content was read and indexed.
func TestToolIndex_SymlinkToSensitiveRejected(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	envPath := filepath.Join(wd, ".env")
	mustWrite(t, envPath, "SYMLINK_SECRET_TOKEN=1")
	link := filepath.Join(wd, "notes.txt")
	if err := os.Symlink(envPath, link); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(wd, "normal.txt"), "hello normal")

	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
	if err != nil {
		t.Fatalf("toolIndex: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Indexed 1 file(s)") {
		t.Fatalf("expected 1 indexed file, got: %s", text)
	}
	if !strings.Contains(text, "2 skipped, 2 sensitive)") {
		t.Fatalf("expected both .env and its link skipped as sensitive, got: %s", text)
	}
	// Secret content must not be searchable, and neither the link target nor
	// the link path may be indexed.
	if hits, _ := st.Search("SYMLINK_SECRET_TOKEN", 5); len(hits) != 0 {
		t.Fatalf("sensitive content indexed via harmless link name: %+v", hits)
	}
	if doc, _ := st.Get(envPath); doc != nil {
		t.Fatal("sensitive target must not be in store")
	}
}

// TestToolIndex_SymlinkToSensitiveSingleFileRefused locks in the single-file
// entry point: a link to a sensitive file is refused (resolvePath already
// returns the real target, so the refusal comes from the real-path check).
func TestToolIndex_SymlinkToSensitiveSingleFileRefused(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	envPath := filepath.Join(wd, ".env")
	mustWrite(t, envPath, "SINGLE_SECRET_DATA=1")
	link := filepath.Join(wd, "notes.txt")
	if err := os.Symlink(envPath, link); err != nil {
		t.Fatal(err)
	}

	_, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: link})
	if err == nil {
		t.Fatal("expected refusal for single-file index through link to sensitive file")
	}
	if !strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("expected sensitive error, got: %v", err)
	}
	if doc, _ := st.Get(envPath); doc != nil {
		t.Fatal("sensitive target must not be in store")
	}
}

// TestToolIndex_SymlinkToHugeFileSkipped: a harmless link name pointing at a
// >1MB real file must not be read (the old code checked the link's own size,
// which is tiny, then slurped the whole target with os.ReadFile).
func TestToolIndex_SymlinkToHugeFileSkipped(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	big := filepath.Join(wd, "big-target.txt")
	mustWrite(t, big, strings.Repeat("biglinecontent ", 130000)) // ~2.08MB
	link := filepath.Join(wd, "small.txt")
	if err := os.Symlink(big, link); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(wd, "ok.txt"), "ok content")

	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
	if err != nil {
		t.Fatalf("toolIndex: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "too large") {
		t.Fatalf("expected too-large skip reason, got: %s", text)
	}
	if doc, _ := st.Get(big); doc != nil {
		t.Fatal("link target must not be read/indexed")
	}
	// Defense in depth: indexFile itself must refuse the link.
	if err := s.indexFile(link); err == nil {
		t.Fatal("indexFile must refuse a link to an oversized file")
	}
}

// TestToolIndex_TotalBytesUsesRealLinkTargetSize: the total-byte accounting
// must use the real target size. The old code added the link's own size
// (~9 bytes), so a 600KB link target plus a 600KB real file fit under a 700KB
// cap; with real sizes the second file trips the cap.
func TestToolIndex_TotalBytesUsesRealLinkTargetSize(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	withIndexCaps(t, 5000, 700*1024)

	big := filepath.Join(wd, "bbb-real.txt")
	mustWrite(t, big, strings.Repeat("y", 600*1024))
	link := filepath.Join(wd, "aaa-link.txt")
	if err := os.Symlink(big, link); err != nil {
		t.Fatal(err)
	}

	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
	if err != nil {
		t.Fatalf("toolIndex: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Indexed 1 file(s)") {
		t.Fatalf("expected 1 indexed file (byte cap reached on the second), got: %s", text)
	}
	if !strings.Contains(text, "max total bytes") {
		t.Fatalf("expected byte cap stop notice, got: %s", text)
	}
}

// ============================================================================
// 审计修复 2：run_task / batch 索引标签唯一化
// ============================================================================

func TestRunTask_DuplicateLabelsUniqueAndSearchable(t *testing.T) {
	srv := newTestServer(t)
	run := func() string {
		t.Helper()
		big := strings.Repeat("m", runTaskAutoIndexBytes+1)
		res, _, err := srv.finishRunTaskOutput(big, 0, "go_test", "same-intent")
		if err != nil {
			t.Fatalf("finishRunTaskOutput: %v", err)
		}
		m := regexp.MustCompile(`Indexed as "([^"]+)"`).FindStringSubmatch(mcpResultText(t, res))
		if len(m) != 2 {
			t.Fatalf("cannot extract index label from:\n%s", mcpResultText(t, res))
		}
		return m[1]
	}

	l1 := run()
	l2 := run()
	if l1 == l2 {
		t.Fatalf("repeated run_task with same kind/intent must get distinct labels, got %q", l1)
	}
	for _, l := range []string{l1, l2} {
		if !strings.HasPrefix(l, "run_task:same-intent:") {
			t.Fatalf("label must stay identifiable, got %q", l)
		}
		if doc, _ := srv.store.Get(l); doc == nil {
			t.Fatalf("document %q missing (second run clobbered it?)", l)
		}
		hits, err := srv.store.Search(l, 5)
		if err != nil || len(hits) == 0 {
			t.Fatalf("label %q must be directly searchable (err %v)", l, err)
		}
	}
}

func TestBatchExecute_DuplicateLabelsUniqueAndSearchable(t *testing.T) {
	srv := newTestServer(t)
	srv.workdirs = []string{t.TempDir()}
	run := func() string {
		t.Helper()
		res, _, err := srv.toolBatchExecute(context.Background(), nil, batchArgs{
			Commands: []batchCommand{{Label: "same", Command: "head -c 102500 /dev/zero | tr '\\0' a"}},
		})
		if err != nil {
			t.Fatalf("toolBatchExecute: %v", err)
		}
		var resp batchResponse
		if err := json.Unmarshal([]byte(contentText(res)), &resp); err != nil {
			t.Fatalf("unmarshal: %v\n%s", err, contentText(res))
		}
		if len(resp.Commands) != 1 || resp.Commands[0].IndexLabel == "" {
			t.Fatalf("expected index_label in response, got: %+v", resp.Commands)
		}
		return resp.Commands[0].IndexLabel
	}

	l1 := run()
	l2 := run()
	if l1 == l2 {
		t.Fatalf("repeated batch command label must get distinct index labels, got %q", l1)
	}
	for _, l := range []string{l1, l2} {
		if !strings.HasPrefix(l, batchIndexPrefix) || !strings.Contains(l, ":same:") {
			t.Fatalf("label must stay identifiable by command, got %q", l)
		}
		if doc, _ := srv.store.Get(l); doc == nil {
			t.Fatalf("document %q missing (later batch clobbered it?)", l)
		}
		hits, err := srv.store.Search(l, 5)
		if err != nil || len(hits) == 0 {
			t.Fatalf("label %q must be directly searchable (err %v)", l, err)
		}
	}
}

// ============================================================================
// 审计修复 3：纯 Go rg 超长行
// ============================================================================

// TestRgGo_LongLineSearchable: a 1.5MB single line used to blow past the 1MB
// bufio.Scanner cap and fail the entire search. It must now be scanned as one
// line (the token sits at the very END of the line, so only a full-line read
// can match it) and other files must still be searchable. The existing 100KB
// response cap still applies to the output text.
func TestRgGo_LongLineSearchable(t *testing.T) {
	wd, s := setupFSFixture(t)
	long := strings.Repeat("x", 1500*1024) + "LONG_LINE_TOKEN_XYZ"
	mustWrite(t, filepath.Join(wd, "longline.txt"), long)

	text, truncated, n, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "LONG_LINE_TOKEN_XYZ", Limit: 50}, 50, 0)
	if err != nil {
		t.Fatalf("rg over a long line must not fail the whole search: %v", err)
	}
	if n != 1 {
		t.Fatalf("token at the end of the 1.5MB line must match (full-line read), n=%d", n)
	}
	if !truncated {
		t.Fatal("a 1.5MB matching line exceeds the 100KB output cap and must flag truncated")
	}
	// The final response is still capped at 100KB.
	out := s.rgResult(text, n, truncated, "go")
	respText := mcpResultText(t, out)
	if !strings.Contains(respText, "output truncated at 100KB") {
		t.Fatalf("expected response cap marker, got: %.200s", respText)
	}
	if len(respText) > fsRgMaxOutputBytes+256 {
		t.Fatalf("response exceeds output cap: %d", len(respText))
	}

	// Short-line matches are unaffected: other files are still searched.
	mustWrite(t, filepath.Join(wd, "other.txt"), "NORMAL_RG_TOKEN\n")
	text2, truncated2, n2, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "NORMAL_RG_TOKEN", Limit: 50}, 50, 0)
	if err != nil || n2 != 1 || !strings.Contains(text2, "NORMAL_RG_TOKEN") {
		t.Fatalf("other files must still be searched: err=%v n=%d text=%q", err, n2, text2)
	}
	if truncated2 {
		t.Fatalf("short-line search must not be flagged truncated: %q", text2)
	}
}

// TestRgGo_OversizedLineSkippedNotFatal: a line beyond the explicit cap must
// be skipped per-line (not fail the search, not be searched), the result must
// be flagged truncated (not silent), and scanning must continue both in the
// same file and in other files.
func TestRgGo_OversizedLineSkippedNotFatal(t *testing.T) {
	old := maxRgLineBytes
	maxRgLineBytes = 4 * 1024
	t.Cleanup(func() { maxRgLineBytes = old })

	wd, s := setupFSFixture(t)
	// First line is 100KB (> shrunk 4KB cap), second line is normal.
	mustWrite(t, filepath.Join(wd, "huge.txt"), strings.Repeat("z", 100*1024)+"\nSAME_FILE_RG_TOKEN\n")
	// Buried token inside the oversized line must NOT match.
	mustWrite(t, filepath.Join(wd, "buried.txt"), strings.Repeat("q", 100*1024)+"BURIED_RG_TOKEN\n")
	mustWrite(t, filepath.Join(wd, "normal.txt"), "VISIBLE_RG_TOKEN\n")

	text, truncated, n, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "RG_TOKEN", Limit: 50}, 50, 0)
	if err != nil {
		t.Fatalf("oversized line must not fail the search: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true: an oversized line was skipped, coverage is incomplete")
	}
	if strings.Contains(text, "BURIED_RG_TOKEN") {
		t.Fatal("the skipped oversized line must not be searched")
	}
	if !strings.Contains(text, "SAME_FILE_RG_TOKEN") {
		t.Fatalf("lines after the oversized one in the same file must still be searched, got: %.200s", text)
	}
	if !strings.Contains(text, "VISIBLE_RG_TOKEN") {
		t.Fatalf("other files must still be searched, got: %.200s", text)
	}
	if n != 2 {
		t.Fatalf("expected 2 matches, got %d", n)
	}
}

// TestReadRgLine_BoundedAndContinues is a direct unit test of the line reader:
// a short line, then an oversized line (drained), then another short line.
func TestReadRgLine_BoundedAndContinues(t *testing.T) {
	input := "first\n" + strings.Repeat("a", 1000) + "\nlast\n"
	br := bufio.NewReaderSize(strings.NewReader(input), 16)

	line, tooLong, err := readRgLine(br, 64)
	if err != nil || tooLong || string(line) != "first" {
		t.Fatalf("first: line=%q tooLong=%v err=%v", line, tooLong, err)
	}
	line, tooLong, err = readRgLine(br, 64)
	if err != nil || !tooLong {
		t.Fatalf("oversized line: line=%q tooLong=%v err=%v (want tooLong=true)", line, tooLong, err)
	}
	line, tooLong, err = readRgLine(br, 64)
	if err != nil || tooLong || string(line) != "last" {
		t.Fatalf("after oversized line: line=%q tooLong=%v err=%v (want \"last\")", line, tooLong, err)
	}
	_, _, err = readRgLine(br, 64)
	if err != io.EOF {
		t.Fatalf("expected io.EOF at end, got %v", err)
	}

	// CRLF handling and a final unterminated line.
	br = bufio.NewReaderSize(strings.NewReader("a\r\nb"), 16)
	line, _, err = readRgLine(br, 64)
	if err != nil || string(line) != "a" {
		t.Fatalf("crlf: line=%q err=%v", line, err)
	}
	line, _, err = readRgLine(br, 64)
	if err != nil || string(line) != "b" {
		t.Fatalf("unterminated: line=%q err=%v", line, err)
	}
}

// ============================================================================
// 审计修复 4：singleflight 错误分支 Truncated 状态共享
// ============================================================================

// TestFetchAndIndex_SingleflightErrorTruncatedConsistent: a fetch that
// succeeds at the HTTP level but is truncated (>10MB) and then fails content
// processing (format=json on garbage) goes through the singleflight ERROR
// branch with truncated=true. Every concurrent waiter must report the same
// Truncated value; the old closure-outer local only the executing goroutine
// wrote left waiters with false.
func TestFetchAndIndex_SingleflightErrorTruncatedConsistent(t *testing.T) {
	big := strings.Repeat("j", maxBodySize+1000)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write slowly so all concurrent callers join the in-flight fetch.
		const chunkSize = 64 * 1024
		for i := 0; i < len(big); i += chunkSize {
			end := i + chunkSize
			if end > len(big) {
				end = len(big)
			}
			_, _ = w.Write([]byte(big[i:end]))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(time.Millisecond)
		}
	}
	srv := newFetchTestServer(t, handler)

	const n = 8
	results := make([]*FetchResult, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			res, _ := srv.fetchAndIndex(context.Background(), "http://1.1.1.1/sf-error", "src", "json", false, 3600000, 60*time.Second)
			results[idx] = res
		}(i)
	}
	close(start)
	wg.Wait()

	for i, r := range results {
		if r == nil {
			t.Fatalf("result %d is nil", i)
		}
		if r.Error == "" {
			t.Fatalf("result %d: expected a processing error (truncated JSON), got success", i)
		}
		if !r.Truncated {
			t.Fatalf("result %d: Truncated=false, want true — all singleflight waiters must agree (error=%s)", i, r.Error)
		}
	}
}

// ============================================================================
// 审计修复 5：batch Truncated 只表示真实输出裁剪
// ============================================================================

// TestBatchExecute_TruncatedOnlyWhenReal: output between 100KB and 10MB is
// auto-indexed but NOT truncated; output beyond 10MB is indexed AND truncated.
// Serial and concurrent paths must agree.
func TestBatchExecute_TruncatedOnlyWhenReal(t *testing.T) {
	for _, conc := range []int{1, 2} {
		srv := newTestServer(t)
		srv.workdirs = []string{t.TempDir()}

		res, _, err := srv.toolBatchExecute(context.Background(), nil, batchArgs{
			Commands: []batchCommand{
				{Label: "medium", Command: "head -c 200000 /dev/zero | tr '\\0' m"},
				{Label: "huge", Command: "head -c 11000000 /dev/zero | tr '\\0' h"},
			},
			Concurrency: conc,
		})
		if err != nil {
			t.Fatalf("toolBatchExecute (concurrency=%d): %v", conc, err)
		}
		var resp batchResponse
		if err := json.Unmarshal([]byte(contentText(res)), &resp); err != nil {
			t.Fatalf("unmarshal (concurrency=%d): %v\n%s", conc, err, contentText(res))
		}
		byLabel := map[string]batchResult{}
		for _, r := range resp.Commands {
			byLabel[r.Label] = r
		}

		medium := byLabel["medium"]
		if !medium.Indexed {
			t.Fatalf("concurrency=%d: 200KB output must be auto-indexed: %+v", conc, medium)
		}
		if medium.Truncated {
			t.Fatalf("concurrency=%d: 200KB output (100KB-10MB) must NOT be flagged truncated: %+v", conc, medium)
		}

		huge := byLabel["huge"]
		if !huge.Indexed {
			t.Fatalf("concurrency=%d: >10MB output must be auto-indexed: %+v", conc, huge)
		}
		if !huge.Truncated {
			t.Fatalf("concurrency=%d: >10MB output must be flagged truncated: %+v", conc, huge)
		}
		if huge.Size != maxCmdOutput {
			t.Fatalf("concurrency=%d: captured size must be exactly the 10MB buffer cap, got %d", conc, huge.Size)
		}
		if !resp.Truncated {
			t.Fatalf("concurrency=%d: batch-level truncated must aggregate the real truncation", conc)
		}
	}
}
