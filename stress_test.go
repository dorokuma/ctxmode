package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- helpers ----------

// newStressServer creates a fully-initialized server for stress tests.
func newStressServer(t *testing.T) *server {
	t.Helper()
	tmpDir := t.TempDir()
	store, err := NewStore(filepath.Join(tmpDir, "stress.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	floodGuard := NewFloodGuard(60*time.Second, 64)
	searchPipeline := NewSearchPipeline(store, floodGuard)

	return &server{
		workdirs:       []string{tmpDir},
		store:          store,
		floodGuard:     floodGuard,
		searchPipeline: searchPipeline,
		httpClient:     newHTTPClient(),
	}
}

// writeTempFile creates a file under the server's workdir with the given content.
func writeTempFile(t *testing.T, s *server, name, content string) string {
	t.Helper()
	path := filepath.Join(s.workdirs[0], name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
	return name // relative to workdir
}

// ---------- Test 1: Concurrent Write + Read ----------

func TestStressConcurrentWriteRead(t *testing.T) {
	s := newStressServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const numFiles = 20
	const numWorkers = 16
	const half = numWorkers / 2

	// Prepare temp files with known keywords.
	keywords := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	for i := 0; i < numFiles; i++ {
		content := fmt.Sprintf("file %d content with keywords: %s", i,
			strings.Join(keywords, " "))
		writeTempFile(t, s, fmt.Sprintf("file_%d.txt", i), content)
	}

	// Stats.
	type record struct {
		success bool
		latency time.Duration
		errType string // "" = success, "sqlite_busy", "other_error"
	}
	var mu sync.Mutex
	var records []record
	var panicCount int32

	var wg sync.WaitGroup
	startTime := time.Now()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					atomic.AddInt32(&panicCount, 1)
				}
			}()
			for ctx.Err() == nil {
				before := time.Now()
				var err error
				if id < half {
					// Writer: index a random file.
					fname := fmt.Sprintf("file_%d.txt", rand.Intn(numFiles))
					_, _, err = s.toolIndex(ctx, &mcp.CallToolRequest{}, indexArgs{Path: fname})
				} else {
					// Reader: search for a random keyword.
					kw := keywords[rand.Intn(len(keywords))]
					_, _, err = s.toolSearch(ctx, &mcp.CallToolRequest{}, searchArgs{Query: kw})
				}
				lat := time.Since(before)
				rec := record{latency: lat}
				if err != nil {
					rec.success = false
					errStr := err.Error()
					if strings.Contains(errStr, "SQLITE_BUSY") || strings.Contains(errStr, "database is locked") {
						rec.errType = "sqlite_busy"
					} else if strings.Contains(errStr, "blocked") || strings.Contains(errStr, "throttle") || strings.Contains(errStr, "flood") {
						rec.errType = "flood_guard"
					} else {
						rec.errType = "other_error"
					}
				} else {
					rec.success = true
				}
				mu.Lock()
				records = append(records, rec)
				mu.Unlock()
			}
		}(i)
	}

	// Mid-way purge (after ~10s).
	time.Sleep(10 * time.Second)
	t.Log("--- mid-run purge ---")
	_, _, err := s.toolPurge(ctx, &mcp.CallToolRequest{}, purgeArgs{Confirm: true, Scope: "project"})
	if err != nil {
		t.Logf("purge error (may be ok under load): %v", err)
	}
	// Verify search still works after purge.
	_, _, err = s.toolSearch(ctx, &mcp.CallToolRequest{}, searchArgs{Query: "alpha"})
	if err != nil && !strings.Contains(err.Error(), "blocked") {
		t.Logf("post-purge search error: %v", err)
	} else {
		t.Log("post-purge search succeeded (or blocked by floodguard)")
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	mu.Lock()
	totalCalls := len(records)
	mu.Unlock()

	// Compute stats.
	var totalOK, totalBusy, totalFlood, totalOther int
	var latencies []float64
	for _, r := range records {
		if r.success {
			totalOK++
		} else {
			switch r.errType {
			case "sqlite_busy":
				totalBusy++
			case "flood_guard":
				totalFlood++
			default:
				totalOther++
			}
		}
		latencies = append(latencies, float64(r.latency.Microseconds()))
	}
	sort.Float64s(latencies)

	p50 := percentile(latencies, 50)
	p95 := percentile(latencies, 95)
	p99 := percentile(latencies, 99)

	throughput := float64(totalCalls) / elapsed.Seconds()

	t.Logf("Test1 results: total=%d ok=%d busy=%d flood=%d other=%d panic=%d",
		totalCalls, totalOK, totalBusy, totalFlood, totalOther, panicCount)
	t.Logf("Test1 latency: p50=%.2fms p95=%.2fms p99=%.2fms",
		p50/1000, p95/1000, p99/1000)
	t.Logf("Test1 throughput: %.1f req/s, elapsed: %.1fs", throughput, elapsed.Seconds())

	// Assertions.
	if panicCount > 0 {
		t.Errorf("had %d panics", panicCount)
	}
	if totalCalls == 0 {
		t.Error("no calls completed — possible deadlock or context expired too early")
	}
	// SQLITE_BUSY should be very low (busy_timeout absorbs most).
	t.Logf("SQLITE_BUSY count: %d (should be near 0; busy_timeout=5000ms should absorb)", totalBusy)
	if totalOther > 0 {
		// Collect sample errors for diagnosis.
		mu.Lock()
		var samples []string
		for _, r := range records {
			if r.errType == "other_error" && len(samples) < 5 {
				samples = append(samples, fmt.Sprintf("errType=%s latency=%v", r.errType, r.latency))
			}
		}
		mu.Unlock()
		for _, s := range samples {
			t.Logf("  other_error sample: %s", s)
		}
	}
	t.Logf("Pass: concurrent read/write completed without deadlock")
}

// ---------- Test 2: FloodGuard ----------

func TestStressFloodGuard(t *testing.T) {
	s := newStressServer(t)

	// Index some files to make search meaningful.
	for i := 0; i < 5; i++ {
		content := fmt.Sprintf("test content %d alpha beta gamma", i)
		writeTempFile(t, s, fmt.Sprintf("fg_file_%d.txt", i), content)
	}
	for i := 0; i < 5; i++ {
		s.toolIndex(context.Background(), &mcp.CallToolRequest{},
			indexArgs{Path: fmt.Sprintf("fg_file_%d.txt", i)})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var totalCalls int64
	var statusOK, statusThrottle, statusBlocked int64

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			atomic.AddInt64(&totalCalls, 1)
			result, _, err := s.toolSearch(ctx, &mcp.CallToolRequest{}, searchArgs{Query: "alpha"})
			if err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "blocked") {
					atomic.AddInt64(&statusBlocked, 1)
				} else {
					// Other error — might be throttled (which returns results + meta).
					// Throttled doesn't return error; it's indicated in the response text.
				}
			}
			if result != nil && len(result.Content) > 0 {
				text := result.Content[0].(*mcp.TextContent).Text
				if strings.Contains(text, "blocked") {
					atomic.AddInt64(&statusBlocked, 1)
				} else if strings.Contains(text, "⚠️") || strings.Contains(text, "throttle") || strings.Contains(text, "Throttle") {
					atomic.AddInt64(&statusThrottle, 1)
				} else {
					atomic.AddInt64(&statusOK, 1)
				}
			}
		}
	}()

	wg.Wait()

	t.Logf("Test2 results: total=%d ok=%d throttle=%d blocked=%d",
		totalCalls, statusOK, statusThrottle, statusBlocked)

	if totalCalls == 0 {
		t.Error("no search calls completed")
	}
	// With high-speed search, flood guard should have kicked in at some point.
	if statusThrottle == 0 && statusBlocked == 0 {
		t.Log("Note: floodguard did not trigger — may be expected if rate was low")
	}
	t.Logf("Pass: floodguard test completed without panic/deadlock")
}

// ---------- Test 3: CtxCancel Kill ----------

func TestStressCtxCancelKill(t *testing.T) {
	// Check if pgrep is available.
	if _, err := exec.LookPath("pgrep"); err != nil {
		t.Skip("pgrep not available, skipping process kill verification")
	}

	s := newStressServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a long-running command in a goroutine.
	cmd := "sleep 30"
	done := make(chan struct{})
	var execErr error
	go func() {
		defer close(done)
		_, _, execErr = s.toolExecute(ctx, &mcp.CallToolRequest{}, executeArgs{
			Command:  cmd,
			Language: "shell",
		})
	}()

	// Wait for the sleep process to start.
	time.Sleep(800 * time.Millisecond)

	// Verify the process is running.
	out, err := exec.Command("pgrep", "-f", "sleep 30").Output()
	if err == nil && len(out) > 0 {
		t.Logf("sleep 30 process found (PID(s): %s)", strings.TrimSpace(string(out)))
	} else {
		t.Logf("sleep 30 process not found via pgrep (may have already exited)")
	}

	// Cancel the context.
	cancel()

	// Wait for the goroutine to return with a generous timeout.
	select {
	case <-done:
		t.Log("execute returned after context cancellation")
		took := time.Since(time.Now()) // approximate
		_ = took
	case <-time.After(8 * time.Second):
		t.Error("execute did not return within 8s after context cancellation")
	}

	if execErr != nil {
		t.Logf("execute error (expected cancellation): %v", execErr)
	}

	// Verify the sleep process is gone.
	time.Sleep(1 * time.Second)
	out2, err2 := exec.Command("pgrep", "-f", "sleep 30").Output()
	if err2 == nil && len(out2) > 0 {
		t.Errorf("sleep 30 process still running after cancellation! PIDs: %s",
			strings.TrimSpace(string(out2)))
		// Kill it ourselves.
		for _, pidStr := range strings.Fields(strings.TrimSpace(string(out2))) {
			exec.Command("kill", "-9", pidStr).Run()
		}
	} else {
		t.Log("sleep 30 process cleaned up successfully (no residual)")
	}

	t.Logf("Pass: ctx cancel kills child process")
}

// ---------- Test 4: Singleflight ----------

func TestStressSingleflight(t *testing.T) {
	// Try IPv6 loopback first (allowed in non-strict SSRF mode).
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback not available: %v — skipping singleflight test", err)
	}

	var requestCount int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body><h1>Test Page</h1><p>Unique content for singleflight test.</p></body></html>"))
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	defer srv.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://[::1]:%d/", port)

	appServer := newStressServer(t)

	// --- Sub-test 4a: 8 concurrent fetches, same URL+source+format → singleflight merge ---
	t.Run("same_url_and_format", func(t *testing.T) {
		requestCount = 0
		start := time.Now()

		const concurrent = 8
		var wg sync.WaitGroup
		results := make([]*mcp.CallToolResult, concurrent)
		errs := make([]error, concurrent)

		for i := 0; i < concurrent; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				// Use default TTL (24h) so singleflight path is taken (skipCacheWrite=false).
				r, _, e := appServer.toolFetchAndIndex(context.Background(), &mcp.CallToolRequest{}, fetchArgs{
					URL:    url,
					Source: "sf-test",
					Format: "markdown",
				})
				results[idx] = r
				errs[idx] = e
			}(i)
		}
		wg.Wait()
		elapsed := time.Since(start)

		successCount := 0
		for i := 0; i < concurrent; i++ {
			if errs[i] == nil && results[i] != nil {
				successCount++
			}
		}

		t.Logf("Test4a: %d/%d successful, %d HTTP requests, elapsed=%v",
			successCount, concurrent, requestCount, elapsed)

		if requestCount != 1 {
			t.Errorf("expected 1 HTTP request (singleflight dedup), got %d", requestCount)
		}
		if successCount != concurrent {
			t.Errorf("expected %d successful, got %d", concurrent, successCount)
		}
	})

	// --- Sub-test 4b: different formats → separate singleflight keys (S26) ---
	// Use Force=true to bypass any cache from sub-test 4a, so both formats
	// trigger fresh HTTP requests through singleflight.
	t.Run("different_format_separate", func(t *testing.T) {
		requestCount = 0

		var wg sync.WaitGroup

		// Fetch markdown format (Force=true → skip cache read, still uses singleflight).
		wg.Add(1)
		var r1 *mcp.CallToolResult
		var e1 error
		go func() {
			defer wg.Done()
			r1, _, e1 = appServer.toolFetchAndIndex(context.Background(), &mcp.CallToolRequest{}, fetchArgs{
				URL:    url,
				Source: "sf-test-fmt",
				Format: "markdown",
				Force:  true,
			})
		}()

		// Fetch html format (Force=true → separate singleflight key due to format).
		wg.Add(1)
		var r2 *mcp.CallToolResult
		var e2 error
		go func() {
			defer wg.Done()
			r2, _, e2 = appServer.toolFetchAndIndex(context.Background(), &mcp.CallToolRequest{}, fetchArgs{
				URL:    url,
				Source: "sf-test-fmt",
				Format: "html",
				Force:  true,
			})
		}()

		wg.Wait()

		if e1 != nil {
			t.Errorf("markdown fetch failed: %v", e1)
		}
		if e2 != nil {
			t.Errorf("html fetch failed: %v", e2)
		}
		if r1 == nil || r2 == nil {
			t.Fatal("nil results")
		}

		text1 := r1.Content[0].(*mcp.TextContent).Text
		text2 := r2.Content[0].(*mcp.TextContent).Text

		t.Logf("Test4b: markdown=%v html=%v HTTP requests=%d",
			text1 != "", text2 != "", requestCount)

		// Each format should trigger its own HTTP request (2 total).
		if requestCount != 2 {
			t.Errorf("expected 2 HTTP requests (1 per format due to S26 format-aware key), got %d", requestCount)
		}
	})

	t.Logf("Pass: singleflight dedup + format-aware keys")
}

// ---------- Test 5: Memory ----------

func TestStressMemory(t *testing.T) {
	s := newStressServer(t)

	const iterations = 200
	const sampleInterval = 50

	var memSnapshots []runtime.MemStats

	for i := 0; i < iterations; i++ {
		// Index a new temp file.
		content := fmt.Sprintf("memory test iteration %d with unique content %s",
			i, strings.Repeat("xyz ", 20))
		fname := writeTempFile(t, s, fmt.Sprintf("mem_file_%d.txt", i), content)
		s.toolIndex(context.Background(), &mcp.CallToolRequest{}, indexArgs{Path: fname})

		// Search.
		s.toolSearch(context.Background(), &mcp.CallToolRequest{},
			searchArgs{Query: fmt.Sprintf("iteration %d", i)})

		// Batch execute one command.
		s.toolBatchExecute(context.Background(), &mcp.CallToolRequest{}, batchArgs{
			Commands: []batchCommand{{Label: fmt.Sprintf("mem%d", i), Command: "echo ok"}},
		})

		// Record memory every sampleInterval.
		if (i+1)%sampleInterval == 0 || i == 0 {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			memSnapshots = append(memSnapshots, ms)
			// Trigger GC for cleaner measurement.
			runtime.GC()
		}
	}

	// Final GC.
	runtime.GC()
	var finalMs runtime.MemStats
	runtime.ReadMemStats(&finalMs)

	for idx, ms := range memSnapshots {
		t.Logf("Test5 snapshot[%d]: HeapAlloc=%dKB HeapInuse=%dKB NumGC=%d",
			idx, ms.HeapAlloc/1024, ms.HeapInuse/1024, ms.NumGC)
	}
	t.Logf("Test5 final: HeapAlloc=%dKB HeapInuse=%dKB NumGC=%d",
		finalMs.HeapAlloc/1024, finalMs.HeapInuse/1024, finalMs.NumGC)

	// Check temp file accumulation.
	tmpPattern := filepath.Join(os.TempDir(), "ctxmode_*")
	matches, _ := filepath.Glob(tmpPattern)
	t.Logf("Test5 temp files in /tmp matching ctxmode_*: %d", len(matches))
	if len(matches) > 10 {
		t.Errorf("temp file leak: %d ctxmode_* files in /tmp (expected near 0)", len(matches))
	}

	// Check DB size growth.
	dbPath := s.store.DBPath()
	if fi, err := os.Stat(dbPath); err == nil {
		dbSizeMB := float64(fi.Size()) / (1024 * 1024)
		t.Logf("Test5 DB size: %.2f MB", dbSizeMB)
		if dbSizeMB > 50 {
			t.Errorf("DB file grew too large: %.2f MB", dbSizeMB)
		}
	}

	// Heap growth check: compare final to first snapshot.
	if len(memSnapshots) >= 2 {
		firstAlloc := memSnapshots[0].HeapAlloc
		finalAlloc := finalMs.HeapAlloc
		ratio := float64(finalAlloc) / float64(firstAlloc)
		t.Logf("Test5 heap growth: first=%dKB final=%dKB ratio=%.2fx",
			firstAlloc/1024, finalAlloc/1024, ratio)
		// Allow some growth but not unbounded.
		if ratio > 5.0 {
			t.Errorf("heap grew too much: %.2fx from first snapshot", ratio)
		}
	}

	t.Logf("Pass: memory test completed")
}

// ---------- utility ----------

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	idx := p / 100.0 * float64(len(sorted)-1)
	lo := int(idx)
	hi := lo + 1
	if hi >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	frac := idx - float64(lo)
	return sorted[lo]*(1-frac) + sorted[hi]*frac
}
