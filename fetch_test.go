package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// ---------- checkIP tests ----------

func TestCheckIP_IPv4_Blocked(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		reason string
	}{
		// Private ranges (RFC 1918)
		{"10.0.0.0/8 lower", "10.0.0.1", "10.0.0.0/8 (private)"},
		{"10.0.0.0/8 mid", "10.255.255.254", "10.0.0.0/8 (private)"},
		{"172.16.0.0/12 lower", "172.16.0.1", "172.16.0.0/12 (private)"},
		{"172.16.0.0/12 upper", "172.31.255.254", "172.16.0.0/12 (private)"},
		{"192.168.0.0/16 lower", "192.168.0.1", "192.168.0.0/16 (private)"},
		{"192.168.0.0/16 upper", "192.168.255.254", "192.168.0.0/16 (private)"},

		// Link-local / IMDS
		{"169.254.0.0/16 lower", "169.254.0.1", "169.254.0.0/16 (link-local / IMDS)"},
		{"169.254.0.0/16 upper", "169.254.255.254", "169.254.0.0/16 (link-local / IMDS)"},

		// Loopback
		{"127.0.0.0/8 lower", "127.0.0.1", "127.0.0.0/8 (loopback)"},
		{"127.0.0.0/8 upper", "127.255.255.254", "127.0.0.0/8 (loopback)"},

		// Unspecified
		{"0.0.0.0/8 lower", "0.0.0.0", "0.0.0.0/8 (unspecified address)"},
		{"0.0.0.0/8 mid", "0.255.255.255", "0.0.0.0/8 (unspecified address)"},

		// Multicast
		{"224.0.0.0/4 lower", "224.0.0.1", "224.0.0.0/4 (multicast)"},
		{"224.0.0.0/4 mid", "232.0.0.1", "224.0.0.0/4 (multicast)"},
		{"224.0.0.0/4 upper", "239.255.255.254", "224.0.0.0/4 (multicast)"},

		// Reserved (240.0.0.0/4)
		{"240.0.0.0/4 lower", "240.0.0.1", "240.0.0.0/4 (reserved)"},
		{"240.0.0.0/4 mid", "248.0.0.1", "240.0.0.0/4 (reserved)"},
		{"240.0.0.0/4 upper", "255.255.255.254", "240.0.0.0/4 (reserved)"},

		// CGNAT (100.64.0.0/10)
		{"100.64.0.0/10 lower", "100.64.0.1", "100.64.0.0/10 (CGNAT)"},
		{"100.64.0.0/10 upper", "100.127.255.254", "100.64.0.0/10 (CGNAT)"},

		// Benchmark (198.18.0.0/15)
		{"198.18.0.0/15 lower", "198.18.0.1", "198.18.0.0/15 (benchmark)"},
		{"198.18.0.0/15 upper", "198.19.255.254", "198.18.0.0/15 (benchmark)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("bad test IP: %s", tt.ip)
			}
			err := checkIP(ip)
			if err == nil {
				t.Fatalf("expected blocked, got nil error")
			}
			if err.Error() != tt.reason {
				t.Fatalf("expected %q, got %q", tt.reason, err.Error())
			}
		})
	}
}

func TestCheckIP_IPv4_Allowed(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"public DNS 8.8.8.8", "8.8.8.8"},
		{"public DNS 1.1.1.1", "1.1.1.1"},
		{"public 93.184.216.34", "93.184.216.34"},
		{"just outside 172.16/12 (172.15)", "172.15.255.255"},
		{"just outside 172.16/12 (172.32)", "172.32.0.1"},
		{"just outside CGNAT (100.63)", "100.63.255.255"},
		{"just outside CGNAT (100.128)", "100.128.0.1"},
		{"just outside benchmark (198.17)", "198.17.255.255"},
		{"just outside benchmark (198.20)", "198.20.0.1"},
		{"just outside 0/8 (1.0.0.1)", "1.0.0.1"},
		{"just outside loopback (128.0.0.1)", "128.0.0.1"},
		{"just outside IMDS (169.255)", "169.255.0.1"},
		{"just outside 192.168 (192.169)", "192.169.0.1"},
		{"just below multicast (223.255)", "223.255.255.254"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("bad test IP: %s", tt.ip)
			}
			if err := checkIP(ip); err != nil {
				t.Fatalf("expected allowed, got: %v", err)
			}
		})
	}
}

func TestCheckIP_IPv6_Blocked(t *testing.T) {
	// These are blocked regardless of strict.
	alwaysBlocked := []struct {
		name   string
		ip     string
		reason string
	}{
		{"link-local fe80::1", "fe80::1", "IPv6 link-local unicast (fe80::/10) blocked"},
		{"unspecified ::", "::", "IPv6 unspecified (::) blocked"},
		{"multicast ff00::1", "ff00::1", "IPv6 multicast blocked"},
		{"multicast ff02::1", "ff02::1", "IPv6 multicast blocked"},
	}

	for _, tt := range alwaysBlocked {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("bad test IP: %s", tt.ip)
			}
			err := checkIP(ip)
			if err == nil {
				t.Fatalf("expected blocked, got nil")
			}
			if err.Error() != tt.reason {
				t.Fatalf("expected %q, got %q", tt.reason, err.Error())
			}
		})
	}
}

func TestCheckIP_IPv6_LoopbackAndPrivateBlocked(t *testing.T) {
	// IPv6 rules are symmetric with IPv4: loopback (::1) and private/ULA
	// (fc00::/7) addresses are always blocked.
	tests := []struct {
		name   string
		ip     string
		reason string
	}{
		{"IPv6 loopback ::1", "::1", "::1 (IPv6 loopback) blocked"},
		{"IPv6 ULA fc00::1", "fc00::1", "IPv6 private address (fc00::/7) blocked"},
		{"IPv6 ULA fd00::1", "fd00::1", "IPv6 private address (fc00::/7) blocked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("bad test IP: %s", tt.ip)
			}
			err := checkIP(ip)
			if err == nil {
				t.Fatalf("expected blocked, got nil")
			}
			if err.Error() != tt.reason {
				t.Fatalf("expected %q, got %q", tt.reason, err.Error())
			}
		})
	}
}

func TestCheckIP_Public_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:4860:4860::8888") // Google DNS v6
	if ip == nil {
		t.Fatal("bad test IP")
	}
	if err := checkIP(ip); err != nil {
		t.Fatalf("expected allowed, got: %v", err)
	}
}

func TestCheckIP_Nil(t *testing.T) {
	err := checkIP(nil)
	if err == nil {
		t.Fatal("expected error for nil IP")
	}
	if err.Error() != "nil IP" {
		t.Fatalf("expected 'nil IP', got %q", err.Error())
	}
}

func TestCheckIP_IgnoresStrictEnv(t *testing.T) {
	// CTX_FETCH_STRICT no longer exists (the strict parameter was removed):
	// setting it must not change the SSRF blocklist, which is a single fixed
	// set. This guards against reintroducing an env-var switch.
	t.Setenv("CTX_FETCH_STRICT", "1")
	if err := checkIP(net.ParseIP("10.0.0.1")); err == nil {
		t.Fatal("private IP must be blocked even with CTX_FETCH_STRICT=1")
	}
	if err := checkIP(net.ParseIP("8.8.8.8")); err != nil {
		t.Fatalf("public IP must stay allowed with CTX_FETCH_STRICT=1: %v", err)
	}
	if err := checkIP(net.ParseIP("::1")); err == nil {
		t.Fatal("IPv6 loopback must be blocked even with CTX_FETCH_STRICT=1")
	}
}

func TestCheckIP_IPv4Mapped_IPv6(t *testing.T) {
	// IPv4-mapped IPv6 addresses: ::ffff:10.0.0.1 should be blocked as private.
	ip := net.ParseIP("::ffff:10.0.0.1")
	if ip == nil {
		t.Fatal("bad test IP")
	}
	// To4() returns the v4 address for IPv4-mapped IPv6.
	v4 := ip.To4()
	if v4 == nil {
		t.Fatal("expected non-nil v4 for IPv4-mapped")
	}
	err := checkIP(ip)
	if err == nil {
		t.Fatal("expected blocked for ::ffff:10.0.0.1")
	}
	if err.Error() != "10.0.0.0/8 (private)" {
		t.Fatalf("expected '10.0.0.0/8 (private)', got %q", err.Error())
	}
}

// ---------- singleflight key construction ----------

func TestSingleflightKeyPattern(t *testing.T) {
	// cacheSource = source + "|" + format
	// sfKey = rawURL + "|" + cacheSource
	// This matches the logic in fetchAndIndex:
	//   cacheSource := source + "|" + format
	//   sfKey := rawURL + "|" + cacheSource
	tests := []struct {
		rawURL  string
		source  string
		format  string
		wantKey string
	}{
		{
			rawURL:  "https://example.com",
			source:  "docs",
			format:  "markdown",
			wantKey: "https://example.com|docs|markdown",
		},
		{
			rawURL:  "https://example.com",
			source:  "docs",
			format:  "html",
			wantKey: "https://example.com|docs|html",
		},
		{
			rawURL:  "https://other.example.com",
			source:  "",
			format:  "",
			wantKey: "https://other.example.com||",
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantKey, func(t *testing.T) {
			cacheSource := tt.source + "|" + tt.format
			sfKey := tt.rawURL + "|" + cacheSource
			if sfKey != tt.wantKey {
				t.Fatalf("expected %q, got %q", tt.wantKey, sfKey)
			}
		})
	}
}

func TestSingleflightKey_UniquePerFormat(t *testing.T) {
	// Same URL + source, different formats → different singleflight keys.
	rawURL := "https://example.com"
	source := "api-ref"

	keyMarkdown := rawURL + "|" + source + "|" + "markdown"
	keyHTML := rawURL + "|" + source + "|" + "html"
	keyJSON := rawURL + "|" + source + "|" + "json"

	if keyMarkdown == keyHTML {
		t.Fatalf("markdown and html keys should differ: %q", keyMarkdown)
	}
	if keyMarkdown == keyJSON {
		t.Fatalf("markdown and json keys should differ: %q", keyMarkdown)
	}
	if keyHTML == keyJSON {
		t.Fatalf("html and json keys should differ: %q", keyHTML)
	}
}

// ---------- fetch test harness ----------

// fakeRoundTripper serves HTTP requests locally, bypassing both the network
// and the SSRF DialContext gate. Tests use public-looking IP hosts (e.g.
// http://1.1.1.1/...) so validateURL passes without real DNS lookups.
type fakeRoundTripper struct {
	handler http.Handler
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	return rr.Result(), nil
}

// newFetchTestServer builds a server whose HTTP client is backed by a local
// handler instead of real network dialing.
func newFetchTestServer(t *testing.T, handler http.HandlerFunc) *server {
	t.Helper()
	s := newTestServer(t)
	s.httpClient = &http.Client{Transport: &fakeRoundTripper{handler: handler}}
	return s
}

// ---------- #1 stale chunk cleanup ----------

func TestIndexContentLocked_ClearsStaleChunks(t *testing.T) {
	srv := newTestServer(t)
	const docPath = "src:markdown:http://example.com/doc"

	// Simulate an earlier fetch that indexed 3 chunks.
	indexDoc(t, srv.store, docPath+"#chunk-0", "old alpha")
	indexDoc(t, srv.store, docPath+"#chunk-1", "old beta")
	indexDoc(t, srv.store, docPath+"#chunk-2", "old gamma")

	// Re-index with a single chunk (fewer than before).
	count, err := srv.indexContentLocked(docPath, "new content only")
	if err != nil {
		t.Fatalf("indexContentLocked: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 chunk, got %d", count)
	}

	// Old chunks must be gone; only the new single chunk remains.
	got, _ := srv.store.CountByPrefix(docPath)
	if got != 1 {
		t.Fatalf("expected 1 document under prefix, got %d", got)
	}
	doc, err := srv.store.Get(docPath)
	if err != nil || doc == nil {
		t.Fatalf("expected doc at %q (err=%v)", docPath, err)
	}
	if doc.Content != "new content only" {
		t.Fatalf("unexpected content: %q", doc.Content)
	}
	if stale, _ := srv.store.Get(docPath + "#chunk-1"); stale != nil {
		t.Fatalf("stale chunk %q survived re-index", docPath+"#chunk-1")
	}
}

func TestFetchAndIndex_RefetchClearsStaleChunks(t *testing.T) {
	var mu sync.Mutex
	var body string
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}
	srv := newFetchTestServer(t, handler)
	const url = "http://1.1.1.1/doc"

	mu.Lock()
	// 5 paragraphs of ~1500 bytes each: chunkContent merges paragraphs up to
	// 4000 bytes, so chunks are p1+p2, p3+p4, p5 → 3 chunks.
	para := strings.Repeat("zebra ", 250)
	body = "alpha " + para + "\n\n" + para + "\n\n" + para + "\n\n" + para + "\n\n" + para
	mu.Unlock()
	res, err := srv.fetchAndIndex(context.Background(), url, "src", "markdown", false, 3600000, 30*time.Second)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("first fetch error: %s", res.Error)
	}
	if res.ChunkCount != 3 {
		t.Fatalf("expected 3 chunks, got %d", res.ChunkCount)
	}

	// Re-fetch with fewer chunks (force skips cache read).
	mu.Lock()
	body = "delta zebra only"
	mu.Unlock()
	res2, err := srv.fetchAndIndex(context.Background(), url, "src", "markdown", true, 3600000, 30*time.Second)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if res2.Error != "" {
		t.Fatalf("second fetch error: %s", res2.Error)
	}
	if res2.ChunkCount != 1 {
		t.Fatalf("expected 1 chunk after re-fetch, got %d", res2.ChunkCount)
	}

	// Old chunks must be removed from documents and FTS.
	count, _ := srv.store.CountByPrefix("src:markdown:" + url)
	if count != 1 {
		t.Fatalf("expected 1 document under prefix, got %d", count)
	}
	if stale, _ := srv.store.Get("src:markdown:" + url + "#chunk-1"); stale != nil {
		t.Fatal("stale chunk #chunk-1 survived re-fetch")
	}
	hits, err := srv.store.Search("alpha", 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("old content 'alpha' should no longer be searchable, got %d hits", len(hits))
	}
}

// ---------- #2 index failures surface in results ----------

func TestFetchAndIndex_IndexErrorReported(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "content that cannot be indexed")
	}
	srv := newFetchTestServer(t, handler)

	// Close the store: every index write (purge + insert) must fail.
	if err := srv.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// singleflight branch (ttl > 0): IndexError must be propagated to result.
	res, err := srv.fetchAndIndex(context.Background(), "http://1.1.1.1/doc", "src", "markdown", false, 3600000, 30*time.Second)
	if err != nil {
		t.Fatalf("fetchAndIndex: %v", err)
	}
	if res.Error != "" {
		t.Fatalf("fetch itself should succeed, got error: %s", res.Error)
	}
	if res.IndexError == "" {
		t.Fatal("expected IndexError when store is closed (singleflight branch)")
	}

	// Direct branch (ttl=0, skipCacheWrite=true): same requirement.
	res2, err := srv.fetchAndIndex(context.Background(), "http://1.1.1.1/doc2", "src", "markdown", false, 0, 30*time.Second)
	if err != nil {
		t.Fatalf("fetchAndIndex ttl=0: %v", err)
	}
	if res2.Error != "" {
		t.Fatalf("fetch ttl=0 should succeed, got error: %s", res2.Error)
	}
	if res2.IndexError == "" {
		t.Fatal("expected IndexError when store is closed (direct branch)")
	}

	// Tool summary must not advertise searchability when indexing failed.
	toolRes, _, err := srv.toolFetchAndIndex(context.Background(), nil, fetchArgs{
		URL:    "http://1.1.1.1/doc",
		Source: "src",
		Format: "markdown",
	})
	if err != nil {
		t.Fatalf("toolFetchAndIndex: %v", err)
	}
	text := contentText(toolRes)
	if strings.Contains(text, "searchable") {
		t.Fatalf("must not advertise searchability when indexing failed, got: %s", text)
	}
	if strings.Contains(text, "--- Content ---") {
		t.Fatalf("must not include content preview when indexing failed, got: %s", text)
	}
}

// ---------- #3 cache hit refills missing documents ----------

func TestFetchAndIndex_CacheHitRefillsMissingDocs(t *testing.T) {
	srv := newTestServer(t)
	const url = "http://x.test/doc"
	const content = "cached content with unique token"

	// Seed the fetch cache but no indexed documents (simulates a purge).
	if err := srv.store.SetCache(url, "src|markdown", content); err != nil {
		t.Fatalf("SetCache: %v", err)
	}

	// A cache hit must detect the missing document and re-index it.
	res, err := srv.fetchAndIndex(context.Background(), url, "src", "markdown", false, 3600000, time.Second)
	if err != nil {
		t.Fatalf("fetchAndIndex: %v", err)
	}
	if !res.Cached {
		t.Fatal("expected cache hit")
	}
	if res.IndexError != "" {
		t.Fatalf("unexpected index error: %s", res.IndexError)
	}

	doc, err := srv.store.Get("src:markdown:" + url)
	if err != nil || doc == nil {
		t.Fatalf("cache hit should have re-indexed missing doc (err=%v)", err)
	}
	if doc.Content != content {
		t.Fatalf("re-indexed content mismatch: %q", doc.Content)
	}
	count, _ := srv.store.CountByPrefix("src:markdown:" + url)
	if count != 1 {
		t.Fatalf("expected 1 document, got %d", count)
	}

	// A second hit with the document present must not error or duplicate.
	res2, err := srv.fetchAndIndex(context.Background(), url, "src", "markdown", false, 3600000, time.Second)
	if err != nil {
		t.Fatalf("second fetchAndIndex: %v", err)
	}
	if !res2.Cached || res2.IndexError != "" {
		t.Fatalf("second hit: cached=%v indexError=%q", res2.Cached, res2.IndexError)
	}
	count, _ = srv.store.CountByPrefix("src:markdown:" + url)
	if count != 1 {
		t.Fatalf("expected 1 document after second hit, got %d", count)
	}
}

// ---------- #3b format isolation in KB documents ----------

func TestFetchAndIndex_FormatIsolation(t *testing.T) {
	const url = "http://1.1.1.1/format-isolation"
	const page = "<html><body><h1>FormatIsolationHeader</h1><p>format isolation body</p></body></html>"
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page)
	}
	srv := newFetchTestServer(t, handler)

	// Index the same URL+source in two formats: they must coexist.
	mdRes, err := srv.fetchAndIndex(context.Background(), url, "src", "markdown", false, 3600000, 30*time.Second)
	if err != nil {
		t.Fatalf("markdown fetch: %v", err)
	}
	if mdRes.Error != "" {
		t.Fatalf("markdown fetch error: %s", mdRes.Error)
	}
	htmlRes, err := srv.fetchAndIndex(context.Background(), url, "src", "html", false, 3600000, 30*time.Second)
	if err != nil {
		t.Fatalf("html fetch: %v", err)
	}
	if htmlRes.Error != "" {
		t.Fatalf("html fetch error: %s", htmlRes.Error)
	}
	if htmlRes.Cached {
		t.Fatal("html fetch must not hit the markdown cache entry")
	}

	mdPath := fetchDocPath("src", "markdown", url)
	htmlPath := fetchDocPath("src", "html", url)
	mdDoc, err := srv.store.Get(mdPath)
	if err != nil || mdDoc == nil {
		t.Fatalf("markdown doc missing at %q (err=%v)", mdPath, err)
	}
	htmlDoc, err := srv.store.Get(htmlPath)
	if err != nil || htmlDoc == nil {
		t.Fatalf("html doc missing at %q (err=%v)", htmlPath, err)
	}
	if strings.Contains(mdDoc.Content, "<html") {
		t.Fatalf("markdown doc must not contain raw HTML: %q", mdDoc.Content)
	}
	if !strings.Contains(htmlDoc.Content, "<html") {
		t.Fatalf("html doc must contain raw HTML: %q", htmlDoc.Content)
	}
	count, _ := srv.store.CountByPrefix("src:")
	if count != 2 {
		t.Fatalf("expected both format docs to coexist, got %d", count)
	}

	// Markdown cache hit must keep the markdown doc markdown and must not
	// touch the html doc.
	mdAgain, err := srv.fetchAndIndex(context.Background(), url, "src", "markdown", false, 3600000, 30*time.Second)
	if err != nil {
		t.Fatalf("markdown re-fetch: %v", err)
	}
	if !mdAgain.Cached {
		t.Fatal("expected markdown cache hit")
	}
	if mdDoc2, _ := srv.store.Get(mdPath); mdDoc2 == nil || mdDoc2.Content != mdDoc.Content {
		t.Fatalf("markdown doc must survive cache hit unchanged, got %+v", mdDoc2)
	}
	if htmlDoc2, _ := srv.store.Get(htmlPath); htmlDoc2 == nil || htmlDoc2.Content != htmlDoc.Content {
		t.Fatalf("html doc must be untouched by markdown cache hit, got %+v", htmlDoc2)
	}

	// Search scoped to the markdown format must return the markdown doc.
	hits, err := srv.store.SearchWithPathPrefix("FormatIsolationHeader", "src:markdown:", 5)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 1 || hits[0].Path != mdPath {
		t.Fatalf("expected single markdown-scoped hit on %q, got %+v", mdPath, hits)
	}
	hits, err = srv.store.SearchWithPathPrefix("FormatIsolationHeader", "src:html:", 5)
	if err != nil {
		t.Fatalf("search html scope: %v", err)
	}
	if len(hits) != 1 || hits[0].Path != htmlPath {
		t.Fatalf("expected single html-scoped hit on %q, got %+v", htmlPath, hits)
	}
}

func TestFetchAndIndex_CacheHitBackfillsOnlyItsFormat(t *testing.T) {
	srv := newTestServer(t)
	const url = "http://x.test/partial-purge"
	const mdContent = "markdown backfill token"
	const htmlContent = "<html><body>html backfill token</body></html>"

	// Seed both format caches; simulate a partial purge where only the html
	// doc survived and the markdown doc is missing.
	if err := srv.store.SetCache(url, "src|markdown", mdContent); err != nil {
		t.Fatalf("SetCache markdown: %v", err)
	}
	if err := srv.store.SetCache(url, "src|html", htmlContent); err != nil {
		t.Fatalf("SetCache html: %v", err)
	}
	indexDoc(t, srv.store, "src:html:"+url, htmlContent)

	res, err := srv.fetchAndIndex(context.Background(), url, "src", "markdown", false, 3600000, time.Second)
	if err != nil {
		t.Fatalf("fetchAndIndex: %v", err)
	}
	if !res.Cached {
		t.Fatal("expected markdown cache hit")
	}
	if res.IndexError != "" {
		t.Fatalf("unexpected index error: %s", res.IndexError)
	}

	// Only the markdown doc may be backfilled; the html doc stays untouched.
	mdDoc, err := srv.store.Get("src:markdown:" + url)
	if err != nil || mdDoc == nil {
		t.Fatalf("markdown doc must be backfilled on its format's cache hit (err=%v)", err)
	}
	if mdDoc.Content != mdContent {
		t.Fatalf("backfilled markdown content mismatch: %q", mdDoc.Content)
	}
	htmlDoc, err := srv.store.Get("src:html:" + url)
	if err != nil || htmlDoc == nil {
		t.Fatalf("html doc must survive (err=%v)", err)
	}
	if htmlDoc.Content != htmlContent {
		t.Fatalf("html doc must be untouched by markdown backfill: %q", htmlDoc.Content)
	}
	count, _ := srv.store.CountByPrefix("src:html:" + url)
	if count != 1 {
		t.Fatalf("html doc must stay a single document, got %d", count)
	}
}

// ---------- legacy source:url upgrade cleanup ----------

func TestPurgeLegacyFetchDocs(t *testing.T) {
	srv := newTestServer(t)

	// Old-format docs (source:url), including a chunked one.
	indexDoc(t, srv.store, "src:http://old.example.com/a", "legacy a")
	indexDoc(t, srv.store, "src:http://old.example.com/b#chunk-1", "legacy b")
	indexDoc(t, srv.store, "src:https://old.example.com/c", "legacy c")

	// New-format docs (source:format:url) must survive the cleanup.
	indexDoc(t, srv.store, "src:markdown:http://new.example.com/a", "new md")
	indexDoc(t, srv.store, "src:html:http://new.example.com/a", "new html")
	indexDoc(t, srv.store, "src:json:http://new.example.com/a", "new json")

	// Other sources must not be touched.
	indexDoc(t, srv.store, "other:http://other.example.com/a", "other legacy")

	n, err := srv.purgeLegacyFetchDocs("src")
	if err != nil {
		t.Fatalf("purgeLegacyFetchDocs: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 legacy docs deleted, got %d", n)
	}
	for _, p := range []string{
		"src:http://old.example.com/a",
		"src:http://old.example.com/b#chunk-1",
		"src:https://old.example.com/c",
	} {
		if doc, _ := srv.store.Get(p); doc != nil {
			t.Fatalf("legacy doc %q survived cleanup", p)
		}
	}
	for _, p := range []string{
		"src:markdown:http://new.example.com/a",
		"src:html:http://new.example.com/a",
		"src:json:http://new.example.com/a",
		"other:http://other.example.com/a",
	} {
		if doc, _ := srv.store.Get(p); doc == nil {
			t.Fatalf("doc %q must survive cleanup", p)
		}
	}

	// Idempotent: a second run removes nothing.
	n2, err := srv.purgeLegacyFetchDocs("src")
	if err != nil {
		t.Fatalf("second purgeLegacyFetchDocs: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("expected 0 on second run, got %d", n2)
	}
}

// ---------- #4 singleflight uses a caller-independent context ----------

func TestFetchAndIndex_SingleflightSurvivesCallerCancel(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "independent context content")
	}
	srv := newFetchTestServer(t, handler)

	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		res *FetchResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := srv.fetchAndIndex(ctx, "http://1.1.1.1/doc", "src", "markdown", false, 3600000, 30*time.Second)
		done <- outcome{res: res, err: err}
	}()

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("request never reached handler")
	}

	// Cancel the caller while the shared singleflight fetch is in flight.
	cancel()
	close(release)

	select {
	case o := <-done:
		if o.err != nil {
			t.Fatalf("fetchAndIndex: %v", o.err)
		}
		if o.res.Error != "" {
			t.Fatalf("singleflight fetch must survive caller cancel, got error: %s", o.res.Error)
		}
		if o.res.Content != "independent context content" {
			t.Fatalf("unexpected content: %q", o.res.Content)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("fetchAndIndex did not return")
	}
}

// ---------- #5 body truncation at UTF-8 boundary ----------

func TestFetchURL_TruncatesAtUTF8Boundary(t *testing.T) {
	// 3-byte runes: maxBodySize falls in the middle of a rune (maxBodySize%3==1).
	big := strings.Repeat("界", maxBodySize/3+5000)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, big)
	}
	srv := newFetchTestServer(t, handler)

	body, _, truncated, err := srv.fetchURL(context.Background(), "http://1.1.1.1/big", 30*time.Second)
	if err != nil {
		t.Fatalf("fetchURL: %v", err)
	}
	if !truncated {
		t.Fatal("expected truncated=true for oversized body")
	}
	if len(body) > maxBodySize {
		t.Fatalf("body length %d exceeds maxBodySize %d", len(body), maxBodySize)
	}
	if !utf8.Valid(body) {
		t.Fatal("truncated body must end on a valid UTF-8 boundary")
	}
	if !strings.HasPrefix(big, string(body)) {
		t.Fatal("truncated body must be a prefix of the original content")
	}
}

// ---------- #7 oversized paragraphs are force-split ----------

func TestChunkContent_ForceSplitsOversizedParagraph(t *testing.T) {
	const maxChunkSize = 4000

	t.Run("ascii wall of text", func(t *testing.T) {
		long := strings.Repeat("a", 10000) // no blank lines at all
		chunks := chunkContent(long)
		if len(chunks) != 3 {
			t.Fatalf("expected 3 chunks, got %d", len(chunks))
		}
		for i, c := range chunks {
			if len(c) > maxChunkSize {
				t.Fatalf("chunk %d is %d bytes (max %d)", i, len(c), maxChunkSize)
			}
		}
		if strings.Join(chunks, "") != long {
			t.Fatal("force-split must be lossless")
		}
	})

	t.Run("multibyte wall of text", func(t *testing.T) {
		wide := strings.Repeat("界", 2000) // 6000 bytes, no blank lines
		chunks := chunkContent(wide)
		if len(chunks) != 2 {
			t.Fatalf("expected 2 chunks, got %d", len(chunks))
		}
		for i, c := range chunks {
			if len(c) > maxChunkSize {
				t.Fatalf("chunk %d is %d bytes (max %d)", i, len(c), maxChunkSize)
			}
			if !utf8.ValidString(c) {
				t.Fatalf("chunk %d split mid-rune", i)
			}
		}
		if strings.Join(chunks, "") != wide {
			t.Fatal("force-split must be lossless")
		}
	})

	t.Run("mixed short and oversized paragraphs", func(t *testing.T) {
		long := strings.Repeat("b", 9000)
		mixed := "short intro\n\n" + long + "\n\nshort outro"
		chunks := chunkContent(mixed)
		if len(chunks) != 5 {
			t.Fatalf("expected 5 chunks (1 + 3 + 1), got %d", len(chunks))
		}
		for i, c := range chunks {
			if len(c) > maxChunkSize {
				t.Fatalf("chunk %d is %d bytes (max %d)", i, len(c), maxChunkSize)
			}
		}
		if chunks[0] != "short intro" {
			t.Fatalf("unexpected first chunk: %q", chunks[0])
		}
		if chunks[len(chunks)-1] != "short outro" {
			t.Fatalf("unexpected last chunk: %q", chunks[len(chunks)-1])
		}
	})
}

// ---------- #8 search hint uses ctx_kb action=search ----------

func TestToolFetchAndIndex_SearchHintUsesCtxKB(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "hint test content")
	}
	srv := newFetchTestServer(t, handler)

	toolRes, _, err := srv.toolFetchAndIndex(context.Background(), nil, fetchArgs{
		URL:    "http://1.1.1.1/doc",
		Source: "src",
		Format: "markdown",
	})
	if err != nil {
		t.Fatalf("toolFetchAndIndex: %v", err)
	}
	text := contentText(toolRes)
	if strings.Contains(text, "ctx_search") {
		t.Fatalf("runtime text must not mention the removed ctx_search tool: %s", text)
	}
	if !strings.Contains(text, "ctx_kb action=search") {
		t.Fatalf("expected ctx_kb action=search hint, got: %s", text)
	}
}

func TestCheckIP_EmbeddedIPv4Blocked(t *testing.T) {
	cases := []string{
		"64:ff9b::a9fe:a9fe",
		"64:ff9b::a00:1",
		"64:ff9b:1::a9fe:a9fe",
		"64:ff9b:1::a00:1",
		"2002:a9fe:a9fe::",
		"::169.254.169.254",
		"::10.0.0.1",
	}
	for _, raw := range cases {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("ParseIP(%q) nil", raw)
		}
		if err := checkIP(ip); err == nil {
			t.Errorf("checkIP(%s) allowed embedded private/IMDS", raw)
		}
	}
}

func TestIndexContentLocked_DoesNotDeleteLongerURL(t *testing.T) {
	srv := newTestServer(t)
	shortPath := fetchDocPath("web", "markdown", "http://ex.com/foo")
	longPath := fetchDocPath("web", "markdown", "http://ex.com/foobar")
	if _, err := srv.indexContentLocked(shortPath, "SHORT"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.indexContentLocked(longPath, "LONG"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.indexContentLocked(shortPath, "SHORT_V2"); err != nil {
		t.Fatal(err)
	}
	if doc, _ := srv.store.Get(longPath); doc == nil {
		t.Fatal("longer URL document must survive re-index of the shorter prefix")
	}
	if doc, _ := srv.store.Get(shortPath); doc == nil || doc.Content != "SHORT_V2" {
		t.Fatalf("short URL not updated: %+v", doc)
	}
}

func TestStripURLFragment(t *testing.T) {
	if got := stripURLFragment("http://ex.com/foo#chunk-1"); got != "http://ex.com/foo" {
		t.Fatalf("got %q", got)
	}
	if got := stripURLFragment("http://ex.com/foo"); got != "http://ex.com/foo" {
		t.Fatalf("unchanged: %q", got)
	}
}

func TestRedactUserinfoInText(t *testing.T) {
	in := `Get "http://user:s3cret@1.1.1.1/x": EOF`
	got := redactUserinfoInText(in)
	if strings.Contains(got, "s3cret") || strings.Contains(got, "user:") {
		t.Fatalf("leaked userinfo: %q", got)
	}
	if !strings.Contains(got, `http://1.1.1.1/x`) {
		t.Fatalf("expected redacted URL kept, got %q", got)
	}
	plain := `Get "http://1.1.1.1/x": EOF`
	if redactUserinfoInText(plain) != plain {
		t.Fatalf("rewrote URL without userinfo: %q", redactUserinfoInText(plain))
	}
}

func TestFetchURL_RedactsUserinfoInError(t *testing.T) {
	s := newTestServer(t)
	s.httpClient = &http.Client{Transport: roundTripError{err: &url.Error{
		Op:  "Get",
		URL: "http://user:s3cret@1.1.1.1/secret-doc",
		Err: io.EOF,
	}}}
	_, _, _, err := s.fetchURL(context.Background(), "http://user:s3cret@1.1.1.1/secret-doc", 0)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "user:") {
		t.Fatalf("fetchURL error leaked userinfo: %v", err)
	}

	res, ferr := s.fetchAndIndex(context.Background(), "http://user:s3cret@1.1.1.1/secret-doc", "web", "html", true, 0, time.Second)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if res.Error == "" {
		t.Fatal("expected fetchAndIndex error")
	}
	if strings.Contains(res.Error, "s3cret") || strings.Contains(res.Error, "user:") {
		t.Fatalf("fetchAndIndex error leaked userinfo: %q", res.Error)
	}
}

type roundTripError struct{ err error }

func (r roundTripError) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, r.err
}

func TestRedactURLUserinfo(t *testing.T) {
	got := redactURLUserinfo("https://user:s3cret@example.com/x")
	if got != "https://example.com/x" {
		t.Fatalf("got %q", got)
	}
	if got := redactURLUserinfo("https://example.com/x"); got != "https://example.com/x" {
		t.Fatalf("unchanged: %q", got)
	}
	if p := fetchDocPath("web", "html", "https://user:s3cret@example.com/x"); strings.Contains(p, "user:s3cret") {
		t.Fatalf("fetchDocPath leaked userinfo: %q", p)
	}
	if p := fetchDocPath("web", "html", "https://user:s3cret@example.com/x"); p != "web:html:https://example.com/x" {
		t.Fatalf("fetchDocPath = %q", p)
	}
}

func TestFetchAndIndex_RedactsUserinfoFromStorageAndSearch(t *testing.T) {
	var sawUserinfo bool
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.User != nil {
			pass, ok := r.URL.User.Password()
			if r.URL.User.Username() == "user" && ok && pass == "s3cret" {
				sawUserinfo = true
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "userinfo-body-marker")
	}
	srv := newFetchTestServer(t, handler)
	srv.floodGuard = NewFloodGuard(60*time.Second, 64)
	srv.searchPipeline = NewSearchPipeline(srv.store, srv.floodGuard)

	const raw = "http://user:s3cret@1.1.1.1/secret-doc"
	res, err := srv.fetchAndIndex(context.Background(), raw, "web", "html", true, 0, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatalf("fetch error: %s", res.Error)
	}
	if !sawUserinfo {
		t.Fatal("HTTP GET should still send userinfo")
	}
	if strings.Contains(res.URL, "user:s3cret") || strings.Contains(res.URL, "s3cret") {
		t.Fatalf("FetchResult.URL leaked userinfo: %q", res.URL)
	}
	if res.URL != "http://1.1.1.1/secret-doc" {
		t.Fatalf("FetchResult.URL = %q", res.URL)
	}
	if doc, _ := srv.store.Get(fetchDocPath("web", "html", "http://1.1.1.1/secret-doc")); doc == nil {
		t.Fatal("expected document at redacted path")
	}
	if leak, _ := srv.store.Get(fetchDocPath("web", "html", raw)); leak != nil && strings.Contains(leak.Path, "s3cret") {
		t.Fatalf("store path leaked userinfo: %q", leak.Path)
	}

	hits, err := srv.store.Search("userinfo-body-marker", 10)
	if err != nil || len(hits) == 0 {
		t.Fatalf("expected search hits (err %v, n %d)", err, len(hits))
	}
	for _, h := range hits {
		if strings.Contains(h.Path, "user:s3cret") || strings.Contains(h.Path, "s3cret") {
			t.Fatalf("store search path leaked userinfo: %q", h.Path)
		}
	}

	sres, _, err := srv.toolSearch(context.Background(), nil, searchArgs{Query: "userinfo-body-marker"})
	if err != nil {
		t.Fatalf("toolSearch: %v", err)
	}
	stext := mcpResultText(t, sres)
	if strings.Contains(stext, "user:s3cret") || strings.Contains(stext, "s3cret") {
		t.Fatalf("toolSearch leaked userinfo:\n%s", stext)
	}
}

func TestFetchAndIndex_StripsFragmentBeforePath(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "hello fragment")
	}
	srv := newFetchTestServer(t, handler)
	res, err := srv.fetchAndIndex(context.Background(), "http://1.1.1.1/doc#chunk-1", "web", "html", true, 0, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatalf("fetch error: %s", res.Error)
	}
	if res.URL != "http://1.1.1.1/doc" {
		t.Fatalf("URL should drop fragment, got %q", res.URL)
	}
	if doc, _ := srv.store.Get(fetchDocPath("web", "html", "http://1.1.1.1/doc")); doc == nil {
		t.Fatal("expected document at fragment-free path")
	}
}

func TestToolFetchAndIndex_ReportsBodyTruncated(t *testing.T) {
	big := strings.Repeat("A", maxBodySize+4096)
	srv := newFetchTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(big))
	})
	ttl := 0
	toolRes, _, err := srv.toolFetchAndIndex(context.Background(), nil, fetchArgs{
		URL:    "http://1.1.1.1/huge",
		Format: "html",
		Force:  true,
		TTL:    &ttl,
	})
	if err != nil {
		t.Fatalf("toolFetchAndIndex: %v", err)
	}
	text := contentText(toolRes)
	if !strings.Contains(text, "body truncated at 10MB") {
		t.Fatalf("expected 10MB body-truncation notice, got:\n%s", text)
	}
}
