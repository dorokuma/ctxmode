package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	md "github.com/JohannesKaufmann/html-to-markdown/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- constants ----------

const (
	defaultFetchTimeout = 150 * time.Second
	clientTimeout       = 5 * time.Minute
	maxRedirects        = 5
	maxBodySize         = 10 * 1024 * 1024 // 10 MB
	defaultMaxBytes     = 50 * 1024        // 50 KB return limit
	defaultTTL         = 24 * time.Hour
	maxConcurrency     = 8
)

// fetchGroup deduplicates concurrent fetches for the same URL+source.
var fetchGroup singleflight.Group

// fetchResultData carries results between singleflight-merged callers.
type fetchResultData struct {
	content    string
	chunkCount int
	truncated  bool
}

// ---------- data types ----------

// FetchResult holds the result of fetching and indexing a single URL.
type FetchResult struct {
	URL        string `json:"url"`
	Source     string `json:"source"`
	Content    string `json:"content,omitempty"`
	Cached     bool   `json:"cached"`
	ChunkCount int    `json:"chunkCount,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Error      string `json:"error,omitempty"`
}

// fetchArgs is the JSON schema for the ctx_fetch_and_index tool.
type fetchArgs struct {
	URL        string   `json:"url,omitempty" jsonschema:"Single URL to fetch"`
	URLs       []string `json:"urls,omitempty" jsonschema:"URLs to fetch (up to 10)"`
	Source     string   `json:"source,omitempty" jsonschema:"Label for indexed content"`
	Format     string   `json:"format,omitempty" jsonschema:"Output format (markdown/html/json, default markdown)"`
	Force      bool     `json:"force,omitempty" jsonschema:"Skip cache and re-fetch"`
	MaxBytes   int      `json:"maxBytes,omitempty" jsonschema:"Max bytes to return (default 50KB)"`
	TimeoutMs  int      `json:"timeoutMs,omitempty" jsonschema:"Timeout in ms (default 150000)"`
	TTL        *int     `json:"ttl,omitempty" jsonschema:"Cache TTL in ms (0 = skip cache, omit = 24h default)"`
} 

// ---------- SSRF validation ----------

// validateURL performs SSRF-protection checks on a URL.
// It verifies the scheme is http/https, resolves DNS, and checks the IP
// against blocklists.
func validateURL(rawURL string, strict bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed (only http/https)", u.Scheme)
	}

	host := u.Hostname()

	// Resolve DNS to check IP addresses.
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("DNS resolution failed for %q: %w", host, err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses found for %q", host)
	}

	for _, ip := range ips {
		if err := checkIP(ip, strict); err != nil {
			return fmt.Errorf("blocked IP %v for host %q: %w", ip, host, err)
		}
	}

	return nil
}

// checkIP returns an error if the IP is in a blocked range.
// Always blocked: 0.0.0.0/8 (unspecified), 127.0.0.0/8 (loopback),
// 169.254.0.0/16 (link-local/IMDS), 224.0.0.0/4 (multicast),
// 240.0.0.0/4 (reserved), 10.0.0.0/8 / 172.16.0.0/12 / 192.168.0.0/16 (private),
// 100.64.0.0/10 (CGNAT), 198.18.0.0/15 (benchmark),
// IPv6 link-local, unspecified, and multicast.
// Strict mode (CTX_FETCH_STRICT=1): additionally blocks IPv6 loopback (::1)
// and IPv6 private addresses.
func checkIP(ip net.IP, strict bool) error {
	if ip == nil {
		return fmt.Errorf("nil IP")
	}

	// Normalize to IPv4 if IPv4-mapped IPv6.
	v4 := ip.To4()

	if v4 != nil {
		// 0.0.0.0/8 — "unspecified" / "this network" (RFC 791)
		if v4[0] == 0 {
			return fmt.Errorf("0.0.0.0/8 (unspecified address)")
		}
		// 127.0.0.0/8 — loopback
		if v4[0] == 127 {
			return fmt.Errorf("127.0.0.0/8 (loopback)")
		}
		// 169.254.0.0/16 — link-local / IMDS
		if v4[0] == 169 && v4[1] == 254 {
			return fmt.Errorf("169.254.0.0/16 (link-local / IMDS)")
		}
		// 224.0.0.0/4 — multicast
		if v4[0] >= 224 && v4[0] <= 239 {
			return fmt.Errorf("224.0.0.0/4 (multicast)")
		}
		// 240.0.0.0/4 — reserved (formerly Class E)
		if v4[0] >= 240 {
			return fmt.Errorf("240.0.0.0/4 (reserved)")
		}
		// 10.0.0.0/8 — private (RFC 1918)
		if v4[0] == 10 {
			return fmt.Errorf("10.0.0.0/8 (private)")
		}
		// 172.16.0.0/12 — private (RFC 1918)
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return fmt.Errorf("172.16.0.0/12 (private)")
		}
		// 192.168.0.0/16 — private (RFC 1918)
		if v4[0] == 192 && v4[1] == 168 {
			return fmt.Errorf("192.168.0.0/16 (private)")
		}
		// 100.64.0.0/10 — CGNAT (RFC 6598)
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return fmt.Errorf("100.64.0.0/10 (CGNAT)")
		}
		// 198.18.0.0/15 — benchmark / testing (RFC 2544)
		if v4[0] == 198 && v4[1] >= 18 && v4[1] <= 19 {
			return fmt.Errorf("198.18.0.0/15 (benchmark)")
		}
	} else {
		// IPv6
		if ip.IsLoopback() {
			if strict {
				return fmt.Errorf("::1 (IPv6 loopback) blocked in strict mode")
			}
			// In non-strict mode, allow loopback for testing convenience.
		}
		if ip.IsLinkLocalUnicast() {
			return fmt.Errorf("IPv6 link-local unicast (fe80::/10) blocked")
		}
		if ip.IsUnspecified() {
			return fmt.Errorf("IPv6 unspecified (::) blocked")
		}
		if ip.IsMulticast() {
			return fmt.Errorf("IPv6 multicast blocked")
		}
		if ip.IsPrivate() && strict {
			return fmt.Errorf("IPv6 private address blocked in strict mode")
		}
	}

	return nil
}

// ---------- HTTP client (singleton) ----------

// newHTTPClient creates the singleton HTTP client with SSRF protection,
// connection reuse, and simplified redirect checking.
// DialContext is the SSRF gate — it resolves DNS and checks IPs on every
// connection (including redirects). CheckRedirect only enforces max redirects
// and scheme whitelist (no redundant DNS or validateURL calls).
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				hostFromAddr, portFromAddr, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address %q: %w", addr, err)
				}

				ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostFromAddr)
				if err != nil {
					return nil, fmt.Errorf("DNS resolution in DialContext: %w", err)
				}

				strict := os.Getenv("CTX_FETCH_STRICT") == "1"
				var safeIP net.IP
				for _, ip := range ips {
					if err := checkIP(ip.IP, strict); err == nil {
						safeIP = ip.IP
						break
					}
				}
				if safeIP == nil {
					return nil, fmt.Errorf("all resolved IPs for %q blocked by SSRF rules", hostFromAddr)
				}

				safeAddr := net.JoinHostPort(safeIP.String(), portFromAddr)
				return (&net.Dialer{}).DialContext(ctx, network, safeAddr)
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects (max %d)", maxRedirects)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to scheme %q not allowed", req.URL.Scheme)
			}
			return nil
		},
	}
}

// ---------- HTTP fetch ----------

// fetchURL performs an HTTP GET request with redirect limits and body size limit.
// Uses the server-level singleton HTTP client for connection reuse (SSRF via DialContext).
func (s *server) fetchURL(ctx context.Context, rawURL string, timeout time.Duration) (body []byte, contentType string, truncated bool, err error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("create request: %w", err)
	}

	// Set a friendly User-Agent.
	req.Header.Set("User-Agent", "ctxmode/1.0 (MCP context server)")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body with size limit + 1 to detect truncation.
	limited := io.LimitReader(resp.Body, maxBodySize+1)
	body, err = io.ReadAll(limited)
	if err != nil {
		return nil, "", false, fmt.Errorf("read body: %w", err)
	}
	truncated = len(body) > maxBodySize
	if truncated {
		body = body[:maxBodySize]
	}

	contentType = resp.Header.Get("Content-Type")
	// Clean up content type (strip charset etc).
	if idx := strings.Index(contentType, ";"); idx > 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}

	return body, contentType, truncated, nil
}

// ---------- content processing ----------

// processContent converts raw bytes into indexable text based on explicit format
// (when non-empty) or Content-Type detection as fallback.
func processContent(body []byte, contentType, format string, truncated bool) (string, error) {
	// Clean Content-Type: case-insensitive matching.
	ct := strings.ToLower(strings.TrimSpace(contentType))
	// If format is explicitly specified, use it.
	if format != "" {
		switch format {
		case "markdown":
			return htmlToMarkdown(body)
		case "html":
			return string(body), nil
		case "json":
			return formatJSON(body, truncated)
		default:
			return "", fmt.Errorf("unknown format: %q", format)
		}
	}
	// Fallback: detect from Content-Type.
	switch {
	case strings.Contains(ct, "text/html"):
		return htmlToMarkdown(body)
	case strings.Contains(ct, "application/json"):
		return formatJSON(body, truncated)
	default:
		// text/plain, text/markdown, application/xml, etc.
		return string(body), nil
	}
}

// htmlToMarkdown converts HTML content to markdown using the html-to-markdown library.
func htmlToMarkdown(body []byte) (string, error) {
	mdContent, err := md.ConvertString(string(body))
	if err != nil {
		return "", fmt.Errorf("html-to-markdown conversion failed: %w", err)
	}
	return mdContent, nil
}

// formatJSON pretty-prints JSON content for indexing.
func formatJSON(body []byte, truncated bool) (string, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, body, "", "  "); err != nil {
		if truncated {
			return "", fmt.Errorf("JSON content was truncated and cannot be parsed")
		}
		// If it's not valid JSON, index as text
		return string(body), nil
	}
	return buf.String(), nil
}

// ---------- chunking ----------

// chunkContent splits content into chunks for indexing.
// Simple strategy: split by double newlines (paragraphs).
func chunkContent(content string) []string {
	const maxChunkSize = 4000

	// First split by double newlines (paragraphs).
	paragraphs := strings.Split(content, "\n\n")

	var chunks []string
	var current strings.Builder

	for _, p := range paragraphs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if current.Len() > 0 && current.Len()+len(p)+2 > maxChunkSize {
			chunks = append(chunks, current.String())
			current.Reset()
		}

		if current.Len() > 0 {
			current.WriteString("\n\n")
		}
		current.WriteString(p)
	}

	if current.Len() > 0 {
		chunks = append(chunks, current.String())
	}

	// If we got no chunks (e.g., all whitespace), return the original as one chunk.
	if len(chunks) == 0 {
		return []string{content}
	}

	return chunks
}

// ---------- fetch and index (single URL) ----------

// fetchAndIndex fetches a URL, processes the content, and indexes it into the store.
func (s *server) fetchAndIndex(ctx context.Context, rawURL, source, format string, force bool, ttl int, timeout time.Duration) (*FetchResult, error) {
	result := &FetchResult{
		URL:    rawURL,
		Source: source,
	}

	// Determine effective TTL.
	// ttl=-1 means use default (24h), ttl=0 means skip cache entirely.
	// force=true skips cache read (forced re-fetch) but still writes back to refresh cache.
	// S24: split skipCache into skipCacheRead (force || ttl==0) and skipCacheWrite (ttl==0 only).
	effectiveTTL := defaultTTL
	skipCacheRead := force
	skipCacheWrite := false
	if ttl >= 0 {
		if ttl == 0 {
			skipCacheRead = true
			skipCacheWrite = true
		} else {
			effectiveTTL = time.Duration(ttl) * time.Millisecond
		}
	}

	// Build cache key with format dimension (S26).
	cacheSource := source + "|" + format

	if !skipCacheRead {
		cached, err := s.store.GetCached(rawURL, cacheSource)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cache lookup error: %v\n", err)
		}
		if cached != nil {
			age := time.Now().Unix() - cached.FetchedAt
			if time.Duration(age)*time.Second < effectiveTTL {
				result.Content = cached.Content
				result.Cached = true
				result.ChunkCount = countChunks(cached.Content)
				return result, nil
			}
		}
	}

	// SSRF validation.
	strict := os.Getenv("CTX_FETCH_STRICT") == "1"
	if err := validateURL(rawURL, strict); err != nil {
		result.Error = fmt.Sprintf("SSRF check failed: %v", err)
		return result, nil
	}

	// Check context before proceeding.
	if err := ctx.Err(); err != nil {
		result.Error = fmt.Sprintf("cancelled: %v", err)
		return result, nil
	}

	// Fetch, process, and index.
	// skipCacheWrite=true (ttl==0): direct fetch (no singleflight merge, no cache write).
	// skipCacheWrite=false (normal or force): use singleflight to merge concurrent fetches for the same URL+source.
	if skipCacheWrite {
		body, contentType, truncated, err := s.fetchURL(ctx, rawURL, timeout)
		if err != nil {
			result.Error = fmt.Sprintf("fetch failed: %v", err)
			return result, nil
		}
		result.Truncated = truncated

		content, err := processContent(body, contentType, format, truncated)
		if err != nil {
			result.Error = fmt.Sprintf("content processing failed: %v", err)
			return result, nil
		}
		result.Content = content

		// Index into store.
		docPath := source + ":" + rawURL
		chunks := chunkContent(content)
		result.ChunkCount = len(chunks)
		for i, chunk := range chunks {
			chunkPath := docPath
			if len(chunks) > 1 {
				chunkPath = fmt.Sprintf("%s#chunk-%d", docPath, i)
			}
			if err := s.storeIndexLocked(chunkPath, chunk); err != nil {
				fmt.Fprintf(os.Stderr, "index chunk %d failed: %v\n", i, err)
			}
		}
		// skipCacheWrite=true: no cache write.
		return result, nil
	}

	// skipCacheWrite=false: use singleflight to merge concurrent fetches.
	sfKey := rawURL + "|" + cacheSource
	var sfTruncated bool
	sfResult, err, _ := fetchGroup.Do(sfKey, func() (interface{}, error) {
		body, contentType, truncated, err := s.fetchURL(ctx, rawURL, timeout)
		if err != nil {
			return nil, fmt.Errorf("fetch failed: %w", err)
		}
		sfTruncated = truncated

		content, err := processContent(body, contentType, format, truncated)
		if err != nil {
			return nil, fmt.Errorf("content processing failed: %w", err)
		}

		// Index into store.
		docPath := source + ":" + rawURL
		chunks := chunkContent(content)
		for i, chunk := range chunks {
			chunkPath := docPath
			if len(chunks) > 1 {
				chunkPath = fmt.Sprintf("%s#chunk-%d", docPath, i)
			}
			if err := s.storeIndexLocked(chunkPath, chunk); err != nil {
				fmt.Fprintf(os.Stderr, "index chunk %d failed: %v\n", i, err)
			}
		}

		// Write to cache (with mutex protection).
		s.mu.Lock()
		if err := s.store.SetCache(rawURL, cacheSource, content); err != nil {
			fmt.Fprintf(os.Stderr, "cache write failed: %v\n", err)
		}
		_ = s.store.PruneCache(7 * 24 * time.Hour)
		s.mu.Unlock()

		return &fetchResultData{content: content, chunkCount: len(chunks), truncated: truncated}, nil
	})
	if err != nil {
		result.Error = err.Error()
		result.Truncated = sfTruncated
		return result, nil
	}
	data := sfResult.(*fetchResultData)
	result.Content = data.content
	result.ChunkCount = data.chunkCount
	result.Truncated = data.truncated

	return result, nil
}

// countChunks counts how many chunks a content would produce (for reporting).
func countChunks(content string) int {
	return len(chunkContent(content))
}

// ---------- batch fetch (multiple URLs) ----------

// batchFetchAndIndex fetches and indexes multiple URLs concurrently.
// Results are returned in the same order as the input URLs.
// Concurrency is limited by a semaphore (max 8).
func (s *server) batchFetchAndIndex(ctx context.Context, urls []string, source, format string, force bool, ttl int, timeout time.Duration) []*FetchResult {
	if len(urls) == 0 {
		return nil
	}

	// Limit concurrency.
	concurrency := maxConcurrency
	if len(urls) < concurrency {
		concurrency = len(urls)
	}

	sem := make(chan struct{}, concurrency)
	results := make([]*FetchResult, len(urls))
	var wg sync.WaitGroup

	for i, u := range urls {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			// Check context cancellation.
			if err := ctx.Err(); err != nil {
				results[idx] = &FetchResult{
					URL:   url,
					Error: fmt.Sprintf("cancelled: %v", err),
				}
				return
			}

			result, err := s.fetchAndIndex(ctx, url, source, format, force, ttl, timeout)
			if err != nil {
				results[idx] = &FetchResult{
					URL:   url,
					Error: err.Error(),
				}
			} else {
				results[idx] = result
			}
		}(i, u)
	}

	wg.Wait()
	return results
}

// ---------- MCP tool handler ----------

func (s *server) toolFetchAndIndex(ctx context.Context, _ *mcp.CallToolRequest, args fetchArgs) (*mcp.CallToolResult, any, error) {
	// Collect and deduplicate URLs.
	seen := make(map[string]bool)
	var urls []string
	if args.URL != "" {
		if !seen[args.URL] {
			seen[args.URL] = true
			urls = append(urls, args.URL)
		}
	}
	for _, u := range args.URLs {
		if u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	if len(urls) == 0 {
		return nil, nil, fmt.Errorf("at least one non-empty URL is required in 'url' or 'urls'")
	}

	if len(urls) > 10 {
		return nil, nil, fmt.Errorf("maximum 10 URLs per call")
	}

	// Validate format before fetching.
	if args.Format != "" && args.Format != "markdown" && args.Format != "html" && args.Format != "json" {
		return nil, nil, fmt.Errorf("format must be markdown, html, or json, got %q", args.Format)
	}

	// Default timeout.
	timeout := defaultFetchTimeout
	if args.TimeoutMs > 0 {
		timeout = time.Duration(args.TimeoutMs) * time.Millisecond
	}

	// Resolve TTL: nil means use default (24h), 0 means skip cache.
	ttl := -1 // sentinel: use default 24h TTL
	if args.TTL != nil {
		ttl = *args.TTL // may be 0 (skip cache) or positive (custom ms)
	}

	// Batch fetch.
	results := s.batchFetchAndIndex(ctx, urls, args.Source, args.Format, args.Force, ttl, timeout)

	// Apply maxBytes limit to returned content.
	maxBytes := defaultMaxBytes
	if args.MaxBytes > 0 {
		maxBytes = args.MaxBytes
	}
	if maxBytes > 200*1024 {
		maxBytes = 200 * 1024 // cap at 200KB
	}

	// Build response summary.
	var summaryLines []string
	totalChunks := 0
	successCount := 0
	cacheHitCount := 0

	for _, r := range results {
		if r == nil {
			continue
		}
		status := "✅ fetched"
		if r.Cached {
			status = "💾 cached"
			cacheHitCount++
		}
		if r.Error != "" {
			status = "❌ " + r.Error
		} else {
			successCount++
		}

		chunkInfo := ""
		if r.ChunkCount > 0 {
			chunkInfo = fmt.Sprintf(" (%d chunks)", r.ChunkCount)
			totalChunks += r.ChunkCount
		}

		summaryLines = append(summaryLines, fmt.Sprintf("- %s %s%s", status, r.URL, chunkInfo))
	}

	// Build the search hint.
	searchHint := ""
	if successCount > 0 {
		searchHint = fmt.Sprintf("\n\nIndexed content is searchable via ctx_search. Use queries like %q to find specific sections.", args.Source+":*")
	}

	// Truncate individual contents and build the full response.
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Fetched %d URL(s): %d successful, %d cache hits, %d total chunks\n\n",
		len(results), successCount, cacheHitCount, totalChunks))
	builder.WriteString(strings.Join(summaryLines, "\n"))
	builder.WriteString(searchHint)

	// If it was a single URL and successful, include the content preview.
	if len(results) == 1 && results[0] != nil && results[0].Error == "" && results[0].Content != "" {
		content := results[0].Content
		if len(content) > maxBytes {
			content = truncateUTF8(content, maxBytes) + "\n... (truncated)"
		}
		builder.WriteString("\n\n--- Content ---\n")
		builder.WriteString(content)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: builder.String()}},
	}, nil, nil
}
