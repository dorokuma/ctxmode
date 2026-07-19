package main

import (
	"bytes"
	"context"
	"crypto/tls"
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

	md "github.com/JohannesKaufmann/html-to-markdown/v2"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- constants ----------

const (
	defaultFetchTimeout = 150 * time.Second
	maxRedirects       = 5
	maxBodySize        = 50 * 1024 * 1024 // 50 MB
	defaultMaxBytes    = 50 * 1024        // 50 KB return limit
	defaultTTL         = 24 * time.Hour
	maxConcurrency     = 8
)

// ---------- data types ----------

// FetchResult holds the result of fetching and indexing a single URL.
type FetchResult struct {
	URL        string `json:"url"`
	Source     string `json:"source"`
	Content    string `json:"content,omitempty"`
	Cached     bool   `json:"cached"`
	ChunkCount int    `json:"chunkCount,omitempty"`
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
	Links      bool     `json:"links,omitempty" jsonschema:"Include page hyperlinks (not yet implemented)"`
	ImageLinks bool     `json:"image_links,omitempty" jsonschema:"Include image URLs (not yet implemented)"`
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
// Hard-blocked: 169.254.x.x (link-local/IMDS), 224.0.0.0/4 (multicast),
// 0.0.0.0/8 (unspecified), 127.0.0.0/8 (loopback).
// Strict mode: additionally blocks 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
// and IPv6 loopback (::1).
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

		if strict {
			// 10.0.0.0/8 — private
			if v4[0] == 10 {
				return fmt.Errorf("10.0.0.0/8 (private) blocked in strict mode")
			}
			// 172.16.0.0/12 — private
			if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
				return fmt.Errorf("172.16.0.0/12 (private) blocked in strict mode")
			}
			// 192.168.0.0/16 — private
			if v4[0] == 192 && v4[1] == 168 {
				return fmt.Errorf("192.168.0.0/16 (private) blocked in strict mode")
			}
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

// ---------- HTTP fetch ----------

// fetchURL performs an HTTP GET request with redirect limits and body size limit.
// It includes DNS rebinding protection: DNS is resolved inside DialContext and
// the resolved IP is verified against SSRF rules right before connecting, closing
// the TOCTOU window between validateURL and the actual TCP connection.
func fetchURL(ctx context.Context, rawURL string, timeout time.Duration) (body []byte, contentType string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", fmt.Errorf("parse URL: %w", err)
	}
	host := u.Hostname()
	strict := os.Getenv("CTX_FETCH_STRICT") == "1"

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("create request: %w", err)
	}

	// Set a friendly User-Agent.
	req.Header.Set("User-Agent", "ctxmode/1.0 (MCP context server)")

	dialer := &net.Dialer{}

	// Use a custom transport that resolves DNS inside DialContext and verifies
	// the resolved IP is safe. This prevents DNS rebinding attacks (TOCTOU
	// between validateURL above and the actual TCP connection).
	cli := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Re-resolve DNS inside DialContext to close TOCTOU window.
				hostFromAddr, portFromAddr, err := net.SplitHostPort(addr)
				if err != nil {
					hostFromAddr = addr
					if u.Scheme == "https" {
						portFromAddr = "443"
					} else {
						portFromAddr = "80"
					}
				}

				ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostFromAddr)
				if err != nil {
					return nil, fmt.Errorf("DNS resolution in DialContext: %w", err)
				}

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
				return dialer.DialContext(ctx, network, safeAddr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: host, // SNI: original hostname for TLS virtual hosting
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects (max %d)", maxRedirects)
			}
			// Validate redirect target for SSRF.
			if err := validateURL(req.URL.String(), strict); err != nil {
				return fmt.Errorf("redirect blocked by SSRF check: %w", err)
			}
			return nil
		},
	}

	resp, err := cli.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body with size limit.
	limited := io.LimitReader(resp.Body, maxBodySize)
	body, err = io.ReadAll(limited)
	if err != nil {
		return nil, "", fmt.Errorf("read body: %w", err)
	}

	contentType = resp.Header.Get("Content-Type")
	// Clean up content type (strip charset etc).
	if idx := strings.Index(contentType, ";"); idx > 0 {
		contentType = strings.TrimSpace(contentType[:idx])
	}

	return body, contentType, nil
}

// ---------- content processing ----------

// processContent converts raw bytes into indexable markdown/text based on content type.
func processContent(body []byte, contentType string) (string, error) {
	switch {
	case strings.Contains(contentType, "text/html"):
		return htmlToMarkdown(body)
	case strings.Contains(contentType, "application/json"):
		return formatJSON(body)
	default:
		// text/plain, text/markdown, application/xml, etc.
		return string(body), nil
	}
}

// htmlToMarkdown converts HTML content to markdown using the html-to-markdown library.
func htmlToMarkdown(body []byte) (string, error) {
	mdContent, err := md.ConvertString(string(body))
	if err != nil {
		// Fallback: try basic text extraction
		return string(body), nil
	}
	return mdContent, nil
}

// formatJSON pretty-prints JSON content for indexing.
func formatJSON(body []byte) (string, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, body, "", "  "); err != nil {
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
func (s *server) fetchAndIndex(ctx context.Context, rawURL, source string, force bool, ttl int, timeout time.Duration) (*FetchResult, error) {
	result := &FetchResult{
		URL:    rawURL,
		Source: source,
	}

	// Determine effective TTL.
	// ttl=-1 means use default (24h), ttl=0 means skip cache.
	effectiveTTL := defaultTTL
	skipCache := force
	if ttl >= 0 {
		if ttl == 0 {
			skipCache = true
		} else {
			effectiveTTL = time.Duration(ttl) * time.Millisecond
		}
	}

	if !skipCache {
		cached, err := s.store.GetCached(rawURL, source)
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

	// Fetch.
	body, contentType, err := fetchURL(ctx, rawURL, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("fetch failed: %v", err)
		return result, nil
	}

	// Process content.
	content, err := processContent(body, contentType)
	if err != nil {
		result.Error = fmt.Sprintf("content processing failed: %v", err)
		return result, nil
	}

	result.Content = content

	// Index into store.
	// Use source:url as the document path for uniqueness.
	docPath := source + ":" + rawURL

	// For indexing, we chunk the content for better search granularity.
	chunks := chunkContent(content)
	result.ChunkCount = len(chunks)

	for i, chunk := range chunks {
		chunkPath := docPath
		if len(chunks) > 1 {
			chunkPath = fmt.Sprintf("%s#chunk-%d", docPath, i)
		}
		if err := s.storeIndexLocked(chunkPath, chunk); err != nil {
			// Log but continue with remaining chunks.
			fmt.Fprintf(os.Stderr, "index chunk %d failed: %v\n", i, err)
		}
	}

	// Write to cache (with mutex protection against concurrent fetch goroutines).
	s.mu.Lock()
	if err := s.store.SetCache(rawURL, source, content); err != nil {
		fmt.Fprintf(os.Stderr, "cache write failed: %v\n", err)
	}
	// Prune old cache entries occasionally (every fetch, but cheap DELETE).
	_ = s.store.PruneCache(7 * 24 * time.Hour)
	s.mu.Unlock()

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
func (s *server) batchFetchAndIndex(ctx context.Context, urls []string, source string, force bool, ttl int, timeout time.Duration) []*FetchResult {
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

			result, err := s.fetchAndIndex(ctx, url, source, force, ttl, timeout)
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
	// Collect URLs to fetch.
	var urls []string
	if args.URL != "" {
		urls = append(urls, args.URL)
	}
	if len(args.URLs) > 0 {
		urls = append(urls, args.URLs...)
	}

	if len(urls) == 0 {
		return nil, nil, fmt.Errorf("either 'url' or 'urls' is required")
	}

	if len(urls) > 10 {
		return nil, nil, fmt.Errorf("maximum 10 URLs per call")
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
	results := s.batchFetchAndIndex(ctx, urls, args.Source, args.Force, ttl, timeout)

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
