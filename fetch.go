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
	"regexp"
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
	defaultTTL          = 24 * time.Hour
	maxConcurrency      = 8
)

// fetchGroup deduplicates concurrent fetches for the same URL+source.
var fetchGroup singleflight.Group

// fetchResultData carries results between singleflight-merged callers.
type fetchResultData struct {
	content    string
	chunkCount int
	truncated  bool
	indexError string
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
	IndexError string `json:"indexError,omitempty"`
}

// fetchArgs is the JSON schema for the ctx_kb fetch tool.
type fetchArgs struct {
	URL       string   `json:"url,omitempty" jsonschema:"Single URL to fetch"`
	URLs      []string `json:"urls,omitempty" jsonschema:"URLs to fetch (up to 10)"`
	Source    string   `json:"source,omitempty" jsonschema:"Label for indexed content"`
	Format    string   `json:"format,omitempty" jsonschema:"Output format (markdown/html/json, default markdown)"`
	Force     bool     `json:"force,omitempty" jsonschema:"Skip cache and re-fetch"`
	MaxBytes  int      `json:"maxBytes,omitempty" jsonschema:"Max bytes to return (default 50KB)"`
	TimeoutMs int      `json:"timeoutMs,omitempty" jsonschema:"Timeout in ms (default 150000)"`
	TTL       *int     `json:"ttl,omitempty" jsonschema:"Cache TTL in ms (0 = skip cache, omit = 24h default)"`
}

// ---------- SSRF validation ----------

const dnsValidationTimeout = 5 * time.Second

// validateURL performs SSRF-protection checks on a URL.
// It verifies the context, scheme (http/https), resolves DNS with a short timeout,
// and checks the IP against blocklists. Multi-address hosts are allowed when at
// least one resolved IP is safe (aligned with DialContext, which also picks the
// first safe IP rather than requiring every address to pass).
func validateURL(ctx context.Context, rawURL string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed (only http/https)", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("empty host in URL")
	}

	// If host is already an IP literal, skip DNS resolution.
	if ip := net.ParseIP(host); ip != nil {
		if err := checkIP(ip); err != nil {
			return fmt.Errorf("blocked IP %v for host %q: %w", ip, host, err)
		}
		return nil
	}

	// Resolve DNS with a dedicated short timeout bounded by the request context.
	dnsCtx, cancel := context.WithTimeout(ctx, dnsValidationTimeout)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(dnsCtx, "ip", host)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("DNS resolution failed for %q: %w", host, err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses found for %q", host)
	}

	var firstErr error
	for _, ip := range ips {
		if err := checkIP(ip); err == nil {
			// At least one safe IP — DialContext will pick a safe address.
			return nil
		} else if firstErr == nil {
			firstErr = fmt.Errorf("blocked IP %v for host %q: %w", ip, host, err)
		}
	}
	return fmt.Errorf("all resolved IPs for %q blocked by SSRF rules: %v", host, firstErr)
}

// checkIPv4 returns an error if the IPv4 address is in a blocked range.
func checkIPv4(v4 net.IP) error {
	if len(v4) != 4 {
		v4 = v4.To4()
	}
	if v4 == nil {
		return fmt.Errorf("nil or non-IPv4 address")
	}
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
	return nil
}

// checkIP returns an error if the IP is in a blocked range.
// The blocklist is a single fixed set: 0.0.0.0/8 (unspecified), 127.0.0.0/8
// (loopback), 169.254.0.0/16 (link-local/IMDS), 224.0.0.0/4 (multicast),
// 240.0.0.0/4 (reserved), 10.0.0.0/8 / 172.16.0.0/12 / 192.168.0.0/16 (private),
// 100.64.0.0/10 (CGNAT), 198.18.0.0/15 (benchmark),
// IPv6 loopback (::1), IPv6 private (fc00::/7, RFC 4193), IPv6 link-local,
// unspecified, and multicast. IPv6 rules are symmetric with IPv4: loopback
// and private addresses are always blocked.
// Embedded IPv4 in IPv6 (mapped, compatible, NAT64, 6to4, Teredo, ISATAP) is decoded
// and checked against the IPv4 rules.
func checkIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("nil IP")
	}

	// Plain IPv4 (4-byte representation)
	if len(ip) == 4 {
		return checkIPv4(ip)
	}

	// IPv4-mapped IPv6 (e.g. ::ffff:192.0.2.1)
	if v4 := ip.To4(); v4 != nil {
		return checkIPv4(v4)
	}

	if len(ip) == net.IPv6len {
		// IPv6 standard checks
		if ip.IsLoopback() {
			return fmt.Errorf("::1 (IPv6 loopback) blocked")
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
		if ip.IsPrivate() {
			return fmt.Errorf("IPv6 private address (fc00::/7) blocked")
		}

		// IPv4-compatible ::a.b.c.d (deprecated; To4() does not decode these).
		// :: and ::1 are already handled above.
		if ipv6Zeros(ip, 0, 12) {
			if !(ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && (ip[15] == 0 || ip[15] == 1)) {
				if err := checkIPv4(net.IP(ip[12:16])); err != nil {
					return fmt.Errorf("IPv4-compatible embedded IP: %w", err)
				}
			}
		}

		// NAT64 well-known prefix 64:ff9b::/96 and RFC 8215 local-use 64:ff9b:1::/48
		if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b {
			if ipv6Zeros(ip, 4, 12) || (ip[4] == 0x00 && ip[5] == 0x01 && ipv6Zeros(ip, 6, 12)) {
				if err := checkIPv4(net.IP(ip[12:16])); err != nil {
					return fmt.Errorf("NAT64 embedded IP: %w", err)
				}
			}
		}

		// 6to4 2002:AABB:CCDD::/48 — bytes 2-5 are the IPv4 address.
		if ip[0] == 0x20 && ip[1] == 0x02 {
			if err := checkIPv4(net.IP(ip[2:6])); err != nil {
				return fmt.Errorf("6to4 embedded IP: %w", err)
			}
		}

		// Teredo 2001:0000::/32 (RFC 4380)
		// Bytes 0..3: 2001:0000 prefix
		// Bytes 4..7: Server IPv4
		// Bytes 8..9: Flags
		// Bytes 10..11: Port (XOR'd)
		// Bytes 12..15: Client IPv4 (XOR with 0xFFFFFFFF)
		if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 {
			serverV4 := net.IP(ip[4:8])
			if err := checkIPv4(serverV4); err != nil {
				return fmt.Errorf("Teredo server IPv4 blocked: %w", err)
			}
			clientV4 := net.IP{ip[12] ^ 0xff, ip[13] ^ 0xff, ip[14] ^ 0xff, ip[15] ^ 0xff}
			if err := checkIPv4(clientV4); err != nil {
				return fmt.Errorf("Teredo client IPv4 blocked: %w", err)
			}
		}

		// ISATAP (RFC 5214): interface identifier in bytes 8..11 is 00-00-5E-FE or 02-00-5E-FE
		if (ip[8] == 0x00 || ip[8] == 0x02) && ip[9] == 0x00 && ip[10] == 0x5e && ip[11] == 0xfe {
			isatapV4 := net.IP(ip[12:16])
			if err := checkIPv4(isatapV4); err != nil {
				return fmt.Errorf("ISATAP embedded IPv4 blocked: %w", err)
			}
		}
	}

	return nil
}

func ipv6Zeros(ip net.IP, start, end int) bool {
	for i := start; i < end; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return true
}

// embeddedIPv4 extracts an IPv4 address hidden inside IPv6 (mapped, deprecated
// compatible, NAT64 64:ff9b::/96, RFC 8215 local-use 64:ff9b:1::/48, 6to4
// 2002::/16, or ISATAP). Plain IPv4 is returned as-is.
func embeddedIPv4(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if len(ip) != net.IPv6len {
		return nil
	}
	// IPv4-compatible ::a.b.c.d (deprecated; To4() does not decode these).
	// :: and ::1 are IPv6 unspecified/loopback, not IPv4-compatible.
	if ipv6Zeros(ip, 0, 12) {
		if ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && (ip[15] == 0 || ip[15] == 1) {
			return nil
		}
		return net.IP(ip[12:16])
	}
	// NAT64 well-known prefix 64:ff9b::/96 and RFC 8215 local-use 64:ff9b:1::/48
	// (IPv4 in the last 32 bits, the /96 embedding used inside that /48).
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b {
		if ipv6Zeros(ip, 4, 12) || (ip[4] == 0x00 && ip[5] == 0x01 && ipv6Zeros(ip, 6, 12)) {
			return net.IP(ip[12:16])
		}
	}
	// 6to4 2002:AABB:CCDD::/48 — bytes 2-5 are the IPv4 address.
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IP(ip[2:6])
	}
	// ISATAP 0000:5efe / 0200:5efe
	if (ip[8] == 0x00 || ip[8] == 0x02) && ip[9] == 0x00 && ip[10] == 0x5e && ip[11] == 0xfe {
		return net.IP(ip[12:16])
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

				var safeIP net.IP
				for _, ip := range ips {
					if err := checkIP(ip.IP); err == nil {
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

	// Set a friendly User-Agent (version aligned with Version constant).
	req.Header.Set("User-Agent", "ctxmode/"+Version+" (MCP context server)")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("HTTP request failed: %s", redactUserinfoInText(err.Error()))
	}
	defer resp.Body.Close()

	// Non-2xx responses are errors — do not index error pages as content.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Drain a small amount of body for diagnostics then discard.
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil, "", false, fmt.Errorf("HTTP %d %s", resp.StatusCode, resp.Status)
	}

	// Read body with size limit + 1 to detect truncation.
	limited := io.LimitReader(resp.Body, maxBodySize+1)
	body, err = io.ReadAll(limited)
	if err != nil {
		return nil, "", false, fmt.Errorf("read body: %w", err)
	}
	truncated = len(body) > maxBodySize
	if truncated {
		// Cut at a valid UTF-8 boundary so the tail of the last rune is not
		// split into invalid bytes (truncateUTF8 backs off to the previous
		// rune boundary).
		body = []byte(truncateUTF8(string(body), maxBodySize))
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
			// Only run HTML→Markdown when content is actually HTML.
			// text/markdown, text/plain, etc. are returned as-is.
			if isHTMLContentType(ct) || looksLikeHTML(body) {
				return htmlToMarkdown(body)
			}
			return string(body), nil
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
	case isHTMLContentType(ct):
		return htmlToMarkdown(body)
	case strings.Contains(ct, "application/json"):
		return formatJSON(body, truncated)
	default:
		// text/plain, text/markdown, application/xml, etc.
		return string(body), nil
	}
}

// isHTMLContentType reports whether ct looks like HTML.
func isHTMLContentType(ct string) bool {
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

// looksLikeHTML does a cheap sniff when Content-Type is missing/misleading.
func looksLikeHTML(body []byte) bool {
	// Skip leading whitespace.
	i := 0
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r') {
		i++
	}
	if i >= len(body) {
		return false
	}
	// Strong document-level markers only in the opening bytes.
	// Do not treat arbitrary "<" or inline markdown HTML fragments as a full page.
	s := strings.ToLower(string(body[i:min(i+64, len(body))]))
	if strings.HasPrefix(s, "<!doctype html") || strings.HasPrefix(s, "<html") {
		return true
	}
	// Weaker openers (<head>/<body>) require additional structural HTML tags
	// in a larger window to avoid misclassifying markdown that happens to
	// start with those tokens or contains HTML snippets.
	if strings.HasPrefix(s, "<head") || strings.HasPrefix(s, "<body") {
		window := strings.ToLower(string(body[i:min(i+512, len(body))]))
		signals := 0
		for _, tag := range []string{
			"<html", "</html", "<head", "</head", "<body", "</body",
			"<meta", "<link", "<title", "<script", "<div", "<span",
		} {
			if strings.Contains(window, tag) {
				signals++
			}
		}
		// Need at least two distinct structural signals (the opener already counts).
		return signals >= 2
	}
	return false
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
// Simple strategy: split by double newlines (paragraphs). A single paragraph
// longer than maxChunkSize is force-split at UTF-8 boundaries so no chunk
// exceeds the size limit.
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

		// Oversized paragraph (e.g. a wall of text with no blank lines) must
		// be force-split instead of producing a single huge chunk.
		if len(p) > maxChunkSize {
			if current.Len() > 0 {
				chunks = append(chunks, current.String())
				current.Reset()
			}
			chunks = append(chunks, splitLongText(p, maxChunkSize)...)
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

// splitLongText splits s into pieces of at most max bytes, breaking only at
// valid UTF-8 rune boundaries (lossless: joining the pieces reproduces s).
func splitLongText(s string, max int) []string {
	var parts []string
	for len(s) > max {
		cut := truncateUTF8(s, max)
		if cut == "" {
			// Invalid UTF-8 leading byte; advance one byte to guarantee progress.
			cut = s[:1]
		}
		parts = append(parts, cut)
		s = s[len(cut):]
	}
	if len(s) > 0 {
		parts = append(parts, s)
	}
	return parts
}

// ---------- fetch and index (single URL) ----------

// indexContentLocked replaces the documents under docPath (source:format:url)
// with freshly chunked content: stale chunks from an earlier fetch are removed
// and new chunks are indexed atomically. All sensitive patterns are refused
// before any purge. If validation or indexing fails, existing documents are preserved.
// Returns the number of chunks written and the first indexing error, if any.
func (s *server) indexContentLocked(docPath, content string) (int, error) {
	if err := checkSensitiveContent(content); err != nil {
		return 0, err
	}
	chunks := chunkContent(content)
	for _, chunk := range chunks {
		if err := checkSensitiveContent(chunk); err != nil {
			return 0, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.ReplaceExactAndChunks(docPath, chunks); err != nil {
		return len(chunks), err
	}
	return len(chunks), nil
}

// storePurgePrefixLocked deletes all documents under a path prefix with the
// server mutex held (same serialization as storeIndexLocked).
func (s *server) storePurgePrefixLocked(prefix string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.store.PurgeByPrefix(prefix)
	return err
}

func (s *server) storePurgeExactAndChunksLocked(docPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.store.PurgeExactAndChunks(docPath)
	return err
}

// fetchDocPath builds the KB document path for a fetched URL. The format is
// embedded between source and URL so the same URL can coexist in the KB in
// several formats (markdown/html/json) without overwriting each other.
func fetchDocPath(source, format, rawURL string) string {
	return source + ":" + format + ":" + redactURLUserinfo(rawURL)
}

func (s *server) fetchDocPath(source, format, rawURL string) string {
	p := fetchDocPath(source, format, rawURL)
	if s != nil && s.sessionID != "" {
		return "session:" + s.sessionID + ":" + p
	}
	return p
}

// purgeLegacyFetchDocs removes documents that older versions indexed under
// the pre-format path scheme source:url. SSRF validation guarantees the URL
// part always starts with http:// or https://, so new-format paths
// (source:format:url) can never match: they carry the format segment right
// after the source. The LIKE prefix is bounded to one source and cannot
// spill into other sources. Returns the number of documents removed.
func (s *server) purgeLegacyFetchDocs(source string) (int, error) {
	// Escape LIKE wildcards so a source containing % or _ matches literally.
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(source)
	total := 0
	for _, scheme := range []string{"http://", "https://"} {
		s.mu.Lock()
		res, err := s.store.db.Exec(`DELETE FROM documents WHERE path LIKE ? ESCAPE '\'`, escaped+":"+scheme+"%")
		s.mu.Unlock()
		if err != nil {
			return total, fmt.Errorf("purge legacy fetch docs for %q: %w", source, err)
		}
		n, _ := res.RowsAffected()
		total += int(n)
	}
	return total, nil
}

// fetchAndIndex fetches a URL, processes the content, and indexes it into the store.
func stripURLFragment(raw string) string {
	if i := strings.Index(raw, "#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// redactURLUserinfo strips user:password from a URL so tokens are not stored
// in the KB, cache keys, or tool results. HTTP GET still uses the original.
func redactURLUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

// userinfoInURLRe matches http(s) userinfo (user or user:pass) so tokens can
// be stripped from error text that embeds the request URL.
var userinfoInURLRe = regexp.MustCompile(`(?i)(https?://)[^/\s?#]+@`)

func redactUserinfoInText(s string) string {
	return userinfoInURLRe.ReplaceAllString(s, "${1}")
}

func (s *server) fetchAndIndex(ctx context.Context, rawURL, source, format string, force bool, ttl int, timeout time.Duration) (*FetchResult, error) {
	rawURL = stripURLFragment(rawURL)
	requestURL := rawURL
	rawURL = redactURLUserinfo(rawURL)
	// Default source avoids path becoming ":{url}".
	if source == "" {
		source = "fetch"
	}

	// Upgrade cleanup: older versions indexed documents as source:url without
	// a format segment. Remove them for this source so search does not surface
	// stale duplicates; new source:format:url paths are never matched.
	if _, err := s.purgeLegacyFetchDocs(source); err != nil {
		fmt.Fprintf(os.Stderr, "legacy fetch doc cleanup failed: %v\n", err)
	}

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

				// The cache can outlive the indexed documents (e.g. after a
				// purge). Verify the document for this exact format still exists
				// in the KB and re-index it when missing, otherwise we'd report
				// a cache hit for content that search cannot find. Only this
				// format's document is checked/backfilled.
				docPath := s.fetchDocPath(source, format, rawURL)
				count, err := s.store.CountExactAndChunks(docPath)
				if err != nil || count == 0 {
					if _, err := s.indexContentLocked(docPath, cached.Content); err != nil {
						result.IndexError = fmt.Sprintf("cache hit re-index failed: %v", err)
						fmt.Fprintf(os.Stderr, "cache hit re-index failed for %q: %v\n", docPath, err)
					}
				}
				return result, nil
			}
		}
	}

	// SSRF validation.
	if err := validateURL(ctx, rawURL); err != nil {
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
		body, contentType, truncated, err := s.fetchURL(ctx, requestURL, timeout)
		if err != nil {
			result.Error = "fetch failed: " + redactUserinfoInText(err.Error())
			return result, nil
		}
		result.Truncated = truncated

		content, err := processContent(body, contentType, format, truncated)
		if err != nil {
			result.Error = fmt.Sprintf("content processing failed: %v", err)
			return result, nil
		}
		result.Content = content

		// Index into store: clear stale chunks for this source:format:url first
		// so a re-fetch with fewer chunks does not leave old chunks searchable.
		docPath := s.fetchDocPath(source, format, rawURL)
		chunkCount, indexErr := s.indexContentLocked(docPath, content)
		result.ChunkCount = chunkCount
		if indexErr != nil {
			result.IndexError = indexErr.Error()
			fmt.Fprintf(os.Stderr, "index %q failed: %v\n", docPath, indexErr)
		}
		// skipCacheWrite=true: no cache write.
		return result, nil
	}

	// skipCacheWrite=false: use singleflight to merge concurrent fetches.
	sfKey := rawURL + "|" + cacheSource
	sfResult, err, _ := fetchGroup.Do(sfKey, func() (interface{}, error) {
		// Use a context that does not inherit the caller's cancel: when the
		// first caller of a shared singleflight key times out or is cancelled,
		// later callers waiting on the same key must not be cancelled with it.
		// An independent timeout is still applied by fetchURL below.
		sfCtx := context.WithoutCancel(ctx)

		body, contentType, truncated, err := s.fetchURL(sfCtx, requestURL, timeout)
		if err != nil {
			// Error results still carry their state through the shared return
			// value (singleflight hands the same value to every waiter), so all
			// callers agree on Truncated instead of reading a closure-outer local.
			return &fetchResultData{truncated: truncated}, fmt.Errorf("fetch failed: %s", redactUserinfoInText(err.Error()))
		}

		content, err := processContent(body, contentType, format, truncated)
		if err != nil {
			return &fetchResultData{truncated: truncated}, fmt.Errorf("content processing failed: %w", err)
		}

		// Index into store: clear stale chunks for this source:format:url first
		// so a re-fetch with fewer chunks does not leave old chunks searchable.
		docPath := s.fetchDocPath(source, format, rawURL)
		chunkCount, indexErr := s.indexContentLocked(docPath, content)
		var indexErrString string
		if indexErr != nil {
			indexErrString = indexErr.Error()
			fmt.Fprintf(os.Stderr, "index %q failed: %v\n", docPath, indexErr)
		}

		// Write to cache (with mutex protection).
		s.mu.Lock()
		if err := s.store.SetCache(rawURL, cacheSource, content); err != nil {
			fmt.Fprintf(os.Stderr, "cache write failed: %v\n", err)
		}
		_ = s.store.PruneCache(7 * 24 * time.Hour)
		s.mu.Unlock()

		return &fetchResultData{content: content, chunkCount: chunkCount, truncated: truncated, indexError: indexErrString}, nil
	})
	if err != nil {
		result.Error = redactUserinfoInText(err.Error())
		// The error's state travels in the shared singleflight return value, so
		// the executing caller and every waiter see the same Truncated value.
		if data, ok := sfResult.(*fetchResultData); ok {
			result.Truncated = data.truncated
		}
		return result, nil
	}
	data := sfResult.(*fetchResultData)
	result.Content = data.content
	result.ChunkCount = data.chunkCount
	result.Truncated = data.truncated
	result.IndexError = data.indexError

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
					URL:   redactURLUserinfo(url),
					Error: fmt.Sprintf("cancelled: %v", err),
				}
				return
			}

			result, err := s.fetchAndIndex(ctx, url, source, format, force, ttl, timeout)
			if err != nil {
				results[idx] = &FetchResult{
					URL:   redactURLUserinfo(url),
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
		u := stripURLFragment(args.URL)
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	for _, raw := range args.URLs {
		u := stripURLFragment(raw)
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
		} else if r.IndexError != "" {
			// Content was fetched but indexing failed: it is not searchable.
			status = "❌ " + r.IndexError
		} else {
			successCount++
		}

		chunkInfo := ""
		if r.ChunkCount > 0 {
			chunkInfo = fmt.Sprintf(" (%d chunks)", r.ChunkCount)
			totalChunks += r.ChunkCount
		}
		if r.Truncated && r.Error == "" {
			chunkInfo += " [body truncated at 10MB — indexed content may be incomplete]"
		}

		summaryLines = append(summaryLines, fmt.Sprintf("- %s %s%s", status, r.URL, chunkInfo))
	}

	// Build the search hint.
	searchHint := ""
	if successCount > 0 {
		searchHint = fmt.Sprintf("\n\nIndexed content is searchable via ctx_kb action=search. Use queries like %q to find specific sections.", args.Source+":*")
	}

	// Truncate individual contents and build the full response.
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Fetched %d URL(s): %d successful, %d cache hits, %d total chunks\n\n",
		len(results), successCount, cacheHitCount, totalChunks))
	builder.WriteString(strings.Join(summaryLines, "\n"))
	builder.WriteString(searchHint)

	// If it was a single URL and successful, include the content preview.
	if len(results) == 1 && results[0] != nil && results[0].Error == "" && results[0].IndexError == "" && results[0].Content != "" {
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
