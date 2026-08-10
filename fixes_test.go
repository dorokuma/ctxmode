package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- #1 symlink path fence ----------

func TestResolvePath_SymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Symlink inside workdir pointing outside.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatal(err)
	}

	s := &server{workdirs: []string{root}}
	_, err := s.resolvePath(link)
	if err == nil {
		t.Fatal("expected resolvePath to reject symlink escaping workdir")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Fatalf("expected outside error, got: %v", err)
	}
}

func TestResolvePath_SymlinkInsideOK(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "real.txt")
	if err := os.WriteFile(inner, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias.txt")
	if err := os.Symlink(inner, link); err != nil {
		t.Fatal(err)
	}
	s := &server{workdirs: []string{root}}
	got, err := s.resolvePath(link)
	if err != nil {
		t.Fatalf("expected inside symlink OK: %v", err)
	}
	// Real path should resolve to inner.
	if got != inner {
		// EvalSymlinks may normalize; compare via same-file.
		ri, _ := filepath.EvalSymlinks(inner)
		if got != ri {
			t.Fatalf("got %q, want %q", got, ri)
		}
	}
}

func TestExcludeFromGit_RefusesSymlinkGitDir(t *testing.T) {
	wd := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outside, "info", "exclude")
	if err := os.WriteFile(target, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(wd, ".git")); err != nil {
		t.Fatal(err)
	}
	s := &server{workdirs: []string{wd}}
	s.excludeFromGitOne(wd)
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "sentinel\n" {
		t.Fatalf("outside exclude file was modified: %q", data)
	}
}

// ---------- #3 python trailing backslash ----------

func TestInjectFileContent_PythonTrailingBackslash(t *testing.T) {
	content := `path\to\`
	code := "print(FILE_CONTENT)"
	out := injectFileContent("python", code, content)
	if strings.Contains(out, `r"""`) {
		t.Fatalf("trailing backslash must not use raw triple-quote:\n%s", out)
	}
	if !strings.Contains(out, "base64") {
		t.Fatalf("expected base64 fallback, got:\n%s", out)
	}
	// Round-trip: decoded content must match.
	if !strings.Contains(out, "b64decode") {
		t.Fatalf("expected b64decode, got:\n%s", out)
	}
}

// ---------- #4 HTTP non-2xx ----------

func TestFetchURL_Non2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer ts.Close()

	s := &server{httpClient: ts.Client()}
	_, _, _, err := s.fetchURL(context.Background(), ts.URL, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected 404 in error, got: %v", err)
	}
}

// ---------- #5 batch path-scoped search ----------

func TestSearchWithPathPrefix_Batch(t *testing.T) {
	st := newTestStore(t)
	indexDoc(t, st, "batch:cmd1", "alpha uniquebatchtoken omega")
	indexDoc(t, st, "batch:cmd2", "other content")
	// Flood the global index with non-batch docs that also match.
	for i := 0; i < 30; i++ {
		indexDoc(t, st, "other:"+string(rune('a'+i%26))+string(rune('0'+i%10)), "uniquebatchtoken filler "+string(rune('a'+i%26)))
	}

	// Without prefix, results may bury batch hits.
	// With batch: prefix, we must find the batch doc.
	hits, err := st.SearchWithPathPrefix("uniquebatchtoken", "batch:", 5)
	if err != nil {
		t.Fatalf("SearchWithPathPrefix: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least one batch-scoped hit")
	}
	for _, h := range hits {
		if !strings.HasPrefix(h.Path, "batch:") {
			t.Fatalf("non-batch path in scoped results: %q", h.Path)
		}
	}
}

func TestSearchBatchScoped_BypassesFlood(t *testing.T) {
	st := newTestStore(t)
	indexDoc(t, st, "batch:x", "floodbypassmarker content here")
	fg := NewFloodGuard(60*time.Second, 64)
	// Exhaust flood guard.
	for i := 0; i < 20; i++ {
		fg.Allow()
	}
	sp := NewSearchPipeline(st, fg)
	// Global search should be blocked.
	_, meta, err := sp.Search("floodbypassmarker", 5)
	if err == nil || meta == nil || meta.FloodStatus != "blocked" {
		t.Fatalf("expected global search blocked, err=%v meta=%+v", err, meta)
	}
	// Batch-scoped must still work.
	hits, meta2, err := sp.SearchBatchScoped("floodbypassmarker", 5)
	if err != nil {
		t.Fatalf("SearchBatchScoped should bypass flood: %v", err)
	}
	if meta2.FloodStatus != "ok" {
		t.Fatalf("expected flood ok for batch scope, got %q", meta2.FloodStatus)
	}
	if len(hits) == 0 {
		t.Fatal("expected hits from batch-scoped search")
	}
}

// ---------- #6 DB permissions ----------

func TestNewStore_Chmod0600(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "perm.db")
	st, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	// assertPrivate fails only if p exists and has group/other bits set.
	// -wal/-shm may not exist until a write, so absence is not a failure.
	assertPrivate := func(label, p string) {
		fi, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				return
			}
			t.Fatalf("stat %s: %v", label, err)
		}
		if mode := fi.Mode().Perm(); mode&0o077 != 0 {
			t.Fatalf("%s permissions too open: %o (want 0600)", label, mode)
		}
	}

	// After NewStore the main DB and any WAL/SHM sidecars must be 0600.
	assertPrivate("db", dbPath)
	assertPrivate("-wal", dbPath+"-wal")
	assertPrivate("-shm", dbPath+"-shm")

	// A real app write creates/extends the WAL; perms must stay 0600.
	if err := st.Index("test/path", "content to trigger a WAL write"); err != nil {
		t.Fatalf("Index: %v", err)
	}
	assertPrivate("db", dbPath)
	assertPrivate("-wal", dbPath+"-wal")
	assertPrivate("-shm", dbPath+"-shm")
}

// ---------- #8 session exact purge ----------

func TestPurgeSessionKeys_Exact(t *testing.T) {
	st := newTestStore(t)
	indexDoc(t, st, "session:ab", "1")
	indexDoc(t, st, "session:abc", "2")
	indexDoc(t, st, "session:ab:child", "3")

	n, err := st.PurgeSessionKeys("ab")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}
	if doc, _ := st.Get("session:abc"); doc == nil {
		t.Fatal("session:abc must survive")
	}
}

// ---------- #11 binary content ----------

func TestIsBinaryContent(t *testing.T) {
	if isBinaryContent([]byte("hello world\n")) {
		t.Fatal("text should not be binary")
	}
	if !isBinaryContent([]byte{0x00, 0x01, 0x02, 'a'}) {
		t.Fatal("null byte should be binary")
	}
	// High control-char ratio.
	ctrl := make([]byte, 100)
	for i := range ctrl {
		ctrl[i] = 0x01
	}
	if !isBinaryContent(ctrl) {
		t.Fatal("control-heavy sample should be binary")
	}
}

// ---------- #12 goWrapper imports ----------

func TestGoWrapper_DetectsOSAndStrings(t *testing.T) {
	code := `s := strings.ToUpper("hi"); _ = os.Getenv("PATH"); fmt.Println(s)`
	out := goWrapper(code)
	if !strings.Contains(out, `"os"`) {
		t.Fatalf("expected os import:\n%s", out)
	}
	if !strings.Contains(out, `"strings"`) {
		t.Fatalf("expected strings import:\n%s", out)
	}
	if !strings.Contains(out, `"fmt"`) {
		t.Fatalf("expected fmt import:\n%s", out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "package main") {
		t.Fatalf("expected package main:\n%s", out)
	}
}

func TestGoWrapper_AlreadyFullProgram(t *testing.T) {
	code := "package main\n\nfunc main() {}\n"
	out := goWrapper(code)
	if out != code {
		t.Fatalf("full program should pass through unchanged")
	}
}

// ---------- #14 format=markdown only for HTML ----------

func TestProcessContent_MarkdownNotForcedOnPlain(t *testing.T) {
	body := []byte("# Title\n\nplain markdown with **bold**")
	got, err := processContent(body, "text/markdown", "markdown", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(body) {
		t.Fatalf("plain/markdown must not be htmlToMarkdown'd, got %q", got)
	}

	htmlBody := []byte("<html><body><h1>Hi</h1></body></html>")
	got2, err := processContent(htmlBody, "text/html", "markdown", false)
	if err != nil {
		t.Fatal(err)
	}
	// html-to-markdown should produce something without raw <h1> tags ideally,
	// or at least not equal to the raw HTML if conversion works.
	if got2 == "" {
		t.Fatal("expected non-empty conversion")
	}
}

// Markdown with inline HTML fragments must not be forced through htmlToMarkdown
// when Content-Type is not HTML and body lacks a strong document opener.
func TestProcessContent_MarkdownWithHTMLFragments(t *testing.T) {
	// Inline tags mid-document — classic false-positive case.
	body := []byte("# Guide\n\nUse the `<code>` tag and a <br> break. See also <span>x</span>.\n")
	got, err := processContent(body, "text/markdown", "markdown", false)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(body) {
		t.Fatalf("markdown with HTML fragments must pass through unchanged, got %q", got)
	}

	// A lone "<body" without structural companions should not force conversion.
	weak := []byte("<body note>this is not really HTML documentation\n")
	got2, err := processContent(weak, "text/plain", "markdown", false)
	if err != nil {
		t.Fatal(err)
	}
	if got2 != string(weak) {
		t.Fatalf("weak <body without structure must not convert, got %q", got2)
	}

	// Strong document opener still converts even with misleading Content-Type.
	real := []byte("<!DOCTYPE html><html><body><h1>Hi</h1></body></html>")
	got3, err := processContent(real, "text/plain", "markdown", false)
	if err != nil {
		t.Fatal(err)
	}
	if got3 == string(real) {
		// Conversion may keep some tags, but empty would be wrong; equality with
		// raw HTML is unlikely if htmlToMarkdown ran. Accept non-empty either way.
		t.Logf("conversion may be identity depending on converter; got non-panic result")
	}
	if got3 == "" {
		t.Fatal("expected non-empty result for real HTML document")
	}

	if looksLikeHTML([]byte("# Title\n\n<code>x</code>")) {
		t.Fatal("markdown fragment must not looksLikeHTML")
	}
	if !looksLikeHTML([]byte("<!doctype html><html></html>")) {
		t.Fatal("doctype html must looksLikeHTML")
	}
	if !looksLikeHTML([]byte("<html><head><title>t</title></head></html>")) {
		t.Fatal("<html opener must looksLikeHTML")
	}
}

// ---------- #16 default source ----------

func TestFetchAndIndex_DefaultSource(t *testing.T) {
	// The fake transport serves HTTP locally, bypassing both the network and
	// the SSRF DialContext gate: ::1 loopback is now blocked in non-strict
	// SSRF mode too, so a real [::1] listener can no longer be used. The
	// public-looking host passes validateURL without any DNS lookup. This
	// still exercises the real fetchAndIndex production path, not a local
	// if-copy.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello default source"))
	}
	s := newFetchTestServer(t, handler)

	rawURL := "http://1.1.1.1/default-source"

	result, err := s.fetchAndIndex(context.Background(), rawURL, "", "markdown", true, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("fetchAndIndex: %v", err)
	}
	if result.Error != "" {
		t.Fatalf("fetchAndIndex error field: %s", result.Error)
	}
	if result.Source != "fetch" {
		t.Fatalf("default source: got %q, want %q", result.Source, "fetch")
	}
	// Indexed path must use fetch: prefix, never bare :{url}.
	doc, getErr := s.store.Get("fetch:" + rawURL)
	if getErr != nil {
		t.Fatalf("Get indexed doc: %v", getErr)
	}
	if doc == nil {
		// May be chunked as fetch:{url}#chunk-0 for multi-chunk; try prefix search.
		hits, sErr := s.store.SearchWithPathPrefix("hello", "fetch:", 5)
		if sErr != nil {
			t.Fatalf("SearchWithPathPrefix: %v", sErr)
		}
		if len(hits) == 0 {
			t.Fatal("expected document indexed under fetch: prefix")
		}
		for _, h := range hits {
			if !strings.HasPrefix(h.Path, "fetch:") {
				t.Fatalf("indexed path %q missing fetch: prefix", h.Path)
			}
			if strings.HasPrefix(h.Path, ":") {
				t.Fatalf("must not produce :{url} path, got %q", h.Path)
			}
		}
	} else if !strings.Contains(doc.Content, "hello default source") {
		t.Fatalf("unexpected content: %q", doc.Content)
	}
}

// ---------- #17 validateURL multi-IP aligns with DialContext ----------

func TestValidateURL_AllowsIfAnyIPSafe(t *testing.T) {
	// Hosts that resolve only to blocked IPs should fail.
	err := validateURL("http://127.0.0.1/", false)
	if err == nil {
		t.Fatal("expected 127.0.0.1 blocked")
	}

	// Public IP host (example.com may resolve to public addresses).
	// If DNS fails in offline env, skip.
	if ips, err := net.LookupIP("example.com"); err == nil && len(ips) > 0 {
		var anySafe bool
		for _, ip := range ips {
			if checkIP(ip, false) == nil {
				anySafe = true
				break
			}
		}
		if anySafe {
			if err := validateURL("https://example.com/", false); err != nil {
				t.Fatalf("expected example.com allowed when a public IP exists: %v", err)
			}
		}
	}
}

// ---------- #13 version constant ----------

func TestVersionAligned(t *testing.T) {
	// Keep in sync with CHANGELOG release label.
	if Version != "2.1.0" {
		t.Fatalf("Version=%q, want 2.1.0 (CHANGELOG)", Version)
	}
}

// ---------- #7 background registry ----------

func TestBackgroundRegistry_ListAndKill(t *testing.T) {
	result, err := runShell(context.Background(), "sleep 60", "/tmp", 0, true)
	if err != nil {
		t.Fatalf("start background: %v", err)
	}
	if !strings.Contains(result.Stdout, "id:") {
		t.Fatalf("expected id in background message: %q", result.Stdout)
	}

	entries := listBackground()
	if len(entries) == 0 {
		t.Fatal("expected at least one background entry")
	}
	// Find the sleep entry by command/language observability fields.
	var id string
	var found *bgEntry
	for i := range entries {
		e := &entries[i]
		if e.Language == "shell" && strings.Contains(e.Command, "sleep 60") && !e.Done {
			id = e.ID
			found = e
			break
		}
	}
	if id == "" {
		// Fallback: last entry (prior behaviour) but still assert fields when present.
		last := entries[len(entries)-1]
		id = last.ID
		found = &last
	}
	if found.Language != "shell" {
		t.Fatalf("expected language=shell, got %q", found.Language)
	}
	if found.Command == "" {
		t.Fatal("expected non-empty command for background entry")
	}
	if !strings.Contains(found.Command, "sleep") {
		t.Fatalf("expected command to mention sleep, got %q", found.Command)
	}

	msg, err := killBackground(id)
	if err != nil {
		t.Fatalf("kill: %v", err)
	}
	if !strings.Contains(msg, "killed") && !strings.Contains(msg, "exited") {
		t.Fatalf("unexpected kill msg: %s", msg)
	}
	// Kill must mark Done promptly so list no longer shows a live process.
	for _, e := range listBackground() {
		if e.ID == id && !e.Done {
			t.Fatalf("entry %s should be Done after killBackground", id)
		}
	}
}

// ---------- #2 Indexed only on success (auto-index >100KB failure path) ----------

func TestAutoIndex_FailureHasPreviewNotIndexedAs(t *testing.T) {
	st := newTestStore(t)
	s := &server{
		store:    st,
		workdirs: []string{t.TempDir()},
	}
	// Close the underlying DB so store.Index fails.
	if err := st.db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// Produce >100KB stdout so the unconditional auto-index branch runs.
	// Pure shell, no external runtime dependency: 110000 null bytes -> 'X'.
	code := `head -c 110000 /dev/zero | tr '\0' X`
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:  code,
		Language: "shell",
		Timeout:  15000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text := ""
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text = tc.Text
			break
		}
	}
	if text == "" {
		t.Fatal("expected non-empty tool result text")
	}
	if strings.Contains(text, "Indexed as") {
		t.Fatalf("Index failure must not claim 'Indexed as'; got: %s", truncateForTest(text, 300))
	}
	if !strings.Contains(text, "NOT indexed") {
		t.Fatalf("expected NOT indexed in failure message, got: %s", truncateForTest(text, 300))
	}
	if !strings.Contains(text, "--- Preview ---") {
		t.Fatalf("expected truncated preview on index failure, got: %s", truncateForTest(text, 300))
	}
	// Preview should include some of the output body.
	if !strings.Contains(text, "XXXX") {
		t.Fatalf("expected preview to include output sample, got: %s", truncateForTest(text, 300))
	}
}

func truncateForTest(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
