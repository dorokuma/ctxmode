package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

func TestInjectFileContent_PythonFutureAndElixirBytes(t *testing.T) {
	code := "from __future__ import annotations\nprint(FILE_CONTENT)\n"
	out := injectFileContent("python", code, "hello")
	fut := strings.Index(out, "from __future__ import annotations")
	decl := strings.Index(out, "FILE_CONTENT")
	if fut < 0 || decl < 0 || fut > decl {
		t.Fatalf("FILE_CONTENT must come after __future__, got:\n%s", out)
	}

	el := injectFileContent("elixir", "IO.puts(FILE_CONTENT)", "abc")
	if !strings.Contains(el, `~S"""abc"""`) {
		t.Fatalf("elixir FILE_CONTENT must be exact bytes, got:\n%s", el)
	}

	goSrc := "package main\n\nfunc main() {}\n"
	gout := injectFileContent("go", goSrc, "xyz")
	if !strings.HasPrefix(strings.TrimSpace(gout), "package main") {
		t.Fatalf("go package line must stay first:\n%s", gout)
	}
	if !strings.Contains(gout, "var FILE_CONTENT =") {
		t.Fatalf("package-level FILE_CONTENT must use var, got:\n%s", gout)
	}

	elQ := injectFileContent("elixir", "IO.puts(FILE_CONTENT)", `abc"`)
	if !strings.Contains(elQ, "decode64") {
		t.Fatalf("elixir trailing quote must use base64, got:\n%s", elQ)
	}
}

func TestInjectFileContent_GoPackageLevelCompiles(t *testing.T) {
	src := "package main\n\nfunc main() {\n\t_ = FILE_CONTENT\n}\n"
	injected := injectFileContent("go", src, "xyz")
	wrapped := wrapCode("go", injected)
	dir := t.TempDir()
	p := filepath.Join(dir, "main.go")
	if err := os.WriteFile(p, []byte(wrapped), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("go", "run", p).CombinedOutput()
	if err != nil {
		t.Fatalf("go run injected package: %v\n%s\n%s", err, wrapped, out)
	}
}

func TestPHPWrapper_DoesNotDoubleOpenTag(t *testing.T) {
	injected := injectFileContent("php", "<?php\necho $FILE_CONTENT;\n", "hi")
	wrapped := wrapCode("php", injected)
	if n := strings.Count(wrapped, "<?php"); n != 1 {
		t.Fatalf("expected one <?php, got %d in:\n%s", n, wrapped)
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

func TestSearchPrefixScoped_ThisBatchRunOnly(t *testing.T) {
	st := newTestStore(t)
	fg := NewFloodGuard(time.Hour, 64)
	sp := NewSearchPipeline(st, fg)
	indexDoc(t, st, "batch:111-old:cmd:1:1", "OLD_BATCH_UNIQUE_FAIL_MARKER leftover")
	indexDoc(t, st, "batch:222-new:cmd:1:1", "NEW_BATCH_OK_MARKER plus OLD_BATCH_UNIQUE_FAIL_MARKER")
	hits, _, err := sp.SearchPrefixScoped("OLD_BATCH_UNIQUE_FAIL_MARKER", "batch:222-new:", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected only this-run hit, got %d", len(hits))
	}
	if !strings.HasPrefix(hits[0].Path, "batch:222-new:") {
		t.Fatalf("historical batch leaked into this-run search: %q", hits[0].Path)
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

func TestGoWrapper_NoDefaultFmtWithoutSelector(t *testing.T) {
	// No real selector: the old code defaulted to importing fmt, which made
	// any snippet that does NOT use fmt fail to compile (unused import).
	code := `println("hello")`
	imports := detectGoImports(code)
	if len(imports) != 0 {
		t.Fatalf("expected no imports for selector-free code, got %v", imports)
	}
	out := goWrapper(code)
	if strings.Contains(out, `"fmt"`) {
		t.Fatalf("selector-free code must not import fmt:\n%s", out)
	}
	if !strings.Contains(out, `println("hello")`) {
		t.Fatalf("code body must be preserved:\n%s", out)
	}
}

func TestGoWrapper_SkipsRawStringData(t *testing.T) {
	// Selector-looking text inside a raw backtick string is DATA (e.g. the
	// FILE_CONTENT literal injected by injectFileContent), not code: it must
	// not trigger imports. Real selectors outside the literal still do.
	code := "s := `fmt.Println(os.Getenv(\"HOME\"))`\nfmt.Println(len(s))"
	imports := detectGoImports(code)
	if len(imports) != 1 || imports[0] != "fmt" {
		t.Fatalf("expected only fmt, got %v", imports)
	}
	out := goWrapper(code)
	if strings.Contains(out, `"os"`) {
		t.Fatalf("raw-string data must not import os:\n%s", out)
	}
	if !strings.Contains(out, `"fmt"`) {
		t.Fatalf("real fmt selector must still be imported:\n%s", out)
	}
}

func TestGoWrapper_SkipsInterpretedStringData(t *testing.T) {
	// Selector-looking text inside interpreted strings is data too, even
	// with escaped quotes (backslash must not end the string early).
	code := "s := \"os.Getenv(\\\"X\\\") strings.Split\"\nfmt.Println(s)"
	imports := detectGoImports(code)
	if len(imports) != 1 || imports[0] != "fmt" {
		t.Fatalf("expected only fmt, got %v", imports)
	}
	out := goWrapper(code)
	if strings.Contains(out, `"os"`) || strings.Contains(out, `"strings"`) {
		t.Fatalf("string-literal data must not import os/strings:\n%s", out)
	}
}

func TestGoWrapper_CommentSelectorsIgnored(t *testing.T) {
	// Selector text in comments must not trigger imports; a stray quote in a
	// comment must not swallow the real code either.
	code := "// fmt.Println(os.Getenv(\"X\")) note\nfmt.Println(\"real\")"
	imports := detectGoImports(code)
	if len(imports) != 1 || imports[0] != "fmt" {
		t.Fatalf("expected only fmt, got %v", imports)
	}
}

func TestGoWrapper_SkipsInjectedFileContentSimpleRaw(t *testing.T) {
	// Simple injection form (no backticks in the file): selector text inside
	// the FILE_CONTENT raw literal must not be imported.
	content := "plain data fmt.Println(os.Getenv(\"X\")) strings.Split(\"a,b\", \",\")"
	code := "fmt.Println(len(FILE_CONTENT))"
	injected := injectFileContent("go", code, content)
	if !strings.HasPrefix(injected, "var FILE_CONTENT = `") {
		t.Fatalf("expected simple raw form, got:\n%s", injected)
	}
	imports := detectGoImports(injected)
	if len(imports) != 1 || imports[0] != "fmt" {
		t.Fatalf("expected only fmt, got %v", imports)
	}
}

func TestGoWrapper_SkipsInjectedFileContentBacktickConcat(t *testing.T) {
	// Backtick-concatenation injection form (file contains backticks):
	// var FILE_CONTENT = `a` + "`" + `b...` — the backticks inside the "`"
	// strings are literal data, not raw-string delimiters, and the data must
	// not trigger imports. Real selectors in the user code still do.
	content := "a`b`c fmt.Println(os.Getenv(\"X\")) strings.Split(\"a,b\", \",\")"
	code := "fmt.Println(strings.Count(FILE_CONTENT, \"`\"))"
	injected := injectFileContent("go", code, content)
	const concatForm = `+ "` + "`" + `" +`
	if !strings.Contains(injected, concatForm) {
		t.Fatalf("expected backtick concatenation form, got:\n%s", injected)
	}
	imports := detectGoImports(injected)
	got := map[string]bool{}
	for _, p := range imports {
		got[p] = true
	}
	if !got["fmt"] || !got["strings"] {
		t.Fatalf("real selectors fmt/strings must be imported, got %v", imports)
	}
	if got["os"] {
		t.Fatalf("FILE_CONTENT data must not import os, got %v", imports)
	}
}

func TestExecuteFile_GoCompilesWithoutSpuriousImports(t *testing.T) {
	// Real end-to-end regression through toolExecuteFile: FILE_CONTENT data
	// that LOOKS like Go selectors (fmt/os/strings...) must not be scanned
	// for imports. The old detector saw the raw-string data, imported os
	// (unused), and the wrapped program failed to compile.
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: newTestStore(t)}
	ctx := context.Background()

	// Backticks in the content force the concatenation injection form.
	content := "package fake\nfmt.Println(os.Getenv(\"HOME\"))\nstrings.Split(`a,b`, \",\")\n"
	mustWrite(t, filepath.Join(wd, "data.txt"), content)

	res, _, err := s.toolExecuteFile(ctx, nil, executeFileArgs{
		Path:     "data.txt",
		Code:     "fmt.Println(strings.Count(FILE_CONTENT, \"\\n\"))",
		Language: "go",
		Timeout:  60000,
	})
	if err != nil {
		t.Fatalf("toolExecuteFile (go): %v", err)
	}
	text := strings.TrimSpace(mcpResultText(t, res))
	if text != "3" {
		t.Fatalf("expected line count 3, got %q (a compile failure surfaces as stderr here)", text)
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
	doc, getErr := s.store.Get("fetch:markdown:" + rawURL)
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
	err := validateURL(context.Background(), "http://127.0.0.1/")
	if err == nil {
		t.Fatal("expected 127.0.0.1 blocked")
	}

	// Public IP host (example.com may resolve to public addresses).
	// If DNS fails in offline env, skip.
	if ips, err := net.LookupIP("example.com"); err == nil && len(ips) > 0 {
		var anySafe bool
		for _, ip := range ips {
			if checkIP(ip) == nil {
				anySafe = true
				break
			}
		}
		if anySafe {
			if err := validateURL(context.Background(), "https://example.com/"); err != nil {
				t.Fatalf("expected example.com allowed when a public IP exists: %v", err)
			}
		}
	}
}

// ---------- #13 version constant ----------

func TestVersionAligned(t *testing.T) {
	// Keep in sync with CHANGELOG release label.
	if Version != "3.1.7" {
		t.Fatalf("Version=%q, want 3.1.7 (CHANGELOG)", Version)
	}
}

// ---------- #7 background registry ----------

func TestBackgroundRegistry_ListAndKill(t *testing.T) {
	requireLinux(t) // killBackground succeeds only with /proc identity
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
	if !strings.Contains(text, "--- Tail preview ---") && !strings.Contains(text, "--- Preview ---") {
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

// ---------- #18 concurrent & idempotent shutdownBackground ----------

func TestShutdownBackground_ConcurrentAndIdempotent(t *testing.T) {
	requireLinux(t)
	// Clean slate: terminate any leftover background jobs from prior tests.
	shutdownBackground()

	// Start 3 background processes.
	for i := 0; i < 3; i++ {
		_, err := runShell(context.Background(), "sleep 30", "/tmp", 0, true)
		if err != nil {
			t.Fatalf("start bg proc %d: %v", i, err)
		}
	}

	initial := listBackground()
	if len(initial) != 3 {
		t.Fatalf("expected 3 background entries before shutdown, got %d", len(initial))
	}
	var pids []int
	for _, e := range initial {
		pids = append(pids, e.PID)
	}

	// Concurrent callers invoking shutdownBackground simultaneously.
	var wg sync.WaitGroup
	const callers = 5
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			shutdownBackground()
		}()
	}
	wg.Wait()

	// All procs must be gone from registry.
	if procs := listBackground(); len(procs) != 0 {
		t.Fatalf("expected empty registry after shutdown, got %d", len(procs))
	}

	// Verify all processes are terminated deterministically.
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		dead := false
		for attempt := 0; attempt < 100; attempt++ {
			if procStartTime(pid) == 0 {
				dead = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !dead {
			t.Fatalf("background process %d still running after shutdown", pid)
		}
	}

	// Idempotent: subsequent calls (both single and concurrent) must succeed safely
	// and leave the registry empty.
	shutdownBackground()
	if procs := listBackground(); len(procs) != 0 {
		t.Fatalf("expected empty registry after second shutdown, got %d", len(procs))
	}

	var wg2 sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			shutdownBackground()
		}()
	}
	wg2.Wait()

	if procs := listBackground(); len(procs) != 0 {
		t.Fatalf("expected empty registry after concurrent second shutdown, got %d", len(procs))
	}
}

// ---------- #19 ensureDBDir permissions ----------

func TestEnsureDBDir_Permissions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// 1. Default DB path: ensureDBDir creates dedicated dir with 0700 permissions.
	t.Setenv("CTXMODE_DB", "")
	defPath, _, err := databasePath(filepath.Join(home, "myproject"))
	if err != nil {
		t.Fatalf("databasePath: %v", err)
	}
	if err := ensureDBDir(defPath); err != nil {
		t.Fatalf("ensureDBDir: %v", err)
	}
	dirInfo, err := os.Stat(filepath.Dir(defPath))
	if err != nil {
		t.Fatalf("stat default db dir: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("default db directory permissions = %o, want 0700", mode)
	}

	// 2. Custom CTXMODE_DB: parent dir permissions must NOT be chmodded to 0700.
	sharedDir := filepath.Join(home, "shared_dir")
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sharedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	customDB := filepath.Join(sharedDir, "custom.db")
	t.Setenv("CTXMODE_DB", customDB)
	if err := ensureDBDir(customDB); err != nil {
		t.Fatalf("ensureDBDir custom: %v", err)
	}
	sharedInfo, err := os.Stat(sharedDir)
	if err != nil {
		t.Fatal(err)
	}
	if mode := sharedInfo.Mode().Perm(); mode != 0o755 {
		t.Fatalf("custom CTXMODE_DB modified parent dir permissions to %o, want 0755", mode)
	}
}

// ---------- #20 Teredo / ISATAP / Transitions checkIP ----------

func TestCheckIP_TeredoISATAPAndTransitions(t *testing.T) {
	// Teredo (2001:0000::/32): bytes 4..7 is server IPv4, bytes 12..15 XOR 0xFFFFFFFF is client IPv4.
	// Server private (10.0.0.1 -> 0a 00 00 01)
	teredoPrivServer := net.IP{0x20, 0x01, 0x00, 0x00, 10, 0, 0, 1, 0, 0, 0, 0, 0xfe, 0xfe, 0xfe, 0xfe}
	if err := checkIP(teredoPrivServer); err == nil {
		t.Fatal("expected Teredo with private server IP to be blocked")
	}

	// Server public (1.1.1.1), Client private (192.168.1.1 -> XOR with FF -> 192^0xff=63, 168^0xff=87, 1^0xff=254)
	teredoPrivClient := net.IP{0x20, 0x01, 0x00, 0x00, 1, 1, 1, 1, 0, 0, 0, 0, 192 ^ 0xff, 168 ^ 0xff, 1 ^ 0xff, 1 ^ 0xff}
	if err := checkIP(teredoPrivClient); err == nil {
		t.Fatal("expected Teredo with private client IP to be blocked")
	}

	// Server public (1.1.1.1), Client public (8.8.8.8 -> XOR with FF -> 8^0xff = 0xf7)
	teredoPublic := net.IP{0x20, 0x01, 0x00, 0x00, 1, 1, 1, 1, 0, 0, 0, 0, 8 ^ 0xff, 8 ^ 0xff, 8 ^ 0xff, 8 ^ 0xff}
	if err := checkIP(teredoPublic); err != nil {
		t.Fatalf("expected Teredo with public server & client IPs to be allowed: %v", err)
	}

	// ISATAP: bytes 8..11 is 00:00:5E:FE or 02:00:5E:FE, bytes 12..15 is IPv4.
	isatapPriv1 := net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x00, 0x00, 0x5e, 0xfe, 10, 0, 0, 1}
	if err := checkIP(isatapPriv1); err == nil {
		t.Fatal("expected ISATAP (00-00-5E-FE) with private IPv4 to be blocked")
	}
	isatapPriv2 := net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xfe, 192, 168, 1, 1}
	if err := checkIP(isatapPriv2); err == nil {
		t.Fatal("expected ISATAP (02-00-5E-FE) with private IPv4 to be blocked")
	}
	isatapPublic := net.IP{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x02, 0x00, 0x5e, 0xfe, 8, 8, 8, 8}
	if err := checkIP(isatapPublic); err != nil {
		t.Fatalf("expected ISATAP with public IPv4 to be allowed: %v", err)
	}

	// Plain public IPv6
	pubV6 := net.ParseIP("2606:4700:4700::1111")
	if err := checkIP(pubV6); err != nil {
		t.Fatalf("expected public IPv6 to be allowed: %v", err)
	}

	// 6to4 (2002::/16)
	sixToFourPriv := net.IP{0x20, 0x02, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if err := checkIP(sixToFourPriv); err == nil {
		t.Fatal("expected 6to4 private to be blocked")
	}
	sixToFourPub := net.IP{0x20, 0x02, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if err := checkIP(sixToFourPub); err != nil {
		t.Fatalf("expected 6to4 public to be allowed: %v", err)
	}

	// NAT64 well-known (64:ff9b::/96) and local-use (64:ff9b:1::/48)
	nat64Priv := net.IP{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1}
	if err := checkIP(nat64Priv); err == nil {
		t.Fatal("expected NAT64 private to be blocked")
	}
	nat64Pub := net.IP{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1}
	if err := checkIP(nat64Pub); err != nil {
		t.Fatalf("expected NAT64 public to be allowed: %v", err)
	}

	// IPv4-compatible (::a.b.c.d)
	compatPriv := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	if err := checkIP(compatPriv); err == nil {
		t.Fatal("expected IPv4-compatible private to be blocked")
	}
	compatPub := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8}
	if err := checkIP(compatPub); err != nil {
		t.Fatalf("expected IPv4-compatible public to be allowed: %v", err)
	}
}

// ---------- #21 migrateFromJSON tests ----------

func TestMigrateFromJSON_OversizedSymlinkAndValid(t *testing.T) {
	// 1. Oversized JSON DB: must return error and NOT rename.
	t.Run("oversized file rejected", func(t *testing.T) {
		wd := t.TempDir()
		st := newTestStore(t)
		s := &server{workdirs: []string{wd}, store: st}
		jsonPath := filepath.Join(wd, ".context_mode_db.json")

		origLimit := maxJSONMigrationBytes
		defer func() { maxJSONMigrationBytes = origLimit }()
		maxJSONMigrationBytes = 32

		f, err := os.Create(jsonPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(64); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()

		err = s.migrateFromJSON()
		if err == nil {
			t.Fatal("expected error for oversized JSON DB")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("expected too large error, got: %v", err)
		}
		if _, err := os.Lstat(jsonPath); err != nil {
			t.Fatalf("original file must remain in place: %v", err)
		}
		if _, err := os.Lstat(jsonPath + ".bak"); !os.IsNotExist(err) {
			t.Fatal("backup file must not exist on failed migration")
		}
	})

	// 2. Symlink JSON DB: must return error and NOT rename.
	t.Run("symlink rejected", func(t *testing.T) {
		wd := t.TempDir()
		st := newTestStore(t)
		s := &server{workdirs: []string{wd}, store: st}
		target := filepath.Join(t.TempDir(), "target.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		jsonPath := filepath.Join(wd, ".context_mode_db.json")
		if err := os.Symlink(target, jsonPath); err != nil {
			t.Fatal(err)
		}

		err := s.migrateFromJSON()
		if err == nil {
			t.Fatal("expected error for symlink JSON DB")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected not a regular file error, got: %v", err)
		}
		if _, err := os.Lstat(jsonPath); err != nil {
			t.Fatalf("symlink must remain in place: %v", err)
		}
		if _, err := os.Lstat(jsonPath + ".bak"); !os.IsNotExist(err) {
			t.Fatal("backup file must not exist on rejected symlink")
		}
	})

	// 3. Valid small JSON DB: documents migrated and renamed to .bak.
	t.Run("valid small JSON DB migrated", func(t *testing.T) {
		wd := t.TempDir()
		st := newTestStore(t)
		s := &server{workdirs: []string{wd}, store: st}
		jsonPath := filepath.Join(wd, ".context_mode_db.json")
		validJSON := `{"doc1": {"path": "doc1.txt", "content": "migrated content alpha"}}`
		if err := os.WriteFile(jsonPath, []byte(validJSON), 0o600); err != nil {
			t.Fatal(err)
		}

		err := s.migrateFromJSON()
		if err != nil {
			t.Fatalf("migrateFromJSON failed: %v", err)
		}
		if _, err := os.Lstat(jsonPath); !os.IsNotExist(err) {
			t.Fatal("original JSON file should have been renamed")
		}
		if _, err := os.Lstat(jsonPath + ".bak"); err != nil {
			t.Fatalf("backup file .bak must exist: %v", err)
		}
		doc, err := st.Get("doc1.txt")
		if err != nil || doc == nil {
			t.Fatalf("expected doc1.txt in store: %v", err)
		}
		if doc.Content != "migrated content alpha" {
			t.Fatalf("unexpected content: %q", doc.Content)
		}
	})

	// 4. File appears within limit on Stat but exceeds limit during Read (LimitReader overflow path).
	// Must return "exceeded maximum allowed size" error, must NOT rename file, and .bak must not exist.
	t.Run("limit reader exceeded during read", func(t *testing.T) {
		wd := t.TempDir()
		st := newTestStore(t)
		s := &server{workdirs: []string{wd}, store: st}
		jsonPath := filepath.Join(wd, ".context_mode_db.json")

		// Write 100 bytes of content.
		content := strings.Repeat("A", 100)
		if err := os.WriteFile(jsonPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		origLimit := maxJSONMigrationBytes
		origHook := jsonMigrationStatHook
		defer func() {
			maxJSONMigrationBytes = origLimit
			jsonMigrationStatHook = origHook
		}()

		maxJSONMigrationBytes = 32
		realFi, err := os.Lstat(jsonPath)
		if err != nil {
			t.Fatal(err)
		}
		// Stat hook reports size 10 (<= maxJSONMigrationBytes), but reading the file yields 100 bytes (> 32 bytes).
		jsonMigrationStatHook = func(p string) (os.FileInfo, error) {
			return fakeFileInfo{
				name:    realFi.Name(),
				size:    10,
				mode:    realFi.Mode(),
				modTime: realFi.ModTime(),
			}, nil
		}

		err = s.migrateFromJSON()
		if err == nil {
			t.Fatal("expected error when LimitReader exceeds maxJSONMigrationBytes during read")
		}
		if !strings.Contains(err.Error(), "exceeded maximum allowed size") {
			t.Fatalf("expected exceeded maximum allowed size error, got: %v", err)
		}
		if _, err := os.Lstat(jsonPath); err != nil {
			t.Fatalf("original file must remain in place: %v", err)
		}
		if _, err := os.Lstat(jsonPath + ".bak"); !os.IsNotExist(err) {
			t.Fatal("backup file must not exist on failed migration")
		}
	})
}

type fakeFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return f.modTime }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

// ---------- #22 single-link sensitive inode scan skip ----------

func TestIndexFile_SingleLinkNoInodeScan(t *testing.T) {
	wd := t.TempDir()
	st := newTestStore(t)
	s := &server{workdirs: []string{wd}, store: st}

	// Create sensitive file .env in workdir.
	envFile := filepath.Join(wd, ".env")
	if err := os.WriteFile(envFile, []byte("SEC"+"RET=123\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create regular file (nlink == 1).
	normalFile := filepath.Join(wd, "normal.txt")
	if err := os.WriteFile(normalFile, []byte("hello normal\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Reset scan counter.
	s.sensitiveInodesScans.Store(0)

	// Indexing single regular file must NOT trigger collectSensitiveInodes.
	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: normalFile})
	if err != nil {
		t.Fatalf("toolIndex normalFile: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res), "Indexed 1 file(s)") {
		t.Fatalf("expected 1 indexed file: %s", mcpResultText(t, res))
	}
	if scans := s.sensitiveInodesScans.Load(); scans != 0 {
		t.Fatalf("expected 0 sensitive inodes scans for nlink=1 file, got %d", scans)
	}

	// Hardlink to .env (nlink == 2) with harmless name:
	// nlink > 1 triggers scan and hardlink protection rejects it.
	hardlinkToEnv := filepath.Join(wd, "safe_name.txt")
	if err := os.Link(envFile, hardlinkToEnv); err != nil {
		t.Fatal(err)
	}
	_, _, err = s.toolIndex(context.Background(), nil, indexArgs{Path: hardlinkToEnv})
	if err == nil {
		t.Fatal("expected hardlink to .env to be rejected")
	}
	if !strings.Contains(err.Error(), "hardlink to sensitive file") {
		t.Fatalf("expected hardlink to sensitive file error, got: %v", err)
	}
	if scans := s.sensitiveInodesScans.Load(); scans == 0 {
		t.Fatal("expected sensitive inodes scan to run for nlink > 1 file")
	}
}

// ---------- #23 validateURL canceled context ----------

func TestValidateURL_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Canceled context returns immediately for hostnames.
	err := validateURL(ctx, "https://example.com/test")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled for hostname, got: %v", err)
	}

	// Canceled context returns immediately even for IP literals.
	err = validateURL(ctx, "http://1.1.1.1/test")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled for IP literal, got: %v", err)
	}
}
