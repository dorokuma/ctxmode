package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// === Merged from fixes_test.go ===

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
		Path:      "data.txt",
		Code:      "fmt.Println(strings.Count(FILE_CONTENT, \"\\n\"))",
		Language:  "go",
		TimeoutMs: 60000,
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
	if Version != "6.2.2" {
		t.Fatalf("Version=%q, want 6.2.2 (CHANGELOG)", Version)
	}
}

func TestTimeoutFields_SchemaIsMs(t *testing.T) {
	checks := []struct {
		typ   reflect.Type
		field string
	}{
		{reflect.TypeOf(ctxRunArgs{}), "TimeoutMs"},
		{reflect.TypeOf(ctxKbArgs{}), "TimeoutMs"},
		{reflect.TypeOf(ctxKbArgs{}), "TTLMs"},
		{reflect.TypeOf(ctxBgArgs{}), "TimeoutMs"},
	}
	for _, c := range checks {
		f, ok := c.typ.FieldByName(c.field)
		if !ok {
			t.Fatalf("%s.%s missing", c.typ.Name(), c.field)
		}
		tag := f.Tag.Get("jsonschema")
		if !strings.HasPrefix(tag, "ms ") && tag != "ms" {
			t.Fatalf("%s.%s jsonschema must start with ms, got %q", c.typ.Name(), c.field, tag)
		}
		if strings.Contains(tag, "1h") || strings.Contains(tag, "24h") || strings.Contains(tag, " second") {
			t.Fatalf("%s.%s jsonschema mixes non-ms units: %q", c.typ.Name(), c.field, tag)
		}
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
		Command:   code,
		Language:  "shell",
		TimeoutMs: 15000,
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
	// Legacy KB paths are absolute (resolvePath/Walk products) and must be
	// backed by an existing file; they migrate under their workspace-
	// relative display path.
	t.Run("valid small JSON DB migrated", func(t *testing.T) {
		wd := t.TempDir()
		st := newTestStore(t)
		s := &server{workdirs: []string{wd}, store: st}
		if err := os.WriteFile(filepath.Join(wd, "doc1.txt"), []byte("on disk"), 0o600); err != nil {
			t.Fatal(err)
		}
		jsonPath := filepath.Join(wd, ".context_mode_db.json")
		validJSON := `{"doc1": {"path": "` + filepath.Join(wd, "doc1.txt") + `", "content": "migrated content alpha"}}`
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

// === Merged from fixes2_test.go ===

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

	text, truncated, n, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "LONG_LINE_TOKEN_XYZ", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
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
	text2, truncated2, n2, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "NORMAL_RG_TOKEN", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
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

	text, truncated, n, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "RG_TOKEN", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
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

// === Merged from fixes3_test.go ===

// ============================================================================
// 1. 自动索引敏感内容拦截测试 (execute, execute_file, batch, run_task, store)
// ============================================================================

var (
	testPrivateKeyPayload = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3...\n-----END " + "RSA PRIVATE KEY-----\n"
	testAWSAccessKey      = "AKIA" + "IOSFODNN7EXAMPLE"
	testGitHubToken       = "ghp_" + "123456789012345678901234567890123456"
)

func TestAutoIndex_SensitiveContentRefused_Execute(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	// 1. Large output (> 100KB) containing private key
	bigSensitiveOutput := strings.Repeat("A", 105*1024) + "\n" + testPrivateKeyPayload
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command: "printf '%s'",
		Argv:    []string{"printf", "%s", bigSensitiveOutput},
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Content was NOT indexed") || !strings.Contains(text, "private key material") {
		t.Fatalf("expected unindexed result with private key refusal, got: %s", text)
	}
	if hits, _ := st.Search("RSA PRIVATE KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive execute output was indexed to store: %+v", hits)
	}

	// 2. Large output (> 100KB) containing AWS Access Key
	bigAWSOutput := strings.Repeat("A", 105*1024) + "\n" + testAWSAccessKey
	res, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Command: "printf '%s'",
		Argv:    []string{"printf", "%s", bigAWSOutput},
	})
	if err != nil {
		t.Fatalf("toolExecute AWS: %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "Content was NOT indexed") || !strings.Contains(text, "credential / secret material") {
		t.Fatalf("expected unindexed result with credential refusal, got: %s", text)
	}
	if hits, _ := st.Search(testAWSAccessKey, 5); len(hits) != 0 {
		t.Fatalf("sensitive AWS key was indexed to store: %+v", hits)
	}

	// 3. Intent-tagged output (> 5KB) containing GitHub token
	intentSensitiveOutput := strings.Repeat("B", 6*1024) + "\n" + testGitHubToken
	res, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Command: "printf '%s'",
		Argv:    []string{"printf", "%s", intentSensitiveOutput},
		Intent:  "leak_test",
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "was NOT indexed") || !strings.Contains(text, "credential / secret material") {
		t.Fatalf("expected intent unindexed result with credential refusal, got: %s", text)
	}
	if hits, _ := st.Search("leak_test", 5); len(hits) != 0 {
		t.Fatalf("sensitive intent execute output was indexed to store: %+v", hits)
	}
}

func TestAutoIndex_SensitiveContentRefused_ExecuteFile(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	// Case 1: Target file is a sensitive file (.env). Must be refused BEFORE reading or executing.
	envFile := filepath.Join(wd, ".env")
	mustWrite(t, envFile, "SECRET_KEY=123456\n"+strings.Repeat("LARGE_CONF_VAL=XYZ\n", 6000))
	_, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     envFile,
		Code:     "console.log(FILE_CONTENT);",
		Language: "javascript",
	})
	if err == nil {
		t.Fatal("expected error refusing execution on sensitive file (.env), got nil")
	}
	if !strings.Contains(err.Error(), "refusing to execute on sensitive file") {
		t.Fatalf("expected sensitive file execution refusal message, got: %v", err)
	}
	if hits, _ := st.Search("SECRET_KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive file content was indexed to store: %+v", hits)
	}

	// Case 2: Target file is normal, but code output contains private key (large output)
	if !checkRuntime("javascript", false, "") {
		t.Skip("skipping execute_file javascript test: node runtime not available")
	}
	normalFile := filepath.Join(wd, "data.txt")
	mustWrite(t, normalFile, "hello")
	jsCode := fmt.Sprintf(`console.log(%q + "\n" + %q);`, strings.Repeat("X", 105*1024), testPrivateKeyPayload)
	res, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     normalFile,
		Code:     jsCode,
		Language: "javascript",
	})
	if err != nil {
		t.Fatalf("toolExecuteFile (sensitive output): %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Content was NOT indexed") || !strings.Contains(text, "private key material") {
		t.Fatalf("expected private key output index refusal, got: %s", text)
	}
	if hits, _ := st.Search("RSA PRIVATE KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive output from execute_file was indexed to store: %+v", hits)
	}
}

func TestAutoIndex_SensitiveContentRefused_Batch(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	// The graded screen now hard-blocks any command string >64KiB, so build the
	// >100KB OUTPUT from a small command (fill NUL->'C') and read the private key
	// from a file instead of embedding it in an oversized command. The assertion
	// under test — index-time refusal of sensitive content — is unchanged.
	keyPath := filepath.Join(wd, "leak.key")
	if err := os.WriteFile(keyPath, []byte(testPrivateKeyPayload), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	resp, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "sensitive_cmd", Command: "head -c 110000 /dev/zero | tr '\\0' 'C'; printf '\\n'; cat \"" + keyPath + "\""},
		},
		CWD: wd,
	})
	if err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	text := mcpResultText(t, resp)
	var batchResp batchResponse
	if err := json.Unmarshal([]byte(text), &batchResp); err != nil {
		t.Fatalf("unmarshal batch response: %v\ntext: %s", err, text)
	}
	if len(batchResp.Commands) != 1 {
		t.Fatalf("expected 1 command result, got %d", len(batchResp.Commands))
	}
	cmdRes := batchResp.Commands[0]
	if cmdRes.Indexed {
		t.Fatal("sensitive batch output must NOT have Indexed=true")
	}
	if !strings.Contains(cmdRes.IndexError, "private key material") {
		t.Fatalf("expected IndexError with private key refusal, got %q", cmdRes.IndexError)
	}
	if hits, _ := st.Search("RSA PRIVATE KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive batch output was indexed: %+v", hits)
	}
}

func TestAutoIndex_SensitiveContentRefused_RunTask(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	bigSensitive := strings.Repeat("D", 105*1024) + "\n" + testPrivateKeyPayload
	res, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom",
		Args: []string{"printf", "%s", bigSensitive},
		CWD:  wd,
	})
	if err != nil {
		t.Fatalf("toolRunTask: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Content was NOT indexed") || !strings.Contains(text, "private key material") {
		t.Fatalf("expected run_task index refusal, got: %s", text)
	}
	if hits, _ := st.Search("RSA PRIVATE KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive run_task output was indexed: %+v", hits)
	}
}

func TestStore_Index_SensitiveContentRefused(t *testing.T) {
	st := newTestStore(t)

	// Direct Index call with private key must fail
	err := st.Index("secrets/key.pem", testPrivateKeyPayload)
	if err == nil {
		t.Fatal("expected Store.Index to refuse private key")
	}
	if !strings.Contains(err.Error(), "private key material") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Direct Index call with AWS key must fail
	err = st.Index("secrets/aws.txt", "export AWS_ACCESS_KEY_ID="+testAWSAccessKey)
	if err == nil {
		t.Fatal("expected Store.Index to refuse AWS access key")
	}
	if !strings.Contains(err.Error(), "credential / secret material") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// ============================================================================
// 2. background jsonschema 文案一致性测试
// ============================================================================

func TestBackground_JSONSchema_ReflectsTimeoutTermination(t *testing.T) {
	fExec, ok := reflect.TypeOf(executeArgs{}).FieldByName("Background")
	if !ok {
		t.Fatal("Background field missing in executeArgs")
	}
	tagExec := fExec.Tag.Get("jsonschema")
	if strings.Contains(tagExec, "Keep running after timeout") {
		t.Fatalf("executeArgs.Background tag contains outdated text: %q", tagExec)
	}
	if !strings.Contains(tagExec, "terminated on timeout") && !strings.Contains(tagExec, "terminated after timeout") {
		t.Fatalf("executeArgs.Background tag must reflect timeout termination, got: %q", tagExec)
	}

	fRun, ok := reflect.TypeOf(ctxRunArgs{}).FieldByName("Background")
	if !ok {
		t.Fatal("Background field missing in ctxRunArgs")
	}
	tagRun := fRun.Tag.Get("jsonschema")
	if strings.Contains(tagRun, "Keep running after timeout") {
		t.Fatalf("ctxRunArgs.Background tag contains outdated text: %q", tagRun)
	}
	if !strings.Contains(tagRun, "terminated on timeout") && !strings.Contains(tagRun, "terminated after timeout") {
		t.Fatalf("ctxRunArgs.Background tag must reflect timeout termination, got: %q", tagRun)
	}
}

// ============================================================================
// 3. batch 取消路径 stdout/stderr 合并换行测试
// ============================================================================

func TestBatchExecute_Cancellation_NewlineSeparation(t *testing.T) {
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyFile := filepath.Join(wd, "ready.txt")
	cmdStr := fmt.Sprintf(`printf "stdout_line"; printf "stderr_line" >&2; : > %q; sleep 10`, readyFile)

	done := make(chan struct{})
	var out string
	var exitCode int
	var execErr error

	go func() {
		out, exitCode, execErr, _ = s.executeCommand(ctx, cmdStr, s.workdirs[0])
		close(done)
	}()

	// Wait until stdout and stderr have been produced before cancelling.
	ready := false
	for i := 0; i < 500; i++ {
		if _, err := os.Stat(readyFile); err == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-done
		t.Fatal("timed out waiting for command to produce output")
	}

	cancel()
	<-done

	if execErr == nil {
		t.Fatal("expected non-nil error on cancellation")
	}
	if exitCode != -1 {
		t.Fatalf("expected exitCode -1 on cancellation, got %d", exitCode)
	}

	if !strings.Contains(out, "stdout_line\nstderr_line") {
		t.Fatalf("expected newline separation between stdout and stderr on cancellation, got %q", out)
	}
}

// ============================================================================
// 4. 后台启动/注册失败时 cleanups 临时文件清理测试
// ============================================================================

func TestBackground_LaunchFailure_CleanupsRemoved(t *testing.T) {
	wd := t.TempDir()

	tmpFile, err := os.CreateTemp(os.TempDir(), "test_bg_cleanup_*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	cmd := exec.Command("/nonexistent/binary/for/test")
	cmd.Dir = wd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	_, err = runCmd(context.Background(), cmd, 5*time.Second, true, "custom", "bad_cmd", tmpPath)
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		_ = os.Remove(tmpPath)
		t.Fatalf("temp file %s was not cleaned up after background launch failure", tmpPath)
	}
}

func TestBackground_RegisterFailure_Cleanup(t *testing.T) {
	bgMu.Lock()
	saved := bgProcs
	bgProcs = make(map[string]*bgEntry)
	// Fill up to maxBackgroundProcs live entries
	for i := 0; i < maxBackgroundProcs; i++ {
		id := fmt.Sprintf("mock-live-%d", i)
		bgProcs[id] = &bgEntry{
			ID:        id,
			PID:       10000 + i,
			StartedAt: time.Now(),
			Done:      false,
		}
	}
	bgMu.Unlock()

	defer func() {
		bgMu.Lock()
		bgProcs = saved
		bgMu.Unlock()
	}()

	tmpFile, err := os.CreateTemp(os.TempDir(), "test_bg_cap_*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	cmd := exec.Command("sleep", "10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	_, err = runCmd(context.Background(), cmd, 10*time.Second, true, "shell", "sleep 10", tmpPath)
	if err == nil {
		t.Fatal("expected error when background cap is exceeded")
	}
	if !strings.Contains(err.Error(), "too many concurrent background processes") {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		_ = os.Remove(tmpPath)
		t.Fatalf("temp file %s was not cleaned up when background cap was reached", tmpPath)
	}
}

// ============================================================================
// 5. 后台结果保留及上限修剪测试
// ============================================================================

func TestBackground_Retention_QueryableAfterCompletion(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}

	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:    "echo 'background retention test output'",
		Background: true,
	})
	if err != nil {
		t.Fatalf("toolExecute background: %v", err)
	}
	text := mcpResultText(t, res)

	var jobID string
	for _, part := range strings.Fields(text) {
		if strings.HasPrefix(part, "bg-") {
			jobID = strings.Trim(part, ",.)")
			break
		}
	}
	if jobID == "" {
		t.Fatalf("failed to extract jobID from: %s", text)
	}

	t.Cleanup(func() {
		bgMu.Lock()
		e, ok := bgProcs[jobID]
		if ok {
			delete(bgProcs, jobID)
		}
		bgMu.Unlock()
		if e != nil {
			if e.LogPath != "" {
				unprotectTemp(e.LogPath)
				_ = os.Remove(e.LogPath)
			}
			for _, tmp := range e.TempFiles {
				unprotectTemp(tmp)
				_ = os.Remove(tmp)
			}
		}
	})

	waitRes, _, err := s.toolBackgroundWait(context.Background(), nil, backgroundWaitArgs{
		ID:        jobID,
		TimeoutMs: 5000,
	})
	if err != nil {
		t.Fatalf("toolBackgroundWait: %v", err)
	}
	wText := mcpResultText(t, waitRes)
	if !strings.Contains(wText, "background retention test output") {
		t.Fatalf("expected output in wait, got: %s", wText)
	}

	logRes, _, err := s.toolBackgroundLog(context.Background(), nil, backgroundLogArgs{
		ID: jobID,
	})
	if err != nil {
		t.Fatalf("toolBackgroundLog after completion: %v", err)
	}
	lText := mcpResultText(t, logRes)
	if !strings.Contains(lText, "background retention test output") {
		t.Fatalf("expected output in log query, got: %s", lText)
	}
}

func TestBackground_MaxCompletedJobs_Eviction(t *testing.T) {
	bgMu.Lock()
	saved := bgProcs
	bgProcs = make(map[string]*bgEntry)
	bgMu.Unlock()

	defer func() {
		bgMu.Lock()
		bgProcs = saved
		bgMu.Unlock()
	}()

	var logFiles []string
	totalJobs := maxCompletedBackgroundJobs + 10

	for i := 0; i < totalJobs; i++ {
		f, err := os.CreateTemp(os.TempDir(), "test_evict_*.log")
		if err != nil {
			t.Fatal(err)
		}
		lp := f.Name()
		logFiles = append(logFiles, lp)
		_, _ = f.WriteString(fmt.Sprintf("log output %d\n", i))
		protectTemp(lp)

		id := fmt.Sprintf("evict-bg-%d", i)
		bgMu.Lock()
		bgProcs[id] = &bgEntry{
			ID:        id,
			PID:       20000 + i,
			StartedAt: time.Now().Add(time.Duration(i) * time.Millisecond),
			LogPath:   lp,
			logFile:   f,
			logWriter: &limitedFileWriter{f: f, limit: bgLogMaxBytes},
		}
		bgMu.Unlock()

		finishBackground(id, 0)
	}

	bgMu.Lock()
	doneCount := 0
	for _, e := range bgProcs {
		if e.Done {
			doneCount++
		}
	}
	bgMu.Unlock()

	if doneCount > maxCompletedBackgroundJobs {
		t.Fatalf("expected at most %d completed background jobs retained, got %d", maxCompletedBackgroundJobs, doneCount)
	}

	// Verify the oldest 10 log files were removed
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(logFiles[i]); !os.IsNotExist(err) {
			_ = os.Remove(logFiles[i])
			t.Errorf("oldest log file %s should have been removed by eviction", logFiles[i])
		}
	}

	// Clean up remaining log files
	for i := 10; i < len(logFiles); i++ {
		_ = os.Remove(logFiles[i])
	}
}

// ============================================================================
// 6. Leader 退出但子进程存活时 ctx_bg kill 进程组清理测试
// ============================================================================

func TestBackground_Kill_LeaderExitedChildSurviving(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping process group procfs test on non-linux platform")
	}
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("skipping test: /proc is not available")
	}

	s := &server{workdirs: []string{t.TempDir()}}

	// Launch a shell script that spawns a long-running sleep child in background and exits immediately.
	cmdStr := "sleep 100 &"
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:    cmdStr,
		Background: true,
	})
	if err != nil {
		t.Fatalf("toolExecute background: %v", err)
	}
	text := mcpResultText(t, res)

	var jobID string
	for _, part := range strings.Fields(text) {
		if strings.HasPrefix(part, "bg-") {
			jobID = strings.Trim(part, ",.)")
			break
		}
	}
	if jobID == "" {
		t.Fatalf("failed to extract jobID from: %s", text)
	}

	entry := findBackground(jobID)
	if entry == nil {
		t.Fatalf("background job %s not found", jobID)
	}

	t.Cleanup(func() {
		// 1. Attempt clean kill first
		_, _ = killBackground(jobID)

		// 2. Kill the process group directly in case killBackground failed or didn't catch everything
		if entry.PID > 0 {
			_ = syscall.Kill(-entry.PID, syscall.SIGKILL)
			if entry.starttime > 0 {
				surviving := findProcessGroupPIDs(entry.PID, entry.starttime)
				for _, pid := range surviving {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}

		// 3. Clean up registry entry and temporary files
		bgMu.Lock()
		e, ok := bgProcs[jobID]
		if ok {
			delete(bgProcs, jobID)
		}
		bgMu.Unlock()

		if e != nil {
			if e.LogPath != "" {
				unprotectTemp(e.LogPath)
				_ = os.Remove(e.LogPath)
			}
			for _, tmp := range e.TempFiles {
				unprotectTemp(tmp)
				_ = os.Remove(tmp)
			}
		}
	})

	// Poll until leader has exited
	leaderExited := false
	for i := 0; i < 100; i++ {
		time.Sleep(30 * time.Millisecond)
		if procStartTime(entry.PID) == 0 {
			leaderExited = true
			break
		}
	}
	if !leaderExited {
		t.Fatalf("leader process %d did not exit as expected", entry.PID)
	}

	// Poll for surviving child processes in the process group
	var surviving []int
	for i := 0; i < 50; i++ {
		surviving = findProcessGroupPIDs(entry.PID, entry.starttime)
		if len(surviving) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(surviving) == 0 {
		t.Fatalf("expected surviving child process in process group %d, found none", entry.PID)
	}

	// Verify before kill: surviving process is alive and in the process group
	for _, pid := range surviving {
		if err := syscall.Kill(pid, 0); err != nil {
			t.Fatalf("child process %d in group %d is not alive before kill: %v", pid, entry.PID, err)
		}
	}

	// Kill background job
	killMsg, err := killBackground(jobID)
	if err != nil {
		t.Fatalf("killBackground failed: %v", err)
	}
	if !strings.Contains(killMsg, "killed orphan background process group") {
		t.Fatalf("unexpected kill message: %s", killMsg)
	}

	// Verify after kill: all child processes are terminated
	remaining := findProcessGroupPIDs(entry.PID, entry.starttime)
	if len(remaining) > 0 {
		t.Fatalf("orphan processes %v still running in process group %d after killBackground", remaining, entry.PID)
	}
	for _, pid := range surviving {
		// Confirm process is dead. A zombie still holds its PID-table entry,
		// so kill(pid,0) returns nil for it — check the /proc state field too
		// and treat Z/X (dead, unreaped) as dead, matching the fix that makes
		// findProcessGroupPIDs ignore zombies in the kill loop above.
		if err := syscall.Kill(pid, 0); err == nil && !procStatIsDead(pid) {
			t.Fatalf("child process %d is still alive after killBackground", pid)
		}
	}
}

// procStatIsDead reports whether /proc/<pid>/stat marks the process in a
// dead state (Z zombie or X/x dead) — a zombie keeps its PID-table entry so
// kill(pid,0) returns nil even though the process no longer runs.
func procStatIsDead(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return true // gone
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 >= len(data) {
		return false
	}
	f := strings.Fields(string(data[i+2:]))
	if len(f) == 0 {
		return false
	}
	return f[0] == "Z" || f[0] == "X" || f[0] == "x"
}

func TestBackground_Kill_UnknownIdentity_Refused(t *testing.T) {
	bgMu.Lock()
	saved := bgProcs
	bgProcs = make(map[string]*bgEntry)
	// Entry with unknown identity (starttime = 0)
	bgProcs["bg-unknown"] = &bgEntry{
		ID:        "bg-unknown",
		PID:       99999,
		starttime: 0,
		Done:      false,
	}
	bgMu.Unlock()

	defer func() {
		bgMu.Lock()
		bgProcs = saved
		bgMu.Unlock()
	}()

	_, err := killBackground("bg-unknown")
	if err == nil {
		t.Fatal("expected killBackground to fail on unknown starttime")
	}
	if !strings.Contains(err.Error(), "process identity unknown") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Ensure slot was NOT marked Done
	e := findBackground("bg-unknown")
	if e == nil || e.Done {
		t.Fatal("entry with unknown identity must not be marked Done on failed kill")
	}
}

// ============================================================================
// 7. 数据库权限防护与恢复测试
// ============================================================================

func TestStore_SecureDBFiles_RestoresRelaxedPermissionsOnWrite(t *testing.T) {
	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "test.db")

	st, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	// Initial write creates database and sidecar (WAL)
	if err := st.Index("doc/1", "initial content"); err != nil {
		t.Fatalf("Index: %v", err)
	}

	walPath := dbPath + "-wal"

	// Relax permissions to 0644 (simulating external modification or default umask creation)
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(walPath); err == nil {
		if err := os.Chmod(walPath, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Subsequent write must detect and restore 0600 on DB and sidecars
	if err := st.Index("doc/2", "second content"); err != nil {
		t.Fatalf("Index 2: %v", err)
	}

	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected main DB file permissions restored to 0600, got %o", perm)
	}

	if fiWal, err := os.Stat(walPath); err == nil {
		if perm := fiWal.Mode().Perm(); perm != 0o600 {
			t.Fatalf("expected WAL sidecar permissions restored to 0600, got %o", perm)
		}
	}
}

// ============================================================================
// 8. finishBackground 与 shutdownBackground 并发竞态测试
// ============================================================================

func TestBackground_Concurrent_FinishAndShutdown_Race(t *testing.T) {
	bgMu.Lock()
	saved := bgProcs
	bgProcs = make(map[string]*bgEntry)
	bgMu.Unlock()

	defer func() {
		bgMu.Lock()
		bgProcs = saved
		bgMu.Unlock()
	}()

	for round := 0; round < 10; round++ {
		f, err := os.CreateTemp(os.TempDir(), "test_race_bg_*.log")
		if err != nil {
			t.Fatal(err)
		}
		lp := f.Name()
		protectTemp(lp)

		id := fmt.Sprintf("race-bg-%d", round)
		writer := &limitedFileWriter{f: f, limit: bgLogMaxBytes}

		bgMu.Lock()
		bgProcs[id] = &bgEntry{
			ID:        id,
			PID:       30000 + round,
			StartedAt: time.Now(),
			LogPath:   lp,
			logFile:   f,
			logWriter: writer,
			Done:      false,
		}
		bgMu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			finishBackground(id, 0)
		}()

		go func() {
			defer wg.Done()
			shutdownBackground()
		}()

		wg.Wait()
		unprotectTemp(lp)
		_ = os.Remove(lp)
	}
}

// === Merged from fixes4_test.go ===

// ============================================================================
// 1. 数据库权限：VACUUM 路径恢复 0600 权限测试
// ============================================================================

func TestStore_Vacuum_Restores0600(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "vacuum_perm.db")

	st, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	if err := st.Index("doc/1", "initial content to allocate pages"); err != nil {
		t.Fatalf("Index: %v", err)
	}

	walPath := dbPath + "-wal"
	shmPath := dbPath + "-shm"

	// Relax permissions to 0644 (simulating external chmod or recreation during VACUUM)
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(walPath); err == nil {
		if err := os.Chmod(walPath, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(shmPath); err == nil {
		if err := os.Chmod(shmPath, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Run VACUUM directly
	if err := st.Vacuum(); err != nil {
		t.Fatalf("Vacuum: %v", err)
	}

	// Permissions must be immediately restored to 0600 without needing next Index/SetCache
	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected main DB file perm 0600 after Vacuum, got %o", perm)
	}

	if fiWal, err := os.Stat(walPath); err == nil {
		if perm := fiWal.Mode().Perm(); perm != 0o600 {
			t.Fatalf("expected WAL sidecar perm 0600 after Vacuum, got %o", perm)
		}
	}
	if fiShm, err := os.Stat(shmPath); err == nil {
		if perm := fiShm.Mode().Perm(); perm != 0o600 {
			t.Fatalf("expected SHM sidecar perm 0600 after Vacuum, got %o", perm)
		}
	}
}

func TestPurgeProject_Vacuum_Restores0600(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "purge_perm.db")

	st, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	if err := st.Index("doc/1", "initial content to purge"); err != nil {
		t.Fatalf("Index: %v", err)
	}

	srv := &server{
		workdirs: []string{dir},
		store:    st,
	}

	// Relax permissions
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatal(err)
	}

	// Call purgeProject via toolPurge
	res, _, err := srv.toolPurge(context.Background(), nil, purgeArgs{
		Scope:         "project",
		Confirm:       true,
		ConfirmPhrase: filepath.Base(dir),
	})
	if err != nil {
		t.Fatalf("toolPurge project: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, `"scope": "project"`) {
		t.Fatalf("unexpected purge response: %s", text)
	}

	// Permissions must be 0600 immediately
	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected main DB file perm 0600 after purgeProject, got %o", perm)
	}
}

// ============================================================================
// 2. execute_file: 拒绝指向敏感文件 inode 的硬链接
// ============================================================================

func TestExecuteFile_HardlinkToSensitiveFile_Refused(t *testing.T) {
	wd := t.TempDir()
	st := newTestStore(t)
	s := &server{workdirs: []string{wd}, store: st}

	// Create a sensitive file (.env) in workdir
	envPath := filepath.Join(wd, ".env")
	if err := os.WriteFile(envPath, []byte("SEC"+"RET_API_"+"KEY=supersecret12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create harmless-named hardlink pointing to .env
	hardlinkPath := filepath.Join(wd, "harmless_script.js")
	if err := os.Link(envPath, hardlinkPath); err != nil {
		t.Skipf("hard links not supported: %v", err)
	}

	// Attempt execute_file on the harmless-named hardlink
	_, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     hardlinkPath,
		Language: "javascript",
		Code:     "console.log(FILE_CONTENT);",
	})
	if err == nil {
		t.Fatal("expected execute_file to refuse hardlink to .env, but got nil error")
	}
	if !strings.Contains(err.Error(), "sensitive file") && !strings.Contains(err.Error(), "hardlink") {
		t.Fatalf("expected sensitive file or hardlink error, got: %v", err)
	}

	// Verify normal non-sensitive file is not blocked
	normalPath := filepath.Join(wd, "normal.js")
	if err := os.WriteFile(normalPath, []byte("const x = 42;"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     normalPath,
		Language: "javascript",
		Code:     "console.log(FILE_CONTENT.length);",
	})
	// If node runtime is available, it should succeed; if not, language executor error is fine, but path check passed
	if err != nil && !strings.Contains(err.Error(), "executable file not found") && !strings.Contains(err.Error(), "exec:") && !strings.Contains(err.Error(), "is not available") {
		t.Fatalf("unexpected path error for normal file: %v", err)
	}
	if res != nil {
		text := mcpResultText(t, res)
		if !strings.Contains(text, "13") {
			t.Logf("execute_file output: %s", text)
		}
	}
}

// ============================================================================
// 3. fetch: 敏感内容检查先于 purge 且失败时保留旧索引
// ============================================================================

func TestFetchAndIndex_SensitiveContent_PreservesOldIndex(t *testing.T) {
	const docURL = "http://1.1.1.1/docs/manual"
	const oldContent = "This is important documentation about system architecture and components."
	const sensitiveContent = "Here is a secret credential: " + "AKIA" + "IOSFODNN7EXAMPLE for testing."

	var currentResponse string
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, currentResponse)
	}

	srv := newFetchTestServer(t, handler)
	docPath := srv.fetchDocPath("web", "markdown", docURL)

	// 1. Initial fetch: index valid content
	currentResponse = oldContent
	res, err := srv.fetchAndIndex(context.Background(), docURL, "web", "markdown", true, 0, 10*time.Second)
	if err != nil {
		t.Fatalf("initial fetch error: %v", err)
	}
	if res.Error != "" || res.IndexError != "" {
		t.Fatalf("initial fetch returned error: err=%q indexErr=%q", res.Error, res.IndexError)
	}

	// Verify old content is indexed in store
	doc, err := srv.store.Get(docPath)
	if err != nil || doc == nil {
		t.Fatalf("expected doc at %q after initial fetch (err=%v)", docPath, err)
	}
	if doc.Content != oldContent {
		t.Fatalf("expected content %q, got %q", oldContent, doc.Content)
	}

	// Verify old content is searchable
	hits, err := srv.store.Search("architecture", 10)
	if err != nil || len(hits) == 0 {
		t.Fatalf("expected search hits for 'architecture', got %d hits (err=%v)", len(hits), err)
	}

	// 2. Second fetch: server returns sensitive content (AWS key)
	currentResponse = sensitiveContent
	res2, err := srv.fetchAndIndex(context.Background(), docURL, "web", "markdown", true, 0, 10*time.Second)
	if err != nil {
		t.Fatalf("second fetch unexpected error: %v", err)
	}
	if res2.IndexError == "" {
		t.Fatalf("expected IndexError for sensitive content, got none")
	}
	if !strings.Contains(res2.IndexError, "sensitive") && !strings.Contains(res2.IndexError, "credential") {
		t.Fatalf("expected sensitive content error, got: %s", res2.IndexError)
	}

	// 3. Verify OLD document is STILL preserved in store!
	docAfter, err := srv.store.Get(docPath)
	if err != nil || docAfter == nil {
		t.Fatalf("old doc was wiped out after sensitive fetch failure: err=%v", err)
	}
	if docAfter.Content != oldContent {
		t.Fatalf("old doc content was modified, got %q, want %q", docAfter.Content, oldContent)
	}

	// 4. Verify old content is STILL searchable!
	hitsAfter, err := srv.store.Search("architecture", 10)
	if err != nil || len(hitsAfter) == 0 {
		t.Fatalf("expected search hits for 'architecture' to survive, got %d hits (err=%v)", len(hitsAfter), err)
	}

	// 5. Verify sensitive content is NOT searchable
	sensitiveHits, err := srv.store.Search("AKIA"+"IOSFODNN7EXAMPLE", 10)
	if err != nil || len(sensitiveHits) != 0 {
		t.Fatalf("sensitive content was indexed to store: %+v", sensitiveHits)
	}
}

func TestIndexContentLocked_Direct_PreservesOldIndexOnFailure(t *testing.T) {
	srv := newTestServer(t)
	const docPath = "web:markdown:http://example.com/testdoc"
	const oldContent = "Valid original doc content that must survive failed indexing."

	// 1. Initial valid index
	count, err := srv.indexContentLocked(docPath, oldContent)
	if err != nil || count == 0 {
		t.Fatalf("initial indexContentLocked failed: %v", err)
	}

	// Verify old doc exists
	doc, err := srv.store.Get(docPath)
	if err != nil || doc == nil || doc.Content != oldContent {
		t.Fatalf("initial doc not stored properly: doc=%+v err=%v", doc, err)
	}

	// 2. Attempt to index private key
	_, err = srv.indexContentLocked(docPath, testPrivateKeyPayload)
	if err == nil {
		t.Fatal("expected error indexing private key, got nil")
	}

	// 3. Attempt to index GitHub token
	_, err = srv.indexContentLocked(docPath, "ghp_"+"123456789012345678901234567890123456")
	if err == nil {
		t.Fatal("expected error indexing github token, got nil")
	}

	// 4. Old doc must still be intact
	docFinal, err := srv.store.Get(docPath)
	if err != nil || docFinal == nil {
		t.Fatalf("old doc lost after failed index: %v", err)
	}
	if docFinal.Content != oldContent {
		t.Fatalf("old doc overwritten with %q", docFinal.Content)
	}
}
