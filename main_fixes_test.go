package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- t1: migrateFromJSON hardening ----------

// writeLegacyJSONDB marshals docs into a legacy .context_mode_db.json file.
func writeLegacyJSONDB(t *testing.T, wd string, docs map[string]Document) {
	t.Helper()
	data, err := json.Marshal(docs)
	if err != nil {
		t.Fatalf("marshal legacy docs: %v", err)
	}
	p := filepath.Join(wd, ".context_mode_db.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write legacy json: %v", err)
	}
}

// mustWriteWorkdirFile creates a real file (and parent dirs) inside wd so a
// legacy absolute path passes the strict EvalSymlinks fence.
func mustWriteWorkdirFile(t *testing.T, wd, rel, content string) {
	t.Helper()
	p := filepath.Join(wd, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("mkdir for %q: %v", rel, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %q: %v", rel, err)
	}
}

// TestMigratedDocPathValid pins the legacy-path whitelist: only absolute
// paths that resolve (strict EvalSymlinks) inside a workdir are accepted, and
// the returned display path is workspace-relative. Relative paths and the
// rg:/batch:/session:/URL shapes only ever occur in crafted or corrupted
// legacy JSON and must all be rejected.
func TestMigratedDocPathValid(t *testing.T) {
	wd := t.TempDir()
	wd2 := t.TempDir()
	mustWriteWorkdirFile(t, wd, "doc1.txt", "hello")
	mustWriteWorkdirFile(t, wd, "src/dir/notes.md", "notes")
	mustWriteWorkdirFile(t, wd, ".env", "SECRET=1") // exists, but sensitive
	mustWriteWorkdirFile(t, wd2, "other.md", "other")
	// Dangling symlink inside the workdir.
	if err := os.Symlink(filepath.Join(wd, "does-not-exist"), filepath.Join(wd, "dangling")); err != nil {
		t.Fatal(err)
	}
	workdirs := []string{wd, wd2}

	valid := []struct{ path, display string }{
		{filepath.Join(wd, "doc1.txt"), "doc1.txt"},
		{filepath.Join(wd, "src", "dir", "notes.md"), filepath.Join("src", "dir", "notes.md")},
		{wd + "//doc1.txt", "doc1.txt"},                          // Clean normalizes
		{filepath.Join(wd, "src", "..", "doc1.txt"), "doc1.txt"}, // embedded .. resolved by Clean
		{filepath.Join(wd2, "other.md"), "other.md"},             // any workdir counts
	}
	invalid := []string{
		"",                       // empty
		strings.Repeat("a", 513), // over 512 bytes
		filepath.Join(wd, strings.Repeat("a", 513)), // overlong absolute
		"doc1.txt",                                   // relative: never a real legacy shape
		"src/dir/notes.md",                           // relative with directories
		"rg:notes",                                   // structured rg label (hostile JSON only)
		"rg:session:OTHER:stolen",                    // forged rg label
		"batch:run1:label",                           // batch label (hostile JSON only)
		"web:markdown:https://example.com/doc",       // fetch doc path (hostile JSON only)
		"fetch:http://example.com/x",                 // legacy fetch doc path
		"session:aabbccdd00112233:rg:ok",             // session namespace (hostile JSON only)
		"session:deadbeef:rg:stolen",                 // cross-session forgery
		"evil:scheme:x",                              // colon label of no known shape
		"C:\\Users\\x",                               // windows-style (not absolute on linux)
		"../escaped",                                 // traversal segment
		"a/../../escaped",                            // embedded traversal
		filepath.Join(wd, "does-not-exist"),          // dangling: strict EvalSymlinks fails
		filepath.Join(wd, "dangling"),                // dangling symlink
		filepath.Join(wd, "..", "escaped"),           // Clean escapes the workdir
		"/etc/passwd",                                // absolute but outside every workdir
		filepath.Join(wd, "doc1.txt") + " https://x", // hostile URL suffix
		filepath.Join(wd, ".env"),                    // sensitive file never migrates
		filepath.Join(wd, "doc\x1b[31m.txt"),         // ESC (ANSI/OSC escape)
		filepath.Join(wd, "doc\x00null.txt"),         // NUL
		filepath.Join(wd, "doc\u009b.txt"),           // C1 control (U+009B)
		filepath.Join(wd, "doc\xff\xfe.txt"),         // invalid UTF-8
	}
	for _, tc := range valid {
		display, ok := migratedDocPathValid(workdirs, tc.path)
		if !ok {
			t.Errorf("migratedDocPathValid(%q) = false, want true", tc.path)
			continue
		}
		if display != tc.display {
			t.Errorf("migratedDocPathValid(%q) display = %q, want %q", tc.path, display, tc.display)
		}
	}
	for _, p := range invalid {
		if display, ok := migratedDocPathValid(workdirs, p); ok {
			t.Errorf("migratedDocPathValid(%q) = (%q, true), want false", p, display)
		}
	}
	// No workdirs: nothing can be contained.
	if _, ok := migratedDocPathValid(nil, filepath.Join(wd, "doc1.txt")); ok {
		t.Errorf("empty workdirs must reject every path")
	}
}

// TestMigrateFromJSON_MaliciousPathsSkipped: forged / control-char / oversized
// paths from the legacy JSON db are skipped (with the rest of the batch
// intact); legitimate absolute paths inside a workdir migrate under their
// workspace-relative display path and the file is renamed to .bak.
func TestMigrateFromJSON_MaliciousPathsSkipped(t *testing.T) {
	wd := t.TempDir()
	st := newTestStore(t)
	s := &server{workdirs: []string{wd}, store: st, sessionID: "aabbccdd00112233"}

	// Real files the legacy KB indexed (absolute paths of existing files).
	mustWriteWorkdirFile(t, wd, "doc1.txt", "on disk")
	mustWriteWorkdirFile(t, wd, "src/notes.md", "on disk")
	mustWriteWorkdirFile(t, wd, ".env", "SECRET=1")
	mustWriteWorkdirFile(t, wd, "doc-sensitive.txt", "harmless on disk")

	esc := "rg:\x1b[31minjected"
	longPath := strings.Repeat("a", 513)
	writeLegacyJSONDB(t, wd, map[string]Document{
		"forged_session":  {Path: "session:deadbeef:rg:stolen", Content: "forged cross-session doc"},
		"current_session": {Path: "session:aabbccdd00112233:rg:ok", Content: "current session doc"},
		"esc_inject":      {Path: esc, Content: "escape sequence doc"},
		"too_long":        {Path: longPath, Content: "overlong path doc"},
		"absolute_out":    {Path: "/etc/injected", Content: "absolute path doc"},
		"traversal":       {Path: "../escaped", Content: "traversal doc"},
		"bogus_scheme":    {Path: "evil:scheme:x", Content: "bogus scheme doc"},
		"rg_forge":        {Path: "rg:session:OTHER:stolen", Content: "forged rg doc"},
		"batch_forge":     {Path: "batch:run1:label", Content: "forged batch doc"},
		"url_forge":       {Path: "web:markdown:https://example.com/doc", Content: "forged fetch doc"},
		"url_suffix":      {Path: "doc1.txt https://evil.example/x", Content: "URL suffix doc"},
		"relative":        {Path: "doc1.txt", Content: "relative path doc"},
		"sensitive_path":  {Path: filepath.Join(wd, ".env"), Content: "harmless content"},
		"sensitive_doc":   {Path: filepath.Join(wd, "doc-sensitive.txt"), Content: "aws key " + fakeAWSKey + " inside"},
		"good_file":       {Path: filepath.Join(wd, "doc1.txt"), Content: "migrated content alpha"},
		"good_nested":     {Path: filepath.Join(wd, "src", "notes.md"), Content: "migrated notes"},
	})

	if err := s.migrateFromJSON(); err != nil {
		t.Fatalf("migrateFromJSON: %v", err)
	}

	// Forged shapes, hostile forms and invalid paths must all be skipped.
	for _, p := range []string{
		"session:deadbeef:rg:stolen",
		"session:aabbccdd00112233:rg:ok",
		esc,
		longPath,
		"/etc/injected",
		"../escaped",
		"evil:scheme:x",
		"rg:session:OTHER:stolen",
		"batch:run1:label",
		"web:markdown:https://example.com/doc",
		"doc1.txt https://evil.example/x",
		// NOTE: the relative "doc1.txt" entry is rejected too, but its name
		// collides with the display path of the legitimate absolute doc, so
		// the store check below pins that only the good content landed there.
	} {
		if doc, _ := st.Get(p); doc != nil {
			t.Errorf("malicious/unwanted path %q must not be migrated", p)
		}
	}
	// Sensitive: by KB path (.env, under either the absolute or the display
	// name it would appear under) and by content (store gate skips the AWS
	// key doc even though its path is benign).
	for _, p := range []string{
		filepath.Join(wd, ".env"),
		".env",
		filepath.Join(wd, "doc-sensitive.txt"),
		"doc-sensitive.txt",
	} {
		if doc, _ := st.Get(p); doc != nil {
			t.Errorf("sensitive path %q must not be migrated", p)
		}
	}
	// Legitimate absolute paths migrate under workspace-relative display paths.
	for p, want := range map[string]string{
		"doc1.txt":     "migrated content alpha",
		"src/notes.md": "migrated notes",
	} {
		doc, err := st.Get(p)
		if err != nil || doc == nil {
			t.Errorf("expected legitimate path %q to be migrated (err=%v)", p, err)
			continue
		}
		if doc.Content != want {
			t.Errorf("path %q content = %q, want %q", p, doc.Content, want)
		}
	}
	// Batch completed: legacy file renamed to .bak.
	if _, err := os.Lstat(filepath.Join(wd, ".context_mode_db.json")); !os.IsNotExist(err) {
		t.Errorf("legacy JSON should be renamed after completed migration (err=%v)", err)
	}
	if _, err := os.Lstat(filepath.Join(wd, ".context_mode_db.json.bak")); err != nil {
		t.Errorf(".bak should exist after completed migration: %v", err)
	}
}

// TestMigrateFromJSON_DamagedDocDoesNotAbortBatch: one damaged entry (not a
// document object) is skipped; sibling documents still migrate.
func TestMigrateFromJSON_DamagedDocDoesNotAbortBatch(t *testing.T) {
	wd := t.TempDir()
	st := newTestStore(t)
	s := &server{workdirs: []string{wd}, store: st, sessionID: "ff01"}
	mustWriteWorkdirFile(t, wd, "doc-ok.txt", "on disk")
	mustWriteWorkdirFile(t, wd, "doc-ok2.txt", "on disk")
	docs := map[string]Document{
		"good":  {Path: filepath.Join(wd, "doc-ok.txt"), Content: "fine"},
		"good2": {Path: filepath.Join(wd, "doc-ok2.txt"), Content: "fine too"},
	}
	good, err := json.Marshal(docs)
	if err != nil {
		t.Fatal(err)
	}
	// Splice a damaged entry (not a document object) into the raw JSON.
	raw := string(good[:len(good)-1]) + `, "damaged": "not-an-object"}`
	p := filepath.Join(wd, ".context_mode_db.json")
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateFromJSON(); err != nil {
		t.Fatalf("single damaged document must not abort migration: %v", err)
	}
	for _, want := range []string{"doc-ok.txt", "doc-ok2.txt"} {
		if doc, _ := st.Get(want); doc == nil {
			t.Errorf("expected %q to be migrated despite a damaged sibling", want)
		}
	}
}

// TestMigrateFromJSON_CorruptJSONSkipsMigrationNotFatal: a corrupt legacy file
// returns an error from migrateFromJSON, the startup wrapper
// migrateFromJSONOrWarn returns without exiting, and the damaged file stays in
// place for a retry on the next start.
func TestMigrateFromJSON_CorruptJSONSkipsMigrationNotFatal(t *testing.T) {
	wd := t.TempDir()
	st := newTestStore(t)
	s := &server{workdirs: []string{wd}, store: st, sessionID: "ff00"}
	p := filepath.Join(wd, ".context_mode_db.json")
	if err := os.WriteFile(p, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateFromJSON(); err == nil {
		t.Fatal("expected error for corrupt legacy JSON")
	}
	s.migrateFromJSONOrWarn() // must return, not exit
	if _, err := os.Lstat(p); err != nil {
		t.Fatalf("damaged legacy file must stay in place: %v", err)
	}
	if _, err := os.Lstat(p + ".bak"); !os.IsNotExist(err) {
		t.Fatal(".bak must not be created for a failed migration")
	}
}

// ---------- t2: isSensitiveFilePath red-team lists ----------

// TestIsSensitiveFilePath_BackupVariants: the red-team escapes (backup and
// renamed credential files) all hit; the dot-less credential rules match by
// EXACT name only, so unrelated files (netrc.go, pgpass.md,
// git-credentials-helper.sh) stay non-sensitive; established non-sensitive
// names keep passing.
func TestIsSensitiveFilePath_BackupVariants(t *testing.T) {
	hits := []string{
		"/home/u/.ssh/id_rsa.bak",
		"/home/u/.ssh/id_rsa_primary", // prefix + "_" name boundary
		"/home/u/.ssh/id_ed25519_sk",  // FIDO variant
		"/home/u/.ssh/id_rsa.go",      // extension tail keeps hitting (conservative)
		"/dl/prod.pem.txt",
		"/dl/prod.key.1",          // numeric copy marker
		"/dl/server.pem.20240901", // datestamped copy marker
		"/home/u/.pgpass.bak",
		"/home/u/netrc.bak", // exact name after backup strip
		"/home/u/pgpass",    // dot-less exact name
		"/home/u/netrc",     // dot-less exact name
		"/var/www/.htpasswd.old",
		"/etc/ssl/key.pem.orig",
		"/proj/.env~",
		"/home/u/git-credentials.txt",
		// multi-suffix stripping and established hits that must not regress
		"/x/id_rsa.bak.old",
		"/x/vault.pem.save.tmp",
		"/x/credentials.json.gpg",
		"/x/NETRC.TXT", // case-insensitive
		"reid_rsa",     // suffix hit preserved (conservative direction)
	}
	misses := []string{
		// red-team false positives removed by the exact-name rules
		"/src/netrc.go",
		"/src/pgpass.md",
		"/tools/git-credentials-helper.sh",
		"/etc/pgpass.example.com",
		"/x/id_rsafoo", // prefix without a name boundary
		"/proj/src/main.go",
		"/docs/report.pdf",
		"/home/u/bash_history",        // no leading dot, not a credential name
		"/infra/terraform.tfvars.bak", // existing contract: stays non-sensitive
		"/proj/config.json",
		"/proj/service.json",
		"/infra/terraform.tf",
		"notes.txt",
		"README.md",
	}
	for _, p := range hits {
		if !isSensitiveFilePath(p) {
			t.Errorf("isSensitiveFilePath(%q) = false, want true", p)
		}
	}
	for _, p := range misses {
		if isSensitiveFilePath(p) {
			t.Errorf("isSensitiveFilePath(%q) = true, want false", p)
		}
	}
}

// ---------- t3: fetch must not cache or keep rejected content ----------

// TestFetchAndIndex_IndexErrSkipsCacheWrite: content refused by the
// sensitive-content fence (indexErr != nil) must not be written to
// fetch_cache; benign content is still cached.
func TestFetchAndIndex_IndexErrSkipsCacheWrite(t *testing.T) {
	const docURL = "http://1.1.1.1/docs/cache-gate"
	var mu sync.Mutex
	sensitive := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		if sensitive {
			fmt.Fprint(w, "here is a secret credential: "+fakeAWSKey+" for testing")
		} else {
			fmt.Fprint(w, "This is plain documentation about system architecture.")
		}
	}
	srv := newFetchTestServer(t, handler)

	// Non-forced fetch (singleflight path with cache write) of sensitive content.
	mu.Lock()
	sensitive = true
	mu.Unlock()
	res, err := srv.fetchAndIndex(context.Background(), docURL, "web", "markdown", false, 3600000, 10*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if res.IndexError == "" {
		t.Fatalf("expected IndexError for sensitive content, got none")
	}
	cached, err := srv.store.GetCached(docURL, "web|markdown")
	if err != nil {
		t.Fatalf("GetCached: %v", err)
	}
	if cached != nil {
		t.Fatalf("rejected content must not be written to fetch_cache")
	}
	if n, _ := srv.store.CacheCount(); n != 0 {
		t.Fatalf("fetch_cache must stay empty after rejected fetch, got %d entries", n)
	}

	// Benign content is still cached (no over-blocking).
	mu.Lock()
	sensitive = false
	mu.Unlock()
	res2, err := srv.fetchAndIndex(context.Background(), docURL, "web", "markdown", false, 3600000, 10*time.Second)
	if err != nil {
		t.Fatalf("benign fetch: %v", err)
	}
	if res2.IndexError != "" {
		t.Fatalf("benign fetch must not fail: %s", res2.IndexError)
	}
	cached2, err := srv.store.GetCached(docURL, "web|markdown")
	if err != nil {
		t.Fatalf("GetCached: %v", err)
	}
	if cached2 == nil || !strings.Contains(cached2.Content, "architecture") {
		t.Fatalf("benign content must be cached, got %+v", cached2)
	}
}

// TestFetchAndIndex_IndexErrDeletesStaleCache: a fetch_cache row that already
// holds rejected plaintext (e.g. written by a version before the index fence)
// is deleted when a fetch of the same URL is refused, and the cache-hit
// re-index failure path drops the row as well, so sensitive plaintext can
// neither linger for the full cache TTL nor resurrect through the cache.
func TestFetchAndIndex_IndexErrDeletesStaleCache(t *testing.T) {
	const docURL = "http://1.1.1.1/docs/cache-delete"
	var mu sync.Mutex
	sensitive := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		if sensitive {
			fmt.Fprint(w, "here is a secret credential: "+fakeAWSKey+" for testing")
		} else {
			fmt.Fprint(w, "This is plain documentation about system architecture.")
		}
	}
	srv := newFetchTestServer(t, handler)

	// Path 1: stale pre-upgrade row + rejected fetch (singleflight path).
	// Seed a row with fetched_at far past the TTL, as an older version that
	// predated the SetCache skip would have left behind.
	staleAt := time.Now().Add(-8 * 24 * time.Hour).Unix()
	if _, err := srv.store.db.Exec(
		`INSERT OR REPLACE INTO fetch_cache (url, source, content, fetched_at) VALUES (?, ?, ?, ?)`,
		docURL, "web|markdown", "stale pre-upgrade plaintext with "+fakeAWSKey, staleAt,
	); err != nil {
		t.Fatalf("seed stale cache row: %v", err)
	}
	mu.Lock()
	sensitive = true
	mu.Unlock()
	res, err := srv.fetchAndIndex(context.Background(), docURL, "web", "markdown", false, 3600000, 10*time.Second)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if res.Cached || res.IndexError == "" {
		t.Fatalf("expected a non-cached rejected fetch, got %+v", res)
	}
	if c, err := srv.store.GetCached(docURL, "web|markdown"); err != nil || c != nil {
		t.Fatalf("stale cache row must be deleted when the fetch is refused (got %+v, err=%v)", c, err)
	}

	// Path 2: fresh cache hit whose re-index is refused drops the row.
	if err := srv.store.SetCache(docURL, "web|markdown", "cached pre-upgrade plaintext with "+fakeAWSKey); err != nil {
		t.Fatalf("seed cache row: %v", err)
	}
	mu.Lock()
	sensitive = false // handler content irrelevant: the cache hit short-circuits
	mu.Unlock()
	res2, err := srv.fetchAndIndex(context.Background(), docURL, "web", "markdown", false, 3600000, 10*time.Second)
	if err != nil {
		t.Fatalf("cache-hit fetch: %v", err)
	}
	if !res2.Cached || res2.IndexError == "" || !strings.Contains(res2.IndexError, "cache hit re-index failed") {
		t.Fatalf("expected cache-hit re-index failure, got %+v", res2)
	}
	if c, err := srv.store.GetCached(docURL, "web|markdown"); err != nil || c != nil {
		t.Fatalf("cache row must be deleted after refused cache-hit re-index (got %+v, err=%v)", c, err)
	}
	if n, _ := srv.store.CacheCount(); n != 0 {
		t.Fatalf("fetch_cache must be empty after rejected fetches, got %d entries", n)
	}
}

// ---------- t4: PurgeAll clears fetch_cache ----------

// TestPurgeAll_ClearsFetchCache: a project purge (PurgeAll) must remove every
// fetch_cache entry together with the documents, so purged content cannot be
// resurrected by a single fetch via the cache-hit re-index path.
func TestPurgeAll_ClearsFetchCache(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetCache("http://example.com/a", "web|markdown", "content a"); err != nil {
		t.Fatalf("SetCache: %v", err)
	}
	if err := s.SetCache("http://example.com/b", "web|html", "content b"); err != nil {
		t.Fatalf("SetCache: %v", err)
	}
	if err := s.Index("session:x:doc", "some document body"); err != nil {
		t.Fatalf("Index: %v", err)
	}
	if n, _ := s.CacheCount(); n != 2 {
		t.Fatalf("expected 2 cache entries before purge, got %d", n)
	}
	docs, cache, err := s.PurgeAll()
	if err != nil {
		t.Fatalf("PurgeAll: %v", err)
	}
	if docs != 1 {
		t.Fatalf("expected 1 document purged, got %d", docs)
	}
	if cache != 2 {
		t.Fatalf("expected 2 cache entries purged, got %d", cache)
	}
	if n, _ := s.CacheCount(); n != 0 {
		t.Fatalf("fetch_cache must be empty after PurgeAll, got %d", n)
	}
	for _, key := range [][2]string{
		{"http://example.com/a", "web|markdown"},
		{"http://example.com/b", "web|html"},
	} {
		if c, err := s.GetCached(key[0], key[1]); err != nil || c != nil {
			t.Fatalf("cache entry %v survived PurgeAll: %+v (err=%v)", key, c, err)
		}
	}
	if doc, _ := s.Get("session:x:doc"); doc != nil {
		t.Fatal("document survived PurgeAll")
	}
}
