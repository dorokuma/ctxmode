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

// TestMigratedDocPathValid pins the legacy-path whitelist shapes.
func TestMigratedDocPathValid(t *testing.T) {
	const sid = "aabbccdd00112233"
	valid := []string{
		"doc1.txt",                             // plain relative file path (legacy contract)
		"src/dir/notes.md",                     // relative path with directories
		"rg:notes",                             // structured rg label
		"batch:run1:label",                     // batch label
		"web:markdown:https://example.com/doc", // fetch doc path
		"fetch:http://example.com/x",           // legacy fetch doc path
		"session:" + sid + ":rg:ok",            // current session namespace
	}
	invalid := []string{
		"",                             // empty
		strings.Repeat("a", 513),       // over 512 bytes
		"rg:\x1b[31minjected",          // ESC (ANSI/OSC escape)
		"doc\x00null",                  // NUL
		"session:deadbeef:rg:stolen",   // cross-session forgery
		"session:" + sid + "\x1b:rg:x", // ESC inside session id
		"/etc/injected",                // absolute path
		"../escaped",                   // traversal segment
		"a/../../escaped",              // embedded traversal
		"evil:scheme:x",                // colon label of no known shape
		"C:\\Users\\x",                 // windows-style absolute
	}
	for _, p := range valid {
		if !migratedDocPathValid(sid, p) {
			t.Errorf("migratedDocPathValid(%q) = false, want true", p)
		}
	}
	for _, p := range invalid {
		if migratedDocPathValid(sid, p) {
			t.Errorf("migratedDocPathValid(%q) = true, want false", p)
		}
	}
	// Empty session id must not accept any session-prefixed path.
	if migratedDocPathValid("", "session:"+sid+":x") {
		t.Errorf("empty sessionID must reject session-prefixed paths")
	}
}

// TestMigrateFromJSON_MaliciousPathsSkipped: forged / control-char / oversized
// paths from the legacy JSON db are skipped (with the rest of the batch
// intact); legitimate paths migrate and the file is renamed to .bak.
func TestMigrateFromJSON_MaliciousPathsSkipped(t *testing.T) {
	wd := t.TempDir()
	st := newTestStore(t)
	const sid = "aabbccdd00112233"
	s := &server{workdirs: []string{wd}, store: st, sessionID: sid}

	esc := "rg:\x1b[31minjected"
	longPath := strings.Repeat("a", 513)
	writeLegacyJSONDB(t, wd, map[string]Document{
		"forged_session": {Path: "session:deadbeef:rg:stolen", Content: "forged cross-session doc"},
		"esc_inject":     {Path: esc, Content: "escape sequence doc"},
		"too_long":       {Path: longPath, Content: "overlong path doc"},
		"absolute":       {Path: "/etc/injected", Content: "absolute path doc"},
		"traversal":      {Path: "../escaped", Content: "traversal doc"},
		"bogus_scheme":   {Path: "evil:scheme:x", Content: "bogus scheme doc"},
		"sensitive_doc":  {Path: "doc-sensitive.txt", Content: "aws key " + fakeAWSKey + " inside"},
		"good_file":      {Path: "doc1.txt", Content: "migrated content alpha"},
		"good_rg":        {Path: "rg:notes", Content: "rg migrated"},
		"good_fetch":     {Path: "web:markdown:https://example.com/doc", Content: "fetch migrated"},
		"good_batch":     {Path: "batch:run1:label", Content: "batch migrated"},
		"good_session":   {Path: "session:" + sid + ":rg:ok", Content: "current session doc"},
	})

	if err := s.migrateFromJSON(); err != nil {
		t.Fatalf("migrateFromJSON: %v", err)
	}

	for _, p := range []string{
		"session:deadbeef:rg:stolen",
		esc,
		longPath,
		"/etc/injected",
		"../escaped",
		"evil:scheme:x",
		"doc-sensitive.txt", // store sensitive-content gate skips it
	} {
		if doc, _ := st.Get(p); doc != nil {
			t.Errorf("malicious/unwanted path %q must not be migrated", p)
		}
	}
	for p, want := range map[string]string{
		"doc1.txt":                             "migrated content alpha",
		"rg:notes":                             "rg migrated",
		"web:markdown:https://example.com/doc": "fetch migrated",
		"batch:run1:label":                     "batch migrated",
		"session:" + sid + ":rg:ok":            "current session doc",
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
	raw := `{"good": {"path": "doc-ok.txt", "content": "fine"}, "damaged": "not-an-object", "good2": {"path": "doc-ok2.txt", "content": "fine too"}}`
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

// ---------- t2: isSensitiveFilePath backup variants ----------

// TestIsSensitiveFilePath_BackupVariants: the red-team escapes (backup and
// renamed credential files) all hit; established non-sensitive names stay
// non-sensitive.
func TestIsSensitiveFilePath_BackupVariants(t *testing.T) {
	hits := []string{
		"/home/u/.ssh/id_rsa.bak",
		"/home/u/.ssh/id_rsa_primary",
		"/dl/prod.pem.txt",
		"/home/u/.pgpass.bak",
		"/home/u/netrc.bak",
		"/var/www/.htpasswd.old",
		"/etc/ssl/key.pem.orig",
		"/proj/.env~",
		"/home/u/pgpass",
		"/home/u/git-credentials.txt",
		"/home/u/.ssh/id_ed25519_sk",
		// multi-suffix stripping and established hits that must not regress
		"/x/id_rsa.bak.old",
		"/x/vault.pem.save.tmp",
		"/x/credentials.json.gpg",
		"/x/NETRC.TXT", // case-insensitive
		"reid_rsa",     // suffix hit preserved (conservative direction)
	}
	misses := []string{
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

// ---------- t3: fetch must not cache rejected content ----------

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
			fmt.Fprint(w, "here is a secret credential: AKIA"+"IOSFODNN7EXAMPLE for testing")
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
