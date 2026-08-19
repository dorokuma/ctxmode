package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
		Scope:   "project",
		Confirm: true,
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
	if err != nil && !strings.Contains(err.Error(), "executable file not found") && !strings.Contains(err.Error(), "exec:") {
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
