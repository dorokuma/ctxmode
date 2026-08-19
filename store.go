package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Document represents an indexed document in the store.
type Document struct {
	Path      string
	Content   string
	IndexedAt time.Time
}

// SearchResult represents a search hit with a highlighted snippet.
type SearchResult struct {
	Path    string
	Snippet string
}

// Store wraps a SQLite database with FTS5 full-text search.
type Store struct {
	db      *sql.DB
	dbPath  string
	secured atomic.Bool
}

// sqliteDSN builds a file: URI DSN so paths containing space, %, ?, or #
// are not parsed as URI syntax. :memory: and already-URI paths are left as-is
// except for the per-connection pragmas.
func sqliteDSN(dbPath string) string {
	if dbPath == ":memory:" {
		return dbPath
	}
	const pragmas = "_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	if strings.HasPrefix(dbPath, "file:") {
		sep := "&"
		if !strings.Contains(dbPath, "?") {
			sep = "?"
		}
		return dbPath + sep + pragmas
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(dbPath)}
	return u.String() + "?" + pragmas
}

// NewStore opens or creates a SQLite database at dbPath and initializes
// the schema (documents table, FTS5 virtual table, and sync triggers).
func NewStore(dbPath string) (*Store, error) {
	cleanPath := extractFilePath(dbPath)
	if cleanPath != "" {
		f, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create database file %q: %w", cleanPath, err)
		}
		f.Close()
		if err := os.Chmod(cleanPath, 0o600); err != nil {
			return nil, fmt.Errorf("chmod database file %q (0600): %w", cleanPath, err)
		}
	}

	// Build DSN with per-connection pragmas so every new connection gets
	// busy_timeout and synchronous settings, not just the first one.
	dsn := sqliteDSN(dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Set WAL mode for better concurrent performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL: %w", err)
	}

	// Limit to a single connection to avoid SQLITE_BUSY on concurrent writes.
	// With SetMaxOpenConns(1), database/sql serializes all queries internally.
	db.SetMaxOpenConns(1)

	// Create the main documents table.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS documents (
			path       TEXT PRIMARY KEY,
			content    TEXT,
			indexed_at INTEGER
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create documents table: %w", err)
	}

	// Create the FTS5 virtual table with Porter stemmer + unicode61 tokenizer.
	// path and content are indexed columns; the external content table is 'documents'.
	if _, err := db.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
			path, content,
			tokenize='porter unicode61',
			content='documents',
			content_rowid='rowid'
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create fts5 table: %w", err)
	}

	// Create the trigram FTS5 table for substring matching.
	// This enables fuzzy/partial matches that the porter table misses.
	if _, err := db.Exec(`
		CREATE VIRTUAL TABLE IF NOT EXISTS documents_trigram USING fts5(
			path, content,
			tokenize='trigram',
			content='documents',
			content_rowid='rowid'
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create trigram fts5 table: %w", err)
	}

	// Triggers to keep FTS5 (porter) in sync with the documents table.

	// After INSERT: add row to FTS5.
	if _, err := db.Exec(`
		CREATE TRIGGER IF NOT EXISTS documents_ai AFTER INSERT ON documents BEGIN
			INSERT INTO documents_fts(rowid, path, content)
			VALUES (new.rowid, new.path, new.content);
		END
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create insert trigger: %w", err)
	}

	// After DELETE: remove row from FTS5.
	if _, err := db.Exec(`
		CREATE TRIGGER IF NOT EXISTS documents_ad AFTER DELETE ON documents BEGIN
			INSERT INTO documents_fts(documents_fts, rowid, path, content)
			VALUES ('delete', old.rowid, old.path, old.content);
		END
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create delete trigger: %w", err)
	}

	// After UPDATE: remove old row, insert new row.
	if _, err := db.Exec(`
		CREATE TRIGGER IF NOT EXISTS documents_au AFTER UPDATE ON documents BEGIN
			INSERT INTO documents_fts(documents_fts, rowid, path, content)
			VALUES ('delete', old.rowid, old.path, old.content);
			INSERT INTO documents_fts(rowid, path, content)
			VALUES (new.rowid, new.path, new.content);
		END
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create update trigger: %w", err)
	}

	// Triggers to keep FTS5 (trigram) in sync.

	if _, err := db.Exec(`
		CREATE TRIGGER IF NOT EXISTS documents_trigram_ai AFTER INSERT ON documents BEGIN
			INSERT INTO documents_trigram(rowid, path, content)
			VALUES (new.rowid, new.path, new.content);
		END
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create trigram insert trigger: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TRIGGER IF NOT EXISTS documents_trigram_ad AFTER DELETE ON documents BEGIN
			INSERT INTO documents_trigram(documents_trigram, rowid, path, content)
			VALUES ('delete', old.rowid, old.path, old.content);
		END
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create trigram delete trigger: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TRIGGER IF NOT EXISTS documents_trigram_au AFTER UPDATE ON documents BEGIN
			INSERT INTO documents_trigram(documents_trigram, rowid, path, content)
			VALUES ('delete', old.rowid, old.path, old.content);
			INSERT INTO documents_trigram(rowid, path, content)
			VALUES (new.rowid, new.path, new.content);
		END
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create trigram update trigger: %w", err)
	}

	// Create the fetch_cache table for URL caching.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS fetch_cache (
			url        TEXT NOT NULL,
			source     TEXT NOT NULL DEFAULT '',
			content    TEXT,
			fetched_at INTEGER NOT NULL,
			PRIMARY KEY (url, source)
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create fetch_cache table: %w", err)
	}

	// Only rebuild FTS on startup if inconsistency detected.
	// FTS5Health checks row count parity between documents and FTS tables;
	// triggers normally keep them in sync.
	s := &Store{db: db, dbPath: dbPath}
	if err := s.FTS5Health(); err != nil {
		if _, err2 := db.Exec(`INSERT INTO documents_fts(documents_fts) VALUES('rebuild')`); err2 != nil {
			db.Close()
			return nil, fmt.Errorf("rebuild fts5: %w", err2)
		}
		if _, err2 := db.Exec(`INSERT INTO documents_trigram(documents_trigram) VALUES('rebuild')`); err2 != nil {
			db.Close()
			return nil, fmt.Errorf("rebuild trigram fts5: %w", err2)
		}
	}

	// Restrict DB file permissions to owner read/write only (after file exists).
	if err := secureDBFile(dbPath); err != nil {
		db.Close()
		return nil, fmt.Errorf("secure database file: %w", err)
	}

	return s, nil
}

// Index inserts or replaces a document in the store. The FTS5 index is
// automatically kept in sync via triggers.
func (s *Store) Index(path, content string) error {
	if err := checkSensitiveContent(content); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO documents (path, content, indexed_at) VALUES (?, ?, ?)`,
		path, content, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("index document: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return err
	}
	return nil
}

// Unindex removes a document from the store by its path.
func (s *Store) Unindex(path string) error {
	_, err := s.db.Exec(`DELETE FROM documents WHERE path = ?`, path)
	if err != nil {
		return fmt.Errorf("unindex document: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return err
	}
	return nil
}

// Get retrieves a single document by path. Returns nil if not found.
func (s *Store) Get(path string) (*Document, error) {
	row := s.db.QueryRow(`SELECT path, content, indexed_at FROM documents WHERE path = ?`, path)
	var p, c string
	var ts int64
	if err := row.Scan(&p, &c, &ts); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get document: %w", err)
	}
	return &Document{Path: p, Content: c, IndexedAt: time.Unix(ts, 0)}, nil
}

// Search runs a full-text search across both the porter and trigram indices,
// merging results via RRF (Reciprocal Rank Fusion) for better ranking.
// This is the simple entry point used by batch.go and other internal callers.
// For the full pipeline (flood guard, fuzzy, proximity), use SearchPipeline.
func (s *Store) Search(query string, limit int) ([]SearchResult, error) {
	return s.SearchWithPathPrefix(query, "", limit)
}

// SearchWithPathPrefix is like Search but restricts hits to paths under pathPrefix
// (range comparison: path >= prefix AND path < prefix+\U0010ffff). Empty prefix
// means no path filter.
func (s *Store) SearchWithPathPrefix(query, pathPrefix string, limit int) ([]SearchResult, error) {
	if limit < 0 {
		limit = 0
	}
	porterResults, porterErr := s.searchPorter(query, pathPrefix, limit*3)
	trigramResults, trigramErr := s.searchTrigram(query, pathPrefix, limit*3)

	if porterErr != nil && trigramErr != nil {
		return nil, fmt.Errorf("porter: %v / trigram: %v", porterErr, trigramErr)
	}
	if porterErr != nil && len(trigramResults) == 0 {
		return nil, porterErr
	}
	if trigramErr != nil && len(porterResults) == 0 {
		return nil, trigramErr
	}

	if len(porterResults) == 0 && len(trigramResults) == 0 {
		return nil, nil
	}

	return rrfMerge(porterResults, trigramResults, limit), nil
}

// searchPorter searches the porter-stemmed FTS5 index.
// pathPrefix, when non-empty, constrains results to that path range.
func (s *Store) searchPorter(query, pathPrefix string, limit int) ([]SearchResult, error) {
	ftsQuery := fts5Escape(query)

	var (
		sqlQuery string
		args     []any
	)
	if pathPrefix == "" {
		sqlQuery = `
			SELECT path, snippet(documents_fts, 1, '<b>', '</b>', '...', 256) AS snippet
			FROM documents_fts
			WHERE documents_fts MATCH ?
			ORDER BY rank
			LIMIT ?
		`
		args = []any{ftsQuery, limit}
	} else {
		sqlQuery = `
			SELECT path, snippet(documents_fts, 1, '<b>', '</b>', '...', 256) AS snippet
			FROM documents_fts
			WHERE documents_fts MATCH ?
			  AND path >= ? AND path < ?
			ORDER BY rank
			LIMIT ?
		`
		args = []any{ftsQuery, pathPrefix, pathPrefix + "\U0010ffff", limit}
	}

	rows, err := s.db.Query(sqlQuery, args...)
	if err != nil {
		// If phrase-mode fails, try per-term escaping.
		fallbackQuery := fts5LiteralEscape(query)
		if pathPrefix == "" {
			args = []any{fallbackQuery, limit}
		} else {
			args = []any{fallbackQuery, pathPrefix, pathPrefix + "\U0010ffff", limit}
		}
		rows, err = s.db.Query(sqlQuery, args...)
		if err != nil {
			return nil, fmt.Errorf("porter search: %w", err)
		}
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.Path, &r.Snippet); err != nil {
			return nil, fmt.Errorf("scan porter result: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// searchTrigram searches the trigram FTS5 index (substring matching).
func (s *Store) searchTrigram(query, pathPrefix string, limit int) ([]SearchResult, error) {
	ftsQuery := fts5Escape(query)

	var (
		sqlQuery string
		args     []any
	)
	if pathPrefix == "" {
		sqlQuery = `
			SELECT path, snippet(documents_trigram, 1, '<b>', '</b>', '...', 256) AS snippet
			FROM documents_trigram
			WHERE documents_trigram MATCH ?
			ORDER BY rank
			LIMIT ?
		`
		args = []any{ftsQuery, limit}
	} else {
		sqlQuery = `
			SELECT path, snippet(documents_trigram, 1, '<b>', '</b>', '...', 256) AS snippet
			FROM documents_trigram
			WHERE documents_trigram MATCH ?
			  AND path >= ? AND path < ?
			ORDER BY rank
			LIMIT ?
		`
		args = []any{ftsQuery, pathPrefix, pathPrefix + "\U0010ffff", limit}
	}

	rows, err := s.db.Query(sqlQuery, args...)
	if err != nil {
		// Trigram is more tolerant; try per-term escaping as fallback.
		fallbackQuery := fts5LiteralEscape(query)
		if pathPrefix == "" {
			args = []any{fallbackQuery, limit}
		} else {
			args = []any{fallbackQuery, pathPrefix, pathPrefix + "\U0010ffff", limit}
		}
		rows, err = s.db.Query(sqlQuery, args...)
		if err != nil {
			return nil, fmt.Errorf("trigram search: %w", err)
		}
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		if err := rows.Scan(&r.Path, &r.Snippet); err != nil {
			return nil, fmt.Errorf("scan trigram result: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// extractFilePath extracts clean filesystem path from dbPath / file: URI.
func extractFilePath(dbPath string) string {
	if dbPath == "" || dbPath == ":memory:" {
		return ""
	}
	path := dbPath
	if strings.HasPrefix(path, "file:") {
		path = strings.TrimPrefix(path, "file:")
		if i := strings.IndexAny(path, "?#"); i >= 0 {
			path = path[:i]
		}
	}
	return path
}

// ensureFilePerm0600 checks if the file exists and restores permissions to 0600 if relaxed.
func ensureFilePerm0600(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode().Perm() != 0o600 {
		if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("chmod %q (0600): %w", path, err)
		}
	}
	return nil
}

// secureDBFile ensures the database file (and WAL/SHM sidecars) have 0600 permissions.
func secureDBFile(dbPath string) error {
	path := extractFilePath(dbPath)
	if path == "" {
		return nil
	}
	if err := ensureFilePerm0600(path); err != nil {
		return fmt.Errorf("secure db file %q: %w", path, err)
	}
	for _, ext := range []string{"-wal", "-shm"} {
		sidecar := path + ext
		if err := ensureFilePerm0600(sidecar); err != nil {
			return fmt.Errorf("secure sidecar %q: %w", sidecar, err)
		}
	}
	return nil
}

func (s *Store) secureDBFiles() error {
	path := s.dbPath
	if path == "" {
		path = s.DBPath()
	}
	return secureDBFile(path)
}

// PurgeSessionKeys deletes documents whose path is exactly session:{id}
// or starts with session:{id}: (colon-delimited sub-keys). This avoids the
// classic prefix false-positive where purging "session:ab" also removes
// "session:abc".
func (s *Store) PurgeSessionKeys(sessionID string) (deleted int, err error) {
	exact := "session:" + sessionID
	subPrefix := exact + ":"

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Exact key.
	res, err := tx.Exec(`DELETE FROM documents WHERE path = ?`, exact)
	if err != nil {
		return 0, fmt.Errorf("purge session exact: %w", err)
	}
	rows, _ := res.RowsAffected()
	deleted = int(rows)

	// Colon-delimited children only (not hyphen/other suffix collisions).
	res, err = tx.Exec(
		`DELETE FROM documents WHERE path >= ? AND path < ?`,
		subPrefix, subPrefix+"\U0010ffff",
	)
	if err != nil {
		return 0, fmt.Errorf("purge session sub-keys: %w", err)
	}
	rows, _ = res.RowsAffected()
	deleted += int(rows)

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit session purge: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// CountSessionKeys counts documents matching the same keys as PurgeSessionKeys.
func (s *Store) CountSessionKeys(sessionID string) (int, error) {
	exact := "session:" + sessionID
	subPrefix := exact + ":"
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM documents
		WHERE path = ?
		   OR (path >= ? AND path < ?)
	`, exact, subPrefix, subPrefix+"\U0010ffff").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count session keys: %w", err)
	}
	return count, nil
}

// List returns all documents in the store.
func (s *Store) List() ([]Document, error) {
	rows, err := s.db.Query(`SELECT path, content, indexed_at FROM documents ORDER BY path`)
	if err != nil {
		return nil, fmt.Errorf("list documents: %w", err)
	}
	defer rows.Close()

	var docs []Document
	for rows.Next() {
		var p, c string
		var ts int64
		if err := rows.Scan(&p, &c, &ts); err != nil {
			return nil, fmt.Errorf("scan document: %w", err)
		}
		docs = append(docs, Document{Path: p, Content: c, IndexedAt: time.Unix(ts, 0)})
	}
	return docs, rows.Err()
}

// Stats returns the number of indexed documents and the database file size in bytes.
func (s *Store) Stats() (docCount int, dbSize int64, err error) {
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM documents`).Scan(&docCount); err != nil {
		return 0, 0, fmt.Errorf("count documents: %w", err)
	}

	// Get the database file path from the connection.
	var dbPath string
	var dbSeq int
	var dbName string
	if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&dbSeq, &dbName, &dbPath); err != nil {
		// Non-fatal; return 0 for size.
		dbSize = 0
	} else if fi, statErr := os.Stat(dbPath); statErr == nil {
		dbSize = fi.Size()
	}

	return docCount, dbSize, nil
}

// FTS5Health checks the production FTS5 tables for integrity.
// It verifies that both FTS5 virtual tables (porter and trigram) are accessible
// and that their row counts match the documents table.
//
// Note: row count equality is a necessary but not sufficient condition for
// FTS integrity. Stale FTS content with matching row counts would pass this
// check. In normal operation the AFTER DELETE/INSERT/UPDATE triggers
// guarantee consistency, so this is a best-effort sanity check.
func (s *Store) FTS5Health() error {
	var docRows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM documents`).Scan(&docRows); err != nil {
		return fmt.Errorf("count documents: %w", err)
	}

	var ftsRows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM documents_fts`).Scan(&ftsRows); err != nil {
		return fmt.Errorf("documents_fts not accessible: %w", err)
	}
	if ftsRows != docRows {
		return fmt.Errorf("documents_fts row count mismatch: fts=%d docs=%d", ftsRows, docRows)
	}

	var trigramRows int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM documents_trigram`).Scan(&trigramRows); err != nil {
		return fmt.Errorf("documents_trigram not accessible: %w", err)
	}
	if trigramRows != docRows {
		return fmt.Errorf("documents_trigram row count mismatch: trigram=%d docs=%d", trigramRows, docRows)
	}

	// Row counts matching is necessary but not sufficient. Probe one document
	// so a stale FTS table with the right COUNT still fails.
	if docRows > 0 {
		var content string
		if err := s.db.QueryRow(`SELECT content FROM documents LIMIT 1`).Scan(&content); err != nil {
			return fmt.Errorf("sample document: %w", err)
		}
		if tok := firstFTSToken(content); tok != "" {
			var n int
			q := fts5LiteralEscape(tok)
			if err := s.db.QueryRow(`SELECT COUNT(*) FROM documents_fts WHERE documents_fts MATCH ?`, q).Scan(&n); err != nil {
				return fmt.Errorf("documents_fts MATCH probe: %w", err)
			}
			if n == 0 {
				return fmt.Errorf("documents_fts MATCH probe for %q returned 0 rows", tok)
			}
		}
	}

	return nil
}

func firstFTSToken(content string) string {
	var b strings.Builder
	for _, r := range content {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			if b.Len() >= 8 {
				break
			}
			continue
		}
		if b.Len() >= 3 {
			break
		}
		b.Reset()
	}
	if b.Len() < 3 {
		return ""
	}
	return b.String()
}

// CachedResult represents a cached fetch entry.
type CachedResult struct {
	URL       string
	Source    string
	Content   string
	FetchedAt int64
}

// GetCached retrieves a cached fetch result by url and source.
// Returns nil if not found.
func (s *Store) GetCached(url, source string) (*CachedResult, error) {
	row := s.db.QueryRow(`SELECT url, source, content, fetched_at FROM fetch_cache WHERE url = ? AND source = ?`, url, source)
	var r CachedResult
	if err := row.Scan(&r.URL, &r.Source, &r.Content, &r.FetchedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get cached: %w", err)
	}
	return &r, nil
}

// SetCache inserts or updates a cached fetch result.
func (s *Store) SetCache(url, source, content string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO fetch_cache (url, source, content, fetched_at) VALUES (?, ?, ?, ?)`,
		url, source, content, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("set cache: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return err
	}
	return nil
}

// PruneCache deletes cache entries older than the given duration.
func (s *Store) PruneCache(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge).Unix()
	_, err := s.db.Exec(`DELETE FROM fetch_cache WHERE fetched_at < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("prune cache: %w", err)
	}
	return nil
}

// Close shuts down the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// DBPath returns the filesystem path of the database file.
func (s *Store) DBPath() string {
	if s.dbPath != "" {
		return extractFilePath(s.dbPath)
	}
	var dbPath string
	var dbSeq int
	var dbName string
	// Try to get the database path from SQLite's database_list pragma.
	if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&dbSeq, &dbName, &dbPath); err != nil {
		// Fallback: return empty string; caller should handle.
		return ""
	}
	return dbPath
}

// PurgeAll deletes all documents and cache entries.
// Returns the number of deleted documents and cache entries.
func (s *Store) PurgeAll() (deletedDocs int, deletedCache int, err error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete all documents — the AFTER DELETE triggers clean up FTS tables automatically.
	res, err := tx.Exec(`DELETE FROM documents`)
	if err != nil {
		return 0, 0, fmt.Errorf("purge documents: %w", err)
	}
	docRows, _ := res.RowsAffected()
	deletedDocs = int(docRows)

	// Delete all cache entries.
	res, err = tx.Exec(`DELETE FROM fetch_cache`)
	if err != nil {
		return 0, 0, fmt.Errorf("purge cache: %w", err)
	}
	cacheRows, _ := res.RowsAffected()
	deletedCache = int(cacheRows)

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit purge: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return deletedDocs, deletedCache, err
	}
	return deletedDocs, deletedCache, nil
}

// PurgeExactAndChunks deletes path exactly and path#chunk-* children only.
// Unlike PurgeByPrefix it will not delete a longer sibling (foo vs foobar).
func (s *Store) PurgeExactAndChunks(docPath string) (deleted int, err error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM documents WHERE path = ?`, docPath)
	if err != nil {
		return 0, fmt.Errorf("purge exact: %w", err)
	}
	rows, _ := res.RowsAffected()
	deleted = int(rows)

	chunkPrefix := docPath + "#chunk-"
	res, err = tx.Exec(`DELETE FROM documents WHERE path >= ? AND path < ?`, chunkPrefix, chunkPrefix+"\U0010ffff")
	if err != nil {
		return 0, fmt.Errorf("purge chunks: %w", err)
	}
	rows, _ = res.RowsAffected()
	deleted += int(rows)

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit exact/chunks purge: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// ReplaceExactAndChunks atomically removes existing docPath and docPath#chunk-* entries
// and inserts the provided chunks within a single transaction. If any check or step fails,
// the transaction is rolled back and existing entries are preserved.
func (s *Store) ReplaceExactAndChunks(docPath string, chunks []string) error {
	for _, chunk := range chunks {
		if err := checkSensitiveContent(chunk); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM documents WHERE path = ?`, docPath); err != nil {
		return fmt.Errorf("purge exact: %w", err)
	}
	chunkPrefix := docPath + "#chunk-"
	if _, err := tx.Exec(`DELETE FROM documents WHERE path >= ? AND path < ?`, chunkPrefix, chunkPrefix+"\U0010ffff"); err != nil {
		return fmt.Errorf("purge chunks: %w", err)
	}

	now := time.Now().Unix()
	if len(chunks) == 1 {
		if _, err := tx.Exec(
			`INSERT INTO documents (path, content, indexed_at) VALUES (?, ?, ?)`,
			docPath, chunks[0], now,
		); err != nil {
			return fmt.Errorf("insert doc: %w", err)
		}
	} else {
		for i, chunk := range chunks {
			chunkPath := fmt.Sprintf("%s#chunk-%d", docPath, i)
			if _, err := tx.Exec(
				`INSERT INTO documents (path, content, indexed_at) VALUES (?, ?, ?)`,
				chunkPath, chunk, now,
			); err != nil {
				return fmt.Errorf("insert chunk %d: %w", i, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit replace: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return err
	}
	return nil
}

func (s *Store) CountExactAndChunks(docPath string) (int, error) {
	var n int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM documents
		WHERE path = ? OR (path >= ? AND path < ?)`,
		docPath, docPath+"#chunk-", docPath+"#chunk-\U0010ffff",
	).Scan(&n)
	return n, err
}

// PurgeByPrefix deletes documents whose path starts with the given prefix.
// Returns the number of deleted documents.
func (s *Store) PurgeByPrefix(prefix string) (deleted int, err error) {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM documents WHERE path >= ? AND path < ?`, prefix, prefix+"\U0010ffff")
	if err != nil {
		return 0, fmt.Errorf("purge by prefix: %w", err)
	}
	rows, _ := res.RowsAffected()
	deleted = int(rows)
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit prefix purge: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// CountByPrefix returns the number of documents whose path starts with the
// given prefix. It uses the same range comparison as PurgeByPrefix but does
// not delete anything.
func (s *Store) CountByPrefix(prefix string) (int, error) {
	var count int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM documents WHERE path >= ? AND path < ?`,
		prefix, prefix+"\U0010ffff",
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count by prefix: %w", err)
	}
	return count, nil
}

// Vacuum rebuilds the database file to reclaim space after deletions.
func (s *Store) Vacuum() error {
	_, err := s.db.Exec(`VACUUM`)
	if err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	if err := s.secureDBFiles(); err != nil {
		return fmt.Errorf("vacuum secure db files: %w", err)
	}
	return nil
}

// CacheCount returns the number of entries in the fetch_cache table.
func (s *Store) CacheCount() (int, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM fetch_cache`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count cache: %w", err)
	}
	return count, nil
}

// ---------- FTS5 query escaping ----------

// fts5Escape wraps the query as a phrase search, which lets FTS5 apply the
// porter stemmer to each term while preventing raw FTS5 syntax injection.
// Example: "caching files" → '"caching files"'
func fts5Escape(query string) string {
	// Escape any embedded double quotes by doubling them (FTS5 convention).
	escaped := strings.ReplaceAll(query, `"`, `""`)
	return `"` + escaped + `"`
}

// fts5LiteralEscape is a fallback for when phrase-mode fails. It treats the
// query as a set of individual terms, each double-quoted to prevent syntax
// errors while still benefiting from the porter stemmer.
func fts5LiteralEscape(query string) string {
	parts := strings.Fields(query)
	if len(parts) == 0 {
		return `""`
	}
	escaped := make([]string, len(parts))
	for i, p := range parts {
		e := strings.ReplaceAll(p, `"`, `""`)
		// If it looks like a number, no quoting needed.
		if _, err := strconv.ParseFloat(e, 64); err == nil {
			escaped[i] = e
		} else {
			escaped[i] = `"` + e + `"`
		}
	}
	return strings.Join(escaped, " ")
}
