package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
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
	db *sql.DB
}

// NewStore opens or creates a SQLite database at dbPath and initializes
// the schema (documents table, FTS5 virtual table, and sync triggers).
func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
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

	// Rebuild both FTS5 indices to fix any rowid inconsistencies.
	// This is safe to call on every startup and is a no-op if the index is already clean.
	if _, err := db.Exec(`INSERT INTO documents_fts(documents_fts) VALUES('rebuild')`); err != nil {
		db.Close()
		return nil, fmt.Errorf("rebuild fts5: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO documents_trigram(documents_trigram) VALUES('rebuild')`); err != nil {
		db.Close()
		return nil, fmt.Errorf("rebuild trigram fts5: %w", err)
	}

	return &Store{db: db}, nil
}

// Index inserts or replaces a document in the store. The FTS5 index is
// automatically kept in sync via triggers.
func (s *Store) Index(path, content string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO documents (path, content, indexed_at) VALUES (?, ?, ?)`,
		path, content, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("index document: %w", err)
	}
	return nil
}

// Unindex removes a document from the store by its path.
func (s *Store) Unindex(path string) error {
	_, err := s.db.Exec(`DELETE FROM documents WHERE path = ?`, path)
	if err != nil {
		return fmt.Errorf("unindex document: %w", err)
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
	porterResults, err := s.searchPorter(query, limit*3)
	if err != nil {
		porterResults = nil
	}

	trigramResults, err := s.searchTrigram(query, limit*3)
	if err != nil {
		trigramResults = nil
	}

	if len(porterResults) == 0 && len(trigramResults) == 0 {
		return nil, nil
	}

	return rrfMerge(porterResults, trigramResults, limit), nil
}

// searchPorter searches the porter-stemmed FTS5 index.
func (s *Store) searchPorter(query string, limit int) ([]SearchResult, error) {
	ftsQuery := fts5Escape(query)

	sqlQuery := `
		SELECT path, snippet(documents_fts, 1, '<b>', '</b>', '...', 256) AS snippet
		FROM documents_fts
		WHERE documents_fts MATCH ?
		ORDER BY rank
		LIMIT ?
	`

	rows, err := s.db.Query(sqlQuery, ftsQuery, limit)
	if err != nil {
		// If phrase-mode fails, try per-term escaping.
		fallbackQuery := fts5LiteralEscape(query)
		rows, err = s.db.Query(sqlQuery, fallbackQuery, limit)
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
	return results, rows.Err()
}

// searchTrigram searches the trigram FTS5 index (substring matching).
func (s *Store) searchTrigram(query string, limit int) ([]SearchResult, error) {
	ftsQuery := fts5Escape(query)

	sqlQuery := `
		SELECT path, snippet(documents_trigram, 1, '<b>', '</b>', '...', 256) AS snippet
		FROM documents_trigram
		WHERE documents_trigram MATCH ?
		ORDER BY rank
		LIMIT ?
	`

	rows, err := s.db.Query(sqlQuery, ftsQuery, limit)
	if err != nil {
		// Trigram is more tolerant; try the raw query as fallback.
		rows, err = s.db.Query(sqlQuery, query, limit)
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
	return results, rows.Err()
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
	var dbSeq int; var dbName string
	if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&dbSeq, &dbName, &dbPath); err != nil {
		// Non-fatal; return 0 for size.
		dbSize = 0
	} else if fi, statErr := os.Stat(dbPath); statErr == nil {
		dbSize = fi.Size()
	}

	return docCount, dbSize, nil
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
	var dbPath string
	var dbSeq int; var dbName string
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
	// Delete all documents — the AFTER DELETE triggers clean up FTS tables automatically.
	res, err := s.db.Exec(`DELETE FROM documents`)
	if err != nil {
		return 0, 0, fmt.Errorf("purge documents: %w", err)
	}
	docRows, _ := res.RowsAffected()
	deletedDocs = int(docRows)

	// Rebuild both FTS indices to guarantee consistency even if triggers were
	// missing or disabled during the DELETE.
	_, _ = s.db.Exec(`INSERT INTO documents_fts(documents_fts) VALUES('rebuild')`)
	_, _ = s.db.Exec(`INSERT INTO documents_trigram(documents_trigram) VALUES('rebuild')`)

	// Delete all cache entries.
	res, err = s.db.Exec(`DELETE FROM fetch_cache`)
	if err != nil {
		return deletedDocs, 0, fmt.Errorf("purge cache: %w", err)
	}
	cacheRows, _ := res.RowsAffected()
	deletedCache = int(cacheRows)

	return deletedDocs, deletedCache, nil
}

// PurgeByPrefix deletes documents whose path starts with the given prefix.
// Returns the number of deleted documents.
func (s *Store) PurgeByPrefix(prefix string) (deleted int, err error) {
	// Escape LIKE wildcards in the prefix so that literal % and _ are not
	// interpreted as pattern characters.
	escaped := strings.ReplaceAll(prefix, "%", `\%`)
	escaped = strings.ReplaceAll(escaped, "_", `\_`)
	res, err := s.db.Exec(`DELETE FROM documents WHERE path LIKE ?`, escaped+"%")
	if err != nil {
		return 0, fmt.Errorf("purge by prefix: %w", err)
	}
	rows, _ := res.RowsAffected()
	deleted = int(rows)
	// Rebuild FTS indexes to guarantee consistency after selective deletions.
	if deleted > 0 {
		_, _ = s.db.Exec(`INSERT INTO documents_fts(documents_fts) VALUES('rebuild')`)
		_, _ = s.db.Exec(`INSERT INTO documents_trigram(documents_trigram) VALUES('rebuild')`)
	}
	return deleted, nil
}

// Vacuum rebuilds the database file to reclaim space after deletions.
func (s *Store) Vacuum() error {
	_, err := s.db.Exec(`VACUUM`)
	if err != nil {
		return fmt.Errorf("vacuum: %w", err)
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
