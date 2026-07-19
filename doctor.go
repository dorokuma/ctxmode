package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	_ "modernc.org/sqlite"
)

// doctorResult holds the full diagnostic output.
type doctorResult struct {
	Version     string            `json:"version"`
	DBPath      string            `json:"db_path"`
	DBSizeBytes int64             `json:"db_size_bytes"`
	FTS5Status  string            `json:"fts5_status"`    // "ok" / "error: ..."
	Runtimes    map[string]string `json:"runtimes"`       // language -> "available" / "not found: ..."
	DocCount    int               `json:"doc_count"`
	CacheCount  int               `json:"cache_count"`
}

// runDoctor collects all diagnostic information.
func runDoctor(store *Store, dbPath string) (*doctorResult, error) {
	res := &doctorResult{
		Version:  "0.2.0",
		DBPath:   dbPath,
		Runtimes: make(map[string]string),
	}

	// Database file size.
	if fi, err := os.Stat(dbPath); err == nil {
		res.DBSizeBytes = fi.Size()
	}

	// FTS5 self-test.
	if err := checkFTS5(); err != nil {
		res.FTS5Status = "error: " + err.Error()
	} else {
		res.FTS5Status = "ok"
	}

	// Runtime availability.
	langs := make([]string, 0, len(runtimes))
	for name := range runtimes {
		langs = append(langs, name)
	}
	sort.Strings(langs)
	for _, name := range langs {
		if checkRuntime(name) {
			res.Runtimes[name] = "available"
		} else {
			rt := runtimes[name]
			res.Runtimes[name] = "not found: " + rt.Exe
		}
	}

	// Document and cache counts.
	var err error
	res.DocCount, _, err = store.Stats()
	if err != nil {
		res.DocCount = 0
	}
	res.CacheCount, err = store.CacheCount()
	if err != nil {
		res.CacheCount = 0
	}

	return res, nil
}

// checkFTS5 performs a self-test of the FTS5 engine by creating an in-memory
// database, writing test data, and verifying a search round-trip.
func checkFTS5() error {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return fmt.Errorf("open in-memory db: %w", err)
	}
	defer db.Close()

	// Enable FTS5 (loaded by modernc.org/sqlite by default, but verify).
	if _, err := db.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS test_fts USING fts5(content, tokenize='porter unicode61')`); err != nil {
		return fmt.Errorf("create FTS5 table: %w", err)
	}

	// Insert test data.
	if _, err := db.Exec(`INSERT INTO test_fts(content) VALUES('hello world')`); err != nil {
		return fmt.Errorf("insert test data: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO test_fts(content) VALUES('goodbye moon')`); err != nil {
		return fmt.Errorf("insert test data 2: %w", err)
	}

	// Query test data.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM test_fts WHERE test_fts MATCH 'hello'`).Scan(&count); err != nil {
		return fmt.Errorf("query test data: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("expected 1 result for 'hello', got %d", count)
	}

	// Test trigram tokenizer.
	if _, err := db.Exec(`CREATE VIRTUAL TABLE IF NOT EXISTS test_trigram USING fts5(content, tokenize='trigram')`); err != nil {
		return fmt.Errorf("create trigram FTS5 table: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO test_trigram(content) VALUES('hello world')`); err != nil {
		return fmt.Errorf("insert trigram data: %w", err)
	}

	var tc int
	if err := db.QueryRow(`SELECT COUNT(*) FROM test_trigram WHERE test_trigram MATCH '"wor"'`).Scan(&tc); err != nil {
		return fmt.Errorf("query trigram: %w", err)
	}
	if tc != 1 {
		return fmt.Errorf("expected 1 trigram result for 'wor', got %d", tc)
	}

	return nil
}

// ---------- MCP tool handler for ctx_doctor ----------

type doctorArgs struct {
}

func (s *server) toolDoctor(ctx context.Context, _ *mcp.CallToolRequest, _ doctorArgs) (*mcp.CallToolResult, any, error) {
	// Get the database path from the store.
	dbPath := s.store.DBPath()

	result, err := runDoctor(s.store, dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("doctor check failed: %w", err)
	}

	js, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal doctor result: %w", err)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}
