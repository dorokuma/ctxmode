package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// doctorResult holds the full diagnostic output.
type doctorResult struct {
	Version     string            `json:"version"`
	DBPath      string            `json:"db_path"`
	DBSizeBytes int64             `json:"db_size_bytes"`
	DBError     string            `json:"db_error,omitempty"`
	FTS5Status  string            `json:"fts5_status"` // "ok" / "error: ..."
	Runtimes    map[string]string `json:"runtimes"`    // language -> "available" / "not found: ..."
	DocCount    int               `json:"doc_count"`
	CacheCount  int               `json:"cache_count"`
	Healthy     bool              `json:"healthy"`
	Warnings    []string          `json:"warnings,omitempty"`
}

// runDoctor collects all diagnostic information.
func runDoctor(store *Store, dbPath string) (*doctorResult, error) {
	res := &doctorResult{
		Version:  "1.1.1",
		DBPath:   dbPath,
		Runtimes: make(map[string]string),
		Healthy:  true,
	}

	// Database file size.
	if fi, err := os.Stat(dbPath); err == nil {
		res.DBSizeBytes = fi.Size()
	} else {
		res.DBError = fmt.Sprintf("db file not found / unreadable: %v", err)
		res.Healthy = false
	}

	// FTS5 self-test against the production store.
	if err := store.FTS5Health(); err != nil {
		res.FTS5Status = "error: " + err.Error()
		res.Healthy = false
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
		if checkRuntime(name, false) {
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
		res.Warnings = append(res.Warnings, fmt.Sprintf("doc count failed: %v", err))
		res.Healthy = false
	}
	res.CacheCount, err = store.CacheCount()
	if err != nil {
		res.CacheCount = 0
		res.Warnings = append(res.Warnings, fmt.Sprintf("cache count failed: %v", err))
		res.Healthy = false
	}

	return res, nil
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
