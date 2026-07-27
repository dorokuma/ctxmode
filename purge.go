package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// purgeArgs is the JSON schema for the ctx_purge tool.
type purgeArgs struct {
	Confirm   bool   `json:"confirm" jsonschema:"MUST be true. Destructive operation; false returns 'purge cancelled'."`
	Scope     string `json:"scope,omitempty" jsonschema:"'session' or 'project'"`
	SessionID string `json:"sessionId,omitempty" jsonschema:"UUID of session to purge (for scope='session')"`
	DryRun    bool   `json:"dryRun,omitempty" jsonschema:"If true, preview what would be deleted without actually deleting"`
}

// purgeResult holds the result of a purge operation.
type purgeResult struct {
	Scope        string `json:"scope"`
	DeletedDocs  int    `json:"deleted_docs"`
	DeletedCache int    `json:"deleted_cache,omitempty"`
	FreedBytes   int64  `json:"freed_bytes,omitempty"`
	Warning      string `json:"warning,omitempty"`
}

func (s *server) toolPurge(ctx context.Context, _ *mcp.CallToolRequest, args purgeArgs) (*mcp.CallToolResult, any, error) {
	// DryRun: preview only, no actual deletion.
	if args.DryRun {
		return s.purgeDryRun(args.Scope, args.SessionID)
	}

	// Must confirm.
	if !args.Confirm {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "purge cancelled"}},
		}, nil, nil
	}

	// Scope is required.
	if args.Scope == "" {
		return nil, nil, fmt.Errorf("must specify scope: 'session' or 'project'")
	}

	switch args.Scope {
	case "project":
		return s.purgeProject()
	case "session":
		return s.purgeSession(args.SessionID)
	default:
		return nil, nil, fmt.Errorf("invalid scope %q: must be 'session' or 'project'", args.Scope)
	}
}

func (s *server) purgeProject() (*mcp.CallToolResult, any, error) {
	// Get DB size before purge for freed bytes calculation.
	// Include WAL and SHM files for accurate measurement.
	dbPath := s.store.DBPath()
	var beforeSize int64
	for _, ext := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(dbPath + ext); err == nil {
			beforeSize += fi.Size()
		}
	}

	deletedDocs, deletedCache, err := s.store.PurgeAll()
	if err != nil {
		return nil, nil, fmt.Errorf("purge project: %w", err)
	}

	// Run VACUUM to reclaim space. VACUUM cannot run inside a transaction,
	// so it is called separately here. If VACUUM fails, the documents have
	// already been deleted successfully — we report a warning, not an error.
	var warning string
	if err := s.store.Vacuum(); err != nil {
		warning = fmt.Sprintf("vacuum after purge failed (documents deleted, space not reclaimed): %v", err)
	}

	// Calculate freed bytes (include WAL and SHM files).
	var afterSize int64
	for _, ext := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Stat(dbPath + ext); err == nil {
			afterSize += fi.Size()
		}
	}
	freedBytes := beforeSize - afterSize
	if freedBytes < 0 {
		freedBytes = 0
	}

	res := purgeResult{
		Scope:        "project",
		DeletedDocs:  deletedDocs,
		DeletedCache: deletedCache,
		FreedBytes:   freedBytes,
		Warning:      warning,
	}

	js, _ := json.MarshalIndent(res, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

func (s *server) purgeSession(sessionID string) (*mcp.CallToolResult, any, error) {
	if sessionID == "" {
		return nil, nil, fmt.Errorf("sessionId is required when scope='session'")
	}

	// Exact match on session:{id} plus colon-delimited children session:{id}:...
	// Avoids prefix false-positives (session:ab must not delete session:abc).
	totalDeleted, err := s.store.PurgeSessionKeys(sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("purge session %q: %w", sessionID, err)
	}

	res := purgeResult{
		Scope:       "session",
		DeletedDocs: totalDeleted,
	}

	js, _ := json.MarshalIndent(res, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

// purgeDryRun counts what would be deleted without actually deleting anything.
func (s *server) purgeDryRun(scope, sessionID string) (*mcp.CallToolResult, any, error) {
	if scope == "" {
		return nil, nil, fmt.Errorf("must specify scope: 'session' or 'project'")
	}

	switch scope {
	case "project":
		docCount, _, err := s.store.Stats()
		if err != nil {
			return nil, nil, fmt.Errorf("dryRun count: %w", err)
		}
		cacheCount, err := s.store.CacheCount()
		if err != nil {
			return nil, nil, fmt.Errorf("dryRun cache count: %w", err)
		}
		res := purgeResult{
			Scope:        "project",
			DeletedDocs:  docCount,
			DeletedCache: cacheCount,
		}
		js, _ := json.MarshalIndent(res, "", "  ")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("DRY RUN — would delete:\n%s", string(js))}},
		}, nil, nil
	case "session":
		if sessionID == "" {
			return nil, nil, fmt.Errorf("sessionId is required when scope='session'")
		}
		n, err := s.store.CountSessionKeys(sessionID)
		if err != nil {
			return nil, nil, fmt.Errorf("dryRun count: %w", err)
		}
		res := purgeResult{
			Scope:       "session",
			DeletedDocs: n,
		}
		js, _ := json.MarshalIndent(res, "", "  ")
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("DRY RUN — would delete:\n%s", string(js))}},
		}, nil, nil
	default:
		return nil, nil, fmt.Errorf("invalid scope %q: must be 'session' or 'project'", scope)
	}
}
