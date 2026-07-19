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
}

// purgeResult holds the result of a purge operation.
type purgeResult struct {
	Scope        string `json:"scope"`
	DeletedDocs  int    `json:"deleted_docs"`
	DeletedCache int    `json:"deleted_cache,omitempty"`
	FreedBytes   int64  `json:"freed_bytes,omitempty"`
}

func (s *server) toolPurge(ctx context.Context, _ *mcp.CallToolRequest, args purgeArgs) (*mcp.CallToolResult, any, error) {
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
	dbPath := s.store.DBPath()
	var beforeSize int64
	if fi, err := os.Stat(dbPath); err == nil {
		beforeSize = fi.Size()
	}

	deletedDocs, deletedCache, err := s.store.PurgeAll()
	if err != nil {
		return nil, nil, fmt.Errorf("purge project: %w", err)
	}

	// Run VACUUM to reclaim space.
	if err := s.store.Vacuum(); err != nil {
		return nil, nil, fmt.Errorf("vacuum after purge: %w", err)
	}

	// Calculate freed bytes.
	var afterSize int64
	if fi, err := os.Stat(dbPath); err == nil {
		afterSize = fi.Size()
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

	// Delete documents whose path starts with known index prefixes.
	// NOTE: session isolation is not yet fully implemented — execute/execute_file
	// labels currently use timestamps or intent strings, not sessionID.
	// For now, session scope deletes anything under session:/batch:/execute:/execute_file:
	// with a caller-chosen sessionID. For full cleanup, use scope="project".
	prefixes := []string{
		"session:" + sessionID,
		"batch:" + sessionID,
		"execute_file:" + sessionID,
		"execute:" + sessionID,
	}

	totalDeleted := 0
	for _, prefix := range prefixes {
		n, err := s.store.PurgeByPrefix(prefix)
		if err != nil {
			return nil, nil, fmt.Errorf("purge session prefix %q: %w", prefix, err)
		}
		totalDeleted += n
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
