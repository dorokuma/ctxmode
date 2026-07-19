// ctxmode: a Go MCP server that virtualizes tool output to save context tokens.
// Registers: ctx_execute, ctx_execute_file, ctx_index, ctx_search, ctx_stats, ctx_fetch_and_index, ctx_batch_execute, ctx_doctor, ctx_purge.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type server struct {
	workdir        string
	mu             sync.Mutex
	store          *Store
	floodGuard     *FloodGuard
	searchPipeline *SearchPipeline
	totalInput     int64
	totalOutput    int64
}

func main() {
	var workdir string
	flag.StringVar(&workdir, "workdir", "", "workspace root (default: cwd)")
	flag.Parse()

	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatalf("cannot get cwd: %v", err)
		}
		workdir = wd
	}
	absWd, err := filepath.Abs(workdir)
	if err != nil {
		log.Fatalf("bad workdir: %v", err)
	}
	workdir = absWd

	store, err := NewStore(filepath.Join(workdir, "context_mode.db"))
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	floodGuard := NewFloodGuard(60 * time.Second)
	searchPipeline := NewSearchPipeline(store, floodGuard)

	s := &server{
		workdir:        workdir,
		store:          store,
		floodGuard:     floodGuard,
		searchPipeline: searchPipeline,
	}
	if err := s.migrateFromJSON(); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}
	s.excludeFromGit()

	srv := mcp.NewServer(&mcp.Implementation{Name: "ctxmode", Version: "1.0.0"}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_execute",
		Description: "Run code in a sandboxed subprocess. Supports 12 languages (javascript, typescript, python, shell, go, rust, php, perl, ruby, r, elixir, csharp). Heavy outputs are auto-indexed to prevent flooding the context window.",
	}, s.toolExecute)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_index",
		Description: "Index a file or directory into the local knowledge base, avoiding sending the entire file repeatedly.",
	}, s.toolIndex)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_search",
		Description: "Search for query terms in the indexed local knowledge base, returning only matching lines or snippets.",
	}, s.toolSearch)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_stats",
		Description: "Report token saving statistics of the current context virtualization session.",
	}, s.toolStats)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_fetch_and_index",
		Description: "Fetch URL content, convert to markdown, and index into knowledge base. Cache hits are returned immediately.",
	}, s.toolFetchAndIndex)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_batch_execute",
		Description: "Run multiple commands in ONE call. Every command's output is auto-indexed into the knowledge base; if you also pass queries, the matching sections come back in the same round trip.",
	}, s.toolBatchExecute)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_execute_file",
		Description: "Read a file into a FILE_CONTENT variable and run code over it. Languages: javascript, python, shell, go, rust, php, perl, ruby, r, elixir, csharp. Supports auto-indexing for large output.",
	}, s.toolExecuteFile)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_doctor",
		Description: "Diagnose context-mode installation. Checks runtimes, FTS5, storage, and version.",
	}, s.toolDoctor)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_purge",
		Description: "DESTRUCTIVE: permanently delete indexed content. Cannot be undone. Requires confirm:true.",
	}, s.toolPurge)

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

// ---------- tool implementations ----------

type executeArgs struct {
	Command    string `json:"command,omitempty" jsonschema:"Command or code to execute"`
	Language   string `json:"language,omitempty" jsonschema:"Runtime language (javascript/python/shell/go/...)"`
	Timeout    int    `json:"timeout,omitempty" jsonschema:"Max execution time in ms"`
	Background bool   `json:"background,omitempty" jsonschema:"Keep running after timeout (for servers/daemons)"`
	Intent     string `json:"intent,omitempty" jsonschema:"What you're looking for in the output (for auto-indexing)"`
	CWD        string `json:"cwd,omitempty" jsonschema:"Working directory"`
}

func (s *server) toolExecute(ctx context.Context, _ *mcp.CallToolRequest, args executeArgs) (*mcp.CallToolResult, any, error) {
	if args.Command == "" {
		return nil, nil, fmt.Errorf("command is required")
	}

	// Default language is shell (backward compatible).
	language := args.Language
	if language == "" {
		language = "shell"
	}

	// Parse timeout.
	var timeout time.Duration
	if args.Timeout > 0 {
		timeout = time.Duration(args.Timeout) * time.Millisecond
	}

	// Resolve working directory.
	cwd := s.workdir
	if args.CWD != "" {
		resolved, err := s.resolvePath(args.CWD)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cwd: %w", err)
		}
		cwd = resolved
	}

	// Execute code in the sandbox.
	result, err := runCode(language, args.Command, cwd, timeout, args.Background)
	if err != nil {
		return nil, nil, err
	}

	// Track stats.
	s.mu.Lock()
	s.totalInput += int64(len(args.Command))
	s.totalOutput += int64(len(result.Stdout) + len(result.Stderr))
	s.mu.Unlock()

	// Build output text.
	outputText := result.Stdout
	if result.Stderr != "" {
		if outputText != "" {
			outputText += "\n"
		}
		outputText += result.Stderr
	}
	if result.ExitCode != 0 && !strings.HasPrefix(outputText, "Process started in background") {
		if outputText != "" {
			outputText += "\n"
		}
		outputText += fmt.Sprintf("(exited with code %d)", result.ExitCode)
	}

	// Auto-indexing logic.
	const (
		autoIndexThreshold = 100 * 1024 // 100KB
		intentThreshold    = 5 * 1024  // 5KB
	)

	if len(outputText) > autoIndexThreshold {
		// Unconditionally index large outputs.
		label := fmt.Sprintf("execute:%d", time.Now().UnixNano())
		if args.Intent != "" {
			label = "execute:" + args.Intent
		}
		if err := s.storeIndexLocked(label, outputText); err == nil {
			result.Indexed = true
			result.IndexLabel = label
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{
				Text: fmt.Sprintf("Output is too large (%d bytes). Indexed as %q. Use ctx_search(queries: [%q]) to search the indexed content.",
					len(outputText), label, args.Intent),
			}},
		}, nil, nil
	}

	if len(outputText) > intentThreshold && args.Intent != "" {
		// Index and return a preview.
		label := "execute:" + args.Intent
		if err := s.storeIndexLocked(label, outputText); err == nil {
			result.Indexed = true
			result.IndexLabel = label
		}

		preview := outputText
		if len(preview) > 2000 {
			preview = truncateUTF8(preview, 2000) + "\n... (truncated)"
		}
		summary := fmt.Sprintf("Output (%d bytes) indexed as %q. Use ctx_search(queries: [%q]) to search.\n\n--- Preview ---\n%s",
			len(outputText), label, args.Intent, preview)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, nil, nil
	}

	// Normal return.
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: outputText}},
	}, nil, nil
}

type indexArgs struct {
	Path string `json:"path" jsonschema:"file or directory path to index"`
}

func (s *server) toolIndex(ctx context.Context, _ *mcp.CallToolRequest, args indexArgs) (*mcp.CallToolResult, any, error) {
	if args.Path == "" {
		return nil, nil, fmt.Errorf("path is required")
	}

	target, err := s.resolvePath(args.Path)
	if err != nil {
		return nil, nil, err
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, nil, err
	}

	indexedCount := 0
	skippedCount := 0
	if info.IsDir() {
		err = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.Contains(path, "/.git/") || strings.Contains(path, "/node_modules/") {
				skippedCount++
				return nil
			}
			if isProbablyBinary(info.Name()) || info.Size() > 1*1024*1024 {
				skippedCount++
				return nil
			}
			if err := s.indexFile(path); err == nil {
				indexedCount++
			} else {
				skippedCount++
			}
			return nil
		})
	} else {
		if isProbablyBinary(info.Name()) || info.Size() > 1*1024*1024 {
			return nil, nil, fmt.Errorf("file %q is binary or too large (> 1MB)", target)
		}
		err = s.indexFile(target)
		if err == nil {
			indexedCount = 1
		} else {
			skippedCount = 1
		}
	}

	if err != nil {
		return nil, nil, err
	}

	msg := fmt.Sprintf("Indexed %d file(s)", indexedCount)
	if skippedCount > 0 {
		msg += fmt.Sprintf(" (%d skipped)", skippedCount)
	}
	msg += "."
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil, nil
}

type searchArgs struct {
	Query string `json:"query" jsonschema:"search terms or pattern"`
}

func (s *server) toolSearch(ctx context.Context, _ *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
	if args.Query == "" {
		return nil, nil, fmt.Errorf("query is required")
	}

	results, meta, err := s.searchPipeline.Search(args.Query, 20)
	if err != nil {
		// If blocked by flood guard, return a friendly message.
		if meta != nil && meta.FloodStatus == "blocked" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "Search blocked: too many requests in a short time. Use ctx_batch_execute to batch your searches, or wait a moment."}},
			}, nil, nil
		}
		return nil, nil, fmt.Errorf("search failed: %w", err)
	}

	if len(results) == 0 {
		msg := "No matches found."
		if meta != nil && meta.Corrected {
			msg = "No matches found (fuzzy search attempted)."
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, nil, nil
	}

	var lines []string

	// Add throttle warning if present.
	if meta != nil && meta.ThrottleMsg != "" {
		lines = append(lines, "⚠️  "+meta.ThrottleMsg)
	}

	// Add fuzzy correction notice.
	if meta != nil && meta.Corrected {
		lines = append(lines, "ℹ️  Fuzzy search applied (results may include similar terms)")
	}

	for _, r := range results {
		rel, _ := filepath.Rel(s.workdir, r.Path)
		if rel == "" {
			rel = r.Path
		}
		lines = append(lines, fmt.Sprintf("Matches in file %s:\n  Snippet: %s", rel, r.Snippet))
	}

	text := strings.Join(lines, "\n\n")
	if len(text) > 40_000 {
		text = truncateUTF8(text, 40_000) + "\n... (truncated search results)"
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}

// statsResult is the detailed response for ctx_stats.
type statsResult struct {
	DocsIndexed        int   `json:"docs_indexed"`
	CacheEntries       int   `json:"cache_entries"`
	DBSizeBytes        int64 `json:"db_size_bytes"`
	TotalInput         int64 `json:"total_input_bytes"`
	TotalOutput        int64 `json:"total_output_bytes"`
	SavedEstimateBytes int64 `json:"saved_estimate_bytes"`
	SearchCallsWindow  int   `json:"search_calls_60s,omitempty"`
}

type statsArgs struct{}

func (s *server) toolStats(ctx context.Context, _ *mcp.CallToolRequest, _ statsArgs) (*mcp.CallToolResult, any, error) {
	// Get flood guard count outside server lock (has its own mutex).
	windowCount := s.floodGuard.WindowCount()

	s.mu.Lock()
	defer s.mu.Unlock()

	docCount, dbSize, err := s.store.Stats()
	if err != nil {
		docCount = 0
	}

	cacheCount, err := s.store.CacheCount()
	if err != nil {
		cacheCount = 0
	}

	savedBytes := s.totalOutput - s.totalInput
	if savedBytes < 0 {
		savedBytes = 0
	}

	res := statsResult{
		DocsIndexed:        docCount,
		CacheEntries:       cacheCount,
		DBSizeBytes:        dbSize,
		TotalInput:         s.totalInput,
		TotalOutput:        s.totalOutput,
		SavedEstimateBytes: savedBytes,
		SearchCallsWindow:  windowCount,
	}

	js, _ := json.MarshalIndent(res, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

// ---------- ctx_execute_file ----------

type executeFileArgs struct {
	Path     string `json:"path" jsonschema:"File path to read into FILE_CONTENT variable"`
	Language string `json:"language,omitempty" jsonschema:"Runtime language (javascript/python/shell/go/...)"`
	Code     string `json:"code" jsonschema:"Code that processes FILE_CONTENT variable"`
	Timeout  int    `json:"timeout,omitempty" jsonschema:"Max execution time in ms"`
	Intent   string `json:"intent,omitempty" jsonschema:"What you're looking for in the output"`
	CWD      string `json:"cwd,omitempty" jsonschema:"Working directory"`
}

func (s *server) toolExecuteFile(ctx context.Context, _ *mcp.CallToolRequest, args executeFileArgs) (*mcp.CallToolResult, any, error) {
	if args.Path == "" {
		return nil, nil, fmt.Errorf("path is required")
	}
	if args.Code == "" {
		return nil, nil, fmt.Errorf("code is required")
	}

	// Resolve file path.
	target, err := s.resolvePath(args.Path)
	if err != nil {
		return nil, nil, err
	}

	// Check file size before reading to prevent OOM on huge files.
	info, err := os.Stat(target)
	if err != nil {
		return nil, nil, fmt.Errorf("stat file: %w", err)
	}
	if info.Size() > 10*1024*1024 {
		return nil, nil, fmt.Errorf("file %q is too large (%d bytes, max 10MB)", target, info.Size())
	}
	if isProbablyBinary(info.Name()) {
		return nil, nil, fmt.Errorf("file %q appears to be binary, refusing to read as code input", target)
	}

	// Read file content.
	fileContent, err := os.ReadFile(target)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	// Default language.
	language := args.Language
	if language == "" {
		language = "javascript"
	}

	// Parse timeout.
	var timeout time.Duration
	if args.Timeout > 0 {
		timeout = time.Duration(args.Timeout) * time.Millisecond
	}

	// Resolve working directory.
	cwd := s.workdir
	if args.CWD != "" {
		resolved, err := s.resolvePath(args.CWD)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cwd: %w", err)
		}
		cwd = resolved
	}

	// Inject FILE_CONTENT into user code.
	injectedCode := injectFileContent(language, args.Code, string(fileContent))

	// Execute the injected code.
	result, err := runCode(language, injectedCode, cwd, timeout, false)
	if err != nil {
		return nil, nil, err
	}

	// Track stats.
	s.mu.Lock()
	s.totalInput += int64(len(args.Code) + len(target))
	s.totalOutput += int64(len(result.Stdout) + len(result.Stderr))
	s.mu.Unlock()

	// Build output text.
	outputText := result.Stdout
	if result.Stderr != "" {
		if outputText != "" {
			outputText += "\n"
		}
		outputText += result.Stderr
	}

	// Auto-indexing logic (same as toolExecute).
	const (
		autoIndexThreshold = 100 * 1024 // 100KB
		intentThreshold    = 5 * 1024  // 5KB
	)

	if len(outputText) > autoIndexThreshold {
		label := "execute_file:" + filepath.Base(target)
		if args.Intent != "" {
			label = "execute_file:" + args.Intent
		}
		if err := s.storeIndexLocked(label, outputText); err == nil {
			result.Indexed = true
			result.IndexLabel = label
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{
				Text: fmt.Sprintf("Output is too large (%d bytes). Indexed as %q. Use ctx_search to search.",
					len(outputText), label),
			}},
		}, nil, nil
	}

	if len(outputText) > intentThreshold && args.Intent != "" {
		label := "execute_file:" + args.Intent
		if err := s.storeIndexLocked(label, outputText); err == nil {
			result.Indexed = true
			result.IndexLabel = label
		}

		preview := outputText
		if len(preview) > 2000 {
			preview = truncateUTF8(preview, 2000) + "\n... (truncated)"
		}
		summary := fmt.Sprintf("Output (%d bytes) indexed as %q. Use ctx_search to search.\n\n--- Preview ---\n%s",
			len(outputText), label, preview)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: outputText}},
	}, nil, nil
}

// ---------- db helpers ----------

func (s *server) indexFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return s.storeIndexLocked(path, string(data))
}

func (s *server) migrateFromJSON() error {
	oldPath := filepath.Join(s.workdir, ".context_mode_db.json")

	data, err := os.ReadFile(oldPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read old JSON db: %w", err)
	}

	// Check if we already have data in SQLite.
	docCount, _, err := s.store.Stats()
	if err != nil {
		return fmt.Errorf("check store stats: %w", err)
	}
	if docCount > 0 {
		// Already migrated; just backup the old file.
		_ = os.Rename(oldPath, oldPath+".bak")
		return nil
	}

	// Parse old JSON format: map[string]Document
	var oldDocs map[string]Document
	if err := json.Unmarshal(data, &oldDocs); err != nil {
		return fmt.Errorf("parse old JSON: %w", err)
	}

	for _, doc := range oldDocs {
		if err := s.storeIndexLocked(doc.Path, doc.Content); err != nil {
			return fmt.Errorf("migrate document %q: %w", doc.Path, err)
		}
	}

	// Rename old file as backup.
	_ = os.Rename(oldPath, oldPath+".bak")
	return nil
}

// truncateUTF8 truncates a string to the given byte limit at a valid UTF-8 boundary.
// If the limit falls in the middle of a multi-byte rune, it backs up to the
// previous complete rune boundary.
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// Truncate to maxBytes, then step back to a valid rune boundary.
	// Invalid UTF-8 at the end is almost always a truncated multi-byte rune.
	s = s[:maxBytes]
	for len(s) > 0 && !utf8.Valid([]byte(s)) {
		s = s[:len(s)-1]
	}
	return s
}

func isProbablyBinary(name string) bool {
	for _, ext := range []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".zip", ".tar", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar",
		".exe", ".bin", ".dll", ".so", ".dylib", ".wasm",
		".o", ".a", ".lib", ".obj",
		".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".ogg",
		".ttf", ".otf", ".woff", ".woff2",
		".pyc", ".pyo", ".class", ".jar",
		".db", ".sqlite", ".sqlite3",
		".iso", ".dmg", ".img",
	} {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			return true
		}
	}
	return false
}

// storeIndexLocked wraps store.Index with the server mutex, ensuring that
// concurrent writes from different goroutines are serialized. Combined with
// SetMaxOpenConns(1) in the store, this prevents SQLITE_BUSY on concurrent
// index operations.
func (s *server) storeIndexLocked(path, content string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Index(path, content)
}

// resolvePath converts a user-supplied path into an absolute path within the workspace.
// It guarantees the result is inside s.workdir, preventing path traversal.
func (s *server) resolvePath(p string) (string, error) {
	if p == "" {
		return s.workdir, nil
	}
	var target string
	if filepath.IsAbs(p) {
		target = filepath.Clean(p)
	} else {
		target = filepath.Clean(filepath.Join(s.workdir, p))
	}
	if target != s.workdir && !strings.HasPrefix(target, s.workdir+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside workspace %q", p, s.workdir)
	}
	return target, nil
}

// excludeFromGit appends the local database files to .git/info/exclude to avoid workspace pollution.
func (s *server) excludeFromGit() {
	gitDir := filepath.Join(s.workdir, ".git")
	if info, err := os.Stat(gitDir); err == nil && info.IsDir() {
		excludePath := filepath.Join(gitDir, "info", "exclude")
		_ = os.MkdirAll(filepath.Dir(excludePath), 0755)
		data, err := os.ReadFile(excludePath)
		content := ""
		if err == nil {
			content = string(data)
		}
		if !strings.Contains(content, "context_mode.db") {
			f, err := os.OpenFile(excludePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				_, _ = f.WriteString("\n# ctxmode local database\ncontext_mode.db\ncontext_mode.db-wal\ncontext_mode.db-shm\n")
			}
		}
	}
}
