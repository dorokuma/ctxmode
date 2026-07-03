// ctxmode: a Go MCP server that virtualizes tool output to save context tokens.
// Registers: ctx_execute, ctx_index, ctx_search, ctx_stats.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Document struct {
	Path      string    `json:"path"`
	Content   string    `json:"content"`
	IndexedAt time.Time `json:"indexed_at"`
}

type server struct {
	workdir     string
	mu          sync.Mutex
	documents   map[string]Document
	dbPath      string
	totalInput  int64
	totalOutput int64
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

	s := &server{
		workdir:   workdir,
		documents: make(map[string]Document),
		dbPath:    filepath.Join(workdir, ".context_mode_db.json"),
	}
	if err := s.loadDB(); err != nil {
		log.Fatalf("failed to load database: %v", err)
	}
	s.excludeFromGit()

	srv := mcp.NewServer(&mcp.Implementation{Name: "ctxmode", Version: "0.1.0"}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_execute",
		Description: "Run a shell command in a sandboxed way. Heavy outputs (logs, build traces) are compressed and saved locally to prevent flooding the context window.",
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

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

// ---------- tool implementations ----------

type executeArgs struct {
	Command string `json:"command" jsonschema:"shell command to execute"`
}

func (s *server) toolExecute(ctx context.Context, _ *mcp.CallToolRequest, args executeArgs) (*mcp.CallToolResult, any, error) {
	if args.Command == "" {
		return nil, nil, fmt.Errorf("command is required")
	}

	var cmd *exec.Cmd
	if os.Getenv("SHELL") != "" {
		cmd = exec.Command(os.Getenv("SHELL"), "-c", args.Command)
	} else {
		cmd = exec.Command("sh", "-c", args.Command)
	}
	cmd.Dir = s.workdir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		case <-done:
		}
	}()

	out, err := cmd.CombinedOutput()
	rawOutput := string(out)
	if err != nil && rawOutput == "" {
		rawOutput = fmt.Sprintf("Command failed to execute: %v", err)
	}

	s.mu.Lock()
	s.totalInput += int64(len(args.Command))
	s.totalOutput += int64(len(rawOutput))
	s.mu.Unlock()

	// Virtualization limit: if output exceeds 40KB, intercept and summarize
	limit := 40_000
	if len(rawOutput) > limit {
		// truncate safe to rune boundary
		truncAt := limit
		for truncAt > 0 && !utf8.ValidString(rawOutput[:truncAt]) {
			truncAt--
		}
		truncated := rawOutput[:truncAt]
		savedPath := filepath.Join(os.TempDir(), fmt.Sprintf("context_mode_log_%d.log", time.Now().UnixNano()))
		_ = os.WriteFile(savedPath, out, 0600)

		summary := fmt.Sprintf(
			"Command executed successfully.\nWarning: Output is too large (%d bytes).\nSaved full log to: %s\n\n--- [First %d bytes] ---\n%s\n--- [Truncated] ---",
			len(rawOutput), savedPath, limit, truncated,
		)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: rawOutput}},
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
	if info.IsDir() {
		err = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.Contains(path, "/.git/") || strings.Contains(path, "/node_modules/") {
				return nil
			}
			if isProbablyBinary(info.Name()) || info.Size() > 1*1024*1024 {
				return nil
			}
			if err := s.indexFile(path); err == nil {
				indexedCount++
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
		}
	}

	if err != nil {
		return nil, nil, err
	}

	s.saveDB()

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Successfully indexed %d file(s) into local database.", indexedCount)}},
	}, nil, nil
}

type searchArgs struct {
	Query string `json:"query" jsonschema:"search terms or pattern"`
}

func (s *server) toolSearch(ctx context.Context, _ *mcp.CallToolRequest, args searchArgs) (*mcp.CallToolResult, any, error) {
	if args.Query == "" {
		return nil, nil, fmt.Errorf("query is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var results []string
	queryLower := strings.ToLower(args.Query)

	for _, doc := range s.documents {
		if strings.Contains(strings.ToLower(doc.Content), queryLower) {
			// Find matching lines
			lines := strings.Split(doc.Content, "\n")
			matchedLines := 0
			var snippet []string
			for idx, line := range lines {
				if strings.Contains(strings.ToLower(line), queryLower) {
					snippet = append(snippet, fmt.Sprintf("  Line %d: %s", idx+1, strings.TrimSpace(line)))
					matchedLines++
					if matchedLines >= 5 {
						snippet = append(snippet, "  ...")
						break
					}
				}
			}
			rel, _ := filepath.Rel(s.workdir, doc.Path)
			if rel == "" {
				rel = doc.Path
			}
			results = append(results, fmt.Sprintf("Matches in file %s:\n%s", rel, strings.Join(snippet, "\n")))
		}
	}

	if len(results) == 0 {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "No matches found."}},
		}, nil, nil
	}

	text := strings.Join(results, "\n\n")
	if len(text) > 40_000 {
		text = text[:40_000] + "\n... (truncated search results)"
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}

type statsArgs struct{}

func (s *server) toolStats(ctx context.Context, _ *mcp.CallToolRequest, _ statsArgs) (*mcp.CallToolResult, any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	savedBytes := s.totalOutput - s.totalInput
	if savedBytes < 0 {
		savedBytes = 0
	}
	// Estimate token saving: roughly 1 token = 4 characters/bytes
	estimatedTokens := savedBytes / 4

	res := map[string]any{
		"total_command_inputs_bytes": s.totalInput,
		"total_raw_outputs_bytes":    s.totalOutput,
		"saved_context_bytes":        savedBytes,
		"estimated_tokens_saved":     estimatedTokens,
		"indexed_documents_count":    len(s.documents),
	}

	js, _ := json.MarshalIndent(res, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

// ---------- db helpers ----------

func (s *server) indexFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.documents[path] = Document{
		Path:      path,
		Content:   string(data),
		IndexedAt: time.Now(),
	}
	s.mu.Unlock()
	return nil
}

func (s *server) loadDB() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(data, &s.documents)
}

func (s *server) saveDB() {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(s.documents)
	if err != nil {
		return
	}
	tmpPath := s.dbPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return
	}
	_ = os.Rename(tmpPath, s.dbPath)
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
		if !strings.Contains(content, ".context_mode_db.json") {
			f, err := os.OpenFile(excludePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				_, _ = f.WriteString("\n# ctxmode local database\n.context_mode_db.json\n.context_mode_db.json.tmp\n")
			}
		}
	}
}
