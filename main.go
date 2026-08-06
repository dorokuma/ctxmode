// ctxmode: a Go MCP server that virtualizes tool output to save context tokens.
// v2.0 MCP surface (category tools + action=):
//
//	ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg
//
// Internal handlers retain the former ctx_* names; they are not registered as MCP tools.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

// Version is the single source of truth for MCP, doctor, and User-Agent.
// Keep aligned with CHANGELOG.md latest release.
const Version = "2.1.0"

// toolIndex walk / size limits.
const (
	maxIndexFiles      = 5000
	maxIndexDepth      = 32
	maxIndexTotalBytes = 100 * 1024 * 1024 // 100 MB total content
	maxIndexFileBytes  = 1 * 1024 * 1024   // 1 MB per file
	binarySampleSize   = 8192
)

type server struct {
	workdirs       []string
	policy         *ShellPolicy
	mu             sync.Mutex
	store          *Store
	floodGuard     *FloodGuard
	searchPipeline *SearchPipeline
	httpClient     *http.Client
	totalInput     int64
	totalOutput    int64
}

func fatal(s *Store, format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	if s != nil {
		s.Close()
	}
	os.Exit(1)
}

func main() {
	var workdir string
	var configPath string
	flag.StringVar(&workdir, "workdir", "", "workspace root (default: cwd)")
	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.Parse()

	// Load workdirs + policy from config file (or fall back to cwd / default denylist).
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	workdirs := cfg.Workdirs

	// If -workdir flag was given, prepend it (backward compatibility).
	if workdir != "" {
		absWd, err := filepath.Abs(workdir)
		if err != nil {
			fatal(nil, "bad workdir: %v", err)
		}
		hasWd := false
		for _, wd := range workdirs {
			if wd == absWd {
				hasWd = true
				break
			}
		}
		if !hasWd {
			workdirs = append([]string{absWd}, workdirs...)
		}
	}

	// Deduplicate and absolutize all workdirs.
	seen := make(map[string]bool)
	var unique []string
	for _, wd := range workdirs {
		absWd, err := filepath.Abs(wd)
		if err != nil {
			fatal(nil, "bad workdir %q: %v", wd, err)
		}
		if !seen[absWd] {
			seen[absWd] = true
			unique = append(unique, absWd)
		}
	}
	workdirs = unique

	if len(workdirs) == 0 {
		fatal(nil, "no workspace directories configured")
	}

	// Rebuild policy with final absolute workdirs.
	policy, err := NewShellPolicy(cfg.ShellPolicy, workdirs)
	if err != nil {
		log.Fatalf("failed to build shell policy: %v", err)
	}

	store, err := NewStore(filepath.Join(workdirs[0], "context_mode.db"))
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	floodGuard := NewFloodGuard(60*time.Second, 64)
	searchPipeline := NewSearchPipeline(store, floodGuard)

	s := &server{
		workdirs:       workdirs,
		policy:         policy,
		store:          store,
		floodGuard:     floodGuard,
		searchPipeline: searchPipeline,
		httpClient:     newHTTPClient(),
	}
	if err := s.migrateFromJSON(); err != nil {
		fatal(store, "failed to migrate database: %v", err)
	}
	s.excludeFromGit()

	srv := mcp.NewServer(&mcp.Implementation{Name: "ctxmode", Version: Version}, &mcp.ServerOptions{Instructions: serverInstructions})
	s.registerCategoryTools(srv)

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fatal(store, "server exited: %v", err)
	}
}

// ---------- configuration ----------

// appConfig is the fully loaded runtime configuration.
type appConfig struct {
	Workdirs    []string
	ShellPolicy ShellPolicyConfig
}

// loadConfig reads workdirs and optional policy from a YAML config file.
// Priority: -config flag > $CTXMODE_CONFIG env > ./ctxmode-config.yaml > ~/.config/ctxmode/config.yaml.
// If no config file is found, falls back to a single workdir from cwd (backward compatible).
// Policy defaults to mode=denylist (built-in high-risk commands/patterns).
// Explicit mode=off|allowlist and CTXMODE_POLICY_MODE override apply in NewShellPolicy.
func loadConfig(configFlag string) (*appConfig, error) {
	var configPath string
	switch {
	case configFlag != "":
		configPath = configFlag
	case os.Getenv("CTXMODE_CONFIG") != "":
		configPath = os.Getenv("CTXMODE_CONFIG")
	default:
		if _, err := os.Stat("ctxmode-config.yaml"); err == nil {
			configPath = "ctxmode-config.yaml"
		} else if home, err := os.UserHomeDir(); err == nil {
			candidate := filepath.Join(home, ".config", "ctxmode", "config.yaml")
			if _, err := os.Stat(candidate); err == nil {
				configPath = candidate
			}
		}
	}

	out := &appConfig{}
	if configPath == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("cannot get cwd: %w", err)
		}
		out.Workdirs = []string{wd}
		return out, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", configPath, err)
	}

	var cfg struct {
		Workdirs []string `yaml:"workdirs"`
		Policy   struct {
			Shell ShellPolicyConfig `yaml:"shell"`
		} `yaml:"policy"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", configPath, err)
	}

	out.ShellPolicy = cfg.Policy.Shell

	if len(cfg.Workdirs) == 0 {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("no workdirs in config and cannot get cwd: %w", err)
		}
		out.Workdirs = []string{wd}
		return out, nil
	}

	out.Workdirs = cfg.Workdirs
	return out, nil
}

// ---------- tool implementations ----------

type executeArgs struct {
	Command    string            `json:"command,omitempty" jsonschema:"Command or code to execute (ignored when argv is non-empty)"`
	Language   string            `json:"language,omitempty" jsonschema:"Runtime language (javascript/python/shell/go/...). Ignored in argv mode"`
	Timeout    int               `json:"timeout,omitempty" jsonschema:"Max execution time in ms"`
	Background bool              `json:"background,omitempty" jsonschema:"Keep running after timeout (for servers/daemons)"`
	Intent     string            `json:"intent,omitempty" jsonschema:"What you're looking for in the output (for auto-indexing)"`
	CWD        string            `json:"cwd,omitempty" jsonschema:"Working directory"`
	Argv       []string          `json:"argv,omitempty" jsonschema:"If non-empty, exec directly without shell (preferred over command). argv[0]=executable"`
	Env        map[string]string `json:"env,omitempty" jsonschema:"Extra env vars (allowlist only; never PATH/HOME/LD_*). Merged onto process env"`
	Stdin      string            `json:"stdin,omitempty" jsonschema:"Stdin payload written to the process then closed (max 1MB)"`
}

func (s *server) toolExecute(ctx context.Context, _ *mcp.CallToolRequest, args executeArgs) (*mcp.CallToolResult, any, error) {
	useArgv := len(args.Argv) > 0
	if !useArgv && args.Command == "" {
		return nil, nil, fmt.Errorf("command is required (or provide non-empty argv)")
	}

	// Default language is shell (backward compatible). In argv mode language is ignored.
	language := args.Language
	if language == "" {
		language = "shell"
	}

	// Parse timeout (capped at 1 hour).
	var timeout time.Duration
	if args.Timeout > 0 {
		if args.Timeout > 3600000 {
			return nil, nil, fmt.Errorf("timeout %dms exceeds maximum allowed (1 hour)", args.Timeout)
		}
		timeout = time.Duration(args.Timeout) * time.Millisecond
	}

	// Resolve working directory.
	cwd := s.workdirs[0]
	if args.CWD != "" {
		resolved, err := s.resolvePath(args.CWD)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cwd: %w", err)
		}
		cwd = resolved
	}

	// Validate env allowlist and stdin size.
	filteredEnv, err := filterExecEnv(args.Env)
	if err != nil {
		return nil, nil, err
	}
	if len(args.Stdin) > maxStdinBytes {
		return nil, nil, fmt.Errorf("stdin exceeds maximum size (%d bytes, max %d)", len(args.Stdin), maxStdinBytes)
	}
	var opts *runOptions
	if len(filteredEnv) > 0 || args.Stdin != "" {
		opts = &runOptions{Env: filteredEnv, Stdin: args.Stdin}
	}

	// Execute: argv mode (no shell) takes priority over command string.
	var result *executeResult
	if useArgv {
		argv, aerr := s.validateArgv(args.Argv, cwd)
		if aerr != nil {
			return nil, nil, aerr
		}
		if err := s.checkArgvPolicy(argv, cwd); err != nil {
			return nil, nil, err
		}
		result, err = runArgv(ctx, argv, cwd, timeout, args.Background, opts)
	} else {
		// Shell policy applies to language=shell (default) command strings.
		if language == "shell" {
			if err := s.checkShellPolicy(args.Command, cwd); err != nil {
				return nil, nil, err
			}
		}
		result, err = runCodeOpts(ctx, language, args.Command, cwd, timeout, args.Background, opts)
	}
	if err != nil {
		return nil, nil, err
	}

	// Track stats.
	inputLen := len(args.Command)
	if useArgv {
		inputLen = 0
		for _, a := range args.Argv {
			inputLen += len(a) + 1
		}
	}
	inputLen += len(args.Stdin)
	s.mu.Lock()
	s.totalInput += int64(inputLen)
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
	if result.Truncated {
		if outputText != "" {
			outputText += "\n"
		}
		outputText += "[WARNING: output truncated at 10MB — indexed content may be incomplete]"
	}

	// Auto-indexing logic.
	const (
		autoIndexThreshold = 100 * 1024 // 100KB
		intentThreshold    = 5 * 1024   // 5KB
	)

	if len(outputText) > autoIndexThreshold {
		// Unconditionally index large outputs.
		label := fmt.Sprintf("execute:%d", time.Now().UnixNano())
		if args.Intent != "" {
			label = "execute:" + args.Intent
		}
		if err := s.storeIndexLocked(label, outputText); err != nil {
			// Index failed: still return a truncated preview so the agent is not blind.
			preview := outputText
			if len(preview) > 2000 {
				preview = truncateUTF8(preview, 2000) + "\n... (truncated)"
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf("Output is too large (%d bytes). Indexing failed: %v. Content was NOT indexed.\n\n--- Preview ---\n%s",
						len(outputText), err, preview),
				}},
			}, nil, nil
		}
		result.Indexed = true
		result.IndexLabel = label
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{
				Text: fmt.Sprintf("Output is too large (%d bytes). Indexed as %q. Use ctx_search(queries: [%q]) to search the indexed content.",
					len(outputText), label, label),
			}},
		}, nil, nil
	}

	if len(outputText) > intentThreshold && args.Intent != "" {
		// Index and return a preview.
		label := "execute:" + args.Intent
		if err := s.storeIndexLocked(label, outputText); err != nil {
			preview := outputText
			if len(preview) > 2000 {
				preview = truncateUTF8(preview, 2000) + "\n... (truncated)"
			}
			summary := fmt.Sprintf("Output (%d bytes) was NOT indexed (error: %v).\n\n--- Preview ---\n%s",
				len(outputText), err, preview)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: summary}},
			}, nil, nil
		}
		result.Indexed = true
		result.IndexLabel = label

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
	var skipSamples []string // sample skip reasons (capped)
	var totalBytes int64
	hitFileCap := false
	hitByteCap := false

	addSkip := func(reason string) {
		skippedCount++
		if len(skipSamples) < 5 {
			skipSamples = append(skipSamples, reason)
		}
	}

	if info.IsDir() {
		baseDepth := strings.Count(target, string(filepath.Separator))
		err = filepath.Walk(target, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				addSkip(fmt.Sprintf("%s: walk error: %v", path, walkErr))
				return nil
			}
			// Depth limit (directories and files).
			depth := strings.Count(path, string(filepath.Separator)) - baseDepth
			if depth > maxIndexDepth {
				if fi.IsDir() {
					return filepath.SkipDir
				}
				addSkip(fmt.Sprintf("%s: max depth %d", path, maxIndexDepth))
				return nil
			}
			if fi.IsDir() {
				base := filepath.Base(path)
				if base == ".git" || base == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if hitFileCap || hitByteCap {
				return filepath.SkipDir
			}
			if indexedCount >= maxIndexFiles {
				hitFileCap = true
				return filepath.SkipDir
			}
			if strings.Contains(path, "/.git/") || strings.Contains(path, "/node_modules/") {
				addSkip(fmt.Sprintf("%s: excluded dir", path))
				return nil
			}
			// Symlink fence: refuse paths that resolve outside workspaces.
			if real, rerr := s.ensureInsideWorkspaces(path); rerr != nil {
				addSkip(fmt.Sprintf("%s: outside workspace (%v)", path, rerr))
				return nil
			} else {
				path = real
			}
			if fi.Size() > maxIndexFileBytes {
				addSkip(fmt.Sprintf("%s: too large (%d bytes)", path, fi.Size()))
				return nil
			}
			if isProbablyBinaryName(fi.Name()) {
				addSkip(fmt.Sprintf("%s: binary extension", path))
				return nil
			}
			if totalBytes+fi.Size() > maxIndexTotalBytes {
				hitByteCap = true
				addSkip(fmt.Sprintf("%s: total size cap reached", path))
				return filepath.SkipDir
			}
			if err := s.indexFile(path); err != nil {
				addSkip(fmt.Sprintf("%s: %v", path, err))
				return nil
			}
			indexedCount++
			totalBytes += fi.Size()
			return nil
		})
	} else {
		if isProbablyBinaryName(info.Name()) || info.Size() > maxIndexFileBytes {
			return nil, nil, fmt.Errorf("file %q is binary or too large (> 1MB)", target)
		}
		// Content-based binary check happens in indexFile.
		err = s.indexFile(target)
		if err == nil {
			indexedCount = 1
		} else {
			return nil, nil, err
		}
	}

	if err != nil {
		return nil, nil, err
	}

	msg := fmt.Sprintf("Indexed %d file(s)", indexedCount)
	if skippedCount > 0 {
		msg += fmt.Sprintf(" (%d skipped)", skippedCount)
		if len(skipSamples) > 0 {
			msg += ": " + strings.Join(skipSamples, "; ")
			if skippedCount > len(skipSamples) {
				msg += "; ..."
			}
		}
	}
	if hitFileCap {
		msg += fmt.Sprintf(" [stopped: max files %d]", maxIndexFiles)
	}
	if hitByteCap {
		msg += fmt.Sprintf(" [stopped: max total bytes %d]", maxIndexTotalBytes)
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
	q := strings.TrimSpace(args.Query)
	if q == "" {
		return nil, nil, fmt.Errorf("query is required")
	}

	results, meta, err := s.searchPipeline.Search(q, 20)
	if err != nil {
		// If blocked by flood guard, return a friendly message.
		if meta != nil && meta.FloodStatus == "blocked" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "Search blocked: too many requests in a short time. Wait a moment, or use ctx_run action=batch (query_scope=batch searches bypass the flood guard)."}},
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
		rel := ""
		for _, wd := range s.workdirs {
			if rp, err := filepath.Rel(wd, r.Path); err == nil && !strings.HasPrefix(rp, "..") {
				rel = rp
				break
			}
		}
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
	SearchCallsWindow  int   `json:"search_calls_60s,omitempty" jsonschema:"number of OK search calls in the 60s sliding window (counts only allowed calls, not throttled or blocked)"`
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
	if isProbablyBinaryName(info.Name()) {
		return nil, nil, fmt.Errorf("file %q appears to be binary, refusing to read as code input", target)
	}

	// Read file content.
	fileContent, err := os.ReadFile(target)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}
	if isBinaryContent(fileContent) {
		return nil, nil, fmt.Errorf("file %q appears to be binary (content sample), refusing to read as code input", target)
	}

	// Default language.
	language := args.Language
	if language == "" {
		language = "javascript"
	}

	// Parse timeout (capped at 1 hour).
	var timeout time.Duration
	if args.Timeout > 0 {
		if args.Timeout > 3600000 {
			return nil, nil, fmt.Errorf("timeout %dms exceeds maximum allowed (1 hour)", args.Timeout)
		}
		timeout = time.Duration(args.Timeout) * time.Millisecond
	}

	// Resolve working directory.
	cwd := s.workdirs[0]
	if args.CWD != "" {
		resolved, err := s.resolvePath(args.CWD)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cwd: %w", err)
		}
		cwd = resolved
	}

	// Shell policy on user code only (not the FILE_CONTENT injection wrapper).
	if language == "shell" {
		if err := s.checkShellPolicy(args.Code, cwd); err != nil {
			return nil, nil, err
		}
	}

	// Inject FILE_CONTENT into user code.
	injectedCode := injectFileContent(language, args.Code, string(fileContent))

	// Execute the injected code.
	result, err := runCode(ctx, language, injectedCode, cwd, timeout, false)
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
	if result.Truncated {
		if outputText != "" {
			outputText += "\n"
		}
		outputText += "[WARNING: output truncated at 10MB — indexed content may be incomplete]"
	}

	// Auto-indexing logic (same as toolExecute).
	const (
		autoIndexThreshold = 100 * 1024 // 100KB
		intentThreshold    = 5 * 1024   // 5KB
	)

	if len(outputText) > autoIndexThreshold {
		label := "execute_file:" + filepath.Base(target)
		if args.Intent != "" {
			label = "execute_file:" + args.Intent
		}
		if err := s.storeIndexLocked(label, outputText); err != nil {
			// Index failed: still return a truncated preview so the agent is not blind.
			preview := outputText
			if len(preview) > 2000 {
				preview = truncateUTF8(preview, 2000) + "\n... (truncated)"
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf("Output is too large (%d bytes). Indexing failed: %v. Content was NOT indexed.\n\n--- Preview ---\n%s",
						len(outputText), err, preview),
				}},
			}, nil, nil
		}
		result.Indexed = true
		result.IndexLabel = label
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{
				Text: fmt.Sprintf("Output is too large (%d bytes). Indexed as %q. Use ctx_search to search.",
					len(outputText), label),
			}},
		}, nil, nil
	}

	if len(outputText) > intentThreshold && args.Intent != "" {
		label := "execute_file:" + args.Intent
		if err := s.storeIndexLocked(label, outputText); err != nil {
			preview := outputText
			if len(preview) > 2000 {
				preview = truncateUTF8(preview, 2000) + "\n... (truncated)"
			}
			summary := fmt.Sprintf("Output (%d bytes) was NOT indexed (error: %v).\n\n--- Preview ---\n%s",
				len(outputText), err, preview)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: summary}},
			}, nil, nil
		}
		result.Indexed = true
		result.IndexLabel = label

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
	// Re-check symlink fence at read time (Walk may encounter links).
	real, err := s.ensureInsideWorkspaces(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(real)
	if err != nil {
		return err
	}
	if isBinaryContent(data) {
		return fmt.Errorf("binary content detected")
	}
	return s.storeIndexLocked(real, string(data))
}

func (s *server) migrateFromJSON() error {
	oldPath := filepath.Join(s.workdirs[0], ".context_mode_db.json")

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
// Fast path: if the full string is valid UTF-8, the only possible issue is at the
// truncation boundary — use DecodeLastRuneInString (O(1) per step) to back up.
// Slow path: if the full string has mid-string invalid bytes, scan forward to find
// the longest valid UTF-8 prefix (single pass, O(n)).
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	truncated := s[:maxBytes]

	// Fast path: full string is valid UTF-8, only truncation boundary matters.
	if utf8.ValidString(s) {
		for len(truncated) > 0 {
			r, size := utf8.DecodeLastRuneInString(truncated)
			if r != utf8.RuneError || size == 0 {
				break
			}
			truncated = truncated[:len(truncated)-1]
		}
		return truncated
	}

	// Slow path: original has mid-string invalid bytes.
	// Single forward pass to find the longest valid UTF-8 prefix.
	for i := 0; i < len(truncated); {
		r, size := utf8.DecodeRuneInString(truncated[i:])
		if r == utf8.RuneError && size <= 1 {
			return truncated[:i]
		}
		i += size
	}
	return truncated
}

// isProbablyBinaryName returns true if the filename extension indicates a binary file.
func isProbablyBinaryName(name string) bool {
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

// isProbablyBinary is kept as an alias for extension-only checks used by older call sites.
func isProbablyBinary(name string) bool {
	return isProbablyBinaryName(name)
}

// isBinaryContent samples the first bytes and detects binary data via null
// bytes or a high proportion of non-text control characters.
func isBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > binarySampleSize {
		sample = sample[:binarySampleSize]
	}
	// Null byte is a strong binary signal.
	for _, b := range sample {
		if b == 0 {
			return true
		}
	}
	// Count non-text bytes (excluding common whitespace control chars).
	nonText := 0
	for _, b := range sample {
		if b < 0x09 || (b > 0x0d && b < 0x20) {
			// Allow tab(9), LF(10), VT(11), FF(12), CR(13); treat other controls as non-text.
			nonText++
		}
	}
	// If more than 30% of the sample is non-text control bytes, treat as binary.
	if len(sample) > 0 && nonText*100/len(sample) > 30 {
		return true
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

// checkShellPolicy applies the configured shell command policy (no-op when mode=off).
func (s *server) checkShellPolicy(command, cwd string) error {
	if s == nil || s.policy == nil {
		return nil
	}
	return s.policy.CheckShell(command, cwd)
}

// checkArgvPolicy applies allowlist/denylist to direct-exec argv (with cwd for rm paths).
func (s *server) checkArgvPolicy(argv []string, cwd string) error {
	if s == nil || s.policy == nil {
		return nil
	}
	return s.policy.CheckArgv(argv, cwd)
}

// validateArgv checks argv for ctx_execute argv mode.
// argv[0] must be a simple executable name (no path separators) or a path
// resolved inside a workdir. Empty argv / empty argv[0] are rejected.
func (s *server) validateArgv(argv []string, cwd string) ([]string, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("argv must not be empty")
	}
	exe := argv[0]
	if exe == "" {
		return nil, fmt.Errorf("argv[0] must not be empty")
	}
	// Absolute or relative path -> must stay inside workspaces.
	if strings.Contains(exe, "/") || strings.Contains(exe, string(filepath.Separator)) ||
		strings.Contains(exe, `\`) || exe == "." || exe == ".." || strings.HasPrefix(exe, ".") {
		target := exe
		if !filepath.IsAbs(target) {
			if cwd == "" {
				cwd = s.workdirs[0]
			}
			target = filepath.Join(cwd, target)
		}
		target = filepath.Clean(target)
		if !s.lexicallyInside(target) {
			return nil, fmt.Errorf("argv[0] path %q is outside all workspaces", exe)
		}
		resolved, err := s.ensureInsideWorkspaces(target)
		if err != nil {
			return nil, fmt.Errorf("argv[0] path invalid: %w", err)
		}
		out := make([]string, len(argv))
		copy(out, argv)
		out[0] = resolved
		return out, nil
	}
	// Simple name: no path traversal.
	if strings.Contains(exe, "..") {
		return nil, fmt.Errorf("argv[0] %q is invalid", exe)
	}
	return argv, nil
}

// resolvePath converts a user-supplied path into an absolute path within any workspace.
// After Clean, it resolves symlinks (EvalSymlinks) and re-checks that the real
// path still lies inside a configured workdir. Symlinks that escape are rejected.
func (s *server) resolvePath(p string) (string, error) {
	if p == "" {
		return s.workdirs[0], nil
	}
	var target string
	if filepath.IsAbs(p) {
		target = filepath.Clean(p)
	} else {
		target = filepath.Clean(filepath.Join(s.workdirs[0], p))
	}
	// First-pass lexical containment (fast reject before syscall).
	if !s.lexicallyInside(target) {
		return "", fmt.Errorf("path %q is outside all workspaces %q", p, s.workdirs)
	}
	return s.ensureInsideWorkspaces(target)
}

// lexicallyInside reports whether path is under any workdir before symlink resolution.
func (s *server) lexicallyInside(target string) bool {
	for _, wd := range s.workdirs {
		cleanWd := strings.TrimSuffix(wd, string(filepath.Separator))
		if target == wd || target == cleanWd || strings.HasPrefix(target, cleanWd+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ensureInsideWorkspaces resolves symlinks on path (or its longest existing
// prefix) and verifies the real path remains inside a configured workdir.
func (s *server) ensureInsideWorkspaces(path string) (string, error) {
	resolved, err := evalSymlinksPartial(path)
	if err != nil {
		return "", fmt.Errorf("resolve symlinks for %q: %w", path, err)
	}
	for _, wd := range s.workdirs {
		realWd := wd
		if rw, err := filepath.EvalSymlinks(wd); err == nil {
			realWd = rw
		}
		cleanWd := strings.TrimSuffix(realWd, string(filepath.Separator))
		if resolved == realWd || resolved == cleanWd || strings.HasPrefix(resolved, cleanWd+string(filepath.Separator)) {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("path %q resolves to %q which is outside all workspaces", path, resolved)
}

// evalSymlinksPartial is like filepath.EvalSymlinks but works when the final
// path component does not yet exist: it resolves the longest existing prefix
// and re-appends the missing trailing components.
func evalSymlinksPartial(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path")
	}
	// Fast path: whole path exists.
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real, nil
	}
	// Walk up until an existing prefix is found.
	missing := []string{}
	cur := path
	for {
		if cur == "" || cur == string(filepath.Separator) {
			break
		}
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			// Rejoin missing components.
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return filepath.Clean(real), nil
		}
		dir, base := filepath.Dir(cur), filepath.Base(cur)
		if dir == cur {
			break
		}
		missing = append(missing, base)
		cur = dir
	}
	// Fall back to Clean if nothing is resolvable (e.g. brand-new absolute path).
	return filepath.Clean(path), nil
}

// excludeFromGit appends the local database files to .git/info/exclude for all workspaces.
func (s *server) excludeFromGit() {
	for _, wd := range s.workdirs {
		s.excludeFromGitOne(wd)
	}
}

// excludeFromGitOne handles a single workspace's git exclusion.
func (s *server) excludeFromGitOne(wd string) {
	gitDir := filepath.Join(wd, ".git")
	info, err := os.Lstat(gitDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	excludePath := filepath.Join(gitDir, "info", "exclude")
	if _, err := s.ensureInsideWorkspaces(excludePath); err != nil {
		log.Printf("excludeFromGit: unsafe path %s: %v", excludePath, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(excludePath), 0755); err != nil {
		log.Printf("excludeFromGit: MkdirAll %s: %v", filepath.Dir(excludePath), err)
		return
	}
	if li, err := os.Lstat(excludePath); err == nil && li.Mode()&os.ModeSymlink != 0 {
		log.Printf("excludeFromGit: refusing symlink %s", excludePath)
		return
	}
	resolvedExclude, err := s.ensureInsideWorkspaces(excludePath)
	if err != nil {
		log.Printf("excludeFromGit: unsafe path %s: %v", excludePath, err)
		return
	}
	data, err := os.ReadFile(resolvedExclude)
	if err != nil && !os.IsNotExist(err) {
		log.Printf("excludeFromGit: ReadFile %s: %v", resolvedExclude, err)
	}
	content := ""
	if err == nil {
		content = string(data)
	}
	if strings.Contains(content, "context_mode.db") {
		return
	}
	f, err := os.OpenFile(resolvedExclude, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("excludeFromGit: OpenFile %s: %v", resolvedExclude, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString("\n# ctxmode local database\ncontext_mode.db\ncontext_mode.db-wal\ncontext_mode.db-shm\n"); err != nil {
		log.Printf("excludeFromGit: WriteString %s: %v", resolvedExclude, err)
		return
	}
	if err := f.Sync(); err != nil {
		log.Printf("excludeFromGit: Sync %s: %v", resolvedExclude, err)
	}
}
