package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- data types ----------

type batchCommand struct {
	Label   string `json:"label"`
	Command string `json:"command"`
}

type batchArgs struct {
	Commands    []batchCommand `json:"commands" jsonschema:"Array of {label, command} objects"`
	Queries     []string       `json:"queries,omitempty" jsonschema:"Search queries over indexed output (max 20)"`
	Concurrency int            `json:"concurrency,omitempty" jsonschema:"Max parallel commands (1-8, default 1)"`
	CWD         string         `json:"cwd,omitempty" jsonschema:"Working directory"`
	Timeout     int            `json:"timeout,omitempty" jsonschema:"Max execution time in ms (serial: total budget; concurrent: per-command budget)"`
	QueryScope  string         `json:"query_scope,omitempty" jsonschema:"Search scope (batch or global, default batch)"`
}

type batchResult struct {
	Label      string `json:"label"`
	Command    string `json:"command"`
	Success    bool   `json:"success"`
	ExitCode   int    `json:"exit_code"`
	Truncated  bool   `json:"truncated,omitempty"`
	Indexed    bool   `json:"indexed,omitempty"`
	IndexLabel string `json:"index_label,omitempty"` // actual unique store label
	Size       int    `json:"size"`
	Error      string `json:"error,omitempty"`
	IndexError string `json:"index_error,omitempty"`
}

type batchResponse struct {
	Commands      []batchResult          `json:"commands"`
	Indexed       int                    `json:"indexed"`
	IndexFailures int                    `json:"index_failures,omitempty"`
	Truncated     bool                   `json:"truncated"`
	Search        map[string][]searchHit `json:"search,omitempty"`
}

type searchHit struct {
	Path    string `json:"path"`
	Snippet string `json:"snippet"`
}

const (
	batchIndexPrefix = "batch:"
	maxOutputSize    = 100 * 1024 // 100KB
)

// ---------- command execution ----------

// executeCommand runs a shell command with the given context and working directory.
// It captures stdout and stderr separately, then merges them.
// Returns merged output, exit code, and any execution error. The fourth return
// value reports whether the captured output was actually cut at the buffer limit
// (maxCmdOutput) — it is the ONLY source of the batch Truncated flag; the 100KB
// auto-index threshold is unrelated to real truncation.
func (s *server) executeCommand(ctx context.Context, command, cwd string) (output string, exitCode int, execErr error, truncated bool) {
	var cmd *exec.Cmd
	shellPath := os.Getenv("SHELL")
	if shellPath != "" {
		parts := strings.Fields(shellPath)
		if len(parts) == 0 {
			cmd = exec.Command("sh", "-c", command)
		} else {
			args := append(parts[1:], "-c", command)
			cmd = exec.Command(parts[0], args...)
		}
	} else {
		cmd = exec.Command("sh", "-c", command)
	}
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var stdoutBuf, stderrBuf limitedBuffer
	stdoutBuf.limit = maxCmdOutput
	stderrBuf.limit = maxCmdOutput
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	// Strip sensitive inherited variables (same default as the execute path;
	// see childEnv). batch runs caller-controlled shell commands and stores
	// their output in the KB, so the child env must not leak secrets.
	cmd.Env = flattenEnv(childEnv(nil))

	// Start the command.
	if err := cmd.Start(); err != nil {
		return "", -1, fmt.Errorf("failed to start command: %w", err), false
	}

	// Wait for completion or context cancellation.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		// Context was cancelled (timeout or parent cancellation).
		// Two-stage kill: SIGTERM first for graceful shutdown, then SIGKILL after 3s.
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
			// Process exited gracefully after SIGTERM.
		case <-time.After(3 * time.Second):
			// Force-kill and drain to release pipe resources.
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return stdoutBuf.String() + stderrBuf.String(), -1, fmt.Errorf("command cancelled: %w", ctx.Err()), stdoutBuf.truncated || stderrBuf.truncated

	case err := <-done:
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()

		if err != nil {
			// The process exited with a non-zero status or was killed.
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
			// Merge output even on failure.
			output = stdout
			if stderr != "" {
				if output != "" {
					output += "\n"
				}
				output += stderr
			}
			return output, exitCode, nil, stdoutBuf.truncated || stderrBuf.truncated
		}

		// Success.
		output = stdout
		if stderr != "" {
			if output != "" {
				output += "\n"
			}
			output += stderr
		}
		return output, cmd.ProcessState.ExitCode(), nil, stdoutBuf.truncated || stderrBuf.truncated
	}
}

// ---------- MCP tool handler ----------

func (s *server) toolBatchExecute(ctx context.Context, _ *mcp.CallToolRequest, args batchArgs) (*mcp.CallToolResult, any, error) {
	// Validate commands.
	if len(args.Commands) == 0 {
		return nil, nil, fmt.Errorf("commands is required")
	}
	if len(args.Commands) > 50 {
		return nil, nil, fmt.Errorf("too many commands: %d (max 50)", len(args.Commands))
	}

	// Check for duplicate labels (Index uses label as key).
	seen := make(map[string]bool, len(args.Commands))
	for _, cmd := range args.Commands {
		if strings.TrimSpace(cmd.Label) == "" {
			return nil, nil, fmt.Errorf("command label must not be empty")
		}
		if seen[cmd.Label] {
			return nil, nil, fmt.Errorf("duplicate command label: %q", cmd.Label)
		}
		seen[cmd.Label] = true
	}

	// Validate concurrency (1-8, default 1). Invalid values are errors, not silent clamps.
	concurrency := args.Concurrency
	if concurrency < 0 {
		return nil, nil, fmt.Errorf("invalid concurrency %d (valid range: 1-8, default 1)", concurrency)
	}
	if concurrency == 0 {
		concurrency = 1 // default (unset)
	}
	if concurrency > 8 {
		return nil, nil, fmt.Errorf("concurrency %d exceeds maximum 8 (valid range: 1-8, default 1)", concurrency)
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

	// Validate query_scope (batch or global, default batch). Invalid values are errors.
	queryScope := strings.ToLower(args.QueryScope)
	if queryScope == "" {
		queryScope = "batch" // default (unset)
	} else if queryScope != "batch" && queryScope != "global" {
		return nil, nil, fmt.Errorf("invalid query_scope %q (valid values: batch, global; default batch)", args.QueryScope)
	}

	// Validate queries max (fast-fail before executing commands).
	if len(args.Queries) > 20 {
		return nil, nil, fmt.Errorf("too many queries: %d (max 20)", len(args.Queries))
	}

	// Parse timeout (capped at 1 hour).
	var timeout time.Duration
	if args.Timeout > 0 {
		if args.Timeout > 3600000 {
			return nil, nil, fmt.Errorf("timeout %dms exceeds maximum allowed (1 hour)", args.Timeout)
		}
		timeout = time.Duration(args.Timeout) * time.Millisecond
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// Pre-allocate results slice.
	results := make([]batchResult, len(args.Commands))

	// ---------- execute commands ----------

	if concurrency == 1 {
		// Serial execution with a shared timeout.
		s.executeBatchSerial(ctx, args.Commands, cwd, timeout, results)
	} else {
		// Concurrent execution with per-command timeouts.
		s.executeBatchConcurrent(ctx, args.Commands, cwd, timeout, concurrency, results)
	}

	// Count indexed commands, failures, and check for truncation.
	totalIndexed := 0
	indexFailures := 0
	anyTruncated := false
	for _, r := range results {
		if r.Indexed {
			totalIndexed++
		}
		if r.IndexError != "" {
			indexFailures++
		}
		if r.Truncated {
			anyTruncated = true
		}
	}

	// ---------- handle queries ----------

	var searchResults map[string][]searchHit
	var searchErrors []string
	if len(args.Queries) > 0 {
		searchResults = make(map[string][]searchHit)
		for _, q := range args.Queries {
			q = strings.TrimSpace(q)
			if q == "" {
				continue
			}

			if queryScope == "batch" {
				// Path-scoped at store layer (no post-filter false negatives).
				// Bypasses flood guard so batch is a reliable escape hatch.
				hits, meta, err := s.searchPipeline.SearchBatchScoped(q, 5)
				if err != nil {
					msg := err.Error()
					if meta != nil && meta.FloodStatus == "blocked" {
						msg = "search blocked by flood guard (unexpected for batch scope): " + msg
					}
					searchErrors = append(searchErrors, fmt.Sprintf("%q: %s", q, msg))
					continue
				}
				for _, h := range hits {
					searchResults[q] = append(searchResults[q], searchHit{Path: h.Path, Snippet: h.Snippet})
				}
			} else {
				// Global scope: search the entire store (subject to flood guard).
				hits, meta, err := s.searchPipeline.Search(q, 5)
				if err != nil {
					msg := err.Error()
					if meta != nil && meta.FloodStatus == "blocked" {
						msg = "search blocked: too many requests; retry later or use query_scope=batch"
					}
					searchErrors = append(searchErrors, fmt.Sprintf("%q: %s", q, msg))
					continue
				}
				for _, h := range hits {
					searchResults[q] = append(searchResults[q], searchHit{Path: h.Path, Snippet: h.Snippet})
				}
			}
		}
	}

	// ---------- build response ----------

	resp := batchResponse{
		Commands:      results,
		Indexed:       totalIndexed,
		IndexFailures: indexFailures,
		Truncated:     anyTruncated,
		Search:        searchResults,
	}

	js, _ := json.MarshalIndent(resp, "", "  ")
	text := string(js)
	if len(searchErrors) > 0 {
		text += "\n\nSearch errors:\n- " + strings.Join(searchErrors, "\n- ")
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, nil, nil
}

// ---------- execution strategies ----------

// executeBatchSerial runs commands one by one with a shared timeout.
// The timeout is the total budget for all commands combined.
// If the shared context expires mid-way, remaining commands are marked as skipped.
func (s *server) executeBatchSerial(ctx context.Context, commands []batchCommand, cwd string, timeout time.Duration, results []batchResult) {
	var cmdCtx context.Context
	var cancel context.CancelFunc
	if timeout > 0 {
		cmdCtx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		cmdCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	for i, cmd := range commands {
		// Check if the shared context has expired.
		if err := cmdCtx.Err(); err != nil {
			results[i] = batchResult{
				Label:    cmd.Label,
				Command:  cmd.Command,
				Success:  false,
				ExitCode: -1,
				Error:    fmt.Sprintf("skipped: shared timeout exceeded (%v)", err),
			}
			continue
		}

		out, exitCode, execErr, truncated := s.executeCommand(cmdCtx, cmd.Command, cwd)

		r := batchResult{
			Label:     cmd.Label,
			Command:   cmd.Command,
			ExitCode:  exitCode,
			Size:      len(out),
			Truncated: truncated,
		}

		if execErr != nil {
			r.Success = false
			r.Error = execErr.Error()
		} else {
			r.Success = exitCode == 0
		}

		// Auto-index only large output (same 100KB threshold as the execute path);
		// small output is not persisted. Each index gets a unique label so a
		// repeated command label cannot silently overwrite an earlier document
		// (INSERT OR REPLACE); the actual label is returned in the response.
		if len(out) > maxOutputSize {
			label := uniqueIndexLabel("batch", cmd.Label)
			s.mu.Lock()
			if err := s.store.Index(label, out); err != nil {
				r.IndexError = err.Error()
			} else {
				r.Indexed = true
				r.IndexLabel = label
			}
			s.mu.Unlock()
		}

		results[i] = r
	}
}

// executeBatchConcurrent runs commands in parallel with per-command timeouts.
// Each command gets its own timeout budget (the full timeout value).
// Concurrency is limited by a semaphore. Store writes are serialized with a mutex.
func (s *server) executeBatchConcurrent(ctx context.Context, commands []batchCommand, cwd string, timeout time.Duration, concurrency int, results []batchResult) {
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, cmd := range commands {
		wg.Add(1)
		go func(idx int, c batchCommand) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			// Per-command context with its own timeout.
			var cmdCtx context.Context
			var cmdCancel context.CancelFunc
			if timeout > 0 {
				cmdCtx, cmdCancel = context.WithTimeout(ctx, timeout)
			} else {
				cmdCtx, cmdCancel = context.WithCancel(ctx)
			}
			defer cmdCancel()

			out, exitCode, execErr, truncated := s.executeCommand(cmdCtx, c.Command, cwd)

			r := batchResult{
				Label:     c.Label,
				Command:   c.Command,
				ExitCode:  exitCode,
				Size:      len(out),
				Truncated: truncated,
			}

			if execErr != nil {
				r.Success = false
				r.Error = execErr.Error()
			} else {
				r.Success = exitCode == 0
			}

			// Auto-index only large output (same 100KB threshold as the execute path);
			// small output is not persisted. Mutex serializes SQLite single-writer.
			// Unique label per index (see executeBatchSerial).
			if len(out) > maxOutputSize {
				label := uniqueIndexLabel("batch", c.Label)
				s.mu.Lock()
				if err := s.store.Index(label, out); err != nil {
					r.IndexError = err.Error()
				} else {
					r.Indexed = true
					r.IndexLabel = label
				}
				s.mu.Unlock()
			}

			results[idx] = r
		}(i, cmd)
	}

	wg.Wait()
}
