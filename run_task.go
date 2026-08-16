package main

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- ctx_run: run_task ----------

const (
	runTaskDefaultTimeoutMs = 300000  // 5 minutes
	runTaskMaxTimeoutMs     = 3600000 // 1 hour hard cap
	runTaskAutoIndexBytes   = 100 * 1024
	runTaskIntentIndexBytes = 5 * 1024
	runTaskPreviewBytes     = 2000
	runTaskTailBytes        = 4000
)

// makeTargetRe restricts make targets to simple identifiers (no shell injection).
var makeTargetRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// validRunTaskKinds lists supported kind values.
var validRunTaskKinds = map[string]bool{
	"go_test":       true,
	"go_build":      true,
	"go_vet":        true,
	"npm_test":      true,
	"npm_run_build": true,
	"cargo_test":    true,
	"cargo_build":   true,
	"make":          true,
	"custom":        true,
}

type runTaskArgs struct {
	Kind      string            `json:"kind" jsonschema:"Task kind: go_test|go_build|go_vet|npm_test|npm_run_build|cargo_test|cargo_build|make|custom"`
	Target    string            `json:"target,omitempty" jsonschema:"go: package path (default ./...); make: target name; custom unused"`
	Args      []string          `json:"args,omitempty" jsonschema:"Extra argv appended as independent args (no shell). custom: full argv with args[0]=executable"`
	CWD       string            `json:"cwd,omitempty" jsonschema:"Working directory (sandboxed via resolvePath)"`
	TimeoutMs int               `json:"timeout_ms,omitempty" jsonschema:"Timeout in ms (default 300000, hard max 3600000)"`
	Intent    string            `json:"intent,omitempty" jsonschema:"Label hint for large-output auto-index"`
	Env       map[string]string `json:"env,omitempty" jsonschema:"Extra env (same allowlist as ctx_run action=execute; never PATH/HOME/LD_*)"`
}

func (s *server) toolRunTask(ctx context.Context, _ *mcp.CallToolRequest, args runTaskArgs) (*mcp.CallToolResult, any, error) {
	if args.Kind == "" {
		return nil, nil, fmt.Errorf("kind is required (go_test|go_build|go_vet|npm_test|npm_run_build|cargo_test|cargo_build|make|custom)")
	}
	if !validRunTaskKinds[args.Kind] {
		return nil, nil, fmt.Errorf("unknown kind %q (supported: go_test, go_build, go_vet, npm_test, npm_run_build, cargo_test, cargo_build, make, custom)", args.Kind)
	}

	if err := validateRunTaskArgElements(args.Args); err != nil {
		return nil, nil, err
	}

	// Timeout: default 5m, hard cap 1h.
	timeoutMs := args.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = runTaskDefaultTimeoutMs
	}
	if timeoutMs > runTaskMaxTimeoutMs {
		return nil, nil, fmt.Errorf("timeout_ms %d exceeds maximum allowed (%d)", timeoutMs, runTaskMaxTimeoutMs)
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	// Resolve cwd inside sandbox.
	cwd := s.workdirs[0]
	if args.CWD != "" {
		resolved, err := s.resolvePath(args.CWD)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cwd: %w", err)
		}
		cwd = resolved
	}

	// Env allowlist (same as ctx_run action=execute / P1).
	filteredEnv, err := filterExecEnv(args.Env)
	if err != nil {
		return nil, nil, err
	}
	var opts *runOptions
	if len(filteredEnv) > 0 {
		opts = &runOptions{Env: filteredEnv}
	}

	// Map kind → fixed argv (never via sh -c).
	argv, err := buildRunTaskArgv(args.Kind, args.Target, args.Args)
	if err != nil {
		return nil, nil, err
	}

	// custom (and any path-like argv[0]) go through validateArgv.
	// Fixed kinds use simple exe names (go/npm/cargo/make) which pass as-is.
	argv, err = s.validateArgv(argv, cwd)
	if err != nil {
		return nil, nil, err
	}

	result, err := runArgv(ctx, argv, cwd, timeout, false, opts)
	if err != nil {
		return nil, nil, err
	}

	// Stats.
	inputLen := 0
	for _, a := range argv {
		inputLen += len(a) + 1
	}
	s.mu.Lock()
	s.totalInput += int64(inputLen)
	s.totalOutput += int64(len(result.Stdout) + len(result.Stderr))
	s.mu.Unlock()

	outputText := formatRunTaskOutput(args.Kind, argv, result)

	// Auto-index large / intent-tagged outputs (same thresholds as toolExecute).
	return s.finishRunTaskOutput(outputText, result.ExitCode, args.Kind, args.Intent)
}

// buildRunTaskArgv maps kind + target + args to a fixed argv slice (no shell).
func buildRunTaskArgv(kind, target string, args []string) ([]string, error) {
	switch kind {
	case "go_test":
		if target == "" {
			target = "./..."
		}
		return append([]string{"go", "test", target}, args...), nil
	case "go_build":
		if target == "" {
			target = "./..."
		}
		return append([]string{"go", "build", target}, args...), nil
	case "go_vet":
		if target == "" {
			target = "./..."
		}
		return append([]string{"go", "vet", target}, args...), nil
	case "npm_test":
		out := []string{"npm", "test"}
		if len(args) > 0 {
			// npm may swallow flags; separate user args after --.
			out = append(out, "--")
			out = append(out, args...)
		}
		return out, nil
	case "npm_run_build":
		out := []string{"npm", "run", "build"}
		if len(args) > 0 {
			out = append(out, "--")
			out = append(out, args...)
		}
		return out, nil
	case "cargo_test":
		return append([]string{"cargo", "test"}, args...), nil
	case "cargo_build":
		return append([]string{"cargo", "build"}, args...), nil
	case "make":
		out := []string{"make"}
		if target != "" {
			if !makeTargetRe.MatchString(target) {
				return nil, fmt.Errorf("make target %q is invalid (must match [A-Za-z0-9_.-]+)", target)
			}
			out = append(out, target)
		}
		return append(out, args...), nil
	case "custom":
		if len(args) == 0 {
			return nil, fmt.Errorf("custom kind requires non-empty args (args[0]=executable)")
		}
		if args[0] == "" {
			return nil, fmt.Errorf("custom kind: args[0] (executable) must not be empty")
		}
		// Return a copy so callers cannot mutate the original slice.
		out := make([]string, len(args))
		copy(out, args)
		return out, nil
	default:
		return nil, fmt.Errorf("unknown kind %q", kind)
	}
}

// validateRunTaskArgElements rejects null bytes in extra args.
func validateRunTaskArgElements(args []string) error {
	for i, a := range args {
		if strings.Contains(a, "\x00") {
			return fmt.Errorf("args[%d] contains null byte", i)
		}
	}
	return nil
}

// formatRunTaskOutput builds a structured text report with exit_code and sectioned streams.
func formatRunTaskOutput(kind string, argv []string, result *executeResult) string {
	var b strings.Builder
	b.WriteString("kind: ")
	b.WriteString(kind)
	b.WriteString("\nargv: ")
	b.WriteString(strings.Join(argv, " "))
	b.WriteString("\nexit_code: ")
	b.WriteString(fmt.Sprintf("%d", result.ExitCode))
	if result.Truncated {
		b.WriteString("\ntruncated: true")
	}
	b.WriteString("\n")

	if result.Stdout != "" {
		b.WriteString("\n--- stdout ---\n")
		b.WriteString(result.Stdout)
		if !strings.HasSuffix(result.Stdout, "\n") {
			b.WriteString("\n")
		}
	}
	if result.Stderr != "" {
		b.WriteString("\n--- stderr ---\n")
		b.WriteString(result.Stderr)
		if !strings.HasSuffix(result.Stderr, "\n") {
			b.WriteString("\n")
		}
	}
	if result.Stdout == "" && result.Stderr == "" {
		b.WriteString("\n(no output)\n")
	}
	return b.String()
}

// finishRunTaskOutput applies auto-index thresholds and shapes the MCP result.
// On failure with large output, returns a tail preview + index label when indexed.
func (s *server) finishRunTaskOutput(outputText string, exitCode int, kind, intent string) (*mcp.CallToolResult, any, error) {
	labelBase := kind
	if intent != "" {
		labelBase = intent
	}

	if len(outputText) > runTaskAutoIndexBytes {
		// Unique label per index: a fixed "run_task:<kind>" label would let a
		// later run silently overwrite an earlier document (INSERT OR REPLACE).
		label := uniqueIndexLabel("run_task", labelBase)
		if err := s.storeIndexLocked(label, outputText); err != nil {
			preview := tailUTF8(outputText, runTaskTailBytes)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf("exit_code: %d\nOutput is too large (%d bytes). Indexing failed: %v. Content was NOT indexed.\n\n--- Tail preview ---\n%s",
						exitCode, len(outputText), err, preview),
				}},
			}, nil, nil
		}
		preview := tailUTF8(outputText, runTaskTailBytes)
		// Search hint must use the index label (not empty intent).
		msg := fmt.Sprintf("exit_code: %d\nOutput is too large (%d bytes). Indexed as %q. Use ctx_kb action=search query=%q to search the indexed content.\n\n--- Tail preview ---\n%s",
			exitCode, len(outputText), label, label, preview)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		}, nil, nil
	}

	if len(outputText) > runTaskIntentIndexBytes && intent != "" {
		label := uniqueIndexLabel("run_task", intent)
		if err := s.storeIndexLocked(label, outputText); err != nil {
			preview := tailUTF8(outputText, runTaskPreviewBytes)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf("exit_code: %d\nOutput (%d bytes) was NOT indexed (error: %v).\n\n--- Tail preview ---\n%s",
						exitCode, len(outputText), err, preview),
				}},
			}, nil, nil
		}
		preview := tailUTF8(outputText, runTaskPreviewBytes)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{
				Text: fmt.Sprintf("exit_code: %d\nOutput (%d bytes) indexed as %q. Use ctx_kb action=search query=%q to search.\n\n--- Tail preview ---\n%s",
					exitCode, len(outputText), label, label, preview),
			}},
		}, nil, nil
	}

	// Normal return (includes exit_code in the structured body).
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: outputText}},
	}, nil, nil
}

// tailUTF8 returns the last maxBytes of s at a valid UTF-8 boundary, with a marker if truncated.
func tailUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	start := len(s) - maxBytes
	// Advance to next valid rune boundary.
	for start < len(s) && !utf8RuneStart(s[start]) {
		start++
	}
	return "... (truncated head)\n" + s[start:]
}

func utf8RuneStart(b byte) bool {
	// ASCII or leading multibyte (not a continuation 10xxxxxx).
	return b&0xC0 != 0x80
}
