package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Category MCP tools (v2.0): fewer top-level tools, action= selects capability.
// Hosts (Grok, Pi, others) call these as real tools — not skills.

// ---------- ctx_run ----------

type ctxRunArgs struct {
	Action string `json:"action" jsonschema:"execute|execute_file|batch|run_task"`

	// execute
	Command    string            `json:"command,omitempty"`
	Language   string            `json:"language,omitempty"`
	Timeout    int               `json:"timeout,omitempty"`
	Background bool              `json:"background,omitempty"`
	Intent     string            `json:"intent,omitempty"`
	CWD        string            `json:"cwd,omitempty"`
	Argv       []string          `json:"argv,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Stdin      string            `json:"stdin,omitempty"`

	// execute_file
	Path string `json:"path,omitempty"`
	Code string `json:"code,omitempty"`

	// batch
	Commands    []batchCommand `json:"commands,omitempty"`
	Queries     []string       `json:"queries,omitempty"`
	Concurrency int            `json:"concurrency,omitempty"`
	QueryScope  string         `json:"query_scope,omitempty"`

	// run_task
	Kind      string   `json:"kind,omitempty"`
	Target    string   `json:"target,omitempty"`
	Args      []string `json:"args,omitempty"`
	TimeoutMs int      `json:"timeout_ms,omitempty"`
}

func (s *server) toolCtxRun(ctx context.Context, req *mcp.CallToolRequest, args ctxRunArgs) (*mcp.CallToolResult, any, error) {
	switch strings.ToLower(strings.TrimSpace(args.Action)) {
	case "execute":
		return s.toolExecute(ctx, req, executeArgs{
			Command: args.Command, Language: args.Language, Timeout: args.Timeout,
			Background: args.Background, Intent: args.Intent, CWD: args.CWD,
			Argv: args.Argv, Env: args.Env, Stdin: args.Stdin,
		})
	case "execute_file":
		return s.toolExecuteFile(ctx, req, executeFileArgs{
			Path: args.Path, Language: args.Language, Code: args.Code,
			Timeout: args.Timeout, Intent: args.Intent, CWD: args.CWD,
		})
	case "batch":
		return s.toolBatchExecute(ctx, req, batchArgs{
			Commands: args.Commands, Queries: args.Queries, Concurrency: args.Concurrency,
			CWD: args.CWD, Timeout: args.Timeout, QueryScope: args.QueryScope,
		})
	case "run_task":
		return s.toolRunTask(ctx, req, runTaskArgs{
			Kind: args.Kind, Target: args.Target, Args: args.Args,
			CWD: args.CWD, TimeoutMs: args.TimeoutMs, Intent: args.Intent, Env: args.Env,
		})
	case "":
		return nil, nil, fmt.Errorf("action is required (execute|execute_file|batch|run_task)")
	default:
		return nil, nil, fmt.Errorf("unknown ctx_run action %q (execute|execute_file|batch|run_task)", args.Action)
	}
}

// ---------- ctx_fs ----------

type ctxFsArgs struct {
	Action        string `json:"action" jsonschema:"ls|glob|stat|rg"`
	Path          string `json:"path,omitempty"`
	Pattern       string `json:"pattern,omitempty"`
	Glob          string `json:"glob,omitempty"`
	Depth         int    `json:"depth,omitempty"`
	IncludeHidden bool   `json:"include_hidden,omitempty"`
	Limit         int    `json:"limit,omitempty"`
	IgnoreCase    bool   `json:"ignore_case,omitempty"`
	Context       int    `json:"context,omitempty"`
	Literal       bool   `json:"literal,omitempty"`
}

func (s *server) toolCtxFs(ctx context.Context, req *mcp.CallToolRequest, args ctxFsArgs) (*mcp.CallToolResult, any, error) {
	switch strings.ToLower(strings.TrimSpace(args.Action)) {
	case "ls":
		return s.toolLs(ctx, req, lsArgs{
			Path: args.Path, Depth: args.Depth, IncludeHidden: args.IncludeHidden, Limit: args.Limit,
		})
	case "glob":
		pat := args.Pattern
		if pat == "" {
			pat = args.Glob
		}
		return s.toolGlob(ctx, req, globArgs{Pattern: pat, Path: args.Path, Limit: args.Limit})
	case "stat":
		return s.toolStat(ctx, req, statArgs{Path: args.Path})
	case "rg":
		return s.toolRg(ctx, req, rgArgs{
			Pattern: args.Pattern, Path: args.Path, Glob: args.Glob,
			IgnoreCase: args.IgnoreCase, Context: args.Context, Limit: args.Limit, Literal: args.Literal,
		})
	case "":
		return nil, nil, fmt.Errorf("action is required (ls|glob|stat|rg)")
	default:
		return nil, nil, fmt.Errorf("unknown ctx_fs action %q (ls|glob|stat|rg)", args.Action)
	}
}

// ---------- ctx_git ----------

type ctxGitArgs struct {
	Action  string `json:"action" jsonschema:"status|diff|log"`
	CWD     string `json:"cwd,omitempty"`
	Path    string `json:"path,omitempty"`
	Stat    bool   `json:"stat,omitempty"`
	Unified int    `json:"unified,omitempty"`
	Staged  bool   `json:"staged,omitempty"`
	N       int    `json:"n,omitempty"`
	Oneline *bool  `json:"oneline,omitempty"`
}

func (s *server) toolCtxGit(ctx context.Context, req *mcp.CallToolRequest, args ctxGitArgs) (*mcp.CallToolResult, any, error) {
	switch strings.ToLower(strings.TrimSpace(args.Action)) {
	case "status":
		return s.toolGitStatus(ctx, req, gitStatusArgs{CWD: args.CWD})
	case "diff":
		return s.toolGitDiff(ctx, req, gitDiffArgs{
			CWD: args.CWD, Path: args.Path, Stat: args.Stat, Unified: args.Unified, Staged: args.Staged,
		})
	case "log":
		return s.toolGitLog(ctx, req, gitLogArgs{
			CWD: args.CWD, N: args.N, Path: args.Path, Oneline: args.Oneline,
		})
	case "":
		return nil, nil, fmt.Errorf("action is required (status|diff|log)")
	default:
		return nil, nil, fmt.Errorf("unknown ctx_git action %q (status|diff|log)", args.Action)
	}
}

// ---------- ctx_kb ----------

type ctxKbArgs struct {
	Action    string   `json:"action" jsonschema:"index|search|fetch|stats|purge|doctor"`
	Path      string   `json:"path,omitempty"`
	Query     string   `json:"query,omitempty"`
	URL       string   `json:"url,omitempty"`
	URLs      []string `json:"urls,omitempty"`
	Source    string   `json:"source,omitempty"`
	Format    string   `json:"format,omitempty"`
	Force     bool     `json:"force,omitempty"`
	MaxBytes  int      `json:"maxBytes,omitempty"`
	TimeoutMs int      `json:"timeoutMs,omitempty"`
	TTL       *int     `json:"ttl,omitempty"`
	Confirm   bool     `json:"confirm,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	SessionID string   `json:"sessionId,omitempty"`
	DryRun    bool     `json:"dryRun,omitempty"`
}

func (s *server) toolCtxKb(ctx context.Context, req *mcp.CallToolRequest, args ctxKbArgs) (*mcp.CallToolResult, any, error) {
	switch strings.ToLower(strings.TrimSpace(args.Action)) {
	case "index":
		return s.toolIndex(ctx, req, indexArgs{Path: args.Path})
	case "search":
		return s.toolSearch(ctx, req, searchArgs{Query: args.Query})
	case "fetch":
		return s.toolFetchAndIndex(ctx, req, fetchArgs{
			URL: args.URL, URLs: args.URLs, Source: args.Source, Format: args.Format,
			Force: args.Force, MaxBytes: args.MaxBytes, TimeoutMs: args.TimeoutMs, TTL: args.TTL,
		})
	case "stats":
		return s.toolStats(ctx, req, statsArgs{})
	case "purge":
		return s.toolPurge(ctx, req, purgeArgs{
			Confirm: args.Confirm, Scope: args.Scope, SessionID: args.SessionID, DryRun: args.DryRun,
		})
	case "doctor":
		return s.toolDoctor(ctx, req, doctorArgs{})
	case "":
		return nil, nil, fmt.Errorf("action is required (index|search|fetch|stats|purge|doctor)")
	default:
		if strings.EqualFold(strings.TrimSpace(args.Action), "fetch_and_index") {
			return nil, nil, fmt.Errorf("unknown ctx_kb action %q: fetch_and_index is not a valid action, use \"fetch\"", args.Action)
		}
		return nil, nil, fmt.Errorf("unknown ctx_kb action %q (index|search|fetch|stats|purge|doctor)", args.Action)
	}
}

// ---------- ctx_bg ----------

type ctxBgArgs struct {
	Action    string `json:"action" jsonschema:"list|kill|log|wait"`
	ID        string `json:"id,omitempty"`
	PID       int    `json:"pid,omitempty"`
	TailLines int    `json:"tail_lines,omitempty"`
	TailBytes int    `json:"tail_bytes,omitempty"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
}

func (s *server) toolCtxBg(ctx context.Context, req *mcp.CallToolRequest, args ctxBgArgs) (*mcp.CallToolResult, any, error) {
	switch strings.ToLower(strings.TrimSpace(args.Action)) {
	case "list":
		return s.toolBackgroundList(ctx, req, backgroundListArgs{})
	case "kill":
		return s.toolBackgroundKill(ctx, req, backgroundKillArgs{ID: args.ID, PID: args.PID})
	case "log":
		return s.toolBackgroundLog(ctx, req, backgroundLogArgs{
			ID: args.ID, PID: args.PID, TailLines: args.TailLines, TailBytes: args.TailBytes,
		})
	case "wait":
		return s.toolBackgroundWait(ctx, req, backgroundWaitArgs{
			ID: args.ID, PID: args.PID, TimeoutMs: args.TimeoutMs,
		})
	case "":
		return nil, nil, fmt.Errorf("action is required (list|kill|log|wait)")
	default:
		return nil, nil, fmt.Errorf("unknown ctx_bg action %q (list|kill|log|wait)", args.Action)
	}
}

// ctxRunDescription is the registered description of the ctx_run tool.
// The kind list must match validRunTaskKinds (run_task.go).
const ctxRunDescription = "PRIMARY for commands/tests/builds. action=execute (shell/code; prefer argv), " +
	"execute_file (code over FILE_CONTENT), batch (many commands + optional queries), " +
	"run_task (go_test|go_build|go_vet|npm_test|npm_run_build|cargo_test|cargo_build|make|custom; fixed argv). Large output auto-indexed."

// registerCategoryTools wires the v2.0 multi-category MCP surface (end state).
func (s *server) registerCategoryTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "ctx_run",
		Description: ctxRunDescription,
	}, s.toolCtxRun)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ctx_fs",
		Description: "Workspace filesystem (sandboxed). action=ls (list), glob (pattern), " +
			"stat (metadata), rg (content search). Prefer over ad-hoc shell find/ls/rg when possible.",
	}, s.toolCtxFs)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ctx_git",
		Description: "Read-only git. action=status (porcelain -b), diff (optional path/stat/staged), " +
			"log (n, path, oneline). No commit/push/reset.",
	}, s.toolCtxGit)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ctx_kb",
		Description: "Local knowledge base / context virtualization. action=index (path), search (query), " +
			"fetch (URL→markdown→index), stats, purge (confirm:true), doctor (install check).",
	}, s.toolCtxKb)

	mcp.AddTool(srv, &mcp.Tool{
		Name: "ctx_bg",
		Description: "Background processes started via ctx_run action=execute background:true. " +
			"action=list|kill|log|wait (id or pid).",
	}, s.toolCtxBg)
}
