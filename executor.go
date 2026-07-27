package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// defaultBackgroundMaxAge is how long a background process may live before
// the supervisor reaps it. Override is not exposed as a flag yet; constant
// is documented here for operators.
const defaultBackgroundMaxAge = 1 * time.Hour

// bgTempPrefix marks temp files owned by background processes so init
// cleanup can skip them when they are still registered.
const bgTempPrefix = "ctxmode_bg_"

// ---------- background process registry ----------

// bgEntry tracks a background subprocess for list/kill/reap.
type bgEntry struct {
	ID        string    `json:"id"`
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Command   string    `json:"command,omitempty"`
	Language  string    `json:"language,omitempty"`
	TempFiles []string  `json:"temp_files,omitempty"`
	Done      bool      `json:"done"`
	ExitCode  int       `json:"exit_code,omitempty"`
	// pgid for process-group kill (Setpgid=true).
	pgid int
	cmd  *exec.Cmd
}

var (
	bgMu      sync.Mutex
	bgProcs   = map[string]*bgEntry{}
	bgSeq     atomic.Uint64
	bgReaper  sync.Once
)

// registerBackground records a live background process.
func registerBackground(cmd *exec.Cmd, language, command string, temps []string) *bgEntry {
	bgReaper.Do(func() { go backgroundReaperLoop() })
	id := fmt.Sprintf("bg-%d", bgSeq.Add(1))
	pgid := 0
	if cmd.Process != nil {
		pgid = cmd.Process.Pid
	}
	// Cap command string for list readability.
	if len(command) > 200 {
		command = command[:200] + "..."
	}
	e := &bgEntry{
		ID:        id,
		PID:       cmd.Process.Pid,
		StartedAt: time.Now(),
		Language:  language,
		Command:   command,
		TempFiles: append([]string(nil), temps...),
		pgid:      pgid,
		cmd:       cmd,
	}
	bgMu.Lock()
	bgProcs[id] = e
	// Protect temp paths from init-style cleanup while registered.
	for _, t := range temps {
		protectTemp(t)
	}
	bgMu.Unlock()
	return e
}

// finishBackground marks entry done and cleans temps.
// Idempotent: a second call (e.g. Wait after killBackground) is a no-op.
func finishBackground(id string, exitCode int) {
	bgMu.Lock()
	e, ok := bgProcs[id]
	if !ok {
		bgMu.Unlock()
		return
	}
	if e.Done {
		bgMu.Unlock()
		return
	}
	e.Done = true
	e.ExitCode = exitCode
	temps := append([]string(nil), e.TempFiles...)
	e.TempFiles = nil
	// Keep entry briefly for list visibility, but unprotect temps for cleanup.
	for _, t := range temps {
		unprotectTemp(t)
	}
	bgMu.Unlock()
	for _, t := range temps {
		os.Remove(t)
	}
	// Remove from registry after a short grace so list can still show it.
	go func() {
		time.Sleep(30 * time.Second)
		bgMu.Lock()
		delete(bgProcs, id)
		bgMu.Unlock()
	}()
}

// listBackground returns a snapshot of registered processes.
func listBackground() []bgEntry {
	bgMu.Lock()
	defer bgMu.Unlock()
	out := make([]bgEntry, 0, len(bgProcs))
	for _, e := range bgProcs {
		cp := *e
		cp.cmd = nil
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out
}

// killBackground kills by id or by PID string. Returns a status message.
// On success the entry is marked Done promptly so list no longer shows it as live.
// Kill errors (other than ESRCH / already gone) are returned to the caller.
func killBackground(idOrPID string) (string, error) {
	bgMu.Lock()
	var target *bgEntry
	if e, ok := bgProcs[idOrPID]; ok {
		target = e
	} else if pid, err := strconv.Atoi(idOrPID); err == nil {
		for _, e := range bgProcs {
			if e.PID == pid {
				target = e
				break
			}
		}
	}
	if target == nil {
		bgMu.Unlock()
		return "", fmt.Errorf("no background process matching %q", idOrPID)
	}
	if target.Done {
		id := target.ID
		bgMu.Unlock()
		return fmt.Sprintf("process %s already exited", id), nil
	}
	pgid := target.pgid
	id := target.ID
	pid := target.PID
	bgMu.Unlock()

	// Two-stage kill of the process group; surface real failures (ignore ESRCH).
	killErr := func(err error) error {
		if err == nil || err == syscall.ESRCH {
			return nil
		}
		return err
	}
	var lastErr error
	if pgid != 0 {
		if err := killErr(syscall.Kill(-pgid, syscall.SIGTERM)); err != nil {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
		if err := killErr(syscall.Kill(-pgid, syscall.SIGKILL)); err != nil {
			lastErr = err
		} else {
			lastErr = nil // process gone or SIGKILL delivered
		}
	} else {
		if err := killErr(syscall.Kill(pid, syscall.SIGTERM)); err != nil {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
		if err := killErr(syscall.Kill(pid, syscall.SIGKILL)); err != nil {
			lastErr = err
		} else {
			lastErr = nil
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("kill background process %s (PID %d): %w", id, pid, lastErr)
	}
	// Mark Done ASAP (exit code -1 = killed) so list no longer shows a live task.
	// Wait goroutine may also call finishBackground; that path is now idempotent.
	finishBackground(id, -1)
	return fmt.Sprintf("killed background process %s (PID %d)", id, pid), nil
}

// backgroundReaperLoop kills processes that exceed defaultBackgroundMaxAge.
func backgroundReaperLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		bgMu.Lock()
		var stale []string
		for id, e := range bgProcs {
			if !e.Done && now.Sub(e.StartedAt) > defaultBackgroundMaxAge {
				stale = append(stale, id)
			}
		}
		bgMu.Unlock()
		for _, id := range stale {
			_, _ = killBackground(id)
		}
	}
}

// protectedTemps tracks temp files currently owned by live background jobs.
var (
	protectedTempsMu sync.Mutex
	protectedTemps   = map[string]int{}
)

func protectTemp(path string) {
	protectedTempsMu.Lock()
	protectedTemps[path]++
	protectedTempsMu.Unlock()
}

func unprotectTemp(path string) {
	protectedTempsMu.Lock()
	if protectedTemps[path] > 1 {
		protectedTemps[path]--
	} else {
		delete(protectedTemps, path)
	}
	protectedTempsMu.Unlock()
}

func isTempProtected(path string) bool {
	protectedTempsMu.Lock()
	defer protectedTempsMu.Unlock()
	return protectedTemps[path] > 0
}

// init cleans up stale temp files from previous runs that may have been
// killed (e.g., SIGKILL) before their deferred cleanup could execute.
// Skips temps still referenced by the background registry (same process).
func init() {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "ctxmode_") {
			continue
		}
		full := filepath.Join(os.TempDir(), name)
		if isTempProtected(full) {
			continue
		}
		// Background-owned temps use a distinct prefix; if not protected
		// they belong to a dead prior process and may be reaped after 24h.
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > 24*time.Hour {
			os.Remove(full)
		}
	}
}

// ---------- MCP tools: background list / kill ----------

type backgroundListArgs struct{}

func (s *server) toolBackgroundList(ctx context.Context, _ *mcp.CallToolRequest, _ backgroundListArgs) (*mcp.CallToolResult, any, error) {
	entries := listBackground()
	type row struct {
		ID        string `json:"id"`
		PID       int    `json:"pid"`
		StartedAt string `json:"started_at"`
		AgeSec    int64  `json:"age_sec"`
		Language  string `json:"language,omitempty"`
		Command   string `json:"command,omitempty"`
		Done      bool   `json:"done"`
		ExitCode  int    `json:"exit_code,omitempty"`
	}
	now := time.Now()
	out := make([]row, 0, len(entries))
	for _, e := range entries {
		out = append(out, row{
			ID:        e.ID,
			PID:       e.PID,
			StartedAt: e.StartedAt.Format(time.RFC3339),
			AgeSec:    int64(now.Sub(e.StartedAt).Seconds()),
			Language:  e.Language,
			Command:   e.Command,
			Done:      e.Done,
			ExitCode:  e.ExitCode,
		})
	}
	js, _ := json.MarshalIndent(out, "", "  ")
	if len(out) == 0 {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "[]\n(no background processes; max age " + defaultBackgroundMaxAge.String() + ")"}},
		}, nil, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

type backgroundKillArgs struct {
	ID  string `json:"id,omitempty" jsonschema:"Background process id from ctx_background_list"`
	PID int    `json:"pid,omitempty" jsonschema:"Process PID to kill"`
}

func (s *server) toolBackgroundKill(ctx context.Context, _ *mcp.CallToolRequest, args backgroundKillArgs) (*mcp.CallToolResult, any, error) {
	key := args.ID
	if key == "" && args.PID != 0 {
		key = strconv.Itoa(args.PID)
	}
	if key == "" {
		return nil, nil, fmt.Errorf("id or pid is required")
	}
	msg, err := killBackground(key)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil, nil
}

// ---------- runtime configuration ----------

// runtimeConfig describes how to execute code in a given language.
type runtimeConfig struct {
	Exe  string   // executable name (e.g., "node")
	Ext  string   // temp file extension (e.g., ".js")
	Wrap func(code string) string // wraps user code with language boilerplate
}

// executeResult holds the output of a code execution.
type executeResult struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	Truncated  bool   `json:"truncated,omitempty"`
	Indexed    bool   `json:"indexed,omitempty"`
	IndexLabel string `json:"index_label,omitempty"`
}

// runtimes maps language name to its configuration.
var runtimes = map[string]runtimeConfig{
	"javascript": {Exe: "node", Ext: ".js", Wrap: jsWrapper},
	"typescript": {Exe: "ts-node", Ext: ".ts", Wrap: tsWrapper},
	"python":     {Exe: "python3", Ext: ".py", Wrap: pyWrapper},
	"shell":      {Exe: "sh", Ext: ".sh", Wrap: shellWrapper},
	"go":         {Exe: "go", Ext: ".go", Wrap: goWrapper},
	"rust":       {Exe: "rustc", Ext: ".rs", Wrap: rustWrapper},
	"php":        {Exe: "php", Ext: ".php", Wrap: phpWrapper},
	"perl":       {Exe: "perl", Ext: ".pl", Wrap: perlWrapper},
	"ruby":       {Exe: "ruby", Ext: ".rb", Wrap: rubyWrapper},
	"r":          {Exe: "Rscript", Ext: ".R", Wrap: rWrapper},
	"elixir":     {Exe: "elixir", Ext: ".exs", Wrap: elixirWrapper},
	"csharp":     {Exe: "dotnet-script", Ext: ".csx", Wrap: csWrapper},
}

// ---------- wrapper functions ----------

// shellWrapper returns the code as-is. Shell is run via "sh -c" directly.
func shellWrapper(code string) string {
	return code
}

// jsWrapper wraps code in an async IIFE so users can use await at top level.
func jsWrapper(code string) string {
	return "(async () => {\n" + code + "\n})();\n"
}

// tsWrapper wraps TypeScript code like JavaScript.
func tsWrapper(code string) string {
	return "(async () => {\n" + code + "\n})();\n"
}

// pyWrapper returns Python code as-is.
func pyWrapper(code string) string {
	return code
}

// goStdImportAliases maps common package selectors to their import paths.
var goStdImportAliases = map[string]string{
	"fmt":        "fmt",
	"os":         "os",
	"strings":    "strings",
	"strconv":    "strconv",
	"time":       "time",
	"bytes":      "bytes",
	"io":         "io",
	"bufio":      "bufio",
	"errors":     "errors",
	"sort":       "sort",
	"math":       "math",
	"sync":       "sync",
	"context":    "context",
	"regexp":     "regexp",
	"log":        "log",
	"filepath":   "path/filepath",
	"json":       "encoding/json",
	"base64":     "encoding/base64",
	"http":       "net/http",
	"url":        "net/url",
	"ioutil":     "io/ioutil",
	"exec":       "os/exec",
	"path":       "path",
	"unicode":    "unicode",
	"utf8":       "unicode/utf8",
	"hex":        "encoding/hex",
	"sha256":     "crypto/sha256",
	"md5":        "crypto/md5",
	"rand":       "math/rand",
	"big":        "math/big",
	"reflect":    "reflect",
	"runtime":    "runtime",
	"flag":       "flag",
	"net":        "net",
	"template":   "text/template",
	"html":       "html",
	"csv":        "encoding/csv",
	"gzip":       "compress/gzip",
	"tar":        "archive/tar",
	"zip":        "archive/zip",
	"syscall":    "syscall",
	"atomic":     "sync/atomic",
	"binary":     "encoding/binary",
	"xml":        "encoding/xml",
	"sql":        "database/sql",
	"tls":        "crypto/tls",
	"x509":       "crypto/x509",
	"hmac":       "crypto/hmac",
	"sha1":       "crypto/sha1",
	"sha512":     "crypto/sha512",
	"aes":        "crypto/aes",
	"cipher":     "crypto/cipher",
	"elliptic":   "crypto/elliptic",
	"ecdsa":      "crypto/ecdsa",
	"rsa":        "crypto/rsa",
	"ed25519":    "crypto/ed25519",
	"pem":        "encoding/pem",
	"ascii85":    "encoding/ascii85",
	"gob":        "encoding/gob",
	"tabwriter":  "text/tabwriter",
	"scanner":    "text/scanner",
	"parser":     "go/parser",
	"ast":        "go/ast",
	"token":      "go/token",
	"format":     "go/format",
	"printer":    "go/printer",
	"types":      "go/types",
	"constant":   "go/constant",
	"build":      "go/build",
	"doc":        "go/doc",
	"importer":   "go/importer",
}

// goSelectorRe matches pkg.Ident uses (simple heuristic for import detection).
var goSelectorRe = regexp.MustCompile(`\b([a-z][a-zA-Z0-9_]*)\.[A-Z(]`)

// detectGoImports scans user code for common stdlib package selectors and
// returns the import paths needed. Always includes "fmt" if nothing else is
// found and the code looks like it might use Print-style helpers, else just
// the detected set (may be empty → we still default to fmt for ergonomics).
func detectGoImports(code string) []string {
	seen := map[string]bool{}
	for _, m := range goSelectorRe.FindAllStringSubmatch(code, -1) {
		if len(m) < 2 {
			continue
		}
		if path, ok := goStdImportAliases[m[1]]; ok {
			seen[path] = true
		}
	}
	// Ergonomic default: snippets often use fmt without other packages.
	if len(seen) == 0 {
		seen["fmt"] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// goWrapper wraps user code into a complete main package, auto-importing
// standard library packages detected from selector usage (fmt, os, strings, …).
// If the code already declares `package `, it is returned unchanged.
func goWrapper(code string) string {
	trimmed := strings.TrimSpace(code)
	if strings.HasPrefix(trimmed, "package ") {
		return code
	}
	imports := detectGoImports(code)
	var b strings.Builder
	b.WriteString("package main\n\n")
	if len(imports) == 1 {
		b.WriteString(fmt.Sprintf("import %q\n\n", imports[0]))
	} else {
		b.WriteString("import (\n")
		for _, imp := range imports {
			b.WriteString(fmt.Sprintf("\t%q\n", imp))
		}
		b.WriteString(")\n\n")
	}
	b.WriteString("func main() {\n")
	b.WriteString(code)
	b.WriteString("\n}\n")
	return b.String()
}

// rustWrapper wraps user code into a complete main function.
func rustWrapper(code string) string {
	return `fn main() {
` + code + `
}
`
}

// phpWrapper adds <?php tag.
func phpWrapper(code string) string {
	return "<?php\n" + code + "\n"
}

// perlWrapper returns Perl code as-is.
func perlWrapper(code string) string {
	return code
}

// rubyWrapper returns Ruby code as-is.
func rubyWrapper(code string) string {
	return code
}

// rWrapper returns R code as-is.
func rWrapper(code string) string {
	return code
}

// elixirWrapper returns Elixir code as-is.
func elixirWrapper(code string) string {
	return code
}

// csWrapper returns C#/dotnet-script code as-is.
func csWrapper(code string) string {
	return code
}

// ---------- runtime checking ----------

// tsNodeAvailable caches typescript runtime detection result.
var (
	tsNodeAvailable  bool
	tsNodePath       string
	tsNodeCheckOnce  sync.Once
	tsNodePathMu     sync.Mutex
)

// detectTsNode probes for a local ts-node installation without network access.
// Returns whether it's available and the path to the executable.
func detectTsNode() (bool, string) {
	// 1. Check for global ts-node binary
	if p, err := exec.LookPath("ts-node"); err == nil {
		return true, p
	}
	// 2. Check cwd/node_modules/.bin/ts-node
	cwd, err := os.Getwd()
	if err == nil {
		p := filepath.Join(cwd, "node_modules", ".bin", "ts-node")
		if _, err := os.Stat(p); err == nil {
			return true, p
		}
	}
	// 3. Fall back to npm ls (local only, reads package.json)
	npmCtx, npmCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer npmCancel()
	if exec.CommandContext(npmCtx, "npm", "ls", "ts-node", "--depth=0").Run() == nil {
		// ts-node is installed locally; use the local path
		cwd, _ := os.Getwd()
		p := filepath.Join(cwd, "node_modules", ".bin", "ts-node")
		if _, err := os.Stat(p); err == nil {
			return true, p
		}
		// Last resort: assume it's resolvable by name
		return true, "ts-node"
	}
	return false, ""
}

// checkRuntime checks if the runtime executable for the given language is
// available on the system PATH. Shell is always available.
// When useCache is true, TypeScript detection is cached via sync.Once
// (for execution gating). When false, detection runs fresh (for doctor).
func checkRuntime(language string, useCache bool) bool {
	if language == "shell" {
		return true
	}
	rt, ok := runtimes[language]
	if !ok {
		return false
	}

	switch language {
	case "go":
		// go version exits 0
		return exec.Command(rt.Exe, "version").Run() == nil
	case "typescript":
		if useCache {
			tsNodeCheckOnce.Do(func() {
				av, p := detectTsNode()
				tsNodePathMu.Lock()
				tsNodeAvailable = av
				tsNodePath = p
				tsNodePathMu.Unlock()
			})
			return tsNodeAvailable
		}
		// Fresh detection for doctor — update cached path for execution use.
		avail, p := detectTsNode()
		if avail {
			tsNodePathMu.Lock()
			tsNodePath = p
			tsNodePathMu.Unlock()
		}
		return avail
	default:
		// Use Go standard library instead of external "which" command.
		_, err := exec.LookPath(rt.Exe)
		return err == nil
	}
}

// ---------- code wrapping ----------

// wrapCode wraps user code with language-appropriate boilerplate.
func wrapCode(language, code string) string {
	rt, ok := runtimes[language]
	if !ok || rt.Wrap == nil {
		return code
	}
	return rt.Wrap(code)
}

// ---------- file content injection for ctx_execute_file ----------

// injectFileContent prepends a FILE_CONTENT variable definition to the user's
// code, so the sandbox script can access the file contents through a variable.
func injectFileContent(language, code, fileContent string) string {
	switch language {
	case "shell":
		// Single-quoted string: all characters are literal except single quote.
		// Escape single quotes by ending the quote, adding an escaped quote, and
		// reopening: 'text'\''more' evaluates to text'more.
		escaped := strings.ReplaceAll(fileContent, `'`, `'\''`)
		return fmt.Sprintf(`FILE_CONTENT='%s'
%s`, escaped, code)

	case "javascript", "typescript":
		// Backtick template literal; escape backslash, backticks, and ${} interpolation.
		// Order matters: backslash first so we don't re-escape injected backslashes.
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, "`", "\\`")
		escaped = strings.ReplaceAll(escaped, "${", "\\${")
		return "const FILE_CONTENT = `" + escaped + "`;\n" + code

	case "python":
		// Triple-quoted raw string. Raw strings cannot contain """, and a
		// trailing quote would prematurely close the literal. A trailing
		// backslash is also illegal in a Python raw string (r"foo\").
		// Fall back to base64 for those cases.
		if strings.Contains(fileContent, `"""`) ||
			strings.HasSuffix(fileContent, `"`) ||
			strings.HasSuffix(fileContent, `\`) {
			encoded := base64.StdEncoding.EncodeToString([]byte(fileContent))
			return "import base64\nFILE_CONTENT = base64.b64decode(\"" + encoded + "\").decode()\n" + code
		}
		return "FILE_CONTENT = r\"\"\"" + fileContent + "\"\"\"\n" + code

	case "go":
		// Go raw string literal (backtick-delimited); cannot contain backticks.
		// Split on backticks and concatenate with escaped quotes.
		parts := strings.Split(fileContent, "`")
		if len(parts) == 1 {
			return "FILE_CONTENT := `" + fileContent + "`\n" + code
		}
		// Multiple backticks: build a concatenation expression.
		var sb strings.Builder
		sb.WriteString("FILE_CONTENT := ")
		for i, p := range parts {
			if i > 0 {
				sb.WriteString(" + \"`\" + ")
			}
			sb.WriteString("`" + p + "`")
		}
		sb.WriteString("\n" + code)
		return sb.String()

	case "rust":
		// Rust uses double-quoted strings with escaped quotes and backslashes.
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		escaped = strings.ReplaceAll(escaped, "\n", `\n`)
		escaped = strings.ReplaceAll(escaped, "\r", `\r`)
		return `    let FILE_CONTENT = "` + escaped + `";` + "\n" + code

	case "php":
		// Single-quoted PHP string; escape single quotes and backslashes.
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		return "$FILE_CONTENT = '" + escaped + "';\n" + code

	case "perl":
		// Single-quoted Perl string: only \\ and \' are special.
		// Newlines are literal (multi-line string is valid).
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		return "my $FILE_CONTENT = '" + escaped + "';\n" + code

	case "ruby":
		// Single-quoted Ruby string.
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		return "FILE_CONTENT = '" + escaped + "'\n" + code

	case "r":
		// Single-quoted R string.
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		return "FILE_CONTENT <- '" + escaped + "'\n" + code

	case "elixir":
		// ~S sigil disables interpolation and escapes.
		// Triple-quote cannot be escaped inside ~S, so fall back to base64.
		if strings.Contains(fileContent, `"""`) {
			encoded := base64.StdEncoding.EncodeToString([]byte(fileContent))
			return "FILE_CONTENT = Base.decode64!(\"" + encoded + "\")\n" + code
		}
		return "FILE_CONTENT = ~S\"\"\"\n" + fileContent + "\n\"\"\"\n" + code

	case "csharp":
		// Verbatim string literal (@"").
		escaped := strings.ReplaceAll(fileContent, `"`, `""`)
		return "var FILE_CONTENT = @\"" + escaped + "\";\n" + code

	default:
		return code
	}
}

// ---------- core execution ----------

// runCode executes code in the specified language sandbox.
// It handles temp file creation, runtime selection, timeout, and background mode.
func runCode(ctx context.Context, language, code, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
	rt, ok := runtimes[language]
	if !ok {
		return nil, fmt.Errorf("unsupported language: %q (supported: javascript, typescript, python, shell, go, rust, php, perl, ruby, r, elixir, csharp)", language)
	}

	if !checkRuntime(language, true) {
		return nil, fmt.Errorf("runtime %q is not available for language %q — install it first or use a different language", rt.Exe, language)
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	wrapped := wrapCode(language, code)

	// Shell is handled specially — no temp file needed.
	if language == "shell" {
		return runShell(ctx, wrapped, cwd, timeout, background)
	}

	// Create a temp file with the appropriate extension.
	// Background temps use a distinct prefix so cleanup can treat them carefully.
	pattern := "ctxmode_*" + rt.Ext
	if background {
		pattern = bgTempPrefix + "*" + rt.Ext
	}
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	// In background mode the process outlives this function — the temp file
	// must stick around until it exits. We defer removal only for foreground runs.
	if !background {
		defer os.Remove(tmpPath)
	}

	if _, err := tmpFile.WriteString(wrapped); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	// Build and run the command based on language.
	return runCompiled(ctx, language, rt, tmpPath, cwd, timeout, background)
}

// runShell executes code directly via "sh -c".
func runShell(ctx context.Context, code, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
	var cmd *exec.Cmd
	shellPath := os.Getenv("SHELL")
	if shellPath != "" {
		parts := strings.Fields(shellPath)
		if len(parts) == 0 {
			cmd = exec.Command("sh", "-c", code)
		} else {
			args := append(parts[1:], "-c", code)
			cmd = exec.Command(parts[0], args...)
		}
	} else {
		cmd = exec.Command("sh", "-c", code)
	}
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	return runCmd(ctx, cmd, timeout, background, "shell", code)
}

// runCompiled executes a language that uses a temp source file.
func runCompiled(ctx context.Context, language string, rt runtimeConfig, tmpPath, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
	var cmd *exec.Cmd
	var cleanups []string

	switch language {
	case "rust":
		// Two-step: compile via rustc, then run the binary.
		outPath := tmpPath + "_bin"
		if !background {
			defer os.Remove(outPath)
		} else {
			cleanups = append(cleanups, outPath)
		}

		compileStart := time.Now()
		compileCtx := ctx
		if timeout > 0 {
			var cancel context.CancelFunc
			compileCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		compileCmd := exec.Command("rustc", "-o", outPath, tmpPath)
		compileCmd.Dir = cwd
		compileCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		var compileOutBuf limitedBuffer
		compileOutBuf.limit = maxCmdOutput
		compileCmd.Stdout = &compileOutBuf
		compileCmd.Stderr = &compileOutBuf
		if err := compileCmd.Start(); err != nil {
			if background {
				os.Remove(tmpPath)
				os.Remove(outPath)
			}
			return &executeResult{
				Stdout:   compileOutBuf.String(),
				Stderr:   fmt.Sprintf("compilation failed: %v", err),
				ExitCode: -1,
			}, nil
		}
		compileDone := make(chan error, 1)
		go func() { compileDone <- compileCmd.Wait() }()
		var compileErr error
		if timeout > 0 {
			select {
			case compileErr = <-compileDone:
			case <-compileCtx.Done():
				if compileCmd.Process != nil {
					_ = syscall.Kill(-compileCmd.Process.Pid, syscall.SIGTERM)
					select {
					case compileErr = <-compileDone:
					case <-time.After(3 * time.Second):
						_ = syscall.Kill(-compileCmd.Process.Pid, syscall.SIGKILL)
						compileErr = <-compileDone
					}
				} else {
					compileErr = <-compileDone
				}
			}
		} else {
			compileErr = <-compileDone
		}
		if compileErr != nil {
			if background {
				os.Remove(tmpPath)
				os.Remove(outPath)
			}
			return &executeResult{
				Stdout:   compileOutBuf.String(),
				Stderr:   fmt.Sprintf("compilation failed: %v", compileErr),
				ExitCode: -1,
			}, nil
		}
		cmd = exec.Command(outPath)
		cmd.Dir = cwd
		// Deduct compilation time from the runtime budget.
		if timeout > 0 {
			elapsed := time.Since(compileStart)
			timeout -= elapsed
			if timeout <= 0 {
				timeout = time.Nanosecond
			}
		}

	case "typescript":
		tsNodePathMu.Lock()
		exe := tsNodePath
		tsNodePathMu.Unlock()
		if exe == "" {
			exe = "ts-node"
		}
		cmd = exec.Command(exe, tmpPath)
		cmd.Dir = cwd

	case "go":
		cmd = exec.Command("go", "run", tmpPath)
		cmd.Dir = cwd

	default:
		cmd = exec.Command(rt.Exe, tmpPath)
		cmd.Dir = cwd
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if background {
		cleanups = append(cleanups, tmpPath)
	}
	// Prefer argv string for observability; falls back to language label.
	cmdStr := strings.Join(cmd.Args, " ")
	if cmdStr == "" {
		cmdStr = language
	}
	return runCmd(ctx, cmd, timeout, background, language, cmdStr, cleanups...)
}

// maxCmdOutput is the maximum number of bytes captured from a subprocess's
// stdout and stderr. If the subprocess produces more output, it is silently
// dropped to prevent OOM.
const maxCmdOutput = 10 * 1024 * 1024 // 10 MB

// limitedBuffer is an io.Writer that wraps bytes.Buffer and silently drops
// writes after the limit is reached. This prevents unbounded memory growth
// from misbehaving subprocesses.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	if lb.buf.Len() >= lb.limit {
		lb.truncated = true
		return len(p), nil
	}
	remaining := lb.limit - lb.buf.Len()
	if len(p) <= remaining {
		return lb.buf.Write(p)
	}
	lb.truncated = true
	_, _ = lb.buf.Write(p[:remaining])
	return len(p), nil
}

func (lb *limitedBuffer) String() string {
	return lb.buf.String()
}

// runCmd is the shared execution loop for all languages.
// It starts the process, optionally waits with a timeout, and returns
// the combined stdout/stderr and exit code.
func runCmd(ctx context.Context, cmd *exec.Cmd, timeout time.Duration, background bool, language, command string, cleanups ...string) (*executeResult, error) {
	var stdoutBuf, stderrBuf limitedBuffer
	stdoutBuf.limit = maxCmdOutput
	stderrBuf.limit = maxCmdOutput
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start process: %w", err)
	}

	if background {
		// Register for list/kill supervision; reap on exit; enforce max age.
		entry := registerBackground(cmd, language, command, cleanups)
		go func(id string, c *exec.Cmd) {
			err := c.Wait()
			exitCode := 0
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					exitCode = ee.ExitCode()
				} else {
					exitCode = -1
				}
			}
			finishBackground(id, exitCode)
		}(entry.ID, cmd)
		return &executeResult{
			Stdout: fmt.Sprintf("Process started in background (id: %s, PID: %d). Use ctx_background_list / ctx_background_kill. Max age %s.",
				entry.ID, cmd.Process.Pid, defaultBackgroundMaxAge),
			ExitCode: 0,
		}, nil
	}

	// Wait with timeout.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var timer *time.Timer
	if timeout > 0 {
		timer = time.NewTimer(timeout)
		defer timer.Stop()
	}

	truncated := false

	select {
	case <-timer.C:
		// Timeout: send SIGTERM first for graceful shutdown, then SIGKILL.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
				// Process exited gracefully after SIGTERM.
			case <-time.After(3 * time.Second):
				// Force-kill and drain to release pipe resources.
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
		}
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()
		if stderr == "" {
			stderr = fmt.Sprintf("Process timed out after %v", timeout)
		}
		truncated = stdoutBuf.truncated || stderrBuf.truncated
		return &executeResult{
			Stdout:    stdout,
			Stderr:    stderr,
			ExitCode:  -1,
			Truncated: truncated,
		}, nil

	case <-ctx.Done():
		// Context cancelled: same two-stage kill as timeout.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
		}
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()
		if stderr == "" {
			stderr = fmt.Sprintf("process cancelled: %v", ctx.Err())
		}
		truncated = stdoutBuf.truncated || stderrBuf.truncated
		return &executeResult{
			Stdout:    stdout,
			Stderr:    stderr,
			ExitCode:  -1,
			Truncated: truncated,
		}, nil

	case err := <-done:
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()

		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}

		truncated = stdoutBuf.truncated || stderrBuf.truncated
		return &executeResult{
			Stdout:    stdout,
			Stderr:    stderr,
			ExitCode:  exitCode,
			Truncated: truncated,
		}, nil
	}
}

// ---------- runtime listing ----------

// availableLanguages returns a list of languages whose runtimes are installed.
func availableLanguages() []string {
	var langs []string
	for name := range runtimes {
		if checkRuntime(name, false) {
			langs = append(langs, name)
		}
	}
	return langs
}

// ---------- FILE_CONTENT injection for ctx_execute_file (base64 fallback) ----------

// injectFileContentBase64 uses base64 encoding to safely inject arbitrary file
// content into any language. The user code must decode the variable.
func injectFileContentBase64(language, code, fileContent string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(fileContent))
	switch language {
	case "shell":
		return fmt.Sprintf(`FILE_CONTENT_B64='%s'
FILE_CONTENT=$(echo "$FILE_CONTENT_B64" | base64 -d)
%s`, encoded, code)
	case "javascript", "typescript":
		return fmt.Sprintf(`const FILE_CONTENT = Buffer.from("%s", "base64").toString();
%s`, encoded, code)
	case "python":
		return fmt.Sprintf(`import base64
FILE_CONTENT = base64.b64decode("%s").decode()
%s`, encoded, code)
	case "go":
		return fmt.Sprintf(`import "encoding/base64"
FILE_CONTENT_BYTES, _ := base64.StdEncoding.DecodeString("%s")
FILE_CONTENT := string(FILE_CONTENT_BYTES)
%s`, encoded, code)
	default:
		// For languages that don't have a native decode, inject the raw content
		// via string literal (limited to text content).
		return injectFileContent(language, code, fileContent)
	}
}
