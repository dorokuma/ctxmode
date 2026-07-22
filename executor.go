package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// init cleans up stale temp files from previous runs that may have been
// killed (e.g., SIGKILL) before their deferred cleanup could execute.
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
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > 24*time.Hour {
			os.Remove(filepath.Join(os.TempDir(), name))
		}
	}
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

// goWrapper wraps user code into a complete main package.
func goWrapper(code string) string {
	return `package main

import "fmt"

func main() {
` + code + `
}
`
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
	if exec.Command("npm", "ls", "ts-node", "--depth=0").Run() == nil {
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
		// Triple-quoted raw string. Raw strings cannot escape triple
		// quotes, and a trailing quote would prematurely close the literal.
		// Fall back to base64 if content contains """ or ends with a quote.
		if strings.Contains(fileContent, `"""`) || strings.HasSuffix(fileContent, `"`) {
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
func runCode(language, code, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
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
		return runShell(wrapped, cwd, timeout, background)
	}

	// Create a temp file with the appropriate extension.
	tmpFile, err := os.CreateTemp("", "ctxmode_*"+rt.Ext)
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
	return runCompiled(language, rt, tmpPath, cwd, timeout, background)
}

// runShell executes code directly via "sh -c".
func runShell(code, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
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

	return runCmd(cmd, timeout, background)
}

// runCompiled executes a language that uses a temp source file.
func runCompiled(language string, rt runtimeConfig, tmpPath, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
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

		compileCtx := context.Background()
		if timeout > 0 {
			var cancel context.CancelFunc
			compileCtx, cancel = context.WithTimeout(compileCtx, timeout)
			defer cancel()
		}
		compileCmd := exec.CommandContext(compileCtx, "rustc", "-o", outPath, tmpPath)
		compileCmd.Dir = cwd
		if compileOutput, err := compileCmd.CombinedOutput(); err != nil {
			return &executeResult{
				Stdout:   string(compileOutput),
				Stderr:   fmt.Sprintf("compilation failed: %v", err),
				ExitCode: -1,
			}, nil
		}
		cmd = exec.Command(outPath)
		cmd.Dir = cwd

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
	return runCmd(cmd, timeout, background, cleanups...)
}

// maxCmdOutput is the maximum number of bytes captured from a subprocess's
// stdout and stderr. If the subprocess produces more output, it is silently
// dropped to prevent OOM.
const maxCmdOutput = 10 * 1024 * 1024 // 10 MB

// limitedBuffer is an io.Writer that wraps bytes.Buffer and silently drops
// writes after the limit is reached. This prevents unbounded memory growth
// from misbehaving subprocesses.
type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	if lb.buf.Len() >= lb.limit {
		return len(p), nil
	}
	remaining := lb.limit - lb.buf.Len()
	if len(p) <= remaining {
		return lb.buf.Write(p)
	}
	_, _ = lb.buf.Write(p[:remaining])
	return len(p), nil
}

func (lb *limitedBuffer) String() string {
	return lb.buf.String()
}

// runCmd is the shared execution loop for all languages.
// It starts the process, optionally waits with a timeout, and returns
// the combined stdout/stderr and exit code.
func runCmd(cmd *exec.Cmd, timeout time.Duration, background bool, cleanups ...string) (*executeResult, error) {
	var stdoutBuf, stderrBuf limitedBuffer
	stdoutBuf.limit = maxCmdOutput
	stderrBuf.limit = maxCmdOutput
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start process: %w", err)
	}

	if background {
		// Detach: let the process continue running independently.
		// We reap it in a goroutine to avoid zombie processes, and
		// clean up temp files after the process exits.
		go func() {
			_ = cmd.Wait()
			for _, p := range cleanups {
				os.Remove(p)
			}
		}()
		return &executeResult{
			Stdout:   fmt.Sprintf("Process started in background (PID: %d)", cmd.Process.Pid),
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
		return &executeResult{
			Stdout:   stdout,
			Stderr:   stderr,
			ExitCode: -1,
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

		return &executeResult{
			Stdout:   stdout,
			Stderr:   stderr,
			ExitCode: exitCode,
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
