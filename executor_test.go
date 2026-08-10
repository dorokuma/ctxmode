package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ============================================================================
// limitedBuffer 测试
// ============================================================================

func TestLimitedBuffer_WriteUnderLimit(t *testing.T) {
	lb := &limitedBuffer{limit: 100}
	data := []byte(strings.Repeat("a", 50))
	n, err := lb.Write(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 50 {
		t.Fatalf("Write: expected n=50, got %d", n)
	}
	if lb.String() != string(data) {
		t.Fatalf("String: expected %q, got %q", string(data), lb.String())
	}
}

func TestLimitedBuffer_WriteAtLimit(t *testing.T) {
	lb := &limitedBuffer{limit: 10}
	data := []byte(strings.Repeat("b", 10))
	n, err := lb.Write(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 10 {
		t.Fatalf("Write: expected n=10, got %d", n)
	}
	if lb.String() != string(data) {
		t.Fatalf("String: expected %q, got %q", string(data), lb.String())
	}
}

func TestLimitedBuffer_WriteOverLimit_SingleWrite(t *testing.T) {
	// 单次写入超过 limit：只保留 limit 字节，返回 len(p)。
	lb := &limitedBuffer{limit: 5}
	data := []byte("0123456789") // 10 bytes
	n, err := lb.Write(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 10 {
		t.Fatalf("Write: expected n=10 (len of input), got %d", n)
	}
	if lb.buf.Len() != 5 {
		t.Fatalf("buffer should be capped at 5, got %d", lb.buf.Len())
	}
	if lb.String() != "01234" {
		t.Fatalf("String: expected '01234', got %q", lb.String())
	}
}

func TestLimitedBuffer_WriteAfterLimitReached(t *testing.T) {
	// C4 OOM 保护：达到限制后再写入，buffer 不再增长。
	lb := &limitedBuffer{limit: 10}
	lb.Write([]byte(strings.Repeat("x", 15))) // over-fill
	if lb.buf.Len() != 10 {
		t.Fatalf("after first write: expected buf len 10, got %d", lb.buf.Len())
	}

	n, err := lb.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("Write: expected n=5 (len of input), got %d", n)
	}
	if lb.buf.Len() != 10 {
		t.Fatalf("buffer grew beyond limit after second write: %d", lb.buf.Len())
	}
}

func TestLimitedBuffer_WriteCrossesLimit_Partial(t *testing.T) {
	// 部分写入穿过 limit 边界：只写入剩余空间，返回完整 len(p)。
	lb := &limitedBuffer{limit: 8}
	lb.Write([]byte(strings.Repeat("a", 6))) // 6 bytes, 2 remaining
	n, err := lb.Write([]byte("bcdef"))      // 5 bytes, only 2 fit
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("Write: expected n=5, got %d", n)
	}
	s := lb.String()
	if len(s) != 8 {
		t.Fatalf("expected 8 bytes, got %d: %q", len(s), s)
	}
	if !strings.HasPrefix(s, "aaaaaa") {
		t.Fatalf("expected prefix 'aaaaaa', got %q", s)
	}
	if !strings.HasSuffix(s, "bc") {
		t.Fatalf("expected suffix 'bc', got %q", s)
	}
}

func TestLimitedBuffer_WriteReturnValue_AlwaysLenP(t *testing.T) {
	// Write 永远返回 len(p)，即使丢弃数据。
	lb := &limitedBuffer{limit: 1}
	data := []byte("abcde")
	n1, _ := lb.Write(data) // fills buffer
	n2, _ := lb.Write(data) // buffer already full
	if n1 != 5 {
		t.Fatalf("first Write: expected n=5, got %d", n1)
	}
	if n2 != 5 {
		t.Fatalf("second Write (at limit): expected n=5, got %d", n2)
	}
}

func TestLimitedBuffer_String(t *testing.T) {
	lb := &limitedBuffer{limit: 100}
	lb.Write([]byte("hello"))
	lb.Write([]byte(" "))
	lb.Write([]byte("world"))
	if lb.String() != "hello world" {
		t.Fatalf("expected 'hello world', got %q", lb.String())
	}
}

// ============================================================================
// runShell 测试 — 正常执行路径
// ============================================================================

func TestRunShell_NormalCompletion(t *testing.T) {
	result, err := runShell(context.Background(), "echo hello", "/tmp", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "hello") {
		t.Fatalf("expected stdout to contain 'hello', got %q", result.Stdout)
	}
}

func TestRunShell_NonZeroExit(t *testing.T) {
	result, err := runShell(context.Background(), "exit 42", "/tmp", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 42 {
		t.Fatalf("expected exit code 42, got %d", result.ExitCode)
	}
}

func TestRunShell_Stderr(t *testing.T) {
	result, err := runShell(context.Background(), "echo to_stderr >&2", "/tmp", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stderr, "to_stderr") {
		t.Fatalf("expected stderr to contain 'to_stderr', got %q", result.Stderr)
	}
}

// ============================================================================
// runShell 测试 — 超时 SIGTERM / SIGKILL 路径（S10 / S13）
// ============================================================================

func TestRunShell_TimeoutSIGTERM_GracefulExit(t *testing.T) {
	// S10: 子进程收到 SIGTERM 后优雅退出，runCmd 在 3s 内收到 done。
	script := `trap 'echo SIGTERM_RECEIVED; exit 0' TERM; sleep 60`
	result, err := runShell(context.Background(), script, "/tmp", 200*time.Millisecond, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != -1 {
		t.Fatalf("expected exit code -1 (timeout), got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "SIGTERM_RECEIVED") {
		t.Fatalf("expected stdout to contain 'SIGTERM_RECEIVED', got %q", result.Stdout)
	}
}

func TestRunShell_TimeoutSIGKILL_ForceKill(t *testing.T) {
	// S13: 子进程忽略 SIGTERM，runCmd 等 3s 后发送 SIGKILL 强杀。
	script := `trap '' TERM; sleep 60`
	start := time.Now()
	result, err := runShell(context.Background(), script, "/tmp", 200*time.Millisecond, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != -1 {
		t.Fatalf("expected exit code -1 (timeout), got %d", result.ExitCode)
	}
	// 必须等了至少 3 秒 (SIGTERM → 3s wait → SIGKILL)
	if elapsed < 3*time.Second {
		t.Fatalf("expected at least 3s elapsed for SIGKILL fallback, got %v", elapsed)
	}
}

// ============================================================================
// runShell 测试 — SHELL 环境变量拆分（S14）
// ============================================================================

func TestRunShell_SHELLWithArgs(t *testing.T) {
	// S14: SHELL="/bin/bash -l" → strings.Fields 拆分为 ["/bin/bash", "-l"]
	// 验证 bash -l 模式确实被执行（通过 BASH_VERSION 环境变量验证）。
	origShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", origShell)
	os.Setenv("SHELL", "/bin/bash -l")

	// bash -l 会设置一些 login shell 环境，echo 基本命令应正常执行
	result, err := runShell(context.Background(), "echo hello_from_bash", "/tmp", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, stderr=%q", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "hello_from_bash") {
		t.Fatalf("expected stdout to contain 'hello_from_bash', got %q", result.Stdout)
	}
}

func TestRunShell_EmptySHELL_FallbackSh(t *testing.T) {
	// S14 兜底: SHELL 为空时 fallback 到 "sh"
	origShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", origShell)
	os.Unsetenv("SHELL")

	result, err := runShell(context.Background(), "echo hello_from_sh", "/tmp", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}
	if !strings.Contains(result.Stdout, "hello_from_sh") {
		t.Fatalf("expected stdout to contain 'hello_from_sh', got %q", result.Stdout)
	}
}

// ============================================================================
// runCmd 测试 — done drain（SIGKILL 后清空 wait channel）
// ============================================================================

func TestRunShell_SIGKILLDoneDrain(t *testing.T) {
	// 验证 done channel 在 SIGKILL 后被正确 drain，runShell 不会 hang。
	// 这个测试被 TestRunShell_TimeoutSIGKILL_ForceKill 隐式覆盖（它能返回就说明 drain 成功）。
	// 这里再用一个独立的快速脚本做双重确认。
	script := `trap '' TERM; sleep 60`
	done := make(chan struct{}, 1)
	go func() {
		runShell(context.Background(), script, "/tmp", 100*time.Millisecond, false)
		done <- struct{}{}
	}()
	select {
	case <-done:
		// passed — runShell returned without hanging
	case <-time.After(10 * time.Second):
		t.Fatal("runShell hung after SIGKILL (done drain failed)")
	}
}

// ============================================================================
// background log / wait
// ============================================================================

func TestBackgroundLogAndWait(t *testing.T) {
	// Start a short-lived background job that prints then exits.
	result, err := runShell(context.Background(), "echo BG_HELLO_MARKER; echo BG_ERR_MARKER 1>&2; exit 7", "/tmp", 0, true)
	if err != nil {
		t.Fatalf("start background: %v", err)
	}
	if !strings.Contains(result.Stdout, "id:") {
		t.Fatalf("expected id in message: %q", result.Stdout)
	}
	// Parse id from "id: bg-N"
	id := ""
	for _, part := range strings.Split(result.Stdout, " ") {
		if strings.HasPrefix(part, "bg-") {
			id = strings.TrimSuffix(part, ",")
			id = strings.TrimSuffix(id, ".")
			break
		}
	}
	// More reliable: find in list
	if id == "" {
		for _, e := range listBackground() {
			if strings.Contains(e.Command, "BG_HELLO_MARKER") || strings.Contains(result.Stdout, e.ID) {
				id = e.ID
				break
			}
		}
	}
	if id == "" {
		// Fallback: extract with simple scan
		const p = "id: "
		if i := strings.Index(result.Stdout, p); i >= 0 {
			rest := result.Stdout[i+len(p):]
			for j, c := range rest {
				if c == ',' || c == ' ' || c == ')' {
					id = rest[:j]
					break
				}
			}
		}
	}
	if id == "" {
		t.Fatalf("could not parse background id from %q", result.Stdout)
	}

	s := &server{workdirs: []string{"/tmp"}}
	// Wait until done (should be quick).
	wres, _, err := s.toolBackgroundWait(context.Background(), nil, backgroundWaitArgs{
		ID:        id,
		TimeoutMs: 5000,
	})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	wtext := ""
	for _, c := range wres.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			wtext = tc.Text
			break
		}
	}
	if !strings.Contains(wtext, `"done": true`) {
		t.Fatalf("expected done=true: %s", wtext)
	}
	if !strings.Contains(wtext, "BG_HELLO_MARKER") {
		t.Fatalf("wait log should contain stdout marker: %s", wtext)
	}
	if !strings.Contains(wtext, "BG_ERR_MARKER") {
		t.Fatalf("wait log should contain stderr marker: %s", wtext)
	}
	// exit_code 7
	if !strings.Contains(wtext, `"exit_code": 7`) {
		t.Fatalf("expected exit_code 7: %s", wtext)
	}

	// Log tool should also return content after exit.
	lres, _, err := s.toolBackgroundLog(context.Background(), nil, backgroundLogArgs{
		ID:        id,
		TailLines: 50,
	})
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	ltext := ""
	for _, c := range lres.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			ltext = tc.Text
			break
		}
	}
	if !strings.Contains(ltext, "BG_HELLO_MARKER") {
		t.Fatalf("log should contain marker: %s", ltext)
	}

	// List should report log_available.
	listRes, _, err := s.toolBackgroundList(context.Background(), nil, backgroundListArgs{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	listText := ""
	for _, c := range listRes.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			listText = tc.Text
			break
		}
	}
	if !strings.Contains(listText, id) {
		t.Fatalf("list should include %s: %s", id, listText)
	}
	if !strings.Contains(listText, "log_available") {
		t.Fatalf("list should include log_available field: %s", listText)
	}
}

func TestBackgroundWait_TimeoutNoKill(t *testing.T) {
	result, err := runShell(context.Background(), "sleep 30", "/tmp", 0, true)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	id := ""
	const p = "id: "
	if i := strings.Index(result.Stdout, p); i >= 0 {
		rest := result.Stdout[i+len(p):]
		for j, c := range rest {
			if c == ',' || c == ' ' || c == ')' {
				id = rest[:j]
				break
			}
		}
	}
	if id == "" {
		t.Fatalf("no id in %q", result.Stdout)
	}
	defer killBackground(id)

	s := &server{workdirs: []string{"/tmp"}}
	wres, _, err := s.toolBackgroundWait(context.Background(), nil, backgroundWaitArgs{
		ID:        id,
		TimeoutMs: 200,
	})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	wtext := ""
	for _, c := range wres.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			wtext = tc.Text
			break
		}
	}
	if !strings.Contains(wtext, `"done": false`) {
		t.Fatalf("expected done=false on timeout: %s", wtext)
	}
	if !strings.Contains(wtext, `"timed_out": true`) {
		t.Fatalf("expected timed_out: %s", wtext)
	}
	// Process must still be running.
	entries := listBackground()
	found := false
	for _, e := range entries {
		if e.ID == id && !e.Done {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("process should still be live after wait timeout")
	}
}

// ============================================================================
// H1: background log tail seeks from end (no full-file ReadFile)
// ============================================================================

func TestReadBackgroundLogTail_TailBytesEndOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bg.log")
	// Build a multi-line file: head markers must not appear when tail_bytes is small.
	var b strings.Builder
	b.WriteString("HEAD_MARKER_SHOULD_NOT_APPEAR\n")
	for i := 0; i < 50; i++ {
		b.WriteString(strings.Repeat("x", 40) + "\n")
	}
	b.WriteString("TAIL_MARKER_VISIBLE\n")
	b.WriteString("END_LINE_ZZZ\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	// tail_bytes small enough that HEAD cannot fit.
	got, err := readBackgroundLogTail(path, 0, 80)
	if err != nil {
		t.Fatalf("readBackgroundLogTail: %v", err)
	}
	if strings.Contains(got, "HEAD_MARKER_SHOULD_NOT_APPEAR") {
		t.Fatalf("tail_bytes must not return head content: %q", got)
	}
	if !strings.Contains(got, "END_LINE_ZZZ") && !strings.Contains(got, "TAIL_MARKER") {
		t.Fatalf("expected tail content, got %q", got)
	}
	if len(got) > 80+10 { // allow newline drop of partial first line
		// After dropping partial first line, result may be slightly under 80.
		// It must never exceed the requested byte window by much more than one line.
	}
	// Strict: returned payload after seek window is at most tail_bytes.
	// (partial-line drop can only shrink it)
	if len(got) > 80 {
		t.Fatalf("result longer than tail_bytes=80: len=%d got=%q", len(got), got)
	}
}

func TestReadBackgroundLogTail_RejectsOversizedRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bg.log")
	if err := os.WriteFile(path, []byte("line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackgroundLogTail(path, maxBackgroundTailLines+1, 0); err == nil {
		t.Fatal("expected oversized tail_lines rejection")
	}
	if _, err := readBackgroundLogTail(path, 1, maxBackgroundTailBytes+1); err == nil {
		t.Fatal("expected oversized tail_bytes rejection")
	}
}

func TestReadBackgroundLogTail_TailLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lines.log")
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf("line-%02d", i))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readBackgroundLogTail(path, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "line-00") || strings.Contains(got, "line-01") {
		t.Fatalf("tail_lines=3 should not include early lines: %q", got)
	}
	if !strings.Contains(got, "line-19") || !strings.Contains(got, "line-17") {
		t.Fatalf("expected last 3 lines, got %q", got)
	}
}

func TestLimitedFileWriter_CapsAtLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cap.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := &limitedFileWriter{f: f, limit: 100}
	n, err := w.Write([]byte(strings.Repeat("a", 80)))
	if err != nil || n != 80 {
		t.Fatalf("first write: n=%d err=%v", n, err)
	}
	n, err = w.Write([]byte(strings.Repeat("b", 50))) // only 20 fit
	if err != nil || n != 50 {
		t.Fatalf("second write should accept full len: n=%d err=%v", n, err)
	}
	if !w.isTruncated() {
		t.Fatal("expected truncated=true")
	}
	// Further writes discarded.
	n, err = w.Write([]byte("ccccc"))
	if err != nil || n != 5 {
		t.Fatalf("third write: n=%d err=%v", n, err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 100 {
		t.Fatalf("file size should be capped at 100, got %d", st.Size())
	}
}

// M7: wait timeout_ms hard cap (1 hour)
func TestBackgroundWait_TimeoutMsCap(t *testing.T) {
	s := &server{workdirs: []string{"/tmp"}}
	_, _, err := s.toolBackgroundWait(context.Background(), nil, backgroundWaitArgs{
		ID:        "bg-nonexistent",
		TimeoutMs: maxBackgroundWaitMs + 1,
	})
	if err == nil {
		t.Fatal("expected error for timeout_ms > 1 hour")
	}
	if !strings.Contains(err.Error(), "1 hour") && !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected cap error, got: %v", err)
	}
}

// M5: kill marks Done but Wait closes log — log still readable after kill
func TestBackgroundKill_LogReadableAfterKill(t *testing.T) {
	// Long-running process that prints then sleeps; kill should preserve log tail.
	result, err := runShell(context.Background(),
		`echo KILL_LOG_MARKER; while true; do sleep 1; done`,
		"/tmp", 0, true)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	id := parseBgID(t, result.Stdout)
	// Give the process a moment to flush the marker.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entry := findBackground(id)
		if entry != nil && entry.LogPath != "" {
			if data, err := readBackgroundLogTail(entry.LogPath, 50, 0); err == nil && strings.Contains(data, "KILL_LOG_MARKER") {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	msg, err := killBackground(id)
	if err != nil {
		t.Fatalf("kill: %v", err)
	}
	if !strings.Contains(msg, "killed") {
		t.Fatalf("unexpected kill msg: %s", msg)
	}

	// Immediately after kill, log should still be readable (FD not closed prematurely
	// in a way that deletes content — file path remains until reaper).
	entry := findBackground(id)
	if entry == nil {
		t.Fatal("entry should still be in registry after kill")
	}
	if !entry.Done {
		t.Fatal("entry should be marked Done after kill")
	}
	// Wait briefly for Wait goroutine to finishBackground (close log).
	time.Sleep(200 * time.Millisecond)
	logText, err := readBackgroundLogTail(entry.LogPath, 50, 0)
	if err != nil {
		t.Fatalf("log after kill should be readable: %v", err)
	}
	if !strings.Contains(logText, "KILL_LOG_MARKER") {
		t.Fatalf("expected marker in log after kill: %q", logText)
	}
}

func parseBgID(t *testing.T, stdout string) string {
	t.Helper()
	const p = "id: "
	if i := strings.Index(stdout, p); i >= 0 {
		rest := stdout[i+len(p):]
		for j, c := range rest {
			if c == ',' || c == ' ' || c == ')' {
				return rest[:j]
			}
		}
	}
	t.Fatalf("no id in %q", stdout)
	return ""
}

// ============================================================================
// argv / env / stdin (P1)
// ============================================================================

func TestRunArgv_Echo(t *testing.T) {
	result, err := runArgv(context.Background(), []string{"echo", "hi"}, "/tmp", 5*time.Second, false, nil)
	if err != nil {
		t.Fatalf("runArgv: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit %d stderr=%q", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "hi") {
		t.Fatalf("expected hi in stdout, got %q", result.Stdout)
	}
}

func TestRunArgv_EmptyRejected(t *testing.T) {
	_, err := runArgv(context.Background(), nil, "/tmp", 5*time.Second, false, nil)
	if err == nil {
		t.Fatal("expected empty argv error")
	}
}

func TestFilterExecEnv_AllowAndDeny(t *testing.T) {
	ok, err := filterExecEnv(map[string]string{"GOOS": "linux", "NODE_ENV": "test", "CTXMODE_FOO": "1"})
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	if ok["GOOS"] != "linux" || ok["CTXMODE_FOO"] != "1" {
		t.Fatalf("unexpected filtered: %#v", ok)
	}
	_, err = filterExecEnv(map[string]string{"LD_PRELOAD": "/evil.so"})
	if err == nil {
		t.Fatal("expected LD_PRELOAD rejected")
	}
	_, err = filterExecEnv(map[string]string{"PATH": "/evil"})
	if err == nil {
		t.Fatal("expected PATH rejected")
	}
	_, err = filterExecEnv(map[string]string{"UNKNOWN_KEY": "x"})
	if err == nil {
		t.Fatal("expected unknown key rejected")
	}
}

func TestRunArgv_EnvAllowlist(t *testing.T) {
	opts := &runOptions{Env: map[string]string{"NODE_ENV": "production"}}
	// printenv should see NODE_ENV when allowlisted env is applied.
	result, err := runArgv(context.Background(), []string{"printenv", "NODE_ENV"}, "/tmp", 5*time.Second, false, opts)
	if err != nil {
		t.Fatalf("runArgv env: %v", err)
	}
	if !strings.Contains(result.Stdout, "production") {
		t.Fatalf("expected NODE_ENV=production, got stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
}

func TestRunArgv_StdinCat(t *testing.T) {
	opts := &runOptions{Stdin: "hello-stdin\n"}
	result, err := runArgv(context.Background(), []string{"cat"}, "/tmp", 5*time.Second, false, opts)
	if err != nil {
		t.Fatalf("runArgv stdin: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit %d stderr=%q", result.ExitCode, result.Stderr)
	}
	if !strings.Contains(result.Stdout, "hello-stdin") {
		t.Fatalf("expected stdin echo, got %q", result.Stdout)
	}
}

func TestToolExecute_ArgvEnvStdin(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)

	// argv mode
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv: []string{"echo", "hi"},
	})
	if err != nil {
		t.Fatalf("argv execute: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res), "hi") {
		t.Fatalf("expected hi: %s", mcpResultText(t, res))
	}

	// env deny
	_, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Argv: []string{"echo", "x"},
		Env:  map[string]string{"LD_PRELOAD": "/tmp/x"},
	})
	if err == nil || !strings.Contains(err.Error(), "LD_PRELOAD") {
		t.Fatalf("expected LD_PRELOAD error, got %v", err)
	}

	// stdin via cat
	res3, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  []string{"cat"},
		Stdin: "from-stdin",
	})
	if err != nil {
		t.Fatalf("stdin execute: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res3), "from-stdin") {
		t.Fatalf("expected from-stdin: %s", mcpResultText(t, res3))
	}

	// shell mode still works
	res4, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command: "echo shell-ok",
	})
	if err != nil {
		t.Fatalf("shell execute: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res4), "shell-ok") {
		t.Fatalf("expected shell-ok: %s", mcpResultText(t, res4))
	}
}

func TestValidateArgv(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	// simple name ok
	got, err := s.validateArgv([]string{"echo", "a"}, wd)
	if err != nil || got[0] != "echo" {
		t.Fatalf("simple: got=%v err=%v", got, err)
	}
	// empty rejected
	if _, err := s.validateArgv(nil, wd); err == nil {
		t.Fatal("empty argv")
	}
	// outside path rejected
	if _, err := s.validateArgv([]string{"/etc/passwd"}, wd); err == nil {
		t.Fatal("expected outside path rejected")
	}
	// workdir-relative path ok
	tool := filepath.Join(wd, "mytool")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho ok\n"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err = s.validateArgv([]string{tool}, wd)
	if err != nil {
		t.Fatalf("workdir path: %v", err)
	}
	if got[0] != tool && !strings.HasPrefix(got[0], wd) {
		t.Fatalf("expected resolved under wd, got %q", got[0])
	}

	// Relative executable paths resolve from the requested cwd, including a
	// secondary configured workdir.
	wd2 := t.TempDir()
	s.workdirs = []string{wd, wd2}
	tool2 := filepath.Join(wd2, "tool2")
	if err := os.WriteFile(tool2, []byte("#!/bin/sh\necho ok\n"), 0755); err != nil {
		t.Fatal(err)
	}
	got, err = s.validateArgv([]string{"./tool2"}, wd2)
	if err != nil {
		t.Fatalf("secondary-workdir relative path: %v", err)
	}
	if got[0] != tool2 {
		t.Fatalf("got %q want %q", got[0], tool2)
	}
}

// M1: stdin larger than 1 MiB must be rejected at toolExecute.
func TestToolExecute_StdinTooLarge(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	huge := strings.Repeat("x", maxStdinBytes+1)
	_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  []string{"cat"},
		Stdin: huge,
	})
	if err == nil {
		t.Fatal("expected stdin > 1MB to be rejected")
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "stdin") || (!strings.Contains(low, "maximum") && !strings.Contains(low, "max")) {
		t.Fatalf("expected stdin max-size error, got: %v", err)
	}
	// Exactly max bytes is accepted (size check is strict >).
	// Use a no-output command so auto-index is not triggered on a nil store.
	exact := strings.Repeat("y", maxStdinBytes)
	_, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  []string{"true"},
		Stdin: exact,
	})
	if err != nil {
		t.Fatalf("stdin == maxStdinBytes should be allowed: %v", err)
	}
}

// M1: background + argv starts and background_log shows output.
func TestToolExecute_BackgroundArgvLog(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)

	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv:       []string{"sh", "-c", "echo BG_ARGV_MARKER; sleep 0.2"},
		Background: true,
	})
	if err != nil {
		t.Fatalf("background argv execute: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "id:") && !strings.Contains(text, "bg-") {
		t.Fatalf("expected background id in start message: %q", text)
	}
	id := parseBgID(t, text)
	defer killBackground(id)

	// Wait briefly for output to be teed, then read log.
	deadline := time.Now().Add(5 * time.Second)
	var logText string
	for time.Now().Before(deadline) {
		lres, _, lerr := s.toolBackgroundLog(context.Background(), nil, backgroundLogArgs{
			ID:        id,
			TailLines: 50,
		})
		if lerr == nil {
			logText = mcpResultText(t, lres)
			if strings.Contains(logText, "BG_ARGV_MARKER") {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("background_log did not show BG_ARGV_MARKER within timeout; last log=%q", logText)
}

// ============================================================================
// env merge: true override, no duplicate keys (fix #1)
// ============================================================================

func TestChildEnv_OverrideReplacesHostValue(t *testing.T) {
	old := os.Getenv("TZ")
	defer os.Setenv("TZ", old)
	os.Setenv("TZ", "Host/Zone")

	flat := flattenEnv(childEnv(map[string]string{"TZ": "Injected/Zone"}))
	tzCount := 0
	for _, kv := range flat {
		if strings.HasPrefix(kv, "TZ=") {
			tzCount++
			if kv != "TZ=Injected/Zone" {
				t.Fatalf("TZ must be the injected value, got %q", kv)
			}
		}
	}
	if tzCount != 1 {
		t.Fatalf("expected exactly one TZ entry (no duplicate), got %d in %v", tzCount, flat)
	}
}

func TestApplyRunOptions_EnvOverrideWins(t *testing.T) {
	old := os.Getenv("TZ")
	defer os.Setenv("TZ", old)
	os.Setenv("TZ", "Host/Zone")

	opts := &runOptions{Env: map[string]string{"TZ": "Injected/Zone"}}
	result, err := runShellOpts(context.Background(), `echo "TZ=$TZ"`, "/tmp", 5*time.Second, false, opts)
	if err != nil {
		t.Fatalf("runShellOpts: %v", err)
	}
	if !strings.Contains(result.Stdout, "TZ=Injected/Zone") {
		t.Fatalf("child must see the injected TZ even though the host has the same key: stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
	if strings.Contains(result.Stdout, "Host/Zone") {
		t.Fatalf("host TZ leaked into the child: %q", result.Stdout)
	}
}

// ============================================================================
// secret env stripping (fix #2)
// ============================================================================

func TestChildEnv_StripsSensitiveKeys(t *testing.T) {
	for _, kv := range []string{
		"API_KEY=sk-123", "GITHUB_TOKEN=tok", "DB_PASSWORD=pw", "PASSWD=x",
		"AUTH_TOKEN=at", "COOKIE=c1", "SESSION_ID=s1", "CREDENTIAL_FILE=cf",
	} {
		k, v, _ := strings.Cut(kv, "=")
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}
	os.Setenv("CTXMODE_TEST_PLAIN_VAR", "visible")
	defer os.Unsetenv("CTXMODE_TEST_PLAIN_VAR")

	env := childEnv(nil)
	for _, k := range []string{"API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "PASSWD", "AUTH_TOKEN", "COOKIE", "SESSION_ID", "CREDENTIAL_FILE"} {
		if _, ok := env[k]; ok {
			t.Fatalf("sensitive key %s must be stripped from child env", k)
		}
	}
	if env["CTXMODE_TEST_PLAIN_VAR"] != "visible" {
		t.Fatal("non-sensitive keys must still be inherited")
	}
	if env["PATH"] == "" {
		t.Fatal("PATH must still be inherited")
	}
}

func TestChildEnv_KeepsExplicitAndAllowlistedKeys(t *testing.T) {
	// Caller-passed keys always survive, even when the key name is sensitive.
	env := childEnv(map[string]string{"API_KEY": "explicit"})
	if env["API_KEY"] != "explicit" {
		t.Fatalf("caller-passed sensitive key must be kept, got %q", env["API_KEY"])
	}

	// Allowlisted keys survive stripping even when the name matches a pattern.
	envAllowlist["TEST_KEY_ALLOWED_SENSITIVE"] = true
	defer delete(envAllowlist, "TEST_KEY_ALLOWED_SENSITIVE")
	os.Setenv("TEST_KEY_ALLOWED_SENSITIVE", "keepme")
	defer os.Unsetenv("TEST_KEY_ALLOWED_SENSITIVE")
	env = childEnv(nil)
	if env["TEST_KEY_ALLOWED_SENSITIVE"] != "keepme" {
		t.Fatal("allowlisted key must survive secret stripping")
	}
}

func TestChildEnv_PassthroughDisablesStripping(t *testing.T) {
	os.Setenv("API_KEY", "sk-passthrough")
	defer os.Unsetenv("API_KEY")
	old := os.Getenv("CTXMODE_ENV_PASSTHROUGH")
	defer os.Setenv("CTXMODE_ENV_PASSTHROUGH", old)
	os.Setenv("CTXMODE_ENV_PASSTHROUGH", "1")

	env := childEnv(nil)
	if env["API_KEY"] != "sk-passthrough" {
		t.Fatal("CTXMODE_ENV_PASSTHROUGH=1 must disable secret stripping")
	}
}

func TestRunShell_ChildEnvStripsSecrets(t *testing.T) {
	os.Setenv("API_KEY", "hunter2topsecret")
	defer os.Unsetenv("API_KEY")

	result, err := runShell(context.Background(),
		`if env | grep -q '^API_KEY='; then echo HAS_API_KEY; else echo NO_API_KEY; fi; echo "key=[$API_KEY]"`,
		"/tmp", 5*time.Second, false)
	if err != nil {
		t.Fatalf("runShell: %v", err)
	}
	if strings.Contains(result.Stdout, "HAS_API_KEY") || strings.Contains(result.Stdout, "hunter2topsecret") {
		t.Fatalf("secret leaked into the child environment: %q", result.Stdout)
	}
	if !strings.Contains(result.Stdout, "NO_API_KEY") || !strings.Contains(result.Stdout, "key=[]") {
		t.Fatalf("expected stripped child env, got %q", result.Stdout)
	}
}

// ============================================================================
// UTF-8 boundary handling (fixes #3/#4/#5)
// ============================================================================

func TestLimitedBuffer_DoesNotSplitUTF8(t *testing.T) {
	lb := &limitedBuffer{limit: 3}
	if _, err := lb.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	// "é" is 2 bytes; only 1 of the 4 input bytes fits, landing inside the rune.
	n, err := lb.Write([]byte("écd"))
	if err != nil || n != 4 {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	if !lb.truncated {
		t.Fatal("expected truncated")
	}
	if got := lb.String(); got != "ab" {
		t.Fatalf("buffer must not contain a split rune, got %q", got)
	}
}

func TestLimitedBuffer_MultiByteRuneFitsExactly(t *testing.T) {
	lb := &limitedBuffer{limit: 3}
	if _, err := lb.Write([]byte("a")); err != nil {
		t.Fatal(err)
	}
	// é (2 bytes) fits exactly in the remaining 2 bytes: no split, no truncate.
	if _, err := lb.Write([]byte("é")); err != nil {
		t.Fatal(err)
	}
	if got := lb.String(); got != "aé" {
		t.Fatalf("expected 'aé', got %q", got)
	}
	if lb.truncated {
		t.Fatal("exact fit must not be flagged truncated")
	}
}

func TestLimitedFileWriter_DoesNotSplitUTF8(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "w.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := &limitedFileWriter{f: f, limit: 3}
	if _, err := w.Write([]byte("ab")); err != nil {
		t.Fatal(err)
	}
	n, err := w.Write([]byte("écd")) // only 1 byte fits — inside the 2-byte é
	if err != nil || n != 4 {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	if !w.isTruncated() {
		t.Fatal("expected truncated")
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 2 {
		t.Fatalf("file must not contain a split rune: size=%d (want 2)", st.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ab" {
		t.Fatalf("file content must be exactly 'ab', got %q", string(data))
	}
}

func TestReadBackgroundLogTail_HeadUTF8Boundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "utf8.log")
	// A single 200-byte line of é (no newline): any byte offset can land
	// mid-rune and there is no '\n' to realign the head.
	if err := os.WriteFile(path, []byte(strings.Repeat("é", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readBackgroundLogTail(path, 0, 9)
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("expected non-empty tail")
	}
	if !utf8.ValidString(got) {
		t.Fatalf("tail must be valid UTF-8, got %q", got)
	}
	if !strings.HasPrefix(got, "é") {
		t.Fatalf("head must start on a rune boundary, got %q", got)
	}
	if len(got) > 9 {
		t.Fatalf("tail longer than the requested window: %d", len(got))
	}
}

func TestReadBackgroundLogTail_TrailingPartialRune(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.log")
	// File ends mid-rune (process killed mid-write): 中 = E4 B8 AD, only the
	// first two bytes were flushed.
	if err := os.WriteFile(path, []byte("hello\xE4\xB8"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readBackgroundLogTail(path, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("expected trailing partial rune dropped, got %q", got)
	}
}

func TestRegisterBackground_CommandTruncatedAtUTF8Boundary(t *testing.T) {
	// 99 é (198 bytes) + "é x" (4 bytes) = 202 bytes; a 200-byte cut lands
	// inside the last é.
	cmdStr := strings.Repeat("é", 99) + "é x"
	if len(cmdStr) <= 200 {
		t.Fatalf("test setup: command must exceed 200 bytes, got %d", len(cmdStr))
	}
	result, err := runShell(context.Background(), cmdStr, "/tmp", 0, true)
	if err != nil {
		t.Fatalf("start background: %v", err)
	}
	id := parseBgID(t, result.Stdout)
	defer killBackground(id)

	entry := findBackground(id)
	if entry == nil {
		t.Fatal("entry not found")
	}
	if !utf8.ValidString(entry.Command) {
		t.Fatalf("truncated command must be valid UTF-8, got %q", entry.Command)
	}
	if len(entry.Command) > 203 {
		t.Fatalf("command too long after truncation: %d", len(entry.Command))
	}
}

// ============================================================================
// background timeout + concurrency cap (fix #6)
// ============================================================================

func TestBackground_CallerTimeoutStopsJob(t *testing.T) {
	result, err := runShell(context.Background(), "sleep 30", "/tmp", 300*time.Millisecond, true)
	if err != nil {
		t.Fatalf("start background: %v", err)
	}
	if !strings.Contains(result.Stdout, "Max age 300ms.") {
		t.Fatalf("start message should reflect the caller timeout, got: %q", result.Stdout)
	}
	id := parseBgID(t, result.Stdout)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entry := findBackground(id)
		if entry != nil && entry.Done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	entry := findBackground(id)
	if entry == nil {
		t.Fatalf("entry %s disappeared", id)
	}
	if !entry.Done {
		t.Fatal("background job must be stopped by the caller-provided timeout")
	}
	// The underlying process must actually be gone.
	if entry.PID > 0 {
		deadline = time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if procStartTime(entry.PID) == 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if procStartTime(entry.PID) != 0 {
			t.Fatalf("background process %d still alive after timeout stop", entry.PID)
		}
	}
}

func TestBackground_CapRejectsOverflow(t *testing.T) {
	// Clean slate: kill any leftover live jobs from earlier tests.
	bgMu.Lock()
	var live []string
	for id, e := range bgProcs {
		if !e.Done {
			live = append(live, id)
		}
	}
	bgMu.Unlock()
	for _, id := range live {
		_, _ = killBackground(id)
	}

	started := make([]string, 0, maxBackgroundProcs)
	defer func() {
		for _, id := range started {
			_, _ = killBackground(id)
		}
	}()
	for i := 0; i < maxBackgroundProcs; i++ {
		res, err := runShell(context.Background(), "sleep 60", "/tmp", 0, true)
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		started = append(started, parseBgID(t, res.Stdout))
	}
	// The (cap+1)-th launch must be rejected, not queued.
	_, err := runShell(context.Background(), "sleep 60", "/tmp", 0, true)
	if err == nil {
		t.Fatal("expected cap rejection error")
	}
	if !strings.Contains(err.Error(), "too many") {
		t.Fatalf("expected cap error mentioning the limit, got: %v", err)
	}
}

// ============================================================================
// killBackground PID-reuse guard (fix #7)
// ============================================================================

func TestProcStartTime_ReadsOwnPID(t *testing.T) {
	st := procStartTime(os.Getpid())
	if st == 0 {
		t.Fatal("expected non-zero starttime for the test process")
	}
}

func TestKillBackground_RefusesIdentityMismatch(t *testing.T) {
	result, err := runShell(context.Background(), "sleep 30", "/tmp", 0, true)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	id := parseBgID(t, result.Stdout)

	bgMu.Lock()
	e := bgProcs[id]
	real := e.starttime
	if real == 0 {
		bgMu.Unlock()
		t.Fatal("expected a recorded starttime")
	}
	e.starttime = real + 1 // simulate PID reuse: stale recorded identity
	bgMu.Unlock()
	defer func() {
		bgMu.Lock()
		if e2 := bgProcs[id]; e2 != nil {
			e2.starttime = real
		}
		bgMu.Unlock()
		_, _ = killBackground(id)
	}()

	msg, err := killBackground(id)
	if err == nil {
		t.Fatalf("expected refusal on identity mismatch, got msg %q", msg)
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Fatalf("expected identity-mismatch error, got: %v", err)
	}
	// The process must be untouched.
	e2 := findBackground(id)
	if e2 == nil || e2.Done {
		t.Fatal("process must not be killed when identity does not match")
	}
	// Restore the real identity: the kill now succeeds.
	bgMu.Lock()
	if e3 := bgProcs[id]; e3 != nil {
		e3.starttime = real
	}
	bgMu.Unlock()
	msg, err = killBackground(id)
	if err != nil {
		t.Fatalf("kill after identity restore: %v", err)
	}
	if !strings.Contains(msg, "killed") {
		t.Fatalf("expected killed message, got %q", msg)
	}
}

// ============================================================================
// runCmd without timeout (fix #8)
// ============================================================================

func TestRunCmd_ZeroTimeoutNoPanic(t *testing.T) {
	cmd := exec.Command("echo", "no-timeout-ok")
	cmd.Dir = "/tmp"
	res, err := runCmd(context.Background(), cmd, 0, false, "argv", "echo no-timeout-ok")
	if err != nil {
		t.Fatalf("runCmd: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "no-timeout-ok") {
		t.Fatalf("unexpected result: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

func TestRunCmd_NegativeTimeoutNoPanic(t *testing.T) {
	cmd := exec.Command("echo", "neg-timeout-ok")
	cmd.Dir = "/tmp"
	res, err := runCmd(context.Background(), cmd, -5*time.Second, false, "argv", "echo neg-timeout-ok")
	if err != nil {
		t.Fatalf("runCmd: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "neg-timeout-ok") {
		t.Fatalf("unexpected result: exit=%d stdout=%q stderr=%q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

// ============================================================================
// tool-name messaging (fix #9)
// ============================================================================

func TestBackground_StartMessageMentionsCtxBg(t *testing.T) {
	result, err := runShell(context.Background(), "sleep 30", "/tmp", 0, true)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	id := parseBgID(t, result.Stdout)
	defer killBackground(id)
	if !strings.Contains(result.Stdout, "ctx_bg action=list|kill|log|wait") {
		t.Fatalf("start message must reference ctx_bg action=list|kill|log|wait, got: %q", result.Stdout)
	}
}
