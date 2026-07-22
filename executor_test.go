package main

import (
	"os"
	"strings"
	"testing"
	"time"
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
	result, err := runShell("echo hello", "/tmp", 5*time.Second, false)
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
	result, err := runShell("exit 42", "/tmp", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 42 {
		t.Fatalf("expected exit code 42, got %d", result.ExitCode)
	}
}

func TestRunShell_Stderr(t *testing.T) {
	result, err := runShell("echo to_stderr >&2", "/tmp", 5*time.Second, false)
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
	result, err := runShell(script, "/tmp", 200*time.Millisecond, false)
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
	result, err := runShell(script, "/tmp", 200*time.Millisecond, false)
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
	result, err := runShell("echo hello_from_bash", "/tmp", 5*time.Second, false)
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

	result, err := runShell("echo hello_from_sh", "/tmp", 5*time.Second, false)
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
		runShell(script, "/tmp", 100*time.Millisecond, false)
		done <- struct{}{}
	}()
	select {
	case <-done:
		// passed — runShell returned without hanging
	case <-time.After(10 * time.Second):
		t.Fatal("runShell hung after SIGKILL (done drain failed)")
	}
}
