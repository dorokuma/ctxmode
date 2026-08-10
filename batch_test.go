package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// executeCommand 测试 — 正常路径
// ============================================================================

func TestExecuteCommand_Normal(t *testing.T) {
	s := &server{}
	ctx := context.Background()
	out, exitCode, err := s.executeCommand(ctx, "echo hello_batch", "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(out, "hello_batch") {
		t.Fatalf("expected output to contain 'hello_batch', got %q", out)
	}
}

func TestExecuteCommand_NonZeroExit(t *testing.T) {
	s := &server{}
	ctx := context.Background()
	_, exitCode, err := s.executeCommand(ctx, "exit 7", "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 7 {
		t.Fatalf("expected exit code 7, got %d", exitCode)
	}
}

func TestExecuteCommand_Stderr(t *testing.T) {
	s := &server{}
	ctx := context.Background()
	out, exitCode, err := s.executeCommand(ctx, "echo to_stderr >&2", "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(out, "to_stderr") {
		t.Fatalf("expected output to contain 'to_stderr', got %q", out)
	}
}

func TestExecuteCommand_WorkingDirectory(t *testing.T) {
	s := &server{}
	ctx := context.Background()
	out, exitCode, err := s.executeCommand(ctx, "pwd", "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(out, "/tmp") {
		t.Fatalf("expected output to contain '/tmp', got %q", out)
	}
}

// ============================================================================
// executeCommand 测试 — context 取消 / SIGKILL
// ============================================================================

func TestExecuteCommand_ContextCancellation(t *testing.T) {
	s := &server{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, exitCode, err := s.executeCommand(ctx, "sleep 60", "/tmp")
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
	if exitCode != -1 {
		t.Fatalf("expected exit code -1, got %d", exitCode)
	}
	if !strings.Contains(err.Error(), "cancelled") && !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("expected cancellation/deadline error, got %v", err)
	}
}

func TestExecuteCommand_ContextCancelled(t *testing.T) {
	// 用 cancel() 主动取消（非 timeout 路径）。
	s := &server{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		_, _, _ = s.executeCommand(ctx, "sleep 60", "/tmp")
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// passed
	case <-time.After(5 * time.Second):
		t.Fatal("executeCommand hung after context cancel")
	}
}

// ============================================================================
// executeCommand 测试 — SHELL 环境变量
// ============================================================================

func TestExecuteCommand_WithSHELLEnv(t *testing.T) {
	origShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", origShell)
	os.Setenv("SHELL", "/bin/bash")

	// executeCommand 使用 strings.Fields 拆分 SHELL，支持带参数。
	// 不带参数时也能正常工作。
	s := &server{}
	ctx := context.Background()
	out, exitCode, err := s.executeCommand(ctx, "echo from_bash", "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, output=%q", exitCode, out)
	}
	if !strings.Contains(out, "from_bash") {
		t.Fatalf("expected output to contain 'from_bash', got %q", out)
	}
}

func TestExecuteCommand_SHELLWithArgs(t *testing.T) {
	// S14: verify that SHELL with extra arguments (e.g. "/bin/sh -e") is
	// correctly split via strings.Fields instead of treating the whole string
	// as an executable name.
	origShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", origShell)
	os.Setenv("SHELL", "/bin/sh -e")

	s := &server{}
	ctx := context.Background()
	out, exitCode, err := s.executeCommand(ctx, "echo shell_split_ok", "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d, output=%q", exitCode, out)
	}
	if !strings.Contains(out, "shell_split_ok") {
		t.Fatalf("expected output to contain 'shell_split_ok', got %q", out)
	}
}

func TestExecuteCommand_EmptySHELL_FallbackSh(t *testing.T) {
	origShell := os.Getenv("SHELL")
	defer os.Setenv("SHELL", origShell)
	os.Unsetenv("SHELL")

	s := &server{}
	ctx := context.Background()
	out, exitCode, err := s.executeCommand(ctx, "echo from_sh", "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(out, "from_sh") {
		t.Fatalf("expected output to contain 'from_sh', got %q", out)
	}
}

// ============================================================================
// executeCommand 测试 — limitedBuffer 集成（batch 路径用 limitedBuffer）
// ============================================================================

func TestExecuteCommand_OutputUsesLimitedBuffer(t *testing.T) {
	// 验证 executeCommand 内部使用 limitedBuffer：
	// 大输出应被截断且不会导致 panic/OOM。
	s := &server{}
	ctx := context.Background()
	// 生成超过 maxCmdOutput 的输出（通过大量 echo）
	// 但我们不真测 10MB，用已知受限的 small 测试即可——
	// limitedBuffer 的单元测试在 executor_test.go 已覆盖。
	out, exitCode, err := s.executeCommand(ctx, "printf '%-1000000s' x", "/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	// 输出应该被 limitedBuffer 截断到 maxCmdOutput (10MB)
	if len(out) > maxCmdOutput+1024 {
		t.Fatalf("output not capped: len=%d, maxCmdOutput=%d", len(out), maxCmdOutput)
	}
	t.Logf("output length: %d (maxCmdOutput: %d)", len(out), maxCmdOutput)
}

// ============================================================================
// executeCommand 测试 — S13 两段式 kill（SIGTERM → 3s → SIGKILL）
// ============================================================================

func TestExecuteCommand_CancellationSIGTERM_GracefulExit(t *testing.T) {
	// S13: 子进程收到 SIGTERM 后优雅退出。
	s := &server{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	script := `trap 'echo SIGTERM_RECEIVED; exit 0' TERM; sleep 60`
	out, exitCode, err := s.executeCommand(ctx, script, "/tmp")
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
	if exitCode != -1 {
		t.Fatalf("expected exit code -1, got %d", exitCode)
	}
	if !strings.Contains(out, "SIGTERM_RECEIVED") {
		t.Fatalf("expected stdout to contain 'SIGTERM_RECEIVED', got %q", out)
	}
}

func TestExecuteCommand_CancellationSIGKILL_ForceKill(t *testing.T) {
	// S13: 子进程忽略 SIGTERM，等 3s 后 SIGKILL 强杀。
	s := &server{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	script := `trap '' TERM; sleep 60`
	start := time.Now()
	_, exitCode, err := s.executeCommand(ctx, script, "/tmp")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}
	if exitCode != -1 {
		t.Fatalf("expected exit code -1, got %d", exitCode)
	}
	// 必须等了至少 3 秒 (SIGTERM → 3s wait → SIGKILL)
	if elapsed < 3*time.Second {
		t.Fatalf("expected at least 3s elapsed for SIGKILL fallback, got %v", elapsed)
	}
}

// ============================================================================
// batch auto-index threshold（与 execute 路径一致的 100KB 门槛）
// ============================================================================

// TestBatchExecute_LargeOutputIndexedSmallNot verifies that batch output is
// auto-indexed ONLY when it exceeds the 100KB threshold (same as the execute
// path); small output must NOT be persisted, and the response must flag which
// entries were indexed.
func TestBatchExecute_LargeOutputIndexedSmallNot(t *testing.T) {
	srv := newTestServer(t)
	srv.workdirs = []string{t.TempDir()}

	res, _, err := srv.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "big", Command: "head -c 102500 /dev/zero | tr '\\0' 'a'"},
			{Label: "small", Command: "echo tiny_batch_output"},
		},
	})
	if err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	text := contentText(res)
	var resp batchResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, text)
	}
	if resp.Indexed != 1 {
		t.Fatalf("expected indexed=1 (only big), got %d\n%s", resp.Indexed, text)
	}

	byLabel := map[string]batchResult{}
	for _, r := range resp.Commands {
		byLabel[r.Label] = r
	}
	big, ok := byLabel["big"]
	if !ok {
		t.Fatalf("missing big entry: %s", text)
	}
	if !big.Indexed {
		t.Fatalf("big output should be indexed: %+v", big)
	}
	if !big.Truncated {
		t.Fatalf("big output should be truncated in response: %+v", big)
	}
	small, ok := byLabel["small"]
	if !ok {
		t.Fatalf("missing small entry: %s", text)
	}
	if small.Indexed {
		t.Fatalf("small output must NOT be indexed: %+v", small)
	}

	// Store must contain batch:big but not batch:small.
	if doc, _ := srv.store.Get(batchIndexPrefix + "big"); doc == nil {
		t.Fatal("batch:big should be present in store")
	}
	if doc, _ := srv.store.Get(batchIndexPrefix + "small"); doc != nil {
		t.Fatal("batch:small must NOT be persisted (no-size-threshold indexing removed)")
	}
}

// TestBatchExecute_ConcurrentIndexesLargeOutput verifies the concurrent path
// applies the same threshold and flags indexed entries.
func TestBatchExecute_ConcurrentIndexesLargeOutput(t *testing.T) {
	srv := newTestServer(t)
	srv.workdirs = []string{t.TempDir()}

	res, _, err := srv.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "c1", Command: "head -c 102500 /dev/zero | tr '\\0' 'a'"},
			{Label: "c2", Command: "head -c 102500 /dev/zero | tr '\\0' 'b'"},
		},
		Concurrency: 2,
	})
	if err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	text := contentText(res)
	var resp batchResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, text)
	}
	if resp.Indexed != 2 {
		t.Fatalf("expected indexed=2, got %d\n%s", resp.Indexed, text)
	}
	for _, r := range resp.Commands {
		if !r.Indexed {
			t.Fatalf("expected all entries indexed in concurrent path: %+v", r)
		}
	}
	if doc, _ := srv.store.Get(batchIndexPrefix + "c1"); doc == nil {
		t.Fatal("batch:c1 should be in store")
	}
	if doc, _ := srv.store.Get(batchIndexPrefix + "c2"); doc == nil {
		t.Fatal("batch:c2 should be in store")
	}
}

// ============================================================================
// batch 参数校验（不再静默夹紧/默认化）
// ============================================================================

func TestBatchExecute_ConcurrencyTooHigh(t *testing.T) {
	srv := newTestServer(t)
	srv.workdirs = []string{t.TempDir()}
	_, _, err := srv.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands:    []batchCommand{{Label: "a", Command: "echo hi"}},
		Concurrency: 9,
	})
	if err == nil {
		t.Fatal("expected error for concurrency > 8")
	}
	if !strings.Contains(err.Error(), "concurrency") || !strings.Contains(err.Error(), "1-8") {
		t.Fatalf("expected valid range in error, got: %v", err)
	}
}

func TestBatchExecute_NegativeConcurrency(t *testing.T) {
	srv := newTestServer(t)
	srv.workdirs = []string{t.TempDir()}
	_, _, err := srv.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands:    []batchCommand{{Label: "a", Command: "echo hi"}},
		Concurrency: -3,
	})
	if err == nil {
		t.Fatal("expected error for negative concurrency")
	}
	if !strings.Contains(err.Error(), "1-8") {
		t.Fatalf("expected valid range in error, got: %v", err)
	}
}

func TestBatchExecute_InvalidQueryScope(t *testing.T) {
	srv := newTestServer(t)
	srv.workdirs = []string{t.TempDir()}
	_, _, err := srv.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands:   []batchCommand{{Label: "a", Command: "echo hi"}},
		QueryScope: "everything",
	})
	if err == nil {
		t.Fatal("expected error for invalid query_scope")
	}
	if !strings.Contains(err.Error(), "batch") || !strings.Contains(err.Error(), "global") {
		t.Fatalf("expected valid values in error, got: %v", err)
	}
}
