package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ============================================================================
// 1. 自动索引敏感内容拦截测试 (execute, execute_file, batch, run_task, store)
// ============================================================================

var (
	testPrivateKeyPayload = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3...\n-----END " + "RSA PRIVATE KEY-----\n"
	testAWSAccessKey      = "AKIA" + "IOSFODNN7EXAMPLE"
	testGitHubToken       = "ghp_" + "123456789012345678901234567890123456"
)

func TestAutoIndex_SensitiveContentRefused_Execute(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	// 1. Large output (> 100KB) containing private key
	bigSensitiveOutput := strings.Repeat("A", 105*1024) + "\n" + testPrivateKeyPayload
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command: "printf '%s'",
		Argv:    []string{"printf", "%s", bigSensitiveOutput},
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Content was NOT indexed") || !strings.Contains(text, "private key material") {
		t.Fatalf("expected unindexed result with private key refusal, got: %s", text)
	}
	if hits, _ := st.Search("RSA PRIVATE KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive execute output was indexed to store: %+v", hits)
	}

	// 2. Large output (> 100KB) containing AWS Access Key
	bigAWSOutput := strings.Repeat("A", 105*1024) + "\n" + testAWSAccessKey
	res, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Command: "printf '%s'",
		Argv:    []string{"printf", "%s", bigAWSOutput},
	})
	if err != nil {
		t.Fatalf("toolExecute AWS: %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "Content was NOT indexed") || !strings.Contains(text, "credential / secret material") {
		t.Fatalf("expected unindexed result with credential refusal, got: %s", text)
	}
	if hits, _ := st.Search(testAWSAccessKey, 5); len(hits) != 0 {
		t.Fatalf("sensitive AWS key was indexed to store: %+v", hits)
	}

	// 3. Intent-tagged output (> 5KB) containing GitHub token
	intentSensitiveOutput := strings.Repeat("B", 6*1024) + "\n" + testGitHubToken
	res, _, err = s.toolExecute(context.Background(), nil, executeArgs{
		Command: "printf '%s'",
		Argv:    []string{"printf", "%s", intentSensitiveOutput},
		Intent:  "leak_test",
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "was NOT indexed") || !strings.Contains(text, "credential / secret material") {
		t.Fatalf("expected intent unindexed result with credential refusal, got: %s", text)
	}
	if hits, _ := st.Search("leak_test", 5); len(hits) != 0 {
		t.Fatalf("sensitive intent execute output was indexed to store: %+v", hits)
	}
}

func TestAutoIndex_SensitiveContentRefused_ExecuteFile(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	// Case 1: Target file is a sensitive file (.env). Must be refused BEFORE reading or executing.
	envFile := filepath.Join(wd, ".env")
	mustWrite(t, envFile, "SECRET_KEY=123456\n"+strings.Repeat("LARGE_CONF_VAL=XYZ\n", 6000))
	_, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     envFile,
		Code:     "console.log(FILE_CONTENT);",
		Language: "javascript",
	})
	if err == nil {
		t.Fatal("expected error refusing execution on sensitive file (.env), got nil")
	}
	if !strings.Contains(err.Error(), "refusing to execute on sensitive file") {
		t.Fatalf("expected sensitive file execution refusal message, got: %v", err)
	}
	if hits, _ := st.Search("SECRET_KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive file content was indexed to store: %+v", hits)
	}

	// Case 2: Target file is normal, but code output contains private key (large output)
	if !checkRuntime("javascript", false, "") {
		t.Skip("skipping execute_file javascript test: node runtime not available")
	}
	normalFile := filepath.Join(wd, "data.txt")
	mustWrite(t, normalFile, "hello")
	jsCode := fmt.Sprintf(`console.log(%q + "\n" + %q);`, strings.Repeat("X", 105*1024), testPrivateKeyPayload)
	res, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     normalFile,
		Code:     jsCode,
		Language: "javascript",
	})
	if err != nil {
		t.Fatalf("toolExecuteFile (sensitive output): %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Content was NOT indexed") || !strings.Contains(text, "private key material") {
		t.Fatalf("expected private key output index refusal, got: %s", text)
	}
	if hits, _ := st.Search("RSA PRIVATE KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive output from execute_file was indexed to store: %+v", hits)
	}
}

func TestAutoIndex_SensitiveContentRefused_Batch(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	bigSensitive := strings.Repeat("C", 105*1024) + "\n" + testPrivateKeyPayload
	resp, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "sensitive_cmd", Command: fmt.Sprintf("printf '%%s' '%s'", bigSensitive)},
		},
		CWD: wd,
	})
	if err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	text := mcpResultText(t, resp)
	var batchResp batchResponse
	if err := json.Unmarshal([]byte(text), &batchResp); err != nil {
		t.Fatalf("unmarshal batch response: %v\ntext: %s", err, text)
	}
	if len(batchResp.Commands) != 1 {
		t.Fatalf("expected 1 command result, got %d", len(batchResp.Commands))
	}
	cmdRes := batchResp.Commands[0]
	if cmdRes.Indexed {
		t.Fatal("sensitive batch output must NOT have Indexed=true")
	}
	if !strings.Contains(cmdRes.IndexError, "private key material") {
		t.Fatalf("expected IndexError with private key refusal, got %q", cmdRes.IndexError)
	}
	if hits, _ := st.Search("RSA PRIVATE KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive batch output was indexed: %+v", hits)
	}
}

func TestAutoIndex_SensitiveContentRefused_RunTask(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	bigSensitive := strings.Repeat("D", 105*1024) + "\n" + testPrivateKeyPayload
	res, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom",
		Args: []string{"printf", "%s", bigSensitive},
		CWD:  wd,
	})
	if err != nil {
		t.Fatalf("toolRunTask: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Content was NOT indexed") || !strings.Contains(text, "private key material") {
		t.Fatalf("expected run_task index refusal, got: %s", text)
	}
	if hits, _ := st.Search("RSA PRIVATE KEY", 5); len(hits) != 0 {
		t.Fatalf("sensitive run_task output was indexed: %+v", hits)
	}
}

func TestStore_Index_SensitiveContentRefused(t *testing.T) {
	st := newTestStore(t)

	// Direct Index call with private key must fail
	err := st.Index("secrets/key.pem", testPrivateKeyPayload)
	if err == nil {
		t.Fatal("expected Store.Index to refuse private key")
	}
	if !strings.Contains(err.Error(), "private key material") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Direct Index call with AWS key must fail
	err = st.Index("secrets/aws.txt", "export AWS_ACCESS_KEY_ID="+testAWSAccessKey)
	if err == nil {
		t.Fatal("expected Store.Index to refuse AWS access key")
	}
	if !strings.Contains(err.Error(), "credential / secret material") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

// ============================================================================
// 2. background jsonschema 文案一致性测试
// ============================================================================

func TestBackground_JSONSchema_ReflectsTimeoutTermination(t *testing.T) {
	fExec, ok := reflect.TypeOf(executeArgs{}).FieldByName("Background")
	if !ok {
		t.Fatal("Background field missing in executeArgs")
	}
	tagExec := fExec.Tag.Get("jsonschema")
	if strings.Contains(tagExec, "Keep running after timeout") {
		t.Fatalf("executeArgs.Background tag contains outdated text: %q", tagExec)
	}
	if !strings.Contains(tagExec, "terminated on timeout") && !strings.Contains(tagExec, "terminated after timeout") {
		t.Fatalf("executeArgs.Background tag must reflect timeout termination, got: %q", tagExec)
	}

	fRun, ok := reflect.TypeOf(ctxRunArgs{}).FieldByName("Background")
	if !ok {
		t.Fatal("Background field missing in ctxRunArgs")
	}
	tagRun := fRun.Tag.Get("jsonschema")
	if strings.Contains(tagRun, "Keep running after timeout") {
		t.Fatalf("ctxRunArgs.Background tag contains outdated text: %q", tagRun)
	}
	if !strings.Contains(tagRun, "terminated on timeout") && !strings.Contains(tagRun, "terminated after timeout") {
		t.Fatalf("ctxRunArgs.Background tag must reflect timeout termination, got: %q", tagRun)
	}
}

// ============================================================================
// 3. batch 取消路径 stdout/stderr 合并换行测试
// ============================================================================

func TestBatchExecute_Cancellation_NewlineSeparation(t *testing.T) {
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyFile := filepath.Join(wd, "ready.txt")
	cmdStr := fmt.Sprintf(`printf "stdout_line"; printf "stderr_line" >&2; : > %q; sleep 10`, readyFile)

	done := make(chan struct{})
	var out string
	var exitCode int
	var execErr error

	go func() {
		out, exitCode, execErr, _ = s.executeCommand(ctx, cmdStr, s.workdirs[0])
		close(done)
	}()

	// Wait until stdout and stderr have been produced before cancelling.
	ready := false
	for i := 0; i < 500; i++ {
		if _, err := os.Stat(readyFile); err == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		cancel()
		<-done
		t.Fatal("timed out waiting for command to produce output")
	}

	cancel()
	<-done

	if execErr == nil {
		t.Fatal("expected non-nil error on cancellation")
	}
	if exitCode != -1 {
		t.Fatalf("expected exitCode -1 on cancellation, got %d", exitCode)
	}

	if !strings.Contains(out, "stdout_line\nstderr_line") {
		t.Fatalf("expected newline separation between stdout and stderr on cancellation, got %q", out)
	}
}

// ============================================================================
// 4. 后台启动/注册失败时 cleanups 临时文件清理测试
// ============================================================================

func TestBackground_LaunchFailure_CleanupsRemoved(t *testing.T) {
	wd := t.TempDir()

	tmpFile, err := os.CreateTemp(os.TempDir(), "test_bg_cleanup_*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	cmd := exec.Command("/nonexistent/binary/for/test")
	cmd.Dir = wd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	_, err = runCmd(context.Background(), cmd, 5*time.Second, true, "custom", "bad_cmd", tmpPath)
	if err == nil {
		t.Fatal("expected error for nonexistent binary")
	}

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		_ = os.Remove(tmpPath)
		t.Fatalf("temp file %s was not cleaned up after background launch failure", tmpPath)
	}
}

func TestBackground_RegisterFailure_Cleanup(t *testing.T) {
	bgMu.Lock()
	saved := bgProcs
	bgProcs = make(map[string]*bgEntry)
	// Fill up to maxBackgroundProcs live entries
	for i := 0; i < maxBackgroundProcs; i++ {
		id := fmt.Sprintf("mock-live-%d", i)
		bgProcs[id] = &bgEntry{
			ID:        id,
			PID:       10000 + i,
			StartedAt: time.Now(),
			Done:      false,
		}
	}
	bgMu.Unlock()

	defer func() {
		bgMu.Lock()
		bgProcs = saved
		bgMu.Unlock()
	}()

	tmpFile, err := os.CreateTemp(os.TempDir(), "test_bg_cap_*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	cmd := exec.Command("sleep", "10")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	_, err = runCmd(context.Background(), cmd, 10*time.Second, true, "shell", "sleep 10", tmpPath)
	if err == nil {
		t.Fatal("expected error when background cap is exceeded")
	}
	if !strings.Contains(err.Error(), "too many concurrent background processes") {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		_ = os.Remove(tmpPath)
		t.Fatalf("temp file %s was not cleaned up when background cap was reached", tmpPath)
	}
}

// ============================================================================
// 5. 后台结果保留及上限修剪测试
// ============================================================================

func TestBackground_Retention_QueryableAfterCompletion(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}

	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:    "echo 'background retention test output'",
		Background: true,
	})
	if err != nil {
		t.Fatalf("toolExecute background: %v", err)
	}
	text := mcpResultText(t, res)

	var jobID string
	for _, part := range strings.Fields(text) {
		if strings.HasPrefix(part, "bg-") {
			jobID = strings.Trim(part, ",.)")
			break
		}
	}
	if jobID == "" {
		t.Fatalf("failed to extract jobID from: %s", text)
	}

	t.Cleanup(func() {
		bgMu.Lock()
		e, ok := bgProcs[jobID]
		if ok {
			delete(bgProcs, jobID)
		}
		bgMu.Unlock()
		if e != nil {
			if e.LogPath != "" {
				unprotectTemp(e.LogPath)
				_ = os.Remove(e.LogPath)
			}
			for _, tmp := range e.TempFiles {
				unprotectTemp(tmp)
				_ = os.Remove(tmp)
			}
		}
	})

	waitRes, _, err := s.toolBackgroundWait(context.Background(), nil, backgroundWaitArgs{
		ID:        jobID,
		TimeoutMs: 5000,
	})
	if err != nil {
		t.Fatalf("toolBackgroundWait: %v", err)
	}
	wText := mcpResultText(t, waitRes)
	if !strings.Contains(wText, "background retention test output") {
		t.Fatalf("expected output in wait, got: %s", wText)
	}

	logRes, _, err := s.toolBackgroundLog(context.Background(), nil, backgroundLogArgs{
		ID: jobID,
	})
	if err != nil {
		t.Fatalf("toolBackgroundLog after completion: %v", err)
	}
	lText := mcpResultText(t, logRes)
	if !strings.Contains(lText, "background retention test output") {
		t.Fatalf("expected output in log query, got: %s", lText)
	}
}

func TestBackground_MaxCompletedJobs_Eviction(t *testing.T) {
	bgMu.Lock()
	saved := bgProcs
	bgProcs = make(map[string]*bgEntry)
	bgMu.Unlock()

	defer func() {
		bgMu.Lock()
		bgProcs = saved
		bgMu.Unlock()
	}()

	var logFiles []string
	totalJobs := maxCompletedBackgroundJobs + 10

	for i := 0; i < totalJobs; i++ {
		f, err := os.CreateTemp(os.TempDir(), "test_evict_*.log")
		if err != nil {
			t.Fatal(err)
		}
		lp := f.Name()
		logFiles = append(logFiles, lp)
		_, _ = f.WriteString(fmt.Sprintf("log output %d\n", i))
		protectTemp(lp)

		id := fmt.Sprintf("evict-bg-%d", i)
		bgMu.Lock()
		bgProcs[id] = &bgEntry{
			ID:        id,
			PID:       20000 + i,
			StartedAt: time.Now().Add(time.Duration(i) * time.Millisecond),
			LogPath:   lp,
			logFile:   f,
			logWriter: &limitedFileWriter{f: f, limit: bgLogMaxBytes},
		}
		bgMu.Unlock()

		finishBackground(id, 0)
	}

	bgMu.Lock()
	doneCount := 0
	for _, e := range bgProcs {
		if e.Done {
			doneCount++
		}
	}
	bgMu.Unlock()

	if doneCount > maxCompletedBackgroundJobs {
		t.Fatalf("expected at most %d completed background jobs retained, got %d", maxCompletedBackgroundJobs, doneCount)
	}

	// Verify the oldest 10 log files were removed
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(logFiles[i]); !os.IsNotExist(err) {
			_ = os.Remove(logFiles[i])
			t.Errorf("oldest log file %s should have been removed by eviction", logFiles[i])
		}
	}

	// Clean up remaining log files
	for i := 10; i < len(logFiles); i++ {
		_ = os.Remove(logFiles[i])
	}
}

// ============================================================================
// 6. Leader 退出但子进程存活时 ctx_bg kill 进程组清理测试
// ============================================================================

func TestBackground_Kill_LeaderExitedChildSurviving(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping process group procfs test on non-linux platform")
	}
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("skipping test: /proc is not available")
	}

	s := &server{workdirs: []string{t.TempDir()}}

	// Launch a shell script that spawns a long-running sleep child in background and exits immediately.
	cmdStr := "sleep 100 &"
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:    cmdStr,
		Background: true,
	})
	if err != nil {
		t.Fatalf("toolExecute background: %v", err)
	}
	text := mcpResultText(t, res)

	var jobID string
	for _, part := range strings.Fields(text) {
		if strings.HasPrefix(part, "bg-") {
			jobID = strings.Trim(part, ",.)")
			break
		}
	}
	if jobID == "" {
		t.Fatalf("failed to extract jobID from: %s", text)
	}

	entry := findBackground(jobID)
	if entry == nil {
		t.Fatalf("background job %s not found", jobID)
	}

	t.Cleanup(func() {
		// 1. Attempt clean kill first
		_, _ = killBackground(jobID)

		// 2. Kill the process group directly in case killBackground failed or didn't catch everything
		if entry.PID > 0 {
			_ = syscall.Kill(-entry.PID, syscall.SIGKILL)
			if entry.starttime > 0 {
				surviving := findProcessGroupPIDs(entry.PID, entry.starttime)
				for _, pid := range surviving {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}

		// 3. Clean up registry entry and temporary files
		bgMu.Lock()
		e, ok := bgProcs[jobID]
		if ok {
			delete(bgProcs, jobID)
		}
		bgMu.Unlock()

		if e != nil {
			if e.LogPath != "" {
				unprotectTemp(e.LogPath)
				_ = os.Remove(e.LogPath)
			}
			for _, tmp := range e.TempFiles {
				unprotectTemp(tmp)
				_ = os.Remove(tmp)
			}
		}
	})

	// Poll until leader has exited
	leaderExited := false
	for i := 0; i < 100; i++ {
		time.Sleep(30 * time.Millisecond)
		if procStartTime(entry.PID) == 0 {
			leaderExited = true
			break
		}
	}
	if !leaderExited {
		t.Fatalf("leader process %d did not exit as expected", entry.PID)
	}

	// Poll for surviving child processes in the process group
	var surviving []int
	for i := 0; i < 50; i++ {
		surviving = findProcessGroupPIDs(entry.PID, entry.starttime)
		if len(surviving) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(surviving) == 0 {
		t.Fatalf("expected surviving child process in process group %d, found none", entry.PID)
	}

	// Verify before kill: surviving process is alive and in the process group
	for _, pid := range surviving {
		if err := syscall.Kill(pid, 0); err != nil {
			t.Fatalf("child process %d in group %d is not alive before kill: %v", pid, entry.PID, err)
		}
	}

	// Kill background job
	killMsg, err := killBackground(jobID)
	if err != nil {
		t.Fatalf("killBackground failed: %v", err)
	}
	if !strings.Contains(killMsg, "killed orphan background process group") {
		t.Fatalf("unexpected kill message: %s", killMsg)
	}

	// Verify after kill: all child processes are terminated
	remaining := findProcessGroupPIDs(entry.PID, entry.starttime)
	if len(remaining) > 0 {
		t.Fatalf("orphan processes %v still running in process group %d after killBackground", remaining, entry.PID)
	}
	for _, pid := range surviving {
		// Confirm process is dead
		if err := syscall.Kill(pid, 0); err == nil {
			t.Fatalf("child process %d is still alive after killBackground", pid)
		}
	}
}

func TestBackground_Kill_UnknownIdentity_Refused(t *testing.T) {
	bgMu.Lock()
	saved := bgProcs
	bgProcs = make(map[string]*bgEntry)
	// Entry with unknown identity (starttime = 0)
	bgProcs["bg-unknown"] = &bgEntry{
		ID:        "bg-unknown",
		PID:       99999,
		starttime: 0,
		Done:      false,
	}
	bgMu.Unlock()

	defer func() {
		bgMu.Lock()
		bgProcs = saved
		bgMu.Unlock()
	}()

	_, err := killBackground("bg-unknown")
	if err == nil {
		t.Fatal("expected killBackground to fail on unknown starttime")
	}
	if !strings.Contains(err.Error(), "process identity unknown") {
		t.Fatalf("unexpected error message: %v", err)
	}

	// Ensure slot was NOT marked Done
	e := findBackground("bg-unknown")
	if e == nil || e.Done {
		t.Fatal("entry with unknown identity must not be marked Done on failed kill")
	}
}

// ============================================================================
// 7. 数据库权限防护与恢复测试
// ============================================================================

func TestStore_SecureDBFiles_RestoresRelaxedPermissionsOnWrite(t *testing.T) {
	dbDir := t.TempDir()
	dbPath := filepath.Join(dbDir, "test.db")

	st, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer st.Close()

	// Initial write creates database and sidecar (WAL)
	if err := st.Index("doc/1", "initial content"); err != nil {
		t.Fatalf("Index: %v", err)
	}

	walPath := dbPath + "-wal"

	// Relax permissions to 0644 (simulating external modification or default umask creation)
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(walPath); err == nil {
		if err := os.Chmod(walPath, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Subsequent write must detect and restore 0600 on DB and sidecars
	if err := st.Index("doc/2", "second content"); err != nil {
		t.Fatalf("Index 2: %v", err)
	}

	fi, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected main DB file permissions restored to 0600, got %o", perm)
	}

	if fiWal, err := os.Stat(walPath); err == nil {
		if perm := fiWal.Mode().Perm(); perm != 0o600 {
			t.Fatalf("expected WAL sidecar permissions restored to 0600, got %o", perm)
		}
	}
}

// ============================================================================
// 8. finishBackground 与 shutdownBackground 并发竞态测试
// ============================================================================

func TestBackground_Concurrent_FinishAndShutdown_Race(t *testing.T) {
	bgMu.Lock()
	saved := bgProcs
	bgProcs = make(map[string]*bgEntry)
	bgMu.Unlock()

	defer func() {
		bgMu.Lock()
		bgProcs = saved
		bgMu.Unlock()
	}()

	for round := 0; round < 10; round++ {
		f, err := os.CreateTemp(os.TempDir(), "test_race_bg_*.log")
		if err != nil {
			t.Fatal(err)
		}
		lp := f.Name()
		protectTemp(lp)

		id := fmt.Sprintf("race-bg-%d", round)
		writer := &limitedFileWriter{f: f, limit: bgLogMaxBytes}

		bgMu.Lock()
		bgProcs[id] = &bgEntry{
			ID:        id,
			PID:       30000 + round,
			StartedAt: time.Now(),
			LogPath:   lp,
			logFile:   f,
			logWriter: writer,
			Done:      false,
		}
		bgMu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			finishBackground(id, 0)
		}()

		go func() {
			defer wg.Done()
			shutdownBackground()
		}()

		wg.Wait()
		unprotectTemp(lp)
		_ = os.Remove(lp)
	}
}
