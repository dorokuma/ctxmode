package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Executor output gate tests: every ctx_run return path that hands command
// output back to the (untrusted LLM) client must pass the sensitive-content
// fence. Secret fixtures are split across concatenation so secret scanners do
// not flag this file (same pattern as fixes_test.go / fs_security_fixes_test.go).
const (
	gateAWSAccessKeyID = "AKIA" + "IOSFODNN7EXAMPLE"
	gateAWSSecretKey   = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
	gateTokenValue     = "0123456789abcdef"
)

// gateResultText extracts the first TextContent payload from a tool result.
func gateResultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil {
		t.Fatal("nil tool result")
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatal("no TextContent in tool result")
	return ""
}

// TestExecutorGate_ExecuteSmallOutputWithheld: a small (<5KB, no intent)
// execute output containing a secret is withheld; the notice keeps exit_code
// and the output size but echoes no fragment of the raw output.
func TestExecutorGate_ExecuteSmallOutputWithheld(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	secretLine := "aws_" + "secret_access_key = \"" + gateAWSSecretKey + "\""
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:   "printf '%s' '" + secretLine + "'",
		Language:  "shell",
		TimeoutMs: 15000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text := gateResultText(t, res)
	if !strings.Contains(text, "exit_code: 0") {
		t.Fatalf("withheld notice must keep exit_code, got: %s", text)
	}
	if !strings.Contains(text, "withheld") || !strings.Contains(text, "sensitive content detected") {
		t.Fatalf("expected withheld notice, got: %s", text)
	}
	for _, frag := range []string{gateAWSSecretKey, gateAWSAccessKeyID, "aws_secret_access_key"} {
		if strings.Contains(text, frag) {
			t.Fatalf("withheld output leaked fragment %q: %s", frag, text)
		}
	}
}

// TestExecutorGate_ExecuteSmallOutputPassthrough: benign small output is
// returned verbatim, proving the gate does not touch clean output.
func TestExecutorGate_ExecuteSmallOutputPassthrough(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:   "echo hello",
		Language:  "shell",
		TimeoutMs: 15000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	if text := gateResultText(t, res); text != "hello\n" {
		t.Fatalf("benign output must pass through verbatim, got %q", text)
	}
}

// TestExecutorGate_ExecuteErrorClassPreserved: the withheld notice keeps the
// error_class the raw output would have produced (failing command, exit 3).
func TestExecutorGate_ExecuteErrorClassPreserved(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	secretLine := "db_" + "password = \"" + gateTokenValue + "\""
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:   "printf '%s\n' '" + secretLine + "'; exit 3",
		Language:  "shell",
		TimeoutMs: 15000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text := gateResultText(t, res)
	if !strings.Contains(text, "exit_code: 3") {
		t.Fatalf("withheld notice must keep exit_code, got: %s", text)
	}
	got, _ := res.Meta["error_class"].(string)
	if got != errorClassUnknown {
		t.Fatalf("error_class must be preserved on withheld result, got %q (text: %s)", got, text)
	}
	if strings.Contains(text, gateTokenValue) {
		t.Fatalf("withheld output leaked secret: %s", text)
	}
}

// TestExecutorGate_ExecuteFileOutputWithheld: execute_file user code that
// prints a secret gets the same gate on its small-output return path.
func TestExecutorGate_ExecuteFileOutputWithheld(t *testing.T) {
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}}
	script := filepath.Join(wd, "task.sh")
	if err := os.WriteFile(script, []byte("echo script body\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	secretLine := "refresh_" + "token = \"" + gateTokenValue + "\""
	res, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:      script,
		Code:      "printf '%s' '" + secretLine + "'",
		Language:  "shell",
		TimeoutMs: 15000,
	})
	if err != nil {
		t.Fatalf("toolExecuteFile: %v", err)
	}
	text := gateResultText(t, res)
	if !strings.Contains(text, "exit_code: 0") || !strings.Contains(text, "sensitive content detected") {
		t.Fatalf("expected withheld notice, got: %s", text)
	}
	if strings.Contains(text, "refresh_token") || strings.Contains(text, gateTokenValue) {
		t.Fatalf("execute_file output leaked secret: %s", text)
	}
}

// TestExecutorGate_RunTaskOutputWithheld: run_task small-output return path
// applies the same gate.
func TestExecutorGate_RunTaskOutputWithheld(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	secretArg := "session_" + "token = \"" + gateTokenValue + `"`
	res, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom",
		Args: []string{"printf", "%s", secretArg},
	})
	if err != nil {
		t.Fatalf("toolRunTask: %v", err)
	}
	text := gateResultText(t, res)
	if !strings.Contains(text, "exit_code: 0") || !strings.Contains(text, "sensitive content detected") {
		t.Fatalf("expected withheld notice, got: %s", text)
	}
	if strings.Contains(text, "session_token") || strings.Contains(text, gateTokenValue) {
		t.Fatalf("run_task output leaked secret: %s", text)
	}
}

// TestExecutorGate_RunTaskIndexedTailWithheld: the 4KB/2KB tail previews in
// the run_task large/intent-output branches are withheld when indexing is
// refused on sensitive content.
func TestExecutorGate_RunTaskIndexedTailWithheld(t *testing.T) {
	srv := &server{workdirs: []string{t.TempDir()}}

	big := strings.Repeat("x", runTaskAutoIndexBytes+100) + "\n" + "db_" + "pass = \"" + gateTokenValue + `"`
	res, _, err := srv.finishRunTaskOutput(big, 3, "go_test", "")
	if err != nil {
		t.Fatalf("finishRunTaskOutput: %v", err)
	}
	text := gateResultText(t, res)
	if strings.Contains(text, "--- Tail preview ---") || strings.Contains(text, gateTokenValue) {
		t.Fatalf("sensitive run_task large output must not carry a tail preview: %s", text)
	}
	if !strings.Contains(text, "Tail preview withheld (sensitive content)") || !strings.Contains(text, "exit_code: 3") {
		t.Fatalf("expected withheld-tail notice with exit_code, got: %s", text)
	}

	med := strings.Repeat("y", runTaskIntentIndexBytes+50) + "\n" + "db_" + "password = \"" + gateTokenValue + `"`
	res2, _, err := srv.finishRunTaskOutput(med, 3, "go_test", "gate-intent")
	if err != nil {
		t.Fatalf("finishRunTaskOutput intent: %v", err)
	}
	text2 := gateResultText(t, res2)
	if strings.Contains(text2, "--- Tail preview ---") || strings.Contains(text2, gateTokenValue) {
		t.Fatalf("sensitive run_task intent output must not carry a tail preview: %s", text2)
	}
	if !strings.Contains(text2, "Tail preview withheld (sensitive content)") {
		t.Fatalf("expected withheld-tail notice, got: %s", text2)
	}
}

// TestExecutorGate_IndexedTailWithheldOnSensitiveIndexErr: when indexing is
// refused because the output trips the sensitive-content fence, the tail
// preview (which would be the secret itself) is dropped; non-sensitive index
// failures keep the debugging tail.
func TestExecutorGate_IndexedTailWithheldOnSensitiveIndexErr(t *testing.T) {
	sensitive := strings.Repeat("A", 3000) + "\nsecret_access_key = \"" + "ABCDEFGHIJKLMNOP" + "\""
	benign := strings.Repeat("B", 3000) + "\nplain debug tail"

	msg := formatLargeIndexed(3, len(sensitive), "lbl", sensitive, errors.New("store closed"))
	if strings.Contains(msg, "--- Tail preview ---") || strings.Contains(msg, "ABCDEFGHIJKLMNOP") {
		t.Fatalf("sensitive large-output index failure must not carry a tail: %s", msg)
	}
	if !strings.Contains(msg, "Tail preview withheld (sensitive content)") || !strings.Contains(msg, "exit_code: 3") {
		t.Fatalf("expected withheld-tail notice with exit_code, got: %s", msg)
	}
	msg = formatLargeIndexed(3, len(benign), "lbl", benign, errors.New("store closed"))
	if !strings.Contains(msg, "--- Tail preview ---") || !strings.Contains(msg, "plain debug tail") {
		t.Fatalf("non-sensitive large-output index failure must keep the tail, got: %s", msg)
	}

	msg = formatIntentIndexed(3, len(sensitive), "lbl", sensitive, errors.New("boom"))
	if strings.Contains(msg, "--- Tail preview ---") || strings.Contains(msg, "ABCDEFGHIJKLMNOP") {
		t.Fatalf("sensitive intent-output index failure must not carry a tail: %s", msg)
	}
	if !strings.Contains(msg, "Tail preview withheld (sensitive content)") {
		t.Fatalf("expected withheld-tail notice, got: %s", msg)
	}
	msg = formatIntentIndexed(3, len(benign), "lbl", benign, errors.New("boom"))
	if !strings.Contains(msg, "--- Tail preview ---") {
		t.Fatalf("non-sensitive intent-output index failure must keep the tail, got: %s", msg)
	}
}

// TestExecutorGate_SensitiveFilePathListExtended: the canonical additions to
// isSensitiveFilePath match (basename, case-insensitive), while benign files
// keep passing.
func TestExecutorGate_SensitiveFilePathListExtended(t *testing.T) {
	hits := []string{
		"/root/.git-credentials",
		"/home/u/.bash_history",
		"/home/u/.zsh_history",
		"/home/u/.pgpass",
		"/var/www/.htpasswd",
		"/infra/terraform.tfvars",
		"/infra/env/prod.auto.tfvars",
		"/infra/terraform.tfstate",
		"/vault/db.kdbx",
		"/gcp/service-account.json",
		"/gcp/service-account-prod.json",
		"/gcp/Service-Account-Keys.JSON", // case-insensitive
	}
	misses := []string{
		"/proj/config.json",
		"/proj/service.json",
		"/infra/terraform.tf",
		"/infra/terraform.tfvars.bak",
		"/home/u/bash_history", // no leading dot
		"/proj/src/main.go",
	}
	for _, p := range hits {
		if !isSensitiveFilePath(p) {
			t.Errorf("isSensitiveFilePath(%q) = false, want true", p)
		}
	}
	for _, p := range misses {
		if isSensitiveFilePath(p) {
			t.Errorf("isSensitiveFilePath(%q) = true, want false", p)
		}
	}
}

// TestExecutorGate_SecretRegexKeyExtensions: every new key name is detected,
// while underscore-prefixed/plural/embedded identifiers are not (boundary:
// the key must be preceded by a non-identifier character or string start and
// followed directly by ":" or "=").
func TestExecutorGate_SecretRegexKeyExtensions(t *testing.T) {
	hits := map[string]string{
		"refresh_token":         "refresh_" + "token = \"" + gateTokenValue + `"`,
		"session_token":         "session_" + "token: \"" + gateTokenValue + `"`,
		"id_token":              "id_" + "token = \"" + gateTokenValue + `"`,
		"aws_secret_access_key": "aws_" + "secret_access_key = \"" + gateAWSSecretKey + `"`,
		"secret_access_key":     "secret_" + "access_key = \"" + "ABCDEFGHIJKLMNOP" + `"`,
		"db_password":           "db_" + "password = \"" + gateTokenValue + `"`,
		"db_pass":               "db_" + "pass = \"" + gateTokenValue + `"`,
		"uppercase_key":         "DB_" + "PASSWORD: \"" + gateTokenValue + `"`,
	}
	for name, line := range hits {
		if err := checkSensitiveContent(line); err == nil {
			t.Errorf("expected %s to be detected as sensitive: %s", name, line)
		}
	}
	misses := []string{
		"my_db_" + "passwords = \"" + gateTokenValue + `"`, // underscore prefix + plural suffix
		"my_db_" + "password = \"" + gateTokenValue + `"`,  // underscore prefix
		"kid_" + "token = \"" + gateTokenValue + `"`,       // key embedded in identifier
		"session_" + "tokens = \"" + gateTokenValue + `"`,  // plural suffix blocks key[:=]
		"plain log line with no credentials",
	}
	for _, line := range misses {
		if err := checkSensitiveContent(line); err != nil {
			t.Errorf("unexpected sensitive hit for %q: %v", line, err)
		}
	}
}

// bg family: log/wait must apply the same sensitive-content gate as the
// synchronous execute paths (background output comes from arbitrary commands).
func TestExecutorGate_BackgroundLogWithheld(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	secret := "RRRR" + "RRRRRRRRRRRRRRRR"
	cmd := "printf \"%s\\n\" \"refresh_token = \\\"" + secret + "\\\"\""
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:    cmd,
		Background: true,
	})
	if err != nil {
		t.Fatalf("toolExecute background: %v", err)
	}
	jobID := extractBgJobID(t, mcpResultText(t, res))
	t.Cleanup(func() { cleanupBgJob(jobID) })

	wres, _, err := s.toolBackgroundWait(context.Background(), nil, backgroundWaitArgs{ID: jobID, TimeoutMs: 5000})
	if err != nil {
		t.Fatalf("toolBackgroundWait: %v", err)
	}
	wtext := mcpResultText(t, wres)
	if strings.Contains(wtext, secret) {
		t.Errorf("background wait leaked sensitive output:\n%s", wtext)
	}
	if !strings.Contains(wtext, "withheld: sensitive content detected") {
		t.Errorf("expected withheld notice in wait log, got:\n%s", wtext)
	}

	lres, _, err := s.toolBackgroundLog(context.Background(), nil, backgroundLogArgs{ID: jobID})
	if err != nil {
		t.Fatalf("toolBackgroundLog: %v", err)
	}
	ltext := mcpResultText(t, lres)
	if strings.Contains(ltext, secret) {
		t.Errorf("background log leaked sensitive output:\n%s", ltext)
	}
	if !strings.Contains(ltext, "withheld: sensitive content detected") {
		t.Errorf("expected withheld notice in log, got:\n%s", ltext)
	}
}

func TestExecutorGate_BackgroundLogPassthrough(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:    "echo bg_plain_output_marker",
		Background: true,
	})
	if err != nil {
		t.Fatalf("toolExecute background: %v", err)
	}
	jobID := extractBgJobID(t, mcpResultText(t, res))
	t.Cleanup(func() { cleanupBgJob(jobID) })

	if _, _, err := s.toolBackgroundWait(context.Background(), nil, backgroundWaitArgs{ID: jobID, TimeoutMs: 5000}); err != nil {
		t.Fatalf("toolBackgroundWait: %v", err)
	}
	lres, _, err := s.toolBackgroundLog(context.Background(), nil, backgroundLogArgs{ID: jobID})
	if err != nil {
		t.Fatalf("toolBackgroundLog: %v", err)
	}
	ltext := mcpResultText(t, lres)
	if !strings.Contains(ltext, "bg_plain_output_marker") {
		t.Errorf("benign background output must pass through, got:\n%s", ltext)
	}
	if strings.Contains(ltext, "withheld: sensitive content detected") {
		t.Errorf("benign background output must not be withheld, got:\n%s", ltext)
	}
}

func extractBgJobID(t *testing.T, text string) string {
	t.Helper()
	for _, part := range strings.Fields(text) {
		if strings.HasPrefix(part, "bg-") {
			return strings.Trim(part, ",.)")
		}
	}
	t.Fatalf("failed to extract background job id from: %s", text)
	return ""
}

func cleanupBgJob(jobID string) {
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
}
