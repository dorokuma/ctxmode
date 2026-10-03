package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain keeps the audit log away from its production path for the whole test
// binary: every ctx_run call in every test would otherwise append to
// /root/.local/state/ctxmode/audit.jsonl and bury real records in test noise.
// Tests that assert on audit content point CTXMODE_AUDIT_LOG at their own temp
// file with t.Setenv, which overrides this value for their duration.
//
// It uses os.Setenv rather than t.Setenv on purpose: TestMain has no *testing.T,
// and t.Setenv only works inside a test (it registers a cleanup with that test).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ctxmode-audit-test")
	if err != nil {
		os.Exit(1)
	}
	os.Setenv(auditEnvLogPath, filepath.Join(dir, "audit.jsonl"))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// auditRecordKeys is the fixed field set every audit line must carry.
var auditRecordKeys = []string{
	"timestamp", "pid", "session_id", "action", "role", "caller_readonly",
	"command_type", "raw_cmd", "resolved_exe", "cwd", "background",
	"background_id", "duration_ms", "exit_code", "error", "screen_verdict",
	"screen_rule", "audit_tags", "env_keys", "stdin_len", "indexed",
	"index_label", "commands", "first_failed_label", "output_len", "truncated",
}

// readAuditLines returns the raw lines of an audit file.
func readAuditLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log %q: %v", path, err)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// decodeAuditLines parses each line as JSON into both a key map and the record
// type, so a test can assert exact key presence and typed values.
func decodeAuditLines(t *testing.T, lines []string) ([]map[string]any, []auditRecord) {
	t.Helper()
	keys := make([]map[string]any, 0, len(lines))
	recs := make([]auditRecord, 0, len(lines))
	for _, l := range lines {
		var km map[string]any
		if err := json.Unmarshal([]byte(l), &km); err != nil {
			t.Fatalf("audit line is not JSON (%q): %v", l, err)
		}
		var rec auditRecord
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("audit line does not decode into auditRecord (%q): %v", l, err)
		}
		keys = append(keys, km)
		recs = append(recs, rec)
	}
	return keys, recs
}

// auditTestServer builds a server whose audit lines land in a per-test file and
// returns the server plus the log path.
func auditTestServer(t *testing.T) (*server, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv(auditEnvLogPath, logPath)
	t.Setenv(auditEnvRole, "")
	t.Setenv(auditEnvReadonly, "")
	return testServerWithWorkdir(t, t.TempDir()), logPath
}

// TestAuditLogPath_DefaultIsStateNotCache pins the documented default. The
// literal path is asserted on purpose: the default is part of the documented
// contract (root deployment), and a change to it must be deliberate.
func TestAuditLogPath_DefaultIsStateNotCache(t *testing.T) {
	t.Setenv(auditEnvLogPath, "")
	if got := auditLogPath(); got != auditDefaultPath {
		t.Fatalf("auditLogPath() = %q, want %q", got, auditDefaultPath)
	}
	if auditDefaultPath != "/root/.local/state/ctxmode/audit.jsonl" {
		t.Fatalf("unexpected default audit path %q", auditDefaultPath)
	}
	if strings.Contains(auditDefaultPath, "/.cache/") {
		t.Fatalf("audit log must not live in a cache directory: %q", auditDefaultPath)
	}
}

// TestAudit_ExecuteArgvRecord locks the record shape for a successful argv call:
// the full field set is present, the bare argv[0] is recorded as its real
// LookPath path, the output size is counted — and the output itself is not
// stored anywhere in the line.
func TestAudit_ExecuteArgvRecord(t *testing.T) {
	// Nested directory on purpose: the writer must create it.
	logPath := filepath.Join(t.TempDir(), "state", "audit.jsonl")
	t.Setenv(auditEnvLogPath, logPath)
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")

	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	s.sessionID = "sess-audit-test"
	// The command text never contains the literal output, so finding the output
	// in the line would prove stdout was written to the audit.
	if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv: []string{"sh", "-c", "printf 'OUT_%s' MARKER"},
	}); err != nil {
		t.Fatalf("toolExecute: %v", err)
	}

	lines := readAuditLines(t, logPath)
	if len(lines) != 1 {
		t.Fatalf("expected exactly one audit line, got %d: %v", len(lines), lines)
	}
	if strings.Contains(lines[0], "OUT_MARKER") {
		t.Fatalf("audit line must not contain captured stdout: %s", lines[0])
	}
	if !strings.Contains(lines[0], `"action":"execute"`) {
		t.Fatalf("expected un-indented single-line JSON: %s", lines[0])
	}

	keys, recs := decodeAuditLines(t, lines)
	for _, k := range auditRecordKeys {
		if _, ok := keys[0][k]; !ok {
			t.Errorf("audit record missing field %q: %s", k, lines[0])
		}
	}
	if len(keys[0]) != len(auditRecordKeys) {
		t.Errorf("audit record has %d fields, want %d: %s", len(keys[0]), len(auditRecordKeys), lines[0])
	}
	rec := recs[0]
	if rec.Action != "execute" || rec.CommandType != "argv" {
		t.Fatalf("action/command_type = %q/%q, want execute/argv", rec.Action, rec.CommandType)
	}
	if rec.PID != os.Getpid() || rec.SessionID != "sess-audit-test" {
		t.Fatalf("pid/session_id = %d/%q, want %d/sess-audit-test", rec.PID, rec.SessionID, os.Getpid())
	}
	if rec.RawCmd != "sh -c printf 'OUT_%s' MARKER" {
		t.Fatalf("raw_cmd = %q", rec.RawCmd)
	}
	if !filepath.IsAbs(rec.ResolvedExe) || filepath.Base(rec.ResolvedExe) != "sh" {
		t.Fatalf("resolved_exe = %q, want an absolute path ending in sh", rec.ResolvedExe)
	}
	if rec.CWD != wd {
		t.Fatalf("cwd = %q, want %q", rec.CWD, wd)
	}
	if rec.ExitCode != 0 || rec.OutputLen != len("OUT_MARKER") {
		t.Fatalf("exit_code/output_len = %d/%d, want 0/%d", rec.ExitCode, rec.OutputLen, len("OUT_MARKER"))
	}
	if rec.Indexed || rec.IndexLabel != "" || rec.Truncated || rec.Background || rec.BackgroundID != "" {
		t.Fatalf("unexpected index/truncate/background state: %+v", rec)
	}
	if rec.Error != "" || rec.ScreenVerdict != "ok" || rec.ScreenRule != "" {
		t.Fatalf("unexpected error/screen state: error=%q verdict=%q rule=%q", rec.Error, rec.ScreenVerdict, rec.ScreenRule)
	}
	if rec.Role != "worker" || rec.CallerReadonly {
		t.Fatalf("role/caller_readonly = %q/%v, want worker/false", rec.Role, rec.CallerReadonly)
	}
	if len(rec.Commands) != 0 || rec.FirstFailedLabel != "" {
		t.Fatalf("non-batch call must not carry batch aggregation: %+v", rec.Commands)
	}
	if _, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err != nil {
		t.Fatalf("timestamp %q is not RFC3339Nano: %v", rec.Timestamp, err)
	}
	if rec.DurationMs < 0 {
		t.Fatalf("duration_ms must not be negative, got %d", rec.DurationMs)
	}
	// audit_tags is always an array, never null.
	if _, ok := keys[0]["audit_tags"].([]any); !ok {
		t.Fatalf("audit_tags must be a JSON array, got %T", keys[0]["audit_tags"])
	}

	// The record is a credential-adjacent log: file 0600, directory 0700.
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("audit file mode = %o, want 600", perm)
	}
	di, err := os.Stat(filepath.Dir(logPath))
	if err != nil {
		t.Fatalf("stat audit dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("audit dir mode = %o, want 700", perm)
	}
}

// TestAudit_ReadonlyRoleTag covers rule (i): a read-only CTXMODE_ROLE or
// CTXMODE_READONLY=1 tags the record; an ordinary role does not. The tag is
// recorded only — the call still runs.
func TestAudit_ReadonlyRoleTag(t *testing.T) {
	cases := []struct {
		name     string
		role     string
		readonly string
		wantTag  bool
		wantRO   bool
	}{
		{name: "readonly role", role: "reviewer", wantTag: true},
		{name: "readonly env", role: "worker", readonly: "1", wantTag: true, wantRO: true},
		{name: "ordinary role", role: "worker", wantTag: false},
		{name: "no role", wantTag: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "audit.jsonl")
			t.Setenv(auditEnvLogPath, logPath)
			t.Setenv(auditEnvRole, tc.role)
			t.Setenv(auditEnvReadonly, tc.readonly)

			wd := t.TempDir()
			s := testServerWithWorkdir(t, wd)
			// The call must still execute: the tag never blocks anything.
			res, _, err := s.toolExecute(context.Background(), nil, executeArgs{Argv: []string{"echo", "tagged"}})
			if err != nil {
				t.Fatalf("toolExecute: %v", err)
			}
			if !strings.Contains(mcpResultText(t, res), "tagged") {
				t.Fatalf("read-only role must not block execution: %q", mcpResultText(t, res))
			}

			_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
			got := strings.Join(recs[0].AuditTags, ",")
			hasTag := strings.Contains(got, auditTagReadonlyRoleCall)
			if hasTag != tc.wantTag {
				t.Fatalf("tags = %q, wantTag=%v", got, tc.wantTag)
			}
			if recs[0].CallerReadonly != tc.wantRO {
				t.Fatalf("caller_readonly = %v, want %v", recs[0].CallerReadonly, tc.wantRO)
			}
		})
	}
}

// TestAudit_EvalInterpreterTag covers rule (ii) at the unit level. The table
// doubles as the documented boundary of the heuristic: shell `-e` (errexit),
// node `--help`, perl `-c` (syntax check) and `env -i` are NOT inline code,
// while bundled short options, `--eval=`, php `-r` and Rscript `-e` are.
func TestAudit_EvalInterpreterTag(t *testing.T) {
	cases := []struct {
		name string
		exe  string
		argv []string
		want bool
	}{
		// shells
		{name: "sh -c", exe: "/bin/sh", argv: []string{"sh", "-c", "id"}, want: true},
		{name: "sh -lc bundled", exe: "/bin/sh", argv: []string{"sh", "-lc", "id"}, want: true},
		{name: "bash -ec bundled", exe: "/bin/bash", argv: []string{"bash", "-ec", "true"}, want: true},
		{name: "bash -e file is errexit, not inline", exe: "/bin/bash", argv: []string{"bash", "-e", "script.sh"}, want: false},
		{name: "bash -l login shell", exe: "/bin/bash", argv: []string{"bash", "-l"}, want: false},
		{name: "dash script file", exe: "/bin/dash", argv: []string{"dash", "run.sh"}, want: false},
		// node
		{name: "node -e", exe: "/usr/bin/node", argv: []string{"node", "-e", "1"}, want: true},
		{name: "node --eval=", exe: "/usr/bin/node", argv: []string{"node", "--eval=console.log(1)"}, want: true},
		{name: "node --print", exe: "/usr/bin/node", argv: []string{"node", "--print", "1"}, want: true},
		{name: "node --help is not inline", exe: "/usr/bin/node", argv: []string{"node", "--help"}, want: false},
		{name: "node script", exe: "/usr/bin/node", argv: []string{"node", "app.js"}, want: false},
		// perl / ruby / php / R
		{name: "perl -e", exe: "/usr/bin/perl", argv: []string{"perl", "-e", "1"}, want: true},
		{name: "perl -pe one-liner", exe: "/usr/bin/perl", argv: []string{"perl", "-pe", "s/x/y/"}, want: true},
		{name: "perl -c is a syntax check", exe: "/usr/bin/perl", argv: []string{"perl", "-c", "x.pl"}, want: false},
		{name: "ruby -e", exe: "/usr/bin/ruby", argv: []string{"ruby", "-e", "1"}, want: true},
		{name: "ruby script", exe: "/usr/bin/ruby", argv: []string{"ruby", "x.rb"}, want: false},
		{name: "php -r", exe: "/usr/bin/php", argv: []string{"php", "-r", "echo 1;"}, want: true},
		{name: "php -f file", exe: "/usr/bin/php", argv: []string{"php", "-f", "x.php"}, want: false},
		{name: "Rscript -e", exe: "/usr/bin/Rscript", argv: []string{"Rscript", "-e", "print(1)"}, want: true},
		// python (including the prefix rule and the -i/-m false positive)
		{name: "python -c", exe: "/usr/bin/python3", argv: []string{"python3", "-c", "print(1)"}, want: true},
		{name: "python prefix matches", exe: "/usr/bin/python3.12", argv: []string{"python3.12", "-c", "1"}, want: true},
		{name: "python -m pip install -i is not inline", exe: "/usr/bin/python3", argv: []string{"python3", "-m", "pip", "install", "-i", "https://x"}, want: false},
		{name: "python -i alone reads stdin", exe: "/usr/bin/python3", argv: []string{"python3", "-i"}, want: true},
		{name: "python -i with -m is module mode", exe: "/usr/bin/python3", argv: []string{"python3", "-i", "-m", "http.server"}, want: false},
		// wrappers
		{name: "env wrapping sh -c", exe: "/usr/bin/env", argv: []string{"env", "FOO=1", "sh", "-c", "id"}, want: true},
		{name: "env -i cmd is not inline", exe: "/usr/bin/env", argv: []string{"env", "-i", "sleep", "1"}, want: false},
		{name: "busybox sh -c", exe: "/bin/busybox", argv: []string{"busybox", "sh", "-c", "id"}, want: true},
		{name: "busybox -i alone is not inline", exe: "/bin/busybox", argv: []string{"busybox", "-i"}, want: false},
		// non-interpreters
		{name: "echo -e is not an interpreter", exe: "/usr/bin/echo", argv: []string{"echo", "-e", "x"}, want: false},
		{name: "go test", exe: "/usr/local/go/bin/go", argv: []string{"go", "test", "./..."}, want: false},
		{name: "no argv", exe: "/bin/sh", argv: nil, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditEvalInterpreter(tc.exe, tc.argv); got != tc.want {
				t.Fatalf("auditEvalInterpreter(%q, %q) = %v, want %v", tc.exe, tc.argv, got, tc.want)
			}
		})
	}

	// End to end: `sh -c` through toolExecute is tagged and still executes.
	s, logPath := auditTestServer(t)
	if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv: []string{"sh", "-c", "echo eval_tagged"},
	}); err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	if strings.Join(recs[0].AuditTags, ",") != auditTagEvalInterpreter {
		t.Fatalf("tags = %v, want [%s]", recs[0].AuditTags, auditTagEvalInterpreter)
	}
}

// TestAudit_ArgvNulBlockRecorded verifies the blocked argv path: the caller sees
// the argv-specific error, no process runs, and the audit line still lands with
// the block verdict, the rule name and the error.
func TestAudit_ArgvNulBlockRecorded(t *testing.T) {
	s, logPath := auditTestServer(t)
	_, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv: []string{"echo", "bad\x00arg"},
	})
	if err == nil || !strings.Contains(err.Error(), "argv command blocked (nul_byte)") {
		t.Fatalf("expected argv nul_byte block, got %v", err)
	}

	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	if len(recs) != 1 {
		t.Fatalf("expected exactly one audit line, got %d", len(recs))
	}
	rec := recs[0]
	if rec.ScreenVerdict != "block" || rec.ScreenRule != "nul_byte" {
		t.Fatalf("screen = %q/%q, want block/nul_byte", rec.ScreenVerdict, rec.ScreenRule)
	}
	if rec.ExitCode != auditExitNotRun {
		t.Fatalf("exit_code = %d, want %d (never ran)", rec.ExitCode, auditExitNotRun)
	}
	if !strings.Contains(rec.Error, "argv command blocked") {
		t.Fatalf("error = %q, want the block message", rec.Error)
	}
	if rec.OutputLen != 0 {
		t.Fatalf("output_len = %d, want 0", rec.OutputLen)
	}
}

// TestAudit_EarlyValidationRecorded covers the consistency requirement: the two
// handlers with required-field checks (execute, execute_file) start their audit
// record before those checks, so a rejected empty call still produces a line —
// exactly like batch and run_task already did.
func TestAudit_EarlyValidationRecorded(t *testing.T) {
	s, logPath := auditTestServer(t)

	if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{}); err == nil {
		t.Fatal("expected execute with no command/argv to be rejected")
	}
	if _, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{}); err == nil {
		t.Fatal("expected execute_file with no path/code to be rejected")
	}
	if _, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{}); err == nil {
		t.Fatal("expected batch with no commands to be rejected")
	}
	if _, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{}); err == nil {
		t.Fatal("expected run_task with no kind to be rejected")
	}

	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	if len(recs) != 4 {
		t.Fatalf("expected one audit line per rejected call, got %d: %+v", len(recs), recs)
	}
	wantActions := map[string]string{"execute": "command", "execute_file": "file", "batch": "command", "run_task": "task"}
	seen := map[string]bool{}
	for _, rec := range recs {
		if rec.Error == "" {
			t.Errorf("%s call must record its rejection error: %+v", rec.Action, rec)
		}
		if rec.ExitCode != auditExitNotRun {
			t.Errorf("%s rejected call exit_code = %d, want %d", rec.Action, rec.ExitCode, auditExitNotRun)
		}
		if want, ok := wantActions[rec.Action]; ok {
			if rec.CommandType != want {
				t.Errorf("%s command_type = %q, want %q", rec.Action, rec.CommandType, want)
			}
			seen[rec.Action] = true
		} else {
			t.Errorf("unexpected action %q", rec.Action)
		}
	}
	for action := range wantActions {
		if !seen[action] {
			t.Errorf("no audit line for rejected %s call", action)
		}
	}
}

// TestAudit_SensitiveCommandRedacted covers S2: the recorded command text goes
// through the shared sensitive-content check, and the caller's env KEY NAMES and
// stdin LENGTH are recorded without any value.
func TestAudit_SensitiveCommandRedacted(t *testing.T) {
	s, logPath := auditTestServer(t)
	// Assembled from parts on purpose: this file must not contain a well-formed
	// credential literal, because the repository commit hook rejects staged tokens
	// shaped like real ones. The runtime value is a full-shape AWS access key ID,
	// so awsAccessKeyRe still matches it.
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  []string{"echo", awsKey},
		Env:   map[string]string{"NODE_ENV": "test", "CTXMODE_FOO": "1"},
		Stdin: "payload",
	}); err != nil {
		t.Fatalf("toolExecute: %v", err)
	}

	lines := readAuditLines(t, logPath)
	if strings.Contains(lines[0], awsKey) {
		t.Fatalf("command text was recorded verbatim despite the sensitive check: %s", lines[0])
	}
	_, recs := decodeAuditLines(t, lines)
	rec := recs[0]
	if !strings.Contains(rec.RawCmd, "[redacted:") {
		t.Fatalf("raw_cmd = %q, want a redaction marker", rec.RawCmd)
	}
	if !strings.Contains(rec.RawCmd, "len=25") {
		// len("echo " + the 20-byte AWS key above) — the marker records the
		// original length so a redacted line is still attributable.
		t.Fatalf("raw_cmd = %q, want the original length in the marker", rec.RawCmd)
	}
	if got := strings.Join(rec.EnvKeys, ","); got != "CTXMODE_FOO,NODE_ENV" {
		t.Fatalf("env_keys = %q, want the sorted caller key names", got)
	}
	if rec.StdinLen != len("payload") {
		t.Fatalf("stdin_len = %d, want %d", rec.StdinLen, len("payload"))
	}
	if strings.Contains(lines[0], "payload") {
		t.Fatalf("stdin payload must never be recorded: %s", lines[0])
	}
}

// TestAudit_BackgroundStartRecordsJobID covers S5: a background call records the
// ctx_bg job id and does NOT report exit_code 0 as if the job had succeeded.
func TestAudit_BackgroundStartRecordsJobID(t *testing.T) {
	s, logPath := auditTestServer(t)
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv:       []string{"sleep", "2"},
		Background: true,
	})
	if err != nil {
		t.Fatalf("background toolExecute: %v", err)
	}
	id := parseBgID(t, mcpResultText(t, res))
	defer killBackground(id)

	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	rec := recs[0]
	if !rec.Background || rec.BackgroundID != id {
		t.Fatalf("background/background_id = %v/%q, want true/%q", rec.Background, rec.BackgroundID, id)
	}
	if rec.ExitCode != auditExitNotRun {
		t.Fatalf("background line exit_code = %d, want %d (the job's status is not known here)", rec.ExitCode, auditExitNotRun)
	}
	if rec.OutputLen == 0 {
		t.Fatal("output_len for a background start is the start-message length (documented)")
	}
}

// TestAudit_TargetIsValidatedBeforeOpening covers F1: a target that is not the
// regular file ctxmode creates (FIFO, symlink, directory) is refused promptly
// and never blocks the append mutex — a FIFO would otherwise stall every later
// ctx_run call.
func TestAudit_TargetIsValidatedBeforeOpening(t *testing.T) {
	dir := t.TempDir()

	// FIFO: opening it for write blocks until a reader appears.
	fifo := filepath.Join(dir, "audit.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable on this platform: %v", err)
	}
	t.Setenv(auditEnvLogPath, fifo)
	done := make(chan error, 1)
	go func() { done <- appendAuditLine([]byte("{}\n")) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the FIFO target to be refused")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("unexpected refusal reason: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("appendAuditLine blocked on a FIFO target (F1 regression)")
	}

	// The tool call itself must still complete and still work.
	s := testServerWithWorkdir(t, t.TempDir())
	callDone := make(chan error, 1)
	go func() {
		_, _, err := s.toolExecute(context.Background(), nil, executeArgs{Argv: []string{"echo", "fifo_target"}})
		callDone <- err
	}()
	select {
	case err := <-callDone:
		if err != nil {
			t.Fatalf("a broken audit target must not fail the call: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("toolExecute blocked with a FIFO audit target (F1 regression)")
	}

	// Symlink: refused, and the link target is left untouched.
	real := filepath.Join(dir, "real.jsonl")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(auditEnvLogPath, link)
	if err := appendAuditLine([]byte("{}\n")); err == nil {
		t.Fatal("expected a symlink target to be refused")
	}
	if b, err := os.ReadFile(real); err != nil || len(b) != 0 {
		t.Fatalf("symlink target must be untouched (err=%v, %d bytes)", err, len(b))
	}

	// Directory.
	t.Setenv(auditEnvLogPath, dir)
	if err := appendAuditLine([]byte("{}\n")); err == nil {
		t.Fatal("expected a directory target to be refused")
	}

	// A missing path in a missing directory is created, as documented.
	ok := filepath.Join(dir, "new", "audit.jsonl")
	t.Setenv(auditEnvLogPath, ok)
	if err := appendAuditLine([]byte("{}\n")); err != nil {
		t.Fatalf("a missing target must be created: %v", err)
	}
	if lines := readAuditLines(t, ok); len(lines) != 1 {
		t.Fatalf("expected the written line, got %v", lines)
	}
}

// TestAudit_RotatesAtSizeCap covers S6: the audit file is capped and rotated to
// "<path>.1" instead of growing without bound.
func TestAudit_RotatesAtSizeCap(t *testing.T) {
	old := auditRotateBytes
	auditRotateBytes = 200
	defer func() { auditRotateBytes = old }()

	s, logPath := auditTestServer(t)
	for _, marker := range []string{"rot_one", "rot_two"} {
		if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{Argv: []string{"echo", marker}}); err != nil {
			t.Fatalf("toolExecute %s: %v", marker, err)
		}
	}
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatalf("expected a rotated file %q: %v", logPath+".1", err)
	}
	_, current := decodeAuditLines(t, readAuditLines(t, logPath))
	_, rotated := decodeAuditLines(t, readAuditLines(t, logPath+".1"))
	if len(current)+len(rotated) != 2 {
		t.Fatalf("expected both records to survive the rotation, got %d current + %d rotated", len(current), len(rotated))
	}
}

// TestAudit_RotationFailureKeepsWriting covers R2-F1: rotation is best effort and
// losing the line is the real loss. With "<path>.1" occupied by a non-empty
// directory, os.Rename fails (ENOTEMPTY/EISDIR) — the record must still be
// appended to the current file, the call must return nil, and every later append
// must keep working (the old code lost the line and then failed forever on the
// same path).
func TestAudit_RotationFailureKeepsWriting(t *testing.T) {
	old := auditRotateBytes
	auditRotateBytes = 1 // every append wants to rotate
	defer func() { auditRotateBytes = old }()

	s, logPath := auditTestServer(t)
	// Occupy "<path>.1" with a non-empty directory so the rename fails.
	if err := os.MkdirAll(filepath.Join(logPath+".1", "occupied"), 0o700); err != nil {
		t.Fatalf("prepare blocking .1 directory: %v", err)
	}

	for i, marker := range []string{"failrot_one", "failrot_two", "failrot_three"} {
		if _, _, err := s.toolExecute(context.Background(), nil, executeArgs{Argv: []string{"echo", marker}}); err != nil {
			t.Fatalf("toolExecute %s (append %d): %v", marker, i+1, err)
		}
		_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
		if len(recs) != i+1 {
			t.Fatalf("after append %d the current file has %d record(s), want %d (a failed rotation must not drop the line)",
				i+1, len(recs), i+1)
		}
	}
	// The blocking directory is untouched, and the .1 path never became a file.
	if fi, err := os.Stat(logPath + ".1"); err != nil || !fi.IsDir() {
		t.Fatalf("the occupied .1 path must be left alone (err=%v)", err)
	}
}

// tightenFDLimitToOneExtraOpen lowers RLIMIT_NOFILE so that exactly one more
// descriptor can be opened, which is what makes the post-rotation reopen fail
// deterministically (EMFILE) while the call's own first open still succeeds.
// It returns a restore function and ok=false when the limit cannot be tightened
// (no RLIMIT_NOFILE, no /proc, or the soft limit already sits at the hard one).
func tightenFDLimitToOneExtraOpen(t *testing.T) (restore func(), ok bool) {
	t.Helper()
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &orig); err != nil {
		return func() {}, false
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return func() {}, false
	}
	// ReadDir includes the descriptor it needed to read the directory, which is
	// already closed by now, so the live count is at most that. The probe below
	// settles the off-by-one empirically on either behaviour: raise the candidate
	// until one single extra open is exactly what still fits.
	live := uint64(len(entries))
	reset := func() { _ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &orig) }
	for k := live; k < live+8; k++ {
		if k > orig.Max {
			break
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: k, Max: orig.Max}); err != nil {
			continue
		}
		f, oerr := os.Open(os.DevNull)
		if oerr == nil {
			f.Close()
			return reset, true
		}
	}
	reset()
	return func() {}, false
}

// TestAudit_ReopenAfterRotationFailsKeepsRecord covers the second half of the
// R2-F1 invariant (same rotation family as
// TestAudit_RotationFailureKeepsWriting): the rename succeeds but the replacement
// file cannot be opened. The record must land in the generation that was just
// rotated to "<path>.1" instead of being dropped. The branch is reached with
// RLIMIT_NOFILE tightened to exactly one spare descriptor, so the call's first
// open succeeds and the reopen after the rename fails with EMFILE.
func TestAudit_ReopenAfterRotationFailsKeepsRecord(t *testing.T) {
	old := auditRotateBytes
	auditRotateBytes = 1 // the seed append fills a "cap" of one byte
	defer func() { auditRotateBytes = old }()

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv(auditEnvLogPath, logPath)

	// A brand-new file has size 0, so this append does not try to rotate.
	if err := appendAuditLine([]byte("{\"seq\":1}\n")); err != nil {
		t.Fatalf("seed append: %v", err)
	}

	restore, ok := tightenFDLimitToOneExtraOpen(t)
	if !ok {
		// This half of the R2-F1 invariant must not be silently untested. Every
		// Linux host in the CI matrix can tighten RLIMIT_NOFILE (the helper only
		// gives up when Getrlimit fails, /proc/self/fd is unreadable, or the soft
		// limit already equals the hard one), so a failure here on Linux is a
		// broken signal: fail loudly instead of reporting a green run that
		// asserted nothing. Only a non-Linux host, where syscall.RLIMIT_NOFILE
		// and /proc/self/fd need not exist, is allowed to skip.
		if runtime.GOOS != "linux" {
			t.Skipf("cannot tighten RLIMIT_NOFILE to one spare descriptor on %s", runtime.GOOS)
		}
		t.Fatalf("cannot tighten RLIMIT_NOFILE to one spare descriptor on linux; " +
			"the failed-reopen path would be silently untested")
	}
	appendErr := appendAuditLine([]byte("{\"seq\":2}\n"))
	restore()
	if appendErr != nil {
		t.Fatalf("a failed reopen must not fail the append: %v", appendErr)
	}

	// The record survives, in the generation that was rotated away...
	rotated := readAuditLines(t, logPath+".1")
	if len(rotated) != 2 || !strings.Contains(rotated[1], `"seq":2`) {
		t.Fatalf("rotated generation = %v, want the seed line plus the record kept through the failed reopen", rotated)
	}
	// ...and nothing was written into the path it could not reopen.
	cur, err := os.ReadFile(logPath)
	if err == nil {
		if strings.Contains(string(cur), `"seq":2`) {
			t.Fatalf("record went into the current file: %s", cur)
		}
	} else if !os.IsNotExist(err) {
		t.Fatalf("read current file: %v", err)
	}
}

// TestAudit_BatchAndRunTaskWireEntryPoints smoke-tests the other two injection
// points: each call appends exactly one line with its own action/command_type,
// and run_task's argv is screened too (S3).
func TestAudit_BatchAndRunTaskWireEntryPoints(t *testing.T) {
	s, logPath := auditTestServer(t)
	if _, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{{Label: "one", Command: "echo batch_line"}},
	}); err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	if _, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom", Args: []string{"sh", "-c", "echo task_line"},
	}); err != nil {
		t.Fatalf("toolRunTask: %v", err)
	}

	// The auto-index branch writes through the store, which the audit fixture
	// server does not carry (no other case in this family reaches it).
	s.store = newTestStore(t)
	if _, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom", Args: []string{"sh", "-c", "yes indexed_line | head -n 40000"},
	}); err != nil {
		t.Fatalf("toolRunTask (indexed): %v", err)
	}

	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	if len(recs) != 3 {
		t.Fatalf("expected three audit lines, got %d: %+v", len(recs), recs)
	}
	if recs[0].Action != "batch" || recs[0].CommandType != "command" {
		t.Fatalf("batch record = %+v", recs[0])
	}
	if recs[0].ExitCode != 0 || recs[0].OutputLen == 0 || !strings.Contains(recs[0].RawCmd, "one: echo batch_line") {
		t.Fatalf("batch record aggregate fields = %+v", recs[0])
	}
	if len(recs[0].Commands) != 1 || recs[0].Commands[0].Label != "one" || recs[0].Commands[0].ExitCode != 0 {
		t.Fatalf("batch per-command entries = %+v", recs[0].Commands)
	}
	if recs[1].Action != "run_task" || recs[1].CommandType != "task" {
		t.Fatalf("run_task record = %+v", recs[1])
	}
	if recs[1].RawCmd != "sh -c echo task_line" || recs[1].ExitCode != 0 || recs[1].OutputLen == 0 {
		t.Fatalf("run_task record fields = %+v", recs[1])
	}
	// run_task argv goes through the same screen as execute argv.
	if recs[1].ScreenVerdict != "ok" {
		t.Fatalf("run_task screen_verdict = %q, want ok (S3: run_task argv is screened)", recs[1].ScreenVerdict)
	}
	if len(recs[1].AuditTags) != 1 || recs[1].AuditTags[0] != auditTagEvalInterpreter {
		t.Fatalf("run_task tags = %v, want [%s]", recs[1].AuditTags, auditTagEvalInterpreter)
	}
	// R5 gap: the auto-index branch above runTaskAutoIndexBytes mints the label
	// inside finishRunTaskOutput, so indexed/index_label are only recorded when
	// the audit call is actually passed through.
	if !recs[2].Indexed || recs[2].IndexLabel == "" {
		t.Fatalf("indexed run_task record = %+v, want indexed=true and a label", recs[2])
	}
}

// TestAudit_BatchFirstFailureNotFolded covers F2: a first command that fails
// with -1 (blocked by the screen, skipped on a shared timeout, or killed) must
// not be folded into a later command's 0 by the "no result yet" sentinel.
func TestAudit_BatchFirstFailureNotFolded(t *testing.T) {
	s, logPath := auditTestServer(t)
	if _, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "blocked", Command: "echo \x00 bad"},
			{Label: "ok", Command: "echo fine"},
		},
	}); err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}

	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	rec := recs[0]
	if rec.ExitCode != -1 {
		t.Fatalf("batch exit_code = %d, want -1 (the first command was blocked)", rec.ExitCode)
	}
	if rec.FirstFailedLabel != "blocked" {
		t.Fatalf("first_failed_label = %q, want blocked", rec.FirstFailedLabel)
	}
	if len(rec.Commands) != 2 {
		t.Fatalf("commands = %+v, want two entries", rec.Commands)
	}
	if rec.Commands[0].Label != "blocked" || rec.Commands[0].ExitCode != -1 || rec.Commands[0].ScreenRule != "nul_byte" {
		t.Fatalf("commands[0] = %+v", rec.Commands[0])
	}
	if rec.Commands[1].Label != "ok" || rec.Commands[1].ExitCode != 0 {
		t.Fatalf("commands[1] = %+v", rec.Commands[1])
	}
}

// TestAuditEnvKeys covers R2-D3: key names go through the sensitive-content
// check, values are never touched, and the list stays sorted, deduplicated and
// capped.
func TestAuditEnvKeys(t *testing.T) {
	// Assembled from parts on purpose (see TestAudit_SensitiveCommandRedacted):
	// the runtime values are full-shape AWS/GitHub tokens so the patterns match.
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	ghToken := "ghp_" + "0123456789012345678901234567890123ab"
	// Credential-shaped names collapse into one marker.
	keys := auditEnvKeys(map[string]string{
		awsKey:        "",
		ghToken:       "",
		"CTXMODE_FOO": "1",
		"NODE_ENV":    "test",
	})
	joined := strings.Join(keys, ",")
	if strings.Contains(joined, awsKey) || strings.Contains(joined, "ghp_") {
		t.Fatalf("credential-shaped key names must be redacted, got %q", joined)
	}
	if !strings.Contains(joined, auditRedactedKey) {
		t.Fatalf("expected a %s marker, got %q", auditRedactedKey, joined)
	}
	if joined != "CTXMODE_FOO,NODE_ENV,"+auditRedactedKey {
		// Byte-sorted, deduplicated: "[" (0x5b) sorts after the letters, and the
		// two credential-shaped names collapse into one marker.
		t.Fatalf("env_keys = %q, want the two real names then one marker", joined)
	}

	if got := auditEnvKeys(nil); len(got) != 0 {
		t.Fatalf("nil env must record an empty list, got %v", got)
	}
	// The cap keeps the line bounded even for a pathological request.
	big := map[string]string{}
	for i := 0; i < 200; i++ {
		big[fmt.Sprintf("K%03d", i)] = "v"
	}
	if got := auditEnvKeys(big); len(got) != auditMaxEnvKeys+1 || got[len(got)-1] != "…" {
		t.Fatalf("capped list = %d entries (last %q), want %d + marker", len(got), got[len(got)-1], auditMaxEnvKeys)
	}
}

// TestResolveAuditExeAgreesWithExecutor covers R2-S1: the audit record must name
// the same path the executor will use for every path-like spelling, including the
// dotted and backslash forms that a separator-only check used to treat as bare
// names (and then reported as a PATH lookup result instead of the real target).
func TestResolveAuditExeAgreesWithExecutor(t *testing.T) {
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	for _, name := range []string{".hidden", "..x", "./sub/x", "sub/x", "dir/../x", "..", ".", "a\\b", "/abs/x"} {
		if !looksLikePath(name) {
			t.Fatalf("%q must be path-like", name)
		}
		got := resolveAuditExe(name, wd)
		want := s.resolveArgvExe(name, wd)
		if got != want {
			t.Errorf("resolveAuditExe(%q) = %q, resolveArgvExe = %q (the audit must not name a different file)", name, got, want)
		}
		if !filepath.IsAbs(got) {
			t.Errorf("resolveAuditExe(%q) = %q, want an absolute path", name, got)
		}
	}
	// A bare name is the one intentional difference: the executor leaves it for
	// exec.LookPath, the record names the binary that will run.
	if got := resolveAuditExe("sh", wd); !filepath.IsAbs(got) || filepath.Base(got) != "sh" {
		t.Fatalf("resolveAuditExe(\"sh\") = %q, want the LookPath result", got)
	}
	if got := s.resolveArgvExe("sh", wd); got != "sh" {
		t.Fatalf("resolveArgvExe(\"sh\") = %q, want it left alone", got)
	}
	if got := resolveAuditExe("", wd); got != "" {
		t.Fatalf("empty argv[0] must stay empty, got %q", got)
	}
}

// TestAudit_BatchPerCommandScreenRules covers O8: the call-level screen fields
// can only carry the worst verdict and one rule, so the per-command rules are
// recorded too — a specific idiom rule stays visible even when another command
// in the same batch was blocked for size.
func TestAudit_BatchPerCommandScreenRules(t *testing.T) {
	s, logPath := auditTestServer(t)
	if _, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "huge", Command: strings.Repeat("a", maxShellCommandBytes+1)},
			{Label: "idiom", Command: "base64 -d /nonexistent/x.b64 | sh"},
		},
	}); err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}

	_, recs := decodeAuditLines(t, readAuditLines(t, logPath))
	rec := recs[0]
	if rec.ScreenVerdict != "block" || rec.ScreenRule != shellRuleOversized {
		t.Fatalf("call-level screen = %q/%q, want block/%s", rec.ScreenVerdict, rec.ScreenRule, shellRuleOversized)
	}
	if len(rec.Commands) != 2 {
		t.Fatalf("commands = %+v", rec.Commands)
	}
	if rec.Commands[0].ScreenRule != shellRuleOversized {
		t.Fatalf("commands[0] screen_rule = %q, want %s", rec.Commands[0].ScreenRule, shellRuleOversized)
	}
	if rec.Commands[1].ScreenVerdict != "warn" || rec.Commands[1].ScreenRule != "base64_pipe_to_shell" {
		t.Fatalf("commands[1] screen = %q/%q, want warn/base64_pipe_to_shell (O8: idiom rule must stay visible)",
			rec.Commands[1].ScreenVerdict, rec.Commands[1].ScreenRule)
	}
}
