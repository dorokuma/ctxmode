package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestClassifyError_EachBucket(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{"file_not_found", "ENOENT: no such file or directory, open '/tmp/x'", errorClassFileNotFound},
		{"command_not_found", "bash: foo: command not found", errorClassCommandNotFound},
		{"edit_match_failed", "old_string not found in file", errorClassEditMatchFailed},
		{"git_conflict", "CONFLICT (content): Merge conflict in foo.go", errorClassGitConflict},
		{"timeout", "Error: timed out after 30s", errorClassTimeout},
		{"permission_denied", "EACCES: permission denied, open '/etc/shadow'", errorClassPermissionDenied},
		{"syntax_error", "SyntaxError: unexpected token '{'", errorClassSyntaxError},
		{"test_failed", "FAIL src/foo.test.ts", errorClassTestFailed},
		{"runtime_error", "TypeError: cannot read property 'x' of undefined", errorClassRuntimeError},
		{"unknown", "something went sideways", errorClassUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyError(tc.msg)
			if got != tc.want {
				t.Fatalf("classifyError(%q) = %q, want %q", tc.msg, got, tc.want)
			}
		})
	}
}

func TestClassifyError_PriorityAndFallbacks(t *testing.T) {
	// Empty / malformed → unknown.
	if got := classifyError(""); got != errorClassUnknown {
		t.Fatalf("empty = %q, want unknown", got)
	}
	// file_not_found beats command_not_found (": not found" vs "no such file").
	if got := classifyError("no such file or directory"); got != errorClassFileNotFound {
		t.Fatalf("enoent-style = %q", got)
	}
	// Distinctive edit phrasing without a tool name.
	if got := classifyError("string to replace not found"); got != errorClassEditMatchFailed {
		t.Fatalf("edit phrasing = %q", got)
	}
	// git_conflict before test_failed.
	if got := classifyError("git merge failed with CONFLICT"); got != errorClassGitConflict {
		t.Fatalf("git+fail = %q", got)
	}
	// timeout before test_failed.
	if got := classifyError("test timed out after 10s"); got != errorClassTimeout {
		t.Fatalf("test timed out = %q", got)
	}
	// POSIX 127 via our execute suffix.
	if got := classifyError("(exited with code 127)"); got != errorClassCommandNotFound {
		t.Fatalf("exit 127 suffix = %q", got)
	}
	if got := classifyError("process exit code: 127"); got != errorClassCommandNotFound {
		t.Fatalf("exit code 127 = %q", got)
	}
	// tsc / python syntax.
	if got := classifyError("error TS2322: Type 'string' is not assignable"); got != errorClassSyntaxError {
		t.Fatalf("tsc = %q", got)
	}
	if got := classifyError("Traceback (most recent call last):\n  File"); got != errorClassRuntimeError {
		t.Fatalf("python traceback = %q", got)
	}
	// Success must not classify.
	if got := errorClassForExit(0, "permission denied"); got != "" {
		t.Fatalf("exit 0 must not classify, got %q", got)
	}
	if got := errorClassForExit(1, "permission denied"); got != errorClassPermissionDenied {
		t.Fatalf("exit 1 = %q", got)
	}
}

func TestPrefixErrorClass(t *testing.T) {
	if got := prefixErrorClass("body", ""); got != "body" {
		t.Fatalf("empty class must be no-op, got %q", got)
	}
	got := prefixErrorClass("body", errorClassTimeout)
	if got != "error_class: timeout\nbody" {
		t.Fatalf("prefixed = %q", got)
	}
}

func TestErrorClass_ExecuteMetaEvenWhenNotIndexed(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:  "echo permission denied; exit 1",
		Language: "shell",
		Timeout:  10000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	if res == nil || res.Meta == nil {
		t.Fatal("expected Meta.error_class on failed execute")
	}
	got, _ := res.Meta["error_class"].(string)
	if got != errorClassPermissionDenied {
		t.Fatalf("error_class = %q, want %s (meta=%v text=%q)", got, errorClassPermissionDenied, res.Meta, mcpResultText(t, res))
	}
	// Small output is not indexed.
	docs, _, _ := st.Stats()
	if docs != 0 {
		t.Fatalf("small failed output must not be indexed, docs=%d", docs)
	}
}

func TestErrorClass_ExecuteSuccessHasNoMeta(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:  "echo ok_success",
		Language: "shell",
		Timeout:  10000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	if res != nil && res.Meta != nil {
		if _, ok := res.Meta["error_class"]; ok {
			t.Fatalf("success must not set error_class, meta=%v", res.Meta)
		}
	}
}

func TestErrorClass_IndexedContentHeader(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	// >5KB + intent triggers index; non-zero exit triggers classification.
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Command:  "printf 'no such file or directory\\n'; head -c 6000 /dev/zero | tr '\\0' x; exit 1",
		Language: "shell",
		Intent:   "errcls",
		Timeout:  15000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	if res == nil || res.Meta == nil {
		t.Fatal("expected Meta.error_class")
	}
	if got, _ := res.Meta["error_class"].(string); got != errorClassFileNotFound {
		t.Fatalf("error_class = %q, want file_not_found", got)
	}
	text := mcpResultText(t, res)
	m := regexp.MustCompile(`(?i)indexed as "([^"]+)"`).FindStringSubmatch(text)
	if len(m) != 2 {
		t.Fatalf("cannot extract index label from:\n%s", text)
	}
	doc, err := st.Get(m[1])
	if err != nil || doc == nil {
		t.Fatalf("indexed doc %q missing: %v", m[1], err)
	}
	if !strings.HasPrefix(doc.Content, "error_class: file_not_found\n") {
		t.Fatalf("indexed content must start with error_class header, got prefix %q", doc.Content[:min(60, len(doc.Content))])
	}
}

func TestErrorClass_BatchPerCommandAndMeta(t *testing.T) {
	st := newTestStore(t)
	fg := NewFloodGuard(60*time.Second, 64)
	s := &server{
		workdirs:       []string{t.TempDir()},
		store:          st,
		floodGuard:     fg,
		searchPipeline: NewSearchPipeline(st, fg),
	}
	res, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "fail", Command: "echo 'bash: zzz: command not found'; exit 127"},
			{Label: "ok", Command: "echo tiny_ok"},
		},
	})
	if err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	if res == nil || res.Meta == nil {
		t.Fatal("expected Meta.error_class when a batch command fails")
	}
	if got, _ := res.Meta["error_class"].(string); got != errorClassCommandNotFound {
		t.Fatalf("batch meta error_class = %q", got)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, `"error_class": "command_not_found"`) {
		t.Fatalf("per-command error_class missing from JSON:\n%s", text)
	}
}

func TestErrorClass_BatchEmptyOutputExit127(t *testing.T) {
	st := newTestStore(t)
	fg := NewFloodGuard(60*time.Second, 64)
	s := &server{
		workdirs:       []string{t.TempDir()},
		store:          st,
		floodGuard:     fg,
		searchPipeline: NewSearchPipeline(st, fg),
	}
	res, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "missing", Command: "exit 127"},
		},
	})
	if err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	if res == nil || res.Meta == nil {
		t.Fatal("expected Meta.error_class for empty-output exit 127")
	}
	if got, _ := res.Meta["error_class"].(string); got != errorClassCommandNotFound {
		t.Fatalf("empty output exit 127 error_class = %q, want command_not_found (text=%s)", got, mcpResultText(t, res))
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, `"error_class": "command_not_found"`) {
		t.Fatalf("per-command error_class missing from JSON:\n%s", text)
	}
}

func TestErrorClass_BatchIndexedContentHeader(t *testing.T) {
	st := newTestStore(t)
	fg := NewFloodGuard(60*time.Second, 64)
	s := &server{
		workdirs:       []string{t.TempDir()},
		store:          st,
		floodGuard:     fg,
		searchPipeline: NewSearchPipeline(st, fg),
	}
	res, _, err := s.toolBatchExecute(context.Background(), nil, batchArgs{
		Commands: []batchCommand{
			{Label: "bigfail", Command: "head -c 102500 /dev/zero | tr '\\0' 'x'; exit 127"},
		},
	})
	if err != nil {
		t.Fatalf("toolBatchExecute: %v", err)
	}
	text := mcpResultText(t, res)
	var resp batchResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, text)
	}
	if len(resp.Commands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(resp.Commands))
	}
	r := resp.Commands[0]
	if !r.Indexed || r.IndexLabel == "" {
		t.Fatalf("large failed output must be indexed: %+v", r)
	}
	if r.ErrorClass != errorClassCommandNotFound {
		t.Fatalf("error_class = %q, want command_not_found", r.ErrorClass)
	}
	doc, err := st.Get(r.IndexLabel)
	if err != nil || doc == nil {
		t.Fatalf("indexed doc %q missing: %v", r.IndexLabel, err)
	}
	if !strings.HasPrefix(doc.Content, "error_class: command_not_found\n") {
		prefix := doc.Content
		if len(prefix) > 60 {
			prefix = prefix[:60]
		}
		t.Fatalf("indexed content must start with error_class header, got prefix %q", prefix)
	}
}

func TestErrorClass_RunTaskCustom(t *testing.T) {
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: newTestStore(t)}
	res, _, err := s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind:      "custom",
		Args:      []string{"sh", "-c", "echo 'SyntaxError: unexpected token'; exit 1"},
		TimeoutMs: 10000,
		CWD:       wd,
	})
	if err != nil {
		t.Fatalf("toolRunTask: %v", err)
	}
	if res == nil || res.Meta == nil {
		t.Fatal("expected Meta.error_class")
	}
	if got, _ := res.Meta["error_class"].(string); got != errorClassSyntaxError {
		t.Fatalf("run_task error_class = %q, text=%s", got, mcpResultText(t, res))
	}
}

func TestErrorClass_ExecuteFileMeta(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	st := newTestStore(t)
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "data.txt"), "hello")
	s := &server{workdirs: []string{wd}, store: st}
	res, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     "data.txt",
		Code:     "import sys; print('Traceback (most recent call last):'); sys.exit(1)",
		Language: "python",
		Timeout:  15000,
	})
	if err != nil {
		t.Fatalf("toolExecuteFile: %v", err)
	}
	if res == nil || res.Meta == nil {
		t.Fatal("expected Meta.error_class")
	}
	if got, _ := res.Meta["error_class"].(string); got != errorClassRuntimeError {
		t.Fatalf("execute_file error_class = %q text=%s", got, mcpResultText(t, res))
	}
}
