package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// 10-bucket error_class ABI. Matching rules follow
// github.com/mksglu/context-mode src/session/error-classifier.ts
// (most-specific first).
const (
	errorClassFileNotFound     = "file_not_found"
	errorClassCommandNotFound  = "command_not_found"
	errorClassEditMatchFailed  = "edit_match_failed"
	errorClassGitConflict      = "git_conflict"
	errorClassTimeout          = "timeout"
	errorClassPermissionDenied = "permission_denied"
	errorClassSyntaxError      = "syntax_error"
	errorClassTestFailed       = "test_failed"
	errorClassRuntimeError     = "runtime_error"
	errorClassUnknown          = "unknown"
)

var (
	reExit127      = regexp.MustCompile(`\bexit(?:\s+code)?\s*[:=]?\s*127\b`)
	reTSError      = regexp.MustCompile(`\berror\s+ts\d{3,5}\b`)
	reFailThenTest = regexp.MustCompile(`\bfail(?:ed)?\b.*\btest\b`)
	reNTestsFailed = regexp.MustCompile(`\b\d+\s+tests?\s+failed\b`)
	reFailLine     = regexp.MustCompile(`(?:^|\n)fail\s`)
)

// classifyError maps an error message into one of the 10 fixed buckets.
// Empty input yields unknown. Never panics.
func classifyError(message string) string {
	msg := strings.ToLower(message)
	if msg == "" {
		return errorClassUnknown
	}

	// file_not_found
	if strings.Contains(msg, "enoent") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "cannot find module") ||
		strings.Contains(msg, "filenotfounderror") {
		return errorClassFileNotFound
	}

	// command_not_found (POSIX 127, including our "(exited with code 127)" suffix)
	if strings.Contains(msg, "command not found") ||
		strings.Contains(msg, ": not found") ||
		strings.Contains(msg, "exited with code 127") ||
		reExit127.MatchString(msg) {
		return errorClassCommandNotFound
	}

	// edit_match_failed — distinctive Edit-tool phrasing (no tool-name gate)
	if strings.Contains(msg, "old_string not found") ||
		strings.Contains(msg, "string to replace not found") {
		return errorClassEditMatchFailed
	}

	// git_conflict — before test_failed ("CONFLICT" can co-occur with "fail")
	if strings.Contains(msg, "conflict") &&
		(strings.Contains(msg, "merge") || strings.Contains(msg, "rebase") || strings.Contains(msg, "git")) {
		return errorClassGitConflict
	}
	if strings.HasPrefix(msg, "conflict") || strings.Contains(msg, "merge conflict") {
		return errorClassGitConflict
	}

	// timeout — before test_failed ("test timed out")
	if strings.Contains(msg, "etimedout") ||
		strings.Contains(msg, "timed out") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") {
		return errorClassTimeout
	}

	// permission_denied
	if strings.Contains(msg, "eacces") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "eperm") {
		return errorClassPermissionDenied
	}

	// syntax_error
	if strings.Contains(msg, "syntaxerror") ||
		reTSError.MatchString(msg) ||
		strings.Contains(msg, "unexpected token") ||
		strings.Contains(msg, "unexpected end of") ||
		strings.Contains(msg, "parse error") {
		return errorClassSyntaxError
	}

	// test_failed
	if strings.Contains(msg, "test failed") ||
		strings.Contains(msg, "tests failed") ||
		reFailThenTest.MatchString(msg) ||
		reNTestsFailed.MatchString(msg) ||
		strings.Contains(msg, "assertion") ||
		reFailLine.MatchString(msg) {
		return errorClassTestFailed
	}

	// runtime_error
	if strings.Contains(msg, "typeerror") ||
		strings.Contains(msg, "referenceerror") ||
		strings.Contains(msg, "rangeerror") ||
		strings.Contains(msg, "uncaught exception") ||
		strings.Contains(msg, "traceback (most recent call last)") ||
		strings.Contains(msg, "nullpointerexception") {
		return errorClassRuntimeError
	}

	return errorClassUnknown
}

// errorClassForExit classifies failed runs (exit != 0). Success returns "".
// Always folds "(exited with code N)" into the classifier input so empty
// output with POSIX 127 is command_not_found across execute/batch/run_task.
// The execute path may already append "(exited with code N)" to outputText
// before calling this; folding then duplicates the suffix. Classification
// uses existence matches (strings.Contains / regexp), so a repeated suffix
// is idempotent and harmless.
func errorClassForExit(exitCode int, output string) string {
	if exitCode == 0 {
		return ""
	}
	msg := output
	if msg != "" {
		msg += "\n"
	}
	msg += fmt.Sprintf("(exited with code %d)", exitCode)
	return classifyError(msg)
}

// prefixErrorClass annotates indexed KB content. No-op when class is empty.
func prefixErrorClass(content, class string) string {
	if class == "" {
		return content
	}
	return "error_class: " + class + "\n" + content
}

// withErrorClassMeta sets CallToolResult._meta.error_class when class is non-empty.
func withErrorClassMeta(res *mcp.CallToolResult, class string) *mcp.CallToolResult {
	if res == nil || class == "" {
		return res
	}
	if res.Meta == nil {
		res.Meta = mcp.Meta{}
	}
	res.Meta["error_class"] = class
	return res
}

func textResult(text, errorClass string) *mcp.CallToolResult {
	return withErrorClassMeta(&mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}, errorClass)
}
