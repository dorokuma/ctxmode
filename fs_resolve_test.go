package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func setupResolveFixture(t *testing.T) (wd string, s *server) {
	t.Helper()
	wd = t.TempDir()
	mustWrite(t, filepath.Join(wd, "a.go"), "package main\n")
	mustWrite(t, filepath.Join(wd, "sub", "c.go"), "package sub\n")
	mustWrite(t, filepath.Join(wd, "sub", "deep", "deep_helper.go"), "package deep\n")
	mustWrite(t, filepath.Join(wd, "vendor", "x.go"), "package vendor\n")
	mustWrite(t, filepath.Join(wd, "c.spec.ts"), "export {}\n")
	mustWrite(t, filepath.Join(wd, ".env"), "SECRET=1\n")
	return wd, testServerWithWorkdir(t, wd)
}

func TestFuzzyScoreTiers(t *testing.T) {
	if score, ok := fuzzyScore("c.go", "/w/sub/c.go"); !ok || score < 80 {
		t.Fatalf("exact basename match should score high, got %v ok=%v", score, ok)
	}
	if score, ok := fuzzyScore("cgo", "/w/sub/c.go"); !ok || score <= 0 {
		t.Fatalf("subsequence should match, got %v ok=%v", score, ok)
	}
	if score, ok := fuzzyScore("helper", "/w/sub/deep/deep_helper.go"); !ok || score <= 40 {
		t.Fatalf("substring should match, got %v ok=%v", score, ok)
	}
	if _, ok := fuzzyScore("zzz", "/w/sub/c.go"); ok {
		t.Fatal("non-match should be rejected")
	}
	// Scattered subsequence over a long span must lose to a close substring.
	scattered, ok1 := fuzzyScore("sbh", "/w/a_very_long_directory_name/sub/deep/deep_helper.go")
	closeSub, ok2 := fuzzyScore("helper", "/w/sub/deep/deep_helper.go")
	if !ok1 || !ok2 || scattered >= closeSub {
		t.Fatalf("span normalization failed: scattered=%v close=%v", scattered, closeSub)
	}
}

func TestToolResolveRanksAndFences(t *testing.T) {
	wd, s := setupResolveFixture(t)
	res, _, err := s.toolResolve(context.Background(), nil, resolveArgs{Path: "c.go", Limit: 5})
	if err != nil {
		t.Fatalf("toolResolve: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, wd) {
		t.Fatalf("resolve leaked host prefix: %s", text)
	}
	var parsed struct {
		Count   int `json:"count"`
		Matches []struct {
			Path string `json:"path"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("json: %v\n%s", err, text)
	}
	if parsed.Count == 0 {
		t.Fatalf("no matches: %s", text)
	}
	if !strings.HasSuffix(parsed.Matches[0].Path, "c.go") {
		t.Fatalf("top match should be c.go, got %q", parsed.Matches[0].Path)
	}
	if strings.Contains(text, "vendor") || strings.Contains(text, ".env") {
		t.Fatalf("walk fence leaked ignored/sensitive files: %s", text)
	}
}

func TestToolResolveAtPrefixAndLimit(t *testing.T) {
	_, s := setupResolveFixture(t)
	res, _, err := s.toolResolve(context.Background(), nil, resolveArgs{Path: "@c", Limit: 1})
	if err != nil {
		t.Fatalf("toolResolve @-prefix: %v", err)
	}
	text := mcpResultText(t, res)
	var parsed struct {
		Count     int  `json:"count"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("json: %v", err)
	}
	if parsed.Count != 1 || !parsed.Truncated {
		t.Fatalf("limit not applied: %s", text)
	}
	if _, _, err := s.toolResolve(context.Background(), nil, resolveArgs{Path: ""}); err == nil {
		t.Fatal("empty query should error")
	}
}

func TestToolRelatedPairs(t *testing.T) {
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "pkg", "user.go"), "package pkg\n")
	mustWrite(t, filepath.Join(wd, "pkg", "user_test.go"), "package pkg\n")
	mustWrite(t, filepath.Join(wd, "web", "user.ts"), "export {}\n")
	mustWrite(t, filepath.Join(wd, "web", "user.tsx"), "export {}\n")
	mustWrite(t, filepath.Join(wd, "pkg", "unrelated.txt"), "x\n")
	s := testServerWithWorkdir(t, wd)

	res, _, err := s.toolRelated(context.Background(), nil, relatedArgs{Path: filepath.Join(wd, "pkg", "user.go")})
	if err != nil {
		t.Fatalf("toolRelated: %v", err)
	}
	text := mcpResultText(t, res)
	var parsed struct {
		Related []struct {
			Path   string  `json:"path"`
			Score  float64 `json:"score"`
			Reason string  `json:"reason"`
		} `json:"related"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("json: %v\n%s", err, text)
	}
	if len(parsed.Related) == 0 {
		t.Fatalf("no related hits: %s", text)
	}
	if !strings.HasSuffix(parsed.Related[0].Path, "user_test.go") || parsed.Related[0].Score != 100 {
		t.Fatalf("top related should be the Go test pair, got %+v", parsed.Related[0])
	}

	res, _, err = s.toolRelated(context.Background(), nil, relatedArgs{Path: filepath.Join(wd, "web", "user.ts")})
	if err != nil {
		t.Fatalf("toolRelated ts: %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "user.tsx") {
		t.Fatalf("same-family stem pair missing: %s", text)
	}
	if _, _, err := s.toolRelated(context.Background(), nil, relatedArgs{Path: ""}); err == nil {
		t.Fatal("empty path should error")
	}
}

func TestSplitStemExtAndPairStem(t *testing.T) {
	stem, ext := splitStemExt("user_test.go")
	if stem != "user_test" || ext != ".go" {
		t.Fatalf("splitStemExt: %q %q", stem, ext)
	}
	if got := pairStem("user_test", ".go"); got != "user" {
		t.Fatalf("pairStem go: %q", got)
	}
	if got := pairStem("user.test", ".ts"); got != "user" {
		t.Fatalf("pairStem ts: %q", got)
	}
	if got := pairStem("test_user", ".py"); got != "user" {
		t.Fatalf("pairStem py: %q", got)
	}
	if got := pairStem("user", ".go"); got != "user" {
		t.Fatalf("pairStem impl: %q", got)
	}
}
