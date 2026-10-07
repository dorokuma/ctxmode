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

// TestToolRelatedSiblingBeatsStemPrefix pins the documented tier order:
// a same-directory sibling (score 40) outranks a stem-prefix match (score 30).
// The fixture makes the two tiers compete — the sibling's stem is also a
// longer prefix of the target's stem, with both stems >= 4 characters — so a
// reordered switch lets the 30 tier capture the file and makes the 40 tier
// unreachable for it.
func TestToolRelatedSiblingBeatsStemPrefix(t *testing.T) {
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "pkg", "user.go"), "package pkg\n")
	mustWrite(t, filepath.Join(wd, "pkg", "user_profile.go"), "package pkg\n")
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
	if len(parsed.Related) != 1 {
		t.Fatalf("expected exactly the sibling hit, got %+v", parsed.Related)
	}
	got := parsed.Related[0]
	if !strings.HasSuffix(got.Path, "user_profile.go") {
		t.Fatalf("unexpected hit %q", got.Path)
	}
	if got.Score != 40 {
		t.Fatalf("same-directory sibling must take the score 40 tier, got %v (reason %q)", got.Score, got.Reason)
	}
	if !strings.HasPrefix(got.Reason, "sibling in ") {
		t.Fatalf("reason should name the sibling tier, got %q", got.Reason)
	}
}

// TestToolResolveTruncatedOnFileCap pins that stopping the workspace walk on
// its file cap is reported as truncated:true instead of being returned as a
// complete result. The cap is lowered through the server's test hook, which is
// also the only way to reach the early-stop branch without a 100k-file
// fixture; the wall-clock branch shares the same code path.
func TestToolResolveTruncatedOnFileCap(t *testing.T) {
	wd := t.TempDir()
	for _, name := range []string{"alpha_match.go", "beta_match.go", "gamma_match.go"} {
		mustWrite(t, filepath.Join(wd, name), "package main\n")
	}
	s := testServerWithWorkdir(t, wd)
	s.scanMaxFilesOverride = 2

	res, _, err := s.toolResolve(context.Background(), nil, resolveArgs{Path: "match.go", Limit: 50})
	if err != nil {
		t.Fatalf("toolResolve: %v", err)
	}
	text := mcpResultText(t, res)
	var parsed struct {
		Count     int  `json:"count"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Fatalf("json: %v\n%s", err, text)
	}
	if parsed.Count >= 3 {
		t.Fatalf("the cap should have stopped the walk before all three files: %s", text)
	}
	if !parsed.Truncated {
		t.Fatalf("exhausting the file cap must set truncated=true: %s", text)
	}
}

// TestToolResolveQuotedAtReference documents the accepted input spellings. The
// bare "@path" prefix is stripped, while quotes are trimmed after that prefix,
// so a quoted reference keeps its "@" and is matched literally (it cannot hit a
// file whose path has no "@").
func TestToolResolveQuotedAtReference(t *testing.T) {
	_, s := setupResolveFixture(t)

	bare, _, err := s.toolResolve(context.Background(), nil, resolveArgs{Path: "@c.go", Limit: 5})
	if err != nil {
		t.Fatalf("toolResolve bare @: %v", err)
	}
	var bareParsed struct {
		Matches []struct {
			Path string `json:"path"`
		} `json:"matches"`
	}
	if err := json.Unmarshal([]byte(mcpResultText(t, bare)), &bareParsed); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(bareParsed.Matches) == 0 || !strings.HasSuffix(bareParsed.Matches[0].Path, "c.go") {
		t.Fatalf("bare @c.go should resolve c.go first, got %+v", bareParsed.Matches)
	}

	quoted, _, err := s.toolResolve(context.Background(), nil, resolveArgs{Path: `"@c.go"`, Limit: 5})
	if err != nil {
		t.Fatalf("toolResolve quoted @: %v", err)
	}
	var quotedParsed struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(mcpResultText(t, quoted)), &quotedParsed); err != nil {
		t.Fatalf("json: %v", err)
	}
	if quotedParsed.Count != 0 {
		t.Fatalf("quoted @c.go is matched literally and should hit nothing, got count=%d", quotedParsed.Count)
	}
}
