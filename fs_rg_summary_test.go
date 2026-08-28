package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGroupRgLines_ContextAttached(t *testing.T) {
	input := []string{
		"pkg/foo-bar.go:10:func DoWork() {",
		"pkg/foo-bar.go-11-    // context line 1",
		"pkg/foo-bar.go-12-    // context line 2",
		"--",
		"pkg/foo-bar.go:20:func AnotherWork() {",
		"other/baz.go:5:const Pi = 3.14",
	}

	groups := groupRgLines(input)
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	if groups[0].file != "pkg/foo-bar.go" {
		t.Errorf("group 0 file expected 'pkg/foo-bar.go', got %q", groups[0].file)
	}
	if groups[0].hits != 2 {
		t.Errorf("group 0 hits expected 2, got %d", groups[0].hits)
	}
	if len(groups[0].lines) != 5 {
		t.Errorf("group 0 lines count expected 5, got %d", len(groups[0].lines))
	}

	if groups[1].file != "other/baz.go" {
		t.Errorf("group 1 file expected 'other/baz.go', got %q", groups[1].file)
	}
	if groups[1].hits != 1 {
		t.Errorf("group 1 hits expected 1, got %d", groups[1].hits)
	}

	rendered := renderGroups(groups)
	expectedRendered := "pkg/foo-bar.go:10:func DoWork() {\npkg/foo-bar.go-11-    // context line 1\npkg/foo-bar.go-12-    // context line 2\n--\npkg/foo-bar.go:20:func AnotherWork() {\nother/baz.go:5:const Pi = 3.14"
	if rendered != expectedRendered {
		t.Errorf("rendered output mismatch.\nGot:\n%s\nWant:\n%s", rendered, expectedRendered)
	}
}

// 7.1 A/B Golden Before/After
func TestRgAB_Golden_BeforeAfter(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	origGit := rgGitRankEnabled
	rgGitRankEnabled = true
	defer func() { rgGitRankEnabled = origGit }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "1f3e9a44b7c2",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	// 1. noise.ts: 30 matches
	var noiseContent strings.Builder
	for i := 1; i <= 30; i++ {
		noiseContent.WriteString(fmt.Sprintf("// TODO: noise item %d\n", i))
	}
	commitFile(t, repoDir, "noise.ts", noiseContent.String(), "commit noise")

	// 2. app.ts: 2 matches (committed then modified)
	commitFile(t, repoDir, "app.ts", "// TODO: initial app todo\n", "commit app")
	mustWrite(t, filepath.Join(repoDir, "app.ts"), "// TODO: refactor auth flow\n// line\n// TODO: handle token expiry\n")

	// 3. utils.ts: 1 match (untracked)
	mustWrite(t, filepath.Join(repoDir, "utils.ts"), "// TODO: dedupe helper functions\n")

	// Execute with default limit (20)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "TODO",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}

	text := mcpResultText(t, res)
	t.Logf("Golden Output:\n%s", text)

	// Assert B key elements
	if !strings.Contains(text, "matches=33") {
		t.Errorf("expected matches=33 in header, got: %s", text)
	}
	if !strings.Contains(text, "files=3") {
		t.Errorf("expected files=3 in header, got: %s", text)
	}
	if !strings.Contains(text, "limit=20") {
		t.Errorf("expected limit=20 in header, got: %s", text)
	}
	if !strings.Contains(text, "git_dirty=2") {
		t.Errorf("expected git_dirty=2 in header, got: %s", text)
	}
	if !strings.Contains(text, "indexed=session:1f3e9a44b7c2:rg:TODO:") {
		t.Errorf("expected indexed label with session:1f3e9a44b7c2:rg:TODO: prefix, got: %s", text)
	}

	// Assert ordering: app.ts (dirty) appears before noise.ts (clean)
	appIdx := strings.Index(text, "* app.ts")
	noiseIdx := strings.Index(text, "noise.ts")
	utilsIdx := strings.Index(text, "* utils.ts")
	if appIdx < 0 || noiseIdx < 0 || utilsIdx < 0 {
		t.Fatalf("expected * app.ts, * utils.ts and noise.ts in summary, got: %s", text)
	}
	if appIdx > noiseIdx || utilsIdx > noiseIdx {
		t.Errorf("expected dirty files (* app.ts, * utils.ts) before noise.ts in summary")
	}

	// Extract indexed label from header
	var label string
	for _, part := range strings.Split(strings.Split(text, "\n")[0], " ") {
		if strings.HasPrefix(part, "indexed=") {
			label = strings.TrimPrefix(part, "indexed=")
			break
		}
	}
	if label == "" {
		t.Fatalf("could not extract indexed label from output: %s", text)
	}

	doc, err := st.Get(label)
	if err != nil || doc == nil {
		t.Fatalf("expected indexed doc in store for label %q, err=%v", label, err)
	}

	// Verify indexed document contains all 33 match lines
	docHits := 0
	for _, l := range strings.Split(doc.Content, "\n") {
		if isRgMatchLine(l) {
			docHits++
		}
	}
	if docHits != 33 {
		t.Errorf("expected 33 indexed match lines in store doc, got %d. Content:\n%s", docHits, doc.Content)
	}
}

// 9. TestRgSummary_TriggerAndFormat
func TestRgSummary_TriggerAndFormat(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess1",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	// Create 25 matching lines across 2 files
	var f1 strings.Builder
	for i := 0; i < 20; i++ {
		f1.WriteString("MATCH_TOKEN line\n")
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	var f2 strings.Builder
	for i := 0; i < 5; i++ {
		f2.WriteString("MATCH_TOKEN line\n")
	}
	commitFile(t, repoDir, "f2.txt", f2.String(), "commit f2")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "MATCH_TOKEN",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "matches=25") || !strings.Contains(text, "files=2") || !strings.Contains(text, "indexed=") {
		t.Fatalf("unexpected summary format: %s", text)
	}
	if !strings.Contains(text, "Retrieve details: ctx_kb action=search query=") {
		t.Fatalf("expected retrieval guidance in summary: %s", text)
	}
}

// 10. TestRgSummary_NoTrigger_UnderLimit
func TestRgSummary_NoTrigger_UnderLimit(t *testing.T) {
	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess1",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	var f1 strings.Builder
	for i := 0; i < 15; i++ {
		f1.WriteString("UNDER_LIMIT_TOKEN line\n")
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "UNDER_LIMIT_TOKEN",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "indexed=") {
		t.Errorf("under-limit search should NOT index: %s", text)
	}
	if !strings.Contains(text, "f1.txt:1:UNDER_LIMIT_TOKEN") {
		t.Errorf("under-limit search should return raw lines: %s", text)
	}
}

// 11. TestRgSummary_ExplicitLimitRespected
func TestRgSummary_ExplicitLimitRespected(t *testing.T) {
	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess1",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	var f1 strings.Builder
	for i := 0; i < 33; i++ {
		f1.WriteString("EXPLICIT_LIMIT_TOKEN line\n")
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	// Pass limit=100 (> 33)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "EXPLICIT_LIMIT_TOKEN",
		Path:    repoDir,
		Limit:   100,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "indexed=") {
		t.Errorf("explicit limit=100 with 33 hits should NOT index: %s", text)
	}
	if !strings.Contains(text, "limit=100") || !strings.Contains(text, "f1.txt:33:EXPLICIT_LIMIT_TOKEN") {
		t.Errorf("expected all raw lines up to 33: %s", text)
	}
}

// 12. TestRgSummary_DedupReusesLabel
func TestRgSummary_DedupReusesLabel(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess1",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	var f1 strings.Builder
	for i := 0; i < 25; i++ {
		f1.WriteString("DEDUP_TOKEN line\n")
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	// 1st query
	res1, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "DEDUP_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("1st toolRg failed: %v", err)
	}
	text1 := mcpResultText(t, res1)

	// 2nd identical query
	res2, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "DEDUP_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("2nd toolRg failed: %v", err)
	}
	text2 := mcpResultText(t, res2)

	var label1, label2 string
	for _, p := range strings.Split(strings.Split(text1, "\n")[0], " ") {
		if strings.HasPrefix(p, "indexed=") {
			label1 = p
		}
	}
	for _, p := range strings.Split(strings.Split(text2, "\n")[0], " ") {
		if strings.HasPrefix(p, "indexed=") {
			label2 = p
		}
	}
	if label1 == "" || label1 != label2 {
		t.Fatalf("expected reused label, got label1=%q label2=%q", label1, label2)
	}
	if !strings.Contains(text2, "reused") {
		t.Errorf("expected reused marker in summary: %s", text2)
	}
}

// 13. TestRgSummary_DedupContentChange
func TestRgSummary_DedupContentChange(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess1",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	var f1 strings.Builder
	for i := 0; i < 25; i++ {
		f1.WriteString("CONTENT_CHANGE_TOKEN line\n")
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	res1, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "CONTENT_CHANGE_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("1st toolRg failed: %v", err)
	}
	text1 := mcpResultText(t, res1)

	// Modify file content to produce different matches
	mustWrite(t, filepath.Join(repoDir, "f1.txt"), f1.String()+"CONTENT_CHANGE_TOKEN newly added line\n")

	res2, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "CONTENT_CHANGE_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("2nd toolRg failed: %v", err)
	}
	text2 := mcpResultText(t, res2)

	var label1, label2 string
	for _, p := range strings.Split(strings.Split(text1, "\n")[0], " ") {
		if strings.HasPrefix(p, "indexed=") {
			label1 = p
		}
	}
	for _, p := range strings.Split(strings.Split(text2, "\n")[0], " ") {
		if strings.HasPrefix(p, "indexed=") {
			label2 = p
		}
	}
	if label1 == label2 {
		t.Fatalf("expected new label after content change, got same %q", label1)
	}
}

// 14. TestRgSummary_SensitiveFallback
func TestRgSummary_SensitiveFallback(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess1",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	// 25 lines containing AWS access key pattern
	fakeKey := "AKIA" + "IOSFODNN7EXAMPLE"
	var f1 strings.Builder
	for i := 0; i < 25; i++ {
		f1.WriteString(fakeKey + " secret_key_probe\n")
	}
	commitFile(t, repoDir, "secret.txt", f1.String(), "commit secrets")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "secret_key_probe",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "indexed=") {
		t.Errorf("sensitive content must NOT be indexed: %s", text)
	}
	if !strings.Contains(text, "sensitive content detected") {
		t.Errorf("expected sensitive fallback note: %s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Errorf("expected truncated=true in fallback: %s", text)
	}
}

// 15. TestRgSummary_NoStoreFallback
func TestRgSummary_NoStoreFallback(t *testing.T) {
	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	s := &server{
		workdirs:      []string{repoDir},
		store:         nil, // no store
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}

	var f1 strings.Builder
	for i := 0; i < 30; i++ {
		f1.WriteString("NO_STORE_TOKEN line\n")
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "NO_STORE_TOKEN",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "indexed=") {
		t.Errorf("no-store server must NOT index: %s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Errorf("expected truncated=true on fallback: %s", text)
	}
}

// 16. TestRgOffset_Paging
func TestRgOffset_Paging(t *testing.T) {
	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	s := &server{
		workdirs:      []string{repoDir},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}

	var f1 strings.Builder
	for i := 1; i <= 33; i++ {
		f1.WriteString(fmt.Sprintf("PAGING_TOKEN line %02d\n", i))
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	// Paging: offset=20, default limit=20 -> lines 21..33 (13 lines)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "PAGING_TOKEN",
		Path:    repoDir,
		Offset:  20,
	})
	if err != nil {
		t.Fatalf("toolRg offset=20 failed: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "offset=20") {
		t.Errorf("expected offset=20 in header: %s", text)
	}
	if !strings.Contains(text, "f1.txt:21:PAGING_TOKEN line 21") {
		t.Errorf("expected line 21 in paged output: %s", text)
	}
	if !strings.Contains(text, "f1.txt:33:PAGING_TOKEN line 33") {
		t.Errorf("expected line 33 in paged output: %s", text)
	}
	if strings.Contains(text, "f1.txt:20:PAGING_TOKEN") {
		t.Errorf("line 20 should have been skipped by offset=20: %s", text)
	}

	// offset=33 -> empty results with matches=33
	resEmpty, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "PAGING_TOKEN",
		Path:    repoDir,
		Offset:  33,
	})
	if err != nil {
		t.Fatalf("toolRg offset=33 failed: %v", err)
	}
	textEmpty := mcpResultText(t, resEmpty)
	if !strings.Contains(textEmpty, "(no matches)") || !strings.Contains(textEmpty, "matches=33") {
		t.Errorf("expected (no matches) with matches=33 for offset=33, got: %s", textEmpty)
	}

	// invalid offsets: offset < 0 and offset+limit > 500
	_, _, err = s.toolRg(context.Background(), nil, rgArgs{Pattern: "PAGING_TOKEN", Path: repoDir, Offset: -1})
	if err == nil {
		t.Errorf("expected error for offset < 0")
	}

	_, _, err = s.toolRg(context.Background(), nil, rgArgs{Pattern: "PAGING_TOKEN", Path: repoDir, Offset: 490, Limit: 20})
	if err == nil {
		t.Errorf("expected error for offset+limit > 500")
	}
}

// 17. TestRgOffset_HeaderCarriesLabel
func TestRgOffset_HeaderCarriesLabel(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess1",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	var f1 strings.Builder
	for i := 1; i <= 30; i++ {
		f1.WriteString(fmt.Sprintf("LABEL_CARRY_TOKEN %d\n", i))
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	// Trigger indexing with offset=0
	res1, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "LABEL_CARRY_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("toolRg 1 failed: %v", err)
	}
	text1 := mcpResultText(t, res1)
	if !strings.Contains(text1, "indexed=") {
		t.Fatalf("expected indexed label in 1st query: %s", text1)
	}

	// 2nd query with offset=20
	res2, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "LABEL_CARRY_TOKEN", Path: repoDir, Offset: 20})
	if err != nil {
		t.Fatalf("toolRg 2 failed: %v", err)
	}
	text2 := mcpResultText(t, res2)
	if !strings.Contains(text2, "indexed=") {
		t.Errorf("expected header to carry indexed label in offset query: %s", text2)
	}
}

// 18. TestKbSearch_ScopeRg_FloodFree
func TestKbSearch_ScopeRg_FloodFree(t *testing.T) {
	st := newTestStore(t)
	fg := NewFloodGuard(60*time.Second, 64)
	sp := NewSearchPipeline(st, fg)
	s := &server{
		sessionID:      "testsession",
		store:          st,
		floodGuard:     fg,
		searchPipeline: sp,
	}

	// Index an rg label
	label := s.indexLabel("rg", "myquery")
	indexDoc(t, st, label, "matched_content_term here in doc")

	// toolSearch with invalid scope -> error
	_, _, err := s.toolSearch(context.Background(), nil, searchArgs{Query: "matched_content_term", Scope: "invalid_scope"})
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}

	// Exhaust flood guard
	for i := 0; i < 20; i++ {
		fg.Allow()
	}

	// Global search should fail due to flood guard
	resGlobal, _, err := s.toolSearch(context.Background(), nil, searchArgs{Query: "matched_content_term"})
	if err != nil || !resGlobal.IsError {
		t.Fatalf("expected flood-blocked error result for global search, res=%v err=%v", resGlobal, err)
	}

	// toolSearch with scope=rg should succeed and bypass flood guard
	resScoped, _, err := s.toolSearch(context.Background(), nil, searchArgs{Query: "matched_content_term", Scope: "rg"})
	if err != nil {
		t.Fatalf("toolSearch scope=rg failed: %v", err)
	}
	if resScoped.IsError {
		t.Fatalf("toolSearch scope=rg returned error: %s", mcpResultText(t, resScoped))
	}
	if !strings.Contains(mcpResultText(t, resScoped), "matched_content_term") {
		t.Fatalf("expected match in result: %s", mcpResultText(t, resScoped))
	}
}

// 19. TestRgLabel_NeverStaleFalsePositive
func TestRgLabel_NeverStaleFalsePositive(t *testing.T) {
	st := newTestStore(t)
	fg := NewFloodGuard(60*time.Second, 64)
	sp := NewSearchPipeline(st, fg)
	s := &server{
		sessionID:      "sess1",
		store:          st,
		floodGuard:     fg,
		searchPipeline: sp,
	}

	label := s.indexLabel("rg", "stale_test")
	// Index with non-existent path so mtime/size = 0
	indexDoc(t, st, label, "some_unique_text_for_stale_test")

	res, _, err := s.toolSearch(context.Background(), nil, searchArgs{Query: "some_unique_text_for_stale_test", Scope: "rg"})
	if err != nil {
		t.Fatalf("toolSearch failed: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "[STALE") {
		t.Errorf("rg indexed documents must NEVER produce [STALE: false positive: %s", text)
	}
}

// Regression: CTXMODE_RG_SUMMARY=0 switch off
func TestRgSummary_EnvSwitchOff(t *testing.T) {
	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess1",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	var f1 strings.Builder
	for i := 0; i < 30; i++ {
		f1.WriteString("SWITCH_OFF_TOKEN line\n")
	}
	commitFile(t, repoDir, "f1.txt", f1.String(), "commit f1")

	orig := rgSummaryEnabled
	rgSummaryEnabled = false
	defer func() { rgSummaryEnabled = orig }()

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "SWITCH_OFF_TOKEN",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "indexed=") {
		t.Errorf("when CTXMODE_RG_SUMMARY=0, search must NOT index: %s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Errorf("expected truncated=true on raw fallback: %s", text)
	}
}
