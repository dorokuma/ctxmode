package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// === Merged from fs_rg_rank_test.go ===

// 1. TestParsePorcelainZ_States
func TestParsePorcelainZ_States(t *testing.T) {
	toplevel := "/workspace/repo"
	// \x00 separated
	// XY path\x00
	raw := []byte("?? untracked.go\x00?? untracked_dir/\x00 M modified_worktree.go\x00M  staged.go\x00MM both.go\x00")
	dirty := parsePorcelainZ(raw, toplevel)

	expected := []string{
		filepath.Join(toplevel, "untracked.go"),
		filepath.Join(toplevel, "untracked_dir"),
		filepath.Join(toplevel, "modified_worktree.go"),
		filepath.Join(toplevel, "staged.go"),
		filepath.Join(toplevel, "both.go"),
	}

	if len(dirty) != len(expected) {
		t.Fatalf("expected %d dirty files, got %d", len(expected), len(dirty))
	}
	for _, exp := range expected {
		if _, ok := dirty[filepath.Clean(exp)]; !ok {
			t.Errorf("expected dirty set to contain %s", exp)
		}
	}
}

// 2. TestParsePorcelainZ_RenameConsumesOrigPath
func TestParsePorcelainZ_RenameConsumesOrigPath(t *testing.T) {
	toplevel := "/workspace/repo"
	// R  new.go\x00old.go\x00?? other.go\x00
	raw := []byte("R  new.go\x00old.go\x00?? other.go\x00")
	dirty := parsePorcelainZ(raw, toplevel)

	if len(dirty) != 2 {
		t.Fatalf("expected 2 dirty files, got %d", len(dirty))
	}
	newPath := filepath.Clean(filepath.Join(toplevel, "new.go"))
	oldPath := filepath.Clean(filepath.Join(toplevel, "old.go"))
	otherPath := filepath.Clean(filepath.Join(toplevel, "other.go"))

	if _, ok := dirty[newPath]; !ok {
		t.Errorf("expected new.go to be in dirty set")
	}
	if _, ok := dirty[oldPath]; ok {
		t.Errorf("old.go should NOT be in dirty set")
	}
	if _, ok := dirty[otherPath]; !ok {
		t.Errorf("expected other.go to be in dirty set")
	}
}

// 3. TestGitDirtyFiles_TTLCacheAndNegativeCache
func TestGitDirtyFiles_TTLCacheAndNegativeCache(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	var clockTime atomic.Int64
	clockTime.Store(now.UnixNano())

	s := &server{
		gitStatusClock: func() time.Time {
			return time.Unix(0, clockTime.Load())
		},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}

	var callCount atomic.Int32
	s.gitDirtyRunner = func(ctx context.Context, cwd string, args ...string) (string, error) {
		callCount.Add(1)
		return " M foo.go\x00", nil
	}

	tempDir := t.TempDir()
	initTestRepo(t, tempDir)
	s.workdirs = []string{tempDir}

	// 1st call: should invoke runner
	dirty, status := s.gitDirtyFiles(context.Background(), tempDir)
	if status != "ok" || len(dirty) != 1 {
		t.Fatalf("expected status=ok and 1 dirty, got status=%s, dirty=%v", status, dirty)
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected 1 runner call, got %d", callCount.Load())
	}

	// 2nd call before TTL (advance 1 second < 3s TTL): should use cache, callCount remains 1
	clockTime.Store(now.Add(1 * time.Second).UnixNano())
	dirty2, status2 := s.gitDirtyFiles(context.Background(), tempDir)
	if status2 != "ok" || len(dirty2) != 1 {
		t.Fatalf("expected cached status=ok and 1 dirty")
	}
	if callCount.Load() != 1 {
		t.Fatalf("expected runner NOT to be called, got %d calls", callCount.Load())
	}

	// 3rd call after TTL (advance 4 seconds > 3s TTL): should invoke runner again
	clockTime.Store(now.Add(5 * time.Second).UnixNano())
	dirty3, status3 := s.gitDirtyFiles(context.Background(), tempDir)
	if status3 != "ok" || len(dirty3) != 1 {
		t.Fatalf("expected status=ok after TTL")
	}
	if callCount.Load() != 2 {
		t.Fatalf("expected runner to be called 2nd time, got %d calls", callCount.Load())
	}

	// Test negative cache: runner returns error
	tempDir2 := t.TempDir()
	initTestRepo(t, tempDir2)
	s.workdirs = append(s.workdirs, tempDir2)
	s.gitDirtyRunner = func(ctx context.Context, cwd string, args ...string) (string, error) {
		callCount.Add(1)
		return "", fmt.Errorf("git error")
	}

	dNeg1, statNeg1 := s.gitDirtyFiles(context.Background(), tempDir2)
	if statNeg1 != "none" || dNeg1 != nil {
		t.Fatalf("expected status=none on error")
	}
	cnt := callCount.Load()

	// Before TTL: should return negative cache without invoking runner
	clockTime.Store(now.Add(6 * time.Second).UnixNano())
	dNeg2, statNeg2 := s.gitDirtyFiles(context.Background(), tempDir2)
	if statNeg2 != "none" || dNeg2 != nil {
		t.Fatalf("expected cached status=none")
	}
	if callCount.Load() != cnt {
		t.Fatalf("expected negative cache to prevent runner call")
	}
}

// 4. TestGitDirtyFiles_NonGitDir
func TestGitDirtyFiles_NonGitDir(t *testing.T) {
	orig := rgGitRankEnabled
	rgGitRankEnabled = true
	defer func() { rgGitRankEnabled = orig }()

	tempDir := t.TempDir()
	s := &server{
		workdirs:      []string{tempDir},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "some_pattern",
		Path:    tempDir,
	})
	if err != nil {
		t.Fatalf("toolRg returned error: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "git=none") {
		t.Errorf("expected header to contain git=none, got %q", text)
	}
}

// 5. TestRankGroups_DirtyFirstStable
func TestRankGroups_DirtyFirstStable(t *testing.T) {
	root := "/workspace"
	groups := []rgFileGroup{
		{file: "clean1.go", lines: []string{"clean1.go:1:a"}, hits: 1},
		{file: "dirty1.go", lines: []string{"dirty1.go:1:b"}, hits: 1},
		{file: "clean2.go", lines: []string{"clean2.go:1:c"}, hits: 1},
		{file: "dirty2.go", lines: []string{"dirty2.go:1:d"}, hits: 1},
		{file: "clean3.go", lines: []string{"clean3.go:1:e"}, hits: 1},
	}

	dirty := map[string]struct{}{
		filepath.Join(root, "dirty1.go"): {},
		filepath.Join(root, "dirty2.go"): {},
	}

	rankGroups(groups, dirty, root)

	expectedFiles := []string{"dirty1.go", "dirty2.go", "clean1.go", "clean2.go", "clean3.go"}
	for i, exp := range expectedFiles {
		if groups[i].file != exp {
			t.Errorf("group %d expected %s, got %s", i, exp, groups[i].file)
		}
	}
}

// 6. TestGitRank_Integration
func TestGitRank_Integration(t *testing.T) {
	orig := rgGitRankEnabled
	rgGitRankEnabled = true
	defer func() { rgGitRankEnabled = orig }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	s := &server{
		workdirs:      []string{repoDir},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}

	// Create clean file (committed)
	commitFile(t, repoDir, "noise.go", "package main\n// TOKEN\n", "commit noise")

	// Create dirty file (committed then modified unstaged)
	commitFile(t, repoDir, "app.go", "package main\n// TOKEN\n", "commit app")
	mustWrite(t, filepath.Join(repoDir, "app.go"), "package main\n// TOKEN edited\n")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "TOKEN",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "git_dirty=1") {
		t.Errorf("expected git_dirty=1 in header, got: %s", text)
	}

	appIdx := strings.Index(text, "app.go")
	noiseIdx := strings.Index(text, "noise.go")
	if appIdx < 0 || noiseIdx < 0 {
		t.Fatalf("expected both app.go and noise.go in output, got: %s", text)
	}
	if appIdx > noiseIdx {
		t.Errorf("expected dirty file app.go to appear before noise.go. Output:\n%s", text)
	}
}

// 7. TestGitRank_EnvSwitchOff
func TestGitRank_EnvSwitchOff(t *testing.T) {
	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	s := &server{
		workdirs:      []string{repoDir},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}

	mustWrite(t, filepath.Join(repoDir, "dirty.go"), "package main\n// TOKEN\n")

	orig := rgGitRankEnabled
	rgGitRankEnabled = false
	defer func() { rgGitRankEnabled = orig }()

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "TOKEN",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "git_dirty=") || strings.Contains(text, "git=none") {
		t.Errorf("expected no git header fields when disabled, got: %s", text)
	}
}

// 8. TestGitDirtyFiles_TTL_RealRepo (E2E TTL on real git repository)
func TestGitDirtyFiles_TTL_RealRepo(t *testing.T) {
	orig := rgGitRankEnabled
	rgGitRankEnabled = true
	defer func() { rgGitRankEnabled = orig }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)

	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	var clockTime atomic.Int64
	clockTime.Store(now.UnixNano())

	s := &server{
		workdirs: []string{repoDir},
		gitStatusClock: func() time.Time {
			return time.Unix(0, clockTime.Load())
		},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}

	commitFile(t, repoDir, "file1.go", "package main\n", "initial commit")

	// 1. Initially clean
	dirty1, stat1 := s.gitDirtyFiles(context.Background(), repoDir)
	if stat1 != "ok" || len(dirty1) != 0 {
		t.Fatalf("expected 0 dirty initially, got status=%s, dirty=%v", stat1, dirty1)
	}

	// 2. Modify file on disk, but before TTL expiry (1 second), query again -> should get cached empty set
	mustWrite(t, filepath.Join(repoDir, "file1.go"), "package main\n// modified\n")
	clockTime.Store(now.Add(1 * time.Second).UnixNano())

	dirty2, stat2 := s.gitDirtyFiles(context.Background(), repoDir)
	if stat2 != "ok" || len(dirty2) != 0 {
		t.Fatalf("expected cached 0 dirty before TTL expiry, got: %v", dirty2)
	}

	// 3. Advance clock past 3s TTL (4 seconds) -> should refresh and see file1.go dirty
	clockTime.Store(now.Add(4 * time.Second).UnixNano())
	dirty3, stat3 := s.gitDirtyFiles(context.Background(), repoDir)
	if stat3 != "ok" || len(dirty3) != 1 {
		t.Fatalf("expected 1 dirty file after TTL expiry, got: %v", dirty3)
	}
	if _, ok := dirty3[filepath.Join(repoDir, "file1.go")]; !ok {
		t.Fatalf("expected file1.go in dirty set after TTL refresh")
	}
}

// 9. TestGitRank_UntrackedDirectory (Untracked directory files correctly weighted)
func TestGitRank_UntrackedDirectory(t *testing.T) {
	orig := rgGitRankEnabled
	rgGitRankEnabled = true
	defer func() { rgGitRankEnabled = orig }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	s := &server{
		workdirs:      []string{repoDir},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}

	commitFile(t, repoDir, "clean.go", "// TOKEN\n", "commit clean")

	newDir := filepath.Join(repoDir, "brand_new_dir")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(newDir, "new_file.go"), "// TOKEN\n")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "TOKEN",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "git_dirty=1") {
		t.Errorf("expected git_dirty=1 for untracked directory file, got: %s", text)
	}
	dirtyIdx := strings.Index(text, "brand_new_dir/new_file.go")
	cleanIdx := strings.Index(text, "clean.go")
	if dirtyIdx < 0 || cleanIdx < 0 {
		t.Fatalf("expected both files in output: %s", text)
	}
	if dirtyIdx > cleanIdx {
		t.Errorf("expected untracked directory file to be ranked before clean file: %s", text)
	}
}

// === Merged from rg_label_test.go ===

// rg_label_test.go covers the summary label layer (fs_rg_summary.go):
// group labels and Read hints must name the real file even when the rg line
// is ambiguous (a path containing ":<digits>:" parses as its first colon
// split), while normal unambiguous output stays byte-identical.

// Control goldens: normal, unambiguous rg output must render byte-identically
// regardless of the label-disambiguation change. These run against real files
// under a temp workdir so rgFileSizeTag resolves (small files -> empty tag).

func TestRgLabel_NormalPathSummaryGolden(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "plain-a.txt"), "alpha hit\nline\nbeta hit\n")
	mustWrite(t, filepath.Join(dir, "sub", "plain-b.md"), "gamma\n")

	groups := []rgFileGroup{
		{file: "plain-a.txt", hits: 2, lines: []string{"plain-a.txt:1:alpha hit", "plain-a.txt:5:beta hit"}},
		{file: "sub/plain-b.md", hits: 1, lines: []string{"sub/plain-b.md:2:gamma"}},
	}
	got := renderRgSummary(groups, 3, 20, "sess:test:rg:golden", "alpha", false, false, false, dir)
	want := strings.Join([]string{
		"→ Read plain-a.txt",
		`3 matches in 2 files (full set indexed, > first-screen limit 20). Retrieve details: ctx_kb action=search query="sess:test:rg:golden" scope=rg or page raw lines: ctx_fs action=rg pattern="alpha" offset=20`,
		"Files (M=modified, A=added, ??=untracked; then by match count):",
		"plain-a.txt 2 matches",
		"  1: alpha hit",
		"  5: beta hit",
		"sub/plain-b.md 1 match",
		"  2: gamma",
	}, "\n")
	if got != want {
		t.Errorf("summary golden mismatch.\nGot:\n%q\nWant:\n%q", got, want)
	}
}

func TestRgLabel_NormalPathReadHintGolden(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "plain-a.txt"), "alpha hit\n")

	groups := []rgFileGroup{
		{file: "plain-a.txt", hits: 2, lines: []string{"plain-a.txt:1:alpha hit", "plain-a.txt:5:beta hit"}},
	}
	body := renderGroups(groups)
	got := prependReadHint(body, groups, dir)
	want := "→ Read plain-a.txt\n" + body
	if got != want {
		t.Errorf("read-hint golden mismatch.\nGot:\n%q\nWant:\n%q", got, want)
	}
}

// TestRgLabel_AmbiguousPathSummaryE2E feeds fake rg output (same technique as
// TestSecurityFixes_AmbiguousPathOutputFence) through toolRg: a non-sensitive
// file under a directory "x:12:y" must be labeled with its real path in the
// summary file list and in the Read hint, not with the mis-split prefix "x",
// on both the indexed summary path and the raw-body path.
func TestRgLabel_AmbiguousPathSummaryE2E(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "x:12:y", "notes.md"), "hit one\nmid\nhit two\n")

	script := "#!/bin/sh\n" +
		"root=\"\"\n" +
		"for a; do root=\"$a\"; done\n" +
		"echo \"${root}/x:12:y/notes.md:1:hit one\"\n" +
		"echo \"${root}/x:12:y/notes.md-2-mid\"\n" +
		"echo \"${root}/x:12:y/notes.md:3:hit two\"\n"
	fake := filepath.Join(dir, "rg")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	s := &server{
		workdirs:        []string{dir},
		store:           newTestStore(t),
		sessionID:       "sess-rglabel",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	// Indexed summary path: totalHits > limit.
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "hit", Path: dir, Limit: 1})
	if err != nil {
		t.Fatalf("toolRg summary path: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "x:12:y/notes.md 3 matches") {
		t.Errorf("summary file label must show the real path, got:\n%s", text)
	}
	if !strings.Contains(text, "→ Read x:12:y/notes.md") {
		t.Errorf("Read hint must show the real path, got:\n%s", text)
	}
	if strings.Contains(text, "x 3 matches") || strings.Contains(text, "→ Read x\n") {
		t.Errorf("summary must not label the mis-split prefix \"x\", got:\n%s", text)
	}

	// Raw-body path: totalHits <= limit, hint over raw groups.
	res, _, err = s.toolRg(context.Background(), nil, rgArgs{Pattern: "hit", Path: dir, Limit: 10})
	if err != nil {
		t.Fatalf("toolRg raw path: %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "→ Read x:12:y/notes.md") {
		t.Errorf("raw-path Read hint must show the real path, got:\n%s", text)
	}
	if strings.Contains(text, "→ Read x\n") {
		t.Errorf("raw path must not hint the mis-split prefix \"x\", got:\n%s", text)
	}
	// Raw lines (match and context forms) must survive byte-identically.
	for _, raw := range []string{
		"x:12:y/notes.md:1:hit one",
		"x:12:y/notes.md-2-mid",
		"x:12:y/notes.md:3:hit two",
	} {
		if !strings.Contains(text, raw) {
			t.Errorf("raw line %q must be preserved, got:\n%s", raw, text)
		}
	}
}

// TestRgLabel_AmbiguousPathUnitResolution pins the resolution rule on
// groupRgLines output: the legacy mis-split label "x" is rewritten to the
// stat-verified real path; renderRgSummary and prependReadHint both surface
// it while the caller slice stays untouched.
func TestRgLabel_AmbiguousPathUnitResolution(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "x:12:y", "notes.md")
	mustWrite(t, base, "hit one\nhit two\n")
	legacy := filepath.Join(dir, "x")

	groups := groupRgLines([]string{base + ":1:hit one", base + ":2:hit two"})
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].file != legacy {
		t.Fatalf("pre-resolution parse should be the legacy split %q, got %q", legacy, groups[0].file)
	}

	fixed := make([]rgFileGroup, len(groups))
	copy(fixed, groups)
	disambiguateRgGroupLabels(fixed, dir)
	if fixed[0].file != base {
		t.Fatalf("disambiguated label = %q, want real path %q", fixed[0].file, base)
	}
	if groups[0].file != legacy {
		t.Fatalf("caller slice must not be mutated, got %q", groups[0].file)
	}

	text := renderRgSummary(groups, 2, 20, "sess:test:rg:unit", "hit", false, false, false, dir)
	if !strings.Contains(text, base+" 2 matches") || !strings.Contains(text, "→ Read "+base) {
		t.Errorf("summary must label the real path, got:\n%s", text)
	}
	if strings.Contains(text, "\n"+legacy+" 2 matches") || strings.Contains(text, "→ Read "+legacy+"\n") {
		t.Errorf("summary must not label the mis-split prefix %q, got:\n%s", legacy, text)
	}

	body := renderGroups(groups)
	if got, want := prependReadHint(body, groups, dir), "→ Read "+base+"\n"+body; got != want {
		t.Errorf("read hint mismatch.\nGot:\n%q\nWant:\n%q", got, want)
	}
}

// TestRgLabel_AmbiguousPathFallback: when no candidate stats (file gone or
// fake output without a fixture), the legacy parse is kept so labels for
// vanished files stay byte-identical.
func TestRgLabel_AmbiguousPathFallback(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "x:12:y", "notes.md")
	legacy := filepath.Join(dir, "x")

	groups := groupRgLines([]string{base + ":1:hit one", base + "-2-ctx"})
	if len(groups) != 1 || groups[0].file != legacy {
		t.Fatalf("expected single legacy-parsed group, got %+v", groups)
	}
	fixed := make([]rgFileGroup, len(groups))
	copy(fixed, groups)
	disambiguateRgGroupLabels(fixed, dir)
	if fixed[0].file != legacy {
		t.Fatalf("fallback must keep the legacy parse %q, got %q", legacy, fixed[0].file)
	}
}

// TestRgLabel_ContextAndMatchLabelsConsistent: context lines
// ("path-N-content") and match lines mixed in one block resolve to the same
// label; for normal paths the label is untouched.
func TestRgLabel_ContextAndMatchLabelsConsistent(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "x:12:y", "notes.md")
	mustWrite(t, base, "prev\nhit\nafter\n")
	legacy := filepath.Join(dir, "x")

	// rg -C 1 style block: context, match, context. All lines carry the
	// ":12:" ambiguity and parse to the same legacy prefix.
	lines := []string{base + "-1-prev", base + ":2:hit", base + "-3-after"}
	groups := groupRgLines(lines)
	if len(groups) != 1 || groups[0].file != legacy {
		t.Fatalf("expected 1 group with legacy parse %q, got %+v", legacy, groups)
	}
	if groups[0].hits != 3 {
		t.Fatalf("expected 3 match-counted lines, got %d", groups[0].hits)
	}
	fixed := make([]rgFileGroup, len(groups))
	copy(fixed, groups)
	disambiguateRgGroupLabels(fixed, dir)
	if fixed[0].file != base {
		t.Fatalf("mixed context/match group label = %q, want %q", fixed[0].file, base)
	}

	// Normal-path control: context and match lines already share one exact
	// label, and disambiguation leaves it byte-identical.
	norm := groupRgLines([]string{"sub/f.md-1-ctx", "sub/f.md:2:hit", "sub/f.md-3-after"})
	if len(norm) != 1 || norm[0].file != "sub/f.md" {
		t.Fatalf("expected 1 group labeled sub/f.md, got %+v", norm)
	}
	nfix := make([]rgFileGroup, len(norm))
	copy(nfix, norm)
	disambiguateRgGroupLabels(nfix, dir)
	if nfix[0].file != "sub/f.md" {
		t.Fatalf("normal label must stay byte-identical, got %q", nfix[0].file)
	}
}
