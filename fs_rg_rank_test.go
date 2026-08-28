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
