package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ============================================================================
// 项 7：按 workdir 分库 — 不同 workdir 得到不同库路径且数据不互见
// ============================================================================

func TestDatabasePath_PerWorkdirIsolation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CTXMODE_DB", "")

	wd1 := filepath.Join(home, "projA")
	wd2 := filepath.Join(home, "projB")

	p1, legacy, err := databasePath(wd1)
	if err != nil {
		t.Fatalf("databasePath(wd1): %v", err)
	}
	p2, _, err := databasePath(wd2)
	if err != nil {
		t.Fatalf("databasePath(wd2): %v", err)
	}

	// Different primary workdirs must resolve to different database files.
	if p1 == p2 {
		t.Fatalf("expected different db paths for different workdirs, both %q", p1)
	}
	// The legacy global shared path must no longer be the default.
	legacyWant := filepath.Join(home, ".local", "share", "ctxmode", "context_mode.db")
	if legacy != legacyWant {
		t.Fatalf("legacy path = %q, want %q", legacy, legacyWant)
	}
	if p1 == legacy {
		t.Fatalf("db path %q must not be the legacy shared path %q", p1, legacy)
	}
	// Per-workdir layout: <hash>-<basename>/context_mode.db under the ctxmode dir.
	if filepath.Base(p1) != "context_mode.db" {
		t.Fatalf("db file name = %q, want context_mode.db", filepath.Base(p1))
	}
	if !strings.HasSuffix(filepath.Base(filepath.Dir(p1)), "-projA") {
		t.Fatalf("db dir %q must end with -projA (hash-basename layout)", filepath.Dir(p1))
	}
	if !strings.HasSuffix(filepath.Base(filepath.Dir(p2)), "-projB") {
		t.Fatalf("db dir %q must end with -projB (hash-basename layout)", filepath.Dir(p2))
	}
	// Deterministic: same workdir always resolves to the same path.
	p1b, _, err := databasePath(wd1)
	if err != nil || p1b != p1 {
		t.Fatalf("databasePath not deterministic: %q vs %q (err %v)", p1b, p1, err)
	}

	// Data isolation: content indexed into workdir A's db must not be
	// searchable from workdir B's db.
	if err := ensureDBDir(p1); err != nil {
		t.Fatalf("ensureDBDir(p1): %v", err)
	}
	if err := ensureDBDir(p2); err != nil {
		t.Fatalf("ensureDBDir(p2): %v", err)
	}
	stA, err := NewStore(p1)
	if err != nil {
		t.Fatalf("NewStore(p1): %v", err)
	}
	defer stA.Close()
	stB, err := NewStore(p2)
	if err != nil {
		t.Fatalf("NewStore(p2): %v", err)
	}
	defer stB.Close()

	if err := stA.Index("doc-a", "unique-secret-for-project-A-xyz"); err != nil {
		t.Fatalf("Index into A: %v", err)
	}

	hits, err := stB.Search("unique-secret-for-project-A-xyz", 5)
	if err != nil {
		t.Fatalf("search B: %v", err)
	}
	if len(hits) != 0 {
		t.Fatalf("cross-workdir leak: content indexed in A found in B: %+v", hits)
	}

	hits, err = stA.Search("unique-secret-for-project-A-xyz", 5)
	if err != nil {
		t.Fatalf("search A: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit in A's own db, got %d", len(hits))
	}
}

func TestDatabasePath_EnvOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	custom := filepath.Join(home, "custom", "db.sqlite")
	t.Setenv("CTXMODE_DB", custom)

	p, legacy, err := databasePath(filepath.Join(home, "projA"))
	if err != nil {
		t.Fatalf("databasePath: %v", err)
	}
	absCustom, _ := filepath.Abs(custom)
	if p != absCustom {
		t.Fatalf("CTXMODE_DB must take priority: got %q, want %q", p, absCustom)
	}
	// With an explicit env path there is no "changed" hint (legacy == resolved).
	if legacy != p {
		t.Fatalf("legacy %q should equal resolved %q when CTXMODE_DB is set", legacy, p)
	}
}

// ============================================================================
// 项 7（顺带）：excludeFromGit 按真实相对路径写，库在仓库外则不再写 git 元数据
// ============================================================================

func TestExcludeFromGit_WritesRepoRelativePath(t *testing.T) {
	wd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(wd, ".git", "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	exclude := filepath.Join(wd, ".git", "info", "exclude")
	if err := os.WriteFile(exclude, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Database inside the workspace: entry must use the real repo-relative path.
	s := &server{workdirs: []string{wd}, dbPath: filepath.Join(wd, "sub", "ctxmode.db")}
	s.excludeFromGitOne(wd)
	data, err := os.ReadFile(exclude)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{"sub/ctxmode.db", "sub/ctxmode.db-wal", "sub/ctxmode.db-shm"} {
		if !strings.Contains(content, want) {
			t.Fatalf("exclude must contain %q, got:\n%s", want, content)
		}
	}
}

func TestExcludeFromGit_SkipsDbOutsideRepo(t *testing.T) {
	wd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(wd, ".git", "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	exclude := filepath.Join(wd, ".git", "info", "exclude")
	if err := os.WriteFile(exclude, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Default per-workdir database lives outside the workspace: no git
	// metadata modification at all (previously it wrote a meaningless
	// context_mode.db entry).
	s := &server{workdirs: []string{wd}, dbPath: "/outside-workspace/ctxmode/context_mode.db"}
	s.excludeFromGitOne(wd)
	data, err := os.ReadFile(exclude)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "sentinel\n" {
		t.Fatalf("exclude file must be untouched when db is outside the repo, got %q", data)
	}
}

// ============================================================================
// 项 2：toolStats 错误上抛（不再用 0 冒充空库）
// ============================================================================

func TestToolStats_ReportsStoreErrors(t *testing.T) {
	st := newTestStore(t)
	s := &server{store: st, floodGuard: NewFloodGuard(60*time.Second, 64)}

	// Healthy store: stats succeed.
	res, _, err := s.toolStats(context.Background(), nil, statsArgs{})
	if err != nil {
		t.Fatalf("toolStats on healthy store: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, `"docs_indexed": 0`) {
		t.Fatalf("expected docs_indexed in stats json, got: %s", text)
	}

	// Broken store (db closed): the error must propagate, not be swallowed
	// into zero-filled stats that look like an empty knowledge base.
	if err := st.db.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	_, _, err = s.toolStats(context.Background(), nil, statsArgs{})
	if err == nil {
		t.Fatal("toolStats must fail when store is broken")
	}
	if !strings.Contains(err.Error(), "store stats") {
		t.Fatalf("expected store stats error, got: %v", err)
	}
}

// ============================================================================
// 项 3：索引默认跳过密钥类文件 + 结果中报告跳过数量
// ============================================================================

func TestToolIndex_SkipsSensitiveFiles(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	sensitive := map[string]string{
		".env":             "SECRET_ENV=1",
		".env.local":       "SECRET_LOCAL=1",
		".env.production":  "SECRET_PROD=1",
		"server.pem":       "PRIVATE KEY",
		"deploy.key":       "KEYDATA",
		"id_rsa":           "PRIVATE KEY",
		"credentials.json": `{"client_secret":"x"}`,
		".npmrc":           "//registry.npmjs.org/:_authToken=abc",
		".netrc":           "machine example.com login u password p",
		".aws/credentials": "aws_secret_access_key = xyz",
	}
	for name, content := range sensitive {
		mustWrite(t, filepath.Join(wd, name), content)
	}
	mustWrite(t, filepath.Join(wd, "normal.txt"), "hello world normal")
	mustWrite(t, filepath.Join(wd, "app.go"), "package app")

	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
	if err != nil {
		t.Fatalf("toolIndex: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Indexed 2 file(s)") {
		t.Fatalf("expected 2 indexed files, got: %s", text)
	}
	if !strings.Contains(text, "10 skipped, 10 sensitive)") {
		t.Fatalf("expected sensitive skip report, got: %s", text)
	}

	// Secret content must not be searchable; normal content must be.
	if hits, _ := st.Search("SECRET_ENV", 5); len(hits) != 0 {
		t.Fatalf(".env content was indexed: %+v", hits)
	}
	if hits, _ := st.Search("aws_secret_access_key", 5); len(hits) != 0 {
		t.Fatalf(".aws/credentials content was indexed: %+v", hits)
	}
	if doc, _ := st.Get(filepath.Join(wd, ".env")); doc != nil {
		t.Fatalf(".env document must not exist in store")
	}
	hits, err := st.Search("hello", 5)
	if err != nil || len(hits) != 1 {
		t.Fatalf("expected normal.txt indexed (err %v, hits %d)", err, len(hits))
	}
	if !strings.HasSuffix(hits[0].Path, "normal.txt") {
		t.Fatalf("unexpected hit path: %s", hits[0].Path)
	}
}

func TestToolIndex_RefusesSensitiveSingleFile(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	envPath := filepath.Join(wd, ".env")
	mustWrite(t, envPath, "SECRET=1")

	_, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: envPath})
	if err == nil {
		t.Fatal("expected explicit index of a sensitive file to be refused")
	}
	if !strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("expected sensitive error, got: %v", err)
	}
	if doc, _ := st.Get(envPath); doc != nil {
		t.Fatalf("refused sensitive file must not be stored")
	}
}

// ============================================================================
// 项 4：排除目录按 filepath 分段判断（不再硬编码 "/.git/"）
// ============================================================================

func TestPathHasExcludedSegment_FilepathSemantics(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{filepath.Join("a", ".git", "b", "file.txt"), true},
		{filepath.Join("a", "node_modules", "x.js"), true},
		{filepath.Join(".git", "config"), true},
		{filepath.Join("a", "b", "c.go"), false},
		// A file named .gitignore is NOT a .git directory segment.
		{"a/.gitignore", false},
		{"plain.txt", false},
	}
	for _, c := range cases {
		if got := pathHasExcludedSegment(c.path, ".git", "node_modules"); got != c.want {
			t.Fatalf("pathHasExcludedSegment(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// ============================================================================
// 项 5：resolvePath 相对路径多 workdir 唯一匹配，否则报错
// ============================================================================

func TestResolvePath_MultiWorkdirMatch(t *testing.T) {
	wd1 := t.TempDir()
	wd2 := t.TempDir()
	mustWrite(t, filepath.Join(wd1, "only1.txt"), "1")
	mustWrite(t, filepath.Join(wd2, "only2.txt"), "2")
	mustWrite(t, filepath.Join(wd1, "shared.txt"), "1")
	mustWrite(t, filepath.Join(wd2, "shared.txt"), "2")

	s := &server{workdirs: []string{wd1, wd2}}

	// Unique match in the second workdir — previously unreachable (silently
	// joined to workdirs[0]).
	got, err := s.resolvePath("only2.txt")
	if err != nil {
		t.Fatalf("resolvePath(only2.txt): %v", err)
	}
	if want, _ := filepath.EvalSymlinks(filepath.Join(wd2, "only2.txt")); got != want {
		t.Fatalf("resolvePath(only2.txt) = %q, want %q", got, want)
	}

	// Unique match in the first workdir.
	got, err = s.resolvePath("only1.txt")
	if err != nil {
		t.Fatalf("resolvePath(only1.txt): %v", err)
	}
	if want, _ := filepath.EvalSymlinks(filepath.Join(wd1, "only1.txt")); got != want {
		t.Fatalf("resolvePath(only1.txt) = %q, want %q", got, want)
	}

	// Ambiguous: exists under multiple workdirs -> error, no silent fallback.
	_, err = s.resolvePath("shared.txt")
	if err == nil {
		t.Fatal("expected error for ambiguous relative path")
	}
	if !strings.Contains(err.Error(), "multiple") || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected multiple/absolute error, got: %v", err)
	}

	// No match anywhere -> error, no silent fallback to workdirs[0].
	_, err = s.resolvePath("does-not-exist.txt")
	if err == nil {
		t.Fatal("expected error for non-existent relative path")
	}
	if !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected does-not-exist/absolute error, got: %v", err)
	}

	// Empty path still resolves to the primary workdir; absolute paths work.
	if got, err := s.resolvePath(""); err != nil || got != wd1 {
		t.Fatalf("resolvePath(\"\") = %q, err %v", got, err)
	}
	// "." exists under every workdir; it means the primary root, not "ambiguous".
	if got, err := s.resolvePath("."); err != nil || got != wd1 {
		t.Fatalf("resolvePath(\".\") = %q, err %v; want primary workdir", got, err)
	}
	abs, err := s.resolvePath(filepath.Join(wd1, "only1.txt"))
	if err != nil || abs != filepath.Join(wd1, "only1.txt") {
		t.Fatalf("resolvePath(abs) = %q, err %v", abs, err)
	}
}

// ============================================================================
// 项 6：index label 唯一化（同 intent 并发/连续执行不互相覆盖）
// ============================================================================

func TestUniqueIndexLabel_NoCollision(t *testing.T) {
	a := uniqueIndexLabel("execute", "build")
	b := uniqueIndexLabel("execute", "build")
	if a == b {
		t.Fatalf("sequential labels with same intent must differ: %q", a)
	}
	if !strings.HasPrefix(a, "execute:build:") {
		t.Fatalf("expected execute:build: prefix, got %q", a)
	}
	if !strings.HasPrefix(uniqueIndexLabel("execute", ""), "execute:") {
		t.Fatalf("intent-less label must still carry the execute: prefix")
	}

	// Concurrent same-intent labels must all be distinct.
	const n = 50
	var wg sync.WaitGroup
	labels := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			labels <- uniqueIndexLabel("execute", "build")
		}()
	}
	wg.Wait()
	close(labels)
	seen := make(map[string]bool, n)
	for l := range labels {
		if seen[l] {
			t.Fatalf("duplicate concurrent label: %q", l)
		}
		seen[l] = true
	}
}

// ============================================================================
// 项 1 + 项 6：toolExecute 提示文案指向 ctx_kb action=search，label 可直接搜索
// ============================================================================

func TestExecute_IndexedHintUsesCtxKbAndUniqueLabels(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	ctx := context.Background()

	run := func(b byte) string {
		t.Helper()
		res, _, err := s.toolExecute(ctx, nil, executeArgs{
			Command:  fmt.Sprintf("head -c 6000 /dev/zero | tr '\\0' %c", b),
			Language: "shell",
			Intent:   "build-log",
			Timeout:  15000,
		})
		if err != nil {
			t.Fatalf("toolExecute: %v", err)
		}
		text := mcpResultText(t, res)
		if !strings.Contains(text, "ctx_kb action=search query=") {
			t.Fatalf("hint must reference ctx_kb action=search, got:\n%s", text)
		}
		if strings.Contains(text, "ctx_search") {
			t.Fatalf("hint must not reference removed ctx_search tool:\n%s", text)
		}
		m := regexp.MustCompile(`(?i)indexed as "([^"]+)"`).FindStringSubmatch(text)
		if len(m) != 2 {
			t.Fatalf("cannot extract index label from:\n%s", text)
		}
		return m[1]
	}

	l1 := run('a')
	l2 := run('b')
	if l1 == l2 {
		t.Fatalf("two executes with the same intent must get distinct labels, got %q", l1)
	}

	// Both documents must exist: the second run must not have clobbered the first.
	d1, err := st.Get(l1)
	if err != nil || d1 == nil {
		t.Fatalf("first run's document %q missing (err %v): concurrent clobber", l1, err)
	}
	d2, err := st.Get(l2)
	if err != nil || d2 == nil {
		t.Fatalf("second run's document %q missing (err %v)", l2, err)
	}
	if !strings.HasPrefix(d1.Content, "aaa") || !strings.HasPrefix(d2.Content, "bbb") {
		t.Fatalf("content mismatch: d1 prefix %q, d2 prefix %q", d1.Content[:3], d2.Content[:3])
	}

	// The returned label is directly usable as a search query.
	hits, err := st.Search(l1, 5)
	if err != nil {
		t.Fatalf("search by label: %v", err)
	}
	if len(hits) == 0 {
		t.Fatalf("search by returned label %q found nothing", l1)
	}

	// Auto-index branch (>100KB) message format.
	res, _, err := s.toolExecute(ctx, nil, executeArgs{
		Command:  "head -c 110000 /dev/zero | tr '\\0' X",
		Language: "shell",
		Timeout:  15000,
	})
	if err != nil {
		t.Fatalf("toolExecute (110KB): %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Output is too large (110000 bytes)") {
		t.Fatalf("expected too-large notice, got:\n%s", text)
	}
	if !strings.Contains(text, "ctx_kb action=search query=") {
		t.Fatalf("auto-index hint must reference ctx_kb action=search, got:\n%s", text)
	}
	if strings.Contains(text, "ctx_search") {
		t.Fatalf("auto-index hint must not reference ctx_search:\n%s", text)
	}
}

// ============================================================================
// 项 1（execute_file 分支）：提示文案同样指向 ctx_kb action=search
// ============================================================================

func TestExecuteFile_IndexedHintUsesCtxKb(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	ctx := context.Background()

	// Intent branch (5KB-100KB): python prints FILE_CONTENT (6000 bytes).
	mustWrite(t, filepath.Join(wd, "data.txt"), strings.Repeat("z", 6000))
	res, _, err := s.toolExecuteFile(ctx, nil, executeFileArgs{
		Path:     "data.txt",
		Code:     "print(FILE_CONTENT)",
		Language: "python",
		Intent:   "ef-intent",
		Timeout:  15000,
	})
	if err != nil {
		t.Fatalf("toolExecuteFile: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "ctx_kb action=search query=") {
		t.Fatalf("execute_file hint must reference ctx_kb action=search, got:\n%s", text)
	}
	if strings.Contains(text, "ctx_search") {
		t.Fatalf("execute_file hint must not reference ctx_search:\n%s", text)
	}
	m := regexp.MustCompile(`(?i)indexed as "([^"]+)"`).FindStringSubmatch(text)
	if len(m) != 2 {
		t.Fatalf("cannot extract index label from:\n%s", text)
	}
	label := m[1]
	if !strings.HasPrefix(label, "execute_file:ef-intent:") {
		t.Fatalf("unexpected label: %q", label)
	}
	if doc, _ := st.Get(label); doc == nil {
		t.Fatalf("document %q must exist in store", label)
	}

	// Auto-index branch (>100KB).
	mustWrite(t, filepath.Join(wd, "big.txt"), strings.Repeat("w", 110000))
	res, _, err = s.toolExecuteFile(ctx, nil, executeFileArgs{
		Path:     "big.txt",
		Code:     "print(FILE_CONTENT)",
		Language: "python",
		Timeout:  15000,
	})
	if err != nil {
		t.Fatalf("toolExecuteFile (110KB): %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "Output is too large") {
		t.Fatalf("expected too-large notice, got:\n%s", text)
	}
	if !strings.Contains(text, "ctx_kb action=search query=") {
		t.Fatalf("execute_file auto-index hint must reference ctx_kb action=search, got:\n%s", text)
	}
	if strings.Contains(text, "ctx_search") {
		t.Fatalf("execute_file auto-index hint must not reference ctx_search:\n%s", text)
	}
}

func TestExecuteFile_ReportsExitCode(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	mustWrite(t, filepath.Join(wd, "n.txt"), "x")
	res, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     "n.txt",
		Language: "python",
		Code:     "import sys; sys.exit(1)",
		Timeout:  15000,
	})
	if err != nil {
		t.Fatalf("toolExecuteFile: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "exited with code 1") {
		t.Fatalf("execute_file must report exit code, got %q", text)
	}
}

func TestExecute_LargeOutputKeepsExitAndTail(t *testing.T) {
	st := newTestStore(t)
	s := &server{workdirs: []string{t.TempDir()}, store: st}
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv:    []string{"python3", "-c", "import sys; sys.stdout.write('X'*110000); sys.exit(3)"},
		Timeout: 20000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "exit_code: 3") {
		t.Fatalf("large execute must include exit_code, got:\n%s", text)
	}
	if !strings.Contains(text, "--- Tail preview ---") {
		t.Fatalf("large execute must include tail preview, got:\n%s", text)
	}
}

func TestExecute_IntentMidSizeKeepsExitAndTail(t *testing.T) {
	st := newTestStore(t)
	s := &server{workdirs: []string{t.TempDir()}, store: st}
	res, _, err := s.toolExecute(context.Background(), nil, executeArgs{
		Argv:    []string{"python3", "-c", "import sys; sys.stdout.write('H'*6000); sys.exit(7)"},
		Intent:  "recheck-mid",
		Timeout: 20000,
	})
	if err != nil {
		t.Fatalf("toolExecute: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "exit_code: 7") {
		t.Fatalf("mid-size+intent must include exit_code, got:\n%s", text)
	}
	if !strings.Contains(text, "--- Tail preview ---") {
		t.Fatalf("mid-size+intent must include tail preview, got:\n%s", text)
	}
}

// ============================================================================
// 项：toolIndex 文件数 / 总字节 cap 后整棵 Walk 早停（SkipAll）
// ============================================================================

// withIndexCaps shrinks the package-level walk caps for one test and restores
// them on cleanup. These tests must NOT run in parallel: the caps are shared
// package state.
func withIndexCaps(t *testing.T, files int, totalBytes int64) {
	t.Helper()
	oldFiles, oldBytes := maxIndexFiles, maxIndexTotalBytes
	maxIndexFiles, maxIndexTotalBytes = files, totalBytes
	t.Cleanup(func() { maxIndexFiles, maxIndexTotalBytes = oldFiles, oldBytes })
}

// buildIndexTree writes cap+1 indexable files under dirA and, in a sibling dir
// (alphabetically after dirA) beyond maxIndexDepth, a marker file. If the walk
// does not truly stop at the cap, the walk would reach the marker and record a
// "max depth 32" skip; if it stops early (SkipAll), the sibling is never
// visited and no such skip appears.
func buildIndexTree(t *testing.T, wd string, n int) {
	t.Helper()
	dirA := filepath.Join(wd, "aaa")
	sib := filepath.Join(wd, "zzz-marker")
	for i := 0; i < n; i++ {
		mustWrite(t, filepath.Join(dirA, fmt.Sprintf("f%d.txt", i)), "hello world")
	}
	deep := sib
	for i := 0; i < 31; i++ {
		deep = filepath.Join(deep, fmt.Sprintf("d%d", i))
	}
	mustWrite(t, filepath.Join(deep, "marker.txt"), "marker")
}

func TestToolIndex_StopsWalkAtFileCap(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	withIndexCaps(t, 3, 100*1024*1024)

	buildIndexTree(t, wd, 4) // 4 files in dirA, cap 3

	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
	if err != nil {
		t.Fatalf("toolIndex: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Indexed 3 file(s)") {
		t.Fatalf("expected 3 indexed files, got: %s", text)
	}
	if !strings.Contains(text, "[stopped: max files 3]") {
		t.Fatalf("expected file cap stop notice, got: %s", text)
	}
	if strings.Contains(text, "max depth") {
		t.Fatalf("walk entered sibling dir after file cap (SkipAll missing), got: %s", text)
	}
}

func TestToolIndex_StopsWalkAtByteCap(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	withIndexCaps(t, 5000, 20) // each file is 11 bytes; cap 20 → hit on second file

	buildIndexTree(t, wd, 4)

	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
	if err != nil {
		t.Fatalf("toolIndex: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Indexed 1 file(s)") {
		t.Fatalf("expected 1 indexed file, got: %s", text)
	}
	if !strings.Contains(text, "[stopped: max total bytes 20]") {
		t.Fatalf("expected byte cap stop notice, got: %s", text)
	}
	if strings.Contains(text, "max depth") {
		t.Fatalf("walk entered sibling dir after byte cap (SkipAll missing), got: %s", text)
	}
}

func TestToolIndex_SkipsFIFOWithoutHang(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	fifo := filepath.Join(wd, "pipe.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	mustWrite(t, filepath.Join(wd, "ok.txt"), "fifo-sibling-ok")

	done := make(chan error, 1)
	go func() {
		res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
		if err != nil {
			done <- err
			return
		}
		text := mcpResultText(t, res)
		if !strings.Contains(text, "Indexed 1 file(s)") {
			done <- fmt.Errorf("expected regular file indexed, got: %s", text)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("toolIndex hung on FIFO")
	}

	hits, err := st.Search("fifo-sibling-ok", 5)
	if err != nil || len(hits) != 1 {
		t.Fatalf("regular file must still be indexed (err %v, hits %d)", err, len(hits))
	}

	done = make(chan error, 1)
	go func() {
		_, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: fifo})
		if err == nil {
			done <- fmt.Errorf("expected single-file FIFO index to fail")
			return
		}
		if !strings.Contains(err.Error(), "non-regular") {
			done <- fmt.Errorf("expected non-regular error, got: %v", err)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("toolIndex(single FIFO) hung")
	}
}

func TestToolExecuteFile_FIFODoesNotHang(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	fifo := filepath.Join(wd, "pipe.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := s.toolExecuteFile(context.Background(), nil, executeFileArgs{
			Path:     fifo,
			Language: "python",
			Code:     "print(FILE_CONTENT)",
			Timeout:  2000,
		})
		if err == nil {
			done <- fmt.Errorf("expected execute_file on FIFO to fail")
			return
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			done <- fmt.Errorf("expected not-regular error, got: %v", err)
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("toolExecuteFile hung on FIFO")
	}
}

func TestToolIndex_HardlinkAndPrivateKeyContent(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	priv := "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nAAAAfakeprivkey\n-----END OPENSSH PRIVATE KEY-----\n"
	keyPath := filepath.Join(wd, ".ssh", "id_rsa")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(priv), 0600); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(wd, "notes.txt")
	if err := os.Link(keyPath, notes); err != nil {
		t.Fatalf("hardlink: %v", err)
	}
	mustWrite(t, filepath.Join(wd, "ok.txt"), "public-ok-marker")

	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
	if err != nil {
		t.Fatalf("toolIndex: %v", err)
	}
	text := mcpResultText(t, res)
	if hits, _ := st.Search("AAAAfakeprivkey", 5); len(hits) != 0 {
		t.Fatalf("private key body was indexed via hardlink: %+v (msg %s)", hits, text)
	}
	if doc, _ := st.Get(notes); doc != nil {
		t.Fatalf("notes.txt hardlink must not be stored")
	}
	if hits, err := st.Search("public-ok-marker", 5); err != nil || len(hits) != 1 {
		t.Fatalf("regular file should still be indexed (err %v, hits %d)", err, len(hits))
	}

	st2 := newTestStore(t)
	s2 := &server{workdirs: []string{wd}, store: st2}
	if err := s2.indexFile(notes); err == nil {
		t.Fatal("indexFile(notes.txt) must refuse private-key content")
	} else if !strings.Contains(err.Error(), "private key") && !strings.Contains(err.Error(), "hardlink") {
		t.Fatalf("expected private key or hardlink error, got: %v", err)
	}
	if doc, _ := st2.Get(notes); doc != nil {
		t.Fatalf("refused hardlink must not be stored")
	}

	pub := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----\n"
	pubPath := filepath.Join(wd, "pubkey.txt")
	mustWrite(t, pubPath, pub)
	if err := s.indexFile(pubPath); err != nil {
		t.Fatalf("public key should still index: %v", err)
	}
}

func TestLooksLikePrivateKey(t *testing.T) {
	if !looksLikePrivateKey([]byte("-----BEGIN " + "RSA PRIVATE KEY-----\nMII\n")) {
		t.Fatal("RSA private key not detected")
	}
	if looksLikePrivateKey([]byte("-----BEGIN PUBLIC KEY-----\nMII\n")) {
		t.Fatal("PUBLIC KEY must not be treated as private")
	}
	if looksLikePrivateKey([]byte("-----BEGIN SSH2 PUBLIC KEY-----\nAAA\n")) {
		t.Fatal("SSH2 PUBLIC KEY must not be treated as private")
	}
	if !looksLikePrivateKey([]byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\n")) {
		t.Fatal("PGP private key not detected")
	}
	if !looksLikePrivateKey([]byte("-----BEGIN " + "PRIVATE KEY-----\nMII\n")) {
		t.Fatal("PKCS#8 PRIVATE KEY not detected")
	}
	if looksLikePrivateKey([]byte("-----BEGIN PUBLIC KEY-----\nMII\n")) {
		t.Fatal("PUBLIC KEY must not be treated as private")
	}

	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}
	notes := filepath.Join(wd, "notes.txt")
	mustWrite(t, notes, "-----BEGIN "+"PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKc\n-----END "+"PRIVATE KEY-----\n")
	if err := s.indexFile(notes); err == nil {
		t.Fatal("indexFile(notes.txt) must refuse PKCS#8 private key")
	} else if !strings.Contains(err.Error(), "private key") {
		t.Fatalf("expected private key error, got: %v", err)
	}
	if doc, _ := st.Get(notes); doc != nil {
		t.Fatal("PKCS#8 body must not be stored")
	}
}

func TestToolIndex_HardlinkEnvWalkOrder(t *testing.T) {
	st := newTestStore(t)
	wd := t.TempDir()
	s := &server{workdirs: []string{wd}, store: st}

	envDir := filepath.Join(wd, "z")
	if err := os.MkdirAll(envDir, 0o755); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(envDir, ".env")
	mustWrite(t, envPath, "SECRET_TOKEN=abc\n")
	aaa := filepath.Join(wd, "aaa.txt")
	if err := os.Link(envPath, aaa); err != nil {
		t.Fatalf("hardlink: %v", err)
	}
	mustWrite(t, filepath.Join(wd, "ok.txt"), "public-ok-marker")

	res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: wd})
	if err != nil {
		t.Fatalf("toolIndex: %v", err)
	}
	text := mcpResultText(t, res)
	if hits, _ := st.Search("SECRET_TOKEN", 5); len(hits) != 0 {
		t.Fatalf("SECRET_TOKEN was indexed via hardlink: %+v (msg %s)", hits, text)
	}
	if doc, _ := st.Get(aaa); doc != nil {
		t.Fatalf("aaa.txt hardlink must not be stored")
	}
	if hits, err := st.Search("public-ok-marker", 5); err != nil || len(hits) != 1 {
		t.Fatalf("ok.txt should still be indexed (err %v, hits %d)", err, len(hits))
	}

	st2 := newTestStore(t)
	s2 := &server{workdirs: []string{wd}, store: st2}
	_, _, err = s2.toolIndex(context.Background(), nil, indexArgs{Path: aaa})
	if err == nil {
		t.Fatal("single-file index of hardlink to .env must refuse")
	}
	if !strings.Contains(err.Error(), "hardlink") {
		t.Fatalf("expected hardlink error, got: %v", err)
	}
	if hits, _ := st2.Search("SECRET_TOKEN", 5); len(hits) != 0 {
		t.Fatalf("single-file index stored SECRET_TOKEN: %+v", hits)
	}
}
