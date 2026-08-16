package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testServerWithWorkdir(t *testing.T, wd string) *server {
	t.Helper()
	return &server{workdirs: []string{wd}}
}

func mcpResultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil {
		t.Fatal("nil CallToolResult")
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatal("no TextContent in result")
	return ""
}

func setupFSFixture(t *testing.T) (wd string, s *server) {
	t.Helper()
	wd = t.TempDir()
	// Tree under workdir.
	mustWrite(t, filepath.Join(wd, "a.go"), "package main\nfunc Alpha() {}\n")
	mustWrite(t, filepath.Join(wd, "b.txt"), "hello world\n")
	mustWrite(t, filepath.Join(wd, "sub", "c.go"), "package sub\nfunc Charlie() {}\n")
	mustWrite(t, filepath.Join(wd, "sub", "deep", "d.go"), "package deep\nfunc Delta() {}\n")
	mustWrite(t, filepath.Join(wd, ".hidden"), "secret\n")
	mustWrite(t, filepath.Join(wd, "vendor", "x.go"), "package vendor\n")
	mustWrite(t, filepath.Join(wd, ".git", "config"), "gitdir\n")
	mustWrite(t, filepath.Join(wd, ".gitignore"), "ignored.txt\n")
	mustWrite(t, filepath.Join(wd, "ignored.txt"), "should be ignored by glob\n")
	s = testServerWithWorkdir(t, wd)
	return wd, s
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// ---- ctx_fs: ls ----

func TestCtxLs_DefaultAndDepth(t *testing.T) {
	_, s := setupFSFixture(t)

	res, _, err := s.toolLs(context.Background(), nil, lsArgs{})
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	text := mcpResultText(t, res)
	var out struct {
		Count   int `json:"count"`
		Entries []struct {
			Path  string `json:"path"`
			IsDir bool   `json:"is_dir"`
			Depth int    `json:"depth"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, text)
	}
	if out.Count == 0 {
		t.Fatal("expected entries at depth 1")
	}
	var paths []string
	for _, e := range out.Entries {
		paths = append(paths, e.Path)
		if strings.Contains(e.Path, "c.go") || strings.Contains(e.Path, "d.go") {
			t.Fatalf("depth 1 should not list nested file %s", e.Path)
		}
		if e.Depth > 1 {
			t.Fatalf("depth 1 entry has depth=%d path=%s", e.Depth, e.Path)
		}
	}
	joined := strings.Join(paths, " ")
	if !strings.Contains(joined, "a.go") {
		t.Fatalf("expected a.go in %v", paths)
	}

	res2, _, err := s.toolLs(context.Background(), nil, lsArgs{Depth: 2})
	if err != nil {
		t.Fatalf("ls depth2: %v", err)
	}
	text2 := mcpResultText(t, res2)
	if !strings.Contains(text2, "c.go") {
		t.Fatalf("depth 2 should include c.go: %s", text2)
	}
	if strings.Contains(text2, ".hidden") {
		t.Fatalf("hidden should be excluded by default: %s", text2)
	}

	res3, _, err := s.toolLs(context.Background(), nil, lsArgs{IncludeHidden: true, Depth: 1})
	if err != nil {
		t.Fatalf("ls hidden: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res3), ".hidden") {
		t.Fatal("include_hidden should list .hidden")
	}
}

func TestCtxLs_LimitAndOutside(t *testing.T) {
	wd, s := setupFSFixture(t)
	for i := 0; i < 30; i++ {
		mustWrite(t, filepath.Join(wd, "extra", "f"+itoa(i)+".txt"), "x")
	}
	res, _, err := s.toolLs(context.Background(), nil, lsArgs{Limit: 3, Depth: 3})
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	text := mcpResultText(t, res)
	var out struct {
		Count     int  `json:"count"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("json: %v", err)
	}
	if out.Count > 3 {
		t.Fatalf("limit 3 but got count %d", out.Count)
	}
	if out.Count == 3 && !out.Truncated {
		t.Fatal("expected truncated=true when hitting limit")
	}

	_, _, err = s.toolLs(context.Background(), nil, lsArgs{Path: "/etc"})
	if err == nil {
		t.Fatal("expected outside path rejection")
	}
	if !strings.Contains(err.Error(), "outside") {
		t.Fatalf("expected outside error, got %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// ---- ctx_fs: glob ----

func TestCtxGlob_GoFilesAndSkip(t *testing.T) {
	_, s := setupFSFixture(t)
	res, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "**/*.go"})
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	text := mcpResultText(t, res)
	var out struct {
		Matches []string `json:"matches"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, text)
	}
	joined := strings.Join(out.Matches, "\n")
	if !strings.Contains(joined, "a.go") {
		t.Fatalf("expected a.go: %s", joined)
	}
	if !strings.Contains(joined, "c.go") {
		t.Fatalf("expected c.go: %s", joined)
	}
	if !strings.Contains(joined, "d.go") {
		t.Fatalf("expected d.go: %s", joined)
	}
	if strings.Contains(joined, "vendor") {
		t.Fatalf("vendor should be skipped: %s", joined)
	}
	if strings.Contains(joined, ".git") {
		t.Fatalf(".git should be skipped: %s", joined)
	}

	res2, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "ignored.txt"})
	if err != nil {
		t.Fatalf("glob ignore: %v", err)
	}
	var outIgn struct {
		Matches []string `json:"matches"`
	}
	if err := json.Unmarshal([]byte(mcpResultText(t, res2)), &outIgn); err != nil {
		t.Fatalf("json: %v", err)
	}
	for _, m := range outIgn.Matches {
		if strings.Contains(m, "ignored.txt") {
			t.Fatalf(".gitignore should exclude ignored.txt, got matches %v", outIgn.Matches)
		}
	}

	res3, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "**/*", Limit: 2})
	if err != nil {
		t.Fatalf("glob limit: %v", err)
	}
	var out3 struct {
		Count     int  `json:"count"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(mcpResultText(t, res3)), &out3); err != nil {
		t.Fatal(err)
	}
	if out3.Count > 2 {
		t.Fatalf("limit 2 got %d", out3.Count)
	}
	if !out3.Truncated {
		t.Fatal("expected truncated=true")
	}
}

func TestCtxGlob_Outside(t *testing.T) {
	_, s := setupFSFixture(t)
	_, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "*", Path: "/etc"})
	if err == nil {
		t.Fatal("expected path outside rejection")
	}
}

// ---- ctx_fs: stat ----

func TestCtxStat_FileAndSymlink(t *testing.T) {
	wd, s := setupFSFixture(t)
	res, _, err := s.toolStat(context.Background(), nil, statArgs{Path: "a.go"})
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	text := mcpResultText(t, res)
	var out struct {
		Size      int64  `json:"size"`
		IsDir     bool   `json:"is_dir"`
		IsSymlink bool   `json:"is_symlink"`
		InWorkdir bool   `json:"in_workdir"`
		Mode      string `json:"mode"`
		Mtime     string `json:"mtime"`
	}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, text)
	}
	if out.IsDir {
		t.Fatal("a.go should not be dir")
	}
	if out.Size <= 0 {
		t.Fatalf("expected size > 0, got %d", out.Size)
	}
	if !out.InWorkdir {
		t.Fatal("expected in_workdir")
	}
	if out.Mode == "" || out.Mtime == "" {
		t.Fatalf("missing mode/mtime: %s", text)
	}

	link := filepath.Join(wd, "link-a")
	if err := os.Symlink(filepath.Join(wd, "a.go"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	res2, _, err := s.toolStat(context.Background(), nil, statArgs{Path: "link-a"})
	if err != nil {
		t.Fatalf("stat link: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res2), `"is_symlink": true`) {
		t.Fatalf("expected is_symlink: %s", mcpResultText(t, res2))
	}

	_, _, err = s.toolStat(context.Background(), nil, statArgs{Path: "/etc/passwd"})
	if err == nil {
		t.Fatal("expected outside rejection")
	}
}

// resolvePathKeepFinal must resolve relative paths against every workdir (not
// just workdirs[0]) and preserve leaf symlink semantics via Lstat.
func TestCtxStat_MultiWorkdirResolution(t *testing.T) {
	wd1 := t.TempDir()
	wd2 := t.TempDir()
	s := &server{workdirs: []string{wd1, wd2}}

	// wd2-only file: relative path must resolve into wd2 (previously silently
	// joined to workdirs[0] and failed with "no such file").
	mustWrite(t, filepath.Join(wd2, "only-wd2.txt"), "hello")
	res, _, err := s.toolStat(context.Background(), nil, statArgs{Path: "only-wd2.txt"})
	if err != nil {
		t.Fatalf("stat wd2-only file: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, filepath.Join(wd2, "only-wd2.txt")) {
		t.Fatalf("expected wd2 path in result, got: %s", text)
	}

	// Duplicate relative path in both workdirs: must demand an absolute path.
	mustWrite(t, filepath.Join(wd1, "dup.txt"), "one")
	mustWrite(t, filepath.Join(wd2, "dup.txt"), "two")
	_, _, err = s.toolStat(context.Background(), nil, statArgs{Path: "dup.txt"})
	if err == nil {
		t.Fatal("expected ambiguity error for duplicate relative path")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("expected absolute-path hint, got: %v", err)
	}

	// Missing under every workdir: explicit not-exists error.
	_, _, err = s.toolStat(context.Background(), nil, statArgs{Path: "nope.txt"})
	if err == nil {
		t.Fatal("expected error for missing relative path")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("expected does-not-exist error, got: %v", err)
	}

	// Absolute path still resolves and disambiguates (no regression).
	res2, _, err := s.toolStat(context.Background(), nil, statArgs{Path: filepath.Join(wd1, "dup.txt")})
	if err != nil {
		t.Fatalf("stat absolute dup: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res2), filepath.Join(wd1, "dup.txt")) {
		t.Fatalf("expected wd1 dup path in result, got: %s", mcpResultText(t, res2))
	}

	// Absolute path outside workspaces still rejected (no regression).
	if _, _, err = s.toolStat(context.Background(), nil, statArgs{Path: "/etc/hostname"}); err == nil {
		t.Fatal("expected outside rejection for absolute path")
	}
}

// A leaf symlink inside wd2 must be found by relative path (Lstat counts the
// link itself, even when broken) and reported as a symlink, not dereferenced.
func TestCtxStat_Wd2LeafSymlink(t *testing.T) {
	wd1 := t.TempDir()
	wd2 := t.TempDir()
	s := &server{workdirs: []string{wd1, wd2}}

	mustWrite(t, filepath.Join(wd2, "target.txt"), "data")
	link := filepath.Join(wd2, "leaf-link")
	if err := os.Symlink(filepath.Join(wd2, "target.txt"), link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	res, _, err := s.toolStat(context.Background(), nil, statArgs{Path: "leaf-link"})
	if err != nil {
		t.Fatalf("stat wd2 leaf symlink: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, `"is_symlink": true`) {
		t.Fatalf("expected is_symlink, got: %s", text)
	}
	if !strings.Contains(text, filepath.Join(wd2, "leaf-link")) {
		t.Fatalf("expected wd2 link path in result, got: %s", text)
	}

	// Broken leaf symlink in wd2 must still match and be reported as a link.
	broken := filepath.Join(wd2, "broken-link")
	if err := os.Symlink(filepath.Join(wd2, "no-such-target"), broken); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	res2, _, err := s.toolStat(context.Background(), nil, statArgs{Path: "broken-link"})
	if err != nil {
		t.Fatalf("stat wd2 broken symlink: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res2), `"is_symlink": true`) {
		t.Fatalf("expected broken link still reported as symlink, got: %s", mcpResultText(t, res2))
	}
}

// ---- ctx_fs: rg ----

func TestCtxRg_HitAndLiteral(t *testing.T) {
	_, s := setupFSFixture(t)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "Alpha",
		Glob:    "*.go",
	})
	if err != nil {
		t.Fatalf("rg: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "Alpha") {
		t.Fatalf("expected Alpha hit: %s", text)
	}
	if !strings.Contains(text, "a.go") {
		t.Fatalf("expected a.go path: %s", text)
	}

	res2, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern:    "alpha",
		IgnoreCase: true,
		Glob:       "*.go",
	})
	if err != nil {
		t.Fatalf("rg i: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res2), "Alpha") {
		t.Fatalf("ignore_case should match Alpha: %s", mcpResultText(t, res2))
	}

	mustWrite(t, filepath.Join(s.workdirs[0], "meta.txt"), "price is $5.00\n")
	res3, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "$5.00",
		Literal: true,
		Path:    "meta.txt",
	})
	if err != nil {
		t.Fatalf("rg literal: %v", err)
	}
	if !strings.Contains(mcpResultText(t, res3), "$5.00") {
		t.Fatalf("literal should match: %s", mcpResultText(t, res3))
	}

	_, _, err = s.toolRg(context.Background(), nil, rgArgs{Pattern: "x", Path: "/etc"})
	if err == nil {
		t.Fatal("expected outside rejection")
	}
}

func TestCtxRg_Limit(t *testing.T) {
	wd, s := setupFSFixture(t)
	var b strings.Builder
	for i := 0; i < 30; i++ {
		b.WriteString("MATCH_LINE unique_token\n")
	}
	mustWrite(t, filepath.Join(wd, "many.txt"), b.String())
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "unique_token",
		Limit:   5,
		Path:    "many.txt",
	})
	if err != nil {
		t.Fatalf("rg limit: %v", err)
	}
	text := mcpResultText(t, res)
	// Count path:line: match lines (exclude header).
	hits := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "unique_token") && strings.Contains(line, ":") {
			// header line also may contain words — only count content lines
			if strings.Contains(line, "many.txt") || strings.Contains(line, "MATCH_LINE") {
				hits++
			}
		}
	}
	if hits > 5 {
		t.Fatalf("limit 5 but saw %d hits in %s", hits, text)
	}
}

func TestMatchGlobPattern(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"*.go", "a.go", true},
		{"*.go", "a.txt", false},
		{"**/*.go", "sub/c.go", true},
		{"**/*.go", "sub/deep/d.go", true},
		{"**/*.go", "a.go", true},
		{"sub/*", "sub/c.go", true},
		{"sub/*", "sub/deep/d.go", false},
		{"**/d.go", "sub/deep/d.go", true},
	}
	for _, tc := range cases {
		got := matchGlobPattern(tc.pat, tc.name)
		if got != tc.want {
			t.Errorf("matchGlobPattern(%q, %q)=%v want %v", tc.pat, tc.name, got, tc.want)
		}
	}
}

// ---- M3: symlink escape e2e (ls/glob/rg must not leak outside secret) ----

func TestFSTools_SymlinkEscapeNoSecretLeak(t *testing.T) {
	wd := t.TempDir()
	outside := t.TempDir()
	secret := "OUTSIDE_SECRET_CONTENT_XYZ_98765"
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Symlink inside workdir pointing at external secret.
	link := filepath.Join(wd, "escape-link")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatal(err)
	}
	// Also a dir symlink escape.
	outsideDir := filepath.Join(outside, "secrdir")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "nested-secret.txt"), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(wd, "escape-dir")
	if err := os.Symlink(outsideDir, dirLink); err != nil {
		t.Fatal(err)
	}
	// Benign in-workspace file so tools return something.
	mustWrite(t, filepath.Join(wd, "ok.txt"), "safe content\n")

	s := testServerWithWorkdir(t, wd)

	// ctx_fs ls
	res, _, err := s.toolLs(context.Background(), nil, lsArgs{Depth: 3, Limit: 100})
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	lsText := mcpResultText(t, res)
	if strings.Contains(lsText, secret) {
		t.Fatalf("ls leaked outside secret content: %s", lsText)
	}
	if strings.Contains(lsText, "nested-secret") {
		t.Fatalf("ls should not list files under escaped dir symlink: %s", lsText)
	}

	// ctx_fs glob
	resG, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "**/*", Limit: 500})
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	gText := mcpResultText(t, resG)
	if strings.Contains(gText, secret) {
		t.Fatalf("glob leaked outside secret: %s", gText)
	}
	if strings.Contains(gText, "nested-secret") || strings.Contains(gText, outside) {
		t.Fatalf("glob should not include escaped paths: %s", gText)
	}

	// ctx_fs rg — must not match secret content via symlink
	resR, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "OUTSIDE_SECRET_CONTENT",
		Limit:   50,
	})
	if err != nil {
		t.Fatalf("rg: %v", err)
	}
	rText := mcpResultText(t, resR)
	if strings.Contains(rText, secret) || strings.Contains(rText, "OUTSIDE_SECRET_CONTENT") {
		// Header/engine line shouldn't carry the secret body either.
		// If matches=0 and no body lines with secret, OK — only fail on content leak.
		for _, line := range strings.Split(rText, "\n") {
			if strings.Contains(line, secret) {
				t.Fatalf("rg leaked outside secret: %s", rText)
			}
			// Match lines look like path:line:content
			if strings.Contains(line, "OUTSIDE_SECRET_CONTENT") && strings.Contains(line, ":") {
				t.Fatalf("rg matched escaped symlink content: %s", rText)
			}
		}
	}
}

// ---- M4: limit/depth over-limit validation (was silent clamp, now explicit error) ----

func TestCtxLs_OverLimitErrors(t *testing.T) {
	_, s := setupFSFixture(t)

	// Depth beyond fsMaxDepth must error with the legal range.
	_, _, err := s.toolLs(context.Background(), nil, lsArgs{Depth: 99})
	if err == nil {
		t.Fatal("expected error for depth > fsMaxDepth")
	}
	if !strings.Contains(err.Error(), "depth") || !strings.Contains(err.Error(), "5") {
		t.Fatalf("expected depth valid range (1-5) in error, got: %v", err)
	}

	// Limit beyond fsHardLimit must error with the legal range.
	_, _, err = s.toolLs(context.Background(), nil, lsArgs{Limit: 99999})
	if err == nil {
		t.Fatal("expected error for limit > fsHardLimit")
	}
	if !strings.Contains(err.Error(), "limit") || !strings.Contains(err.Error(), "2000") {
		t.Fatalf("expected limit valid range (1-2000) in error, got: %v", err)
	}

	// Boundary values remain accepted.
	res, _, err := s.toolLs(context.Background(), nil, lsArgs{Depth: fsMaxDepth, Limit: fsHardLimit})
	if err != nil {
		t.Fatalf("boundary depth/limit should be accepted: %v", err)
	}
	if mcpResultText(t, res) == "" {
		t.Fatal("expected result text")
	}
}

func TestCtxGlob_OverLimitErrors(t *testing.T) {
	wd := t.TempDir()
	for i := 0; i < 50; i++ {
		mustWrite(t, filepath.Join(wd, "g"+itoa(i)+".txt"), "y")
	}
	s := testServerWithWorkdir(t, wd)

	// Limit beyond fsHardLimit must error with the legal range (no silent clamp).
	_, _, err := s.toolGlob(context.Background(), nil, globArgs{
		Pattern: "**/*",
		Limit:   99999,
	})
	if err == nil {
		t.Fatal("expected error for limit > fsHardLimit")
	}
	if !strings.Contains(err.Error(), "limit") || !strings.Contains(err.Error(), "2000") {
		t.Fatalf("expected limit valid range (1-2000) in error, got: %v", err)
	}

	// Boundary value remains accepted.
	res, _, err := s.toolGlob(context.Background(), nil, globArgs{
		Pattern: "**/*",
		Limit:   fsHardLimit,
	})
	if err != nil {
		t.Fatalf("boundary limit should be accepted: %v", err)
	}
	if mcpResultText(t, res) == "" {
		t.Fatal("expected result text")
	}
}

func TestCtxRg_OverLimitErrors(t *testing.T) {
	wd := t.TempDir()
	var b strings.Builder
	for i := 0; i < 600; i++ {
		b.WriteString("RG_HARD_CAP_TOKEN line\n")
	}
	mustWrite(t, filepath.Join(wd, "many.txt"), b.String())
	s := testServerWithWorkdir(t, wd)

	// Limit beyond fsRgHardLimit must error with the legal range (no silent clamp).
	_, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "RG_HARD_CAP_TOKEN",
		Limit:   99999,
		Path:    "many.txt",
	})
	if err == nil {
		t.Fatal("expected error for limit > fsRgHardLimit")
	}
	if !strings.Contains(err.Error(), "limit") || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected limit valid range (1-500) in error, got: %v", err)
	}

	// Boundary value remains accepted.
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "RG_HARD_CAP_TOKEN",
		Limit:   fsRgHardLimit,
		Path:    "many.txt",
	})
	if err != nil {
		t.Fatalf("boundary limit should be accepted: %v", err)
	}
	if mcpResultText(t, res) == "" {
		t.Fatal("expected result text")
	}
}

// ============================================================================
// rg 子进程环境隔离（rgSystem 复用 childEnv/flattenEnv）
// ============================================================================

// writeFakeRg installs a fake rg shim that prints the CTXMODE_ENV_PROBE
// marker (a positive probe that proves the shim actually ran and inherited
// the non-sensitive marker) plus the FAKE_* env vars the subprocess actually
// inherited — a direct probe of the child environment.
func writeFakeRg(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nenv | grep '^CTXMODE_ENV_PROBE=' || true\nenv | grep '^FAKE_' || true\n"
	fake := filepath.Join(dir, "fakerg")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return fake
}

func TestRgSystem_StripsSensitiveEnv(t *testing.T) {
	t.Setenv("FAKE_TOKEN_SENTINEL", "super-secret-value")
	t.Setenv("FAKE_AUTH_SENTINEL", "super-secret-value")
	t.Setenv("CTXMODE_ENV_PROBE", "1")
	dir := t.TempDir()
	s := &server{}
	out, _, _, err := s.rgSystem(context.Background(), writeFakeRg(t), dir, rgArgs{Pattern: "x", Limit: 50}, 50, 0)
	if err != nil {
		t.Fatalf("rgSystem: %v", err)
	}
	if !strings.Contains(out, "CTXMODE_ENV_PROBE=1") {
		t.Fatalf("fake rg shim must have run and inherited the marker (probe absent): %q", out)
	}
	if strings.Contains(out, "FAKE_TOKEN_SENTINEL") || strings.Contains(out, "FAKE_AUTH_SENTINEL") || strings.Contains(out, "super-secret-value") {
		t.Fatalf("sensitive env leaked into rg child env: %q", out)
	}
}

func TestRgSystem_PassthroughKeepsEnv(t *testing.T) {
	t.Setenv("FAKE_TOKEN_SENTINEL", "super-secret-value")
	t.Setenv("CTXMODE_ENV_PASSTHROUGH", "1")
	dir := t.TempDir()
	s := &server{}
	out, _, _, err := s.rgSystem(context.Background(), writeFakeRg(t), dir, rgArgs{Pattern: "x", Limit: 50}, 50, 0)
	if err != nil {
		t.Fatalf("rgSystem: %v", err)
	}
	if !strings.Contains(out, "FAKE_TOKEN_SENTINEL=") {
		t.Fatalf("CTXMODE_ENV_PASSTHROUGH=1 must keep sensitive vars in rg child env, got %q", out)
	}
}

func TestGlob_GitignoreNegationAndNested(t *testing.T) {
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, ".gitignore"), "*.log\n!keep.log\n")
	mustWrite(t, filepath.Join(wd, "a.log"), "x")
	mustWrite(t, filepath.Join(wd, "keep.log"), "y")
	mustWrite(t, filepath.Join(wd, "sub", ".gitignore"), "skip.txt\n")
	mustWrite(t, filepath.Join(wd, "sub", "skip.txt"), "z")
	mustWrite(t, filepath.Join(wd, "sub", "ok.txt"), "w")
	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "**/*", Limit: 50})
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "a.log") {
		t.Fatalf("*.log should be ignored: %s", text)
	}
	if !strings.Contains(text, "keep.log") {
		t.Fatalf("!keep.log should be visible: %s", text)
	}
	if strings.Contains(text, "skip.txt") {
		t.Fatalf("nested gitignore should hide skip.txt: %s", text)
	}
	if !strings.Contains(text, "ok.txt") {
		t.Fatalf("nested ok.txt should be visible: %s", text)
	}
}

func TestSensitivePath_EnvDirectory(t *testing.T) {
	if !isSensitiveFilePath("/proj/.env/production") {
		t.Fatal(".env/production must be treated as sensitive")
	}
	if isSensitiveFilePath("/proj/src/main.go") {
		t.Fatal("normal source must not be sensitive")
	}
}
