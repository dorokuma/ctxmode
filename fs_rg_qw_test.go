package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// ---------- ① wildcard-only grep guard ----------

func TestIsWildcardOnlyPattern(t *testing.T) {
	yes := []string{".*", "*", ".+", ".", ".*.*", "^$", "()", ".*?", ".+", "  .*  ", "..", "^.*$"}
	for _, p := range yes {
		if !isWildcardOnlyPattern(p) {
			t.Errorf("isWildcardOnlyPattern(%q)=false, want true", p)
		}
	}
	no := []string{"foo.*", "Get.*Name", "Alpha", "func", `\d`, `[0-9]`, "foo", "a.b", "TODO", ""}
	for _, p := range no {
		if isWildcardOnlyPattern(p) {
			t.Errorf("isWildcardOnlyPattern(%q)=true, want false", p)
		}
	}
}

func TestToolRg_WildcardOnlyRejected(t *testing.T) {
	_, s := setupFSFixture(t)
	for _, pat := range []string{".*", "*", ".+", ".", ".*.*"} {
		_, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: pat})
		if err == nil {
			t.Errorf("pattern %q: expected tool error", pat)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "concrete") && !strings.Contains(msg, "identifier") {
			t.Errorf("pattern %q: error should steer to identifier, got %q", pat, msg)
		}
		if !strings.Contains(msg, "literal:true") {
			t.Errorf("pattern %q: error should mention literal:true escape, got %q", pat, msg)
		}
	}

	// Mixed patterns must pass (may have zero matches, but no tool error).
	if _, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "foo.*", Glob: "*.go"}); err != nil {
		t.Fatalf("mixed pattern foo.* must be allowed: %v", err)
	}
	if _, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "Get.*Name"}); err != nil {
		t.Fatalf("mixed pattern Get.*Name must be allowed: %v", err)
	}

	// Literal '*' is a real search, not a wildcard-only regex.
	if _, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "*", Literal: true}); err != nil {
		t.Fatalf("literal '*' must be allowed: %v", err)
	}
}

// ---------- ② wall-clock budget ----------

func TestEnvIntDefault_BudgetStyle(t *testing.T) {
	t.Setenv("CTXMODE_RG_BUDGET_MS_TEST", "2500")
	if got := envIntDefault("CTXMODE_RG_BUDGET_MS_TEST", 10000); got != 2500 {
		t.Fatalf("got %d want 2500", got)
	}
	t.Setenv("CTXMODE_RG_BUDGET_MS_TEST", "0")
	if got := envIntDefault("CTXMODE_RG_BUDGET_MS_TEST", 10000); got != 0 {
		t.Fatalf("got %d want 0 (disable)", got)
	}
	t.Setenv("CTXMODE_RG_BUDGET_MS_TEST", "-5")
	if got := envIntDefault("CTXMODE_RG_BUDGET_MS_TEST", 10000); got != -5 {
		t.Fatalf("got %d want -5 (disable)", got)
	}
	t.Setenv("CTXMODE_RG_BUDGET_MS_TEST", "abc")
	if got := envIntDefault("CTXMODE_RG_BUDGET_MS_TEST", 10000); got != 10000 {
		t.Fatalf("got %d want default 10000", got)
	}
}

func TestRgGo_BudgetStopsZeroMatch(t *testing.T) {
	orig := rgBudgetMs
	rgBudgetMs = 1
	defer func() { rgBudgetMs = orig }()

	wd := t.TempDir()
	for i := 0; i < 400; i++ {
		mustWrite(t, filepath.Join(wd, fmt.Sprintf("f%03d.txt", i)), "nope nope nope\n")
	}
	s := testServerWithWorkdir(t, wd)
	_, truncated, n, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "NO_SUCH_TOKEN_ZZZ", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
	if !errors.Is(err, errRgBudget) {
		t.Fatalf("zero-match scan must stop at budget, err=%v truncated=%v n=%d", err, truncated, n)
	}
	if !truncated {
		t.Fatal("expected truncated=true on budget stop")
	}
}

func TestRgGo_BudgetDisabledCompletes(t *testing.T) {
	orig := rgBudgetMs
	rgBudgetMs = 0
	defer func() { rgBudgetMs = orig }()

	wd := t.TempDir()
	for i := 0; i < 40; i++ {
		mustWrite(t, filepath.Join(wd, fmt.Sprintf("z%02d.txt", i)), "nope\n")
	}
	s := testServerWithWorkdir(t, wd)
	_, truncated, n, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "NO_SUCH_TOKEN_ZZZ", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
	if err != nil {
		t.Fatalf("disabled budget must complete: %v", err)
	}
	if truncated {
		t.Fatal("disabled budget should not truncate a small zero-match scan")
	}
	if n != 0 {
		t.Fatalf("want 0 matches, got %d", n)
	}
}

func TestRgSystem_BudgetKeepsPartial(t *testing.T) {
	dir := t.TempDir()
	s := &server{workdirs: []string{dir}}
	script := "#!/bin/sh\nroot=\"$1\"\nfor a; do root=\"$a\"; done\necho \"${root}:1:BUDGET_PARTIAL_TOKEN\"\nsleep 30\n"
	fake := filepath.Join(t.TempDir(), "rg")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	out, truncated, n, err := s.rgSystem(ctx, fake, dir, rgArgs{Pattern: "x", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
	if !errors.Is(err, errRgBudget) {
		t.Fatalf("expected errRgBudget, got err=%v out=%q n=%d truncated=%v", err, out, n, truncated)
	}
	if !truncated {
		t.Fatal("expected truncated=true")
	}
	if !strings.Contains(out, "BUDGET_PARTIAL_TOKEN") {
		t.Fatalf("expected partial capture, got %q", out)
	}
}

func TestRgRenderResult_BudgetHint(t *testing.T) {
	s := &server{}
	res := s.rgRenderResult(rgHeader{Engine: "go", Matches: 0, Truncated: true, BudgetHit: true}, "")
	text := mcpResultText(t, res)
	if !strings.Contains(text, "budget_exceeded=true") {
		t.Fatalf("header missing budget_exceeded: %s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Fatalf("header missing truncated=true (must not be short-circuited by budget_exceeded): %s", text)
	}
	if !strings.Contains(text, "narrow path/glob") {
		t.Fatalf("missing narrow-path hint: %s", text)
	}
	if !strings.Contains(text, "ctx_kb action=search") {
		t.Fatalf("budget hint must suggest ctx_kb search: %s", text)
	}
	if strings.Contains(text, "offset") {
		t.Fatalf("budget hint must not mention rg offset: %s", text)
	}
}

func TestToolRg_BudgetHintOnTimeout(t *testing.T) {
	orig := rgBudgetMs
	rgBudgetMs = 150
	defer func() { rgBudgetMs = orig }()

	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "hit.txt"), "BUDGET_HINT_TOKEN\n")
	s := testServerWithWorkdir(t, wd)

	scriptDir := t.TempDir()
	script := "#!/bin/sh\nroot=\"$1\"\nfor a; do root=\"$a\"; done\necho \"${root}/hit.txt:1:BUDGET_HINT_TOKEN\"\nsleep 30\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "rg"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", scriptDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "BUDGET_HINT_TOKEN", Path: wd})
	if err != nil {
		t.Fatalf("toolRg budget timeout should return partial result, not error: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "budget_exceeded=true") {
		t.Fatalf("expected budget_exceeded in header: %s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Fatalf("expected truncated=true independently of budget_exceeded: %s", text)
	}
	if !strings.Contains(text, "narrow path/glob") {
		t.Fatalf("expected narrow-path hint: %s", text)
	}
	if !strings.Contains(text, "ctx_kb action=search") {
		t.Fatalf("budget hint must suggest ctx_kb search: %s", text)
	}
	if strings.Contains(text, "offset") {
		t.Fatalf("budget timeout hint must not mention rg offset: %s", text)
	}
}

// ---------- ③ tool guidance ----------

func TestServerInstructions_RgGuidance(t *testing.T) {
	for _, want := range []string{
		"concrete identifier",
		"never '.*'",
		"after 1-2 greps",
		"ctx_kb action=search",
		"offset paging",
	} {
		if !strings.Contains(serverInstructions, want) {
			t.Errorf("serverInstructions missing %q", want)
		}
	}
}

func TestPiGuidelines_RgGuidance(t *testing.T) {
	b, err := os.ReadFile("integrations/pi/ctxmode.ts")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{
		"never '.*'",
		"after 1-2 greps",
		"ctx_kb action=search",
		"offset paging",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("ctxmode.ts promptGuidelines missing %q", want)
		}
	}
}

// ---------- ④ definition-line heuristic + Read hint ----------

func TestIsDefinitionLine(t *testing.T) {
	yes := []string{
		"func DoWork() {",
		"  type Reader interface {",
		"pub(crate) fn foo()",
		"export default function foo()",
		"class Bar:",
		"def baz(self):",
		"async function qux()",
		"impl Display for X",
		"enum Color {",
		"trait Foo {",
		"interface Foo {",
		"struct Point {",
		"module M",
		"object Foo",
		"public class Bar",
		"static func helper()",
		"func (s *T) Method()",
		"  func (recv *Type) Name(a int)",
	}
	for _, line := range yes {
		if !isDefinitionLine(line) {
			t.Errorf("isDefinitionLine(%q)=false, want true", line)
		}
	}
	no := []string{
		"type(x)",
		"type (x)", // '(' only for func, not type
		"object.foo",
		"interface{}",
		"type = 1",
		"object = {}",
		"typeof x",
		"funcfoo()",
		"defaults: 1",
		"// func foo",
		"x := struct{}",
		"fn: not a def",
		"return foo",
	}
	for _, line := range no {
		if isDefinitionLine(line) {
			t.Errorf("isDefinitionLine(%q)=true, want false", line)
		}
	}
}

func TestToolRg_DefTagAndReadHint(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "a.go"), "package main\nfunc DoWork() {}\n")
	mustWrite(t, filepath.Join(wd, "b.go"), "package main\nconst DoWorkName = \"x\"\n")
	s := testServerWithWorkdir(t, wd)

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "DoWork", Path: wd})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "→ Read") {
		t.Fatalf("first screen missing → Read hint: %s", text)
	}
	if !strings.Contains(text, "[def]") {
		t.Fatalf("expected [def] on func DoWork line: %s", text)
	}
	// Match-line order must not be rearranged within a file; a.go def stays a.go:2.
	if !strings.Contains(text, "a.go:2:") {
		t.Fatalf("expected a.go:2 match line preserved: %s", text)
	}
}

func TestToolRg_DefTagEntersIndex(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess-def",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}
	var b strings.Builder
	b.WriteString("func IndexedDef() {}\n")
	for i := 0; i < 24; i++ {
		b.WriteString("IndexedDef mention\n")
	}
	commitFile(t, repoDir, "def.go", b.String(), "commit def")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "IndexedDef", Path: repoDir})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "→ Read") {
		t.Fatalf("summary missing → Read: %s", text)
	}
	if !strings.Contains(text, "[def]") {
		t.Fatalf("summary missing [def]: %s", text)
	}
	var label string
	for _, part := range strings.Split(strings.Split(text, "\n")[0], " ") {
		if strings.HasPrefix(part, "indexed=") {
			label = strings.TrimPrefix(part, "indexed=")
		}
	}
	if label == "" {
		t.Fatalf("no indexed label: %s", text)
	}
	doc, err := st.Get(label)
	if err != nil || doc == nil {
		t.Fatalf("store get %q: %v", label, err)
	}
	if !strings.Contains(doc.Content, "[def]") {
		t.Fatalf("[def] must enter ctx_kb index, got:\n%s", doc.Content)
	}
}

func TestRgReadHint_FallsBackToFirstFile(t *testing.T) {
	groups := []rgFileGroup{
		{file: "a.txt", hits: 1, lines: []string{"a.txt:1:hello"}},
		{file: "b.txt", hits: 1, lines: []string{"b.txt:1:world"}},
	}
	p, isDef, ok := rgReadHint(groups)
	if !ok || p != "a.txt" || isDef {
		t.Fatalf("want a.txt no-def, got path=%q isDef=%v ok=%v", p, isDef, ok)
	}
}

// ---------- ⑤ match-line truncation + large-file hint ----------

func TestTruncateRgMatchLine(t *testing.T) {
	if got := truncateRgMatchLine("short"); got != "short" {
		t.Fatalf("short: %q", got)
	}
	long := strings.Repeat("a", 500)
	if got := truncateRgMatchLine(long); got != long {
		t.Fatal("500 runes must be kept intact")
	}
	longer := strings.Repeat("a", 600)
	got := truncateRgMatchLine(longer)
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("missing ellipsis: %q", got)
	}
	if utf8.RuneCountInString(strings.TrimSuffix(got, "...")) != 500 {
		t.Fatalf("want 500 runes before ellipsis, got %d", utf8.RuneCountInString(strings.TrimSuffix(got, "...")))
	}
	cjk := strings.Repeat("你", 520)
	got = truncateRgMatchLine(cjk)
	if !utf8.ValidString(got) {
		t.Fatal("truncated CJK must stay valid UTF-8")
	}
	if utf8.RuneCountInString(strings.TrimSuffix(got, "...")) != 500 {
		t.Fatalf("CJK: want 500 runes, got %d", utf8.RuneCountInString(strings.TrimSuffix(got, "...")))
	}
}

func TestToolRg_TruncatesLongMatchLine(t *testing.T) {
	wd := t.TempDir()
	payload := "HEAD_TOKEN " + strings.Repeat("x", 600) + " TAIL_UNIQUE_ZZZ"
	mustWrite(t, filepath.Join(wd, "long.txt"), payload+"\n")
	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "HEAD_TOKEN", Path: wd})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "TAIL_UNIQUE_ZZZ") {
		t.Fatalf("tail past 500 runes should be truncated: %s", text)
	}
	if !strings.Contains(text, "...") {
		t.Fatalf("expected ellipsis on truncated line: %s", text)
	}
	if !strings.Contains(text, "HEAD_TOKEN") {
		t.Fatalf("head of line must be kept: %s", text)
	}
}

func TestToolRg_DedupHashOnTruncatedText(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess-trunc",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}
	var b strings.Builder
	for i := 0; i < 25; i++ {
		b.WriteString("TRUNC_DEDUP_TOKEN " + strings.Repeat("y", 600) + "\n")
	}
	commitFile(t, repoDir, "long.txt", b.String(), "commit long")

	res1, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "TRUNC_DEDUP_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("1st: %v", err)
	}
	text1 := mcpResultText(t, res1)
	res2, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "TRUNC_DEDUP_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("2nd: %v", err)
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
		t.Fatalf("dedup should reuse truncated-text hash, label1=%q label2=%q", label1, label2)
	}
	if !strings.Contains(text2, "reused") {
		t.Errorf("expected reused marker: %s", text2)
	}
	label := strings.TrimPrefix(label1, "indexed=")
	doc, err := st.Get(label)
	if err != nil || doc == nil {
		t.Fatalf("store: %v", err)
	}
	for _, line := range strings.Split(doc.Content, "\n") {
		if !isRgMatchLine(line) {
			continue
		}
		_, num, ok := splitRgMatchLine(line)
		if !ok {
			continue
		}
		prefixLen := len("long.txt") + 1 + len(num) + 1
		if len(line) < prefixLen {
			continue
		}
		content := line[prefixLen:]
		if utf8.RuneCountInString(strings.TrimSuffix(content, "...")) > 500 {
			t.Fatalf("indexed content not truncated: %q", content)
		}
	}
}

func TestToolRg_LargeFileHint(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess-large",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}
	var b strings.Builder
	for i := 0; i < 25; i++ {
		b.WriteString("LARGE_HINT_TOKEN line\n")
	}
	// Pad past 20KB so the summary group header gets a size tag.
	b.WriteString(strings.Repeat("x", 25*1024))
	commitFile(t, repoDir, "big.txt", b.String(), "commit big")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "LARGE_HINT_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "KB - use offset to read relevant section") {
		t.Fatalf("expected large-file hint, got: %s", text)
	}
}

// ---------- ⑥ git porcelain short tags + glob dirty-first ----------

func TestPorcelainTagFromXY(t *testing.T) {
	cases := []struct {
		x, y byte
		want string
	}{
		{'?', '?', "??"},
		{' ', 'M', "M"},
		{'M', ' ', "M"},
		{'M', 'M', "M"},
		{'A', 'M', "M"}, // modified wins over added
		{'A', ' ', "A"},
		{'R', ' ', "A"},
		{'C', ' ', "A"},
		{' ', 'A', "A"},
		{'D', ' ', "M"},
	}
	for _, tc := range cases {
		if got := porcelainTagFromXY(tc.x, tc.y); got != tc.want {
			t.Errorf("XY=%c%c got %q want %q", tc.x, tc.y, got, tc.want)
		}
	}
}

func TestParsePorcelainZFull_Tags(t *testing.T) {
	toplevel := "/workspace/repo"
	raw := []byte("?? untracked.go\x00 M modified.go\x00A  added.go\x00AM both.go\x00")
	dirty, tags := parsePorcelainZFull(raw, toplevel)
	if len(dirty) != 4 {
		t.Fatalf("dirty=%d", len(dirty))
	}
	want := map[string]string{
		filepath.Join(toplevel, "untracked.go"): "??",
		filepath.Join(toplevel, "modified.go"):  "M",
		filepath.Join(toplevel, "added.go"):     "A",
		filepath.Join(toplevel, "both.go"):      "M",
	}
	for path, tag := range want {
		if tags[filepath.Clean(path)] != tag {
			t.Errorf("%s: tag=%q want %q (tags=%v)", path, tags[filepath.Clean(path)], tag, tags)
		}
	}
}

func TestGlob_DirtyFirst(t *testing.T) {
	orig := rgGitRankEnabled
	rgGitRankEnabled = true
	defer func() { rgGitRankEnabled = orig }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	commitFile(t, repoDir, "a_clean.txt", "x", "c1")
	commitFile(t, repoDir, "m_mod.txt", "x", "c2")
	commitFile(t, repoDir, "z_clean.txt", "x", "c3")
	mustWrite(t, filepath.Join(repoDir, "m_mod.txt"), "edited\n")
	mustWrite(t, filepath.Join(repoDir, "u_new.txt"), "new\n")

	s := &server{
		workdirs:      []string{repoDir},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}
	res, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "*.txt", Path: repoDir})
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out struct {
		Matches []string `json:"matches"`
	}
	if err := json.Unmarshal([]byte(mcpResultText(t, res)), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, mcpResultText(t, res))
	}
	if len(out.Matches) < 4 {
		t.Fatalf("matches=%v", out.Matches)
	}
	// Dirty (m_mod.txt, u_new.txt) first, lex among themselves; then clean lex.
	var dirtyPos, cleanPos []int
	for i, m := range out.Matches {
		base := filepath.Base(m)
		switch base {
		case "m_mod.txt", "u_new.txt":
			dirtyPos = append(dirtyPos, i)
		case "a_clean.txt", "z_clean.txt":
			cleanPos = append(cleanPos, i)
		}
	}
	if len(dirtyPos) != 2 || len(cleanPos) != 2 {
		t.Fatalf("dirtyPos=%v cleanPos=%v matches=%v", dirtyPos, cleanPos, out.Matches)
	}
	if dirtyPos[0] > cleanPos[0] || dirtyPos[1] > cleanPos[0] {
		t.Fatalf("dirty files should precede clean: %v", out.Matches)
	}
	// Relative order among dirty is lex: m_mod then u_new.
	if filepath.Base(out.Matches[dirtyPos[0]]) != "m_mod.txt" {
		t.Fatalf("among dirty, lex order expected m_mod then u_new: %v", out.Matches)
	}
}

func TestGlob_DirtyFirstDisabledKeepsLex(t *testing.T) {
	orig := rgGitRankEnabled
	rgGitRankEnabled = false
	defer func() { rgGitRankEnabled = orig }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	commitFile(t, repoDir, "a.txt", "x", "c1")
	mustWrite(t, filepath.Join(repoDir, "z.txt"), "new\n")
	s := &server{workdirs: []string{repoDir}, gitDirtyCache: make(map[string]gitDirtyEntry)}
	res, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "*.txt", Path: repoDir})
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out struct {
		Matches []string `json:"matches"`
	}
	if err := json.Unmarshal([]byte(mcpResultText(t, res)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Matches) < 2 {
		t.Fatalf("matches=%v", out.Matches)
	}
	if filepath.Base(out.Matches[0]) != "a.txt" {
		t.Fatalf("with git rank off, lex order expected, got %v", out.Matches)
	}
}

// ---------- R1: subdirectory search root dirty keys / tags ----------

func TestGitDirtyState_SubdirRootUsesToplevel(t *testing.T) {
	orig := rgGitRankEnabled
	rgGitRankEnabled = true
	defer func() { rgGitRankEnabled = orig }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	commitFile(t, repoDir, "sub/mod.go", "package sub\n", "c1")
	commitFile(t, repoDir, "sub/clean.go", "package sub\n", "c2")
	mustWrite(t, filepath.Join(repoDir, "sub", "mod.go"), "package sub\n// edited\n")
	mustWrite(t, filepath.Join(repoDir, "sub", "new.go"), "package sub\n")

	s := &server{
		workdirs:      []string{repoDir},
		gitDirtyCache: make(map[string]gitDirtyEntry),
	}
	sub := filepath.Join(repoDir, "sub")
	dirty, tags, status := s.gitDirtyState(context.Background(), sub)
	if status != "ok" {
		t.Fatalf("status=%s", status)
	}
	modAbs := filepath.Clean(filepath.Join(repoDir, "sub", "mod.go"))
	newAbs := filepath.Clean(filepath.Join(repoDir, "sub", "new.go"))
	if _, ok := dirty[modAbs]; !ok {
		t.Fatalf("dirty keys must be toplevel-absolute, want %s in %v", modAbs, dirty)
	}
	if _, ok := dirty[newAbs]; !ok {
		t.Fatalf("missing untracked %s in %v", newAbs, dirty)
	}
	wrong := filepath.Clean(filepath.Join(sub, "sub", "mod.go"))
	if _, ok := dirty[wrong]; ok {
		t.Fatalf("double-prefixed dirty key %s must not exist: %v", wrong, dirty)
	}
	if tags[modAbs] != "M" {
		t.Fatalf("mod.go tag=%q want M (tags=%v)", tags[modAbs], tags)
	}
	if tags[newAbs] != "??" {
		t.Fatalf("new.go tag=%q want ?? (tags=%v)", tags[newAbs], tags)
	}
}

func TestToolRgAndGlob_SubdirRootDirtyFirstAndTags(t *testing.T) {
	origRank := rgGitRankEnabled
	rgGitRankEnabled = true
	defer func() { rgGitRankEnabled = origRank }()
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess-subdir",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	var cleanBody, modBody, newBody strings.Builder
	for i := 0; i < 12; i++ {
		cleanBody.WriteString("SUBDIR_DIRTY_TOKEN clean\n")
		modBody.WriteString("SUBDIR_DIRTY_TOKEN mod\n")
		newBody.WriteString("SUBDIR_DIRTY_TOKEN new\n")
	}
	commitFile(t, repoDir, "sub/clean.go", cleanBody.String(), "c1")
	commitFile(t, repoDir, "sub/mod.go", modBody.String(), "c2")
	mustWrite(t, filepath.Join(repoDir, "sub", "mod.go"), modBody.String()+"// edited\n")
	mustWrite(t, filepath.Join(repoDir, "sub", "new.go"), newBody.String())

	sub := filepath.Join(repoDir, "sub")
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "SUBDIR_DIRTY_TOKEN", Path: sub})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "git_dirty=") {
		t.Fatalf("expected git_dirty in header: %s", text)
	}
	modIdx := strings.Index(text, "sub/mod.go")
	newIdx := strings.Index(text, "sub/new.go")
	cleanIdx := strings.Index(text, "sub/clean.go")
	if modIdx < 0 || newIdx < 0 || cleanIdx < 0 {
		t.Fatalf("missing subdir files in output: %s", text)
	}
	if cleanIdx < modIdx || cleanIdx < newIdx {
		t.Fatalf("clean file should not precede dirty files:\n%s", text)
	}
	if !strings.Contains(text, "M sub/mod.go") {
		t.Fatalf("expected M tag on sub/mod.go:\n%s", text)
	}
	if !strings.Contains(text, "?? sub/new.go") {
		t.Fatalf("expected ?? tag on sub/new.go:\n%s", text)
	}

	gres, _, err := s.toolGlob(context.Background(), nil, globArgs{Pattern: "*.go", Path: sub})
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out struct {
		Matches []string `json:"matches"`
	}
	if err := json.Unmarshal([]byte(mcpResultText(t, gres)), &out); err != nil {
		t.Fatalf("glob json: %v\n%s", err, mcpResultText(t, gres))
	}
	var dirtyPos, cleanPos []int
	for i, m := range out.Matches {
		switch filepath.Base(m) {
		case "mod.go", "new.go":
			dirtyPos = append(dirtyPos, i)
		case "clean.go":
			cleanPos = append(cleanPos, i)
		}
	}
	if len(dirtyPos) != 2 || len(cleanPos) != 1 {
		t.Fatalf("glob dirtyPos=%v cleanPos=%v matches=%v", dirtyPos, cleanPos, out.Matches)
	}
	for _, d := range dirtyPos {
		if d > cleanPos[0] {
			t.Fatalf("glob dirty-first failed under path=subdir: %v", out.Matches)
		}
	}
}

// ---------- R2: budget partial set still auto-indexes ----------

func TestToolRg_BudgetTimeoutStillAutoIndexes(t *testing.T) {
	origBudget := rgBudgetMs
	rgBudgetMs = 150
	defer func() { rgBudgetMs = origBudget }()
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess-budget-idx",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	var body strings.Builder
	for i := 0; i < 30; i++ {
		body.WriteString("BUDGET_INDEX_TOKEN line\n")
	}
	commitFile(t, repoDir, "hits.txt", body.String(), "commit hits")

	scriptDir := t.TempDir()
	script := "#!/bin/sh\nroot=\"$1\"\nfor a; do root=\"$a\"; done\ni=1\nwhile [ \"$i\" -le 25 ]; do\n  echo \"${root}/hits.txt:$i:BUDGET_INDEX_TOKEN line\"\n  i=$((i+1))\ndone\nsleep 30\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "rg"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", scriptDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "BUDGET_INDEX_TOKEN", Path: repoDir})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "budget_exceeded=true") {
		t.Fatalf("expected budget_exceeded: %s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Fatalf("expected truncated=true: %s", text)
	}
	if !strings.Contains(text, "indexed=") {
		t.Fatalf("budget timeout must still auto-index: %s", text)
	}
	if !strings.Contains(text, "partial set indexed (budget exceeded)") {
		t.Fatalf("expected partial-set tag: %s", text)
	}
	if strings.Contains(text, "capture truncated at 200KB") {
		t.Fatalf("budget partial must not use 200KB-cap wording: %s", text)
	}
	if strings.Contains(text, "offset=") || strings.Contains(text, "offset paging") {
		t.Fatalf("budget summary must not suggest rg offset: %s", text)
	}

	var label string
	for _, part := range strings.Split(strings.Split(text, "\n")[0], " ") {
		if strings.HasPrefix(part, "indexed=") {
			label = strings.TrimPrefix(part, "indexed=")
		}
	}
	if label == "" {
		t.Fatalf("no indexed label: %s", text)
	}
	doc, err := st.Get(label)
	if err != nil || doc == nil {
		t.Fatalf("store get %q: %v", label, err)
	}
	if !strings.Contains(doc.Content, "# partial=true") {
		t.Fatalf("KB document must carry partial=true, got:\n%s", doc.Content)
	}
}

// ---------- R3: match-line truncation switch ----------

func TestPrepareRgGroups_TruncationDisabled(t *testing.T) {
	orig := rgMaxLineRunes
	rgMaxLineRunes = 0
	defer func() { rgMaxLineRunes = orig }()

	tail := "TAIL_UNIQUE_KEEP_ZZZ"
	long := "HEAD_TOKEN " + strings.Repeat("x", 600) + " " + tail
	groups := []rgFileGroup{{
		file:  "long.txt",
		hits:  1,
		lines: []string{"long.txt:1:" + long},
	}}
	prepareRgGroups(groups)
	if !strings.Contains(groups[0].lines[0], tail) {
		t.Fatalf("rgMaxLineRunes<=0 must keep the full line, got %q", groups[0].lines[0])
	}
	if strings.HasSuffix(groups[0].lines[0], "...") && !strings.HasSuffix(long, "...") {
		t.Fatalf("disabled truncation must not add ellipsis: %q", groups[0].lines[0])
	}
}

func TestToolRg_MaxLineRunesDisabledKeepsTail(t *testing.T) {
	orig := rgMaxLineRunes
	rgMaxLineRunes = 0
	defer func() { rgMaxLineRunes = orig }()

	wd := t.TempDir()
	payload := "HEAD_TOKEN " + strings.Repeat("x", 600) + " TAIL_UNIQUE_KEEP_ZZZ"
	mustWrite(t, filepath.Join(wd, "long.txt"), payload+"\n")
	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "HEAD_TOKEN", Path: wd})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "TAIL_UNIQUE_KEEP_ZZZ") {
		t.Fatalf("disabled truncation must keep tail: %s", text)
	}
}

func TestTruncateRgMatchLine_Disabled(t *testing.T) {
	orig := rgMaxLineRunes
	rgMaxLineRunes = -1
	defer func() { rgMaxLineRunes = orig }()
	long := strings.Repeat("a", 600)
	if got := truncateRgMatchLine(long); got != long {
		t.Fatalf("<=0 must be no-op, got len=%d", len(got))
	}
}

// ---------- R4: system rg --line-buffered when budget on ----------

func TestRgSystem_LineBufferedWhenBudgetOn(t *testing.T) {
	dir := t.TempDir()
	s := &server{workdirs: []string{dir}}
	script := "#!/bin/sh\nsaw=\nroot=\"$1\"\nfor a; do\n  root=\"$a\"\n  if [ \"$a\" = \"--line-buffered\" ]; then saw=1; fi\ndone\nif [ -n \"$saw\" ]; then echo \"${root}:1:HAS_LINE_BUFFERED\"; else echo \"${root}:1:NO_LINE_BUFFERED\"; fi\n"
	fake := filepath.Join(t.TempDir(), "rg")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	orig := rgBudgetMs
	rgBudgetMs = 5000
	defer func() { rgBudgetMs = orig }()
	out, _, _, err := s.rgSystem(context.Background(), fake, dir, rgArgs{Pattern: "x", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
	if err != nil {
		t.Fatalf("rgSystem: %v", err)
	}
	if !strings.Contains(out, "HAS_LINE_BUFFERED") {
		t.Fatalf("budget on must pass --line-buffered, got %q", out)
	}

	rgBudgetMs = 0
	out, _, _, err = s.rgSystem(context.Background(), fake, dir, rgArgs{Pattern: "x", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
	if err != nil {
		t.Fatalf("rgSystem budget off: %v", err)
	}
	if !strings.Contains(out, "NO_LINE_BUFFERED") {
		t.Fatalf("budget off must not pass --line-buffered, got %q", out)
	}
}

// ---------- R5: few-file repo still hits wall-clock budget ----------

func TestRgGo_BudgetStopsFewerThan8Files(t *testing.T) {
	orig := rgBudgetMs
	rgBudgetMs = 1
	defer func() { rgBudgetMs = orig }()

	wd := t.TempDir()
	payload := strings.Repeat("nope nope nope\n", 80_000) // ~1.2MB, under 5MB skip
	for i := 0; i < 3; i++ {
		mustWrite(t, filepath.Join(wd, fmt.Sprintf("f%d.txt", i)), payload)
	}
	s := testServerWithWorkdir(t, wd)
	_, truncated, _, err := s.rgGo(context.Background(), wd, rgArgs{Pattern: "NO_SUCH_TOKEN_ZZZ", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
	if !errors.Is(err, errRgBudget) {
		t.Fatalf("<8-file scan must stop at budget, err=%v truncated=%v", err, truncated)
	}
	if !truncated {
		t.Fatal("expected truncated=true on budget stop")
	}
}

// ---------- R6: 20KiB large-file threshold ----------

func TestRgLargeFileBytes_Is20KiB(t *testing.T) {
	if rgLargeFileBytes != 20*1024 {
		t.Fatalf("rgLargeFileBytes=%d want 20*1024", rgLargeFileBytes)
	}
}

func TestRgFileSizeTag_Threshold(t *testing.T) {
	wd := t.TempDir()
	under := filepath.Join(wd, "under.txt")
	over := filepath.Join(wd, "over.txt")
	mustWrite(t, under, strings.Repeat("a", 20*1024-1))
	mustWrite(t, over, strings.Repeat("a", 20*1024))
	if tag := rgFileSizeTag(wd, "under.txt"); tag != "" {
		t.Fatalf("19999 bytes must not tag, got %q", tag)
	}
	if tag := rgFileSizeTag(wd, "over.txt"); tag == "" {
		t.Fatal("20480 bytes must tag")
	}
}

func TestToolRg_GoMethodDefTag(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "m.go"), "package main\nfunc (s *T) DoWork() {}\n")
	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "DoWork", Path: wd})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "[def]") {
		t.Fatalf("Go method must be tagged [def]: %s", text)
	}
}
