package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures below are AWS's public documentation example key and an
// obviously fake PEM block, split so secret scanners do not flag them.
const fakeAWSKey = "AKIA" + "IOSFODNN7EXAMPLE"
const fakePEMHeader = "-----BEGIN RSA " + "PRIVATE KEY-----"
const fakePEMFooter = "-----END RSA " + "PRIVATE KEY-----"

// Regression tests for the fs_tools.go security fixes:
//   F1  sensitive-file fence (glob order, explicit path, output-side filter,
//       sensitive-content gate on directly-returned results)
//   F2  dedupKey carries truncated/budget state
//   F4a killedByBudget distinguishes the rg budget from the parent context
//   F4b rgGo fallback is charged only the remaining budget
//   F4e wildcard-only guard strips zero-width assertions

// expiredCtx returns an already-expired context (budget deadline hit).
func expiredCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	t.Cleanup(cancel)
	<-ctx.Done()
	return ctx
}

// writeArgDumpRg installs a fake rg that dumps its argv one line per arg.
func writeArgDumpRg(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nfor a in \"$@\"; do echo \"ARG:$a\"; done\n"
	fake := filepath.Join(dir, "rg")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return fake
}

// ---------- F1.1 client glob must precede the built-in deny globs ----------

func TestSecurityFixes_UserGlobBeforeDenyGlobs(t *testing.T) {
	fake := writeArgDumpRg(t)
	wd := t.TempDir()
	s := testServerWithWorkdir(t, wd)
	out, _, _, err := s.rgSystem(context.Background(), fake, wd, rgArgs{Pattern: "x", Glob: ".env*", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
	if err != nil {
		t.Fatalf("rgSystem: %v", err)
	}
	userIdx, denyIdx := -1, -1
	for i, line := range strings.Split(out, "\n") {
		switch line {
		case "ARG:.env*":
			if userIdx < 0 {
				userIdx = i
			}
		case "ARG:!.env*":
			if denyIdx < 0 {
				denyIdx = i
			}
		}
	}
	if denyIdx < 0 {
		t.Fatalf("built-in deny glob !.env* missing from rg args: %q", out)
	}
	if userIdx < 0 {
		t.Fatalf("client glob .env* missing from rg args: %q", out)
	}
	if userIdx > denyIdx {
		t.Fatalf("client glob (idx %d) must precede deny glob (idx %d) so the deny list wins: %q", userIdx, denyIdx, out)
	}
}

func TestSecurityFixes_UserGlobCannotRevealEnv(t *testing.T) {
	skipIfNoSystemRg(t)
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, ".env"), "SECRET_TOKEN_ALPHA=hunter2\n")
	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "SECRET_TOKEN_ALPHA", Glob: ".env*"})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "SECRET_TOKEN_ALPHA") || strings.Contains(text, "hunter2") {
		t.Fatalf("client glob .env* must not override the deny-glob fence: %s", text)
	}
}

// ---------- F1.2 explicit path to a sensitive file must be rejected ----------

func TestSecurityFixes_ExplicitSensitivePathRejected(t *testing.T) {
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, ".env"), "SECRET_TOKEN_ALPHA=hunter2\n")
	mustWrite(t, filepath.Join(wd, "a.go"), "package main\nfunc Alpha() {}\n")
	s := testServerWithWorkdir(t, wd)

	_, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "SECRET_TOKEN_ALPHA", Path: ".env"})
	if err == nil {
		t.Fatal("explicit rg path to .env must be rejected")
	}
	if !strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("rejection should mention the sensitive fence, got: %v", err)
	}

	// Searching the containing directory stays legal (deny globs and the
	// output-side filter handle it there), and plain files are unaffected.
	if _, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "Alpha", Path: wd}); err != nil {
		t.Fatalf("directory search must keep working: %v", err)
	}
}

// ---------- F1.3 output-side filter drops sensitive result lines ----------

func TestSecurityFixes_OutputSideSensitiveFilter(t *testing.T) {
	dir := t.TempDir()
	s := testServerWithWorkdir(t, dir)
	script := "#!/bin/sh\nroot=\"\"\nfor a; do root=\"$a\"; done\n" +
		"echo \"${root}/.env:1:SECRET_ENV_LINE\"\n" +
		"echo \"${root}/.env-2-CONTEXT_SECRET_LINE\"\n" +
		"echo \"${root}/id_rsa.key-3-KEY_SECRET_LINE\"\n" +
		"echo \"${root}/server.go:1:PUBLIC_LINE_OK\"\n"
	fake := filepath.Join(dir, "rg")
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, _, _, err := s.rgSystem(context.Background(), fake, dir, rgArgs{Pattern: "x", Limit: 50}, 50, 0, fsRgMaxOutputBytes)
	if err != nil {
		t.Fatalf("rgSystem: %v", err)
	}
	if !strings.Contains(out, "PUBLIC_LINE_OK") {
		t.Fatalf("non-sensitive result line must survive: %q", out)
	}
	for _, leak := range []string{"SECRET_ENV_LINE", "CONTEXT_SECRET_LINE", "KEY_SECRET_LINE", ".env", "id_rsa"} {
		if strings.Contains(out, leak) {
			t.Fatalf("sensitive line leaked into output (%s): %q", leak, out)
		}
	}
}

// ---------- F1 sensitive-content gate on directly-returned results ----------

func TestSecurityFixes_DirectReturnSensitiveWithheld(t *testing.T) {
	wd := t.TempDir()
	mustWrite(t, filepath.Join(wd, "notes.md"), ""+fakePEMHeader+"\nMIIBabcsecret\n"+fakePEMFooter+"\n")
	mustWrite(t, filepath.Join(wd, "plain.txt"), "nothing to see\n")
	s := testServerWithWorkdir(t, wd)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "BEGIN RSA PRIVATE KEY"})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, "MIIBabcsecret") || strings.Contains(text, "RSA PRIVATE KEY") {
		t.Fatalf("raw sensitive match lines must be withheld on direct return: %s", text)
	}
	if !strings.Contains(text, "sensitive content detected") {
		t.Fatalf("expected a sensitive-content warning: %s", text)
	}
	if !strings.Contains(text, "notes.md") {
		t.Fatalf("warning must name the offending file: %s", text)
	}
}

// ---------- F2 dedupKey must carry truncated/budget state ----------

func TestSecurityFixes_DedupKeyDistinguishesTruncated(t *testing.T) {
	base := rgArgs{Pattern: "tok", Glob: "*.go", IgnoreCase: true}
	full := rgDedupKey("/w", base, 2, false, false)
	trunc := rgDedupKey("/w", base, 2, true, false)
	budget := rgDedupKey("/w", base, 2, false, true)
	if full == trunc || full == budget || trunc == budget {
		t.Fatalf("truncated/budget state must change the dedup key: full=%q trunc=%q budget=%q", full, trunc, budget)
	}
	if again := rgDedupKey("/w", base, 2, false, false); again != full {
		t.Fatalf("identical state must produce an identical key: %q vs %q", again, full)
	}

	// Integration: a truncated-set entry must never serve a full-set lookup.
	// Real runs differ in text anyway (truncation cuts the body); using two
	// bodies keeps the labels content-derived like production.
	s := &server{}
	labelT, reusedT := s.rgIndexDedup(rgDedupKey("/w", base, 2, true, false), "partial body", "slug")
	if reusedT {
		t.Fatal("first insert must not be reported as reused")
	}
	labelF, reusedF := s.rgIndexDedup(rgDedupKey("/w", base, 2, false, false), "full body", "slug")
	if reusedF {
		t.Fatal("full-set key must not reuse the truncated-set entry")
	}
	if labelT == labelF {
		t.Fatalf("labels must differ between truncated and full sets: %q", labelT)
	}
	// Repeating the full search reuses the full-set entry (stable label).
	if _, reused := s.rgIndexDedup(rgDedupKey("/w", base, 2, false, false), "full body", "slug"); !reused {
		t.Fatal("identical repeat of the full set must be reused")
	}
}

// ---------- F4a killedByBudget vs parent cancel/timeout ----------

func TestSecurityFixes_RgBudgetKilledVsParent(t *testing.T) {
	killErr := exec.Command("sh", "-c", "kill -9 $$").Run()
	var killed *exec.ExitError
	if !errors.As(killErr, &killed) || killed.ExitCode() != -1 {
		t.Fatalf("setup: expected a signal-killed ExitError, got %v", killErr)
	}
	exitErr := exec.Command("false").Run() // real exit status 1 (no-match)
	live := context.Background()

	// Budget deadline alone: the kill belongs to the budget.
	if !rgBudgetKilled(expiredCtx(t), live, killErr) {
		t.Fatal("kill at the budget deadline must be attributed to the budget")
	}
	// Legacy single-context callers (nil parent) keep budget attribution.
	if !rgBudgetKilled(expiredCtx(t), nil, killErr) {
		t.Fatal("legacy nil-parent budget kill must stay budget-attributed")
	}
	// Parent canceled or timed out: the kill is NOT the budget's doing.
	parentCtx, cancel := context.WithCancel(live)
	cancel()
	defer cancel()
	if rgBudgetKilled(expiredCtx(t), parentCtx, killErr) {
		t.Fatal("kill under a canceled parent must not be labeled budget_exceeded")
	}
	if rgBudgetKilled(expiredCtx(t), expiredCtx(t), killErr) {
		t.Fatal("kill under an expired parent must not be labeled budget_exceeded")
	}
	// rg finished on its own: never a budget kill, no matter how late.
	if rgBudgetKilled(expiredCtx(t), live, nil) {
		t.Fatal("clean completion must never be labeled budget_exceeded")
	}
	if rgBudgetKilled(expiredCtx(t), live, exitErr) {
		t.Fatal("real exit status (e.g. no-match exit 1) must not be labeled budget_exceeded")
	}
	// No deadline hit on the budget context: not a budget kill.
	if rgBudgetKilled(live, live, killErr) {
		t.Fatal("kill without a budget deadline must not be labeled budget_exceeded")
	}
}

// ---------- F4b rgGo fallback is charged only the remaining budget ----------

func TestSecurityFixes_FallbackBudgetNoDoubleSpend(t *testing.T) {
	orig := rgBudgetMs
	defer func() { rgBudgetMs = orig }()

	now := time.Now()
	rgBudgetMs = 0
	if b, ok := rgFallbackBudget(now.Add(-time.Hour), now); !ok || b != 0 {
		t.Fatalf("budget disabled: fallback must be unrestricted, got budget=%d ok=%v", b, ok)
	}
	rgBudgetMs = 1000
	start := now.Add(-400 * time.Millisecond)
	if b, ok := rgFallbackBudget(start, now); !ok || b != 600 {
		t.Fatalf("remaining budget: want 600ms, got budget=%d ok=%v", b, ok)
	}
	if _, ok := rgFallbackBudget(now.Add(-1000*time.Millisecond), now); ok {
		t.Fatal("exactly-spent budget must refuse the fallback")
	}
	if _, ok := rgFallbackBudget(now.Add(-2*time.Hour), now); ok {
		t.Fatal("over-spent budget must refuse the fallback")
	}
}

func TestSecurityFixes_FallbackStillWorksAfterRgError(t *testing.T) {
	orig := rgBudgetMs
	rgBudgetMs = 30_000
	defer func() { rgBudgetMs = orig }()

	// Fake system rg that fails hard (exit 2, no stdout): rgSystem errors and
	// toolRg must still fall back to the Go engine with the remaining budget.
	fakeDir := t.TempDir()
	script := "#!/bin/sh\nexit 2\n"
	if err := os.WriteFile(filepath.Join(fakeDir, "rg"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	wd, s := setupFSFixture(t)
	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "Charlie"})
	if err != nil {
		t.Fatalf("toolRg must fall back to the Go engine on rg failure: %v", err)
	}
	text := mcpResultText(t, res)
	if !strings.Contains(text, "engine=go") {
		t.Fatalf("expected engine=go fallback, got: %s", text)
	}
	if !strings.Contains(text, "Charlie") {
		t.Fatalf("fallback search must still find matches in %s: %s", wd, text)
	}
}

// ---------- F4e wildcard-only guard vs zero-width assertions ----------

func TestSecurityFixes_WildcardGuardZeroWidth(t *testing.T) {
	for _, p := range []string{`\b\b`, `\B\B`, `\A\z`, `\b\B`, `\b`, `\b \b`, `\b.*\b`, "^$"} {
		if !isWildcardOnlyPattern(p) {
			t.Errorf("isWildcardOnlyPattern(%q)=false, want true (zero-width assertions match everything)", p)
		}
	}
	for _, p := range []string{`\bfoo\b`, `\bAlpha\b`, `word\b`, `\\b`, `\bx\b`, `\bfunc \w+\b`, "foo.*"} {
		if isWildcardOnlyPattern(p) {
			t.Errorf("isWildcardOnlyPattern(%q)=true, want false (real literal present)", p)
		}
	}
}

func TestSecurityFixes_WildcardGuardToolRg(t *testing.T) {
	_, s := setupFSFixture(t)
	if _, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: `\b\b`}); err == nil {
		t.Fatal(`\b\b must be rejected by the wildcard-only guard`)
	} else if !strings.Contains(err.Error(), "concrete") && !strings.Contains(err.Error(), "identifier") {
		t.Fatalf(`\b\b rejection should steer to a concrete identifier, got: %v`, err)
	}
	// A pattern with a real literal between boundaries must still search.
	if _, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: `\bAlpha\b`}); err != nil {
		t.Fatalf(`\bAlpha\b must not be rejected: %v`, err)
	}
}

// ---------- F1 sensitive-content gate on offset pages ----------

// TestSecurityFixes_OffsetPageSensitiveWithheld: a paged result (offset>0) is
// a direct return too. Content withheld on the first page must not be readable
// by paging one offset further: the page goes through the same gate and is
// replaced by the warning plus the offending file names.
func TestSecurityFixes_OffsetPageSensitiveWithheld(t *testing.T) {
	// Fake rg: three matches in creds.md, every line carrying credential
	// material, so any page over the match set is sensitive. The fake keeps
	// the test independent of a system rg install.
	dir := t.TempDir()
	s := testServerWithWorkdir(t, dir)
	script := "#!/bin/sh\nroot=\"\"\nfor a; do root=\"$a\"; done\n" +
		"echo \"${root}/creds.md:1:aws_key=" + fakeAWSKey + " one\"\n" +
		"echo \"${root}/creds.md:2:aws_key=" + fakeAWSKey + " two\"\n" +
		"echo \"${root}/creds.md:3:aws_key=" + fakeAWSKey + " three\"\n"
	if err := os.WriteFile(filepath.Join(dir, "rg"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "AKIA", Offset: 2, Limit: 10})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	for _, leak := range []string{fakeAWSKey, "aws_key", "creds.md:"} {
		if strings.Contains(text, leak) {
			t.Fatalf("offset page must not echo sensitive match lines (%s): %s", leak, text)
		}
	}
	if !strings.Contains(text, "sensitive content detected") {
		t.Fatalf("expected the sensitive-content warning: %s", text)
	}
	if !strings.Contains(text, "creds.md") {
		t.Fatalf("warning must name the offending file: %s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Fatalf("withheld offset page must be marked truncated: %s", text)
	}

	// Control: an offset page without sensitive content still passes through.
	dir2 := t.TempDir()
	plain := "#!/bin/sh\nroot=\"\"\nfor a; do root=\"$a\"; done\n" +
		"echo \"${root}/plain.txt:1:alpha one\"\n" +
		"echo \"${root}/plain.txt:2:alpha two\"\n" +
		"echo \"${root}/plain.txt:3:alpha three\"\n"
	if err := os.WriteFile(filepath.Join(dir2, "rg"), []byte(plain), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir2+string(os.PathListSeparator)+os.Getenv("PATH"))
	res, _, err = s.toolRg(context.Background(), nil, rgArgs{Pattern: "alpha", Offset: 1, Limit: 10})
	if err != nil {
		t.Fatalf("toolRg (plain offset page): %v", err)
	}
	text = mcpResultText(t, res)
	if !strings.Contains(text, "alpha two") {
		t.Fatalf("non-sensitive offset page must pass through unchanged: %s", text)
	}
}

// ---------- F1 sensitive-content gate on the over-limit fallback ----------

// TestSecurityFixes_OverLimitSensitiveFallbackWithheld: with hits > limit the
// result takes the index-to-store branch. When its content trips the
// sensitive-content gate, indexing stays skipped AND the raw-match fallback
// must not echo the first N raw lines — that fallback used to hand the secret
// to any search whose hit count exceeded the limit.
func TestSecurityFixes_OverLimitSensitiveFallbackWithheld(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = true
	defer func() { rgSummaryEnabled = origSummary }()

	// Fake rg: five matches in secrets.md, every line tripping the
	// credential gate. limit=2 with 5 hits selects the index-to-store branch.
	dir := t.TempDir()
	st := newTestStore(t)
	s := &server{workdirs: []string{dir}, store: st}
	script := "#!/bin/sh\nroot=\"\"\nfor a; do root=\"$a\"; done\n" +
		"echo \"${root}/secrets.md:1:aws_key=" + fakeAWSKey + " one\"\n" +
		"echo \"${root}/secrets.md:2:aws_key=" + fakeAWSKey + " two\"\n" +
		"echo \"${root}/secrets.md:3:aws_key=" + fakeAWSKey + " three\"\n" +
		"echo \"${root}/secrets.md:4:aws_key=" + fakeAWSKey + " four\"\n" +
		"echo \"${root}/secrets.md:5:aws_key=" + fakeAWSKey + " five\"\n"
	if err := os.WriteFile(filepath.Join(dir, "rg"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{Pattern: "AKIA", Limit: 2})
	if err != nil {
		t.Fatalf("toolRg: %v", err)
	}
	text := mcpResultText(t, res)
	for _, leak := range []string{fakeAWSKey, "aws_key", "secrets.md:"} {
		if strings.Contains(text, leak) {
			t.Fatalf("over-limit sensitive fallback must not echo raw match lines (%s): %s", leak, text)
		}
	}
	if !strings.Contains(text, "sensitive content detected") {
		t.Fatalf("expected the sensitive-content warning: %s", text)
	}
	if !strings.Contains(text, "secrets.md") {
		t.Fatalf("warning must name the offending file: %s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Fatalf("withheld over-limit result must be marked truncated: %s", text)
	}
	// Indexing must stay skipped: no sensitive content may reach the store.
	if hits, _ := st.Search(fakeAWSKey, 5); len(hits) != 0 {
		t.Fatalf("sensitive content must not be indexed to the store: %+v", hits)
	}

	// Control: an over-limit non-sensitive search keeps indexing normally.
	dir2 := t.TempDir()
	plain := "#!/bin/sh\nroot=\"\"\nfor a; do root=\"$a\"; done\n" +
		"echo \"${root}/plain.txt:1:alpha one\"\n" +
		"echo \"${root}/plain.txt:2:alpha two\"\n"
	if err := os.WriteFile(filepath.Join(dir2, "rg"), []byte(plain), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir2+string(os.PathListSeparator)+os.Getenv("PATH"))
	res, _, err = s.toolRg(context.Background(), nil, rgArgs{Pattern: "alpha", Limit: 1})
	if err != nil {
		t.Fatalf("toolRg (plain over-limit): %v", err)
	}
	text = mcpResultText(t, res)
	if strings.Contains(text, "sensitive content detected") {
		t.Fatalf("non-sensitive over-limit search must not be gated: %s", text)
	}
	if !strings.Contains(text, "indexed=") {
		t.Fatalf("non-sensitive over-limit search should still index to the store: %s", text)
	}
}

// F1 extension: the non-indexing fallback (store or summary disabled, hits >
// limit) must withhold raw sensitive lines exactly like the indexed fallback.
func TestSecurityFixes_NonIndexingSensitiveWithheld(t *testing.T) {
	origSummary := rgSummaryEnabled
	rgSummaryEnabled = false
	defer func() { rgSummaryEnabled = origSummary }()

	repoDir := t.TempDir()
	initTestRepo(t, repoDir)
	st := newTestStore(t)
	s := &server{
		workdirs:        []string{repoDir},
		store:           st,
		sessionID:       "sess-noidx",
		gitDirtyCache:   make(map[string]gitDirtyEntry),
		rgIndexDedupMap: make(map[string]rgIndexEntry),
	}

	fakeKey := "AKIA" + "IOSFODNN7EXAMPLE"
	commitFile(t, repoDir, "keys2.txt", strings.Repeat("// SECRET "+fakeKey+"\n", 30), "commit keys2")

	res, _, err := s.toolRg(context.Background(), nil, rgArgs{
		Pattern: "SECRET",
		Path:    repoDir,
	})
	if err != nil {
		t.Fatalf("toolRg failed: %v", err)
	}
	text := mcpResultText(t, res)
	if strings.Contains(text, fakeKey) || strings.Contains(text, "keys2.txt:") {
		t.Errorf("non-indexing fallback must not echo raw sensitive lines, got:\n%s", text)
	}
	if !strings.Contains(text, "sensitive content detected") || !strings.Contains(text, "files: keys2.txt") {
		t.Errorf("expected withheld warning naming the sensitive file, got:\n%s", text)
	}
	if !strings.Contains(text, "truncated=true") {
		t.Errorf("expected truncated=true in header, got:\n%s", text)
	}
}
