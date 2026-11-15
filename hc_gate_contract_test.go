package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// hcStubSource is a tiny Go program that records argv to HC_STUB_LOG and exits 0.
const hcStubSource = `package main
import (
  "encoding/json"
  "os"
)
func main() {
  path := os.Getenv("HC_STUB_LOG")
  if path == "" { os.Exit(2) }
  f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o755)
  if err != nil { os.Exit(3) }
  defer f.Close()
  _ = json.NewEncoder(f).Encode(os.Args)
}
`

func buildHcStub(t *testing.T, dir string) string {
	t.Helper()
	src := filepath.Join(dir, "stub.go")
	bin := filepath.Join(dir, "herdr-core")
	if err := os.WriteFile(src, []byte(hcStubSource), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stub: %v\n%s", err, out)
	}
	return bin
}

func readStubArgv(t *testing.T, logPath string) [][]string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var argv []string
		if err := json.Unmarshal([]byte(line), &argv); err != nil {
			t.Fatalf("parse stub log %q: %v", line, err)
		}
		out = append(out, argv)
	}
	return out
}

func withIsolatedHcPath(t *testing.T, stubBin, logPath string) (restore func()) {
	t.Helper()
	dir := filepath.Dir(stubBin)
	// hc -> herdr-core in the same dir
	hcLink := filepath.Join(dir, "hc")
	_ = os.Remove(hcLink)
	if err := os.Symlink(stubBin, hcLink); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	oldLog := os.Getenv("HC_STUB_LOG")
	os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	os.Setenv("HC_STUB_LOG", logPath)
	_ = os.Remove(logPath)
	// Pin BOTH layers in one helper: the in-process testHcGatePin plus the
	// three child-process env names a --hc-gate child of this binary reads in
	// mustActivateChildHcGatePin. A test that adds the stub to PATH without the
	// pin is exactly the accident this contract closes.
	restorePin := activateHcTestPin(t, stubBin, logPath)
	return func() {
		restorePin()
		os.Setenv("PATH", oldPath)
		if oldLog == "" {
			os.Unsetenv("HC_STUB_LOG")
		} else {
			os.Setenv("HC_STUB_LOG", oldLog)
		}
	}
}

// hcPinHomeForStub returns the trusted-home root containing stubBin: the fake
// home when the stub sits in <home>/.local/bin, else the stub's own directory.
func hcPinHomeForStub(stubBin string) string {
	dir := filepath.Dir(stubBin)
	if filepath.Base(dir) == "bin" && filepath.Base(filepath.Dir(dir)) == ".local" {
		return filepath.Dir(filepath.Dir(dir))
	}
	return dir
}

// restoreHcTestEnv restores one environment variable (unsetting when it was
// previously empty).
func restoreHcTestEnv(key, val string) {
	if val == "" {
		_ = os.Unsetenv(key)
		return
	}
	_ = os.Setenv(key, val)
}

// activateHcTestPin installs the in-process pin plus the child-process pin
// environment for one test and returns its restore func.
func activateHcTestPin(t *testing.T, stubBin, logPath string) func() {
	t.Helper()
	home := hcPinHomeForStub(stubBin)
	info, err := os.Stat(stubBin)
	if err != nil {
		t.Fatalf("hc test pin: stat %s: %v", stubBin, err)
	}
	prevPin := testHcGatePin
	prevHome := os.Getenv(hcTestEnvTrustedHome)
	prevStub := os.Getenv(hcTestEnvStub)
	prevLog := os.Getenv(hcTestEnvStubLog)
	testHcGatePin = &hcGateTestPin{trustedHome: home, stubBin: stubBin, stubInfo: info}
	_ = os.Setenv(hcTestEnvTrustedHome, home)
	_ = os.Setenv(hcTestEnvStub, stubBin)
	_ = os.Setenv(hcTestEnvStubLog, logPath)
	return func() {
		testHcGatePin = prevPin
		restoreHcTestEnv(hcTestEnvTrustedHome, prevHome)
		restoreHcTestEnv(hcTestEnvStub, prevStub)
		restoreHcTestEnv(hcTestEnvStubLog, prevLog)
	}
}

// pinFail reports a pin rejection and exits 125 BEFORE runHcGate: a test
// child must never reach fd-exec without a fully verified pin.
func pinFail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "hc-gate test pin: "+format+"\n", args...)
	os.Exit(125)
}

// pinOwnerPermOK requires euid/root ownership and no group/other write bits.
func pinOwnerPermOK(fi os.FileInfo) bool {
	if fi == nil {
		return false
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != os.Geteuid() && st.Uid != 0 {
			return false
		}
	}
	return fi.Mode().Perm()&0022 == 0
}

// mustActivateChildHcGatePin is the SOLE reader of CTXMODE_TEST_* / HC_STUB_LOG
// in this package. It runs at the top of a --hc-gate child of the test binary
// and hard-fails (os.Exit(125)) on any missing, malformed or unsafe input:
// trusted home outside the temp root, wrong owner or group/other-writable
// dirs, a stub that is not an ELF regular executable strictly inside that
// home, a stub that IS the test binary (SameFile self), or a stub log outside
// the home. Only then are testTrustedHomeRoot and testHcGatePin installed.
func mustActivateChildHcGatePin() {
	home := os.Getenv(hcTestEnvTrustedHome)
	stub := os.Getenv(hcTestEnvStub)
	logPath := os.Getenv(hcTestEnvStubLog)
	if home == "" || stub == "" || logPath == "" {
		pinFail("missing pin environment (need %s, %s, %s)", hcTestEnvTrustedHome, hcTestEnvStub, hcTestEnvStubLog)
	}
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		pinFail("trusted home %q: %v", home, err)
	}
	realHome = filepath.Clean(realHome)
	tmpRoot := filepath.Clean(os.TempDir())
	if r, rerr := filepath.EvalSymlinks(tmpRoot); rerr == nil {
		tmpRoot = filepath.Clean(r)
	}
	if !strings.HasPrefix(realHome, tmpRoot+"/") && !strings.HasPrefix(realHome, "/tmp/") {
		pinFail("trusted home %q is not under the temp root %q", realHome, tmpRoot)
	}
	hst, err := os.Stat(realHome)
	if err != nil || !hst.IsDir() {
		pinFail("trusted home %q is not a directory: %v", realHome, err)
	}
	if !pinOwnerPermOK(hst) {
		pinFail("trusted home %q has a foreign owner or group/other write bits", realHome)
	}
	realStub, err := filepath.EvalSymlinks(stub)
	if err != nil {
		pinFail("stub %q: %v", stub, err)
	}
	realStub = filepath.Clean(realStub)
	if !strings.HasPrefix(realStub, realHome+"/") {
		pinFail("stub %q escapes the pinned home %q", realStub, realHome)
	}
	if filepath.Base(realStub) != "herdr-core" {
		pinFail("stub %q is not named herdr-core", realStub)
	}
	sst, err := os.Stat(realStub)
	if err != nil || !sst.Mode().IsRegular() || sst.Mode()&0111 == 0 {
		pinFail("stub %q is not an executable regular file: %v", realStub, err)
	}
	if !pinOwnerPermOK(sst) {
		pinFail("stub %q has a foreign owner or group/other write bits", realStub)
	}
	if _, selfInfo, serr := resolvedSelfExe(); serr == nil && selfInfo != nil && os.SameFile(sst, selfInfo) {
		pinFail("stub %q IS the test binary (SameFile self)", realStub)
	}
	f, err := os.Open(realStub)
	if err != nil {
		pinFail("stub %q open: %v", realStub, err)
	}
	var hdr [4]byte
	_, rerr := f.ReadAt(hdr[:], 0)
	_ = f.Close()
	if rerr != nil || string(hdr[:]) != "\x7fELF" {
		pinFail("stub %q is not an ELF binary", realStub)
	}
	logDir := filepath.Clean(filepath.Dir(logPath))
	if r, lerr := filepath.EvalSymlinks(logDir); lerr == nil {
		logDir = filepath.Clean(r)
	}
	if logDir != realHome && !strings.HasPrefix(logDir, realHome+"/") {
		pinFail("stub log %q is outside the pinned home %q", logPath, realHome)
	}
	testTrustedHomeRoot = realHome
	testHcGatePin = &hcGateTestPin{trustedHome: realHome, stubBin: realStub, stubInfo: sst}
}

func prepRule(role, ro, cmd string) preparedShell {
	os.Setenv("CTXMODE_ROLE", role)
	os.Setenv("CTXMODE_READONLY", ro)
	defer os.Unsetenv("CTXMODE_ROLE")
	defer os.Unsetenv("CTXMODE_READONLY")
	return currentGuardCall().prepareCtxRunShell(cmd)
}

func TestT_GAP1_XargsFindNestedHC_StaticBlock(t *testing.T) {
	cases := []string{
		"xargs -I{} hc send t42 {}",
		"xargs -Itt hc send tt ok",
		"xargs hc send t42 ok",
		"find /tmp -exec hc send t42 {} ;",
		"find /tmp -execdir hc send t42 {} ;",
		"find /tmp -ok hc send t42 {} ;",
		"find /tmp -okdir hc send t42 {} ;",
		"find /tmp -exec hc send t42 {} +",
	}
	for _, cmd := range cases {
		rule, detail := rtCmdRule("worker", "", cmd, "")
		if rule == "" {
			t.Errorf("%q: got ALLOW, want STATIC BLOCK", cmd)
			continue
		}
		if !strings.Contains(detail, "hc") && !strings.Contains(detail, "herdr-core") &&
			!strings.Contains(detail, "xargs") && !strings.Contains(detail, "find") {
			t.Errorf("%q: blocked with unexpected detail %q/%q", cmd, rule, detail)
		}
	}
	// Non-hc xargs/find must remain free.
	for _, cmd := range []string{
		"xargs -I{} echo {}",
		"find /tmp -name '*.go' -print",
		"find . -type f -exec cat {} ;",
	} {
		rule, detail := rtCmdRule("worker", "", cmd, "")
		if rule != "" {
			t.Errorf("non-hc %q: got BLOCK %s: %s", cmd, rule, detail)
		}
	}
}

func TestT_AST1_SingleArgWordPredicates(t *testing.T) {
	allow := []string{
		`hc send t42 '$@ $*'`,
		`hc send t42 "dev@a.com"`,
		`hc send t42 "$*"`,
		`hc send t42 "$((1+1))"`,
		`hc send t42 "$(cat /tmp/r.txt)"`,
	}
	for _, cmd := range allow {
		prep := prepRule("worker", "", cmd)
		if prep.rule != "" {
			t.Errorf("ALLOW candidate %q blocked: %s (%s)", cmd, prep.rule, prep.detail)
		}
		if !strings.Contains(prep.execCode, "--hc-gate") && strings.Contains(cmd, "$(") {
			t.Errorf("%q: expected --hc-gate rewrite, got %q", cmd, prep.execCode)
		}
	}
	// Pure static guard must still BLOCK dynamic send (A4 invariant).
	if rule, _ := rtCmdRule("worker", "", `hc send t1 "$(printf hi)"`, ""); rule == "" {
		t.Error("pure guard must still BLOCK dynamic hc send")
	}
	block := []string{
		`hc send t42 "$@"`,
		`hc send t42 "${a[@]}"`,
		`hc send t42 "${x:-$@}"`,
		`hc send t42 $x`,
		`hc send t42 $(cat f)`,
		`hc send t42 a*`,
	}
	for _, cmd := range block {
		prep := prepRule("worker", "", cmd)
		if prep.rule == "" {
			t.Errorf("BLOCK candidate %q got ALLOW exec=%q", cmd, prep.execCode)
		}
	}
}

func TestT_INNER1_InnerFirst(t *testing.T) {
	for _, cmd := range []string{
		`hc send t42 "$(hc kill t2)"`,
		`hc send t42 "$(pig)"`,
	} {
		prep := prepRule("worker", "", cmd)
		if prep.rule == "" {
			t.Errorf("%q: want BLOCK, got ALLOW", cmd)
		}
	}
	prep := prepRule("scout", "", `hc send t42 "$(rm /tmp/w)"`)
	if prep.rule == "" {
		t.Error("scout rm inside subst: want BLOCK")
	}
}

func TestT_EX1_PrepareRewriteWorker(t *testing.T) {
	cmd := `hc send t42 "$(cat /tmp/r.md)"`
	prep := prepRule("worker", "", cmd)
	if prep.rule != "" {
		t.Fatalf("prepare blocked: %s (%s)", prep.rule, prep.detail)
	}
	if !strings.Contains(prep.execCode, "--hc-gate") {
		t.Fatalf("missing --hc-gate in %q", prep.execCode)
	}
	if !strings.Contains(prep.execCode, `$(cat /tmp/r.md)`) {
		t.Fatalf("text word lost in %q", prep.execCode)
	}
	if strings.Contains(prep.rawCode, "--hc-gate") {
		t.Fatal("rawCode must stay original")
	}
	// wrapper + assign
	cmd2 := `FOO=1 timeout 5 env A=1 hc send t42 "$msg"`
	prep2 := prepRule("worker", "", cmd2)
	if prep2.rule != "" {
		t.Fatalf("wrapper prepare blocked: %s (%s)", prep2.rule, prep2.detail)
	}
	if !strings.Contains(prep2.execCode, "timeout") || !strings.Contains(prep2.execCode, "--hc-gate") {
		t.Fatalf("wrappers not preserved: %q", prep2.execCode)
	}
}

func TestT_RO1_ScoutPrepareReadonly(t *testing.T) {
	prep := prepRule("scout", "", `hc send t42 "$(cat /tmp/existing.txt)"`)
	if prep.rule != "" {
		t.Fatalf("scout prepare blocked: %s (%s)", prep.rule, prep.detail)
	}
	if !strings.Contains(prep.execCode, "--hc-gate") {
		t.Fatalf("missing rewrite: %q", prep.execCode)
	}
	prep2 := prepRule("scout", "", `hc send t42 "状态：$(git status --short)"`)
	if prep2.rule != "" {
		t.Fatalf("scout git subst blocked: %s (%s)", prep2.rule, prep2.detail)
	}
}

func TestT_GATE1_ValidateHcGateArgs(t *testing.T) {
	if got := validateHcGateArgs([]string{"send", "t42", "ok"}); got != "" {
		t.Fatalf("benign blocked: %s", got)
	}
	if got := validateHcGateArgs([]string{"send", "t42", "--force"}); got == "" {
		t.Fatal("leading dash text must block")
	}
	if got := validateHcGateArgs([]string{"send", "t42", "a\rb"}); got == "" || !strings.Contains(got, "CR") {
		t.Fatalf("CR must block with CR tip, got %q", got)
	}
	if got := validateHcGateArgs([]string{"send", "t42", "x\x03y"}); got == "" {
		t.Fatal("C0 must block")
	}
	if got := validateHcGateArgs([]string{"send", "t42", "BEGIN RSA PRIVATE KEY"}); !strings.Contains(got, "sensitive") {
		t.Fatalf("sensitive must redact, got %q", got)
	} else if strings.Contains(got, "BEGIN RSA") {
		t.Fatal("must not echo sensitive body")
	}
}

func TestT_GATE1_ExtraFilesFdExec(t *testing.T) {
	if testing.Short() {
		t.Skip("fd exec")
	}
	home := withTestTrustedHome(t)
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := buildHcStub(t, binDir)
	logPath := filepath.Join(home, "captured.jsonl")
	restore := withIsolatedHcPath(t, stub, logPath)
	defer restore()

	code := runHcGate([]string{"send", "t42", "hello-from-gate"})
	if code != 0 {
		t.Fatalf("runHcGate rc=%d", code)
	}
	got := readStubArgv(t, logPath)
	if len(got) != 1 {
		t.Fatalf("stub calls=%d want 1; log=%v", len(got), got)
	}
	if got[0][0] != "hc" || got[0][1] != "send" || got[0][2] != "t42" || got[0][3] != "hello-from-gate" {
		t.Fatalf("argv=%v", got[0])
	}
}

func TestT_EX2_ArgvLiteralVsShell(t *testing.T) {
	os.Setenv("CTXMODE_ROLE", "worker")
	defer os.Unsetenv("CTXMODE_ROLE")
	g := currentGuardCall()

	// Literal argv: $(...) is data, not shell.
	prep := g.prepareCtxRunArgv([]string{"hc", "send", "t42", "$(cat /tmp/r.txt)"}, "")
	if prep.rule != "" {
		t.Fatalf("literal argv blocked: %s", prep.detail)
	}
	if prep.execArgv[3] != "$(cat /tmp/r.txt)" {
		t.Fatalf("literal changed: %v", prep.execArgv)
	}
	if strings.Contains(strings.Join(prep.execArgv, " "), "--hc-gate") {
		t.Fatal("literal argv must not rewrite to --hc-gate")
	}

	prep2 := g.prepareCtxRunArgv([]string{"bash", "-c", `hc send t42 "$(cat /tmp/r.txt)"`}, "")
	if prep2.rule != "" {
		t.Fatalf("bash -c prepare blocked: %s (%s)", prep2.rule, prep2.detail)
	}
	joined := strings.Join(prep2.execArgv, " ")
	if !strings.Contains(joined, "--hc-gate") {
		t.Fatalf("bash -c missing rewrite: %v", prep2.execArgv)
	}
}

// TestT_EF1_ExecuteFilePrepareThenInject asserts the prepare+inject
// ordering contract: prepareCtxRunShellWithTaint must NOT block on
// FILE_CONTENT as data (taint marks it dynamic, the text slot accepts a
// guaranteed-single-arg word), and injectFileContent must splice the
// content above the prepared code. The full delivery path (stub receives
// the hostile body verbatim and embedded fragments never run) is covered
// by TestT_EF1_HostileFileContent in hc_gate_e2e_test.go.
func TestT_EF1_ExecuteFilePrepareThenInject(t *testing.T) {
	body := "line with `hc kill t1` and $(pig) and 'a'\\''b' and \"$HOME\"\n中文多行\n"
	os.Setenv("CTXMODE_ROLE", "worker")
	defer os.Unsetenv("CTXMODE_ROLE")

	g := currentGuardCall()
	prep := g.prepareCtxRunShellWithTaint(`hc send t42 "$FILE_CONTENT"`, map[string]bool{"FILE_CONTENT": true})
	if prep.rule != "" {
		t.Fatalf("prepare with FILE_CONTENT taint blocked: %s (%s)", prep.rule, prep.detail)
	}
	if !strings.Contains(prep.execCode, "--hc-gate") {
		t.Fatalf("expected --hc-gate rewrite, got %q", prep.execCode)
	}
	if !strings.Contains(prep.execCode, "$FILE_CONTENT") {
		t.Fatalf("FILE_CONTENT word lost in %q", prep.execCode)
	}
	injected := injectFileContent("shell", prep.execCode, body)
	if !strings.HasSuffix(injected, "\n"+prep.execCode) {
		t.Fatalf("injected code lost prepared suffix: %q", injected)
	}
	if !strings.HasPrefix(injected, "FILE_CONTENT=") {
		t.Fatalf("missing FILE_CONTENT decl: %q", injected)
	}
	verdict, rule := screenShellBlock(injected)
	if verdict == shellBlock {
		t.Fatalf("injected code blocked: %s", rule)
	}
}

func TestIsGuaranteedSingleArgWord(t *testing.T) {
	p := syntaxNewWord(t, `"$(cat f)"`)
	if !isGuaranteedSingleArgWord(p, false) {
		t.Fatal(`"$(cat f)" should be single-arg`)
	}
	p2 := syntaxNewWord(t, `"$@"`)
	if isGuaranteedSingleArgWord(p2, false) {
		t.Fatal(`"$@" must not be single-arg`)
	}
	p3 := syntaxNewWord(t, `"$*"`)
	if !isGuaranteedSingleArgWord(p3, false) {
		t.Fatal(`"$*" should be single-arg`)
	}
	p4 := syntaxNewWord(t, `'$@'`)
	if !isGuaranteedSingleArgWord(p4, false) {
		t.Fatal(`'$@' literal should be single-arg`)
	}
}

// syntaxNewWord parses a single shell word via mvdan parser.
func syntaxNewWord(t *testing.T, word string) *syntax.Word {
	t.Helper()
	code := "hc send t42 " + word
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(code), "")
	if err != nil {
		t.Fatal(err)
	}
	call := file.Stmts[0].Cmd.(*syntax.CallExpr)
	return call.Args[3]
}

// ================= 1114E §3.3 contract matrix =================
// Static-compile-only additions for the 1114E consensus spec. These tests
// pin the NEW stage-A behavior; none of them run in stage A.

// prepArgvRule runs prepareCtxRunArgv under a role and returns the prepared
// artifact (never executes it).
func prepArgvRule(t *testing.T, role, ro string, argv []string, stdin string) preparedArgv {
	t.Helper()
	prevRole := os.Getenv("CTXMODE_ROLE")
	prevRO := os.Getenv("CTXMODE_READONLY")
	os.Setenv("CTXMODE_ROLE", role)
	os.Setenv("CTXMODE_READONLY", ro)
	defer restoreHcTestEnv("CTXMODE_ROLE", prevRole)
	defer restoreHcTestEnv("CTXMODE_READONLY", prevRO)
	return currentGuardCall().prepareCtxRunArgv(argv, stdin)
}

// prepShellStdinRule runs prepareCtxRunShellAndStdin under a role and returns
// the prepared artifact (never executes it).
func prepShellStdinRule(t *testing.T, role, ro, cmd, stdin string) preparedShell {
	t.Helper()
	prevRole := os.Getenv("CTXMODE_ROLE")
	prevRO := os.Getenv("CTXMODE_READONLY")
	os.Setenv("CTXMODE_ROLE", role)
	os.Setenv("CTXMODE_READONLY", ro)
	defer restoreHcTestEnv("CTXMODE_ROLE", prevRole)
	defer restoreHcTestEnv("CTXMODE_READONLY", prevRO)
	return currentGuardCall().prepareCtxRunShellAndStdin(cmd, stdin)
}

// TestT_STDIN1_RewrittenStdinNoSelfLock pins 1114E §3.1 finding ①: a
// `hc send` payload arriving on stdin must be REWRITTEN to `<selfExe>
// --hc-gate` and pass the prov-aware guard inside prepareCtxRunShellTargets —
// the rewritten bytes must never re-enter a pure-check stdin guard
// (hcProv == nil would self-block every legal send).
func TestT_STDIN1_RewrittenStdinNoSelfLock(t *testing.T) {
	dynSend := `hc send t42 "x: $(cat /tmp/r.txt)"`

	// argv form: ["sh"] + dynamic hc send on stdin.
	p := prepArgvRule(t, "worker", "", []string{"sh"}, dynSend)
	if p.rule != "" {
		t.Fatalf("[sh]+stdin prepare blocked (self-lock?): %s (%s)", p.rule, p.detail)
	}
	if !strings.Contains(p.execStdin, "--hc-gate") {
		t.Fatalf("[sh]+stdin: execStdin missing --hc-gate rewrite: %q", p.execStdin)
	}

	// command form: Command "sh" + the same stdin.
	os.Setenv("CTXMODE_ROLE", "worker")
	os.Setenv("CTXMODE_READONLY", "")
	defer os.Unsetenv("CTXMODE_ROLE")
	defer os.Unsetenv("CTXMODE_READONLY")
	sp := currentGuardCall().prepareCtxRunShellAndStdin("sh", dynSend)
	if sp.rule != "" {
		t.Fatalf("Command sh + stdin blocked (self-lock?): %s (%s)", sp.rule, sp.detail)
	}
	if !strings.Contains(sp.execStdin, "--hc-gate") {
		t.Fatalf("Command sh + stdin: execStdin missing --hc-gate: %q", sp.execStdin)
	}
}

// TestT_STDIN2_CScripStdinMatrix covers the -c + stdin contract rows:
// foreign-language target, local shell target, ssh remote target and the
// mixed data+shell line.
func TestT_STDIN2_CScripStdinMatrix(t *testing.T) {
	dynSend := `hc send t42 "x: $(cat /tmp/r.txt)"`

	// bash -c 'python3 -' + anything: python reads ITS program from stdin,
	// so a shell-looking hc send must block, never be rewritten.
	p := prepArgvRule(t, "worker", "", []string{"bash", "-c", "python3 -"}, dynSend)
	if p.rule == "" {
		t.Fatalf("bash -c 'python3 -' + shell stdin must block (foreign lang), got ALLOW stdin=%q", p.execStdin)
	}

	// bash -c 'sh' + dynamic hc send: the script body reads a PROGRAM from
	// stdin — it is a local shell, so the rewrite applies and the payload
	// ships inside --hc-gate.
	p = prepArgvRule(t, "worker", "", []string{"bash", "-c", "sh"}, dynSend)
	if p.rule != "" {
		t.Fatalf("bash -c 'sh' + dyn send must allow the rewrite, got %s (%s)", p.rule, p.detail)
	}
	if !strings.Contains(p.execStdin, "--hc-gate") {
		t.Fatalf("bash -c 'sh' + dyn send: execStdin missing --hc-gate: %q", p.execStdin)
	}

	// bash -c 'ssh dmit sh' + dynamic hc send: stdin forwards to a REMOTE
	// shell. The bytes must never be rewritten into a local --hc-gate
	// call AND the remote-program screen must block the dynamic send.
	p = prepArgvRule(t, "worker", "", []string{"bash", "-c", "ssh dmit sh"}, dynSend)
	if p.rule == "" {
		t.Fatalf("bash -c 'ssh dmit sh' + dyn send must block (remote program)")
	}
	if strings.Contains(p.execStdin, "--hc-gate") {
		t.Fatalf("remote stdin must NOT be rewritten to --hc-gate: %q", p.execStdin)
	}

	// Same ssh target + benign stdin: a worker may send benign bytes; the
	// stream must pass through UNCHANGED (still data, no rewrite).
	p = prepArgvRule(t, "worker", "", []string{"bash", "-c", "ssh dmit sh"}, "ls")
	if p.rule != "" {
		t.Fatalf("worker benign stdin to ssh must pass, got %s (%s)", p.rule, p.detail)
	}
	if p.execStdin != "ls" {
		t.Fatalf("benign remote stdin must stay verbatim, got %q", p.execStdin)
	}

	// Verifier (read-only, non-strict): the same benign write-ish program
	// escalates to strictReadonly for remote targets — `rm -rf /` on a
	// remote shell must block.
	p = prepArgvRule(t, "verifier", "", []string{"bash", "-c", "ssh dmit sh"}, "rm -rf /")
	if p.rule == "" {
		t.Fatalf("verifier remote stdin write must escalate + block")
	}

	// Mixed command line: `jq . ; sh` — jq consumes the stream as DATA, so
	// the stdin must pass through verbatim; rewriting it into --hc-gate
	// would destroy the JSON.
	p = prepArgvRule(t, "worker", "", []string{"bash", "-c", "jq . ; sh"}, `{"k":1}`)
	if p.rule != "" {
		t.Fatalf("jq . ; sh must pass, got %s (%s)", p.rule, p.detail)
	}
	if p.execStdin != `{"k":1}` {
		t.Fatalf("data stdin must stay verbatim through a mixed line, got %q", p.execStdin)
	}
	if strings.Contains(p.execStdin, "--hc-gate") {
		t.Fatalf("data stdin must NEVER be rewritten: %q", p.execStdin)
	}

	// Same mixed line as a plain Command string.
	os.Setenv("CTXMODE_ROLE", "worker")
	os.Setenv("CTXMODE_READONLY", "")
	defer os.Unsetenv("CTXMODE_ROLE")
	defer os.Unsetenv("CTXMODE_READONLY")
	sp := currentGuardCall().prepareCtxRunShellAndStdin("jq . ; sh", `{"k":1}`)
	if sp.rule != "" {
		t.Fatalf("Command 'jq . ; sh' must pass, got %s (%s)", sp.rule, sp.detail)
	}
	if sp.execStdin != `{"k":1}` {
		t.Fatalf("Command data stdin must stay verbatim, got %q", sp.execStdin)
	}

	// Multi-target different-PATH regression (1114F §3.1 item 2): two local
	// shell stdin targets whose PATH= prefixes differ must EACH be screened
	// under its own env — a merged replay ends with the LAST PATH= and the
	// first target's alias view would escape audit. Plant a blocked-agent
	// alias (myrunner -> pig) under the trusted <home>/.local/bin: the
	// first segment resolves `myrunner` in $binDir (blocked name), the
	// second resolves it in /usr/bin (harmless script). Only the per-target
	// guardPreparedShellEnv pass sees the $binDir view.
	home := withTestTrustedHome(t)
	binDir := filepath.Join(home, ".local", "bin")
	writeTestExecutable(t, filepath.Join(binDir, "pig"), 0o755)
	if err := os.Symlink(filepath.Join(binDir, "pig"), filepath.Join(binDir, "myrunner")); err != nil {
		t.Fatal(err)
	}
	multiPath := fmt.Sprintf("PATH=%s:/usr/bin:/bin sh ; PATH=/usr/bin:/bin sh", binDir)
	p = prepArgvRule(t, "worker", "", []string{"bash", "-c", multiPath}, "myrunner")
	if p.rule == "" {
		t.Fatalf("multi-target PATH=%s:/usr/bin:/bin + stdin 'myrunner' must block (per-target PATH audit), got ALLOW stdin=%q", binDir, p.execStdin)
	}
	// Same shape through the Command-string entry.
	sp = prepShellStdinRule(t, "worker", "", multiPath, "myrunner")
	if sp.rule == "" {
		t.Fatalf("Command multi-target PATH= + stdin 'myrunner' must block (per-target PATH audit), got ALLOW stdin=%q", sp.execStdin)
	}

	// 1114G stage-B fix 1: a bare `hc send`/`herdr-core …` as the FIRST
	// statement head of foreign-language code must block even though the
	// foreign runtime raises a SyntaxError (no spawn primitive fires, so
	// the spawn-gated hasIdent scan cannot see it). Defence-in-depth.

	// Inline -c form: python3 -c 'hc send …' blocks.
	if rule, detail := rtArgvRule("worker", "", []string{"python3", "-c", `hc send t42 "x: $(cat /tmp/r.txt)"`}, ""); rule == "" {
		t.Fatalf("python3 -c 'hc send …' must block, got ALLOW (detail=%s)", detail)
	}

	// Leading comment + herdr-core: `# cmt\nherdr-core send …` via
	// python3 - stdin blocks (comment stripped, head still the agent).
	p = prepArgvRule(t, "worker", "", []string{"bash", "-c", "python3 -"}, "# cmt\nherdr-core send t42 hi")
	if p.rule == "" {
		t.Fatalf("python3 - stdin '# cmt\\nherdr-core send …' must block, got ALLOW stdin=%q", p.execStdin)
	}

	// Benign lookalike: `hc = 5` is an assignment (no horizontal-space
	// command head), and a `--hc-gate`/`hc` substring inside a string must
	// never trip the head check — ALLOW proves no regression to kill.
	if rule, detail := rtArgvRule("worker", "", []string{"python3", "-c", `hc = 5; print("--hc-gate", hc)`}, ""); rule != "" {
		t.Fatalf("benign 'hc = 5; print(\"--hc-gate\", hc)' must allow, got %s (%s)", rule, detail)
	}
}

// TestT_GLUED1_GluedShellC covers the glued -c matrix rows: spellings with
// no clean script word must keep the argv untouched (never nil-execArgv,
// never a rewritten stdin) and still face the full guard.
func TestT_GLUED1_GluedShellC(t *testing.T) {
	// Benign glued spellings: allowed, execArgv is the verbatim argv.
	for _, argv := range [][]string{
		{"sh", "-cecho ok"},
		{"sh", "-ce", "echo ok"},
		{"sh", "-co", "errexit", "echo ok"},
	} {
		p := prepArgvRule(t, "worker", "", argv, "")
		if p.rule != "" {
			t.Fatalf("benign glued %v must pass, got %s (%s)", argv, p.rule, p.detail)
		}
		if len(p.execArgv) != len(argv) {
			t.Fatalf("benign glued %v: execArgv=%v must be the full verbatim argv", argv, p.execArgv)
		}
		for i := range argv {
			if p.execArgv[i] != argv[i] {
				t.Fatalf("benign glued %v: execArgv[%d]=%q want %q (no rewrite)", argv, i, p.execArgv[i], argv[i])
			}
		}
	}

	// Hostile glued spellings: the decoded text hides a dynamic hc send —
	// the guard must block (the rewrite path must never see them).
	for _, argv := range [][]string{
		{"sh", "-ce", `hc send "$t" ok`},
		{"sh", "-co", "errexit", `hc send t42 "$(cat r)"`},
		{"sh", "-cecho hi; hc send t42 \"$(cat r)\""},
	} {
		p := prepArgvRule(t, "worker", "", argv, "")
		if p.rule == "" {
			t.Fatalf("hostile glued %v must block (dynamic hc send), got ALLOW argv=%v", argv, p.execArgv)
		}
	}

	// Glued -c + stdin: the stdin is screened but NEVER rewritten — a
	// `sh -ce 'sh'` line whose body would read a program must keep stdin
	// verbatim.
	p := prepArgvRule(t, "worker", "", []string{"sh", "-ce", "sh"}, "ls")
	if p.rule != "" {
		t.Fatalf("glued -c + benign stdin must pass, got %s (%s)", p.rule, p.detail)
	}
	if p.execStdin != "ls" {
		t.Fatalf("glued -c stdin must never be rewritten, got %q", p.execStdin)
	}

	// `sh -ce 'sh'` unwraps to "e\nsh" whose `sh` IS a stdin-program
	// target — the pre-1114F code rewrote the stdin bytes into a
	// `<selfExe> --hc-gate` call anyway. With a dynamic hc send on stdin
	// the verdict must be a block AND the bytes must never be rewritten.
	p = prepArgvRule(t, "worker", "", []string{"sh", "-ce", "sh"}, `hc send t42 "$(cat /tmp/r.txt)"`)
	if p.rule == "" {
		t.Fatal("glued -c 'sh' + dynamic hc send stdin must block")
	}
	if strings.Contains(p.execStdin, "--hc-gate") {
		t.Fatalf("glued -c 'sh' stdin must NEVER be rewritten to --hc-gate: %q", p.execStdin)
	}
}

// TestT_GATEHEAD1_CtxmodeOptionZone covers the screenCtxmodeGateHead
// contract: a dynamic word anywhere in the option zone fails closed,
// --hc-gate spellings fail closed, while known global options with
// single-word values and the subcommand's own operands stay free.
func TestT_GATEHEAD1_CtxmodeOptionZone(t *testing.T) {
	// Blocks (worker): dynamic option-zone words and raw --hc-gate.
	for _, cmd := range []string{
		`a=--hc-gate; ctxmode "$a" send t42 hi`,
		`ctxmode "$@"`,
		`ctxmode -"$x" search`,
		`ctxmode --workdir "$@" search`,
		`ctxmode --workdir="$@" search`,
		`ctxmode --hc-gate send t42 hi`,
		`ctxmode --hc-gate=x send t42 hi`,
		// 1114G stage-B fix 2: every double-quoted @-split form expands to
		// one argv word per element, so it is NOT a split-safe single-word
		// option value — it must block like bare "$@".
		`ctxmode --workdir "${arr[@]}" search`,
		`ctxmode --workdir="${arr[@]}" search`,
		`ctxmode --workdir "${x:-$@}" search`,
		`ctxmode --workdir="${x:-$@}" search`,
		`ctxmode --workdir "${!prefix@}" search`,
		`ctxmode --workdir "${x:-${arr[@]}}" search`,
	} {
		if rule, detail := rtCmdRule("worker", "", cmd, ""); rule == "" {
			t.Errorf("worker %q: got ALLOW, want block", cmd)
			_ = detail
		}
	}
	// env -S payload: a double-quoted @-split inside the split-string
	// operand is screened by the same rule (fail closed on the payload).
	for _, cmd := range []string{
		`env -S 'ctxmode --workdir "$@" search'`,
		`env -S 'ctxmode --workdir "${arr[@]}" search'`,
	} {
		if rule, detail := rtCmdRule("worker", "", cmd, ""); rule == "" {
			t.Errorf("worker %q: got ALLOW, want block", cmd)
			_ = detail
		}
	}
	// Allows (worker): subcommand operands are free, and single-word
	// dynamic option values (quoted $PWD, a literal @ default, "$*") are
	// fine.
	for _, cmd := range []string{
		`ctxmode search --hc-gate`,
		`ctxmode search "$q"`,
		`ctxmode --workdir="$PWD" search`,
		`ctxmode --workdir "$PWD" search`,
		`ctxmode --workdir="$PWD/sub" index`,
		`ctxmode --workdir "${x:-@}" search`, // literal @ default = one word
		`ctxmode --workdir "${x:-@@}" search`,
		`ctxmode --workdir "$*" search`, // "$*" joins to one word
	} {
		if rule, detail := rtCmdRule("worker", "", cmd, ""); rule != "" {
			t.Errorf("worker %q: got BLOCK %s: %s, want ALLOW", cmd, rule, detail)
		}
	}
}

// TestT_VERIFIER1_VerifierGateRows covers the verifier-facing rows: a
// verifier is a read-only-but-not-strict caller — it may still deliver a
// dynamic hc send through the gate, a raw --hc-gate stays blocked, and
// env -S / ${x:-$@} spellings keep their verdicts.
func TestT_VERIFIER1_VerifierGateRows(t *testing.T) {
	// Positive: verifier dynamic send through prepare → --hc-gate.
	p := prepRule("verifier", "", `hc send t42 "v: $(cat /tmp/r.txt)"`)
	if p.rule != "" {
		t.Fatalf("verifier dynamic send must be allowed via rewrite, got %s (%s)", p.rule, p.detail)
	}
	if !strings.Contains(p.execCode, "--hc-gate") {
		t.Fatalf("verifier dynamic send missing --hc-gate: %q", p.execCode)
	}

	// Raw literal --hc-gate: never authorized.
	if rule, _ := rtCmdRule("verifier", "", `ctxmode --hc-gate send t42 hi`, ""); rule == "" {
		t.Error("verifier raw --hc-gate must block")
	}

	// env -S payload: provenance surrendered — a dynamic hc send behind it
	// must block.
	if rule, _ := rtCmdRule("verifier", "", `env -S 'hc send t42 "$(cat r)"'`, ""); rule == "" {
		t.Error("verifier env -S dynamic send must block")
	}

	// ${x:-@} data default stays free; a real $@ split inside the default
	// fails closed.
	prep := prepRule("verifier", "", `hc send t42 "${x:-@}"`)
	if prep.rule != "" {
		t.Fatalf("verifier ${x:-@} must allow (literal @), got %s (%s)", prep.rule, prep.detail)
	}
	prep = prepRule("verifier", "", `hc send t42 "${x:-${y:-$@}}"`)
	if prep.rule == "" {
		t.Error("verifier nested ${x:-${y:-$@}} must block")
	}
}

// TestT_PIN1_ShimAndFakeHcPins covers the selection-stage pin behaviour:
// a PATH dir with NO hc entry is skipped normally (mise/pnpm compat), but
// a dir WITH an hc entry outside the pinned home fails immediately.
func TestT_PIN1_ShimAndFakeHcPins(t *testing.T) {
	home := withTestTrustedHome(t)
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := buildHcStub(t, binDir)
	logPath := filepath.Join(home, "captured.jsonl")
	restore := withIsolatedHcPath(t, stub, logPath)
	defer restore()

	// An empty shim dir BEFORE the pinned dir is skipped (no hc entry).
	shimDir := t.TempDir()
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", shimDir+string(os.PathListSeparator)+oldPath)
	defer os.Setenv("PATH", oldPath)
	got, err := findTrustedHcExecutable()
	if err != nil || got == "" {
		t.Fatalf("empty shim dir must be skipped, got %q err %v", got, err)
	}

	// A fake hc in a dir OUTSIDE the pinned home is an immediate failure.
	fakeDir := t.TempDir()
	fakeHc := filepath.Join(fakeDir, "hc")
	if err := os.WriteFile(fakeHc, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Setenv("PATH", fakeDir+string(os.PathListSeparator)+oldPath)
	if _, err := findTrustedHcExecutable(); err == nil {
		t.Fatal("fake hc outside pinned home must fail the selection stage")
	}
}
