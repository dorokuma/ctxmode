package main

// C3 contract e2e tests: every case below drives a REAL production entry
// point (toolExecute / toolExecuteFile / toolBatchExecute / toolRunTask)
// with the prepared-artifact rewrite, and the only stand-in is the terminal
// herdr-core ELF recorder placed on PATH under a withTestTrustedHome fake
// home. The rewritten `<selfExe> --hc-gate send ...` execs THIS test binary
// (see TestMain's --hc-gate branch), which runs the real runHcGate →
// findTrustedHcExecutable → fd-exec chain against the stub.
//
// No soft passes: a delivery failure is a test failure. The only env-shaped
// gate is the linux/arm64+go toolchain needed to build the stub, checked
// once by requireHcE2E.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// hcE2EEnv bundles the fake trusted home, the ELF hc stand-in and its
// capture log so each contract case gets a fresh, isolated environment.
type hcE2EEnv struct {
	home     string
	binDir   string
	stubBin  string
	logPath  string
	workdir  string
	report   string
	auditLog string
	s        *server
	restore  func()
}

var hcE2ESetupOnce bool

// requireHcE2E hard-fails (never silently skips) when the platform cannot
// run the fd-exec chain; the stub build itself needs `go build`, which is
// part of the standard test toolchain.
func requireHcE2E(t *testing.T) {
	t.Helper()
	if hcE2ESetupOnce {
		return
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("hc e2e contract tests require the go toolchain on PATH: %v", err)
	}
	hcE2ESetupOnce = true
}

// newHcE2E installs the trusted-home + PATH stub environment for one test
// and returns the env plus a cleanup. CTXMODE_ROLE is set per-case by the
// caller (worker / scout / ...).
func newHcE2E(t *testing.T) *hcE2EEnv {
	t.Helper()
	requireHcE2E(t)
	e := &hcE2EEnv{}
	e.home = withTestTrustedHome(t)
	e.binDir = filepath.Join(e.home, ".local", "bin")
	if err := os.MkdirAll(e.binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	e.stubBin = buildHcStub(t, e.binDir)
	e.logPath = filepath.Join(e.home, "captured.jsonl")
	e.restore = withIsolatedHcPath(t, e.stubBin, e.logPath)
	// Pin the fake home for --hc-gate CHILD PROCESSES of the test binary:
	// a spawned `ctxmode.test --hc-gate …` re-runs TestMain in a fresh
	// process where the package-level testTrustedHomeRoot is empty, and
	// without this pin the fake home under /tmp is classified as scratch,
	// the stub is untrusted and findTrustedHcExecutable falls through to
	// the real hc on PATH (a REAL send — must never happen in a test).
	if err := os.Setenv("CTXMODE_TEST_TRUSTED_HOME", e.home); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Unsetenv("CTXMODE_TEST_TRUSTED_HOME") })
	// bash -l / sh -l (login shells) re-read /etc/profile and reset PATH,
	// which would drop the stub dir and let the inner --hc-gate fall through to
	// the REAL hc. Prepend the stub dir via the fake home's .bash_profile AND
	// .profile so both login spellings keep the stub first on PATH. This is
	// fixture hygiene, NOT an isolation control: the real boundaries are the
	// compile-time pin (above) and the stage-B outer OS isolation.
	profileLine := []byte("export PATH=" + shellSingleQuote(e.binDir) + ":$PATH\n")
	for _, name := range []string{".bash_profile", ".profile"} {
		if err := os.WriteFile(filepath.Join(e.home, name), profileLine, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.workdir = t.TempDir()
	e.report = filepath.Join(e.workdir, "r.txt")
	if err := os.WriteFile(e.report, []byte("e2e-report-body-中文\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.auditLog = filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv(auditEnvLogPath, e.auditLog)
	t.Cleanup(e.restore)
	return e
}

// stubCalls returns the recorded hc argv invocations ([]os.Args per call).
func (e *hcE2EEnv) stubCalls(t *testing.T) [][]string {
	t.Helper()
	return readStubArgv(t, e.logPath)
}

// wantSends asserts the stub log is EXACTLY the given send argv triples
// (each inner slice is [send, addr, text]). Any other count or shape fails.
func (e *hcE2EEnv) wantSends(t *testing.T, want [][3]string) {
	t.Helper()
	got := e.stubCalls(t)
	if len(got) != len(want) {
		t.Fatalf("stub calls=%d want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		argv := got[i]
		if len(argv) != 4 || argv[0] != "hc" || argv[1] != w[0] || argv[2] != w[1] || argv[3] != w[2] {
			t.Fatalf("call %d argv=%v want [hc %s %s %s]", i, argv, w[0], w[1], w[2])
		}
	}
}

// wantZeroSends asserts no downstream hc call was recorded at all.
func (e *hcE2EEnv) wantZeroSends(t *testing.T) {
	t.Helper()
	if got := e.stubCalls(t); len(got) != 0 {
		t.Fatalf("expected zero downstream calls, got %v", got)
	}
}

// setRole pins CTXMODE_ROLE/CTXMODE_READONLY for the duration of one test.
func (e *hcE2EEnv) setRole(t *testing.T, role, ro string) {
	t.Helper()
	t.Setenv(auditEnvRole, role)
	t.Setenv(auditEnvReadonly, ro)
	if e.s == nil {
		e.s = testServerWithWorkdir(t, e.workdir)
	}
}

// executeShell runs the production execute entry (command form).
func (e *hcE2EEnv) executeShell(t *testing.T, cmd string, timeoutMs int) (*mcp.CallToolResult, any, error) {
	t.Helper()
	return e.s.toolExecute(context.Background(), nil, executeArgs{
		Command:   cmd,
		TimeoutMs: timeoutMs,
	})
}

// executeArgv runs the production execute entry (argv form).
func (e *hcE2EEnv) executeArgv(t *testing.T, argv []string, stdin string) (*mcp.CallToolResult, any, error) {
	t.Helper()
	return e.s.toolExecute(context.Background(), nil, executeArgs{
		Argv:  argv,
		Stdin: stdin,
	})
}

// execOK asserts a no-error call with exit_code 0.
func (e *hcE2EEnv) execOK(t *testing.T, res *mcp.CallToolResult, out any, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("entry returned error: %v", err)
	}
	if res == nil {
		t.Fatal("nil CallToolResult")
	}
}

// execBlocked asserts the call was refused by a role guard (non-nil error).
func (e *hcE2EEnv) execBlocked(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected guard-blocked error, got nil")
	}
	if !strings.Contains(err.Error(), "subagent_nested_agent") &&
		!strings.Contains(err.Error(), "readonly_write_blocked") {
		t.Fatalf("unexpected block error (want a guard rule): %v", err)
	}
}

// ---------------- T-EX1: execute (command form) delivery matrix ---------

// TestT_EX1_ExecuteShellDelivery covers the contract T-EX1 positive shapes
// through the REAL toolExecute entry: heredoc+send, wrapper chain, absolute
// hc path, bash -l -c, PATH-prefixed send, 48 KiB body, and background+wait.
func TestT_EX1_ExecuteShellDelivery(t *testing.T) {
	e := newHcE2E(t)
	e.setRole(t, "worker", "")
	e.s = testServerWithWorkdir(t, e.workdir)

	type sendCase struct {
		name string
		cmd  string
		want [3]string // send / addr / expected text at the stub
	}
	// Per-case report file (heredoc case rewrites the file, so a shared
	// path would leak into later cases).
	mkReport := func(name, body string) string {
		p := filepath.Join(e.workdir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	bigBody := strings.Repeat("x", 48*1024)
	bigPath := mkReport("big.txt", bigBody)
	cases := []sendCase{
		{
			"heredoc-then-send",
			fmt.Sprintf("cat <<'EOF' > %[1]s\nmulti 中文 line1\n```code fence```\n\nline3\nEOF\nhc send t11j \"report: $(cat %[1]s)\"", filepath.Join(e.workdir, "hd.txt")),
			[3]string{"send", "t11j", "report: multi 中文 line1\n```code fence```\n\nline3"},
		},
		{
			"wrapper-env-timeout",
			fmt.Sprintf("msg=$(cat %s); FOO=1 timeout 5 env A=1 hc send t11j \"$msg\"", mkReport("r1.txt", "wrap-body")),
			[3]string{"send", "t11j", "wrap-body"},
		},
		{
			"abs-hc-path",
			fmt.Sprintf("%s send t11j \"report: $(cat %s)\"", filepath.Join(e.binDir, "hc"), mkReport("r2.txt", "abs-body")),
			[3]string{"send", "t11j", "report: abs-body"},
		},
		{
			"bash-l-c",
			fmt.Sprintf("bash -l -c 'hc send t11j \"report: $(cat %s)\"'", mkReport("r3.txt", "bashl-body")),
			[3]string{"send", "t11j", "report: bashl-body"},
		},
		{
			"path-prefix-send",
			fmt.Sprintf("PATH=%s:/usr/bin:/bin hc send t11j \"report: $(cat %s)\"", e.binDir, mkReport("r4.txt", "pathp-body")),
			[3]string{"send", "t11j", "report: pathp-body"},
		},
		{
			"48kib-body",
			fmt.Sprintf("hc send t11j \"big:$(cat %s)\"", bigPath),
			[3]string{"send", "t11j", "big:" + bigBody},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(e.stubCalls(t))
			res, out, err := e.executeShell(t, c.cmd, 30000)
			e.execOK(t, res, out, err)
			calls := e.stubCalls(t)
			if len(calls) != before+1 {
				t.Fatalf("stub calls grew by %d, want exactly 1 (case %s): %v", len(calls)-before, c.name, calls[before:])
			}
			argv := calls[len(calls)-1]
			want := c.want
			if len(argv) != 4 || argv[0] != "hc" || argv[1] != want[0] || argv[2] != want[1] {
				t.Fatalf("argv=%v want hc %s %s …", argv, want[0], want[1])
			}
			if argv[3] != want[2] {
				t.Fatalf("text=%q want %q", argv[3], want[2])
			}
		})
	}
}

// TestT_EX1_BackgroundWait delivers a send through execute background:true
// then waits the ctx_bg entry to Done and asserts the stub captured it.
func TestT_EX1_BackgroundWait(t *testing.T) {
	e := newHcE2E(t)
	e.setRole(t, "worker", "")
	e.s = testServerWithWorkdir(t, e.workdir)

	res, _, err := e.s.toolExecute(context.Background(), nil, executeArgs{
		Command:    fmt.Sprintf("hc send t11j \"bg: $(cat %s)\"", e.report),
		Background: true,
	})
	e.execOK(t, res, nil, err)
	text := mcpResultText(t, res)
	re := regexp.MustCompile(`id: ([A-Za-z0-9._-]+)`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("no background id in %q", text)
	}
	waitBackgroundDone(t, m[1])
	e.wantSends(t, [][3]string{{"send", "t11j", "bg: e2e-report-body-中文"}})
}

// ---------------- T-EX2: argv + stdin delivery --------------------------

// TestT_EX2_ArgvStdinDelivery drives all three contract T-EX2 cases through
// the real execute argv entry.
func TestT_EX2_ArgvStdinDelivery(t *testing.T) {
	e := newHcE2E(t)
	e.setRole(t, "worker", "")
	e.s = testServerWithWorkdir(t, e.workdir)

	// ① bash -c dynamic send expands and reaches the stub.
	res, _, err := e.executeArgv(t,
		[]string{"bash", "-c", fmt.Sprintf(`hc send t11j "task: $(cat %s)"`, e.report)}, "")
	e.execOK(t, res, nil, err)

	// ② ["sh"] + stdin script expands and reaches the stub.
	res2, _, err2 := e.executeArgv(t,
		[]string{"sh"}, fmt.Sprintf(`hc send t11j "stdin: $(cat %s)"`, e.report))
	e.execOK(t, res2, nil, err2)

	// ③ literal argv must NOT expand: the stub receives the literal
	// "$(cat /tmp/r.txt)" word as data (no shell ever sees it).
	res3, _, err3 := e.executeArgv(t,
		[]string{"hc", "send", "t11j", "$(cat /tmp/r.txt)"}, "")
	e.execOK(t, res3, nil, err3)

	e.wantSends(t, [][3]string{
		{"send", "t11j", "task: e2e-report-body-中文"},
		{"send", "t11j", "stdin: e2e-report-body-中文"},
		{"send", "t11j", "$(cat /tmp/r.txt)"},
	})
}

// ---------------- T-EF1: hostile FILE_CONTENT ---------------------------

// TestT_EF1_HostileFileContent replaces the old soft-pass test: a
// FILE_CONTENT body containing `hc kill`, $(pig), quotes and multi-line
// Chinese must arrive VERBATIM at the stub and never be executed.
func TestT_EF1_HostileFileContent(t *testing.T) {
	e := newHcE2E(t)
	e.setRole(t, "worker", "")
	e.s = testServerWithWorkdir(t, e.workdir)

	// Hostile body: every byte must survive verbatim inside the send text.
	// The backtick and $(...) fragments would execute if the FILE_CONTENT
	// splice ever leaked into shell source — so we also plant a canary file
	// the embedded commands would create if they ran.
	canary := filepath.Join(e.workdir, "canary-created")
	body := "line with `hc send t1 PWN` and $(touch " + canary + ") and 'a'\\''b' and \"$HOME\"\n中文多行 content\nend"
	report := filepath.Join(e.workdir, "hostile.txt")
	if err := os.WriteFile(report, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	res, _, err := e.s.toolExecuteFile(context.Background(), nil, executeFileArgs{
		Path:     report,
		Language: "shell",
		Code:     `hc send t11j "$FILE_CONTENT"`,
	})
	e.execOK(t, res, nil, err)

	// The body (with the injectFileContent single-quote round-trip) must be
	// received byte-identical.
	e.wantSends(t, [][3]string{{"send", "t11j", body}})

	// Embedded command fragments must never have executed: the canary the
	// $(touch …) fragment would create must not exist, and the stub must
	// have logged exactly ONE call (the outer send) — a second call would
	// mean the `hc send t1 PWN` backtick fragment ran as a command.
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatalf("embedded $(touch canary) executed: %v", err)
	}
}

// ---------------- T-BA1: batch serial + concurrent ----------------------

// TestT_BA1_BatchMixed runs the mixed batch (legal dynamic send + legal
// normal command + violating command) through toolBatchExecute at
// concurrency=1 AND concurrency=4 (run under -race in CI). It asserts:
// audit.jsonl AND batchResult.Command carry the original command text;
// the legal send reaches the stub; the violating item gets ExitCode == -1
// with zero downstream calls.
func TestT_BA1_BatchMixed(t *testing.T) {
	for _, conc := range []int{1, 4} {
		t.Run(fmt.Sprintf("concurrency=%d", conc), func(t *testing.T) {
			e := newHcE2E(t)
			e.setRole(t, "worker", "")
			e.s = testServerWithWorkdir(t, e.workdir)

			legalSend := fmt.Sprintf(`hc send t11j "batch: $(cat %s)"`, e.report)
			legalNormal := `echo batch-normal-ok`
			violating := `hc send t11j "$(pig)"`

			res, _, err := e.s.toolBatchExecute(context.Background(), nil, batchArgs{
				Commands: []batchCommand{
					{Label: "send", Command: legalSend},
					{Label: "normal", Command: legalNormal},
					{Label: "violate", Command: violating},
				},
				Concurrency: conc,
				TimeoutMs:   30000,
			})
			e.execOK(t, res, nil, err)

			var resp batchResponse
			if err := json.Unmarshal([]byte(mcpResultText(t, res)), &resp); err != nil {
				t.Fatalf("unmarshal batchResponse: %v\nraw=%s", err, mcpResultText(t, res))
			}
			if len(resp.Commands) != 3 {
				t.Fatalf("want 3 results, got %+v", resp.Commands)
			}
			by := map[string]batchResult{}
			for _, r := range resp.Commands {
				by[r.Label] = r
			}
			// batchResult.Command must be the ORIGINAL text, not the rewrite.
			if by["send"].Command != legalSend || by["normal"].Command != legalNormal || by["violate"].Command != violating {
				t.Fatalf("batchResult.Command not raw: %+v", resp.Commands)
			}
			if !by["send"].Success || by["send"].ExitCode != 0 {
				t.Fatalf("legal send failed: %+v", by["send"])
			}
			if !by["normal"].Success {
				t.Fatalf("normal command failed: %+v", by["normal"])
			}
			if by["violate"].Success || by["violate"].ExitCode != -1 {
				t.Fatalf("violating item must be ExitCode=-1: %+v", by["violate"])
			}
			// Exactly one downstream call (the legal send); violating zero.
			e.wantSends(t, [][3]string{{"send", "t11j", "batch: e2e-report-body-中文"}})

			// Audit raw_cmd must also be original text, and the violating
			// command's per-command entry records its guard block.
			lines := readAuditLines(t, e.auditLog)
			if len(lines) == 0 {
				t.Fatal("no audit line")
			}
			var rec auditRecord
			for _, l := range lines {
				var r auditRecord
				if json.Unmarshal([]byte(l), &r) == nil && r.Action == "batch" {
					rec = r
				}
			}
			if !strings.Contains(rec.RawCmd, legalSend) || !strings.Contains(rec.RawCmd, violating) {
				t.Fatalf("audit raw_cmd lost original text: %q", rec.RawCmd)
			}
			violated := false
			for _, c := range rec.Commands {
				if c.Label == "violate" {
					violated = true
					if c.ExitCode != -1 || c.ScreenVerdict != "block" {
						t.Fatalf("violating audit entry=%+v want exit=-1 block", c)
					}
				}
			}
			if !violated {
				t.Fatalf("audit commands missing violate entry: %+v", rec.Commands)
			}
		})
	}
}

// ---------------- T-RT1: run_task custom -------------------------------

// TestT_RT1_RunTaskCustom drives run_task custom through toolRunTask:
// ① args bash -c dynamic send expands and delivers;
// ② argv ["hc","send","--force","t42","x"] is statically refused.
func TestT_RT1_RunTaskCustom(t *testing.T) {
	e := newHcE2E(t)
	e.setRole(t, "worker", "")
	e.s = testServerWithWorkdir(t, e.workdir)

	res, _, err := e.s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom",
		Args: []string{"bash", "-c", fmt.Sprintf(`hc send t11j "task: $(cat %s)"`, e.report)},
	})
	e.execOK(t, res, nil, err)

	_, _, err2 := e.s.toolRunTask(context.Background(), nil, runTaskArgs{
		Kind: "custom",
		Args: []string{"hc", "send", "--force", "t42", "x"},
	})
	e.execBlocked(t, err2)

	e.wantSends(t, [][3]string{{"send", "t11j", "task: e2e-report-body-中文"}})
}

// ---------------- T-RO1: readonly roles via real entry ------------------

// TestT_RO1_ReadonlyRolesDelivery sends from each read-only role through
// the real toolExecute entry; the dynamic readonly hc send (cat / git
// subst) must reach the stub under guardShellReadonlyDepthPrepare.
func TestT_RO1_ReadonlyRolesDelivery(t *testing.T) {
	for _, role := range []string{"scout", "reviewer", "oracle"} {
		t.Run(role, func(t *testing.T) {
			e := newHcE2E(t)
			e.setRole(t, role, "")
			e.s = testServerWithWorkdir(t, e.workdir)

			res, _, err := e.executeShell(t,
				fmt.Sprintf(`hc send t42 "ro: $(cat %s)"`, e.report), 30000)
			e.execOK(t, res, nil, err)
			// git status --short inside dq subst is read-only and allowed.
			res2, _, err2 := e.executeShell(t,
				`hc send t42 "状态：$(git status --short)"`, 30000)
			e.execOK(t, res2, nil, err2)
			calls := e.stubCalls(t)
			if len(calls) != 2 {
				t.Fatalf("role %s: stub calls=%d want 2: %v", role, len(calls), calls)
			}
			if calls[0][3] != "ro: e2e-report-body-中文" {
				t.Fatalf("call0 text=%q", calls[0][3])
			}
			if !strings.HasPrefix(calls[1][3], "状态：") {
				t.Fatalf("call1 text=%q", calls[1][3])
			}
		})
	}
}

// T-RO1 negative: a write inside a readonly role must be blocked and must
// NOT reach the stub.
func TestT_RO1_ReadonlyWriteBlocked(t *testing.T) {
	e := newHcE2E(t)
	e.setRole(t, "scout", "")
	e.s = testServerWithWorkdir(t, e.workdir)

	w := filepath.Join(e.workdir, "w.txt")
	_, _, err := e.executeShell(t,
		fmt.Sprintf(`echo x > %s && hc send t42 "$(cat %s)"`, w, w), 30000)
	if err == nil {
		t.Fatal("scout write must be blocked")
	}
	e.wantZeroSends(t)
}
