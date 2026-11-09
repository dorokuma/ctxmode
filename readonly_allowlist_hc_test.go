package main

import (
	"os"
	"path/filepath"
	"testing"
)

// hcAllowlistFixture builds an isolated PATH dir where `hc` is a symlink to
// the given link target, mirroring the two live layouts found during the P11
// acceptance: /root/.local/bin/hc -> herdr-core on the host, and hc -> sbx
// inside an `sbx --preset reviewer-agent` sandbox. PATH is rebound to the
// fixture dir for the duration of the test so resolution is deterministic.
func hcAllowlistFixture(t *testing.T, linkTarget string) string {
	t.Helper()
	bin := t.TempDir()
	for _, name := range []string{"herdr-core", "sbx"} {
		writeTestExecutable(t, filepath.Join(bin, name), 0755)
	}
	if err := os.Symlink(filepath.Join(bin, linkTarget), filepath.Join(bin, "hc")); err != nil {
		t.Fatalf("symlink hc -> %s: %v", linkTarget, err)
	}
	t.Setenv("PATH", bin)
	return bin
}

// hcReadonlyAllowArgv is the exact set a strict-readonly role may run: the
// `hc send <addr> <text>` report channel plus the pure query spellings.
var hcReadonlyAllowArgv = [][]string{
	{"hc", "send", "t42", "summary ok"},
	{"hc", "--help"},
	{"hc", "-h"},
	{"hc", "--version"},
	{"hc", "-V"},
	{"hc", "send", "--help"},
}

// hcReadonlyBlockArgv is everything else a strict-readonly role must not
// reach, including directly naming the hc symlink target binary.
var hcReadonlyBlockArgv = [][]string{
	{"hc"},
	{"hc", "ls"},
	{"hc", "read", "t42"},
	{"hc", "get", "t42"},
	{"hc", "run", "--bg", "x"},
	{"hc", "exec", "t42", "x"},
	{"hc", "keys", "t42", "a"},
	{"hc", "kill", "t42"},
	{"hc", "rm", "t42"},
	{"hc", "send", "--force", "t42", "x"},
	{"hc", "send", "badaddr", "x"},
	{"hc", "send", "t42", "-flag"},
	// herdr-core itself is NOT in the readonly allowlist: a strict-readonly
	// caller must go through `hc`, never address the target binary directly.
	{"herdr-core", "send", "t42", "x"},
}

var hcReadonlyAllowShell = []string{
	`hc send t42 "summary ok"`,
	`hc --help`,
	`hc -h`,
	`hc --version`,
	`hc -V`,
	`hc send --help`,
}

var hcReadonlyBlockShell = []string{
	`hc`,
	`hc ls`,
	`hc read t42`,
	`hc get t42`,
	`hc run --bg x`,
	`hc exec t42 x`,
	`hc keys t42 a`,
	`hc kill t42`,
	`hc rm t42`,
	`hc send --force t42 x`,
	`hc send badaddr x`,
	`hc send t42 -flag`,
	`herdr-core send t42 x`,
}

// TestGuard_HcReadonlyAllowlist covers the strict-readonly registration of
// `hc` (readonlyAllowlist["hc"] -> screenHcSubagent) plus the hc -> herdr-core
// and hc -> sbx system-alias pass in screenReadonlyAliasTarget, under
// guardCtxRunArgv and guardCtxRunShell for every strict-readonly identity:
// CTXMODE_ROLE=scout/reviewer/oracle and CTXMODE_READONLY=1.
func TestGuard_HcReadonlyAllowlist(t *testing.T) {
	for _, target := range []string{"herdr-core", "sbx"} {
		t.Run("hc->"+target, func(t *testing.T) {
			hcAllowlistFixture(t, target)
			for _, ro := range []struct {
				name     string
				role     string
				readonly string
			}{
				{name: "scout", role: "scout"},
				{name: "reviewer", role: "reviewer"},
				{name: "oracle", role: "oracle"},
				{name: "readonly-env", role: "", readonly: "1"},
			} {
				t.Run(ro.name, func(t *testing.T) {
					t.Setenv(auditEnvRole, ro.role)
					t.Setenv(auditEnvReadonly, ro.readonly)
					g := currentGuardCall()
					if !g.strictReadonly {
						t.Fatalf("role=%q readonly=%q must classify as strict readonly",
							ro.role, ro.readonly)
					}
					for _, argv := range hcReadonlyAllowArgv {
						if rule, detail := g.guardCtxRunArgv(argv); rule != "" {
							t.Fatalf("argv %v must pass, got rule=%q detail=%q",
								argv, rule, detail)
						}
					}
					for _, argv := range hcReadonlyBlockArgv {
						if rule, _ := g.guardCtxRunArgv(argv); rule == "" {
							t.Fatalf("argv %v must block under strict readonly", argv)
						}
					}
					for _, code := range hcReadonlyAllowShell {
						if rule, detail := g.guardCtxRunShell(code); rule != "" {
							t.Fatalf("shell %q must pass, got rule=%q detail=%q",
								code, rule, detail)
						}
					}
					for _, code := range hcReadonlyBlockShell {
						if rule, _ := g.guardCtxRunShell(code); rule == "" {
							t.Fatalf("shell %q must block under strict readonly", code)
						}
					}
				})
			}
		})
	}
}

// TestGuard_HcReadonlyAllowlistLexical exercises the allowlist keyed on the
// typed basename alone — no PATH resolution — proving `hc` itself is the
// registered head while `herdr-core`/`sbx` stay unlisted.
func TestGuard_HcReadonlyAllowlistLexical(t *testing.T) {
	for _, argv := range hcReadonlyAllowArgv {
		if hit := screenReadonlyAllowlist(argv); hit != "" {
			t.Fatalf("screenReadonlyAllowlist(%v) = %q, want pass", argv, hit)
		}
	}
	for _, argv := range hcReadonlyBlockArgv {
		if hit := screenReadonlyAllowlist(argv); hit == "" {
			t.Fatalf("screenReadonlyAllowlist(%v) must block", argv)
		}
	}
	for _, argv := range [][]string{
		{"sbx", "send", "t42", "x"},
		{"herdr-core", "run", "x"},
	} {
		if hit := screenReadonlyAllowlist(argv); hit == "" {
			t.Fatalf("screenReadonlyAllowlist(%v) must block: symlink target must stay unlisted", argv)
		}
	}
}

// TestGuard_HcSubagentHerdrCore covers the non-readonly sub-agent path:
// directly naming the symlink target `herdr-core` routes through the same hc
// whitelist (screenNestedDispatch case "hc", "herdr-core") so `herdr-core run`
// cannot bypass the `hc` interception, while the send channel stays open.
func TestGuard_HcSubagentHerdrCore(t *testing.T) {
	hcAllowlistFixture(t, "herdr-core")
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")
	g := currentGuardCall()
	if !g.subagent || g.strictReadonly {
		t.Fatalf("worker must classify as non-strict sub-agent")
	}
	for _, argv := range [][]string{
		{"herdr-core", "run", "x"},
		{"herdr-core", "exec", "t42", "x"},
		{"herdr-core", "ls"},
		{"herdr-core", "send", "--force", "t42", "x"},
	} {
		if rule, detail := g.guardCtxRunArgv(argv); rule != ruleSubagentNestedAgent {
			t.Fatalf("argv %v = rule %q detail %q, want %q",
				argv, rule, detail, ruleSubagentNestedAgent)
		}
	}
	for _, argv := range [][]string{
		{"herdr-core", "send", "t42", "x"},
		{"hc", "send", "t42", "x"},
		{"herdr-core", "--version"},
	} {
		if rule, detail := g.guardCtxRunArgv(argv); rule != "" {
			t.Fatalf("argv %v must pass, got rule=%q detail=%q", argv, rule, detail)
		}
	}
	if rule, detail := g.guardCtxRunShell(`herdr-core run x`); rule != ruleSubagentNestedAgent {
		t.Fatalf("shell `herdr-core run x` = rule %q detail %q, want %q",
			rule, detail, ruleSubagentNestedAgent)
	}
	if rule, detail := g.guardCtxRunShell(`herdr-core send t42 x`); rule != "" {
		t.Fatalf("shell `herdr-core send t42 x` must pass, got rule=%q detail=%q",
			rule, detail)
	}
}
