package main

// Static + CLI-contract coverage for the outer test-isolation wiring:
// the ns-hc scripts, Makefile check target and CI fixture step.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

var errPeelExhausted = errors.New("peelWrappers depth exhausted")

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// stripCommentLine drops the '#' tail; for the ci.yml scan only, never TAB lines.
func stripCommentLine(line string) (string, bool) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	return line, strings.TrimSpace(line) != ""
}

// makeRecipeBlock returns `target:`'s recipe joined into one shell block, `\` merged.
// Make hands TAB lines verbatim to /bin/sh, so '#' stays for the shell parser (may
// sit inside quotes); multi-line if/for blocks need the join.
func makeRecipeBlock(t *testing.T, target string) string {
	t.Helper()
	recipe, inRecipe := []string(nil), false
loop:
	for _, raw := range strings.Split(readRepoFile(t, "Makefile"), "\n") {
		switch {
		case !inRecipe: // targets start at column 0, recipe lines with TAB
			inRecipe = strings.HasPrefix(raw, target+":") && !strings.HasPrefix(raw, "\t")
		case strings.HasPrefix(raw, "\t"):
			if line := strings.TrimLeft(raw, "\t"); strings.TrimSpace(line) != "" {
				recipe = append(recipe, line)
			}
		case strings.TrimSpace(raw) == "": // blank lines keep recipe going
		default:
			break loop
		}
	}
	out := mergeMakeContinuations(recipe) // one continuation-merge implementation
	if len(out) == 0 {
		t.Fatalf("Makefile has no %s: recipe", target)
	}
	return strings.Join(out, "\n")
}

// stripMakeLinePrefix strips recipe prefixes (@,-,+) and unescapes $$, per
// line of a multi-line recipe/dry-run block.
func stripMakeLinePrefix(block string) string {
	lines := strings.Split(block, "\n")
	for i, l := range lines {
		lines[i] = strings.ReplaceAll(strings.TrimLeft(l, " \t@+-"), "$$", "$")
	}
	return strings.Join(lines, "\n")
}

// isNsHcGotestDriver reports a peeled head invoking ns-hc-gotest.sh with --race.
func isNsHcGotestDriver(head []string) bool {
	return len(head) > 0 && filepath.Base(head[0]) == "ns-hc-gotest.sh" && slices.Contains(head[1:], "--race")
}

// isBareGoTestArgv reports a bare `go test` (`go -C` counts) — TestMain's gate refuses (125).
func isBareGoTestArgv(head []string) bool {
	if len(head) == 0 || filepath.Base(head[0]) != "go" {
		return false
	}
	for args := head[1:]; len(args) > 0; { // peel `go -C` global flags
		if args[0] == "-C" || args[0] == "--C" {
			if len(args) < 2 {
				return false
			}
			args = args[2:]
		} else if strings.HasPrefix(args[0], "-C=") || strings.HasPrefix(args[0], "--C=") {
			args = args[1:]
		} else {
			return args[0] == "test"
		}
	}
	return false
}

// checkShellSrc parses shell source then applies checkCallHeads; parse failure is err.
func checkShellSrc(src string, depth int) (hitDriver, hitBare bool, err error) {
	f, perr := syntax.NewParser(syntax.Variant(syntax.LangPOSIX), syntax.KeepComments(false)).Parse(strings.NewReader(src), "")
	if perr != nil {
		return false, false, perr
	}
	return checkCallHeads(f, depth)
}

// checkCallHeads visits every peeled command head; env -S payloads, `sh -c` and `eval` args recurse at depth+1.
func checkCallHeads(f *syntax.File, depth int) (hitDriver, hitBare bool, err error) {
	if f == nil {
		return false, false, nil
	}
	if depth >= shellSplitMaxDepth {
		return false, false, errPeelExhausted // fail-closed
	}
	var perr error
	syntax.Walk(f, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if perr != nil || !ok {
			return perr == nil
		}
		argv := make([]string, 0, len(call.Assigns)+len(call.Args))
		for _, a := range call.Assigns { // nil Name / Naked → skip
			if a.Name != nil && !a.Naked {
				val, static := wordToArg(a.Value)
				if !static {
					val = cmdSubPlaceholder
				}
				argv = append(argv, a.Name.Value+"="+val)
			}
		}
		for _, w := range call.Args {
			s, static := wordToArg(w)
			if !static && s == "" {
				s = cmdSubPlaceholder
			}
			argv = append(argv, s)
		}
		head, splitPayloads, _, exhausted := peelWrappers(argv)
		if exhausted {
			perr = errPeelExhausted
			return false
		}
		hitDriver = hitDriver || isNsHcGotestDriver(head)
		if isBareGoTestArgv(head) {
			hitBare = true
			return false
		}
		var inner []string // nested payloads re-checked at depth+1
		for _, p := range splitPayloads {
			if !strings.HasPrefix(p, envUnknownLongPrefix) {
				inner = append(inner, p)
			}
		}
		if shText, has := unwrapShellArgv(head); has && strings.TrimSpace(shText) != "" {
			inner = append(inner, shText)
		}
		if len(head) >= 2 && head[0] == "eval" { // eval args are shell source too
			inner = append(inner, strings.Join(head[1:], " "))
		}
		for _, src := range inner {
			d, b, e := checkShellSrc(src, depth+1)
			if e != nil {
				perr = e
				return false
			}
			if b {
				hitBare = true
				return false
			}
			hitDriver = hitDriver || d
		}
		return true
	})
	return hitDriver, hitBare, perr
}

// checkShellLine strips make prefixes then reports driver/bare hits; unparseable fatal.
func checkShellLine(t *testing.T, line string) (hitDriver, hitBare bool) {
	t.Helper()
	d, b, err := checkShellSrc(stripMakeLinePrefix(line), 0)
	if err != nil {
		t.Fatalf("not parseable as shell: %q: %v", line, err)
	}
	return d, b
}

func TestNSHcScripts_ExecutableAndParse(t *testing.T) {
	for _, rel := range []string{"scripts/ns-hc-gotest.sh", "scripts/ns-hc-isolate.sh"} {
		fi, err := os.Stat(rel)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable (mode %v)", rel, fi.Mode().Perm())
		}
		if out, err := exec.Command("bash", "-n", rel).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", rel, err, out)
		}
		src := readRepoFile(t, rel)
		if strings.Contains(src, "/root/ctxmode-merge-jobs") {
			t.Errorf("%s references a hardcoded host merge-jobs path", rel)
		}
		// Stand-in is bind-mounted over hc/herdr-core slots: world-writable is unsafe.
		if strings.Contains(src, "chmod 0777") || strings.Contains(src, "chmod 777") {
			t.Errorf("%s must not chmod a stand-in world-writable", rel)
		}
	}
}

// mergeMakeContinuations folds `\` continuations (odd trailing count = continued).
func mergeMakeContinuations(lines []string) []string {
	var out []string
	pending := ""
	for _, raw := range lines {
		line := pending + raw
		pending = ""
		if trimmed := strings.TrimRight(line, " \t"); line == "" {
			continue
		} else if hasOddTrailingBackslash(trimmed) {
			pending = trimmed[:len(trimmed)-1] + " "
		} else {
			out = append(out, line)
		}
	}
	if pending != "" {
		out = append(out, pending)
	}
	return out
}

func TestMakefileCheckRunsSuiteUnderIsolation(t *testing.T) {
	// Self-check the matcher + continuation merge: must-flag shapes plus near-misses.
	for _, tc := range []struct {
		line string
		want bool
	}{
		{strings.Join(mergeMakeContinuations([]string{"go \\", "test ./..."}), "\n"), true}, // merge self-check
		{"./scripts/ns-hc-gotest.sh --race --timeout 30m; go test ./...", true},
		{"@go test ./...", true},
		{"-@CGO_ENABLED=1 /usr/local/bin/go test .", true},
		{"./scripts/ns-hc-gotest.sh --race --timeout 30m; env -- go test ./...", true},
		{"true; command -p -- go test ./...", true},
		{"sh -c 'go test ./...'", true},
		{"./scripts/ns-hc-gotest.sh --race --timeout 30m", false},
		{"go build -o /dev/null .", false},
		{"echo go test ./...", false},
	} {
		if _, got := checkShellLine(t, tc.line); got != tc.want {
			t.Fatalf("checkShellLine(%q) bare = %v, want %v", tc.line, got, tc.want)
		}
	}

	// Cross-check make's dry-run (fatal if fails): must carry the --race driver, no bare `go test`.
	if _, err := exec.LookPath("make"); err == nil {
		out, err := exec.Command("make", "-n", "check").CombinedOutput()
		if err != nil {
			t.Fatalf("make -n check failed: %v\n%s", err, out)
		}
		var shellLines []string
		for _, dline := range mergeMakeContinuations(strings.Split(string(out), "\n")) {
			if !strings.HasPrefix(strings.TrimSpace(dline), "make[") { // skip bookkeeping
				shellLines = append(shellLines, dline)
			}
		}
		d, b, cerr := checkShellSrc(stripMakeLinePrefix(strings.Join(shellLines, "\n")), 0)
		if cerr != nil {
			t.Fatalf("make -n check output not parseable as shell: %v", cerr)
		}
		if b {
			t.Error("make -n check output still runs a bare 'go test'")
		} else if !d {
			t.Errorf("make -n check output has no './scripts/ns-hc-gotest.sh ... --race' invocation:\n%s", out)
		}
	}

	// Check recipe as one shell block (multi-line if only parses joined).
	hitDriver, hitBare, err := checkShellSrc(stripMakeLinePrefix(makeRecipeBlock(t, "check")), 0)
	if err != nil {
		t.Fatalf("check recipe not parseable as shell: %v", err)
	} else if hitBare {
		t.Error("check recipe runs a bare 'go test' — TestMain refuses it with exit 125")
	} else if !hitDriver {
		t.Error("Makefile check must run tests via ./scripts/ns-hc-gotest.sh")
	}
}

func TestCIInstallsHostIsolationFixture(t *testing.T) {
	src := readRepoFile(t, filepath.FromSlash(".github/workflows/ci.yml"))
	find := func(parts ...string) int { // first non-comment line matching all parts
		for i, raw := range strings.Split(src, "\n") {
			line, ok := stripCommentLine(raw)
			if ok && !slices.ContainsFunc(parts, func(p string) bool { return !strings.Contains(line, p) }) {
				return i
			}
		}
		return -1
	}
	fixtureIdx := find("sudo install", "/usr/local/bin/herdr-core")
	hcLinkIdx := find("sudo ln -sf", "/usr/local/bin/hc")
	makeIdx := find("make check")
	if fixtureIdx < 0 {
		t.Error("ci.yml must install a real /usr/local/bin/herdr-core isolation target (sudo install)")
	}
	if hcLinkIdx < 0 {
		t.Error("ci.yml must symlink /usr/local/bin/hc to the isolation target (sudo ln -sf)")
	}
	if makeIdx < 0 {
		t.Error("ci.yml must still run make check")
	}
	for name, idx := range map[string]int{"herdr-core fixture install": fixtureIdx, "hc symlink": hcLinkIdx} {
		if idx >= 0 && makeIdx >= 0 && idx >= makeIdx {
			t.Errorf("%s (line %d) must come before make check (line %d)", name, idx+1, makeIdx+1)
		}
	}
}

// TestNSHcIsolate_ArgErrorsFailClosed runs the isolate script with a sentinel `sudo`
// first on PATH: validation errors exit non-zero WITHOUT invoking it (pre-re-exec).
func TestNSHcIsolate_ArgErrorsFailClosed(t *testing.T) {
	script, err := filepath.Abs("scripts/ns-hc-isolate.sh")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Sentinel sudo: records that it ran, exits 99 — reaching it proves regression.
	sudoMarker := filepath.Join(tmp, "sudo.called")
	stub := "#!/bin/sh\ntouch " + sudoMarker + "\nexit 99\n"
	if err := os.WriteFile(filepath.Join(binDir, "sudo"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	// A real ELF stand-in lets --standin FILE pass the magic check.
	standin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// PATH: sentinel dir first; PWD outside /root keeps NS_SEAL_ROOT logic live.
	env := append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	run := func(args []string, sub string) { // run + assert non-zero + diagnostic
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Env, cmd.Dir = env, tmp
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatalf("run %v: %v", args, err)
		} else if ee == nil {
			t.Errorf("ns-hc-isolate.sh %v: want non-zero exit\n%s", args, out)
		}
		if !strings.Contains(string(out), sub) {
			t.Errorf("ns-hc-isolate.sh %v: want %q in:\n%s", args, sub, out)
		}
	}
	for _, c := range []struct {
		args []string
		sub  string
	}{
		{[]string{}, "no command given"},
		{[]string{"--standin"}, "STANDIN"},
		{[]string{"--bogus"}, "unknown option: --bogus"},
		{[]string{"--standin", "/tmp/x"}, "no command given"},
		{[]string{"--standin", "/nonexistent", "--", "true"}, "stand-in not found: /nonexistent"},
	} {
		run(c.args, c.sub)
	}
	if _, err := os.Stat(sudoMarker); err == nil {
		t.Error("sentinel sudo was invoked: validation must run BEFORE the re-exec")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	// C-1 regression: a non-regular enumeration target (a FIFO shadowing
	// the `hc` name) must kill the script.
	if os.Geteuid() == 0 {
		if _, err := os.Stat("/root/.local/bin/herdr-core"); err != nil {
			t.Skip("no /root/.local/bin/herdr-core")
		}
		if err := syscall.Mkfifo(filepath.Join(binDir, "hc"), 0o644); err != nil {
			t.Fatal(err)
		}
		run([]string{"--standin", standin, "--", "true"}, "cannot resolve enumerated target to a regular file")
		if _, err := os.Stat(sudoMarker); err == nil {
			t.Error("sentinel sudo invoked during enumeration-error")
		}
	}
}
