package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// AlFix7: real dash argv differential tests (independent printer, race-safe).
// Host-safety hardened: no auto-delete under /, absolute redirects gated,
// write-dangerous names → argvprinter, fuzz corpus free of /, .., cd, ~.
// ---------------------------------------------------------------------------

var (
	argvPrinterOnce sync.Once
	argvPrinterPath string
	argvPrinterErr  error
)

func ensureArgvPrinter(t *testing.T) string {
	t.Helper()
	argvPrinterOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ctxmode-argvprinter-*")
		if err != nil {
			argvPrinterErr = err
			return
		}
		srcDir := filepath.Join(dir, "src")
		if err := os.MkdirAll(srcDir, 0o755); err != nil {
			argvPrinterErr = err
			return
		}
		src := filepath.Join(srcDir, "main.go")
		// Prefer checked-in testdata; fall back to embedded source.
		candidates := []string{
			"testdata/argvprinter/main.go",
		}
		var data []byte
		for _, c := range candidates {
			data, err = os.ReadFile(c)
			if err == nil {
				break
			}
		}
		if err != nil {
			data = []byte(argvPrinterSource)
		}
		if err := os.WriteFile(src, data, 0o644); err != nil {
			argvPrinterErr = err
			return
		}
		out := filepath.Join(dir, "argvprinter")
		cmd := exec.Command("go", "build", "-o", out, src)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			argvPrinterErr = fmt.Errorf("go build argvprinter: %v\n%s", err, b)
			return
		}
		argvPrinterPath = out
	})
	if argvPrinterErr != nil {
		t.Fatalf("argv printer: %v", argvPrinterErr)
	}
	return argvPrinterPath
}

const argvPrinterSource = `package main
import (
	"encoding/json"
	"os"
	"path/filepath"
)
func main() {
	out := os.Getenv("CTXMODE_ARGV_OUT")
	if out == "" { os.Exit(2) }
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil { os.Exit(2) }
	argv := make([]string, len(os.Args))
	copy(argv, os.Args)
	if len(argv) > 0 { argv[0] = filepath.Base(argv[0]) }
	if err := json.NewEncoder(f).Encode(argv); err != nil { _ = f.Close(); os.Exit(2) }
	_ = f.Close()
}
`

// collectGoCmdArgvs returns argv slices for segments that look like real commands
// (non-empty argv, not depth-exceeded markers). Nested substitution segments are
// included because dash executes them too.
func collectGoCmdArgvs(code string) (argvs [][]string, depthExceeded bool) {
	// Nested CmdSubst/heredoc commands are already sibling segments from the AST parser.
	// parseErr is fail-closed (same as depthExceeded for dash-diff purposes): the guard
	// rejected before emitting a complete argv picture, so argv mismatch is expected.
	// Wrapper heads are peeled so dash argv[0] (post env/nice/xargs) can match Go targets.
	// Interpreter -c payloads are recursively collected so dashExecutedUnknown sees nested
	// heads (SF-1). When peelWrappers consumes the whole argv (env -S only, etc.), treat
	// as fail-closed — the argv picture of what -S would exec is incomplete.
	segs := splitShellSegments(code)
	for _, s := range segs {
		if s.depthExceeded || s.parseErr != "" {
			depthExceeded = true
			continue
		}
		if len(s.argv) == 0 {
			continue
		}
		i, payloads, _, exhausted := peelWrappers(s.argv)
		if exhausted {
			depthExceeded = true
			continue
		}
		if i < 0 {
			i = 0
		}
		if i > len(s.argv) {
			i = len(s.argv)
		}
		head := s.argv[i:]
		if len(head) == 0 {
			// Peel ate everything (e.g. env -vS '…' with no trailing command).
			if len(payloads) > 0 || i > 0 {
				depthExceeded = true
			}
			continue
		}
		cp := append([]string(nil), head...)
		argvs = append(argvs, cp)
		if shellText, ok := unwrapShellArgv(head); ok && shellText != "" {
			nested, nestEx := collectGoCmdArgvs(shellText)
			if nestEx {
				depthExceeded = true
			}
			argvs = append(argvs, nested...)
		}
		// flock LOCK -c CMD / flock LOCK cmd…: collect inner command so
		// dashExecutedUnknown sees what dash runs after the lock wrapper (SF-1).
		if filepath.Base(head[0]) == "flock" {
			inner, cmdText := skipFlockArgs(head, 1)
			if cmdText != "" {
				if isDynamicArg(cmdText) {
					depthExceeded = true
				} else {
					nested, nestEx := collectGoCmdArgvs(cmdText)
					if nestEx {
						depthExceeded = true
					}
					argvs = append(argvs, nested...)
				}
			} else if inner >= 0 && inner < len(head) {
				nestedHead := append([]string(nil), head[inner:]...)
				if len(nestedHead) > 0 {
					argvs = append(argvs, nestedHead)
					if shellText2, ok2 := unwrapShellArgv(nestedHead); ok2 && shellText2 != "" {
						n2, n2ex := collectGoCmdArgvs(shellText2)
						if n2ex {
							depthExceeded = true
						}
						argvs = append(argvs, n2...)
					}
				}
			}
		}
	}
	return argvs, depthExceeded
}

// realWrapperBins are wrappers/interpreters that must resolve to real system
// binaries so MF-6-style env/nice/xargs/find peeling still works under PATH.
var realWrapperBins = []string{
	"sh", "dash", "bash", "env", "nice", "timeout", "xargs", "find",
	"stdbuf", "setsid", "flock", "nohup",
}

// argvPrinterLeafNames are leaf probes, blocked targets, and write-dangerous
// command names that must NEVER resolve to real binaries in the test PATH.
var argvPrinterLeafNames = []string{
	"p1", "p2", "p3", "probe", "printargv", "pig", "pi", "agy",
	"dispatch-agent", "dispatch-agent-go", "grok", "tmux", "screen", "sudo",
	"rg", "ls", "cat", "git", "rm", "mv", "cp", "tee", "dd", "chmod", "ln",
	"herdr", "herdsman", "ctxmode", "head", "tail", "wc", "sort", "uniq",
	"cut", "tr", "jq", "diff", "stat", "file", "du", "df",
	"python3", "node", "perl", "ruby", "php",
}

func lookRealBin(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range []string{"/bin", "/usr/bin"} {
		cand := filepath.Join(d, name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	return ""
}

// setupPrinterPATH creates a temp dir with:
//   - real symlinks for wrappers/interpreters (sh/env/nice/find/…)
//   - argvprinter symlinks for leaf probes + write-dangerous names
//
// Dash builtins (echo/true/false/test/[) are NOT faked into PATH.
func setupPrinterPATH(t *testing.T, names []string) (pathDir, outFile string) {
	t.Helper()
	printer := ensureArgvPrinter(t)
	pathDir = t.TempDir()
	outFile = filepath.Join(t.TempDir(), "argv.jsonl")
	seen := map[string]bool{}

	linkPrinter := func(base string) {
		if base == "" || base == "." || base == "/" || seen[base] {
			return
		}
		if isDashBuiltin(base) {
			return
		}
		seen[base] = true
		if err := os.Symlink(printer, filepath.Join(pathDir, base)); err != nil {
			t.Fatalf("symlink printer %s: %v", base, err)
		}
	}
	linkReal := func(base string) {
		if base == "" || seen[base] {
			return
		}
		seen[base] = true
		target := lookRealBin(base)
		if target == "" {
			// Missing wrapper: fall back to printer so PATH stays closed.
			if err := os.Symlink(printer, filepath.Join(pathDir, base)); err != nil {
				t.Fatalf("symlink fallback %s: %v", base, err)
			}
			return
		}
		if err := os.Symlink(target, filepath.Join(pathDir, base)); err != nil {
			t.Fatalf("symlink real %s -> %s: %v", base, target, err)
		}
	}

	for _, n := range realWrapperBins {
		linkReal(n)
	}
	for _, n := range argvPrinterLeafNames {
		linkPrinter(n)
	}
	for _, n := range names {
		linkPrinter(filepath.Base(n))
	}
	return pathDir, outFile
}

func namesFromGoArgvs(argvs [][]string) []string {
	var names []string
	for _, a := range argvs {
		if len(a) > 0 {
			names = append(names, a[0])
		}
	}
	return names
}

// snapshotRootDir records the set of names present directly under "/".
func snapshotRootDir(t *testing.T) map[string]struct{} {
	t.Helper()
	ents, err := os.ReadDir("/")
	if err != nil {
		t.Fatalf("snapshot /: %v", err)
	}
	m := make(map[string]struct{}, len(ents))
	for _, e := range ents {
		m[e.Name()] = struct{}{}
	}
	return m
}

// assertRootDirUnchanged fails if "/" gained new entries.
// It NEVER deletes or modifies anything under "/".
func assertRootDirUnchanged(t *testing.T, before map[string]struct{}) {
	t.Helper()
	ents, err := os.ReadDir("/")
	if err != nil {
		t.Fatalf("re-read /: %v", err)
	}
	var added []string
	for _, e := range ents {
		if _, ok := before[e.Name()]; !ok {
			added = append(added, e.Name())
		}
	}
	if len(added) > 0 {
		t.Fatalf("host safety: new entries appeared under /: %v (report only; nothing deleted)", added)
	}
}

// takeRedirectWord returns the next shell word at s[0:] (quoted or bare) and
// the number of bytes consumed. Quotes are stripped for the returned value;
// glued quote/bare tails are concatenated (e.g. '/dev/null'foo → /dev/nullfoo).
func takeRedirectWord(s string) (word string, n int) {
	if s == "" {
		return "", 0
	}
	i := 0
	var b strings.Builder
	for i < len(s) {
		switch s[i] {
		case ' ', '\t', '\n', '\r', ';', '&', '|', '<', '>', '(', ')', '\x00':
			return b.String(), i
		case '\'':
			i++
			for i < len(s) && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++ // closing '
			}
		case '"':
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++ // closing "
			}
		case '\\':
			if i+1 < len(s) {
				b.WriteByte(s[i+1])
				i += 2
			} else {
				b.WriteByte('\\')
				i++
			}
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String(), i
}

// isSafeRedirectForTestExec reports whether code is safe to feed to /bin/sh.
// Unsafe = absolute redirect targets other than /dev/null, dynamic redirect
// targets ($ ` * ? [ ..), unquoted-# comment quote-flip hazards, or find
// write actions (-delete/-fprint*/-fls). Heredocs and fd-duplication (>&N)
// are ignored. On unsafe, callers must NOT exec /bin/sh.
func isSafeRedirectForTestExec(code string) bool {
	// Real find in PATH can write/delete; never feed those samples to /bin/sh.
	if strings.Contains(code, "-delete") || strings.Contains(code, "-fprint") || strings.Contains(code, "-fls") {
		return false
	}
	i := 0
	for i < len(code) {
		// Unquoted '#' at a word-start boundary starts a comment through '\n'.
		// Quotes inside the comment must NOT flip quote state (SF-1).
		if code[i] == '#' {
			atWordStart := i == 0
			if !atWordStart {
				prev := code[i-1]
				atWordStart = prev == ' ' || prev == '\t' || prev == '\n' ||
					prev == ';' || prev == '|' || prev == '&' || prev == '(' || prev == ')'
			}
			if atWordStart {
				for i < len(code) && code[i] != '\n' {
					i++
				}
				continue
			}
		}
		// Skip single-quoted regions so literal > inside quotes is ignored.
		if code[i] == '\'' {
			i++
			for i < len(code) && code[i] != '\'' {
				i++
			}
			if i < len(code) {
				i++
			}
			continue
		}
		if code[i] == '"' {
			i++
			for i < len(code) && code[i] != '"' {
				if code[i] == '\\' && i+1 < len(code) {
					i += 2
					continue
				}
				i++
			}
			if i < len(code) {
				i++
			}
			continue
		}
		if code[i] == '\\' && i+1 < len(code) {
			i += 2
			continue
		}

		c := code[i]
		if c != '>' && c != '<' {
			i++
			continue
		}
		// Heredoc << / <<- : not a file redirect target we gate.
		if c == '<' && i+1 < len(code) && code[i+1] == '<' {
			i += 2
			continue
		}
		j := i + 1
		if c == '>' && j < len(code) && (code[j] == '>' || code[j] == '|') {
			j++ // >> or >|
		}
		// Fd duplication: >&1 / <&0 — no path target.
		if j < len(code) && code[j] == '&' {
			i = j + 1
			continue
		}
		for j < len(code) && (code[j] == ' ' || code[j] == '\t') {
			j++
		}
		if j >= len(code) {
			return true
		}
		rawStart := j
		target, n := takeRedirectWord(code[j:])
		rawTarget := code[rawStart : rawStart+n]
		if target == "" ||
			strings.ContainsAny(rawTarget, "$`*?[\r\n") ||
			strings.Contains(target, "..") ||
			(strings.HasPrefix(target, "/") && target != "/dev/null") {
			return false
		}
		i = j
	}
	return true
}

// runDashCollectArgvs executes code under /bin/sh with PATH limited to the
// printer directory. Returns the JSONL-decoded argv sequences dash invoked.
// Host safety: skips exec when redirects target absolute paths other than
// /dev/null; snapshots "/" around the run and fails on new entries (never deletes).
func runDashCollectArgvs(t *testing.T, code, pathDir, outFile string) ([][]string, string, error) {
	t.Helper()
	if !isSafeRedirectForTestExec(code) {
		return nil, "", nil
	}
	before := snapshotRootDir(t)
	defer assertRootDirUnchanged(t, before)

	_ = os.Remove(outFile)
	workDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", code)
	cmd.Dir = workDir
	cmd.Env = []string{
		"PATH=" + pathDir,
		"CTXMODE_ARGV_OUT=" + outFile,
		"HOME=" + workDir,
		"TMPDIR=" + workDir,
		"LANG=C",
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	raw := buf.String()
	data, rerr := os.ReadFile(outFile)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return nil, raw, err
		}
		return nil, raw, fmt.Errorf("read argv out: %v (run err=%v raw=%q)", rerr, err, raw)
	}
	var argvs [][]string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var a []string
		if jerr := json.Unmarshal(line, &a); jerr != nil {
			return argvs, raw, fmt.Errorf("json line %q: %w", line, jerr)
		}
		argvs = append(argvs, a)
	}
	return argvs, raw, err
}

func argvsEqual(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

func fmtArgvs(a [][]string) string {
	var b strings.Builder
	for i, v := range a {
		fmt.Fprintf(&b, "  [%d]=%#v\n", i, v)
	}
	return b.String()
}

// isDashBuiltin reports Debian dash builtins measured via `type` (TASK sh8).
// fc/help/let/bind/typeset/declare are absent on this dash.
func isDashBuiltin(name string) bool {
	switch name {
	case ":", ".", "[", "alias", "bg", "break", "cd", "command", "continue",
		"echo", "eval", "exec", "exit", "export", "false", "fg", "getopts",
		"hash", "jobs", "kill", "local", "printf", "pwd", "read", "readonly",
		"return", "set", "shift", "test", "times", "trap", "true", "type",
		"ulimit", "umask", "unalias", "unset", "wait":
		return true
	}
	return false
}

// filterExternalArgvs drops dash builtins (they never hit the printer PATH).
func filterExternalArgvs(argvs [][]string) [][]string {
	var out [][]string
	for _, a := range argvs {
		if len(a) == 0 || isDashBuiltin(a[0]) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// isRealWrapper reports wrappers/interpreters that resolve to real binaries.
func isRealWrapper(name string) bool {
	for _, w := range realWrapperBins {
		if name == w {
			return true
		}
	}
	return false
}

// staticLeafArgvs keeps argvprinter-leaf commands (not builtins, not real wrappers)
// for deep argv[0]+argv[1:] matching against dash printer captures.
func staticLeafArgvs(argvs [][]string) [][]string {
	var out [][]string
	for _, a := range argvs {
		if len(a) == 0 || isDashBuiltin(a[0]) || isRealWrapper(a[0]) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// argvHasDynamic reports placeholders left by the AST for non-static words.
func argvHasDynamic(a []string) bool {
	for _, s := range a {
		if strings.Contains(s, cmdSubPlaceholder) || strings.Contains(s, cmdSubPlaceholderQuoted) ||
			strings.Contains(s, dynamicRedirectTarget) ||
			strings.Contains(s, envUnknownLongPrefix) || strings.Contains(s, "__ctx_") {
			return true
		}
	}
	return false
}

// staticConcreteLeafArgvs keeps printer-leaf commands with fully static argv
// (no __ctx_cmdsub__ / dynamic placeholders) for deep argv[0]+argv[1:] checks.
func staticConcreteLeafArgvs(argvs [][]string) [][]string {
	var out [][]string
	for _, a := range staticLeafArgvs(argvs) {
		if argvHasDynamic(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// leafArgvDeepAgree reports whether every dash leaf whose argv[0] appears in
// goLeaves has an exact full argv[0]+argv[1:] match among those Go leaves.
// When Go also tracked a dynamic sibling with the same argv[0] (placeholder
// args), a dash expansion that does not exact-match is ignored — the static
// Go leaf is a different invocation. Unknown dash heads use dashExecutedUnknown.
// Go-only over-parses (untaken || branches, uncalled function bodies) are ignored.
func leafArgvDeepAgree(goLeaves, dashLeaves [][]string) bool {
	return leafArgvDeepAgreeExt(goLeaves, dashLeaves, nil)
}

func leafArgvDeepAgreeExt(goLeaves, dashLeaves, goWithDyn [][]string) bool {
	// When dash ran a head that Go listed as a static leaf, full argv must
	// exact-match one static Go leaf. If Go also tracked a dynamic sibling
	// with the same argv0 (placeholder args), a dash expansion that does not
	// exact-match is ignored — the static Go leaf is a different invocation.
	// Unknown dash heads use dashExecutedUnknown. Go-only over-parses are ignored.
	byHead := map[string][][]string{}
	for _, g := range goLeaves {
		if len(g) == 0 {
			continue
		}
		byHead[g[0]] = append(byHead[g[0]], g)
	}
	dynHeads := map[string]bool{}
	for _, g := range goWithDyn {
		if len(g) == 0 || !argvHasDynamic(g) {
			continue
		}
		dynHeads[g[0]] = true
	}
	for _, d := range dashLeaves {
		if len(d) == 0 {
			continue
		}
		cands := byHead[d[0]]
		if len(cands) == 0 {
			continue
		}
		ok := false
		for _, g := range cands {
			if len(g) != len(d) {
				continue
			}
			eq := true
			for k := range g {
				if g[k] != d[k] {
					eq = false
					break
				}
			}
			if eq {
				ok = true
				break
			}
		}
		if !ok {
			if dynHeads[d[0]] {
				continue
			}
			return false
		}
	}
	return true
}

// dashExecutedUnknown reports whether dash ran a command name that Go did not
// list in any segment argv[0]. This is the Must-Fix-1 failure shape.

// envArgv0Aliases collects names that env -a / --argv0 would install as the
// executed process argv[0], so argvprinter recordings of those names are not
// treated as real executions of a binary with that basename.
func envArgv0Aliases(argvs [][]string) map[string]bool {
	out := map[string]bool{}
	for _, a := range argvs {
		for i := 0; i < len(a); i++ {
			switch {
			case a[i] == "-a" || a[i] == "--argv0":
				if i+1 < len(a) {
					out[a[i+1]] = true
					i++
				}
			case strings.HasPrefix(a[i], "-a") && a[i] != "-a" && !strings.HasPrefix(a[i], "--"):
				rest := a[i][2:]
				if rest != "" {
					out[rest] = true
				}
			case strings.HasPrefix(a[i], "--argv0="):
				out[a[i][len("--argv0="):]] = true
			}
		}
	}
	return out
}

func filterAliasMisses(miss []string, aliases map[string]bool) []string {
	if len(aliases) == 0 {
		return miss
	}
	var out []string
	for _, m := range miss {
		if !aliases[m] {
			out = append(out, m)
		}
	}
	return out
}

func dashExecutedUnknown(goArgvs, dashArgvs [][]string) []string {
	seen := map[string]bool{}
	argv0Aliases := map[string]bool{} // env -a NAME / --argv0 NAME rename the executed argv0
	for _, a := range goArgvs {
		if len(a) > 0 {
			seen[a[0]] = true
		}
		for i := 0; i+1 < len(a); i++ {
			if a[i] == "-a" || a[i] == "--argv0" {
				argv0Aliases[a[i+1]] = true
			}
			if strings.HasPrefix(a[i], "--argv0=") {
				argv0Aliases[a[i][len("--argv0="):]] = true
			}
		}
	}
	var miss []string
	for _, a := range dashArgvs {
		if len(a) == 0 {
			continue
		}
		if !seen[a[0]] && !argv0Aliases[a[0]] {
			miss = append(miss, a[0])
		}
	}
	return miss
}

type dashDiffCase struct {
	name string
	code string
	// compareFull: when true, require exact argv sequence match (segment count + bytes).
	// when false, only fail if dash executed a command Go did not see (or segment-count 0 vs >0).
	compareFull bool
	// expectDashRuns: optional; if set, require dash to have invoked at least one command.
	expectDashRuns bool
}

func alfix7MustFixSamples() []dashDiffCase {
	return []dashDiffCase{
		// Must Fix 1
		{name: "MF1_comment_cont_rm", code: "# \\\nrm -rf /tmp/pwn", compareFull: false, expectDashRuns: true},
		{name: "MF1_comment_cont_pig", code: "# \\\npig", compareFull: false, expectDashRuns: true},
		{name: "MF1_comment_cont_python", code: "# \\\npython3 -c 'import os'", compareFull: false, expectDashRuns: true},
		{name: "MF1_even_bs_pig", code: "echo \\\\\npig", compareFull: false, expectDashRuns: true},
		{name: "MF1_dq_sq_contam", code: "echo \"'\" \"$\\\n(pig)\"", compareFull: false, expectDashRuns: true},
		// Must Fix 2
		{name: "MF2_heredoc_cr_delim", code: "cat <<'EOF'\r\nEOF\n'\nEOF\r\npig\n# '\n", compareFull: false, expectDashRuns: true},
		// Must Fix 3
		{name: "MF3_param_sq_in_dq", code: `echo "${UNSET:-'$(pig)'}"`, compareFull: false, expectDashRuns: true},
		{name: "MF3_param_brace_sq", code: `echo "${UNSET:-'}"; pig # '}"`, compareFull: false, expectDashRuns: true},
		{name: "MF3_nested_param", code: `echo ${UNSET1:-"${UNSET2:-"'"}" $(pig)}`, compareFull: false, expectDashRuns: true},
		{name: "MF3_redir_param", code: `true < "${UNSET:-"'"}" 2>/dev/null ; pig # '`, compareFull: false, expectDashRuns: true},
		// Must Fix 4
		{name: "MF4_bt_in_param", code: "echo ${UNSET:-`\\`pig\\``}", compareFull: false, expectDashRuns: true},
		{name: "MF4_bt_in_arith", code: "echo $(( `\\`pig\\`` + 0 ))", compareFull: false, expectDashRuns: true},
		// Must Fix 5
		{name: "MF5_case_in_dq_cmdsub", code: `echo "$(case x in x) pig;; esac)"`, compareFull: false, expectDashRuns: true},
		{name: "MF5_heredoc_in_dq_cmdsub", code: "echo \"$(cat <<EOF\n)\nEOF\npig)\"", compareFull: false, expectDashRuns: true},
		// Must Fix 6 (argv-level; also exercised via shell)
		{name: "MF6_env_a", code: "env -a true pig", compareFull: false, expectDashRuns: true},
		{name: "MF6_env_argv0", code: "env --argv0 true pig", compareFull: false, expectDashRuns: true},
		{name: "MF6_env_vS", code: "env -vS 'env pig'", compareFull: false, expectDashRuns: true},
		{name: "MF6_env_dash", code: "env - sh -c p1", compareFull: false, expectDashRuns: false},
	}
}

func alfix7Audit3Diff32() []dashDiffCase {
	// Shell-string cases from AUDIT3 §4 (argv-only cases handled separately).
	return []dashDiffCase{
		{name: "A01_cr_comment", code: "true \r#; echo PWN", compareFull: false},
		{name: "A02_cr_cmdhead", code: "ls\r", compareFull: false},
		{name: "A03_cr_opt", code: "rg -e \r --pre=/usr/bin/id pat .", compareFull: true},
		{name: "A04_cr_redir", code: "echo hi >/dev/null\rfoo", compareFull: false},
		{name: "A05_ctrl_v", code: "ls \v -la", compareFull: true},
		{name: "A06_sq_digit", code: "rg -e '2'>/dev/null --pre=/usr/bin/id pat .", compareFull: true},
		{name: "A07_dq_digit", code: `nice -n "2">/dev/null pig`, compareFull: false, expectDashRuns: true},
		{name: "A08_bs_digit", code: `rg -e \2>/dev/null --pre=/usr/bin/id pat .`, compareFull: true},
		{name: "A09_empty_q_digit", code: `rg -e ""2>/dev/null --pre=/usr/bin/id pat .`, compareFull: true},
		{name: "A10_midword_digit", code: "echo a2>/dev/null b", compareFull: false},
		{name: "A11_bare_io", code: "ls 2>/dev/null", compareFull: true},
		{name: "A12_digit_space", code: "echo 2 >/dev/null", compareFull: false},
		{name: "A13_redir_glue", code: "echo hi >'/dev/null'foo", compareFull: false},
		{name: "A14_fd_glue", code: "echo hi 2>&1foo", compareFull: false},
		{name: "A15_leading_redir", code: "2>/dev/null ls -la", compareFull: true},
		{name: "A16_quoted_if", code: "'if' true; then ls; fi", compareFull: false},
		{name: "A17_tilde", code: "~", compareFull: false},
		{name: "A18_tilde_arg", code: "ls ~", compareFull: false},
		{name: "A19_glob", code: "ls *.go", compareFull: false},
		{name: "A20_fake_arith", code: `bash -c 'echo $((pig); (true))'`, compareFull: false},
		{name: "A21_arith_nested", code: "echo $(( (1+1) * $(pig) ))", compareFull: false, expectDashRuns: true},
		{name: "A22_param_dq", code: `echo $(echo "${x:-")"}"; pig)`, compareFull: false, expectDashRuns: true},
		{name: "A23_param_sq", code: `echo $(echo ${x:-')'}; pig)`, compareFull: false, expectDashRuns: true},
		{name: "A24_linecont_dollar", code: "echo $\\\n(pig)", compareFull: false, expectDashRuns: true},
		{name: "A25_dq_linecont", code: "echo \"$\\\n(pig)\"", compareFull: false, expectDashRuns: true},
		{name: "A26_linecont_heredoc", code: "cat <\\\n<EOF\n$(pig)\nEOF", compareFull: false, expectDashRuns: true},
		{name: "A27_bt_escape", code: "echo `\\`pig\\``", compareFull: false, expectDashRuns: true},
		{name: "A28_bt_dbs", code: "echo `echo a\\\\` ; pig ; #`", compareFull: false, expectDashRuns: true},
		{name: "A29_heredoc_cr", code: "cat <<'EOF'\nEOF\r\n'; pig; '\nEOF", compareFull: false},
	}
}

func alfix7ShouldFixSamples() []dashDiffCase {
	return []dashDiffCase{
		{name: "SF_comment_cont_ls", code: "# \\\nls", compareFull: false, expectDashRuns: true},
		{name: "SF_heredoc_phys_line", code: "cat <<'EOF' >/dev/null\nEO\\\nF\n'\nEOF\npig\n# '\n", compareFull: false, expectDashRuns: true},
	}
}

func alfix7ReportTableSamples() []dashDiffCase {
	// From REPORT §2 excerpt table (shell forms).
	return []dashDiffCase{
		{name: "R_cr_pwn", code: "true \r#; echo PWN", compareFull: false},
		{name: "R_rg_cr_pre", code: "rg -e \r --pre=/usr/bin/id pat .", compareFull: true},
		{name: "R_sq_digit_pre", code: "rg -e '2'>/dev/null --pre=/usr/bin/id pat .", compareFull: true},
		{name: "R_bs_digit", code: `rg -e \2>/dev/null --pre=/usr/bin/id pat .`, compareFull: true},
		{name: "R_fd_glue", code: "echo hi 2>&1foo", compareFull: false},
		{name: "R_fake_arith", code: `bash -c 'echo $((pig); (true))'`, compareFull: false},
		{name: "R_comment_cont_pwn", code: "# \\\npig", compareFull: false, expectDashRuns: true},
		{name: "R_comment_cont_pig", code: "# \\\npig", compareFull: false, expectDashRuns: true},
		{name: "R_comment_cont_ls", code: "# \\\nls", compareFull: false, expectDashRuns: true},
		{name: "R_comment_cont_cat", code: "# \\\ncat", compareFull: false, expectDashRuns: true},
	}
}

func runDashDiffCases(t *testing.T, cases []dashDiffCase) (mismatches []string) {
	t.Helper()
	if _, err := exec.LookPath("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	_ = ensureArgvPrinter(t)
	rootBefore := snapshotRootDir(t)
	t.Cleanup(func() { assertRootDirUnchanged(t, rootBefore) })

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			before := snapshotRootDir(t)
			t.Cleanup(func() { assertRootDirUnchanged(t, before) })

			goArgvs, depthEx := collectGoCmdArgvs(c.code)
			// Always install printer names for expected dash heads + common set.
			names := namesFromGoArgvs(goArgvs)
			// Seed likely heads from the code text for MF1 (Go may see 0 segs).
			for _, h := range []string{"rm", "pig", "python3", "echo", "true", "ls", "cat", "env", "sh", "bash", "nice", "rg"} {
				if strings.Contains(c.code, h) {
					names = append(names, h)
				}
			}
			pathDir, outFile := setupPrinterPATH(t, names)
			safe := isSafeRedirectForTestExec(c.code)
			dashArgvs, raw, _ := runDashCollectArgvs(t, c.code, pathDir, outFile)

			// SF-1: never early-return on guard reject. When !depthEx the Go AST
			// produced a complete argv picture, so dashExecutedUnknown must still
			// fire even if the worker guard blocked pig/rm by name. Only depthEx
			// (parseErr / depthExceeded fail-closed) skips those asserts.
			// expectDashRuns: skip when safety gate refused exec or AST fail-closed.
			if c.expectDashRuns && len(dashArgvs) == 0 && safe && !depthEx {
				msg := fmt.Sprintf("%s: expected dash to run external probe; raw=%q go=%s Hint: replace builtins with p1/p2/pig", c.name, raw, fmtArgvs(goArgvs))
				mismatches = append(mismatches, msg)
				t.Error(msg)
				return
			}

			goExt := filterExternalArgvs(goArgvs)
			// env -a/--argv0 aliases come from the unpeeled segment argv.
			rawArgvs := [][]string{}
			for _, s := range splitShellSegments(c.code) {
				if len(s.argv) > 0 {
					rawArgvs = append(rawArgvs, append([]string(nil), s.argv...))
				}
			}
			aliases := envArgv0Aliases(rawArgvs)
			miss := filterAliasMisses(dashExecutedUnknown(goExt, dashArgvs), aliases)
			if len(miss) > 0 && !depthEx {
				msg := fmt.Sprintf("%s: dash ran cmds Go missed: %v\ncode=%q\ngo:\n%sdash:\n%sraw=%q",
					c.name, miss, c.code, fmtArgvs(goArgvs), fmtArgvs(dashArgvs), raw)
				mismatches = append(mismatches, msg)
				t.Error(msg)
				return
			}
			// Segment count mismatch when Go sees 0 externals but dash ran ≥1 (MF1 shape).
			if len(goExt) == 0 && len(dashArgvs) > 0 && !depthEx {
				msg := fmt.Sprintf("%s: Go 0 external segs but dash ran %d\ncode=%q\ndash:\n%s",
					c.name, len(dashArgvs), c.code, fmtArgvs(dashArgvs))
				mismatches = append(mismatches, msg)
				t.Error(msg)
				return
			}
			if c.compareFull && !depthEx {
				// Full argv[0]+argv[1:] compare for external commands only.
				if !argvsEqual(goExt, dashArgvs) {
					msg := fmt.Sprintf("%s: argv sequence mismatch\ncode=%q\ngoExt:\n%sdash:\n%sraw=%q",
						c.name, c.code, fmtArgvs(goExt), fmtArgvs(dashArgvs), raw)
					mismatches = append(mismatches, msg)
					t.Error(msg)
				}
			}
		})
	}
	return mismatches
}

func TestAlFix7_DashDiff_MustFix(t *testing.T) {
	runDashDiffCases(t, alfix7MustFixSamples())
}

func TestAlFix7_DashDiff_Audit3_32(t *testing.T) {
	runDashDiffCases(t, alfix7Audit3Diff32())
}

func TestAlFix7_DashDiff_ShouldFixSamples(t *testing.T) {
	runDashDiffCases(t, alfix7ShouldFixSamples())
}

func TestAlFix7_DashDiff_ReportTable(t *testing.T) {
	runDashDiffCases(t, alfix7ReportTableSamples())
}

// Guard-level red tests for Must Fix samples (subagent must see nested agent).
func TestAlFix7_MustFix_SubagentBlocks(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")
	cases := []struct {
		name string
		code string
		argv []string
	}{
		{name: "MF1_comment_cont_pig", code: "# \\\npig"},
		{name: "MF1_even_bs", code: "echo \\\\\npig"},
		{name: "MF1_dq_sq", code: "echo \"'\" \"$\\\n(pig)\""},
		{name: "MF2_heredoc_cr", code: "cat <<'EOF'\r\nEOF\n'\nEOF\r\npig\n# '\n"},
		{name: "MF3_param_sq", code: `echo "${UNSET:-'$(pig)'}"`},
		{name: "MF3_brace", code: `echo "${UNSET:-'}"; pig # '}"`},
		{name: "MF3_nested", code: `echo ${UNSET1:-"${UNSET2:-"'"}" $(pig)}`},
		{name: "MF4_bt_param", code: "echo ${UNSET:-`\\`pig\\``}"},
		{name: "MF4_bt_arith", code: "echo $(( `\\`pig\\`` + 0 ))"},
		{name: "MF5_case", code: `echo "$(case x in x) pig;; esac)"`},
		{name: "MF5_heredoc", code: "echo \"$(cat <<EOF\n)\nEOF\npig)\""},
		{name: "MF6_env_a", argv: []string{"env", "-a", "true", "pig"}},
		{name: "MF6_env_argv0", argv: []string{"env", "--argv0", "true", "pig"}},
		{name: "MF6_env_vS", argv: []string{"env", "-vS", "env pig"}},
		{name: "MF6_env_vC", argv: []string{"env", "-vC", "/tmp", "pig"}},
		{name: "MF6_env_vu", argv: []string{"env", "-vu", "CTXMODE_ROLE", "pig"}},
		{name: "MF6_env_dash", argv: []string{"env", "-", "sh", "-c", "id"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hit string
			if len(c.argv) > 0 {
				hit = guardArgvSubagent(c.argv)
			} else {
				hit = guardShellSubagent(c.code)
			}
			if hit == "" {
				t.Fatalf("expected subagent block for %s code=%q argv=%v", c.name, c.code, c.argv)
			}
		})
	}
}

func TestAlFix7_MustFix_ReadonlyBlocks(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")
	cases := []struct {
		name string
		code string
	}{
		{name: "MF1_comment_cont_pig", code: "# \\\npig"},
		{name: "MF1_comment_cont_rm", code: "# \\\nrm -rf /tmp/pwn"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if hit := guardShellReadonly(c.code); hit == "" {
				t.Fatalf("expected readonly block for %q", c.code)
			}
		})
	}
	// After the parse fix, comment-continuation + allowlisted cmd is visible and allowed.
	t.Run("MF1_comment_cont_ls_allow", func(t *testing.T) {
		if hit := guardShellReadonly("# \\\nls"); hit != "" {
			t.Fatalf("expected allow for comment-cont + ls, got %q", hit)
		}
	})
}

// Should Fix / Nice to Have allow/block expectations.
func TestAlFix7_ShouldFix_Allowlist(t *testing.T) {
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	allow := []struct {
		name string
		argv []string
		code string
	}{
		{name: "trailing_nl", code: "ls -la\n"},
		{name: "blank_line", code: "git status\n\ngit log -n 5"},
		{name: "comment_line", code: "# 查看状态\ngit status"},
		{name: "trailing_comment", code: "git status\n# 备注"},
		{name: "find_prune", argv: []string{"find", ".", "-path", "./.git", "-prune", "-o", "-name", "*.go", "-print"}},
		{name: "find_newermt", argv: []string{"find", ".", "-newermt", "2026-01-01"}},
		{name: "git_tag_sort_desc", argv: []string{"git", "tag", "-l", "--sort", "-creatordate"}},
		{name: "herdr_pane_current", argv: []string{"herdr", "pane", "current"}},
		{name: "herdr_pane_help", argv: []string{"herdr", "pane", "--help"}},
		{name: "herdr_skill", argv: []string{"herdr", "--skill"}},
		{name: "herdr_default_config", argv: []string{"herdr", "--default-config"}},
		{name: "herdsman_status", argv: []string{"herdsman", "status"}},
		{name: "herdsman_agent_list", argv: []string{"herdsman", "agent", "list"}},
		{name: "git_reflog_n", argv: []string{"git", "reflog", "-n", "10"}},
		{name: "ctxmode_h", argv: []string{"ctxmode", "-h"}},
		{name: "ctxmode_help_flag", argv: []string{"ctxmode", "--help"}},
		{name: "rg_a", argv: []string{"rg", "-a", "pat", "."}},
		{name: "rg_c", argv: []string{"rg", "-c", "pat", "."}},
		{name: "rg_g", argv: []string{"rg", "-g", "*.go", "pat"}},
	}
	for _, c := range allow {
		t.Run("allow_"+c.name, func(t *testing.T) {
			var hit string
			if len(c.argv) > 0 {
				hit = guardArgvReadonly(c.argv)
			} else {
				hit = guardShellReadonly(c.code)
			}
			if hit != "" {
				t.Fatalf("expected allow, got %q for %s", hit, c.name)
			}
		})
	}

	block := []struct {
		name string
		argv []string
	}{
		{name: "ctxmode_help_sub", argv: []string{"ctxmode", "help"}},
		{name: "ctxmode_ddash_h", argv: []string{"ctxmode", "--", "-h"}},
		{name: "git_tag_delete", argv: []string{"git", "tag", "-l", "-d", "foo"}},
		{name: "git_branch_sort_D", argv: []string{"git", "branch", "-l", "--sort", "-D", "foo"}},
	}
	for _, c := range block {
		t.Run("block_"+c.name, func(t *testing.T) {
			if hit := guardArgvReadonly(c.argv); hit == "" {
				t.Fatalf("expected block for %v", c.argv)
			}
		})
	}
}

func TestAlFix7_FuzzArgvDiff(t *testing.T) {
	t.Setenv(auditEnvRole, "worker")
	t.Setenv(auditEnvReadonly, "")
	rootBefore := snapshotRootDir(t)
	t.Cleanup(func() { assertRootDirUnchanged(t, rootBefore) })

	const seed = 20261104
	rng := rand.New(rand.NewSource(seed))
	N := 20000
	if raceEnabled {
		N = 2000
	}

	// Byte fragments with NO implicit surrounding spaces (PLAN §5.3).
	// Host safety: no "/", "..", "cd", or "~" in any frag.
	frags := []string{
		"p1", "p2", "pig",
		" ", "\t", "\n", ";", "|", "&&", "||",
		"\\\n", "\\\\\n", "\\", "\\\"", "\\$", "\\'",
		"'a'", "'", "\"", "$(", ")", "$((", "))", "${x:-", "${x:-\"", "}", "`",
		"cat <<EOF\n", "cat <<'EOF'\n", "cat <<EO\\\nF\n", "cat <<\"\\$EOF\"\n",
		"\nEOF\n", "\n$EOF\n", "\n)\nEOF\n",
		"case $? in 0) p1;; esac", "case x in x) pig;; esac",
		"# \\\np1\n", "2\\\n>sink", "'2'>sink",
		// SF-1 grammar-aware lexical seeds (no "/", "..", "cd", "~")
		"$", "$\\\n", "{x:-pig}", "{x:-p1}", "{x:--c}", "1",
		"\\\n # \\\n", " # \\\n", "p1 \\\n # \\\npig\n",
		"sh -c '", "' _ pig", "env -u ", "flock sink -c ", "trap ", " EXIT",
		"${x:-", "\\\"\"", "$(case x in x) p1;; esac)",
	}
	// Host safety: no "/", "..", "cd", or "~"; redirects use relative sink.
	templates := []string{
		"p1 $(p2)",
		"p1 ${x:-p2}",
		"p1 \"${x:-'y'}\"",
		"cat <<EOF\n$(pig)\nEOF",
		"cat <<'EOF'\n$(pig)\nEOF",
		"env -a p1 pig",
		"echo \"$(case x in x) pig;; esac)\"",
		"p1; pig",
		"p1 && pig",
		"p1 | p2",
		"# \\\npig",
		"echo \\\\\npig",
		"p1 $\\\n(pig)",
		"echo \"$\\\n(pig)\"",
		"cat <<EO\\\nF\n$(pig)\nEOF",
		"env --default-signal pig",
		"env -S pig",
		"${UNSET:-pig}",
		"\"${UNSET:-pig}\"",
		"eval \"$X\"",
		"f() { pig; }; p1",
		"((pig))",
		"p1 <<EOF\n$\\\n(pig)\nEOF",
		"echo \"$(echo case in)\" >sink ; pig",
		"nice -n 1 pig",
		"p1 `pig`",
		"p1 `\\`pig\\``",
		"true; pig",
		"p1\npig",
		"cat <<\"\\$EOF\"\n$EOF\npig",
		// SF-1 grammar-aware templates
		"$\\\n{x:-pig}",
		"echo \\\n # \\\npig",
		"sh -c '$\\\n1' _ pig",
		"flock sink -c 'pig'",
		"trap 'pig' EXIT",
		"env -u CTXMODE_ROLE sh -c p1",
	}

	mismatches := 0
	bypasses := 0
	for i := 0; i < N; i++ {
		var code string
		if rng.Intn(2) == 0 {
			// Template with random byte inserts.
			base := templates[rng.Intn(len(templates))]
			b := []byte(base)
			inserts := 1 + rng.Intn(3)
			for k := 0; k < inserts; k++ {
				frag := frags[rng.Intn(len(frags))]
				pos := rng.Intn(len(b) + 1)
				nb := make([]byte, 0, len(b)+len(frag))
				nb = append(nb, b[:pos]...)
				nb = append(nb, frag...)
				nb = append(nb, b[pos:]...)
				b = nb
			}
			code = string(b)
		} else {
			// Byte-join 4..12 fragments; sometimes insert space/tab between.
			nTok := 4 + rng.Intn(9)
			parts := make([]string, 0, nTok*2)
			for k := 0; k < nTok; k++ {
				parts = append(parts, frags[rng.Intn(len(frags))])
				if rng.Intn(2) == 0 {
					if rng.Intn(2) == 0 {
						parts = append(parts, " ")
					} else {
						parts = append(parts, "\t")
					}
				}
			}
			code = strings.Join(parts, "")
		}

		// Guard first: if worker allows, dash must never execute pig/agy, and
		// static-leaf full argv must agree with Go AST. When parseReadonlyShellAST
		// allows, also require concrete static-leaf argv[0]+argv[1:] agreement.
		hit := guardShellSubagent(code)
		goArgvs, depthEx := collectGoCmdArgvs(code)
		roArgvs, roReject := parseReadonlyShellAST(code)
		names := namesFromGoArgvs(goArgvs)
		names = append(names, "p1", "p2", "pig", "agy", "cat", "env", "nice", "printargv")
		pathDir, outFile := setupPrinterPATH(t, names)
		_ = os.Remove(outFile)
		dashArgvs, _, _ := runDashCollectArgvs(t, code, pathDir, outFile)

		goExt := filterExternalArgvs(goArgvs)

		if hit == "" {
			var rawArgvs [][]string
			for _, s := range splitShellSegments(code) {
				if len(s.argv) > 0 {
					rawArgvs = append(rawArgvs, append([]string(nil), s.argv...))
				}
			}
			aliases := envArgv0Aliases(rawArgvs)
			for _, a := range dashArgvs {
				if len(a) == 0 {
					continue
				}
				if (a[0] == "pig" || a[0] == "agy") && !aliases[a[0]] {
					bypasses++
					if bypasses <= 5 {
						t.Fatalf("BYPASS FOUND: worker guard allowed script that executed %s in dash: %q", a[0], code)
					}
				}
			}
			miss := filterAliasMisses(dashExecutedUnknown(goExt, dashArgvs), aliases)
			if len(miss) > 0 && !depthEx {
				mismatches++
				if mismatches <= 10 {
					t.Logf("AST BLINDSPOT i=%d miss=%v code=%q", i, miss, code)
				}
			}
			// Concrete static-leaf full argv must agree with dash captures.
			if !depthEx {
				goLeaves := staticConcreteLeafArgvs(goExt)
				dashLeaves := staticLeafArgvs(dashArgvs)
				if !leafArgvDeepAgreeExt(goLeaves, dashLeaves, goExt) {
					mismatches++
					if mismatches <= 10 {
						t.Logf("LEAF ARGV MISMATCH i=%d code=%q goLeaves=%s dashLeaves=%s",
							i, code, fmtArgvs(goLeaves), fmtArgvs(dashLeaves))
					}
				}
			}
		}

		// Readonly AST allow path: concrete static-leaf full argv must agree with dash.
		if roReject == "" && !depthEx {
			roExt := filterExternalArgvs(roArgvs)
			roLeaves := staticConcreteLeafArgvs(roExt)
			dashLeaves := staticLeafArgvs(dashArgvs)
			if !leafArgvDeepAgreeExt(roLeaves, dashLeaves, roExt) {
				mismatches++
				if mismatches <= 10 {
					t.Logf("RO FULL ARGV MISMATCH i=%d code=%q roLeaves=%s dashLeaves=%s",
						i, code, fmtArgvs(roLeaves), fmtArgvs(dashLeaves))
				}
			}
		}
	}
	if bypasses > 0 {
		t.Fatalf("fuzz bypasses: %d / %d", bypasses, N)
	}
	if mismatches > 0 {
		t.Fatalf("fuzz AST blindspots: %d / %d (seed=%d race=%v)", mismatches, N, seed, raceEnabled)
	}
}

func TestAlFix7_CaptureBaselineMismatches(t *testing.T) {
	if os.Getenv("CTXMODE_ALFIX7_CAPTURE") != "1" {
		t.Skip("set CTXMODE_ALFIX7_CAPTURE=1 to write baseline mismatch report")
	}
	outPath := os.Getenv("CTXMODE_ALFIX7_CAPTURE_OUT")
	if outPath == "" {
		outPath = "/tmp/alfix7-baseline-mismatches.txt"
	}
	var all []dashDiffCase
	all = append(all, alfix7MustFixSamples()...)
	all = append(all, alfix7Audit3Diff32()...)
	all = append(all, alfix7ShouldFixSamples()...)
	all = append(all, alfix7ReportTableSamples()...)

	var report strings.Builder
	report.WriteString("alfix7 baseline dash/Go mismatches\n")
	report.WriteString("HEAD capture mode\n\n")

	nFail := 0
	for _, c := range all {
		goArgvs, depthEx := collectGoCmdArgvs(c.code)
		names := namesFromGoArgvs(goArgvs)
		for _, h := range []string{"rm", "pig", "python3", "echo", "true", "ls", "cat", "env", "sh", "bash", "nice", "rg"} {
			if strings.Contains(c.code, h) {
				names = append(names, h)
			}
		}
		pathDir, outFile := setupPrinterPATH(t, names)
		dashArgvs, raw, _ := runDashCollectArgvs(t, c.code, pathDir, outFile)
		goExt := filterExternalArgvs(goArgvs)
		miss := dashExecutedUnknown(goExt, dashArgvs)
		fail := false
		reason := ""
		if len(goExt) == 0 && len(dashArgvs) > 0 && !depthEx {
			fail = true
			reason = "Go0_dashN"
		} else if len(miss) > 0 && !depthEx {
			fail = true
			reason = "dash_unknown:" + strings.Join(miss, ",")
		} else if c.compareFull && !depthEx && !argvsEqual(goExt, dashArgvs) {
			fail = true
			reason = "argv_mismatch"
		} else if c.expectDashRuns && len(dashArgvs) == 0 {
			fail = true
			reason = "dash_no_run"
		}
		if fail {
			nFail++
			fmt.Fprintf(&report, "FAIL %s reason=%s\ncode=%q\ngo_segs=%d dash_segs=%d depthEx=%v\ngo:\n%sdash:\n%sraw=%q\n\n",
				c.name, reason, c.code, len(goArgvs), len(dashArgvs), depthEx, fmtArgvs(goArgvs), fmtArgvs(dashArgvs), raw)
		}
	}
	fmt.Fprintf(&report, "TOTAL_FAIL=%d TOTAL=%d\n", nFail, len(all))
	if err := os.WriteFile(outPath, []byte(report.String()), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("wrote %s fail=%d/%d", outPath, nFail, len(all))
}

// TestIsSafeRedirect_SF1 closes PLAN10 R10_SF1_01/02: comment quote-flip and
// dynamic redirect targets must never be fed to real /bin/sh.
func TestIsSafeRedirect_SF1(t *testing.T) {
	if isSafeRedirectForTestExec("# '\necho x > /pwn # '") {
		t.Fatalf("R10_SF1_01: comment quote-flip must be unsafe")
	}
	if isSafeRedirectForTestExec("echo x > ${UNSET:-/pwn}") {
		t.Fatalf("R10_SF1_02: dynamic redirect target must be unsafe")
	}
	if isSafeRedirectForTestExec("find . -delete") {
		t.Fatalf("find -delete must be unsafe")
	}
	if isSafeRedirectForTestExec("find . -fprint /tmp/x") {
		t.Fatalf("find -fprint must be unsafe")
	}
	if !isSafeRedirectForTestExec("echo x > sink") {
		t.Fatalf("relative sink redirect should be safe")
	}
	if !isSafeRedirectForTestExec("cat < /dev/null") {
		t.Fatalf("/dev/null redirect should be safe")
	}
}
