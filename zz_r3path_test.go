package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writePwnTool(t *testing.T, path, tag string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	body := "#!/bin/sh\necho PWNED-" + tag + "\n"
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func writeBenign(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho BENIGN\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}

// tmpScratchDir explicitly allocates a small directory under /tmp regardless
// of TMPDIR so C10 isTmpOrScratchPath tests behave identically when TMPDIR
// points to a disk directory.
func tmpScratchDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "ctxmode-w5-")
	if err != nil {
		return t.TempDir()
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// nonTmpWS creates a temporary workspace outside /tmp|/var/tmp|/dev/shm|/run
// without requiring root or /opt write access (uses ~/.cache or parent of cwd).
func nonTmpWS(t *testing.T) string {
	t.Helper()
	var candidates []string
	if h, err := os.UserHomeDir(); err == nil && h != "" && !isTmpOrScratchPath(h) {
		candidates = append(candidates, filepath.Join(h, ".cache", "ctxmode-r3-repro"))
	}
	if wd, err := os.Getwd(); err == nil && wd != "" && !isTmpOrScratchPath(wd) {
		candidates = append(candidates, filepath.Join(filepath.Dir(wd), ".ctxmode-r3-repro"))
	}
	for _, root := range candidates {
		if err := os.MkdirAll(root, 0755); err != nil {
			continue
		}
		ws, err := os.MkdirTemp(root, "ws-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(ws) })
		return ws
	}
	t.Skip("no writable non-/tmp workspace directory available for current user")
	return ""
}

func relVenvLink(t *testing.T, ws, linkName, target string) {
	t.Helper()
	bin := filepath.Join(ws, ".venv", "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(bin, 0755)
	link := filepath.Join(bin, linkName)
	_ = os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func guardWorker(t *testing.T, cwd, cmd string) string {
	t.Helper()
	if cwd != "" {
		defer withScreenCwd(cwd)()
	}
	return rtGuard(t, rtCase{id: t.Name(), role: "worker", cmd: cmd})
}

func TestR3_RelativePATH_SymlinkToTmp(t *testing.T) {
	scratch := tmpScratchDir(t)
	samePytest := filepath.Join(scratch, "pytest")
	writePwnTool(t, samePytest, "pytest-same")
	tmpRuff := filepath.Join(scratch, "ruff")
	writePwnTool(t, tmpRuff, "ruff-cross")
	evil := filepath.Join(scratch, "evil")
	writePwnTool(t, evil, "evil")
	samePy := filepath.Join(scratch, "python3")
	writePwnTool(t, samePy, "python3-same")
	usrPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("lookpath python3: %v", err)
	}
	usrSu, _ := exec.LookPath("su")

	type tc struct {
		id, wsKind, linkName, target, cmd string
		wantAllow                         bool
		note                              string
	}
	cases := []tc{
		{id: "W5-same-pytest-nontmp", wsKind: "nontmp", linkName: "pytest", target: samePytest,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "same-name .venv/bin/pytest -> /tmp/pytest, non-/tmp cwd"},
		{id: "W5-same-pytest-intmp", wsKind: "intmp", linkName: "pytest", target: samePytest,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "same-name, workspace itself under /tmp"},
		{id: "W5-cross-pytest-to-tmpruff-nontmp", wsKind: "nontmp", linkName: "pytest", target: tmpRuff,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "cross-name .venv/bin/pytest -> /tmp/ruff (ruff in toolchainRelPathHeads)"},
		{id: "W5-pytest-to-evil-nontmp", wsKind: "nontmp", linkName: "pytest", target: evil,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "pytest -> /tmp/evil"},
		{id: "W5-python3-to-evil-nontmp", wsKind: "nontmp", linkName: "python3", target: evil,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'print(1)'`, wantAllow: false,
			note: "structural head python3 -> /tmp/evil"},
		{id: "W5-python3-to-tmppython-nontmp", wsKind: "nontmp", linkName: "python3", target: samePy,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'print(1)'`, wantAllow: false,
			note: "structural head python3 -> /tmp/python3"},
		{id: "W5-abs-same-pytest-nontmp", wsKind: "nontmp", linkName: "pytest", target: samePytest,
			cmd: `PATH="$PWD/.venv/bin:$PATH" pytest`, wantAllow: false,
			note: "dynamic $PWD in PATH"},
		{id: "W5-abs-literal-same-pytest-nontmp", wsKind: "nontmp-litabs", linkName: "pytest", target: samePytest,
			cmd: "PLACEHOLDER", wantAllow: false,
			note: "literal abs PATH .venv/bin -> /tmp/pytest"},
		{id: "W5-bin-rel-pytest-nontmp", wsKind: "nontmp-bin", linkName: "pytest", target: samePytest,
			cmd: `PATH="bin:$PATH" pytest`, wantAllow: false,
			note: "PATH=bin:$PATH rejected by pathIsUnsafeForSubagent"},
		{id: "M-rel-venv-pytest-file-nontmp", wsKind: "nontmp-file", linkName: "pytest", target: "",
			cmd: `PATH=".venv/bin:$PATH" pytest -q`, wantAllow: true,
			note: "regular file .venv/bin/pytest"},
		{id: "M-rel-nodemod-tsc-nontmp", wsKind: "nontmp-nm", linkName: "tsc", target: "",
			cmd: `PATH="node_modules/.bin:$PATH" tsc --noEmit`, wantAllow: true,
			note: "regular file node_modules/.bin/tsc"},
		{id: "M-rel-monorepo-hoisted-tsc", wsKind: "monorepo-hoisted", linkName: "tsc", target: "",
			cmd: `PATH="node_modules/.bin:$PATH" tsc --noEmit`, wantAllow: true,
			note: "monorepo subpackage node_modules/.bin/tsc -> ../../node_modules/typescript/bin/tsc"},
		{id: "M-rel-monorepo-pnpm-tsc", wsKind: "monorepo-pnpm", linkName: "tsc", target: "",
			cmd: `PATH="node_modules/.bin:$PATH" tsc --noEmit`, wantAllow: true,
			note: "pnpm workspace subpackage node_modules/.bin/tsc -> ../../node_modules/.pnpm/.../tsc"},
		{id: "M-rel-venv-python3-sys-nontmp", wsKind: "nontmp", linkName: "python3", target: usrPython,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'import sys; print(sys.version)'`, wantAllow: true,
			note: "normal venv: .venv/bin/python3 -> system python3"},
		{id: "M-rel-venv-python3-sys-intmp", wsKind: "intmp", linkName: "python3", target: usrPython,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'import sys; print(sys.version)'`, wantAllow: true,
			note: "normal venv under /tmp workspace"},
	}
	if usrSu != "" {
		cases = append(cases, tc{
			id: "A8-python3-to-su-nontmp", wsKind: "nontmp", linkName: "python3", target: usrSu,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'unset CTXMODE_ROLE; pig'`, wantAllow: false,
			note: ".venv/bin/python3 -> /bin/su must block before unwrapInterpreterInline",
		})
	}

	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			var ws string
			switch c.wsKind {
			case "nontmp", "nontmp-bin", "nontmp-file", "nontmp-nm", "nontmp-litabs",
				"monorepo-hoisted", "monorepo-pnpm":
				ws = nonTmpWS(t)
			default:
				ws = tmpScratchDir(t)
			}
			cwd := ws
			switch c.wsKind {
			case "nontmp-bin":
				bin := filepath.Join(ws, "bin")
				if err := os.MkdirAll(bin, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(c.target, filepath.Join(bin, c.linkName)); err != nil {
					t.Fatal(err)
				}
			case "nontmp-file":
				writeBenign(t, filepath.Join(ws, ".venv", "bin", c.linkName))
			case "nontmp-nm":
				writeBenign(t, filepath.Join(ws, "node_modules", ".bin", c.linkName))
			case "monorepo-hoisted":
				realBin := filepath.Join(ws, "node_modules", "typescript", "bin", "tsc")
				writeBenign(t, realBin)
				subPkg := filepath.Join(ws, "packages", "app")
				nmBin := filepath.Join(subPkg, "node_modules", ".bin")
				if err := os.MkdirAll(nmBin, 0775); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(realBin, filepath.Join(nmBin, "tsc")); err != nil {
					t.Fatal(err)
				}
				cwd = subPkg
			case "monorepo-pnpm":
				realBin := filepath.Join(ws, "node_modules", ".pnpm", "typescript@5.6.3", "node_modules", "typescript", "bin", "tsc")
				writeBenign(t, realBin)
				subPkg := filepath.Join(ws, "packages", "app")
				nmBin := filepath.Join(subPkg, "node_modules", ".bin")
				if err := os.MkdirAll(nmBin, 0775); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(realBin, filepath.Join(nmBin, "tsc")); err != nil {
					t.Fatal(err)
				}
				cwd = subPkg
			default:
				relVenvLink(t, ws, c.linkName, c.target)
			}
			cmd := c.cmd
			if c.wsKind == "nontmp-litabs" {
				cmd = "PATH=\"" + filepath.Join(ws, ".venv", "bin") + ":$PATH\" pytest"
			}
			got := guardWorker(t, cwd, cmd)
			allow := strings.HasPrefix(got, "ALLOW")
			if allow != c.wantAllow {
				t.Errorf("%s: got %s, wantAllow=%v (%s)", c.id, got, c.wantAllow, c.note)
			}
		})
	}
}

func TestR3_hcSendAddrAndCtrl(t *testing.T) {
	for _, s := range []string{"t1", "t42", "t0", "test", "tmux", "tab"} {
		if !hcSendAddrOK(s) {
			t.Errorf("hcSendAddrOK(%q)=false, want true", s)
		}
	}
	for _, s := range []string{"main", "editor", "machine/t7", "T1", "t-1", "1t", ""} {
		if hcSendAddrOK(s) {
			t.Errorf("hcSendAddrOK(%q)=true, want false", s)
		}
	}
	cases := []rtCase{
		{id: "A4-ctrl-x03-argv", role: "scout", argv: []string{"hc", "send", "t1", "\x03touch /tmp/x\r"}, wantAllow: false},
		{id: "A4-ctrl-esc-argv", role: "scout", argv: []string{"hc", "send", "t1", "\x1b[Ahello"}, wantAllow: false},
		{id: "A4-ansic-ctrl-shell", role: "scout", cmd: "hc send t1 $'\\x03touch /tmp/x\\r'", wantAllow: false},
		{id: "A4-ansic-ctrl-bash", role: "worker", cmd: "bash -c \"hc send t1 $'\\x03touch /tmp/x\\r'\"", wantAllow: false},
		// shell_ast.go encodes ANSI-C $'...' as dynamic placeholder __ctx_dq_sub__, so it fails closed;
		// ordinary single-quoted and double-quoted multiline literals stay allowed.
		{id: "A4-ansic-placeholder-bash", role: "worker", cmd: "bash -c \"hc send t1 $'line1\\nline2'\"", wantAllow: false},
		{id: "A4-newline-shell", role: "scout", cmd: "hc send t1 'line1\nline2'", wantAllow: true},
		{id: "A4-newline-dq-shell", role: "scout", cmd: "hc send t1 \"line1\nline2\"", wantAllow: true},
		{id: "A4-named-test", role: "scout", cmd: "hc send test hello", wantAllow: true},
		{id: "A4-named-tmux", role: "scout", cmd: "hc send tmux hello", wantAllow: true},
		{id: "A4-plain-t1", role: "scout", cmd: "hc send t1 'done: report ready'", wantAllow: true},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			got := rtGuard(t, c)
			allow := strings.HasPrefix(got, "ALLOW")
			if allow != c.wantAllow {
				t.Errorf("%s: got %s, wantAllow=%v", c.id, got, c.wantAllow)
			}
		})
	}
}
