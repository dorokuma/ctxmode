package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// nonTmpWS is a workspace outside /tmp /var/tmp /dev/shm /run, as Gemini
// requested for the relative-PATH repro (t.TempDir lives under /tmp).
func nonTmpWS(t *testing.T) string {
	t.Helper()
	root := "/opt/ctxmode-r3-repro"
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", root, err)
	}
	ws, err := os.MkdirTemp(root, "ws-")
	if err != nil {
		t.Fatalf("mktemp in %s: %v", root, err)
	}
	t.Cleanup(func() { os.RemoveAll(ws) })
	return ws
}

func relVenvLink(t *testing.T, ws, linkName, target string) {
	t.Helper()
	bin := filepath.Join(ws, ".venv", "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, linkName)
	os.Remove(link)
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
	// Shared scratch targets (always under /tmp).
	scratch := t.TempDir()
	samePytest := filepath.Join(scratch, "pytest")
	writePwnTool(t, samePytest, "pytest-same")
	evil := filepath.Join(scratch, "evil")
	writePwnTool(t, evil, "evil")
	samePy := filepath.Join(scratch, "python3")
	writePwnTool(t, samePy, "python3-same")
	usrPython, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("lookpath python3: %v", err)
	}

	type tc struct {
		id, wsKind, linkName, target, cmd string
		wantAllow                         bool
		note                              string
	}
	cases := []tc{
		// Gemini's core claim: same-name symlink into /tmp + relative PATH.
		// rt1111 裁决：这些用例在基线 ALLOW（洞），修复后必须 BLOCK
		// untrusted path binary — wantAllow 已按修复目标改为 false。
		{id: "W5-same-pytest-nontmp", wsKind: "nontmp", linkName: "pytest", target: samePytest,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "same-name .venv/bin/pytest -> /tmp/pytest, non-/tmp cwd"},
		{id: "W5-same-pytest-intmp", wsKind: "intmp", linkName: "pytest", target: samePytest,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "same-name, workspace itself under /tmp (t.TempDir)"},
		// Audit's original case: name changes to evil, pathIsUnsafeForSubagent trips.
		{id: "W5-pytest-to-evil-nontmp", wsKind: "nontmp", linkName: "pytest", target: evil,
			cmd: `PATH=".venv/bin:$PATH" pytest`, wantAllow: false,
			note: "pytest -> /tmp/evil (name change); audit A9a saw BLOCK env PATH"},
		// Structural head keeps typed base, so python3 -> /tmp/evil still relOK.
		{id: "W5-python3-to-evil-nontmp", wsKind: "nontmp", linkName: "python3", target: evil,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'print(1)'`, wantAllow: false,
			note: "structural head python3 -> /tmp/evil, base stays python3"},
		{id: "W5-python3-to-tmppython-nontmp", wsKind: "nontmp", linkName: "python3", target: samePy,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'print(1)'`, wantAllow: false,
			note: "structural head python3 -> /tmp/python3 (same name)"},
		// Absolute PATH should still hit C10 (dot=false).
		{id: "W5-abs-same-pytest-nontmp", wsKind: "nontmp", linkName: "pytest", target: samePytest,
			cmd: `PATH="$PWD/.venv/bin:$PATH" pytest`, wantAllow: false,
			note: "PATH uses $PWD (dynamic) — expect BLOCK env PATH, not necessarily C10"},
		{id: "W5-abs-literal-same-pytest-nontmp", wsKind: "nontmp-litabs", linkName: "pytest", target: samePytest,
			cmd: "PLACEHOLDER", wantAllow: false,
			note: "literal abs PATH .venv/bin -> /tmp/pytest; C10 untrusted path binary"},
		// Oversimplified PATH=bin:$PATH is already rejected by pathIsUnsafeForSubagent.
		{id: "W5-bin-rel-pytest-nontmp", wsKind: "nontmp-bin", linkName: "pytest", target: samePytest,
			cmd: `PATH="bin:$PATH" pytest`, wantAllow: false,
			note: "PATH=bin:$PATH is not in the rel-allow list; expect BLOCK env PATH"},
		// Must-allow: normal relative prepend, no escape.
		{id: "M-rel-venv-pytest-file-nontmp", wsKind: "nontmp-file", linkName: "pytest", target: "",
			cmd: `PATH=".venv/bin:$PATH" pytest -q`, wantAllow: true,
			note: "regular file .venv/bin/pytest (must-allow)"},
		{id: "M-rel-nodemod-tsc-nontmp", wsKind: "nontmp-nm", linkName: "tsc", target: "",
			cmd: `PATH="node_modules/.bin:$PATH" tsc --noEmit`, wantAllow: true,
			note: "regular file node_modules/.bin/tsc (must-allow R11_ALW_11)"},
		{id: "M-rel-venv-python3-sys-nontmp", wsKind: "nontmp", linkName: "python3", target: usrPython,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'import sys; print(sys.version)'`, wantAllow: true,
			note: "normal venv: .venv/bin/python3 -> system python3 (must-allow)"},
		{id: "M-rel-venv-python3-sys-intmp", wsKind: "intmp", linkName: "python3", target: usrPython,
			cmd: `PATH=".venv/bin:$PATH" python3 -c 'import sys; print(sys.version)'`, wantAllow: true,
			note: "same must-allow with workspace under /tmp"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			var ws string
			switch c.wsKind {
			case "nontmp", "nontmp-bin", "nontmp-file", "nontmp-nm", "nontmp-litabs":
				ws = nonTmpWS(t)
			default:
				ws = t.TempDir()
			}
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
			default:
				relVenvLink(t, ws, c.linkName, c.target)
			}
			cmd := c.cmd
			if c.wsKind == "nontmp-litabs" {
				cmd = "PATH=\"" + filepath.Join(ws, ".venv", "bin") + ":$PATH\" pytest"
			}
			got := guardWorker(t, ws, cmd)
			allow := len(got) >= 5 && got[:5] == "ALLOW"
			fmt.Printf("R3PATH\t%s\t%s\tws=%s\tcmd=%s\tlink=%s->%s\t%s\n", c.id, got, ws, cmd, c.linkName, c.target, c.note)
			if allow != c.wantAllow {
				t.Errorf("%s: got %s, wantAllow=%v (%s)", c.id, got, c.wantAllow, c.note)
			}
		})
	}
}

func TestR3_hcSendAddrAndCtrl(t *testing.T) {
	// Comment at role_guards.go:1927-1929 documents ^t[0-9a-z]+$, not "no names".
	for _, s := range []string{"t1", "t42", "t0", "test", "tmux", "tab"} {
		if !hcSendAddrOK(s) {
			t.Errorf("hcSendAddrOK(%q)=false, want true (matches ^t[0-9a-z]+$)", s)
		} else {
			fmt.Printf("R3HC\thcSendAddrOK(%q)=true\n", s)
		}
	}
	for _, s := range []string{"main", "editor", "machine/t7", "T1", "t-1", "1t", ""} {
		if hcSendAddrOK(s) {
			t.Errorf("hcSendAddrOK(%q)=true, want false", s)
		} else {
			fmt.Printf("R3HC\thcSendAddrOK(%q)=false\n", s)
		}
	}
	cases := []rtCase{
		{id: "A4-ctrl-x03-argv", role: "scout", argv: []string{"hc", "send", "t1", "\x03touch /tmp/x\r"}},
		{id: "A4-ctrl-esc-argv", role: "scout", argv: []string{"hc", "send", "t1", "\x1b[Ahello"}},
		{id: "A4-newline-shell", role: "scout", cmd: "hc send t1 'line1\nline2'"},
		{id: "A4-named-test", role: "scout", cmd: "hc send test hello"},
		{id: "A4-named-tmux", role: "scout", cmd: "hc send tmux hello"},
		{id: "A4-plain-t1", role: "scout", cmd: "hc send t1 'done: report ready'"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			got := rtGuard(t, c)
			fmt.Printf("R3HC\t%s\t%s\n", c.id, got)
		})
	}
}
