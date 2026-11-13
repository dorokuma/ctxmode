package main

// R3 audit probe (not for commit).

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAUProbe3(t *testing.T) {
	cases := []auCase{
		// (4) npx --userconfig
		{id: "R3-npx-uc-tilde", role: "worker", cmd: "npx --userconfig ~/.npmrc tsc --noEmit"},
		{id: "R3-npx-uc-home-dq-glued", role: "worker", cmd: "npx --userconfig=\"$HOME/.npmrc\" tsc --noEmit"},
		{id: "R3-npx-uc-tmp", role: "worker", cmd: "npx --userconfig /tmp/evil.npmrc tsc --noEmit"},
		{id: "R3-npx-uc-tilde-dotdot-tmp", role: "worker", cmd: "npx --userconfig ~/../../tmp/evil.npmrc tsc --noEmit"},
		{id: "R3-npx-uc-home-dotdot-tmp", role: "worker", cmd: "npx --userconfig \"$HOME/../../tmp/evil.npmrc\" tsc --noEmit"},
		{id: "R3-npx-uc-rel-dotdot-tmp", role: "worker", cmd: "npx --userconfig ../../../../../../tmp/evil.npmrc tsc --noEmit"},
		{id: "R3-npx-uc-devshm", role: "worker", cmd: "npx --userconfig /dev/shm/evil.npmrc tsc --noEmit"},
		{id: "R3-npx-uc-tilde-user", role: "worker", cmd: "npx --userconfig ~nobody/.npmrc tsc --noEmit"},
		{id: "R3-npx-uc-tilde-glob", role: "worker", cmd: "npx --userconfig ~/*.npmrc tsc --noEmit"},
		{id: "R3-npx-uc-tilde-cmdsub", role: "worker", cmd: "npx --userconfig ~/$(echo x) tsc --noEmit"},
		{id: "R3-npx-uc-tilde-then-pig", role: "worker", cmd: "npx --userconfig ~/.npmrc pig"},
		{id: "R3-npx-uc-tilde-then-c", role: "worker", cmd: "npx --userconfig ~/.npmrc -c pig"},
		{id: "R3-npx-uc-var-split", role: "worker", cmd: "u='x pig'; npx --userconfig $u tsc"},
		{id: "R3-npx-prefix-tilde", role: "worker", cmd: "npx --prefix ~/proj tsc --noEmit"},
		{id: "R3-npx-registry-dq", role: "worker", cmd: "npx --registry \"$REG\" tsc --noEmit"},
		{id: "R3-npx-yes-glued-dyn", role: "worker", cmd: "npx --yes=$(echo x) tsc"},
		{id: "R3-npx-dyn-name", role: "worker", cmd: "npx --$(echo call)=pig tsc"},
		{id: "R3-npx-p-tilde", role: "worker", cmd: "npx -p ~/pkg tsc"},
		{id: "R3-bunx-bun-glued", role: "worker", cmd: "bunx --bun=$(echo x) vitest"},
		{id: "R3-M-npx-tsc", role: "worker", cmd: "npx tsc --noEmit"},
		{id: "R3-M-npx-y-p", role: "worker", cmd: "npx -y -p typescript tsc --noEmit"},
		// (1) cp.fork
		{id: "R3-fork-x-worker", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.fork('/tmp/x.js')"},
		{id: "R3-fork-pig-worker", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.fork('/tmp/pig')"},
		{id: "R3-fork-dyn-worker", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); const p = process.argv[2]; cp.fork(p)"},
		{id: "R3-fork-dyn-pigstr-worker", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); const p = '/usr/local/bin/' + 'pig'; cp.fork(p)"},
		{id: "R3-fork-execpath-pig-worker", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.fork('/tmp/x.js', [], {execPath: '/usr/local/bin/pig'})"},
		{id: "R3-fork-strict", role: "scout", lang: "javascript", cmd: "const cp = require('child_process'); cp.fork('/tmp/x.js')"},
		{id: "R3-node-file-worker", role: "worker", cmd: "node /tmp/x.js"},
		{id: "R3-execfile-x-worker", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.execFileSync('/tmp/x.sh')"},
		// (2)(3) verifier local writes
		{id: "R3-verifier-touch", role: "verifier", cmd: "touch ./x"},
		{id: "R3-verifier-redirect", role: "verifier", cmd: "echo hi > ./x"},
		{id: "R3-verifier-rm", role: "verifier", cmd: "rm -rf ./build"},
		{id: "R3-verifier-gotest", role: "verifier", cmd: "go test ./..."},
		{id: "R3-verifier-ctxindex", role: "verifier", cmd: "ctxmode index ."},
		{id: "R3-reviewer-touch", role: "reviewer", cmd: "touch ./x"},
		{id: "R3-scout-touch", role: "scout", cmd: "touch ./x"},
		// (5)(6) code guard direct
		{id: "R3-strict-py-open-kwarg", role: "scout", lang: "python", cmd: "dict(open=True)\nprint('open(\"/tmp/x\",\"w\")')\n"},
		{id: "R3-strict-js-string-cp", role: "scout", lang: "javascript", cmd: "console.log('see child_process docs')"},
		{id: "R3-strict-py-zipfile", role: "scout", lang: "python", cmd: "import zipfile\nzipfile.ZipFile('/tmp/x', 'w')\n"},
		{id: "R3-strict-py-tarfile", role: "scout", lang: "python", cmd: "import tarfile\ntarfile.open('/tmp/x.tar', 'w')\n"},
		{id: "R3-strict-py-pathlib", role: "scout", lang: "python", cmd: "import pathlib\npathlib.Path('/tmp/x').write_text('pwn')\n"},
		{id: "R3-strict-py-shutil", role: "scout", lang: "python", cmd: "import shutil\nshutil.copy('/etc/hosts', '/tmp/x')\n"},
		{id: "R3-strict-py-sqlite", role: "scout", lang: "python", cmd: "import sqlite3\nsqlite3.connect('/tmp/x.db').execute('create table t(a)')\n"},
		// reachable path: ssh heredoc for scout (remote write)
		{id: "R3-ssh-py-zipfile-scout", role: "scout", cmd: "ssh dmit 'python3 -' <<'EOF'\nimport zipfile\nzipfile.ZipFile('/tmp/x', 'w')\nEOF"},
		{id: "R3-ssh-py-pathlib-scout", role: "scout", cmd: "ssh dmit 'python3 -' <<'EOF'\nimport pathlib\npathlib.Path('/tmp/x').write_text('pwn')\nEOF"},
		{id: "R3-ssh-py-read-scout", role: "scout", cmd: "ssh dmit 'python3 -' <<'EOF'\nprint(open('/etc/hosts').read())\nEOF"},
		// (8) hc send ANSI-C
		{id: "R3-hc-ansic-nl-scout", role: "scout", cmd: "hc send t1 $'line1\\nline2'"},
		{id: "R3-hc-ansic-nl-bashc-worker", role: "worker", cmd: "bash -c \"hc send t1 $'line1\\nline2'\""},
		{id: "R3-hc-ansic-ctrl-scout", role: "scout", cmd: "hc send t1 $'\\x03touch /tmp/x\\r'"},
		{id: "R3-hc-sq-nl-scout", role: "scout", cmd: "hc send t1 'line1\nline2'"},
		{id: "R3-hc-dq-nl-scout", role: "scout", cmd: "hc send t1 \"line1\nline2\""},
		{id: "R3-hc-dq-nl-worker", role: "worker", cmd: "hc send t1 \"line1\nline2\""},
		{id: "R3-hc-sq-nl-bashc-worker", role: "worker", cmd: "bash -c \"hc send t1 'line1\nline2'\""},
		// (7) scout inline PATH
		{id: "R3-scout-inline-path-ls", role: "scout", cmd: "PATH=\"$HOME/.local/share/mise/installs/node/22/bin:$HOME/.local/share/pnpm:$PATH\" ls"},
		{id: "R3-scout-inline-lang-ls", role: "scout", cmd: "LANG=C ls"},
		{id: "R3-scout-plain-ls", role: "scout", cmd: "ls -la"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			auPrint(c.id, c.role, auGuard(t, c))
		})
	}
	// (7) inherited PATH for scout
	run := func(id, role, cmd string, prep func(t *testing.T)) {
		t.Run(id, func(t *testing.T) {
			prep(t)
			auPrint(id, role, auGuard(t, auCase{id: id, role: role, cmd: cmd}))
		})
	}
	run("R3-scout-inh-mise-rg", "scout", "rg -n foo .", func(t *testing.T) {
		h := withTestTrustedHome(t)
		d := filepath.Join(h, ".local/share/mise/installs/ripgrep/14/bin")
		_ = os.MkdirAll(d, 0755)
		writeTestExecutable(t, filepath.Join(d, "rg"), 0755)
		t.Setenv("PATH", d+":"+os.Getenv("PATH"))
	})
	run("R3-scout-inh-mise-rg-to-sh", "scout", "rg -c pig", func(t *testing.T) {
		h := withTestTrustedHome(t)
		d := filepath.Join(h, ".local/share/mise/installs/ripgrep/14/bin")
		_ = os.MkdirAll(d, 0755)
		_ = os.Symlink("/bin/sh", filepath.Join(d, "rg"))
		t.Setenv("PATH", d+":"+os.Getenv("PATH"))
	})
	run("R3-scout-inh-tmp-rg", "scout", "rg -n foo .", func(t *testing.T) {
		d, _ := os.MkdirTemp("/tmp", "aurg-")
		t.Cleanup(func() { os.RemoveAll(d) })
		writeTestExecutable(t, filepath.Join(d, "rg"), 0755)
		t.Setenv("PATH", d+":"+os.Getenv("PATH"))
	})
}
