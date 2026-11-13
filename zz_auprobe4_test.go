package main

import "testing"

func TestAUProbe4(t *testing.T) {
	cases := []auCase{
		{id: "R3b-js-fork-execPath-pig", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.fork('/tmp/x.js', [], {execPath: '/usr/local/bin/pig'})"},
		{id: "R3b-js-spawnSync-shell-pig", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.spawnSync('ls', [], {shell: '/usr/local/bin/pig'})"},
		{id: "R3b-js-execSync-shell-pig", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.execSync('ls', {shell: '/usr/local/bin/pig'})"},
		{id: "R3b-js-execFileSync-shell-pig", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.execFileSync('ls', [], {shell: 'pig'})"},
		{id: "R3b-js-direct-require-execSync-shell", role: "worker", lang: "javascript", cmd: "require('child_process').execSync('ls', {shell: '/usr/local/bin/pig'})"},
		{id: "R3b-js-node-e-fork-execPath", role: "worker", argv: []string{"node", "-e", "require('child_process').fork('/tmp/x.js', [], {execPath: '/usr/local/bin/pig'})"}},
		{id: "R3b-js-shell-node-e-execSync-shell", role: "worker", cmd: "node -e \"require('child_process').execSync('ls', {shell: '/usr/local/bin/pig'})\""},
		{id: "R3b-py-run-executable-pig", role: "worker", lang: "python", cmd: "import subprocess\nsubprocess.run(['ls'], executable='/usr/local/bin/pig')\n"},
		{id: "R3b-py-run-shell-executable-pig", role: "worker", lang: "python", cmd: "import subprocess\nsubprocess.run('ls', shell=True, executable='/usr/local/bin/pig')\n"},
		{id: "R3b-py-popen-executable-pig", role: "worker", lang: "python", cmd: "import subprocess\nsubprocess.Popen(['ls'], executable='pig')\n"},
		{id: "R3b-py-execv-pig", role: "worker", lang: "python", cmd: "import os\nos.execv('/usr/local/bin/pig', ['ls'])\n"},
		{id: "R3b-py-posix-spawn-pig", role: "worker", lang: "python", cmd: "import os\nos.posix_spawn('/usr/local/bin/pig', ['ls'], {})\n"},
		{id: "R3b-M-js-execSync-ls", role: "worker", lang: "javascript", cmd: "const cp = require('child_process'); cp.execSync('ls', {cwd: '/tmp'})"},
		{id: "R3b-M-py-run-ls", role: "worker", lang: "python", cmd: "import subprocess\nsubprocess.run(['ls'], cwd='/tmp')\n"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) { auPrint(c.id, c.role, auGuard(t, c)) })
	}
}
