package main

import "testing"

func TestAUProbe6(t *testing.T) {
	z := "import zipfile\nzipfile.ZipFile('/tmp/x', 'w').writestr('a', 'pwn')\n"
	l := "import logging\nlogging.FileHandler('/tmp/x.log')\n"
	f := "import io\nio.FileIO('/tmp/x', 'w').write(b'pwn')\n"
	cases := []auCase{
		{id: "R3d-scout-py-heredoc-zip", role: "scout", cmd: "python3 - <<'EOF'\n" + z + "EOF"},
		{id: "R3d-scout-argv-py-stdin-zip", role: "scout", argv: []string{"python3", "-"}, stdin: z},
		{id: "R3d-scout-py-c-zip", role: "scout", cmd: "python3 -c \"import zipfile; zipfile.ZipFile('/tmp/x', 'w')\""},
		{id: "R3d-reviewer-py-heredoc-zip", role: "reviewer", cmd: "python3 - <<'EOF'\n" + z + "EOF"},
		{id: "R3d-ro-worker-py-heredoc-zip", role: "worker", ro: "1", cmd: "python3 - <<'EOF'\n" + z + "EOF"},
		{id: "R3d-ro-worker-py-heredoc-read", role: "worker", ro: "1", cmd: "python3 - <<'EOF'\nprint(open('/etc/hosts').read())\nEOF"},
		{id: "R3d-ro-worker-argv-py-zip", role: "worker", ro: "1", argv: []string{"python3", "-"}, stdin: z},
		{id: "R3d-ro-worker-argv-py-logging", role: "worker", ro: "1", argv: []string{"python3", "-"}, stdin: l},
		{id: "R3d-ro-worker-argv-py-fileio", role: "worker", ro: "1", argv: []string{"python3", "-"}, stdin: f},
		{id: "R3d-ro-worker-argv-py-c-zip", role: "worker", ro: "1", argv: []string{"python3", "-c", z}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) { auPrint(c.id, c.role, auGuard(t, c)) })
	}
}
