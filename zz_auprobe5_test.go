package main

import "testing"

func TestAUProbe5(t *testing.T) {
	cases := []auCase{
		{id: "R3c-strict-py-zipfile-w", role: "scout", lang: "python", cmd: "import zipfile\nzipfile.ZipFile('/tmp/x', 'w')\n"},
		{id: "R3c-strict-py-zipfile-mode-kw", role: "scout", lang: "python", cmd: "import zipfile\nzipfile.ZipFile('/tmp/x', mode='a')\n"},
		{id: "R3c-strict-py-zipfile-read", role: "scout", lang: "python", cmd: "import zipfile\nprint(zipfile.ZipFile('/tmp/x').namelist())\n"},
		{id: "R3c-strict-py-shelve", role: "scout", lang: "python", cmd: "import shelve\nshelve.open('/tmp/x')\n"},
		{id: "R3c-strict-py-dbm-c", role: "scout", lang: "python", cmd: "import dbm\ndbm.open('/tmp/x', 'c')\n"},
		{id: "R3c-strict-py-os-mkdir", role: "scout", lang: "python", cmd: "import os\nos.mkdir('/tmp/d')\n"},
		{id: "R3c-strict-py-os-makedirs", role: "scout", lang: "python", cmd: "import os\nos.makedirs('/tmp/d/e')\n"},
		{id: "R3c-strict-py-os-symlink", role: "scout", lang: "python", cmd: "import os\nos.symlink('/etc/hosts', '/tmp/l')\n"},
		{id: "R3c-strict-py-os-truncate", role: "scout", lang: "python", cmd: "import os\nos.truncate('/tmp/x', 0)\n"},
		{id: "R3c-strict-py-io-FileIO-w", role: "scout", lang: "python", cmd: "import io\nio.FileIO('/tmp/x', 'w')\n"},
		{id: "R3c-strict-py-codecs-open-w", role: "scout", lang: "python", cmd: "import codecs\ncodecs.open('/tmp/x', 'w')\n"},
		{id: "R3c-strict-py-gzip-open-wb", role: "scout", lang: "python", cmd: "import gzip\ngzip.open('/tmp/x.gz', 'wb')\n"},
		{id: "R3c-strict-py-tempfile-mkstemp", role: "scout", lang: "python", cmd: "import tempfile\ntempfile.mkstemp()\n"},
		{id: "R3c-strict-py-logging-FileHandler", role: "scout", lang: "python", cmd: "import logging\nlogging.FileHandler('/tmp/x.log')\n"},
		{id: "R3c-strict-py-os-open-wronly", role: "scout", lang: "python", cmd: "import os\nos.open('/tmp/x', os.O_WRONLY | os.O_CREAT)\n"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) { auPrint(c.id, c.role, auGuard(t, c)) })
	}
}
