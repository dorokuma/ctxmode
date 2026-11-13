package main

// R6 audit adversarial probe (not for commit).

import (
	"fmt"
	"testing"
)

type r6adv struct {
	id   string
	want string
	code string
}

var r6advCases = []r6adv{
	// ---- alias forms: must BLOCK ----
	{"AL-from-F", "B", "from logging import FileHandler as F\nF('/tmp/x.log')\n"},
	{"AL-paren-R", "B", "from logging.handlers import (\n  RotatingFileHandler as R,\n)\nR('/tmp/x.log')\n"},
	{"AL-zip-Z", "B", "from zipfile import ZipFile as Z\nZ('/tmp/x.zip', 'w').writestr('a', 'b')\n"},
	{"AL-fileio", "B", "from io import FileIO as F\nF('/tmp/x', 'w').write(b'x')\n"},
	{"AL-pyzip", "B", "from zipfile import PyZipFile as P\nP('/tmp/x.zip', 'w')\n"},
	{"AL-multi-second", "B", "from logging.handlers import RotatingFileHandler as R, WatchedFileHandler as W\nW('a.log')\n"},
	{"AL-double-as", "B", "from zipfile import ZipFile as Z, ZipFile as Y\nY('a.zip', 'w')\n"},
	{"AL-chain-assign", "B", "from zipfile import ZipFile as Z\nZ2 = Z\nZ2('a.zip', 'w')\n"},
	{"AL-semi", "B", "from zipfile import ZipFile as Z; Z('a.zip', 'w')\n"},
	{"AL-bs-before-as", "B", "from zipfile import ZipFile \\\n    as Z\nZ('a.zip', 'w')\n"},
	{"AL-bs-after-as", "B", "from zipfile import ZipFile as \\\n    Z\nZ('a.zip', 'w')\n"},
	{"AL-paren-nl-before-as", "B", "from zipfile import (\n    ZipFile\n    as Z,\n)\nZ('a.zip', 'w')\n"},
	{"AL-paren-comment-before-as", "B", "from zipfile import (ZipFile  # c\n    as Z)\nZ('a.zip', 'w')\n"},
	{"AL-paren-nl-after-as", "B", "from zipfile import (ZipFile as\n    Z)\nZ('a.zip', 'w')\n"},
	{"AL-crlf", "B", "from zipfile import ZipFile as Z\r\nZ('a.zip', 'w')\r\n"},
	{"AL-tabs", "B", "from zipfile import ZipFile\tas\tZ\nZ('a.zip', 'w')\n"},
	{"AL-nested-def", "B", "def f():\n    from zipfile import ZipFile as Z\n    return Z('a.zip', 'w')\nf()\n"},
	{"AL-use-before-import", "B", "def p():\n    return Z('a.zip', 'w')\nfrom zipfile import ZipFile as Z\np()\n"},
	{"AL-class-attr", "B", "class C:\n    from zipfile import ZipFile as Z\nC.Z('a.zip', 'w')\n"},
	{"AL-kw-mode", "B", "from zipfile import ZipFile as Z\nZ('a.zip', mode='a')\n"},
	{"AL-var-mode", "B", "from zipfile import ZipFile as Z\nm = 'w'\nZ('a.zip', m)\n"},
	{"AL-star-args", "B", "from zipfile import ZipFile as Z\na = ('a.zip', 'w')\nZ(*a)\n"},
	{"AL-fileio-opener", "B", "from io import FileIO as F\nF('a', 'r', True, lambda p, f: 3)\n"},
	{"AL-fileio-rplus", "B", "from io import FileIO as F\nF('a', 'r+')\n"},
	{"AL-concat-mode", "B", "from io import FileIO as F\nF('a', 'r' '+')\n"},
	{"AL-handler-ref", "B", "from logging import FileHandler as F\nprint(F)\n"},
	{"AL-handler-dict", "B", "from logging import FileHandler as F\nd = {'h': F}\n"},
	{"AL-unicode-alias", "B", "from zipfile import ZipFile as \u00e9Z\n\u00e9Z('a.zip', 'w')\n"},
	{"AL-unicode-alias-handler", "B", "from logging import FileHandler as \u00e9F\n\u00e9F('a.log')\n"},
	{"NFKC-fullwidth-zipfile", "B", "import zipfile\nzipfile.\uff3aipFile('a.zip', 'w')\n"},
	{"NFKC-fullwidth-handler", "B", "import logging\nlogging.\uff26ileHandler('a.log')\n"},
	{"NFKC-fullwidth-open", "B", "\uff4fpen('a.txt', 'w').write('x')\n"},
	{"AL-star", "B", "from zipfile import *\nZipFile('a.zip', 'w')\n"},
	{"AL-dunder-import", "B", "__import__('zipfile').ZipFile('a.zip', 'w')\n"},
	{"AL-sysmodules", "B", "import sys, zipfile\nsys.modules['zipfile'].ZipFile('a.zip', 'w')\n"},
	{"AL-open-io-alias", "B", "from io import open as o\no('a.txt', 'w').write('x')\n"},
	{"AL-open-builtins-alias", "B", "from builtins import open as o\no('a.txt', 'w').write('x')\n"},
	{"AL-open-gzip-alias", "B", "from gzip import open as go\ngo('a.gz', 'wb').write(b'x')\n"},
	{"AL-open-assign", "B", "o = open\no('a.txt', 'w').write('x')\n"},
	{"AL-io-module-alias-open", "B", "import io as I\nI.open('a.txt', 'w').write('x')\n"},
	{"AL-os-open-alias", "B", "from os import open as oo, O_WRONLY, O_CREAT\noo('a.txt', O_WRONLY | O_CREAT)\n"},
	// ---- logging config entries: must BLOCK ----
	{"LG-bc-filename", "B", "import logging\nlogging.basicConfig(filename='a.log')\n"},
	{"LG-bc-ml", "B", "import logging\nlogging.basicConfig(\n    level=10,\n    filename='a.log',\n)\n"},
	{"LG-bc-alias", "B", "from logging import basicConfig as bc\nbc(filename='a.log')\n"},
	{"LG-bc-rebind", "B", "import logging\nb = logging.basicConfig\nb(filename='a.log')\n"},
	{"LG-bc-kw", "B", "import logging\nkw = {'filename': 'a.log'}\nlogging.basicConfig(**kw)\n"},
	{"LG-bc-handlers", "B", "import logging\nlogging.basicConfig(handlers=[logging.FileHandler('a.log')])\n"},
	{"LG-bc-stream-open", "B", "import logging\nlogging.basicConfig(stream=open('a.log', 'w'))\n"},
	{"LG-dict-alias", "B", "from logging.config import dictConfig as dc\ndc({'version': 1})\n"},
	{"LG-dict-modalias", "B", "import logging.config as lc\nlc.dictConfig({'version': 1})\n"},
	{"LG-DictConfigurator", "B", "import logging.config\nlogging.config.DictConfigurator({'version': 1, 'handlers': {'f': {'class': 'logging.FileHandler', 'filename': 'a.log'}}, 'root': {'handlers': ['f']}}).configure()\n"},
	{"LG-dictConfigClass", "B", "import logging.config\nlogging.config.dictConfigClass({'version': 1, 'handlers': {'f': {'class': 'logging.FileHandler', 'filename': 'a.log'}}, 'root': {'handlers': ['f']}}).configure()\n"},
	{"LG-BaseRotatingHandler", "B", "import logging.handlers\nlogging.handlers.BaseRotatingHandler('a.log', 'a')\n"},
	{"LG-install-handlers", "B", "import logging.config, configparser\ncp = configparser.ConfigParser()\ncp.read_string('[handlers]\\nkeys=f\\n[handler_f]\\nclass=FileHandler\\nargs=(\\'a.log\\',)\\n')\nlogging.config._install_handlers(cp, {})\n"},
	{"LG-fileconfig-alias", "B", "from logging.config import fileConfig as fc\nfc('a.ini')\n"},
	{"LG-listen-modalias", "B", "from logging import config as c\nc.listen(9999)\n"},
	{"LG-listen-from", "B", "from logging.config import listen\nlisten(9999).start()\n"},
	// ---- reflection: must BLOCK (her §3 claims) ----
	{"RF-getattr", "B", "import logging\ngetattr(logging, 'FileHandler')('a.log')\n"},
	{"RF-dict", "B", "import logging.handlers\nlogging.handlers.__dict__['FileHandler']('a.log')\n"},
	{"RF-vars", "B", "import logging\nvars(logging)['FileHandler']('a.log')\n"},
	{"RF-globals", "B", "from logging import *\nglobals()['FileHandler']('a.log')\n"},
	{"RF-locals", "B", "from logging import *\nlocals()['FileHandler']('a.log')\n"},
	{"RF-dict-get", "B", "import builtins\nbuiltins.__dict__.get('open')('a.txt', 'w')\n"},
	{"RF-getattribute", "B", "import builtins\nbuiltins.__getattribute__('open')('a.txt', 'w')\n"},
	// ---- must ALLOW ----
	{"OK-alias-zip-read", "A", "from zipfile import ZipFile as Z\nwith Z('a.zip') as z:\n    print(z.namelist())\n"},
	{"OK-alias-zip-read-r", "A", "from zipfile import ZipFile as Z\nwith Z('a.zip', 'r') as z:\n    print(z.namelist())\n"},
	{"OK-alias-zip-str-mention", "A", "from zipfile import ZipFile as Z\nwith Z('a.zip') as z:\n    print(\"Z(1,'w')\")\n"},
	{"OK-zip-ml-r", "A", "import zipfile\nwith zipfile.ZipFile(\n    'a.zip',\n    'r',\n) as z:\n    print(z.namelist())\n"},
	{"OK-zip-kw-r", "A", "import zipfile\nz = zipfile.ZipFile('a.zip', mode = \"r\", allowZip64=True)\n"},
	{"OK-zip-bytesio", "A", "import io, zipfile\nz = zipfile.ZipFile(io.BytesIO(b''))\n"},
	{"OK-zip-r-compress", "A", "import zipfile\nz = zipfile.ZipFile('a.zip', 'r', zipfile.ZIP_DEFLATED)\n"},
	{"OK-fileio-rb", "A", "import io\nio.FileIO('a', 'rb').read()\n"},
	{"OK-fileio-fd", "A", "import io\nio.FileIO(0).read(1)\n"},
	{"OK-alias-handler-unused-paren", "A", "from logging.handlers import (\n  RotatingFileHandler as RFH,  # c\n)\n"},
	{"OK-bc-none", "A", "import logging\nlogging.basicConfig()\n"},
	{"OK-bc-level-fmt", "A", "import logging\nlogging.basicConfig(level=logging.INFO, format='%(message)s filename=x')\n"},
	{"OK-socket-listen", "A", "import socket\ns = socket.socket()\ns.listen(5)\n"},
	{"OK-config-dict", "A", "config = {'listen': 1}\nprint(config.get('listen'))\n"},
	{"OK-config-attr-listen", "A", "import argparse\nconfig = argparse.Namespace(listen=1)\nprint(config.listen)\n"},
	{"OK-getattr-benign", "A", "import sys\nprint(getattr(sys, 'version', ''), vars(sys).get('platform'))\n"},
	{"OK-getattr-lineno", "A", "import ast\nfor n in ast.walk(ast.parse('x')):\n    print(getattr(n, 'lineno', None))\n"},
	{"OK-hasattr-open", "A", "import io\nprint(hasattr(io, 'open'))\n"},
	{"OK-getattr-args-system", "A", "import argparse\nargs = argparse.Namespace(system='x')\nprint(getattr(args, 'system', None))\n"},
	{"OK-plain-read", "A", "print(open('a.txt').read())\n"},
	{"OK-logging-getlogger", "A", "import logging\nlog = logging.getLogger(__name__)\nlog.info('x')\n"},
	{"OK-logging-streamhandler", "A", "import logging, sys\nlogging.getLogger().addHandler(logging.StreamHandler(sys.stderr))\n"},
	{"OK-from-io-stringio-as", "A", "from io import StringIO as S\nprint(S('x').read())\n"},
	{"OK-json-config", "A", "import json\nconfig = json.load(open('c.json'))\nprint(config['x'])\n"},
}

func TestAUProbeR6(t *testing.T) {
	for _, c := range r6advCases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			got := auGuard(t, auCase{id: c.id, role: "scout", lang: "python", cmd: c.code})
			auPrint("R6ADV-scout-"+c.want+"-"+c.id, "scout", got)
		})
	}
}

func TestR6Direct(t *testing.T) {
	for _, c := range r6advCases {
		if m := pythonMask(c.code); len(m) != len(c.code) {
			fmt.Printf("MASKLEN\t%s\n", c.id)
		}
		hit := pythonWriteModeHit(c.code)
		v := "A"
		if hit != "" {
			v = "B"
		}
		mark := "ok"
		if v != c.want {
			mark = "MISMATCH"
		}
		fmt.Printf("DIRECT\t%s\twant=%s\tgot=%s\t%s\t%q\n", c.id, c.want, v, mark, hit)
	}
}
