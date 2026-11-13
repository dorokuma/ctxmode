package main

import (
	"os"
	"strings"
	"testing"
)

func TestR5_PythonImportStmtBoundary(t *testing.T) {
	// Override TMPDIR with a cwd-local directory and exercise non-/tmp relative
	// filenames ('audit.log', 'bundle.zip', 'raw.bin', 'log.ini') alongside '/tmp'
	// fixtures so every assertion is completely independent of TMPDIR or /tmp rules.
	altTmp, err := os.MkdirTemp(".", ".r7-tmpdir-")
	if err == nil {
		t.Cleanup(func() { _ = os.RemoveAll(altTmp) })
		t.Setenv("TMPDIR", altTmp)
	}

	cases := []struct {
		name      string
		code      string
		wantBlock bool
		wantSub   string
	}{
		// --- Pure import statements: must ALLOW ---
		{
			name:      "allow-pure-import-logging",
			code:      "import logging\n",
			wantBlock: false,
		},
		{
			name:      "allow-pure-from-rotatinghandler",
			code:      "from logging.handlers import RotatingFileHandler\n",
			wantBlock: false,
		},
		{
			name: "allow-pure-multiline-paren-handlers",
			code: "from logging.handlers import (\n" +
				"    RotatingFileHandler,\n" +
				"    WatchedFileHandler,\n" +
				")\n",
			wantBlock: false,
		},
		{
			name: "allow-pure-multiline-paren-with-comments-and-alias",
			code: "from logging.handlers import (  # handlers\n" +
				"    RotatingFileHandler as RFH,  # keep\n" +
				"    TimedRotatingFileHandler,\n" +
				")\n",
			wantBlock: false,
		},
		{
			name: "allow-pure-backslash-continued-import",
			code: "from logging.handlers \\\n" +
				"    import \\\n" +
				"    RotatingFileHandler\n",
			wantBlock: false,
		},
		{
			name: "allow-indented-from-import-zipfile",
			code: "if True:\n" +
				"    from zipfile import ZipFile\n",
			wantBlock: false,
		},
		{
			name:      "allow-pure-relative-from-import",
			code:      "from .handlers import WatchedFileHandler\n",
			wantBlock: false,
		},
		{
			name:      "allow-pure-import-zipfile",
			code:      "import zipfile\n",
			wantBlock: false,
		},
		{
			name:      "allow-import-zipfile-as-zf-alone",
			code:      "import zipfile as zf\n",
			wantBlock: false,
		},
		{
			name:      "allow-import-logging-handlers-as-lh-alone",
			code:      "import logging.handlers as lh\n",
			wantBlock: false,
		},
		{
			name:      "allow-from-logging-import-star-alone",
			code:      "from logging import *\n",
			wantBlock: false,
		},
		{
			name:      "allow-import-logging-config-alone",
			code:      "import logging.config\n",
			wantBlock: false,
		},

		// --- Runtime logging handler calls across newline / `;` / parens: must BLOCK ---
		{
			name:      "block-import-newline-logging-filehandler-relpath",
			code:      "import logging\nlogging.FileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-import-newline-logging-filehandler-tmppath",
			code:      "import logging\nlogging.FileHandler('/tmp/x.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name: "block-from-import-newline-rotatinghandler",
			code: "from logging.handlers import RotatingFileHandler\n" +
				"RotatingFileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "RotatingFileHandler",
		},
		{
			name: "block-multiline-import-then-runtime-watchedhandler",
			code: "from logging.handlers import (\n" +
				"    RotatingFileHandler,\n" +
				"    WatchedFileHandler,\n" +
				")\n" +
				"WatchedFileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "WatchedFileHandler",
		},
		{
			name:      "block-semicolon-import-logging-filehandler",
			code:      "import logging ; logging.FileHandler('audit.log')",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-import-then-multiline-paren-expr-filehandler",
			code:      "import logging\n(\n    logging.FileHandler('audit.log')\n)\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-yield-from-filehandler",
			code:      "import logging\ndef g():\n    yield from logging.FileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-from-logging-star-then-filehandler",
			code:      "from logging import *\nFileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},

		// --- R6 §4 Mutation M2 killers: non-import parenthesized references must BLOCK ---
		{
			name:      "block-m2-call-multiline-paren-filehandler-arg",
			code:      "foo(\n    FileHandler,\n)\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-m2-tuple-filehandler-index-call",
			code:      "x = (FileHandler,)\nx[0]('audit.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name:      "block-m2-call-multiline-paren-zipfile-arg",
			code:      "f(\n    ZipFile,\n)\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},

		// --- R6 §1: `from ... import X as Alias` across all 7 classes ---
		{
			name:      "block-alias-filehandler",
			code:      "from logging import FileHandler as F\nF('/tmp/x.log')\n",
			wantBlock: true,
			wantSub:   "FileHandler",
		},
		{
			name: "block-alias-multiline-rotatinghandler",
			code: "from logging.handlers import (\n" +
				"  RotatingFileHandler as R,\n" +
				")\n" +
				"R('audit.log')\n",
			wantBlock: true,
			wantSub:   "RotatingFileHandler",
		},
		{
			name:      "block-alias-timed-and-watched-handlers",
			code:      "from logging.handlers import TimedRotatingFileHandler as T, WatchedFileHandler as W\nT('audit.log')\n",
			wantBlock: true,
			wantSub:   "TimedRotatingFileHandler",
		},
		{
			name:      "block-alias-watchedhandler-call",
			code:      "from logging.handlers import WatchedFileHandler as W\nW('audit.log')\n",
			wantBlock: true,
			wantSub:   "WatchedFileHandler",
		},
		{
			name:      "block-alias-zipfile-write",
			code:      "from zipfile import ZipFile as Z\nZ('bundle.zip', 'w').writestr('a', 'b')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-alias-fileio-write",
			code:      "from io import FileIO as F\nF('raw.bin', 'w').write(b'x')\n",
			wantBlock: true,
			wantSub:   "FileIO",
		},
		{
			name:      "block-alias-pyzipfile-write",
			code:      "from zipfile import PyZipFile as P\nP('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "PyZipFile",
		},
		{
			name:      "block-alias-zipfile-chained-rebind",
			code:      "from zipfile import ZipFile as Z\ng = Z\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-module-alias-zf-zipfile-write",
			code:      "import zipfile as zf\nzf.ZipFile('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name: "allow-alias-zipfile-readonly-with",
			code: "from zipfile import ZipFile as Z\n" +
				"with Z('bundle.zip') as z:\n" +
				"    print(z.namelist())\n",
			wantBlock: false,
		},

		// --- R6 §2: logging.basicConfig / dictConfig / fileConfig / config.listen ---
		{
			name:      "block-logging-basicconfig-filename",
			code:      "import logging\nlogging.basicConfig(filename='audit.log')\nlogging.warning('x')\n",
			wantBlock: true,
			wantSub:   "basicConfig",
		},
		{
			name:      "block-logging-basicconfig-kwargs-unpack",
			code:      "import logging\nlogging.basicConfig(**{'filename': 'audit.log'})\n",
			wantBlock: true,
			wantSub:   "basicConfig",
		},
		{
			name:      "block-logging-basicconfig-alias-filename",
			code:      "from logging import basicConfig as bc\nbc(level=20, filename='audit.log')\n",
			wantBlock: true,
			wantSub:   "basicConfig",
		},
		{
			name: "block-logging-dictconfig",
			code: "import logging.config\n" +
				"logging.config.dictConfig({'version': 1, 'handlers': {'f': {'class': 'logging.FileHandler', 'filename': 'audit.log'}}, 'root': {'handlers': ['f']}})\n",
			wantBlock: true,
			wantSub:   "dictConfig",
		},
		{
			name:      "block-logging-fileconfig",
			code:      "import logging.config\nlogging.config.fileConfig('log.ini')\n",
			wantBlock: true,
			wantSub:   "fileConfig",
		},
		{
			name:      "block-logging-config-listen-qualified",
			code:      "import logging.config\nlogging.config.listen(9999)\n",
			wantBlock: true,
			wantSub:   "config.listen",
		},
		{
			name:      "block-logging-config-listen-aliased",
			code:      "from logging.config import listen as L\nL(9999)\n",
			wantBlock: true,
			wantSub:   "config.listen",
		},
		{
			name:      "allow-logging-basicconfig-level-only",
			code:      "import logging\nlogging.basicConfig(level=logging.INFO)\n",
			wantBlock: false,
		},
		{
			name:      "allow-unrelated-socket-listen",
			code:      "import socket\ns = socket.socket()\ns.listen(5)\n",
			wantBlock: false,
		},

		// --- R6 §3: Reflection via getattr / __dict__ / vars / globals ---
		{
			name:      "block-getattr-logging-filehandler",
			code:      "import logging\ngetattr(logging, 'FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "getattr FileHandler",
		},
		{
			name:      "block-dict-subscript-filehandler",
			code:      "import logging.handlers\nlogging.handlers.__dict__['FileHandler']('audit.log')\n",
			wantBlock: true,
			wantSub:   "__dict__ FileHandler",
		},
		{
			name:      "block-getattr-builtins-open",
			code:      "import builtins\ngetattr(builtins, 'open')('audit.log', 'w')\n",
			wantBlock: true,
			wantSub:   "getattr open",
		},
		{
			name:      "block-getattr-builtins-hex-escaped-open",
			code:      "import builtins\ngetattr(builtins, '\\x6fpen')('audit.log', 'w')\n",
			wantBlock: true,
			wantSub:   "getattr open",
		},
		{
			name:      "block-vars-logging-filehandler",
			code:      "import logging\nvars(logging)['FileHandler']('audit.log')\n",
			wantBlock: true,
			wantSub:   "vars FileHandler",
		},
		{
			name:      "allow-benign-getattr-and-vars",
			code:      "import sys\nprint(getattr(sys, 'version', ''), vars(sys).get('platform'))\n",
			wantBlock: false,
		},

		// --- ZipFile / PyZipFile / FileIO regressions & bare/rebind checks ---
		{
			name:      "block-zipfile-assign-rebind",
			code:      "import zipfile\nf = zipfile.ZipFile\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-zipfile-bare-expr-after-import",
			code:      "import zipfile\nzipfile.ZipFile\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-from-zipfile-bare-expr-second-line",
			code:      "from zipfile import ZipFile\nZipFile\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-zipfile-paren-wrapped-ctor-write",
			code:      "import zipfile\n(zipfile.ZipFile)('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "allow-zipfile-readonly-var-arg",
			code:      "from zipfile import ZipFile\np = 'bundle.zip'\nz = ZipFile(p)\n",
			wantBlock: false,
		},
		{
			name:      "allow-zipfile-readonly-default",
			code:      "from zipfile import ZipFile\nwith ZipFile('bundle.zip') as z:\n    print(z.namelist())\n",
			wantBlock: false,
		},
		{
			name:      "allow-zipfile-readonly-explicit-r",
			code:      "import zipfile\nzipfile.ZipFile('bundle.zip', 'r')\n",
			wantBlock: false,
		},
		{
			name:      "allow-fileio-readonly-explicit-r",
			code:      "import io\nio.FileIO('raw.bin', 'r')\n",
			wantBlock: false,
		},
		{
			name:      "block-zipfile-positional-w",
			code:      "import zipfile\nzipfile.ZipFile('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-zipfile-kwarg-mode-a",
			code:      "from zipfile import ZipFile\nZipFile('bundle.zip', mode='a')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-fileio-positional-w",
			code:      "import io\nio.FileIO('raw.bin', 'w')\n",
			wantBlock: true,
			wantSub:   "FileIO",
		},

		// --- R7 §1: Python NFKC non-ASCII identifiers vs UTF-8 strings/comments/f-strings ---
		{
			name:      "allow-utf8-strings-and-comments-ete-cafe",
			code:      "print('été')\n# café\n",
			wantBlock: false,
		},
		{
			name:      "allow-utf8-fstring-literal-segment",
			code:      "x = 42\nprint(f'结果 café: {x}')\n",
			wantBlock: false,
		},
		{
			name:      "block-nfkc-fullwidth-open",
			code:      "\uff4fpen('audit.txt', 'w').write('x')\n",
			wantBlock: true,
			wantSub:   "non-ASCII identifier",
		},
		{
			name:      "block-nfkc-fullwidth-zipfile",
			code:      "import zipfile\nzipfile.\uff3aipFile('bundle.zip', 'w').writestr('a', 'b')\n",
			wantBlock: true,
			wantSub:   "non-ASCII identifier",
		},
		{
			name:      "block-nfkc-fullwidth-filehandler",
			code:      "import logging\nlogging.\uff26ileHandler('audit.log')\n",
			wantBlock: true,
			wantSub:   "non-ASCII identifier",
		},
		{
			name:      "block-nfkc-inside-fstring-expr",
			code:      "f\"{\uff4fpen('audit.txt', 'w')}\"\n",
			wantBlock: true,
			wantSub:   "non-ASCII identifier",
		},

		// --- R7 §2: BaseRotatingHandler & whole-module logging.config closure ---
		{
			name:      "block-logging-handlers-baserotatinghandler",
			code:      "import logging.handlers\nlogging.handlers.BaseRotatingHandler('audit.log', 'a')\n",
			wantBlock: true,
			wantSub:   "BaseRotatingHandler",
		},
		{
			name:      "block-alias-baserotatinghandler",
			code:      "from logging.handlers import BaseRotatingHandler as B\nB('audit.log', 'a')\n",
			wantBlock: true,
			wantSub:   "BaseRotatingHandler",
		},
		{
			name: "block-logging-config-dictconfigurator",
			code: "import logging.config\n" +
				"logging.config.DictConfigurator({'version': 1, 'handlers': {'f': {'class': 'logging.FileHandler', 'filename': 'audit.log'}}, 'root': {'handlers': ['f']}}).configure()\n",
			wantBlock: true,
			wantSub:   "logging.config.DictConfigurator",
		},
		{
			name:      "block-logging-config-dictconfigclass",
			code:      "import logging.config\nlogging.config.dictConfigClass({'version': 1}).configure()\n",
			wantBlock: true,
			wantSub:   "logging.config.dictConfigClass",
		},
		{
			name: "block-logging-config-install-handlers",
			code: "import logging.config, configparser\n" +
				"cp = configparser.ConfigParser()\n" +
				"cp.read_string(\"[handlers]\\nkeys=f\\n[handler_f]\\nclass=FileHandler\\nargs=('audit.log',)\\n\")\n" +
				"logging.config._install_handlers(cp, {})\n",
			wantBlock: true,
			wantSub:   "logging.config._install_handlers",
		},
		{
			name:      "block-logging-config-private-resolve",
			code:      "import logging.config\nlogging.config._resolve('logging.FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "logging.config._resolve",
		},
		{
			name:      "block-logging-config-baseconfigurator-resolve",
			code:      "import logging.config\nlogging.config.BaseConfigurator({}).resolve('logging.FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "logging.config.BaseConfigurator",
		},
		{
			name:      "block-from-logging-config-import-resolve-alias",
			code:      "from logging.config import _resolve as r\nr('logging.FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "logging.config._resolve",
		},
		{
			name:      "block-from-logging-config-import-star",
			code:      "from logging.config import *\n",
			wantBlock: true,
			wantSub:   "logging.config",
		},
		{
			name:      "block-logging-config-module-rebind",
			code:      "import logging.config\nc = logging.config\n",
			wantBlock: true,
			wantSub:   "logging.config",
		},

		// --- R7 §3: pkgutil.resolve_name & pydoc.{locate,safeimport} ---
		{
			name:      "block-pkgutil-resolve-name",
			code:      "import pkgutil\npkgutil.resolve_name('logging:FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "resolve_name",
		},
		{
			name:      "block-pkgutil-resolve-name-alias",
			code:      "from pkgutil import resolve_name as rn\nrn('logging:FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "resolve_name",
		},
		{
			name:      "block-pydoc-locate",
			code:      "import pydoc\npydoc.locate('logging.FileHandler')('audit.log')\n",
			wantBlock: true,
			wantSub:   "pydoc.locate",
		},
		{
			name:      "block-pydoc-safeimport-alias",
			code:      "from pydoc import safeimport as si\nsi('logging.handlers')\n",
			wantBlock: true,
			wantSub:   "pydoc.safeimport",
		},
		{
			name:      "allow-import-pkgutil-and-pydoc-alone",
			code:      "import pkgutil, pydoc\n",
			wantBlock: false,
		},

		// --- R7 §4.1: locals() & __getattribute__ reflection ---
		{
			name:      "block-locals-subscript-filehandler",
			code:      "from logging import *\nlocals()['FileHandler']('audit.log')\n",
			wantBlock: true,
			wantSub:   "locals FileHandler",
		},
		{
			name:      "block-builtins-dunder-getattribute-open",
			code:      "import builtins\nbuiltins.__getattribute__('open')('audit.txt', 'w')\n",
			wantBlock: true,
			wantSub:   "__getattribute__ open",
		},
		{
			name:      "block-object-dunder-getattribute-builtins-open",
			code:      "import builtins\nobject.__getattribute__(builtins, 'open')('audit.txt', 'w')\n",
			wantBlock: true,
			wantSub:   "__getattribute__ open",
		},

		// --- R7 §4.2: False-positive regressions (argparse config.listen & getattr system) ---
		{
			name:      "allow-argparse-namespace-config-listen",
			code:      "import argparse\nconfig = argparse.Namespace(listen=1)\nprint(config.listen)\n",
			wantBlock: false,
		},
		{
			name:      "allow-argparse-config-listen-with-import-logging",
			code:      "import argparse, logging\nconfig = argparse.Namespace(listen=1)\nprint(config.listen)\n",
			wantBlock: false,
		},
		{
			name:      "allow-getattr-args-system-none",
			code:      "print(getattr(args, 'system', None))\n",
			wantBlock: false,
		},
		{
			name:      "block-getattr-os-system",
			code:      "import os\ngetattr(os, 'system')('id')\n",
			wantBlock: true,
			wantSub:   "getattr system",
		},

		// --- R7 §4.3: 5 surviving mutation-gap killers ---
		{
			name: "block-mut-paren-import-newline-before-as",
			code: "from zipfile import (\n" +
				"    ZipFile\n" +
				"    as Z,\n" +
				")\n" +
				"Z('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name: "block-mut-paren-import-comment-before-as",
			code: "from zipfile import (\n" +
				"    ZipFile  # c\n" +
				"    as Z,\n" +
				")\n" +
				"Z('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name: "block-mut-paren-import-newline-after-as",
			code: "from zipfile import (\n" +
				"    ZipFile as\n" +
				"    Z,\n" +
				")\n" +
				"Z('bundle.zip', 'w')\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-mut-zipfile-star-args-unpack",
			code:      "from zipfile import ZipFile as Z\na = ('bundle.zip', 'w')\nZ(*a)\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-mut-zipfile-kw-star-unpack",
			code:      "from zipfile import ZipFile as Z\nkw = {'mode': 'w'}\nZ('bundle.zip', **kw)\n",
			wantBlock: true,
			wantSub:   "ZipFile",
		},
		{
			name:      "block-mut-fileio-positional-opener",
			code:      "import io\nio.FileIO('raw.bin', 'r', True, lambda p, f: 3)\n",
			wantBlock: true,
			wantSub:   "FileIO",
		},
		{
			name:      "block-mut-fileio-keyword-opener",
			code:      "import io\nio.FileIO('raw.bin', opener=o)\n",
			wantBlock: true,
			wantSub:   "FileIO",
		},
		{
			name:      "allow-fileio-explicit-none-opener",
			code:      "import io\nio.FileIO('raw.bin', 'r', True, None)\nio.FileIO('raw.bin', 'r', opener=None)\n",
			wantBlock: false,
		},
		{
			name:      "block-mut-from-logging-import-config-as-c-listen",
			code:      "from logging import config as c\nc.listen(9999)\n",
			wantBlock: true,
			wantSub:   "logging.config.listen",
		},
		{
			name:      "block-mut-import-logging-config-as-lc",
			code:      "import logging.config as lc\nlc.DictConfigurator({})\n",
			wantBlock: true,
			wantSub:   "logging.config.DictConfigurator",
		},
		{
			name:      "block-mut-basicconfig-rebind",
			code:      "import logging\nb = logging.basicConfig\nb(filename='audit.log')\n",
			wantBlock: true,
			wantSub:   "basicConfig rebind",
		},
		{
			name:      "allow-alias-zipfile-readonly-positional",
			code:      "from zipfile import ZipFile as Z\nz = Z('bundle.zip')\n",
			wantBlock: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit := pythonWriteModeHit(tc.code)
			gotBlock := hit != ""
			if gotBlock != tc.wantBlock {
				t.Fatalf("pythonWriteModeHit(%q) = %q (block=%v), want block=%v", tc.code, hit, gotBlock, tc.wantBlock)
			}
			if tc.wantBlock && tc.wantSub != "" && !strings.Contains(hit, tc.wantSub) {
				t.Errorf("pythonWriteModeHit(%q) = %q, want substring %q", tc.code, hit, tc.wantSub)
			}
		})
	}
}

func TestR5_IsPythonImportStmtAtUnit(t *testing.T) {
	// 1. Multiline parenthesized `from ... import (...)` vs runtime call after `)`.
	src := "from logging.handlers import (\n    RotatingFileHandler,\n)\nRotatingFileHandler('audit.log')\n"
	first := strings.Index(src, "RotatingFileHandler")
	second := strings.LastIndex(src, "RotatingFileHandler")
	if first < 0 || second <= first {
		t.Fatalf("unexpected fixture indices: first=%d second=%d", first, second)
	}
	if !isPythonImportStmtAt(src, first) {
		t.Errorf("first RotatingFileHandler at %d inside multiline import (...) got false, want true", first)
	}
	if isPythonImportStmtAt(src, second) {
		t.Errorf("second RotatingFileHandler at %d on runtime call line got true, want false", second)
	}

	// 2. Direct R4-regression assertions (R4 returned true on all three due to `\n` skip).
	r4CrossLine := "import logging\nlogging.FileHandler"
	fhIdx := strings.Index(r4CrossLine, "FileHandler")
	if isPythonImportStmtAt(r4CrossLine, fhIdx) {
		t.Errorf("R4 regression: FileHandler at %d after bare newline got true, want false", fhIdx)
	}

	r4FromCrossLine := "from logging.handlers import RotatingFileHandler\nRotatingFileHandler"
	rfhSecond := strings.LastIndex(r4FromCrossLine, "RotatingFileHandler")
	if isPythonImportStmtAt(r4FromCrossLine, rfhSecond) {
		t.Errorf("R4 regression: second RotatingFileHandler at %d got true, want false", rfhSecond)
	}

	r4BareZip := "import zipfile\nzipfile.ZipFile\n"
	zfIdx := strings.Index(r4BareZip, "ZipFile")
	if isPythonImportStmtAt(r4BareZip, zfIdx) {
		t.Errorf("R4 regression: bare zipfile.ZipFile at %d got true, want false", zfIdx)
	}

	// 3. Direct M2-killer assertion: non-import parenthesized multiline call argument.
	m2Call := "foo(\n    FileHandler,\n)\n"
	m2Idx := strings.Index(m2Call, "FileHandler")
	if isPythonImportStmtAt(m2Call, m2Idx) {
		t.Errorf("M2 regression: FileHandler inside foo(...) at %d got true, want false", m2Idx)
	}

	// 4. CRLF backslash continuation vs bare CRLF newline.
	crlf := "from logging.handlers \\\r\n    import RotatingFileHandler\r\nRotatingFileHandler('audit.log')\r\n"
	cFirst := strings.Index(crlf, "RotatingFileHandler")
	cSecond := strings.LastIndex(crlf, "RotatingFileHandler")
	if !isPythonImportStmtAt(crlf, cFirst) {
		t.Errorf("CRLF continued import RotatingFileHandler at %d got false, want true", cFirst)
	}
	if isPythonImportStmtAt(crlf, cSecond) {
		t.Errorf("CRLF runtime RotatingFileHandler at %d got true, want false", cSecond)
	}
}

func TestR7_JSUnicodeIdentEscapeHit(t *testing.T) {
	jsCases := []struct {
		name      string
		code      string
		wantBlock bool
	}{
		{
			name:      "block-js-hex4-writefilesync",
			code:      "require('fs').\\u0077riteFileSync('js.txt', 'x')\n",
			wantBlock: true,
		},
		{
			name:      "block-js-codepoint-brace-writefilesync",
			code:      "require('fs').\\u{77}riteFileSync('js.txt', 'x')\n",
			wantBlock: true,
		},
		{
			name:      "block-js-hex4-execsync",
			code:      "const cp = require('child_process'); cp.\\u0065xecSync('id')\n",
			wantBlock: true,
		},
		{
			name:      "allow-js-unicode-escape-in-strings-and-comments",
			code:      "console.log('\\u00e9té'); // \\u0077riteFileSync café\nconst s = \"\\u{1F600}\";\n",
			wantBlock: false,
		},
		{
			name:      "allow-js-unicode-escape-in-template-literal",
			code:      "const n = 1;\nconsole.log(`café \\u00e9 ${n}`);\n",
			wantBlock: false,
		},
	}
	for _, tc := range jsCases {
		t.Run(tc.name, func(t *testing.T) {
			hit := jsUnicodeIdentEscapeHit(tc.code)
			gotBlock := hit != ""
			if gotBlock != tc.wantBlock {
				t.Fatalf("jsUnicodeIdentEscapeHit(%q) = %q (block=%v), want block=%v", tc.code, hit, gotBlock, tc.wantBlock)
			}
		})
	}
}
