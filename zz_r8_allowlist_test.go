package main

import (
	"strings"
	"testing"
)

func expandTestLang(l string) string {
	if l == "py" {
		return "python"
	}
	if l == "js" {
		return "javascript"
	}
	return l
}

func TestR8_StrictReadonlyAllowlistEndToEnd(t *testing.T) {
	type tc struct {
		name string
		lang string
		code string
		deny bool
	}
	cases := []tc{
		{"r8-s1-posix-system", "py", "import posix\ngetattr(posix, 'system')('touch s1')", true},
		{"r8-s2-vars-os-system", "py", "import os\nvars(os)['system']('touch s2')", true},
		{"r8-s3-os-dict-system", "py", "import os\nos.__dict__['system']('touch s3')", true},
		{"r8-s4-sys-modules-os", "py", "import sys, os\ngetattr(sys.modules['os'], 'system')('touch s4')", true},
		{"r8-s5-os-path-os", "py", "from os import path\ngetattr(path.os, 'system')('touch s5')", true},
		{"r8-s6-os-dict-get", "py", "import os\nos.__dict__.get('system')('touch s6')", true},
		{"r8-s7-os-getattribute", "py", "import os\nos.__getattribute__('system')('touch s7')", true},
		{"r8-a01-getattr-concat", "py", "import logging\ngetattr(logging, 'File' + 'Handler')('a.log')", true},
		{"r8-a02-getattr-implicit-concat", "py", "import builtins\ngetattr(builtins, 'op' 'en')('a.txt', 'w')", true},
		{"r8-a03-getattr-join", "py", "import logging\ngetattr(logging, ''.join(['File', 'Handler']))('a.log')", true},
		{"r8-a04-getattr-var", "py", "import logging\nn = 'FileHandler'\ngetattr(logging, n)('a.log')", true},
		{"r8-a05-getattr-chr", "py", "import builtins\ngetattr(builtins, chr(111) + 'pen')('a.txt', 'w')", true},
		{"r8-a06-getattr-slice-rev", "py", "import builtins\ngetattr(builtins, 'nepo'[::-1])('a.txt', 'w')", true},
		{"r8-a07-getattr-fromhex", "py", "import builtins\ngetattr(builtins, bytes.fromhex('6f70656e').decode())('a.txt', 'w')", true},
		{"r8-a08-getattr-fstring", "py", "import logging\nx = 'File'\ngetattr(logging, f'{x}Handler')('a.log')", true},
		{"r8-a09-attrgetter", "py", "import operator, logging\noperator.attrgetter('FileHandler')(logging)('a.log')", true},
		{"r8-a10-inspect-getmembers", "py", "import inspect, logging\ndict(inspect.getmembers(logging))['FileHandler']('a.log')", true},
		{"r8-a11-vars-comprehension", "py", "import logging\n[v for k, v in vars(logging).items() if k == 'FileHandler'][0]('a.log')", true},
		{"r8-a12-vars-getitem", "py", "import logging\nvars(logging).__getitem__('FileHandler')('a.log')", true},
		{"r8-a13-dict-setdefault", "py", "import logging\nlogging.__dict__.setdefault('FileHandler', None)('a.log')", true},
		{"r8-a14-dict-var-sub", "py", "import logging\nk = 'FileHandler'\nlogging.__dict__[k]('a.log')", true},
		{"r8-a15-builtins-dict-concat", "py", "import builtins\nbuiltins.__dict__['op' + 'en']('a.txt', 'w')", true},
		{"r8-a16-getattr-rebind", "py", "import builtins\ng = getattr\ng(builtins, 'open')('a.txt', 'w')", true},
		{"r8-a17-handlers-implicit-concat", "py", "import logging.handlers as lh\ngetattr(lh, 'RotatingFile' 'Handler')('a.log')", true},
		{"r8-b01-gzipfile-wb", "py", "import gzip\ngzip.GzipFile('a.gz', 'wb')", true},
		{"r8-b02-bz2file-w", "py", "import bz2\nbz2.BZ2File('a.bz2', 'w')", true},
		{"r8-b03-lzmafile-w", "py", "import lzma\nlzma.LZMAFile('a.xz', 'w')", true},
		{"r8-b04-tarfile-w", "py", "import tarfile\ntarfile.TarFile('a.tar', 'w')", true},
		{"r8-b05-py-compile", "py", "import py_compile\npy_compile.compile('x.py', cfile='x.pyc')", true},
		{"r8-b06-compileall", "py", "import compileall\ncompileall.compile_file('x.py')", true},
		{"r8-b07-cprofile-out", "py", "import cProfile\ncProfile.run('1', 'a.prof')", true},
		{"r8-b08-os-mkfifo", "py", "import os\nos.mkfifo('a.fifo')", true},
		{"r8-b09-os-mknod", "py", "import os\nos.mknod('a.nod')", true},
		{"r8-b10-os-renames", "py", "import os\nos.renames('x.py', 'y.py')", true},
		{"r8-b11-os-utime", "py", "import os\nos.utime('x.py', None)", true},
		{"r8-b12-unix-socket-bind", "py", "import socket\nsocket.socket(socket.AF_UNIX).bind('a.sock')", true},
		{"r8-b13-et-write", "py", "import xml.etree.ElementTree as ET\nET.ElementTree(ET.Element('a')).write('a.xml')", true},
		{"r8-b14-cookiejar-save", "py", "import http.cookiejar\nhttp.cookiejar.MozillaCookieJar('c.txt').save()", true},
		{"r8-b15-tempdir-keep", "py", "import tempfile\ntempfile.TemporaryDirectory(dir='.', delete=False)", true},
		{"r8-b16-maildir-create", "py", "import mailbox\nmailbox.Maildir('md', create=True)", true},
		{"r8-b17-zipapp-create", "py", "import zipapp\nzipapp.create_archive('zdir', 'a.pyz')", true},
		{"r8-b18-unpack-archive", "py", "import shutil\nshutil.unpack_archive('in.zip', 'out')", true},
		{"r8-b19-readline-history", "py", "import readline\nreadline.write_history_file('h.txt')", true},
		{"r8-c01-cprofile-code", "py", "import cProfile\ncProfile.run(\"open('cp.txt','w').write('x')\")", true},
		{"r8-c02-timeit", "py", "import timeit\ntimeit.timeit(\"open('t.txt','w').write('x')\", number=1)", true},
		{"r8-c03-types-functiontype", "py", "import types\ntypes.FunctionType(compile(\"open('f.txt','w')\", 'f', 'exec'), {})()", true},
		{"r8-c04-code-interpreter", "py", "import code\ncode.InteractiveInterpreter().runsource(\"open('i.txt','w')\")", true},
		{"r8-c05-pdb-run", "py", "import pdb\npdb.run(\"open('p.txt','w')\")", true},
		{"r8-c06-runpy", "py", "import runpy\nrunpy.run_path('x.py')", true},
		{"r8-js01-fs-concat-sub", "js", "require('fs')['write' + 'FileSync']('j1.txt', 'x');", true},
		{"r8-js02-fs-tmpl-sub", "js", "const n = 'File'; require('fs')[`write${n}Sync`]('j2.txt', 'x');", true},
		{"r8-js03-fs-fromcharcode", "js", "const fs = require('fs'); fs[String.fromCharCode(119) + 'riteFileSync']('j3.txt', 'x');", true},
		{"r8-js04-reflect-get", "js", "const fs = require('fs'); Reflect.get(fs, 'write' + 'FileSync')('j4.txt', 'x');", true},
		{"r8-js05-vm-run", "js", "require('vm').runInThisContext(\"require('fs').writeFileSync('j5.txt','x')\");", true},
		{"r8-js06-globalthis-eval", "js", "globalThis['ev' + 'al'](\"require('fs').writeFileSync('j6.txt','x')\");", true},
		{"r8-js07-fs-symlink", "js", "require('fs').symlinkSync('x.py', 'j7.lnk');", true},
		{"r8-js08-fs-link", "js", "require('fs').linkSync('x.py', 'j8.lnk');", true},
		{"r8-js09-fs-chmod", "js", "require('fs').chmodSync('x.py', 0o777);", true},
		{"r8-js10-fs-utimes", "js", "require('fs').utimesSync('x.py', 1, 1);", true},
		{"r8-js11-fs-promises-open-w", "js", "require('fs').promises.open('j11.txt', 'w');", true},
		{"r9-21-map-path-replace", "py", "from pathlib import Path\nlist(map(Path.replace, [Path('x.py')], [Path('rp2.py')]))", true},
		{"r9-21-starmap-path-replace", "py", "import itertools, pathlib\nlist(itertools.starmap(pathlib.Path.replace, [(pathlib.Path('x.py'), 'rp3.py')]))", true},
		{"r9-21-subclass-path-alias", "py", "import pathlib\nclass P(pathlib.Path):\n    read = pathlib.Path.replace\nP('x.py').read('rp4.py')", true},
		{"r9-21-3arg-type-path", "py", "import pathlib\nQ = type('Q', (pathlib.Path,), {'read': pathlib.Path.replace})\nQ('x.py').read('rp5.py')", true},
		{"r9-21-partial-path-replace", "py", "import functools, pathlib\nfunctools.partial(pathlib.Path('x.py').replace, 'rp6.py')()", true},
		{"r9-21-vars-path-replace", "py", "import pathlib\nr = vars(pathlib.Path).get('replace')\nr(pathlib.Path('x.py'), 'rp7.py')", true},
		{"r9-21-getattr-path-replace", "py", "import pathlib\nr = getattr(pathlib.Path('x.py'), 'replace')\nr('rp8.py')", true},
		{"r9-21-kw-target-replace", "py", "from pathlib import Path\nPath('x.py').replace(target='rp1.py')", true},
		{"r9-22-walk-gi-frame-globals", "py", "import os\nos.walk('.').gi_frame.f_globals['system']('touch fr1.txt')", true},
		{"r9-22-gen-gi-frame-builtins", "py", "b = (x for x in [1]).gi_frame.f_builtins\nb['exec'](\"import os; os.mkdir('fr2')\")", true},
		{"r9-22-gen-builtins-get", "py", "(x for x in [1]).gi_frame.f_builtins.get('exec')(\"import os; os.mkdir('fr3')\")", true},
		{"r9-22-coro-cr-frame", "py", "async def f():\n    pass\nc = f()\nc.cr_frame.f_builtins['exec'](\"import os; os.mkdir('fr4')\")\nc.close()", true},
		{"r9-22-walk-globals-get-concat", "py", "import os\nm = os.walk('.').gi_frame.f_globals.get('mk' + 'dir')\nm('fr8')", true},
		{"r9-23-get-type-hints-cls", "py", "import typing\nclass A:\n    x: \"__import__('os').mkdir('ev1')\"\ntyping.get_type_hints(A)", true},
		{"r9-23-get-type-hints-fn1", "py", "import typing\ndef f(a: \"__import__('os').mkdir('ev2')\"): pass\ntyping.get_type_hints(f)", true},
		{"r9-23-get-type-hints-fn2", "py", "import typing\ndef f(a: \"print(open('ev3.txt', 'w'))\"): pass\ntyping.get_type_hints(f)", true},
		{"r9-24-sqlite-vacuum-into", "py", "import sqlite3\nc = sqlite3.connect('file:in.db?mode=ro', uri=True)\nc.execute(\"VACUUM INTO 'sq1.db'\")", true},
		{"r9-24-sqlite-attach-uri", "py", "import sqlite3\nc = sqlite3.connect('file:in.db?mode=ro', uri=True)\nc.execute(\"ATTACH DATABASE 'file:sq2.db?mode=rwc' AS a\")", true},
		{"r9-24-sqlite-attach-plain", "py", "import sqlite3\nc = sqlite3.connect('file:in.db?mode=ro', uri=True)\nc.execute(\"ATTACH DATABASE 'sq3.db' AS a\")", true},
		{"r9-25-platform-processor", "py", "import os, platform\nos.environ['PATH'] = 'bin'\nprint(platform.processor())", true},
		{"r9-25-platform-architecture", "py", "import os, platform\nos.environ['PATH'] = 'bin'\nprint(platform.architecture())", true},
		{"r9-26-coding-unicode-escape", "py", "# coding: unicode_escape\n#\\u000aimport os; os.mkdir('lx1')", true},
		{"r9-26-bare-cr-newline", "py", "# c\rimport os; os.mkdir('lx3')", true},
		{"r9-27-js-module-require", "js", "module.require('fs').lutimes('x.py', 1, 1, () => {});", true},
		{"r9-27-js-arguments-require", "js", "arguments[1]('fs').lutimes('x.py', 1, 1, () => {});", true},
		{"r9-27-js-sloppy-this-proc", "js", "(function () { return this })().process.getBuiltinModule('fs').lutimes('x.py', 2, 2, () => {});", true},
		{"r9-27-js-mod-req-dyn", "js", "const m = module.require('fs'); const k = 'copy' + 'FileSync'; m[k]('x.py', 'jcp1.txt');", true},
		{"r9-27-js-args-req-dyn", "js", "const m = arguments[1]('fs'); const k = ['copy', 'File', 'Sync'].join(''); m[k]('x.py', 'jcp2.txt');", true},
		{"r9-27-js-fn-ctor-1", "js", "const k = 'constr' + 'uctor'; const f = () => 0; f[k](\"process.getBuiltinModule('fs').mkdtempSync('jc1-')\")();", true},
		{"r9-27-js-fn-ctor-2", "js", "const k = ['constr', 'uctor'].join(''); const f = () => 0; f[k](\"1\")();", true},
		{"r9-27-js-proc-builtin-cp", "js", "const p = (function () { return this })().process; const cp = p.getBuiltinModule('child' + '_process');", true},
		{"r9-28-perl-blocked", "perl", "print 1;\n", true},
		{"r9-28-ruby-blocked", "ruby", "puts 1\n", true},
		{"r9-28-php-blocked", "php", "echo 1;\n", true},
		{"r9-28-r-blocked", "r", "print(1)\n", true},
		{"r9-28-elixir-blocked", "elixir", "IO.puts(1)\n", true},
		{"r10-21-print-file-et1", "py", "import xml.etree.ElementTree as ET\nprint('pf1.xml', file=ET.parse('c.xml'), end='')", true},
		{"r10-21-print-file-et2", "py", "import xml.etree.ElementTree as ET\nt = ET.parse('c.xml')\nprint('pf2.xml', file=t, end='')", true},
		{"r10-21-print-file-et-star", "py", "import xml.etree.ElementTree as ET\nprint(file=ET.parse('c.xml'), end='', *['pf8.xml'])", true},
		{"r10-21-pprint-stream-et", "py", "import pprint\nimport xml.etree.ElementTree as ET\npprint.pprint('pf3', stream=ET.parse('c.xml'))", true},
		{"r10-22-match-gen-frame", "py", "match (x for x in [1]):\n    case object(gi_frame=object(f_builtins=b)):\n        b.get('ex' + 'ec')(\"import os; os.mkdir('mt1')\")", true},
		{"r10-22-match-walk-frame", "py", "import os\nmatch os.walk('.'):\n    case object(gi_frame=object(f_globals=g)):\n        g.get('mk' + 'dir')('mt2')", true},
		{"r10-22-match-path-replace", "py", "from pathlib import Path\nmatch Path('x.py'):\n    case Path(replace=r):\n        r('mt3.py')", true},
		{"r10-22-match-obj-replace", "py", "from pathlib import Path\nmatch Path('x.py'):\n    case object(replace=r):\n        r('mt4.py')", true},
		{"r10-22-match-or-replace", "py", "from pathlib import Path\nmatch Path('x.py'):\n    case str(replace=r) | object(replace=r):\n        r('mt5.py')", true},
		{"r10-23-type-bind-replace", "py", "from pathlib import Path\nT = type(Path('.'))\nT.replace(T('x.py'), 'ty1.py')", true},
		{"r10-23-type-inline-replace", "py", "from pathlib import Path\np = Path('x.py')\ntype(p).replace(p, 'ty2.py')", true},
		{"r10-23-type-parent-replace", "py", "import pathlib\np = pathlib.Path('x.py')\nC = type(p.parent)\nC.replace(p, 'ty3.py')", true},
		{"r10-24-js-linecont-ctor", "js", "(() => 0)['constr\\\nuctor']('1')();", true},
		{"r10-25-js-proc-env-assign", "js", "process.env.PATH = 'bin:' + process.env.PATH;", true},
		{"r11-21-mw1-match-walrus-path", "py", "from pathlib import Path\nmatch p := Path('x.py'):\n    case Path(replace=r) if q := 1:\n        r('mw1.py')", true},
		{"r11-21-mw2-match-walrus-gen", "py", "match g := (x for x in [1]):\n    case object(gi_frame=object(f_builtins=b)) if q := 1:\n        b.get('ex' + 'ec')(\"import os; os.mkdir('mw2')\")", true},
		{"r11-21-mw3-match-walrus-walk", "py", "import os\nmatch w := os.walk('.'):\n    case object(gi_frame=object(f_globals=g)) if q := 1:\n        g.get('mk' + 'dir')('mw3')", true},
		{"r11-21-mw4-match-walrus-obj", "py", "from pathlib import Path\nmatch p := Path('x.py'):\n    case object(replace=r) if z := 2:\n        r('mw4.py')", true},
		{"r11-22-tk1-def-makedir", "py", "import tarfile\ndef makedir():\n    pass\nt = tarfile.open('in.tar')\nti = t.getmember('f.txt')\nt.makedir(ti, 'tk1')", true},
		{"r11-22-tk2-def-makefile", "py", "import tarfile\ndef makefile():\n    pass\nt = tarfile.open('in.tar')\nti = t.getmember('f.txt')\nt.makefile(ti, 'tk2.txt')", true},
		{"r11-22-tk3-attr-makedir", "py", "import tarfile\nt = tarfile.open('in.tar')\nti = t.getmember('f.txt')\nm = t.makedir\nm(ti, 'tk3')", true},
		{"r11-22-tk4-map-makefile", "py", "import tarfile\nt = tarfile.open('in.tar')\nti = t.getmember('f.txt')\nlist(map(t.makefile, [ti], ['tk4.txt']))", true},
		{"r11-22-tk5-partial-makefile", "py", "import functools, tarfile\nt = tarfile.open('in.tar')\nti = t.getmember('f.txt')\nfunctools.partial(t.makefile, ti, 'tk5.txt')()", true},
		{"r11-22-tk6-attr-utime", "py", "import tarfile\nt = tarfile.open('in.tar')\nti = t.getmember('f.txt')\nti.mtime = 0\nu = t.utime\nu(ti, 'x.py')", true},
		{"r11-22-tk7-cls-def-makedir", "py", "import tarfile\nclass C:\n    def makedir(self):\n        pass\nt = tarfile.open('in.tar')\nti = t.getmember('f.txt')\nt.makedir(ti, 'tk7')", true},
		{"r11-22-tk8-loop-makefile", "py", "import tarfile\nt = tarfile.open('in.tar')\nfor m in t.getmembers():\n    t.makefile(m, 'tk8-' + m.name)", true},
		{"r11-23-ty4-tuple-type-call", "py", "from pathlib import Path\np = Path('x.py')\nT = (str, type)[1](p)\nT.replace(p, 'ty4.py')", true},
		{"r11-23-ty5-var-tuple-type", "py", "from pathlib import Path\np = Path('x.py')\nfs = (str, type)\nT = fs[1](p)\nT.replace(p, 'ty5.py')", true},
		{"r11-23-ty6-map-tuple-type", "py", "from pathlib import Path\np = Path('x.py')\nT = list(map(lambda f, x: f(x), (str, type), (p, p)))[1]\nT.replace(p, 'ty6.py')", true},
		{"r11-23-cl1-typing-cast-path", "py", "import typing\nfrom pathlib import Path\nT = typing.cast(object, Path)\nT.replace(T('x.py'), 'cl1.py')", true},
		{"r11-24-jt1-array-destruct", "js", "const k = 'constr' + 'uctor';\nconst o = {};\nconst [A] = [o[k]];\nconst [F] = [A[k]];\nF('process.getBuiltin' + 'Module(\"fs\").mkdirSync(\"jt1\")')();", true},
		{"r11-24-jt2-for-of-destruct", "js", "const k = 'constr' + 'uctor';\nconst arr = {};\nfor (const A of [arr[k]]) for (const F of [A[k]]) F('process.getBuiltin' + 'Module(\"fs\").mkdirSync(\"jt2\")')();", true},
		{"r11-24-jt5-inst-this-sub", "js", "class C {\n  m() {\n    const k = 'constr' + 'uctor';\n    const [A] = [this[k]];\n    const [F] = [A[k]];\n    return F;\n  }\n}\nnew C().m()('1')();", true},
		{"r11-24-jt6-assign-destruct", "js", "const k = 'constr' + 'uctor';\nconst o = {};\nlet A, F;\n[A] = [o[k]];\n[F] = [A[k]];\nF('1')();", true},
		{"r11-24-jt8-object-values", "js", "const k = 'constr' + 'uctor';\nconst o = {};\nconst [A] = Object.values({a: o[k]});\nconst [F] = Object.values({a: A[k]});\nF('1')();", true},
		{"r11-24-jt15-static-this-sub", "js", "class C {\n  static m() {\n    const k = 'constr' + 'uctor';\n    const [F] = [this[k]];\n    return F;\n  }\n}\nconst [G] = [C.m()];\nG('process.getBuiltin' + 'Module(\"fs\").mkdirSync(\"jt15\")')();", true},
		{"r11-25-js-proc-env-alias", "js", "const e = process.env;\ne.PATH = 'bin:' + e.PATH;", true},
		{"r11-3-match-stmt-blocked-by-design", "py", "x = 3\nmatch x:\n    case 1:\n        print('one')\n    case _:\n        print('other')", true},
		{"allow-r8-open-read", "py", "print(open('/etc/hosts').read())", false},
		{"allow-r8-with-open", "py", "with open('/etc/hosts') as f:\n    print(f.read())", false},
		{"allow-r8-zipfile-namelist", "py", "import zipfile\nprint(zipfile.ZipFile('/tmp/x').namelist())", false},
		{"allow-r8-dict-open-kw", "py", "dict(open=True)\nprint('open(\"/tmp/x\",\"w\")')", false},
		{"allow-r8-utf8-str-comment", "py", "print('été')\n# café", false},
		{"allow-r8-fstring-cjk-key", "py", "d = {'键': 1}\nprint(f\"{d['键']}\")", false},
		{"allow-r8-json-load-open", "py", "import json\nconfig = json.load(open('c.json'))\nprint(config['x'])", false},
		{"allow-r8-sys-getattr-vars", "py", "import sys\nprint(getattr(sys, 'version', ''), vars(sys).get('platform'))", false},
		{"allow-r8-ast-walk-getattr", "py", "import ast\nfor n in ast.walk(ast.parse('x')):\n    print(getattr(n, 'lineno', None))", false},
		{"allow-r8-logging-info", "py", "import logging\nlog = logging.getLogger(__name__)\nlog.info('x')", false},
		{"allow-r8-stringio-alias", "py", "from io import StringIO as S\nprint(S('x').read())", false},
		{"allow-r8-js-cp-in-str", "js", "console.log('see child_process docs');", false},
		{"allow-r8-js-cp-in-comment", "js", "// do not use child_process here\nconsole.log(1);", false},
		{"allow-r8-js-regex-unicode", "js", "console.log(/\\u0077/.test('w'));", false},
		{"allow-r8-js-fs-readfilesync", "js", "console.log(require('fs').readFileSync('x.py', 'utf8'));", false},
		{"allow-r9-sqlite-noimport-1", "py", "sqlite3.connect('file:/tmp/x.db?mode=ro', uri=True)", false},
		{"allow-r9-sqlite-noimport-2", "py", "sqlite3.connect(database='file:/tmp/x.db?cache=shared&mode=ro', uri=True)", false},
		{"allow-r9-sqlite-noimport-frag", "py", "sqlite3.connect('file:/tmp/x.db?mode=ro#frag', uri=True)", false},
		{"allow-r9-sqlite-select", "py", "import sqlite3\nc = sqlite3.connect('file:in.db?mode=ro', uri=True)\nprint(c.execute('SELECT count(*) FROM sqlite_master').fetchall())", false},
		{"allow-r9-print-stderr", "py", "import sys\nprint('warn', file=sys.stderr)", false},
		{"allow-r9-stdout-write", "py", "import sys\nsys.stdout.write('x\\n')", false},
		{"allow-r9-sys-exit", "py", "import sys\nsys.exit(0)", false},
		{"allow-r9-json-load-stdin", "py", "import sys, json\ndata = json.load(sys.stdin)\nprint(len(data))", false},
		{"allow-r9-json-dump-stdout", "py", "import json, sys\njson.dump({'a': 1}, sys.stdout)", false},
		{"allow-r9-datetime-now", "py", "import datetime\nprint(datetime.datetime.now().isoformat())", false},
		{"allow-r9-date-today", "py", "import datetime\nprint(datetime.date.today())", false},
		{"allow-r9-type-exc-name", "py", "try:\n    int('x')\nexcept ValueError as exc:\n    print(type(exc).__name__, str(exc))", false},
		{"allow-r9-exc-class-name", "py", "try:\n    1/0\nexcept Exception as e:\n    print(e.__class__.__name__)", false},
		{"allow-r9-logging-streamhandler", "py", "import logging, sys\nlogging.getLogger().addHandler(logging.StreamHandler(sys.stderr))", false},
		{"allow-r9-js-proc-exit", "js", "if (!require('fs').existsSync('x.py')) process.exit(1);\nconsole.log('ok');", false},
		{"allow-r9-js-stderr-write", "js", "process.stderr.write('warn\\n');", false},
		{"allow-r10-datetime-replace", "py", "from datetime import datetime, timezone\nprint(datetime.now(timezone.utc).replace(microsecond=0).isoformat())", false},
		{"allow-r10-js-entries-destruct", "js", "for (const [k, v] of Object.entries({a: 1, b: 2})) console.log(k, v);", false},
		{"allow-r10-js-noimport-fs-sync", "js", "fs.readFileSync('/tmp/x');", false},
		{"allow-r10-js-noimport-fs-tmpl", "js", "`${fs.readFileSync('/tmp/x')}`;", false},
		{"allow-r10-js-noimport-fs-async", "js", "fs.readFile('/tmp/x', 'utf8', (err, d) => console.log(d));", false},
		{"allow-r10-py-noimport-gzip-rb", "py", "gzip.open('/tmp/x.gz', 'rb')", false},
		{"allow-r10-py-noimport-gzip-1arg", "py", "gzip.open('/tmp/x.gz')", false},
		{"allow-r10-py-noimport-bz2-rt", "py", "bz2.open('/tmp/x.bz2', 'rt')", false},
		{"allow-r10-user-class-stats", "py", "class Stats:\n    def __init__(self):\n        self.count = 0\n    def add(self):\n        self.count += 1\ns = Stats()\ns.add()\nprint(s.count)", false},
		{"allow-r10-namedtuple", "py", "import collections\nPoint = collections.namedtuple('Point', 'x y')\np = Point(1, 2)\nprint(p.x + p.y)", false},
		{"allow-r10-dataclass", "py", "from dataclasses import dataclass\n@dataclass\nclass P:\n    x: int\nprint(P(1).x)", false},
		{"allow-r10-max-dict-get", "py", "data = {'b': 2, 'a': 1}\nprint(max(data, key=data.get))", false},
		{"allow-r10-map-str-strip", "py", "print(list(map(str.strip, [' a ', 'b '])))", false},
		{"allow-r10-argparse-depth", "py", "import argparse\nap = argparse.ArgumentParser()\nap.add_argument('--depth', type=int, default=2)\nargs = ap.parse_args([])\nprint(args.depth)", false},
		{"allow-r10-js-for-arr-idx", "js", "const arr = [3, 1, 2];\nfor (let i = 0; i < arr.length; i++) console.log(arr[i]);", false},
		{"allow-r10-js-for-obj-keys", "js", "const obj = JSON.parse(require('fs').readFileSync('c.json', 'utf8'));\nfor (const k of Object.keys(obj)) console.log(k, obj[k]);", false},
		{"allow-r10-js-word-counts", "js", "const counts = {};\nfor (const w of 'a b a'.split(' ')) counts[w] = (counts[w] || 0) + 1;\nconsole.log(counts);", false},
		{"allow-r10-js-arr-destruct", "js", "const [a, b] = [1, 2];\nconsole.log(a + b);", false},
		{"allow-r10-js-regexp-exec", "js", "const re = /(\\w+)/g;\nlet m;\nwhile ((m = re.exec('a b')) !== null) console.log(m[1]);", false},
		{"allow-r10-js-class-this", "js", "class Box {\n  constructor(v) { this.v = v; }\n  get() { return this.v; }\n}\nconsole.log(new Box(3).get());", false},
		{"allow-r11-1-dbm-gnu-open-r", "py", "dbm.gnu.open('/tmp/d', 'r')", false},
		{"allow-r11-3-self-private-attr", "py", "class T:\n    def __init__(self):\n        self._v = 1\n    def get(self):\n        return self._v\nprint(T().get())", false},
		{"allow-r11-3-enum-subclass", "py", "import enum\nclass Color(enum.Enum):\n    RED = 1\nprint(Color.RED.name)", false},
		{"allow-r11-3-argparse-ns-listen", "py", "import argparse\nconfig = argparse.Namespace(listen=1)\nprint(config.listen)", false},
		{"allow-r11-4-re-match-var-group", "py", "import re\nmatch = re.match(r'(\\w+)', 'hello')\nmatch.group(0)\nprint(match.group(0))", false},
		{"allow-r11-isinstance-tuple-union", "py", "from pathlib import Path\np = Path('.')\nprint(isinstance(p, (int, Path)), isinstance(p, str | Path), isinstance(int, type))", false},
		{"r12-existing-dbm-flag-c", "py", "dbm.open('/tmp/d', flag='c')", true},
		{"r12-existing-dbm-var-flag", "py", "dbm.open('/tmp/d', f)", true},
		{"allow-r12-existing-path-open-empty", "py", "p.open()", false},
		{"allow-r12-existing-path-open-encoding", "py", "p.open(encoding='utf-8')", false},
		{"allow-r12-existing-dbm-flag-r", "py", "dbm.open('/tmp/d', flag='r')", false},
		{"allow-r12-existing-bn-js-row-index-var", "js", "const rows = [{n: 1}, {n: 2}];\nconst i = 1;\nconst r = rows[i];\nconsole.log(r.n);", false},
		{"allow-r12-existing-ua-ref-print-help", "py", "import argparse\nap = argparse.ArgumentParser()\nf = ap.format_help\nprint(f())", false},
		{"allow-r12-existing-cl-def-touch-name", "py", "from pathlib import Path\ndef owner():\n    pass\nprint(Path('x.py').owner())", false},
		{"allow-r12-existing-ua-zip-fp", "py", "import zipfile\nz = zipfile.ZipFile('in.zip')\nprint(z.fp.name)", false},
	}
	g := guardCall{strictReadonly: true, readonly: true}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lang := expandTestLang(c.lang)
			rule, detail := g.guardCtxRunCode(lang, c.code)
			blocked := rule != "" || detail != ""
			if blocked != c.deny {
				t.Fatalf("guardCtxRunCode(%q) blocked=%v (rule=%q detail=%q), want deny=%v\ncode:\n%s", lang, blocked, rule, detail, c.deny, c.code)
			}
			if c.deny && rule != ruleReadonlyWrite {
				t.Fatalf("expected rule=%q, got %q (detail=%q)", ruleReadonlyWrite, rule, detail)
			}
		})
	}
}

func TestR9_AllowlistSingleRuleMutations(t *testing.T) {
	type mutTC struct {
		name string
		lang string
		code string
		pref string
	}
	cases := []mutTC{
		{"mut-001", "perl", "my $x = 1;", "allowlist: [lang-legacy]"},
		{"mut-002", "py", "x = 1\fx = 2", "allowlist: [py-ctrl-char]"},
		{"mut-003", "py", "ｏ = 1", "allowlist: [py-non-ascii]"},
		{"mut-004", "py", "x = 1 \\ ", "allowlist: [py-stray-backslash]"},
		{"mut-005", "py", "x = 'unterminated", "allowlist: [py-unclosed-string]"},
		{"mut-006", "py", "x = f'{1'", "allowlist: [py-fstring-syntax]"},
		{"mut-007", "py", "x = $1", "allowlist: [py-unknown-char]"},
		{"mut-008", "py", "x = (1 + 2]", "allowlist: [py-delim-mismatch]"},
		{"mut-009", "py", "open('a.txt', 'r', opener=f)", "allowlist: [py-open-opener]"},
		{"mut-010", "py", "import zipfile\nzipfile.ZipFile('a.zip', m)", "allowlist: [py-archive-mode]"},
		{"mut-011", "py", "import gzip\ngzip.open('a.gz', m)", "allowlist: [py-open-mode]"},
		{"mut-012", "py", "import sqlite3\nsqlite3.connect('file:a.db', uri=True)", "allowlist: [py-sqlite-ro]"},
		{"mut-013", "py", "import logging\nlogging.StreamHandler(x)", "allowlist: [py-streamhandler-arg]"},
		{"mut-014", "py", "import logging\nlogging.basicConfig(x)", "allowlist: [py-basicconfig-arg]"},
		{"mut-015", "py", "import pprint\npprint.pprint(1, stream=x)", "allowlist: [py-pprint-stream]"},
		{"mut-016", "py", "import json\njson.dump(1, x)", "allowlist: [py-jsondump-fp]"},
		{"mut-017", "py", "# coding: unicode_escape\nx = 1", "allowlist: [py-coding-cookie]"},
		{"mut-018", "py", "from . import foo", "allowlist: [py-relative-import]"},
		{"mut-019", "py", "from math import *", "allowlist: [py-wildcard-import]"},
		{"mut-020", "py", "import marshal", "allowlist: [py-import-mod]"},
		{"mut-021", "py", "from marshal import loads", "allowlist: [py-from-mod]"},
		{"mut-022", "py", "from os import getuid", "allowlist: [py-from-member]"},
		{"mut-023", "py", "import 123", "allowlist: [py-import-syntax]"},
		{"mut-024", "py", "a = [1]\na.", "allowlist: [py-dot-syntax]"},
		{"mut-025", "py", "print(x.__dict__)", "allowlist: [py-dunder-attr]"},
		{"mut-026", "py", "print(__builtins__)", "allowlist: [py-dunder-ident]"},
		{"mut-027", "py", "self = 1", "allowlist: [py-self-rebind]"},
		{"mut-028", "py", "getattr = 1", "allowlist: [py-builtin-shadow]"},
		{"mut-029", "py", "import math\nmath = 1", "allowlist: [py-mod-rebind]"},
		{"mut-030", "py", "class C(list):\n    pass", "allowlist: [py-class-base]"},
		{"mut-031", "py", "del x.a", "allowlist: [py-del-attr]"},
		{"mut-032", "py", "import sys\nsys.version = '1'", "allowlist: [py-confined-attr-assign]"},
		{"mut-033", "py", "x._v = 1", "allowlist: [py-priv-attr-assign]"},
		{"mut-034", "py", "self_obj.makedir = 1", "allowlist: [py-stdlib-attr-assign]"},
		{"mut-035", "py", "match x:\n    case 1:\n        pass", "allowlist: [py-match-stmt]"},
		{"mut-036", "py", "isinstance(1)", "allowlist: [py-isinstance-call]"},
		{"mut-037", "py", "getattr(x, k)", "allowlist: [py-getattr-syntax]"},
		{"mut-038", "py", "import pathlib\ngetattr(pathlib.Path, 'name', '')", "allowlist: [py-getattr-confined-dot]"},
		{"mut-039", "py", "from pathlib import Path\ngetattr(Path, 'name', '')", "allowlist: [py-getattr-confined-sym]"},
		{"mut-040", "py", "import os\ngetattr(os, 'getuid')", "allowlist: [py-getattr-mod]"},
		{"mut-041", "py", "getattr(x, 'makedir', None)", "allowlist: [py-getattr-attr]"},
		{"mut-042", "py", "vars(x)", "allowlist: [py-vars-call]"},
		{"mut-043", "py", "print(dir(1))", "allowlist: [py-forbidden-ident]"},
		{"mut-044", "py", "from os import environ as E\nx = E", "allowlist: [py-environ-alias-use]"},
		{"mut-045", "py", "import math\nx = math", "allowlist: [py-mod-bare]"},
		{"mut-046", "py", "import os\nos.getuid()", "allowlist: [py-mod-member]"},
		{"mut-047", "py", "import os\nx = os.path", "allowlist: [py-submod-bare]"},
		{"mut-048", "py", "import os\ne = os.environ", "allowlist: [py-environ-use]"},
		{"mut-049", "py", "import sys\ns = sys.stdout", "allowlist: [py-stdio-use]"},
		{"mut-050", "py", "import sys\nsys.path.append('.')", "allowlist: [py-sys-path-mutate]"},
		{"mut-051", "py", "import math\nf = math.sqrt", "allowlist: [py-mod-callable]"},
		{"mut-052", "py", "import datetime\nd = datetime.datetime", "allowlist: [py-mod-valcls]"},
		{"mut-053", "py", "from pathlib import Path\nP = Path", "allowlist: [py-imp-callable]"},
		{"mut-054", "py", "from collections import Counter\nC = Counter", "allowlist: [py-imp-valcls]"},
		{"mut-055", "py", "f = open", "allowlist: [py-bare-open]"},
		{"mut-056", "py", "p = print", "allowlist: [py-print-bare]"},
		{"mut-057", "py", "print(1, file=x)", "allowlist: [py-print-file]"},
		{"mut-058", "py", "T = type(1)", "allowlist: [py-type-call]"},
		{"mut-059", "py", "x._foo()", "allowlist: [py-priv-method]"},
		{"mut-060", "py", "s.replace('a')", "allowlist: [py-replace-call]"},
		{"mut-061", "py", "d.copy('dst')", "allowlist: [py-copy-call]"},
		{"mut-062", "py", "z.printdir(x)", "allowlist: [py-printdir-file]"},
		{"mut-063", "py", "c.execute('CREATE TABLE t(x)')", "allowlist: [py-sqlite-sql]"},
		{"mut-064", "py", "t.makedir(ti, 'd')", "allowlist: [py-method-call]"},
		{"mut-065", "py", "print(x._v)", "allowlist: [py-priv-attr]"},
		{"mut-066", "py", "print(t.makedir)", "allowlist: [py-uncalled-attr]"},
		{"mut-067", "js", "const x = 1;\fconst y = 2;", "allowlist: [js-ctrl-char]"},
		{"mut-068", "js", "const 變數 = 1;", "allowlist: [js-non-ascii]"},
		{"mut-069", "js", "/* unclosed comment", "allowlist: [js-unclosed-comment]"},
		{"mut-070", "js", "const \\u0061 = 1;", "allowlist: [js-unicode-esc]"},
		{"mut-071", "js", "const x = 1; \\ ", "allowlist: [js-stray-bs]"},
		{"mut-072", "js", "const s = 'unclosed", "allowlist: [js-unclosed-string]"},
		{"mut-073", "js", "String`hello`;", "allowlist: [js-tagged-template]"},
		{"mut-074", "js", "const s = `unclosed", "allowlist: [js-unclosed-template]"},
		{"mut-075", "js", "const r = /abc", "allowlist: [js-unclosed-regex]"},
		{"mut-076", "js", "@dec", "allowlist: [js-unknown-char]"},
		{"mut-077", "js", "const a = [1, 2);", "allowlist: [js-delim-mismatch]"},
		{"mut-078", "js", "const m = 'path'; require(m);", "allowlist: [js-require-syntax]"},
		{"mut-079", "js", "const v = require('v8');", "allowlist: [js-require-mod]"},
		{"mut-080", "js", "const { ...r } = require('path');", "allowlist: [js-destruct-require-unconfined]"},
		{"mut-081", "js", "console.log(require('path'));", "allowlist: [js-require-unconfined]"},
		{"mut-082", "js", "console.log(a?.[0]);", "allowlist: [js-optchain-sub-call]"},
		{"mut-083", "js", "a.", "allowlist: [js-dot-syntax]"},
		{"mut-084", "js", "import('path');", "allowlist: [js-dynamic-import]"},
		{"mut-085", "js", "import x from 'path';", "allowlist: [js-esm-import]"},
		{"mut-086", "js", "with (a) {}", "allowlist: [js-with-stmt]"},
		{"mut-087", "js", "console.log(this);", "allowlist: [js-this-outside-class]"},
		{"mut-088", "js", "class C { m() { return this; } }", "allowlist: [js-this-non-dot]"},
		{"mut-089", "js", "console.log(typeof Proxy);", "allowlist: [js-forbidden-ident]"},
		{"mut-090", "js", "const { toString: f } = {};", "allowlist: [js-destruct-forbidden-prop]"},
		{"mut-091", "js", "let p = require('path'); p = 1;", "allowlist: [js-mod-rebind]"},
		{"mut-092", "js", "const p = require('path'); console.log(p);", "allowlist: [js-mod-bare]"},
		{"mut-093", "js", "const { join } = require('path'); const f = join;", "allowlist: [js-destruct-callable]"},
		{"mut-095", "js", "console.log(a.prototype);", "allowlist: [js-forbidden-prop]"},
		{"mut-096", "js", "a.lutimes(1, 2);", "allowlist: [js-method-call]"},
		{"mut-097", "js", "console.log(a[]);", "allowlist: [js-sub-empty]"},
		{"mut-098", "js", "console.log(a['x\\ny']);", "allowlist: [js-sub-escaped-key]"},
		{"mut-099", "js", "console.log(a['prototype']);", "allowlist: [js-sub-static-prop]"},
		{"mut-100", "js", "a['lutimes'](1, 2);", "allowlist: [js-sub-static-call]"},
		{"mut-101", "js", "a[k]();", "allowlist: [js-dynsub-call]"},
		{"mut-102", "js", "console.log(a.slice[k]);", "allowlist: [js-dynsub-method-prop]"},
		{"mut-103", "js", "const f = () => 0; console.log(f[k]);", "allowlist: [js-dynsub-base]"},
		{"mut-104", "js", "const [A] = [o[k]];", "allowlist: [js-dynsub-escape]"},
		{"mut-105", "js", "const { getFips } = require('crypto');", "allowlist: [js-destruct-require-prop]"},
		{"mut-106", "js", "const c = require('crypto'); c.getFips();", "allowlist: [js-mod-member]"},
		{"mut-107", "js", "const fs = require('fs'); fs.promises.lutimes('a', 1, 1);", "allowlist: [js-fs-promises-member]"},
		{"mut-108", "js", "const p = require('path'); const j = p.join;", "allowlist: [js-mod-callable]"},
		{"mut-109", "js", "console.log(process.title);", "allowlist: [js-process-member]"},
		{"mut-110", "js", "const s = process.stdout;", "allowlist: [js-process-stdio]"},
		{"mut-111", "js", "process.env.PATH = 'x';", "allowlist: [js-process-env-mutate]"},
		{"mut-112", "js", "const e = process.env;", "allowlist: [js-process-env-alias]"},
		{"mut-113", "js", "const f = process.cwd;", "allowlist: [js-process-callable]"},
	}
	g := guardCall{strictReadonly: true, readonly: true}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lang := expandTestLang(c.lang)
			hit := strictReadonlyCodeAllowlistHit(lang, c.code)
			if !strings.HasPrefix(hit, c.pref) {
				t.Fatalf("strictReadonlyCodeAllowlistHit(%q) = %q, want prefix %q", lang, hit, c.pref)
			}
			rule, detail := g.guardCtxRunCode(lang, c.code)
			if rule != ruleReadonlyWrite || detail == "" {
				t.Fatalf("guardCtxRunCode(%q) failed to block: rule=%q detail=%q", lang, rule, detail)
			}
		})
	}

	wiring := []mutTC{
		{"wire-py-hook", "py", "import marshal", "allowlist: [py-import-mod]"},
		{"wire-js-hook", "js", "const v = require('v8');", "allowlist: [js-require-mod]"},
		{"wire-ts-hook", "typescript", "const [A] = [o[k]];", "allowlist: [js-dynsub-escape]"},
		{"wire-cr-norm", "py", "# comment\rimport marshal", "allowlist: [py-import-mod]"},
		{"wire-coding-cookie", "py", "# -*- coding: latin-1 -*-\nx = 1", "allowlist: [py-coding-cookie]"},
		{"wire-legacy-r", "r", "x <- 1", "allowlist: [lang-legacy]"},
	}
	for _, w := range wiring {
		t.Run(w.name, func(t *testing.T) {
			lang := expandTestLang(w.lang)
			rule, detail := g.guardCtxRunCode(lang, w.code)
			if rule != ruleReadonlyWrite || !strings.HasPrefix(detail, w.pref) {
				t.Fatalf("wiring %s: rule=%q detail=%q, want prefix %q", w.name, rule, detail, w.pref)
			}
		})
	}

	t.Run("node-perm-tier-separation", func(t *testing.T) {
		flags, ok := strictReadonlyNodeExecFlags("javascript", true, true, true)
		if !ok || len(flags) != 2 || flags[0] != "--permission" || flags[1] != "--allow-fs-read=*" {
			t.Fatalf("unexpected local js flags: %v ok=%v", flags, ok)
		}
		if _, okTS := strictReadonlyNodeExecFlags("typescript", true, true, true); okTS {
			t.Fatal("typescript ts-node must not claim node --permission")
		}
		if _, okSSH := strictReadonlyNodeExecFlags("javascript", true, false, true); okSSH {
			t.Fatal("remote path must not claim node --permission")
		}
		if h := strictReadonlyCodeAllowlistHitWithNodePerm("javascript", "const v = o[k]; console.log(v);", true); h != "" {
			t.Fatalf("local node --permission tier should allow local data read: %q", h)
		}
		if h := strictReadonlyCodeAllowlistHitWithNodePerm("javascript", "const v = o[k]; v();", true); !strings.HasPrefix(h, "allowlist: [js-dynsub-taint-call]") {
			t.Fatalf("expected [js-dynsub-taint-call], got %q", h)
		}
	})

	t.Run("legacy-helper-wrappers", func(t *testing.T) {
		if got := jsUnicodeIdentEscapeHit("const \\u0061 = 1;"); got != "js unicode identifier escape" {
			t.Fatalf("jsUnicodeIdentEscapeHit(\\u0061) = %q", got)
		}
		if got := jsUnicodeIdentEscapeHit("console.log(/\\u0077/.test('w'));"); got != "" {
			t.Fatalf("jsUnicodeIdentEscapeHit(regex) = %q, want empty", got)
		}
		if got := pyMaskedNonASCIIIdentHit("ｏ = 1"); got != "python non-ASCII identifier" {
			t.Fatalf("pyMaskedNonASCIIIdentHit(fullwidth) = %q", got)
		}
		if got := pyMaskedNonASCIIIdentHit("x = 1\r\nｏ = 2"); got != "python non-ASCII identifier" {
			t.Fatalf("pyMaskedNonASCIIIdentHit(crlf+fullwidth) = %q", got)
		}
		if got := pyMaskedNonASCIIIdentHit("\xef\xbb\xbfprint('été')\n# café"); got != "" {
			t.Fatalf("pyMaskedNonASCIIIdentHit(bom+utf8-str-comment) = %q, want empty", got)
		}
	})
}
