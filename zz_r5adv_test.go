package main

// R5 audit adversarial probe (not for commit): full guard path.

import "testing"

type r5adv struct {
	id   string
	want string // "A" or "B"
	code string
}

var r5advCases = []r5adv{
	// ---- pure imports: must ALLOW ----
	{"P-paren-alias-comment", "A", "from logging.handlers import (\n  RotatingFileHandler as RFH,  # c\n)\n"},
	{"P-paren-alias-comment-crlf", "A", "from logging.handlers import (\r\n  RotatingFileHandler as RFH,  # c\r\n)\r\n"},
	{"P-def-indented-from", "A", "def f():\n    from logging.handlers import RotatingFileHandler\n    return 1\n"},
	{"P-try-indented-from", "A", "try:\n    from logging.handlers import RotatingFileHandler\nexcept ImportError:\n    pass\n"},
	{"P-if-inline-colon", "A", "if True: from logging import FileHandler\n"},
	{"P-class-body", "A", "class A:\n    from logging import FileHandler\n"},
	{"P-multi-names", "A", "from logging import FileHandler, StreamHandler\n"},
	{"P-paren-single-line", "A", "from logging import (FileHandler)\n"},
	{"P-paren-trailing-comment", "A", "from logging.handlers import (\n    RotatingFileHandler\n)  # trailing\n"},
	{"P-paren-first-line-names", "A", "from logging.handlers import (RotatingFileHandler,\n    WatchedFileHandler)\n"},
	{"P-from-dot", "A", "from . import FileHandler\n"},
	{"P-from-dotdot", "A", "from .. import FileHandler\n"},
	{"P-from-dot-mod", "A", "from .handlers import WatchedFileHandler\n"},
	{"P-crlf", "A", "from logging import FileHandler\r\n"},
	{"P-semi-after-other", "A", "import os; from logging import FileHandler\n"},
	{"P-semi-before-other", "A", "from logging import FileHandler; import os\n"},
	{"P-comment-import-word", "A", "from logging import FileHandler  # import x\n"},
	{"P-tabs", "A", "from\tlogging.handlers\timport\tRotatingFileHandler\n"},
	{"P-backslash-names", "A", "from logging.handlers import RotatingFileHandler,\\\n    WatchedFileHandler\n"},
	{"P-import-mod-as", "A", "import logging.handlers as lh\n"},
	{"P-import-a-b", "A", "import os, logging\n"},
	{"P-zip-alias", "A", "from zipfile import ZipFile as Z\n"},
	{"P-zip-indented-try", "A", "try:\n    from zipfile import ZipFile\nexcept Exception:\n    ZipFile = None\n"},
	{"P-paren-trailing-comma-crlf", "A", "from logging.handlers import (\r\n    RotatingFileHandler,\r\n    WatchedFileHandler,\r\n)\r\n"},
	{"P-paren-empty-line", "A", "from logging.handlers import (\n\n    RotatingFileHandler,\n\n)\n"},
	{"P-string-has-call", "A", "from logging import FileHandler\nprint('FileHandler(\"/tmp/x\")')\n"},
	// ---- runtime uses: must BLOCK ----
	{"B-def-import-call", "B", "def f():\n    import logging\n    logging.FileHandler('a.log')\n"},
	{"B-try-import-call", "B", "try:\n    import logging\n    logging.FileHandler('a.log')\nexcept Exception:\n    pass\n"},
	{"B-if-semi", "B", "if True:\n    import logging; logging.FileHandler('a.log')\n"},
	{"B-semi", "B", "import logging; logging.FileHandler('a.log')"},
	{"B-semi-nospace", "B", "from logging import FileHandler;FileHandler('a.log')"},
	{"B-bs-semi", "B", "from logging import FileHandler \\\n;FileHandler('a.log')\n"},
	{"B-paren1-newline-call", "B", "from logging.handlers import (RotatingFileHandler)\nRotatingFileHandler('a.log')\n"},
	{"B-paren1-semi-call", "B", "from logging.handlers import (RotatingFileHandler); RotatingFileHandler('a.log')\n"},
	{"B-parenML-semi-call", "B", "from logging.handlers import (\n    RotatingFileHandler,\n); RotatingFileHandler('a.log')\n"},
	{"B-paren1-crlf-call", "B", "from logging.handlers import (RotatingFileHandler)\r\nRotatingFileHandler('a.log')\r\n"},
	{"B-import-crlf-call", "B", "import logging\r\nlogging.FileHandler('a.log')\r\n"},
	{"B-comment-import-then-call", "B", "# import logging\nlogging.FileHandler('a.log')\n"},
	{"B-string-import-then-call", "B", "x = 'import'\nlogging.FileHandler('a.log')\n"},
	{"B-import-a-b-call", "B", "import os, logging\nlogging.FileHandler('a.log')\n"},
	{"B-mod-alias-call", "B", "import logging as L\nL.FileHandler('a.log')\n"},
	{"B-paren-wrapped-attr", "B", "import logging\nh = (logging\n  .FileHandler('a.log'))\n"},
	{"B-bs-attr", "B", "import logging\nlogging.\\\nFileHandler('a.log')\n"},
	{"B-bs-before-call-line", "B", "import logging \\\n\nlogging.FileHandler('a.log')\n"},
	{"B-ref-print", "B", "import logging\nprint(logging.FileHandler)\n"},
	{"B-list", "B", "import logging\n[logging.FileHandler('a.log')]\n"},
	{"B-call-arg-ml", "B", "from logging import FileHandler\nfoo(\n    FileHandler,\n)\n"},
	{"B-paren-ref-ml", "B", "from logging import FileHandler\n(\n    FileHandler\n)('a.log')\n"},
	{"B-paren-ref-1", "B", "from logging import FileHandler\n(FileHandler)('a.log')\n"},
	{"B-tuple-ref", "B", "from logging import FileHandler\nx = (FileHandler,)\nx[0]('a.log')\n"},
	{"B-lambda", "B", "from logging import FileHandler\nf = lambda: FileHandler('a.log')\n"},
	{"B-yield-from-bare", "B", "def g():\n    yield from FileHandler\n"},
	{"B-raise-from", "B", "raise X from FileHandler('a.log')\n"},
	{"B-ifinline-call", "B", "if True: FileHandler('a.log')\n"},
	{"B-else-inline-call", "B", "if 0: pass\nelse: FileHandler('a.log')\n"},
	{"B-from-imp-then-indented-call", "B", "from logging import FileHandler\nif True:\n    FileHandler('a.log')\n"},
	{"B-zip-bare-indented", "B", "import zipfile\nif True:\n    zipfile.ZipFile\n"},
	{"B-zip-paren-ctor", "B", "import zipfile\n(zipfile.ZipFile)('b.zip', 'w')\n"},
	{"B-zip-paren-ml-ctor", "B", "from zipfile import ZipFile\n(\n  ZipFile\n)('b.zip', 'w')\n"},
	{"B-zip-ref-in-call-ml", "B", "from zipfile import ZipFile\nf(\n  ZipFile,\n)\n"},
	{"B-fileio-bare", "B", "import io\nio.FileIO\n"},
	{"B-zip-semi-bare", "B", "import zipfile; zipfile.ZipFile\n"},
	{"B-watched-bs-call", "B", "from logging.handlers import WatchedFileHandler\nWatchedFileHandler \\\n('a.log')\n"},
	{"B-handler-import-then-from-call-same", "B", "from logging import FileHandler as F, FileHandler\nFileHandler('a.log')\n"},
	{"B-timed-call", "B", "import logging.handlers\nlogging.handlers.TimedRotatingFileHandler('a.log')\n"},
	{"B-walrus", "B", "import logging\n(h := logging.FileHandler('a.log'))\n"},
	{"B-decorator", "B", "import logging\n@logging.FileHandler\ndef f(): pass\n"},
	{"B-fstring", "B", "import logging\nf\"{logging.FileHandler('a.log')}\"\n"},
	// ---- semantic aliasing / other routes (design questions; expected BLOCK for fail-closed) ----
	{"S-from-alias-call", "B", "from logging import FileHandler as F\nF('/tmp/x.log')\n"},
	{"S-paren-alias-call", "B", "from logging.handlers import (\n  RotatingFileHandler as R,\n)\nR('/tmp/x.log')\n"},
	{"S-zip-alias-write", "B", "from zipfile import ZipFile as Z\nZ('/tmp/x.zip', 'w').writestr('a', 'b')\n"},
	{"S-fileio-alias-write", "B", "from io import FileIO as F\nF('/tmp/x', 'w').write(b'x')\n"},
	{"S-pyzip-alias-write", "B", "from zipfile import PyZipFile as P\nP('/tmp/x.zip', 'w')\n"},
	{"S-basicconfig-filename", "B", "import logging\nlogging.basicConfig(filename='/tmp/x.log')\nlogging.warning('x')\n"},
	{"S-getattr-handler", "B", "import logging\ngetattr(logging, 'FileHandler')('/tmp/x.log')\n"},
}

func TestAUProbeR5(t *testing.T) {
	for _, c := range r5advCases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			got := auGuard(t, auCase{id: c.id, role: "scout", lang: "python", cmd: c.code})
			auPrint("R5ADV-scout-"+c.want+"-"+c.id, "scout", got)
			got2 := auGuard(t, auCase{id: c.id, role: "worker", ro: "1", argv: []string{"python3", "-"}, stdin: c.code})
			auPrint("R5ADV-roworker-"+c.want+"-"+c.id, "worker", got2)
		})
	}
}
