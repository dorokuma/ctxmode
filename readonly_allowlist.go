package main

import (
	"path/filepath"
	"strings"
	"unicode"
)

// readonly_allowlist.go — default-deny allowlist for strict read-only roles.
//
// Every shell segment / argv that reaches the strict read-only guard must
// parse cleanly, name a command in this table, and carry only options the
// entry permits. Anything else fails closed with detail
// "not in readonly allowlist: <reason>". The legacy blacklist in
// screenReadonlyWrite still runs afterward as a second layer.

const allowlistDetailPrefix = "not in readonly allowlist: "

func allowlistDetail(reason string) string {
	if reason == "" {
		return allowlistDetailPrefix + "denied"
	}
	if strings.HasPrefix(reason, allowlistDetailPrefix) {
		return reason
	}
	return allowlistDetailPrefix + reason
}

// cmdAllow is the allowlist entry for one command basename.
type cmdAllow struct {
	shortBool  string          // bytes of allowed boolean short opts
	shortValue string          // bytes of short opts that take a value
	longBool   map[string]bool // --flag
	longValue  map[string]bool // --flag VAL / --flag=VAL
	// check, when non-nil, runs after generic option scanning (or alone when
	// no generic opts are configured) and receives the full argv.
	check func(argv []string) string
	// noPositional blocks any non-option operand.
	noPositional bool
}

func longSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// readonlyAllowlist maps command basename → policy.
var readonlyAllowlist = map[string]*cmdAllow{}

func init() {
	simple := func(shortBool, shortValue string, longBool, longValue []string) *cmdAllow {
		return &cmdAllow{
			shortBool:  shortBool,
			shortValue: shortValue,
			longBool:   longSet(longBool...),
			longValue:  longSet(longValue...),
		}
	}

	readonlyAllowlist["ls"] = simple("lahrtR1AUdvX", "",
		[]string{"all", "almost-all", "human-readable", "reverse", "recursive",
			"directory", "classify", "group-directories-first",
			"full-time", "inode", "size", "author", "help", "version", "color", "time"},
		[]string{"width", "tabsize", "block-size", "format", "sort",
			"quoting-style", "hide", "ignore", "indicator-style", "time-style"})
	readonlyAllowlist["cat"] = simple("nbsAET", "",
		[]string{"number", "number-nonblank", "squeeze-blank", "show-all",
			"show-ends", "show-tabs", "show-nonprinting", "help", "version"}, nil)
	readonlyAllowlist["head"] = simple("qvz", "nc",
		[]string{"quiet", "silent", "verbose", "zero-terminated", "help", "version"},
		[]string{"bytes", "lines"})
	// -f/-F/--follow block forever-follow; keep -n/-c value opts only.
	readonlyAllowlist["tail"] = simple("qvz", "nc",
		[]string{"quiet", "silent", "verbose", "zero-terminated", "help", "version"},
		[]string{"bytes", "lines", "sleep-interval", "max-unchanged-stats", "pid"})
	readonlyAllowlist["wc"] = simple("cmlLw", "",
		[]string{"bytes", "chars", "lines", "max-line-length", "words", "help", "version"}, nil)
	// shortBool / shortValue are explicit disjoint tables: boolean shorts must
	// NEVER appear in shortValue or scanAllowedOpts will swallow the next argv
	// (e.g. rg -n --pre=... used to skip --pre).
	readonlyAllowlist["rg"] = simple("ninlFvUHPcwoqsS", "egmABCtTM",
		[]string{"ignore-case", "line-number", "files-with-matches", "files-without-match",
			"fixed-strings", "vimgrep", "json", "pretty", "no-heading", "with-filename",
			"no-filename", "count", "stats", "help", "version", "hidden", "follow", "multiline",
			"word-regexp", "column", "only-matching", "quiet", "no-config", "no-ignore",
			"no-ignore-vcs", "pcre2", "files", "smart-case", "case-sensitive", "color"},
		[]string{"regexp", "file", "glob", "type", "type-add", "type-not", "max-count", "max-depth", "max-filesize",
			"context", "before-context", "after-context", "colors", "encoding",
			"replace", "sort", "sortr", "iglob", "ignore-file", "max-columns"})
	readonlyAllowlist["grep"] = simple("ninlFvwxqRHEor", "emABC",
		[]string{"ignore-case", "line-number", "files-with-matches", "files-without-match",
			"fixed-strings", "word-regexp", "line-regexp", "quiet", "silent", "recursive",
			"dereference-recursive", "extended-regexp", "perl-regexp", "basic-regexp",
			"help", "version", "count", "only-matching", "no-filename", "with-filename",
			"invert-match", "byte-offset", "null", "color"},
		[]string{"regexp", "file", "exclude", "exclude-dir", "include", "max-count",
			"context", "before-context", "after-context", "binary-files"})
	readonlyAllowlist["egrep"] = readonlyAllowlist["grep"]
	readonlyAllowlist["fgrep"] = readonlyAllowlist["grep"]
	readonlyAllowlist["stat"] = simple("ftLq", "c",
		[]string{"file-system", "filesystem", "terse", "dereference", "help", "version"},
		[]string{"format", "printf"})
	// Deny -s/--special-files/-z/--compressed/-m/--magic-file (side effects / decompressors).
	readonlyAllowlist["file"] = simple("bLk", "",
		[]string{"brief", "dereference", "keep-going",
			"help", "version", "mime", "mime-type", "mime-encoding", "raw"},
		[]string{"separator", "exclude"})
	readonlyAllowlist["du"] = simple("ahsdcHx", "B",
		[]string{"all", "human-readable", "summarize", "total", "bytes", "si",
			"dereference", "help", "version", "time"},
		[]string{"block-size", "max-depth", "exclude", "threshold", "time-style"})
	readonlyAllowlist["df"] = simple("ahTih", "",
		[]string{"all", "human-readable", "print-type", "inodes", "si", "help",
			"version", "total", "local", "portability"},
		[]string{"type", "exclude-type", "block-size", "output"})
	readonlyAllowlist["pwd"] = simple("LP", "", []string{"help", "version", "logical", "physical"}, nil)
	readonlyAllowlist["echo"] = simple("neE", "", []string{"help", "version"}, nil)
	readonlyAllowlist["printf"] = simple("", "", []string{"help", "version"}, nil)
	readonlyAllowlist["true"] = simple("", "", []string{"help", "version"}, nil)
	readonlyAllowlist["false"] = simple("", "", []string{"help", "version"}, nil)
	readonlyAllowlist["which"] = simple("a", "", []string{"all", "help", "version"}, nil)
	readonlyAllowlist["type"] = simple("afpP", "", nil, nil)
	readonlyAllowlist["date"] = simple("uR", "dfr",
		[]string{"utc", "universal", "rfc-email", "help", "version", "iso-8601"},
		[]string{"date", "file", "reference", "rfc-3339"})
	readonlyAllowlist["date"].check = func(argv []string) string {
		endOpts := false
		for _, a := range argv[1:] {
			if endOpts {
				if !strings.HasPrefix(a, "+") {
					return "date set"
				}
				continue
			}
			if a == "--" {
				endOpts = true
				continue
			}
			if a == "-s" || a == "--set" || strings.HasPrefix(a, "--set=") ||
				(strings.HasPrefix(a, "-s") && !strings.HasPrefix(a, "--") && a != "-s") {
				return "date set"
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				continue
			}
			if a != "-" && !strings.HasPrefix(a, "+") {
				return "date set"
			}
		}
		return ""
	}
	readonlyAllowlist["sort"] = simple("nruubczfR", "kt",
		[]string{"numeric-sort", "reverse", "unique", "ignore-leading-blanks",
			"ignore-case", "zero-terminated", "help", "version", "check", "merge",
			"stable", "random-sort", "general-numeric-sort", "human-numeric-sort",
			"version-sort", "month-sort"},
		[]string{"key", "field-separator", "buffer-size", "parallel", "random-source"})
	readonlyAllowlist["sort"].check = func(argv []string) string {
		for _, a := range argv[1:] {
			if a == "-o" || a == "--output" || strings.HasPrefix(a, "--output=") {
				return "sort output"
			}
		}
		return ""
	}
	readonlyAllowlist["uniq"] = simple("cudiz", "fws",
		[]string{"count", "repeated", "all-repeated", "ignore-case", "unique",
			"zero-terminated", "help", "version", "group"},
		[]string{"skip-fields", "skip-chars", "check-chars"})
	readonlyAllowlist["uniq"].check = func(argv []string) string {
		// uniq [INPUT [OUTPUT]]: second positional overwrites OUTPUT.
		pos := 0
		endOpts := false
		for i := 1; i < len(argv); i++ {
			a := argv[i]
			if endOpts {
				pos++
				continue
			}
			if a == "--" {
				endOpts = true
				continue
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				// value-taking shorts already consumed by scanAllowedOpts; here
				// just skip flags. Glued long values handled above.
				if strings.HasPrefix(a, "--") {
					name := a[2:]
					if eq := strings.IndexByte(name, '='); eq >= 0 {
						continue
					}
					if readonlyAllowlist["uniq"].longValue[name] {
						i++
					}
					continue
				}
				// short cluster: if last char is value-taking and no glued val, skip next
				last := a[len(a)-1]
				if strings.IndexByte(readonlyAllowlist["uniq"].shortValue, last) >= 0 && len(a) == 2 {
					i++
				}
				continue
			}
			pos++
		}
		if pos > 1 {
			return "uniq output"
		}
		return ""
	}
	readonlyAllowlist["cut"] = simple("snz", "fdbc",
		[]string{"only-delimited", "complement", "zero-terminated", "help", "version"},
		[]string{"characters", "bytes", "fields", "delimiter", "output-delimiter"})
	readonlyAllowlist["tr"] = simple("cdst", "",
		[]string{"complement", "delete", "squeeze-repeats", "truncate-set1", "help", "version"}, nil)
	readonlyAllowlist["jq"] = simple("ncrRMSes", "f",
		[]string{"null-input", "compact-output", "raw-output", "raw-input", "slurp",
			"seq", "sort-keys", "tab", "ascii-output", "color-output", "monochrome-output",
			"help", "version", "exit-status"},
		[]string{"from-file", "indent"})
	readonlyAllowlist["diff"] = simple("urNqbwBy", "",
		[]string{"unified", "recursive", "new-file", "brief", "ignore-space-change",
			"ignore-all-space", "ignore-blank-lines", "side-by-side", "help", "version",
			"report-identical-files", "normal", "color"},
		[]string{"context", "exclude", "exclude-from", "label", "width"})
	readonlyAllowlist["cmp"] = simple("bls", "in",
		[]string{"print-bytes", "quiet", "silent", "verbose", "help", "version"},
		[]string{"ignore-initial", "bytes"})
	readonlyAllowlist["tree"] = simple("adflnhFC", "L",
		[]string{"help", "version", "dirsfirst", "noreport"},
		[]string{"filelimit", "charset"})
	readonlyAllowlist["realpath"] = simple("eqzs", "",
		[]string{"canonicalize-existing", "canonicalize-missing", "quiet", "silent",
			"strip", "no-symlinks", "zero", "help", "version"},
		[]string{"relative-to", "relative-base"})
	readonlyAllowlist["basename"] = simple("az", "s",
		[]string{"multiple", "zero", "help", "version"}, []string{"suffix"})
	readonlyAllowlist["dirname"] = simple("z", "", []string{"zero", "help", "version"}, nil)
	readonlyAllowlist["readlink"] = simple("efmnqsz", "",
		[]string{"canonicalize", "canonicalize-existing", "canonicalize-missing",
			"no-newline", "quiet", "silent", "verbose", "zero", "help", "version"}, nil)
	readonlyAllowlist["md5sum"] = simple("bctwz", "",
		[]string{"binary", "check", "tag", "text", "quiet", "status", "warn", "strict",
			"zero", "help", "version"}, nil)
	readonlyAllowlist["sha256sum"] = readonlyAllowlist["md5sum"]
	readonlyAllowlist["sha1sum"] = readonlyAllowlist["md5sum"]
	readonlyAllowlist["sha512sum"] = readonlyAllowlist["md5sum"]
	readonlyAllowlist["strings"] = simple("o", "ant",
		[]string{"all", "print-file-name", "help", "version"},
		[]string{"bytes", "radix", "encoding", "output-separator"})
	readonlyAllowlist["objdump"] = simple("dshxtrRw", "j",
		[]string{"disassemble", "disassemble-all", "section-headers", "headers",
			"reloc", "dynamic-reloc", "syms", "help", "version", "source", "line-numbers", "demangle"},
		[]string{"section", "start-address", "stop-address", "disassembler-options"})
	readonlyAllowlist["readelf"] = simple("ahSnldseWI", "",
		[]string{"all", "headers", "file-header", "section-headers", "sections", "syms",
			"symbols", "relocs", "dynamic", "notes", "version-info", "help", "version", "wide", "demangle"},
		[]string{"hex-dump", "string-dump", "debug-dump"})
	readonlyAllowlist["ps"] = simple("eflAuxHw", "o",
		[]string{"help", "version", "forest", "threads"},
		[]string{"pid", "ppid", "user", "format", "sort", "tty", "cols", "columns", "width"})
	readonlyAllowlist["pgrep"] = simple("alfnvx", "PugGsdte",
		[]string{"list-name", "list-full", "full", "inverse", "newest", "oldest",
			"exact", "help", "version", "count", "ignore-case"},
		[]string{"parent", "uid", "euid", "gid", "group", "session", "terminal", "delimiter"})
	readonlyAllowlist["ss"] = simple("antuplreo", "",
		[]string{"all", "numeric", "tcp", "udp", "listening", "processes", "resolve",
			"extended", "options", "memory", "info", "summary", "help", "version", "ipv4", "ipv6"},
		[]string{"query", "family", "filter"})
	readonlyAllowlist["journalctl"] = simple("exqrb", "unSo",
		[]string{"no-pager", "catalog", "disk-usage", "help", "version", "list-boots",
			"reverse", "utc", "quiet", "pager-end", "merge", "system", "user",
			"dmesg", "boot"},
		[]string{"unit", "user-unit", "identifier", "priority", "grep", "output",
			"directory", "since", "until", "lines", "facility"})
	readonlyAllowlist["systemctl"] = &cmdAllow{
		shortBool: "qal",
		longBool:  longSet("no-pager", "no-legend", "all", "full", "failed", "quiet", "help", "version", "user", "system"),
		longValue: longSet("type", "state", "property"),
		check:     checkSystemctlReadonly,
	}
	readonlyAllowlist["gofmt"] = &cmdAllow{
		check: func(argv []string) string {
			for _, a := range argv[1:] {
				if a == "-w" || strings.HasPrefix(a, "-w=") {
					return "gofmt -w"
				}
				// allow common read flags; unknown non-dash already files
				if strings.HasPrefix(a, "-") && a != "--" {
					switch a {
					case "-d", "-r", "-e", "-l", "-s", "-p":
						continue
					default:
						return "gofmt " + a
					}
				}
			}
			return ""
		},
	}

	readonlyAllowlist["find"] = &cmdAllow{check: checkFindReadonly}
	readonlyAllowlist["sed"] = &cmdAllow{check: checkSedReadonly}
	readonlyAllowlist["gsed"] = readonlyAllowlist["sed"]
	readonlyAllowlist["git"] = &cmdAllow{check: checkGitReadonly}
	readonlyAllowlist["go"] = &cmdAllow{check: checkGoReadonly}
	readonlyAllowlist["herdr"] = &cmdAllow{check: checkHerdrReadonly}
	readonlyAllowlist["mount"] = &cmdAllow{check: checkMountReadonly}
	readonlyAllowlist["kill"] = &cmdAllow{check: checkKillReadonly}
	readonlyAllowlist["ctxmode"] = &cmdAllow{check: checkCtxmodeReadonly}
	// Deleted from strict allowlist (prefer misblock): shells, python*, tar/unzip/
	// compressors, sqlite3, curl, cd/read/((, gcc/make family, git-fsck.
}

func checkSystemctlReadonly(argv []string) string {
	// Narrow: only status / is-active / is-enabled / list-units / show.
	// longValue options (--type/--state/--property) must skip their value
	// so `--property status` cannot masquerade as the subcommand and
	// `--type service list-units` is not misread as subcommand "service".
	args := argv[1:]
	longValue := map[string]bool{"type": true, "state": true, "property": true}
	sub := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			continue
		}
		if strings.HasPrefix(a, "--") {
			name := a[2:]
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
			} else if longValue[name] {
				i++ // skip value
			}
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			continue
		}
		sub = a
		break
	}
	if sub == "" {
		return ""
	}
	switch sub {
	case "status", "is-active", "is-enabled", "list-units", "show",
		"help", "--help", "-h":
		return ""
	default:
		return "systemctl " + sub
	}
}

func checkFindReadonly(argv []string) string {
	args := argv[1:]
	for _, a := range args {
		switch a {
		case "-exec", "-execdir", "-ok", "-okdir":
			return "find " + a
		case "-delete", "-fprint", "-fprint0", "-fprintf", "-fls":
			return "find " + a
		}
	}
	allowed := map[string]bool{
		"print": true, "print0": true, "ls": true, "quit": true, "help": true, "version": true,
		"true": true, "false": true, "name": true, "iname": true, "path": true, "ipath": true,
		"regex": true, "iregex": true, "type": true, "size": true, "mtime": true, "mmin": true,
		"ctime": true, "cmin": true, "atime": true, "amin": true, "uid": true, "gid": true,
		"user": true, "group": true, "perm": true, "links": true, "empty": true, "readable": true,
		"writable": true, "executable": true, "newer": true, "maxdepth": true, "mindepth": true,
		"depth": true, "xdev": true, "mount": true, "follow": true, "noleaf": true,
		"daystart": true, "regextype": true, "printf": true, "and": true, "or": true, "not": true,
		"samefile": true, "inum": true, "used": true, "xtype": true, "lname": true, "ilname": true,
		"nouser": true, "nogroup": true, "fstype": true, "cnewer": true, "anewer": true,
		"wholename": true, "iwholename": true, "warn": true, "nowarn": true,
		"H": true, "L": true, "P": true, "D": true, "O": true, "a": true, "o": true,
	}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(a, "--"), "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		if !allowed[name] {
			return "find unknown " + a
		}
	}
	return ""
}

func checkSedReadonly(argv []string) string {
	// Only: sed -n '<digits>p' file...  or  sed -n '<digits>,<digits>p' file...
	// Script must match ^[0-9]+(,[0-9]+)?p$ ; only -n allowed among options.
	args := argv[1:]
	if len(args) == 0 {
		return "sed"
	}
	i := 0
	sawN := false
	script := ""
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if a == "-n" || a == "--quiet" || a == "--silent" {
			sawN = true
			i++
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			return "sed flag " + a
		}
		break
	}
	if !sawN {
		return "sed requires -n"
	}
	if i >= len(args) {
		return "sed missing script"
	}
	script = args[i]
	i++
	if !sedReadonlyPrintScript(script) {
		return "sed script"
	}
	// remaining must be file operands (no more options)
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			return "sed flag after script"
		}
	}
	return ""
}

func sedReadonlyPrintScript(script string) bool {
	if script == "" {
		return false
	}
	// ^[0-9]+(,[0-9]+)?p$
	n := len(script)
	i := 0
	if i >= n || script[i] < '0' || script[i] > '9' {
		return false
	}
	for i < n && script[i] >= '0' && script[i] <= '9' {
		i++
	}
	if i < n && script[i] == ',' {
		i++
		if i >= n || script[i] < '0' || script[i] > '9' {
			return false
		}
		for i < n && script[i] >= '0' && script[i] <= '9' {
			i++
		}
	}
	return i == n-1 && script[i] == 'p'
}

func checkGitReadonly(argv []string) string {
	args := argv[1:]
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-C":
			if i+1 >= len(args) {
				return "git -C missing"
			}
			i += 2
		case a == "-c":
			return "git -c"
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			return "git -c"
		case a == "--git-dir" || a == "--work-tree" || a == "--namespace":
			if i+1 >= len(args) {
				return "git opt missing"
			}
			i += 2
		case strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") ||
			strings.HasPrefix(a, "--namespace="):
			i++
		case a == "--exec-path" || strings.HasPrefix(a, "--exec-path="):
			return "git --exec-path"
		case a == "--bare" || a == "--no-pager" || a == "-P" || a == "--paginate" ||
			a == "--no-replace-objects" || a == "--help" || a == "-h" || a == "--version":
			i++
		case strings.HasPrefix(a, "--"):
			name := a[2:]
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
			}
			switch name {
			case "no-pager", "paginate", "bare", "help", "version", "git-dir", "work-tree",
				"namespace", "no-replace-objects", "literal-pathspecs", "glob-pathspecs",
				"noglob-pathspecs", "icase-pathspecs":
				if (name == "git-dir" || name == "work-tree" || name == "namespace") && !strings.Contains(a, "=") {
					i += 2
					continue
				}
				i++
			default:
				return "git unknown global " + a
			}
		case strings.HasPrefix(a, "-"):
			return "git unknown global " + a
		default:
			goto sub
		}
	}
	return ""
sub:
	if i >= len(args) {
		return ""
	}
	sub := args[i]
	rest := args[i+1:]
	for _, a := range rest {
		if a == "--output" || strings.HasPrefix(a, "--output=") {
			return "git " + sub + " --output"
		}
		if a == "--ext-diff" || a == "--textconv" {
			return "git " + sub + " " + a
		}
	}
	switch sub {
	case "log", "show", "diff", "status", "blame", "grep", "rev-parse",
		"ls-files", "ls-tree", "cat-file", "for-each-ref",
		"describe", "shortlog", "count-objects", "check-ignore",
		"var", "name-rev", "rev-list", "merge-base":
		return gitOptsAllow(sub, rest)
	case "reflog":
		// Skip leading flags; only bare or "show" (help) are read-only.
		j := 0
		for j < len(rest) {
			a := rest[j]
			if a == "--" {
				j++
				break
			}
			if !strings.HasPrefix(a, "-") || a == "-" {
				break
			}
			// value-taking shorts commonly used with reflog listing
			if a == "-n" || a == "--max-count" || strings.HasPrefix(a, "--max-count=") {
				if !strings.Contains(a, "=") && a != "--max-count=" {
					j += 2
					continue
				}
			}
			if strings.HasPrefix(a, "-n") && a != "-n" && !strings.HasPrefix(a, "--") {
				j++
				continue
			}
			j++
		}
		if j >= len(rest) {
			return gitOptsAllow(sub, rest)
		}
		sub2 := rest[j]
		if sub2 == "show" || sub2 == "-h" || sub2 == "--help" {
			return gitOptsAllow(sub, rest)
		}
		return "git reflog " + sub2
	case "branch":
		return gitBranchAllow(rest)
	case "tag":
		return gitTagAllow(rest)
	case "config":
		return gitConfigAllow(rest)
	case "remote":
		return gitRemoteAllow(rest)
	case "worktree":
		return gitWorktreeAllow(rest)
	case "stash":
		return gitStashAllow(rest)
	case "submodule":
		if len(rest) == 0 || rest[0] == "status" || rest[0] == "--help" || rest[0] == "-h" {
			return ""
		}
		return "git submodule " + rest[0]
	case "help", "version":
		return ""
	default:
		return "git " + sub
	}
}

func gitOptsAllow(sub string, rest []string) string {
	for _, a := range rest {
		if a == "--" || !strings.HasPrefix(a, "-") {
			continue
		}
		if a == "--output" || strings.HasPrefix(a, "--output=") ||
			a == "--exec-path" || strings.HasPrefix(a, "--exec-path=") ||
			strings.Contains(a, "upload-pack") || strings.Contains(a, "receive-pack") ||
			strings.HasPrefix(a, "--exec") {
			return "git " + sub + " " + a
		}
		// git grep -O/--open-files-in-pager executes an external program.
		if sub == "grep" {
			if a == "-O" || strings.HasPrefix(a, "-O") && !strings.HasPrefix(a, "--") ||
				a == "--open-files-in-pager" || strings.HasPrefix(a, "--open-files-in-pager=") {
				return "git grep open-files-in-pager"
			}
		}
	}
	return ""
}

func gitBranchAllow(rest []string) string {
	writeFlags := map[string]bool{
		"-d": true, "-D": true, "-m": true, "-M": true, "-c": true, "-C": true,
		"--delete": true, "--move": true, "--copy": true, "--set-upstream-to": true,
		"--unset-upstream": true, "-f": true, "--force": true, "--edit-description": true,
	}
	hasOperand := false
	query := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if writeFlags[a] || strings.HasPrefix(a, "--set-upstream-to=") {
			return "git branch " + a
		}
		switch a {
		case "-a", "--all", "-r", "--remotes", "-l", "--list",
			"--contains", "--no-contains",
			"--merged", "--no-merged", "--points-at", "-h", "--help":
			query = true
			switch a {
			case "--contains", "--no-contains", "--merged", "--no-merged", "--points-at":
				i++
			}
			continue
		case "-v", "-vv", "--verbose", "-q", "--quiet", "--color", "--no-color",
			"--column", "--no-column", "--sort", "--format":
			// Modifiers only — do not alone authorize branch creation.
			if a == "--sort" || a == "--format" {
				i++
			}
			continue
		}
		if strings.HasPrefix(a, "--contains=") || strings.HasPrefix(a, "--merged=") ||
			strings.HasPrefix(a, "--points-at=") {
			query = true
			continue
		}
		if strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--format=") ||
			strings.HasPrefix(a, "--color=") {
			// modifiers with values — not query flags
			continue
		}
		if strings.HasPrefix(a, "-") {
			return "git branch unknown " + a
		}
		hasOperand = true
	}
	if hasOperand && !query {
		return "git branch create"
	}
	return ""
}

func gitTagAllow(rest []string) string {
	for _, a := range rest {
		switch a {
		case "-d", "--delete", "-f", "--force", "-a", "--annotate", "-s", "--sign",
			"-u", "--local-user", "-m", "--message", "-F", "--file", "-e", "--edit":
			return "git tag " + a
		}
		if strings.HasPrefix(a, "--local-user=") || strings.HasPrefix(a, "--message=") ||
			strings.HasPrefix(a, "--file=") {
			return "git tag write"
		}
	}
	listish := false
	hasOperand := false
	for _, a := range rest {
		switch a {
		case "-l", "--list", "-n", "-n1", "-n2", "-n3", "--contains", "--points-at",
			"--merged", "--no-merged", "--verify", "-v",
			"-h", "--help":
			listish = true
			continue
		case "--color", "--no-color", "-i", "--ignore-case", "--format", "--sort":
			// modifiers only — do not authorize tag creation
			continue
		}
		if strings.HasPrefix(a, "-n") || strings.HasPrefix(a, "--contains=") {
			listish = true
			continue
		}
		if strings.HasPrefix(a, "--format=") || strings.HasPrefix(a, "--sort=") {
			continue
		}
		if strings.HasPrefix(a, "-") {
			return "git tag unknown " + a
		}
		hasOperand = true
	}
	if hasOperand && !listish {
		return "git tag create"
	}
	return ""
}

func gitConfigAllow(rest []string) string {
	hasGet := false
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch a {
		case "--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list",
			"-h", "--help":
			hasGet = true
			continue
		case "--global", "--system", "--local", "--worktree", "--includes", "--no-includes",
			"--name-only", "--show-origin", "--show-scope":
			// Scope / display modifiers only — require an explicit get/list action.
			continue
		case "--get-color", "--get-colorbool":
			hasGet = true
			i++
			continue
		case "-e", "--edit", "--add", "--replace-all", "--unset", "--unset-all",
			"--rename-section", "--remove-section":
			return "git config " + a
		}
		if strings.HasPrefix(a, "--file") || a == "-f" {
			return "git config --file"
		}
		if strings.HasPrefix(a, "-") {
			return "git config unknown " + a
		}
		// positional key/value: only OK after an explicit get/list flag
		if !hasGet {
			return "git config write"
		}
	}
	if !hasGet {
		return "git config"
	}
	return ""
}

func gitRemoteAllow(rest []string) string {
	if len(rest) == 0 {
		return ""
	}
	sub := rest[0]
	if strings.HasPrefix(sub, "-") {
		switch sub {
		case "-v", "--verbose", "-h", "--help":
			return gitRemoteAllow(rest[1:])
		default:
			return "git remote " + sub
		}
	}
	switch sub {
	case "get-url", "help":
		return ""
	case "show", "add", "remove", "rm", "rename", "set-url", "set-branches", "set-head", "prune", "update":
		return "git remote " + sub
	default:
		return "git remote " + sub
	}
}

func gitWorktreeAllow(rest []string) string {
	j := 0
	for j < len(rest) {
		a := rest[j]
		if a == "--" {
			j++
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		j++
	}
	if j >= len(rest) {
		return "git worktree"
	}
	sub := rest[j]
	switch sub {
	case "list", "-h", "--help":
		return ""
	case "add", "remove", "rm", "prune", "move", "lock", "unlock", "repair":
		return "git worktree " + sub
	default:
		return "git worktree " + sub
	}
}

func gitStashAllow(rest []string) string {
	// Bare `git stash` is `git stash push` — deny. Require explicit list/show.
	// Flags like -q/--quiet may precede the subcommand (`git stash -q list`).
	if len(rest) == 0 {
		return "git stash"
	}
	i := 0
	for i < len(rest) {
		a := rest[i]
		switch a {
		case "-q", "--quiet", "-v", "--verbose", "--color", "--no-color", "-h", "--help":
			i++
			continue
		}
		if strings.HasPrefix(a, "--color=") {
			i++
			continue
		}
		break
	}
	if i >= len(rest) {
		return "git stash"
	}
	sub := rest[i]
	switch sub {
	case "list", "show", "-h", "--help":
		return ""
	case "push", "pop", "apply", "drop", "clear", "create", "store", "branch", "save":
		return "git stash " + sub
	default:
		if strings.HasPrefix(sub, "-") {
			return "git stash " + sub
		}
		return "git stash " + sub
	}
}

func checkCurlReadonly(argv []string) string {
	// Tiny readonly allowlist: -s -S -f -L -I -i -m/--max-time
	// --connect-timeout -k -H/--header (value must not start with @)
	// -X/--request GET|HEAD. Everything else fails closed.
	args := argv[1:]
	longBool := map[string]bool{
		"silent": true, "show-error": true, "fail": true,
		"location": true, "head": true, "include": true,
		"insecure": true, "help": true, "manual": true, "version": true,
	}
	longValue := map[string]bool{
		"header": true, "max-time": true, "connect-timeout": true, "request": true,
	}
	shortBool := map[byte]bool{
		's': true, 'S': true, 'f': true, 'L': true, 'I': true, 'i': true, 'k': true,
	}
	shortValue := map[byte]bool{
		'H': true, 'm': true, 'X': true,
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			for _, p := range args[i+1:] {
				if strings.HasPrefix(p, "@") {
					return "curl @file"
				}
			}
			continue
		}
		if strings.HasPrefix(a, "@") {
			return "curl @file"
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			continue // URL / positional
		}
		if strings.HasPrefix(a, "--") {
			name := a[2:]
			valGlued := ""
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				valGlued = name[eq+1:]
				name = name[:eq]
			}
			if longBool[name] {
				continue
			}
			if longValue[name] {
				val := valGlued
				if val == "" {
					if i+1 >= len(args) {
						return "curl --" + name + " missing"
					}
					i++
					val = args[i]
				}
				if strings.HasPrefix(val, "@") {
					return "curl @file"
				}
				if name == "request" {
					m := strings.ToUpper(val)
					if m != "GET" && m != "HEAD" {
						return "curl method " + m
					}
				}
				continue
			}
			return "curl unknown --" + name
		}
		// short cluster
		for j := 1; j < len(a); j++ {
			ch := a[j]
			if shortValue[ch] {
				tail := a[j+1:]
				var val string
				if tail != "" {
					val = tail
					j = len(a)
				} else if i+1 < len(args) {
					i++
					val = args[i]
					j = len(a)
				} else {
					return "curl -" + string(ch) + " missing"
				}
				if strings.HasPrefix(val, "@") {
					return "curl @file"
				}
				if ch == 'X' {
					m := strings.ToUpper(val)
					if m != "GET" && m != "HEAD" {
						return "curl method " + m
					}
				}
				continue
			}
			if shortBool[ch] {
				continue
			}
			return "curl unknown -" + string(ch)
		}
	}
	return ""
}

func checkSqliteReadonly(argv []string) string {
	args := argv[1:]
	hasRO := false
	hasSafe := false
	var sqlParts []string
	endOpts := false
	sawDB := false
	sawMeta := false // --version / --help
	onlyMeta := true // no DB / SQL / other operational flags
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !endOpts {
			switch {
			case a == "--":
				endOpts = true
				continue
			case a == "-readonly" || a == "-read-only" || a == "--readonly" || a == "--read-only":
				hasRO = true
				onlyMeta = false
				continue
			case a == "-safe" || a == "--safe":
				hasSafe = true
				onlyMeta = false
				continue
			case a == "-version" || a == "--version" || a == "-help" || a == "--help":
				sawMeta = true
				continue
			case a == "-bail" || a == "-batch" || a == "-csv" || a == "-html" || a == "-json" ||
				a == "-list" || a == "-line" || a == "-markdown" || a == "-table" || a == "-box" ||
				a == "-ascii" || a == "-noheader" || a == "-header" || a == "-tabs" ||
				a == "-stats" || a == "-echo":
				onlyMeta = false
				continue
			case a == "-separator" || a == "-nullvalue" || a == "-cmd" || a == "-init":
				return "sqlite3 " + a
			case strings.HasPrefix(a, "-"):
				return "sqlite3 unknown " + a
			}
		}
		if !sawDB {
			sawDB = true
			onlyMeta = false
			if strings.HasPrefix(a, "file:") {
				if !sqliteURIModeRO(a) || sqliteURIHasRW(a) {
					return "sqlite3 uri not ro"
				}
			}
			continue
		}
		sqlParts = append(sqlParts, a)
		onlyMeta = false
	}
	// version/help alone (no DB operand) needs no -readonly/-safe.
	if sawMeta && onlyMeta && !sawDB && len(sqlParts) == 0 {
		return ""
	}
	// -safe is mandatory (disables writefile/edit/load_extension/.shell).
	// -readonly alone is not enough; -safe alone is accepted (sqlite docs).
	_ = hasRO
	if !hasSafe {
		return "sqlite3 missing -safe"
	}
	// Fail closed without an explicit SQL positional.
	if len(sqlParts) == 0 {
		return "sqlite3 missing sql"
	}
	return sqliteSQLReadonlyAllow(strings.Join(sqlParts, " "))
}

// sqliteDangerousFuncs are SQLite extension / CLI function names that write
// files or load code even under -readonly. Rejected as a lexical belt-and-
// suspenders on top of the required -safe flag.
var sqliteDangerousFuncs = []string{
	"WRITEFILE", "READFILE", "EDIT", "LOAD_EXTENSION", "FTS3_TOKENIZER",
}

// sqliteSQLReadonlyAllow fail-closes on any line-leading dot-command and only
// allows statements that begin with SELECT / WITH / EXPLAIN / PRAGMA
// (PRAGMA without '=' assignment). Also lexically rejects dangerous function
// names. Statements are split on ';' outside quotes/comments.
func sqliteSQLReadonlyAllow(sql string) string {
	// Dot-commands: only detect at line start (after trim), independent of ';' split.
	for _, line := range strings.Split(sql, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, ".") {
			return "sqlite3 dot-command"
		}
	}
	for _, raw := range splitSQLiteStatements(sql) {
		stmt := strings.TrimSpace(raw)
		if stmt == "" {
			continue
		}
		// Strip leading /* */ and -- comments for prefix check.
		stmt = sqliteStripLeadingComments(stmt)
		if stmt == "" {
			continue
		}
		if strings.HasPrefix(stmt, ".") {
			return "sqlite3 dot-command"
		}
		upper := strings.ToUpper(stmt)
		for _, fn := range sqliteDangerousFuncs {
			if containsSQLKeyword(upper, fn) {
				return "sqlite3 dangerous func"
			}
		}
		switch {
		case sqliteStmtHasPrefix(upper, "SELECT"),
			sqliteStmtHasPrefix(upper, "WITH"),
			sqliteStmtHasPrefix(upper, "EXPLAIN"):
			continue
		case sqliteStmtHasPrefix(upper, "PRAGMA"):
			if strings.Contains(stmt, "=") {
				return "sqlite3 pragma assign"
			}
			continue
		default:
			return "sqlite3 sql not readonly"
		}
	}
	return ""
}

func sqliteStripLeadingComments(stmt string) string {
	for {
		stmt = strings.TrimSpace(stmt)
		if strings.HasPrefix(stmt, "--") {
			if i := strings.IndexByte(stmt, '\n'); i >= 0 {
				stmt = stmt[i+1:]
				continue
			}
			return ""
		}
		if strings.HasPrefix(stmt, "/*") {
			if i := strings.Index(stmt, "*/"); i >= 0 {
				stmt = stmt[i+2:]
				continue
			}
			return ""
		}
		return stmt
	}
}

// splitSQLiteStatements splits on ';' outside quotes, brackets, backticks
// and outside -- / /* */ comments. Newlines alone do not split (multiline
// SELECT must stay one statement).
func splitSQLiteStatements(sql string) []string {
	var out []string
	var cur strings.Builder
	var quote rune // 0 / '\'' / '"' / '`' / '['
	inLineComment := false
	inBlockComment := false
	runes := []rune(sql)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if inLineComment {
			cur.WriteRune(r)
			if r == '\n' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			cur.WriteRune(r)
			if r == '*' && i+1 < len(runes) && runes[i+1] == '/' {
				cur.WriteRune('/')
				i++
				inBlockComment = false
			}
			continue
		}
		if quote != 0 {
			cur.WriteRune(r)
			if quote == '[' {
				if r == ']' {
					quote = 0
				}
				continue
			}
			if r == quote {
				// SQL '' escape inside single quotes
				if quote == '\'' && i+1 < len(runes) && runes[i+1] == '\'' {
					cur.WriteRune(runes[i+1])
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"', '`':
			quote = r
			cur.WriteRune(r)
		case '[':
			quote = '['
			cur.WriteRune(r)
		case '-':
			if i+1 < len(runes) && runes[i+1] == '-' {
				inLineComment = true
				cur.WriteRune(r)
				continue
			}
			cur.WriteRune(r)
		case '/':
			if i+1 < len(runes) && runes[i+1] == '*' {
				inBlockComment = true
				cur.WriteRune(r)
				continue
			}
			cur.WriteRune(r)
		case ';':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func sqliteStmtHasPrefix(upper, kw string) bool {
	if !strings.HasPrefix(upper, kw) {
		return false
	}
	if len(upper) == len(kw) {
		return true
	}
	return !isSQLIdentChar(rune(upper[len(kw)]))
}

func sqliteURIHasRW(uri string) bool {
	q := uri
	if i := strings.IndexByte(q, '?'); i >= 0 {
		q = q[i+1:]
	} else {
		return false
	}
	if i := strings.IndexByte(q, '#'); i >= 0 {
		q = q[:i]
	}
	for _, part := range strings.Split(q, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := kv[0]
		key = strings.ReplaceAll(key, "%6d", "m")
		key = strings.ReplaceAll(key, "%6D", "m")
		key = strings.ReplaceAll(key, "%6f", "o")
		key = strings.ReplaceAll(key, "%6F", "o")
		key = strings.ReplaceAll(key, "%64", "d")
		key = strings.ReplaceAll(key, "%65", "e")
		if !strings.EqualFold(key, "mode") {
			continue
		}
		val := strings.ToLower(kv[1])
		if val != "ro" && val != "r" {
			return true
		}
	}
	return false
}

func containsSQLKeyword(upper, kw string) bool {
	idx := 0
	for {
		j := strings.Index(upper[idx:], kw)
		if j < 0 {
			return false
		}
		j += idx
		beforeOK := j == 0 || !isSQLIdentChar(rune(upper[j-1]))
		after := j + len(kw)
		afterOK := after >= len(upper) || !isSQLIdentChar(rune(upper[after]))
		if beforeOK && afterOK {
			return true
		}
		idx = j + len(kw)
	}
}

func isSQLIdentChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func checkGoReadonly(argv []string) string {
	// Narrow: only `go version`, `go env` (no -w/-u/--w/--u), `go list`
	// (option-table driven; deny -toolexec/-exec/-modfile/-overlay).
	args := argv[1:]
	if len(args) == 0 {
		return ""
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "version", "help":
		return ""
	case "env":
		for _, a := range rest {
			if a == "--" {
				continue
			}
			if a == "-w" || a == "-u" || a == "--w" || a == "--u" ||
				strings.HasPrefix(a, "-w") || strings.HasPrefix(a, "-u") ||
				strings.HasPrefix(a, "--w") || strings.HasPrefix(a, "--u") {
				return "go env " + a
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				// allow -json and similar read-only env flags; unknown dash stays denied
				switch a {
				case "-json", "--json", "-h", "--help":
					continue
				default:
					if strings.HasPrefix(a, "-") {
						// bare variable names are positionals; flags other than
						// json/help are not part of the narrow allowlist
						return "go env " + a
					}
				}
			}
		}
		return ""
	case "list":
		// Whitelist only: -f (valued), -json, -m, -u, -versions, -deps, -e, -find.
		allowBool := map[string]bool{
			"json": true, "m": true, "u": true, "versions": true,
			"deps": true, "e": true, "find": true, "h": true, "help": true,
		}
		allowVal := map[string]bool{"f": true}
		for i := 0; i < len(rest); i++ {
			a := rest[i]
			if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
				continue
			}
			name := strings.TrimLeft(a, "-")
			glued := false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
				glued = true
			}
			if allowVal[name] {
				if !glued && !strings.Contains(a, "=") && (strings.HasPrefix(a, "--") || a == "-f") {
					i++ // consume value
				} else if !glued && strings.HasPrefix(a, "-f") && a != "-f" && !strings.HasPrefix(a, "--") {
					// glued -f{{.X}}
				}
				continue
			}
			if allowBool[name] {
				continue
			}
			return "go list -" + name
		}
		return ""
	case "fmt", "vet", "test", "build", "run", "generate",
		"mod", "get", "install", "work", "clean", "fix", "doc", "tool":
		return "go " + sub
	default:
		if strings.HasPrefix(sub, "mod") {
			return "go " + sub
		}
		return "go " + sub
	}
}

func checkShellReadonly(argv []string) string {
	// Narrow: only `bash|sh -c <script>` (recursive same-policy screening of
	// the script body happens downstream). Bare shell, -s, -V, script files,
	// and other flags fail closed at the allowlist layer.
	args := argv[1:]
	if len(args) == 0 {
		return "shell bare"
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-c":
			if i+1 >= len(args) {
				return "shell -c missing"
			}
			return ""
		case strings.HasPrefix(a, "-c") && a != "-c" && !strings.HasPrefix(a, "--"):
			// glued -cSCRIPT
			return ""
		case a == "--noprofile" || a == "--norc" || a == "-p":
			// harmless modifiers ahead of -c
			continue
		case a == "--":
			return "shell script file"
		case strings.HasPrefix(a, "-"):
			return "shell flag " + a
		default:
			return "shell script file"
		}
	}
	return "shell bare"
}

func checkHerdrReadonly(argv []string) string {
	args := argv[1:]
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "--version", "-v", "--help", "-h", "help", "version", "list", "ls", "status", "info":
		return ""
	case "pane":
		if len(args) < 2 {
			return "herdr pane"
		}
		switch args[1] {
		case "read", "list", "ls", "capture", "dump", "get", "info", "status", "help":
			return ""
		default:
			return "herdr pane " + args[1]
		}
	default:
		return "herdr " + args[0]
	}
}

func checkTarReadonly(argv []string) string {
	args := argv[1:]
	safeCompressors := map[string]bool{
		"gzip": true, "gunzip": true, "pigz": true,
		"bzip2": true, "bunzip2": true, "pbzip2": true,
		"xz": true, "unxz": true, "lz4": true, "zstd": true, "unzstd": true,
		"lzop": true, "compress": true, "uncompress": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		prog := ""
		switch {
		case a == "-I" || a == "--use-compress-program":
			if i+1 < len(args) {
				prog = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--use-compress-program="):
			prog = a[len("--use-compress-program="):]
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsRune(a, 'I'):
			if i+1 < len(args) {
				prog = args[i+1]
			}
		default:
			continue
		}
		if prog == "" {
			return "tar -I"
		}
		base := filepath.Base(prog)
		if base != prog || strings.ContainsAny(prog, "/\\") || !safeCompressors[base] {
			return "tar -I"
		}
	}
	joined := strings.Join(args, " ")
	// Deny write/extract-to-disk modes; allow list/help/version and stdout extract.
	hasList := false
	hasCreate := false
	hasExtract := false
	hasAppend := false
	hasUpdate := false
	hasDelete := false
	toStdout := false
	for _, a := range args {
		switch a {
		case "--help", "--version":
			// defer: allow only when no extract/create modes present
		case "-h":
			// Standalone -h may be help; do not early-return so that
			// "tar -h -xf" still observes the -xf extract mode.
		case "--list", "-t":
			hasList = true
		case "--create", "-c":
			hasCreate = true
		case "--extract", "--get", "-x":
			hasExtract = true
		case "--append", "-r":
			hasAppend = true
		case "--update", "-u":
			hasUpdate = true
		case "--delete":
			hasDelete = true
		case "--to-stdout", "-O":
			toStdout = true
		}
		if strings.HasPrefix(a, "--checkpoint-action") || a == "--to-command" || strings.HasPrefix(a, "--to-command=") {
			return "tar " + a
		}
		// Old-style clustered flags without dash: tf, tvf, xf, cf, czf, ...
		if !strings.HasPrefix(a, "-") && a != "" && !strings.Contains(a, "/") && !strings.Contains(a, ".") {
			for _, ch := range a {
				switch ch {
				case 't':
					hasList = true
				case 'c':
					hasCreate = true
				case 'x':
					hasExtract = true
				case 'r':
					hasAppend = true
				case 'u':
					hasUpdate = true
				case 'O':
					toStdout = true
				}
			}
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			for _, ch := range a[1:] {
				switch ch {
				case 't':
					hasList = true
				case 'c':
					hasCreate = true
				case 'x':
					hasExtract = true
				case 'r':
					hasAppend = true
				case 'u':
					hasUpdate = true
				case 'O':
					toStdout = true
				}
			}
		}
	}
	_ = joined
	if hasDelete {
		return "tar --delete"
	}
	if hasCreate {
		return "tar -c"
	}
	if hasAppend {
		return "tar -r"
	}
	if hasUpdate {
		return "tar -u"
	}
	if hasExtract && !toStdout {
		return "tar -x"
	}
	if hasList || (hasExtract && toStdout) {
		return ""
	}
	// help/version-only argv
	onlyMeta := true
	for _, a := range args {
		if a == "--help" || a == "--version" || a == "-h" {
			continue
		}
		onlyMeta = false
		break
	}
	if onlyMeta && len(args) > 0 {
		return ""
	}
	// bare/unknown — deny at allowlist layer (do not rely on legacy blacklist)
	if len(args) == 0 {
		return "tar bare"
	}
	return "tar"
}

func checkUnzipReadonly(argv []string) string {
	hasRead := false
	for _, a := range argv[1:] {
		switch a {
		case "-l", "-t", "-p", "-v", "-Z", "-c", "--help", "-h", "-hh":
			hasRead = true
			continue
		case "-o", "-f", "-u", "-d":
			return "unzip " + a
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if strings.ContainsAny(a, "odf") && a != "-p" {
				for _, ch := range a[1:] {
					if ch == 'o' || ch == 'd' || ch == 'f' {
						return "unzip -" + string(ch)
					}
				}
			}
			for _, ch := range a[1:] {
				if strings.ContainsRune("ltpvcZh", ch) {
					hasRead = true
				}
			}
		}
	}
	if !hasRead {
		return "unzip extract"
	}
	return ""
}

func checkGzipReadonly(argv []string) string {
	base := filepath.Base(argv[0])
	args := argv[1:]
	hasStdout := false
	hasList := false
	hasTest := false
	hasDecompress := false
	hasVersion := false
	for _, a := range args {
		switch a {
		case "-c", "--stdout", "--to-stdout":
			hasStdout = true
			continue
		case "-l", "--list":
			hasList = true
			continue
		case "-t", "--test":
			hasTest = true
			continue
		case "-d", "--decompress", "--uncompress":
			hasDecompress = true
			continue
		case "-V", "--version", "--help", "-h", "-k", "--keep",
			"-n", "-N", "-q", "-v", "-f":
			if a == "-V" || a == "--version" || a == "--help" || a == "-h" {
				hasVersion = true
			}
			continue
		case "-1", "-2", "-3", "-4", "-5", "-6", "-7", "-8", "-9":
			return base + " compress"
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			for _, ch := range a[1:] {
				switch ch {
				case 'c':
					hasStdout = true
				case 'l':
					hasList = true
				case 't':
					hasTest = true
				case 'd':
					hasDecompress = true
				case 'V', 'h':
					hasVersion = true
				case 'k', 'n', 'N', 'q', 'v', 'f':
					// ok modifiers
				default:
					if ch >= '1' && ch <= '9' {
						return base + " compress"
					}
					return base + " unknown -" + string(ch)
				}
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			return base + " unknown " + a
		}
	}
	// gunzip/bunzip2/unxz without -c write a sibling file — require -c/list/test.
	switch base {
	case "gunzip", "bunzip2", "unxz", "unzstd":
		if hasStdout || hasList || hasTest || hasVersion || len(args) == 0 {
			return ""
		}
		return base + " decompress write"
	}
	// gzip -d without -c writes decompressed file and may delete source.
	if hasDecompress && !hasStdout && !hasList && !hasTest {
		return base + " -d without -c"
	}
	if hasStdout || hasList || hasTest || hasVersion || len(args) == 0 {
		return ""
	}
	if hasDecompress && hasStdout {
		return ""
	}
	return base + " compress"
}

func checkMountReadonly(argv []string) string {
	args := argv[1:]
	if len(args) == 0 {
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-l" || a == "--help" || a == "-h" || a == "-V" || a == "--version" || a == "-v":
			continue
		case a == "-a" || a == "--all":
			return "mount " + a
		case a == "-t" || a == "--types":
			i++ // type value
			continue
		case strings.HasPrefix(a, "-t") || strings.HasPrefix(a, "--types="):
			continue
		case strings.HasPrefix(a, "-"):
			return "mount " + a
		default:
			// A bare operand is a mount point / device → write
			return "mount"
		}
	}
	return ""
}

func checkKillReadonly(argv []string) string {
	args := argv[1:]
	if len(args) == 1 && (args[0] == "-l" || args[0] == "-L" || args[0] == "--list") {
		return ""
	}
	return "kill"
}

func checkCompilerQuery(argv []string) string {
	args := argv[1:]
	base := filepath.Base(argv[0])
	// make/gmake: bare runs the default target — always deny unless the
	// argv is solely a version/help query flag.
	if base == "make" || base == "gmake" {
		if len(args) == 0 {
			return "make"
		}
		for _, a := range args {
			if a == "--version" || a == "-v" || a == "--help" || a == "-h" {
				continue
			}
			return "make"
		}
		return ""
	}
	// Other compilers/builders: bare argv is denied; only pure query flags.
	if len(args) == 0 {
		return base + " bare"
	}
	queryOK := func(a string) bool {
		switch a {
		case "--version", "-v", "-V", "--help", "-h", "-dumpversion", "-dumpmachine",
			"--print-search-dirs", "-E", "-###", "-quiet", "-Q":
			return true
		}
		if strings.HasPrefix(a, "-print-") || strings.HasPrefix(a, "--print-") {
			return true
		}
		return false
	}
	for _, a := range args {
		if !queryOK(a) {
			return base + " non-query"
		}
	}
	return ""
}

func checkCtxmodeReadonly(argv []string) string {
	args := argv[1:]
	// Readonly roles must not load external -config/--config.
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if strings.HasPrefix(a, "-") {
			if a == "-config" || a == "--config" || strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config=") {
				return "ctxmode config"
			}
			// value-taking globals: -workdir/--workdir/-C must skip their value
			if a == "-workdir" || a == "--workdir" || a == "-C" {
				i += 2
				continue
			}
			if strings.HasPrefix(a, "-workdir=") || strings.HasPrefix(a, "--workdir=") {
				i++
				continue
			}
			i++
			continue
		}
		break
	}
	if i >= len(args) {
		return ""
	}
	sub := args[i]
	switch sub {
	case "search", "help", "version", "doctor", "stats", "show", "get", "list":
		return ""
	case "index", "purge", "delete", "rm", "write", "put", "set":
		return "ctxmode " + sub
	default:
		return "ctxmode " + sub
	}
}

// screenReadonlyAllowlist is the primary default-deny gate for a resolved
// command argv. Returns "" when the argv is within policy.
func screenReadonlyAllowlist(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	if strings.Contains(argv[0], cmdSubPlaceholder) {
		return "dynamic command head"
	}
	// Reject path-form argv[0] (./ls, /tmp/rg); basename matching alone is unsafe.
	if strings.Contains(argv[0], "/") {
		return "path command"
	}
	base := filepath.Base(argv[0])
	base = canonicalResolvedBase(base)
	switch base {
	case "eval", "exec", "source", ".", "coproc", "nohup":
		return base
	case "function":
		return "function definition"
	case "[[", "[", "test":
		return ""
	case "((":
		return "arithmetic (("
	}
	if strings.HasSuffix(base, "()") {
		return "function definition"
	}
	if hit := allowlistInterpreterHit(argv, base); hit != "" {
		return hit
	}
	if allowlistIsInterpreter(base) {
		return "interpreter " + base
	}
	entry := readonlyAllowlist[base]
	if entry == nil {
		return "unknown command " + base
	}
	if entry.check != nil && entry.shortBool == "" && entry.shortValue == "" &&
		len(entry.longBool) == 0 && len(entry.longValue) == 0 {
		return entry.check(argv)
	}
	if hit := scanAllowedOpts(argv[1:], entry); hit != "" {
		return hit
	}
	if entry.check != nil {
		return entry.check(argv)
	}
	return ""
}

func allowlistIsInterpreter(base string) bool {
	if base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3") {
		return true
	}
	switch base {
	case "node", "nodejs", "ts-node", "tsx", "bun", "perl", "ruby", "php",
		"awk", "gawk", "mawk", "nawk":
		return true
	}
	return false
}

func allowlistInterpreterHit(argv []string, base string) string {
	if !allowlistIsInterpreter(base) {
		return ""
	}
	isPython := base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3")
	if isPython {
		return "python interpreter"
	}
	if base == "node" || base == "nodejs" || base == "ts-node" || base == "tsx" || base == "bun" {
		return "node interpreter"
	}
	if base == "awk" || base == "gawk" || base == "mawk" || base == "nawk" {
		return "awk program"
	}
	return base + " interpreter"
}

func scanAllowedOpts(args []string, entry *cmdAllow) string {
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if endOpts {
			if entry.noPositional {
				return "unexpected operand"
			}
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			if entry.noPositional {
				return "unexpected operand"
			}
			continue
		}
		if strings.HasPrefix(a, "--") {
			name := a[2:]
			valGlued := false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
				valGlued = true
			}
			if entry.longBool[name] || entry.longValue[name] {
				if entry.longValue[name] && !valGlued {
					i++
				}
				continue
			}
			return "unknown option --" + name
		}
		for j := 1; j < len(a); j++ {
			ch := a[j]
			// Prefer shortBool over shortValue so a char wrongly listed in
			// both cannot swallow the next argv element.
			if strings.IndexByte(entry.shortBool, ch) >= 0 {
				continue
			}
			if strings.IndexByte(entry.shortValue, ch) >= 0 {
				if j+1 < len(a) {
					break // glued value in rest of cluster
				}
				i++ // consume next argv as value
				break
			}
			return "unknown option -" + string(ch)
		}
	}
	return ""
}

// readonlyPrePeelHit rejects exec/eval/source/`.` / function / coproc / nohup
// before peelWrappers can strip them into a benign head.
func readonlyPrePeelHit(argv []string) string {
	i := 0
	steps := 0
	for i < len(argv) && steps < peelWrapperMaxSteps {
		a := argv[i]
		if isAssignWord(a) {
			return "env assign"
		}
		if shellNoopWords[a] {
			i++
			continue
		}
		base := filepath.Base(a)
		switch base {
		case "exec", "eval", "source", ".", "coproc", "nohup":
			return base
		case "function":
			return "function definition"
		case "env", "command", "builtin", "nice", "timeout", "stdbuf", "busybox",
			"ionice", "taskset", "chrt", "strace", "ltrace", "setsid", "time":
			// Wrappers removed from readonly peel: fail closed (no strip).
			return base
		case "if", "then", "elif", "else", "while", "until", "do", "!":
			i++
			steps++
			continue
		default:
			if strings.HasSuffix(base, "()") {
				return "function definition"
			}
			return ""
		}
	}
	return ""
}

// allowlistShellStructuralHit rejects shell features forbidden by policy.
func allowlistShellStructuralHit(seg shellSegment) string {
	if seg.backgrounded {
		return "background &"
	}
	if seg.processSubst {
		return "process substitution"
	}
	for _, w := range seg.argv {
		if strings.Contains(w, cmdSubPlaceholder) {
			return "command substitution"
		}
		if strings.HasPrefix(w, "<(") || strings.HasPrefix(w, ">(") {
			return "process substitution"
		}
	}
	if seg.redirectFile == dynamicRedirectTarget {
		return "dynamic redirect"
	}
	if seg.redirectFile != "" {
		return "> " + seg.redirectFile
	}
	return ""
}

// readonlyBlockWithHint appends a short alternative suggestion for agents
// when a strict-readonly allowlist block fires. Keeps the original reason
// prefix intact for tests and audit.
func readonlyBlockWithHint(detail string) string {
	if detail == "" {
		return detail
	}
	if strings.Contains(detail, "Hint:") {
		return detail
	}
	hint := readonlyHintFor(detail)
	if hint == "" {
		return detail
	}
	return detail + " Hint: " + hint
}

func readonlyHintFor(detail string) string {
	d := strings.ToLower(detail)
	switch {
	case strings.Contains(d, "python") || strings.Contains(d, "javascript") || strings.Contains(d, "node") ||
		(strings.Contains(d, "perl") && strings.Contains(d, "interpreter")) ||
		(strings.Contains(d, "ruby") && strings.Contains(d, "interpreter")) ||
		strings.Contains(d, "json.tool"):
		return "for JSON use jq . ; for text/files use rg / rg --files; for file view use cat/head/sed -n 'N,Mp'"
	case strings.Contains(d, "bash") || strings.Contains(d, "shell") ||
		strings.Contains(d, "unknown command sh") || strings.Contains(d, "unknown command dash") ||
		strings.Contains(d, "unknown command zsh"):
		return "run allowlisted tools directly (rg/jq/cat/head/tail/git); no shell -c"
	case strings.Contains(d, "sqlite"):
		return "sqlite3 removed from readonly allowlist; use jq . for JSON or git show/cat for files"
	case strings.Contains(d, "curl") || strings.Contains(d, "wget"):
		return "curl removed; for local files use cat/rg/git show/log/diff"
	case strings.Contains(d, "tar") || strings.Contains(d, "unzip") || strings.Contains(d, "gzip"):
		return "archives removed; inspect with git show / cat / rg instead"
	case strings.Contains(d, "sed"):
		return "only sed -n 'N,Mp' file is allowed; prefer rg / cut / tr"
	case strings.Contains(d, "git config"):
		return "use git config --get <key> or git config -l"
	case strings.Contains(d, "go test") || strings.Contains(d, "go build") ||
		strings.Contains(d, "go run") || strings.Contains(d, "go fmt") ||
		strings.Contains(d, "npm") || strings.Contains(d, "cargo") ||
		strings.Contains(d, "make") || strings.Contains(d, "gcc"):
		return "this is a readonly role; hand write/test/build work to verifier or the main agent"
	case strings.Contains(d, "process substitution"):
		return "avoid <(...) / >(...); use a pipe (cmd | other) or rg/cat"
	case strings.Contains(d, "env assign") || strings.Contains(d, "strace") ||
		strings.Contains(d, "busybox") || strings.Contains(d, "timeout") ||
		strings.Contains(d, "unknown command"):
		return "use allowlisted read tools (ls/cat/rg/git/jq); no wrappers or VAR=val prefixes"
	case strings.Contains(d, "command substitution") || strings.Contains(d, "eval") ||
		strings.Contains(d, "exec") || strings.Contains(d, "source"):
		return "run allowed commands directly; no eval/source/exec/$(...)"
	default:
		return "use allowlisted read tools (ls/cat/rg/git/jq/sed -n); write/test → verifier"
	}
}

// readonlyToolsDescription is a short grouped list of commands strict
// readonly roles may run via ctx_run. Kept compact (≤15 lines) and checked
// against readonlyAllowlist by TestReadonlyAllowlist_ToolsDescriptionSync.
func readonlyToolsDescription() string {
	return strings.TrimSpace(`
Readonly role commands (strict scout/planner/researcher/reviewer/oracle):
files: ls cat head tail wc stat file du tree realpath basename dirname readlink
search: rg grep find sed
text: sort uniq cut tr jq diff cmp echo printf true false
vcs: git
go_meta: go gofmt ctxmode
ops: ps pgrep ss journalctl systemctl which date pwd mount kill herdr
`)
}
