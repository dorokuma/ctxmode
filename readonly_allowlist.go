package main

import (
	"path/filepath"
	"strings"
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
	// longTwoValue: --flag KEY VAL (e.g. jq --arg / --argjson).
	longTwoValue map[string]bool
	// allowLegacyNumOpt permits a lone -[0-9]+ token (head -20 / tail -5).
	allowLegacyNumOpt bool
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
	readonlyAllowlist["head"] = &cmdAllow{check: checkHeadReadonly}
	// -f/-F/--follow block forever-follow; keep -n/-c value opts only.
	readonlyAllowlist["tail"] = &cmdAllow{check: checkTailReadonly}
	readonlyAllowlist["wc"] = simple("cmlLw", "",
		[]string{"bytes", "chars", "lines", "max-line-length", "words", "help", "version"}, nil)
	// shortBool / shortValue are explicit disjoint tables: boolean shorts must
	// NEVER appear in shortValue or scanAllowedOpts will swallow the next argv
	// (e.g. rg -n --pre=... used to skip --pre).
	readonlyAllowlist["rg"] = simple("ninlFvUHPcwoqsSa", "egmABCtTMg",
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
	readonlyAllowlist["du"] = simple("ahscHx", "Bd",
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
		for i := 1; i < len(argv); i++ {
			a := argv[i]
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
			if a == "-s" || a == "--set" || strings.HasPrefix(a, "--set=") {
				return "date set"
			}
			if strings.HasPrefix(a, "--") {
				name := a[2:]
				valGlued := false
				if eq := strings.IndexByte(name, '='); eq >= 0 {
					name = name[:eq]
					valGlued = true
				}
				switch name {
				case "date", "file", "reference", "rfc-3339":
					if !valGlued {
						i++
					}
					continue
				case "set":
					return "date set"
				default:
					continue
				}
			}
			if strings.HasPrefix(a, "-") && a != "-" {
				if strings.HasPrefix(a, "-s") && a != "-s" && !strings.ContainsAny(a[1:], "dfru") {
					return "date set"
				}
				for j := 1; j < len(a); j++ {
					ch := a[j]
					if ch == 's' {
						return "date set"
					}
					if ch == 'd' || ch == 'f' || ch == 'r' {
						if j+1 < len(a) {
							break
						}
						i++
						break
					}
				}
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
				for j := 1; j < len(a); j++ {
					ch := a[j]
					if strings.IndexByte(readonlyAllowlist["uniq"].shortBool, ch) >= 0 {
						continue
					}
					if strings.IndexByte(readonlyAllowlist["uniq"].shortValue, ch) >= 0 {
						if j+1 < len(a) {
							break
						}
						i++
						break
					}
					break
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
	readonlyAllowlist["jq"] = &cmdAllow{check: checkJqReadonly}
	readonlyAllowlist["diff"] = simple("urNqbwBy", "UCIx",
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
	readonlyAllowlist["ps"] = simple("eflAuxHwT", "opU",
		[]string{"help", "version", "forest", "threads"},
		[]string{"pid", "ppid", "user", "format", "sort", "tty", "cols", "columns", "width"})
	readonlyAllowlist["pgrep"] = simple("alfnvx", "PugGsdte",
		[]string{"list-name", "list-full", "full", "inverse", "newest", "oldest",
			"exact", "help", "version", "count", "ignore-case"},
		[]string{"parent", "uid", "euid", "gid", "group", "session", "terminal", "delimiter"})
	readonlyAllowlist["ss"] = simple("antuplreos46", "",
		[]string{"all", "numeric", "tcp", "udp", "listening", "processes", "resolve",
			"extended", "options", "memory", "info", "summary", "help", "version", "ipv4", "ipv6"},
		[]string{"query", "family", "filter"})
	readonlyAllowlist["journalctl"] = simple("exqrbn", "uSo",
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
	readonlyAllowlist["herdsman"] = &cmdAllow{check: checkHerdsmanReadonly}
	// hc reuses the sub-agent whitelist screen: only `hc send <addr> <text>`
	// and the pure query spellings pass under strict readonly. The symlink
	// targets (herdr-core on the host, sbx inside the reviewer sandbox) stay
	// OUT of this table — they are admitted only as hc's resolved alias in
	// isAllowedSystemReadonlyAlias.
	readonlyAllowlist["hc"] = &cmdAllow{check: screenHcSubagent}
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
			if strings.IndexByte(name, '=') < 0 && longValue[name] {
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

func checkHeadReadonly(argv []string) string {
	entry := &cmdAllow{
		shortBool:         "qvz",
		shortValue:        "nc",
		longBool:          longSet("quiet", "silent", "verbose", "zero-terminated", "help", "version"),
		longValue:         longSet("bytes", "lines"),
		allowLegacyNumOpt: true,
	}
	return scanAllowedOpts(argv[1:], entry)
}

func checkTailReadonly(argv []string) string {
	entry := &cmdAllow{
		shortBool:         "qvz",
		shortValue:        "nc",
		longBool:          longSet("quiet", "silent", "verbose", "zero-terminated", "help", "version"),
		longValue:         longSet("bytes", "lines", "sleep-interval", "max-unchanged-stats", "pid"),
		allowLegacyNumOpt: true,
	}
	return scanAllowedOpts(argv[1:], entry)
}

func checkJqReadonly(argv []string) string {
	entry := &cmdAllow{
		shortBool:  "ncrRMSes",
		shortValue: "f",
		longBool: longSet("null-input", "compact-output", "raw-output", "raw-input", "slurp",
			"seq", "sort-keys", "tab", "ascii-output", "color-output", "monochrome-output",
			"help", "version", "exit-status"),
		longValue:    longSet("from-file", "indent"),
		longTwoValue: longSet("arg", "argjson"),
	}
	return scanAllowedOpts(argv[1:], entry)
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
		"prune":   true,
		"newermt": true, "newerat": true, "newerct": true,
		"H": true, "L": true, "P": true, "D": true, "O": true, "a": true, "o": true,
	}
	singleVal := map[string]bool{
		"name": true, "iname": true, "path": true, "ipath": true, "wholename": true, "iwholename": true,
		"regex": true, "iregex": true, "lname": true, "ilname": true, "type": true, "xtype": true,
		"size": true, "mtime": true, "mmin": true, "ctime": true, "cmin": true, "atime": true, "amin": true,
		"uid": true, "gid": true, "user": true, "group": true, "perm": true, "links": true,
		"newer": true, "anewer": true, "cnewer": true, "samefile": true, "inum": true, "used": true,
		"fstype": true, "maxdepth": true, "mindepth": true, "regextype": true, "printf": true, "D": true,
		"newermt": true, "newerat": true, "newerct": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(a, "--"), "-")
		// -O3 / -Dxxx glued forms
		if (strings.HasPrefix(name, "O") || strings.HasPrefix(name, "D")) && len(name) > 1 {
			base := name[:1]
			if allowed[base] {
				continue
			}
		}
		if !allowed[name] {
			return "find unknown " + a
		}
		if singleVal[name] {
			i++
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
		case strings.HasPrefix(a, "-C") && len(a) > 2:
			i++
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
		if gitLongOptPrefixHit(a, "output", "ext-diff", "textconv", "filters") {
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
	if sub == "grep" {
		return gitGrepOptsAllow(rest)
	}
	for _, a := range rest {
		if a == "--" || !strings.HasPrefix(a, "-") {
			continue
		}
		if gitLongOptPrefixHit(a, "output", "exec-path", "textconv", "ext-diff", "filters") {
			return "git " + sub + " " + a
		}
		if a == "--exec-path" || strings.HasPrefix(a, "--exec-path=") ||
			strings.Contains(a, "upload-pack") || strings.Contains(a, "receive-pack") ||
			strings.HasPrefix(a, "--exec") {
			return "git " + sub + " " + a
		}
	}
	return ""
}

func gitLongOptPrefixHit(a string, blocked ...string) bool {
	if !strings.HasPrefix(a, "--") {
		return false
	}
	name := a[2:]
	if eq := strings.IndexByte(name, '='); eq >= 0 {
		name = name[:eq]
	}
	if name == "" {
		return false
	}
	for _, b := range blocked {
		if name == b || strings.HasPrefix(b, name) {
			return true
		}
	}
	return false
}

func gitGrepOptsAllow(rest []string) string {
	entry := &cmdAllow{
		shortBool:  "invwxlqceEFGHhILpqru",
		shortValue: "eAfBmM",
		longBool: longSet("ignore-case", "invert-match", "word-regexp", "line-regexp",
			"null", "count", "quiet", "cached", "no-index", "untracked", "no-exclude-standard",
			"exclude-standard", "recurse-submodules", "text", "full-name",
			"extended-regexp", "fixed-strings", "basic-regexp", "perl-regexp", "help", "all-match",
			"no-textconv"),
		longValue: longSet("max-depth", "max-count", "threads"),
	}
	for _, a := range rest {
		if a == "--" || !strings.HasPrefix(a, "-") {
			continue
		}
		if gitLongOptPrefixHit(a, "open-files-in-pager", "open-files", "open", "textconv", "ext-diff", "output", "filters") {
			return "git grep " + a
		}
		if !strings.HasPrefix(a, "--") {
			for j := 1; j < len(a); j++ {
				if a[j] == 'O' {
					return "git grep open-files-in-pager"
				}
			}
		}
	}
	if hit := scanAllowedOpts(rest, entry); hit != "" {
		return "git grep " + hit
	}
	return ""
}

// gitSortKeyOK reports whether s is a safe --sort value: optional leading
// reverse "-", then a letter-led key matching ^-?[a-zA-Z][a-zA-Z0-9:._-]*$
// with at least two key characters so single-letter write flags (-D/-d/-f/-m)
// are never swallowed as sort keys.
func gitSortKeyOK(s string) bool {
	if s == "" {
		return false
	}
	key := s
	if key[0] == '-' {
		key = key[1:]
	}
	if len(key) < 2 {
		return false
	}
	c0 := key[0]
	if !((c0 >= 'a' && c0 <= 'z') || (c0 >= 'A' && c0 <= 'Z')) {
		return false
	}
	for i := 1; i < len(key); i++ {
		c := key[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == ':' || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// gitConsumeRefListOpt advances i past a shared git branch/tag list option.
// Returns (newIndex, isQuery, ok). ok=false means unknown/blocked option form.
func gitConsumeRefListOpt(rest []string, i int) (int, bool, bool) {
	a := rest[i]
	switch a {
	case "--contains", "--no-contains", "--merged", "--no-merged", "--points-at":
		if i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "-") {
			return i + 1, true, true
		}
		return i, true, true
	case "--sort":
		if i+1 < len(rest) && gitSortKeyOK(rest[i+1]) {
			return i + 1, false, true
		}
		// Missing/invalid sort key: leave for caller to reject as unknown.
		return i, false, false
	case "--format":
		if i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "-") {
			return i + 1, false, true
		}
		return i, false, false
	}
	if strings.HasPrefix(a, "--contains=") || strings.HasPrefix(a, "--no-contains=") ||
		strings.HasPrefix(a, "--merged=") || strings.HasPrefix(a, "--no-merged=") ||
		strings.HasPrefix(a, "--points-at=") {
		return i, true, true
	}
	if strings.HasPrefix(a, "--sort=") {
		val := a[len("--sort="):]
		if gitSortKeyOK(val) {
			return i, false, true
		}
		return i, false, false
	}
	if strings.HasPrefix(a, "--format=") {
		return i, false, true
	}
	return i, false, false
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
			"-h", "--help", "--show-current":
			query = true
			continue
		case "-v", "-vv", "--verbose", "-q", "--quiet", "--color", "--no-color",
			"--column", "--no-column":
			continue
		case "--contains", "--no-contains", "--merged", "--no-merged", "--points-at",
			"--sort", "--format":
			ni, isQ, ok := gitConsumeRefListOpt(rest, i)
			if !ok {
				return "git branch unknown " + a
			}
			if isQ {
				query = true
			}
			i = ni
			continue
		}
		if strings.HasPrefix(a, "--color=") {
			continue
		}
		if strings.HasPrefix(a, "--contains=") || strings.HasPrefix(a, "--no-contains=") ||
			strings.HasPrefix(a, "--merged=") || strings.HasPrefix(a, "--no-merged=") ||
			strings.HasPrefix(a, "--points-at=") || strings.HasPrefix(a, "--sort=") ||
			strings.HasPrefix(a, "--format=") {
			ni, isQ, ok := gitConsumeRefListOpt(rest, i)
			if !ok {
				return "git branch unknown " + a
			}
			if isQ {
				query = true
			}
			_ = ni
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
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch a {
		case "-l", "--list", "-n", "-n1", "-n2", "-n3", "--verify", "-v",
			"-h", "--help":
			listish = true
			continue
		case "--color", "--no-color", "-i", "--ignore-case":
			continue
		case "--contains", "--no-contains", "--merged", "--no-merged", "--points-at",
			"--sort", "--format":
			ni, isQ, ok := gitConsumeRefListOpt(rest, i)
			if !ok {
				return "git tag unknown " + a
			}
			if isQ || a == "--sort" || a == "--format" || a == "--contains" ||
				a == "--no-contains" || a == "--merged" || a == "--no-merged" ||
				a == "--points-at" {
				listish = true
			}
			i = ni
			continue
		}
		if strings.HasPrefix(a, "-n") {
			listish = true
			continue
		}
		if strings.HasPrefix(a, "--color=") {
			continue
		}
		if strings.HasPrefix(a, "--contains=") || strings.HasPrefix(a, "--no-contains=") ||
			strings.HasPrefix(a, "--merged=") || strings.HasPrefix(a, "--no-merged=") ||
			strings.HasPrefix(a, "--points-at=") || strings.HasPrefix(a, "--sort=") ||
			strings.HasPrefix(a, "--format=") {
			ni, isQ, ok := gitConsumeRefListOpt(rest, i)
			if !ok {
				return "git tag unknown " + a
			}
			if isQ {
				listish = true
			}
			_ = ni
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
				} else if !glued && strings.HasPrefix(a, "-f") && a != "-f" {
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

func checkHerdrReadonly(argv []string) string {
	args := argv[1:]
	idx, query := skipToolGlobalFlags(args)
	if idx >= len(args) {
		if query {
			return ""
		}
		return "herdr bare"
	}
	if query {
		return ""
	}
	if strings.HasPrefix(args[idx], "-") {
		return "herdr " + args[idx]
	}
	switch args[idx] {
	case "--version", "--help", "-h", "help", "version", "list", "ls", "status", "info":
		return ""
	case "-v":
		if idx+1 >= len(args) {
			return ""
		}
		return "herdr " + args[idx+1]
	case "pane":
		rest := args[idx+1:]
		if len(rest) == 0 {
			return "herdr pane"
		}
		switch rest[0] {
		case "read", "list", "ls", "capture", "dump", "get", "info", "status", "help",
			"current", "--help", "-h":
			return ""
		default:
			return "herdr pane " + rest[0]
		}
	default:
		return "herdr " + args[idx]
	}
}

func checkHerdsmanReadonly(argv []string) string {
	args := argv[1:]
	idx, query := skipToolGlobalFlags(args)
	if idx >= len(args) {
		if query {
			return ""
		}
		return "herdsman bare"
	}
	if query {
		return ""
	}
	if strings.HasPrefix(args[idx], "-") {
		return "herdsman " + args[idx]
	}
	key := toolSubKey(args[idx:], herdsmanSecondLevel)
	if herdsmanReadonlySubs[key] {
		return ""
	}
	return "herdsman " + key
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

func checkCtxmodeReadonly(argv []string) string {
	args := argv[1:]
	i := 0
	sawHelp := false
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if strings.HasPrefix(a, "-") {
			if a == "-h" || a == "--help" {
				sawHelp = true
				i++
				continue
			}
			if a == "-config" || a == "--config" || strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config=") {
				return "ctxmode config"
			}
			if a == "-workdir" || a == "--workdir" || strings.HasPrefix(a, "-workdir=") ||
				strings.HasPrefix(a, "--workdir=") || a == "-C" || (strings.HasPrefix(a, "-C") && len(a) > 2) {
				return "ctxmode workdir"
			}
			return "ctxmode " + a
		}
		break
	}
	if i >= len(args) {
		if sawHelp {
			return ""
		}
		return "ctxmode bare"
	}
	sub := args[i]
	switch sub {
	case "search":
		return ""
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
	case "[", "test":
		return ""
	case "[[":
		return "[["
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
		if entry.allowLegacyNumOpt && len(a) > 1 && a[0] == '-' && allDigits(a[1:]) {
			continue
		}
		if strings.HasPrefix(a, "--") {
			name := a[2:]
			valGlued := false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
				valGlued = true
			}
			if entry.longTwoValue[name] {
				if valGlued {
					return "unknown option --" + name + " (glued two-value)"
				}
				i += 2 // KEY VAL
				continue
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
// and the peelable wrapper heads before peelWrappers can strip them into a
// benign head. `sbx` keeps the exact default-deny wording a non-peeled head
// produces (`unknown command sbx`) so strict-readonly callers get the same
// verdict the allowlist handed out before sbx became peelable.
func readonlyPrePeelHit(argv []string) string {
	i := 0
	steps := 0
	for i < len(argv) && steps < peelWrapperMaxSteps {
		a := argv[i]
		if isAssignWord(a) {
			return "env assign"
		}
		if strings.Contains(a, "/") {
			return "path command"
		}
		if shellNoopWords[a] {
			i++
			continue
		}
		switch a {
		case "exec", "eval", "source", ".", "coproc", "nohup":
			return a
		case "function":
			return "function definition"
		case "env", "command", "builtin", "nice", "timeout", "stdbuf", "busybox",
			"ionice", "taskset", "chrt", "strace", "ltrace", "setsid", "time":
			return a
		case "sbx":
			// Default-deny wording preserved for the strict-readonly path
			// ([pattern:sbx-wrapper-unwrap-asymmetry]).
			return "unknown command sbx"
		case "if", "then", "elif", "else", "while", "until", "do", "!",
			"fi", "done", "for", "in", "case", "esac", "select", "[[", "]]":
			return "control flow " + a
		default:
			if strings.HasSuffix(a, "()") {
				return "function definition"
			}
			return ""
		}
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
ops: ps pgrep ss journalctl systemctl which date pwd mount kill herdr herdsman
`)
}
