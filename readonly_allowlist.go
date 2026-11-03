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
			"full-time", "inode", "size", "author", "help", "version"},
		[]string{"width", "tabsize", "block-size", "format", "sort", "time",
			"quoting-style", "hide", "ignore", "indicator-style", "color", "time-style"})
	readonlyAllowlist["cat"] = simple("nbsAET", "",
		[]string{"number", "number-nonblank", "squeeze-blank", "show-all",
			"show-ends", "show-tabs", "show-nonprinting", "help", "version"}, nil)
	readonlyAllowlist["head"] = simple("nqvz", "nc",
		[]string{"quiet", "silent", "verbose", "zero-terminated", "help", "version"},
		[]string{"bytes", "lines"})
	readonlyAllowlist["tail"] = simple("nqfvz", "nc",
		[]string{"quiet", "silent", "verbose", "zero-terminated", "help", "version"},
		[]string{"bytes", "lines", "sleep-interval", "max-unchanged-stats", "pid", "follow"})
	readonlyAllowlist["tail"].longBool["follow"] = true
	readonlyAllowlist["wc"] = simple("cmlLw", "",
		[]string{"bytes", "chars", "lines", "max-line-length", "words", "help", "version"}, nil)
	// shortBool / shortValue are explicit disjoint tables: boolean shorts must
	// NEVER appear in shortValue or scanAllowedOpts will swallow the next argv
	// (e.g. rg -n --pre=... used to skip --pre).
	readonlyAllowlist["rg"] = simple("ninlFvUHAPcwoqsS", "egmABCtTM",
		[]string{"ignore-case", "line-number", "files-with-matches", "files-without-match",
			"fixed-strings", "vimgrep", "json", "pretty", "no-heading", "with-filename",
			"no-filename", "count", "stats", "help", "version", "hidden", "follow", "multiline",
			"word-regexp", "column", "only-matching", "quiet", "no-config", "no-ignore",
			"no-ignore-vcs", "search-zip", "pcre2", "files", "smart-case", "case-sensitive"},
		[]string{"regexp", "file", "glob", "type", "type-add", "type-not", "max-count", "max-depth", "max-filesize",
			"context", "before-context", "after-context", "color", "colors", "encoding",
			"replace", "sort", "sortr", "iglob", "ignore-file", "max-columns"})
	readonlyAllowlist["grep"] = simple("ninlFvwxqRHEor", "emABC",
		[]string{"ignore-case", "line-number", "files-with-matches", "files-without-match",
			"fixed-strings", "word-regexp", "line-regexp", "quiet", "silent", "recursive",
			"dereference-recursive", "extended-regexp", "perl-regexp", "basic-regexp",
			"help", "version", "count", "only-matching", "no-filename", "with-filename",
			"invert-match", "byte-offset", "null"},
		[]string{"regexp", "file", "exclude", "exclude-dir", "include", "max-count",
			"context", "before-context", "after-context", "color", "binary-files"})
	readonlyAllowlist["egrep"] = readonlyAllowlist["grep"]
	readonlyAllowlist["fgrep"] = readonlyAllowlist["grep"]
	readonlyAllowlist["stat"] = simple("cftLq", "c",
		[]string{"file-system", "filesystem", "terse", "dereference", "help", "version"},
		[]string{"format", "printf"})
	readonlyAllowlist["file"] = simple("bLszk", "",
		[]string{"brief", "dereference", "special-files", "compressed", "keep-going",
			"help", "version", "mime", "mime-type", "mime-encoding", "raw"},
		[]string{"separator", "exclude", "magic-file"})
	readonlyAllowlist["du"] = simple("ahsdcBHx", "B",
		[]string{"all", "human-readable", "summarize", "total", "bytes", "si",
			"dereference", "help", "version"},
		[]string{"block-size", "max-depth", "exclude", "threshold", "time", "time-style"})
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
		[]string{"utc", "universal", "rfc-email", "help", "version"},
		[]string{"date", "file", "reference", "rfc-3339", "iso-8601"})
	readonlyAllowlist["date"].check = func(argv []string) string {
		for _, a := range argv[1:] {
			if a == "-s" || a == "--set" || strings.HasPrefix(a, "--set=") {
				return "date set"
			}
		}
		return ""
	}
	readonlyAllowlist["env"] = &cmdAllow{
		shortBool:  "i0",
		shortValue: "u",
		longBool:   longSet("ignore-environment", "help", "version", "null"),
		longValue:  longSet("unset"),
		check: func(argv []string) string {
			for i := 1; i < len(argv); i++ {
				a := argv[i]
				if a == "--" {
					if i+1 < len(argv) {
						return "env command"
					}
					return ""
				}
				if strings.HasPrefix(a, "-") {
					continue
				}
				if strings.Contains(a, "=") {
					return "env assign"
				}
				return "env command"
			}
			return ""
		},
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
	readonlyAllowlist["uniq"] = simple("cudifz", "fws",
		[]string{"count", "repeated", "all-repeated", "ignore-case", "unique",
			"zero-terminated", "help", "version"},
		[]string{"skip-fields", "skip-chars", "check-chars", "group"})
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
			"report-identical-files", "normal"},
		[]string{"unified", "context", "exclude", "exclude-from", "label", "color", "width"})
	readonlyAllowlist["cmp"] = simple("bls", "in",
		[]string{"print-bytes", "quiet", "silent", "verbose", "help", "version"},
		[]string{"ignore-initial", "bytes"})
	readonlyAllowlist["tree"] = simple("adflLnhFC", "L",
		[]string{"help", "version", "dirsfirst", "noreport"},
		[]string{"filelimit", "charset"})
	readonlyAllowlist["realpath"] = simple("eqzs", "",
		[]string{"canonicalize-existing", "canonicalize-missing", "quiet", "silent",
			"strip", "no-symlinks", "zero", "help", "version"},
		[]string{"relative-to", "relative-base"})
	readonlyAllowlist["basename"] = simple("azs", "s",
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
	readonlyAllowlist["strings"] = simple("anot", "ant",
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
	readonlyAllowlist["journalctl"] = simple("efxqrb", "unSo",
		[]string{"no-pager", "catalog", "disk-usage", "help", "version", "list-boots",
			"reverse", "utc", "quiet", "follow", "pager-end", "merge", "system", "user",
			"dmesg"},
		[]string{"unit", "user-unit", "boot", "identifier", "priority", "grep", "output",
			"directory", "since", "until", "lines", "facility"})
	readonlyAllowlist["systemctl"] = &cmdAllow{
		shortBool: "qal",
		longBool:  longSet("no-pager", "no-legend", "all", "full", "failed", "quiet", "help", "version", "user", "system"),
		longValue: longSet("type", "state", "property"),
		check:     checkSystemctlReadonly,
	}
	readonlyAllowlist["cd"] = &cmdAllow{
		shortBool: "LP",
		check: func(argv []string) string {
			pos := 0
			for _, a := range argv[1:] {
				if strings.HasPrefix(a, "-") && a != "-" {
					if a == "-L" || a == "-P" {
						continue
					}
					return "cd flag " + a
				}
				pos++
				if pos > 1 {
					return "cd extra args"
				}
			}
			return ""
		},
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
	readonlyAllowlist["git-fsck"] = &cmdAllow{check: func(argv []string) string {
		return checkGitReadonly(append([]string{"git", "fsck"}, argv[1:]...))
	}}
	readonlyAllowlist["curl"] = &cmdAllow{check: checkCurlReadonly}
	readonlyAllowlist["sqlite3"] = &cmdAllow{check: checkSqliteReadonly}
	readonlyAllowlist["go"] = &cmdAllow{check: checkGoReadonly}
	for _, sh := range []string{"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash"} {
		readonlyAllowlist[sh] = &cmdAllow{check: checkShellReadonly}
	}
	readonlyAllowlist["herdr"] = &cmdAllow{check: checkHerdrReadonly}

	readonlyAllowlist["read"] = &cmdAllow{check: func(argv []string) string { return "" }}
	readonlyAllowlist["tar"] = &cmdAllow{check: checkTarReadonly}
	readonlyAllowlist["gtar"] = readonlyAllowlist["tar"]
	readonlyAllowlist["bsdtar"] = readonlyAllowlist["tar"]
	readonlyAllowlist["unzip"] = &cmdAllow{check: checkUnzipReadonly}
	readonlyAllowlist["gzip"] = &cmdAllow{check: checkGzipReadonly}
	readonlyAllowlist["gunzip"] = readonlyAllowlist["gzip"]
	readonlyAllowlist["xz"] = readonlyAllowlist["gzip"]
	readonlyAllowlist["unxz"] = readonlyAllowlist["gzip"]
	readonlyAllowlist["zstd"] = readonlyAllowlist["gzip"]
	readonlyAllowlist["unzstd"] = readonlyAllowlist["gzip"]
	readonlyAllowlist["bzip2"] = readonlyAllowlist["gzip"]
	readonlyAllowlist["bunzip2"] = readonlyAllowlist["gzip"]
	readonlyAllowlist["lz4"] = readonlyAllowlist["gzip"]
	readonlyAllowlist["mount"] = &cmdAllow{check: checkMountReadonly}
	readonlyAllowlist["kill"] = &cmdAllow{check: checkKillReadonly}
	readonlyAllowlist["gcc"] = &cmdAllow{check: checkCompilerQuery}
	readonlyAllowlist["g++"] = readonlyAllowlist["gcc"]
	readonlyAllowlist["cc"] = readonlyAllowlist["gcc"]
	readonlyAllowlist["c++"] = readonlyAllowlist["gcc"]
	readonlyAllowlist["clang"] = readonlyAllowlist["gcc"]
	readonlyAllowlist["clang++"] = readonlyAllowlist["gcc"]
	readonlyAllowlist["make"] = &cmdAllow{check: checkCompilerQuery}
	readonlyAllowlist["gmake"] = readonlyAllowlist["make"]

	readonlyAllowlist["ctxmode"] = &cmdAllow{check: checkCtxmodeReadonly}
	readonlyAllowlist["command"] = &cmdAllow{
		check: func(argv []string) string {
			if isCommandQuery(argv[1:]) {
				return ""
			}
			return "command execute"
		},
	}
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
	scripts, errReason := collectSedScripts(argv[1:])
	if errReason != "" {
		return errReason
	}
	if len(scripts) == 0 {
		return "sed missing script"
	}
	for _, sc := range scripts {
		if reason := sedScriptAllowReason(sc); reason != "" {
			return reason
		}
	}
	return ""
}

func collectSedScripts(args []string) (scripts []string, reason string) {
	endOpts := false
	sawScript := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !endOpts {
			switch {
			case a == "--":
				endOpts = true
				continue
			case a == "-e" || a == "--expression":
				if i+1 >= len(args) {
					return nil, "sed -e missing"
				}
				scripts = append(scripts, args[i+1])
				sawScript = true
				i++
				continue
			case strings.HasPrefix(a, "--expression="):
				scripts = append(scripts, a[len("--expression="):])
				sawScript = true
				continue
			case a == "-f" || a == "--file" || strings.HasPrefix(a, "--file="):
				return nil, "sed -f file"
			case a == "-i" || strings.HasPrefix(a, "--in-place"):
				return nil, "sed -i"
			case a == "-n" || a == "--quiet" || a == "--silent" || a == "-E" || a == "-r" ||
				a == "--regexp-extended" || a == "-s" || a == "--separate" || a == "-z" ||
				a == "--null-data" || a == "--help" || a == "--version" || a == "-u" || a == "--unbuffered":
				continue
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1:
				for j := 1; j < len(a); j++ {
					switch a[j] {
					case 'n', 'E', 'r', 's', 'z', 'u':
						continue
					case 'e':
						tail := a[j+1:]
						if tail != "" {
							scripts = append(scripts, tail)
							sawScript = true
						} else if i+1 < len(args) {
							scripts = append(scripts, args[i+1])
							sawScript = true
							i++
						} else {
							return nil, "sed -e missing"
						}
						j = len(a)
					case 'f', 'i':
						return nil, "sed -" + string(a[j])
					default:
						return nil, "sed unknown -" + string(a[j])
					}
				}
				continue
			case strings.HasPrefix(a, "-"):
				return nil, "sed unknown " + a
			}
		}
		if !sawScript {
			scripts = append(scripts, a)
			sawScript = true
			continue
		}
	}
	return scripts, ""
}

func sedScriptAllowReason(script string) string {
	s := script
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == ';') {
			i++
		}
		if i >= len(s) {
			break
		}
		if s[i] == '#' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		}
		if s[i] == '{' || s[i] == '}' {
			return "sed brace"
		}
		adv, ok := sedConsumeAddress(s, i)
		if !ok {
			// bare command with no address is fine — reparse as command
			adv = i
		} else {
			i = adv
			if i < len(s) && s[i] == ',' {
				i++
				adv, ok = sedConsumeAddress(s, i)
				if !ok {
					return "sed address range"
				}
				i = adv
			}
		}
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i < len(s) && s[i] == '!' {
			i++
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
		}
		if i >= len(s) {
			return "sed missing command"
		}
		cmd := s[i]
		i++
		switch cmd {
		case 'p', 'd', '=', 'x', 'h', 'g', 'G', 'H', 'n', 'N', 'P', 'D', 'z':
			// zero-arg
		case 'q', 'Q':
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
		case 's':
			flags, next, ok := sedConsumeS(s, i)
			if !ok {
				return "sed s parse"
			}
			for _, f := range flags {
				switch f {
				case 'g', 'p', 'i', 'I', 'm', 'M', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
					continue
				default:
					return "sed s flag " + string(f)
				}
			}
			i = next
		case 'y':
			return "sed y"
		case 'a', 'i', 'c', 'r', 'R', 'w', 'W', 'e', 'b', 't', 'T', 'l', 'L', 'F', 'v':
			return "sed cmd " + string(cmd)
		default:
			return "sed cmd " + string(cmd)
		}
	}
	return ""
}

func sedConsumeAddress(s string, i int) (int, bool) {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) {
		return i, false
	}
	if s[i] == '$' {
		return i + 1, true
	}
	if s[i] >= '0' && s[i] <= '9' {
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		return i, true
	}
	if s[i] == '/' {
		i++
		for i < len(s) && s[i] != '/' {
			if s[i] == '\\' && i+1 < len(s) {
				i += 2
				continue
			}
			if s[i] == '\n' {
				return i, false
			}
			i++
		}
		if i >= len(s) || s[i] != '/' {
			return i, false
		}
		return i + 1, true
	}
	if s[i] == '\\' && i+1 < len(s) {
		delim := s[i+1]
		if delim == '\n' || delim == '\\' {
			return i, false
		}
		i += 2
		for i < len(s) && s[i] != delim {
			if s[i] == '\\' && i+1 < len(s) {
				i += 2
				continue
			}
			i++
		}
		if i >= len(s) {
			return i, false
		}
		return i + 1, true
	}
	return i, false
}

func sedConsumeS(s string, i int) (flags string, next int, ok bool) {
	if i >= len(s) {
		return "", i, false
	}
	delim := s[i]
	i++
	for i < len(s) && s[i] != delim {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		i++
	}
	if i >= len(s) {
		return "", i, false
	}
	i++
	for i < len(s) && s[i] != delim {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		i++
	}
	if i >= len(s) {
		return "", i, false
	}
	i++
	start := i
	for i < len(s) && s[i] != ';' && s[i] != '\n' && s[i] != ' ' && s[i] != '\t' && s[i] != '{' && s[i] != '}' {
		i++
	}
	return s[start:i], i, true
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
		"ls-files", "ls-tree", "ls-remote", "cat-file", "for-each-ref",
		"describe", "shortlog", "fsck", "count-objects", "check-ignore",
		"var", "name-rev", "rev-list", "symbolic-ref", "merge-base":
		return gitOptsAllow(sub, rest)
	case "reflog":
		// allowlist-layer close: expire/delete write; bare/show inspect.
		if len(rest) == 0 {
			return gitOptsAllow(sub, rest)
		}
		sub2 := rest[0]
		if sub2 == "show" || sub2 == "-h" || sub2 == "--help" {
			return gitOptsAllow(sub, rest)
		}
		if strings.HasPrefix(sub2, "-") {
			// flag-only reflog listing (e.g. -n 5) stays read-only
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
			"--merged", "--no-merged", "--points-at", "--format", "--sort", "-h", "--help",
			"--column", "--no-column":
			query = true
			switch a {
			case "--contains", "--no-contains", "--merged", "--no-merged", "--points-at",
				"--format", "--sort":
				i++
			}
			continue
		case "-v", "-vv", "--verbose", "-q", "--quiet", "--color", "--no-color":
			// Modifiers only — do not alone authorize branch creation.
			continue
		}
		if strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--format=") ||
			strings.HasPrefix(a, "--contains=") || strings.HasPrefix(a, "--merged=") ||
			strings.HasPrefix(a, "--points-at=") || strings.HasPrefix(a, "--color=") {
			query = true
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
			"--format", "--sort", "--merged", "--no-merged", "--verify", "-v",
			"-h", "--help", "--color", "--no-color", "-i", "--ignore-case":
			listish = true
			continue
		}
		if strings.HasPrefix(a, "-n") || strings.HasPrefix(a, "--format=") ||
			strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--contains=") {
			listish = true
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
			"--name-only", "--show-origin", "--show-scope", "-h", "--help":
			hasGet = true
			continue
		case "--global", "--system", "--local", "--worktree", "--includes", "--no-includes":
			// Scope modifiers only — require an explicit get/list action.
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
	case "show", "get-url", "help":
		return ""
	case "add", "remove", "rm", "rename", "set-url", "set-branches", "set-head", "prune", "update":
		return "git remote " + sub
	default:
		return "git remote " + sub
	}
}

func gitWorktreeAllow(rest []string) string {
	if len(rest) == 0 {
		return ""
	}
	sub := rest[0]
	switch sub {
	case "list", "-h", "--help":
		return ""
	case "add", "remove", "rm", "prune", "move", "lock", "unlock", "repair":
		return "git worktree " + sub
	default:
		if strings.HasPrefix(sub, "-") {
			return ""
		}
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
		deny := []string{
			"toolexec", "exec", "modfile", "overlay", "go", "sdk",
			"asmflags", "gcflags", "ldflags", "gccgoflags",
		}
		for _, a := range rest {
			if a == "--" || !strings.HasPrefix(a, "-") {
				continue
			}
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
			}
			for _, d := range deny {
				if name == d {
					return "go list -" + d
				}
			}
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
		case "read", "list", "ls", "capture", "dump", "get", "info", "status", "help", "wait-output":
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
	// Skip global flags (-workdir, -config, etc.)
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if strings.HasPrefix(a, "-") {
			// value-taking globals commonly used
			if a == "-workdir" || a == "-config" || a == "-C" || strings.HasPrefix(a, "-workdir=") || strings.HasPrefix(a, "-config=") {
				if !strings.Contains(a, "=") {
					i += 2
				} else {
					i++
				}
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
	base := filepath.Base(argv[0])
	base = canonicalResolvedBase(base)
	switch base {
	case "eval", "exec", "source", ".", "coproc", "nohup":
		return base
	case "function":
		return "function definition"
	case "[[", "[", "test", "((":
		return ""
	}
	if strings.HasSuffix(base, "()") {
		return "function definition"
	}
	if hit := allowlistInterpreterHit(argv, base); hit != "" {
		return hit
	}
	if allowlistIsInterpreter(base) {
		return ""
	}
	if allDigits(base) {
		return ""
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
	label := "interpreter"
	isPython := base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3")
	if isPython {
		label = "python interpreter"
	} else if base == "node" || base == "nodejs" || base == "ts-node" || base == "tsx" || base == "bun" {
		label = "node interpreter"
	} else if base == "awk" || base == "gawk" || base == "mawk" || base == "nawk" {
		label = "awk program"
	} else {
		label = base + " interpreter"
	}
	// Narrow: interpreters are removed from the strict allowlist except
	// `python3 -m json.tool` with at most one positional input file.
	// --version/--help/syntax-check and all other interpreters fail closed.
	if isPython {
		if hit, has := pythonModuleHit(argv[1:]); has {
			return hit
		}
	}
	return label
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
			i++
			continue
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
			"ionice", "taskset", "chrt", "strace", "ltrace", "setsid", "time",
			"if", "then", "elif", "else", "while", "until", "do", "!":
			i++
			steps++
			if base == "timeout" {
				i = skipTimeoutArgs(argv, i)
				continue
			}
			for i < len(argv) {
				x := argv[i]
				if x == "--" {
					i++
					break
				}
				if !strings.HasPrefix(x, "-") || x == "-" {
					break
				}
				// value-taking short cuts for common wrappers
				if base == "env" && (x == "-u" || x == "--unset") {
					i += 2
					continue
				}
				if (base == "nice" && (x == "-n" || x == "--adjustment")) ||
					(base == "strace" || base == "ltrace") {
					i++
					continue
				}
				i++
			}
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
	case strings.Contains(d, "python") && (strings.Contains(d, "program") || strings.Contains(d, "interpreter")),
		strings.Contains(d, "javascript") || strings.Contains(d, "node"),
		strings.Contains(d, "perl") && strings.Contains(d, "interpreter"),
		strings.Contains(d, "ruby") && strings.Contains(d, "interpreter"):
		return "for JSON use jq; for text/files use rg / rg --files; for file view use cat/head/sed -n"
	case strings.Contains(d, "git config"):
		return "use git config --get <key> or git config -l"
	case strings.Contains(d, "sqlite") && (strings.Contains(d, "safe") || strings.Contains(d, "readonly")):
		return "add -readonly -safe and pass SQL as a positional argument"
	case strings.Contains(d, "sqlite") && strings.Contains(d, "sql"):
		return "pass SQL as a positional arg (stdin/pipe/interactive blocked); keep -readonly -safe"
	case strings.Contains(d, "sqlite") && strings.Contains(d, "dangerous"):
		return "add -readonly -safe; avoid writefile/edit/load_extension"
	case strings.Contains(d, "go test") || strings.Contains(d, "go build") ||
		strings.Contains(d, "go run") || strings.Contains(d, "go fmt") ||
		strings.Contains(d, "npm") || strings.Contains(d, "cargo") ||
		strings.Contains(d, "make"):
		return "this is a readonly role; hand write/test/build work to verifier or the main agent"
	case strings.Contains(d, "process substitution"):
		return "avoid <(...) / >(...); use a pipe (cmd | other) or temp-free constructs like rg/cat"
	case strings.Contains(d, "wget") || strings.Contains(d, "unknown command"):
		return "prefer curl -sS for HTTP GET, or cat/rg/git show for local files"
	case strings.Contains(d, "command substitution") || strings.Contains(d, "eval") ||
		strings.Contains(d, "exec") || strings.Contains(d, "source"):
		return "run allowed commands directly; no eval/source/exec/$(...)"
	default:
		return "use allowlisted read tools (ls/cat/rg/git/jq/curl -sS); write/test → verifier"
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
text: sort uniq cut tr jq diff cmp echo printf
vcs: git
http_db: curl sqlite3
go_meta: go gofmt ctxmode
ops: ps pgrep ss journalctl systemctl env which date pwd
archive: tar unzip gzip
`)
}
