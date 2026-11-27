package main

// role_guards_readonly.go — strict read-only command-head and CLI flag screeners.

import (
	"path/filepath"
	"strconv"
	"strings"
)

// ---------- rule 2: read-only write guard ----------

// fsWriteHeads are command heads that unconditionally write, remove, create or
// move filesystem objects (or, for the lock/pty/shell runners at the end,
// always escape the read-only write fence).
var fsWriteHeads = map[string]bool{
	"rm": true, "unlink": true, "rmdir": true, "mv": true, "cp": true,
	"install": true, "mkdir": true, "mktemp": true, "touch": true,
	"truncate": true, "dd": true, "tee": true, "chmod": true, "chown": true,
	"chgrp": true, "ln": true, "patch": true, "rsync": true, "scp": true,
	"sftp": true,
	// Interactive / in-place editors and stream copiers.
	"ed": true, "ex": true, "vi": true, "vim": true, "nvim": true,
	"nano": true, "sponge": true,
	// File split/allocation/attribute writes.
	"split": true, "csplit": true, "fallocate": true, "chattr": true,
	"setfattr": true, "setfacl": true,
	"shred": true, "rename": true, "prename": true, "file-rename": true,
	"wipefs": true,
	// Mount and special-file creation (mount is handled by a dual-mode
	// screen: bare/`mount -l`/`mount -t T` listings stay free).
	"umount": true, "mknod": true, "mkfifo": true,
	// Archive writers / binary tools.
	"uudecode": true, "zip": true, "7z": true, "7za": true, "7zr": true,
	"rar": true, "cpio": true, "ar": true, "ranlib": true,
	"strip": true, "objcopy": true,
	// Compilers and build drivers are handled by a dual-mode screen
	// (compilerQueryOnly): pure --version/--help/-dumpversion probes stay
	// free; anything else writes.
	// Package managers mutate environments/caches.
	"pip": true, "pip3": true, "pipx": true, "uv": true, "poetry": true,
	"conda": true, "gem": true, "composer": true,
	// flock takes a write lock; script writes a pty transcript / spawns a shell.
	"flock": true, "script": true,
	// `.`/`source` execute unreviewed script files in the current shell.
	".": true, "source": true,
}

// procKillHeads terminate processes; blocked for strict read-only roles.
// kill is handled by a dual-mode screen (`kill -l`/`kill -L` lists signal
// names and stays free).
var procKillHeads = map[string]bool{
	"pkill": true, "killall": true,
}

// mountQueryOnly reports whether a mount argv is a pure listing: no
// positional device/dir operand, no -a, no -o/--options, no --bind/--move.
// `mount`, `mount -l`, `mount -t ext4`, `mount -l -t tmpfs` list the table.
func mountQueryOnly(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t" || a == "--types" || a == "-O" || a == "--test-opts":
			i++ // -t TYPE / -O LIST consume a value but stay a listing
		case a == "-a" || a == "--all" || a == "-o" || a == "--options" ||
			a == "--bind" || a == "--move" || a == "-B" || a == "-M" || a == "-R" ||
			a == "--remount" || a == "--rbind" || a == "--make-shared" ||
			strings.HasPrefix(a, "--make-") || strings.HasPrefix(a, "--options="):
			return false
		case strings.HasPrefix(a, "-"):
			continue // -l / -v / -s / -f-free listing flags
		default:
			return false // device or mountpoint operand => a real mount
		}
	}
	return true
}

// compilerQueryOnly reports whether a compiler/build-driver argv is a pure
// version/help probe: only --version/-version/-V/--help/-h (and gcc-style
// -dumpversion/-dumpmachine), no source file or build target operand.
func compilerQueryOnly(args []string, base string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		switch a {
		case "--version", "-version", "-V", "--help", "-h", "-v":
			continue
		}
		if (base == "gcc" || base == "g++" || base == "cc" || base == "c++" ||
			base == "clang" || base == "clang++") &&
			(a == "-dumpversion" || a == "-dumpmachine" || strings.HasPrefix(a, "-print-")) {
			continue
		}
		return false
	}
	return true
}

// npmFamilyWriteSubs are the mutating subcommands shared by npm/pnpm/yarn/bun.
var npmFamilyWriteSubs = map[string]bool{
	"install": true, "i": true, "add": true, "a": true, "remove": true,
	"rm": true, "uninstall": true, "ci": true,
	"publish": true, "link": true, "unlink": true, "update": true,
	"run": true, "test": true, "build": true,
	"init": true, "create": true, "patch": true, "pm": true,
}

// goWriteSubs are the go-tool subcommands that build, run, generate or mutate
// (version/env/list/doc stay free; env -w/-u and work are screened inside
// screenGoWrite).
var goWriteSubs = map[string]bool{
	"build": true, "test": true, "install": true, "run": true, "generate": true,
	"get": true, "mod": true, "clean": true, "fix": true, "fmt": true,
}

// cargoWriteSubs likewise for cargo.
var cargoWriteSubs = map[string]bool{
	"build": true, "test": true, "run": true, "install": true, "clean": true,
	"publish": true, "add": true, "remove": true,
	"fix": true, "update": true, "init": true, "new": true,
	"vendor": true, "generate-lockfile": true,
}

// systemctlWriteSubs are systemctl verbs that change state.
var systemctlWriteSubs = map[string]bool{
	"start": true, "stop": true, "restart": true, "reload": true,
	"enable": true, "disable": true, "mask": true, "unmask": true,
	"daemon-reload": true,
}

// screenGoWrite applies the go-tool write model for strict read-only:
// goWriteSubs verbs mutate; `go env -w`/`-u` (including glued
// -wKEY=VAL/-uKEY) writes go env config; `go work` (init/use/sync/edit)
// mutates the workspace file.
func screenGoWrite(args []string) string {
	sub := firstNonFlagArg(args)
	if sub == "" {
		return ""
	}
	if goWriteSubs[sub] {
		return "go " + sub
	}
	if sub == "work" {
		return "go work"
	}
	if sub == "env" {
		// Scan only the operands after `env`: -w/-u (and the glued
		// -wKEY=VAL/-uKEY forms) write go env configuration.
		seenEnv := false
		for _, a := range args {
			if a == "env" && !seenEnv {
				seenEnv = true
				continue
			}
			if !seenEnv {
				continue
			}
			if a == "-w" || a == "-u" || a == "--w" || a == "--u" ||
				strings.HasPrefix(a, "-w") || strings.HasPrefix(a, "-u") ||
				strings.HasPrefix(a, "--w=") || strings.HasPrefix(a, "--u=") {
				return "go env " + a
			}
		}
	}
	return ""
}

// screenCargoWrite applies the cargo write model; `cargo fmt` is dual-mode
// (--check stays read-only).
func screenCargoWrite(args []string) string {
	sub := firstNonFlagArg(args)
	if sub == "" {
		return ""
	}
	if sub == "fmt" {
		for _, a := range args {
			if a == "--check" {
				return ""
			}
		}
		return "cargo fmt"
	}
	if cargoWriteSubs[sub] {
		return "cargo " + sub
	}
	return ""
}

// gitReadonlySubs is the explicit whitelist of read-only git subcommands.
// Anything not here and not handled by the dual-mode branches
// (worktree/branch/tag/config/remote/stash) is a write for the strict guard.
var gitReadonlySubs = map[string]bool{
	"status": true, "diff": true, "log": true, "show": true,
	"rev-parse": true, "ls-files": true, "ls-tree": true, "ls-remote": true,
	"cat-file": true, "blame": true, "annotate": true, "grep": true,
	"describe": true, "merge-base": true, "rev-list": true,
	"for-each-ref": true, "shortlog": true, "name-rev": true,
	"check-ignore": true, "check-attr": true, "check-ref-format": true,
	"var": true, "version": true, "help": true,
	"diff-tree": true, "diff-files": true, "diff-index": true,
	"verify-commit": true, "verify-tag": true, "whatchanged": true,
	"cherry": true, "count-objects": true,
	// fsck is dual-mode: plain checks are free, --lost-found writes.
	// Dual-mode subcommands are handled in screenGitWrite and deliberately
	// absent here: worktree, branch, tag, config, remote, stash.
}

// gitStashReadonlySubs are the stash verbs that only inspect.
var gitStashReadonlySubs = map[string]bool{
	"list": true, "show": true,
}

// screenReadonlyWrite returns the guard hit for ONE resolved command head and
// its argv (starting at the head), or "" when allowed. The head is screened
// under its own basename AND the basename of the file it resolves through
// (headBaseAliasHits), so an alias like `ln -s /usr/bin/rm /tmp/remove`
// cannot walk past the write table.
// screenReadonlyWrite is the no-caller convenience form: it screens
// under the process-cwd fallback the old empty screenCwd had. Guard
// recursions that already hold a caller use screenReadonlyWritePath so
// the call's own cwd reaches alias resolution.
func screenReadonlyWrite(headArgv []string) string {
	return screenReadonlyWritePath(headArgv, "", callerIdentity{})
}

// screenReadonlyWritePath is screenReadonlyWrite with an explicit effective
// PATH for alias resolution (Q4 symlink penetration under envAs overrides).
func screenReadonlyWritePath(headArgv []string, pathEnv string, caller callerIdentity) string {
	if len(headArgv) == 0 {
		return ""
	}
	args := headArgv[1:]
	for _, base := range headBaseAliasHits(headArgv, pathEnv, caller) {
		// `python -m <mod>` runs an arbitrary module: screen it as the command
		// it actually executes instead of as an interpreter head. Runs before
		// the alias walk so /usr/bin/python3 and python3 behave identically.
		if lang, ok := heredocInterpLang(base); ok && lang == "python" {
			if hit, isModuleRun := pythonModuleHit(args); isModuleRun {
				if hit != "" {
					return hit
				}
				continue // vetted module run: the interpreter head is done here
			}
		}
		if isPureQueryInvocation(headArgv) && pureQueryOnlyHeads[base] {
			continue // `dispatch-agent --version` is a query, not a spawn
		}
		if hit := screenReadonlyWriteAlias(headArgv, base, args); hit != "" {
			return hit
		}
	}
	return ""
}

// screenReadonlyWriteAlias applies the whole strict read-only head model to
// ONE candidate name for the command head: base is the spelling under test
// (the name as typed, or the basename of the symlink behind it) and args are
// the words after the head.
func screenReadonlyWriteAlias(headArgv []string, base string, args []string) string {
	if fsWriteHeads[base] || procKillHeads[base] {
		return base
	}
	// Dual-mode heads: a pure query spelling stays free, everything else
	// writes.
	switch base {
	case "crontab":
		if len(args) == 1 && args[0] == "-l" {
			return ""
		}
		return "crontab"
	case "mount":
		if mountQueryOnly(args) {
			return ""
		}
		return "mount"
	case "kill":
		if len(args) == 1 && (args[0] == "-l" || args[0] == "-L" || args[0] == "--list") {
			return ""
		}
		return "kill"
	case "gcc", "g++", "cc", "c++", "clang", "clang++", "rustc", "javac",
		"make", "gmake", "cmake", "ninja", "meson":
		if compilerQueryOnly(args, base) {
			return ""
		}
		return base
	case "flock", "script":
		return base
	}
	switch base {
	case "sed", "gsed":
		if hasInPlaceFlag(args) {
			return base + " -i"
		}
		if hit := screenSedScriptWrite(args); hit != "" {
			return hit
		}
	case "perl", "ruby":
		if hasInterpInPlaceFlag(headArgv) {
			return base + " -i"
		}
		// Reaching here means unwrapInterpreterInline found no -e/-r inline
		// code: a script file or stdin must block; -n (syntax check) and
		// version/help flags stay free.
		return screenInterpFileRun(args, base)
	case "awk", "gawk", "mawk", "nawk":
		if hit := screenAwkInplace(args); hit != "" {
			return hit
		}
		if hit := screenAwkProgram(args); hit != "" {
			return hit
		}
	case "gofmt", "goimports":
		for _, a := range args {
			if a == "-w" || strings.HasPrefix(a, "-w=") {
				return base + " -w"
			}
		}
	case "git":
		if _, hit := screenGitGlobalArgs(args); hit != "" {
			return hit
		}
		return screenGitWrite(args)
	case "git-fsck":
		// Dashed form /usr/lib/git-core/git-fsck → symlink to git with implicit
		// "fsck" subcommand; screen as git fsck <args>.
		return screenGitWrite(append([]string{"fsck"}, args...))
	case "tar", "bsdtar", "gtar":
		return screenTarWrite(args, base)
	case "unzip":
		return screenUnzipWrite(args)
	case "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "zstd", "unzstd", "lz4":
		return screenCompressWrite(args, base)
	case "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash":
		// Reaching here means unwrapShellArgv found no `-c` inline code, so
		// the invocation runs a script file or reads stdin — both must block
		// for strict read-only. `-n` syntax checks and version/help stay free.
		return screenShellFileRun(args, base)
	case "node", "nodejs", "ts-node", "tsx", "php":
		// Reaching here means unwrapInterpreterInline found no -e/-r inline
		// code: a script file or stdin must block; version/help stay free.
		return screenInterpFileRun(args, base)
	case "bun":
		// bun doubles as a package manager: its npm-family verbs
		// (install/add/remove/update/link/publish/init/create/build/pm)
		// mutate before any script-run logic applies.
		if sub := firstNonFlagArg(args); sub != "" && npmFamilyWriteSubs[sub] {
			return "bun " + sub
		}
		return screenInterpFileRun(args, base)
	case "ctxmode":
		// `ctxmode index` writes the shared KB — same surface as
		// ctx_kb action=index (router.go): every read-only role,
		// verifier included, is refused. `ctxmode search` / `-h` /
		// `--help` stay free; global -workdir/-config flags are skipped.
		if sub := ctxmodeCLIAction(args); sub == "index" {
			return "ctxmode index"
		}
	case "curl":
		return screenCurlWrite(args)
	case "wget":
		return screenWgetWrite(args)
	case "systemctl":
		if sub := firstNonFlagArg(args); sub != "" && systemctlWriteSubs[sub] {
			return "systemctl " + sub
		}
	case "go":
		if hit := screenGoWrite(args); hit != "" {
			return hit
		}
	case "cargo":
		if hit := screenCargoWrite(args); hit != "" {
			return hit
		}
	case "npm", "pnpm", "yarn":
		// npm/pnpm/yarn run under the same finite accept grammar as the
		// sub-agent screen (parseNpmFamilyArgv): an argv that does not fit
		// the grammar Rejects here too (fail closed — the value slot of an
		// unlisted option could masquerade as a read-only verb), the
		// exec/dlx verbs fetch-and-run unvetted code, and the remaining
		// verbs hit the write table. A flag-only or other-verb argv falls
		// through unchanged.
		switch r := parseNpmFamilyArgv(base, args); r.state {
		case npmArgvReject:
			return base + " " + r.reason
		case npmArgvExec:
			return base + " " + r.verb
		default:
			if r.verb != "" && npmFamilyWriteSubs[r.verb] {
				return base + " " + r.verb
			}
		}
	case "npx", "bunx", "pnpx":
		return base // package-runner: always executes a fetched binary
	default:
		if base == "python" || strings.HasPrefix(base, "python2") || strings.HasPrefix(base, "python3") {
			// Reaching here means unwrapInterpreterInline found no -c inline
			// code and pythonModuleHit found no -m: a script file or stdin
			// must block while --version/-V/-VV/--help/-h stay free.
			return screenInterpFileRun(args, base)
		}
	}
	return ""
}

// awkProgramFrags collects awk's program text for a SUB-AGENT caller:
// every -e PROG / -ePROG / --source PROG / --source=PROG fragment plus
// the first positional operand when no -e/--source appeared, joined with
// "\n" for screening. -f FILE / --file=FILE names an unvetted program
// file — reported via the file flag so the caller can decide (sub-agent:
// skip; strict read-only: block). hit names the offending dynamic operand
// in a code/exec position; a plain data-position dynamic word (input file,
// -v/-F value, -f path) is not a hit (SH11 W11-2).
// isStdinDevicePath reports a literal path spelling of the process stdin
// device: reading it is equivalent to reading fd 0, so `sh /dev/stdin`,
// `python3 /proc/self/fd/0`, `awk -f /dev/stdin` and `sed -f /dev/fd/0`
// all consume the piped/redirected stream as PROGRAM text. Dynamic words
// are handled by the callers' own placeholder checks.
func isStdinDevicePath(p string) bool {
	if p == "" {
		return false
	}
	// Dynamic words under /dev or /proc can resolve to the stdin device at
	// runtime (`/dev/stdi?`, `/dev/$(printf stdin)`): treat them as stdin
	// program paths so sed/awk -f cannot smuggle unvetted script text.
	if isDynamicArg(p) {
		clean := filepath.Clean(p)
		return clean == "/dev" || clean == "/proc" ||
			strings.HasPrefix(clean, "/dev/") || strings.HasPrefix(clean, "/proc/")
	}
	p = filepath.Clean(p) // /dev/fd/./0 -> /dev/fd/0
	if p == "/dev/stdin" {
		return true
	}
	// Compare the trailing fd number numerically: Linux open() accepts
	// padded spellings (fd/00, fd/000) that filepath.Clean does NOT fold,
	// while non-numeric tails (fd/x) and other fds (fd/1) stay free.
	for _, prefix := range []string{"/dev/fd", "/proc/self/fd", "/proc/thread-self/fd"} {
		if tail, ok := strings.CutPrefix(p, prefix+"/"); ok && tail != "" && !strings.Contains(tail, "/") {
			if n, err := strconv.Atoi(tail); err == nil {
				return n == 0
			}
		}
	}
	return false
}

func awkProgramFrags(args []string) (string, bool, string) {
	var frags []string
	var positional string
	sawFile := false
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if isDynamicArg(a) {
			if !endOpts && strings.HasPrefix(a, "-") {
				return "", sawFile, "dynamic code payload"
			}
			if !isSafeDynamicDataOperand(a) || isStdinDevicePath(a) {
				return "", sawFile, "dynamic code payload"
			}
			if !endOpts && positional == "" && len(frags) == 0 {
				return "", sawFile, "dynamic code payload"
			}
			if positional == "" {
				positional = a
			}
			continue
		}
		if !endOpts && strings.HasPrefix(a, "--") && a != "--" {
			name, val, hasEq := strings.Cut(a[2:], "=")
			switch {
			case isLongOptAbbrev(name, "file", 3):
				sawFile = true
				if !hasEq {
					if i+1 < len(args) {
						val = args[i+1]
					}
					i++
				}
				if val == "-" || isStdinDevicePath(val) {
					return "", sawFile, "awk script from stdin"
				}
				if isDynamicArg(val) && !isSafeDynamicDataOperand(val) {
					return "", sawFile, "dynamic code payload"
				}
				continue
			case isLongOptAbbrev(name, "source", 2):
				if hasEq {
					frags = append(frags, val)
				} else if i+1 < len(args) {
					frags = append(frags, args[i+1])
					i++
				}
				continue
			case name == "assign" || name == "field-separator" || isLongOptAbbrev(name, "include", 3):
				if !hasEq {
					i++
				}
				continue
			case strings.HasPrefix("file", name) || strings.HasPrefix("include", name):
				return "", sawFile, "dynamic code payload"
			default:
				continue
			}
		}
		switch {
		case a == "--" && !endOpts:
			endOpts = true
		case a == "-f":
			sawFile = true
			if i+1 < len(args) {
				v := args[i+1]
				// S3: `awk -f -` (and the /dev/stdin family) reads the
				// PROGRAM from stdin — unvetted.
				if v == "-" || isStdinDevicePath(v) {
					return "", sawFile, "awk script from stdin"
				}
				if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
					return "", sawFile, "dynamic code payload"
				}
			}
			i++ // consume the file operand
		case strings.HasPrefix(a, "--file="):
			sawFile = true
			v := a[len("--file="):]
			if v == "-" || isStdinDevicePath(v) {
				return "", sawFile, "awk script from stdin"
			}
			if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
				return "", sawFile, "dynamic code payload"
			}
		case a == "-e" || a == "--source":
			if i+1 < len(args) {
				frags = append(frags, args[i+1])
				i++
			}
		case a == "-F" || a == "-v" || a == "-i":
			i++
		case !endOpts && strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'e':
					if tail := a[j+1:]; tail != "" {
						frags = append(frags, tail)
					} else if i+1 < len(args) {
						frags = append(frags, args[i+1])
						i++
					}
					j = len(a)
				case 'f':
					sawFile = true
					if j+1 < len(a) {
						v := a[j+1:]
						if v == "-" || isStdinDevicePath(v) {
							return "", sawFile, "awk script from stdin"
						}
						if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
							return "", sawFile, "dynamic code payload"
						}
					} else {
						if i+1 < len(args) {
							v := args[i+1]
							if v == "-" || isStdinDevicePath(v) {
								return "", sawFile, "awk script from stdin"
							}
							if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
								return "", sawFile, "dynamic code payload"
							}
						}
						i++
					}
					j = len(a)
				case 'F', 'v', 'i':
					if j+1 >= len(a) {
						i++
					}
					j = len(a)
				}
			}
		default:
			if positional == "" && len(frags) == 0 {
				positional = a
			}
		}
	}
	if len(frags) == 0 && positional != "" && !isDynamicArg(positional) {
		frags = append(frags, positional)
	}
	return strings.Join(frags, "\n"), sawFile, ""
}

// screenAwkSubagent extracts awk's program text for a SUB-AGENT caller and
// screens the command strings inside its exec escapes (system("cmd"),
// "cmd" | getline, print x | "cmd") as shell text. A dynamic command
// (system(var), concatenation) cannot be screened statically — the program
// is blocked outright when it mentions a blocked agent/orchestrator name.
// A -f program FILE is skipped here (unvetted text is worse than skipped
// text: the strict guard blocks it; the sub-agent guard has no write
// fence to protect inside awk).
func screenAwkSubagent(args []string, depth int, caller callerIdentity) string {
	program, _, hit := awkProgramFrags(args)
	if hit != "" {
		return hit
	}
	if program == "" {
		return ""
	}
	if isDynamicArg(program) {
		return "dynamic code payload"
	}
	// Screen each STRING LITERAL that reaches a command sink as shell text;
	// a non-literal command is only allowed when it names no blocked head.
	for _, lit := range awkCommandLiterals(program) {
		if isDynamicArg(lit.text) {
			return "dynamic code payload"
		}
		if lit.dynamic {
			// Dynamic command text: only fails when the program itself names
			// a blocked agent/orchestrator identifier. A dispatch-report hit
			// keeps the report command identity in the detail so
			// blockedReportError appends the ctx_report hint.
			if programNamesBlockedAgent(program) {
				if codeTokens(program).hasIdent("dispatch-report") {
					return "awk dynamic cmd dispatch-report"
				}
				return "awk dynamic cmd"
			}
			continue
		}
		if hit := guardShellSubagentDepth(lit.text, depth+1, caller); hit != "" {
			return hit
		}
	}
	return ""
}

// awkCmdLit is one command-text literal extracted from an awk program, or a
// dynamic marker when the command is not a static string.
type awkCmdLit struct {
	text    string
	dynamic bool
}

// awkCommandLiterals walks the program and returns the string literals
// (decoded, quotes stripped) that feed command sinks: system(...),
// `"cmd" | getline`, `print x | "cmd"`. A sink fed by a non-literal
// expression yields a dynamic entry instead.
func awkCommandLiterals(prog string) []awkCmdLit {
	var out []awkCmdLit
	n := len(prog)
	i := 0
	inStr := byte(0)
	strStart := -1
	var lastLit string
	lastWasLit := false
	inPrint := false
	paren := 0
	for i < n {
		c := prog[i]
		switch {
		case inStr != 0:
			if c == '\\' {
				i++
			} else if c == inStr {
				inStr = 0
				lit, _, ok := leadingStringLiteral(prog[strStart : i+1])
				lastWasLit = ok
				lastLit = lit
			}
		case c == '"' || c == '\'':
			inStr = c
			strStart = i
			lastWasLit = false
		case c == '(' || c == '[':
			paren++
		case c == ')' || c == ']':
			if paren > 0 {
				paren--
			}
		case c == ' ' || c == '\t':
			// Whitespace does not disturb the last-literal tracking (a literal
			// may precede `| getline` with a space: "cmd" | getline).
		case c == ';' || c == '\n' || c == '{' || c == '}':
			if paren == 0 {
				inPrint = false
			}
			lastWasLit = false
		case c == '|':
			rest := strings.TrimLeft(prog[i+1:], " \t")
			if strings.HasPrefix(rest, "getline") {
				if lastWasLit {
					out = append(out, awkCmdLit{text: lastLit})
				} else {
					out = append(out, awkCmdLit{dynamic: true})
				}
			} else if inPrint {
				// print x | "cmd": screen the literal after the pipe.
				j := i + 1
				for j < n && (prog[j] == ' ' || prog[j] == '\t') {
					j++
				}
				if j < n && (prog[j] == '"' || prog[j] == '\'') {
					if lit, _, ok := leadingStringLiteral(prog[j:]); ok {
						out = append(out, awkCmdLit{text: lit})
					}
				} else {
					out = append(out, awkCmdLit{dynamic: true})
				}
			}
			lastWasLit = false
		default:
			if isIdentByte(c) {
				j := i
				for j < n && isIdentByte(prog[j]) {
					j++
				}
				w := prog[i:j]
				if w == "print" || w == "printf" {
					inPrint = true
				}
				if w == "system" {
					// system( LIT ) / system LIT: take the literal operand.
					k := j
					for k < n && (prog[k] == ' ' || prog[k] == '\t' || prog[k] == '(') {
						k++
					}
					if k < n && (prog[k] == '"' || prog[k] == '\'') {
						if lit, _, ok := leadingStringLiteral(prog[k:]); ok {
							out = append(out, awkCmdLit{text: lit})
						}
					} else if k < n {
						out = append(out, awkCmdLit{dynamic: true})
					}
				}
				lastWasLit = false
				i = j
				continue
			}
			lastWasLit = false
		}
		i++
	}
	return out
}

// programNamesBlockedAgent reports whether program text names a blocked
// agent executable or orchestrator identifier (used to fail closed on
// dynamic awk command construction).
func programNamesBlockedAgent(prog string) bool {
	toks := codeTokens(prog)
	for _, name := range codeAgentNames {
		if toks.hasIdent(name) {
			return true
		}
	}
	return toks.hasIdent("herdr") || toks.hasIdent("herdsman") || toks.hasIdent("hc")
}

// sedDynamicScriptSafe is gone (R4): a dynamic s/// fragment can inject
// sed `e` commands when the expanded value contains the delimiter
// (`p='x/g;e pig'` → s/x/g;e pig/bar/g = EXECUTION). Restricted literal
// binds (litVars) resolve to static text BEFORE this point, so any
// placeholder still present is unvettable and the script slot rejects it.

// screenSedSubagent collects sed script text (inline -e payloads and the
// first positional operand) for a SUB-AGENT caller and screens any GNU sed
// `e` exec commands: `1e pig`, `sed -e 'e agy'`, `s/.*/pig/e`. The command
// text after `e` is screened as shell text.
func screenSedSubagent(args []string, depth int, caller callerIdentity) string {
	scripts, _ := sedScripts(args)
	for _, s := range scripts {
		if isDynamicArg(s) {
			return "dynamic code payload"
		}
		cmds := sedExecCommands(s)
		for _, cmd := range cmds {
			if hit := guardShellSubagentDepth(cmd, depth+1, caller); hit != "" {
				return hit
			}
		}
		if len(cmds) > 0 {
			return "sed e"
		}
	}
	sawExplicit := false
	sawScript := false
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" && !endOpts {
			endOpts = true
			continue
		}
		dynOptVal, dynOptKind := sedDynamicOptValue(a)
		if !endOpts && strings.HasPrefix(a, "-") && a != "-" && (!isDynamicArg(a) || dynOptKind != 0 || strings.HasPrefix(a, "--")) {
			if isDynamicArg(a) && dynOptKind == 0 {
				return "dynamic code payload"
			}
			if dynOptKind != 0 {
				switch {
				case dynOptVal == "-" || isStdinDevicePath(dynOptVal):
					return "sed script from stdin"
				case !isSafeDynamicDataOperand(dynOptVal):
					return "dynamic code payload"
				}
				sawExplicit = true
				continue
			}
			if strings.HasPrefix(a, "--") {
				name, val, hasEq := strings.Cut(a[2:], "=")
				switch {
				case isLongOptAbbrev(name, "file", 2):
					sawExplicit = true
					if !hasEq {
						if i+1 < len(args) {
							val = args[i+1]
						}
						i++
					}
					if val == "-" || isStdinDevicePath(val) {
						return "sed script from stdin"
					}
					if isDynamicArg(val) && !isSafeDynamicDataOperand(val) {
						return "dynamic code payload"
					}
				case isLongOptAbbrev(name, "expression", 1):
					sawExplicit = true
					if !hasEq {
						i++
					}
				case isLongOptAbbrev(name, "line-length", 1):
					if !hasEq {
						i++
					}
				case name == "f":
					return "dynamic code payload"
				}
				continue
			}
			switch {
			case a == "-f":
				sawExplicit = true
				// S3: `sed -f -` (and the /dev/stdin family) reads the SCRIPT
				// from stdin — unvetted program text; reject it like a
				// dynamic payload. A process-substitution target arrives as
				// a placeholder and must still name a safe data path.
				if i+1 < len(args) {
					v := args[i+1]
					if v == "-" || isStdinDevicePath(v) {
						return "sed script from stdin"
					}
					if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
						return "dynamic code payload"
					}
				}
				i++
			case a == "-e":
				sawExplicit = true
				// R13: the =value still names the script FILE — validate it
				// like a separate -f operand so a dynamic/proc-subst path
				// (--file=<(…) / --file=$X) or a stdin device path cannot
				// smuggle unvetted program text past the first-positional
				// check.
				if strings.HasPrefix(a, "--file=") {
					v := a[len("--file="):]
					if v == "-" || isStdinDevicePath(v) {
						return "sed script from stdin"
					}
					if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
						return "dynamic code payload"
					}
				}
			case strings.HasPrefix(a, "--"):
				// other long options: no value operand consumed
			default:
				for j := 1; j < len(a); j++ {
					switch a[j] {
					case 'e', 'f':
						sawExplicit = true
						if j+1 >= len(a) {
							if a[j] == 'f' && i+1 < len(args) {
								v := args[i+1]
								if v == "-" || isStdinDevicePath(v) {
									return "sed script from stdin"
								}
								if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
									return "dynamic code payload"
								}
							}
							i++
						} else {
							// Glued file/script operand (cluster tail): an `f`
							// tail names the script FILE — '-' or a stdin device
							// path reads stdin and a dynamic tail must still be a
							// safe data path.
							if a[j] == 'f' {
								v := a[j+1:]
								if v == "-" || isStdinDevicePath(v) {
									return "sed script from stdin"
								}
								if isDynamicArg(v) && !isSafeDynamicDataOperand(v) {
									return "dynamic code payload"
								}
							}
						}
						j = len(a)
					case 'l':
						if j+1 >= len(a) {
							i++
						}
						j = len(a)
					}
				}
			}
			continue
		}
		if isDynamicArg(a) {
			if !sawScript && !sawExplicit && a != "-" {
				sawScript = true
				continue
			}
			if !isSafeDynamicDataOperand(a) {
				return "dynamic code payload"
			}
			continue
		}
		if !sawScript && !sawExplicit && a != "-" {
			sawScript = true
		}
	}
	return ""
}

// sedDynamicOptValue locates the value slot of a DYNAMIC short-option
// cluster (-nf<V>, -e<V>, -l<V>): it scans the static prefix before the
// first dynamic byte for sed's value-carrying letters (e script, f file,
// l length — each ends the cluster). kind is 'e', 'f' or 'l' and val the
// dynamic tail (the glued operand); kind 0 means no recognisable value
// slot — either the word is not dynamic/option-shaped or the option zone
// itself is unvettable.
func sedDynamicOptValue(a string) (val string, kind byte) {
	if len(a) < 3 || a[0] != '-' || a[1] == '-' || !isDynamicArg(a) {
		return "", 0
	}
	// lim: the static prefix length — the cluster scan never crosses a
	// placeholder boundary.
	lim := len(a)
	for _, ph := range []string{cmdSubPlaceholder, cmdSubPlaceholderQuoted,
		cmdSubPlaceholderGlob, cmdSubPlaceholderAbsDq} {
		if k := strings.Index(a, ph); k >= 0 && k < lim {
			lim = k
		}
	}
	for j := 1; j < lim; j++ {
		switch a[j] {
		case 'e', 'f', 'l':
			if lim < len(a) {
				// The glued operand is everything after the letter — it
				// may carry static bytes before the dynamic part.
				return a[j+1:], a[j]
			}
			return "", 0 // value letter inside a fully static cluster
		}
	}
	return "", 0
}

// sedScripts extracts the script text fragments a sed invocation actually
// executes: every -e/--expression payload (separate, =glued, or a
// short-option-cluster tail) plus the FIRST positional operand when no -e/-f
// appeared — GNU sed treats only that first operand as the script; later
// positionals are always input file names. sawFile reports -f/--file
// (unvetted script file): the strict read-only guard fails closed on it,
// the sub-agent caller just keeps the inline fragments.
func sedScripts(args []string) (scripts []string, sawFile bool) {
	sawExplicit := false
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" && !endOpts {
			endOpts = true
			continue
		}
		if !endOpts && strings.HasPrefix(a, "--") {
			name, val, hasEq := strings.Cut(a[2:], "=")
			switch {
			case isLongOptAbbrev(name, "expression", 1):
				sawExplicit = true
				if hasEq {
					scripts = append(scripts, val)
				} else if i+1 < len(args) {
					scripts = append(scripts, args[i+1])
					i++
				}
			case isLongOptAbbrev(name, "file", 2):
				sawExplicit = true
				sawFile = true
				if !hasEq {
					i++
				}
			case isLongOptAbbrev(name, "line-length", 1):
				if !hasEq {
					i++
				}
			case name == "f":
				sawExplicit = true
				sawFile = true
			}
			continue
		}
		if !endOpts {
			switch {
			case a == "-e":
				sawExplicit = true
				if i+1 < len(args) {
					scripts = append(scripts, args[i+1])
					i++
				}
			case a == "-f":
				sawExplicit = true
				sawFile = true
				i++
			case strings.HasPrefix(a, "-") && len(a) > 1:
				lim := len(a)
				for _, ph := range []string{cmdSubPlaceholder, cmdSubPlaceholderQuoted,
					cmdSubPlaceholderGlob, cmdSubPlaceholderAbsDq} {
					if k := strings.Index(a, ph); k >= 0 && k < lim {
						lim = k
					}
				}
				sawValLetter := false
				for j := 1; j < lim; j++ {
					switch a[j] {
					case 'e':
						sawExplicit = true
						sawValLetter = true
						if tail := a[j+1:]; tail != "" {
							scripts = append(scripts, tail)
						} else if i+1 < len(args) {
							scripts = append(scripts, args[i+1])
							i++
						}
						j = lim
					case 'f':
						sawExplicit = true
						sawFile = true
						sawValLetter = true
						if j+1 >= len(a) {
							i++
						}
						j = lim
					case 'l':
						sawValLetter = true
						if j+1 >= len(a) {
							i++
						}
						j = lim
					}
				}
				if isDynamicArg(a) && !sawValLetter {
					scripts = append(scripts, a)
				}
			}
		}
		if endOpts || !strings.HasPrefix(a, "-") || a == "-" {
			if !sawExplicit && len(scripts) == 0 && a != "-" {
				scripts = append(scripts, a)
			}
		}
	}
	return scripts, sawFile
}

// sedExecCommands extracts the command text of GNU sed `e` executions:
// a bare `e cmd` command (executes cmd, output into pattern space) and
// `s///e` whose substituted text is executed. Returns nil when no e is
// present (sed -n '1,20p', s/a/b/g, /err/p stay free).
func sedExecCommands(s string) []string {
	var out []string
	i := 0
	n := len(s)
	atCmdStart := true // after ; { } or start-of-script an `e` is a command
	for i < n {
		c := s[i]
		switch {
		case c == '#':
			for i < n && s[i] != '\n' && s[i] != ';' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == ';' || c == '{' || c == '}':
			atCmdStart = true
			i++
		case c == '/':
			// Regex address: skip to the unquoted closing /, tracking [...].
			i++
			for i < n {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if s[i] == '[' {
					// Character class: delimiters inside [...] are literal.
					i++
					if i < n && s[i] == '^' {
						i++
					}
					if i < n && s[i] == ']' { // ] as first (data) char is literal
						i++
					}
					for i < n && s[i] != ']' {
						if s[i] == '\\' {
							if i+1 < n {
								i += 2
							} else {
								i = n
							}
							continue
						}
						i++
					}
					if i < n {
						i++ // closing ]
					}
					continue
				}
				if s[i] == '/' {
					i++
					// GNU sed allows I/M (and i/m) regex flags after the close.
					for i < n && (s[i] == 'I' || s[i] == 'M' || s[i] == 'i' || s[i] == 'm') {
						i++
					}
					break
				}
				i++
			}
			atCmdStart = true // an address precedes a command
		case c == 's' && atCmdStart:
			// s<delim><pat><delim><repl><delim><flags>: an `e` flag executes
			// the REPLACEMENT text as a command — extract it for screening.
			atCmdStart = false
			i++
			if i >= n {
				break
			}
			delim := s[i]
			i++
			// Skip the pattern part.
			for i < n && s[i] != delim {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				i++
			}
			if i >= n {
				break // truncated: no middle delimiter, no e flag possible
			}
			i++
			// The replacement part is the command text for s///e.
			replStart := i
			for i < n && s[i] != delim {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				i++
			}
			repl := s[replStart:i]
			if i >= n {
				break // truncated: no closing delimiter, no e flag possible
			}
			i++
			for i < n {
				fc := s[i]
				if fc == 'e' {
					if strings.TrimSpace(repl) != "" {
						out = append(out, repl)
					} else {
						out = append(out, s) // dynamic: pattern space content
					}
					break
				}
				if fc == ' ' || fc == '\t' || fc == ';' || fc == '\n' {
					break
				}
				if fc >= 'a' && fc <= 'z' || fc >= 'A' && fc <= 'Z' || fc >= '0' && fc <= '9' {
					i++
					continue
				}
				break
			}
		case c == 'e' && atCmdStart:
			// Bare `e cmd` command: everything after it on the command is the
			// shell text (up to ; or newline).
			atCmdStart = false
			i++
			j := i
			for j < n && s[j] != ';' && s[j] != '\n' {
				j++
			}
			out = append(out, strings.TrimSpace(s[i:j]))
			i = j
		case c >= '0' && c <= '9' || c == '$' || c == ',' || c == '~' || c == '+' || c == '!':
			// Address components / negation: keep atCmdStart so the following
			// letter is still read as a command (1!e cmd).
			i++
		case c == '\\':
			// Custom-delimiter regex address \c...c (e.g. \|root|e pig).
			if i+1 >= n {
				i = n
				break
			}
			delim := s[i+1]
			i += 2
			for i < n {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if s[i] == '[' {
					// Character class: delimiters inside [...] are literal.
					i++
					if i < n && s[i] == '^' {
						i++
					}
					if i < n && s[i] == ']' { // ] as first (data) char is literal
						i++
					}
					for i < n && s[i] != ']' {
						if s[i] == '\\' {
							if i+1 < n {
								i += 2
							} else {
								i = n
							}
							continue
						}
						i++
					}
					if i < n {
						i++ // closing ]
					}
					continue
				}
				if s[i] == delim {
					i++
					// GNU sed allows I/M (and i/m) regex flags after the close.
					for i < n && (s[i] == 'I' || s[i] == 'M' || s[i] == 'i' || s[i] == 'm') {
						i++
					}
					break
				}
				i++
			}
			atCmdStart = true // an address precedes a command
		default:
			// Any other command letter consumes the rest of its command.
			atCmdStart = false
			i++
			for i < n && s[i] != ';' && s[i] != '\n' {
				i++
			}
		}
	}
	return out
}

// screenTarSubagent screens tar exec-hook options for a SUB-AGENT caller:
// --checkpoint-action=exec=CMD, --to-command CMD and --use-compress-program
// CMD / -I CMD carry shell text screened as a command. Dynamic words are
// refused only when they can sit in an OPTION or hook position — value
// operands of -f/-C/-T/-X and split-safe member paths are data (W11-2).
func screenTarSubagent(args []string, depth int, caller callerIdentity) string {
	screenCmd := func(cmd string) string {
		if isDynamicArg(cmd) {
			return "dynamic code payload"
		}
		if hit := guardShellSubagentDepth(cmd, depth+1, caller); hit != "" {
			return hit
		}
		return "tar exec hook" // any non-blocked hook command still executes
	}
	bsdAction := false // first operand without '-' is the BSD action word
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if isDynamicArg(a) {
			// Value slots of -f/-C/-T/-X and member paths: split-safe path
			// operands only — a word-start __ctx_dq_sub__ may expand to an
			// option and is refused (Q1-C).
			if isSafeDynamicDataOperand(a) {
				continue
			}
			return "dynamic code payload"
		}
		var cmd string
		switch {
		case strings.HasPrefix(a, "--checkpoint-action="):
			v := a[len("--checkpoint-action="):]
			if strings.HasPrefix(v, "exec=") {
				cmd = v[len("exec="):]
			} else if v == "exec" {
				cmd = "true" // bare exec still arms the hook
			}
		case a == "--checkpoint-action":
			if i+1 < len(args) {
				v := args[i+1]
				if strings.HasPrefix(v, "exec=") {
					cmd = v[len("exec="):]
				}
				i++
			}
		case a == "--to-command" || a == "--use-compress-program" || a == "-I":
			if i+1 < len(args) {
				cmd = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--to-command="):
			cmd = a[len("--to-command="):]
		case strings.HasPrefix(a, "--use-compress-program="):
			cmd = a[len("--use-compress-program="):]
		case strings.HasPrefix(a, "-I") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			cmd = a[2:]
		case a == "-f" || a == "--file" || a == "-C" || a == "--directory" ||
			a == "-T" || a == "--files-from" || a == "-X" || a == "--exclude-from" ||
			a == "--exclude" || a == "--owner" || a == "--group" || a == "--mode" ||
			a == "--mtime" || a == "--strip-components" || a == "--transform" ||
			a == "--format" || a == "--index-file" || a == "--occurrence":
			// Data value slot: the next argv is a filename/dir/pattern, not
			// an option — a dynamic value is already screened above.
			i++
		case strings.HasPrefix(a, "--"):
			// Other long options (--numeric-owner, --exclude=pat, ...).
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// Short-option cluster: f/C/T/X take a value operand — the
			// cluster tail or the next argv — and end the cluster.
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'f', 'C', 'T', 'X', 'b', 'L', 'H', 'h':
					if j+1 >= len(a) {
						i++ // value operand is the next argv
					}
					j = len(a)
				}
			}
		default:
			// BSD first-operand action word (tar cf / tar xf / tar tzf):
			// when it contains 'f' the NEXT operand is the archive value.
			if !bsdAction {
				bsdAction = true
				if strings.Contains(a, "f") {
					i++
				}
			}
		}
		if cmd == "" {
			continue
		}
		if hit := screenCmd(cmd); hit != "" {
			return hit
		}
		return "tar exec hook" // any non-blocked hook command still executes
	}
	return ""
}

// -i inplace / -iINCL / --include inplace. Ordinary `awk '{print $1}'` passes.
func screenAwkInplace(args []string) string {
	for i, a := range args {
		switch {
		case a == "-i" || a == "--include":
			if i+1 < len(args) && (args[i+1] == "inplace" || strings.HasPrefix(args[i+1], "inplace")) {
				return "awk -i inplace"
			}
			if a == "-i" {
				return "awk -i"
			}
		case strings.HasPrefix(a, "-i") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			if strings.Contains(a[2:], "inplace") || a[2] != '-' {
				return "awk " + a
			}
		}
	}
	return ""
}

// screenCurlWrite blocks download-to-disk spellings for strict read-only:
// -O/--remote-name/--remote-name-all and -o/--output whose target is a real
// file (-o -, -o /dev/null, /dev/stdout, /dev/stderr stay free). Short
// OPTION CLUSTERS count too: -sO, -fsSLO, -so /tmp/x, -so/tmp/x.
func screenCurlWrite(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" || a == "--remote-name" || a == "--remote-name-all":
			return "curl " + a
		case a == "-o" || a == "--output":
			if i+1 < len(args) {
				switch args[i+1] {
				case "-", "/dev/null", "/dev/stdout", "/dev/stderr":
					i++
				default:
					return "curl " + a + " " + args[i+1]
				}
			}
		case strings.HasPrefix(a, "--output="):
			if !curlSafeOutput(a[len("--output="):]) {
				return "curl " + a
			}
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1:
			// Short cluster: walk letters; 'O' anywhere writes to disk, 'o'
			// carries the output target (rest of cluster, else next argv).
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'O':
					return "curl " + a
				case 'o':
					if tail := a[j+1:]; tail != "" {
						if !curlSafeOutput(tail) {
							return "curl " + a
						}
					} else if i+1 < len(args) {
						if !curlSafeOutput(args[i+1]) {
							return "curl -o " + args[i+1]
						}
						i++
					}
					j = len(a)
				}
			}
		}
	}
	return ""
}

func curlSafeOutput(t string) bool {
	switch t {
	case "-", "/dev/null", "/dev/stdout", "/dev/stderr":
		return true
	}
	return false
}

// ctxmodeCLIAction returns the CLI action word of a `ctxmode` argv
// (skipping its boolean -workdir/-config flag spellings), or "" when the
// argv is a bare server invocation. `-workdir DIR` / `-config FILE` /
// `--workdir=DIR` / `-h` / `--help` do not count as actions.
func ctxmodeCLIAction(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-workdir" || a == "-config" || a == "--workdir" || a == "--config":
			i++ // consumes a value operand
		case strings.HasPrefix(a, "-"):
			// boolean flags incl. -h/--help and --workdir=/path
		default:
			return a
		}
	}
	return ""
}

// screenWgetWrite allows only explicit no-disk spellings (-O -, -O /dev/null,
// --spider); every other wget invocation downloads to disk by default.

// wgetSafeOutput reports destinations that do not create a payload file.
func wgetSafeOutput(t string) bool {
	switch t {
	case "-", "/dev/null", "/dev/stdout", "/dev/stderr":
		return true
	}
	return false
}

// wgetLongPrefix reports whether arg (without leading --) uniquely matches
// one of the candidate long option names (GNU getopt_long unique-prefix).
// Returns the matched full name or "".
func wgetLongPrefix(arg string, candidates []string) string {
	name, _, _ := strings.Cut(arg, "=")
	var hit string
	for _, c := range candidates {
		if name == c || (len(name) >= 1 && strings.HasPrefix(c, name)) {
			if hit != "" {
				return "" // ambiguous
			}
			hit = c
		}
	}
	return hit
}

func screenWgetWrite(args []string) string {
	// Model GNU wget getopt_long: short clusters, glued values, value slots,
	// unique long-option prefixes, and disk-writing side channels
	// (logs/cookies/warc/hsts/background/execute logfile=).
	okDownload := false
	onlyQuery := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			continue
		}
		if a == "--help" || a == "--version" || a == "-h" || a == "-V" {
			onlyQuery = true
			continue
		}
		if a == "--spider" {
			okDownload = true
			continue
		}

		// Long options (exact or unique prefix), with optional =value.
		if strings.HasPrefix(a, "--") {
			body := strings.TrimPrefix(a, "--")
			name, val, hasEq := strings.Cut(body, "=")

			// Disk-writing long options.
			diskLong := []string{
				"output-file", "append-output", "rejected-log",
				"save-cookies", "warc-file", "hsts-file",
				"output-document",
			}
			if hit := wgetLongPrefix(name, diskLong); hit != "" {
				dest := val
				if !hasEq {
					if i+1 >= len(args) {
						return "wget"
					}
					i++
					dest = args[i]
				}
				if hit == "output-document" {
					if wgetSafeOutput(dest) {
						okDownload = true
						continue
					}
					return "wget"
				}
				if !wgetSafeOutput(dest) {
					return "wget"
				}
				continue
			}
			if hit := wgetLongPrefix(name, []string{"background"}); hit != "" {
				return "wget" // -b/--background writes wget-log
			}
			if hit := wgetLongPrefix(name, []string{"execute"}); hit != "" {
				cmd := val
				if !hasEq {
					if i+1 >= len(args) {
						return "wget"
					}
					i++
					cmd = args[i]
				}
				if wgetExecuteWrites(cmd) {
					return "wget"
				}
				continue
			}
			// Value-taking long options that must consume the next argv so a
			// following --spider is not mistaken for a flag.
			valueLong := []string{
				"user-agent", "header", "referer", "proxy-user", "proxy-password",
				"user", "password", "base", "directory-prefix", "input-file",
				"bind-address", "tries", "timeout", "dns-timeout", "connect-timeout",
				"read-timeout", "wait", "waitretry", "limit-rate", "quota",
				"level", "load-cookies", "certificate", "ca-certificate",
				"private-key", "random-file", "egd-file", "secure-protocol",
				"post-data", "post-file", "method", "body-data", "body-file",
				"regex-type", "accept", "reject", "include-directories",
				"exclude-directories", "domains", "exclude-domains",
			}
			if hit := wgetLongPrefix(name, valueLong); hit != "" {
				if !hasEq {
					i++ // consume value slot
				}
				continue
			}
			continue // other long boolean flags
		}

		// Short options / clusters.
		if strings.HasPrefix(a, "-") && a != "-" && !strings.HasPrefix(a, "--") {
			cluster := a[1:]
			for j := 0; j < len(cluster); j++ {
				switch cluster[j] {
				case 'O':
					rest := cluster[j+1:]
					var dest string
					if rest != "" {
						dest = rest
						j = len(cluster)
					} else if i+1 < len(args) {
						i++
						dest = args[i]
						j = len(cluster)
					} else {
						return "wget"
					}
					if wgetSafeOutput(dest) {
						okDownload = true
					} else {
						return "wget"
					}
				case 'o', 'a':
					rest := cluster[j+1:]
					var dest string
					if rest != "" {
						dest = rest
						j = len(cluster)
					} else if i+1 < len(args) {
						i++
						dest = args[i]
						j = len(cluster)
					} else {
						return "wget"
					}
					if !wgetSafeOutput(dest) {
						return "wget"
					}
				case 'b':
					return "wget" // background → wget-log
				case 'e':
					rest := cluster[j+1:]
					var cmd string
					if rest != "" {
						cmd = rest
						j = len(cluster)
					} else if i+1 < len(args) {
						i++
						cmd = args[i]
						j = len(cluster)
					} else {
						return "wget"
					}
					if wgetExecuteWrites(cmd) {
						return "wget"
					}
				case 'U', 'P', 'i', 'B', 't', 'T', 'w', 'Q', 'l':
					// Value-taking shorts that shift subsequent argv slots.
					rest := cluster[j+1:]
					if rest != "" {
						j = len(cluster)
					} else {
						i++ // consume next argv as value
						j = len(cluster)
					}
				case 'h', 'V':
					onlyQuery = true
				default:
					// boolean short (q, n, c, ...)
				}
			}
			continue
		}
	}
	if okDownload || onlyQuery {
		return ""
	}
	return "wget"
}

// wgetExecuteWrites reports whether an -e/--execute COMMAND writes a logfile
// (wgetrc `logfile=PATH`).
func wgetExecuteWrites(cmd string) bool {
	for _, part := range strings.Split(cmd, ",") {
		part = strings.TrimSpace(part)
		key, val, hasEq := strings.Cut(part, "=")
		if !hasEq {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), "logfile") {
			if !wgetSafeOutput(strings.TrimSpace(val)) {
				return true
			}
		}
	}
	return false
}

// firstNonFlagArg returns the first argument that is not a -flag.
func firstNonFlagArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return ""
}

// hasInPlaceFlag reports whether args contain an in-place spelling for
// sed/perl/ruby: -i, -i.SUFFIX, a bundled cluster containing i (-ni, -Ei,
// -ri), or --in-place[=SUFFIX]. `sed -n '1,20p' f` has none and passes.
func hasInPlaceFlag(args []string) bool {
	for _, a := range args {
		switch {
		case a == "--in-place" || strings.HasPrefix(a, "--in-place="):
			return true
		case a == "-i" || strings.HasPrefix(a, "-i."):
			return true
		case strings.HasPrefix(a, "-") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			for j := 1; j < len(a); j++ {
				if a[j] == 'i' {
					return true
				}
			}
		}
	}
	return false
}

// hasInterpInPlaceFlag reports whether a perl/ruby argv (starting at the
// interpreter head) carries an in-place -i flag. Unlike hasInPlaceFlag it
// stops scanning at `--` (what follows is the script filename/args, not
// options) and skips the operand of -e/-E so the script text itself can
// never be mistaken for an option cluster: `perl -e '-i'` and
// `perl -ne 'print' -- -input.txt` stay free.
func hasInterpInPlaceFlag(argv []string) bool {
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return false
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return false // first non-option operand ends the option run
		}
		if strings.HasPrefix(a, "--") {
			if a == "--in-place" || strings.HasPrefix(a, "--in-place=") {
				return true
			}
			continue
		}
		// Short cluster: -e/-E take an inline-script operand — when glued
		// (-eCODE) the cluster ends there and holds no i; when bare
		// (-e CODE) the next arg is the script text and must be skipped.
		// -M/-m/-I/-r/-x/-F also take a separate operand when bare (-r lib
		// for ruby, -x[dir]/-F pattern for perl): without them a library
		// name like 'time' would be misread for an 'i' letter.
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 'i':
				return true
			case 'e', 'E', 'M', 'm', 'I', 'r', 'x', 'F':
				if j+1 >= len(a) {
					i++ // operand is the next argv
				}
				j = len(a)
			}
		}
	}
	return false
}

// gitBranchWriteFlags are the branch flags that mutate.
var gitBranchWriteFlags = map[string]bool{
	"-d": true, "-D": true, "-m": true, "-M": true, "-c": true, "-C": true,
	"--delete": true, "--move": true, "--copy": true,
	"-f": true, "--force": true, "-u": true, "--unset-upstream": true,
	"--edit-description": true,
}

// gitBranchQueryFlags make `git branch` a listing/query even with operands.
// -q/--quiet are deliberately ABSENT: `git branch -q newbranch` creates a
// branch quietly — the flag must not turn a creation into a "query".
var gitBranchQueryFlags = map[string]bool{
	"--contains": true, "--no-contains": true, "--merged": true,
	"--no-merged": true, "--points-at": true,
	"-l": true, "--list": true,
	"--show-current": true, "-a": true, "--all": true, "-r": true,
	"--remotes": true, "-v": true, "--verbose": true,
}

// gitTagWriteFlags are tag flags that mutate (delete/create/sign/force).
var gitTagWriteFlags = map[string]bool{
	"-d": true, "--delete": true, "-a": true, "-s": true, "-u": true,
	"-f": true, "--force": true, "-m": true, "-F": true,
	"--annotate": true, "--sign": true, "--local-user": true,
}

// gitTagReadFlags are tag flags that keep the invocation a listing/verify.
var gitTagReadFlags = map[string]bool{
	"-l": true, "--list": true, "-v": true, "--verify": true,
	"--points-at": true, "--contains": true, "--no-contains": true,
	"--merged": true, "--no-merged": true,
	"-h": true, "--help": true,
}

// gitConfigWriteFlags are config operations that write.
var gitConfigWriteFlags = map[string]bool{
	"--unset": true, "--unset-all": true, "--replace-all": true,
	"--add": true, "--remove-section": true, "--rename-section": true,
	"-e": true, "--edit": true,
}

// gitConfigReadFlags make config a pure query.
var gitConfigReadFlags = map[string]bool{
	"--get": true, "--get-all": true, "--get-regexp": true,
	"--get-urlmatch": true, "--list": true, "-l": true,
	"--show-origin": true, "--show-scope": true, "-h": true, "--help": true,
}

// screenGitWrite applies the git subcommand model: global options are skipped
// first, then the subcommand decides. Read-only subcommands must not carry a
// file-writing --output; worktree/branch/tag/config/remote/stash get
// dual-mode flag checks; every other subcommand is a write for strict roles.

// gitFsckLostFoundOpt reports whether a is a unique prefix of --lost-found
// (Git parse-options accepts unambiguous abbreviations; fsck has no other
// --l* option, so --l / --lo / --lost / --lost-f all mean --lost-found).
func gitFsckLostFoundOpt(a string) bool {
	const full = "--lost-found"
	if a == full {
		return true
	}
	if !strings.HasPrefix(a, "--") || len(a) < 3 || strings.Contains(a, "=") {
		return false
	}
	return strings.HasPrefix(full, a)
}

func screenGitWrite(args []string) string {
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-C" || a == "-c" || a == "--git-dir" || a == "--work-tree" || a == "--namespace" || a == "--exec-path":
			i += 2
		case strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") ||
			strings.HasPrefix(a, "--namespace=") || strings.HasPrefix(a, "--exec-path="):
			i++
		case strings.HasPrefix(a, "-c") && len(a) > 2 && strings.ContainsRune(a[2:], '='):
			i++ // -ckey=value bundle
		case strings.HasPrefix(a, "-"):
			i++ // boolean global flags (--no-pager, --bare, -P, ...)
		default:
			goto subFound
		}
	}
	return ""
subFound:
	if i >= len(args) {
		return ""
	}
	sub := args[i]
	rest := args[i+1:]

	// A file-writing --output on any subcommand is a write.
	for _, a := range rest {
		if a == "--output" || strings.HasPrefix(a, "--output=") {
			return "git " + sub + " --output"
		}
	}
	// A pager/exec helper armed inside a read-only verb still executes a
	// command inside git's plumbing — block it for strict roles too.
	if hit := gitExecArgHit(rest); hit != "" {
		return hit
	}

	switch sub {
	case "worktree":
		// Bare `git worktree`, `list`, and -h/--help are read-only; every
		// other verb (add/remove/prune/move/lock/unlock/repair/...) writes.
		if len(rest) == 0 {
			return ""
		}
		first := rest[0]
		if first == "-h" || first == "--help" {
			return ""
		}
		if strings.HasPrefix(first, "-") {
			return "" // bare `git worktree -v`-style flags stay a listing
		}
		if first == "list" {
			return ""
		}
		return "git worktree " + first
	case "branch":
		writeFlag := ""
		query := false
		hasOperand := false
		for k := 0; k < len(rest); k++ {
			a := rest[k]
			if gitBranchWriteFlags[a] || strings.HasPrefix(a, "--set-upstream-to") {
				writeFlag = a
				break
			}
			if gitBranchQueryFlags[a] {
				// -v/-vv (verbose listing) alone does not make an operand a
				// query: `git branch -v newbranch` shows it, `git branch
				// newbranch` creates it — the verb decides on operands.
				if a != "-v" && a != "--verbose" && a != "-vv" {
					query = true
				}
				// --points-at/--contains/--no-contains/--merged/--no-merged
				// take a separate value; skip it.
				switch a {
				case "--points-at", "--contains",
					"--no-contains", "--merged", "--no-merged":
					if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
						k++
					}
				}
				continue
			}
			// --sort/--format only pick a display order/layout — they are
			// NOT listing triggers. Consume their value so the operand is
			// not misread as a branch name, but never set query.
			if a == "--sort" || a == "--format" {
				if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
					k++
				}
				continue
			}
			if strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--format=") {
				continue
			}
			if strings.HasPrefix(a, "--points-at=") || strings.HasPrefix(a, "--contains=") ||
				strings.HasPrefix(a, "--no-contains=") || strings.HasPrefix(a, "--merged=") ||
				strings.HasPrefix(a, "--no-merged=") {
				query = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue // other flags (-q, --quiet, -f handled above)
			}
			hasOperand = true
		}
		if writeFlag != "" {
			return "git branch " + writeFlag
		}
		if query {
			return "" // `git branch --contains HEAD` / `-l pat` etc.
		}
		if hasOperand {
			for _, a := range rest {
				if !strings.HasPrefix(a, "-") {
					return "git branch " + a
				}
			}
		}
		return "" // bare `git branch` / flag-only listing (-v, -q)
	case "tag":
		for _, a := range rest {
			if gitTagWriteFlags[a] {
				return "git tag " + a
			}
		}
		// Any explicit list/verify flag keeps it read-only; bare `git tag`
		// lists; a bare name operand without read flags creates a tag.
		hasReadFlag := false
		hasOperand := false
		for k := 0; k < len(rest); k++ {
			a := rest[k]
			// --sort/--format only choose a display order/layout — they are
			// NOT read flags. Consume their value so it is not misread as a
			// tag name, but never set hasReadFlag.
			if a == "--sort" || a == "--format" {
				if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
					k++
				}
				continue
			}
			if strings.HasPrefix(a, "--sort=") || strings.HasPrefix(a, "--format=") {
				continue
			}
			if gitTagReadFlags[a] || strings.HasPrefix(a, "-n") ||
				strings.HasPrefix(a, "--contains=") || strings.HasPrefix(a, "--no-contains=") ||
				strings.HasPrefix(a, "--merged=") || strings.HasPrefix(a, "--no-merged=") {
				hasReadFlag = true
				// Separate-value forms consume the next arg.
				switch a {
				case "-n", "--points-at", "--contains",
					"--no-contains", "--merged", "--no-merged":
					if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
						k++
					}
				case "-l", "--list", "-v", "--verify":
					// list/verify take an optional pattern; never swallow a flag.
					if k+1 < len(rest) && !strings.HasPrefix(rest[k+1], "-") {
						k++
					}
				}
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			hasOperand = true
		}
		if hasReadFlag {
			return ""
		}
		if hasOperand {
			return "git tag"
		}
		return "" // bare `git tag` or flag-only invocation lists
	case "config":
		for _, a := range rest {
			if gitConfigWriteFlags[a] {
				return "git config " + a
			}
		}
		hasRead := false
		positional := 0
		for _, a := range rest {
			if gitConfigReadFlags[a] {
				hasRead = true
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue // --global/--file scope flags: neither proves read nor write
			}
			positional++
		}
		if hasRead {
			return "" // --get/-l style query (value operands are the pattern)
		}
		switch {
		case positional >= 2:
			return "git config" // `git config name value` writes
		case positional == 1:
			return "" // `git config name` reads a key
		default:
			return "git config" // flag-only / bare: fail closed for strict
		}
	case "remote":
		if len(rest) == 0 {
			return ""
		}
		// Peel a leading -v/--verbose BEFORE the subcommand: `git remote -v`
		// alone is the listing, `git remote -v show origin` still reaches
		// the read-only `show` verb.
		k := 0
		for k < len(rest) && (rest[k] == "-v" || rest[k] == "--verbose") {
			k++
		}
		if k >= len(rest) {
			return ""
		}
		sub2 := rest[k]
		if sub2 == "-h" || sub2 == "--help" {
			return ""
		}
		if sub2 == "show" || sub2 == "get-url" {
			return ""
		}
		if strings.HasPrefix(sub2, "-") {
			return "" // bare flag-only remote (-v -h) stays a listing
		}
		return "git remote " + sub2
	case "stash":
		if len(rest) == 0 {
			return "git stash" // bare stash pushes
		}
		// Peel a leading -q/--quiet BEFORE the verb: `git stash -q list` is
		// still the read-only list; bare `git stash -q` pushes.
		k := 0
		for k < len(rest) && (rest[k] == "-q" || rest[k] == "--quiet") {
			k++
		}
		if k >= len(rest) {
			return "git stash" // flag-only: still pushes quietly
		}
		sub2 := rest[k]
		if sub2 == "-h" || sub2 == "--help" {
			return ""
		}
		if gitStashReadonlySubs[sub2] {
			return ""
		}
		return "git stash " + sub2
	case "reflog":
		// `git reflog`, `reflog show`, --help / -n listing inspect; expire/delete write.
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
			if a == "-n" || a == "--max-count" || strings.HasPrefix(a, "--max-count=") {
				if !strings.Contains(a, "=") {
					j += 2
					continue
				}
				j++
				continue
			}
			if strings.HasPrefix(a, "-n") && a != "-n" && !strings.HasPrefix(a, "--") {
				j++
				continue
			}
			if a == "-h" || a == "--help" {
				return ""
			}
			j++
		}
		if j >= len(rest) {
			return ""
		}
		sub2 := rest[j]
		if sub2 == "show" || sub2 == "-h" || sub2 == "--help" {
			return ""
		}
		return "git reflog " + sub2
	case "fsck":
		// Plain fsck / connectivity checks are read-only; --lost-found
		// (and unique prefixes --l/--lo/--lost/...) write into .git/lost-found/.
		for _, a := range rest {
			if gitFsckLostFoundOpt(a) {
				return "git fsck --lost-found"
			}
		}
		return ""
	case "submodule":
		// Bare `git submodule`, `status`, `summary`, --help inspect; init/
		// update/add/deinit/sync/set-url/set-branch/foreach/absorbgitdirs
		// mutate the tree — and a leading option run (--quiet, -q,
		// --recursive, --branch NAME) must be peeled BEFORE the verb is read,
		// or `git submodule --quiet foreach 'touch /tmp/x'` slips through on
		// the flag.
		verb, isVerb := gitSubmoduleVerb(rest)
		if !isVerb {
			return "" // bare / flag-only `git submodule --quiet` lists
		}
		switch verb {
		case "status", "summary":
			return ""
		}
		return "git submodule " + verb
	default:
		if gitReadonlySubs[sub] {
			return ""
		}
		return "git " + sub
	}
}

// gitSubmoduleVerb returns the verb of `git submodule [flags] VERB`: the
// leading option run is peeled first (GNU --quiet/-q/--progress/--no-progress
// are boolean; --branch/-b/--configuration carry a separate value; `--`
// terminates options). isVerb is false when no verb word follows — a bare or
// flag-only `git submodule` is the listing.
func gitSubmoduleVerb(args []string) (verb string, isVerb bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case a == "--branch" || a == "-b" || a == "--configuration":
			i++ // verb-taking option: its value is not the verb
		case strings.HasPrefix(a, "--branch=") || strings.HasPrefix(a, "--configuration="):
			// glued value, nothing to skip
		case strings.HasPrefix(a, "-"):
			// boolean global flag (--quiet/-q/--recursive/--progress/…)
		default:
			return a, true
		}
	}
	return "", false
}

// ---------- additional head screens ----------

// screenGitGlobalArgs scans the global options before a git subcommand for
// execution-arming configuration: `-c` / `--config-env` entries that hand a
// command string to a hook key (or a `!`-prefixed shell alias), and
// `--exec-path=<dir>` that redirects git to an unvetted helper directory.
// Returns (index of the subcommand, guard hit or ""). Bare `git --exec-path`
// (no value) is the path query and stays free.

func gitKeyIsExecCapable(key string) bool {
	if gitExecConfigKeys[key] {
		return true
	}
	for _, p := range gitExecConfigPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	lk := strings.ToLower(key)
	for _, needle := range []string{"hook", "command", "exec", "driver", "helper", "askpass", "editor", "pager", "ssh", "proxy"} {
		if strings.Contains(lk, needle) {
			return true
		}
	}
	return false
}

func screenGitGlobalArgs(args []string) (int, string) {
	i := 0
	for i < len(args) {
		a := args[i]
		if isDynamicArg(a) {
			return i, "git dynamic global option"
		}
		switch {
		case a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace":
			if i+1 >= len(args) {
				return i, "git " + a
			}
			if isDynamicArg(args[i+1]) && !isSplitSafeDynamicWord(args[i+1]) {
				return i, "git dynamic global option"
			}
			i += 2
		case a == "-c":
			if i+1 >= len(args) {
				return i, "git -c"
			}
			pair := args[i+1]
			if isDynamicArg(pair) {
				// SH11 MF-2.2: the whole KEY=VAL word must be split-safe — an
				// unquoted $X value can field-split a second `-c` option in.
				if !isSplitSafeDynamicWord(pair) {
					return i, "git dynamic global option"
				}
				// Key must be static; value may be split-safe dynamic for non-hook keys.
				eq := strings.IndexByte(pair, '=')
				if eq < 0 || isDynamicArg(pair[:eq]) {
					return i, "git dynamic global option"
				}
				key, val := pair[:eq], pair[eq+1:]
				if gitKeyIsExecCapable(key) || strings.HasPrefix(val, "!") {
					return i, "git dynamic global option"
				}
			} else if hit := screenGitConfigPair(pair); hit != "" {
				return i, hit
			}
			i += 2
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			if isDynamicArg(a) {
				return i, "git dynamic global option"
			}
			if hit := screenGitConfigPair(a[2:]); hit != "" {
				return i, hit
			}
			i++
		case a == "--config-env":
			if i+1 >= len(args) || isDynamicArg(args[i+1]) {
				return i, "git dynamic global option"
			}
			if hit := screenGitConfigEnvPair(args[i+1]); hit != "" {
				return i, hit
			}
			i += 2
		case strings.HasPrefix(a, "--config-env="):
			if isDynamicArg(a) {
				return i, "git dynamic global option"
			}
			if hit := screenGitConfigEnvPair(a[len("--config-env="):]); hit != "" {
				return i, hit
			}
			i++
		case a == "--exec-path":
			// Bare `git --exec-path` prints the path (read-only); a following
			// operand binds a directory that must block.
			if i+1 < len(args) {
				return i, "git --exec-path"
			}
			i++
		case strings.HasPrefix(a, "--exec-path="):
			return i, "git --exec-path"
		case strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") ||
			strings.HasPrefix(a, "--namespace="):
			if isDynamicArg(a) && !isSplitSafeDynamicWord(a) {
				return i, "git dynamic global option"
			}
			i++
		case strings.HasPrefix(a, "-"):
			i++ // boolean global flags (--no-pager, --bare, -P, ...)
		default:
			return i, ""
		}
	}
	return i, ""
}

// screenGitSubagentExecArgs scans the args AFTER the global options for
// execution-arming subcommand flags a sub-agent must not use:
// `git grep --open-files-in-pager=cmd` / `-Ocmd`, and `git rebase --exec cmd`
// (also git fetch --recurse-submodules=<cmd>-style run helpers are not
// covered — those go through the command whitelist). A non-empty, non-cat
// pager/exec value is screened as shell text.
func screenGitSubagentExecArgs(args []string, caller callerIdentity) string {
	// Skip the global options (same walk as screenGitGlobalArgs) to reach
	// the subcommand operands.
	i, hit := screenGitGlobalArgs(args)
	if hit != "" {
		return hit
	}
	sub := ""
	if i < len(args) {
		sub = args[i]
		i++
	}
	endOpts := false
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			endOpts = true
			continue
		}
		if !endOpts && isDynamicArg(a) && (sub == "grep" || sub == "rebase") {
			return "git " + sub + " dynamic option"
		}
		var val string
		switch {
		case a == "--open-files-in-pager" || a == "-O":
			if i+1 < len(args) {
				val = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--open-files-in-pager="):
			val = a[len("--open-files-in-pager="):]
		case strings.HasPrefix(a, "-O") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			val = a[2:]
		case a == "--exec":
			if i+1 < len(args) {
				val = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "--exec="):
			val = a[len("--exec="):]
		default:
			continue
		}
		if val == "" || val == "cat" {
			continue
		}
		if hit := guardShellSubagentDepth(val, 1, caller); hit != "" {
			return "git " + a
		}
		// Non-blocked but non-trivial command text still arms a hook — a
		// sub-agent must not run ANY pager/exec helper; only cat/"" disable.
		return "git " + a
	}
	return ""
}

// gitExecArgHit scans subcommand args for --open-files-in-pager/-O/--exec
// spellings carrying a non-empty, non-cat command: for strict read-only the
// command runs unscreened inside git's plumbing, so it must block outright.
func gitExecArgHit(rest []string) string {
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--open-files-in-pager" || a == "-O" || a == "--exec":
			if i+1 < len(rest) && rest[i+1] != "" && rest[i+1] != "cat" {
				return "git " + a
			}
			i++
		case strings.HasPrefix(a, "--open-files-in-pager="):
			if v := a[len("--open-files-in-pager="):]; v != "" && v != "cat" {
				return "git --open-files-in-pager"
			}
		case strings.HasPrefix(a, "-O") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			if v := a[2:]; v != "" && v != "cat" {
				return "git -O"
			}
		case strings.HasPrefix(a, "--exec="):
			if v := a[len("--exec="):]; v != "" && v != "cat" {
				return "git --exec"
			}
		}
	}
	return ""
}

// gitExecConfigKeys are the lower-cased config keys whose value git execs:
// pager/ssh/editor/hook paths, credential and diff helpers.
var gitExecConfigKeys = map[string]bool{
	"core.pager": true, "core.sshcommand": true, "core.fsmonitor": true,
	"core.editor": true, "sequence.editor": true, "core.hookspath": true,
	"core.askpass": true, "diff.external": true, "credential.helper": true,
}

// gitExecConfigPrefixes are lower-cased key prefixes whose values git execs.
var gitExecConfigPrefixes = []string{
	"pager.", "alias.", "filter.", "difftool.", "mergetool.",
}

// screenGitConfigPair screens one `key=value` from `git -c`. A `!`-prefixed
// value is a shell alias; a blocked key hands a command path to git.
// `core.pager=cat` / `core.pager=` stay free (pager disabling is read-only).
func screenGitConfigPair(pair string) string {
	eq := strings.IndexByte(pair, '=')
	if eq < 0 {
		return ""
	}
	key := strings.ToLower(pair[:eq])
	val := pair[eq+1:]
	if strings.HasPrefix(val, "!") {
		return "git -c " + pair[:eq] // key only: the !cmd value may carry secrets
	}
	if key == "core.pager" && (val == "" || val == "cat") {
		return ""
	}
	if gitExecConfigKeys[key] {
		return "git -c " + pair[:eq]
	}
	for _, p := range gitExecConfigPrefixes {
		if strings.HasPrefix(key, p) {
			return "git -c " + pair[:eq]
		}
	}
	return ""
}

// screenGitConfigEnvPair screens one `key=ENVNAME` from `git --config-env`:
// the value comes from an environment variable, so only the key side can be
// screened for exec-arming configuration — and unlike `git -c`, the env
// value cannot carry the literal `cat` exemption, so exec keys block
// unconditionally (disabling a pager stays available via `--no-pager` or
// `-c core.pager=cat`).
func screenGitConfigEnvPair(pair string) string {
	eq := strings.IndexByte(pair, '=')
	if eq < 0 {
		return ""
	}
	key := strings.ToLower(pair[:eq])
	if gitExecConfigKeys[key] {
		return "git --config-env " + pair[:eq]
	}
	for _, p := range gitExecConfigPrefixes {
		if strings.HasPrefix(key, p) {
			return "git --config-env " + pair[:eq]
		}
	}
	return ""
}

// screenTarWrite allows only read-only tar spellings for strict roles:
// -t/--list (and --diff/--compare), --help, --version, or extraction to
// stdout via -O/--to-stdout. Creation (-c), append (-r), update (-u),
// --delete, disk extraction (-x without -O), and BSD flag-less `cf`/`xf`/
// `czf` bundles all block. Exec hooks (--checkpoint-action=exec*,
// --to-command) run shell text inside tar and block outright;
// --use-compress-program/-I may only name a plain compressor binary
// (gzip/bzip2/xz/zstd/lz4). A bare `tar` with no verb fails closed.
func screenTarWrite(args []string, base string) string {
	verb := byte(0) // t / x / c / r / u / d (delete) / 0 none
	sawStdout := false
	sawHelp := false
	firstOperand := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" || a == "--to-stdout":
			sawStdout = true
		case a == "--help" || a == "--version" || a == "--usage":
			sawHelp = true
		case a == "--list" || a == "--diff" || a == "--compare" || a == "--show":
			if verb == 0 {
				verb = 't'
			}
		case a == "--extract" || a == "--get":
			if verb == 0 {
				verb = 'x'
			}
		case a == "--create":
			verb = 'c'
		case a == "--append":
			verb = 'r'
		case a == "--update":
			verb = 'u'
		case a == "--delete":
			return base + " --delete"
		case a == "--concatenate" || a == "--catenate":
			verb = 'c'
		case a == "--checkpoint-action":
			if i+1 < len(args) {
				v := args[i+1]
				if strings.HasPrefix(v, "exec") {
					return base + " --checkpoint-action=exec"
				}
				i++
			}
		case strings.HasPrefix(a, "--checkpoint-action="):
			if strings.HasPrefix(a[len("--checkpoint-action="):], "exec") {
				return base + " --checkpoint-action=exec"
			}
		case a == "--to-command":
			return base + " --to-command"
		case strings.HasPrefix(a, "--to-command="):
			return base + " --to-command"
		case a == "--use-compress-program" || a == "-I":
			if i+1 < len(args) {
				if !tarCompressorSafe(args[i+1]) {
					return base + " " + a
				}
				i++
			}
		case strings.HasPrefix(a, "--use-compress-program="):
			if !tarCompressorSafe(a[len("--use-compress-program="):]) {
				return base + " --use-compress-program"
			}
		case strings.HasPrefix(a, "-I") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			if !tarCompressorSafe(a[2:]) {
				return base + " -I"
			}
		case strings.HasPrefix(a, "--"):
			// Other long options: skip a separate value operand when the
			// option takes one.
			if !strings.ContainsRune(a, '=') && tarLongTakesValue(a) && i+1 < len(args) {
				i++
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// Short-option cluster: letters with operands consume the rest of
			// the cluster or the next argv.
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 't':
					if verb == 0 {
						verb = 't'
					}
				case 'x':
					if verb == 0 {
						verb = 'x'
					}
				case 'c':
					verb = 'c'
				case 'r':
					verb = 'r'
				case 'u':
					verb = 'u'
				case 'O':
					sawStdout = true
				case 'f', 'C', 'T', 'X', 'b', 'k', 'K', 'N', 'W', 'g', 'F', 'L', 'P', 'S', 'U', 'V':
					// Operand-bearing letters (approximate GNU set): consume the
					// rest of the cluster or the next argv.
					if j+1 >= len(a) && i+1 < len(args) {
						i++
					}
					j = len(a)
				}
			}
		default:
			if firstOperand == "" {
				firstOperand = a // BSD flag-less bundle (cf / xf / czf ...)
			}
		}
	}
	if firstOperand != "" && verb == 0 {
		for k := 0; k < len(firstOperand); k++ {
			switch firstOperand[k] {
			case 't':
				verb = 't'
			case 'x':
				verb = 'x'
			case 'c':
				verb = 'c'
			case 'r':
				verb = 'r'
			case 'u':
				verb = 'u'
			case 'O':
				sawStdout = true
			}
		}
	}
	switch {
	case sawHelp:
		return ""
	case verb == 't':
		return ""
	case verb == 'x':
		if sawStdout {
			return ""
		}
		return base + " -x"
	case verb == 'c':
		return base + " -c"
	case verb == 'r':
		return base + " -r"
	case verb == 'u':
		return base + " -u"
	default:
		return base // bare tar / no verb: fail closed
	}
}

// tarCompressorSafe reports whether a --use-compress-program / -I value
// names a plain compressor binary (and nothing else): a bare name on PATH
// or an absolute/relative path whose base is a known compressor, with no
// extra arguments.
func tarCompressorSafe(v string) bool {
	switch filepath.Base(strings.TrimSpace(v)) {
	case "gzip", "bzip2", "xz", "zstd", "lz4":
		return !strings.ContainsAny(v, " \t")
	}
	return false
}

// tarLongTakesValue reports whether a GNU tar long option consumes a separate
// operand (used to skip its value when scanning).
func tarLongTakesValue(a string) bool {
	switch a {
	case "--file", "--directory", "--files-from", "--exclude", "--include",
		"--transform", "--format", "--checkpoint-action", "--newer",
		"--after-date", "--occurrence", "--index-file", "--use-compress-program",
		"--owner", "--group", "--mode", "--mtime", "--sort", "--quoting-style":
		return true
	}
	return false
}

// screenUnzipWrite allows only query spellings of unzip for strict roles:
// -l/-t/-p/-v/-Z/-h/--help/--version. Extraction (default, -d, -o, -f, -u)
// writes. A `w` in a bundled flag cluster is zipinfo's verbose mode and is
// not a query on its own.
func screenUnzipWrite(args []string) string {
	sawQuery := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-d" || a == "--dir" {
			i++ // -d exdir: consume the dir operand
			continue
		}
		if !strings.HasPrefix(a, "-") {
			continue // zipfile / member operands
		}
		if strings.HasPrefix(a, "--") {
			if a == "--help" || a == "--version" {
				sawQuery = true
			}
			continue
		}
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 'l', 't', 'p', 'v', 'Z', 'h', 'c':
				sawQuery = true // -c pipes the member to stdout: read-only
			case 'o', 'f', 'u', 'n':
				// overwrite-policy flags: extraction still writes
				return "unzip " + a
			}
		}
	}
	if sawQuery {
		return ""
	}
	// No explicit read verb: unzip's default action extracts to disk.
	return "unzip"
}

// screenCompressWrite allows only stream/query spellings of compressors
// for strict roles: --stdout/--to-stdout/-c (stdout), --list/-l, --test/-t,
// --version/-V, --license/-L, --help/-h. Every other spelling REWRITES the
// operand file in place — including -d (decompress in place) and
// -n/--no-name (compress without name metadata): both block.
func screenCompressWrite(args []string, base string) string {
	sawSafe := false
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--stdout", "--to-stdout", "--list", "--test", "--version",
				"--help", "--license":
				sawSafe = true
			}
			continue
		}
		for j := 1; j < len(a); j++ {
			switch a[j] {
			case 'c', 'l', 't', 'V', 'L', 'h':
				sawSafe = true
			}
		}
	}
	if sawSafe {
		return ""
	}
	return base
}

// screenSedScriptWrite scans sed's script arguments (inline -e payloads and
// the first positional operand) for `w`/`W` write-file commands and GNU
// `e` exec commands: `s///w file` flags, address-followed `w file`/`W file`
// commands, bare `e cmd`, and `s///e`. `-f`/`--file` hands sed an unvetted
// script FILE and blocks outright for strict read-only. Comparison text
// (`/word/p`, `s/a/word/`) must not trip the screen.
func screenSedScriptWrite(args []string) string {
	scripts, sawFile := sedScripts(args)
	if sawFile {
		return "sed -f" // unvetted script file
	}
	for _, s := range scripts {
		if hit := sedScriptHasWrite(s); hit != "" {
			return hit
		}
		if len(sedExecCommands(s)) > 0 {
			return "sed e"
		}
	}
	return ""
}

// sedScriptHasWrite parses sed command text for w/W write commands. It is a
// shallow scanner: comments (#...), addresses (/re/, $, N, N,M, \$), s///
// with its w flag, and the bare w/W commands are recognized; text inside
// pattern space (a/c/i commands, regex bodies) is skipped.
func sedScriptHasWrite(s string) string {
	i := 0
	n := len(s)
	for i < n {
		c := s[i]
		switch {
		case c == '#':
			for i < n && s[i] != '\n' && s[i] != ';' {
				i++
			}
		case c == ' ' || c == '\t' || c == '\n' || c == ';':
			i++
		case c == '/':
			// Regex address: skip to the unquoted closing /, tracking [...].
			i++
			for i < n {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if s[i] == '[' {
					// Character class: delimiters inside [...] are literal.
					i++
					if i < n && s[i] == '^' {
						i++
					}
					if i < n && s[i] == ']' { // ] as first (data) char is literal
						i++
					}
					for i < n && s[i] != ']' {
						if s[i] == '\\' {
							if i+1 < n {
								i += 2
							} else {
								i = n
							}
							continue
						}
						i++
					}
					if i < n {
						i++ // closing ]
					}
					continue
				}
				if s[i] == '/' {
					i++
					// GNU sed allows I/M (and i/m) regex flags after the close.
					for i < n && (s[i] == 'I' || s[i] == 'M' || s[i] == 'i' || s[i] == 'm') {
						i++
					}
					break
				}
				i++
			}
		case c == '$' || c >= '0' && c <= '9' || c == '~' || c == '+' || c == ',':
			i++ // address components
		case c == '!':
			i++ // address negation: 1!w / /pat/!w
		case c == '\\':
			// Custom-delimiter regex address \c...c (e.g. \|root|w).
			if i+1 >= n {
				i = n
				break
			}
			delim := s[i+1]
			i += 2
			for i < n {
				if s[i] == '\\' {
					if i+1 < n {
						i += 2
					} else {
						i = n
					}
					continue
				}
				if s[i] == '[' {
					// Character class: delimiters inside [...] are literal.
					i++
					if i < n && s[i] == '^' {
						i++
					}
					if i < n && s[i] == ']' { // ] as first (data) char is literal
						i++
					}
					for i < n && s[i] != ']' {
						if s[i] == '\\' {
							if i+1 < n {
								i += 2
							} else {
								i = n
							}
							continue
						}
						i++
					}
					if i < n {
						i++ // closing ]
					}
					continue
				}
				if s[i] == delim {
					i++
					// GNU sed allows I/M (and i/m) regex flags after the close.
					for i < n && (s[i] == 'I' || s[i] == 'M' || s[i] == 'i' || s[i] == 'm') {
						i++
					}
					break
				}
				i++
			}
		case c == 's':
			// s<delim><pat><delim><repl><delim><flags>
			i++
			if i >= n {
				break
			}
			delim := s[i]
			i++
			for part := 0; part < 2 && i < n; part++ {
				for i < n && s[i] != delim {
					if s[i] == '\\' {
						if i+1 < n {
							i += 2
						} else {
							i = n
						}
						continue
					}
					i++
				}
				if i >= n {
					break // truncated: no closing delimiter
				}
				i++ // consume the delim
			}
			// Flags: n N g p w. A `w` or `W` flag followed by a filename writes.
			for i < n {
				fc := s[i]
				if fc == 'w' || fc == 'W' {
					return "sed s///w"
				}
				if fc == ' ' || fc == '\t' || fc == ';' || fc == '\n' {
					break
				}
				if fc >= 'a' && fc <= 'z' || fc >= 'A' && fc <= 'Z' || fc >= '0' && fc <= '9' {
					i++
					continue
				}
				break
			}
		case c == 'w' || c == 'W':
			// Bare w/W command: `w file` / `W file`.
			return "sed " + string(c)
		case c == 'r' || c == 'R':
			// r/R read a file (input, not a write) — still not a write; skip the
			// filename operand.
			i++
			for i < n && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			for i < n && s[i] != ';' && s[i] != '\n' {
				i++
			}
		case c == '{':
			i++ // command group: keep scanning the contents
		case c == '}':
			i++
		default:
			// Any other command letter: skip the rest of the command to the
			// next ;/newline — some (a/i/c) carry free text that must not be
			// re-scanned for w.
			i++
			for i < n && s[i] != ';' && s[i] != '\n' {
				i++
			}
		}
	}
	return ""
}

// screenAwkProgram extracts awk's program text (every -e/--source
// fragment joined, or the first positional operand) and blocks constructs
// that write: `system(`, cmd pipes via `getline`, and print/printf output
// redirection `>` `>>` inside the program. `-f`/`--file` in any spelling
// (separate, =glued, or cluster tail) is an unvetted script file and
// blocks.
func screenAwkProgram(args []string) string {
	program, sawFile, _ := awkProgramFrags(args)
	if sawFile {
		return "awk -f" // unvetted program file
	}
	if program == "" {
		return ""
	}
	return awkProgramWrite(program)
}

// awkProgramWrite scans awk program text for write escapes: `system(`, a
// command piped into `getline` ("cmd" | getline, getline < "cmd"), and
// print/printf output redirections `>` / `>>`. Comparisons like `$1 > 5`
// and regexes like /a|b/ must not trip it. The inPrintStmt flag is
// statement-scoped: `)` inside `print (x) > f` no longer cancels the
// statement, while a top-level `;`, `{` or `}` does.
func awkProgramWrite(prog string) string {
	// Scan for `system (` calls, `>`/`>>` after print/printf, and
	// `| getline` / `getline <`. The system check runs on the lexer path
	// (identifier boundary + openParenAfter) so `system  (` and
	// `system\t(` hit while a regex literal like /system\(/ cannot trip it.
	i := 0
	n := len(prog)
	inStr := byte(0)
	inRegex := false
	inPrintStmt := false    // inside a print/printf statement (resets at ; \n { })
	prevWasOperand := false // last token was $/literal/)/number (division vs regex)
	parenDepth := 0
	for i < n {
		c := prog[i]
		switch {
		case inStr != 0:
			if c == '\\' {
				i++
			} else if c == inStr {
				inStr = 0
			}
		case inRegex:
			if c == '\\' {
				i++
			} else if c == '/' {
				inRegex = false
			}
		case c == '"' || c == '\'':
			inStr = c
			prevWasOperand = true
		case c == '/':
			// '/' after an operand is division; after an operator/open it is
			// a regex literal (whose body may contain `|`/`>`).
			if !prevWasOperand {
				inRegex = true
			} else {
				prevWasOperand = false
			}
		case c == '|':
			prevWasOperand = false
			// `cmd | getline` — a command feeding getline is a spawn+read.
			rest := strings.TrimLeft(prog[i+1:], " \t")
			if strings.HasPrefix(rest, "getline") {
				return "awk | getline"
			}
			// `print x | "cmd"` writes to a command pipe — also an escape.
			if inPrintStmt {
				return "awk print | cmd"
			}
		case c == '>':
			if inPrintStmt {
				return "awk print >"
			}
			prevWasOperand = false
		case c == '<':
			prevWasOperand = false
		case c == '(' || c == '[':
			parenDepth++
			prevWasOperand = false
		case c == ')' || c == ']':
			if parenDepth > 0 {
				parenDepth--
			}
			prevWasOperand = true // a closed group is a value (print (x))
		case c == '{':
			if parenDepth == 0 {
				inPrintStmt = false
			}
			prevWasOperand = false
		case c == '}':
			if parenDepth == 0 {
				inPrintStmt = false
			}
			prevWasOperand = false
		case c == ';' || c == '\n':
			if parenDepth == 0 {
				inPrintStmt = false
			}
			prevWasOperand = false
		case c == ' ' || c == '\t':
			// keep both flags across whitespace
		case c == '$' || c >= '0' && c <= '9':
			prevWasOperand = true
		default:
			// Track whether the current word is print/printf.
			j := i
			for j < n && isIdentByte(prog[j]) {
				j++
			}
			if j == i {
				prevWasOperand = false
				i++
				continue
			}
			w := prog[i:j]
			if w == "print" || w == "printf" {
				inPrintStmt = true
			}
			if w == "system" && openParenAfter(prog, j) >= 0 {
				return "awk system("
			}
			// Any word counts as an operand for the division-vs-regex heuristic.
			prevWasOperand = true
			i = j
			continue
		}
		i++
	}
	return ""
}

// pythonModuleArgvFrom returns the program argv `python … -m MOD [args…]`
// actually executes ([MOD, args…]) or nil when the argv has no -m operand.
// The glued `-mMOD` spelling is expanded back into its own word.
func pythonModuleArgvFrom(argv []string) []string {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-m":
			if i+1 < len(argv) {
				return argv[i+1:]
			}
			return nil
		case strings.HasPrefix(a, "-m") && len(a) > 2:
			return append([]string{a[2:]}, argv[i+1:]...)
		case a == "-W" || a == "-X":
			i++ // value-bearing option
		case !strings.HasPrefix(a, "-") || a == "-":
			return nil // script-file operand ends the option run
		}
	}
	return nil
}

// pythonModuleHit screens `python[3] [flags] -m <mod> [args]` for a strict
// read-only caller: the module name resolves through sys.path, so `-m`
// default-allowing an arbitrary module (http.server, compileall, venv, a
// local evil_mod) means default-allowing arbitrary code and writes. Only a
// pure `--help`/`-h` query and the side-effect-free text filters of
// pythonSafeModules with no output file stay free; anything else — and any
// module the caller cannot name statically — blocks. hasModule is false when
// the argv carries no `-m`, leaving the caller to the interpreter-head model.
func pythonModuleHit(args []string) (hit string, hasModule bool) {
	mod, rest := "", []string(nil)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-m":
			if i+1 >= len(args) {
				return "python -m <missing>", true
			}
			mod, rest = args[i+1], args[i+2:]
			i = len(args)
		case strings.HasPrefix(a, "-m") && len(a) > 2:
			mod, rest = a[2:], args[i+1:]
			i = len(args)
		case a == "-W" || a == "-X":
			i++ // value-bearing options
		case strings.HasPrefix(a, "-W") || strings.HasPrefix(a, "-X"):
			// glued value (-Wmodule, -Xutf8): no extra operand
		case strings.HasPrefix(a, "-") && a != "-":
			// other interpreter flags (-q, -O, -B, -u, …)
		default:
			return "", false // a script-file operand before -m ends the option run
		}
	}
	if mod == "" {
		return "", false // no -m on this invocation
	}
	hasModule = true
	if isDynamicArg(mod) {
		return "python -m <dynamic>", true // module name generated at run time
	}
	// `--` ends options; positionals after it still count (outfile path).
	switch {
	case allQueryArgs(rest):
		return "", true // `python -m x --help`
	case pythonSafeModules[mod] && !moduleWritesOutput(rest):
		return "", true // pure stdin→stdout text filter
	}
	// Everything else RUNS the module — with no operands at all in the
	// common case (`python -m venv`, `python -m http.server`, a local
	// `python -m evil_mod`), which is exactly when default-allowing would be
	// wrong.
	return "python -m " + mod, true
}

// allQueryArgs reports whether a module/tool option run is nothing but the
// help query (`--help`, `-h`, in any repetition): the program prints its
// usage and exits without touching the filesystem.
func allQueryArgs(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		if a != "--help" && a != "-h" {
			return false
		}
	}
	return true
}

// pythonSafeModules are `python -m` modules that read stdin/an input file
// and write ONLY stdout: no side effects a strict read-only role must not
// take. Any spelling that names an output file (-o/--out/--inplace) blocks.
var pythonSafeModules = map[string]bool{
	"json.tool": true,
}

// moduleWritesOutput reports whether a `python -m` module run carries an
// output-file flag OR a second positional output path. json.tool takes
// `[infile [outfile]]` — two positionals overwrite outfile. After `--`,
// every operand is positional (`python -m json.tool -- -o` is infile "-o").
func moduleWritesOutput(args []string) bool {
	pos := 0
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if endOpts {
			pos++
			if pos > 1 {
				return true
			}
			continue
		}
		switch {
		case a == "--":
			endOpts = true
		case a == "-o" || a == "--out" || a == "--output" || a == "--outfile" || a == "-O" || a == "--inplace" || a == "--in-place":
			return true
		case strings.HasPrefix(a, "--out="), strings.HasPrefix(a, "--output="), strings.HasPrefix(a, "--outfile="):
			return true
		case strings.HasPrefix(a, "-o") && len(a) > 2 && a != "-o":
			return true
		case a == "--indent":
			if i+1 < len(args) {
				i++
			}
		case strings.HasPrefix(a, "--indent="):
			// glued
		case strings.HasPrefix(a, "-") && a != "-":
			// other module flags
		default:
			pos++
			if pos > 1 {
				return true
			}
		}
	}
	return false
}

// screenShellFileRun decides a bare shell invocation (no -c payload): -n
// (syntax check, no execution) and version/help spellings stay free — but
// ONLY before the first non-option script operand (`bash script.sh -n`
// runs the script). Anything else runs a script file or reads stdin and
// blocks.
func screenShellFileRun(args []string, base string) string {
	for _, a := range args {
		if a == "-n" || a == "--version" || a == "--help" || a == "-V" {
			return ""
		}
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			break // script-file operand reached: trailing flags are its args
		}
	}
	return base
}

// interpSyntaxCheckFlags are the per-interpreter "parse, do not execute"
// option spellings that stay free for strict read-only roles: node
// --check/-c, perl -c, ruby -c, php -l (php -l consumes no value here —
// screenInterpFileRun only reaches this table when unwrapInterpreterInline
// already ruled out inline code, so a bare php -c is php's -l-free ini
// option and still blocks through the default path).
var interpSyntaxCheckFlags = map[string][]string{
	"sh": {"-n"}, "bash": {"-n"}, "dash": {"-n"}, "zsh": {"-n"},
	"ksh": {"-n"}, "mksh": {"-n"}, "ash": {"-n"},
	"node": {"--check", "-c"}, "nodejs": {"--check", "-c"},
	"perl": {"-c"}, "ruby": {"-c"}, "php": {"-l"},
}

// screenInterpFileRun decides a bare interpreter invocation with no inline
// code: --version/-V/--help/-h spellings and the `-` stdin marker (whose
// program stream is screened via the heredoc/stdin payload paths) stay
// free, but ONLY while still in the option run — a flag after the first
// non-option script operand is an argument to the script
// (`python3 app.py --help` RUNS app.py and must block). Pure syntax-check
// spellings (node --check, perl -c, php -l) stay free too. Anything else
// runs a script file and blocks for strict read-only.
func screenInterpFileRun(args []string, base string) string {
	syntaxFlags := interpSyntaxCheckFlags[base]
	for _, a := range args {
		switch a {
		case "-", "--version", "-V", "-VV", "--help", "-h":
			return ""
		}
		for _, f := range syntaxFlags {
			if a == f {
				return ""
			}
		}
		if a == "--" || !strings.HasPrefix(a, "-") {
			break // script operand reached: later flags belong to the script
		}
	}
	return base
}
