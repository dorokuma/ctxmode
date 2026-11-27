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

// awkProgramLongStep handles one `--` word of awkProgramFrags' walk
// (extracted so the main loop stays under the complexity budget — v6.2.2
// Oracle R4 R4-MF-4): frags carries the inline program fragments
// (--source — R14-Oracle-S3: a SLICE, in parity with awkClusterFragsEnd's
// []string channel, so an explicitly EMPTY program `--source=` survives
// the fragment collection instead of being dropped by a non-empty
// string check), sawFile marks a program-FILE source, consumed counts
// EXTRA argv operands eaten, endOpts reports gawk --exec's end-of-options,
// hit is the stdin/dynamic verdict.
func awkProgramLongStep(args []string, i int, a string) (frags []string, sawFile bool, consumed int, endOpts bool, hit string) {
	name, val, hasEq := strings.Cut(a[2:], "=")
	if isLongOptAbbrev(name, "exec", 1) {
		// gawk --exec == --file plus end-of-options. GNU unique-prefix
		// spelling `--e` resolves here too (e* is --exec alone in optab[]
		// — v6.2.2 Oracle R5 R5-MF-4).
		endOpts = true
	}
	switch {
	case isLongOptAbbrev(name, "file", 3) || isLongOptAbbrev(name, "exec", 1):
		sawFile = true
		if !hasEq {
			if i+1 < len(args) {
				val = args[i+1]
			}
			consumed = 1
		}
		return nil, sawFile, consumed, endOpts, awkProgramFileHit(val)
	case isLongOptAbbrev(name, "source", 2):
		// R14-Oracle-S3: `--source=` (or `--source ""`) is awk's explicit
		// EMPTY program — semantically identical to `-e ""`. Returning the
		// empty string in a SLICE keeps len(frags) visible to the caller, so
		// a `--`-terminated dynamic data file (`gawk --source= -- "$F"`)
		// is no longer misjudged as the positional program text.
		if hasEq {
			return []string{val}, false, 0, false, ""
		}
		if i+1 < len(args) {
			return []string{args[i+1]}, false, 1, false, ""
		}
		return nil, false, 0, false, ""
	case awkLongIsDataAssign(name):
		// --assign / --field-separator (and their GNU unique prefixes
		// --as/--fie) consume their separate value operand so it cannot
		// usurp the positional program slot and hide the REAL program
		// text behind it (v6.2.2 Oracle R5 R5-MF-4
		// `gawk --as 'x=1' 'BEGIN{system("pig")}'`). An UNQUOTED dynamic
		// value operand word-splits at runtime and re-arms awk's own
		// option parse the same way -v/-F/-W assign do (v6.2.2 Oracle R8
		// R8-MF-2 `gawk --as $VAR '1'`).
		if !hasEq {
			if i+1 < len(args) {
				if sh := awkDataValSplitHit(args[i+1]); sh != "" {
					return nil, false, 0, false, sh
				}
			}
			consumed = 1
		}
		return nil, false, consumed, false, ""
	case isLongOptAbbrev(name, "include", 1) || isLongOptAbbrev(name, "load", 2):
		// --include/--load supply library text/compiled files: consume the
		// operand and apply the program-file validation to it (a stdin device
		// would smuggle unvetted awk text — v6.2.2 Oracle R4 R4-MF-4, with
		// --include wired in and the GNU unique prefixes --i/--lo aligned
		// in Oracle R5 R5-MF-4).
		if !hasEq {
			if i+1 < len(args) {
				val = args[i+1]
			}
			consumed = 1
		}
		return nil, false, consumed, endOpts, awkProgramFileHit(val)
	case awkAmbiguousShortPrefix(name):
		return nil, false, 0, false, "dynamic code payload"
	}
	return nil, false, 0, false, ""
}

// awkAmbiguousShortPrefix reports whether name is a SHORT prefix of one of
// gawk's program-source long options that is too short for GNU's
// unique-prefix resolution — a word awk itself would reject or
// mis-resolve, so the guard fails closed instead of guessing its arity
// (v6.2.2 Oracle R5 R5-MF-4).
func awkAmbiguousShortPrefix(name string) bool {
	if name == "" {
		return false
	}
	for _, full := range []string{"file", "source", "load", "field-separator"} {
		if strings.HasPrefix(full, name) && len(name) < len(full) {
			return true
		}
	}
	return false
}

// awkDataAssignOptStep validates the separate value operand of one
// awk -F/-v pure-data assignment option (extracted so awkProgramFrags
// stays under the complexity budget — v6.2.2 Oracle R8 R8-Obs-2): an
// UNQUOTED dynamic operand word-splits at runtime and the fragments
// re-arm awk's own option parse (v6.2.2 Oracle R7 R7-SF-1).
func awkDataAssignOptStep(args []string, i int) (hit string) {
	if i+1 < len(args) {
		return awkDataValSplitHit(args[i+1])
	}
	return ""
}

// awkDynWordStep settles one dynamic word of awkProgramFrags' walk
// (extracted so the main loop stays under the complexity budget —
// v6.2.2 Oracle R8 R8-Obs-2): hit reports the pre-terminator re-arm
// verdict or the argv-programmed positional-program verdict; setPos
// reports the word must be recorded as the positional candidate when
// none is set yet (input data after a program source).
func awkDynWordStep(a string, sawFile, endOpts bool, hasPos bool, nFrags int) (hit string, setPos bool) {
	if !endOpts && (strings.HasPrefix(a, "-") || !isSafeDynamicDataOperand(a)) {
		// Dynamic words BEFORE the option terminator: awk's own parser
		// (mawk/nawk positional scan, gawk getopt_long permutation) can
		// re-read the expansion as further options — even after a -f
		// program file or a positional program (v6.2.2 Oracle R7
		// R7-MF-1 `awk -f /dev/null "$X"` / `gawk '1' "$X"` regression).
		return "dynamic code payload", false
	}
	// R15-Oracle-S2: hasPos distinguishes "an EMPTY positional program
	// was explicitly provided" (hasPos=true, positional=="") from "no
	// positional program yet" — the former already supplies awk's program
	// text (an inert empty one), so a following dynamic word is INPUT
	// data, not argv-programmed code.
	if !sawFile && !hasPos && nFrags == 0 {
		// The first positional is awk's PROGRAM text — including the
		// word right after `--` (`awk -- "$VAR"` is argv-programmed
		// awk code, not inert data — v6.2.2 Oracle R6 R6-SF-1). The
		// gawk -f/--file program file (sawFile) retires it instead.
		// A dynamic data word AFTER a program source (`awk -f
		// parse.awk -- "$FILE"` / `awk '1' -- "$FILE"`) is awk INPUT
		// data, not code — it stays exempt (v6.2.2 Oracle R6
		// positives).
		return "dynamic code payload", false
	}
	return "", !hasPos
}

func awkProgramFrags(args []string) (string, bool, string) {
	var frags []string
	var aux []string
	var positional string
	// R15-Oracle-S2: hasPos records that a positional program word was
	// PROVIDED — even an explicitly empty one (`awk -- "" data`) — so it
	// is never confused with the not-yet-provided state the empty string
	// also encoded before.
	hasPos := false
	sawFile := false
	endOpts := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if isDynamicArg(a) {
			dHit, dSetPos := awkDynWordStep(a, sawFile, endOpts, hasPos, len(frags))
			if dHit != "" {
				return "", sawFile, dHit
			}
			if dSetPos {
				positional = a
				hasPos = true
			}
			continue
		}
		if !endOpts && strings.HasPrefix(a, "--") && a != "--" {
			lFrags, lSawFile, consumed, lEnd, lHit := awkProgramLongStep(args, i, a)
			if lHit != "" {
				return "", sawFile || lSawFile, lHit
			}
			if lEnd {
				endOpts = true
			}
			sawFile = sawFile || lSawFile
			// R14-Oracle-S3: append unconditionally — an explicitly empty
			// program fragment (`--source=`) counts as a program source even
			// though its bytes are empty, exactly like `-e ""` and the
			// cluster channel below.
			frags = append(frags, lFrags...)
			i += consumed
			continue
		}
		switch {
		case a == "--" && !endOpts:
			endOpts = true
		case !endOpts && (a == "-f" || a == "-E"):
			sawFile = true
			if a == "-E" {
				endOpts = true // gawk -E == --exec: ends option parsing (R4-MF-4)
			}
			if i+1 < len(args) {
				v := args[i+1]
				// S3: `awk -f -` (and the /dev/stdin family) reads the
				// PROGRAM from stdin — unvetted.
				if fh := awkProgramFileHit(v); fh != "" {
					return "", sawFile, fh
				}
			}
			i++ // consume the file operand
		case !endOpts && a == "-e":
			if i+1 < len(args) {
				frags = append(frags, args[i+1])
				i++
			}
		case !endOpts && (a == "-i" || a == "-l"):
			// gawk -i/--include and -l/--load consume a library operand that
			// is awk program material: a stdin device smuggles unvetted text
			// (v6.2.2 Oracle R5 R5-MF-4 `gawk -i /dev/stdin '1'`). They do
			// NOT mark sawFile — they are library additions, not the program
			// file — so the positional program word still extracts.
			if i+1 < len(args) {
				if fh := awkProgramFileHit(args[i+1]); fh != "" {
					return "", sawFile, fh
				}
			}
			i++
		case !endOpts && (a == "-F" || a == "-v"):
			if dsh := awkDataAssignOptStep(args, i); dsh != "" {
				return "", sawFile, dsh
			}
			i++
		case !endOpts && strings.HasPrefix(a, "-") && len(a) > 1:
			var cFrag []string
			var cSawFile bool
			var cHit string
			var consumedNext int
			var cEnd bool
			cFrag, cSawFile, consumedNext, cHit = awkClusterFragsEnd(args, i, a, &cEnd, &aux)
			if cEnd {
				endOpts = true
			}
			if cHit != "" {
				return "", sawFile || cSawFile, cHit
			}
			frags = append(frags, cFrag...)
			sawFile = sawFile || cSawFile
			i += consumedNext
		default:
			if !hasPos && len(frags) == 0 {
				positional = a
				hasPos = true
			}
		}
	}
	if len(frags) == 0 && !sawFile && hasPos && !isDynamicArg(positional) {
		// The first positional is awk's program text ONLY when no explicit
		// -f program file supplied it — folding input filenames into the
		// program here masked a REAL later -e fragment behind `!sawFile`
		// downstream (v6.2.2 R3 R3-MF-6 `gawk -f /dev/null /dev/null -e
		// '{}'`). An explicitly EMPTY positional program joins as the empty
		// fragment (a no-op in the joined program) and — crucially — the
		// hasPos settlement above already kept post-terminator data words
		// out of the program slot (R15-Oracle-S2).
		frags = append(frags, positional)
	}
	// v6.2.2 Oracle R8 R8-MF-1: the -Wi/-W in collision operand (out-of-band
	// aux channel) merges into the program ONLY after the positional
	// settlement and never enters the len(frags) gates — under mawk the
	// same bytes ARE the main program text. Appending it last keeps a
	// library file name carrying an unclosed quote (`gawk -W i "a'b"
	// 'BEGIN{system("pig")}'`) from poisoning the REAL program text that
	// precedes it inside awkCommandLiterals.
	frags = append(frags, aux...)
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
						// R10-MF-3: the separate length operand must stay one
						// argv word — an unquoted $VAR splits into extra options
						// (-e 1epig) and a multi-match glob overflows the slot.
						if i+1 < len(args) {
							if hit := sedValueSlotHit(args[i+1]); hit != "" {
								return hit
							}
						}
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
							// R10-MF-3: vet the separate -l operand like
							// --line-length above.
							if i+1 < len(args) {
								if hit := sedValueSlotHit(args[i+1]); hit != "" {
									return hit
								}
							}
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

// sedValueSlotHit vets one operand CONSUMED by sed's -l/--line-length
// value slot: an unquoted $VAR field-splits at runtime into extra options
// (-e 1epig executes pig) and a multi-match glob overflows the single
// operand slot (v6.2.2 Oracle R10 R10-MF-3). sedScripts has no error
// channel, so its callers surface the verdict by recording the unsafe
// operand as a script fragment; screenSedSubagent returns the hit text.
func sedValueSlotHit(a string) string {
	if isDynamicArg(a) && !isSingleWordSplitSafe(a) {
		return "dynamic code payload"
	}
	return ""
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
					if i+1 < len(args) {
						// R10-MF-3: record the unsafe value operand so the
						// caller's dynamic check fails closed (it never
						// validates as script text).
						if sedValueSlotHit(args[i+1]) != "" {
							scripts = append(scripts, args[i+1])
						}
					}
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
							if i+1 < len(args) && sedValueSlotHit(args[i+1]) != "" {
								scripts = append(scripts, args[i+1])
							}
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
		consume, cmdText := tarSubagentWordStep(args, i, &bsdAction)
		// R10-MF-1: every operand the word consumes must stay exactly ONE
		// argv word at runtime — an unquoted $VAR or a multi-match glob in a
		// -f/-C/--file value slot expands past the slot boundary, shifting
		// every later operand allocation (in particular -I's exec hook) or
		// smuggling option-shaped words back into the parse (tar -cf $VAR).
		unsafeVal := false
		// R11-MF-1: the consume count is only validated against the words
		// ACTUALLY present — a trailing dangling value option (tar -f / tar -C
		// / tar --file with no operand) must never index past len(args).
		for k := 1; k <= consume && i+k < len(args); k++ {
			v := args[i+k]
			if isDynamicArg(v) && !isSingleWordSplitSafe(v) {
				unsafeVal = true
				break
			}
		}
		i += consume
		if unsafeVal {
			return "dynamic code payload"
		}
		cmd = cmdText
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

// tarSubagentWordStep advances screenTarSubagent past the word at index i
// (extracted so the scan loop stays reviewable — v6.2.2 R3): consume counts
// EXTRA argv operands the word eats, cmd carries an exec-hook command text
// the word arms ("" when the word is plain data or a boolean flag).
func tarSubagentWordStep(args []string, i int, bsdAction *bool) (consume int, cmd string) {
	a := args[i]
	if strings.HasPrefix(a, "--") {
		return tarSubagentLongStep(args, i)
	}
	if a == "-I" {
		if i+1 < len(args) {
			return 1, args[i+1]
		}
		return 0, ""
	}
	if strings.HasPrefix(a, "-I") && len(a) > 2 {
		return 0, a[2:]
	}
	if tarShortDataOpt(a) {
		// R11-MF-1: a trailing dangling data option consumes NOTHING — there
		// is no operand word to validate (tar itself errors at runtime).
		if i+1 < len(args) {
			return 1, "" // plain data value operand
		}
		return 0, ""
	}
	if strings.HasPrefix(a, "-") && len(a) > 1 {
		return tarSubagentClusterStep(args, i)
	}
	// BSD FIRST-ARGV action word only (tar cf / tar xf / tar tzf): GNU tar
	// treats argv[1] as a legacy action word exclusively when NO dashed
	// option appeared before it — a later operand containing 'f' is data,
	// never a cluster (v6.2.2 R3 R3-MF-1: tar -cf /dev/null /etc/fstab
	// --use-compress-program=pig must not swallow the exec option).
	if i == 0 && !*bsdAction {
		consume, cmd = tarBSDWordStep(args, i, a)
		*bsdAction = true
		return consume, cmd
	}
	return 0, ""
}

// tarBSDWordStep scans one BSD legacy action word (tar's argv[1] without
// a leading dash, e.g. `cIf`/`cfz`) letter by letter: the value letters
// f/C/T/X/I each consume one following operand IN ORDER ('I' arms the
// compress-program exec hook — tar cIf pig ... runs pig). Boolean letters
// (c/x/t/z/j/v/...) consume nothing. consume counts EXTRA argv operands
// the word eats (v6.2.2 R3 R3-MF-1).
func tarBSDWordStep(args []string, i int, a string) (consume int, cmd string) {
	slot := i + 1 // next unconsumed operand position
	for j := 0; j < len(a); j++ {
		ch := a[j]
		if ch != 'I' && ch != 'f' && ch != 'C' && ch != 'T' && ch != 'X' {
			continue
		}
		if slot < len(args) {
			if ch == 'I' {
				cmd = args[slot]
			}
			consume++
			slot++
		}
	}
	return consume, cmd
}

// tarShortDataOpt reports whether a is one of tar's plain-data value
// options consuming a separate operand. '-h' is NOT here: tar -h is the
// dereference BOOLEAN flag, never a valued option (v6.2.2 R3 R3-MF-1).
func tarShortDataOpt(a string) bool {
	switch a {
	case "-f", "--file", "-C", "--directory", "-T", "--files-from", "-X",
		"--exclude-from", "--exclude", "--owner", "--group", "--mode",
		"--mtime", "--strip-components", "--transform", "--format",
		"--index-file":
		return true
	}
	return false
}

// tarSubagentLongStep handles one `--` word of screenTarSubagent's scan.
func tarSubagentLongStep(args []string, i int) (consume int, cmd string) {
	a := args[i]
	lname, lval, hasEq := a[2:], "", false
	if k := strings.IndexByte(lname, '='); k >= 0 {
		lname, lval, hasEq = lname[:k], lname[k+1:], true
	}
	isCheckpoint := tarExecLongMatch(lname, "checkpoint-action")
	isExecValue := tarExecLongMatch(lname, "to-command") || tarExecLongMatch(lname, "use-compress-program")
	if !isCheckpoint && !isExecValue {
		// Plain-data long options (--file/--directory/...) still consume a
		// separate operand: skipping it here let the value word pose as a
		// BSD action word and swallow the REAL exec option behind it
		// (v6.2.2 R3 R3-MF-1).
		if !hasEq && tarShortDataOpt("--"+lname) {
			// R11-MF-1: a trailing dangling data option consumes NOTHING.
			if i+1 < len(args) {
				return 1, ""
			}
			return 0, ""
		}
		return 0, "" // other long options (--numeric-owner, --exclude=pat, ...)
	}
	if hasEq {
		if isCheckpoint {
			if strings.HasPrefix(lval, "exec=") {
				return 0, lval[len("exec="):]
			}
			if lval == "exec" {
				return 0, "true" // bare exec still arms the hook
			}
			return 0, ""
		}
		return 0, lval
	}
	if i+1 < len(args) {
		v := args[i+1]
		if isCheckpoint {
			if isDynamicArg(v) {
				// R10-MF-1: a --checkpoint-action operand is shell text at
				// runtime, so even a split-safe dynamic word cannot be
				// statically vetted — refuse it like the glued
				// --checkpoint-action="$VAR" form the outer scan blocks.
				return 1, v
			}
			if strings.HasPrefix(v, "exec=") {
				return 1, v[len("exec="):]
			}
			if v == "exec" {
				return 1, "true" // separate-operand bare exec arms the hook (R3-MF-1)
			}
			return 1, ""
		}
		return 1, v
	}
	return 0, ""
}

// tarSubagentClusterStep handles one short-option cluster of
// screenTarSubagent's scan: f/C/T/X take a value operand — the cluster
// tail or the next argv — and end the cluster. 'I' inside a cluster is
// --use-compress-program's short form whose operand arms an exec hook
// (v6.2.2 R3 R2-SF-3).
func tarSubagentClusterStep(args []string, i int) (consume int, cmd string) {
	a := args[i]
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'I':
			if j+1 < len(a) {
				return 0, a[j+1:]
			}
			if i+1 < len(args) {
				return 1, args[i+1]
			}
			return 0, ""
		case 'f', 'C', 'T', 'X', 'b', 'L', 'H':
			if j+1 >= len(a) && i+1 < len(args) {
				return 1, "" // value operand is the next argv
			}
			return 0, ""
		}
	}
	return 0, ""
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
