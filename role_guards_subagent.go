package main

// role_guards_subagent.go — sub-agent nested-dispatch guard, hc/ctxmode gate, npm/node runners, and caller identity.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ---------- rule 1: sub-agent nested-dispatch guard ----------

// blockedAgentExecutableList is the canonical list of executables a
// sub-agent must never spawn. blockedAgentExecutables (argv heads) and
// codeAgentNames (in-code identifier scan) are both derived from it so the
// two screens cannot drift.
var blockedAgentExecutableList = []string{
	"pig", "pi", "agy", "dispatch-agent", "dispatch-agent-go", "grok",
	// claude family: the CLI, its -code/-pty derivatives and the codex
	// launcher are all nested-agent surfaces a sub-agent must never reach.
	// The len>=5 prefix-derivative rule in isBlockedAgentHead covers
	// `claude-*`/`claude.*` (claude-code, claude-pty, claude-x.y); the
	// explicit spellings below pin the names so codeAgentNames carries them
	// verbatim for the in-code identifier scan.
	"claude", "claude-code", "claude-pty", "codex",
	// herdr/herdsman are retired as a sub-agent terminal-control surface:
	// hc is the only sanctioned channel, so even their read-only verbs
	// block outright now. dispatch-report joins the same list (v6.0.0):
	// ctx_report is the sole role-side delivery entry, so every spelling —
	// bare/path head, <t-addr>, --flush, --help — blocks for a role-guarded
	// caller; the name is NOT in pureQueryOnlyHeads, so even a
	// `dispatch-report --version` query blocks like `pig --version`.
	"herdr", "herdsman", "dispatch-report",
	// Detached session managers let a sub-agent spawn an agent outside the
	// audited ctx_run surface.
	"tmux", "screen",
	// Privilege / namespace / scheduler / remote wrappers whose inner command
	// escapes the caller's role context or scheduling control.
	"sudo", "doas", "su", "pkexec", "nsenter", "unshare", "chroot",
	"systemd-run", "at",
}

// blockedAgentExecutables are the agent executables a sub-agent must never
// spawn from ctx_run. Matching is on filepath.Base of each command head, so a
// bare name, an absolute path, or a worktree-relative path are all caught
// while `echo pig` (pig is an argument, not a head) is not.
var blockedAgentExecutables = func() map[string]bool {
	m := make(map[string]bool, len(blockedAgentExecutableList))
	for _, n := range blockedAgentExecutableList {
		m[n] = true
	}
	return m
}()

// blockedAgentDerivMinLen is the minimum stem length for the prefix
// derivative rule below: only list entries at least this long spawn
// `name-…`/`name.…` derivatives. Short stems stay exact-match — `pig-x`,
// `su-x`, `at.job` would otherwise re-identity unrelated tools
// (pigz/pigz-derivatives, at jobs, systemd units) as blocked agents.
const blockedAgentDerivMinLen = 5

// isBlockedAgentHead reports whether a resolved command-head basename names
// a blocked agent executable: an exact blockedAgentExecutables entry, or a
// `stem-…`/`stem.…` derivative of a list entry whose stem is at least
// blockedAgentDerivMinLen long. Real agent CLIs ship feature/version
// binaries under such suffixes (claude-code, claude-pty, claude.x,
// dispatch-agent-go, codex-cli); matching the stem with a '-' or '.'
// boundary keeps `claude-x` out without letting `clauder` or `piglet`
// match.
func isBlockedAgentHead(base string) bool {
	if blockedAgentExecutables[base] {
		return true
	}
	for _, n := range blockedAgentExecutableList {
		if len(n) < blockedAgentDerivMinLen {
			continue
		}
		if strings.HasPrefix(base, n+"-") || strings.HasPrefix(base, n+".") {
			return true
		}
	}
	return false
}

// hcSendAddrOK reports whether s is an hc terminal address a sub-agent may
// send to: `^t[0-9a-z]+$` — the numeric/lettered tN ids only. Named
// terminals and machine-qualified `machine/t7` spellings are not admitted.
func hcSendAddrOK(s string) bool {
	if len(s) < 2 || s[0] != 't' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

// screenHcSubagent applies the hc whitelist: `hc send <addr> <text>` with
// exactly two operand words (so --force/--if/--wait/--timeout and extra
// operands block), plus the pure query spellings `hc --help`,
// `hc --version` and `hc <sub> --help`. Every other verb — run/attach/read/
// ls/get/wait/keys/exec/file/kill/rm/label/server/machine/connect/update
// and unknown verbs — blocks; hc is a terminal-control surface like herdr,
// and send is the only channel a sub-agent is granted (the report path).
// hasHcControlChars reports code points that inject terminal control into a
// pasted `hc send` text: C0 controls other than \n/\t (\x00-\x08,
// \x0b-\x1f including \r, \x03 ETX and \x1b ESC), DEL and the C1 set
// (U+0080-U+009F — 0x9B is the ANSI CSI, a second escape-sequence lead-in).
// C1 must be rejected on the decoded RUNE, not on the byte value: every
// UTF-8 continuation byte is >= 0x80, so a byte-level 0x80-0x9F check would
// also reject the second byte of legal multi-byte encodings (U+00A0 is
// `C2 A0`) and break ordinary multilingual text.
func hasHcControlChars(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f ||
			(r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// headIsCtxmodeOrSelfExe reports whether head0 denotes THIS ctxmode binary:
// its canonical basename is "ctxmode", or the typed/resolved head is the
// running executable (path or SameFile). This is an IDENTITY test only — the
// authorization decision always needs the span-bound provenance, never
// SameFile alone.
func headIsCtxmodeOrSelfExe(head0, effPath, cwd string) bool {
	if head0 == "" || isDynamicArg(head0) {
		return false
	}
	if canonicalResolvedBase(filepath.Base(head0)) == "ctxmode" {
		return true
	}
	if canonicalResolvedBase(resolveHeadBase(head0, effPath, cwd)) == "ctxmode" {
		return true
	}
	self, selfInfo, err := resolvedSelfExe()
	if err != nil || self == "" || selfInfo == nil {
		return false
	}
	cand := head0
	if !filepath.IsAbs(cand) {
		cand = filepath.Join(cwd, cand)
	}
	if filepath.Clean(cand) == self {
		return true
	}
	if resolved, err := filepath.EvalSymlinks(cand); err == nil && filepath.Clean(resolved) == self {
		return true
	}
	if st, err := os.Stat(cand); err == nil && os.SameFile(st, selfInfo) {
		return true
	}
	return false
}

// screenCtxmodeGateHead blocks a ctxmode/selfExe head that is not backed by
// the exact prepare*-minted provenance of THIS segment. It returns "" for a
// bare binary or a plain subcommand spelling (ctxmode search …) and for a
// fully verified `<selfExe> --hc-gate send addr text` leaf; everything else
// in the --hc-gate / dynamic-option zone fails closed.
func screenCtxmodeGateHead(typedHead []string, seg shellSegment, prov *hcGateProvenance, caller callerIdentity) string {
	if len(typedHead) < 2 {
		return ""
	}
	if typedHead[1] == "--hc-gate" {
		// The rewrite must be the one this prepare* pass minted: same buffer,
		// exact head word span, exact --hc-gate word span, safe wrappers, no
		// env -i, and the prepared argv shape. The peel re-derives each head
		// under THIS call's caller cwd (peelResolvedSegDepth carries it), not
		// the process fallback — a wrapper env -C or nested -c must not
		// re-anchor the slot walk to a different directory. A cwd-changing
		// env -C/--chdir inside the wrapper chain surrenders provenance
		// outright (the prepared slot was minted under the outer cwd).
		_, headIdx, wrappers, envAs, exhausted := peelWrappersWithIndex(seg.argv, caller)
		if exhausted || headIdx < 0 || len(seg.argWords) != len(seg.argv) {
			return "ctxmode --hc-gate"
		}
		for _, op := range envAs.ops {
			if op.kind == 'c' || op.kind == 'd' {
				return "ctxmode --hc-gate"
			}
		}
		for _, w := range wrappers {
			if !hcGateSafeWrappers[w] {
				return "ctxmode --hc-gate"
			}
		}
		if prov == nil || headIdx+1 >= len(seg.argWords) {
			return "ctxmode --hc-gate"
		}
		if !prov.hasGateCall(seg.srcCode, seg.argWords[headIdx], seg.argWords[headIdx+1]) {
			return "ctxmode --hc-gate"
		}
		if !isPreparedHcGateArgv(typedHead) || len(typedHead) != 5 || typedHead[2] != "send" ||
			isDynamicArg(typedHead[3]) || !hcSendAddrOK(typedHead[3]) ||
			strings.HasPrefix(typedHead[3], "-") {
			return "ctxmode --hc-gate"
		}
		// Leading-dash on the TEXT slot: the flattened placeholder never starts
		// with "-", so the check on typedHead[4] is not a runtime guarantee.
		// The static side judges the AST word (staticWordPrefix) and the real
		// runtime check stays validateHcGateArgs on the expanded argv.
		if strings.HasPrefix(typedHead[4], "-") {
			return "ctxmode --hc-gate"
		}
		if headIdx+4 < len(seg.argWords) && seg.argWords[headIdx+4] != nil {
			if strings.HasPrefix(staticWordPrefix(seg.argWords[headIdx+4]), "-") {
				return "ctxmode --hc-gate"
			}
		}
		return ""
	}
	// Option zone before the subcommand: scan indices 1.. until the first
	// static non-'-' word (the subcommand). Everything in that zone — a
	// --hc-gate spelling, a value-carrying global option whose value is not
	// a single word, or ANY dynamic word (`a=--hc-gate; ctxmode "$a" send …`,
	// ctxmode "$@", ctxmode -"$x") — fails closed; the subcommand's own
	// operands (ctxmode search --hc-gate, ctxmode search "$q") stay free.
	for i := 1; i < len(typedHead); {

		a := typedHead[i]
		if a == "--" {
			// os.Args[1] == "--" can never reach runHcGate.
			return ""
		}
		if a == "--hc-gate" || strings.HasPrefix(a, "--hc-gate=") {
			return "ctxmode --hc-gate"
		}
		if a == "-workdir" || a == "--workdir" || a == "-config" || a == "--config" {
			// Known value-carrying global option: the next word is its value.
			// A missing value or a value that can split at runtime fails
			// closed; --workdir "$PWD" / --workdir "$PWD/x" stays open.
			if i+1 >= len(typedHead) {
				return "ctxmode " + a
			}
			if !isSingleWordOptionValue(typedHead[i+1]) {
				return "ctxmode dynamic option"
			}
			i += 2
			continue
		}
		if strings.HasPrefix(a, "-workdir=") || strings.HasPrefix(a, "--workdir=") ||
			strings.HasPrefix(a, "-config=") || strings.HasPrefix(a, "--config=") {
			val := a[strings.IndexByte(a, '=')+1:]
			if !isSingleWordOptionValue(val) {
				return "ctxmode dynamic option"
			}
			i++
			continue
		}
		if a == "-h" || a == "--help" || a == "-version" || a == "--version" || a == "-V" {
			i++
			continue
		}
		if isDynamicArg(a) {
			return "ctxmode dynamic option"
		}
		if strings.HasPrefix(a, "-") {
			// Unknown static option: keep scanning — a later dynamic word or
			// --hc-gate still fails closed.
			i++
			continue
		}
		// First static non-'-' word: the subcommand — its operands are free.
		return ""
	}
	return ""
}

func screenHcSubagent(headArgv []string) string {
	args := headArgv[1:]
	if isPureQueryInvocation(headArgv) {
		return "" // hc --help / hc -h / hc --version / hc -V
	}
	if len(args) == 0 {
		return "hc bare"
	}
	sub := args[0]
	rest := args[1:]
	if strings.HasPrefix(sub, "-") {
		return "hc " + sub
	}
	// hc <sub> --help / -h: a one-flag query on any spelled subcommand.
	if len(rest) == 1 && (rest[0] == "--help" || rest[0] == "-h") {
		return ""
	}
	if sub == "send" {
		// The addr and the text must both be static and option-free:
		// an unquoted $x splits into extra operands at runtime, and a
		// double-quoted "$(…)" placeholder could expand to a leading
		// dash or fresh control bytes, so any dynamic word fails closed.
		if len(rest) == 2 && !strings.HasPrefix(rest[0], "-") && !strings.HasPrefix(rest[1], "-") &&
			hcSendAddrOK(rest[0]) && !isDynamicArg(rest[0]) && !isDynamicArg(rest[1]) &&
			!hasHcControlChars(rest[1]) {
			return ""
		}
		return "hc send"
	}
	return "hc " + sub
}

// readonlyCanonicalHeads are the report-channel command heads a role-guarded
// caller may invoke by absolute path from their standard install locations:
// hc, the terminal client whose `send` subcommand is the notify channel. The
// map value is the set of resolved-basename aliases the on-disk file may
// legitimately carry: hc is installed as a symlink to herdr-core on the
// host. dispatch-report is deliberately absent — it is not a role-side
// spelling at all: ctx_report is the sole report entry and it execs the
// helper itself, so every ctx_run spelling of dispatch-report (bare,
// path, query or --flush) blocks for a role-guarded caller.
var readonlyCanonicalHeads = map[string][]string{
	"hc": {"hc", "herdr-core"},
}

// admittedReadonlyCanonicalHead reports whether arg0 is an absolute path
// naming a report-channel head at a TRUSTED standard install location —
// /usr/local/bin/<name> or <trusted-home>/.local/bin/<name> (the
// trustedHomeDirs() set, which testTrustedHomeRoot extends for tests) — and
// returns the canonical bare name ("hc") the allowlist
// and nested-dispatch screens should evaluate in its place. It returns ""
// for every other spelling (./name, /tmp/name, non-clean or relative
// paths), so a path-form head keeps its default-deny verdict unless it
// points at a real install slot.
//
// The on-disk file must satisfy isTrustedExecutableOnDisk AND — because
// ADAPT2 exempts system dirs like /usr/local/bin from the owner and
// permission checks — an explicit post-EvalSymlinks os.Stat requiring a
// regular file with an execute bit (a FIFO, socket or 0644 file is never
// admitted) whose resolved basename is one of the head's alias names (a
// link to an unrelated binary is never admitted either).
func admittedReadonlyCanonicalHead(arg0 string, euid int) string {
	if arg0 == "" || !filepath.IsAbs(arg0) || filepath.Clean(arg0) != arg0 {
		return ""
	}
	dir, base := filepath.Dir(arg0), filepath.Base(arg0)
	aliases, ok := readonlyCanonicalHeads[base]
	if !ok {
		return ""
	}
	ok = dir == "/usr/local/bin"
	if !ok {
		for _, h := range trustedHomeDirs() {
			if dir == filepath.Join(h, ".local/bin") {
				ok = true
				break
			}
		}
	}
	if !ok || !isTrustedExecutableOnDisk(arg0, euid) {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(arg0)
	if err != nil {
		return ""
	}
	rb := filepath.Base(resolved)
	aliasOK := false
	for _, a := range aliases {
		if rb == a {
			aliasOK = true
			break
		}
	}
	if !aliasOK {
		return ""
	}
	st, err := os.Stat(resolved)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return ""
	}
	return base
}

// queryOnlyFlagArgs are the pure query flags of the agent-launcher heads:
// they print and exit without dispatching anything. `--dry-run` and
// `--print` are deliberately absent — dispatch-agent writes its combined
// prompt files under /tmp for those, which is a write and (for a
// sub-agent) an orchestration side effect.
var queryOnlyFlagArgs = map[string]bool{
	"--version": true, "-V": true, "--help": true, "-h": true,
}

// isPureQueryInvocation reports whether argv is the program alone plus a
// single version/help flag (`prog -h`, `prog --version`). Exactly two words:
// `prog --version extra` may do more than print.
func isPureQueryInvocation(argv []string) bool {
	return len(argv) == 2 && queryOnlyFlagArgs[argv[1]]
}

// pureQueryOnlyHeads are agent-launcher heads whose ONLY job is dispatch, so
// a version/help query is their one safe spelling. `pig`/`pi`/`agy`/`grok`
// keep blocking outright: for them --version/--help is an ordinary argument
// to the agent run, not a separate query mode.
var pureQueryOnlyHeads = map[string]bool{
	"dispatch-agent":    true,
	"dispatch-agent-go": true,
}

// resolveHeadBase resolves relative command spellings against cwd — the
// ctx_run cwd of the call being screened when a guard carried it in on the
// caller identity, else the process working directory (where a bare name
// would exec anyway). cwd is per-call state: it travels inside the
// immutable callerIdentity that every recursion threads explicitly, never
// through shared package state, so two calls screened concurrently can no
// longer pollute each other's resolution base.
func (c callerIdentity) screenCwd() string {
	if c.cwd != "" {
		return c.cwd
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return ""
}

// testTrustedHomeRoot is set only by isolated unit tests (via
// withTestTrustedHome) so tests can build a fake $HOME inside t.TempDir()
// without weakening the production /tmp ban.
var testTrustedHomeRoot string

// transparentShimBins are toolchain version-manager shim multiplexers whose
// runtime dispatch is keyed on argv[0] (the shim link name) rather than the
// multiplexer binary's own basename. When ~/.local/share/mise/shims/node or
// ~/.local/share/mise/shims/rg resolves to /usr/bin/mise, the command being
// executed is still "node" or "rg", never "mise".
var transparentShimBins = map[string]bool{
	"mise": true, "asdf": true, "rustup": true, "pyenv": true,
	"rbenv": true, "nodenv": true, "volta": true, "fnm": true,
	"corepack": true,
}

// isPeeledWrapperBase reports whether base is one of the wrapper heads
// peelWrappers / peelWrappersAndWrapperAliases strip. A PATH symlink
// whose typed name is not itself a wrapper but resolves to one
// (myenv -> env, mytimeout -> timeout) must be re-peeled: the option
// peel ran on the typed name before alias resolution rewrote head[0].
func isPeeledWrapperBase(b string) bool {
	switch b {
	case "env", "command", "builtin", "exec", "nohup", "setsid",
		"nice", "timeout", "stdbuf", "busybox", "ionice", "taskset", "chrt",
		"strace", "ltrace", "time":
		return true
	}
	return false
}

// structuralFamilyKey maps a structural command basename to its
// CLI-option-compatible equivalence class. Distinct runtimes whose
// inline-code, syntax-check or subcommand flags differ (e.g. node vs
// bun/ts-node/tsx) do NOT share a key and fail closed when symlinked across
// names.
func structuralFamilyKey(base string) string {
	if shellHeads[base] {
		return "shell"
	}
	if isPythonInterpBase(base) {
		return "python"
	}
	switch base {
	case "node", "nodejs":
		return "node"
	case "awk", "gawk", "mawk", "nawk":
		return "awk"
	case "sed", "gsed":
		return "sed"
	case "tar", "gtar", "bsdtar":
		return "tar"
	case "npx", "npx-cli.js":
		return "npx"
	case "npm", "npm-cli.js":
		return "npm"
	}
	return ""
}

// sameStructuralFamily reports whether a typed structural head and its
// resolved symlink target basename are aliases for the SAME tool — the
// normal distro/toolchain layout (Debian /bin/sh -> dash, python3 ->
// python3.13, awk -> mawk, gtar -> tar, node -> nodejs, hc -> herdr-core).
// Aliases inside a family keep the typed base; a resolved name that crosses
// to a different family (bun -> node) is a conflicting alias.
func sameStructuralFamily(a, b string) bool {
	if a == b {
		return true
	}
	if (a == "hc" || a == "herdr-core") && b == "herdr-core" {
		return true
	}
	fa := structuralFamilyKey(a)
	return fa != "" && fa == structuralFamilyKey(b)
}

// isStructuralGuardHead reports whether base is a command name with
// dedicated structural/code-unwrapping logic in peelResolvedSegDepth. A
// symlink target must never overwrite a structural head name into an
// unrecognized name (which would skip -c/-e unwrapping).
func isStructuralGuardHead(base string) bool {
	if shellHeads[base] {
		return true
	}
	if _, ok := heredocInterpLang(base); ok {
		return true
	}
	switch base {
	case "ssh", "xargs", "find", "eval", "watch", "flock", "script",
		"trap", "unset", "export", "readonly", "declare", "typeset", "local",
		"read", "getopts", "printf", "command", "ctxmode",
		"awk", "gawk", "mawk", "nawk", "sed", "gsed", "tar", "gtar", "bsdtar",
		"npx", "bunx", "pnpx", "npm", "pnpm", "yarn", "git", "hc", "herdr-core":
		return true
	}
	return false
}

// userDirForbiddenShadowHeads are core OS / POSIX utilities and guard-critical
// binaries that legitimately reside in root-owned system directories
// (/bin, /usr/bin, /sbin, /usr/sbin, /usr/local/bin, /nix/store, /opt, or
// /home/linuxbrew/.linuxbrew/bin for git), never in user-home writable bin
// directories (~/.local/bin, ~/.cargo/bin, ~/go/bin, ~/.local/share/mise/shims,
// node_modules/.bin, .venv/bin). A same-name binary planted in a user-writable
// directory to shadow one of these heads is blocked by screenPathHeadTrust.
var userDirForbiddenShadowHeads = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true,
	"env": true, "command": true, "exec": true, "nohup": true, "timeout": true, "nice": true,
	"setsid": true, "stdbuf": true, "ionice": true, "taskset": true, "chrt": true,
	"strace": true, "ltrace": true, "flock": true, "script": true, "watch": true,
	"ls": true, "cat": true, "head": true, "tail": true, "wc": true, "stat": true,
	"file": true, "du": true, "df": true, "pwd": true, "echo": true, "printf": true,
	"true": true, "false": true, "which": true, "date": true, "sort": true, "uniq": true,
	"cut": true, "tr": true, "diff": true, "cmp": true, "realpath": true, "basename": true,
	"dirname": true, "readlink": true, "md5sum": true, "sha256sum": true, "sha1sum": true,
	"sha512sum": true, "strings": true, "objdump": true, "readelf": true,
	"ps": true, "pgrep": true, "ss": true, "journalctl": true, "systemctl": true,
	"find": true, "xargs": true, "sed": true, "gsed": true, "grep": true, "egrep": true, "fgrep": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true,
	"tar": true, "gtar": true, "bsdtar": true, "gzip": true, "gunzip": true,
	"bzip2": true, "bunzip2": true, "xz": true, "unxz": true, "zstd": true, "unzstd": true, "lz4": true,
	"unzip": true, "mount": true, "umount": true, "kill": true, "pkill": true, "killall": true,
	"rm": true, "unlink": true, "rmdir": true, "mv": true, "cp": true, "ln": true,
	"chmod": true, "chown": true, "chgrp": true, "mkdir": true, "mktemp": true, "touch": true,
	"dd": true, "tee": true, "crontab": true, "at": true,
	"ssh": true, "scp": true, "sftp": true, "rsync": true,
	"sudo": true, "doas": true, "su": true, "pkexec": true, "nsenter": true, "unshare": true,
	"chroot": true, "systemd-run": true, "git": true,
	// Report-channel / dispatcher heads: a planted hc/herdr-core in a
	// user-writable toolchain dir (.venv/bin, node_modules/.bin,
	// ~/.cargo/bin) must never shadow the real install slot —
	// /usr/local/bin/{hc,herdr-core} and <trustedHome>/.local/bin/{...}
	// stay free via the trusted-dir exemption in screenPathHeadTrust and
	// admittedReadonlyCanonicalHead (R2-6).
	"hc": true, "herdr-core": true,
}

// isSystemPathDir reports whether a cleaned absolute directory path is a
// system-level (non-user-home) executable directory.
func isSystemPathDir(norm string) bool {
	norm = filepath.Clean(norm)
	if isTmpOrScratchPath(norm) {
		return false
	}
	switch norm {
	case "/usr/bin", "/bin", "/usr/sbin", "/sbin",
		"/usr/local/bin", "/usr/local/sbin",
		"/usr/games", "/usr/local/games", "/snap/bin":
		return true
	}
	for _, sysPref := range []string{
		"/usr/local/", "/usr/lib/", "/usr/libexec/", "/opt/",
		"/nix/store/", "/snap/",
	} {
		if strings.HasPrefix(norm, sysPref) {
			return true
		}
	}
	return false
}

// isLinuxbrewPathDir reports whether norm is under /home/linuxbrew/.linuxbrew.
func isLinuxbrewPathDir(norm string) bool {
	norm = filepath.Clean(norm)
	const brewRoot = "/home/linuxbrew/.linuxbrew"
	return norm == brewRoot || strings.HasPrefix(norm, brewRoot+"/")
}

// resolveHeadBase returns the basename of the executable program a command
// head actually runs: the same name when head[0] is not a symlink (or cannot
// be located), the target's basename when it is. Transparent version-manager
// shims (mise, asdf, rustup, pyenv, volta, fnm, corepack) preserve the typed
// tool basename so shim-wrapped interpreters and allowlisted tools keep their
// real identity.
func resolveHeadBase(name, pathEnv, cwd string) string {
	if name == "" || isDynamicArg(name) {
		return ""
	}
	target := name
	if !filepath.IsAbs(target) {
		if !looksLikePath(target) {
			p, dot, err := lookPathIn(target, pathEnv, cwd)
			if err != nil || (dot && !hasExplicitRelativeSegment(pathEnv)) {
				return ""
			}
			target = p
		} else if cwd != "" {
			target = filepath.Join(cwd, target)
		}
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return ""
	}
	rb := filepath.Base(resolved)
	typedBase := filepath.Base(name)
	if rb != typedBase && transparentShimBins[rb] {
		return typedBase
	}
	return rb
}

// hasExplicitRelativeSegment reports whether pathEnv carries a relative
// segment the guard explicitly admitted (the toolchain-relative list) —
// only then is a "." lookup result reachable at runtime.
func hasExplicitRelativeSegment(pathEnv string) bool {
	for _, p := range strings.Split(pathEnv, ":") {
		if p != "" && !strings.HasPrefix(p, "/") {
			return true
		}
	}
	return false
}

// lookPathIn emulates execvp name resolution over an explicit PATH value:
// bare names scan each segment (relative segments resolve against cwd, the
// screened call's working directory; empty segments mean "."); returns
// (path, foundInDot, err).
func lookPathIn(name, pathEnv, cwd string) (string, bool, error) {
	if pathEnv == "" {
		pathEnv = os.Getenv("PATH")
	}
	for _, dir := range strings.Split(pathEnv, ":") {
		if p, dot, ok := lookPathOneSeg(name, dir, cwd); ok {
			return p, dot, nil
		}
	}
	return "", false, exec.ErrNotFound
}

// lookPathOneSeg resolves name inside one PATH segment (extracted from
// lookPathIn so the untrusted-marker skip and the cwd re-anchoring carry
// no extra nesting): a segment carrying the command-substitution
// placeholder is the UNTRUSTED-PATH marker, never a real directory
// (R22-Oracle-#6 / R22-Reviewer-#6) — probing the filesystem for it
// would treat an unknowable PATH as an ordinary lookup failure, or
// worse, resolve inside a directory literally named after the marker —
// so it skips to not-found exactly like a missing directory and the
// caller's untrusted-PATH classification decides the verdict. Relative
// and empty segments re-anchor against the call cwd; a missing cwd or
// a non-executable entry reports not-found.
func lookPathOneSeg(name, dir, cwd string) (string, bool, bool) {
	if pathSegUnvettable(dir) {
		return "", false, false
	}
	dot := false
	switch {
	case dir == "":
		dot = true
		dir = "."
	case !filepath.IsAbs(dir):
		dot = true // relative segment resolves against the call cwd
	}
	if !filepath.IsAbs(dir) {
		if cwd == "" {
			return "", false, false
		}
		dir = filepath.Join(cwd, dir)
	}
	p := filepath.Join(dir, name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
		return p, dot, true
	}
	return "", false, false
}

// pathSegUnvettable reports whether a PATH segment can never be a real
// lookup directory: the command-substitution placeholder anywhere in it
// marks an unknowable PATH fragment (R22-Oracle-#6).
func pathSegUnvettable(dir string) bool {
	return strings.Contains(dir, cmdSubPlaceholder)
}

// canonicalResolvedBase maps a symlink-resolved executable basename to the
// canonical program name the name-keyed screens know.
func canonicalResolvedBase(b string) string {
	switch b {
	case "npx-cli.js":
		return "npx"
	case "npm-cli.js":
		return "npm"
	}
	for _, stem := range []string{"php", "ruby", "perl"} {
		if rest, ok := strings.CutPrefix(b, stem); ok && isVersionSuffix(rest) {
			return stem
		}
	}
	// GNU packages installed by Homebrew (coreutils, findutils, grep, sed,
	// tar, ...) place the real binary under a "g"/"gnu" prefix (gdf,
	// gnutrue, gls) and symlink the unprefixed name to it, so a resolved
	// basename can carry the prefix. Map it back to the canonical program,
	// but ONLY for names Homebrew actually ships g-prefixed — stripping
	// 'g' off an unrelated real tool (gps -> ps, ghc -> hc, gcrontab)
	// would re-identity it as a different program.
	for _, pref := range []string{"gnu", "g"} {
		if rest, ok := strings.CutPrefix(b, pref); ok && gnuCanonicalSet[rest] {
			return rest
		}
	}
	return b
}

// gnuCanonicalSet is the closed list of program names that have a real
// Homebrew/Linuxbrew g-prefixed binary (coreutils, findutils, gnu-sed,
// gnu-tar, grep, gawk, diffutils, ed, getopt, gzip, make, parallel,
// gnu-time, which, gnu-getopt, gnu-indent, gnu-units) plus the wrapper
// names a g-prefixed coreutils install also provides (genv, gtimeout,
// gnice, gnohup, gstdbuf). Real tools like gps, ghc, gcrontab are NOT
// in the set: stripping their 'g' would alias them to ps/hc/crontab.
var gnuCanonicalSet = map[string]bool{
	// coreutils
	"env": true, "timeout": true, "nice": true, "nohup": true, "stdbuf": true,
	"printenv": true, "true": true, "false": true, "ls": true, "dir": true,
	"vdir": true, "cat": true, "head": true, "tail": true, "wc": true,
	"stat": true, "du": true, "df": true, "pwd": true, "echo": true,
	"printf": true, "yes": true, "date": true, "sort": true, "uniq": true,
	"cut": true, "tr": true, "fold": true, "fmt": true, "join": true,
	"paste": true, "split": true, "csplit": true, "nl": true, "pr": true,
	"expand": true, "unexpand": true, "comm": true, "tsort": true,
	"factor": true, "shuf": true, "tee": true, "mktemp": true, "install": true,
	"mkdir": true, "rmdir": true, "mkfifo": true, "mknod": true,
	"mv": true, "cp": true, "ln": true, "link": true, "unlink": true,
	"rm": true, "chmod": true, "chown": true, "chgrp": true, "touch": true,
	"dd": true, "sync": true, "truncate": true, "shred": true,
	"basename": true, "dirname": true, "readlink": true, "realpath": true,
	"pathchk": true, "md5sum": true, "sha1sum": true, "sha256sum": true,
	"sha384sum": true, "sha512sum": true, "b2sum": true, "cksum": true,
	"sum": true, "base32": true, "base64": true, "basenc": true,
	"tty": true, "uname": true, "hostname": true, "arch": true,
	"id": true, "whoami": true, "who": true, "users": true, "groups": true,
	"logname": true, "nproc": true, "uptime": true, "sleep": true,
	"kill": true, "test": true, "[": true, "expr": true,
	"numfmt": true, "seq": true, "stty": true, "chroot": true,
	"chcon": true, "runcon": true, "hostid": true, "pinky": true,
	"dircolors": true,
	// findutils
	"find": true, "xargs": true, "locate": true, "updatedb": true,
	// grep / sed / awk / tar / diffutils / ed / getopt / make / which / time
	"grep": true, "egrep": true, "fgrep": true, "sed": true,
	"awk": true, "tar": true, "diff": true, "cmp": true, "diff3": true,
	"sdiff": true, "patch": true, "ed": true, "getopt": true, "make": true,
	"which": true, "time": true, "indent": true, "units": true,
	// compression tools that also get brew g-prefixes on some formulas
	"gzip": true, "gunzip": true, "zcat": true,
}

// isVersionSuffix reports whether s is a version tail: a digit followed by
// digits and dots only ("8.3", "3.2", "5.38.2").
func isVersionSuffix(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// headBaseAliasHits returns every name a command head can resolve to: its
// own basename plus, when the file behind head[0] is a symlink, the basename
// of the resolved target.
func headBaseAliasHits(headArgv []string, pathEnv string, caller callerIdentity) []string {
	if len(headArgv) == 0 {
		return nil
	}
	out := []string{filepath.Base(headArgv[0])}
	if b := resolveHeadBase(headArgv[0], pathEnv, caller.screenCwd()); b != "" && b != out[0] {
		out = append(out, b)
		// Normalize the resolved target (npm-cli.js -> npm family, g-prefixed
		// GNU spellings): an unnormalized alias target must never slip past
		// the structural-name screens downstream (v6.2.2 MF-4a).
		if canon := canonicalResolvedBase(b); canon != b && canon != out[0] {
			out = append(out, canon)
		}
	}
	return out
}

// screenPathHeadTrust verifies that a bare command head resolved through
// pathEnv is not backed by an untrusted/world-writable binary, a symlink
// escaping into /tmp, or a user-directory binary planted to shadow a core
// system command (C10: [pattern:path-trust-user-writable]).
func screenPathHeadTrust(head0, pathEnv string, caller callerIdentity) string {
	if head0 == "" || isDynamicArg(head0) || looksLikePath(head0) || filepath.IsAbs(head0) {
		return ""
	}
	p, dot, err := lookPathIn(head0, pathEnv, caller.screenCwd())
	if err != nil {
		return ""
	}
	euid := os.Geteuid()
	if dot {
		// A relative PATH segment skips every on-disk check above, so a
		// whitelisted toolchain dir (.venv/bin, node_modules/.bin) could
		// smuggle a symlink escaping the workspace (.venv/bin/pytest ->
		// /tmp/pytest, or -> /home/otheruser/.local/bin/pytest). Resolve
		// the link and require the target to stay inside the current
		// workspace, or to land in a trusted system/linuxbrew/user
		// toolchain dir that also passes the executable trust check
		// (regular venv .venv/bin/python3 -> /usr/bin/python3.x).
		if !hasExplicitRelativeSegment(pathEnv) {
			return ""
		}
		resolved, rerr := filepath.EvalSymlinks(p)
		if rerr != nil {
			return "untrusted path binary " + head0
		}
		resolved = filepath.Clean(resolved)
		// R5 MF-5/SF-6: the resolved TARGET's basename gets the same planted-
		// shadow rule the typed head carries below — but ONLY when the target
		// itself lives in a user/toolchain/workspace dir. A symlink alias
		// pointing at a real system binary (.venv/bin/mysh -> /bin/sh,
		// ssx -> /usr/bin/ssh) resolves to a legitimate system location and
		// must NOT trip the block (the remote boundary and structural-alias
		// screens judge it downstream); a linuxbrew-dir target only exempts
		// when the resolved path differs from the lookup path itself. The
		// hc/herdr-core install slot keeps its existing hcSlotOK exemption.
		rdir := filepath.Clean(filepath.Dir(resolved))
		rbShadow := canonicalResolvedBase(filepath.Base(resolved))
		if userDirForbiddenShadowHeads[rbShadow] &&
			!isSystemPathDir(rdir) && !(isLinuxbrewPathDir(rdir) && resolved != filepath.Clean(p)) &&
			rbShadow != head0 && !isAllowedSystemReadonlyAlias(head0, rbShadow, head0, pathEnv, caller.screenCwd()) {
			absP := filepath.Clean(p)
			if !filepath.IsAbs(absP) {
				absP = filepath.Join(caller.screenCwd(), absP)
			}
			if !(admittedReadonlyCanonicalHead(absP, euid) != "" &&
				(head0 == "hc" || head0 == "herdr-core")) {
				return "planted shadow binary in user path: " + head0
			}
		}
		realCwd := filepath.Clean(caller.screenCwd())
		if ec, e := filepath.EvalSymlinks(realCwd); e == nil {
			realCwd = filepath.Clean(ec)
		}
		// The hc/herdr-core admission judges the CANDIDATE path the PATH
		// lookup produced (p), never the EvalSymlinks target (whose
		// basename is typically herdr-core): /usr/local/bin/hc and
		// <trustedHome>/.local/bin/hc -> herdr-core stay free while a
		// .venv/bin/hc or node_modules/.bin/hc symlink — even one whose
		// target lands back inside the workspace or a toolchain dir —
		// is a planted shadow and fails closed (R3 SF-2). A symlink ALIAS
		// name (myhc -> hc, .venv/bin/mysh -> .venv/bin/sh) hits the same
		// rule through the resolved target's basename (R4 MF-4).
		rb := canonicalResolvedBase(filepath.Base(resolved))
		hcSlotOK := func() bool {
			if head0 != "hc" && head0 != "herdr-core" && rb != "hc" && rb != "herdr-core" {
				return true
			}
			absP := filepath.Clean(p)
			if !filepath.IsAbs(absP) {
				absP = filepath.Join(caller.screenCwd(), absP)
			}
			return admittedReadonlyCanonicalHead(absP, euid) != "" &&
				(head0 == "hc" || head0 == "herdr-core")
		}
		if realCwd != "" && realCwd != "." && realCwd != string(filepath.Separator) &&
			(resolved == realCwd || strings.HasPrefix(resolved, realCwd+string(filepath.Separator))) {
			// A report-channel/dispatcher head that resolved inside the
			// workspace is only admissible at a REAL install slot
			// (/usr/local/bin or <trustedHome>/.local/bin). A planted
			// .venv/bin/hc, node_modules/.bin/hc or <cwd>/hc that the
			// relative-PATH lookup resolved inside the project tree is a
			// shadow and must block (R2-6).
			if !hcSlotOK() {
				return "planted shadow binary in user path: " + head0
			}
			return "" // resolved target stays inside the workspace
		}
		if isTrustedRelToolchainTarget(resolved, realCwd, euid) {
			// A hoisted-monorepo/sibling-worktree hc/herdr-core shadow still
			// fails closed unless it lands at a real install slot.
			if !hcSlotOK() {
				return "planted shadow binary in user path: " + head0
			}
			return ""
		}
		if (isSystemPathDir(rdir) || isLinuxbrewPathDir(rdir) || caller.isUserToolchainPathDir(rdir)) &&
			isTrustedExecutableOnDiskCwd(resolved, euid, caller.screenCwd()) {
			if !hcSlotOK() {
				return "planted shadow binary in user path: " + head0
			}
			return ""
		}
		return "untrusted path binary " + head0
	}
	dir := filepath.Clean(filepath.Dir(p))
	inToolchainDir := caller.isUserToolchainPathDir(dir) || isLinuxbrewPathDir(dir)
	if !isSystemPathDir(dir) && !inToolchainDir {
		return ""
	}
	if !isTrustedExecutableOnDiskCwd(p, euid, caller.screenCwd()) {
		return "untrusted path binary " + head0
	}
	// A symlink alias name (myhc -> hc, myenv -> env, mysh -> sh) escapes
	// the literal-head0 check, so resolve the candidate once and judge the
	// TARGET's canonical basename through the same planted-shadow rule
	// (R5 MF-5/SF-6): when the resolved target itself lives in a
	// user/toolchain/workspace dir and its basename names a forbidden
	// shadow head, the alias is a planted shadow — the .local/bin
	// install-slot exemption stays keyed on the TYPED name (a myhc -> hc
	// alias there is still a shadow, never an install slot), and a
	// standard same-name / same-family alias (rb == head0 or
	// isAllowedSystemReadonlyAlias, e.g. sh -> dash, awk -> mawk) is a
	// distro spelling, not a shadow. Targets resolving to a real system
	// dir (/bin/sh, /usr/bin/ssh) — or a linuxbrew dir only when the
	// symlink is real — likewise stay free, so ssx -> /usr/bin/ssh and
	// ordinary distro links are never evidence of a planted shadow.
	resolved := ""
	rb := ""
	if r, rerr := filepath.EvalSymlinks(p); rerr == nil {
		resolved = filepath.Clean(r)
		rb = canonicalResolvedBase(filepath.Base(resolved))
	}
	if resolved != "" {
		rdir := filepath.Clean(filepath.Dir(resolved))
		if userDirForbiddenShadowHeads[rb] &&
			!isSystemPathDir(rdir) && !(isLinuxbrewPathDir(rdir) && resolved != filepath.Clean(p)) &&
			rb != head0 && !isAllowedSystemReadonlyAlias(head0, rb, head0, pathEnv, caller.screenCwd()) {
			// The <trustedHome>/.local/bin install slot is the only typed-name
			// exemption (a myhc -> hc alias there is still a shadow). A
			// standard same-name / same-family alias (sh -> dash, awk -> mawk,
			// grep -> ggrep) inside a toolchain dir is a distro spelling, not
			// a planted shadow, and stays free.
			localBinSlot := false
			if tail, ok := stripTrustedHomePrefix(dir); ok && tail == "/.local/bin" {
				localBinSlot = true
			}
			if !(head0 == "hc" || head0 == "herdr-core") || !localBinSlot {
				return "planted shadow binary in user path: " + head0
			}
		}
	}
	if inToolchainDir && userDirForbiddenShadowHeads[head0] {
		if head0 == "git" && isLinuxbrewPathDir(dir) {
			return ""
		}
		// The hc/herdr-core shadow rule must not kill the REAL install slot
		// a trusted-home .local/bin legitimately holds (the report channel
		// admits that same slot via admittedReadonlyCanonicalHead); every
		// other toolchain dir — .venv/bin, node_modules/.bin, ~/.cargo/bin,
		// mise shims, project-local venvs — keeps the block. The slot
		// exemption stays keyed on the TYPED name: a myhc -> hc alias in
		// .local/bin is still a planted shadow, never an install slot.
		if head0 == "hc" || head0 == "herdr-core" {
			if tail, ok := stripTrustedHomePrefix(dir); ok && tail == "/.local/bin" {
				return ""
			}
		}
		// A standard same-name / same-family alias whose resolved target
		// lives in a real system dir (sh -> /usr/bin/dash, awk -> mawk,
		// grep -> ggrep, which -> debianutils.which) is a distro spelling,
		// not a planted shadow — the R5 resolved-target rule above already
		// blocks targets planted inside user/toolchain/workspace dirs, so
		// this exemption can only admit system-dir targets.
		if resolved != "" {
			rdir := filepath.Clean(filepath.Dir(resolved))
			if (isSystemPathDir(rdir) || (isLinuxbrewPathDir(rdir) && resolved != filepath.Clean(p))) &&
				(rb == head0 || isAllowedSystemReadonlyAlias(head0, rb, head0, pathEnv, caller.screenCwd())) {
				return ""
			}
		}
		return "planted shadow binary in user path: " + head0
	}
	return ""
}

// isTrustedExecutableOnDisk checks that an executable resolved from a
// toolchain/system PATH directory (and its EvalSymlinks target) is owned by
// root or euid — at system locations the owner check is exempt (ADAPT2) and
// write bits are not judged there (see the note in isTrustedPathDirOnDisk) —
// and that it does not resolve into /tmp|/var/tmp|/dev/shm|/run.
func isTrustedExecutableOnDisk(binPath string, euid int) bool {
	return isTrustedExecutableOnDiskCwd(binPath, euid, "")
}
func isTrustedExecutableOnDiskCwd(binPath string, euid int, cwd string) bool {
	dir := filepath.Clean(filepath.Dir(binPath))
	if !isTrustedPathDirOnDiskCwd(dir, euid, cwd) {
		return false
	}
	// ADAPT2: a binary in a lexical system PATH dir skips the owner-uid
	// check, mirroring isTrustedPathDirOnDisk — system dirs are
	// admin-managed, so a third-party image owner (e.g. uid 65534 on a
	// container image's /opt) is normal there. The fixed linuxbrew prefix
	// gets the same treatment (see isTrustedPathDirOnDisk). Write bits are
	// not judged at system locations either (same note); a target that
	// escapes into a user dir keeps the owner check below, and user
	// toolchain dirs keep the full owner check here.
	sysBin := isSystemPathDir(dir) || isLinuxbrewPathDir(dir)
	if lst, err := os.Lstat(binPath); err == nil && !sysBin {
		if !statUIDAndPermOK(lst, euid, true) {
			return false
		}
	}
	resolved, err := filepath.EvalSymlinks(binPath)
	if err != nil {
		return false
	}
	resolved = filepath.Clean(resolved)
	if isTmpOrScratchPath(resolved) {
		return false
	}
	st, err := os.Stat(resolved)
	if err != nil || st.IsDir() {
		return false
	}
	resDir := filepath.Clean(filepath.Dir(resolved))
	// The resolved target is judged by where it lives: a target inside a
	// system dir (or the linuxbrew prefix) gets the same ADAPT2 exemption;
	// a target that escapes into a user dir keeps the owner check.
	if !isSystemPathDir(resDir) && !isLinuxbrewPathDir(resDir) {
		if !statUIDAndPermOK(st, euid, false) {
			return false
		}
	}
	return isTrustedPathDirOnDiskCwd(resDir, euid, cwd)
}

// isAllowedSystemReadonlyAlias reports whether a symlink from typedBase to
// resolvedBase is a standard OS/distro alias for an allowlisted command.
func isAllowedSystemReadonlyAlias(typedBase, resolvedBase, head0, pathEnv, cwd string) bool {
	if typedBase == resolvedBase || transparentShimBins[resolvedBase] {
		return true
	}
	if canonicalResolvedBase(resolvedBase) == typedBase {
		return true
	}
	if shellHeads[typedBase] && shellHeads[resolvedBase] {
		return true
	}
	switch typedBase {
	case "awk", "gawk", "mawk", "nawk":
		if resolvedBase == "awk" || resolvedBase == "gawk" || resolvedBase == "mawk" || resolvedBase == "nawk" {
			return true
		}
	case "grep", "egrep", "fgrep":
		if resolvedBase == "grep" || resolvedBase == "egrep" || resolvedBase == "fgrep" {
			return true
		}
	case "sed", "gsed":
		if resolvedBase == "sed" || resolvedBase == "gsed" {
			return true
		}
	case "systemctl", "journalctl":
		if resolvedBase == "systemd" || resolvedBase == "systemctl" || resolvedBase == "journalctl" {
			return true
		}
	case "hc":
		if resolvedBase == "herdr-core" {
			return true
		}
	case "which":
		if strings.Contains(resolvedBase, "which") || resolvedBase == "debianutils" {
			return true
		}
	case "strings", "objdump", "readelf":
		if strings.HasSuffix(resolvedBase, "-"+typedBase) || strings.Contains(resolvedBase, typedBase) {
			return true
		}
	}
	if resolvedBase == "coreutils" || resolvedBase == "busybox" {
		if p, _, err := lookPathIn(head0, pathEnv, cwd); err == nil && isSystemPathDir(filepath.Dir(p)) {
			return true
		}
	}
	return false
}

// screenReadonlyAliasTarget ensures that when a bare command in strict
// readonly mode resolves through a symlink to a different binary name, the
// target binary name is also permitted by the readonly allowlist (closing the
// C10 symlink-to-unlisted-binary bypass).
func screenReadonlyAliasTarget(typedHead []string, pathEnv string, caller callerIdentity) string {
	if len(typedHead) == 0 {
		return ""
	}
	typedBase := canonicalResolvedBase(filepath.Base(typedHead[0]))
	rb := resolveHeadBase(typedHead[0], pathEnv, caller.screenCwd())
	if rb == "" {
		return ""
	}
	rbCanon := canonicalResolvedBase(rb)
	if isAllowedSystemReadonlyAlias(typedBase, rbCanon, typedHead[0], pathEnv, caller.screenCwd()) {
		return ""
	}
	aliasArgv := append([]string{rbCanon}, typedHead[1:]...)
	return screenReadonlyAllowlist(aliasArgv)
}

// screenNestedDispatch returns the guard hit for ONE resolved command head
// (already wrapper-peeled), or "" when allowed. headArgv starts at the head.
// depth carries the enclosing peel budget (peelChainMaxDepth) so a nested
// recursion — `npm exec -- npm exec -- …`, `npm exec -- npx …` — consumes
// the SAME budget instead of restarting it; caller is the env-seeded
// identity the inner command inherits.
// `git` heads also get the global exec-config screen: a sub-agent must not
// arm a pager/ssh/hook command through `git -c`/`--config-env`/`--exec-path`.
func screenNestedDispatch(headArgv []string, pathEnv string, depth int, caller callerIdentity) string {
	if len(headArgv) == 0 {
		return ""
	}
	bases := headBaseAliasHits(headArgv, pathEnv, caller)
	// A path-form head (./x, /tmp/x, ...) whose typed OR resolved basename
	// lands on a report-channel head must be a trusted standard install
	// path: screenHcSubagent judges only the tail args, so a planted
	// /tmp/hc would otherwise inherit the bare-name grant. The same
	// admission the strict-readonly canonical-head rule applies; every
	// other path-form head keeps the existing basename dispatch unchanged.
	if strings.Contains(headArgv[0], "/") || looksLikePath(headArgv[0]) {
		for _, base := range bases {
			switch base {
			case "hc", "herdr-core":
				// A dot-prefixed relative head like `.foo` is a path spelling
				// (looksLikePath), never a PATH lookup — admittedReadonlyCanonicalHead
				// requires filepath.IsAbs, so it fails closed on this branch.
				if admittedReadonlyCanonicalHead(headArgv[0], os.Geteuid()) == "" {
					return "untrusted path binary " + filepath.Base(headArgv[0])
				}
			}
		}
	}
	for _, base := range bases {
		if isPureQueryInvocation(headArgv) && pureQueryOnlyHeads[base] {
			continue // `dispatch-agent --version`: nothing is dispatched
		}
		// Exact blocked names hit before the switch; the prefix-derivative
		// check runs only in the default branch so a resolved alias the
		// switch owns (hc -> herdr-core, a legitimate herder-family target)
		// is not re-blocked by a coincidental `herdr-`/`dispatch-agent-`
		// prefix match on its real binary name.
		if blockedAgentExecutables[base] {
			return base
		}
		switch base {
		// `herdr-core` is the host-side symlink target of `hc`; naming the
		// target directly must route through the same hc whitelist so
		// `herdr-core run ...` cannot bypass the `hc` interception.
		case "hc", "herdr-core":
			if hit := screenHcSubagent(headArgv); hit != "" {
				return hit
			}
		case "crontab":
			// `crontab -l` alone is a read-only listing; every other spelling
			// (-e, -r, file, -, extra args) mutates or schedules.
			if len(headArgv) != 2 || headArgv[1] != "-l" {
				return "crontab"
			}
		case "git":
			if _, hit := screenGitGlobalArgs(headArgv[1:]); hit != "" {
				return hit
			}
			if hit := screenGitSubagentExecArgs(headArgv[1:], caller); hit != "" {
				return hit
			}
		// npm/pnpm/yarn `exec`/`dlx` fetch-and-run a package binary — the
		// same unvetted-code surface as npx/bunx/pnpx. The argv is parsed
		// once by parseNpmFamilyArgv's finite accept grammar: the verb is
		// the FIRST positional (`npm view exec pig`'s `exec` is a `view`
		// field name), `-c`/`--call` and every unlisted option Reject, and
		// the WHOLE child argv recurses through peelResolvedSegDepth at
		// depth+1 so `npm exec -- npm exec pig` and `npm exec -- npx pig`
		// are screened under the shared budget.
		case "npm", "pnpm", "yarn":
			r := parseNpmFamilyArgv(base, headArgv[1:])
			switch r.state {
			case npmArgvExec:
				// A -p/--package spec naming a blocked executable is a hit
				// whatever the child command is: `tsc` cannot launder
				// `--package=pig`.
				for _, spec := range r.packages {
					if isBlockedAgentHead(filepath.Base(nodePkgSpecBase(spec))) {
						return base + " " + r.verb + " " + spec
					}
				}
				// The child's FIRST positional is the package spec the runner
				// fetch-and-runs: normalize it like the -p/--package specs
				// above (`pig@latest` -> `pig`, `@scope/pig@1.2` -> `pig`) or
				// the version tag hides the blocked name from the PATH lookup
				// and the agent blacklist. A non-scoped spec containing `/`
				// is a path, not a registry name, and stays verbatim (the
				// recursion's own filepath.Base still sees `pig`). The tail
				// always stays verbatim so a nested
				// `npm exec -- npm exec pig` still recurses.
				child := r.child
				if head0 := child[0]; strings.HasPrefix(head0, "@") || !strings.Contains(head0, "/") {
					child = append([]string{filepath.Base(nodePkgSpecBase(head0))}, child[1:]...)
				}
				if hit := peelResolvedSegDepth(child, shellSegment{}, 's', depth+1, caller); hit != "" {
					return base + " " + r.verb + " " + hit
				}
			case npmArgvReject:
				return r.rejectHit(base)
			}
		default:
			if isBlockedAgentHead(base) {
				return base
			}
		}
	}
	return ""
}

// npmArgvState is the verdict of parseNpmFamilyArgv.
type npmArgvState int

const (
	npmArgvNoVerb npmArgvState = iota // flag-only argv: no subcommand
	npmArgvOther                      // a non-exec/dlx verb
	npmArgvExec                       // verb is exec/dlx: child/packages filled
	npmArgvReject                     // argv does not fit the accepted grammar
)

// npmArgvParse is the result of parseNpmFamilyArgv: the locked verb (and
// its argv index), the exec/dlx child command plus -p/--package specs, or
// the rejection reason.
type npmArgvParse struct {
	state    npmArgvState
	verbIx   int      // argv index of the subcommand word (-1 when none)
	verb     string   // the subcommand word
	child    []string // exec/dlx: the fetched command argv to re-screen
	packages []string // exec/dlx: package specs named by -p/--package
	reason   string   // Reject detail
}

// rejectHit formats the guard hit for a rejected parse.
func (r npmArgvParse) rejectHit(base string) string {
	if r.verb != "" {
		return base + " " + r.verb + " " + r.reason
	}
	return base + " " + r.reason
}

// npmOptKind classifies an accepted npm-family option spelling.
type npmOptKind byte

const (
	npmOptBool    npmOptKind = 'B' // boolean: no operand
	npmOptValue   npmOptKind = 'V' // consumes one operand value
	npmOptPackage npmOptKind = 'S' // consumes a package spec operand
)

// npmFamilyOptTable is the FINITE accepted set of npm/pnpm/yarn option
// spellings keyed by manager: a boolean, a value-taker or (in exec mode)
// a package-spec taker. Anything not listed — long or short — is a
// Reject, never a guessed pass: the guard deliberately does not emulate
// the full CLI surface.
var npmFamilyOptTable = map[string]map[string]npmOptKind{
	"npm": {
		"help": npmOptBool, "h": npmOptBool,
		"version": npmOptBool, "v": npmOptBool,
		"yes": npmOptBool, "y": npmOptBool,
		"global": npmOptBool, "g": npmOptBool,
		"parseable": npmOptBool, "p": npmOptBool,
		"prefix": npmOptValue, "workspace": npmOptValue, "w": npmOptValue,
		"userconfig": npmOptValue, "globalconfig": npmOptValue,
		"cache": npmOptValue, "registry": npmOptValue,
		"loglevel": npmOptValue, "tag": npmOptValue,
	},
	"pnpm": {
		"help": npmOptBool, "h": npmOptBool,
		"version": npmOptBool, "v": npmOptBool,
		"workspace-root": npmOptBool, "w": npmOptBool,
		"recursive": npmOptBool, "r": npmOptBool,
		"dir": npmOptValue, "C": npmOptValue,
		"filter": npmOptValue, "F": npmOptValue,
	},
	"yarn": {
		"help": npmOptBool, "h": npmOptBool,
		"version": npmOptBool, "v": npmOptBool,
		"cwd": npmOptValue,
	},
}

// npmFamilyExecOptTable lists the extra options exec/dlx accept on top of
// the common set: -p/--package name a fetched package spec. npm's own `-p`
// stays boolean (parseable): unlike pnpm's/yarn's it is NOT a --package
// alias, so `npm exec -p pig` cannot smuggle a spec — and only yarn gets
// `-p` as a spec taker here.
var npmFamilyExecOptTable = map[string]map[string]npmOptKind{
	"npm":  {"package": npmOptPackage},
	"pnpm": {"package": npmOptPackage},
	"yarn": {"package": npmOptPackage, "p": npmOptPackage},
}

// parseNpmFamilyArgv parses an npm/pnpm/yarn argv under the guard's
// finite accept grammar. The first positional locks the subcommand verb —
// only exec/dlx enter the exec state (every other verb is Other, so
// `npm view exec pig`'s `exec` stays field data, and no trailing scan can
// resurrect it). exec/dlx then collect the child command the manager
// would fetch-and-run: manager options are consumed up front — the
// option-zone boundary differs per manager (npm's own `--` ends its
// option zone so `--package`/`--call` still parse BETWEEN the first
// child word and that `--`; pnpm/yarn's first child word locks the
// child command and ends their option zone) — and the child's first
// positional is version/tag-stripped like a -p/--package spec so
// `pig@latest` still hits the blacklist. Once the zone ends, `--` and
// every later word are child data passed through
// verbatim — `pnpm exec npm exec -- tsc --noEmit` and
// `npm -- exec tsc --noEmit` keep `--noEmit` as tsc's own option.
// `-c`/`--call` in the option zone, every unlisted option spelling, a
// dynamic operand and a malformed value slot all Reject — the grammar
// fails closed everywhere instead of guessing.
func parseNpmFamilyArgv(base string, args []string) npmArgvParse {
	r := npmArgvParse{verbIx: -1}
	reject := func(reason string) npmArgvParse {
		return npmArgvParse{state: npmArgvReject, verbIx: r.verbIx, verb: r.verb, reason: reason}
	}
	common := npmFamilyOptTable[base]
	execOpts := npmFamilyExecOptTable[base]

	// takeValue consumes an inline or separate option value; it returns
	// the value and the index of the next unconsumed word, or a Reject.
	takeValue := func(i int, inline string, hasInline bool) (string, int, npmArgvParse) {
		if hasInline {
			v := strings.TrimPrefix(inline, "=") // short cluster may glue -C=dir
			if v == "" {
				return "", 0, reject("empty option value")
			}
			if isDynamicArg(v) {
				return "", 0, reject("dynamic option value")
			}
			return v, i + 1, npmArgvParse{}
		}
		if i+1 >= len(args) || args[i+1] == "--" {
			return "", 0, reject("missing option value")
		}
		v := args[i+1]
		if v == "" {
			return "", 0, reject("empty option value")
		}
		if strings.HasPrefix(v, "-") || isDynamicArg(v) {
			return "", 0, reject("missing option value")
		}
		return v, i + 2, npmArgvParse{}
	}

	inExec := false
	childLocked := false // a child word was seen (pnpm/yarn: ends the option zone)
	managerDD := false   // the manager's own `--` was consumed (npm exec: zone end)
	for i := 0; i < len(args); {
		a := args[i]
		if a == "--" {
			if (childLocked && base != "npm") || managerDD {
				// pnpm/yarn: the first child word already ended the manager
				// option zone, so this `--` belongs to the child. Any manager
				// (incl. npm): a `--` after the manager's own is child data.
				// Either way pass it — and every word after it — through
				// verbatim so `pnpm exec npm exec -- tsc --noEmit` keeps
				// `--noEmit` as tsc's own data instead of reopening manager
				// option parsing. npm's FIRST `--` is deliberately excluded
				// here even when a child word already locked: it is the
				// manager's own zone boundary (removed below), not child
				// data — keeping it verbatim would hand the inner npm a
				// separator that lets `npm exec npm exec -- --call=pig`
				// smuggle the option past the outer screen.
				r.child = append(r.child, args[i:]...)
				break
			}
			if !inExec {
				// `--` closes manager option parsing; the NEXT word is the
				// verb (a dynamic verb cannot be judged — fail closed). This
				// pre-verb `--` is also the manager's own separator: for npm
				// it ends the option zone, so `npm -- exec tsc --noEmit`
				// keeps `--noEmit` as the child's data once `tsc` locks.
				managerDD = true
				i++
				if i >= len(args) {
					r.state = npmArgvNoVerb
					return r
				}
				if isDynamicArg(args[i]) {
					return reject("dynamic operand")
				}
				r.verbIx, r.verb = i, args[i]
				if r.verb == "exec" || r.verb == "dlx" {
					inExec, r.state = true, npmArgvExec
					i++
					continue
				}
				r.state = npmArgvOther
				return r
			}
			// exec: `--` removes itself; everything after joins the child.
			// For npm this is also the manager's own option-zone boundary:
			// `--package`/`--call` found BEFORE it are still manager options
			// even when a child word already appeared.
			managerDD = true
			r.child = append(r.child, args[i+1:]...)
			break
		}
		treatAsOpt := strings.HasPrefix(a, "-") && a != "-"
		switch {
		case !inExec:
			// GLOBAL: option-looking words are manager options.
		case base == "npm" && !managerDD:
			// npm's own `--` — not the first child word — ends the option
			// zone: `--package`/`--call` between the child head and `--`
			// are still manager options, so `npm exec tsc --package=pig`
			// cannot hide a spec behind the locked command.
		case childLocked:
			// pnpm/yarn: once the first child word locks the fetched
			// command, the tail is the child's own argv — an option-looking
			// word there is the CHILD's option (`tsc --noEmit`), never a
			// manager option. The same rule governs `--` above.
			treatAsOpt = false
		}
		if treatAsOpt {
			endBool := false // last consumed kind was a bare boolean
			if strings.HasPrefix(a, "--") {
				name, val, hasEq := strings.Cut(a[2:], "=")
				switch {
				case name == "c" || name == "call":
					return reject("option --" + name)
				}
				kind, ok := common[name]
				if !ok && inExec {
					kind, ok = execOpts[name]
				}
				if !ok {
					return reject("option --" + name)
				}
				switch kind {
				case npmOptBool:
					if hasEq {
						if val != "true" && val != "false" {
							return reject("option --" + name + " value")
						}
					} else {
						endBool = true
					}
					i++
				case npmOptValue:
					_, ni, rr := takeValue(i, val, hasEq)
					if rr.state == npmArgvReject {
						return rr
					}
					i = ni
				case npmOptPackage:
					v, ni, rr := takeValue(i, val, hasEq)
					if rr.state == npmArgvReject {
						return rr
					}
					r.packages = append(r.packages, v)
					i = ni
				}
			} else {
				// Short option or cluster: B letters continue; a V/S letter
				// eats the cluster tail (an optional leading `=` is dropped)
				// or the next word, then the word is done. `c` and unknown
				// letters Reject.
				valueEnd := false
				for j := 1; j < len(a); j++ {
					ch := a[j : j+1]
					if ch == "c" {
						return reject("option -c")
					}
					kind, ok := common[ch]
					if !ok && inExec {
						kind, ok = execOpts[ch]
					}
					if !ok {
						return reject("option -" + ch)
					}
					if kind == npmOptBool {
						endBool = true
						continue
					}
					v, ni, rr := takeValue(i, a[j+1:], j+1 < len(a))
					if rr.state == npmArgvReject {
						return rr
					}
					if kind == npmOptPackage {
						r.packages = append(r.packages, v)
					}
					i = ni
					valueEnd = true
					break
				}
				if !valueEnd {
					i++
				}
			}
			if endBool && i < len(args) && (args[i] == "true" || args[i] == "false") {
				// An optional boolean value must be glued; a separated
				// true/false word would misparse as the verb or a child
				// word — fail closed rather than guess the arity.
				return reject("separated boolean value")
			}
			continue
		}
		// Positional word.
		if isDynamicArg(a) {
			return reject("dynamic operand")
		}
		if !inExec {
			r.verbIx, r.verb = i, a
			if a == "exec" || a == "dlx" {
				inExec, r.state = true, npmArgvExec
				i++
				continue
			}
			r.state = npmArgvOther
			return r
		}
		r.child = append(r.child, a)
		childLocked = true
		i++
	}
	if r.state == npmArgvExec && len(r.child) == 0 {
		// `npm exec` with no command: do not guess a manifest default bin
		// or an interactive shell — fail closed.
		return reject("missing command")
	}
	return r
}

// nodePkgSpecBase strips the version/tag suffix from an npm package
// spec: `pig@latest` → `pig`, `@scope/pkg@1.2` → `@scope/pkg`, a bare
// `pig` or `@scope/pkg` unchanged. The executable the runner dispatches
// is what matters to the guard, not the registry version pin.
func nodePkgSpecBase(spec string) string {
	if i := strings.LastIndexByte(spec, '@'); i > 0 {
		return spec[:i]
	}
	return spec
}

// screenNodeRunnerSubagent vets an npx/bunx/pnpx invocation for a
// sub-agent caller: -c/--call hands a raw command string to a shell
// (unvettable), -p/--package installs-and-runs the named package (its
// spec is checked against blockedAgentExecutables after version
// stripping), unknown flags fail closed, and the first positional
// package spec is re-dispatched through screenNestedDispatch so
// `npx pig@latest` and `bunx hc kill t1` cannot dodge the agent/terminal
// whitelists.
func screenNodeRunnerSubagent(base string, args []string, effPath string, depth int, caller callerIdentity) string {
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if isDynamicArg(a) {
			return "dynamic code payload"
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break // first positional: package spec / command
		}
		if strings.HasPrefix(a, "--") {
			name := a[2:]
			val := ""
			glued := false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				val = name[eq+1:]
				name = name[:eq]
				glued = true
			}
			switch name {
			case "call":
				return base + " -c"
			case "package":
				if !glued && i+1 < len(args) {
					i++
					val = args[i]
				}
				if isDynamicArg(val) {
					return "dynamic code payload"
				}
				if spec := filepath.Base(nodePkgSpecBase(val)); isBlockedAgentHead(spec) {
					return base + " " + spec
				}
			case "prefix", "userconfig":
				if !glued && i+1 < len(args) {
					i++
					val = args[i]
				}
				if !isSingleWordOptionValue(val) {
					return "dynamic code payload"
				}
				if _, ok := resolveNodeRunnerPathOpt(val, caller.screenCwd()); !ok {
					return base + " --" + name
				}
			case "cache", "registry", "workspace":
				if !glued && i+1 < len(args) {
					i++
					val = args[i]
				}
				if !isSingleWordOptionValue(val) {
					return "dynamic code payload"
				}
			case "yes", "no", "no-install", "quiet", "silent", "offline",
				"prefer-offline", "workspaces", "workspace-root",
				"include-workspace-root", "help", "version":
				if glued && isDynamicArg(val) {
					return "dynamic code payload"
				}
			case "bun":
				if base != "bunx" || (glued && isDynamicArg(val)) {
					return base + " " + a
				}
			default:
				return base + " " + a // fail closed on unknown long flags
			}
			continue
		}
		// Short-option cluster: c is -c (arbitrary command); p carries a
		// value; -w is value-taking for npx and boolean for pnpx; y/n/q/s/v/h
		// and bunx -b are boolean.
		for j := 1; j < len(a); j++ {
			ch := a[j]
			switch {
			case ch == 'c':
				return base + " -c"
			case ch == 'p' || (ch == 'w' && base == "npx"):
				val := a[j+1:]
				if val == "" && i+1 < len(args) {
					i++
					val = args[i]
				}
				if isDynamicArg(val) {
					return "dynamic code payload"
				}
				if ch == 'p' {
					if spec := filepath.Base(nodePkgSpecBase(val)); isBlockedAgentHead(spec) {
						return base + " " + spec
					}
				}
				j = len(a) // value ends the cluster
			case ch == 'y' || ch == 'n' || ch == 'q' || ch == 's' || ch == 'v' || ch == 'h' ||
				(ch == 'w' && base == "pnpx") || (ch == 'b' && base == "bunx"):
				// boolean short flags
			default:
				return base + " " + a // fail closed on unknown short flags
			}
		}
	}
	if i >= len(args) {
		return "" // bare npx / flag-only invocation
	}
	spec := filepath.Base(nodePkgSpecBase(args[i]))
	if isDynamicArg(spec) || spec == "." || spec == ".." {
		return "dynamic code payload"
	}
	inner := append([]string{spec}, args[i+1:]...)
	// The fetched command argv re-enters the shared peel at depth+1: the
	// inner head may itself be a manager/runner (`npx npx pig`,
	// `npm exec -- npx pig`) or a shell (`npx sh -c pig`), and every such
	// hop consumes the SAME peel budget.
	if hit := peelResolvedSegDepth(inner, shellSegment{}, 's', depth+1, caller); hit != "" {
		return base + " " + hit
	}
	return ""
}

// isSingleWordOptionValue reports whether a value operand of a known two-slot
// option cannot split into multiple argv words at runtime: static words,
// split-safe dynamic words ("$HOME/...", "$PWD/..."), and pure tilde paths
// (`~/.npmrc` — carries a single cmdSubPlaceholderGlob at leading '~' with no
// unquoted $/cmdsub and no wildcard characters). R14-Oracle-S2: brace
// expansion and quoting bytes join the exclusion set — a `~/{a,b}` spelling
// expands into MULTIPLE words under bash even though it carries no glob
// metacharacter, so the pure-tilde exemption must never cover it.
func isSingleWordOptionValue(val string) bool {
	// R18-Oracle-S5: the NUL-provenanced tilde marker is pure provenance —
	// it never changes how many argv words the expansion produces (bash's
	// tilde expansion never field-splits), so it is stripped before the
	// dynamic grading: an untainted `~/banner` AND a tainted one both stay
	// exactly one word, while the path-restoration proof they differ on is
	// judged independently in resolveNodeRunnerPathOpt.
	val = strings.ReplaceAll(val, cmdSubPlaceholderTilde, "")
	if !isDynamicArg(val) || isSingleWordSplitSafe(val) {
		return true
	}
	if strings.HasPrefix(val, "~") &&
		!strings.Contains(val, cmdSubPlaceholder) &&
		!strings.ContainsAny(val, "*?[") &&
		strings.Count(val, cmdSubPlaceholderGlob) == 1 &&
		!strings.Contains(strings.SplitN(val, cmdSubPlaceholderGlob, 2)[0], "{") {
		return true
	}
	return false
}

// callerIdentity is the role identity a spawned child would inherit: the
// caller's own CTXMODE_ROLE / CTXMODE_READONLY process-env values. The env
// op replay in screenEnvAssignments starts from it so `env -i`/`env -u`
// shedding is judged against who the caller really is, not against a
// static allowlist.
type callerIdentity struct {
	role     string // CTXMODE_ROLE as-is (trimmed)
	readonly string // CTXMODE_READONLY raw value
	// envTaint marks variables an outer envAs overrode (HOME=/x sh -c,
	// env -i, env -u PWD). Nested shell payloads parsed under this
	// caller degrade the PATH/HOME/abs-dir placeholder grants for these
	// names (SH11 F3/Q5).
	envTaint map[string]bool
	// pathEnv is the EFFECTIVE PATH the nested child resolves against:
	// the process PATH replayed through every envAs op seen so far. ""
	// means "use the process PATH" — the same fallback lookPathIn
	// already applies to an empty pathEnv argument (R7).
	pathEnv string
	// hcProv is the prepare*-minted provenance of the buffer being screened.
	// It is non-nil ONLY on the guardPreparedShell entry and while crossing one
	// verified `sh -c` script word; every other cross-buffer recursion clears
	// it by construction.
	hcProv *hcGateProvenance
	// cwd is the ctx_run cwd of the call under screening: immutable per-call
	// state carried by value on this identity so every recursion resolves
	// relative heads/PATH segments against THIS call's directory and two
	// concurrent screens cannot pollute each other (replaces the former
	// package-level screenCwd, [pattern:shared-guard-cwd]). "" means no
	// call cwd was pinned — screenCwd() then falls back to the process
	// working directory, the same semantics the global empty value had
	// (unit screening).
	cwd string
	// xw is the request-scoped xargs memo/budget table (R22-Reviewer-#1 /
	// R22-Oracle-M5): minted once per top-level guard entry, it threads
	// through every recursion of the SAME analysis request so all xargs
	// descents share the single 512-node budget, while two parallel
	// requests can never share a verdict or a step count. nil means no
	// request scope exists (direct unit screening) — xargsWork then
	// mints a fresh table per entry.
	xw *xargsWorkState
}

// effectivePATH returns the PATH the identity resolves against: pathEnv
// already replayed through every env op seen so far by seededWith, or the
// process PATH fallback lookPathIn applies to an empty value.
func (c callerIdentity) effectivePATH() string {
	if c.pathEnv != "" {
		return c.pathEnv
	}
	return os.Getenv("PATH")
}

// currentCallerIdentity reads the caller's role identity from the process
// environment once per top-level guard entry.
func currentCallerIdentity() callerIdentity {
	return callerIdentity{
		role:     strings.TrimSpace(os.Getenv(auditEnvRole)),
		readonly: os.Getenv(auditEnvReadonly),
		pathEnv:  os.Getenv("PATH"),
		// R22-Reviewer-#1: one xargs memo/budget table per top-level guard
		// request — every recursion of this analysis shares the 512-node
		// budget, and a concurrent request can never observe or reset it.
		xw: &xargsWorkState{},
	}
}

// seededWith returns a copy of the identity whose envTaint additionally
// covers every name envAs overrode or cleared. Recursion into nested shell
// payloads (-c scripts, eval text, env -S, flock -c, script -c, watch
// operands, heredoc bodies, here-strings) uses it so inner placeholder
// grants match the real env. The effective PATH is replayed too (R7): a
// PATH=/x prefix must drive alias resolution inside the nested payload.
// An `env -C DIR`/`env --chdir=DIR` op additionally re-anchors cwd so the
// inner command's relative heads and any relative PATH segments resolve
// under the directory env would actually chdir into (R2-4).
func (c callerIdentity) seededWith(envAs envAssignments) callerIdentity {
	c.pathEnv = envAs.effectivePATHFrom(c.pathEnv)
	c = c.seededCwdWith(envAs)
	extra := envAs.taintedSentinelNames()
	if len(extra) == 0 {
		return c
	}
	merged := make(map[string]bool, len(c.envTaint)+len(extra))
	for k, v := range c.envTaint {
		merged[k] = v
	}
	for k := range extra {
		merged[k] = true
	}
	c.envTaint = merged
	return c
}

// seededCwdWith applies env -C/--chdir ops in order: each `d` op re-anchors
// the identity cwd to the resolved target (a relative DIR joins onto the
// CURRENT screen cwd, then filepath.Clean). An empty or dynamic DIR
// clears cwd so downstream head/PATH resolution fails closed rather than
// silently falling back to the outer directory.
func (c callerIdentity) seededCwdWith(envAs envAssignments) callerIdentity {
	for _, op := range envAs.ops {
		if op.kind != 'd' {
			continue
		}
		dir := op.value
		if dir == "" || isDynamicArg(dir) {
			c.cwd = ""
			continue
		}
		if !filepath.IsAbs(dir) {
			base := c.screenCwd()
			if base == "" {
				c.cwd = ""
				continue
			}
			dir = filepath.Join(base, dir)
		}
		c.cwd = filepath.Clean(dir)
	}
	return c
}

// callerIdentity returns a callerIdentity consistent with g's role flags so
// direct unit-test guardCall structs (e.g. guardCall{subagent: true} run
// under `CTXMODE_ROLE=verifier go test`) never inherit a conflicting role
// from the outer test runner's process environment. The pinned call cwd
// rides along so alias/PATH resolution inside the guard sees THIS call's
// working directory.
func (g guardCall) callerIdentity() callerIdentity {
	c := currentCallerIdentity()
	c.cwd = g.cwd
	if !g.readonly && !g.strictReadonly {
		c.readonly = ""
		if auditRoleIsReadonly(c.role) {
			c.role = "worker"
		} else if c.role == "" && g.subagent {
			c.role = "worker"
		}
	} else {
		if !callerReadonlyRole(c) {
			c.readonly = "1"
		}
	}
	return c
}

// wrapperWriteOpHit scans the leading wrapper chain of argv for options
// that WRITE: strace/ltrace -o FILE / --output=FILE, /usr/bin/time -o FILE
// / --output=FILE, flock -o / --close. Peeling must not discard them — a
// strict read-only caller running `strace -o /tmp/t ls` still writes
// /tmp/t. Non-writing wrappers and KEY=VAL prefixes are stepped through
// the same way peelWrappers walks them, so `env strace -o /tmp/t ls` and
// `FOO=1 nice time -o /tmp/t ls` cannot hide the write behind a prefix.
// The scan stops at the first operand that is not part of a wrapper; it
// returns the offending `head -o` detail or "".
func wrapperWriteOpHit(argv []string) string {
	var envAs envAssignments
	for i := 0; i < len(argv); {
		a := argv[i]
		if isAssignWord(a) {
			envAs.addAssign(a)
			i++
			continue
		}
		if shellNoopWords[a] {
			i++
			continue
		}
		base := filepath.Base(a)
		switch base {
		case "strace", "ltrace":
			j := i + 1
			for j < len(argv) {
				a := argv[j]
				if a == "--" {
					j++
					break
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-o" || a == "--output" {
					return base + " -o"
				}
				if strings.HasPrefix(a, "-o") && len(a) > 2 || strings.HasPrefix(a, "--output=") {
					return base + " -o"
				}
				if straceArgHasValue(a) {
					j += 2
					continue
				}
				j++
			}
			i = j
		case "time":
			j := i + 1
			for j < len(argv) {
				a := argv[j]
				if a == "--" {
					j++
					break
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-o" || a == "--output" || strings.HasPrefix(a, "--output=") ||
					(strings.HasPrefix(a, "-o") && len(a) > 2) ||
					a == "-a" || a == "--append" {
					return base + " -o"
				}
				if a == "-f" || a == "--format" {
					j += 2
					continue
				}
				j++
			}
			i = j
		case "flock":
			j := i + 1
			for j < len(argv) {
				a := argv[j]
				if a == "--" {
					j++
					break
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-o" || a == "--close" {
					return base + " " + a
				}
				if flockArgHasValue(a) {
					j += 2
					continue
				}
				j++
			}
			i = j
		// Non-writing wrappers: step through exactly like peelWrappers does
		// so the scan keeps looking at the next head.
		case "if", "then", "elif", "else", "while", "until", "do", "!", "coproc":
			i++
		case "env":
			var payloads []string
			var rest []string
			rest, payloads, envAs = skipEnvOperands(argv, i+1, envAs)
			argv = rest
			i = 0
			_ = payloads // env -S payloads are screened by the caller chain
		case "command":
			if isCommandQuery(argv[i+1:]) {
				return "" // pure query: nothing after it executes
			}
			i++
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				i++
			}
			i = skipDashDash(argv, i)
		case "builtin":
			i++
			for i < len(argv) && strings.HasPrefix(argv[i], "-") && argv[i] != "--" {
				i++
			}
			i = skipDashDash(argv, i)
		case "exec":
			// bash exec [-cl] [-a name] [--] command (internal_getopt "cla:").
			i, _ = skipExecArgs(argv, i+1)
		case "nohup":
			i++
			i = skipDashDash(argv, i)
		case "setsid":
			i++
			for i < len(argv) {
				a := argv[i]
				if a == "--" {
					i++
					break
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				i++
			}
		case "nice":
			i++
			for i < len(argv) {
				a := argv[i]
				if a == "--" {
					i++
					break
				}
				if !strings.HasPrefix(a, "-") || a == "-" {
					break
				}
				if a == "-n" || a == "--adjustment" {
					i += 2 // separate value
					continue
				}
				i++ // -nN / -n-N / --adjustment=N / -N glued level / boolean
			}
		case "timeout":
			i, _ = skipTimeoutArgs(argv, i+1)
		case "stdbuf":
			i, _ = skipStdbufArgs(argv, i+1)
		case "busybox":
			i++
		case "ionice":
			i, _ = skipIoniceArgs(argv, i+1)
		case "taskset":
			i, _ = skipTasksetArgs(argv, i+1)
		case "chrt":
			i, _ = skipChrtArgs(argv, i+1)
		case "--":
			i++
		default:
			return ""
		}
	}
	return ""
}

// peelPreludeHasNonAssign reports whether the declaration builtin at
// head[0] LOSES POSIX declaration-utility status at runtime, in which case
// its KEY=VAL operands DO field-split like ordinary command arguments.
// Four demotion channels are covered (v6.2.2 Oracle R10 R10-MF-4 extended
// by Oracle R11 R11-MF-2):
//  1. a peeled non-assignment wrapper word (command/builtin/env/timeout/...)
//     — the posix prelude scan over argv[:len(argv)-len(head)];
//  2. an env -S operand-stream rewrite — head is no longer a contiguous
//     tail slice of argv, so the positional correspondence the lenient
//     declaration rule relies on is unprovable;
//  3. a QUOTED or ESCAPED command word ("export"/\export/ex"port") —
//     dash and bash gate declaration status on an unquoted, unescaped
//     literal token, which seg.argWords' parse shape proves: the head
//     word must be exactly one *syntax.Lit whose value IS head[0];
//  4. a for-loop enum-expanded command head ($E) — runtime expansion
//     never carries declaration status, and the expansion leaves
//     argWords[headIdx] == nil.
//
// A bash DeclClause segment (seg.declClause) is exempt from channel 3/4:
// the parser itself only forms that node for an unquoted literal keyword.
func peelPreludeHasNonAssign(argv, head []string, seg shellSegment) bool {
	if len(head) == 0 {
		return false
	}
	if len(argv) < len(head) || &argv[len(argv)-len(head)] != &head[0] {
		return true // env -S (or any) operand-stream rewrite (channel 2)
	}
	headIdx := len(argv) - len(head)
	for _, w := range argv[:headIdx] {
		if !isAssignWord(w) {
			return true // non-assignment wrapper word (channel 1)
		}
	}
	if seg.declClause {
		return false
	}
	if len(seg.argWords) != len(argv) {
		// No parse-shape provenance for these words (ctx_run argv mode, or a
		// rebuilt stream): fail closed on the command word's lexical status.
		return true
	}
	hw := seg.argWords[headIdx]
	if hw == nil || len(hw.Parts) != 1 {
		return true // enum-expanded head / concatenated or empty word
	}
	lit, ok := hw.Parts[0].(*syntax.Lit)
	if !ok || lit.Value != head[0] {
		return true // quoted/escaped or non-literal command word
	}
	return false
}

// straceArgHasValue reports whether an strace/ltrace option consumes a
// separate value slot (so the next argv word is its argument, not the
// traced command). The list MUST match skipStraceArgs' two-slot set — an
// option missing here lets its value masquerade as the traced command
// and can hide a later -o FILE from wrapperWriteOpHit.
func straceArgHasValue(a string) bool {
	switch a {
	case "-e", "-o", "-p", "-s", "-u", "-E", "-a", "-b", "-O", "-S", "-I", "-P",
		"-X", "-U",
		"--trace", "--output", "--attach", "--string-limit", "--user",
		"--env", "--columns", "--const-print-style", "--summary-columns",
		"--trace-path", "--signal":
		return true
	}
	return false
}

// flockArgHasValue reports whether a flock option consumes a separate
// value slot: -w/--timeout SEC, -E/--conflict-exit-code CODE,
// -F/--fcntl, -d/--fd FD.
func flockArgHasValue(a string) bool {
	switch a {
	case "-w", "--timeout", "-E", "--conflict-exit-code", "-F", "--fcntl",
		"-d", "--fd":
		return true
	}
	return false
}

// peelResolved strips wrappers from argv then applies the shared recursive
// checks (env -S payload, execution-hook env screen, shell -c unwrap,
// interpreter inline code, eval / xargs / find tail recursion, watch/flock
// inner commands, trap actions, unset targets) for the given guard kind.
// kind is 's' (subagent) or 'r' (strict read-only); depth bounds recursion
// and fails closed at peelChainMaxDepth. It returns the guard hit or "".
