package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Shell policy modes.
const (
	PolicyModeOff       = "off"
	PolicyModeAllowlist = "allowlist"
	PolicyModeDenylist  = "denylist"
)

// defaultSystemProtectedPaths are refused as rm targets when not inside a workdir.
var defaultSystemProtectedPaths = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib64",
	"/proc", "/sys", "/sbin", "/usr", "/var",
}

// defaultDenyCommands are built-in high-risk commands refused by basename in
// denylist mode. User entries are merged with this set. Network inspection
// tools are handled separately by checkCommandArgs so read-only diagnostics
// remain available while mutation subcommands are refused.
var defaultDenyCommands = []string{
	// Shutdown / reboot.
	"shutdown", "reboot", "poweroff", "halt", "init", "telinit", "kexec",
	// Block device / filesystem destruction.
	"mkfs", "fdisk", "sfdisk", "cfdisk", "parted", "wipefs", "dd", "shred",
	// Bulk firewall restore bypasses command-level mutation checks.
	"iptables-restore", "ip6tables-restore", "ebtables-restore", "arptables-restore",
	// Privilege escalation / identity switching.
	"su", "sudo", "doas", "pkexec",
}

// defaultDenyPrefixes match command basenames that start with the prefix
// (e.g. mkfs.ext4, mkfs.xfs, mkfs.btrfs, …). Exact-name entries in
// defaultDenyCommands cover the bare tools.
var defaultDenyPrefixes = []string{"mkfs."}

// defaultDenyPatterns are regexes applied to the full command string whenever
// mode != off (both shell and argv paths). They cover patterns a plain
// command-name list cannot express: remote script piping into a shell, and
// common fork-bomb literals. User `deny_patterns` are merged with these.
var defaultDenyPatterns = []string{
	// Remote content piped into a shell, including wrappers between pipe and shell.
	`(?is)\b(?:curl|wget)\b[^|;\n]*\|[^|;\n]*\b(?:ba|da|z|k)?sh\b`,
	// Canonical bash fork bomb literal:  :(){ :|:& };:
	`:\s*\(\s*\)\s*\{`,
	// Common named fork bombs:  bomb() { bomb | bomb & }; bomb
	`(?i)\b(bomb|fork)\s*\(\s*\)\s*\{`,
}

// ShellPolicyConfig is the YAML/serializable policy configuration.
type ShellPolicyConfig struct {
	Mode         string         `yaml:"mode"`
	Allow        []string       `yaml:"allow"`
	Deny         []string       `yaml:"deny"`
	DenyPatterns []string       `yaml:"deny_patterns"`
	RM           RMPolicyConfig `yaml:"rm"`
	SystemPaths  []string       `yaml:"system_paths"`
}

// RMPolicyConfig controls rm target checks.
type RMPolicyConfig struct {
	// AllowInWorkdir permits rm of paths inside configured workdirs (default true).
	AllowInWorkdir *bool `yaml:"allow_in_workdir"`
	// DenySystemPaths rejects system-protected paths outside workdirs (default true).
	DenySystemPaths *bool `yaml:"deny_system_paths"`
}

// ShellPolicy is the runtime checker for shell/argv execution.
// Default mode is denylist: normal commands run, built-in high-risk commands
// and patterns are refused. mode=off and mode=allowlist remain available.
type ShellPolicy struct {
	Mode            string
	allowSet        map[string]bool
	denySet         map[string]bool
	denyPrefixes    []string
	denyRes         []*regexp.Regexp
	workdirs        []string
	systemPaths     []string
	allowInWorkdir  bool
	denySystemPaths bool
}

// builtinDenySet returns a fresh map of the built-in denied command basenames.
func builtinDenySet() map[string]bool {
	m := make(map[string]bool, len(defaultDenyCommands))
	for _, c := range defaultDenyCommands {
		m[c] = true
	}
	return m
}

// builtinDenyRegexps returns the compiled built-in deny patterns. These are
// static constants; a compile failure is a programming error, so MustCompile
// is intentional here.
var builtinDenyRegexps = func() []*regexp.Regexp {
	res := make([]*regexp.Regexp, 0, len(defaultDenyPatterns))
	for _, pat := range defaultDenyPatterns {
		res = append(res, regexp.MustCompile(pat))
	}
	return res
}()

// DefaultShellPolicy returns the default policy: denylist mode with the
// built-in high-risk command set and deny patterns active. mode=off is the
// explicit escape hatch for fully disabling checks.
func DefaultShellPolicy() *ShellPolicy {
	return &ShellPolicy{
		Mode:            PolicyModeDenylist,
		allowSet:        map[string]bool{},
		denySet:         builtinDenySet(),
		denyPrefixes:    append([]string{}, defaultDenyPrefixes...),
		denyRes:         append([]*regexp.Regexp{}, builtinDenyRegexps...),
		allowInWorkdir:  true,
		denySystemPaths: true,
		systemPaths:     append([]string{}, defaultSystemProtectedPaths...),
	}
}

// NewShellPolicy builds a policy from config + workdirs.
// Default mode is denylist (built-in high-risk commands/patterns refused);
// explicit mode=off or mode=allowlist keeps the documented override semantics.
// CTXMODE_POLICY_MODE env overrides Mode when set (off|allowlist|denylist).
func NewShellPolicy(cfg ShellPolicyConfig, workdirs []string) (*ShellPolicy, error) {
	p := DefaultShellPolicy()
	p.workdirs = append([]string{}, workdirs...)

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = PolicyModeDenylist
	}
	if env := strings.ToLower(strings.TrimSpace(os.Getenv("CTXMODE_POLICY_MODE"))); env != "" {
		mode = env
	}
	switch mode {
	case PolicyModeOff, PolicyModeAllowlist, PolicyModeDenylist:
		p.Mode = mode
	default:
		return nil, fmt.Errorf("invalid policy.shell.mode %q (want off|allowlist|denylist)", mode)
	}

	for _, a := range cfg.Allow {
		a = strings.TrimSpace(a)
		if a != "" {
			p.allowSet[filepath.Base(a)] = true
		}
	}
	for _, d := range cfg.Deny {
		d = strings.TrimSpace(d)
		if d != "" {
			// Merged into (never replacing) the built-in deny set.
			p.denySet[filepath.Base(d)] = true
		}
	}

	// User deny_patterns are merged after the built-in patterns.
	for _, pat := range cfg.DenyPatterns {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid deny_pattern %q: %w", pat, err)
		}
		p.denyRes = append(p.denyRes, re)
	}

	if len(cfg.SystemPaths) > 0 {
		p.systemPaths = nil
		for _, sp := range cfg.SystemPaths {
			sp = filepath.Clean(strings.TrimSpace(sp))
			if sp != "" {
				p.systemPaths = append(p.systemPaths, sp)
			}
		}
	}

	p.allowInWorkdir = true
	if cfg.RM.AllowInWorkdir != nil {
		p.allowInWorkdir = *cfg.RM.AllowInWorkdir
	}
	p.denySystemPaths = true
	if cfg.RM.DenySystemPaths != nil {
		p.denySystemPaths = *cfg.RM.DenySystemPaths
	}

	return p, nil
}

// CheckShell validates a shell command string against the policy.
// cwd is the process working directory used to resolve relative rm paths.
func (p *ShellPolicy) CheckShell(command, cwd string) error {
	if p == nil || p.Mode == "" || p.Mode == PolicyModeOff {
		return nil
	}
	command = strings.TrimSpace(command)
	if command == "" {
		return fmt.Errorf("policy: empty command")
	}

	// Fail-closed: unescaped $(...) or backticks enable hidden commands.
	if hasCommandSubstitution(command) {
		return fmt.Errorf("policy rejects command substitution")
	}

	// deny_patterns apply whenever mode != off.
	if err := p.matchDenyPatterns(command); err != nil {
		return err
	}

	segments := splitShellSegments(command)
	if len(segments) == 0 {
		return fmt.Errorf("policy: empty command")
	}

	for _, seg := range segments {
		tokens := tokenizeShell(seg)
		tokens = skipEnvAssignments(tokens)
		if len(tokens) == 0 {
			continue
		}
		// Peel env/nice/timeout/… so allowlist + checkRM see the real command.
		tokens = stripCommandWrappers(tokens)
		if len(tokens) == 0 {
			continue
		}
		cmdName := commandBasename(tokens[0])
		if cmdName == "" {
			return fmt.Errorf("policy: empty command token")
		}

		if err := p.checkCommandName(cmdName); err != nil {
			return err
		}
		if err := p.checkCommandArgs(cmdName, tokens); err != nil {
			return err
		}

		if cmdName == "rm" {
			if err := p.checkRM(tokens, cwd); err != nil {
				return err
			}
		}

		// If allowlist permits a shell, re-check -c payload under the same policy.
		if isShellName(cmdName) {
			if err := p.checkShellDashC(tokens, cwd); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckArgv validates a direct-exec argv (no shell) against the policy.
// When mode=allowlist, the real command basename (after wrapper strip) must be allowed.
// cwd is the process working directory used to resolve relative rm paths.
func (p *ShellPolicy) CheckArgv(argv []string, cwd string) error {
	if p == nil || p.Mode == "" || p.Mode == PolicyModeOff {
		return nil
	}
	if len(argv) == 0 {
		return fmt.Errorf("policy: empty argv")
	}

	// Apply deny_patterns to a space-joined form for curl|sh style patterns.
	if err := p.matchDenyPatterns(strings.Join(argv, " ")); err != nil {
		return err
	}

	tokens := stripCommandWrappers(argv)
	if len(tokens) == 0 {
		// Only wrappers / env assignments — fall back to argv[0].
		tokens = argv
	}
	cmdName := commandBasename(tokens[0])
	if cmdName == "" {
		return fmt.Errorf("policy: empty argv[0]")
	}

	if err := p.checkCommandName(cmdName); err != nil {
		return err
	}
	if err := p.checkCommandArgs(cmdName, tokens); err != nil {
		return err
	}

	if cmdName == "rm" {
		return p.checkRM(tokens, cwd)
	}

	if isShellName(cmdName) {
		return p.checkShellDashC(tokens, cwd)
	}
	return nil
}

// isShellName reports names that accept a -c script payload.
func isShellName(name string) bool {
	switch name {
	case "bash", "sh", "dash", "zsh", "ksh":
		return true
	default:
		return false
	}
}

// checkShellDashC re-runs CheckShell on the script argument of sh/bash -c.
func (p *ShellPolicy) checkShellDashC(tokens []string, cwd string) error {
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if t == "-c" {
			if i+1 >= len(tokens) {
				return fmt.Errorf("policy: shell -c missing script")
			}
			return p.CheckShell(tokens[i+1], cwd)
		}
		if strings.HasPrefix(t, "--") {
			if t == "--" {
				break
			}
			continue
		}
		if strings.HasPrefix(t, "-") && t != "-" {
			// Combined short flags: -lc, -ec, … treat like -c when 'c' present.
			if strings.Contains(t, "c") {
				if i+1 >= len(tokens) {
					return fmt.Errorf("policy: shell -c missing script")
				}
				return p.CheckShell(tokens[i+1], cwd)
			}
			continue
		}
		// Non-option: shell script path (not -c).
		break
	}
	return nil
}

// shellWrapperNames are prefix commands that wrap another executable.
// After stripping these (and their flags), policy checks the real command.
var shellWrapperNames = map[string]bool{
	"env": true, "nice": true, "nohup": true, "stdbuf": true,
	"timeout": true, "command": true, "builtin": true, "time": true,
	"busybox": true, "toybox": true,
}

// stripCommandWrappers peels common wrappers (env, nice, nohup, …) and their
// flags until the real command token remains. Handles nested wrappers.
func stripCommandWrappers(tokens []string) []string {
	for len(tokens) > 0 {
		name := commandBasename(tokens[0])
		if !shellWrapperNames[name] {
			return tokens
		}
		rest := tokens[1:]
		var next []string
		switch name {
		case "env":
			next = stripEnvWrapperArgs(rest)
		case "nice":
			next = stripNiceWrapperArgs(rest)
		case "timeout":
			next = stripTimeoutWrapperArgs(rest)
		case "stdbuf":
			next = stripStdbufWrapperArgs(rest)
		case "command":
			next = stripCommandBuiltinArgs(rest)
		case "time":
			next = stripTimeWrapperArgs(rest)
		case "nohup", "builtin", "busybox", "toybox":
			next = stripSimpleWrapperArgs(rest)
		default:
			return tokens
		}
		if len(next) == 0 {
			return nil
		}
		// Safety: must make progress (consume at least the wrapper token).
		if len(next) >= len(tokens) {
			return next
		}
		tokens = next
	}
	return tokens
}

// stripEnvWrapperArgs skips env flags and VAR=val assignments.
// e.g. env -i FOO=bar rm -rf /  →  rm -rf /
func stripEnvWrapperArgs(rest []string) []string {
	i := 0
	for i < len(rest) {
		t := rest[i]
		if t == "--" {
			return rest[i+1:]
		}
		if isEnvAssignment(t) {
			i++
			continue
		}
		if strings.HasPrefix(t, "-") && t != "-" {
			// Value-taking long options (without =value form).
			switch t {
			case "--unset", "--chdir", "--split-string",
				"--block-signal", "--default-signal", "--ignore-signal",
				"-u", "-C", "-S":
				i++
				if i < len(rest) {
					i++
				}
				continue
			}
			i++
			continue
		}
		return rest[i:]
	}
	return nil
}

func stripNiceWrapperArgs(rest []string) []string {
	if len(rest) == 0 {
		return nil
	}
	if rest[0] == "-n" {
		if len(rest) >= 2 {
			return rest[2:]
		}
		return nil
	}
	// nice -10 / nice +5
	if isNiceAdjustment(rest[0]) {
		return rest[1:]
	}
	return stripSimpleWrapperArgs(rest)
}

func isNiceAdjustment(t string) bool {
	if t == "" || t == "-" || t == "+" || t == "--" {
		return false
	}
	s := t
	if s[0] == '-' || s[0] == '+' {
		s = s[1:]
	} else {
		return false
	}
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// stripTimeoutWrapperArgs: timeout [options] DURATION COMMAND…
func stripTimeoutWrapperArgs(rest []string) []string {
	i := 0
	for i < len(rest) {
		t := rest[i]
		if t == "--" {
			i++
			break
		}
		if strings.HasPrefix(t, "-") && t != "-" {
			switch t {
			case "-k", "-s", "--kill-after", "--signal":
				i++
				if i < len(rest) {
					i++
				}
				continue
			}
			// --kill-after=1s / --signal=TERM already one token; other flags flag-only.
			i++
			continue
		}
		// First non-option is DURATION.
		i++
		break
	}
	if i >= len(rest) {
		return nil
	}
	return rest[i:]
}

func stripStdbufWrapperArgs(rest []string) []string {
	i := 0
	for i < len(rest) {
		t := rest[i]
		if t == "--" {
			return rest[i+1:]
		}
		if strings.HasPrefix(t, "-") && t != "-" {
			switch t {
			case "-i", "-o", "-e", "--input", "--output", "--error":
				i++
				if i < len(rest) {
					i++
				}
				continue
			}
			i++
			continue
		}
		return rest[i:]
	}
	return nil
}

func stripCommandBuiltinArgs(rest []string) []string {
	// command [-pVv] name args…
	return stripSimpleWrapperArgs(rest)
}

func stripTimeWrapperArgs(rest []string) []string {
	i := 0
	for i < len(rest) {
		t := rest[i]
		if t == "--" {
			return rest[i+1:]
		}
		if strings.HasPrefix(t, "-") && t != "-" {
			switch t {
			case "-f", "-o", "--format", "--output":
				i++
				if i < len(rest) {
					i++
				}
				continue
			}
			i++
			continue
		}
		return rest[i:]
	}
	return nil
}

// stripSimpleWrapperArgs skips leading flag tokens then returns the command.
func stripSimpleWrapperArgs(rest []string) []string {
	i := 0
	for i < len(rest) {
		t := rest[i]
		if t == "--" {
			return rest[i+1:]
		}
		if strings.HasPrefix(t, "-") && t != "-" {
			i++
			continue
		}
		return rest[i:]
	}
	return nil
}

// hasCommandSubstitution reports unescaped $( or ` outside single quotes.
// Double-quoted regions still expand command substitutions, so they count.
func hasCommandSubstitution(cmd string) bool {
	inSingle, inDouble := false, false
	escaped := false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if escaped {
			escaped = false
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		// Backslash escape (outside single quotes).
		if c == '\\' {
			if inDouble {
				// In double quotes only $ ` " \ newline are escapable.
				if i+1 < len(cmd) {
					n := cmd[i+1]
					if n == '$' || n == '`' || n == '"' || n == '\\' || n == '\n' {
						escaped = true
						continue
					}
				}
				// Literal backslash otherwise.
				continue
			}
			escaped = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = true
			continue
		}
		if c == '"' {
			inDouble = !inDouble
			continue
		}
		if c == '`' {
			return true
		}
		if c == '$' && i+1 < len(cmd) && cmd[i+1] == '(' {
			return true
		}
		// Bash/zsh process substitution also executes a hidden command.
		if (c == '<' || c == '>') && i+1 < len(cmd) && cmd[i+1] == '(' {
			return true
		}
	}
	return false
}

func (p *ShellPolicy) matchDenyPatterns(s string) error {
	for _, re := range p.denyRes {
		if re.MatchString(s) {
			return fmt.Errorf("policy: command denied by deny_pattern %q", re.String())
		}
	}
	return nil
}

func (p *ShellPolicy) checkCommandName(cmdName string) error {
	if p.Mode != PolicyModeOff && strings.ContainsAny(cmdName, "$`*?[{") {
		return fmt.Errorf("policy cannot safely resolve dynamic command name %q", cmdName)
	}
	switch p.Mode {
	case PolicyModeAllowlist:
		if !p.allowSet[cmdName] {
			return fmt.Errorf("policy: command %q not in allowlist", cmdName)
		}
	case PolicyModeDenylist:
		if p.denySet[cmdName] {
			return fmt.Errorf("policy: command %q is denied", cmdName)
		}
		for _, prefix := range p.denyPrefixes {
			if strings.HasPrefix(cmdName, prefix) {
				return fmt.Errorf("policy: command %q is denied (built-in prefix %q)", cmdName, prefix)
			}
		}
	}
	return nil
}

// checkCommandArgs applies conservative subcommand rules to tools that mix
// harmless inspection with host mutation. It is denylist-only so an explicit
// allowlist retains its documented exact-command semantics.
func (p *ShellPolicy) checkCommandArgs(cmdName string, tokens []string) error {
	if p.Mode != PolicyModeDenylist {
		return nil
	}
	args := tokens[1:]
	deny := func(reason string) error {
		return fmt.Errorf("policy: command %q is denied (%s)", cmdName, reason)
	}
	containsAny := func(words ...string) bool {
		set := make(map[string]bool, len(words))
		for _, word := range words {
			set[word] = true
		}
		for _, arg := range args {
			if set[strings.ToLower(arg)] {
				return true
			}
		}
		return false
	}

	switch cmdName {
	case "ip":
		if containsAny("add", "del", "delete", "change", "replace", "append", "flush", "set", "exec") {
			return deny("network mutation")
		}
		for _, arg := range args {
			if arg == "-batch" || arg == "--batch" || arg == "-b" {
				return deny("network batch mutation")
			}
		}
	case "route":
		if containsAny("add", "del", "delete", "flush") {
			return deny("route mutation")
		}
	case "ifconfig":
		if containsAny("up", "down", "add", "del", "delete", "netmask", "broadcast", "pointopoint", "mtu", "hw", "promisc", "-promisc") {
			return deny("interface mutation")
		}
		// Read-only forms are: no args, display flags, or one interface name.
		if len(args) > 1 {
			return deny("interface mutation")
		}
		if len(args) == 1 && strings.HasPrefix(args[0], "-") && args[0] != "-a" && args[0] != "-s" && args[0] != "-v" {
			return deny("interface mutation")
		}
	case "iptables", "ip6tables", "ebtables", "arptables":
		for _, arg := range args {
			a := strings.ToUpper(arg)
			if strings.HasPrefix(a, "--APPEND") || strings.HasPrefix(a, "--INSERT") ||
				strings.HasPrefix(a, "--DELETE") || strings.HasPrefix(a, "--REPLACE") ||
				strings.HasPrefix(a, "--FLUSH") || strings.HasPrefix(a, "--ZERO") ||
				strings.HasPrefix(a, "--NEW-CHAIN") || strings.HasPrefix(a, "--DELETE-CHAIN") ||
				strings.HasPrefix(a, "--POLICY") || strings.HasPrefix(a, "--RENAME-CHAIN") {
				return deny("firewall mutation")
			}
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1 {
				for _, flag := range a[1:] {
					// A/I/D/R/F/Z/X/P/E mutate; -L/-n and other
					// inspection flags are intentionally allowed.
					if strings.ContainsRune("AIDRFZXPE", flag) {
						return deny("firewall mutation")
					}
				}
			}
		}
	case "nft":
		first := ""
		for _, arg := range args {
			lower := strings.ToLower(arg)
			if lower == "-i" || lower == "--interactive" || lower == "-f" || lower == "--file" || strings.HasPrefix(lower, "--file=") {
				return deny("firewall mutation")
			}
			if !strings.HasPrefix(arg, "-") {
				first = lower
				break
			}
		}
		if first == "" || (first != "list" && first != "monitor" && first != "describe") {
			return deny("firewall mutation")
		}
	case "systemctl", "loginctl":
		if containsAny("reboot", "poweroff", "halt", "kexec", "suspend", "hibernate", "hybrid-sleep", "suspend-then-hibernate") {
			return deny("host power-state change")
		}
		for _, arg := range args {
			lower := strings.ToLower(arg)
			if strings.Contains(lower, "reboot.target") || strings.Contains(lower, "poweroff.target") ||
				strings.Contains(lower, "halt.target") || strings.Contains(lower, "kexec.target") {
				return deny("host power-state target")
			}
		}
	case "sysctl":
		for _, arg := range args {
			if arg == "-w" || arg == "--write" || (!strings.HasPrefix(arg, "-") && strings.Contains(arg, "=")) {
				return deny("kernel parameter mutation")
			}
		}
	}
	return nil
}

// checkRM enforces rm path safety: no bare /, no system roots outside workdirs,
// unparseable expansions rejected.
func (p *ShellPolicy) checkRM(tokens []string, cwd string) error {
	// tokens[0] is rm (possibly with path prefix).
	paths, err := extractRMPaths(tokens)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		// `rm` with only flags — shell would error; treat as parse failure for safety.
		return fmt.Errorf("policy cannot safely parse rm targets: no path arguments")
	}

	for _, raw := range paths {
		if err := p.checkRMPath(raw, cwd); err != nil {
			return err
		}
	}
	return nil
}

func (p *ShellPolicy) checkRMPath(raw, cwd string) error {
	if raw == "" {
		return fmt.Errorf("policy cannot safely parse rm targets: empty path")
	}
	// Shell expansions / globs we cannot resolve safely → reject.
	if rmPathUnparseable(raw) {
		return fmt.Errorf("policy cannot safely parse rm targets: %q", raw)
	}

	abs, err := resolvePolicyPath(raw, cwd, p.workdirs)
	if err != nil {
		return fmt.Errorf("policy cannot safely parse rm targets: %w", err)
	}

	// Bare root and root globs.
	if abs == "/" || abs == "/*" || raw == "/" || raw == "/*" {
		return fmt.Errorf("policy: rm of root %q is denied", raw)
	}
	// Cleaned form of "/." etc.
	if filepath.Clean(abs) == "/" {
		return fmt.Errorf("policy: rm of root %q is denied", raw)
	}

	inWD := p.pathInWorkdir(abs)

	if inWD {
		if p.allowInWorkdir {
			return nil
		}
		return fmt.Errorf("policy: rm of %q denied (allow_in_workdir=false)", abs)
	}

	// Outside workdirs: refuse system-protected trees.
	if p.denySystemPaths && p.isSystemProtected(abs) {
		return fmt.Errorf("policy: rm of system path %q is denied", abs)
	}

	// Outside all workdirs (and not allowed by system-path exception) → deny.
	// Safety: agents should only delete inside sandboxed workspaces.
	return fmt.Errorf("policy: rm of %q is outside workdirs and denied", abs)
}

func (p *ShellPolicy) pathInWorkdir(abs string) bool {
	abs = filepath.Clean(abs)
	for _, wd := range p.workdirs {
		if wd == "" {
			continue
		}
		realWd := wd
		if rw, err := filepath.EvalSymlinks(wd); err == nil {
			realWd = rw
		}
		cleanWd := strings.TrimSuffix(filepath.Clean(realWd), string(filepath.Separator))
		if abs == cleanWd || strings.HasPrefix(abs, cleanWd+string(filepath.Separator)) {
			return true
		}
		// Also compare without eval (config may list non-existing path).
		cleanCfg := strings.TrimSuffix(filepath.Clean(wd), string(filepath.Separator))
		if abs == cleanCfg || strings.HasPrefix(abs, cleanCfg+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (p *ShellPolicy) isSystemProtected(abs string) bool {
	abs = filepath.Clean(abs)
	if abs == "/" {
		return true
	}
	for _, sp := range p.systemPaths {
		sp = strings.TrimSuffix(filepath.Clean(sp), string(filepath.Separator))
		if sp == "" || sp == "." {
			continue
		}
		if abs == sp || strings.HasPrefix(abs, sp+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// extractRMPaths returns non-flag operands of an rm invocation.
func extractRMPaths(tokens []string) ([]string, error) {
	if len(tokens) < 1 {
		return nil, fmt.Errorf("policy cannot safely parse rm targets")
	}
	var paths []string
	endOfFlags := false
	for i := 1; i < len(tokens); i++ {
		t := tokens[i]
		if !endOfFlags {
			if t == "--" {
				endOfFlags = true
				continue
			}
			if strings.HasPrefix(t, "-") && t != "-" {
				// Flag cluster (-r, -f, -rf, --force, --interactive=never, …).
				// Long options with required values are rare for rm; reject
				// ambiguous --opt=value already handled as single token.
				continue
			}
		}
		paths = append(paths, t)
	}
	return paths, nil
}

func rmPathUnparseable(p string) bool {
	// Variable / command substitution.
	if strings.ContainsAny(p, "$`") {
		return true
	}
	// Glob / brace that shell would expand (we cannot know final targets).
	if strings.ContainsAny(p, "*?[") {
		return true
	}
	if strings.Contains(p, "{") && strings.Contains(p, "}") {
		return true
	}
	return false
}

func resolvePolicyPath(raw, cwd string, workdirs []string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty path")
	}
	// Reject path-like tokens that are clearly not paths we can resolve.
	if strings.Contains(raw, "\x00") {
		return "", fmt.Errorf("NUL in path")
	}

	var target string
	if filepath.IsAbs(raw) {
		target = filepath.Clean(raw)
	} else {
		base := cwd
		if base == "" {
			if len(workdirs) > 0 {
				base = workdirs[0]
			} else {
				wd, err := os.Getwd()
				if err != nil {
					return "", err
				}
				base = wd
			}
		}
		if !filepath.IsAbs(base) {
			abs, err := filepath.Abs(base)
			if err != nil {
				return "", err
			}
			base = abs
		}
		target = filepath.Clean(filepath.Join(base, raw))
	}

	// Resolve existing symlink prefixes when possible (non-fatal on missing).
	if real, err := evalSymlinksPartial(target); err == nil {
		target = real
	}
	return target, nil
}

func commandBasename(tok string) string {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return ""
	}
	// Strip simple redirections glued to token (rare).
	return filepath.Base(tok)
}

// skipEnvAssignments drops leading FOO=bar tokens (shell variable assignments).
func skipEnvAssignments(tokens []string) []string {
	i := 0
	for i < len(tokens) {
		t := tokens[i]
		if isEnvAssignment(t) {
			i++
			continue
		}
		break
	}
	return tokens[i:]
}

func isEnvAssignment(t string) bool {
	eq := strings.IndexByte(t, '=')
	if eq <= 0 {
		return false
	}
	name := t[:eq]
	if name == "" {
		return false
	}
	for i, r := range name {
		if i == 0 && !unicode.IsLetter(r) && r != '_' {
			return false
		}
		if i > 0 && !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

// splitShellSegments splits a command line into simple commands on
// pipe, semicolon, &&, ||, and newlines — outside quotes.
func splitShellSegments(cmd string) []string {
	var segs []string
	var b strings.Builder
	inSingle, inDouble := false, false
	escaped := false

	flush := func() {
		s := strings.TrimSpace(b.String())
		b.Reset()
		if s != "" {
			segs = append(segs, s)
		}
	}

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if inSingle {
			b.WriteByte(c)
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if c == '\\' {
				b.WriteByte(c)
				escaped = true
				continue
			}
			b.WriteByte(c)
			if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\\':
			b.WriteByte(c)
			escaped = true
		case '\'':
			inSingle = true
			b.WriteByte(c)
		case '"':
			inDouble = true
			b.WriteByte(c)
		case '\n', '\r', ';':
			flush()
		case '|':
			// || or |
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				flush()
				i++
			} else {
				flush()
			}
		case '&':
			// && — single & (background) also ends segment for policy purposes
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				flush()
				i++
			} else if i > 0 && (cmd[i-1] == '>' || cmd[i-1] == '<') {
				// >& or <& is a file-descriptor redirection operator, not a
				// background ampersand. Keep it in the segment; tokenizeShell
				// already skips it (and its target) as a redirection.
				b.WriteByte(c)
			} else {
				flush()
			}
		case '(':
			// Subshell start — treat as segment boundary; content still scanned.
			flush()
		case ')':
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return segs
}

// tokenizeShell splits a simple command into tokens with basic quote handling.
func tokenizeShell(seg string) []string {
	var tokens []string
	var b strings.Builder
	inSingle, inDouble := false, false
	escaped := false

	flush := func() {
		if b.Len() == 0 {
			return
		}
		tokens = append(tokens, b.String())
		b.Reset()
	}

	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			} else {
				b.WriteByte(c)
			}
			continue
		}
		if inDouble {
			if c == '\\' {
				// Keep common escapes; otherwise keep backslash.
				if i+1 < len(seg) {
					n := seg[i+1]
					if n == '"' || n == '\\' || n == '$' || n == '`' || n == '\n' {
						i++
						if n != '\n' {
							b.WriteByte(n)
						}
						continue
					}
				}
				b.WriteByte(c)
				continue
			}
			if c == '"' {
				inDouble = false
				continue
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '\\':
			escaped = true
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case ' ', '\t':
			flush()
		case '<', '>':
			// Redirection: flush current token, skip op and optional digits already in token.
			flush()
			// Skip >> or >& or >|
			if i+1 < len(seg) && (seg[i+1] == '>' || seg[i+1] == '|' || seg[i+1] == '&') {
				i++
			}
			// Skip spaces then the redirect target token (not a command).
			j := i + 1
			for j < len(seg) && (seg[j] == ' ' || seg[j] == '\t') {
				j++
			}
			// Consume target without adding to tokens (policy only cares about command name / rm paths).
			// If target is needed for nothing, still skip it as one shell word.
			if j < len(seg) {
				// Re-parse one word into discard.
				discard, adv := readOneShellWord(seg[j:])
				_ = discard
				i = j + adv - 1
			} else {
				i = j - 1
			}
		default:
			b.WriteByte(c)
		}
	}
	if escaped {
		// Trailing backslash — keep literal.
	}
	flush()
	return tokens
}

// readOneShellWord reads one shell word from s; returns word and bytes consumed.
func readOneShellWord(s string) (string, int) {
	var b strings.Builder
	inSingle, inDouble := false, false
	escaped := false
	i := 0
	for i < len(s) {
		c := s[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			i++
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			} else {
				b.WriteByte(c)
			}
			i++
			continue
		}
		if inDouble {
			if c == '\\' && i+1 < len(s) {
				n := s[i+1]
				if n == '"' || n == '\\' || n == '$' || n == '`' {
					b.WriteByte(n)
					i += 2
					continue
				}
			}
			if c == '"' {
				inDouble = false
				i++
				continue
			}
			b.WriteByte(c)
			i++
			continue
		}
		if c == '\\' {
			escaped = true
			i++
			continue
		}
		if c == '\'' {
			inSingle = true
			i++
			continue
		}
		if c == '"' {
			inDouble = true
			i++
			continue
		}
		if c == ' ' || c == '\t' || c == '|' || c == '&' || c == ';' || c == '<' || c == '>' || c == '\n' {
			break
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), i
}
