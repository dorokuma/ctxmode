package main

// audit.go — execution audit trail for ctx_run (pure standard library).
//
// Every ctx_run entry point (execute, execute_file, batch, run_task) appends one
// JSON object per CALL of the tool — not per spawned subprocess — to a local
// JSONL file. A record carries metadata, the command text, and statistics.
// Captured stdout/stderr bodies are never written: they can be huge and are the
// most likely place for secrets. The file itself is plaintext — only the command
// text and the caller env key names pass through a redaction check (see the
// README for the residual risk).
//
// What this is NOT:
//   - Not a security boundary, and not tamper-proof. "append-only" describes how
//     the file is opened (O_APPEND) and nothing more: any process running as the
//     same user can truncate, rewrite, delete or forge lines. The 0700/0600
//     modes apply only when the directory and file are first created; an
//     existing file keeps whatever mode it already had.
//   - Not a permission model. Both tag rules only annotate records.
//   - Not a place that can be trusted to hold every ctx_run execution: a write
//     failure (bad CTXMODE_AUDIT_LOG, read-only state dir, full disk) is
//     rate-limit logged once per distinct path+reason and then swallowed, so a
//     misconfigured target degrades to "no audit trail" plus one log line rather
//     than failing tool calls. The one failure that COULD have taken the tools
//     down is the target itself: the path is Lstat-checked before the append
//     mutex is taken, and the open adds O_NONBLOCK plus a Stat re-check, so a
//     FIFO/symlink/device/directory target is refused instead of blocking every
//     later ctx_run call (all four entry points append through that same mutex).
//     Rotation to "<path>.1" at 32 MiB is best effort: a failed rename is logged
//     (once per reason) and the line is appended to the current file instead, so
//     rotation can neither drop a record nor stop later appends.
//   - Not an archival log. Only the current file and one rotated generation are
//     kept (~2x the cap); older generations are overwritten, not archived, and
//     there is no cross-process lock — several ctxmode processes sharing one path
//     can race the same rotation.
//   - Not redaction-free. The command text goes through the same sensitive
//     content check used for indexing and, on a hit, is replaced by a length +
//     digest marker; caller env KEY NAMES get the same check. Residual risk
//     (unformatted secrets, credential-shaped names outside the pattern set,
//     stdout-derived metadata) is documented in README.
//
// Injection points use a deferred emit, so every exit path is covered exactly
// once: calls rejected before validation, spawn failures, jobs killed by the
// timeout/reaper, background starts, and large output that was auto-indexed
// instead of returned.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	// auditDefaultPath is where records land unless CTXMODE_AUDIT_LOG overrides
	// it. State, not cache: ~/.cache is evictable, audit lines are not. The
	// default is root-specific by design; a non-root deployment must set
	// CTXMODE_AUDIT_LOG (the failure to create it is logged, once).
	auditDefaultPath = "/root/.local/state/ctxmode/audit.jsonl"

	// Environment overrides / inputs, all read from the server process env.
	auditEnvLogPath  = "CTXMODE_AUDIT_LOG"
	auditEnvRole     = "CTXMODE_ROLE"
	auditEnvReadonly = "CTXMODE_READONLY"

	// auditRawCmdCap bounds the recorded command text. argv is not path
	// validated and an over-length argv is warn-only, so without a cap a single
	// call could append a multi-megabyte JSONL line. The cap applies to the
	// final string, marker included.
	auditRawCmdCap = maxShellCommandBytes
	auditRawCmdCut = "…(truncated)"

	// auditMaxEnvKeys bounds how many caller env key names are recorded.
	auditMaxEnvKeys = 64

	// auditRedactedKey replaces an env key name that matched the
	// sensitive-content check (see auditEnvKeys).
	auditRedactedKey = "[redacted]"

	// auditExitNotRun marks a call with no exit status of its own: a call that
	// never spawned a process (rejected argv, setup failure) and a background
	// call, which only starts a job. It shares the value reported for a killed
	// process because ctxmode already uses -1 for "no usable exit status";
	// `error`, `background_id` and `background` distinguish the cases.
	auditExitNotRun = -1

	// Audit tags. Recorded, never enforced.
	//
	// readonly_role_call depends on CTXMODE_ROLE / CTXMODE_READONLY being set by
	// the dispatch layer that starts the agent session; until that layer sets
	// them, the tag (and the role/caller_readonly fields) are simply absent.
	auditTagReadonlyRoleCall = "readonly_role_call"
	auditTagEvalInterpreter  = "eval_interpreter"
)

// auditRotateBytes caps one audit file. On reaching it, the file is renamed to
// "<path>.1" (replacing the previous generation) and a fresh file starts, so a
// long-lived server cannot grow one file without bound. Package var so tests can
// shrink it.
var auditRotateBytes int64 = 32 << 20

// auditRecord is one JSONL line. The schema is fixed — every field is present on
// every line (empty string, 0, false, [] when not applicable) — so a consumer
// can rely on the same key set instead of treating a missing key as a third
// state. It is NOT a claim about severity: values are truncated where documented
// and the command text is redacted on a sensitive-content hit.
type auditRecord struct {
	Timestamp        string               `json:"timestamp"`
	PID              int                  `json:"pid"`
	SessionID        string               `json:"session_id"`
	Action           string               `json:"action"`
	Role             string               `json:"role"`
	CallerReadonly   bool                 `json:"caller_readonly"`
	CommandType      string               `json:"command_type"`
	RawCmd           string               `json:"raw_cmd"`
	ResolvedExe      string               `json:"resolved_exe"`
	CWD              string               `json:"cwd"`
	Background       bool                 `json:"background"`
	BackgroundID     string               `json:"background_id"`
	DurationMs       int64                `json:"duration_ms"`
	ExitCode         int                  `json:"exit_code"`
	Error            string               `json:"error"`
	ScreenVerdict    string               `json:"screen_verdict"`
	ScreenRule       string               `json:"screen_rule"`
	AuditTags        []string             `json:"audit_tags"`
	EnvKeys          []string             `json:"env_keys"`
	StdinLen         int                  `json:"stdin_len"`
	Indexed          bool                 `json:"indexed"`
	IndexLabel       string               `json:"index_label"`
	Commands         []auditCommandResult `json:"commands"`
	FirstFailedLabel string               `json:"first_failed_label"`
	OutputLen        int                  `json:"output_len"`
	Truncated        bool                 `json:"truncated"`
}

// auditCommandResult is one batch command's outcome inside the audit line. The
// array exists so a batch line can be parsed mechanically: the first version
// folded N results into the call-level exit_code and a comma-joined label list,
// which neither survives a label containing a comma nor lets a reader tell which
// command failed. The screen verdict/rule are repeated per command so a specific
// idiom rule is still visible when the call-level summary reports the worst
// verdict of the batch.
//
// label and index_label are recorded verbatim, NOT through capAuditText: a
// label is the caller's own short key that also names real index entries (the
// index_label here is the label the KB actually stored), so truncating it would
// desync the record from the store. The 64 KiB cap bounds raw_cmd only; a batch
// line is otherwise bounded by the 50-command limit plus whatever request size
// the MCP layer accepts (known gap, see .agents/notes/20260930-audit-review-fixes.md).
type auditCommandResult struct {
	Label         string `json:"label"`
	ExitCode      int    `json:"exit_code"`
	ScreenVerdict string `json:"screen_verdict"`
	ScreenRule    string `json:"screen_rule"`
	Indexed       bool   `json:"indexed"`
	IndexLabel    string `json:"index_label"`
}

// auditCall is the mutable state of one audited call. Create it at handler
// entry, fill in what each path learns, and `defer c.emit()` immediately so the
// record survives every return branch.
type auditCall struct {
	start time.Time
	rec   auditRecord
}

// startAudit creates the record for one call. action is the ctx_run action
// (execute/execute_file/batch/run_task) and commandType is one of
// argv/command/file/task; rawCmd is the caller's command as received (empty is
// allowed when the handler only learns it later).
func (s *server) startAudit(action, commandType, rawCmd string) *auditCall {
	now := time.Now()
	role := os.Getenv(auditEnvRole)
	readonly := auditReadonlyEnv()
	c := &auditCall{
		start: now,
		rec: auditRecord{
			Timestamp:      now.UTC().Format(time.RFC3339Nano),
			PID:            os.Getpid(),
			Action:         action,
			Role:           role,
			CallerReadonly: readonly,
			CommandType:    commandType,
			RawCmd:         auditCommandText(rawCmd),
			EnvKeys:        []string{},
			Commands:       []auditCommandResult{},
			ExitCode:       auditExitNotRun,
		},
	}
	if s != nil {
		c.rec.SessionID = s.sessionID
	}
	// Rule (i): a read-only role or an explicit read-only caller is tagged.
	// Recorded only — nothing enforces a read-only role.
	if readonly || auditRoleIsReadonly(role) {
		c.rec.AuditTags = append(c.rec.AuditTags, auditTagReadonlyRoleCall)
	}
	return c
}

// setCommand overwrites the recorded command text and working directory (both
// are only known after cwd resolution / argv construction in some handlers).
func (c *auditCall) setCommand(rawCmd, cwd string) {
	c.rec.RawCmd = auditCommandText(rawCmd)
	c.rec.CWD = cwd
}

// setInputs records the caller's env KEY NAMES (never values) and the stdin
// payload length (never the payload).
func (c *auditCall) setInputs(env map[string]string, stdinLen int) {
	c.rec.EnvKeys = auditEnvKeys(env)
	c.rec.StdinLen = stdinLen
}

// setArgv records argv[0] resolved to a real absolute path (bare names go
// through exec.LookPath) and applies rule (ii). cwd is used to resolve a
// relative path the same way the executor will.
func (c *auditCall) setArgv(argv []string, cwd string) {
	if len(argv) == 0 {
		return
	}
	c.rec.ResolvedExe = resolveAuditExe(argv[0], cwd)
	if auditEvalInterpreter(c.rec.ResolvedExe, argv) {
		c.rec.AuditTags = append(c.rec.AuditTags, auditTagEvalInterpreter)
	}
}

// setInterpreter records the interpreter of a non-argv execution path (/bin/sh
// for the command form, the language runtime for execute_file).
func (c *auditCall) setInterpreter(name string) {
	c.rec.ResolvedExe = resolveAuditExe(name, "")
}

// setScreen records the graded screen outcome applied to this call. verdict is
// "ok", "warn" or "block"; a call that was never screened keeps "".
func (c *auditCall) setScreen(verdict shellVerdict, rule string) {
	c.rec.ScreenVerdict = verdict.String()
	c.rec.ScreenRule = rule
}

// setResult folds a finished execution in. result may be nil when no process was
// ever spawned. Index state is only ever added, never cleared: run_task learns
// its index label after the result exists (see setIndex).
func (c *auditCall) setResult(result *executeResult) {
	if result == nil {
		return
	}
	c.rec.ExitCode = result.ExitCode
	c.rec.Truncated = result.Truncated
	c.rec.OutputLen = len(result.Stdout) + len(result.Stderr)
	if result.BackgroundID != "" {
		c.rec.BackgroundID = result.BackgroundID
	}
	if c.rec.Background {
		// A background call only starts a job: there is no exit status to report
		// yet, so the line must not read as "exit_code 0 = success". output_len
		// for such a line is the length of the start message, not of job output.
		c.rec.ExitCode = auditExitNotRun
	}
	if result.Indexed {
		c.rec.Indexed = true
		c.rec.IndexLabel = result.IndexLabel
	}
}

// setIndex records an auto-indexed output whose label the handler learned
// out-of-band (finishRunTaskOutput builds its own label internally). It is
// nil-safe because finishRunTaskOutput is also callable without an audit call.
func (c *auditCall) setIndex(label string) {
	if c == nil || label == "" {
		return
	}
	c.rec.Indexed = true
	c.rec.IndexLabel = label
}

// setAggregate records a multi-command call (batch). Per-command outcomes go
// into Commands; the call-level fields are: exitCode 0 only when every command
// succeeded and otherwise the first failing code (including -1 from a blocked or
// skipped command — a failure is never folded into 0), outputLen summed over all
// commands, truncated when any command hit the output cap, and the label of the
// first failing command. Batch leaves the call-level IndexLabel empty on
// purpose: per-command labels live in Commands, where a comma inside a label
// cannot be confused with a separator.
func (c *auditCall) setAggregate(exitCode, outputLen int, truncated bool, commands []auditCommandResult) {
	c.rec.ExitCode = exitCode
	c.rec.OutputLen = outputLen
	c.rec.Truncated = truncated
	c.rec.Commands = commands
	for _, r := range commands {
		if r.Indexed {
			c.rec.Indexed = true
		}
		if r.ExitCode != 0 && c.rec.FirstFailedLabel == "" {
			c.rec.FirstFailedLabel = r.Label
		}
	}
}

// setError records the caller-visible error, if any.
func (c *auditCall) setError(err error) {
	if err != nil {
		c.rec.Error = err.Error()
	}
}

// emit writes the record as a single JSONL line. It is meant to be deferred.
// A failure is logged at most once per distinct path+reason: a broken target
// produces one identical failure per tool call, and flooding the server log
// instead of the audit file helps nobody.
func (c *auditCall) emit() {
	if c == nil {
		return
	}
	c.rec.DurationMs = time.Since(c.start).Milliseconds()
	if c.rec.AuditTags == nil {
		c.rec.AuditTags = []string{}
	}
	if c.rec.EnvKeys == nil {
		c.rec.EnvKeys = []string{}
	}
	if c.rec.Commands == nil {
		c.rec.Commands = []auditCommandResult{}
	}
	line, err := json.Marshal(&c.rec)
	if err != nil {
		logAuditFailure(auditLogPath(), fmt.Errorf("encode record: %w", err))
		return
	}
	line = append(line, '\n')
	if err := appendAuditLine(line); err != nil {
		logAuditFailure(auditLogPath(), err)
	}
}

// auditMu serializes appends process-wide: batch runs commands concurrently, so
// without it two records could interleave inside one write. Each line is fully
// built before the lock is taken and written with a single Write. The only
// target check done while holding it is openAuditFile's own O_NONBLOCK + Stat
// re-check, which cannot block on a FIFO (see auditTargetOK).
var auditMu sync.Mutex

// appendAuditLine appends one complete line to the audit log, creating the
// parent directory (0700) and the file (0600) as needed and rotating the file to
// "<path>.1" once it reaches auditRotateBytes.
func appendAuditLine(line []byte) error {
	path := auditLogPath()
	// Validate the target BEFORE the lock. Opening a FIFO for writing blocks
	// until a reader appears, and OpenFile under auditMu would queue every later
	// ctx_run call behind it — the whole tool surface, not just this line.
	if err := auditTargetOK(path); err != nil {
		return err
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := openAuditFile(path)
	if err != nil {
		return err
	}
	// Rotation is best effort, and it is attempted BEFORE the write so the new
	// generation starts clean. Losing the line is the real loss, so a failed
	// rename must not turn into a dropped record or into a permanently failing
	// append: the old generation is renamed while its descriptor is still open
	// (POSIX allows that), and when the rename fails the SAME open descriptor is
	// kept and this line is appended to the current file. The next call will try
	// again (the file is still over the cap), report the same failure at most
	// once more, and still write its line. The same reasoning covers the second
	// half: if the renamed generation is gone but the fresh file cannot be
	// opened, the line is written to the generation just rotated away instead of
	// being dropped — no path through this block loses a record.
	if st, serr := f.Stat(); serr == nil && auditRotateBytes > 0 && st.Size() >= auditRotateBytes {
		switch rerr := os.Rename(path, path+".1"); {
		case rerr != nil:
			logAuditFailure(path+".1", fmt.Errorf("rotate (keeping the current file): %w", rerr))
		default:
			nf, nerr := openAuditFile(path)
			if nerr != nil {
				// The rotation succeeded but the replacement could not be opened.
				// Keep the record: this line lands in the generation that was just
				// renamed to "<path>.1".
				logAuditFailure(path, fmt.Errorf("reopen after rotation (record goes to %s.1): %w", path, nerr))
				break
			}
			f.Close()
			f = nf
		}
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

// openAuditFile opens the audit file for appending. O_NONBLOCK is a safety net
// for the Lstat/OpenFile race: if the path is swapped for a FIFO in between,
// opening it without a reader fails immediately (ENXIO) instead of blocking
// while auditMu is held. It is a no-op for regular files. The opened descriptor
// is re-checked, because O_NONBLOCK only protects the open, not the write.
func openAuditFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("audit target %q is not a regular file (%s)", path, st.Mode().Type())
	}
	return f, nil
}

// auditTargetOK rejects an audit target that is not (or will not be) a regular
// file it created: a symlink silently redirects the trail elsewhere, and a
// FIFO/device/directory either blocks the open or cannot take the append. A
// missing path is fine — it is created below with the documented modes.
//
// Scope of the check, stated explicitly because it is easy to overread:
//   - Only the LAST path component is inspected (Lstat, no path resolution). A
//     symlinked PARENT directory (e.g. /var/log -> /mnt/log) still redirects the
//     trail silently and is not detected.
//   - A hardlink is indistinguishable from a regular file here: a target that is
//     a hardlink to another file is accepted (the modes and the trail follow the
//     other name).
//   - A regular file that another process also writes to (or that is a symlink
//     at neither end but is bind-mounted) is accepted.
//
// In short: this verifies "a dedicated regular file", not "the file I created".
// Rejecting all of the above would need openat2/RESOLVE_NO_SYMLINKS or an
// inode-identity check, which is out of scope for a record-only trail.
func auditTargetOK(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("audit target %q is a symlink (refusing to follow it)", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("audit target %q is not a regular file (%s)", path, fi.Mode().Type())
	}
	return nil
}

// auditFailureMu guards auditFailedKeys; auditFailedKeys bounds how much memory
// the failure log suppression may use.
var (
	auditFailureMu   sync.Mutex
	auditFailedKeys  = map[string]bool{}
	auditFailureHint = " (set CTXMODE_AUDIT_LOG to a writable path)"
)

// logAuditFailure logs an audit write failure once per distinct path+reason.
// Repeats are suppressed so a misconfigured target does not flood the server
// log on every tool call; the suppression map is bounded and recycled, so a
// pathological stream of distinct failures still cannot grow memory.
func logAuditFailure(path string, err error) {
	key := path + "\x00" + err.Error()
	auditFailureMu.Lock()
	if len(auditFailedKeys) >= 64 {
		auditFailedKeys = map[string]bool{}
	}
	seen := auditFailedKeys[key]
	auditFailedKeys[key] = true
	auditFailureMu.Unlock()
	if seen {
		return
	}
	hint := ""
	if path == auditDefaultPath {
		// The default target is root-specific: say so instead of leaving a
		// non-root deployment silently unaudited.
		hint = auditFailureHint
	}
	log.Printf("ctxmode: audit: cannot append to %q: %v%s (further identical failures are not logged)", path, err, hint)
}

// auditLogPath resolves the log target on every write so an override set at
// runtime (tests) takes effect without restarting the server.
func auditLogPath() string {
	if p := os.Getenv(auditEnvLogPath); p != "" {
		return p
	}
	return auditDefaultPath
}

// auditCommandText prepares the caller's command text for the record: first the
// sensitive-content check (a hit replaces the text entirely), then the length
// cap. Running the check on the full text matters — a credential past the cap
// would otherwise be recorded verbatim.
func auditCommandText(raw string) string {
	if raw == "" {
		return ""
	}
	if err := checkSensitiveContent(raw); err != nil {
		sum := sha256.Sum256([]byte(raw))
		return fmt.Sprintf("[redacted: %v; len=%d sha256=%x]", err, len(raw), sum[:8])
	}
	return capAuditText(raw)
}

// auditEnvKeys returns the caller-supplied env KEY NAMES (never values), sorted
// for a stable line and capped so a pathological request cannot inflate the
// record. A key name can itself be credential-shaped (`{"sk-live-…": ""}`), so
// each name goes through the same sensitive-content check as the command text
// and is replaced by a marker on a hit. Values are never inspected or recorded.
func auditEnvKeys(env map[string]string) []string {
	if len(env) == 0 {
		return []string{}
	}
	uniq := make(map[string]bool, len(env))
	for k := range env {
		if checkSensitiveContent(k) != nil {
			// A credential-shaped name (`AKIA…`, `ghp_…`, a JWT) is replaced by a
			// marker; several such names collapse to one marker rather than
			// filling the list with duplicates.
			uniq[auditRedactedKey] = true
			continue
		}
		uniq[k] = true
	}
	keys := make([]string, 0, len(uniq))
	for k := range uniq {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > auditMaxEnvKeys {
		keys = append(keys[:auditMaxEnvKeys], "…")
	}
	return keys
}

// capAuditText bounds one recorded command string to auditRawCmdCap BYTES in
// total (marker included), cutting on a rune boundary so the JSON stays valid
// UTF-8.
func capAuditText(s string) string {
	if len(s) <= auditRawCmdCap {
		return s
	}
	cut := s[:auditRawCmdCap-len(auditRawCmdCut)]
	for len(cut) > 0 {
		r, size := utf8.DecodeLastRuneInString(cut)
		if r != utf8.RuneError || size > 1 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut + auditRawCmdCut
}

// auditExeCache memoizes successful LookPath results: the executable behind a
// bare name does not change during a process lifetime and audit writes must stay
// cheap. Failures are NOT cached (a tool installed later in the session would
// otherwise stay unknown for the process's lifetime), and the cache is bounded
// so a caller cannot grow it without limit by naming many missing binaries.
var (
	auditExeMu    sync.Mutex
	auditExeCache = map[string]string{}
)

const auditExeCacheMax = 256

// resolveAuditExe turns argv[0] into the path that will really be executed, for
// attribution only. It is NOT the executor's normalization: main.go
// resolveArgvExe deliberately leaves bare names alone (exec.LookPath resolves
// them at spawn time), while this one performs that lookup so the record names
// the real binary. The two agree on what counts as a path because both call
// looksLikePath — a name is only treated as a PATH lookup when looksLikePath is
// false, so dotted names (".hidden", "..x"), backslash names and separators all
// resolve to the same path the executor will use. The only residual difference
// is the degenerate empty-cwd case: the executor falls back to the primary
// workdir, this falls back to the process working directory (no current caller
// can reach it — execute and run_task both pass their resolved workdir).
func resolveAuditExe(name, cwd string) string {
	if name == "" {
		return ""
	}
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	if looksLikePath(name) {
		if cwd == "" {
			if abs, err := filepath.Abs(name); err == nil {
				return abs
			}
			return filepath.Clean(name)
		}
		return filepath.Clean(filepath.Join(cwd, name))
	}
	auditExeMu.Lock()
	cached, ok := auditExeCache[name]
	auditExeMu.Unlock()
	if ok {
		return cached
	}
	resolved, err := exec.LookPath(name)
	if err != nil {
		// Not on PATH: keep the bare name rather than inventing a path.
		return name
	}
	auditExeMu.Lock()
	if len(auditExeCache) >= auditExeCacheMax {
		auditExeCache = map[string]string{}
	}
	auditExeCache[name] = resolved
	auditExeMu.Unlock()
	return resolved
}

// readonlyAuditRoles are the collaboration roles that must not mutate the
// machine (rule (i)).
var readonlyAuditRoles = map[string]bool{
	"scout":      true,
	"planner":    true,
	"researcher": true,
	"reviewer":   true,
	"oracle":     true,
}

// auditRoleIsReadonly reports whether CTXMODE_ROLE names a read-only role.
func auditRoleIsReadonly(role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	return role != "" && readonlyAuditRoles[role]
}

// auditReadonlyEnv reports CTXMODE_READONLY. "1" is the documented spelling;
// "true" is accepted because it is the other common way to say it.
func auditReadonlyEnv() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(auditEnvReadonly)))
	return v == "1" || v == "true"
}

// ---------------------------------------------------------------------------
// rule (ii): eval_interpreter
//
// This is a SPELLING TABLE over an interpreter's own options, not a parse of
// the command line. It answers "does this argv contain an explicit inline-code
// spelling for an interpreter" — `sh -c`, `node -e`, `php -r`, `Rscript -e`,
// `env FOO=1 sh -c` — and nothing more. It is a record-only annotation: the tag
// never blocks, delays or modifies a call, and it is not a detector with a
// coverage guarantee. Known limits are listed in README.
// ---------------------------------------------------------------------------

// evalInterpreterKind describes one interpreter family's inline-code spellings.
type evalInterpreterKind struct {
	// shortInline is the set of single-letter short options that carry inline
	// code (e.g. -c for POSIX shells, -e for node/perl/ruby). A bundled spelling
	// (-lc, -ec, -pe) counts when any of its letters is in this set.
	shortInline map[byte]bool
	// longInline is the set of long options that carry inline code; a
	// "--opt=value" spelling matches its "--opt" key.
	longInline map[string]bool
	// stdinInteractive marks interpreters where a LEADING -i means "read the
	// program from stdin".
	stdinInteractive bool
}

// evalInterpreterKinds is keyed by executable file name. Deliberately narrow:
// flags that are not inline code in that interpreter are absent, which is why
// shell `-e` (errexit) and node `--help` (the letter p/e inside a long option)
// are not tagged.
var evalInterpreterKinds = map[string]evalInterpreterKind{
	"sh":      {shortInline: map[byte]bool{'c': true}, stdinInteractive: true},
	"bash":    {shortInline: map[byte]bool{'c': true}, stdinInteractive: true},
	"dash":    {shortInline: map[byte]bool{'c': true}, stdinInteractive: true},
	"zsh":     {shortInline: map[byte]bool{'c': true}, stdinInteractive: true},
	"ksh":     {shortInline: map[byte]bool{'c': true}, stdinInteractive: true},
	"python":  {shortInline: map[byte]bool{'c': true}, stdinInteractive: true},
	"node":    {shortInline: map[byte]bool{'e': true, 'p': true}, longInline: map[string]bool{"--eval": true, "--print": true}},
	"nodejs":  {shortInline: map[byte]bool{'e': true, 'p': true}, longInline: map[string]bool{"--eval": true, "--print": true}},
	"perl":    {shortInline: map[byte]bool{'e': true, 'E': true}, stdinInteractive: true},
	"ruby":    {shortInline: map[byte]bool{'e': true}, stdinInteractive: true},
	"php":     {shortInline: map[byte]bool{'r': true}},
	"Rscript": {shortInline: map[byte]bool{'e': true}},
}

// evalWrappers are commands whose own options and NAME=value assignments precede
// the real command, so `env FOO=1 sh -c '…'` still has to be graded. Peeling
// them also stops `env -i cmd` from looking like an interactive interpreter.
var evalWrappers = map[string]bool{"env": true, "busybox": true}

// evalUnwrapDepth bounds wrapper peeling so `env env env …` cannot loop.
const evalUnwrapDepth = 4

// evalKindFor resolves an executable file name to its interpreter family,
// including the python3/python3.12 prefix rule.
func evalKindFor(base string) (evalInterpreterKind, bool) {
	if k, ok := evalInterpreterKinds[base]; ok {
		return k, true
	}
	if strings.HasPrefix(base, "python") {
		return evalInterpreterKinds["python"], true
	}
	return evalInterpreterKind{}, false
}

// skipWrapperArgs returns the index of the wrapped command within rest, skipping
// the wrapper's own options and NAME=value assignments.
func skipWrapperArgs(rest []string) int {
	i := 0
	for i < len(rest) {
		a := rest[i]
		switch {
		case a == "--ignore-environment" || a == "--null" || a == "-i" || a == "-0":
			i++
		case a == "--unset" || a == "-u" || a == "--chdir" || a == "-C":
			i += 2
		case a != "-" && !strings.HasPrefix(a, "-") && strings.ContainsRune(a, '='):
			i++
		default:
			return i
		}
	}
	return i
}

// unwrapEvalCommand peels env/busybox wrappers and returns the command left to
// grade (nil when the wrappers consumed every argument).
func unwrapEvalCommand(argv []string) []string {
	cur := argv
	for depth := 0; depth < evalUnwrapDepth; depth++ {
		if len(cur) == 0 || !evalWrappers[filepath.Base(cur[0])] {
			return cur
		}
		idx := skipWrapperArgs(cur[1:])
		if idx >= len(cur)-1 {
			return nil
		}
		cur = cur[1+idx:]
	}
	return cur
}

// auditEvalInterpreter implements rule (ii): the executable's file name (or the
// name of the command an env/busybox wrapper hands over to) belongs to an
// interpreter family AND the arguments contain an explicit inline-code spelling
// for it. Record-only.
func auditEvalInterpreter(resolvedExe string, argv []string) bool {
	inner := unwrapEvalCommand(argv)
	if len(inner) == 0 {
		return false
	}
	kind, ok := evalKindFor(filepath.Base(inner[0]))
	if !ok {
		// The invoked name is not a known interpreter (e.g. a Python venv shim
		// called "py"): fall back to the name LookPath actually resolved.
		if kind, ok = evalKindFor(filepath.Base(resolvedExe)); !ok {
			return false
		}
	}
	args := inner[1:]
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			name := a
			if j := strings.IndexByte(a, '='); j > 0 {
				name = a[:j]
			}
			if kind.longInline[name] {
				return true
			}
			continue
		}
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		letters := a[1:]
		for i := 0; i < len(letters); i++ {
			if kind.shortInline[letters[i]] {
				return true
			}
		}
	}
	// -i only counts as "read the program from stdin" when it is the first
	// argument and the interpreter is not in module mode: `python3 -m pip
	// install -i URL` must not be tagged.
	if kind.stdinInteractive && len(args) > 0 && args[0] == "-i" {
		for _, a := range args {
			if a == "-m" {
				return false
			}
		}
		return true
	}
	return false
}
