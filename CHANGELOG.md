# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

## [4.2.0] - 2026-10-03

### Changed
- **Deployment is run by the agent, not by hand.** The build/deploy rule no longer describes `./deploy.sh` as a manual, human-only step: the agent runs `./deploy.sh` directly (build → `initialize` verification → atomic replacement of the live binary), with no hand-off, confirmation or approval in between. `README.md`'s Deployment section states the same for readers of the repository; the local, gitignored `AGENTS.md` carries the matching wording. Nothing else about the build/deploy rule changed.
- **`ctx_run`: argv is no longer path-fenced** (`main.go` `validateArgv`, new `resolveArgvExe`/`looksLikePath`). The old branch rejected any `argv[0]` that was not a bare name or a path inside a workdir (`lexicallyInside` + `ensureInsideWorkspaces`). Only an empty `argv`/`argv[0]` is rejected now; otherwise `argv[0]` is normalized: an absolute path is `filepath.Clean`ed and kept, a relative path is joined onto the resolved `cwd` and cleaned, a bare name is passed through verbatim for `exec.LookPath` at spawn time. Absolute paths and bare names now mean the same thing — anything the server user can execute — which the security model already documented; the argv fence was the last place implying otherwise. The `ctx_fs`/`ctx_git` workspace fences (`resolvePath`, `ensureInsideWorkspaces`) and the `cwd` fence are untouched and still apply to `path`/`pathspec`; `run_task`'s `custom` kind inherits the same normalization.
- **argv mode now goes through the pre-execution screen** (`shell_screen.go`, new `screenArgv`, wired into the argv branch of `toolExecute`). The rules differ from the shell-string case because argv never reaches a shell: a NUL byte in any argument is a hard block (`argv command blocked (nul_byte)` — `execve` rejects such an argument with EINVAL, so the spawn could never succeed and the old behaviour was a confusing start failure), an argv whose joined bytes exceed 64 KiB is **warn-only** (never blocked: large build/codegen arguments are legitimate and are exactly what the argv path exists for), and the three `shellWarnPatterns` are matched against the space-joined argv so shapes like `sh -c 'curl … | sh'` are still logged. A warn hit calls `logShellScreen` and its rule name goes into the audit record.
- **Documentation states the new argv contract**: the `instructions.go` usage policy and `README.md` (the `execute` and `run_task` entries plus new security-model bullets) no longer claim argv is "path-validated"; they document that argv skips the shell entirely (no shell string, therefore no injection surface), that it is not path-fenced, and that the argv screen blocks only a NUL byte and warns on an over-length argv.
- **Tests**: `TestValidateArgv` now asserts an absolute path outside every workspace is allowed and preserved (and that `../` traversal is resolved rather than rejected); `shell_screen_test.go` gains `TestScreenArgv` (NUL block, oversize warn, idiom warn, at-cap must-pass) plus the `toolExecute` wiring check; new `audit_test.go` covers the full field set for a successful argv call, the bare-name `exec.LookPath` resolution, both tag rules, the argv NUL block record, and the batch/`run_task` injection points. Its `TestMain` points `CTXMODE_AUDIT_LOG` at a throwaway temp file for the whole test binary so test runs cannot append noise to the real audit log.

### Added
- **Execution audit log** (`audit.go`, new; pure stdlib). One JSON line per `ctx_run` call, from all four entry points (`toolExecute`, `toolExecuteFile`, `toolBatchExecute`, `toolRunTask`), written from a `defer` so early validation errors, spawn failures, timeout/reaper kills, background starts and large output that was auto-indexed instead of returned are each recorded exactly once and never decoupled from the call. Records calls (`ctx_fs`/`ctx_git`/`ctx_kb`/`ctx_bg` are not audited) and never subprocesses. Target is `CTXMODE_AUDIT_LOG`, default `/root/.local/state/ctxmode/audit.jsonl` (state, not `~/.cache`); the parent directory and the file are created `0700`/`0600` **on first create only** (an existing file keeps its mode), opened `O_CREATE|O_APPEND|O_WRONLY`, each complete line appended under one process-wide mutex so concurrent batch commands cannot interleave bytes, with the directory created on demand and the file rotated to `<path>.1` at 32 MiB. Fields: `timestamp`, `pid`, `session_id`, `action`, `role` (`CTXMODE_ROLE`), `caller_readonly` (`CTXMODE_READONLY`), `command_type` (`argv`/`command`/`file`/`task`), `raw_cmd` (capped at 64 KiB with a `…(truncated)` marker, cut on a rune boundary, and replaced by a `[redacted: … len=… sha256=…]` marker when the sensitive-content check hits), `resolved_exe` (bare names resolved through `exec.LookPath`, `/bin/sh` for the command form, the runtime binary for `execute_file`), `cwd`, `background`, `background_id`, `duration_ms`, `exit_code`, `error`, `screen_verdict`/`screen_rule`, `audit_tags`, `env_keys` (caller env **key names** only), `stdin_len` (a byte count, never the payload), `indexed`/`index_label`, `commands`, `first_failed_label`, `output_len`, `truncated`. The schema is fixed — every key appears on every line (empty string / 0 / false / `[]` when not applicable) so consumers never have to treat a missing key as a third state — and **stdout/stderr bodies are never recorded**: they can be huge and are the likeliest place for secrets. The file itself is plaintext and not secret-free: `raw_cmd` is the caller's command text (or `execute_file`'s path/language/`code`) and unformatted secrets outside the patterns can still be recorded. `batch` has no single exit status, so its line carries both the per-command `commands` array (`label`, `exit_code`, `screen_verdict`/`screen_rule`, `indexed`/`index_label`) and an aggregate (0 only when every command succeeded, otherwise the first failing code; summed output size; whether any command truncated; `first_failed_label`). The target is validated (`Lstat` + `O_NONBLOCK`, before the append mutex) so a symlink/FIFO/device/directory target is refused with one log line instead of stalling the tool surface; a write failure is logged and ignored — the audit is a record, never a policy, and must not turn the execution tools off.
- **Two record-only audit tags.** `readonly_role_call` when `CTXMODE_ROLE` ∈ {`scout`,`planner`,`researcher`,`reviewer`,`oracle`} or `CTXMODE_READONLY=1` (both set by the dispatch layer, so the tag is absent until that layer sets them); `eval_interpreter` when the invoked file name (`argv[0]`, after `exec.LookPath`, or the command an `env`/`busybox` wrapper hands over to) belongs to an interpreter family (`sh`/`bash`/`dash`/`zsh`/`ksh`/`env`/`busybox`/`node`/`nodejs`/`perl`/`ruby`/`php`/`Rscript` or `python*`) and a later argument contains an explicit inline-code spelling for it (`-c`/`-e`/`-p`/`-r` including bundled short options such as `-lc`/`-ec`/`-pe`, `--eval=…`/`--print`, `php -r`, `Rscript -e`, or a leading `-i` where that means "read the program from stdin"). It is a **spelling check over argv, not a detector**: known false positives (`bash -e file.sh`, `env -i cmd`) and the absence of any coverage guarantee are documented in `README.md`. Neither tag blocks, delays or modifies an execution, and neither is a permission model.

### Fixed
- **The commit gate's arrow-adjacent residual shapes are recorded, not fixed** (global `/root/.git-hooks/{commit-msg,pre-push}` — shared tooling in the image; documentation only, no behaviour change). A second verification pass measured four more narrow bypass spellings for the assignment rule: `password -> v12345`, `password =>> v12345`, `password = > v12345` and `password => => v12345` all pass, because once the separator is consumed the value side still begins with a single symbol (`-` or `>`) that becomes the "first token" and stays under the 6-character floor. `->` is not an assignment operator in any language (Perl/Ruby's `->` dereferences, `=>` is the hash assignment), and `=>>` / `= >` are the same family of pseudo-shapes; a value that does hit a known format (`sk-` / `AKIA` …) is still caught by the pattern layer. Decision: **record only, do not fix** — extending the separator table has diminishing returns, and "take the second token when the first one is a single-character symbol" would change the value semantics. The measured shapes and their provenance live in `.agents/notes/20261003-hook-header-filter-structural.md` (second verification pass, oracle session, 2026-10-03, after `f0c6050`).
- **The commit gate's credential assignment no longer matches only the bare separator and the bare keyword** (global `/root/.git-hooks/{commit-msg,pre-push}` — shared tooling in the image, not code shipped from this repository; the in-repo `githooks/` mirror is untouched). Two narrow escapes are closed, both in the assignment rule of the two hooks: the keyword alternative now tolerates an identifier suffix (`(password|api_key|secret)[A-Za-z0-9_]*`), so a name such as `SECRET_KEY`, `PASSWORD_HASH` or `API_KEY_ID` — keyword immediately followed by `_…`, which matched neither the whitespace nor the separator — is no longer skipped; and the separator alternative covers the arrow forms (`[:=]+>?`), so an arrow assignment no longer leaves the `>` behind as the "first token" and passes the 6-character floor. What did **not** change: the first-non-whitespace-token rule, the 6-character floor, the placeholder/env-var/`none` exemptions, the awk header filter, and the known over-strict side of matching a keyword as a substring — which is also the one deliberate behaviour change here: a word that merely contains a keyword and is followed by an assignment (e.g. `secretary`) moves from pass to reject, the price of catching the real `_KEY`/`_HASH` names. The template `/root/.git-templates/hooks/pre-commit` mirrors the header filter and has no assignment scan; it is this repository's effective pre-commit (the repo-local `core.hooksPath` is `/root/.git-templates/hooks`, where `commit-msg`/`pre-push` are symlinks into `/root/.git-hooks/` and `pre-commit` is a real file, so it does run here — an earlier wording that called it overridden by the global `core.hooksPath` was wrong, corrected 2026-10-03), and it was synced to the same awk state machine in the same round (sha256 `2b8b4be7dfba7d1546c4ca766f1391522e14b5aa1d6591f3c21f7f95af517245`, backup `pre-commit.bak-20261003143116`, 25-case regression green); this entry's change does not reach it. Old-vs-new differential, the 45-case matrix re-run and the measured residual list live in `.agents/notes/20261003-hook-header-filter-structural.md`; previous hooks kept at `commit-msg.bak-20261003145322` and `pre-push.bak-20261003145322`.
- **The commit gate's diff header filter is structural, not prefix-based** (global `/root/.git-hooks/{commit-msg,pre-push}` — shared tooling in the image, not code shipped from this repository). A `+++ …` line now counts as a file header only when it directly follows a `--- …` line while still outside a hunk: `added_lines_only` became an awk state machine keyed on the `diff --git` opener and the `@@ ` hunk marker, so inside a hunk every `+` line is added content. The prefix filter it replaces (`grep -v '^+++ \(b/\|/dev/null\)'` plus the `"+++ b/"*|"+++ /dev/null"*` case arm in `commit-msg` and a bare `"+++"*` in `pre-push`) could not distinguish a header from an added line whose own text starts with `++ `, and the previous narrowing still dropped the `++ b/…` and `++ /dev/null …` spellings. Both remaining escapes are closed and both false positives are gone: a secret-shaped **file name** is no longer scanned, and skewed prefixes (`diff.noprefix=true`, `diff.mnemonicPrefix=true`) no longer make real headers survive the filter. This supersedes the "Residuals" paragraph of the *commit gate only scans added lines* entry below; the rest of that entry stands. The two credential scanners also stop re-applying a prefix skip of their own — the feeder is what removes headers now, and a prefix skip there would re-drop real added content. Second change in the same hooks: the assignment value is the **first non-whitespace token** after the separator (quotes/backticks then stripped) instead of the whole tail, so documentation prose on an `api_key` line that points at a runbook is no longer reported as a hardcoded credential; the existing 6-character floor and the placeholder/env-var/`none` exemptions are unchanged, and single-token assignments are still rejected. Measured residuals, all narrow: a first token of 6+ characters still trips the check (prose included), a diff format that omits the `diff --git` opener would over-report later files' headers, and secret-shaped file names stay unscanned. Method, old-vs-new differential and the 45-case end-to-end matrix live in `.agents/notes/20261003-hook-header-filter-structural.md`; previous hooks kept at `commit-msg.bak-20261003141636` and `pre-push.bak-20261003141636`.
- **The commit gate only scans added lines now.** The global `commit-msg` hook scanned every line of the staged diff, so removed and context lines could reject a commit that was in fact *removing* a credential-shaped line (its `"-")` case arm, meant to skip diff markers, was a typo for `"-"*`), and it dropped any added line whose content starts with `++` — diffs render those as `+++content`, indistinguishable from a file header by prefix alone — which let a real secret through. Both scanners now receive only the added lines, and the header filter is anchored on the two forms git actually emits for the added side (`added_lines_only`: `grep '^+'` plus `grep -v '^+++ \(b/\|/dev/null\)'`; the `check_credential_assignments` case arm is `"+++ b/"*|"+++ /dev/null"*`). Anchoring on `b/` and `/dev/null` rather than on a bare `"+++ "` closes the spelling that a first fix still dropped: an added line whose content starts with `++ ` renders as `"+++ …"`, so an assignment or a pattern-shaped credential in such a line — dropped whole until now — is caught. The `pre-commit` hook in this repository's configured hooks path (`/root/.git-templates/hooks/pre-commit`, a real file rather than a `commit-msg`/`pre-push`-style symlink) got the same filter (`git diff --cached -U0 | grep -v '^+++ \(b/\|/dev/null\)'`). Residuals: a line whose content starts with `++ b/…` renders as `"+++ b/…"` and is still dropped, and secret-shaped *file names* are not checked now that header lines are excluded (kept deliberately, low risk); a skewed header prefix (`diff.noprefix=true`, `diff.mnemonicPrefix=true`) makes real headers survive the filter, which can only over-report, never under-report. This is shared tooling in the image, not code shipped from this repository; the notes record the reasoning. Backup of the previous hooks: `commit-msg.bak-20260930094017`, `pre-commit.bak-20260930094017` (earlier: `commit-msg.bak-20260930082550`, `pre-commit.bak-20260930092955`).
- **Pre-commit review fixes for the two features above** (oracle/reviewer double review; items F1–F2, S1–S10, O1–O5/O8 of the fix package).
  - **F1 — the audit target is validated before it is opened.** `appendAuditLine` now `Lstat`s the target and refuses anything that is not the regular file ctxmode creates (symlink, FIFO, device, directory) with a once-per-path+reason log, `O_NONBLOCK` plus a post-open `Stat` re-check back that up, and the **`Lstat` validation** happens **before** `auditMu` is taken (the `O_NONBLOCK` open and its `Stat` re-check run inside it — they are what makes the in-lock open non-blocking) — a FIFO target could previously block inside the append mutex and queue every later `ctx_run` call behind it. This also corrects the earlier "audit problems never slow down an execution" claim: write failures still never fail a call, but the one failure that could have stalled the tool surface is now refused up front. Adds rotation to `<path>.1` at 32 MiB (S6). Tests: `TestAudit_TargetIsValidatedBeforeOpening`, `TestAudit_RotatesAtSizeCap`.
  - **F2 — a batch failure is no longer folded into 0.** The call-level aggregate reused `auditExitNotRun` (-1) as both its "no result yet" sentinel and a legitimate failure code, so a first command blocked by the screen, skipped on a shared timeout or killed at -1 was overwritten by the next command's 0. It now tracks `seen bool` separately and always keeps a failure. Test: `TestAudit_BatchFirstFailureNotFolded`.
  - **S1/S4/S5 — record shape.** Adds `pid` and `session_id`; `batch` lines carry a machine-readable `commands` array plus `first_failed_label`, replacing atomically-joined label lists (a label containing a comma used to be ambiguous); a background line records `background_id` and `exit_code: -1` instead of an `exit_code: 0` that never happened, with `output_len` documented as the start-message length.
  - **S2 — command-text redaction and inputs.** `raw_cmd` goes through the same `checkSensitiveContent` patterns used for indexing and becomes a length+digest marker on a hit; `env_keys` (key names only, sorted, capped at 64) and `stdin_len` (a count) are recorded. README drops "metadata and statistics only" and states that the file is plaintext and may contain credentials.
  - **S3/S10 — `run_task` joins the screen, `-i` false positive removed.** Every `run_task` kind (including `custom`) applies `applyArgvScreen`/`setScreen`, so no argv path is left unscreened; the `-i` "reads stdin" rule fires only as the first argument and is suppressed in `-m` module mode, so `python3 -m pip install -i URL` is no longer tagged.
  - **S7/S8 — `eval_interpreter` coverage and wording.** Handles bundled short options (`-lc`/`-ec`/`-pe`), `--eval=`/`--print`, `php -r`, `Rscript -e` and `env`/`busybox` unwrapping; README/CHANGELOG wording is narrowed to "a spelling check over argv, not a detector" with its known false positives and misses listed.
  - **S9 — uniform audit timing.** `toolExecute` and `toolExecuteFile` create the audit record before their required-field checks, so an empty `execute`/`execute_file` call is recorded like `batch`/`run_task` already were. Test: `TestAudit_EarlyValidationRecorded`.
  - **O1/O2/O3/O4/O5/O8.** `auditExeCache` is bounded (256) and only caches successes; the argv `oversized` warn logs no command head; `screen_verdict`'s unscreened value (`""`) and the `exit_code: -1` semantics (rejected call / background start) are documented; a failure on the default path logs a hint that it is root-specific; `TestMain`'s `os.Setenv` (unavoidable outside a `*testing.T`) and the literal default-path assertion are documented as deliberate; per-command screen verdicts/rules are recorded so a specific idiom rule is not hidden by another command's size block in the same batch.
  - **Known gaps (deliberate, unchanged):** audit covers `ctx_run` only; one line per **call**, never per subprocess; "append-only" means `O_APPEND`, not tamper-proof (same-uid processes can rewrite or delete the file); `readonly_role_call` stays absent until the dispatch layer sets `CTXMODE_ROLE`/`CTXMODE_READONLY`; the target check is `Lstat` + `O_NONBLOCK` rather than an `O_NOFOLLOW` open. Rationale and the full observation-item list live in `.agents/notes/`.
- **Round-2 review fixes** (oracle round 2: `R2-F1` must fix, `R2-S1`/`R2-S2`; documentation items `R2-D1`–`R2-D3`; reviewer items `R2-R1`–`R2-R3`).
  - **R2-F1 — a failed rotation no longer loses the line or wedges the log.** Rotation ran *after* `f.Close()` and returned on a rename error: that line was dropped, the file stayed over the cap, and every later append re-took the same failing path (measured causes: `<path>.1` is a non-empty directory, or the directory is not writable for the process — a same-directory rename is always within one filesystem, so `EXDEV` is unreachable; a target that is a mount point gives `EBUSY`). Rotation is now best effort and attempted **before** the write, while the descriptor is still open: a failed rename is logged once per reason and the current line is appended to the current file with the same descriptor, so no record is lost and no later append can fail permanently. The same invariant covers the second half of the rotation — if the rename succeeds but the replacement file cannot be opened, the line goes to the generation just rotated away instead of being dropped. Tests: `TestAudit_RotationFailureKeepsWriting` (an occupied `.1` directory, three appends, each recorded) and `TestAudit_ReopenAfterRotationFailsKeepsRecord` (the reopen failure forced with `RLIMIT_NOFILE`).
  - **R2-S1 — `resolveAuditExe` really shares `looksLikePath` now.** Its comment claimed a shared "what counts as a path" rule that the code did not implement (it looked for a separator only), so `.hidden`, `..x` and `a\b` were recorded as PATH-lookup results while the executor resolved them as paths. The audit side now calls `looksLikePath` itself, so both name the same file for every path-like spelling; the one remaining difference (empty-cwd fallback) is documented and unreachable from the current call sites. Test: `TestResolveAuditExeAgreesWithExecutor`.
  - **R2-D3 — env key names go through the sensitive-content check.** A key name that is itself credential-shaped (`AKIA…`, `ghp_…`, a JWT) is recorded as `[redacted]` instead of verbatim, and the list stays sorted, deduplicated and capped at 64. Values are still never inspected. README notes that names outside the pattern set are recorded as sent, so key names are potentially sensitive too. Test: `TestAuditEnvKeys`.
  - **R2-S2 / R2-D1 / R2-D2 / R2-R1 — documentation now matches the implementation.** README and the `audit.go` header state that only the `Lstat` runs before the append mutex (the `O_NONBLOCK` open plus `Stat` re-check run inside it), that only the **last path component** is checked — a symlinked parent directory still redirects the trail, a hardlink to a regular file is indistinguishable, and a hung NFS/FUSE/CIFS mount or frozen block device can still delay a write — that only the current file plus one `.1` generation are kept (≈2×32 MiB; older generations are silently overwritten, no archive, no cross-process lock, so two processes sharing a path can race the rotation) with external-archiving suggestions, and that refusing symlinks means `/dev/stdout`-style targets no longer work (containers must use a real file, a path inside a mounted volume, or a file the log collector tails).
  - **Recorded, not changed (R2-R2, R2-R3 and the reviewer's confirmations).** `O_NONBLOCK` stays set on the descriptor: on Linux it is ignored for regular files and clearing it via `F_SETFL` risks dropping `O_APPEND` for no real gain, so the NFS/CIFS/FUSE `EAGAIN` write path is a documented boundary instead. The multi-process rotation race and the single-generation window are likewise documented rather than fixed (single-process design assumption). Recorded as such in `.agents/notes/`.

## [4.1.0] - 2026-09-24

### Added
- **Agent collaboration scaffolding**: added `AGENTS.md` collaboration rules, `.agents/notes/` architecture decision records, and `scripts/notes-index.sh` indexing script.
- Align skeleton test commands with CI (glob Pi extension tests, race-enabled go tests) and unify notes-index.sh.

### Changed
- **`ctx_run` command form now uses a fixed, controlled shell.** `executor.go` gains `shellCommand(code)` (`exec.Command("/bin/sh", "-c", code)`, absolute path); `runShellOpts` and `batch.executeCommand` no longer read `os.Getenv("SHELL")` or split it with `strings.Fields` — the interpreter for shell `command` strings is no longer caller-controllable via the environment. Existing SHELL-based tests were rewritten to assert the real child interpreter (`readlink /proc/$$/exe`) is dash/sh under `SHELL=/bin/bash`, `"/bin/bash -l"`, unset, and a hostile `/tmp/evil`.
- **Graded pre-execution screen for shell commands** (`shell_screen.go`, pure stdlib). `screenShellCommand` returns `shellOK`/`shellWarn`/`shellBlock`. Blocks only two conditions: a NUL byte or a command >64 KiB. The limit is counted on the entire code segment as received by `runShellOpts` (i.e. after injection), and the check is sunk into `runShellOpts` so it covers both `execute` and `execute_file`; the empty string is still handled by the existing "command is required" error. For `execute_file` with the shell language this means the injected `FILE_CONTENT` plus the caller's `code` is measured together, so it is rejected once the two exceed 64 KiB even though the `execute_file` file-read limit is 10 MB; non-shell languages are written to a temp file and are not subject to this limit. Warns (logged, execution continues) on three heuristic idioms — `base64 -d … | sh`, `curl`/`wget … | sh`, and a redirect into `/etc/` or `/dev/sd[a-z]` — logging only the rule name, length, and first 80 bytes, never the full command. Wired into `toolExecute` (command/shell path only) and `executeCommand`, where a block fails only that one command's `batchResult` and never cascades to siblings.
- **Tool schema and docs now state the command/batch shell boundary.** `executeArgs.Command`, `ctxRunArgs.Command`, `batchCommand.Command`, the Pi bridge `ctx_run` guideline + `command` description, `instructions.go`, and `README.md` (execute/batch entries + a security-model note) all document the fixed `/bin/sh -c` semantics (SHELL ignored, no command allowlist, argv bypasses the shell and is path-validated) and that the command screen only logs heuristic warnings and is not a policy.

### Fixed
- **Pi bridge: Esc could not stop a running `ctx_run`** (`integrations/pi/ctxmode.ts`). Pi aborts the turn locally (`session.abort()` → the extension tool's `AbortSignal`), but the bridge never told the ctxmode server: the five `execute()` handlers dropped the third `signal` argument, and the hand-rolled MCP client had no `notifications/cancelled` path at all (its per-request `setTimeout` only rejected locally). The server-side kill path (`executor.go` `runCmd` `ctx.Done` → `kill(-pgid, SIGTERM)` → 3s → `SIGKILL` + descendant sweep) therefore never fired, so a `ctx_run`/`run_task` child kept running until its own default budget (execute 30s, run_task 5min, background 1h). Tools now accept and forward the signal; abort writes `notifications/cancelled` with the matching `requestId` (always after the `tools/call` line so it lands on an in-flight request) and immediately rejects the local wait instead of dangling until the client timeout; the client-side timeout path now cancels server-side too instead of orphaning the job. No server-side change — verified at the bridge level only: the bytes written to the server (`tools/call` followed by `notifications/cancelled`), the matched `requestId` and its ordering invariant (request before cancel), and local pending-request cleanup; the subprocess kill itself is the server-side `runCmd` path, not re-exercised end-to-end against the real binary here.
- **Pi bridge: an explicit `stop()` could be undone by an internal reconnect** (same file). `cleanup()` rejects in-flight calls with "ctxmode disconnected", and `callTool`'s reconnect branch then called `start()`, which unconditionally reset `this.stopped = false` — so stopping while a long `tools/call` was in flight (`/ctxmode-stop`, `/reload`, session exit) spawned a second `ctxmode` process the extension could no longer reference or stop. Reproduced: 2 spawns, the second alive. `start()` now refuses once the client has been explicitly stopped; explicit starts (`/ctxmode-start`, `session_start`) always construct a fresh `CtxmodeClient`, and crash-driven auto-restart is unaffected because `stopped` stays false there — both locked in by tests.

## [4.0.9] - 2026-09-13

### Fixed
- **Timing schema copy unified to ms**: the last three descriptions still using human units now state the bound in milliseconds — the `ctx_run` `background` jsonschema ("default max 1h" → "default max 3600000ms") and the Pi adapter's `background` parameter description and `ctx_bg` tool description ("max 1h" / "最大1小时" → "max 3600000ms"). No behaviour change: every tool-facing timing input was and remains `timeout_ms`/`ttl_ms` in ms with matching code defaults.

## [4.0.8] - 2026-09-13

### Fixed
- All 20 staticcheck findings resolved: dead assignments in the kill/drain and rg-line-drain paths removed, dead functions (superseded purges, unused runCompiled/isProbablyBinary wrappers) deleted, error strings normalized. No behavioural changes.

### Added
- **deploy.sh rollback subcommand**: the previous binary is kept as `.prev` on every deploy, and `deploy.sh rollback` verifies it through the same initialize check before atomically swapping it back.
- **KB backups**: every `context_mode.db` under the data directory is snapshotted weekly (Sunday 06:00 UTC) via `sqlite3 .backup` with per-database integrity checks, gzip, and 4-week retention into `/root/backups/ctxmode/`; restore documented in README.
- **CI quality gates**: staticcheck (pinned 2025.1.1) and the Pi-adapter TypeScript tests (`node --test`, Node 24 via setup-node) now run on every push; coverage baseline measured at 78.3% with new table-driven tests for the weakest newly-covered paths.

## [4.0.7] - 2026-09-13

### Fixed
- **migrateFromJSON rewritten**: the v4.0.6 whitelist rejected every real legacy document (the JSON era stored absolute workdir paths, and old session ids can never match the per-process random id). Legacy paths are now accepted only as absolute paths that resolve inside a workdir (EvalSymlinks + `..`-segment rejection + valid-UTF-8 + control-character checks), normalized to workdir-relative display paths, and re-checked by `isSensitiveFilePath`; the rg:/batch:/URL accept branches that only existed for hostile JSON are gone.
- **timeout branch of runCmd now bounds its final wait** (reapWaitBound, mirroring the ctx-cancel and batch branches), and `limitedBuffer` is mutex-protected, removing a data race when an abandoned Wait's copy goroutine is still writing.
- **fetch**: a fence-refused URL now deletes any pre-existing stale `fetch_cache` row (new `DeleteCached`) instead of leaving plaintext until the 7-day TTL.
- **isSensitiveFilePath false positives narrowed**: pgpass/netrc/git-credentials match exact names only (netrc.go / pgpass.md no longer flagged), private-key prefixes require a name boundary, and pure-numeric secondary suffixes are stripped (`prod.key.1`, `server.pem.20240901` now match).

### Changed
- Pi adapter stripANSI covers two/three-byte ESC forms with intermediate bytes and DCS/SOS/PM/APC sequences (verified by new TS tests).

## [4.0.6] - 2026-09-12

### Fixed
- **fetch persistence no longer bypasses the sensitive fence**: when indexing is refused, the page content is not written to `fetch_cache` (previously refused content persisted in plaintext for 7 days and could revive purged documents via cache hits).
- **migrateFromJSON hardening**: legacy JSON document paths are validated against a whitelist (session-namespace, rg/batch prefixes, fetch URL shapes, plain relative paths; no control characters, length-capped); malformed documents are skipped with a warning instead of aborting, and a corrupt migration file no longer fatals the server at startup.
- **setsid escapee reaping extended to the ctx-cancel and batch branches** (previously timeout-only): descendants are snapshotted and SIGKILLed before draining, and the final wait is bounded (5s) - a single `setsid` child can no longer hang an MCP call indefinitely.
- **killBackground fallback for unknown process start time**: entries whose /proc starttime could not be read are conservatively group-killed when the recorded pgid matches, instead of expiring never and occupying a background slot.
- **Sensitive-file name variants**: backup/secondary suffixes (`id_rsa.bak`, `prod.pem.txt`, `.pgpass.bak`, `netrc.bak`, `.htpasswd.old`, `.env~`, `pgpass`, `git-credentials.txt`) and private-key prefixes (`id_rsa_primary`, `id_ed25519_sk`) now match `isSensitiveFilePath`.
- **Pi adapter**: ctx_kb schema gains `confirm_phrase` (project purge was unusable from Pi), tool text is stripped of ANSI/OSC/CSI sequences before TUI rendering.

### Changed
- Shell execution is documented as `$SHELL -c` (not `sh -c`).

## [4.0.5] - 2026-09-12

### Fixed
- **Timeout kill reaps setsid escapees**: descendants are snapshotted from /proc (PPID tree, comm-safe parsing, starttime recheck against PID reuse) and SIGKILLed in the hard-kill branch plus a post-drain sweep; a `setsid ... &` child can no longer survive the timeout as an orphan.
- **Background maxAge safety timers stop on early finish**: a completed/killed background job no longer leaves its 1-hour safety timer around to fire a no-op.
- **rg summary labels disambiguate ambiguous paths**: group labels and Read hints resolve `x:12:y/notes.md`-style paths with the same candidate-path stat strategy as the output fence; normal paths are byte-identical.

### Changed
- **FloodGuard covers rg-scoped search and fetch**: rg-scoped KB search gets its own bucket (throttle 20 / block 40, five times the global search limits) and ctx_kb fetch a per-server bucket (throttle 8 / block 16); unscoped search and the batch bypass are unchanged.
- **deploy.sh initialize verification retries up to three times**, absorbing the transient stdin-EOF shutdown race during first-run initialize.
- Middle-path-component TOCTOU is documented as out of scope in fs_tools.go / main.go under the README threat model.

## [4.0.4] - 2026-09-12

### Security
- **ctx_git diff/log outputs are gated**: outputs from git diff and git log now pass the sensitive-content fence; credential-bearing diffs or commit messages are withheld with a metadata-only notice (previously returned raw). status remains ungated: it is pure metadata.
- **KB search snippets are escape-sanitized on the MCP path**: toolSearch applies the same ANSI/OSC stripping as the CLI, so untrusted indexed content cannot carry terminal escape sequences or injection payloads back into model context.
- **KB writes neutralize forged [def] markers at every path**: toolIndex (file and directory walk) and the store layer (Store.Index, ReplaceExactAndChunks, covering batch and JSON-migration writes) neutralize a literal `[def] ` prefix at content position 0, matching the rg-path behavior; mid-content markers stay byte-identical.
- **purge scope=project requires an explicit confirmation phrase**: confirm:true alone no longer wipes the knowledge base; confirm_phrase must byte-equal the knowledge base name (surfaced in the error message). session scope and dryRun semantics unchanged; the MCP schema carries confirm_phrase.

## [4.0.3] - 2026-09-12

### Security
- **All command-output return paths are gated**: `ctx_run` execute / execute_file / run_task normal returns and the bg log / bg wait paths now run returned output through the sensitive-content fence — small outputs were previously returned raw, so a single `cat` could exfiltrate credential files the rg fence had just been hardened against. Indexing-refused outputs no longer include a tail preview (the preview echoed the very secret that was refused).
- **Sensitive-path deny list extended** (`isSensitiveFilePath` + rg deny-globs, same-name-same-set): `.git-credentials`, `.bash_history`, `.zsh_history`, `.pgpass`, `.htpasswd`, `*.tfvars`, `*.tfstate`, `*.kdbx`, `service-account*.json`.
- **Secret-value regexes extended**: refresh/session/id token, aws_secret_access_key, db_password, db_pass; word boundaries rebuilt without `\b` so underscore-prefixed keys (`_db_password`) match; value charset accepts `/` for real AWS secrets.
- **rg output fence ambiguity fixed**: match and context lines are resolved with candidate-path stat disambiguation — paths containing `:<digits>:` or `-<digits>-` segments (e.g. `x:12:y/.docker/config.json`, `v1-2-id_rsa`) can no longer bypass the sensitive-path filter; genuine ambiguity fails closed.

## [4.0.2] - 2026-09-12

### Security
- **rg sensitive-file fence hardened** (`ctx_fs`): the client-supplied `glob` is now appended *before* the built-in deny-globs, so built-in excludes always win (a trailing user glob could previously re-include `.env*`, `*.pem`, `.ssh/**`, ...); an explicit `path` that resolves to a deny-listed sensitive file is refused; rg output lines whose file path is sensitive are dropped; on the direct-return path (hits <= limit) content matching secret patterns is withheld and replaced by a warning listing the file names.
- **Sensitive-content withholding extended to every `ctx_fs` rg return path**: with more hits than the limit (indexed fallback), on offset-paginated pages, and in the non-indexing fallback (store or summary disabled), raw match lines used to be echoed without the sensitive-content gate; all paths now return the withheld warning listing the file names.
- **rg dedup key now carries `truncated`/budget state**: a truncated or budget-partial result set can no longer be cached and later served as the complete result for the same query.
- **`[def]` marker spoofing neutralized** (`fs_rg_summary`): a literal `[def] ` prefix at the start of untrusted file content can no longer forge definition hints or poison KB summaries; only ctxmode-generated markers are recognized.
- **`ctx_fs` MCP annotation `readOnlyHint` corrected to `false`**: over-limit rg hits write the KB store, so the tool is not read-only.
- **CLI output is escape-sanitized**: untrusted KB content written by `ctxmode index`/`search` is stripped of ANSI CSI/OSC sequences before hitting the terminal.
- **`ttl_ms` validation**: negative values are rejected with an explicit error and a 30-day cap prevents `time.Duration` overflow (previously silently fell back to the default or wrapped negative).
- **`maxFetchTTLms` is an explicitly typed `int64`** so the 30-day TTL cap compiles on 32-bit platforms (64-bit behavior unchanged).
- **rg budget bookkeeping fixes**: a parent-request timeout is no longer mislabeled as `budget_exceeded` and a clean finish is not flagged truncated; the Go fallback engine now consumes only the remaining rg budget instead of a fresh one; the wildcard-only-pattern guard now rejects zero-width-assertion-only patterns such as `\b\b` while keeping `\bword\b` working.

### Changed
- **`deploy.sh` installs the Pi extension** (`integrations/pi/ctxmode.ts` → `~/.pi/agent/extensions/ctxmode.ts`). Pi has no MCP client; tools come from that file. Binary-only deploys left Pi on a stale schema.

## [4.0.1] - 2026-09-11

### Changed
- **Timeout/TTL schema copy is ms-only**: MCP `jsonschema` and Pi descriptions for `timeout_ms` / `ttl_ms` now state unit, default, and max in milliseconds (no `1h`/`24h`). Execute/batch default documented as 30000 (was wrongly 60000). Router structs that MCP `tools/list` actually uses now carry the descriptions.

## [4.0.0] - 2026-09-11

### Breaking changes
- **One timeout field: `timeout_ms`**. `ctx_run` execute / execute_file / batch no longer accept `timeout`. `ctx_kb` fetch no longer accepts camelCase `timeoutMs`. Unknown JSON keys are dropped silently, so a leftover `timeout`/`timeoutMs` becomes the action default instead of an error.
- **One fetch TTL field: `ttl_ms`**. `ctx_kb` fetch no longer accepts `ttl`.

### Changed
- Pi adapter schemas expose only `timeout_ms` and `ttl_ms`. Client request timeout reads only `timeout_ms`.

## [3.5.0] - 2026-09-11

### Added
- **`timeout_ms` on execute / execute_file / batch**: canonical millisecond timeout (same unit as the old `timeout` field). `timeout` remains as a deprecated alias; `timeout_ms` wins when both are set. Previously only `run_task` and `ctx_bg` wait honored `timeout_ms`.
- **`ttl_ms` on ctx_kb fetch**: canonical cache TTL in milliseconds. `ttl` remains as a deprecated alias.

### Changed
- Pi adapter schemas advertise `timeout_ms` / `ttl_ms` as canonical and mark `timeout` / `ttl` deprecated.

## [3.4.0] - 2026-09-10

### Added
- **Wildcard-only rg guard** (behavior change, always-on): `ctx_fs` rg rejects patterns that contain no literal characters after stripping regex metacharacters (`.*`, `*`, `.+`, `.`, `.*.*`), returning a short tool error that steers the caller to a concrete identifier. Mixed patterns (`foo.*`, `Get.*Name`) still run. This guard cannot be disabled; pass `literal:true` to search those metacharacters as a literal string. Previously these patterns scanned every line.
- **rg wall-clock budget**: `ctx_fs` rg searches stop after 10s by default (override with `CTXMODE_RG_BUDGET_MS`; `<=0` disables). Unlike pi-fff, the budget applies to zero-match scans too. Timeout returns partial results with `truncated=true` and a hint to narrow path/glob or use `ctx_kb` search (not rg offset). Partial results still go through auto-index/summary, tagged `partial set indexed (budget exceeded)` with `# partial=true` in the KB document.
- **Definition-line `[def]` tags and `→ Read` hint**: rg summary and first-screen output (when `CTXMODE_RG_SUMMARY` is on) annotate definition lines (tightened heuristic: keyword then identifier, including Go methods `func (s *T) M(...)`) and suggest `→ Read <path>` (first file with a definition, else the first ranked file). Match-line order is not rearranged.
- **Match-line truncation and large-file hints**: match lines longer than 500 runes are UTF-8-truncated with `...` (override with `CTXMODE_RG_MAX_LINE_RUNES`; `<=0` disables). Files over 20KiB (`20*1024` bytes) shown in the summary get `(NN KB - use offset to read relevant section)`. Dedup hash is computed on the truncated (and tagged) match text. The wildcard-only guard stays always-on even when this truncation switch is off.
- **Git porcelain short tags on rg summary**: dirty-file `*` prefix becomes `M` (modified), `A` (added), or `??` (untracked); one tag per file, priority modified > added > untracked.

### Changed
- **`ctx_fs` glob dirty-first ordering**: glob results reuse the rg git dirty set (3s TTL) to list dirty files first; remaining entries keep their previous relative (lexicographic) order.
- **Tool guidance**: `instructions.go` and the pi `ctx_fs` promptGuidelines now tell agents to grep with concrete identifiers, Read after 1-2 greps, and page huge result sets via `ctx_kb` search or rg offset.

## [3.3.0] - 2026-09-09

### Added
- **MCP tool annotations**: each of the five public tools now advertises MCP `ToolAnnotations` on `tools/list` — `ctx_fs`/`ctx_git`: `readOnlyHint=true`, `destructiveHint=false`; `ctx_run`: `readOnlyHint=false`, `destructiveHint=true`, `openWorldHint=true`; `ctx_kb`/`ctx_bg`: `readOnlyHint=false`, `destructiveHint=true`.
- **Error auto-classification**: failed `execute`, `execute_file`, `batch`, and `run_task` results set `_meta.error_class` (10-bucket ABI) and prefix indexed KB content with `error_class: <class>`.
- **CLI `index`/`search` subcommands**: `ctxmode index <path>` indexes a file or directory into the knowledge base; `ctxmode search <query>` prints matching snippets without starting the MCP server.

### Fixed
- **Error-class exit-code fold**: `(exited with code N)` folding is unified into `errorClassForExit` so `execute`/`batch`/`run_task` classify empty-output exit 127 as `command_not_found`.
- **`ctx_fs` rg summary dedup hash**: hash on raw match text (drop timestamp) to fix intermittent flake and unbounded KB entry proliferation.
- **CI ripgrep**: install ripgrep on the runner; skip the byte-for-byte equivalence test when system `rg` is absent (CI had been red since v3.2.0).

## [3.2.0] - 2026-08-28

### Added
- **`ctx_fs` rg git-aware ranking**: search results prioritize modified and untracked files (`git status -uall`) with dirty-file weighting to surface actively edited code first.
- **`ctx_fs` rg auto-indexing & grouped summary**: searches exceeding match limits or the 200KB capture ceiling automatically index into `ctx_kb` under stable content-hashed labels (`rg:<hash>`), returning a concise per-file match count summary.
- **`ctx_fs` rg offset paging**: linear pagination via `offset` parameter while preserving ranking baselines across pages.
- **`ctx_fs` rg rollback switches**: `CTXMODE_RG_SUMMARY` and `CTXMODE_RG_GIT_RANK` environment variables allow disabling auto-indexing fallback and git-aware ranking.

### Changed
- **`ctx_fs` rg default limit**: default limit reduced from 50 to 20 matches to reduce initial noise and context overhead.

### Fixed
- **`ctx_fs` rg match parsing & context preservation**: `splitRgMatchLine` scans colon pairs for numeric line numbers to handle file paths containing colons and `#` symbols; `sliceGroupsWithContext` preserves `-C` context lines across fallback paths.
- **Security audit fixes across tools**:
  - `run_task`: rejects leading-dash targets/args for Go kinds; restricts `make` arguments against `-f`/`-C`/`SHELL=` overrides.
  - `ctx_fs` rg: filters sensitive paths across both search engines.
  - `execute_file`: re-validates opened file descriptors against TOCTOU hardlink swap attacks.
  - `git` pathspec: fails closed on unexpected `EvalSymlinks` errors.
  - `store`: records mtime/size at index time, marks stale hits, enforces atomic indexing, and verifies chunk base documents.
  - `executor`: cleans up leaked temporary files on background execution write failure.
  - Search flood guard returns tool error; directory walks honor context cancellation; fetch caps timeout at 1h and exhausts safe IP endpoints.

## [3.1.8] - 2026-08-21

### Changed
- **Background process waiting**: background execution now returns explicit one-shot wait guidance, supports bounded blocking waits with stable terminal results, and rejects ambiguous id/pid usage.
- **Pi integration guidance**: tool schemas document the background wait workflow and timeout semantics.

## [3.1.7] - 2026-08-19

### Fixed
- **Background process shutdown cleanup**: `shutdownBackground` terminates all running background processes concurrently and cleans up temporary files and disk logs on server exit (SIGINT, SIGTERM, fatal error) in an idempotent and thread-safe manner.
- **DNS and SSRF validation**: `validateURL` bounds DNS resolution with a dedicated 5s timeout chained to request context, directly allows safe IP literals without DNS lookup, and expands embedded IPv4 detection in IPv6 to include Teredo (`2001:0::/32`) and ISATAP (`0000:5efe`/`0200:5efe`).
- **Database permissions**: `ensureDBDir` restricts the dedicated database directory to `0700` and creates SQLite database files with `0600` permissions; custom directories from `CTXMODE_DB` are created with `0755` without mutating existing permissions.
- **JSON migration boundaries**: `migrateFromJSON` enforces a 50MB file size limit with `LimitReader` and verifies regular file status without following symlinks before reading, ensuring the backup `.bak` rename occurs only after successful migration.
- **Index performance for single-link files**: single-file indexing skips the global sensitive inode collection when `nlink == 1`, only scanning when hardlinks (`nlink > 1`) are detected.
- **Git hooks credential checks**: `commit-msg` and `pre-push` hooks scan assignment patterns with placeholder exceptions and allow code review round commit messages.

## [3.1.6] - 2026-08-19

### Fixed
- **`ctx_git` log** ignores repository `log.showSignature` and `gpg.program` / `gpg.ssh.program` (command-line `-c` plus `--no-show-signature`) so a local git config cannot run an arbitrary verifier.
- **Sensitive hardlinks** are detected by collecting secret-path inodes across workdirs first, then walking or indexing a single file against that table. Harmless names no longer depend on walk order. `indexFile` also collects when `Nlink>1` if no table was passed.
- **`looksLikePrivateKey`** also matches PKCS#8 `BEGIN PRIVATE KEY`.
- **`ctx_fs` stat** `abs_path` is the workdir-relative display path, same as `path`, and no longer returns a host absolute path.
- **`ctx_kb` fetch** refuses to index private-key bodies before purge/write. Page text is still returned to the caller.

## [3.1.5] - 2026-08-18

### Fixed
- **index / execute_file** refuse FIFO and other non-regular files before Open/ReadAll so a named pipe cannot hang the MCP session. Directory walks still follow a symlink to a regular file.
- **Background log rename** updates `LogPath` under `bgMu`, closing a data race with `ctx_bg` list/log.
- **fetch URLs** strip userinfo from KB paths, cache keys, `FetchResult.URL`, search hits, and error text. HTTP GET still sends credentials.
- **Sensitive index** skips hardlinks of secret paths (same device+inode) and refuses OpenSSH/PEM/PGP private-key bodies. Public keys still index.

## [3.1.4] - 2026-08-18

### Fixed
- **Background Rust** compiles and runs as one `sh -c` job (`rustc && exec`) instead of blocking the tool call on a synchronous `rustc`.
- **TypeScript `ts-node` detection** uses the request `cwd` (LookPath, then `cwd/node_modules/.bin/ts-node`, then `npm ls` with `cmd.Dir=cwd`) and caches per cwd instead of a process-wide `sync.Once`.
- **Pi `compressToolText`** keeps about 75% head plus a tail on character overflow so a trailing `(exited with code N)` is not sliced off.
- **`ctx_bg` `wait`** reports `log_error` when the log cannot be read; `done` and `exit_code` are still returned.
- **Sensitive-path skip list** now includes `.envrc`, `*.p12`/`*.pfx`, and `.docker/config.json` (not the rest of `.docker/`).
- **Foreground `limitedBuffer`** keeps the newest bytes (same policy as the background ring log) and `String()` drops incomplete UTF-8 runes.

## [3.1.3] - 2026-08-18

### Fixed
- **`ctx_fs` default path with multiple workdirs**: omitted `path`, `.`, and `./` resolve to the primary workdir instead of matching every root and erroring. `ls` / `glob` / `rg` and `cwd=.` work with the documented two-workdir config.
- **`execute` / `execute_file` mid-size auto-index** (5KB–100KB with `intent`) now include `exit_code` and a tail preview, matching `run_task` and the >100KB path.
- **`execute_file` Go** injects `var FILE_CONTENT` so whole-file sources with `package` still compile (package-level `:=` was a syntax error).
- **`execute_file` PHP** no longer prepends a second `<?php` when the source already has an opener.
- **`execute_file` Elixir** uses base64 when file content ends with `"` or `\`, same as the Python path.
- **SQLite DSN**: filesystem paths are opened as encoded `file:` URIs so `%`, `?`, and `#` in `CTXMODE_DB` or a workdir basename no longer break open or write the wrong file.
- **`ctx_kb` fetch**: URL fragments are stripped before indexing (no collision with `#chunk-`); bodies cut at 10MB report `body truncated at 10MB` in the tool summary; SSRF also decodes RFC 8215 local-use NAT64 `64:ff9b:1::/48`.
- **Search**: one FTS side failing while the other returns no hits is an error, not a silent "no matches".
- **Pi adapter**: `ctx_kb` `fetch` client timeout defaults to 150s plus a 30s buffer and honors `timeoutMs` as well as `timeout_ms`.

## [3.1.2] - 2026-08-16

### Fixed
- **`execute_file` reports exit codes** the same way `execute` does; large auto-indexed output from both paths now includes `exit_code` and a tail preview (same contract as `run_task`).
- **Background logs keep the newest 16MB** (ring writer) instead of dropping new writes after the cap; `ctx_bg` `log`/`wait` report `log_truncated`. SIGKILL after SIGTERM re-checks `/proc` starttime.
- **fetch SSRF** decodes NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, and IPv4-compatible addresses before applying the IPv4 blocklist.
- **System `rg` is invoked with `--no-config`** so `RIPGREP_CONFIG_PATH` / `~/.ripgreprc` cannot add `--follow`/`--pre` or extra roots.
- **Re-fetch of a short URL no longer deletes a longer sibling** (`foo` vs `foobar`); stale chunks still use the `#chunk-` suffix only.
- **Session purge works**: execute/batch/run_task/fetch documents are tagged `session:<id>:…` (id from `stats`/`doctor`).
- **`query_scope=batch` searches only that batch run**, not historical `batch:` documents.
- **`.env/` directories** are skipped by the sensitive-path gate; glob/`rgGo` honor nested `.gitignore` and `!` negation.
- **`FILE_CONTENT` is spliced after** Go `package`/imports, Python `__future__`, and PHP `declare`; Elixir `~S"""` no longer adds wrapping newlines.
- **doctor** lists missing runtimes under `warnings` and probes FTS with a sample MATCH.
- **index / execute_file / rgGo** open files with `O_NOFOLLOW`.
- rust compile failures propagate the 10MB `Truncated` flag.
- **git hooks** match `github_pat_`, hyphenated `sk-proj-` / `sk-ant-api03-` keys, and fail closed when the non-ASCII check cannot run (no more silent skip without PCRE).
- **`deploy.sh`** initializes the staged binary before `mv`; verification failure leaves the old binary in place and does not print success.
- **Pi adapter** disposes the child on handshake failure and does not replay `tools/call` after disconnect.

## [3.1.1] - 2026-08-16

### Fixed
- **Git hooks hardened** (`githooks/pre-push`, `githooks/commit-msg`): pre-push now parses the four-field push line, handles branch deletions and new branches (zero SHA) correctly, scans only outgoing commits, and fails loudly on malformed input or git errors instead of silently passing; grep patterns are `--`-separated so patterns can never be parsed as options, and the noisy `bug.*fix`/`fix.*bug` words were dropped from commit-msg (normal bugfix messages pass again). Regression coverage in `githooks_test.go`.
- **`scripts/install-hooks.sh` honors `core.hooksPath`**: relative hooksPath values resolve against the repo root, and a missing hooks directory fails fast instead of claiming installation into a directory git would never use.
- **`ctx_kb` fetch**: the strict/non-strict split is gone — `CTX_FETCH_STRICT` was removed and the SSRF blocklist is a single fixed set; indexed documents are isolated per format (`source:format:url`), legacy `source:url` documents are purged on fetch, and the cache-hit re-index check backfills only the requested format.
- **Atomic deployment** (`deploy.sh`): the binary is staged inside the target directory and `mv`-renamed into place (same filesystem, atomic), with an ERR trap that cleans the temp file and leaves the old binary untouched on failure.
- **`ctx_fs` stat with multiple workdirs**: relative paths must match exactly one existing path under the configured workspaces; zero or multiple matches are errors demanding an absolute path instead of silently resolving to the first workdir.
- **Index walk early-stop**: `toolIndex` uses `filepath.SkipAll` once the file/size caps are hit, so the whole remaining tree is skipped instead of walking it.
- **Go `execute_file` imports**: selector-like text inside string literals and comments (including the injected `FILE_CONTENT` data) no longer triggers imports, and the default `fmt` import was removed — the wrapped program compiles without unused imports.
- **Background job memory**: background stdout/stderr stream straight to the capped disk log with no in-memory capture, removing up to 10MB per stream per job for concurrent jobs.
- **Linux platform contract documented**: `ctx_bg kill` verifies the PID identity via `/proc/<pid>/stat` starttime; on non-Linux platforms the check fails closed (never signal an unknown identity), so `ctx_bg` termination is only guaranteed on Linux.
- **Index walk resolves symlinks before any gate**: sensitive/size/binary checks and the total-byte accounting now run against the resolved real target, so a harmless-looking link name can no longer smuggle a sensitive or oversized file past the checks; `indexFile` re-verifies every gate at read time and reads with a hard cap (`maxIndexFileBytes+1`) instead of slurping the whole file.
- **Unique index labels for `ctx_run` batch and `run_task`**: a repeated command label or run_task kind/intent no longer silently overwrites an earlier document (INSERT OR REPLACE); each index gets a unique label that stays identifiable by command, and the actual label is returned in the response (`index_label`).
- **Pure-Go rg handles overlong lines**: the 1MB bufio.Scanner cap (which failed the entire search on any longer line) is replaced by a bounded per-line reader (8MB cap); lines beyond the cap are drained and skipped per line while scanning continues, and the result is flagged truncated so incomplete coverage is never silent.
- **`ctx_kb` fetch singleflight error branch**: the Truncated state now travels in the shared singleflight return value, so the executing caller and every concurrent waiter agree on `Truncated` even when the fetch is truncated and then fails content processing.
- **batch `Truncated` means real output cut**: the flag now comes only from the actual capture cap (10MB); output between 100KB and 10MB is auto-indexed but no longer misreported as truncated, and the batch-level flag aggregates the real truncation.

## [3.1.0] - 2026-08-11

### Fixed
- **Subprocess environment isolation gaps closed in five paths** (security hardening). `batch.go` `executeCommand`, `git_tools.go` `sanitizedGitEnv`, `fs_tools.go` `rgSystem`, and the two runtime probes in `executor.go` (`npm ls` and `go version`) now all build the child environment from `childEnv`/`flattenEnv`, same as the execute path. Children no longer inherit parent environment variables whose names match `token`/`key`/`secret`/`password`/`credential`/`auth`/`cookie`/`session`; hosts that must pass the full inherited set can set `CTXMODE_ENV_PASSTHROUGH=1`.
- Six regression tests added (strip vs. passthrough pairs for the batch, git, and rg paths), verified by mutation testing — reverting any fix line makes its test fail.
- **Documentation and probe tests for the isolation behavior**: the README gains a *Subprocess environment isolation* section under Security model (stripping mechanism, side effects, `CTXMODE_ENV_PASSTHROUGH` semantics and risks); the two runtime probes (`npm ls` in `DetectTsNode`, `go version` in `CheckRuntime`) get strip-vs-passthrough regression tests; the git and rg strip tests now assert a positive `CTXMODE_ENV_PROBE=1` passthrough alongside the sensitive-value stripping.

## [3.0.0] - 2026-08-10

### Breaking changes
- **Shell command policy removed entirely** (`policy.go` deleted). The `denylist`/`allowlist` modes, `CTXMODE_POLICY_MODE`, and the `policy.shell` config are gone: the checks only inspected the command basename, which interpreters (`python3 -c`, …) trivially bypassed, offering false confidence. ctxmode executes arbitrary commands and code with the server process's privileges — it is **not a sandbox** and provides **no security boundary**; run it only in trusted environments. Upgrade impact: configs carrying a `policy:` section still load (the section is ignored), but deployments that relied on the policy for protection lose it silently — move ctxmode to a trusted environment.
- **Knowledge base is now per-workdir**: `~/.local/share/ctxmode/<hash>-<basename>/context_mode.db` (hash = first 8 bytes of SHA-256 over the primary workdir's absolute path). The legacy global shared database is no longer used and is **not** migrated automatically; `CTXMODE_DB` still takes priority. Upgrade impact: previously indexed documents are no longer searchable until each workdir re-indexes them (or point `CTXMODE_DB` at the old file to keep using it).
- **Invalid parameters are hard errors** instead of silent clamps: `ctx_run` batch `concurrency` (1-8) and `query_scope` (`batch`|`global`); `ctx_fs` ls `depth` (1-5) and `limit` (max 2000). Upgrade impact: callers that previously passed out-of-range values and got clamped defaults now receive an error and must pass valid values.
- **`ctx_kb` purge without `confirm:true` returns an error** instead of a success-style "purge cancelled" message. Upgrade impact: scripts that treated the no-op as success must pass `confirm:true` (or `dryRun:true` to preview without deleting).
- **`env` injection truly overrides same-named inherited variables** (deduplicated map, not appended duplicates), and subprocess environments strip sensitive inherited variables (names matching `token`/`key`/`secret`/`password`/`credential`/`auth`/`cookie`/`session`) by default; `CTXMODE_ENV_PASSTHROUGH=1` disables the stripping. Upgrade impact: injected values now take effect where the host value previously won, and subprocesses no longer inherit secrets; hosts that must pass the full environment set `CTXMODE_ENV_PASSTHROUGH=1`.

### Changed
- Indexing skips secret-like files by default: `.env`/`.env.*`, private keys (`*.pem`, `*.key`, `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`), `credentials.json`, `.npmrc`, `.netrc`, and anything under `.aws`/`.ssh`/`.gnupg`/`.kube`.
- `ctx_run` batch auto-indexes only output >100KB (same threshold as `execute`); small output is no longer persisted to the KB.
- `ctx_kb` fetch blocks IPv6 loopback (`::1`), link-local (`fe80::/10`), private (`fc00::/7`), unspecified, and multicast addresses symmetrically with IPv4, in both strict and non-strict modes.
- Background jobs honor the caller-provided `timeout` (default max age 1h) and are capped at **16 concurrent jobs** (exceeding returns an error instead of queueing).
- Relative paths with multiple configured workdirs no longer silently resolve to the first workdir: zero or multiple matches are errors demanding an absolute path.

### Fixed
- CI runs `go test -race ./...` (the flood-guard concurrency tests only detect races under `-race`) with a 20-minute job timeout.
- **Pi extension** (`integrations/pi/ctxmode.ts`): child process lifecycle diagnostics no longer use `console.error`/`console.warn` on the host process (those writes corrupt Pi's TUI input row). Logs go to `~/.pi/agent/logs/ctxmode.log` unless `CTXMODE_DEBUG` is set; clean exits stay quiet, unexpected exits still file-log and auto-restart.

## [2.1.0] - 2026-08-06

### Added
- Server **instructions** returned on MCP `initialize` (playbook for the five category tools; `mcp.ServerOptions.Instructions`).
- Pi extension: captures `result.instructions` during the initialize handshake and appends a `## Ctxmode server instructions` section to the agent system prompt (`before_agent_start`). Missing instructions degrade to `null`, no error.
- Pi extension: `action` parameters for all five tools now carry an `enum` (ctx_run: execute\|execute_file\|batch\|run_task; ctx_fs: ls\|glob\|stat\|rg; ctx_git: status\|diff\|log; ctx_kb: index\|search\|fetch\|stats\|purge\|doctor; ctx_bg: list\|kill\|log\|wait).
- `.codegraph/` index artifacts ignored.

### Changed
- Version **2.1.0** (on top of the v2.0.0 five-tool folding baseline).

## [2.0.0] - 2026-08-05

### Changed
- **Breaking:** MCP tool surface reduced to **five category tools** with required `action=`:
  - `ctx_run` — execute | execute_file | batch | run_task
  - `ctx_fs` — ls | glob | stat | rg
  - `ctx_git` — status | diff | log
  - `ctx_kb` — index | search | fetch | stats | purge | doctor
  - `ctx_bg` — list | kill | log | wait
- Former top-level tools (`ctx_execute`, `ctx_ls`, …) are **not registered**; same handlers via routers.
- Pi adapter registers the same five tools and forwards full payloads to MCP.
- Version **2.0.0**.

### Migration
| Old tool | New call |
|----------|----------|
| `ctx_execute` | `ctx_run` + `action=execute` |
| `ctx_execute_file` | `ctx_run` + `action=execute_file` |
| `ctx_batch_execute` | `ctx_run` + `action=batch` |
| `ctx_run_task` | `ctx_run` + `action=run_task` |
| `ctx_ls` / `glob` / `stat` / `rg` | `ctx_fs` + matching `action` |
| `ctx_git_*` | `ctx_git` + `action=status\|diff\|log` |
| `ctx_index` / `search` / `fetch_and_index` / `stats` / `purge` / `doctor` | `ctx_kb` + `action` |
| `ctx_background_*` | `ctx_bg` + `action=list\|kill\|log\|wait` |

Grok names: `ctxmode__ctx_run` (etc.). Pi: same short names as MCP tools.

## [1.3.0] - 2026-08-04

### Added
- Filesystem tools: `ctx_ls`, `ctx_glob`, `ctx_stat`, `ctx_rg` (paths limited to configured workdirs via `resolvePath`)
- Background observability: `ctx_background_log`, `ctx_background_wait`; background jobs tee stdout/stderr to a log file
- `ctx_background_list` now reports `log_path` / `log_available`
- **P1** Git tools (read-only): `ctx_git_status`, `ctx_git_diff`, `ctx_git_log` (no commit/push/reset)
- **P1** `ctx_execute` enhancements: `argv` (direct exec, no shell), `env` (explicit allowlist; deny PATH/HOME/LD_*), `stdin` (max 1MB). Applies to foreground and background. `ctx_batch_execute` unchanged (no argv/env/stdin).
- **P2** `ctx_run_task`: structured test/build entrypoint (`go_test`/`go_build`/`go_vet`/`npm_test`/`npm_run_build`/`cargo_test`/`cargo_build`/`make`/`custom`). Fixed argv (no shell); make target charset whitelist; custom via `validateArgv`; large output auto-index (same 100KB threshold as `ctx_execute`).
- **P3** Shell command policy (`policy.shell` in YAML): `mode` off|allowlist|denylist (default **denylist**), `allow`/`deny`, `deny_patterns`, rm workdir/system-path rules. Applied to `ctx_execute` shell + `ctx_batch_execute`; argv/`ctx_run_task` use `CheckArgv` on basename. Override via `CTXMODE_POLICY_MODE`. See `config.example.yaml`. `ctx_doctor` reports `policy_mode`.

### Changed
- **P3** Default shell mode is **denylist** instead of off. It blocks explicit high-risk commands, destructive subcommands for network/system tools, remote-script pipes including wrapper variants, command/process substitution, and common fork-bomb literals while retaining read-only diagnostics. User rules merge with built-ins; wrappers including busybox/toybox cannot bypass command checks. Explicit `mode: off` and `mode: allowlist` remain available. This is an accident-prevention policy, not an OS sandbox.

### Fixed
- Hardened Git read-only tools against inherited `GIT_*` redirection variables, external diff/textconv, hooks, prompts, and oversized subprocess output.
- Fixed relative `argv[0]` resolution when executing from a secondary configured workdir.
- Bounded `ctx_rg` subprocess capture and closed files promptly in the pure-Go search fallback.
- Bounded background log tail requests and protected automatic Git exclude updates from symlinked `.git` directories.
- Made the stress cancellation test track only its own child process instead of scanning or killing unrelated `sleep` processes.

## [1.2.0] - 2026-07-27

### Added
- Background process list/kill tools with registry and reaper
- `SearchWithPathPrefix` and batch-scoped search
- Secure DB file permissions (0600)
- Index walk limits and binary content sniffing
- Go auto-imports for common stdlib packages
- Default fetch source labeling

### Fixed
- Symlink path escape outside workdir
- False "Indexed as" reporting
- Python trailing backslash handling
- Non-2xx fetch responses no longer indexed
- Session purge prefix false positives
- Flood guard vs batch execute interaction
- Forced markdown conversion issues
- Temp cleanup racing long-running background jobs
- Multi-IP `validateURL` / `Dial` alignment
- Index-fail preview messaging
- Kill marks background jobs as Done

## [1.1.1] - 2026-07-25

### Added
- A versioned Pi-specific adapter under `integrations/pi/` with installation and configuration documentation.
- GitHub Actions CI for tests, vetting, and binary builds.

### Changed
- The Pi adapter relies on tool schemas and prompt guidelines instead of injecting a fixed per-turn system prompt.
- MCP initialize and `ctx_doctor` now consistently report version 1.1.1.


## [1.1.0] - 2026-07-23

### Added
- YAML config file support (`-config` flag > `$CTXMODE_CONFIG` env > `./ctxmode-config.yaml` > `~/.config/ctxmode/config.yaml`)
- Multi-workdir support: paths under any directory in the `workdirs:` list are accepted as valid cwd
- `resolvePath` validates path containment against all configured workdirs
- `toolSearch` result paths are correctly relativized against the first matching workdir
- `excludeFromGit` runs `.git/info/exclude` exclusion for each workdir
- Falls back to cwd when no config is present (backward compatible)

## [1.0.0] - 2026-07-23

### Added
- 9 MCP tools: execute, execute_file, index, search, batch_execute, fetch_and_index, stats, doctor, purge
- SQLite FTS5 full-text search
- Subprocess execution (12 languages): javascript, typescript, python, shell, go, rust, php, perl, ruby, r, elixir, csharp
- Web page fetch and convert to Markdown for indexing
- Flood guard
- Background execution support
