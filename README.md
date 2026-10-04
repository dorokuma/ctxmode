# ctxmode

A 100% NPM/NodeJS-free, Go implementation of Mert Koseoglu's [context-mode](https://github.com/mksglu/context-mode).

Local-first Model Context Protocol (MCP) server that virtualizes tool outputs, allowing AI coding agents to execute heavy tasks and save up to 98% in token usage.

Current version: **4.2.0**.

Supported platform: **Linux**. Background process identity verification reads `/proc/<pid>/stat`; on other platforms ctxmode still runs, but `ctx_bg` termination is not promised (see [ctx_bg](#ctx_bg--background-process-supervision-from-ctx_run-actionexecute-backgroundtrue)).

## MCP tools (v2)

Five real tools (not skills). Each takes **`action=`** plus capability-specific fields:

| Tool | Actions | Key parameters |
|------|---------|----------------|
| **ctx_run** | `execute`, `execute_file`, `batch`, `run_task` | `command`/`language`/`timeout_ms`/`background`/`intent`/`cwd`/`argv`/`env`/`stdin`; `path`+`code`; `commands`/`queries`/`concurrency`/`query_scope`; `kind`/`target`/`args`/`timeout_ms` |
| **ctx_fs** | `ls`, `glob`, `stat`, `rg` | `path`/`depth`/`include_hidden`/`limit`; `pattern`/`path`/`limit`; `path`; `pattern`/`glob`/`ignore_case`/`context`/`literal` |
| **ctx_git** | `status`, `diff`, `log` | `cwd`; `path`/`stat`/`unified`/`staged`; `n`/`path`/`oneline` |
| **ctx_kb** | `index`, `search`, `fetch`, `stats`, `purge`, `doctor` | `path`; `query`; `url`/`urls`/`source`/`format`/`force`/`maxBytes`/`timeout_ms`/`ttl_ms`; —; `confirm`/`scope`/`sessionId`/`dryRun`; — |
| **ctx_bg** | `list`, `kill`, `log`, `wait` | —; `id`/`pid`; `id`/`pid`/`tail_lines`/`tail_bytes`; `id`/`pid`/`timeout_ms` |

Any MCP host (Grok, Pi, …) uses this surface. Grok prefixes the server name (e.g. `ctxmode__ctx_run`).

## Pi integration

A Pi-specific TypeScript adapter is maintained in [`integrations/pi/`](integrations/pi/README.md). It registers the **same five tools** and bridges stdio MCP to the Go binary.

## Quick Start

```bash
git clone https://github.com/dorokuma/ctxmode.git
cd ctxmode
bash scripts/install-hooks.sh   # ← MANDATORY: blocks bad commits & secret leaks
go build -o ctxmode .
```

## Git Hooks

`scripts/install-hooks.sh` installs two hard gates into `.git/hooks/`:

| Hook | What it blocks |
|------|---------------|
| `commit-msg` | Non-English characters, noise words, secret patterns (tokens, keys, passwords) |
| `pre-push` | Same checks across all outgoing commits |

Run the script once after `git clone`. Without it, commits may be written in Chinese or leak credentials — both are rejected at the hook level.

## Configuration

Optional YAML (`-config` / `$CTXMODE_CONFIG` / `./ctxmode-config.yaml` / `~/.config/ctxmode/config.yaml`):

```yaml
workdirs:
  - /path/to/your/project
  - /path/to/another/project
```

`workdirs` defines the workspace roots; every `cwd`/`path` argument is resolved against them (see Tools below). See [`config.example.yaml`](config.example.yaml).

Environment variables:

- `CTXMODE_DB` — absolute path to the SQLite database file; takes priority over the per-workdir default (see Database).
- `CTXMODE_CONFIG` — path to the YAML config file.
- `CTXMODE_ENV_PASSTHROUGH=1` — disable the default stripping of sensitive variables from subprocess environments (see [Subprocess environment isolation](#subprocess-environment-isolation)).
- `CTXMODE_AUDIT_LOG` — `ctx_run` audit target (default `/root/.local/state/ctxmode/audit.jsonl`, which is root-specific; see [the audit bullet](#security-model--not-a-sandbox)). The last path component must be a regular file: a symlink/FIFO/device/directory is refused, so `/dev/stdout` and symlinked paths are not usable as targets (point it at a real file instead). A refused or failed write is logged once and the call still runs.
- `CTXMODE_ROLE` / `CTXMODE_READONLY=1` — recorded in the audit line as `role`/`caller_readonly` and as the `readonly_role_call` tag. **Record-only:** they enforce nothing (`CTXMODE_ROLE ∈ scout|planner|researcher|reviewer|oracle`, `CTXMODE_READONLY` accepts `1`/`true`).
- `CTXMODE_RG_BUDGET_MS` — `ctx_fs` rg wall-clock budget in milliseconds (default `10000`; `<=0` disables).
- `CTXMODE_RG_MAX_LINE_RUNES` — `ctx_fs` rg match-line truncation in UTF-8 runes (default `500`; `<=0` disables). The wildcard-only pattern guard is always-on and has no env switch; pass `literal:true` to search metacharacters as a literal string.

## Security model — NOT a sandbox

**Threat model:** ctxmode runs as root by design. The operator is the
trusted party; the fences below (sensitive-path deny list, secret-value
regexes, output gates) exist to keep **untrusted content** - repository
files, fetched web pages - from leaking into model context or the
knowledge base. They do not constrain operator privileges and are not a
substitute for trusting whoever can call the tools. Auditors: do not
report "runs as root", "arbitrary command execution", or "the removed
shell-command policy" as findings; they are this documented design.

ctxmode executes arbitrary commands and code **with the server process's privileges**. There is no sandbox and no security boundary: nothing stops `ctx_run` from running any shell/argv/code, and interpreters can perform any action the server user can. **Run ctxmode only in trusted environments.**

The following are defense-in-depth measures, never a security guarantee:

- The `ctx_run` command screen is deliberately narrow: it runs shell `command` strings through a fixed `/bin/sh -c` and only hard-blocks a NUL byte or a command >64 KiB — measured on the entire code segment as received by the shell runner (post-injection), so `execute_file` with the shell language is rejected once the file content plus your `code` exceed 64 KiB even though the `execute_file` file-read limit is 10 MB, while non-shell languages run from a temp file and are not subject to this limit. Its heuristic alerts (encoded/downloaded payload piped into a shell, or a redirect into `/etc/`/`/dev/sd*`) are logged only and write to the log — they do not block execution and do not constitute policy. The same screen runs in argv mode with two adjustments: a NUL byte in **any argument** is a hard block (`argv command blocked (nul_byte)`; `execve` cannot spawn such a process anyway), while an argv whose joined bytes exceed 64 KiB only warns (`oversized`) — argv is not a shell string and killing large build/codegen arguments is exactly what the argv path exists to avoid.

- **argv mode is not path-fenced.** `ctx_run action=execute` with `argv` and `run_task` kind `custom` execute the given file directly; an absolute path is used as-is, a relative path is resolved against `cwd`, and a bare name is resolved through `PATH` — all three are equivalent in what they may run (anything the server user can execute). Only an empty `argv`/`argv[0]` is rejected. The workspace fences (`resolvePath` / `ensureInsideWorkspaces`) still apply to `ctx_fs` and `ctx_git` `path`/`pathspec` arguments and to every `cwd`, and are deliberately not applied to `argv`.

- **`ctx_run` calls are audited** (`audit.go`): one JSON line per **call** for `execute`, `execute_file`, `batch` and `run_task` — not per spawned subprocess, and nothing else is covered (`ctx_fs`, `ctx_git`, `ctx_kb`, `ctx_bg` are not audited). Target: `CTXMODE_AUDIT_LOG`, default `/root/.local/state/ctxmode/audit.jsonl`. That default is root-specific: a non-root deployment that does not set the variable gets a failed create, not a trail. The parent directory is created `0700` and the file opened `0600` **only when they are first created** — an existing file keeps the mode it already has, and nothing re-chmods it. "Append-only" describes only how the file is opened (`O_APPEND`); it is **not tamper-proof**: any process running as the same user can truncate, rewrite, delete or forge lines. Each line is built in full and appended under a process-wide mutex (batch runs commands concurrently, so lines never interleave). **Rotation is best effort**: at 32 MiB the file is renamed to `<path>.1` and a fresh file starts; a failed rename (the two measured causes: `<path>.1` is a non-empty directory, or the directory is not writable for the process) is logged once per reason and the line is appended to the current file instead — rotation can never drop a record nor stop later appends. (A same-directory rename is always within one filesystem, so `EXDEV` is not reachable here; a target path that *is* a mount point fails with `EBUSY` instead.) **Only the current file and one `.1` generation are kept** (≈2×32 MiB); older generations are silently overwritten, there is no archive and no compression, and there is no cross-process lock — two ctxmode processes sharing one `CTXMODE_AUDIT_LOG` can both rotate, so the retention window then favors whichever writes faster. If you need history, archive externally, e.g. `logrotate` on that path (`daily`, `rotate 30`, `copytruncate` — do not rely on ctxmode's own rotation for retention) or a periodic `cp <path>.1 /archive/audit-$(date +%F).jsonl` from a timer. The target must be a **dedicated regular file**: the *last path component* is `Lstat`-checked and a symlink, FIFO, directory or device there is refused (logged once per distinct path+reason, then silent) instead of being followed or opened. That check runs **before** the append mutex, and the open additionally uses `O_NONBLOCK` plus a `Stat` re-check on the descriptor, so a hostile target cannot stall the tool surface (a FIFO would otherwise block the open while the mutex is held); a write failure is logged and ignored rather than failing the call. Scope, stated because it is easy to over-read: a symlinked **parent** directory still redirects the trail silently, a hardlink to another file is indistinguishable from a regular file here, and a file the filesystem itself stalls on (hung NFS/FUSE/CIFS mount, frozen block device) can still delay a write — `O_NONBLOCK` protects the open, not a wedged mount. Refusing symlinks also means **`CTXMODE_AUDIT_LOG=/dev/stdout` (or a symlink to an external mount) no longer works**, which matters in containers: point it at a real file, at a path inside a mounted volume, or at a file the container's log collector tails. Fields: `timestamp`, `pid`, `session_id`, `action`, `role` (`CTXMODE_ROLE`), `caller_readonly` (`CTXMODE_READONLY`), `command_type` (`argv`/`command`/`file`/`task`), `raw_cmd` (capped at 64 KiB), `resolved_exe` (the bare name actually resolved via `exec.LookPath`), `cwd`, `background`, `background_id`, `duration_ms`, `exit_code`, `error`, `screen_verdict`/`screen_rule`, `audit_tags`, `env_keys`, `stdin_len`, `indexed`/`index_label`, `commands`, `first_failed_label`, `output_len`, `truncated`. **Process stdout/stderr are never recorded** — they can be huge and are the likeliest place for secrets. The record is not secret-free either: `raw_cmd` is the caller's command (or `execute_file`'s path/language/`code`) and goes through the same sensitive-content patterns used for indexing, replaced by a `[redacted: … len=… sha256=…]` marker on a hit; a hit keeps only a length and digest, and an **unformatted** secret (or a secret outside those patterns) can still land in the line. `env_keys` records the caller's env **key names** and `stdin_len` only a byte count — the values and the stdin payload are never written; a credential-shaped key name (`AKIA…`, `ghp_…`, a JWT) is replaced by `[redacted]`, but a name outside those patterns is recorded as sent, so treat key names as potentially sensitive too. `screen_verdict` is `ok`, `warn` or `block`, or `""` for a call rejected before it was screened. `exit_code` is `-1` for "no exit status of its own" (rejected call, spawn failure, or a background start — the latter also sets `background_id`, and its `output_len` is the length of the start message, not of job output). `batch` folds N commands into `commands` (per-command `label`, `exit_code`, `screen_verdict`/`screen_rule`, `indexed`/`index_label`) plus `first_failed_label` and a call-level `exit_code` that is 0 only when every command succeeded, otherwise the first failing code (including `-1`). Two tags are recorded and enforce nothing: `readonly_role_call` (`CTXMODE_ROLE` ∈ `scout`/`planner`/`researcher`/`reviewer`/`oracle`, or `CTXMODE_READONLY=1` — both are set by the dispatch layer that starts the session, so the tag is absent until that layer sets them) and `eval_interpreter`, a **spelling check** over argv, not a detector: it matches explicit inline-code spellings only (`-c`/`-e`/`-p`/`-r` incl. bundled forms like `-lc`/`-ec`/`-pe`, `--eval`/`--print`, `Rscript -e`, `php -r`, `env`/`busybox` wrappers), has known false positives (`bash -e file.sh`, `env -i cmd`, an interpreter reading stdin) and known misses (any spelling not in the table), and never blocks or delays a call.

- Subprocess environments strip inherited variables whose names look sensitive (`token`, `key`, `secret`, `password`, `passwd`, `credential`, `auth`, `cookie`, `session`, case-insensitive) by default; `CTXMODE_ENV_PASSTHROUGH=1` disables this. Caller-provided `env` overrides truly replace same-named inherited variables (deduplicated map, not appended duplicates), and the allowlist still rejects `PATH`/`HOME`/`SHELL`/`LD_*`/`DYLD_*` etc.
- Indexing skips secret-like files by default: `.env`/`.env.*`, `.envrc`, anything under a `.env/` directory, private keys (`*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`), `credentials.json`, `.npmrc`, `.netrc`, `.docker/config.json` (not the rest of `.docker/`), and anything under `.aws`/`.ssh`/`.gnupg`/`.kube`.
- `ctx_kb action=fetch` refuses SSRF targets: IPv4 and IPv6 loopback, link-local (169.254.0.0/16, fe80::/10), multicast, reserved, private (RFC 1918, fc00::/7), CGNAT and benchmark ranges. Embedded IPv4 in IPv6 (IPv4-mapped, IPv4-compatible, NAT64 `64:ff9b::/96`, RFC 8215 local-use `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001:0::/32`, ISATAP) is decoded and checked against the same IPv4 list. The blocklist is a single fixed set: the former strict/non-strict split was removed (`CTX_FETCH_STRICT` no longer exists) and the intercepted set cannot be changed via the environment.

### Subprocess environment isolation

Every subprocess ctxmode spawns — `execute`/`execute_file`, `run_task` (including its compile step), `batch`, and the `rg` and `git` helpers — starts from a sanitized environment built by `childEnv` (`executor.go`). By default, inherited variables whose **key name** matches `(?i)token|key|secret|password|passwd|credential|auth|cookie|session` (case-insensitive substring match; values are never inspected) are removed, so API keys, tokens or passwords present in the server's environment never reach a child — whose output is captured and auto-indexed.

Exceptions, in priority order:

- Keys on the `envAllowlist` (`executor.go`) are always kept, even when the name matches the pattern.
- Caller-provided `env` overrides (already validated by `filterExecEnv`, which still rejects `PATH`/`HOME`/`SHELL`/`LD_*`/`DYLD_*` etc.) are applied last and always win.
- Everything else that does not match the pattern — `PATH`, `HOME`, `SHELL`, `LANG`, `TZ`, … — is inherited unchanged.

Side effects to be aware of:

- `SSH_AUTH_SOCK` (contains `auth`) and `XDG_SESSION_*` / `DESKTOP_SESSION` (contain `session`) are stripped too — git remotes over SSH that authenticate via ssh-agent will fail, and session-aware desktop tooling may misbehave. The `git` tool additionally drops all inherited `GIT_*` overrides (see `sanitizedGitEnv` in `git_tools.go`).
- Stripping is name-based only: a variable like `MYVAR` whose *value* contains a secret still passes through.

`CTXMODE_ENV_PASSTHROUGH=1` disables stripping:

- It is a **global switch**: it affects every execution path at once, not a single command.
- It is read from the ctxmode server process's own environment — `childEnv` calls `os.Getenv("CTXMODE_ENV_PASSTHROUGH")` (`executor.go`). Passing it through `ctx_run`'s `env` parameter has no effect (that env is filtered and applied to the child, not to the server); set it in the parent environment that starts ctxmode, e.g. the shell or MCP host launching the binary.
- Risk: with passthrough enabled, every subprocess can read **all** sensitive variables of the host. On top of that, ctxmode stores captured output into the local knowledge base as plaintext without redaction once it exceeds the indexing threshold (>100KB, or >5KB with `intent`) — secrets that reach stdout would be persisted to disk. Prefer enabling it only temporarily, and only in trusted environments.

## Tools

### ctx_run — PRIMARY for commands/tests/builds

- `execute` — 12-language subprocess execution (`javascript`, `typescript`, `python`, `shell`, `go`, `rust`, `php`, `perl`, `ruby`, `r`, `elixir`, `csharp`). `command` runs via shell (default language); `argv` execs directly without a shell (preferred). `env` (allowlist-validated), `stdin` (≤1MB), `timeout_ms` (ms, max 1h), `background` (supervise via ctx_bg), `intent`, `cwd` (workdir-resolved). Output >100KB is auto-indexed (with `intent`, >5KB too). Auto-indexed replies include `exit_code` and a tail preview (same contract as `run_task`). **Shell safety boundary:** when `command` runs as shell (language shell/unset) it executes via a fixed, controlled `/bin/sh -c` — the `SHELL` variable is ignored and there is no command allowlist; `argv` skips the shell entirely, so there is no shell string to inject into (preferred). **argv is not path-fenced:** an absolute path is used as-is, a relative path is resolved against `cwd`, and a bare name is resolved via `PATH` — all three are equivalent in what they may execute (anything the server user can run). A pre-execution screen hard-blocks a command >64 KiB and a NUL byte in either the command string or any argv argument — counted on the whole post-injection segment (for `execute_file` with the shell language that is the file content plus your `code` measured together, which can be rejected below the 10 MB file-read limit; non-shell interpreters are not content-screened). It logs (never blocks) a few hostile-looking shell idioms, and an over-length argv is warned about (`oversized`) but never blocked, so large build arguments survive. Every `ctx_run` call — all four entry points — is appended to the audit log (see the security model below).
- `execute_file` — `path` + `code`: file content is injected as `FILE_CONTENT` and the code processes it. Files ≤10MB; binary files refused. Whole-file Go sources use `var FILE_CONTENT` (legal at package scope); PHP does not add a second `<?php` when the source already has one. Auto-indexed replies match `execute` (`exit_code` + tail preview).
- `batch` — `commands` (≤50, non-empty unique labels), `queries` (≤20), `concurrency` (1-8, default 1; out-of-range is an error), `query_scope` (`batch`|`global`, default `batch`; invalid is an error), `cwd`, `timeout_ms` (default 30s, max 1h; serial: shared budget, concurrent: per-command). Only output >100KB is indexed (same threshold as `execute`); small output is not persisted. `query_scope=batch` searches only this run's indexed command output. **Shell safety boundary:** each `command` uses the same fixed `/bin/sh -c` semantics as `execute` (`SHELL` ignored, no allowlist); a NUL/>64 KiB block on one command fails only that command's result and never cascades to its siblings.
- `run_task` — structured test/build with fixed argv (no shell): `kind` ∈ `go_test`|`go_build`|`go_vet`|`npm_test`|`npm_run_build`|`cargo_test`|`cargo_build`|`make`|`custom`, `target`, `args`, `timeout_ms` (default 300000, max 3600000), `cwd`, `intent`, `env`. Go kinds accept package targets only (no flag arguments); `custom` requires `args[0]` as the executable, which (like `execute` argv) is **not path-fenced** — it is only normalized (relative paths resolved against `cwd`). Its argv goes through the same pre-execution screen as `execute` argv (NUL block, `oversized` warn) and is recorded in the audit log.

### ctx_fs — workspace filesystem (paths limited to workdirs)

- `ls` — list directory: `path` (omitted, `.`, or `./` is the primary workdir, even when several `workdirs` are configured), `depth` (1-5, default 1; >5 is an error), `include_hidden`, `limit` (default 200, max 2000; >2000 is an error).
- `glob` — `pattern` (`**` supported), `path` (same default as `ls`), `limit` (default 200, max 2000; >2000 is an error); skips `.git`/`node_modules`/`vendor` and applies basic `.gitignore` rules.
- `stat` — `path`: size/mode/mtime/symlink/workdir metadata (symlink-aware).
- `rg` — content search: `pattern` (or `literal`), `path` (same default as `ls`), `glob`, `ignore_case`, `context` (0-5), `limit` (default 20 with summary on, max 500; >500 is an error); system `rg` with `--no-config` (ignores `RIPGREP_CONFIG_PATH` / `~/.ripgreprc`) and a pure-Go fallback; skips binaries. Wildcard-only patterns (`.*`, `*`, `.+`, `.`) are rejected (always-on; pass `literal:true` to search those characters). Match lines longer than 500 runes are truncated (`CTXMODE_RG_MAX_LINE_RUNES`; `<=0` disables). Files over 20KiB (`20*1024` bytes) get a size tag in the summary.

### ctx_git — read-only git (no commit/push/reset)

- `status` — `git status --porcelain=v1 -b` (`cwd`).
- `diff` — `path`, `stat`, `staged`, `unified`; output hard-truncated (200KB/2000 lines).
- `log` — `n` (default 20, hard max 100), `path`, `oneline` (default). Ignores repository `log.showSignature` / `gpg.program`.

### ctx_kb — local knowledge base

- `index` — `path` (file or directory) into SQLite FTS5; skips `.git`/`node_modules`, sensitive/secret files, binaries and >1MB files; capped at 5000 files / 100MB total.
- `search` — `query`: BM25 + Porter + Trigram + RRF + proximity rerank; flood-guarded (default 60-second window; 4 successful queries in the same window start throttling with half results; 9 attempts hard-reject). If one FTS index errors and the other returns no hits, the error is returned (not a silent "no matches"). `ctx_run` batch `query_scope=batch` searches only that batch run's indexed documents and bypasses the guard; it does not search `execute`/`run_task`/fetch output.
- `fetch` — `url`/`urls` (≤10) → markdown → index; `source`, `format` (markdown/html/json), `force`, `maxBytes` (default 50KB), `timeout_ms` (default 150000), `ttl_ms` (default 24h, 0 = skip cache); SSRF protection as above. URL fragments (`#…`) are stripped before indexing so a user fragment cannot collide with internal `#chunk-` keys. Bodies cut at the 10MB fetch cap are still indexed, and the summary reports `body truncated at 10MB`. Indexed documents are isolated per `format`: the KB path embeds the format (`source:format:url`), so the same URL can coexist as markdown/html/json without overwriting, and re-fetching in one format never touches the others. Re-fetching a short URL does not delete a longer sibling URL. The Pi adapter default request timeout for `fetch` is 150s plus a 30s buffer (and honors `timeout_ms`).
- `stats` — document/cache/DB statistics, token-savings estimate, and `session_id` for this server process.
- `purge` — `confirm:true` is mandatory: missing or `false` returns an error (not a silent no-op). `scope=project` wipes the whole KB. `scope=session` deletes documents tagged with `sessionId` (the id from `stats`/`doctor`); execute/batch/run_task/fetch writes from this process are tagged automatically.
- `doctor` — runtime availability (missing runtimes are listed under `warnings`), FTS5 self-test, storage info, `session_id`.

### ctx_bg — background process supervision (from `ctx_run action=execute background:true`)

- `list` — registered jobs (id/pid/age/exit_code/log availability).
- `kill` — by `id` or `pid`; PID-reuse guarded via the process starttime read from `/proc/<pid>/stat`.
- `log` — `id`/`pid`, `tail_lines` (≤10000), `tail_bytes` (≤4MB); newest output (ring-capped at 16MB), with `log_truncated` when the cap fired.
- `wait` — `id`/`pid`, `timeout_ms` (default 60000, max 1h); never kills on timeout; includes `log_truncated` when the log cap fired.
- Max 16 concurrent background jobs (exceeding is an error); a caller-provided `timeout_ms` on the launch is honored (default max age 1h); log files capped at 16MB.
- Platform contract: the `kill` identity check reads `/proc/<pid>/stat` (Linux). On platforms where that file is unavailable the check fails closed — a job with unknown identity is never signaled — so `ctx_bg` termination is only guaranteed on Linux; `list`/`log`/`wait` keep working everywhere.

## Database

Each primary workdir gets its own SQLite database at `~/.local/share/ctxmode/<hash>-<basename>/context_mode.db`, where `<hash>` is the first 8 bytes of SHA-256 over the primary workdir's absolute path. The on-disk path is opened as a `file:` URI with special characters (`%`, `?`, `#`, spaces) percent-encoded, so a basename or `CTXMODE_DB` containing those characters does not get parsed as URI syntax. Documents indexed in one project are never searchable from another. `CTXMODE_DB` overrides the location entirely. The legacy global shared database (`~/.local/share/ctxmode/context_mode.db`) is **no longer used and is not migrated automatically**.

## Deployment

The agent runs `deploy.sh` directly: the script is non-interactive, needs no confirmation and has **no manual step**. `deploy.sh` builds the binary, verifies it with an `initialize` handshake, and atomically replaces the live binary. Right before the atomic swap it backs up the current live binary to `<BINARY>.prev` (best-effort; a failed backup only disables rollback for that deployment).

The same run also syncs the Pi extension through `integrations/pi/install.sh` (md5-identical target left untouched; destination `PI_CTXMODE_EXT` or `~/.pi/agent/extensions/ctxmode.ts`); a failed sync aborts the deployment, matching the script's existing hard-failure convention.

```bash
./deploy.sh            # build + verify + atomic deploy (default)
./deploy.sh rollback   # restore the previous binary
```

`rollback` runs the same `initialize` verification against `<BINARY>.prev` and only then atomically renames it back over `<BINARY>`, printing the restored version. If `<BINARY>.prev` is missing (no prior deploy, or already consumed by a previous rollback), or verification fails, it exits 1 without touching the live binary. A successful rollback consumes `.prev`; deploying again recreates the backup.

### Backups

A weekly cron job (root, Sunday 06:00 UTC) snapshots every `context_mode.db` under the data root via `sqlite3 .backup` (consistent even while the server is writing), runs `PRAGMA integrity_check` on each snapshot, gzips it, and keeps the last 4 weekly sets in `/root/backups/ctxmode/<YYYY-MM-DD>/<hash>-<basename>.db.gz`. The script lives at `/root/backups/ctxmode/backup-ctxmode.sh` and logs to `/var/log/ctxmode-backup.log`.

To restore one project's KB:

```bash
gzip -dc /root/backups/ctxmode/<date>/<hash>-<basename>.db.gz > /tmp/restore.db
sqlite3 ~/.local/share/ctxmode/<hash>-<basename>/context_mode.db ".restore '/tmp/restore.db'"
# or: stop ctxmode, replace context_mode.db with the snapshot, start ctxmode again
```

## License

Elastic License 2.0 (ELv2) — see [LICENSE](LICENSE). Based on original TypeScript work by Mert Koseoglu.
