# ctxmode

A 100% NPM/NodeJS-free, Go implementation of Mert Koseoglu's [context-mode](https://github.com/mksglu/context-mode).

Local-first Model Context Protocol (MCP) server that virtualizes tool outputs, allowing AI coding agents to execute heavy tasks and save up to 98% in token usage.

Current version: **3.1.2**.

Supported platform: **Linux**. Background process identity verification reads `/proc/<pid>/stat`; on other platforms ctxmode still runs, but `ctx_bg` termination is not promised (see [ctx_bg](#ctx_bg--background-process-supervision-from-ctx_run-actionexecute-backgroundtrue)).

## MCP tools (v2)

Five real tools (not skills). Each takes **`action=`** plus capability-specific fields:

| Tool | Actions | Key parameters |
|------|---------|----------------|
| **ctx_run** | `execute`, `execute_file`, `batch`, `run_task` | `command`/`language`/`timeout`/`background`/`intent`/`cwd`/`argv`/`env`/`stdin`; `path`+`code`; `commands`/`queries`/`concurrency`/`query_scope`; `kind`/`target`/`args`/`timeout_ms` |
| **ctx_fs** | `ls`, `glob`, `stat`, `rg` | `path`/`depth`/`include_hidden`/`limit`; `pattern`/`path`/`limit`; `path`; `pattern`/`glob`/`ignore_case`/`context`/`literal` |
| **ctx_git** | `status`, `diff`, `log` | `cwd`; `path`/`stat`/`unified`/`staged`; `n`/`path`/`oneline` |
| **ctx_kb** | `index`, `search`, `fetch`, `stats`, `purge`, `doctor` | `path`; `query`; `url`/`urls`/`source`/`format`/`force`/`maxBytes`/`timeoutMs`/`ttl`; —; `confirm`/`scope`/`sessionId`/`dryRun`; — |
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
  - /tmp
```

`workdirs` defines the workspace roots; every `cwd`/`path` argument is resolved against them (see Tools below). See [`config.example.yaml`](config.example.yaml).

Environment variables:

- `CTXMODE_DB` — absolute path to the SQLite database file; takes priority over the per-workdir default (see Database).
- `CTXMODE_CONFIG` — path to the YAML config file.
- `CTXMODE_ENV_PASSTHROUGH=1` — disable the default stripping of sensitive variables from subprocess environments (see [Subprocess environment isolation](#subprocess-environment-isolation)).

## Security model — NOT a sandbox

ctxmode executes arbitrary commands and code **with the server process's privileges**. There is no sandbox and no security boundary: nothing stops `ctx_run` from running any shell/argv/code, and interpreters can perform any action the server user can. **Run ctxmode only in trusted environments.**

The following are defense-in-depth measures, never a security guarantee:

- Subprocess environments strip inherited variables whose names look sensitive (`token`, `key`, `secret`, `password`, `passwd`, `credential`, `auth`, `cookie`, `session`, case-insensitive) by default; `CTXMODE_ENV_PASSTHROUGH=1` disables this. Caller-provided `env` overrides truly replace same-named inherited variables (deduplicated map, not appended duplicates), and the allowlist still rejects `PATH`/`HOME`/`SHELL`/`LD_*`/`DYLD_*` etc.
- Indexing skips secret-like files by default: `.env`/`.env.*`, anything under a `.env/` directory, private keys (`*.pem`, `*.key`, `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`), `credentials.json`, `.npmrc`, `.netrc`, and anything under `.aws`/`.ssh`/`.gnupg`/`.kube`.
- `ctx_kb action=fetch` refuses SSRF targets: IPv4 and IPv6 loopback, link-local (169.254.0.0/16, fe80::/10), multicast, reserved, private (RFC 1918, fc00::/7), CGNAT and benchmark ranges. Embedded IPv4 in IPv6 (IPv4-mapped, IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) is decoded and checked against the same IPv4 list. The blocklist is a single fixed set: the former strict/non-strict split was removed (`CTX_FETCH_STRICT` no longer exists) and the intercepted set cannot be changed via the environment.

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

- `execute` — 12-language subprocess execution (`javascript`, `typescript`, `python`, `shell`, `go`, `rust`, `php`, `perl`, `ruby`, `r`, `elixir`, `csharp`). `command` runs via shell (default language); `argv` execs directly without a shell (preferred). `env` (allowlist-validated), `stdin` (≤1MB), `timeout` (ms, max 1h), `background` (supervise via ctx_bg), `intent`, `cwd` (workdir-resolved). Output >100KB is auto-indexed (with `intent`, >5KB too).
- `execute_file` — `path` + `code`: file content is injected as `FILE_CONTENT` and the code processes it. Files ≤10MB; binary files refused.
- `batch` — `commands` (≤50, non-empty unique labels), `queries` (≤20), `concurrency` (1-8, default 1; out-of-range is an error), `query_scope` (`batch`|`global`, default `batch`; invalid is an error), `cwd`, `timeout` (default 30s, max 1h; serial: shared budget, concurrent: per-command). Only output >100KB is indexed (same threshold as `execute`); small output is not persisted. `query_scope=batch` searches only this run's indexed command output.
- `run_task` — structured test/build with fixed argv (no shell): `kind` ∈ `go_test`|`go_build`|`go_vet`|`npm_test`|`npm_run_build`|`cargo_test`|`cargo_build`|`make`|`custom`, `target`, `args`, `timeout_ms` (default 300000, max 3600000), `cwd`, `intent`, `env`. `custom` requires `args[0]` as the executable.

### ctx_fs — workspace filesystem (paths limited to workdirs)

- `ls` — list directory: `path`, `depth` (1-5, default 1; >5 is an error), `include_hidden`, `limit` (default 200, max 2000; >2000 is an error).
- `glob` — `pattern` (`**` supported), `path`, `limit` (default 200, max 2000; >2000 is an error); skips `.git`/`node_modules`/`vendor` and applies basic `.gitignore` rules.
- `stat` — `path`: size/mode/mtime/symlink/workdir metadata (symlink-aware).
- `rg` — content search: `pattern` (or `literal`), `path`, `glob`, `ignore_case`, `context` (0-5), `limit` (default 50, max 500; >500 is an error); system `rg` with `--no-config` (ignores `RIPGREP_CONFIG_PATH` / `~/.ripgreprc`) and a pure-Go fallback; skips binaries.

### ctx_git — read-only git (no commit/push/reset)

- `status` — `git status --porcelain=v1 -b` (`cwd`).
- `diff` — `path`, `stat`, `staged`, `unified`; output hard-truncated (200KB/2000 lines).
- `log` — `n` (default 20, hard max 100), `path`, `oneline` (default).

### ctx_kb — local knowledge base

- `index` — `path` (file or directory) into SQLite FTS5; skips `.git`/`node_modules`, sensitive/secret files, binaries and >1MB files; capped at 5000 files / 100MB total.
- `search` — `query`: BM25 + Porter + Trigram + RRF + proximity rerank; flood-guarded. `ctx_run` batch `query_scope=batch` searches only that batch run's indexed documents and bypasses the guard; it does not search `execute`/`run_task`/fetch output.
- `fetch` — `url`/`urls` (≤10) → markdown → index; `source`, `format` (markdown/html/json), `force`, `maxBytes` (default 50KB), `timeoutMs` (default 150000), `ttl` (default 24h, 0 = skip cache); SSRF protection as above. Indexed documents are isolated per `format`: the KB path embeds the format (`source:format:url`), so the same URL can coexist as markdown/html/json without overwriting, and re-fetching in one format never touches the others. Re-fetching a short URL does not delete a longer sibling URL.
- `stats` — document/cache/DB statistics, token-savings estimate, and `session_id` for this server process.
- `purge` — `confirm:true` is mandatory: missing or `false` returns an error (not a silent no-op). `scope=project` wipes the whole KB. `scope=session` deletes documents tagged with `sessionId` (the id from `stats`/`doctor`); execute/batch/run_task/fetch writes from this process are tagged automatically.
- `doctor` — runtime availability (missing runtimes are listed under `warnings`), FTS5 self-test, storage info, `session_id`.

### ctx_bg — background process supervision (from `ctx_run action=execute background:true`)

- `list` — registered jobs (id/pid/age/exit_code/log availability).
- `kill` — by `id` or `pid`; PID-reuse guarded via the process starttime read from `/proc/<pid>/stat`.
- `log` — `id`/`pid`, `tail_lines` (≤10000), `tail_bytes` (≤4MB); newest output (ring-capped at 16MB), with `log_truncated` when the cap fired.
- `wait` — `id`/`pid`, `timeout_ms` (default 60000, max 1h); never kills on timeout; includes `log_truncated` when the log cap fired.
- Max 16 concurrent background jobs (exceeding is an error); a caller-provided `timeout` on the launch is honored (default max age 1h); log files capped at 16MB.
- Platform contract: the `kill` identity check reads `/proc/<pid>/stat` (Linux). On platforms where that file is unavailable the check fails closed — a job with unknown identity is never signaled — so `ctx_bg` termination is only guaranteed on Linux; `list`/`log`/`wait` keep working everywhere.

## Database

Each primary workdir gets its own SQLite database at `~/.local/share/ctxmode/<hash>-<basename>/context_mode.db`, where `<hash>` is the first 8 bytes of SHA-256 over the primary workdir's absolute path. Documents indexed in one project are never searchable from another. `CTXMODE_DB` overrides the location entirely. The legacy global shared database (`~/.local/share/ctxmode/context_mode.db`) is **no longer used and is not migrated automatically**.

## License

Elastic License 2.0 (ELv2) — see [LICENSE](LICENSE). Based on original TypeScript work by Mert Koseoglu.
