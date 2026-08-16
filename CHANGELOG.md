# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
