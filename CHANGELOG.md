# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

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
