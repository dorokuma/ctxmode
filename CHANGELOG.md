# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

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
- Sandbox execution (12 languages): javascript, typescript, python, shell, go, rust, php, perl, ruby, r, elixir, csharp
- Web page fetch and convert to Markdown for indexing
- Flood guard
- Background execution support
