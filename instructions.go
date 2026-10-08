package main

// serverInstructions is sent in MCP initialize so agents learn the playbook once.
const serverInstructions = `# ctxmode — context virtualization for agent tool output

ctxmode runs code, inspects files and git, and virtualizes large output into a
local knowledge base to save context tokens. Six tools; five take a required
action argument (ctx_stats takes none).

## Tool map (action)

- ctx_run: PRIMARY for commands/tests/builds. execute (shell/code; prefer argv),
  execute_file (code over FILE_CONTENT), batch (many commands + optional
  queries), run_task (go_test|go_build|go_vet|npm_test|npm_run_build|
  cargo_test|cargo_build|make|custom; fixed argv). Large output auto-indexed.
- ctx_fs: sandboxed workspace filesystem. ls (list), glob (pattern), stat
  (metadata), rg (content search), resolve (fuzzy-ranked file lookup from an
  approximate/@-style path), related (files related to a given file: test/impl
  pairs, same stem, siblings). Prefer over ad-hoc shell find/ls/rg.
- ctx_git: read-only git. status (porcelain -b), diff (path/stat/staged), log
  (n/path/oneline). No commit/push/reset.
- ctx_kb: local knowledge base. index (path), search (query), fetch
  (URL→markdown→index), stats, purge (confirm:true), doctor (install check).
- ctx_bg: background processes from ctx_run action=execute background:true. Starting a background job returns immediately and never proactively pushes notifications. After receiving its id, call ctx_bg action=wait once by id or pid (blocking this tool call; default 60000ms, maximum 1 hour; timeout does not kill). Completed results remain wait-addressable through a bounded handoff window even if the detailed registry entry is pruned; after that window the id is unknown. id and pid are mutually exclusive. kill terminates (and wakes waiters); repeated wait is a stable read of the same terminal result, while repeated kill or kill of a completed/expired id returns no-match.
- ctx_stats: context-consumption statistics for the session: per-tool call counts, bytes returned to the context window, estimated tokens, and bytes kept out of it by auto-indexing into the KB store (every KB write path is covered: oversized ctx_run output, ctx_fs rg auto-index, ctx_kb index, ctx_run action=batch, ctx_kb fetch, legacy migration). No action argument; pass
  json:true for machine-readable output.

## Usage policy

- Prefer argv over shell command strings; prefer ctx_fs over shell find/ls/rg.
- ctx_run execute command (language shell/unset) and batch commands run via a fixed, controlled /bin/sh -c (the SHELL variable is ignored; there is no command allowlist). argv is exec'd directly, with no shell in between (so no shell-injection surface) and no path fence: any executable path or bare name the server user can run is allowed. The command screen logs (does not block) a few hostile-looking patterns and hard-blocks only a NUL byte or a command >64KiB; in argv mode a NUL byte in an argument is blocked and an over-length argv is only warned about. Every ctx_run call (all four entry points, one line per CALL — not per spawned subprocess) appends a record to a local audit log (CTXMODE_AUDIT_LOG, default /root/.local/state/ctxmode/audit.jsonl); nothing else is audited, and an unwritable or non-regular-file target is refused with a log line while the call itself still runs.
- rg: search with a concrete identifier (e.g. MyFunc), never '.*' — grep is not a file reader.
- rg: after 1-2 greps, Read the top-hit file instead of grepping again.
- rg: for huge result sets use ctx_kb action=search or ctx_fs rg offset paging.
- Big outputs are auto-indexed: search ctx_kb instead of re-running.
- Mutating: ctx_run (executes code/commands), ctx_kb index/fetch/purge (writes
  the local KB), ctx_bg kill. Everything else is read-only.
- NOT a sandbox: commands and code run with the server process's privileges;
  no security boundary. Use only in trusted environments.

## Host notes

- Tool names: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg, ctx_stats; action is a
  required argument for all but ctx_stats (e.g. ctx_fs action=ls path=.).
- Grok prefixes the server name onto tool names; pi registers the same tool
  names directly.
`
