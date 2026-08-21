package main

// serverInstructions is sent in MCP initialize so agents learn the playbook once.
const serverInstructions = `# ctxmode — context virtualization for agent tool output

ctxmode runs code, inspects files and git, and virtualizes large output into a
local knowledge base to save context tokens. Five tools; each takes a required
action argument.

## Tool map (action)

- ctx_run: PRIMARY for commands/tests/builds. execute (shell/code; prefer argv),
  execute_file (code over FILE_CONTENT), batch (many commands + optional
  queries), run_task (go_test|go_build|go_vet|npm_test|npm_run_build|
  cargo_test|cargo_build|make|custom; fixed argv). Large output auto-indexed.
- ctx_fs: sandboxed workspace filesystem. ls (list), glob (pattern), stat
  (metadata), rg (content search). Prefer over ad-hoc shell find/ls/rg.
- ctx_git: read-only git. status (porcelain -b), diff (path/stat/staged), log
  (n/path/oneline). No commit/push/reset.
- ctx_kb: local knowledge base. index (path), search (query), fetch
  (URL→markdown→index), stats, purge (confirm:true), doctor (install check).
- ctx_bg: background processes from ctx_run action=execute background:true. Starting a background job returns immediately and never proactively pushes notifications. After receiving its id, call ctx_bg action=wait once by id or pid (blocking this tool call; default 60000ms, maximum 1 hour; timeout does not kill). Completed results remain wait-addressable through a bounded handoff window even if the detailed registry entry is pruned; after that window the id is unknown. id and pid are mutually exclusive. kill terminates (and wakes waiters); repeated wait is a stable read of the same terminal result, while repeated kill or kill of a completed/expired id returns no-match.

## Usage policy

- Prefer argv over shell command strings; prefer ctx_fs over shell find/ls/rg.
- Big outputs are auto-indexed: search ctx_kb instead of re-running.
- Mutating: ctx_run (executes code/commands), ctx_kb index/fetch/purge (writes
  the local KB), ctx_bg kill. Everything else is read-only.
- NOT a sandbox: commands and code run with the server process's privileges;
  no security boundary. Use only in trusted environments.

## Host notes

- Tool names: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg; action is a required
  argument (e.g. ctx_fs action=ls path=.).
- Grok prefixes the server name onto tool names; pi registers the same tool
  names directly.
`
