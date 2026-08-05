# ctxmode

A 100% NPM/NodeJS-free, Go implementation of Mert Koseoglu's [context-mode](https://github.com/mksglu/context-mode).

Local-first Model Context Protocol (MCP) server that virtualizes tool outputs, allowing AI coding agents to execute heavy tasks and save up to 98% in token usage.

Current version: **2.0.0**.

## MCP tools (v2)

Five real tools (not skills). Each takes **`action=`** plus capability-specific fields:

| Tool | Actions |
|------|---------|
| **ctx_run** | `execute`, `execute_file`, `batch`, `run_task` |
| **ctx_fs** | `ls`, `glob`, `stat`, `rg` |
| **ctx_git** | `status`, `diff`, `log` |
| **ctx_kb** | `index`, `search`, `fetch`, `stats`, `purge`, `doctor` |
| **ctx_bg** | `list`, `kill`, `log`, `wait` |

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
  - /root
  - /tmp
policy:
  shell:
    mode: denylist   # denylist (default) | allowlist | off
    deny: [nmap, tcpdump]  # merged with built-in high-risk set
    deny_patterns: ['(?i)\bhydra\b']  # merged with built-in patterns
    rm:
      allow_in_workdir: true
      deny_system_paths: true
```

See [`config.example.yaml`](config.example.yaml). **`policy.shell.mode` defaults to `denylist`**: normal shell/argv commands run, while a built-in, auditable set of high-risk commands and patterns is refused. Set `mode: off` to fully disable the policy (escape hatch / legacy behavior) or `mode: allowlist` for hardened deployments (also the documented way to permit a built-in-denied command). Runtime override: `CTXMODE_POLICY_MODE=allowlist|denylist|off`.

### Shell policy (P3)

| Path | When checked |
|------|----------------|
| `ctx_execute` language=shell / command string | `CheckShell` before start |
| `ctx_batch_execute` | each command via `CheckShell` |
| `ctx_execute` argv / `ctx_run_task` | `CheckArgv` on `argv[0]` basename (same deny set/patterns as shell) |
| default `denylist` | built-in + user `deny` (basename, merged), built-in + user `deny_patterns`, rm path rules |
| mode=`allowlist` | first token of each `\|` / `&&` / `;` segment must be on `allow`; `deny_patterns` still apply |
| mode=`off` | all checks disabled (explicit escape hatch) |
| `deny_patterns` | full command regex (e.g. curl\|sh) when mode≠off, shell and argv |
| `rm` | targets resolved vs workdirs; `/` `/etc` denied; unparseable `$var`/globs denied |

Default `denylist` protections (merged with user `deny`, never replaced):

- Shutdown/reboot: `shutdown`, `reboot`, `poweroff`, `halt`, `init`, `telinit`
- Block device / filesystem destruction: `mkfs` and `mkfs.*`, `fdisk`, `sfdisk`, `cfdisk`, `parted`, `wipefs`, `dd`, `shred`
- Bulk firewall restore: `iptables-restore`, `ip6tables-restore`, `ebtables-restore`, `arptables-restore`
- Privilege escalation / identity switch: `su`, `sudo`, `doas`, `pkexec`
- Mutation subcommands are rejected for `ip`, `route`, `ifconfig`, `iptables`/`ip6tables`, `nft`, `systemctl`/`loginctl` power actions, and `sysctl` writes; read-only diagnostics such as `ip addr`, `ip route`, `iptables -L`, `nft list`, and `systemctl status` remain available
- Built-in `deny_patterns`: remote content piped through wrappers into `sh`/`bash`/`dash`/`zsh`/`ksh`, common fork-bomb literals, command substitution, and process substitution

Command-name matches use the basename after stripping wrappers (`env`, `nice`, `nohup`, `stdbuf`, `timeout`, `command`, `time`, `busybox`, `toybox`) — wrappers cannot bypass the policy, in shell or argv form. Ordinary dev/ops commands (`apt`/`apt-get`, `ping`, `curl`/`wget` downloads, `git`, `python`, `go`, `npm`, …) are **not** in the default deny set.

**Limitations — not a sandbox.** The denylist checks command *names* and literal patterns only. Interpreters (`python3`, `node`, `go`, …) are allowed, and nothing stops `python3 -c 'import os; os.system("shutdown -h now")'` — an interpreter's internal side effects cannot be expressed as a command name. The policy is a safety net against accidental high-risk commands, not a security boundary.

`rm -rf /root/...` is **allowed** when `/root` is a configured workdir (do not blanket-deny `/root`).

## Tools

- **ctx_execute** — 12-language subprocess execution (JS/TS/Python/Go/Rust/PHP/Perl/Ruby/R/Elixir/CSharp/Shell); optional **argv** (no shell), **env** (allowlist), **stdin** (≤1MB). Background mode supports argv/env/stdin. `ctx_batch_execute` does **not** support argv/env/stdin. Optional **shell policy** (default denylist; see above). This is not an OS security sandbox.
- **ctx_execute_file** — inject file content into sandbox as FILE_CONTENT
- **ctx_index** — index files/directories into SQLite FTS5
- **ctx_search** — full-text search (BM25 + Porter + Trigram + RRF + proximity rerank)
- **ctx_fetch_and_index** — fetch URL → convert to markdown → index (SSRF protection + TTL cache)
- **ctx_batch_execute** — run N commands concurrently, auto-index output, search
- **ctx_stats** — document/cache/DB statistics
- **ctx_doctor** — runtime availability, FTS5 self-test, storage info, policy mode
- **ctx_purge** — delete indexed content (project or session scope)
- **ctx_background_list / kill / log / wait** — supervise background `ctx_execute` jobs; capture and tail logs
- **ctx_ls** — list workspace directories (depth/limit/hidden; path limited to configured workdirs)
- **ctx_glob** — glob under workspace (`**` supported; skips `.git`/`node_modules`/`vendor` + basic `.gitignore`)
- **ctx_stat** — file metadata (size/mode/mtime/symlink/workdir)
- **ctx_rg** — content search (system `rg` or pure-Go fallback; skips binaries)
- **ctx_git_status** — `git status --porcelain=v1 -b` (read-only; non-repo error)
- **ctx_git_diff** — `git diff` with path/stat/staged/unified; hard-truncated 200KB/2000 lines
- **ctx_git_log** — `git log` (n default 20, hard max 100; oneline default). No commit/push/reset.
- **ctx_run_task** — structured test/build (`go_test`/`go_build`/`go_vet`/`npm_*`/`cargo_*`/`make`/`custom`); fixed argv no shell; cwd limited to configured workdirs; large output auto-indexed. Prefer over raw shell for CI-like tasks.

## License

Elastic License 2.0 (ELv2) — see [LICENSE](LICENSE). Based on original TypeScript work by Mert Koseoglu.
