# ctxmode

A 100% NPM/NodeJS-free, Go implementation of Mert Koseoglu's [context-mode](https://github.com/mksglu/context-mode).

Local-first Model Context Protocol (MCP) server that virtualizes tool outputs, allowing AI coding agents to execute heavy tasks and save up to 98% in token usage.

Current version: **1.1.1**.

## Pi integration

A Pi-specific TypeScript adapter is maintained in [`integrations/pi/`](integrations/pi/README.md). The Go binary remains a generic stdio MCP server. The adapter handles Pi lifecycle and tool registration without injecting fixed tool instructions into the system prompt.

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

## Tools (9)

- **ctx_execute** — 12-language sandbox (JS/TS/Python/Go/Rust/PHP/Perl/Ruby/R/Elixir/CSharp/Shell)
- **ctx_execute_file** — inject file content into sandbox as FILE_CONTENT
- **ctx_index** — index files/directories into SQLite FTS5
- **ctx_search** — full-text search (BM25 + Porter + Trigram + RRF + proximity rerank)
- **ctx_fetch_and_index** — fetch URL → convert to markdown → index (SSRF protection + TTL cache)
- **ctx_batch_execute** — run N commands concurrently, auto-index output, search
- **ctx_stats** — document/cache/DB statistics
- **ctx_doctor** — runtime availability, FTS5 self-test, storage info
- **ctx_purge** — delete indexed content (project or session scope)

## License

Elastic License 2.0 (ELv2) — see [LICENSE](LICENSE). Based on original TypeScript work by Mert Koseoglu.
