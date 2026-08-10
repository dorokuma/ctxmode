# Pi integration

Thin bridge: spawn `ctxmode`, register the **same five MCP tools** on Pi
(`ctx_run`, `ctx_fs`, `ctx_git`, `ctx_kb`, `ctx_bg`). Requires **ctxmode ≥ 2.0.0**.

```bash
go build -o ctxmode .
install -m 755 ctxmode /usr/local/bin/ctxmode
install -m 644 integrations/pi/ctxmode.ts ~/.pi/agent/extensions/ctxmode.ts
```

`/reload` or restart Pi.

## Env knobs

- `CTXMODE_BIN` — 二进制路径（默认 `ctxmode`）
- `CTXMODE_WORKDIR` — 默认工作目录（默认会话 cwd）
- `CTXMODE_START_TIMEOUT_MS` / `CTXMODE_REQUEST_TIMEOUT_MS` — 启动/请求超时
- `CTXMODE_DEBUG` — 诊断同时打 stderr（会污染 TUI 输入行，仅调试用）
- `CTXMODE_DIAG_STDERR=1` — opt-in：诊断同时写 stderr（默认只写日志文件，保 TUI 干净）
- `CTXMODE_DIAG_DIR` — 诊断日志目录（默认 `~/.pi/agent/logs`）
- `CTXMODE_DIAG_MAX_BYTES` — 日志轮转体积上限（默认 5MB；超限轮转为 `ctxmode.log.1/.2`，最多两个历史）
- `CTXMODE_DISPOSE_WAIT_MS` — 换进程时 SIGTERM→SIGKILL 等待窗口（默认 3000ms）

## Tests

零新增依赖（node:test + `--experimental-strip-types`，Node ≥ 22.6）：

```bash
node --experimental-strip-types --test integrations/pi/ctxmode.test.ts
```
