# Pi integration

Thin bridge: Pi has **no MCP client**. This extension spawns the `ctxmode`
binary (MCP over stdio, internal only) and registers five **native Pi tools**
(`ctx_run`, `ctx_fs`, `ctx_git`, `ctx_kb`, `ctx_bg`). Requires **ctxmode ≥ 2.0.0**.

```bash
go build -o ctxmode .
install -m 755 ctxmode ~/.local/bin/ctxmode
install -m 644 integrations/pi/ctxmode.ts ~/.pi/agent/extensions/ctxmode.ts
```

建议直接用仓库自带的 `deploy.sh` 一键部署（编译 → 原子替换到 `~/.local/bin`，
并同步 Pi 扩展到 `~/.pi/agent/extensions/`），不要手动 install，避免装到
别处造成版本分叉。

`deploy.sh` 末尾的 Pi 扩展同步由独立脚本 `integrations/pi/install.sh` 完成
（也可单独执行验证）。其契约：

- 目标为 **`~/.pi/agent/extensions/ctxmode.ts` 文件路径**（可用
  `PI_CTXMODE_EXT` 覆盖，路径语义与 deploy.sh 既有口径一致）；
- **幂等**：目标与源 md5 一致时报告 `unchanged` 且不重写（不动 mtime）；
- md5sum 缺失、`HOME` 未设置（且未指定 `PI_CTXMODE_EXT`）、目标为目录或非
  绝对路径、源/目标 md5 取空——一律显式报错并非零退出；
- 同步失败时 `deploy.sh` **硬失败退出**（沿用本仓既有约定：扩展不过，
  部署不算完成）。

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
- `PI_CTXMODE_EXT` — 部署时 Pi 扩展的目标文件路径（默认
  `~/.pi/agent/extensions/ctxmode.ts`；`deploy.sh` 与
  `integrations/pi/install.sh` 共用此变量，必须是绝对路径）

Handshake 失败（`initialize` / `tools/list`）会回收已 spawn 的子进程。`callTool` 遇到 disconnect / not running 时可以拉起客户端，但不会自动重放刚才那次 `tools/call`（execute/batch 非幂等）。

## Esc / 取消语义

用户按 Esc 时 Pi 只会本地中止这一轮（`session.abort()`），并把 `AbortSignal`
传给扩展工具。桥现在把这个 signal 透传给 ctxmode：abort 时向前一个 `tools/call`
补发 `notifications/cancelled`（requestId 对得上，且一定晚于请求行本身，否则取消
落空），ctxmode 的 handler ctx 随之取消，`runCmd` 的 `ctx.Done` 分支对进程组两段式
kill，子进程跟着请求一起结束——注意取消只覆盖前台请求：`execute` 带
`background: true` 拉起的后台进程不受取消影响（它已不隶属于这个前台请求），按
max age（默认 1h）回收，要提前结束得走 `ctx_bg`。同时本地立即拒绝等待，不再空等到客户端超时。
客户端超时（`CTXMODE_REQUEST_TIMEOUT_MS` 等）同样会先发取消——否则服务端任务会
变成孤儿进程，一路跑到默认预算（execute 30s / run_task 5min / background 1h）。

## 停止语义

`stop()`（`/ctxmode-stop`、`session_shutdown`、Pi 退出都会调用）对 client 是终态：
之后再调 `start()` 一律拒绝、不会拉起进程。这条堵的是一个竞态：在途 `tools/call`
被 `cleanup()` 以 `ctxmode disconnected` 拒绝后，`callTool` 的重连分支会去调
`start()`，而旧实现无条件把 `stopped` 复位，于是本该退出的进程又被拉起一个，且
扩展侧 `client` 已置 null，谁都管不到它（实测：2 个 spawn，第二个存活）。

显式启动（`/ctxmode-start`、`session_start`）总是新建 `CtxmodeClient`；进程崩溃后的
自动重连 `stopped` 仍为 false，兜底能力不受影响。

## Tests

零新增依赖（node:test + `--experimental-strip-types`，Node ≥ 22.15）：

```bash
node --experimental-strip-types --test integrations/pi/*.test.ts
```

版本下限由 `node:module` 的 `registerHooks` 卡住：测试用它把 `typebox`
解析到内置 stub（本机无 node_modules），该 API 自 Node 22.15.0 才可用
（官方文档 Added in: v22.15.0 / v23.5.0）；`--experimental-strip-types`
（v22.6.0 起）与 `node:test` 的 mock（v18.13.0 起）要求都低于它，故取 22.15。
