# 2026-10-07 — Feature port from the original upstreams (context-mode / pi-fff)

## 背景

按任务要求，将两个原版项目的有用功能 cherry-pick 进 ctxmode：

- **原版 1**：[mksglu/context-mode](https://github.com/mksglu/context-mode)（TypeScript MCP 服务器，本仓 README 的 "Based on original TypeScript work by Mert Koseoglu" 即指它）。克隆于 eqi12 `/tmp/upstream/context-mode`（v1.0.169）。
- **原版 2**：[ShpetimA/pi-fff](https://github.com/ShpetimA/pi-fff)（pi 扩展：模糊文件解析、`@` 引用补全、FFF 索引内容搜索，powered by `@ff-labs/fff-node`）。克隆于 eqi12 `/tmp/upstream/pi-fff`（v0.1.13）。

## 已移植（3 项）

1. **`ctx_stats`**（新只读 MCP 工具，`stats.go`）— 来自 context-mode 的同名工具。本仓已有 audit JSONL（`audit.go`）与 `storeIndexLocked` 入库口径，统计功能只差聚合层：
   - `router.go` 的 `counted()` 泛型包装器包住全部 6 个工具 handler，按响应 `TextContent` 字节数记入 `server.statTools`（新字段 `statMu`/`statTools`/`startedAt`）。
   - `storeIndexLocked` 成功后把入库字节数记入伪工具行 `store` —— 全部索引路径（rg 超限入库、run 输出截断入库、kb index/fetch）的唯一汇合点，一处插桩覆盖 11 个调用点。
   - **订正（2026-10-07 后补标注，原文不改）**：上面「全部索引路径（…kb index/fetch）的唯一汇合点」这一表述已被 `.agents/notes/20261007-175eb05-audit-residuals.md` 的「既定口径」项订正——kept-out 只统计**经过 `storeIndexLocked` 的索引汇合点**的路径；`ctx_run action=batch` 的超限直存（直接调 `Store.Index`）与 `ctx_kb fetch`（`indexContentLocked` → `Store.ReplaceExactAndChunks`）**不经该汇合点、不计入**。
   - `aggregateAuditLog` 按当前 `session_id` 过滤 audit JSONL，给 lifetime 视图（calls/output/indexed/truncated）。超长行跳过而非整体失败。
   - token 估算 bytes÷4，与 context-mode 相同口径。
2. **`ctx_fs action=resolve`**（`fs_resolve.go`）— 来自 pi-fff 的 `resolve_file`。模糊排序：exact > suffix > basename substring > path substring > 有序子序列；路径边界（`/_-.`）加分、连续段加分、span 归一化防“散落在长路径里的短查询”逆袭。`@path` 风格与引号包裹的输入均接受。
3. **`ctx_fs action=related`**（`fs_resolve.go`）— 来自 pi-fff 的 `related_files`。stem 先剥 `_test.go`/`.test.ts`/`.spec.ts`/`test_*.py` 标记再比较，测试/实现跨目录配对拿最高分（100），之后依次是同族同 stem（90）、异扩展同 stem（70）、同目录 sibling（40）、stem 前缀（30），每条带 `reason`。

两个 ctx_fs 新动作复用 glob 遍历的全部围栏（`skipWalkDirs`、`.gitignore` 层、符号链接围栏、敏感路径闸门），加 5s 墙钟预算与 10 万文件上限（同 rg 的墙钟预算模式）。

## 明确不移植（及原因）

- **`ctx_insight`**：跳外部仪表盘 URL，纯外部副作用，与本仓无数据库后台的定位冲突。
- **`ctx_upgrade`**：本仓由 `deploy.sh` 全权负责编译与原子替换，无二进制自更新需求。
- **auto-memory / retrieval-marker / hooks 桥**：context-mode 的这些模块依附其 Claude-Code-hook 管线（PostToolUse、tmp marker 握手），本仓无此架构；instruction 文件已由 `instructions.go` 覆盖。
- **fff-node 依赖**：pi-fff 的搜索引擎是 Rust 原生库的 Node 绑定，触碰“零 Node 依赖”铁律，故 resolve/related 用纯 Go 重实现（内容搜索已有 rg + KB FTS5，无需再造）。

## 排查记录：MCP 冒烟计数为 0

首次冒烟（请求一次性灌入 stdin）中 `ctx_stats` 读到空 map。加临时 stderr 日志定位：go-sdk v1.6.1 对并发 `tools/call` 各起 goroutine，`ctx_stats` 的 handler 在 `ctx_run` 的 `counted()` 记账之前执行（日志 `read tools=map[]` 先于 `record ctx_run`）。机制无误，是冒烟脚本时序问题；顺序请求（每次 sleep 1s）后计数正确（1 call / 12B / 3 token）。此并发语义已写入 README 的 ctx_stats 段。

另：调试期间一次 `gofmt -l .` 在 ssh 默认家目录执行，扫遍 `/root`（含 go mod cache）耗时且刷屏，并误拷 `/root/stats.go`（已删）。教训：远程命令必须显式 `cd ~/workspace/ctxmode`。

## 验证

- `go vet ./...`、`go test ./...` 全量通过（含新增 `fs_resolve_test.go`、`stats_test.go`）。
- MCP 冒烟：initialize → tools/list 六工具齐全 → `resolve` 命中 `sub/c.go`（score 95）→ `related` 正确配对 `user.go` ↔ `user_test.go`（score 100）→ `ctx_stats` 文本/JSON 双格式正常。
