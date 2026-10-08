---
status: active
superseded_by: ""
supersedes: ""
模块: stats, store, router, integrations/pi
---

# 2026-10-08 — kept-out 记账下沉到 Store；ctx_kb stats 字段改为 kept_out_bytes；ctx_stats 注册进 Pi

## 一句话结论
- 把 `ctx_stats` 的 kept-out 记账从 `storeIndexLocked` 这个「汇合点」下沉到 `Store` 本身（新增可选回调 `Store.onIndexedBytes`），一处覆盖**全部** KB 写路径：`ctx_run action=batch` 的直存 `Store.Index` 与 `ctx_kb action=fetch` 的 `Store.ReplaceExactAndChunks` 分块写不再漏计。
- `ctx_kb action=stats` 的 `saved_estimate_bytes`（= `totalOutput-totalInput`，把「原样全量返回的输出」也当成节省，虚高）改为 `kept_out_bytes`（本会话 kept-out 合计，与 `ctx_stats` 的 `total_kept_out` 同值）；`total_input_bytes`/`total_output_bytes` 保留为原始计数器。
- `ctx_stats` 此前只在 Go MCP 面注册、却已被 `instructions.go`/`README.md` 广告——本轮补进 Pi 扩展（`getTools()` 与 `pi.registerTool`）。

## 背景
- 触发：`175eb05` 的三方审计遗留项清单（`.agents/notes/20261007-175eb05-audit-residuals.md`）第 7 项把「kept-out 只统计经过 `storeIndexLocked` 的路径」记为**既定口径、保留不修**，并给出处方：若将来要全覆盖，应把记账下沉到 `Store`。本轮执行该处方，并顺带修掉同一次审计里被点名的 `saved_estimate_bytes` 口径错误。
- 两处缺口的事实：`batch.go` 的超限输出走 `s.store.Index(...)` 直存，`fetch.go` 经 `indexContentLocked` → `Store.ReplaceExactAndChunks` 分块原子替换；二者都绕开 `storeIndexLocked`，旧实现下 `ctx_stats` 的 `store` 行为空。
- 另一个事实：`ctx_stats` 在 `router.go` 注册，`instructions.go` 与 `README.md` 已把它写进模型可见的说明，但 `integrations/pi/ctxmode.ts` 的 `getTools()` 与 `registerTools` 都只有五个工具，Pi 侧模型实际调不到它。

## 决策
1. **记账点：`Store` 层，不是 `storeIndexLocked`**。`Store` 新增 `onIndexedBytes func(int)`，在 `Store.Index`（记入参 `content` 长度）与 `Store.ReplaceExactAndChunks`（记各 chunk 长度之和）**成功提交后**调用；两处都在 `neutralizeDefMarker` 改写**之前**取长度，避免记账值受改写影响（改写最多加 1 字节/文档）。`main` 经新增的 `server.attachStore(store)` 注入 `s.statRecordKeptOut("store", n)`，`storeIndexLocked` 内的记账调用删除以免双重计数。
2. **口径不变的部分**：仅成功写入才记；失败/被 `checkSensitiveContent` 拒绝时不记（`ReplaceExactAndChunks` 在同一个循环里先校验后累加，任一 chunk 被拒即整笔返回，不记）；归到伪工具行 `store`；回调为 nil 时静默不记（测试与 CLI 路径构造的 `Store` 不受影响）。
3. **`statsResult` 字段**：`SavedEstimateBytes int64 \`json:"saved_estimate_bytes"\`` → `KeptOutBytes int64 \`json:"kept_out_bytes"\``，取值从 `statTools` 汇总（持 `statMu`）。`total_input_bytes`/`total_output_bytes` 保留，注释与 `ctx_kb` 工具描述写明它们是命令原始字节、不是节省量。
4. **Pi 扩展**：`getTools()` 加 `"ctx_stats"`；`registerTools` 新增 `pi.registerTool`，字段样式对齐既有五工具，`parameters` 为 `{ json?: boolean }`，`execute` 走 `run("ctx_stats", params, signal)`；`timeoutForTool` 走默认分支。

## 被放弃的方案（必填）
- **方案 A：把 batch/fetch 的写库并入 `storeIndexLocked`**。否决：batch 需要逐命令 label 与 `IndexError` 回填，fetch 需要分块原子替换并保留旧文档，二者的事务/标签语义与 `storeIndexLocked` 不同；硬并入会改写该函数语义，且仍要逐个核对 11 个调用点。下沉到 `Store` 只改两处写方法，覆盖面更大。
- **方案 B：在 `batch.go` 与 `fetch.go` 各自补一次 `statRecordKeptOut` 调用**。否决：仍是「按调用点枚举」的思路，下一个绕过 `storeIndexLocked` 的写路径会再次漏计；且 fetch 的记账点要落在事务成功之后，散落两处容易与事务边界脱节。
- **方案 C：只改文档、不动计数**（即维持第 7 项的「保留不修」）。否决：本轮明确要求统一口径；且 `saved_estimate_bytes` 是**语义错误**（不是覆盖不足），文档改不掉虚高的数字。
- **方案 D：保留 `saved_estimate_bytes` 字段名、只改取值**。否决：同名不同义会让既有读者把「kept-out 合计」继续读成「output-input 估算」，字段名本身就是错误口径的一部分。
- **方案 E：给 Pi 的 `ctx_stats` 加自定义超时分支**。否决：该工具只做本地聚合，默认分支足够，加分支属无依据的复杂度。

## 来源
- 任务：统一 `ctx_stats` 记账口径（记账下沉 + 字段修正 + Pi 扩展注册），标记 `[MARK-CTXSTATS-C-20261008]`。
- 代码位置（改动后）：`store.go:37-52`（`onIndexedBytes` 字段与 `recordIndexedBytes`）、`store.go:276-277`、`store.go:316`（`Index` 取长与调用）、`store.go:897-901`、`store.go:961`（`ReplaceExactAndChunks` 取长与调用）；`main.go:80-93`（`attachStore`）、`main.go:194`（注入点）、`main.go:809-830`（`statsResult`）、`main.go:847-869`（`toolStats` 汇总）、`main.go:1851-1862`（`storeIndexLocked` 注释，记账已移出）；`stats.go:55-68`、`stats.go:82-84`；`router.go:299-301`、`router.go:313`；`instructions.go:25-27`；`integrations/pi/ctxmode.ts:610`、`:916-931`。
- 回归测试（`stats_test.go`）：`TestStoreLayerKeptOutCoversBatchDirectIndex`、`TestStoreLayerKeptOutCoversFetchChunks`、`TestToolStatsKeptOutBytesIsKeptOutTotal`——三条均先在改动前的源码上实测 FAIL（batch/fetch 探针看不到 `store` 行；`ctx_kb action=stats` 对 100000/1000 的 output/input 返回 `saved_estimate_bytes: 99000`），改动后 PASS。Pi 侧 `integrations/pi/ctxmode.test.ts` 新增「ctx_stats 已注册且列入 getTools()」，同样在改动前的 `ctxmode.ts` 上实测 FAIL（`ctx_stats 已注册` / `getTools() 必须包含 ctx_stats`）。
- 沿革：本笔记**仅**取代 `.agents/notes/20261007-175eb05-audit-residuals.md` 第 7 项的结论（该笔记的其余六条观察仍为 active 遗留清单，故不整体置 `status: superseded`）；该笔记第 7 项末尾已追加订正条目，`20261007-port-features-from-originals.md` 的对应订正行也追加了再订正标注。
