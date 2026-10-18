---
status: active
superseded_by: ""
supersedes: ""
模块: stats, store, batch, fetch
---

# 2026-10-09 — kept-out 记账与字段改名两审遗留项清单（8 条，均不阻断放行）

## 一句话结论
- 分支 `fix/ctxstats-keptout-accounting`（HEAD `c3403ce`）的「记账下沉到 Store + `ctx_kb action=stats` 字段改名 + `ctx_stats` 注册进 Pi」经 reviewer 与 oracle 两审通过；两审留下的 8 条非阻断项（6 条 oracle 观察项 + 2 条 reviewer consider）逐条落盘于此，一条不丢，本轮**均判不阻断放行、均不修实现**。
- 这 8 条**均非本次改动引入的新缺陷**：第 1–4 条为既有语义或既有包装差额，第 5–6 条为既有口径观察，第 7–8 条为边界与兼容性提示。唯一需要外部动作的是第 8 条——`saved_estimate_bytes` → `kept_out_bytes` 是 MCP JSON 契约的破坏性变更，发版说明必须保留 BREAKING 级别措辞（本轮已在 `CHANGELOG.md` 的 `[Unreleased]` 与 `README.md` 的 `ctx_kb` `stats` 条目标注）。
- 落盘行号以本笔记写作时的当前工作区（`c3403ce`）为准，**不是两审报告所给行号**；逐条差异见「来源」末段。

## 背景
- 触发：本轮改动把 kept-out 记账从 `storeIndexLocked` 下沉到 `Store`（`Store.onIndexedBytes`，`store.go:37-54`），并改了 `ctx_kb action=stats` 的 JSON 字段（`saved_estimate_bytes` → `kept_out_bytes`，`main.go:823`），同时把 `ctx_stats` 注册进 Pi 扩展。两审（reviewer + oracle）判通过，但各留下若干「不阻断放行」的观察项与 consider 项，按仓库规范必须落盘，否则会随改动一起消失。
- 本笔记是**遗留清单**，不是新决策：8 条一律「记而不修」，每条写明位置（文件:行号）、触发条件、后果、处置与级别，供后续审计/复核参照，避免重复报告或误判为本次回归。
- 阅读前提：第 1、2、3、7 条涉及的行号在两审报告与当前源码之间有位移（本次改动本身把 `Index`/`ReplaceExactAndChunks` 的记账代码挪过位置），引用报告旧行号会找不到位置；以本笔记行号为准。
- 复核方式：8 条的机制均按当前源码逐条核对（`ctx_search_digest` + 直读），未运行任何探针程序；第 1 条的算术示例与第 4 条的包装差额按代码路径推导，未做端到端实测（不影响「不修」的结论，但实测证据缺失如实记于此）。

## 决策
总口径：**8 条全部记而不修，本轮不阻断放行**。逐条落在下面的「处置」里，理由分四类——(a) 既有语义，本次改动只是对齐口径（第 1 条）；(b) 既有提交/返回语义或既有包装差额，非本次引入（第 2、3、4 条）；(c) 既有口径观察，改动会牵动展示语义（第 5、6 条）；(d) 边界与兼容性提示，需保留措辞或仅需记录（第 7、8 条）。

### 8. consider｜`saved_estimate_bytes` → `kept_out_bytes` 是 MCP JSON 契约的破坏性变更
- **位置**：字段定义 `main.go:823`（`KeptOutBytes int64 \`json:"kept_out_bytes"\``，`statsResult` 结构体自 `main.go:809`）；README 说明 `README.md:147`（`ctx_kb` 的 `stats` 条目）；per-tool 快照的同名字段 `stats.go:34`。仓内除 `stats_test.go:174-175`（断言旧字段名必须消失）外无其它引用，已 grep 确认无仓内消费者。
- **触发条件**：仓外脚本/集成按旧字段名 `saved_estimate_bytes` 读取 `ctx_kb action=stats` 的 JSON 输出。
- **后果**：旧字段名不再返回，消费方取值为空或直接报错——属契约层面的不兼容。
- **处置**：本轮已落盘记录，并在 `CHANGELOG.md` 的 `## [Unreleased]` 该条目开头加 `**BREAKING:**` 标注、在 `README.md` 的 `stats` 条目写明旧字段名不再返回；**发版说明须保留 BREAKING 级别措辞**。
- **级别**：consider（reviewer）。

## 被放弃的方案（必填）
- **方案 A：把 8 条都当缺陷修掉**。否决：第 1、2、5、6、7 条是既有语义与既有口径（第 1 条还经用户裁决），改动会推翻已通过两审的实现口径并超出本轮「只做文档与笔记」的范围；第 3、4 条是 1 字节/前缀级差额，修了反而要重新定义「记账量以哪一版字节为准」。
- **方案 B：只写 CHANGELOG，不写笔记**。否决：仓库规范要求跨模块/口径类结论落盘到 `.agents/notes/`，且两审要求逐项记录位置、触发条件、后果与处置，CHANGELOG 的条目粒度放不下 8 条明细。
- **方案 C：把第 8 条写成普通 `### Changed` 条目、不加 BREAKING 措辞**。否决：MCP JSON 字段改名会断掉仓外消费者，属契约破坏性变更，发版说明必须能一眼识别。
- **方案 D：手工编辑 `.agents/notes/INDEX.md`**。否决：索引由 `scripts/notes-index.sh` 生成（脚本存在且 `-rwxr-xr-x`），手改会在下次生成时被覆盖，且违反文件头 `do not edit manually`。
- **方案 E：为第 1、4 条补端到端探针测试作为证据**。否决：本轮范围明确为「纯文档改动、不新增测试」，且这两条的机制在代码路径上是确定性的（先 DELETE 再 INSERT、切块丢弃连接符），无需测试佐证「不修」的结论；缺实测证据已如实记在「背景」里。

## 来源
- 任务：把两审遗留项落盘并为破坏性字段变更加 BREAKING 措辞，标记 `[MARK-NOTES-RESIDUALS-20261009]`。
- 前序笔记：`.agents/notes/20261008-ctxstats-keptout-accounting.md`（本轮改动的决策与实现记录）；`.agents/notes/20261007-175eb05-audit-residuals.md`（第 7 项的口径已被 20261008 笔记订正）。
- 本笔记涉及的代码位置（当前工作区实测行号，均以 `c3403ce` 为基准）：`store.go:37-54`（`onIndexedBytes` 与 `recordIndexedBytes`）、`store.go:272-318`（`Index`）、`store.go:321-331`（`Unindex`）、`store.go:533-573`（权限收紧链）、`store.go:769-780`（`SetCache`）、`store.go:829-861`（`PurgeAll`）、`store.go:863-895`（`PurgeExactAndChunks`）、`store.go:897-962`（`ReplaceExactAndChunks`）；`batch.go:567-578`；`fetch.go:513-559`（`chunkContent`）、`fetch.go:588-604`（`indexContentLocked`）、`fetch.go:734`、`fetch.go:840`；`stats.go:34`、`stats.go:167-169`；`main.go:88-93`（`attachStore`）、`main.go:823`、`main.go:1816-1845`；`error_classifier.go:142-147`；`fs_rg_summary.go:508-520`；`README.md:147`；`CHANGELOG.md` `[Unreleased]`。
- **行号差异（两审报告 → 当前源码）**：第 1 条 `Index` 报告 :305-316 → 实际 :272-318（取长 :278、记账 :316），`ReplaceExactAndChunks` 报告 :938-961 → 实际 :897-962；第 2 条报告 :313-316 / :958-961 → 实际 :310-316 / :955-961；第 3 条报告 :276-290 / :897-910 → 实际 :272-290（改写 :290）/ :897-911；第 4 条 batch.go :567-578 一致，fetch.go 报告 :895-910 → 实际记账链在 :588-604 与 :513-559（:895-910 是 `batchFetchAndIndex` 的并发调度段）；第 5 条报告 stats.go :155-159 → 实际 :167-169；第 6 条报告 fetch.go :1025-1037 → 实际 `SetCache` 定义在 `store.go:769-780`、调用点 `fetch.go:840`（:1025-1037 是 URL 去重段）；第 7 条报告 store.go :555 → 实际 chmod 在 :542（`ensureFilePerm0600` :533-548）；第 8 条报告 README.md :123 → 实际 `stats` 条目在 :147（:124 是 `batch` 条目）。位移主要来自本次改动本身对 `Index`/`ReplaceExactAndChunks` 记账代码的重排。
