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

### 1. 观察项｜kept-out 是「成功写入事件的单调累计」，不是「当前仍留在库中的字节量」
- **位置**：`store.go:272-318`（`Store.Index`：取长 `:278`、`DELETE FROM documents WHERE path = ?` 替换旧行 `:301`、`tx.Commit()` `:310`、`recordIndexedBytes(inputBytes)` `:316`）；`store.go:897-962`（`Store.ReplaceExactAndChunks`：逐 chunk 取长 `:902-907`、替换 `:919`/`:923`、提交 `:955`、记账 `:961`）。不扣减的路径：`Unindex` `store.go:321-331`、`PurgeExactAndChunks` `store.go:863-895`、`PurgeAll` `store.go:829-861`。
- **触发条件**：同一路径被成功写入两次——`Index` 与 `ReplaceExactAndChunks` 都是「先 DELETE 旧行、再 INSERT 新内容」，旧内容已不在库中，但两次写入各自记一次。
- **后果**：库中最终只有新内容，计数却累加两次。例：同一路径先索引 1000B 再索引 1000B，库中最终 1000B，计数为 2000。删库（`Unindex`/`PurgeExactAndChunks`/`PurgeAll`）不回扣。
- **处置**：**用户裁决判观察项，本轮不改实现**。理由：旧实现 `storeIndexLocked` 同样每次成功都累加 `len(content)`，`ctx_stats` 的 `total_kept_out` 一直是「本次会话有多少字节被挡在上下文之外」这一语义，本次改动只是把 `ctx_run action=batch` 直存与 `ctx_kb fetch` 分块写对齐到该既有语义，并非本次引入；改成「当前库中字节量」需要额外的减法记账，属另一轮独立改动。
- **级别**：观察项（oracle）。

### 2. 观察项｜`tx.Commit()` 成功后 `secureDBFiles()` 失败：已落库但不记账且返回错误
- **位置**：`store.go:310-316`（`Index`）与 `store.go:955-961`（`ReplaceExactAndChunks`）；`secureDBFiles` `store.go:567-573` → `secureDBFile` `store.go:550-565` → `ensureFilePerm0600` `store.go:533-548`（chmod 失败返回错误 `:542`）。
- **触发条件**：事务提交成功，随后把 db / `-wal` / `-shm` 权限收紧为 0600 的 chmod 失败（例如文件属主或挂载点不允许改权限）。
- **后果**：内容已落库，但方法返回错误且不记账（`recordIndexedBytes` 排在 `secureDBFiles` 之后）。反向的「记了但回滚」不存在：`recordIndexedBytes` 只在两处成功路径的末尾调用（`store.go:49-54`），事务失败路径提前 `return`。
- **处置**：属既有提交/返回语义，非本次引入；本轮不修（要改就是重排「提交后收紧权限」与「记账」的先后，属独立改动）。
- **级别**：观察项（oracle）。

### 3. 观察项｜`[def] ` 前缀改写导致少记 1 字节
- **位置**：`store.go:278`（`inputBytes := len(content)`）与 `store.go:290`（`content = neutralizeDefMarker(content)`）；`store.go:902-911`（逐 chunk 取长 `:902-907`、逐 chunk 改写 `:911`）。`neutralizeDefMarker` 定义在 `fs_rg_summary.go:515-520`，`defMarker` 常量 `fs_rg_summary.go:508`。
- **触发条件**：入库内容以字面 `[def] ` 开头（文档位置 0，或 fetch 分块的每个 chunk 起点）。
- **后果**：计数取改写**前**的长度，而入库内容被加一个前导空格 → 每个命中该条件的文档/chunk 少记 1 字节。该改写不截断正文，批量路径也不会重复少记（`ReplaceExactAndChunks` 在同一循环里先校验后累加，每 chunk 只改写一次）。
- **处置**：本轮不修。取「改写前长度」是刻意的口径选择——记账量应反映调用方交进来的原始字节，而不是入库时的防伪改写；差额固定为 1 字节/文档，无累计放大。
- **级别**：观察项（oracle）。

### 4. 观察项｜包装差额：`error_class` 前缀计入、fetch 分块的 `\n\n` 连接文本不计入
- **位置**：`batch.go:567-578`（`storeOut := prefixErrorClass(out, r.ErrorClass)` `:569`、`s.store.Index(label, storeOut)` `:574`）；`prefixErrorClass` `error_classifier.go:142-147`（前缀为 `"error_class: " + class + "\n"`）。fetch 侧：`fetch.go:588-604`（`indexContentLocked`，`s.store.ReplaceExactAndChunks(docPath, chunks)` `:600`）与 `chunkContent` `fetch.go:513-559`（块间连接 `current.WriteString("\n\n")` `:545`）。
- **触发条件**：batch 命令带 `error_class`（失败命令）；fetch 内容被 `chunkContent` 切成多块。
- **后果**：带前缀时计数包含前缀字节；fetch 多块之间的 `\n\n` 连接文本在切块时被丢弃、不计入。差额很小（前缀一条几十字节；连接符 2 字节/块）。核对中未发现路径标签或 `#chunk-N` 编号被写入正文（chunk 编号只出现在文档 path 列，不在 content）。
- **处置**：本轮不修；属既有包装差额，非本次引入。
- **级别**：观察项（oracle）。

### 5. 观察项｜`savings` 的分母不是同一份输出的划分
- **位置**：`stats.go:167-169`（`savings = float64(totalKeptOut) / float64(totalReturned+totalKeptOut) * 100`）。
- **触发条件**：有超限输出被索引——`main.go:1816-1831`（`formatLargeIndexed`）与 `main.go:1833-1845`（`formatIntentIndexed`）在回复里附 `--- Tail preview ---`（`tailUTF8(outputText, 2000)`，`main.go:1824` / `:1838`）。
- **后果**：比率数学自洽，但尾部预览计入工具行的 `returned`、完整输出计入 `store.keptOut`，同一段尾部同时出现在分子与分母两侧，比率被轻微压低；未被索引的小输出只出现在 `returned` 一侧。
- **处置**：本轮不修；属既有口径观察，改分子/分母定义会牵动 `ctx_stats` 的展示语义（`stats.go:158-171`），需单独一轮定口径。
- **级别**：观察项（oracle）。

### 6. 观察项｜`SetCache` 不经 kept-out 钩子
- **位置**：`store.go:769-780`（`SetCache` 只 `INSERT OR REPLACE INTO fetch_cache`，表定义 `store.go:234-242`）；调用点 `fetch.go:840`（`s.store.SetCache(rawURL, cacheSource, content)`）；缓存命中且文档缺失时的补索引 `fetch.go:734`（`s.indexContentLocked(docPath, cached.Content)`，走 `ReplaceExactAndChunks`，会正常记一次）。FTS 触发器 `store.go:165-175` / `:201-209` 只复制 `documents.content`。
- **触发条件**：`ctx_kb fetch` 写缓存；或缓存命中但对应格式的 KB 文档已被清掉。
- **后果**：缓存内容不直接返回给模型，因此不计入 kept-out 是合理的；缓存行本身没有独立的正文写入路径（FTS 触发器只跟随 `documents` 表），不会漏记正文。补索引路径会照常记一次，不构成缺口。
- **处置**：本轮不修；记录为口径边界即可。
- **级别**：观察项（oracle）。

### 7. consider｜权限收紧失败时口径偏保守（入库成功、计数为 0）
- **位置**：`store.go:533-548`（`ensureFilePerm0600`，chmod 失败返回错误于 `:542`），由 `secureDBFile` `store.go:550-565` / `secureDBFiles` `store.go:567-573` 调用；记账点 `store.go:316` / `:961`。
- **触发条件**：db 文件或 sidecar 的 chmod 0600 失败（见第 2 条）。
- **后果**：文档已提交但 kept-out 计 0，形成「入库成功、计数为 0」的轻微偏保守（少记，不会虚计）。
- **处置**：**不动实现**——把记账前移到 chmod 之前反而会在 chmod 失败时虚计（记了但调用方看到失败），保守方向更安全；仅在此记录该边界。无正确性风险。
- **级别**：consider（reviewer）。

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
