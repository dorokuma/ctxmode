---
status: active
superseded_by: ""
supersedes: ""
模块: ctx_fs, stats, githooks
---

# 2026-10-07 — 175eb05 审计残留：R1–R5 未覆盖的观察项清单

## 一句话结论
- main 上 commit `175eb05`（`feat(tools): port ctx_stats and pi-fff resolve/related from upstream originals`）经 verifier + reviewer + oracle 三方审计、在工作分支 `fix/175eb05-audit-rework` 上做了 R1–R5 返工（本笔记写作时仍未提交）；返工未覆盖的观察项逐条落盘于此，一条不丢。
- 本笔记是**遗留清单**：七条观察（A–G）一律**不修**，每条写明现象、位置（行号以返工后的工作区为准）、保留理由与后续处置；另附两条既定口径（kept-out 计数范围、被推翻的审计结论），供后续审计参照、避免复发。

## 背景
- 触发：175eb05 的三方审计结论中，一部分被返工修掉，一部分被判不成立，剩下的是「功能无误但语义脆弱/口径未定/覆盖不足」的观察项。没有落盘渠道的话，这些项会随返工一起消失——本轮要求逐条落盘。
- 落盘范围：只新增本笔记；源码、README.md、CHANGELOG.md、其它笔记均不改，batch.go 与 fetch.go 不动；不 commit / push / merge。
- 阅读前提：**行号以 R1–R5 返工后的工作区为准**。R1 修掉 staticcheck S1005 后 `fs_resolve.go` 有行号位移（原 :339 的 `pairExts, _ := ...` 现为 :354），R4 改了 `scanWorkspaceFiles` 的签名与早停记录，引用旧行号会找不到位置。
- 复核方式：观察项的机制均在本轮按源码逐条核对；纯函数（`pairStem` / `isTestName` / `splitStemExt`）的实测用一次性镜像程序跑过（同源函数体，跑完即删，不入仓、不留引用路径）；探针类实测（`isSensitiveFilePath` 的路径段规则、`scanWorkspaceFiles` 的上限/截断语义）用 `go test -overlay` 把一次性测试文件从 /tmp 挂进包内跑（不在仓内落地任何文件，跑完即删），结论与本笔记一致的部分已注明，不一致的部分以「订正」标出。

## 决策
总口径：**观察项不修、逐条记录**。理由分三类，逐条落在下面各项的「为何保留不修」里——(a) 无实际后果、只是语义脆弱；(b) 属怪异输入或上游未定义口径，改动要以上游期望为依据；(c) 属覆盖不足，补测需要给生产代码开测试专用缝，超出本轮返工范围。

### 7. 既定口径（非缺陷）｜kept-out 字节只在经过 `storeIndexLocked` 的索引路径计数
- **口径**：kept-out 记账的唯一触发点是 `storeIndexLocked` 成功后调用 `statRecordKeptOut`（main.go:1818-1826，调用点 :1823）。两条写库路径绕开它、**因此不计入**：ctx_run action=batch 超限直存时直接调 `s.store.Index(label, storeOut)`（batch.go:572-582，调用点 :574）；ctx_kb fetch 经 `indexContentLocked` → `Store.ReplaceExactAndChunks`（fetch.go:588-604，调用点 :600；store 侧方法定义 store.go:876）。该口径已写进代码注释：`statRecordKeptOut` 上方（stats.go:60-64）、`Store.Index` 内（store.go:264-269）、`storeIndexLocked` 上方（main.go:1814-1817），文档侧亦按此对齐。
- **为何保留不修**：用户裁定「改文档对齐现状，不动写库路径」。两条直存路径各有自己的事务/标签语义（batch 需逐命令 label 与 `IndexError` 回填，fetch 需分块原子替换并保留旧文档），硬并入 `storeIndexLocked` 会把该函数的语义从「串行化写库 + 记账」扩成「全路径写库入口」，风险大于收益。
- **后续**：若将来要求 kept-out 全覆盖，应把记账**下沉到 Store 层**（`Store.Index` / `Store.ReplaceExactAndChunks` 内部处理），一处覆盖全部写路径；届时同步更新上述三处注释与 README 口径，避免注释与实现再次分叉。
- **订正（2026-10-08，本次改动已执行该「后续」）**：kept-out 记账已按本项处方**下沉到 Store 层**——`Store` 新增可选回调字段 `onIndexedBytes func(int)`，在 `Store.Index` 与 `Store.ReplaceExactAndChunks` 成功提交后调用（`Index` 记入参 `content` 长度；`ReplaceExactAndChunks` 记各 chunk 长度之和，均在 `neutralizeDefMarker` 改写前取值），由 `main` 经 `server.attachStore` 注入 `s.statRecordKeptOut("store", n)`；`storeIndexLocked` 内的 `statRecordKeptOut` 调用已删除，避免双重计数。因此本项的「两条路径不计入」结论**不再成立**：batch 直存与 fetch 分块写现在都计入 kept-out。同一轮另修 `ctx_kb action=stats` 的字段口径（`saved_estimate_bytes = totalOutput-totalInput` 虚高，改为 `kept_out_bytes` = 全会话 kept-out 合计），并把 `ctx_stats` 注册进 Pi 扩展。注释（stats.go / store.go / main.go）、README、instructions.go、router.go 描述已同步。回归证据见 `stats_test.go` 的 `TestStoreLayerKeptOutCoversBatchDirectIndex` / `TestStoreLayerKeptOutCoversFetchChunks` / `TestToolStatsKeptOutBytesIsKeptOutTotal`（先 FAIL 后 PASS）。

### 8. 已被推翻的审计结论｜「175eb05 主题 78 字符超 hook 上限」（避免复发）
- **事实**：commit `175eb05` 的主题行整体 78 字节（`feat(tools): port ctx_stats and pi-fff resolve/related from upstream originals`），但 commit-msg hook 只量**冒号后的 subject**：`SUBJECT_LEN=$(printf '%s' "$SUBJECT_CONTENT" | wc -m | tr -d '[:space:]')` 与 72 上限比较，超限才 die（/root/.git-hooks/commit-msg:135-141）。该 commit 的 subject 为 65 字符，hook 对其实测 exit 0。
- **另核**：pre-push（/root/.git-hooks/pre-push）无任何主题长度检查（全文搜 `72`/`subject`/`length` 无命中），也不存在「推送时补刀」的第二道长度门禁。
- **为何保留不修**：结论本身不成立，无需任何代码或 hook 改动；此处落盘只为后续审计/复核不再按「整行长度」重复误报——判定主题长度请量 `SUBJECT_CONTENT`，不是整行 header。

### 9. 本轮审计项 → 处置对照表（防漏、防回改）
| 审计项 | 处置 |
| --- | --- |
| reviewer 致命 2（kept-out 漏记账） | 落为本笔记第 7 项**既定口径**（文档对齐现状，不动写库路径） |
| reviewer 应修 3（sibling 死代码） | **R2 已修**：评分 switch 里 sibling 档（40）提到 stem-prefix 档（30）之前，并加顺序说明注释（fs_resolve.go:367-370、:371-382），由 `TestToolRelatedSiblingBeatsStemPrefix`（fs_resolve_test.go:165）钉住 |
| reviewer 应修 4（`@` 与引号剥除顺序） | oracle 判不成立，落为本笔记第 5 项观察 |
| verifier staticcheck S1005（原 fs_resolve.go:339） | **R1 已修**：`pairExts, _ := relatedPairRules[...]` 改为 `pairExts := relatedPairRules[...]`（现 fs_resolve.go:354） |
| oracle 漏项 A（预算耗尽 truncated 恒 false） | **R4 已修**：`scanWorkspaceFiles` 返回 `(bool, error)`，早停置 `truncated` 并由调用方透出（fs_resolve.go:140、:158-163、:212-221、:253-273） |
| oracle 观察 1-5 | 落为本笔记第 1-4 项与第 8 项 |
| （本轮文档返工新增）`scanWorkspaceFiles` 的上限判定先于 `seen++`：cap=N 交付 N 个文件、截断点在「下一个被访问的条目」 | 落为本笔记第 10 项观察 G（记而不修，N−1 的说法已在第 10 项订正） |


> 注（2026-10-17）：原「观察 A–G」等记而不修的观察条目经复核判定不做，已从本笔记清理；上表与下文对它们的引用仅作历史对照，原文见 git 历史。

## 被放弃的方案（必填）
- 方案 A：**顺手把观察 A–G 一次性修掉**。否决：观察项里 A/C/D 属语义脆弱但功能无误，B/E 的口径归上游 pi-fff 裁定，F/G 的补测要动生产代码加测试缝——一并修会把「审计返工」扩成「重新设计 resolve/related 围栏」，且 R1–R5 的验证范围会再次失效；本轮任务边界明确只落盘不改动。
- 方案 B：**把观察项写进 README 或 CHANGELOG 的 [Unreleased]**。否决：README 面向使用者、CHANGELOG 面向变更史，观察项既非对外契约变更也非已发生的行为变更；按本目录惯例（`.agents/notes/README.md` 六条触发里的「临时降级/特判/与 upstream 的故意分歧」）应落在笔记。
- 方案 C：**把观察项改成 TODO 注释散落在源码里**。否决：注释随重构漂移、无日期与归属，且会改动源码（本轮不允许改源码）；笔记是唯一可检索、可与 INDEX.md 联动的位置。
- 方案 D：**为 5s deadline 分支现在就加 `scanBudgetOverride` 测试缝**。否决：为一条观察项改生产代码的测试面，超出「只落盘」的边界；已作为第 6 项的后续动作登记。

## 来源
- 审计对象：commit `175eb05e16b16d134168ee6b36a1544f32ce05ee`（`feat(tools): port ctx_stats and pi-fff resolve/related from upstream originals`，subject 65 字符）；返工分支 `fix/175eb05-audit-rework`（R1–R5，本笔记写作时未提交）。R1–R5 触及的 **7 个**文件为 M：CHANGELOG.md、README.md、fs_resolve.go、fs_resolve_test.go、main.go、stats.go、store.go；其后 docfix 轮另追加 `router.go` 与 `.agents/notes/20261007-port-features-from-originals.md` 的订正标注，提交时 `git status` 为 **9 个 M** 加本笔记（未跟踪）。
- 代码位置（返工后行号）：fs_resolve.go:23、:51、:58、:91、:104-115、:140-163、:172-185、:206-209、:212-221、:236-243、:253、:354-382、:417-473；fs_tools.go:405-420、:670-685、:1627、:1771-1826；main.go:1530-1570、:1814-1826；stats.go:60-64；store.go:264-269、:876；batch.go:572-582；fetch.go:588-604；fs_resolve_test.go:23、:96、:140、:165、:206、:226、:238。
- 门禁依据：/root/.git-hooks/commit-msg:135-141（主题长度只量 `SUBJECT_CONTENT`）、/root/.git-hooks/pre-push（无主题长度检查）。
- 口径来源：用户裁定「改文档对齐现状，不动写库路径」（第 7 项）；oracle 判「reviewer 应修 4 不成立」（第 5 项）；三方审计结论与 R1–R5 的对应关系见第 9 项对照表。
