---
status: active
superseded_by: ""
supersedes: ""
# 可选模块: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg, floodguard, store, executor, router, cli, integrations/pi, githooks, scripts
模块: router, integrations/pi
---

# 2026-10-07 — 4.3.0 发版：CHANGELOG 口径订正、README 工具数对齐与 Pi 桥缺口

## 一句话结论
- 4.3.0 发版在 `chore/release-4.3.0`（基线 main 尖 `9d5cb9dc`）上，除 4 个文件的版本字面量外，另动了两处**文档口径**：CHANGELOG `[4.3.0]` 段 `### Fixed` 首句的 `still-unreleased` / `are unreleased` 改为 `then-unreleased` / `were then unreleased`（**刻意偏离** `f52fa52` 的「entries moved verbatim」惯例），以及根 `README.md` 的 Pi 工具数表述。
- 本轮改动在工作区完成，其后随**发版末笔提交**一并入库（本笔记为发版后补记，annotated tag `v4.3.0` 打在末笔上，照 `v4.2.0` 先例）；Pi 桥未暴露 `ctx_stats` 与 `ctx_fs action=resolve|related` 登记为后续项，相关文档不得写成「Pi 已支持」。

## 背景
- 分支 `chore/release-4.3.0` 自 main 尖 `9d5cb9dc` 新建。发版改动本应只有 4 个文件的版本字面量：`main.go` 的 `Version` → `4.3.0`；`CHANGELOG.md:6` 的 `## [Unreleased]` → `## [4.3.0] - 2026-10-07`（正文逐字未动）；`README.md` 的 `Current version` → `4.3.0`；`fixes_test.go` 的 `TestVersionAligned`。
- 上一轮 reviewer + oracle 审查判可发版，但指出两处文档债，用户拍板本次顺带修：① `[4.3.0]` 段 `### Fixed` 首句自称「两个特性还未发布」，与已挂上发布标签的 `[4.3.0]` 标题自相矛盾；② 根 README 与 Pi 桥文档的工具数口径互相矛盾。

## 决策

### ① CHANGELOG：刻意偏离「entries moved verbatim」（`CHANGELOG.md:15`）
- 发版惯例来自 `f52fa52`（`chore(release): v4.2.0 argv fence removed, audit log, agent-run deploy`）：其提交信息写「Release bookkeeping only: Version, README and the version test are aligned to 4.2.0, and the CHANGELOG [Unreleased] section is relabelled to [4.2.0] - 2026-10-03 with its entries moved verbatim, not rewritten」，实测该 commit 对 `CHANGELOG.md` **只改了标题行 1 行**（`git show f52fa52 -- CHANGELOG.md`）。
- 本次**刻意不沿用**：`CHANGELOG.md:15` 的 `### Fixed` 首句 `… on the still-unreleased \`ctx_stats\` …` 与 `… the two features are unreleased, so the entries above are corrected …`，在发布标签下自相矛盾（该段本就叙述「两个特性尚未发布时所做的返工」）。改为 `on the then-unreleased \`ctx_stats\`` 与 `the two features were then unreleased, so …`，语义变为「当时尚未发布」，与历史事实一致。
- **只动这一句的两处措辞**，段落其余逐字未动。同段的 R3 引用 `then-unreleased \`[4.2.0]\` section`（`CHANGELOG.md:12`，描述历史版本分节）不属于自相矛盾，不改。

### ② 根 README 工具数口径订正（`README.md:28`）
- 代码事实：Go MCP 面 `router.go` 的 `registerCategoryTools` 注册 **6** 个工具——`ctx_run`(`router.go:276`)、`ctx_fs`(`:282`)、`ctx_git`(`:290`)、`ctx_kb`(`:297`)、`ctx_bg`(`:304`)、`ctx_stats`(`:310`)。Pi 桥 `integrations/pi/ctxmode.ts` 只注册 **5** 个——`pi.registerTool` 位于 `:778`/`:815`/`:844`/`:865`/`:897`，`getTools()`(`:609`) 同样返回这 5 个。
- 原文 `README.md:13` 的 `Six real tools (not skills).` 指 MCP 面（其下表恰 6 行，含 `ctx_stats`），准确，**不改**。
- 原文 `README.md:28` 的 `It registers the **same five tools** …`——`same` 暗示与上面 6 个「相同」，是矛盾根源，且未说明 `ctx_stats` 缺口。改为 `It registers **five of those tools** (\`ctx_run\`, \`ctx_fs\`, \`ctx_git\`, \`ctx_kb\`, \`ctx_bg\`; \`ctx_stats\` is not exposed) and bridges stdio MCP to the Go binary.`：数量按 Pi 桥实际数（5），并写明是哪 5 个与缺口。只动数量词与限定词，未重写段落、未新增功能声明。

### ③ Pi 桥功能缺口（登记为后续项）
- `ctx_stats`：只在 Go MCP 面注册（`router.go:309-313`）；`integrations/pi/ctxmode.ts` 全文无 `ctx_stats`。
- `ctx_fs action=resolve|related`：Go MCP 面的 `ctx_fs` 工具描述含这两个动作（`router.go:285`）；Pi 侧 `ctx_fs` 的动作 enum 仅 `ls|glob|stat|rg`（`integrations/pi/ctxmode.ts:827`，工具描述 `:818`）。
- 处置：本次只补文档边界说明（`integrations/pi/README.md` 开头段后新增边界段），**不改** `ctxmode.ts`。后续若要在 Pi 面暴露，需同步桥的 enum 与 `getTools()`；在此之前，任何「Pi 已支持 `ctx_stats` / `resolve` / `related`」的表述都不成立，须避免。

## 被放弃的方案（必填）
- **严格沿用 `f52fa52` 惯例、只改标题行**：被否。发布标签下的 `[4.3.0]` 段若保留 `the two features are unreleased`，则同一段自称「未发布」而上级标题已是 `[4.3.0] - 2026-10-07`，属可读性缺陷，用户拍板本次最小改准，并在此笔记记明该偏离。
- **根 README 保留 `same five tools`、只把 `five` 改成 `six`**：被否。Pi 桥实际只注册 5 个，改成 6 反而失真；矛盾在 `same` 一词与「未说明缺口」，不在数字本身。
- **在 Pi 桥补上 `ctx_stats` / `resolve` / `related` 再发版**：超出本次「只改文档文字，不动 Pi 桥代码」的范围，登记为后续项。

## 来源
- 分支 `chore/release-4.3.0`（基线 main 尖 `9d5cb9dc`）；发版惯例参照 commit `f52fa52`。
- 代码位置：`router.go:276/282/290/297/304/310`（MCP 面 6 工具）、`router.go:285`（`ctx_fs` 的 resolve|related 动作枚举）、`integrations/pi/ctxmode.ts:609/778/815/827/844/865/897`（Pi 面 5 工具与 `ctx_fs` 的 enum）。
- 文档改动：`CHANGELOG.md:15`、`README.md:28`、`integrations/pi/README.md`（开头段后新增边界段）。

## 追加（第三批）：MCP `initialize` playbook 口径债一并修
- 性质：**4.3.0 之前遗留的口径债**（不是 4.3.0 引入），用户拍板本轮一并修；本小节只追加，不改上文（唯一例外见文末「第四批（收口批）」对两处状态句的订正）。
- 代码事实（本轮修订依据）：MCP 面 6 工具——`router.go:276`(`ctx_run`)、`router.go:282`(`ctx_fs`)、`router.go:290`(`ctx_git`)、`router.go:297`(`ctx_kb`)、`router.go:304`(`ctx_bg`)、`router.go:310-313`(`ctx_stats`)；`ctx_fs` 动作枚举 `ls|glob|stat|rg|resolve|related` 见 `router.go:82`（schema）与 `router.go:122`（错误消息）；`ctx_stats` 无 action 字段，只有 `json`。Pi 桥仍为 5 工具（`integrations/pi/ctxmode.ts:609/779/816/845/866/898`），`ctx_fs` enum 仍只有 `ls|glob|stat|rg`（`integrations/pi/ctxmode.ts:827`）。
- `instructions.go`（MCP `initialize` 时模型真正读到的文本）：`:7` 的 `Five tools; each takes a required action argument.` → `Six tools; five take a required action argument (ctx_stats takes none).`；`:16-17` 工具表 `ctx_fs` 行补 `resolve`/`related` 两个动作；工具表在 `ctx_bg` 行后新增 `ctx_stats` 行；`:39` 的 `Tool names: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg` → 末尾补 `ctx_stats`，并把 `action is a required argument` 限定为 `for all but ctx_stats`。只改文本，未动逻辑与结构。
- `main.go:2-4` 头注释：工具清单补 `ctx_stats`，版本标识行 `v2.0 MCP surface (category tools + action=):` → 加 `; ctx_stats takes no action`。`const Version` 与代码逻辑未动。
- 根 `README.md:13`：`Each takes **\`action=\`**` 对 `ctx_stats` 为假（`:22` 表格已写 `— (no \`action=\`; single capability)`），改为 `Five take **\`action=\`** plus capability-specific fields; \`ctx_stats\` takes no action and only accepts \`json\`:`。
- 根 `README.md:24`：`Any MCP host (Grok, Pi, …) uses this surface.` 把六工具面说成 Pi 也用，与 `:28` 矛盾；改为 `Any MCP host (e.g. Grok) uses this surface; the Pi adapter below is the exception.`，把 Pi 的例外交给 `:28`（该行已写明 Pi 只桥 5 个且无 `ctx_stats`），两处不重复、不冲突。
- 测试影响：无。全仓测试中唯一断言 playbook 文本的是 `fs_rg_qw_test.go:215-221`（`TestServerInstructions_RgGuidance`），只检查 `concrete identifier` / `never '.*'` / `after 1-2 greps` / `ctx_kb action=search` / `offset paging` 五串，未被本轮改动触及。
- 状态：本轮改动在工作区完成后，随**发版末笔提交**一并入库（提交与 tag 形态见文末「第四批（收口批）」）；未改 `router.go`、`fs_*.go`、任何测试文件、`integrations/pi/ctxmode.ts`。

## 追加（第四批·收口批）
- 性质：oracle 第二意见对冻结态提的可证伪项，用户逐条拍板；本小节为**发版后补记**（随本轮末笔提交入库），只追加，不改上文——唯一例外是对两处状态句的最小订正（`§一句话结论:13` 与 `§追加（第三批）` 末尾状态行），把「未提交（改动留在工作区）」改为「随发版末笔提交一并入库」，以在提交后仍然成立，删去提交后即失效的「未提交 / 未 push / 未打 tag / 未合并」表述。
- ① `instructions.go:25` 的 `ctx_stats` playbook 行补计数例外。依据 `router.go:311` 的描述原文：「… bytes kept out by auto-indexing at the `storeIndexLocked` choke point only — `ctx_run action=batch` direct stores and `ctx_kb fetch` are not counted.」——即 kept-out 计数**只**覆盖经由 `storeIndexLocked` 落库的路径，`ctx_run action=batch` 的直接落库（`Store.Index`）与 `ctx_kb fetch` 不计入。改动：在该行 `bytes kept out by auto-indexing` 后补入限定「counted only where output is stored through the `storeIndexLocked` choke point; `ctx_run action=batch` direct stores and `ctx_kb fetch` are not counted」。`ctx_stats` 无 action 字段、只接受 `json`（`stats.go:103-105` 的 `ctxStatsArgs` 仅 `JSON bool`），故 playbook 行原有的「No action argument; pass `json:true` for machine-readable output」保留不动。忠实补写、保持压缩风格，未新增与代码不符的说法。
- ② `integrations/pi/README.md:5` 版本措辞。HEAD 原文 `Requires **ctxmode ≥ 2.0.0**.`，本轮一度改为 `≥ 4.3.0`（把「桥随 4.3.0 一起发布」误读为「服务端必须 ≥ 4.3.0」）；按 oracle 证据改为**准确措辞**：桥本身**不校验**服务端 ctxmode 版本，本文档描述的是随 4.3.0 发布的桥（注册的仍是那五个工具），Go MCP 面的 `ctx_stats` 与 `ctx_fs action=resolve|related` 自 4.3.0 起才有且**本桥不暴露**。桥对 4.2.x 服务端仍可用，故不再写任何版本下限。同文件 `:81` 的 `Node ≥ 22.15`（本批在开头段增行后由 `:78` 位移）属测试运行环境要求，本次未动。
- ③ 提交与打 tag 形态：docs 提交（本轮三处文档修订）→ `chore(release): v4.3.0`（**只含四个版本字面量**）→ 本笔记作为**末笔**提交；annotated tag `v4.3.0` 打在**末笔**上，照 `v4.2.0` 先例（实测其 annotated tag 指向 `bd83f34`，即当轮的笔记末笔）。
- 状态：第四批三处改动在工作区完成后随末笔提交入库；未改 `router.go`、`stats.go`、任何测试文件、`integrations/pi/ctxmode.ts`。
- 行号核正（本笔记实读复核）：`integrations/pi/ctxmode.ts` 的 `getTools(): string[]`（`:609`，返回列表在 `:610`）、`pi.registerTool`（`:778`/`:815`/`:844`/`:865`/`:897`）与各工具 `name:`（`:779`/`:816`/`:845`/`:866`/`:898`）、Pi 侧 `ctx_fs` enum（`:827`）；`integrations/pi/README.md` 的 `Node ≥ 22.15`（`:81`，由 `:78` 位移）；`router.go` 的 `ctx_fs` 动作 enum（`:82`，错误消息 `:120`/`:122`）与描述中列出动作的行（`:285`）。
