---
status: active
superseded_by: ""
supersedes: ""
# 可选模块: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg, floodguard, store, executor, router, cli, integrations/pi, githooks, scripts
模块: integrations/pi, ctx_fs, router
---

# 2026-10-15 — Pi 扩展桥补齐 ctx_fs action=resolve|related 并同步文档口径

## 一句话结论
- 在 `integrations/pi/ctxmode.ts` 中将 `resolve` 与 `related` 加入 Pi 侧 `ctx_fs` 的 `action` 枚举（`ls|glob|stat|rg|resolve|related`）与工具描述，实现与 Go MCP 面 `router.go` 的动作枚举与 path/limit 参数对齐；`path` 与 `limit` 参数在既有 schema 中已存在，无需新增参数字段。
- 同步更新 `README.md`、`integrations/pi/README.md` 与 `CHANGELOG.md` `[Unreleased]`，移除「Pi 桥未暴露 `resolve|related`」的旧边界说明并补齐主工具表 `ctx_fs` 参数列；至此 `20261007-release-430-notes.md` §决策③ 登记的两项 Pi 桥功能缺口（`ctx_stats` 与 `ctx_fs action=resolve|related`）已全部闭合。

## 背景
- `4.3.0` 发版笔记（`.agents/notes/20261007-release-430-notes.md` §决策③）登记了两处 Pi 桥与 Go MCP 面的功能缺口：① `ctx_stats` 未在 Pi 侧注册；② `ctx_fs action=resolve|related` 在 `router.go` 已提供，但 `integrations/pi/ctxmode.ts` 的 `ctx_fs` 动作 enum 仍只有 `ls|glob|stat|rg`。
- 其中第 ① 项（`ctx_stats` 注册进 Pi）已于 `c3403ce`（记录于 `.agents/notes/20261008-ctxstats-keptout-accounting.md`）补齐，而第 ② 项 `ctx_fs action=resolve|related` 仍留在 Pi 桥缺口中，`integrations/pi/README.md` 与 `README.md` 也保留了对应的例外说明。

## 决策
1. **对齐 `integrations/pi/ctxmode.ts` 的 `ctx_fs` 定义（`:815-842`）**：
   - 对照 `router.go:81-93`（`ctxFsArgs`）、`router.go:115-118`（`toolCtxFs` 分发处构造 `resolveArgs{Path: args.Path, Limit: args.Limit}` / `relatedArgs{Path: args.Path, Limit: args.Limit}` 字面量）与 `fs_resolve.go:226/295`（`resolveArgs` / `relatedArgs` 结构体定义），Pi 侧 `ctx_fs` 的 `parameters` 已包含 `path`（`:828`）与 `limit`（`:833`），无需新增字段。
   - 将 `:827` 的 `action` 定义更新为 `Type.String({ description: "ls|glob|stat|rg|resolve|related", enum: ["ls", "glob", "stat", "rg", "resolve", "related"] })`。
   - 将 `:818-819` 的 `description` 与 `promptSnippet` 补入 `resolve`（按近似/`@`路径模糊检索候选文件，移植自 pi-fff）与 `related`（查找给定文件的测试/实现配对、同 stem 与同目录关联文件）说明。
   - 超时策略不变：服务端 `resolve`/`related` 内置 5s 墙钟预算（`fs_resolve.go:23` `resolveScanBudget = 5 * time.Second`），客户端默认 `REQUEST_TIMEOUT_MS`（120s）充裕，无需在 `timeoutForTool` 中新增特判分支。
2. **文档口径同步**：
   - `README.md:18`、`:24` 与 `:28`：在主工具表 `ctx_fs` 行的 `Key parameters` 列补齐 `resolve` 与 `related` 的 `path`/`limit` 参数说明，并顺手为 `rg` 补上 `offset` 参数（与 `README.md:132-134` 及 `router.go` 实际实现对齐）；移除将 Pi 适配器列为工具面例外的旧表述，写明 Pi 适配器注册相同的六个工具（含 `ctx_fs` 的 `resolve` 与 `related`）。
   - `integrations/pi/README.md:8-10`：将边界段更新为六个工具及 `ctx_fs` 的 `ls|glob|stat|rg|resolve|related` 动作枚举均已与 `router.go` 对齐。
   - `CHANGELOG.md:6-9`：新增 `## [Unreleased]` 段落登记本次变更。
3. **最小测试纪律**：
   - 在已有 `integrations/pi/ctxmode.test.ts`（`:720-817`）新增单条测试 `扩展层：ctx_fs 暴露 resolve 与 related 动作枚举并透传调用`，覆盖 `action.enum`、`action.description`、工具 `description`，并解析 recorded JSONL 请求行断言同一条 `tools/call` 请求中同时包含 `name === "ctx_fs"`、`arguments.action === "resolve"`（含 `path: "@router.go", limit: 5`）及 `arguments.action === "related"`（含 `path: "router.go", limit: 3`）（改动前实测 FAIL，改动后 PASS）。

## 被放弃的方案（必填）
- **方案 A：在 Pi 桥将 `resolve` 与 `related` 拆成独立顶层工具（如 `ctx_resolve` / `ctx_related`）**。否决：违背 v2 类别工具面设计（`ctx_fs` 通过 `action=` 承载文件类能力），且会与 Go MCP 面 `router.go` 及 `instructions.go` 的 playbook 产生分叉。
- **方案 B：在 `timeoutForTool` 为 `ctx_fs` 的 `resolve|related` 单独加超时分支**。否决：服务端 `resolve`/`related` 已有 5s 墙钟预算上限（`resolveScanBudget`），远小于客户端默认 120s 超时，增加分支属于无依据的冗余复杂度。
- **方案 C：直接改写 `20261007-release-430-notes.md` 的历史结论或将其整篇标为 `superseded`**。否决：违反 `.agents/notes/README.md`「禁止篡改或覆盖旧笔记的历史结论与记录」规范，且该笔记还承载 4.3.0 发版 CHANGELOG 措辞与 MCP playbook 等仍有效的历史记录；该笔记 §决策③ 本就将 Pi 桥对齐定义为后续项，由 `20261008` 笔记与本笔记共同完成闭环。

## 来源
- 任务：为 Pi 扩展桥补齐 `ctx_fs` 的 `resolve` 与 `related` 动作，标记 `[MARK-CTXMODE-PI-RESOLVE-20261015]`；双审闭环修正标记 `[MARK-CTXMODE-FIXUP-20261015]`。
- 前序笔记：`.agents/notes/20261007-release-430-notes.md`（§决策③ 登记缺口）、`.agents/notes/20261008-ctxstats-keptout-accounting.md`（补齐 `ctx_stats`）。
- 代码与文档位置：`router.go:81-124`（`:115-118` `toolCtxFs` 分发处构造字面量）、`:281-287`；`fs_resolve.go:22-25`、`:226/295`（`resolveArgs` / `relatedArgs` 结构体定义）、`:371-382`；`integrations/pi/ctxmode.ts:120-121`、`:155-180`、`:815-842`；`integrations/pi/ctxmode.test.ts:720-817`；`README.md:18`、`:24`、`:28`；`integrations/pi/README.md:8-10`；`CHANGELOG.md:6-9`。
