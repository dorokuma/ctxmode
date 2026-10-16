---
status: active
superseded_by: ""
supersedes: "20261004-pi-ext-deploy-sync.md" # 条款级：仅闭合其中「遗留清单 #2 prism.ts」条目，旧笔记主体契约仍有效
# 可选模块: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg, floodguard, store, executor, router, cli, integrations/pi, githooks, scripts
模块: integrations/pi
---

# 2026-10-16 — 闭合 20261004-pi-ext-deploy-sync.md 中 prism.ts 扩展同步遗留项

## 一句话结论
- 声明历史笔记 `.agents/notes/20261004-pi-ext-deploy-sync.md:37`（「## 遗留清单」第 2 条）中关于 `prism.ts`「整机无第二份源码（部署目录里就是唯一副本），没有可同步的仓库源」的遗留项已于 2026-10-16 彻底闭合：`prism` 扩展已从 `/root/workspace/pi-extensions` 分发中枢移除、部署副本 `/root/.pi/agent/extensions/prism.ts` 已删除、`prism` 项目已归档并完成本机运行时清除；历史笔记 `.agents/notes/20261004-pi-ext-deploy-sync.md` 按不可篡改规范保持一字不改。

## 背景
- `.agents/notes/20261004-pi-ext-deploy-sync.md:35-40` 在 2026-10-04 记录本仓 `integrations/pi/install.sh` 提炼时，于「## 遗留清单」第 2 条（第 37 行）写有现在时状态描述：
  > `2. prism.ts / auto-continue.ts / no-tables.ts —— 整机无第二份源码（部署目录里就是唯一副本），没有可同步的仓库源；`
- 本分支前序提交 `c4ed556`（`.agents/notes/20261016-drop-prism-related-repo.md`）已从本地 `AGENTS.md` 移除 `prism` 关联仓库条目，但尚未对 `20261004-pi-ext-deploy-sync.md:37` 的现在时遗留项建立显式闭合记录。
- 按 `.agents/notes/README.md`「禁止篡改或覆盖旧笔记的历史结论与记录」规范及本次任务硬边界，不得修改 `.agents/notes/20261004-pi-ext-deploy-sync.md` 正文，须新增闭合笔记声明销账。

## 决策
- **条款级闭合声明（关联旧笔记 `.agents/notes/20261004-pi-ext-deploy-sync.md:37`）**：
  1. **`prism` 扩展已从分发中枢移除**：`prism.ts` 曾于 2026-10-04 纳入联邦分发中枢 `/root/workspace/pi-extensions` 作为 hosted 扩展；因 `prism` 已被 MAGPIE 替代且远端 `dorokuma/prism` 归档封存，`/root/workspace/pi-extensions` 已于提交 `21411bd`（`chore(extensions): remove archived prism extension`，任务 `[MARK-PRISM-EXT-REMOVE-20261016]`）彻底移除 `extensions/prism/` 源码及 `federated/registry.json` 登记，全机纳管扩展数由 12 收敛为 11（详见 `/root/workspace/pi-extensions/.agents/notes/20261016-remove-prism-extension.md`）。
  2. **部署目录副本已删除**：`/root/.pi/agent/extensions/prism.ts`（删除前 md5 `e1c6c8debe8cc8a77425ca69f345d35d`，7725 字节）已于合入收口轮次（任务 `[MARK-PRISM-EXT-CLOSE-20261016]`）删除。
  3. **`prism` 项目已归档并完成本机清除**：本机仓库目录 `/root/workspace/prism`、二进制 `/usr/local/bin/prism` 与运行时配置 `/var/lib/prism/` 已于 2026-10-16 彻底清除，全局台账 `/root/workspace/PROJECTS.md:42` 已更新为「已归档清除」墓碑行，本仓 `AGENTS.md` 关联仓库引用亦已于提交 `c4ed556` 移除。至此 `prism.ts` 同步漂移遗留项因标的物退役清除而终结闭合。
  4. **同条其余扩展现状备查**：`.agents/notes/20261004-pi-ext-deploy-sync.md:37-39` 同列举的 `auto-continue.ts`、`no-tables.ts`、`herdsman-pi.ts`（仓内名 `herdsman-bridge`）均已纳入 `/root/workspace/pi-extensions` 作为 hosted 权威源统一同步，`herdr-agent-state.ts` 作为 `herdr` 二进制托管的 external 只读巡检项。
- **闭合关系界定**：本笔记在 frontmatter 中以条款级 `supersedes: "20261004-pi-ext-deploy-sync.md"` 指向旧笔记，仅闭合其「## 遗留清单」第 2 条（第 37 行），不废止该笔记关于本仓 `integrations/pi/install.sh` 契约与 `deploy.sh` 硬失败策略的主体决策；旧笔记文件字节与 mtime 保持未变。
- **变更登记与索引刷新**：在 `CHANGELOG.md` 的 `[Unreleased] -> Changed` 追加英文闭合记录；运行 `bash scripts/notes-index.sh` 刷新本地 `.agents/notes/INDEX.md`（受 `.gitignore` 忽略）。

## 被放弃的方案（必填）
- **方案 A：直接编辑 `.agents/notes/20261004-pi-ext-deploy-sync.md:37` 删除 `prism.ts` 或加注完成状态**。否决：违反 `.agents/notes/README.md` 历史记录不可篡改规范及本次任务「不得修改任何历史笔记正文」禁令。
- **方案 B：`git commit --amend` 合并入前序提交 `c4ed556`**。否决：违反本次任务「在既有分支 `chore/remove-prism-reference` 上追加一个提交（不得改写既有提交 `c4ed556`）」的提交边界约束。

## 来源
- 关联旧笔记：`.agents/notes/20261004-pi-ext-deploy-sync.md:37`、本分支前序笔记 `.agents/notes/20261016-drop-prism-related-repo.md`（提交 `c4ed556`）。
- 关联外部删除记录：`/root/workspace/pi-extensions` 提交 `21411bd` 及 `.agents/notes/20261016-remove-prism-extension.md`、全局台账 `/root/workspace/PROJECTS.md:42`。
- 任务标记：`[MARK-PRISM-BACKLOG-20261016]`（分支 `chore/remove-prism-reference`）。
