---
status: active
superseded_by: ""
supersedes: ""
# 可选模块: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg, floodguard, store, executor, router, cli, integrations/pi, githooks, scripts
模块: scripts
---

# 2026-10-16 — 移除 AGENTS.md 中已归档 prism 关联仓库条目

## 一句话结论
- 从本地 `AGENTS.md`（受全局 `/root/.config/git/ignore` 忽略）的「## 关联仓库」章节移除已归档退役的 `prism` 条目，仅保留 `codegraph-go`；历史笔记 `.agents/notes/20261004-pi-ext-deploy-sync.md` 按不可篡改历史规范保持原样不改。

## 背景
- `prism` 项目已归档退役并完成全机运行时与 Pi 扩展清理，本仓 `AGENTS.md` 第 17 行仍将其列为活关联仓库（`- `prism`：同属 AI 基础设施`），属于过期协作指引。

## 决策
- 从本地 `AGENTS.md`（自提交 `69060e4` 起不再纳入 Git 跟踪，沿用 `4f5b626` 本地更新惯例）的「## 关联仓库」列表移除 `- `prism`：同属 AI 基础设施`，保留 `- `codegraph-go`：同为 Pi 与 MCP 工具链组件`。
- 在 `CHANGELOG.md` 的 `[Unreleased] -> Changed` 登记本次文档清理，新增本笔记并运行 `scripts/notes-index.sh` 刷新本地 `.agents/notes/INDEX.md`（`.gitignore` 忽略）。
- 历史笔记 `.agents/notes/20261004-pi-ext-deploy-sync.md:37`（记录 2026-10-04 当时的扩展目录快照）按 `.agents/notes/README.md` 维护规范保持不改。

## 被放弃的方案（必填）
- **方案 A：使用 `git add -f AGENTS.md` 强制将 `AGENTS.md` 重新纳入 Git 跟踪**。否决：违背提交 `69060e4`（`chore(git): stop tracking local agent docs`）及全局 `/root/.config/git/ignore` 约束，且与 `4f5b626` 对待本地 `AGENTS.md` 的既有惯例相悖。
- **方案 B：直接删改 `.agents/notes/20261004-pi-ext-deploy-sync.md` 中的 `prism.ts` 历史记录**。否决：违反 `.agents/notes/README.md`「禁止篡改或覆盖旧笔记的历史结论与记录」规范。

## 来源
- 关联任务：`MARK-PRISM-REFS-20261016`（分支 `chore/remove-prism-reference`）。
