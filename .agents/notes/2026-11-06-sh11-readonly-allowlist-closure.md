---
status: active
superseded_by: ""
supersedes: ""
模块: ctx_run
---

# [pattern:closure-record] feat/readonly-allowlist 收口记录

## 一句话结论
`feat/readonly-allowlist`（readonly allowlist + guards hardening，8 轮审查、88 探针）已于 2026-11-06 以 merge commit `54143c8` 合入 main；worktree 与分支已清理，`.wt` 登记状态已置 `merged`。

## 合并事实
- Merge SHA：`54143c8`（`Merge branch 'feat/readonly-allowlist'`，--no-ff）
- 分支：`feat/readonly-allowlist`，合入前 HEAD `7d31147`（`docs(notes): record linuxbrew PATH trust boundary consider`，基线 `2e1e386` 起共 7 commits）
- 门禁档位：reviewer + verifier 全绿，gate_scan 人工核验通过（主代理派发确认）
- 合并提交消息偏差：任务书给定 `merge:` 类型不在当前 commit-msg hook 白名单（feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert），按仓库既有 merge commit 惯例（`0c524eb`/`c4bff1f` 等）改用 `Merge branch 'feat/readonly-allowlist'` 主题（hook 豁免行）+ 正文说明，未绕过 hook

## 远端推送状态
- 任务书声明「无 origin」，实测 `origin` 存在且指向 `https://github.com/dorokuma/ctxmode.git`（我方控制推送权的允许远端）；但任务书同时明示「不 push」，故**未推送**，本地 main 领先 origin/main 55 commits（含既往未推历史，非本合并引入）。是否推送待主代理决定。

## 遗留项
- round-8 consider（非 must fix）：`[pattern:path-trust-user-writable]` PATH 信任表含用户可写目录（`/home/linuxbrew/`、`/.local/bin`、toolchain shim 目录），植入同名恶意二进制可解析为已放行名；已归档 `.agents/notes/2026-11-01-role-guards-non-sandbox-boundaries.md` C10 条。
- ssh peel 两项结构性观察（`[pattern:code-static-spawn-single-layer]`、`[pattern:indirect-wrapper-seg-stdin]`）见 `2026-11-04-ssh-peel-followups.md`。

## 来源
任务【MARK-SH11CLOSE-20261106】收口指令；worktree `/root/workspace/.wt/ctxmode/feat-readonly-allowlist`（已 `git worktree remove`）；登记文件 `.wt/ctxmode/feat-readonly-allowlist.json` status=merged。
