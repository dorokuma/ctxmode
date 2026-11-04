---
status: active
superseded_by: ""
supersedes: ""
模块: "ctx_run"
---

# ssh peel 第 1 轮评审遗留观察项（feat/subagent-ssh-peel）

## 一句话结论

Reviewer/oracle 第 1 轮对 `parseSSHInvocation`/`screenSSHHead` 的 `should fix` 项已在本分支修复（`-o` 值门控 + 长选项 fail-closed）；本笔记归档剩余非阻断观察项，不构成本轮改动目标。

## 背景

`feat/subagent-ssh-peel` 把 ssh 从整禁改为透明剥壳 + 远端命令继承调用者守卫。评审中除已修复项外，还有两项结构性观察，判定为非阻断，记录待后续轮次或另行评估。

## 决策

已修复（本轮 C 档第 1 轮小返修，详见 CHANGELOG `[Unreleased]` Fixed 段）：

- `sshOValueOK` 对 `userknownhostsfile`/`globalknownhostsfile` 仅放行 `/dev/null`|`none`，对 `enableescapecommandline` 仅放行 `no`。
- `parseSSHInvocation` 的双横线长选项改为统一 fail-closed（OpenSSH ssh 无合法 `--long`，`--help`/`--version` 亦不发起远端命令），`sshValueLongs` 表移除。

遗留非阻断观察项：

- `[pattern:code-static-spawn-single-layer]`：`guardCtxRunCode` 对非 shell 代码里的静态数组 spawn（如 `subprocess.run(['ssh','dmit','pig'])`）只做单层 `screenNestedDispatch`——argv 命中 ssh 时目前只按 agent 名单判断 head[0]，未把 `parseSSHInvocation` 接到 code 层静态 argv 上，远端命令里的嵌套派发不经 ssh 选项剥壳复核。评估方向：在 code-spawn 的 argv 筛查分支中对 `head[0]=="ssh"` 调用 `parseSSHInvocation` 复用远端命令继承逻辑。
- `[pattern:indirect-wrapper-seg-stdin]`：经 `xargs`/`find -exec` 间接派生 `ssh` 时不携带外层 `shellSegment` 的 `pipedStdin` 上下文——`echo code | xargs ssh dmit sh` / `find . -exec ssh dmit sh \;` 形态的 stdin 语义与直接管道段不同（xargs 不转发 stdin 给子命令，find -exec 亦然），当前 peel 路径未见外层段 stdin 信息，属上下文保真观察而非漏洞。

## 被放弃的方案

- 本轮直接修两项遗留观察：判定为非阻断且涉及 code 层/段上下文传递的结构性改动，超出 C 档第 1 轮小返修范围，留给主代理后续决策。
- 对 `--help`/`--version` 保留特殊放行：OpenSSH ssh 没有 GNU 风格长选项，`--help` 本身是未知选项；统一 fail-closed 更符合守卫语义且实现最简。

## 来源

- 分支：`feat/subagent-ssh-peel`，worktree `/root/workspace/.wt/ctxmode/feat-subagent-ssh-peel`
- 代码：`role_guards.go` `sshOValueOK`/`parseSSHInvocation`；观察项关联 `guardCtxRunCode`、`peelResolvedSegDepth`/`screenOneSegmentDepth` 的 `shellSegment` 传递
