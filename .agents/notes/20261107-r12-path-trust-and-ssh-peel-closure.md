20261107-r12-path-trust-and-ssh-peel-closure.md

Markdown
---
status: active
superseded_by: ""
supersedes: "2026-11-04-ssh-peel-followups.md"
模块: "ctx_run"
---

# 第 12 轮守卫收口：PATH 用户目录信任边界（C10）与 ssh 剥壳两项遗留闭环

## 一句话结论
通过「家目录前缀锚定 + 磁盘属主/0022 权限位/软链逃逸校验 + 系统核心命令防遮蔽 + 透明 shim 识别 + 只读别名双向白名单」闭合 C10（`[pattern:path-trust-user-writable]`），并在 `guardCtxRunCode` 与 `xargs`/`find`/`flock`/`watch` 派生链中补齐 `parseSSHInvocation` 远端守卫继承与 `shellSegment` stdin 上下文保真（闭合 `[pattern:code-static-spawn-single-layer]` 与 `[pattern:indirect-wrapper-seg-stdin]`）。

## 背景
第 11 轮 `feat/readonly-allowlist`（`54143c8` / `a480142` v5.2.1）合入后，遗留三项结构性观察：
1. **C10 `[pattern:path-trust-user-writable]`**：`isSafePathDirEntry` 仅做无锚定子串匹配且不查磁盘权限/软链目标；`peelResolvedSegDepth` 用软链目标覆盖 `base` 导致早退分支跳过 `typedHead` 或吞掉 `mise` shim 包装的解释器头；`screenReadonlyAllowlist` 未复核软链目标名，且系统核心命令（`ls`/`git`/`sh` 等）可被 `~/.local/bin` 中的同名植入二进制遮蔽。
2. **`[pattern:code-static-spawn-single-layer]`**：`guardCtxRunCode` 中 `strictReadonly` 抢先于 `subagent` 拦截静态 spawn、`currentCallerIdentity()` 未与 `guardCall` 接收者对齐（受外层 `CTXMODE_ROLE=verifier` 污染）、`staticSpawnArgv` 对 `os.execv*`/`os.execl*`/`shell=True`/`args=` 缺乏精确解析（`os.execvp('ssh', ['ssh', 'dmit', 'pig'])` 因 `argv[0]` 重复拼接导致 `<destination>` 错位漏判）。
3. **`[pattern:indirect-wrapper-seg-stdin]`**：`screenSSHHead` 第 1295 行对 `verifier` 使用 `!stdinIsProg` 而非 `!vehicleOnly`（导致 `ssh dmit "rm -rf /tmp/x; sh"` 与 `find . -exec ssh dmit sh \;` 误豁免远端只读检查）；`flock`/`watch -x`/`xargs -a`/`find -ok` 递归时丢失外层 `shellSegment` 的 `stdinRedir`/`pipedStdin`/`heredocText`；`xargs` 与 `find -exec` 的 `{}` 落入命令头或代码槽时缺乏位置感知拦截。

## 决策
1. **C10 三层收紧且保持日常 toolchain 零误拦**：
   - `isSafePathDirEntry` 要求用户 toolchain 段必须位于 `trustedHomeDirs()`（或 `currentScreenCwd()`）之下，`/home/linuxbrew/` 收紧为 `/home/linuxbrew/.linuxbrew`；存在目录经 `isTrustedPathDirOnDisk` 校验 `uid == 0 || uid == euid`、`perm & 0022 == 0` 且 `EvalSymlinks` 不落入 `/tmp|/var/tmp|/dev/shm|/run`；不存在目录校验最近存在祖先，保持离线回放零误杀。
   - `screenPathHeadTrust` 拦截用户可写 toolchain 目录中遮蔽系统核心命令（`userDirForbiddenShadowHeads`）的同名二进制；`transparentShimBins`（`mise`/`asdf`/`rustup`/`pyenv`/`volta`/`fnm`/`corepack`）保留原命令头语义；`screenReadonlyAliasTarget` 对非系统标准别名的软链目标做二次只读白名单校验。
2. **Code 静态 spawn 完整接入 ssh 剥壳与规则优先级对齐**：
   - 新增 `(g guardCall) callerIdentity()`；调整 `guardCtxRunCode` 使 `g.subagent` 先于 `g.strictReadonly` 筛查静态 spawn；在 `staticSpawnArgv` 中支持 `os.execv*` 首参去重、`os.execl*` 变长字面量、`shell=True` 列表与 `args=` 关键字参数。
3. **间接包装器 stdin 保真与执行槽位占位符拦截**：
   - `screenSSHHead` 统一使用 `!vehicleOnly`；`flock`/`watch -x`/`xargs -a`/`find -ok` 透传外层 `seg`，`xargs`（无 `-a`）与 `find -exec` 按真实 `/dev/null` 或参数拼接语义构造派生 `shellSegment`；`replTokenInExecSlot` 精准拦截落在命令头/代码槽/远端命令头的 `{}` 占位符，放行数据参数位。

## 被放弃的方案（必填）
- **一刀切要求所有 PATH 目录 `uid == 0` 或禁止 `~/.local/bin` / `mise/shims`**：否决。会直接打断开发者与子代理日常 `export PATH="$HOME/.local/share/mise/shims:$PATH"` 工作流，违反零误拦原则。
- **对 `ENOENT`（不存在的 PATH 目录）fail-closed**：否决。`execvp` 天然忽略不存在的目录，不存在的目录无法承载植入二进制，而拒绝 `ENOENT` 会在未安装对应工具链的测试机上破坏回放基准。
- **凡 `find -exec` / `xargs -I` 含 `{}` 一律拒绝**：否决。会误杀 `find . -exec grep foo {} +` 与 `find . -exec sh -c 'echo "$1"' _ {} +` 等高频合法命令。

## 来源
`role_guards.go`（`isSafePathDirEntry`、`screenPathHeadTrust`、`peelResolvedSegDepth`、`screenSSHHead`、`guardCtxRunCode`、`staticSpawnArgv`、`screenFindArgsSeg`）；`role_guards_r12_test.go`；关联 `2026-11-01-role-guards-non-sandbox-boundaries.md`（C10）与 `2026-11-04-ssh-peel-followups.md`。

## 落地补充（相对方案核查残留）
- 去掉 `trustedHomeDirs()` 在 `HOME=/root`（或未设）时追加 `/home/*` 通配的逻辑；跨用户家目录 PATH 段（如 `/home/otheruser/.local/bin`）一律拒绝。
- 回归：`TestGuard_R12_RootHomeRejectsForeignHomePath`（不经 `withTestTrustedHome`）。
- ADAPT2：`/usr/local/bin` 等词法系统目录跳过属主 uid 检查，仍拒 group/world-writable（`0022`）与 scratch 软链（代码注释已写明）。
