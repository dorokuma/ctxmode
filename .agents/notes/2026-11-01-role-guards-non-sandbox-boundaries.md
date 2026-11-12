---
status: active
superseded_by: ""
supersedes: ""
模块: ctx_run
---

# role_guards 是应用层静态词法门禁而非沙盒：三类已知可绕过边界

## 一句话结论
`role_guards.go` 的角色门禁（`subagent_nested_agent` / `readonly_write_blocked`）是执行前的应用层静态词法与 argv 预检，不是内核级沙盒；它挡得住文本上可见的被禁命令头与写原语，但存在运行期才求值、词法层不含任何静态原语字面量的已知绕过形态，强隔离必须由独立 OS 沙盒层承担。

## 背景
角色门禁在 `ctx_run`（execute/execute_file/batch/run_task）与 `ctx_kb`/`ctx_bg`/`ctxmode index` 等入口对 argv 与代码文本做静态扫描：剥 wrapper、分词、用 `pythonMask`/`jsMask`/`codeCommentText` 遮蔽字符串与注释后按标识符边界匹配 spawn/write 原语表。该设计刻意不做语义求值，因此对"词法层完全不含被禁字面量"的构造存在结构性盲区；同时遮蔽式匹配也天然带来字符串误报风险（本轮已按字节对齐重构 `pythonWriteModeHit`/`jsFsOpenWriteHit` 消除已知误报）。

## 决策
在文档与 README 安全模型层面明确记录三项已知边界，门禁本身保持纯词法实现：

1. **Shell 动态变量/参数间接拼装命令头**：词法扫描看到的是 `$c$d`、数组展开、`${!var}`、`eval "$x"` 这类展开点，而不是它们运行期求值后的命令头。当拼出的命令头（如 `c=p; d=ig; $c$d run`）在文本里从不出现静态代理字面量（`pig`/`tmux`/`rm` 等）时，两道门禁都不会命中；`eval`/heredoc/`$(...)` 中已做深度截断与递归筛查，但变量赋值链路本身不求值。

2. **解释器动态反射/字符串拼接别名**：`getattr(__builtins__, '__im'+'port__')`、Python `vars()['ev'+'al']`、JS `globalThis['ev'+'al']`、`Reflect.construct` 等在词法层完全不出现 `eval`/`__import__`/`exec`/`Function` 原语标识符，原语表自然落空。

3. **非解释器命令的未加引号 heredoc 正文词法近似**：`cat <<EOF` 等正文复用 `scanInlineSubstitutions` 扫描内嵌 `$(...)` 与反引号时，正文中的 `'...'` 会按普通 shell 词法作为单引号字面量跳过；而真实 shell 在未加引号 `<<EOF` 正文内并不把单引号当引号（`'` 内仍展开 `$(...)`）。保留该静态近似、不为 heredoc 单独维护第二套无单引号展开器，属有意识的词法边界。

三类形态的共同点是：真正危险的标识符只在运行期由解释器求值产生，静态文本中没有可锚定的字面量。

## 被放弃的方案（必填）
- **在 ctxmode Go MCP 层内嵌完整 Shell/Python/JS 运行时求值器**：否决。要对变量展开、间接引用、反射调用做正确求值就必须复刻各解释器的完整语义（作用域、加载序、属性查找、元编程），任何简化实现都会与真实解释器行为漂移，反而产出"看似求值过、实则漏判"的虚假安全信号；同时引入巨大的维护与每次调用延迟成本，与"预检要快且可推理"的设计目标冲突。
- **复杂跨过程污点分析**（数据流跟踪变量赋值→展开点、反射目标推导）：否决。跨函数/跨模块/动态属性下的静态污点精度上限低，误报会淹没正常只读调用，漏报面也并未收敛到可证明的边界内；投入产出不成立。
- **在门禁层声称进程/文件系统强隔离**：否决。词法门禁只负责"在工具入口处拒绝形态可识别的违规调用"，进程级、文件系统级强隔离属于独立 OS 沙盒层（容器/命名空间/seccomp/Landlock 等）的职责——ctxmode 明确"NOT a sandbox"，边界笔记的作用正是防止这层应用预检被误当成沙盒。

## 来源
`role_guards.go`（`guardCtxRunShell`/`guardCtxRunArgv`/`guardCtxRunCode`、`pythonMask`/`jsMask`/`codeCommentText`、`codeSpawnPrims`/`codeWritePrims`/`blockedAgentExecutables`）；README「Security model — NOT a sandbox」；dispatch 角色模型中 worker/reviewer/verifier 等只读与子代理约束。

## C 档复审观察项与设计权衡归档（2026-11-03）

oracle 第 1 轮复审输出的 5 条 `consider` 观察项及结论，逐条归档如下（均为刻意的 fail-closed / 信任边界设计，非缺陷）：

- **C1 `screenEnvAssignments` 严格双向身份等价校验**：env 运算重放以调用者自身的 `CTXMODE_ROLE`/`CTXMODE_READONLY` 为起点，凡是产出与调用者身份不等价的组合一律拦截——包括同向改名（如把 `worker` 改成另一个角色名）与临时自降（worker 给自己追加 `CTXMODE_READONLY=1`）。这是刻意的 fail-closed 设计：身份字段是门禁的输入而不是数据，任何使其漂移的 env 序列都视同逃逸尝试，宁可误伤也不放行。
- **C2 `guardCtxRunStdinForCommand` 的 stdin-program head 短路**：当 peeled argv 头部是会从 stdin 读程序的解释器/shell（裸 `sh`/`python3`/`node` 等无 `-c`/`-e` 形态）时，stdin 载荷直接按代码筛查并短路返回；与 `guardShellSubagent` 对 heredoc 正文的筛查形成互补——前者覆盖 argv 携带的 stdin 通道，后者覆盖命令文本内嵌的 `<<EOF`/`<<<` 通道，两条入口各自把不可见载荷当作代码走完整门禁，无漏口。
- **C3 `guardCtxRunEnv` 与 `isDeniedEnvKeyForCaller` 的双层纵深**：`guardCtxRunEnv` 在工具入口处筛查显式 `env` 参数/赋值，`isDeniedEnvKeyForCaller` 在执行钩子弹射变量（`GIT_PAGER`/`EDITOR`/`LD_PRELOAD`/`BASH_ENV`/`PROMPT_COMMAND`/`NODE_OPTIONS`/`PYTHONSTARTUP`/`PERL5OPT`/`RUBYOPT`/`JAVA_TOOL_OPTIONS` 等）层面做第二道拦截。两层名单是文档与代码需要同步维护的点：新增执行钩变量时必须同时进入两处，否则会出现一层放行一层拦截的口径漂移。
- **C4 `CTXMODE_ROLE=worker` 叠加 `CTXMODE_READONLY=1` 取严为 `strictReadonly`**：worker 不在只读角色名表内，但显式 `CTXMODE_READONLY=1` 标志优先，该组合按 `auditCallerIsStrictReadonly` 取严处理（worker 无 verifier 豁免，直接落入 strict 集合）。已在 `role_guards.go` 顶部角色分类注释显式点明，与表驱动测试一致。
- **C5 `deploy.sh` 的 `unlock_immutable -> mv -> lock_immutable` 毫秒级窗口**：`deploy.sh` 在原子替换运行中二进制时先解 immutable 锁、`mv` 原子替换后立即重新加锁，窗口仅毫秒级。该锁的定位是同 root 信任边界内的防误覆盖锁（防止常规写操作意外破坏部署产物），并非针对攻击者的权限沙盒——同 root 进程本来就握有解锁能力，窗口不构成新增威胁面。
- **C6 `ctx_run action=batch` 无 `stdin` 字段面**：`batch` 的每个子命令结构体（`batchCommand`，`batch.go`）仅接受 `label` 与 `command` 字符串，协议层不存在独立 `stdin` 输入通道；所有内联载荷（如 heredoc / `<<<`）均位于 `command` 文本中，并经 `guardCtxRunShell`（子代理走 `guardShellSubagent`、只读走 `guardReadonlyShell`）逐条筛查，命中按命令粒度拒绝（`guardCommandBlocked`），不存在绕过 command 文本的第二条载荷通道。
- **C7 `ctx_run action=run_task` 输入面收敛**：`run_task` 仅接受受控 `kind` 白名单（`validRunTaskKinds`：go/npm/cargo/make/custom）、`target`、`args` 与 `env`，无自由 `command`/`code`/`stdin` 通道；`strictReadonly` 直接整入口拦截，`verifier` 与 `worker` 的 `args`/`env` 均继续经子代理嵌套（`guardCtxRunArgv`）与环境钩子（`guardCtxRunEnv`）门禁校验，构造出的 argv 与 `ctx_run action=execute` 走同一套筛查。
- **C8 `withScreenCwd` 串行化假设**：门禁预检期切换/解析相对路径的辅助逻辑建立在单次工具预检串行求值之上（MCP server 由 `jsonrpc2.HandlerSerializer` 串行化请求，同一时刻只有一次调用在被筛查，`runtime.LockOSThread` 作纵深防护），不跨并发进程共享可变全局工作目录；真并发执行由各 `exec.Cmd.Dir` 独立承载，`screenCwd` 只在预检窗口内存在且随 defer 还原。若未来协议层引入并发预检，可将 `cwd` 收敛进调用上下文结构体（如 `guardCall` 显式字段）并向 `resolveHeadBase` 显式传参，从而彻底移除包级 `screenCwd` 与 `LockOSThread`。
- **C9 `deploy.sh` 预检重试窗口临时清除 EXIT trap（deploy.sh:170-184）**：`deploy.sh` 在解锁线上二进制之前的 `set +e` MCP `initialize` 探针重试循环中临时执行了 `trap - EXIT`（随后恢复 `trap cleanup_on_error EXIT`）；该极窄窗口内若收到外部 `SIGINT`/`SIGTERM` 可能遗留 staging 临时文件 `$TMP_FILE` / `$TMP_FILE.err`，但此时线上 `$BINARY` 尚未解锁（仍保持 `0555` + `chattr +i`），不影响线上二进制与不可变锁安全性；正常成功与探针失败退出分支均已显式清理临时文件，后续如需进一步收紧可拆分 `ERR` 与 `EXIT` trap。

附注：`run_task.go:103` 的 run_task 拦截仅针对 `guard.strictReadonly`（即只读角色集合减去 verifier）；`verifier` 因此仍可使用固定 `kind` 白名单的 `ctx_run action=run_task`，其 `args`/`env` 参数继续走子代理嵌套门禁筛查（`guardCtxRunArgv`/`guardCtxRunShell`），身份与环境字段不受豁免。

## SH11 round-8 复审 consider 归档（2026-11-06）

- **O3（rt1111）[pattern:argv-parser-out-of-scope-eval]** argv 预检器（`parseNpmFamilyArgv`/`npmFamilyOptTable`）不求值 npm 生态的运行期配置面：`package.json` `scripts.*`（npm/pnpm/yarn run 钩子里的脚本）、`.npmrc`/`npm_config_*` env 驱动的配置键（`pre-install`/`install`/`postinstall` 脚本注入、registry 覆盖）均不在词法屏范围内。该边界**非本 diff（rt1111）引入**：argv parser 语义边界在 `argv` 层止于事前能静态看到的字面词；这些执行面的求值归 npm/pnpm/yarn 各自的运行时语义，预检层不为它们内嵌解释器。属固定边界（考虑项，非 must fix）；如需覆盖须在独立进程层拦截（如 sandbox 环境剥除 `npm_config_*` 前缀、或 deploy 阶段冻结 `scripts`/`npmrc`）。
- **C10 [pattern:path-trust-user-writable] PATH 信任表含用户可写目录段**：`isSafePathDirEntry` 把 `/home/linuxbrew/` 前缀、`/.local/bin`、`/.local/share/mise/shims` 等 dev-toolchain/包管理器目录视为可信 PATH 段；`headBaseAliasHits`/`resolveHeadBase` 在解析命令头时同样走这份信任。若此类用户可写目录被植入同名恶意二进制，命令头会被解析为已放行名而绕过名白名单。该边界**非本 diff（readonly allowlist + 守卫加固）引入**，属刻意的信任边界权衡：这些目录本身已握有执行权（PATH 中任何二进制都在用户权限下运行），门禁层的 PATH 筛查目标是挡"明显不可信的可写区"（`/tmp`/`/var/tmp`/`/dev/shm`/`/run` 已显式拒绝），不为用户家目录内已有的执行位做第二层防植入。标记为 consider（非 must fix）；如需收紧可在 `isSafePathDirEntry` 引入"仅 root 可写"校验（`os.Stat` mode 位 + owner 检查），代价是失去 portable 信任语义并引入每次调用的 stat 开销。关联 round-8 审查与 `role_guards.go` `isSafePathDirEntry`/`headBaseAliasHits`。
