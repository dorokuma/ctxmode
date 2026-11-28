# v6.2.2 守卫审计 R25 闭环记录（Oracle R25 + Reviewer R25）

date: 2026-11-28
module: role_guards, shell_ast
status: active

## 背景

Oracle R25（Must-Fix 7 + Should-Fix 2）与 Reviewer R25（Must-Fix 8 + Should-Fix 2）两份对抗审计在 `028ac50` 上检出 6 项生产交集 + 1 项文档校准。本轮在 worktree `feat-v622-guard-hardening` 一次性闭环；R25 套件 10 个判别子测试 FAIL-first 于父树 `028ac50`（闭环时第 11 行 legacy 纯载体委托在两树同 PASS——两份实现当时对四形状取值一致，属回归控制非判别行）。（R26 勘误：Reviewer R26-#9 判定该第 11 行与生产入口等价参数调用同一函数、不具判别力，R26 已删除该同义反复控制行；`TestGuard_V622_OracleR25Probes` 此后保持 10 个判别子测试。）

## 根因与修复要点（留痕口径）

1. **declare 家族内联赋值的运算符判决与 emitCall 对齐**：`emitDecl` 对具名非 Naked 赋值不看 `a.Append || a.Index != nil`，`declare ARR[1]=/marker`/`declare VAR+=/marker` 直接以 RHS 建立标量绑定。提取 `noteDeclInlineAssign`：append/下标一律 `noteShellAssign(name, "", false)` 污染，普通 `=` 保持精确绑定（并经 readonly 门）。
2. **readonly 重放覆盖 POSIX CallExpr 与 declare -r 标志词**：POSIX 的 `readonly NAME` 解析为 `*syntax.CallExpr`（mvdan parser 方言分流），原扫描只处理 `DeclClause`；bash `declare -r` 的 `-r` 是 `Naked=true, Name=nil, Value=<词>`，`assignToPrefix` 对 Name==nil 序列化为空串丢失 `-r`。修复：`declClauseArgv` 对该形状用 `wordToArg` 序列化标志词（与 emitDecl 一致）；`noteEvalStmtReadonlyDecls` 增加 CallExpr 分支（`callArgsArgv`，与 emitCall 的词转换一致）。
3. **非 nil 空注册表别名 + 子进程 eval 重放隔离**：(a) 增量撤销栈删到空后 `len==0` 的非 nil map 被 `newSub` 当私有——共享判定改 `!= nil`。(b) 后台/协程 eval 语句的重放丢失进程位：`bindEvalCallWrites`/`bindEvalOneStmt` 对 `st.Background || st.Coprocess` 用 `defer c.snapshotProcessRegs()()` 包裹整条语句重放——变量保守污染**不受影响**（污染属于可能性，不属于进程归属），positional 登记随子进程回滚。(c) `taintHiddenEvalWrites` 的 walker 换成进程边界感知递归 `scanHiddenEvalNode`/`scanHiddenEvalDispatch`/`scanHiddenEvalStmt`：管道分量、命令/进程替换、子 shell、协程、后台语句各在自己的 frame 内扫描子树（syntax.Walk 无退出钩子，frame 必须由显式递归驱动——这是本轮最大的坑：闭包内 `defer` 会推迟到整个扫描结束，错杀同进程后续登记）。
4. **替换模式深度截止登记 exhaustion**：`replTokenInExecSlotDepth` 自有 `depth >= peelChainMaxDepth` 出口原只返回 true；现经 `xargsMarkSharedWorkExhausted`（caller.xw != nil 时）置位，与 append 模式截止一致。坑：内层 xargs 不带自己的 -I 时令牌不向下传播，但深度 0 的替换扫描独立沿链下钻，截止仍在该扫描内命中。
5. **SSH 正文环境 + xargs 内层方言 + 纯载体委托**：(a) `sshStdinProgramBodiesHit` 对每个 target 用 `sshRemoteCallerIdentity(caller).seededWith(target.envAs)`（保留本地 role/readonly/cwd/xw，远端 envAs 作基底）。(b) `stdinXargsInnerTarget` 回退空语言目标用 `stdinInnerShellBashDialect`（委托 `hcShellDialectBash`）填 bash 位。(c) `isPureRemoteStdinVehicleCwd` 改单行委托 `isPureRemoteStdinVehicleCaller(argv, stdinEntryCaller(cwd))`，平行实现删除。
6. **逐层 wrapper 校验 + 斜杠身份保留**：`externalWrapperUntrustedPATH` 重写为逐层跟随（`peelOneWrapperLayer`/`skipExternalWrapperLayer`/`skipTransparentBuiltinArgs`/`skipNiceWrapperArgs`）：KEY=VAL 折入 layerEnv，`--`/noop/关键字跳过，`command`/`builtin`/`exec` 内建豁免但消耗其选项区，`env` 经 `skipEnvOperands` 折叠并重写剩余 argv（与 peelWrappers 的 argv=rest 语义一致），timeout/stdbuf/ionice/taskset/chrt/strace/time/setsid/nice/nohup/busybox 用各自 skip helper 消耗选项区；每层**采用**裸外部 wrapper 前检查 `layerEnv.pathUntrusted(basePath) || caller.pathUntrusted()`。坑 1：`command -v/-V` 查询形态 peel 直接停止——扫描也必须停，否则死循环。坑 2：`skipTimeSingleArgs`/`skipPlainFlagZone` 已存在可复用，nice 需新增选项区 skipper。canonical 改写：`stdinCanonHeadRewrite` 用 `filepath.Join(filepath.Dir(head[0]), canon)` 保留目录前缀，`stdinProgramTargetsDialect` 的文件解析用改写前原始拼写 `origHead`。
7. **闭包零增长门禁按含闭包口径复核**：三个正增长闭包提取为单行委托（`snapshotProcessRegs` 的恢复闭包→`restoreProcessRegFrame`，frame 增 `restored` 位保证幂等；`taintOperandParamAssigns` walker→`taintOperandWalkNode`；`noteSameProcessFuncDefs` walker→`visitSameProcessFuncDefNode`）。多重集配对按 file+receiver+name+出现序号，重复键实例逐一核对（`wordToArg`/`pathUntrusted`/`guardArgvReadonly` 等同名不同 receiver 均双侧同现且数值一致）。实测：523 共享、33 新增、3 删除、**0 正增长**，新增最大 `noteEnumHeadBuiltin` 23（R24 既有提取）、`bindEvalOneStmtBody` 19。

## 验证归档

- FAIL-first（父树 `028ac50` overlay 闭环时测试文件，`/tmp/r27-parent` 已删）：`go vet` rc=0；R25 套件 10 FAIL / 1 PASS（PASS 行 = legacy 纯载体委托回归控制，该行后于 R26 按 Reviewer R26-#9 删除）。修复树同套件闭环时 11/11 PASS（R26 删除该控制行后 10/10 PASS）。
- cccc 全量前后对照：0 正增长、新增 < 35（明细见上节）。
- `make check` 与 3 轮 `-race -count=10` 记录见交付报告。

[pattern:role-guards-r25-closure]
