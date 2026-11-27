# v6.2.2 守卫审计 R23 闭环记录（Oracle R23 + Reviewer R23）

date: 2026-11-28
module: role_guards, shell_ast, hc_prepare
status: active

## 背景

Oracle R23（Must-Fix 6 + Should-Fix 2）与 Reviewer R23（Must-Fix 8）两份对抗审计在 `b9d481e` 上检出 8 项交集问题。本轮在 worktree `feat-v622-guard-hardening` 一次性闭环，全部 11 个判别子测试 FAIL-first 于父树 `b9d481e`。

## 根因与修复要点（留痕口径）

1. **单请求共享一份 xargs 预算**：`guardCall` 预初始化一份 `xw *xargsWorkState`（`currentGuardCall` 铸造），全部派生身份经 `pickRequestXargsWork` 继承同一指针；`xargsEnsureWork` 在首个递归消费前把新表写回 caller（按值传递的修复）；无 caller 入口（`stdinEntryCaller`）预装自己的表。零值手工 guardCall 保留偶发欠共享但绝不跨请求的退路。坑：测试须断言 `c1.xw == c2.xw` 指针同一，且另一新 guardCall 独立满预算。
2. **赋值运算符身份随序列化传递**：`assignToPrefix` 丢弃 `Append`/`Index` 会把 `PATH+=/x` 与 `arr[1]=v` 抹成独立常量覆写。并行 `assignFlags` 字节串随段传递，`foldAssignWord` 仅对纯标量 `=` 且 RHS 无自引用/动态才清除 taint；`+=` 在旧值确定时保留自引用形式、不确定时保持 taint，下标写绝不建立标量精确值。坑：复杂度预算下 `foldAssignWord` 的三个分支形态（cond/index/append）提取为 `taintTrackedVar`/`foldAppendWrite`。
3. **函数定义/readonly 按执行作用域传播**：同进程复合块（`{ }`、if/while/for/case 体）内的 `FuncDecl` 登记进当前进程；子 shell/管道段/后台/命令替换退出时恢复父快照（`snapshotProcessRegs`/`noteSameProcessFuncDefs`）。eval 重放与主遍历共用同一登记助手。`PIPESTATUS` 与 `_` 入 non-bindable 表（每条命令被 shell 重写）。
4. **eval 操作数求值写与重解析写分属不同所有者**：`writeNamesInStmtFuncs` 对 bind 根调用截断到首词时同时扣掉了操作数词片自己的参数展开写（`${X=/v}`），动态操作数回放只污染 sentinel 集不覆盖普通变量——写凭空消失。`taintOperandParamAssigns` 对每个存活链判定显式扫描操作数词片；嵌套两条回放路径对短/无 rest 的 Taint 链统一走 `taintEvalBoundary`。
5. **远端认证查全表，xargs 预算耗尽与命中可分**：`remoteStdinProgramLangsCwd` 遍历全部非数据目标并传播 exhaustion（heredoc/here-string 流按深度判定失败）；`isPureRemoteStdinVehicleCwd` 要求每个非数据目标都是正面识别的纯 shell（`stdinTargetsAllPureShell`）。`xargsBudgetSpent` 读共享表的粘性耗尽位，`stdinXargsTargets` 在预算耗尽时即使内层是 cat 也返回 `exhausted: true`。死助手 `stdinProgramHeadCwd`/`stdinProgramHeadCwdExh`/`xargsWork` 删除。
6. **裸头先判 PATH 可信再采用任何解析**：`bareHeadUntrustedPATH` 在 typed 分支之前拦截一切无斜杠头——PATH 不可信时裸 `sh` 也是身份不明（exhausted），固定绝对拼写不受影响。`hc_prepare` 两入口共享 `stdinRewriteableTarget` 是本轮 R23 才接线的：R23 diff 前脚本入口仍走 `stdinSingleShellTargetDialect` + 内联拒绝；缺的是投影侧拦截。
7. **嵌套纯赋值跳过条件写反 + O(1) 父查表**：`collectOneStdinSeg` 的 `!seg.pureAssign` 只包住空头检查，真正纯赋值逐段复制前缀（4/8 段复制 10/36 ops）。fold 后 pureAssign 直接 return nil；`stateFor` 切尾 id 一步查父；heredoc 侧 `segNeedsConsumerView` 仅在屏幕实际读 runEnv 时物化。
8. **文档校准**：CHANGELOG 19/24-27/40 与 R22 closure note 按 blob 与测量对象分别写数（详见 R22 note 内联 R23 校正标记与 CHANGELOG R23 条）。

## 复杂度零回归纪律（本轮实测）

cccc 既计 bool 运算也计嵌套，新增分支靠等量提取补偿。本轮提取 helper：sshStdinProgramBodiesHit 12 / sshExhaustedStdinHit 6 / stdinTargetsAllPureShell 6 / stdinProgramHeadsExh 5 / stdinTargetsPeelPrologue 5 / taintOperandParamAssigns 3 / assignOpFlag 3 / segNeedsConsumerView 3 / stdinXargsInnerTarget 2 / stdinInnerHeadLang 2 / snapshotProcessRegs 2 / noteSameProcessFuncDefs 2 / bareHeadUntrustedPATH 2 / taintTrackedVar 2 / foldAppendWrite 2 / replayEvalOperandTail 2 / noteEvalStmtFuncDefs 1 / evalChainSkippable 1 / taintShortRestBoundary 1 / nestedEvalMustTaint 1 / assignFlagAt 1 / pickRequestXargsWork 1 / xargsEnsureWork 1 / xargsBudgetSpent 0 / sshRemoteCallerIdentity 0 / restoreRegs 0 / stdinEntryCaller 0。既有函数全部 delta ≤ 0（screenSSHHead 50→34、stdinProgramTargetsDialect 22→21、bindEvalOneStmt 20→19、stdinXargsTargets 8→3、foldAssignWord 11→8、bindEvalCallWrites 7→5、stateFor 11→9 等只降或持平）。

## 验证归档

- FAIL-first（父树 `b9d481e` overlay 最终测试文件）：`go vet` rc=0；R23 套件 11 FAIL / 0 PASS。修复树同套件 11/11 PASS。
- `make check` rc=0（go test -race 441.097s + staticcheck + Pi 40/40）；3 轮 `-race -count=10` 记录见交付报告。
- 环境性伪失败留痕：`TestAlFix7_FuzzArgvDiff` 的非 race 形态（N=20000）在父树未改代码上同样报 `no space left on device`（tmpfs inode 压力，宿主环境伪影），race 形态（N=2000，门禁所用配置）两树均绿——非本轮改动引入。

[pattern:role-guards-r23-closure]
