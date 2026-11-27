# v6.2.2 守卫审计 R24 闭环记录（Oracle R24 + Reviewer R24）

date: 2026-11-28
module: role_guards, shell_ast, hc_prepare
status: active

## 背景

Oracle R24（Must-Fix 6 + Should-Fix 2）与 Reviewer R24（Must-Fix 7 + Should-Fix 1）两份对抗审计在 `f8cd003` 上检出 6 项生产交集 + 1 项文档校准。本轮在 worktree `feat-v622-guard-hardening` 一次性闭环；R24 套件 12 个判别子测试 FAIL-first 于父树 `f8cd003`（第 13 行嵌套短 rest 行为钉在两树均为 PASS，机制自 R23 已存在——Reviewer R24-#4 明确要求该行回归而非判据）。

## 根因与修复要点（留痕口径）

1. **SSH 远端投影全程贯通单请求 xargs 表**：`screenSSHHead`/`sshTunnelsStdinProgram` 先 `xargsEnsureWork(&caller)` 再经 `sshRemoteCallerIdentity`（清远端 env、保留 `cwd` 与 `xw` 指针）贯通 `remoteReadsProgramFromStdinCaller`/`remoteStdinProgramTargets`/`isPureRemoteStdinVehicleCaller`；追加模式 SSH、内层代码审查（`role_guards_peel.go` 的 `g.xw = caller.xw`）与全部派生 `guardCall`/`callerIdentity` 继承父级 `xw`。坑：远端投影表是非 nil 纯赋值追踪器无关的另一条 `stdinProgramHeadsExh` 链，须整条换 caller 版 API。
2. **`+=`/下标赋值不建标量静态绑定**：主 AST collector `emitCall` 对 `a.Append || a.Index != nil` 的纯赋值语句以 `noteShellAssign(name, "", false)` 污染处理（与 eval 重放 `bindEvalOneStmt` 严格对齐），不再以 `staticAssignVal` 建立 `/marker` 标量绑定。
3. **eval 重放与主遍历子进程边界统一 + 增量撤销栈**：`noteEvalStmtFuncDefs`/`noteSameProcessFuncDefs`/`noteEvalStmtReadonlyDecls` 对 `st.Background || st.Coprocess`、管道分量、命令替换、子 shell 一律停向下登记（共享谓词 `childProcStmtBoundary`）；静态 eval 重放对声明命令调 `noteReadonlyDecls`；管道 `b.X`/`b.Y` 各自独立包裹注册表边界。`snapshotProcessRegs`/`restoreRegs` 改增量撤销栈：进入边界不克隆，仅 `noteFuncDef`/`noteReadonlyDecls` 实际插入新键时记入当前 frame，退出删回；`newSub` 的 positional 两表共享引用 + 首次写惰性克隆（`funcNamesShared`/`readonlyVarsShared`）。判别量用字节：n=4→64 注册人口的写less 子 shell 边际分配比率须 ≤1.5（旧树随人口线性增长）。
4. **eval 根操作数算术写有回放所有者**：`taintOperandParamAssigns` 除 `*syntax.ParamExp` 默认赋值外同步扫描 `*syntax.ArithmExp` 内的 `BinaryArithm` 赋值与 `UnaryArithm` 自增减并逐一 `taintVar`（与预扫写集合严格对齐）。嵌套短 rest 链（`command -x eval`）回归行钉 `taintEvalBoundary` 的 PATH+sentinel 全集——机制自 R23 存在，故该行在两树同 PASS，非判别行。
5. **深度截止与步数耗尽区分 + 远端跨段折叠 + 方言保留**：`xargsFeedsCodeFlagDepth` 在 `depth >= peelChainMaxDepth` 显式置 `xw.exhausted`；步数预算仅在被拒绝的第 513 步请求处置位（第 512 步正常完成不置位），`xargsBudgetSpent` 改读 `exhausted` 位而非计数。`remoteStdinProgramTargets` 用 `scopeEnvTracker` 跨段 `foldSegment`（赋值段先折叠再跳过消费），传 `tracker.view(seg.scopePath)`；`stdinProgramHeadsWithEnvExh`/`sshStdinProgramBodiesHit` 携带 `target.bash` 方言位到 `screenStdinProgram`。坑：`splitShellSegmentsCaller` 须接 caller 否则 heredoc 采集丢 cwd。
6. **剥 wrapper 前校验原始身份 + 规范化保留斜杠身份**：`stdinWrapperPeelUntrusted`（内部 `externalWrapperUntrustedPATH`）在 peel 采用前扫描首个外部 wrapper 层——无斜杠且 PATH 不可信即 `exhausted: true`（`command`/`builtin`/`exec` 内建豁免）；canonical 改写前记 `origHasSlash`，仅 `!origHasSlash` 时才触发 `bareHeadUntrustedPATH`，`/usr/bin/ruby3.2` 等带斜杠版本化解释器保住固定路径身份且 `lang` 识别准确。
7. **文档校准**：CHANGELOG 26 行（`foldSegment` 仍每段 peel 一次）、27 行（14 subtests 统一）、R23 条（`newGuardCall`→`currentGuardCall`、删「否定命令」、`stdinRewriteableTarget` 接线时点改述为 R23 本轮）、拆分条（删 byte-exact 残留）全部按树与测量对象改写；R22/R23 note 同步校正。

## 复杂度零回归纪律（本轮实测）

新增函数全部 cognitive < 35：`noteEnumHeadBuiltin` 23（自 `emitCall` 等量提取，非新逻辑）、`externalWrapperUntrustedPATH` 13、`remoteStdinProgramTargets` 9、`isPureRemoteStdinVehicleCaller` 6、`noteProcessRegAdd` 5、`stdinProgramHeadsWithEnvExh` 5、`regInsertFuncNames` 3、`regInsertReadonlyVar` 3、`declClauseArgv` 3、`noteEvalStmtReadonlyDecls` 2（闭包 8）、`stdinCanonHeadRewrite` 2、`childProcStmtBoundary` 1、`remoteReadsProgramFromStdinCaller` 0、`stdinWrapperPeelUntrusted` 0。既有函数全部 delta ≤ 0，经 cccc 前后 JSON 全量 diff 核实（`emitCall` 87→59、`stdinProgramTargetsDialect` 21→19、`stdinTargetsPeelPrologue` 5→4、`noteReadonlyDecls` 18→16、`noteFuncDef` 3→2、`noteSameProcessFuncDefs` 2→1、`snapshotProcessRegs` 2→0 等只降或持平）。`noteEvalStmtFuncDefs` 的顶层 FuncDecl 快路径删除（`syntax.Walk` 以根节点先访问，`noteSameProcessFuncDefs` 单扫描所有者零重复），才使 `childProcStmtBoundary` 守卫下的复杂度回到 1。死助手 `remoteReadsProgramFromStdinCwd`/`stdinProgramHeadsExh` 因 caller 化改写失去全部生产调用方，按 staticcheck U1000 删除（与 R22/R23 死代码清理同例）。

## 验证归档

- FAIL-first（父树 `f8cd003` overlay 最终测试文件，`/tmp/r24-parent-copy`）：`go vet` rc=0；R24 套件 12 FAIL / 1 PASS（PASS 行 = 嵌套短 rest 回归控制，机制自 R23 已钉，非判别行）。修复树同套件 13/13 PASS。
- cccc 全量前后对照：新增 < 35、既有 delta ≤ 0（明细见上节）。
- `make check` 与 3 轮 `-race -count=10` 记录见交付报告。

[pattern:role-guards-r24-closure]
