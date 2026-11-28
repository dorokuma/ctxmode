# Role Guards R29 闭环（Oracle R29 4 Must-Fix + 3 Should-Fix 与 Reviewer R29 4 Must-Fix + 2 Should-Fix 交集）

Oracle R29（4 Must-Fix + 3 Should-Fix）与 Reviewer R29（4 Must-Fix + 2 Should-Fix）两份对抗审计在 `8b4e3d5` 上检出交集：隐藏 eval 扫描的重定向求值顺序与循环回边可见性、主遍历协程 Name 词覆盖、directExec 下 shell 语法词与内建 wrapper 剥离、原生 plain-argv 入口身份、空头证明与正式投影的作用域环境一致性、引号赋值形命令头、重写资格判定的动态占位符覆盖，以及别名顺序断言判别力与版本证据账目问题。本轮在 worktree `feat-v622-guard-hardening` 一次性闭环；R29 套件 4 个一级子测试**全部** FAIL-first 于父树 `8b4e3d5`（`GOTOOLCHAIN=go1.26.0 go vet .` rc=0），修复树 4/4 PASS。

## 根因与修复要点（留痕口径）

1. **重定向先于语句体扫描 + 循环回边 + 协程 Name（Oracle R29-M2 + 观察项 / Reviewer R29-#1）**：
   - `scanHiddenEvalStmtBody` 改为先扫描 `ist.Redirs`（提取 `scanHiddenEvalRedirs`），再 `noteHiddenEvalStmtDirectRegs(ist.Cmd)`、再 `taintOneEvalCallWrites`、再命令子树下降——`{ eval() { :; }; } >/dev/null/$(eval)` 的块入口重定向在进入块体前求值，不再受块内后置定义逆向遮蔽。
   - `taintEvalTextWrites` 与 `bindEvalOneStmtBody` 不再有任何预登记（`noteHiddenEvalStmtDirectRegsBoundary` 删除——无其余调用方）；语句自身直接事实统一由 `scanHiddenEvalStmtBody` 在重定向扫描之后就地登记，两个重放循环共享同一位置序。
   - `scanHiddenEvalChildFrame` 对 `*syntax.ForClause`/`*syntax.WhileClause` 走 `scanHiddenEvalLoopNode`：记录首遍前后 `len(c.funcNames)`/`len(c.readonlyVars)`，有新增登记时对循环节点**单次**再扫一遍（有界最多 2 遍；同名再登记不增长登记表，故嵌套循环不会级联放大）——`for x in 1 2; do eval; eval() { :; }; done` 第二轮迭代可见第一轮定义，直线块 `{ eval; eval() { :; }; }` 仍只扫一遍。
   - `walkStmt` 的 `case *syntax.CoprocClause:` 提取为 `walkCoprocStmt`（保持 `walkStmt` 复杂度零正增长），`cmd.Name != nil` 时先 `emitNestedFromWord(cmd.Name, stdinFeed{})`——与隐藏重放帧的 Name 覆盖对齐。
2. **原生 plain-argv 入口身份 + directExec 语法豁免（Oracle R29-M3 / Reviewer R29-#2）**：
   - `role_guards_subagent.go` 新增 `guardCall.argvCallerIdentity()` = `callerIdentity().withDirectExec(true)`；`guardCtxRunStdin` 与 `prepareCtxRunArgv` 原生 plain-argv 分支改用之（显式 shell 文本入口保持 `g.callerIdentity()`）。
   - `peelCoreStep`（提取 `peelCoreGrammarStep`/`peelCoreDirectBuiltinVerdict`/`peelDirectExecLexing` 保持零复杂度正增长）：`tk.directExec` 时赋值形/无操作/保留词**不剥离**（OS execvp 无 shell 词法；`env` 自身仍由 `case "env"` -> `skipEnvOperands` 剥离）；`tk.directExec` 且 `isShellBuiltinWrapperBase(base)`（`command`/`builtin`/`exec`）时——不可信 PATH 经 `tk.untrusted()` 拒绝（exhausted），可信 PATH 停止剥离并返回 `done: true` 残段头（OS execvp 绝不以内建语义分派）。
   - `role_guards_handlers.go`（`stdinProgramTargetsDialect` 别名重写，提取 `stdinHeadAliasAdoptable`）与 `role_guards_shell.go`（`peelWrappersAndWrapperAliasesChecked`，提取 `peelWrapperAliasAdoptable`）在 `directExec` 下排除 `isShellBuiltinWrapperBase(rb)`。可信空目录 `emptyDir` 下 `watch -x command /bin/sh`、`flock /tmp/lk command /bin/sh`、`xargs command /bin/sh`、`exec command /bin/sh` 投影 nil；shell 入口 `command /bin/sh` 仍认证 `/bin/sh`。
3. **空头证明与正式投影共用作用域环境 + 引号赋值形命令头（Oracle R29-M4 / Reviewer R29-#3）**：
   - `hc_prepare.go` 新增 `segHasQuotedAssignHead`（`!pureAssign` 时 `argWords` 第一个非 nil 下标对应 `argv` 词若为 `isAssignWord` 即引号命令头）与 `peelSegProvesEmptyHead`（`pureAssign` 快路 true、引号头 false、否则以 `inherited`/`basePath` 建 tracker 并双 peel 复核）；`segQuotedAssignHeadVerdict`（可信 PATH `data: true`、不可信 `exhausted: true`）与共享投影 `stdinSegProjectTargets`。
   - `scriptAllowsLocalShellStdinPrepareDialect`（提取 `stdinConsumableSegView` 保持零复杂度正增长）、`collectOneStdinSeg`、`stdinTargetsWithDataFallback`（签名加 `runEnv`/`subPath`）三处：`pureAssign` 快路先于任何 view 物化，非纯赋值段先算 `runEnv = ...merged(tracker.view(seg.scopePath))` 再以 `peelSegProvesEmptyHead` 判定——证明与投影共用同一作用域 `runEnv`/`basePath`。
4. **重写资格判定统一 isDynamicArg（Oracle R29-M5）**：`envsUntrustedForRewrite` 的 `strings.Contains(..., cmdSubPlaceholder)` 改为 `isDynamicArg`——全双引号动态 PATH 值与裸占位符同为不可信环境。
5. **R27-4 别名顺序断言强化（Oracle R29-S1 / Reviewer R29-#4）**：断言升级为 `!ordExhausted || len(ordHead) == 0 || ordHead[0] != "myenv"` 全假即失败——先验拒绝保留原名 `myenv`（先重写再拒绝会变成 `env`，两者 exhausted 同为 true，单靠 exhausted 无法区分）；诊断文案更正（改写产物是裸规范名 `env`，非带斜杠路径）。
6. **文档与历史勘误校准（Oracle R29-S2/S3 / Reviewer R29-#5/#6）**：`role_guards_shell.go` 兼容说明、CHANGELOG R26/R27 条目、R26/R27/R28 closure 全部按三分精确口径与下述历史更正就地互引。

## S2/S3 历史勘误（保留原始观测、错误机械判词与正确门限分离）

1. **nil-tracker `peelWrappers` vs `abe543b` 三分类**：(i) 已有动态选项值（`timeout -k $DYN`）返回 `(argv[i:], true)` 逐字节恢复 `abe543b`；(ii) `timeout -k` 尾缺选项值在 `abe543b` 经循环尾钳位已返回 `([], true)`，新实现在 skipper 边界直接返回 `(len, true)`，顶层同为 `([], true)`——无行为变化；(iii) `taskset -p`/`chrt -p` 静态 PID 新旧同为 `([], false)`，尾缺 PID 旧 `([], false)` → 新 `([], true)`，动态 PID 旧 `([], false)` → 新 `(["-p", $DYN], true)`。
2. **R27 closure 新增最大**：「最大 20」仅限直接父基线 `0d907a8`；跨基线 `abe543b`/`f8cd003` 新增最大为 **23**（`peelFlagZone`、`noteEnumHeadBuiltin`）。
3. **`role_guards_shell.go` 修改史**：R22（`b9d481e^..b9d481e`）已修改（**+162/−57**），R23 +88/−21；R24..R27 四步窗口内首次修改为 R26（**+352/−169**）。
4. **R28 计数勘误**：`+462`（numstat `+447/−15`）与 `7220` L1 PASS 的勘误对象为 **Worker R29**（非 R28）；旧 `parent-test.log:176-193` 另七行亦有具体断言消息的勘误已补入 R28 closure；`8b4e3d5` 真实 diff 分母为 **11 文件 +627/−83**（`shell_ast.go` **+119/−36**，155 为触及行数）。

## 复杂度多重集核对（`cccc --no-config --no-cache`，(file, kind, parent, name, occurrence_index) 含闭包多重集）

七文件基组：`shell_ast.go`、`role_guards_handlers.go`、`role_guards_peel.go`、`role_guards_shell.go`、`role_guards_heredoc.go`、`role_guards_code_env.go`、`hc_prepare.go`（总实例 **714**）；八文件核验口径为七文件基组 + `role_guards_subagent.go`（总实例 **764**，R28 起核验口径含全部受影响生产文件）。（R32 勘误：原文误将基组第 6 个文件写成 `shell_screen.go`，正确为 `role_guards_code_env.go`；且原 657/20/6 系列数字仅按 (file, name) 配对、未含 `parent`/`occurrence_index` 键，本节数字已全部按标准含闭包多重集键重测。）

**七文件基组（714 实例）**：

- 对比 `8b4e3d5`（直接父，701 实例）：**700 shared / 14 added / 1 deleted / 0 positive deltas**（5 down，695 same，0 up）；
- 对比 `1aa4752`（696 实例）：**695 shared / 19 added / 1 deleted / 0 positive deltas**（5 down，690 same，0 up）；
- 对比 `0d907a8`（681 实例）：**680 shared / 34 added / 1 deleted / 0 positive deltas**（11 down，669 same，0 up）；
- 对比 `abe543b`（672 实例）：**665 shared / 49 added / 7 deleted / 0 positive deltas**（16 down，649 same，0 up）；
- 对比 `f8cd003`（642 实例）：**638 shared / 76 added / 4 deleted / 0 positive deltas**（25 down，613 same，0 up）。

**八文件核验口径（764 实例）**：

- 对比 `8b4e3d5`（直接父，750 实例）：**749 shared / 15 added / 1 deleted / 0 positive deltas**（5 down，744 same，0 up）；
- 对比 `1aa4752`（744 实例）：**743 shared / 21 added / 1 deleted / 0 positive deltas**（5 down，738 same，0 up）；
- 对比 `0d907a8`（729 实例）：**728 shared / 36 added / 1 deleted / 0 positive deltas**（11 down，717 same，0 up）；
- 对比 `abe543b`（720 实例）：**713 shared / 51 added / 7 deleted / 0 positive deltas**（16 down，697 same，0 up）；
- 对比 `f8cd003`（690 实例）：**686 shared / 78 added / 4 deleted / 0 positive deltas**（25 down，661 same，0 up）。

全部新增函数 cognitive < 35（最大 `scanHiddenEvalRedirs`/`peelCoreGrammarStep` 7、`peelSegProvesEmptyHead`/`segHasQuotedAssignHead` 5、`stdinHeadAliasAdoptable`/`peelWrapperAliasAdoptable` 4、`segQuotedAssignHeadVerdict` 3、`scanHiddenEvalLoopNode`/`walkCoprocStmt`/`stdinConsumableSegView`/`peelCoreDirectBuiltinVerdict` 2、`isShellBuiltinWrapperBase`/`peelDirectExecLexing`/`stdinSegProjectTargets` 1、`argvCallerIdentity` 0）。被修改既有函数无一正增长（`peelCoreStep` 13→10、`peelWrappersAndWrapperAliasesChecked` 12→11、`scanHiddenEvalStmtBody` 9→2、`walkStmt` 115→112、`stdinProgramTargetsDialectSteps` 20→19、`scriptAllowsLocalShellStdinPrepareDialect` 25 持平、`collectOneStdinSeg` 6 持平）。

## 验证归档

- FAIL-first（父树 `8b4e3d5` 本机归档副本叠加最终测试文件，`/tmp/herdr-r31-parent-tree`，用后删除）：`GOTOOLCHAIN=go1.26.0 go vet .` rc=0；R29 套件 **4 FAIL / 0 PASS**（一级子测试 R29-1..R29-4 各自独立失败消息：块入口重定向逆向遮蔽、四条直接执行边与语法词豁免错位、`collectOneStdinSeg([taskset -p 1])` 返回空目标、`stdinRewriteableTarget` 引号占位符 ok=true）；修复树同套件 4/4 PASS。父树证据日志 `/tmp/r31-parent-r29b.log`。
- 环境注记同 R27/R28：宿主默认 Go 与 staticcheck `2025.1.1` 不兼容，全部验证经 `GOTOOLCHAIN=go1.26.0` 运行（与 CI 对齐）。
- `make check` 与 `-race -count=10 -run 'TestGuard_V622_OracleR2*'` 记录见交付报告。

[pattern:role-guards-r29-closure]
