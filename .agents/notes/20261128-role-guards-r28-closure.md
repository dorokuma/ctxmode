# v6.2.2 守卫审计 R28 闭环记录（Oracle R28 + Reviewer R28）

date: 2026-11-28
module: role_guards, shell_ast
status: active

## 背景

Oracle R28（5 Must-Fix + 3 Should-Fix）与 Reviewer R28 两份对抗审计在 `1aa4752` 上检出交集：协程 Name 词漏扫描、隐藏 eval 登记的进程帧与词法顺序错位、directExec 未贯通全部外部直接执行边、`peelProvesEmptyHead` 以未耗尽误充无消费者证明、PATH 信任判定漏识别引号占位符，以及测试断言判别力与版本证据账目问题。本轮在 worktree `feat-v622-guard-hardening` 一次性闭环；R28 套件 5 个一级子测试**全部** FAIL-first 于父树 `1aa4752`（`GOTOOLCHAIN=go1.26.0 go vet .` rc=0），修复树 5/5 PASS。

## 本轮实际修改文件（`git diff --name-only 1aa4752 HEAD`）

- `shell_ast.go`
- `role_guards_handlers.go`
- `role_guards_shell.go`
- `role_guards_heredoc.go`
- `role_guards_subagent.go`
- `hc_prepare.go`
- `role_guards_v622_r20_test.go`
- `CHANGELOG.md`
- `.agents/notes/20261128-role-guards-r26-closure.md`（仅内联勘误标注）
- `.agents/notes/20261128-role-guards-r27-closure.md`（仅内联勘误与数字就地写入）
- `.agents/notes/20261128-role-guards-r28-closure.md`（本文件）

R22 closure note 依审计惯例**未触碰**。

## 根因与修复要点（留痕口径）

1. **协程 Name 词扫描（Oracle R28-M1 / Reviewer R28）**：`scanHiddenEvalCoprocFrame` 恢复对 `CoprocClause.Name` 的帧内扫描（pinned mvdan.cc/sh 解析器对 `coproc $(command -x eval) { :; }` 产生携带命令替换的 Name 词，`syntax.Walk` 本就分别遍历 Name 与 Stmt）；`x == nil` 守卫修正后 Name 经提取的 `scanHiddenEvalCoprocName` 扫描、body 经 `scanHiddenEvalStmt` 扫描。
2. **隐藏 eval 登记进入子帧按词法顺序就地登记（Oracle R28-M2 / Reviewer R28）**：`scanHiddenEvalFramedStmt` 删除，登记义务移入 `scanHiddenEvalStmtBody` 开头——`noteHiddenEvalStmtDirectRegs` 只登记当前语句自身直接 `cmd`（FuncDecl/DeclClause/CallExpr），后台/协程语句的登记自然落在 `scanHiddenEvalStmt` 已开启的子帧内；复合块子语句由词法下降逐条登记，`{ eval; eval() { :; }; }` 的首条调用不再被尾部定义逆向遮蔽，`$( { eval() { :; }; eval; } & )` 带进程位块内的定义在子帧内正确生效。`taintEvalTextWrites` 与 `bindEvalOneStmt` 的跨语句批登记（`noteHiddenEvalStmtBatchRegs`）移到语句扫描**之后**。
3. **directExec 贯通（Oracle R28-M3 / Reviewer R28）**：`callerIdentity` 新增 `directExec` 位与 `withDirectExec`；`stdinTargetsPeelPrologue` 以 `caller.directExec` 构造 tracker 并把剥离后 `tk.directExec` 继承给递归（`caller.seededWith(ea).withDirectExec(tk.directExec)`）；xargs `!feedsCode` 分支、flock argv 分支、watch `-x` 分支递归传 `withDirectExec(true)`；进入子 shell 文本解析的分支（`stdinShellCTargets`/eval/flock -c/script -c/watch 默认模式）传 `withDirectExec(false)`；`peelCoreStep` 剥离 `exec` 内建层时同样翻转 `tk.directExec`（`exec` 不以 shell 内建分派启动下一层——目标经 OS PATH 查找）。
4. **`peelProvesEmptyHead` 守卫侧交叉校验（Oracle R28-M4 / Reviewer R28）**：索引 peel 判空且未耗尽后，另经 `peelCheckedEmptyProved` 以守卫侧 checked peel（`newWrapperPathTracker` + `peelWrappersAndWrapperAliasesChecked`）复核——缺 PID（`taskset -p`/`chrt -p`）与缺选项值（`timeout -k`）在 checked peel 中 fail-closed exhausted，不再被当作无消费者跳过；静态 PID 查询（`taskset -p 1`）与纯赋值（`FOO=1`/`env FOO=1`）保持 true。
5. **PATH 信任判定识别全部动态占位符（Oracle R28-M5 / Reviewer R28）**：`wrapperPathTracker.untrusted`、`envAssignments.pathUntrusted`、`callerIdentity.pathUntrusted`、`expandPathSelfRefs` 的 base 检查、`pathSegUnvettable` 五处统一改键 `isDynamicArg`——全双引号动态值（`cmdSubPlaceholderQuoted`）边界可知但内容不可知，与裸占位符同为不可信搜索列表。
6. **测试断言强化（Oracle R28-S1 / Reviewer R28）**：R26-4 追加 `first.envAs.pathUntrusted` 断言、`:2252` 升级为 `assertShell(trusted, {"env","/bin/sh"}, "")`、传播行改用引号占位符 `PATH=<quoted>`；R27-3 贴顶夹具修正为 `maxShellCommandBytes-2`（单次展开恰为上限合法、二次超限必退化）并断言 `tk2.cur == pad+"/x"` 与 `!tk2.untrusted()`；R27-4 外层改固定路径 `/usr/bin/env command /bin/sh`，顺序钉改用 `t.TempDir()` 下指向 `/usr/bin/env` 的软链 `myenv`（裸名非静态识别 wrapper，真正进入别名循环在 `resolveHeadBase` 前被拦截）；R27-5 预算内正例补 `len(within)==1 && !within[0].data && within[0].lang==""` 断言。新增 `TestGuard_V622_OracleR28Probes` 5 个一级子测试（R28-1..R28-5）。
7. **文档账目校准（Oracle R28-S2/S3 / Reviewer R28）**：`peelWrappers` 兼容承诺精确化（动态选项值恢复 pre-R26 残段索引；末尾真缺操作数保留 `(len,true)` 有意 fail-closed 修复——`role_guards_shell.go` 注释、CHANGELOG R27 条目、R26 closure 内联勘误三处一致）；CHANGELOG R27 首行文件清单删去未改的 `role_guards_peel.go`；R27 closure 的 `stdinTargetsPeelPrologueShared` 更正为 `stdinTargetsPeelPrologue`，cccc 实测数字就地写入（696 总；vs `0d907a8` 680/16/1/0 up；vs `abe543b` 665/31/7/0 up；vs `f8cd003` 638/58/4/0 up）。

## S3 历史勘误（保留原始观测、错误机械判词与正确门限分离）

1. **执行地点**：Verifier R28 所述「各判据各用 clone」不适用于修复树八组对照——fixed-test 在被审 worktree 本树运行（工作树干净），父树 FAIL-first 与完整 `make check`、race 三轮才在 `/tmp` 一次性副本执行；判据应是比较日志 `# repo=`、HEAD、tree 三字段。
2. **机械门限**：`cccc_multiset_diff.py` 的 VERDICT 行把「up 计数」与「≥35 计数」标为 `(must be 0)`——真实门限是**新增条目 cognitive < 35** 且**共享键无一正增长**；预存高复杂度函数与整树 ≥35 条目数本就不清零。该文件 `:86` 的 down+same 按自身数字为 536 而非 538。
3. **修改历史**：`role_guards_shell.go` 首次修改并非 R26——`git diff --numstat b9d481e f8cd003` 证实 R23 已修改该文件（**+88/−21**）；可成立的表述是「在 R24 至 R27 这四步内首次修改是 R26」。R25（`028ac50 -> abe543b`）五文件多重集 `538 = 7 降 + 529 平 + 2 升`（E/F 口径沿用 R27 证据），其中 **9 为变化总数**（降 7 + 升 2），不是增长数。
4. **计数口径**：Worker R28 前序报告中的「测试 +462」是触及行数、「每轮 PASS 行 7220」是 L1 行数，均非新增行数或全层 PASS 行数。

## 复杂度多重集核对（file+kind+parent+name+occurrence_index，`cccc --no-config --no-cache`）

七文件同 R27 口径。R28 修复树总实例 **701**；以同一多重集配对：

- 对比 `1aa4752`（直接父）：**695 共享、6 新增、1 删除、0 正增长**——6 个新增条目为 `peelCheckedEmptyProved`（cognitive 1）、`wrapperFlipsDirectExec`（1）、`scanHiddenEvalCoprocName`（1）、`noteHiddenEvalStmtDirectRegs`（1）、`noteHiddenEvalStmtDirectRegsBoundary`（1）、`noteHiddenEvalStmtBatchRegs`（0），全部 < 35；删除 1 项为被取代的 `scanHiddenEvalFramedStmt`；
- 对比 `0d907a8`：680 共享、21 新增、1 删除、**0 正增长**；
- 对比 `abe543b`：665 共享、36 新增、7 删除、**0 正增长**；
- 对比 `f8cd003`：638 共享、63 新增、4 删除、**0 正增长**。

补充说明：以**不含 parent** 的朴素键配对时 `shell_ast.go` 匿名闭包出现 8 条位置平移噪声（如 6→71 与 71→1 互为镜像），该噪声在 `f8cd003 -> 1aa4752`（不含本轮改动）上逐字节相同，证实非 R28 引入；parent-inclusive 键下四基线对照的正增长均为 0。

## 验证归档

- FAIL-first（父树 `1aa4752` 克隆叠加最终测试文件，`/tmp/r28-parent-copy`，用后删除）：`GOTOOLCHAIN=go1.26.0 go vet .` rc=0；R28 套件 **5 FAIL / 0 PASS**（失败消息逐条对应 M1..M5：coproc Name 漏扫、后台块定义未入子帧、xargs 直接执行边豁免错位、`peelProvesEmptyHead([taskset -p]) = true`、引号占位符 PATH 误信）；修复树同套件 5/5 PASS。父树证据日志 `/tmp/r28-parent-test.log`。
- 环境注记同 R27：宿主默认 Go `go1.27.4` 与 staticcheck `2025.1.1` 不兼容，全部验证经 `GOTOOLCHAIN=go1.26.0` 运行（与 CI 对齐）。
- 环境噪声备忘：`TestAlFix7_FuzzArgvDiff` 在本机孤立环境复现 `symlink argvprinter: no space left on device`（/tmp tmpfs 余量充足时亦然）；**干净父树 `1aa4752` 克隆同环境单独复跑同样失败**，与 R26 记录的同类噪声一致，非本轮代码回归。
- `make check` 与 `-race -count=10` 专项记录见交付报告。

[pattern:role-guards-r28-closure]
