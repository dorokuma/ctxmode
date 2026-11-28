# v6.2.2 守卫审计 R27 闭环记录（Oracle R27 + Reviewer R27）

date: 2026-11-28
module: role_guards, shell_ast
status: active

## 背景

Oracle R27（7 Must-Fix / 2 Should-Fix）与 Reviewer R27（7 Must-Fix / 3 Should-Fix）两份对抗审计在 `0d907a8` 上检出交集：管道分量根语句漏检与同分量声明可见性、动态值/尾缺操作数索引混淆、xargs checked peel 环境操作二次施加、内建豁免缺执行上下文、跨别名步数预算重置与双 `--` 消费、env/taskset/chrt 尾缺 fail-closed 缺口、R26 正例断言强度不足、版本记录账目错误。本轮在 worktree `feat-v622-guard-hardening` 一次性闭环；R27 套件 9 个判别子测试**全部** FAIL-first 于父树 `0d907a8`（`go vet` rc=0），修复树 9/9 PASS。

## 本轮实际修改文件（`git diff --name-only 0d907a8 HEAD`）

- `shell_ast.go`
- `role_guards_handlers.go`
- `role_guards_shell.go`
- `hc_prepare.go`
- `role_guards_v622_r20_test.go`
- `CHANGELOG.md`
- `.agents/notes/20261128-role-guards-r26-closure.md`（仅内联勘误标注，不新增结论）
- `.agents/notes/20261128-role-guards-r27-closure.md`（本文件）

`role_guards_peel.go` 未改（`peelSingleWrapperArgs` 的 `(2,false)` 判定全部由 `role_guards_shell.go` 内 skipper 语义变化自动获得）；R22 closure note 依两份审计明确要求**未触碰**。

## 根因与修复要点（留痕口径）

1. **管道分量根语句与同分量声明（Oracle R27-M1 / Reviewer R27-#1）**：`scanHiddenEvalPipeSiblings` 对 `x.X`/`x.Y`（`*syntax.Stmt`）改经 `scanHiddenEvalFramedStmt` 从语句入口扫描（`scanHiddenEvalStmt` 的根调用检查 + Redirs 遍历恢复），并在扫描前于分量自身帧内登记 `noteEvalStmtFuncDefs`/`noteEvalStmtReadonlyDecls`——`{ eval() { :; }; eval; } | cat` 的直接 AST FuncDecl 对同分量后续语句可见，退出帧时回滚；`CmdSubst`/`ProcSubst`/`Subshell`/`CoprocClause` 帧内语句列表同样逐语句「先登记后扫描」，消除与 `scanHiddenEvalNode` 的重复遍历。
2. **动态值/尾缺索引分离（Oracle R27-S2 / Reviewer R27-#2）**：`skipExecArgs`（含短簇 `-a`）/`skipTimeoutArgs`/`skipStdbufArgs`/`skipIoniceArgs`/`skipTasksetArgs`/`skipStraceArgs`/`peelFlagZone` 拆开两条件——`i+1 >= len(argv)` 返回 `(len(argv), true)`（钳界），`isDynamicArg(argv[i+1])` 返回 `(i, true)`（恢复 pre-R26 `abe543b` 残段索引）；`hc_prepare.go` 脚本扫描与 `collectOneStdinSeg`/`stdinTargetsWithDataFallback` 的空头跳过增加 `!peelExhausted` 条件——耗尽 peel 永不当作无消费者跳过。
3. **单次施加环境操作（Oracle R27-M2 / Reviewer R27-#3）**：删除 `peelWrappersAndWrapperAliasesChecked` 中重复的 `tk.applyOps(envAs.ops[before:])`——`peelWrappersCore` 已在剥离时实时推进 tracker，`PATH=$PATH:/x` 对 `/base` 只展开一次为 `/base/x`，贴 `maxShellCommandBytes` 上限的合法单次展开不再被二次展开误判。注释与 r26-closure 勘误：`expandPathSelfRefs` 对含占位符 base 直接拒绝，仅 `env -i`/`-u PATH` 清空后常量赋值才能恢复。
4. **执行上下文敏感内建豁免 + 先验裸名（Oracle R27-M3 / Reviewer R27-#4）**：`wrapperPathTracker` 新增 `directExec` 位——shell 调度入口初始 `false`、xargs 内层初始 `true`、剥过任何外部 wrapper 层后置 `true`；`wrapperNeedsPathValidation` 在 `directExec == true` 时对裸 `command`/`builtin`/`exec` 同样要求 PATH 可信。`peelWrappersAndWrapperAliasesChecked` 的裸头不可信判定移到 `resolveHeadBase` 别名采纳**之前**。
5. **跨别名共享 32 步 + 单 `--`（Oracle R27-M4 / Reviewer R27-#5）**：`peelWrappersCore` 改为经 `sharedSteps *int` 计数——别名循环共享一个计数器贯穿全部改写轮，`stdinProgramTargetsDialect` 的 canonical/resolved-wrapper 递归经 `stdinProgramTargetsDialectSteps`/`stdinTargetsPeelPrologue`（R28 勘误：原文误写 `stdinTargetsPeelPrologueShared`，源码中不存在该名，实际线程计数的共享 prologue 即 `stdinTargetsPeelPrologue`）线程同一计数（其它递归入口 nil 时新建独立预算，保持原语义）；33 层含 `./genv`/`./myenv` 链与 33 层规范名链同样 exhausted。`peelWrapperLayer` 删除 `command`/`builtin` 分支多余的 `skipDashDash`——`peelFlagZone` 遇 `--` 已返回 `i+1` 消费唯一终止符。
6. **env/taskset/chrt 尾缺 fail-closed（Oracle R27-M5 / Reviewer R27-#6）**：`skipTasksetArgs`/`skipChrtArgs` 的 `-p`/`--pid` 区分三态——静态 PID 操作数 `(len(argv), false)`（合法查询）、末尾缺失 `(len(argv), true)`、动态 PID `(i, true)`；`peelWrappersCore`（tk != nil）与 `peelWrappersAndWrapperAliases*`（含 tk == nil 路径）对 `envUnknownLongPrefix` 前缀载荷判 exhausted，nil tracker 的 `peelWrappers` 保持载荷通道不抢先置位，`peelResolvedSegDepth` 的精确 `"env unknown option ..."` 诊断不回归。
7. **测试与文档校准（Oracle R27-M6 / Reviewer R27-#7/#8/#9）**：R26-4/7/8 正例就地断言非空非 data 非 exhausted `lang == ""` 的确认 shell 目标，env 折叠用静态或单字安全引号动态赋值并断言 `first.envAs` 携带折叠后 op；删除 CHANGELOG 重复的第二个 `## [6.2.2] - 2026-11-27` 标题；七文件 cccc 多重集更正为 639 shared/42 added/3 deleted（vs `f8cd003`）与 666 shared/15 added/6 deleted（vs `abe543b`），`scanHiddenEvalDispatch` 更正为 4→2。

## 复杂度多重集核对（file+kind+parent+name+occurrence_index，`cccc --no-config --no-cache`）

七文件：`shell_ast.go`、`role_guards_handlers.go`、`role_guards_peel.go`、`role_guards_shell.go`、`role_guards_heredoc.go`、`role_guards_code_env.go`、`hc_prepare.go`（与 R26 口径一致）。（R28 勘误：原文将实测数字推给「交付报告」这一 /tmp 易失入口，现将数字就地写入。）R27 修复树（`1aa4752`）七文件总实例 **696**；以多重集配对（file+kind+parent+name+occurrence，shared 键无一正增长）：

- 对比 `0d907a8`：**680 共享、16 新增、1 删除、0 正增长**（删除项为 `stdinProgramTargetsDialect::collectSegs` 旧键——同名闭包迁入 `stdinProgramTargetsDialectSteps` 新键）；
- 对比 `abe543b`：**665 共享、31 新增、7 删除、0 正增长**；
- 对比 `f8cd003`：**638 共享、58 新增、4 删除、0 正增长**。

全部新增函数/闭包 cognitive < 35（最大 `stdinProgramTargetsDialectSteps` 20）。`shared + added == 696` 逐对照成立（680+16=665+31=638+58=696）。

## 验证归档

- FAIL-first（父树 `0d907a8` 本机克隆叠加最终测试文件，`/tmp/r27-parent-copy`）：`go vet` rc=0；R27 套件 **9 FAIL / 0 PASS**；修复树同套件 9/9 PASS；副本用后删除。
- 环境注记：宿主默认 Go 为 `go1.27.4-X:nodwarf5`，staticcheck `2025.1.1 (0.6.1)` 无法解码 go1.27 export data v5；`go.mod` 声明 `go 1.26.0` 与 CI `go-version-file` 一致，故全部验证经 `GOTOOLCHAIN=go1.26.0` 运行——这是环境对齐而非代码修复，staticcheck 二进制本身为项目规定的 `2025.1.1 (0.6.1)`。
- `make check` rc=0（修复树；父树 `0d907a8` 克隆同命令对照见交付报告）；3 轮 `./scripts/ns-hc-gotest.sh --race -- -v -count=10 -run 'TestGuard_V622_OracleR2*'` 记录见交付报告。

[pattern:role-guards-r27-closure]
