# v6.2.2 守卫审计 R26 闭环记录（Oracle R26 + Reviewer R26）

date: 2026-11-28
module: role_guards, shell_ast
status: active

## 背景

Oracle R26（Must-Fix 5 + Should-Fix 1）与 Reviewer R26（Must-Fix 7 + Should-Fix 2）两份对抗审计在 `abe543b` 上检出交集：eval 重放的进程边界三处、wrapper 校验的环境时点/越界切片/无界预扫描、相对斜杠别名身份丢失、历史文件清单不实、同义反复委托测试行。本轮在 worktree `feat-v622-guard-hardening` 一次性闭环；R26 套件 8 个判别子测试 **全部** FAIL-first 于父树 `abe543b`（8 FAIL / 0 PASS，`go vet` rc=0），修复树 8/8 PASS。

## 本轮实际修改文件（`git diff --name-only abe543b HEAD`）

- `shell_ast.go`
- `role_guards_handlers.go`
- `role_guards_peel.go`
- `role_guards_shell.go`
- `role_guards_v622_r20_test.go`
- `CHANGELOG.md`
- `.agents/notes/20261128-role-guards-r24-closure.md`（仅内联勘误标注，不新增结论）
- `.agents/notes/20261128-role-guards-r25-closure.md`（仅内联勘误标注）
- `.agents/notes/20261128-role-guards-r26-closure.md`（本文件）

R22 closure note 依两份审计明确要求**未触碰**。

## 根因与修复要点（留痕口径）

1. **eval 重放进程边界三处**（Oracle R26-M1 / Reviewer R26-#5/#6）：
   - (a) `taintEvalTextWrites` 顶层循环改为经 `taintEvalOneStmt` 调度——后台/协进程语句的隐藏 eval 重放整体包进 `snapshotProcessRegs` 帧（回滚 `funcNames`/`readonlyVars`，保守变量污染 `taintedVars` 不回滚）；`taintHiddenEvalWrites` 直接委托 `scanHiddenEvalStmt`（删除未建帧的根 CallExpr 调用）。
   - (b) 管道兄弟隔离：`scanHiddenEvalDispatch` 对 `Pipe/PipeAll` 走 `scanHiddenEvalPipeSiblings`——X、Y 各自独立建帧（镜像 `walkStmt`），同一分量内部的同进程声明/定义对该分量的后续语句仍然可见。
   - (c) `scanHiddenEvalStmt` 改查 `ist == nil`（非 `ist.Cmd == nil`），遍历 `ist.Redirs` 的 `r.Word`/`r.Hdoc` 经 `scanHiddenEvalDispatch`（typed-nil 单独守卫），嵌套语句重定向子树内的 `$(command -x eval)` 回到重放覆盖。
2. **单趟有界校验 peel**（Oracle R26-M2/M4 / Reviewer R26-#1/#2/#3）：删除无界预扫描家族（`stdinWrapperPeelUntrusted`/`externalWrapperUntrustedPATH`/`peelOneWrapperLayer`/`skipTransparentBuiltinArgs`/`skipExternalWrapperLayer`/`skipNiceWrapperArgs`），`peelWrappers` 重构为 `peelWrappersCore`（nil tracker 时逐字节复现原行为）：共享 `peelWrapperMaxSteps=32` 步数（纯 KEY=VAL 与 shellNoopWords 依旧 `depth--` 免步）、`wrapperPathTracker` 以 O(1)/op 增量镜像 `effectivePATHFrom`+`pathUntrusted`（'t' 粘性、占位符可被 `env -i`/`-u PATH` 清除、常量赋值可覆盖），每个**裸外部** wrapper 在消费其选项/`env` 操作数**之前**按入层环境校验（command/builtin/exec 内建豁免、带斜杠拼写豁免）。九个选项 skipper 的尾部缺操作数全部钳到 `len(argv)` 且 fail-closed（返回值永不超界）；`peelSingleWrapperArgs` 对 `nice -n`/`time -o` 尾缺返回 `(len(argv), false)`。
3. **xargs 内层校验**（Oracle R26-M2 / Reviewer R26-#1）：`stdinXargsInnerTarget` 经 `peelWrappersAndWrapperAliasesChecked` 跑同一校验 peel 与别名循环，并对剥后裸头补 `tk.untrusted()` 判定——`/usr/bin/xargs -I{} env /bin/sh -c {}` 与 `/usr/bin/xargs -I{} sh -c {}` 在不可信 PATH 下 exhausted，固定路径 `/usr/bin/env /bin/bash` 保持确认消费者且 `bash` 位准确。
4. **斜杠身份保持**（Oracle R26-M3 / Reviewer R26-#4）：共享 `rewriteKeepSlashIdentity`——原始拼写无斜杠时用规范名；有斜杠时 `filepath.Join(Dir, canon)`，清洗后丢斜杠（`.` 或 `sub/..`）则补 `./` 前缀，canonical 改写、解析后 wrapper 递归、`peelWrappersAndWrapperAliases*` 三处共用，`./genv`、`sub/../genv` 与 symlink `./myenv -> /usr/bin/env` 不再降级为裸名。
5. **文档校准**（Oracle R26-M5 / Reviewer R26-#7）：CHANGELOG R25 首行文件清单改 `r24-closure.md`（去掉从未在 `028ac50..abe543b` 修改的 r22）、R24 首行改 `r23-closure.md`（去掉从未在 `f8cd003..028ac50` 修改的 r22）；R24/R25 note 各条加内联勘误括注；R24 复杂度表述限定为「5 个受影响生产文件上的具名顶层函数」口径。R22 note 未动。
6. **测试纪律**（Reviewer R26-#9）：删除同义反复子测试「R25-5 the legacy pure-vehicle spelling delegates to the production entry」；`TestGuard_V622_OracleR25Probes` 保持 10 个判别子测试；新增 `TestGuard_V622_OracleR26Probes` 8 个子测试全部 FAIL-first（行 827/834/1254/1266/1270 的独立行为断言未动）。

## 复杂度多重集核对（file+kind+parent+name+occurrence_index，`cccc --no-config --no-cache`）

- 对比 `f8cd003`：638 共享、42 新增、3 删除、**0 正增长**。
- 对比 `abe543b`：665 共享、15 新增、6 删除、**0 正增长**。
- 新增函数全部 cognitive < 35：最大 `peelWrappersCore` 30、`peelFlagZone` 23、`applyOps` 16、`peelWrappersAndWrapperAliasesChecked` 12、`scanHiddenEvalStmtBody` 9、`scanHiddenEvalChildFrame` 4、`peelWrapperLayer` 3、`taintEvalOneStmt`/`rewriteKeepSlashIdentity`/`wrapperNeedsPathValidation` 2、`niceValuedOpt`/`timeValuedOpt`/`untrusted`/`scanHiddenEvalPipeSiblings`/`newWrapperPathTracker` 0-1。
- 被修改既有函数无一正增长（`skipExecArgs` 34 持平、`scanHiddenEvalDispatch` 4 持平、各 `(int,bool)` skipper 持平或下降、`peelWrappers` 129→0 单行委托）。删除的预扫描家族 6 个函数（`externalWrapperUntrustedPATH`/`peelOneWrapperLayer`/`skipTransparentBuiltinArgs`/`skipExternalWrapperLayer`/`skipNiceWrapperArgs`/`stdinWrapperPeelUntrusted`）无生产调用方残留。

## 验证归档

- FAIL-first（父树 `abe543b` overlay 最终测试文件，`/tmp/r26-parent-copy`）：`go vet` rc=0；R26 套件 **8 FAIL / 0 PASS**。修复树同套件 8/8 PASS。
- cccc 全量前后对照：明细见上节。
- `make check` rc=0（基线 `abe543b` 对照同 rc=0）；3 轮 `-race -count=10 -run 'TestGuard_V622_OracleR2*'` 记录见交付报告。
- 备注：首次全量 `go test` 与并行基线 `make check` 同跑时 `TestAlFix7_FuzzArgvDiff` 因 /tmp 空间争抢报 `no space left on device`，干净 `abe543b` 树同环境单独复现同样失败，为环境噪声非代码回归；串行 `make check` 基线与修复树均 rc=0。

[pattern:role-guards-r26-closure]
