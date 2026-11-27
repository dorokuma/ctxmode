# v6.2.2 守卫审计 R22 闭环记录（Oracle R22 + Reviewer R22）

date: 2026-11-28
module: role_guards, shell_ast, hc_prepare
status: active

## 背景

Oracle R22 与 Reviewer R22 两份对抗审计在 `0c618ac` 上检出 8+1 项发现，收敛为 6 个生产根因与 2 项测试/文档收口项。本轮在 worktree `feat-v622-guard-hardening` 一次性闭环，全部判别测试 FAIL-first 于父树。

## 根因与修复要点（留痕口径）

1. **eval 复制链的写定义统一 + 函数遮蔽 + 只读变量**：`writeNamesInStmtFuncs` 对 taint 判定不截断根调用（仅 bind 判定保留复制自有的截断）；无法确认操作数边界的 eval 形态链施最大污染（sentinelTrustVars+PATH），但普通动态命令头（`$s`）非 eval 形态、不施此罚——否则 enum 展开的正例会大面积退化（本轮实测踩坑：`for s in "ls -l"; do $s; done` 一度被 maximal 污染误伤 PATH/sentinel）。同名 shell 函数遮蔽 eval/command/builtin 时拒绝精确绑定（只查链首词：幸存未遮蔽 command/builtin 包装器对其后不再走函数查找）；`readonly`/特殊变量经 `noteShellAssign` 路由污染。坑：声明自身的内联写（`readonly X=/x`）必须先 mint 再记录属性。
2. **控制流合流不确定性**：elif 链的条件列表必须进入 conditional 区（首层 if 的 Cond 才是必经）；自引用/依赖未知旧值的无条件覆写不得清除既有 taint（`PATH=$PATH:/suffix` 的旧值未知故新值未知），仅独立常量覆写可清除。赋值折叠许可以 AST 的 `pureAssign` 判定为准，剥引号后形如 `KEY=VAL` 的命令词绝不误作赋值。
3. **stdin 目标 exhaustion 端到端传播 + 不可信 PATH 显式未知目标**：peel 预算耗尽、嵌套 parseErr/depthExceeded、xargs 内层耗尽全部构造 `exhausted:true` 目标，严禁零值伪 POSIX shell。无斜杠 bare 名在 PATH 不可信（条件 taint 或超限占位符，含 caller 的粘性 pathEnv）时返回显式未知目标而非 nil——nil 会搭乘 data-consumer fallback。
4. **xargs 记忆化/预算按请求隔离**：包级 memo/steps 删除，改为每请求一份 `xargsWorkState`（memo+steps，由 `xargsWork` 惰性分配并经 `callerIdentity` 传递——R23 校正：R22 当时该表在每次 `callerIdentity()` 调用内独立铸造，同请求各阶段不共享预算，`stdinProgramHeadCwdExh` 等无 caller 入口甚至无表；R23 闭环改为 `guardCall` 预初始化一份 `xw` 并由全部派生身份继承，见 R23 闭环记录），key 含 depth/argv/token/有效 PATH。并发不同解析上下文不再互串。
5. **环境快照按需物化 + 父链共享**：`scopeEnvTracker` 父链 fork（parent/baseLen），view 仅在消费段物化一次容量冻结快照；纯赋值段由 AST 判定在平坦 subagent 循环中免费跳过（R23 校正：嵌套 `collectOneStdinSeg` 的跳过条件当时写反——`!seg.pureAssign` 只包住空头检查，真正纯赋值段仍逐段复制前缀；`stateFor` 当时仍遍历全部状态查父级。两处由 R23 闭环修复，见 R23 闭环记录；本条的零复制断言仅对当时实测的本地 subagent 循环成立）。判别量用**字节**非次数——copy 是每段一次分配无论大小，malloc 计数无判别力（实测两侧 ratio 均 ~0.9）；等宽窗（seg 1-8 vs 57-64）字节比率旧树 ~3.8、新树 ~0.8。切片 append 倍增噪声要求窗从 n=8 起测。
6. **复杂度零回归纪律**：cccc 既计 bool 运算也计嵌套；新增分支须靠等量提取既有逻辑补偿。本轮提取 helper：visitIf/noteFuncDef/bindImpossible/evalChainTaintedRest/evalChainLayerVerdict/evalChainPathVerdict/taintEvalBoundary/replayEvalTextWrites/bindEvalOneStmt/isPureAssignCall/foldAssignWord/scopeVisibleLen/chainView/consumerViewEnv/stdinCommandSegRule/collectOneStdinSeg/stdinUnknownHeadTargets/stdinRewriteableTarget/pathSegUnvettable/lookPathOneSeg。
7. **死代码清理**：`writeNamesInStmt`（薄包装）、`pureAssignEnv`、`accumulatePureAssignEnv` 均已无生产/测试调用方，删除。

## 验证归档

- FAIL-first（父树 `0c618ac` overlay 最终合并测试文件）：`go vet` rc=0；R22 套件 14 FAIL / 0 PASS；R20 套件 0 FAIL / 8 PASS、R21 合并套件 0 FAIL / 10 PASS（回归覆盖非新发现判别，符合预期）。
- cccc：8 个生产文件逐函数前后对照零回归；全部新增函数 < 35。
- `make check` 全绿记录见交付报告。

[pattern:role-guards-r22-closure]
