---
status: closed
superseded_by: ""
supersedes: ""
模块: "role_guards, readonly_allowlist"
---

# sbx 包装器剥离闭环 [pattern:sbx-wrapper-unwrap-asymmetry]

## 一句话结论
`peelWrappers` 新增 `sbx` 分支（分支 `fix/peel-sbx-wrapper`，基线 `3eea472`）：非只读子代理的 `sbx [opts] -- CMD` 解包到内层 head 并照常过嵌套派发/环境筛查，严格只读仍首层以 `unknown command sbx` 拦截；Oracle R2 的 S-NEW-1（stdin 模型别名解析忽略剥离出的 PATH）与 S-NEW-2（`PI_SANDBOX_*` 未筛查）、Oracle R3 的 S-R3-1（三个兄弟 helper 仍按进程 PATH 解析别名）、Oracle R4 的 S-R4-1/S-R4-2（隧道判定与 stdin head 以空种子重放 envAs，远端 `PATH=` 泄漏 + `PATH=$PATH:` 坍缩）均已修复，O1–O-NEW-2 观察项闭环。

## 决策
1. `case "sbx"` 按 Go `flag.FlagSet` 语义解析：单/双横线、`--flag=val` 与双槽 `--flag val`，8 个带值选项（`preset`/`workdir`/`ro`/`rw`/`exec`/`reviewer`/`report-to`/`env`，对齐真实 `sbx` `parseArgs`，幻影 `tmpfs` 已删），`--` 后首个词为内层 head；布尔 `deny-net`/`best-effort` 单槽剥离（含 `=glued` 写法），`--check`/`-version` 与 `-h`/`--help`/`-V`/`--version` 作为纯查询保持 `sbx` head；其余未知 `-` flag 一律 exhausted 防槽位错位。
2. `--env KEY=VAL` 按真实 `stringSlice.Set` 先按 `,` 拆分再逐段筛查（`screenSbxEnvValue`）：每段须为静态 `KEY=VAL`，进 `envAs` → `PATH`/`LD_PRELOAD`/`CTXMODE_*` 由既有 env 屏幕拦截；`sentinelTrustVars` 键与空段在剥离时直接 fail-closed（修复 Oracle M1：`A=1,PATH=/x` 单槽多变量注入绕过）。
3. 严格只读：`readonlyPrePeelHit` 增 `case "sbx"` 返回 `unknown command sbx`，保持剥离前的默认拒绝文案不变。
4. 符号链接晋升补齐：`peelResolvedSegDepth` 对 `foo -> sbx` 晋升出的 `sbx` head 递归重筛；`stdinProgramHeadDepth` 对解析为 `sbx` 的 head 重写后递归（管道 `echo pig | foo -- sh` 不再漏过 stdin 模型）。
5. flag 表与真实 `sbx` `parseArgs` 对齐（修复 Oracle S1）：补 `exec`/`reviewer` 带值选项与 `deny-net`/`best-effort` 布尔，删幻影 `tmpfs`；`--check`/-`version` 归入纯查询早退，`peelWrappers` 顶部注释改为只列自身剥离的包装器（`watch`/`flock`/`script`/`sudo`/`doas` 标注为下游 `peelResolvedSegDepth`/`stdinProgramHeadDepth` 解包）。
6. stdin 模型按剥离出的 PATH 做别名解析（修复 Oracle S-NEW-1）：`stdinProgramHeadWithEnv` 携带累积 `envAs`，`resolveHeadBase` 改查 `envAs.effectivePATHFrom("")`，且 `sbx` 别名重写与 `flock`/`watch -x`/`xargs`/`-c`/`eval`/`script` 递归一律把 `envAs` 传作 `inherited`（ssh 远端命令按远端环境全新解析不继承），`echo pig | PATH=dir foo -- sh`（`dir/foo -> sbx`）不再漏判。
7. `PI_SANDBOX_*` 归 env 屏幕（修复 Oracle S-NEW-2）：`envHookVars` 收 `PI_SANDBOX_INTERNAL_CHILD_SPEC`，`isEnvHookVar` 加 `PI_SANDBOX_` 前缀——前缀赋值、`env` 与 `sbx --env` 注入伪造子 spec 一律 `env PI_SANDBOX_INTERNAL_CHILD_SPEC` 拦截。
8. S-R3-1（修复 Oracle R3）：`replTokenInExecSlot`/`xargsFeedsCodeFlag`/`peelToSSHHead`（经 `sshTunnelsStdinProgram`、`xargsDerivedSeg`）增传 `pathEnv`，别名解析改查 `ea.effectivePATHFrom(pathEnv)`，并对 `foo -> sbx` 晋升做二次解包（rewrite head 再 peel 一次、合并 `ea2`）；`xargs`/`find`/`stdin`/heredoc 与 code-spawn 六处调用点分别传 `caller.pathEnv` 或 `envAs.effectivePATHFrom("")`，远端递归传 `""`（远端 login 不继承本机 PATH）。否则 `PATH=<dir> xargs ssx dmit sh -c`、`find . -exec ssx dmit sh -c {} ;`、`echo x | PATH=<dir> xargs ssx dmit sh`（`ssx -> ssh`）漏过喂码槽/`{}` exec 槽/隧道升级三道判定。
9. S-R4-1（修复 Oracle R4）：`guardCtxRunStdin`/`guardCtxRunStdinForCommand` 的 `sshTunnelsStdinProgram` 基底改回调用方初始 `os.Getenv("PATH")`——`peelToSSHHead` 自身逐层重放 argv 内 ops，传 `envAs.effectivePATHFrom("")` 会把 `stdinProgramHeadWithEnv` 合并进来的远端 `PATH=` op 泄漏作本机解析基底（`xargs ssx dmit 'PATH=/nope sh'` 基底=/nope → ssx 漏解析 → 只读非严格丢 strict 升级），`PATH=$PATH:` 前缀亦被二次重放坍缩。`screenSegmentHeredocsDepth` 的隧道探针移到 `caller.seededWith(envAs)` 之前对剥离前 `caller.pathEnv` 计算，head 分类直调 `stdinProgramHeadWithEnv(seg.argv, 0, {}, caller.pathEnv)`（首层 `PATH=` 不再丢失）。
10. S-R4-2（修复 Oracle R4）：`stdinProgramHeadWithEnv` 增传 `basePath` 种子，`effPath` 改 `envAs.effectivePATHFrom(basePath)`——无 `env -i` 时 `PATH=$PATH:/usr/bin` 的 `$PATH` 按调用方 PATH 展开（空种子曾坍缩为 `:<dir>` → `ssx`/`foo` 漏解析 → `isProg=false` 整体绕过 stdin 载荷筛查），`'c'` op 仍先归零；本机递归透传 `basePath`，ssh 远端递归与 `replTokenInExecSlot`/`xargsFeedsCodeFlag` 远端分支以 `os.Getenv("PATH")` 为种子（远端 `$PATH` 自引用不再坍缩）。已持 `caller.pathEnv` 的调用点（`screenOneSegmentDepth` 管道与 hereString、`guardCtxRunCode`）直接贯通。
11. M-REV-1（修复 Reviewer R1）：`sbx` 七个非 env 双槽带值选项（`preset`/`workdir`/`ro`/`rw`/`exec`/`reviewer`/`report-to`）原先只查 `i+1 >= len(argv)` 即 `i += 2`，`argv[i+1]` 为动态词（`sbx --deny-net --workdir $(printf '/tmp sh -c pig') echo ok`）时静态跳过——运行时 field-split 使内层命令槽位错位（`sh -c pig echo ok`）。现条件加 `|| isDynamicArg(argv[i+1])`，与 `env` 槽动态值 fail-closed 对齐。
12. M-REV-2（修复 Reviewer R1）：`replTokenInExecSlot`/`xargsFeedsCodeFlag`/`stdinProgramHeadWithEnv` xargs `innerHead` 三处 `foo -> sbx` 别名原先各只重写+重剥离一次，`xargs -IXX foo --deny-net -- foo --deny-net -- sh -c XX` 第二层 `foo` 被当普通命令漏过喂码槽/exec 槽判定。抽取共用有界辅助 `peelWrappersAndSbxAliases`：`for steps := 0; steps < peelWrapperMaxSteps` 循环 peel → 头解析为 `sbx` 则 `cur = append([]string{"sbx"}, head[1:]...)` 续剥；env ops 逐层累进合并、`effPath` 逐层 `ea.effectivePATHFrom(effPath)` 重放（每层别名在自身 env ops 安装的 PATH 下解析）；peel 耗尽或别名链触界均返回 exhausted（fail-closed）——`xargsFeedsCodeFlag` exhausted 时返回 false 的既有契约不变（后续 `peelResolvedSegDepth` 仍 fail-closed）。

## 门禁观察项分诊（Oracle O1–O2 + R2 新增）
- **O1 / O-NEW-1 — 剥离后空 head 时 wrapper `argv[0]` 未经 `screenPathHeadTrust` 的残余信任边界** `[pattern:sbx-wrapper-unwrap-asymmetry]`：`confirmed（consider，保留现状）`。需攻击者先向排在系统目录之前的授信可写工具链目录植入同名影子二进制；跨 wrapper 空 head 回检 `argv[0]` 属独立架构增强，留后续评估。
- **O2 — `stdinProgramHeadDepth` 别名解析忽略 `envAs` `PATH`** `[pattern:sbx-wrapper-unwrap-asymmetry]`：`fixed`。Oracle R2 证伪原分诊前提：`PATH=<cwd>/.venv/bin` 属合法重定向，`resolveHeadBase(head[0], "")` 漏判 `foo -> sbx`；现 `stdinProgramHeadWithEnv` 按 `envAs.effectivePATHFrom("")` 解析并向下传 `envAs`，闭环为修复而非遗留。
- **O-NEW-2 — `sbx --check -- CMD` / `--check=true` 等组合写法按未知/多参 fail-closed** `[pattern:sbx-wrapper-unwrap-asymmetry]`：`confirmed（consider，保留现状）`。与真实 `parseArgs` 的良性偏差，守卫偏向更严的 fail-closed，无安全风险。
- **O-R6-1 — `peelWrappersAndSbxAliases` 别名链触界时返回 `cur`（未剥完的 argv）而非最后一次剥出的 `head`** `[pattern:sbx-wrapper-unwrap-asymmetry]`：`confirmed（consider，保留现状）`。`exhausted` 语义本身正确且全部 3 处调用方均先查 `exhausted` 再取 `head`，当前无可达误用，属 API 脆弱点，留后续改动留意。
- **O-R6-2 — `peelResolvedSegDepth:2894` `sbx` 晋升重筛以 `caller.seededWith(envAs)` 递归导致 `envAs` 二次 seed** `[pattern:sbx-wrapper-unwrap-asymmetry]`：`confirmed（consider，保留现状）`。`PATH=$PATH:/x` 会展开为 `<path>:/x:/x`，重复目录仅使别名解析更宽（fail-safe 方向），纯语义冗余、无绕过面。

## 被放弃的方案
- `sbx --env` 仅 `addAssign` 不加 sentinel 前置检查：`env HOME=/tmp` 对 worker 合法但 sandbox 内重锚 PATH 信任，且任务要求 `HOME=/tmp` 必拦 → 剥离时 fail-closed。
- 只改 `peelWrappers` 不补符号链接晋升：typed 名 `foo` 先过剥离、后晋升 `sbx`，内层 head 将绕过全部筛查 → 补 `peelResolvedSegDepth`/`stdinProgramHeadDepth` 重入口。
- ssh 远端命令继承外层 `envAs`：远端 head 在远端 login 环境下解析，外层 `PATH=` 不跨 wire → `stdinProgramHeadWithEnv` 对远端以空 `inherited` 起步、只把远端剥离的 ops 合并回外层返回。

## 验证
- `go test -race -count=1 ./...` 全绿；`TestGuard_PeelSbxWrapper`（44 行 ≤45）覆盖 worker 拦截/放行（含逗号拆分 `--env`、`PI_SANDBOX_INTERNAL_CHILD_SPEC`、`PATH=`+`foo -> sbx` 管道别名、`--exec`/`--reviewer`/`--deny-net`、`--check` 纯查询）与 reviewer `unknown command sbx`；新增 `ssx -> ssh` 别名三条 S-R3-1 探针（xargs 喂码槽 `dynamic code payload`、find -exec `{}` exec 槽 `find -exec dynamic code payload`、piped `xargs ssx dmit sh` 隧道判定 `piped stdin to ssh`），修复前复现 FAIL、修复后 PASS。S-R4-1/S-R4-2 由同函数引出的 `checkSbxSSHStdinTunnel` 覆盖：verifier+READONLY 下 `xargs ssx dmit 'PATH=/nope sh'`+stdin `rm -rf /tmp/x` 命中 strict 升级 `readonly_write_blocked`（远端 `PATH=` op 不再泄漏作解析基底），worker 下 `PATH=$PATH:<dir> xargs ssx dmit sh`+stdin `hc kill t1` 命中 `subagent_nested_agent`（`$PATH` 自引用不再坍缩为 `:<dir>`）。M-REV-1/M-REV-2 回归并入同表：`sbx --deny-net --workdir $(printf '/tmp sh -c pig') echo ok` 命中 `exceeded max shell nesting depth`（双槽动态值 fail-closed，argv 路径无 `$(` 语义故 checked 条件加 `!strings.Contains(tc.code, "$(")`），`PATH=<localBin> xargs -IXX foo --deny-net -- foo --deny-net -- sh -c XX` 命中 `dynamic code payload`（双层 `foo -> sbx` 别名全剥后 `sh -c` 的 XX 占位符落进 code 槽）——两条均在修复前复现 FAIL、修复后 PASS。
- `gofmt -l .`、`go vet ./...`、`staticcheck` 全绿。

## 来源
- 观察项分诊：`.agents/notes/20261109-v531-hc-allowlist-followup.md` O1；Oracle 审计 `/root/.dev-baseline/gate-ctxmode-peel-sbx-oracle-r1.txt`（M1/S1 + O1/O2 分诊）、`gate-ctxmode-peel-sbx-oracle-r2.txt`（S-NEW-1/S-NEW-2 修复 + O-NEW-1/O-NEW-2 分诊）、`gate-ctxmode-peel-sbx-oracle-r3.txt`（S-R3-1）与 `gate-ctxmode-peel-sbx-oracle-r4.txt`（S-R4-1/S-R4-2 修复）、Reviewer 复审 `/root/.dev-baseline/gate-ctxmode-peel-sbx-reviewer-r1.txt`（M-REV-1/M-REV-2）、Oracle 对抗审计 `/root/.dev-baseline/gate-ctxmode-peel-sbx-oracle-r6.txt`（O-R6-1/O-R6-2 分诊）与 Reviewer R2 `/root/.dev-baseline/gate-ctxmode-peel-sbx-reviewer-r2.txt`（红轮早退 must fix）。
- 代码：`role_guards.go`（`peelWrappers` case sbx、`isStructuralGuardHead`、`peelResolvedSegDepth` 晋升重筛、`stdinProgramHeadWithEnv` 携带 `envAs` 递归、`envHookVars`/`isEnvHookVar` `PI_SANDBOX_*`、`replTokenInExecSlot`/`xargsFeedsCodeFlag`/`peelToSSHHead`/`sshTunnelsStdinProgram`/`xargsDerivedSeg` 增传 `pathEnv` 与 sbx 别名二次解包、`peelWrappersAndSbxAliases` 有界重复别名重剥替代三处一次性重写）；`readonly_allowlist.go`（`readonlyPrePeelHit`）；`readonly_allowlist_test.go`（`TestGuard_PeelSbxWrapper`、`mustSbxBin`/`mustSymlink` 脚手架）。
