---
status: active
superseded_by: ""
supersedes: ""
模块: "ctx_run, executor"
---

# v5.3.1 hc 只读白名单修复：Oracle/Reviewer 观察项落盘与分诊闭环

## 一句话结论
v5.3.1 C 档守卫修复（`fix/readonly-allowlist-hc`，基线 `0bffa15`）的 Oracle `0 must fix / 0 should fix / 3 consider` 与验证期新发现项全部分诊完毕：O1/O2/O4 转为后续分支任务，O3 按设计无需改码；本轮仅将分诊结论落盘仓内，不改变守卫语义。

## 背景
`hc`（herdr-core / sbx 沙箱别名）注册入严格只读白名单后，Oracle 审计与验证期共记录 4 项观察。原分诊记录存放在仓外 `/root/.dev-baseline/followup-ctxmode-v531-oracle-consider.md`，C 档 reviewer 指出仓内可见性缺口，按授权将结论入库留痕。

## 决策（分诊结论与后续分支计划）
1. **O1 `[pattern:sbx-wrapper-unwrap-asymmetry]`** — `confirmed`，转后续分支 `fix/peel-sbx-wrapper`。
   - 严格只读身份下直调 `sbx` 已被只读白名单默认拒绝，路径写法命中 `path command`；缺口在非只读子代理（worker/verifier）对 `sbx` 包装器的解包不对称。
   - 不可直接把 `sbx` 加进 `blockedAgentExecutableList`：`headBaseAliasHits(["hc","send","t42","ok"])` 在沙箱内解析出 `["hc","sbx"]` 会误杀 `hc send`；`codeAgentNames` 派生自封禁表会误拦合法脚本文本；verifier 会话合法调用 `sbx --preset reviewer-agent`。
   - 后续方案：教 `peelWrappers` 解析 `sbx` 参数（`--preset`/`--workdir`/`--ro`/`--rw`/`--exec`/`--env`/`--report-to`/`--`），`--env` 赋值送入 `sentinelTrustVars` 校验，并递归筛查内层 `COMMAND [ARGS...]`，对 `subagent_nested_agent` fail-closed。
2. **O2 `[pattern:readonly-alias-basename-trust]`** — `confirmed`（consider，与既有 `awk`/`sed`/`systemctl` 条目威胁模型一致），可选加固转后续任务。
   - `isAllowedSystemReadonlyAlias` 只比对软链目标 basename；不安全 PATH 段已由 `pathIsUnsafeForSubagent`/`isSafePathDirEntry` 拦截，绝对路径写法由 `readonlyPrePeelHit`（`path command`）拦截。
   - 可选加固：向 `isAllowedSystemReadonlyAlias` 传入 `resolvedDir` 一并校验。
3. **O3 `[pattern:hc-subcommand-help-query]`** — `confirmed` 按设计保留，无需改码。
   - `hc <sub> --help` 单 flag 查询放行：herdr-core 与 sbx 的 `--help` 均为纯打印，无副作用与 socket 连接。
4. **验证期发现 `[pattern:ctxmode-bg-log-collision]`** — `confirmed`（`executor.go:263` 既有缺陷，v5.3.1 范围外）。
   - `/tmp/ctxmode_bg_bg-1.log` 跨进程碰撞：多个 ctxmode MCP 实例或 `go test` 套件共享 `/tmp` 时互相覆盖/删除活动日志。
   - 后续方案：`bgTempPrefix` 日志名加入实例随机 token 或 PID（`ctxmode_bg_<instance>_<id>.log`），并收紧 `executor.go:1207-1231` `init()` 的 >24h 旧文件清扫，避免误删其它实例的活动日志。该结论同步登记于 `chore/baseline-l2-make-check` 分支 `.agents/notes/20261109-baseline-l2-make-check.md`。

## 被放弃的方案（必填）
- **本轮直接把 `sbx` 加入 `blockedAgentExecutableList`**：否决，如上会误杀 `hc send` 回报通道与合法 verifier 探针。
- **本轮收紧 `isAllowedSystemReadonlyAlias` 至校验目标目录**：否决，威胁模型与既有别名条目一致，属可选加固而非缺陷，留给后续 pass。
- **删除 `hc <sub> --help` 查询放行**：否决，破坏设计契约且该查询纯打印无副作用。

## 来源
- 仓外分诊：`/root/.dev-baseline/followup-ctxmode-v531-oracle-consider.md`（Oracle 报告 `/root/.dev-baseline/gate-ctxmode-hc-oracle.txt`，Reviewer 报告 `/root/.dev-baseline/gate-ctxmode-hc-reviewer.txt`）。
- 代码：`role_guards.go`（`isAllowedSystemReadonlyAlias` case "hc"、`screenHcSubagent`、`screenNestedDispatch` case "hc","herdr-core"`、`peelWrappers`）；`executor.go:263`、`executor.go:1207-1231`。
- 回归：`readonly_allowlist_test.go` `TestGuard_HcReadonlyAndSubagent`。
