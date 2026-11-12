---
status: closed
superseded_by: ""
supersedes: ""
模块: "role_guards, readonly_allowlist"
---

# rt1111 红队批闭环 [pattern:role-guards-rt1111-closure]

## 一句话结论
分支 `feat/redteam-1111`（10 commit，`fddc298` 尖）以 `--no-ff` 合并 `a6a409f` 进 `main`（隔离 worktree `/root/workspace/.wt/ctxmode/merge-rt1111`，主目录脏工作树未动）；12 条加固 + 3 条同族漏网修复 + 表断言补正 + 固定 A 统一模型（npm 家族 argv 解析器）合入，`[Unreleased]` 并列 `### Security`（rt1111）与 `### Fixed`（drain EOF + 外来 mcp_argunwrap）三方条目、不开新版本节；C 档门禁 verifier/reviewer/oracle 已全闭环，W-5 残余面 refuted-with-evidence。

## 闭环结论
- **12 条加固**（A-1..A-11 + W-5）全部落地：ssh head 管写/known_hosts、journalctl `--lines=` 等值锁、`git tag --sort` 展示槽、`hc send` C0/C1 控制字与动态词、`isStdinDevicePath`（含 fd/00 拼法）、stdin 逐段扫描、wrapper 双槽 fail-closed、`isPeeledWrapperBase` 别名重剥与 `sameStructuralFamily`/`gnuCanonicalSet`、`screenNodeRunnerSubagent`（npx/bunx/pnpx）、`isEnvHookVar` 增 `CTXMODE_*`（AUDIT_LOG/ENV_PASSTHROUGH/DB/CONFIG）、`herdr`/`herdsman` 入 blockedAgentExecutableList、`screenPathHeadTrust` 经 `EvalSymlinks` 解相对 PATH。
- **3 条同族漏网**（R4/R5/R6 追加）：`npm --prefix /tmp exec pig`（exec 不是首个非 flag 词也拦）、`npm exec --call=pig`/`--call pig`（`-c`/`--call` fail-closed 与 `npx -c` 对齐）、`npm exec tsc --package=pig`/`--call=pig`（npm option zone 以自身 `--` 收束而非首个 child 词）。
- **表断言补正**（`ea440f6`）：audit 表断言以结果判定替代打印。
- **固定 A 统一模型**（R6，`c878f63` 起）：`parseNpmFamilyArgv` 单一 B/V/S 选项表取代 `npmFamilyValueFlags`/`npmFamilyExecArgs`/`npmFamilyVerbIndex`/`npmFamilyExecSub`；npm/pnpm/yarn 各自的 exec 选项边界（npm 以自身 `--`、pnpm/yarn 以首个 child 词）建模在 `npmFamilyOptTable`/`npmFamilyExecOptTable`；`-p`/`--package` spec 与首个 child positional 均去版本/tag 再过 `blockedAgentExecutables`。
- **10 commit 门禁轨迹**：多轮 verifier 双快照 + M1/S1 oracle 复验 + reviewer must0/should0/consider0 终裁 + `jev_check gate_scan` 无命中。
- **W-5 残余面 refuted-with-evidence**：verifier 实测 `C_sym(8)=9 / C_plain(8)=9`，`2n+1=17`（线性 n+1），原「指数级回溯」假设被实测否决，无隐藏缺陷。

## 遗留与观察项
- **consider `[pattern:trusted-user-toolchain-same-euid]`（1/2）**：`isSafePathDirEntry`/`isTrustedExecutableOnDisk` 接受 owner=euid 且 mode 无 group/world 写位的用户工具链目录（`~/.local/bin`、`~/go/bin`、`~/.local/share/mise/shims` 等）。同 euid 进程本可写这些目录，因此「同 euid 可写 toolchain 的二进制信任」属既有 ADAPT2/C10 边界、非本 diff 引入；门禁层不为同 euid 已握执行位的路径做第二层防植入。**不阻断，交用户过目。**
- **O1 unresolved `[pattern:version-strip-drops-dynamic-mark]`**：`npm exec pig@__ctx_cmdsub__` 一类「版本/tag 后缀」剥离把 `pig@__ctx_cmdsub__` 归一化为 `pig`，随后命中 `blockedAgentExecutables` 放行——版本剥离可能擦掉动态标记（`npm@__ctx_cmdsub__` → `npm`）。`@` 是 npm 版本/tag 语法合法部分，argv 层无第二信号可区分；如需收紧须引入「`@` 右段含 `__ctx_` 前缀即 fail-closed」的句法特例，代价是任何合法 `@` 后跟该前缀的字符串（极小概率）被误拦。**观察项不阻断。**
- **O2 unresolved `[pattern:screenCwd-unsynchronized]`**：既有 `screenCwd` 包级变量无锁竞态——`withScreenCwd` 在预检串行假设（`jsonrpc2.HandlerSerializer` + `runtime.LockOSThread` 纵深）下安全，但若未来协议层并发化预检或同一进程内多个 goroutine 并行进入 `resolveHeadBase`，`screenCwd` 是共享可变状态。**非本 diff 引入**，属既有设计权衡；如需彻底移除可重构为 `guardCall` 显式字段并向 `resolveHeadBase` 显式传参。**观察项不阻断。**
- **O3 out-of-scope `[pattern:argv-parser-out-of-scope-eval]`**：`package.json` `scripts`、`.npmrc`、`npm_config_*` 不由 argv parser 求值——已补记至 `.agents/notes/2026-11-01-role-guards-non-sandbox-boundaries.md`（O3 段），结构性边界，非缺陷。
- **M2 refuted-with-evidence `[pattern:rt1111-m2-refuted]`**：reviewer M2 怀疑「表断言补正遮蔽中间行」。实测 `C_sym(8)=9 / C_plain(8)=9`、`2n+1=17`——对 n 行结构 `n+1` 线性，不存在被断言遮蔽的行漂移；**不得据此在断言外加防御性冗余**。结论与 W-5 同法（以数制实测拒证结构性怀疑）。

## 被放弃的方案
- 主目录内合并：否决。主目录工作树有 mcp_argunwrap 外来未提交改动（`M CHANGELOG.md`/`M main.go`/`?? mcp_argunwrap.go`/`?? mcp_argunwrap_test.go`），`git checkout`/`stash`/`merge` 会污染或破坏它们 → 用户裁定隔离 worktree 合并。
- 推送后起 tag/版本节：否决。`[Unreleased]` 三方并列已是用户裁定的终点，不开 `[X.Y.Z]`。
- 拆分 `parseNpmFamilyArgv` 为 per-manager 三个函数：否决。npm/pnpm/yarn 差异（exec verb 识别、option zone 收束点、`-p` 是 bool 还是 spec taker、`-c`/`--call` 语义）以参数化表承载，保持单一 accept 模型，避免三份近似实现漂移。

## 验证
- 合并后 `git diff fddc298 HEAD -- role_guards.go readonly_allowlist.go role_guards*_test.go zz_*_test.go REPORT.md` 为空（CHANGELOG 之外树与 `fddc298` 完全一致）。
- `gofmt -l .`（空）、`/root/go/bin/staticcheck ./...`（rc=0）、`go vet ./...`（rc=0）、`go build -o /dev/null .`（rc=0）、`go test -race -count=1 -timeout 25m ./...`（rc=0，644.7s）、`node --experimental-strip-types --test integrations/pi/*.test.ts`（39/39 通过，node v22.23.4 vs CI 24）。
- `git rev-list --count origin/main..HEAD` = 0；`origin/main` 前进 `6ab1908 → a6a409f`。

## 来源
- 合并 worktree：`/root/workspace/.wt/ctxmode/merge-rt1111`（临时，**保留**，主代理下一步用它处理主目录 fast-forward 尾巴）。
- 报告：`REPORT.md`（rt1111 详情）。验证日志：rt1111 worktree 自检输出，CI check-runs 轮询（`gh api repos/dorokuma/ctxmode/commits/a6a409f/check-runs`）。
