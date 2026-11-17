---
status: active
superseded_by: ""
supersedes: 20261115-report-channel-security-r1.md
模块: "ctx_run, router, role guards"
tags: [pattern:dispatch-report-channel-env-binding, pattern:ctx-report-sole-entry]
---

# v6.0.0：ctx_report 收口为角色侧唯一报告交付入口

## 一句话结论

v6.0.0 起 `ctx_report` MCP 工具是全部 7 个被守卫角色的唯一报告交付
入口；`dispatch-report` 并入 `blockedAgentExecutableList` 与
`codeHeadIsAgentInvocation` 主表，`ctx_run` 的 4 个 action 下全部拼写
（裸名/受信与非受信绝对路径/wrapper 包裹/`<t-addr>`/`--flush`/
`--help`/`--version`，及解释器 spawn、awk 动态命令、npm 族 exec/-p
包名、外语解释器裸语句头）一律封禁。

## 背景

5.6.0 引入 `ctx_report` 后仍保留 `ctx_run argv=["dispatch-report",
"<t-addr>"]` 作为严格只读角色的等价拼写（`readonlyAllowlist` +
`screenDispatchReportReadonly` + `readonlyCanonicalHeads` 双名豁免）。
双入口使派发器、角色规则文档与守卫代码需要同时维护两套契约，且
`dispatch-report` 二进制作为 argv 头暴露在所有角色的可执行面上，
攻击面随每个新拦截分支（解释器、npm 族、awk、stdin 管道）重复评估。
C2 终审进一步发现仅给 `screenNestedDispatch` 加 `case
"dispatch-report"` 并未同步依赖主表的其余 5 条防线：动态 Python/JS
spawn（`codeStaticSpawnsDetailed` allResolved=false 时仅靠
`codeAgentNames` 兜底）、go/rust/perl/ruby/php/r/elixir/csharp 八种
runtime（恒 allResolved=false）、awk 动态命令
（`programNamesBlockedAgent` 由 `codeAgentNames` 派生）、npm/npx 族
`-p`/`--package` 包名与 `dispatch-report-*` 前缀派生
（`isBlockedAgentHead`）、外语解释器裸语句头
（`codeHeadIsAgentInvocation`）全部漏检，worker/verifier 可真实绕过
封禁执行 `dispatch-report`（含 `--flush`）。

## 决策

1. **退役角色侧 `ctx_run dispatch-report` 拼写，收口 `ctx_report`
   单入口。** 删除 `readonlyAllowlist["dispatch-report"]`、
   `screenDispatchReportReadonly`、`readonlyCanonicalHeads` 中的
   `dispatch-report` 条目及
   `screenReadonlyAllowlistSeg`/`readonlyPrePeelHitExempt` 的双名
   绝对路径豁免（收窄为 hc-only）；`instructions.go` 与 Pi 扩展指南
   同步去掉 `argv=["dispatch-report",...]` 备选拼写。
   `ctx_report` 自身经 `findDispatchReport` 的独立受信链直调
   `dispatch-report <parent>` 子进程，不经 `ctx_run` 守卫；主代理
   （无 `CTXMODE_ROLE`/`CTXMODE_READONLY=1`）不受角色守卫影响。

2. **`dispatch-report` 并入嵌套代理主表，与 herdr/herdsman 退役
   同构。** 加入 `blockedAgentExecutableList`（自动同步进入
   `blockedAgentExecutables`、`isBlockedAgentHead`、
   `codeAgentNames` 与 `programNamesBlockedAgent`；不在
   `pureQueryOnlyHeads`，`--help`/`--version` 保持阻断）；原
   `screenNestedDispatch` 的专门 case 变死代码删除；
   `codeHeadIsAgentInvocation` 的语句头名单补入 `dispatch-report`。
   由此一次性封死上面 5 条漏检防线，且 `dispatch-report-helper`/
   `dispatch-report.x` 派生名按 len≥5 stem 规则同判阻断。

3. **自愈指引补齐全拦截面并消除伪后缀误提示。**
   `blockedReportError` 除 argv[0]/shell 段头两类正向外，对
   `ruleSubagentNestedAgent` 错误提取 detail：detail 恰为
   `dispatch-report`，或以 ` dispatch-report` 结尾且非
   `untrusted path binary `/`planted shadow binary ` 前缀（排除
   `foo: dispatch-report` 伪后缀误挂）时追加
   `reportDeliveryHintText`（"call the ctx_report MCP tool …"）。
   `run_task` 的 env 前置拦截在 `kind="custom"` 时把 `args.Args`
   传入 `blockedReportError` 包裹；固定 kind 不传 argv，避免
   `go_test` 额外参数误挂指引。

4. **C4 补漏：进程启动原语表与拦截身份透传。** `codeSpawnPrims`
   补入 C#（dotnet-script）`Process.Start`/`ProcessStartInfo`/
   `.StartInfo` 及同构 `os.StartProcess`/`syscall.StartProcess`
   （Go）、`process::Command`（Rust `use std::process`）、`os.cmd`
   （Elixir `:os.cmd`），使 `language="csharp"` 的
   `System.Diagnostics.Process.Start("dispatch-report", …)` 命中
   spawn 门控后走 `codeAgentNames` 兜底返回
   `code spawns dispatch-report`；抽出 `isReportGuardDetail`
   供 `blockedReportError` 与解释器 `-c`/`-e` 剥壳分支共用——外层
   `python3 -c`/`node -e`/`ruby -e`/`perl -e` 内层命中
   dispatch-report 时原样透传 detail（其余拦截仍折叠为
   `<lang> inline code`），动态 awk 命中时返回
   `awk dynamic cmd dispatch-report`，三处均追加单入口 hint。
   **边界声明**：`codeSpawnPrims` 词法原语门控（表外 spawn 拼写
   静态不可见）与管道无参流（`echo … | sh` 返回
   `piped code to shell`）属既有非沙盒词法边界，对全部黑名单名
   同构，非本轮新增缺口。

## 被放弃的方案

- **仅加 `screenNestedDispatch` case 而不入主表**：C2 已证实留下
  5 条真实绕过路径，否决。
- **`blockedReportError` 按渲染后错误字符串 `": dispatch-report"`
  后缀匹配**：会把路径信任类 detail（`untrusted path binary foo:
  dispatch-report`）误挂指引，且无法区分 `npm exec dispatch-report`
  与 `code spawns dispatch-report` 前缀形态，否决；改为解析
  `ruleSubagentNestedAgent` 前缀后的 detail 并显式排除路径信任前缀。
- **保留旧笔记 `status: active` + 发布号 `superseded_by`**：不符合
  `.agents/notes/README.md` 的 superseded 规范（`superseded_by` 须为
  新笔记文件名），否决；旧笔记整篇置 superseded，正文历史记录不改。
- **`run_task` env 拦截改用构造后 argv 判 hint**：把
  `guardCtxRunEnv` 移到 `buildRunTaskArgv` 之后改动面更大；仅
  `kind=="custom"` 传 `args.Args` 已精确覆盖场景且固定 kind 无误挂。

## 与 20261115-report-channel-security-r1 的关系

该笔记第 1 条（复合赋值写算子）、第 3 条（extras 工作区窄策略）、
第 4 条（词法屏幕边界）及 env 绑定 denylist
（`DISPATCH_REPORT_PATH`/`DISPATCH_REPORT_PARENT`/
`CTXMODE_EXTRA_WORKDIRS` 的 `envHookVars`/`isDeniedEnvKeyForCaller`
拦截）在代码中**继续有效**；仅其第 2 条中角色侧 `ctx_run
dispatch-report <t-addr>` 放行契约（含 `screenDispatchReportReadonly`
单拼写与 `--flush` 派发器保留措辞的实现形态）被本笔记取代——
`--flush` 仍是派发器外层专属动词且强校验 `.meta`，但角色侧已无任何
`dispatch-report` 拼写。

## 来源

- 分支 `feat/ctx-report-v600`（基线 `29fbca2`）；C2 reviewer/oracle
  终审（must fix 1 + should fix 2 + OBS-1 + SF-2）。
- 跨仓锁步：`dispatch-agent`（`config.ReportAddrRe`、helper 的
  fd-chain/`.meta`/`.sent` 契约不变）、`pi-extensions/go/sandbox/
  preset.go` 的 `DefaultReviewerTools` 仅保留 `dispatch-report` 作
  沙盒内 `ctx_report` 子进程 `exec` 的 Landlock 许可。
