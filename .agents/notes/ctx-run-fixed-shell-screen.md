---
status: active
superseded_by: ""
supersedes: ""
模块: executor, router, integrations/pi
---

# ctx_run command 形态固定为受控 /bin/sh -c 并加分级前置检查

## 一句话结论
shell `command` 一律走 `exec.Command("/bin/sh", "-c", code)`，不再读取 `os.Getenv("SHELL")` 或做 `strings.Fields` 拆分；在 toolExecute 与 executeCommand 两处接入分级前置检查（阻断：NUL/>64KiB；告警：base64/curl/wget 管道到 shell、重定向写 /etc//dev/sd*），告警只写日志不构成政策。

## 背景
原实现用 `SHELL` 环境变量选择 shell，`SHELL="/bin/bash -l"` 会被拆分执行、空值时回落 `sh`。这使命令形态的实际解释器可被环境变量左右，是应当收敛的攻击面。方案已由 planner 定稿、主代理批准固定 `/bin/sh`。

## 决策
- `executor.go` 新增 `shellCommand(code string) *exec.Cmd` = `exec.Command("/bin/sh", "-c", code)`（绝对路径）。`runShellOpts` 与 `batch.executeCommand` 整段 shell 选择逻辑替换为一次 `shellCommand` 调用，`cmd.Dir`/`Setpgid`/`applyRunOptions`/`runCmd` 全部保持原样。sync 修正 1502/2356 处注释。
- 新建 `shell_screen.go`（纯标准库）：`screenShellCommand(code) (shellVerdict, string)`，verdict ∈ shellOK/shellWarn/shellBlock。阻断仅两项：`strings.ContainsRune(code,0)` 与 `len(code)>64*1024`（空串不在此检查，保持 main.go:316 现有报错）。告警 ≤4 条包级 regexp.MustCompile（实际 3 条），命中后 `log.Printf` 只打规则名、命令长度、前 80 字节（%q），不打全文。
- 接入点：长度/NUL 阻断下沉到 `runShellOpts` 开头一处，同时覆盖 execute 与 execute_file；模式告警只在 `toolExecute`（language 空或 shell）与 `executeCommand` 入口打，sb block 返回 batchResult.Error 不连坐其他条目，execute_file 不单独接入（避免对 FILE_CONTENT 误报）。三处不重复写检查逻辑。
- `rustBackgroundArgv` 的 `sh -c` 不动（非命令形态，属编译运行 argv）。

## 被放弃的方案（必填）
- allow/deny 清单或 basename 拦截复活：明确不做（无白名单设计）。
- 新增 shell_ack 确认字段：不做（仅文档级知情）。
- 对 python/node 等非 shell 解释器做内容筛查：不做（screen 仅作用于 shell 命令字符串）。

## 来源
任务【ctx_run command 形态安全加固】四阶段实施；`executor.go` `shellCommand`/`runShellOpts`、`batch.go` `executeCommand`、`shell_screen.go`、`main.go` `toolExecute`、`README.md`、`CHANGELOG.md [Unreleased]`。
