---
status: active
superseded_by: ""
supersedes: ""
模块: executor, router, main, batch, run_task, shell_screen
---

# argv 开放路径 + 真审计 + argv 补 screen

## 一句话结论
`validateArgv` 只保留空 argv/空 argv[0] 拦截，argv[0] 仅做规范化（绝对路径 Clean、相对路径按 cwd Join 后 Clean、裸名原样）不再做 workspace 围栏；argv 形态接入 `screenArgv`（NUL 硬阻断、超 64KiB 只 warn、拼接串跑 shellWarnPatterns）；新增 `audit.go`，四个 ctx_run 入口用 defer 各落一行 JSONL 到 `CTXMODE_AUDIT_LOG`（默认 `/root/.local/state/ctxmode/audit.jsonl`），只记元数据不记 stdout/stderr，另有两条只记录不阻断的标签规则。

## 背景
- 原 `validateArgv` 对 argv[0] 做 `lexicallyInside`/`ensureInsideWorkspaces` 围栏，但 README 威胁模型早已写明「无沙箱、无安全边界、argv 可执行任意命令」，围栏只制造了「有边界」的错觉，且阻断了大参数构建类命令的自然写法。
- shell `command` 形态在 4.1.0 已接入分级 screen，argv 形态未接入；NUL 字节在 argv 里经 execve 必然 EINVAL，旧行为表现为难以理解的 start 失败。
- 执行侧此前没有任何审计留痕：谁在什么角色下调了什么、screen 判定如何、是否被自动索引，事后无法归因。

## 决策
- **路径围栏**：`validateArgv` 仅拦 `len(argv)==0` 与 `argv[0]==""`；`resolveArgvExe` 用 `filepath.IsAbs` → Clean、`looksLikePath`（含分隔符或以 `.` 开头）→ `Clean(Join(cwd, exe))`、否则裸名原样（交给 exec.LookPath）。`ctx_fs`/`ctx_git` 的 `resolvePath`/`ensureInsideWorkspaces` 与 `cwd` 围栏一字未动。
- **argv screen**：`screenArgv` 独立于 `screenShellCommand`，因为 argv 不经 shell：NUL 硬阻断（错误串 `argv command blocked (nul_byte)`），拼接字节超 64KiB **只 warn**（大参数构建命令合法，阻断会误杀），三条 shellWarnPatterns 跑在空格拼接串上。warn 走 `logShellScreen` 并把规则名交给审计。
- **审计**：`audit.go` 单文件纯标准库。`startAudit(action, command_type, raw_cmd)` 在 handler 入口创建，`defer audit.emit()` 配合**具名返回值**折叠 `err`，`setResult` 折叠 exit_code/output_len/truncated/indexed，因此早期校验失败、spawn 失败、超时被杀、后台启动、大输出被索引都恰好落一行，无需在每个 return 点手写上报。落盘：`os.O_CREATE|O_APPEND|O_WRONLY` 0600，父目录 0700 按需创建，整行 `json.Marshal` 后在包级 mutex 内单次 Write（batch 并发命令不交织行）。字段固定（首批 19 个，双审回修后 **26 个**，见 `20260930-audit-review-fixes.md`）全部必现（不适用时为 \"\"/0/false/[]），便于消费方按固定 key 解析。
- **不记全文**：只记 `output_len` 与统计量，stdout/stderr 正文一律不落盘（体积 + 明文敏感内容 + 审计文件无脱敏环节）。
- **标签**：(i) `readonly_role_call` = `CTXMODE_ROLE` ∈ {scout,planner,researcher,reviewer,oracle} 或 `CTXMODE_READONLY=1`；(ii) `eval_interpreter` = LookPath 后 basename ∈ {sh,bash,dash,zsh,ksh,env,busybox,node,perl,ruby,php} 或 `python` 前缀，且 argv[1:] 含 `-c`/`-e`/`--eval`/`-i`。两条都只打标。
- **写失败只记日志不失败**：审计是记录不是策略，读状态目录/磁盘满不应把执行工具整体关掉。（双审回修后补充：目标类型校验、轮转与「FIFO 能拖死工具面」的实证见 `20260930-audit-review-fixes.md`；「永不拖慢执行」只对写失败成立。）

## 被放弃的方案（必填）
- **argv 超长阻断**：原计划在「改动点」写阻断、「风险」写 warn 自相矛盾；按 warn 实施，避免大参数构建命令被误杀。
- **把 stdout/stderr 存入审计**：拒绝（体积膨胀 + 明文敏感内容 + 无脱敏）。
- **审计整行不加长度上限**：拒绝，argv 已开放路径且超长只 warn，单行可达数 MB；改为 64KiB 截断 + `…(truncated)` 标记（按 rune 边界切）。
- **batch 每个命令一行**：本次为调用级一行（字段含 label: command 汇总 + 聚合 exit/output/truncated/index 标签），避免一次 batch 落 50 行；每命令级别的细粒度留待后续需要时再拆分。
- **给 `eval_interpreter` 覆盖 command/batch 形态**：拒绝，command 形态本质就是 `sh -c`，全量打标等于噪声；该标签只描述调用方显式给出的 argv。
- **`execute_file` 记 FILE_CONTENT**：拒绝，文件内容是数据不是调用方输入，只记 path/language/code。
- **权限模型 / PTY / 流式 / fs-git 围栏改动**：明确不做（任务范围外）。
- **全量输出取回**：明确不做（已决定暂不纳入）。

## 来源
任务【取消 argv 路径校验 + 真审计 + argv 补 screen】第一批实施。代码：`main.go` `validateArgv`/`resolveArgvExe`/`looksLikePath`/`toolExecute`/`toolExecuteFile`/`auditFileCommand`、`shell_screen.go` `screenArgv`/`shellVerdict.String`、`audit.go`（新）、`batch.go` `toolBatchExecute`/`auditBatchCommand`、`run_task.go` `toolRunTask`/`finishRunTaskOutput`、`instructions.go`、`README.md`、`CHANGELOG.md [Unreleased]`、`audit_test.go`（新）、`shell_screen_test.go`、`executor_test.go`。
