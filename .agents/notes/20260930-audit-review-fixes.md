---
status: active
superseded_by: ""
supersedes: ""
模块: audit, batch, run_task, shell_screen, main
---

# 审计与 argv 提交前双审回修（F1/F2 + S1–S10 + 观察项）

## 一句话结论
审计落盘改为「先 `Lstat` 校验目标、再进 mutex」，非普通文件（FIFO/软链/目录/设备）一律拒写且错误路径不阻塞，堵掉「FIFO 挂死整个 ctx_run 工具面」；batch 调用级 `exit_code` 改用独立 `seen` 哨兵，首条 -1 不再被后一条 0 折叠；审计行补 `pid`/`session_id`/`env_keys`/`stdin_len`/`commands`/`first_failed_label`/`background_id`，`raw_cmd` 命中敏感内容改为 `len+sha256` 标记；`run_task` 接入同一 argv screen；`eval_interpreter` 支持捆绑短选项、`--eval=`、`php -r`、`Rscript -e` 并收窄 README 措辞。

## 背景
- 第一批实施（见 `20260925-argv-open-and-audit.md`）提交前经 oracle 对抗审计 + reviewer 复核，结论为「不能原样提交 / 条件放行」，回修清单：`/tmp/fix-package-argv-audit-20260930-0005.md`（must fix F1/F2、should fix S1–S10、观察项 O1–O8、6 条需删改的绝对化表述）。
- F1 是真缺陷而非措辞问题：`auditMu.Lock()` 在 `OpenFile` 之前，若目标被换成 FIFO，`open` 在锁内永久阻塞，其后每次 emit 全部排队 → ctx_run 四个入口一起死锁，直接推翻「审计永不拖慢执行」的说法。

## 决策
- **F1 目标校验**：`auditTargetOK(path)` 先 `os.Lstat`：不存在 → 放行（随后按 0700/0600 创建）；软链、FIFO、目录、设备 → 拒写并返回错误。校验在 `auditMu.Lock()` **之前**，任何失败路径都不持锁返回。再加 `syscall.O_NONBLOCK` 与打开后 `f.Stat()` 复检作为 Lstat/Open 竞态兜底（`O_NONBLOCK` 对普通文件是 no-op，对 FIFO 无读者时直接 ENXIO 失败而不阻塞）。失败仍只记一条进程日志（按 path+reason 去重），调用本身照常执行。
- **F1 附带 S6**：审计文件上限 32MiB，达到后 `rename` 到 `<path>.1`（覆盖上一代）再新开，长驻服务不会把单文件撑爆；无需外部 logrotate。旋转阈值做包级变量，测试可调小。
- **F2 batch 聚合**：`auditExitNotRun`(-1) 同时是「还没有结果」的哨兵和合法失败码，旧代码首条 -1 会被下一次循环判回「首次」分支而被后一条 0 覆盖。改为独立 `batchSeen bool`；语义固定为「全成功才 0，否则首个非 0 码，-1 一律当失败保留」。
- **S4 batch 可机械解析**：单行内加 `commands` 数组（`label`/`exit_code`/`screen_verdict`/`screen_rule`/`indexed`/`index_label`）与 `first_failed_label`，替掉逗号拼接的 label 串（label 允许含逗号，拼接必然歧义）。仍是「一次 batch 一行」。
- **S5 后台行语义**：后台调用只启动 job，没有 exit status，故记 `exit_code: -1` + `background_id`，并在 README 字段表写清该行 `output_len` 是启动文案长度、不是 job 输出。
- **S1/S2 记录内容**：补 `pid`（`os.Getpid()`，行可定位到进程）、`session_id`（复用 `store.session_id`）；`raw_cmd` 复用 `checkSensitiveContent`，命中改记 `[redacted: … len=… sha256=…]`（先做敏感检查再截断，避免截断后漏判）；新增 `env_keys`（只记调用方 env 的**键名**，排序 + 上限 64）与 `stdin_len`（只记长度）。README 删掉「metadata and statistics only」，明确写「明文、可能含凭据」「0700/0600 只在创建时生效」「append-only 只是 O_APPEND，不是防篡改」。
- **S3/S10 run_task 入 screen**：`run_task`（含 `custom`，即唯一由调用方给 argv 的 kind）走 `applyArgvScreen` + `setScreen`，与 execute argv 共用同一实现与同一错误串，避免两个 argv 入口行为分叉、记录语义分叉。
- **S10 `-i` 误报收敛**：`stdinInteractive` 的 `-i` 仅在**首个**参数且非 `-m` 模块模式时成立；`python3 -m pip install -i URL` 不再打标，`python3 -i` 仍打标。
- **S7/S8 eval_interpreter 覆盖**：短选项按「捆绑字母集合」判定（`-lc`/`-ec`/`-pe` 命中），长选项支持 `--eval=…`/`--print`（按 `=` 截取名字），补 `php -r`、`Rscript -e`；`env`/`busybox` 包装层剥离（含 `-i`/`-u`/`NAME=value` 等自身选项），使 `env FOO=1 sh -c …` 仍能打标、`env -i cmd` 不再像交互式解释器。**表驱动、拼写级**，不是解析器。
- **S9 四入口时机一致**：`toolExecute`/`toolExecuteFile` 的 `startAudit` 提到函数最前（含必填项校验之前），空参调用也落行；四个入口的 `raw_cmd` 允许先记空串/原始入参，稍后 `setCommand` 覆盖。
- **O1/O2/O3/O4/O5/O8**：`auditExeCache` 上限 256 且只缓存成功（失败不缓存，避免「刚装的工具终身查不到」）；argv `oversized` warn 走 `logShellScreenNoHead`（不打 80 字节头，大参数列表头部无信号）；README 写明 `screen_verdict` 第三值 `""` = 未及筛查就被拒；默认路径失败时额外打出「默认路径是 root 专用，请设 CTXMODE_AUDIT_LOG」提示；测试里的 `os.Setenv`（TestMain 没有 `*testing.T`，`t.Setenv` 不可用）与字面默认路径断言都在测试注释里写明是有意为之；batch 每命令的 screen 判定一并入 `commands`，避免同批次的 idiom 规则被另一条 oversized 阻断遮盖。

## 被放弃的方案（必填）
- **把 FIFO/软链目标降级为「只记日志、静默跳过」**：拒绝。目标是运维可控输入，配置错了却静默不写会让人以为有审计；拒绝 + 一次性日志更诚实。
- **给审计打开加 `O_NOFOLLOW`**：拒绝。Lstat + O_NONBLOCK + 打开后复检已覆盖同一竞态窗口，且同 uid 攻击者本就能改写审计文件（威胁模型已写明不防篡改）。代价已写进 README：**软链目标（例如把 `CTXMODE_AUDIT_LOG` 指到 `/dev/stdout`）一律被拒**，这是有意的取舍。
- **审计复用 `main.go` 的 `resolveArgvExe`**：拒绝。两者目标不同——执行侧只 `Clean` 裸名（交给 exec.LookPath），审计要落「真正会被执行的绝对路径」，合并会把 LookPath 代价塞进执行路径；改为给缓存加上限并只缓存成功，两处实现共用 `looksLikePath` 保证「什么算路径」不漂移。
- **每命令一行 / 后台行记真实 exit_code**：拒绝。前者制造记录噪声，后者在启动时刻根本不存在。
- **去掉 batch 调用级 screen 汇总字段**：拒绝。保留汇总（最差 verdict + 一条代表规则）同时给每命令明细，两层都能读。

## 已知缺口（本批未修，已写进 README/CHANGELOG）
- O6 审计只覆盖 ctx_run，不含 ctx_fs/ctx_git/ctx_kb/ctx_bg。
- O7 一行 = 一次**调用**，不是一次**执行**（子进程不单独记）。
- 「append-only」只是 `O_APPEND`，同 uid 可 truncate/改写/删除/伪造；`readonly_role_call` 需派发层设置 `CTXMODE_ROLE`/`CTXMODE_READONLY`，在此之前恒不出现。
- O3 部分完成：`raw_cmd` 有 64KiB 上限，但 `commands` 数组里的 `label`/`index_label` 有意**原样记录不截断**（label 是调用方给 batch 的键，也会真实用于 KB index label；截断会让审计行与库里的标签对不上）。因此 batch 单行上限只剩「50 条命令 + MCP 请求体积」约束，已写入代码注释与本清单。
- 敏感内容检查按模式匹配，未格式化的凭据仍可能随 `raw_cmd`、`env_keys` 落入明文文件。

## 来源
双审回修第二批。修复包 `/tmp/fix-package-argv-audit-20260930-0005.md`；代码：`audit.go`（F1/F2 辅助、S1/S2/S5/S6/S7/S8/S10、O1–O3、每命令 screen 字段）、`batch.go`（F2/S4/O8）、`run_task.go`（S3/S10）、`shell_screen.go`（O2）、`main.go`/`run_task.go`（S9、S2 inputs）、`audit_test.go`（新用例）、`README.md`、`instructions.go`、`CHANGELOG.md [Unreleased]`。
