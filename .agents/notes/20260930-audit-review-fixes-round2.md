---
status: active
superseded_by: ""
supersedes: ""
模块: audit, main, shell_screen
---

# 审计轮转失败不丢行 + 双审第二轮收口（R2-F1/S1/S2/D1–D3/R1–R3）

## 一句话结论
轮转改为「尽力而为」：rename 失败只记一次日志，该行仍以同一 fd 追加到当前文件，既不丢行也不会让后续 append 永久失败；`resolveAuditExe` 真正复用 `looksLikePath`（消除 `.hidden`/`..x`/`a\b` 上 `resolved_exe` 与真实执行路径的分歧）；env 键名逐个过 `checkSensitiveContent`（命中记 `[redacted]`）；README 与 `audit.go` 头注释把「Lstat 在锁外、open 在锁内且带 O_NONBLOCK」「只校验末段组件」「只保留 current + `.1`」「软链目标被拒（含 `/dev/stdout`）」全部改成与实现一致。

## 背景
- oracle 第二轮：F1/F2 已确认闭环，新发现轮转缺陷 —— 旧实现 `f.Close()` 在先、`os.Rename` 失败即 `return err`：该行丢失，且文件仍 ≥ 阈值，之后每次 append 都复走同一失败路径，等于永久静默停写。触发面（实测成因）：`<path>.1` 是非空目录（EISDIR/ENOTEMPTY）、目录对本进程不可写（EACCES）。**不写 EXDEV**：同目录 rename 必然同一文件系统，`EXDEV` 对该调用不可达；若 `path` 本身是挂载点，得到的是 `EBUSY`。
- reviewer 第二轮：放行（可提交），另提 3 条记录项：软链拒写带来的运维代价（容器里 `/dev/stdout`）、`O_NONBLOCK` 在 NFS/CIFS/FUSE 下的 `EAGAIN` 写失败、多实例共享同一审计路径时无跨进程锁。
- 另有两处「注释/文档与实现不符」被点名：`resolveAuditExe` 声称共用 `looksLikePath` 但实现只查分隔符；README/CHANGELOG 写「`O_NONBLOCK` 在 append mutex 之前」但实测 open 在锁内。

## 决策
- **R2-F1**：rename 移到 `f.Close()` 之前（POSIX 允许带打开的 fd 改名）。失败 → `logAuditFailure(path+".1", "rotate (keeping the current file): …")`（复用按 path+reason 去重的一次性日志）→ 继续用同一个 fd 把当前行写进当前文件；成功 → 先 `openAuditFile(path)` 拿到新文件，再 close 旧 fd。下一次调用仍会尝试轮转（文件仍超阈值）但同样只记一次日志并正常写行，因此既无丢行也无永久停写。
  - 额外堵一个同族缺口：rename 成功后新文件打不开（EMFILE/ENFILE 等），旧实现会在 `return err` 处丢行。现在 `openAuditFile` 失败时**不替换 fd**，该行写进刚被轮转走的那一代（`.1`），并打一条 `reopen after rotation` 日志。即「这个块里没有任何一条路径会丢记录」。
  - 该分支已固化为单测 `TestAudit_ReopenAfterRotationFailsKeepsRecord`（与 `TestAudit_RotationFailureKeepsWriting` 同文件、同族）：用 `RLIMIT_NOFILE` 把软限收紧到“刚好还多一个 fd”，使调用内的首次 open 成功、rename 后的重开以 EMFILE 失败；断言该行落在 `.1`（两行齐）、当前路径上没有该行。辅助函数 `tightenFDLimitToOneExtraOpen` 用「探针 open」经验性收敛 off-by-one，宿主机做不到收紧时 `t.Skip`。撤销上一轮笔记里「root 下无法构造、故无单测」的说法 —— oracle 三审已用 RLIMIT_NOFILE 确定性构造并实测行为与注释一致，这个说法不成立。
  - 补记（R3/R4）：该分支已由 `TestAudit_ReopenAfterRotationFailsKeepsRecord` 覆盖（用 `RLIMIT_NOFILE` 收紧软限构造 EMFILE），实测行为与注释一致；此前的「未写单测」说法作废。
- **R5 缺口闭环（索引标签的正向守护）**：`finishRunTaskOutput` 的自动索引分支（>`runTaskAutoIndexBytes`=100KiB）在函数内部铸造 label，审计行的 `indexed`/`index_label` 只能由该函数的实参带回，先前没有任何用例走真入口 `toolRunTask` 的**超阈值**路径，所以「标签有没有被带回来」缺正向守护。现由 `TestAudit_BatchAndRunTaskWireEntryPoints` 第三次调用补齐：`toolRunTask(custom, sh -c "yes indexed_line | head -n 40000")`（实测 `output_len`=520000）后断言 `indexed=true` 且 `index_label` 非空。该 fixture server（`auditTestServer`→`testServerWithWorkdir`）原本不带 store，索引分支一进 `storeIndexLocked` 就 nil 崩 —— 这正是缺口长期没被发现的原因，测试内补一行 `s.store = newTestStore(t)`。
  - 非空跑验证：临时删掉 `run_task.go` 里 `finishRunTaskOutput(..., audit)` 的实参，该记录变为 `Indexed:false IndexLabel:`、用例失败；恢复实参后通过。
  - **保留 oracle R5 的风险说明**：改成可变参数后，调用点漏传 audit **没有编译错误、也没有运行时错误**，只是静默丢掉 `indexed`/`index_label`（`setIndex` 对 nil 安全，defer 那行记录照常写出）；不设运行时兜底，只靠这个用例与审阅约束。
- **R2-S1**：`resolveAuditExe` 的路径分支改用 `looksLikePath`（`filepath.IsAbs` → Clean；否则 `Join(cwd, name)` → Clean），与 `main.go resolveArgvExe` 同判据，`.hidden`/`..x`/`a\b`/`.`/`..` 都与执行侧一致。唯一残留差异是 cwd 为空时的兜底（执行侧 `workdirs[0]`、审计侧进程 cwd），当前两个调用点都传已解析的 workdir，够不到；已在函数注释里写清。
- **R2-D3**：`auditEnvKeys` 逐键过 `checkSensitiveContent`，命中记 `[redacted]`；实现改为「集合去重 → 排序 → 上限 64」，避免多个命中键刷出重复项。覆盖范围等于既有 pattern 集（`AKIA…`/`ghp_…`/`xox…`/JWT/私钥/显式赋值），`sk-live-…` 这类没有 pattern 的名字仍原样落盘 → README 补「键名同样可能含凭据」，值始终不落盘。
- **R2-S2 / R2-D1 / R2-D2 / R2-R1（只改措辞与说明，不动行为）**：README 与头注释明确「Lstat 在锁外；open（含 `O_NONBLOCK` + 打开后 `Stat` 复检）在锁内，故 FIFO 不会挂住工具面」；「只校验**末段**路径组件：父目录是软链仍会静默改道、硬链接无法识别、文件系统自身停摆（NFS/FUSE/CIFS 挂死、冻结块设备）仍可能拖慢一次写入」；「只保留 current + `.1`（约 2×32MiB），更早世代静默丢弃、无归档、无跨进程锁，多进程共享路径时窗口偏向写得快的一方」，并给出外部归档建议（对该路径用 logrotate `copytruncate`，或定时 `cp <path>.1 /archive/…`；不动系统 `/etc/logrotate.d`、不动 `deploy.sh`）；「软链目标一律被拒 → 容器里 `CTXMODE_AUDIT_LOG=/dev/stdout` 不再可用，请指向真实普通文件、挂载卷内路径或日志采集器跟随的文件」。

## 被放弃的方案（必填）
- **轮转失败时删除 `.1` 再重试 / 直接停写**：拒绝。删除用户路径下的既有内容超出审计职责；停写正是本次要修的缺陷本身。
- **rename 失败后改用 `<path>.<timestamp>` 等替代世代名**：暂不做。会产生无界世际文件并需要额外清理策略；当前选择「单代保留 + 失败就不轮转」。
- **用 `fcntl(F_SETFL)` 清掉 `O_NONBLOCK`（R2-R2）**：拒绝。本机普通文件本就忽略该标志（无收益），而 Linux 下 `F_SETFL` 传错标志位可能把 `O_APPEND` 一并清掉 —— 用真实的 append 语义换一个罕见的 NFS `EAGAIN` 写失败不划算；改为把「NFS/CIFS/FUSE 写锁竞争可能 `EAGAIN` 导致该行写失败」落 notes 已知边界。
- **跨进程文件锁（R2-R3）**：不做。当前是单进程设计假设；已在 README/notes 写明多进程共享同一路径会并发 rename、`.1` 可能被瞬时覆盖且无压缩。

## 已确认可接受（本轮仅记录，不修）
- **同 uid 预置 `<path>.1` 目录会永久抑制轮转**（oracle 三审）：rename 永远失败 → 只记一次日志、继续写当前文件 → 审计文件可无界增长。不再丢行、不再停写（对比修前），但保留窗口失效；缓解办法是靠外部 logrotate/定时归档该路径，不应指望 ctxmode 自身轮转。
- **rename 移到 `f.Close()` 之前带来的匿名 inode 窗口**（oracle 三审）：若 `path` 这个目录项在 open 与 rename 之间被同 uid 进程换走，本行可能写进已被取消链接的匿名 inode（内容随最后一个 fd 关闭而消失）。与「同 uid 可截断/改写/删除/伪造整条轨迹」属同一已声明不设防的威胁类（README 已写明 append-only 只是 `O_APPEND`，不是防篡改），不额外加固。
- `auditExeCache` 上限 256、只缓存成功、溢出整表清空（O1 闭环）。
- `/dev/null`、`/dev/stdout` 作为目标现在被拒（有意的取舍，会打一条日志；README 已写替代做法）。
- `commands[].label`/`index_label` 有意不截断（要与 KB index 标签对齐），单行体积上界 = 50 条命令 × 标签长 + 64KiB `raw_cmd` 上限。
- 审计路径新增线性开销（`raw_cmd` 命中有 sha256，`execute_file`/`run_task` 的入参描一遍）：字节本来就是调用方发来的，不是放大器，不修。
- schema 稳定性：26 个字段无 `omitempty`、`emit()` 把 nil 归一为 `[]`、固定 key 集断言在 `-race` 下通过（`TestAudit_ExecuteArgvRecord` 逐 key 校验）。
- 文件系统自身停摆（NFS/FUSE/冻结块设备）不受 `O_NONBLOCK` 保护：已知边界，已写进 README。
- `batchSeen` 取的是**配置清单里首个非零码**而非并发时序上最先返回的码 —— 确定性设计，reviewer 已确认不是缺陷，不改。
- **新测试的 `t.Skip` 可见性**（oracle 三审）：本包只能 Linux 构建，`tightenFDLimitToOneExtraOpen` 的 skip 分支（无 RLIMIT_NOFILE / 无 `/proc` / 软限已顶到硬限）近似不可达；但 CI 跑的是 `go test -race ./...` 非 `-v`，包摘要只打 `ok`/`FAIL`、不显示 `SKIP`，极端环境下可能静默少测掉「重开失败仍保记录」这半个不变量。决定：**不加固**（oracle 也倾向不动），仅记录。可选缓解：CI 命令加 `-v`（或在摘要里 grep `--- SKIP`）。

## 提交门禁：commit-msg hook 把删除行/上下文行也扫进凭据检查
- 全局 hook（`/root/.git-hooks/commit-msg`，2026-09-17 经 `/root/.git-templates/hooks` 生效）的 `check_credential_assignments` 只跳过整行恰好等于 `-` 的行（`case "+++"*|"---"*|"@@"*|"-")`，疑似 `"-"*` 笔误），因此**删除行与上下文行会被一起扫描**；模式为 `(password|api_key|secret)[[:space:]]*[:=]+` 后取值长度 ≥6。
- `executor_gate_test.go` 里有一行**合成**敏感夹具（`db_` 前缀 + 一个凭据类词名 + `=` 与占位值拼出来的字符串，正是 hook 想拦的形状），来自 6fb9125（2026-09-12，早于 hook 安装）；该行位于 `finishRunTaskOutput(..., nil)` 改动点的上下文窗口内，无论是上下文还是删除行都会被判为 “hardcoded credential assignment”，即**只要改动这个文件就会被拒**。
- 处理：把 `finishRunTaskOutput` 的 audit 参数改为可变参数（该函数注释本就写明“可无 audit 调用”、`setIndex` 已 nil-safe），于是 4 个测试文件里只为凑参数的 `nil` 改动全部回退、`executor_gate_test.go` 不再进入 diff，hook 全量生效（未用 `COMMIT_MSG_SKIP_DIFF=1`，也未用 `--no-verify`）。
- 更正与收窄（2026-09-30，全局 hook 已修）：`commit-msg` 改为**只扫新增行**——新增 `added_lines_only()`，两个扫描器 `check_secret_patterns` / `check_credential_assignments` 都只吃过滤后的文本；过滤判据最终锚定为 `grep -v '^+++ \(b/\|/dev/null\)'`，即只跳 `git diff` 对新增侧实际输出的两种文件头（`+++ b/<path>`，以及删除文件时的 `+++ /dev/null`），`check_credential_assignments` 的跳过分支同步收窄为 `"+++ b/"*|"+++ /dev/null"*`（原为 `"+++"*`，会把内容以 `++` 开头的新增行整行当文件头跳过；中间过渡的一版 `'^+++ '` 仍会丢内容以 `++ ` 起的行）。因此「删除行/上下文行里的历史夹具拦住本次提交」这类误报不再出现 —— `executor_gate_test.go` 那行夹具就此解开，不必再靠回退参数规避。**残留**：①内容以 `++ ` 开头的新增行【已由 `'^+++ \(b/\|/dev/null\)'` 锚定关闭】，实测这类新增行（赋值式与凭据形状两类写法）现在都会被拒；②**密钥形状的文件名**仍不被扫（普通提交里文件头照旧被正确跳过），**标为低危、本轮不动**。极窄新残留：内容恰为 `++ b/…` 的行会被当文件头误丢；改前缀的环境（`diff.noprefix=true` / `diff.mnemonicPrefix=true`）会让真文件头存活，只会**误报**（多扫一次文件名）不会**漏报**。同一轮也把 `/root/.git-templates/hooks/pre-commit` 的同一判据收窄（`git diff --cached -U0 | grep -v '^+++ \(b/\|/dev/null\)'`；该文件不在 `/root/.git-hooks/` 下，是 templates 目录里的真实文件）。备份：`commit-msg.bak-20260930094017`、`pre-commit.bak-20260930094017`（更早：`commit-msg.bak-20260930082550`、`pre-commit.bak-20260930092955`）。

## 来源
双审第二轮回修。修复包 `/tmp/fix-package-argv-audit-round2-20260930-0045.md`；代码：`audit.go`（R2-F1 轮转路径、R2-S1 路径判据、R2-D3 键名脱敏、R2-D1 注释范围说明、头注释措辞）、`audit_test.go`（新增 `TestAudit_RotationFailureKeepsWriting`、`TestAudit_ReopenAfterRotationFailsKeepsRecord`、`TestAuditEnvKeys`、`TestResolveAuditExeAgreesWithExecutor`；其中轮转两条同族共用辅助函数 `tightenFDLimitToOneExtraOpen`）、`README.md`、`CHANGELOG.md [Unreleased]`。
