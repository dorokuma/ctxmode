---
status: active
superseded_by: ""
supersedes: ""
模块: "executor"
---

# ctx_bg 后台任务日志跨实例同名碰撞修复闭环（[pattern:ctxmode-bg-log-collision]）

## 一句话结论
`registerBackground` 固定重命名为 `ctxmode_bg_<id>.log`（`bg-1` 起算）导致多实例共享 `/tmp` 时互相覆盖/删除活动日志；现改为实例隔离命名 `ctxmode_bg_<pid>_<rand-hex>_<id>.log`，缺陷闭环。

## 背景
`executor.go` `runCmd` 先用 `os.CreateTemp(os.TempDir(), "ctxmode_bg_*.log")` 生成进程间唯一的临时日志，但 `registerBackground`（原 `executor.go:263`）随后 `os.Rename` 到固定 `filepath.Join(os.TempDir(), "ctxmode_bg_"+id+".log")`。由于 `bgSeq` 每进程从 1 起算，同一主机上多个 `ctxmode` 进程并发跑后台任务、或宿主 `ctxmode` 后台任务内跑 `go test`（内层测试自身也拉起 `bg-1` 并共享 `/tmp`）时，内层实例会覆盖并清理外层正在使用的 `/tmp/ctxmode_bg_bg-1.log`。该缺陷在 v5.3.1 验证期发现并登记为 `[pattern:ctxmode-bg-log-collision]`（见 `20261109-v531-hc-allowlist-followup.md` 第 4 项）。

## 决策
1. 新增包级变量 `bgInstanceID = newBGInstanceID()`：`fmt.Sprintf("%d_%x", os.Getpid(), buf)`，`crypto/rand` 读 4 字节编码为 8 位 hex；`rand.Read` 失败时回退 `time.Now().UnixNano()`（16 位 hex，仍含 PID，隔离性不丢）。
2. `registerBackground` 中 `finalPath` 改为 `filepath.Join(os.TempDir(), fmt.Sprintf("%s%s_%s.log", bgTempPrefix, bgInstanceID, id))`，即 `/tmp/ctxmode_bg_<pid>_<hex>_bg-1.log`。
3. `init()` 的 >24h 孤儿清扫无需改动：新文件名仍以 `ctxmode_` 前缀开头，且各实例的 `unprotectTemp`/`os.Remove` 只触碰自身 `bgInstanceID` 的文件，不会误删其它存活实例日志。
4. 回归测试 `TestBackground_LogPathInstanceScoped`（`executor_test.go`，含签名共 29 行 / 函数体 28 行，≤35 行预算）：断言 `LogPath` 位于 `os.TempDir()`、base 名以 `bgTempPrefix+bgInstanceID+"_"` 开头、以 `"_"+id+".log"` 结尾、且不等于裸 `ctxmode_bg_bg-1.log`。

## 被放弃的方案（必填）
- **保留 `CreateTemp` 随机名、不再 rename**：否决。固定 `bg-<id>` 后缀便于按 job id 定位日志，且 `CreateTemp` 随机段不可读；实例 token 方案在保留可读 id 的同时消除碰撞。
- **用 `os.MkdirTemp` 每实例目录**：否决。额外目录生命周期与 `init()` 清扫语义更复杂，单文件前缀方案改动最小。
- **`init()` 清扫按实例前缀过滤**：否决。`init()` 只在文件 >24h 且未受本进程保护时删除，属于死进程遗留文件清理；按实例过滤反而会让旧实例垃圾永不被收。

## 门禁观察项分诊（Oracle C1–C3）
- **C1 — `init()` >24h 跨实例清扫窗口** `[pattern:ctxmode-bg-log-collision]`：`refuted-with-evidence`。`executor.go:30` 强制 `defaultBackgroundMaxAge = 1 * time.Hour`（由 `backgroundReaperLoop` 定期回收）且 `maxBackgroundWaitMs = 3600000`（1 小时），合法后台任务不可能存活超过 1 小时；`mtime > 24h` 的 `ctxmode_bg_*` 必为已终止进程的孤儿残留，不存在跨实例误删活跃日志路径。
- **C2 — `newBGInstanceID` 回退分支 hex 宽度与笔记行数措辞** `[pattern:doc-minor-wording]`：`confirmed（consider，已在本笔记同步修正）`。正常 `crypto/rand` 分支输出 `<pid>_<8-hex>`，`UnixNano()` 回退分支输出 `<pid>_<16-hex>`，两者均满足进程级唯一性；单测函数含签名共 29 行（函数体 28 行），已在上文决策段对齐表述。
- **C3 — `os.Rename` 失败回退保留 `os.CreateTemp` 随机路径** `[pattern:graceful-degradation-fallback]`：`confirmed（consider，保留现状）`。若 `os.Rename` 异常失败，`e.LogPath` 保持 `os.CreateTemp` 生成的唯一路径 `ctxmode_bg_<random>.log`，同样具备跨进程无碰撞与生命周期自动清理保证，无需额外改动。

## 来源
- 缺陷登记：`.agents/notes/20261109-v531-hc-allowlist-followup.md`（`[pattern:ctxmode-bg-log-collision]`）。
- 代码：`executor.go`（`bgInstanceID`/`newBGInstanceID`、`registerBackground` finalPath、`runCmd` CreateTemp、`init()` 清扫）。
- 回归：`executor_test.go` `TestBackground_LogPathInstanceScoped`。
