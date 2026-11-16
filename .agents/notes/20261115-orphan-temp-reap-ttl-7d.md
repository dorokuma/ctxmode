---
status: active
superseded_by: ""
supersedes: ""
模块: "executor"
---

# 孤儿 ctxmode_* 临时文件清扫阈值升至 7 天与审查观察项归档

## 一句话结论
`init()` 期孤儿 `ctxmode_*` 临时文件清扫阈值从 `24 * time.Hour` 提升至 `orphanTempReapTTL = 7 * 24 * time.Hour`（`executor.go`），1–6 天的残留不再被误判为死进程孤儿过早删除；清扫主体原样迁入 `sweepOrphanTempFiles` 以便隔离 `TMPDIR` 下单测行为边界。

## 背景
`init()` 在包加载时清扫 `os.TempDir()` 中未被本进程 `protectTemp` 保护的 `ctxmode_*` 文件，原阈值为 `mtime > 24h`。该窗口对「仅被挂起或长寿命进程持有的临时文件」过窄：1–6 天的文件会被当作 `SIGKILL` 等异常终止进程的孤儿残留删掉。`sweepOrphanTempFiles` 抽成独立函数后，可在测试中 `t.Setenv("TMPDIR", t.TempDir())` 隔离验证保留/回收边界而不触碰真实 `/tmp`。

## 决策
1. 新增包级常量 `orphanTempReapTTL = 7 * 24 * time.Hour`，`init()` 改为薄封装调用 `sweepOrphanTempFiles()`；原清扫循环体逐字迁移，仅把字面量 `24*time.Hour` 换成常量，行为除阈值外零变化。
2. `7d` 取值理由：长到足以覆盖被挂起/长运行进程持有的临时文件，同时与宿主典型 `/etc/tmpfiles.d/tmp.conf` `7d` 策略同界，不超出系统级清理语义。
3. 回归测试 `TestSweepOrphanTempFiles_TTLBoundary`（`executor_reap_test.go`）在隔离 `TMPDIR` 下断言：6 天与 2 天（`.log`）文件保留（旧 24h 阈值下会被删）、`7d+10m` 与 30 天文件回收、`protectTemp` 保护文件过期仍保留、非 `ctxmode_*` 前缀文件不被触碰。

## 被放弃的方案（必填）
- **仅靠环境变量运行时覆盖而不改内置默认常量**：否决。MCP 子进程环境未必全链路透传自定义环境变量，内置默认 `7 * 24 * time.Hour` 才能根治 1–6 天文件早删。
- **在测试中写 `orphanTempReapTTL == 7*24*time.Hour` 同义反复断言**：否决。常量自证断言无行为覆盖价值，改用 `6d` 保留 / `7d+10m` 回收的行为边界测试锁住真实语义。

## C 档审查观察项归档（O1–O5）
本次 `oracle` 终审输出 5 条非阻断 `consider` 观察项，经全仓 `.agents/notes/*.md` 检索核实 5 个标签均为本仓首次记录（1/2），逐条归档：

1. **O1 `[pattern:historical-note-superseded-ttl]`（1/2）**：`20261109-ctxmode-bg-log-collision-closure.md` 中旧 `>24h` 清扫窗口表述属当时历史事实，保留原文（v5.3.1 验证期观察分片旧文同述，该分片已核销清理，Git 历史留底）；由本笔记记录已于 `fix/temp-reap-ttl-7d` 提升至 `orphanTempReapTTL = 7 * 24 * time.Hour`。旧笔记「`defaultBackgroundMaxAge = 1 * time.Hour` 防跨实例误删」结论依然成立，安全余量扩大 7 倍。
2. **O2 `[pattern:tmpfs-orphan-log-footprint]`（1/2）**：极端情况下单实例满载 `maxBackgroundProcs = 16` 个打满 `bgLogMaxBytes = 16MB` 的后台任务遭 `SIGKILL` 跳过 `shutdownBackground` 时，最多约 256MB 残留日志在 `/tmp`（`tmpfs`）保留至 7 天；重启即清空且与宿主 `/etc/tmpfiles.d/tmp.conf` `7d` 策略同界，可接受。
3. **O3 `[pattern:uncleaned-tmpdir-protect-key]`（1/2）**：当 `TMPDIR` 含重复斜杠（如 `//tmp`）时 `os.CreateTemp` 返回未清洗路径，与 `sweepOrphanTempFiles` 经 `filepath.Join` 清洗后的键字符串潜在不等；属存量行为，且因仓内活后台任务寿命 `<=1h`（`defaultBackgroundMaxAge`）远小于 7 天清扫闸门，实际不可达。
4. **O4 `[pattern:silent-startup-temp-sweep]`（1/2）**：`sweepOrphanTempFiles` 对 `ReadDir` / `Info` / `Remove` 错误静默忽略无日志，属存量设计（避免在 MCP stdio 启动期污染协议流或刷屏 stderr）。
5. **O5 `[pattern:interval-bound-test-without-const-tautology]`（1/2）**：`TestSweepOrphanTempFiles_TTLBoundary` 以 `6d` 保留与 `7d+10m` 回收锁住行为边界，不写常量自证同义断言，符合最小测试纪律。

另记：`oracle` 顺带提及的 `scripts/notes-index.sh:10` 临时文件清理经 `reviewer` 核实第 11 行已有 `trap 'rm -f "$TMP"' EXIT`，归 `refuted-with-evidence`。

## 来源
- 代码：`executor.go`（`orphanTempReapTTL`、`init()`、`sweepOrphanTempFiles`）。
- 回归：`executor_reap_test.go` `TestSweepOrphanTempFiles_TTLBoundary`。
- 变更登记：`CHANGELOG.md` `[Unreleased]` → `Changed`。
- 关联笔记：`20261109-ctxmode-bg-log-collision-closure.md`（旧 `>24h` 表述，历史原文保留）。
- 审查：`fix/temp-reap-ttl-7d` 分支 `oracle` 终审 O1–O5 观察项、`reviewer` 对 `scripts/notes-index.sh` trap 的核实。
