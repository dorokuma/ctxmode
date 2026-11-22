---
status: active
---
# 待办池

## 升级 cccc 时的检查项（2026-11-20）

严格只读放行表 `readonlyAllowlist["cccc"]` 的默认拒绝挡不住所有上游变化。升级 `cccc` 时复核：

- **默认拒绝能挡住**：上游新增选项（含写文件/外调选项）——未列名即拒。
- **默认拒绝挡不住**：
  - 已放行选项被赋予写文件或调用外部程序的副作用；
  - `--no-cache` 或 `--no-config` 的语义改变；
  - 工具在不开缓存时也默认写文件或派生子进程。
- **升级时要做**：
  - 重读 `cccc --help`，与放行表逐项比对；
  - 重跑「当前目录的配置文件开启缓存时，带齐 `--no-cache --no-config` 不产生任何文件」的检查。
- **同名工具前提**：本策略只针对 github.com/moznion/cccc 的选项语义；Debian 等发行版另有同名老工具 cccc（C and C++ Code Counter，默认会在当前目录写输出），守卫只认命令名不校验具体二进制。详见 `readonly_allowlist.go` 中 `readonlyAllowlist["cccc"]` 登记处注释。

## `v6.1.1` C 档 Oracle 审计发现的基线既有守卫加固待办（2026-11-22，规划归入 `v6.1.2`）

- **来源**：`release/v6.1.1`（merge `7a35751`）R6 `oracle` 对抗审计（`role-oracle-4e1d2ee3`）检出，均确认属 `main` `9528448` 基线既有边界（非 `v6.1.1` 引入）：
  1. **Python `--` 长选项解析（`role_guards.go:1867-1927, 12426-12528`）**：`unwrapInterpreterInline` Python 分支缺少 `strings.HasPrefix(a, "--")` 前置判断，且 `interpCodeSlots` Python `longValue` 缺 `--check-hash-based-pycs` 空格值处理，导致 `python3 --check-hash-based-pycs=default -c ...` 或空格形式可绕过直接执行、`find -exec` 与 `xargs` 拦截。建议统一收敛至 `interpCodeSlots` 并对未知 `--` 选项采用保守策略。
  2. **`sameStructuralFamily` JavaScript 族标志集不对称（`role_guards.go:2408-2412, 4044-4053`）**：`bun`/`ts-node`/`tsx` 与 `node`/`nodejs` 共享 `heredocInterpLang == "javascript"` 被归为同族，但 `node` 认 `-p`/`--print` 而 `bun`/`ts-node`/`tsx` 不认，导致 `bun -> /usr/bin/node` 软链可用 `-p` 绕过。建议拆族或按解析目标规范化。
  3. **`replTokenInExecSlot` / `xargsFeedsCodeFlag` 多层 `xargs`/`flock`/`watch -x` 穿透（`role_guards.go:4477, 12618`）**：当前仅穿透 `ssh` 与 `peelWrappersAndSbxAliases`，未穿透二层 `xargs`/`flock -c`/`watch -x`，导致 `xargs -I{} flock -x /dev/null -c '{}'`、`find . -exec xargs sh -c {} \;` 可将占位符注入内层代码槽。建议补受限递归下降（计入 `depth` 上限）。
