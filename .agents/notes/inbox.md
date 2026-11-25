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
