---
status: active
superseded_by: ""
supersedes: ""
模块: integrations/pi
---

# Pi 扩展同步提炼为 integrations/pi/install.sh：契约对齐 codegraph-go，失败保持硬失败

## 一句话结论
- deploy.sh 里内联的 Pi 扩展同步块提炼为独立脚本 `integrations/pi/install.sh`（md5 幂等、md5sum 预检、HOME/目标形态显式校验、不吞 stderr、md5 取空即败、结尾 /reload 提示），deploy.sh 改为调用它；契约与 codegraph-go 样板逐条对齐，失败策略沿用本仓既有约定——硬失败，不照抄 codegraph-go 的非阻断 WARN。

## 背景
- 本仓 deploy.sh 的 Pi 扩展同步是内联块：`install -m 644` 无条件重写——即使部署副本与仓库 md5 一致也动 mtime；没有 `command -v md5sum` 预检；没有 HOME 未设置、目标为目录、目标非绝对路径等显式校验；缺源时 exit 1 但其它失败形态可读性差。
- 样板（已读）：`/root/workspace/codegraph-go/integrations/pi/install.sh`、其 `deploy.sh:53-68`、`:410`、`:426-432`，以及 `.agents/notes/20261003-pi-ext-deploy-sync.md`——后者记录了 R2 双审实测出的静默失败形态清单（PATH 无 md5sum 时静默 exit 127 且输出全空；md5 取空时带空值走进 unchanged 分支静默跳过同步等），本次契约即按该清单逐条防住。
- 现状数据（本次任务开始时实测）：仓库源与部署副本 md5 均为 `516d5f127f9ad250a8589acfb2713bed`，但部署副本 mtime（2026-10-03 23:37）晚于源（2026-09-24 11:13）——正是无条件重写的痕迹。

## 决策
- 提炼 `integrations/pi/install.sh`（可单独执行验证），契约：目标 md5 与源一致 → 报告 unchanged 且不重写（mtime 不变）；`command -v md5sum` 预检失败即显式 FAILED；HOME 未设置/为空给可操作提示（而非 set -u 的「未绑定的变量」）；DEST 必须是绝对路径；DEST 为已存在目录时显式 FAILED（不静默补全文件名、不静默拷进目录）；`md5_of` 不吞 md5sum 的 stderr 与退出码；源/目标 md5 取空一律 FAILED；结尾提示 Pi 需 /reload 或新会话生效。
- 路径解析与覆盖变量沿用 deploy.sh 既有语义：`SRC=$ROOT/integrations/pi/ctxmode.ts`，`DEST=${PI_CTXMODE_EXT:-$HOME/.pi/agent/extensions/ctxmode.ts}`，既有调用方式不变（不引入 codegraph-go 的 PI_EXT_DEST 命名）。
- deploy.sh 失败策略：**硬失败**。依据：本仓既有约定就是硬失败——原内联块缺源时 `exit 1`，且 deploy.sh 是 `set -euo pipefail`，`install` 失败同样会让整套部署中止；ctxmode 的定位是「Pi 无 MCP：工具来自扩展」，扩展没同步上则二进制换了也拿不到工具，静默 WARN 会让「部署成功」名不副实。codegraph-go 的非阻断 WARN 是为「不影响二进制/daemon 主体」设计的另一套语义，两仓不同，不照抄。
- 文档按本仓惯例登记：`integrations/pi/README.md` 安装方式段同步更新、`PI_CTXMODE_EXT` 补入 Env knobs；`CHANGELOG.md [Unreleased]` 新增 Changed 条目；根 `README.md` Deployment 段补一句同步机制说明。

## 被放弃的方案（必填）
- 方案 A：照抄 codegraph-go 的非阻断 WARN（同步失败仅告警、退出码保持 0）。否决：本仓 deploy.sh 对 Pi 同步的既有约定是硬失败（缺源 exit 1 + set -e），且扩展是 ctxmode 在 Pi 里的唯一工具面——静默 WARN 等于允许「部署成功但无工具可用」。两仓部署语义不同。
- 方案 B：保持内联块、只在其内部加校验。否决：失去可单独触发验证的能力（codegraph-go R2 双审的结论即该步骤必须能单独触发）；独立脚本与本仓 `scripts/notes-index.sh` 等小脚本惯例一致。
- 方案 C：`PI_CTXMODE_EXT` 指向目录时自动补全为 `<dir>/ctxmode.ts`。否决：静默改写用户给的路径是另一种歧义（显式失败优于魔法），且 `install` 拷进目录的行为正是要消灭的静默形态。
- 方案 D：覆盖变量改名对齐 codegraph-go 的 `PI_EXT_DEST`。否决：口径要求不破坏既有调用方式，`PI_CTXMODE_EXT` 是 deploy.sh 现有变量名。

## 来源
- 分支 `chore/pi-ext-sync`（未提交，用户口径：带行为改动先开分支、提交前双审，本任务不 commit）。样板：codegraph-go `integrations/pi/install.sh`、`deploy.sh` 53-68/410/426-432、`.agents/notes/20261003-pi-ext-deploy-sync.md`。
- 实测（命令与输出见任务回报）：unchanged 路径 md5 `516d5f127f9ad250a8589acfb2713bed` 且目标 mtime 不变；`PI_CTXMODE_EXT` 指向临时路径冷安装报 changed 且 md5 一致；三条失败路径（PATH 无 md5sum、HOME 未设置、DEST 为目录）均显式报错并非零退出；`bash -n` 两脚本通过；未执行 ctxmode 的 deploy.sh（热替换属部署操作）。

## 遗留清单（不阻断本次，均不在本仓库可管范围）
- 同一部署目录 `~/.pi/agent/extensions/` 下的其它自研扩展各踩同一颗雷（「二进制有部署、扩展靠手工」的漂移），均不在本仓库可管范围：
  1. `cache-guardian.ts` —— 该问题已在它自己仓库处理；
  2. `prism.ts` / `auto-continue.ts` / `no-tables.ts` —— 整机无第二份源码（部署目录里就是唯一副本），没有可同步的仓库源；
  3. `herdsman-pi.ts` —— 转发壳，真身走 npm，同步机制归属 npm 包侧；
  4. `herdr-agent-state.ts` —— 由 herdr 自身安装器管理，同步机制在 herdr。
- 结论：这些扩展的同步机制需各自归属仓库补齐（或确认真身管理方已覆盖），本仓库的 install.sh 只管 `ctxmode.ts`。

## 遗留清单 · 双审观察项（仅登记，本轮不实现）

本轮（双审后收尾）已完成项：`install.sh` 目标解析顺序倒挂已修——优先采纳显式 `PI_CTXMODE_EXT`，仅在未指定时才校验 HOME 并回落默认路径（修复前 `env -u HOME PI_CTXMODE_EXT=…` 也被「HOME is not set」拦下，与报错文案自相矛盾）；目录目标文案统一为「(须指定文件名而非目录本体)」，与其余副本同口径。以下为两关共同指出、仅登记的观察项：

- **`deploy.sh` 硬失败时的状态歧义**：`install.sh` 失败时 `deploy.sh` 报「部署中止」，但二进制已在此前完成原子替换——真实状态是「二进制已部署成功、仅扩展未同步」。审读建议把该错误信息补一句「二进制部署已完成，仅扩展未同步」，或留待后续统一处理；本轮不动 `deploy.sh` 文案。
- **扩展同步在二进制替换之后的固有顺序**：同步发生在 `mv` 换二进制之后，若未来要把原子性扩到「二进制 + 扩展」粒度，须先同步扩展并验证、再换二进制；当前顺序做不到，仅登记。
- **未来联邦中枢（`/root/workspace/pi-extensions`）接口登记**：本脚本输出是人类可读文本，退出码 0/1 不区分「本次同步了」与「本就无需同步」，中枢若要消费须自行判定（或后续约定机器可读输出/退出码）；覆盖变量名是仓级的（本仓 `PI_CTXMODE_EXT`、codegraph-go 用 `PI_EXT_DEST`），中枢级联须按仓适配，不能假定统一变量名。
- **备查**：本仓改动**未执行** `deploy.sh`（PROJECTS.md 明令热替换属人工操作），真实部署路径上的扩展同步仍待人工部署时验证。
- **新增观察项（oracle 第二轮提出）**：`install.sh` 的 `changed` 分支在 `install` 成功后不复验目标 md5——极端情形（写坏盘）会报成功；**此条与样板 `codegraph-go` 同源，属模板级问题，若修应四仓同修，不在本仓单改**。
- **对 `deploy.sh:175-178` 文案歧义的处置决定**：双审（reviewer 与 oracle）都指出「扩展同步失败时报『部署中止』，但此时二进制已替换完成」，oracle 建议改文案、reviewer 建议保持现状；**本轮处置＝保持现状、仅登记**（理由：改动已过双审，post-review 的代码改动会使被提交产物与已审产物不一致，且该条为非阻断 consider），随下次 `deploy.sh` 变更统一处理。
