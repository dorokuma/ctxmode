---
status: active
superseded_by: ""
supersedes: ""
# 可选模块: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg, floodguard, store, executor, router, cli, integrations/pi, githooks, scripts
模块: cli, router, store, ctx_fs, ctx_run, integrations/pi, githooks
---

# 2026-10-21 — agy 宿主适配、全仓审计修复与 C 档门禁闭环记录

## 一句话结论
- 分支 `fix/agy-support-and-audit` 完成 `ctxmode` 对 `agy`（Antigravity CLI）宿主的适配与全仓审计发现的 9 项真实问题修复，并在 C 档提交门禁第 1 轮返修中闭环 SF-1 ~ SF-4 及观察项 C-1 ~ C-5（含用户对 SF-4 `collectSensitiveInodes` 缓存目录跳过策略的明示豁免登记）。

## 背景
- 在 `ctxmode` 接入 `agy`（Antigravity CLI）双宿主（Ultra `/root` 与 Pro `/root/.agy-pro-home`）并进行全仓代码与配置审计时，定位出 9 项真实问题（涵盖 `-workdir` 优先级、`ctx_stats` JSON 审计聚合序列化、`ctx_kb action=purge` FTS5 墓碑与 WAL 回收、`toolExecuteFile` 硬链接扫描复用与大目录跳过、`ctx_bg` 旧动作别名兼容、只读角色 `verifier` 与角色环境注入、敏感凭据文件名黑名单扩展、`ctx_kb.scope` Schema 与宿主文档同步、以及基线测试版本与 `githooks/pre-push` 规则对齐）。
- C 档门禁首轮审查（reviewer + oracle）通过主体实现，同时提出 4 项轻量返修项（SF-1 ~ SF-4）与 5 项观察项（C-1 ~ C-5），须在本笔记中完整登记闭环。

## 决策

### 1. 本次修复的 9 项真实问题摘要
1. **`-workdir` 始终作为 `workdirs[0]` 优先生效（`main.go:123-131`）**：移除「当 `config.yaml` 的 `workdirs` 列表后位已含 `absWd` 时跳过前置插入」的旧分支，改为无条件将 `absWd` 置于切片首位再由后续保序去重循环清理重复项，确保按主工作目录派生的 SQLite 数据库与默认 `.` 路径始终绑定 `-workdir`。
2. **`ctx_stats`（`json=true`）正确序列化 `audit_session` 计数（`stats.go:108-112, 178, 207-214`，`stats_test.go:69-105`）**：将 `auditAgg` 结构体的 `calls`/`output`/`indexed`/`truncated` 字段导出为 `Calls`/`Output`/`Indexed`/`Truncated` 并补齐 `json` 标签，修复 `json.Marshal` 输出空对象 `"audit_session": {}` 的缺陷。
3. **`ctx_kb action=purge`（`scope=project`）重建 FTS5 索引并截断 WAL（`store.go:836-849, 1026-1028`，`purge_test.go:272-297`）**：`Store.PurgeAll` 在事务内对 `documents_fts` 与 `documents_trigram` 执行 `INSERT INTO <tbl>(<tbl>) VALUES('rebuild')` 清除 FTS5 shadow 表墓碑段，`Store.Vacuum` 在 `VACUUM` 后执行 `PRAGMA wal_checkpoint(TRUNCATE)` 将 `-wal` 截断归零，使 `freed_bytes` 真实反映回收空间。
4. **`toolExecuteFile` 复用 `sensitiveInodes` 并跳过重型缓存目录（`main.go:920-959, 1617-1641`）**：单次 `toolExecuteFile` 调用在打开前 `Stat` 与 `O_NOFOLLOW` 打开后 `fdInfo` 两次 `Nlink > 1` 检查间共享同一次 `collectSensitiveInodes()` 结果；`collectSensitiveInodes` 同步跳过 `skipWalkDirs` 及 `.cache`、`.cargo`、`.rustup`、`.npm`、`.pnpm-store`（仍遍历 `.ssh`、`.aws`、`.gnupg`、`.kube`、`.gemini`、`.pi`、`.grok`、`.config` 等凭据目录）。
5. **`ctx_bg` 兼容 `status` 与 `output` 动作别名（`router.go:224-228`，`router_test.go:59-65`）**：`toolCtxBg` 将 `status` 路由至 `list`、将 `output` 路由至 `log`，容错旧版提示词或规则文案中的历史动作名。
6. **只读角色集合纳入 `verifier` 且宿主启动层注入角色环境（`audit.go:637`，`audit_test.go:221`，`integrations/pi/ctxmode.ts:209-234, 410`，`integrations/pi/ctxmode.test.ts:491-501`，`/root/.local/bin/agy:63-70`）**：`readonlyAuditRoles`、`README.md`（第 68 行与第 91 行）及 Pi/agy 启动链路统一纳入 `verifier`；Pi 扩展导出 `resolveRoleEnv` 从 `--name role-<role>-<8hex>` 提取角色，`/root/.local/bin/agy` 从 `--agent` 提取角色。
7. **扩展敏感凭据文件名黑名单（`main.go:1545-1551`，`fs_tools.go:1385-1390`，`executor_gate_test.go:242-247`）**：`isSensitiveCredentialBase` 与 `rgSystemBounded` 新增拦截 `antigravity-oauth-token`、`auth.json`、`logins.json`、`plugin-auth.json`、`hosts.yml`、`hosts.yaml` 及其备份后缀变体（`rgSystemBounded` 中统一使用 `*` 通配后缀，含 SF-3 返修补齐的 `!hosts.yml*` 与 `!hosts.yaml*`）。
8. **`ctx_kb.scope` Schema 描述与 `agy` 宿主文档补齐（`router.go:12, 174`，`instructions.go:46-48`，`README.md:24, 94`）**：为 `ctxKbArgs.Scope` 补充 `jsonschema` 描述，并在代码注释、`instructions.go` 与 `README.md` 中登记 `agy`（Antigravity CLI）MCP 调用约定；`~/.gemini/antigravity-cli/mcp/ctxmode/` 下的 `ctx_kb.json` 与 `instructions.md` 属于 `agy` 从 `/root/.local/bin/ctxmode` 动态拉取生成的运行时缓存（已获用户明示豁免部署前回写现象，在 `./deploy.sh` 原子替换 `/root/.local/bin/ctxmode` 后同步双端缓存持久生效，SF-2）。
9. **基线测试版本与仓内 `githooks/pre-push` 规则对齐（`fixes_test.go:646-648`，`README.md:7`，`githooks/pre-push:72-73`）**：将 `TestVersionAligned` 期望值更新为 `5.1.0`（同时清理 `README.md:7` 多余句号），并在 `githooks/pre-push` 中恢复与 `githooks/commit-msg` 一致的两条密钥前缀正则，使 `TestPrePushHook` 全量通过。

### 2. SF-4 豁免记录（性能与纵深防御折中）
- **背景与折中**：`collectSensitiveInodes`（`main.go:1620-1641`）用于在 `toolExecuteFile` 目标文件 `Nlink > 1` 时扫描工作区敏感文件 inode 以防御硬链接绕过。`collectSensitiveInodes` 按目录 `filepath.Base` 匹配跳过 `skipWalkDirs`（含任意层级的 `dist`/`build`/`target`/`vendor` 等）及 `.cache`/`.cargo`/`.rustup`/`.npm`/`.pnpm-store`。在 `/root` 等超大型宿主工作区下，若遍历 `.cache`、`.cargo`、`.rustup`、`.npm`、`.pnpm-store` 及 `skipWalkDirs` 等重型缓存/构建目录，单次文件树遍历会触发数十万级 `Lstat` 系统调用导致严重延迟或超时。
- **用户明示豁免**：用户已明示豁免保留 `collectSensitiveInodes` 跳过 `skipWalkDirs` + `.cache`/`.cargo`/`.rustup`/`.npm`/`.pnpm-store` 的性能与纵深防御折中——直接按敏感路径名访问上述目录内的敏感文件仍受 `isSensitiveFilePath` 拦截，且 `.ssh`、`.aws`、`.gnupg`、`.kube`、`.gemini`、`.pi`、`.grok`、`.config` 等核心凭据目录仍全量纳入 inode 扫描；该边界已在 `README.md` 的 `## Security model — NOT a sandbox` 章节明文标注。同时，`~/.gemini/antigravity-cli/mcp/ctxmode/` 下的 `ctx_kb.json` 与 `instructions.md` 属于 `agy` 从 `/root/.local/bin/ctxmode` 动态拉取生成的运行时缓存（已获用户明示豁免部署前回写现象，在 `./deploy.sh` 原子替换 `/root/.local/bin/ctxmode` 后同步双端缓存持久生效）。

### 3. C-1 ~ C-5 观察项闭环记录
- **(a) C-1（`/root/.local/bin/agy` 不覆盖外部显式环境）**：`/root/.local/bin/agy`（第 63–70 行）已由无条件赋值改为 `: "${CTXMODE_ROLE:=$ROLE}"` + `export CTXMODE_ROLE`，且匹配只读角色时同样改为 `: "${CTXMODE_READONLY:=1}"` + `export CTXMODE_READONLY`，与 Pi 侧 `resolveRoleEnv`「仅在外部未显式指定时赋默认值」的语义完全一致。
- **(b) C-2（`ctx_bg` 的 `status`/`output` 别名不写入公开 Schema 枚举）**：`router.go` 中 `toolCtxBg` 支持 `status`（映射 `list`）与 `output`（映射 `log`）仅作为向后兼容旧提示词的运行时容错别名，故意不写入 `ctxBgArgs.Action` 的公开 `jsonschema` 枚举或 `README.md` 工具表，以避免引导模型继续生成已废弃的旧动作词。
- **(c) C-3（`ctxmode.test.ts` 拆分独立 `test()`）**：`integrations/pi/ctxmode.test.ts` 已将原附着在 `timeoutForTool` 用例末尾的 `resolveRoleEnv` 断言拆出为独立用例 `test("扩展层：resolveRoleEnv 从 --name 提取角色且不覆盖显式环境变量", ...)`（用例总数由 26 增至 27）。
- **(d) C-4（只读角色集合三处同步维护检查点）**：只读角色集合（`scout`、`planner`、`researcher`、`reviewer`、`oracle`、`verifier`）当前在三处定义维护：
  1. Go 服务端审计判定：`audit.go` 中的 `readonlyAuditRoles`；
  2. Pi 扩展启动器：`integrations/pi/ctxmode.ts` 中的 `READONLY_ROLES`；
  3. agy 包装脚本：`/root/.local/bin/agy` 中的 `case "$ROLE" in scout|planner|researcher|reviewer|oracle|verifier)`。
  后续新增或调整只读角色时，须同步核对上述三处检查点及 `README.md` 文档。
- **(e) C-5（`/root/workspace/PROJECTS.md` 部署描述对齐）**：`/root/workspace/PROJECTS.md` 第 17 行已更新为 `部署脚本为 ./deploy.sh（编译 → initialize 验证 → 原子替换运行中二进制）`，与 `ctxmode/AGENTS.md` 铁律第 1 条完全一致；该文件属工作区顶层无版本控制文档，不在 `ctxmode` 仓库 git 跟踪范围内。

## 被放弃的方案（必填）
- **方案 A：在 `collectSensitiveInodes` 中全量扫描 `.cache`/`.cargo`/`.npm` 等重型缓存目录**。否决：在 `/root` 等宿主工作区下包含海量构建缓存文件，全量遍历会造成 `toolExecuteFile` 在处理 `Nlink > 1` 文件时严重卡顿；保留缓存目录跳过并在 `README.md` 与本笔记中记录纵深防御边界（且已获用户明示豁免）是更合理的工程折中。
- **方案 B：把 `ctx_bg` 的兼容别名 `status`/`output` 写进公开 JSON Schema 描述**。否决：公开 Schema 是模型选择参数的首要依据，写入旧词会反向鼓励模型使用非标准动作名，背离「仅作运行时容错」的初衷。
- **方案 C：在 `/root/.local/bin/agy` 中强制覆盖调用方传入的 `CTXMODE_ROLE`/`CTXMODE_READONLY`**。否决：破坏调用方显式指定环境变量的优先级，且与 Pi 侧 `resolveRoleEnv` 行为不一致。

## 来源
- 分支：`fix/agy-support-and-audit`
- 任务标记：`[MARK-WRK-CTXMODE-RWK1-20261021]`
- 涉及文件：`main.go`、`fs_tools.go`、`audit.go`、`router.go`、`stats.go`、`store.go`、`instructions.go`、`githooks/pre-push`、`integrations/pi/ctxmode.ts`、`integrations/pi/ctxmode.test.ts`、`README.md`、`CHANGELOG.md`，以及仓外宿主文件 `/root/.local/bin/agy`、`/root/.gemini/antigravity-cli/mcp/ctxmode/ctx_kb.json`、`/root/.agy-pro-home/.gemini/antigravity-cli/mcp/ctxmode/ctx_kb.json`、`/root/.gemini/antigravity-cli/mcp/ctxmode/instructions.md`、`/root/.agy-pro-home/.gemini/antigravity-cli/mcp/ctxmode/instructions.md`、`/root/workspace/PROJECTS.md`。
