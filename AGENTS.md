# AGENTS.md
档位：L2

## 铁律
1. **构建与测试**：`make check` 是唯一检查入口，覆盖 `gofmt`、`staticcheck`（本地版本与 CI 一致：`honnef.co/go/tools/cmd/staticcheck@2025.1.1`）、`go vet`、`go build` 及有 `node` / CI 环境下的 `integrations/pi/*.test.ts`；其中 `go test -race` 经 `./scripts/ns-hc-gotest.sh` 在外层 mount/PID/net 命名空间内执行（测试二进制绑定只读 hc/herdr-core/sbx stand-in、清能力并降权），裸 `go test` 会被 `TestMain` 的外层隔离门禁以 exit 125 拒绝；本机 zero-node 无 `node` 时仅跳过 Pi 扩展单测，`CI=true` 强制要求 `node`。部署由 agent 直接执行 `./deploy.sh`（编译 → initialize 验证 → 原子替换运行中二进制），**不设人工步骤**。
2. **零 Node 依赖**：核心代码为纯 Go 实现，禁止引入 NPM/NodeJS 运行时依赖。
3. **变更登记**：任何改动须在 `CHANGELOG.md` 的 `[Unreleased]` 段落登记。
4. **提交与门禁**：提交、分支、门禁与收口按 `/root/.pig/agent/SYSTEM.md` §4（维护者本机由全局 `/root/.git-hooks` 执行提交扫描；仓内 `githooks/` 为可选增强、未接管 `hooksPath`）。
5. **安全隔离与状态**：严禁提交 `.db`/`.db-wal`/`bin/` 等产物；敏感环境变量与未授信路径按安全模型隔离。

## 索引
- 现状与架构文档：[README.md](README.md)
- 架构决策与排坑记录：[.agents/notes/](.agents/notes/)
- 写完笔记刷新索引：scripts/notes-index.sh（本地生成 INDEX.md，不入 git）

## 关联仓库
- `codegraph-go`：同为 Pi 与 MCP 工具链组件
- `dispatch-agent`：无 Go 模块依赖，但下列 4 项硬编码协议不变量两仓各自实现、必须锁步同步（任一变更须同批改对侧并复核本笔记）：
  1. 报告根目录 `/tmp/herdr-role-reports`
  2. 父终端地址形状 `^t[0-9a-z]+$`（本仓 `hcSendAddrOK`，对端 `config.ReportAddrRe`）
  3. 角色侧唯一放行拼写 `dispatch-report <t-addr>`；`--flush` 仅限派发器外层调用（本仓 MCP 工具 `ctx_report` 内部委托同一 `dispatch-report <t-addr>` 子进程，非新协议入口）
  4. 回执通知格式 `报告已写入 path=<abs> bytes=<n> sha256=<hex>`；`CTXMODE_EXTRA_WORKDIRS` 空串视为未设置
## Release Policy / 发布规范

本节是本仓库发版的强制规则。仓库已有的更具体版本、构建或发布渠道规则优先，但不得降低以下底线。

1. **版本与变更记录**：遵循 Semantic Versioning，正式版本使用 `vX.Y.Z`。破坏性变更升 MAJOR，新功能升 MINOR，兼容修复升 PATCH。任何用户可见行为、运行时/API/包接口、依赖、安全性或分发产物变化，都必须在同一发版提交中更新版本元数据并写入 CHANGELOG/Release Notes；纯文档且不产生可分发产物时可免升版，但须在规则或 Release Notes 中明确说明。
2. **发布门禁**：发版前工作树必须干净，版本号、CHANGELOG 与发布说明必须一致；必须运行仓库规定的测试、构建、lint、类型检查及必要的安全检查，且全部通过。若仓库提供 `release-check`、`make release-check`、版本检查脚本或同等门禁，必须原样通过，不得绕过。
3. **发布顺序**：先提交并推送发布提交到目标分支 → 在该发布提交上创建 Tag（默认使用带注解的 `git tag -a vX.Y.Z -m "vX.Y.Z"`；仅当现有发布工具明确要求轻量 Tag 时可例外）→ 推送 Tag → 创建**非草稿** GitHub Release → 再发布 npm、PyPI、容器镜像等关联分发渠道。不得只推分支或只打 Tag 就宣称发版完成。
4. **GitHub Release 产物**：标题使用 `vX.Y.Z`，正文必须包含实质性变更摘要、升级/破坏性变更说明及验证结果；二进制、安装包、插件包等适用产物必须作为 Release assets 上传，并提供校验和（如适用）。**Tag 本身不等于完整发版，必须同时存在可访问的 GitHub Release。**
5. **发布后验收**：至少执行并确认 `git ls-remote --tags origin refs/tags/vX.Y.Z`、Tag 指向发布提交、`gh release view vX.Y.Z` 可访问且不是 draft；若发布到包仓库/镜像仓库，还必须核验对应版本、摘要或安装链接可用。
6. **不可变性**：已发布 Tag 不得复用、移动或删除，不得 force push 发布分支或 Tag，不得从未提交、未经测试或未通过门禁的树发布。发布后发现问题须通过新的 patch 版本修复，禁止覆盖历史 Release。
7. **例外必须显式化**：归档、已停用、被替代、仅文档或无可分发产物的仓库，必须在项目规则中明确写出“不发新版本”及历史 Tag/Release 的处置方式；例外不能用于绕过上述发布闭环。

### Repository-specific release contract

- 本仓的具体检查命令以 README、CONTRIBUTING、AGENTS 既有条款及 CI 配置为准。
