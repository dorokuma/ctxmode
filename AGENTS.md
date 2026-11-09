# AGENTS.md
档位：L2

## 铁律
1. **构建与测试**：`make check` 是唯一检查入口，覆盖 `gofmt`、`staticcheck`、`go vet`、`go test -race`、`go build` 及有 `node` / CI 环境下的 `integrations/pi/*.test.ts`；本机 zero-node 无 `node` 时仅跳过 Pi 扩展单测，`CI=true` 强制要求 `node`。部署由 agent 直接执行 `./deploy.sh`（编译 → initialize 验证 → 原子替换运行中二进制），**不设人工步骤**。
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
