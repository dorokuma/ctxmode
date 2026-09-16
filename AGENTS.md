# AGENTS.md

## 铁律
1. **构建与测试**：编译使用 `go build -o ctxmode .`（`./deploy.sh` 会热替换运行中二进制，属部署操作须人工执行）；Go 测试运行 `go test ./...`；Pi 扩展测试运行 `node --experimental-strip-types --test integrations/pi/*.test.ts`。
2. **零 Node 依赖**：核心代码为纯 Go 实现，禁止引入 NPM/NodeJS 运行时依赖。
3. **变更登记**：任何改动须在 `CHANGELOG.md` 的 `[Unreleased]` 段落登记。
4. **Hooks 门禁**：必须遵守 `githooks/` 约束，禁止私自修改或绕过 commit 检查（阻断非英文 commit、噪声词与密钥泄露）。
5. **安全隔离与状态**：严禁提交 `.db`/`.db-wal`/`bin/` 等产物；敏感环境变量与未授信路径按安全模型隔离。

## 索引
- 现状与架构文档：[README.md](README.md)
- 架构决策与排坑记录：[.agents/notes/](.agents/notes/)

## 关联仓库
- `codegraph-go`：同为 Pi 与 MCP 工具链组件
- `prism`：同属 AI 基础设施
