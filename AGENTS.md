# AGENTS.md

## 铁律
1. **构建与测试**：编译使用 `go build -o ctxmode .`（`./deploy.sh` 会热替换运行中二进制，属部署操作须人工执行）；Go 测试运行 `go test -race ./...`；Pi 扩展测试运行 `node --experimental-strip-types --test integrations/pi/*.test.ts`。
2. **零 Node 依赖**：核心代码为纯 Go 实现，禁止引入 NPM/NodeJS 运行时依赖。
3. **变更登记**：任何改动须在 `CHANGELOG.md` 的 `[Unreleased]` 段落登记。
4. **Hooks 门禁**：commit 须过当前生效的全局 commit-msg hook（生效路径 `/root/.git-templates/hooks`，实现在 `/root/.git-hooks/commit-msg`）：Conventional Commits 类型白名单、主题 ≤72 字、冒号后恰好一空格、禁过程噪声词与密钥泄露，禁止绕过 hook；仓内 `githooks/` 为可选增强、当前未接管 hooksPath。
5. **安全隔离与状态**：严禁提交 `.db`/`.db-wal`/`bin/` 等产物；敏感环境变量与未授信路径按安全模型隔离。

## 索引
- 现状与架构文档：[README.md](README.md)
- 架构决策与排坑记录：[.agents/notes/](.agents/notes/)
- 写完笔记刷新索引：scripts/notes-index.sh（本地生成 INDEX.md，不入 git）

## 关联仓库
- `codegraph-go`：同为 Pi 与 MCP 工具链组件
- `prism`：同属 AI 基础设施
