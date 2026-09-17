# AGENTS.md

## 铁律
1. **构建与测试**：编译使用 `go build -o ctxmode .`（`./deploy.sh` 会热替换运行中二进制，属部署操作须人工执行）；Go 测试运行 `go test -race ./...`；Pi 扩展测试运行 `node --experimental-strip-types --test integrations/pi/*.test.ts`。
2. **零 Node 依赖**：核心代码为纯 Go 实现，禁止引入 NPM/NodeJS 运行时依赖。
3. **变更登记**：任何改动须在 `CHANGELOG.md` 的 `[Unreleased]` 段落登记。
4. **Hooks 门禁**：必须遵守 commit 检查约束（统一校验器 `/root/.git-hooks/commit-msg`）。提交信息须符合 `type: 主题` 或 `type(scope): 主题` 格式，type 白名单为 `feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert`，scope 可选（小写 `[a-z0-9._-]+`），主题非空且 ≤72 字符（允许中英文混合；Merge/Revert/fixup!/squash! 豁免；保留密钥扫描与过程噪声词拦截），禁止私自修改或绕过。
5. **安全隔离与状态**：严禁提交 `.db`/`.db-wal`/`bin/` 等产物；敏感环境变量与未授信路径按安全模型隔离。

## 索引
- 现状与架构文档：[README.md](README.md)
- 架构决策与排坑记录：[.agents/notes/](.agents/notes/)
- 写完笔记刷新索引：scripts/notes-index.sh（本地生成 INDEX.md，不入 git）

## 关联仓库
- `codegraph-go`：同为 Pi 与 MCP 工具链组件
- `prism`：同属 AI 基础设施
