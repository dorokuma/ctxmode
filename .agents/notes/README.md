# 架构与决策笔记

本目录记录仓库的重要技术决策、架构演进及踩坑记录。

## 命名规则
- 文件命名格式为 `YYYYMMDD-slug.md`（例如 `20260916-sqlite-schema-migration.md`）。
- 新建笔记请参考模板：[_template.md](_template.md)。

## 何时必须写笔记（六条触发）
满足任一条件即须写笔记，而非六条全部满足：
1. SQLite schema、索引格式、配置文件格式、对外 API 契约变更
2. 跨两个以上模块或跨仓库
3. 否决了看似更好的方案
4. 临时降级或 workaround 或特判
5. 与 upstream 的故意分歧
6. 性能取舍参数的取值原因

## 何时不用写
- 版本号 bump
- 文案样式调整
- 行为不变的单文件 bug 修复
- 依赖小版本升级
- 纯补测试

触发优先于豁免：单文件 workaround、降级、特判即使只是单文件修改也必须记笔记。

## 维护规范
- **只加 superseded 链接、不改写旧结论**：当旧决策被新决策取代时，仅在旧笔记的 frontmatter 中修改 `status: superseded` 并填入 `superseded_by: <新笔记文件名>`，在新笔记中注明 `supersedes: <旧笔记文件名>`，禁止篡改或覆盖旧笔记的历史结论与记录。
