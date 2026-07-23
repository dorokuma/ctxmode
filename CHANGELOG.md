# Changelog

版本规则：[语义化版本](https://semver.org/) (MAJOR.MINOR.PATCH)
- MAJOR：不兼容的 API 破坏
- MINOR：新功能，向后兼容
- PATCH：bug 修复，向后兼容

## [1.1.0] - 2026-07-23

### MINOR（新功能）
- YAML 配置文件支持（`-config` flag > `$CTXMODE_CONFIG` env > `./ctxmode-config.yaml` > `~/.config/ctxmode/config.yaml`）
- 多 workdir 支持：`workdirs:` 列表中的目录均可作为合法 cwd
- `resolvePath` 跨所有 workdir 校验路径合法性
- `toolSearch` 结果路径跨 workdir 正确相对化
- `excludeFromGit` 对每个 workdir 执行 `.git/info/exclude` 排除
- 未配置时 fallback 到 cwd（向后兼容）

## [1.0.0] - 2026-07-23

### Added
- 9 工具 MCP server：execute, execute_file, index, search, batch_execute, fetch_and_index, stats, doctor, purge
- SQLite FTS5 全文搜索
- 沙箱执行（12 语言）：javascript, typescript, python, shell, go, rust, php, perl, ruby, r, elixir, csharp
- 网页抓取转 Markdown 索引
- 防 flood guard
- 后台执行支持
