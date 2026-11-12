---
status: active
tags: [pattern:mcp-arguments-jsonstring-unwrap]
---
# MCP tools/call arguments 字符串化解包兼容

agy lazy 工具桥 `call_mcp_tool` 声明 `Arguments` 为 `type:string`，宿主只解一层
JSON；模型偶发双重 stringify 的 `"{...}"` 透传到服务端违反规范（arguments
必须 object）。修复：`srv.AddReceivingMiddleware(argUnwrapMiddleware)`（新
`mcp_argunwrap.go`）在工具分派前对 `*CallToolParamsRaw.Arguments` 循环解
JSON-string ≤3 层；非 JSON-string/非 tools/call 一律透传，触发写 stderr。
详见 CHANGELOG [Unreleased] 与同批 pi-extensions notes
（20261111-mcp-args-jsonstring-unwrap.md）。
