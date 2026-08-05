# Pi integration

Thin bridge: spawn `ctxmode`, register the **same five MCP tools** on Pi
(`ctx_run`, `ctx_fs`, `ctx_git`, `ctx_kb`, `ctx_bg`). Requires **ctxmode ≥ 2.0.0**.

```bash
go build -o ctxmode .
install -m 755 ctxmode /usr/local/bin/ctxmode
install -m 644 integrations/pi/ctxmode.ts ~/.pi/agent/extensions/ctxmode.ts
```

`/reload` or restart Pi.
