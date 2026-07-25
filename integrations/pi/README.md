# Pi integration

This directory contains the Pi-specific adapter for the generic `ctxmode` stdio MCP server.

- `ctxmode.ts` starts and supervises the Go binary.
- It registers ctxmode tools with `@earendil-works/pi-coding-agent`.
- Tool selection guidance lives in each tool's description and `promptGuidelines`.
- The adapter deliberately does not inject a fixed `before_agent_start` system prompt, avoiding repeated context.

The adapter is not required by other MCP clients.

## Install

Build and install the binary:

```bash
go build -o ctxmode .
install -m 755 ctxmode /usr/local/bin/ctxmode
```

Install the Pi adapter:

```bash
install -m 644 integrations/pi/ctxmode.ts ~/.pi/agent/extensions/ctxmode.ts
```

Restart Pi or run `/reload`.

## Runtime configuration

- `CTXMODE_BIN`: explicit path to the Go binary.
- `CTXMODE_WORKDIR`: override the workspace sent to the server.
- `CTXMODE_START_TIMEOUT_MS` and `CTXMODE_REQUEST_TIMEOUT_MS`: startup and request timeouts.
- `CTXMODE_OUTPUT_CHARS` and `CTXMODE_OUTPUT_LINES`: adapter-side output caps.
- `CTXMODE_CONFIG`: generic Go-server YAML configuration path.

The Go server remains usable directly from any stdio MCP client.
