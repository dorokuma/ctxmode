// ctxmode MCP Bridge for Pi
// Wraps the ctxmode Go binary (MCP over stdio) as pi custom tools.
//
// Requires: ctxmode on PATH (or set CTXMODE_BIN env var)

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent"
import { Type } from "typebox"
import { spawn, type ChildProcess } from "node:child_process"
import { createInterface } from "node:readline"
import path from "node:path"

const START_TIMEOUT_MS = Number(process.env.CTXMODE_START_TIMEOUT_MS || 15000)
const REQUEST_TIMEOUT_MS = Number(process.env.CTXMODE_REQUEST_TIMEOUT_MS || 120000)

// ---- Output budget (same spirit as codegraph-go) ----
const OUTPUT_CHAR_CAP = Number(process.env.CTXMODE_OUTPUT_CHARS || 50000)
const OUTPUT_LINE_CAP = Number(process.env.CTXMODE_OUTPUT_LINES || 500)

function compressToolText(text: string): string {
  if (!text) return text
  let t = text.replace(/\r\n/g, "\n").replace(/[ \t]+$/gm, "")
  t = t.replace(/\n{4,}/g, "\n\n\n")

  const lines = t.split("\n")
  let body: string
  if (lines.length > OUTPUT_LINE_CAP) {
    const headN = Math.max(40, Math.floor(OUTPUT_LINE_CAP * 0.75))
    const tailN = Math.max(15, OUTPUT_LINE_CAP - headN - 1)
    const omitted = lines.length - headN - tailN
    body =
      lines.slice(0, headN).join("\n") +
      `\n... (省略 ${omitted} 行；可缩小范围再查) ...\n` +
      lines.slice(-tailN).join("\n")
  } else {
    body = t
  }

  if (body.length <= OUTPUT_CHAR_CAP) return body
  let truncAt = OUTPUT_CHAR_CAP
  if (truncAt > 0 && (body.charCodeAt(truncAt - 1) & 0xfc00) === 0xd800) truncAt--
  const nl = body.lastIndexOf("\n", truncAt)
  const cut = nl > OUTPUT_CHAR_CAP * 0.7 ? nl : truncAt
  return body.slice(0, cut) + `\n... (输出达上限 ${OUTPUT_CHAR_CAP} 字，已截断)`
}

// ---- MCP client (minimal, same pattern as codegraph-go) ----

interface MCPRequest {
  jsonrpc: "2.0"
  id: number
  method: string
  params?: Record<string, unknown>
}

interface MCPResponse {
  jsonrpc: "2.0"
  id: number
  result?: {
    content?: Array<{ type: string; text: string }>
    tools?: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }>
  }
  error?: { code: number; message: string }
}

interface MCPToolResult {
  content: Array<{ type: string; text: string }>
  tools?: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }>
}

class CtxmodeClient {
  private proc: ChildProcess | null = null
  private requestId = 0
  private pending = new Map<
    number,
    {
      resolve: (result: MCPToolResult) => void
      reject: (err: Error) => void
      timer?: ReturnType<typeof setTimeout>
    }
  >()
  private initialized = false
  private starting: Promise<void> | null = null
  private stopped = false
  private restartAttempts = 0
  private restartTimer: ReturnType<typeof setTimeout> | null = null
  readonly workdir: string

  constructor(workdir: string) {
    this.workdir = workdir
  }

  async start(): Promise<void> {
    if (this.proc && this.initialized) return
    if (this.starting) return this.starting
    this.stopped = false
    this.starting = this.doStart().finally(() => {
      this.starting = null
    })
    return this.starting
  }

  private async doStart(): Promise<void> {
    if (this.proc) {
      try { this.proc.kill() } catch { /* ignore */ }
      this.proc = null
    }

    const bin = process.env.CTXMODE_BIN || "ctxmode"
    this.proc = spawn(bin, ["-workdir", this.workdir], {
      stdio: ["pipe", "pipe", "pipe"],
    })

    this.proc.on("error", (err) => {
      console.error(`[ctxmode] process error: ${err.message}`)
      this.cleanup()
      this.scheduleRestart()
    })

    this.proc.on("exit", (code) => {
      console.error(`[ctxmode] process exited with code ${code}`)
      this.cleanup()
      this.scheduleRestart()
    })

    if (this.proc.stderr) {
      this.proc.stderr.on("data", (chunk: Buffer | string) => {
        if (process.env.CTXMODE_DEBUG) {
          const text = typeof chunk === "string" ? chunk : chunk.toString("utf8")
          console.error(`[ctxmode] ${text.trimEnd()}`)
        }
      })
    }

    const rl = createInterface({ input: this.proc.stdout! })
    rl.on("line", (line) => {
      try {
        const msg: MCPResponse = JSON.parse(line)
        if (msg.id !== undefined && this.pending.has(msg.id)) {
          const entry = this.pending.get(msg.id)!
          this.pending.delete(msg.id)
          if (entry.timer) clearTimeout(entry.timer)
          if (msg.error) entry.reject(new Error(msg.error.message))
          else entry.resolve(msg.result as MCPToolResult)
        }
      } catch { /* non-JSON noise */ }
    })

    await this.sendRequest("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "pi-ctxmode", version: "1.0.0" },
    }, START_TIMEOUT_MS)
    this.sendNotification("notifications/initialized")

    const listResult = await this.sendRequest("tools/list", {}, START_TIMEOUT_MS)
    const toolNames = (listResult.tools || []).map(t => t.name).join(", ")
    this.initialized = true

    console.error(
      `[ctxmode] started workdir=${this.workdir}, tools: ${toolNames}, out≤${OUTPUT_CHAR_CAP}c/${OUTPUT_LINE_CAP}L`,
    )
  }

  private sendRequest(method: string, params: Record<string, unknown>, timeoutMs: number = REQUEST_TIMEOUT_MS): Promise<MCPToolResult> {
    return new Promise((resolve, reject) => {
      if (!this.proc?.stdin) {
        reject(new Error("ctxmode not running"))
        return
      }
      const id = ++this.requestId
      const req: MCPRequest = { jsonrpc: "2.0", id, method, params }
      const timer = setTimeout(() => {
        if (!this.pending.has(id)) return
        this.pending.delete(id)
        reject(new Error(`ctxmode ${method} timed out after ${timeoutMs}ms`))
      }, timeoutMs)
      this.pending.set(id, { resolve, reject, timer })
      this.proc.stdin.write(JSON.stringify(req) + "\n")
    })
  }

  private sendNotification(method: string, params?: Record<string, unknown>): void {
    if (!this.proc?.stdin) return
    this.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params: params || {} }) + "\n")
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<string> {
    if (!this.initialized) {
      await this.start()
    }
    if (!this.initialized) throw new Error("ctxmode not initialized")
    try {
      const result = await this.sendRequest("tools/call", { name, arguments: args })
      const text = result.content?.map((c) => c.text).join("\n") || ""
      this.restartAttempts = 0
      return compressToolText(text)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      if (/not running|disconnected|timed out/i.test(msg)) {
        await this.start()
        const result = await this.sendRequest("tools/call", { name, arguments: args })
        const text = result.content?.map((c) => c.text).join("\n") || ""
        return compressToolText(text)
      }
      throw err
    }
  }

  getTools(): string[] {
    // We know the tools statically; no need to query.
    return ["ctx_execute", "ctx_execute_file", "ctx_index", "ctx_search", "ctx_stats", "ctx_fetch_and_index", "ctx_batch_execute", "ctx_doctor", "ctx_purge"]
  }

  private scheduleRestart() {
    if (this.stopped) return
    if (this.restartAttempts >= 5) {
      console.error("[ctxmode] gave up auto-restart after 5 attempts")
      return
    }
    if (this.restartTimer) return
    const delay = Math.min(1000 * 2 ** this.restartAttempts, 15000)
    this.restartAttempts++
    console.error(`[ctxmode] auto-restart in ${delay}ms (attempt ${this.restartAttempts})`)
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null
      if (this.stopped) return
      this.start().catch((err) => {
        console.error(`[ctxmode] auto-restart failed: ${err}`)
        this.scheduleRestart()
      })
    }, delay)
  }

  cleanup() {
    for (const { reject, timer } of this.pending.values()) {
      if (timer) clearTimeout(timer)
      reject(new Error("ctxmode disconnected"))
    }
    this.pending.clear()
    this.proc = null
    this.initialized = false
  }

  stop() {
    this.stopped = true
    if (this.restartTimer) {
      clearTimeout(this.restartTimer)
      this.restartTimer = null
    }
    if (this.proc) {
      this.proc.stdin?.end()
      this.proc.kill()
      this.cleanup()
    }
  }
}

// ---- Pi Extension ----

export default function (pi: ExtensionAPI) {
  let client: CtxmodeClient | null = null
  let toolsRegistered = false

  pi.on("session_start", async (_event, ctx) => {
    const workdir = process.env.CTXMODE_WORKDIR || ctx.cwd
    try {
      client = new CtxmodeClient(path.resolve(workdir))
      await client.start()
      if (!toolsRegistered) {
        registerTools(pi, () => client)
        toolsRegistered = true
      }
      ctx.ui.notify(`ctxmode 已启动 (workdir: ${workdir})`, "info")
    } catch (err) {
      client = null
      const msg = err instanceof Error ? err.message : String(err)
      ctx.ui.notify(`ctxmode 启动失败: ${msg}`, "warning")
    }
  })

  pi.on("session_shutdown", async () => {
    if (client) {
      client.stop()
      client = null
    }
  })

  pi.registerCommand("ctxmode-start", {
    description: "启动 ctxmode",
    handler: async (_args, ctx) => {
      if (client) {
        ctx.ui.notify("ctxmode 已在运行", "info")
        return
      }
      const workdir = process.env.CTXMODE_WORKDIR || ctx.cwd
      try {
        client = new CtxmodeClient(path.resolve(workdir))
        await client.start()
        if (!toolsRegistered) {
          registerTools(pi, () => client)
          toolsRegistered = true
        }
        ctx.ui.notify(`ctxmode 已启动 (workdir: ${workdir})`, "info")
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        ctx.ui.notify(`ctxmode 启动失败: ${msg}`, "error")
      }
    },
  })

  pi.registerCommand("ctxmode-stop", {
    description: "停止 ctxmode",
    handler: async (_args, ctx) => {
      if (!client) {
        ctx.ui.notify("ctxmode 未运行", "info")
        return
      }
      client.stop()
      client = null
      ctx.ui.notify("ctxmode 已停止", "info")
    },
  })
}

// ---- Tool Registration ----

function registerTools(pi: ExtensionAPI, getClient: () => CtxmodeClient | null) {
  const run = async (name: string, params: Record<string, unknown>) => {
    const c = getClient()
    if (!c) {
      return {
        content: [{ type: "text" as const, text: "ctxmode 未运行。用 /ctxmode-start 启动。" }],
        details: {},
      }
    }
    try {
      const result = await c.callTool(name, params)
      return { content: [{ type: "text" as const, text: result }], details: {} }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      return {
        content: [{ type: "text" as const, text: `ctxmode error: ${msg}` }],
        details: {},
      }
    }
  }

  // ctx_execute
  pi.registerTool({
    name: "ctx_execute",
    label: "CTX Execute",
    description: "跑一段代码或 shell 命令。支持 12 种语言（javascript, typescript, python, shell, go, rust, php, perl, ruby, r, elixir, csharp）。大输出自动索引到 FTS5，不占上下文窗口。",
    promptSnippet: "Run code or shell commands with auto-indexing for large output",
    promptGuidelines: [
      "Use ctx_execute for any command where output length is uncertain. When in doubt, use it.",
      "Use ctx_execute for: git log/diff, build output, test output, docker/kubectl, curl, any command that might produce lots of output.",
      "Do NOT use ctx_execute for: pwd, whoami, echo, or commands where you need exact untruncated output.",
    ],
    parameters: Type.Object({
      command: Type.String({ description: "Command or code to execute" }),
      language: Type.Optional(Type.String({ description: "Runtime language (javascript/python/shell/go/...). Default: shell" })),
      timeout: Type.Optional(Type.Number({ description: "Max execution time in ms" })),
      background: Type.Optional(Type.Boolean({ description: "Keep running after timeout (for servers/daemons)" })),
      intent: Type.Optional(Type.String({ description: "What you're looking for in the output (for auto-indexing)" })),
      cwd: Type.Optional(Type.String({ description: "Working directory" })),
    }),
    async execute(_id, params) {
      return run("ctx_execute", params as Record<string, unknown>)
    },
  })

  // ctx_execute_file
  pi.registerTool({
    name: "ctx_execute_file",
    label: "CTX Execute File",
    description: "读一个文件到 FILE_CONTENT 变量，然后跑代码处理它。文件内容不进上下文。",
    promptSnippet: "Process a file with code without loading it into context",
    promptGuidelines: [
      "Use ctx_execute_file to analyze large files (logs, CSV, JSON) without loading them into the context window.",
    ],
    parameters: Type.Object({
      path: Type.String({ description: "File path to read into FILE_CONTENT variable" }),
      code: Type.String({ description: "Code that processes FILE_CONTENT variable" }),
      language: Type.Optional(Type.String({ description: "Runtime language. Default: javascript" })),
      timeout: Type.Optional(Type.Number({ description: "Max execution time in ms" })),
      intent: Type.Optional(Type.String({ description: "What you're looking for in the output" })),
      cwd: Type.Optional(Type.String({ description: "Working directory" })),
    }),
    async execute(_id, params) {
      return run("ctx_execute_file", params as Record<string, unknown>)
    },
  })

  // ctx_index
  pi.registerTool({
    name: "ctx_index",
    label: "CTX Index",
    description: "索引一个文件或目录到本地知识库，之后用 ctx_search 搜。",
    promptSnippet: "Index files or directories for later search",
    promptGuidelines: [
      "Use ctx_index to index project files, documentation, or any content you'll search repeatedly.",
    ],
    parameters: Type.Object({
      path: Type.String({ description: "File or directory path to index" }),
    }),
    async execute(_id, params) {
      return run("ctx_index", params as Record<string, unknown>)
    },
  })

  // ctx_search
  pi.registerTool({
    name: "ctx_search",
    label: "CTX Search",
    description: "在已索引内容里搜关键词，FTS5 全文搜索，返回匹配片段。",
    promptSnippet: "Search indexed content with FTS5 full-text search",
    promptGuidelines: [
      "Use ctx_search to find content in previously indexed files and command outputs.",
      "Search supports fuzzy matching for typos.",
    ],
    parameters: Type.Object({
      query: Type.String({ description: "Search terms or pattern" }),
    }),
    async execute(_id, params) {
      return run("ctx_search", params as Record<string, unknown>)
    },
  })

  // ctx_fetch_and_index
  pi.registerTool({
    name: "ctx_fetch_and_index",
    label: "CTX Fetch & Index",
    description: "抓取网页 HTML 转 Markdown 后索引并返回预览。支持缓存（24h 默认 TTL）。",
    promptSnippet: "Fetch URL content, convert to markdown, index for search",
    promptGuidelines: [
      "Use ctx_fetch_and_index to fetch web pages and index them for later search.",
      "Supports up to 10 URLs per call. Cached results return immediately.",
    ],
    parameters: Type.Object({
      url: Type.Optional(Type.String({ description: "Single URL to fetch" })),
      urls: Type.Optional(Type.Array(Type.String(), { description: "URLs to fetch (up to 10)" })),
      source: Type.Optional(Type.String({ description: "Index label for search" })),
      format: Type.Optional(Type.String({ description: "Output format: markdown (default), html, json" })),
      force: Type.Optional(Type.Boolean({ description: "Skip cache" })),
      maxBytes: Type.Optional(Type.Number({ description: "Return limit in bytes (default 50KB)" })),
      timeoutMs: Type.Optional(Type.Number({ description: "Client timeout in ms (default 150000)" })),
      links: Type.Optional(Type.Boolean({ description: "Include page hyperlinks in result" })),
      image_links: Type.Optional(Type.Boolean({ description: "Include image URLs in result" })),
      ttl: Type.Optional(Type.Number({ description: "Cache TTL in ms (0 = skip cache). Default: 24h" })),
    }),
    async execute(_id, params) {
      return run("ctx_fetch_and_index", params as Record<string, unknown>)
    },
  })

  // ctx_batch_execute
  pi.registerTool({
    name: "ctx_batch_execute",
    label: "CTX Batch Execute",
    description: "一次跑多个命令，输出自动索引，还能同时搜。支持并发（1-8）。",
    promptSnippet: "Run multiple commands in one call with auto-indexing",
    promptGuidelines: [
      "Use ctx_batch_execute when you need to run several independent commands at once.",
      "Pass queries to search indexed outputs in the same round trip.",
    ],
    parameters: Type.Object({
      commands: Type.Array(
        Type.Object({
          label: Type.String({ description: "Label for this command" }),
          command: Type.String({ description: "Command to execute" }),
        }),
        { description: "Array of {label, command} to execute" },
      ),
      queries: Type.Optional(Type.Array(Type.String(), { description: "Search terms to match in outputs" })),
      concurrency: Type.Optional(Type.Number({ description: "Concurrency level (1-8, default 1)" })),
      cwd: Type.Optional(Type.String({ description: "Working directory" })),
      timeout: Type.Optional(Type.Number({ description: "Max execution time per command in ms" })),
      query_scope: Type.Optional(Type.String({ description: "Search scope: 'batch' (default) or 'global'" })),
    }),
    async execute(_id, params) {
      return run("ctx_batch_execute", params as Record<string, unknown>)
    },
  })

  // ctx_stats
  pi.registerTool({
    name: "ctx_stats",
    label: "CTX Stats",
    description: "查看 token 节省统计：索引数量、数据库大小、节省的字节数。",
    promptSnippet: "Report token saving statistics",
    promptGuidelines: [
      "Use ctx_stats to check how much context has been saved by ctxmode.",
    ],
    parameters: Type.Object({}),
    async execute(_id, params) {
      return run("ctx_stats", params as Record<string, unknown>)
    },
  })

  // ctx_doctor
  pi.registerTool({
    name: "ctx_doctor",
    label: "CTX Doctor",
    description: "诊断 ctxmode：检查运行时、FTS5、存储、版本。",
    promptSnippet: "Diagnose ctxmode installation",
    promptGuidelines: [
      "Use ctx_doctor when ctxmode tools aren't working as expected.",
    ],
    parameters: Type.Object({}),
    async execute(_id, params) {
      return run("ctx_doctor", params as Record<string, unknown>)
    },
  })

  // ctx_purge
  pi.registerTool({
    name: "ctx_purge",
    label: "CTX Purge",
    description: "永久删除已索引内容。不可撤销，必须 confirm: true。",
    promptSnippet: "Permanently delete indexed content",
    promptGuidelines: [
      "Use ctx_purge to clear indexed content. Must confirm with confirm: true.",
    ],
    parameters: Type.Object({
      confirm: Type.Boolean({ description: "Must be true to proceed" }),
      scope: Type.String({ description: '"session" or "project"' }),
      sessionId: Type.Optional(Type.String({ description: "Required when scope is session" })),
    }),
    async execute(_id, params) {
      return run("ctx_purge", params as Record<string, unknown>)
    },
  })
}
