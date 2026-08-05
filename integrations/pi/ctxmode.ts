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

  /** Per-tool client timeout. Long tasks (run_task/execute/batch) need ≥ server budget. */
  private timeoutForTool(name: string, args: Record<string, unknown>): number {
    const fromArgs =
      typeof args.timeout_ms === "number" && args.timeout_ms > 0
        ? args.timeout_ms
        : typeof args.timeout === "number" && args.timeout > 0
          ? args.timeout
          : 0
    // Server defaults: run_task 300s, execute often 30s–hours; keep buffer for MCP overhead.
    let base = REQUEST_TIMEOUT_MS
    if (name === "ctx_run") {
      const act = String(args.action || "")
      if (act === "run_task") {
        base = Math.max(REQUEST_TIMEOUT_MS, (fromArgs || 300000) + 30000)
      } else {
        base = Math.max(REQUEST_TIMEOUT_MS, (fromArgs || 120000) + 30000)
      }
    } else if (name === "ctx_bg" && String(args.action || "") === "wait") {
      base = Math.max(REQUEST_TIMEOUT_MS, (fromArgs || 60000) + 15000)
    }
    // Cap at 1h + buffer (server max).
    return Math.min(base, 3600000 + 60000)
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<string> {
    if (!this.initialized) {
      await this.start()
    }
    if (!this.initialized) throw new Error("ctxmode not initialized")
    const timeoutMs = this.timeoutForTool(name, args)
    try {
      const result = await this.sendRequest("tools/call", { name, arguments: args }, timeoutMs)
      const text = result.content?.map((c) => c.text).join("\n") || ""
      this.restartAttempts = 0
      return compressToolText(text)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      // Do not restart+retry on tool-call timeout: long jobs may still be running
      // server-side and a retry would duplicate work / orphan processes.
      if (/timed out/i.test(msg)) {
        throw err
      }
      if (/not running|disconnected/i.test(msg)) {
        await this.start()
        const result = await this.sendRequest("tools/call", { name, arguments: args }, timeoutMs)
        const text = result.content?.map((c) => c.text).join("\n") || ""
        return compressToolText(text)
      }
      throw err
    }
  }

  getTools(): string[] {
    return ["ctx_run", "ctx_fs", "ctx_git", "ctx_kb", "ctx_bg"]
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

// ---- Tool Registration (v2.0 category tools; MCP names match) ----

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

  pi.registerTool({
    name: "ctx_run",
    label: "CTX Run",
    description:
      "执行/测编。action=execute|execute_file|batch|run_task。测编优先 run_task；不确定输出用 execute（argv 优先）。",
    promptSnippet: "Run commands, batch jobs, or structured test/build tasks",
    promptGuidelines: [
      "Use ctx_run action=run_task for go/npm/cargo/make test and build.",
      "Use ctx_run action=execute for shell/code; prefer argv over command.",
      "Use ctx_run action=batch for multiple commands with optional queries.",
    ],
    parameters: Type.Object({
      action: Type.String({ description: "execute|execute_file|batch|run_task" }),
      command: Type.Optional(Type.String()),
      language: Type.Optional(Type.String()),
      timeout: Type.Optional(Type.Number()),
      background: Type.Optional(Type.Boolean()),
      intent: Type.Optional(Type.String()),
      cwd: Type.Optional(Type.String()),
      argv: Type.Optional(Type.Array(Type.String())),
      env: Type.Optional(Type.Record(Type.String(), Type.String())),
      stdin: Type.Optional(Type.String()),
      path: Type.Optional(Type.String()),
      code: Type.Optional(Type.String()),
      commands: Type.Optional(Type.Array(Type.Object({ label: Type.String(), command: Type.String() }))),
      queries: Type.Optional(Type.Array(Type.String())),
      concurrency: Type.Optional(Type.Number()),
      query_scope: Type.Optional(Type.String()),
      kind: Type.Optional(Type.String()),
      target: Type.Optional(Type.String()),
      args: Type.Optional(Type.Array(Type.String())),
      timeout_ms: Type.Optional(Type.Number()),
    }),
    async execute(_id, params) {
      return run("ctx_run", params as Record<string, unknown>)
    },
  })

  pi.registerTool({
    name: "ctx_fs",
    label: "CTX FS",
    description: "工作区文件（沙箱）。action=ls|glob|stat|rg。",
    promptSnippet: "List, glob, stat, or search files under workdirs",
    promptGuidelines: ["Prefer ctx_fs over shell find/ls/rg when listing or searching workspace files."],
    parameters: Type.Object({
      action: Type.String({ description: "ls|glob|stat|rg" }),
      path: Type.Optional(Type.String()),
      pattern: Type.Optional(Type.String()),
      glob: Type.Optional(Type.String()),
      depth: Type.Optional(Type.Number()),
      include_hidden: Type.Optional(Type.Boolean()),
      limit: Type.Optional(Type.Number()),
      ignore_case: Type.Optional(Type.Boolean()),
      context: Type.Optional(Type.Number()),
      literal: Type.Optional(Type.Boolean()),
    }),
    async execute(_id, params) {
      return run("ctx_fs", params as Record<string, unknown>)
    },
  })

  pi.registerTool({
    name: "ctx_git",
    label: "CTX Git",
    description: "只读 git。action=status|diff|log。",
    promptSnippet: "Read-only git status/diff/log",
    promptGuidelines: ["Prefer ctx_git for status/diff/log instead of shell git."],
    parameters: Type.Object({
      action: Type.String({ description: "status|diff|log" }),
      cwd: Type.Optional(Type.String()),
      path: Type.Optional(Type.String()),
      stat: Type.Optional(Type.Boolean()),
      unified: Type.Optional(Type.Number()),
      staged: Type.Optional(Type.Boolean()),
      n: Type.Optional(Type.Number()),
      oneline: Type.Optional(Type.Boolean()),
    }),
    async execute(_id, params) {
      return run("ctx_git", params as Record<string, unknown>)
    },
  })

  pi.registerTool({
    name: "ctx_kb",
    label: "CTX KB",
    description: "本地知识库。action=index|search|fetch|stats|purge|doctor。",
    promptSnippet: "Index/search knowledge base, fetch URLs, doctor, purge",
    promptGuidelines: [
      "Use ctx_kb action=search after large ctx_run outputs were auto-indexed.",
      "purge requires confirm:true.",
    ],
    parameters: Type.Object({
      action: Type.String({ description: "index|search|fetch|stats|purge|doctor" }),
      path: Type.Optional(Type.String()),
      query: Type.Optional(Type.String()),
      url: Type.Optional(Type.String()),
      urls: Type.Optional(Type.Array(Type.String())),
      source: Type.Optional(Type.String()),
      format: Type.Optional(Type.String()),
      force: Type.Optional(Type.Boolean()),
      maxBytes: Type.Optional(Type.Number()),
      timeoutMs: Type.Optional(Type.Number()),
      ttl: Type.Optional(Type.Number()),
      confirm: Type.Optional(Type.Boolean()),
      scope: Type.Optional(Type.String()),
      sessionId: Type.Optional(Type.String()),
      dryRun: Type.Optional(Type.Boolean()),
    }),
    async execute(_id, params) {
      return run("ctx_kb", params as Record<string, unknown>)
    },
  })

  pi.registerTool({
    name: "ctx_bg",
    label: "CTX Background",
    description: "后台进程。action=list|kill|log|wait（id 或 pid）。",
    promptSnippet: "Manage background jobs from ctx_run execute background:true",
    promptGuidelines: ["Use ctx_bg after starting background processes with ctx_run action=execute background:true."],
    parameters: Type.Object({
      action: Type.String({ description: "list|kill|log|wait" }),
      id: Type.Optional(Type.String()),
      pid: Type.Optional(Type.Number()),
      tail_lines: Type.Optional(Type.Number()),
      tail_bytes: Type.Optional(Type.Number()),
      timeout_ms: Type.Optional(Type.Number()),
    }),
    async execute(_id, params) {
      return run("ctx_bg", params as Record<string, unknown>)
    },
  })
}
