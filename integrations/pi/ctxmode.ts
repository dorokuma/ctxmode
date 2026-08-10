// ctxmode MCP Bridge for Pi
// Wraps the ctxmode Go binary (MCP over stdio) as pi custom tools.
//
// Requires: ctxmode on PATH (or set CTXMODE_BIN env var)
//
// Env knobs（详见 integrations/pi/README.md）:
//   CTXMODE_BIN              二进制路径（默认 "ctxmode"）
//   CTXMODE_WORKDIR          默认工作目录（默认会话 cwd）
//   CTXMODE_START_TIMEOUT_MS / CTXMODE_REQUEST_TIMEOUT_MS  超时
//   CTXMODE_DEBUG            诊断同时打 stderr（会污染 TUI 输入行，仅调试用）
//   CTXMODE_DIAG_STDERR=1    opt-in：诊断同时写 stderr（默认只写日志文件，保 TUI 干净）
//   CTXMODE_DIAG_DIR         诊断日志目录（默认 ~/.pi/agent/logs）
//   CTXMODE_DIAG_MAX_BYTES   日志轮转体积上限（默认 5MB，保留 .1/.2 最多两个历史）
//   CTXMODE_DISPOSE_WAIT_MS  换进程时 SIGTERM→SIGKILL 等待窗口（默认 3000ms）

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent"
import { Type } from "typebox"
import { spawn, type ChildProcess } from "node:child_process"
import { createInterface, type Interface } from "node:readline"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

const START_TIMEOUT_MS = Number(process.env.CTXMODE_START_TIMEOUT_MS || 15000)
const REQUEST_TIMEOUT_MS = Number(process.env.CTXMODE_REQUEST_TIMEOUT_MS || 120000)
const STDERR_KEEP_LINES = 20
const DIAG_TAG = "ctxmode"
const DIAG_LOG_FILE = "ctxmode.log"
/** 日志轮转体积上限默认 5MB（超限时轮转为 .1/.2，最多保留两个历史文件）。 */
const DIAG_MAX_BYTES_DEFAULT = 5 * 1024 * 1024
/** disposeProc 换进程时 SIGTERM → SIGKILL 等待窗口默认 3s（异步等待，不阻塞事件循环）。 */
const DISPOSE_WAIT_MS_DEFAULT = 3000

/** Opt-in：CTXMODE_DIAG_STDERR=1 时诊断同时写 stderr（默认不写，保持 TUI 干净）。 */
function diagStderrEnabled(): boolean {
  return process.env.CTXMODE_DIAG_STDERR === "1"
}
/** 日志轮转体积上限（运行时读取，便于测试与调优）。 */
function diagMaxBytes(): number {
  return Number(process.env.CTXMODE_DIAG_MAX_BYTES || DIAG_MAX_BYTES_DEFAULT)
}
/** disposeProc 等待窗口（运行时读取，便于测试与调优）。 */
function disposeWaitMs(): number {
  return Number(process.env.CTXMODE_DISPOSE_WAIT_MS || DISPOSE_WAIT_MS_DEFAULT)
}

/** Cache log path after first ensure (avoids mkdir per line). */
let diagLogPath: string | null = null
/** 降级提示只报一次（首次失败 console.error 一条，之后不再重复刷）。 */
let diagDegradedReported = false

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function reportDiagDegraded(reason: string): void {
  if (diagDegradedReported) return
  diagDegradedReported = true
  console.error(`[${DIAG_TAG}] 诊断日志降级: ${reason}; 本次会话不再重复提示`)
}

/** 超限轮转：log → log.1 → log.2，旧 .2 删除（最多保留两个历史文件）。 */
function rotateDiagLog(p: string): void {
  try { fs.unlinkSync(`${p}.2`) } catch { /* 不存在 */ }
  try { fs.renameSync(`${p}.1`, `${p}.2`) } catch { /* 不存在 */ }
  try { fs.renameSync(p, `${p}.1`) } catch { /* 不存在 */ }
}

function ensureDiagLogPath(): string | null {
  if (diagLogPath) return diagLogPath
  const dir = process.env.CTXMODE_DIAG_DIR || path.join(os.homedir() || "/tmp", ".pi", "agent", "logs")
  try {
    fs.mkdirSync(dir, { recursive: true })
    diagLogPath = path.join(dir, DIAG_LOG_FILE)
  } catch (err) {
    reportDiagDegraded(`日志目录不可用: ${errMessage(err)}`)
    return null
  }
  return diagLogPath
}

/**
 * TUI-safe diagnostics. console.* corrupts Pi's input row — only DEBUG or
 * CTXMODE_DIAG_STDERR=1 may print. Otherwise append to
 * ~/.pi/agent/logs/ctxmode.log（CTXMODE_DIAG_DIR 可覆盖目录）；超体积上限
 * （CTXMODE_DIAG_MAX_BYTES，默认 5MB）轮转为 .1/.2，最多保留两个历史文件；
 * 写失败首次降级提示一次并记录原因，之后静默重试。
 */
export function diagLog(msg: string): void {
  const line = `[${DIAG_TAG}] ${msg}`
  if (process.env.CTXMODE_DEBUG) {
    console.error(line)
    return
  }
  if (diagStderrEnabled()) console.error(line)
  const p = ensureDiagLogPath()
  if (!p) return
  try {
    let size = 0
    try { size = fs.statSync(p).size } catch { /* 新文件 */ }
    if (size > diagMaxBytes()) rotateDiagLog(p)
    fs.appendFileSync(p, `${new Date().toISOString()} ${line}\n`)
  } catch (err) {
    diagLogPath = null // 路径失效则下次重建
    reportDiagDegraded(`写入失败: ${errMessage(err)}`)
  }
}

function isInterestingStderrLine(line: string): boolean {
  if (/\blevel=INFO\b/i.test(line) || /"level"\s*:\s*"INFO"/i.test(line)) return false
  if (/\blevel=DEBUG\b/i.test(line) || /"level"\s*:\s*"DEBUG"/i.test(line)) return false
  return true
}

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
    instructions?: string
  }
  error?: { code: number; message: string }
}

interface MCPToolResult {
  content: Array<{ type: string; text: string }>
  tools?: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }>
  instructions?: string
}

export class CtxmodeClient {
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
  /** Server-provided instructions from the MCP initialize handshake (may be null). */
  private serverInstructions: string | null = null
  private starting: Promise<void> | null = null
  private stopped = false
  /** stop()/替换旧进程时置 true，避免 exit 监听把预期关闭当成故障。 */
  private intentionalClose = false
  private restartAttempts = 0
  private restartTimer: ReturnType<typeof setTimeout> | null = null
  /** readline 实例（doStart 创建，disposeProc 关闭）；持引用才能关闭。 */
  private rl: Interface | null = null
  /** 最近 N 行 stderr，异常退出时写入诊断日志。 */
  private stderrBuffer: string[] = []
  private stderrCarry = ""
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

  /**
   * 摘除 exit/error/stderr-data 监听、关闭 readline、销毁 stdio，确保旧进程再也
   * 碰不到新进程的缓冲与状态；随后 SIGTERM，等待窗口内未退出则升级 SIGKILL
   * （异步等待，不阻塞事件循环）；kill 失败走 diagLog 记录，不静默吞。
   */
  private async disposeProc(proc: ChildProcess): Promise<void> {
    this.intentionalClose = true
    try {
      proc.removeAllListeners("exit")
      proc.removeAllListeners("error")
    } catch { /* ignore */ }
    try { this.rl?.close() } catch { /* ignore */ }
    this.rl = null
    try { proc.stdin?.end() } catch { /* ignore */ }
    try {
      proc.stderr?.removeAllListeners("data")
      proc.stderr?.destroy()
      proc.stdout?.destroy()
    } catch { /* ignore */ }
    const exitPromise = new Promise<void>((resolve) => proc.once("exit", () => resolve()))
    let sent = false
    try {
      sent = proc.kill("SIGTERM")
    } catch (err) {
      diagLog(`dispose: kill(SIGTERM) 失败: ${errMessage(err)}`)
    }
    if (sent && proc.exitCode === null && proc.signalCode === null) {
      await Promise.race([exitPromise, sleep(disposeWaitMs())])
      if (proc.exitCode === null && proc.signalCode === null) {
        try {
          proc.kill("SIGKILL")
        } catch (err) {
          diagLog(`dispose: kill(SIGKILL) 失败: ${errMessage(err)}`)
        }
      }
    }
  }

  /** dispose + 清 stderr + reject pending（doStart 换进程 / stop 共用）。 */
  private async shutDownProc(): Promise<void> {
    if (!this.proc) return
    const proc = this.proc
    await this.disposeProc(proc)
    this.clearStderrBuffer()
    this.cleanup()
  }

  private pushStderrLine(line: string): void {
    if (!line) return
    this.stderrBuffer.push(line)
    if (this.stderrBuffer.length > STDERR_KEEP_LINES) this.stderrBuffer.shift()
  }

  private flushStderrCarry(): void {
    const tail = this.stderrCarry.trimEnd()
    if (tail) this.pushStderrLine(tail)
    this.stderrCarry = ""
  }

  private clearStderrBuffer(): void {
    this.flushStderrCarry()
    this.stderrBuffer = []
  }

  /** 异常退出写最近 stderr（滤 INFO/DEBUG）；force 时过滤空则回退末 5 行。 */
  private dumpStderrBuffer(force = false): void {
    this.flushStderrCarry()
    if (this.stderrBuffer.length === 0) return
    const all = this.stderrBuffer.slice(-STDERR_KEEP_LINES)
    this.stderrBuffer = []
    let lines = all.filter(isInterestingStderrLine)
    if (lines.length === 0 && force) lines = all.slice(-5)
    if (lines.length === 0) return
    diagLog(`last stderr before exit (${lines.length} lines):`)
    for (const line of lines) diagLog(`  ${line}`)
  }

  /** 统一处理退出：code===0 才算干净；null（被信号杀等）按异常 dump 并带 signal。 */
  private handleProcExit(code: number | null, signal: NodeJS.Signals | null): void {
    const intentional = this.intentionalClose
    this.intentionalClose = false
    if (intentional) {
      this.clearStderrBuffer()
      this.cleanup()
      return
    }
    if (code === 0) {
      // 意外退出写文件一行（仍不 console）。
      diagLog(`unexpected exit code=0 signal=${signal ?? ""} (silent to TUI; auto-restart if enabled)`)
      this.clearStderrBuffer()
    } else {
      diagLog(`process exited abnormally code=${code} signal=${signal ?? ""}`)
      this.dumpStderrBuffer(true)
    }
    this.cleanup()
    this.scheduleRestart()
  }

  /** stderr 数据：DEBUG 模式逐段输出之外，同样填充环形缓冲（两件事不互斥）。 */
  private handleStderrChunk(chunk: Buffer | string): void {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf8")
    if (process.env.CTXMODE_DEBUG) {
      diagLog(text.trimEnd())
    }
    const lines = (this.stderrCarry + text).split("\n")
    this.stderrCarry = lines.pop() || ""
    for (const line of lines) this.pushStderrLine(line.trimEnd())
  }

  private async doStart(): Promise<void> {
    if (this.proc) await this.shutDownProc()

    const bin = process.env.CTXMODE_BIN || "ctxmode"
    this.intentionalClose = false
    this.proc = spawn(bin, ["-workdir", this.workdir], {
      stdio: ["pipe", "pipe", "pipe"],
    })
    const proc = this.proc

    // 禁止 console.*（污染 Pi TUI 输入行）。
    proc.on("error", (err) => {
      const intentional = this.intentionalClose
      if (!intentional) {
        diagLog(`process error: ${err.message}`)
        this.dumpStderrBuffer(true)
      } else {
        this.clearStderrBuffer()
      }
      this.cleanup()
      if (!intentional) this.scheduleRestart()
    })

    proc.on("exit", (code, signal) => this.handleProcExit(code, signal))

    if (proc.stderr) {
      proc.stderr.on("data", (chunk: Buffer | string) => {
        // 兜底：dispose 已摘监听，但旧进程残留事件也不得污染新进程状态。
        if (this.proc !== proc) return
        this.handleStderrChunk(chunk)
      })
    }

    this.rl = createInterface({ input: proc.stdout! })
    this.rl.on("line", (line) => {
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

    const initResult = await this.sendRequest("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "pi-ctxmode", version: "1.0.0" },
    }, START_TIMEOUT_MS)
    this.serverInstructions = initResult.instructions ?? null
    this.sendNotification("notifications/initialized")

    const listResult = await this.sendRequest("tools/list", {}, START_TIMEOUT_MS)
    const toolNames = (listResult.tools || []).map(t => t.name).join(", ")
    this.initialized = true

    diagLog(
      `started workdir=${this.workdir}, tools: ${toolNames}, out≤${OUTPUT_CHAR_CAP}c/${OUTPUT_LINE_CAP}L`,
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

  /** Instructions announced by the server during initialize (absent → null). */
  getServerInstructions(): string | null {
    return this.serverInstructions
  }

  private scheduleRestart() {
    if (this.stopped) return
    if (this.restartAttempts >= 5) {
      diagLog("gave up auto-restart after 5 attempts")
      return
    }
    if (this.restartTimer) return
    const delay = Math.min(1000 * 2 ** this.restartAttempts, 15000)
    this.restartAttempts++
    diagLog(`auto-restart in ${delay}ms (attempt ${this.restartAttempts})`)
    this.restartTimer = setTimeout(() => {
      this.restartTimer = null
      if (this.stopped) return
      this.start().catch((err) => {
        diagLog(`auto-restart failed: ${err}`)
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

  async stop() {
    this.stopped = true
    if (this.restartTimer) {
      clearTimeout(this.restartTimer)
      this.restartTimer = null
    }
    await this.shutDownProc()
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

  pi.on("before_agent_start", async (event, _ctx) => {
    // 只追加说明，不解析用户口令、不改焦点、不拦截消息。
    if (client) {
      const serverInstructions = client.getServerInstructions()
      if (serverInstructions) {
        return {
          systemPrompt:
            event.systemPrompt +
            `

## Ctxmode server instructions

${serverInstructions}`,
        }
      }
    }
  })

  pi.on("session_shutdown", async () => {
    if (client) {
      await client.stop()
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
      await client.stop()
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
      action: Type.String({ description: "execute|execute_file|batch|run_task", enum: ["execute", "execute_file", "batch", "run_task"] }),
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
      action: Type.String({ description: "ls|glob|stat|rg", enum: ["ls", "glob", "stat", "rg"] }),
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
      action: Type.String({ description: "status|diff|log", enum: ["status", "diff", "log"] }),
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
      action: Type.String({ description: "index|search|fetch|stats|purge|doctor", enum: ["index", "search", "fetch", "stats", "purge", "doctor"] }),
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
      action: Type.String({ description: "list|kill|log|wait", enum: ["list", "kill", "log", "wait"] }),
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
