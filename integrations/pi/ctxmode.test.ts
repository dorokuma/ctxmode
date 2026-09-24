// ctxmode.test.ts — pi MCP bridge 行为测试（node:test + --experimental-strip-types，零新增依赖）
//
// 运行：node --experimental-strip-types --test integrations/pi/ctxmode.test.ts
//
// 说明：
// - ctxmode.ts 顶部 `import { Type } from "typebox"` 由 pi 宿主环境提供，本机无
//   node_modules；测试用 node:module.registerHooks 把 "typebox" 解析到内置
//   data: URL stub（测试只触及 CtxmodeClient/diagLog，不触发 registerTools，
//   stub 无需真实实现）。
// - 日志全部指向 os.tmpdir() 下临时目录，after() 统一删除，不碰真实家目录。
// - 假 child process / 假流（EventEmitter）。启动失败回收测一次本地 stub 脚本。
import { after, before, test } from "node:test"
import assert from "node:assert/strict"
import { EventEmitter } from "node:events"
import { registerHooks } from "node:module"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

// 运行期可见的 CtxmodeClient 测试面（TS private 仅编译期约束；strip-types 不做类型检查）。
interface ClientTestSurface {
  handleStderrChunk(chunk: Buffer | string): void
  flushStderrCarry(): void
  dumpStderrBuffer(force?: boolean): void
  handleProcExit(code: number | null, signal: NodeJS.Signals | null): void
  disposeProc(proc: unknown): Promise<void>
  sendRequest(
    method: string,
    params: Record<string, unknown>,
    timeoutMs?: number,
    onId?: (id: number) => void,
  ): Promise<{ content?: Array<{ text: string }> }>
  start(): Promise<void>
  callTool(name: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<string>
  timeoutForTool(name: string, args: Record<string, unknown>): number
  stderrBuffer: string[]
  stderrCarry: string
  stopped: boolean
  initialized: boolean
  proc: { pid?: number; stdin?: { end(): void; write(line: string): unknown } } | null
  rl: { close(): void } | null
  /** 在途 JSON-RPC 请求（id → resolve/reject/timer），测试直接响应或断言其存在。 */
  pending: Map<
    number,
    { resolve: (result: unknown) => void; reject: (err: Error) => void; timer?: ReturnType<typeof setTimeout> }
  >
}

let CtxmodeClient: new (workdir: string) => ClientTestSurface
let diagLog: (msg: string) => void
let compressToolText: (text: string) => string
/** ctxmode.ts 的默认导出（pi 扩展入口）：registerTools 的工具就是它注册的。 */
let ctxmodeExtension: (pi: unknown) => void

let tmpDir: string
const logPath = () => path.join(tmpDir, "ctxmode.log")

before(async () => {
  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === "typebox") {
        return {
          url:
            "data:text/javascript," +
            encodeURIComponent(
              "export const Type = { Object: (s) => s, String: (s) => s, Optional: (s) => s," +
                " Array: (s) => s, Number: (s) => s, Boolean: (s) => s, Record: (s) => s }",
            ),
          shortCircuit: true,
        }
      }
      return nextResolve(specifier, context)
    },
  })
  const mod = await import("./ctxmode.ts")
  CtxmodeClient = mod.CtxmodeClient
  diagLog = mod.diagLog
  compressToolText = mod.compressToolText
  ctxmodeExtension = mod.default

  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ctxmode-test-"))
  process.env.CTXMODE_DIAG_DIR = tmpDir
  delete process.env.CTXMODE_DEBUG
  delete process.env.CTXMODE_DIAG_STDERR
  delete process.env.CTXMODE_DIAG_MAX_BYTES
  delete process.env.CTXMODE_DISPOSE_WAIT_MS
})

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true })
  delete process.env.CTXMODE_DIAG_DIR
})

const newClient = () => new CtxmodeClient("/tmp/fake-workdir")

test("compressToolText 字数超限保留头尾和退出码", () => {
  const tail = "(exited with code 7)"
  const text = "HEAD_MARKER\n" + "x".repeat(60000) + "\n" + tail
  const out = compressToolText(text)
  assert.ok(out.includes("HEAD_MARKER"), "keep head")
  assert.ok(out.includes(tail), "keep trailing exit line")
  assert.ok(out.includes("已截断"), "insert omission marker")
  assert.ok(out.length < text.length, "must compress")
})

// ---- diagLog：写失败降级（缺陷 4）----
// 必须第一个跑：此时 diagLogPath 尚未缓存，坏目录才会真正生效。
test("diagLog 写失败：首次降级提示一次并带原因，目录恢复后能继续写", (t) => {
  const errSpy = t.mock.method(console, "error")
  const blocker = path.join(tmpDir, "blocked")
  fs.writeFileSync(blocker, "i am a file, not a dir")
  process.env.CTXMODE_DIAG_DIR = path.join(blocker, "sub")
  try {
    diagLog("degrade-probe-1")
    diagLog("degrade-probe-2")
  } finally {
    process.env.CTXMODE_DIAG_DIR = tmpDir
  }
  assert.equal(errSpy.mock.calls.length, 1, "两次失败只提示一次")
  assert.ok(String(errSpy.mock.calls[0].arguments[0]).includes("诊断日志降级"), "提示带降级原因")
  diagLog("degrade-recovery")
  assert.ok(fs.readFileSync(logPath(), "utf8").includes("degrade-recovery"), "目录恢复后能继续写")
})

// ---- 环形缓冲（缺陷 5 的缓冲部分）----
test("环形缓冲只保留最近 20 行", () => {
  const c = newClient()
  const lines = Array.from({ length: 25 }, (_, i) => `ring-line-${i + 1}`).join("\n") + "\n"
  c.handleStderrChunk(lines)
  assert.equal(c.stderrBuffer.length, 20)
  assert.equal(c.stderrBuffer[0], "ring-line-6")
  assert.equal(c.stderrBuffer[19], "ring-line-25")
})

test("不完整行 carry 跨 chunk 拼接，flush 落缓冲", () => {
  const c = newClient()
  c.handleStderrChunk("carry-a\ncarry-b\ncarry-")
  assert.deepEqual(c.stderrBuffer, ["carry-a", "carry-b"])
  assert.equal(c.stderrCarry, "carry-")
  c.handleStderrChunk("c-tail\n")
  assert.ok(c.stderrBuffer.includes("carry-c-tail"), "跨 chunk 拼接成完整行")
  assert.equal(c.stderrCarry, "")
  c.handleStderrChunk("dangling-no-newline")
  c.flushStderrCarry()
  assert.ok(c.stderrBuffer.includes("dangling-no-newline"), "flush 把残留 carry 落缓冲")
  assert.equal(c.stderrCarry, "")
})

// ---- dumpStderrBuffer 回退（缺陷 5/6 的 dump 行为）----
test("dumpStderrBuffer(force) 过滤后为空时回退末 5 行", () => {
  const c = newClient()
  c.handleStderrChunk(
    Array.from({ length: 6 }, (_, i) => `fallback level=INFO n=${i + 1}`).join("\n"),
  )
  c.dumpStderrBuffer(true)
  const log = fs.readFileSync(logPath(), "utf8")
  assert.ok(log.includes("last stderr before exit (5 lines)"), "回退 5 行")
  assert.ok(log.includes("n=2") && log.includes("n=6"), "包含末 5 行（第 2..6 行）")
  assert.ok(!log.includes("n=1"), "最早一行被丢弃")
  assert.equal(c.stderrBuffer.length, 0, "dump 后缓冲清空")

  // 非 force：过滤后为空 → 什么都不写
  c.handleStderrChunk("fallback2 level=INFO x=1\n")
  const before = fs.readFileSync(logPath(), "utf8")
  c.dumpStderrBuffer(false)
  assert.equal(fs.readFileSync(logPath(), "utf8"), before, "非 force 且过滤空则无输出")
})

// ---- exit code 语义（缺陷 6）----
test("exit code=0 视为干净退出：不 dump stderr", () => {
  const c = newClient()
  c.stopped = true
  c.handleStderrChunk("exit0-visible\n")
  const before = fs.readFileSync(logPath(), "utf8")
  c.handleProcExit(0, null)
  const log = fs.readFileSync(logPath(), "utf8")
  const added = log.slice(before.length) // 只看本次新增字节，避免历史断言污染
  assert.ok(added.includes("unexpected exit code=0"), "记录干净退出 summary")
  assert.ok(!added.includes("abnormally"), "不按异常记")
  assert.ok(!added.includes("exit0-visible"), "缓冲内容未写入日志（不 dump）")
})

test("exit code=null（被信号杀死）按异常处理：dump stderr 且带 signal", () => {
  const c = newClient()
  c.stopped = true
  c.handleStderrChunk("killed-line-1\nkilled-line-2\n")
  c.handleProcExit(null, "SIGKILL")
  const log = fs.readFileSync(logPath(), "utf8")
  assert.ok(log.includes("abnormally code=null signal=SIGKILL"), "带 code 与 signal 记异常")
  assert.ok(log.includes("last stderr before exit (2 lines)"), "异常时 dump")
  assert.ok(log.includes("killed-line-1") && log.includes("killed-line-2"), "缓冲内容入日志")
})

test("exit 非零 code 也按异常 dump", () => {
  const c = newClient()
  c.stopped = true
  c.handleStderrChunk("crash-code-5\n")
  c.handleProcExit(5, null)
  const log = fs.readFileSync(logPath(), "utf8")
  assert.ok(log.includes("abnormally code=5"), "非零 code 记异常")
  assert.ok(log.includes("crash-code-5"), "dump 内容入日志")
})

// ---- disposeProc（缺陷 1、2）----

class FakeStream extends EventEmitter {
  destroyed = false
  end() {}
  destroy() {
    this.destroyed = true
  }
}

class FakeProc extends EventEmitter {
  exitCode: number | null = null
  signalCode: NodeJS.Signals | null = null
  stdin = {
    end: () => {
      this.stdinEnded = true
    },
  }
  stderr = new FakeStream()
  stdout = new FakeStream()
  signals: (string | undefined)[] = []
  autoExit = false
  stdinEnded = false
  kill(signal?: string): boolean {
    this.signals.push(signal ?? "SIGTERM")
    if (this.autoExit) {
      this.exitCode = 0
      setImmediate(() => this.emit("exit", 0, null))
    }
    return true
  }
}

test("disposeProc：摘 stderr 监听、关 readline、销毁 stdio", async () => {
  const c = newClient()
  let rlClosed = false
  c.rl = {
    close: () => {
      rlClosed = true
    },
  }
  const proc = new FakeProc()
  proc.autoExit = true // SIGTERM 即退 → 不应有 SIGKILL
  await c.disposeProc(proc)
  assert.deepEqual(proc.signals, ["SIGTERM"], "只发 SIGTERM，及时退出不升级")
  assert.equal(rlClosed, true, "readline 被关闭")
  assert.equal(c.rl, null, "readline 引用被清空")
  assert.equal(proc.stdinEnded, true, "stdin end")
  assert.equal(proc.stderr.destroyed, true, "stderr 流销毁")
  assert.equal(proc.stdout.destroyed, true, "stdout 流销毁")
  assert.equal(proc.stderr.listenerCount("data"), 0, "stderr data 监听已摘除")
})

test("disposeProc：SIGTERM 窗口内未退出则升级 SIGKILL", async () => {
  process.env.CTXMODE_DISPOSE_WAIT_MS = "50"
  try {
    const c = newClient()
    const proc = new FakeProc() // autoExit=false → 不响应 SIGTERM
    await c.disposeProc(proc)
    assert.deepEqual(proc.signals, ["SIGTERM", "SIGKILL"], "超时后升级 SIGKILL")
  } finally {
    delete process.env.CTXMODE_DISPOSE_WAIT_MS
  }
})

test("disposeProc 后旧进程 stderr 事件不再污染缓冲", async () => {
  const c = newClient()
  const proc = new FakeProc()
  proc.stderr.on("data", (chunk: Buffer | string) => c.handleStderrChunk(chunk))
  proc.autoExit = true
  await c.disposeProc(proc)
  proc.stderr.emit("data", "pollute-me\n")
  assert.equal(proc.stderr.listenerCount("data"), 0, "data 监听已被摘除")
  assert.deepEqual(c.stderrBuffer, [], "旧进程残留 stderr 不再写入缓冲")
})

// ---- diagLog 轮转（缺陷 3）----
test("diagLog 超体积上限真的轮转，历史最多保留两个", () => {
  // 清掉此前测试产物，让轮转链从空文件开始，断言确定
  for (const p of [logPath(), logPath() + ".1", logPath() + ".2"]) {
    try { fs.unlinkSync(p) } catch { /* 不存在 */ }
  }
  process.env.CTXMODE_DIAG_MAX_BYTES = "100"
  try {
    diagLog("ROT#1 " + "x".repeat(150)) // 新文件 size 0 → 不轮转
    diagLog("ROT#2 " + "y".repeat(150)) // size>100 → log → .1
    diagLog("ROT#3 " + "z".repeat(150)) // .1 → .2，log → .1
    diagLog("ROT#4 " + "w".repeat(150)) // 删旧 .2，链式前移
    const cur = fs.readFileSync(logPath(), "utf8")
    const h1 = fs.readFileSync(logPath() + ".1", "utf8")
    const h2 = fs.readFileSync(logPath() + ".2", "utf8")
    assert.ok(cur.includes("ROT#4"), "当前文件是最新写入")
    assert.ok(!cur.includes("ROT#1") && !cur.includes("ROT#2") && !cur.includes("ROT#3"), "当前文件无历史")
    assert.ok(h1.includes("ROT#3") && !h1.includes("ROT#4"), ".1 是上一代")
    assert.ok(h2.includes("ROT#2") && !h2.includes("ROT#1"), ".2 是上上代，更老的被删")
  } finally {
    delete process.env.CTXMODE_DIAG_MAX_BYTES
  }
})

function writeStubBin(name: string, body: string): string {
  const p = path.join(tmpDir, name)
  fs.writeFileSync(p, `#!${process.execPath}\n${body}`)
  fs.chmodSync(p, 0o755)
  return p
}

/**
 * 回复 initialize / tools/list 的最小 ctxmode 替身，并把收到的每一行 JSON-RPC
 * 追加到 $CTXMODE_TEST_RECV —— 用来断言"取消通知是否真的写给了服务端"。
 */
function writeRecordingStubBin(name: string): string {
  return writeStubBin(
    name,
    [
      'const fs = require("fs");',
      'if (process.env.CTXMODE_TEST_PIDLOG) fs.appendFileSync(process.env.CTXMODE_TEST_PIDLOG, process.pid + "\\n");',
      'let buf = "";',
      'process.stdin.setEncoding("utf8");',
      'process.stdin.on("data", (chunk) => {',
      '  buf += chunk;',
      '  let idx;',
      '  while ((idx = buf.indexOf("\\n")) >= 0) {',
      '    const line = buf.slice(0, idx);',
      '    buf = buf.slice(idx + 1);',
      '    if (!line.trim()) continue;',
      '    if (process.env.CTXMODE_TEST_RECV) fs.appendFileSync(process.env.CTXMODE_TEST_RECV, line + "\\n");',
      '    let msg;',
      '    try { msg = JSON.parse(line); } catch { continue; }',
      '    if (msg.method === "initialize") {',
      '      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id,',
      '        result: { protocolVersion: "2024-11-05", capabilities: {},',
      '          serverInfo: { name: "ctxmode", version: "stub" }, instructions: "stub" } }) + "\\n");',
      '    } else if (msg.method === "tools/list") {',
      '      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id,',
      '        result: { tools: [{ name: "ctx_run", description: "stub", inputSchema: { type: "object" } }] } }) + "\\n");',
      '    }',
      '  }',
      '});',
      'process.stdin.resume();',
    ].join("\n"),
  )
}

/** 握手完成后延迟退出的 stub：用来验证"进程崩溃后仍会自动重连"这条既有兜底。 */
function writeCrashingStubBin(name: string, crashAfterMs: number): string {
  return writeStubBin(
    name,
    [
      'const fs = require("fs");',
      'if (process.env.CTXMODE_TEST_PIDLOG) fs.appendFileSync(process.env.CTXMODE_TEST_PIDLOG, process.pid + "\\n");',
      'let buf = "";',
      'let served = false;',
      'process.stdin.setEncoding("utf8");',
      'setTimeout(() => process.exit(3), ' + String(crashAfterMs) + ');',
      'process.stdin.on("data", (chunk) => {',
      '  buf += chunk;',
      '  let idx;',
      '  while ((idx = buf.indexOf("\\n")) >= 0) {',
      '    const line = buf.slice(0, idx);',
      '    buf = buf.slice(idx + 1);',
      '    if (!line.trim()) continue;',
      '    let msg;',
      '    try { msg = JSON.parse(line); } catch { continue; }',
      '    if (msg.method === "initialize") {',
      '      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id,',
      '        result: { protocolVersion: "2024-11-05", capabilities: {},',
      '          serverInfo: { name: "ctxmode", version: "stub" }, instructions: "stub" } }) + "\\n");',
      '    } else if (msg.method === "tools/list") {',
      '      served = true;',
      '      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id,',
      '        result: { tools: [{ name: "ctx_run", description: "stub", inputSchema: { type: "object" } }] } }) + "\\n");',
      '    }',
      '  }',
      '});',
      'process.stdin.resume();',
    ].join("\n"),
  )
}

/** 极简 ExtensionAPI 替身：只留下测试要用的 on/registerTool。 */
function fakePi() {
  const handlers = new Map<string, (...args: unknown[]) => unknown>()
  const tools = new Map<string, Record<string, unknown>>()
  const pi = {
    on(event: string, handler: (...args: unknown[]) => unknown) {
      handlers.set(event, handler)
      return () => handlers.delete(event)
    },
    registerTool(tool: Record<string, unknown>) {
      tools.set(String(tool.name), tool)
    },
    registerCommand() {},
  }
  return { pi, handlers, tools }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    return (err as NodeJS.ErrnoException).code !== "ESRCH"
  }
}

// ---- start/initialize 失败回收进程 ----
test("start/initialize 失败后进程被回收", async () => {
  const pidfile = path.join(tmpDir, "fail-init.pid")
  const bin = writeStubBin("fail-init-ctxmode", `
const fs = require("fs");
fs.writeFileSync(process.env.CTXMODE_TEST_PIDFILE, String(process.pid));
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let idx;
  while ((idx = buf.indexOf("\\n")) >= 0) {
    const line = buf.slice(0, idx);
    buf = buf.slice(idx + 1);
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === "initialize") {
      process.stdout.write(JSON.stringify({
        jsonrpc: "2.0",
        id: msg.id,
        error: { code: -32000, message: "initialize refused" },
      }) + "\\n");
    }
  }
});
process.stdin.resume();
`)
  process.env.CTXMODE_BIN = bin
  process.env.CTXMODE_TEST_PIDFILE = pidfile
  process.env.CTXMODE_DISPOSE_WAIT_MS = "50"
  const c = newClient()
  try {
    await assert.rejects(() => c.start(), /initialize refused/)
    assert.equal(c.proc, null, "start 失败后不再持有子进程")
    assert.equal(c.initialized, false, "未标记 initialized")
    const pid = Number(fs.readFileSync(pidfile, "utf8"))
    assert.ok(pid > 0, "stub 写出了 pid")
    assert.equal(pidAlive(pid), false, "子进程已退出")
  } finally {
    delete process.env.CTXMODE_BIN
    delete process.env.CTXMODE_TEST_PIDFILE
    delete process.env.CTXMODE_DISPOSE_WAIT_MS
  }
})

// ---- callTool disconnect 不重放 ----
test("callTool 在 disconnected 时不二次 tools/call", async () => {
  for (const boom of ["ctxmode disconnected", "ctxmode not running"]) {
    const c = newClient()
    c.initialized = true
    let toolCalls = 0
    c.start = async () => {
      c.initialized = true
    }
    c.sendRequest = async (method: string) => {
      if (method === "tools/call") {
        toolCalls++
        throw new Error(boom)
      }
      return { content: [] }
    }
    await assert.rejects(
      () => c.callTool("ctx_run", { action: "execute", command: "echo hi" }),
      new RegExp(boom.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    )
    assert.equal(toolCalls, 1, `${boom}: 不重放 tools/call`)
  }
})

test("timeoutForTool: fetch 默认大于服务端 150s，并读取 timeout_ms", () => {
  const c = newClient()
  const fetchDefault = c.timeoutForTool("ctx_kb", { action: "fetch" })
  assert.ok(fetchDefault >= 180000, `fetch default ${fetchDefault} should be 150s+buffer`)
  const custom = c.timeoutForTool("ctx_kb", { action: "fetch", timeout_ms: 200000 })
  assert.ok(custom >= 230000, `timeout_ms 200000 + buffer, got ${custom}`)
  const snake = c.timeoutForTool("ctx_run", { action: "run_task", timeout_ms: 400000 })
  assert.ok(snake >= 430000, `timeout_ms still works, got ${snake}`)
})

// ---- Esc / 客户端超时必须闭环成 notifications/cancelled ----
// 背景：pi 只做前端中止（session.abort）而不会替 MCP 子进程收尸；ctxmode 的
// runCmd 只在 handler ctx 被取消时才 kill 子进程组。若桥不发取消通知，子进程
// 会一路跑到服务端默认超时（execute 30s / run_task 5min）——用户按 Esc 却杀不掉。

/** 装一个只记录 stdin 写入的假 proc，并直接标记 initialized（跳过 start 握手）。 */
function stubRecordingProc(c: ClientTestSurface): string[] {
  const writes: string[] = []
  c.initialized = true
  c.proc = {
    stdin: {
      end: () => {},
      write: (line: string) => {
        writes.push(line)
      },
    },
  } as unknown as ClientTestSurface["proc"]
  return writes
}

/** 取出在途请求（不存在即断言失败），并清掉它的超时计时器后响应它让 promise 落地。 */
function settleWith(
  c: ClientTestSurface,
  id: number,
  result: { content: Array<{ type: string; text: string }> },
): Promise<unknown> {
  const entry = c.pending.get(id)
  assert.ok(entry, `request ${id} 应在 pending 中`)
  if (entry.timer) clearTimeout(entry.timer) // 否则 120s 计时器挂住事件循环
  entry.resolve(result)
  return Promise.resolve(result)
}

const nextTick = () => new Promise((r) => setImmediate(r))

test("Esc（AbortSignal.abort）→ 发 notifications/cancelled 并立刻拒绝等待，不留 120s 计时器", async () => {
  const c = newClient()
  const writes = stubRecordingProc(c)
  const ctrl = new AbortController()

  const done = c.callTool(
    "ctx_run",
    { action: "execute", argv: ["sleep", "300"] },
    ctrl.signal,
  )
  await nextTick()
  assert.equal(writes.length, 1, "先发 tools/call")
  const req = JSON.parse(writes[0])
  assert.equal(req.method, "tools/call")
  assert.equal(c.pending.size, 1, "请求在途")

  ctrl.abort() // 用户按 Esc
  assert.equal(writes.length, 2, "abort 后立刻补发取消通知")
  // 顺序不变量：请求必须先上线，取消通知才可能命中在途的 requestId；
  // 早发的取消服务端 preempter 根本找不到目标，等于白写、请求照跑到超时。
  const idxReq = writes.findIndex((w) => w.includes('"tools/call"'))
  const idxCancel = writes.findIndex((w) => w.includes('"notifications/cancelled"'))
  assert.ok(idxReq >= 0 && idxCancel >= 0, "tools/call 与取消通知都必须写出")
  assert.ok(idxReq < idxCancel, `request(idx ${idxReq}) 必须先于 cancel(idx ${idxCancel})`)
  const notify = JSON.parse(writes[1])
  assert.equal(notify.method, "notifications/cancelled")
  assert.equal(notify.params.requestId, req.id, "requestId 必须对上前一个 tools/call")
  assert.match(String(notify.params.reason), /esc/, "reason 说明是用户中止")
  assert.equal(c.pending.size, 0, "本地等待同步结束，不等服务端回包")
  await assert.rejects(done, /cancelled \(user pressed esc\)/, "Esc 后立刻 reject，不干等超时")
})

test("客户端超时也发取消通知，不把子进程丢给服务端默认超时", async () => {
  const c = newClient()
  const writes = stubRecordingProc(c)
  c.timeoutForTool = () => 20

  await assert.rejects(
    () => c.callTool("ctx_run", { action: "execute", argv: ["sleep", "300"] }),
    /timed out after 20ms/,
  )
  assert.equal(writes.length, 2, "超时后先发取消再 reject")
  const notify = JSON.parse(writes[1])
  assert.equal(notify.method, "notifications/cancelled")
  assert.equal(notify.params.requestId, 1)
  assert.match(String(notify.params.reason), /client gave up/, "reason 标明是客户端放弃")
  assert.equal(c.pending.size, 0, "pending 已清空")
})

test("无 signal 且正常返回：只写 tools/call，绝不发取消通知", async () => {
  const c = newClient()
  const writes = stubRecordingProc(c)

  const done = c.callTool("ctx_git", { action: "status" })
  await nextTick()
  assert.equal(writes.length, 1, "无 signal → 只有 tools/call，没有多余通知")
  assert.ok(!writes[0].includes("cancelled"), "不得出现取消通知")

  settleWith(c, 1, { content: [{ type: "text", text: "CLEAN" }] })
  assert.equal(await done, "CLEAN")
})

test("调用前 signal 已 abort：不发请求、不发通知，直接拒绝", async () => {
  const c = newClient()
  const writes = stubRecordingProc(c)
  const ctrl = new AbortController()
  ctrl.abort()

  await assert.rejects(
    () => c.callTool("ctx_run", { action: "execute", argv: ["sleep", "300"] }, ctrl.signal),
    /cancelled \(user pressed esc\)/,
  )
  assert.equal(writes.length, 0, "未连接上就取消：连 tools/call 都不该写")
  assert.equal(c.pending.size, 0)
})

test("abort 晚于响应到达：请求已完成，不再补发取消通知", async () => {
  const c = newClient()
  const writes = stubRecordingProc(c)
  const ctrl = new AbortController()

  const done = c.callTool("ctx_git", { action: "status" }, ctrl.signal)
  await nextTick()
  settleWith(c, 1, { content: [{ type: "text", text: "CLEAN" }] })
  assert.equal(await done, "CLEAN")

  ctrl.abort() // 结果已回收之后 abort
  assert.equal(writes.length, 1, "无在途请求 → 不再写取消通知")
  assert.ok(!writes.some((w) => w.includes("cancelled")), "不得出现取消通知")
})

// ---- 扩展层：abort 必须让工具调用 reject（与 pi 内置工具一致），而不是
// 变成一段 "ctxmode error: ... cancelled" 的成功结果留在对话历史里。----
test("扩展层：ctx_run 在 abort 时 reject，且不向服务端发 tools/call", async () => {
  const recvPath = path.join(tmpDir, "ext-recv.jsonl")
  fs.writeFileSync(recvPath, "")
  const bin = writeRecordingStubBin("recording-ctxmode")
  process.env.CTXMODE_BIN = bin
  process.env.CTXMODE_TEST_RECV = recvPath
  process.env.CTXMODE_DISPOSE_WAIT_MS = "50"
  try {
    const { pi, handlers, tools } = fakePi()
    ctxmodeExtension(pi)
    const start = handlers.get("session_start") as (
      e: unknown,
      ctx: unknown,
    ) => Promise<void>
    await start({ type: "session_start" }, { cwd: tmpDir, ui: { notify() {} } })

    const ctxRun = tools.get("ctx_run") as {
      execute: (
        id: string,
        params: Record<string, unknown>,
        signal?: AbortSignal,
        onUpdate?: unknown,
        ctx?: unknown,
      ) => Promise<unknown>
    }
    assert.ok(ctxRun, "ctx_run 已注册")

    const ctrl = new AbortController()
    ctrl.abort() // 用户早已按过 Esc
    await assert.rejects(
      () => ctxRun.execute("id-1", { action: "execute", argv: ["sleep", "300"] }, ctrl.signal),
      /cancelled \(user pressed esc\)/,
      "abort 时必须 reject，而不是返回 error 文本结果",
    )

    const lines = fs.readFileSync(recvPath, "utf8").trim().split("\n").filter(Boolean)
    const methods = lines.map((l) => JSON.parse(l).method)
    assert.ok(methods.includes("initialize") && methods.includes("tools/list"), "握手正常")
    assert.ok(!methods.includes("tools/call"), "已取消 → 不该发出 tools/call")
    assert.ok(!methods.includes("notifications/cancelled"), "没有在途请求可取消")

    const shutdown = handlers.get("session_shutdown") as () => Promise<void>
    await shutdown()
  } finally {
    delete process.env.CTXMODE_BIN
    delete process.env.CTXMODE_TEST_RECV
    delete process.env.CTXMODE_DISPOSE_WAIT_MS
  }
})

// ---- 显式停止是终态：stop 之后不得再被内部重连拉起新进程 ----
// 这是 shutdown 竞态的根因：stopped 曾会被 start() 里的 `this.stopped = false`
// 无条件抹掉，于是 stop() 路径上被 cleanup() 拒绝的在途调用，会经 callTool 的
// reconnect 分支把 client 复活，spawn 出一个扩展侧已引用不到的进程。
const spawnCount = () =>
  fs.readFileSync(process.env.CTXMODE_TEST_PIDLOG!, "utf8").trim().split("\n").filter(Boolean).length

const sleepMs = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** 轮询直到 predicate 成立或超时（返回是否成立）。 */
async function waitUntil(predicate: () => boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return true
    await sleepMs(25)
  }
  return predicate()
}

test("stop 之后的 start() 一律拒绝，且不拉起任何进程", async () => {
  const pidLog = path.join(tmpDir, "stop-guard-pids.log")
  fs.writeFileSync(pidLog, "")
  process.env.CTXMODE_BIN = writeRecordingStubBin("stop-guard-bin")
  process.env.CTXMODE_TEST_RECV = path.join(tmpDir, "stop-guard-recv.jsonl")
  process.env.CTXMODE_TEST_PIDLOG = pidLog
  process.env.CTXMODE_DISPOSE_WAIT_MS = "50"
  try {
    const c = newClient()
    c.stopped = true // 等价 stop() 之后的终态
    await assert.rejects(() => c.start(), /was stopped/, "显式停止后拒绝启动")
    assert.equal(spawnCount(), 0, "一个进程都不该拉起")
  } finally {
    delete process.env.CTXMODE_BIN
    delete process.env.CTXMODE_TEST_RECV
    delete process.env.CTXMODE_TEST_PIDLOG
    delete process.env.CTXMODE_DISPOSE_WAIT_MS
  }
})

test("在途长任务 + session_shutdown：只 spawn 1 个进程，不泄漏第二个", async () => {
  const pidLog = path.join(tmpDir, "shutdown-race-pids.log")
  const recvPath = path.join(tmpDir, "shutdown-race-recv.jsonl")
  fs.writeFileSync(pidLog, "")
  fs.writeFileSync(recvPath, "")
  process.env.CTXMODE_BIN = writeRecordingStubBin("shutdown-race-bin")
  process.env.CTXMODE_TEST_RECV = recvPath
  process.env.CTXMODE_TEST_PIDLOG = pidLog
  process.env.CTXMODE_DISPOSE_WAIT_MS = "50"
  try {
    const { pi, handlers, tools } = fakePi()
    ctxmodeExtension(pi)
    await (handlers.get("session_start") as (e: unknown, c: unknown) => Promise<void>)(
      { type: "session_start" },
      { cwd: tmpDir, ui: { notify() {} } },
    )
    const ctxRun = tools.get("ctx_run") as {
      execute: (id: string, p: Record<string, unknown>) => Promise<unknown>
    }

    // stub 永不回复 tools/call → 调用一直挂在途（等价一个长任务）
    const settled = ctxRun
      .execute("id-1", { action: "run_task", kind: "go_test", timeout_ms: 600000 })
      .then(
        (r) => ({
          rejected: false,
          text: (r as { content?: Array<{ text?: string }> }).content?.[0]?.text ?? "",
        }),
        (e: Error) => ({ rejected: true, text: e?.message ?? "" }),
      )
    await waitUntil(() => spawnCount() === 1, 3000)
    assert.equal(spawnCount(), 1, "启动只 spawn 1 个")

    await (handlers.get("session_shutdown") as () => Promise<void>)()
    const outcome = await settled
    assert.equal(outcome.rejected, false, "disconnect 走文本错误路径（与其它错误一致）")
    assert.match(outcome.text, /ctxmode disconnected/, "stop 后调用应以 disconnected 收尾")
    // 给任何错误的重连留足时间（重连是同步发起、无退避）；若有第二个 spawn 会立刻出现
    await sleepMs(500)
    assert.equal(spawnCount(), 1, "stop 后不得再拉起第二个进程（回归：shutdown 竞态）")
  } finally {
    delete process.env.CTXMODE_BIN
    delete process.env.CTXMODE_TEST_RECV
    delete process.env.CTXMODE_TEST_PIDLOG
    delete process.env.CTXMODE_DISPOSE_WAIT_MS
  }
})

test("回归保护：进程崩溃后仍会自动重连（修复没有削弱既有兜底）", async () => {
  const pidLog = path.join(tmpDir, "crash-restart-pids.log")
  fs.writeFileSync(pidLog, "")
  process.env.CTXMODE_BIN = writeCrashingStubBin("crash-restart-bin", 400)
  process.env.CTXMODE_TEST_RECV = path.join(tmpDir, "crash-restart-recv.jsonl")
  process.env.CTXMODE_TEST_PIDLOG = pidLog
  process.env.CTXMODE_DISPOSE_WAIT_MS = "50"
  try {
    const c = newClient()
    await c.start()
    assert.equal(spawnCount(), 1, "首次启动")
    // stub 400ms 后 exit(3) → 异常退出 → scheduleRestart 退避重拉
    const restarted = await waitUntil(() => spawnCount() >= 2, 6000)
    assert.equal(restarted, true, "进程崩溃后仍应自动重连（stopped=false 不受 start 守卫影响）")
    await c.stop()
    const afterStop = spawnCount()
    await sleepMs(600)
    assert.equal(spawnCount(), afterStop, "stop 之后重启链也停住")
  } finally {
    delete process.env.CTXMODE_BIN
    delete process.env.CTXMODE_TEST_RECV
    delete process.env.CTXMODE_TEST_PIDLOG
    delete process.env.CTXMODE_DISPOSE_WAIT_MS
  }
})
