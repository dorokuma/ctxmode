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
  sendRequest(method: string, params: Record<string, unknown>, timeoutMs?: number): Promise<{ content?: Array<{ text: string }> }>
  start(): Promise<void>
  callTool(name: string, args: Record<string, unknown>): Promise<string>
  stderrBuffer: string[]
  stderrCarry: string
  stopped: boolean
  initialized: boolean
  proc: { pid?: number } | null
  rl: { close(): void } | null
}

let CtxmodeClient: new (workdir: string) => ClientTestSurface
let diagLog: (msg: string) => void

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
