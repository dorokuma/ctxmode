// stripansi.test.ts — stripANSI 转义序列剥离测试（node:test + --experimental-strip-types，零新增依赖）
//
// 运行：node --experimental-strip-types --test integrations/pi/stripansi.test.ts
// （仓库根目录全量 TS 测试：node --experimental-strip-types --test integrations/pi/*.test.ts）
//
// 覆盖第 4 轮双路审计确认的缺失项：
// - 两/三字节 ESC 形式：ESC c（RIS）、ESC # 8（DECALN）、ESC ( B（字符集）、
//   ESC % G、ESC 7/8 —— 中间字节区 0x20-0x2F 与 final 0x30-0x5F 此前完全不处理；
// - DCS/SOS/PM/APC（ESC P/X/^/_）整体剥离到终止器（BEL 或 ESC \），未终止则吞剩余；
// - OSC/CSI 与正常文本行为回归。
import { before, test } from "node:test"
import assert from "node:assert/strict"
import { registerHooks } from "node:module"

let stripANSI: (s: string) => string

before(async () => {
  // ctxmode.ts 顶部 `import { Type } from "typebox"` 由 pi 宿主环境提供，
  // 本机无 node_modules，解析到内置 data: URL stub（与 ctxmode.test.ts 相同做法）。
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
  stripANSI = mod.stripANSI
})

const ESC = "\x1b"

test("两字节 ESC 形式：ESC c（RIS 复位）被剥离", () => {
  assert.equal(stripANSI(`${ESC}c rest`), " rest")
})

test("三字节 ESC 形式：ESC # 8（DECALN）被剥离", () => {
  assert.equal(stripANSI(`${ESC}#8out`), "out")
})

test("三字节 ESC 形式：ESC ( B（字符集）整体剥离，不残留 B", () => {
  assert.equal(stripANSI(`${ESC}(Btext`), "text")
})

test("三字节 ESC 形式：ESC % G 与 ESC 7/ESC 8（保存/恢复光标）", () => {
  assert.equal(stripANSI(`${ESC}%Gx${ESC}7y${ESC}8z`), "xyz")
})

test("DCS 整体剥离到 ST（ESC \\）终止器", () => {
  assert.equal(stripANSI(`${ESC}P1$r0;1r${ESC}\\ok`), "ok")
})

test("DCS 剥离到 BEL 终止器", () => {
  assert.equal(stripANSI(`a${ESC}P0;1|payload\x07b`), "ab")
})

test("SOS/PM/APC（ESC X/^/_）整体剥离到 ST", () => {
  const s = `a${ESC}X sos text ${ESC}\\b${ESC}^ pm ${ESC}\\c${ESC}_ apc ${ESC}\\d`
  assert.equal(stripANSI(s), "abcd")
})

test("DCS 未终止：吞掉剩余全部内容", () => {
  assert.equal(stripANSI(`head ${ESC}P1;2|payload that never ends`), "head ")
})

test("OSC 保留原行为：BEL 与 ST 终止", () => {
  assert.equal(stripANSI(`a${ESC}]0;title\x07b`), "ab")
  assert.equal(stripANSI(`a${ESC}]2;t${ESC}\\b`), "ab")
})

test("CSI 保留原行为：SGR/光标/清屏序列", () => {
  const s = `a${ESC}[31;1mred${ESC}[0m${ESC}[2J${ESC}[1;1Hb`
  assert.equal(stripANSI(s), "aredb")
})

test("正常文本不受影响", () => {
  const s = "plain text 123 !@# $ % ^ & * ( ) [ ] { } < > ~ ` \\ | é ü 中文 \n\ttab"
  assert.equal(stripANSI(s), s)
})

test("混合真实终端流量", () => {
  const raw = `${ESC}[?25l${ESC}c${ESC}]8;;http://x\x07link${ESC}]8;;\x07${ESC}(B${ESC}[1mBOLD${ESC}[0m`
  assert.equal(stripANSI(raw), "linkBOLD")
})
