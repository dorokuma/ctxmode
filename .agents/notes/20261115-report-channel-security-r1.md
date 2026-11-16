---
status: active
tags: [pattern:dispatch-report-channel-env-binding, pattern:ctxmode-extra-workdirs-policy]
---
# 报告通路第二轮加固：复合赋值写算子 + 父绑定 env + extras 工作区

背景：第一轮（14b9ece/93cf997）只识别 env 下标后的裸 `=`，且 `-workdir`
是单值 flag、Claude MCP 配置里重复的 `-workdir` 只剩最后一个生效。
本轮（fix/report-channel-security-r1）补三类缺口。

## 决策

1. **复合赋值写算子**：`maskAssignOpAt` 统一识别 `=`,`+=`,`-=`,`*=`,`/=`,
   `//=`,`%=`,`**=`,`<<=`,`>>=`,`>>>=`,`&=`,`|=`,`^=`,`@=`,`&&=`,`||=`,
   `??=`；`==`,`!=`,`<=`,`>=`,`===`,`=>`,`??` 保持读语义。下标
   (`maskAssignAfterBracket`) 与 JS 点成员共用同一判定，key 判责仍走
   `envOverrideKeyVerdict`（hook/taint/sentinel 阻断、良性键放行、动态
   key fail-closed）。Python `environ['K'] += v`、JS `process.env.K += v`
   不再绕过。

2. **报告通道 env 绑定**：`envHookVars` 增加 `DISPATCH_REPORT_PARENT` 与
   `CTXMODE_EXTRA_WORKDIRS`；`isDeniedEnvKeyForCaller` 对受守卫调用方把
   `DISPATCH_REPORT_PATH`/`DISPATCH_REPORT_PARENT`/`CTXMODE_EXTRA_WORKDIRS`
   一并拒绝（非 CTXMODE_ 前缀的两键不在前缀放行范围内，必须显式列名）。
   未受守卫的调用方（dispatcher 自身）保留 `CTXMODE_` 前缀透传。
   `dispatch-report --flush` 不开放给角色，仍按 `screenDispatchReportReadonly`
   的 `argv=[helper, t-addr]` 单拼写放行。

3. **extras 工作区窄策略**：`-workdir` 改 `stringListFlag` 可重复，首个显
   式值仍为 primary——单 `-workdir` 的 primary 与 `<sha8>-<base>` 库键完
   全不变；但历史重复 `-workdir` 配置由旧版 last-wins 变为 first-wins，
   对应库目录由 `<sha8(last)>-<base>` 切到 `<sha8(first)>-<base>`，旧目
   录保留在磁盘、不自动迁移（CTXMODE_DB 未设时；两分库间切换无自动启
   动提示）。`CTXMODE_EXTRA_WORKDIRS`（JSON
   `[]string`）在 flag/config 之后追加，每项必须绝对、归一化，且拒绝
   `/`、`/tmp`、`/var/tmp` 及 `/tmp/herdr-role-reports` 报告根子树（符号
   链接归一后同判）。非法值启动即错，不静默忽略。窄根拒绝策略只作用于
   `CTXMODE_EXTRA_WORKDIRS` 启动体检；`-workdir` 属宿主显式授信配置，不
   入该 denylist。刻意只拦宽根与报告树，不扩散到 `/etc`/`/var`（那会误
   伤主代理合法的全局 `-workdir`）。

4. **词法屏幕边界**：`codeEnvOverrideHit` 仅覆盖对 `environ`/
   `process.env` 的直接键写（下标/点成员、`del`）与已知写方法
   （`update`/`setdefault`/`__setitem__`/`pop`/`popitem`/`clear`）；不覆盖
   接收者别名（`e=os.environ; e['K']=v`）、整对象替换或 `__dict__` 操纵
   ——同 uid 词法层不构成独立信任边界。

## 范围外（遗留）

- `sh /tmp/x.sh` 脚本体不被守卫内容扫描，env 伪造对蓄意攻击不构成
  边界（同 uid 无独立信任根）；本轮定位是投递一致性/防误传。
- `CTXMODE_ENV_PASSTHROUGH` 关闭敏感键剥离属于宿主显式选择，未变。
- `CTXMODE_EXTRA_WORKDIRS` 属派发器内部接线环境变量而非面向终端
  用户的 CLI 参数；`-workdir` 的可重复与 first-wins 宿主接线语义已
  登记于 `CHANGELOG.md` 与本笔记决策 3；两者均刻意不写入
  `README.md`（已拍板 wontfix）。
- 并发/时序行为未改；三轮并发验证属 dispatch-agent 仓职责。

## r2 补记：基线两处阻塞修复（同分支授权追加）

`make check` 基线有两处既有缺陷，已获授权在本分支一并修复（未 commit）：

1. **测试进程全局误匹配**：`executor_reap_test.go`/`executor_kill_test.go`
   原用 `pkill -f "slee[p] 120"`、`pkill -f "sleep 37"` 与裸
   `"sleep 120"/"sleep 37"/"sleep 0.4"` 做 /proc cmdline 匹配，跨会话
   误杀并假失败。改为 `newTestSleeper(t)`：在 `t.TempDir()` 下建指向
   系统 sleep 的唯一符号链接，被测命令经该路径启动 setsid 与前后台
   sleep（进程树/session/pgid/stdio 拓扑不变）；`killTestSleepers` 与
   `waitForNoProc` 仅匹配该唯一路径。生产收割逻辑零改动。新
   `TestFindProcCmdline_IgnoresForeignSleeper` 断言外来 sleep 不被命中。

2. **切分二次方 + 重复敏感扫描慢路径**：
   - `splitLongText` 原每轮对剩余全串跑 `truncateUTF8`（含全串
     `utf8.ValidString`），10MB 单行退化 O(n²)。改为切点处最多回退
     `utf8.UTFMax-1` 个续字节的 O(1) rune 边界切分，拼接无损语义不变。
     补注（r5/F6②）：非法 UTF-8 落在窗口尾时，回退界内仍全部是不
     完整序列则不切半 rune——整块按字节原样前移（首字节 verbatim
     切出），保证每片 ≤ maxBytes 且整体逐字节无损，不吞字节。
   - `truncateUTF8`（main.go）改为只校验 `s[:maxBytes]` 窗口，复杂度
     严格 O(maxBytes)；边界回退与非法前缀截断语义不变。
   - `indexContentLocked` 删除调 `ReplaceExactAndChunks` 前那遍逐块
     `checkSensitiveContent` 循环：全文预检 + Store 在开启事务与任何
     写库变更之前（`BeginTx` 前逐块预检）逐块兜底均保留，拦截边界未削弱。
   - 回归：`TestSplitLongText_LargeSingleLine`（10MB 单行、无损拼接、
     30s 上限）。`-race` 下 `TestToolFetchAndIndex_ReportsBodyTruncated`
     由 >300s 降至 ~227s；残余耗时为 2622 chunk 行的 FTS5 trigram
     单事务写入，属 schema 层面，未动。
   - `truncateUTF8` 边界精确语义：只检查 `s[:maxBytes]` 窗口，窗口尾
     的 RuneError 每步 DecodeLastRune 最多回退 `utf8.UTFMax-1` 字节，窗
     口之外字节原样返回、不影响结果。

## r3 补记：oracle-ctxmode-r1 M1/S1/S2/S3 修复（同分支授权追加）

1. **M1（换行/续行/圆括号绕过）**：`skipMaskSpace` 扩展为跳过
   ` '\t' '\r' '\n'` 与反斜杠续行（`\`+可选 `' '/'\t'/'\r'`+`\n`）；
   `maskAssignAfterBracket` 在 `]` 闭合后跳过空白与外层 `)`；
   `pyEnvOverrideHit` 新增 `pyEnvironWriteMethodAfter`（`environ`+空白+
   `.`+空白+写方法 `update`/`setdefault`/`__setitem__`/`pop`/`popitem`/
   `clear`，`environ.get` 等读放行）；`pyDelEnvironKeyHit` 改为按语句边
   界正向扫描（`[`/`(`/`{` 深度内与 `\\` 续行后的 `\n` 不切语句），
   闭合 `del (\nos.environ['K']\n)` 与 `del \\\nos.environ['K']`；JS 侧
   新增 `jsProcessEnvAt` 匹配 `process`+空白+`.`+空白+`env`，并在
   `'.'`/`delete` 后读属性名前跳空白，`jsEnvOverrideHit` 点成员名后同
   样跳过 `)` 再判写算子。

2. **S1**：`unquoteCodeKey` 对含 `${` 的反引号模板返回 `("",false)`，
   ``process.env[`K${x}`]=v`` 走 `env override dynamic` fail-closed；
   无插值的 `` `FOO` `` 仍提取静态键放行。

3. **S2/S3**：`instructions.go` 通知行与 dispatch-agent helper 对齐为
   `报告已写入 path=<abs> bytes=<n> sha256=<hex>`；修正
   `role_guards_test.go` 注释——未受守卫调用方仅 `CTXMODE_EXTRA_WORKDIRS`
   经 `CTXMODE_` 前缀放行，`DISPATCH_*` 在 `filterExecEnv` 仍因不在
   `envAllowlist` 被拒（dispatcher 经其它渠道导出，不走 args.env）；
   删除 `executor_reap_test.go` 已无函数体的 `reapSleeperCleanup` 悬挂注释。

4. **跨仓配对**：`DISPATCH_REPORT_PARENT` 绑定与 `--flush` 动词对应
   dispatch-agent 同批次分支实现（`^t[0-9a-z]+$` 地址形）；本仓侧仅守
   `dispatch-report <t-addr>` 单拼写。跨仓锁步不变量（报告根
   `/tmp/herdr-role-reports`、`^t[0-9a-z]+$` 地址形、
   `dispatch-report <t-addr>` 单拼写、回执 `path=/bytes=/sha256=` 形）
   的权威登记已固化至 `AGENTS.md` 关联仓库段。

## r4 补记：oracle-ctxmode-r2 should-fix 闭合（同分支授权追加）

1. **S-A（`\v`/`\f` 空白盲区）**：`skipMaskSpace` 跳过集合加入 `'\v'`
   （\x0b）与 `'\f'`（\x0c），反斜杠续行的中间空白集合同步扩为
   `' '/'\t'/'\r'/'\v'/'\f'`；`pyLineContBefore` 同一集合。JS/Python 两侧
   `environ\f.update`、`.env\f.K`、`HC_SOCKET\x0b<<=1` 等跨形写不再绕过。

2. **S-B（限定名跨空白调用）**：新增 `hasMaskQualCall(masked, recv,
   method)`——`recv` 以非 ident 左边界定位后经 `skipMaskSpace + '.' +
   skipMaskSpace` 匹配 `method`（右边界非 ident），替代 `jsEnvOverrideHit`
   中对 `Object.assign`/`Object.defineProperty`/`Reflect.set` 的字面
   `hasTokenLike` 子串匹配；`putenv` 仍走 `hasIdent`，命中前提仍要求
   `toks.hasIdent("env")` 或 `jsProcessEnvAt` 命中（新增
   `jsProcessEnvAtAny` 以边界感知扫描替代 `strings.Contains(masked,
   "process.env")`）。`Object .assign(process.env,…)`、`Object\n.assign`
   `Reflect\f.set` 现按同 sink 阻断。

3. **O-B（`.delete` 成员名误判）**：`jsDeleteEnvHit` 从 `delete` 起点向前
   跳过 mask 空白后若前一字节为 `.` 则跳过该匹配——`api.delete` 是成员
   访问而非一元 delete 运算符；真实 `delete\nprocess.env.HC_SOCKET` 仍
   阻断。

4. **O-H（空 `-workdir`）**：`workdirFlags` prepend 循环跳过空串，保持
   旧版 `-workdir ""`（last-wins 下不产生任何 workdir）语义；空值不再被
   `filepath.Abs` 物化为 cwd 主工作区。子断言
   `EmptyFlagValueIgnored`（前置/后置空值都不改变 wd1 primary）。

5. **O-E（回执形跨仓锁定）**：`instructions.go` 保留
   `报告已写入 path=<abs> bytes=<n> sha256=<hex>` 字面量，旁注过渡期兼容——
   派发器升级前旧回执无 `sha256=`，父代理在回执含 `sha256=` 时比对摘要，
   否则核对路径与字节数后读全文。

6. **测试补强**：`TestGuard_CompoundEnvOverride` 追加 `\v`/`\f` 变体
   （Python `\f.update`/`\v=`，JS `\f.` 点写/`\x0b<<=1`）、S-B 跨空白
   限定名（`Object .assign`/`Object\n.assign`/`Reflect\f.set`）与 O-B
   双向断言（`delete\nprocess.env.HC_SOCKET` 阻断、`api.delete` 后语
   句放行）；`TestGuard_EnvHookReportVars` 断言 `filterExecEnv` 拒绝文
   本含 `security denylist`；`TestCLI_WorkdirFlagsAndExtraEnv` 新增
   `EmptyFlagValueIgnored`。

## r5 补记：oracle-ctxmode-r3 should-fix 闭合（同分支授权追加）

1. **F1（`.delete` 成员排除过宽）**：`jsDeleteEnvHit` 原向前跨任意 mask
   空白（含 `\n`/`\v`/`\f`）找 `.` 即跳过——`let q=1.\ndelete
   process.env.DISPATCH_REPORT_PATH` 借 `1.` 逃屏。收紧为仅排除紧贴
   `delete` 的 `.`（`masked[i-1]=='.'`）：`x.delete` 仍是成员名放行，
   跨空白成员访问不存在于 JS 语法（`x.\ndelete` 是下一条语句的一元
   delete），故不再留跨行逃逸；`api.delete\nconsole.log(process.env.K)`
   负例保持放行。

2. **F2（解构赋值目标元素写）**：新增 `maskDestructAssignTarget(masked,
   exprLo, exprHi, py)`——env 接收表达式自身不跟 `=`，但作为字面量目
   标元素被外层解构写入时拦截。包裹形：反向按括号深度找未配对开括号，
   开括号前一非空白字节为 ident/`)`/`]` 则属调用实参或下标（读，
   放行）；py 模式下跨非续行 `\n`/`;` 到语句首的字面量不套此前提
   （Python `x\n[y]` 不是下标，JS 中是）。每层闭括号后即查单纯 `=`
   （`({p:X}={Y})` 的 `=` 在内层 `}` 后、外层 `)` 前），再向外剥同
   前提的闭合括号。裸元组形（仅 py）：无包裹开括号且 exprHi 后接
   `,` 时，在同一语句深度 0 扫描到单纯 `=`（`os.environ['K'], a =
   '/x', 1`）即判写。JS 侧关裸元组形：`x, y` 是逗号表达式/多声明
   子，`const a=process.env.K, b=1` 是读。接入 `pyEnvOverrideHit` 下
   标分支（`maskAssignAfterBracket` 否时提取 `[lo,hi]`）与
   `jsEnvOverrideHit` 下标/点成员两分支，key 判责仍走
   `unquoteCodeKey`+`envOverrideKeyVerdict`（动态 key fail-closed）。
   负例保留：`d[os.environ['K']]=1`、`o[process.env.K]=1`、
   `const o={p:process.env.K}`、`const a=[process.env.K]`。

3. **F3（env 清除 sink 补齐）**：`pyEnvOverrideHit` 原语表加
   `environ.__delitem__` 与 `unsetenv`；`pyEnvironWriteMethodAfter`
   case 加 `__delitem__`；`jsEnvOverrideHit` 限定名条件加
   `Reflect.deleteProperty`（同 `delete`/`del` 属 env clear）。

4. **F5/F9（注释与工具链假设）**：`fetch.go` `indexContentLocked` 注
   释 `inside its transaction guard` 改为 `before any mutation (prior
   to opening its transaction)`（与 Store 侧 BeginTx 前预检表述一致）；
   `main_test.go` `buildCtxmodeCLI` 开头加 `exec.LookPath("go")` 缺失
   即 `t.Skipf`（无 go 工具链环境下由硬失败转为跳过）。

## r5b 补记：主分支源码复核两处边界收紧（同分支授权追加，未 commit）

主分支快进同步至 `4158fb1`（`githooks/commit-msg` 英文同步）后，按主
代理源码复核结论收紧 `maskDestructAssignTarget` 两处确定性漏口：

1. **漏口 A（Python 嵌套组+裸元组混合目标）**：`[os.environ['K']], a =
   ['/x'], 1` 中外层 `[` 闭合后是 `,` 而非 `=`，原剥层到 `nextOpen<0`
   直接 `return false` 漏判。抽出新辅助 `pyBareTupleAssignAfter(masked,
   pos)`（`pos` 后须先经 mask 空白遇 `,`，再从 `,` 后按括号深度 0 在
   同一语句内扫到 `;`/非续行 `\n` 止的单纯 `=`），在 `openIdx<0`
   （传 `exprHi`）与剥层末尾 `nextOpen<0`（传 `closeIdx+1`）两处当
   `py` 时统一调用；`x = [env['K']], 1`（`=` 在 `,` 前）仍放行。

2. **漏口 B（语句头关键字/条件括号/JS ASI 后 `[` 被误判下标读）**：
   原前驱判定只看前一字节是否 ident/`)`/`]`，把 `if (1) [K]=v`、
   `if (0); else [K]=v`、`let x\n[K]=v` 误判成下标读放行。抽出新辅
   助 `openIsCallOrSubscript(masked, openIdx, py)`：`{` 永不构成调用
   或下标；`(` 配对闭合后紧跟单纯 `=` 时是 `(…)=rhs` 目标组而非调
   用；回溯跨 mask 空白时 py 非续行 `\n` 语句止、JS 对 `[` 开括号
   把跨 `\n` 视为 ASI 语句起点；`]` 前驱为链式下标（读）；`)` 前
   驱反向配对其 `(` 后读紧邻标识词，属语句头关键字（`if`/`while`/
   `for`/`with`/`switch`/`catch`）返回 false（`fn()[K]=v` 仍放行）；
   ident 前驱反向取完整词，属语句/前缀关键字（`else`/`do`/`return`/
   `throw`/`yield`/`await`/`case`/`of`/`in`/`void`/`typeof`/`delete`/
   `elif`/`except`/`raise`/`assert`/`del`/`not`/`and`/`or`/`is`/`from`/
   `import` 及条件头）返回 false，其余词（`d`/`o`/`String`）返回
   true 保留下标读放行。

回归断言（`TestGuard_CompoundEnvOverride`）：pyBlock 加混合元组写；
jsBlock 加 `if (1) [K]=v`/`else [K]=v`/`let x\n[K]=v`；allow 加
`[String(K),a]=…`（调用实参元素读）与 `fn()[K]=1`（下标读）。旧实
现先验 FAIL、新实现 PASS（stash 对象 `09dfccd` 旧文件复现）。

## r6 补记：oracle-ctxmode-r4 终审收口修复（同分支授权追加，未 commit）

1. **上游 `4158fb1` 遗留 `githooks_test.go` 用例失配**：上游已将英文
   （ASCII-only）规则同步入 `githooks/commit-msg`（拒绝任何非 ASCII
   字符）但漏改测试——`TestCommitMsgHook` 子用例
   `chinese subject in conventional commit passes` 仍在断言中文主题通
   过。改为 `… is rejected` 并对 `fix(db): 修复缓存 TTL` 断言非零退
   出（English-only rule）。

2. **S1（Python `os.environb` 字节环境映射）**：
   - `unquoteCodeKey` 增加 Python 非插值字面量前缀剥离——仅对 `'`/`"`
     引号剥 `b`/`B`/`r`/`R`/`u`/`U` 及双字母组合
     `br`/`bR`/`Br`/`BR`/`rb`/`rB`/`Rb`/`RB`；`f`/`F`/`fr`/`rf` 插值
     前缀不剥（动态键 fail-closed），反引号不剥前缀（JS tagged
     template `tag\`...\`` 不是静态键）。引号内部含反斜杠转义（如
     `\x48`）仍返回 `("", false)` fail-closed。
   - `pyEnvOverrideHit`/`pyDelEnvironKeyHit`：原语表追加
     `environb.update`/`environb.setdefault`/`environb.__setitem__`/
     `environb.__delitem__`；接收者匹配改为 `environb`（长前缀优先，
     `envLen=8`）或 `environ`（`envLen=7`），右边界校验排除
     `environment` 等更长词；`pyDelEnvironKeyHit` 增加 `envLen` 参
     数。`os.environb[b'HC_SOCKET']=b'/x'`、
     `[os.environb[b'HC_SOCKET']]=[b'/x']`、
     `del os.environb[b'DISPATCH_REPORT_PATH']`、
     `os.environb.pop(b'HC_SOCKET')` 全部与 `os.environ` 同口径拦截。

3. **O4（JS 限定名写原语补齐）**：`jsEnvOverrideHit` 限定名条件补入
   `Reflect.defineProperty` 与 `Object.defineProperties`——
   `Reflect.defineProperty(process.env,'HC_SOCKET',{value:'/x'})` 与
   `Object.defineProperties(process.env,{HC_SOCKET:{value:'/x'}})` 现按
   同 sink 阻断。

4. **S2（跨仓状态更正）**：此前补记中「跨仓同步待 dispatch-agent
   侧落地」的表述已过期——`DISPATCH_REPORT_PARENT`、`--flush`、
   `^t[0-9a-z]+$` 与
   `报告已写入 path=/bytes=/sha256=` 已在对端 `dispatch-agent` 合入
   `main`（`c9a533d`）；预定部署顺序为本仓 `ctxmode` 门禁合入 `main`
   并执行 `./deploy.sh` 后，立即在干净的 `dispatch-agent` `main` 执行
   `./scripts/deploy.sh`。

回归断言（`TestGuard_CompoundEnvOverride`）：pyBlock 加
`os.environb[b'HC_SOCKET']=b'/x'`、`del os.environb[b'DISPATCH_REPORT_PATH']`、
`os.environb.pop(b'HC_SOCKET')`；jsBlock 加 `Reflect.defineProperty` 与
`Object.defineProperties` 两条；allow 加 `os.environb[b'FOO']=b'bar'`
（良性字节键放行）。

## r7 补记：基线对齐上游 9e61e80（未 commit）

远端 `origin/main` 前进至 `9e61e8092a8d1bc0439f2c68ef1fcc14e8ac623f`，
已包含 `githooks_test.go` 中文主题拒绝断言修复及对应 `CHANGELOG.md`
`### Fixed` 条目（`CI: fix stale TestCommitMsgHook expectation for
Chinese subjects`）。原 `r1` 工作分支登记已置 `merged`，遂新开
`fix/report-channel-security-r2` 工作树于 `9e61e80` 之上承接合流：
10 个 Go 生产/测试文件与提交对象 `73e8359` 保持逐字节一致，
`githooks_test.go` 直接沿用 `9e61e80`（工作区零差异）；
`CHANGELOG.md` 去掉 `73e8359` 中重复的 `TestCommitMsgHook aligned`
条目后，将 Baseline fixes 条目移入上游 `### Fixed` 段、Report-channel
hardening round 2 块完整保留于 `### Security` 段。全部改动停留在未
提交工作树状态，供 verifier / oracle / reviewer 执行提交前门禁。
