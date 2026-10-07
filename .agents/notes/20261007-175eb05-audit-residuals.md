---
status: active
superseded_by: ""
supersedes: ""
模块: ctx_fs, stats, githooks
---

# 2026-10-07 — 175eb05 审计残留：R1–R5 未覆盖的观察项清单

## 一句话结论
- main 上 commit `175eb05`（`feat(tools): port ctx_stats and pi-fff resolve/related from upstream originals`）经 verifier + reviewer + oracle 三方审计、在工作分支 `fix/175eb05-audit-rework` 上做了 R1–R5 返工（本笔记写作时仍未提交）；返工未覆盖的观察项逐条落盘于此，一条不丢。
- 本笔记是**遗留清单**：七条观察（A–G）一律**不修**，每条写明现象、位置（行号以返工后的工作区为准）、保留理由与后续处置；另附两条既定口径（kept-out 计数范围、被推翻的审计结论），供后续审计参照、避免复发。

## 背景
- 触发：175eb05 的三方审计结论中，一部分被返工修掉，一部分被判不成立，剩下的是「功能无误但语义脆弱/口径未定/覆盖不足」的观察项。没有落盘渠道的话，这些项会随返工一起消失——本轮要求逐条落盘。
- 落盘范围：只新增本笔记；源码、README.md、CHANGELOG.md、其它笔记均不改，batch.go 与 fetch.go 不动；不 commit / push / merge。
- 阅读前提：**行号以 R1–R5 返工后的工作区为准**。R1 修掉 staticcheck S1005 后 `fs_resolve.go` 有行号位移（原 :339 的 `pairExts, _ := ...` 现为 :354），R4 改了 `scanWorkspaceFiles` 的签名与早停记录，引用旧行号会找不到位置。
- 复核方式：观察项的机制均在本轮按源码逐条核对；纯函数（`pairStem` / `isTestName` / `splitStemExt`）的实测用一次性镜像程序跑过（同源函数体，跑完即删，不入仓、不留引用路径）；探针类实测（`isSensitiveFilePath` 的路径段规则、`scanWorkspaceFiles` 的上限/截断语义）用 `go test -overlay` 把一次性测试文件从 /tmp 挂进包内跑（不在仓内落地任何文件，跑完即删），结论与本笔记一致的部分已注明，不一致的部分以「订正」标出。

## 决策
总口径：**观察项不修、逐条记录**。理由分三类，逐条落在下面各项的「为何保留不修」里——(a) 无实际后果、只是语义脆弱；(b) 属怪异输入或上游未定义口径，改动要以上游期望为依据；(c) 属覆盖不足，补测需要给生产代码开测试专用缝，超出本轮返工范围。

### 1. 观察 A｜resolve 遍历的敏感路径闸门只丢条目、不剪枝（口径订正）
- **现象**：`scanWorkspaceFiles` 的 walk 回调为每个访问到的条目先取 `name := fi.Name()`（fs_resolve.go:172），再依次走 `skipWalkDirs` 剪枝（:173-175）、工作区/符号链接围栏（:176-181）、敏感闸门（:182-184）。敏感闸门是 `return nil`，**对目录不返回 `filepath.SkipDir`**，于是 `.ssh/`、`.aws/` 这类敏感目录不会被剪掉：walk 会进入该目录并逐个访问其直接子项，子项再由 main.go:1563-1568 的目录段规则（`.aws`/`.ssh`/`.gnupg`/`.kube`/`.env`）判为敏感后丢弃。丢弃发生在调用方回调 `fn` 之前，所以**内容从不读取、响应里也不含这些名字**，多的只是对敏感目录直接子项的一次 Walk/stat 开销，数量有界。
- **位置**：fs_resolve.go:172（读 `fi.Name()`）、:182-184（敏感闸门）、:185（`filepath.Rel`）；主闸门实现 main.go:1530-1570，其中目录段规则在 main.go:1563-1568。
- **订正（与审计原述不符，以源码为准）**：(a)「resolve 把敏感判断放在 `filepath.Rel` 之后」不成立——fs_resolve.go:182 在 :185 的 `filepath.Rel` **之前**；(b)「glob 路径先按 `isSensitiveFilePath` 跳过整棵子树」也不成立——toolGlob 的敏感闸门 fs_tools.go:416-418 同样是 `return nil`、不 SkipDir（`filepath.Rel` 在 :420），审计所引的 fs_tools.go:406-411 实际是 `skipWalkDirs` 剪枝（:406-408）与符号链接围栏剪枝（:410-415），不是敏感闸门。**glob 与 resolve 在「敏感目录是否剪枝」这一点上行为一致**，因此不构成两条路径的口径分歧。(c) 同形闸门只有上述**两处**，不是原先写的「三处」：纯 Go rg 的敏感闸门 fs_tools.go:1824-1826 排在 `filepath.Rel`（目录分支 :1781、文件分支 :1804）与 gitignore 判定（目录分支 :1793、文件分支 :1806）**之后**，而且它只在**文件分支**里——目录条目在 :1796 就 `return nil`（同样不 SkipDir），从不经过该闸门，所以它与 glob/resolve 那两处「在 `filepath.Rel` 之前、对文件与目录统一判定」的回调结构不同形，不能与它们并成一处同形改动。**但这不等于「敏感目录的子项不会被丢」**——`isSensitiveFilePath` 的路径段规则（main.go:1563-1568 的 `for … range strings.Split(lower, separator)` 段比对）让 `…/.ssh/id_rsa` 这类路径自身就命中，所以 rg 路径下敏感目录的直接子项照样被逐条丢弃，只是丢弃点落在 fs_tools.go:1824-1826（实测：`isSensitiveFilePath` 对 `/w/.ssh/id_rsa`、`/w/.aws/credentials`、`/w/sub/.kube/config` 均返回 true，对 `/w/normal/plain.go` 返回 false；一次性探针经 `go test -overlay` 挂 /tmp，不入仓）。因此三条 walk 在**可观察结果**上都是「丢条目、不剪子树」，差异只在闸门在回调里的**位置与作用对象**。(d) fs_tools.go:1627 是 rg **输出行**的敏感闸门（`rgRawLineSensitive` 内逐候选路径 stat 后判定），不是 walk 闸门，不属于「统一 walk 闸门」的范围。
- **为何保留不修**：无泄漏面（敏感目录的子项名字不回传、内容不读），只有遍历开销；把敏感闸门改成对目录 `SkipDir` 会改变 glob 与 resolve 两条 walk 的语义面（纯 Go rg 的目录分支走不到该闸门，不受影响），且要重新核对与 `.gitignore` 层、符号链接围栏的交互顺序，超出本轮返工范围。
- **后续**：若要收紧，作为独立改动统一处理**两处**同形闸门——fs_resolve.go:182-184（resolve）与 fs_tools.go:416-418（glob，`filepath.Rel` 在 :420）：两处都在 `filepath.Rel` **之前**判敏感、且都 `return nil` 而不 `SkipDir`，改法一致。改前先补「敏感目录的直接子项名不出现在任何响应里」的断言，改后再补一条「不进入敏感目录」的遍历计数断言。

### 2. 观察 B｜related 的大小写口径与 `pairStem` 的检测/切片不对称
- **现象 1（可复现）**：`relatedPairRules` 的键查表大小写不敏感、同族比较大小写敏感。toolRelated 用 `relatedPairRules[strings.ToLower(targetExt)]` 取 `pairExts`（fs_resolve.go:354），但同族判定用 `extIn`（:452-459，`ext == e` 精确比较）与 `stemPair == targetPairStem`（:372/:374）。靶文件名带大写扩展名时（如 `FOO.GO`），`pairExts` 能取到 `{".go"}`，但候选 `FOO.GO` 的 ext `.GO` ∉ `{".go"}`、候选 `foo.go` 的 stem `"foo"` ≠ `"FOO"`，**90/100 两档都不可达**，只能落到 :376 的 70 档（同 stem、异扩展）。
- **现象 2（订正）**：审计原述「`user_TEST.go` 经 `strings.ToLower` 检测后用原始长度切片，`pairStem` 变成 `user_`，会与 `user_.go` 误配成 test/impl」**未复现**。`.go`/`.py` 分支的 `isTestName`（fs_resolve.go:424-433）用大小写敏感的 `HasSuffix(stem, "_test")` 与 `HasPrefix(stem, "test_")`，`user_TEST` 判定为非测试名，`pairStem`（:437-450）原样返回 `user_TEST`，不产生 `user_`。`Test_user.py` 的「同理」需要说清：`isTestName` 对 `.py` 用的是大小写敏感的 `HasPrefix(stem, "test_")`，`Test_user` 与 `user_TEST` 一样被判为**非**测试名、`pairStem` 原样返回（属「不剥」而非「误剥」）；只有全小写的 `test_user.py` 才会切成 `user`。切片侧（:442/:446 用原始 `stem` 长度，检测侧 :439/:441/:445 用 `strings.ToLower`）实测也无偏差：`user_test/.go→user`、`USER_test/.GO→USER`、`user.TEST/.ts→user`、`test_user/.py→user`——后缀字符集（`_test`/`.test`/`.spec`/`test_`）全为 ASCII，Go 的简单大小写映射不改变这些字母的字节长度，故切片安全。真正的怪象只是「靶名/候选名大小写混写时档位降级」（现象 1）。
- **位置**：fs_resolve.go:354（键查表）、:371-382（评分 switch，:372/:374 的 100/90 档）、:424-433（`isTestName`）、:437-450（`pairStem`）、:452-459（`extIn`）；既有断言 fs_resolve_test.go:140（`TestSplitStemExtAndPairStem`）、:96（`TestToolRelatedPairs`）只覆盖全小写输入。
- **为何保留不修**：(a) 大小写混写的文件名在 Linux 上属怪异输入；(b) 本仓 resolve/related 是 pi-fff 的近似移植，上游未定义大小写语义，统一比较口径会改动评分分层，须以上游期望为依据。
- **后续**：若上游 pi-fff 明确「大小写不敏感」，把键、`extIn`、`stemPair` **三处同口径** ToLower 化，并补 `FOO.GO ↔ foo.go` 命中 100 档的断言；否则维持现状，把「大小写敏感」写进 `ctx_fs action=related` 的文档说明。

### 3. 观察 C｜`isFuzzyBoundaryByte` 与 `isFuzzyBoundaryRune` 两套边界语义并存
- **现象**：`isFuzzyBoundaryByte`（fs_resolve.go:104-107）用 `rune(s[idx])` 按**字节下标**取字符，无 `idx <= 0` 保护、不含空白判定；被 `fuzzyScore` 的字符串子串档调用（:51、:58，下标来自 `strings.Index`，是字节偏移——用法正确）。`isFuzzyBoundaryRune`（:109-115）按 **rune 切片下标**取值，带 `idx <= 0 → true` 保护并额外认 `unicode.IsSpace`；被 `subsequenceScore` 调用（:91，下标是 rune 序号——用法也正确）。两函数在同一文件、同名族、语义不同（下标单位、零下标行为、空白算不算边界），当前调用方各配各的，功能无误。
- **位置**：fs_resolve.go:51、:58、:91、:104-107、:109-115。
- **为何保留不修**：R1–R5 只做最小返工；合并两函数会牵动全部评分档与 `TestFuzzyScoreTiers`（fs_resolve_test.go:23）的既有断言，收益只是可读性。
- **后续**：下次再动 `fuzzyScore`/`subsequenceScore` 时优先合并为单一 rune 版（入参先统一转 `[]rune`，边界判定一处），并补至少一条非 ASCII 路径的评分断言——现有用例只覆盖 ASCII，非 ASCII 下标错配不会被测出来。

### 4. 观察 D｜`scanWorkspaceFiles` 的 gitignore 基目录依赖调用方传「workdir 根」
- **现象**：gitignore 栈由 `newGitignoreStack(scanRoot)` 建（fs_resolve.go:156），`scanRoot` = 当前 workdir `wd`（`root` 传空时）或传入的 `root`（:149-155，且要求 root 在 wd 之内）；`newGitignoreStack`（fs_tools.go:670-674）只把给定 root 作为 base `.` 入栈、只加载该目录自身的 `.gitignore`，**祖先目录的 `.gitignore` 永不加载**（栈只随 walk 向下 push，见 fs_tools.go:676-685）。当前两个调用方都传安全值：`toolResolve` 传 `""`（fs_resolve.go:253）→ 每轮以 workdir 为根；`toolRelated` 传 `workspaceRootOf(abs, s.workdirs)`（:355；:466-473 返回命中的 workdir 根）→ 也是 workdir 根。**风险只在签名预留面**：一旦有调用方传子目录，父级 `.gitignore` 规则会整层丢失（忽略范围被静默放大）。
- **附注**：`workspaceRootOf` 命中不到任何 workdir 时返回 `""`，此时退化为遍历全部 workdir（每个 workdir 各自建栈，仍不丢层），不触发本项风险。
- **位置**：fs_resolve.go:140（签名）、:149-156、:253、:355、:466-473；fs_tools.go:670-685。
- **为何保留不修**：现有调用方均传 workdir 根，无现网行为差异；改签名（如强制传 workdir 根 + 子目录用相对过滤）会同时改动两处调用点与围栏语义，属独立改动的范围。
- **后续**：真要支持「只扫子目录」时，按「栈从 workdir 根起、用相对路径过滤」实现，并在 `scanWorkspaceFiles` 上加注释/断言声明 `root` 必须是某 workdir 根；在此之前不要新增传子目录的调用方。

### 5. 观察 E｜`"@foo"`（引号在外、`@` 在内）的剥除顺序残留 `@`，字面匹配 0 命中
- **现象**：toolResolve 先 `strings.TrimPrefix(query, "@")`（fs_resolve.go:242）再 `strings.Trim(query, "\"'")`（:243）。输入 `"@c.go"` 时第一步不生效（首字符是引号），第二步剥掉引号后查询里残留 `@`，而 `fuzzyScore` 是字面子串匹配 → 0 命中。现状已被断言锁住：`TestToolResolveQuotedAtReference`（fs_resolve_test.go:238）验证裸 `@c.go` 命中 `c.go`、带引号的 `"@c.go"` count=0。
- **位置**：fs_resolve.go:241-243；fs_resolve_test.go:238。
- **为何保留不修**：oracle 判定 reviewer 的「应修 4」不成立（属口径问题而非缺陷）；且反序剥除（先引号、后 `@`）会让带引号的引用与裸引用等价，是否与上游 pi-fff 的 `@` 引用语法一致尚未裁定，先按现状锁定行为。
- **后续**：等上游 pi-fff 口径裁定。若改为「剥引号后允许 `@` 前缀」，把 fs_resolve.go:242-243 换序（先 Trim 引号、再 TrimPrefix `@`），并**同步改** `TestToolResolveQuotedAtReference` 的 count=0 断言——那条断言是行为锁，改口径必须一起改，不能只改代码。

### 6. 观察 F｜5s 墙钟 deadline 分支未单独构造用例
- **现象**：预算与文件上限共用同一段 early-stop 代码路径——`if seen >= maxFiles || time.Now().After(deadline)` → 置 `truncated` 后 `SkipAll`（fs_resolve.go:158-163）；R4 之后该标志经 `(bool, error)` 返回并透出给调用方（:140、:212-221、:253-273）。上限分支有 `TestToolResolveTruncatedOnFileCap`（fs_resolve_test.go:206，置 `s.scanMaxFilesOverride = 2`）断言 `truncated=true`；**deadline 分支没有独立用例**，测试侧也没有可注入的预算变量（只有 `s.scanMaxFilesOverride`，fs_resolve.go:142-145），预算来自常量 `resolveScanBudget = 5 * time.Second`（:23）。
- **为何保留不修**：两分支落在同一行判定、同一段早停逻辑，上限分支已覆盖该代码路径；单独覆盖 deadline 要么给生产代码加时钟/预算注入缝（超出本轮返工范围），要么真等 5 秒（慢测）。
- **后续**：最小做法是照 `scanMaxFilesOverride` 增加一个测试专用预算覆盖字段（如 `scanBudgetOverride`），测试里置为 1ns 后断言 `truncated=true`；或重构时把早停判定抽成纯函数直接单测。

### 7. 既定口径（非缺陷）｜kept-out 字节只在经过 `storeIndexLocked` 的索引路径计数
- **口径**：kept-out 记账的唯一触发点是 `storeIndexLocked` 成功后调用 `statRecordKeptOut`（main.go:1818-1826，调用点 :1823）。两条写库路径绕开它、**因此不计入**：ctx_run action=batch 超限直存时直接调 `s.store.Index(label, storeOut)`（batch.go:572-582，调用点 :574）；ctx_kb fetch 经 `indexContentLocked` → `Store.ReplaceExactAndChunks`（fetch.go:588-604，调用点 :600；store 侧方法定义 store.go:876）。该口径已写进代码注释：`statRecordKeptOut` 上方（stats.go:60-64）、`Store.Index` 内（store.go:264-269）、`storeIndexLocked` 上方（main.go:1814-1817），文档侧亦按此对齐。
- **为何保留不修**：用户裁定「改文档对齐现状，不动写库路径」。两条直存路径各有自己的事务/标签语义（batch 需逐命令 label 与 `IndexError` 回填，fetch 需分块原子替换并保留旧文档），硬并入 `storeIndexLocked` 会把该函数的语义从「串行化写库 + 记账」扩成「全路径写库入口」，风险大于收益。
- **后续**：若将来要求 kept-out 全覆盖，应把记账**下沉到 Store 层**（`Store.Index` / `Store.ReplaceExactAndChunks` 内部处理），一处覆盖全部写路径；届时同步更新上述三处注释与 README 口径，避免注释与实现再次分叉。

### 8. 已被推翻的审计结论｜「175eb05 主题 78 字符超 hook 上限」（避免复发）
- **事实**：commit `175eb05` 的主题行整体 78 字节（`feat(tools): port ctx_stats and pi-fff resolve/related from upstream originals`），但 commit-msg hook 只量**冒号后的 subject**：`SUBJECT_LEN=$(printf '%s' "$SUBJECT_CONTENT" | wc -m | tr -d '[:space:]')` 与 72 上限比较，超限才 die（/root/.git-hooks/commit-msg:135-141）。该 commit 的 subject 为 65 字符，hook 对其实测 exit 0。
- **另核**：pre-push（/root/.git-hooks/pre-push）无任何主题长度检查（全文搜 `72`/`subject`/`length` 无命中），也不存在「推送时补刀」的第二道长度门禁。
- **为何保留不修**：结论本身不成立，无需任何代码或 hook 改动；此处落盘只为后续审计/复核不再按「整行长度」重复误报——判定主题长度请量 `SUBJECT_CONTENT`，不是整行 header。

### 9. 本轮审计项 → 处置对照表（防漏、防回改）
| 审计项 | 处置 |
| --- | --- |
| reviewer 致命 2（kept-out 漏记账） | 落为本笔记第 7 项**既定口径**（文档对齐现状，不动写库路径） |
| reviewer 应修 3（sibling 死代码） | **R2 已修**：评分 switch 里 sibling 档（40）提到 stem-prefix 档（30）之前，并加顺序说明注释（fs_resolve.go:367-370、:371-382），由 `TestToolRelatedSiblingBeatsStemPrefix`（fs_resolve_test.go:165）钉住 |
| reviewer 应修 4（`@` 与引号剥除顺序） | oracle 判不成立，落为本笔记第 5 项观察 |
| verifier staticcheck S1005（原 fs_resolve.go:339） | **R1 已修**：`pairExts, _ := relatedPairRules[...]` 改为 `pairExts := relatedPairRules[...]`（现 fs_resolve.go:354） |
| oracle 漏项 A（预算耗尽 truncated 恒 false） | **R4 已修**：`scanWorkspaceFiles` 返回 `(bool, error)`，早停置 `truncated` 并由调用方透出（fs_resolve.go:140、:158-163、:212-221、:253-273） |
| oracle 观察 1-5 | 落为本笔记第 1-4 项与第 8 项 |
| （本轮文档返工新增）`scanWorkspaceFiles` 的上限判定先于 `seen++`：cap=N 交付 N 个文件、截断点在「下一个被访问的条目」 | 落为本笔记第 10 项观察 G（记而不修，N−1 的说法已在第 10 项订正） |

### 10. 观察 G｜`scanWorkspaceFiles` 的上限判定先于计数：cap=N 交付 N 个文件，截断点落在「下一个被访问的条目」
- **现象**：上限/预算判定写在 walk 回调**最前面**（fs_resolve.go:158 `if seen >= maxFiles || time.Now().After(deadline)`），计数与交付在其后（:206-209：通过全部围栏后 `seen++`、`fn(p)`）。因此语义是「先交付满上限，再在**下一个被访问的条目**上中止」：置 `truncated = true`（:161）后 `return filepath.SkipAll`（:162）。`seen` 只在通过 `skipWalkDirs` 剪枝、工作区/符号链接围栏、敏感闸门、`.gitignore` 之后自增（本函数内没有 glob 过滤这道围栏，glob 过滤发生在 `toolGlob` 的 walk 里），所以被围栏丢掉的条目同样参与触发中止。
- **后果 1（交付数）**：合格文件数 ≥ 上限时交付数**恰好 = cap**，不是 cap−1。实测（一次性探针，经 `go test -overlay` 挂在 /tmp，不入仓）：平铺目录里 5 个 `*_match.go`，cap=1/2/3/4 分别交付 1/2/3/4 个文件，`truncated` 均为 true。
- **后果 2（截断点与目录）**：中止发生在「下一个被访问的条目」上，而 `filepath.Walk` 的条目包含目录：该条目若为目录，它的**整棵子树连同其后的所有兄弟**都不再遍历（实测：`a/1.go`、`a/2.go`、`b/3.go`、`b/4.go`，cap=2 → 交付 `1.go`、`2.go`，`b/` 从未进入）。由此 `truncated=true` 只表示「walk 被上限/预算打断」，**不等于确有候选文件被丢弃**——触发中止的条目可能是目录，也可能是一条本会被 `.gitignore`/敏感闸门丢掉的条目（:158 的判定早于 :173-205 的全部围栏）。
- **订正（实测，与审计初述不符）**：审计初述写作「cap=N 时最多只交出 N−1 个文件」，实测不是——判定在 `seen++`（:207）之前意味着「已交付满 N 个」才会中止，交付数为 N；N−1 只会出现在「判定改成 `seen+1 >= maxFiles`」的写法下。证据即上面后果 1 的实测。
- **既有语义，非 R4 引入**：R4 之前早停直接 `return filepath.SkipAll`（`filepath.Walk` 把 SkipAll 吞成 nil），上限判定位置、交付数与中止点完全相同，只是调用方看不出结果被截断；R4 把这个半截结果标成 `truncated: true`，未改上限语义与计数。R5 的用例 `TestToolResolveTruncatedOnFileCap`（fs_resolve_test.go:206）只断言 `count < 3`（:226）与 `truncated == true`（:229-231），没有钉住精确计数，因此「cap=N → 交付 N」这一边界目前无断言守护。
- **位置**：fs_resolve.go:140（签名）、:142-145（上限来源 `resolveMaxFiles` / `scanMaxFilesOverride`）、:148-155（按 workdir 轮转）、:158（上限/预算判定）、:161-162（`truncated` / `SkipAll`）、:206-209（`seen++` / `fn(p)`）、:215-219（早停后直接返回）；fs_resolve_test.go:206、:226、:229-231。
- **为何保留不修**：改成「恰好交出 N 个且不丢任何候选」需要先裁定口径——上限是对**交付数**还是对**访问数**、目录子树是否允许被整段丢掉；两种改法都会改变 resolve/related 的结果集与 `truncated` 语义，且 related 侧还要重核与 `limit` 的交互，超出本轮返工范围。
- **后续**：若只是钉住现状，把 `TestToolResolveTruncatedOnFileCap` 的 `count < 3` 收紧为 `count == 2`（cap=2 时），并补一条「平铺目录下合格文件数恰为 cap 时 delivered == cap 且 `truncated == false`」的用例（有后续目录条目时后一条不成立，见后果 2）；若要改口径，先裁定「上限算交付还是算访问」，再动 :158 的判定位置。

## 被放弃的方案（必填）
- 方案 A：**顺手把观察 A–G 一次性修掉**。否决：观察项里 A/C/D 属语义脆弱但功能无误，B/E 的口径归上游 pi-fff 裁定，F/G 的补测要动生产代码加测试缝——一并修会把「审计返工」扩成「重新设计 resolve/related 围栏」，且 R1–R5 的验证范围会再次失效；本轮任务边界明确只落盘不改动。
- 方案 B：**把观察项写进 README 或 CHANGELOG 的 [Unreleased]**。否决：README 面向使用者、CHANGELOG 面向变更史，观察项既非对外契约变更也非已发生的行为变更；按本目录惯例（`.agents/notes/README.md` 六条触发里的「临时降级/特判/与 upstream 的故意分歧」）应落在笔记。
- 方案 C：**把观察项改成 TODO 注释散落在源码里**。否决：注释随重构漂移、无日期与归属，且会改动源码（本轮不允许改源码）；笔记是唯一可检索、可与 INDEX.md 联动的位置。
- 方案 D：**为 5s deadline 分支现在就加 `scanBudgetOverride` 测试缝**。否决：为一条观察项改生产代码的测试面，超出「只落盘」的边界；已作为第 6 项的后续动作登记。

## 来源
- 审计对象：commit `175eb05e16b16d134168ee6b36a1544f32ce05ee`（`feat(tools): port ctx_stats and pi-fff resolve/related from upstream originals`，subject 65 字符）；返工分支 `fix/175eb05-audit-rework`（R1–R5，本笔记写作时未提交）。R1–R5 触及的 **7 个**文件为 M：CHANGELOG.md、README.md、fs_resolve.go、fs_resolve_test.go、main.go、stats.go、store.go；其后 docfix 轮另追加 `router.go` 与 `.agents/notes/20261007-port-features-from-originals.md` 的订正标注，提交时 `git status` 为 **9 个 M** 加本笔记（未跟踪）。
- 代码位置（返工后行号）：fs_resolve.go:23、:51、:58、:91、:104-115、:140-163、:172-185、:206-209、:212-221、:236-243、:253、:354-382、:417-473；fs_tools.go:405-420、:670-685、:1627、:1771-1826；main.go:1530-1570、:1814-1826；stats.go:60-64；store.go:264-269、:876；batch.go:572-582；fetch.go:588-604；fs_resolve_test.go:23、:96、:140、:165、:206、:226、:238。
- 门禁依据：/root/.git-hooks/commit-msg:135-141（主题长度只量 `SUBJECT_CONTENT`）、/root/.git-hooks/pre-push（无主题长度检查）。
- 口径来源：用户裁定「改文档对齐现状，不动写库路径」（第 7 项）；oracle 判「reviewer 应修 4 不成立」（第 5 项）；三方审计结论与 R1–R5 的对应关系见第 9 项对照表。
