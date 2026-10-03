---
status: active
superseded_by: ""
supersedes: ""
# 可选模块: ctx_run, ctx_fs, ctx_git, ctx_kb, ctx_bg, floodguard, store, executor, router, cli, integrations/pi, githooks, scripts
模块: githooks
---

# commit gate 的 diff 文件头判定改为结构判定

## 一句话结论

全局 commit gate（`/root/.git-hooks/commit-msg`、`/root/.git-hooks/pre-push`）里"只扫新增行"的文件头过滤，从**前缀匹配**改成**结构判定**（awk 状态机：`diff --git` 重置状态、`@@ ` 进入 hunk、hunk 外紧跟 `--- ` 的 `+++ ` 才算文件头）。上一轮笔记留下的两条残留（内容以 `++ b/…`、`++ /dev/null …` 开头的新增行被当成文件头整行丢掉）就此消除，上一轮接受的两处**误报**也一并消除：`diff.noprefix`/`diff.mnemonicPrefix` 下真文件头未被过滤而存活，密钥形状的**文件名**因此被误扫（默认前缀下文件名本就不扫，见"残留"），改前缀后真文件头同样不再存活。同一轮把凭据赋值的取值由"分隔符后到行尾（贪心）"收敛为"分隔符后**第一个非空白 token**，再裁引号/空白"，保留既有 ≥6 长度门槛与占位符豁免；同一轮后半段又收口了赋值判定里两处窄逃逸（`=>` 分隔符、`SECRET_KEY`/`PASSWORD_HASH` 这类关键字后缀，见"决策"第 4 节），取值规则本身未再变。

与旧笔记的关系：本笔记**只取代** `20260930-audit-review-fixes-round2.md` 中关于 hook 文件头过滤的那段结论（第 49、52 行，含其"残留①/②"与"极窄新残留"）。该笔记的其余结论（审计字段、RLIMIT 用例、`O_NONBLOCK` 边界等）仍然有效，因此**未改该笔记的 frontmatter、未标记 superseded**，也不改写其正文（遵守"只加补记/新条目"的维护规范）。

## 背景

- 2026-09-30 那一轮把判据锚定成 `^+++ \(b/\|/dev/null\)`，并把两条残留按"只会误报、不会漏报"接受：内容恰为 `++ b/…` 的新增行会被当文件头误丢；`diff.noprefix` / `diff.mnemonicPrefix` 会让真文件头存活而多扫一次文件名。
- 本轮要求反过来：内容以 `++ b/`、`++ /dev/null`、`++ `、`++`、`+++` 开头的新增行**都不再被丢**，同时两种改前缀环境下真文件头仍被正确跳过。
- 另一处误报来自取值：`check_credential_assignments` 取"分隔符后到行尾整段"，于是笔记/文档里一句普通说明（关键字 + `=` + 一段英文说明）只要整段 ≥6 字符就被判成硬编码凭据。

前缀与内容同形是根因：`git diff` 给新增行加一个 `+`，所以内容 `++ x` 渲染成 `+++ x`，与文件头**字节相同**。任何"再加一条前缀规则"的做法都只是把漏报换个拼写。

## 决策

### 1) 结构判定（两个 hook 的 `added_lines_only` 逐字相同）

`printf '%s\n' "$1" | awk` 状态机：

| 当前行 | 条件 | 动作 |
| --- | --- | --- |
| `/^diff --git /` | 任意状态 | `state=0; minus=0`（每个文件开头重置） |
| `/^@@ /` | `state==0` | `state=1`（进入 hunk） |
| `/^@@ /` | `state==1` | 跳过（同文件的下一个 hunk 头） |
| `/^--- /` | `state==0` | 记为"上一行是 `--- `"（`minus=1`） |
| `/^[+][+][+] /` | `state==0` 且 `minus==1` | 真文件头，丢弃 |
| 其余 | `state==0` | 丢弃（`index`/`new file mode`/`diff --git` 等元数据） |
| `/^[+]/` | `state==1` | 打印（保留行首 `+`，与旧输出一致，下游扫描器一行未改） |

**为什么必须带 hunk 状态**：hunk 内"删除行内容 `-- x`"渲染成 `--- x`、"新增行内容 `++ y`"渲染成 `+++ y`，两行相邻。只按"紧跟 `--- ` 之后的 `+++ ` 就是头"判，会把真新增行误丢 —— 正是要修的类。用 `state==1` 把 hunk 内容整段豁免，判据只作用于 hunk 之外的文件头位置。

### 2) 取消下游的前缀跳过

`commit-msg` 的 `check_credential_assignments` 删掉 `case "+++ b/"*|"+++ /dev/null"*|"---"*|"@@"*) continue`，`pre-push` 的 `check_commit_assignments` 删掉 `case "+++"*|"---"*|"@@"*|"-") continue`。喂进这两个函数的文本已由 `added_lines_only` 结构去头，留下前缀跳过只会把内容以 `++ ` 开头的新增行**再丢一次**（`pre-push` 的 `"+++"*` 尤其宽：任何内容以 `++` 开头的新增行都被整行跳过）。

### 3) 取值收敛（B2）

`rest` = 用原有 `sed` 切掉到最后一个关键字 + 分隔符的部分；再 `sed -E 's/^[[:space:]]+//; s/[[:space:]].*$//'` 取**第一个非空白 token**；再沿用原有两条 `sed` 裁首尾引号/反引号/空白与尾部 `;,`。≥6 长度门槛、`""`/`none`/`optional`/`removed`/`changeme`/`<…>`/`$…` 等豁免**原样保留**。单 token 的真赋值（无空格的密钥串、被引号包住的密钥串）依旧被拒。

### 4) 凭据赋值判定的两处窄逃逸收口（同一轮补做）

判定正则两侧同步改（`grep` 与 `sed` 各一处、两个 hook 各自一对，`commit-msg` 的 `check_credential_assignments` 与 `pre-push` 的 `check_commit_assignments` 逐字一致）：

- 旧：`(password|api_key|secret)[[:space:]]*[:=]+[[:space:]]*`
- 新：`(password|api_key|secret)[A-Za-z0-9_]*[[:space:]]*[:=]+>?[[:space:]]*`

两处逃逸因此关闭：

1. **分隔符不认箭头形**：`[:=]+` 只消费掉 `=`，`>` 落在值侧并成为"第一个 token"（1 字符），低于 ≥6 门槛 —— 于是 `password` 后接 `=>` 再跟真值的写法被放行。新式 `[:=]+>?` 覆盖 `=>`/`:=>`，取到的是真值 token。
2. **关键字后被标识符后缀紧跟**：关键字后既非空白也非分隔符时整条规则不触发，于是 `SECRET_KEY`、`PASSWORD_HASH`、`API_KEY_ID` 这类命名逃过检查。新式 `[A-Za-z0-9_]*` 允许后缀。

取舍：关键字仍按**子串**匹配、不加词边界（`mysecret`/`client_secret` 之类本来就会被拒），因此允许后缀会让"仅含关键字的普通词 + 赋值"也进入被拒侧；`secretary` 由放行变拒即属此类，理由与代价见"验证"里的单列条目。取值规则（第一个非空白 token）、≥6 门槛、占位符/环境变量/`none` 豁免**均未改动**。

### 5) 模板 pre-commit 同步（同一轮补做）

`/root/.git-templates/hooks/pre-commit`（真实文件，非指向 `/root/.git-hooks` 的符号链接）含同一类前缀过滤。

**实测更正（2026-10-03，作者自查，此前判断有误）**：本笔记初稿在此写过「全局 `core.hooksPath=/root/.git-hooks` 会整体覆盖 `.git/hooks`，该文件实际不生效」，该判断是错的，现按实测事实更正——本仓 `.git/config` 带**仓本地覆盖** `core.hooksPath=/root/.git-templates/hooks`，本仓生效的 hooks 目录就是它；该目录里 `commit-msg`、`pre-push` 是指向 `/root/.git-hooks/` 的**符号链接**，而 `pre-commit` 是**真实可执行文件**——所以**本仓生效的 pre-commit 正是这个文件，它在生效**。全局 `/root/.gitconfig` 的 `core.hooksPath=/root/.git-hooks` 里**没有** pre-commit，因此只有「没有仓本地覆盖」的仓才不会跑 pre-commit。实测命令与原始输出：

```text
$ git config --local --get core.hooksPath
/root/.git-templates/hooks
$ git config --global --get core.hooksPath
/root/.git-hooks
$ git config core.hooksPath            # 本仓生效值
/root/.git-templates/hooks

$ ls -l /root/.git-templates/hooks/
总计 16
lrwxrwxrwx 1 root root   27  9月17日 09:58 commit-msg -> /root/.git-hooks/commit-msg
-rwx--x--x 1 root root 3398 10月  3日 14:31 pre-commit
-rwx--x--x 1 root root 1317  7月  5日 15:35 pre-commit.bak-20260930092955
-rwx--x--x 1 root root 1318  9月30日 09:30 pre-commit.bak-20260930094017
-rwx--x--x 1 root root 1335  9月30日 09:40 pre-commit.bak-20261003143116
lrwxrwxrwx 1 root root   25  9月17日 09:58 pre-push -> /root/.git-hooks/pre-push

$ ls -l /root/.git-hooks/             # 该目录内没有 pre-commit
总计 92
-rwxr-xr-x 1 root root 12202 10月  3日 14:53 commit-msg
-rwxr-xr-x 1 root root  8977  9月17日 09:57 commit-msg.bak-20260930082550
-rwxr-xr-x 1 root root 10355  9月30日 08:47 commit-msg.bak-20260930094017
-rwxr-xr-x 1 root root 10714  9月30日 09:40 commit-msg.bak-20261003141636
-rwxr-xr-x 1 root root 11749 10月  3日 14:17 commit-msg.bak-20261003145322
-rwxr-xr-x 1 root root  6740 10月  3日 14:53 pre-push
-rwxr-xr-x 1 root root  4447 10月  3日 13:56 pre-push.bak-20261003-055646
-rwxr-xr-x 1 root root  5259 10月  3日 13:57 pre-push.bak-20261003141636
-rwxr-xr-x 1 root root  6236 10月  3日 14:17 pre-push.bak-20261003145322
```

**本笔记成稿后、同一轮内它已被改成与两个全局 hook 逐字相同的 awk 状态机**：改后 sha256 `2b8b4be7dfba7d1546c4ca766f1391522e14b5aa1d6591f3c21f7f95af517245`，改动前副本 `/root/.git-templates/hooks/pre-commit.bak-20261003143116`，端到端差分回归 `TOTAL ok=25 bad=0`（见"验证"）。它**只**匹配已知密钥格式、**没有**凭据赋值扫描，所以上面第 3)、4) 两节针对赋值判定的规则与它无关，也没有为它新增赋值检查。

## 验证（原始证据，全部在 /tmp 一次性跑）

- `sh -n commit-msg`、`sh -n pre-push`：均通过。
- **过滤层差分**（对真实 `git diff --cached`，三种前缀环境，旧 `added_lines_only` 取自 `commit-msg.bak-20261003141636`）：
  - 默认前缀：NEW 输出 = 内容行（`+++ <密钥>`、`+++ b/<密钥>`、`+++ /dev/null <密钥>`、`+++ 赋值式`）+ `+benign`/`+BETA2`，真文件头（`+++ b/…`、`+++ b/<密钥>.txt`）被丢；OLD **丢掉** `+++ b/<密钥>`、`+++ /dev/null <密钥>`（漏报）。
  - `diff.noprefix=true`：NEW 同默认前缀（真头 `+++ keep.txt`、`+++ tricky.txt`、`+++ <密钥>.txt` 一律被丢）；OLD 把这三个**真文件头当内容扫**（误报）且仍丢 `++ b/`、`++ /dev/null` 两种拼写。
  - `diff.mnemonicPrefix=true`：同上，OLD 把头 `+++ i/…` 当内容扫。
  - 手写最小 diff：真头对（`--- f` / `+++ f`）两版都丢；两文件 diff 的第二个头两版都丢。新旧输出逐字节一致（除已修的两类）。
- **旧/新 hook 端到端差分**（同夹具，hook 版本由 repo 局部 `core.hooksPath` 切换；旧版为备份副本）：

  | 夹具 | 旧 hook | 新 hook |
  | --- | --- | --- |
  | staged 新增行内容 `++ b/<密钥>` | rc=0 放行（漏） | rc=1 拒 |
  | staged 新增行内容 `++ /dev/null <密钥>` | rc=0 放行（漏） | rc=1 拒 |
  | push 提交新增行内容 `++api_key` + 赋值 | rc=0 放行（漏） | rc=1 拒 |
  | staged 文档句式（关键字 + `=` + 英文说明） | rc=1 误报 | rc=0 放行 |
  | noprefix 下密钥形状文件名 | rc=1 误报 | rc=0 放行 |

- **45 例端到端矩阵全绿**（真实 `git commit` / `git push`，全局 hook 生效）：staged 15 例（5 种 `++` 开头内容在默认/noprefix/mnemonicPrefix 下都拒；增/改/删三种头正常放行；删除行带密钥放行；上下文行带密钥放行；密钥形状文件名放行；两环境干净提交放行）；取值 5 例（文档句式放行、真赋值拒）；消息侧 13 例（类型白名单、大小写、冒号后恰一空格、80 字符主题拒/72 字符放行、噪声词、消息体真赋值拒、消息体文档句式放行）；push 12 例（含 `++` 开头内容、赋值式、删除行、上下文行、三环境）。
- 取值层直接对拍（同一行喂旧/新函数体）：真赋值两版都拒；文档句式旧拒新放行；新值确实等于"第一个 token"（旧值等于整段行尾）。
- **A1/A2 收口回归**（`/tmp/hook-regress/sepkw.sh`，同一行喂旧/新函数体、两个 hook 各测一遍，20 例）：
  - 5 条新增必拒：`password` 后接 `=>`（带引号/不带引号各一）、`SECRET_KEY`、`PASSWORD_HASH`、`API_KEY_ID` —— 旧版（备份）全放行、新版全拒。
  - 7 条原必放行（`$GITHUB_TOKEN`、`${API_KEY}`、`<your-key-here>`、`changeme`、`""`、`use the vault helper`、`see`）与 4 条原必拒（`hunter2secret`、`abcdef123456`、带 `# comment`、带 `;`）两版结果完全一致。
  - `TOTAL ok=20 bad=0`。
- **有意行为变化（单列）**：`secretary = <6字符值>` 由**放行变拒**（旧版 ACCEPT、新版 REJECT）。A2 允许关键字后紧跟标识符后缀，而关键字是无词边界的子串匹配，`secretary` 里的 `secret` 也被算作关键字 —— 这是既有的偏严侧在 A2 之后的自然延伸（`mysecret`、`client_secret` 早已是拒）。取舍理由：宁可对这类普通词偏严（误报可读、只挡本地一次提交），也不放过 `SECRET_KEY`/`PASSWORD_HASH` 这种真实命名（漏报会把凭据写进历史）。
- **残留项逐条实测**（`/tmp/hook-regress/residuals.sh`）：关键字子串无词边界（`mysecret`、`client_secret` 新旧都拒；`secretary` 放行变拒）；hunk 头 `@@ … @@ <函数上下文>` 整行跳过（含密钥形状函数上下文的 hunk 头不进扫描，`added_lines_only` 只留 `+added line`）；二进制内容不扫（staged 二进制里带密钥形状串，diff 只有 `Binary files … differ`，`rc=0` 放行）；缺 `diff --git` 的 diff 让下一个文件的 `+++ ` 头当内容保留（只会误报）；`--- ` 前缀行的理论残留在本机 git 2.47.3 上未能构造出（见"残留"）。
- **45 例端到端矩阵重跑**（`/tmp/hook-regress/e2e.sh`，A 收口之后）：`TOTAL ok=45 bad=0`。
- **模板 pre-commit 25 例重跑**（`/tmp/hook-regress/precommit.sh`）：`TOTAL ok=25 bad=0`，文件 sha256 仍为 `2b8b4be7…`（本轮只读未改）。
- `sh -n commit-msg`、`sh -n pre-push`：改动后重跑，均通过。

## 被放弃的方案（必填）

1. **继续收窄前缀**（例如再排除 `++ b/`、`++ /dev/null` 之外的新拼写）：前缀与内容同形，枚举永远追不上漏报的下一个拼写。
2. **只按相邻行判头**（`--- ` 后紧跟的 `+++ ` 即头，不看 hunk 状态）：hunk 内 `-- x` + `++ y` 会被误判成头，新增一条漏报。
3. **保留下游前缀 `case` 作为"纵深防御"**：输入已被结构去头，保留它只会重新引入"内容以 `++ ` 开头的新增行被丟"的漏报，纯负收益。
4. **取第一个 token 用 `awk '{print $1}'` 或 `cut -d' ' -f1`**：为不在 hook 里引入新工具/不踩 tab 分列，改为纯 `sed` 两步，行为等价。
5. **给 `++` 内容行加"转义标记"**：需要改 `git diff` 输出或调用方式，成本远超收益。

## 残留（实测确认版）

**本轮已修（此前属本类逃逸，现已在两个全局 hook 关闭）**

- **分隔符不认箭头形**：`password` 后接 `=>` 再跟真值时，`>` 被当成第一个 token 而低于门槛。分隔符判定已扩为 `[:=]+>?`（覆盖 `=>`/`:=>`），见"决策"第 4 节。
- **关键字后被标识符后缀紧跟**：`SECRET_KEY`、`PASSWORD_HASH`、`API_KEY_ID` 这类命名此前不触发规则。关键字后已允许 `[A-Za-z0-9_]*`。

**仍保留（逐条实测）**

- 关键字按**子串**匹配、不加词边界：`mysecret = <6字符值>`、`client_secret = <6字符值>` 一直会被拒；A2 之后 `secretary = <6字符值>` 也进入被拒侧（"验证"里有单列条目与理由）。属偏严侧，代价是本地提交被挡、报错可读。
- 赋值右侧**第一个 token ≥6 字符**仍会被拒 —— 若文档句式恰好在关键字 + 分隔符之后紧跟一个 6 字符词，仍会误报。这是"保留 ≥6 长度门槛"的直接代价，属有意保留（矩阵里 `password` 后跟 `rotate` 那例即此）。
- hunk 头 `@@ … @@ <函数上下文>` 整行跳过：函数上下文里若恰好含密钥形状的赋值，不参与扫描（扫描范围只有新增行）。
- **二进制内容不扫**：`git diff` 对二进制只输出 `Binary files … differ`，没有可扫的新增行，密钥形状的二进制内容因此不会被拦。
- 缺 `diff --git` 行的 diff 格式（例如 `git diff --no-index`）会让后续文件的真文件头被当内容扫描，**只会误报**；两个 hook 的调用点只用 `git diff --cached` 与 `git show --format=`，不涉及。
- 密钥形状的**文件名**仍不被扫（默认前缀下文件头整行被跳过，保持低危）；上一轮在 `diff.noprefix`/`diff.mnemonicPrefix` 下的那处**误扫**已随结构判定一并消除，两者不再字面对立。
- "git 发出 `--- ` 前缀行"仅作理论残留列出：本机实测 git 2.47.3，未能构造出 hunk 外、非文件头的 `--- ` 输出行（本笔记初稿依据的"2.39.5"与本机实测版本不符，此处以实测为准）。
- 仓内 `githooks/` 镜像（`githooks/commit-msg`、`githooks/pre-push`）**未同步**，仍是可被 `githooks_test.go` 测的旧实现；本轮范围只覆盖全局 hook（任务明确要求不动镜像）。

**第二轮复验新测得的窄形状（只记录、不修）**

- `password -> v12345`、`password =>> v12345`、`password = > v12345`、`password => => v12345` 放行：分隔符消费后若值侧仍以单个符号（`-`、`>`）开头，它成为"第一个 token"，低于 ≥6 门槛。`->` 不是任何语言的赋值运算符（Perl/Ruby 的 `->` 是解引用、`=>` 才是哈希赋值），`=>>`、`= >` 属同族伪形状；三者若值命中 `sk-`/`AKIA` 等已知格式仍被模式层拦。
- 判据：**只记录不修**——再扩分隔符表边际收益递减，且"首 token 为单字符符号时取第二个 token"会改变取值语义。

**第二轮对抗复验观察项（只记录；来源：第二轮对抗复验，oracle 原会话，2026-10-03，`bd83f34` 之后）**

- **R1**：笔记与 CHANGELOG 说“没有仓本地覆盖的仓不跑 pre-commit”时未提示：那些仓的 commit-msg 阶段仍会用 `git diff --cached` 扫密钥模式（oracle 实测 `/root/.git-hooks/commit-msg` 自身会拦 `ghp_` 形状），读者不应据此推出“密钥不设防”。
- **R2**：`fixes_test.go` 的 `TestVersionAligned` 是硬编码字面量比对、不解析 CHANGELOG，能抓“忘记 bump Version”但抓不到“Version 改了而 CHANGELOG 标题没改”，下次发版可考虑让测试读 CHANGELOG 首个版本标题。
- **R3（锚点已更正，2026-10-03）**：本条初稿曾写「CHANGELOG 的 `[4.1.0]` 历史段保留的 `global pre-commit` 旧措辞是有意不改（历史段落不清洗）」，该锚点经实测有误——CHANGELOG 里的 `pre-commit` 字样只出现在 `[4.2.0]` 段，`[4.1.0]` 段（第 46-60 行）没有任何 `pre-commit` 字样；那句 `global pre-commit` 是同一次事实误判的产物，且早已在 `bd83f34` 更正。保留的原则仍成立：历史发版段落不清洗，本轮无需为此清洗任何历史段落，判定可接受。

## 来源

- 备份（结构判定那一轮）：`/root/.git-hooks/commit-msg.bak-20261003141636`、`/root/.git-hooks/pre-push.bak-20261003141636`（改动前 sha256 见当次回报）。
- 备份（本轮分隔符/关键字收口之前）：`/root/.git-hooks/commit-msg.bak-20261003145322`（sha256 `4b054371015f9ff8101826e8f21e02e242fcb2302191d0d25f21b3cbf77896a6`）、`/root/.git-hooks/pre-push.bak-20261003145322`（sha256 `85beff271a5cf4b78fdc81ff3b2d4a267bdd72276cd55b9756110f097aa0eb64`）；模板 hook 改动前副本 `/root/.git-templates/hooks/pre-commit.bak-20261003143116`。
- 上一轮笔记：`.agents/notes/20260930-audit-review-fixes-round2.md`（第 49、52 行，本文取代其 hook 文件头过滤结论）。
- 一次性回归脚本：`/tmp/hook-regress/{filters,credval,e2e,olddiff,precommit,sepkw,residuals}.sh`（未入仓，属一次性中间产物）。
- 本节形状来自第二轮复验（oracle 原会话，2026-10-03，`f0c6050` 之后）。
