---
status: active
superseded_by: ""
supersedes: ""
模块: "scripts"
---

# L2 基线 `make check` 收口：门禁发现闭环与四条复发模式留痕

## 一句话结论
本轮在 `chore/baseline-l2-make-check` 收口 C 档 R1 oracle/reviewer 全部代码与文档发现：`Makefile` 修复 `gofmt` 命令替换吞退出码（oracle S1）并新增 `staticcheck` 前置快检；`.gitignore` 反选根锚定（oracle C2）；`AGENTS.md` 写明 `staticcheck@2025.1.1` 与 CI 对齐（oracle C3）；四条复发模式（含两条跨仓 2/2、两条存量观察）按下述决策留痕。

## 背景
`d5a99a8` 已完成 L2 基线收敛（`Makefile check` 单一入口 + `ci.yml` 瘦身为 `make check`）。C 档门禁 R1 复检提出：
- oracle `S1`（should-fix）：`files="$$(gofmt -l .)"` 赋值只捕获 stdout，`gofmt` 对带 `//go:build ignore` 等非本机标签遮蔽的语法错文件把诊断打 stderr、stdout 为空且退出码 2 被命令替换丢弃，`make check` 全绿逃逸；
- oracle `C2`：`!AGENTS.md` 未根锚定，子目录同名文件会被意外解除忽略；
- oracle `C3`：CI 固定 `staticcheck@2025.1.1`（`ci.yml`），本机 `make check` 依赖 `$(go env GOPATH)/bin/staticcheck` 存在性但未写明版本；
- reviewer：验证报告条目为 verifier 产物内部计数偏差（`/root/.dev-baseline/gate-ctxmode-b34-verifier.txt`），属仓外证据文件，不在本 worktree 改动范围，回主代理处理。

## 决策
四条模式标签与处置：

1. **`[pattern:posix-only-check-entry]`**（跨仓 2/2 复发，首例 `codegraph-go`）：`Makefile` `check:` 采用 POSIX shell 语法与 `go build -o /dev/null`，当前目标平台为 Linux/macOS；原生 Windows 未来按需扩展，不在本轮引入平台分支。
2. **`[pattern:makefile-cmdsub-exit-swallow]`**（跨仓 2/2 复发，首例 `codegraph-go`）：`files="$$(gofmt -l .)"` 缺 `|| exit $$?`，吞掉 `gofmt` 语法错退出码 2；本轮已修复为 `files=... || exit $$?`，并建议下沉为 `dev-audit` 静态检查规则（Makefile recipe 内命令替换赋值必须传播退出码）。
3. **`[pattern:mcp-cli-immediate-eof-race]`**（oracle `CM2` 存量观察）：`ctxmode` CLI 在 stdin 立即 EOF 时偶发关闭竞态返回 `rc=1` `"server is closing: EOF"`；`deploy.sh` 已用 `sleep 1` 规避。属存量行为，不在基线收敛分支改动业务代码，留待独立修复。
4. **`[pattern:ctxmode-bg-log-collision]`**（验证期新发现存量缺陷）：`executor.go:263` 后台任务日志固定写 `filepath.Join(os.TempDir(), "ctxmode_bg_" + id + ".log")` 且每实例任务 id 从 `bg-1` 起算；多实例或 `go test` 内层单测共享 `/tmp` 时同名覆盖/误删。留待后续独立 fix 分支按进程实例随机前缀隔离（`executor.go:2663` 已有 `os.CreateTemp` 随机名路径可循）。

## 被放弃的方案（必填）
- **本分支顺手修 `ctxmode_bg_` 日志碰撞**：否决。属存量业务代码缺陷，超出基线收敛分支授权范围，改业务代码会扩大本分支评审面。
- **`!AGENTS.md` 保持非锚定写法**：否决。子目录 `AGENTS.md`（如后续嵌套文档约定）会被意外解除全局忽略；根锚定零成本且语义精确。
- **`check:` 前置快检改为静默失败或仅用 `command -v staticcheck`**：否决。快检必须验证 `$(go env GOPATH)/bin/staticcheck` 可执行（与 recipe 实际调用路径一致），且明确打印安装命令，避免 make 的 `command not found` 报错掩盖真实缺项。

## 来源
`Makefile`、`AGENTS.md`、`.gitignore`、`CHANGELOG.md`；门禁文件 `/root/.dev-baseline/gate-ctxmode-b34-oracle-r1.txt`（S1/C2/C3/CM2）、`/root/.dev-baseline/gate-ctxmode-b34-reviewer-r1.txt`；`executor.go:34,263,2663`；`deploy.sh`（`sleep 1` 规避）。
