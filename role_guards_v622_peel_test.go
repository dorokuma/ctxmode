package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// role_guards_v622_peel_test.go — v6.2.2 regression tests: wrapper peeling, env/cwd propagation,
// Python/JS long-option parsing, exec-slot recursion, and Oracle R1–R4 probes.
// (Migrated losslessly from zz_r2fix_test.go; the three v622 files concatenated
// reproduce the original test bodies exactly.)

// ---------------------------------------------------------------------------
// v6.2.2 待办 1: Python `--` 长选项解析统一收敛 —
// --check-hash-based-pycs 两种形态（=val / 空格分隔）在任何守卫入口都不再
// 逃逸，未知 Python `--` 长选项保守 fail-closed，合法查询长选项保持放行。
// ---------------------------------------------------------------------------

func TestGuard_V622_PythonLongOpts(t *testing.T) {
	blockCases := []struct {
		name, role, ro, cmd string
		want                string
	}{
		// 粘连值形态：基线误把 heck-hash-based-pycs=default 当 -c 载荷放行。
		{"v622-1a glued -c", "worker", "", `python3 --check-hash-based-pycs=default -c 'import os; os.system("pig")'`, "python"},
		// worker+ro=1（strict readonly verifier 模型）：基线漏审 python 写文件载荷。
		{"v622-1b verifier write", "worker", "1", `python3 --check-hash-based-pycs default -c "open('out.txt', 'w')"`, "python"},
		// worker 嵌套代理守卫：-c 载荷含 pig，基线借长选项逃逸。
		{"v622-1b2 worker subagent write", "worker", "", `python3 --check-hash-based-pycs default -c "open('out.txt', 'w'); import os; os.system('pig')"`, "python"},
		// 空格分隔形态："default" 不得提前终止选项区扫描。
		{"v622-1c xargs -c feed", "worker", "", `echo 'import os; os.system("pig")' | xargs python3 --check-hash-based-pycs default -c`, "BLOCK"},
		{"v622-1d find -exec -c", "worker", "", `find . -exec python3 --check-hash-based-pycs default -c '{}' \;`, "BLOCK"},
		{"v622-1e1 -m after long", "worker", "", `python3 --check-hash-based-pycs default -m pig`, "pig"},
		{"v622-1e2 -um glued", "worker", "", `python3 -um pig`, "pig"},
		// 未知 Python 长选项（--jit off）：操作数 arity 不可知，fail-closed。
		{"v622-1f unknown long", "worker", "", `python3 --jit off -c 'import os; os.system("pig")'`, "BLOCK"},
		{"v622-1f2 missing mode", "worker", "", `python3 --check-hash-based-pycs -c 'print(1)'`, "BLOCK"},
		{"v622-1f3 bad mode", "worker", "", `python3 --check-hash-based-pycs=bogus -c 'print(1)'`, "BLOCK"},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: tc.role, ro: tc.ro, cmd: tc.cmd}, "")
			if tc.want == "BLOCK" {
				if got == "ALLOW" {
					t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want substring %q", tc.cmd, got, tc.want)
			}
		})
	}
	allowCases := []struct {
		name, role, ro, cmd string
	}{
		{"worker python3 --version", "worker", "", `python3 --version`},
		{"verifier python3 --version", "verifier", "", `python3 --version`},
		{"worker python3 --help-all", "worker", "", `python3 --help-all`},
		{"worker pycs then --version", "worker", "", `python3 --check-hash-based-pycs=default --version`},
		{"worker pycs benign -c", "worker", "", `python3 --check-hash-based-pycs default -c 'print(1)' "$HOME"`},
		{"worker script custom flag", "worker", "", `python3 app.py --custom-flag val`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: tc.role, ro: tc.ro, cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// v6.2.2 待办 2: JavaScript 族拆族 — bun/ts-node/tsx 不再与 node/nodejs
// 共享结构族；跨名软链（bun -> node）conflicting structural alias fail-
// closed，真实 bun/tsx 自身的 -p/--print 内联代码也被拦截；node <-> nodejs
// 同族合法软链保持放行。
// ---------------------------------------------------------------------------

func TestGuard_V622_JSFamilySplit(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	binDir := filepath.Join(fakeHome, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("mkdir binDir: %v", err)
	}
	writeTestExecutable(t, filepath.Join(binDir, "node"), 0755)
	for _, name := range []string{"bun", "tsx"} {
		if err := os.Symlink(filepath.Join(binDir, "node"), filepath.Join(binDir, name)); err != nil {
			t.Fatalf("symlink %s -> node: %v", name, err)
		}
	}
	pathEnv := binDir + ":" + os.Getenv("PATH")
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", pathEnv)
	for _, tc := range []struct {
		name, cmd string
	}{
		{"v622-2a bun symlink", `bun -p 'require("child_process").execSync("pig")'`},
		{"v622-2b tsx symlink", `tsx -p 'require("child_process").execSync("pig")'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want conflicting structural alias block", tc.cmd)
			}
		})
	}
	// Direct bun -p with no symlink at all: -p is inline code and must hit
	// the nested-agent scan even when resolution finds nothing. The PATH
	// restore must re-bind the ORIGINAL PATH — re-reading os.Getenv after
	// t.Setenv would hand back the already-modified value and keep the
	// bun -> node symlink visible (v6.2.2 Oracle R1 Obs-2).
	t.Setenv("PATH", origPath)
	t.Run("v622-2c direct bun -p", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "v622-2c", role: "worker", cmd: `bun -p 'require("child_process").execSync("pig")'`}, "")
		if !strings.Contains(got, "javascript inline code") {
			t.Fatalf("direct bun -p = %q, want javascript inline code block", got)
		}
	})
	// node -> nodejs is the same distro family: the inline code is
	// screened under the shared node grammar, never a conflicting alias.
	writeTestExecutable(t, filepath.Join(binDir, "nodejs"), 0755)
	if err := os.Remove(filepath.Join(binDir, "node")); err != nil {
		t.Fatalf("remove node stub: %v", err)
	}
	if err := os.Symlink(filepath.Join(binDir, "nodejs"), filepath.Join(binDir, "node")); err != nil {
		t.Fatalf("symlink node -> nodejs: %v", err)
	}
	t.Setenv("PATH", pathEnv)
	t.Run("node->nodejs same family no conflict", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "v622-node-nodejs", role: "worker", argv: []string{"node", "-p", "1+1"}}, "")
		if strings.Contains(got, "conflicting structural alias") {
			t.Fatalf("node -> nodejs = %q, want no conflicting structural alias", got)
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 待办 3: replTokenInExecSlot / xargsFeedsCodeFlag 受限递归穿透 —
// 二层 xargs / flock -c / watch -x / script -qc / find -okdir / 悬空 env
// 包装器与 peelChainMaxDepth 深度上限全部 fail-closed；数据位 {} 保持放行。
// ---------------------------------------------------------------------------

func TestGuard_V622_MultiLayerExecSlots(t *testing.T) {
	blockCases := []struct {
		name, cmd string
	}{
		{"v622-3a xargs flock -c", `echo pig | xargs -I{} flock -x /dev/null -c '{}'`},
		{"v622-3b find xargs sh -c", `find . -exec xargs sh -c {} \;`},
		{"v622-3c1 xargs watch -x repl", `echo pig | xargs -I{} watch -x sh -c '{}'`},
		{"v622-3c2 xargs watch -x open", `echo pig | xargs watch -x sh -c`},
		{"v622-3d1 find -okdir flock cmd", `xargs -I% find . -okdir flock /tmp/lk --command='%' \;`},
		{"v622-3d2 script -qc token", `xargs -I{} script -qc '{}' /dev/null`},
		{"v622-3d3 dangling env", `echo pig | xargs env`},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want dynamic code payload block", tc.cmd)
			}
		})
	}
	allowCases := []struct {
		name, cmd string
	}{
		{"flock data operand", `find . -exec flock /tmp/lk grep foo {} \;`},
		{"watch -x data operand", `echo foo | xargs -I{} watch -x grep foo {}`},
		{"find path-position token", `echo x | xargs -I{} find {} -maxdepth 1 -name '*.go'`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
	// v622-3e: 25 层 watch -x 嵌套直达 peelChainMaxDepth (24) — 两处直接
	// 单测入口都必须 fail-closed。
	t.Run("v622-3e depth cap", func(t *testing.T) {
		deep := []string{"echo", "safe"}
		for n := 0; n < 25; n++ {
			deep = append([]string{"watch", "-x"}, deep...)
		}
		caller := callerIdentity{}
		if !replTokenInExecSlot(deep, "{}", os.Getenv("PATH"), caller) {
			t.Fatalf("replTokenInExecSlot 25-layer watch -x = false, want depth-cap fail-closed")
		}
		if !xargsFeedsCodeFlag(deep, nil, os.Getenv("PATH"), caller) {
			t.Fatalf("xargsFeedsCodeFlag 25-layer watch -x = false, want depth-cap fail-closed")
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R1: MF-1〜MF-9 / SF-1〜SF-5 / Obs-1〜Obs-2 探针回归 —
// Python -c/-m 后选项区终止与 -uW/-uX 短簇四处同构、bun -c/node -r/php -c
// 值槽动态拦截、npm 族结构头与 shell --rcfile、env -S 包装链扫描、递归
// caller 重锚、find 谓词/尾部追加/-fprintf 二元 arity、占位符非首词注入、
// script/flock 选项状态机、xargs --r* 缩写、awk/sed/tar/git -c 执行槽、
// find -H/-L/-P 前置标志豁免。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR1Probes(t *testing.T) {
	blockCases := []struct {
		name, cmd string
	}{
		// MF-2: -uW/-uX 短簇消费下一 argv 后，$OPT 动态词与非法长选项均 fail-closed。
		{"P-MF2-a -uW dynOPT", `OPT=-c; python3 -uW ignore "$OPT" 'import os; os.system("pig")'`},
		{"P-MF2-b -uW unknown long", `python3 -uW ignore --jit off -c 'import os; os.system("pig")'`},
		{"P-MF2-c -uW bad pycs", `python3 -uW ignore --check-hash-based-pycs=bogus -c 'import os; os.system("pig")'`},
		{"P-MF2-f xargs -0 feed", `printf '%s\0' -c 'import os; os.system("pig")' | xargs -0 python3 -uW ignore`},
		// MF-3: bun -c 是 bunfig 值槽而非代码标志——动态操作数 fail-closed。
		{"P-MF3-a bun -c $X", `X='a.toml -e require("child_process").execSync("pig")'; bun -c $X`},
		// MF-4b: shell --rcfile/--init-file 值槽消费与非 /dev/null fail-closed。
		{"P-MF4b-1 bash rcfile -c", `bash --rcfile /etc/profile -c 'pig'`},
		{"P-MF4b-2 xargs rcfile open -c", `echo pig | xargs bash --rcfile /dev/null -c`},
		{"P-MF4b-3 find rcfile -c", `find . -exec bash --rcfile /etc/profile -c '{}' \;`},
		{"P-MF4b-4 pipe rcfile stdin", `echo pig | bash --rcfile /dev/null`},
		// MF-5: env -S 分词注入——前导包装器/赋值/裸 '-'/GNU 缩写全线拦截。
		{"P-MF5-a nice env -S", `echo "-e system('pig')" | xargs -I{} nice env -S 'perl {}'`},
		{"P-MF5-b FOO=1 env -S", `echo "-e system('pig')" | xargs -I{} FOO=1 env -S 'perl {}'`},
		{"P-MF5-c env - -S", `echo "-e system('pig')" | xargs -I{} env - -S 'perl {}'`},
		{"P-MF5-d env --split abbrev", `echo "-e system('pig')" | xargs -I{} env --split 'perl {}'`},
		// MF-7: find 路径位占位符全后缀扫描、尾部追加、-fprintf 二元 arity。
		{"P-MF7-a pathword exec suffix", `echo -exec | xargs -I% find . % pig ';'`},
		{"P-MF7-b append mode", `printf -- '-exec\npig\n;\n' | xargs find .`},
		{"P-MF7-c fprintf shift", `echo pig | xargs -I{} find . -fprintf /dev/null -exec -exec sh -c '{}' ';'`},
		// MF-8: shell/解释器选项区占位符、内层 xargs 选项位、flock 锁文件位、ssh 本地与远端注入。
		{"P-MF8-a sh opt zone", `echo -c | xargs -I% sh % 'pig'`},
		{"P-MF8-b python opt zone", `echo -c | xargs -I% python3 % 'import os; os.system("pig")'`},
		{"P-MF8-c inner xargs zone", `echo pig > /tmp/p && echo 'I{}' | xargs -I% xargs -a /tmp/p -% sh -c '{}'`},
		{"P-MF8-d flock lockfile zone", `echo -c | xargs -I% flock % 'sh -c pig' /dev/null`},
		{"P-MF8-e ssh dest zone", `echo '-oProxyCommand=pig' | xargs -I{} ssh {} dmit ls`},
		{"P-MF8-f1 ssh remote repl", `echo '; pig' | xargs -I{} ssh dmit 'echo {}'`},
		{"P-MF8-f2 ssh remote append", `echo '; pig' | xargs ssh dmit echo hi`},
		// MF-9: script -T 文件名字母 c 不再误判、flock 短簇/--/--fcntl 修正。
		{"P-MF9-a script -T open -c", `echo pig | xargs script -T/tmp/xc -c`},
		{"P-MF9-b script -T token -c", `echo pig | xargs -I{} script -T/tmp/c.log -c '{}' /dev/null`},
		{"P-MF9-c flock -xc cluster", `echo pig | xargs -I{} flock -xc '{}' /dev/null`},
		{"P-MF9-d flock -- then -c", `echo pig | xargs -I{} flock -- /dev/null -c '{}'`},
		{"P-MF9-e flock --fcntl boolean", `echo pig | xargs -I{} flock --fcntl /dev/null sh -c '{}'`},
		// SF-3: GNU xargs --r* 唯一前缀缩写。
		{"SF3 xargs --repl", `echo pig | xargs --repl sh -c '{}'`},
		// SF-4: awk/sed/tar/git -c 执行槽。
		{"SF4 awk program", `echo 'BEGIN{system("pig")}' | xargs -I{} awk '{}' /dev/null`},
		{"SF4 sed script", `echo '1e pig' | xargs -I{} sed '{}' /dev/null`},
		{"SF4 tar checkpoint-action", `echo 'pig' | xargs -I{} tar --checkpoint=1 --checkpoint-action=exec='{}' -cf /dev/null /dev/null`},
		{"SF4 git -c pager", `echo 'pig' | xargs -I{} git -c core.pager='{}' log`},
		// SF-5: node --input-type 入 longValue 后动态/静态错位不再逃逸。
		{"SF5 node --input-type", `node --input-type commonjs -e 'require("child_process").execSync("pig")'`},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
		})
	}
	// MF-1 功能回归与 Obs-1 假阳性豁免：以下合法调用必须放行。
	allowCases := []struct {
		name, cmd string
	}{
		{"P-MF1-a pytest module", `python3 -m pytest --cov=x`},
		{"P-MF1-b json.tool module", `python3 -m json.tool --sort-keys`},
		{"P-MF1-c -c then script args", `python3 -c 'import sys; print(sys.argv)' --foo`},
		{"P-OBS1 find -L path token", `echo src | xargs -I{} find -L {} -name '*.go'`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
	// P-MF2-d: screenReadonlyWrite 对 -uX 携带值与粘连 -c 的只读文件运行拦截。
	t.Run("P-MF2-d readonly -uX", func(t *testing.T) {
		if got := screenReadonlyWrite([]string{"python3", "-uX", "--version", "evil.py"}); got == "" {
			t.Fatalf("screenReadonlyWrite python3 -uX --version evil.py = empty, want python3 block")
		}
	})
	t.Run("P-MF2-d2 readonly glued -c", func(t *testing.T) {
		if got := screenReadonlyWrite([]string{"python3", "-c__import__('os').system('touch /tmp/pwn')", "--version"}); got == "" {
			t.Fatalf("screenReadonlyWrite glued -c --version = empty, want python3 block")
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R2 (R3 闭环): R2-MF-1..7 / R2-SF-1..4 / R2-Obs-1..2 探针回归 —
// 长值选项 valueExact 统一消费与动态校验、pyInterpScanStep consumesNext 恢复
// 粘连 -m、sed/awk/git 复用仓内单源解析器、script -t optional_argument 与
// 位置参数置换、flock/xargs/tar GNU 唯一前缀缩写、ssh 短簇值操作数、xargs -a
// 与 argv+stdin 闭合、peelExecSlotHead canonical 变体写回、find 谓词表补齐、
// env -S 包装链约束扫描。每条 block 探针在修复前均为 ALLOW（或回归BLOCK），
// 每条 allow 探针钉住不得误伤的合法调用。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR2Probes(t *testing.T) {
	blockCases := []struct {
		name, cmd string
	}{
		// R2-MF-1: 非 Python 长值选项经 valueExact 统一消费并校验动态操作数。
		{"P-R2-MF1-a bash rcfile /dev/null $OPT", `OPT=-c; bash --rcfile /dev/null "$OPT" 'pig'`},
		{"P-R2-MF1-b bash double rcfile", `bash --rcfile /dev/null --rcfile /etc/profile -c 'pig'`},
		{"P-R2-MF1-c node --conditions --import", `X='a.js -e require("child_process").execSync("pig")'; node --conditions default --import $X`},
		{"P-R2-MF1-d bun --cwd -c", `X='a.toml -e require("child_process").execSync("pig")'; bun --cwd . -c $X`},
		{"P-R2-MF1-e node --input-type -r", `X='a.js -e require("child_process").execSync("pig")'; node --input-type commonjs -r $X`},
		{"P-R2-MF1-f node --require no reverse polarity", `X='a.js -e require("child_process").execSync("pig")'; node --require $X`},
		// R2-MF-2: spec 驱动短簇带值消费先查动态词再 i++。
		{"P-R2-MF2-c python3 -uW dyn", `X='ignore -c __import__("os").system("pig")'; python3 -uW $X`},
		{"P-R2-MF2-d bash -xo cluster", `bash -xo errexit --rcfile /etc/profile -c 'pig'`},
		{"P-R2-MF2-e sh -xo dynOPT", `OPT=-c; sh -xo errexit "$OPT" 'pig'`},
		{"P-R2-MF2-f perl -wI dyn", `X='/tmp -e system("pig")'; perl -wI /tmp -I $X`},
		{"P-R2-MF2-g perl -wI heredoc", "perl -wI /tmp <<'EOF'\nsystem(\"pig\")\nEOF"},
		// R2-MF-3: sed/awk/git 复用单源解析器后的绕过面。
		{"P-R2-MF3-d sed -ne glued", `echo '1e pig' | xargs -I{} sed -ne'{}' /etc/hosts`},
		{"P-R2-MF3-e sed --expr abbrev", `echo '1e pig' | xargs -I{} sed --expr='{}' /etc/hosts`},
		{"P-R2-MF3-f gawk -e glued", `echo 'BEGIN{system("pig")}' | xargs -I{} gawk -e'{}' /dev/null`},
		{"P-R2-MF3-g gawk --assign then token", `echo 'BEGIN{system("pig")}' | xargs -I{} gawk --assign x=1 '{}' /dev/null`},
		{"P-R2-MF3-h git -c bare token", `echo 'core.pager=pig' | xargs -I{} git -c '{}' log`},
		{"P-R2-MF3-i git optzone token", `echo '-c' | xargs -I% git % 'core.pager=pig' log`},
		{"P-R2-MF3-j git merge driver key", `echo 'pig' | xargs -I{} git -c 'merge.foo.driver={}' merge`},
		// R2-MF-4: script -t optional_argument / 长选项补全 / 位置参数置换;
		// flock GNU 唯一前缀缩写。
		{"P-R2-MF4-a script -t bare", `script -t -c 'pig' /dev/null`},
		{"P-R2-MF4-b xargs script -t", `echo pig | xargs -I{} script -t -c '{}' /dev/null`},
		{"P-R2-MF4-c script --timing bare", `script --timing -c 'pig' /dev/null`},
		{"P-R2-MF4-d script --log-io", `script --log-io /dev/null -c 'pig'`},
		{"P-R2-MF4-e script positional then -c", `script /dev/null -c 'pig'`},
		{"P-R2-MF4-f flock --com glued", `flock --com='pig' /dev/null`},
		{"P-R2-MF4-g flock --time separate", `flock --time 5 /dev/null -c 'pig'`},
		// R2-MF-5: ssh 短簇带值操作数不再冒充 destination。
		{"P-R2-MF5-a ssh -p operand", `echo '-oProxyCommand=pig' | xargs -I{} ssh -p 22 {} dmit ls`},
		// R2-MF-6: interpOptionZoneHasToken spec 驱动跳值、多 -e 继续扫描。
		{"P-R2-MF6-a python3 -W operand", `echo -c | xargs -I% python3 -W ignore % 'import os; os.system("pig")'`},
		{"P-R2-MF6-b sh -o operand", `echo -c | xargs -I% sh -o errexit % 'pig'`},
		{"P-R2-MF6-c bun -c value then token", `echo -e | xargs -I% bun -c a.toml % 'require("child_process").execSync("pig")'`},
		{"P-R2-MF6-d perl multi -e", `echo -e | xargs -I% perl -e '1' % 'system("pig")'`},
		{"P-R2-MF6-e php -r then token", `echo -r | xargs -I% php -r '1;' % 'system("pig");'`},
		{"P-R2-MF6-f script optzone token", `echo -c | xargs -I% script % 'pig' /dev/null`},
		// R2-SF-1..4: canonical 变体、find 谓词、xargs/tar GNU 缩写、stdin spec 派生。
		{"P-R2-SF1-a gfind canonical", `echo pig | xargs -I% gfind . -exec sh -c '%' ';'`},
		{"P-R2-SF2-a find -newermm shift", `find . -newermm -exec -exec pig ';'`},
		{"P-R2-SF3-a xargs --replace= empty", `echo pig | xargs --replace= sh -c '{}'`},
		{"P-R2-SF3-b xargs --max-a abbrev", `echo pig | xargs --max-a 1 -I{} sh -c '{}'`},
		{"P-R2-SF3-c tar -cI cluster", `echo 'pig' | xargs -I{} tar -cI '{}' -f /dev/null /dev/null`},
		{"P-R2-SF4-a bun --cwd stdin", `echo 'require("child_process").execSync("pig")' | bun --cwd . -`},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
		})
	}
	allowCases := []struct {
		name, cmd string
	}{
		// R2-MF-2 功能回归恢复:粘连 -m 后动态/通配参数是模块参数而非模块名。
		{"P-R2-MF2-a python3 -mjson.tool", `python3 -mjson.tool "$HOME/a.json"`},
		{"P-R2-MF2-b python3 -mpytest glob", `python3 -mpytest tests/*.py`},
		// R2-MF-3 功能回归恢复:-e/-f 之后输入文件名是数据。
		{"P-R2-MF3-a find sed -e", `find . -name '*.txt' -exec sed -e 's/foo/bar/' {} \;`},
		{"P-R2-MF3-b xargs sed -e", `echo foo.txt | xargs -I{} sed -e 's/foo/bar/' {}`},
		{"P-R2-MF3-c find awk -f", `find . -name '*.log' -exec awk -f parse.awk {} \;`},
		{"P-R2-MF3-a2 find sed -n -e", `find . -name '*.txt' -exec sed -n -e '1,5p' {} \;`},
		{"P-R2-MF3-a3 find sed -f", `find . -name '*.txt' -exec sed -f rules.sed {} \;`},
		// R2-MF-7 功能回归恢复:rg 参数位的 env -S 不触发包装链扫描。
		{"P-R2-MF7-b rg env -S operand", `find . -name '*.go' -exec rg env -S {} \;`},
		{"P-R2-MF7-b2 echo env -S operand", `echo foo | xargs -I{} echo env -S {}`},
		// R2-SF-2 假阳性恢复:-ctime 等时间谓词的值是数据。
		{"P-R2-SF2-b find -ctime value", `echo 5 | xargs -I{} find . -ctime {}`},
		// flock 正例:-xw 粘连簇与分离 -x -w 都正确解析到命令头 true。
		{"flock -xw 0 positive", `flock -xw 0 /dev/null true`},
		{"flock -x -w 30 positive", `flock -x -w 30 /dev/null true`},
		// script/typescript 合法调用不受选项区扫描误伤。
		{"script benign -c no token", `script -c 'echo hi' /tmp/out`},
		// R12 数据位保持:sh -c positional $1 与 git -C 路径值。
		{"R12 sh positional", `find . -exec sh -c 'echo "$1"' _ {} +`},
		{"R12 git -C data", `echo /tmp/repo | xargs -I{} git -C {} status`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// P-R2-MF5-b/c: xargs -a 文件喂词与 argv+stdin 两路闭合。文件用
	// t.TempDir() 预建——`printf ... > /tmp/p` 前置重定向会独立命中写拦截
	// 掩盖目标路径 (Reviewer should-fix),且断言精确 verdict 子串。
	t.Run("P-R2-MF5-b xargs -a file feed", func(t *testing.T) {
		payload := filepath.Join(t.TempDir(), "payload")
		if err := os.WriteFile(payload, []byte("-c\npig\n"), 0644); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		got := rtGuardCwd(t, rtCase{id: "P-R2-MF5-b", role: "worker", cmd: `xargs -a ` + payload + ` ssh dmit sh`}, "")
		if !strings.Contains(got, "ssh") {
			t.Fatalf("xargs -a payload ssh dmit sh = %q, want an ssh verdict block", got)
		}
	})
	t.Run("P-R2-MF5-c argv+stdin feed", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{
			id: "P-R2-MF5-c", role: "worker",
			argv:  []string{"xargs", "ssh", "dmit", "sh"},
			stdin: "-c pig",
		}, "")
		if !strings.Contains(got, "ssh") {
			t.Fatalf("argv xargs ssh dmit sh + stdin '-c pig' = %q, want an ssh verdict block", got)
		}
	})
	// R12 精确 verdict 不破坏:pipe 与 file-redir 两种传输必须各归其名。
	t.Run("R12 piped verdict exact", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R12-a", role: "worker", cmd: `echo code | xargs ssh dmit sh`}, "")
		if !strings.Contains(got, "piped stdin to ssh") {
			t.Fatalf("echo code | xargs ssh dmit sh = %q, want piped stdin to ssh", got)
		}
	})
	t.Run("R12 file-redir verdict exact", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R12-b", role: "worker", cmd: `xargs -a /tmp/items ssh dmit sh < /tmp/script.sh`}, "")
		if !strings.Contains(got, "file stdin to ssh stdin-program") {
			t.Fatalf("xargs -a file ssh dmit sh < redir = %q, want file stdin to ssh stdin-program", got)
		}
	})
}

// TestGuard_V622_OracleR2EnvCwd 覆盖 R2-MF-7 软链别名 env -S 注入
// (依赖文件系统软链布置,单独成组)。
func TestGuard_V622_OracleR2EnvCwd(t *testing.T) {
	cwd := t.TempDir()
	if err := os.Symlink("/usr/bin/env", filepath.Join(cwd, "myenv")); err != nil {
		t.Fatalf("symlink myenv -> /usr/bin/env: %v", err)
	}
	t.Run("P-R2-MF7-a symlink alias env -S", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{
			id: "P-R2-MF7-a", role: "worker",
			cmd: `echo "-e system('pig')" | xargs -I{} ./myenv -S "perl -e '1' {}"`,
		}, cwd)
		if got == "ALLOW" {
			t.Fatalf("./myenv -S split injection = ALLOW, want a guard block")
		}
	})
	// P-MF2-e 补齐 (R2-Obs-1):-uW 后 heredoc 代码流同样拦截。
	t.Run("P-MF2-e python3 -uW heredoc", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{
			id: "P-MF2-e", role: "worker",
			cmd: "python3 -uW ignore <<'EOF'\nimport os; os.system(\"pig\")\nEOF",
		}, "")
		if got == "ALLOW" {
			t.Fatalf("python3 -uW ignore heredoc = ALLOW, want a guard block")
		}
	})
	// R2-Obs-1: 独立两字符 -c 后查询标志不得放行脚本文件运行。
	t.Run("P-R2-Obs1 readonly bare -c then --version", func(t *testing.T) {
		if got := screenReadonlyWrite([]string{"python3", "-c", "-1; open('/var/a','w').write('x')", "--version"}); got == "" {
			t.Fatalf("screenReadonlyWrite python3 -c <code> --version = empty, want python3 block")
		}
	})
}

// TestGuard_V622_OracleR1EnvCwd 覆盖 MF-4a 结构别名与 MF-6 env -C 重锚
// 递归 caller 修复(依赖文件系统软链布置,单独成组)。
func TestGuard_V622_OracleR1EnvCwd(t *testing.T) {
	fakeHome := withTestTrustedHome(t)
	binDir := filepath.Join(fakeHome, ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("mkdir binDir: %v", err)
	}
	writeTestExecutable(t, filepath.Join(binDir, "npm-cli.js"), 0755)
	if err := os.Symlink(filepath.Join(binDir, "npm-cli.js"), filepath.Join(binDir, "bun")); err != nil {
		t.Fatalf("symlink bun -> npm-cli.js: %v", err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Run("P-MF4a bun->npm-cli.js conflict", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-MF4a", role: "worker", cmd: `bun exec -- pig`}, "")
		if !strings.Contains(got, "conflicting structural alias") {
			t.Fatalf("bun exec -- pig = %q, want conflicting structural alias", got)
		}
	})

	cwd := filepath.Join(fakeHome, "proj")
	sub := filepath.Join(cwd, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.Symlink("/bin/sh", filepath.Join(sub, "mysh")); err != nil {
		t.Fatalf("symlink mysh -> /bin/sh: %v", err)
	}
	mf6 := []struct {
		name, cmd string
	}{
		{"P-MF6-a env -C watch -x", `echo pig | xargs -I{} env -C sub watch -x ./mysh -c '{}'`},
		{"P-MF6-b env -C watch open", `echo pig | xargs env -C sub watch -x ./mysh -c`},
		{"P-MF6-c env -C flock", `echo pig | xargs -I{} env -C sub flock /dev/null ./mysh -c '{}'`},
		{"P-MF6-d env -C find -exec", `echo pig | xargs -I{} env -C sub find . -exec ./mysh -c '{}' ';'`},
		{"P-MF6-e env -C flock open", `echo pig | xargs env -C sub flock /dev/null ./mysh -c`},
	}
	for _, tc := range mf6 {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, cwd)
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R3 (R4 闭环): R3-MF-1..6 / R3-SF-1..2 / R3-Obs-1 探针回归 —
// tar 长数据选项与 BSD 首词、wrapperChainEnvSplitHasToken 单步剥离、flock
// 真实长选项表 fail-closed、script 置换扫描与 -E/--echo、多代码槽短簇操作数
// 消费与合法数据文件名恢复、git/awk/xargs -a ssh 三路残余绕过、node spec
// 单源收口。BLOCK 探针均断言目标 verdict 子串(不被上游管道/重定向规则掩盖),
// ALLOW 探针钉住 Reviewer R2-6 的合法数据语义。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR3Probes(t *testing.T) {
	// xargs -a / heredoc 用例的预建 payload(t.TempDir 避免前导重定向命中写
	// 拦截掩盖目标 verdict —— R3-Obs-2 测试隔离纪律)。
	payloadC := filepath.Join(t.TempDir(), "payload-c")
	if err := os.WriteFile(payloadC, []byte("-c\n"), 0644); err != nil {
		t.Fatalf("write payload-c: %v", err)
	}
	payloadCPig := filepath.Join(t.TempDir(), "payload-cpig")
	if err := os.WriteFile(payloadCPig, []byte("-c\npig\n"), 0644); err != nil {
		t.Fatalf("write payload-cpig: %v", err)
	}
	// R3/R5 探针的 xargs -a 无管道 payload(Oracle R4 精确 verdict 纪律:
	// 管道 echo 会被上游 piped code 规则掩盖目标 verdict,改用 -a 文件喂入)。
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadFooExec := mkPayload("payload-fooexec", "foo -exec pig ;\n")
	payloadCkpt := mkPayload("payload-ckpt", "a --checkpoint=1 --checkpoint-action=exec=pig\n")
	payloadDashE := mkPayload("payload-dashe", "-e\n")
	payloadBegin := mkPayload("payload-begin", "BEGIN{system(\"pig\")}\n")
	payloadCorePager := mkPayload("payload-cp", "core.pager\n")
	payloadPig := mkPayload("payload-pig", "pig\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R3-MF-1: tar 长数据选项消费操作数 + BSD 首词严格限定 argv[0]。
		{"P-R3-MF1-a tar --file swallow", `tar -c --file foo.tar --use-compress-program=pig /dev/null`, "pig"},
		{"P-R3-MF1-b tar --directory ckpt", `tar --directory /tmp/f --checkpoint=1 --checkpoint-action=exec=pig -cf /dev/null /dev/null`, "pig"},
		{"P-R3-MF1-c tar fstab nonfirst", `tar -cf /dev/null /etc/fstab --use-compress-program=pig`, "pig"},
		{"P-R3-MF1-d tar BSD cIf", `tar cIf pig /dev/null /dev/null`, "pig"},
		// R3-MF-2: 单步剥离包装链,nice/timeout/嵌套 env 不再跃过 env -S。
		{"P-R3-MF2-a nice env -S find", `xargs -a ` + payloadFooExec + ` -I{} nice env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R3-MF2-b timeout env -S", `xargs -a ` + payloadFooExec + ` -I{} timeout 10 env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R3-MF2-c env -- env -S", `xargs -a ` + payloadFooExec + ` -I{} env -- env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R3-MF2-d env -i env -S", `xargs -a ` + payloadFooExec + ` -I{} env -i env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R3-MF2-e nice env -S tar", `xargs -a ` + payloadCkpt + ` -I{} nice env -S "tar -cf /dev/null {}"`, "dynamic code payload"},
		// R3-MF-3: flock 真实长选项表 + 未知长选项 fail-closed。
		{"P-R3-MF3-a flock --no-fork", `flock --no-fork /dev/null pig`, "pig"},
		{"P-R3-MF3-c flock --f fcntl", `flock --f /dev/null pig`, "pig"},
		{"P-R3-MF3-d flock --nb", `flock --nb /dev/null pig`, "pig"},
		// R3-MF-5: 多代码槽短簇操作数消费后继续扫选项区。
		{"P-R3-MF5-a perl -we -I", `X='/tmp -e system("pig")'; perl -we '1' -I $X`, "dynamic code payload"},
		{"P-R3-MF5-b ruby -we -I", `X='/tmp -e system("pig")'; ruby -we '1' -I $X`, "dynamic code payload"},
		{"P-R3-MF5-c php -nr -c", `X='a.ini -r system("pig");'; php -nr '1;' -c $X`, "dynamic code payload"},
		{"P-R3-MF5-d node -pe -r", `X='a.js -e require("child_process").execSync("pig")'; node -pe '1' -r $X`, "dynamic code payload"},
		{"P-R3-MF5-e bun -pe -c", `X='a.toml -e require("child_process").execSync("pig")'; bun -pe '1' -c $X`, "dynamic code payload"},
		// R3-MF-5 攻击面补充: 代码槽后选项位占位符仍拦截。
		{"P-R3-MF5-f perl -e xargs %", `xargs -a ` + payloadDashE + ` -I% perl -e '1' % 'system("pig")'`, "dynamic code payload"},
		{"P-R3-MF5-g perl -e dash-%", `xargs -a ` + payloadDashE + ` -I% perl -e '1' -%`, "dynamic code payload"},
		// v6.2.2 R5 加固: 自定义/默认替换 token 位于非末尾位置时,其后方参数
		// 仍可被扩展武装成 -e/-r 代码操作数,不再依赖硬编码拼写名单。
		{"P-R5-a xargs -I{} perl trailing", `xargs -a ` + payloadDashE + ` -I{} perl -e '1' {} 'system("pig")'`, "dynamic code payload"},
		{"P-R5-b xargs -IFOO custom token", `xargs -a ` + payloadDashE + ` -IFOO perl -e '1' FOO 'system("pig")'`, "dynamic code payload"},
		// R3-MF-6: git/awk/xargs 三路残余绕过。
		{"P-R3-MF6-a git -c key-side", `xargs -a ` + payloadCorePager + ` -I{} git -c '{}=pig' log`, "dynamic code payload"},
		{"P-R3-MF6-a2 git --config-env", `xargs -a ` + payloadPig + ` -I{} git --config-env 'core.pager={}' log`, "dynamic code payload"},
		{"P-R3-MF6-b gawk -f masks -e", `xargs -a ` + payloadBegin + ` -I{} gawk -f /dev/null /dev/null -e '{}'`, "dynamic code payload"},
		{"P-R3-MF6-c gawk -W source", `xargs -a ` + payloadBegin + ` -I{} gawk -e '1' -W 'source={}' /dev/null`, "dynamic code payload"},
		// R3-SF-1: node spec 单源收口(-C / 长值选项)。
		{"P-R3-SF1-a node --title", `node --title x -e 'require("child_process").execSync("pig")'`, "javascript inline code"},
		{"P-R3-SF1-b node --env-file", `node --env-file /dev/null -e 'require("child_process").execSync("pig")'`, "javascript inline code"},
		{"P-R3-SF1-c node -C", `node -C default -e 'require("child_process").execSync("pig")'`, "javascript inline code"},
		{"P-R3-SF1-d node -C stdin", `echo 'require("child_process").execSync("pig")' | node -C default -`, "piped code to javascript"},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want verdict substring %q", tc.cmd, got, tc.want)
			}
		})
	}

	// R3-MF-4: script 置换扫描(xargs -a 无管道入口,断言 dynamic code payload
	// 精确 verdict —— 修复前仅靠 echo 管道误触 piped code to shell 掩盖)。
	for _, tc := range []struct{ name, cmd string }{
		{"P-R3-MF4-a script xargs -a pre", `xargs -a ` + payloadC + ` -I% script % 'pig' /dev/null`},
		{"P-R3-MF4-b script xargs -a post", `xargs -a ` + payloadC + ` -I% script /dev/null % 'pig'`},
		{"P-R3-MF4-d find -exec script", `find . -name '-c' -exec script {} 'pig' /dev/null \;`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if !strings.Contains(got, "dynamic code payload") {
				t.Fatalf("rtGuardCwd(%q) = %q, want dynamic code payload", tc.cmd, got)
			}
		})
	}
	t.Run("P-R3-MF4-c script argv+stdin", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{
			id: "P-R3-MF4-c", role: "worker",
			argv:  []string{"xargs", "-I%", "script", "%", "pig", "/dev/null"},
			stdin: "-c",
		}, "")
		if !strings.Contains(got, "dynamic code payload") {
			t.Fatalf("argv script %% pig + stdin '-c' = %q, want dynamic code payload", got)
		}
	})

	// R3-MF-3-b: flock --no-fork 后 python3 不再被错当锁文件。
	t.Run("P-R3-MF3-b flock --no-fork python3", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R3-MF3-b", role: "worker", cmd: `flock --no-fork /dev/null python3 -c 'import os; os.system("pig")'`}, "")
		if !strings.Contains(got, "python inline code") {
			t.Fatalf("flock --no-fork python3 -c = %q, want python inline code", got)
		}
	})

	// R3-MF-6-d/e: xargs -a 配良性 here-string/heredoc 不再绕过 ssh stdin
	// 追加审查;f: GNU --arg-f 缩写接入 xargsMatchValueLong(verifier 外泄)。
	t.Run("P-R3-MF6-d xargs -a argv+stdin", func(t *testing.T) {
		// <<< here-string 是 bash-only 语法(/bin/sh dash 拒收),stdin 流通道
		// 经 argv+stdin 入口钉精确 verdict;heredoc 的 POSIX 拼写见 MF6-e。
		got := rtGuardCwd(t, rtCase{
			id: "P-R3-MF6-d", role: "worker",
			argv:  []string{"xargs", "-a", payloadCPig, "ssh", "dmit", "sh"},
			stdin: "echo hi",
		}, "")
		if !strings.Contains(got, "piped stdin to ssh") {
			t.Fatalf("xargs -a payload ssh dmit sh + stdin = %q, want piped stdin to ssh", got)
		}
	})
	t.Run("P-R3-MF6-e xargs -a heredoc", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R3-MF6-e", role: "worker", cmd: "xargs -a " + payloadCPig + " ssh dmit sh <<'EOF'\necho hi\nEOF"}, "")
		if !strings.Contains(got, "piped stdin to ssh") {
			t.Fatalf("xargs -a payload ssh dmit sh heredoc = %q, want piped stdin to ssh", got)
		}
	})
	t.Run("P-R3-MF6-f xargs --arg-f verifier", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R3-MF6-f", role: "verifier", cmd: `xargs --arg-f=/tmp/items -I{} ssh dmit cat < /etc/passwd`}, "")
		if !strings.Contains(got, "ssh remote write") {
			t.Fatalf("xargs --arg-f ssh cat exfil = %q, want ssh remote write", got)
		}
	})

	// Reviewer R2-6 合法数据 ALLOW 行: 解释器输入文件名 / awk -v 纯数据赋
	// 值 / git 纯数据路径值(glued 与分离双形态)。
	allowCases := []struct {
		name, cmd string
	}{
		{"R2-6-a find perl -pe data", `find . -exec perl -pe 's/a/b/' {} \;`},
		{"R2-6-b find awk -v data", `find . -exec awk -v f={} 'END {print f}' {} \;`},
		{"R2-6-c find awk -f -v data", `find . -exec awk -f parse.awk -v fname={} {} \;`},
		{"R2-6-d find git --git-dir glued", `find . -name .git -exec git --git-dir={} log -1 \;`},
		{"R2-6-e xargs awk -v", `echo x | xargs -I{} awk -v k={} 'BEGIN{print k}' /dev/null`},
		{"R2-6-f git --git-dir separate", `echo /tmp/repo | xargs -I{} git --git-dir {} log -1`},
		{"R2-6-g perl -we legit -I", `perl -we 'print qq(ok)' -I /tmp`},
		{"R5-a xargs -I{} perl -pe data", `echo a.txt | xargs -I{} perl -pe 's/a/b/' -- {}`},
		{"R5-b xargs -I{} perl -pe dot-slash", `echo a.txt | xargs -I{} perl -pe 's/a/b/' ./{}`},
		{"R5-c find perl -pe trailing", `find . -exec perl -pe 's/a/b/' {} other.txt \;`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// R12 精确 verdict 不受 xargsDerivedSeg 收紧影响: 真管道与文件重定向
	// 各归其名。
	t.Run("R12 piped verdict unchanged", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R12-a-r3", role: "worker", cmd: `echo code | xargs ssh dmit sh`}, "")
		if !strings.Contains(got, "piped stdin to ssh") {
			t.Fatalf("echo code | xargs ssh dmit sh = %q, want piped stdin to ssh", got)
		}
	})
	t.Run("R12 file-redir verdict unchanged", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "R12-b-r3", role: "worker", cmd: `xargs -a /tmp/items ssh dmit sh < /tmp/script.sh`}, "")
		if !strings.Contains(got, "file stdin to ssh stdin-program") {
			t.Fatalf("xargs -a file ssh dmit sh < redir = %q, want file stdin to ssh stdin-program", got)
		}
	})

	// 目标层直断断言(R3-Obs-2 防掩盖纪律): wrapperChainEnvSplitHasToken /
	// scriptOptZoneHasToken / gitExecConfigValueHasToken / flockMatchLong 的
	// 单元 verdict 不依赖上层管道或外围规则兜出 BLOCK。
	t.Run("R3-unit env-split chain direct", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
			want bool
		}{
			{"nice env -S find", []string{"nice", "env", "-S", "find . -name {}"}, true},
			{"timeout env -S find", []string{"timeout", "10", "env", "-S", "find . -name {}"}, true},
			{"env -- env -S find", []string{"env", "--", "env", "-S", "find . -name {}"}, true},
			{"env -i env -S find", []string{"env", "-i", "env", "-S", "find . -name {}"}, true},
			{"nice env -S tar", []string{"nice", "env", "-S", "tar -cf /dev/null {}"}, true},
			{"rg env -S operand", []string{"rg", "env", "-S", "{}"}, false},
			{"echo env -S operand", []string{"echo", "env", "-S", "{}"}, false},
		} {
			if got := wrapperChainEnvSplitHasToken(tc.argv, os.Getenv("PATH"), callerIdentity{}, "{}"); got != tc.want {
				t.Errorf("wrapperChainEnvSplitHasToken(%v) = %v, want %v", tc.argv, got, tc.want)
			}
		}
	})
	t.Run("R3-unit script zone direct", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			h    []string
			want bool
		}{
			{"script % pig", []string{"script", "%", "pig", "/dev/null"}, true},
			{"script positional then %", []string{"script", "/dev/null", "%", "pig"}, true},
			{"script -q % pig", []string{"script", "-q", "%", "pig", "/dev/null"}, true},
			{"script -c benign", []string{"script", "-c", "echo hi", "/tmp/out"}, false},
			{"script -- terminator", []string{"script", "--", "%"}, false},
		} {
			if got := scriptOptZoneHasToken(tc.h, "%"); got != tc.want {
				t.Errorf("scriptOptZoneHasToken(%v) = %v, want %v", tc.h, got, tc.want)
			}
		}
	})
	t.Run("R3-unit git -c key-side direct", func(t *testing.T) {
		if !gitExecConfigValueHasToken("{}=pig", "{}") {
			t.Errorf("gitExecConfigValueHasToken({}=pig) = false, want true")
		}
		if !gitExecConfigValueHasToken("core.pager={}", "{}") {
			t.Errorf("gitExecConfigValueHasToken(core.pager={}) = false, want true")
		}
		if gitExecConfigValueHasToken("user.name={}", "{}") {
			t.Errorf("gitExecConfigValueHasToken(user.name={}) = true, want false for a non-exec key")
		}
	})
	t.Run("R3-unit flock long table direct", func(t *testing.T) {
		for _, tc := range []struct {
			in, want string
			ok       bool
		}{
			{"no-fork", "no-fork", true},
			{"nb", "nb", true},
			{"f", "fcntl", true},
			{"fd", "", false},
			{"nofork", "", false},
			{"com", "command", true},
			{"c", "", false},
		} {
			if full, ok := flockMatchLong(tc.in); full != tc.want || ok != tc.ok {
				t.Errorf("flockMatchLong(%q) = %q,%v want %q,%v", tc.in, full, ok, tc.want, tc.ok)
			}
		}
		if got := skipFlockLong([]string{"flock", "--no-fork-x", "/dev/null", "pig"}, 1); got != -1 {
			t.Errorf("skipFlockLong unknown long = %d, want -1 fail-closed", got)
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R4 (R6 闭环): R4-MF-1..4 / R4-SF-1..4 / R4-Obs-1 探针回归 —
// tar 布尔 -h 不再吞并后续 exec 选项;xargs 替换 token 的单词粘连/=` 代码
// 选项 RCE(-esystem pig / --eval=...)在末词也不豁免;env -S 嵌套重拆链
// 不再被 len(rest)>=len(cur) 截断;gawk -W 按 GNU getopt_long "W;" 解析
// 且 -E/--exec 接通 stdin/动态校验,awk 位置参数不再终止选项区扫描。
// 管道 echo 形态受上游 piped code 规则掩盖(verdict 为 piped code to shell/
// perl/javascript),精确 dynamic code payload 断言一律走 xargs -a 无管道
// 入口(R3-Obs-2 隔离纪律);stdin 程序源断言走 echo 管道与 argv+stdin 双通道。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR4Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadEsys := mkPayload("r4-esys", "-esystem(\"pig\")\n")
	payloadEval := mkPayload("r4-eval", "--eval=require(\"child_process\").execSync(\"pig\")\n")
	payloadDash := mkPayload("r4-dash", "-\n")
	payloadFooExec := mkPayload("r4-fooexec", "foo -exec pig ;\n")
	payloadCkpt := mkPayload("r4-ckpt", "a --checkpoint=1 --checkpoint-action=exec=pig\n")
	payloadBegin := mkPayload("r4-begin", "BEGIN{system(\"pig\")}\n")
	payloadEvilAwk := mkPayload("r4-evilawk", "/tmp/evil.awk\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R4-MF-1: tar 布尔 -h(--dereference)不再当带值字母吞并后续 exec 选项。
		{"P-R4-MF1-a tar -h use-compress", `tar -h --use-compress-program=pig -cf /dev/null /dev/null`, "pig"},
		{"P-R4-MF1-b tar -ch use-compress", `tar -ch --use-compress-program=pig -cf /dev/null /dev/null`, "pig"},
		{"P-R4-MF1-c tar -xh to-command", `tar -xh --to-command=pig -f /dev/null`, "pig"},
		{"P-R4-MF1-d tar -chI pig", `tar -chI pig -cf /dev/null /dev/null`, "pig"},
		{"P-R4-MF1-e tar -h ckpt-exec", `tar -h --checkpoint-action=exec=pig --checkpoint=1 -cf /dev/null /dev/null`, "pig"},
		// R4-MF-2: 单词粘连/=` 代码选项 RCE —— 末词也不豁免(xargs -a 无管道
		// 入口断言 dynamic code payload;stdin 管道形态的上游 verdict 另行验证)。
		{"P-R4-MF2-a perl glued -e", `xargs -a ` + payloadEsys + ` -I{} perl -e '1' {}`, "dynamic code payload"},
		{"P-R4-MF2-b perl -pe glued", `xargs -a ` + payloadEsys + ` -I{} perl -pe 's/a/b/' {}`, "dynamic code payload"},
		{"P-R4-MF2-c custom token FOO", `xargs -a ` + payloadEsys + ` -IFOO perl -e '1' FOO`, "dynamic code payload"},
		{"P-R4-MF2-d ruby glued -e", `xargs -a ` + payloadEsys + ` -I{} ruby -e '1' {}`, "dynamic code payload"},
		{"P-R4-MF2-e node --eval=", `xargs -a ` + payloadEval + ` -I{} node -e '1' {}`, "dynamic code payload"},
		{"P-R4-MF2-f bun --eval=", `xargs -a ` + payloadEval + ` -I{} bun -e '1' {}`, "dynamic code payload"},
		{"P-R4-MF2-g php glued -r", `xargs -a ` + mkPayload("r4-phpr", "-rsystem(\"pig\");\n") + ` -I{} php -r '1;' {}`, "dynamic code payload"},
		{"P-R4-MF2-h tsx --eval=", `xargs -a ` + payloadEval + ` -I{} tsx -e '1' {}`, "dynamic code payload"},
		// R4-MF-3: env -S 拆词重拼嵌套链不再被 len(rest)>=len(cur) 截断。
		{"P-R4-MF3-a env -Senv -S find", `xargs -a ` + payloadFooExec + ` -I{} env "-Senv -S" "find . -name {}"`, "dynamic code payload"},
		{"P-R4-MF3-b env -S nice chain", `xargs -a ` + payloadFooExec + ` -I{} env -S "nice nice nice" env -S "find . -name {}"`, "dynamic code payload"},
		{"P-R4-MF3-c env -S nested env", `xargs -a ` + payloadFooExec + ` -I{} env -S "nice nice env -S" "find . -name {}"`, "dynamic code payload"},
		{"P-R4-MF3-d env -Senv -S tar", `xargs -a ` + payloadCkpt + ` -I{} env "-Senv -S" "tar -cf /dev/null {}"`, "dynamic code payload"},
		// R4-MF-4: gawk -W GNU "W;" 语义 / -E/--exec / 位置参数后置选项。
		{"P-R4-MF4-c -W source PROG", `gawk -e '1' -W source 'BEGIN{system("pig")}' /dev/null`, "pig"},
		{"P-R4-MF4-d -W source xargs", `xargs -a ` + payloadBegin + ` -I{} gawk -e '1' -W source '{}' /dev/null`, "dynamic code payload"},
		{"P-R4-MF4-e -W so= prefix", `gawk -e '1' -W 'so=BEGIN{system("pig")}' /dev/null`, "pig"},
		{"P-R4-MF4-f -W exec xargs", `xargs -a ` + payloadBegin + ` -I{} gawk -e '1' -W exec '{}' /dev/null`, "dynamic code payload"},
		{"P-R4-MF4-g positional -f", `xargs -a ` + payloadDash + ` -I{} gawk -e '1' /dev/null -f '{}'`, "dynamic code payload"},
		{"P-R4-MF4-x1 --file= positional", `xargs -a ` + payloadEvilAwk + ` -I{} gawk -e '1' /dev/null --file='{}'`, "dynamic code payload"},
		{"P-R4-MF4-x2 -f mask -f", `xargs -a ` + payloadEvilAwk + ` -I{} gawk -f /dev/null /dev/null -f '{}'`, "dynamic code payload"},
		{"P-R4-MF4-x3 positional -i", `xargs -a ` + payloadEvilAwk + ` -I{} gawk -e '1' /dev/null -i '{}'`, "dynamic code payload"},
		{"P-R4-MF4-x4 -W file= token", `xargs -a ` + payloadEvilAwk + ` -I{} gawk -e '1' /dev/null -W 'file={}'`, "dynamic code payload"},
		// R4-SF-1: flagCodes 后接非代码字母不再丢失 hasFlagCode。
		{"P-R4-SF1 node -pi pending", `xargs -a ` + payloadDash + ` -I% node -pi '1' %`, "dynamic code payload"},
	}
	for _, tc := range blockCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want verdict substring %q", tc.cmd, got, tc.want)
			}
		})
	}

	// R4-MF-2 管道路径:stdin 是任意字节的 xargs 馈入,整块管线必 BLOCK
	// (上游 piped code verdict 与精确 exec-slot verdict 任一都算闭合)。
	for _, tc := range []struct{ name, cmd string }{
		{"P-R4-MF2-a-pipe perl glued", `echo '-esystem("pig")' | xargs -I{} perl -e '1' {}`},
		{"P-R4-MF2-b-pipe perl -pe glued", `echo '-eBEGIN{system("pig")}' | xargs -I{} perl -pe 's/a/b/' {}`},
		{"P-R4-MF2-c-pipe custom FOO", `echo '-esystem("pig")' | xargs -IFOO perl -e '1' FOO`},
		{"P-R4-MF2-d-pipe ruby glued", `echo '-esystem("pig")' | xargs -I{} ruby -e '1' {}`},
		{"P-R4-MF2-e-pipe node --eval=", `echo '--eval=require("child_process").execSync("pig")' | xargs -I{} node -e '1' {}`},
		{"P-R4-MF2-f-pipe bun --eval=", `echo '--eval=require("child_process").execSync("pig")' | xargs -I{} bun -e '1' {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = ALLOW, want a guard block", tc.cmd)
			}
		})
	}

	// R4-MF-4 awk stdin 程序源:echo 管道 + guardCtxRunArgv argv+stdin 双通道
	// 均须拦截(Reviewer R3 #3 argv+stdin 独立性)。
	for _, tc := range []struct {
		name, cmd, want string
	}{
		{"P-R4-MF4-a -W file=-", `echo 'BEGIN{system("pig")}' | gawk -W file=-`, "awk script from stdin"},
		{"P-R4-MF4-b -W file=/dev/stdin", `echo 'BEGIN{system("pig")}' | gawk -W file=/dev/stdin`, "awk script from stdin"},
		{"P-R4-MF4-h gawk -E stdin", `echo 'BEGIN{system("pig")}' | gawk -E /dev/stdin`, "awk script from stdin"},
		{"P-R4-MF4-i --exec=stdin", `echo 'BEGIN{system("pig")}' | gawk --exec=/dev/stdin`, "awk script from stdin"},
		{"P-R4-MF4-j --exec stdin sep", `echo 'BEGIN{system("pig")}' | gawk --exec /dev/stdin`, "awk script from stdin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("rtGuardCwd(%q) = %q, want verdict substring %q", tc.cmd, got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"P-R4-MF4-a-argvstdin", []string{"gawk", "-W", "file=-"}, "awk script from stdin"},
		{"P-R4-MF4-b-argvstdin", []string{"gawk", "-W", "file=/dev/stdin"}, "awk script from stdin"},
		{"P-R4-MF4-h-argvstdin", []string{"gawk", "-E", "/dev/stdin"}, "awk script from stdin"},
		{"P-R4-MF4-i-argvstdin", []string{"gawk", "--exec=/dev/stdin"}, "awk script from stdin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{
				id: tc.name, role: "worker",
				argv:  tc.argv,
				stdin: "BEGIN{system(\"pig\")}",
			}, "")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("guardCtxRunArgv %v + stdin = %q, want verdict substring %q", tc.argv, got, tc.want)
			}
		})
	}
	t.Run("P-R4-MF4-k -W file heredoc", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R4-MF4-k", role: "worker", cmd: "gawk -W file=- <<'EOF'\nBEGIN{system(\"pig\")}\nEOF"}, "")
		if !strings.Contains(got, "awk script from stdin") {
			t.Fatalf("gawk -W file=- heredoc = %q, want awk script from stdin", got)
		}
	})

	// 放行守卫正例(R4 零假阳纪律):find 自身 {}、xargs -- 分隔/./{} 前缀、
	// awk/git 合法数据、script 以值字母结尾的位置文件名不再吞 --。
	allowCases := []struct {
		name, cmd string
	}{
		{"R4-pos find perl -pe", `find . -exec perl -pe 's/a/b/' {} \;`},
		{"R4-pos find perl trailing", `find . -exec perl -pe 's/a/b/' {} other.txt \;`},
		{"R4-pos xargs perl -- token", `echo a.txt | xargs -I{} perl -pe 's/a/b/' -- {}`},
		{"R4-pos xargs perl dot-slash", `echo a.txt | xargs -I{} perl -pe 's/a/b/' ./{}`},
		{"R4-pos find awk -f -v", `find . -exec awk -f parse.awk -v fname={} {} \;`},
		{"R4-pos find git --git-dir", `find . -name .git -exec git --git-dir={} log -1 \;`},
		{"R4-pos find rg env -S", `find . -name '*.go' -exec rg env -S {} \;`},
		{"R4-pos git -c user.name", `xargs -a ` + payloadEvilAwk + ` -I{} git -cuser.name={} log`},
		{"R4-pos git -C glued", `find . -exec git -C{} status \;`},
		{"R4-pos awk glued -vf", `xargs -a ` + payloadEvilAwk + ` -I{} awk -vf={} 'END{print f}' /dev/null`},
		{"R4-pos awk glued -F", `xargs -a ` + payloadEvilAwk + ` -I{} awk -F{} 'END{print f}' /dev/null`},
		{"R4-pos awk --assign glued", `xargs -a ` + payloadEvilAwk + ` -I{} awk --assign=f={} 'END{print f}' /dev/null`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// R4-SF-3: script 以值字母结尾的位置文件名不再吞掉 --(xargs -a 无管道
	// 入口,避免上游 piped code verdict 掩盖)。
	t.Run("R4-pos script positional .o", func(t *testing.T) {
		payloadX := mkPayload("r4-x", "x\n")
		got := rtGuardCwd(t, rtCase{id: "R4-pos-script-o", role: "worker", cmd: `xargs -a ` + payloadX + ` -I% script /tmp/out.o -- %`}, "")
		if got != "ALLOW" {
			t.Fatalf("xargs script /tmp/out.o -- %% = %q, want ALLOW", got)
		}
	})

	// 目标层直断断言:R4 修复点的单元 verdict 不依赖外层规则兜出 BLOCK。
	t.Run("R4-unit env-split re-split chain", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
			want bool
		}{
			{"env -Senv -S", []string{"env", "-Senv -S", "find . -name {}"}, true},
			{"env -S nice nice env -S", []string{"env", "-S", "nice nice env -S", "find . -name {}"}, true},
			{"env -S nice nice nice env -S", []string{"env", "-S", "nice nice nice", "env", "-S", "find . -name {}"}, true},
		} {
			if got := wrapperChainEnvSplitHasToken(tc.argv, os.Getenv("PATH"), callerIdentity{}, "{}"); got != tc.want {
				t.Errorf("wrapperChainEnvSplitHasToken(%v) = %v, want %v", tc.argv, got, tc.want)
			}
		}
	})
	t.Run("R4-unit awk -W shapes direct", func(t *testing.T) {
		if _, _, hit := awkProgramFrags([]string{"-W", "file=-"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-W file=-) hit = %q, want awk script from stdin", hit)
		}
		if _, _, hit := awkProgramFrags([]string{"-W", "file=/dev/stdin"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-W file=/dev/stdin) hit = %q, want awk script from stdin", hit)
		}
		if _, _, hit := awkProgramFrags([]string{"-Wfile=-"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-Wfile=-) hit = %q, want awk script from stdin", hit)
		}
		if _, _, hit := awkProgramFrags([]string{"-E", "/dev/stdin"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-E /dev/stdin) hit = %q, want awk script from stdin", hit)
		}
		if _, _, hit := awkProgramFrags([]string{"--exec=/dev/stdin"}); hit != "awk script from stdin" {
			t.Errorf("awkProgramFrags(--exec=/dev/stdin) hit = %q, want awk script from stdin", hit)
		}
		prog, _, hit := awkProgramFrags([]string{"-e", "1", "-W", "source", "BEGIN{1}", "/dev/null"})
		if hit != "" || !strings.Contains(prog, "BEGIN{1}") {
			t.Errorf("awkProgramFrags(-W source PROG) = %q hit %q, want program containing BEGIN{1}", prog, hit)
		}
		prog2, _, hit2 := awkProgramFrags([]string{"-e", "1", "-W", "so=BEGIN{2}", "/dev/null"})
		if hit2 != "" || !strings.Contains(prog2, "BEGIN{2}") {
			t.Errorf("awkProgramFrags(-W so=PROG) = %q hit %q, want program containing BEGIN{2}", prog2, hit2)
		}
	})
	t.Run("R4-unit awkOptZone positional scan", func(t *testing.T) {
		if !awkOptZoneHasToken([]string{"-e", "1", "/dev/null", "-f", "{}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken(positional then -f {}) = false, want true")
		}
		if !awkOptZoneHasToken([]string{"-e", "1", "/dev/null", "--file={}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken(positional then --file={}) = false, want true")
		}
		if awkOptZoneHasToken([]string{"-vf={}", "/dev/null"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken(-vf={}) = true, want false (glued data assignment)")
		}
	})
	t.Run("R4-unit scriptOptWord positional", func(t *testing.T) {
		if consume, hit := scriptOptWordTokenStep([]string{"script", "/tmp/out.o", "--", "%"}, 1, "%"); consume != 0 || hit {
			t.Errorf("scriptOptWordTokenStep(positional /tmp/out.o) = %d,%v want 0,false", consume, hit)
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R5 (R7 闭环): R5-MF-1..4 / R5-SF-1..3 探针回归 —
// flagCodes+valShort 双槽消费恢复 sh -co/bash -co/node -pr/bun -pc 的 BLOCK;
// env -S 同层递归拆出内层 -S 载荷沿 token 传播闭合;awk 选项区裸 token
// 按 findPathToken 语义命中;gawk GNU 唯一前缀与 -W assign/--as 操作数消费
// 闭合。所有 dynamic code payload 精确断言走 xargs -a 无管道入口,stdin
// 程序源断言走 echo 管道与 argv+stdin 双通道(R3-Obs-2 隔离纪律)。
// ---------------------------------------------------------------------------
