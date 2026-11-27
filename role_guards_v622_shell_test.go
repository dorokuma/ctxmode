package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// role_guards_v622_shell_test.go — v6.2.2 regression tests: shell stdin/heredoc/analysis probes
// (Oracle R5–R13, Reviewer R4). Migrated losslessly from zz_r2fix_test.go.

func TestGuard_V622_OracleR5Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadEval := mkPayload("r5-eval", "--eval=require(\"child_process\").execSync(\"pig\")\n")
	payloadFooExec := mkPayload("r5-fooexec", "foo -exec pig ;\n")
	payloadCkpt := mkPayload("r5-ckpt", "a --checkpoint=1 --checkpoint-action=exec=pig\n")
	payloadEBegin := mkPayload("r5-ebegin", "-eBEGIN{system(\"pig\")}\n")
	payloadFstdin := mkPayload("r5-fstdin", "-f/dev/stdin\n")
	payloadEvilSo := mkPayload("r5-evilso", "/tmp/evil.so\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R5-MF-1: R6 回归修复 — flagCodes+valShort 集群的值槽先查动态词,
		// 待定代码槽再消费一个操作数(sh/bash/node/bun 全部恢复 BLOCK)。
		{"P-R5-MF1-a sh -co", `X='errexit pig'; sh -co $X 'echo hi'`, "dynamic code payload"},
		{"P-R5-MF1-b bash -co", `X='errexit pig'; bash -co $X 'echo hi'`, "dynamic code payload"},
		{"P-R5-MF1-c node -pr", `X='a.js -e require("child_process").execSync("pig")'; node -pr $X '1'`, "dynamic code payload"},
		{"P-R5-MF1-d bun -pc", `X='a.toml -e require("child_process").execSync("pig")'; bun -pc $X '1'`, "dynamic code payload"},
		{"P-R5-MF1-e node -pC separate", `X='a.js -e require("child_process").execSync("pig")'; node -pC default '1' -r $X`, "dynamic code payload"},
		{"P-R5-MF1-f node -pC glued", `X='a.js -e require("child_process").execSync("pig")'; node -pCdefault '1' -r $X`, "dynamic code payload"},
		{"P-R5-MF1-g xargs node -pC", `xargs -a ` + payloadEval + ` -I% node -pC default '1' %`, "dynamic code payload"},
		{"P-R5-MF1-h xargs node -pC glued", `xargs -a ` + payloadEval + ` -I% node -pCdefault '1' %`, "dynamic code payload"},
		// R5-MF-2: env -S 同层递归拆出内层 -S 载荷沿 token 传播。
		{"P-R5-MF2-a env -S -S find", `xargs -a ` + payloadFooExec + ` -I{} env -S "-S" "find . -name {}"`, "dynamic code payload"},
		{"P-R5-MF2-b env -S-S find", `xargs -a ` + payloadFooExec + ` -I{} env "-S-S" "find . -name {}"`, "dynamic code payload"},
		{"P-R5-MF2-c env -S split-string", `xargs -a ` + payloadFooExec + ` -I{} env -S "--split-string" "find . -name {}"`, "dynamic code payload"},
		{"P-R5-MF2-d env -S -i -S tar", `xargs -a ` + payloadCkpt + ` -I{} env -S "-i -S" "tar -cf /dev/null {}"`, "dynamic code payload"},
		// R5-MF-3: awk 选项区裸 token 按 findPathToken 语义命中(单词粘连
		// 选项注入 — mawk/gawk 均可触发)。
		{"P-R5-MF3-a gawk -e glued", `xargs -a ` + payloadEBegin + ` -I{} gawk -e '1' {}`, "dynamic code payload"},
		{"P-R5-MF3-b gawk -e /dev/null", `xargs -a ` + payloadEBegin + ` -I{} gawk -e '1' /dev/null {}`, "dynamic code payload"},
		{"P-R5-MF3-c awk -f devstdin", `xargs -a ` + payloadFstdin + ` -I{} awk -f /dev/null {}`, "dynamic code payload"},
		// R5-MF-4: gawk GNU 唯一前缀 / -i 库验证 / -W assign 操作数消费。
		{"P-R5-MF4-f -W assign program", `gawk -W assign 'x=1' 'BEGIN{system("pig")}'`, "pig"},
		{"P-R5-MF4-f2 -W field-separator", `gawk -W field-separator : 'BEGIN{system("pig")}'`, "pig"},
		{"P-R5-MF4-g --as program", `gawk --as 'x=1' 'BEGIN{system("pig")}'`, "pig"},
		{"P-R5-MF4-g2 --fie program", `gawk --fie : 'BEGIN{system("pig")}'`, "pig"},
		{"P-R5-MF4-h -l load xargs", `xargs -a ` + payloadEvilSo + ` -I{} gawk -e '1' -l '{}'`, "dynamic code payload"},
		{"P-R5-MF4-h2 -W lo xargs", `xargs -a ` + payloadEvilSo + ` -I{} gawk -e '1' -W lo '{}'`, "dynamic code payload"},
		{"P-R5-MF4-h3 -W e xargs", `xargs -a ` + payloadEvilSo + ` -I{} gawk -e '1' -W e '{}'`, "dynamic code payload"},
		{"P-R5-MF4-x1 --as xargs", `xargs -a ` + mkPayload("r5-begin2", "BEGIN{system(\"pig\")}\n") + ` -I{} gawk --as 'x=1' '{}'`, "dynamic code payload"},
		// R4-Obs-1: script 追加模式回归用例(补 R4 缺口)。
		{"P-R4-Obs1 script append", `xargs -a ` + mkPayload("r5-cflag", "-c pig\n") + ` script /dev/null`, "dynamic code payload"},
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

	// R5-MF-4 stdin 程序源管道:--include/-i/--e/-W e 各形态均须命中
	// awk script from stdin(echo 管道 + argv+stdin 双通道)。
	for _, tc := range []struct {
		name, cmd, want string
	}{
		{"P-R5-MF4-a --include=stdin pipe", `echo 'BEGIN{system("pig")}' | gawk --include=/dev/stdin '1'`, "awk script from stdin"},
		{"P-R5-MF4-a2 --include sep pipe", `echo 'BEGIN{system("pig")}' | gawk --include /dev/stdin '1'`, "awk script from stdin"},
		{"P-R5-MF4-b -i stdin pipe", `echo 'BEGIN{system("pig")}' | gawk -i /dev/stdin '1'`, "awk script from stdin"},
		{"P-R5-MF4-b2 -i glued pipe", `echo 'BEGIN{system("pig")}' | gawk -i/dev/stdin '1'`, "awk script from stdin"},
		{"P-R5-MF4-d --e=stdin pipe", `echo 'BEGIN{system("pig")}' | gawk --e=/dev/stdin`, "awk script from stdin"},
		{"P-R5-MF4-d2 --e sep pipe", `echo 'BEGIN{system("pig")}' | gawk --e /dev/stdin`, "awk script from stdin"},
		{"P-R5-MF4-e -W e=stdin pipe", `echo 'BEGIN{system("pig")}' | gawk -W e=/dev/stdin`, "awk script from stdin"},
		{"P-R5-MF4-e2 -W e sep pipe", `echo 'BEGIN{system("pig")}' | gawk -W e /dev/stdin`, "awk script from stdin"},
		{"P-R5-MF4-e3 -W in=stdin pipe", `echo 'BEGIN{system("pig")}' | gawk -W in=/dev/stdin '1'`, "awk script from stdin"},
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
		{"P-R5-MF4-c argvstdin --include=", []string{"gawk", "--include=/dev/stdin", "1"}, "awk script from stdin"},
		{"P-R5-MF4-c2 argvstdin -i sep", []string{"gawk", "-i", "/dev/stdin", "1"}, "awk script from stdin"},
		{"P-R5-MF4-c3 argvstdin --e=", []string{"gawk", "--e=/dev/stdin"}, "awk script from stdin"},
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

	// 放行守卫正例(R5 零假阳纪律):find 自身 {}、xargs --/./{} 拼写、
	// awk -v 纯数据、静态 sh -co、-- 后的 awk argv 数据。
	allowCases := []struct {
		name, cmd string
	}{
		{"R5-pos find perl -pe", `find . -exec perl -pe 's/a/b/' {} \;`},
		{"R5-pos find perl trailing", `find . -exec perl -pe 's/a/b/' {} other.txt \;`},
		{"R5-pos xargs perl -- token", `echo a.txt | xargs -I{} perl -pe 's/a/b/' -- {}`},
		{"R5-pos xargs perl dot-slash", `echo a.txt | xargs -I{} perl -pe 's/a/b/' ./{}`},
		{"R5-pos find awk -f -v", `find . -exec awk -f parse.awk -v fname={} {} \;`},
		{"R5-pos find awk -v data", `find . -exec awk -v f={} 'END {print f}' {} \;`},
		{"R5-pos xargs awk -vf glued", `echo x | xargs -I{} awk -vf={} 'END{print f}' /dev/null`},
		{"R5-pos xargs awk -- token", `echo x | xargs -I{} awk -f parse.awk -- {}`},
		{"R5-pos xargs awk dot-slash", `echo x | xargs -I{} awk -f parse.awk ./{}`},
		{"R5-pos sh -co static", `sh -co errexit 'echo hi'`},
		{"R5-pos gawk -- data", `gawk 'BEGIN{print ARGV[1]}' -- -f -`},
		{"R5-pos find rg env -S", `find . -name '*.go' -exec rg env -S {} \;`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// 目标层直断断言(R5-Obs 防掩盖纪律):skipEnvOperandsToken /
	// awkOptZoneHasToken findPathToken / awkWOperandProgram 的单元 verdict
	// 不依赖外层管道或外围规则兜出 BLOCK。
	t.Run("R5-unit env re-split token propagation", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
			want bool
		}{
			{"env -S -S", []string{"env", "-S", "-S", "find . -name {}"}, true},
			{"env -S-S", []string{"env", "-S-S", "find . -name {}"}, true},
			{"env -S -i -S", []string{"env", "-S", "-i -S", "find . -name {}"}, true},
			{"env -S benign", []string{"env", "-S", "echo hi"}, false},
			{"rg env -S operand", []string{"rg", "env", "-S", "{}"}, false},
		} {
			if got := wrapperChainEnvSplitHasToken(tc.argv, os.Getenv("PATH"), callerIdentity{}, "{}"); got != tc.want {
				t.Errorf("wrapperChainEnvSplitHasToken(%v) = %v, want %v", tc.argv, got, tc.want)
			}
		}
	})
	t.Run("R5-unit awkOptZone bare token find-vs-xargs", func(t *testing.T) {
		if !awkOptZoneHasToken([]string{"-e", "1", "{}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken xargs bare token = false, want true")
		}
		if awkOptZoneHasToken([]string{"-e", "1", "{}"}, "{}", true) {
			t.Errorf("awkOptZoneHasToken find own {} = true, want false")
		}
		if awkOptZoneHasToken([]string{"-e", "1", "./{}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken ./{} = true, want false")
		}
		if awkOptZoneHasToken([]string{"-e", "1", "--", "{}"}, "{}", false) {
			t.Errorf("awkOptZoneHasToken -- {} = true, want false (post-terminator data)")
		}
	})
	t.Run("R5-unit awk -W assign consumption", func(t *testing.T) {
		prog, _, hit := awkProgramFrags([]string{"-W", "assign", "x=1", "BEGIN{1}"})
		if hit != "" || !strings.Contains(prog, "BEGIN{1}") {
			t.Errorf("awkProgramFrags(-W assign x=1 PROG) = %q hit %q, want program BEGIN{1}", prog, hit)
		}
		prog2, _, hit2 := awkProgramFrags([]string{"--as", "x=1", "BEGIN{2}"})
		if hit2 != "" || !strings.Contains(prog2, "BEGIN{2}") {
			t.Errorf("awkProgramFrags(--as x=1 PROG) = %q hit %q, want program BEGIN{2}", prog2, hit2)
		}
		if _, _, hit3 := awkProgramFrags([]string{"--include=/dev/stdin", "1"}); hit3 != "awk script from stdin" {
			t.Errorf("awkProgramFrags(--include=/dev/stdin) hit = %q, want awk script from stdin", hit3)
		}
		if _, _, hit4 := awkProgramFrags([]string{"-i", "/dev/stdin", "1"}); hit4 != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-i /dev/stdin) hit = %q, want awk script from stdin", hit4)
		}
		if _, _, hit5 := awkProgramFrags([]string{"--e=/dev/stdin"}); hit5 != "awk script from stdin" {
			t.Errorf("awkProgramFrags(--e=/dev/stdin) hit = %q, want awk script from stdin", hit5)
		}
		if _, _, hit6 := awkProgramFrags([]string{"-l", "/dev/stdin"}); hit6 != "awk script from stdin" {
			t.Errorf("awkProgramFrags(-l /dev/stdin) hit = %q, want awk script from stdin", hit6)
		}
	})
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R6 (R8 终局收口): R6-MF-1..4 / R6-SF-1..2 探针回归 —
// POSIX shell pending -c 全链路对齐(sh -co errexit -o $X / sh -co errexit --
// /xargs -a sh -c -- 回归与逃逸闭合);awkClusterWOperand -W include/-W load
// 不再错置 sawFile;awkWOperandTokenStep/awkWOperandProgram 覆盖 -W '{}' /
// -W "$X" 选项名盲区与 awkProgramTokenHit 空程序门控;gawk 可选参数短选项
// d/D/L/o/p 粘连尾串立即结束集群;awk -- "$VAR" 与 clusterConsumesOperand
// 非纯字母尾 hasFlagCode 锁步对齐。所有 dynamic code payload 精确断言走
// xargs -a 无管道入口(R3-Obs-2 隔离纪律)。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR6Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadPig := mkPayload("r6-pig", "pig\n")
	payloadExec := mkPayload("r6-exec", "exec\n")
	payloadSource := mkPayload("r6-source", "source=BEGIN{system(\"pig\")}\n")
	payloadEBegin := mkPayload("r6-ebegin", "-eBEGIN{system(\"pig\")}\n")
	payloadEvilSo := mkPayload("r6-evilso", "/tmp/evil.so\n")
	payloadDevStdin := mkPayload("r6-devstdin", "/dev/stdin\n")
	payloadX := mkPayload("r6-x", "x\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R6-MF-1: POSIX shell pending -c 全链路对齐 — R7 回归(sh/bash -co
		// errexit -o $X 从 3ddc0a7 BLOCK 退化)与 -o/-- 逃逸全部恢复 BLOCK。
		{"P-R6-MF1-a sh -co -o X", `X='errexit pig'; sh -co errexit -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R6-MF1-b bash -co -o X", `X='errexit pig'; bash -co errexit -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R6-MF1-c bash -co -o pipefail", `bash -co errexit -o pipefail 'pig'`, "pig"},
		{"P-R6-MF1-d sh -co -- pig", `sh -co errexit -- 'pig'`, "pig"},
		{"P-R6-MF1-e sh -ce -o X", `X='errexit pig'; sh -ce -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R6-MF1-f xargs -I% sh -co -- %", `xargs -a ` + payloadPig + ` -I% sh -co errexit -- %`, "dynamic code payload"},
		{"P-R6-MF1-g xargs sh -c --", `xargs -a ` + payloadPig + ` sh -c --`, "dynamic code payload"},
		// R6-MF-2: -W include/-W load 不再错置 sawFile,位置主程序正常提取。
		{"P-R6-MF2-a -W include=", `gawk -W include=/dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF2-b -W include sep", `gawk -W include /dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF2-c -W i=", `gawk -W i=/dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF2-d -W load=time", `gawk -W load=time 'BEGIN{system("pig")}'`, "pig"},
		// R6-MF-3: -W '{}' / -W "$X" 选项名盲区与 awkProgramTokenHit 空程序
		// 门控跳过全部闭合。
		{"P-R6-MF3-a xargs awk -W '{}' /dev/stdin", `xargs -a ` + payloadExec + ` -I{} awk -W '{}' /dev/stdin`, "dynamic code payload"},
		{"P-R6-MF3-b xargs gawk -W '{}' '1'", `xargs -a ` + payloadSource + ` -I{} gawk -W '{}' '1'`, "dynamic code payload"},
		{"P-R6-MF3-c awk -W X /dev/stdin", `X='exec'; echo 'BEGIN{system("pig")}' | awk -W "$X" /dev/stdin`, "dynamic code payload"},
		{"P-R6-MF3-d gawk -W X 1", `X='source=BEGIN{system("pig")}'; gawk -W "$X" '1'`, "dynamic code payload"},
		{"P-R6-MF3-e gawk -e '' {}", `xargs -a ` + payloadEBegin + ` -I{} gawk -e '' {}`, "dynamic code payload"},
		{"P-R6-MF3-f gawk -e '' -l '{}'", `xargs -a ` + payloadEvilSo + ` -I{} gawk -e '' -l '{}'`, "dynamic code payload"},
		{"P-R6-MF3-g gawk -e '' -i '{}'", `xargs -a ` + payloadDevStdin + ` -I{} gawk -e '' -i '{}'`, "dynamic code payload"},
		// R6-MF-4: gawk 可选参数短选项 d/D/L/o/p 粘连尾串立即结束集群。
		{"P-R6-MF4-a -Lfatal", `gawk -Lfatal 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF4-b -Lno-ext", `gawk -Lno-ext 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF4-c -p/dev/null", `gawk -p/dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R6-MF4-d -d/tmp/v xargs", `xargs -a ` + payloadEBegin + ` -I{} gawk -d/tmp/v {} '1'`, "dynamic code payload"},
		// R6-SF-1: awk -- "$VAR" 在本机 mawk/gawk 直通 — !endOpts 改 !sawFile。
		{"P-R6-SF1-a awk -- VAR", `VAR='BEGIN{system("pig")}'; awk -- "$VAR"`, "dynamic code payload"},
		// R6-SF-2: clusterConsumesOperand 非纯字母尾保留 hasFlagCode。
		{"P-R6-SF2-a node -pCfoo-bar", `X='a.js -e require("child_process").execSync("pig")'; node -pCfoo-bar '1' -r $X`, "dynamic code payload"},
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

	// 放行守卫正例(R6 零假阳纪律):合法 $0/$1 数据槽、-W assign 纯数据、
	// awk -- 后文件名、gawk -Lfatal 合法 lint 值。
	allowCases := []struct {
		name, cmd string
	}{
		{"R6-pos sh -co errexit echo", `sh -co errexit 'echo hi'`},
		{"R6-pos sh -co errexit $1", `sh -co errexit 'echo "$1"' _ "$ARG"`},
		{"R6-pos xargs sh -c $1", `xargs -a ` + payloadX + ` -I{} sh -c 'echo "$1"' _ {}`},
		{"R6-pos gawk -W assign", `gawk -W assign 'x=1' 'BEGIN{print x}'`},
		{"R6-pos xargs -W assign {}", `xargs -a ` + payloadX + ` -I{} gawk -W assign '{}' '1' /dev/null`},
		{"R6-pos xargs -W assign=x={}", `xargs -a ` + payloadX + ` -I{} gawk -W 'assign=x={}' '1' /dev/null`},
		{"R6-pos awk -f -- $FILE", `awk -f parse.awk -- "$FILE"`},
		{"R6-pos awk '1' -- $FILE", `awk '1' -- "$FILE"`},
		{"R6-pos gawk -Lfatal lint", `gawk -Lfatal 'BEGIN{print 1}'`},
		{"R6-pos gawk -- data", `gawk 'BEGIN{print ARGV[1]}' -- -f -`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R7 (R9 终局收口): R7-MF-1..4 / R7-SF-1 探针回归 —
// awkProgramFrags 恢复 !endOpts 动态词门控(awk -f /dev/null "$X" / gawk '1'
// "$X" 系列 R8 安全回归);unwrapShellWordStep 的 isCluster 通道杜绝单字
// --long-opt 落入短选项集群(bash --restricted 四路 stdin 回归);裸 -c 布
// 尔语义与 POSIX 单横杠 "-"/"+" 终止符结算(sh -c -o ... -o $X / sh -c -
// 'pig' / xargs -a sh -c -);mawk -W 语法冲突(-Wi/-W i/-W in 布尔吞程序
// 与逗号串联 -W interactive,exec);awk 纯数据赋值槽无引号词拆分拦截
// (-v/-F/--assign/-W assign)。所有探针仅依赖基线共有入口 rtGuardCwd
// 与 guardCtxRunStdin(argv 通道)。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR7Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadPig := mkPayload("r7-pig", "pig\n")
	payloadX := mkPayload("r7-x", "x\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R7-MF-1: awkProgramFrags -- 前动态选项注入 R8 回归恢复 BLOCK。
		{"P-R7-MF1-a awk -f null X", `X='-f/dev/stdin'; echo 'BEGIN{system("pig")}' | awk -f /dev/null "$X"`, "dynamic code payload"},
		{"P-R7-MF1-b awk -f null split X", `X='-f /dev/stdin'; echo 'BEGIN{system("pig")}' | awk -f /dev/null $X`, "dynamic code payload"},
		{"P-R7-MF1-c gawk 1 X", `X='-eBEGIN{system("pig")}'; gawk '1' "$X"`, "dynamic code payload"},
		{"P-R7-MF1-d gawk -e 1 X", `X='-eBEGIN{system("pig")}'; gawk -e '1' "$X"`, "dynamic code payload"},
		{"P-R7-MF1-e gawk 1 ./X", `X='x -e BEGIN{system("pig")}'; gawk '1' ./$X`, "dynamic code payload"},
		// R7-MF-2: 单字 --long-opt 不再落入短选项集群(bash --restricted
		// 管道/here-string/heredoc/stdin 四路 R8 回归)。
		{"P-R7-MF2-a pipe bash --restricted", `echo 'pig' | bash --restricted`, "piped code to shell"},
		// 注: <<< 是 bash-only 语法,外层 dash 语法门在 stdin 筛查前先 BLOCK —
		// 该探针的裁决串不含 pig(与 Oracle R7 预期串的偏差,判别性证据由
		// 探针 a/c/d 承担,此处断言其恒定 BLOCK 不回归为 ALLOW)。
		{"P-R7-MF2-b bash --restricted herestring", `bash --restricted <<< 'pig'`, "bash-only syntax"},
		{"P-R7-MF2-c bash --restricted heredoc", `bash --restricted <<'EOF'
pig
EOF`, "pig"},
		// R7-MF-3 路径 A: 裸 -c 布尔语义 + 裸 -o/+o/-O/+O 动态词校验。
		{"P-R7-MF3-a sh -c -o -o X", `X='errexit pig'; sh -c -o errexit -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R7-MF3-b bash -c -o -o X", `X='errexit pig'; bash -c -o errexit -o $X 'echo hi'`, "dynamic code payload"},
		{"P-R7-MF3-c sh -c +o +o X", `X='errexit pig'; sh -c +o errexit +o $X 'echo hi'`, "dynamic code payload"},
		{"P-R7-MF3-d bash -c -O -O X", `X='extglob pig'; bash -c -O extglob -O $X 'echo hi'`, "dynamic code payload"},
		// R7-MF-3 路径 B: POSIX 单横杠 "-" 终止符结算。
		{"P-R7-MF3-e sh -c - pig", `sh -c - 'pig'`, "pig"},
		{"P-R7-MF3-f bash -c - pig", `bash -c - 'pig'`, "pig"},
		{"P-R7-MF3-g sh -co errexit - pig", `sh -co errexit - 'pig'`, "pig"},
		{"P-R7-MF3-h sh -c - X", `X='pig'; sh -c - "$X"`, "dynamic code payload"},
		{"P-R7-MF3-i xargs sh -c -", `xargs -a ` + payloadPig + ` sh -c -`, "dynamic code payload"},
		// R7-MF-4: mawk -W 语法冲突(布尔吞程序与逗号串联)。
		{"P-R7-MF4-a awk -Wi", `awk -Wi 'BEGIN{system("pig")}'`, "pig"},
		{"P-R7-MF4-b awk -W i", `awk -W i 'BEGIN{system("pig")}'`, "pig"},
		{"P-R7-MF4-c awk -W in", `awk -W in 'BEGIN{system("pig")}'`, "pig"},
		{"P-R7-MF4-d awk -W interactive,exec", `echo 'BEGIN{system("pig")}' | awk -W interactive,exec /dev/stdin`, "awk script from stdin"},
		// R7-SF-1: awk 纯数据赋值槽无引号词拆分选项注入。
		{"P-R7-SF1-a awk -v x=VAR", `VAR='1 -f /dev/stdin'; echo 'BEGIN{system("pig")}' | awk -v x=$VAR -f /dev/null`, "dynamic code payload"},
		{"P-R7-SF1-b gawk -W assign=x=VAR", `VAR='1 -e BEGIN{system("pig")}'; gawk -W assign=x=$VAR '1'`, "dynamic code payload"},
		{"P-R7-SF1-c gawk -W assign VAR", `VAR='x=1 -e BEGIN{system("pig")}'; gawk -W assign $VAR '1'`, "dynamic code payload"},
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

	// R7-MF-2-d: guardCtxRunStdin argv+stdin 通道(argv 不走 shell 字符串)。
	t.Run("P-R7-MF2-d argv bash --restricted stdin", func(t *testing.T) {
		got := rtGuardCwd(t, rtCase{id: "P-R7-MF2-d", role: "worker", argv: []string{"bash", "--restricted"}, stdin: "pig\n"}, "")
		if got == "ALLOW" {
			t.Fatalf("rtGuardCwd(argv bash --restricted stdin pig) = ALLOW, want a guard block")
		}
		if !strings.Contains(got, "pig") {
			t.Fatalf("rtGuardCwd(argv bash --restricted) = %q, want verdict substring %q", got, "pig")
		}
	})

	// 放行守卫正例(R7 零假阳纪律,含 R6 既有放行契约的核心行)。
	allowCases := []struct {
		name, cmd string
	}{
		{"R7-pos awk -f -- $FILE", `awk -f parse.awk -- "$FILE"`},
		{"R7-pos awk '1' -- $FILE", `awk '1' -- "$FILE"`},
		{"R7-pos awk 1 $PWD data", `awk '1' "$PWD/data.txt"`},
		{"R7-pos awk glob log", `awk '{print $1}' /tmp/*.log`},
		{"R7-pos awk f static", `f=/tmp/data.log; awk '{print $1, $2}' "$f"`},
		{"R7-pos awk -v ts quoted", `val=$(date +%s); awk -v ts="$val" 'BEGIN{print ts}'`},
		{"R7-pos gawk -W assign=x=quoted", `gawk -W assign=x="$VAR" '1'`},
		{"R7-pos gawk -W assign quoted", `gawk -W assign "$VAR" '1'`},
		{"R7-pos awk -Wi benign", `awk -Wi 'BEGIN{print 1}'`},
		{"R7-pos gawk -W i devnull benign", `gawk -W i /dev/null 'BEGIN{print 1}'`},
		{"R7-pos bash --restricted scriptfile", `bash --restricted "a'b.sh"`},
		{"R7-pos sh -c $1", `sh -c 'echo "$1"' _ "$ARG"`},
		{"R7-pos sh -c -o errexit $1", `sh -c -o errexit 'echo "$1"' _ "$ARG"`},
		{"R7-pos sh -c - $1", `sh -c - 'echo "$1"' _ "$ARG"`},
		{"R7-pos xargs sh -c - $1", `xargs -a ` + payloadX + ` -I{} sh -c - 'echo "$1"' _ {}`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

func TestGuard_V622_OracleR8Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadPigProg := mkPayload("r8-prog", "BEGIN{system(\"pig\")}\n")
	payloadPig := mkPayload("r8-pig", "pig\n")
	payloadX := mkPayload("r8-x", "x\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R8-MF-1: -Wi/-W in 碰撞值经独立 aux 通道,不再压死位置主程序
		// 与 -- 后动态程序提取(R9 引入的 gawk 直通回归)。
		{"P-R8-MF1-a gawk -W i devnull pig", `gawk -W i /dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R8-MF1-b gawk -Wi devnull pig", `gawk -Wi /dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R8-MF1-c gawk -W in devnull pig", `gawk -W in /dev/null 'BEGIN{system("pig")}'`, "pig"},
		{"P-R8-MF1-d gawk -W i devnull -- VAR", `VAR='BEGIN{system("pig")}'; gawk -W i /dev/null -- "$VAR"`, "dynamic code payload"},
		{"P-R8-MF1-e xargs gawk -W i devnull -- tok", `xargs -a ` + payloadPigProg + ` -I{} gawk -W i /dev/null -- '{}'`, "dynamic code payload"},
		{"P-R8-MF1-f xargs gawk -W i devnull tok prog", `xargs -a ` + payloadPig + ` -I{} gawk -W i /dev/null 'BEGIN{system("{}")}'`, "dynamic code payload"},
		// R8-MF-2: awkProgramLongStep 接入 --assign/--field-separator
		// 分离值的 awkDataValSplitHit(无引号词拆分重新武装选项解析)。
		{"P-R8-MF2-a gawk --as VAR", `VAR='x=1 -e BEGIN{system("pig")}'; gawk --as $VAR '1'`, "dynamic code payload"},
		{"P-R8-MF2-b gawk --assign VAR", `VAR='x=1 -e BEGIN{system("pig")}'; gawk --assign $VAR '1'`, "dynamic code payload"},
		{"P-R8-MF2-c gawk --field-separator VAR", `VAR=', -e BEGIN{system("pig")}'; gawk --field-separator $VAR '1'`, "dynamic code payload"},
		{"P-R8-MF2-d gawk --fie VAR", `VAR=', -e BEGIN{system("pig")}'; gawk --fie $VAR '1'`, "dynamic code payload"},
		// R8-MF-3: MAWK_LONG_OPTIONS 纳入 envHookVars(KEY=VAL 前缀/export/env 通路)。
		{"P-R8-MF3-a MAWK ignore --file", `MAWK_LONG_OPTIONS=ignore awk --file=/dev/null 'BEGIN{system("pig")}'`, "MAWK_LONG_OPTIONS"},
		{"P-R8-MF3-b MAWK ignore --assign", `MAWK_LONG_OPTIONS=ignore awk --assign 'BEGIN{system("pig")}'`, "MAWK_LONG_OPTIONS"},
		{"P-R8-MF3-c MAWK warn --file", `MAWK_LONG_OPTIONS=warn awk --file=/dev/null 'BEGIN{system("pig")}'`, "MAWK_LONG_OPTIONS"},
		{"P-R8-MF3-d MAWK allow --i", `MAWK_LONG_OPTIONS=allow awk --i 'BEGIN{system("pig")}'`, "MAWK_LONG_OPTIONS"},
		// 附加反例守卫:引号毒化 / 末项非 exec 的逗号链 / R8-Obs-1 穿透 here-string。
		{"R8-neg gawk -W i quote poison", `gawk -W i "a'b" 'BEGIN{system("pig")}'`, "pig"},
		{"R8-neg awk -W i,interactive pig", `awk -W i,interactive 'BEGIN{system("pig")}'`, "pig"},
		{"R8-neg bash -c nested restricted herestring", `bash -c "bash --restricted <<< 'pig'"`, "pig"},
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

	// P-R8-MF3-e: ctx_run env 通道的 MAWK_LONG_OPTIONS 覆盖拦截。
	t.Run("P-R8-MF3-e guardCtxRunEnv MAWK", func(t *testing.T) {
		rule, detail := guardCall{subagent: true}.guardCtxRunEnv(map[string]string{"MAWK_LONG_OPTIONS": "ignore"})
		if rule != "subagent_nested_agent" || detail != "env MAWK_LONG_OPTIONS" {
			t.Fatalf("guardCtxRunEnv(MAWK_LONG_OPTIONS=ignore) = (%q, %q), want (%q, %q)", rule, detail, "subagent_nested_agent", "env MAWK_LONG_OPTIONS")
		}
	})

	// P-R8-SF1-c: 逗号末项名契约 — -W interactive,exec FILE 标记 sawFile。
	t.Run("P-R8-SF1-c awkProgramFrags sawFile contract", func(t *testing.T) {
		_, sawFile, hit := awkProgramFrags([]string{"-W", "interactive,exec", "/tmp/evil.awk"})
		if hit != "" {
			t.Fatalf("awkProgramFrags hit = %q, want empty", hit)
		}
		if !sawFile {
			t.Fatalf("awkProgramFrags(-W interactive,exec FILE) sawFile = false, want true")
		}
	})

	// 放行守卫正例(R8 零假阳纪律)。
	allowCases := []struct {
		name, cmd string
	}{
		{"P-R8-SF1-a awk -W interactive,exec parse", `awk -W interactive,exec parse.awk "$FILE"`},
		{"P-R8-SF1-b xargs awk -W interactive,exec parse", `xargs -a ` + payloadX + ` -I{} awk -W interactive,exec parse.awk {}`},
		{"R8-pos awk -Winteractive,exec parse", `awk -Winteractive,exec parse.awk "$FILE"`},
		{"R8-pos gawk --assign quoted", `VAR='x=1'; gawk --assign "$VAR" '1'`},
		{"R8-pos gawk --as quoted", `VAR='x=1'; gawk --as "$VAR" '1'`},
		{"R8-pos gawk --field-separator quoted", `SEP=','; gawk --field-separator "$SEP" '1'`},
		{"R8-pos awk -Wi benign", `awk -Wi 'BEGIN{print 1}'`},
		{"R8-pos gawk -W i devnull benign", `gawk -W i /dev/null 'BEGIN{print 1}'`},
		{"R8-pos gawk -W i devnull benign -- FILE", `gawk -W i /dev/null 'BEGIN{print 1}' -- "$FILE"`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// v6.2.2 Oracle R9 (R9 终局收口): R9-MF-1..4 探针回归 —
// R9-MF-1: -Wi/-W i/-W in 碰撞值以 '-' 开头(gawk --include 库文件语义
// 与 mawk 布尔冲突不可调和)一律 fail-closed,不再把 -v/-F/-f/-W 选项词
// 吞入 aux 丢弃真实主程序或放行 -f /dev/stdin;
// R9-MF-2: isSingleWordSplitSafe 收紧全部单值选项槽 — 无引号通配符
// (cmdSubPlaceholderGlob)路径展开产出 N>=2 个 argv 词,match[1..] 溢出
// 至主程序/命令头/子命令槽(awk -F B* / env -a p* / xargs -a p* /
// flock -w 0* / git -C g* / npx --cache p*);
// R9-MF-3: skipEnvOperandsToken 三重缺陷 — GNU env 消费任何含 '=' 的
// 操作数(POSIX 键与否、`--` 之后均为赋值),且 `env FOO=$X` 无引号词
// 拆分(env 的 argv 不是 shell 前缀赋值);
// R9-MF-4: TAR_OPTIONS 与 BASH_FUNC_* 纳入 envHookVars/isEnvHookVar。
// 全部探针仅依赖基线共有入口 rtGuardCwd 与 guardCall.guardCtxRunEnv。
// ---------------------------------------------------------------------------

func TestGuard_V622_OracleR9Probes(t *testing.T) {
	mkPayload := func(name, content string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	payloadProg := mkPayload("r9-prog", "BEGIN{system(\"pig\")}\n")
	payloadX := mkPayload("r9-x", "x\n")

	blockCases := []struct {
		name, cmd, want string
	}{
		// R9-MF-1: -Wi/-W i/-W in 碰撞值以 '-' 开头一律 fail-closed。
		{"P-R9-MF1-a awk -Wi -v x=1 pig", `awk -Wi -v x=1 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-b awk -W i -v x=1 pig", `awk -W i -v x=1 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-c awk -W in -F : pig", `awk -W in -F : 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-d awk -Wi -f devstdin", `echo 'BEGIN{system("pig")}' | awk -Wi -f /dev/stdin`, "dynamic code payload"},
		{"P-R9-MF1-e awk -Wi -W exec devstdin", `echo 'BEGIN{system("pig")}' | awk -Wi -W exec /dev/stdin`, "dynamic code payload"},
		{"P-R9-MF1-f awk -Wi -W i pig", `awk -Wi -W i 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-g awk -W interactive,i -v pig", `awk -W interactive,i -v x=1 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"P-R9-MF1-h awk -Wi -v x=1 -- VAR", `VAR='BEGIN{system("pig")}'; awk -Wi -v x=1 -- "$VAR"`, "dynamic code payload"},
		{"P-R9-MF1-i xargs awk -Wi -v x=1 -- tok", `xargs -a ` + payloadProg + ` -I{} awk -Wi -v x=1 -- '{}'`, "dynamic code payload"},
		// R9-MF-2: 单值选项槽无引号 glob 多词溢出。
		{"P-R9-MF2-a awk -F glob", `awk -F B*`, "dynamic code payload"},
		{"P-R9-MF2-b awk -v a=1 glob", `awk -v a=1*`, "dynamic code payload"},
		{"P-R9-MF2-c gawk --assign glob", `gawk --assign a=1*`, "dynamic code payload"},
		{"P-R9-MF2-d gawk -W assign glob", `gawk -W assign a=1*`, "dynamic code payload"},
		{"P-R9-MF2-e env -a glob", `env -a p*`, "dynamic option"},
		{"P-R9-MF2-f xargs -a glob", `xargs -a p*`, "dynamic command head"},
		{"P-R9-MF2-g flock -w glob", `flock -w 0* pig`, "dynamic code payload"},
		{"P-R9-MF2-h git -C glob", `git -C g* -Opig foo`, "git dynamic global option"},
		{"P-R9-MF2-i npx --cache glob", `npx --cache p*`, "dynamic code payload"},
		// R9-MF-3: skipEnvOperandsToken 三重缺陷。
		{"P-R9-MF3-a env a.b=1 pig", `env 'a.b=1' pig`, "pig"},
		{"P-R9-MF3-b env a-b=1 hc", `env 'a-b=1' hc list`, "hc"},
		{"P-R9-MF3-c env -- -x=1 pig", `env -- -x=1 pig`, "pig"},
		{"P-R9-MF3-d env -- a.b=1 pig", `env -- 'a.b=1' pig`, "pig"},
		{"P-R9-MF3-e env FOO=X unquoted", `X='1 pig'; env FOO=$X`, "dynamic option"},
		{"P-R9-MF3-f xargs env a.b=1 env -S", `xargs -a ` + payloadX + ` -I{} env 'a.b=1' env -S "find . -name {}"`, "dynamic code payload"},
		// R9-MF-4: TAR_OPTIONS / BASH_FUNC_* 钩子变量。
		{"P-R9-MF4-a TAR_OPTIONS use-compress-program", `TAR_OPTIONS='--use-compress-program=pig' tar -cf /dev/null /dev/null`, "TAR_OPTIONS"},
		{"P-R9-MF4-b TAR_OPTIONS checkpoint-action", `TAR_OPTIONS='--checkpoint=1 --checkpoint-action=exec=pig' tar -cf /dev/null /dev/null`, "TAR_OPTIONS"},
		{"P-R9-MF4-e env BASH_FUNC bash", `env 'BASH_FUNC_echo%%=() { pig; }' bash -c 'echo hi'`, "BASH_FUNC_echo%%"},
		// 附加回归(Oracle R9 底部):-Wi - 保精准 stdin 裁决;-W i -foo
		// 与 glob/`--` 变体全 BLOCK。
		{"R9-reg awk -Wi dash stdin", `awk -Wi -`, "awk script from stdin"},
		{"R9-reg gawk -W i -foo pig", `gawk -W i -foo 'BEGIN{system("pig")}'`, "dynamic code payload"},
		{"R9-reg env -- FOO=X unquoted", `X='1 pig'; env -- FOO=$X`, "dynamic option"},
		{"R9-reg gawk --field-separator glob", `gawk --field-separator B*`, "dynamic code payload"},
		{"R9-reg gawk -W assign=a=1 glob", `gawk -W assign=a=1*`, "dynamic code payload"},
		{"R9-reg env --argv0 glob", `env --argv0 p*`, "dynamic option"},
		{"R9-reg env -C glob", `env -C p*`, "dynamic option"},
		{"R9-reg xargs --arg-file glob", `xargs --arg-file p*`, "dynamic command head"},
		{"R9-reg flock --timeout glob", `flock --timeout 0* pig`, "dynamic code payload"},
		{"R9-reg flock -xw glob", `flock -xw 0* pig`, "dynamic code payload"},
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

	// P-R9-MF4-c: ctx_run env 通道的 TAR_OPTIONS 覆盖拦截。
	t.Run("P-R9-MF4-c guardCtxRunEnv TAR_OPTIONS", func(t *testing.T) {
		rule, detail := guardCall{subagent: true}.guardCtxRunEnv(map[string]string{"TAR_OPTIONS": "--use-compress-program=pig"})
		if rule != "subagent_nested_agent" || detail != "env TAR_OPTIONS" {
			t.Fatalf("guardCtxRunEnv(TAR_OPTIONS) = (%q, %q), want (%q, %q)", rule, detail, "subagent_nested_agent", "env TAR_OPTIONS")
		}
	})

	// P-R9-MF4-d: ctx_run env 通道的 BASH_FUNC_* 覆盖拦截。
	t.Run("P-R9-MF4-d guardCtxRunEnv BASH_FUNC", func(t *testing.T) {
		rule, detail := guardCall{subagent: true}.guardCtxRunEnv(map[string]string{"BASH_FUNC_echo%%": "() { pig; }"})
		if rule != "subagent_nested_agent" || detail != "env BASH_FUNC_echo%%" {
			t.Fatalf("guardCtxRunEnv(BASH_FUNC_echo%%) = (%q, %q), want (%q, %q)", rule, detail, "subagent_nested_agent", "env BASH_FUNC_echo%%")
		}
	})

	// 放行守卫正例(R9 零假阳纪律):带引号动态值、单字 glob 多文件操作数、
	// 纯波浪线路径与非 POSIX 键 env 赋值全部保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R9-pos awk -W interactive -v benign", `awk -W interactive -v x=1 'BEGIN{print 1}'`},
		{"R9-pos awk -v x=1 -Wi benign", `awk -v x=1 -Wi 'BEGIN{print 1}'`},
		{"R9-pos awk -Wi benign", `awk -Wi 'BEGIN{print 1}'`},
		{"R9-pos gawk -W i devnull benign", `gawk -W i /dev/null 'BEGIN{print 1}'`},
		{"R9-pos gawk -W i devnull benign -- FILE", `gawk -W i /dev/null 'BEGIN{print 1}' -- "$FILE"`},
		{"R9-pos awk glob log", `awk '{print $1}' /tmp/*.log`},
		{"R9-pos awk -v ts quoted", `awk -v ts="$val" 'BEGIN{print ts}'`},
		{"R9-pos env a.b=1 ls", `env 'a.b=1' ls`},
		{"R9-pos env FOO=X quoted", `env FOO="$X" ls`},
		{"R9-pos env -- FOO=X quoted VAR", `env -- FOO="$X" ls "$VAR"`},
		{"R9-pos env -- ls VAR", `env -- ls "$VAR"`},
		// 注: Oracle R9 正例列表中的 `env -C "$PWD" ls` 未纳入 — R2-4 既有契约
		// (zz_r2fix_test.go:130)对动态 chdir 目录一律 fail-closed,属 Oracle 与
		// 基线固定契约的冲突,不改核心策略,报告中列明偏差。
		{"R9-pos xargs -a FILE grep", `xargs -a "$FILE" grep foo`},
		{"R9-pos flock -w T lk true", `flock -w "$T" /tmp/lk true`},
		{"R9-pos git -C DIR status", `git -C "$DIR" status`},
		{"R9-pos npx --userconfig tilde", `npx --userconfig ~/.npmrc tsc --noEmit`},
		{"R9-pos FOO=X shell prefix true", `FOO=$X true`},
		{"R9-pos python glob pytest", `python3 -m pytest tests/*.py`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// TestGuard_V622_OracleR10Probes covers the Oracle R10 must-fix matrix:
// tar/find/sed/ssh separated single-value operand slots must require
// isSingleWordSplitSafe on dynamic words (R10-MF-1/2/3), the separated
// --checkpoint-action operand must refuse every dynamic word, and a
// declaration builtin demoted by a non-assignment wrapper (command/
// builtin) must reject non-split-safe dynamic export operands
// (R10-MF-4) — plus the shell_ast.go isEnvHookVar closure for
// GIT_CONFIG_PARAMETERS-style hook variables. Zero new production symbols
// are referenced here: every probe goes through rtGuardCwd.
func TestGuard_V622_OracleR10Probes(t *testing.T) {
	blockCases := []struct {
		name, cmd, want string
	}{
		// R10-MF-1: tar 分离值槽词拆分/glob 溢出与动态 --checkpoint-action。
		{"P-R10-MF1-a tar checkpoint-action quoted VAR", `VAR='exec=pig'; tar --checkpoint=1 --checkpoint-action "$VAR" -cf /dev/null /dev/null`, "dynamic code payload"},
		{"P-R10-MF1-b tar -cf unquoted VAR", `VAR='/dev/null -Ipig'; tar -cf $VAR /dev/null`, "dynamic code payload"},
		{"P-R10-MF1-c tar -f unquoted VAR", `VAR='/dev/null --use-compress-program=pig'; tar -f $VAR -c /dev/null`, "dynamic code payload"},
		{"P-R10-MF1-d tar --file unquoted VAR", `VAR='/dev/null --use-compress-program=pig'; tar --file $VAR -c /dev/null`, "dynamic code payload"},
		{"P-R10-MF1-e tar cfI glob", `tar cfI p*`, "dynamic code payload"},
		{"P-R10-MF1-e2 tar cfI unquoted VAR", `X='/dev/null pig /dev/null'; tar cfI $X`, "dynamic code payload"},
		// R10-MF-2: find -name/-fprintf 值槽词拆分与 glob 吞噬 -exec。
		{"P-R10-MF2-a find -name unquoted VAR", `VAR='null -exec pig ;'; find /dev/null -name $VAR`, "find dynamic predicate"},
		{"P-R10-MF2-b find -fprintf glob", `find /dev/null -fprintf p* -exec pig \;`, "find dynamic predicate"},
		{"P-R10-MF2-c find -fprintf unquoted VAR", `VAR='/dev/null fmt'; find /dev/null -fprintf $VAR -exec pig \;`, "find dynamic predicate"},
		// R10-MF-3: sed -l/--line-length 与 ssh 值选项分离值槽。
		{"P-R10-MF3-a sed -l unquoted VAR", `VAR='80 -e 1epig'; sed -e '1p' -l $VAR CHANGELOG.md`, "dynamic code payload"},
		{"P-R10-MF3-a2 sed --line-length unquoted VAR", `VAR='80 -e 1epig'; sed -e '1p' --line-length $VAR CHANGELOG.md`, "dynamic code payload"},
		{"P-R10-MF3-b sed -l glob", `sed -l 1* CHANGELOG.md`, "dynamic code payload"},
		{"P-R10-MF3-b2 sed --line-length glob", `sed --line-length 1* CHANGELOG.md`, "dynamic code payload"},
		{"P-R10-MF3-c ssh -p unquoted VAR", `VAR='22 -o ProxyCommand=pig'; ssh -p $VAR dmit ls`, "dynamic code payload"},
		{"P-R10-MF3-d ssh -l glob", `ssh -l p* a true`, "dynamic code payload"},
		// R10-MF-4: command/builtin export 词拆分导出与 GIT_CONFIG_* 钩子变量。
		{"P-R10-MF4-a command export TAR_OPTIONS", `X='1 TAR_OPTIONS=--use-compress-program=pig'; command export FOO=$X; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R10-MF4-b builtin export BASH_FUNC", `bash -c 'X="1 BASH_FUNC_echo%%=() { pig; }"; builtin export FOO=$X; bash -c "echo hi"'`, "env dynamic export"},
		{"P-R10-MF4-c command export glob", `command export FOO=T*`, "env dynamic export"},
		// R11-MF-3: the UNQUOTED spelling is the discriminating probe — the
		// quoted variant hits paramExpD2Ambiguous before reaching
		// peAssignsHookOrTaint, so it could never reproduce RED on b13a82b.
		{"P-R10-MF4-d GIT_CONFIG_PARAMETERS paramexp", `set -a; printf '' ${GIT_CONFIG_PARAMETERS:='alias.x=!pig'}; git x`, ""},
		{"P-R10-MF4-d2 GIT_CONFIG_PARAMETERS quoted", `set -a; printf '' "${GIT_CONFIG_PARAMETERS:='alias.x=!pig'}"; git x`, ""},
		{"P-R10-MF4-e GIT_CONFIG_PARAMETERS for-loop", `set -a; for GIT_CONFIG_PARAMETERS in "'alias.x=!pig'"; do git x; done`, ""},
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

	// 放行守卫正例(R10 零假阳纪律):带引号单值槽、BSD 消耗槽带引号值、
	// xargs 静态 {} 替换、裸/包装声明内建的带引号与无包装动态赋值全部
	// 保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R10-pos tar -cf quoted OUT", `tar -cf "$OUT" /tmp/*.log`},
		{"R10-pos tar -C xf quoted", `tar -C "$DIR" -xf "$ARCHIVE"`},
		{"R10-pos find -name quoted PAT", `find . -name "$PAT"`},
		{"R10-pos find PWD maxdepth", `find "$PWD" -maxdepth 1`},
		{"R10-pos xargs find -ctime token", `echo 5 | xargs -I{} find . -ctime {}`},
		{"R10-pos find -exec rg", `find . -name '*.go' -exec rg foo {} \;`},
		{"R10-pos sed -l quoted N", `sed -l "$N" '1p' CHANGELOG.md`},
		{"R10-pos ssh -p quoted PORT", `ssh -p "$PORT" dmit ls`},
		{"R10-pos ssh -i quoted KEY", `ssh -i "$KEY" dmit ls`},
		{"R10-pos command export quoted", `command export FOO="$X"`},
		{"R10-pos bash -c export quoted", `bash -c 'export FOO="$X"'`},
		{"R10-pos bare export unquoted", `export FOO=$X`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// TestGuard_V622_OracleR11Probes covers the Oracle R11 must-fix matrix:
// trailing dangling tar value options must never panic the guard
// (R11-MF-1), quoted/escaped/enum-expanded/env -S-rewritten declaration
// builtins lose their field-splitting exemption (R11-MF-2), and
// printf -v/read/getopts write-target slots must vet glued and repeated
// spellings plus dynamic single-value operands (R11-MF-3). Zero new
// production symbols are referenced here: every probe goes through
// rtGuardCwd so an independent verifier can copy this file onto the
// pre-fix tree fd8f417 and reproduce FAIL/panic directly.
func TestGuard_V622_OracleR11Probes(t *testing.T) {
	// R11-MF-1: trailing dangling value options must not panic. On the
	// pre-fix tree ANY of these crashes the test binary with
	// `panic: index out of range`; the rows assert nothing about the
	// verdict itself — reaching the comparison IS the assertion.
	noPanicShell := []struct {
		name, cmd string
	}{
		{"P-R11-MF1-a tar -f dangling", `tar -f`},
		{"P-R11-MF1-b tar --file dangling", `tar --file`},
		{"P-R11-MF1-b2 tar -cf then -C dangling", `tar -cf /dev/null -C`},
		{"P-R11-MF1-b3 tar -C dangling", `tar -C`},
		{"P-R11-MF1-b4 tar --directory dangling", `tar --directory`},
	}
	for _, tc := range noPanicShell {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got == "" {
				t.Fatalf("rtGuardCwd(%q) returned empty verdict", tc.cmd)
			}
		})
	}
	noPanicArgv := []struct {
		name string
		argv []string
	}{
		{"P-R11-MF1-c argv tar -f dangling", []string{"tar", "-f"}},
		{"P-R11-MF1-d argv tar --file dangling", []string{"tar", "--file"}},
		{"P-R11-MF1-e argv tar -cf then -C dangling", []string{"tar", "-cf", "/dev/null", "-C"}},
	}
	for _, tc := range noPanicArgv {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", argv: tc.argv}, "")
			if got == "" {
				t.Fatalf("rtGuardCwd(%v) returned empty verdict", tc.argv)
			}
		})
	}

	blockCases := []struct {
		name, cmd, want string
	}{
		// R11-MF-2: quoted/escaped/enum-expanded/env -S declaration heads.
		{"P-R11-MF2-a dq export demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; "export" FOO=$X; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R11-MF2-b backslash export demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; \export FOO=$X; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R11-MF2-b2 sq export demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; 'export' FOO=$X; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R11-MF2-c enum export demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; for E in export; do $E FOO=$X; done; tar -cf /dev/null /dev/null`, "env dynamic export"},
		{"P-R11-MF2-d env -S rewrite demotion", `X='1 TAR_OPTIONS=--use-compress-program=pig'; env -S 'command export a=1 b=2' FOO=$X`, "env dynamic export"},
		// R11-MF-3: printf -v glued/repeated, read/getopts dynamic slots.
		{"P-R11-MF3-a printf -vTAR_OPTIONS glued", `bash -c 'set -a; printf -vTAR_OPTIONS "%s" "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env TAR_OPTIONS"},
		{"P-R11-MF3-b printf repeated -v", `bash -c 'set -a; printf -v x -v TAR_OPTIONS "%s" "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env TAR_OPTIONS"},
		{"P-R11-MF3-c read -p dynamic split", `bash -c 'set -a; X="x TAR_OPTIONS"; read -p $X <<< "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env dynamic read"},
		{"P-R11-MF3-d getopts dynamic optstring", `set -a; X='1 GIT_CONFIG_COUNT'; getopts $X -1`, "env dynamic getopts"},
		{"P-R11-MF3-e getopts glob optstring", `set -a; getopts p* -1`, "env dynamic getopts"},
		// R11 closure: quoted dynamic OPTION-ZONE words pick their option
		// letters (or terminator status) at runtime even though the expansion
		// itself never field-splits.
		{"P-R11-MF3-f printf dq dynamic format", `bash -c 'set -a; OPT="-vTAR_OPTIONS"; printf "$OPT" "%s" "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env dynamic printf"},
		// NOTE: the value must NOT be a static-literal single assignment —
		// the collector in-lines safe literals, so `OPT="vTAR_OPTIONS"` would
		// statically resolve `-$OPT` to `-vTAR_OPTIONS` and hit the (correct)
		// static `env TAR_OPTIONS` verdict instead of exercising the dynamic
		// branch. Concatenating an undefined expansion keeps the word dynamic.
		{"P-R11-MF3-g printf dq dash-prefixed", `bash -c 'set -a; OPT="vTAR_OPTIONS$NOPE"; printf "-$OPT" "%s" "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env dynamic printf"},
		{"P-R11-MF3-h read dq dash-prefixed cluster", `bash -c 'set -a; OPT="aTAR_OPTIONS"; read "-$OPT" <<< "--use-compress-program=pig"; tar -cf /dev/null /dev/null'`, "env dynamic read"},
		{"P-R11-MF3-i getopts dq terminator shift", `set -a; H="--"; getopts "$H" opt TAR_OPTIONS`, "env TAR_OPTIONS"},
		{"P-R11-MF3-j getopts dq terminator dyn name", `set -a; H="--"; V='GIT_CONFIG_COUNT'; getopts "$H" opt "$V"`, "env dynamic getopts"},
		// R11 closure: quoted/escaped declaration heads inside the BASH-dialect
		// parse (bash -c) lose field-splitting exemption exactly like the
		// POSIX-level probes a/b above.
		{"P-R11-MF2-e bash -c dq export demotion", `bash -c 'X="1 TAR_OPTIONS=--use-compress-program=pig"; "export" FOO=$X; tar -cf /dev/null /dev/null'`, "env dynamic export"},
		{"P-R11-MF2-f bash -c backslash export demotion", `bash -c 'X="1 TAR_OPTIONS=--use-compress-program=pig"; \export FOO=$X; tar -cf /dev/null /dev/null'`, "env dynamic export"},
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

	// 放行守卫正例(R11 零假阳纪律):无包装声明内建、带引号包装导出、
	// printf 格式串/-- 终止、带引号 read 提示符、静态/带引号 getopts
	// 与正常 tar 带值选项全部保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R11-pos tar -cf quoted OUT", `tar -cf "$OUT" /dev/null`},
		{"R11-pos tar -C xf normal", `tar -C /tmp -xf "$ARCHIVE"`},
		{"R11-pos bare export unquoted", `export FOO=$X`},
		{"R11-pos prefix-assign export", `A=1 export FOO=$X`},
		{"R11-pos bash -c export quoted", `bash -c 'export FOO="$X"'`},
		{"R11-pos command export quoted", `command export FOO="$X"`},
		{"R11-pos printf format quoted", `printf '%s\n' "$X"`},
		{"R11-pos printf dq static format", `printf "val=$X\n"`},
		{"R11-pos printf -- terminator", `printf -- -v TAR_OPTIONS`},
		{"R11-pos printf -v benign", `printf -v myvar '%s' "$X"`},
		{"R11-pos printf -vmyvar glued benign", `printf -vmyvar '%s' "$X"`},
		{"R11-pos read -p quoted prompt", `bash -c 'read -p "$PROMPT" x <<< y'`},
		{"R11-pos read -r plain", `read -r line`},
		{"R11-pos getopts static optstring", `getopts ":ab:" opt`},
		{"R11-pos getopts quoted optstring", `getopts "$OPTS" opt`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}
}

// TestGuard_V622_ReviewerR4Probes covers the Reviewer R4 / Oracle R12 audit
// matrix: printf write-target closure (glued/clustered -v, static %n slots
// with Bash format reuse, dynamic format strings and array-subscripted write
// targets — R4-MF-1/MF-3/MF-4), printf first-word glob expansion into the
// option zone (R4-MF-2), GNU tar --occurrence as an OPTIONAL-argument option
// (R4-MF-5), read's -i value letter and glued dynamic value tails (R4-SF-1),
// and the getopts dynamic first operand standby slot narrowed to a real "--"
// expansion shape (R4-SF-2). Zero new production symbols are referenced here:
// every probe goes through rtGuardCwd so an independent verifier can copy
// this file onto the pre-fix tree 9139e0e and reproduce FAIL directly.
func TestGuard_V622_ReviewerR4Probes(t *testing.T) {
	blockCases := []struct {
		name, cmd, want string
	}{
		// R4-MF-1: preScanVarMutations never counted glued/clustered -v or
		// %n writes, so a second write into `cmd` stayed static-bindable.
		{"P-R4-MF1-a printf glued -v double write", `bash -c 'cmd=/bin/true; printf -vcmd %s pig; "$cmd"'`, ""},
		{"P-R4-MF1-b printf clustered -v double write", `bash -c 'cmd=/bin/true; printf -v cmd %s pig; "$cmd"'`, ""},
		// R4-MF-3: static format-string %n write targets were never scanned.
		{"P-R4-MF3-a printf %n TAR_OPTIONS", `bash -c 'printf "%n" TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R4-MF3-b printf %n aligned arg", `bash -c 'printf "%s %n" x TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R4-MF3-c printf -- %n", `bash -c 'printf -- "%n" TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R4-MF3-d printf width-star %n alignment", `bash -c 'printf "%*s %n" 1 x TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R4-MF3-e printf dynamic fmt args", `bash -c 'printf x"$FMT" "%s" x'`, "env dynamic printf"},
		{"P-R4-MF3-f printf %n unquoted arg splitting", `bash -c 'printf "%s %n" $X TAR_OPTIONS'`, "env dynamic printf"},
		{"P-R4-MF3-g printf %n dynamic target", `bash -c 'printf "%n" "$X"'`, "env dynamic printf"},
		{"P-R4-MF3-h printf %n array subscript hook", `bash -c 'printf "%n" '\''TAR_OPTIONS[0]'\'''`, "env TAR_OPTIONS"},
		{"P-R4-MF3-i printf %n dynamic subscript", `bash -c 'printf "%n" "x[$(echo 0)]"'`, "env dynamic printf"},
		// R13-SF-4: inside bash double quotes '$' starts a parameter expansion,
		// so the positional designator must be backslash-escaped to reach
		// printf as literal '%2$s%n' (unescaped '$s' expanded empty and the
		// probe tested the wrong string).
		{"P-R4-MF3-j printf %n positional slot", `bash -c 'printf "%2\$s%n" x TAR_OPTIONS'`, "env dynamic printf"},
		// R14 closure: bash printf honours length modifiers on '%n', the
		// '%*2$n' star-positional width is unvettable, and a glob-expanded
		// filename can legitimately spell '%n' (`lit%n`) so a glob-only
		// format word WITH arguments is no longer trusted.
		{"P-R14-1 printf glob-only fmt with args", `printf lit* TAR_OPTIONS`, "env dynamic printf"},
		// R13-MF-1: even with NO trailing argument an unquoted glob format
		// word can expand to MULTIPLE words at runtime — match[0] becomes the
		// real format string and match[1] the first argument, so `lit%n`
		// content would write into whatever match[1] names. Only a split-safe
		// (quoted) zero-argument spelling stays safe.
		{"P-R13-MF1 printf glob fmt no args", `printf lit*`, "env dynamic printf"},
		{"P-R14-2 printf %ln length modifier", `bash -c 'printf "%ln" TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R14-3 printf %hhn length modifier", `bash -c 'printf "%hhn" TAR_OPTIONS'`, "env TAR_OPTIONS"},
		{"P-R14-4 printf star-positional %n", `bash -c 'printf "%*2\$n" 1 TAR_OPTIONS'`, "env dynamic printf"},
		// R14 closure: read's separate value operand word-splits at runtime
		// when unquoted (`read -p $X` with X="p cmd"), shifting the positional
		// layout. The argv layer already refused this shape at 9139e0e
		// (readClusterStep vets the consumed operand), so the discriminating
		// regression pin is the direct preScanVarMutations unit row below the
		// positive table.
		{"P-R14-5-shell read -p unquoted value blocks", `bash -c 'cmd=/bin/true; X="p cmd"; read -p $X <<< pig; "$cmd"'`, ""},
		// R4-MF-4: write-target subscripts must validate their base name and
		// reject arithmetic/dynamic subscripts fail-closed. NOTE: an UNQUOTED
		// arr[0] is itself a glob character class (litHasUnquotedGlobOrTilde),
		// so the static-subscript spellings are single-quoted here.
		{"P-R4-MF4-a printf -v array hook", `bash -c 'printf -v '\''TAR_OPTIONS[0]'\'' "%s" x'`, "env TAR_OPTIONS"},
		{"P-R4-MF4-b printf -v glued array hook", `bash -c 'printf "-vTAR_OPTIONS[0]" "%s" x'`, "env TAR_OPTIONS"},
		{"P-R4-MF4-c printf -v arithmetic subscript", `bash -c 'printf -v x[1+1] "%s" y'`, "env dynamic printf"},
		{"P-R4-MF4-d printf -v dangling subscript", `bash -c 'printf -v x[0 "%s" y'`, "env dynamic printf"},
		// R4-MF-2: a glob word first in the format position may expand into
		// -vNAME at runtime, desynchronizing the option zone.
		{"P-R4-MF2-a printf glob star format", `printf * '%s' x`, "env dynamic printf"},
		{"P-R4-MF2-b printf glob qmark format", `printf ? '%s' x`, "env dynamic printf"},
		// R4-MF-5: GNU tar --occurrence[=N] is optional-argument — the bare
		// spelling consumes NO operand, so the following exec hook must be
		// scanned instead of swallowed as the "occurrence value".
		{"P-R4-MF5-a tar occurrence swallow glued hook", `tar --occurrence --use-compress-program=pig -cf /dev/null /dev/null`, ""},
		{"P-R4-MF5-b tar occurrence swallow split hook", `tar --occurrence --use-compress-program pig -cf /dev/null /dev/null`, ""},
		// R4-SF-1: a dynamic placeholder inside read's option-letter zone is
		// unvettable, including a glued -p tail that word-splits at runtime.
		{"P-R4-SF1-a read glued -p unquoted dyn", `bash -c 'read -p$P x <<< y'`, "env dynamic read"},
		// R13-MF-4: a glued dynamic prompt tail that can expand EMPTY at
		// runtime (`read -p"$PROMPT"` with PROMPT='') turns into `read -p`
		// which consumes the NEXT argv word as the prompt — the positional
		// write-target layout diverges from the static scan.
		{"P-R13-MF4 read glued empty-able dq prompt", `bash -c 'read -p"$PROMPT" answer <<< y'`, "env dynamic read"},
		// R4-SF-2: a dynamic getopts first operand may expand to exactly "--",
		// shifting NAME out of its static slot.
		{"P-R4-SF2-a getopts dyn terminator hook", `set -a; H="--"; getopts "$H" opt TAR_OPTIONS`, "env TAR_OPTIONS"},
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

	// 放行守卫正例(R4 零假阳纪律):普通/复用格式串参数、带引号动态格式串
	// 无参、静态下标合法数组写、安全字面前缀 glob、tar 正常带参、read -p/-i
	// 带引号提示与初始值、getopts 带冒号/字母的动态 OPTSTRING 全部保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R4-pos printf static fmt benign", `bash -c 'printf "%s %s" "$A" "$B"'`},
		{"R4-pos printf fmt reuse benign", `bash -c 'printf "%s" "$A" "$B"'`},
		{"R4-pos printf dq fmt no args", `bash -c 'printf x"$FMT"'`},
		{"R4-pos printf unquoted arg no %n", `printf '%s\n' $UNQUOTED`},
		{"R4-pos printf %n benign var", `bash -c 'printf "%n" myvar'`},
		{"R4-pos printf %n benign array", `bash -c 'printf "%n" '\''arr[0]'\'''`},
		{"R4-pos printf -v benign array", `bash -c 'printf -v '\''arr[0]'\'' "%s" x'`},
		// R14 closure: the glob-only literal-prefix positive keeps ONLY the
		// zero-argument spelling — with no arguments nothing can be written
		// regardless of what the expansion spells; ANY trailing argument
		// makes the dynamically shaped format unvettable (blocked above).
		{"R4-pos printf glob literal prefix quoted no args", `printf 'lit*'`},
		{"R14-pos printf strftime width conv", `bash -c 'printf "%10(%Y)T\n" -1'`},
		{"R4-pos printf quoted star format", `printf '*' '%s' x`},
		{"R4-pos tar occurrence value benign", `tar --occurrence 2 -tf /dev/null`},
		{"R4-pos tar occurrence glued benign", `tar --occurrence=2 -tf /dev/null`},
		{"R4-pos read -p glued dq prompt", `bash -c 'read -p"Prompt: $PROMPT" line <<< y'`},
		{"R4-pos read -ei separate value", `bash -c 'read -ei "$DEFAULT" answer <<< y'`},
		{"R4-pos getopts colon dyn optstring", `getopts ":$OPTS" opt TAR_OPTIONS`},
		{"R4-pos getopts colon dyn optstring arg", `getopts ":$OPTS" opt "$arg"`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// P-R14-5 direct unit pin: rtGuardCwd cannot discriminate this fix
	// because screenReadEnvWrite's readClusterStep already refuses a
	// word-splitting separate value operand at the argv layer — the
	// preScanVarMutations taint is DEPTH defense for the shell-string
	// static-bind analysis inside bash -c. The regression is pinned at
	// the function itself: an unquoted expansion in read's consumed value
	// slot (`read -p $X` — X="p cmd" word-splits at runtime, shifting the
	// positional layout so the REAL write targets diverge from the static
	// operand scan) must taint every static bind, while the split-safe
	// quoted spelling keeps the scan clean.
	t.Run("P-R14-5 preScanVarMutations read unquoted value slot", func(t *testing.T) {
		p := syntax.NewParser()
		f, err := p.Parse(strings.NewReader(`X="p cmd"; read -p $X <<< pig; echo ok`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		_, tainted := preScanVarMutations(f)
		if !tainted {
			t.Fatal("preScanVarMutations(read -p $X): allTainted = false, want true (unquoted value slot word-splits at runtime)")
		}
	})
	t.Run("P-R14-5-pos preScanVarMutations read quoted value slot", func(t *testing.T) {
		p := syntax.NewParser()
		f, err := p.Parse(strings.NewReader(`read -p "$PROMPT" x <<< pig; echo ok`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		_, tainted := preScanVarMutations(f)
		if tainted {
			t.Fatal("preScanVarMutations(read -p \"$PROMPT\" x): allTainted = true, want false (quoted value stays one argv word)")
		}
	})
}

// TestGuard_V622_OracleR13Probes pins the Oracle R13 audit closure:
// printf zero-argument dynamic/glob format write slots (R13-MF-1), the
// '%q' conversion letter mis-parsed as a length modifier (R13-MF-2),
// read's static-cluster end-letter misjudgment `-eii` (R13-MF-3), a glued
// dynamic read prompt tail that can expand empty and swallow the next
// argv word (R13-MF-4), the printf/read/getopts AST pre-scan alignment
// (R13-SF-1), dynWordCanSpellDashDash exactness and the '$$' PID
// recognition (R13-SF-2) and external-path /usr/bin/printf exemption
// (R13-SF-3). Pure-function pins reference only existing production
// symbols plus parse helpers, so the file can be copied onto the pre-fix
// tree 056cb3e5 to reproduce FAIL directly.
func TestGuard_V622_OracleR13Probes(t *testing.T) {
	// ---- Pure-function pins (R13-SF-4) ----
	t.Run("R13-MF1 printfFmtWriteSlots zero-arg glob fmt is dyn", func(t *testing.T) {
		if _, dyn := printfFmtWriteSlots("sample*"+cmdSubPlaceholderGlob, nil); !dyn {
			t.Fatal("printfFmtWriteSlots(glob-only fmt, no args): dyn = false, want true (glob expands to many words — match[0] becomes the format, match[1] a '%n' write target)")
		}
	})
	t.Run("R13-MF1-pos printfFmtWriteSlots zero-arg split-safe fmt stays safe", func(t *testing.T) {
		if _, dyn := printfFmtWriteSlots("sample"+cmdSubPlaceholderQuoted, nil); dyn {
			t.Fatal("printfFmtWriteSlots(quoted dyn fmt, no args): dyn = true, want false (no arguments — nothing can be written)")
		}
	})
	t.Run("R13-MF2 printfFmtSlots %q%n is conv+write pair", func(t *testing.T) {
		slots, pos := printfFmtSlots("%q%n")
		if pos || len(slots) != 2 || slots[0] || !slots[1] {
			t.Fatalf("printfFmtSlots(%%q%%n) = %v positional=%v, want [false true] positional=false ('q' is a conversion letter, not a length modifier)", slots, pos)
		}
	})
	t.Run("R13-MF2-pos printfFmtSlots %qn is single non-write slot", func(t *testing.T) {
		slots, pos := printfFmtSlots("%qn")
		if pos || len(slots) != 1 || slots[0] {
			t.Fatalf("printfFmtSlots(%%qn) = %v positional=%v, want [false] positional=false (the trailing 'n' is literal text after the %%q conversion)", slots, pos)
		}
	})
	t.Run("R13-MF3 preScanVarMutations read -eii counts sample", func(t *testing.T) {
		p := syntax.NewParser()
		f, err := p.Parse(strings.NewReader(`read -eii sample <<< ok`), "")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		writes, tainted := preScanVarMutations(f)
		if tainted {
			t.Fatal("preScanVarMutations(read -eii sample): allTainted = true, want false")
		}
		if writes["sample"] != 1 {
			t.Fatalf("preScanVarMutations(read -eii sample): writes[sample] = %d, want 1 (the glued -i VALUE ends the cluster — trailing 'i' text never consumes the next word)", writes["sample"])
		}
	})
	t.Run("R13-MF4 readDynClusterHit empty-able glued prompt tail blocks", func(t *testing.T) {
		if hit := readDynClusterHit("-p" + cmdSubPlaceholderQuoted); hit == "" {
			t.Fatal("readDynClusterHit(-p\"$PROMPT\") = \"\", want non-empty (an empty PROMPT collapses the glued tail so -p swallows the next argv word)")
		}
	})
	t.Run("R13-MF4-pos readDynClusterHit static-prefix prompt tail allows", func(t *testing.T) {
		if hit := readDynClusterHit("-pPrompt: " + cmdSubPlaceholderQuoted); hit != "" {
			t.Fatalf("readDynClusterHit(-p\"Prompt: $PROMPT\") = %q, want empty (static non-empty prefix keeps the glued tail non-empty at runtime)", hit)
		}
	})
	t.Run("R13-SF2 dynWordCanSpellDashDash precision", func(t *testing.T) {
		if dynWordCanSpellDashDash("---" + cmdSubPlaceholderQuoted) {
			t.Fatal("dynWordCanSpellDashDash(---$X) = true, want false (three static dashes can never shrink to exactly '--')")
		}
		if dynWordCanSpellDashDash(cmdSubPlaceholderAbsDq) {
			t.Fatal("dynWordCanSpellDashDash(abs-dq) = true, want false (absolute-path expansions always start with '/')")
		}
		if dynWordCanSpellDashDash("0" + cmdSubPlaceholderQuoted) {
			t.Fatal("dynWordCanSpellDashDash(PID encoding) = true, want false ('$$' is decimal digits, never '--')")
		}
		if !dynWordCanSpellDashDash("--" + cmdSubPlaceholderQuoted) {
			t.Fatal("dynWordCanSpellDashDash(--$X) = false, want true (an empty expansion spells exactly '--')")
		}
	})

	// ---- End-to-end guard verdicts ----
	blockCases := []struct {
		name, cmd, want string
	}{
		// R13-MF-2 argv layer: '%q' was skipped as a length modifier, so
		// printf "%q%n" hid its write conversion and printf "%qn" invented
		// a false '%n' write.
		{"P-R13-MF2-a printf %q%n write", `bash -c 'printf "%q%n" x TAR_OPTIONS'`, "env TAR_OPTIONS"},
		// R13-MF-3: `read -eii sample` — the trailing 'i' is the glued -i
		// initial value text, so `sample` remains the write target; the
		// pre-scan must count it so a double write into `sample` blocks the
		// static bind.
		{"P-R13-MF3 read -eii sample rewrite", `bash -c 'sample=/bin/true; read -eii sample <<< pig; "$sample"'`, ""},
		// R13-MF-4 shell layer: an empty-expanding glued prompt swallows the
		// positional layout inside a bash -c script.
		{"P-R13-MF4-shell read empty-able prompt in script", `bash -c 'cmd=/bin/true; read -p"$PROMPT" answer <<< ok; "$cmd"'`, ""},
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

	// 放行守卫正例(R13 零假阳纪律):'%q' 引号转换、分离写法 read 提示符、
	// 静态非空前缀粘连提示符、printf/read/getopts 带安全动态参数的组合脚
	// 本、'$$' PID OPTSTRING 与显式路径 /usr/bin/printf 全部保持 ALLOW。
	allowCases := []struct {
		name, cmd string
	}{
		{"R13-pos printf %qn conversion benign", `bash -c 'printf "%qn" "$X"'`},
		{"R13-pos read -p separate dq prompt", `bash -c 'read -p "$PROMPT" answer <<< y'`},
		{"R13-pos read -p glued static-prefix prompt", `bash -c 'read -p"Prompt: $PROMPT" line <<< y'`},
		// R13-SF-1: combination scripts with dynamic but safe printf/read/
		// getopts arguments must not all-taint the pre-scan — `cmd` keeps
		// its static bind and the script stays ALLOW.
		{"R13-SF1 printf dyn args in script", `bash -c 'cmd=/bin/true; printf "%s" "$DATA"; "$cmd"'`},
		{"R13-SF1 read static-prefix prompt in script", `bash -c 'cmd=/bin/true; read -p"Prompt: $PROMPT" answer <<< ok; "$cmd"'`},
		{"R13-SF1 getopts colon dyn optstring in script", `bash -c 'cmd=/bin/true; getopts ":$OPTS" opt; "$cmd"'`},
		// R13-SF-2: '$$' expands to decimal PID digits — it can never spell
		// the "--" terminator, so the standby NAME slot is not vetted.
		{"R13-SF2 getopts PID optstring", `bash -c 'getopts "$$" opt "$arg"'`},
		// R13-SF-3: an explicit-path printf invokes /usr/bin/printf — a
		// child process can never write shell variables, so neither the
		// dynamic format text nor '%n'-looking content is vetted as a
		// shell write.
		{"R13-SF3 usr bin printf dyn format", `/usr/bin/printf "label=$LABEL %s" value`},
		{"R13-SF3 usr bin printf static format", `/usr/bin/printf 'label=%s' value`},
		// R14-Oracle-S4: the R13 combination-script counterpart of the
		// external-path exemption — inside bash -c the AST pre-scan must not
		// all-taint on the external printf either, so `cmd` keeps its static
		// bind (this is the 10th allow row the R13 closure counted).
		{"R13-SF3-script usr bin printf dyn format in script", `bash -c 'cmd=/bin/true; /usr/bin/printf "label=$LABEL %s" value; "$cmd"'`},
	}
	for _, tc := range allowCases {
		t.Run(tc.name, func(t *testing.T) {
			got := rtGuardCwd(t, rtCase{id: tc.name, role: "worker", cmd: tc.cmd}, "")
			if got != "ALLOW" {
				t.Fatalf("rtGuardCwd(%q) = %q, want ALLOW", tc.cmd, got)
			}
		})
	}

	// R14-Oracle-S4: the two R13 discriminating assertions that were never
	// landed. `%10(%Y)T%n` proves the strftime conversion consumes exactly
	// one non-write slot BEFORE the real '%n' write (slot shape, not just a
	// rejection verdict), and the read cluster row pins the unknown-letter
	// fail-closed path with a STATIC non-empty glued tail so the R13-MF-4
	// empty-tail rule cannot produce a coincidental pass.
	t.Run("R13-SF4 printfFmtSlots strftime width slot vector", func(t *testing.T) {
		slots, pos := printfFmtSlots("%10(%Y)T%n")
		if pos || len(slots) != 2 || slots[0] || !slots[1] {
			t.Fatalf("printfFmtSlots(%%10(%%Y)T%%n) = %v positional=%v, want [false true] positional=false", slots, pos)
		}
	})
	t.Run("R13-SF4 readDynClusterHit unknown letter before value letter", func(t *testing.T) {
		if hit := readDynClusterHit("-Zptext" + cmdSubPlaceholderQuoted); hit == "" {
			t.Fatal("readDynClusterHit(-Zptext+$P) = \"\", want non-empty (unknown option letter 'Z' fails closed even though a value letter follows)")
		}
	})
}

// parseBashSingleCmdWord parses src with the bash dialect and returns the
// args-th word of its single call expression (test helper for the Oracle
// R14 parser probes).
func parseBashSingleCmdWord(t *testing.T, src string, arg int) *syntax.Word {
	t.Helper()
	p := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := p.Parse(strings.NewReader(src), "")
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	if len(f.Stmts) != 1 {
		t.Fatalf("parse %q: %d stmts, want 1", src, len(f.Stmts))
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		t.Fatalf("parse %q: cmd is %T, want *syntax.CallExpr", src, f.Stmts[0].Cmd)
	}
	if arg >= len(call.Args) {
		t.Fatalf("parse %q: %d args, want index %d", src, len(call.Args), arg)
	}
	return call.Args[arg]
}

// blankSubCollector returns a subCollector with no static binds, no script
// writes and no env taints — the fixture state the Oracle R14 parser
// probes pin (e.g. unbound "$OLDPWD").
func blankSubCollector() *subCollector {
	return &subCollector{
		staticVars:   map[string]string{},
		enumVars:     map[string]string{},
		taintedVars:  map[string]bool{},
		enumCmdWords: map[string][]string{},
		ssaBlocked:   map[string]bool{},
	}
}
