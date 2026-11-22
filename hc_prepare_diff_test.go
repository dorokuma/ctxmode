package main

// Stage-C differential contracts between the two wrapper peelers:
//
//   - hc_prepare.go peelWrappersWithIndex — the slot-index mapper the
//     hc-gate rewrite uses to locate the inner command head word. It MUST
//     stop peeling (headIdx < 0) on every non-provenance wrapper form:
//     `env -S`/`--split-string` (the split payload's inner words have no
//     1:1 argv index), `env -i`/`--ignore-environment`, and the unsafe
//     peel bases exec/builtin/busybox/strace/ltrace.
//   - role_guards.go peelWrappers — the guard-side peeler. It MUST keep
//     unwrapping on those same forms so the inner command is still
//     screened.
//
// The relation is a designed one-way conservative asymmetry, NOT equality.
// Three contracts pin it:
//
//   Contract A (同剥必同位): whenever peelWrappersWithIndex reaches an
//   inner head with idx > 0 over a whitelisted wrapper chain, the guard
//   side's peeled headArgv must equal argv[idx:] word-for-word.
//
//   Contract B (禁止反向越权剥离): no corpus row may show the prepare
//   peeler peeled INTO the inner command (idx > 0, head != argv) while
//   the guard peeler is still parked on an outer wrapper word.
//
//   Contract C (显式单向保守差集 + 端到端闭环): on the white-box
//   enumerated non-provenance forms the prepare peeler surrenders
//   (idx < 0) while the guard peeler still reaches the expected inner
//   head, and the end-to-end rtCmdRule/prepArgvRule verdicts block the
//   hostile payloads and pass the benign single-word ones.

import (
	"reflect"
	"strings"
	"testing"
)

// peelRow is one argv corpus row: the full argv and, for contract-A rows,
// the index of the inner command head word.
type peelRow struct {
	name string
	argv []string
	// guardHead is the inner head word the guard-side peeler must reach.
	guardHead string
}

func peelGuardHead(t *testing.T, argv []string) []string {
	t.Helper()
	head, _, _, _ := peelWrappers(append([]string{}, argv...))
	return head
}

func TestDiffPeel_ContractAB_SafeWrapperChains(t *testing.T) {
	// Contract A + B corpus: every row peels to an inner command on BOTH
	// sides; the prepare peeler's headIdx must locate exactly the same
	// words the guard peeler returns.
	rows := []peelRow{
		{"env -u FOO", []string{"env", "-u", "FOO", "ls", "-la"}, "ls"},
		{"env --unset=FOO", []string{"env", "--unset=FOO", "ls", "-la"}, "ls"},
		{"env -C /tmp", []string{"env", "-C", "/tmp", "pwd"}, "pwd"},
		{"env --chdir=/tmp", []string{"env", "--chdir=/tmp", "pwd"}, "pwd"},
		{"env --", []string{"env", "--", "ls"}, "ls"},
		{"env VAR=x", []string{"env", "VAR=x", "ls", "-la"}, "ls"},
		{"timeout 5", []string{"timeout", "5", "sleep", "1"}, "sleep"},
		{"timeout -k 2 5", []string{"timeout", "-k", "2", "5", "sleep", "1"}, "sleep"},
		{"timeout long opts", []string{"timeout", "--kill-after=2", "--signal=TERM", "--foreground", "5", "sleep", "1"}, "sleep"},
		{"timeout -- 5", []string{"timeout", "--", "5", "sleep", "1"}, "sleep"},
		{"nice -n 10", []string{"nice", "-n", "10", "make"}, "make"},
		{"stdbuf -oL -e0", []string{"stdbuf", "-oL", "-e0", "cat"}, "cat"},
		{"nohup", []string{"nohup", "make", "test"}, "make"},
		{"command -p --", []string{"command", "-p", "--", "ls", "-la"}, "ls"},
		{"nohup timeout env chain", []string{"nohup", "timeout", "-k", "1", "5", "env", "A=1", "B=2", "sh", "-c", "echo ok"}, "sh"},
	}
	for _, r := range rows {
		head, idx, _, _, exhausted := peelWrappersWithIndex(append([]string{}, r.argv...), callerIdentity{})
		if exhausted {
			t.Fatalf("%s: prepare peeler exhausted on %v", r.name, r.argv)
		}
		gHead := peelGuardHead(t, r.argv)
		if len(gHead) == 0 || gHead[0] != r.guardHead {
			t.Fatalf("%s: guard head=%v want head[0]=%q", r.name, gHead, r.guardHead)
		}
		// Contract B: whenever the guard side peeled INTO the inner
		// command (guardHead != argv[0]), the prepare side must not have
		// peeled further than the guard side — and on this corpus every
		// row is a whitelisted chain, so the prepare side MUST reach the
		// same head (idx > 0) rather than surrendering.
		if idx < 0 {
			t.Fatalf("%s: contract B violated — prepare surrendered (idx<0) but guard peeled to %v", r.name, gHead)
		}
		// Contract A: same peeled inner command, word-for-word.
		if !reflect.DeepEqual(head, r.argv[idx:]) {
			t.Fatalf("%s: contract A violated — head=%v but argv[idx:]=%v (idx=%d)", r.name, head, r.argv[idx:], idx)
		}
		if !reflect.DeepEqual(head, gHead) {
			t.Fatalf("%s: contract A violated — prepare head=%v != guard head=%v", r.name, head, gHead)
		}
	}
}

func TestDiffPeel_ContractB_NoReverseOverPeel(t *testing.T) {
	// Contract B on the FULL corpus (safe + non-provenance rows): it is
	// never legal for peelWrappersWithIndex to locate an inner command
	// (idx > 0) while peelWrappers still sits on an outer wrapper word.
	corpus := [][]string{
		{"env", "-u", "FOO", "ls"},
		{"env", "-S", "timeout 5 hc send t42 ok"},
		{"env", "--split-string=nice -n 1 ls"},
		{"env", "-i", "ls"},
		{"env", "--ignore-environment", "ls"},
		{"exec", "ls"},
		{"builtin", "echo", "ok"},
		{"busybox", "ls"},
		{"strace", "-o", "/tmp/t", "ls"},
		{"ltrace", "ls"},
		{"timeout", "5", "env", "A=1", "sh", "-c", "echo ok"},
		{"command", "-v", "hc"},
		{"command", "-v", "env"},
		{"command", "-p", "--", "ls"},
	}
	for _, argv := range corpus {
		head, idx, _, _, _ := peelWrappersWithIndex(append([]string{}, argv...), callerIdentity{})
		gHead := peelGuardHead(t, argv)
		if idx > 0 && len(gHead) > 0 && isPeeledWrapperBase(baseName(gHead[0])) && baseName(gHead[0]) != baseName(argv[0]) {
			t.Fatalf("contract B violated on %v: prepare peeled to idx=%d head=%v while guard head still on wrapper %v", argv, idx, head, gHead)
		}
		// Stronger symmetric statement: prepare must never peel DEEPER
		// than guard. If guard stopped on a wrapper word (head[0] is a
		// wrapper base) while argv[0] was not that same wrapper, prepare
		// having idx>0 with head != argv is over-peel.
		if idx > 0 && len(gHead) > 0 && !reflect.DeepEqual(gHead, head) {
			// prepare and guard disagree on WHERE the inner head is.
			// This is only legal when guard peeled deeper (env -S) —
			// never when prepare peeled deeper.
			if len(gHead) >= len(head) && !isPeeledWrapperBase(baseName(gHead[0])) {
				// guard reached at least as deep a non-wrapper head — but
				// the heads differ in content; report for review.
				t.Fatalf("contract B ambiguous on %v: prepare head=%v (idx=%d), guard head=%v", argv, head, idx, gHead)
			}
		}
	}
}

func baseName(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// contractCRow pins one non-provenance wrapper form. wantIdxSurrender
// means peelWrappersWithIndex must stop peeling (idx < 0); when false the
// peeler may still reach an argv head but MUST record the non-provenance
// env op (envClear/'c') that collectLeafHcEdit / screenCtxmodeGateHead
// use to refuse the rewrite. wantHead is the exact guard-side peeled
// head; headOnly checks only head[0].
type contractCRow struct {
	name             string
	argv             []string
	wantHead         []string // exact guard-side peeled head words; nil = only check head[0]
	headOnly         string   // expected guard head[0] when wantHead is nil
	wantIdxSurrender bool     // true: idx must be < 0; false: idx allowed but envAs must carry a clear op
}

func TestDiffPeel_ContractC_NonProvenanceForms(t *testing.T) {
	rows := []contractCRow{
		// env -S / --split-string: the payload's inner words have no argv
		// index — prepare surrenders, guard unwraps the split payload.
		{"env -S separate", []string{"env", "-S", "timeout 5 hc send t42 ok"}, nil, "hc", true},
		{"env -S glued", []string{"env", "-Stimeout 5 ls"}, nil, "ls", true},
		{"env --split-string=x", []string{"env", "--split-string=timeout 5 ls"}, nil, "ls", true},
		{"env --split-string separate", []string{"env", "--split-string", "timeout 5 ls"}, nil, "ls", true},
		{"env -S wrapped hc", []string{"env", "-S", "timeout 5 hc send t42 x"}, nil, "hc", true},
		// env -i / --ignore-environment: the clear op voids provenance —
		// peelWrappersWithIndex may still locate the argv head (the slot
		// index itself is intact) but MUST record the 'c' env op that
		// collectLeafHcEdit / screenCtxmodeGateHead refuse on.
		{"env -i", []string{"env", "-i", "ls", "-la"}, []string{"ls", "-la"}, "", false},
		{"env --ignore-environment", []string{"env", "--ignore-environment", "ls"}, []string{"ls"}, "", false},
		// Unsafe peel bases: the guard keeps unwrapping them; prepare
		// refuses to grant cross-wrapper rewrite provenance.
		{"exec", []string{"exec", "ls", "-la"}, []string{"ls", "-la"}, "", true},
		{"exec -a name", []string{"exec", "-a", "foo", "ls"}, []string{"ls"}, "", true},
		{"builtin", []string{"builtin", "echo", "ok"}, []string{"echo", "ok"}, "", true},
		{"busybox", []string{"busybox", "ls"}, []string{"ls"}, "", true},
		{"strace", []string{"strace", "-o", "/tmp/t.log", "ls"}, []string{"ls"}, "", true},
		{"ltrace", []string{"ltrace", "ls"}, []string{"ls"}, "", true},
		// Gemini note: `env -C`/`--chdir` switches the working directory
		// — it stays INSIDE the whitelist grammar on both sides (contract
		// A rows above), NOT part of this difference set.
	}
	for _, r := range rows {
		head, idx, _, envAs, _ := peelWrappersWithIndex(append([]string{}, r.argv...), callerIdentity{})
		if r.wantIdxSurrender {
			if idx >= 0 {
				t.Fatalf("%s: contract C violated — prepare peeler peeled to idx=%d head=%v on non-provenance form %v", r.name, idx, head, r.argv)
			}
		} else {
			// Slot-index rows (env -i / --ignore-environment / bare dash):
			// the peel may locate the head, but the recorded env ops must
			// carry the 'c' clear that the rewrite layers refuse on.
			hasClear := false
			for _, op := range envAs.ops {
				if op.kind == 'c' {
					hasClear = true
				}
			}
			if !hasClear {
				t.Fatalf("%s: contract C violated — env clear op not recorded on %v (idx=%d)", r.name, r.argv, idx)
			}
		}
		gHead := peelGuardHead(t, r.argv)
		if len(gHead) == 0 {
			t.Fatalf("%s: guard peeler returned empty head on %v", r.name, r.argv)
		}
		if r.wantHead != nil {
			if !reflect.DeepEqual(gHead, r.wantHead) {
				t.Fatalf("%s: guard head=%v want %v", r.name, gHead, r.wantHead)
			}
		} else if gHead[0] != r.headOnly {
			t.Fatalf("%s: guard head[0]=%q want %q (head=%v)", r.name, gHead[0], r.headOnly, gHead)
		}
	}
}

// TestDiffPeel_QueryForm_CommandV covers the asymmetric query-form row:
// `command -v hc` is a RESOLUTION QUERY on both sides — neither peeler may
// treat `hc` as an executed wrapper target. Both leave `command` as head.
func TestDiffPeel_QueryForm_CommandV(t *testing.T) {
	for _, argv := range [][]string{
		{"command", "-v", "hc"},
		{"command", "-V", "hc"},
		{"command", "-pv", "hc"},
	} {
		head, idx, _, _, _ := peelWrappersWithIndex(append([]string{}, argv...), callerIdentity{})
		gHead := peelGuardHead(t, argv)
		// Both sides report `command` itself as the head (a query, not a
		// wrapped execution): prepare keeps idx == 0 and head == argv.
		if idx != 0 || !reflect.DeepEqual(head, argv) {
			t.Fatalf("%v: prepare query head=%v idx=%d, want verbatim argv", argv, head, idx)
		}
		if !reflect.DeepEqual(gHead, argv) {
			t.Fatalf("%v: guard query head=%v, want verbatim argv", argv, gHead)
		}
	}
	// Contrast: `command -p -- ls` IS an executed wrapper — both peel.
	head, idx, _, _, _ := peelWrappersWithIndex([]string{"command", "-p", "--", "ls"}, callerIdentity{})
	if idx <= 0 || head[0] != "ls" {
		t.Fatalf("command -p -- ls: prepare head=%v idx=%d", head, idx)
	}
}

// TestDiffPeel_EndToEnd_PayloadVerdicts is the contract-C end-to-end
// half: hostile payloads on the non-provenance forms and dynamic heads
// block; benign single-word dynamic option values pass.
func TestDiffPeel_EndToEnd_PayloadVerdicts(t *testing.T) {
	// Hostile: @-split workdir values, unauthorized --hc-gate, dynamic hc
	// send behind env -S / wrappers — all must block for a worker.
	// `${arr[@]}`/`$@` array spellings are bash-only syntax: POSIX-parseable
	// variants (env -S payload is opaque text to the outer parser) block on
	// the top-level /bin/sh path, while the bare ctxmode/argv forms route
	// through `bash -c` where the array parse succeeds and the option-zone
	// screen still fails closed.
	blocked := []string{
		`ctxmode --workdir "$@" search`,
		`env -S 'ctxmode --workdir "$@" search'`,
		`env -S 'ctxmode --workdir "${arr[@]}" search'`,
		`env -S 'ctxmode --workdir "${x:-$@}" search'`,
		`bash -c 'ctxmode --workdir "${arr[@]}" search'`,
		`bash -c 'ctxmode --workdir "${x:-$@}" search'`,
		`ctxmode --hc-gate send t42 hi`,
		`ctxmode --hc-gate=x send t42 hi`,
		`env -S 'hc send t42 "$(cat r)"'`,
		`nohup timeout -k 1 5 env A=1 B=2 sh -c 'hc send t42 "$(cat r)"'`,
		`exec env -S 'hc send t42 "$(cat r)"'`,
		`busybox env -S 'hc send t42 "$(cat r)"'`,
		`builtin env -S 'hc send t42 "$(cat r)"'`,
	}
	for _, cmd := range blocked {
		if rule, detail := rtCmdRule("worker", "", cmd, ""); rule == "" {
			t.Errorf("worker %q: got ALLOW, want block (detail=%s)", cmd, detail)
		}
	}

	// Benign: "${#arr[@]}" is a ${#…} length — always ONE integer word —
	// so it is a split-safe single-word option value and must pass. The
	// bash-only-syntax screen only applies to the POSIX /bin/sh dialect,
	// so every "${#arr[@]}" row goes through an explicit `bash -c` (the
	// length expansion is a bash feature); "${x:-@}"-class rows stay
	// POSIX-portable on the plain `ctxmode` head.
	allowed := []string{
		`bash -c 'ctxmode --workdir "${#arr[@]}" search'`,
		`bash -c 'env -S '"'"'ctxmode --workdir "${#arr[@]}" search'"'"''`,
		`bash -c 'env -S '"'"'ctxmode --workdir "$PWD" search'"'"''`,
		`timeout 5 env A=1 sh -c 'echo ok'`,
		`nohup timeout -k 1 5 env A=1 B=2 sh -c 'echo ok'`,
	}
	for _, cmd := range allowed {
		if rule, detail := rtCmdRule("worker", "", cmd, ""); rule != "" {
			t.Errorf("worker %q: got BLOCK %s: %s, want ALLOW", cmd, rule, detail)
		}
	}

	// ${#arr[@]} through the argv prepare path: the single-word dynamic
	// value is not an @-split, so the option-zone screen must accept it.
	p := prepArgvRule(t, "worker", "", []string{"bash", "-c", `env -S 'ctxmode --workdir "${#arr[@]}" search'`}, "")
	if p.rule != "" {
		t.Fatalf(`bash -c env -S 'ctxmode --workdir "${#arr[@]}" search' argv prepare blocked: %s (%s)`, p.rule, p.detail)
	}
	// A real @-split through the same path must still fail closed.
	p = prepArgvRule(t, "worker", "", []string{"bash", "-c", `env -S 'ctxmode --workdir "${arr[@]}" search'`}, "")
	if p.rule == "" {
		t.Fatal(`bash -c env -S 'ctxmode --workdir "${arr[@]}" search' argv prepare must block`)
	}
	// Nested-quote / backtick payload inside env -S also fails closed.
	p = prepArgvRule(t, "worker", "", []string{"bash", "-c", "env -S 'hc send t42 \"`cat r`\"'"}, "")
	if p.rule == "" {
		t.Fatal("env -S backtick hc send payload must block")
	}
}
