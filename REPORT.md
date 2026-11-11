# REPORT: feat/redteam-1111 packaging (rt1111-finish)

Worktree: `/tmp/ctxmode-rt1111`  
Branch: `feat/redteam-1111`  
Baseline HEAD before packaging: `76c042c`  
Scope: packaging only — no program-behavior changes beyond Pig’s already-present working tree.

## 1. Per-item changes (A-1..A-11, W-5)

### A-1 — SSH remote vehicle + code spawn tightening
- **Functions:** `isPureRemoteStdinVehicle`, `screenSSHHead`, `guardCtxRunCode`.
- **Behavior:** Remote stdin vehicle exemption is pure shell only (`lang == ""`); `node -` / `python3 -` no longer skip remote screening. For read-only callers, piped stdin into `ssh` and `StrictHostKeyChecking=no|accept-new` without `UserKnownHostsFile=/dev/null|none` return the readonly-write hit. JS/TS raw `child_process` identifier counts as spawn; Python masked `open` identifier without an `open(` call site fails closed (rebind), while string-literal `open(...)` stays free.

### A-2 — journalctl bare `--lines`
- **Functions:** `cmdAllow.longEqOnly`, journalctl allowlist init, `scanAllowedOpts`.
- **Behavior:** `lines` moves from `longValue` to `longEqOnly`. Only `--lines=N` (non-empty, non-dash value) is accepted; bare `--lines` (and smuggling `--rotate` / `--vacuum-size`) is rejected. `-n` / `-nN` unchanged.

### A-3 — git tag/branch `--sort`/`--format` are display-only
- **Functions:** `gitTagAllow` (`readonly_allowlist.go`); `gitBranchQueryFlags`, `gitTagReadFlags`, `screenGitWrite` (`role_guards.go`).
- **Behavior:** `--sort` / `--format` no longer mark listing/query. Operand-less `git tag --sort=…` stays allowed; `git tag --sort refname pwned-tag` blocks as create. Values are still consumed so they are not mistaken for names.

### A-4 — hc send control chars + dynamic operands
- **Functions:** `hasHcControlChars`, `screenHcSubagent`.
- **Behavior:** Text operand rejects C0 controls other than `\n`/`\t`, plus DEL (`0x7f`). Both addr and text reject `isDynamicArg` (unquoted `$x` and double-quoted `"$x"` / `"$(…)"`). Static multiline text stays allowed. `hcSendAddrOK` unchanged.

### A-5 — stdin device paths as program sources
- **Functions:** `isStdinDevicePath`; local updates in `stdinProgramHeadWithEnv`, `awkProgramFrags`, `screenSedSubagent`.
- **Behavior:** `/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`, `/proc/thread-self/fd/0` are treated like `-` for shell/interpreter/awk `-f`/sed `-f` (including glued/`--file=` forms).

### A-6 — multi-segment stdin screening
- **Function:** `guardCtxRunStdinForCommand`.
- **Behavior:** Segments with their own stdin (pipe / `<` / `<<` / `<<<`) are skipped; a clean stdin-program segment no longer ends the scan early, so `python3 - </dev/null; sh` + stdin still screens `sh`.

### A-7 — wrapper option/value slots fail closed on dynamics
- **Functions:** `peelWrappers` / `skipExecArgs` / `skipTimeoutArgs` / `skipStdbufArgs` / `skipIoniceArgs` / `skipTasksetArgs` / `skipChrtArgs` / `skipWatchArgs` / `skipStraceArgs` / `skipToolGlobalFlags`; `stdinProgramHeadWithEnv` honours `exhausted`.
- **Behavior:** Dynamic words in wrapper option or required value slots set `exhausted` (fail closed), including `timeout "$T" cmd` without `--`.

### A-8 — symlink alias re-peel, same-family allow, GNU prefix set
- **Functions:** `isPeeledWrapperBase`, `sameStructuralFamily`, `gnuCanonicalSet`, `peelResolvedSegDepth`, `canonicalResolvedBase`; `screenReadonlyAllowlist` keys on typed basename.
- **Behavior:** Resolved wrapper names re-peel; same-family aliases (`sh→dash`, `python3→python3.13`, `awk→mawk`, `hc→herdr-core|sbx`) keep the typed base; cross-family structural aliases return `conflicting structural alias`. `g`/`gnu` strip limited to real Homebrew GNU set so `gps`/`ghc` no longer alias to `ps`/`hc`; typed `genv`/`gfind` normalize.

### A-9 — npx/bunx/pnpx screening
- **Function:** `screenNodeRunnerSubagent` (replaces the thin peelResolvedSegDepth npx branch).
- **Behavior:** `-c`/`--call`, `-p`/`--package` package specs (version-stripped against blocked agents), and a blocked first positional fail closed; `npx tsc`, `npx -y -p typescript tsc`, `bunx vitest` stay free.

### A-10 — CTXMODE_* env hook keys
- **Function:** `isEnvHookVar`.
- **Behavior:** Adds `CTXMODE_AUDIT_LOG`, `CTXMODE_ENV_PASSTHROUGH`, `CTXMODE_DB`, `CTXMODE_CONFIG` so sub-agents cannot rewrite identity/audit path via env / export / `sbx --env`.

### A-11 — retire herdr/herdsman sub-agent whitelist
- **Functions:** `blockedAgentExecutableList` (+`herdr`,`herdsman`); remove dedicated herdr/herdsman screens and dead helpers from `isStructuralGuardHead` / `screenNestedDispatch`.
- **Behavior:** Every spelling blocks on the bare name (`herdr` / `herdsman`). `hc` / `herdr-core` report channel unchanged.

### W-5 — relative PATH symlink escape
- **Function:** `screenPathHeadTrust` only (`pathIsUnsafeForSubagent` untouched).
- **Behavior:** Relative-PATH hits always `EvalSymlinks`; cwd is EvalSymlinks’d before under-cwd checks. Targets under real cwd stay free; targets escaping cwd must land in system/linuxbrew/user-toolchain dirs and pass `isTrustedExecutableOnDisk`, else `untrusted path binary`.

## 2. Tests: new and edited

### New
- `role_guards_rt1111_test.go` — `TestRT_A1_SSHTightening`, `TestRT_A2_JournalctlLinesEqOnly`, `TestRT_A3_GitTagSort`, `TestRT_A4_HcSendCtrlAndDynamic`, `TestRT_A5_StdinDevicePath`, `TestRT_A6_StdinPerSegment`, `TestRT_A7_WrapperDynamicSlots`, `TestRT_A8_AliasFamilyAndGnuPrefix`, `TestRT_A9_NodeRunner`, `TestRT_A10_EnvHookCtxmodeKeys`, `TestRT_A11_HerdrHerdsmanRetired` (W-5 covered via `zz_r3path_test.go`).
- `zz_rtaudit_test.go` — `TestRTAudit`, `TestRTAuditPath` (table-driven audit reproductions).
- `zz_r3path_test.go` — `TestR3_RelativePATH_SymlinkToTmp` (W-5 cases), `TestR3_hcSendAddrAndCtrl`.

### Edited (why)
- `role_guards_test.go` — A-11: former herdr/herdsman allow rows and detail strings now expect bare-name block (`herdr` / `herdsman`) in `TestGuard_SubagentNestedArgv`, `TestGuard_SubagentNestedShell`, `TestGuard_CtxRunCodeAliasAndFallback`, `TestGuard_SSHPeel`, `TestGuard_HardGuardsRound3`.
- `role_guards_r12_test.go` — A-11: `TestGuard_R12_CodeStaticSpawnSSHPeel` detail `herdr tab create` → `herdr`.

No assertion “improvements” beyond matching the retired-head / agreed detail contract.

## 3. A-4 `hc send $var` usage search

### Source
Pig session (read-only): `/tmp/herdr-role-sessions/default/role-worker-b9ff36d1/2026-11-11T05-41-06-762Z_01a1c91f-cc49-72f1-870b-ce46dcbdfbf3.jsonl`  
Pig ran scoped `rg` over repo tests/docs, `/root/workspace` scripts/docs, and `/root/.pig/agent` agents/skills (lines ~35–43 of that transcript). This packaging pass re-checked the same scopes; nothing under `/tmp/herdr-role-sessions` was modified.

### Scope (quoted from pig’s searches + re-check)
- Repo `*.go` / `.agents/` notes: test fixtures and docs for static `hc send t42 done` / `hc send t2 hi`; intentional attack rows with `$x` / `"$x"` / `$(…)` only in rt1111 / audit tests.
- `/root/.pig/agent`: instructional templates such as `hc send <父终端ID> "<完整报告>"` and docs mentioning `hc send $HC_TERMINAL_ID` as the **address** placeholder in prompt-writing guidance (`skills/herdr/SKILL.md`, `references/ordinary-agents.md`, `dispatch-shared.md`, `SYSTEM.md`). Report **text** is described as a quoted literal body.
- `/root/workspace` docs/scripts: same pattern — documentation of the report channel; no live main-agent flow sending dynamic **text** operands.

### Conclusion
Dynamic **text** in `hc send` was **not** found in real main-agent flows. `$HC_TERMINAL_ID` appears in agent docs as an address template for writing prompts; sub-agents receive a concrete terminal id, and the main agent (no `CTXMODE_ROLE` / `CTXMODE_READONLY`) is outside `screenHcSubagent`. Therefore the implemented rule — **both operands reject dynamic words for all screened roles**, plus control-char rejection on text — stands.

## 4. Must-allow / intentional new blocks

**Evidence authority:** gate evidence is the asserted test tables —
`TestRTAudit` and `TestRTAuditPath` (`zz_rtaudit_test.go`),
`TestR3_RelativePATH_SymlinkToTmp` and `TestR3_hcSendAddrAndCtrl`
(`zz_r3path_test.go`). Each `t.Run` case carries `wantAllow` and fails on
mismatch; the "Evidence" column names the asserting test function / sub-case.
`rt1111-logs/` is an untracked local dev log directory — **not part of the
commit and not gate evidence**; its print lines were only the pre-assertion
scratch record.

### Must-allow (representative; asserted ALLOW on fixed tree)
| Case | Evidence |
|------|----------|
| M-hc-send-ok / M-hc-send-t42 | `TestRTAudit/M-hc-send-ok`, `…/M-hc-send-t42` |
| M-ls / M-rg | `TestRTAudit/M-ls`, `…/M-rg` |
| M-git-tag-list / M-git-tag-l-sort / M-git-tag-contains | `TestRTAudit/M-git-tag-list`, `…/M-git-tag-l-sort`, `…/M-git-tag-contains` |
| M-journalctl-n / M-journalctl-lines-eq | `TestRTAudit/M-journalctl-n`, `…/M-journalctl-lines-eq` |
| M-worker-go-test / M-worker-timeout / M-worker-nice / M-worker-env | `TestRTAudit/M-worker-*` |
| M-worker-npx-tsc / M-worker-npx-p | `TestRTAudit/M-worker-npx-tsc`, `…/M-worker-npx-p` |
| M-verifier-pipe-sh-file | `TestRTAudit/M-verifier-pipe-sh-file` |
| M-worker-ssh-heredoc-sh / M-worker-python-stdin / M-worker-js | `TestRTAudit/M-worker-*` |
| M-rel-venv-normal / M-rel-nodemod-normal / M-mise-pnpm-prepend | `TestRTAuditPath/M-*` |
| X-A4-hc-send-multiline-report / X-git-*-sort / X-worker-python-stdin-then-ls | `TestRTAudit/X-*` |
| R3PATH M-rel-venv-pytest-file / M-rel-nodemod-tsc / M-rel-venv-python3-sys-{nontmp,intmp} | `TestR3_RelativePATH_SymlinkToTmp/M-*` |

### Intentional new blocks (asserted BLOCK; not regressions)
| Case | Evidence | Note |
|------|----------|------|
| M-journalctl-lines-sep (`journalctl --lines 50`) | `TestRTAudit/M-journalctl-lines-sep` | A-2: bare `--lines` is no longer allowed; use `--lines=N` or `-n` |
| X-worker-timeout-var-ok (`timeout "$T" …`) | `TestRTAudit/X-worker-timeout-var-ok` | A-7 agreed fail-closed |
| X-A11-herdr-pane-list / X-A11-herdsman-agent-list | `TestRTAudit/X-A11-*` | A-11 retirement |
| M-scout-mise-pnpm-ls (scout `PATH=… ls`) | `TestRTAuditPath/M-scout-mise-pnpm-ls` | scout forbids `VAR=val` env prefixes (pre-existing rule); also listed as a B-group known block |
| A9a-rel-venv-0777 (0777 .venv/bin real file) | `TestRTAuditPath/A9a-rel-venv-0777` | **asserts ALLOW** — a relative `.venv/bin` segment is exempt from on-disk trust checks entirely; only symlinks escaping the workspace are screened (W-5). Dir/file write bits in a whitelisted rel segment are not judged. Listed here so the expectation is explicit. |

### B-group known blocks (pre-existing allowlist semantics, asserted BLOCK)
`git reflog HEAD` (any ref operand hits `git reflog HEAD` — reflog delete/exist/expire reach it),
`git remote show [-n] origin` (network fetch; `role_guards_test.go` already expects "deleted"),
scout `VAR=val` env-prefix assigns (`env assign forbidden`),
`git branch --sort refname newbr` / `git tag --format x pwned-tag` (operand = create).
These were already BLOCK on baseline too; they are pinned so the audit table
cannot silently regress either way.

## 5. Check results

**Caveat:** `rt1111-logs/` below is **untracked and not part of this commit** —
rc values copied here are historical local-log values, not reproducible from
the commit. Gate evidence is the asserted tests in §4 plus the rc lines each
reviewer/verifier re-runs independently.

### Earlier logs (pre-packaging tree; untracked, unverifiable from commit)
| Check | Log | Result |
|-------|-----|--------|
| gofmt | (pig session; reconfirmed empty before commit) | rc=0, no files listed |
| go vet | cited ok in FINISH / pig | rc=0 |
| go build | pig | BUILD_OK / rc=0 |
| go test (mid) | `rt1111-logs/full-test-1.log` | rc≠0: A-11 expectation updates still pending in that snapshot + ENOSPC on `TestAlFix7_FuzzArgvDiff` |
| go test -race (short timeout) | `rt1111-logs/race.log` | FAIL at ~600s timeout (not a logic fail) |
| go test -race (30m) | `rt1111-logs/race2.log` | **ok** `github.com/dorokuma/ctxmode` 696.242s, rc=0 (historical log value; untracked — not reproducible from commit, verifier re-ran independently) |
| staticcheck (wrong toolchain) | `rt1111-logs/staticcheck.log` | compile error go1.24 vs go1.26 |
| staticcheck (U1000 mid) | `rt1111-logs/staticcheck2.log` | U1000 on unused helpers (cleaned) |
| staticcheck final | `rt1111-logs/staticcheck3.log` | empty, rc=0 with `GOTOOLCHAIN=go1.26.0` |

### Final-HEAD logs (this packaging pass; untracked, unverifiable from commit)
Recorded under `rt1111-logs/final-*.log` after commits (see §5b below once filled). Commands:

```bash
gofmt -l . > rt1111-logs/final-gofmt.log 2>&1; rc=$?
go vet ./... > rt1111-logs/final-vet.log 2>&1; rc=$?
go build -o /dev/null . > rt1111-logs/final-build.log 2>&1; rc=$?
GOTMPDIR=/root/go-tmp-rt1111 TMPDIR=/root/go-tmp-rt1111 \
  go test -count=1 -timeout 30m ./... > rt1111-logs/final-test.log 2>&1; rc=$?
```

Race and staticcheck were already green on this tree (`race2.log`, `staticcheck3.log`); re-run only if cheap after commit.

### §5b Final-HEAD exit codes (after impl commit `89032c1`; untracked log values)

| Check | Log | rc | Notes |
|-------|-----|----|-------|
| gofmt -l . | `rt1111-logs/final-gofmt.log` | **0** | empty (no files listed) |
| go vet ./... | `rt1111-logs/final-vet.log` | **0** | |
| go build -o /dev/null . | `rt1111-logs/final-build.log` | **0** | |
| go test -count=1 -timeout 30m ./... | `rt1111-logs/final-test.log` | **1** | sole failure: `TestAlFix7_FuzzArgvDiff` ENOSPC on `/tmp` tmpfs symlink (known env; see §6) |
| go test -skip TestAlFix7_FuzzArgvDiff | `rt1111-logs/final-test-skip-alfix7.log` | **0** | confirms all other tests green |
| go test -run TestAlFix7_FuzzArgvDiff with `TMPDIR=/root/go-tmp-rt1111` | `rt1111-logs/final-alfix7-disk.tmp.log` | **0** | same test passes off tmpfs |

Race (`race2.log`) and staticcheck (`staticcheck3.log`, `GOTOOLCHAIN=go1.26.0`) were already green on this tree and were not re-run. All `rt1111-logs/` entries are untracked local logs — values here are historical, not gate evidence.

Snapshot check: tracked implementation `.go` files after commit match `/tmp/rt1111-snapshot/` (pre-packaging copy).

## 6. Known env failure and commit grouping

### Known env failure
`TestAlFix7_FuzzArgvDiff` failed on the final full suite with:
`symlink … /tmp/TestAlFix7_FuzzArgvDiff…/env: no space left on device`
(`/tmp` tmpfs still showed free bytes/inodes; fuzz creates a large symlink forest). Same class of failure on baseline (`rt1111-logs/baseline-test.log`). **Test not changed.**

Workarounds verified without code edits:
- Full suite minus that test: rc=0 (`final-test-skip-alfix7.log`).
- That test alone with `TMPDIR=/root/go-tmp-rt1111`: rc=0 (`final-alfix7-disk.tmp.log`).
- Note: pointing the whole suite’s `TMPDIR` at `/root/go-tmp-rt1111` moves W-5 scratch targets off `/tmp`, so `W5-abs-literal-same-pytest-nontmp` (C10 `isTmpOrScratchPath`) can falsely ALLOW; do not use that env for the full suite.

`/root/go-tmp-rt1111` removed after checks.

### Commit grouping
`role_guards.go` (~995-line interleaved diff) and the shared allowlist/test files cannot be split 1:1 with `git add -p` without risking a behavior change. Grouping used:

1. **Implementation + tests** — one commit covering A-1..A-11 and W-5 (`role_guards.go`, `readonly_allowlist.go`, `role_guards_rt1111_test.go`, `role_guards_test.go`, `role_guards_r12_test.go`, `zz_rtaudit_test.go`, `zz_r3path_test.go`).
2. **Docs** — `CHANGELOG.md` + `REPORT.md`.

`rt1111-logs/` and the local `ctxmode` binary remain untracked / uncommitted.
