package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- ctx_report ----------
//
// ctx_report is the zero-shell-ambiguity report delivery tool: it delegates
// the whole delivery contract (DISPATCH_REPORT_PATH fd-chain validation,
// .dispatch-report.lock serialization, atomic report.md install, the
// `hc send <parent>` receipt notify and the .sent dedup marker) to the single
// trusted `dispatch-report <parent>` helper — the same entry point the
// ctx_run argv spelling uses, so there is exactly one delivery truth source.
//
// A dispatched role may call it with any role identity (strict read-only
// included): the tool itself never opens the report path, never runs a shell
// and never audits the report body — per the instructions.go contract only
// ctx_run calls land in audit.jsonl, and ctx_report is no exception.

// ctxReportMaxBody mirrors the helper's stdin bound (1 MiB, valid UTF-8).
const ctxReportMaxBody = 1 << 20

// ctxReportTimeout bounds the helper subprocess. It must comfortably cover
// dispatch-report's internal worst case — lockWait (20s, bounded flock wait)
// plus hcSendTimeout (5s) plus write/marker overhead — so a delivery that is
// merely queued behind a peer's critical section is never SIGKILLed
// mid-send (a kill after the report landed on disk would drop the
// saved=true stdout receipt and leave an orphan hc send that re-notifies
// the parent without a .sent marker).
const ctxReportTimeout = 35 * time.Second

// ctxReportWaitDelay bounds the post-cancel drain: cmd.Cancel SIGKILLs the
// whole process group, and WaitDelay caps how long Wait() waits for the
// orphaned pipes (an hc send grandchild still holding the inherited
// stdout/stderr writers) before closing them and releasing Wait.
const ctxReportWaitDelay = 3 * time.Second

type ctxReportArgs struct {
	Content string `json:"content" jsonschema:"Complete UTF-8 report body (1 byte .. 1 MiB), written verbatim to the dispatch report file"`
}

// dispatchReportCandidates returns the fixed install locations searched for
// the dispatch-report helper, in order: every trusted home's .local/bin
// (production root → /root/.local/bin/dispatch-report; testTrustedHomeRoot
// gives tests the same slot under t.TempDir()) then /usr/local/bin. Never
// $PATH and never an env override — same contract the helper itself applies
// to hc. The variable (not a func value) is replaced by unit tests to point
// the search at a fake candidate set.
var dispatchReportCandidates = func() []string {
	out := make([]string, 0, 4)
	for _, h := range trustedHomeDirs() {
		out = append(out, filepath.Join(h, ".local/bin", "dispatch-report"))
	}
	return append(out, "/usr/local/bin/dispatch-report")
}

// findDispatchReport locates the first executable dispatch-report among the
// candidate install paths. A candidate must pass the full trust model —
// isTrustedExecutableOnDisk (trusted dir ancestry, no /tmp|/var/tmp escape,
// owner/write-bit rules for non-system locations) AND, because ADAPT2 exempts
// system dirs from the permission checks, an explicit post-EvalSymlinks
// os.Stat requiring a regular file with an execute bit (a FIFO, socket or
// 0644 file must be skipped, never exec'd or hung on) whose resolved basename
// is exactly "dispatch-report" (no alias names the helper itself).
func findDispatchReport(euid int) string {
	for _, cand := range dispatchReportCandidates() {
		if cand == "" || filepath.Clean(cand) != cand || !filepath.IsAbs(cand) {
			continue
		}
		// Full trust chain on the CANDIDATE first — the same model
		// admittedReadonlyCanonicalHead applies: trusted dir ancestry
		// (0022 write bits for non-system dirs, non-system-slot owner
		// check, the candidate's own symlink Lstat owner) and no
		// /tmp|/var/tmp escape. Skipping this and only judging the
		// resolved path would miss a poisoned ancestor dir or a
		// foreign-owned symlink at the install slot.
		if !isTrustedExecutableOnDisk(cand, euid) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(cand)
		if err != nil {
			continue
		}
		resolved = filepath.Clean(resolved)
		if filepath.Base(resolved) != "dispatch-report" {
			continue
		}
		// ADAPT2 exempts system dirs like /usr/local/bin from the owner
		// and write-bit checks, so the RESOLVED target gets an explicit
		// stat: it must be a regular file with an execute bit — a FIFO,
		// socket or 0644 file is skipped, never exec'd or hung on.
		st, err := os.Stat(resolved)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
			continue
		}
		// No bare isTmpOrScratchPath(resolved): under withTestTrustedHome
		// the fake home lives inside t.TempDir() (/tmp) and must still be
		// reachable, so the resolved path is re-run through the SAME
		// trust function (which honors testTrustedHomeRoot) — this keeps
		// the /tmp-escape ban while also re-checking the resolved dir
		// ancestry and owner bits.
		if !isTrustedExecutableOnDisk(resolved, euid) {
			continue
		}
		// Return RESOLVED, not cand: exec.CommandContext does no further
		// EvalSymlinks, so handing back the candidate path would leave a
		// symlink-swap TOCTOU between this check and the exec. The peer
		// dispatch-report's resolveTrustedHc follows the same contract.
		return resolved
	}
	return ""
}

// toolCtxReport delivers the report body via the trusted dispatch-report
// helper: `dispatch-report <DISPATCH_REPORT_PARENT>` with the body on stdin.
// The env binding is read live (t.Setenv-compatible): DISPATCH_REPORT_PATH
// marks the call as dispatch-issued, DISPATCH_REPORT_PARENT is the only
// parent id the helper will notify — ctx_report never lets the caller name
// the address, so a report can never be steered to a foreign terminal.
func (s *server) toolCtxReport(ctx context.Context, _ *mcp.CallToolRequest, args ctxReportArgs) (*mcp.CallToolResult, any, error) {
	reportPath := os.Getenv("DISPATCH_REPORT_PATH")
	parent := os.Getenv("DISPATCH_REPORT_PARENT")
	content := args.Content

	// Same precondition set the helper enforces, failed fast with precise
	// errors so a mis-dispatched call never reaches a subprocess.
	if reportPath == "" {
		return nil, nil, fmt.Errorf("ctx_report: DISPATCH_REPORT_PATH is unset (no dispatch-issued report file for this call)")
	}
	if !hcSendAddrOK(parent) {
		return nil, nil, fmt.Errorf("ctx_report: DISPATCH_REPORT_PARENT %q is unset or not a t[0-9a-z]+ terminal id", parent)
	}
	if self := os.Getenv("HC_TERMINAL_ID"); self != "" && self == parent {
		return nil, nil, fmt.Errorf("ctx_report: DISPATCH_REPORT_PARENT %q equals own HC_TERMINAL_ID (self-notification loop)", parent)
	}
	if len(content) == 0 {
		return nil, nil, fmt.Errorf("ctx_report: content is empty (1 byte .. %d bytes required)", ctxReportMaxBody)
	}
	if len(content) > ctxReportMaxBody {
		return nil, nil, fmt.Errorf("ctx_report: content exceeds %d bytes (got %d)", ctxReportMaxBody, len(content))
	}
	if !utf8.ValidString(content) {
		return nil, nil, fmt.Errorf("ctx_report: content is not valid UTF-8")
	}

	bin := findDispatchReport(os.Geteuid())
	if bin == "" {
		return nil, nil, fmt.Errorf("ctx_report: no trusted dispatch-report binary found under %v (regular executable required)", dispatchReportCandidates())
	}

	// The subprocess budget covers lockWait+hcSendTimeout inside the helper
	// with headroom (ctxReportTimeout). CommandContext alone would SIGKILL
	// only the direct child; Setpgid + a group-wide Cancel kill sweeps the
	// `hc send` grandchild too, and WaitDelay caps the orphaned-pipe drain.
	rctx, cancel := context.WithTimeout(ctx, ctxReportTimeout)
	defer cancel()
	cmd := exec.CommandContext(rctx, bin, parent)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = ctxReportWaitDelay
	// Same secret-strip model as every ctx_run child (childEnv): host API
	// keys/tokens never reach the helper while DISPATCH_REPORT_*, HC_*,
	// PATH, HOME and TMPDIR all pass through untouched.
	cmd.Env = flattenEnv(childEnv(nil))
	cmd.Stdin = strings.NewReader(content)

	// stdout AND stderr are both captured unconditionally: on a non-zero
	// exit (e.g. hc send failed) the helper still prints its structured
	// `status=failed ... saved=true` receipt on stdout, and that receipt is
	// the caller's proof the report actually landed on disk — dropping it
	// would misreport a saved report as lost.
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()

	var b strings.Builder
	out := strings.TrimRight(outBuf.String(), "\n")
	errOut := strings.TrimRight(errBuf.String(), "\n")
	if out != "" {
		b.WriteString(out)
	}
	if errOut != "" {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(errOut)
	}
	merged := b.String()

	if runErr != nil {
		if merged != "" {
			return nil, nil, fmt.Errorf("ctx_report: dispatch-report failed: %v\n%s", runErr, merged)
		}
		return nil, nil, fmt.Errorf("ctx_report: dispatch-report failed: %v", runErr)
	}
	if merged == "" {
		merged = "ctx_report: dispatch-report exited 0 without a receipt"
	}
	return textResult(merged, ""), nil, nil
}
