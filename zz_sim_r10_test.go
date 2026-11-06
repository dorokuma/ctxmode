package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// TestRound10_HistReplayWrite replays readonly 6141 + worker 6159 histories
// against HEAD guards. Opt-in: ROUND10_SIM=1.
func TestRound10_HistReplayWrite(t *testing.T) {
	if os.Getenv("ROUND10_SIM") == "" {
		t.Skip("set ROUND10_SIM=1 to write replay JSON")
	}

	type histItem struct {
		Role     string   `json:"role"`
		Readonly bool     `json:"readonly"`
		Type     string   `json:"type"`
		Cmd      string   `json:"cmd"`
		Argv     []string `json:"argv"`
	}
	type histFile struct {
		N     int        `json:"n"`
		Items []histItem `json:"items"`
	}
	type kv struct {
		K string `json:"K"`
		V int    `json:"V"`
	}
	type detail struct {
		Role string `json:"role"`
		Cmd  string `json:"cmd"`
		Hit  string `json:"hit"`
	}
	sortKV := func(m map[string]int) []kv {
		out := make([]kv, 0, len(m))
		for k, v := range m {
			out = append(out, kv{k, v})
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].V != out[j].V {
				return out[i].V > out[j].V
			}
			return out[i].K < out[j].K
		})
		return out
	}
	load := func(path string) histFile {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var h histFile
		if err := json.Unmarshal(raw, &h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	writeJSON := func(path string, v any) {
		t.Helper()
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	isG1 := func(hit string) bool {
		h := strings.ToLower(hit)
		return strings.Contains(h, "ambiguous line continuation") ||
			strings.Contains(h, "comment line continuation") ||
			strings.Contains(h, "line continuation after $") ||
			strings.Contains(h, "line continuation before redirect") ||
			strings.Contains(h, "token-splitting line continuation") ||
			strings.Contains(h, "g1")
	}

	// --- readonly ---
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")
	ro := load("/tmp/readonly-hist-cmds.json")
	roByHead, roByReason := map[string]int{}, map[string]int{}
	roBlocked, roOK := 0, 0
	roG1 := []detail{}
	for _, it := range ro.Items {
		var hit string
		fields := strings.Fields(it.Cmd)
		head := ""
		if len(fields) > 0 {
			head = fields[0]
		}
		if it.Type == "command" {
			hit = guardShellReadonly(it.Cmd)
		} else {
			hit = guardArgvReadonly(fields)
		}
		if strings.Contains(head, "/") {
			head = "path:" + head[strings.LastIndex(head, "/")+1:]
		}
		if hit != "" {
			roBlocked++
			roByHead[head]++
			reason := hit
			if i := strings.Index(reason, " Hint:"); i >= 0 {
				reason = reason[:i]
			}
			roByReason[reason]++
			if isG1(hit) {
				roG1 = append(roG1, detail{Role: "readonly", Cmd: it.Cmd, Hit: hit})
			}
		} else {
			roOK++
		}
	}
	roOut := map[string]any{
		"total":     len(ro.Items),
		"blocked":   roBlocked,
		"ok":        roOK,
		"rate":      float64(roBlocked) / float64(len(ro.Items)),
		"by_head":   sortKV(roByHead),
		"by_reason": sortKV(roByReason),
	}
	writeJSON("/tmp/readonly-allowlist-sim-sh10-head.json", roOut)
	writeJSON("/tmp/ctxsh10-g1-fp-readonly.json", roG1)
	t.Logf("RO total=%d blocked=%d ok=%d rate=%.6f g1=%d", len(ro.Items), roBlocked, roOK, float64(roBlocked)/float64(len(ro.Items)), len(roG1))

	// --- worker/verifier ---
	wh := load("/tmp/worker-hist-cmds.json")
	wByHead, wByReason := map[string]int{}, map[string]int{}
	wBlocked, wOK := 0, 0
	var wDetails []detail
	wG1 := []detail{}
	for _, it := range wh.Items {
		role := it.Role
		if role == "" {
			role = "worker"
		}
		t.Setenv(auditEnvRole, role)
		t.Setenv(auditEnvReadonly, "")
		hit := guardShellSubagent(it.Cmd)
		fields := strings.Fields(it.Cmd)
		head := ""
		if len(fields) > 0 {
			head = fields[0]
		}
		if strings.Contains(head, "/") {
			head = "path:" + head[strings.LastIndex(head, "/")+1:]
		}
		wDetails = append(wDetails, detail{Role: role, Cmd: it.Cmd, Hit: hit})
		if hit != "" {
			wBlocked++
			wByHead[head]++
			reason := hit
			if i := strings.Index(reason, " Hint:"); i >= 0 {
				reason = reason[:i]
			}
			wByReason[reason]++
			if isG1(hit) {
				wG1 = append(wG1, detail{Role: role, Cmd: it.Cmd, Hit: hit})
			}
		} else {
			wOK++
		}
	}
	wOut := map[string]any{
		"total":     len(wh.Items),
		"blocked":   wBlocked,
		"ok":        wOK,
		"rate":      float64(wBlocked) / float64(len(wh.Items)),
		"by_head":   sortKV(wByHead),
		"by_reason": sortKV(wByReason),
	}
	writeJSON("/tmp/worker-allowlist-sim-sh10-head.json", wOut)
	writeJSON("/tmp/worker-allowlist-sim-sh10-head-details.json", wDetails)
	writeJSON("/tmp/ctxsh10-g1-fp-worker.json", wG1)
	t.Logf("WORKER total=%d blocked=%d ok=%d rate=%.6f g1=%d", len(wh.Items), wBlocked, wOK, float64(wBlocked)/float64(len(wh.Items)), len(wG1))
}
