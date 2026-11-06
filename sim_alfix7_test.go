package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestAlFix7_HistReplayWrite(t *testing.T) {
	if os.Getenv("ALFIX7_SIM") == "" {
		t.Skip("set ALFIX7_SIM=1 to write replay JSON")
	}
	t.Setenv(auditEnvRole, "scout")
	t.Setenv(auditEnvReadonly, "")

	raw, err := os.ReadFile("/tmp/readonly-hist-cmds.json")
	if err != nil {
		t.Fatal(err)
	}
	var hist struct {
		N     int `json:"n"`
		Items []struct {
			Role     string   `json:"role"`
			Readonly bool     `json:"readonly"`
			Type     string   `json:"type"`
			Cmd      string   `json:"cmd"`
			Argv     []string `json:"argv"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &hist); err != nil {
		t.Fatal(err)
	}

	byHead := map[string]int{}
	byReason := map[string]int{}
	blocked, okN := 0, 0
	for _, it := range hist.Items {
		var hit string
		head := ""
		fields := strings.Fields(it.Cmd)
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
			blocked++
			byHead[head]++
			reason := hit
			if i := strings.Index(reason, " Hint:"); i >= 0 {
				reason = reason[:i]
			}
			byReason[reason]++
		} else {
			okN++
		}
	}

	type kv struct {
		K string `json:"K"`
		V int    `json:"V"`
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

	out := map[string]any{
		"total":     len(hist.Items),
		"blocked":   blocked,
		"ok":        okN,
		"rate":      float64(blocked) / float64(len(hist.Items)),
		"by_head":   sortKV(byHead),
		"by_reason": sortKV(byReason),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile("/tmp/readonly-allowlist-sim-alfix7.json", b, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("total=%d blocked=%d ok=%d rate=%.4f", len(hist.Items), blocked, okN, float64(blocked)/float64(len(hist.Items)))
}
