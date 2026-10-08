package main

// ctx_stats — context-consumption statistics, ported from the original
// context-mode MCP server's ctx_stats tool (mksglu/context-mode). Reports how
// many bytes each tool returned into the agent's context window this session,
// and how many bytes were kept out of it by auto-indexing oversized outputs
// into the ctx_kb store (the "context virtualization" savings).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolStat accumulates per-tool session counters.
type toolStat struct {
	calls    int64
	returned int64 // bytes handed back to the caller (context cost)
	keptOut  int64 // bytes auto-indexed into the KB store instead of returned
}

// statSnapshot is the JSON-friendly shape of one tool's counters.
type statSnapshot struct {
	Tool     string  `json:"tool"`
	Calls    int64   `json:"calls"`
	Returned int64   `json:"returned_bytes"`
	KeptOut  int64   `json:"kept_out_bytes"`
	EstTok   float64 `json:"est_tokens"`
}

const estBytesPerToken = 4

func (s *server) statRecordCall(tool string, returnedBytes int) {
	s.statMu.Lock()
	defer s.statMu.Unlock()
	if s.statTools == nil {
		s.statTools = make(map[string]*toolStat)
	}
	st := s.statTools[tool]
	if st == nil {
		st = &toolStat{}
		s.statTools[tool] = st
	}
	st.calls++
	st.returned += int64(returnedBytes)
}

// statRecordKeptOut counts bytes written to the KB store instead of the
// context window. It is installed on the Store itself (Store.onIndexedBytes,
// wired up in main), so every successful KB write is covered — the
// auto-indexing paths that funnel through storeIndexLocked (oversized ctx_run
// execute / execute_file / run_task output, ctx_fs rg auto-index, ctx_kb
// index), ctx_run action=batch's direct Store.Index calls, ctx_kb fetch's
// Store.ReplaceExactAndChunks writes, and the legacy JSON migration re-index.
// Attributed to the pseudo-tool "store" because the sink does not know which
// top-level tool triggered the write.
func (s *server) statRecordKeptOut(tool string, bytes int) {
	if bytes <= 0 {
		return
	}
	s.statMu.Lock()
	defer s.statMu.Unlock()
	if s.statTools == nil {
		s.statTools = make(map[string]*toolStat)
	}
	st := s.statTools[tool]
	if st == nil {
		st = &toolStat{}
		s.statTools[tool] = st
	}
	st.keptOut += int64(bytes)
}

// counted wraps a tool handler so every call's returned text length feeds
// ctx_stats. Kept-out bytes are recorded separately by the Store-layer sink
// (Store.onIndexedBytes → statRecordKeptOut), which covers every KB write
// path.
func counted[T any](s *server, name string, h func(context.Context, *mcp.CallToolRequest, T) (*mcp.CallToolResult, any, error)) func(context.Context, *mcp.CallToolRequest, T) (*mcp.CallToolResult, any, error) {
	return func(ctx context.Context, req *mcp.CallToolRequest, args T) (*mcp.CallToolResult, any, error) {
		res, anyRes, err := h(ctx, req, args)
		n := 0
		if res != nil {
			for _, c := range res.Content {
				if tc, ok := c.(*mcp.TextContent); ok {
					n += len(tc.Text)
				}
			}
		}
		s.statRecordCall(name, n)
		return res, anyRes, err
	}
}

// ---------- ctx_stats tool ----------

type ctxStatsArgs struct {
	JSON bool `json:"json,omitempty"`
}

type auditAgg struct {
	calls     int64
	output    int64
	indexed   int64
	truncated int64
}

func (s *server) toolCtxStats(_ context.Context, _ *mcp.CallToolRequest, args ctxStatsArgs) (*mcp.CallToolResult, any, error) {
	s.statMu.Lock()
	snaps := make([]statSnapshot, 0, len(s.statTools))
	var totalReturned, totalKeptOut int64
	for name, st := range s.statTools {
		snaps = append(snaps, statSnapshot{
			Tool:     name,
			Calls:    st.calls,
			Returned: st.returned,
			KeptOut:  st.keptOut,
			EstTok:   float64(st.returned) / estBytesPerToken,
		})
		totalReturned += st.returned
		totalKeptOut += st.keptOut
	}
	s.statMu.Unlock()
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].Tool < snaps[j].Tool })

	var audit auditAgg
	auditErr := aggregateAuditLog(auditLogPath(), s.sessionID, &audit)

	if args.JSON {
		out := map[string]any{
			"session_id":      s.sessionID,
			"est_bytes/token": estBytesPerToken,
			"tools":           snaps,
			"total_returned":  totalReturned,
			"total_kept_out":  totalKeptOut,
		}
		if auditErr == nil {
			out["audit_session"] = audit
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return nil, nil, err
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(data)}}}, nil, nil
	}

	var b strings.Builder
	uptime := "-"
	if !s.startedAt.IsZero() {
		uptime = formatUptime(time.Since(s.startedAt))
	}
	fmt.Fprintf(&b, "ctx_stats — session %s, uptime %s (est. %d bytes/token)\n\n", s.sessionID, uptime, int64(estBytesPerToken))
	fmt.Fprintf(&b, "%-10s %8s %12s %12s %12s %12s\n", "tool", "calls", "returned", "est.tokens", "kept-out", "est.tokens")
	for _, sn := range snaps {
		fmt.Fprintf(&b, "%-10s %8d %12s %12s %12s %12s\n",
			sn.Tool, sn.Calls, humanBytes(sn.Returned), humanTokens(int64(sn.EstTok)), humanBytes(sn.KeptOut), humanTokens(sn.KeptOut/estBytesPerToken))
	}
	if len(snaps) == 0 {
		b.WriteString("(no tool calls recorded yet this session)\n")
	}
	savings := 0.0
	if totalReturned+totalKeptOut > 0 {
		savings = float64(totalKeptOut) / float64(totalReturned+totalKeptOut) * 100
	}
	fmt.Fprintf(&b, "\nreturned to context: %s (~%s tokens); kept out by auto-indexing: %s (~%s tokens); savings %.0f%%\n",
		humanBytes(totalReturned), humanTokens(totalReturned/estBytesPerToken),
		humanBytes(totalKeptOut), humanTokens(totalKeptOut/estBytesPerToken), savings)
	if auditErr != nil {
		fmt.Fprintf(&b, "audit log: unavailable (%v)\n", auditErr)
	} else {
		fmt.Fprintf(&b, "audit log (ctx_run, this session): %d calls, %s raw output, %d auto-indexed, %d truncated\n",
			audit.calls, humanBytes(audit.output), audit.indexed, audit.truncated)
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, nil, nil
}

// aggregateAuditLog sums the ctx_run audit JSONL for one session. Records are
// bounded in size by the audit writer, but the file itself is append-only, so
// scanning uses a generous line cap and skips oversize lines instead of
// failing the whole aggregation.
func aggregateAuditLog(path, sessionID string, agg *auditAgg) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec auditRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		if sessionID != "" && rec.SessionID != sessionID {
			continue
		}
		agg.calls++
		agg.output += int64(rec.OutputLen)
		if rec.Indexed {
			agg.indexed++
		}
		if rec.Truncated {
			agg.truncated++
		}
	}
	return sc.Err()
}

func humanBytes(n int64) string {
	const k = 1024
	switch {
	case n >= k*k*k:
		return fmt.Sprintf("%.1fGB", float64(n)/(k*k*k))
	case n >= k*k:
		return fmt.Sprintf("%.1fMB", float64(n)/(k*k))
	case n >= k:
		return fmt.Sprintf("%.1fKB", float64(n)/k)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func humanTokens(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func formatUptime(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	sec := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, sec)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, sec)
	}
	return fmt.Sprintf("%ds", sec)
}
