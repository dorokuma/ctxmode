package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestUnwrapArgString(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		want      string
		wantDepth int
	}{
		{"object unchanged", `{"action":"execute"}`, `{"action":"execute"}`, 0},
		{"one string layer", `"{\"action\":\"execute\"}"`, `{"action":"execute"}`, 1},
		{"two string layers", `"\"{\\\"a\\\":1}\""`, `{"a":1}`, 2},
		{"plain string untouched", `"abc"`, `"abc"`, 0},
		{"non-json string untouched", `"hello, world"`, `"hello, world"`, 0},
		{"number untouched", `123`, `123`, 0},
		{"null untouched", `null`, `null`, 0},
		{"array untouched", `[1,2]`, `[1,2]`, 0},
		{"string containing array unwraps", `"[1,2]"`, `[1,2]`, 1},
		{"bool string unwraps", `"true"`, `true`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, depth := unwrapArgString(json.RawMessage(tc.in))
			if string(got) != tc.want || depth != tc.wantDepth {
				t.Fatalf("unwrapArgString(%s) = %s, depth %d; want %s, depth %d", tc.in, got, depth, tc.want, tc.wantDepth)
			}
		})
	}
}

func TestUnwrapArgStringDepthCap(t *testing.T) {
	// Four nested string layers: only maxArgUnwrapDepth are removed, so the
	// result is still a JSON string and downstream reports a type error.
	in := `{"a":1}`
	for i := 0; i < maxArgUnwrapDepth+1; i++ {
		b, _ := json.Marshal(in)
		in = string(b)
	}
	got, depth := unwrapArgString(json.RawMessage(in))
	if depth != maxArgUnwrapDepth {
		t.Fatalf("depth = %d, want %d", depth, maxArgUnwrapDepth)
	}
	var s string
	if err := json.Unmarshal(got, &s); err != nil {
		t.Fatalf("expected result still a JSON string after cap, got %s", got)
	}
}

type captureParamsHandler struct {
	params mcp.Params
}

func (h *captureParamsHandler) handle(_ context.Context, _ string, req mcp.Request) (mcp.Result, error) {
	h.params = req.GetParams()
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
}

func TestArgUnwrapMiddleware(t *testing.T) {
	h := &captureParamsHandler{}
	mw := argUnwrapMiddleware(h.handle)

	req := &mcp.ServerRequest[*mcp.CallToolParamsRaw]{
		Params: &mcp.CallToolParamsRaw{
			Name:      "ctx_run",
			Arguments: json.RawMessage(`"{\"action\":\"execute\",\"argv\":[\"x\"]}"`),
		},
	}
	if _, err := mw(context.Background(), "tools/call", req); err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	p, ok := h.params.(*mcp.CallToolParamsRaw)
	if !ok {
		t.Fatalf("params type = %T, want *mcp.CallToolParamsRaw", h.params)
	}
	var args map[string]any
	if err := json.Unmarshal(p.Arguments, &args); err != nil {
		t.Fatalf("arguments after unwrap not an object: %v (%s)", err, p.Arguments)
	}
	if args["action"] != "execute" {
		t.Fatalf("args = %v", args)
	}
}

func TestArgUnwrapMiddlewareOtherMethods(t *testing.T) {
	h := &captureParamsHandler{}
	mw := argUnwrapMiddleware(h.handle)
	raw := json.RawMessage(`"unchanged"`)
	req := &mcp.ServerRequest[*mcp.CallToolParamsRaw]{
		Params: &mcp.CallToolParamsRaw{Name: "x", Arguments: raw},
	}
	if _, err := mw(context.Background(), "tools/list", req); err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
}
