// Tolerance for LLM hosts that deliver tools/call params.arguments as a
// JSON-encoded string (possibly nested) instead of the object the MCP spec
// requires: observed in the wild as both "{...}" (one extra string layer)
// and "\"{...}\"" (two). The wire-level unmarshal into CallToolParamsRaw
// succeeds either way (Arguments is json.RawMessage), so the failure only
// surfaces later inside the tool's own unmarshal. This receiving middleware
// unwraps string layers before that point, capped at maxArgUnwrapDepth.
package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxArgUnwrapDepth = 3

// argUnwrapMiddleware rewrites tools/call params.arguments when it arrives as
// a JSON string containing JSON, then delegates to the next handler. Values
// that are not JSON strings, or whose decoded content is not valid JSON, pass
// through untouched so downstream still reports the real type error.
func argUnwrapMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method == "tools/call" {
			if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok {
				if unwrapped, depth := unwrapArgString(p.Arguments); depth > 0 {
					log.Printf("ctxmode: tools/call %q: unwrapped %d extra JSON string layer(s) in arguments", p.Name, depth)
					p.Arguments = unwrapped
				}
			}
		}
		return next(ctx, method, req)
	}
}

// unwrapArgString decodes raw while it holds a JSON string that itself parses
// as JSON, returning the last decoded raw value and how many string layers
// were removed (0 = unchanged).
func unwrapArgString(raw json.RawMessage) (json.RawMessage, int) {
	cur := raw
	depth := 0
	for depth < maxArgUnwrapDepth {
		var s string
		if err := json.Unmarshal(cur, &s); err != nil {
			break
		}
		inner := strings.TrimSpace(s)
		if !json.Valid([]byte(inner)) {
			break
		}
		cur = json.RawMessage(inner)
		depth++
	}
	return cur, depth
}
