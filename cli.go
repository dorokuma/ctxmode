package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func cliUsage() string {
	return `ctxmode — context virtualization MCP server

Usage:
  ctxmode [flags]                 run as MCP server on stdio (default)
  ctxmode [flags] index <path>    index a file or directory into the knowledge base
  ctxmode [flags] search <query>  search the knowledge base and print matches
  ctxmode -h, --help              show this help

`
}

func runCLI(s *server, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("no command")
	}
	switch args[0] {
	case "index":
		if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
			return fmt.Errorf("usage: ctxmode index <path>")
		}
		res, _, err := s.toolIndex(context.Background(), nil, indexArgs{Path: args[1]})
		if err != nil {
			return err
		}
		return writeCLIText(stdout, callToolText(res))
	case "search":
		q := strings.TrimSpace(strings.Join(args[1:], " "))
		if q == "" {
			return fmt.Errorf("usage: ctxmode search <query>")
		}
		res, _, err := s.toolSearch(context.Background(), nil, searchArgs{Query: q})
		if err != nil {
			return err
		}
		return writeCLIText(stdout, callToolText(res))
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], cliUsage())
	}
}

func writeCLIText(w io.Writer, text string) error {
	if text == "" {
		return nil
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	_, err := io.WriteString(w, text)
	return err
}

func callToolText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
