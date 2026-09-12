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

// stripANSI removes ANSI escape sequences from text so content indexed from
// untrusted sources (web fetches, repository files) cannot inject terminal
// control codes when the CLI prints KB content to stdout. Handles OSC
// (ESC ] ... BEL or ESC \), CSI (ESC [ parameter bytes, intermediate bytes,
// final byte), and remaining ESC forms (intermediate bytes 0x20-0x2F plus
// one final byte: the two-byte ESC X form and e.g. ESC ( B). An unterminated
// OSC swallows the rest of the text, mirroring terminal behavior.
func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\x1b' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 >= len(s) {
			break // dangling trailing ESC: drop
		}
		switch s[i+1] {
		case ']':
			// OSC: terminated by BEL (0x07) or ST (ESC \)
			end := -1
			for j := i + 2; j < len(s); j++ {
				if s[j] == '\x07' {
					end = j
					break
				}
				if s[j] == '\x1b' && j+1 < len(s) && s[j+1] == '\\' {
					end = j + 1
					break
				}
			}
			if end < 0 {
				i = len(s) // unterminated OSC: drop the remainder
			} else {
				i = end + 1
			}
		case '[':
			// CSI: parameter bytes 0x30-0x3F, intermediates 0x20-0x2F, final 0x40-0x7E
			j := i + 2
			for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
				j++
			}
			if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
				i = j + 1
			} else {
				i = j // malformed CSI: drop what was scanned
			}
		default:
			// Other ESC sequences: intermediate bytes 0x20-0x2F then one final byte
			// 0x30-0x7E (two-byte ESC X, or three-byte e.g. ESC ( B).
			j := i + 1
			for j < len(s) && s[j] >= 0x20 && s[j] <= 0x2f {
				j++
			}
			if j < len(s) && s[j] >= 0x30 && s[j] <= 0x7e {
				i = j + 1
			} else {
				i = j // dangling ESC or intermediates: drop them
			}
		}
	}
	return b.String()
}

func writeCLIText(w io.Writer, text string) error {
	if text == "" {
		return nil
	}
	text = stripANSI(text)
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
