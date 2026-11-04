// Minimal argv printer for ctxmode dash differential tests.
// Each invocation appends one JSON array line to CTXMODE_ARGV_OUT (O_APPEND).
// argv[0] is the basename of the invoked name so PATH symlinks work.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func main() {
	out := os.Getenv("CTXMODE_ARGV_OUT")
	if out == "" {
		os.Exit(2)
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		os.Exit(2)
	}
	argv := make([]string, len(os.Args))
	copy(argv, os.Args)
	if len(argv) > 0 {
		argv[0] = filepath.Base(argv[0])
	}
	if err := json.NewEncoder(f).Encode(argv); err != nil {
		_ = f.Close()
		os.Exit(2)
	}
	_ = f.Close()
}
