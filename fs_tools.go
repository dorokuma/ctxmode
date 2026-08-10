package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- filesystem tool limits ----------

const (
	fsDefaultLimit          = 200
	fsHardLimit             = 2000
	fsDefaultDepth          = 1
	fsMaxDepth              = 5
	fsRgDefaultLimit        = 50
	fsRgHardLimit           = 500
	fsRgMaxContext          = 5
	fsRgMaxOutputBytes      = 100 * 1024 // 100 KB
	fsRgProcessCaptureBytes = 2 * fsRgMaxOutputBytes
)

// skipWalkDirs are well-known bulk/VCS directories always skipped by glob/rg walks.
var skipWalkDirs = map[string]bool{
	".git":          true,
	"node_modules":  true,
	"vendor":        true,
	".hg":           true,
	".svn":          true,
	"__pycache__":   true,
	".tox":          true,
	".mypy_cache":   true,
	".pytest_cache": true,
	"dist":          true,
	"build":         true,
	".next":         true,
	".nuxt":         true,
	"target":        true, // Rust/Java common
}

// ---------- ctx_fs: ls ----------

type lsArgs struct {
	Path          string `json:"path,omitempty" jsonschema:"Directory path to list (default: .)"`
	Depth         int    `json:"depth,omitempty" jsonschema:"Recursion depth 1-5 (default: 1)"`
	IncludeHidden bool   `json:"include_hidden,omitempty" jsonschema:"Include dotfiles (default: false)"`
	Limit         int    `json:"limit,omitempty" jsonschema:"Max entries to return (default: 200, hard max: 2000)"`
}

type lsEntry struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	IsDir     bool   `json:"is_dir"`
	IsSymlink bool   `json:"is_symlink,omitempty"`
	Size      int64  `json:"size,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Depth     int    `json:"depth"`
}

func (s *server) toolLs(ctx context.Context, _ *mcp.CallToolRequest, args lsArgs) (*mcp.CallToolResult, any, error) {
	pathArg := args.Path
	if pathArg == "" {
		pathArg = "."
	}
	depth := args.Depth
	if depth <= 0 {
		depth = fsDefaultDepth
	}
	if depth > fsMaxDepth {
		return nil, nil, fmt.Errorf("invalid depth %d: exceeds maximum %d (valid range: 1-%d, default %d)", depth, fsMaxDepth, fsMaxDepth, fsDefaultDepth)
	}
	limit := args.Limit
	if limit <= 0 {
		limit = fsDefaultLimit
	}
	if limit > fsHardLimit {
		return nil, nil, fmt.Errorf("invalid limit %d: exceeds maximum %d (valid range: 1-%d, default %d)", limit, fsHardLimit, fsHardLimit, fsDefaultLimit)
	}

	root, err := s.resolvePath(pathArg)
	if err != nil {
		return nil, nil, err
	}
	// Follow final component only if it stays inside workspaces (resolvePath already did).
	st, err := os.Stat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("stat %q: %w", pathArg, err)
	}
	if !st.IsDir() {
		return nil, nil, fmt.Errorf("path %q is not a directory", pathArg)
	}
	walkRoot := root

	var entries []lsEntry
	truncated := false

	// BFS / Walk with depth limit relative to walkRoot.
	baseDepth := strings.Count(walkRoot, string(filepath.Separator))
	err = filepath.Walk(walkRoot, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable
		}
		if p == walkRoot {
			return nil // skip root itself
		}
		// Symlink fence: never follow escapes.
		if real, rerr := s.ensureInsideWorkspaces(p); rerr != nil {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		} else {
			// Prefer real path for containment; still report relative to walkRoot.
			_ = real
		}

		relDepth := strings.Count(p, string(filepath.Separator)) - baseDepth
		if relDepth > depth {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		name := fi.Name()
		if !args.IncludeHidden && strings.HasPrefix(name, ".") {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Do not descend into directories beyond depth-1 of listing.
		// When relDepth == depth we still list the entry but skip children.
		if fi.IsDir() && relDepth >= depth {
			// List this dir entry then skip children.
			if len(entries) >= limit {
				truncated = true
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(walkRoot, p)
			if rel == "" || rel == "." {
				rel = name
			}
			// Prefer path relative to first workdir when possible.
			display := s.displayPath(p)
			entries = append(entries, lsEntry{
				Path:      display,
				Name:      name,
				IsDir:     true,
				IsSymlink: fi.Mode()&os.ModeSymlink != 0,
				Mode:      fi.Mode().String(),
				Depth:     relDepth,
			})
			return filepath.SkipDir
		}

		if len(entries) >= limit {
			truncated = true
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		display := s.displayPath(p)
		isLink := fi.Mode()&os.ModeSymlink != 0
		// Lstat via Walk already; for size of symlink report link size.
		e := lsEntry{
			Path:      display,
			Name:      name,
			IsDir:     fi.IsDir(),
			IsSymlink: isLink,
			Size:      fi.Size(),
			Mode:      fi.Mode().String(),
			Depth:     relDepth,
		}
		if fi.IsDir() {
			e.Size = 0
		}
		entries = append(entries, e)

		// If directory is a symlink, do not follow (Walk follows by default only if
		// we walk into it — filepath.Walk does not follow symlink dirs on Unix).
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	// Stable sort by path.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})

	type lsResult struct {
		Root      string    `json:"root"`
		Count     int       `json:"count"`
		Truncated bool      `json:"truncated,omitempty"`
		Entries   []lsEntry `json:"entries"`
	}
	out := lsResult{
		Root:      s.displayPath(walkRoot),
		Count:     len(entries),
		Truncated: truncated,
		Entries:   entries,
	}
	js, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

// displayPath returns a path relative to the first matching workdir, else absolute.
func (s *server) displayPath(abs string) string {
	for _, wd := range s.workdirs {
		realWd := wd
		if rw, err := filepath.EvalSymlinks(wd); err == nil {
			realWd = rw
		}
		cleanWd := strings.TrimSuffix(realWd, string(filepath.Separator))
		// Also try raw wd if EvalSymlinks differs.
		for _, base := range []string{cleanWd, strings.TrimSuffix(wd, string(filepath.Separator))} {
			if abs == base {
				return "."
			}
			if strings.HasPrefix(abs, base+string(filepath.Separator)) {
				rel, err := filepath.Rel(base, abs)
				if err == nil {
					return rel
				}
			}
		}
	}
	return abs
}

// ---------- ctx_fs: glob ----------

type globArgs struct {
	Pattern string `json:"pattern" jsonschema:"Glob pattern (e.g. **/*.go)"`
	Path    string `json:"path,omitempty" jsonschema:"Search root (default: .)"`
	Limit   int    `json:"limit,omitempty" jsonschema:"Max matches (default: 200, hard max: 2000)"`
}

func (s *server) toolGlob(ctx context.Context, _ *mcp.CallToolRequest, args globArgs) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(args.Pattern) == "" {
		return nil, nil, fmt.Errorf("pattern is required")
	}
	pathArg := args.Path
	if pathArg == "" {
		pathArg = "."
	}
	limit := args.Limit
	if limit <= 0 {
		limit = fsDefaultLimit
	}
	if limit > fsHardLimit {
		return nil, nil, fmt.Errorf("invalid limit %d: exceeds maximum %d (valid range: 1-%d, default %d)", limit, fsHardLimit, fsHardLimit, fsDefaultLimit)
	}

	root, err := s.resolvePath(pathArg)
	if err != nil {
		return nil, nil, err
	}
	st, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !st.IsDir() {
		return nil, nil, fmt.Errorf("path %q is not a directory", pathArg)
	}

	// Optional .gitignore basic ignore patterns (root only).
	gitignore := loadBasicGitignore(root)

	var matches []string
	truncated := false
	pattern := filepath.ToSlash(args.Pattern)

	err = filepath.Walk(root, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if p == root {
			return nil
		}
		base := fi.Name()
		if fi.IsDir() && skipWalkDirs[base] {
			return filepath.SkipDir
		}
		// Symlink fence.
		if _, rerr := s.ensureInsideWorkspaces(p); rerr != nil {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)

		if gitignore.ignores(relSlash, fi.IsDir()) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Match files and dirs against pattern (both useful).
		if matchGlobPattern(pattern, relSlash) {
			if len(matches) >= limit {
				truncated = true
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			matches = append(matches, s.displayPath(p))
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	sort.Strings(matches)

	type globResult struct {
		Pattern   string   `json:"pattern"`
		Root      string   `json:"root"`
		Count     int      `json:"count"`
		Truncated bool     `json:"truncated,omitempty"`
		Matches   []string `json:"matches"`
	}
	out := globResult{
		Pattern:   args.Pattern,
		Root:      s.displayPath(root),
		Count:     len(matches),
		Truncated: truncated,
		Matches:   matches,
	}
	js, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

// matchGlobPattern supports *, ?, and ** against slash-separated relative paths.
func matchGlobPattern(pattern, name string) bool {
	pattern = strings.TrimPrefix(pattern, "./")
	name = strings.TrimPrefix(name, "./")
	return globMatch(pattern, name)
}

// globMatch is a simple recursive matcher for path globs with **.
func globMatch(pattern, name string) bool {
	// Fast path: no ** — use path segment matching with filepath.Match on full string
	// after converting ** absence. filepath.Match does not treat / specially for **.
	if !strings.Contains(pattern, "**") {
		ok, err := filepath.Match(pattern, name)
		if err == nil && ok {
			return true
		}
		// Also try matching basename only when pattern has no slash.
		if !strings.Contains(pattern, "/") {
			ok, err := filepath.Match(pattern, filepath.Base(name))
			return err == nil && ok
		}
		return false
	}

	// Recursive ** matching.
	return globMatchRec(pattern, name)
}

func globMatchRec(pattern, name string) bool {
	for {
		if pattern == "" {
			return name == ""
		}
		if strings.HasPrefix(pattern, "**") {
			rest := pattern[2:]
			rest = strings.TrimPrefix(rest, "/")
			if rest == "" {
				return true // ** at end matches everything
			}
			// Try matching rest at every suffix of name.
			if globMatchRec(rest, name) {
				return true
			}
			for i := 0; i < len(name); i++ {
				if name[i] == '/' {
					if globMatchRec(rest, name[i+1:]) {
						return true
					}
				}
			}
			// Also match rest against full name segments without leading slash cases.
			return false
		}

		// Consume until next / or end on both sides with * and ? support for one segment.
		var pSeg, nSeg string
		if i := strings.IndexByte(pattern, '/'); i >= 0 {
			pSeg = pattern[:i]
			pattern = pattern[i+1:]
		} else {
			pSeg = pattern
			pattern = ""
		}
		if name == "" {
			// Pattern still has a segment — only OK if remaining can match empty via **
			// (handled at top). Here name exhausted.
			return false
		}
		if i := strings.IndexByte(name, '/'); i >= 0 {
			nSeg = name[:i]
			name = name[i+1:]
		} else {
			nSeg = name
			name = ""
		}
		ok, err := filepath.Match(pSeg, nSeg)
		if err != nil || !ok {
			return false
		}
		// continue with remaining pattern/name
		if pattern == "" {
			return name == ""
		}
		if name == "" && !strings.HasPrefix(pattern, "**") {
			// more pattern but no name
			return pattern == "" || pattern == "**" || strings.HasPrefix(pattern, "**/") && globMatchRec(pattern, "")
		}
	}
}

// basicGitignore holds simple gitignore-style rules from a single file.
type basicGitignore struct {
	// patterns are relative; trailing / means dir-only; leading ! means negation (ignored for simplicity — we skip !).
	patterns []string
}

func loadBasicGitignore(root string) basicGitignore {
	data, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return basicGitignore{}
	}
	var pats []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		pats = append(pats, filepath.ToSlash(line))
	}
	return basicGitignore{patterns: pats}
}

func (g basicGitignore) ignores(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	base := filepath.Base(rel)
	for _, p := range g.patterns {
		dirOnly := strings.HasSuffix(p, "/")
		if dirOnly {
			p = strings.TrimSuffix(p, "/")
			if !isDir {
				continue
			}
		}
		p = strings.TrimPrefix(p, "/")
		if matchGlobPattern(p, rel) || matchGlobPattern(p, base) {
			return true
		}
		// **/pattern
		if matchGlobPattern("**/"+p, rel) {
			return true
		}
	}
	return false
}

// ---------- ctx_fs: stat ----------

type statArgs struct {
	Path string `json:"path" jsonschema:"File or directory path to stat"`
}

func (s *server) toolStat(ctx context.Context, _ *mcp.CallToolRequest, args statArgs) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(args.Path) == "" {
		return nil, nil, fmt.Errorf("path is required")
	}
	// Keep the final path component so Lstat can see symlinks; still fence parents.
	target, err := s.resolvePathKeepFinal(args.Path)
	if err != nil {
		return nil, nil, err
	}

	// Lstat so we can detect symlinks without following.
	li, err := os.Lstat(target)
	if err != nil {
		return nil, nil, err
	}

	isLink := li.Mode()&os.ModeSymlink != 0
	var linkTarget string
	if isLink {
		if lt, err := os.Readlink(target); err == nil {
			linkTarget = lt
		}
	}

	// in_workdir: the path itself is inside (resolvePathKeepFinal); also note if
	// following the symlink (if any) still lands inside a workdir.
	inWorkdir := true
	if _, err := s.ensureInsideWorkspaces(target); err != nil {
		// Broken link or escape after follow — path entry may still be in workdir lexically.
		inWorkdir = s.lexicallyInside(target)
	}

	isDir := li.IsDir()
	size := li.Size()
	if isLink {
		if fi, err := os.Stat(target); err == nil {
			isDir = fi.IsDir()
			_ = fi
		}
	}

	type statResult struct {
		Path          string `json:"path"`
		AbsPath       string `json:"abs_path"`
		Size          int64  `json:"size"`
		Mode          string `json:"mode"`
		ModePerm      string `json:"mode_perm"`
		ModTime       string `json:"mtime"`
		IsDir         bool   `json:"is_dir"`
		IsSymlink     bool   `json:"is_symlink"`
		SymlinkTarget string `json:"symlink_target,omitempty"`
		InWorkdir     bool   `json:"in_workdir"`
	}
	out := statResult{
		Path:          s.displayPath(target),
		AbsPath:       target,
		Size:          size,
		Mode:          li.Mode().String(),
		ModePerm:      li.Mode().Perm().String(),
		ModTime:       li.ModTime().UTC().Format(time.RFC3339),
		IsDir:         isDir,
		IsSymlink:     isLink,
		SymlinkTarget: linkTarget,
		InWorkdir:     inWorkdir,
	}
	js, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

// resolvePathKeepFinal is like resolvePath but does not EvalSymlinks the final
// path component. This allows Lstat to observe a symlink at the leaf while still
// fencing parent directories against workspace escape.
func (s *server) resolvePathKeepFinal(p string) (string, error) {
	if p == "" {
		return s.workdirs[0], nil
	}
	var target string
	if filepath.IsAbs(p) {
		target = filepath.Clean(p)
	} else {
		target = filepath.Clean(filepath.Join(s.workdirs[0], p))
	}
	if !s.lexicallyInside(target) {
		return "", fmt.Errorf("path %q is outside all workspaces %q", p, s.workdirs)
	}
	parent := filepath.Dir(target)
	base := filepath.Base(target)
	// Root edge: Dir("/") == "/".
	if parent == target {
		return s.ensureInsideWorkspaces(target)
	}
	resolvedParent, err := s.ensureInsideWorkspaces(parent)
	if err != nil {
		return "", err
	}
	full := filepath.Join(resolvedParent, base)
	// Final lexical check after parent resolution.
	if !s.lexicallyInside(full) {
		// Parent resolved somewhere still under workdir; join should stay inside.
		// Re-check with ensure on the full path only if it exists and is not a link.
		if fi, err := os.Lstat(full); err == nil && fi.Mode()&os.ModeSymlink == 0 {
			return s.ensureInsideWorkspaces(full)
		}
	}
	return full, nil
}

// ---------- ctx_fs: rg ----------

type rgArgs struct {
	Pattern    string `json:"pattern" jsonschema:"Regex pattern to search (or literal if literal=true)"`
	Path       string `json:"path,omitempty" jsonschema:"Search root (default: .)"`
	Glob       string `json:"glob,omitempty" jsonschema:"Optional file glob filter (e.g. *.go)"`
	IgnoreCase bool   `json:"ignore_case,omitempty" jsonschema:"Case-insensitive match"`
	Context    int    `json:"context,omitempty" jsonschema:"Lines of context around match (0-5)"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Max matches (default: 50, hard max: 500)"`
	Literal    bool   `json:"literal,omitempty" jsonschema:"Treat pattern as literal string"`
}

func (s *server) toolRg(ctx context.Context, _ *mcp.CallToolRequest, args rgArgs) (*mcp.CallToolResult, any, error) {
	if args.Pattern == "" {
		return nil, nil, fmt.Errorf("pattern is required")
	}
	pathArg := args.Path
	if pathArg == "" {
		pathArg = "."
	}
	limit := args.Limit
	if limit <= 0 {
		limit = fsRgDefaultLimit
	}
	if limit > fsRgHardLimit {
		return nil, nil, fmt.Errorf("invalid limit %d: exceeds maximum %d (valid range: 1-%d, default %d)", limit, fsRgHardLimit, fsRgHardLimit, fsRgDefaultLimit)
	}
	contextLines := args.Context
	if contextLines < 0 {
		contextLines = 0
	}
	if contextLines > fsRgMaxContext {
		contextLines = fsRgMaxContext
	}

	root, err := s.resolvePath(pathArg)
	if err != nil {
		return nil, nil, err
	}

	// Prefer system rg when available.
	if rgPath, lookErr := exec.LookPath("rg"); lookErr == nil {
		text, truncated, n, err := s.rgSystem(ctx, rgPath, root, args, limit, contextLines)
		if err == nil {
			return s.rgResult(text, n, truncated, "rg"), nil, nil
		}
		// Fall through to pure-Go on unexpected failure (e.g. bad flags).
		// If rg exits 1 (no matches) that is success with empty output.
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			return s.rgResult("", 0, false, "rg"), nil, nil
		}
		// Other errors: try Go fallback.
	}

	text, truncated, n, err := s.rgGo(ctx, root, args, limit, contextLines)
	if err != nil {
		return nil, nil, err
	}
	return s.rgResult(text, n, truncated, "go"), nil, nil
}

func (s *server) rgResult(text string, count int, truncated bool, engine string) *mcp.CallToolResult {
	header := fmt.Sprintf("engine=%s matches=%d", engine, count)
	if truncated {
		header += " truncated=true"
	}
	if text == "" {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: header + "\n(no matches)"}},
		}
	}
	// Cap total response size.
	if len(text) > fsRgMaxOutputBytes {
		text = truncateUTF8(text, fsRgMaxOutputBytes) + "\n... (output truncated at 100KB)"
		truncated = true
		header = fmt.Sprintf("engine=%s matches=%d truncated=true", engine, count)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: header + "\n" + text}},
	}
}

func (s *server) rgSystem(ctx context.Context, rgPath, root string, args rgArgs, limit, contextLines int) (string, bool, int, error) {
	cmdArgs := []string{
		"--no-heading",
		"--line-number",
		"--color", "never",
		"--hidden",
		"--glob", "!.git/**",
		"--glob", "!node_modules/**",
		"--glob", "!vendor/**",
		"-m", strconv.Itoa(limit),
	}
	if args.IgnoreCase {
		cmdArgs = append(cmdArgs, "-i")
	}
	if args.Literal {
		cmdArgs = append(cmdArgs, "-F")
	}
	if contextLines > 0 {
		cmdArgs = append(cmdArgs, "-C", strconv.Itoa(contextLines))
	}
	if args.Glob != "" {
		cmdArgs = append(cmdArgs, "--glob", args.Glob)
	}
	// Pattern and path last.
	cmdArgs = append(cmdArgs, "--", args.Pattern, root)

	cmd := exec.CommandContext(ctx, rgPath, cmdArgs...)
	var stdout limitedBuffer
	stdout.limit = fsRgProcessCaptureBytes
	var stderr limitedBuffer
	stderr.limit = 64 * 1024
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// Exit 0 = matches, 1 = no match, 2 = error.
			if ee.ExitCode() == 1 {
				return "", false, 0, nil
			}
			if ee.ExitCode() != 0 && stdout.buf.Len() == 0 {
				return "", false, 0, fmt.Errorf("rg: %s", strings.TrimSpace(stderr.String()))
			}
		} else {
			return "", false, 0, err
		}
	}

	// Rewrite absolute paths to display paths and count matches.
	lines := strings.Split(stdout.String(), "\n")
	var b strings.Builder
	matchCount := 0
	truncated := stdout.truncated
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Match lines look like path:line:content or path-line-content (context).
		rewritten := s.rewriteRgLine(root, line)
		// Count real matches (colon form with line number), not context separators.
		if isRgMatchLine(rewritten) {
			if matchCount >= limit {
				truncated = true
				break
			}
			matchCount++
		}
		if b.Len()+len(rewritten)+1 > fsRgMaxOutputBytes {
			truncated = true
			break
		}
		b.WriteString(rewritten)
		b.WriteByte('\n')
	}
	// rg -m may stop early; if we got exactly limit matches, note truncated possibility.
	if matchCount >= limit {
		truncated = true
	}
	return strings.TrimRight(b.String(), "\n"), truncated, matchCount, nil
}

func isRgMatchLine(line string) bool {
	// path:123:content — not path-123-content (context) and not "--"
	if line == "--" {
		return false
	}
	// Find first :digits:
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return false
	}
	rest := line[i+1:]
	j := strings.IndexByte(rest, ':')
	if j < 0 {
		return false
	}
	num := rest[:j]
	if num == "" {
		return false
	}
	for _, c := range num {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (s *server) rewriteRgLine(root, line string) string {
	// Lines start with absolute path from rg.
	// Split carefully: path may contain colons on Windows — we target Unix.
	// Form: /abs/path:linenum:content or /abs/path-linenum-content
	if strings.HasPrefix(line, root) {
		rest := line[len(root):]
		// rest starts with / or : or -
		displayRoot := s.displayPath(root)
		if displayRoot == "." {
			rest = strings.TrimPrefix(rest, string(filepath.Separator))
			if rest == "" {
				return "."
			}
			// If rest starts with : or - keep; if with path sep already trimmed.
			if len(rest) > 0 && rest[0] != ':' && rest[0] != '-' {
				return displayRoot + "/" + rest
			}
			// root file itself: ".:n:..." doesn't make sense; use basename path
			return s.displayPath(root) + rest
		}
		return displayRoot + rest
	}
	// Try displayPath on the path prefix before : or -
	for _, sep := range []byte{':', '-'} {
		if i := strings.IndexByte(line, sep); i > 0 {
			p := line[:i]
			if filepath.IsAbs(p) {
				return s.displayPath(p) + line[i:]
			}
		}
	}
	return line
}

func (s *server) rgGo(ctx context.Context, root string, args rgArgs, limit, contextLines int) (string, bool, int, error) {
	pattern := args.Pattern
	if args.Literal {
		pattern = regexp.QuoteMeta(pattern)
	}
	flags := ""
	if args.IgnoreCase {
		flags = "(?i)"
	}
	re, err := regexp.Compile(flags + pattern)
	if err != nil {
		return "", false, 0, fmt.Errorf("invalid pattern: %w", err)
	}

	var fileGlob string
	if args.Glob != "" {
		fileGlob = filepath.ToSlash(args.Glob)
	}

	var b strings.Builder
	matchCount := 0
	truncated := false
	gitignore := loadBasicGitignore(root)

	walkErr := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		// Honour cancellation so long pure-Go walks do not outlive the request.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil || truncated {
			return nil
		}
		if fi.IsDir() {
			base := fi.Name()
			if skipWalkDirs[base] {
				return filepath.SkipDir
			}
			if _, rerr := s.ensureInsideWorkspaces(p); rerr != nil {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, p)
			if rel != "." && gitignore.ignores(filepath.ToSlash(rel), true) {
				return filepath.SkipDir
			}
			return nil
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		if _, rerr := s.ensureInsideWorkspaces(p); rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		relSlash := filepath.ToSlash(rel)
		if gitignore.ignores(relSlash, false) {
			return nil
		}
		if isProbablyBinaryName(fi.Name()) {
			return nil
		}
		if fileGlob != "" {
			base := filepath.Base(p)
			if !matchGlobPattern(fileGlob, relSlash) && !matchGlobPattern(fileGlob, base) {
				return nil
			}
		}

		// Size cap: skip huge files (> 5MB) in pure-Go path for responsiveness.
		if fi.Size() > 5*1024*1024 {
			return nil
		}

		f, err := os.Open(p)
		if err != nil {
			return nil
		}

		// Sniff binary.
		head := make([]byte, binarySampleSize)
		n, _ := io.ReadFull(f, head)
		head = head[:n]
		if isBinaryContent(head) {
			_ = f.Close()
			return nil
		}
		// Rewind with combined reader.
		reader := io.MultiReader(bytes.NewReader(head), f)
		scanner := bufio.NewScanner(reader)
		// Increase buffer for long lines.
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		display := s.displayPath(p)
		var ring []string // previous lines for context
		lineNo := 0
		pendingAfter := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			// Ensure valid display of possibly invalid UTF-8.
			if !utf8.ValidString(line) {
				line = strings.ToValidUTF8(line, "\uFFFD")
			}
			matched := re.MatchString(line)
			if matched {
				// Emit pre-context.
				if contextLines > 0 && len(ring) > 0 {
					start := 0
					if len(ring) > contextLines {
						start = len(ring) - contextLines
					}
					for i := start; i < len(ring); i++ {
						ctxNo := lineNo - (len(ring) - i)
						fmt.Fprintf(&b, "%s-%d-%s\n", display, ctxNo, ring[i])
					}
				}
				fmt.Fprintf(&b, "%s:%d:%s\n", display, lineNo, line)
				matchCount++
				pendingAfter = contextLines
				if matchCount >= limit {
					truncated = true
					_ = f.Close()
					return io.EOF // stop walk
				}
				if b.Len() > fsRgMaxOutputBytes {
					truncated = true
					_ = f.Close()
					return io.EOF
				}
			} else if pendingAfter > 0 {
				fmt.Fprintf(&b, "%s-%d-%s\n", display, lineNo, line)
				pendingAfter--
			}
			if contextLines > 0 {
				ring = append(ring, line)
				if len(ring) > contextLines {
					ring = ring[1:]
				}
			}
		}
		scanErr := scanner.Err()
		closeErr := f.Close()
		if scanErr != nil {
			return scanErr
		}
		return closeErr
	})
	if walkErr != nil && walkErr != io.EOF {
		return "", false, 0, walkErr
	}
	return strings.TrimRight(b.String(), "\n"), truncated, matchCount, nil
}
