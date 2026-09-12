package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ---------- filesystem tool limits ----------

const (
	fsDefaultLimit          = 200
	fsHardLimit             = 2000
	fsDefaultDepth          = 1
	fsMaxDepth              = 5
	fsRgDefaultLimit        = 20
	fsRgHardLimit           = 500
	fsRgMaxContext          = 5
	fsRgMaxOutputBytes      = 100 * 1024 // 100 KB
	fsRgProcessCaptureBytes = 2 * fsRgMaxOutputBytes
)

// rgBudgetMs is the wall-clock search budget for ctx_fs rg, in milliseconds.
// Default 10s; CTXMODE_RG_BUDGET_MS overrides; <=0 disables.
var rgBudgetMs = envIntDefault("CTXMODE_RG_BUDGET_MS", 10_000)

// errRgBudget is returned by rgSystem/rgGo when the wall-clock budget is hit.
// Partial results are in the text return; toolRg turns this into truncated=true
// plus a narrow-path/glob hint rather than an MCP error.
var errRgBudget = errors.New("rg wall-clock budget exceeded")

func envIntDefault(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// isWildcardOnlyPattern reports whether a regex pattern contains no literal
// characters after stripping regex metacharacters and whitespace. Such patterns
// (".*", "*", ".+", ".", ".*.*") match (nearly) every line and are almost
// always grep misused as a file reader. Mixed patterns ("foo.*", "Get.*Name")
// always pass. Metacharacter-free strings are never wildcard-only.
//
// Zero-width assertions (\b \B \A \z \Z) are stripped from the copy used for
// the literal scan (while still marking the pattern regex-bearing): they
// match position only, so `\b\b`/`\B\B` cannot smuggle b/B past the guard,
// while `\bfoo\b` keeps its real literal and passes.
func isWildcardOnlyPattern(pattern string) bool {
	var stripped strings.Builder
	stripped.Grow(len(pattern))
	assertion := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c == '\\' && i+1 < len(pattern) {
			switch pattern[i+1] {
			case 'b', 'B', 'A', 'z', 'Z':
				assertion = true
				i++
				continue
			case '\\':
				// Escaped backslash: keep both bytes so a following b/B is
				// not misread as an assertion escape (`\\b` = literal "\b").
				stripped.WriteByte(c)
				stripped.WriteByte(pattern[i+1])
				i++
				continue
			}
		}
		stripped.WriteByte(c)
	}
	hasMeta := assertion
	onlyMetaOrSpace := true
	for _, r := range stripped.String() {
		switch r {
		case '.', '*', '+', '?', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\':
			hasMeta = true
		default:
			if !unicode.IsSpace(r) {
				onlyMetaOrSpace = false
			}
		}
	}
	return hasMeta && onlyMetaOrSpace
}

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
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if walkErr != nil {
			return nil
		}
		if p == walkRoot {
			return nil
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

// displayPathBase returns the workdir that displayPath would relativize abs against.
// Used to invert workdir-relative rg match paths back to absolute dirty keys.
func (s *server) displayPathBase(abs string) string {
	if s == nil {
		return abs
	}
	for _, wd := range s.workdirs {
		realWd := wd
		if rw, err := filepath.EvalSymlinks(wd); err == nil {
			realWd = rw
		}
		cleanWd := strings.TrimSuffix(realWd, string(filepath.Separator))
		for _, base := range []string{cleanWd, strings.TrimSuffix(wd, string(filepath.Separator))} {
			if abs == base {
				return base
			}
			if strings.HasPrefix(abs, base+string(filepath.Separator)) {
				return base
			}
		}
	}
	return abs
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

	// Root + nested .gitignore (last match wins, including !).
	gitignore := newGitignoreStack(root)

	var absMatches []string
	truncated := false
	pattern := filepath.ToSlash(args.Pattern)

	err = filepath.Walk(root, func(p string, fi os.FileInfo, walkErr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if walkErr != nil {
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
		if isSensitiveFilePath(p) {
			return nil
		}

		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		for len(gitignore.layers) > 1 {
			base := gitignore.layers[len(gitignore.layers)-1].base
			if base == "." || relSlash == base || strings.HasPrefix(relSlash, base+"/") {
				break
			}
			gitignore.layers = gitignore.layers[:len(gitignore.layers)-1]
		}
		if fi.IsDir() && rel != "." {
			gitignore.push(p, relSlash)
		}
		if gitignore.ignores(relSlash, fi.IsDir()) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Match files and dirs against pattern (both useful).
		if matchGlobPattern(pattern, relSlash) {
			if len(absMatches) >= limit {
				truncated = true
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			absMatches = append(absMatches, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	matches := s.globOrderMatches(ctx, absMatches, root)

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

// globOrderMatches converts abs paths to display paths, sorts lexicographically,
// then stably partitions dirty files first using the rg git dirty set (3s TTL).
// Remaining entries keep their previous relative (lex) order.
func (s *server) globOrderMatches(ctx context.Context, absMatches []string, root string) []string {
	type item struct{ display, abs string }
	items := make([]item, len(absMatches))
	for i, p := range absMatches {
		items[i] = item{display: s.displayPath(p), abs: filepath.Clean(p)}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].display < items[j].display })
	dirty, _ := s.gitDirtyFiles(ctx, root)
	out := make([]string, 0, len(items))
	if len(dirty) == 0 {
		for _, it := range items {
			out = append(out, it.display)
		}
		return out
	}
	for _, it := range items {
		if _, ok := dirty[it.abs]; ok {
			out = append(out, it.display)
		}
	}
	for _, it := range items {
		if _, ok := dirty[it.abs]; !ok {
			out = append(out, it.display)
		}
	}
	return out
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

type giRule struct {
	neg     bool
	dirOnly bool
	pat     string
}

// basicGitignore holds simple gitignore-style rules from a single file.
// Last matching rule wins, including leading ! negation.
type basicGitignore struct {
	rules []giRule
}

func loadBasicGitignore(dir string) basicGitignore {
	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		return basicGitignore{}
	}
	var rules []giRule
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := giRule{}
		if strings.HasPrefix(line, "!") {
			r.neg = true
			line = strings.TrimSpace(line[1:])
			if line == "" {
				continue
			}
		}
		line = filepath.ToSlash(line)
		if strings.HasSuffix(line, "/") {
			r.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}
		r.pat = strings.TrimPrefix(line, "/")
		if r.pat == "" {
			continue
		}
		rules = append(rules, r)
	}
	return basicGitignore{rules: rules}
}

func (g basicGitignore) match(rel string, isDir bool) (matched, neg bool) {
	rel = filepath.ToSlash(rel)
	base := filepath.Base(rel)
	for _, r := range g.rules {
		if r.dirOnly && !isDir {
			continue
		}
		if matchGlobPattern(r.pat, rel) || matchGlobPattern(r.pat, base) || matchGlobPattern("**/"+r.pat, rel) {
			matched = true
			neg = r.neg
		}
	}
	return matched, neg
}

func (g basicGitignore) ignores(rel string, isDir bool) bool {
	matched, neg := g.match(rel, isDir)
	return matched && !neg
}

// gitignoreStack applies root-to-current .gitignore layers (last match wins).
type gitignoreStack struct {
	layers []struct {
		base string // slash-rel from walk root; "." = root
		gi   basicGitignore
	}
}

func newGitignoreStack(root string) gitignoreStack {
	var s gitignoreStack
	s.push(root, ".")
	return s
}

func (s *gitignoreStack) push(absDir, relFromRoot string) {
	gi := loadBasicGitignore(absDir)
	if len(gi.rules) == 0 {
		return
	}
	s.layers = append(s.layers, struct {
		base string
		gi   basicGitignore
	}{base: filepath.ToSlash(relFromRoot), gi: gi})
}

func (s *gitignoreStack) ignores(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	ignored := false
	for _, layer := range s.layers {
		local := rel
		if layer.base != "." && layer.base != "" {
			pref := layer.base + "/"
			if rel == layer.base {
				local = "."
			} else if strings.HasPrefix(rel, pref) {
				local = rel[len(pref):]
			} else {
				continue
			}
		}
		if matched, neg := layer.gi.match(local, isDir); matched {
			ignored = !neg
		}
	}
	return ignored
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
		AbsPath:       s.displayPath(target),
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
// fencing parent directories against workspace escape. Relative paths are tried
// against every workdir and must match exactly one existing path (existence is
// checked with Lstat so a leaf symlink counts even when broken); zero or
// multiple matches are errors that demand an absolute path.
func (s *server) resolvePathKeepFinal(p string) (string, error) {
	if isWorkspaceRootRel(p) {
		return s.workdirs[0], nil
	}
	if filepath.IsAbs(p) {
		target := filepath.Clean(p)
		if !s.lexicallyInside(target) {
			return "", fmt.Errorf("path %q is outside all workspaces %q", p, s.workdirs)
		}
		return s.resolveKeepFinalFenced(target)
	}
	var matches []string
	for _, wd := range s.workdirs {
		cand := filepath.Clean(filepath.Join(wd, p))
		if _, err := os.Lstat(cand); err == nil {
			matches = append(matches, cand)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("relative path %q does not exist under any workspace %q; use an absolute path", p, s.workdirs)
	case 1:
		return s.resolveKeepFinalFenced(matches[0])
	default:
		return "", fmt.Errorf("relative path %q exists under multiple workspaces %q; use an absolute path to disambiguate", p, s.workdirs)
	}
}

// resolveKeepFinalFenced resolves the parent of target (symlink-aware) and
// re-appends the final component so a leaf symlink is preserved for Lstat; the
// resolved parent must stay inside a workspace.
func (s *server) resolveKeepFinalFenced(target string) (string, error) {
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
	Limit      int    `json:"limit,omitempty" jsonschema:"Max matches (default: 20, hard max: 500)"`
	Offset     int    `json:"offset,omitempty" jsonschema:"Skip the first N matches for linear paging; match lines only, no context. offset+limit <= 500"`
	Literal    bool   `json:"literal,omitempty" jsonschema:"Treat pattern as literal string"`
}

type rgHeader struct {
	Engine    string
	Matches   int
	Files     int
	Limit     int
	Offset    int
	Truncated bool
	GitDirty  int
	GitStatus string
	Indexed   string
	BudgetHit bool
}

func defaultRgLimit() int {
	if rgSummaryEnabled {
		return fsRgDefaultLimit
	}
	return 50
}

func formatRgHeader(hdr rgHeader) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("engine=%s", hdr.Engine))
	parts = append(parts, fmt.Sprintf("matches=%d", hdr.Matches))
	if rgSummaryEnabled {
		if hdr.Files > 0 {
			parts = append(parts, fmt.Sprintf("files=%d", hdr.Files))
		}
		if hdr.Limit > 0 {
			parts = append(parts, fmt.Sprintf("limit=%d", hdr.Limit))
		}
		if hdr.Offset > 0 {
			parts = append(parts, fmt.Sprintf("offset=%d", hdr.Offset))
		}
		if hdr.Truncated {
			parts = append(parts, "truncated=true")
		} else {
			parts = append(parts, "truncated=false")
		}
	} else {
		if hdr.Truncated {
			parts = append(parts, "truncated=true")
		}
	}
	if rgGitRankEnabled {
		if hdr.GitStatus == "none" {
			parts = append(parts, "git=none")
		} else if hdr.GitStatus == "ok" {
			parts = append(parts, fmt.Sprintf("git_dirty=%d", hdr.GitDirty))
		}
	}
	if hdr.BudgetHit {
		parts = append(parts, "budget_exceeded=true")
	}
	if hdr.Indexed != "" {
		parts = append(parts, fmt.Sprintf("indexed=%s", hdr.Indexed))
	}
	return strings.Join(parts, " ")
}

func rgBudgetLabel() string {
	if rgBudgetMs >= 1000 && rgBudgetMs%1000 == 0 {
		return fmt.Sprintf("%ds", rgBudgetMs/1000)
	}
	return fmt.Sprintf("%dms", rgBudgetMs)
}

// rgFallbackBudget returns the wall-clock budget (ms) still available for an
// rgGo fallback after rgSystem ran since rgStart. ok is false when the budget
// is already spent, so the fallback is refused instead of restarting with a
// fresh full budget (2x spend).
func rgFallbackBudget(rgStart, now time.Time) (budgetMs int, ok bool) {
	if rgBudgetMs <= 0 {
		return 0, true // budget disabled: fallback unrestricted
	}
	left := rgBudgetMs - int(now.Sub(rgStart).Milliseconds())
	if left <= 0 {
		return 0, false
	}
	return left, true
}

func (s *server) rgRenderResult(hdr rgHeader, text string) *mcp.CallToolResult {
	budgetHint := ""
	if hdr.BudgetHit {
		budgetHint = fmt.Sprintf("\n(search stopped at %s wall-clock budget — results may be incomplete; narrow path/glob or use ctx_kb action=search)", rgBudgetLabel())
	}
	if text == "" {
		header := formatRgHeader(hdr)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: header + "\n(no matches)" + budgetHint}},
		}
	}
	// Cap total response size.
	if len(text) > fsRgMaxOutputBytes {
		text = truncateUTF8(text, fsRgMaxOutputBytes) + "\n... (output truncated at 100KB)"
		hdr.Truncated = true
	}
	header := formatRgHeader(hdr)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: header + "\n" + text + budgetHint}},
	}
}

func (s *server) rgResult(text string, count int, truncated bool, engine string) *mcp.CallToolResult {
	return s.rgRenderResult(rgHeader{
		Engine:    engine,
		Matches:   count,
		Truncated: truncated,
	}, text)
}

// rgDedupKey builds the rg result-index dedup key. The truncated/budget
// state is part of the key: a truncated or budget-cut result set must never
// be reused as (or replace) the complete set within the reuse window, or
// "(reused)" would present an incomplete corpus as a stable conclusion.
func rgDedupKey(root string, args rgArgs, contextLines int, truncated, budgetHit bool) string {
	return fmt.Sprintf("%s|%s|%s|%v|%v|%d|trunc=%v|budget=%v", root, args.Pattern, args.Glob, args.IgnoreCase, args.Literal, contextLines, truncated, budgetHit)
}

func (s *server) toolRg(ctx context.Context, _ *mcp.CallToolRequest, args rgArgs) (*mcp.CallToolResult, any, error) {
	if args.Pattern == "" {
		return nil, nil, fmt.Errorf("pattern is required")
	}
	if !args.Literal && isWildcardOnlyPattern(args.Pattern) {
		return nil, nil, fmt.Errorf("pattern %q matches everything — grep needs a concrete substring or identifier (e.g. 'MyClass' or 'export function'); pass literal:true to search metacharacters as a literal string", args.Pattern)
	}
	pathArg := args.Path
	if pathArg == "" {
		pathArg = "."
	}
	limit := args.Limit
	if limit <= 0 {
		limit = defaultRgLimit()
	}
	if limit > fsRgHardLimit {
		return nil, nil, fmt.Errorf("invalid limit %d: exceeds maximum %d (valid range: 1-%d, default %d)", limit, fsRgHardLimit, fsRgHardLimit, defaultRgLimit())
	}
	if args.Offset < 0 {
		return nil, nil, fmt.Errorf("invalid offset %d: must be >= 0", args.Offset)
	}
	if args.Offset+limit > fsRgHardLimit {
		return nil, nil, fmt.Errorf("invalid offset+limit %d: exceeds maximum %d (offset=%d, limit=%d, hard max: %d)", args.Offset+limit, fsRgHardLimit, args.Offset, limit, fsRgHardLimit)
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
	// Explicit-path fence: ripgrep applies glob filters only to walked files,
	// never to an explicit file argument, so {"path": ".env"} would read a
	// credential file straight past the deny-glob fence. Refuse file targets
	// on the sensitive-path deny list.
	if st, statErr := os.Stat(root); statErr == nil && !st.IsDir() && isSensitiveFilePath(root) {
		return nil, nil, fmt.Errorf("refusing to search %q: explicit path is a sensitive file (credentials / secret material, deny-listed)", pathArg)
	}

	dirty, tags, gitStatus := s.gitDirtyState(ctx, root)
	matchRoot := s.displayPathBase(root)

	indexingPossible := s.store != nil && rgSummaryEnabled && args.Offset == 0
	var fetchLimit, fetchBytes int
	if !rgSummaryEnabled {
		fetchLimit, fetchBytes = min(fsRgHardLimit, limit+args.Offset), fsRgMaxOutputBytes
	} else {
		fetchLimit, fetchBytes = fsRgHardLimit, fsRgProcessCaptureBytes
	}

	budgetCtx := ctx
	var cancelBudget context.CancelFunc
	if rgBudgetMs > 0 {
		budgetCtx, cancelBudget = context.WithTimeout(ctx, time.Duration(rgBudgetMs)*time.Millisecond)
		defer cancelBudget()
	}

	var text string
	var truncated bool
	var budgetHit bool
	engine := "rg"

	fillHdr := func(hdr rgHeader) rgHeader {
		if budgetHit {
			hdr.BudgetHit = true
			hdr.Truncated = true
		}
		return hdr
	}

	// Prefer system rg when available.
	if rgPath, lookErr := exec.LookPath("rg"); lookErr == nil {
		var sysErr error
		rgStart := time.Now()
		text, truncated, _, sysErr = s.rgSystemBounded(budgetCtx, ctx, rgPath, root, args, fetchLimit, contextLines, fetchBytes)
		if errors.Is(sysErr, errRgBudget) {
			budgetHit = true
			sysErr = nil
		}
		if sysErr != nil {
			if ee, ok := sysErr.(*exec.ExitError); ok && ee.ExitCode() == 1 {
				hdr := rgHeader{
					Engine:    "rg",
					Matches:   0,
					Limit:     limit,
					Offset:    args.Offset,
					Truncated: false,
					GitDirty:  0,
					GitStatus: gitStatus,
				}
				return s.rgRenderResult(fillHdr(hdr), ""), nil, nil
			}
			// Parent request already canceled or timed out: falling back to
			// the Go engine cannot succeed; surface the real cause.
			if perr := ctx.Err(); perr != nil {
				return nil, nil, perr
			}
			// Other errors: fall back to pure-Go, charged only the rg budget
			// REMAINING since rgSystem started, so a single tool call can
			// never spend 2x CTXMODE_RG_BUDGET_MS.
			budgetLeft, fallbackOK := rgFallbackBudget(rgStart, time.Now())
			if !fallbackOK {
				// Budget exhausted inside rgSystem: no fallback; surface the
				// original rg error.
				err = sysErr
			} else {
				text, truncated, _, err = s.rgGoBudget(ctx, budgetLeft, root, args, fetchLimit, contextLines, fetchBytes)
				engine = "go"
			}
		}
	} else {
		text, truncated, _, err = s.rgGo(ctx, root, args, fetchLimit, contextLines, fetchBytes)
		engine = "go"
	}

	if errors.Is(err, errRgBudget) {
		budgetHit = true
		err = nil
	}
	if err != nil {
		return nil, nil, err
	}

	var groups []rgFileGroup
	if text != "" {
		lines := strings.Split(text, "\n")
		groups = groupRgLines(lines)
		prepareRgGroups(groups)
		rankGroups(groups, dirty, matchRoot)
		tagGroups(groups, tags, matchRoot)
	}

	totalHits := 0
	for _, g := range groups {
		totalHits += g.hits
	}
	truncated = truncated || (totalHits >= fetchLimit)

	var validGroups []rgFileGroup
	for _, g := range groups {
		if g.hits > 0 {
			validGroups = append(validGroups, g)
		}
	}

	var gitDirtyCount int
	for _, g := range groups {
		if g.dirty {
			gitDirtyCount++
		}
	}

	// truncated/budget state is part of the key: a truncated or budget-cut
	// result set must never be reused as (or replace) the complete set
	// within the reuse window (see rgDedupKey).
	dedupKey := rgDedupKey(root, args, contextLines, truncated, budgetHit)

	switch {
	case args.Offset > 0:
		slicedText := sliceMatchLines(groups, args.Offset, limit)
		hdr := rgHeader{
			Engine:    engine,
			Matches:   totalHits,
			Files:     len(validGroups),
			Limit:     limit,
			Offset:    args.Offset,
			Truncated: args.Offset+limit < totalHits || truncated,
			GitDirty:  gitDirtyCount,
			GitStatus: gitStatus,
			Indexed:   s.getRgIndexLabel(dedupKey),
		}
		// Paged output is a direct return too: gate the page exactly
		// like the <=limit path, or content withheld on the first page
		// could be read back one offset at a time.
		if serr := checkSensitiveContent(slicedText); serr != nil {
			hdr.Truncated = true
			return s.rgRenderResult(fillHdr(hdr), rgSensitiveWithheldWarning(groups)), nil, nil
		}
		return s.rgRenderResult(fillHdr(hdr), slicedText), nil, nil

	case totalHits <= limit:
		body := renderGroups(groups)
		if serr := checkSensitiveContent(body); serr != nil {
			// Directly-returned results get the same sensitive-content gate
			// as the index-to-store path. Most conservative handling: never
			// echo the raw matched lines back; return a warning plus the
			// offending file names only.
			hdr := rgHeader{
				Engine:    engine,
				Matches:   totalHits,
				Files:     len(validGroups),
				Limit:     limit,
				Truncated: true,
				GitDirty:  gitDirtyCount,
				GitStatus: gitStatus,
			}
			return s.rgRenderResult(fillHdr(hdr), rgSensitiveWithheldWarning(groups)), nil, nil
		}
		if rgSummaryEnabled {
			body = prependReadHint(body, groups, matchRoot)
		}
		hdr := rgHeader{
			Engine:    engine,
			Matches:   totalHits,
			Files:     len(validGroups),
			Limit:     limit,
			Truncated: truncated,
			GitDirty:  gitDirtyCount,
			GitStatus: gitStatus,
		}
		return s.rgRenderResult(fillHdr(hdr), body), nil, nil

	case !indexingPossible:
		// Fallback: old behavior (first limit match lines with context preserved and truncated=true)
		slicedText := sliceGroupsWithContext(groups, limit)
		hdr := rgHeader{
			Engine:    engine,
			Matches:   totalHits,
			Files:     len(validGroups),
			Limit:     limit,
			Truncated: true,
			GitDirty:  gitDirtyCount,
			GitStatus: gitStatus,
		}
		if serr := checkSensitiveContent(slicedText); serr != nil {
			// Same withholding gate as the indexed fallback below: with the
			// store or summary disabled this path echoed raw lines, no gate.
			return s.rgRenderResult(fillHdr(hdr), rgSensitiveWithheldWarning(groups)), nil, nil
		}
		return s.rgRenderResult(fillHdr(hdr), slicedText), nil, nil

	default:
		// Exceeds limit: index to ctx_kb and return summary
		rawText := renderGroups(groups)
		textToStore := indexHeader(args.Pattern, root, args.Glob, totalHits, budgetHit) + rawText
		if serr := checkSensitiveContent(textToStore); serr != nil {
			// Indexing stays skipped, and the raw-match fallback is withheld
			// exactly like the <=limit direct-return gate above: echoing the
			// first N raw lines here would hand the secret to any search whose
			// hit count exceeds the limit.
			hdr := rgHeader{
				Engine:    engine,
				Matches:   totalHits,
				Files:     len(validGroups),
				Limit:     limit,
				Truncated: true,
				GitDirty:  gitDirtyCount,
				GitStatus: gitStatus,
			}
			return s.rgRenderResult(fillHdr(hdr), rgSensitiveWithheldWarning(groups)), nil, nil
		}

		slug := slugifyRgPattern(args.Pattern, args.Glob)
		// Hash match body only: indexHeader embeds a wall-clock timestamp, so
		// hashing textToStore made identical searches miss the reuse window.
		// Hash is over truncated+tagged match text (the stored body).
		label, reused := s.rgIndexDedup(dedupKey, rawText, slug)
		if !reused {
			if ierr := s.storeIndexLocked(label, textToStore); ierr != nil {
				// Fallback on index failure: return raw match lines with context preserved
				slicedText := sliceGroupsWithContext(groups, limit)
				hdr := rgHeader{
					Engine:    engine,
					Matches:   totalHits,
					Files:     len(validGroups),
					Limit:     limit,
					Truncated: true,
					GitDirty:  gitDirtyCount,
					GitStatus: gitStatus,
				}
				return s.rgRenderResult(fillHdr(hdr), fmt.Sprintf("%s\n(indexing failed: %v, returning first %d matches)", slicedText, ierr, limit)), nil, nil
			}
		}

		summary := renderRgSummary(groups, totalHits, limit, label, args.Pattern, reused, truncated, budgetHit, matchRoot)
		hdr := rgHeader{
			Engine:    engine,
			Matches:   totalHits,
			Files:     len(validGroups),
			Limit:     limit,
			Truncated: truncated,
			GitDirty:  gitDirtyCount,
			GitStatus: gitStatus,
			Indexed:   label,
		}
		return s.rgRenderResult(fillHdr(hdr), summary), nil, nil
	}
}

// rgSensitiveWithheldWarning builds the warning returned in place of raw
// matched lines on every direct-return path of toolRg (<=limit results,
// offset pages, and >limit fallbacks). It names the files whose own lines
// trip checkSensitiveContent, so the caller can inspect those files
// through the gated read paths without ever seeing the matched lines.
func rgSensitiveWithheldWarning(groups []rgFileGroup) string {
	var hitFiles []string
	for _, g := range groups {
		if g.file == "" {
			continue
		}
		if gerr := checkSensitiveContent(strings.Join(g.lines, "\n")); gerr != nil {
			hitFiles = append(hitFiles, g.file)
		}
	}
	warning := "(sensitive content detected: matched lines withheld"
	if len(hitFiles) > 0 {
		warning += "; files: " + strings.Join(hitFiles, ", ")
	}
	warning += ")"
	return warning
}

// rgSystem keeps its historical single-context signature (tests call it
// directly): with no separate parent context, a DeadlineExceeded on ctx is
// attributed to the rg wall-clock budget exactly as before.
func (s *server) rgSystem(ctx context.Context, rgPath, root string, args rgArgs, fetchLimit, contextLines, fetchCapBytes int) (string, bool, int, error) {
	return s.rgSystemBounded(ctx, nil, rgPath, root, args, fetchLimit, contextLines, fetchCapBytes)
}

// rgBudgetKilled reports whether runErr means rg was SIGKILLed by this
// search's own wall-clock budget. A clean exit (rg finished, matched or not)
// is never a budget kill, and neither is a kill caused by the parent request
// being canceled or timed out. parentCtx == nil (legacy single-context
// callers) means the budget context is authoritative.
func rgBudgetKilled(budgetCtx, parentCtx context.Context, runErr error) bool {
	if runErr == nil {
		return false // rg completed on its own
	}
	var ee *exec.ExitError
	if !errors.As(runErr, &ee) || ee.ExitCode() != -1 {
		return false // exited with a real status, not killed by a signal
	}
	berr := budgetCtx.Err()
	if berr == nil || berr != context.DeadlineExceeded {
		return false
	}
	if parentCtx != nil && parentCtx.Err() != nil {
		return false // parent canceled/timed out: real cause is upstream
	}
	return true
}

// rgSystemBounded is rgSystem with the parent request context passed
// separately from the budget context, so a parent cancel/timeout is never
// mislabeled as an rg wall-clock budget hit (budget_exceeded).
func (s *server) rgSystemBounded(ctx, parentCtx context.Context, rgPath, root string, args rgArgs, fetchLimit, contextLines, fetchCapBytes int) (string, bool, int, error) {
	cmdArgs := []string{
		"--no-config",
		"--no-heading",
		"--with-filename",
		"--line-number",
		"--color", "never",
	}
	// Line-buffer stdout when a wall-clock budget may SIGKILL rg, so partial
	// hits are flushed instead of sitting in a pipe buffer and looking empty.
	if rgBudgetMs > 0 {
		cmdArgs = append(cmdArgs, "--line-buffered")
	}
	// Client glob goes BEFORE the built-in deny globs: ripgrep gives
	// precedence to the last --glob, so appending a client glob like
	// ".env*" after the deny block would re-include deny-listed files.
	if args.Glob != "" {
		cmdArgs = append(cmdArgs, "--glob", args.Glob)
	}
	cmdArgs = append(cmdArgs,
		"--hidden",
		"--glob", "!.git/**",
		"--glob", "!.git/*",
		"--glob", "!.git",
		"--glob", "!**/.git/**",
		"--glob", "!node_modules/**",
		"--glob", "!vendor/**",
		"--glob", "!.env*",
		"--glob", "!*.pem",
		"--glob", "!*.key",
		"--glob", "!*.p12",
		"--glob", "!*.pfx",
		"--glob", "!id_rsa*",
		"--glob", "!id_dsa*",
		"--glob", "!id_ecdsa*",
		"--glob", "!id_ed25519*",
		"--glob", "!.npmrc",
		"--glob", "!.netrc",
		"--glob", "!credentials*",
		"--glob", "!.aws/**",
		"--glob", "!.ssh/**",
		"--glob", "!.gnupg/**",
		"--glob", "!.kube/**",
		"-m", strconv.Itoa(fetchLimit),
	)
	if args.IgnoreCase {
		cmdArgs = append(cmdArgs, "-i")
	}
	if args.Literal {
		cmdArgs = append(cmdArgs, "-F")
	}
	if contextLines > 0 {
		cmdArgs = append(cmdArgs, "-C", strconv.Itoa(contextLines))
	}
	// Pattern and path last.
	cmdArgs = append(cmdArgs, "--", args.Pattern, root)

	cmd := exec.CommandContext(ctx, rgPath, cmdArgs...)
	// Strip sensitive inherited variables (same default as the execute path).
	cmd.Env = flattenEnv(childEnv(nil))
	var stdout limitedBuffer
	stdout.limit = fetchCapBytes
	var stderr limitedBuffer
	stderr.limit = 64 * 1024
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	// Classify the exit before deciding what to keep: only a kill caused by
	// this search's own budget deadline marks budget_exceeded; a parent
	// cancel/timeout surfaces as the real error instead.
	budgetKilled := rgBudgetKilled(ctx, parentCtx, err)
	parentDone := parentCtx != nil && parentCtx.Err() != nil
	if err != nil {
		if budgetKilled {
			// SIGKILLed at the wall-clock budget: keep partial stdout below.
		} else if parentDone {
			// Parent request canceled or timed out mid-search: propagate the
			// real cause instead of mislabeling it as a budget hit.
			return "", false, 0, parentCtx.Err()
		} else if ee, ok := err.(*exec.ExitError); ok {
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
	truncated := stdout.truncated
	if stdout.truncated && !strings.HasSuffix(stdout.String(), "\n") && len(lines) > 0 {
		// Discard incomplete trailing half-line
		lines = lines[:len(lines)-1]
	}

	var b strings.Builder
	matchCount := 0
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Match lines look like path:line:content or path-line-content (context).
		rewritten := s.rewriteRgLine(root, line)
		if strings.HasPrefix(rewritten, ".git/") || strings.HasPrefix(rewritten, "./.git/") || strings.Contains(rewritten, "/.git/") {
			continue
		}
		// Output-side fence: drop any result line whose file path is on the
		// sensitive-path deny list (defense in depth alongside the deny
		// globs and the explicit-path check; mirrors rgGo's per-file gate).
		if linePath, ok := rgLineFilePath(rewritten); ok && isSensitiveFilePath(linePath) {
			continue
		}
		// Count real matches (colon form with line number), not context separators.
		if isRgMatchLine(rewritten) {
			if matchCount >= fetchLimit {
				truncated = true
				break
			}
			matchCount++
		}
		if b.Len()+len(rewritten)+1 > fetchCapBytes {
			truncated = true
			break
		}
		b.WriteString(rewritten)
		b.WriteByte('\n')
	}
	if matchCount >= fetchLimit || stdout.truncated {
		truncated = true
	}
	out := strings.TrimRight(b.String(), "\n")
	if budgetKilled {
		return out, true, matchCount, errRgBudget
	}
	return out, truncated, matchCount, nil
}

func isRgMatchLine(line string) bool {
	_, _, ok := splitRgMatchLine(line)
	return ok
}

// rgLineFilePath extracts the file path from an rg output line, either the
// match form "path:line:content" or the context form "path-line-content".
// ok is false for separator lines like "--" that carry no path.
func rgLineFilePath(line string) (string, bool) {
	if p, _, ok := splitRgMatchLine(line); ok {
		return p, true
	}
	// Context form: find the first "-<digits>-" run so paths containing '-'
	// (e.g. "foo-bar.pem-12-x") still split correctly.
	for i := 0; i < len(line); i++ {
		if line[i] != '-' {
			continue
		}
		j := i + 1
		for j < len(line) && line[j] >= '0' && line[j] <= '9' {
			j++
		}
		if j > i+1 && j < len(line) && line[j] == '-' {
			return line[:i], true
		}
	}
	return "", false
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
				return rest
			}
			// root file itself: ".:n:..." doesn't make sense; use basename path
			return filepath.Base(root) + rest
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

// maxRgLineBytes is the explicit per-line resource cap for the pure-Go rg
// engine. It deliberately exceeds the 5MB per-file skip so every line of a
// regular file is searchable (the old 1MB bufio.Scanner cap failed the whole
// search on any longer line). Only pathological lines (e.g. via a symlink to
// a huge file) exceed it: those lines are skipped (drained, not accumulated)
// and the result is flagged truncated so incomplete coverage is never silent.
// Memory stays bounded at one line per file.
var maxRgLineBytes = 8 * 1024 * 1024 // 8 MB

// readRgLine reads one line (trailing newline/CR stripped) from br using
// bounded memory: chunks are accumulated up to maxBytes, then discarded.
// tooLong is true when the line exceeded maxBytes — the line is skipped
// entirely (its remainder drained) so the next call starts at the following
// line. io.EOF is returned only when no data remains.
func readRgLine(br *bufio.Reader, maxBytes int) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, rerr := br.ReadSlice('\n')
		if len(buf)+len(chunk) > maxBytes {
			tooLong = true
			// Drain the remainder of the oversized line without accumulating it.
			for rerr == bufio.ErrBufferFull {
				chunk, rerr = br.ReadSlice('\n')
			}
			return nil, true, nil
		}
		buf = append(buf, chunk...)
		if rerr == bufio.ErrBufferFull {
			continue
		}
		if rerr == io.EOF {
			if len(buf) == 0 {
				return nil, false, io.EOF
			}
			return trimRgLineEnd(buf), false, nil
		}
		return trimRgLineEnd(buf), false, nil
	}
}

// trimRgLineEnd strips the trailing newline (and optional CR) from a line.
func trimRgLineEnd(buf []byte) []byte {
	if len(buf) > 0 && buf[len(buf)-1] == '\n' {
		buf = buf[:len(buf)-1]
	}
	if len(buf) > 0 && buf[len(buf)-1] == '\r' {
		buf = buf[:len(buf)-1]
	}
	return buf
}

// rgGo keeps its historical signature (tests call it directly) and runs with
// the default CTXMODE_RG_BUDGET_MS wall-clock budget.
func (s *server) rgGo(ctx context.Context, root string, args rgArgs, fetchLimit, contextLines, fetchCapBytes int) (string, bool, int, error) {
	return s.rgGoBudget(ctx, rgBudgetMs, root, args, fetchLimit, contextLines, fetchCapBytes)
}

// rgGoBudget is rgGo with an explicit wall-clock budget in milliseconds
// (<= 0 disables), so a fallback after rgSystem can be charged only the
// remaining budget instead of a fresh full one.
func (s *server) rgGoBudget(ctx context.Context, budgetMs int, root string, args rgArgs, fetchLimit, contextLines, fetchCapBytes int) (string, bool, int, error) {
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
	stopped := false // walk halted by match limit / output cap (NOT by skipped lines)
	budgetStopped := false
	fileCount := 0
	start := time.Now()
	var budget time.Duration
	if budgetMs > 0 {
		budget = time.Duration(budgetMs) * time.Millisecond
	}
	gitignore := newGitignoreStack(root)

	walkErr := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		// Honour cancellation so long pure-Go walks do not outlive the request.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err != nil || stopped {
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
			relSlash := filepath.ToSlash(rel)
			for len(gitignore.layers) > 1 {
				base := gitignore.layers[len(gitignore.layers)-1].base
				if base == "." || relSlash == base || strings.HasPrefix(relSlash, base+"/") {
					break
				}
				gitignore.layers = gitignore.layers[:len(gitignore.layers)-1]
			}
			if rel != "." {
				gitignore.push(p, relSlash)
			}
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

		if isSensitiveFilePath(p) {
			return nil
		}
		// Wall-clock budget: check every 8th scanned file (fff-style throttle).
		// Unlike pi-fff, there is no "must have matched first" gate — zero-match
		// searches stop too.
		fileCount++
		if budget > 0 && fileCount%8 == 0 && time.Since(start) > budget {
			truncated = true
			budgetStopped = true
			return io.EOF
		}
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
		br := bufio.NewReaderSize(reader, 64*1024)

		display := s.displayPath(p)
		var ring []string // previous lines for context
		lineNo := 0
		pendingAfter := 0
		for {
			line, tooLong, rerr := readRgLine(br, maxRgLineBytes)
			if rerr != nil {
				if rerr == io.EOF {
					break
				}
				_ = f.Close()
				return rerr
			}
			lineNo++
			if tooLong {
				// Per-line resource cap hit: the line was drained and is skipped;
				// scanning continues with the following line (and other files).
				// Flag the result so incomplete coverage is not silent.
				truncated = true
				ring = ring[:0] // context window must not span the skipped line
				continue
			}
			sline := string(line)
			// Ensure valid display of possibly invalid UTF-8.
			if !utf8.ValidString(sline) {
				sline = strings.ToValidUTF8(sline, "\uFFFD")
			}
			matched := re.MatchString(sline)
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
				fmt.Fprintf(&b, "%s:%d:%s\n", display, lineNo, sline)
				matchCount++
				pendingAfter = contextLines
				if matchCount >= fetchLimit {
					truncated = true
					stopped = true
					_ = f.Close()
					return io.EOF // stop walk
				}
				if b.Len() > fetchCapBytes {
					truncated = true
					stopped = true
					_ = f.Close()
					return io.EOF
				}
			} else if pendingAfter > 0 {
				fmt.Fprintf(&b, "%s-%d-%s\n", display, lineNo, sline)
				pendingAfter--
			}
			if contextLines > 0 {
				ring = append(ring, sline)
				if len(ring) > contextLines {
					ring = ring[1:]
				}
			}
		}
		return f.Close()
	})
	if walkErr != nil && walkErr != io.EOF {
		return "", false, 0, walkErr
	}
	// Repos with fewer than 8 files never trip the %8 throttle; check once
	// more after the walk so a small tree is still wall-clock bounded.
	if budget > 0 && !budgetStopped && time.Since(start) > budget {
		truncated = true
		budgetStopped = true
	}
	out := strings.TrimRight(b.String(), "\n")
	if budgetStopped {
		return out, true, matchCount, errRgBudget
	}
	return out, truncated, matchCount, nil
}
