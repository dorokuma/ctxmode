package main

// Fuzzy path resolution and related-file ranking for ctx_fs, ported from the
// pi-fff extension's resolve_file / related_files tools (ShpetimA/pi-fff).
// Pure Go: no fff-node dependency. Both actions walk the workspace with the
// same gitignore + symlink fences as glob (fs_tools.go).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	resolveScanBudget = 5 * time.Second
	resolveMaxFiles   = 100000
)

// ---------- fuzzy scoring ----------

// fuzzyScore scores target against query (both normalized). Higher is better;
// ok=false means no match. Tiers: exact path/basename match > suffix > basename
// substring > path substring > in-order subsequence. Within a tier, matches
// closer to the basename and longer relative to the target score higher.
func fuzzyScore(query, target string) (float64, bool) {
	q := normalizeFuzzy(query)
	t := normalizeFuzzy(target)
	if q == "" || t == "" {
		return 0, false
	}
	if q == t {
		return 100, true
	}
	base := filepath.Base(t)
	if q == base {
		return 95, true
	}
	if strings.HasSuffix(t, q) || strings.HasSuffix(base, q) {
		return 85 + float64(len(q))/float64(len(t)), true
	}
	if idx := strings.Index(base, q); idx >= 0 {
		score := 70.0
		if idx == 0 || isFuzzyBoundaryByte(base, idx) {
			score += 8
		}
		return score + float64(len(q))/float64(len(t)), true
	}
	if idx := strings.Index(t, q); idx >= 0 {
		score := 55.0
		if idx == 0 || isFuzzyBoundaryByte(t, idx) {
			score += 6
		}
		return score + float64(len(q))/float64(len(t)), true
	}
	return subsequenceScore(q, t)
}

// subsequenceScore matches query as an in-order subsequence of target,
// rewarding contiguous runs and boundary anchors. Scattered hits over a long
// span sink below the substring tiers, so a short query cannot match nearly
// every path and drown meaningful results.
func subsequenceScore(q, t string) (float64, bool) {
	runes := []rune(t)
	qr := []rune(q)
	if len(qr) > len(runes) {
		return 0, false
	}
	score := 0.0
	run := 0
	ti := 0
	for _, qc := range qr {
		found := -1
		for ; ti < len(runes); ti++ {
			if runes[ti] == qc {
				found = ti
				ti++
				break
			}
		}
		if found < 0 {
			return 0, false
		}
		if found > 0 && isFuzzyBoundaryRune(runes, found) {
			score += 3
			run = 0
		}
		run++
		if run > 1 {
			score += float64(run)
		}
	}
	span := ti
	return score * float64(len(q)) / float64(span+1), true
}

func isFuzzyBoundaryByte(s string, idx int) bool {
	r := rune(s[idx])
	return r == '/' || r == '_' || r == '-' || r == '.'
}

func isFuzzyBoundaryRune(runes []rune, idx int) bool {
	if idx <= 0 {
		return true
	}
	r := runes[idx]
	return r == '/' || r == '_' || r == '-' || r == '.' || unicode.IsSpace(r)
}

func normalizeFuzzy(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsUpper(r):
			return unicode.ToLower(r)
		case r == '\\':
			return '/'
		case unicode.IsSpace(r):
			return -1
		}
		return r
	}, s)
}

// ---------- workspace scan ----------

// scanWorkspaceFiles walks every workdir (or the workdir containing root) and
// calls fn with each regular file's absolute path. It stops on ctx
// cancellation, the wall-clock budget, or the file cap, and reuses the glob
// walk's fences: skipWalkDirs, .gitignore layers, symlink fencing, and the
// sensitive-path gate. The bool result reports that the budget or the cap cut
// the walk short: the caller holds a partial result, not a complete one, and
// surfaces it as `truncated` rather than as an error.
func (s *server) scanWorkspaceFiles(ctx context.Context, root string, fn func(p string)) (bool, error) {
	deadline := time.Now().Add(resolveScanBudget)
	maxFiles := resolveMaxFiles
	if s.scanMaxFilesOverride > 0 {
		maxFiles = s.scanMaxFilesOverride
	}
	seen := 0
	truncated := false
	for _, wd := range s.workdirs {
		scanRoot := wd
		if root != "" {
			if root != wd && !strings.HasPrefix(root, wd+string(filepath.Separator)) {
				continue
			}
			scanRoot = root
		}
		gitignore := newGitignoreStack(scanRoot)
		err := filepath.Walk(scanRoot, func(p string, fi os.FileInfo, walkErr error) error {
			if seen >= maxFiles || time.Now().After(deadline) {
				// filepath.Walk swallows SkipAll and returns nil, so
				// record the early stop for the caller here.
				truncated = true
				return filepath.SkipAll
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if walkErr != nil {
				return nil
			}
			name := fi.Name()
			if fi.IsDir() && skipWalkDirs[name] {
				return filepath.SkipDir
			}
			if _, rerr := s.ensureInsideWorkspaces(p); rerr != nil {
				if fi.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if isSensitiveFilePath(p) {
				return nil
			}
			rel, err := filepath.Rel(scanRoot, p)
			if err != nil {
				return nil
			}
			relSlash := filepath.ToSlash(rel)
			for len(gitignore.layers) > 1 {
				gbase := gitignore.layers[len(gitignore.layers)-1].base
				if gbase == "." || relSlash == gbase || strings.HasPrefix(relSlash, gbase+"/") {
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
			if !fi.IsDir() && fi.Mode().IsRegular() {
				seen++
				fn(p)
			}
			return nil
		})
		if err != nil {
			return truncated, err
		}
		if truncated {
			// Budget or cap exhausted: walking the remaining workdirs
			// cannot add anything.
			return true, nil
		}
	}
	return truncated, nil
}

// ---------- action=resolve ----------

type resolveArgs struct {
	Path  string `json:"path"`
	Limit int    `json:"limit,omitempty"`
}

type resolveHit struct {
	Path  string  `json:"path"`
	Score float64 `json:"score"`
}

func (s *server) toolResolve(ctx context.Context, _ *mcp.CallToolRequest, args resolveArgs) (*mcp.CallToolResult, any, error) {
	query := strings.TrimSpace(args.Path)
	if query == "" {
		return nil, nil, fmt.Errorf("path is required (approximate file path to resolve)")
	}
	// pi-fff accepts "@path" style references and quoted paths.
	query = strings.TrimPrefix(query, "@")
	query = strings.Trim(query, `"'`)
	limit := args.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > fsHardLimit {
		return nil, nil, fmt.Errorf("invalid limit %d: exceeds maximum %d", limit, fsHardLimit)
	}

	var hits []resolveHit
	scanTruncated, err := s.scanWorkspaceFiles(ctx, "", func(p string) {
		score, ok := fuzzyScore(query, p)
		if !ok {
			return
		}
		hits = append(hits, resolveHit{Path: s.displayPath(p), Score: roundScore(score)})
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return len(hits[i].Path) < len(hits[j].Path)
	})
	truncated := scanTruncated
	if len(hits) > limit {
		hits = hits[:limit]
		truncated = true
	}
	if hits == nil {
		hits = []resolveHit{}
	}
	out, err := json.MarshalIndent(map[string]any{
		"query":     query,
		"count":     len(hits),
		"truncated": truncated,
		"matches":   hits,
	}, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

func roundScore(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// ---------- action=related ----------

type relatedArgs struct {
	Path  string `json:"path"`
	Limit int    `json:"limit,omitempty"`
}

type relatedHit struct {
	Path   string  `json:"path"`
	Score  float64 `json:"score"`
	Reason string  `json:"reason"`
}

// relatedPairRules maps an extension to the extensions of the same language
// family; same-stem files inside one family are the strongest relation.
var relatedPairRules = map[string][]string{
	".go":   {".go"},
	".ts":   {".ts", ".tsx"},
	".tsx":  {".tsx", ".ts"},
	".js":   {".js", ".jsx"},
	".jsx":  {".jsx", ".js"},
	".py":   {".py"},
	".rs":   {".rs"},
	".c":    {".c", ".h"},
	".h":    {".h", ".c"},
	".cpp":  {".cpp", ".cc", ".cxx", ".hpp", ".h"},
	".cc":   {".cc", ".cpp", ".hpp", ".h"},
	".cxx":  {".cxx", ".cpp", ".hpp", ".h"},
	".hpp":  {".hpp", ".cpp", ".cc", ".cxx"},
	".java": {".java"},
}

func (s *server) toolRelated(ctx context.Context, _ *mcp.CallToolRequest, args relatedArgs) (*mcp.CallToolResult, any, error) {
	target := strings.TrimSpace(args.Path)
	if target == "" {
		return nil, nil, fmt.Errorf("path is required (file to find related files for)")
	}
	limit := args.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > fsHardLimit {
		return nil, nil, fmt.Errorf("invalid limit %d: exceeds maximum %d", limit, fsHardLimit)
	}
	abs, err := s.resolvePath(target)
	if err != nil {
		return nil, nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("path %q not found: %w", target, err)
	}
	if st.IsDir() {
		return nil, nil, fmt.Errorf("path %q is a directory; related files need a file", target)
	}
	targetDir := filepath.Dir(abs)
	targetStem, targetExt := splitStemExt(filepath.Base(abs))
	// Strip the test suffix so foo.go and foo_test.go pair up; isTestName on
	// the stripped stem says whether the target itself is a test.
	targetIsTest := isTestName(targetStem, targetExt)
	targetPairStem := pairStem(targetStem, targetExt)
	pairExts := relatedPairRules[strings.ToLower(targetExt)]
	rootOf := workspaceRootOf(abs, s.workdirs)

	var hits []relatedHit
	scanTruncated, err := s.scanWorkspaceFiles(ctx, rootOf, func(p string) {
		if p == abs {
			return
		}
		base := filepath.Base(p)
		stem, ext := splitStemExt(base)
		stemPair := pairStem(stem, ext)
		dir := filepath.Dir(p)
		var hit relatedHit
		// Tiers are checked in descending score order, so the same-directory
		// sibling tier (40) has to precede the stem-prefix tier (30): a
		// same-directory file whose stem is also a >= 4 char prefix of the
		// target's stem would otherwise never reach the sibling tier.
		switch {
		case stemPair == targetPairStem && extIn(ext, pairExts) && isTestName(stem, ext) != targetIsTest:
			hit = relatedHit{Path: s.displayPath(p), Score: 100, Reason: "test/impl pair with " + base}
		case stemPair == targetPairStem && extIn(ext, pairExts):
			hit = relatedHit{Path: s.displayPath(p), Score: 90, Reason: "same stem (" + targetExt + " ↔ " + ext + ")"}
		case stemPair == targetPairStem:
			hit = relatedHit{Path: s.displayPath(p), Score: 70, Reason: "same stem, other extension"}
		case dir == targetDir:
			hit = relatedHit{Path: s.displayPath(p), Score: 40, Reason: "sibling in " + s.displayPath(dir)}
		case stemStartsWith(stemPair, targetPairStem) || stemStartsWith(targetPairStem, stemPair):
			hit = relatedHit{Path: s.displayPath(p), Score: 30, Reason: "stem prefix match"}
		}
		if hit.Path != "" {
			hits = append(hits, hit)
		}
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Path < hits[j].Path
	})
	truncated := scanTruncated
	if len(hits) > limit {
		hits = hits[:limit]
		truncated = true
	}
	if hits == nil {
		hits = []relatedHit{}
	}
	out, err := json.MarshalIndent(map[string]any{
		"target":    s.displayPath(abs),
		"count":     len(hits),
		"truncated": truncated,
		"related":   hits,
	}, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(out)}}}, nil, nil
}

// splitStemExt splits "foo.test.go" into stem "foo.test" and ext ".go".
func splitStemExt(name string) (string, string) {
	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext), ext
}

// isTestName reports whether stem+ext looks like a test file. Python tests
// prefix (test_foo.py); Go/JS-style tests suffix (_test.go, foo.test.ts).
func isTestName(stem, ext string) bool {
	switch strings.ToLower(ext) {
	case ".go", ".py":
		return strings.HasSuffix(stem, "_test") || (strings.EqualFold(ext, ".py") && strings.HasPrefix(stem, "test_"))
	case ".ts", ".tsx", ".js", ".jsx", ".rs":
		lower := strings.ToLower(stem)
		return strings.HasSuffix(lower, ".test") || strings.HasSuffix(lower, ".spec")
	}
	return false
}

// pairStem strips the test marker so impl and test compare equal: foo_test.go,
// foo.test.ts and test_foo.py all reduce to foo.
func pairStem(stem, ext string) string {
	if isTestName(stem, ext) {
		lower := strings.ToLower(stem)
		for _, suffix := range []string{"_test", ".test", ".spec"} {
			if strings.HasSuffix(lower, suffix) {
				return stem[:len(stem)-len(suffix)]
			}
		}
		if strings.HasPrefix(lower, "test_") {
			return stem[len("test_"):]
		}
	}
	return stem
}

func extIn(ext string, exts []string) bool {
	for _, e := range exts {
		if ext == e {
			return true
		}
	}
	return false
}

func stemStartsWith(stem, prefix string) bool {
	return len(stem) >= 4 && len(prefix) >= 4 && strings.HasPrefix(stem, prefix)
}

// workspaceRootOf returns the workdir containing abs, or "" when none does.
func workspaceRootOf(abs string, workdirs []string) string {
	for _, wd := range workdirs {
		if abs == wd || strings.HasPrefix(abs, wd+string(filepath.Separator)) {
			return wd
		}
	}
	return ""
}
