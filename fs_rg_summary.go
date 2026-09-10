package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var rgSummaryEnabled = envFlagDefaultOn("CTXMODE_RG_SUMMARY")

type rgIndexEntry struct {
	label     string
	hash      uint64
	createdAt time.Time
}

type rgFileGroup struct {
	file   string
	lines  []string
	hits   int
	dirty  bool
	gitTag string // porcelain short tag: M, A, ?? (empty = clean)
}

func fnv64a(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func isAllDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// splitRgMatchLine parses a line to determine if it is a match line of the form path:lineNum:content.
// It scans pairs of colons from left to right to find the first non-empty, all-digit segment between two colons.
// Known limitation: filenames containing an all-digit segment between colons (e.g. foo:12:bar.txt:1:...) may be ambiguous.
func splitRgMatchLine(line string) (path string, lineNum string, ok bool) {
	if line == "--" ||
		strings.HasPrefix(line, "# rg ") ||
		strings.HasPrefix(line, "# pattern=") ||
		strings.HasPrefix(line, "# indexed for ") {
		return "", "", false
	}
	c1 := -1
	for {
		nextC := strings.IndexByte(line[c1+1:], ':')
		if nextC < 0 {
			break
		}
		c := c1 + 1 + nextC
		if c1 >= 0 {
			seg := line[c1+1 : c]
			if isAllDigits(seg) {
				return line[:c1], seg, true
			}
		}
		c1 = c
	}
	return "", "", false
}

func slugifyRgPattern(pat, glob string) string {
	raw := pat
	if glob != "" {
		raw += "_" + glob
	}
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	res := b.String()
	if len(res) > 24 {
		res = res[:24]
	}
	return strings.Trim(res, "_")
}

// rgStableIndexLabel generates a deterministic label based on session, slug, and the FNV-64a hash of the stored text.
// Format: session:<sid>:rg:<slug>:<hash16hex> (or rg:<slug>:<hash16hex> when sessionID is empty).
// FNV-64a produces a 64-bit hash (collision probability ~ 1/(2^32) for ~5 billion items by birthday paradox, virtually zero within a single session).
func (s *server) rgStableIndexLabel(slug string, hash uint64) string {
	prefix := s.rgIndexPrefix()
	if slug != "" {
		return fmt.Sprintf("%s%s:%016x", prefix, slug, hash)
	}
	return fmt.Sprintf("%s%016x", prefix, hash)
}

func (s *server) rgIndexDedup(key, text, slug string) (label string, reused bool) {
	s.rgIndexMu.Lock()
	defer s.rgIndexMu.Unlock()

	if s.rgIndexDedupMap == nil {
		s.rgIndexDedupMap = make(map[string]rgIndexEntry)
	}

	h := fnv64a(text)
	now := time.Now()
	if s.gitStatusClock != nil {
		now = s.gitStatusClock()
	}

	if entry, ok := s.rgIndexDedupMap[key]; ok {
		if now.Sub(entry.createdAt) < 10*time.Minute && entry.hash == h {
			return entry.label, true
		}
	}

	if len(s.rgIndexDedupMap) >= 64 {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range s.rgIndexDedupMap {
			if first || v.createdAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.createdAt
				first = false
			}
		}
		if oldestKey != "" {
			delete(s.rgIndexDedupMap, oldestKey)
		}
	}

	label = s.rgStableIndexLabel(slug, h)
	s.rgIndexDedupMap[key] = rgIndexEntry{
		label:     label,
		hash:      h,
		createdAt: now,
	}
	return label, false
}

func (s *server) getRgIndexLabel(key string) string {
	s.rgIndexMu.Lock()
	defer s.rgIndexMu.Unlock()
	if s.rgIndexDedupMap == nil {
		return ""
	}
	if entry, ok := s.rgIndexDedupMap[key]; ok {
		return entry.label
	}
	return ""
}

func groupRgLines(lines []string) []rgFileGroup {
	var groups []rgFileGroup
	for _, line := range lines {
		if line == "" {
			continue
		}
		if path, _, ok := splitRgMatchLine(line); ok {
			if len(groups) == 0 || groups[len(groups)-1].file != path {
				groups = append(groups, rgFileGroup{file: path})
			}
			last := &groups[len(groups)-1]
			last.lines = append(last.lines, line)
			last.hits++
		} else {
			// context line or separator line like "--"
			if len(groups) == 0 {
				filePath := ""
				if line != "--" {
					if dashIdx := strings.IndexByte(line, '-'); dashIdx > 0 {
						filePath = line[:dashIdx]
					}
				}
				groups = append(groups, rgFileGroup{file: filePath})
			}
			last := &groups[len(groups)-1]
			last.lines = append(last.lines, line)
		}
	}
	return groups
}

func renderGroups(groups []rgFileGroup) string {
	var totalLines int
	for _, g := range groups {
		totalLines += len(g.lines)
	}
	if totalLines == 0 {
		return ""
	}
	var b strings.Builder
	for i, g := range groups {
		for j, line := range g.lines {
			b.WriteString(line)
			if i < len(groups)-1 || j < len(g.lines)-1 {
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

func sliceGroupsWithContext(groups []rgFileGroup, limit int) string {
	if limit <= 0 {
		return ""
	}
	var resLines []string
	remainingLimit := limit
	for _, g := range groups {
		if remainingLimit <= 0 {
			break
		}
		if g.hits == 0 {
			continue
		}
		if g.hits <= remainingLimit {
			resLines = append(resLines, g.lines...)
			remainingLimit -= g.hits
		} else {
			hitCount := 0
			for _, line := range g.lines {
				if isRgMatchLine(line) {
					hitCount++
					if hitCount > remainingLimit {
						break
					}
					resLines = append(resLines, line)
				} else {
					if hitCount == remainingLimit && line == "--" {
						break
					}
					if hitCount <= remainingLimit {
						resLines = append(resLines, line)
					}
				}
			}
			remainingLimit = 0
			break
		}
	}
	return strings.Join(resLines, "\n")
}

func sliceMatchLines(groups []rgFileGroup, offset, limit int) string {
	var matchLines []string
	for _, g := range groups {
		for _, line := range g.lines {
			if isRgMatchLine(line) {
				matchLines = append(matchLines, line)
			}
		}
	}
	if offset >= len(matchLines) {
		return ""
	}
	end := offset + limit
	if end > len(matchLines) {
		end = len(matchLines)
	}
	return strings.Join(matchLines[offset:end], "\n")
}

func indexHeader(pattern, root, glob string, totalHits int, partial bool) string {
	ts := time.Now().UTC().Format(time.RFC3339)
	var b strings.Builder
	fmt.Fprintf(&b, "# rg pattern=%q root=%q glob=%q matches=%d timestamp=%s\n", pattern, root, glob, totalHits, ts)
	if partial {
		b.WriteString("# partial=true\n")
	}
	b.WriteString("# indexed for ctx_fs action=rg\n---\n")
	return b.String()
}

func renderRgSummary(groups []rgFileGroup, totalHits, limit int, label, pattern string, reused, truncated, budgetHit bool, root string) string {
	var b strings.Builder

	indexedTag := "full set indexed"
	switch {
	case budgetHit:
		indexedTag = "partial set indexed (budget exceeded)"
		if reused {
			indexedTag = "partial set indexed (budget exceeded) (reused)"
		}
	case truncated:
		indexedTag = "capture truncated at 200KB / 500-match cap"
		if reused {
			indexedTag = "capture truncated at 200KB / 500-match cap (reused)"
		}
	default:
		if reused {
			indexedTag = "full set indexed (reused)"
		}
	}

	var summaryGroups []rgFileGroup
	for _, g := range groups {
		if g.hits > 0 {
			summaryGroups = append(summaryGroups, g)
		}
	}

	sort.SliceStable(summaryGroups, func(i, j int) bool {
		if summaryGroups[i].dirty != summaryGroups[j].dirty {
			return summaryGroups[i].dirty
		}
		if summaryGroups[i].hits != summaryGroups[j].hits {
			return summaryGroups[i].hits > summaryGroups[j].hits
		}
		return false
	})

	if p, isDef, ok := rgReadHint(summaryGroups); ok {
		b.WriteString(formatReadHint(p, isDef, root))
		b.WriteByte('\n')
	}

	if budgetHit {
		fmt.Fprintf(&b, "%d matches in %d files (%s, > first-screen limit %d). Retrieve details: ctx_kb action=search query=%q scope=rg\n",
			totalHits, len(summaryGroups), indexedTag, limit, label)
	} else {
		fmt.Fprintf(&b, "%d matches in %d files (%s, > first-screen limit %d). Retrieve details: ctx_kb action=search query=%q scope=rg or page raw lines: ctx_fs action=rg pattern=%q offset=%d\n",
			totalHits, len(summaryGroups), indexedTag, limit, label, pattern, limit)
	}
	b.WriteString("Files (M=modified, A=added, ??=untracked; then by match count):\n")

	maxFiles := 25
	shownCount := len(summaryGroups)
	if shownCount > maxFiles {
		shownCount = maxFiles
	}

	for i := 0; i < shownCount; i++ {
		g := summaryGroups[i]
		matchStr := "matches"
		if g.hits == 1 {
			matchStr = "match"
		}
		prefix := ""
		if g.gitTag != "" {
			prefix = g.gitTag + " "
		} else if g.dirty {
			prefix = "* "
		}
		fmt.Fprintf(&b, "%s%s %d %s%s\n", prefix, g.file, g.hits, matchStr, rgFileSizeTag(root, g.file))

		var matchPreviews []string
		for _, line := range g.lines {
			if path, lineNo, ok := splitRgMatchLine(line); ok {
				prefixLen := len(path) + 1 + len(lineNo) + 1
				content := ""
				if len(line) >= prefixLen {
					content = line[prefixLen:]
				}
				matchPreviews = append(matchPreviews, fmt.Sprintf("  %s: %s", lineNo, strings.TrimLeft(content, " \t")))
				if len(matchPreviews) == 2 {
					break
				}
			}
		}

		for _, prev := range matchPreviews {
			b.WriteString(prev)
			b.WriteByte('\n')
		}
		if g.hits > len(matchPreviews) {
			fmt.Fprintf(&b, "  ... (+%d more)\n", g.hits-len(matchPreviews))
		}
	}

	if len(summaryGroups) > maxFiles {
		fmt.Fprintf(&b, "... (+%d more files)\n", len(summaryGroups)-maxFiles)
	}

	res := strings.TrimRight(b.String(), "\n")
	if len(res) > 4096 {
		res = truncateUTF8(res, 4096)
	}
	return res
}

// ---------- definition-line heuristic, match-line truncation, Read hint ----------

// rgMaxLineRunes caps match-line content (UTF-8 runes) on the toolRg path.
// Default 500; CTXMODE_RG_MAX_LINE_RUNES overrides; <=0 disables truncation.
var rgMaxLineRunes = envIntDefault("CTXMODE_RG_MAX_LINE_RUNES", 500)

// rgLargeFileBytes is the summary size-tag threshold: 20KiB = 20*1024 bytes.
const rgLargeFileBytes = 20 * 1024

var rgDefModifiers = []string{
	"pub", "export", "default", "async", "abstract", "unsafe",
	"static", "protected", "private", "public",
}

var rgDefKeywords = []string{
	"struct", "fn", "enum", "trait", "impl", "class", "interface",
	"function", "def", "func", "type", "module", "object",
}

func isIdentStart(s string) bool {
	if s == "" {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s)
	return r == '_' || r == '$' || unicode.IsLetter(r)
}

func skipDefModifiers(s string) string {
	for {
		s = strings.TrimLeft(s, " \t")
		if strings.HasPrefix(s, "pub(") {
			end := strings.IndexByte(s, ')')
			if end < 0 {
				return s
			}
			s = s[end+1:]
			continue
		}
		matched := false
		for _, kw := range rgDefModifiers {
			if strings.HasPrefix(s, kw) {
				rest := s[len(kw):]
				if rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
					s = rest
					matched = true
					break
				}
			}
		}
		if !matched {
			return s
		}
	}
}

// isDefinitionLine reports whether a matched line looks like a code definition.
// Tightened vs the pi-fff POC: the definition keyword must be followed by
// whitespace and then an identifier-class character, so `type(x)`, `object.foo`,
// and `interface{}` are not tagged (prefer miss over false positive).
func isDefinitionLine(line string) bool {
	s := skipDefModifiers(strings.TrimLeft(line, " \t"))
	s = strings.TrimLeft(s, " \t")
	for _, kw := range rgDefKeywords {
		if !strings.HasPrefix(s, kw) {
			continue
		}
		rest := s[len(kw):]
		if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
			continue
		}
		rest = strings.TrimLeft(rest, " \t")
		if isIdentStart(rest) {
			return true
		}
		// Go methods: `func (s *T) M(...)` — only on this line-start keyword
		// path, and only for `func`, so `type (x)` stays untagged.
		if kw == "func" && strings.HasPrefix(rest, "(") {
			return true
		}
	}
	return false
}

// truncateRgMatchLine caps match-line content at rgMaxLineRunes (UTF-8 safe)
// with a "..." marker, mirroring pi-fff GREP_MAX_LINE_LENGTH. No-op when the
// cap is <=0 (disabled via CTXMODE_RG_MAX_LINE_RUNES).
func truncateRgMatchLine(content string) string {
	if rgMaxLineRunes <= 0 || utf8.RuneCountInString(content) <= rgMaxLineRunes {
		return content
	}
	var b strings.Builder
	n := 0
	for _, r := range content {
		if n == rgMaxLineRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String() + "..."
}

// prepareRgGroups optionally truncates match-line content (CTXMODE_RG_MAX_LINE_RUNES,
// default 500, <=0 disables) and, when the rg summary feature is on, prefixes
// definition lines with "[def] ". Applied before indexing so tags/truncation
// flow into ctx_kb.
func prepareRgGroups(groups []rgFileGroup) {
	for i := range groups {
		for j, line := range groups[i].lines {
			path, lineNo, ok := splitRgMatchLine(line)
			if !ok {
				continue
			}
			prefixLen := len(path) + 1 + len(lineNo) + 1
			if len(line) < prefixLen {
				continue
			}
			content := line[prefixLen:]
			tagged := rgSummaryEnabled && isDefinitionLine(content)
			if rgMaxLineRunes > 0 {
				content = truncateRgMatchLine(content)
			}
			if tagged {
				content = "[def] " + content
			}
			groups[i].lines[j] = line[:prefixLen] + content
		}
	}
}

func groupHasDef(g rgFileGroup) bool {
	for _, line := range g.lines {
		path, lineNo, ok := splitRgMatchLine(line)
		if !ok {
			continue
		}
		prefixLen := len(path) + 1 + len(lineNo) + 1
		if len(line) >= prefixLen && strings.HasPrefix(line[prefixLen:], "[def] ") {
			return true
		}
	}
	return false
}

// rgReadHint picks the first group (in the existing order) that contains a
// definition line, else the first group with matches. Does not reorder lines.
func rgReadHint(groups []rgFileGroup) (path string, isDef bool, ok bool) {
	var first string
	for _, g := range groups {
		if g.hits == 0 || g.file == "" {
			continue
		}
		if first == "" {
			first = g.file
		}
		if groupHasDef(g) {
			return g.file, true, true
		}
	}
	if first == "" {
		return "", false, false
	}
	return first, false, true
}

func rgFileSizeTag(root, file string) string {
	if file == "" {
		return ""
	}
	abs := rgGroupAbsPath(root, file)
	fi, err := os.Stat(abs)
	if err != nil {
		return ""
	}
	if fi.Size() < rgLargeFileBytes {
		return ""
	}
	kb := (fi.Size() + 512) / 1024
	return fmt.Sprintf(" (%dKB - use offset to read relevant section)", kb)
}

func formatReadHint(path string, isDef bool, root string) string {
	s := "→ Read " + path
	if isDef {
		s += " [def]"
	}
	s += rgFileSizeTag(root, path)
	return s
}

func prependReadHint(body string, groups []rgFileGroup, root string) string {
	p, isDef, ok := rgReadHint(groups)
	if !ok {
		return body
	}
	hint := formatReadHint(p, isDef, root)
	if body == "" {
		return hint
	}
	return hint + "\n" + body
}
