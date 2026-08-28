package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

var rgSummaryEnabled = envFlagDefaultOn("CTXMODE_RG_SUMMARY")

type rgIndexEntry struct {
	label     string
	hash      uint64
	createdAt time.Time
}

type rgFileGroup struct {
	file  string
	lines []string
	hits  int
	dirty bool
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

func indexHeader(pattern, root, glob string, totalHits int) string {
	ts := time.Now().UTC().Format(time.RFC3339)
	return fmt.Sprintf("# rg pattern=%q root=%q glob=%q matches=%d timestamp=%s\n# indexed for ctx_fs action=rg\n---\n", pattern, root, glob, totalHits, ts)
}

func renderRgSummary(groups []rgFileGroup, totalHits, limit int, label, pattern string, reused, truncated bool) string {
	var b strings.Builder

	indexedTag := "full set indexed"
	if truncated {
		indexedTag = "capture truncated at 200KB / 500-match cap"
		if reused {
			indexedTag = "capture truncated at 200KB / 500-match cap (reused)"
		}
	} else if reused {
		indexedTag = "full set indexed (reused)"
	}

	var summaryGroups []rgFileGroup
	for _, g := range groups {
		if g.hits > 0 {
			summaryGroups = append(summaryGroups, g)
		}
	}

	fmt.Fprintf(&b, "%d matches in %d files (%s, > first-screen limit %d). Retrieve details: ctx_kb action=search query=%q scope=rg or page raw lines: ctx_fs action=rg pattern=%q offset=%d\n",
		totalHits, len(summaryGroups), indexedTag, limit, label, pattern, limit)
	b.WriteString("Files (* = git modified/staged/untracked, then by match count):\n")

	sort.SliceStable(summaryGroups, func(i, j int) bool {
		if summaryGroups[i].dirty != summaryGroups[j].dirty {
			return summaryGroups[i].dirty
		}
		if summaryGroups[i].hits != summaryGroups[j].hits {
			return summaryGroups[i].hits > summaryGroups[j].hits
		}
		return false
	})

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
		if g.dirty {
			prefix = "* "
		}
		fmt.Fprintf(&b, "%s%s %d %s\n", prefix, g.file, g.hits, matchStr)

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
