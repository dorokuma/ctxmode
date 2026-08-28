package main

import (
	"strings"
)

type rgFileGroup struct {
	file  string
	lines []string
	hits  int
	dirty bool
}

func groupRgLines(lines []string) []rgFileGroup {
	var groups []rgFileGroup
	for _, line := range lines {
		if line == "" {
			continue
		}
		if isRgMatchLine(line) {
			colonIdx := strings.IndexByte(line, ':')
			filePath := line[:colonIdx]
			if len(groups) == 0 || groups[len(groups)-1].file != filePath {
				groups = append(groups, rgFileGroup{file: filePath})
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
