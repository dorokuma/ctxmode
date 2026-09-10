package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var rgGitRankEnabled = envFlagDefaultOn("CTXMODE_RG_GIT_RANK")

const gitDirtyTTL = 3 * time.Second

type gitDirtyEntry struct {
	dirty     map[string]struct{}
	tags      map[string]string
	isGit     bool
	expiresAt time.Time
}

func envFlagDefaultOn(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return true
	}
	return v != "0" && strings.ToLower(v) != "false" && strings.ToLower(v) != "off"
}

func (s *server) gitNow() time.Time {
	if s != nil && s.gitStatusClock != nil {
		return s.gitStatusClock()
	}
	return time.Now()
}

// porcelainTagFromXY maps git status --porcelain=v1 XY codes to a single
// short label. Priority: modified (M) > added (A) > untracked (??).
func porcelainTagFromXY(x, y byte) string {
	if x == '?' && y == '?' {
		return "??"
	}
	// Index or worktree modification (and similar tracked changes) wins.
	if x == 'M' || y == 'M' || x == 'T' || y == 'T' || x == 'U' || y == 'U' || x == 'D' || y == 'D' {
		return "M"
	}
	if x == 'A' || x == 'R' || x == 'C' || y == 'A' {
		return "A"
	}
	if x != ' ' || y != ' ' {
		return "M"
	}
	return ""
}

func parsePorcelainZFull(data []byte, toplevel string) (map[string]struct{}, map[string]string) {
	dirty := make(map[string]struct{})
	tags := make(map[string]string)
	parts := bytes.Split(data, []byte{0})
	for i := 0; i < len(parts); i++ {
		part := parts[i]
		if len(part) < 4 {
			continue
		}
		x := part[0]
		y := part[1]
		pathStr := string(part[3:])
		if pathStr != "" {
			abs := filepath.Clean(filepath.Join(toplevel, pathStr))
			dirty[abs] = struct{}{}
			if tag := porcelainTagFromXY(x, y); tag != "" {
				tags[abs] = tag
			}
		}
		if x == 'R' || x == 'C' || y == 'R' || y == 'C' {
			// next item is the orig path, consume it
			i++
		}
	}
	return dirty, tags
}

func parsePorcelainZ(data []byte, toplevel string) map[string]struct{} {
	dirty, _ := parsePorcelainZFull(data, toplevel)
	return dirty
}

func (s *server) gitDirtyFiles(ctx context.Context, root string) (map[string]struct{}, string) {
	dirty, _, status := s.gitDirtyState(ctx, root)
	return dirty, status
}

func (s *server) gitDirtyState(ctx context.Context, root string) (map[string]struct{}, map[string]string, string) {
	if !rgGitRankEnabled {
		return nil, nil, "disabled"
	}
	if s == nil {
		return nil, nil, "none"
	}

	cleanRoot := filepath.Clean(root)
	now := s.gitNow()

	s.gitDirtyMu.Lock()
	if s.gitDirtyCache == nil {
		s.gitDirtyCache = make(map[string]gitDirtyEntry)
	}
	if entry, ok := s.gitDirtyCache[cleanRoot]; ok && now.Before(entry.expiresAt) {
		s.gitDirtyMu.Unlock()
		if !entry.isGit {
			return nil, nil, "none"
		}
		return entry.dirty, entry.tags, "ok"
	}
	s.gitDirtyMu.Unlock()

	// Perform git probe under an isolated 2s timeout.
	gctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	run := s.runGitIn
	if s.gitDirtyRunner != nil {
		run = s.gitDirtyRunner
	}

	fail := func() (map[string]struct{}, map[string]string, string) {
		s.gitDirtyMu.Lock()
		s.gitDirtyCache[cleanRoot] = gitDirtyEntry{
			dirty:     nil,
			tags:      nil,
			isGit:     false,
			expiresAt: now.Add(gitDirtyTTL),
		}
		s.gitDirtyMu.Unlock()
		return nil, nil, "none"
	}

	if _, err := exec.LookPath("git"); err != nil {
		return fail()
	}

	toplevel, err := s.ensureGitToplevelInside(gctx, cleanRoot)
	if err != nil {
		return fail()
	}

	out, err := run(gctx, cleanRoot, "status", "--porcelain=v1", "-uall", "-z")
	if err != nil {
		return fail()
	}

	// Porcelain paths are always relative to the true toplevel, never to the
	// search root (which may be a subdirectory). Join against toplevel so dirty
	// keys are real absolute paths and match glob abs paths / workdir-relative
	// rg match lines inverted via displayPathBase.
	dirty, tags := parsePorcelainZFull([]byte(out), toplevel)

	s.gitDirtyMu.Lock()
	s.gitDirtyCache[cleanRoot] = gitDirtyEntry{
		dirty:     dirty,
		tags:      tags,
		isGit:     true,
		expiresAt: now.Add(gitDirtyTTL),
	}
	s.gitDirtyMu.Unlock()

	return dirty, tags, "ok"
}

func rgGroupAbsPath(root, file string) string {
	if filepath.IsAbs(file) {
		return filepath.Clean(file)
	}
	return filepath.Clean(filepath.Join(root, file))
}

func rankGroups(groups []rgFileGroup, dirty map[string]struct{}, root string) {
	if len(groups) == 0 {
		return
	}
	for i := range groups {
		if _, ok := dirty[rgGroupAbsPath(root, groups[i].file)]; ok {
			groups[i].dirty = true
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].dirty != groups[j].dirty {
			return groups[i].dirty
		}
		return false
	})
}

func tagGroups(groups []rgFileGroup, tags map[string]string, root string) {
	if len(groups) == 0 || len(tags) == 0 {
		return
	}
	for i := range groups {
		if t, ok := tags[rgGroupAbsPath(root, groups[i].file)]; ok {
			groups[i].gitTag = t
		}
	}
}
