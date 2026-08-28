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

func parsePorcelainZ(data []byte, toplevel string) map[string]struct{} {
	dirty := make(map[string]struct{})
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
			abs := filepath.Join(toplevel, pathStr)
			dirty[filepath.Clean(abs)] = struct{}{}
		}
		if x == 'R' || x == 'C' || y == 'R' || y == 'C' {
			// next item is the orig path, consume it
			i++
		}
	}
	return dirty
}

func (s *server) gitDirtyFiles(ctx context.Context, root string) (map[string]struct{}, string) {
	if !rgGitRankEnabled {
		return nil, "disabled"
	}
	if s == nil {
		return nil, "none"
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
			return nil, "none"
		}
		return entry.dirty, "ok"
	}
	s.gitDirtyMu.Unlock()

	// Perform git probe under an isolated 2s timeout.
	gctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	run := s.runGitIn
	if s.gitDirtyRunner != nil {
		run = s.gitDirtyRunner
	}

	fail := func() (map[string]struct{}, string) {
		s.gitDirtyMu.Lock()
		s.gitDirtyCache[cleanRoot] = gitDirtyEntry{
			dirty:     nil,
			isGit:     false,
			expiresAt: now.Add(gitDirtyTTL),
		}
		s.gitDirtyMu.Unlock()
		return nil, "none"
	}

	if _, err := exec.LookPath("git"); err != nil {
		return fail()
	}

	if err := s.ensureGitToplevelInside(gctx, cleanRoot); err != nil {
		return fail()
	}

	out, err := run(gctx, cleanRoot, "status", "--porcelain=v1", "-z")
	if err != nil {
		return fail()
	}

	dirty := parsePorcelainZ([]byte(out), cleanRoot)

	s.gitDirtyMu.Lock()
	s.gitDirtyCache[cleanRoot] = gitDirtyEntry{
		dirty:     dirty,
		isGit:     true,
		expiresAt: now.Add(gitDirtyTTL),
	}
	s.gitDirtyMu.Unlock()

	return dirty, "ok"
}

func rankGroups(groups []rgFileGroup, dirty map[string]struct{}, root string) {
	if len(groups) == 0 {
		return
	}
	for i := range groups {
		file := groups[i].file
		abs := file
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, file)
		}
		if _, ok := dirty[filepath.Clean(abs)]; ok {
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
