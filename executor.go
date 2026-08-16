package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultBackgroundMaxAge = 1 * time.Hour
	bgLogMaxBytes           = 16 * 1024 * 1024 // 16 MB
	maxBackgroundWaitMs     = 3600000
	maxBackgroundTailBytes  = 4 * 1024 * 1024
	maxBackgroundTailLines  = 10000
	bgTempPrefix            = "ctxmode_bg_"
	// maxBackgroundProcs caps concurrently running background jobs. Reaching
	// the cap rejects new background launches with an error instead of
	// silently queueing or spawning unbounded processes.
	maxBackgroundProcs = 16
)

// ---------- background process registry ----------

// bgEntry tracks a background subprocess for list/kill/reap.
type bgEntry struct {
	ID           string    `json:"id"`
	PID          int       `json:"pid"`
	StartedAt    time.Time `json:"started_at"`
	Command      string    `json:"command,omitempty"`
	Language     string    `json:"language,omitempty"`
	TempFiles    []string  `json:"temp_files,omitempty"`
	LogPath      string    `json:"log_path,omitempty"` // captured stdout/stderr path
	LogTruncated bool      `json:"log_truncated,omitempty"`
	Done         bool      `json:"done"`
	ExitCode     int       `json:"exit_code,omitempty"`
	// pgid for process-group kill (Setpgid=true).
	pgid int
	// starttime (field 22 of /proc/<pid>/stat, clock ticks since boot)
	// captured at registration; killBackground verifies it before signaling
	// so a recycled PID can never cause an unrelated process to be killed.
	starttime uint64
	cmd       *exec.Cmd
	// logFile is the open handle that background stdout/stderr write to;
	// closed on process exit (Wait → finishBackground). kill must not close it
	// early or log tail is lost.
	logFile       *os.File
	logWriter     *limitedFileWriter
	reapScheduled bool // grace-period removal already started
}

// limitedFileWriter keeps the newest `limit` bytes of a background log.
// Writes wrap in a ring so a long job's FAIL/summary at the end stays
// readable. compact() linearizes the file so readBackgroundLogTail can
// seek from EOF. Safe for concurrent stdout+stderr.
type limitedFileWriter struct {
	mu        sync.Mutex
	f         *os.File
	limit     int64
	pos       int64 // next write offset in [0, limit)
	filled    int64 // valid bytes, ≤ limit
	truncated bool
}

func (w *limitedFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.limit <= 0 || w.f == nil {
		return len(p), nil
	}
	want := len(p)
	for len(p) > 0 {
		if w.pos >= w.limit {
			w.pos = 0
			w.truncated = true
		}
		room := w.limit - w.pos
		chunk := p
		if int64(len(chunk)) > room {
			chunk = chunk[:room]
			w.truncated = true
		}
		if _, err := w.f.WriteAt(chunk, w.pos); err != nil {
			return 0, err
		}
		w.pos += int64(len(chunk))
		if w.filled < w.limit {
			w.filled += int64(len(chunk))
			if w.filled > w.limit {
				w.filled = w.limit
			}
		} else {
			w.truncated = true
		}
		p = p[len(chunk):]
	}
	return want, nil
}

func (w *limitedFileWriter) isTruncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}

func (w *limitedFileWriter) logicalBytes() ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logicalBytesLocked()
}

func (w *limitedFileWriter) logicalBytesLocked() ([]byte, error) {
	if w.f == nil || w.filled == 0 {
		return nil, nil
	}
	buf := make([]byte, w.filled)
	if !w.truncated || w.filled < w.limit {
		_, err := w.f.ReadAt(buf, 0)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		return dropLeadingPartialRune(buf), nil
	}
	// Ring: [pos, limit) oldest, [0, pos) newest.
	head := w.limit - w.pos
	n1, err := w.f.ReadAt(buf[:head], w.pos)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	n2, err := w.f.ReadAt(buf[n1:n1+int(w.pos)], 0)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return dropLeadingPartialRune(buf[:n1+n2]), nil
}

// compact rewrites the file as a linear tail so later readers can seek from EOF.
func (w *limitedFileWriter) compact() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	data, err := w.logicalBytesLocked()
	if err != nil {
		return err
	}
	if err := w.f.Truncate(0); err != nil {
		return err
	}
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := w.f.Write(data); err != nil {
		return err
	}
	w.pos = int64(len(data))
	w.filled = int64(len(data))
	return nil
}

var (
	bgMu     sync.Mutex
	bgProcs  = map[string]*bgEntry{}
	bgSeq    atomic.Uint64
	bgReaper sync.Once
)

// registerBackground records a live background process.
// logPath/logFile/logWriter may be empty/nil when capture is unavailable.
// Returns an error when the concurrent-background cap is reached; the caller
// must then stop the already-started process and clean up the log file.
func registerBackground(cmd *exec.Cmd, language, command string, temps []string, logPath string, logFile *os.File, logWriter *limitedFileWriter) (*bgEntry, error) {
	bgReaper.Do(func() { go backgroundReaperLoop() })
	id := fmt.Sprintf("bg-%d", bgSeq.Add(1))
	pgid := 0
	if cmd.Process != nil {
		pgid = cmd.Process.Pid
	}
	// Cap command string for list readability, on a UTF-8 rune boundary
	// (a hard byte cut could leave a half character in the listing).
	if len(command) > 200 {
		command = truncateUTF8(command, 200) + "..."
	}
	e := &bgEntry{
		ID:        id,
		PID:       cmd.Process.Pid,
		StartedAt: time.Now(),
		Language:  language,
		Command:   command,
		TempFiles: append([]string(nil), temps...),
		LogPath:   logPath,
		logFile:   logFile,
		logWriter: logWriter,
		pgid:      pgid,
		cmd:       cmd,
		// Identity snapshot for the PID-reuse guard in killBackground.
		starttime: procStartTime(cmd.Process.Pid),
	}
	bgMu.Lock()
	// Enforce the concurrent-background cap under the lock (authoritative;
	// runCmd's pre-check only avoids starting a doomed process).
	live := 0
	for _, ent := range bgProcs {
		if !ent.Done {
			live++
		}
	}
	if live >= maxBackgroundProcs {
		bgMu.Unlock()
		return nil, fmt.Errorf("too many concurrent background processes (%d max): wait for some to finish or kill them first", maxBackgroundProcs)
	}
	bgProcs[id] = e
	// Protect temp paths from init-style cleanup while registered.
	for _, t := range temps {
		protectTemp(t)
	}
	bgMu.Unlock()

	// Prefer stable log name that includes the id (rename if we used a temp
	// name). Done after registration so a cap rejection never renames; e is
	// the live registry entry, so updating e.LogPath keeps the registry in
	// sync. The final path is protected once it exists.
	if logFile != nil && logPath != "" {
		finalPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s%s.log", bgTempPrefix, id))
		if logPath != finalPath {
			if err := os.Rename(logPath, finalPath); err == nil {
				e.LogPath = finalPath
				protectTemp(finalPath)
			}
		}
	}
	return e, nil
}

// liveBackgroundCount returns the number of background jobs still running
// (not yet Done). Used by runCmd to enforce the concurrent-background cap.
func liveBackgroundCount() int {
	bgMu.Lock()
	defer bgMu.Unlock()
	n := 0
	for _, e := range bgProcs {
		if !e.Done {
			n++
		}
	}
	return n
}

// finishBackground marks entry done, closes the log FD, and cleans temps.
// Safe to call after markBackgroundKilled: if Done is already set, still
// closes log and schedules reaping (kill intentionally leaves the log open
// so the process can flush remaining output before Wait returns).
// Fully idempotent once log is closed and temps cleared.
func finishBackground(id string, exitCode int) {
	bgMu.Lock()
	e, ok := bgProcs[id]
	if !ok {
		bgMu.Unlock()
		return
	}
	// Already fully finalized (log closed, temps cleared).
	if e.Done && e.logFile == nil && len(e.TempFiles) == 0 {
		bgMu.Unlock()
		return
	}
	if !e.Done {
		e.Done = true
		e.ExitCode = exitCode
	} else if exitCode >= 0 {
		// Prefer real Wait exit code over kill's placeholder (-1) when available.
		e.ExitCode = exitCode
	}
	if e.logWriter != nil && e.logWriter.isTruncated() {
		e.LogTruncated = true
	}
	temps := append([]string(nil), e.TempFiles...)
	e.TempFiles = nil
	logFile := e.logFile
	logWriter := e.logWriter
	e.logFile = nil
	e.logWriter = nil
	logPath := e.LogPath
	// Keep entry briefly for list visibility, but unprotect temps for cleanup.
	for _, t := range temps {
		unprotectTemp(t)
	}
	scheduleReap := !e.reapScheduled
	if scheduleReap {
		e.reapScheduled = true
	}
	bgMu.Unlock()
	if logWriter != nil && logFile != nil {
		_ = logWriter.compact()
	}
	if logFile != nil {
		_ = logFile.Close()
	}
	for _, t := range temps {
		os.Remove(t)
	}
	if !scheduleReap {
		return
	}
	// Remove from registry after a short grace so list/log can still show it.
	go func() {
		time.Sleep(30 * time.Second)
		bgMu.Lock()
		if ent, ok := bgProcs[id]; ok {
			lp := ent.LogPath
			delete(bgProcs, id)
			bgMu.Unlock()
			if lp != "" {
				unprotectTemp(lp)
				os.Remove(lp)
			}
			return
		}
		bgMu.Unlock()
		if logPath != "" {
			unprotectTemp(logPath)
			os.Remove(logPath)
		}
	}()
}

// markBackgroundKilled marks the entry Done without closing the log FD.
// The Wait goroutine must still call finishBackground to close the log and
// reap temps — closing early can drop the final flush of stdout/stderr.
func markBackgroundKilled(id string) {
	bgMu.Lock()
	defer bgMu.Unlock()
	e, ok := bgProcs[id]
	if !ok || e.Done {
		return
	}
	e.Done = true
	e.ExitCode = -1
}

// snapshotBgEntry copies a registry entry for external use (no live handles).
func snapshotBgEntry(e *bgEntry) bgEntry {
	cp := *e
	if cp.logWriter != nil && cp.logWriter.isTruncated() {
		cp.LogTruncated = true
	}
	cp.cmd = nil
	cp.logFile = nil
	cp.logWriter = nil
	return cp
}

// listBackground returns a snapshot of registered processes.
func listBackground() []bgEntry {
	bgMu.Lock()
	defer bgMu.Unlock()
	out := make([]bgEntry, 0, len(bgProcs))
	for _, e := range bgProcs {
		out = append(out, snapshotBgEntry(e))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out
}

// findBackground looks up a live/recent entry by id or PID string.
func findBackground(idOrPID string) *bgEntry {
	bgMu.Lock()
	defer bgMu.Unlock()
	if e, ok := bgProcs[idOrPID]; ok {
		cp := snapshotBgEntry(e)
		return &cp
	}
	if pid, err := strconv.Atoi(idOrPID); err == nil {
		for _, e := range bgProcs {
			if e.PID == pid {
				cp := snapshotBgEntry(e)
				return &cp
			}
		}
	}
	return nil
}

// readBackgroundLogTail returns the tail of a background process log.
// Seeks from the end of the file — never loads the whole file into memory.
// tailLines defaults to 100; if tailBytes > 0 it is applied as a byte window
// (and still refined by tailLines when > 0).
func readBackgroundLogTail(logPath string, tailLines, tailBytes int) (string, error) {
	if logPath == "" {
		return "", fmt.Errorf("no log available")
	}
	if tailLines <= 0 {
		tailLines = 100
	}
	if tailLines > maxBackgroundTailLines {
		return "", fmt.Errorf("tail_lines %d exceeds maximum allowed (%d)", tailLines, maxBackgroundTailLines)
	}
	if tailBytes < 0 || tailBytes > maxBackgroundTailBytes {
		return "", fmt.Errorf("tail_bytes %d exceeds maximum allowed (%d)", tailBytes, maxBackgroundTailBytes)
	}
	if live, ok := readLiveBgLog(logPath); ok {
		return trimBgLogTail(live, tailLines, tailBytes, false), nil
	}
	f, err := os.Open(logPath)
	if err != nil {
		return "", fmt.Errorf("read log: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat log: %w", err)
	}
	size := st.Size()
	if size == 0 {
		return "", nil
	}

	// How many bytes to pull from the end. Prefer explicit tailBytes; else
	// estimate from line count with a hard safety cap so huge logs stay cheap.
	const maxTailRead = 4 * 1024 * 1024 // 4 MB safety for line-based tail
	var readSize int64
	if tailBytes > 0 {
		readSize = int64(tailBytes)
	} else {
		// ~512 bytes/line estimate, floor 64KB, cap maxTailRead.
		readSize = int64(tailLines) * 512
		if readSize < 64*1024 {
			readSize = 64 * 1024
		}
		if readSize > maxTailRead {
			readSize = maxTailRead
		}
	}
	if readSize > size {
		readSize = size
	}

	offset := size - readSize
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", fmt.Errorf("seek log: %w", err)
	}
	data := make([]byte, readSize)
	n, err := io.ReadFull(f, data)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", fmt.Errorf("read log: %w", err)
	}
	data = data[:n]
	return trimBgLogTail(data, tailLines, tailBytes, offset > 0), nil
}

func readLiveBgLog(logPath string) ([]byte, bool) {
	bgMu.Lock()
	defer bgMu.Unlock()
	for _, e := range bgProcs {
		if e.LogPath == logPath && e.logWriter != nil {
			b, err := e.logWriter.logicalBytes()
			if err != nil {
				return nil, false
			}
			return b, true
		}
	}
	return nil, false
}

func trimBgLogTail(data []byte, tailLines, tailBytes int, droppedPrefix bool) string {
	if droppedPrefix {
		if i := bytes.IndexByte(data, '\n'); i >= 0 && i+1 <= len(data) {
			data = data[i+1:]
		}
	}
	if tailBytes > 0 && len(data) > tailBytes {
		data = data[len(data)-tailBytes:]
		if i := bytes.IndexByte(data, '\n'); i >= 0 && i+1 < len(data) {
			data = data[i+1:]
		}
	}
	if tailLines > 0 {
		lines := bytes.Split(data, []byte{'\n'})
		if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
			lines = lines[:len(lines)-1]
		}
		if len(lines) > tailLines {
			lines = lines[len(lines)-tailLines:]
		}
		data = bytes.Join(lines, []byte{'\n'})
	}
	data = dropLeadingPartialRune(data)
	data = trimTrailingPartialRune(data)
	return string(data)
}

// procStartTime reads field 22 (starttime, in clock ticks since boot) from
// /proc/<pid>/stat — a stable per-process identity that survives PID reuse.
//
// Linux-specific: this depends on procfs (/proc/<pid>/stat), which is present
// on Linux (and a few BSDs with procfs mounted); there is no portable
// equivalent that is also race-free against PID reuse. On platforms where the
// file cannot be read, 0 is returned and callers fail closed: killBackground
// refuses to signal on an unknown identity, so a recycled PID can never be
// killed. That fail-closed behavior is the contract — no fake cross-platform
// implementation is attempted, and the pid-reuse guard degrades to "never
// kill" rather than "kill blind".
//
// Returns 0 when the process no longer exists or the file is unreadable.
// The comm field (2) is parenthesized and may contain spaces/parens, so the
// remainder is parsed after the LAST ')'.
func procStartTime(pid int) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 >= len(data) {
		return 0
	}
	fields := strings.Fields(string(data[i+2:]))
	// Fields after comm: state(1) ppid(2) pgrp(3) session(4) tty_nr(5)
	// tpgid(6) flags(7) minflt(8) cminflt(9) majflt(10) cmajflt(11)
	// utime(12) stime(13) cutime(14) cstime(15) priority(16) nice(17)
	// num_threads(18) itrealvalue(19) starttime(20) → index 19.
	if len(fields) < 20 {
		return 0
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// dropLeadingPartialRune drops leading bytes until b starts on a UTF-8 rune
// boundary. Used when a byte-window read (seek from the end of a log) lands
// mid-rune: the half character would otherwise render as U+FFFD.
func dropLeadingPartialRune(b []byte) []byte {
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r != utf8.RuneError || size > 1 {
			return b
		}
		b = b[1:]
	}
	return b
}

// trimTrailingPartialRune drops trailing bytes that form an incomplete rune
// (e.g. a process killed mid-write). Unlike a full validity scan, mid-stream
// invalid bytes are preserved untouched.
func trimTrailingPartialRune(b []byte) []byte {
	for len(b) > 0 {
		r, size := utf8.DecodeLastRune(b)
		if r != utf8.RuneError || size > 1 {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

// killBackground kills by id or by PID string. Returns a status message.
// On success the entry is marked Done promptly so list no longer shows it as live.
// Kill errors (other than ESRCH / already gone) are returned to the caller.
func killBackground(idOrPID string) (string, error) {
	bgMu.Lock()
	var target *bgEntry
	if e, ok := bgProcs[idOrPID]; ok {
		target = e
	} else if pid, err := strconv.Atoi(idOrPID); err == nil {
		for _, e := range bgProcs {
			if e.PID == pid {
				target = e
				break
			}
		}
	}
	if target == nil {
		bgMu.Unlock()
		return "", fmt.Errorf("no background process matching %q", idOrPID)
	}
	if target.Done {
		id := target.ID
		bgMu.Unlock()
		return fmt.Sprintf("process %s already exited", id), nil
	}
	pgid := target.pgid
	id := target.ID
	pid := target.PID
	starttime := target.starttime
	bgMu.Unlock()

	// PID-reuse guard: verify the process identity before signaling. The PID
	// (and its process group) may have been recycled by an unrelated process
	// since registration; signaling blindly could kill an innocent process.
	current := procStartTime(pid)
	if current == 0 || current != starttime {
		return "", fmt.Errorf("refusing to kill %s (PID %d): process identity mismatch (starttime recorded %d, current %d); PID likely reused or process already gone", id, pid, starttime, current)
	}

	// Two-stage kill of the process group; surface real failures (ignore ESRCH).
	killErr := func(err error) error {
		if err == nil || err == syscall.ESRCH {
			return nil
		}
		return err
	}
	var lastErr error
	if pgid != 0 {
		if err := killErr(syscall.Kill(-pgid, syscall.SIGTERM)); err != nil {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
		current = procStartTime(pid)
		if current == 0 || current != starttime {
			// Exited after SIGTERM, or PID was reused — do not SIGKILL.
			lastErr = nil
		} else if err := killErr(syscall.Kill(-pgid, syscall.SIGKILL)); err != nil {
			lastErr = err
		} else {
			lastErr = nil
		}
	} else {
		if err := killErr(syscall.Kill(pid, syscall.SIGTERM)); err != nil {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
		current = procStartTime(pid)
		if current == 0 || current != starttime {
			lastErr = nil
		} else if err := killErr(syscall.Kill(pid, syscall.SIGKILL)); err != nil {
			lastErr = err
		} else {
			lastErr = nil
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("kill background process %s (PID %d): %w", id, pid, lastErr)
	}
	// Mark Done ASAP so list no longer shows a live task, but do NOT close the
	// log FD here — closing early races the dying process and drops log tail.
	// Wait goroutine calls finishBackground, which closes the log after exit.
	markBackgroundKilled(id)
	return fmt.Sprintf("killed background process %s (PID %d)", id, pid), nil
}

// backgroundReaperLoop kills processes that exceed defaultBackgroundMaxAge.
func backgroundReaperLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		bgMu.Lock()
		var stale []string
		for id, e := range bgProcs {
			if !e.Done && now.Sub(e.StartedAt) > defaultBackgroundMaxAge {
				stale = append(stale, id)
			}
		}
		bgMu.Unlock()
		for _, id := range stale {
			_, _ = killBackground(id)
		}
	}
}

// protectedTemps tracks temp files currently owned by live background jobs.
var (
	protectedTempsMu sync.Mutex
	protectedTemps   = map[string]int{}
)

func protectTemp(path string) {
	protectedTempsMu.Lock()
	protectedTemps[path]++
	protectedTempsMu.Unlock()
}

func unprotectTemp(path string) {
	protectedTempsMu.Lock()
	if protectedTemps[path] > 1 {
		protectedTemps[path]--
	} else {
		delete(protectedTemps, path)
	}
	protectedTempsMu.Unlock()
}

func isTempProtected(path string) bool {
	protectedTempsMu.Lock()
	defer protectedTempsMu.Unlock()
	return protectedTemps[path] > 0
}

// init cleans up stale temp files from previous runs that may have been
// killed (e.g., SIGKILL) before their deferred cleanup could execute.
// Skips temps still referenced by the background registry (same process).
func init() {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "ctxmode_") {
			continue
		}
		full := filepath.Join(os.TempDir(), name)
		if isTempProtected(full) {
			continue
		}
		// Background-owned temps use a distinct prefix; if not protected
		// they belong to a dead prior process and may be reaped after 24h.
		info, err := e.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > 24*time.Hour {
			os.Remove(full)
		}
	}
}

// ---------- MCP tools: background list / kill / log / wait ----------

type backgroundListArgs struct{}

func (s *server) toolBackgroundList(ctx context.Context, _ *mcp.CallToolRequest, _ backgroundListArgs) (*mcp.CallToolResult, any, error) {
	entries := listBackground()
	type row struct {
		ID           string `json:"id"`
		PID          int    `json:"pid"`
		StartedAt    string `json:"started_at"`
		AgeSec       int64  `json:"age_sec"`
		Language     string `json:"language,omitempty"`
		Command      string `json:"command,omitempty"`
		Done         bool   `json:"done"`
		ExitCode     int    `json:"exit_code,omitempty"`
		LogPath      string `json:"log_path,omitempty"`
		LogAvailable bool   `json:"log_available"`
		LogTruncated bool   `json:"log_truncated,omitempty"`
	}
	now := time.Now()
	out := make([]row, 0, len(entries))
	for _, e := range entries {
		logOK := false
		if e.LogPath != "" {
			if st, err := os.Stat(e.LogPath); err == nil && st.Size() >= 0 {
				logOK = true
			}
		}
		out = append(out, row{
			ID:           e.ID,
			PID:          e.PID,
			StartedAt:    e.StartedAt.Format(time.RFC3339),
			AgeSec:       int64(now.Sub(e.StartedAt).Seconds()),
			Language:     e.Language,
			Command:      e.Command,
			Done:         e.Done,
			ExitCode:     e.ExitCode,
			LogPath:      e.LogPath,
			LogAvailable: logOK,
			LogTruncated: e.LogTruncated,
		})
	}
	js, _ := json.MarshalIndent(out, "", "  ")
	if len(out) == 0 {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "[]\n(no background processes; max age " + defaultBackgroundMaxAge.String() + ")"}},
		}, nil, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

type backgroundKillArgs struct {
	ID  string `json:"id,omitempty" jsonschema:"Background process id from ctx_bg action=list"`
	PID int    `json:"pid,omitempty" jsonschema:"Process PID to kill"`
}

func (s *server) toolBackgroundKill(ctx context.Context, _ *mcp.CallToolRequest, args backgroundKillArgs) (*mcp.CallToolResult, any, error) {
	key := args.ID
	if key == "" && args.PID != 0 {
		key = strconv.Itoa(args.PID)
	}
	if key == "" {
		return nil, nil, fmt.Errorf("id or pid is required")
	}
	msg, err := killBackground(key)
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}, nil, nil
}

type backgroundLogArgs struct {
	ID        string `json:"id,omitempty" jsonschema:"Background process id from ctx_bg action=list"`
	PID       int    `json:"pid,omitempty" jsonschema:"Process PID"`
	TailLines int    `json:"tail_lines,omitempty" jsonschema:"Number of trailing lines (default: 100)"`
	TailBytes int    `json:"tail_bytes,omitempty" jsonschema:"Optional max trailing bytes (applied before lines)"`
}

func (s *server) toolBackgroundLog(ctx context.Context, _ *mcp.CallToolRequest, args backgroundLogArgs) (*mcp.CallToolResult, any, error) {
	key := args.ID
	if key == "" && args.PID != 0 {
		key = strconv.Itoa(args.PID)
	}
	if key == "" {
		return nil, nil, fmt.Errorf("id or pid is required")
	}
	entry := findBackground(key)
	if entry == nil {
		return nil, nil, fmt.Errorf("no background process matching %q", key)
	}
	tailLines := args.TailLines
	if tailLines <= 0 {
		tailLines = 100
	}
	if tailLines > maxBackgroundTailLines {
		return nil, nil, fmt.Errorf("tail_lines %d exceeds maximum allowed (%d)", tailLines, maxBackgroundTailLines)
	}
	if args.TailBytes < 0 || args.TailBytes > maxBackgroundTailBytes {
		return nil, nil, fmt.Errorf("tail_bytes %d exceeds maximum allowed (%d)", args.TailBytes, maxBackgroundTailBytes)
	}
	logText, err := readBackgroundLogTail(entry.LogPath, tailLines, args.TailBytes)
	if err != nil {
		return nil, nil, err
	}
	type logResult struct {
		ID           string `json:"id"`
		PID          int    `json:"pid"`
		Done         bool   `json:"done"`
		ExitCode     int    `json:"exit_code,omitempty"`
		LogPath      string `json:"log_path,omitempty"`
		Log          string `json:"log"`
		LogTruncated bool   `json:"log_truncated,omitempty"`
	}
	out := logResult{
		ID:           entry.ID,
		PID:          entry.PID,
		Done:         entry.Done,
		ExitCode:     entry.ExitCode,
		LogPath:      entry.LogPath,
		Log:          logText,
		LogTruncated: entry.LogTruncated,
	}
	js, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

type backgroundWaitArgs struct {
	ID        string `json:"id,omitempty" jsonschema:"Background process id from ctx_bg action=list"`
	PID       int    `json:"pid,omitempty" jsonschema:"Process PID"`
	TimeoutMs int    `json:"timeout_ms,omitempty" jsonschema:"Max wait in ms (default: 60000). Does not kill on timeout."`
}

func (s *server) toolBackgroundWait(ctx context.Context, _ *mcp.CallToolRequest, args backgroundWaitArgs) (*mcp.CallToolResult, any, error) {
	key := args.ID
	if key == "" && args.PID != 0 {
		key = strconv.Itoa(args.PID)
	}
	if key == "" {
		return nil, nil, fmt.Errorf("id or pid is required")
	}
	timeoutMs := args.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 60000
	}
	if timeoutMs > maxBackgroundWaitMs {
		return nil, nil, fmt.Errorf("timeout_ms %dms exceeds maximum allowed (1 hour)", timeoutMs)
	}
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var entry *bgEntry
	for {
		entry = findBackground(key)
		if entry == nil {
			return nil, nil, fmt.Errorf("no background process matching %q", key)
		}
		if entry.Done {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-ticker.C:
		}
	}

	logText, _ := readBackgroundLogTail(entry.LogPath, 100, 0)
	type waitResult struct {
		ID           string `json:"id"`
		PID          int    `json:"pid"`
		Done         bool   `json:"done"`
		ExitCode     int    `json:"exit_code,omitempty"`
		LogPath      string `json:"log_path,omitempty"`
		Log          string `json:"log"`
		TimedOut     bool   `json:"timed_out,omitempty"`
		LogTruncated bool   `json:"log_truncated,omitempty"`
	}
	out := waitResult{
		ID:           entry.ID,
		PID:          entry.PID,
		Done:         entry.Done,
		ExitCode:     entry.ExitCode,
		LogPath:      entry.LogPath,
		Log:          logText,
		TimedOut:     !entry.Done,
		LogTruncated: entry.LogTruncated,
	}
	js, _ := json.MarshalIndent(out, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(js)}},
	}, nil, nil
}

// ---------- runtime configuration ----------

// runtimeConfig describes how to execute code in a given language.
type runtimeConfig struct {
	Exe  string                   // executable name (e.g., "node")
	Ext  string                   // temp file extension (e.g., ".js")
	Wrap func(code string) string // wraps user code with language boilerplate
}

// executeResult holds the output of a code execution.
type executeResult struct {
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	Truncated  bool   `json:"truncated,omitempty"`
	Indexed    bool   `json:"indexed,omitempty"`
	IndexLabel string `json:"index_label,omitempty"`
}

// runtimes maps language name to its configuration.
var runtimes = map[string]runtimeConfig{
	"javascript": {Exe: "node", Ext: ".js", Wrap: jsWrapper},
	"typescript": {Exe: "ts-node", Ext: ".ts", Wrap: tsWrapper},
	"python":     {Exe: "python3", Ext: ".py", Wrap: pyWrapper},
	"shell":      {Exe: "sh", Ext: ".sh", Wrap: shellWrapper},
	"go":         {Exe: "go", Ext: ".go", Wrap: goWrapper},
	"rust":       {Exe: "rustc", Ext: ".rs", Wrap: rustWrapper},
	"php":        {Exe: "php", Ext: ".php", Wrap: phpWrapper},
	"perl":       {Exe: "perl", Ext: ".pl", Wrap: perlWrapper},
	"ruby":       {Exe: "ruby", Ext: ".rb", Wrap: rubyWrapper},
	"r":          {Exe: "Rscript", Ext: ".R", Wrap: rWrapper},
	"elixir":     {Exe: "elixir", Ext: ".exs", Wrap: elixirWrapper},
	"csharp":     {Exe: "dotnet-script", Ext: ".csx", Wrap: csWrapper},
}

// ---------- wrapper functions ----------

// shellWrapper returns the code as-is. Shell is run via "sh -c" directly.
func shellWrapper(code string) string {
	return code
}

// jsWrapper wraps code in an async IIFE so users can use await at top level.
func jsWrapper(code string) string {
	return "(async () => {\n" + code + "\n})();\n"
}

// tsWrapper wraps TypeScript code like JavaScript.
func tsWrapper(code string) string {
	return "(async () => {\n" + code + "\n})();\n"
}

// pyWrapper returns Python code as-is.
func pyWrapper(code string) string {
	return code
}

// goStdImportAliases maps common package selectors to their import paths.
var goStdImportAliases = map[string]string{
	"fmt":       "fmt",
	"os":        "os",
	"strings":   "strings",
	"strconv":   "strconv",
	"time":      "time",
	"bytes":     "bytes",
	"io":        "io",
	"bufio":     "bufio",
	"errors":    "errors",
	"sort":      "sort",
	"math":      "math",
	"sync":      "sync",
	"context":   "context",
	"regexp":    "regexp",
	"log":       "log",
	"filepath":  "path/filepath",
	"json":      "encoding/json",
	"base64":    "encoding/base64",
	"http":      "net/http",
	"url":       "net/url",
	"ioutil":    "io/ioutil",
	"exec":      "os/exec",
	"path":      "path",
	"unicode":   "unicode",
	"utf8":      "unicode/utf8",
	"hex":       "encoding/hex",
	"sha256":    "crypto/sha256",
	"md5":       "crypto/md5",
	"rand":      "math/rand",
	"big":       "math/big",
	"reflect":   "reflect",
	"runtime":   "runtime",
	"flag":      "flag",
	"net":       "net",
	"template":  "text/template",
	"html":      "html",
	"csv":       "encoding/csv",
	"gzip":      "compress/gzip",
	"tar":       "archive/tar",
	"zip":       "archive/zip",
	"syscall":   "syscall",
	"atomic":    "sync/atomic",
	"binary":    "encoding/binary",
	"xml":       "encoding/xml",
	"sql":       "database/sql",
	"tls":       "crypto/tls",
	"x509":      "crypto/x509",
	"hmac":      "crypto/hmac",
	"sha1":      "crypto/sha1",
	"sha512":    "crypto/sha512",
	"aes":       "crypto/aes",
	"cipher":    "crypto/cipher",
	"elliptic":  "crypto/elliptic",
	"ecdsa":     "crypto/ecdsa",
	"rsa":       "crypto/rsa",
	"ed25519":   "crypto/ed25519",
	"pem":       "encoding/pem",
	"ascii85":   "encoding/ascii85",
	"gob":       "encoding/gob",
	"tabwriter": "text/tabwriter",
	"scanner":   "text/scanner",
	"parser":    "go/parser",
	"ast":       "go/ast",
	"token":     "go/token",
	"format":    "go/format",
	"printer":   "go/printer",
	"types":     "go/types",
	"constant":  "go/constant",
	"build":     "go/build",
	"doc":       "go/doc",
	"importer":  "go/importer",
}

// goSelectorRe matches pkg.Ident uses (simple heuristic for import detection).
var goSelectorRe = regexp.MustCompile(`\b([a-z][a-zA-Z0-9_]*)\.[A-Z(]`)

// goStringSpans returns half-open byte ranges of Go string literal, rune
// literal, and comment regions in code. Selector-looking text inside these
// regions is data, not code, and must not drive import detection:
//   - raw strings (backtick-delimited), e.g. the FILE_CONTENT literal that
//     injectFileContent prepends — including its backtick-concatenation form,
//     where backticks inside "`" strings are literal data;
//   - interpreted "..." strings and '...' rune literals (backslash escapes the
//     next byte inside them; raw strings have no escapes and end at the next
//     backtick);
//   - // line comments and /* */ block comments (a stray quote in a comment
//     must not swallow the rest of the code).
func goStringSpans(code string) [][2]int {
	var spans [][2]int
	for i := 0; i < len(code); {
		switch {
		case code[i] == '/' && i+1 < len(code) && code[i+1] == '/':
			if end := strings.IndexByte(code[i:], '\n'); end < 0 {
				spans = append(spans, [2]int{i, len(code)})
				return spans
			} else {
				spans = append(spans, [2]int{i, i + end})
				i += end
			}
		case code[i] == '/' && i+1 < len(code) && code[i+1] == '*':
			if end := strings.Index(code[i+2:], "*/"); end < 0 {
				spans = append(spans, [2]int{i, len(code)})
				return spans
			} else {
				spans = append(spans, [2]int{i, i + end + 4})
				i += end + 4
			}
		case code[i] == '`':
			if end := strings.IndexByte(code[i+1:], '`'); end < 0 {
				spans = append(spans, [2]int{i, len(code)})
				return spans
			} else {
				spans = append(spans, [2]int{i, i + end + 2})
				i += end + 2
			}
		case code[i] == '"' || code[i] == '\'':
			quote := code[i]
			j := i + 1
			for j < len(code) {
				if code[j] == '\\' {
					j += 2
					continue
				}
				if code[j] == quote {
					break
				}
				j++
			}
			if j >= len(code) {
				spans = append(spans, [2]int{i, len(code)})
				return spans
			}
			spans = append(spans, [2]int{i, j + 1})
			i = j + 1
		default:
			i++
		}
	}
	return spans
}

// detectGoImports scans user code for common stdlib package selectors and
// returns the import paths needed. Matches inside string literals and
// comments (see goStringSpans) are data, not code, and are skipped — this
// keeps FILE_CONTENT raw-string data injected by injectFileContent from
// triggering unused imports. No default import is added: only packages with a
// real selector usage are imported, so the wrapped program compiles.
func detectGoImports(code string) []string {
	spans := goStringSpans(code)
	inData := func(pos int) bool {
		for _, s := range spans {
			if pos >= s[0] && pos < s[1] {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for _, m := range goSelectorRe.FindAllStringSubmatchIndex(code, -1) {
		if len(m) < 4 || inData(m[0]) {
			continue
		}
		if path, ok := goStdImportAliases[code[m[2]:m[3]]]; ok {
			seen[path] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// goWrapper wraps user code into a complete main package, auto-importing
// standard library packages detected from selector usage (fmt, os, strings, …).
// If the code already declares `package `, it is returned unchanged.
func goWrapper(code string) string {
	trimmed := strings.TrimSpace(code)
	if strings.HasPrefix(trimmed, "package ") {
		return code
	}
	imports := detectGoImports(code)
	var b strings.Builder
	b.WriteString("package main\n\n")
	if len(imports) == 1 {
		b.WriteString(fmt.Sprintf("import %q\n\n", imports[0]))
	} else if len(imports) > 1 {
		b.WriteString("import (\n")
		for _, imp := range imports {
			b.WriteString(fmt.Sprintf("\t%q\n", imp))
		}
		b.WriteString(")\n\n")
	}
	b.WriteString("func main() {\n")
	b.WriteString(code)
	b.WriteString("\n}\n")
	return b.String()
}

// rustWrapper wraps user code into a complete main function.
func rustWrapper(code string) string {
	return `fn main() {
` + code + `
}
`
}

// phpWrapper adds <?php tag.
func phpWrapper(code string) string {
	return "<?php\n" + code + "\n"
}

// perlWrapper returns Perl code as-is.
func perlWrapper(code string) string {
	return code
}

// rubyWrapper returns Ruby code as-is.
func rubyWrapper(code string) string {
	return code
}

// rWrapper returns R code as-is.
func rWrapper(code string) string {
	return code
}

// elixirWrapper returns Elixir code as-is.
func elixirWrapper(code string) string {
	return code
}

// csWrapper returns C#/dotnet-script code as-is.
func csWrapper(code string) string {
	return code
}

// ---------- runtime checking ----------

// tsNodeAvailable caches typescript runtime detection result.
var (
	tsNodeAvailable bool
	tsNodePath      string
	tsNodeCheckOnce sync.Once
	tsNodePathMu    sync.Mutex
)

// detectTsNode probes for a local ts-node installation without network access.
// Returns whether it's available and the path to the executable.
func detectTsNode() (bool, string) {
	// 1. Check for global ts-node binary
	if p, err := exec.LookPath("ts-node"); err == nil {
		return true, p
	}
	// 2. Check cwd/node_modules/.bin/ts-node
	cwd, err := os.Getwd()
	if err == nil {
		p := filepath.Join(cwd, "node_modules", ".bin", "ts-node")
		if _, err := os.Stat(p); err == nil {
			return true, p
		}
	}
	// 3. Fall back to npm ls (local only, reads package.json)
	npmCtx, npmCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer npmCancel()
	npmCmd := exec.CommandContext(npmCtx, "npm", "ls", "ts-node", "--depth=0")
	npmCmd.Env = flattenEnv(childEnv(nil))
	if npmCmd.Run() == nil {
		// ts-node is installed locally; use the local path
		cwd, _ := os.Getwd()
		p := filepath.Join(cwd, "node_modules", ".bin", "ts-node")
		if _, err := os.Stat(p); err == nil {
			return true, p
		}
		// Last resort: assume it's resolvable by name
		return true, "ts-node"
	}
	return false, ""
}

// checkRuntime checks if the runtime executable for the given language is
// available on the system PATH. Shell is always available.
// When useCache is true, TypeScript detection is cached via sync.Once
// (for execution gating). When false, detection runs fresh (for doctor).
func checkRuntime(language string, useCache bool) bool {
	if language == "shell" {
		return true
	}
	rt, ok := runtimes[language]
	if !ok {
		return false
	}

	switch language {
	case "go":
		// go version exits 0
		cmd := exec.Command(rt.Exe, "version")
		cmd.Env = flattenEnv(childEnv(nil))
		return cmd.Run() == nil
	case "typescript":
		if useCache {
			tsNodeCheckOnce.Do(func() {
				av, p := detectTsNode()
				tsNodePathMu.Lock()
				tsNodeAvailable = av
				tsNodePath = p
				tsNodePathMu.Unlock()
			})
			return tsNodeAvailable
		}
		// Fresh detection for doctor — update cached path for execution use.
		avail, p := detectTsNode()
		if avail {
			tsNodePathMu.Lock()
			tsNodePath = p
			tsNodePathMu.Unlock()
		}
		return avail
	default:
		// Use Go standard library instead of external "which" command.
		_, err := exec.LookPath(rt.Exe)
		return err == nil
	}
}

// ---------- code wrapping ----------

// wrapCode wraps user code with language-appropriate boilerplate.
func wrapCode(language, code string) string {
	rt, ok := runtimes[language]
	if !ok || rt.Wrap == nil {
		return code
	}
	return rt.Wrap(code)
}

// ---------- file content injection for ctx_run: execute_file ----------

// injectFileContent inserts a FILE_CONTENT variable so execute_file code can
// read the target file. The declaration is spliced after language preambles
// (Go package/import, Python __future__, PHP declare) so whole-file sources
// still compile.
func injectFileContent(language, code, fileContent string) string {
	decl := fileContentDecl(language, fileContent)
	if decl == "" {
		return code
	}
	return spliceFileContentDecl(language, code, decl)
}

func fileContentDecl(language, fileContent string) string {
	switch language {
	case "shell":
		escaped := strings.ReplaceAll(fileContent, `'`, `'\''`)
		return fmt.Sprintf("FILE_CONTENT='%s'\n", escaped)

	case "javascript", "typescript":
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, "`", "\\`")
		escaped = strings.ReplaceAll(escaped, "${", "\\${")
		return "const FILE_CONTENT = `" + escaped + "`;\n"

	case "python":
		if strings.Contains(fileContent, `"""`) ||
			strings.HasSuffix(fileContent, `"`) ||
			strings.HasSuffix(fileContent, `\`) {
			encoded := base64.StdEncoding.EncodeToString([]byte(fileContent))
			return "import base64\nFILE_CONTENT = base64.b64decode(\"" + encoded + "\").decode()\n"
		}
		return "FILE_CONTENT = r\"\"\"" + fileContent + "\"\"\"\n"

	case "go":
		parts := strings.Split(fileContent, "`")
		if len(parts) == 1 {
			return "FILE_CONTENT := `" + fileContent + "`\n"
		}
		var sb strings.Builder
		sb.WriteString("FILE_CONTENT := ")
		for i, p := range parts {
			if i > 0 {
				sb.WriteString(" + \"`\" + ")
			}
			sb.WriteString("`" + p + "`")
		}
		sb.WriteByte('\n')
		return sb.String()

	case "rust":
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		escaped = strings.ReplaceAll(escaped, "\n", `\n`)
		escaped = strings.ReplaceAll(escaped, "\r", `\r`)
		return `    let FILE_CONTENT = "` + escaped + `";` + "\n"

	case "php":
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		return "$FILE_CONTENT = '" + escaped + "';\n"

	case "perl":
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		return "my $FILE_CONTENT = '" + escaped + "';\n"

	case "ruby":
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		return "FILE_CONTENT = '" + escaped + "'\n"

	case "r":
		escaped := strings.ReplaceAll(fileContent, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		return "FILE_CONTENT <- '" + escaped + "'\n"

	case "elixir":
		if strings.Contains(fileContent, `"""`) {
			encoded := base64.StdEncoding.EncodeToString([]byte(fileContent))
			return "FILE_CONTENT = Base.decode64!(\"" + encoded + "\")\n"
		}
		// ~S"""content""" — no extra wrapping newlines (those would become data).
		return "FILE_CONTENT = ~S\"\"\"" + fileContent + "\"\"\"\n"

	case "csharp":
		escaped := strings.ReplaceAll(fileContent, `"`, `""`)
		return "var FILE_CONTENT = @\"" + escaped + "\";\n"

	default:
		return ""
	}
}

func spliceFileContentDecl(language, code, decl string) string {
	switch language {
	case "go":
		return spliceAfterGoPreamble(code, decl)
	case "python":
		return spliceAfterPythonPreamble(code, decl)
	case "php":
		return spliceAfterPHPPreamble(code, decl)
	default:
		return decl + code
	}
}

func spliceAfterGoPreamble(code, decl string) string {
	if !strings.Contains(code, "package ") {
		return decl + code
	}
	// After `package x` and an optional import / import ( ... ) block.
	rest := code
	var head strings.Builder
	// package line
	if i := strings.Index(rest, "package "); i >= 0 {
		head.WriteString(rest[:i])
		rest = rest[i:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			head.WriteString(rest[:nl+1])
			rest = rest[nl+1:]
		} else {
			return code + "\n" + decl
		}
	}
	// skip blanks and line comments
	skipWSComments := func() {
		for {
			trim := strings.TrimLeft(rest, " \t")
			if strings.HasPrefix(trim, "\n") {
				head.WriteString(rest[:len(rest)-len(trim)+1])
				rest = trim[1:]
				continue
			}
			if strings.HasPrefix(trim, "//") {
				if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
					head.WriteString(rest[:nl+1])
					rest = rest[nl+1:]
					continue
				}
			}
			return
		}
	}
	skipWSComments()
	trim := strings.TrimLeft(rest, " \t")
	if strings.HasPrefix(trim, "import (") {
		if end := strings.Index(rest, "\n)"); end >= 0 {
			// include closing line
			nl := strings.IndexByte(rest[end+2:], '\n')
			if nl >= 0 {
				head.WriteString(rest[:end+2+nl+1])
				rest = rest[end+2+nl+1:]
			} else {
				head.WriteString(rest)
				rest = ""
			}
		}
	} else if strings.HasPrefix(trim, "import ") {
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			head.WriteString(rest[:nl+1])
			rest = rest[nl+1:]
		}
	}
	head.WriteString(decl)
	head.WriteString(rest)
	return head.String()
}

func spliceAfterPythonPreamble(code, decl string) string {
	rest := code
	var head strings.Builder
	takeLine := func() (string, bool) {
		nl := strings.IndexByte(rest, '\n')
		if nl < 0 {
			line := rest
			rest = ""
			return line, false
		}
		line := rest[:nl+1]
		rest = rest[nl+1:]
		return line, true
	}
	if strings.HasPrefix(rest, "#!") {
		line, _ := takeLine()
		head.WriteString(line)
	}
	// encoding cookie / comments / blanks
	for rest != "" {
		trim := strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(trim, "\n") || strings.HasPrefix(trim, "#") {
			line, _ := takeLine()
			head.WriteString(line)
			continue
		}
		break
	}
	// module docstring
	trim := strings.TrimLeft(rest, " \t")
	if strings.HasPrefix(trim, `"""`) || strings.HasPrefix(trim, "'''") {
		q := `"""`
		if strings.HasPrefix(trim, "'''") {
			q = "'''"
		}
		// find closing quotes after the opener
		start := strings.Index(rest, q)
		if start >= 0 {
			end := strings.Index(rest[start+3:], q)
			if end >= 0 {
				abs := start + 3 + end + 3
				if nl := strings.IndexByte(rest[abs:], '\n'); nl >= 0 {
					abs += nl + 1
				}
				head.WriteString(rest[:abs])
				rest = rest[abs:]
			}
		}
	}
	for rest != "" {
		trim = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(trim, "from __future__ import") {
			line, _ := takeLine()
			head.WriteString(line)
			continue
		}
		if strings.HasPrefix(trim, "\n") {
			line, _ := takeLine()
			head.WriteString(line)
			continue
		}
		break
	}
	head.WriteString(decl)
	head.WriteString(rest)
	return head.String()
}

func spliceAfterPHPPreamble(code, decl string) string {
	rest := code
	var head strings.Builder
	trim := strings.TrimLeft(rest, " \t")
	if strings.HasPrefix(trim, "<?php") {
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			head.WriteString(rest[:nl+1])
			rest = rest[nl+1:]
		}
	}
	for rest != "" {
		trim = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(trim, "declare(") {
			if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
				head.WriteString(rest[:nl+1])
				rest = rest[nl+1:]
				continue
			}
			head.WriteString(rest)
			rest = ""
			break
		}
		break
	}
	head.WriteString(decl)
	head.WriteString(rest)
	return head.String()
}

// ---------- core execution ----------

// runOptions carries optional env/stdin for execute (shell, argv, and language modes).
// Env must already be allowlist-filtered. Stdin is written then closed (via Reader EOF).
type runOptions struct {
	Env   map[string]string
	Stdin string
}

// maxStdinBytes caps ctx_run execute stdin payload size (1 MiB).
const maxStdinBytes = 1 * 1024 * 1024

// envAllowlist is the explicit set of keys callers may inject via ctx_run execute env.
// Unknown keys are rejected. Dangerous keys are always denied even if listed.
var envAllowlist = map[string]bool{
	"GOFLAGS":                 true,
	"CGO_ENABLED":             true,
	"GOOS":                    true,
	"GOARCH":                  true,
	"GOPROXY":                 true,
	"GOSUMDB":                 true,
	"GOROOT":                  true,
	"GOTOOLCHAIN":             true,
	"GO111MODULE":             true,
	"GOTMPDIR":                true,
	"NODE_ENV":                true,
	"CI":                      true,
	"RUST_BACKTRACE":          true,
	"RUSTFLAGS":               true,
	"CARGO_TERM_COLOR":        true,
	"PYTHONDONTWRITEBYTECODE": true,
	"PYTHONUNBUFFERED":        true,
	"TZ":                      true,
	"LANG":                    true,
	"LC_ALL":                  true,
}

// isDeniedEnvKey reports keys that must never be overridden (PATH, loader, shell, home).
func isDeniedEnvKey(key string) bool {
	uk := strings.ToUpper(key)
	switch uk {
	case "PATH", "HOME", "SHELL", "USER", "LOGNAME",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"IFS", "CDPATH", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS",
		"SSLKEYLOGFILE", "TERM":
		return true
	}
	if strings.HasPrefix(uk, "LD_") || strings.HasPrefix(uk, "DYLD_") {
		return true
	}
	return false
}

// filterExecEnv validates env against the allowlist. Returns a copy or an error.
// Keys with the CTXMODE_ prefix are also accepted (except denylist collisions).
func filterExecEnv(env map[string]string) (map[string]string, error) {
	if len(env) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(env))
	for k, v := range env {
		if k == "" {
			return nil, fmt.Errorf("env: empty key is not allowed")
		}
		if strings.ContainsAny(k, "=\x00") {
			return nil, fmt.Errorf("env: invalid key %q", k)
		}
		if isDeniedEnvKey(k) {
			return nil, fmt.Errorf("env key %q is not allowed (security denylist)", k)
		}
		if envAllowlist[k] || strings.HasPrefix(k, "CTXMODE_") {
			out[k] = v
			continue
		}
		return nil, fmt.Errorf("env key %q is not in the allowlist (allowed: GO*, NODE_ENV, CI, CTXMODE_*, …)", k)
	}
	return out, nil
}

// sensitiveEnvKeyRe matches environment variable names that commonly carry
// secrets (API keys, tokens, passwords, credentials, auth material, cookies,
// session data). Matching is case-insensitive on the KEY NAME; values are not
// inspected.
var sensitiveEnvKeyRe = regexp.MustCompile(`(?i)token|key|secret|password|passwd|credential|auth|cookie|session`)

// childEnv builds the environment map for a subprocess.
//
// Security default: variables inherited from the parent whose key name
// matches sensitiveEnvKeyRe are REMOVED. A subprocess would otherwise inherit
// API keys / tokens / passwords, and because its output is captured and
// auto-indexed, those secrets could be persisted to disk.
//
// Exceptions, in priority order:
//   - CTXMODE_ENV_PASSTHROUGH=1 in the parent environment disables stripping
//     entirely (opt-out for hosts that must pass the full environment).
//   - Keys explicitly allowlisted (envAllowlist) are always kept.
//   - Keys explicitly passed by the caller (overrides, already validated by
//     filterExecEnv) always win and are never stripped.
//
// The merge also fixes duplicate-key injection: overrides are applied to a
// map and the result is flattened, so a caller-provided value truly replaces
// a same-named inherited one. Previously the new entry was appended after
// os.Environ(), and with a duplicate key glibc getenv returns the FIRST
// occurrence — the stale host value — making the injection ineffective.
func childEnv(overrides map[string]string) map[string]string {
	env := make(map[string]string)
	strip := os.Getenv("CTXMODE_ENV_PASSTHROUGH") != "1"
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		if strip && !envAllowlist[k] && sensitiveEnvKeyRe.MatchString(k) {
			continue
		}
		env[k] = v
	}
	for k, v := range overrides {
		env[k] = v
	}
	return env
}

// flattenEnv renders a merged env map as the sorted "K=V" slice exec.Cmd
// expects (sorted for deterministic ordering).
func flattenEnv(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// applyRunOptions sets Env (merged with process env) and Stdin on cmd.
// cmd.Env is ALWAYS set (even with no caller options) so that sensitive
// inherited variables are stripped by default — see childEnv.
func applyRunOptions(cmd *exec.Cmd, opts *runOptions) {
	if opts == nil {
		cmd.Env = flattenEnv(childEnv(nil))
		return
	}
	cmd.Env = flattenEnv(childEnv(opts.Env))
	if opts.Stdin != "" {
		cmd.Stdin = strings.NewReader(opts.Stdin)
	}
}

// runCode executes code in the specified language sandbox.
// It handles temp file creation, runtime selection, timeout, and background mode.
func runCode(ctx context.Context, language, code, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
	return runCodeOpts(ctx, language, code, cwd, timeout, background, nil)
}

// runCodeOpts is runCode with optional env/stdin.
func runCodeOpts(ctx context.Context, language, code, cwd string, timeout time.Duration, background bool, opts *runOptions) (*executeResult, error) {
	rt, ok := runtimes[language]
	if !ok {
		return nil, fmt.Errorf("unsupported language: %q (supported: javascript, typescript, python, shell, go, rust, php, perl, ruby, r, elixir, csharp)", language)
	}

	if !checkRuntime(language, true) {
		return nil, fmt.Errorf("runtime %q is not available for language %q — install it first or use a different language", rt.Exe, language)
	}

	if timeout <= 0 && !background {
		// Foreground default is 30s. Background jobs without an explicit
		// caller timeout are bounded by defaultBackgroundMaxAge instead
		// (enforced by the per-job timer in runCmd and by the reaper).
		timeout = 30 * time.Second
	}

	wrapped := wrapCode(language, code)

	// Shell is handled specially — no temp file needed.
	if language == "shell" {
		return runShellOpts(ctx, wrapped, cwd, timeout, background, opts)
	}

	// Create a temp file with the appropriate extension.
	// Background temps use a distinct prefix so cleanup can treat them carefully.
	pattern := "ctxmode_*" + rt.Ext
	if background {
		pattern = bgTempPrefix + "*" + rt.Ext
	}
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	// In background mode the process outlives this function — the temp file
	// must stick around until it exits. We defer removal only for foreground runs.
	if !background {
		defer os.Remove(tmpPath)
	}

	if _, err := tmpFile.WriteString(wrapped); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	tmpFile.Close()

	// Build and run the command based on language.
	return runCompiledOpts(ctx, language, rt, tmpPath, cwd, timeout, background, opts)
}

// runShell executes code directly via "sh -c".
func runShell(ctx context.Context, code, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
	return runShellOpts(ctx, code, cwd, timeout, background, nil)
}

// runShellOpts is runShell with optional env/stdin.
func runShellOpts(ctx context.Context, code, cwd string, timeout time.Duration, background bool, opts *runOptions) (*executeResult, error) {
	var cmd *exec.Cmd
	shellPath := os.Getenv("SHELL")
	if shellPath != "" {
		parts := strings.Fields(shellPath)
		if len(parts) == 0 {
			cmd = exec.Command("sh", "-c", code)
		} else {
			args := append(parts[1:], "-c", code)
			cmd = exec.Command(parts[0], args...)
		}
	} else {
		cmd = exec.Command("sh", "-c", code)
	}
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	applyRunOptions(cmd, opts)

	return runCmd(ctx, cmd, timeout, background, "shell", code)
}

// runArgv runs exec.Command(argv[0], argv[1:]...) without a shell.
// argv must already be validated (non-empty; argv[0] simple name or workdir path).
func runArgv(ctx context.Context, argv []string, cwd string, timeout time.Duration, background bool, opts *runOptions) (*executeResult, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("argv must not be empty")
	}
	if argv[0] == "" {
		return nil, fmt.Errorf("argv[0] must not be empty")
	}
	if timeout <= 0 && !background {
		// Foreground default is 30s. Background jobs without an explicit
		// caller timeout are bounded by defaultBackgroundMaxAge instead
		// (enforced by the per-job timer in runCmd and by the reaper).
		timeout = 30 * time.Second
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	applyRunOptions(cmd, opts)
	cmdStr := strings.Join(argv, " ")
	return runCmd(ctx, cmd, timeout, background, "argv", cmdStr)
}

// runCompiled executes a language that uses a temp source file.
func runCompiled(ctx context.Context, language string, rt runtimeConfig, tmpPath, cwd string, timeout time.Duration, background bool) (*executeResult, error) {
	return runCompiledOpts(ctx, language, rt, tmpPath, cwd, timeout, background, nil)
}

// runCompiledOpts is runCompiled with optional env/stdin.
func runCompiledOpts(ctx context.Context, language string, rt runtimeConfig, tmpPath, cwd string, timeout time.Duration, background bool, opts *runOptions) (*executeResult, error) {
	var cmd *exec.Cmd
	var cleanups []string

	switch language {
	case "rust":
		// Two-step: compile via rustc, then run the binary.
		outPath := tmpPath + "_bin"
		if !background {
			defer os.Remove(outPath)
		} else {
			cleanups = append(cleanups, outPath)
		}

		compileStart := time.Now()
		compileCtx := ctx
		// Background jobs without an explicit caller timeout still cap the
		// synchronous compile step at the background default so a hung rustc
		// cannot block the tool call forever.
		compileBudget := timeout
		if compileBudget <= 0 {
			compileBudget = defaultBackgroundMaxAge
		}
		var cancel context.CancelFunc
		compileCtx, cancel = context.WithTimeout(ctx, compileBudget)
		defer cancel()
		compileCmd := exec.Command("rustc", "-o", outPath, tmpPath)
		compileCmd.Dir = cwd
		compileCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		// Env applies to compile + run; stdin only to the run step.
		// Same dedup + secret-strip rules as the run step (see childEnv).
		var optsEnv map[string]string
		if opts != nil {
			optsEnv = opts.Env
		}
		compileCmd.Env = flattenEnv(childEnv(optsEnv))
		var compileOutBuf limitedBuffer
		compileOutBuf.limit = maxCmdOutput
		compileCmd.Stdout = &compileOutBuf
		compileCmd.Stderr = &compileOutBuf
		if err := compileCmd.Start(); err != nil {
			if background {
				os.Remove(tmpPath)
				os.Remove(outPath)
			}
			return &executeResult{
				Stdout:    compileOutBuf.String(),
				Stderr:    fmt.Sprintf("compilation failed: %v", err),
				ExitCode:  -1,
				Truncated: compileOutBuf.truncated,
			}, nil
		}
		compileDone := make(chan error, 1)
		go func() { compileDone <- compileCmd.Wait() }()
		var compileErr error
		if compileBudget > 0 {
			select {
			case compileErr = <-compileDone:
			case <-compileCtx.Done():
				if compileCmd.Process != nil {
					_ = syscall.Kill(-compileCmd.Process.Pid, syscall.SIGTERM)
					select {
					case compileErr = <-compileDone:
					case <-time.After(3 * time.Second):
						_ = syscall.Kill(-compileCmd.Process.Pid, syscall.SIGKILL)
						compileErr = <-compileDone
					}
				} else {
					compileErr = <-compileDone
				}
			}
		} else {
			compileErr = <-compileDone
		}
		if compileErr != nil {
			if background {
				os.Remove(tmpPath)
				os.Remove(outPath)
			}
			return &executeResult{
				Stdout:    compileOutBuf.String(),
				Stderr:    fmt.Sprintf("compilation failed: %v", compileErr),
				ExitCode:  -1,
				Truncated: compileOutBuf.truncated,
			}, nil
		}
		cmd = exec.Command(outPath)
		cmd.Dir = cwd
		// Deduct compilation time from the runtime budget.
		if timeout > 0 {
			elapsed := time.Since(compileStart)
			timeout -= elapsed
			if timeout <= 0 {
				timeout = time.Nanosecond
			}
		}

	case "typescript":
		tsNodePathMu.Lock()
		exe := tsNodePath
		tsNodePathMu.Unlock()
		if exe == "" {
			exe = "ts-node"
		}
		cmd = exec.Command(exe, tmpPath)
		cmd.Dir = cwd

	case "go":
		cmd = exec.Command("go", "run", tmpPath)
		cmd.Dir = cwd

	default:
		cmd = exec.Command(rt.Exe, tmpPath)
		cmd.Dir = cwd
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	applyRunOptions(cmd, opts)
	if background {
		cleanups = append(cleanups, tmpPath)
	}
	// Prefer argv string for observability; falls back to language label.
	cmdStr := strings.Join(cmd.Args, " ")
	if cmdStr == "" {
		cmdStr = language
	}
	return runCmd(ctx, cmd, timeout, background, language, cmdStr, cleanups...)
}

// maxCmdOutput is the maximum number of bytes captured from a subprocess's
// stdout and stderr. If the subprocess produces more output, it is silently
// dropped to prevent OOM.
const maxCmdOutput = 10 * 1024 * 1024 // 10 MB

// limitedBuffer is an io.Writer that wraps bytes.Buffer and silently drops
// writes after the limit is reached. This prevents unbounded memory growth
// from misbehaving subprocesses.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	if lb.buf.Len() >= lb.limit {
		lb.truncated = true
		return len(p), nil
	}
	remaining := lb.limit - lb.buf.Len()
	if len(p) <= remaining {
		return lb.buf.Write(p)
	}
	lb.truncated = true
	// Cut on a UTF-8 rune boundary: a hard byte cut would leave a half
	// character at the tail of the captured output. The FULL input chunk is
	// passed with the remaining budget so truncateUTF8's boundary back-off
	// actually runs (passing p[:remaining] would short-circuit on len==max).
	_, _ = lb.buf.WriteString(truncateUTF8(string(p), remaining))
	return len(p), nil
}

func (lb *limitedBuffer) String() string {
	return lb.buf.String()
}

// runCmd is the shared execution loop for all languages.
// It starts the process, optionally waits with a timeout, and returns
// the combined stdout/stderr and exit code.
func runCmd(ctx context.Context, cmd *exec.Cmd, timeout time.Duration, background bool, language, command string, cleanups ...string) (*executeResult, error) {
	var stdoutBuf, stderrBuf limitedBuffer
	stdoutBuf.limit = maxCmdOutput
	stderrBuf.limit = maxCmdOutput

	// For background jobs, route stdout/stderr straight to a disk log for the
	// log/wait tools — no in-memory capture at all. The log size is
	// hard-capped at bgLogMaxBytes to prevent unbounded disk growth. The
	// background result is never returned to the caller, so the foreground
	// limitedBuffer capture is unnecessary; a 10MB buffer per stream per job
	// would multiply with maxBackgroundProcs concurrent jobs.
	var logFile *os.File
	var logPath string
	var logWriter *limitedFileWriter
	if background {
		// Cap concurrently running background jobs: reject with an error
		// instead of silently queueing. registerBackground re-checks under
		// the lock (authoritative); this pre-check avoids starting a doomed
		// process in the common case.
		if liveBackgroundCount() >= maxBackgroundProcs {
			return nil, fmt.Errorf("too many concurrent background processes (%d max): wait for some to finish or kill them first", maxBackgroundProcs)
		}
		f, err := os.CreateTemp(os.TempDir(), bgTempPrefix+"*.log")
		if err != nil {
			return nil, fmt.Errorf("create background log: %w", err)
		}
		logFile = f
		logPath = f.Name()
		logWriter = &limitedFileWriter{f: f, limit: bgLogMaxBytes}
		cmd.Stdout = logWriter
		cmd.Stderr = logWriter
	} else {
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
	}

	if err := cmd.Start(); err != nil {
		if logFile != nil {
			logFile.Close()
			os.Remove(logPath)
		}
		return nil, fmt.Errorf("failed to start process: %w", err)
	}

	if background {
		// Register for list/kill/log/wait supervision; reap on exit; enforce max age.
		entry, err := registerBackground(cmd, language, command, cleanups, logPath, logFile, logWriter)
		if err != nil {
			// Cap reached (e.g. a concurrent launch won the race): stop the
			// just-started process, reap it, and clean up the log.
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				_ = cmd.Wait()
			}
			if logFile != nil {
				logFile.Close()
				os.Remove(logPath)
			}
			return nil, err
		}
		go func(id string, c *exec.Cmd) {
			err := c.Wait()
			exitCode := 0
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					exitCode = ee.ExitCode()
				} else {
					exitCode = -1
				}
			}
			finishBackground(id, exitCode)
		}(entry.ID, cmd)
		// Honor the caller-provided timeout on the background job; without an
		// explicit timeout the defaultBackgroundMaxAge (1h) applies. The
		// reaper loop remains as a safety net.
		maxAge := timeout
		if maxAge <= 0 {
			maxAge = defaultBackgroundMaxAge
		}
		time.AfterFunc(maxAge, func() {
			// Entry may already be Done or reaped — nothing to do then.
			_, _ = killBackground(entry.ID)
		})
		return &executeResult{
			Stdout: fmt.Sprintf("Process started in background (id: %s, PID: %d). Use ctx_bg action=list|kill|log|wait. Max age %s.",
				entry.ID, cmd.Process.Pid, maxAge),
			ExitCode: 0,
		}, nil
	}

	// Wait with timeout.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// timeout <= 0 means no deadline: timerC stays nil and its select case is
	// disabled (a nil channel never fires). The select then waits on context
	// cancellation or process exit. (Dereferencing a nil *time.Timer for .C
	// would panic with a nil-pointer dereference, hence the channel variable.)
	var timerC <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		timerC = timer.C
	}

	truncated := false

	select {
	case <-timerC:
		// Timeout: send SIGTERM first for graceful shutdown, then SIGKILL.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
				// Process exited gracefully after SIGTERM.
			case <-time.After(3 * time.Second):
				// Force-kill and drain to release pipe resources.
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
		}
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()
		if stderr == "" {
			stderr = fmt.Sprintf("Process timed out after %v", timeout)
		}
		truncated = stdoutBuf.truncated || stderrBuf.truncated
		return &executeResult{
			Stdout:    stdout,
			Stderr:    stderr,
			ExitCode:  -1,
			Truncated: truncated,
		}, nil

	case <-ctx.Done():
		// Context cancelled: same two-stage kill as timeout.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
		}
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()
		if stderr == "" {
			stderr = fmt.Sprintf("process cancelled: %v", ctx.Err())
		}
		truncated = stdoutBuf.truncated || stderrBuf.truncated
		return &executeResult{
			Stdout:    stdout,
			Stderr:    stderr,
			ExitCode:  -1,
			Truncated: truncated,
		}, nil

	case err := <-done:
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()

		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}

		truncated = stdoutBuf.truncated || stderrBuf.truncated
		return &executeResult{
			Stdout:    stdout,
			Stderr:    stderr,
			ExitCode:  exitCode,
			Truncated: truncated,
		}, nil
	}
}

// ---------- runtime listing ----------

// availableLanguages returns a list of languages whose runtimes are installed.
func availableLanguages() []string {
	var langs []string
	for name := range runtimes {
		if checkRuntime(name, false) {
			langs = append(langs, name)
		}
	}
	return langs
}

// ---------- FILE_CONTENT injection for ctx_run: execute_file (base64 fallback) ----------

// injectFileContentBase64 uses base64 encoding to safely inject arbitrary file
// content into any language. The user code must decode the variable.
func injectFileContentBase64(language, code, fileContent string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(fileContent))
	switch language {
	case "shell":
		return fmt.Sprintf(`FILE_CONTENT_B64='%s'
FILE_CONTENT=$(echo "$FILE_CONTENT_B64" | base64 -d)
%s`, encoded, code)
	case "javascript", "typescript":
		return fmt.Sprintf(`const FILE_CONTENT = Buffer.from("%s", "base64").toString();
%s`, encoded, code)
	case "python":
		return fmt.Sprintf(`import base64
FILE_CONTENT = base64.b64decode("%s").decode()
%s`, encoded, code)
	case "go":
		return fmt.Sprintf(`import "encoding/base64"
FILE_CONTENT_BYTES, _ := base64.StdEncoding.DecodeString("%s")
FILE_CONTENT := string(FILE_CONTENT_BYTES)
%s`, encoded, code)
	default:
		// For languages that don't have a native decode, inject the raw content
		// via string literal (limited to text content).
		return injectFileContent(language, code, fileContent)
	}
}
