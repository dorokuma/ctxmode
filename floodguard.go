package main

import (
	"sync"
	"time"
)

// FloodStatus represents the result of a flood guard check.
type FloodStatus int

const (
	// StatusOK means the request is allowed with full results.
	StatusOK FloodStatus = iota
	// StatusThrottled means the request is allowed but with reduced results.
	StatusThrottled
	// StatusBlocked means the request is denied.
	StatusBlocked
)

// FloodGuard implements a sliding window rate limiter for search requests.
// It tracks recent request timestamps and determines whether to allow,
// throttle, or block new requests.
type FloodGuard struct {
	mu        sync.Mutex
	window    []time.Time
	windowDur time.Duration // e.g., 60 seconds
}

// NewFloodGuard creates a FloodGuard with the given window duration.
func NewFloodGuard(windowDur time.Duration) *FloodGuard {
	return &FloodGuard{
		window:    make([]time.Time, 0, 64),
		windowDur: windowDur,
	}
}

// WindowCount returns the number of calls recorded in the current sliding window
// without recording a new call. This is used for stats reporting.
func (fg *FloodGuard) WindowCount() int {
	fg.mu.Lock()
	defer fg.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-fg.windowDur)

	count := 0
	for _, t := range fg.window {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// Allow checks whether a new request should be allowed.
//
// Window size is 60 seconds (configurable via windowDur).
// The current request is recorded first, then the count of calls
// within the window determines the status:
//   - 1st–3rd call → StatusOK (full results)
//   - 4th–8th call → StatusThrottled (reduced results + warning)
//   - 9th+ call → StatusBlocked (denied)
func (fg *FloodGuard) Allow() FloodStatus {
	fg.mu.Lock()
	defer fg.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-fg.windowDur)

	// Prune entries outside the window.
	pruneCount := 0
	for _, t := range fg.window {
		if !t.After(cutoff) {
			pruneCount++
		}
	}
	if pruneCount > 0 {
		copy(fg.window, fg.window[pruneCount:])
		fg.window = fg.window[:len(fg.window)-pruneCount]
	}
	kept := len(fg.window)

	// Record this request first, then count (including this one).
	fg.window = append(fg.window, now)
	count := kept + 1

	switch {
	case count >= 9:
		return StatusBlocked
	case count >= 4:
		return StatusThrottled
	default:
		return StatusOK
	}
}
