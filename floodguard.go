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
// It uses two ring buffers:
//   - okBuf tracks OK (allowed) request timestamps for the throttle threshold.
//   - attemptsBuf tracks all request timestamps (including rejected) for the
//     hard-block threshold.  This ensures sustained abuse triggers a full block
//     rather than staying permanently throttled.
type FloodGuard struct {
	mu          sync.Mutex
	okBuf       []time.Time   // ring buffer of OK timestamps
	okHead      int           // next write position in okBuf
	okTail      int           // oldest valid entry in okBuf
	okSize      int           // current entries within the window (≤ capacity)
	attemptsBuf []time.Time   // ring buffer of all attempt timestamps
	attHead     int           // next write position in attemptsBuf
	attTail     int           // oldest valid entry in attemptsBuf
	attSize     int           // current entries within the window (≤ capacity)
	capacity    int           // max entries in each buffer
	windowDur   time.Duration // e.g., 60 seconds
}

// NewFloodGuard creates a FloodGuard with the given window duration and ring
// buffer capacity. capacity controls how many recent timestamps are tracked in
// each of the two internal ring buffers; it is clamped to a minimum of 64 so
// that the rate-limit thresholds (block at 9, throttle at 4) are always
// correctly measurable.
func NewFloodGuard(windowDur time.Duration, capacity int) *FloodGuard {
	if capacity < 64 {
		capacity = 64
	}
	return &FloodGuard{
		okBuf:       make([]time.Time, capacity),
		attemptsBuf: make([]time.Time, capacity),
		capacity:    capacity,
		windowDur:   windowDur,
	}
}

// WindowCount returns the number of OK calls recorded in the current sliding
// window, without recording a new call.  This counts only calls that received
// StatusOK — it does not include throttled or blocked attempts.
// It is used for stats reporting (SearchCallsWindow field in ctx_kb stats).
func (fg *FloodGuard) WindowCount() int {
	fg.mu.Lock()
	defer fg.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-fg.windowDur)

	count := 0
	for i := 0; i < fg.okSize; i++ {
		idx := (fg.okTail + i) % fg.capacity
		if fg.okBuf[idx].After(cutoff) {
			count++
		}
	}
	return count
}

// Allow checks whether a new request should be allowed.
//
// It maintains two sliding-window ring buffers:
//   - attemptsBuf records every call (OK, throttled, blocked).
//   - okBuf records only StatusOK calls.
//
// Thresholds (evaluated after pruning expired entries):
//   - total attempts >= 9 → StatusBlocked (hard deny — sustained abuse)
//   - OK count       >= 4 → StatusThrottled (reduced results — temporary load)
//   - otherwise            → StatusOK (full results)
//
// The dual-counter design guarantees that a sustained burst of requests
// eventually triggers a hard block (total reaches 9), while a legitimate
// caller who pauses will see OK entries age out of okBuf and recover
// (throttled/blocked attempts do not prevent okBuf from draining).
func (fg *FloodGuard) Allow() FloodStatus {
	fg.mu.Lock()
	defer fg.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-fg.windowDur)

	// Prune entries that have fallen outside the sliding window.
	for fg.okSize > 0 && !fg.okBuf[fg.okTail].After(cutoff) {
		fg.okTail = (fg.okTail + 1) % fg.capacity
		fg.okSize--
	}
	for fg.attSize > 0 && !fg.attemptsBuf[fg.attTail].After(cutoff) {
		fg.attTail = (fg.attTail + 1) % fg.capacity
		fg.attSize--
	}

	total := fg.attSize
	okCount := fg.okSize

	// Determine status based on window counts.
	// Block takes priority: once total reaches 9, deny outright.
	// Throttle applies when the OK count alone reaches 4.
	var status FloodStatus
	switch {
	case total >= 9:
		status = StatusBlocked
	case okCount >= 4:
		status = StatusThrottled
	default:
		status = StatusOK
	}

	// Always record the attempt (so total can reach the block threshold).
	fg.attemptsBuf[fg.attHead] = now
	fg.attHead = (fg.attHead + 1) % fg.capacity
	if fg.attSize < fg.capacity {
		fg.attSize++
	} else {
		fg.attTail = (fg.attTail + 1) % fg.capacity
	}

	// Only OK requests are recorded in the OK buffer.
	// Throttled and blocked requests do not consume OK slots,
	// allowing legitimate callers to recover when OK entries age out.
	if status == StatusOK {
		fg.okBuf[fg.okHead] = now
		fg.okHead = (fg.okHead + 1) % fg.capacity
		if fg.okSize < fg.capacity {
			fg.okSize++
		} else {
			fg.okTail = (fg.okTail + 1) % fg.capacity
		}
	}

	return status
}
