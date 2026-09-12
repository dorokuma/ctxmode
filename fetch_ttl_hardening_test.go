package main

import (
	"context"
	"strings"
	"testing"
)

// Compile-time guard: maxFetchTTLms must stay in the int64 domain. Retyping
// it as plain int fails here on 64-bit, and dropping the explicit int64
// typing fails 32-bit builds (30 days in ms exceeds int32).
var _ int64 = maxFetchTTLms

// F4f: negative ttl_ms must be rejected instead of silently falling back to
// the 24h default, and values above the 30-day cap must be rejected so
// time.Duration multiplication cannot overflow into a never-matching cache.
func TestValidateFetchTTLms(t *testing.T) {
	if err := validateFetchTTLms(0); err != nil {
		t.Fatalf("ttl_ms=0 (skip cache) must be accepted, got %v", err)
	}
	if err := validateFetchTTLms(maxFetchTTLms); err != nil {
		t.Fatalf("ttl_ms=%d (30-day cap) must be accepted, got %v", maxFetchTTLms, err)
	}
	if err := validateFetchTTLms(-1); err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("negative ttl_ms must be rejected, got %v", err)
	}
	if err := validateFetchTTLms(maxFetchTTLms + 1); err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("ttl_ms above the 30-day cap must be rejected, got %v", err)
	}
}

// F4f: toolFetchAndIndex surfaces both ttl_ms errors as parameter errors,
// before any fetch or cache access happens.
func TestToolFetchAndIndex_RejectsInvalidTTLms(t *testing.T) {
	s := &server{workdirs: []string{t.TempDir()}}

	neg := -5
	_, _, err := s.toolFetchAndIndex(context.Background(), nil, fetchArgs{
		URL:   "http://1.1.1.1/doc",
		TTLMs: &neg,
	})
	if err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("negative ttl_ms must be rejected by the tool handler, got %v", err)
	}

	// 30 days in ms exceeds int32, so build the over-cap value through an int64
	// variable: exact on 64-bit; on 32-bit the conversion wraps negative and
	// the over-cap handler path is unreachable (int cannot exceed the cap).
	capMs := maxFetchTTLms
	huge := int(capMs) + 1
	if huge > 0 {
		_, _, err = s.toolFetchAndIndex(context.Background(), nil, fetchArgs{
			URL:   "http://1.1.1.1/doc",
			TTLMs: &huge,
		})
		if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
			t.Fatalf("oversized ttl_ms must be rejected by the tool handler, got %v", err)
		}
	}
}
