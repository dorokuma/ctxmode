package main

import (
	"testing"
)

// TestGuard_R4_FsckLostFound blocks git fsck write options such as
// --lost-found while plain fsck stays free.
func TestGuard_R4_FsckLostFound(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "fsck --lost-found", argv: []string{"git", "fsck", "--lost-found"}, want: "git fsck --lost-found"},
		{name: "fsck --lost-found variant order", argv: []string{"git", "fsck", "--unreachable", "--lost-found"}, want: "git fsck --lost-found"},
		{name: "fsck plain ok", argv: []string{"git", "fsck"}, want: ""},
		{name: "fsck --unreachable ok", argv: []string{"git", "fsck", "--unreachable"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}

// TestGuard_R4_WgetLogFile blocks wget log-to-disk flags (-o/-a/
// --output-file/--append-output) even when -O - / --spider would otherwise
// allow the download itself.
func TestGuard_R4_WgetLogFile(t *testing.T) {
	t.Setenv(auditEnvRole, "reviewer")
	t.Setenv(auditEnvReadonly, "")

	cases := []struct {
		name string
		argv []string
		want string
	}{
		{name: "wget -O - -o log", argv: []string{"wget", "-O", "-", "-o", "/tmp/log", "https://x"}, want: "wget"},
		{name: "wget --spider --output-file", argv: []string{"wget", "--spider", "--output-file=/tmp/log", "https://x"}, want: "wget"},
		{name: "wget -O - -a log", argv: []string{"wget", "-O", "-", "-a", "/tmp/log", "https://x"}, want: "wget"},
		{name: "wget -O - ok", argv: []string{"wget", "-O", "-", "https://x"}, want: ""},
		{name: "wget --spider ok", argv: []string{"wget", "--spider", "https://x"}, want: ""},
		{name: "wget -O - -o - ok", argv: []string{"wget", "-O", "-", "-o", "-", "https://x"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardArgvReadonly(tc.argv)
			if got != tc.want {
				t.Fatalf("guardArgvReadonly(%v) = %q, want %q", tc.argv, got, tc.want)
			}
		})
	}
}
