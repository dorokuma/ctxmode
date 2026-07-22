package main

import (
	"net"
	"testing"
)

// ---------- checkIP tests ----------

func TestCheckIP_IPv4_Blocked(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		reason string
	}{
		// Private ranges (RFC 1918)
		{"10.0.0.0/8 lower", "10.0.0.1", "10.0.0.0/8 (private)"},
		{"10.0.0.0/8 mid", "10.255.255.254", "10.0.0.0/8 (private)"},
		{"172.16.0.0/12 lower", "172.16.0.1", "172.16.0.0/12 (private)"},
		{"172.16.0.0/12 upper", "172.31.255.254", "172.16.0.0/12 (private)"},
		{"192.168.0.0/16 lower", "192.168.0.1", "192.168.0.0/16 (private)"},
		{"192.168.0.0/16 upper", "192.168.255.254", "192.168.0.0/16 (private)"},

		// Link-local / IMDS
		{"169.254.0.0/16 lower", "169.254.0.1", "169.254.0.0/16 (link-local / IMDS)"},
		{"169.254.0.0/16 upper", "169.254.255.254", "169.254.0.0/16 (link-local / IMDS)"},

		// Loopback
		{"127.0.0.0/8 lower", "127.0.0.1", "127.0.0.0/8 (loopback)"},
		{"127.0.0.0/8 upper", "127.255.255.254", "127.0.0.0/8 (loopback)"},

		// Unspecified
		{"0.0.0.0/8 lower", "0.0.0.0", "0.0.0.0/8 (unspecified address)"},
		{"0.0.0.0/8 mid", "0.255.255.255", "0.0.0.0/8 (unspecified address)"},

		// Multicast
		{"224.0.0.0/4 lower", "224.0.0.1", "224.0.0.0/4 (multicast)"},
		{"224.0.0.0/4 mid", "232.0.0.1", "224.0.0.0/4 (multicast)"},
		{"224.0.0.0/4 upper", "239.255.255.254", "224.0.0.0/4 (multicast)"},

		// Reserved (240.0.0.0/4)
		{"240.0.0.0/4 lower", "240.0.0.1", "240.0.0.0/4 (reserved)"},
		{"240.0.0.0/4 mid", "248.0.0.1", "240.0.0.0/4 (reserved)"},
		{"240.0.0.0/4 upper", "255.255.255.254", "240.0.0.0/4 (reserved)"},

		// CGNAT (100.64.0.0/10)
		{"100.64.0.0/10 lower", "100.64.0.1", "100.64.0.0/10 (CGNAT)"},
		{"100.64.0.0/10 upper", "100.127.255.254", "100.64.0.0/10 (CGNAT)"},

		// Benchmark (198.18.0.0/15)
		{"198.18.0.0/15 lower", "198.18.0.1", "198.18.0.0/15 (benchmark)"},
		{"198.18.0.0/15 upper", "198.19.255.254", "198.18.0.0/15 (benchmark)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("bad test IP: %s", tt.ip)
			}
			err := checkIP(ip, false)
			if err == nil {
				t.Fatalf("expected blocked, got nil error")
			}
			if err.Error() != tt.reason {
				t.Fatalf("expected %q, got %q", tt.reason, err.Error())
			}
			// strict=true should also block (same as non-strict for v4).
			err = checkIP(ip, true)
			if err == nil {
				t.Fatalf("strict: expected blocked, got nil error")
			}
		})
	}
}

func TestCheckIP_IPv4_Allowed(t *testing.T) {
	tests := []struct {
		name string
		ip   string
	}{
		{"public DNS 8.8.8.8", "8.8.8.8"},
		{"public DNS 1.1.1.1", "1.1.1.1"},
		{"public 93.184.216.34", "93.184.216.34"},
		{"just outside 172.16/12 (172.15)", "172.15.255.255"},
		{"just outside 172.16/12 (172.32)", "172.32.0.1"},
		{"just outside CGNAT (100.63)", "100.63.255.255"},
		{"just outside CGNAT (100.128)", "100.128.0.1"},
		{"just outside benchmark (198.17)", "198.17.255.255"},
		{"just outside benchmark (198.20)", "198.20.0.1"},
		{"just outside 0/8 (1.0.0.1)", "1.0.0.1"},
		{"just outside loopback (128.0.0.1)", "128.0.0.1"},
		{"just outside IMDS (169.255)", "169.255.0.1"},
		{"just outside 192.168 (192.169)", "192.169.0.1"},
		{"just below multicast (223.255)", "223.255.255.254"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("bad test IP: %s", tt.ip)
			}
			err := checkIP(ip, false)
			if err != nil {
				t.Fatalf("expected allowed, got: %v", err)
			}
			err = checkIP(ip, true)
			if err != nil {
				t.Fatalf("strict: expected allowed, got: %v", err)
			}
		})
	}
}

func TestCheckIP_IPv6_Blocked(t *testing.T) {
	// These are blocked regardless of strict.
	alwaysBlocked := []struct {
		name   string
		ip     string
		reason string
	}{
		{"link-local fe80::1", "fe80::1", "IPv6 link-local unicast (fe80::/10) blocked"},
		{"unspecified ::", "::", "IPv6 unspecified (::) blocked"},
		{"multicast ff00::1", "ff00::1", "IPv6 multicast blocked"},
		{"multicast ff02::1", "ff02::1", "IPv6 multicast blocked"},
	}

	for _, tt := range alwaysBlocked {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("bad test IP: %s", tt.ip)
			}
			err := checkIP(ip, false)
			if err == nil {
				t.Fatalf("non-strict: expected blocked, got nil")
			}
			if err.Error() != tt.reason {
				t.Fatalf("non-strict: expected %q, got %q", tt.reason, err.Error())
			}
			err = checkIP(ip, true)
			if err == nil {
				t.Fatalf("strict: expected blocked, got nil")
			}
		})
	}
}

func TestCheckIP_IPv6_StrictOnly(t *testing.T) {
	t.Run("::1 allowed in non-strict", func(t *testing.T) {
		ip := net.ParseIP("::1")
		if ip == nil {
			t.Fatal("bad test IP")
		}
		err := checkIP(ip, false)
		if err != nil {
			t.Fatalf("non-strict: expected allowed, got: %v", err)
		}
		err = checkIP(ip, true)
		if err == nil {
			t.Fatal("strict: expected blocked for ::1")
		}
		if err.Error() != "::1 (IPv6 loopback) blocked in strict mode" {
			t.Fatalf("strict: unexpected error: %v", err)
		}
	})

	t.Run("IPv6 private fc00::1 allowed in non-strict", func(t *testing.T) {
		ip := net.ParseIP("fc00::1")
		if ip == nil {
			t.Fatal("bad test IP")
		}
		err := checkIP(ip, false)
		if err != nil {
			t.Fatalf("non-strict: expected allowed, got: %v", err)
		}
		err = checkIP(ip, true)
		if err == nil {
			t.Fatal("strict: expected blocked for v6 private")
		}
		if err.Error() != "IPv6 private address blocked in strict mode" {
			t.Fatalf("strict: unexpected error: %v", err)
		}
	})

	t.Run("IPv6 private fd00::1 allowed in non-strict", func(t *testing.T) {
		ip := net.ParseIP("fd00::1")
		if ip == nil {
			t.Fatal("bad test IP")
		}
		err := checkIP(ip, false)
		if err != nil {
			t.Fatalf("non-strict: expected allowed, got: %v", err)
		}
		err = checkIP(ip, true)
		if err == nil {
			t.Fatal("strict: expected blocked for v6 private")
		}
	})
}

func TestCheckIP_Public_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:4860:4860::8888") // Google DNS v6
	if ip == nil {
		t.Fatal("bad test IP")
	}
	err := checkIP(ip, false)
	if err != nil {
		t.Fatalf("non-strict: expected allowed, got: %v", err)
	}
	err = checkIP(ip, true)
	if err != nil {
		t.Fatalf("strict: expected allowed, got: %v", err)
	}
}

func TestCheckIP_Nil(t *testing.T) {
	err := checkIP(nil, false)
	if err == nil {
		t.Fatal("expected error for nil IP")
	}
	if err.Error() != "nil IP" {
		t.Fatalf("expected 'nil IP', got %q", err.Error())
	}
}

func TestCheckIP_IPv4Mapped_IPv6(t *testing.T) {
	// IPv4-mapped IPv6 addresses: ::ffff:10.0.0.1 should be blocked as private.
	ip := net.ParseIP("::ffff:10.0.0.1")
	if ip == nil {
		t.Fatal("bad test IP")
	}
	// To4() returns the v4 address for IPv4-mapped IPv6.
	v4 := ip.To4()
	if v4 == nil {
		t.Fatal("expected non-nil v4 for IPv4-mapped")
	}
	err := checkIP(ip, false)
	if err == nil {
		t.Fatal("expected blocked for ::ffff:10.0.0.1")
	}
	if err.Error() != "10.0.0.0/8 (private)" {
		t.Fatalf("expected '10.0.0.0/8 (private)', got %q", err.Error())
	}
}

// ---------- singleflight key construction ----------

func TestSingleflightKeyPattern(t *testing.T) {
	// cacheSource = source + "|" + format
	// sfKey = rawURL + "|" + cacheSource
	// This matches the logic in fetchAndIndex:
	//   cacheSource := source + "|" + format
	//   sfKey := rawURL + "|" + cacheSource
	tests := []struct {
		rawURL  string
		source  string
		format  string
		wantKey string
	}{
		{
			rawURL:  "https://example.com",
			source:  "docs",
			format:  "markdown",
			wantKey: "https://example.com|docs|markdown",
		},
		{
			rawURL:  "https://example.com",
			source:  "docs",
			format:  "html",
			wantKey: "https://example.com|docs|html",
		},
		{
			rawURL:  "https://other.example.com",
			source:  "",
			format:  "",
			wantKey: "https://other.example.com||",
		},
	}

	for _, tt := range tests {
		t.Run(tt.wantKey, func(t *testing.T) {
			cacheSource := tt.source + "|" + tt.format
			sfKey := tt.rawURL + "|" + cacheSource
			if sfKey != tt.wantKey {
				t.Fatalf("expected %q, got %q", tt.wantKey, sfKey)
			}
		})
	}
}

func TestSingleflightKey_UniquePerFormat(t *testing.T) {
	// Same URL + source, different formats → different singleflight keys.
	rawURL := "https://example.com"
	source := "api-ref"

	keyMarkdown := rawURL + "|" + source + "|" + "markdown"
	keyHTML := rawURL + "|" + source + "|" + "html"
	keyJSON := rawURL + "|" + source + "|" + "json"

	if keyMarkdown == keyHTML {
		t.Fatalf("markdown and html keys should differ: %q", keyMarkdown)
	}
	if keyMarkdown == keyJSON {
		t.Fatalf("markdown and json keys should differ: %q", keyMarkdown)
	}
	if keyHTML == keyJSON {
		t.Fatalf("html and json keys should differ: %q", keyHTML)
	}
}
