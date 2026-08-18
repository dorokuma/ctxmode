package main

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func indexDoc(t *testing.T, s *Store, path, content string) {
	t.Helper()
	if err := s.Index(path, content); err != nil {
		t.Fatalf("Index(%q): %v", path, err)
	}
}

func TestPurgeByPrefix_Basic(t *testing.T) {
	s := newTestStore(t)

	indexDoc(t, s, "session:abc", "a")
	indexDoc(t, s, "session:def", "b")
	indexDoc(t, s, "batch:abc", "c")

	// Purge only session:abc — batch:abc should survive.
	n, err := s.PurgeByPrefix("session:abc")
	if err != nil {
		t.Fatalf("PurgeByPrefix: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}

	// session:def should survive.
	doc, err := s.Get("session:def")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if doc == nil {
		t.Fatal("session:def should still exist")
	}

	// batch:abc should survive (different prefix).
	doc, err = s.Get("batch:abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if doc == nil {
		t.Fatal("batch:abc should still exist")
	}
}

func TestPurgeByPrefix_RangeSemantics(t *testing.T) {
	s := newTestStore(t)

	indexDoc(t, s, "session:a", "1")
	indexDoc(t, s, "session:ab", "2")
	indexDoc(t, s, "session:abc", "3")
	indexDoc(t, s, "session:abz", "4")
	indexDoc(t, s, "session:b", "5")

	// Purge with prefix "session:ab" should match session:ab, session:abc, session:abz
	// but NOT session:a or session:b.
	n, err := s.PurgeByPrefix("session:ab")
	if err != nil {
		t.Fatalf("PurgeByPrefix: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 deleted (session:ab, session:abc, session:abz), got %d", n)
	}

	// session:a should survive.
	if doc, _ := s.Get("session:a"); doc == nil {
		t.Fatal("session:a should survive")
	}
	// session:b should survive.
	if doc, _ := s.Get("session:b"); doc == nil {
		t.Fatal("session:b should survive")
	}
}

func TestPurgeByPrefix_UnderscoreNotWildcard(t *testing.T) {
	// C8 fix verification: _ and % in prefix must NOT be treated as wildcards.
	s := newTestStore(t)

	// Exact path.
	indexDoc(t, s, "session:test_session", "exact")

	// Paths that differ by one char where _ would be wildcard in LIKE.
	indexDoc(t, s, "session:testXsession", "similar1")
	indexDoc(t, s, "session:testYsession", "similar2")

	// Purge with prefix containing literal underscore.
	n, err := s.PurgeByPrefix("session:test_session")
	if err != nil {
		t.Fatalf("PurgeByPrefix: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}

	// Similar paths must survive (LIKE _ wildcard would have matched them).
	if doc, _ := s.Get("session:testXsession"); doc == nil {
		t.Fatal("session:testXsession should survive (underscore not wildcard)")
	}
	if doc, _ := s.Get("session:testYsession"); doc == nil {
		t.Fatal("session:testYsession should survive (underscore not wildcard)")
	}
}

func TestPurgeByPrefix_PercentNotWildcard(t *testing.T) {
	// C8 fix verification: % in prefix must NOT act as wildcard.
	s := newTestStore(t)

	indexDoc(t, s, "session:test%path", "exact")
	indexDoc(t, s, "session:testXpath", "similar")
	indexDoc(t, s, "session:testYYpath", "similar2")

	n, err := s.PurgeByPrefix("session:test%path")
	if err != nil {
		t.Fatalf("PurgeByPrefix: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 deleted, got %d", n)
	}

	// Similar paths must survive (LIKE % would have matched them).
	if doc, _ := s.Get("session:testXpath"); doc == nil {
		t.Fatal("session:testXpath should survive (% not wildcard)")
	}
	if doc, _ := s.Get("session:testYYpath"); doc == nil {
		t.Fatal("session:testYYpath should survive (% not wildcard)")
	}
}

func TestPurgeByPrefix_EmptyPrefix(t *testing.T) {
	s := newTestStore(t)

	indexDoc(t, s, "session:a", "1")
	indexDoc(t, s, "batch:a", "2")

	// Empty prefix should delete all documents.
	n, err := s.PurgeByPrefix("")
	if err != nil {
		t.Fatalf("PurgeByPrefix(\"\"): %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 deleted with empty prefix, got %d", n)
	}

	if doc, _ := s.Get("session:a"); doc != nil {
		t.Fatal("session:a should be deleted")
	}
	if doc, _ := s.Get("batch:a"); doc != nil {
		t.Fatal("batch:a should be deleted")
	}
}

func TestPurgeByPrefix_NonExistentPrefix(t *testing.T) {
	s := newTestStore(t)

	indexDoc(t, s, "session:a", "1")

	n, err := s.PurgeByPrefix("nonexistent")
	if err != nil {
		t.Fatalf("PurgeByPrefix: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 deleted, got %d", n)
	}

	// Existing doc should survive.
	if doc, _ := s.Get("session:a"); doc == nil {
		t.Fatal("session:a should survive")
	}
}

func TestCountByPrefix_Basic(t *testing.T) {
	s := newTestStore(t)

	indexDoc(t, s, "session:abc", "1")
	indexDoc(t, s, "session:def", "2")
	indexDoc(t, s, "batch:abc", "3")

	n, err := s.CountByPrefix("session:abc")
	if err != nil {
		t.Fatalf("CountByPrefix: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1, got %d", n)
	}

	n, err = s.CountByPrefix("session:")
	if err != nil {
		t.Fatalf("CountByPrefix: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2, got %d", n)
	}

	n, err = s.CountByPrefix("nonexistent")
	if err != nil {
		t.Fatalf("CountByPrefix: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0, got %d", n)
	}
}

func TestNewStore_URISpecialChars(t *testing.T) {
	cases := []string{"My Project", "foo%20bar", "foo#bar", "foo?bar", "foo&bar"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			dbPath := filepath.Join(dir, "context_mode.db")
			st, err := NewStore(dbPath)
			if err != nil {
				t.Fatalf("NewStore(%q): %v", dbPath, err)
			}
			defer st.Close()
			marker := "dsn-marker-" + name
			if err := st.Index("p", marker); err != nil {
				t.Fatalf("Index: %v", err)
			}
			if _, err := os.Stat(dbPath); err != nil {
				t.Fatalf("expected db at literal path %s: %v", dbPath, err)
			}
			hits, err := st.Search(marker, 5)
			if err != nil {
				t.Fatalf("Search: %v", err)
			}
			if len(hits) == 0 {
				t.Fatalf("indexed row not searchable for dir %q", name)
			}
		})
	}
}
